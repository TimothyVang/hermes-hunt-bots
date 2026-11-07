"""Project hunt-rubric-1: evaluator-only measurements and deterministic scoring.

These formulas are not MITRE certification and never grant lab authority.
"""
import copy
import math

from benchmark_contracts import (
    BenchmarkError, _digest, _id, _text, _window, canonical_bytes, digest_bytes,
    validate_stage_output, validate_truth,
)
from benchmark_attack import canonical_parent, canonical_technique, technique_status

RUBRIC_VERSION = 'hunt-rubric-1'
HUMAN = 'human'
MECHANICAL = 'mechanical'
ADJUDICATIONS = (HUMAN, MECHANICAL)
# Versioned rule identity; part of every mechanical adjudication record.
MECHANICAL_RULES = 'mechanical-rules-1'
NOT_MEASURED_MECHANICAL = 'not_measured_mechanical'


def difficulty_from_measurements(*, benign_events, relevant_events, required_joins,
                                 correlation_seconds, missing_records,
                                 alternative_complete, unresolvable_questions,
                                 benign_lookalikes, matched_control=None):
    """Rate curator-validated evidence facts, never model success or actor names.

required_joins is the number of distinct source/asset contexts necessary for a
complete support set, not the total number of available sensors. Curators must
validate seeded benign explanations rather than infer them from model answers.
A zero-positive control inherits its matched attack-family measurements.
"""
    for field, value in (('benign_events', benign_events), ('relevant_events', relevant_events),
                         ('required_joins', required_joins),
                         ('unresolvable_questions', unresolvable_questions),
                         ('benign_lookalikes', benign_lookalikes)):
        if type(value) is not int or value < 0:
            raise BenchmarkError('invalid_measurement', field)
    if (type(correlation_seconds) not in (int, float)
            or not math.isfinite(correlation_seconds) or correlation_seconds < 0):
        raise BenchmarkError('invalid_measurement', 'correlation_seconds')
    if type(missing_records) is not bool or type(alternative_complete) is not bool:
        raise BenchmarkError('invalid_measurement', 'gaps')
    if relevant_events == 0:
        if matched_control is None:
            raise BenchmarkError('matched_family_required', 'difficulty')
        from benchmark_contracts import _difficulty
        _difficulty(matched_control)
        result = copy.deepcopy(matched_control)
        result['control'] = True
        return result
    if matched_control is not None or required_joins == 0:
        raise BenchmarkError('invalid_measurement', 'difficulty')
    if missing_records and not alternative_complete and not unresolvable_questions:
        raise BenchmarkError('unresolved_gap', 'gaps')
    ratio = benign_events / relevant_events
    noise = 0 if ratio <= 10 else (1 if ratio <= 100 else 2)
    joins = min(required_joins - 1, 2)
    span = 0 if correlation_seconds <= 300 else (1 if correlation_seconds <= 3600 else 2)
    gaps = 2 if unresolvable_questions else (1 if missing_records else 0)
    ambiguity = min(benign_lookalikes, 2)
    values = {
        'noise': (noise, '{} benign / {} relevant events; ratio {:g}.'.format(benign_events, relevant_events, ratio)),
        'joins': (joins, '{} source/asset contexts required by a complete support set.'.format(required_joins)),
        'time_span': (span, '{:g} seconds of required correlation.'.format(correlation_seconds)),
        'gaps': (gaps, '{} unresolvable questions; missing records {}; alternative complete support {}.'.format(unresolvable_questions, missing_records, alternative_complete)),
        'ambiguity': (ambiguity, '{} validated seeded benign or contradictory explanations.'.format(benign_lookalikes)),
    }
    return {'band': 'D' + str(min(sum(item[0] for item in values.values()) // 2 + 1, 5)),
            'control': False,
            'factors': {key: {'score': score, 'rationale': rationale}
                        for key, (score, rationale) in values.items()}}


def edge_item_id(edge):
    """Stable opaque adjudication identifier for an ordered finding-ID pair."""
    if type(edge) is not list or len(edge) != 2:
        raise BenchmarkError('invalid_edge', 'chain_edges')
    for item in edge:
        _id(item, 'chain_edges')
    return 'edge_' + digest_bytes(canonical_bytes(edge))


def disputed_only(finding, truth):
    """True when a finding cites only records of disputed agent-consensus steps: scoring ignores it."""
    cited = set(finding['event_ids'])
    return bool(cited) and cited.issubset(truth.get('disputed_event_ids', ()))


def _rate(section, name, numerator, denominator, reason):
    section[name] = numerator / denominator if denominator else None
    if not denominator:
        section['null_reasons'][name] = reason


def _detection_rates(section):
    tp, fp, fn = section['tp'], section['fp'], section['fn']
    _rate(section, 'precision', tp, tp + fp, 'no_predicted_positives')
    _rate(section, 'recall', tp, tp + fn, 'no_eligible_positives')
    _rate(section, 'f1', 2 * tp, 2 * tp + fp + fn, 'no_eligible_or_predicted_positives')


def _overlaps(left, right):
    a, b = _window(left['window_utc'], 'window_utc')
    c, d = _window(right['window_utc'], 'window_utc')
    return a < d and c < b


def _scoped(left, right):
    return left['asset_id'] == right['asset_id'] and _overlaps(left, right)


def _technique(item):
    """Pinned-release canonical technique ID: revoked IDs follow their replacement,
    unknown IDs stay unchanged (and so never match truth), null stays null."""
    value = item['technique_id']
    return None if value is None else canonical_technique(value)


def _parent_only(finding, step):
    """Finding names the canonical parent of a canonical sub-technique step."""
    return ('.' in _technique(step) and finding['technique_id'] is not None
            and _technique(finding) == canonical_parent(step['technique_id']))


def assertion_key(finding):
    """Canonical finding assertion without its ID; exact duplicates share it."""
    start, end = _window(finding['window_utc'], 'window_utc')
    assertion = {key: value for key, value in finding.items() if key != 'finding_id'}
    assertion['technique_id'] = _technique(finding)
    assertion['event_ids'] = sorted(finding['event_ids'])
    assertion['window_utc'] = {'start_inclusive': start.isoformat(),
                               'end_exclusive': end.isoformat()}
    return canonical_bytes(assertion)


def _verdict_index(verdicts, items, events, trial_id, output_sha256):
    if type(verdicts) is not list:
        raise BenchmarkError('invalid_array', 'verdicts')
    required = {'trial_id', 'output_sha256', 'item_kind', 'item_id', 'verdict',
                'event_ids', 'by', 'note'}
    prohibited = {'model', 'evidence-checker', 'checker', 'benchmark-scorer',
                  'jev', 'typesafe', 'framework-coordinator', 'framework-researcher',
                  'framework-network-analyst', 'framework-librarian',
                  'framework-builder', 'framework-reviewer'}
    result = {}
    for verdict in verdicts:
        if type(verdict) is not dict or set(verdict) != required:
            raise BenchmarkError('invalid_fields', 'verdicts')
        if verdict['trial_id'] != trial_id or verdict['output_sha256'] != output_sha256:
            raise BenchmarkError('adjudication_binding_mismatch', 'verdicts')
        _id(verdict['item_id'], 'verdicts.item_id')
        if verdict['item_kind'] not in ('claim', 'finding', 'edge'):
            raise BenchmarkError('invalid_enum', 'verdicts.item_kind')
        key = (verdict['item_kind'], verdict['item_id'])
        if key not in items:
            raise BenchmarkError('unknown_reference', 'verdicts.item_id')
        if key in result:
            raise BenchmarkError('duplicate_item', 'verdicts')
        if verdict['verdict'] not in ('supported', 'contradicted', 'insufficient'):
            raise BenchmarkError('invalid_enum', 'verdicts.verdict')
        _text(verdict['by'], 'verdicts.by')
        _text(verdict['note'], 'verdicts.note')
        if verdict['by'].strip().casefold().replace('_', '-') in prohibited:
            raise BenchmarkError('human_adjudication_required', 'verdicts.by')
        ids = verdict['event_ids']
        if type(ids) is not list:
            raise BenchmarkError('invalid_array', 'verdicts.event_ids')
        for event_id in ids:
            _id(event_id, 'verdicts.event_ids')
        if len(set(ids)) != len(ids) or not set(ids).issubset(events):
            raise BenchmarkError('invalid_citation', 'verdicts.event_ids')
        result[key] = verdict
    return result


def _maximum_matching(candidates):
    """Sorted augmenting paths; maximum cardinality, without recursion limits."""
    from collections import deque
    step_owner = {}
    finding_step = {}
    for root in sorted(candidates):
        queue = deque([root])
        parents = {}
        visited_findings = {root}
        free_step = None
        while queue and free_step is None:
            finding_id = queue.popleft()
            for step_id in sorted(candidates[finding_id]):
                if step_id in parents:
                    continue
                parents[step_id] = finding_id
                owner = step_owner.get(step_id)
                if owner is None:
                    free_step = step_id
                    break
                if owner not in visited_findings:
                    visited_findings.add(owner)
                    queue.append(owner)
        while free_step is not None:
            finding_id = parents[free_step]
            previous = finding_step.get(finding_id)
            step_owner[free_step] = finding_id
            finding_step[finding_id] = free_step
            free_step = previous
    return finding_step


def mechanical_verdicts(findings, truth, events):
    """Deterministic rule verdicts for findings; never human verdicts, never a model.

    supported: cites every event of at least one complete support set of a truth
    step with the same canonical technique, the same asset and an overlapping window.
    contradicted: suspicious, overlaps a benign control and matches no such step.
    insufficient: everything else. Claims and edges have no rule verdict: claim
    semantic support is not measured and an edge counts only when both endpoints
    are matched detections and truth holds that ordered edge.
    """
    result = {}
    for finding in findings:
        cited = set(finding['event_ids'])
        exact = [step for step in truth['steps']
                 if _technique(finding) == _technique(step) and _scoped(finding, step)]
        if any(support and set(support).issubset(cited)
               for step in exact for support in step['support_sets']):
            verdict = 'supported'
        elif finding['disposition'] == 'suspicious' and not exact and any(
                control['expected_disposition'] == 'benign' and _scoped(finding, control)
                for control in truth['controls']):
            verdict = 'contradicted'
        else:
            verdict = 'insufficient'
        result[('finding', finding['finding_id'])] = {
            'verdict': verdict, 'event_ids': sorted(cited & events), 'basis': MECHANICAL_RULES}
    return result


def score_output(output, truth, public_bundle, verdicts, *, trial_id,
                 output_sha256, completed=True, adjudication='human'):
    """Score sealed assertions against frozen truth and independent verdicts.

    ``adjudication='human'`` takes the human verdict list; ``'mechanical'`` takes
    ``verdicts=None`` and applies ``mechanical_verdicts``. Mechanical metrics carry
    status ``mechanical``, never ``final``, and claim semantic support is reported
    as ``not_measured_mechanical`` rather than fabricated.

    This pure function does not attest to the pre-answer truth freeze or workflow
    completion; the experiment scorer owns those additional final-ranking gates.
    Unaccepted outputs never contribute findings or successful control outcomes.
    """
    _id(trial_id, 'trial_id')
    if type(completed) is not bool:
        raise BenchmarkError('invalid_boolean', 'completed')
    if adjudication not in ADJUDICATIONS:
        raise BenchmarkError('invalid_enum', 'adjudication')
    mechanical = adjudication == MECHANICAL
    if mechanical and verdicts is not None:
        raise BenchmarkError('invalid_fields', 'verdicts')
    validate_truth(truth, public_bundle)
    if output is None:
        if output_sha256 is not None:
            raise BenchmarkError('output_digest_mismatch', 'output_sha256')
    else:
        _digest(output_sha256, 'output_sha256')
        # Missing answers are accounted for below; never substitute probability 0.
        validate_stage_output(output)
    events = {event['event_id'] for event in public_bundle['events']}
    all_claims = output['claims'] if output is not None else []
    all_findings = output['findings'] if output is not None else []
    all_edges = output.get('chain_edges', []) if output is not None else []
    finding_items = {('finding', item['finding_id']) for item in all_findings}
    items = ({('claim', item['claim_id']) for item in all_claims} | finding_items
             | {('edge', edge_item_id(edge)) for edge in all_edges})
    if mechanical:
        judgments = mechanical_verdicts(all_findings, truth, events)
        required = finding_items
    else:
        judgments = _verdict_index(verdicts, items, events, trial_id, output_sha256)
        required = items
    accepted = completed and output is not None
    claims = all_claims if accepted else []
    cited_findings = all_findings if accepted else []
    # Agent-consensus truth: a finding citing ONLY records of steps the drafts disagreed on is dropped before
    # matching (neither credit nor penalty), and so is every edge touching it.
    ignored = {finding['finding_id'] for finding in cited_findings if disputed_only(finding, truth)}
    findings = [finding for finding in cited_findings if finding['finding_id'] not in ignored]
    edges = [edge for edge in (all_edges if accepted else [])
             if edge[0] not in ignored and edge[1] not in ignored]
    ignored_edges = (len(all_edges) if accepted else 0) - len(edges)
    ignored_items = ({('finding', finding_id) for finding_id in ignored}
                     | {('edge', edge_item_id(edge)) for edge in all_edges
                        if edge[0] in ignored or edge[1] in ignored})
    missing = [{'item_kind': kind, 'item_id': item_id}
               for kind, item_id in sorted(required - ignored_items - set(judgments))] if accepted else []
    assets = {asset['asset_id'] for asset in public_bundle['assets']}
    outer_start, outer_end = _window(public_bundle['window_utc'], 'window_utc')
    scope_errors = []
    outside = set()
    groups = {}
    aliases = {}
    for finding in sorted(findings, key=lambda item: item['finding_id']):
        finding_id = finding['finding_id']
        start, end = _window(finding['window_utc'], 'window_utc')
        reasons = []
        if finding['asset_id'] not in assets:
            reasons.append('unknown_asset')
        if start < outer_start or end > outer_end:
            reasons.append('outside_public_window')
        if reasons:
            outside.add(finding_id)
            scope_errors.append({'item_kind': 'finding', 'item_id': finding_id,
                                 'reasons': reasons})
        groups.setdefault(assertion_key(finding), []).append(finding)
    canonical = {}
    group_verdicts = {}
    conflicts = []
    for group in groups.values():
        representative = group[0]['finding_id']
        canonical[representative] = group[0]
        for finding in group:
            aliases[finding['finding_id']] = representative
        bound = [judgments.get(('finding', finding['finding_id'])) for finding in group]
        states = {verdict['verdict'] for verdict in bound if verdict is not None}
        if len(states) > 1:
            conflicts.append({'item_kind': 'finding',
                              'item_ids': [finding['finding_id'] for finding in group]})
        group_verdicts[representative] = bound

    def supported(finding_id):
        bound = group_verdicts[finding_id]
        return (finding_id not in outside
                and all(verdict is not None and verdict['verdict'] == 'supported'
                        for verdict in bound))

    def support_complete(finding_id, step):
        cited = set(canonical[finding_id]['event_ids'])
        bound = group_verdicts[finding_id]
        return supported(finding_id) and all(
            any(set(support).issubset(cited & set(verdict['event_ids']))
                for support in step['support_sets']) for verdict in bound)

    eligible = {step['step_id']: step for step in truth['steps']
                if step['observability'] == 'sufficient'}
    suspicious = {key: finding for key, finding in canonical.items()
                  if finding['disposition'] == 'suspicious'}
    candidates = {}
    limited_candidates = set()
    correct_unsupported = 0
    incorrect = 0
    parent_only = 0
    for finding_id, finding in suspicious.items():
        exact = [step for step in truth['steps']
                 if _technique(finding) == _technique(step) and _scoped(finding, step)]
        complete = [step for step in exact if support_complete(finding_id, step)]
        candidates[finding_id] = [step['step_id'] for step in complete if step['step_id'] in eligible]
        if any(step['step_id'] not in eligible for step in complete):
            limited_candidates.add(finding_id)
        if exact and not complete:
            correct_unsupported += 1
        if not exact:
            incorrect += 1
        if not exact and any(
                _parent_only(finding, step)
                and _scoped(finding, step) for step in truth['steps']):
            parent_only += 1
    matched = _maximum_matching(candidates)
    tp = len(matched)
    # A supported exact detection of a step whose observability is not
    # 'sufficient' is neither recall credit nor a false positive: unknown or
    # insufficient visibility is never a negative label.
    visibility_limited = sorted(limited_candidates - set(matched))
    detection = {'tp': tp, 'fp': len(suspicious) - tp - len(visibility_limited),
                 'fn': len(eligible) - tp,
                 'eligible_steps': len(eligible),
                 'visibility_limited_steps': len(truth['steps']) - len(eligible),
                 'visibility_limited_detections': len(visibility_limited),
                 'visibility_statuses': {
                     status: sum(step['observability'] == status for step in truth['steps'])
                     for status in ('sufficient', 'insufficient', 'absent', 'unknown')},
                 'truth_correct_unsupported': correct_unsupported,
                 'truth_incorrect': incorrect, 'parent_technique_only': parent_only,
                 'disputed_ignored': len(ignored),
                 'execution_outcomes': {}, 'null_reasons': {}}
    _detection_rates(detection)
    for outcome in ('succeeded', 'blocked', 'failed', 'unknown'):
        detection['execution_outcomes'][outcome] = {
            'eligible_steps': sum(step['execution_outcome'] == outcome for step in eligible.values()),
            'matched_steps': sum(eligible[step_id]['execution_outcome'] == outcome
                                 for step_id in matched.values())}

    claim_metrics = {'total': len(claims), 'supported': 0, 'contradicted': 0,
                     'insufficient': 0, 'missing': 0, 'unsupported': 0, 'null_reasons': {}}
    if mechanical:
        # Semantic support needs a human reader; only citation existence is checked.
        valid = sum(set(claim['event_ids']).issubset(events) for claim in claims)
        claim_metrics.update(supported=None, contradicted=None, insufficient=None,
                             unsupported=None, semantic_support=NOT_MEASURED_MECHANICAL,
                             citation_valid=valid, citation_invalid=len(claims) - valid)
        for name in ('support_rate', 'contradicted_rate'):
            claim_metrics[name] = None
            claim_metrics['null_reasons'][name] = NOT_MEASURED_MECHANICAL
        _rate(claim_metrics, 'citation_valid_rate', valid, len(claims), 'no_claims')
    else:
        for claim in claims:
            verdict = judgments.get(('claim', claim['claim_id']))
            if verdict is None:
                claim_metrics['missing'] += 1
            elif verdict['verdict'] == 'supported':
                if set(claim['event_ids']) & set(verdict['event_ids']):
                    claim_metrics['supported'] += 1
                else:
                    claim_metrics['unsupported'] += 1
            else:
                claim_metrics[verdict['verdict']] += 1
        _rate(claim_metrics, 'support_rate', claim_metrics['supported'], len(claims), 'no_claims')
        _rate(claim_metrics, 'contradicted_rate', claim_metrics['contradicted'], len(claims), 'no_claims')
    cited_items = claims + cited_findings
    citations = {'total': sum(len(item['event_ids']) for item in cited_items),
                 'invalid': sum(event_id not in events for item in cited_items
                                for event_id in item['event_ids']),
                 'items_with_invalid_citations': sum(
                     not set(item['event_ids']).issubset(events) for item in cited_items),
                 'null_reasons': {}}
    _rate(citations, 'invalid_rate', citations['invalid'], citations['total'], 'no_citations')

    controls = {}
    for disposition in ('benign', 'insufficient'):
        scoped_controls = [control for control in truth['controls']
                           if control['expected_disposition'] == disposition]
        section = {'eligible': len(scoped_controls),
                   'evaluated': len(scoped_controls) if accepted else 0,
                   'missing_or_failed': 0 if accepted else len(scoped_controls),
                   'correct_dispositions': 0, 'null_reasons': {}}
        alarms = 0
        for control in scoped_controls:
            relevant = {key: finding for key, finding in canonical.items()
                        if _scoped(finding, control)}
            alarm = any(finding['disposition'] == 'suspicious' for finding in relevant.values())
            alarms += int(alarm)
            section['correct_dispositions'] += int(
                not alarm and any(finding['disposition'] == disposition and supported(key)
                                  for key, finding in relevant.items()))
        if disposition == 'benign':
            section['false_alarms'] = alarms
            _rate(section, 'false_alarm_rate', alarms, section['evaluated'], 'no_evaluated_controls')
        if mechanical:
            # A correct benign/insufficient disposition is a semantic judgment.
            section['correct_dispositions'] = None
            section['correct_disposition_rate'] = None
            section['null_reasons']['correct_disposition_rate'] = NOT_MEASURED_MECHANICAL
        else:
            _rate(section, 'correct_disposition_rate', section['correct_dispositions'],
                  section['eligible'], 'no_eligible_controls')
        controls[disposition] = section

    truth_edges = {tuple(edge) for edge in truth['edges']
                   if edge[0] in eligible and edge[1] in eligible}
    edge_groups = {}
    for edge in edges:
        edge_groups.setdefault((aliases[edge[0]], aliases[edge[1]]), []).append(edge)
    supported_edges = set()
    for endpoints, group in sorted(edge_groups.items()):
        pair = (matched.get(endpoints[0]), matched.get(endpoints[1]))
        if mechanical:
            # Both endpoints mechanically matched and truth holds the ordered edge.
            if pair in truth_edges:
                supported_edges.add(pair)
            continue
        bound = [judgments.get(('edge', edge_item_id(edge))) for edge in group]
        states = {verdict['verdict'] for verdict in bound if verdict is not None}
        if len(states) > 1:
            conflicts.append({'item_kind': 'edge',
                              'item_ids': sorted(edge_item_id(edge) for edge in group)})
        if (pair in truth_edges and all(
                verdict is not None and verdict['verdict'] == 'supported'
                and verdict['event_ids'] for verdict in bound)):
            supported_edges.add(pair)
    chain = {'tp': len(supported_edges), 'fp': len(edge_groups) - len(supported_edges),
             'fn': len(truth_edges) - len(supported_edges),
             'eligible_edges': len(truth_edges),
             'visibility_limited_edges': len(truth['edges']) - len(truth_edges),
             'disputed_ignored': ignored_edges,
             'null_reasons': {}}
    _detection_rates(chain)

    labels = truth['assessment_labels']
    applicable = accepted and output['stage_key'] == 'handoff'
    answers = {answer['question_id']: answer['probability_suspicious']
               for answer in output.get('assessment_answers', [])} if applicable else {}
    if set(answers) - set(labels):
        raise BenchmarkError('unknown_reference', 'assessment_answers.question_id')
    calibration = {'eligible_questions': sum(label is not None for label in labels.values()),
                   'undecidable_questions': sum(label is None for label in labels.values()),
                   'supplied': 0, 'missing': 0, 'abstained': 0,
                   'applicable': applicable, 'null_reasons': {}}
    squared_errors = []
    for question_id, label in labels.items():
        if label is None:
            continue
        if question_id not in answers:
            calibration['missing'] += 1
        elif answers[question_id] is None:
            calibration['abstained'] += 1
        else:
            calibration['supplied'] += 1
            squared_errors.append((answers[question_id] - label) ** 2)
    _rate(calibration, 'decision_coverage', calibration['supplied'],
          calibration['eligible_questions'], 'no_decidable_questions')
    _rate(calibration, 'brier', math.fsum(squared_errors), calibration['supplied'],
          'no_supplied_probabilities' if applicable else 'no_accepted_handoff')
    diagnostics = {
        'matched_pairs': sorted(
            ({'step_id': step_id, 'finding_id': finding_id}
             for finding_id, step_id in matched.items()), key=lambda item: (item['step_id'], item['finding_id'])),
        'duplicate_findings': len(findings) - len(canonical),
        # Information only, never a penalty: revoked IDs score as their replacement.
        'technique_ids_revoked_used': sum(
            finding['technique_id'] is not None and technique_status(finding['technique_id']) == 'revoked'
            for finding in cited_findings),
        'duplicate_conflicts': len(conflicts), 'duplicate_conflict_items': conflicts,
        'scope_boundary_violations': len(scope_errors), 'scope_errors': scope_errors,
        'completed': accepted, 'diagnostic_only': accepted and output['stage_key'] != 'handoff',
        'visibility_limited_finding_ids': visibility_limited,
        # Plan gap kept explicit: stage outputs carry no execution-outcome
        # assertion, so only matched counts per truth outcome are measurable.
        'execution_outcome_correctness': None,
        'execution_outcome_correctness_reason': 'stage_output_has_no_execution_outcome_field',
        'execution_outcome_reported_as': 'detection.execution_outcomes_matched_counts_only',
        'scope_limitations': ['structural_checks_only_no_semantic_policy_inference']}
    ranking_blockers = []
    if missing:
        ranking_blockers.append('missing_adjudication')
    if conflicts:
        ranking_blockers.append('conflicting_duplicate_adjudication')
    if any(not (set(finding['event_ids']) & events) for finding in suspicious.values()):
        ranking_blockers.append('missing_model_citation')
    if diagnostics['diagnostic_only']:
        ranking_blockers.append('non_handoff_diagnostic')
    status = MECHANICAL if mechanical else 'provisional' if missing or conflicts else 'final'
    return {'status': status, 'adjudication': adjudication,
            'ranking_eligible': not ranking_blockers, 'ranking_blockers': ranking_blockers,
            'missing_adjudications': missing, 'detection': detection,
            'claims': claim_metrics, 'citations': citations, 'controls': controls,
            'chain_edges': chain, 'calibration': calibration, 'diagnostics': diagnostics}

"""Development-split error taxonomy: the human prompt-improvement feedback loop.

The report is written for the person revising role prompts. It is never sent to
a model, never fed back into a trial automatically, and is refused outright for
any experiment containing a holdout scenario (``holdout_feedback_refused``).

Evaluator truth leaks only as far as describing a miss requires: an ATT&CK
technique ID, a pseudonymous asset ID and a UTC window. Step IDs, support sets,
execution outcomes, observability, control IDs and expected dispositions are
never written. Model text is referenced by item ID, never copied.

Each item-level error is attributed to the earliest workflow stage whose
auto-advanced output introduced an equivalent assertion; later stages that
carried it forward are listed in ``propagated_to``. A miss is attributed to the
stage that dropped an earlier detection, to the earliest stage that reported it
without full support, or otherwise to ``handoff`` (``not_determinable``).

Diagnostics run on mechanical adjudication by default or on an optional human
adjudication file. Every error carries its ``basis``: ``mechanical_rules`` or
``human_verdicts`` when it depends on support verdicts, ``truth_comparison`` or
``public_evidence`` when it does not, and ``call_receipt`` for call failures.
"""
import html
import os
from collections import defaultdict
from pathlib import Path

from benchmark_adjudication import _fail, _sealed_snapshot, _template, load_adjudication, load_truths
from benchmark_comparison import FORMAT_FAILURES
from benchmark_contracts import (REVIEW_POLICY, STAGE_KEYS, _window, bundle_event_ids,
                                 canonical_bytes, digest_bytes)
from benchmark_holdout import write_new_file
from benchmark_scoring import (
    MECHANICAL, RUBRIC_VERSION, _parent_only, _technique, assertion_key, disputed_only, edge_item_id,
    mechanical_verdicts, score_output,
)
from benchmark_store import STAGE_ROLES


BASES = {MECHANICAL: 'mechanical_rules', 'human': 'human_verdicts'}
TRUTH_BASIS = 'truth_comparison'
EVIDENCE_BASIS = 'public_evidence'
CALL_BASIS = 'call_receipt'
TRUTH_LIMITATIONS = {
    'publisher_labels': 'Some truth is derived mechanically from dataset-publisher ground-truth labels, '
                        'never human-reviewed (publisher_labels).',
    'unreviewed_proposal': 'Some truth is an unreviewed proposed answer key (unreviewed_proposal).',
    'agent_consensus': 'Some truth is an agent consensus answer key: two independent AI drafts merged '
                       'mechanically, never human-reviewed (agent_consensus); findings citing only its disputed '
                       'records are ignored.'}


TAXONOMY = ('missed_eligible_step', 'wrong_asset', 'wrong_window', 'parent_only_technique',
            'unsupported_claim', 'contradicted_claim', 'invalid_citation', 'false_alarm_on_control',
            'unmatched_suspicious_finding', 'missing_assessment_probability', 'format_failure',
            'timeout_failure', 'transport_failure', 'other_call_failure', 'unsupported_chain_edge')
TRANSPORT_FAILURES = ('transport_failed', 'dispatch_interrupted', 'execution_failed',
                      'previous_dispatch_unknown')
# Every later stage in this chain depends transitively on all earlier stages.
CHAIN = ('analysis', 'review', 'handoff')


def _span(value):
    return _window(value, 'window_utc')


def _window_text(value):
    start, end = _span(value)
    return {'start_inclusive': start.isoformat(), 'end_exclusive': end.isoformat()}


def _overlaps(left, right):
    a, b = _span(left['window_utc'])
    c, d = _span(right['window_utc'])
    return a < d and c < b


def _scoped(left, right):
    return left['asset_id'] == right['asset_id'] and _overlaps(left, right)


def _finding_key(finding):
    window = _window_text(finding['window_utc'])
    return (finding['asset_id'], _technique(finding), window['start_inclusive'],
            window['end_exclusive'], finding['disposition'])


def _claim_key(claim):
    return (' '.join(claim['text'].split()).casefold(), tuple(sorted(claim['event_ids'])))


class _Output:
    """Errors one sealed stage output exhibits against frozen truth and verdicts."""

    def __init__(self, item, truth, evidence, verdicts, trial_id, mode):
        output = item['output']
        self.mechanical = mode == MECHANICAL
        self.basis = BASES[mode]
        self.metrics = score_output(output, truth, evidence, verdicts, trial_id=trial_id,
                                    output_sha256=item['output_sha256'], adjudication=mode)
        self.errors = []
        self.unadjudicated = len(self.metrics['missing_adjudications'])
        events = bundle_event_ids(evidence)
        if self.mechanical:
            judged = mechanical_verdicts(output['findings'], truth, events)
        else:
            judged = {(verdict['item_kind'], verdict['item_id']): verdict for verdict in verdicts}
        findings = {finding['finding_id']: finding for finding in output['findings']}
        # Findings citing only disputed agent-consensus records are ignored by scoring, so they are never errors.
        ignored = {finding_id for finding_id, finding in findings.items() if disputed_only(finding, truth)}
        kept = [finding for finding in output['findings'] if finding['finding_id'] not in ignored]
        diagnostics = self.metrics['diagnostics']
        steps_by_key = {assertion_key(findings[pair['finding_id']]): pair['step_id']
                        for pair in diagnostics['matched_pairs']}
        limited = {assertion_key(findings[finding_id])
                   for finding_id in diagnostics['visibility_limited_finding_ids']}
        outside = {error['item_id'] for error in diagnostics['scope_errors']}
        self.matched_steps = set(steps_by_key.values())
        self.exact_steps = {step['step_id'] for step in truth['steps']
                            for finding in kept
                            if finding['disposition'] == 'suspicious'
                            and _technique(finding) == _technique(step) and _scoped(finding, step)}
        eligible = {step['step_id'] for step in truth['steps'] if step['observability'] == 'sufficient'}

        for kind, items, id_field in (('claim', output['claims'], 'claim_id'),
                                      ('finding', kept, 'finding_id')):
            for value in items:
                content = (kind,) + (_claim_key(value) if kind == 'claim' else _finding_key(value))
                identity = {'item_kind': kind, 'item_id': value[id_field]}
                invalid = sorted(eid for eid in set(value['event_ids']) if eid not in events)
                if invalid:
                    self._add('invalid_citation', content + tuple(invalid),
                              dict(identity, invalid_event_ids=invalid), EVIDENCE_BASIS)
                if self.mechanical:
                    # Rule verdicts are not semantic judgments: claim support is not
                    # measured, contradicted findings surface as control false alarms
                    # and incomplete support is classified per finding below.
                    continue
                verdict = judged.get((kind, value[id_field]))
                if verdict is None:
                    continue
                if verdict['verdict'] == 'contradicted':
                    self._add('contradicted_claim', content, identity)
                elif verdict['verdict'] == 'insufficient':
                    self._add('unsupported_claim', content, dict(identity, reason='adjudicated_insufficient'))
                elif kind == 'claim' and not set(value['event_ids']) & set(verdict['event_ids']):
                    self._add('unsupported_claim', content,
                              dict(identity, reason='citations_outside_supporting_events'))

        for finding in sorted(kept, key=lambda value: value['finding_id']):
            if finding['disposition'] != 'suspicious':
                continue
            key = assertion_key(finding)
            if key in steps_by_key or key in limited:
                continue
            self._classify(finding, truth, judged, eligible, outside, steps_by_key)

        for control in truth['controls']:
            alarms = sorted(finding['finding_id'] for finding in kept
                            if finding['disposition'] == 'suspicious' and _scoped(finding, control))
            if alarms:
                window = _window_text(control['window_utc'])
                self._add('false_alarm_on_control',
                          (control['asset_id'], window['start_inclusive'], window['end_exclusive']),
                          {'asset_id': control['asset_id'], 'window_utc': window, 'finding_ids': alarms},
                          TRUTH_BASIS)

        truth_edges = {tuple(edge) for edge in truth['edges'] if edge[0] in eligible and edge[1] in eligible}
        for edge in output.get('chain_edges', []):
            if set(edge) & ignored:
                continue
            ends = [findings.get(finding_id) for finding_id in edge]
            pair = tuple(steps_by_key.get(assertion_key(end)) if end is not None else None for end in ends)
            verdict = judged.get(('edge', edge_item_id(edge)))
            if None in pair:
                reason = 'endpoint_not_a_supported_detection'
            elif pair not in truth_edges:
                reason = 'link_or_order_not_supported_by_truth'
            elif verdict is None:
                continue
            elif verdict['verdict'] != 'supported' or not verdict['event_ids']:
                reason = 'adjudicated_' + verdict['verdict']
            else:
                continue
            key = tuple(_finding_key(end) if end is not None else None for end in ends)
            self._add('unsupported_chain_edge', key,
                      {'item_kind': 'edge', 'item_id': edge_item_id(edge),
                       'from_finding_id': edge[0], 'to_finding_id': edge[1], 'reason': reason})

        if output['stage_key'] == 'handoff':
            answers = {answer['question_id']: answer['probability_suspicious']
                       for answer in output.get('assessment_answers', [])}
            questions = {question['question_id']: question for question in evidence['assessment_questions']}
            for question_id, label in sorted(truth['assessment_labels'].items()):
                if label is None or answers.get(question_id) is not None:
                    continue
                question = questions[question_id]
                self._add('missing_assessment_probability', (question_id,),
                          {'question_id': question_id, 'asset_id': question['asset_id'],
                           'window_utc': _window_text(question['window_utc']),
                           'reason': 'abstained' if question_id in answers else 'missing'}, TRUTH_BASIS)

    def _add(self, kind, key, detail, basis=None):
        self.errors.append({'kind': kind, 'key': (kind,) + tuple(key), 'detail': detail,
                            'basis': basis or self.basis})

    def _classify(self, finding, truth, judged, eligible, outside, steps_by_key):
        steps = truth['steps']
        technique = finding['technique_id']
        key = ('finding',) + _finding_key(finding)
        identity = {'item_kind': 'finding', 'item_id': finding['finding_id'],
                    'asset_id': finding['asset_id'], 'technique_id': technique,
                    'window_utc': _window_text(finding['window_utc'])}
        exact = [step for step in steps if _technique(step) == _technique(finding) and _scoped(finding, step)]
        if exact:
            verdict = judged.get(('finding', finding['finding_id']))
            if self.mechanical and verdict['verdict'] != 'supported':
                self._add('unsupported_claim', key, dict(identity, reason='incomplete_support_set'))
                return
            if verdict is None or verdict['verdict'] != 'supported':
                return  # The verdict error (or missing adjudication) is already recorded.
            if finding['finding_id'] in outside:
                reason = 'outside_public_scope'
            elif any(set(support).issubset(set(finding['event_ids']) & set(verdict['event_ids']))
                     for step in exact for support in step['support_sets']):
                reason = 'step_already_matched'
            else:
                self._add('unsupported_claim', key, dict(identity, reason='incomplete_support_set'))
                return
            self._add('unmatched_suspicious_finding', key, dict(identity, reason=reason))
            return
        parents = [step for step in steps if _parent_only(finding, step) and _scoped(finding, step)]
        if parents:
            self._add('parent_only_technique', key,
                      dict(identity, expected_technique_id=sorted(_technique(step) for step in parents)[0]),
                      TRUTH_BASIS)
            return
        related = [step for step in steps
                   if _technique(step) == _technique(finding) or _parent_only(finding, step)]
        same_asset = sorted((step for step in related if step['asset_id'] == finding['asset_id']),
                            key=lambda step: step['step_id'])
        if same_asset:
            self._add('wrong_window', key,
                      dict(identity, expected_window_utc=_window_text(same_asset[0]['window_utc'])),
                      TRUTH_BASIS)
            return
        same_window = sorted((step for step in related if _overlaps(finding, step)),
                             key=lambda step: step['step_id'])
        if same_window:
            self._add('wrong_asset', key, dict(identity, expected_asset_id=same_window[0]['asset_id']),
                      TRUTH_BASIS)
            return
        if any(_scoped(finding, control) for control in truth['controls']):
            return  # Reported once per control as false_alarm_on_control.
        self._add('unmatched_suspicious_finding', key, dict(identity, reason='no_related_truth_step'),
                  TRUTH_BASIS)


def _advanced(seal):
    """Latest bound auto-advanced submission per stage (what flowed forward)."""
    return dict(seal['advanced'])


def _call_kind(call):
    reason = (call.get('receipt') or {}).get('failure_reason')
    if call['status'] in ('reserved', 'unknown'):
        return 'transport_failure', reason or 'outcome_unknown'
    if call['status'] != 'failed':
        return None, None
    if reason in FORMAT_FAILURES:
        return 'format_failure', reason
    if reason == 'timeout':
        return 'timeout_failure', reason
    if reason in TRANSPORT_FAILURES:
        return 'transport_failure', reason
    return 'other_call_failure', reason


def _trial(trial, seal, case, truth, verdicts, calls, mode):
    evidence = case['evidence']
    advanced = _advanced(seal)
    handoffs = [item for item in seal['submissions'] if item['stage_key'] == 'handoff']
    if seal['accepted'] is not None:
        basis_name, basis = 'team_output', seal['accepted']
    elif 'handoff' in advanced:
        basis_name, basis = 'auto_advanced', advanced['handoff']
    elif handoffs:
        basis_name, basis = 'unadvanced_latest', handoffs[-1]
    else:
        basis_name, basis = 'no_handoff_output', None
    outputs = [(stage, advanced[stage]) for stage in STAGE_KEYS if stage != 'handoff' and stage in advanced]
    if basis is not None:
        outputs.append(('handoff', basis))
    recorded, errors, present, unadjudicated = {}, [], {}, 0
    matched = set()
    for stage, item in outputs:
        analysis = _Output(item, truth, evidence, verdicts[(trial['trial_id'], item['output_sha256'])],
                           trial['trial_id'], mode)
        present[stage] = analysis.exact_steps
        unadjudicated += analysis.unadjudicated
        if stage == 'handoff':
            matched = analysis.matched_steps
        for error in analysis.errors:
            existing = recorded.get(error['key'])
            if existing is not None:
                if stage != existing['stage_key'] and stage not in existing['propagated_to']:
                    existing['propagated_to'].append(stage)
                continue
            record = {'kind': error['kind'], 'stage_key': stage, 'role': STAGE_ROLES[stage],
                      'attribution': 'introduced', 'basis': error['basis'],
                      'output_sha256': item['output_sha256'], 'detail': error['detail'], 'propagated_to': []}
            recorded[error['key']] = record
            errors.append(record)
    for step in sorted(truth['steps'], key=lambda value: value['step_id']):
        if step['observability'] != 'sufficient' or step['step_id'] in matched:
            continue
        detected = [stage for stage, _ in outputs if step['step_id'] in present[stage]]
        attribution = 'introduced'
        if basis is None:
            stage, reason, attribution = 'handoff', 'no_handoff_output', 'not_determinable'
        elif not detected:
            stage, reason, attribution = 'handoff', 'never_reported', 'not_determinable'
        elif step['step_id'] not in present['handoff']:
            first = STAGE_KEYS.index(detected[0])
            stage = next((key for key in CHAIN if STAGE_KEYS.index(key) > first and key in present
                          and step['step_id'] not in present[key]), 'handoff')
            reason = 'dropped_after_' + detected[0]
        else:
            stage, reason = detected[0], 'reported_without_full_support'
        errors.append({'kind': 'missed_eligible_step', 'stage_key': stage, 'role': STAGE_ROLES[stage],
                       'attribution': attribution, 'basis': BASES[mode], 'output_sha256': None,
                       'detail': {'technique_id': step['technique_id'], 'asset_id': step['asset_id'],
                                  'window_utc': _window_text(step['window_utc']), 'reason': reason},
                       'propagated_to': []})
    for call in sorted(calls, key=lambda value: (STAGE_KEYS.index(value['spec']['stage_key']),
                                                 value['spec']['attempt_index'], value['spec']['component'])):
        kind, reason = _call_kind(call)
        if kind is None:
            continue
        stage = call['spec']['stage_key']
        detail = {'call_id': call['call_id'], 'component': call['spec']['component'],
                  'attempt_index': call['spec']['attempt_index'], 'failure_reason': reason}
        if kind == 'format_failure':
            # Why the validator refused it; the evaluator-only rejected answer is
            # referenced for a developer, never fed to a model or scored.
            rejected = (call.get('receipt') or {}).get('rejected_response') or {}
            detail.update(error_code=rejected.get('error_code'), error_field=rejected.get('error_field'),
                          rejected_response_artifact=rejected.get('artifact'),
                          rejected_truncated=rejected.get('truncated'))
        errors.append({'kind': kind, 'stage_key': stage, 'role': STAGE_ROLES[stage],
                       'attribution': 'observed', 'basis': CALL_BASIS, 'output_sha256': None,
                       'detail': detail, 'propagated_to': []})
    by_stage = {}
    for stage in STAGE_KEYS:
        counts = defaultdict(int)
        for error in errors:
            if error['stage_key'] == stage:
                counts[error['kind']] += 1
        by_stage[stage] = {'role': STAGE_ROLES[stage],
                           'advanced_output_sha256': advanced[stage]['output_sha256'] if stage in advanced else None,
                           'error_counts': dict(sorted(counts.items()))}
    return {'trial_id': trial['trial_id'], 'team_id': trial['team_id'], 'case_id': trial['case_id'],
            'scenario_id': trial['scenario_id'], 'family_id': case['scenario']['family_id'],
            'repetition': trial['repetition'], 'trial_status': seal['trial_status'],
            'terminal_reason': trial.get('terminal_reason'), 'handoff_basis': basis_name,
            'unadjudicated_items': unadjudicated, 'errors': errors, 'by_stage': by_stage}


def _aggregate(trials):
    rows = defaultdict(lambda: {'errors': 0, 'trials': set(), 'repetitions': set(), 'scenarios': set()})
    by_role = defaultdict(lambda: defaultdict(int))
    formats = defaultdict(int)
    for trial in trials:
        for error in trial['errors']:
            row = rows[(trial['team_id'], error['role'], error['kind'])]
            row['errors'] += 1
            row['trials'].add(trial['trial_id'])
            row['repetitions'].add(trial['repetition'])
            row['scenarios'].add(trial['scenario_id'])
            by_role[error['role']][error['kind']] += 1
            if error['kind'] == 'format_failure':
                detail = error['detail']
                formats[(trial['team_id'], error['role'], detail['failure_reason'],
                         detail['error_code'] or '', detail['error_field'] or '')] += 1
    return {'by_team_role_kind': [{'team_id': team, 'role': role, 'kind': kind, 'errors': row['errors'],
                                   'trials_affected': len(row['trials']),
                                   'repetitions_affected': sorted(row['repetitions']),
                                   'scenarios_affected': len(row['scenarios'])}
                                  for (team, role, kind), row in sorted(rows.items())],
            'by_role_kind': {role: dict(sorted(kinds.items())) for role, kinds in sorted(by_role.items())},
            'format_failures_by_reason': [
                {'team_id': team, 'role': role, 'failure_reason': reason, 'error_code': code or None,
                 'error_field': field or None, 'calls': count}
                for (team, role, reason, code, field), count in sorted(formats.items())]}


def _markdown(report):
    def cell(value):
        if value is None:
            return 'null'
        text = html.escape(str(value), quote=True).replace('\r', ' ').replace('\n', ' ')
        for token, escaped in (('|', '&#124;'), ('`', '&#96;'), ('[', '&#91;'),
                               (']', '&#93;'), ('*', '&#42;'), ('_', '&#95;')):
            text = text.replace(token, escaped)
        return text

    lines = ['# Development diagnostics (human prompt-improvement feedback)', '',
             'Experiment {}; rubric {}. Development split only. Never feed this report to a model.'.format(
                 cell(report['experiment_id']), cell(report['rubric_version'])), '',
             'Adjudication: {} ({}). Review policy: {}. Truth attestation: {}.'.format(
                 cell(report['adjudication']), cell(report['adjudication_basis']), cell(report['review_policy']),
                 cell(', '.join(sorted(set(report['truth_attestation'].values()))))), '',
             '## Errors by team, role and kind (all repetitions)', '',
             '| Team | Role | Kind | Errors | Trials | Repetitions |', '| --- | --- | --- | --- | --- | --- |']
    lines.extend('| {} | {} | {} | {} | {} | {} |'.format(
        cell(row['team_id']), cell(row['role']), cell(row['kind']), row['errors'], row['trials_affected'],
        cell(', '.join(str(value) for value in row['repetitions_affected'])))
        for row in report['aggregate']['by_team_role_kind'])
    lines.extend(['', '## Format failures by validator reason', '',
                  '| Team | Role | Failure | Error code | Error field | Calls |',
                  '| --- | --- | --- | --- | --- | --- |'])
    lines.extend('| {} | {} | {} | {} | {} | {} |'.format(
        cell(row['team_id']), cell(row['role']), cell(row['failure_reason']), cell(row['error_code']),
        cell(row['error_field']), row['calls'])
        for row in report['aggregate']['format_failures_by_reason'])
    lines.extend(['', '## Per trial', ''])
    for trial in report['trials']:
        lines.append('### {} / {} / repetition {} ({}, handoff basis {})'.format(
            cell(trial['team_id']), cell(trial['scenario_id']), trial['repetition'],
            cell(trial['trial_status']), cell(trial['handoff_basis'])))
        lines.append('')
        if not trial['errors']:
            lines.extend(['No errors found.', ''])
            continue
        lines.extend(['| Stage | Role | Kind | Basis | Attribution | Detail | Propagated to |',
                      '| --- | --- | --- | --- | --- | --- | --- |'])
        lines.extend('| {} | {} | {} | {} | {} | {} | {} |'.format(
            cell(error['stage_key']), cell(error['role']), cell(error['kind']), cell(error['basis']),
            cell(error['attribution']), cell(canonical_bytes(error['detail']).decode('utf-8')),
            cell(', '.join(error['propagated_to'])))
            for error in trial['errors'])
        lines.append('')
    lines.extend(['## Limitations', ''])
    lines.extend('- ' + cell(item) for item in report['limitations'])
    lines.append('')
    return '\n'.join(lines)


def _markdown_path(path):
    path = Path(os.path.abspath(os.fspath(path)))
    return path.with_suffix('.md') if path.suffix.casefold() == '.json' else path.with_name(path.name + '.md')


def diagnose(store, experiment_id, truth_dir, adjudication, output_path):
    """Write JSON plus Markdown error diagnostics for a development-only experiment.

    ``adjudication`` None applies the mechanical rules; a path uses human verdicts.
    """
    snapshot, seals = _sealed_snapshot(store, experiment_id)
    frozen = snapshot['experiment']
    # Refuse before any truth is read: holdout answers must never shape prompts.
    if any(case['scenario']['split'] == 'holdout' for case in frozen['cases']):
        _fail('holdout_feedback_refused', 'scenario.split')
    json_path = Path(os.path.abspath(os.fspath(output_path)))
    markdown_path = _markdown_path(json_path)
    for path in (json_path, markdown_path):
        if path.exists() or path.is_symlink():
            _fail('already_exists', 'diagnostics.output')
    truths = load_truths(truth_dir, frozen)
    freezes = [event for event in snapshot['events'] if event['payload'].get('record_type') == 'truth_frozen']
    for event in freezes:
        store._verify_truth_freeze(event, frozen)
    if freezes:
        expected = {item['case_id']: item['truth_sha256'] for item in freezes[0]['payload']['cases']}
        if expected != {key: value['sha256'] for key, value in truths.items()}:
            _fail('fingerprint_conflict', 'truth.frozen')
    verdicts, mode, adjudication_sha, _ = load_adjudication(adjudication, _template(snapshot, seals), frozen)
    cases = {case['evidence']['case_id']: case for case in frozen['cases']}
    trials = []
    for trial in sorted(snapshot['trials'], key=lambda value: (value['team_id'], value['scenario_id'],
                                                               value['repetition'], value['trial_id'])):
        calls = [call for call in snapshot['calls'] if call['spec']['trial_id'] == trial['trial_id']]
        trials.append(_trial(trial, seals[trial['trial_id']], cases[trial['case_id']],
                             truths[trial['case_id']]['truth'], verdicts, calls, mode))
    limitations = [
        'Never fed to a model automatically; a human decides any prompt change.',
        'Development split only; holdout experiments are refused.',
        'Truth is disclosed only as technique ID, asset pseudonym and window for misses.',
        'Attribution is the earliest auto-advanced stage output with an equivalent assertion; '
        'misses without a determinable origin are attributed to handoff.',
        'Every stage auto-advanced without human review.',
        'Execution-outcome correctness is not measured: stage outputs carry no outcome field.']
    if mode == MECHANICAL:
        limitations.append('Mechanical adjudication: deterministic support-set rules, not human verdicts; '
                           'claim semantic support is not_measured_mechanical and never reported as an error.')
    else:
        limitations.append('Unadjudicated items are counted, not classified as errors.')
    for attestation in sorted({value['attestation'] for value in truths.values()} - {'human_attested'}):
        limitations.append(TRUTH_LIMITATIONS[attestation])
    report = {'schema_version': 1, 'rubric_version': RUBRIC_VERSION, 'experiment_id': experiment_id,
              'split': 'development', 'purpose': 'human_prompt_improvement_only',
              'adjudication': mode, 'adjudication_basis': BASES[mode], 'review_policy': REVIEW_POLICY,
              'adjudication_sha256': adjudication_sha, 'truth_frozen': bool(freezes),
              'truth_sha256': {key: value['sha256'] for key, value in sorted(truths.items())},
              'truth_attestation': {key: value['attestation'] for key, value in sorted(truths.items())},
              'taxonomy': list(TAXONOMY), 'trials': trials, 'aggregate': _aggregate(trials),
              'limitations': limitations}
    data = canonical_bytes(report) + b'\n'
    write_new_file(json_path, data, 'diagnostics.output')
    try:
        write_new_file(markdown_path, _markdown(report).encode('utf-8'), 'diagnostics.output')
    except BaseException:
        json_path.unlink()
        raise
    return {'experiment_id': experiment_id, 'status': 'diagnosed', 'trials': len(trials),
            'errors': sum(len(trial['errors']) for trial in trials),
            'json': str(json_path), 'markdown': str(markdown_path), 'sha256': digest_bytes(data)}

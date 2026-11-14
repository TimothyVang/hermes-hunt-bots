"""Pure, snapshot-only full-team scorecards and paired family-cluster comparisons.

This project's rubric is not MITRE certification. Models are treatments, not
pairing keys; rendered prompts legitimately differ after predecessor answers.
Deployment (cloud/local/hybrid), runtime facts and harness versions are reported
treatment attributes, never cohort controls; only a local-vs-local comparison
requires both sides' runtime facts so hardware differences stay visible.

Every stage auto-advances, so there is one scored variant, ``team_output``.
Adjudication (``mechanical`` or ``human``), truth attestation, review policy,
truth freeze and timing contention are cohort controls: cohorts that differ in
any of them are ``not_comparable`` and never ranked together. A mechanical
cohort settles at status ``mechanical``; only human adjudication is ``final``.
"""

import hashlib
import itertools
import json
import math
import random
from collections import defaultdict


VARIANTS = ('team_output',)
ADJUDICATIONS = ('human', 'mechanical')
SETTLED_STATUS = {'human': 'final', 'mechanical': 'mechanical'}
BOOTSTRAP_SAMPLES = 2000
BOOTSTRAP_SEED = 1729
AXES = ('os', 'network', 'identity_domain', 'operational_domain', 'dns_domain',
        'difficulty', 'sophistication', 'ioc_regime')
RATE_NAMES = {'precision', 'recall', 'f1', 'support_rate', 'contradicted_rate',
              'invalid_rate', 'false_alarm_rate', 'correct_disposition_rate',
              'decision_coverage', 'brier'}
# Scenarios without eligible attack steps contribute false alarms through
# controls.benign, never an asymmetric 0-versus-undefined detection rate.
DETECTION_RATES = ('detection.precision', 'detection.recall', 'detection.f1')
FORMAT_FAILURES = ('invalid_response', 'empty_response', 'tool_response', 'output_limit')
FAILED_STATUSES = ('failed', 'blocked', 'terminated')
LOCAL_RUNTIME_FACTS = ('server', 'server_version', 'context_configuration', 'concurrency')


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)


def _digest(value):
    return hashlib.sha256(_canonical(value).encode('utf-8')).hexdigest()


def _number(value):
    return type(value) in (int, float) and math.isfinite(value)


def _mean(values):
    known = [value for value in values if _number(value)]
    return sum(known) / len(known) if known else None


def _measurement(values):
    known = [value for value in values if _number(value)]
    return {'total': sum(known) if values and len(known) == len(values) else None,
            'known_subtotal': sum(known) if known else None,
            'known_count': len(known), 'unknown_count': len(values) - len(known)}


def _leaves(value, prefix=''):
    result = {}
    if not isinstance(value, dict):
        return result
    for key, item in value.items():
        path = prefix + '.' + key if prefix else key
        if isinstance(item, dict) and key != 'null_reasons':
            result.update(_leaves(item, path))
        elif _number(item) or item is None:
            result[path] = item
    return result


def _null_reasons(metrics):
    reasons = []
    for key, value in metrics.items():
        if key == 'null_reasons':
            items = value.values() if isinstance(value, dict) else value if isinstance(value, list) else []
            reasons.extend(item for item in items if isinstance(item, str))
        elif isinstance(value, dict):
            reasons.extend(_null_reasons(value))
    return reasons


def _valid_score(score, trial, scenario, rubric):
    if not isinstance(score, dict) or score.get('schema_version') != 1:
        return False
    required = {'variant', 'case_id', 'scenario_id', 'family_id', 'team_id',
                'repetition', 'output_sha256', 'truth_sha256', 'adjudication_sha256',
                'truth_frozen', 'status', 'completed', 'trial_status', 'metrics',
                'adjudication', 'truth_attestation', 'review_policy'}
    if not required.issubset(score) or score.get('rubric_version') != rubric:
        return False
    if score['adjudication'] not in ADJUDICATIONS or score['status'] not in (
            'provisional', SETTLED_STATUS[score['adjudication']]) or any(
            type(score[key]) is not bool for key in ('completed', 'truth_frozen')):
        return False
    if any(score[key] != trial.get(key) for key in ('case_id', 'scenario_id', 'team_id', 'repetition')):
        return False
    if score['family_id'] != scenario.get('family_id'):
        return False
    metrics = score['metrics']
    if (not isinstance(metrics, dict) or metrics.get('adjudication') != score['adjudication']
            or metrics.get('status') not in ('provisional', SETTLED_STATUS[score['adjudication']])):
        return False
    if any(not isinstance(metrics.get(key), dict) for key in
           ('detection', 'claims', 'citations', 'controls', 'chain_edges', 'calibration', 'diagnostics')):
        return False
    if type(metrics.get('ranking_eligible')) is not bool or not isinstance(metrics.get('ranking_blockers'), list):
        return False
    sections = {
        'claims': {'total', 'supported', 'contradicted', 'insufficient', 'missing', 'support_rate', 'contradicted_rate'},
        'citations': {'total', 'invalid', 'invalid_rate', 'items_with_invalid_citations'},
        'chain_edges': {'tp', 'fp', 'fn', 'eligible_edges', 'visibility_limited_edges', 'precision', 'recall', 'f1'},
        'calibration': {'eligible_questions', 'undecidable_questions', 'supplied', 'missing', 'abstained',
                        'decision_coverage', 'brier', 'applicable'},
        'diagnostics': {'duplicate_findings', 'duplicate_conflicts', 'scope_boundary_violations'},
    }
    if any(not fields.issubset(metrics[section]) for section, fields in sections.items()):
        return False
    for kind in ('benign', 'insufficient'):
        control = metrics['controls'].get(kind)
        required_control = {'eligible', 'evaluated', 'missing_or_failed', 'correct_dispositions', 'correct_disposition_rate'}
        if kind == 'benign':
            required_control.update(('false_alarms', 'false_alarm_rate'))
        if not isinstance(control, dict) or not required_control.issubset(control):
            return False
    detection = metrics['detection']
    for key in ('tp', 'fp', 'fn', 'eligible_steps', 'visibility_limited_steps', 'visibility_limited_detections',
                'truth_correct_unsupported', 'truth_incorrect', 'parent_technique_only'):
        if type(detection.get(key)) is not int or detection[key] < 0:
            return False
    for key in ('precision', 'recall', 'f1'):
        if key not in detection or (detection[key] is not None and
                (not _number(detection[key]) or not 0 <= detection[key] <= 1)):
            return False
    return True


def _identity(calls):
    """Identity from receipts that carry a reported model, or produced output.

    A failed call that never returned a model is a failure (counted in the
    failure rates), not an identity observation. A completed output without a
    reported model is unverified, and any reported mismatch always blocks.
    """
    receipts = [(call, call.get('receipt') or {}) for call in calls]
    if any(receipt.get('identity_status') == 'reported_mismatch' for _, receipt in receipts):
        return 'reported_mismatch'
    judged = [receipt.get('identity_status', 'unreported') for call, receipt in receipts
              if receipt.get('model_returned') is not None or call.get('status') == 'completed']
    return 'reported_match' if judged and all(item == 'reported_match' for item in judged) else 'unreported'


def _team_controls(team, calls):
    limits = {role: {key: spec.get(key) for key in ('timeout_seconds', 'max_output_tokens')}
              for role, spec in sorted(team.get('roles', {}).items())}
    return {'identity': _identity(calls), 'role_limits': limits}


def _team_attributes(team, calls):
    """Reported treatment attributes: visible, never cohort or pairing keys."""
    runtime = {key: value for key, value in team.get('runtime_facts', {}).items()
               if key != 'model_weight_sha256'}
    versions = {key: sorted({call.get('spec', {}).get(key) for call in calls
                            if call.get('spec', {}).get(key) is not None})
                for key in ('adapter_sha256', 'executable_sha256', 'executable_version')}
    # Schema-constrained decoding is a model setting: a treatment, never a control.
    structured = sorted(role for role, spec in team.get('roles', {}).items()
                        if spec.get('parameters', {}).get('structured_output') is True)
    return {'deployment': team.get('deployment'), 'runtime_facts': runtime,
            'runtime_versions': versions, 'structured_output_roles': structured}


def _labels(case):
    scenario, evidence = case['scenario'], case['evidence']
    coverage = scenario.get('coverage', {})
    actual_os = sorted({asset.get('os_family') for asset in evidence.get('assets', [])
                        if asset.get('os_family') is not None})
    labels = {axis: sorted(coverage.get(axis, [])) for axis in AXES
              if axis not in ('os', 'difficulty', 'sophistication', 'ioc_regime')}
    labels['os'] = actual_os
    labels['difficulty'] = [scenario.get('difficulty', {}).get('band')]
    labels['sophistication'] = [scenario.get('sophistication', {}).get('band')]
    labels['ioc_regime'] = [scenario['ioc_regime']] if scenario.get('ioc_regime') else []
    mismatch = set(actual_os) != set(coverage.get('os', []))
    return labels, mismatch


def _condition(case):
    return ('with_detector_alerts' if any(event.get('fields', {}).get('detector_attack_ids')
            for event in case['evidence'].get('events', [])) else 'raw_telemetry')


def _summary(rows):
    scenarios = defaultdict(list)
    for row in rows:
        scenarios[row['scenario_id']].append(row)
    paths = sorted({path for row in rows for path in row['numeric_metrics']})
    aggregates = {}
    attack_free = sorted(scenario_id for scenario_id, group in scenarios.items()
                         if any(row['attack_free'] for row in group))
    for path in paths:
        selected = [(scenario_id, group) for scenario_id, group in sorted(scenarios.items())
                    if path not in DETECTION_RATES or scenario_id not in attack_free]
        per_scenario = [_mean([row['numeric_metrics'].get(path) for row in group])
                        for _, group in selected]
        values = [row['numeric_metrics'].get(path) for row in rows]
        known = [value for value in values if _number(value)]
        aggregates[path] = {'macro_mean': _mean(per_scenario),
                            'known_trials': len(known), 'unknown_trials': len(rows) - len(known),
                            'defined_scenarios': sum(value is not None for value in per_scenario),
                            'undefined_scenarios': sum(value is None for value in per_scenario)}
        if path in DETECTION_RATES:
            aggregates[path]['excluded_attack_free_scenarios'] = len(scenarios) - len(selected)
        if path.rsplit('.', 1)[-1] not in RATE_NAMES:
            aggregates[path]['raw_total'] = sum(known) if known else None
    statuses = defaultdict(int)
    for row in rows:
        statuses[row['trial_status']] += 1
    completed = sum(row['completed'] is True for row in rows)
    known_completion = sum(row['completed'] is not None for row in rows)
    failure_counts = {key: sum(row[key] for row in rows)
                      for key in ('format_error', 'timeout', 'unknown', 'failed')}
    failure_counts.update({'scheduled': len(rows), 'completed': completed,
                           'completion_unknown': len(rows) - known_completion,
                           'completion_rate': completed / len(rows) if rows else None,
                           'completion_failure_rate': (known_completion - completed) / len(rows) if rows else None})
    for key in ('format_error', 'timeout', 'unknown', 'failed'):
        failure_counts[key + '_rate'] = failure_counts[key] / len(rows) if rows else None
    coverage = {axis: sorted({tag for row in rows for tag in row['labels'][axis] if tag is not None})
                for axis in AXES}
    counts = {key: aggregates.get('detection.' + key, {}).get('raw_total')
              for key in ('tp', 'fp', 'fn', 'visibility_limited_detections')}
    counts['benign_control_false_alarms'] = aggregates.get(
        'controls.benign.false_alarms', {}).get('raw_total')
    return {'scheduled_trials': len(rows), 'scored_trials': sum(row['score'] is not None for row in rows),
            'attack_free_scenario_ids': attack_free,
            'settled_trials': sum(row['settled'] for row in rows),
            'scenario_count': len(scenarios), 'family_count': len({row['family_id'] for row in rows}),
            'scenario_ids': sorted(scenarios), 'trial_statuses': dict(sorted(statuses.items())),
            'detection': dict(counts, **{key: aggregates.get('detection.' + key, {}).get('macro_mean')
                                      for key in ('precision', 'recall', 'f1')}),
            'metrics': aggregates, 'failures': failure_counts, 'coverage': coverage,
            'measurements': _measurements(rows),
            'offline_time_to_first_supported_finding_ms': _measurement([
                row['score'].get('offline_time_to_first_supported_finding_ms') if row['score'] else None
                for row in rows]),
            'null_reasons': sorted({reason for row in rows for reason in row['null_reasons']})}


def _measurements(rows):
    calls = [call for row in rows for call in row['calls']]
    receipts = [call.get('receipt') or {} for call in calls]
    return {'calls': len(calls), 'scope': 'whole_trial_lifetime_including_retries_and_checker',
            'model_active_ms': _measurement([receipt.get('elapsed_ms') for receipt in receipts]),
            'api_cost_usd': _measurement([receipt.get('cost', {}).get('api_cost_usd') for receipt in receipts]),
            'local_compute_cost_usd': _measurement([receipt.get('cost', {}).get('local_compute_cost_usd') for receipt in receipts]),
            'local_energy_cost_usd': _measurement([receipt.get('cost', {}).get('local_energy_cost_usd') for receipt in receipts]),
            'provider_reported_usage': {key: _measurement([receipt.get('usage', {}).get(key) for receipt in receipts])
                                        for key in ('input_tokens', 'output_tokens', 'cached_input_tokens', 'reasoning_tokens')},
            'query_store_usage': {key: _measurement([(receipt.get('query_usage') or {}).get(key) for receipt in receipts])
                                  for key in ('queries_executed', 'rows_returned_total',
                                              'bytes_returned_total', 'ioc_lookups')},
            'evidence_checker_calls': sum(call.get('spec', {}).get('component') == 'evidence_checker' for call in calls)}


def _percentile(values, probability):
    position = (len(values) - 1) * probability
    lower, upper = math.floor(position), math.ceil(position)
    return values[lower] + (values[upper] - values[lower]) * (position - lower)


def _bootstrap(scenarios, paired=True):
    """Sample families, retaining all scenarios/windows in each sampled family."""
    families = defaultdict(list)
    for scenario in scenarios:
        if scenario['difference'] is not None:
            families[scenario['family_id']].append(scenario['difference'])
    keys = sorted(families)
    if len(keys) < 5:
        return None
    rng = random.Random(BOOTSTRAP_SEED)
    samples = []
    for _ in range(BOOTSTRAP_SAMPLES):
        sampled = [value for _ in keys for value in families[keys[rng.randrange(len(keys))]]]
        samples.append(sum(sampled) / len(sampled))
    samples.sort()
    return {'lower': _percentile(samples, 0.025), 'upper': _percentile(samples, 0.975),
            'confidence': 0.95, 'samples': BOOTSTRAP_SAMPLES, 'seed': BOOTSTRAP_SEED,
            'unit': 'family_id', 'method': 'paired_cluster_percentile' if paired else 'family_cluster_percentile'}


def timing_contention(experiment):
    """Concurrent calls contend for hosts/providers; timings are then not isolated."""
    from benchmark_contracts import max_concurrent_calls
    return isinstance(experiment.get('budgets'), dict) and max_concurrent_calls(experiment) > 1


def _cohort_status(rows):
    """``final`` (human) or ``mechanical`` only when every row settled that way."""
    statuses = {row['score']['status'] if row['settled'] else 'provisional' for row in rows}
    return statuses.pop() if len(statuses) == 1 and 'provisional' not in statuses else 'provisional'


def _card_reasons(rows, controls, attributes):
    reasons = []
    if not all(row['settled'] for row in rows):
        reasons.append('scores_not_settled')
    for row in rows:
        if row['score'] and not row['score']['metrics']['ranking_eligible']:
            reasons.extend(row['score']['metrics']['ranking_blockers'] or ['metrics_not_ranking_eligible'])
    if controls['identity'] != 'reported_match':
        reasons.append('identity_unverified')
    # One team's harness changing mid-schedule is not a single treatment.
    if any(len(values) > 1 for values in attributes['runtime_versions'].values()):
        reasons.append('runtime_versions_mixed')
    if any(row['os_mismatch'] for row in rows):
        reasons.append('scenario_os_differs_from_public_assets')
    if any(row['score'] is None for row in rows):
        reasons.append('missing_or_unrecognized_scores')
    if any(row['fingerprint']['evidence_sha256'] is None for row in rows):
        reasons.append('evidence_sha256_unknown')
    return sorted(set(reasons))


def _local_runtime_reasons(card):
    attributes = card['reported_treatment']
    reasons = set()
    if any(attributes['runtime_facts'].get(key) is None for key in LOCAL_RUNTIME_FACTS):
        reasons.add('runtime_facts_unknown')
    if any(not values for values in attributes['runtime_versions'].values()):
        reasons.add('runtime_versions_unknown')
    return reasons


def _compare(left, right, left_rows, right_rows):
    reasons = set(left['not_comparable_reasons'] + right['not_comparable_reasons'])
    for key in sorted(set(left['controls']) | set(right['controls'])):
        if left['controls'].get(key) != right['controls'].get(key):
            reasons.add('fingerprint.' + key)
    # Deployment and runtime facts are treatments. Only two local teams must
    # both disclose them, so local hardware/server differences stay visible.
    if left['reported_treatment']['deployment'] == right['reported_treatment']['deployment'] == 'local':
        reasons.update(_local_runtime_reasons(left) | _local_runtime_reasons(right))
    indexes = [{(row['scenario_id'], row['repetition']): row for row in rows}
               for rows in (left_rows, right_rows)]
    pairs, scenario_pairs = [], defaultdict(list)
    for key in sorted(set(indexes[0]) | set(indexes[1])):
        a, b = indexes[0].get(key), indexes[1].get(key)
        differences = []
        if a is None or b is None:
            differences.append('missing_pair')
        else:
            differences = ['fingerprint.' + field for field in sorted(set(a['fingerprint']) | set(b['fingerprint']))
                           if a['fingerprint'].get(field) != b['fingerprint'].get(field)]
        reasons.update(differences)
        if (a is not None and a['attack_free']) or (b is not None and b['attack_free']):
            # No eligible attack steps: excluded from F1 pairing for both
            # sides; false alarms are reported through controls.benign.
            pairs.append({'scenario_id': key[0], 'repetition': key[1],
                          'left_trial_id': a['trial_id'] if a else None,
                          'right_trial_id': b['trial_id'] if b else None,
                          'left_f1': None, 'right_f1': None, 'difference': None,
                          'excluded': 'no_eligible_steps', 'not_comparable_reasons': differences})
            continue
        av = a['numeric_metrics'].get('detection.f1') if a else None
        bv = b['numeric_metrics'].get('detection.f1') if b else None
        delta = av - bv if _number(av) and _number(bv) and not differences else None
        if (av is None) != (bv is None):
            reasons.add('asymmetric_undefined_detection_f1')
        pair = {'scenario_id': key[0], 'repetition': key[1],
                'left_trial_id': a['trial_id'] if a else None,
                'right_trial_id': b['trial_id'] if b else None,
                'left_f1': av, 'right_f1': bv, 'difference': delta,
                'excluded': None, 'not_comparable_reasons': differences}
        pairs.append(pair)
        if a is not None and b is not None:
            scenario_pairs[key[0]].append((a['family_id'], pair))
    scenarios = []
    for scenario_id, entries in sorted(scenario_pairs.items()):
        deltas = [pair['difference'] for _, pair in entries]
        scenarios.append({'scenario_id': scenario_id, 'family_id': entries[0][0],
                          'paired_repetitions': len(entries),
                          'defined_repetitions': sum(value is not None for value in deltas),
                          'difference': _mean(deltas)})
    family_count = len({item['family_id'] for item in scenarios if item['difference'] is not None})
    if not any(item['difference'] is not None for item in scenarios):
        reasons.add('no_defined_detection_f1')
    comparable = not reasons
    interval = _bootstrap(scenarios) if comparable and family_count >= 5 else None
    return {'left_scorecard_id': left['scorecard_id'], 'right_scorecard_id': right['scorecard_id'],
            'left_team_id': left['team_id'], 'right_team_id': right['team_id'], 'variant': left['variant'],
            'status': 'comparable' if comparable else 'not_comparable',
            'not_comparable_reasons': sorted(reasons), 'independent_families': family_count,
            'underpowered': family_count < 5,
            'inference': 'descriptive_underpowered' if family_count < 5 else
                         'paired_family_cluster_bootstrap' if comparable else 'descriptive_not_comparable',
            'difference_direction': 'left_minus_right',
            'macro_f1_difference': _mean([item['difference'] for item in scenarios]),
            'paired_differences': pairs, 'scenario_differences': scenarios, 'confidence_interval': interval,
            'significant_direction': ('left_higher' if interval['lower'] > 0 else
                                      'right_higher' if interval['upper'] < 0 else None) if interval else None}


def build_comparison(snapshot):
    """Return report['scoring']; never read files, dispatch, or mutate the snapshot.

    Old/incomplete scores are retained as explicit unknowns. They cannot turn a
    scheduled failure into a successful benign trial or a rankable observation.
    """
    frozen = snapshot.get('experiment', {})
    experiment = frozen.get('experiment', {})
    cases = frozen.get('cases', [])
    teams = experiment.get('teams', [])
    timing_contended = timing_contention(experiment)
    trials = {(trial.get('case_id'), trial.get('team_id'), trial.get('repetition')): trial
              for trial in snapshot.get('trials', [])}
    events = sorted(snapshot.get('events', []), key=lambda event: event.get('seq', 0))
    score_events = [event for event in events if event.get('kind') == 'score_recorded']
    latest, unrecognized = {}, 0
    for event in score_events:
        payload = event.get('payload', {})
        score = payload.get('score', payload)
        if isinstance(score, dict) and score.get('variant') in VARIANTS:
            latest[(event.get('trial_id'), score['variant'])] = score
        else:
            unrecognized += 1
    call_index = defaultdict(list)
    for call in snapshot.get('calls', []):
        call_index[call.get('spec', {}).get('trial_id')].append(call)
    team_controls, team_attributes = {}, {}
    for team in teams:
        ids = {trial['trial_id'] for trial in trials.values() if trial.get('team_id') == team['team_id']}
        team_calls = [call for tid in sorted(ids) for call in call_index[tid]]
        team_controls[team['team_id']] = _team_controls(team, team_calls)
        team_attributes[team['team_id']] = _team_attributes(team, team_calls)
    rows = []
    for case, team, repetition, variant in itertools.product(cases, teams,
            range(1, experiment.get('repetitions', 0) + 1), VARIANTS):
        scenario, evidence = case['scenario'], case['evidence']
        trial = trials.get((evidence['case_id'], team['team_id'], repetition), {})
        identity = {'trial_id': trial.get('trial_id'), 'case_id': evidence['case_id'],
                    'scenario_id': scenario['scenario_id'], 'team_id': team['team_id'], 'repetition': repetition}
        candidate = latest.get((identity['trial_id'], variant))
        score = candidate if _valid_score(candidate, identity, scenario, experiment.get('rubric_version')) else None
        calls = call_index[identity['trial_id']] if identity['trial_id'] else []
        labels, mismatch = _labels(case)
        # Cohort controls: never pooled, compared or ranked across differing values.
        controls = dict(team_controls[team['team_id']], variant=variant,
                        adjudication=score['adjudication'] if score else None,
                        truth_attestation=score['truth_attestation'] if score else None,
                        review_policy=score['review_policy'] if score else None,
                        truth_frozen=score['truth_frozen'] if score else None,
                        timing_contended=timing_contended,
                        split=scenario.get('split'), provenance=scenario.get('provenance'),
                        ioc_regime=scenario.get('ioc_regime'),
                        detector_condition=_condition(case), budgets=experiment.get('budgets'))
        for key in ('workflow_sha256', 'prompt_contract_sha256', 'coverage_sha256', 'rubric_version'):
            controls[key] = experiment.get(key)
        controls['pricing_snapshot_sha256'] = _digest(experiment.get('pricing_snapshot'))
        fingerprint = dict(controls, evidence_sha256=trial.get('case_evidence_sha256', scenario.get('evidence_manifest_sha256')),
                           scenario_id=scenario['scenario_id'], family_id=scenario.get('family_id'),
                           truth_sha256=score.get('truth_sha256') if score else None)
        reasons = []
        if candidate is not None and score is None:
            reasons.append('unrecognized_or_incomplete_score_envelope')
        elif score is None:
            reasons.append('no_score_recorded')
        if score:
            reasons.extend(_null_reasons(score['metrics']))
        status = score['trial_status'] if score else trial.get('status', 'missing_trial')
        failures = [(call.get('receipt') or {}).get('failure_reason') for call in calls]
        rows.append(dict(identity, variant=variant, family_id=scenario.get('family_id'), score=score,
                         controls=controls, fingerprint=fingerprint, labels=labels, os_mismatch=mismatch,
                         numeric_metrics=_leaves(score['metrics']) if score else {}, calls=calls,
                         settled=bool(score and score['status'] != 'provisional'
                                      and score['metrics']['status'] == score['status']),
                         completed=score['completed'] if score else None, trial_status=status,
                         failed=int(status in FAILED_STATUSES),
                         unknown=int(status == 'unknown' or any(call.get('status') in ('unknown', 'reserved') for call in calls)),
                         timeout=int('timeout' in failures),
                         format_error=int(any(reason in FORMAT_FAILURES for reason in failures)),
                         null_reasons=reasons))
    attack_free = {row['scenario_id'] for row in rows
                   if row['score'] and row['score']['metrics']['detection']['eligible_steps'] == 0}
    for row in rows:
        row['attack_free'] = row['scenario_id'] in attack_free
    # An unscored trial is not a license to rank the remaining success-only
    # cohort. Keep every such schedule incomplete.
    incomplete_schedules = {(row['team_id'], row['variant']) for row in rows if row['score'] is None}
    groups = defaultdict(list)
    for row in rows:
        groups[(row['team_id'], _canonical(row['controls']))].append(row)
    cards, grouped, slices = [], {}, []
    for (team_id, _), group in sorted(groups.items()):
        controls = group[0]['controls']
        card_id = _digest({'team_id': team_id, 'controls': controls})
        reasons = _card_reasons(group, controls, team_attributes[team_id])
        if (team_id, controls['variant']) in incomplete_schedules:
            reasons = sorted(set(reasons + ['team_schedule_incomplete']))
        summary = _summary(group)
        card = dict(summary, scorecard_id=card_id, team_id=team_id, variant=controls['variant'],
                    controls=controls, reported_treatment=team_attributes[team_id],
                    status=_cohort_status(group),
                    not_comparable_reasons=reasons,
                    trial_ids=[row['trial_id'] for row in group],
                    scenario_scores=[dict(_summary(selected), scenario_id=scenario_id,
                                          family_id=selected[0]['family_id'])
                                     for scenario_id, selected in sorted(_by_scenario(group).items())])
        scenario_values = [{'family_id': item['family_id'], 'difference': item['detection']['f1']}
                           for item in card['scenario_scores']]
        card['f1_confidence_interval'] = _bootstrap(scenario_values, paired=False) if not reasons else None
        card['underpowered'] = len({item['family_id'] for item in scenario_values if item['difference'] is not None}) < 5
        cards.append(card)
        grouped[card_id] = group
        for axis in AXES:
            for category in summary['coverage'][axis]:
                selected = [row for row in group if category in row['labels'][axis]]
                slices.append(dict(_summary(selected), scorecard_id=card_id, team_id=team_id,
                                   variant=controls['variant'], axis=axis, category=category,
                                   inference='descriptive_only'))
    comparisons = [_compare(left, right, grouped[left['scorecard_id']], grouped[right['scorecard_id']])
                   for left, right in itertools.combinations(cards, 2)
                   if left['team_id'] != right['team_id'] and left['variant'] == right['variant']]
    ranking = _rank(cards, comparisons)
    reasons = sorted({reason for card in cards for reason in card['not_comparable_reasons']} |
                     {reason for comparison in comparisons for reason in comparison['not_comparable_reasons']})
    if any(card['underpowered'] for card in cards):
        reasons.append('fewer_than_five_independent_families')
    if unrecognized:
        reasons.append('unrecognized_legacy_score_events')
    return {'status': 'pending' if not score_events else
                      _cohort_status(rows) if rows and not unrecognized else 'provisional',
            'recorded_scores': len(score_events), 'latest_recognized_scores': sum(row['score'] is not None for row in rows),
            'unrecognized_score_events': unrecognized, 'scheduled_trials': len(rows) // len(VARIANTS),
            'review_policy': sorted({row['controls']['review_policy'] for row in rows
                                     if row['controls']['review_policy'] is not None}),
            'adjudication': sorted({row['controls']['adjudication'] for row in rows
                                    if row['controls']['adjudication'] is not None}),
            'truth_attestation': sorted({row['controls']['truth_attestation'] for row in rows
                                         if row['controls']['truth_attestation'] is not None}),
            'timing_contended': timing_contended,
            'scorecards': cards, 'comparisons': comparisons, 'slices': slices,
            'ranking': ranking or None, 'not_comparable_reasons': sorted(set(reasons)),
            'methodology': {'primary_metric': 'macro_evidence_supported_f1',
                            'aggregation': 'repetitions_within_scenario_then_equal_weight_scenarios',
                            'bootstrap_unit': 'family_id', 'bootstrap_samples': BOOTSTRAP_SAMPLES,
                            'bootstrap_seed': BOOTSTRAP_SEED,
                            'references': ['https://evals.mitre.org/methodology-overview/',
                                           'https://aclanthology.org/P18-1128/']},
            'limitations': ['Project rubric, not official MITRE certification.',
                            'Repetitions and derived windows are not independent attack families.',
                            'Null metrics remain undefined; known-subset means disclose their denominators.',
                            'Secondary coverage slices are descriptive; no multiple-testing winner claim.',
                            'No significant paired difference is not evidence of equivalence.',
                            'Model identities are provider reports, not weight attestation.',
                            'Training contamination is unknown; public recipes are development material.',
                            'Model/settings/checker choice, deployment, runtime facts and harness versions are '
                            'reported treatment attributes; resource and corpus controls are pairing keys. '
                            'Local-vs-local comparisons require both teams to disclose runtime facts.',
                            'Scenarios with no eligible attack steps are excluded from detection-rate pairing and '
                            'macro averages for every team; their false alarms are reported via benign controls.',
                            'Identity is judged on calls that reported a model or produced output; failed calls '
                            'without a model count as failures, and any reported mismatch blocks.',
                            'Every stage auto-advanced without human review (review_policy auto_advance).',
                            'Mechanical adjudication applies deterministic rules, not human verdicts: its status is '
                            'mechanical, claim semantic support and correct control dispositions are '
                            'not_measured_mechanical, and it is never compared or ranked with human adjudication.',
                            'Truth marked publisher_labels is derived mechanically from dataset-publisher labels, '
                            'truth marked unreviewed_proposal is an unreviewed proposed answer key, and truth '
                            'marked agent_consensus is two independent AI drafts merged mechanically; none is a '
                            'human attestation, and findings citing only agent_consensus disputed records are '
                            'ignored; truth attestation and truth freeze are cohort controls.',
                            'Concurrent calls (timing_contended) share hosts and providers; elapsed times are '
                            'not isolated per call and only compare within the same contention setting.',
                            'Execution-outcome correctness is not measured: stage outputs carry no outcome '
                            'assertion; only matched counts per truth execution outcome are reported.',
                            'No production MTTD is inferred; early support timing is offline only.',
                            'Timing and full role configurations are also reported by the snapshot report.']}


def _by_scenario(rows):
    result = defaultdict(list)
    for row in rows:
        result[row['scenario_id']].append(row)
    return result


def _rank(cards, comparisons):
    """Rank only complete comparable cohorts, keeping all scheduled outcomes."""
    groups = defaultdict(list)
    for card in cards:
        groups[_canonical(card['controls'])].append(card)
    results = []
    pairs = {(item['left_scorecard_id'], item['right_scorecard_id']): item for item in comparisons}
    for key, group in sorted(groups.items()):
        if len(group) < 2 or any(card['not_comparable_reasons'] or card['underpowered'] or
                                 card['detection']['f1'] is None for card in group):
            continue
        if any(pairs.get((left['scorecard_id'], right['scorecard_id']), {}).get('status') != 'comparable'
               for left, right in itertools.combinations(group, 2)):
            continue
        ordered = sorted(group, key=lambda card: (-card['detection']['f1'], card['team_id']))
        entries, previous, rank = [], None, 0
        for index, card in enumerate(ordered, 1):
            if card['detection']['f1'] != previous:
                rank = index
            previous = card['detection']['f1']
            entries.append({'rank': rank, 'team_id': card['team_id'], 'scorecard_id': card['scorecard_id'],
                            'macro_f1': card['detection']['f1'], 'confidence_interval': card['f1_confidence_interval'],
                            'failures': card['failures'], 'measurements': card['measurements'],
                            'coverage': card['coverage'], 'scenario_count': card['scenario_count'],
                            'family_count': card['family_count']})
        controls = group[0]['controls']
        results.append({'cohort_id': _digest(json.loads(key)), 'variant': group[0]['variant'],
                        'status': group[0]['status'], 'adjudication': controls['adjudication'],
                        'truth_attestation': controls['truth_attestation'],
                        'review_policy': controls['review_policy'], 'truth_frozen': controls['truth_frozen'],
                        'timing_contended': controls['timing_contended'],
                        'metric': 'macro_evidence_supported_f1', 'entries': entries,
                        'interpretation': 'Ordering of point estimates; see paired intervals, not an automatic winner claim.'})
    return results

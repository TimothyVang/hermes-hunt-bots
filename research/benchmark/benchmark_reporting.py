"""Export one authoritative snapshot; this is not a statistical scoring engine.

Coverage credit requires an explicit verified catalog row and immutable evidence.
Unknown identity, usage, cost and human timings remain unknown, never zero.
"""
import csv
import html
import math
import os
from pathlib import Path, PurePosixPath
import shutil
import stat

from benchmark_contracts import (REVIEW_POLICY, BenchmarkError, canonical_bytes, campaign_manifest_digest,
                                 digest_bytes, max_concurrent_calls, parse_utc, validate_coverage,
                                 validate_experiment)
from benchmark_holdout import load_registry, retired_keys


VERIFIED = ('synthetic_verified', 'replay_verified', 'live_verified')
USAGE_FIELDS = ('input_tokens', 'output_tokens', 'cached_input_tokens', 'reasoning_tokens')
COST_FIELDS = ('api_cost_usd', 'local_compute_cost_usd', 'local_energy_cost_usd')


def _fail(field):
    raise BenchmarkError('incomplete_snapshot', field)


def _unique(rows, key, field):
    result = {}
    for row in rows:
        if type(row) is not dict or type(row.get(key)) is not str or row[key] in result:
            _fail(field)
        result[row[key]] = row
    return result


def _verify_artifacts(store, snapshot, trials):
    """Verify referenced immutable bytes, not source-bundle file declarations."""
    verified = {}

    def walk(value, trial_id=None, field='snapshot'):
        if isinstance(value, list):
            for item in value:
                walk(item, trial_id, field)
        elif isinstance(value, dict):
            trial_id = value.get('trial_id', trial_id)
            path = value.get('path')
            is_ref = (isinstance(path, str) and path.startswith('artifacts/'))
            is_ref = is_ref or field.endswith('_artifact') or field == 'public_artifact'
            if is_ref:
                if set(value) != {'path', 'sha256', 'byte_count'} or trial_id not in trials:
                    _fail('artifact')
                key = (trial_id, path)
                if key in verified and verified[key] != value:
                    _fail('artifact')
                if key not in verified:
                    data = store.read_artifact(trial_id, value)
                    if len(data) != value['byte_count'] or digest_bytes(data) != value['sha256']:
                        raise BenchmarkError('digest_mismatch', 'artifact')
                    verified[key] = value
                return
            for name, item in value.items():
                if name == 'public_artifacts':
                    if not isinstance(item, dict):
                        _fail('public_artifacts')
                    for ref in item.values():
                        walk(ref, trial_id, 'public_artifact')
                elif item is not None:
                    walk(item, trial_id, name)

    for name in ('trials', 'calls', 'campaign_states', 'campaigns', 'approvals', 'events'):
        for value in snapshot[name]:
            trial_id = value.get('trial_id')
            if name in ('calls', 'campaigns'):
                trial_id = value['spec'].get('trial_id', trial_id)
            walk(value, trial_id)
    for call in snapshot['calls']:
        receipt = call['receipt']
        if receipt is None:
            if call['status'] in ('completed', 'failed'):
                _fail('receipt')
            continue
        ref = receipt.get('response_artifact')
        if call['status'] == 'completed' and ref is None:
            _fail('response_artifact')
        if ref is not None and receipt.get('response_sha256') != ref['sha256']:
            raise BenchmarkError('digest_mismatch', 'response_sha256')
    return verified


def _validate_snapshot(snapshot, experiment_id):
    required = {'schema_version', 'experiment', 'trials', 'calls', 'campaign_states',
                'campaigns', 'approvals', 'events'}
    if not isinstance(snapshot, dict) or not required.issubset(snapshot) or snapshot['schema_version'] != 1:
        _fail('snapshot')
    for key in required - {'schema_version', 'experiment'}:
        if not isinstance(snapshot[key], list):
            _fail('snapshot')
    frozen = snapshot['experiment']
    if not isinstance(frozen, dict) or not {'experiment', 'coverage', 'cases'}.issubset(frozen):
        _fail('experiment')
    experiment = validate_experiment(frozen['experiment'])
    if experiment['experiment_id'] != experiment_id:
        _fail('experiment_id')
    trials = _unique(snapshot['trials'], 'trial_id', 'trials')
    calls = _unique(snapshot['calls'], 'call_id', 'calls')
    campaigns = _unique(snapshot['campaign_states'], 'campaign_id', 'campaign_states')
    state_fields = {'schema_version', 'campaign_id', 'experiment_id', 'manifest',
                    'manifest_sha256', 'status', 'cleanup_status', 'owned_process',
                    'created_utc', 'updated_utc'}
    approvals = _unique(snapshot['approvals'], 'approval_id', 'approvals')
    linked_campaigns = set()
    for event in snapshot['events']:
        payload = event.get('payload', {})
        if payload.get('record_type') != 'campaign_evidence_release':
            continue
        for destination in payload.get('destinations', []):
            if destination.get('experiment_id') != experiment_id:
                continue
            trial = trials.get(destination.get('trial_id'))
            grant = approvals.get(destination.get('approval_id'))
            if (trial is None or grant is None
                    or payload.get('evidence_sha256') != trial['case_evidence_sha256']
                    or grant.get('kind') != 'authorization'
                    or grant.get('experiment_id') != experiment_id
                    or grant.get('trial_id') != trial['trial_id']
                    or grant.get('evidence_sha256') != trial['case_evidence_sha256']
                    or grant.get('authorization_sha256') != destination.get('authorization_sha256')
                    or grant.get('model_sha256s') != destination.get('model_sha256s')):
                _fail('campaign_release')
            linked_campaigns.add(event.get('campaign_id'))
    for state in campaigns.values():
        if (not state_fields.issubset(state) or state['schema_version'] != 1
                or (state['experiment_id'] != experiment_id
                    and state['campaign_id'] not in linked_campaigns)):
            _fail('campaign_states')
        if campaign_manifest_digest(state['manifest']) != state['manifest_sha256']:
            raise BenchmarkError('digest_mismatch', 'campaign.manifest_sha256')
    for dispatch in snapshot['campaigns']:
        if dispatch.get('campaign_id') not in campaigns:
            _fail('campaigns')
    teams = {team['team_id'] for team in experiment['teams']}
    cases = {item['scenario']['scenario_id']: item for item in frozen['cases']}
    if len(cases) != len(frozen['cases']):
        _fail('cases')
    for trial in trials.values():
        if trial.get('experiment_id') != experiment_id or trial.get('team_id') not in teams:
            _fail('trial')
        case = cases.get(trial.get('scenario_id'))
        if case is None or trial.get('case_id') != case['evidence']['case_id']:
            _fail('trial.case_id')
        if trial.get('case_evidence_sha256') != case['scenario']['evidence_manifest_sha256']:
            _fail('trial.case_evidence_sha256')
        artifacts = trial.get('public_artifacts')
        expected = {item['path']: item for item in case['evidence']['files']}
        if not isinstance(artifacts, dict) or set(artifacts) != set(expected):
            _fail('public_artifacts')
        for path, ref in artifacts.items():
            if not isinstance(ref, dict) or any(ref.get(key) != expected[path][key] for key in ('sha256', 'byte_count')):
                _fail('public_artifacts')
    for call in calls.values():
        if not isinstance(call.get('spec'), dict) or call['spec'].get('trial_id') not in trials:
            _fail('call')
        if 'receipt' not in call or 'status' not in call:
            _fail('call')
    previous_seq = 0
    event_ids = set()
    for event in snapshot['events']:
        if type(event.get('seq')) is not int or event['seq'] <= previous_seq or event.get('event_id') in event_ids:
            _fail('events')
        previous_seq = event['seq']
        event_ids.add(event.get('event_id'))
        if (event.get('experiment_id') not in (None, experiment_id)
                and not (event.get('campaign_id') in linked_campaigns
                         and event.get('trial_id') is None and event.get('call_id') is None)):
            _fail('event')
        if event.get('trial_id') is not None and event['trial_id'] not in trials:
            _fail('event')
        if event.get('call_id') is not None and event['call_id'] not in calls:
            _fail('event')
        if event.get('campaign_id') is not None and event['campaign_id'] not in campaigns:
            _fail('event')
    return frozen, experiment, trials


def _coverage_evidence(frozen, trials, verified):
    """Resolve authored bundle paths solely through frozen, checked public bytes."""
    references = frozen['experiment']['scenario_refs']
    if len(references) != len(frozen['cases']):
        _fail('scenario_refs')
    paths = {}
    for reference, case in zip(references, frozen['cases']):
        evidence = case['evidence']
        digest = digest_bytes(canonical_bytes(evidence))
        if digest != case['scenario']['evidence_manifest_sha256']:
            raise BenchmarkError('digest_mismatch', 'coverage.evidence')
        matching = [trial for trial in trials.values() if trial['case_id'] == evidence['case_id']]
        if not any(all((trial['trial_id'], artifact['path']) in verified
                       for artifact in trial['public_artifacts'].values()) for trial in matching):
            continue
        public_paths = {reference['evidence']: digest}
        directory = PurePosixPath(reference['evidence']).parent
        public_paths.update({str(directory / item['path']): item['sha256'] for item in evidence['files']})
        for path, sha in public_paths.items():
            value = {'sha256': sha, 'case': case}
            if path in paths and paths[path] != value:
                _fail('coverage.evidence_references')
            paths[path] = value
    return paths


def _coverage(frozen, trials, verified):
    catalog = validate_coverage(frozen['coverage'])
    paths = _coverage_evidence(frozen, trials, verified)
    # Accepted case provenance per verified status; public recordings are replays,
    # never live lab evidence.
    provenance = {'synthetic_verified': ('synthetic',),
                  'replay_verified': ('derived_replay', 'public_replay'),
                  'live_verified': ('lab_export',)}
    combinations = []
    for row in catalog['rows']:
        blockers, evidence = [], []
        if row['status'] in VERIFIED:
            references = row['evidence_references']
            if not references:
                _fail('coverage.evidence_references')
            resolved = [paths[path] for path in references if path in paths]
            if len(resolved) != len(references):
                blockers.append('evidence_not_in_snapshot')
            if any(item['case']['scenario']['provenance'] not in provenance[row['status']] for item in resolved):
                blockers.append('evidence_provenance_mismatch')
            for axis in catalog['axes']:
                observed = set()
                for item in resolved:
                    case = item['case']
                    if axis == 'os':
                        observed.update(asset['os_family'] for asset in case['evidence']['assets'])
                    else:
                        observed.update(case['scenario']['coverage'][axis])
                if not set(row['coverage'][axis]).issubset(observed):
                    blockers.append('coverage_not_evidenced.' + axis)
            evidence = [{'path': path, 'sha256': paths[path]['sha256']}
                        for path in references if path in paths]
        combinations.append(dict(row, numerator=int(row['status'] in VERIFIED and not blockers),
                                 denominator=1, verification_blockers=blockers,
                                 verified_evidence=evidence))
    marginal = []
    for axis, categories in catalog['axes'].items():
        for category in categories:
            matching = [row for row in combinations if category in row['coverage'][axis]]
            statuses = {status: sum(row['status'] == status and row['numerator'] == 1 for row in matching)
                        for status in VERIFIED}
            marginal.append({'axis': axis, 'category': category,
                             'numerator': int(any(statuses.values())), 'denominator': 1,
                             'verified_rows': statuses,
                             'registered_rows': [row['row_id'] for row in matching]})
    return {'status': 'available', 'catalog_version': catalog['catalog_version'],
            'basis': 'explicit_catalog_status_and_hash_verified_public_evidence; not_model_performance',
            'marginal': marginal, 'registered_combinations': combinations,
            'marginal_summary': {axis: {
                'numerator': sum(row['numerator'] for row in marginal if row['axis'] == axis),
                'denominator': len(categories)} for axis, categories in catalog['axes'].items()},
            'registered_summary': {'numerator': sum(row['numerator'] for row in combinations),
                                   'denominator': len(combinations)}}


def _measurement(values):
    known = []
    for value in values:
        if value is not None:
            if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
                _fail('measurement')
            known.append(value)
    return {'total': sum(known) if values and len(known) == len(values) else None,
            'known_subtotal': sum(known) if known else None,
            'known_count': len(known), 'unknown_count': len(values) - len(known)}


def _call_summary(calls):
    receipts = [call.get('receipt') or {} for call in calls]
    identities = {key: 0 for key in ('reported_match', 'reported_mismatch', 'unreported')}
    for receipt in receipts:
        identity = receipt.get('identity_status', 'unreported')
        if identity not in identities:
            _fail('identity_status')
        identities[identity] += 1
    statuses = {}
    failures = {}
    for call, receipt in zip(calls, receipts):
        statuses[call['status']] = statuses.get(call['status'], 0) + 1
        reason = receipt.get('failure_reason')
        if reason is not None:
            failures[reason] = failures.get(reason, 0) + 1
    return {'calls': len(calls), 'statuses': statuses, 'failure_reasons': failures,
            'identity': identities, 'model_active_ms': _measurement([r.get('elapsed_ms') for r in receipts]),
            'provider_reported_usage': {key: _measurement([(r.get('usage') or {}).get(key) for r in receipts])
                                        for key in USAGE_FIELDS},
            'estimated_usage': {key: _measurement([(r.get('estimated_usage') or {}).get(key) for r in receipts])
                                for key in USAGE_FIELDS},
            'cost': {key: _measurement([(r.get('cost') or {}).get(key) for r in receipts])
                     for key in COST_FIELDS}}


def _wall_time(value):
    try:
        return parse_utc(value, 'utc')
    except BenchmarkError:
        return None


def _wall_interval(start, end):
    left, right = _wall_time(start), _wall_time(end)
    if left is None or right is None or right < left:
        return None
    return (right - left).total_seconds() * 1000


def _trial_timing(snapshot, trial, contended):
    """Observed workflow interval, not provider execution or production MTTD.

    No stage waits for a human: the interval runs from the first dispatch to the
    store record of the final handoff's automatic advance.
    """
    trial_id = trial['trial_id']
    advances = [event for event in snapshot['events']
                if event.get('trial_id') == trial_id and event['kind'] == 'stage_auto_advanced']
    calls = [item for item in snapshot['calls'] if item['spec']['trial_id'] == trial_id]
    final = [event for event in advances if event['payload'].get('stage_key') == 'handoff']
    starts = [(call.get('receipt') or {}).get('start_utc') for call in calls]
    starts = [value for value in starts if _wall_time(value) is not None]
    first_start = min(starts, key=_wall_time) if starts else None
    elapsed = _wall_interval(first_start, final[-1]['time_utc']) if final else None
    limitations = []
    if elapsed is None:
        limitations.append('no_completed_workflow_interval')
    if contended:
        limitations.append('timing_contended_concurrent_calls')
    return {'end_to_end_ms': elapsed,
            'auto_advanced_stages': len({event['payload'].get('stage_key') for event in advances}),
            'review_policy': REVIEW_POLICY, 'timing_contended': contended,
            'basis': 'first_dispatch_to_final_auto_advance_utc',
            'limitations': limitations}


def _holdout(frozen, scoring, registry):
    """Scored holdout cohorts stay ``holdout_exposed`` until the registry retires them.

    Without a supplied registry nothing can be shown retired. Exposure is not a
    comparability defect of this experiment; it forbids reusing the holdout.
    """
    scenarios = {case['scenario']['scenario_id']: case['scenario'] for case in frozen['cases']}
    retired = retired_keys(registry) if registry is not None else {}
    exposed = []
    for card in scoring['scorecards']:
        if card['controls']['split'] != 'holdout':
            card['holdout_status'] = None
            continue
        keys = {(scenarios[scenario_id]['family_id'], scenarios[scenario_id]['revision'])
                for scenario_id in card['scenario_ids']}
        if not card['scored_trials']:
            card['holdout_status'] = 'holdout_unexposed'
        elif keys.issubset(retired):
            card['holdout_status'] = 'retired'
        else:
            card['holdout_status'] = 'holdout_exposed'
            exposed.append(card['scorecard_id'])
    holdouts = sorted({(scenario['family_id'], scenario['revision']) for scenario in scenarios.values()
                       if scenario['split'] == 'holdout'})
    return {'registry_supplied': registry is not None,
            'holdout_family_revisions': [list(key) for key in holdouts],
            'retired_family_revisions': [list(key) for key in holdouts if key in retired],
            'exposed_cohorts': exposed,
            'status': 'no_holdout' if not holdouts else 'holdout_exposed' if exposed else
                      'retired' if all(key in retired for key in holdouts) else 'holdout_unexposed'}


def _timeouts(snapshot, experiment):
    """Timed-out calls and the remaining margin of completed ones, per stage.

    Elapsed times are receipts, or the observation of an unknown receipt that
    automatic reconciliation discarded (labeled); charges are as budgeted.
    """
    from benchmark_store import call_timing
    timings = [call_timing(call, snapshot['events'], experiment) for call in snapshot['calls']]
    margins = {}
    for item in timings:
        if item['status'] != 'completed' or item['elapsed_ms'] is None:
            continue
        key = item['stage_key'] + '/' + item['component']
        entry = margins.setdefault(key, {'completed_calls': 0, 'max_elapsed_ms': None, 'min_margin_ms': None})
        entry['completed_calls'] += 1
        entry['max_elapsed_ms'] = max(item['elapsed_ms'], entry['max_elapsed_ms'] or 0)
        entry['min_margin_ms'] = (item['timeout_margin_ms'] if entry['min_margin_ms'] is None
                                  else min(item['timeout_margin_ms'], entry['min_margin_ms']))
    timed_out = [item for item in timings if item['failure_reason'] == 'timeout']
    return {'timed_out_calls': len(timed_out), 'calls': timed_out,
            'completed_margin_by_stage': dict(sorted(margins.items()))}


def _format_failures(snapshot):
    """Every format-failed call with the validator's reason (code and field).

    A rejected answer is referenced by its evaluator-only artifact; it is never
    sent to a model or scored. Calls without a received answer have null codes.
    """
    from benchmark_comparison import FORMAT_FAILURES
    calls, counts = [], {}
    for call in snapshot['calls']:
        receipt = call['receipt'] or {}
        if call['status'] != 'failed' or receipt.get('failure_reason') not in FORMAT_FAILURES:
            continue
        rejected = receipt.get('rejected_response') or {}
        item = {'call_id': call['call_id'], 'trial_id': call['spec']['trial_id'],
                'stage_key': call['spec']['stage_key'], 'role': call['spec'].get('role'),
                'component': call['spec']['component'], 'attempt_index': call['spec']['attempt_index'],
                'failure_reason': receipt['failure_reason'], 'error_code': rejected.get('error_code'),
                'error_field': rejected.get('error_field'),
                'rejected_response_artifact': rejected.get('artifact'),
                'rejected_byte_count': rejected.get('byte_count'), 'rejected_truncated': rejected.get('truncated')}
        calls.append(item)
        key = (item['failure_reason'], item['error_code'] or '', item['error_field'] or '')
        counts[key] = counts.get(key, 0) + 1
    return {'count': len(calls), 'calls': calls,
            'by_reason': [{'failure_reason': reason, 'error_code': code or None, 'error_field': field or None,
                           'calls': count} for (reason, code, field), count in sorted(counts.items())]}


def _reconciliations(snapshot):
    """Every recorded reconciliation, labeled automatic or human; never conflated."""
    from benchmark_store import AUTO_RECONCILE_POLICY, HUMAN_RECONCILE_POLICY, reconciliation_policy
    records = []
    for event in snapshot['events']:
        if event['kind'] != 'reconciliation_recorded':
            continue
        payload = event['payload']
        records.append({'event_id': event['event_id'], 'time_utc': event['time_utc'],
                        'call_id': event['call_id'], 'trial_id': event['trial_id'],
                        'campaign_id': event['campaign_id'], 'actor': event['actor'],
                        'policy': reconciliation_policy(event), 'outcome': payload.get('outcome'),
                        'prior_failure_reason': payload.get('prior_failure_reason'),
                        'charged_seconds': payload.get('charged_seconds'),
                        'charged_api_cost_usd': payload.get('charged_api_cost_usd')})
    return {AUTO_RECONCILE_POLICY: sum(item['policy'] == AUTO_RECONCILE_POLICY for item in records),
            HUMAN_RECONCILE_POLICY: sum(item['policy'] == HUMAN_RECONCILE_POLICY for item in records),
            'records': records}


def _automatic_retries(snapshot):
    """New attempts automation scheduled after known model-attributable failures."""
    from benchmark_store import AUTO_RETRY_POLICY
    records = [{'event_id': event['event_id'], 'time_utc': event['time_utc'], 'call_id': event['call_id'],
                'trial_id': event['trial_id'], 'actor': event['actor'],
                'stage_key': event['payload'].get('stage_key'), 'component': event['payload'].get('component'),
                'failed_attempt_index': event['payload'].get('failed_attempt_index'),
                'failure_reason': event['payload'].get('failure_reason')}
               for event in snapshot['events']
               if event['kind'] == 'trial_status_changed' and event['payload'].get('policy') == AUTO_RETRY_POLICY]
    return {'count': len(records), 'records': records}


def _report(snapshot, experiment, frozen, trials, coverage, registry=None):
    from benchmark_comparison import build_comparison, timing_contention
    contended = timing_contention(experiment)
    timing = {trial_id: _trial_timing(snapshot, trial, contended) for trial_id, trial in trials.items()}
    teams = []
    for team in experiment['teams']:
        selected_trials = [trial for trial in trials.values() if trial['team_id'] == team['team_id']]
        ids = {trial['trial_id'] for trial in selected_trials}
        calls = [call for call in snapshot['calls'] if call['spec']['trial_id'] in ids]
        stages = sorted({call['spec']['stage_key'] for call in calls})
        teams.append({'configuration': team, 'identity_attestation': 'unknown' if not calls else 'see_call_receipts',
                      'trials_recorded': len(selected_trials), 'measurements': _call_summary(calls),
                      'stages': {stage: _call_summary([call for call in calls if call['spec']['stage_key'] == stage])
                                 for stage in stages},
                      'end_to_end_ms': _measurement([
                          timing[trial['trial_id']]['end_to_end_ms'] for trial in selected_trials]),
                      'checker_measurements': _call_summary([
                          call for call in calls if call['spec'].get('component') == 'evidence_checker'])})
    status_counts = {}
    for trial in trials.values():
        status = trial['status']
        status_counts[status] = status_counts.get(status, 0) + 1
    scoring = build_comparison(snapshot)
    holdout = _holdout(frozen, scoring, registry)
    return {'schema_version': 1, 'experiment_id': experiment['experiment_id'],
            'execution': 'framework-managed',
            # Honesty labels: no stage was human-reviewed; scores carry their own
            # adjudication and truth attestation (see scoring and its scorecards).
            'review_policy': REVIEW_POLICY, 'timing_contended': contended,
            'max_concurrent_calls': max_concurrent_calls(experiment),
            'adjudication': scoring['adjudication'], 'truth_attestation': scoring['truth_attestation'],
            'snapshot': {'last_event_seq': snapshot['events'][-1]['seq'] if snapshot['events'] else None,
                         'sha256': digest_bytes(canonical_bytes(snapshot))},
            'scoring': scoring, 'holdout': holdout,
            'configuration': experiment, 'teams': teams, 'coverage': coverage,
            'scheduled_trials': len(experiment['scenario_refs']) * len(experiment['teams']) * experiment['repetitions'],
            'recorded_trials': len(trials), 'recorded_trial_statuses': status_counts,
            'trial_timing': timing,
            'timeouts': _timeouts(snapshot, experiment),
            'format_failures': _format_failures(snapshot),
            'reconciliations': _reconciliations(snapshot),
            'automatic_retries': _automatic_retries(snapshot),
            'trials': snapshot['trials'], 'approvals': snapshot['approvals'],
            'campaign_states': snapshot['campaign_states'], 'campaign_dispatches': snapshot['campaigns'],
            'cases': frozen.get('cases', []), 'role_instructions': frozen.get('role_instructions'),
            'limitations': ['No model quality or winner is inferred from configuration or coverage tags.',
                            'Reported model identities are provider claims, not model-weight attestation.',
                            'Unknown cost, usage and timing are null; subset token fields are not added together.',
                            'Coverage verification is not a model benchmark result; OS tags do not establish all versions.',
                            'Scored holdout cohorts are holdout_exposed until retired in the holdout registry; '
                            'exposed holdout results must never inform configuration selection.',
                            'Every stage auto-advanced (review_policy auto_advance); no stage output was '
                            'human-reviewed before it flowed forward or was scored.']}


def _markdown(report):
    # Render numeric summaries and escaped identifiers, never model prose/reviewer notes.
    def cell(value):
        if value is None:
            return 'null'
        if type(value) is float:
            return '{:.4f}'.format(value)
        text = html.escape(str(value), quote=True).replace('\r', ' ').replace('\n', ' ')
        for token, escaped in (('|', '&#124;'), ('`', '&#96;'), ('[', '&#91;'),
                               (']', '&#93;'), ('*', '&#42;'), ('_', '&#95;')):
            text = text.replace(token, escaped)
        return text

    def table(headers, rows):
        lines.append('| ' + ' | '.join(headers) + ' |')
        lines.append('| ' + ' | '.join('---' for _ in headers) + ' |')
        lines.extend('| ' + ' | '.join(cell(value) for value in row) + ' |' for row in rows)
        lines.append('')

    def interval(value):
        return None if value is None else '{:.4f} to {:.4f}'.format(value['lower'], value['upper'])

    scoring = report['scoring']
    lines = ['# Framework-managed benchmark snapshot', '',
             'Scoring: **{}**. Recorded score events: {}.'.format(
                 cell(scoring['status']), scoring['recorded_scores']), '',
             'Review policy: **{}** (no stage was human-reviewed). Adjudication: {}. Truth attestation: {}. '
             'Timing contended: {} (max concurrent calls {}).'.format(
                 cell(report['review_policy']), cell(', '.join(report['adjudication']) or None),
                 cell(', '.join(report['truth_attestation']) or None), cell(report['timing_contended']),
                 report['max_concurrent_calls']), '',
             'Trials: {} recorded / {} scheduled.'.format(report['recorded_trials'], report['scheduled_trials']),
             'Counts below are pooled audit counts; precision, recall and F1 are scenario-macro',
             'means after aggregating repetitions within each scenario. Null means undefined or unknown.', '',
             '## Team scorecards', '']
    cards = scoring.get('scorecards', [])
    ranks = {entry['scorecard_id']: entry['rank']
             for cohort in scoring.get('ranking') or [] for entry in cohort['entries']}
    if cards:
        table(['Team', 'Variant', 'Cohort', 'Rank', 'TP', 'FP', 'FN', 'Precision', 'Recall', 'F1', '95% CI', 'Status'],
              [(card['team_id'], card['variant'], card['scorecard_id'][:12],
                ranks.get(card['scorecard_id']), card['detection']['tp'], card['detection']['fp'],
                card['detection']['fn'], card['detection']['precision'], card['detection']['recall'],
                card['detection']['f1'], interval(card['f1_confidence_interval']), card['status'])
               for card in cards])
        table(['Cohort', 'Adjudication', 'Truth attestation', 'Truth frozen', 'Review policy', 'Timing contended',
               'Deployment', 'Structured-output roles', 'Split', 'Holdout', 'Provenance', 'Detector condition',
               'Scheduled', 'Scored', 'Completed', 'Failed', 'Benign-control false alarms'],
              [(card['scorecard_id'][:12], card['controls']['adjudication'], card['controls']['truth_attestation'],
                card['controls']['truth_frozen'], card['controls']['review_policy'],
                card['controls']['timing_contended'], card['reported_treatment']['deployment'],
                len(card['reported_treatment'].get('structured_output_roles', [])),
                card['controls']['split'], card.get('holdout_status'), card['controls']['provenance'],
                card['controls']['detector_condition'],
                card['scheduled_trials'], card['scored_trials'], card['failures']['completed'],
                card['failures']['failed'], card['detection']['benign_control_false_alarms'])
               for card in cards])
        for card in cards:
            reasons = card.get('not_comparable_reasons', [])
            if reasons:
                lines.append('- Cohort {}: {}.'.format(cell(card['scorecard_id'][:12]), cell(', '.join(reasons))))
        lines.append('')
    else:
        lines.extend(['No adjudicated scorecards are available.', ''])
    lines.extend(['## Measured execution', '',
                  'Whole-trial lifecycle totals include retries and checker calls, not first-pass-only cost.',
                  'Known subtotals below never replace unknown measurements with zero.', ''])
    table(['Team', 'Calls', 'Checker calls', 'API USD known', 'Unpriced calls',
           'Model ms known', 'End-to-end ms known', 'Unfinished/unknown intervals'],
          [(team['configuration']['team_id'], team['measurements']['calls'],
            team['checker_measurements']['calls'],
            team['measurements']['cost']['api_cost_usd']['known_subtotal'],
            team['measurements']['cost']['api_cost_usd']['unknown_count'],
            team['measurements']['model_active_ms']['known_subtotal'],
            team['end_to_end_ms']['known_subtotal'], team['end_to_end_ms']['unknown_count'])
           for team in report['teams']])
    timeouts, reconciliations = report['timeouts'], report['reconciliations']
    lines.extend(['Timed-out calls: {}. Reconciliations: {} automatic (model calls only, output '
                  'discarded, worst case charged), {} human. Automatic retries after known model call '
                  'failures: {} (first attempts stay counted).'.format(
                      timeouts['timed_out_calls'], reconciliations['automatic_model_call'],
                      reconciliations['human_operator'], report['automatic_retries']['count']), ''])
    if timeouts['calls']:
        table(['Trial', 'Stage', 'Component', 'Attempt', 'Elapsed ms', 'Elapsed basis', 'Timeout s',
               'Charged s', 'Reconciliation'],
              [(item['trial_id'][:12], item['stage_key'], item['component'], item['attempt_index'],
                item['elapsed_ms'], item['elapsed_basis'], item['timeout_seconds'], item['charged_seconds'],
                item['reconciliation_policy'])
               for item in timeouts['calls']])
    failures = report['format_failures']
    lines.extend(['Format failures: {} (evaluator-only rejected answers are referenced in report.json, '
                  'never sent to a model or scored).'.format(failures['count']), ''])
    if failures['by_reason']:
        table(['Failure', 'Error code', 'Error field', 'Calls'],
              [(item['failure_reason'], item['error_code'], item['error_field'], item['calls'])
               for item in failures['by_reason']])
    lines.extend(['Per-stage usage/cost, end-to-end intervals, fixed-question calibration, controls,',
                  'claim/citation/edge metrics and complete runtime fingerprints are in report.json.', '',
                  '## Paired comparisons', ''])
    comparisons = scoring.get('comparisons', [])
    if comparisons:
        table(['Left team', 'Right team', 'Variant', 'Families', 'F1 left-minus-right', '95% CI', 'Inference'],
              [(pair['left_team_id'], pair['right_team_id'], pair['variant'], pair['independent_families'],
                pair['macro_f1_difference'], interval(pair['confidence_interval']), pair['inference'])
               for pair in comparisons])
        for comparison in comparisons:
            if comparison['underpowered']:
                lines.append('### Descriptive paired differences: {} / {} ({})'.format(
                    cell(comparison['left_team_id']), cell(comparison['right_team_id']), cell(comparison['variant'])))
                lines.append('')
                table(['Scenario', 'Repetition', 'Left F1', 'Right F1', 'Difference', 'Limitations'],
                      [(pair['scenario_id'], pair['repetition'], pair['left_f1'], pair['right_f1'],
                        pair['difference'], ', '.join(pair['not_comparable_reasons']))
                       for pair in comparison['paired_differences']])
    else:
        lines.extend(['No comparable team pair is available.', ''])
    lines.extend(['Fewer than five independent families is descriptive/underpowered, not a significant winner.',
                  'Secondary coverage slices are descriptive; repeated windows are not independent attacks.', '',
                  '## Coverage', ''])
    table(['Axis', 'Verified categories', 'Registered categories'],
          [(axis, value['numerator'], value['denominator'])
           for axis, value in report['coverage']['marginal_summary'].items()])
    table(['Registered combination', 'Catalog status', 'Verified', 'Denominator', 'Verification blockers'],
          [(row['row_id'], row['status'], row['numerator'], row['denominator'],
            ', '.join(row['verification_blockers']))
           for row in report['coverage']['registered_combinations']])
    lines.extend(['Only explicit verified catalog rows backed by hash-checked evidence receive coverage credit.',
                  'Tags, repetitions and configured models do not prove live support.', '', '## Interpretation', ''])
    lines.extend('- ' + cell(item) for item in report['limitations'] + scoring.get('limitations', []))
    lines.append('')
    return '\n'.join(lines)


def _write_bytes(path, data):
    with path.open('xb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def _write_jsonl(path, rows):
    with path.open('xb') as stream:
        for row in rows:
            stream.write(canonical_bytes(row) + b'\n')
        stream.flush()
        os.fsync(stream.fileno())


def _write_coverage(path, coverage):
    with path.open('x', encoding='utf-8', newline='') as stream:
        writer = csv.writer(stream)
        writer.writerow(('scope', 'axis', 'category_or_row', 'numerator', 'denominator', 'status',
                         'evidence_references', 'verification_blockers', 'verified_evidence'))
        for row in coverage['marginal']:
            writer.writerow(('marginal', row['axis'], row['category'], row['numerator'], row['denominator'],
                             '', '', '', ''))
        for row in coverage['registered_combinations']:
            writer.writerow(('registered_combination', '', row['row_id'], row['numerator'], row['denominator'],
                             row['status'], canonical_bytes(row['evidence_references']).decode('utf-8'),
                             canonical_bytes(row['verification_blockers']).decode('utf-8'),
                             canonical_bytes(row['verified_evidence']).decode('utf-8')))
        stream.flush()
        os.fsync(stream.fileno())


def export_snapshot(store, experiment_id, output, holdout_registry=None):
    """Write a new export from exactly one consistent store snapshot.

    No source manifests, current catalogs or live providers are consulted. Failed
    exports remove only their own newly created directory. Immutable artifacts are
    checked again before output, so missing or changed bytes never yield success.
    An optional holdout registry path lets retired holdout cohorts be shown as
    retired; otherwise scored holdout cohorts are reported ``holdout_exposed``.
    """
    owned = False
    try:
        destination = Path(os.path.abspath(os.fspath(output)))
        if destination.exists() or destination.is_symlink():
            raise BenchmarkError('destination_exists', 'output')
        for parent in (destination.parent,) + tuple(destination.parent.parents):
            info = parent.lstat()
            if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
                raise BenchmarkError('path_alias', 'output')
        registry = load_registry(holdout_registry) if holdout_registry is not None else None
        snapshot = store.snapshot(experiment_id)
        frozen, experiment, trials = _validate_snapshot(snapshot, experiment_id)
        verified = _verify_artifacts(store, snapshot, trials)
        coverage = _coverage(frozen, trials, verified)
        report = _report(snapshot, experiment, frozen, trials, coverage, registry)
        destination.mkdir()
        owned = True
        for name in ('events', 'calls'):
            _write_jsonl(destination / (name + '.jsonl'), snapshot[name])
        _write_jsonl(destination / 'campaigns.jsonl',
                     [dict(state, record_kind='manifest') for state in snapshot['campaign_states']] +
                     [dict(dispatch, record_kind='dispatch_receipt') for dispatch in snapshot['campaigns']])
        _write_jsonl(destination / 'scores.jsonl',
                     [event for event in snapshot['events'] if event['kind'] == 'score_recorded'])
        _write_coverage(destination / 'coverage.csv', coverage)
        _write_bytes(destination / 'report.json', canonical_bytes(report) + b'\n')
        _write_bytes(destination / 'report.md', _markdown(report).encode('utf-8'))
        return report
    except BaseException as exc:
        if owned:
            try:
                shutil.rmtree(destination)
            except OSError:
                raise BenchmarkError('export_cleanup_failed', 'output') from None
        if isinstance(exc, BenchmarkError):
            raise
        if isinstance(exc, (OSError, ValueError, TypeError, KeyError, AttributeError, RecursionError, OverflowError)):
            raise BenchmarkError('export_failed', 'snapshot') from None
        raise

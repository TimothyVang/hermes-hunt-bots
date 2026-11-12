"""Offline scoring of immutable framework-managed team submissions.

Scoring is mechanical by default (deterministic rules, never a model, never
presented as human verdicts). An optional human adjudication file forms a
separate ``human`` cohort. Truth remains in evaluator storage. This module never
invokes a model, a checker, ledger decisions, or lab actions; a human name is an
attestation, not authentication.
"""
import os
from pathlib import Path
import re

from benchmark_contracts import (
    AUTO_ADVANCE_ACTOR, AUTO_ADVANCE_NOTE, REVIEW_POLICY, BenchmarkError, ROLE_IDS, STAGE_KEYS,
    _no_alias, _relative, canonical_bytes, confined_file, decode_json, digest_bytes, parse_utc,
    truth_attestation, validate_truth,
)
from benchmark_decisions import _read_ledger_artifact, _receipt_handoff, ledger_snapshot
from benchmark_scoring import (
    HUMAN, MECHANICAL, MECHANICAL_RULES, RUBRIC_VERSION, edge_item_id, score_output,
)
from benchmark_store import BenchmarkStore


SCORE_FIELDS = frozenset((
    'schema_version', 'rubric_version', 'variant', 'case_id', 'scenario_id',
    'family_id', 'team_id', 'repetition', 'output_sha256', 'truth_sha256',
    'adjudication_sha256', 'truth_frozen', 'status', 'completed', 'trial_status',
    'metrics', 'offline_time_to_first_supported_finding_ms',
    'timing_limitations', 'adjudication', 'truth_attestation', 'review_policy',
))
# Every stage auto-advances: the one scored variant is the team's final handoff.
VARIANT = 'team_output'
SCORE_STATUSES = ('final', 'provisional', MECHANICAL)


def adjudication_mode(adjudication):
    """None or the literal ``mechanical`` selects mechanical rules; a path is human."""
    return MECHANICAL if adjudication is None or adjudication == MECHANICAL else HUMAN


def _fail(code, field):
    raise BenchmarkError(code, field) from None


def _fields(value, keys, field):
    if type(value) is not dict or set(value) != set(keys):
        _fail('invalid_fields', field)


def _text(value, field):
    if type(value) is not str or not value.strip() or '\x00' in value:
        _fail('invalid_text', field)


def _identity(value):
    return re.sub(r'[\s_]+', '-', value.strip().casefold())


def _model_identities(frozen):
    names = set(ROLE_IDS) | {'model', 'evidence-checker', 'checker', 'benchmark-scorer',
                              'jev', 'typesafe', 'assistant', 'bot'}
    for team in frozen['experiment']['teams']:
        names.add(team['team_id'])
        models = list(team['roles'].values())
        if 'evidence_checker' in team:
            models.append(team['evidence_checker'])
        for model in models:
            names.update([model['provider'], model['model_requested']])
            names.update(model['expected_model_ids'])
    return {_identity(name) for name in names}


def _human(by, note, frozen):
    _text(by, 'adjudication.by')
    _text(note, 'adjudication.note')
    if _identity(by) in _model_identities(frozen):
        _fail('human_adjudication_required', 'adjudication.by')


def _read_file(path, field):
    path = Path(path)
    try:
        return confined_file(path.parent, path.name).read_bytes()
    except OSError:
        _fail('file_unavailable', field)


def load_truths(directory, frozen):
    """Validate ``<case_id>/evaluator/truth.json`` for every frozen case; no writes."""
    result = {}
    for case in frozen['cases']:
        case_id = case['evidence']['case_id']
        try:
            path = confined_file(Path(directory), case_id + '/evaluator/truth.json')
            content = path.read_bytes()
        except OSError:
            _fail('file_unavailable', 'truth')
        truth = decode_json(content)
        validate_truth(truth, case['evidence'])
        if truth['attack_release'] != case['scenario']['attack_release']:
            _fail('scope_mismatch', 'truth.attack_release')
        # Unreviewed proposed answer keys are allowed but always carried as a label.
        result[case_id] = {'bytes': content, 'truth': truth, 'sha256': digest_bytes(content),
                           'attestation': truth_attestation(truth)}
    return result


def _submission_call(store, trial, view, submitted, used):
    ledger, calls, events = view['ledger'], view['calls'], view['events']
    stage = next(key for key, task in trial['task_mapping'].items() if task == submitted['task_id'])
    linked = [event for event in events if event['kind'] == 'stage_submitted'
              and event['payload'].get('ledger_submit_event_id') == submitted['id']]
    call_ids = {event['call_id'] for event in linked}
    if len(call_ids) > 1:
        _fail('handoff_mismatch', 'submission.call_id')
    candidates = [call for call in calls if call['spec']['stage_key'] == stage
                  and call['spec']['component'] == 'narrative' and call['status'] == 'completed'
                  and call['call_id'] not in used]
    if linked:
        candidates = [call for call in candidates if call['call_id'] in call_ids]
    elif submitted['actor'] == 'generic':
        artifacts = [artifact for artifact in ledger['artifacts']
                     if artifact['task_id'] == submitted['task_id'] and artifact['description'] == 'CLI stdout'
                     and submitted['note'] == 'CLI exited successfully; authentic output handoff: {}; stderr: {}'.format(
                         artifact['path'], Path(artifact['path']).with_name('stderr.txt'))]
        if len(artifacts) != 1:
            _fail('handoff_mismatch', 'ledger.submit')
        raw = _read_ledger_artifact(store, trial, artifacts[0]['path'],
                                    view['frozen']['experiment']['budgets']['max_response_bytes'])
        sha = digest_bytes(raw)
        candidates = [call for call in candidates if call['receipt']['response_sha256'] == sha]
    else:
        candidates = [call for call in candidates if submitted['note'] ==
                      'Benchmark recovered immutable response: {}; sha256: {}.'.format(
                          call['call_id'], call['receipt']['response_sha256'])]
    if not candidates:
        _fail('unsealed_output', 'ledger.submit')
    # Identical repeated output bytes still retain their original attempt order.
    call = min(candidates, key=lambda item: item['spec']['attempt_index'])
    handoff = _receipt_handoff(store, trial, stage, view, submitted, call)
    used.add(call['call_id'])
    for event in linked:
        payload = event['payload']
        if (event['task_id'] != submitted['task_id'] or payload.get('stage_key') != stage
                or payload.get('attempt_index') != call['spec']['attempt_index']
                or payload.get('output_sha256') != handoff['output_sha256']):
            _fail('handoff_mismatch', 'submission.binding')
        if 'output_artifact' in payload and payload['output_artifact'] != handoff['output_artifact']:
            _fail('handoff_mismatch', 'submission.output_artifact')
    return dict(handoff, stage_key=stage)


def _trial_seals(store, trial, snapshot):
    """Sealed submissions plus their bound automatic advances; nothing is human-approved.

    A ledger ``auto_advance`` counts only with its exact store ``stage_auto_advanced``
    record. A missing record (crash window) leaves the trial unresolved; a
    contradicting one is refused. A direct ledger approve/reject is a manual action
    outside the benchmark and keeps the trial unresolved, never accepted.
    """
    frozen = snapshot['experiment']
    ledger = ledger_snapshot(store, trial, frozen)
    events = [event for event in snapshot['events'] if event['trial_id'] == trial['trial_id']]
    calls = [call for call in snapshot['calls'] if call['spec']['trial_id'] == trial['trial_id']]
    view = {'frozen': frozen, 'ledger': ledger, 'calls': calls, 'events': events}
    used = set()
    submissions = [_submission_call(store, trial, view, event, used)
                   for event in ledger['events'] if event['kind'] == 'submit']
    by_submit = {item['submit_event']['id']: item for item in submissions}
    stages = {task: stage for stage, task in trial['task_mapping'].items()}
    advanced, unbound = {}, False
    for actual in ledger['events']:
        if actual['kind'] != 'auto_advance':
            continue
        bindings = [event for event in events if event['kind'] == 'stage_auto_advanced'
                    and event['payload'].get('ledger_event_id') == actual['id']]
        if not bindings:
            unbound = True
            continue
        stage = stages.get(actual['task_id'])
        payload = bindings[0]['payload']
        handoff = by_submit.get(payload.get('ledger_submit_event_id'))
        if (len(bindings) != 1 or stage is None or handoff is None
                or actual['actor'] != AUTO_ADVANCE_ACTOR or actual['note'] != AUTO_ADVANCE_NOTE
                or bindings[0]['actor'] != AUTO_ADVANCE_ACTOR
                or payload.get('review_policy') != REVIEW_POLICY
                or payload.get('stage_key') != stage or handoff['stage_key'] != stage
                or payload.get('output_sha256') != handoff['output_sha256']
                or payload.get('output_artifact') != handoff['output_artifact']
                or bindings[0]['call_id'] != handoff['call']['call_id']):
            _fail('advance_unbound', 'auto_advance.binding')
        intervening = [event for event in ledger['events']
                       if event['task_id'] == actual['task_id']
                       and handoff['submit_event']['id'] < event['id'] <= actual['id']
                       and event['kind'] in ('submit', 'approve', 'reject', 'run-started', 'auto_advance')]
        if intervening != [actual]:
            _fail('advance_unbound', 'auto_advance.sequence')
        advanced[stage] = handoff
    manual = any(event['kind'] in ('approve', 'reject') for event in ledger['events'])
    unresolved = manual or unbound
    accepted = None
    completed = all(task['status'] == 'done' for task in ledger['tasks'].values()) and not unresolved
    if completed:
        for stage in STAGE_KEYS:
            latest = [item for item in submissions if item['stage_key'] == stage]
            if not latest:
                _fail('incomplete_snapshot', 'ledger.completed')
            item = latest[-1]
            narrative_calls = [call for call in calls if call['spec']['stage_key'] == stage
                               and call['spec']['component'] == 'narrative']
            if not narrative_calls or max(narrative_calls, key=lambda call: call['spec']['attempt_index'])['call_id'] != item['call']['call_id']:
                completed = False
            if advanced.get(stage) is not item:
                completed = False
            elif stage == 'handoff':
                accepted = item
    if not completed:
        accepted = None
    unknown = any(call['status'] in ('reserved', 'unknown') for call in calls)
    unresolved = unresolved or unknown
    terminal_failure = trial['status'] in ('failed', 'blocked') and any(
        call['status'] == 'failed' for call in calls) and not unknown
    if any(task['status'] in ('running', 'review') for task in ledger['tasks'].values()):
        terminal_failure = False
    # A store-recorded termination (budget exhausted, unrecoverable stage) ends
    # the schedule: a completion failure with every eligible positive missed,
    # never an open pending trial.
    if trial['status'] == 'terminated' and not completed and not unknown:
        terminal_failure = True
    state = ('completed' if completed and not unknown else 'unknown' if unknown else
             'manual_ledger_decision' if manual else 'advance_unbound' if unbound else
             trial['status'] if terminal_failure else
             'running' if any(task['status'] == 'running' for task in ledger['tasks'].values()) else
             'review' if any(task['status'] == 'review' for task in ledger['tasks'].values()) else 'pending')
    if ledger_snapshot(store, trial, frozen) != ledger:
        _fail('state_conflict', 'ledger.snapshot')
    return {'ledger': ledger, 'submissions': submissions, 'advanced': advanced,
            'accepted': accepted, 'terminal': completed or terminal_failure,
            'trial_status': state, 'unresolved': unresolved}


def _sealed_snapshot(store, experiment_id):
    snapshot = store.snapshot(experiment_id, verify_truth=False)
    if snapshot['experiment']['experiment']['rubric_version'] != RUBRIC_VERSION:
        _fail('unsupported_rubric', 'adjudication.rubric_version')
    seals = {trial['trial_id']: _trial_seals(store, trial, snapshot) for trial in snapshot['trials']}
    if store.snapshot(experiment_id, verify_truth=False) != snapshot:
        _fail('state_conflict', 'snapshot')
    return snapshot, seals


def _items(output):
    return ([{'item_kind': 'claim', 'item_id': item['claim_id']} for item in output['claims']]
            + [{'item_kind': 'finding', 'item_id': item['finding_id']} for item in output['findings']]
            + [{'item_kind': 'edge', 'item_id': edge_item_id(edge)} for edge in output.get('chain_edges', [])])


def _blind_output(trial, handoff, frozen):
    # Metadata is blind; scored narrative bytes are deliberately never rewritten.
    text = canonical_bytes(handoff['output']).decode('utf-8').casefold()
    names = []
    for team in frozen['experiment']['teams']:
        names.append(team['team_id'])
        models = list(team['roles'].values())
        if 'evidence_checker' in team:
            models.append(team['evidence_checker'])
        for model in models:
            names.extend([model['model_requested'], model['provider']])
            names.extend(model['expected_model_ids'])
    disclosed = any(name.casefold() in text for name in names)
    return {'trial_id': trial['trial_id'], 'case_id': trial['case_id'],
            'output_sha256': handoff['output_sha256'], 'output': handoff['output'],
            'items': _items(handoff['output']),
            'blinding': {'status': 'compromised' if disclosed else 'not_guaranteed',
                         'limitations': ['narrative_identity_disclosure_detected'] if disclosed else
                         ['narrative_may_self_identify_human_inspection_required']}}


def _template(snapshot, seals):
    outputs, seen = [], set()
    for trial in sorted(snapshot['trials'], key=lambda item: item['trial_id']):
        for handoff in seals[trial['trial_id']]['submissions']:
            key = trial['trial_id'], handoff['output_sha256']
            if key not in seen:
                outputs.append(_blind_output(trial, handoff, snapshot['experiment']))
                seen.add(key)
    return {'schema_version': 1, 'rubric_version': RUBRIC_VERSION, 'outputs': outputs, 'verdicts': []}


def adjudication_template(state_root, experiment_id, output_path):
    store = BenchmarkStore(state_root)
    snapshot, seals = _sealed_snapshot(store, experiment_id)
    document = _template(snapshot, seals)
    path = Path(output_path)
    if path.exists() or path.is_symlink():
        _fail('already_exists', 'adjudication.output')
    try:
        _relative(path.name, 'adjudication.output')
        _no_alias(path.absolute(), 'adjudication.output')
        with path.open('xb') as stream:
            stream.write(canonical_bytes(document))
            stream.flush()
            os.fsync(stream.fileno())
    except FileExistsError:
        _fail('already_exists', 'adjudication.output')
    except OSError:
        _fail('file_unavailable', 'adjudication.output')
    return {'experiment_id': experiment_id, 'status': 'template_created',
            'outputs': len(document['outputs']), 'rubric_version': RUBRIC_VERSION,
            'template_sha256': digest_bytes(canonical_bytes(document)),
            'blinding': 'metadata_only_human_inspection_required'}


def _adjudication(path, expected, frozen):
    content = _read_file(path, 'adjudication')
    document = decode_json(content)
    _fields(document, {'schema_version', 'rubric_version', 'outputs', 'verdicts'}, 'adjudication')
    if type(document['schema_version']) is not int or document['schema_version'] != 1:
        _fail('unsupported_schema', 'adjudication.schema_version')
    if document['rubric_version'] != RUBRIC_VERSION:
        _fail('scope_mismatch', 'adjudication.rubric_version')
    if document['outputs'] != expected['outputs']:
        _fail('stale_adjudication', 'adjudication.outputs')
    if type(document['verdicts']) is not list:
        _fail('invalid_array', 'adjudication.verdicts')
    outputs = {(item['trial_id'], item['output_sha256']): item for item in expected['outputs']}
    verdicts = {key: [] for key in outputs}
    for verdict in document['verdicts']:
        _fields(verdict, {'trial_id', 'output_sha256', 'item_kind', 'item_id', 'verdict',
                          'event_ids', 'by', 'note'}, 'adjudication.verdict')
        _human(verdict['by'], verdict['note'], frozen)
        if type(verdict['trial_id']) is not str or type(verdict['output_sha256']) is not str:
            _fail('scope_mismatch', 'adjudication.output_sha256')
        key = verdict['trial_id'], verdict['output_sha256']
        if key not in outputs:
            _fail('scope_mismatch', 'adjudication.output_sha256')
        verdicts[key].append(verdict)
    return verdicts, digest_bytes(content), content


def _mechanical_document(expected):
    """The rule identity plus the exact sealed outputs it judged; no human verdicts."""
    return {'schema_version': 1, 'rubric_version': RUBRIC_VERSION, 'adjudication': MECHANICAL,
            'rules': MECHANICAL_RULES, 'outputs': expected['outputs']}


def load_adjudication(adjudication, expected, frozen):
    """Return (verdicts per sealed output, mode, sha256, private bytes).

    ``adjudication`` None (or the literal ``mechanical``) applies the mechanical
    rules, whose verdict lists are None; a path loads a human adjudication file.
    """
    mode = adjudication_mode(adjudication)
    if mode == MECHANICAL:
        content = canonical_bytes(_mechanical_document(expected))
        return ({(item['trial_id'], item['output_sha256']): None for item in expected['outputs']},
                mode, digest_bytes(content), content)
    verdicts, sha, content = _adjudication(adjudication, expected, frozen)
    return verdicts, mode, sha, content


def settled_status(mode):
    """The non-provisional status a score of this adjudication mode may reach."""
    return MECHANICAL if mode == MECHANICAL else 'final'


def _settles(seal, truth_frozen):
    """Terminal, resolved and scored against truth frozen before any dispatch
    (automatically at init); this holds for mechanical and human cohorts alike."""
    return seal['terminal'] and not seal['unresolved'] and truth_frozen


def _date(value):
    return parse_utc(value, 'receipt.utc')


def _timing(trial, seal, snapshot, scored):
    handoffs = seal['submissions']
    if not handoffs:
        return None, ['no_sealed_submission']
    if any(scored[(trial['trial_id'], item['output_sha256'])]['status'] not in ('final', MECHANICAL)
           for item in handoffs):
        return None, ['early_stage_adjudication_missing']
    calls = [call for call in snapshot['calls'] if call['spec']['trial_id'] == trial['trial_id']]
    if any(call['receipt'] is None or call['receipt']['start_utc'] is None for call in calls):
        return None, ['call_timing_unavailable']
    starts = [_date(call['receipt']['start_utc']) for call in calls]
    supported = [item for item in handoffs if scored[(trial['trial_id'], item['output_sha256'])]['detection']['tp'] > 0]
    if not supported:
        return None, ['no_supported_finding']
    ends = [item['call']['receipt']['end_utc'] for item in supported]
    if not starts or any(end is None for end in ends):
        return None, ['call_timing_unavailable']
    elapsed = (min(_date(end) for end in ends) - min(starts)).total_seconds() * 1000
    if elapsed < 0:
        return None, ['inconsistent_call_timestamps']
    return elapsed, ['offline_elapsed_time_not_production_mttd']


def validate_score_binding(store, trial, output_sha256, score):
    """Store boundary: structured scores bind a real submission, never a sentinel."""
    _fields(score, SCORE_FIELDS, 'score')
    if (type(score['schema_version']) is not int or score['schema_version'] != 1
            or score['rubric_version'] != RUBRIC_VERSION or score['variant'] != VARIANT
            or score['status'] not in SCORE_STATUSES
            or score['adjudication'] not in (HUMAN, MECHANICAL)
            or score['review_policy'] != REVIEW_POLICY
            or score['output_sha256'] != output_sha256):
        _fail('scope_mismatch', 'score')
    # Mechanical scores are never final; human ones are never labelled mechanical.
    if score['status'] != 'provisional' and score['status'] != settled_status(score['adjudication']):
        _fail('scope_mismatch', 'score.status')
    for key in ('truth_frozen', 'completed'):
        if type(score[key]) is not bool:
            _fail('invalid_boolean', 'score.' + key)
    for key in ('truth_sha256', 'adjudication_sha256'):
        if type(score[key]) is not str or re.fullmatch('[0-9a-f]{64}', score[key]) is None:
            _fail('invalid_digest', 'score.' + key)
    for key in ('case_id', 'scenario_id', 'team_id', 'repetition'):
        if score[key] != trial[key]:
            _fail('scope_mismatch', 'score.' + key)
    if type(score['repetition']) is not int:
        _fail('invalid_number', 'score.repetition')
    elapsed = score['offline_time_to_first_supported_finding_ms']
    if elapsed is not None and (type(elapsed) not in (int, float) or elapsed < 0):
        _fail('invalid_number', 'score.offline_time_to_first_supported_finding_ms')
    if type(score['timing_limitations']) is not list or any(type(reason) is not str
                                                         for reason in score['timing_limitations']):
        _fail('invalid_array', 'score.timing_limitations')
    snapshot = store.snapshot(trial['experiment_id'])
    frozen = snapshot['experiment']
    seal = _trial_seals(store, trial, snapshot)
    case = next(case for case in frozen['cases']
                if case['evidence']['case_id'] == trial['case_id'])
    if score['family_id'] != case['scenario']['family_id'] or score['trial_status'] != seal['trial_status']:
        _fail('scope_mismatch', 'score.trial_status')
    if type(score['metrics']) is not dict:
        _fail('invalid_object', 'score.metrics')
    expected = seal['accepted']
    if (expected['output_sha256'] if expected else None) != output_sha256:
        _fail('unsealed_output', 'score.output_sha256')
    if score['completed'] != (expected is not None):
        _fail('scope_mismatch', 'score.completed')
    truth = decode_json(store.read_evaluator_artifact('truth', score['truth_sha256']))
    validate_truth(truth, case['evidence'])
    if truth['attack_release'] != case['scenario']['attack_release']:
        _fail('scope_mismatch', 'truth.attack_release')
    if score['truth_attestation'] != truth_attestation(truth):
        _fail('scope_mismatch', 'score.truth_attestation')
    adjudication = decode_json(store.read_evaluator_artifact('adjudication', score['adjudication_sha256']))
    if score['adjudication'] == MECHANICAL:
        _fields(adjudication, {'schema_version', 'rubric_version', 'adjudication', 'rules', 'outputs'},
                'adjudication')
        if (adjudication['schema_version'] != 1 or adjudication['adjudication'] != MECHANICAL
                or adjudication['rules'] != MECHANICAL_RULES or type(adjudication['outputs']) is not list):
            _fail('invalid_fields', 'adjudication')
    else:
        _fields(adjudication, {'schema_version', 'rubric_version', 'outputs', 'verdicts'}, 'adjudication')
        if (type(adjudication['schema_version']) is not int or adjudication['schema_version'] != 1
                or type(adjudication['outputs']) is not list or type(adjudication['verdicts']) is not list):
            _fail('invalid_fields', 'adjudication')
    if adjudication['rubric_version'] != RUBRIC_VERSION:
        _fail('scope_mismatch', 'adjudication.rubric_version')
    if expected is not None and _blind_output(trial, expected, frozen) not in adjudication['outputs']:
        _fail('unsealed_output', 'adjudication.outputs')
    relevant = None
    if score['adjudication'] == HUMAN:
        relevant = [item for item in adjudication['verdicts']
                    if item['trial_id'] == trial['trial_id'] and item['output_sha256'] == output_sha256]
        for verdict in relevant:
            _human(verdict['by'], verdict['note'], frozen)
    actual = score_output(expected['output'] if expected else None, truth, case['evidence'],
                          relevant, trial_id=trial['trial_id'], output_sha256=output_sha256,
                          completed=expected is not None, adjudication=score['adjudication'])
    if actual != score['metrics']:
        _fail('scope_mismatch', 'score.metrics')
    if score['status'] != 'provisional' and (
            not _settles(seal, score['truth_frozen'])
            or score['metrics'].get('status') != score['status']):
        _fail('provisional_required', 'score.status')
    freezes = [event for event in snapshot['events'] if event['payload'].get('record_type') == 'truth_frozen']
    if score['truth_frozen'] != bool(freezes):
        _fail('scope_mismatch', 'score.truth_frozen')
    if score['truth_frozen']:
        if not freezes or not any(item['case_id'] == trial['case_id']
                                 and item['truth_sha256'] == score['truth_sha256']
                                 for item in freezes[0]['payload']['cases']):
            _fail('scope_mismatch', 'score.truth_sha256')


def score_experiment(state_root, experiment_id, truth_directory, adjudication=None):
    """Score every scheduled trial's ``team_output``.

    ``adjudication`` None applies the mechanical rules (status ``mechanical``);
    a human adjudication file path forms the separate ``human`` cohort.
    """
    store = BenchmarkStore(state_root)
    # All existing responses, ledger handoffs and auto-advances are inspected before truth.
    snapshot, seals = _sealed_snapshot(store, experiment_id)
    if store.snapshot(experiment_id) != snapshot:
        _fail('state_conflict', 'score.snapshot')
    frozen = snapshot['experiment']
    truths = load_truths(truth_directory, frozen)
    freezes = [event for event in snapshot['events'] if event['payload'].get('record_type') == 'truth_frozen']
    for event in freezes:
        store._verify_truth_freeze(event, frozen)
    if freezes:
        expected = {item['case_id']: item['truth_sha256'] for item in freezes[0]['payload']['cases']}
        if expected != {key: value['sha256'] for key, value in truths.items()}:
            _fail('fingerprint_conflict', 'truth.frozen')
    verdicts, mode, adjudication_sha, adjudication_bytes = load_adjudication(
        adjudication, _template(snapshot, seals), frozen)
    target = settled_status(mode)
    cases = {case['evidence']['case_id']: case for case in frozen['cases']}
    scored, records = {}, []
    for trial in snapshot['trials']:
        seal = seals[trial['trial_id']]
        case, truth = cases[trial['case_id']], truths[trial['case_id']]
        for handoff in seal['submissions']:
            key = trial['trial_id'], handoff['output_sha256']
            if key not in scored:
                scored[key] = score_output(handoff['output'], truth['truth'], case['evidence'],
                                           verdicts[key], trial_id=key[0], output_sha256=key[1],
                                           adjudication=mode)
        selected = seal['accepted']
        elapsed, timing_limitations = _timing(trial, seal, snapshot, scored)
        sha = selected['output_sha256'] if selected else None
        metrics = scored[(trial['trial_id'], sha)] if selected else score_output(
            None, truth['truth'], case['evidence'], None if mode == MECHANICAL else [],
            trial_id=trial['trial_id'], output_sha256=None, completed=False, adjudication=mode)
        settled = metrics['status'] == target and _settles(seal, bool(freezes))
        score = {'schema_version': 1, 'rubric_version': RUBRIC_VERSION, 'variant': VARIANT,
                 'case_id': trial['case_id'], 'scenario_id': trial['scenario_id'],
                 'family_id': case['scenario']['family_id'], 'team_id': trial['team_id'],
                 'repetition': trial['repetition'], 'output_sha256': sha,
                 'truth_sha256': truth['sha256'], 'adjudication_sha256': adjudication_sha,
                 'truth_frozen': bool(freezes), 'status': target if settled else 'provisional',
                 'completed': selected is not None, 'trial_status': seal['trial_status'],
                 'metrics': metrics, 'offline_time_to_first_supported_finding_ms': elapsed,
                 'timing_limitations': timing_limitations, 'adjudication': mode,
                 'truth_attestation': truth['attestation'], 'review_policy': REVIEW_POLICY}
        records.append((trial['trial_id'], sha, score))
    # One score batch, or none, if either authority changed while inputs were read.
    with store.connection(immediate=True) as db:
        current, current_seals = _sealed_snapshot(store, experiment_id)
        if current != snapshot or current_seals != seals:
            _fail('state_conflict', 'score.snapshot')
        for truth in truths.values():
            store.write_evaluator_artifact('truth', truth['bytes'])
        store.write_evaluator_artifact('adjudication', adjudication_bytes)
        for trial_id, sha, score in records:
            store.record_score(trial_id, sha, score, 'benchmark-scorer', db=db)
    statuses = {score['status'] for _, _, score in records}
    limitations = [] if freezes else ['truth_not_frozen_before_answers']
    if mode == MECHANICAL:
        limitations.append('mechanical_adjudication_not_human_verdicts')
    limitations.extend('truth_' + attestation for attestation in
                       sorted({truth['attestation'] for truth in truths.values()} - {'human_attested'}))
    return {'experiment_id': experiment_id,
            'status': target if records and statuses == {target} else 'provisional',
            'recorded_scores': len(records), 'scheduled_trials': len(snapshot['trials']),
            'truth_frozen': bool(freezes), 'rubric_version': RUBRIC_VERSION,
            'adjudication': mode, 'review_policy': REVIEW_POLICY, 'variant': VARIANT,
            'truth_attestation': sorted({truth['attestation'] for truth in truths.values()}),
            'limitations': limitations}

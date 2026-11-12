"""Frozen six-role scheduling over the task ledger; fully automatic.

Every validated stage output advances automatically, unreviewed, through the
ledger's distinct `auto_advance` transition; nothing is recorded as a human
approval. Public functions return JSON-compatible reports; build_prompt returns
exact UTF-8 bytes. Dry runs never advance, create artifacts, authorize calls,
or launch a subprocess.
"""
import argparse
import base64
import collections
import concurrent.futures
import contextlib
import datetime as dt
from decimal import Decimal
import importlib.metadata
import io
import math
import os
from pathlib import Path
import random
import shutil
import subprocess
import sys
import threading
import uuid

from benchmark_paths import FRAMEWORK, source_root
import bot
from benchmark_contracts import (REVIEW_POLICY, BenchmarkError, call_cost_bound, canonical_bytes,
                                 confined_file, decode_json, digest_bytes, max_concurrent_calls,
                                 parse_utc, route_is_paid, validate_public_bundle, validate_state_root)
from benchmark_store import BenchmarkStore, STAGE_ROLES, _frozen, automatic_retry, call_timing
from benchmark_decisions import (WORKFLOW_TITLE, WORKFLOW_SCOPE, WORKFLOW_ACCEPTANCE,
                                 advanced_output, auto_advance, auto_reconciled, auto_recover, auto_recovery,
                                 ensure_checker_artifact, inspect_stage, record_submission, retry_eligible,
                                 stage_handoff, trial_view)

HERE = Path(__file__).resolve().parent
DEPENDENCIES = {
    'scope': [], 'endpoint_evidence': ['scope'], 'network_evidence': ['scope'],
    'hypotheses': ['scope'],
    'analysis': ['scope', 'endpoint_evidence', 'network_evidence', 'hypotheses'],
    'review': ['scope', 'endpoint_evidence', 'network_evidence', 'hypotheses', 'analysis'],
    'handoff': ['scope', 'endpoint_evidence', 'network_evidence', 'hypotheses', 'analysis', 'review'],
}
LEDGER_ROLES = dict(zip(DEPENDENCIES, ('coordinator', 'researcher', 'researcher',
                                    'researcher', 'builder', 'reviewer', 'coordinator')))


def _fail(code, field):
    raise BenchmarkError(code, field) from None


def _now():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec='microseconds')


def _workflow(template):
    tasks = template['tasks']
    if ([task['key'] for task in tasks] != list(DEPENDENCIES)
            or any(task['depends_on'] != DEPENDENCIES[task['key']]
                   or task['role'] != LEDGER_ROLES[task['key']] for task in tasks)):
        _fail('invalid_workflow', 'workflow')


def _team(frozen, trial):
    return next(team for team in frozen['experiment']['teams'] if team['team_id'] == trial['team_id'])


def _case(frozen, trial):
    return next(case for case in frozen['cases'] if case['evidence']['case_id'] == trial['case_id'])


def _schedule(frozen, trials):
    ordered = sorted(trials, key=lambda trial: (trial['case_id'], trial['team_id'], trial['repetition']))
    random.Random(frozen['experiment']['schedule_seed']).shuffle(ordered)
    return ordered


def terminate(state_root, experiment_id, trial_id, by, note):
    """Explicit human abandonment: a terminal completion failure; never dispatches."""
    for value, field in ((by, 'terminate.by'), (note, 'terminate.note')):
        if type(value) is not str or not value.strip() or '\x00' in value:
            _fail('invalid_text', field)
    store = BenchmarkStore(state_root)
    trial = store.get_trial(trial_id)
    if trial['experiment_id'] != experiment_id:
        _fail('scope_mismatch', 'trial.experiment_id')
    store.terminate_trial(trial_id, 'human_abandoned', by, note)
    return dict(_status(store, experiment_id), terminated_trial_id=trial_id)


def initialize_experiment(state_root, loaded, truth_directory, holdout_registry=None):
    """Validate all inputs, including truth, before creating fresh, isolated ledgers.

    Truth from `truth_directory` (`<case_id>/evaluator/truth.json`) is frozen
    automatically in the same transaction as the experiment, before any trial
    exists. Holdout scenarios require a registry; a retired holdout is refused
    before any state exists, so a selection-exposed case never joins a new cohort.
    """
    validate_state_root(state_root)
    _workflow(loaded['workflow'])
    scenarios = [case['scenario'] for case in loaded['cases']]
    if holdout_registry is not None:
        from benchmark_holdout import check_unretired, load_registry
        check_unretired(load_registry(holdout_registry), scenarios)
    elif any(scenario['split'] == 'holdout' for scenario in scenarios):
        _fail('holdout_registry_required', 'holdout_registry')
    catalog = decode_json(confined_file(FRAMEWORK, 'hermes-bots/catalog.json').read_bytes())
    purposes = {entry['name']: entry['title'] + ': ' + entry['description']
                for entry in catalog if entry['name'] in set(STAGE_ROLES.values())}
    frozen = decode_json(canonical_bytes({
        'experiment': loaded['experiment'], 'coverage': loaded['coverage'],
        'workflow': loaded['workflow'], 'prompt_contract': loaded['prompt_contract'],
        'cases': [{'scenario': case['scenario'], 'evidence': case['evidence'],
                   'public_files': case['evidence']['files']} for case in loaded['cases']],
        'role_instructions': purposes, 'created_utc': _now(), 'execution': 'framework-managed',
    }))
    _frozen(frozen)
    # Evaluator-only bytes, validated against the released evidence; never
    # copied into a trial or prompt.
    from benchmark_adjudication import load_truths
    truths = {case_id: item['bytes'] for case_id, item in load_truths(truth_directory, frozen).items()}
    # Read the exact released bytes before writing any state. Later copies use
    # these bytes, not mutable source paths; each repetition gets its own refs.
    public = {}
    for case in loaded['cases']:
        evidence = case['evidence']
        root = Path(case['evidence_path']).parent
        validate_public_bundle(evidence, root)
        files = {}
        for entry in evidence['files']:
            data = confined_file(root, entry['path']).read_bytes()
            if len(data) != entry['byte_count'] or digest_bytes(data) != entry['sha256']:
                _fail('digest_mismatch', 'evidence.files')
            files[entry['path']] = data
        public[evidence['case_id']] = files
    root = Path(state_root)
    store = BenchmarkStore(root, create=not (root / 'benchmark.sqlite3').exists())
    store.create_experiment(frozen, truths)
    exp = frozen['experiment']
    for case in frozen['cases']:
        for team in exp['teams']:
            for repetition in range(1, exp['repetitions'] + 1):
                tid = uuid.uuid4().hex
                refs = {path: store.write_artifact(tid, 'public', data)
                        for path, data in public[case['evidence']['case_id']].items()}
                ledger = root / 'trials' / tid / 'ledger'
                with contextlib.redirect_stdout(io.StringIO()):
                    bot.initialize(ledger)
                with contextlib.closing(bot.connect(ledger)) as db:
                    workflow_id, mapping = bot.create_workflow(
                        db, frozen['workflow'], WORKFLOW_TITLE, WORKFLOW_SCOPE, WORKFLOW_ACCEPTANCE)
                store.create_trial({
                    'trial_id': tid, 'experiment_id': exp['experiment_id'],
                    'case_id': case['evidence']['case_id'], 'scenario_id': case['scenario']['scenario_id'],
                    'team_id': team['team_id'], 'repetition': repetition,
                    'workflow_id': workflow_id, 'task_mapping': mapping,
                    'case_evidence_sha256': case['scenario']['evidence_manifest_sha256'],
                    'status': 'pending', 'created_utc': _now(), 'public_artifacts': refs,
                })
    report = status(root, exp['experiment_id'])
    report['initialized'] = True
    return report


def build_prompt(store, trial, stage, view=None):
    """Canonical prompt; no evaluator data, runtime IDs, paths or model labels.

    `view` is a `trial_view` the caller just read; omitted, a fresh one is read.
    """
    if stage not in DEPENDENCIES:
        _fail('invalid_choice', 'stage')
    current = store.get_trial(trial['trial_id'])
    # A concurrent sibling branch may change only the mutable status.
    if {k: v for k, v in current.items() if k != 'status'} != {k: v for k, v in trial.items() if k != 'status'}:
        _fail('fingerprint_conflict', 'trial')
    if view is None:
        view = trial_view(store, trial)
    frozen = view['frozen']
    _workflow(frozen['workflow'])
    case = _case(frozen, trial)
    public = {key: value for key, value in case['evidence'].items() if key != 'files'}
    public['files'] = []
    for entry in case['evidence']['files']:
        data = store.read_artifact(trial['trial_id'], trial['public_artifacts'][entry['path']])
        if digest_bytes(data) != entry['sha256'] or len(data) != entry['byte_count']:
            _fail('digest_mismatch', 'trial.public_artifacts')
        try:
            content, encoding = data.decode('utf-8'), 'utf-8'
        except UnicodeDecodeError:
            content, encoding = base64.b64encode(data).decode('ascii'), 'base64'
        public['files'].append({'sha256': entry['sha256'], 'byte_count': len(data),
                                'encoding': encoding, 'content': content})
    step = next(task for task in frozen['workflow']['tasks'] if task['key'] == stage)
    predecessors = []
    for key in step['depends_on']:
        handoff = advanced_output(store, trial, key, view)
        item = {'stage_key': key, 'output': handoff['output']}
        if handoff.get('checker_output') is not None:
            # Measurements and provider/model identities belong in audit logs,
            # not in the next narrative role's evidence context.
            item['advisory_evidence_checker'] = {
                'results': [{name: result[name] for name in
                             ('claim_id', 'choice', 'confidence', 'probabilities', 'reason')
                             if name in result}
                            for result in handoff['checker_output']['results']]}
        predecessors.append(item)
    prompt = canonical_bytes({
        'prompt_contract': frozen['prompt_contract'],
        'role_purpose': frozen['role_instructions'][STAGE_ROLES[stage]],
        'stage': {'key': stage, 'scope': step['scope'], 'acceptance': step['acceptance']},
        'untrusted_public_evidence': public,
        'untrusted_immediate_predecessors': predecessors,
    })
    if len(prompt) > frozen['experiment']['budgets']['max_prompt_bytes']:
        _fail('budget_exceeded', 'prompt')
    return prompt


def _budgets(frozen, calls):
    budget, experiment = frozen['experiment']['budgets'], frozen['experiment']
    seconds = sum(BenchmarkStore.charge(call, 'seconds', experiment) for call in calls)
    measured = [call['receipt']['elapsed_ms'] if call['receipt'] else None for call in calls]
    if 'max_api_cost_usd' in budget:
        # Decimal, as in the store's reservation check, so rounding never
        # reports a budget the store would refuse (or vice versa).
        used = sum((Decimal(str(BenchmarkStore.charge(call, 'cost', experiment))) for call in calls), Decimal(0))
        cost_remaining = float(max(Decimal(0), Decimal(str(budget['max_api_cost_usd'])) - used))
    else:
        cost_remaining = None
    return {'calls_remaining': max(0, budget['max_calls_per_trial'] - len(calls)),
            'active_seconds_remaining': max(0, budget['max_active_seconds_per_trial'] - seconds),
            'measured_active_seconds': (sum(measured) / 1000.0 if all(value is not None for value in measured) else None),
            'unknown_active_time_calls': sum(value is None for value in measured),
            'api_cost_usd_remaining': cost_remaining,
            'max_prompt_bytes': budget['max_prompt_bytes'], 'max_response_bytes': budget['max_response_bytes'],
            'max_attempts_per_stage': budget['max_attempts_per_stage']}


def _models(team, stage):
    """The stage's narrative model, plus the configured checker for analysis."""
    return [team['roles'][STAGE_ROLES[stage]]] + (
        [team['evidence_checker']] if stage == 'analysis' and 'evidence_checker' in team else [])


def _cost_bounds(experiment, models):
    return [call_cost_bound(experiment['budgets'], model, experiment['pricing_snapshot']['rates'])
            for model in models if route_is_paid(model)]


def _exhausted(frozen, trial, budgets, stage, attempt):
    """Name the budget that permanently prevents this stage's next dispatch.

    Charges only grow while no call is uncertain, so an exhausted stage can never
    run again: the trial is a terminal completion failure, not a stall.
    """
    models = _models(_team(frozen, trial), stage)
    if attempt > budgets['max_attempts_per_stage']:
        return 'attempts'
    if budgets['calls_remaining'] < len(models):
        return 'calls'
    if budgets['active_seconds_remaining'] < sum(model['timeout_seconds'] for model in models):
        return 'active_seconds'
    bounds = _cost_bounds(frozen['experiment'], models)
    if bounds and (any(bound is None for bound in bounds) or budgets['api_cost_usd_remaining'] is None
                   or Decimal(str(budgets['api_cost_usd_remaining']))
                   < sum((Decimal(str(bound)) for bound in bounds), Decimal(0))):
        return 'api_cost'
    return None


def _timing(ledger, trial, calls, completed):
    """UTC wall time, separately labeled from measured model-active time.

    End-to-end runs from the first dispatch (earliest receipt start, as in the
    exported report) to the final handoff's automatic advance; never from init
    time, which would include waiting for other trials.
    """
    now = dt.datetime.now(dt.timezone.utc)
    starts = [parse_utc(call['receipt']['start_utc'], 'receipt.start_utc')
              for call in calls if call['receipt'] is not None]
    end = now
    if completed:
        advances = [parse_utc(event['time'], 'ledger.time') for event in ledger['events']
                    if event['task_id'] == trial['task_mapping']['handoff'] and event['kind'] == 'auto_advance']
        end = max(advances, default=now)
    return {'end_to_end_wall_seconds': (max(0, (end - min(starts)).total_seconds()) if starts else None),
            'end_to_end_basis': 'first_dispatch_to_final_auto_advance_utc'}


def automatic(events, call_id):
    """A failed call whose next attempt automation itself authorized."""
    return auto_reconciled(events, call_id) or automatic_retry(events, call_id)


def _trial_status(store, frozen, trial, retry_call=None):
    # One ledger, call and event read per trial, shared by every stage.
    view = trial_view(store, trial, frozen)
    ledger, calls = view['ledger'], view['calls']
    budgets = _budgets(frozen, calls)
    stages, ready, advance_stages, exhausted, recoverable, unrecoverable = [], [], [], [], [], []
    experiment, now = frozen['experiment'], dt.datetime.now(dt.timezone.utc)
    for key in DEPENDENCIES:
        info = inspect_stage(store, trial, key, view)
        blocker = info['blocker']
        state, latest = info['status'], info['call']
        recovery = auto_recovery(view, trial, key)
        if recovery is not None and recovery['action'] != 'manual':
            # Automation owns this stage's failed or uncertain model call: advance
            # retries, resolves or terminates it, or reports why it cannot.
            blocker = {'reconcile': 'previous_dispatch_unknown', 'retry': 'automatic_retry_pending',
                       'resume': 'auto_resume_pending', 'terminate': 'unrecoverable_configuration',
                       'process_stop_unconfirmed': 'process_stop_unconfirmed'}[recovery['action']]
            if recovery['action'] in ('reconcile', 'retry', 'resume'):
                recoverable.append(key)
            elif recovery['action'] == 'terminate':
                unrecoverable.append({'stage_key': key, 'call_id': recovery['call_id'],
                                      'failure_reason': recovery['failure_reason']})
        attempt = 1 + max((call['spec']['attempt_index'] for call in calls
                           if call['spec']['stage_key'] == key), default=0)
        exhausted_budget = None
        if (state == 'review' and blocker is None) or (state == 'done' and blocker == 'auto_advance_unbound'):
            # A validated submission advances, or an interrupted advance's
            # store mirror completes, without any model call.
            advance_stages.append(key)
        if (state in ('pending', 'active') and blocker is None
                and any(ledger['tasks'][dependency]['status'] != 'done'
                        for dependency in DEPENDENCIES[key])):
            blocker = 'prerequisites_not_advanced'
        if state in ('pending', 'active') and blocker is None:
            needs_dispatch = True
            if latest is not None:
                if latest['status'] in ('reserved', 'unknown'):
                    blocker, needs_dispatch = 'previous_dispatch_unknown', False
                elif latest['status'] == 'failed':
                    # Automatic reconciliation or retry authorizes its own next
                    # attempt; a human-resolved failure needs an explicit --retry-call.
                    if retry_call != latest['call_id'] and not automatic(view['events'], latest['call_id']):
                        blocker = 'retry_required'
                    elif not retry_eligible(store, trial, latest['call_id']):
                        blocker = 'reconciliation_required'
                elif latest['status'] == 'completed':
                    # Only a resolved failed checker call permits a new composite
                    # attempt; a completed narrative is recovered, never re-run.
                    checker_retry = next((call for call in calls
                                          if call['spec']['stage_key'] == key
                                          and call['spec']['component'] == 'evidence_checker'
                                          and call['spec']['attempt_index'] == latest['spec']['attempt_index']
                                          and (call['call_id'] == retry_call
                                               or automatic(view['events'], call['call_id']))), None)
                    if checker_retry is None or not retry_eligible(store, trial, checker_retry['call_id']):
                        blocker, needs_dispatch = 'submission_recovery_required', False
            if needs_dispatch:
                exhausted_budget = _exhausted(frozen, trial, budgets, key, attempt)
                if blocker is None:
                    try:
                        build_prompt(store, trial, key, view)
                    except BenchmarkError as exc:
                        blocker = exc.code
                        if exc.code == 'budget_exceeded' and exc.field == 'prompt' and exhausted_budget is None:
                            exhausted_budget = 'prompt_bytes'
                if exhausted_budget is not None:
                    blocker = 'budget_exceeded'
                    exhausted.append({'stage_key': key, 'budget': exhausted_budget})
            if blocker is None:
                ready.append(key)
        stages.append({'stage_key': key, 'task_id': trial['task_mapping'][key],
                       'role': STAGE_ROLES[key], 'ledger_status': state,
                       'auto_advanced': state == 'done' and blocker is None,
                       'last_call_id': latest['call_id'] if latest else None,
                       'last_call_status': latest['status'] if latest else None,
                       'failure_reason': (latest['receipt']['failure_reason']
                                          if latest and latest['receipt'] else None),
                       'uncertain_call_id': (recovery['call_id'] if recovery is not None and recovery['action']
                                             in ('reconcile', 'process_stop_unconfirmed', 'manual') else None),
                       'failed_call_id': (recovery['call_id'] if recovery is not None and recovery['action']
                                          in ('retry', 'resume', 'terminate') else None),
                       'blocker': blocker, 'exhausted_budget': exhausted_budget,
                       'next_attempt_index': attempt,
                       # Each call's elapsed time against its own timeout: the margin
                       # (an in-flight call counts from its reservation).
                       'calls': [call_timing(call, view['events'], experiment, now)
                                 for call in sorted((c for c in calls if c['spec']['stage_key'] == key),
                                                    key=lambda c: (c['spec']['attempt_index'],
                                                                   c['spec']['component']))]})
    # Independent siblings may run together, but unknown or running work in a
    # trial blocks every new dispatch and advance there until reconciled.
    if any(stage['ledger_status'] == 'running'
           or stage['blocker'] in ('previous_dispatch_unknown', 'process_stop_unconfirmed')
           for stage in stages):
        ready, advance_stages, state = [], [], 'unknown'
    elif all(stage['ledger_status'] == 'done' and stage['blocker'] is None for stage in stages):
        state = 'completed'
    elif ready or advance_stages or recoverable:
        state = 'ready'
    else:
        state = 'blocked'
    return {'trial_id': trial['trial_id'], 'case_id': trial['case_id'], 'team_id': trial['team_id'],
            'repetition': trial['repetition'], 'status': state, 'ready_stages': ready,
            'advance_stages': advance_stages, 'auto_recovery': recoverable,
            'unrecoverable': unrecoverable, 'budget_exhausted': exhausted, 'stages': stages,
            'budgets': budgets, 'timing': _timing(ledger, trial, calls, state == 'completed')}


def _status(store, experiment_id, retry_call=None, preflight=None):
    snapshot = store.snapshot(experiment_id, verify_truth=False, routine=True)
    frozen = snapshot['experiment']
    _workflow(frozen['workflow'])
    reports = []
    for trial in _schedule(frozen, snapshot['trials']):
        identity = {'trial_id': trial['trial_id'], 'case_id': trial['case_id'],
                    'team_id': trial['team_id'], 'repetition': trial['repetition'],
                    'ready_stages': [], 'advance_stages': [], 'auto_recovery': [], 'unrecoverable': [],
                    'budget_exhausted': []}
        if trial['status'] == 'terminated':
            # A terminal completion failure; never selected again, never a stall.
            notes = [event['payload'].get('note') for event in snapshot['events']
                     if event['kind'] == 'trial_terminated' and event['trial_id'] == trial['trial_id']]
            reports.append(dict(identity, status='terminated', terminal_reason=trial['terminal_reason'],
                                terminal_note=notes[-1] if notes else None))
            continue
        try:
            reports.append(_trial_status(store, frozen, trial, retry_call))
        except BenchmarkError as exc:
            reports.append(dict(identity, status='blocked', error={'code': exc.code, 'field': exc.field}))
    active = [trial for trial in reports if trial['status'] not in ('completed', 'terminated')]
    statuses = {trial['status'] for trial in active}
    if not active:
        overall = 'finished'
    elif 'ready' in statuses:
        overall = 'ready'
    elif 'unknown' in statuses:
        overall = 'unknown'
    else:
        overall = 'blocked'
    limit = max_concurrent_calls(frozen['experiment'])
    return {'experiment_id': experiment_id, 'execution': 'framework-managed',
            'status': overall, 'review_policy': REVIEW_POLICY,
            'truth_frozen': any(event['kind'] == 'evidence_sealed'
                                and event['payload'].get('record_type') == 'truth_frozen'
                                for event in snapshot['events']),
            'max_concurrent_calls': limit,
            # Concurrent calls share local resources: their timings are not
            # comparable with an uncontended run.
            'timing_contended': limit > 1,
            'active_trial_id': active[0]['trial_id'] if active else None,
            'selected_tasks': [{'trial_id': trial['trial_id'], 'stage_key': stage}
                               for trial in reports for stage in trial['ready_stages']],
            'pending_advances': [{'trial_id': trial['trial_id'], 'stage_key': stage}
                                 for trial in reports for stage in trial['advance_stages']],
            # Uncertain model calls whose child is confirmed stopped: the next
            # `advance --allow-model-execution` reconciles and retries them itself.
            'pending_auto_recovery': [{'trial_id': trial['trial_id'], 'stage_key': stage}
                                      for trial in reports for stage in trial['auto_recovery']],
            'trials': reports,
            'coverage': frozen['coverage']['rows'],
            'execution_prerequisites': ([] if (HERE / 'benchmark_models.py').is_file()
                                        else ['model_adapter_unavailable']),
            # Status and dry runs launch no subprocess, so the SDK check runs only
            # in an executing advance (which reports its own complete preflight).
            'route_preflight': preflight if preflight is not None else route_preflight(frozen, False)}


def _route_prerequisite(provider, env):
    """The adapter's own SDK/Python check, in the environment the model child gets."""
    code = ('import sys\nsys.path.insert(0, sys.argv[1])\n'
            'from langchain_adapter import PrerequisiteMissing, check_prerequisites\n'
            'try:\n    check_prerequisites(sys.argv[2])\nexcept PrerequisiteMissing:\n    sys.exit(3)\n')
    try:
        result = subprocess.run([sys.executable, '-B', '-c', code, str(FRAMEWORK), provider],
                                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, env=env, timeout=60, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


def route_preflight(frozen, check_sdk):
    """Per team, whether every configured route can run here; never a model call.

    Checks the presence of each role's credential variable (only presence: a
    value is never read or logged) and, given `check_sdk`, the model adapter's
    SDK/Python prerequisite in the model child's environment (a subprocess).
    """
    adapter = (HERE / 'benchmark_models.py').is_file()
    available, report = {}, {}
    for team in frozen['experiment']['teams']:
        routes = sorted(team['roles'].items())
        if 'evidence_checker' in team:
            routes.append(('evidence_checker', team['evidence_checker']))
        problem = None
        for role, model in routes:
            sdk = model['adapter'] == 'langchain'
            if sdk and check_sdk and model['provider'] not in available:
                available[model['provider']] = adapter and _route_prerequisite(
                    model['provider'], _environment(dict(model, credential_env=None)))
            if not adapter or (sdk and check_sdk and not available[model['provider']]):
                problem = {'status': 'blocked', 'reason': 'prerequisite_missing', 'role': role}
            elif model['credential_env'] is not None and model['credential_env'] not in os.environ:
                problem = {'status': 'blocked', 'reason': 'credential_unavailable', 'role': role,
                           'credential_env': model['credential_env']}
            if problem is not None:
                break
        report[team['team_id']] = dict(problem or {'status': 'ok'},
                                       sdk_prerequisite='checked' if check_sdk else 'checked_on_execution')
    return report


def status(state_root, experiment_id):
    return _status(BenchmarkStore(state_root), experiment_id)


@contextlib.contextmanager
def _execution_lock(store):
    """OS-held lock, released after a crash; never a persistent busy marker."""
    path = store.root / 'runner.lock'
    if path.exists():
        confined_file(store.root, 'runner.lock')
    with path.open('a+b') as stream:
        stream.seek(0, os.SEEK_END)
        if stream.tell() == 0:
            stream.write(b'0')
            stream.flush()
        stream.seek(0)
        try:
            if os.name == 'nt':
                import msvcrt
                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            _fail('execution_busy', 'experiment')
        try:
            yield
        finally:
            stream.seek(0)
            if os.name == 'nt':
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)


def _environment(model):
    # Deliberately omit proxy, tracing, PYTHONPATH and ambient provider secrets.
    allowed = ('SYSTEMROOT', 'WINDIR', 'COMSPEC', 'TEMP', 'TMP', 'PATH',
               'LANG', 'LC_ALL', 'SSL_CERT_FILE', 'SSL_CERT_DIR',
               'HOME', 'USERPROFILE', 'HOMEDRIVE', 'HOMEPATH')
    env = {key: os.environ[key] for key in allowed if key in os.environ}
    credential = model['credential_env']
    if credential is not None and credential in os.environ:
        env[credential] = os.environ[credential]
    env['PYTHONDONTWRITEBYTECODE'] = '1'
    env['PYTHONNOUSERSITE'] = '1'
    return env


# Every call's adapter fingerprint covers exactly these sources' bytes.
FINGERPRINTED_SOURCES = ('benchmark_models.py', 'benchmark_runner.py', 'benchmark_decisions.py',
                         'benchmark_contracts.py', 'benchmark_store.py', 'bot.py', 'workflows.py',
                         'langchain_adapter.py', 'envision_protocol.py', 'benchmark_typesafe.py')
# The one declared list of data files the copied modules open beside their
# sources: init/status data, plus the ledger role prompts every `bot.py run`
# reads. Tests audit init/status opens and run a real dispatch from a snapshot.
SOURCE_DATA = ('benchmarks/attack-v20-techniques.json', 'benchmarks/coverage.json',
               'benchmarks/team-workflow.json', 'benchmarks/prompt-contract.txt', 'hermes-bots/catalog.json',
               'roles/builder.txt', 'roles/coordinator.txt', 'roles/researcher.txt', 'roles/reviewer.txt')


def source_files():
    """The fingerprinted sources, the CLI and every framework module they import.

    Static imports anywhere in a module (including function-level ones) are
    followed transitively; campaign recipe drivers, loaded by name, are added
    explicitly. A framework package import is refused rather than half-copied.
    """
    import ast
    pending, found = list(FINGERPRINTED_SOURCES) + ['benchmark.py'], set()
    while pending:
        name = pending.pop()
        if name in found:
            continue
        found.add(name)
        tree = ast.parse(confined_file(source_root(name), name).read_bytes(), filename=name)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                modules = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                modules = [node.module]
            else:
                continue
            for module in modules:
                top = module.split('.')[0]
                if any((root / top / '__init__.py').is_file() for root in (HERE, FRAMEWORK)):
                    _fail('unsupported_source_package', 'source')
                if (source_root(top + '.py') / (top + '.py')).is_file():
                    pending.append(top + '.py')
        if name == 'benchmark_campaigns.py':
            from benchmark_campaigns import RECIPES
            pending.extend('benchmark_{}.py'.format(kind) for kind in set(RECIPES.values()))
    return sorted(found)


def snapshot_source(output):
    """Copy the exact benchmark sources into a NEW directory outside this tree.

    Long runs started from the copy are immune to concurrent source edits, so
    every call keeps one adapter fingerprint. The copy puts the benchmark and
    the framework files it uses in one folder (`NEW_DIR/framework/...`), so the
    snapshot directory itself is the source tree that state roots must stay
    outside of. Writes `NEW_DIR/SOURCE-MANIFEST.json` with each file's digest;
    never overwrites, never runs anything.
    """
    destination = Path(os.path.abspath(os.fspath(output)))
    if any(destination == root or root in destination.parents for root in (HERE, FRAMEWORK)):
        _fail('unsafe_path', 'output')
    files = [(name, confined_file(source_root(name), name).read_bytes())
             for name in source_files() + list(SOURCE_DATA)]
    try:
        destination.mkdir()
    except FileExistsError:
        _fail('destination_exists', 'output')
    except OSError:
        _fail('unsafe_path', 'output')
    framework = destination / 'framework'
    try:
        for name, data in files:
            target = framework / name
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open('xb') as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
        manifest = {'schema_version': 1, 'root': 'framework',
                    'fingerprinted_sources': list(FINGERPRINTED_SOURCES),
                    'files': [{'path': name, 'sha256': digest_bytes(data), 'byte_count': len(data)}
                              for name, data in files]}
        data = canonical_bytes(manifest)
        with (destination / 'SOURCE-MANIFEST.json').open('xb') as stream:
            stream.write(data + b'\n')
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        shutil.rmtree(str(destination), ignore_errors=True)
        raise
    return {'output': str(destination), 'framework': str(framework), 'files': len(files),
            'manifest_sha256': digest_bytes(data)}


def _source_identity():
    if not (HERE / 'benchmark_models.py').is_file():
        _fail('model_adapter_unavailable', 'adapter')
    # The generic executable is this module's child entry point: it runs the
    # model child, then registers the checker appendix before bot.py submits.
    child = HERE / 'benchmark_runner.py'
    sources = {name: digest_bytes(confined_file(source_root(name), name).read_bytes())
               for name in FINGERPRINTED_SOURCES}
    # Versions as the model child sees them: its environment drops PYTHONPATH
    # and the user site, so a package visible only there is absent for it too.
    import site
    dropped = [p for p in os.environ.get('PYTHONPATH', '').split(os.pathsep) if p]
    dropped.append(site.getusersitepackages())
    excluded = {os.path.normcase(os.path.abspath(p)) for p in dropped}
    paths = [p for p in sys.path if p and os.path.normcase(os.path.abspath(p)) not in excluded]
    packages = {}
    for name in ('langchain', 'langchain-core', 'langchain-openai', 'langchain-anthropic',
                 'openai', 'anthropic', 'httpx'):
        found = next(iter(importlib.metadata.distributions(name=name, path=paths)), None)
        packages[name] = found.version if found is not None else None
    executable = Path(sys.executable).resolve()
    return {'adapter_sha256': digest_bytes(canonical_bytes({'sources': sources, 'packages': packages})),
            'executable_sha256': digest_bytes(executable.read_bytes()),
            'executable_version': 'Python ' + sys.version.split()[0] + '; packages='
                                  + canonical_bytes(packages).decode('utf-8')}, child, executable


PUBLIC_PROVENANCE = ('synthetic', 'public_replay')


def release_required(scenario, model):
    """Private evidence needs a recorded release before reaching a non-local route."""
    return scenario['provenance'] not in PUBLIC_PROVENANCE and route_is_paid(model)


def _authorize(store, frozen, trial, model, preceding_seconds=0):
    # An execution flag is operator authority, not a fabricated human review or
    # declassification. Private (lab-derived) evidence needs an existing release
    # before it may leave this machine; local loopback routes and public or
    # synthetic evidence need none.
    model_sha = digest_bytes(canonical_bytes(model))
    if release_required(_case(frozen, trial)['scenario'], model):
        authorizations = store.trial_authorizations(trial['trial_id'])
        with store.connection() as db:
            authorized = False
            for item in authorizations:
                if (item['kind'] == 'authorization' and item['trial_id'] == trial['trial_id']
                        and item['by'] != 'operator-cli' and model_sha in item['model_sha256s']
                        and item['evidence_sha256'] == trial['case_evidence_sha256']):
                    try:
                        store._authorization(db, item['authorization_sha256'])
                        authorized = True
                    except BenchmarkError:
                        pass
            if not authorized:
                _fail('release_required', 'authorization')
    now = dt.datetime.now(dt.timezone.utc)
    return store.record_authorization({
        'approval_id': uuid.uuid4().hex, 'experiment_id': trial['experiment_id'],
        'trial_id': trial['trial_id'], 'campaign_id': None, 'by': 'operator-cli',
        'note': 'Explicit --allow-model-execution for this frozen model and public evidence.',
        'created_utc': now.isoformat(timespec='microseconds'),
        'expires_utc': (now + dt.timedelta(seconds=preceding_seconds + model['timeout_seconds'] + 120)).isoformat(timespec='microseconds'),
        'evidence_sha256': trial['case_evidence_sha256'], 'model_sha256s': [model_sha],
        'manifest_sha256': None, 'phases': [],
    })


def _bot_command(ledger, args, env, timeout):
    """Fixed ledger command: 'ok', 'failed', or 'timeout' (outcome uncertain)."""
    try:
        result = subprocess.run([sys.executable, '-B', str(FRAMEWORK / 'bot.py'), '--workspace',
                                 str(ledger)] + args, stdin=subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                env=env, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        return 'timeout'
    except OSError:
        return 'failed'
    return 'ok' if result.returncode == 0 else 'failed'


def _set_trial_status(store, trial_id, status):
    current = store.get_trial(trial_id)
    if current['status'] != status:
        store.update_trial(trial_id, dict(current, status=status), status)


def _wave(frozen, trial, report, tried):
    """Ready stages, in stable topological order, whose combined worst case fits.

    Every ready stage's predecessors are already advanced, so they are mutually
    independent branches. A stage that does not fit waits for the next wave,
    where its own exhaustion check terminates the trial if it can never run.
    """
    team, experiment, budgets = _team(frozen, trial), frozen['experiment'], report['budgets']
    calls, seconds = budgets['calls_remaining'], budgets['active_seconds_remaining']
    cost = (None if budgets['api_cost_usd_remaining'] is None
            else Decimal(str(budgets['api_cost_usd_remaining'])))
    stages = {stage['stage_key']: stage for stage in report['stages']}
    wave = []
    for key in report['ready_stages']:
        item = {'trial_id': trial['trial_id'], 'stage_key': key,
                'attempt_index': stages[key]['next_attempt_index'],
                'ledger_status': stages[key]['ledger_status']}
        if (item['trial_id'], key, item['attempt_index']) in tried:
            # One dispatch per attempt per invocation, even if it failed before
            # reserving; never a silent loop of retries.
            continue
        models = _models(team, key)
        need_seconds = sum(model['timeout_seconds'] for model in models)
        need_cost = sum((Decimal(str(bound)) for bound in _cost_bounds(experiment, models)), Decimal(0))
        paid = any(route_is_paid(model) for model in models)
        if len(models) > calls or need_seconds > seconds or (paid and (cost is None or need_cost > cost)):
            break
        calls, seconds = calls - len(models), seconds - need_seconds
        if paid:
            cost -= need_cost
        wave.append(item)
    return wave


def _prepare_trial(store, frozen, trial_id, retry_call, run, tried):
    """Recover, advance, terminate a trial that cannot finish, or freeze its next wave.

    Called only while this invocation has no call of the trial in flight, so its
    inspection never races the trial's own dispatches. A model call that failed
    for a model-attributable or transient reason, or whose uncertain outcome is
    resolved once the ledger shows its child stopped, is retried as a new
    attempt; a configuration failure terminates the trial; an uncertain call
    whose child may still run blocks it.
    """
    attempted, recovered = set(), set()
    while True:
        trial = store.get_trial(trial_id)
        if trial['status'] == 'terminated':
            return []
        try:
            report = _trial_status(store, frozen, trial, retry_call)
        except BenchmarkError:
            return []  # status reports the trial as blocked with its error
        if report['status'] == 'completed':
            _set_trial_status(store, trial_id, 'completed')
            return []
        if report['unrecoverable']:
            # Retrying cannot fix an operator configuration failure.
            first = report['unrecoverable'][0]
            store.terminate_trial(trial_id, 'unrecoverable_stage', 'benchmark-runner',
                                  'Stage {} failed with configuration reason {}; a retry cannot help.'.format(
                                      first['stage_key'], first['failure_reason']))
            run['terminated'].append(trial_id)
            return []
        stages = {stage['stage_key']: stage for stage in report['stages']}
        recover = [stage for stage in report['auto_recovery'] if stage not in recovered]
        if recover:
            for stage in recover:
                recovered.add(stage)
                call_id = stages[stage]['uncertain_call_id'] or stages[stage]['failed_call_id']
                try:
                    payload = auto_recover(store, trial, stage)
                except BenchmarkError as exc:
                    run['failures'].append({'trial_id': trial_id, 'stage_key': stage, 'state': 'unknown',
                                            'call_id': call_id, 'error': {'code': exc.code, 'field': exc.field}})
                    return []
                if payload is None:
                    continue
                # Handled without a human: no longer an outstanding failure.
                run['failures'][:] = [item for item in run['failures'] if item['call_id'] != call_id]
                if payload['policy'] == 'automatic_retry':
                    run['auto_retried'].append({
                        'trial_id': trial_id, 'stage_key': stage, 'call_id': call_id,
                        'policy': payload['policy'], 'component': payload['component'],
                        'failed_attempt_index': payload['failed_attempt_index'],
                        'failure_reason': payload['failure_reason']})
                else:
                    run['auto_reconciled'].append({
                        'trial_id': trial_id, 'stage_key': stage, 'call_id': call_id,
                        'policy': payload['policy'], 'prior_failure_reason': payload['prior_failure_reason'],
                        'observed_elapsed_ms': payload['observed_elapsed_ms'],
                        'timeout_seconds': payload['timeout_seconds'],
                        'charged_seconds': payload['charged_seconds'],
                        'charged_api_cost_usd': payload['charged_api_cost_usd']})
            _set_trial_status(store, trial_id, 'ready')
            continue
        for stage in report['stages']:
            if stage['blocker'] == 'process_stop_unconfirmed':
                # Never reconciled automatically: the child may still be running.
                run['failures'][:] = [item for item in run['failures']
                                      if item['call_id'] != stage['uncertain_call_id']] + [{
                    'trial_id': trial_id, 'stage_key': stage['stage_key'], 'state': 'unknown',
                    'call_id': stage['uncertain_call_id'],
                    'error': {'code': 'process_stop_unconfirmed', 'field': 'process'}}]
        pending = [stage for stage in report['advance_stages'] if stage not in attempted]
        if pending:
            for stage in pending:
                attempted.add(stage)
                try:
                    auto_advance(store, trial, stage)
                except BenchmarkError as exc:
                    run['failures'].append({'trial_id': trial_id, 'stage_key': stage, 'state': 'failed',
                                            'call_id': None, 'error': {'code': exc.code, 'field': exc.field}})
                    return []
                run['advanced'].append({'trial_id': trial_id, 'stage_key': stage})
            continue
        if report['advance_stages']:
            return []  # an advance that did not take effect; never loop on it
        if report['budget_exhausted'] and report['status'] != 'unknown':
            # Uncertain trials are left for reconciliation, which may change charges.
            first = report['budget_exhausted'][0]
            store.terminate_trial(trial_id, 'budget_exhausted', 'benchmark-runner',
                                  'Stage {} cannot dispatch: {} budget exhausted.'.format(
                                      first['stage_key'], first['budget']))
            run['terminated'].append(trial_id)
            return []
        if report['status'] != 'ready':
            return []
        wave = _wave(frozen, trial, report, tried)
        tried.update((item['trial_id'], item['stage_key'], item['attempt_index']) for item in wave)
        return wave


def _run(store, experiment_id, retry_call, preflight):
    """Schedule every trial to completion, termination or a blocking outcome.

    Up to `max_concurrent_calls` model calls are in flight across trials and
    the independent branches of one trial; a trial's next wave is computed only
    after its current wave settles, so dependent stages never overlap. A failed
    or unknown dispatch stops its own trial's remaining wave; others continue.
    A team whose routes failed the preflight never dispatches: its unfinished
    trials end `unrecoverable_stage`.
    """
    frozen = store.get_experiment(experiment_id)
    _workflow(frozen['workflow'])
    limit = max_concurrent_calls(frozen['experiment'])
    trials = _schedule(frozen, store.trials(experiment_id))
    order = [trial['trial_id'] for trial in trials]
    locks = {trial_id: threading.Lock() for trial_id in order}
    run = {'dispatched': [], 'advanced': [], 'auto_reconciled': [], 'auto_retried': [], 'terminated': [],
           'failures': []}
    tried, queue, running = set(), collections.deque(), {}
    outstanding = collections.Counter()
    identity, stale = None, list(order)
    for trial in trials:
        problem = preflight[trial['team_id']]
        if problem['status'] == 'ok' or trial['status'] in ('completed', 'terminated'):
            continue
        store.terminate_trial(trial['trial_id'], 'unrecoverable_stage', 'benchmark-runner',
                              'Route preflight: {} for {}; no call was dispatched.'.format(
                                  problem['reason'], problem['role']))
        run['terminated'].append(trial['trial_id'])
        run['failures'].append({'trial_id': trial['trial_id'], 'stage_key': None, 'state': 'failed',
                                'call_id': None, 'error': {'code': problem['reason'],
                                                           'field': 'route.' + problem['role']}})
        stale.remove(trial['trial_id'])
    with concurrent.futures.ThreadPoolExecutor(max_workers=limit) as pool:
        while True:
            for trial_id in stale:
                for item in _prepare_trial(store, frozen, trial_id, retry_call, run, tried):
                    queue.append(item)
                    outstanding[trial_id] += 1
            stale = []
            while queue and len(running) < limit:
                if identity is None:
                    identity = _source_identity()
                item = queue.popleft()
                future = pool.submit(_dispatch, store, experiment_id, item, identity, locks[item['trial_id']])
                running[future] = item
            if not running:
                return run
            done, _ = concurrent.futures.wait(running, return_when=concurrent.futures.FIRST_COMPLETED)
            for future in done:
                item = running.pop(future)
                result = future.result()
                trial_id = item['trial_id']
                if result['call_id'] is not None:
                    run['dispatched'].append(result['call_id'])
                if result['state'] != 'dispatched':
                    run['failures'].append({'trial_id': trial_id, 'stage_key': item['stage_key'],
                                            'state': result['state'], 'call_id': result['call_id'],
                                            'error': result['error']})
                    for queued in [queued for queued in queue if queued['trial_id'] == trial_id]:
                        queue.remove(queued)
                        outstanding[trial_id] -= 1
                        # Never dispatched: leave it eligible for the trial's next wave.
                        tried.discard((queued['trial_id'], queued['stage_key'], queued['attempt_index']))
                outstanding[trial_id] -= 1
                if outstanding[trial_id] == 0:
                    stale.append(trial_id)
            stale.sort(key=order.index)


def advance(state_root, experiment_id, allow_model_execution=False, retry_call=None):
    """Run every trial until finished, budget-terminated or blocked; fully automatic.

    Each validated stage output, including the final handoff, advances
    automatically and unreviewed. A dry run never advances or dispatches.
    """
    store = BenchmarkStore(state_root)
    report = _status(store, experiment_id, retry_call)
    if retry_call is not None:
        matches = [call for call in store.calls(experiment_id=experiment_id) if call['call_id'] == retry_call]
        if len(matches) != 1:
            _fail('scope_mismatch', 'retry_call')
        trial = store.get_trial(matches[0]['spec']['trial_id'])
        if trial['status'] == 'terminated' or not retry_eligible(store, trial, retry_call):
            _fail('reconciliation_required', 'retry_call')
    if not allow_model_execution:
        return dict(report, dry_run=True, dispatched=False)
    if not report['truth_frozen']:
        # Answer keys are fixed before any team output can exist.
        _fail('truth_not_frozen', 'truth')
    with _execution_lock(store):
        # The complete route preflight (including the SDK check) precedes any dispatch.
        preflight = route_preflight(store.get_experiment(experiment_id), True)
        run = _run(store, experiment_id, retry_call, preflight)
    states = {failure['state'] for failure in run['failures']}
    result = dict(_status(store, experiment_id, preflight=preflight), dry_run=False,
                  dispatched=bool(run['dispatched']),
                  dispatched_calls=run['dispatched'], auto_advanced=run['advanced'],
                  auto_reconciled=run['auto_reconciled'], auto_retried=run['auto_retried'],
                  terminated_trials=run['terminated'], failures=run['failures'],
                  outcome='unknown' if 'unknown' in states else 'failed' if states else 'ok')
    if run['failures']:
        result['error'] = run['failures'][0]['error']
    return result


def _dispatch(store, experiment_id, item, identity, lock):
    """One stage dispatch, prepared and verified under its trial's lock.

    The model call itself runs unlocked so independent branches proceed
    concurrently; the child reserves it durably before any transport.
    """
    source, child, executable = identity
    stage = item['stage_key']
    with lock:
        trial = store.get_trial(item['trial_id'])
        frozen = store.get_experiment(experiment_id)
        team = _team(frozen, trial)
        model = team['roles'][STAGE_ROLES[stage]]
        checker = team.get('evidence_checker') if stage == 'analysis' else None
        try:
            prompt = build_prompt(store, trial, stage)
            authorization = _authorize(store, frozen, trial, model)
            if checker is not None:
                _authorize(store, frozen, trial, checker, preceding_seconds=model['timeout_seconds'])
            prompt_ref = store.write_artifact(trial['trial_id'], 'prompts', prompt)
            spec = dict(source, schema_version=1, trial_id=trial['trial_id'], stage_key=stage,
                        attempt_index=item['attempt_index'], component='narrative',
                        prompt_artifact=prompt_ref, input_sha256=digest_bytes(prompt),
                        workflow_sha256=frozen['experiment']['workflow_sha256'],
                        prompt_contract_sha256=frozen['experiment']['prompt_contract_sha256'],
                        evidence_sha256=trial['case_evidence_sha256'], authorization_sha256=authorization,
                        model=model, role=STAGE_ROLES[stage])
            spec_ref = store.write_artifact(trial['trial_id'], 'specs', canonical_bytes(spec))
        except BenchmarkError as exc:
            return {'state': 'failed', 'call_id': None, 'error': {'code': exc.code, 'field': exc.field}}
        call_id = uuid.uuid4().hex
        spec_path = store.root / 'trials' / trial['trial_id'] / spec_ref['path']
        ledger = store.root / 'trials' / trial['trial_id'] / 'ledger'
        env = _environment(model)
        task_id = str(trial['task_mapping'][stage])
        if item['ledger_status'] == 'pending':
            if _bot_command(ledger, ['start', task_id], env, 30) != 'ok':
                return {'state': 'failed', 'call_id': None,
                        'error': {'code': 'ledger_start_failed', 'field': 'task'}}
        timeout = math.ceil(model['timeout_seconds']) + 30
        if checker is not None:
            timeout += math.ceil(checker['timeout_seconds'])
            if checker['credential_env'] and checker['credential_env'] in os.environ:
                env[checker['credential_env']] = os.environ[checker['credential_env']]
    outcome = _bot_command(ledger, ['run', '--adapter', 'generic', '--timeout', str(timeout), task_id,
                                    '--', str(executable), '-B', str(child), '--state-root', str(store.root),
                                    '--call-id', call_id, '--call-spec', str(spec_path)], env, timeout + 30)
    with lock:
        try:
            # Successful process exit is not evidence of a stored model call.
            calls = store.calls(trial_id=trial['trial_id'])
            call = next((item for item in calls if item['call_id'] == call_id), None)
            if call is None or call['status'] != 'completed' or outcome != 'ok':
                _fail('execution_receipt_unverified', 'call')
            if call['spec'] != spec or call['fingerprint'] != digest_bytes(canonical_bytes(spec)):
                _fail('fingerprint_conflict', 'call')
            if checker is None and any(item['spec']['stage_key'] == stage
                                       and item['spec']['component'] == 'evidence_checker' for item in calls):
                _fail('unexpected_checker_call', 'checker')
            # Verifies the receipt, the exact submitted bytes and, for a configured
            # checker, the appendix the child registered before the ledger submit.
            handoff = stage_handoff(store, trial, stage)
            if handoff['call']['call_id'] != call_id:
                _fail('handoff_mismatch', 'call')
            record_submission(store, trial, stage, handoff)
            _set_trial_status(store, trial['trial_id'], 'ready')
        except BenchmarkError as exc:
            current = next((item for item in store.calls(trial_id=trial['trial_id'])
                            if item['call_id'] == call_id), None)
            if current is None:
                # The child reserves before any transport; no row means no model call,
                # unless the ledger run timed out and its child may still be running.
                state = 'unknown' if outcome == 'timeout' else 'failed'
            else:
                state = 'unknown' if current['status'] in ('reserved', 'unknown', 'completed') else 'failed'
            _set_trial_status(store, trial['trial_id'], state)
            return {'state': state, 'call_id': call_id if current is not None else None,
                    'error': {'code': exc.code, 'field': exc.field}}
    return {'state': 'dispatched', 'call_id': call_id}


def child_main(argv=None):
    """Generic ledger executable: the model child, then checker registration.

    bot.py submits as soon as this process exits 0, so the evidence-checker
    appendix is registered here, after the durable receipts and before exit.
    A registration failure exits nonzero; the completed receipt is recovered by
    explicit reconciliation, never a fresh model call.
    """
    import benchmark_models
    argv = sys.argv[1:] if argv is None else list(argv)
    code = benchmark_models.main(argv)
    if code != 0:
        return code
    parser = argparse.ArgumentParser(add_help=False)
    for name in ('--state-root', '--call-id', '--call-spec'):
        parser.add_argument(name, required=True)
    try:
        args = parser.parse_args(argv)
        store = BenchmarkStore(args.state_root)
        call = next(item for item in store.calls() if item['call_id'] == args.call_id)
        ensure_checker_artifact(store, store.get_trial(call['spec']['trial_id']), call)
    except BaseException:
        print('Error: benchmark checker appendix registration failed; the completed receipt '
              'is retained for reconciliation; no automatic retry.', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    import benchmark_runner
    sys.exit(benchmark_runner.child_main())

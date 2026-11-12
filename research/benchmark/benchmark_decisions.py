"""Ledger linkage, unreviewed automatic advances and evidence-backed recovery.

Never model dispatch. The ledger remains authoritative for transitions. A stage
output flows forward only after the runner verifies the current receipt-bound
submission and records an unreviewed automatic advance: a distinct ledger
`auto_advance` transition plus a store `stage_auto_advanced` event, never a human
approval. Reconciliation may submit an existing immutable response, but cannot
execute a replacement call. An uncertain model call whose local child the ledger
shows stopped is resolved automatically as failed (`automatic_model_call`), with
its output discarded and worst-case charges kept; a known model-attributable
failure is retried as a new attempt (`automatic_retry`), its receipt kept.
Neither is ever a human action.
"""
from contextlib import contextmanager
import datetime as dt
import os
from pathlib import Path
import sqlite3
import subprocess
import sys

from benchmark_paths import FRAMEWORK
from benchmark_contracts import (
    AUTO_ADVANCE_ACTOR, AUTO_ADVANCE_NOTE, BenchmarkError, MAX_BYTES, REVIEW_POLICY, STAGE_KEYS,
    canonical_bytes, confined_file, decode_json, digest_bytes, parse_utc, validate_stage_output,
)
from benchmark_store import (AUTO_RECONCILE_ACTOR, AUTO_RECONCILE_POLICY, AUTO_RETRY_ACTOR, AUTO_RETRY_POLICY,
                             CONFIGURATION_FAILURES, HUMAN_RECONCILE_POLICY, RETRYABLE_FAILURES,
                             BenchmarkStore, _unpack, automatic_retry, human_actor)


WORKFLOW_TITLE = 'Framework-managed threat-hunt benchmark'
WORKFLOW_SCOPE = 'Use only the frozen public evidence supplied by this benchmark.'
WORKFLOW_ACCEPTANCE = 'Produce the structured stage output; it advances automatically once it validates.'
BOT = FRAMEWORK / 'bot.py'
CHECKER_DESCRIPTION = 'Benchmark evidence checker'
RECONCILED_DESCRIPTION = 'Benchmark reconciled response'
AUTO_RESUME_NOTE = 'Automatic resume after automatic reconciliation of an unknown model call (automatic_model_call).'
AUTO_RETRY_RESUME_NOTE = 'Automatic resume for a new attempt after a known model call failure (automatic_retry).'
# Human ledger approve/reject stay state events so that a manual transition on a
# benchmark ledger is detected as unsupported rather than silently accepted.
_STATE_EVENTS = frozenset(('start', 'run-started', 'run-failed', 'recover-run', 'resume', 'block',
                           'submit', 'approve', 'reject', 'auto_advance', 'auto_resume'))


def _fail(code, field):
    raise BenchmarkError(code, field) from None


def _text(value, field):
    if type(value) is not str or not value.strip() or '\x00' in value:
        _fail('invalid_text', field)
    try:
        value.encode('utf-8')
    except UnicodeError:
        _fail('invalid_text', field)
    return value


def _stage(stage):
    if type(stage) is not str or stage not in STAGE_KEYS:
        _fail('invalid_choice', 'stage_key')


def _trial(store, experiment_id, trial_id):
    trial = store.get_trial(trial_id)
    if trial['experiment_id'] != experiment_id:
        _fail('scope_mismatch', 'trial.experiment_id')
    return trial


def _scope(frozen, trial):
    """The trial's frozen team and public evidence."""
    if frozen['experiment']['experiment_id'] != trial['experiment_id']:
        _fail('scope_mismatch', 'trial.experiment_id')
    team = next((t for t in frozen['experiment']['teams']
                 if t['team_id'] == trial['team_id']), None)
    case = next((c for c in frozen['cases']
                 if c['evidence']['case_id'] == trial['case_id']), None)
    if team is None or case is None:
        _fail('scope_mismatch', 'trial')
    return team, case['evidence']


@contextmanager
def _ledger(store, trial):
    relative = 'trials/{}/ledger/workflow.sqlite3'.format(trial['trial_id'])
    path = confined_file(store.root, relative)
    db = None
    try:
        db = sqlite3.connect(path.as_uri() + '?mode=ro', uri=True, timeout=30)
        db.row_factory = sqlite3.Row
        db.execute('BEGIN')
        yield db
    except sqlite3.Error:
        _fail('ledger_unavailable', 'ledger')
    finally:
        if db is not None:
            db.close()


def ledger_snapshot(store, trial, frozen=None):
    """Read one ledger snapshot and verify the complete frozen workflow identity.

    `frozen` is the trial's already verified frozen experiment, when the caller has it.
    """
    if frozen is None:
        frozen = store.get_experiment(trial['experiment_id'])
    _scope(frozen, trial)
    with _ledger(store, trial) as db:
        workflow = db.execute('SELECT * FROM workflow_runs WHERE id=?',
                              (trial['workflow_id'],)).fetchone()
        if workflow is None or workflow['template'] != frozen['workflow']['name'] or workflow['title'] != WORKFLOW_TITLE:
            _fail('ledger_scope_mismatch', 'ledger.workflow')
        mapping = {row['task_key']: row['task_id'] for row in db.execute(
            'SELECT task_key,task_id FROM workflow_tasks WHERE workflow_id=?', (trial['workflow_id'],))}
        if mapping != trial['task_mapping']:
            _fail('ledger_scope_mismatch', 'ledger.task_mapping')
        tasks = {}
        for step in frozen['workflow']['tasks']:
            key = step['key']
            row = db.execute('SELECT * FROM tasks WHERE id=?', (mapping[key],)).fetchone()
            if row is None:
                _fail('ledger_scope_mismatch', 'ledger.task')
            task = dict(row)
            expected = {'title': step['title'], 'role': step['role'],
                        'scope': 'Workflow title:\n{}\n\nOperator scope:\n{}\n\nStep scope:\n{}'.format(
                            WORKFLOW_TITLE, WORKFLOW_SCOPE, step['scope']),
                        'acceptance': 'Operator acceptance:\n{}\n\nStep acceptance:\n{}'.format(
                            WORKFLOW_ACCEPTANCE, step['acceptance'])}
            dependencies = {r[0] for r in db.execute(
                'SELECT depends_on FROM dependencies WHERE task_id=?', (mapping[key],))}
            if any(task[k] != v for k, v in expected.items()) or dependencies != {mapping[k] for k in step['depends_on']}:
                _fail('ledger_scope_mismatch', 'ledger.task')
            tasks[key] = task
        ids = set(mapping.values())
        events = [dict(r) for r in db.execute('SELECT * FROM events ORDER BY id') if r['task_id'] in ids]
        artifacts = [dict(r) for r in db.execute('SELECT * FROM artifacts ORDER BY id') if r['task_id'] in ids]
    return {'tasks': tasks, 'events': events, 'artifacts': artifacts}


def _events(store, trial):
    with store.connection() as db:
        return [_unpack(r) for r in db.execute('SELECT * FROM events WHERE trial_id=? ORDER BY seq',
                                               (trial['trial_id'],))]


def trial_view(store, trial, frozen=None):
    """One read of a trial's ledger, calls and store events, shared by every stage.

    Inspecting all stages from one view opens the ledger once per trial instead
    of once per stage and predecessor. Callers that mutate state read a fresh
    view after each transition; a view is never cached across calls.
    """
    if frozen is None:
        frozen = store.get_experiment(trial['experiment_id'])
    return {'frozen': frozen, 'ledger': ledger_snapshot(store, trial, frozen),
            'calls': store.calls(trial_id=trial['trial_id']), 'events': _events(store, trial)}


def _latest_narrative(calls, stage):
    """Latest narrative attempt, including failures; never fall back to an older one."""
    _stage(stage)
    calls = [c for c in calls if c['spec']['stage_key'] == stage and c['spec']['component'] == 'narrative']
    return max(calls, key=lambda c: c['spec']['attempt_index']) if calls else None


def _task_events(snapshot, trial, stage):
    return [e for e in snapshot['events'] if e['task_id'] == trial['task_mapping'][stage]]


def _trial_relative(trial, path):
    """Path of a ledger artifact relative to its trial directory.

    bot.py records absolute paths; anchoring on `trials/<trial_id>/` keeps a
    state directory valid after it is moved while still binding the artifact to
    this trial and file. Content digests are verified separately.
    """
    parts = Path(path).parts
    for index in range(len(parts) - 1):
        if parts[index].lower() == 'trials' and parts[index + 1] == trial['trial_id']:
            relative = parts[index + 2:]
            if relative:
                return Path(*relative).as_posix()
    raise ValueError('artifact outside its trial directory')


def _read_ledger_artifact(store, trial, path, limit):
    try:
        # Never resolve the artifact itself, so a symlink/alias still fails
        # confinement instead of being followed.
        base = (store.root / 'trials' / trial['trial_id']).resolve()
        target = confined_file(base, _trial_relative(trial, path))
        with target.open('rb') as stream:
            content = stream.read(limit + 1)
    except (ValueError, OSError):
        _fail('invalid_handoff', 'ledger.artifact')
    if len(content) > limit:
        _fail('budget_exceeded', 'ledger.artifact')
    return content


def _validated_response(store, trial, call):
    if call is None or call['status'] != 'completed' or call['receipt'] is None:
        _fail('incomplete_receipt', 'call.status')
    with store.connection() as db:
        _, frozen, team = store._call_spec(db, call['spec'], call['fingerprint'])
        store._receipt(call, call['receipt'], frozen, team)
    return store.read_artifact(trial['trial_id'], call['receipt']['response_artifact'])


def checker_validator_output(output, evidence, output_sha256):
    """Expected no-dispatch appendix for a candidate with no checkable citations."""
    known = {e['event_id'] for e in evidence['events']}
    results = []
    for claim in output['claims']:
        if claim['event_ids'] and all(e in known for e in claim['event_ids']):
            return None
        results.append({'claim_id': claim['claim_id'], 'choice': 'insufficient',
                        'reason': 'invalid_or_missing_citation', 'origin': 'validator'})
    return {'schema_version': 1, 'stage_key': 'analysis', 'narrative_sha256': output_sha256,
            'origin': 'validator', 'results': results}


def _checker(store, trial, call, output, view, require_registered=True):
    team, evidence = _scope(view['frozen'], trial)
    if call['spec']['stage_key'] != 'analysis' or 'evidence_checker' not in team:
        return None, None, None
    matching = [c for c in view['calls']
                if c['spec']['stage_key'] == 'analysis' and c['spec']['component'] == 'evidence_checker'
                and c['spec']['attempt_index'] == call['spec']['attempt_index']]
    expected_validator = checker_validator_output(output, evidence, call['receipt']['response_sha256'])
    checker = matching[0] if len(matching) == 1 else None
    if matching:
        if len(matching) != 1:
            _fail('checker_incomplete', 'call.evidence_checker')
        raw = _validated_response(store, trial, checker)
        ref = checker['receipt']['response_artifact']
        checked = decode_json(raw)
        if (type(checked) is not dict or type(checked.get('schema_version')) is not int
                or checked['schema_version'] != 1 or checked.get('stage_key') != 'analysis'):
            _fail('invalid_checker', 'checker.schema_version')
        if checked.get('narrative_sha256') != call['receipt']['response_sha256']:
            _fail('digest_mismatch', 'checker.narrative_sha256')
        results = checked.get('results')
        if type(results) is not list or any(type(result) is not dict
                                           or type(result.get('claim_id')) is not str for result in results):
            _fail('invalid_checker', 'checker.results')
        result_ids = [result['claim_id'] for result in results]
        if (len(result_ids) != len(set(result_ids))
                or set(result_ids) != {claim['claim_id'] for claim in output['claims']}):
            _fail('scope_mismatch', 'checker.results')
    else:
        if expected_validator is None:
            _fail('checker_incomplete', 'call.evidence_checker')
        raw = canonical_bytes(expected_validator)
        sha = digest_bytes(raw)
        ref = {'sha256': sha, 'byte_count': len(raw), 'path': 'artifacts/checker/' + sha}
        if store.read_artifact(trial['trial_id'], ref) != raw:
            _fail('checker_incomplete', 'call.evidence_checker')
        checked = expected_validator
    path = store.root / 'trials' / trial['trial_id'] / ref['path']
    if require_registered and not _checker_registered(view['ledger'], trial, path):
        _fail('checker_incomplete', 'ledger.checker_artifact')
    return checker, ref, checked


def _path_key(trial, path):
    """Ledger artifact identity: its trial-relative path, case-normalized."""
    try:
        return os.path.normcase(_trial_relative(trial, path))
    except ValueError:
        return None


def _checker_registered(snapshot, trial, path):
    key = _path_key(trial, path)
    return key is not None and any(
        a['task_id'] == trial['task_mapping']['analysis'] and _path_key(trial, a['path']) == key
        and a['description'] == CHECKER_DESCRIPTION for a in snapshot['artifacts'])


def ensure_checker_artifact(store, trial, call):
    """Materialize a no-dispatch validator appendix if applicable and register the
    stored checker appendix with the ledger task. Never dispatches a checker call.

    The generic child calls this before it exits, so registration precedes the
    ledger's automatic submit; recovery calls it for interrupted submissions.
    """
    if call['spec']['stage_key'] != 'analysis' or call['spec']['component'] != 'narrative':
        return None
    frozen = store.get_experiment(trial['experiment_id'])
    team, evidence = _scope(frozen, trial)
    if 'evidence_checker' not in team:
        return None
    output = decode_json(_validated_response(store, trial, call))
    validate_stage_output(output, 'analysis', evidence)
    validator = checker_validator_output(output, evidence, call['receipt']['response_sha256'])
    if validator is not None:
        store.write_artifact(trial['trial_id'], 'checker', canonical_bytes(validator))
    view = trial_view(store, trial, frozen)
    _, ref, _ = _checker(store, trial, call, output, view, require_registered=False)
    path = store.root / 'trials' / trial['trial_id'] / ref['path']
    if not _checker_registered(view['ledger'], trial, path):
        _bot(store, trial, 'artifact', 'analysis',
             extra=('--path', str(path), '--description', CHECKER_DESCRIPTION))
    return ref


def record_submission(store, trial, stage, handoff):
    """Runner-style submission record, idempotent per ledger submit event.

    Written by the runner after dispatch, by submission recovery, and before
    each automatic advance, so a crash never silently drops a submission.
    """
    payload = {'stage_key': stage, 'attempt_index': handoff['call']['spec']['attempt_index'],
               'output_sha256': handoff['output_sha256'], 'output_artifact': handoff['output_artifact'],
               'ledger_submit_event_id': handoff['submit_event']['id'],
               'ledger_submit_utc': handoff['submit_event']['time'],
               'checker_artifact': handoff['checker_artifact']}
    call_id = handoff['call']['call_id']
    with store.connection(immediate=True) as db:
        events = [_unpack(r) for r in db.execute('SELECT * FROM events WHERE trial_id=? AND kind=?',
                                                (trial['trial_id'], 'stage_submitted'))]
        same = [e for e in events if e['payload'].get('stage_key') == stage
                and e['payload'].get('ledger_submit_event_id') == payload['ledger_submit_event_id']]
        if any(e['payload'] != payload or e['call_id'] != call_id for e in same):
            _fail('fingerprint_conflict', 'stage_submitted')
        if not same:
            store.event('stage_submitted', 'runner', payload, experiment_id=trial['experiment_id'],
                        trial_id=trial['trial_id'], task_id=trial['task_mapping'][stage],
                        call_id=call_id, db=db)
    return payload


def _recovery_note(call):
    return 'Benchmark recovered immutable response: {}; sha256: {}.'.format(
        call['call_id'], call['receipt']['response_sha256'])


def stage_handoff(store, trial, stage, view=None):
    """Validate current submitted bytes, receipt, checker, and submission linkage.

    `view` is a `trial_view` the caller just read; omitted, a fresh one is read.
    """
    _stage(stage)
    if view is None:
        view = trial_view(store, trial)
    events = _task_events(view['ledger'], trial, stage)
    submits = [e for e in events if e['kind'] == 'submit']
    if not submits:
        _fail('handoff_missing', 'ledger.submit')
    submitted = submits[-1]
    # No handoff from an earlier run may be reused after a new dispatch begins.
    if any(e['id'] > submitted['id'] and e['kind'] == 'run-started' for e in events):
        _fail('handoff_stale', 'ledger.submit')
    call = _latest_narrative(view['calls'], stage)
    return _receipt_handoff(store, trial, stage, view, submitted, call)


def _receipt_handoff(store, trial, stage, view, submitted, call):
    data = _validated_response(store, trial, call)
    frozen, snapshot = view['frozen'], view['ledger']
    _, evidence = _scope(frozen, trial)
    output = decode_json(data)
    validate_stage_output(output, stage, evidence)
    artifacts = [a for a in snapshot['artifacts'] if a['task_id'] == trial['task_mapping'][stage]]
    if submitted['actor'] == 'generic':
        candidates = [a for a in artifacts if a['description'] == 'CLI stdout'
                      and submitted['note'] == 'CLI exited successfully; authentic output handoff: {}; stderr: {}'.format(
                          a['path'], Path(a['path']).with_name('stderr.txt'))]
        if len(candidates) != 1:
            _fail('handoff_mismatch', 'ledger.submit')
        stdout = candidates[0]['path']
        stderr = str(Path(stdout).with_name('stderr.txt'))
        if not any(a['path'] == stderr and a['description'] == 'CLI stderr' for a in artifacts):
            _fail('handoff_mismatch', 'ledger.submit')
        actual = _read_ledger_artifact(store, trial, stdout, frozen['experiment']['budgets']['max_response_bytes'])
    elif submitted['note'] == _recovery_note(call):
        target = store.root / 'trials' / trial['trial_id'] / call['receipt']['response_artifact']['path']
        if not any(_path_key(trial, a['path']) == _path_key(trial, target) and a['description'] == RECONCILED_DESCRIPTION
                   for a in artifacts):
            _fail('handoff_mismatch', 'ledger.artifact')
        if not any(e['kind'] == 'reconciliation_recorded' and e['call_id'] == call['call_id']
                   and e['payload'].get('outcome') == 'completed' for e in view['events']):
            _fail('reconciliation_required', 'ledger.submit')
        actual = _read_ledger_artifact(store, trial, target, frozen['experiment']['budgets']['max_response_bytes'])
    else:
        _fail('handoff_mismatch', 'ledger.submit')
    if actual != data:
        _fail('digest_mismatch', 'ledger.output_sha256')
    checker, ref, checked = _checker(store, trial, call, output, view)
    return {'call': call, 'output': output, 'output_bytes': data,
            'output_artifact': call['receipt']['response_artifact'],
            'output_sha256': call['receipt']['response_sha256'], 'submit_event': submitted,
            'checker': checker, 'checker_artifact': ref, 'checker_output': checked}


def _advance_payload(handoff, stage, event):
    return {'stage_key': stage, 'attempt_index': handoff['call']['spec']['attempt_index'],
            'ledger_event_id': event['id'], 'ledger_submit_event_id': handoff['submit_event']['id'],
            'ledger_event_sha256': digest_bytes(canonical_bytes(event)),
            'output_sha256': handoff['output_sha256'], 'output_artifact': handoff['output_artifact'],
            'checker_artifact': handoff['checker_artifact'],
            'checker_receipt_sha256': (digest_bytes(canonical_bytes(handoff['checker']['receipt']))
                                       if handoff['checker'] else None),
            'review_policy': REVIEW_POLICY}


def _advance_event(snapshot, trial, stage, handoff):
    """The single ledger transition after this submit: an exact automatic advance.

    A human approve/reject on a benchmark ledger is not a benchmark transition;
    it is refused as unsupported instead of being counted as an advance.
    """
    events = [e for e in _task_events(snapshot, trial, stage) if e['id'] > handoff['submit_event']['id']
              and e['kind'] in _STATE_EVENTS]
    if (len(events) != 1 or events[0]['kind'] != 'auto_advance' or events[0]['actor'] != AUTO_ADVANCE_ACTOR
            or events[0]['note'] != AUTO_ADVANCE_NOTE or snapshot['tasks'][stage]['status'] != 'done'):
        _fail('unsupported_ledger_transition', 'ledger.auto_advance')
    return events[0]


def advanced_output(store, trial, stage, view=None):
    """The validated output that flows forward: a bound, unreviewed automatic advance.

    `view` is a `trial_view` the caller just read; omitted, a fresh one is read.
    """
    if view is None:
        view = trial_view(store, trial)
    handoff = stage_handoff(store, trial, stage, view)
    actual = _advance_event(view['ledger'], trial, stage, handoff)
    payload = _advance_payload(handoff, stage, actual)
    if not any(e['kind'] == 'stage_auto_advanced' and e['actor'] == AUTO_ADVANCE_ACTOR
               and e['call_id'] == handoff['call']['call_id'] and e['payload'] == payload
               for e in view['events']):
        _fail('auto_advance_unbound', 'stage_auto_advanced')
    return dict(handoff, auto_advance=payload)


def auto_advance(store, trial, stage):
    """Advance one validated submitted stage without review, or mirror an existing one.

    Never a human approval: a distinct ledger transition, actor, note and store
    event. A crash between the ledger and store commits is completed by mirroring
    the same ledger event; a second transition is never issued.
    """
    _stage(stage)
    handoff = stage_handoff(store, trial, stage)
    record_submission(store, trial, stage, handoff)
    if ledger_snapshot(store, trial)['tasks'][stage]['status'] == 'review':
        try:
            _bot(store, trial, 'auto-advance', stage, AUTO_ADVANCE_ACTOR, AUTO_ADVANCE_NOTE)
        except BenchmarkError as exc:
            # A timed-out CLI can already have committed. Inspect, never repeat.
            try:
                _advance_event(ledger_snapshot(store, trial), trial, stage, handoff)
            except BenchmarkError:
                raise exc from None
    actual = _advance_event(ledger_snapshot(store, trial), trial, stage, handoff)
    current = stage_handoff(store, trial, stage)
    if current['output_sha256'] != handoff['output_sha256'] or current['submit_event'] != handoff['submit_event']:
        _fail('digest_mismatch', 'auto_advance.output_sha256')
    store.record_auto_advance(trial['trial_id'], current['call']['call_id'],
                              _advance_payload(current, stage, actual))
    return advanced_output(store, trial, stage)


def inspect_stage(store, trial, stage, view=None):
    """One stage's ledger state, latest attempt, validated handoff and blocker.

    `view` is a `trial_view` the caller just read; omitted, a fresh one is read.
    """
    _stage(stage)
    if view is None:
        view = trial_view(store, trial)
    status = view['ledger']['tasks'][stage]['status']
    call = _latest_narrative(view['calls'], stage)
    state_events = [e for e in _task_events(view['ledger'], trial, stage) if e['kind'] in _STATE_EVENTS]
    result = {'status': status, 'blocker': None, 'call': call, 'handoff': None}
    try:
        if status == 'done':
            result['handoff'] = advanced_output(store, trial, stage, view)
        elif status == 'review':
            result['handoff'] = stage_handoff(store, trial, stage, view)
        elif status in ('running', 'blocked'):
            result['blocker'] = 'reconciliation_required'
        elif state_events and state_events[-1]['kind'] == 'reject':
            result['blocker'] = 'unsupported_ledger_transition'
        elif call is not None and call['status'] in ('reserved', 'unknown'):
            result['blocker'] = 'previous_dispatch_unknown'
    except BenchmarkError as exc:
        result['blocker'] = exc.code
    return result


def _bot(store, trial, command, stage, by=None, note=None, extra=()):
    """Only fixed ledger commands; no inherited credentials or executable lookup."""
    allowed = ('auto-advance', 'auto-resume', 'recover-run', 'resume', 'artifact', 'submit')
    if command not in allowed:
        _fail('invalid_choice', 'ledger.command')
    workspace = store.root / 'trials' / trial['trial_id'] / 'ledger'
    task_id = str(trial['task_mapping'][stage])
    args = [sys.executable, '-B', str(BOT), '-w', str(workspace), command]
    args.extend(['--id', task_id] if command in ('auto-advance', 'auto-resume') else [task_id])
    if by is not None:
        args.extend(['--by', by, '--note', note])
    args.extend(extra)
    environment = {k: v for k, v in os.environ.items()
                   if k.upper() in ('SYSTEMROOT', 'WINDIR', 'SYSTEMDRIVE', 'TEMP', 'TMP', 'LANG', 'LC_ALL')}
    environment['PYTHONIOENCODING'] = 'utf-8'
    try:
        result = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, cwd=str(BOT.parent), env=environment,
                                timeout=60, check=False)
    except (OSError, subprocess.TimeoutExpired):
        _fail('ledger_command_failed', 'ledger.command')
    if result.returncode:
        _fail('ledger_command_failed', 'ledger.command')


def retry_eligible(store, trial, call_id):
    trial_calls = store.calls(trial_id=trial['trial_id'])
    calls = [c for c in trial_calls if c['call_id'] == call_id]
    if len(calls) != 1 or calls[0]['status'] != 'failed':
        return False
    call = calls[0]
    latest = _latest_narrative(trial_calls, call['spec']['stage_key'])
    if latest is None or latest['spec']['attempt_index'] != call['spec']['attempt_index']:
        return False
    if ledger_snapshot(store, trial)['tasks'][call['spec']['stage_key']]['status'] != 'active':
        return False
    # Either a recorded failed resolution, or automation's own retry of a known
    # model-attributable failure, authorizes the next attempt.
    events = _events(store, trial)
    return automatic_retry(events, call_id) or any(
        e['kind'] == 'reconciliation_recorded' and e['call_id'] == call_id
        and e['payload'].get('outcome') == 'failed' and 'evidence' in e['payload'] for e in events)


def auto_reconciled(events, call_id):
    """True when this call's failed outcome was recorded by automation, not a human."""
    return any(e['kind'] == 'reconciliation_recorded' and e['call_id'] == call_id
               and e['payload'].get('policy') == AUTO_RECONCILE_POLICY for e in events)


def _process_stop(ledger, trial, stage, call):
    """The ledger's own record that the run owning `call` has ended, or None.

    bot.py writes `run-failed` only after its child process returned or was
    killed and reaped on timeout. A `running` task, a run with no such event, or
    a reservation outside that run's window is not confirmation.
    """
    if ledger['tasks'][stage]['status'] != 'blocked':
        return None
    events = [e for e in _task_events(ledger, trial, stage) if e['kind'] in _STATE_EVENTS]
    runs = [index for index, e in enumerate(events) if e['kind'] == 'run-started']
    if not runs or [e['kind'] for e in events[runs[-1] + 1:]] != ['run-failed']:
        return None
    started, ended = events[runs[-1]], events[runs[-1] + 1]
    # Ledger times are whole seconds, truncated: a reservation made by this run's
    # child lies within [run start, run end + 1 s).
    reserved = parse_utc(call['created_utc'], 'call.created_utc')
    if not (parse_utc(started['time'], 'ledger.time') <= reserved
            < parse_utc(ended['time'], 'ledger.time') + dt.timedelta(seconds=1)):
        return None
    return {'basis': 'ledger_run_failed', 'ledger_event_id': ended['id'], 'ledger_event_time': ended['time']}


def auto_recovery(view, trial, stage):
    """The automatic recovery a stage needs, from one `trial_view`, or None.

    `reconcile`: an uncertain model call whose child the ledger shows stopped.
    `retry`: the latest attempt failed for a known model-attributable or
    transient reason and the ledger shows its child stopped. `resume`: either
    of those already recorded while the task is still blocked. `terminate`: the
    latest attempt failed for a configuration reason no retry can fix.
    `process_stop_unconfirmed`: an uncertain call whose child may still run; it
    is never resolved automatically. `manual`: an uncertain call in a ledger
    state automation does not own (left for a human).
    """
    calls = [c for c in view['calls'] if c['spec']['stage_key'] == stage]
    status = view['ledger']['tasks'][stage]['status']
    uncertain = [c for c in calls if c['status'] in ('reserved', 'unknown')]
    if uncertain:
        # A reservation is refused while its stage holds an uncertain call.
        call = uncertain[0]
        if status not in ('pending', 'active', 'running', 'blocked'):
            return {'action': 'manual', 'call_id': call['call_id'], 'process_check': None}
        check = _process_stop(view['ledger'], trial, stage, call)
        return {'action': 'reconcile' if check else 'process_stop_unconfirmed',
                'call_id': call['call_id'], 'process_check': check}
    if not calls:
        return None
    attempt = max(c['spec']['attempt_index'] for c in calls)
    # One failed call per attempt: a failed narrative never reaches its checker.
    failed = [c for c in calls if c['spec']['attempt_index'] == attempt and c['status'] == 'failed']
    if not failed:
        return None
    call = failed[0]
    reason = call['receipt']['failure_reason']
    if reason in CONFIGURATION_FAILURES:
        return {'action': 'terminate', 'call_id': call['call_id'], 'process_check': None, 'failure_reason': reason}
    if status != 'blocked':
        return None
    states = [e['kind'] for e in _task_events(view['ledger'], trial, stage) if e['kind'] in _STATE_EVENTS]
    for policy, recorded in ((AUTO_RECONCILE_POLICY, auto_reconciled), (AUTO_RETRY_POLICY, automatic_retry)):
        if recorded(view['events'], call['call_id']):
            if states and states[-1] == 'run-failed':
                return {'action': 'resume', 'call_id': call['call_id'], 'process_check': None, 'policy': policy}
            return None
    if reason in RETRYABLE_FAILURES:
        check = _process_stop(view['ledger'], trial, stage, call)
        if check is not None:
            return {'action': 'retry', 'call_id': call['call_id'], 'process_check': check,
                    'failure_reason': reason}
    return None


def _auto_note(reason, charged_seconds, charged_cost, check):
    return ('Automatic reconciliation (policy automatic_model_call), not a human review: the model call '
            'outcome was unknown ({}); the local child process was confirmed stopped by ledger event {} '
            '(run-failed); any model output was discarded; the worst-case reserved time ({} s) and cost '
            '({} USD) remain charged; usage is unknown.').format(
                reason, check['ledger_event_id'], charged_seconds, charged_cost)


def auto_recover(store, trial, stage):
    """Resolve one stage's confirmed-stopped call failure, then resume its task.

    An uncertain call is reconciled as failed; a known model-attributable
    failure is scheduled for retry. Never dispatches, approves or touches
    campaign steps. Each step is idempotent from the recorded state, so a crash
    between the store and ledger commits is completed by the next call. Returns
    the recorded payload (its `policy` names which), or None when only the
    ledger resume remained.
    """
    view = trial_view(store, trial)
    pending = auto_recovery(view, trial, stage)
    if pending is None:
        return None
    if pending['action'] == 'process_stop_unconfirmed':
        _fail('process_stop_unconfirmed', 'call')
    if pending['action'] in ('manual', 'terminate'):
        _fail('reconciliation_required', 'call')
    result = None
    if pending['action'] == 'reconcile':
        call = next(c for c in view['calls'] if c['call_id'] == pending['call_id'])
        reason = call['receipt']['failure_reason'] if call['receipt'] is not None else 'dispatch_interrupted'
        receipt = _unmeasured_receipt(view['frozen'], trial, call, reason)
        settled = dict(call, status='failed', receipt=receipt)
        experiment = view['frozen']['experiment']
        note = _auto_note(reason, BenchmarkStore.charge(settled, 'seconds', experiment),
                          BenchmarkStore.charge(settled, 'cost', experiment), pending['process_check'])
        evidence = {'schema_version': 1, 'policy': AUTO_RECONCILE_POLICY, 'call_id': call['call_id'],
                    'fingerprint': call['fingerprint'], 'outcome': 'failed', 'receipt': None,
                    'prior_receipt_sha256': (digest_bytes(canonical_bytes(call['receipt']))
                                             if call['receipt'] is not None else None),
                    'process_stopped': True, 'process_check': pending['process_check']}
        ref = store.write_artifact(trial['trial_id'], 'reconciliation', canonical_bytes(evidence))
        result = store.auto_reconcile_call(call['call_id'], note, ref, receipt, pending['process_check'])
        pending = auto_recovery(trial_view(store, trial), trial, stage)
    elif pending['action'] == 'retry':
        note = ('Automatic retry (policy automatic_retry), not a human decision: the model call failed with '
                'known reason {}; the local child process was confirmed stopped by ledger event {} '
                '(run-failed); its receipt and charges are kept and the stage runs as a new attempt.').format(
                    pending['failure_reason'], pending['process_check']['ledger_event_id'])
        result = store.record_automatic_retry(pending['call_id'], note, pending['process_check'])
        pending = auto_recovery(trial_view(store, trial), trial, stage)
    if pending is not None and pending['action'] == 'resume':
        actor, note = ((AUTO_RECONCILE_ACTOR, AUTO_RESUME_NOTE) if pending['policy'] == AUTO_RECONCILE_POLICY
                       else (AUTO_RETRY_ACTOR, AUTO_RETRY_RESUME_NOTE))
        try:
            _bot(store, trial, 'auto-resume', stage, actor, note)
        except BenchmarkError:
            # A timed-out CLI can already have committed. Inspect, never repeat blindly.
            if ledger_snapshot(store, trial)['tasks'][stage]['status'] != 'active':
                raise
    return result


def _load_reconciliation(path, call, outcome):
    if path is None:
        _fail('evidence_required', 'reconciliation.evidence')
    target = Path(path)
    if not target.is_absolute():
        _fail('unsafe_path', 'reconciliation.evidence')
    try:
        source = confined_file(target.parent, target.name)
        with source.open('rb') as stream:
            raw = stream.read(MAX_BYTES + 1)
    except OSError:
        _fail('evidence_unavailable', 'reconciliation.evidence')
    if len(raw) > MAX_BYTES:
        _fail('budget_exceeded', 'reconciliation.evidence')
    value = decode_json(raw)
    required = {'schema_version', 'call_id', 'fingerprint', 'outcome', 'receipt',
                'observation', 'process_stopped'}
    if type(value) is not dict or set(value) != required:
        _fail('invalid_fields', 'reconciliation.evidence')
    if type(value['schema_version']) is not int or value['schema_version'] != 1:
        _fail('unsupported_schema', 'reconciliation.evidence.schema_version')
    if value['call_id'] != call['call_id'] or value['fingerprint'] != call['fingerprint'] or value['outcome'] != outcome:
        _fail('fingerprint_conflict', 'reconciliation.evidence')
    if value['process_stopped'] is not True:
        _fail('effect_unverified', 'reconciliation.process_stopped')
    _text(value['observation'], 'reconciliation.observation')
    if value['receipt'] is None:
        if outcome != 'failed':
            _fail('incomplete_receipt', 'reconciliation.receipt')
    elif type(value['receipt']) is not dict or value['receipt'].get('status') != outcome:
        _fail('scope_mismatch', 'reconciliation.receipt')
    return value


def _failed_recovery_receipt(store, trial, call):
    if call['receipt'] is not None:
        if call['status'] == 'completed':
            _fail('fingerprint_conflict', 'reconciliation.receipt')
        return dict(call['receipt'], status='failed', failure_reason='human_reconciled')
    return _unmeasured_receipt(store.get_experiment(trial['experiment_id']), trial, call, 'human_reconciled')


def _unmeasured_receipt(frozen, trial, call, reason):
    """A failed receipt with no surviving measurement: elapsed, usage, cost and
    response stay null, so the reserved worst case remains charged."""
    team, _ = _scope(frozen, trial)
    spec = call['spec']
    usage = dict(input_tokens=None, output_tokens=None, cached_input_tokens=None, reasoning_tokens=None)
    return {'schema_version': 1, 'call_id': call['call_id'], 'fingerprint': call['fingerprint'],
            'status': 'failed', 'model_requested': spec['model']['model_requested'],
            'model_returned': None, 'identity_status': 'unreported', 'provider': spec['model']['provider'],
            'deployment': team['deployment'], 'role': spec['role'], 'stage_key': spec['stage_key'],
            'prompt_sha256': spec['input_sha256'], 'response_sha256': None,
            'start_utc': call['created_utc'], 'end_utc': dt.datetime.now(dt.timezone.utc).isoformat(),
            'elapsed_ms': None, 'timeout_seconds': spec['model']['timeout_seconds'],
            'max_calls': frozen['experiment']['budgets']['max_calls_per_trial'],
            'max_output_bytes': frozen['experiment']['budgets']['max_response_bytes'],
            'finish_reason': None, 'usage': usage, 'estimated_usage': dict(usage),
            'cost': {'api_cost_usd': None, 'pricing_snapshot_sha256': digest_bytes(canonical_bytes(
                frozen['experiment']['pricing_snapshot'])), 'cost_basis': 'unknown',
                'local_compute_cost_usd': None, 'local_energy_cost_usd': None,
                'bound_exceeded': False},
            'failure_reason': reason, 'response_artifact': None}


def _recover_submission(store, trial, call, by, note):
    stage = call['spec']['stage_key']
    if call['spec']['component'] != 'narrative':
        _fail('submission_recovery_required', 'call.component')
    latest = _latest_narrative(store.calls(trial_id=trial['trial_id']), stage)
    if latest is None or latest['call_id'] != call['call_id']:
        _fail('handoff_stale', 'call.call_id')
    _validated_response(store, trial, call)
    snapshot = ledger_snapshot(store, trial)
    status = snapshot['tasks'][stage]['status']
    if status in ('review', 'done'):
        if status == 'review':
            # An interrupted dispatch can reach review without its checker
            # appendix; registering the stored appendix completes the handoff.
            ensure_checker_artifact(store, trial, call)
        handoff = stage_handoff(store, trial, stage)
        if handoff['call']['call_id'] != call['call_id']:
            _fail('handoff_mismatch', 'ledger.submit')
        record_submission(store, trial, stage, handoff)
        return status
    events = _task_events(snapshot, trial, stage)
    runs = [e for e in events if e['kind'] == 'run-started']
    if not runs or any(e['id'] > runs[-1]['id'] and e['kind'] in ('submit', 'approve', 'reject') for e in events):
        _fail('submission_recovery_required', 'ledger.run')
    # Composite completion is required before even recovering the handoff.
    ensure_checker_artifact(store, trial, call)
    if status == 'running':
        _bot(store, trial, 'recover-run', stage, by, note)
        status = 'blocked'
    if status == 'blocked':
        _bot(store, trial, 'resume', stage)
        status = 'active'
    if status != 'active':
        _fail('state_conflict', 'ledger.status')
    target = store.root / 'trials' / trial['trial_id'] / call['receipt']['response_artifact']['path']
    artifacts = ledger_snapshot(store, trial)['artifacts']
    if not any(a['task_id'] == trial['task_mapping'][stage] and _path_key(trial, a['path']) == _path_key(trial, target)
               and a['description'] == RECONCILED_DESCRIPTION for a in artifacts):
        _bot(store, trial, 'artifact', stage,
             extra=('--path', str(target), '--description', RECONCILED_DESCRIPTION))
    _bot(store, trial, 'submit', stage, by, _recovery_note(call))
    record_submission(store, trial, stage, stage_handoff(store, trial, stage))
    return 'review'


def reconcile(state_root, experiment_id, call_id, by, note, outcome, evidence_path=None):
    """Resolve with supplied evidence; never dispatch, synthesize metrics, or approve."""
    by, note = _text(by, 'reconciliation.by'), _text(note, 'reconciliation.note')
    human_actor(by)
    if outcome not in ('failed', 'completed'):
        _fail('invalid_choice', 'reconciliation.outcome')
    store = BenchmarkStore(state_root)
    calls = [c for c in store.calls(experiment_id=experiment_id) if c['call_id'] == call_id]
    if len(calls) != 1:
        _fail('not_found', 'call_id')
    call = calls[0]
    trial = _trial(store, experiment_id, call['spec']['trial_id'])
    ledger_snapshot(store, trial)
    evidence = _load_reconciliation(evidence_path, call, outcome)
    receipt = evidence['receipt']
    if receipt is None:
        if call['status'] == 'failed':
            receipt = call['receipt']
        else:
            receipt = _failed_recovery_receipt(store, trial, call)
        if call['receipt'] is None:
            note += (' [Recovery bounds: receipt start/end are reservation/reconciliation times, '
                     'not model execution timestamps; model elapsed time, usage and cost are unknown.]')
    with store.connection() as db:
        _, frozen, team = store._call_spec(db, call['spec'], call['fingerprint'])
        store._receipt(call, receipt, frozen, team)
    if call['status'] in ('completed', 'failed') and receipt != call['receipt']:
        _fail('fingerprint_conflict', 'reconciliation.receipt')
    ref = store.write_artifact(trial['trial_id'], 'reconciliation', canonical_bytes(evidence))
    if call['status'] in ('reserved', 'unknown'):
        store.reconcile_call(call_id, by, note, outcome, ref, receipt)
    else:
        with store.connection(immediate=True) as db:
            events = [_unpack(r) for r in db.execute(
                "SELECT * FROM events WHERE call_id=? AND kind='reconciliation_recorded'", (call_id,))]
            if not any(e['payload'].get('evidence') == ref and e['payload'].get('outcome') == outcome for e in events):
                store.event('reconciliation_recorded', by,
                            {'policy': HUMAN_RECONCILE_POLICY, 'note': note, 'outcome': outcome, 'evidence': ref,
                             'receipt_sha256': digest_bytes(canonical_bytes(receipt))},
                            experiment_id=experiment_id, trial_id=trial['trial_id'], call_id=call_id, db=db)
    call = next(c for c in store.calls(trial_id=trial['trial_id']) if c['call_id'] == call_id)
    ledger_status = ledger_snapshot(store, trial)['tasks'][call['spec']['stage_key']]['status']
    if outcome == 'completed' and call['spec']['component'] == 'narrative':
        ledger_status = _recover_submission(store, trial, call, by, note)
    return {'call_id': call_id, 'outcome': outcome, 'ledger_status': ledger_status,
            'evidence_sha256': ref['sha256'], 'approved': False}

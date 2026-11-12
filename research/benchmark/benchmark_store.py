"""Authoritative, secret-free benchmark state; no model or lab dispatch.

The owner must exclusively administer the state directory. Hashes detect changed
bytes, not authenticity or a malicious concurrent filesystem administrator.
"""
import datetime as dt
import json
import math
import os
from pathlib import Path
import re
import sqlite3
from contextlib import contextmanager
import time
import uuid
from decimal import Decimal

import benchmark_paths
from benchmark_contracts import (
    AUTO_ADVANCE_ACTOR, AUTO_FREEZE_ACTOR, AUTO_FREEZE_NOTE, FREEZE_POLICY, BenchmarkError,
    REVIEW_POLICY, ROLE_IDS, STAGE_KEYS, call_cost_bound, canonical_bytes, campaign_manifest_digest,
    confined_file, decode_json, digest_bytes, parse_utc, route_is_paid, validate_coverage,
    validate_experiment, validate_public_bundle, validate_scenario, validate_stage_output,
    validate_state_root, validate_truth,
)
from workflows import validate_template

EVENT_KINDS = frozenset((
    'experiment_created', 'campaign_preflight', 'authorization_recorded',
    'dispatch_reserved', 'dispatch_finished', 'dispatch_unknown',
    'evidence_sealed', 'stage_submitted', 'stage_auto_advanced',
    'score_recorded', 'reconciliation_recorded', 'trial_status_changed',
    'trial_terminated', 'campaign_status_changed', 'process_started', 'process_stopped',
))
# One unreviewed automatic advance; never a human decision or approval.
AUTO_ADVANCE_FIELDS = ('stage_key', 'attempt_index', 'ledger_event_id', 'ledger_submit_event_id',
                       'ledger_event_sha256', 'output_sha256', 'output_artifact', 'checker_artifact',
                       'checker_receipt_sha256', 'review_policy')
# Automatic resolution of an uncertain *model* call: its only effect is local
# compute and cost. Never a human reconciliation, and never a campaign step.
AUTOMATION_PREFIX = 'benchmark-auto'
AUTO_RECONCILE_ACTOR = 'benchmark-auto-reconcile'
AUTO_RECONCILE_POLICY = 'automatic_model_call'
HUMAN_RECONCILE_POLICY = 'human_operator'
MODEL_COMPONENTS = ('narrative', 'evidence_checker')
PROCESS_CHECK_FIELDS = ('basis', 'ledger_event_id', 'ledger_event_time')
# A known model call failure the model or its transport caused: the next attempt
# is scheduled automatically (never a reconciliation: the outcome is known).
AUTO_RETRY_ACTOR = 'benchmark-auto-retry'
AUTO_RETRY_POLICY = 'automatic_retry'
RETRYABLE_FAILURES = frozenset(('invalid_response', 'empty_response', 'tool_response', 'output_limit',
                                'model_identity_mismatch', 'transport_failed', 'upstream_http_error',
                                'dispatch_interrupted', 'timeout'))
# Operator configuration failures: another attempt cannot help, so the trial ends.
CONFIGURATION_FAILURES = frozenset(('credential_unavailable', 'authentication_failed', 'configuration_invalid',
                                    'unsupported_parameter', 'prerequisite_missing', 'budget_exceeded'))
# Narrative format failures whose received answer is kept, think-stripped and
# capped, as an evaluator-only `rejected_response` artifact for diagnostics.
REJECTED_RESPONSE_FAILURES = ('invalid_response', 'output_limit')
STAGE_ROLES = dict(zip(STAGE_KEYS, (
    'framework-coordinator', 'framework-researcher', 'framework-network-analyst',
    'framework-librarian', 'framework-builder', 'framework-reviewer',
    'framework-coordinator',
)))
TRIAL_STATUSES = ('pending', 'ready', 'running', 'completed', 'failed',
                  'unknown', 'blocked', 'terminated')
TERMINAL_REASONS = ('budget_exhausted', 'human_abandoned', 'unrecoverable_stage')
FAILURES = ('timeout', 'transport_failed', 'invalid_response', 'empty_response',
            'tool_response', 'output_limit', 'model_identity_mismatch',
            'budget_exceeded', 'execution_failed', 'dispatch_interrupted',
            'previous_dispatch_unknown', 'human_reconciled', 'unsupported_metadata',
            'effect_unverified', 'target_mismatch', 'authorization_expired',
            'incomplete_export', 'unsupported_tool_version', 'identity_mismatch',
            'collector_unavailable', 'session_cleanup_failed', 'credential_unavailable',
            'authentication_failed', 'configuration_invalid', 'unsupported_parameter',
            'prerequisite_missing')
PROCESS_STOP_SOURCES = ('run_process', 'stop_owned')
TOKEN_FIELDS = {'input_tokens', 'output_tokens', 'cached_input_tokens', 'reasoning_tokens'}
FORBIDDEN_FIELDS = frozenset((
    'headers', 'environment', 'environ', 'env', 'stderr', 'stdout', 'raw_stderr',
    'exception', 'exception_body', 'provider_error', 'password', 'api_key',
    'access_token', 'secret', 'credentials', 'cookies', 'authorization_header',
    'chain_of_thought', 'hidden_reasoning',
))
SCHEMA = (
    'CREATE TABLE experiments (experiment_id TEXT PRIMARY KEY, data BLOB NOT NULL, sha256 TEXT NOT NULL)',
    'CREATE TABLE trials (trial_id TEXT PRIMARY KEY, experiment_id TEXT NOT NULL REFERENCES experiments(experiment_id), status TEXT NOT NULL, data BLOB NOT NULL, sha256 TEXT NOT NULL)',
    'CREATE TABLE calls (call_id TEXT PRIMARY KEY, trial_id TEXT NOT NULL REFERENCES trials(trial_id), stage_key TEXT NOT NULL, attempt_index INTEGER NOT NULL, component TEXT NOT NULL, status TEXT NOT NULL, data BLOB NOT NULL, sha256 TEXT NOT NULL, UNIQUE(trial_id,stage_key,attempt_index,component))',
    'CREATE TABLE campaign_state (campaign_id TEXT PRIMARY KEY, experiment_id TEXT REFERENCES experiments(experiment_id), status TEXT NOT NULL, cleanup_status TEXT NOT NULL, data BLOB NOT NULL, sha256 TEXT NOT NULL)',
    'CREATE TABLE campaigns (campaign_id TEXT NOT NULL REFERENCES campaign_state(campaign_id), phase TEXT NOT NULL, step_id TEXT NOT NULL, experiment_id TEXT REFERENCES experiments(experiment_id), status TEXT NOT NULL, data BLOB NOT NULL, sha256 TEXT NOT NULL, PRIMARY KEY(campaign_id,phase,step_id))',
    'CREATE TABLE approvals (approval_id TEXT PRIMARY KEY, experiment_id TEXT REFERENCES experiments(experiment_id), trial_id TEXT REFERENCES trials(trial_id), campaign_id TEXT REFERENCES campaign_state(campaign_id), kind TEXT NOT NULL, data BLOB NOT NULL, sha256 TEXT NOT NULL)',
    'CREATE TABLE events (seq INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT UNIQUE NOT NULL, experiment_id TEXT REFERENCES experiments(experiment_id), campaign_id TEXT REFERENCES campaign_state(campaign_id), trial_id TEXT REFERENCES trials(trial_id), call_id TEXT REFERENCES calls(call_id), kind TEXT NOT NULL, data BLOB NOT NULL, sha256 TEXT NOT NULL)',
)

# Content digests already proven within this process. Rows and frozen
# experiments are content-addressed: every read still hashes the actual bytes,
# and only bytes with an identical digest skip re-proving their structure.
_VERIFIED_ROWS = set()
_VERIFIED_FROZEN = set()
# Immutable trial artifacts proven by routine reads, keyed by
# (path, size, mtime_ns, expected digest); any change to the file misses.
_VERIFIED_ARTIFACTS = set()


def _fail(code, field):
    raise BenchmarkError(code, field) from None


def _fields(value, required, field, optional=()):
    if type(value) is not dict:
        _fail('invalid_object', field)
    if not set(required) <= value.keys():
        _fail('missing_field', field)
    if value.keys() - set(required) - set(optional):
        _fail('unknown_field', field)


def _id(value, field, nullable=False):
    if nullable and value is None:
        return
    if type(value) is not str or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,127}', value):
        _fail('invalid_identifier', field)


def _digest(value, field, nullable=False):
    if nullable and value is None:
        return
    if type(value) is not str or not re.fullmatch('[0-9a-f]{64}', value):
        _fail('invalid_digest', field)


def _text(value, field, nullable=False):
    if nullable and value is None:
        return
    if type(value) is not str or not value.strip() or '\x00' in value:
        _fail('invalid_text', field)


def _number(value, field, positive=False, integer=False, nullable=False):
    if nullable and value is None:
        return
    if type(value) not in ((int,) if integer else (int, float)):
        _fail('invalid_number', field)
    try:
        valid = math.isfinite(value) and (value > 0 if positive else value >= 0)
    except OverflowError:
        valid = False
    if not valid:
        _fail('invalid_number', field)


def _choice(value, choices, field):
    if type(value) is not str or value not in choices:
        _fail('invalid_choice', field)


def _time(value, field):
    if type(value) is not str or not re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,6})?(?:Z|\+00:00)', value):
        _fail('invalid_timestamp', field)
    return parse_utc(value, field)


def _process_check(value):
    """The ledger evidence that a model call's local child process ended."""
    _fields(value, set(PROCESS_CHECK_FIELDS), 'process_check')
    _choice(value['basis'], ('ledger_run_failed',), 'process_check.basis')
    _number(value['ledger_event_id'], 'process_check.ledger_event_id', positive=True, integer=True)
    _text(value['ledger_event_time'], 'process_check.ledger_event_time')


def automatic_retry(events, call_id):
    """True when automation scheduled a new attempt after this known failed call."""
    return any(e['kind'] == 'trial_status_changed' and e['call_id'] == call_id
               and e['payload'].get('policy') == AUTO_RETRY_POLICY for e in events)


def human_actor(by):
    """A human reconciler's name, never confusable with benchmark automation."""
    _text(by, 'reconciliation.by')
    if by.strip().lower().startswith(AUTOMATION_PREFIX):
        _fail('reserved_actor', 'reconciliation.by')


def reconciliation_policy(event):
    """Who resolved an uncertain dispatch: automation only when explicitly recorded."""
    if event['payload'].get('policy') == AUTO_RECONCILE_POLICY:
        return AUTO_RECONCILE_POLICY
    return HUMAN_RECONCILE_POLICY


def call_timing(call, events, experiment, now=None):
    """One model call's elapsed time against its own timeout, with its charge.

    A receipt measurement wins. An automatically discarded unknown receipt's
    observation is shown, labeled, but never charged. Given `now`, a call still
    reserved shows the time since its reservation. Charges are the reserved
    worst case unless measured.
    """
    timeout = call['spec']['model']['timeout_seconds']
    receipt = call['receipt']
    recorded = [event for event in events
                if event['kind'] == 'reconciliation_recorded' and event['call_id'] == call['call_id']]
    elapsed, basis = None, None
    if receipt is not None and receipt['elapsed_ms'] is not None:
        elapsed, basis = receipt['elapsed_ms'], 'receipt'
    elif recorded and recorded[-1]['payload'].get('observed_elapsed_ms') is not None:
        elapsed, basis = recorded[-1]['payload']['observed_elapsed_ms'], 'discarded_unknown_receipt'
    elif call['status'] == 'reserved' and now is not None:
        elapsed = max(0.0, (now - parse_utc(call['created_utc'], 'call.created_utc')).total_seconds() * 1000)
        basis = 'since_reservation'
    rejected = receipt.get('rejected_response') if receipt is not None else None
    return {'call_id': call['call_id'], 'trial_id': call['spec']['trial_id'],
            'stage_key': call['spec']['stage_key'], 'component': call['spec']['component'],
            'attempt_index': call['spec']['attempt_index'], 'status': call['status'],
            'failure_reason': receipt['failure_reason'] if receipt is not None else None,
            'format_error': ({'code': rejected['error_code'], 'field': rejected['error_field']}
                             if rejected is not None else None),
            'elapsed_ms': elapsed, 'elapsed_basis': basis, 'timeout_seconds': timeout,
            'timeout_margin_ms': None if elapsed is None else timeout * 1000 - elapsed,
            'charged_seconds': BenchmarkStore.charge(call, 'seconds', experiment),
            'charged_api_cost_usd': BenchmarkStore.charge(call, 'cost', experiment),
            'reconciliation_policy': reconciliation_policy(recorded[-1]) if recorded else None,
            'reconciled_by': recorded[-1]['actor'] if recorded else None,
            'automatic_retry': automatic_retry(events, call['call_id'])}



def _fsync_directory(directory):
    # Directory fsync is POSIX-only; NTFS persists the rename with the file metadata.
    if os.name == 'nt':
        return
    fd = os.open(str(directory), os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _write_temp(directory, prefix, content):
    """Write and fsync a private, uniquely named file in the destination directory."""
    temp = directory / ('.' + prefix + '.' + uuid.uuid4().hex + '.tmp')
    fd = os.open(str(temp), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_BINARY', 0), 0o600)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        _discard(temp)
        raise
    return temp


def _discard(path):
    try:
        os.unlink(str(path))
    except OSError:
        pass


def _publish(base, relative, content, field):
    """Atomically create an immutable content-addressed file.

    The final name only ever holds complete fsynced bytes. A pre-existing final
    file is kept when its digest matches; a partial or mismatched regular file
    (from an interrupted older writer) is atomically replaced. Aliases are never
    followed or replaced.
    """
    path = base.joinpath(*relative.split('/'))
    if path.exists() or path.is_symlink():
        if digest_bytes(confined_file(base, relative).read_bytes()) == digest_bytes(content):
            return
    temp = _write_temp(path.parent, path.name, content)
    try:
        os.replace(str(temp), str(path))
    except BaseException:
        _discard(temp)
        raise
    _fsync_directory(path.parent)
    if digest_bytes(confined_file(base, relative).read_bytes()) != digest_bytes(content):
        _fail('artifact_corrupt', field)


def _now():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec='microseconds')


def _safe(value):
    # Validate the complete JSON once; reserializing every descendant makes
    # repeated immutable-context reads scale with every ancestor's subtree.
    canonical_bytes(value)
    pending = [value]
    while pending:
        item = pending.pop()
        if type(item) is dict:
            for key in item:
                if key.lower() in FORBIDDEN_FIELDS:
                    _fail('forbidden_field', 'snapshot')
            pending.extend(child for child in item.values() if type(child) in (dict, list))
        elif type(item) is list:
            pending.extend(child for child in item if type(child) in (dict, list))


def _encoded(value):
    _safe(value)
    data = canonical_bytes(value)
    return data, digest_bytes(data)


def _unpack(row):
    if row is None:
        _fail('not_found', 'state')
    if type(row['data']) not in (bytes, str):
        _fail('corrupt_state', 'snapshot.data')
    data = bytes(row['data']) if not isinstance(row['data'], str) else row['data'].encode('utf-8')
    sha = digest_bytes(data)
    if sha != row['sha256']:
        _fail('corrupt_state', 'snapshot.sha256')
    if sha in _VERIFIED_ROWS:
        # Identical bytes already passed strict decoding, canonical form and
        # the forbidden-field scan; plain decoding yields the same value.
        result = json.loads(data)
    else:
        result = decode_json(data)
        if type(result) is not dict:
            _fail('corrupt_state', 'snapshot.data')
        if canonical_bytes(result) != data:
            _fail('corrupt_state', 'snapshot.canonical')
        _safe(result)
        _VERIFIED_ROWS.add(sha)
    for key in ('call_id', 'trial_id', 'experiment_id', 'campaign_id', 'stage_key',
                'attempt_index', 'component', 'status', 'cleanup_status', 'phase', 'step_id', 'kind', 'seq', 'event_id', 'approval_id'):
        if key in row.keys():
            expected = result.get(key, result.get('spec', {}).get(key))
            if key == 'experiment_id' and 'experiment' in result:
                expected = result['experiment']['experiment_id']
            if expected != row[key]:
                _fail('corrupt_state', 'snapshot.index')
    return result


def _ref(ref):
    _fields(ref, {'sha256', 'path', 'byte_count'}, 'artifact')
    _digest(ref['sha256'], 'artifact.sha256')
    _number(ref['byte_count'], 'artifact.byte_count', integer=True)
    if type(ref['path']) is not str or not re.fullmatch(r'artifacts/[A-Za-z0-9][A-Za-z0-9_-]{0,127}/[0-9a-f]{64}', ref['path']):
        _fail('unsafe_path', 'artifact.path')
    if ref['path'].rsplit('/', 1)[-1] != ref['sha256']:
        _fail('digest_mismatch', 'artifact.path')


def _frozen(spec):
    _fields(spec, {'experiment', 'coverage', 'workflow', 'prompt_contract', 'cases',
                   'role_instructions', 'created_utc', 'execution'}, 'snapshot')
    validate_experiment(spec['experiment'])
    validate_coverage(spec['coverage'])
    try:
        validate_template(spec['workflow'])
    except (ValueError, TypeError, KeyError):
        _fail('invalid_workflow', 'snapshot.workflow')
    _text(spec['prompt_contract'], 'snapshot.prompt_contract')
    _time(spec['created_utc'], 'snapshot.created_utc')
    _choice(spec['execution'], ('framework-managed',), 'snapshot.execution')
    _fields(spec['role_instructions'], ROLE_IDS, 'snapshot.role_instructions')
    for text in spec['role_instructions'].values():
        _text(text, 'snapshot.role_instructions')
    for field, data in (('coverage', canonical_bytes(spec['coverage'])),
                        ('workflow', canonical_bytes(spec['workflow'])),
                        ('prompt_contract', spec['prompt_contract'].encode('utf-8'))):
        if digest_bytes(data) != spec['experiment'][field + '_sha256']:
            _fail('digest_mismatch', 'snapshot.' + field)
    if type(spec['cases']) is not list or len(spec['cases']) != len(spec['experiment']['scenario_refs']):
        _fail('incomplete_snapshot', 'snapshot.cases')
    cases, scenarios = set(), set()
    for case in spec['cases']:
        _fields(case, {'scenario', 'evidence', 'public_files'}, 'snapshot.cases')
        validate_scenario(case['scenario'], spec['coverage'])
        validate_public_bundle(case['evidence'])
        if case['scenario']['evidence_manifest_sha256'] != digest_bytes(canonical_bytes(case['evidence'])):
            _fail('digest_mismatch', 'snapshot.cases.evidence')
        if case['public_files'] != case['evidence']['files']:
            _fail('incomplete_snapshot', 'snapshot.cases.public_files')
        if case['evidence']['case_id'] in cases or case['scenario']['scenario_id'] in scenarios:
            _fail('duplicate_identifier', 'snapshot.cases')
        cases.add(case['evidence']['case_id'])
        scenarios.add(case['scenario']['scenario_id'])
    _safe(spec)


def _unpack_frozen(row):
    """A frozen experiment row, fully validated once per content digest per process."""
    result = _unpack(row)
    if row['sha256'] not in _VERIFIED_FROZEN:
        _frozen(result)
        _VERIFIED_FROZEN.add(row['sha256'])
    return result



class BenchmarkStore:
    """One SQLite authority; every mutation and its audit event commit together."""

    def __init__(self, state_root, create=False):
        self.root = validate_state_root(state_root)
        self.path = self.root / 'benchmark.sqlite3'
        try:
            if create:
                self._create()
            else:
                self._recover_creation_link()
                confined_file(self.root, 'benchmark.sqlite3')
                with self.connection() as db:
                    if db.execute('PRAGMA user_version').fetchone()[0] != 1:
                        _fail('unsupported_schema', 'store')
        except FileExistsError:
            _fail('already_exists', 'store')
        except OSError:
            _fail('state_unavailable', 'store')

    def _create(self):
        """Build the complete schema privately, then publish it without overwrite.

        A crash leaves either no database or a complete one; never an empty file
        that strands the state root. An orphaned private temporary is inert.
        """
        self.root.mkdir(parents=True, exist_ok=True)
        validate_state_root(self.root)
        if self.path.exists() or self.path.is_symlink():
            raise FileExistsError()
        temp = self.root / ('.benchmark.sqlite3.' + uuid.uuid4().hex + '.tmp')
        try:
            db = sqlite3.connect(temp.as_uri() + '?mode=rwc', uri=True, timeout=30, isolation_level=None)
            try:
                db.execute('PRAGMA synchronous=FULL')
                db.execute('BEGIN IMMEDIATE')
                for statement in SCHEMA:
                    db.execute(statement)
                db.execute('PRAGMA user_version=1')
                db.execute('COMMIT')
            finally:
                db.close()
            fd = os.open(str(temp), os.O_RDWR | getattr(os, 'O_BINARY', 0))
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
            if os.name == 'nt':
                os.rename(str(temp), str(self.path))  # Fails if the destination exists.
            else:
                os.link(str(temp), str(self.path))  # Fails if the destination exists.
                os.unlink(str(temp))
            _fsync_directory(self.root)
        except sqlite3.Error:
            _fail('storage_error', 'store')
        finally:
            _discard(temp)
            for suffix in ('-journal', '-wal', '-shm'):
                _discard(Path(str(temp) + suffix))

    def _recover_creation_link(self):
        """Finish a POSIX publish interrupted between link and temporary unlink."""
        if os.name == 'nt' or not self.path.is_file() or self.path.is_symlink():
            return
        if self.path.lstat().st_nlink < 2:
            return
        for entry in self.root.iterdir():
            if (re.fullmatch(r'\.benchmark\.sqlite3\.[0-9a-f]{32}\.tmp', entry.name)
                    and not entry.is_symlink() and os.path.samefile(str(entry), str(self.path))):
                os.unlink(str(entry))

    def _check_sidecar(self, name):
        """Refuse an aliased SQLite sidecar, tolerating a transient journal.

        Another connection's commit deletes its rollback journal at any moment,
        so a sidecar that vanishes during the check is not an error; one that
        persists and fails confinement still is.
        """
        path = self.root / name
        for _ in range(50):
            if not os.path.lexists(str(path)):
                return
            try:
                confined_file(self.root, name)
                return
            except BenchmarkError as exc:
                if exc.code not in ('file_not_found', 'unsafe_path'):
                    raise
                failure = exc
            time.sleep(0.01)
        raise failure

    @contextmanager
    def connection(self, immediate=False):
        """A single consistent read transaction, or an immediate write transaction.

        The state-root location was validated when this store was constructed and
        is revalidated before every directory creation; each connection still
        refuses an aliased root, database file or sidecar.
        """
        db = None
        try:
            confined_file(self.root, 'benchmark.sqlite3')
            for suffix in ('-journal', '-wal', '-shm'):
                self._check_sidecar('benchmark.sqlite3' + suffix)
            db = sqlite3.connect(self.path.as_uri() + '?mode=rw', uri=True,
                                 timeout=30, isolation_level=None)
            db.row_factory = sqlite3.Row
            db.execute('PRAGMA synchronous=FULL')
            db.execute('PRAGMA foreign_keys=ON')
            if db.execute('PRAGMA user_version').fetchone()[0] != 1:
                _fail('unsupported_schema', 'store')
            db.execute('BEGIN IMMEDIATE' if immediate else 'BEGIN')
            yield db
            db.execute('COMMIT')
        except sqlite3.Error:
            if db is not None and db.in_transaction:
                db.rollback()
            _fail('storage_error', 'store')
        except (KeyError, IndexError, TypeError, OverflowError, StopIteration):
            if db is not None and db.in_transaction:
                db.rollback()
            _fail('corrupt_state', 'store')
        except BaseException:
            if db is not None and db.in_transaction:
                db.rollback()
            raise
        finally:
            if db is not None:
                db.close()

    def event(self, kind, actor, payload, experiment_id=None, campaign_id=None,
              trial_id=None, task_id=None, call_id=None, db=None):
        _choice(kind, EVENT_KINDS, 'event.kind')
        _text(actor, 'event.actor')
        if type(payload) is not dict:
            _fail('invalid_object', 'event.payload')
        _safe(payload)
        for key, value in (('experiment_id', experiment_id), ('campaign_id', campaign_id),
                           ('trial_id', trial_id), ('call_id', call_id)):
            _id(value, 'event.' + key, nullable=True)
        if task_id is not None:
            _number(task_id, 'event.task_id', positive=True, integer=True)
        if experiment_id is None and campaign_id is None:
            _fail('missing_scope', 'event')
        if db is None:
            with self.connection(immediate=True) as conn:
                return self.event(kind, actor, payload, experiment_id, campaign_id,
                                  trial_id, task_id, call_id, conn)
        if not db.in_transaction:
            _fail('transaction_required', 'event')
        if trial_id is not None:
            trial = _unpack(db.execute('SELECT * FROM trials WHERE trial_id=?', (trial_id,)).fetchone())
            if experiment_id != trial['experiment_id']:
                _fail('scope_mismatch', 'event.trial_id')
        if call_id is not None:
            call = _unpack(db.execute('SELECT * FROM calls WHERE call_id=?', (call_id,)).fetchone())
            if trial_id != call['spec']['trial_id']:
                _fail('scope_mismatch', 'event.call_id')
        seq = db.execute('SELECT COALESCE(MAX(seq),0)+1 FROM events').fetchone()[0]
        item = dict(schema_version=1, seq=seq, event_id=uuid.uuid4().hex,
                    time_utc=_now(), experiment_id=experiment_id, campaign_id=campaign_id,
                    trial_id=trial_id, task_id=task_id, call_id=call_id,
                    kind=kind, actor=actor, payload=payload)
        data, sha = _encoded(item)
        db.execute('INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?)',
                   (seq, item['event_id'], experiment_id, campaign_id, trial_id, call_id, kind, data, sha))
        return item

    def create_experiment(self, spec, truths=None):
        """Freeze the experiment; given `truths`, freeze its truth in the same transaction."""
        _frozen(spec)
        eid = spec['experiment']['experiment_id']
        data, sha = _encoded(spec)
        with self.connection(immediate=True) as db:
            if db.execute('SELECT 1 FROM experiments WHERE experiment_id=?', (eid,)).fetchone():
                _fail('already_exists', 'experiment_id')
            db.execute('INSERT INTO experiments VALUES (?,?,?)', (eid, data, sha))
            self.event('experiment_created', 'operator', {'snapshot_sha256': sha}, experiment_id=eid, db=db)
            if truths is not None:
                self._freeze_truths(db, eid, truths)
        return spec

    def get_experiment(self, experiment_id):
        _id(experiment_id, 'experiment_id')
        with self.connection() as db:
            return _unpack_frozen(db.execute('SELECT * FROM experiments WHERE experiment_id=?', (experiment_id,)).fetchone())

    def _trial(self, spec, db, routine=False):
        _fields(spec, {'trial_id', 'experiment_id', 'case_id', 'scenario_id', 'team_id',
                       'repetition', 'workflow_id', 'task_mapping', 'case_evidence_sha256',
                       'status', 'created_utc', 'public_artifacts'}, 'trial', ('terminal_reason',))
        for key in ('trial_id', 'experiment_id', 'case_id', 'scenario_id', 'team_id'):
            _id(spec[key], 'trial.' + key)
        _number(spec['workflow_id'], 'trial.workflow_id', positive=True, integer=True)
        _number(spec['repetition'], 'trial.repetition', positive=True, integer=True)
        _time(spec['created_utc'], 'trial.created_utc')
        _choice(spec['status'], TRIAL_STATUSES, 'trial.status')
        if (spec['status'] == 'terminated') != ('terminal_reason' in spec):
            _fail('invalid_trial_status', 'trial.terminal_reason')
        if spec['status'] == 'terminated':
            _choice(spec['terminal_reason'], TERMINAL_REASONS, 'trial.terminal_reason')
        _digest(spec['case_evidence_sha256'], 'trial.case_evidence_sha256')
        _fields(spec['task_mapping'], STAGE_KEYS, 'trial.task_mapping')
        for task_id in spec['task_mapping'].values():
            _number(task_id, 'trial.task_mapping', positive=True, integer=True)
        if len(set(spec['task_mapping'].values())) != len(STAGE_KEYS):
            _fail('duplicate_identifier', 'trial.task_mapping')
        frozen = _unpack(db.execute('SELECT * FROM experiments WHERE experiment_id=?', (spec['experiment_id'],)).fetchone())
        exp = frozen['experiment']
        if spec['repetition'] > exp['repetitions'] or spec['team_id'] not in {t['team_id'] for t in exp['teams']}:
            _fail('scope_mismatch', 'trial')
        cases = [case for case in frozen['cases'] if case['evidence']['case_id'] == spec['case_id'] and case['scenario']['scenario_id'] == spec['scenario_id']]
        if len(cases) != 1 or cases[0]['scenario']['evidence_manifest_sha256'] != spec['case_evidence_sha256']:
            _fail('scope_mismatch', 'trial.case_id')
        files = {f['path']: f for f in cases[0]['public_files']}
        _fields(spec['public_artifacts'], files, 'trial.public_artifacts')
        for path, ref in spec['public_artifacts'].items():
            _ref(ref)
            if (ref['sha256'], ref['byte_count']) != (files[path]['sha256'], files[path]['byte_count']):
                _fail('digest_mismatch', 'trial.public_artifacts')
            self.verify_artifact(spec['trial_id'], ref, routine)
        if spec['status'] == 'completed':
            # Completed means every stage advanced from a completed receipt.
            calls = {call['call_id']: call for call in (_unpack(row) for row in db.execute(
                "SELECT * FROM calls WHERE trial_id=? AND component='narrative' AND status='completed'",
                (spec['trial_id'],)))}
            advanced = set()
            for row in db.execute("SELECT * FROM events WHERE trial_id=? AND kind='stage_auto_advanced'",
                                  (spec['trial_id'],)):
                event = _unpack(row)
                call = calls.get(event['call_id'])
                if (call is not None and call['spec']['stage_key'] == event['payload']['stage_key']
                        and call['receipt']['response_sha256'] == event['payload']['output_sha256']):
                    advanced.add(call['spec']['stage_key'])
            if advanced != set(STAGE_KEYS):
                _fail('incomplete_snapshot', 'trial.completed')
        return frozen

    def create_trial(self, spec):
        with self.connection(immediate=True) as db:
            self._trial(spec, db)
            if db.execute('SELECT 1 FROM trials WHERE trial_id=?', (spec['trial_id'],)).fetchone():
                _fail('already_exists', 'trial_id')
            for row in db.execute('SELECT * FROM trials WHERE experiment_id=?', (spec['experiment_id'],)):
                old = _unpack(row)
                if all(old[k] == spec[k] for k in ('case_id', 'team_id', 'repetition')):
                    _fail('already_exists', 'trial.schedule')
            data, sha = _encoded(spec)
            db.execute('INSERT INTO trials VALUES (?,?,?,?,?)', (spec['trial_id'], spec['experiment_id'], spec['status'], data, sha))
            self.event('evidence_sealed', 'operator', {'trial_sha256': sha, 'evidence_sha256': spec['case_evidence_sha256']},
                       experiment_id=spec['experiment_id'], trial_id=spec['trial_id'], db=db)
        return spec

    def get_trial(self, trial_id):
        _id(trial_id, 'trial_id')
        with self.connection() as db:
            return _unpack(db.execute('SELECT * FROM trials WHERE trial_id=?', (trial_id,)).fetchone())

    def trials(self, experiment_id):
        _id(experiment_id, 'experiment_id')
        with self.connection() as db:
            return [_unpack(r) for r in db.execute('SELECT * FROM trials WHERE experiment_id=? ORDER BY trial_id', (experiment_id,))]

    def update_trial(self, trial_id, spec, status):
        _id(trial_id, 'trial_id')
        _choice(status, TRIAL_STATUSES, 'trial.status')
        if status == 'terminated':
            _fail('state_conflict', 'trial.status')  # Only terminate_trial records termination.
        if type(spec) is not dict or spec.get('trial_id') != trial_id or spec.get('status') != status:
            _fail('scope_mismatch', 'trial')
        with self.connection(immediate=True) as db:
            old = _unpack(db.execute('SELECT * FROM trials WHERE trial_id=?', (trial_id,)).fetchone())
            if old['status'] == 'terminated':
                _fail('state_conflict', 'trial.status')
            self._trial(spec, db)
            if any(old[key] != spec[key] for key in old if key not in ('status', 'public_artifacts')):
                _fail('fingerprint_conflict', 'trial')
            if 'public_artifacts' in old and old['public_artifacts'] != spec.get('public_artifacts'):
                _fail('fingerprint_conflict', 'trial.public_artifacts')
            data, sha = _encoded(spec)
            db.execute('UPDATE trials SET status=?,data=?,sha256=? WHERE trial_id=?', (status, data, sha, trial_id))
            self.event('trial_status_changed', 'runner',
                       {'previous_status': old['status'], 'trial_status': status, 'snapshot_sha256': sha},
                       experiment_id=spec['experiment_id'], trial_id=trial_id, db=db)
        return spec

    def terminate_trial(self, trial_id, reason, actor, note):
        """Record a terminal completion failure; the trial is never resumed.

        In-flight or unknown calls keep their reserved budget and receipts; this
        neither dispatches, approves, nor reconciles anything.
        """
        _id(trial_id, 'trial_id')
        _choice(reason, TERMINAL_REASONS, 'trial.terminal_reason')
        _text(actor, 'trial.terminated_by')
        _text(note, 'trial.termination_note')
        with self.connection(immediate=True) as db:
            old = _unpack(db.execute('SELECT * FROM trials WHERE trial_id=?', (trial_id,)).fetchone())
            if old['status'] == 'terminated':
                if old['terminal_reason'] != reason:
                    _fail('fingerprint_conflict', 'trial.terminal_reason')
                return old
            if old['status'] == 'completed':
                _fail('state_conflict', 'trial.status')
            spec = dict(old, status='terminated', terminal_reason=reason)
            self._trial(spec, db)
            data, sha = _encoded(spec)
            changed = db.execute('UPDATE trials SET status=?,data=?,sha256=? WHERE trial_id=? AND status=?',
                                 ('terminated', data, sha, trial_id, old['status']))
            if changed.rowcount != 1:
                _fail('state_conflict', 'trial.status')
            self.event('trial_terminated', actor,
                       {'previous_status': old['status'], 'reason': reason, 'note': note,
                        'snapshot_sha256': sha},
                       experiment_id=spec['experiment_id'], trial_id=trial_id, db=db)
        return spec

    def _private_directory(self, relative):
        """Create private state directories, persisting each new directory entry."""
        validate_state_root(self.root)
        directory = self.root
        for part in relative.split('/'):
            parent, directory = directory, directory / part
            if not directory.is_dir():
                try:
                    directory.mkdir()
                except FileExistsError:
                    continue  # A concurrent writer or alias; aliases fail validation below.
                _fsync_directory(parent)
        validate_state_root(self.root)
        return directory

    def write_artifact(self, trial_id, kind, content):
        _id(trial_id, 'trial_id')
        _id(kind, 'artifact.kind')
        if type(content) is not bytes:
            _fail('invalid_bytes', 'artifact')
        sha = digest_bytes(content)
        ref = {'sha256': sha, 'path': 'artifacts/' + kind + '/' + sha, 'byte_count': len(content)}
        try:
            self._private_directory('trials/' + trial_id + '/artifacts/' + kind)
            _publish(self.root / 'trials' / trial_id, ref['path'], content, 'artifact')
        except OSError:
            _fail('artifact_unavailable', 'artifact')
        self.read_artifact(trial_id, ref)
        return ref

    def read_artifact(self, trial_id, ref):
        _id(trial_id, 'trial_id')
        _ref(ref)
        try:
            path = confined_file(self.root / 'trials' / trial_id, ref['path'])
            if path.stat().st_size != ref['byte_count']:
                _fail('artifact_corrupt', 'artifact.byte_count')
            data = path.read_bytes()
        except OSError:
            _fail('artifact_unavailable', 'artifact')
        if len(data) != ref['byte_count'] or digest_bytes(data) != ref['sha256']:
            _fail('artifact_corrupt', 'artifact.sha256')
        return data

    def verify_artifact(self, trial_id, ref, routine=False):
        """Prove an immutable artifact's bytes without returning them.

        A routine status/advance read memoizes each proof within this process by
        (path, size, mtime_ns, digest), so any rewrite misses and is re-hashed.
        Export, score, diagnose and release always re-hash in full.
        """
        if not routine:
            self.read_artifact(trial_id, ref)
            return
        _id(trial_id, 'trial_id')
        _ref(ref)
        try:
            path = confined_file(self.root / 'trials' / trial_id, ref['path'])
            info = path.stat()
        except OSError:
            _fail('artifact_unavailable', 'artifact')
        if info.st_size != ref['byte_count']:
            _fail('artifact_corrupt', 'artifact.byte_count')
        key = (str(path), info.st_size, info.st_mtime_ns, ref['sha256'])
        if key not in _VERIFIED_ARTIFACTS:
            self.read_artifact(trial_id, ref)
            _VERIFIED_ARTIFACTS.add(key)

    def record_authorization(self, spec):
        with self.connection(immediate=True) as db:
            return self._record_authorization(db, spec)

    def _record_authorization(self, db, spec):
        """Share the identical policy with atomic multi-destination releases."""
        _fields(spec, {'approval_id', 'experiment_id', 'trial_id', 'campaign_id', 'by', 'note',
                       'created_utc', 'expires_utc', 'evidence_sha256', 'model_sha256s',
                       'manifest_sha256', 'phases'}, 'authorization')
        for key in ('approval_id', 'experiment_id', 'trial_id', 'campaign_id'):
            _id(spec[key], 'authorization.' + key, nullable=key != 'approval_id')
        for key in ('by', 'note'):
            _text(spec[key], 'authorization.' + key)
        created = _time(spec['created_utc'], 'authorization.created_utc')
        expires = _time(spec['expires_utc'], 'authorization.expires_utc')
        if expires <= created or expires <= dt.datetime.now(dt.timezone.utc):
            _fail('authorization_expired', 'authorization.expires_utc')
        if created > dt.datetime.now(dt.timezone.utc):
            _fail('invalid_timestamp', 'authorization.created_utc')
        _digest(spec['evidence_sha256'], 'authorization.evidence_sha256', nullable=True)
        _digest(spec['manifest_sha256'], 'authorization.manifest_sha256', nullable=True)
        if type(spec['model_sha256s']) is not list or type(spec['phases']) is not list:
            _fail('invalid_array', 'authorization')
        for sha in spec['model_sha256s']:
            _digest(sha, 'authorization.model_sha256s')
        for phase in spec['phases']:
            _choice(phase, ('preflight', 'run', 'stop', 'collect', 'cleanup', 'warmup', 'detonate'), 'authorization.phases')
        if len(set(spec['model_sha256s'])) != len(spec['model_sha256s']) or len(set(spec['phases'])) != len(spec['phases']):
            _fail('duplicate_identifier', 'authorization')
        if spec['trial_id'] is not None:
            if spec['experiment_id'] is None or spec['campaign_id'] is not None or spec['manifest_sha256'] is not None or spec['phases'] or not spec['model_sha256s'] or spec['evidence_sha256'] is None:
                _fail('scope_mismatch', 'authorization')
        elif spec['campaign_id'] is None or spec['manifest_sha256'] is None or not spec['phases'] or spec['model_sha256s'] or spec['evidence_sha256'] is not None:
            _fail('scope_mismatch', 'authorization')
        auth_sha = digest_bytes(canonical_bytes(spec))
        item = dict(spec, kind='authorization', authorization_sha256=auth_sha)
        if spec['trial_id'] is not None:
            trial = _unpack(db.execute('SELECT * FROM trials WHERE trial_id=?', (spec['trial_id'],)).fetchone())
            if spec['experiment_id'] != trial['experiment_id'] or spec['evidence_sha256'] != trial['case_evidence_sha256']:
                _fail('scope_mismatch', 'authorization')
            frozen = _unpack(db.execute('SELECT * FROM experiments WHERE experiment_id=?', (spec['experiment_id'],)).fetchone())
            team = next(t for t in frozen['experiment']['teams'] if t['team_id'] == trial['team_id'])
            models = list(team['roles'].values()) + ([team['evidence_checker']] if 'evidence_checker' in team else [])
            if not set(spec['model_sha256s']) <= {digest_bytes(canonical_bytes(m)) for m in models}:
                _fail('scope_mismatch', 'authorization.model_sha256s')
        else:
            campaign = _unpack(db.execute('SELECT * FROM campaign_state WHERE campaign_id=?', (spec['campaign_id'],)).fetchone())
            if campaign['experiment_id'] != spec['experiment_id'] or campaign['manifest_sha256'] != spec['manifest_sha256']:
                _fail('scope_mismatch', 'authorization.manifest_sha256')
        self._approval_insert(db, item)
        self.event('authorization_recorded', spec['by'], {'approval_id': spec['approval_id'], 'authorization_sha256': auth_sha},
                   experiment_id=spec['experiment_id'], trial_id=spec['trial_id'], campaign_id=spec['campaign_id'], db=db)
        return auth_sha

    def _verify_campaign_seal(self, state, sealed, steps):
        """Check immutable public files and their exact private provenance bytes."""
        _fields(sealed, {'record_type', 'case_id', 'evidence_sha256', 'mapping_sha256',
                         'public_manifest', 'condition', 'sources', 'human_release_required'}, 'campaign.seal')
        _choice(sealed['record_type'], ('public_evidence_sealed',), 'campaign.seal.record_type')
        _choice(sealed['condition'], ('raw_telemetry', 'with_detector_alerts'), 'campaign.seal.condition')
        for key in ('evidence_sha256', 'mapping_sha256'):
            _digest(sealed[key], 'campaign.seal.' + key)
        root = self.root / 'campaigns' / state['campaign_id']
        path = confined_file(root, sealed['public_manifest'])
        if not sealed['public_manifest'].startswith('public/') or path.name != 'evidence.json':
            _fail('scope_mismatch', 'campaign.seal.public_manifest')
        try:
            if path.stat().st_size > 1024 * 1024:
                _fail('output_limit', 'campaign.seal.public_manifest')
            content = path.read_bytes()
        except OSError:
            _fail('artifact_unavailable', 'campaign.seal.public_manifest')
        if digest_bytes(content) != sealed['evidence_sha256']:
            _fail('digest_mismatch', 'campaign.seal.evidence_sha256')
        public = decode_json(content)
        validate_public_bundle(public, root=path.parent)
        if canonical_bytes(public) != content or public['case_id'] != sealed['case_id']:
            _fail('digest_mismatch', 'campaign.seal.public_manifest')
        condition = 'with_detector_alerts' if any(event['fields'].get('detector_attack_ids') for event in public['events']) else 'raw_telemetry'
        if condition != sealed['condition']:
            _fail('scope_mismatch', 'campaign.seal.condition')
        if type(sealed['sources']) is not list:
            _fail('invalid_array', 'campaign.seal.sources')
        expected = {item['source_id']: item for item in state['manifest']['collectors']}
        seen = set()
        for source in sealed['sources']:
            _fields(source, {'source_id', 'sha256'}, 'campaign.seal.sources')
            _id(source['source_id'], 'campaign.seal.source_id')
            _digest(source['sha256'], 'campaign.seal.sources.sha256')
            if source['source_id'] not in expected or source['source_id'] in seen:
                _fail('scope_mismatch', 'campaign.seal.sources')
            seen.add(source['source_id'])
            if not any(row['phase'] == 'collect' and row['step_id'].startswith('cleanup-')
                       and row['status'] == 'completed' and row['receipt'] is not None
                       and row['receipt']['evidence_sha256'] == source['sha256'] for row in steps):
                _fail('incomplete_snapshot', 'campaign.seal.sources')
            raw = confined_file(root, 'raw/' + source['sha256'] + '.json')
            try:
                if raw.stat().st_size > state['manifest']['limits']['max_export_bytes'] + 1024 * 1024:
                    _fail('output_limit', 'campaign.seal.sources')
                data = raw.read_bytes()
            except OSError:
                _fail('artifact_unavailable', 'campaign.seal.sources')
            if digest_bytes(data) != source['sha256']:
                _fail('digest_mismatch', 'campaign.seal.sources')
            value = decode_json(data)
            exports = value.get('raw_exports') if type(value) is dict else None
            if type(exports) is not list or len(exports) != 1:
                _fail('incomplete_export', 'campaign.seal.sources')
            export = exports[0]
            collector = expected[source['source_id']]
            if (type(export) is not dict or export.get('source_id') != source['source_id']
                    or export.get('complete') is not True or export.get('window_utc') != collector['window_utc']
                    or _time(export.get('watermark_utc'), 'campaign.seal.watermark_utc') <
                    _time(collector['window_utc']['end_exclusive'], 'collector.window_utc')):
                _fail('incomplete_export', 'campaign.seal.sources')
        if seen != set(expected) or {item['source_sha256'] for item in public['sources']} != {item['sha256'] for item in sealed['sources']}:
            _fail('incomplete_snapshot', 'campaign.seal.sources')
        return content

    def release_campaign_evidence(self, campaign_id, seal_event_id, authorizations):
        """Commit all trial grants, the campaign link and lifecycle together."""
        _id(campaign_id, 'campaign_id')
        _id(seal_event_id, 'seal_event_id')
        if type(authorizations) is not list or not authorizations:
            _fail('invalid_array', 'release.authorizations')
        with self.connection(immediate=True) as db:
            state = _unpack(db.execute('SELECT * FROM campaign_state WHERE campaign_id=?', (campaign_id,)).fetchone())
            self._campaign_state(state)
            if state['status'] not in ('awaiting_release', 'evidence_ready') or state['cleanup_status'] != 'succeeded' or state['owned_process'] is not None:
                _fail('state_conflict', 'campaign.release')
            steps = [_unpack(row) for row in db.execute('SELECT * FROM campaigns WHERE campaign_id=?', (campaign_id,))]
            if any(row['status'] not in ('completed', 'failed') or row['receipt'] is None or
                   row['receipt']['execution_outcome'] == 'unknown' for row in steps):
                _fail('previous_dispatch_unknown', 'campaign.steps')
            event = _unpack(db.execute('SELECT * FROM events WHERE event_id=?', (seal_event_id,)).fetchone())
            sealed = event['payload']
            if event['campaign_id'] != campaign_id or event['kind'] != 'evidence_sealed' or sealed.get('record_type') != 'public_evidence_sealed':
                _fail('scope_mismatch', 'release.seal_event')
            content = self._verify_campaign_seal(state, sealed, steps)
            from benchmark_decisions import ledger_snapshot
            seen, destinations = set(), []
            for spec in authorizations:
                if type(spec) is not dict or spec.get('trial_id') is None or spec.get('by') == 'operator-cli':
                    _fail('human_release_required', 'release.authorization')
                if spec.get('evidence_sha256') != sealed['evidence_sha256']:
                    _fail('digest_mismatch', 'release.evidence_sha256')
                trial = _unpack(db.execute('SELECT * FROM trials WHERE trial_id=?', (spec['trial_id'],)).fetchone())
                if trial['trial_id'] in seen:
                    _fail('duplicate_identifier', 'release.trials')
                seen.add(trial['trial_id'])
                frozen = self._trial(trial, db)
                _frozen(frozen)
                ledger_snapshot(self, trial)
                case = next(case for case in frozen['cases'] if case['evidence']['case_id'] == trial['case_id'])
                if canonical_bytes(case['evidence']) != content:
                    _fail('digest_mismatch', 'release.trial_evidence')
                auth_sha = self._record_authorization(db, spec)
                destinations.append({'experiment_id': spec['experiment_id'], 'trial_id': spec['trial_id'],
                                     'approval_id': spec['approval_id'], 'authorization_sha256': auth_sha,
                                     'model_sha256s': spec['model_sha256s']})
            updated = dict(state, status='evidence_ready', updated_utc=_now())
            self._campaign_state(updated)
            data, sha = _encoded(updated)
            db.execute('UPDATE campaign_state SET status=?,data=?,sha256=? WHERE campaign_id=?',
                       (updated['status'], data, sha, campaign_id))
            self.event('evidence_sealed', authorizations[0]['by'], {
                'record_type': 'campaign_evidence_release', 'seal_event_id': seal_event_id,
                'evidence_sha256': sealed['evidence_sha256'], 'condition': sealed['condition'],
                'destinations': destinations, 'snapshot_sha256': sha,
            }, campaign_id=campaign_id, db=db)
        return destinations

    def _approval_insert(self, db, item):
        if db.execute('SELECT 1 FROM approvals WHERE approval_id=?', (item['approval_id'],)).fetchone():
            _fail('already_exists', 'approval_id')
        data, sha = _encoded(item)
        db.execute('INSERT INTO approvals VALUES (?,?,?,?,?,?,?)',
                   (item['approval_id'], item['experiment_id'], item['trial_id'], item['campaign_id'], item['kind'], data, sha))

    def _authorization(self, db, sha):
        _digest(sha, 'authorization_sha256')
        # SQLite narrows candidates to rows whose canonical bytes name this digest;
        # every candidate is then fully verified. A row damaged so that it no
        # longer names the digest is not found: dispatch is refused, never allowed.
        needle = ('"authorization_sha256":"' + sha + '"').encode('ascii')
        for row in db.execute("SELECT * FROM approvals WHERE kind='authorization' AND instr(data, ?) > 0",
                              (needle,)):
            item = _unpack(row)
            if item['authorization_sha256'] == sha:
                original = {k: v for k, v in item.items() if k not in ('kind', 'authorization_sha256')}
                if digest_bytes(canonical_bytes(original)) != sha:
                    _fail('corrupt_state', 'authorization_sha256')
                if _time(item['expires_utc'], 'authorization.expires_utc') <= dt.datetime.now(dt.timezone.utc):
                    _fail('authorization_expired', 'authorization.expires_utc')
                return item
        _fail('authorization_required', 'authorization_sha256')

    def trial_authorizations(self, trial_id):
        """One trial's authorization rows, verified exactly as `snapshot` verifies them.

        Dispatch reads only the trial, its frozen experiment and these rows, so
        the verified work does not grow with other trials, calls or events.
        Callers still check expiry, model digest and evidence digest per row.
        """
        _id(trial_id, 'trial_id')
        with self.connection() as db:
            trial = _unpack(db.execute('SELECT * FROM trials WHERE trial_id=?', (trial_id,)).fetchone())
            _unpack_frozen(db.execute('SELECT * FROM experiments WHERE experiment_id=?',
                                      (trial['experiment_id'],)).fetchone())
            recorded = {_unpack(row)['payload'].get('approval_id') for row in db.execute(
                "SELECT * FROM events WHERE trial_id=? AND kind='authorization_recorded'", (trial_id,))}
            items = [_unpack(row) for row in db.execute(
                'SELECT * FROM approvals WHERE trial_id=? ORDER BY approval_id', (trial_id,))]
        for item in items:
            if (item['kind'] != 'authorization' or item['approval_id'] not in recorded
                    or item['experiment_id'] != trial['experiment_id']):
                _fail('incomplete_snapshot', 'snapshot.approvals')
            original = {key: value for key, value in item.items() if key not in ('kind', 'authorization_sha256')}
            if digest_bytes(canonical_bytes(original)) != item['authorization_sha256']:
                _fail('corrupt_state', 'snapshot.approvals')
        return items

    def _call_spec(self, db, spec, fingerprint, routine=False):
        _fields(spec, {'schema_version', 'trial_id', 'stage_key', 'attempt_index', 'component',
                       'prompt_artifact', 'input_sha256', 'workflow_sha256', 'prompt_contract_sha256',
                       'evidence_sha256', 'adapter_sha256', 'executable_sha256', 'executable_version',
                       'authorization_sha256', 'model', 'role'}, 'call.spec')
        if type(spec['schema_version']) is not int or spec['schema_version'] != 1:
            _fail('unsupported_schema', 'call.spec.schema_version')
        _id(spec['trial_id'], 'call.spec.trial_id')
        _choice(spec['stage_key'], STAGE_KEYS, 'call.spec.stage_key')
        _choice(spec['component'], MODEL_COMPONENTS, 'call.spec.component')
        _number(spec['attempt_index'], 'call.spec.attempt_index', positive=True, integer=True)
        _text(spec['executable_version'], 'call.spec.executable_version')
        for key in ('input_sha256', 'workflow_sha256', 'prompt_contract_sha256', 'evidence_sha256',
                    'adapter_sha256', 'executable_sha256', 'authorization_sha256'):
            _digest(spec[key], 'call.spec.' + key)
        _digest(fingerprint, 'call.fingerprint')
        if digest_bytes(canonical_bytes(spec)) != fingerprint:
            _fail('fingerprint_conflict', 'call.fingerprint')
        trial = _unpack(db.execute('SELECT * FROM trials WHERE trial_id=?', (spec['trial_id'],)).fetchone())
        frozen = _unpack(db.execute('SELECT * FROM experiments WHERE experiment_id=?', (trial['experiment_id'],)).fetchone())
        exp = frozen['experiment']
        team = next(t for t in exp['teams'] if t['team_id'] == trial['team_id'])
        if spec['role'] != STAGE_ROLES[spec['stage_key']]:
            _fail('scope_mismatch', 'call.spec.role')
        expected = team['roles'][spec['role']] if spec['component'] == 'narrative' else team.get('evidence_checker')
        if expected is None or canonical_bytes(spec['model']) != canonical_bytes(expected) or (spec['component'] == 'evidence_checker' and spec['stage_key'] != 'analysis'):
            _fail('fingerprint_conflict', 'call.spec.model')
        if spec['workflow_sha256'] != exp['workflow_sha256'] or spec['prompt_contract_sha256'] != exp['prompt_contract_sha256'] or spec['evidence_sha256'] != trial['case_evidence_sha256']:
            _fail('fingerprint_conflict', 'call.spec')
        ref = spec['prompt_artifact']
        self.verify_artifact(spec['trial_id'], ref, routine)
        # The verified reference states the exact prompt digest and length.
        if ref['sha256'] != spec['input_sha256']:
            _fail('digest_mismatch', 'call.spec.input_sha256')
        if not ref['byte_count'] or ref['byte_count'] > exp['budgets']['max_prompt_bytes']:
            _fail('budget_exceeded', 'call.spec.prompt_artifact')
        return trial, frozen, team

    def calls(self, trial_id=None, experiment_id=None):
        if trial_id is not None:
            _id(trial_id, 'trial_id')
        if experiment_id is not None:
            _id(experiment_id, 'experiment_id')
        with self.connection() as db:
            rows = db.execute('SELECT calls.* FROM calls JOIN trials USING(trial_id) WHERE (? IS NULL OR calls.trial_id=?) AND (? IS NULL OR trials.experiment_id=?) ORDER BY calls.call_id',
                              (trial_id, trial_id, experiment_id, experiment_id))
            return [_unpack(row) for row in rows]

    def reserve_call(self, call_id, fingerprint, spec):
        _id(call_id, 'call_id')
        with self.connection(immediate=True) as db:
            trial, frozen, team = self._call_spec(db, spec, fingerprint)
            old = db.execute('SELECT * FROM calls WHERE call_id=?', (call_id,)).fetchone()
            if old is not None:
                return self._reuse(_unpack(old), fingerprint, spec)
            collision = db.execute('SELECT * FROM calls WHERE trial_id=? AND stage_key=? AND attempt_index=? AND component=?',
                                   (spec['trial_id'], spec['stage_key'], spec['attempt_index'], spec['component'])).fetchone()
            if collision is not None:
                _fail('fingerprint_conflict', 'call.reservation')
            if trial['status'] == 'terminated':
                _fail('state_conflict', 'trial.status')
            authorization = self._authorization(db, spec['authorization_sha256'])
            if authorization['trial_id'] != spec['trial_id'] or authorization['experiment_id'] != trial['experiment_id'] or authorization['evidence_sha256'] != spec['evidence_sha256'] or digest_bytes(canonical_bytes(spec['model'])) not in authorization['model_sha256s']:
                _fail('scope_mismatch', 'call.authorization_sha256')
            budget = frozen['experiment']['budgets']
            previous = [_unpack(r) for r in db.execute('SELECT * FROM calls WHERE trial_id=?', (spec['trial_id'],))]
            same_stage = [r for r in previous if r['spec']['stage_key'] == spec['stage_key'] and r['spec']['component'] == spec['component']]
            if same_stage and spec['attempt_index'] <= max(r['spec']['attempt_index'] for r in same_stage):
                _fail('attempt_conflict', 'call.spec.attempt_index')
            if any(r['status'] not in ('completed', 'failed') for r in previous
                   if r['spec']['stage_key'] == spec['stage_key']):
                _fail('previous_dispatch_unknown', 'call.reservation')
            if spec['attempt_index'] > budget['max_attempts_per_stage'] or len(previous) >= budget['max_calls_per_trial']:
                _fail('budget_exceeded', 'call.reservation')
            experiment = frozen['experiment']
            elapsed = sum(self.charge(r, 'seconds', experiment) for r in previous)
            if elapsed + spec['model']['timeout_seconds'] > budget['max_active_seconds_per_trial']:
                _fail('budget_exceeded', 'call.timeout_seconds')
            # Paid status follows the actual route, never the team's deployment label.
            # Each call reserves only its own worst case; a recorded provider cap is
            # additional external protection, not a local billing guarantee.
            paid = route_is_paid(spec['model'])
            bound = call_cost_bound(budget, spec['model'], experiment['pricing_snapshot']['rates'])
            if paid:
                if bound is None or 'max_api_cost_usd' not in budget:
                    _fail('unbounded_paid_route', 'call.api_cost_usd')
                used_cost = sum((Decimal(str(self.charge(r, 'cost', experiment))) for r in previous), Decimal(0))
                if used_cost + Decimal(str(bound)) > Decimal(str(budget['max_api_cost_usd'])):
                    _fail('budget_exceeded', 'call.api_cost_usd')
            stamp = _now()
            item = dict(call_id=call_id, fingerprint=fingerprint, spec=spec, status='reserved',
                        receipt=None, created_utc=stamp, updated_utc=stamp)
            data, sha = _encoded(item)
            db.execute('INSERT INTO calls VALUES (?,?,?,?,?,?,?,?)',
                       (call_id, spec['trial_id'], spec['stage_key'], spec['attempt_index'], spec['component'], 'reserved', data, sha))
            self.event('dispatch_reserved', 'model-adapter',
                       {'fingerprint': fingerprint, 'reserved_seconds': spec['model']['timeout_seconds'],
                        'reserved_api_cost_usd': bound, 'max_output_bytes': budget['max_response_bytes']},
                       experiment_id=trial['experiment_id'], trial_id=trial['trial_id'],
                       task_id=trial['task_mapping'][spec['stage_key']], call_id=call_id, db=db)
        return None

    @staticmethod
    def _reuse(old, fingerprint, spec):
        if old['fingerprint'] != fingerprint or old['spec'] != spec:
            _fail('fingerprint_conflict', 'reservation')
        if old['status'] in ('completed', 'failed'):
            return old['receipt']
        _fail('previous_dispatch_unknown', 'reservation')

    @staticmethod
    def charge(call, kind, experiment):
        """Budget charged to one call: measured when known, else its reserved worst case."""
        _choice(kind, ('seconds', 'cost'), 'charge.kind')
        receipt = call['receipt']
        if kind == 'seconds':
            if receipt is None or call['status'] == 'unknown' or receipt['elapsed_ms'] is None:
                return call['spec']['model']['timeout_seconds']
            return receipt['elapsed_ms'] / 1000.0
        if receipt is None or call['status'] == 'unknown' or receipt['cost']['api_cost_usd'] is None:
            bound = call_cost_bound(experiment['budgets'], call['spec']['model'],
                                    experiment['pricing_snapshot']['rates'])
            if bound is None:
                _fail('unbounded_paid_route', 'call.api_cost_usd')
            return bound
        return receipt['cost']['api_cost_usd']

    def _receipt(self, item, receipt, frozen, team):
        _fields(receipt, {'schema_version', 'call_id', 'fingerprint', 'status', 'model_requested',
                          'model_returned', 'identity_status', 'provider', 'deployment', 'role', 'stage_key',
                          'prompt_sha256', 'response_sha256', 'start_utc', 'end_utc', 'elapsed_ms',
                          'timeout_seconds', 'max_calls', 'max_output_bytes', 'finish_reason', 'usage',
                          'estimated_usage', 'cost', 'failure_reason', 'response_artifact'}, 'receipt',
                {'rejected_response'})
        spec = item['spec']
        if type(receipt['schema_version']) is not int or receipt['schema_version'] != 1:
            _fail('unsupported_schema', 'receipt.schema_version')
        _choice(receipt['status'], ('completed', 'failed', 'unknown'), 'receipt.status')
        _number(receipt['timeout_seconds'], 'receipt.timeout_seconds', positive=True)
        _number(receipt['max_calls'], 'receipt.max_calls', positive=True, integer=True)
        _number(receipt['max_output_bytes'], 'receipt.max_output_bytes', positive=True, integer=True)
        expected = {'call_id': item['call_id'], 'fingerprint': item['fingerprint'],
                    'model_requested': spec['model']['model_requested'], 'provider': spec['model']['provider'],
                    'deployment': team['deployment'], 'role': spec['role'], 'stage_key': spec['stage_key'],
                    'prompt_sha256': spec['input_sha256'], 'timeout_seconds': spec['model']['timeout_seconds'],
                    'max_calls': frozen['experiment']['budgets']['max_calls_per_trial'],
                    'max_output_bytes': frozen['experiment']['budgets']['max_response_bytes']}
        if any(receipt[k] != v for k, v in expected.items()):
            _fail('fingerprint_conflict', 'receipt')
        _text(receipt['model_returned'], 'receipt.model_returned', nullable=True)
        identity = 'unreported' if receipt['model_returned'] is None else ('reported_match' if receipt['model_returned'] in spec['model']['expected_model_ids'] else 'reported_mismatch')
        if receipt['identity_status'] != identity or (receipt['status'] == 'completed' and identity == 'reported_mismatch'):
            _fail('model_identity_mismatch', 'receipt.identity_status')
        if _time(receipt['end_utc'], 'receipt.end_utc') < _time(receipt['start_utc'], 'receipt.start_utc'):
            _fail('invalid_timestamp', 'receipt.end_utc')
        _number(receipt['elapsed_ms'], 'receipt.elapsed_ms',
                nullable=receipt['status'] != 'completed')
        if receipt['finish_reason'] is not None:
            _choice(receipt['finish_reason'], ('stop', 'length', 'end_turn', 'max_tokens',
                    'stop_sequence', 'content_filter', 'tool_calls', 'tool_use',
                    'function_call', 'pause_turn', 'refusal', 'eos_token'), 'receipt.finish_reason')
        if receipt['status'] == 'completed':
            if receipt['failure_reason'] is not None:
                _fail('invalid_choice', 'receipt.failure_reason')
        else:
            _choice(receipt['failure_reason'], FAILURES, 'receipt.failure_reason')
        for key in ('usage', 'estimated_usage'):
            _fields(receipt[key], TOKEN_FIELDS, 'receipt.' + key)
            for value in receipt[key].values():
                _number(value, 'receipt.' + key, integer=True, nullable=True)
            usage = receipt[key]
            for subset, total in (('cached_input_tokens', 'input_tokens'), ('reasoning_tokens', 'output_tokens')):
                if usage[subset] is not None and usage[total] is not None and usage[subset] > usage[total]:
                    _fail('invalid_usage', 'receipt.' + key)
        cost = receipt['cost']
        _fields(cost, {'api_cost_usd', 'pricing_snapshot_sha256', 'cost_basis', 'local_compute_cost_usd',
                       'local_energy_cost_usd', 'bound_exceeded'}, 'receipt.cost')
        for key in ('api_cost_usd', 'local_compute_cost_usd', 'local_energy_cost_usd'):
            _number(cost[key], 'receipt.cost.' + key, nullable=True)
        _choice(cost['cost_basis'], ('reported', 'computed', 'unknown'), 'receipt.cost.cost_basis')
        if cost['pricing_snapshot_sha256'] != digest_bytes(canonical_bytes(frozen['experiment']['pricing_snapshot'])):
            _fail('digest_mismatch', 'receipt.cost.pricing_snapshot_sha256')
        if (cost['cost_basis'] == 'unknown') != (cost['api_cost_usd'] is None):
            _fail('invalid_cost', 'receipt.cost')
        # A measured cost above the reserved worst case is flagged, never hidden.
        bound = call_cost_bound(frozen['experiment']['budgets'], spec['model'],
                                frozen['experiment']['pricing_snapshot']['rates'])
        exceeded = cost['api_cost_usd'] is not None and bound is not None and cost['api_cost_usd'] > bound
        if type(cost['bound_exceeded']) is not bool or cost['bound_exceeded'] != exceeded:
            _fail('invalid_cost', 'receipt.cost.bound_exceeded')
        if cost['cost_basis'] == 'computed':
            usage = receipt['usage']
            rates = [rate for rate in frozen['experiment']['pricing_snapshot']['rates']
                     if rate['provider'] == spec['model']['provider']
                     and rate['model_requested'] == spec['model']['model_requested']]
            if len(rates) != 1 or usage['input_tokens'] is None or usage['output_tokens'] is None:
                _fail('invalid_cost', 'receipt.cost')
            # Cached/reasoning counts are subsets, never additional billed tokens.
            expected_cost = (Decimal(str(rates[0]['input_per_million'])) * usage['input_tokens']
                             + Decimal(str(rates[0]['output_per_million'])) * usage['output_tokens']) / 1000000
            if not math.isclose(cost['api_cost_usd'], float(expected_cost), rel_tol=1e-12, abs_tol=1e-12):
                _fail('invalid_cost', 'receipt.cost.api_cost_usd')
        _digest(receipt['response_sha256'], 'receipt.response_sha256', nullable=True)
        if receipt['response_artifact'] is not None:
            data = self.read_artifact(spec['trial_id'], receipt['response_artifact'])
            if digest_bytes(data) != receipt['response_sha256']:
                _fail('digest_mismatch', 'receipt.response_sha256')
            if len(data) > receipt['max_output_bytes']:
                _fail('budget_exceeded', 'receipt.response_artifact')
            if receipt['status'] == 'completed' and spec['component'] == 'narrative':
                evidence = next(case['evidence'] for case in frozen['cases']
                                if case['scenario']['evidence_manifest_sha256'] == spec['evidence_sha256'])
                validate_stage_output(decode_json(data), spec['stage_key'], evidence)
            elif receipt['status'] == 'completed' and not data:
                _fail('empty_response', 'receipt.response_artifact')
        elif receipt['response_sha256'] is not None or receipt['status'] == 'completed':
            _fail('incomplete_receipt', 'receipt.response_artifact')
        if 'rejected_response' in receipt:
            self._rejected_response(spec, receipt)
        _safe(receipt)

    def _rejected_response(self, spec, receipt):
        """A failed narrative answer kept for diagnostics only: never a response."""
        rejected = receipt['rejected_response']
        field = 'receipt.rejected_response'
        _fields(rejected, {'error_code', 'error_field', 'artifact', 'byte_count', 'truncated'}, field)
        if (spec['component'] != 'narrative' or receipt['status'] != 'failed'
                or receipt['failure_reason'] not in REJECTED_RESPONSE_FAILURES
                or receipt['response_artifact'] is not None):
            _fail('scope_mismatch', field)
        for key in ('error_code', 'error_field'):
            if type(rejected[key]) is not str or not re.fullmatch(r'[a-z][a-z0-9_.]{0,127}', rejected[key]):
                _fail('invalid_identifier', field + '.' + key)
        _number(rejected['byte_count'], field + '.byte_count', integer=True)
        if type(rejected['truncated']) is not bool:
            _fail('invalid_boolean', field + '.truncated')
        maximum = receipt['max_output_bytes']
        if rejected['truncated'] != (rejected['byte_count'] > maximum):
            _fail('invalid_rejected_response', field + '.truncated')
        if rejected['artifact'] is None:
            if rejected['byte_count'] != 0:
                _fail('incomplete_receipt', field + '.artifact')
            return
        data = self.read_artifact(spec['trial_id'], rejected['artifact'])
        if rejected['byte_count'] == 0 or len(data) != min(rejected['byte_count'], maximum):
            _fail('invalid_rejected_response', field + '.byte_count')

    def finish_call(self, call_id, receipt):
        _id(call_id, 'call_id')
        with self.connection(immediate=True) as db:
            item = _unpack(db.execute('SELECT * FROM calls WHERE call_id=?', (call_id,)).fetchone())
            trial, frozen, team = self._call_spec(db, item['spec'], item['fingerprint'])
            self._receipt(item, receipt, frozen, team)
            if item['status'] != 'reserved':
                _fail('state_conflict', 'call.status')
            self._finish_call(db, item, receipt, trial, 'model-adapter')
        return receipt

    def _finish_call(self, db, item, receipt, trial, actor):
        old_status = item['status']
        item = dict(item, status=receipt['status'], receipt=receipt, updated_utc=_now())
        data, sha = _encoded(item)
        changed = db.execute('UPDATE calls SET status=?,data=?,sha256=? WHERE call_id=? AND status=?',
                             (item['status'], data, sha, item['call_id'], old_status))
        if changed.rowcount != 1:
            _fail('state_conflict', 'call.status')
        self.event('dispatch_unknown' if item['status'] == 'unknown' else 'dispatch_finished', actor,
                   {'fingerprint': item['fingerprint'], 'status': item['status'], 'receipt_sha256': digest_bytes(canonical_bytes(receipt))},
                   experiment_id=trial['experiment_id'], trial_id=trial['trial_id'], call_id=item['call_id'],
                   task_id=trial['task_mapping'][item['spec']['stage_key']], db=db)

    def reconcile_call(self, call_id, by, note, outcome, evidence, receipt):
        _id(call_id, 'call_id')
        human_actor(by)
        _text(note, 'reconciliation.note')
        _choice(outcome, ('failed', 'completed'), 'reconciliation.outcome')
        with self.connection(immediate=True) as db:
            item = _unpack(db.execute('SELECT * FROM calls WHERE call_id=?', (call_id,)).fetchone())
            if item['status'] not in ('reserved', 'unknown'):
                _fail('state_conflict', 'call.status')
            self.read_artifact(item['spec']['trial_id'], evidence)
            trial, frozen, team = self._call_spec(db, item['spec'], item['fingerprint'])
            self._receipt(item, receipt, frozen, team)
            if receipt['status'] != outcome:
                _fail('scope_mismatch', 'reconciliation.outcome')
            self._finish_call(db, item, receipt, trial, by)
            self.event('reconciliation_recorded', by, {'policy': HUMAN_RECONCILE_POLICY, 'note': note,
                       'outcome': outcome, 'evidence': evidence,
                       'receipt_sha256': digest_bytes(canonical_bytes(receipt))}, experiment_id=trial['experiment_id'],
                       trial_id=trial['trial_id'], call_id=call_id, db=db)
        return receipt

    def auto_reconcile_call(self, call_id, note, evidence, receipt, process_check):
        """Resolve an uncertain model call as failed automatically; never a human action.

        Only model calls qualify: their sole effect is local compute and cost, and
        the caller has confirmed from the ledger that the owning child process
        ended. Campaign steps live in another table and are never resolved here.
        The receipt carries no measurement (elapsed, usage, cost and response are
        null), so the reserved worst case stays charged and any late output is
        discarded. Returns the recorded event payload.
        """
        _id(call_id, 'call_id')
        _text(note, 'reconciliation.note')
        _process_check(process_check)
        with self.connection(immediate=True) as db:
            item = _unpack(db.execute('SELECT * FROM calls WHERE call_id=?', (call_id,)).fetchone())
            if item['status'] not in ('reserved', 'unknown'):
                _fail('state_conflict', 'call.status')
            self.read_artifact(item['spec']['trial_id'], evidence)
            trial, frozen, team = self._call_spec(db, item['spec'], item['fingerprint'])
            self._receipt(item, receipt, frozen, team)
            prior = item['receipt']
            if (receipt['status'] != 'failed' or receipt['elapsed_ms'] is not None
                    or receipt['response_artifact'] is not None or receipt['finish_reason'] is not None
                    or 'rejected_response' in receipt
                    or receipt['cost']['api_cost_usd'] is not None or receipt['model_returned'] is not None
                    or any(value is not None for key in ('usage', 'estimated_usage')
                           for value in receipt[key].values())
                    or receipt['failure_reason'] != (prior['failure_reason'] if prior else 'dispatch_interrupted')):
                _fail('measurement_not_discarded', 'reconciliation.receipt')
            experiment = frozen['experiment']
            settled = dict(item, status='failed', receipt=receipt)
            payload = {'policy': AUTO_RECONCILE_POLICY, 'note': note, 'outcome': 'failed', 'evidence': evidence,
                       'receipt_sha256': digest_bytes(canonical_bytes(receipt)),
                       'prior_status': item['status'],
                       'prior_failure_reason': prior['failure_reason'] if prior else None,
                       'observed_elapsed_ms': prior['elapsed_ms'] if prior else None,
                       'timeout_seconds': item['spec']['model']['timeout_seconds'],
                       'charged_seconds': self.charge(settled, 'seconds', experiment),
                       'charged_api_cost_usd': self.charge(settled, 'cost', experiment),
                       'process_check': process_check}
            self._finish_call(db, item, receipt, trial, AUTO_RECONCILE_ACTOR)
            self.event('reconciliation_recorded', AUTO_RECONCILE_ACTOR, payload,
                       experiment_id=trial['experiment_id'], trial_id=trial['trial_id'],
                       task_id=trial['task_mapping'][item['spec']['stage_key']], call_id=call_id, db=db)
        return payload

    def record_automatic_retry(self, call_id, note, process_check):
        """Schedule the next attempt after a known, model-attributable call failure.

        Not a reconciliation (the outcome and receipt are known and kept) and
        never a human action: one `trial_status_changed` event by
        `benchmark-auto-retry` with `policy: automatic_retry`, committed with the
        trial's return to `ready`. Idempotent per failed call. Returns the payload.
        """
        _id(call_id, 'call_id')
        _text(note, 'retry.note')
        _process_check(process_check)
        with self.connection(immediate=True) as db:
            item = _unpack(db.execute('SELECT * FROM calls WHERE call_id=?', (call_id,)).fetchone())
            if item['status'] != 'failed' or item['receipt'] is None:
                _fail('state_conflict', 'call.status')
            _choice(item['spec']['component'], MODEL_COMPONENTS, 'call.spec.component')
            reason = item['receipt']['failure_reason']
            if reason not in RETRYABLE_FAILURES:
                _fail('not_retryable', 'call.failure_reason')
            for row in db.execute("SELECT * FROM events WHERE call_id=? AND kind='trial_status_changed'", (call_id,)):
                existing = _unpack(row)
                if existing['payload'].get('policy') == AUTO_RETRY_POLICY:
                    return existing['payload']
            old = _unpack(db.execute('SELECT * FROM trials WHERE trial_id=?', (item['spec']['trial_id'],)).fetchone())
            if old['status'] == 'terminated':
                _fail('state_conflict', 'trial.status')
            spec = dict(old, status='ready')
            self._trial(spec, db)
            data, sha = _encoded(spec)
            db.execute('UPDATE trials SET status=?,data=?,sha256=? WHERE trial_id=?', ('ready', data, sha, old['trial_id']))
            payload = {'policy': AUTO_RETRY_POLICY, 'previous_status': old['status'], 'trial_status': 'ready',
                       'snapshot_sha256': sha, 'note': note, 'stage_key': item['spec']['stage_key'],
                       'component': item['spec']['component'],
                       'failed_attempt_index': item['spec']['attempt_index'], 'failure_reason': reason,
                       'receipt_sha256': digest_bytes(canonical_bytes(item['receipt'])),
                       'process_check': process_check}
            self.event('trial_status_changed', AUTO_RETRY_ACTOR, payload, experiment_id=old['experiment_id'],
                       trial_id=old['trial_id'], task_id=old['task_mapping'][item['spec']['stage_key']],
                       call_id=call_id, db=db)
        return payload

    def _auto_advance_payload(self, trial_id, payload):
        _fields(payload, AUTO_ADVANCE_FIELDS, 'auto_advance')
        _choice(payload['stage_key'], STAGE_KEYS, 'auto_advance.stage_key')
        for key in ('attempt_index', 'ledger_event_id', 'ledger_submit_event_id'):
            _number(payload[key], 'auto_advance.' + key, positive=True, integer=True)
        if payload['ledger_event_id'] <= payload['ledger_submit_event_id']:
            _fail('scope_mismatch', 'auto_advance.ledger_event_id')
        for key in ('ledger_event_sha256', 'output_sha256'):
            _digest(payload[key], 'auto_advance.' + key)
        _digest(payload['checker_receipt_sha256'], 'auto_advance.checker_receipt_sha256', nullable=True)
        _choice(payload['review_policy'], (REVIEW_POLICY,), 'auto_advance.review_policy')
        data = self.read_artifact(trial_id, payload['output_artifact'])
        if digest_bytes(data) != payload['output_sha256']:
            _fail('digest_mismatch', 'auto_advance.output_sha256')
        validate_stage_output(decode_json(data), payload['stage_key'])
        if payload['checker_artifact'] is not None:
            self.read_artifact(trial_id, payload['checker_artifact'])

    def record_auto_advance(self, trial_id, call_id, payload):
        """Mirror one ledger `auto_advance`: an unreviewed advance, never a human decision.

        Idempotent per ledger event, so a crash between the ledger commit and
        this one is completed by mirroring the same event, never a second advance.
        """
        _id(trial_id, 'auto_advance.trial_id')
        _id(call_id, 'auto_advance.call_id')
        self._auto_advance_payload(trial_id, payload)
        with self.connection(immediate=True) as db:
            trial = _unpack(db.execute('SELECT * FROM trials WHERE trial_id=?', (trial_id,)).fetchone())
            call = _unpack(db.execute('SELECT * FROM calls WHERE call_id=?', (call_id,)).fetchone())
            spec = call['spec']
            if (spec['trial_id'] != trial_id or spec['stage_key'] != payload['stage_key']
                    or spec['component'] != 'narrative' or spec['attempt_index'] != payload['attempt_index']
                    or call['status'] != 'completed'
                    or call['receipt']['response_sha256'] != payload['output_sha256']):
                _fail('scope_mismatch', 'auto_advance.call_id')
            existing = [event for event in (_unpack(row) for row in db.execute(
                'SELECT * FROM events WHERE trial_id=? AND kind=?', (trial_id, 'stage_auto_advanced')))
                        if event['payload'].get('ledger_event_id') == payload['ledger_event_id']
                        or (event['payload'].get('stage_key') == payload['stage_key']
                            and event['payload'].get('ledger_submit_event_id') == payload['ledger_submit_event_id'])]
            if any(event['payload'] != payload or event['call_id'] != call_id for event in existing):
                _fail('fingerprint_conflict', 'auto_advance.ledger_event_id')
            if existing:
                return existing[0]
            return self.event('stage_auto_advanced', AUTO_ADVANCE_ACTOR, payload,
                              experiment_id=trial['experiment_id'], trial_id=trial_id,
                              task_id=trial['task_mapping'][payload['stage_key']], call_id=call_id, db=db)

    def write_evaluator_artifact(self, kind, content):
        """Private immutable scoring inputs; writing is not a truth-freeze decision."""
        _choice(kind, ('truth', 'adjudication'), 'evaluator.kind')
        if type(content) is not bytes:
            _fail('invalid_bytes', 'evaluator')
        decode_json(content)
        sha = digest_bytes(content)
        try:
            self._private_directory('evaluator/' + kind)
            _publish(self.root, 'evaluator/' + kind + '/' + sha + '.json', content, 'evaluator')
        except OSError:
            _fail('artifact_unavailable', 'evaluator')
        return sha

    def read_evaluator_artifact(self, kind, sha):
        _choice(kind, ('truth', 'adjudication'), 'evaluator.kind')
        _digest(sha, 'evaluator.sha256')
        try:
            content = confined_file(self.root, 'evaluator/' + kind + '/' + sha + '.json').read_bytes()
        except OSError:
            _fail('artifact_unavailable', 'evaluator')
        if digest_bytes(content) != sha:
            _fail('artifact_corrupt', 'evaluator.sha256')
        return content

    def freeze_truths(self, experiment_id, truths):
        """Automatic truth freeze under the same write lock as call reservations."""
        _id(experiment_id, 'experiment_id')
        with self.connection(immediate=True) as db:
            return self._freeze_truths(db, experiment_id, truths)

    def _freeze_truths(self, db, experiment_id, truths):
        """Validate and retain evaluator bytes before any call reservation, never posthoc.

        Recorded as an automatic freeze, never as a human attestation; whether a
        key was human-attested stays the truth's own `attestation` field.
        """
        frozen = _unpack(db.execute('SELECT * FROM experiments WHERE experiment_id=?',
                                   (experiment_id,)).fetchone())
        cases = {case['evidence']['case_id']: case for case in frozen['cases']}
        _fields(truths, cases, 'truth.cases')
        records = []
        for case_id in sorted(cases):
            content = truths[case_id]
            if type(content) is not bytes:
                _fail('invalid_bytes', 'truth')
            truth = decode_json(content)
            validate_truth(truth, cases[case_id]['evidence'])
            if truth['attack_release'] != cases[case_id]['scenario']['attack_release']:
                _fail('scope_mismatch', 'truth.attack_release')
            sha = digest_bytes(content)
            records.append({'case_id': case_id, 'truth_sha256': sha,
                            'truth_revision': truth['truth_revision'],
                            'evidence_manifest_sha256': truth['evidence_manifest_sha256'],
                            'private_path': 'evaluator/truth/' + sha + '.json',
                            'byte_count': len(content)})
        previous = [_unpack(row) for row in db.execute(
            "SELECT * FROM events WHERE experiment_id=? AND kind='evidence_sealed'",
            (experiment_id,))]
        previous = [event for event in previous
                    if event['payload'].get('record_type') == 'truth_frozen']
        if previous:
            if len(previous) != 1 or previous[0]['payload']['cases'] != records:
                _fail('fingerprint_conflict', 'truth.frozen')
            self._verify_truth_freeze(previous[0], frozen)
            return previous[0]
        if db.execute('SELECT 1 FROM calls JOIN trials USING(trial_id) '
                      'WHERE trials.experiment_id=? LIMIT 1', (experiment_id,)).fetchone():
            _fail('truth_freeze_too_late', 'truth')
        for record in records:
            self.write_evaluator_artifact('truth', truths[record['case_id']])
        return self.event('evidence_sealed', AUTO_FREEZE_ACTOR, {
            'record_type': 'truth_frozen', 'rubric_version': frozen['experiment']['rubric_version'],
            'by': AUTO_FREEZE_ACTOR, 'note': AUTO_FREEZE_NOTE, 'freeze_policy': FREEZE_POLICY,
            'cases': records,
        }, experiment_id=experiment_id, db=db)

    def _verify_truth_freeze(self, event, frozen, verify_content=True):
        payload = event['payload']
        _fields(payload, {'record_type', 'rubric_version', 'by', 'note', 'freeze_policy', 'cases'}, 'truth.freeze')
        if (event['kind'] != 'evidence_sealed' or payload['record_type'] != 'truth_frozen'
                or payload['rubric_version'] != frozen['experiment']['rubric_version']
                or event['actor'] != AUTO_FREEZE_ACTOR or payload['by'] != AUTO_FREEZE_ACTOR
                or payload['note'] != AUTO_FREEZE_NOTE or payload['freeze_policy'] != FREEZE_POLICY):
            _fail('scope_mismatch', 'truth.freeze')
        cases = {case['evidence']['case_id']: case for case in frozen['cases']}
        if type(payload['cases']) is not list or len(payload['cases']) != len(cases):
            _fail('incomplete_snapshot', 'truth.cases')
        seen = set()
        for record in payload['cases']:
            _fields(record, {'case_id', 'truth_sha256', 'truth_revision',
                             'evidence_manifest_sha256', 'private_path', 'byte_count'}, 'truth.freeze')
            case_id = record['case_id']
            if case_id not in cases or case_id in seen:
                _fail('scope_mismatch', 'truth.case_id')
            seen.add(case_id)
            _digest(record['truth_sha256'], 'truth.sha256')
            _number(record['byte_count'], 'truth.byte_count', integer=True)
            _number(record['truth_revision'], 'truth.truth_revision', positive=True, integer=True)
            if record['evidence_manifest_sha256'] != cases[case_id]['scenario']['evidence_manifest_sha256']:
                _fail('scope_mismatch', 'truth.evidence_manifest_sha256')
            if record['private_path'] != 'evaluator/truth/' + record['truth_sha256'] + '.json':
                _fail('unsafe_path', 'truth.private_path')
            if not verify_content:
                continue
            try:
                path = confined_file(self.root, record['private_path'])
                if path.stat().st_size != record['byte_count']:
                    _fail('artifact_corrupt', 'truth.byte_count')
                content = path.read_bytes()
            except OSError:
                _fail('artifact_unavailable', 'truth')
            if digest_bytes(content) != record['truth_sha256']:
                _fail('artifact_corrupt', 'truth.sha256')
            truth = decode_json(content)
            validate_truth(truth, cases[case_id]['evidence'])
            if (truth['truth_revision'] != record['truth_revision']
                    or truth['evidence_manifest_sha256'] != record['evidence_manifest_sha256']
                    or truth['attack_release'] != cases[case_id]['scenario']['attack_release']):
                _fail('scope_mismatch', 'truth.freeze')

    def record_score(self, trial_id, output_sha256, score, actor, db=None):
        _id(trial_id, 'trial_id')
        _digest(output_sha256, 'score.output_sha256', nullable=True)
        if type(score) is not dict:
            _fail('invalid_object', 'score')
        _safe(score)
        if db is None:
            with self.connection(immediate=True) as connection:
                return self.record_score(trial_id, output_sha256, score, actor, db=connection)
        if actor != 'benchmark-scorer':
            _fail('scope_mismatch', 'score.actor')
        trial = _unpack(db.execute('SELECT * FROM trials WHERE trial_id=?', (trial_id,)).fetchone())
        # Every score is the validated scoring envelope bound to sealed outputs. Import
        # locally so the ordinary store has no scorer dependency.
        from benchmark_adjudication import validate_score_binding
        validate_score_binding(self, trial, output_sha256, score)
        return self.event('score_recorded', actor, {'output_sha256': output_sha256, 'score': score},
                          experiment_id=trial['experiment_id'], trial_id=trial_id, db=db)

    def _campaign_state(self, spec):
        _fields(spec, {'schema_version', 'campaign_id', 'experiment_id', 'manifest',
                       'manifest_sha256', 'status', 'cleanup_status', 'owned_process',
                       'created_utc', 'updated_utc'}, 'campaign')
        if type(spec['schema_version']) is not int or spec['schema_version'] != 1:
            _fail('unsupported_schema', 'campaign.schema_version')
        _id(spec['campaign_id'], 'campaign.campaign_id')
        _id(spec['experiment_id'], 'campaign.experiment_id', nullable=True)
        _digest(spec['manifest_sha256'], 'campaign.manifest_sha256')
        manifest = spec['manifest']
        _fields(manifest, {'schema_version', 'campaign_id', 'recipe_id', 'range_kit_sha256',
                           'targets', 'executor', 'collectors', 'limits', 'authorization'}, 'campaign.manifest')
        if type(manifest['schema_version']) is not int or manifest['schema_version'] != 1:
            _fail('unsupported_schema', 'campaign.manifest.schema_version')
        if manifest['campaign_id'] != spec['campaign_id']:
            _fail('scope_mismatch', 'campaign.manifest.campaign_id')
        _id(manifest['recipe_id'], 'campaign.manifest.recipe_id')
        _digest(manifest['range_kit_sha256'], 'campaign.manifest.range_kit_sha256')
        if type(manifest['targets']) is not list or not manifest['targets']:
            _fail('invalid_array', 'campaign.manifest.targets')
        if type(manifest['collectors']) is not list or type(manifest['executor']) is not dict:
            _fail('invalid_object', 'campaign.manifest')
        limits = manifest['limits']
        _fields(limits, {'max_phase_seconds', 'max_campaign_seconds', 'max_export_bytes',
                         'max_cloud_cost_usd', 'latest_cleanup_utc'}, 'campaign.manifest.limits')
        for key in ('max_phase_seconds', 'max_campaign_seconds', 'max_export_bytes'):
            _number(limits[key], 'campaign.manifest.limits.' + key, positive=True, integer=True)
        _number(limits['max_cloud_cost_usd'], 'campaign.manifest.limits.max_cloud_cost_usd', positive=True, nullable=True)
        _time(limits['latest_cleanup_utc'], 'campaign.manifest.limits.latest_cleanup_utc')
        if campaign_manifest_digest(manifest) != spec['manifest_sha256']:
            _fail('digest_mismatch', 'campaign.manifest_sha256')
        _choice(spec['status'], ('draft', 'preflight_passed', 'authorized', 'running',
                                'awaiting_collection', 'awaiting_release', 'evidence_ready',
                                'blocked', 'failed', 'unknown'), 'campaign.status')
        _choice(spec['cleanup_status'], ('not_needed', 'pending', 'running', 'succeeded',
                                        'failed', 'unknown'), 'campaign.cleanup_status')
        if _time(spec['updated_utc'], 'campaign.updated_utc') < _time(spec['created_utc'], 'campaign.created_utc'):
            _fail('invalid_timestamp', 'campaign.updated_utc')
        if spec['owned_process'] is not None:
            _fields(spec['owned_process'], {'pid', 'creation_utc', 'process_group_id'}, 'campaign.owned_process')
            _number(spec['owned_process']['pid'], 'campaign.owned_process.pid', positive=True, integer=True)
            group = spec['owned_process']['process_group_id']
            if type(group) is not str or not 1 <= len(group) <= 256 or any(ord(c) < 32 for c in group):
                _fail('invalid_identifier', 'campaign.owned_process.process_group_id')
            created = spec['owned_process']['creation_utc']
            if (type(created) is not str or not re.fullmatch(
                    r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,7})?(?:Z|\+00:00)', created)):
                _fail('invalid_timestamp', 'campaign.owned_process.creation_utc')
            parse_utc(created, 'campaign.owned_process.creation_utc')
        _safe(spec)

    def create_campaign(self, spec):
        """Freeze metadata only; recipe validation/dispatch belongs to the controller."""
        self._campaign_state(spec)
        if spec['status'] != 'draft' or spec['cleanup_status'] != 'not_needed' or spec['owned_process'] is not None:
            _fail('state_conflict', 'campaign.status')
        with self.connection(immediate=True) as db:
            if db.execute('SELECT 1 FROM campaign_state WHERE campaign_id=?', (spec['campaign_id'],)).fetchone():
                _fail('already_exists', 'campaign_id')
            data, sha = _encoded(spec)
            db.execute('INSERT INTO campaign_state VALUES (?,?,?,?,?,?)',
                       (spec['campaign_id'], spec['experiment_id'], spec['status'], spec['cleanup_status'], data, sha))
            self.event('campaign_preflight', 'campaign-controller',
                       {'record_type': 'campaign_registered', 'status': 'draft', 'snapshot_sha256': sha},
                       experiment_id=spec['experiment_id'], campaign_id=spec['campaign_id'], db=db)
        return spec

    def get_campaign(self, campaign_id):
        _id(campaign_id, 'campaign_id')
        with self.connection() as db:
            spec = _unpack(db.execute('SELECT * FROM campaign_state WHERE campaign_id=?', (campaign_id,)).fetchone())
            self._campaign_state(spec)
            return spec

    def request_campaign_stop(self, campaign_id):
        """Atomically quarantine dispatch and capture the latest owned identity."""
        _id(campaign_id, 'campaign_id')
        with self.connection(immediate=True) as db:
            old = _unpack(db.execute('SELECT * FROM campaign_state WHERE campaign_id=?',
                                    (campaign_id,)).fetchone())
            self._campaign_state(old)
            cleanup = ('unknown' if old['cleanup_status'] in ('pending', 'running')
                       else old['cleanup_status'])
            stopped = dict(old, status='unknown', cleanup_status=cleanup, updated_utc=_now())
            data, sha = _encoded(stopped)
            db.execute('UPDATE campaign_state SET status=?,cleanup_status=?,data=?,sha256=? '
                       'WHERE campaign_id=?', ('unknown', cleanup, data, sha, campaign_id))
            self.event('campaign_status_changed', 'campaign-controller', {
                'record_type': 'campaign_stop_requested',
                'previous_status': old['status'],
                'previous_cleanup_status': old['cleanup_status'],
                'owned_process': old['owned_process'], 'snapshot_sha256': sha,
            }, experiment_id=old['experiment_id'], campaign_id=campaign_id, db=db)
        return stopped, old['owned_process']

    def reconcile_campaign_state(self, campaign_id, expected_status, by, note, evidence):
        """Restore collection only after explicit, evidence-backed effect inspection.

        This cannot restore execution authority or retry any reserved action.
        Each uncertain dispatch must first have its own terminal reconciliation.
        """
        _id(campaign_id, 'campaign_id')
        human_actor(by)  # campaign effects are real: never resolved by automation
        _text(note, 'reconciliation.note')
        if type(evidence) is not bytes or not evidence:
            _fail('evidence_required', 'reconciliation.evidence')
        facts = decode_json(evidence)
        _safe(facts)
        with self.connection(immediate=True) as db:
            old = _unpack(db.execute('SELECT * FROM campaign_state WHERE campaign_id=?',
                                    (campaign_id,)).fetchone())
            if old['status'] != expected_status or old['status'] not in ('blocked', 'failed', 'unknown'):
                _fail('state_conflict', 'campaign.status')
            if old['owned_process'] is not None:
                _fail('process_inspection_required', 'campaign.owned_process')
            steps = [_unpack(row) for row in db.execute(
                'SELECT * FROM campaigns WHERE campaign_id=?', (campaign_id,))]
            if (not any(item['phase'] in ('run', 'warmup', 'detonate') for item in steps)
                    or any(item['status'] in ('reserved', 'unknown') for item in steps)):
                _fail('reconciliation_required', 'campaign.steps')
            restored = dict(old, status='awaiting_collection', updated_utc=_now())
            self._campaign_state(restored)
            data, sha = _encoded(restored)
            changed = db.execute('UPDATE campaign_state SET status=?,data=?,sha256=? '
                                 'WHERE campaign_id=? AND status=?',
                                 (restored['status'], data, sha, campaign_id, expected_status))
            if changed.rowcount != 1:
                _fail('state_conflict', 'campaign.status')
            self.event('reconciliation_recorded', by, {
                'record_type': 'campaign_collection_recovery', 'note': note,
                'previous_status': expected_status, 'status': restored['status'],
                'evidence_sha256': digest_bytes(evidence), 'evidence': facts,
                'snapshot_sha256': sha,
            }, experiment_id=old['experiment_id'], campaign_id=campaign_id, db=db)
        return restored

    def update_campaign(self, campaign_id, spec, expected_status, expected_cleanup_status):
        """Compare-and-swap lifecycle and independent cleanup state, without actions."""
        _id(campaign_id, 'campaign_id')
        self._campaign_state(spec)
        if spec['campaign_id'] != campaign_id:
            _fail('scope_mismatch', 'campaign_id')
        with self.connection(immediate=True) as db:
            old = _unpack(db.execute('SELECT * FROM campaign_state WHERE campaign_id=?', (campaign_id,)).fetchone())
            if old['status'] != expected_status or old['cleanup_status'] != expected_cleanup_status:
                _fail('state_conflict', 'campaign.status')
            if any(old[key] != spec[key] for key in ('schema_version', 'campaign_id', 'experiment_id',
                                                    'manifest', 'manifest_sha256', 'created_utc')):
                _fail('fingerprint_conflict', 'campaign')
            if old['owned_process'] != spec['owned_process']:
                # Only record_owned_process/clear_owned_process change process ownership.
                _fail('state_conflict', 'campaign.owned_process')
            if _time(spec['updated_utc'], 'campaign.updated_utc') < _time(old['updated_utc'], 'campaign.updated_utc'):
                _fail('invalid_timestamp', 'campaign.updated_utc')
            transitions = {'draft': ('preflight_passed',), 'preflight_passed': ('authorized',),
                           'authorized': ('running',), 'running': ('awaiting_collection',),
                           'awaiting_collection': ('awaiting_release',),
                           'awaiting_release': ('evidence_ready',), 'evidence_ready': (),
                           'blocked': (), 'failed': (), 'unknown': ()}
            if spec['status'] != old['status'] and spec['status'] not in transitions[old['status']] + ('blocked', 'failed', 'unknown'):
                _fail('state_conflict', 'campaign.status')
            cleanup = {'not_needed': ('pending',), 'pending': ('running', 'failed', 'unknown'),
                       'running': ('succeeded', 'failed', 'unknown'), 'succeeded': (),
                       'failed': ('running', 'unknown'), 'unknown': ('succeeded', 'failed')}
            if spec['cleanup_status'] != old['cleanup_status'] and spec['cleanup_status'] not in cleanup[old['cleanup_status']]:
                _fail('state_conflict', 'campaign.cleanup_status')
            data, sha = _encoded(spec)
            cursor = db.execute('UPDATE campaign_state SET status=?,cleanup_status=?,data=?,sha256=? WHERE campaign_id=? AND status=? AND cleanup_status=?',
                                (spec['status'], spec['cleanup_status'], data, sha, campaign_id, expected_status, expected_cleanup_status))
            if cursor.rowcount != 1:
                _fail('state_conflict', 'campaign.status')
            self.event('campaign_status_changed', 'campaign-controller',
                       {'record_type': 'campaign_state', 'previous_status': old['status'],
                        'status': spec['status'], 'previous_cleanup_status': old['cleanup_status'],
                        'cleanup_status': spec['cleanup_status'], 'snapshot_sha256': sha},
                       experiment_id=spec['experiment_id'], campaign_id=campaign_id, db=db)
        return spec

    def _set_owned_process(self, db, old, identity):
        updated = dict(old, owned_process=identity, updated_utc=_now())
        self._campaign_state(updated)
        data, sha = _encoded(updated)
        changed = db.execute('UPDATE campaign_state SET data=?,sha256=? WHERE campaign_id=? AND sha256=?',
                             (data, sha, old['campaign_id'], digest_bytes(canonical_bytes(old))))
        if changed.rowcount != 1:
            _fail('state_conflict', 'campaign.owned_process')
        return updated, sha

    def record_owned_process(self, campaign_id, phase, step_id, identity):
        """Persist the exact local process identity of one reserved step before dispatch."""
        _id(campaign_id, 'campaign_id')
        _id(step_id, 'step_id')
        _choice(phase, ('preflight', 'run', 'stop', 'collect', 'cleanup', 'warmup', 'detonate'), 'campaign.phase')
        with self.connection(immediate=True) as db:
            old = _unpack(db.execute('SELECT * FROM campaign_state WHERE campaign_id=?', (campaign_id,)).fetchone())
            self._campaign_state(old)
            if old['owned_process'] is not None:
                if old['owned_process'] == identity:
                    return old
                _fail('state_conflict', 'campaign.owned_process')
            step = _unpack(db.execute('SELECT * FROM campaigns WHERE campaign_id=? AND phase=? AND step_id=?',
                                      (campaign_id, phase, step_id)).fetchone())
            if step['status'] != 'reserved':
                _fail('state_conflict', 'campaign.step')
            if type(identity) is not dict:
                _fail('invalid_object', 'campaign.owned_process')
            updated, sha = self._set_owned_process(db, old, identity)
            self.event('process_started', 'campaign-controller',
                       {'phase': phase, 'step_id': step_id, 'process_identity': identity,
                        'snapshot_sha256': sha},
                       experiment_id=old['experiment_id'], campaign_id=campaign_id, db=db)
        return updated

    def clear_owned_process(self, campaign_id, step_id, local_stopped_evidence):
        """Clear ownership only on verified local teardown; remote effects stay unknown."""
        _id(campaign_id, 'campaign_id')
        _id(step_id, 'step_id')
        evidence = local_stopped_evidence
        _fields(evidence, {'local_stopped', 'source', 'remote_effects'}, 'process_stopped.evidence')
        if evidence['local_stopped'] is not True:
            _fail('process_not_stopped', 'process_stopped.evidence.local_stopped')
        _choice(evidence['source'], PROCESS_STOP_SOURCES, 'process_stopped.evidence.source')
        _choice(evidence['remote_effects'], ('unknown',), 'process_stopped.evidence.remote_effects')
        with self.connection(immediate=True) as db:
            old = _unpack(db.execute('SELECT * FROM campaign_state WHERE campaign_id=?', (campaign_id,)).fetchone())
            self._campaign_state(old)
            if old['owned_process'] is None:
                _fail('state_conflict', 'campaign.owned_process')
            if not db.execute('SELECT 1 FROM campaigns WHERE campaign_id=? AND step_id=?',
                              (campaign_id, step_id)).fetchone():
                _fail('not_found', 'campaign.step_id')
            updated, sha = self._set_owned_process(db, old, None)
            self.event('process_stopped', 'campaign-controller',
                       {'step_id': step_id, 'process_identity': old['owned_process'],
                        'evidence': evidence, 'snapshot_sha256': sha},
                       experiment_id=old['experiment_id'], campaign_id=campaign_id, db=db)
        return updated

    def _campaign_spec(self, spec, fingerprint):
        _fields(spec, {'schema_version', 'experiment_id', 'manifest_sha256', 'authorization_sha256',
                       'executor_sha256', 'executor_version', 'input_sha256', 'target_sha256', 'timeout_seconds'}, 'campaign.spec')
        if type(spec['schema_version']) is not int or spec['schema_version'] != 1:
            _fail('unsupported_schema', 'campaign.spec.schema_version')
        _id(spec['experiment_id'], 'campaign.spec.experiment_id', nullable=True)
        _text(spec['executor_version'], 'campaign.spec.executor_version')
        for field in ('manifest_sha256', 'authorization_sha256', 'executor_sha256', 'input_sha256', 'target_sha256'):
            _digest(spec[field], 'campaign.spec.' + field)
        _number(spec['timeout_seconds'], 'campaign.spec.timeout_seconds', positive=True)
        _digest(fingerprint, 'campaign.fingerprint')
        if digest_bytes(canonical_bytes(spec)) != fingerprint:
            _fail('fingerprint_conflict', 'campaign.fingerprint')

    def reserve_campaign_step(self, campaign_id, phase, step_id, fingerprint, spec):
        _id(campaign_id, 'campaign_id')
        _id(step_id, 'step_id')
        _choice(phase, ('preflight', 'run', 'stop', 'collect', 'cleanup', 'warmup', 'detonate'), 'campaign.phase')
        self._campaign_spec(spec, fingerprint)
        with self.connection(immediate=True) as db:
            old = db.execute('SELECT * FROM campaigns WHERE campaign_id=? AND phase=? AND step_id=?', (campaign_id, phase, step_id)).fetchone()
            if old is not None:
                return self._reuse(_unpack(old), fingerprint, spec)
            auth = self._authorization(db, spec['authorization_sha256'])
            campaign = _unpack(db.execute('SELECT * FROM campaign_state WHERE campaign_id=?', (campaign_id,)).fetchone())
            if campaign['manifest_sha256'] != spec['manifest_sha256'] or campaign['experiment_id'] != spec['experiment_id']:
                _fail('fingerprint_conflict', 'campaign.manifest_sha256')
            if auth['campaign_id'] != campaign_id or auth['manifest_sha256'] != spec['manifest_sha256'] or phase not in auth['phases'] or auth['experiment_id'] != spec['experiment_id']:
                _fail('scope_mismatch', 'campaign.authorization_sha256')
            if spec['timeout_seconds'] > campaign['manifest']['limits']['max_phase_seconds']:
                _fail('budget_exceeded', 'campaign.timeout_seconds')
            stamp = _now()
            item = dict(campaign_id=campaign_id, phase=phase, step_id=step_id, fingerprint=fingerprint,
                        spec=spec, status='reserved', receipt=None, created_utc=stamp, updated_utc=stamp)
            data, sha = _encoded(item)
            db.execute('INSERT INTO campaigns VALUES (?,?,?,?,?,?,?)',
                       (campaign_id, phase, step_id, spec['experiment_id'], 'reserved', data, sha))
            self.event('dispatch_reserved', 'campaign-controller', {'phase': phase, 'step_id': step_id, 'fingerprint': fingerprint},
                       experiment_id=spec['experiment_id'], campaign_id=campaign_id, db=db)
        return None

    def _campaign_receipt(self, item, receipt):
        _fields(receipt, {'schema_version', 'fingerprint', 'status', 'start_utc', 'end_utc', 'elapsed_ms',
                          'campaign_id', 'phase', 'step_id', 'executor_sha256', 'executor_version',
                          'execution_outcome', 'exit_code', 'observed_target_sha256',
                          'effect_verified', 'evidence_sha256', 'failure_reason'}, 'campaign.receipt')
        if type(receipt['schema_version']) is not int or receipt['schema_version'] != 1:
            _fail('unsupported_schema', 'campaign.receipt.schema_version')
        if receipt['fingerprint'] != item['fingerprint']:
            _fail('fingerprint_conflict', 'campaign.receipt.fingerprint')
        expected = {key: item[key] for key in ('campaign_id', 'phase', 'step_id')}
        expected.update({key: item['spec'][key] for key in ('executor_sha256', 'executor_version')})
        if any(receipt[key] != value for key, value in expected.items()):
            _fail('fingerprint_conflict', 'campaign.receipt')
        _choice(receipt['execution_outcome'], ('succeeded', 'blocked', 'failed', 'unknown'), 'campaign.receipt.execution_outcome')
        _choice(receipt['status'], ('completed', 'failed', 'unknown'), 'campaign.receipt.status')
        outcomes = {'completed': ('succeeded',), 'failed': ('failed', 'blocked'), 'unknown': ('unknown',)}
        if receipt['status'] not in outcomes or receipt['execution_outcome'] not in outcomes[receipt['status']]:
            _fail('invalid_choice', 'campaign.receipt.execution_outcome')
        if _time(receipt['end_utc'], 'campaign.receipt.end_utc') < _time(receipt['start_utc'], 'campaign.receipt.start_utc'):
            _fail('invalid_timestamp', 'campaign.receipt.end_utc')
        _number(receipt['elapsed_ms'], 'campaign.receipt.elapsed_ms', nullable=True)
        if receipt['exit_code'] is not None and type(receipt['exit_code']) is not int:
            _fail('invalid_integer', 'campaign.receipt.exit_code')
        _digest(receipt['observed_target_sha256'], 'campaign.receipt.observed_target_sha256', nullable=True)
        _digest(receipt['evidence_sha256'], 'campaign.receipt.evidence_sha256', nullable=True)
        if type(receipt['effect_verified']) is not bool:
            _fail('invalid_boolean', 'campaign.receipt.effect_verified')
        if receipt['status'] == 'completed':
            if not receipt['effect_verified'] or receipt['observed_target_sha256'] != item['spec']['target_sha256'] or receipt['evidence_sha256'] is None or receipt['failure_reason'] is not None:
                _fail('effect_unverified', 'campaign.receipt')
        else:
            _choice(receipt['failure_reason'], FAILURES, 'campaign.receipt.failure_reason')
        _safe(receipt)

    def _finish_campaign(self, db, item, receipt, actor):
        old_status = item['status']
        item = dict(item, status=receipt['status'], receipt=receipt, updated_utc=_now())
        data, sha = _encoded(item)
        updated = db.execute('UPDATE campaigns SET status=?,data=?,sha256=? WHERE campaign_id=? AND phase=? AND step_id=? AND status=?',
                             (item['status'], data, sha, item['campaign_id'], item['phase'], item['step_id'], old_status))
        if updated.rowcount != 1:
            _fail('state_conflict', 'campaign.status')
        self.event('dispatch_unknown' if item['status'] == 'unknown' else 'dispatch_finished', actor,
                   {'phase': item['phase'], 'step_id': item['step_id'], 'status': item['status'],
                    'receipt_sha256': digest_bytes(canonical_bytes(receipt))},
                   experiment_id=item['spec']['experiment_id'], campaign_id=item['campaign_id'], db=db)

    def finish_campaign_step(self, campaign_id, phase, step_id, receipt):
        with self.connection(immediate=True) as db:
            item = _unpack(db.execute('SELECT * FROM campaigns WHERE campaign_id=? AND phase=? AND step_id=?', (campaign_id, phase, step_id)).fetchone())
            self._campaign_receipt(item, receipt)
            if item['status'] != 'reserved':
                _fail('state_conflict', 'campaign.status')
            self._finish_campaign(db, item, receipt, 'campaign-controller')
        return receipt

    def reconcile_campaign_step(self, campaign_id, phase, step_id, by, note, evidence, receipt):
        """Evidence bytes are explicitly supplied, hashed, and retained in private DB state."""
        human_actor(by)  # campaign effects are real: never resolved by automation
        _text(note, 'reconciliation.note')
        # A bounded, structured independent effect observation, never raw stderr.
        _fields(evidence, {'observed_target_sha256', 'effect_verified', 'source_receipt_sha256', 'observed_utc'}, 'reconciliation.evidence')
        _digest(evidence['observed_target_sha256'], 'reconciliation.evidence.observed_target_sha256')
        _digest(evidence['source_receipt_sha256'], 'reconciliation.evidence.source_receipt_sha256')
        _time(evidence['observed_utc'], 'reconciliation.evidence.observed_utc')
        if type(evidence['effect_verified']) is not bool:
            _fail('invalid_boolean', 'reconciliation.evidence.effect_verified')
        with self.connection(immediate=True) as db:
            item = _unpack(db.execute('SELECT * FROM campaigns WHERE campaign_id=? AND phase=? AND step_id=?', (campaign_id, phase, step_id)).fetchone())
            if item['status'] not in ('reserved', 'unknown'):
                _fail('state_conflict', 'campaign.status')
            self._campaign_receipt(item, receipt)
            if receipt['status'] == 'unknown' or receipt['evidence_sha256'] != digest_bytes(canonical_bytes(evidence)) or receipt['observed_target_sha256'] != evidence['observed_target_sha256'] or receipt['effect_verified'] != evidence['effect_verified']:
                _fail('evidence_mismatch', 'reconciliation.evidence')
            self._finish_campaign(db, item, receipt, by)
            self.event('reconciliation_recorded', by, {'phase': phase, 'step_id': step_id,
                       'note': note, 'evidence': evidence, 'outcome': receipt['status']},
                       experiment_id=item['spec']['experiment_id'], campaign_id=campaign_id, db=db)
        return receipt

    def _verify_refs(self, trial_id, value, routine=False):
        if type(value) is dict:
            if set(value) == {'sha256', 'path', 'byte_count'}:
                self.verify_artifact(trial_id, value, routine)
            else:
                for child in value.values():
                    self._verify_refs(trial_id, child, routine)
        elif type(value) is list:
            for child in value:
                self._verify_refs(trial_id, child, routine)

    def snapshot(self, experiment_id, *, verify_truth=True, routine=False):
        """One consistent, fully cross-checked read of an experiment.

        `routine` is for status/advance only: `PRAGMA quick_check` and per-process
        memoized proofs of immutable artifacts. Export, score, diagnose and
        release use the default full `integrity_check` and a full re-hash.
        """
        _id(experiment_id, 'experiment_id')
        with self.connection() as db:
            check = 'PRAGMA quick_check' if routine else 'PRAGMA integrity_check'
            if db.execute(check).fetchone()[0] != 'ok' or db.execute('PRAGMA foreign_key_check').fetchone() is not None:
                _fail('corrupt_state', 'snapshot.database')
            frozen = _unpack_frozen(db.execute('SELECT * FROM experiments WHERE experiment_id=?', (experiment_id,)).fetchone())
            trials = [_unpack(r) for r in db.execute('SELECT * FROM trials WHERE experiment_id=? ORDER BY trial_id', (experiment_id,))]
            calls = [_unpack(r) for r in db.execute('SELECT calls.* FROM calls JOIN trials USING(trial_id) WHERE trials.experiment_id=? ORDER BY call_id', (experiment_id,))]
            all_events = [_unpack(r) for r in db.execute('SELECT * FROM events ORDER BY seq')]
            if [e['seq'] for e in all_events] != list(range(1, len(all_events) + 1)):
                _fail('incomplete_snapshot', 'snapshot.events')
            linked = {event['campaign_id'] for event in all_events
                      if event['payload'].get('record_type') == 'campaign_evidence_release'
                      and any(item['experiment_id'] == experiment_id for item in event['payload']['destinations'])}
            campaign_states = [_unpack(r) for r in db.execute('SELECT * FROM campaign_state ORDER BY campaign_id')]
            campaign_states = [state for state in campaign_states
                               if state['experiment_id'] == experiment_id or state['campaign_id'] in linked]
            linked = {state['campaign_id'] for state in campaign_states}
            campaigns = [_unpack(r) for r in db.execute('SELECT * FROM campaigns ORDER BY campaign_id,phase,step_id')
                         if r['campaign_id'] in linked]
            approvals = [_unpack(r) for r in db.execute('SELECT * FROM approvals ORDER BY approval_id')
                         if r['experiment_id'] == experiment_id or r['campaign_id'] in linked]
            events = [e for e in all_events if e['experiment_id'] == experiment_id or
                      (e['campaign_id'] in linked and e['trial_id'] is None)]
            if sum(e['kind'] == 'experiment_created' for e in events) != 1:
                _fail('incomplete_snapshot', 'snapshot.experiment')
            truth_freezes = [event for event in events
                            if event['payload'].get('record_type') == 'truth_frozen']
            if len(truth_freezes) > 1:
                _fail('incomplete_snapshot', 'truth.freeze')
            for event in truth_freezes:
                self._verify_truth_freeze(event, frozen, verify_content=False)
                if any(prior['kind'] == 'dispatch_reserved' and prior['call_id'] is not None
                       and prior['experiment_id'] == experiment_id and prior['seq'] < event['seq']
                       for prior in events):
                    _fail('truth_freeze_too_late', 'truth.freeze')
            expected_schedule = {(case['evidence']['case_id'], team['team_id'], repetition)
                                 for case in frozen['cases'] for team in frozen['experiment']['teams']
                                 for repetition in range(1, frozen['experiment']['repetitions'] + 1)}
            actual_schedule = [(trial['case_id'], trial['team_id'], trial['repetition']) for trial in trials]
            if len(actual_schedule) != len(expected_schedule) or set(actual_schedule) != expected_schedule:
                _fail('incomplete_snapshot', 'snapshot.trials')
            state_by_id = {item['campaign_id']: item for item in campaign_states}
            for state in campaign_states:
                self._campaign_state(state)
                if not any(e['campaign_id'] == state['campaign_id'] and e['payload'].get('snapshot_sha256') == digest_bytes(canonical_bytes(state)) for e in events):
                    _fail('incomplete_snapshot', 'snapshot.campaign_states')
                for event in events:
                    if event['campaign_id'] == state['campaign_id'] and event['payload'].get('record_type') == 'public_evidence_sealed':
                        self._verify_campaign_seal(state, event['payload'],
                                                   [row for row in campaigns if row['campaign_id'] == state['campaign_id']])
            by_trial, by_call = {}, {}
            for event in events:
                by_trial.setdefault(event['trial_id'], []).append(event)
                by_call.setdefault(event['call_id'], []).append(event)
            for trial in trials:
                self._trial(trial, db, routine)
                self._verify_refs(trial['trial_id'], trial, routine)
                trial_events = by_trial.get(trial['trial_id'], [])
                if not any(e['kind'] == 'evidence_sealed' for e in trial_events):
                    _fail('incomplete_snapshot', 'snapshot.trials')
                if trial['status'] == 'terminated' and not any(
                        e['kind'] == 'trial_terminated'
                        and e['payload'].get('reason') == trial['terminal_reason']
                        and e['payload'].get('snapshot_sha256') == digest_bytes(canonical_bytes(trial))
                        for e in trial_events):
                    _fail('incomplete_snapshot', 'snapshot.trials.terminated')
            for call in calls:
                trial, config, team = self._call_spec(db, call['spec'], call['fingerprint'], routine)
                self._verify_refs(trial['trial_id'], call, routine)
                if call['receipt'] is not None:
                    self._receipt(call, call['receipt'], config, team)
                    if call['status'] != call['receipt']['status']:
                        _fail('corrupt_state', 'snapshot.calls')
                elif call['status'] != 'reserved':
                    _fail('incomplete_snapshot', 'snapshot.calls')
                related = by_call.get(call['call_id'], [])
                if sum(e['kind'] == 'dispatch_reserved' for e in related) != 1:
                    _fail('incomplete_snapshot', 'snapshot.calls')
                if call['receipt'] is not None and not any(e['kind'] in ('dispatch_finished', 'dispatch_unknown') and e['payload'].get('receipt_sha256') == digest_bytes(canonical_bytes(call['receipt'])) for e in related):
                    _fail('incomplete_snapshot', 'snapshot.calls')
            for item in campaigns:
                state = state_by_id.get(item['campaign_id'])
                if state is None or state['manifest_sha256'] != item['spec']['manifest_sha256']:
                    _fail('incomplete_snapshot', 'snapshot.campaigns')
                related = [e for e in events if e['campaign_id'] == item['campaign_id']
                           and e['payload'].get('phase') == item['phase']
                           and e['payload'].get('step_id') == item['step_id']]
                if sum(e['kind'] == 'dispatch_reserved' for e in related) != 1:
                    _fail('incomplete_snapshot', 'snapshot.campaigns')
                if item['receipt'] is not None and not any(e['kind'] in ('dispatch_finished', 'dispatch_unknown')
                        and e['payload'].get('receipt_sha256') == digest_bytes(canonical_bytes(item['receipt'])) for e in related):
                    _fail('incomplete_snapshot', 'snapshot.campaigns')
                self._campaign_spec(item['spec'], item['fingerprint'])
                if item['receipt'] is not None:
                    self._campaign_receipt(item, item['receipt'])
                    if item['status'] != item['receipt']['status']:
                        _fail('corrupt_state', 'snapshot.campaigns')
                elif item['status'] != 'reserved':
                    _fail('incomplete_snapshot', 'snapshot.campaigns')
            recorded_approvals = {e['payload'].get('approval_id') for e in events
                                  if e['kind'] == 'authorization_recorded'}
            approval_ids = {a['approval_id'] for a in approvals}
            for item in approvals:
                # Authorizations only: the benchmark records no human stage decisions.
                if item['kind'] != 'authorization' or item['approval_id'] not in recorded_approvals:
                    _fail('incomplete_snapshot', 'snapshot.approvals')
                original = {key: value for key, value in item.items() if key not in ('kind', 'authorization_sha256')}
                if digest_bytes(canonical_bytes(original)) != item['authorization_sha256']:
                    _fail('corrupt_state', 'snapshot.approvals')
                if item['trial_id'] is not None:
                    self._verify_refs(item['trial_id'], item, routine)
            for item in events:
                _choice(item['kind'], EVENT_KINDS, 'event.kind')
                if item['campaign_id'] is not None and item['campaign_id'] not in state_by_id:
                    _fail('incomplete_snapshot', 'snapshot.campaign_states')
                if item['kind'] == 'authorization_recorded' and item['payload'].get('approval_id') not in approval_ids:
                    _fail('incomplete_snapshot', 'snapshot.approvals')
                if item['kind'] == 'trial_status_changed':
                    retry = item['payload'].get('policy') == AUTO_RETRY_POLICY
                    if (retry != (item['actor'] == AUTO_RETRY_ACTOR)
                            or (retry and (item['call_id'] is None
                                           or item['payload'].get('failure_reason') not in RETRYABLE_FAILURES))):
                        _fail('incomplete_snapshot', 'snapshot.automatic_retry')
                if item['kind'] == 'reconciliation_recorded':
                    # Automation and humans never masquerade as each other, and
                    # automation only ever resolves a model call as failed.
                    automatic = item['payload'].get('policy') == AUTO_RECONCILE_POLICY
                    if (automatic != (item['actor'] == AUTO_RECONCILE_ACTOR)
                            or (not automatic and item['actor'].strip().lower().startswith(AUTOMATION_PREFIX))
                            or (automatic and (item['call_id'] is None or item['campaign_id'] is not None
                                               or item['payload'].get('outcome') != 'failed'))):
                        _fail('incomplete_snapshot', 'snapshot.reconciliation')
                if item['kind'] == 'stage_auto_advanced':
                    if item['actor'] != AUTO_ADVANCE_ACTOR or item['trial_id'] is None or item['call_id'] is None:
                        _fail('incomplete_snapshot', 'snapshot.auto_advance')
                    self._auto_advance_payload(item['trial_id'], item['payload'])
                if item['trial_id'] is not None:
                    self._verify_refs(item['trial_id'], item['payload'], routine)
                if item['kind'] == 'process_started' and not any(
                        row['campaign_id'] == item['campaign_id'] and row['phase'] == item['payload'].get('phase')
                        and row['step_id'] == item['payload'].get('step_id') for row in campaigns):
                    _fail('incomplete_snapshot', 'snapshot.process_started')
                if item['kind'] == 'process_stopped' and (item['payload'].get('evidence') or {}).get('local_stopped') is not True:
                    _fail('incomplete_snapshot', 'snapshot.process_stopped')
                if item['kind'] == 'score_recorded' and 'variant' not in item['payload'].get('score', {}):
                    _fail('incomplete_snapshot', 'snapshot.scores')
            if verify_truth:
                for event in truth_freezes:
                    self._verify_truth_freeze(event, frozen)
                for event in events:
                    if event['kind'] != 'score_recorded':
                        continue
                    score = event['payload']['score']
                    truth = decode_json(self.read_evaluator_artifact('truth', score['truth_sha256']))
                    case = next((case for case in frozen['cases']
                                 if case['evidence']['case_id'] == score['case_id']), None)
                    if case is None:
                        _fail('scope_mismatch', 'score.case_id')
                    validate_truth(truth, case['evidence'])
                    adjudication = decode_json(self.read_evaluator_artifact('adjudication', score['adjudication_sha256']))
                    if adjudication.get('rubric_version') != score['rubric_version']:
                        _fail('scope_mismatch', 'score.rubric_version')
                    if score['output_sha256'] != event['payload'].get('output_sha256'):
                        _fail('scope_mismatch', 'score.output_sha256')
                    if score['output_sha256'] is not None and not any(
                            output.get('trial_id') == event['trial_id']
                            and output.get('output_sha256') == score['output_sha256']
                            for output in adjudication.get('outputs', [])):
                        _fail('unsealed_output', 'score.output_sha256')
            return dict(schema_version=1, experiment=frozen, trials=trials, calls=calls,
                        campaigns=campaigns, campaign_states=campaign_states, approvals=approvals, events=events)

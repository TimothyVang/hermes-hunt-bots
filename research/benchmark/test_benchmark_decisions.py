"""Disposable CLI-ledger simulations of automatic advances and recovery, not model results."""
from contextlib import closing, redirect_stdout
import copy
import io
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from benchmark_paths import FRAMEWORK
import bot
from benchmark_contracts import (AUTO_ADVANCE_ACTOR, AUTO_ADVANCE_NOTE, BenchmarkError,
                                 canonical_bytes, digest_bytes)
from benchmark_decisions import (
    WORKFLOW_ACCEPTANCE, WORKFLOW_SCOPE, WORKFLOW_TITLE, advanced_output, auto_advance, auto_reconciled,
    auto_recovery, checker_validator_output, inspect_stage, ledger_snapshot, reconcile, retry_eligible,
    stage_handoff, trial_view,
)
from benchmark_store import EVENT_KINDS, BenchmarkStore, _unpack
from test_benchmark_runner import (
    authorize_fixture, call_fixture, frozen_fixture, receipt_fixture,
    response_fixture, trial_fixture,
)


HERE = Path(__file__).resolve().parent
# Reconciliation remains an explicit human action; these names label simulations.
TEST_ACTOR = 'disposable-test-only-human-simulation'
TEST_NOTE = 'Disposable regression simulation; no actual human benchmark action.'


class _StageFixture(unittest.TestCase):
    checker_enabled = False

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'state'
        self.store = BenchmarkStore(self.root, create=True)
        self.frozen = frozen_fixture()
        if self.checker_enabled:
            team = self.frozen['experiment']['teams'][0]
            checker = copy.deepcopy(next(iter(team['roles'].values())))
            checker.update(adapter='typesafe', provider='typesafe', model_requested='synthetic-checker-1',
                           expected_model_ids=['synthetic-checker-1'], max_output_tokens=None,
                           base_url='http://127.0.0.1:9', parameters={'temperature': None, 'seed': None})
            team['evidence_checker'] = checker
            # A typesafe checker is always a paid route; a local label would be refused.
            team['deployment'] = 'hybrid'
            self.frozen['experiment']['budgets'].update(max_api_cost_usd=100, per_call_cost_bound_usd=1)
            self.frozen['experiment']['pricing_snapshot']['rates'].append(
                {'provider': 'typesafe', 'model_requested': 'synthetic-checker-1',
                 'input_per_million': 1, 'output_per_million': 1})
        self.eid = self.frozen['experiment']['experiment_id']
        self.store.create_experiment(self.frozen)
        self.trial = trial_fixture(self.store, self.frozen)
        self.tid = self.trial['trial_id']
        self.workspace = self.root / 'trials' / self.tid / 'ledger'
        self.cli('init')
        with closing(bot.connect(self.workspace)) as db, redirect_stdout(io.StringIO()):
            workflow_id, mapping = bot.create_workflow(
                db, self.frozen['workflow'], WORKFLOW_TITLE, WORKFLOW_SCOPE, WORKFLOW_ACCEPTANCE)
        self.assertEqual(workflow_id, self.trial['workflow_id'])
        self.assertEqual(mapping, self.trial['task_mapping'])
        self.authorization = authorize_fixture(self.store, self.frozen, self.trial)

    def cli(self, *args, expected=0):
        result = subprocess.run([sys.executable, '-B', str(FRAMEWORK / 'bot.py'), '-w', str(self.workspace),
                                 *map(str, args)], stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        self.assertEqual(result.returncode, expected, result.stderr.decode('utf-8', errors='replace'))
        return result

    def assert_code(self, code, fn, *args, **kwargs):
        with self.assertRaises(BenchmarkError) as raised:
            fn(*args, **kwargs)
        self.assertEqual(raised.exception.code, code)

    def events(self, kind=None):
        events = ledger_snapshot(self.store, self.trial)['events']
        return [e for e in events if kind is None or e['kind'] == kind]

    def benchmark_events(self, kind=None):
        with self.store.connection() as db:
            values = [_unpack(r) for r in db.execute('SELECT * FROM events ORDER BY seq')]
        return [e for e in values if kind is None or e['kind'] == kind]

    def reserve(self, stage='scope', attempt=1):
        spec = call_fixture(self.store, self.frozen, self.trial, self.authorization, stage, attempt)
        call_id = '{}-{}'.format(stage, attempt)
        self.store.reserve_call(call_id, digest_bytes(canonical_bytes(spec)), spec)
        return call_id, spec

    def complete(self, call_id, spec, output=None):
        receipt = receipt_fixture(self.store, self.frozen, call_id, spec)
        if output is not None:
            ref = self.store.write_artifact(self.tid, 'response', canonical_bytes(output))
            receipt.update(response_artifact=ref, response_sha256=ref['sha256'])
        self.store.finish_call(call_id, receipt)
        return receipt

    def run_ledger(self, data, stage='scope', exit_code=0):
        task_id = self.trial['task_mapping'][stage]
        status = ledger_snapshot(self.store, self.trial)['tasks'][stage]['status']
        if status == 'pending':
            self.cli('start', task_id)
        # This is an explicitly synthetic transport process, never a model shim.
        code = 'import sys; sys.stdin.buffer.read(); sys.stdout.buffer.write(bytes.fromhex({!r})); sys.exit({})'.format(
            data.hex(), exit_code)
        self.cli('run', '--adapter', 'generic', '--timeout', '30', task_id, '--',
                 sys.executable, '-B', '-c', code, expected=0 if exit_code == 0 else 1)

    def submit(self, stage='scope', attempt=1, output=None):
        call_id, spec = self.reserve(stage, attempt)
        receipt = self.complete(call_id, spec, output)
        data = self.store.read_artifact(self.tid, receipt['response_artifact'])
        self.run_ledger(data, stage)
        return receipt

    def advance_stage(self, stage='scope'):
        return auto_advance(self.store, self.trial, stage)

    def evidence(self, call_id, outcome, receipt, **changes):
        call = next(c for c in self.store.calls(trial_id=self.tid) if c['call_id'] == call_id)
        value = {'schema_version': 1, 'call_id': call_id, 'fingerprint': call['fingerprint'],
                 'outcome': outcome, 'receipt': receipt, 'process_stopped': True,
                 'observation': 'Disposable simulation: inspected child exit and immutable artifacts.'}
        value.update(changes)
        path = Path(self.temp.name) / (call_id + '-evidence.json')
        path.write_bytes(canonical_bytes(value))
        return path

    def recover(self, call_id, outcome, path=None):
        return reconcile(self.root, self.eid, call_id, TEST_ACTOR, TEST_NOTE, outcome, path)


class BenchmarkAdvanceTests(_StageFixture):
    def test_auto_advance_binds_exact_receipt_and_is_never_an_approval(self):
        receipt = self.submit()
        advanced = self.advance_stage()
        self.assertEqual(advanced['output_sha256'], receipt['response_sha256'])
        self.assertEqual(advanced['auto_advance']['review_policy'], 'auto_advance')
        self.assertEqual(advanced_output(self.store, self.trial, 'scope'), advanced)
        transitions = self.events('auto_advance')
        self.assertEqual([(e['actor'], e['note']) for e in transitions], [(AUTO_ADVANCE_ACTOR, AUTO_ADVANCE_NOTE)])
        self.assertEqual(self.events('approve'), [])
        mirrored = self.benchmark_events('stage_auto_advanced')
        self.assertEqual([(e['actor'], e['call_id']) for e in mirrored], [(AUTO_ADVANCE_ACTOR, 'scope-1')])
        self.assertEqual(mirrored[0]['payload']['ledger_event_id'], transitions[0]['id'])
        self.assertNotIn('human_decision_observed', EVENT_KINDS)
        self.assertEqual([a['kind'] for a in self.store.snapshot(self.eid)['approvals']], ['authorization'])
        # Idempotent: no second ledger transition or store event.
        self.assertEqual(self.advance_stage(), advanced)
        self.assertEqual(len(self.events('auto_advance')), 1)
        self.assertEqual(len(self.benchmark_events('stage_auto_advanced')), 1)
        shown = self.cli('show', self.trial['task_mapping']['scope']).stdout.decode('utf-8')
        self.assertIn('auto-advanced (unreviewed)', shown)

    def test_manual_ledger_approval_or_rejection_is_unsupported(self):
        for command in ('approve', 'reject'):
            with self.subTest(command=command):
                self.setUp()
                self.submit()
                self.cli(command, self.trial['task_mapping']['scope'], '--by', TEST_ACTOR, '--note', TEST_NOTE)
                self.assertEqual(inspect_stage(self.store, self.trial, 'scope')['blocker'],
                                 'unsupported_ledger_transition')
                self.assert_code('unsupported_ledger_transition', advanced_output, self.store, self.trial, 'scope')
                if command == 'approve':
                    self.assert_code('unsupported_ledger_transition', self.advance_stage)
                self.assertEqual(self.benchmark_events('stage_auto_advanced'), [])

    def test_foreign_automatic_actor_is_not_a_benchmark_advance(self):
        self.submit()
        self.cli('auto-advance', '--id', self.trial['task_mapping']['scope'],
                 '--by', 'benchmark-auto-other', '--note', AUTO_ADVANCE_NOTE)
        self.assert_code('unsupported_ledger_transition', self.advance_stage)
        self.assertEqual(inspect_stage(self.store, self.trial, 'scope')['blocker'], 'unsupported_ledger_transition')

    def test_crash_after_ledger_commit_mirrors_without_second_advance(self):
        receipt = self.submit()
        with mock.patch.object(BenchmarkStore, 'record_auto_advance',
                               side_effect=RuntimeError('test-only mirror crash')):
            with self.assertRaises(RuntimeError):
                self.advance_stage()
        self.assertEqual(len(self.events('auto_advance')), 1)
        self.assertEqual(inspect_stage(self.store, self.trial, 'scope')['blocker'], 'auto_advance_unbound')
        self.assert_code('auto_advance_unbound', advanced_output, self.store, self.trial, 'scope')
        advanced = self.advance_stage()
        self.assertEqual(advanced['output_sha256'], receipt['response_sha256'])
        self.assertEqual(len(self.events('auto_advance')), 1)
        self.assertEqual(len(self.benchmark_events('stage_auto_advanced')), 1)

    def test_advance_records_submission_once(self):
        receipt = self.submit()
        self.assertEqual(self.benchmark_events('stage_submitted'), [])
        self.advance_stage()
        self.advance_stage()
        starts = self.benchmark_events('stage_submitted')
        submit = self.events('submit')[0]
        self.assertEqual(len(starts), 1)
        self.assertEqual(starts[0]['payload']['ledger_submit_event_id'], submit['id'])
        self.assertEqual(starts[0]['payload']['ledger_submit_utc'], submit['time'])
        self.assertEqual(starts[0]['payload']['output_sha256'], receipt['response_sha256'])

    def test_changed_submission_bytes_refuse_before_any_advance(self):
        self.submit()
        artifact = next(a for a in ledger_snapshot(self.store, self.trial)['artifacts']
                        if a['description'] == 'CLI stdout')
        Path(artifact['path']).write_bytes(b'{"changed":"test-only tamper"}')
        self.assert_code('digest_mismatch', self.advance_stage)
        self.assertEqual(self.events('auto_advance'), [])
        self.assertEqual(ledger_snapshot(self.store, self.trial)['tasks']['scope']['status'], 'review')

    def test_current_handoff_mutation_invalidates_an_advanced_output(self):
        self.submit()
        self.advance_stage()
        artifact = next(a for a in ledger_snapshot(self.store, self.trial)['artifacts']
                        if a['description'] == 'CLI stdout')
        Path(artifact['path']).write_bytes(b'{"changed":"test-only tamper"}')
        self.assert_code('digest_mismatch', advanced_output, self.store, self.trial, 'scope')
        self.assertEqual(inspect_stage(self.store, self.trial, 'scope')['blocker'], 'digest_mismatch')

    def test_changed_ledger_transition_invalidates_the_mirror(self):
        self.submit()
        self.advance_stage()
        with closing(bot.connect(self.workspace)) as db, db:
            db.execute("UPDATE events SET time=? WHERE kind='auto_advance'", ('2026-01-01T00:00:00+00:00',))
        self.assert_code('auto_advance_unbound', advanced_output, self.store, self.trial, 'scope')
        self.assert_code('fingerprint_conflict', self.advance_stage)
        self.assertEqual(len(self.benchmark_events('stage_auto_advanced')), 1)

    def test_receipt_not_completed_never_advances(self):
        self.reserve()
        self.run_ledger(canonical_bytes(response_fixture()))
        self.assert_code('incomplete_receipt', self.advance_stage)
        self.assertEqual(self.events('auto_advance'), [])
        self.assertEqual(self.store.calls(trial_id=self.tid)[0]['status'], 'reserved')

    def test_workflow_definition_tamper_blocks_advance(self):
        self.submit()
        with closing(bot.connect(self.workspace)) as db, db:
            db.execute('UPDATE tasks SET scope=? WHERE id=?',
                       ('Test-only tampered scope', self.trial['task_mapping']['scope']))
        self.assert_code('ledger_scope_mismatch', self.advance_stage)

    def test_reconcile_requires_explicit_evidence_and_no_process_uncertainty(self):
        call_id, spec = self.reserve()
        self.assert_code('evidence_required', self.recover, call_id, 'failed')
        path = self.evidence(call_id, 'failed', None, process_stopped=False)
        self.assert_code('effect_unverified', self.recover, call_id, 'failed', path)
        self.assertEqual(self.store.calls(trial_id=self.tid)[0]['status'], 'reserved')
        self.assertEqual(self.events('auto_advance'), [])

    def test_reserved_recovery_without_terminal_measurements_retains_unknowns(self):
        call_id, spec = self.reserve()
        self.run_ledger(b'', exit_code=3)
        path = self.evidence(call_id, 'failed', None)
        self.recover(call_id, 'failed', path)
        call = self.store.calls(trial_id=self.tid)[0]
        self.assertEqual(call['status'], 'failed')
        receipt = call['receipt']
        self.assertIsNone(receipt['elapsed_ms'])
        self.assertEqual(receipt['start_utc'], call['created_utc'])
        self.assertIsNone(receipt['response_artifact'])
        self.assertIsNone(receipt['cost']['api_cost_usd'])
        self.assertTrue(all(v is None for v in receipt['usage'].values()))
        self.assertEqual(BenchmarkStore.charge(call, 'seconds', self.frozen['experiment']),
                         spec['model']['timeout_seconds'])
        notes = [e['payload']['note'] for e in self.benchmark_events('reconciliation_recorded')]
        self.assertTrue(any('not model execution timestamps' in note for note in notes))
        self.assertFalse(retry_eligible(self.store, self.trial, call_id))
        self.cli('resume', self.trial['task_mapping']['scope'])
        self.assertTrue(retry_eligible(self.store, self.trial, call_id))
        self.recover(call_id, 'failed', path)
        self.assertEqual(len(self.benchmark_events('reconciliation_recorded')), 1)
        self.assertEqual(len(self.events('run-started')), 1)
        self.assertEqual(self.events('auto_advance'), [])

    def test_unknown_recovery_preserves_authentic_partial_metrics(self):
        call_id, spec = self.reserve()
        unknown = receipt_fixture(self.store, self.frozen, call_id, spec, status='unknown')
        unknown['elapsed_ms'] = 37
        unknown['usage']['input_tokens'] = 11
        self.store.finish_call(call_id, unknown)
        path = self.evidence(call_id, 'failed', None)
        self.recover(call_id, 'failed', path)
        receipt = self.store.calls(trial_id=self.tid)[0]['receipt']
        self.assertEqual(receipt['elapsed_ms'], 37)
        self.assertEqual(receipt['usage']['input_tokens'], 11)
        self.assertEqual(receipt['start_utc'], unknown['start_utc'])

    def test_known_failed_receipt_needs_reconciliation_and_normal_resume(self):
        call_id, spec = self.reserve()
        receipt = receipt_fixture(self.store, self.frozen, call_id, spec, status='failed')
        self.store.finish_call(call_id, receipt)
        self.run_ledger(b'', exit_code=3)
        self.assertFalse(retry_eligible(self.store, self.trial, call_id))
        path = self.evidence(call_id, 'failed', receipt)
        self.recover(call_id, 'failed', path)
        self.assertFalse(retry_eligible(self.store, self.trial, call_id))
        self.cli('resume', self.trial['task_mapping']['scope'])
        self.assertTrue(retry_eligible(self.store, self.trial, call_id))
        self.assertEqual(self.store.calls(trial_id=self.tid)[0]['receipt'], receipt)

    def test_automation_actor_refused_and_human_resolution_stays_manual(self):
        call_id, _ = self.reserve()
        self.run_ledger(b'', exit_code=3)
        # A human evidence file is still required and recorded as the human's own decision.
        path = self.evidence(call_id, 'failed', None)
        for actor in ('benchmark-auto-reconcile', 'Benchmark-Auto-operator'):
            with self.subTest(actor=actor):
                self.assert_code('reserved_actor', reconcile, self.root, self.eid, call_id, actor,
                                 TEST_NOTE, 'failed', path)
        self.recover(call_id, 'failed', path)
        self.assertEqual([(e['actor'], e['payload']['policy'])
                          for e in self.benchmark_events('reconciliation_recorded')],
                         [(TEST_ACTOR, 'human_operator')])
        # A human-resolved failure is never resumed or retried by automation.
        view = trial_view(self.store, self.trial)
        self.assertIsNone(auto_recovery(view, self.trial, 'scope'))
        self.assertFalse(auto_reconciled(view['events'], call_id))

    def test_process_stop_requires_the_owning_runs_recorded_exit(self):
        trial = {'task_mapping': {'scope': 1}}
        call = {'call_id': 'call-u', 'status': 'unknown', 'created_utc': '2026-01-01T00:00:05.500000+00:00',
                'spec': {'stage_key': 'scope', 'attempt_index': 1}}

        def action(status, *events):
            rows = [{'id': index + 1, 'task_id': 1, 'kind': kind, 'time': '2026-01-01T00:00:{:02d}+00:00'.format(second)}
                    for index, (kind, second) in enumerate(events)]
            view = {'calls': [call], 'events': [],
                    'ledger': {'tasks': {'scope': {'status': status}}, 'events': rows}}
            return auto_recovery(view, trial, 'scope')

        # bot.py's own run-failed after this run's start, enclosing the reservation.
        confirmed = action('blocked', ('start', 1), ('run-started', 5), ('run-failed', 9))
        self.assertEqual((confirmed['action'], confirmed['process_check']),
                         ('reconcile', {'basis': 'ledger_run_failed', 'ledger_event_id': 3,
                                        'ledger_event_time': '2026-01-01T00:00:09+00:00'}))
        self.assertEqual(action('blocked', ('run-started', 5), ('run-failed', 5))['action'], 'reconcile')
        for status, events in (
                ('running', (('run-started', 5),)),                       # child may still run
                ('pending', ()),                                          # no ledger run at all
                ('blocked', (('run-started', 5), ('recover-run', 9))),    # a human's assertion
                ('blocked', (('run-started', 6), ('run-failed', 9))),     # reserved before the run
                ('blocked', (('run-started', 1), ('run-failed', 3)))):    # reserved after it ended
            with self.subTest(status=status, events=events):
                self.assertEqual(action(status, *events)['action'], 'process_stop_unconfirmed')
        self.assertEqual(action('review', ('run-started', 5), ('submit', 9))['action'], 'manual')

    def test_completed_receipt_submission_failure_recovers_without_new_call(self):
        call_id, spec = self.reserve()
        receipt = self.complete(call_id, spec)
        raw = self.store.read_artifact(self.tid, receipt['response_artifact'])
        self.run_ledger(raw, exit_code=3)
        path = self.evidence(call_id, 'completed', receipt)
        result = self.recover(call_id, 'completed', path)
        self.assertEqual(result['ledger_status'], 'review')
        self.assertFalse(result['approved'])
        self.assertEqual(stage_handoff(self.store, self.trial, 'scope')['output_bytes'], raw)
        self.recover(call_id, 'completed', path)
        self.assertEqual(len(self.events('submit')), 1)
        self.assertEqual(len(self.events('run-started')), 1)
        self.assertEqual(len(self.store.calls(trial_id=self.tid)), 1)
        self.assertEqual(self.events('auto_advance'), [])
        # The recovered submission then advances like any other, unreviewed.
        self.assertEqual(self.advance_stage()['output_sha256'], receipt['response_sha256'])
        self.assertEqual(len(self.events('auto_advance')), 1)

    def test_recovery_never_resubmits_after_a_manual_ledger_transition(self):
        receipt = self.submit()
        self.cli('reject', self.trial['task_mapping']['scope'], '--by', TEST_ACTOR, '--note', TEST_NOTE)
        path = self.evidence('scope-1', 'completed', receipt)
        self.assert_code('submission_recovery_required', self.recover, 'scope-1', 'completed', path)
        self.assertEqual(len(self.events('submit')), 1)
        self.assertEqual(self.events('auto_advance'), [])
        self.assertEqual(ledger_snapshot(self.store, self.trial)['tasks']['scope']['status'], 'active')

    def test_completed_recovery_requires_valid_stored_response_and_measurement(self):
        call_id, spec = self.reserve()
        receipt = receipt_fixture(self.store, self.frozen, call_id, spec)
        bad = dict(receipt, response_sha256='f' * 64)
        path = self.evidence(call_id, 'completed', bad)
        self.assert_code('digest_mismatch', self.recover, call_id, 'completed', path)
        bad = dict(receipt, elapsed_ms=None)
        path = self.evidence(call_id, 'completed', bad)
        self.assert_code('invalid_number', self.recover, call_id, 'completed', path)
        self.assertEqual(self.store.calls(trial_id=self.tid)[0]['status'], 'reserved')

    def test_completed_terminal_receipt_cannot_be_rewritten(self):
        receipt = self.submit()
        changed = dict(receipt, elapsed_ms=9)
        path = self.evidence('scope-1', 'completed', changed)
        self.assert_code('fingerprint_conflict', self.recover, 'scope-1', 'completed', path)
        path = self.evidence('scope-1', 'failed', None)
        self.assert_code('fingerprint_conflict', self.recover, 'scope-1', 'failed', path)
        self.assertEqual(self.events('auto_advance'), [])

    def test_reconcile_rejects_foreign_experiment_and_extra_evidence_fields(self):
        call_id, _ = self.reserve()
        path = self.evidence(call_id, 'failed', None, extra='test-only unknown field')
        self.assert_code('invalid_fields', self.recover, call_id, 'failed', path)
        self.assert_code('not_found', reconcile, self.root, 'not-this-experiment', call_id,
                         TEST_ACTOR, TEST_NOTE, 'failed', path)


class BenchmarkCheckerAdvanceTests(_StageFixture):
    checker_enabled = True

    def prepare_analysis(self, output=None):
        for stage in ('scope', 'endpoint_evidence', 'network_evidence', 'hypotheses'):
            self.submit(stage=stage)
            self.advance_stage(stage)
        return self.submit(stage='analysis', output=output)

    def register_checker(self, ref):
        self.cli('artifact', self.trial['task_mapping']['analysis'], '--path',
                 self.root / 'trials' / self.tid / ref['path'], '--description', 'Benchmark evidence checker')

    def test_empty_claims_require_immutable_validator_appendix_without_call(self):
        receipt = self.prepare_analysis()
        with self.assertRaises(BenchmarkError):
            self.advance_stage('analysis')
        output = response_fixture('analysis')
        appendix = checker_validator_output(output, self.frozen['cases'][0]['evidence'], receipt['response_sha256'])
        ref = self.store.write_artifact(self.tid, 'checker', canonical_bytes(appendix))
        self.register_checker(ref)
        advanced = self.advance_stage('analysis')
        self.assertEqual(advanced['checker_output'], appendix)
        self.assertIsNone(advanced['checker'])
        self.assertEqual(advanced['output'], output)
        self.assertEqual(len(self.store.calls(trial_id=self.tid)), 5)

    def test_recovery_registers_missing_checker_appendix_in_review(self):
        receipt = self.prepare_analysis()
        with self.assertRaises(BenchmarkError):
            self.advance_stage('analysis')
        submits = len(self.events('submit'))
        path = self.evidence('analysis-1', 'completed', receipt)
        self.assertEqual(self.recover('analysis-1', 'completed', path)['ledger_status'], 'review')
        self.assertEqual(len(self.events('submit')), submits)
        self.assertEqual(len(self.events('auto_advance')), 4)
        starts = [e for e in self.benchmark_events('stage_submitted') if e['payload']['stage_key'] == 'analysis']
        self.assertEqual(len(starts), 1)
        advanced = self.advance_stage('analysis')
        self.assertIsNone(advanced['checker'])
        self.assertEqual(advanced['checker_output']['origin'], 'validator')
        self.assertEqual(len(self.store.calls(trial_id=self.tid)), 5)

    def candidate(self):
        output = response_fixture('analysis')
        event_id = self.frozen['cases'][0]['evidence']['events'][0]['event_id']
        output['claims'] = [{'claim_id': 'claim-test', 'kind': 'observation',
                             'text': 'Synthetic claim fixture only.', 'event_ids': [event_id]}]
        receipt = self.prepare_analysis(output)
        checked = {'schema_version': 1, 'stage_key': 'analysis',
                   'narrative_sha256': receipt['response_sha256'], 'origin': 'typesafe',
                   'model_requested': 'synthetic-checker-1', 'model_returned': None,
                   'results': [{'claim_id': 'claim-test', 'choice': 'insufficient',
                                'confidence': None, 'probabilities': None, 'origin': 'typesafe', 'reason': None}],
                   'usage': {'input_tokens': None, 'output_tokens': None,
                             'cached_input_tokens': None, 'reasoning_tokens': None},
                   'elapsed_ms': 5}
        return output, receipt, checked

    def reserve_checker(self, checked):
        team = self.frozen['experiment']['teams'][0]
        with self.store.connection() as db:
            authorization = _unpack(db.execute("SELECT * FROM approvals WHERE kind='authorization'").fetchone())
        auth = {k: v for k, v in authorization.items() if k not in ('kind', 'authorization_sha256')}
        auth['approval_id'] = 'checker-test-authorization'
        auth['model_sha256s'].append(digest_bytes(canonical_bytes(team['evidence_checker'])))
        authorization_sha = self.store.record_authorization(auth)
        spec = call_fixture(self.store, self.frozen, self.trial, authorization_sha, 'analysis')
        spec.update(component='evidence_checker', model=team['evidence_checker'])
        self.store.reserve_call('checker-1', digest_bytes(canonical_bytes(spec)), spec)
        checker_receipt = receipt_fixture(self.store, self.frozen, 'checker-1', spec)
        ref = self.store.write_artifact(self.tid, 'checker', canonical_bytes(checked))
        checker_receipt.update(response_artifact=ref, response_sha256=ref['sha256'])
        self.register_checker(ref)
        return checker_receipt

    def test_checker_for_other_narrative_cannot_advance(self):
        _, receipt, checked = self.candidate()
        checked['narrative_sha256'] = 'f' * 64
        checker_receipt = self.reserve_checker(checked)
        self.store.finish_call('checker-1', checker_receipt)
        self.assert_code('digest_mismatch', self.advance_stage, 'analysis')
        self.assertEqual(ledger_snapshot(self.store, self.trial)['tasks']['analysis']['status'], 'review')

    def test_checker_cannot_omit_candidate_claim(self):
        _, receipt, checked = self.candidate()
        checked['results'] = []
        checker_receipt = self.reserve_checker(checked)
        self.store.finish_call('checker-1', checker_receipt)
        self.assert_code('scope_mismatch', self.advance_stage, 'analysis')

    def test_checker_cannot_repeat_candidate_claim(self):
        _, receipt, checked = self.candidate()
        checked['results'].append(copy.deepcopy(checked['results'][0]))
        checker_receipt = self.reserve_checker(checked)
        self.store.finish_call('checker-1', checker_receipt)
        self.assert_code('scope_mismatch', self.advance_stage, 'analysis')

    def test_checker_schema_rejects_boolean_version(self):
        _, receipt, checked = self.candidate()
        checked['schema_version'] = True
        checker_receipt = self.reserve_checker(checked)
        self.store.finish_call('checker-1', checker_receipt)
        self.assert_code('invalid_checker', self.advance_stage, 'analysis')

    def test_checkable_claims_block_without_same_attempt_completed_checker(self):
        output, receipt, checked = self.candidate()
        self.assert_code('checker_incomplete', self.advance_stage, 'analysis')
        checker_receipt = self.reserve_checker(checked)
        ref = checker_receipt['response_artifact']
        self.assert_code('incomplete_receipt', self.advance_stage, 'analysis')
        self.store.finish_call('checker-1', checker_receipt)
        advanced = self.advance_stage('analysis')
        self.assertEqual(advanced['output'], output)
        self.assertEqual(advanced['checker_output'], checked)
        mirrored = [e for e in self.benchmark_events('stage_auto_advanced')
                    if e['payload']['stage_key'] == 'analysis']
        self.assertEqual(mirrored[0]['payload']['checker_artifact'], ref)
        self.assertEqual(mirrored[0]['payload']['checker_receipt_sha256'],
                         digest_bytes(canonical_bytes(checker_receipt)))


if __name__ == '__main__':
    unittest.main()

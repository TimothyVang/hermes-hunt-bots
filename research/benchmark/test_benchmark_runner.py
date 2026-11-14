"""Offline storage regressions; synthetic receipts are not benchmark results."""
import contextlib
import copy
from concurrent.futures import ThreadPoolExecutor
import io
import json
import multiprocessing
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest

import benchmark_runner
from benchmark import main as benchmark_main
from benchmark_contracts import (
    BenchmarkError, ROLE_IDS, STAGE_KEYS, canonical_bytes, digest_bytes, load_json,
)
from benchmark_paths import FRAMEWORK, source_root
from benchmark_store import BenchmarkStore, STAGE_ROLES
from workflows import ROLES

FIXTURES = Path(__file__).resolve().parent / 'benchmarks'
STAMP = '2026-01-01T00:00:00+00:00'
EXPIRES = '2099-01-01T00:00:00+00:00'
HASH = '1' * 64


def frozen_fixture():
    """A complete frozen synthetic experiment reusable by reporting tests."""
    experiment = load_json(FIXTURES / 'examples' / 'experiment.json')
    experiment['repetitions'] = 1
    coverage = load_json(FIXTURES / 'coverage.json')
    workflow = load_json(FIXTURES / 'team-workflow.json')
    prompt = (FIXTURES / 'prompt-contract.txt').read_bytes().decode('utf-8')
    experiment['coverage_sha256'] = digest_bytes(canonical_bytes(coverage))
    experiment['workflow_sha256'] = digest_bytes(canonical_bytes(workflow))
    experiment['prompt_contract_sha256'] = digest_bytes(prompt.encode('utf-8'))
    cases = []
    for ref in experiment['scenario_refs']:
        scenario = load_json(FIXTURES / ref['scenario'])
        evidence = load_json(FIXTURES / ref['evidence'])
        cases.append({'scenario': scenario, 'evidence': evidence,
                      'public_files': copy.deepcopy(evidence['files'])})
    return dict(experiment=experiment, coverage=coverage, workflow=workflow,
                prompt_contract=prompt, cases=cases,
                role_instructions={role: 'Synthetic offline test role purpose.' for role in ROLE_IDS},
                created_utc=STAMP, execution='framework-managed')


def trial_fixture(store, frozen, trial_id='trial-a', repetition=1):
    case = frozen['cases'][0]
    public_root = (FIXTURES / frozen['experiment']['scenario_refs'][0]['evidence']).parent
    artifacts = {f['path']: store.write_artifact(trial_id, 'public', (public_root / f['path']).read_bytes())
                 for f in case['evidence']['files']}
    spec = dict(trial_id=trial_id, experiment_id=frozen['experiment']['experiment_id'],
                case_id=case['evidence']['case_id'], scenario_id=case['scenario']['scenario_id'],
                team_id=frozen['experiment']['teams'][0]['team_id'], repetition=repetition,
                workflow_id=1, task_mapping={key: index + 1 for index, key in enumerate(STAGE_KEYS)},
                case_evidence_sha256=case['scenario']['evidence_manifest_sha256'],
                status='pending', created_utc=STAMP, public_artifacts=artifacts)
    store.create_trial(spec)
    return spec


def authorize_fixture(store, frozen, trial, approval_id='authorization-a'):
    models = frozen['experiment']['teams'][0]['roles'].values()
    spec = dict(approval_id=approval_id, experiment_id=trial['experiment_id'],
                trial_id=trial['trial_id'], campaign_id=None, by='test-only-human',
                note='Synthetic test authority; no actual transport.', created_utc=STAMP,
                expires_utc=EXPIRES, evidence_sha256=trial['case_evidence_sha256'],
                model_sha256s=sorted({digest_bytes(canonical_bytes(m)) for m in models}),
                manifest_sha256=None, phases=[])
    return store.record_authorization(spec)


def call_fixture(store, frozen, trial, authorization_sha256, stage='scope', attempt=1):
    prompt = store.write_artifact(trial['trial_id'], 'prompt', b'Synthetic test prompt; no transport.')
    role = STAGE_ROLES[stage]
    return dict(schema_version=1, trial_id=trial['trial_id'], stage_key=stage,
                attempt_index=attempt, component='narrative', prompt_artifact=prompt,
                input_sha256=prompt['sha256'], workflow_sha256=frozen['experiment']['workflow_sha256'],
                prompt_contract_sha256=frozen['experiment']['prompt_contract_sha256'],
                evidence_sha256=trial['case_evidence_sha256'], adapter_sha256=HASH,
                executable_sha256=HASH, executable_version='synthetic-test-1',
                authorization_sha256=authorization_sha256,
                model=copy.deepcopy(frozen['experiment']['teams'][0]['roles'][role]), role=role)


def response_fixture(stage='scope'):
    output = dict(schema_version=1, stage_key=stage, summary='Synthetic transport test only.',
                  claims=[], findings=[], hypotheses=[], gaps=[], limitations=[],
                  requested_decision='approve')
    if stage == 'handoff':
        output.update(chain_edges=[], assessment_answers=[])
    return output


def receipt_fixture(store, frozen, call_id, spec, status='completed'):
    ref = store.write_artifact(spec['trial_id'], 'response', canonical_bytes(response_fixture(spec['stage_key']))) if status == 'completed' else None
    usage = dict(input_tokens=None, output_tokens=None, cached_input_tokens=None, reasoning_tokens=None)
    return dict(schema_version=1, call_id=call_id, fingerprint=digest_bytes(canonical_bytes(spec)),
                status=status, model_requested=spec['model']['model_requested'], model_returned=None,
                identity_status='unreported', provider=spec['model']['provider'],
                deployment=frozen['experiment']['teams'][0]['deployment'], role=spec['role'],
                stage_key=spec['stage_key'], prompt_sha256=spec['input_sha256'],
                response_sha256=ref['sha256'] if ref else None,
                start_utc=STAMP, end_utc=STAMP, elapsed_ms=5,
                timeout_seconds=spec['model']['timeout_seconds'],
                max_calls=frozen['experiment']['budgets']['max_calls_per_trial'],
                max_output_bytes=frozen['experiment']['budgets']['max_response_bytes'],
                finish_reason=None, usage=usage, estimated_usage=copy.deepcopy(usage),
                cost=dict(api_cost_usd=None,
                          pricing_snapshot_sha256=digest_bytes(canonical_bytes(frozen['experiment']['pricing_snapshot'])),
                          cost_basis='unknown', local_compute_cost_usd=None, local_energy_cost_usd=None,
                          bound_exceeded=False),
                failure_reason=None if status == 'completed' else 'dispatch_interrupted',
                response_artifact=ref)


def _reserve_in_child(root, spec):
    BenchmarkStore(root).reserve_call('child-call', digest_bytes(canonical_bytes(spec)), spec)
    # Process exits without finish; the reserved record is authoritative.


class BenchmarkStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'state'
        self.store = BenchmarkStore(self.root, create=True)
        self.frozen = frozen_fixture()
        self.eid = self.frozen['experiment']['experiment_id']
        self.store.create_experiment(self.frozen)
        self.trial = trial_fixture(self.store, self.frozen)
        self.authorization = authorize_fixture(self.store, self.frozen, self.trial)
        self.spec = call_fixture(self.store, self.frozen, self.trial, self.authorization)
        self.fingerprint = digest_bytes(canonical_bytes(self.spec))

    def assert_code(self, code, operation, *args, **kwargs):
        with self.assertRaises(BenchmarkError) as raised:
            operation(*args, **kwargs)
        self.assertEqual(raised.exception.code, code)
        return raised.exception

    def reserve(self):
        return self.store.reserve_call('call-a', self.fingerprint, self.spec)

    def test_concurrent_reservation_has_exactly_one_owner(self):
        barrier = threading.Barrier(2)

        def contender():
            store = BenchmarkStore(self.root)
            barrier.wait()
            try:
                return store.reserve_call('call-a', self.fingerprint, self.spec)
            except BenchmarkError as exc:
                return exc.code

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: contender(), range(2)))
        self.assertCountEqual(results, [None, 'previous_dispatch_unknown'])
        events = self.store.snapshot(self.eid)['events']
        self.assertEqual(sum(e['kind'] == 'dispatch_reserved' for e in events), 1)

    def test_completed_and_failed_receipts_are_reused_without_dispatch(self):
        self.assertIsNone(self.reserve())
        receipt = receipt_fixture(self.store, self.frozen, 'call-a', self.spec)
        self.store.finish_call('call-a', receipt)
        self.assertEqual(self.reserve(), receipt)
        second = call_fixture(self.store, self.frozen, self.trial, self.authorization, stage='endpoint_evidence')
        fingerprint = digest_bytes(canonical_bytes(second))
        self.store.reserve_call('call-b', fingerprint, second)
        failed = receipt_fixture(self.store, self.frozen, 'call-b', second, 'failed')
        self.store.finish_call('call-b', failed)
        self.assertEqual(self.store.reserve_call('call-b', fingerprint, second), failed)

    def test_changed_fingerprint_and_unique_attempt_conflict(self):
        self.reserve()
        changed = dict(self.spec, executable_version='changed')
        self.assert_code('fingerprint_conflict', self.store.reserve_call,
                         'call-a', digest_bytes(canonical_bytes(changed)), changed)
        self.assert_code('fingerprint_conflict', self.store.reserve_call,
                         'different-id', self.fingerprint, self.spec)
        self.assert_code('fingerprint_conflict', self.store.reserve_call,
                         'call-a', HASH, self.spec)

    def test_unknown_retains_reservation_and_blocks_new_attempt(self):
        self.reserve()
        unknown = receipt_fixture(self.store, self.frozen, 'call-a', self.spec, 'unknown')
        self.store.finish_call('call-a', unknown)
        self.assert_code('previous_dispatch_unknown', self.reserve)
        second = dict(self.spec, attempt_index=2)
        self.assert_code('previous_dispatch_unknown', self.store.reserve_call,
                         'call-b', digest_bytes(canonical_bytes(second)), second)

    def test_process_exit_after_reservation_does_not_allow_redispatch(self):
        process = multiprocessing.get_context('spawn').Process(target=_reserve_in_child, args=(str(self.root), self.spec))
        process.start()
        process.join(20)
        if process.is_alive():
            process.terminate()
            process.join()
            self.fail('Synthetic reservation process failed to exit')
        self.assertEqual(process.exitcode, 0)
        reopened = BenchmarkStore(self.root)
        self.assert_code('previous_dispatch_unknown', reopened.reserve_call,
                         'child-call', self.fingerprint, self.spec)

    def test_conditional_finish_and_fingerprint(self):
        self.reserve()
        receipt = receipt_fixture(self.store, self.frozen, 'call-a', self.spec)
        changed = dict(receipt, fingerprint=HASH)
        self.assert_code('fingerprint_conflict', self.store.finish_call, 'call-a', changed)
        self.store.finish_call('call-a', receipt)
        self.assert_code('state_conflict', self.store.finish_call, 'call-a', receipt)

    def test_reconciliation_requires_artifacts_and_never_dispatches_or_approves(self):
        self.reserve()
        evidence = self.store.write_artifact(self.trial['trial_id'], 'reconciliation', b'Test-only inspected effect evidence.')
        receipt = receipt_fixture(self.store, self.frozen, 'call-a', self.spec, 'failed')
        corrupt = dict(evidence, sha256=HASH, path='artifacts/reconciliation/' + HASH)
        with self.assertRaises(BenchmarkError):
            self.store.reconcile_call('call-a', 'test-human', 'Test evidence inspection.', 'failed', corrupt, receipt)
        self.store.reconcile_call('call-a', 'test-human', 'Test evidence inspection.', 'failed', evidence, receipt)
        snapshot = self.store.snapshot(self.eid)
        self.assertEqual(len(snapshot['calls']), 1)
        self.assertEqual([a['kind'] for a in snapshot['approvals']], ['authorization'])
        self.assertEqual(sum(e['kind'] == 'reconciliation_recorded' for e in snapshot['events']), 1)
        retry = dict(self.spec, attempt_index=2)
        self.assertIsNone(self.store.reserve_call('retry-call', digest_bytes(canonical_bytes(retry)), retry))

    def test_completed_reconciliation_needs_valid_response(self):
        self.reserve()
        evidence = self.store.write_artifact(self.trial['trial_id'], 'reconciliation', b'Test-only inspection.')
        receipt = receipt_fixture(self.store, self.frozen, 'call-a', self.spec)
        receipt['response_artifact'] = None
        self.assert_code('incomplete_receipt', self.store.reconcile_call, 'call-a', 'test-human',
                         'Test inspection.', 'completed', evidence, receipt)

    def test_artifacts_are_content_addressed_and_corruption_is_detected(self):
        one = self.store.write_artifact(self.trial['trial_id'], 'test', b'one')
        self.assertEqual(self.store.write_artifact(self.trial['trial_id'], 'test', b'one'), one)
        two = self.store.write_artifact(self.trial['trial_id'], 'test', b'two')
        self.assertNotEqual(one['path'], two['path'])
        path = self.root / 'trials' / self.trial['trial_id'] / one['path']
        path.write_bytes(b'bad')
        self.assert_code('artifact_corrupt', self.store.read_artifact, self.trial['trial_id'], one)
        # A corrupt/partial file is atomically repaired from the authoritative bytes.
        self.assertEqual(self.store.write_artifact(self.trial['trial_id'], 'test', b'one'), one)
        self.assertEqual(self.store.read_artifact(self.trial['trial_id'], one), b'one')

    def test_receipt_rejects_secret_fields_unknown_usage_and_false_identity(self):
        self.reserve()
        receipt = receipt_fixture(self.store, self.frozen, 'call-a', self.spec)
        for key in ('headers', 'stderr', 'environment', 'hidden_reasoning'):
            invalid = dict(receipt, **{key: 'must-not-appear'})
            error = self.assert_code('unknown_field', self.store.finish_call, 'call-a', invalid)
            self.assertNotIn('must-not-appear', str(error))
        invalid = copy.deepcopy(receipt)
        invalid['usage']['input_tokens'] = False
        self.assert_code('invalid_number', self.store.finish_call, 'call-a', invalid)
        invalid = dict(receipt, model_returned='other-model', identity_status='reported_match')
        self.assert_code('model_identity_mismatch', self.store.finish_call, 'call-a', invalid)
        self.store.finish_call('call-a', receipt)
        saved = self.store.calls()[0]['receipt']
        self.assertIsNone(saved['usage']['input_tokens'])
        self.assertIsNone(saved['cost']['api_cost_usd'])

    def test_raw_database_corruption_fails_snapshot(self):
        with self.store.connection(immediate=True) as db:
            db.execute('UPDATE trials SET data=? WHERE trial_id=?', (b'{}', self.trial['trial_id']))
        self.assert_code('corrupt_state', self.store.snapshot, self.eid)

    def test_missing_dispatch_event_fails_snapshot(self):
        self.reserve()
        with self.store.connection(immediate=True) as db:
            db.execute("DELETE FROM events WHERE kind='dispatch_reserved'")
        self.assert_code('incomplete_snapshot', self.store.snapshot, self.eid)

    def test_missing_public_artifact_fails_snapshot(self):
        ref = next(iter(self.trial['public_artifacts'].values()))
        (self.root / 'trials' / self.trial['trial_id'] / ref['path']).unlink()
        with self.assertRaises(BenchmarkError):
            self.store.snapshot(self.eid)

    def test_duplicate_store_experiment_and_trial_are_refused(self):
        self.assert_code('already_exists', BenchmarkStore, self.root, create=True)
        self.assert_code('already_exists', self.store.create_experiment, self.frozen)
        self.assert_code('already_exists', self.store.create_trial, self.trial)

    def test_authorization_is_bound_not_just_supplied_digest(self):
        spec = dict(self.spec, authorization_sha256=HASH)
        self.assert_code('authorization_required', self.store.reserve_call, 'call-a', digest_bytes(canonical_bytes(spec)), spec)
        spec = copy.deepcopy(self.spec)
        spec['model']['timeout_seconds'] = 1
        self.assert_code('fingerprint_conflict', self.store.reserve_call, 'call-a', digest_bytes(canonical_bytes(spec)), spec)
        spec = dict(self.spec, reserved_api_cost_usd=0)
        self.assert_code('unknown_field', self.store.reserve_call, 'call-a', digest_bytes(canonical_bytes(spec)), spec)

    def test_budget_failure_rolls_back_reservation_and_event(self):
        # A second independent experiment freezes a single-call budget.
        other = copy.deepcopy(self.frozen)
        other['experiment']['experiment_id'] = 'budget-test'
        other['experiment']['budgets']['max_calls_per_trial'] = 1
        self.store.create_experiment(other)
        trial = trial_fixture(self.store, other, 'budget-trial')
        auth = authorize_fixture(self.store, other, trial, 'budget-auth')
        first = call_fixture(self.store, other, trial, auth)
        self.store.reserve_call('budget-call', digest_bytes(canonical_bytes(first)), first)
        second = call_fixture(self.store, other, trial, auth, stage='endpoint_evidence')
        self.assert_code('budget_exceeded', self.store.reserve_call, 'blocked-call', digest_bytes(canonical_bytes(second)), second)
        snapshot = self.store.snapshot('budget-test')
        self.assertEqual(len(snapshot['calls']), 1)
        self.assertEqual(sum(e['kind'] == 'dispatch_reserved' for e in snapshot['events']), 1)

    def test_timeout_reservation_uses_frozen_model_limit(self):
        other = copy.deepcopy(self.frozen)
        other['experiment']['experiment_id'] = 'time-budget-test'
        other['experiment']['budgets']['max_active_seconds_per_trial'] = 30
        self.store.create_experiment(other)
        trial = trial_fixture(self.store, other, 'time-trial')
        auth = authorize_fixture(self.store, other, trial, 'time-auth')
        first = call_fixture(self.store, other, trial, auth)
        self.store.reserve_call('time-call', digest_bytes(canonical_bytes(first)), first)
        second = call_fixture(self.store, other, trial, auth, stage='endpoint_evidence')
        self.assert_code('budget_exceeded', self.store.reserve_call, 'time-blocked', digest_bytes(canonical_bytes(second)), second)

    def test_auto_advance_mirror_binds_completed_output_and_is_idempotent(self):
        self.reserve()
        receipt = receipt_fixture(self.store, self.frozen, 'call-a', self.spec)
        self.store.finish_call('call-a', receipt)
        payload = dict(stage_key='scope', attempt_index=1, ledger_event_id=9, ledger_submit_event_id=8,
                       ledger_event_sha256=HASH, output_sha256=receipt['response_sha256'],
                       output_artifact=receipt['response_artifact'], checker_artifact=None,
                       checker_receipt_sha256=None, review_policy='auto_advance')
        first = self.store.record_auto_advance(self.trial['trial_id'], 'call-a', payload)
        self.assertEqual((first['kind'], first['actor']), ('stage_auto_advanced', 'benchmark-auto-advance'))
        self.assertEqual(self.store.record_auto_advance(self.trial['trial_id'], 'call-a', payload), first)
        self.assert_code('fingerprint_conflict', self.store.record_auto_advance, self.trial['trial_id'],
                         'call-a', dict(payload, ledger_event_sha256='2' * 64))
        self.assert_code('stage_mismatch', self.store.record_auto_advance, self.trial['trial_id'],
                         'call-a', dict(payload, stage_key='endpoint_evidence'))
        self.assert_code('invalid_choice', self.store.record_auto_advance, self.trial['trial_id'],
                         'call-a', dict(payload, review_policy='every_stage'))
        snapshot = self.store.snapshot(self.eid)
        self.assertEqual(sum(e['kind'] == 'stage_auto_advanced' for e in snapshot['events']), 1)
        self.assertEqual([a['kind'] for a in snapshot['approvals']], ['authorization'])

    def test_state_and_event_rollback_together(self):
        before = self.store.snapshot(self.eid)
        original = self.store.event

        def rejected_event(*args, **kwargs):
            raise BenchmarkError('test_failure', 'event')

        self.store.event = rejected_event
        try:
            self.assert_code('test_failure', self.reserve)
        finally:
            self.store.event = original
        self.assertEqual(self.store.snapshot(self.eid), before)

    def test_empty_experiment_still_checks_frozen_integrity(self):
        empty = copy.deepcopy(self.frozen)
        empty['experiment']['experiment_id'] = 'empty-experiment'
        self.store.create_experiment(empty)
        self.assert_code('incomplete_snapshot', self.store.snapshot, 'empty-experiment')
        with self.store.connection(immediate=True) as db:
            db.execute('UPDATE experiments SET sha256=? WHERE experiment_id=?', (HASH, 'empty-experiment'))
        self.assert_code('corrupt_state', self.store.snapshot, 'empty-experiment')

    def test_campaign_reservation_finish_unknown_and_reconciliation(self):
        manifest = dict(schema_version=1, campaign_id='campaign-a', recipe_id='windows-discovery-v1',
                        range_kit_sha256=HASH, targets=[{'asset_id': 'test-asset'}],
                        executor={}, collectors=[], authorization={},
                        limits=dict(max_phase_seconds=10, max_campaign_seconds=60,
                                    max_export_bytes=1024, max_cloud_cost_usd=None,
                                    latest_cleanup_utc=EXPIRES))
        campaign = dict(schema_version=1, campaign_id='campaign-a', experiment_id=self.eid,
                        manifest=manifest, manifest_sha256=digest_bytes(canonical_bytes(manifest)),
                        status='draft', cleanup_status='not_needed', owned_process=None,
                        created_utc=STAMP, updated_utc=STAMP)
        self.store.create_campaign(campaign)
        self.assertEqual(self.store.get_campaign('campaign-a'), campaign)
        advanced = dict(campaign, status='preflight_passed')
        self.store.update_campaign('campaign-a', advanced, 'draft', 'not_needed')
        self.assert_code('state_conflict', self.store.update_campaign,
                         'campaign-a', advanced, 'draft', 'not_needed')
        auth_spec = dict(approval_id='campaign-auth', experiment_id=self.eid, trial_id=None,
                         campaign_id='campaign-a', by='test-human', note='Synthetic campaign; no lab action.',
                         created_utc=STAMP, expires_utc=EXPIRES, evidence_sha256=None,
                         model_sha256s=[], manifest_sha256=campaign['manifest_sha256'], phases=['run'])
        auth = self.store.record_authorization(auth_spec)
        spec = dict(schema_version=1, experiment_id=self.eid, manifest_sha256=campaign['manifest_sha256'],
                    authorization_sha256=auth, executor_sha256=HASH, input_sha256=HASH,
                    executor_version='synthetic-1', target_sha256=HASH, timeout_seconds=10)
        fingerprint = digest_bytes(canonical_bytes(spec))
        reserve = lambda: self.store.reserve_campaign_step('campaign-a', 'run', 'step-a', fingerprint, spec)
        self.assertIsNone(reserve())
        self.assert_code('previous_dispatch_unknown', reserve)
        evidence = dict(observed_target_sha256=HASH, effect_verified=True,
                        source_receipt_sha256=HASH, observed_utc=STAMP)
        receipt = dict(schema_version=1, fingerprint=fingerprint, status='completed',
                       campaign_id='campaign-a', phase='run', step_id='step-a',
                       executor_sha256=HASH, executor_version='synthetic-1', execution_outcome='succeeded',
                       start_utc=STAMP, end_utc=STAMP, elapsed_ms=1, exit_code=0,
                       observed_target_sha256=HASH, effect_verified=True,
                       evidence_sha256=digest_bytes(canonical_bytes(evidence)), failure_reason=None)
        self.store.reconcile_campaign_step('campaign-a', 'run', 'step-a', 'test-human',
                                           'Synthetic inspected effect.', evidence, receipt)
        self.assertEqual(reserve(), receipt)
        self.assertEqual(len(self.store.snapshot(self.eid)['campaigns']), 1)
        self.assertEqual(len(self.store.snapshot(self.eid)['campaign_states']), 1)
        self.store.reserve_campaign_step('campaign-a', 'run', 'step-b', fingerprint, spec)
        failed = dict(receipt, step_id='step-b', status='failed', execution_outcome='failed',
                      effect_verified=False, evidence_sha256=None, failure_reason='execution_failed')
        self.store.finish_campaign_step('campaign-a', 'run', 'step-b', failed)
        self.assertEqual(self.store.reserve_campaign_step('campaign-a', 'run', 'step-b', fingerprint, spec), failed)
        self.store.reserve_campaign_step('campaign-a', 'run', 'step-c', fingerprint, spec)
        unknown = dict(failed, step_id='step-c', status='unknown', execution_outcome='unknown',
                       failure_reason='dispatch_interrupted')
        self.store.finish_campaign_step('campaign-a', 'run', 'step-c', unknown)
        self.assert_code('previous_dispatch_unknown', self.store.reserve_campaign_step,
                         'campaign-a', 'run', 'step-c', fingerprint, spec)
        changed = dict(spec, executor_version='changed-version')
        self.assert_code('fingerprint_conflict', self.store.reserve_campaign_step,
                         'campaign-a', 'run', 'step-b', digest_bytes(canonical_bytes(changed)), changed)
        self.assertEqual(len(self.store.snapshot(self.eid)['campaigns']), 3)
        authorized = dict(advanced, status='authorized')
        self.store.update_campaign('campaign-a', authorized, 'preflight_passed', 'not_needed')
        running = dict(authorized, status='running', cleanup_status='pending')
        self.store.update_campaign('campaign-a', running, 'authorized', 'not_needed')
        identity = {'pid': 123, 'creation_utc': '2026-01-01T00:00:00.1234567Z',
                    'process_group_id': 'Local\\benchmark-test-job'}
        self.assert_code('state_conflict', self.store.update_campaign, 'campaign-a',
                         dict(running, owned_process=identity), 'running', 'pending')
        self.store.reserve_campaign_step('campaign-a', 'run', 'step-d', fingerprint, spec)
        self.store.record_owned_process('campaign-a', 'run', 'step-d', identity)
        stopped, captured = self.store.request_campaign_stop('campaign-a')
        self.assertEqual(captured, identity)
        self.assertEqual(stopped['owned_process'], identity)
        self.assertEqual((stopped['status'], stopped['cleanup_status']), ('unknown', 'unknown'))
        inspection = canonical_bytes({'process_stopped': True, 'observation': 'Synthetic inspection.'})
        self.assert_code('process_inspection_required', self.store.reconcile_campaign_state,
                         'campaign-a', 'unknown', 'test-human', 'Inspected.', inspection)
        self.store.clear_owned_process('campaign-a', 'step-d', {'local_stopped': True, 'source': 'stop_owned',
                                                                'remote_effects': 'unknown'})
        self.assert_code('reconciliation_required', self.store.reconcile_campaign_state,
                         'campaign-a', 'unknown', 'test-human', 'Inspected.', inspection)
        observed = dict(evidence, effect_verified=False)
        for step in ('step-c', 'step-d'):
            resolved = dict(failed, step_id=step, evidence_sha256=digest_bytes(canonical_bytes(observed)))
            self.store.reconcile_campaign_step('campaign-a', 'run', step, 'test-human',
                                               'Synthetic failed effect inspection.', observed, resolved)
        recovered = self.store.reconcile_campaign_state(
            'campaign-a', 'unknown', 'test-human', 'Collection only.', inspection)
        self.assertEqual((recovered['status'], recovered['cleanup_status']),
                         ('awaiting_collection', 'unknown'))
        self.assert_code('state_conflict', self.store.update_campaign,
                         'campaign-a', dict(recovered, status='running'),
                         'awaiting_collection', 'unknown')
        self.assertEqual(self.store.snapshot(self.eid)['campaign_states'][0], recovered)

    def test_paid_cost_reservations_survive_unknown_receipts(self):
        frozen = copy.deepcopy(self.frozen)
        frozen['experiment']['experiment_id'] = 'paid-budget'
        team = frozen['experiment']['teams'][0]
        team['deployment'] = 'cloud'
        # Paid status follows the route, never the deployment label.
        for role in team['roles'].values():
            role['base_url'] = 'https://models.example.test/v1'
        model = team['roles']['framework-coordinator']
        frozen['experiment']['pricing_snapshot']['rates'] = [
            dict(provider=model['provider'], model_requested=model['model_requested'],
                 input_per_million=1, output_per_million=1)]
        frozen['experiment']['budgets'].update(max_api_cost_usd=1, per_call_cost_bound_usd=0.75)
        self.store.create_experiment(frozen)
        trial = trial_fixture(self.store, frozen, 'paid-trial')
        auth = authorize_fixture(self.store, frozen, trial, 'paid-auth')
        first = call_fixture(self.store, frozen, trial, auth)
        self.store.reserve_call('paid-call', digest_bytes(canonical_bytes(first)), first)
        unknown = receipt_fixture(self.store, frozen, 'paid-call', first, 'unknown')
        unknown['cost'].update(api_cost_usd=0, cost_basis='reported')
        self.store.finish_call('paid-call', unknown)
        second = call_fixture(self.store, frozen, trial, auth, stage='endpoint_evidence')
        self.assert_code('budget_exceeded', self.store.reserve_call,
                         'paid-blocked', digest_bytes(canonical_bytes(second)), second)

    def test_snapshot_rejects_incomplete_repetition_schedule(self):
        frozen = copy.deepcopy(self.frozen)
        frozen['experiment']['experiment_id'] = 'missing-repetition'
        frozen['experiment']['repetitions'] = 2
        self.store.create_experiment(frozen)
        trial_fixture(self.store, frozen, 'first-repetition')
        self.assert_code('incomplete_snapshot', self.store.snapshot, 'missing-repetition')
        trial_fixture(self.store, frozen, 'second-repetition', repetition=2)
        self.assertEqual(len(self.store.snapshot('missing-repetition')['trials']), 2)

    def test_expired_authorization_is_not_recorded(self):
        spec = dict(approval_id='expired-auth', experiment_id=self.eid,
                    trial_id=self.trial['trial_id'], campaign_id=None, by='test-human',
                    note='Expired synthetic authority.', created_utc='2000-01-01T00:00:00+00:00',
                    expires_utc='2000-01-02T00:00:00+00:00',
                    evidence_sha256=self.trial['case_evidence_sha256'],
                    model_sha256s=[digest_bytes(canonical_bytes(self.spec['model']))],
                    manifest_sha256=None, phases=[])
        self.assert_code('authorization_expired', self.store.record_authorization, spec)
        self.assertEqual(len(self.store.snapshot(self.eid)['approvals']), 1)

    def test_completed_trial_requires_every_stage_auto_advanced(self):
        completed = dict(self.trial, status='completed')
        self.assert_code('incomplete_snapshot', self.store.update_trial,
                         self.trial['trial_id'], completed, 'completed')
        self.assertEqual(self.store.get_trial(self.trial['trial_id'])['status'], 'pending')

    def test_zero_and_oversized_prompt_cannot_reserve(self):
        empty = self.store.write_artifact(self.trial['trial_id'], 'prompt', b'')
        invalid = dict(self.spec, prompt_artifact=empty, input_sha256=empty['sha256'])
        self.assert_code('budget_exceeded', self.store.reserve_call,
                         'empty-prompt', digest_bytes(canonical_bytes(invalid)), invalid)
        cap = self.frozen['experiment']['budgets']['max_prompt_bytes']
        huge = self.store.write_artifact(self.trial['trial_id'], 'prompt', b'x' * (cap + 1))
        invalid = dict(self.spec, prompt_artifact=huge, input_sha256=huge['sha256'])
        self.assert_code('budget_exceeded', self.store.reserve_call,
                         'oversized-prompt', digest_bytes(canonical_bytes(invalid)), invalid)


# Runs init and status on a bundle under an open() audit hook and reports every
# benchmark or framework file (module or data) the run opened; never a model or lab call.
AUDITED_RUN = '''
import contextlib, io, json, os, sys
here, framework, state, bundle, experiment_id = sys.argv[1:6]
sys.path.insert(0, here)
opened = set()
roots = [(os.path.normcase(root) + os.sep, root) for root in (here, framework)]


def hook(event, args):
    if event == 'open' and isinstance(args[0], (str, bytes, os.PathLike)):
        path = os.path.abspath(os.fsdecode(args[0]))
        for prefix, root in roots:
            if os.path.normcase(path).startswith(prefix) and os.path.isfile(path):
                opened.add(os.path.relpath(path, root).replace(os.sep, '/'))


sys.addaudithook(hook)
from benchmark import main
from benchmark_contracts import canonical_bytes, digest_bytes, load_json
novel_wf = os.path.join(here, 'benchmarks', 'team-workflow-novel-apt.json')
novel_exp_path = os.path.join(bundle, 'examples', 'experiment-novel-apt.json')
novel_exp = dict(load_json(os.path.join(bundle, 'examples', 'experiment.json')),
                 experiment_id='exp-novel-apt-audit',
                 workflow_sha256=digest_bytes(canonical_bytes(load_json(novel_wf))))
with open(novel_exp_path, 'wb') as out:
    out.write(canonical_bytes(novel_exp))
with contextlib.redirect_stdout(io.StringIO()):
    codes = [main(['--state-root', state, 'init', '--experiment',
                   os.path.join(bundle, 'examples', 'experiment-graduated.json'),
                   '--bundle-root', bundle, '--truth', os.path.join(bundle, 'fixtures')]),
             main(['--state-root', state, 'status', '--experiment', experiment_id]),
             main(['validate', '--experiment', novel_exp_path, '--bundle-root', bundle,
                   '--workflow', 'benchmarks/team-workflow-novel-apt.json'])]
print(json.dumps({'codes': codes, 'opened': sorted(opened)}))
'''


class SourceSnapshotTests(unittest.TestCase):
    """`snapshot-source` copies the exact sources a long run executes; offline."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)

    def cli(self, *args):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
            code = benchmark_main([str(arg) for arg in args])
        return code, output.getvalue()

    def bundle(self):
        """The graduated example as user input, copied outside the source tree."""
        bundle = Path(self.temp.name) / 'bundle'
        for name in ('examples', 'fixtures'):
            shutil.copytree(str(FIXTURES / name), str(bundle / name))
        experiment = load_json(bundle / 'examples' / 'experiment-graduated.json')
        return bundle, experiment['experiment_id']

    def test_declared_lists_match_every_file_init_and_status_open(self):
        here = Path(benchmark_runner.__file__).resolve().parent
        bundle, experiment_id = self.bundle()
        environment = {key: value for key, value in os.environ.items() if key != 'PYTHONPATH'}
        result = subprocess.run([sys.executable, '-B', '-c', AUDITED_RUN, str(here), str(FRAMEWORK),
                                 str(Path(self.temp.name) / 'state'), str(bundle), experiment_id],
                                capture_output=True, text=True, cwd=self.temp.name, env=environment)
        self.assertEqual(result.returncode, 0, result.stderr)
        audit = json.loads(result.stdout)
        self.assertEqual(audit['codes'], [0, 0, 0])
        modules, data = set(), set()
        for path in audit['opened']:
            parent, name = path.rpartition('/')[::2]
            if parent.endswith('__pycache__'):  # a cached module stands for its source
                modules.add((parent[:-len('__pycache__')] + name.split('.')[0] + '.py').lstrip('/'))
            elif name.endswith('.py'):
                modules.add(path)
            else:
                data.add(path)
        # Every opened data file is declared, and every declared one is used:
        # the ledger role prompts by `bot.py run`, which the snapshot dispatch
        # test (test_benchmark_team) exercises end to end; the rest here.
        roles = {path for path in benchmark_runner.SOURCE_DATA if path.startswith('roles/')}
        self.assertEqual(roles, {'roles/{}.txt'.format(role) for role in ROLES})
        self.assertEqual(data, set(benchmark_runner.SOURCE_DATA) - roles)
        self.assertLessEqual(modules, set(benchmark_runner.source_files()))

    def test_init_and_status_run_from_a_snapshot_on_the_graduated_example(self):
        bundle, experiment_id = self.bundle()
        output = Path(self.temp.name) / 'source'
        self.assertEqual(self.cli('snapshot-source', '--output', output)[0], 0)
        environment = {key: value for key, value in os.environ.items() if key != 'PYTHONPATH'}
        # A sibling of the snapshot: the snapshot directory is its own source tree.
        state = Path(self.temp.name) / 'snapshot-state'
        for args in (['init', '--experiment', bundle / 'examples' / 'experiment-graduated.json',
                      '--bundle-root', bundle, '--truth', bundle / 'fixtures'],
                     ['status', '--experiment', experiment_id]):
            result = subprocess.run([sys.executable, '-B', str(output / 'framework' / 'benchmark.py'),
                                     '--state-root', str(state)] + [str(arg) for arg in args],
                                    capture_output=True, text=True, cwd=self.temp.name, env=environment)
            self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)['experiment_id'], experiment_id)

    def test_copy_is_complete_exact_and_runs_on_its_own(self):
        output = Path(self.temp.name) / 'source'
        code, printed = self.cli('snapshot-source', '--output', output)
        self.assertEqual(code, 0, printed)
        manifest = json.loads((output / 'SOURCE-MANIFEST.json').read_text(encoding='utf-8'))
        self.assertEqual(manifest['root'], 'framework')
        paths = {item['path'] for item in manifest['files']}
        self.assertEqual(json.loads(printed)['files'], len(paths))
        self.assertLessEqual(set(benchmark_runner.FINGERPRINTED_SOURCES), paths)
        # The CLI, its lazily imported modules, name-loaded drivers and frozen data.
        self.assertLessEqual({'benchmark.py', 'benchmark_reporting.py', 'benchmark_adjudication.py',
                              'benchmark_campaigns.py', 'benchmark_aws.py', 'benchmark_windows.py',
                              'benchmark_linux.py', 'benchmarks/team-workflow.json',
                              'benchmarks/prompt-contract.txt', 'benchmarks/coverage.json',
                              'benchmarks/attack-v20-techniques.json', 'hermes-bots/catalog.json'}, paths)
        self.assertFalse({path for path in paths if Path(path).name.startswith('test_')})
        for item in manifest['files']:
            data = (output / 'framework' / item['path']).read_bytes()
            self.assertEqual((digest_bytes(data), len(data)), (item['sha256'], item['byte_count']))
            self.assertEqual(data, (source_root(item['path']) / item['path']).read_bytes())
        # The copy validates offline from its own tree and fingerprints identically.
        environment = {key: value for key, value in os.environ.items() if key != 'PYTHONPATH'}
        result = subprocess.run([sys.executable, '-B', str(output / 'framework' / 'benchmark.py'), 'validate',
                                 '--experiment',
                                 str(FIXTURES / 'examples' / 'experiment.json'), '--bundle-root', str(FIXTURES)],
                                capture_output=True, text=True, cwd=self.temp.name, env=environment)
        self.assertEqual(result.returncode, 0, result.stderr)
        probe = ('import sys; sys.path.insert(0, sys.argv[1]); import benchmark_runner as r; '
                 'print(r.HERE); print(r.FRAMEWORK); '
                 'print(r.digest_bytes(r.canonical_bytes({n: r.digest_bytes((r.HERE / n).read_bytes()) '
                 'for n in r.FINGERPRINTED_SOURCES})))')
        result = subprocess.run([sys.executable, '-B', '-c', probe, str(output / 'framework')],
                                capture_output=True, text=True, cwd=self.temp.name, env=environment)
        self.assertEqual(result.returncode, 0, result.stderr)
        copied_here, copied_framework, copied_digest = result.stdout.splitlines()
        self.assertEqual(Path(copied_here), (output / 'framework').resolve())
        self.assertEqual(Path(copied_framework), (output / 'framework').resolve())
        self.assertEqual(copied_digest, digest_bytes(canonical_bytes(
            {n: digest_bytes((source_root(n) / n).read_bytes()) for n in benchmark_runner.FINGERPRINTED_SOURCES})))

    def test_never_overwrites_or_writes_into_the_source_tree(self):
        output = Path(self.temp.name) / 'existing'
        output.mkdir()
        code, _ = self.cli('snapshot-source', '--output', output)
        self.assertEqual((code, list(output.iterdir())), (2, []))
        for source in (Path(benchmark_runner.__file__).resolve().parent, FRAMEWORK):
            inside = source / 'snapshot-refused-test-only'
            code, _ = self.cli('snapshot-source', '--output', inside)
            self.assertEqual(code, 2)
            self.assertFalse(inside.exists())


if __name__ == '__main__':
    unittest.main()

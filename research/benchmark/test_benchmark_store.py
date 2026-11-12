"""Offline BenchmarkStore durability/budget regressions; no transport or lab action."""
import copy
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import benchmark_store
from benchmark_contracts import STAGE_KEYS, BenchmarkError, call_cost_bound, canonical_bytes, digest_bytes
from benchmark_store import BenchmarkStore
from test_benchmark_runner import (
    EXPIRES, HASH, STAMP, authorize_fixture, call_fixture, frozen_fixture, response_fixture,
    trial_fixture,
)


def receipt(store, frozen, call_id, spec, status='completed', api_cost_usd=None):
    """Synthetic receipt; costs are invented test numbers, never observations."""
    ref = (store.write_artifact(spec['trial_id'], 'response', canonical_bytes(response_fixture(spec['stage_key'])))
           if status == 'completed' else None)
    usage = dict(input_tokens=None, output_tokens=None, cached_input_tokens=None, reasoning_tokens=None)
    experiment = frozen['experiment']
    bound = call_cost_bound(experiment['budgets'], spec['model'], experiment['pricing_snapshot']['rates'])
    team = experiment['teams'][0]
    return dict(schema_version=1, call_id=call_id, fingerprint=digest_bytes(canonical_bytes(spec)),
                status=status, model_requested=spec['model']['model_requested'], model_returned=None,
                identity_status='unreported', provider=spec['model']['provider'],
                deployment=team['deployment'], role=spec['role'], stage_key=spec['stage_key'],
                prompt_sha256=spec['input_sha256'], response_sha256=ref['sha256'] if ref else None,
                start_utc=STAMP, end_utc=STAMP, elapsed_ms=5,
                timeout_seconds=spec['model']['timeout_seconds'],
                max_calls=experiment['budgets']['max_calls_per_trial'],
                max_output_bytes=experiment['budgets']['max_response_bytes'],
                finish_reason=None, usage=usage, estimated_usage=copy.deepcopy(usage),
                cost=dict(api_cost_usd=api_cost_usd,
                          pricing_snapshot_sha256=digest_bytes(canonical_bytes(experiment['pricing_snapshot'])),
                          cost_basis='unknown' if api_cost_usd is None else 'reported',
                          local_compute_cost_usd=None, local_energy_cost_usd=None,
                          bound_exceeded=api_cost_usd is not None and api_cost_usd > bound),
                failure_reason=None if status == 'completed' else 'dispatch_interrupted',
                response_artifact=ref)


def paid_frozen():
    """The example team rerouted to a non-loopback (paid) endpoint, priced per token."""
    frozen = frozen_fixture()
    experiment = frozen['experiment']
    team = experiment['teams'][0]
    team['deployment'] = 'cloud'
    for spec in team['roles'].values():
        spec.update(base_url='https://api.example.test/v1', credential_env='BENCH_MODEL_TEST_KEY')
    model = next(iter(team['roles'].values()))['model_requested']
    experiment['pricing_snapshot']['rates'] = [
        dict(provider='openai', model_requested=model, input_per_million=1, output_per_million=1)]
    experiment['budgets'].update(max_api_cost_usd=1.0)
    experiment['budgets'].pop('per_call_cost_bound_usd', None)
    return frozen


class StoreTestCase(unittest.TestCase):
    frozen_factory = staticmethod(frozen_fixture)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'state'
        self.store = BenchmarkStore(self.root, create=True)
        self.frozen = self.frozen_factory()
        self.eid = self.frozen['experiment']['experiment_id']
        self.store.create_experiment(self.frozen)
        self.trial = trial_fixture(self.store, self.frozen)
        self.authorization = authorize_fixture(self.store, self.frozen, self.trial)

    def assert_code(self, code, operation, *args, **kwargs):
        with self.assertRaises(BenchmarkError) as raised:
            operation(*args, **kwargs)
        self.assertEqual(raised.exception.code, code)

    def call(self, call_id, stage='scope', status='completed', api_cost_usd=None):
        spec = call_fixture(self.store, self.frozen, self.trial, self.authorization, stage)
        self.assertIsNone(self.store.reserve_call(call_id, digest_bytes(canonical_bytes(spec)), spec))
        result = receipt(self.store, self.frozen, call_id, spec, status, api_cost_usd)
        self.store.finish_call(call_id, result)
        return spec, result

    def kinds(self):
        return [event['kind'] for event in self.store.snapshot(self.eid)['events']]


class CreationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'state'

    def leftovers(self):
        return sorted(p.name for p in self.root.iterdir() if p.name.endswith('.tmp') or '-journal' in p.name)

    def test_interrupted_schema_build_does_not_strand_the_root(self):
        broken = benchmark_store.SCHEMA + ('CREATE TABLE broken (',)
        with mock.patch.object(benchmark_store, 'SCHEMA', broken):
            with self.assertRaises(BenchmarkError) as raised:
                BenchmarkStore(self.root, create=True)
        self.assertEqual(raised.exception.code, 'storage_error')
        self.assertFalse((self.root / 'benchmark.sqlite3').exists())
        self.assertEqual(self.leftovers(), [])
        BenchmarkStore(self.root, create=True)
        self.assertEqual(self.leftovers(), [])
        BenchmarkStore(self.root)

    def test_existing_database_is_never_adopted_and_root_is_resolved(self):
        store = BenchmarkStore(self.root, create=True)
        self.assertEqual(store.root, self.root.resolve())
        with self.assertRaises(BenchmarkError) as raised:
            BenchmarkStore(self.root, create=True)
        self.assertEqual(raised.exception.code, 'already_exists')


class ReservationTests(StoreTestCase):
    def test_concurrent_reservations_have_one_dispatch_owner(self):
        spec = call_fixture(self.store, self.frozen, self.trial, self.authorization)
        fingerprint = digest_bytes(canonical_bytes(spec))

        def attempt(_):
            try:
                return BenchmarkStore(self.root).reserve_call('call-race', fingerprint, spec)
            except BenchmarkError as exc:
                return exc.code

        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(attempt, range(8)))
        self.assertEqual(results.count(None), 1)
        self.assertEqual(sorted(set(results) - {None}), ['previous_dispatch_unknown'])
        self.assertEqual(self.kinds().count('dispatch_reserved'), 1)


class ArtifactTests(StoreTestCase):
    def test_truncated_artifact_is_recovered_by_atomic_rewrite(self):
        content = canonical_bytes(response_fixture())
        ref = self.store.write_artifact(self.trial['trial_id'], 'response', content)
        path = self.root / 'trials' / self.trial['trial_id'] / ref['path']
        path.write_bytes(content[:7])  # A crashed pre-atomic writer's partial file.
        self.assert_code('artifact_corrupt', self.store.read_artifact, self.trial['trial_id'], ref)
        self.assertEqual(self.store.write_artifact(self.trial['trial_id'], 'response', content), ref)
        self.assertEqual(self.store.read_artifact(self.trial['trial_id'], ref), content)
        self.assertEqual([p.name for p in path.parent.iterdir()], [ref['sha256']])

    def test_matching_artifact_is_kept_and_evaluator_partial_is_replaced(self):
        content = canonical_bytes({'synthetic': 'evaluator-input'})
        sha = self.store.write_evaluator_artifact('adjudication', content)
        path = self.root / 'evaluator' / 'adjudication' / (sha + '.json')
        before = path.stat().st_mtime_ns
        self.assertEqual(self.store.write_evaluator_artifact('adjudication', content), sha)
        self.assertEqual(path.stat().st_mtime_ns, before)
        path.write_bytes(b'{')
        self.assertEqual(self.store.write_evaluator_artifact('adjudication', content), sha)
        self.assertEqual(self.store.read_evaluator_artifact('adjudication', sha), content)

    def test_snapshot_recovers_after_interrupted_response_write(self):
        _, completed = self.call('call-a')
        path = self.root / 'trials' / self.trial['trial_id'] / completed['response_artifact']['path']
        content = path.read_bytes()
        path.write_bytes(content[:-1])
        self.assert_code('artifact_corrupt', self.store.snapshot, self.eid)
        self.store.write_artifact(self.trial['trial_id'], 'response', content)
        self.store.snapshot(self.eid)


class RejectedResponseTests(StoreTestCase):
    """Evaluator-only rejected answers: bounded, consistent, never a response."""

    def test_receipt_shape_is_enforced_and_snapshot_reverifies_bytes(self):
        spec = call_fixture(self.store, self.frozen, self.trial, self.authorization)
        self.assertIsNone(self.store.reserve_call('call-r', digest_bytes(canonical_bytes(spec)), spec))
        base = receipt(self.store, self.frozen, 'call-r', spec, 'failed')
        maximum = base['max_output_bytes']
        data = b'Synthetic rejected answer {' * (maximum // 20)
        ref = self.store.write_artifact(self.trial['trial_id'], 'rejected-responses', data[:maximum])
        valid = dict(error_code='invalid_json', error_field='json', artifact=ref,
                     byte_count=len(data), truncated=True)
        self.assertGreater(len(data), maximum)

        def attempt(code, failure='invalid_response', **changes):
            candidate = dict(copy.deepcopy(base), failure_reason=failure, rejected_response=dict(valid, **changes))
            self.assert_code(code, self.store.finish_call, 'call-r', candidate)

        attempt('scope_mismatch', failure='timeout')
        attempt('invalid_rejected_response', truncated=False)
        attempt('invalid_rejected_response', byte_count=maximum - 1, truncated=False)
        attempt('invalid_identifier', error_code='Not A Code')
        attempt('incomplete_receipt', artifact=None)
        attempt('invalid_number', byte_count='many')
        attempt('invalid_boolean', truncated='yes')
        attempt('unknown_field', extra=True)
        finished = dict(copy.deepcopy(base), failure_reason='invalid_response', rejected_response=valid)
        self.store.finish_call('call-r', finished)
        self.assertEqual(self.store.calls()[0]['receipt']['rejected_response'], valid)
        self.store.snapshot(self.eid)
        path = self.root / 'trials' / self.trial['trial_id'] / ref['path']
        path.write_bytes(data[:maximum - 1])
        self.assert_code('artifact_corrupt', self.store.snapshot, self.eid)


class TrialTests(StoreTestCase):
    def test_status_changes_use_a_precise_event_kind(self):
        self.store.update_trial(self.trial['trial_id'], dict(self.trial, status='running'), 'running')
        events = [e for e in self.store.snapshot(self.eid)['events'] if e['kind'] == 'trial_status_changed']
        self.assertEqual([(e['payload']['previous_status'], e['payload']['trial_status']) for e in events],
                         [('pending', 'running')])
        self.assertNotIn('stage_submitted', self.kinds())

    def test_terminate_trial_is_terminal_and_visible(self):
        self.assert_code('invalid_choice', self.store.terminate_trial,
                         self.trial['trial_id'], 'model_was_wrong', 'test-human', 'Synthetic.')
        terminated = self.store.terminate_trial(self.trial['trial_id'], 'human_abandoned',
                                                'test-human', 'Synthetic abandonment.')
        self.assertEqual((terminated['status'], terminated['terminal_reason']), ('terminated', 'human_abandoned'))
        self.assertEqual(self.store.terminate_trial(self.trial['trial_id'], 'human_abandoned',
                                                    'test-human', 'Repeat.'), terminated)
        self.assert_code('fingerprint_conflict', self.store.terminate_trial,
                         self.trial['trial_id'], 'budget_exhausted', 'benchmark-runner', 'Different.')
        self.assert_code('state_conflict', self.store.update_trial, self.trial['trial_id'],
                         dict(self.trial, status='running'), 'running')
        self.assert_code('state_conflict', self.store.update_trial, self.trial['trial_id'],
                         terminated, 'terminated')
        spec = call_fixture(self.store, self.frozen, self.trial, self.authorization)
        self.assert_code('state_conflict', self.store.reserve_call, 'late-call',
                         digest_bytes(canonical_bytes(spec)), spec)
        snapshot = self.store.snapshot(self.eid)
        self.assertEqual(snapshot['trials'][0]['status'], 'terminated')
        self.assertEqual(snapshot['trials'][0]['terminal_reason'], 'human_abandoned')
        events = [e for e in snapshot['events'] if e['kind'] == 'trial_terminated']
        self.assertEqual(len(events), 1)
        self.assertEqual((events[0]['actor'], events[0]['payload']['reason']), ('test-human', 'human_abandoned'))

    def test_scores_require_the_validated_scoring_envelope(self):
        self.assert_code('scope_mismatch', self.store.record_score, self.trial['trial_id'], HASH,
                         {'provisional': True}, 'test-scorer')


class AutoAdvanceTests(StoreTestCase):
    def setUp(self):
        super().setUp()
        _, self.completed = self.call('call-a')
        ref = self.completed['response_artifact']
        self.payload = {'stage_key': 'scope', 'attempt_index': 1, 'ledger_event_id': 7,
                        'ledger_submit_event_id': 6, 'ledger_event_sha256': HASH,
                        'output_sha256': ref['sha256'], 'output_artifact': ref, 'checker_artifact': None,
                        'checker_receipt_sha256': None, 'review_policy': 'auto_advance'}

    def advances(self):
        return [e for e in self.store.snapshot(self.eid)['events'] if e['kind'] == 'stage_auto_advanced']

    def test_mirror_commits_or_rolls_back_atomically_and_is_idempotent(self):
        with mock.patch.object(self.store, 'event', side_effect=BenchmarkError('test_failure', 'event')):
            self.assert_code('test_failure', self.store.record_auto_advance,
                             self.trial['trial_id'], 'call-a', self.payload)
        self.assertEqual(self.advances(), [])
        item = self.store.record_auto_advance(self.trial['trial_id'], 'call-a', self.payload)
        self.assertEqual(self.store.record_auto_advance(self.trial['trial_id'], 'call-a', self.payload), item)
        events = self.advances()
        self.assertEqual([(e['actor'], e['call_id'], e['payload']) for e in events],
                         [('benchmark-auto-advance', 'call-a', self.payload)])
        self.assertNotIn('human_decision_observed', self.kinds())

    def test_changed_mirror_or_mismatched_scope_is_refused(self):
        self.store.record_auto_advance(self.trial['trial_id'], 'call-a', self.payload)
        self.assert_code('fingerprint_conflict', self.store.record_auto_advance, self.trial['trial_id'], 'call-a',
                         dict(self.payload, ledger_event_sha256='2' * 64))
        self.assert_code('scope_mismatch', self.store.record_auto_advance, self.trial['trial_id'], 'call-a',
                         dict(self.payload, attempt_index=2))
        self.assert_code('scope_mismatch', self.store.record_auto_advance, self.trial['trial_id'], 'call-a',
                         dict(self.payload, ledger_event_id=6))
        self.assert_code('digest_mismatch', self.store.record_auto_advance, self.trial['trial_id'], 'call-a',
                         dict(self.payload, output_sha256='2' * 64))
        self.assert_code('unknown_field', self.store.record_auto_advance, self.trial['trial_id'], 'call-a',
                         dict(self.payload, approved_by='test-only-human'))
        self.assertEqual(len(self.advances()), 1)

    def test_incomplete_call_cannot_be_advanced(self):
        spec = call_fixture(self.store, self.frozen, self.trial, self.authorization, stage='endpoint_evidence')
        self.store.reserve_call('call-b', digest_bytes(canonical_bytes(spec)), spec)
        ref = self.store.write_artifact(self.trial['trial_id'], 'response',
                                        canonical_bytes(response_fixture('endpoint_evidence')))
        self.assert_code('scope_mismatch', self.store.record_auto_advance, self.trial['trial_id'], 'call-b',
                         dict(self.payload, stage_key='endpoint_evidence', output_artifact=ref,
                              output_sha256=ref['sha256']))


class CampaignProcessTests(StoreTestCase):
    def setUp(self):
        super().setUp()
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
        state = self.store.update_campaign('campaign-a', dict(campaign, status='preflight_passed'),
                                           'draft', 'not_needed')
        auth = self.store.record_authorization(dict(
            approval_id='campaign-auth', experiment_id=self.eid, trial_id=None, campaign_id='campaign-a',
            by='test-human', note='Synthetic campaign; no lab action.', created_utc=STAMP,
            expires_utc=EXPIRES, evidence_sha256=None, model_sha256s=[],
            manifest_sha256=campaign['manifest_sha256'], phases=['run']))
        self.store.update_campaign('campaign-a', dict(state, status='authorized'), 'preflight_passed', 'not_needed')
        self.spec = dict(schema_version=1, experiment_id=self.eid, manifest_sha256=campaign['manifest_sha256'],
                         authorization_sha256=auth, executor_sha256=HASH, input_sha256=HASH,
                         executor_version='synthetic-1', target_sha256=HASH, timeout_seconds=10)
        self.fingerprint = digest_bytes(canonical_bytes(self.spec))
        self.assertIsNone(self.store.reserve_campaign_step('campaign-a', 'run', 'step-a',
                                                           self.fingerprint, self.spec))
        self.identity = {'pid': 123, 'creation_utc': '2026-01-01T00:00:00.1234567Z',
                         'process_group_id': 'Local\\benchmark-test-job'}
        self.evidence = {'local_stopped': True, 'source': 'run_process', 'remote_effects': 'unknown'}

    def test_process_events_do_not_break_snapshot(self):
        recorded = self.store.record_owned_process('campaign-a', 'run', 'step-a', self.identity)
        self.assertEqual(recorded['owned_process'], self.identity)
        self.assertEqual(self.store.record_owned_process('campaign-a', 'run', 'step-a', self.identity), recorded)
        snapshot = self.store.snapshot(self.eid)
        self.assertEqual(snapshot['campaign_states'][0]['owned_process'], self.identity)
        cleared = self.store.clear_owned_process('campaign-a', 'step-a', self.evidence)
        self.assertIsNone(cleared['owned_process'])
        snapshot = self.store.snapshot(self.eid)
        self.assertEqual(snapshot['campaign_states'][0], cleared)
        kinds = [e['kind'] for e in snapshot['events'] if e['campaign_id'] == 'campaign-a']
        self.assertEqual(kinds.count('dispatch_reserved'), 1)
        self.assertEqual((kinds.count('process_started'), kinds.count('process_stopped')), (1, 1))
        self.assertIn('campaign_status_changed', kinds)
        self.assertNotIn('reconciliation_recorded', kinds)

    def test_ownership_changes_only_through_process_methods(self):
        state = self.store.get_campaign('campaign-a')
        self.assert_code('state_conflict', self.store.update_campaign, 'campaign-a',
                         dict(state, owned_process=self.identity), 'authorized', 'not_needed')
        self.assert_code('state_conflict', self.store.clear_owned_process, 'campaign-a', 'step-a', self.evidence)
        self.store.record_owned_process('campaign-a', 'run', 'step-a', self.identity)
        self.assert_code('state_conflict', self.store.record_owned_process, 'campaign-a', 'run', 'step-a',
                         dict(self.identity, pid=124))
        self.assert_code('process_not_stopped', self.store.clear_owned_process, 'campaign-a', 'step-a',
                         dict(self.evidence, local_stopped=False))
        self.assert_code('not_found', self.store.clear_owned_process, 'campaign-a', 'step-missing', self.evidence)
        stopped, captured = self.store.request_campaign_stop('campaign-a')
        self.assertEqual((stopped['owned_process'], captured), (self.identity, self.identity))
        self.store.clear_owned_process('campaign-a', 'step-a', dict(self.evidence, source='stop_owned'))
        self.store.snapshot(self.eid)

    def test_finished_step_cannot_claim_a_process(self):
        failed = dict(schema_version=1, fingerprint=self.fingerprint, status='failed', campaign_id='campaign-a',
                      phase='run', step_id='step-a', executor_sha256=HASH, executor_version='synthetic-1',
                      execution_outcome='failed', start_utc=STAMP, end_utc=STAMP, elapsed_ms=1, exit_code=1,
                      observed_target_sha256=None, effect_verified=False, evidence_sha256=None,
                      failure_reason='execution_failed')
        self.store.finish_campaign_step('campaign-a', 'run', 'step-a', failed)
        self.assert_code('state_conflict', self.store.record_owned_process, 'campaign-a', 'run', 'step-a',
                         self.identity)

    def test_campaign_steps_are_never_resolved_by_automation(self):
        automatic = benchmark_store.AUTO_RECONCILE_ACTOR
        self.assert_code('reserved_actor', self.store.reconcile_campaign_step, 'campaign-a', 'run', 'step-a',
                         automatic, 'Synthetic.', {}, {})
        self.assert_code('reserved_actor', self.store.reconcile_campaign_state, 'campaign-a', 'unknown',
                         automatic, 'Synthetic.', b'{}')
        # The automatic path addresses model calls only; a campaign step is not one.
        self.assert_code('not_found', self.store.auto_reconcile_call, 'step-a', 'Synthetic.', {},
                         {}, {'basis': 'ledger_run_failed', 'ledger_event_id': 1, 'ledger_event_time': STAMP})
        self.assertEqual(self.store.snapshot(self.eid)['campaigns'][0]['status'], 'reserved')


class SpendBoundTests(StoreTestCase):
    frozen_factory = staticmethod(paid_frozen)

    def test_paid_route_reserves_only_its_per_call_bound(self):
        experiment = self.frozen['experiment']
        spec = call_fixture(self.store, self.frozen, self.trial, self.authorization)
        bound = call_cost_bound(experiment['budgets'], spec['model'], experiment['pricing_snapshot']['rates'])
        self.assertGreater(bound, 0)
        self.assertLess(bound + 0.4, 1.0)
        self.call('call-1', 'scope', api_cost_usd=0.4)
        # The second paid call fits: 0.4 used + its own bound <= 1.0.
        self.call('call-2', 'endpoint_evidence', api_cost_usd=0.4)
        reserved = [e for e in self.store.snapshot(self.eid)['events'] if e['kind'] == 'dispatch_reserved']
        self.assertEqual([e['payload']['reserved_api_cost_usd'] for e in reserved], [bound, bound])
        # A third would exceed it: 0.8 used + bound > 1.0.
        third = call_fixture(self.store, self.frozen, self.trial, self.authorization, 'network_evidence')
        self.assert_code('budget_exceeded', self.store.reserve_call, 'call-3',
                         digest_bytes(canonical_bytes(third)), third)

    def test_cost_above_bound_must_be_flagged(self):
        spec = call_fixture(self.store, self.frozen, self.trial, self.authorization)
        self.store.reserve_call('call-1', digest_bytes(canonical_bytes(spec)), spec)
        hidden = receipt(self.store, self.frozen, 'call-1', spec, api_cost_usd=0.4)
        hidden['cost']['bound_exceeded'] = False
        self.assert_code('invalid_cost', self.store.finish_call, 'call-1', hidden)
        hidden['cost']['bound_exceeded'] = True
        self.store.finish_call('call-1', hidden)

    def test_unknown_cost_keeps_the_reserved_bound(self):
        spec, _ = self.call('call-1', 'scope')
        call = self.store.calls(trial_id=self.trial['trial_id'])[0]
        experiment = self.frozen['experiment']
        self.assertEqual(BenchmarkStore.charge(call, 'cost', experiment),
                         call_cost_bound(experiment['budgets'], spec['model'], experiment['pricing_snapshot']['rates']))


class AutoReconcileTests(StoreTestCase):
    """Automatic failed resolution of an uncertain model call; invented receipts only."""
    frozen_factory = staticmethod(paid_frozen)

    def setUp(self):
        super().setUp()
        self.spec = call_fixture(self.store, self.frozen, self.trial, self.authorization)
        self.store.reserve_call('call-u', digest_bytes(canonical_bytes(self.spec)), self.spec)
        unknown = receipt(self.store, self.frozen, 'call-u', self.spec, 'unknown')
        unknown.update(failure_reason='timeout', elapsed_ms=30000.0)
        self.store.finish_call('call-u', unknown)
        self.evidence = self.store.write_artifact(self.trial['trial_id'], 'reconciliation',
                                                  b'{"synthetic": "automatic reconciliation evidence"}')
        self.check = {'basis': 'ledger_run_failed', 'ledger_event_id': 7, 'ledger_event_time': STAMP}

    def discarded(self, **changes):
        value = receipt(self.store, self.frozen, 'call-u', self.spec, 'failed')
        value.update(elapsed_ms=None, failure_reason='timeout')
        value.update(changes)
        return value

    def reconcile(self, value):
        return self.store.auto_reconcile_call('call-u', 'Synthetic automatic note.', self.evidence, value, self.check)

    def test_failed_with_worst_case_charges_and_labeled_automatic(self):
        payload = self.reconcile(self.discarded())
        experiment = self.frozen['experiment']
        bound = call_cost_bound(experiment['budgets'], self.spec['model'], experiment['pricing_snapshot']['rates'])
        self.assertEqual((payload['policy'], payload['outcome'], payload['prior_status'],
                          payload['prior_failure_reason'], payload['observed_elapsed_ms']),
                         ('automatic_model_call', 'failed', 'unknown', 'timeout', 30000.0))
        self.assertEqual((payload['charged_seconds'], payload['charged_api_cost_usd']),
                         (self.spec['model']['timeout_seconds'], bound))
        call = self.store.calls(trial_id=self.trial['trial_id'])[0]
        self.assertEqual((call['status'], call['receipt']['elapsed_ms'], call['receipt']['response_artifact']),
                         ('failed', None, None))
        self.assertEqual(BenchmarkStore.charge(call, 'seconds', experiment), self.spec['model']['timeout_seconds'])
        events = [e for e in self.store.snapshot(self.eid)['events'] if e['kind'] == 'reconciliation_recorded']
        self.assertEqual([(e['actor'], e['payload']['policy']) for e in events],
                         [('benchmark-auto-reconcile', 'automatic_model_call')])
        # A completed response arriving late is never accepted for a resolved call.
        late = receipt(self.store, self.frozen, 'call-u', self.spec)
        self.assert_code('state_conflict', self.store.finish_call, 'call-u', late)
        self.assert_code('state_conflict', self.reconcile, self.discarded())
        self.assertEqual(self.store.reserve_call('call-u', digest_bytes(canonical_bytes(self.spec)), self.spec),
                         call['receipt'])

    def test_retained_measurements_or_changed_reason_are_refused(self):
        usage = dict(input_tokens=3, output_tokens=None, cached_input_tokens=None, reasoning_tokens=None)
        for changes in ({'elapsed_ms': 5}, {'failure_reason': 'dispatch_interrupted'}, {'usage': usage}):
            with self.subTest(changes=sorted(changes)):
                self.assert_code('measurement_not_discarded', self.reconcile, self.discarded(**changes))
        self.assertEqual(self.store.calls(trial_id=self.trial['trial_id'])[0]['status'], 'unknown')
        self.assert_code('invalid_choice', self.store.auto_reconcile_call, 'call-u', 'Synthetic.', self.evidence,
                         self.discarded(), dict(self.check, basis='operator_says_so'))

    def test_humans_and_automation_never_masquerade(self):
        for actor in ('benchmark-auto-reconcile', 'Benchmark-Auto-operator'):
            with self.subTest(actor=actor):
                self.assert_code('reserved_actor', self.store.reconcile_call, 'call-u', actor, 'Synthetic.',
                                 'failed', self.evidence, self.discarded())
        self.store.event('reconciliation_recorded', 'test-human',
                         {'policy': 'automatic_model_call', 'note': 'Forged label.', 'outcome': 'failed'},
                         experiment_id=self.eid, trial_id=self.trial['trial_id'], call_id='call-u')
        self.assert_code('incomplete_snapshot', self.store.snapshot, self.eid)


class AutoRetryTests(StoreTestCase):
    """Automatic retry after a known model call failure; invented receipts only."""

    def setUp(self):
        super().setUp()
        self.check = {'basis': 'ledger_run_failed', 'ledger_event_id': 7, 'ledger_event_time': STAMP}

    def failed(self, call_id, stage, reason):
        spec = call_fixture(self.store, self.frozen, self.trial, self.authorization, stage)
        self.store.reserve_call(call_id, digest_bytes(canonical_bytes(spec)), spec)
        value = receipt(self.store, self.frozen, call_id, spec, 'failed')
        value['failure_reason'] = reason
        self.store.finish_call(call_id, value)
        return value

    def test_known_failure_schedules_an_honestly_labeled_retry(self):
        kept = self.failed('call-f', 'scope', 'invalid_response')
        payload = self.store.record_automatic_retry('call-f', 'Synthetic automatic retry.', self.check)
        self.assertEqual((payload['policy'], payload['failure_reason'], payload['failed_attempt_index'],
                          payload['trial_status']), ('automatic_retry', 'invalid_response', 1, 'ready'))
        # Idempotent per failed call; the known receipt is untouched.
        self.assertEqual(self.store.record_automatic_retry('call-f', 'Again.', self.check), payload)
        self.assertEqual(self.store.calls(trial_id=self.trial['trial_id'])[0]['receipt'], kept)
        events = [e for e in self.store.snapshot(self.eid)['events'] if e['payload'].get('policy') == 'automatic_retry']
        self.assertEqual([(e['kind'], e['actor'], e['call_id']) for e in events],
                         [('trial_status_changed', 'benchmark-auto-retry', 'call-f')])
        self.assertNotIn('reconciliation_recorded', self.kinds())

    def test_configuration_or_human_failures_are_never_retried(self):
        reasons = sorted(benchmark_store.CONFIGURATION_FAILURES | {'human_reconciled'})
        for reason, stage in zip(reasons, STAGE_KEYS):  # one stage per invented failure
            with self.subTest(reason=reason):
                call_id = 'call-' + reason.replace('_', '-')
                self.failed(call_id, stage, reason)
                self.assert_code('not_retryable', self.store.record_automatic_retry, call_id, 'n', self.check)
        # A still-reserved call has no known outcome to retry.
        spec = call_fixture(self.store, self.frozen, self.trial, self.authorization, 'scope', attempt=2)
        self.store.reserve_call('call-r', digest_bytes(canonical_bytes(spec)), spec)
        self.assert_code('state_conflict', self.store.record_automatic_retry, 'call-r', 'n', self.check)

    def test_forged_retry_label_breaks_the_snapshot(self):
        self.failed('call-f', 'scope', 'invalid_response')
        self.store.event('trial_status_changed', 'runner', {'policy': 'automatic_retry',
                         'failure_reason': 'invalid_response'}, experiment_id=self.eid,
                         trial_id=self.trial['trial_id'], call_id='call-f')
        self.assert_code('incomplete_snapshot', self.store.snapshot, self.eid)


if __name__ == '__main__':
    unittest.main()

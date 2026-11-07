"""Synthetic controller/receipt fixtures only: no lab, network, or coverage claims."""
import copy
import os
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import benchmark_campaigns as campaigns
from benchmark_contracts import BenchmarkError, canonical_bytes, campaign_manifest_digest, digest_bytes
from benchmark_store import BenchmarkStore


class SyntheticDriver:
    """Explicitly invented effect observations; never a runnable lab driver."""
    def __init__(self):
        self.calls = []
        self.complete = False
        self.outcome = 'succeeded'
        self.wrong_identity = False
        self.entered = None
        self.retention = False
        self.use_transport = False
        self.cleanup_outcome = 'succeeded'

    def validate_configuration(self, manifest):
        if manifest['executor']['config'] != {'fixture_only': True}:
            raise BenchmarkError('unknown_field', 'fixture.config')

    def validate_collector(self, manifest, collector):
        if collector['config'] != {'fixture_only': True}:
            raise BenchmarkError('unknown_field', 'fixture.collector')

    def phase_steps(self, manifest, phase, context):
        return {'preflight': ['identity'], 'run': ['discovery'], 'cleanup': ['close_sessions']}[phase]

    def execute_step(self, manifest, kit, phase, step, context, transport):
        self.calls.append((phase, step))
        if phase == 'run' and self.entered:
            self.entered.set()
            if not self.resume.wait(10):
                raise RuntimeError('fixture synchronization timeout')
        collector = context.get('collector')
        targets = [target for target in manifest['targets'] if not collector or target['target_id'] == collector['target_id']]
        outcome = self.outcome if phase == 'run' else (self.cleanup_outcome if phase == 'cleanup' else 'succeeded')
        exports = []
        reason = 'fixture_only'
        if phase == 'collect':
            outcome = 'succeeded' if self.complete else 'blocked'
            reason = 'complete' if self.complete else 'incomplete_export'
            exports = [{'source_id': collector['source_id'], 'records': [{'fixture_only': True}],
                        'window_utc': collector['window_utc'],
                        'watermark_utc': collector['window_utc']['end_exclusive'] if self.complete else campaigns._now(),
                        'complete': self.complete, 'filter': None}]
        if phase == 'run' and self.use_transport:
            response = transport(['fixture-never-launched'], input_bytes=b'', env={}, timeout=10, max_output_bytes=4096)
            if response['status'] == 'unknown':
                outcome = 'unknown'
        return {'execution_outcome': outcome,
                'observed_target_sha256': '0' * 64 if self.wrong_identity and phase == 'run' else campaigns._hash(targets),
                'effect_verified': outcome == 'succeeded', 'evidence': {'fixture_only': True, 'reason': reason},
                'raw_exports': exports,
                'context_updates': {'aws_retention_verified': True, 'aws_baseline_healthy': True} if self.retention else {}}


class CampaignTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='benchmark-campaign-fixture-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.state = self.root / 'private-state'
        self.kit = self.root / 'fixture-kit'
        self.kit.mkdir()
        for name in campaigns.KIT_FILES:
            (self.kit / name).write_bytes(b'SYNTHETIC TEST FIXTURE; NOT EXECUTABLE\n')
        self.executable = self.root / 'fixture-executor'
        self.executable.write_bytes(b'fixture-only executable identity, never launched')
        self.driver = SyntheticDriver()
        self.patch_driver = patch.object(campaigns, '_driver', return_value=self.driver)
        self.patch_driver.start()
        self.addCleanup(self.patch_driver.stop)
        now = datetime.now(timezone.utc)
        self.now = now
        self.expiry = (now + timedelta(days=2)).isoformat()
        self.manifest = {
            'schema_version': 1, 'campaign_id': 'fixture-campaign', 'recipe_id': 'linux-discovery-v1',
            'range_kit_sha256': campaigns._hash({name: digest_bytes((self.kit / name).read_bytes()) for name in campaigns.KIT_FILES}),
            'targets': [{'target_id': 'victim', 'display_id': 'asset-1', 'kind': 'linux',
                         'identity': {'fixture_only': True},
                         'network': {'switch_id': 'fixture-isolated-switch', 'isolation_review': {
                             'by': 'fixture-reviewer', 'checked_utc': now.isoformat(), 'expires_utc': self.expiry,
                             'evidence_sha256': '1' * 64, 'owned_test_endpoints': ['192.0.2.4']}},
                         'clock': {'offset_seconds': 0, 'uncertainty_seconds': 0, 'checked_utc': now.isoformat()}}],
            'executor': {'transport': 'ssh_worker', 'executable': {'path': str(self.executable),
                         'sha256': digest_bytes(self.executable.read_bytes()), 'version': 'synthetic-fixture-1'},
                         'script_sha256': '2' * 64, 'environment_names': [], 'config': {'fixture_only': True}},
            'collectors': [{'source_id': 'sensor-1', 'kind': 'linux', 'target_id': 'victim',
                            'export_root': None, 'bucket': None, 'prefix': None,
                            'window_utc': {'start_inclusive': (now - timedelta(hours=1)).isoformat(),
                                           'end_exclusive': (now + timedelta(hours=1)).isoformat()},
                            'sensor_version': 'synthetic-fixture-1', 'config_version': 'synthetic-fixture-1',
                            'max_bytes': 4096, 'max_seconds': 30, 'watermark_utc': now.isoformat(),
                            'config': {'fixture_only': True}}],
            'limits': {'max_phase_seconds': 60, 'max_campaign_seconds': 86400, 'max_export_bytes': 65536,
                       'max_cloud_cost_usd': None, 'latest_cleanup_utc': (now + timedelta(hours=4)).isoformat()},
            'authorization': {'by': None, 'note': None, 'expires_utc': None, 'manifest_sha256': None, 'allowed_phases': []}}
        self.manifest_path = self.root / 'manifest.json'
        self.save()

    def save(self):
        self.manifest_path.write_bytes(canonical_bytes(self.manifest))

    def use_aws(self, limit=5, recipes=None):
        """Synthetic cost snapshot: invented prices, never an AWS quote."""
        if recipes is None:
            prices = [{'price_id': 'synthetic-event-copy', 'unit': 'management_event', 'usd': 2.0,
                       'per_quantity': 100000, 'source_url': 'https://aws.amazon.com/cloudtrail/pricing/',
                       'source_text': 'synthetic fixture rate', 'unknown_reason': None},
                      {'price_id': 'synthetic-storage', 'unit': 'gb_month', 'usd': 0.25, 'per_quantity': 1,
                       'source_url': 'https://aws.amazon.com/s3/pricing/', 'source_text': 'synthetic fixture rate',
                       'unknown_reason': None}]
            phases = [{'phase': phase, 'step_id': step, 'resources_created': [], 'charges': []}
                      for phase, step in campaigns.AWS_COST_STEPS]
            phases[2]['resources_created'] = [{'address': 'aws_cloudtrail.trail', 'max_lifetime': 'until_latest_cleanup_utc'}]
            phases[2]['charges'] = [
                {'price_id': 'synthetic-event-copy', 'basis': 'per_campaign', 'max_quantity': 50000, 'note': 'fixture'},
                {'price_id': 'synthetic-storage', 'basis': 'per_hour_until_latest_cleanup', 'max_quantity': 1, 'note': 'fixture'}]
            recipes = canonical_bytes({'schema_version': 1, 'kit_version': 'synthetic-fixture', 'recipes': {
                'aws-test-trail-stop-v1': {'cloud_cost_bound': {
                    'bound_version': 'synthetic-cost-1', 'priced_utc': self.now.isoformat(), 'currency': 'USD',
                    'enforcement': campaigns.COST_ENFORCEMENT, 'prices': prices, 'phases': phases}}}})
        (self.kit / 'recipes.json').write_bytes(recipes)
        self.manifest['range_kit_sha256'] = campaigns._hash(
            {name: digest_bytes((self.kit / name).read_bytes()) for name in campaigns.KIT_FILES})
        self.manifest['recipe_id'] = 'aws-test-trail-stop-v1'
        self.manifest['executor']['transport'] = 'aws_cli'
        self.manifest['limits']['max_cloud_cost_usd'] = limit
        self.save()

    def prepare(self):
        result = campaigns.preflight(self.state, self.manifest_path, self.kit, True)
        self.assertEqual(result['status'], 'preflight_passed')
        self.assertFalse(result['live_verified'])
        campaigns.authorize(self.state, 'fixture-campaign', 'fixture-reviewer', 'synthetic authority only',
                            self.expiry, ['run', 'collect', 'cleanup', 'stop'])

    def future_clock(self, hours):
        future = self.now + timedelta(hours=hours)
        class FixtureClock(datetime):
            @classmethod
            def now(cls, tz=None):
                return future if tz is not None else future.replace(tzinfo=None)
        return patch.object(campaigns, 'datetime', FixtureClock)

    def test_plan_is_pure_and_embedded_authority_is_not_authority(self):
        self.manifest['authorization'] = {'by': 'fixture', 'note': 'not authority', 'expires_utc': self.expiry,
                                          'manifest_sha256': None, 'allowed_phases': ['run']}
        self.manifest['authorization']['manifest_sha256'] = campaign_manifest_digest(self.manifest)
        self.save()
        result = campaigns.plan(self.manifest_path)
        self.assertEqual(result['execution'], 'not_dispatched')
        self.assertFalse(self.state.exists())
        self.assertEqual(self.driver.calls, [])
        campaigns.preflight(self.state, self.manifest_path, self.kit, True)
        with self.assertRaises(BenchmarkError):
            campaigns.run(self.state, 'fixture-campaign', True)
        self.assertFalse(any(phase == 'run' for phase, _ in self.driver.calls))

    def test_unknown_fields_duplicate_json_and_flags_rejected(self):
        self.manifest['executor']['command'] = 'must never execute'
        self.save()
        with self.assertRaises(BenchmarkError):
            campaigns.plan(self.manifest_path)
        self.manifest_path.write_bytes(b'{"schema_version":1,"schema_version":1}')
        with self.assertRaises(BenchmarkError):
            campaigns.plan(self.manifest_path)
        with self.assertRaises(BenchmarkError):
            campaigns.preflight(self.state, self.manifest_path, self.kit)
        self.assertFalse(self.state.exists())
        self.assertEqual(self.driver.calls, [])

    def test_full_lifecycle_preserves_partial_then_cleanup_then_final(self):
        self.prepare()
        result = campaigns.run(self.state, 'fixture-campaign', True)
        self.assertEqual(result['status'], 'awaiting_collection')
        self.assertEqual(result['cleanup_status'], 'pending')
        with self.assertRaises(BenchmarkError) as caught:
            campaigns.cleanup(self.state, 'fixture-campaign', True)
        self.assertEqual(caught.exception.code, 'raw_evidence_required')
        result = campaigns.collect(self.state, 'fixture-campaign', True)
        self.assertEqual(result['status'], 'awaiting_collection')
        store = BenchmarkStore(self.state)
        first = [row for row in campaigns._rows(store, 'fixture-campaign', 'campaigns') if row['phase'] == 'collect'][0]
        snapshot = campaigns._result(store, store.get_campaign('fixture-campaign'), first)
        self.assertFalse(snapshot['raw_exports'][0]['complete'])
        result = campaigns.cleanup(self.state, 'fixture-campaign', True)
        self.assertEqual(result['cleanup_status'], 'succeeded')
        self.assertEqual(result['status'], 'awaiting_collection')
        self.driver.complete = True
        with self.future_clock(2):
            result = campaigns.collect(self.state, 'fixture-campaign', True)
        self.assertEqual(result['status'], 'awaiting_release')
        self.assertFalse(result['live_verified'])
        self.assertTrue(result['human_release_required'])
        self.assertEqual(campaigns._result(store, store.get_campaign('fixture-campaign'), first), snapshot)

    def test_expired_authority_never_launches(self):
        self.prepare()
        with self.future_clock(49), self.assertRaises(BenchmarkError) as caught:
            campaigns.run(self.state, 'fixture-campaign', True)
        self.assertEqual(caught.exception.code, 'authorization_expired')
        self.assertFalse(any(phase == 'run' for phase, _ in self.driver.calls))

    def test_changed_kit_and_executable_refuse_dispatch(self):
        self.prepare()
        (self.kit / 'linux_worker.py').write_bytes(b'changed fixture')
        with self.assertRaises(BenchmarkError) as caught:
            campaigns.run(self.state, 'fixture-campaign', True)
        self.assertEqual(caught.exception.code, 'digest_mismatch')
        self.assertFalse(any(phase == 'run' for phase, _ in self.driver.calls))

    def test_changed_executable_refuses_dispatch(self):
        self.prepare()
        self.executable.write_bytes(b'changed fixture identity')
        with self.assertRaises(BenchmarkError) as caught:
            campaigns.run(self.state, 'fixture-campaign', True)
        self.assertEqual(caught.exception.code, 'digest_mismatch')
        self.assertFalse(any(phase == 'run' for phase, _ in self.driver.calls))

    def test_wrong_account_or_machine_result_quarantines(self):
        self.prepare()
        self.driver.wrong_identity = True
        result = campaigns.run(self.state, 'fixture-campaign', True)
        self.assertEqual(result['status'], 'unknown')
        self.assertEqual(result['cleanup_status'], 'unknown')
        with self.assertRaises(BenchmarkError):
            campaigns.run(self.state, 'fixture-campaign', True)
        self.assertEqual(sum(phase == 'run' for phase, _ in self.driver.calls), 1)

    def test_unknown_mutation_never_retries(self):
        self.prepare()
        self.driver.outcome = 'unknown'
        result = campaigns.run(self.state, 'fixture-campaign', True)
        self.assertEqual(result['status'], 'unknown')
        for operation in (campaigns.run, campaigns.cleanup, campaigns.collect):
            with self.assertRaises(BenchmarkError):
                operation(self.state, 'fixture-campaign', True)
        self.assertEqual(sum(phase == 'run' for phase, _ in self.driver.calls), 1)

    def test_concurrent_run_has_one_dispatch_owner(self):
        self.prepare()
        self.driver.entered = threading.Event()
        self.driver.resume = threading.Event()
        results, errors = [], []
        def first_run():
            try:
                results.append(campaigns.run(self.state, 'fixture-campaign', True))
            except Exception as error:
                errors.append(error)
        thread = threading.Thread(target=first_run)
        thread.start()
        try:
            self.assertTrue(self.driver.entered.wait(10))
            with self.assertRaises(BenchmarkError) as caught:
                campaigns.run(self.state, 'fixture-campaign', True)
            self.assertIn(caught.exception.code, ('campaign_busy', 'state_conflict'))
        finally:
            self.driver.resume.set()
            thread.join(10)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(len(results), 1)
        self.assertEqual(sum(phase == 'run' for phase, _ in self.driver.calls), 1)

    def test_explicit_incomplete_collection_gets_new_read_attempt(self):
        self.prepare()
        campaigns.run(self.state, 'fixture-campaign', True)
        campaigns.collect(self.state, 'fixture-campaign', True)
        campaigns.collect(self.state, 'fixture-campaign', True)
        rows = [row for row in campaigns._rows(BenchmarkStore(self.state), 'fixture-campaign', 'campaigns') if row['phase'] == 'collect']
        self.assertEqual(len(rows), 2)
        self.assertNotEqual(rows[0]['step_id'], rows[1]['step_id'])
        self.assertEqual([row['status'] for row in rows], ['failed', 'failed'])

    def run_with_owned_process(self, identity):
        """Synthetic transport: records an owned identity, then reports an uncertain end."""
        self.driver.use_transport = True
        def fake_run_process(argv, **kwargs):
            kwargs['on_started'](identity)
            return {'status': 'unknown', 'exit_code': None, 'stdout': b'', 'failure_reason': 'timeout',
                    'local_stopped': False}
        with patch('benchmark_process.run_process', side_effect=fake_run_process):
            result = campaigns.run(self.state, 'fixture-campaign', True)
        self.assertEqual(result['status'], 'unknown')
        self.assertEqual(result['owned_process'], identity)

    def test_stop_only_owned_identity_and_remote_unknown(self):
        self.prepare()
        identity = {'pid': 12345, 'creation_utc': self.now.isoformat(), 'process_group_id': 'fixture-owned-token'}
        self.run_with_owned_process(identity)
        with patch('benchmark_process.stop_owned', return_value={'status': 'succeeded', 'local_stopped': True}) as stopped:
            result = campaigns.stop(self.state, 'fixture-campaign', True)
        stopped.assert_called_once_with(identity)
        self.assertEqual(result['status'], 'unknown')
        self.assertIsNone(result['owned_process'])
        self.assertEqual(result['cleanup_status'], 'unknown')

    def test_second_stop_reaches_owned_process(self):
        self.prepare()
        identity = {'pid': 12345, 'creation_utc': self.now.isoformat(), 'process_group_id': 'fixture-owned-token'}
        self.run_with_owned_process(identity)
        with patch('benchmark_process.stop_owned', return_value={'status': 'unknown', 'local_stopped': False}) as stopped:
            result = campaigns.stop(self.state, 'fixture-campaign', True)
        stopped.assert_called_once_with(identity)
        self.assertEqual(result['owned_process'], identity)
        with patch('benchmark_process.stop_owned', return_value={'status': 'succeeded', 'local_stopped': True}) as stopped:
            result = campaigns.stop(self.state, 'fixture-campaign', True)
        stopped.assert_called_once_with(identity)
        self.assertIsNone(result['owned_process'])
        stops = [step for step in result['steps'] if step['phase'] == 'stop']
        self.assertEqual([step['step_id'] for step in stops], ['owned-process-1', 'owned-process-2'])
        self.assertEqual(sum(phase == 'run' for phase, _ in self.driver.calls), 1)

    def test_local_teardown_clears_owned_process_but_remote_stays_unknown(self):
        self.prepare()
        identity = {'pid': 4242, 'creation_utc': self.now.isoformat(), 'process_group_id': 'fixture-owned-token'}
        self.driver.use_transport = True
        def fake_run_process(argv, **kwargs):
            kwargs['on_started'](identity)
            return {'status': 'unknown', 'exit_code': None, 'stdout': b'', 'failure_reason': 'timeout',
                    'local_stopped': True}
        with patch('benchmark_process.run_process', side_effect=fake_run_process):
            result = campaigns.run(self.state, 'fixture-campaign', True)
        self.assertEqual(result['status'], 'unknown')
        self.assertIsNone(result['owned_process'])
        self.assertIn('previous_dispatch_unknown', result['reasons'])

    def test_cleanup_and_collection_survive_stale_clock(self):
        self.prepare()
        campaigns.run(self.state, 'fixture-campaign', True)
        # 30h later the frozen clock check (max_campaign_seconds=24h) is stale:
        # it still gates new exercises, never read-only collection or cleanup.
        with self.future_clock(30):
            result = campaigns.collect(self.state, 'fixture-campaign', True)
            self.assertEqual([step['phase'] for step in result['steps']].count('collect'), 1)
            result = campaigns.cleanup(self.state, 'fixture-campaign', True)
        self.assertEqual(result['cleanup_status'], 'succeeded')

    def test_refused_cleanup_dispatches_nothing_and_keeps_status(self):
        self.prepare()
        campaigns.run(self.state, 'fixture-campaign', True)
        campaigns.collect(self.state, 'fixture-campaign', True)
        (self.kit / 'linux_worker.py').write_bytes(b'changed fixture')
        with self.assertRaises(BenchmarkError) as caught:
            campaigns.cleanup(self.state, 'fixture-campaign', True)
        self.assertEqual(caught.exception.code, 'digest_mismatch')
        result = campaigns.status(self.state, 'fixture-campaign')
        self.assertEqual(result['cleanup_status'], 'pending')
        self.assertFalse(any(phase == 'cleanup' for phase, _ in self.driver.calls))

    def test_hard_linked_pinned_executable_is_accepted(self):
        os.link(self.executable, self.root / 'fixture-executor-link')
        self.assertEqual(self.executable.stat().st_nlink, 2)
        self.prepare()
        result = campaigns.run(self.state, 'fixture-campaign', True)
        self.assertEqual(result['status'], 'awaiting_collection')

    def test_export_budget_requires_room_for_both_generations(self):
        self.manifest['collectors'][0]['max_bytes'] = 65536
        self.save()
        with self.assertRaises(BenchmarkError) as caught:
            campaigns.plan(self.manifest_path)
        self.assertEqual(caught.exception.code, 'budget_exceeded')

    def test_both_collection_generations_are_kept(self):
        self.prepare()
        campaigns.run(self.state, 'fixture-campaign', True)
        campaigns.collect(self.state, 'fixture-campaign', True)
        campaigns.collect(self.state, 'fixture-campaign', True)
        campaigns.cleanup(self.state, 'fixture-campaign', True)
        self.driver.complete = True
        with self.future_clock(2):
            campaigns.collect(self.state, 'fixture-campaign', True)
        store = BenchmarkStore(self.state)
        state = store.get_campaign('fixture-campaign')
        generations, complete, current = campaigns._collections(store, state)
        self.assertTrue(complete)
        rows = [row for row in campaigns._rows(store, 'fixture-campaign', 'campaigns') if row['phase'] == 'collect']
        self.assertEqual(generations['exercise']['sensor-1'], rows[1]['receipt']['evidence_sha256'])
        self.assertEqual(generations['cleanup']['sensor-1'], rows[2]['receipt']['evidence_sha256'])
        sealed = [event for event in campaigns._rows(store, 'fixture-campaign', 'events')
                  if event['payload'].get('record_type') == 'private_collection_complete']
        self.assertEqual(sealed[-1]['payload']['generations'], generations)
        # Superseded partial snapshot rows[0] is excluded from the byte budget.
        self.assertEqual(sorted(len(current[key]) for key in current), [1, 1])

    def test_reconcile_does_not_repeat_unknown_action(self):
        self.prepare()
        self.driver.outcome = 'unknown'
        campaigns.run(self.state, 'fixture-campaign', True)
        store = BenchmarkStore(self.state)
        row = next(row for row in campaigns._rows(store, 'fixture-campaign', 'campaigns') if row['phase'] == 'run')
        evidence = {'schema_version': 1, 'campaign_id': 'fixture-campaign', 'phase': 'run',
                    'step_id': row['step_id'], 'fingerprint': row['fingerprint'], 'outcome': 'failed',
                    'process_stopped': True, 'observation': {'observed_target_sha256': row['spec']['target_sha256'],
                        'effect_verified': False, 'source_receipt_sha256': '3' * 64, 'observed_utc': campaigns._now()}}
        path = self.root / 'observation.json'
        path.write_bytes(canonical_bytes(evidence))
        result = campaigns.reconcile(self.state, 'fixture-campaign', 'fixture-reviewer', 'invented independent observation', path)
        self.assertEqual(result['status'], 'awaiting_collection')
        self.assertEqual(result['cleanup_status'], 'failed')
        self.assertEqual(sum(phase == 'run' for phase, _ in self.driver.calls), 1)
        reconciled = next(item for item in campaigns._rows(
            BenchmarkStore(self.state), 'fixture-campaign', 'campaigns') if item['phase'] == 'run')
        self.assertIsNone(reconciled['receipt']['elapsed_ms'])
        with self.assertRaises(BenchmarkError):
            campaigns.run(self.state, 'fixture-campaign', True)

    def test_aws_retention_exception_does_not_release(self):
        self.use_aws()
        self.driver.retention = True
        self.prepare()
        campaigns.run(self.state, 'fixture-campaign', True)
        result = campaigns.cleanup(self.state, 'fixture-campaign', True)
        self.assertEqual(result['cleanup_status'], 'succeeded')
        self.assertEqual(result['status'], 'awaiting_collection')
        self.assertFalse(result['live_verified'])

    def test_shipped_aws_cost_bound_is_unknown_and_blocks_before_state(self):
        shipped = Path(__file__).resolve().parents[1] / 'hunt-range' / 'benchmark' / 'recipes.json'
        if not shipped.is_file():
            self.skipTest('separate range kit is intentionally not bundled')
        self.use_aws(limit=1000000, recipes=shipped.read_bytes())
        bound = campaigns._cloud_cost_bound(self.kit, self.manifest, campaigns._now())
        self.assertIsNone(bound['usd'])
        self.assertIn('run.warmup.cloudtrail-management-event-copy:quantity_unknown', bound['unknown'])
        with self.assertRaises(BenchmarkError) as caught:
            campaigns.preflight(self.state, self.manifest_path, self.kit, True)
        self.assertEqual(caught.exception.code, 'cloud_cost_bound_unknown')
        self.assertFalse(self.state.exists())
        self.assertEqual(self.driver.calls, [])

    def test_cost_ceiling_below_bound_refuses_preflight(self):
        self.use_aws(limit=1.5)
        with self.assertRaises(BenchmarkError) as caught:
            campaigns.preflight(self.state, self.manifest_path, self.kit, True)
        self.assertEqual(caught.exception.code, 'budget_exceeded')
        self.assertFalse(self.state.exists())
        self.assertEqual(self.driver.calls, [])

    def test_cost_bound_is_recorded_in_every_authorization_and_receipt(self):
        self.use_aws()
        self.prepare()
        store = BenchmarkStore(self.state)
        state = store.get_campaign('fixture-campaign')
        bound = campaigns._metadata(store, state)['cloud_cost_bound']
        # 50,000 events at 2.0/100,000 plus 0.25/hour for ceil(<4h) = 4 hours.
        self.assertEqual((bound['status'], bound['usd'], bound['lifetime_hours'], bound['limit_usd']), ('known', 2.0, 4, 5))
        authorizations = {item['authorization_sha256'] for item in campaigns._rows(store, 'fixture-campaign', 'approvals')
                          if item['kind'] == 'authorization'}
        recorded = {event['payload']['authorization_sha256'] for event in campaigns._rows(store, 'fixture-campaign', 'events')
                    if event['payload'].get('record_type') == 'cloud_cost_bound' and event['payload']['cloud_cost_bound'] == bound}
        self.assertEqual(len(authorizations), 2)
        self.assertEqual(recorded, authorizations)
        campaigns.run(self.state, 'fixture-campaign', True)
        rows = [row for row in campaigns._rows(store, 'fixture-campaign', 'campaigns') if row['phase'] in ('preflight', 'run')]
        for row in rows:
            self.assertEqual(campaigns._result(store, state, row)['evidence']['cloud_cost_bound'], bound)
        self.assertEqual(campaigns.status(self.state, 'fixture-campaign')['cloud_cost_bound'], bound)

    def test_authorization_without_recorded_cost_bound_cannot_dispatch(self):
        self.use_aws()
        campaigns.preflight(self.state, self.manifest_path, self.kit, True)
        store = BenchmarkStore(self.state)
        state = store.get_campaign('fixture-campaign')
        store.record_authorization(dict(approval_id='auth-direct-fixture', experiment_id=None, trial_id=None,
                                        campaign_id='fixture-campaign', by='fixture-reviewer', note='bypasses controller',
                                        created_utc=campaigns._now(), expires_utc=self.expiry, evidence_sha256=None,
                                        model_sha256s=[], manifest_sha256=state['manifest_sha256'], phases=['run']))
        campaigns._change(store, state, status='authorized')
        with self.assertRaises(BenchmarkError) as caught:
            campaigns.run(self.state, 'fixture-campaign', True)
        self.assertEqual(caught.exception.code, 'authorization_required')
        self.assertFalse(any(phase == 'run' for phase, _ in self.driver.calls))

    def test_failed_leftover_check_quarantines_targets(self):
        self.prepare()
        campaigns.run(self.state, 'fixture-campaign', True)
        campaigns.collect(self.state, 'fixture-campaign', True)
        self.driver.cleanup_outcome = 'failed'
        result = campaigns.cleanup(self.state, 'fixture-campaign', True)
        self.assertEqual(result['cleanup_status'], 'failed')
        self.assertIn('targets_quarantined', result['reasons'])
        self.manifest['campaign_id'] = 'fixture-campaign-2'
        self.save()
        calls = len(self.driver.calls)
        with self.assertRaises(BenchmarkError) as caught:
            campaigns.preflight(self.state, self.manifest_path, self.kit, True)
        self.assertEqual(caught.exception.code, 'target_quarantined')
        with self.assertRaises(BenchmarkError):
            BenchmarkStore(self.state).get_campaign('fixture-campaign-2')
        self.assertEqual(len(self.driver.calls), calls)

    def test_cleanup_refuses_while_controller_job_is_owned(self):
        self.prepare()
        identity = {'pid': 4343, 'creation_utc': self.now.isoformat(), 'process_group_id': 'fixture-owned-token'}
        self.driver.use_transport = True
        def fake_run_process(argv, **kwargs):
            kwargs['on_started'](identity)
            return {'status': 'succeeded', 'exit_code': 0, 'stdout': b'', 'failure_reason': None,
                    'local_stopped': False}
        with patch('benchmark_process.run_process', side_effect=fake_run_process):
            result = campaigns.run(self.state, 'fixture-campaign', True)
        self.assertEqual(result['status'], 'awaiting_collection')
        self.assertEqual(result['owned_process'], identity)
        campaigns.collect(self.state, 'fixture-campaign', True)
        with self.assertRaises(BenchmarkError) as caught:
            campaigns.cleanup(self.state, 'fixture-campaign', True)
        self.assertEqual(caught.exception.code, 'process_not_stopped')
        self.assertFalse(any(phase == 'cleanup' for phase, _ in self.driver.calls))
        self.assertEqual(campaigns.status(self.state, 'fixture-campaign')['cleanup_status'], 'pending')

    def test_receipt_persistence_failure_remains_unknown_without_retry(self):
        self.prepare()
        campaigns.run(self.state, 'fixture-campaign', True)
        with patch.object(BenchmarkStore, 'finish_campaign_step',
                          side_effect=BenchmarkError('state_unavailable', 'fixture.store')):
            with self.assertRaises(BenchmarkError):
                campaigns.collect(self.state, 'fixture-campaign', True)
        result = campaigns.status(self.state, 'fixture-campaign')
        self.assertEqual(result['status'], 'unknown')
        self.assertIn('previous_dispatch_unknown', result['reasons'])
        count = len(self.driver.calls)
        with self.assertRaises(BenchmarkError):
            campaigns.collect(self.state, 'fixture-campaign', True)
        self.assertEqual(len(self.driver.calls), count)

    def test_zeek_exact_spool_hashes_and_watermark(self):
        spool = self.root / 'spool'
        spool.mkdir()
        private = self.root / 'private-zeek'
        (private / 'raw').mkdir(parents=True)
        context = {'private_root': str(private)}
        collector = copy.deepcopy(self.manifest['collectors'][0])
        collector.update(kind='zeek', export_root=str(spool), config={'manifest_path': 'window.json', 'streams': ['conn'], 'address_assets': []})
        record = canonical_bytes({'ts': self.now.timestamp(), 'uid': 'fixture-only', 'id.orig_h': '192.0.2.4'}) + b'\n'
        (spool / 'conn.jsonl').write_bytes(record)
        metadata = {'schema_version': 1, 'source_id': collector['source_id'], 'window_utc': collector['window_utc'],
                    'watermark_utc': self.now.isoformat(), 'sealed': False,
                    'files': [{'path': 'conn.jsonl', 'sha256': digest_bytes(record), 'byte_count': len(record), 'stream': 'conn'}]}
        (spool / 'window.json').write_bytes(canonical_bytes(metadata))
        campaigns._validate_zeek(self.manifest, collector)
        for assets in ([{'address': '192.0.2.4', 'target_id': 'victim'}], [{'address': '192.0.2.04', 'target_id': 'other'}]):
            bad = copy.deepcopy(collector)
            bad['config']['address_assets'] = assets
            with self.assertRaises(BenchmarkError):
                campaigns._validate_zeek(self.manifest, bad)
        result = campaigns._zeek(self.manifest, collector, 'collect', context)
        self.assertEqual(result['execution_outcome'], 'blocked')
        self.assertFalse(result['raw_exports'][0]['complete'])
        self.assertEqual(len(result['raw_exports'][0]['records']), 1)
        self.assertEqual((private / 'raw' / (digest_bytes(record) + '.bin')).read_bytes(), record)
        (spool / 'conn.jsonl').write_bytes(b'changed fixture')
        with self.assertRaises(BenchmarkError) as caught:
            campaigns._zeek(self.manifest, collector, 'collect', context)
        self.assertEqual(caught.exception.code, 'digest_mismatch')


if __name__ == '__main__':
    unittest.main()

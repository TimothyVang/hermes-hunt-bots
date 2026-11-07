"""Offline synthetic collection/release evidence; no lab or model dispatch."""
import copy
import unittest
from unittest.mock import patch

import benchmark_campaigns as campaigns
import benchmark_runner as runner
import benchmark_store as storage
from benchmark_contracts import BenchmarkError, canonical_bytes, decode_json, digest_bytes
from benchmark_reporting import export_snapshot
from benchmark_store import BenchmarkStore
import test_benchmark_campaigns as campaign_fixtures
from test_benchmark_runner import frozen_fixture


# Embedded inert rules keep these tests independent of the separately provisioned kit.
JOURNAL_RULES = {
    'schema_version': 1, 'version': 'collector-fields-2', 'sources': {
        'journald': {'format': 'journald-json-v1',
                    'allowed_fields': ['_PID', '_COMM', '_EXE', '_UID', '_SYSTEMD_UNIT',
                                       'SYSLOG_IDENTIFIER', 'PRIORITY', '_BOOT_ID', '_MACHINE_ID'],
                    'pseudonym_fields': ['_UID', '_SYSTEMD_UNIT', '_BOOT_ID', '_MACHINE_ID'],
                    'basename_fields': ['_COMM', '_EXE', 'SYSLOG_IDENTIFIER'],
                    'content_fields': [],
                    'supported_event_types': ['journal_record']}}}


class ReleaseTests(unittest.TestCase):
    # Reuse only fixture helpers, not the controller test methods.
    save = campaign_fixtures.CampaignTests.save
    prepare = campaign_fixtures.CampaignTests.prepare
    future_clock = campaign_fixtures.CampaignTests.future_clock

    def setUp(self):
        campaign_fixtures.CampaignTests.setUp(self)
        from benchmark_evidence import FORMATS, EVENTS
        rules = {'schema_version': 1, 'version': 'collector-fields-2', 'sources': {
            key: {'format': value, 'allowed_fields': [], 'pseudonym_fields': [],
                  'basename_fields': [], 'content_fields': [], 'supported_event_types': sorted(EVENTS[key])}
            for key, value in FORMATS.items()}}
        rules['sources']['journald'] = JOURNAL_RULES['sources']['journald']
        (self.kit / 'collector-fields.json').write_bytes(canonical_bytes(rules))
        self.manifest['range_kit_sha256'] = campaigns._hash({
            name: digest_bytes((self.kit / name).read_bytes()) for name in campaigns.KIT_FILES})
        self.manifest['targets'][0]['identity']['machine_id'] = 'a' * 32
        self.save()
        original = self.driver.execute_step

        def journal_result(manifest, kit, phase, step, context, transport):
            result = original(manifest, kit, phase, step, context, transport)
            if phase == 'collect':
                stamp = self.now.replace(microsecond=0)
                result['raw_exports'][0]['records'] = [{
                    'source_type': 'journald', 'record_id': 'synthetic-cursor',
                    'timestamp_utc': stamp.isoformat(),
                    'record': {'__CURSOR': 'synthetic-cursor',
                               '__REALTIME_TIMESTAMP': str(int(stamp.timestamp()) * 1000000),
                               '_PID': '42', '_COMM': 'sshd', '_UID': '1000',
                               '_MACHINE_ID': 'a' * 32, '_BOOT_ID': 'b' * 32,
                               'MESSAGE': 'PRIVATE MESSAGE; never public'}}]
            return result

        self.driver.execute_step = journal_result
        self.mapping = {
            'schema_version': 1, 'case_id': 'case-1234abcd',
            'assets': [{'target_id': 'victim', 'os_family': 'linux',
                        'os_version': None, 'architecture': None, 'vendor': None}],
            'entity_aliases': [], 'known_gaps': [],
            'assessment_windows': [copy.deepcopy(self.manifest['collectors'][0]['window_utc'])],
            'max_public_bytes': 65536}
        self.mapping_path = self.root / 'mapping.json'
        self.mapping_path.write_bytes(canonical_bytes(self.mapping))
        self.public = self.state / 'campaigns' / 'fixture-campaign' / 'public' / 'bundle-a'
        self.destinations_path = self.root / 'destinations.json'

    def collected(self):
        self.prepare()
        campaigns.run(self.state, 'fixture-campaign', True)
        campaigns.collect(self.state, 'fixture-campaign', True)
        campaigns.cleanup(self.state, 'fixture-campaign', True)
        self.driver.complete = True
        with self.future_clock(2):
            campaigns.collect(self.state, 'fixture-campaign', True)
        self.store = BenchmarkStore(self.state)

    def seal(self, destination=None):
        clock = self.future_clock(2)
        with clock, patch.object(storage.dt, 'datetime', clock.new):
            return campaigns.seal(self.state, 'fixture-campaign', self.mapping_path, destination or self.public)

    def initialize(self, experiment_id='release-experiment', repetitions=2, paid=False):
        frozen = frozen_fixture()
        public = decode_json((self.public / 'evidence.json').read_bytes())
        scenario = copy.deepcopy(frozen['cases'][0]['scenario'])
        scenario['provenance'] = 'lab_export'
        scenario['evidence_manifest_sha256'] = digest_bytes(canonical_bytes(public))
        frozen['experiment']['experiment_id'] = experiment_id
        frozen['experiment']['repetitions'] = repetitions
        frozen['experiment']['scenario_refs'] = frozen['experiment']['scenario_refs'][:1]
        team = frozen['experiment']['teams'][0]
        if paid:
            # A non-loopback route: private evidence may reach it only after a release.
            team['deployment'] = 'cloud'
            for spec in team['roles'].values():
                spec.update(base_url='https://api.example.test/v1', credential_env='BENCH_MODEL_TEST_KEY')
            frozen['experiment']['budgets'].update(max_api_cost_usd=1.0, per_call_cost_bound_usd=0.01)
        # Two configured identities permit exact subset-release checks without providers.
        model = team['roles']['framework-researcher']
        model['model_requested'] = 'synthetic-release-model-b'
        model['expected_model_ids'] = ['synthetic-release-model-b']
        loaded = dict(frozen, cases=[{'scenario': scenario, 'evidence': public,
                                     'evidence_path': str(self.public / 'evidence.json')}])
        # Init freezes truth automatically; this synthetic key has no steps or
        # decidable labels: a test-only placeholder for the sealed bundle.
        truth_root = self.root / 'release-truth'
        truth_path = truth_root / public['case_id'] / 'evaluator' / 'truth.json'
        truth_path.parent.mkdir(parents=True, exist_ok=True)
        truth_path.write_bytes(canonical_bytes({
            'schema_version': 1, 'case_id': public['case_id'],
            'evidence_manifest_sha256': scenario['evidence_manifest_sha256'], 'truth_revision': 1,
            'attack_release': scenario['attack_release'], 'steps': [], 'edges': [], 'controls': [],
            'assessment_labels': {q['question_id']: None for q in public['assessment_questions']}}))
        runner.initialize_experiment(self.state, loaded, truth_root)
        trials = self.store.trials(experiment_id)
        models = sorted({campaigns._hash(value) for value in frozen['experiment']['teams'][0]['roles'].values()})
        return [{'experiment_id': experiment_id, 'trial_id': trial['trial_id'],
                 'model_sha256s': models} for trial in trials]

    def destinations(self, trials):
        return {'schema_version': 1, 'evidence_sha256': digest_bytes((self.public / 'evidence.json').read_bytes()),
                'expires_utc': self.expiry, 'trials': trials}

    def release(self, value, by='synthetic-human-reviewer'):
        self.destinations_path.write_bytes(canonical_bytes(value))
        clock = self.future_clock(2)
        with clock, patch.object(storage.dt, 'datetime', clock.new):
            return campaigns.release(self.state, 'fixture-campaign', by,
                                     'Inspected exact synthetic public bytes; no actual provider authority.',
                                     self.destinations_path)

    def trial_grants(self):
        with self.store.connection() as db:
            return db.execute("SELECT approval_id FROM approvals WHERE trial_id IS NOT NULL AND kind='authorization'").fetchall()

    def test_seal_initialization_release_are_separate_and_never_dispatch(self):
        self.collected()
        calls_before = list(self.driver.calls)
        with patch.object(campaigns, '_execute', side_effect=AssertionError('dispatch forbidden')):
            sealed = self.seal()
            self.assertEqual(sealed['execution'], 'not_dispatched')
            self.assertEqual(sealed['condition'], 'raw_telemetry')
            self.assertTrue(sealed['human_release_required'])
            self.assertEqual(self.store.get_campaign('fixture-campaign')['status'], 'awaiting_release')
            self.assertEqual(self.trial_grants(), [])
            trials = self.initialize()
            result = self.release(self.destinations(trials))
        self.assertEqual(result['execution'], 'not_dispatched')
        self.assertEqual(len(self.trial_grants()), len(trials))
        self.assertEqual(self.driver.calls, calls_before)
        self.assertIsNone(self.store.get_campaign('fixture-campaign')['experiment_id'])
        public = (self.public / 'evidence.json').read_bytes() + (self.public / 'records.jsonl').read_bytes()
        self.assertNotIn(b'PRIVATE MESSAGE', public)
        self.assertNotIn(b'linux-discovery-v1', public)
        snapshot = self.store.snapshot('release-experiment')
        self.assertEqual(len(snapshot['campaign_states']), 1)
        self.assertTrue(any(event['payload'].get('record_type') == 'campaign_evidence_release'
                            for event in snapshot['events']))
        for approval in snapshot['approvals']:
            if approval['trial_id'] is not None:
                self.assertEqual(approval['by'], 'synthetic-human-reviewer')
                self.assertIsNone(approval['campaign_id'])
                self.assertEqual(approval['phases'], [])
        export = self.root / 'released-export'
        export_snapshot(self.store, 'release-experiment', export)
        exported = [decode_json(line) for line in (export / 'campaigns.jsonl').read_bytes().splitlines()]
        self.assertTrue(exported)
        self.assertTrue(all(row['campaign_id'] == 'fixture-campaign' for row in exported))

    def test_seal_keeps_both_generations_and_private_phase_windows(self):
        self.collected()
        self.seal()
        private = self.state / 'campaigns' / 'fixture-campaign'
        generations, _, _ = campaigns._collections(self.store, self.store.get_campaign('fixture-campaign'))
        for generation in ('exercise', 'cleanup'):
            sha = generations[generation]['sensor-1']
            self.assertEqual((private / 'sealing' / 'snapshots' / (sha + '.json')).read_bytes(),
                             (private / 'raw' / (sha + '.json')).read_bytes())
        record = decode_json((private / 'sealing' / 'phase-windows.json').read_bytes())
        self.assertEqual(record['record_type'], 'evaluator_phase_windows')
        self.assertEqual([item['phase'] for item in record['phases']], ['exercise', 'cleanup'])
        public = (self.public / 'evidence.json').read_bytes() + (self.public / 'records.jsonl').read_bytes()
        self.assertNotIn(b'phase', public)
        self.assertNotIn(b'fixture-campaign', public)

    def test_exercise_record_lost_before_final_collection_blocks_seal(self):
        current = self.driver.execute_step

        def lose_exercise_record(manifest, kit, phase, step, context, transport):
            result = current(manifest, kit, phase, step, context, transport)
            if phase == 'collect' and context.get('collection_generation') == 'cleanup':
                result['raw_exports'][0]['records'] = []
            return result

        self.driver.execute_step = lose_exercise_record
        self.collected()
        with self.assertRaises(BenchmarkError) as caught:
            self.seal()
        self.assertEqual(caught.exception.code, 'incomplete_export')
        self.assertFalse(self.public.exists())
        self.assertEqual(self.trial_grants(), [])

    def test_export_rejects_corrupted_released_public_and_raw_provenance(self):
        self.collected()
        self.seal()
        self.release(self.destinations(self.initialize()))
        generations, _, _ = campaigns._collections(self.store, self.store.get_campaign('fixture-campaign'))
        raw = self.state / 'campaigns' / 'fixture-campaign' / 'raw' / (generations['cleanup']['sensor-1'] + '.json')
        for index, path in enumerate((self.public / 'evidence.json', self.public / 'records.jsonl', raw)):
            original = path.read_bytes()
            path.write_bytes(original + b' ')
            with self.assertRaises(BenchmarkError):
                export_snapshot(self.store, 'release-experiment', self.root / ('corrupt-export-' + str(index)))
            path.write_bytes(original)

    def test_unusable_initialized_ledger_rolls_back_all_destinations(self):
        self.collected()
        self.seal()
        trials = self.initialize()
        ledger = self.state / 'trials' / trials[-1]['trial_id'] / 'ledger' / 'workflow.sqlite3'
        ledger.write_bytes(b'invalid synthetic ledger bytes')
        with self.assertRaises(BenchmarkError):
            self.release(self.destinations(trials))
        self.assertEqual(self.trial_grants(), [])
        self.assertEqual(self.store.get_campaign('fixture-campaign')['status'], 'awaiting_release')

    def test_atomic_invalid_later_destination_has_no_first_grant(self):
        self.collected()
        self.seal()
        trials = self.initialize()
        trials[-1]['model_sha256s'] = ['f' * 64]
        with self.assertRaises(BenchmarkError):
            self.release(self.destinations(trials))
        self.assertEqual(self.trial_grants(), [])
        self.assertEqual(self.store.get_campaign('fixture-campaign')['status'], 'awaiting_release')
        self.assertFalse(any(event['payload'].get('record_type') == 'campaign_evidence_release'
                             for event in campaigns._rows(self.store, 'fixture-campaign', 'events')))

    def test_wrong_digest_expiry_missing_trial_and_nonhuman_reject_all(self):
        self.collected()
        self.seal()
        trials = self.initialize()
        good = self.destinations(trials)
        for change in ('digest', 'expired', 'trial', 'duplicate', 'unknown_field'):
            bad = copy.deepcopy(good)
            if change == 'digest':
                bad['evidence_sha256'] = 'f' * 64
            elif change == 'expired':
                bad['expires_utc'] = '2001-01-01T00:00:00+00:00'
            elif change == 'trial':
                bad['trials'][-1]['trial_id'] = 'missing-trial'
            elif change == 'duplicate':
                bad['trials'].append(copy.deepcopy(bad['trials'][0]))
            else:
                bad['command'] = 'must-not-execute'
            with self.subTest(change=change), self.assertRaises(BenchmarkError):
                self.release(bad)
            self.assertEqual(self.trial_grants(), [])
        with self.assertRaises(BenchmarkError):
            self.release(good, by='operator-cli')
        self.assertEqual(self.trial_grants(), [])

    def test_changed_public_and_trial_files_are_not_approvable(self):
        self.collected()
        self.seal()
        trials = self.initialize()
        destinations = self.destinations(trials)
        for path in (self.public / 'evidence.json', self.public / 'records.jsonl'):
            original = path.read_bytes()
            path.write_bytes(original + b' ')
            with self.assertRaises(BenchmarkError):
                self.release(destinations)
            self.assertEqual(self.trial_grants(), [])
            path.write_bytes(original)
        last = self.store.get_trial(trials[-1]['trial_id'])
        ref = next(iter(last['public_artifacts'].values()))
        artifact = self.state / 'trials' / last['trial_id'] / ref['path']
        artifact.write_bytes(b'changed frozen evidence')
        with self.assertRaises(BenchmarkError):
            self.release(destinations)
        self.assertEqual(self.trial_grants(), [])

    def test_changed_raw_and_kit_prevent_release(self):
        self.collected()
        self.seal()
        trials = self.initialize()
        destinations = self.destinations(trials)
        state = self.store.get_campaign('fixture-campaign')
        generations, _, _ = campaigns._collections(self.store, state)
        raw = self.state / 'campaigns' / 'fixture-campaign' / 'raw' / (generations['cleanup']['sensor-1'] + '.json')
        for path in (raw, self.kit / 'collector-fields.json'):
            original = path.read_bytes()
            path.write_bytes(original + b' ')
            with self.assertRaises(BenchmarkError):
                self.release(destinations)
            self.assertEqual(self.trial_grants(), [])
            path.write_bytes(original)

    def test_cleanup_incomplete_and_unknown_are_not_sealable(self):
        self.prepare()
        self.store = BenchmarkStore(self.state)
        campaigns.run(self.state, 'fixture-campaign', True)
        with self.assertRaises(BenchmarkError):
            self.seal()
        campaigns.collect(self.state, 'fixture-campaign', True)
        campaigns.cleanup(self.state, 'fixture-campaign', True)
        with self.assertRaises(BenchmarkError):
            self.seal()
        self.driver.complete = True
        with self.future_clock(2):
            campaigns.collect(self.state, 'fixture-campaign', True)
        self.store.request_campaign_stop('fixture-campaign')
        with self.assertRaises(BenchmarkError):
            self.seal()
        self.assertEqual(self.trial_grants(), [])
        self.assertFalse(self.public.exists())

    def test_mapping_frozen_new_destination_required_and_exact_sources_only(self):
        self.collected()
        first = self.seal()
        with self.assertRaises(BenchmarkError):
            self.seal()
        generations, _, _ = campaigns._collections(self.store, self.store.get_campaign('fixture-campaign'))
        clock = self.future_clock(2)
        with clock, patch.object(storage.dt, 'datetime', clock.new):
            second = campaigns.seal_evidence({
                'state_root': str(self.state), 'campaign_id': 'fixture-campaign',
                'snapshots': [{'source_id': source, 'sha256': sha}
                              for source, sha in generations['cleanup'].items()]},
                self.mapping, self.public.with_name('bundle-b'))
        self.assertEqual(first['evidence_sha256'], campaigns._hash(second))
        self.mapping['assets'][0]['vendor'] = 'Changed'
        self.mapping_path.write_bytes(canonical_bytes(self.mapping))
        with self.assertRaises(BenchmarkError):
            self.seal(self.public.with_name('bundle-c'))
        with self.assertRaises(BenchmarkError):
            self.seal(self.root / 'outside-public')
        with self.future_clock(2), self.assertRaises(BenchmarkError):
            campaigns.seal_evidence({'state_root': str(self.state), 'campaign_id': 'fixture-campaign',
                                     'snapshots': [{'source_id': 'sensor-1', 'sha256': 'f' * 64}]},
                                    self.mapping, self.public.with_name('bundle-d'))
        self.assertEqual(self.trial_grants(), [])

    def test_explicit_rerelease_subset_and_multiple_experiments(self):
        self.collected()
        self.seal()
        first = self.initialize('release-one', repetitions=1)
        second = self.initialize('release-two', repetitions=1)
        first[0]['model_sha256s'] = first[0]['model_sha256s'][:1]
        self.release(self.destinations(first))
        self.assertEqual(len(self.trial_grants()), 1)
        self.release(self.destinations(second))
        self.assertEqual(len(self.trial_grants()), 2)
        for experiment in ('release-one', 'release-two'):
            snapshot = self.store.snapshot(experiment)
            self.assertEqual(len(snapshot['campaign_states']), 1)
            self.assertTrue(all(trial['experiment_id'] == experiment for trial in snapshot['trials']))
            self.assertTrue(all(event['trial_id'] is None or event['experiment_id'] == experiment
                                for event in snapshot['events']))
            destination = self.root / (experiment + '-export')
            export_snapshot(self.store, experiment, destination)
            exported = [decode_json(line) for line in (destination / 'events.jsonl').read_bytes().splitlines()]
            self.assertTrue(all(event['trial_id'] is None or event['experiment_id'] == experiment
                                for event in exported))
        self.assertIsNone(self.store.get_campaign('fixture-campaign')['experiment_id'])

    def test_transaction_event_failure_rolls_back_every_grant_and_transition(self):
        self.collected()
        self.seal()
        trials = self.initialize()
        original = BenchmarkStore.event

        def fail_link(store, kind, actor, payload, *args, **kwargs):
            if payload.get('record_type') == 'campaign_evidence_release':
                raise BenchmarkError('storage_error', 'synthetic.release')
            return original(store, kind, actor, payload, *args, **kwargs)

        with patch.object(BenchmarkStore, 'event', fail_link), self.assertRaises(BenchmarkError):
            self.release(self.destinations(trials))
        self.assertEqual(self.trial_grants(), [])
        self.assertEqual(self.store.get_campaign('fixture-campaign')['status'], 'awaiting_release')

    def test_unknown_campaign_after_seal_cannot_grant_destinations(self):
        self.collected()
        self.seal()
        destinations = self.destinations(self.initialize())
        self.store.request_campaign_stop('fixture-campaign')
        with self.assertRaises(BenchmarkError):
            self.release(destinations)
        self.assertEqual(self.trial_grants(), [])

    def test_runner_requires_exact_released_model_and_trial(self):
        self.collected()
        self.seal()
        destinations = self.initialize(paid=True)
        trial = self.store.get_trial(destinations[0]['trial_id'])
        frozen = self.store.get_experiment(trial['experiment_id'])
        team = frozen['experiment']['teams'][0]
        selected = team['roles']['framework-coordinator']
        withheld = team['roles']['framework-researcher']
        with self.assertRaises(BenchmarkError) as caught:
            runner._authorize(self.store, frozen, trial, selected)
        self.assertEqual(caught.exception.code, 'release_required')
        destination = dict(destinations[0], model_sha256s=[campaigns._hash(selected)])
        self.release(self.destinations([destination]))
        with self.assertRaises(BenchmarkError) as caught:
            runner._authorize(self.store, frozen, trial, withheld)
        self.assertEqual(caught.exception.code, 'release_required')
        other_trial = self.store.get_trial(destinations[1]['trial_id'])
        with self.assertRaises(BenchmarkError):
            runner._authorize(self.store, frozen, other_trial, selected)
        authority = runner._authorize(self.store, frozen, trial, selected)
        self.assertEqual(len(authority), 64)
        with self.store.connection() as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM calls').fetchone()[0], 0)

    def test_private_evidence_on_a_loopback_route_needs_no_release(self):
        self.collected()
        self.seal()
        destinations = self.initialize()
        trial = self.store.get_trial(destinations[0]['trial_id'])
        frozen = self.store.get_experiment(trial['experiment_id'])
        model = frozen['experiment']['teams'][0]['roles']['framework-coordinator']
        scenario = runner._case(frozen, trial)['scenario']
        self.assertEqual(scenario['provenance'], 'lab_export')
        # The bytes never leave this machine; any non-loopback route would need a release.
        self.assertFalse(runner.release_required(scenario, model))
        self.assertTrue(runner.release_required(scenario, dict(model, base_url='https://api.example.test/v1')))
        self.assertEqual(len(runner._authorize(self.store, frozen, trial, model)), 64)
        # Only the runner's own execution authority exists; no release grant was needed.
        self.assertEqual({item['by'] for item in self.store.trial_authorizations(trial['trial_id'])},
                         {'operator-cli'})


if __name__ == '__main__':
    unittest.main()

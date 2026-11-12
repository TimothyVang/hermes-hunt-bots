"""Offline export regressions using frozen fixtures, never model measurements."""
import copy
import csv
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from benchmark import load_experiment
from benchmark_contracts import BenchmarkError, STAGE_KEYS, canonical_bytes, confined_file, digest_bytes
from benchmark_reporting import export_snapshot, _holdout, _trial_timing
from benchmark_paths import FRAMEWORK
from benchmark_store import BenchmarkStore


HERE = Path(__file__).resolve().parent
NOW = '2026-01-01T00:00:00+00:00'


def frozen_fixture():
    loaded = load_experiment(HERE / 'benchmarks' / 'examples' / 'experiment.json',
                             HERE / 'benchmarks')
    catalog = json.loads((FRAMEWORK / 'hermes-bots' / 'catalog.json').read_text(encoding='utf-8'))
    frozen = {'experiment': loaded['experiment'], 'coverage': loaded['coverage'],
              'workflow': loaded['workflow'], 'prompt_contract': loaded['prompt_contract'],
              'cases': [{'scenario': case['scenario'], 'evidence': case['evidence'],
                         'public_files': case['evidence']['files']} for case in loaded['cases']],
              'role_instructions': {item['name']: item['description'] for item in catalog},
              'created_utc': NOW, 'execution': 'framework-managed'}
    frozen['experiment']['repetitions'] = 1
    for row in frozen['coverage']['rows']:
        row.update(status='planned', evidence_references=[])
    for field in ('coverage', 'workflow'):
        frozen['experiment'][field + '_sha256'] = digest_bytes(canonical_bytes(frozen[field]))
    return frozen, loaded


class SnapshotFixture:
    """Detached store snapshot with real on-disk artifact bytes for corruption tests."""

    def __init__(self, root):
        self.root = root
        frozen, loaded = frozen_fixture()
        self.backend = BenchmarkStore(root, create=True)
        self.backend.create_experiment(frozen)
        self.experiment_id = frozen['experiment']['experiment_id']
        case = frozen['cases'][0]
        self.trial_id = 'trial-fixture-1'
        trial = {'trial_id': self.trial_id, 'experiment_id': self.experiment_id,
                 'case_id': case['evidence']['case_id'], 'scenario_id': case['scenario']['scenario_id'],
                 'team_id': frozen['experiment']['teams'][0]['team_id'], 'repetition': 1,
                 'workflow_id': 1, 'task_mapping': {stage: index + 1 for index, stage in enumerate(STAGE_KEYS)},
                 'case_evidence_sha256': case['scenario']['evidence_manifest_sha256'],
                 'status': 'pending', 'created_utc': NOW, 'public_artifacts': {}}
        for descriptor in case['evidence']['files']:
            data = confined_file(loaded['cases'][0]['evidence_path'].parent, descriptor['path']).read_bytes()
            trial['public_artifacts'][descriptor['path']] = self.add_artifact(data)
        self.backend.create_trial(trial)
        self.data = self.backend.snapshot(self.experiment_id)
        self.snapshot_count = 0
        self.after_snapshot = None

    def add_artifact(self, data):
        return self.backend.write_artifact(self.trial_id, 'public', data)

    def snapshot(self, experiment_id):
        if experiment_id != self.experiment_id:
            raise BenchmarkError('not_found', 'experiment_id')
        self.snapshot_count += 1
        value = copy.deepcopy(self.data)
        if self.after_snapshot:
            self.after_snapshot()
        return value

    def read_artifact(self, trial_id, reference):
        return self.backend.read_artifact(trial_id, reference)


class ReportingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.store = SnapshotFixture(self.root / 'state')
        self.output = self.root / 'export'

    def export(self):
        return export_snapshot(self.store, self.store.experiment_id, self.output)

    def verified_row(self):
        frozen = self.store.data['experiment']
        row = copy.deepcopy(frozen['coverage']['rows'][0])
        row.update(row_id='synthetic-report-fixture', status='synthetic_verified',
                   coverage=copy.deepcopy(frozen['cases'][0]['scenario']['coverage']),
                   evidence_references=[frozen['experiment']['scenario_refs'][0]['evidence']])
        frozen['coverage']['rows'].append(row)
        return row

    def test_pending_export_contains_all_outputs_and_unknowns(self):
        report = self.export()
        self.assertEqual({path.name for path in self.output.iterdir()}, {
            'events.jsonl', 'calls.jsonl', 'campaigns.jsonl', 'scores.jsonl',
            'coverage.csv', 'report.json', 'report.md'})
        self.assertEqual(report['scoring']['status'], 'pending')
        self.assertIsNone(report['scoring']['ranking'])
        self.assertEqual((self.output / 'scores.jsonl').read_bytes(), b'')
        team = report['teams'][0]
        self.assertEqual(len(team['configuration']['roles']), 6)
        self.assertEqual(team['identity_attestation'], 'unknown')
        self.assertIsNone(team['measurements']['cost']['api_cost_usd']['total'])
        self.assertIsNone(team['end_to_end_ms']['total'])
        self.assertEqual(report['review_policy'], 'auto_advance')
        self.assertEqual(report['max_concurrent_calls'], 4)
        self.assertTrue(report['timing_contended'])
        markdown = (self.output / 'report.md').read_text(encoding='utf-8')
        self.assertIn('Review policy: **auto&#95;advance** (no stage was human-reviewed)', markdown)
        self.assertNotIn('Human wait', markdown)
        self.assertIsNone(team['measurements']['model_active_ms']['total'])
        self.assertEqual(json.loads((self.output / 'report.json').read_bytes()), report)

    def test_snapshot_taken_once_despite_later_store_changes(self):
        original = copy.deepcopy(self.store.data)
        def change_live_state():
            self.store.data['events'].append(dict(original['events'][0], seq=original['events'][-1]['seq'] + 1,
                                                  event_id='later-event'))
            self.store.data['trials'][0]['status'] = 'failed'
        self.store.after_snapshot = change_live_state
        report = self.export()
        self.assertEqual(self.store.snapshot_count, 1)
        self.assertEqual(report['snapshot']['last_event_seq'], original['events'][-1]['seq'])
        self.assertEqual(report['snapshot']['sha256'], digest_bytes(canonical_bytes(original)))
        self.assertEqual(report['trials'][0]['status'], 'pending')
        self.assertEqual(len((self.output / 'events.jsonl').read_text().splitlines()), len(original['events']))

    def test_existing_destination_is_untouched(self):
        self.output.mkdir()
        marker = self.output / 'existing.txt'
        marker.write_text('owned by operator', encoding='utf-8')
        with self.assertRaises(BenchmarkError) as error:
            self.export()
        self.assertEqual(error.exception.code, 'destination_exists')
        self.assertEqual(marker.read_text(encoding='utf-8'), 'owned by operator')
        self.assertEqual(self.store.snapshot_count, 0)

    def test_existing_file_is_untouched(self):
        self.output.write_bytes(b'owned by operator')
        with self.assertRaises(BenchmarkError):
            self.export()
        self.assertEqual(self.output.read_bytes(), b'owned by operator')

    def test_artifact_corruption_aborts_export(self):
        ref = next(iter(self.store.data['trials'][0]['public_artifacts'].values()))
        path = self.store.root / 'trials' / self.store.trial_id / ref['path']
        path.write_bytes(b'corrupted immutable artifact')
        with self.assertRaises(BenchmarkError) as error:
            self.export()
        self.assertEqual(error.exception.code, 'artifact_corrupt')
        self.assertFalse(self.output.exists())

    def test_missing_artifact_aborts_export(self):
        ref = next(iter(self.store.data['trials'][0]['public_artifacts'].values()))
        (self.store.root / 'trials' / self.store.trial_id / ref['path']).unlink()
        with self.assertRaises(BenchmarkError):
            self.export()
        self.assertFalse(self.output.exists())

    def test_missing_public_mapping_aborts_export(self):
        self.store.data['trials'][0]['public_artifacts'] = {}
        with self.assertRaises(BenchmarkError):
            self.export()
        self.assertFalse(self.output.exists())

    def test_partial_write_failure_removes_only_owned_directory(self):
        marker = self.root / 'operator-file'
        marker.write_bytes(b'keep')
        with patch('benchmark_reporting._write_coverage', side_effect=OSError('sensitive OS details')):
            with self.assertRaises(BenchmarkError) as error:
                self.export()
        self.assertEqual(str(error.exception), 'export_failed: snapshot')
        self.assertFalse(self.output.exists())
        self.assertEqual(marker.read_bytes(), b'keep')

    def test_tags_never_infer_verification(self):
        report = self.export()
        coverage = report['coverage']
        self.assertEqual(coverage['registered_summary']['numerator'], 0)
        self.assertGreater(coverage['registered_summary']['denominator'], 0)
        self.assertTrue(all(row['numerator'] == 0 for row in coverage['marginal']))
        with (self.output / 'coverage.csv').open(encoding='utf-8', newline='') as stream:
            rows = list(csv.DictReader(stream))
        self.assertEqual({row['scope'] for row in rows}, {'marginal', 'registered_combination'})
        self.assertTrue(all(row['denominator'] == '1' for row in rows))

    def test_unselected_evidence_cannot_receive_snapshot_coverage_credit(self):
        row = self.verified_row()
        row['evidence_references'] = ['fixtures/unselected/public/evidence.json']
        result = self.export()['coverage']
        self.assertEqual(result['registered_summary']['numerator'], 0)
        actual = next(item for item in result['registered_combinations'] if item['row_id'] == row['row_id'])
        self.assertIn('evidence_not_in_snapshot', actual['verification_blockers'])
        self.assertEqual(actual['verified_evidence'], [])

    def test_authored_paths_resolve_to_immutable_public_evidence(self):
        row = self.verified_row()
        manifest_path = row['evidence_references'][0]
        row['evidence_references'].append(manifest_path.rsplit('/', 1)[0] + '/records.jsonl')
        result = self.export()['coverage']
        self.assertEqual(result['registered_summary']['numerator'], 1)
        actual = next(item for item in result['registered_combinations'] if item['row_id'] == row['row_id'])
        case = self.store.data['experiment']['cases'][0]
        self.assertEqual(actual['verified_evidence'], [
            {'path': manifest_path, 'sha256': case['scenario']['evidence_manifest_sha256']},
            {'path': row['evidence_references'][1], 'sha256': case['evidence']['files'][0]['sha256']}])
        self.assertEqual(actual['verification_blockers'], [])

    def test_arbitrary_artifact_is_not_public_coverage_evidence(self):
        row = self.verified_row()
        ref = self.store.add_artifact(b'An assertion of coverage is not sensor evidence.')
        self.store.data['trials'][0]['coverage_artifact'] = ref
        row['evidence_references'] = [ref['path']]
        self.assertEqual(self.export()['coverage']['registered_summary']['numerator'], 0)

    def test_synthetic_evidence_cannot_credit_live_coverage(self):
        row = self.verified_row()
        row['status'] = 'live_verified'
        result = self.export()['coverage']
        actual = next(item for item in result['registered_combinations'] if item['row_id'] == row['row_id'])
        self.assertEqual(actual['numerator'], 0)
        self.assertIn('evidence_provenance_mismatch', actual['verification_blockers'])

    def test_scenario_tag_cannot_invent_an_observed_os(self):
        row = self.verified_row()
        row['coverage']['os'].append('windows-server')
        self.store.data['experiment']['cases'][0]['scenario']['coverage']['os'].append('windows-server')
        result = self.export()['coverage']
        actual = next(item for item in result['registered_combinations'] if item['row_id'] == row['row_id'])
        self.assertEqual(actual['numerator'], 0)
        self.assertIn('coverage_not_evidenced.os', actual['verification_blockers'])

    def test_explicit_verified_cloud_row_does_not_credit_windows(self):
        frozen = self.store.data['experiment']
        case, trial = frozen['cases'][0], self.store.data['trials'][0]
        evidence = case['evidence']
        for asset in evidence['assets']:
            asset.update(os_family='not-applicable', os_version='Managed control plane',
                         architecture='not-applicable', vendor='Invented cloud')
        for event in evidence['events']:
            event.update(event_type='cloud_api', fields={
                'event_name': 'DescribeInstances', 'result': 'success',
                'timestamp_original': event['timestamp_utc']})
        records = b''.join(canonical_bytes({key: value for key, value in event.items() if key != 'locator'}) + b'\n'
                           for event in evidence['events'])
        reference = self.store.add_artifact(records)
        evidence['files'] = [dict(reference, path='records.jsonl')]
        case['public_files'] = evidence['files']
        trial['public_artifacts'] = {'records.jsonl': reference}
        for event in evidence['events']:
            event['locator']['file_sha256'] = reference['sha256']
        for source in evidence['sources']:
            source.update(telemetry='cloud-audit', source_sha256=reference['sha256'])
        case['scenario']['coverage'].update(
            os=['not-applicable'], execution_platform=['cloud-control-plane'], network=['cloud-vpc'],
            identity_domain=['cloud-iam'], operational_domain=['cloud-saas'], dns_domain=['no-dns'],
            telemetry=['cloud-audit'])
        case['scenario']['evidence_manifest_sha256'] = digest_bytes(canonical_bytes(evidence))
        trial['case_evidence_sha256'] = case['scenario']['evidence_manifest_sha256']
        self.verified_row()
        result = self.export()['coverage']
        self.assertEqual(result['registered_summary']['numerator'], 1)
        os_rows = {item['category']: item for item in result['marginal'] if item['axis'] == 'os'}
        self.assertEqual(os_rows['not-applicable']['numerator'], 1)
        self.assertEqual(os_rows['windows-client']['numerator'], 0)
        self.assertEqual(os_rows['linux']['numerator'], 0)
        self.assertEqual(os_rows['not-applicable']['verified_rows']['live_verified'], 0)

    def test_recorded_score_is_exported_without_fabricated_ranking(self):
        event = dict(self.store.data['events'][0], seq=self.store.data['events'][-1]['seq'] + 1, event_id='score-event',
                     kind='score_recorded', trial_id=self.store.trial_id,
                     payload={'score': {'status': 'provisional', 'tp': 1, 'fp': 1, 'fn': 1}})
        self.store.data['events'].append(event)
        report = self.export()
        self.assertIsNone(report['scoring']['ranking'])
        self.assertEqual(json.loads((self.output / 'scores.jsonl').read_bytes()), event)

    def test_dangling_event_reference_and_bad_sequence_fail(self):
        for change in ({'trial_id': 'missing-trial'}, {'seq': 0}):
            with self.subTest(change=change):
                original = copy.deepcopy(self.store.data)
                self.store.data['events'][0].update(change)
                with self.assertRaises(BenchmarkError):
                    self.export()
                self.assertFalse(self.output.exists())
                self.store.data = original

    def test_failure_usage_and_cost_remain_explicit(self):
        model = self.store.data['experiment']['experiment']['teams'][0]['roles']['framework-coordinator']
        tokens = {key: None for key in ('input_tokens', 'output_tokens', 'cached_input_tokens', 'reasoning_tokens')}
        spec = {'schema_version': 1, 'trial_id': self.store.trial_id, 'stage_key': 'scope',
                'attempt_index': 1, 'component': 'narrative', 'role': 'framework-coordinator',
                'model': model}
        receipt = {'schema_version': 1, 'call_id': 'call-test-only', 'fingerprint': 'a' * 64,
                   'status': 'failed', 'model_requested': model['model_requested'], 'model_returned': None,
                   'identity_status': 'unreported', 'provider': 'openai', 'deployment': 'local',
                   'role': 'framework-coordinator', 'stage_key': 'scope', 'prompt_sha256': 'b' * 64,
                   'response_sha256': None, 'start_utc': NOW, 'end_utc': NOW, 'elapsed_ms': 25,
                   'timeout_seconds': 30, 'max_calls': 1, 'max_output_bytes': 1024,
                   'finish_reason': None, 'usage': tokens, 'estimated_usage': tokens,
                   'cost': {'api_cost_usd': None, 'pricing_snapshot_sha256': 'c' * 64,
                            'cost_basis': 'unknown', 'local_compute_cost_usd': None,
                            'local_energy_cost_usd': None},
                   'failure_reason': 'timeout', 'response_artifact': None}
        self.store.data['calls'] = [{'call_id': 'call-test-only', 'fingerprint': 'a' * 64,
                                     'spec': spec, 'status': 'failed', 'receipt': receipt,
                                     'created_utc': NOW, 'updated_utc': NOW}]
        report = self.export()
        team = report['teams'][0]
        measured = team['measurements']
        self.assertEqual(measured['model_active_ms']['total'], 25)
        self.assertEqual(measured['failure_reasons'], {'timeout': 1})
        self.assertEqual(measured['identity']['unreported'], 1)
        self.assertIsNone(measured['cost']['api_cost_usd']['total'])
        self.assertEqual(measured['cost']['api_cost_usd']['unknown_count'], 1)
        self.assertIsNone(measured['provider_reported_usage']['input_tokens']['total'])
        self.assertEqual(team['stages']['scope']['statuses'], {'failed': 1})

    def test_end_to_end_runs_to_final_handoff_auto_advance(self):
        trial = self.store.data['trials'][0]
        snapshot = {'events': [], 'approvals': [], 'calls': [
            {'spec': {'trial_id': trial['trial_id']},
             'receipt': {'start_utc': NOW}, 'status': 'completed'}]}

        def advanced(stage, second):
            return {'kind': 'stage_auto_advanced', 'trial_id': trial['trial_id'],
                    'time_utc': '2026-01-01T00:00:{:02d}+00:00'.format(second),
                    'payload': {'stage_key': stage, 'review_policy': 'auto_advance'}}
        snapshot['events'] = [advanced('scope', 4)]
        partial = _trial_timing(snapshot, trial, False)
        self.assertIsNone(partial['end_to_end_ms'])
        self.assertEqual(partial['limitations'], ['no_completed_workflow_interval'])
        snapshot['events'].append(advanced('handoff', 10))
        measured = _trial_timing(snapshot, trial, True)
        self.assertEqual(measured['end_to_end_ms'], 10000)
        self.assertEqual(measured['auto_advanced_stages'], 2)
        self.assertEqual((measured['review_policy'], measured['timing_contended']), ('auto_advance', True))
        self.assertIn('timing_contended_concurrent_calls', measured['limitations'])
        self.assertNotIn('human_wait_ms', measured)

    def test_completed_receipt_cannot_omit_response_artifact(self):
        self.store.data['calls'] = [{'call_id': 'incomplete-call', 'fingerprint': 'a' * 64,
                                     'spec': {'trial_id': self.store.trial_id, 'stage_key': 'scope'},
                                     'status': 'completed', 'receipt': {'response_artifact': None},
                                     'created_utc': NOW, 'updated_utc': NOW}]
        with self.assertRaises(BenchmarkError) as error:
            self.export()
        self.assertEqual(error.exception.field, 'response_artifact')
        self.assertFalse(self.output.exists())

    def test_campaign_states_and_dispatches_are_separate_export_records(self):
        manifest = {'schema_version': 1, 'campaign_id': 'campaign-fixture',
                    'recipe_id': 'windows-discovery-v1', 'targets': [], 'authorization': {}}
        state = {'schema_version': 1, 'campaign_id': 'campaign-fixture',
                 'experiment_id': self.store.experiment_id, 'manifest': manifest,
                 'manifest_sha256': digest_bytes(canonical_bytes(manifest)),
                 'status': 'draft', 'cleanup_status': 'not_needed', 'owned_process': None,
                 'created_utc': NOW, 'updated_utc': NOW}
        dispatch = {'campaign_id': 'campaign-fixture', 'phase': 'preflight', 'step_id': 'identity',
                    'fingerprint': 'a' * 64, 'spec': {'experiment_id': self.store.experiment_id},
                    'status': 'reserved', 'receipt': None, 'created_utc': NOW, 'updated_utc': NOW}
        self.store.data['campaign_states'] = [state]
        self.store.data['campaigns'] = [dispatch]
        report = self.export()
        self.assertEqual(report['campaign_states'], [state])
        self.assertEqual(report['campaign_dispatches'], [dispatch])
        records = [json.loads(line) for line in (self.output / 'campaigns.jsonl').read_text().splitlines()]
        self.assertEqual(records, [dict(state, record_kind='manifest'),
                                   dict(dispatch, record_kind='dispatch_receipt')])

    def test_campaign_dispatch_without_authoritative_state_aborts(self):
        self.store.data['campaigns'] = [{'campaign_id': 'missing-campaign'}]
        with self.assertRaises(BenchmarkError) as error:
            self.export()
        self.assertEqual(error.exception.field, 'campaigns')
        self.assertFalse(self.output.exists())

    def test_missing_campaign_state_collection_aborts(self):
        del self.store.data['campaign_states']
        with self.assertRaises(BenchmarkError) as error:
            self.export()
        self.assertEqual(error.exception.field, 'snapshot')
        self.assertFalse(self.output.exists())

    def test_real_store_incomplete_schedule_aborts_export(self):
        frozen, _ = frozen_fixture()
        store = BenchmarkStore(self.root / 'real-state', create=True)
        store.create_experiment(frozen)
        with self.assertRaises(BenchmarkError) as error:
            export_snapshot(store, self.store.experiment_id, self.output)
        self.assertEqual(error.exception.code, 'incomplete_snapshot')
        self.assertFalse(self.output.exists())

    def test_scored_holdout_cohorts_stay_exposed_until_retired(self):
        frozen = {'cases': [{'scenario': {'scenario_id': 'scenario-h', 'family_id': 'family-h',
                                          'revision': 1, 'split': 'holdout'}},
                            {'scenario': {'scenario_id': 'scenario-d', 'family_id': 'family-d',
                                          'revision': 1, 'split': 'development'}}]}

        def scoring(scored):
            return {'scorecards': [
                {'scorecard_id': 'holdout-card', 'controls': {'split': 'holdout'},
                 'scenario_ids': ['scenario-h'], 'scored_trials': scored},
                {'scorecard_id': 'development-card', 'controls': {'split': 'development'},
                 'scenario_ids': ['scenario-d'], 'scored_trials': scored}]}

        unscored = scoring(0)
        self.assertEqual(_holdout(frozen, unscored, None)['status'], 'holdout_unexposed')
        exposed = scoring(1)
        summary = _holdout(frozen, exposed, None)
        self.assertEqual(summary['status'], 'holdout_exposed')
        self.assertEqual(summary['exposed_cohorts'], ['holdout-card'])
        self.assertEqual([card['holdout_status'] for card in exposed['scorecards']], ['holdout_exposed', None])
        registry = {'schema_version': 1, 'retired': [{
            'family_id': 'family-h', 'revision': 1, 'reason': 'retired_by_experiment',
            'retired_by_experiment': 'exp-1', 'scenario_ids': ['scenario-h'], 'by': 'human',
            'note': 'note', 'retired_utc': '2026-01-01T00:00:00Z'}]}
        retired = scoring(1)
        self.assertEqual(_holdout(frozen, retired, registry)['status'], 'retired')
        self.assertEqual(retired['scorecards'][0]['holdout_status'], 'retired')

    def test_trial_without_dispatch_has_no_invented_interval(self):
        snapshot = {'events': [], 'approvals': [], 'calls': []}
        timing = _trial_timing(snapshot, {'trial_id': 'trial-t', 'status': 'terminated'}, False)
        self.assertIsNone(timing['end_to_end_ms'])
        self.assertEqual(timing['auto_advanced_stages'], 0)


if __name__ == '__main__':
    unittest.main()

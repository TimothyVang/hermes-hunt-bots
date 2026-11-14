"""Offline unit tests for Wave 2 SQLite Query-Tool Track (`benchmark_query`)."""
from pathlib import Path
import sqlite3
import tempfile
import unittest

import benchmark_paths  # noqa: F401
from benchmark_contracts import (
    ASSESSMENT_QUESTION, bundle_event_ids, canonical_bytes, digest_bytes,
    load_json, stage_output_schema, validate_public_bundle, validate_scenario,
    validate_stage_output, validate_truth,
)
from benchmark_ioc import PUBLIC_CTI_SEED_CATALOG, attach_ioc_feed
from benchmark_query import (
    QueryExecutor, build_query_store, open_readonly_db, verify_query_store,
)
from benchmark_scoring import MECHANICAL, score_output

HERE = Path(__file__).resolve().parent
FIXTURES = HERE / 'benchmarks'


class BenchmarkQueryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def _sample_events(self, count=300):
        events = []
        file_sha = 'a' * 64
        for idx in range(1, count + 1):
            sec = idx % 60
            minute = (idx // 60) % 60
            asset = 'dc01' if idx == 250 else ('ws01' if idx % 2 == 0 else 'ws02')
            etype = 'sysmon_1' if idx in (10, 250) else 'sysmon_3'
            cmd = 'wmic /node:dc01 process call create "cmd.exe /c whoami"' if idx == 250 else f'benign-{idx}'
            events.append({
                'event_id': f'e{idx:06d}',
                'timestamp_utc': f'2026-02-01T00:{minute:02d}:{sec:02d}Z',
                'source_id': 'sysmon',
                'asset_id': asset,
                'event_type': etype,
                'fields': {
                    'timestamp_original': f'2026-02-01T00:{minute:02d}:{sec:02d}Z',
                    'CommandLine': cmd,
                    'Hashes': 'SHA256=' + ('b' * 64 if idx == 10 else 'c' * 64),
                },
                'locator': {'file_sha256': file_sha, 'record_id': idx},
            })
        return events

    def test_build_verify_readonly_authorizer_and_all_six_tools(self):
        db_path = self.root / 'events.sqlite3'
        events = self._sample_events(300)
        spec = build_query_store(db_path, events, PUBLIC_CTI_SEED_CATALOG[:4], prefix='e', width=6)
        self.assertEqual(spec['event_count'], 300)
        self.assertEqual(spec['ioc_count'], 4)
        verify_query_store(db_path, spec)

        # Read-only authorizer blocks writes even if attempted directly on the connection
        ro = open_readonly_db(db_path, spec['sha256'])
        try:
            with self.assertRaises(sqlite3.DatabaseError):
                ro.execute("DELETE FROM events WHERE seq = 1")
            with self.assertRaises(sqlite3.DatabaseError):
                ro.execute("ATTACH DATABASE ':memory:' AS extra")
        finally:
            ro.close()

        with QueryExecutor(db_path, spec['sha256'], max_calls=7, max_rows=10) as qexec:
            ov = qexec.overview()
            self.assertEqual(sum(r['event_count'] for r in ov['by_asset']), 300)

            r1 = qexec.execute('count_events', {'group_by': 'asset_id'})
            self.assertTrue(r1['ok'])
            self.assertEqual(sum(x['count'] for x in r1['rows']), 300)

            # Exact limit cap (never limit + 1) and explicit null window/limit handling
            r_cap = qexec.execute('search_events', {'source_id': 'sysmon', 'limit': 5})
            self.assertTrue(r_cap['ok'])
            self.assertEqual(len(r_cap['rows']), 5)
            self.assertTrue(r_cap['truncated'])

            r2 = qexec.execute('search_events', {'text_query': 'wmic dc01', 'limit': None})
            self.assertTrue(r2['ok'])
            self.assertEqual([x['event_id'] for x in r2['rows']], ['e000250'])

            r3 = qexec.execute('get_events', {'event_ids': ['e000010', 'e000250']})
            self.assertTrue(r3['ok'])
            self.assertEqual([x['event_id'] for x in r3['rows']], ['e000010', 'e000250'])

            r4 = qexec.execute('asset_timeline', {'asset_id': 'dc01', 'around_utc': '2026-02-01T00:04:10Z', 'window_seconds': 30})
            self.assertTrue(r4['ok'])
            self.assertEqual([x['event_id'] for x in r4['rows']], ['e000250'])

            r5 = qexec.execute('pivot_indicator', {'value': 'b' * 64})
            self.assertTrue(r5['ok'])
            self.assertEqual([x['event_id'] for x in r5['rows']], ['e000010'])

            # Invalid tool call is audited and consumes budget cleanly
            r_bad = qexec.execute('drop_table', {})
            self.assertFalse(r_bad['ok'])
            self.assertEqual(r_bad['error'], 'invalid_tool_or_args')

            # 8th call hits max_calls=7 budget cap cleanly without raising
            r6 = qexec.execute('lookup_ioc', {'query': 'cobalt'})
            self.assertFalse(r6['ok'])
            self.assertEqual(r6['error'], 'query_budget_exhausted')
            self.assertEqual(qexec.summary()['queries_executed'], 7)
            self.assertEqual(len(qexec.summary()['calls']), 7)

    def test_query_track_case_bundle_scoring_and_ioc_resealing(self):
        case_dir = self.root / 'case-99887766'
        pub = case_dir / 'public'
        ev_dir = case_dir / 'evaluator'
        pub.mkdir(parents=True)
        ev_dir.mkdir(parents=True)

        events = self._sample_events(300)
        qspec = build_query_store(pub / 'events.sqlite3', events, (), prefix='e', width=6)
        overview_bytes = canonical_bytes({'total_events': 300, 'assets': ['ws01', 'ws02', 'dc01']}) + b'\n'
        (pub / 'overview.json').write_bytes(overview_bytes)

        evidence = {
            'schema_version': 1,
            'case_id': 'case-99887766',
            'window_utc': {'start_inclusive': '2026-02-01T00:00:00Z', 'end_exclusive': '2026-02-01T01:00:00Z'},
            'assets': [
                {'asset_id': 'ws01', 'os_family': 'windows-client', 'os_version': '10', 'architecture': 'x86_64', 'vendor': 'microsoft'},
                {'asset_id': 'ws02', 'os_family': 'windows-client', 'os_version': '10', 'architecture': 'x86_64', 'vendor': 'microsoft'},
                {'asset_id': 'dc01', 'os_family': 'windows-server', 'os_version': '2019', 'architecture': 'x86_64', 'vendor': 'microsoft'},
            ],
            'sources': [{
                'source_id': 'sysmon',
                'asset_ids': ['ws01', 'ws02', 'dc01'],
                'telemetry': 'sysmon',
                'clock_offset_seconds': 0,
                'clock_uncertainty_seconds': 1,
                'window_utc': {'start_inclusive': '2026-02-01T00:00:00Z', 'end_exclusive': '2026-02-01T01:00:00Z'},
                'sensor_version': '15.0',
                'config_version': '1',
                'completeness': 'complete',
                'source_sha256': 'a' * 64,
            }],
            'events': [],
            'query_store': qspec,
            'known_gaps': [],
            'files': [{
                'path': 'overview.json',
                'byte_count': len(overview_bytes),
                'sha256': digest_bytes(overview_bytes),
            }],
            'assessment_questions': [{
                'question_id': 'q-dc01',
                'asset_id': 'dc01',
                'window_utc': {'start_inclusive': '2026-02-01T00:00:00Z', 'end_exclusive': '2026-02-01T01:00:00Z'},
                'question': ASSESSMENT_QUESTION,
            }],
            'unassessed_asset_ids': ['ws01', 'ws02'],
        }
        ev_bytes = canonical_bytes(evidence)
        ev_sha = digest_bytes(ev_bytes)
        scenario = load_json(FIXTURES / 'fixtures' / 'case-8b42' / 'scenario.json')
        scenario.update(
            scenario_id='scen-query-apt',
            evidence_manifest_sha256=ev_sha,
        )
        truth = {
            'schema_version': 1,
            'case_id': 'case-99887766',
            'truth_revision': 1,
            'evidence_manifest_sha256': ev_sha,
            'attack_release': scenario['attack_release'],
            'attestation': 'publisher_labels',
            'steps': [
                {
                    'step_id': 'step-initial',
                    'asset_id': 'ws01',
                    'technique_id': 'T1059.003',
                    'window_utc': {'start_inclusive': '2026-02-01T00:00:05Z', 'end_exclusive': '2026-02-01T00:00:20Z'},
                    'execution_outcome': 'succeeded',
                    'observability': 'sufficient',
                    'support_sets': [['e000010']],
                    'source_receipt_sha256': 'a' * 64,
                },
                {
                    'step_id': 'step-lateral',
                    'asset_id': 'dc01',
                    'technique_id': 'T1047',
                    'window_utc': {'start_inclusive': '2026-02-01T00:04:00Z', 'end_exclusive': '2026-02-01T00:04:30Z'},
                    'execution_outcome': 'succeeded',
                    'observability': 'sufficient',
                    'support_sets': [['e000250']],
                    'source_receipt_sha256': 'a' * 64,
                },
            ],
            'edges': [['step-initial', 'step-lateral']],
            'controls': [],
            'assessment_labels': {'q-dc01': 1},
        }
        (pub / 'evidence.json').write_bytes(ev_bytes + b'\n')
        (case_dir / 'scenario.json').write_bytes(canonical_bytes(scenario) + b'\n')
        (ev_dir / 'truth.json').write_bytes(canonical_bytes(truth) + b'\n')

        # Attach Novel-APT zero-IOC feed using full `events` and verify SQLite iocs table reseals cleanly
        manifest = attach_ioc_feed(case_dir, regime='novel_apt_zero_ioc', all_events=events)
        self.assertEqual(manifest['active_truth_matches'], 0)

        sealed_ev = validate_public_bundle(load_json(pub / 'evidence.json'), pub)
        sealed_truth = validate_truth(load_json(ev_dir / 'truth.json'), sealed_ev)
        validate_scenario(load_json(case_dir / 'scenario.json'), load_json(FIXTURES / 'coverage.json'))

        id_set = bundle_event_ids(sealed_ev)
        self.assertIn('e000001', id_set)
        self.assertIn('e000300', id_set)
        self.assertNotIn('e000301', id_set)
        self.assertNotIn('e000000', id_set)

        schema = stage_output_schema('handoff', sealed_ev)
        self.assertEqual(schema['type'], 'object')

        handoff = {
            'schema_version': 1,
            'stage_key': 'handoff',
            'summary': 'Detected WMI lateral movement from ws01 to dc01.',
            'claims': [{'claim_id': 'c1', 'kind': 'observation', 'text': 'WMI remote exec on dc01.', 'event_ids': ['e000250']}],
            'findings': [
                {
                    'finding_id': 'f1',
                    'asset_id': 'ws01',
                    'technique_id': 'T1059.003',
                    'window_utc': {'start_inclusive': '2026-02-01T00:00:05Z', 'end_exclusive': '2026-02-01T00:00:20Z'},
                    'disposition': 'suspicious',
                    'confidence': 0.9,
                    'event_ids': ['e000010'],
                    'rationale': 'Initial shell execution.',
                },
                {
                    'finding_id': 'f2',
                    'asset_id': 'dc01',
                    'technique_id': 'T1047',
                    'window_utc': {'start_inclusive': '2026-02-01T00:04:00Z', 'end_exclusive': '2026-02-01T00:04:30Z'},
                    'disposition': 'suspicious',
                    'confidence': 0.95,
                    'event_ids': ['e000250'],
                    'rationale': 'WMI lateral execution.',
                },
            ],
            'hypotheses': ['WMI lateral movement'],
            'gaps': [],
            'limitations': [],
            'requested_decision': 'approve',
            'chain_edges': [['f1', 'f2']],
            'assessment_answers': [{'question_id': 'q-dc01', 'probability_suspicious': 0.95}],
        }
        validate_stage_output(handoff, 'handoff', sealed_ev)
        out_sha = digest_bytes(canonical_bytes(handoff))
        metrics = score_output(handoff, sealed_truth, sealed_ev, None,
                               trial_id='t1', output_sha256=out_sha, adjudication=MECHANICAL)
        self.assertEqual(metrics['detection']['f1'], 1.0)
        self.assertEqual(metrics['chain_edges']['f1'], 1.0)
        self.assertEqual(metrics['citations']['invalid_rate'], 0.0)

    def test_oversized_first_row_is_shrunk_within_max_bytes_and_huge_offset_is_safe(self):
        huge_events = [{
            'event_id': 'e000001',
            'timestamp_utc': '2026-02-01T00:00:01Z',
            'source_id': 'sysmon',
            'asset_id': 'ws01',
            'event_type': 'sysmon_1',
            'fields': {
                'timestamp_original': '2026-02-01T00:00:01Z',
                'CommandLine': 'powershell.exe -enc ' + ('A' * 6000),
            },
            'locator': {'file_sha256': 'a' * 64, 'record_id': 1},
        }]
        db_path = self.root / 'huge.sqlite3'
        spec = build_query_store(db_path, huge_events, (), prefix='e', width=6)
        with QueryExecutor(db_path, spec['sha256'], max_bytes=320) as qexec:
            r = qexec.execute('get_events', {'event_ids': ['e000001']})
            self.assertTrue(r['ok'])
            self.assertTrue(r['truncated'])
            self.assertEqual(r['row_count'], 1)
            self.assertLessEqual(len(canonical_bytes(r['rows'][0])), 320)
            self.assertLessEqual(qexec.summary()['bytes_returned_total'], 320)

            r_off = qexec.execute('search_events', {'offset': 10 ** 30})
            self.assertTrue(r_off['ok'])
            self.assertEqual(r_off['row_count'], 0)


if __name__ == '__main__':
    unittest.main()

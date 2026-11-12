"""Holdout retirement registry regressions on invented identifiers only."""
from pathlib import Path
import tempfile
import unittest

from benchmark_contracts import BenchmarkError, canonical_bytes, decode_json
from benchmark_holdout import check_unretired, load_registry, retire


def scenario(scenario_id, family_id, split, revision=1):
    return {'scenario_id': scenario_id, 'family_id': family_id, 'split': split, 'revision': revision}


def snapshot():
    cases = [{'scenario': scenario('scenario-h1', 'family-a', 'holdout')},
             {'scenario': scenario('scenario-h2', 'family-a', 'holdout')},
             {'scenario': scenario('scenario-d1', 'family-b', 'development')}]
    return {'experiment': {'experiment': {'experiment_id': 'exp-holdout', 'teams': []}, 'cases': cases}}


class HoldoutRegistryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.registry = self.root / 'registry.json'
        self.registry.write_bytes(canonical_bytes({'schema_version': 1, 'retired': []}))

    def assert_code(self, code, fn, *args):
        with self.assertRaises(BenchmarkError) as raised:
            fn(*args)
        self.assertEqual(raised.exception.code, code)

    def retire(self, output='retired.json', registry=None, value=None, by='human-reviewer'):
        return retire(registry or self.registry, value or snapshot(), by, 'Scored holdout exposed.',
                      self.root / output)

    def test_retirement_writes_new_registry_and_refuses_reuse(self):
        empty = load_registry(self.registry)
        check_unretired(empty, [case['scenario'] for case in snapshot()['experiment']['cases']])
        before = self.registry.read_bytes()
        result = self.retire()
        self.assertEqual(result['retired'], [{'family_id': 'family-a', 'revision': 1}])
        self.assertEqual(self.registry.read_bytes(), before)
        document = decode_json((self.root / 'retired.json').read_bytes())
        entry = document['retired'][0]
        self.assertEqual(entry['reason'], 'retired_by_experiment')
        self.assertEqual(entry['retired_by_experiment'], 'exp-holdout')
        self.assertEqual(entry['scenario_ids'], ['scenario-h1', 'scenario-h2'])
        registry = load_registry(self.root / 'retired.json')
        self.assert_code('holdout_retired', check_unretired, registry,
                         [scenario('scenario-x', 'family-a', 'holdout')])
        # A development use or a new curated revision is not the exposed holdout.
        check_unretired(registry, [scenario('scenario-x', 'family-a', 'development'),
                                   scenario('scenario-y', 'family-a', 'holdout', revision=2)])
        self.assert_code('already_retired', self.retire, 'again.json', self.root / 'retired.json')

    def test_outputs_are_new_files_only(self):
        (self.root / 'taken.json').write_bytes(b'{}')
        self.assert_code('already_exists', self.retire, 'taken.json')
        self.assert_code('already_exists', self.retire, 'registry.json')
        self.assertEqual(decode_json(self.registry.read_bytes())['retired'], [])

    def test_no_holdout_and_model_identity_are_refused(self):
        value = snapshot()
        value['experiment']['cases'] = value['experiment']['cases'][2:]
        self.assert_code('no_holdout_scenarios', self.retire, 'out.json', None, value)
        self.assert_code('human_adjudication_required', self.retire, 'out2.json', None, None, 'framework-reviewer')

    def test_registry_is_strict(self):
        entry = {'family_id': 'family-a', 'revision': 1, 'reason': 'retired_by_experiment',
                 'retired_by_experiment': 'exp-1', 'scenario_ids': ['scenario-h1'], 'by': 'human',
                 'note': 'note', 'retired_utc': '2026-01-01T00:00:00Z'}
        for document in ({'schema_version': 1, 'retired': [entry, entry]},
                         {'schema_version': 1, 'retired': [dict(entry, reason='other')]},
                         {'schema_version': 1, 'retired': [dict(entry, extra=True)]},
                         {'schema_version': 1}):
            path = self.root / 'bad.json'
            path.write_bytes(canonical_bytes(document))
            with self.assertRaises(BenchmarkError):
                load_registry(path)
            path.unlink()


if __name__ == '__main__':
    unittest.main()

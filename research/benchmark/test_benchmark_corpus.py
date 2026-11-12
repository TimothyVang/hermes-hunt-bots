"""Corpus manifest builder over the INVENTED OTRF sample imported into a temp directory; offline only."""
import contextlib
import io
from pathlib import Path
import shutil
import tempfile
import unittest

import benchmark
import benchmark_import_otrf as otrf
from benchmark_contracts import canonical_bytes, decode_json, digest_bytes, load_json
from benchmark_corpus import DEFAULT_BUDGETS, build_corpus_experiment
from test_benchmark_import_otrf import (CURATION, DATASET, METADATA, NX_CURATION, NX_DATASET, NX_METADATA,
                                        SALT)

HERE = Path(__file__).resolve().parent


def _quiet(function, argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = function([str(item) for item in argv])
    return code, out.getvalue(), err.getvalue()


class CorpusExperimentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = tempfile.TemporaryDirectory()
        root = Path(cls.source.name)
        salt = root / 'salt.json'
        salt.write_bytes(canonical_bytes({'schema_version': 1, 'salt_hex': SALT.hex()}))
        for name, dataset, metadata, curation in (('flat', DATASET, METADATA, CURATION),
                                                  ('nx', NX_DATASET, NX_METADATA, NX_CURATION),
                                                  ('draft', DATASET, METADATA, None)):
            # The draft gets a fresh random salt, so its case ID differs from the curated flat case.
            mode = ['--curation', curation, '--salt-file', salt] if curation else ['--draft-os-family', 'windows-client']
            code, _, err = _quiet(otrf.main, ['--dataset', dataset, '--metadata', metadata, *mode,
                                              '--output', root / name])
            assert code == 0, err
        cls.imports = root

    @classmethod
    def tearDownClass(cls):
        cls.source.cleanup()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.cases = self.root / 'cases'
        self.cases.mkdir()
        for name in ('flat', 'nx'):
            for case in (self.imports / name).iterdir():
                shutil.copytree(str(case), str(self.cases / case.name))
        self.team = load_json(HERE / 'benchmarks' / 'examples' / 'experiment.json')['teams'][0]
        self.output = self.cases / 'experiment.json'

    def team_file(self, **extra):
        path = self.root / 'team.json'
        path.write_bytes(canonical_bytes(dict({'schema_version': 1, 'team': self.team}, **extra)))
        return path

    def cli(self, *extra, team=None):
        return _quiet(benchmark.main, ['corpus-experiment', '--cases', self.cases, '--team', team or self.team_file(),
                                       '--experiment-id', 'corpus-dev-1', '--repetitions', 3,
                                       '--output', self.output, *extra])

    def test_manifest_validates_with_relative_refs_and_current_digests(self):
        code, stdout, stderr = self.cli()
        self.assertEqual((code, stderr), (0, ''))
        report = decode_json(stdout)
        data = self.output.read_bytes()
        self.assertEqual(report['experiment_sha256'], digest_bytes(data))
        experiment = decode_json(data)
        cases = sorted(path.name for path in self.cases.iterdir() if path.is_dir())
        self.assertEqual(len(cases), 2)
        self.assertEqual(experiment['scenario_refs'],
                         [{'scenario': c + '/scenario.json', 'evidence': c + '/public/evidence.json'} for c in cases])
        self.assertEqual((experiment['repetitions'], experiment['schedule_seed'], experiment['teams']),
                         (3, 1729, [self.team]))
        self.assertEqual(experiment['budgets'], DEFAULT_BUDGETS)
        self.assertEqual(report['budgets_source'], 'defaults')
        loaded = benchmark.load_experiment(self.output, self.cases)
        self.assertEqual({case['scenario']['split'] for case in loaded['cases']}, {'development'})
        self.assertEqual(sorted(p.name for p in self.cases.iterdir() if p.is_file()), ['experiment.json'])
        code, _, stderr = _quiet(benchmark.main, ['validate', '--experiment', self.output, '--bundle-root', self.cases])
        self.assertEqual((code, stderr), (0, ''))

    def test_default_single_repetition_inits_with_the_cases_as_truth(self):
        code, _, stderr = _quiet(benchmark.main, ['corpus-experiment', '--cases', self.cases, '--team',
                                                  self.team_file(), '--experiment-id', 'corpus-dev-1',
                                                  '--output', self.output])
        self.assertEqual((code, stderr), (0, ''))
        self.assertEqual(decode_json(self.output.read_bytes())['repetitions'], 1)
        state = self.root / 'state'
        code, stdout, stderr = _quiet(benchmark.main, ['--state-root', state, 'init', '--experiment', self.output,
                                                       '--bundle-root', self.cases, '--truth', self.cases])
        self.assertEqual((code, stderr), (0, ''))
        report = decode_json(stdout)
        self.assertTrue(report['truth_frozen'])
        self.assertEqual(len(report['trials']), 2)

    def test_team_file_budgets_seed_and_existing_output(self):
        budgets = dict(DEFAULT_BUDGETS, max_prompt_bytes=524288)
        code, _, stderr = self.cli('--seed', 7, team=self.team_file(budgets=budgets))
        self.assertEqual((code, stderr), (0, ''))
        experiment = load_json(self.output)
        self.assertEqual((experiment['budgets'], experiment['schedule_seed']), (budgets, 7))
        before = self.output.read_bytes()
        self.assertEqual(self.cli()[::2], (2, 'already_exists: output\n'))
        self.assertEqual(self.output.read_bytes(), before)

    def test_drafts_holdouts_and_bad_team_files_are_refused(self):
        draft = next((self.imports / 'draft').iterdir())
        shutil.copytree(str(draft), str(self.cases / draft.name))
        self.assertEqual(self.cli()[::2], (2, 'draft_truth_refused: cases\n'))
        shutil.rmtree(str(self.cases / draft.name))
        scenario_path = next(self.cases.glob('case-*/scenario.json'))
        scenario = load_json(scenario_path)
        scenario['split'] = 'holdout'
        scenario_path.write_bytes(canonical_bytes(scenario))
        self.assertEqual(self.cli()[::2], (2, 'holdout_registry_required: holdout_registry\n'))
        self.assertFalse(self.output.exists())
        registry = self.root / 'registry.json'
        registry.write_bytes(canonical_bytes({'schema_version': 1, 'retired': []}))
        self.assertEqual(self.cli('--holdout-registry', registry)[0], 0)
        self.output.unlink()
        self.assertEqual(self.cli(team=self.team_file(teams=[self.team]))[::2],
                         (2, 'unknown_field: team_file\n'))
        self.assertFalse(self.output.exists())


if __name__ == '__main__':
    unittest.main()

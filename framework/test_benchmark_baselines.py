"""Reference baselines on the INVENTED graduated fixtures, and corpus prompt-size refusals; offline only."""
import collections.abc
import contextlib
import copy
import io
import json
import math
from pathlib import Path
import shutil
import tempfile
import unittest

import benchmark
from benchmark import load_experiment
from benchmark_adjudication import load_truths
from benchmark_baselines import (BASELINES, REFERENCE_BASELINE, baseline_output, leave_one_out_prior,
                                 score_baselines)
from benchmark_comparison import _card_reasons, _rank, _summary
from benchmark_contracts import canonical_bytes, decode_json, load_json, validate_stage_output
from benchmark_corpus import DEFAULT_BUDGETS, estimated_tokens, public_prompt_bytes

HERE = Path(__file__).resolve().parent
BUNDLE = HERE / 'benchmarks'
MANIFEST = BUNDLE / 'examples' / 'experiment-graduated.json'
TRUTH = BUNDLE / 'fixtures'
POSITIVE, CONTROL = 'case-8b42', 'case-b060'


def _quiet(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = benchmark.main([str(item) for item in argv])
    return code, out.getvalue(), err.getvalue()


class TrapLabels(collections.abc.Mapping):
    """Assessment labels that fail the test if anything reads them."""

    def __getitem__(self, key):
        raise AssertionError('own labels read')

    def __iter__(self):
        raise AssertionError('own labels read')

    def __len__(self):
        raise AssertionError('own labels read')


class BaselineScoringTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.loaded = load_experiment(MANIFEST, BUNDLE)
        cls.truths = load_truths(TRUTH, cls.loaded)
        cls.report = score_baselines(cls.loaded, cls.truths)
        cls.by_id = {item['baseline_id']: item for item in cls.report['baselines']}

    def case(self, baseline, case_id):
        return next(item for item in self.by_id[baseline]['cases'] if item['case_id'] == case_id)

    def labels(self, case_id):
        return self.truths[case_id]['truth']['assessment_labels']

    def test_silent_misses_attacks_and_never_alarms(self):
        positive = self.case('silent', POSITIVE)['metrics']
        self.assertEqual((positive['detection']['tp'], positive['detection']['fp'], positive['detection']['fn']),
                         (0, 0, 1))
        self.assertEqual(positive['detection']['recall'], 0.0)
        self.assertEqual(positive['detection']['f1'], 0.0)
        self.assertIsNone(positive['detection']['precision'])
        self.assertEqual(positive['calibration']['brier'], 0.5)  # one positive of two questions, answered 0.0
        control = self.case('silent', CONTROL)['metrics']
        self.assertEqual(control['controls']['benign']['false_alarm_rate'], 0.0)
        self.assertEqual(control['calibration']['brier'], 0.0)
        self.assertEqual(self.by_id['silent']['macro']['detection']['benign_control_false_alarms'], 0)

    def test_alarm_all_flags_every_question_without_credit(self):
        evidence = next(case['evidence'] for case in self.loaded['cases'] if case['evidence']['case_id'] == POSITIVE)
        positive = self.case('alarm_all', POSITIVE)['metrics']['detection']
        self.assertEqual((positive['tp'], positive['fp'], positive['fn']),
                         (0, len(evidence['assessment_questions']), 1))
        self.assertEqual((positive['precision'], positive['recall'], positive['f1']), (0.0, 0.0, 0.0))
        control = self.case('alarm_all', CONTROL)['metrics']
        self.assertEqual(control['controls']['benign']['false_alarm_rate'], 1.0)
        self.assertEqual(control['calibration']['brier'], 1.0)
        self.assertIn('missing_model_citation', control['ranking_blockers'])

    def test_coin_is_a_quarter_everywhere(self):
        for item in self.by_id['coin']['cases']:
            self.assertEqual(item['scorecard']['brier'], 0.25)
            self.assertEqual(item['metrics']['detection']['tp'] + item['metrics']['detection']['fp'], 0)
        self.assertEqual(self.by_id['coin']['macro']['brier'], 0.25)

    def test_prior_uses_other_development_cases_only(self):
        cases = [case['evidence']['case_id'] for case in self.loaded['cases']]
        for case_id in cases:
            others = [label for other in cases if other != case_id
                      for label in self.labels(other).values() if label is not None]
            item = self.case('prior', case_id)
            self.assertEqual(item['prior_probability'], sum(others) / len(others))
            self.assertEqual(item['prior_basis']['other_development_cases'], len(cases) - 1)
            supplied = [(item['prior_probability'] - label) ** 2
                        for label in self.labels(case_id).values() if label is not None]
            self.assertTrue(math.isclose(item['metrics']['calibration']['brier'], sum(supplied) / len(supplied)))
        # Hand counts on the invented fixtures: 10 positives in 24 decidable labels overall.
        self.assertEqual(self.case('prior', POSITIVE)['prior_probability'], 9 / 22)
        self.assertEqual(self.case('prior', CONTROL)['prior_probability'], 10 / 22)

    def test_leave_one_out_never_reads_own_labels(self):
        development = {'case-aaaa': TrapLabels(), 'case-bbbb': {'q1': 1, 'q2': 0, 'q3': None},
                       'case-cccc': {'q4': 1}}
        probability, basis = leave_one_out_prior('case-aaaa', development)
        self.assertEqual(probability, 2 / 3)
        self.assertEqual(basis, {'other_development_cases': 2, 'decidable_labels': 3, 'positive_labels': 2})
        with self.assertRaises(AssertionError):
            leave_one_out_prior('case-bbbb', development)
        self.assertEqual(leave_one_out_prior('case-cccc', {'case-cccc': TrapLabels()}),
                         (None, {'other_development_cases': 0, 'decidable_labels': 0, 'positive_labels': 0,
                                 'null_reason': 'no_other_development_labels'}))

    def test_holdout_labels_never_enter_any_prior(self):
        loaded = copy.deepcopy(self.loaded)
        hidden = next(case for case in loaded['cases'] if case['evidence']['case_id'] == 'case-7d33')
        hidden['scenario']['split'] = 'holdout'
        report = score_baselines(loaded, self.truths)
        prior = {item['case_id']: item for item in report['baselines'][BASELINES.index('prior')]['cases']}
        development = [case['evidence']['case_id'] for case in loaded['cases']
                       if case['scenario']['split'] == 'development']
        for case_id, item in prior.items():
            others = [label for other in development if other != case_id
                      for label in self.labels(other).values() if label is not None]
            self.assertEqual(item['prior_probability'], sum(others) / len(others))
        self.assertEqual(prior['case-7d33']['prior_basis']['other_development_cases'], len(development))

    def test_metric_names_and_macro_match_real_scorecards(self):
        silent = self.by_id['silent']['macro']
        self.assertEqual(set(silent['detection']),
                         {'tp', 'fp', 'fn', 'visibility_limited_detections', 'benign_control_false_alarms',
                          'precision', 'recall', 'f1'})
        self.assertEqual(set(silent), set(_summary([])) | {'brier'})
        # Attack-free controls are excluded from detection macro means, as for teams.
        self.assertEqual(silent['metrics']['detection.recall']['excluded_attack_free_scenarios'], 3)
        self.assertEqual(silent['detection']['fn'], 15)
        expected = sum(self.case('silent', case['evidence']['case_id'])['metrics']['calibration']['brier']
                       for case in self.loaded['cases']) / len(self.loaded['cases'])
        self.assertTrue(math.isclose(silent['brier'], expected))
        for name in BASELINES:
            for item in self.by_id[name]['cases']:
                validate_stage_output(baseline_output(name, next(
                    case['evidence'] for case in self.loaded['cases']
                    if case['evidence']['case_id'] == item['case_id']), 0.5), 'handoff')
                self.assertEqual(item['status'], 'mechanical')
                self.assertEqual(item['metrics']['adjudication'], 'mechanical')

    def test_baseline_rows_are_labelled_and_never_rank(self):
        self.assertEqual((self.report['kind'], self.report['label'], self.report['rankable']),
                         (REFERENCE_BASELINE, REFERENCE_BASELINE, False))
        self.assertNotIn('"team_id"', canonical_bytes(self.report).decode('utf-8'))
        cards = []
        for name in BASELINES:
            baseline = self.by_id[name]
            self.assertEqual((baseline['kind'], baseline['rankable']), (REFERENCE_BASELINE, False))
            for item in baseline['cases']:
                self.assertFalse(item['metrics']['ranking_eligible'])
                self.assertIn(REFERENCE_BASELINE, item['metrics']['ranking_blockers'])
            # Even injected into the real scorecard/ranking code as if it were a
            # team with a verified identity, a baseline cohort is not comparable.
            rows = [{'settled': True, 'score': {'metrics': item['metrics']}, 'os_mismatch': False,
                     'fingerprint': {'evidence_sha256': item['evidence_sha256']}} for item in baseline['cases']]
            reasons = _card_reasons(rows, {'identity': 'reported_match'}, {'runtime_versions': {}})
            self.assertIn(REFERENCE_BASELINE, reasons)
            cards.append({'scorecard_id': name, 'team_id': name, 'variant': 'team_output',
                          'controls': {'variant': 'team_output'}, 'status': 'mechanical',
                          'not_comparable_reasons': reasons, 'underpowered': False,
                          'detection': {'f1': 0.5}})
        comparisons = [{'left_scorecard_id': left['scorecard_id'], 'right_scorecard_id': right['scorecard_id'],
                        'status': 'comparable'} for left in cards for right in cards if left is not right]
        self.assertEqual(_rank(cards, comparisons), [])


class BaselineCliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_offline_cli_writes_a_new_report_only(self):
        output = self.root / 'baselines.json'
        argv = ['baselines', '--experiment-manifest', MANIFEST, '--bundle-root', BUNDLE,
                '--truth', TRUTH, '--output', output]
        code, stdout, stderr = _quiet(argv)  # no --state-root: fully offline
        self.assertEqual((code, stderr), (0, ''))
        summary = json.loads(stdout)
        self.assertEqual((summary['kind'], summary['rankable'], summary['cases']), (REFERENCE_BASELINE, False, 9))
        self.assertEqual(summary['macro_brier']['coin'], 0.25)
        report = decode_json(output.read_bytes())
        self.assertEqual([item['baseline_id'] for item in report['baselines']], list(BASELINES))
        self.assertEqual((report['model_calls'], report['adjudication']), (0, 'mechanical'))
        before = output.read_bytes()
        self.assertEqual(_quiet(argv), (2, '', 'already_exists: output\n'))
        self.assertEqual(output.read_bytes(), before)
        missing = self.root / 'other.json'
        code, _, stderr = _quiet(argv[:-3] + [self.root / 'no-truth', '--output', missing])
        self.assertEqual((code, stderr), (2, 'invalid_directory: path\n'))
        self.assertFalse(missing.exists())


class CorpusPromptSizeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.cases = self.root / 'cases'
        self.cases.mkdir()
        for case_id in ('case-8b42', 'case-d080'):
            shutil.copytree(str(TRUTH / case_id), str(self.cases / case_id))
        self.team = load_json(BUNDLE / 'examples' / 'experiment.json')['teams'][0]
        self.output = self.cases / 'experiment.json'
        self.sizes = {}
        for case_id in ('case-8b42', 'case-d080'):
            directory = self.cases / case_id / 'public'
            self.sizes[case_id] = public_prompt_bytes(load_json(directory / 'evidence.json'), directory)
        self.largest = max(self.sizes, key=self.sizes.get)
        self.output_tokens = max(spec['max_output_tokens'] for spec in self.team['roles'].values())

    def run_cli(self, max_prompt_bytes, *extra):
        team = self.root / 'team.json'
        if team.exists():
            team.unlink()
        team.write_bytes(canonical_bytes({'schema_version': 1, 'team': self.team,
                                          'budgets': dict(DEFAULT_BUDGETS, max_prompt_bytes=max_prompt_bytes)}))
        return _quiet(['corpus-experiment', '--cases', self.cases, '--team', team,
                       '--experiment-id', 'size-check-1', '--output', self.output, *extra])

    def test_public_bytes_cover_evidence_and_records(self):
        directory = self.cases / POSITIVE / 'public'
        evidence = load_json(directory / 'evidence.json')
        records = sum((directory / entry['path']).stat().st_size for entry in evidence['files'])
        self.assertGreater(self.sizes[POSITIVE], records)
        self.assertGreater(self.sizes[POSITIVE], len(canonical_bytes(evidence)))

    def test_case_over_prompt_cap_is_refused_by_name(self):
        code, stdout, stderr = self.run_cli(self.sizes[self.largest] - 1)
        self.assertEqual((code, stdout, stderr), (2, '', 'case_exceeds_prompt_cap: {}\n'.format(self.largest)))
        self.assertFalse(self.output.exists())
        code, stdout, stderr = self.run_cli(self.sizes[self.largest])
        self.assertEqual((code, stderr), (0, ''))
        self.assertEqual(json.loads(stdout)['max_public_prompt_bytes'], self.sizes[self.largest])

    def test_case_over_context_is_refused_by_name(self):
        fits = estimated_tokens(self.sizes[self.largest]) + self.output_tokens
        self.assertEqual(estimated_tokens(7), 3)  # bytes / 3, rounded up
        code, stdout, stderr = self.run_cli(DEFAULT_BUDGETS['max_prompt_bytes'], '--context-tokens', fits - 1)
        self.assertEqual((code, stdout, stderr), (2, '', 'case_exceeds_context: {}\n'.format(self.largest)))
        self.assertFalse(self.output.exists())
        code, stdout, stderr = self.run_cli(DEFAULT_BUDGETS['max_prompt_bytes'], '--context-tokens', fits)
        self.assertEqual((code, stderr), (0, ''))
        self.assertEqual(json.loads(stdout)['context_tokens'], fits)
        self.output.unlink()
        code, _, stderr = self.run_cli(DEFAULT_BUDGETS['max_prompt_bytes'], '--context-tokens', 0)
        self.assertEqual((code, stderr), (2, 'invalid_integer: context_tokens\n'))


if __name__ == '__main__':
    unittest.main()

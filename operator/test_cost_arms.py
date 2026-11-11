"""cost_arms behavior the Q4 decision depends on. Synthetic rounds files only; no runtime folder, lab or model."""
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

import cost_arms as ca

CASES = list(ca.DEFAULT_CASES)
PRICES = {'model': 'claude-sonnet-5', 'currency': 'USD', 'source': 'test table',
          'per_million': {'input': 3, 'output': 15, 'cache_read': 0.3, 'cache_write': 3.75}}


def hunt(case, found=7, tokens=3_000_000, completed=True, decoys=0, missing_steps=0, usage=True):
    """One runner line. Usage splits tokens into 100k output, 400k cache writes, 10k uncached input, the rest cache reads."""
    item = {'case': case, 'workflow': f'q4-{case}', 'completed': completed,
            'halted_at': None if completed else 'merge', 'minutes_measured': 15.0,
            'by_kind': {'attack': {'found': found, 'partial': 1, 'total': 9}}, 'decoys_blamed': decoys}
    if usage:
        output, cache_write, uncached = 100_000, 400_000, 10_000
        item['usage'] = {'input_tokens': tokens - output, 'output_tokens': output,
                         'cache_read_tokens': tokens - output - cache_write - uncached,
                         'cache_write_tokens': cache_write, 'total_tokens': tokens,
                         'steps_without_usage': missing_steps}
    return item


def arm(found=7, tokens=3_000_000, cases=CASES, **overrides):
    """One hunt per case; found may be a list (one per case); overrides maps a case to its replacement line."""
    found = found if isinstance(found, list) else [found] * len(cases)
    return [overrides.get(case.replace('-', '_')) or hunt(case, found[n], tokens) for n, case in enumerate(cases)]


class Arms:
    def __init__(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.out = self.root / 'q4' / 'summary.json'

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.tmp.cleanup()

    def write(self, label, hunts):
        path = self.root / f'{label}.jsonl'
        path.write_text(''.join(json.dumps(item) + '\n' for item in hunts), encoding='utf-8')
        return path

    def prices(self, table=PRICES):
        path = self.root / 'prices.json'
        path.write_text(json.dumps(table), encoding='utf-8')
        return path

    def run(self, arms, cases=CASES, prices=None):
        paths = [(label, self.write(label, hunts)) for label, hunts in arms.items()]
        return ca.run(paths, cases, 'K6', prices, self.out)


class RuleTest(unittest.TestCase):
    def test_the_cheapest_arm_within_one_fact_with_no_halt_is_chosen(self):
        with Arms() as lab:
            result = lab.run({'K0': arm(found=6, tokens=1_500_000), 'K3': arm(tokens=2_200_000),
                              'K6': arm(tokens=3_000_000)})
            written = json.loads(lab.out.read_text(encoding='utf-8'))
        rule = result['goals']['G4.2']
        self.assertEqual((rule['chosen'], rule['result'], rule['pass']), ('K0', 'K0', True))
        self.assertEqual(rule['attack_found_floor'], 6.0)
        self.assertTrue(all(verdict['qualifies'] for verdict in rule['arms'].values()))
        self.assertTrue(result['goals']['G4.1']['pass'])
        self.assertTrue(rule['on_complete_data'])
        self.assertEqual(result['per_arm']['K0']['mean_tokens']['total'], 1_500_000)
        self.assertEqual(written['goals']['G4.2']['chosen'], 'K0')
        self.assertNotIn('_exact', written['per_arm']['K0'])

    def test_an_arm_more_than_one_fact_below_the_baseline_is_excluded(self):
        with Arms() as lab:
            result = lab.run({'K0': arm(found=[6, 6, 6, 6, 5], tokens=1_500_000), 'K3': arm(tokens=2_200_000),
                              'K6': arm(tokens=3_000_000)})
        rule = result['goals']['G4.2']
        self.assertEqual(result['per_arm']['K0']['mean_attack_found'], 5.8)
        self.assertFalse(rule['arms']['K0']['qualifies'])
        self.assertIn('below 6.0', rule['arms']['K0']['reasons'][0])
        self.assertEqual(rule['chosen'], 'K3')

    def test_a_halt_disqualifies_and_when_every_arm_halts_none_qualifies(self):
        # Seven facts kept, so the halt alone disqualifies the arm.
        halted = hunt('team-med-013', completed=False)
        with Arms() as lab:
            result = lab.run({'K0': arm(tokens=1_500_000, team_med_013=halted), 'K3': arm(tokens=2_200_000),
                              'K6': arm(tokens=3_000_000)})
        rule = result['goals']['G4.2']
        self.assertEqual(result['per_arm']['K0']['halts'], 1)
        self.assertEqual(rule['arms']['K0']['reasons'], ['1 halts'])
        self.assertEqual(rule['chosen'], 'K3')
        self.assertFalse(result['goals']['G4.1']['pass'])
        self.assertEqual(result['goals']['G4.1']['incomplete'],
                         [{'arm': 'K0', 'case': 'team-med-013', 'workflow': 'q4-team-med-013', 'halted_at': 'merge'}])

        with Arms() as lab:
            result = lab.run({label: arm(tokens=tokens, team_med_013=halted)
                              for label, tokens in (('K0', 1_500_000), ('K3', 2_200_000), ('K6', 3_000_000))})
        rule = result['goals']['G4.2']
        self.assertEqual((rule['chosen'], rule['result'], rule['pass']), (None, 'none qualifies', True))

    def test_more_decoys_blamed_than_the_baseline_excludes_an_arm(self):
        blamed = hunt('team-med-012', decoys=1, tokens=1_500_000)
        with Arms() as lab:
            result = lab.run({'K0': arm(tokens=1_500_000, team_med_012=blamed), 'K3': arm(tokens=2_200_000),
                              'K6': arm(tokens=3_000_000)})
        rule = result['goals']['G4.2']
        self.assertEqual(rule['arms']['K0']['reasons'], ['1 decoys blamed, baseline 0'])
        self.assertEqual(rule['chosen'], 'K3')


class DataTest(unittest.TestCase):
    def test_missing_usage_fails_g41_and_leaves_the_arm_tokens_unknown(self):
        with Arms() as lab:
            result = lab.run({'K0': arm(tokens=1_500_000, team_med_011=hunt('team-med-011', usage=False)),
                              'K3': arm(tokens=2_200_000, team_med_014=hunt('team-med-014', tokens=2_200_000,
                                                                            missing_steps=2)),
                              'K6': arm(tokens=3_000_000)})
        goal = result['goals']['G4.1']
        self.assertFalse(goal['pass'])
        self.assertEqual((goal['expected_hunts'], goal['complete_hunts']), (15, 13))
        self.assertEqual([(item['arm'], item['case'], item['problem']) for item in goal['usage_missing']],
                         [('K0', 'team-med-011', 'no usage recorded'), ('K3', 'team-med-014', '2 steps without usage')])
        self.assertIsNone(result['per_arm']['K0']['mean_tokens'])
        self.assertIsNone(result['per_arm']['K3']['mean_tokens'])
        rule = result['goals']['G4.2']
        self.assertFalse(rule['arms']['K3']['qualifies'])
        self.assertEqual(rule['chosen'], 'K6')
        self.assertFalse(rule['on_complete_data'])

    def test_a_case_missing_from_one_arm_is_left_out_of_every_arm(self):
        k3 = arm(tokens=2_200_000)[:4]
        # Counted, K0's last hunt would raise its mean tokens and drop it below the fact floor.
        k0 = arm(tokens=1_500_000, team_med_015=hunt('team-med-015', found=0, tokens=9_000_000))
        k6 = arm(tokens=3_000_000) + [hunt('team-med-001', found=0)]
        with Arms() as lab:
            result = lab.run({'K0': k0, 'K3': k3, 'K6': k6})
        self.assertEqual(result['paired_cases'], CASES[:4])
        self.assertEqual(result['unpaired'], [{'case': 'team-med-015', 'missing_from': ['K3']}])
        self.assertEqual(result['per_arm']['K0']['hunts'], 4)
        self.assertEqual(result['per_arm']['K0']['mean_tokens']['total'], 1_500_000)
        self.assertEqual(result['per_arm']['K0']['mean_attack_found'], 7.0)
        self.assertEqual(result['goals']['G4.2']['chosen'], 'K0')
        goal = result['goals']['G4.1']
        self.assertFalse(goal['pass'])
        self.assertEqual(goal['missing'], [{'arm': 'K3', 'case': 'team-med-015'}])
        self.assertEqual(goal['ignored_not_in_cases'], [{'arm': 'K6', 'case': 'team-med-001'}])

    def test_a_case_twice_in_one_arm_is_refused(self):
        with Arms() as lab, self.assertRaisesRegex(ValueError, 'appears twice'):
            lab.run({'K0': arm() + [hunt('team-med-011')], 'K3': arm(), 'K6': arm()})


class PriceTest(unittest.TestCase):
    USAGE = {'input_tokens': 1_200_000, 'output_tokens': 50_000, 'cache_read_tokens': 900_000,
             'cache_write_tokens': 200_000, 'total_tokens': 1_250_000, 'steps_without_usage': 0}

    def priced(self, table):
        line = hunt('team-med-011') | {'usage': self.USAGE}
        with Arms() as lab:
            return lab.run({'K0': [line], 'K6': [line]}, cases=['team-med-011'], prices=lab.prices(table))

    def test_cost_per_hunt_is_split_by_token_type_with_input_net_of_cache(self):
        result = self.priced(PRICES)
        self.assertEqual(result['per_arm']['K0']['mean_tokens'],
                         {'uncached_input': 100_000, 'cache_read': 900_000, 'cache_write': 200_000,
                          'output': 50_000, 'total': 1_250_000})
        goal = result['goals']['G4.3']
        cost = goal['arms']['K0']
        self.assertEqual(set(cost['by_type']), {'uncached_input', 'cache_read', 'cache_write', 'output'})
        for kind, expected in (('uncached_input', 0.3), ('cache_read', 0.27), ('cache_write', 0.75), ('output', 0.75)):
            self.assertAlmostEqual(cost['by_type'][kind], expected, places=6)
        self.assertAlmostEqual(cost['total'], 2.07, places=6)
        self.assertEqual((goal['table']['source'], goal['table']['currency']), ('test table', 'USD'))
        self.assertTrue(goal['pass'])

    def test_a_null_rate_leaves_the_total_unpriced_and_fails_g43(self):
        table = dict(PRICES, per_million=dict(PRICES['per_million'], cache_write=None))
        goal = self.priced(table)['goals']['G4.3']
        self.assertEqual(goal['unpriced_rates'], ['cache_write'])
        self.assertIsNone(goal['arms']['K0']['by_type']['cache_write'])
        self.assertIsNone(goal['arms']['K0']['total'])
        self.assertFalse(goal['pass'])

    def test_the_example_table_loads_with_its_source_named(self):
        prices = ca.load_prices(Path(ca.__file__).with_name('prices.example.json'))
        self.assertEqual(prices['currency'], 'USD')
        self.assertIn('Anthropic', prices['source'])


class MainTest(unittest.TestCase):
    def test_main_writes_the_summary_and_prints_the_table(self):
        with Arms() as lab:
            args = [f'--arm={label}={lab.write(label, arm(tokens=tokens))}'
                    for label, tokens in (('K0', 1_500_000), ('K3', 2_200_000), ('K6', 3_000_000))]
            with redirect_stdout(io.StringIO()) as printed:
                code = ca.main([*args, '--prices', str(lab.prices()), '--out', str(lab.out)])
            summary = json.loads(lab.out.read_text(encoding='utf-8'))
        self.assertEqual(code, 0)
        self.assertEqual(summary['cases'], CASES)
        self.assertIn('chosen: K0', printed.getvalue())
        self.assertIn('G4.1 pass', printed.getvalue())

    def test_a_baseline_that_is_not_an_arm_is_an_error(self):
        with Arms() as lab, redirect_stdout(io.StringIO()) as printed:
            code = ca.main([f'--arm=K0={lab.write("K0", arm())}', '--baseline', 'K6', '--out', str(lab.out)])
        self.assertEqual(code, 2)
        self.assertIn('baseline K6', printed.getvalue())


if __name__ == '__main__':
    unittest.main()

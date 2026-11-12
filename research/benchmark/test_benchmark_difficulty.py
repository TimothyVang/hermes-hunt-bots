"""hunt-rubric-1 difficulty measured from records: every band threshold."""
from datetime import datetime, timedelta, timezone
import unittest

from benchmark_contracts import BenchmarkError
from benchmark_difficulty import case_measurements, measure_case

T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)
FACTORS = ('noise', 'joins', 'time_span', 'gaps', 'ambiguity')


def record(event_id, seconds=0, source='s0', asset='a0'):
    stamp = (T0 + timedelta(seconds=seconds)).strftime('%Y-%m-%dT%H:%M:%SZ')
    return {'event_id': event_id, 'timestamp_utc': stamp, 'source_id': source, 'asset_id': asset,
            'event_type': 'invented', 'fields': {'timestamp_original': stamp}}


def case(steps, records, *, lookalikes=(), labels=None, complete=True, gaps=()):
    evidence = {'sources': [{'source_id': 's0', 'completeness': 'complete' if complete else 'partial'}],
                'known_gaps': list(gaps)}
    truth = {'steps': [{'step_id': 'step-%d' % index, 'observability': 'sufficient', 'support_sets': supports}
                       for index, supports in enumerate(steps)],
             'assessment_labels': {'q0': 1} if labels is None else labels,
             'lookalike_event_ids': [list(group) for group in lookalikes]}
    return evidence, records, truth


def benign(count, start=0):
    return [record('n%04d' % index, 1 + index % 50) for index in range(start, start + count)]


def scores(evidence, records, truth, curation=None):
    result = measure_case(evidence, records, truth, curation)
    return [result['factors'][key]['score'] for key in FACTORS], result['band']


def factor_case(noise, joins, span, gaps, ambiguity):
    """Inputs whose measured factors are exactly the requested scores."""
    contexts = joins + 1
    count = max(contexts, 2)
    last = (0, 1000, 5000)[span]
    relevant = [record('r%d' % index, last if index == count - 1 else 0,
                       's%d' % min(index, contexts - 1), 'a%d' % min(index, contexts - 1))
                for index in range(count)]
    others = benign(count * (5, 50, 200)[noise])
    lookalikes = [[others[index]['event_id']] for index in range(ambiguity)]
    labels = {'q0': 1, 'q1': None} if gaps == 2 else {'q0': 1}
    return case([[[item['event_id'] for item in relevant]]], relevant + others, lookalikes=lookalikes,
                labels=labels, complete=gaps == 0, gaps=[{'reason': 'declared'}] if gaps else [])


class DifficultyThresholdTests(unittest.TestCase):
    def test_noise_ratio_thresholds(self):
        for benign_count, expected in ((10, 0), (11, 1), (100, 1), (101, 2)):
            with self.subTest(benign=benign_count):
                inputs = case([[['r0']]], [record('r0')] + benign(benign_count))
                self.assertEqual(scores(*inputs)[0][0], expected)
        # Ratio, not count: two relevant records tolerate twice the noise.
        inputs = case([[['r0', 'r1']]], [record('r0'), record('r1')] + benign(20))
        self.assertEqual(scores(*inputs)[0][0], 0)
        inputs = case([[['r0', 'r1']]], [record('r0'), record('r1')] + benign(21))
        self.assertEqual(scores(*inputs)[0][0], 1)

    def test_join_thresholds_count_required_source_asset_contexts(self):
        for contexts, expected in ((1, 0), (2, 1), (3, 2), (4, 2)):
            with self.subTest(contexts=contexts):
                rows = [record('r%d' % i, 0, 's%d' % i, 'a%d' % i) for i in range(contexts)]
                self.assertEqual(scores(*case([[[r['event_id'] for r in rows]]], rows))[0][1], expected)
        # Same source on two assets is two contexts; same pair twice is one.
        rows = [record('r0', 0, 's0', 'a0'), record('r1', 0, 's0', 'a1'), record('r2', 0, 's0', 'a1')]
        self.assertEqual(case_measurements(*case([[['r0', 'r1', 'r2']]], rows))['required_joins'], 2)

    def test_alternative_support_needs_only_its_cheapest_complete_set(self):
        rows = [record('r%d' % i, 0, 's%d' % i, 'a%d' % i) for i in range(3)] + [record('r3', 0, 's0', 'a0')]
        facts = case_measurements(*case([[['r0', 'r1', 'r2'], ['r0', 'r3']]], rows))
        self.assertEqual(facts['required_joins'], 1)
        self.assertEqual(facts['relevant_events'], 4)
        # Across steps the hardest step's requirement counts.
        facts = case_measurements(*case([[['r0', 'r3']], [['r0', 'r1', 'r2']]], rows))
        self.assertEqual(facts['required_joins'], 3)

    def test_time_span_thresholds_per_support_set(self):
        for seconds, expected in ((300, 0), (301, 1), (3600, 1), (3601, 2)):
            with self.subTest(seconds=seconds):
                rows = [record('r0', 0), record('r1', seconds)]
                self.assertEqual(scores(*case([[['r0', 'r1']]], rows))[0][2], expected)
        # Two short steps far apart are not a long required correlation.
        rows = [record('r0', 0), record('r1', 10), record('r2', 5000), record('r3', 5010)]
        facts = case_measurements(*case([[['r0', 'r1']], [['r2', 'r3']]], rows))
        self.assertEqual(facts['correlation_seconds'], 10)
        # A quick alternative support set bounds the step's requirement.
        facts = case_measurements(*case([[['r0', 'r2'], ['r2', 'r3']]], rows))
        self.assertEqual(facts['correlation_seconds'], 10)

    def test_gap_scores(self):
        rows = [record('r0'), record('r1')]
        self.assertEqual(scores(*case([[['r0']]], rows))[0][3], 0)
        partial = case([[['r0'], ['r1']]], rows, complete=False, gaps=[{'reason': 'sensor restart'}])
        facts = case_measurements(*partial)
        self.assertEqual((facts['missing_records'], facts['alternative_complete']), (True, True))
        self.assertEqual(scores(*partial)[0][3], 1)
        self.assertEqual(scores(*case([[['r0']]], rows, labels={'q0': 1, 'q1': None}, complete=False))[0][3], 2)
        # A step whose only support set lost records, with nothing declared unresolvable, is not measurable.
        broken = case([[['r0', 'r-dropped']], [['r1']]], rows, complete=False)
        self.assertFalse(case_measurements(*broken)['alternative_complete'])
        with self.assertRaises(BenchmarkError) as caught:
            measure_case(*broken)
        self.assertEqual(caught.exception.code, 'unresolved_gap')

    def test_ambiguity_counts_present_curated_groups(self):
        rows = [record('r0')] + benign(6)
        for groups, expected in ((0, 0), (1, 1), (2, 2), (3, 2)):
            with self.subTest(groups=groups):
                lookalikes = [['n%04d' % (2 * i), 'n%04d' % (2 * i + 1)] for i in range(groups)]
                self.assertEqual(scores(*case([[['r0']]], rows, lookalikes=lookalikes))[0][4], expected)
        partial = case([[['r0']]], rows, lookalikes=[['n0000', 'n-dropped']])
        self.assertEqual(case_measurements(*partial)['benign_lookalikes'], 0)
        with self.assertRaises(BenchmarkError) as caught:
            case_measurements(*case([[['r0']]], rows, lookalikes=[['r0']]))
        self.assertEqual(caught.exception.code, 'lookalike_support_overlap')

    def test_band_thresholds_for_every_factor_sum(self):
        combos = {0: (0, 0, 0, 0, 0), 1: (1, 0, 0, 0, 0), 2: (1, 1, 0, 0, 0), 3: (1, 1, 1, 0, 0),
                  4: (1, 1, 1, 1, 0), 5: (1, 1, 1, 1, 1), 6: (2, 1, 1, 1, 1), 7: (2, 2, 1, 1, 1),
                  8: (2, 2, 2, 1, 1), 9: (2, 2, 2, 2, 1), 10: (2, 2, 2, 2, 2)}
        bands = {0: 'D1', 1: 'D1', 2: 'D2', 3: 'D2', 4: 'D3', 5: 'D3', 6: 'D4', 7: 'D4',
                 8: 'D5', 9: 'D5', 10: 'D5'}
        for total, factors in combos.items():
            with self.subTest(total=total):
                measured, band = scores(*factor_case(*factors))
                self.assertEqual(measured, list(factors))
                self.assertEqual(band, bands[total])

    def test_zero_positive_control_requires_matched_family(self):
        matched = measure_case(*factor_case(1, 2, 1, 0, 1))
        control = case([], benign(12), labels={'q0': 0})
        with self.assertRaises(BenchmarkError) as caught:
            measure_case(*control)
        self.assertEqual(caught.exception.code, 'matched_family_required')
        inherited = measure_case(*control, {'matched_control': matched})
        self.assertTrue(inherited['control'])
        self.assertEqual(inherited['factors'], matched['factors'])
        with self.assertRaises(BenchmarkError):
            measure_case(*control, {'matched_control': matched, 'band': 'D1'})

    def test_steps_without_sufficient_observability_inherit_matched_family_but_are_not_controls(self):
        matched = measure_case(*factor_case(1, 2, 1, 0, 1))
        evidence, records, truth = case([[['r0']]], [record('r0')] + benign(12), labels={'q0': None})
        truth['steps'][0]['observability'] = 'insufficient'
        self.assertEqual(case_measurements(evidence, records, truth)['relevant_events'], 0)
        with self.assertRaises(BenchmarkError) as caught:
            measure_case(evidence, records, truth)
        self.assertEqual(caught.exception.code, 'matched_family_required')
        inherited = measure_case(evidence, records, truth, {'matched_control': matched})
        self.assertFalse(inherited['control'])
        self.assertEqual((inherited['band'], inherited['factors']), (matched['band'], matched['factors']))
        # One sufficient step makes the case measurable on its own; a matched family is then refused.
        truth['steps'][0]['observability'] = 'sufficient'
        with self.assertRaises(BenchmarkError):
            measure_case(evidence, records, truth, {'matched_control': matched})


if __name__ == '__main__':
    unittest.main()

"""Deterministic evaluator regressions; no evaluated model judges its answers."""
import copy
import unittest

from benchmark_contracts import BenchmarkError, canonical_bytes, digest_bytes
from benchmark_scoring import (
    NOT_MEASURED_MECHANICAL, difficulty_from_measurements, edge_item_id, mechanical_verdicts, score_output,
)
from test_benchmark_contracts import HASH, WINDOW, public_bundle, truth


class DifficultyTests(unittest.TestCase):
    def measure(self, **changes):
        values = dict(benign_events=10, relevant_events=1, required_joins=1,
                      correlation_seconds=300, missing_records=False,
                      alternative_complete=True, unresolvable_questions=0,
                      benign_lookalikes=0)
        values.update(changes)
        return difficulty_from_measurements(**values)

    def test_quantitative_boundaries(self):
        self.assertEqual(self.measure()['band'], 'D1')
        for count, expected in ((10, 0), (11, 1), (100, 1), (101, 2)):
            self.assertEqual(self.measure(benign_events=count)['factors']['noise']['score'], expected)
        for seconds, expected in ((300, 0), (301, 1), (3600, 1), (3601, 2)):
            self.assertEqual(self.measure(correlation_seconds=seconds)['factors']['time_span']['score'], expected)
        self.assertEqual(self.measure(required_joins=2)['factors']['joins']['score'], 1)
        self.assertEqual(self.measure(required_joins=3)['factors']['joins']['score'], 2)
        self.assertEqual(self.measure(missing_records=True)['factors']['gaps']['score'], 1)
        result = self.measure(benign_events=101, required_joins=3, correlation_seconds=3601,
                              missing_records=True, alternative_complete=False,
                              unresolvable_questions=1, benign_lookalikes=2)
        self.assertEqual(result['band'], 'D5')
        self.assertEqual(sum(item['score'] for item in result['factors'].values()), 10)

    def test_controls_inherit_family_without_infinite_noise(self):
        matched = self.measure(required_joins=3)
        result = self.measure(relevant_events=0, matched_control=matched)
        self.assertEqual(result['band'], 'D2')
        self.assertTrue(result['control'])
        self.assertFalse(matched['control'])
        with self.assertRaises(BenchmarkError):
            self.measure(relevant_events=0)

    def test_unexplained_gaps_and_nonfinite_measurements_fail(self):
        for changes in ({'correlation_seconds': float('nan')}, {'benign_events': True},
                        {'missing_records': True, 'alternative_complete': False},
                        {'required_joins': 0}):
            with self.subTest(changes=changes), self.assertRaises(BenchmarkError):
                self.measure(**changes)


class ScoringTests(unittest.TestCase):
    def setUp(self):
        self.bundle = public_bundle()
        event = copy.deepcopy(self.bundle['events'][0])
        event['event_id'] = 'e2'
        event['locator']['record_id'] = '2'
        self.bundle['events'].append(event)
        self.truth = truth(self.bundle)
        step = copy.deepcopy(self.truth['steps'][0])
        step.update(step_id='t2', technique_id='T1082', support_sets=[['e2']])
        self.truth['steps'].append(step)
        self.output = {
            'schema_version': 1, 'stage_key': 'handoff', 'summary': 'Invented test assertions.',
            'claims': [], 'findings': [self.finding('f1'), self.finding('f2', 'T1082', ['e2'])],
            'hypotheses': [], 'gaps': [], 'limitations': [], 'requested_decision': 'approve',
            'chain_edges': [], 'assessment_answers': [
                {'question_id': 'q1', 'probability_suspicious': 0.8}]}

    def finding(self, finding_id, technique='T1033', events=None, disposition='suspicious'):
        return {'finding_id': finding_id, 'asset_id': 'a1', 'technique_id': technique,
                'window_utc': copy.deepcopy(WINDOW), 'disposition': disposition,
                'confidence': 0.9, 'event_ids': ['e1'] if events is None else events,
                'rationale': 'Invented assertion.'}

    def verdict(self, item_id, state='supported', events=None, kind='finding'):
        return {'trial_id': 'trial1', 'output_sha256': HASH, 'item_kind': kind,
                'item_id': item_id, 'verdict': state,
                'event_ids': ['e1', 'e2'] if events is None else events,
                'by': 'human-reviewer', 'note': 'Synthetic unit-test judgment.'}

    def verdicts(self):
        result = [self.verdict(item['finding_id']) for item in self.output['findings']]
        result += [self.verdict(item['claim_id'], kind='claim') for item in self.output['claims']]
        result += [self.verdict(edge_item_id(edge), kind='edge') for edge in self.output.get('chain_edges', [])]
        return result

    def score(self, verdicts=None, completed=True):
        return score_output(self.output, self.truth, self.bundle,
                            self.verdicts() if verdicts is None else verdicts,
                            trial_id='trial1', output_sha256=HASH, completed=completed)

    def test_supported_precision_recall_oracle(self):
        result = self.score([self.verdict('f1'), self.verdict('f2', 'insufficient')])
        self.assertEqual(result['status'], 'final')
        self.assertEqual([result['detection'][key] for key in ('tp', 'fp', 'fn')], [1, 1, 1])
        for key in ('precision', 'recall', 'f1'):
            self.assertEqual(result['detection'][key], 0.5)
        self.assertEqual(result['detection']['truth_correct_unsupported'], 1)

    def test_unobservable_steps_do_not_inflate_recall_denominator(self):
        invisible = copy.deepcopy(self.truth['steps'][0])
        invisible.update(step_id='t3', observability='absent', support_sets=[])
        self.truth['steps'].append(invisible)
        result = self.score()
        self.assertEqual(result['detection']['eligible_steps'], 2)
        self.assertEqual(result['detection']['visibility_limited_steps'], 1)
        self.assertEqual(result['detection']['recall'], 1)

    def test_supported_detection_of_unobservable_step_is_not_false_positive(self):
        self.truth['steps'][1]['observability'] = 'unknown'
        detection = self.score()['detection']
        self.assertEqual((detection['tp'], detection['fp'], detection['fn']), (1, 0, 0))
        self.assertEqual(detection['visibility_limited_detections'], 1)
        self.assertEqual(detection['eligible_steps'], 1)
        self.assertEqual(detection['precision'], 1)
        self.assertEqual(detection['truth_correct_unsupported'], 0)
        self.assertEqual(detection['truth_incorrect'], 0)

    def test_exact_duplicates_collapse_with_normalized_times_and_event_sets(self):
        duplicate = copy.deepcopy(self.output['findings'][0])
        duplicate['finding_id'] = 'f3'
        duplicate['window_utc']['start_inclusive'] = '2026-01-01T00:00:00+00:00'
        self.output['findings'].append(duplicate)
        result = self.score()
        self.assertEqual(result['detection']['tp'], 2)
        self.assertEqual(result['detection']['fp'], 0)
        self.assertEqual(result['diagnostics']['duplicate_findings'], 1)
        self.assertEqual(result['diagnostics']['matched_pairs'][0]['finding_id'], 'f1')

    def test_duplicate_conflicting_verdicts_never_select_favorable_judgment(self):
        duplicate = copy.deepcopy(self.output['findings'][0])
        duplicate['finding_id'] = 'f3'
        self.output['findings'].append(duplicate)
        result = self.score([self.verdict('f1'), self.verdict('f2'),
                             self.verdict('f3', 'contradicted')])
        self.assertEqual(result['status'], 'provisional')
        self.assertEqual(result['diagnostics']['duplicate_conflicts'], 1)
        self.assertEqual(result['detection']['tp'], 1)
        self.assertEqual(result['detection']['fp'], 1)

    def test_duplicate_missing_verdict_is_provisional_and_not_supported(self):
        duplicate = copy.deepcopy(self.output['findings'][0])
        duplicate['finding_id'] = 'f3'
        self.output['findings'].append(duplicate)
        result = self.score([self.verdict('f1'), self.verdict('f2')])
        self.assertEqual(result['status'], 'provisional')
        self.assertEqual(result['detection']['tp'], 1)
        self.assertIn({'item_kind': 'finding', 'item_id': 'f3'}, result['missing_adjudications'])

    def test_maximum_matching_reassigns_first_finding_instead_of_greedy_loss(self):
        self.truth['steps'][1]['technique_id'] = 'T1033'
        self.output['findings'][0]['event_ids'] = ['e1', 'e2']
        self.output['findings'][1] = self.finding('f2', events=['e1'])
        result = self.score()
        self.assertEqual(result['detection']['tp'], 2)
        self.assertEqual(result['diagnostics']['matched_pairs'],
                         [{'step_id': 't1', 'finding_id': 'f2'},
                          {'step_id': 't2', 'finding_id': 'f1'}])
        self.output['findings'].reverse()
        self.truth['steps'].reverse()
        self.assertEqual(self.score()['diagnostics']['matched_pairs'],
                         result['diagnostics']['matched_pairs'])

    def test_support_sets_require_entire_alternative_in_both_citations(self):
        self.truth['steps'][0]['support_sets'] = [['e1', 'e2']]
        self.assertEqual(self.score()['detection']['tp'], 1)
        self.output['findings'][0]['event_ids'] = ['e1', 'e2']
        result = self.score([self.verdict('f1', events=['e1']), self.verdict('f2')])
        self.assertEqual(result['detection']['tp'], 1)
        self.truth['steps'][0]['support_sets'].append(['e1'])
        self.assertEqual(self.score([self.verdict('f1', events=['e1']),
                                     self.verdict('f2')])['detection']['tp'], 2)

    def test_blocked_attempts_get_detection_not_successful_compromise_claims(self):
        result = self.score()
        self.assertEqual(result['detection']['tp'], 2)
        self.assertEqual(result['detection']['execution_outcomes']['blocked'],
                         {'eligible_steps': 2, 'matched_steps': 2})
        self.assertIsNone(result['diagnostics']['execution_outcome_correctness'])

    def test_parent_technique_is_diagnostic_not_subtechnique_credit(self):
        # Truth IDs must exist in pinned ATT&CK v20 (unknown ones are refused).
        self.truth['steps'][0]['technique_id'] = 'T1059.004'
        self.output['findings'][0]['technique_id'] = 'T1059'
        result = self.score()
        self.assertEqual(result['detection']['parent_technique_only'], 1)
        self.assertEqual(result['detection']['truth_incorrect'], 1)
        self.assertEqual(result['detection']['tp'], 1)

    def test_failed_and_missing_trials_keep_positive_denominators(self):
        for completed in (False, True):
            result = score_output(None, self.truth, self.bundle, [], trial_id='trial1',
                                  output_sha256=None, completed=completed)
            self.assertEqual(result['detection']['fn'], 2)
            self.assertEqual(result['detection']['f1'], 0)
            self.assertIsNone(result['detection']['precision'])
            self.assertEqual(result['detection']['null_reasons']['precision'], 'no_predicted_positives')
            self.assertFalse(result['diagnostics']['completed'])
            self.assertEqual(result['calibration']['missing'], 1)
        result = self.score(completed=False)
        self.assertEqual(result['detection']['tp'], 0)
        self.assertEqual(result['detection']['fn'], 2)

    def test_empty_all_benign_denominators_are_not_perfect_detection(self):
        self.truth['steps'] = []
        self.truth['assessment_labels']['q1'] = 0
        self.output['findings'] = []
        result = self.score()
        for key in ('precision', 'recall', 'f1'):
            self.assertIsNone(result['detection'][key])
            self.assertIn(key, result['detection']['null_reasons'])

    def add_control(self, disposition='benign'):
        self.truth['controls'].append({'control_id': 'control1', 'asset_id': 'a1',
                                       'window_utc': copy.deepcopy(WINDOW),
                                       'expected_disposition': disposition})

    def test_benign_false_alarms_include_unsupported_assertions(self):
        self.add_control()
        result = self.score([self.verdict('f1', 'insufficient'),
                             self.verdict('f2', 'contradicted')])
        benign = result['controls']['benign']
        self.assertEqual(benign['false_alarms'], 1)
        self.assertEqual(benign['false_alarm_rate'], 1)
        self.assertEqual(benign['correct_dispositions'], 0)
        failed = self.score(completed=False)['controls']['benign']
        self.assertEqual(failed['evaluated'], 0)
        self.assertEqual(failed['missing_or_failed'], 1)
        self.assertIsNone(failed['false_alarm_rate'])
        self.assertEqual(failed['correct_disposition_rate'], 0)

    def test_insufficient_requires_explicit_supported_disposition_not_silence(self):
        self.add_control('insufficient')
        self.output['findings'] = []
        self.assertEqual(self.score()['controls']['insufficient']['correct_dispositions'], 0)
        self.output['findings'] = [self.finding('f1', None, [], 'insufficient')]
        self.assertEqual(self.score()['controls']['insufficient']['correct_dispositions'], 1)
        result = self.score([self.verdict('f1', 'insufficient')])
        self.assertEqual(result['controls']['insufficient']['correct_dispositions'], 0)

    def test_chain_edges_need_endpoint_matches_truth_and_ordering_verdict(self):
        self.truth['edges'] = [['t1', 't2']]
        self.output['chain_edges'] = [['f1', 'f2']]
        result = self.score()
        self.assertEqual([result['chain_edges'][key] for key in ('tp', 'fp', 'fn')], [1, 0, 0])
        verdicts = self.verdicts()
        verdicts[-1]['verdict'] = 'insufficient'
        result = self.score(verdicts)
        self.assertEqual([result['chain_edges'][key] for key in ('tp', 'fp', 'fn')], [0, 1, 1])
        result = self.score(verdicts[:-1])
        self.assertEqual(result['status'], 'provisional')
        self.assertEqual(result['chain_edges']['tp'], 0)
        self.output['chain_edges'] = [['f2', 'f1']]
        self.assertEqual(self.score()['chain_edges']['tp'], 0)

    def test_chain_edge_visibility_and_duplicate_aliases(self):
        self.truth['edges'] = [['t1', 't2']]
        duplicate = copy.deepcopy(self.output['findings'][0])
        duplicate['finding_id'] = 'f3'
        self.output['findings'].append(duplicate)
        self.output['chain_edges'] = [['f1', 'f2'], ['f3', 'f2']]
        result = self.score()
        self.assertEqual(result['chain_edges']['tp'], 1)
        self.assertEqual(result['chain_edges']['fp'], 0)
        self.truth['steps'][1]['observability'] = 'unknown'
        result = self.score()
        self.assertEqual(result['chain_edges']['eligible_edges'], 0)
        self.assertEqual(result['chain_edges']['visibility_limited_edges'], 1)

    def test_claims_citations_and_missing_judgments_are_independent(self):
        self.output['claims'] = [
            {'claim_id': 'c1', 'kind': 'observation', 'text': 'Invented.', 'event_ids': ['e1']},
            {'claim_id': 'c2', 'kind': 'inference', 'text': 'Invented.', 'event_ids': ['nonexistent']},
            {'claim_id': 'c3', 'kind': 'hypothesis', 'text': 'Invented.', 'event_ids': []}]
        verdicts = [self.verdict('f1'), self.verdict('f2'),
                    self.verdict('c1', kind='claim'),
                    self.verdict('c2', 'contradicted', kind='claim')]
        result = self.score(verdicts)
        self.assertEqual(result['status'], 'provisional')
        self.assertEqual(result['claims']['supported'], 1)
        self.assertEqual(result['claims']['contradicted'], 1)
        self.assertEqual(result['claims']['missing'], 1)
        self.assertEqual(result['claims']['support_rate'], 1 / 3)
        self.assertEqual(result['citations']['total'], 4)
        self.assertEqual(result['citations']['invalid'], 1)
        self.assertEqual(result['citations']['invalid_rate'], 0.25)
        self.assertEqual(result['detection']['tp'], 2)

    def test_no_citation_cannot_become_supported_claim(self):
        self.output['claims'] = [
            {'claim_id': 'c1', 'kind': 'observation', 'text': 'Invented.', 'event_ids': []}]
        result = self.score()
        self.assertEqual(result['claims']['supported'], 0)
        self.assertEqual(result['claims']['unsupported'], 1)

    def test_calibration_fixed_questions_missing_abstained_and_null_labels(self):
        result = self.score()
        self.assertAlmostEqual(result['calibration']['brier'], 0.04)
        self.assertEqual(result['calibration']['decision_coverage'], 1)
        self.output['assessment_answers'][0]['probability_suspicious'] = None
        result = self.score()
        self.assertEqual(result['calibration']['abstained'], 1)
        self.assertEqual(result['calibration']['missing'], 0)
        self.assertEqual(result['calibration']['decision_coverage'], 0)
        self.assertIsNone(result['calibration']['brier'])
        self.output['assessment_answers'] = []
        self.assertEqual(self.score()['calibration']['missing'], 1)
        self.truth['assessment_labels']['q1'] = None
        result = self.score()
        self.assertEqual(result['calibration']['undecidable_questions'], 1)
        self.assertIsNone(result['calibration']['decision_coverage'])

    def test_non_handoff_calibration_is_explicitly_diagnostic(self):
        self.output['stage_key'] = 'analysis'
        del self.output['assessment_answers']
        del self.output['chain_edges']
        result = self.score()
        self.assertTrue(result['diagnostics']['diagnostic_only'])
        self.assertFalse(result['calibration']['applicable'])
        self.assertEqual(result['calibration']['missing'], 1)
        self.assertIsNone(result['calibration']['brier'])

    def test_scope_violations_do_not_get_credit_and_half_open_intervals_do_not_overlap(self):
        self.output['findings'][0]['asset_id'] = 'unknown'
        self.output['findings'][1]['window_utc']['end_exclusive'] = '2026-01-01T00:06:00Z'
        result = self.score()
        self.assertEqual(result['diagnostics']['scope_boundary_violations'], 2)
        self.assertEqual(result['detection']['tp'], 0)
        self.output['findings'] = [self.finding('f1')]
        self.output['findings'][0]['window_utc']['end_exclusive'] = '2026-01-01T00:02:00Z'
        self.truth['steps'][0]['window_utc']['start_inclusive'] = '2026-01-01T00:02:00Z'
        self.assertEqual(self.score()['detection']['tp'], 0)

    def test_wrong_binding_duplicate_unknown_and_model_verdicts_reject(self):
        changes = ({'trial_id': 'other'}, {'output_sha256': 'b' * 64},
                   {'item_id': 'unknown'}, {'event_ids': ['unknown']},
                   {'event_ids': ['e1', 'e1']}, {'by': 'model'},
                   {'by': 'framework-reviewer'}, {'by': 'evidence_checker'},
                   {'note': ''}, {'extra': 'not allowed'})
        for change in changes:
            with self.subTest(change=change), self.assertRaises(BenchmarkError):
                verdict = self.verdict('f1')
                verdict.update(change)
                self.score([verdict])
        with self.assertRaises(BenchmarkError):
            self.score([self.verdict('f1'), self.verdict('f1')])

    def test_claim_verdict_does_not_adjudicate_finding(self):
        self.output['claims'] = [
            {'claim_id': 'f1', 'kind': 'observation', 'text': 'Invented.', 'event_ids': ['e1']}]
        result = self.score([self.verdict('f1', kind='claim'), self.verdict('f2')])
        self.assertEqual(result['status'], 'provisional')
        self.assertEqual(result['detection']['tp'], 1)

    def test_edge_identifier_is_ordered_stable_canonical_list_hash(self):
        edge = ['f1', 'f2']
        self.assertEqual(edge_item_id(edge), 'edge_' + digest_bytes(canonical_bytes(edge)))
        self.assertNotEqual(edge_item_id(edge), edge_item_id(list(reversed(edge))))
        with self.assertRaises(BenchmarkError):
            edge_item_id(tuple(edge))

    def test_inputs_are_not_mutated(self):
        before = copy.deepcopy((self.output, self.truth, self.bundle))
        self.score()
        self.assertEqual((self.output, self.truth, self.bundle), before)

    def test_missing_model_citation_blocks_ranking_without_discarding_errors(self):
        for citations in ([], ['nonexistent']):
            with self.subTest(citations=citations):
                self.output['findings'][0]['event_ids'] = citations
                result = self.score()
                self.assertEqual(result['status'], 'final')
                self.assertFalse(result['ranking_eligible'])
                self.assertIn('missing_model_citation', result['ranking_blockers'])
                self.assertEqual([result['detection'][key] for key in ('tp', 'fp', 'fn')],
                                 [1, 1, 1])
        self.output['findings'][0]['event_ids'] = ['e1']
        result = self.score([self.verdict('f1', 'contradicted'), self.verdict('f2')])
        self.assertTrue(result['ranking_eligible'])
        self.assertEqual(result['detection']['fp'], 1)

    def test_insufficient_without_citations_does_not_block_ranking(self):
        self.add_control('insufficient')
        self.output['findings'] = [self.finding('f1', None, [], 'insufficient')]
        self.assertTrue(self.score()['ranking_eligible'])

    def test_nonduplicate_supported_assertions_still_have_one_to_one_limit(self):
        extra = copy.deepcopy(self.output['findings'][0])
        extra['finding_id'] = 'f3'
        extra['rationale'] = 'A distinct material assertion.'
        self.output['findings'].append(extra)
        result = self.score()
        self.assertEqual(result['detection']['tp'], 2)
        self.assertEqual(result['detection']['fp'], 1)
        self.assertEqual(result['diagnostics']['duplicate_findings'], 0)

    def test_conflicting_duplicate_edges_are_provisional_without_causal_credit(self):
        self.truth['edges'] = [['t1', 't2']]
        duplicate = copy.deepcopy(self.output['findings'][0])
        duplicate['finding_id'] = 'f3'
        self.output['findings'].append(duplicate)
        self.output['chain_edges'] = [['f1', 'f2'], ['f3', 'f2']]
        verdicts = self.verdicts()
        verdicts[-1]['verdict'] = 'contradicted'
        result = self.score(verdicts)
        self.assertEqual(result['status'], 'provisional')
        self.assertEqual(result['chain_edges']['tp'], 0)
        self.assertEqual(result['chain_edges']['fp'], 1)
        self.assertEqual(result['diagnostics']['duplicate_conflicts'], 1)

    def test_brier_is_not_finding_confidence_or_zero_filled(self):
        self.output['findings'] = []
        self.output['assessment_answers'][0]['probability_suspicious'] = 0.2
        result = self.score()
        self.assertAlmostEqual(result['calibration']['brier'], 0.64)
        self.assertEqual(result['calibration']['supplied'], 1)
        self.assertEqual(result['detection']['fn'], 2)

    def test_overbroad_out_of_scope_alarm_still_counts_against_overlapping_control(self):
        self.add_control()
        self.output['findings'] = [self.finding('f1')]
        self.output['findings'][0]['window_utc']['end_exclusive'] = '2026-01-01T00:06:00Z'
        result = self.score()
        self.assertEqual(result['diagnostics']['scope_boundary_violations'], 1)
        self.assertEqual(result['controls']['benign']['false_alarms'], 1)
        self.assertEqual(result['controls']['benign']['false_alarm_rate'], 1)

    def dispute(self):
        """Agent-consensus truth with one disputed record e3 and a finding citing only it."""
        event = copy.deepcopy(self.bundle['events'][0])
        event['event_id'] = 'e3'
        event['locator']['record_id'] = '3'
        self.bundle['events'].append(event)
        self.truth = dict(self.truth, attestation='agent_consensus', disputed_event_ids=['e3'],
                          evidence_manifest_sha256=digest_bytes(canonical_bytes(self.bundle)))
        self.output['findings'].append(self.finding('f3', 'T1059', ['e3']))

    def test_finding_citing_only_disputed_records_is_neither_tp_nor_fp(self):
        self.dispute()
        self.add_control()
        self.output['findings'] = [self.output['findings'][2], self.finding('f4', 'T1082', ['e3'])]
        self.output['chain_edges'] = [['f3', 'f4']]
        # No verdict for the ignored findings or their edge is needed: the result is final, not provisional.
        result = self.score([])
        detection = result['detection']
        self.assertEqual(result['status'], 'final')
        self.assertEqual(result['missing_adjudications'], [])
        self.assertEqual((detection['tp'], detection['fp'], detection['fn'], detection['disputed_ignored']),
                         (0, 0, 2, 2))
        self.assertEqual((detection['truth_incorrect'], detection['truth_correct_unsupported']), (0, 0))
        self.assertEqual(result['controls']['benign']['false_alarms'], 0)
        self.assertEqual((result['chain_edges']['fp'], result['chain_edges']['disputed_ignored']), (0, 1))

    def test_disputed_findings_do_not_change_supported_scores(self):
        baseline = self.score()['detection']
        self.dispute()
        self.output['chain_edges'] = [['f1', 'f3']]
        result = self.score([self.verdict('f1'), self.verdict('f2')])
        self.assertEqual(result['status'], 'final')
        for key in ('tp', 'fp', 'fn', 'precision', 'recall', 'f1'):
            self.assertEqual(result['detection'][key], baseline[key])
        self.assertEqual(result['detection']['disputed_ignored'], 1)
        self.assertEqual(result['chain_edges']['disputed_ignored'], 1)
        # A finding that also cites undisputed evidence is scored normally: here a wrong technique, an FP.
        self.output['findings'][2]['event_ids'] = ['e1', 'e3']
        result = self.score([self.verdict('f1'), self.verdict('f2'), self.verdict('f3', 'insufficient'),
                             self.verdict(edge_item_id(['f1', 'f3']), 'insufficient', kind='edge')])
        self.assertEqual((result['detection']['fp'], result['detection']['truth_incorrect'],
                          result['detection']['disputed_ignored']), (1, 1, 0))

    def test_human_attested_truth_ignores_nothing(self):
        self.output['findings'].append(self.finding('f3', 'T1059', ['e2']))
        result = self.score()
        self.assertEqual((result['detection']['fp'], result['detection']['disputed_ignored']), (1, 0))


class MechanicalScoringTests(unittest.TestCase):
    """Deterministic rule adjudication: never human verdicts, never ``final``."""

    setUp = ScoringTests.setUp
    finding = ScoringTests.finding
    verdict = ScoringTests.verdict
    verdicts = ScoringTests.verdicts
    add_control = ScoringTests.add_control
    dispute = ScoringTests.dispute

    def mechanical(self, completed=True):
        return score_output(self.output, self.truth, self.bundle, None, trial_id='trial1',
                            output_sha256=HASH, completed=completed, adjudication='mechanical')

    def test_mechanical_oracle_reproduces_half_scores_with_mechanical_status(self):
        self.output['findings'] = [self.finding('f1'), self.finding('f2', 'T9999', ['e1'])]
        result = self.mechanical()
        self.assertEqual((result['status'], result['adjudication']), ('mechanical', 'mechanical'))
        self.assertEqual([result['detection'][key] for key in ('tp', 'fp', 'fn')], [1, 1, 1])
        for key in ('precision', 'recall', 'f1'):
            self.assertEqual(result['detection'][key], 0.5)
        self.assertEqual(result['missing_adjudications'], [])

    def test_mechanical_ignores_disputed_only_findings(self):
        self.dispute()
        self.add_control()
        result = self.mechanical()
        self.assertEqual([result['detection'][key] for key in ('tp', 'fp', 'fn', 'disputed_ignored')],
                         [2, 0, 0, 1])
        self.assertEqual(result['detection']['truth_incorrect'], 0)
        # f1/f2 overlap the control and alarm on it; the disputed f3 adds no alarm of its own.
        self.output['findings'] = [self.output['findings'][2]]
        self.assertEqual(self.mechanical()['controls']['benign']['false_alarms'], 0)

    def test_incomplete_support_set_is_insufficient_not_detection(self):
        self.truth['steps'][1]['support_sets'] = [['e1', 'e2']]
        verdicts = mechanical_verdicts(self.output['findings'], self.truth, {'e1', 'e2'})
        self.assertEqual(verdicts[('finding', 'f1')]['verdict'], 'supported')
        self.assertEqual(verdicts[('finding', 'f2')]['verdict'], 'insufficient')
        detection = self.mechanical()['detection']
        self.assertEqual((detection['tp'], detection['fp'], detection['fn']), (1, 1, 1))
        self.assertEqual(detection['truth_correct_unsupported'], 1)

    def test_unmatched_alarm_on_benign_control_is_contradicted(self):
        self.add_control()
        self.output['findings'] = [self.finding('f9', 'T9999', ['e1']),
                                   self.finding('f8', 'T9999', ['e1'], 'benign')]
        verdicts = mechanical_verdicts(self.output['findings'], self.truth, {'e1', 'e2'})
        self.assertEqual(verdicts[('finding', 'f9')]['verdict'], 'contradicted')
        self.assertEqual(verdicts[('finding', 'f8')]['verdict'], 'insufficient')
        self.assertEqual(verdicts[('finding', 'f9')]['basis'], 'mechanical-rules-1')
        result = self.mechanical()
        self.assertEqual(result['controls']['benign']['false_alarms'], 1)
        # A correct benign disposition is a semantic judgment: never fabricated.
        self.assertIsNone(result['controls']['benign']['correct_dispositions'])
        self.assertEqual(result['controls']['benign']['null_reasons']['correct_disposition_rate'],
                         NOT_MEASURED_MECHANICAL)

    def test_claim_semantic_support_is_not_measured(self):
        self.output['claims'] = [
            {'claim_id': 'c1', 'kind': 'observation', 'text': 'Invented.', 'event_ids': ['e1']},
            {'claim_id': 'c2', 'kind': 'inference', 'text': 'Invented.', 'event_ids': ['missing']}]
        claims = self.mechanical()['claims']
        self.assertEqual(claims['semantic_support'], NOT_MEASURED_MECHANICAL)
        self.assertIsNone(claims['supported'])
        self.assertIsNone(claims['support_rate'])
        self.assertEqual(claims['null_reasons']['support_rate'], NOT_MEASURED_MECHANICAL)
        self.assertEqual((claims['citation_valid'], claims['citation_invalid']), (1, 1))
        self.assertEqual(claims['citation_valid_rate'], 0.5)

    def test_edges_need_matched_endpoints_and_ordered_truth_edge(self):
        self.truth['edges'] = [['t1', 't2']]
        self.output['chain_edges'] = [['f1', 'f2'], ['f2', 'f1']]
        chain = self.mechanical()['chain_edges']
        self.assertEqual((chain['tp'], chain['fp'], chain['fn']), (1, 1, 0))
        self.output['findings'][1]['event_ids'] = ['e1']
        self.output['chain_edges'] = [['f1', 'f2']]
        chain = self.mechanical()['chain_edges']
        self.assertEqual((chain['tp'], chain['fp'], chain['fn']), (0, 1, 1))

    def test_mechanical_refuses_human_verdicts_and_unknown_modes(self):
        with self.assertRaises(BenchmarkError):
            score_output(self.output, self.truth, self.bundle, self.verdicts(), trial_id='trial1',
                         output_sha256=HASH, adjudication='mechanical')
        with self.assertRaises(BenchmarkError):
            score_output(self.output, self.truth, self.bundle, self.verdicts(), trial_id='trial1',
                         output_sha256=HASH, adjudication='model')


if __name__ == '__main__':
    unittest.main()

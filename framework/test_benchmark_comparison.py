"""Deterministic invented scores, not model-quality observations."""

import copy
import json
import unittest

from benchmark_comparison import build_comparison


def metrics(f1=1.0, adjudication='human'):
    tp, fp, fn = ((1, 0, 0) if f1 == 1 else (1, 1, 1) if f1 == 0.5 else (0, 0, 1))
    return {'status': 'final' if adjudication == 'human' else 'mechanical', 'adjudication': adjudication,
            'missing_adjudications': [], 'ranking_eligible': True, 'ranking_blockers': [],
            'detection': {'tp': tp, 'fp': fp, 'fn': fn, 'precision': tp / (tp + fp) if tp + fp else None,
                          'recall': tp / (tp + fn), 'f1': f1, 'eligible_steps': tp + fn,
                          'visibility_limited_steps': 0, 'visibility_limited_detections': 0,
                          'truth_correct_unsupported': 0,
                          'truth_incorrect': fp, 'parent_technique_only': 0,
                          'null_reasons': {}},
            'claims': {'total': 1, 'supported': tp, 'contradicted': 0, 'insufficient': 0,
                       'missing': 0, 'support_rate': float(tp), 'contradicted_rate': 0.0, 'null_reasons': {}},
            'citations': {'total': 1, 'invalid': 0, 'invalid_rate': 0.0,
                         'items_with_invalid_citations': 0, 'null_reasons': {}},
            'controls': {'benign': {'eligible': 0, 'evaluated': 0, 'missing_or_failed': 0,
                                    'false_alarms': 0, 'correct_dispositions': 0,
                                    'false_alarm_rate': None, 'correct_disposition_rate': None,
                                    'null_reasons': {'false_alarm_rate': 'no_evaluated_benign_controls'}},
                         'insufficient': {'eligible': 0, 'evaluated': 0, 'missing_or_failed': 0,
                                          'correct_dispositions': 0, 'correct_disposition_rate': None,
                                          'null_reasons': {}}},
            'chain_edges': {'tp': 0, 'fp': 0, 'fn': 0, 'eligible_edges': 0,
                            'visibility_limited_edges': 0, 'precision': None, 'recall': None,
                            'f1': None, 'null_reasons': {}},
            'calibration': {'eligible_questions': 1, 'undecidable_questions': 0,
                            'supplied': 1, 'missing': 0, 'abstained': 0,
                            'decision_coverage': 1.0, 'brier': 0.0, 'applicable': True, 'null_reasons': {}},
            'diagnostics': {'duplicate_findings': 0, 'duplicate_conflicts': 0,
                            'scope_boundary_violations': 0, 'matched_pairs': [], 'scope_errors': [],
                            'completed': True, 'diagnostic_only': False,
                            'execution_outcome_correctness': None}}


def fixture(families=1, repetitions=1):
    teams = []
    for team_id in ('a', 'b'):
        teams.append({'team_id': team_id, 'deployment': 'local',
                      'roles': {'role-' + str(index): {'model_requested': team_id + '-model',
                                'parameters': {'temperature': 0, 'seed': None},
                                'timeout_seconds': 20, 'max_output_tokens': 200}
                                for index in range(6)},
                      'runtime_facts': {'server': 'invented-server', 'server_version': '1',
                                        'model_weight_sha256': team_id * 64,
                                        'quantization': 'test', 'context_configuration': {'context_window_tokens': 4096},
                                        'cpu': 'test-cpu', 'gpu': None, 'ram_bytes': 1024, 'concurrency': 1}})
    experiment = {'teams': teams, 'repetitions': repetitions, 'workflow_sha256': '1' * 64,
                  'prompt_contract_sha256': '2' * 64, 'coverage_sha256': '3' * 64,
                  'rubric_version': 'hunt-rubric-1', 'pricing_snapshot': {'as_of_utc': '2026-01-01T00:00:00Z'},
                  'budgets': {'max_calls_per_trial': 20, 'max_active_seconds_per_trial': 200,
                              'max_prompt_bytes': 10000, 'max_response_bytes': 10000,
                              'max_attempts_per_stage': 2}}
    snapshot = {'schema_version': 1, 'experiment': {'experiment': experiment, 'cases': []},
                'trials': [], 'calls': [], 'events': [], 'approvals': []}
    for index in range(families):
        case_id, scenario_id, family_id = 'case-' + str(index), 'scenario-' + str(index), 'family-' + str(index)
        case = {'scenario': {'scenario_id': scenario_id, 'family_id': family_id,
                             'evidence_manifest_sha256': str(index % 10) * 64,
                             'split': 'development', 'provenance': 'synthetic',
                             'coverage': {'os': ['linux'], 'network': ['flat-lan'],
                                          'identity_domain': ['workgroup-local'],
                                          'operational_domain': ['enterprise-it'], 'dns_domain': ['no-dns']},
                             'difficulty': {'band': 'D1'}, 'sophistication': {'band': 'S1'}},
                'evidence': {'case_id': case_id, 'assets': [{'os_family': 'linux'}], 'events': []}}
        snapshot['experiment']['cases'].append(case)
        for team in teams:
            for repetition in range(1, repetitions + 1):
                trial_id = '{}-{}-{}'.format(case_id, team['team_id'], repetition)
                trial = {'trial_id': trial_id, 'case_id': case_id, 'scenario_id': scenario_id,
                         'team_id': team['team_id'], 'repetition': repetition, 'status': 'completed',
                         'case_evidence_sha256': case['scenario']['evidence_manifest_sha256']}
                snapshot['trials'].append(trial)
                snapshot['calls'].append({'status': 'completed', 'spec': {
                    'trial_id': trial_id, 'stage_key': 'handoff', 'component': 'narrative',
                    'adapter_sha256': 'a' * 64, 'executable_sha256': 'b' * 64,
                    'executable_version': 'Python test', 'input_sha256': team['team_id'] * 64},
                    'receipt': {'identity_status': 'reported_match', 'elapsed_ms': 10,
                                'usage': {'input_tokens': 5, 'output_tokens': 3},
                                'cost': {'api_cost_usd': 0.01}, 'failure_reason': None}})
                score = {'schema_version': 1, 'rubric_version': 'hunt-rubric-1', 'variant': 'team_output',
                         'case_id': case_id, 'scenario_id': scenario_id, 'family_id': family_id,
                         'team_id': team['team_id'], 'repetition': repetition,
                         'output_sha256': 'c' * 64, 'truth_sha256': 'd' * 64,
                         'adjudication_sha256': 'e' * 64, 'truth_frozen': True, 'status': 'final',
                         'completed': True, 'trial_status': 'completed', 'adjudication': 'human',
                         'truth_attestation': 'human_attested', 'review_policy': 'auto_advance',
                         'metrics': metrics(1.0 if team['team_id'] == 'a' else 0.5),
                         'offline_time_to_first_supported_finding_ms': None, 'timing_limitations': []}
                snapshot['events'].append({'seq': len(snapshot['events']) + 1, 'kind': 'score_recorded',
                                           'trial_id': trial_id,
                                           'payload': {'output_sha256': score['output_sha256'], 'score': score}})
    return snapshot


def mechanize(score):
    """Turn an invented human-adjudicated score into a mechanical one."""
    f1 = score['metrics']['detection']['f1']
    score.update(adjudication='mechanical', status='mechanical', metrics=metrics(f1, 'mechanical'))


def scores(snapshot, team=None):
    return [event['payload']['score'] for event in snapshot['events'] if event['kind'] == 'score_recorded'
            and (team is None or event['payload']['score'].get('team_id') == team)]


def card(report, team='a'):
    return next(item for item in report['scorecards'] if item['team_id'] == team)


def comparison(report):
    return report['comparisons'][0]


class ComparisonTests(unittest.TestCase):
    def test_model_choice_and_rendered_prompts_are_treatments(self):
        report = build_comparison(fixture())
        self.assertEqual(report['status'], 'final')
        pair = comparison(report)
        self.assertEqual(pair['status'], 'comparable')
        self.assertEqual(pair['macro_f1_difference'], 0.5)
        self.assertEqual(pair['paired_differences'][0]['difference'], 0.5)
        self.assertEqual(card(report)['detection']['f1'], 1.0)
        self.assertIsNone(report['ranking'])

    def test_underpowered_repetitions_are_not_independent(self):
        report = build_comparison(fixture(families=2, repetitions=10))
        pair = comparison(report)
        self.assertEqual(pair['independent_families'], 2)
        self.assertEqual(len(pair['paired_differences']), 20)
        self.assertTrue(pair['underpowered'])
        self.assertEqual(pair['inference'], 'descriptive_underpowered')
        self.assertIsNone(pair['confidence_interval'])
        self.assertIsNone(pair['significant_direction'])

    def test_five_family_bootstrap_and_rank_are_real_and_repeatable(self):
        snapshot = fixture(families=5, repetitions=2)
        before = copy.deepcopy(snapshot)
        first = build_comparison(snapshot)
        self.assertEqual(first, build_comparison(snapshot))
        self.assertEqual(snapshot, before)
        json.dumps(first, allow_nan=False)
        pair = comparison(first)
        self.assertFalse(pair['underpowered'])
        self.assertEqual(pair['confidence_interval']['samples'], 2000)
        self.assertEqual(pair['confidence_interval']['seed'], 1729)
        self.assertEqual(pair['confidence_interval']['lower'], 0.5)
        self.assertEqual(pair['confidence_interval']['upper'], 0.5)
        self.assertEqual(pair['significant_direction'], 'left_higher')
        ranking = first['ranking'][0]
        self.assertEqual([item['team_id'] for item in ranking['entries']], ['a', 'b'])
        self.assertIn('failures', ranking['entries'][0])
        self.assertIn('measurements', ranking['entries'][0])
        self.assertIn('coverage', ranking['entries'][0])

    def test_nonconstant_cluster_interval_and_family_windows(self):
        snapshot = fixture(families=6, repetitions=3)
        for score in scores(snapshot, 'a'):
            score['metrics'] = metrics(0.0 if score['scenario_id'] in ('scenario-0', 'scenario-1') else 1.0)
        # Two different scenarios/windows are one independent campaign family.
        snapshot['experiment']['cases'][1]['scenario']['family_id'] = 'family-0'
        for score in scores(snapshot):
            if score['scenario_id'] == 'scenario-1':
                score['family_id'] = 'family-0'
        report = build_comparison(snapshot)
        interval = comparison(report)['confidence_interval']
        self.assertEqual(comparison(report)['independent_families'], 5)
        self.assertLess(interval['lower'], interval['upper'])
        self.assertLessEqual(interval['lower'], comparison(report)['macro_f1_difference'])
        self.assertGreaterEqual(interval['upper'], comparison(report)['macro_f1_difference'])
        self.assertIsNone(comparison(report)['significant_direction'])

    def test_macro_scenarios_not_large_log_or_repetition_weight(self):
        snapshot = fixture(families=2, repetitions=2)
        for score in scores(snapshot, 'a'):
            if score['scenario_id'] == 'scenario-0':
                score['metrics'] = metrics(0.0 if score['repetition'] == 1 else 1.0)
            else:
                score['metrics'] = metrics(1.0)
                score['metrics']['detection']['tp'] = 10000
                score['metrics']['detection']['eligible_steps'] = 10000
        report = build_comparison(snapshot)
        self.assertEqual(card(report)['detection']['f1'], 0.75)
        self.assertEqual(card(report)['metrics']['detection.f1']['defined_scenarios'], 2)
        self.assertEqual(card(report)['detection']['tp'], 20001)

    def test_latest_score_supersedes_without_duplication(self):
        snapshot = fixture()
        event = copy.deepcopy(snapshot['events'][0])
        event['seq'] = len(snapshot['events']) + 1
        event['payload']['score']['metrics'] = metrics(0.0)
        snapshot['events'].append(event)
        report = build_comparison(snapshot)
        self.assertEqual(report['recorded_scores'], 3)
        self.assertEqual(report['latest_recognized_scores'], 2)
        self.assertEqual(card(report)['detection']['f1'], 0.0)

    def test_pending_and_legacy_scores_have_no_invented_metrics(self):
        snapshot = fixture()
        snapshot['events'] = []
        pending = build_comparison(snapshot)
        self.assertEqual(pending['status'], 'pending')
        self.assertIsNone(card(pending)['detection']['f1'])
        snapshot['events'] = [{'seq': 1, 'trial_id': snapshot['trials'][0]['trial_id'],
                              'kind': 'score_recorded', 'payload': {'score': {'f1': 1.0}}}]
        report = build_comparison(snapshot)
        self.assertEqual(report['status'], 'provisional')
        self.assertEqual(report['unrecognized_score_events'], 1)
        self.assertIsNone(report['ranking'])
        self.assertEqual(card(report)['failures']['completion_unknown'], 1)

    def test_new_incomplete_envelope_does_not_reuse_older_score(self):
        snapshot = fixture()
        event = copy.deepcopy(snapshot['events'][0])
        event['seq'] = 100
        del event['payload']['score']['metrics']['detection']['f1']
        snapshot['events'].append(event)
        report = build_comparison(snapshot)
        self.assertEqual(report['status'], 'provisional')
        first = card(report)
        self.assertIsNone(first['detection']['f1'])
        self.assertIn('unrecognized_or_incomplete_score_envelope', first['null_reasons'])

    def test_all_benign_f1_and_calibration_abstentions_stay_null(self):
        snapshot = fixture()
        for score in scores(snapshot):
            detection = score['metrics']['detection']
            detection.update(tp=0, fp=0, fn=0, eligible_steps=0, precision=None, recall=None, f1=None)
            score['metrics']['calibration'].update(supplied=0, abstained=1, brier=None, decision_coverage=0.0)
        report = build_comparison(snapshot)
        self.assertIsNone(card(report)['detection']['f1'])
        self.assertIsNone(card(report)['metrics']['calibration.brier']['macro_mean'])
        self.assertEqual(card(report)['metrics']['calibration.abstained']['raw_total'], 1)
        self.assertIn('no_defined_detection_f1', comparison(report)['not_comparable_reasons'])

    def test_failed_positive_and_unknown_trial_remain_in_denominator(self):
        snapshot = fixture(repetitions=2)
        for score in scores(snapshot, 'a'):
            score.update(completed=False, trial_status='failed' if score['repetition'] == 1 else 'unknown',
                         output_sha256=None, metrics=metrics(0.0))
        report = build_comparison(snapshot)
        summary = card(report)
        self.assertEqual(summary['detection']['f1'], 0.0)
        self.assertEqual(summary['detection']['fn'], 2)
        self.assertEqual(summary['failures']['completion_rate'], 0.0)
        self.assertEqual(summary['failures']['completion_failure_rate'], 1.0)
        self.assertEqual(summary['failures']['failed'], 1)
        self.assertEqual(summary['failures']['unknown'], 1)
        self.assertEqual(summary['scheduled_trials'], 2)

    def test_missing_scheduled_trial_is_retained(self):
        snapshot = fixture(repetitions=2)
        missing_id = snapshot['trials'][-1]['trial_id']
        snapshot['trials'].pop()
        snapshot['events'] = [event for event in snapshot['events'] if event['trial_id'] != missing_id]
        report = build_comparison(snapshot)
        self.assertEqual(report['scheduled_trials'], 4)
        b = [item for item in report['scorecards'] if item['team_id'] == 'b']
        self.assertEqual(sum(item['scheduled_trials'] for item in b), 2)
        self.assertEqual(sum(item['scored_trials'] for item in b), 1)
        self.assertEqual(report['status'], 'provisional')
        self.assertIsNone(report['ranking'])

    def test_evidence_and_truth_mismatches_are_named(self):
        snapshot = fixture()
        snapshot['trials'][1]['case_evidence_sha256'] = 'f' * 64
        for score in scores(snapshot, 'b'):
            score['truth_sha256'] = 'f' * 64
        reasons = comparison(build_comparison(snapshot))['not_comparable_reasons']
        self.assertIn('fingerprint.evidence_sha256', reasons)
        self.assertIn('fingerprint.truth_sha256', reasons)

    def test_resource_limits_are_controls_and_runtime_facts_are_treatments(self):
        snapshot = fixture()
        team = snapshot['experiment']['experiment']['teams'][1]
        team['roles']['role-0']['max_output_tokens'] = 300
        team['runtime_facts']['concurrency'] = 2
        reasons = comparison(build_comparison(snapshot))['not_comparable_reasons']
        self.assertIn('fingerprint.role_limits', reasons)
        self.assertNotIn('fingerprint.runtime_facts', reasons)

    def test_local_hardware_differences_stay_visible_and_rankable(self):
        snapshot = fixture(families=5)
        snapshot['experiment']['experiment']['teams'][1]['runtime_facts']['gpu'] = 'other-gpu'
        report = build_comparison(snapshot)
        self.assertEqual(comparison(report)['status'], 'comparable')
        self.assertEqual(card(report, 'b')['reported_treatment']['runtime_facts']['gpu'], 'other-gpu')
        self.assertNotIn('runtime_facts', card(report, 'b')['controls'])
        ranking = report['ranking'][0]
        self.assertEqual([item['team_id'] for item in ranking['entries']], ['a', 'b'])

    def test_structured_output_is_a_visible_treatment_not_a_control(self):
        snapshot = fixture(families=5)
        roles = snapshot['experiment']['experiment']['teams'][1]['roles']
        for role in ('role-0', 'role-3'):
            roles[role]['parameters']['structured_output'] = True
        report = build_comparison(snapshot)
        self.assertEqual(comparison(report)['status'], 'comparable')
        self.assertEqual(card(report, 'b')['reported_treatment']['structured_output_roles'], ['role-0', 'role-3'])
        self.assertEqual(card(report, 'a')['reported_treatment']['structured_output_roles'], [])
        self.assertNotIn('structured_output_roles', card(report, 'b')['controls'])

    def test_local_pair_requires_disclosed_runtime_facts(self):
        snapshot = fixture(families=5)
        snapshot['experiment']['experiment']['teams'][1]['runtime_facts']['server'] = None
        report = build_comparison(snapshot)
        self.assertIn('runtime_facts_unknown', comparison(report)['not_comparable_reasons'])
        self.assertIsNone(report['ranking'])

    def test_cloud_local_and_hybrid_teams_rank_with_null_cloud_runtime_facts(self):
        snapshot = fixture(families=5)
        teams = snapshot['experiment']['experiment']['teams']
        teams[1]['deployment'] = 'cloud'
        teams[1]['runtime_facts'] = {key: None for key in teams[1]['runtime_facts']}
        hybrid = copy.deepcopy(teams[1])
        hybrid.update(team_id='c', deployment='hybrid')
        teams.append(hybrid)
        for trial in [item for item in snapshot['trials'] if item['team_id'] == 'b']:
            trial_id = trial['trial_id'].replace('-b-', '-c-')
            snapshot['trials'].append(dict(trial, trial_id=trial_id, team_id='c'))
            call = copy.deepcopy(next(item for item in snapshot['calls']
                                      if item['spec']['trial_id'] == trial['trial_id']))
            call['spec']['trial_id'] = trial_id
            snapshot['calls'].append(call)
        for event in [item for item in snapshot['events'] if item['payload']['score']['team_id'] == 'b']:
            copied = copy.deepcopy(event)
            copied.update(seq=len(snapshot['events']) + 1, trial_id=event['trial_id'].replace('-b-', '-c-'))
            copied['payload']['score'].update(team_id='c', metrics=metrics(0.0))
            snapshot['events'].append(copied)
        report = build_comparison(snapshot)
        self.assertEqual({item['status'] for item in report['comparisons']}, {'comparable'})
        ranking = report['ranking'][0]
        self.assertEqual([item['team_id'] for item in ranking['entries']], ['a', 'b', 'c'])
        self.assertEqual(card(report, 'c')['reported_treatment']['deployment'], 'hybrid')

    def test_attack_free_scenario_alarm_does_not_block_pairing(self):
        snapshot = fixture(families=6)
        for score in scores(snapshot):
            if score['scenario_id'] != 'scenario-5':
                continue
            alarm = score['team_id'] == 'b'
            detection = score['metrics']['detection']
            detection.update(tp=0, fp=int(alarm), fn=0, eligible_steps=0, precision=0.0 if alarm else None,
                             recall=None, f1=0.0 if alarm else None)
            score['metrics']['controls']['benign'].update(eligible=1, evaluated=1, false_alarms=int(alarm),
                                                          false_alarm_rate=float(alarm))
        report = build_comparison(snapshot)
        pair = comparison(report)
        self.assertEqual(pair['status'], 'comparable')
        self.assertNotIn('asymmetric_undefined_detection_f1', pair['not_comparable_reasons'])
        excluded = [item for item in pair['paired_differences'] if item['scenario_id'] == 'scenario-5']
        self.assertEqual(excluded[0]['excluded'], 'no_eligible_steps')
        self.assertEqual(pair['independent_families'], 5)
        self.assertEqual(card(report, 'b')['detection']['f1'], 0.5)
        self.assertEqual(card(report, 'b')['detection']['benign_control_false_alarms'], 1)
        self.assertEqual(card(report, 'b')['detection']['fp'], 6)
        self.assertEqual(card(report, 'b')['attack_free_scenario_ids'], ['scenario-5'])
        self.assertIsNotNone(report['ranking'])

    def test_mechanical_and_human_cohorts_are_never_comparable(self):
        snapshot = fixture(families=5)
        for score in scores(snapshot, 'b'):
            mechanize(score)
        report = build_comparison(snapshot)
        pair = comparison(report)
        self.assertEqual(pair['status'], 'not_comparable')
        self.assertIn('fingerprint.adjudication', pair['not_comparable_reasons'])
        self.assertEqual((card(report)['status'], card(report, 'b')['status']), ('final', 'mechanical'))
        self.assertEqual(report['adjudication'], ['human', 'mechanical'])
        self.assertEqual(report['status'], 'provisional')
        self.assertIsNone(report['ranking'])

    def test_mechanical_cohort_ranks_only_among_mechanical_and_is_never_final(self):
        snapshot = fixture(families=5)
        for score in scores(snapshot):
            mechanize(score)
        report = build_comparison(snapshot)
        self.assertEqual(report['status'], 'mechanical')
        self.assertEqual({item['status'] for item in report['scorecards']}, {'mechanical'})
        self.assertEqual(comparison(report)['status'], 'comparable')
        ranking = report['ranking'][0]
        self.assertEqual((ranking['status'], ranking['adjudication'], ranking['review_policy']),
                         ('mechanical', 'mechanical', 'auto_advance'))
        self.assertEqual([item['team_id'] for item in ranking['entries']], ['a', 'b'])

    def test_mechanical_score_claiming_final_is_unrecognized(self):
        snapshot = fixture()
        mechanize(scores(snapshot, 'a')[0])
        scores(snapshot, 'a')[0]['status'] = 'final'
        report = build_comparison(snapshot)
        self.assertIn('unrecognized_or_incomplete_score_envelope', card(report)['null_reasons'])
        self.assertEqual(report['status'], 'provisional')

    def test_truth_attestation_and_timing_contention_are_cohort_controls(self):
        snapshot = fixture(families=5)
        for score in scores(snapshot, 'b'):
            score['truth_attestation'] = 'unreviewed_proposal'
        report = build_comparison(snapshot)
        self.assertIn('fingerprint.truth_attestation', comparison(report)['not_comparable_reasons'])
        self.assertEqual(report['truth_attestation'], ['human_attested', 'unreviewed_proposal'])
        self.assertIsNone(report['ranking'])
        # The default of four concurrent calls contends; one call at a time does not.
        self.assertTrue(report['timing_contended'])
        self.assertTrue(card(report)['controls']['timing_contended'])
        snapshot['experiment']['experiment']['budgets']['max_concurrent_calls'] = 1
        self.assertFalse(card(build_comparison(snapshot))['controls']['timing_contended'])

    def test_agent_consensus_truth_is_its_own_named_cohort(self):
        snapshot = fixture(families=5)
        for score in scores(snapshot, 'b'):
            score['truth_attestation'] = 'agent_consensus'
        report = build_comparison(snapshot)
        self.assertIn('fingerprint.truth_attestation', comparison(report)['not_comparable_reasons'])
        self.assertEqual(report['truth_attestation'], ['agent_consensus', 'human_attested'])
        self.assertIsNone(report['ranking'])
        text = ' '.join(report['limitations'])
        self.assertIn('agent_consensus is two independent AI drafts merged mechanically', text)
        self.assertIn('unreviewed_proposal is an unreviewed proposed answer key', text)

    def test_identity_failure_cannot_be_removed_to_rank_success_subset(self):
        snapshot = fixture(families=5)
        snapshot['calls'][0]['receipt']['identity_status'] = 'unreported'
        report = build_comparison(snapshot)
        self.assertEqual(card(report)['controls']['identity'], 'unreported')
        self.assertEqual(card(report)['scheduled_trials'], 5)
        self.assertIn('identity_unverified', comparison(report)['not_comparable_reasons'])
        self.assertIsNone(report['ranking'])

    def failed_call(self, snapshot, team='b', reason='invalid_response', identity='unreported', model=None):
        call = copy.deepcopy(next(item for item in snapshot['calls']
                                  if item['spec']['trial_id'].split('-')[2] == team))
        call['status'] = 'failed'
        call['receipt'].update(identity_status=identity, model_returned=model, failure_reason=reason)
        snapshot['calls'].append(call)
        return call

    def test_failed_call_without_reported_model_keeps_team_rankable(self):
        snapshot = fixture(families=5)
        self.failed_call(snapshot)
        report = build_comparison(snapshot)
        self.assertEqual(card(report, 'b')['controls']['identity'], 'reported_match')
        self.assertEqual(comparison(report)['status'], 'comparable')
        self.assertEqual(card(report, 'b')['failures']['format_error'], 1)
        self.assertIsNotNone(report['ranking'])

    def test_reported_mismatch_on_failed_call_still_blocks(self):
        snapshot = fixture(families=5)
        self.failed_call(snapshot, reason='model_identity_mismatch', identity='reported_mismatch',
                         model='other-model')
        report = build_comparison(snapshot)
        self.assertEqual(card(report, 'b')['controls']['identity'], 'reported_mismatch')
        self.assertIn('identity_unverified', comparison(report)['not_comparable_reasons'])
        self.assertIsNone(report['ranking'])

    def test_truncation_is_format_error_and_blocked_terminated_are_failed(self):
        snapshot = fixture(repetitions=3)
        self.failed_call(snapshot, team='a', reason='output_limit')
        for score in scores(snapshot, 'a'):
            if score['repetition'] > 1:
                score.update(completed=False, output_sha256=None, metrics=metrics(0.0),
                             trial_status='blocked' if score['repetition'] == 2 else 'terminated')
        result = card(build_comparison(snapshot))
        self.assertEqual(result['failures']['format_error'], 1)
        self.assertEqual(result['failures']['failed'], 2)
        self.assertEqual(result['failures']['completion_failure_rate'], 2 / 3)

    def test_mixed_runtime_versions_and_unsettled_scores_block_ranking(self):
        snapshot = fixture(families=5)
        snapshot['calls'][0]['spec']['executable_version'] = 'different'
        scores(snapshot, 'a')[0].update(truth_frozen=False, status='provisional')
        report = build_comparison(snapshot)
        self.assertIn('runtime_versions_mixed', report['not_comparable_reasons'])
        self.assertIn('scores_not_settled', report['not_comparable_reasons'])
        self.assertIn('fingerprint.truth_frozen', report['not_comparable_reasons'])
        self.assertIsNone(report['ranking'])

    def test_genuine_detector_fields_split_cohorts(self):
        snapshot = fixture(families=2)
        snapshot['experiment']['cases'][0]['evidence']['events'] = [{'fields': {'detector_attack_ids': ['T1000']}}]
        report = build_comparison(snapshot)
        a = [item for item in report['scorecards'] if item['team_id'] == 'a']
        self.assertEqual({item['controls']['detector_condition'] for item in a}, {'raw_telemetry', 'with_detector_alerts'})
        self.assertEqual(sum(item['scheduled_trials'] for item in a), 2)

    def test_provenance_and_holdout_are_separate(self):
        snapshot = fixture(families=2)
        snapshot['experiment']['cases'][1]['scenario'].update(split='holdout', provenance='derived_replay')
        report = build_comparison(snapshot)
        a = [item for item in report['scorecards'] if item['team_id'] == 'a']
        self.assertEqual({(item['controls']['split'], item['controls']['provenance']) for item in a},
                         {('development', 'synthetic'), ('holdout', 'derived_replay')})

    def test_cloud_os_is_not_inflated_by_scenario_tag(self):
        snapshot = fixture()
        case = snapshot['experiment']['cases'][0]
        case['evidence']['assets'][0]['os_family'] = 'not-applicable'
        case['scenario']['coverage']['os'] = ['windows-server', 'linux']
        report = build_comparison(snapshot)
        self.assertEqual(card(report)['coverage']['os'], ['not-applicable'])
        self.assertEqual({item['category'] for item in report['slices'] if item['axis'] == 'os'}, {'not-applicable'})
        self.assertIn('scenario_os_differs_from_public_assets', report['not_comparable_reasons'])

    def test_usage_unknowns_and_checker_cost_are_not_fabricated(self):
        snapshot = fixture()
        checker = copy.deepcopy(snapshot['calls'][0])
        checker['spec']['component'] = 'evidence_checker'
        checker['receipt']['cost']['api_cost_usd'] = None
        checker['receipt']['usage'] = {}
        snapshot['calls'].append(checker)
        measurements = card(build_comparison(snapshot))['measurements']
        self.assertEqual(measurements['evidence_checker_calls'], 1)
        self.assertEqual(measurements['model_active_ms']['total'], 20)
        self.assertEqual(measurements['api_cost_usd']['known_subtotal'], 0.01)
        self.assertIsNone(measurements['api_cost_usd']['total'])
        self.assertIsNone(measurements['provider_reported_usage']['input_tokens']['total'])
        self.assertEqual(measurements['provider_reported_usage']['input_tokens']['unknown_count'], 1)

    def test_missing_citation_blocks_rank_without_erasing_false_positives(self):
        snapshot = fixture(families=5)
        for score in scores(snapshot, 'a'):
            score['metrics'] = metrics(0.5)
            score['metrics']['ranking_eligible'] = False
            score['metrics']['ranking_blockers'] = ['missing_model_citation']
        report = build_comparison(snapshot)
        self.assertEqual(report['status'], 'final')
        self.assertEqual(card(report)['detection']['fp'], 5)
        self.assertEqual(card(report)['detection']['f1'], 0.5)
        self.assertIn('missing_model_citation', report['not_comparable_reasons'])
        self.assertIsNone(report['ranking'])

    def test_unscored_trial_does_not_create_rankable_success_subset(self):
        snapshot = fixture(families=6)
        snapshot['events'] = [event for event in snapshot['events']
                              if event['payload']['score']['scenario_id'] != 'scenario-5']
        report = build_comparison(snapshot)
        self.assertIn('team_schedule_incomplete', report['not_comparable_reasons'])
        self.assertIsNone(report['ranking'])
        self.assertEqual(sum(item['scheduled_trials'] for item in report['scorecards']
                             if item['team_id'] == 'a'), 6)

    def test_format_and_timeout_counts_use_actual_receipts(self):
        snapshot = fixture(repetitions=2)
        snapshot['calls'][0]['receipt']['failure_reason'] = 'invalid_response'
        snapshot['calls'][1]['receipt']['failure_reason'] = 'timeout'
        snapshot['calls'][1]['status'] = 'unknown'
        result = card(build_comparison(snapshot))
        self.assertEqual(result['failures']['format_error'], 1)
        self.assertEqual(result['failures']['timeout'], 1)
        self.assertEqual(result['failures']['unknown'], 1)
        self.assertNotIn('rejected_stages', result)
        self.assertEqual(result['measurements']['scope'], 'whole_trial_lifetime_including_retries_and_checker')

    def test_empty_metric_sections_are_not_complete_scores(self):
        snapshot = fixture()
        scores(snapshot, 'a')[0]['metrics']['calibration'] = {}
        report = build_comparison(snapshot)
        self.assertEqual(report['status'], 'provisional')
        self.assertIsNone(card(report)['detection']['f1'])


if __name__ == '__main__':
    unittest.main()

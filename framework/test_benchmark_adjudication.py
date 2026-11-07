"""Disposable synthetic ledger/verdict fixtures, never model-quality evidence."""
import copy
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing, redirect_stdout
import io
from pathlib import Path
import threading
from unittest import mock

import bot
from benchmark_adjudication import adjudication_template, load_truths, score_experiment
from benchmark_contracts import AUTO_FREEZE_ACTOR, FREEZE_POLICY
from benchmark_contracts import canonical_bytes, decode_json, digest_bytes, load_json
from benchmark_decisions import ledger_snapshot, WORKFLOW_ACCEPTANCE, WORKFLOW_SCOPE, WORKFLOW_TITLE
from benchmark_store import BenchmarkStore
from test_benchmark_decisions import _StageFixture, TEST_ACTOR, TEST_NOTE
from test_benchmark_runner import (
    FIXTURES, authorize_fixture, call_fixture, receipt_fixture, response_fixture, trial_fixture,
)


EARLY_STAGES = ('scope', 'endpoint_evidence', 'network_evidence', 'hypotheses', 'analysis', 'review')


class _AdjudicationFixture(_StageFixture):
    """Shared disposable workflow/truth/verdict helpers; defines no tests."""

    def setUp(self):
        super().setUp()
        self.truth_root = Path(self.temp.name) / 'truth-source'
        self.truth_path = self.truth_root / self.trial['case_id'] / 'evaluator' / 'truth.json'
        self.truth_path.parent.mkdir(parents=True)
        self.truth = load_json(FIXTURES / 'fixtures' / self.trial['case_id'] / 'evaluator' / 'truth.json')
        second = copy.deepcopy(self.truth['steps'][0])
        second.update(step_id='step-b', technique_id='T1059.001')
        self.truth['steps'].append(second)
        self.write_truth()
        # Fixture public IDs are opaque; cite the whole first support set.
        self.event_ids = sorted(self.truth['steps'][0]['support_sets'][0])
        self.adjudication = Path(self.temp.name) / 'human-fixture.json'

    def write_truth(self):
        self.truth_path.write_bytes(canonical_bytes(self.truth))

    def freeze(self, store=None):
        """The automatic init freeze of this test's custom truth, before any reservation."""
        return (store or self.store).freeze_truths(
            self.eid, {self.trial['case_id']: self.truth_path.read_bytes()})

    def oracle(self):
        output = response_fixture('handoff')
        step = self.truth['steps'][0]
        output['findings'] = [
            {'finding_id': 'finding-supported', 'asset_id': step['asset_id'],
             'technique_id': step['technique_id'], 'window_utc': copy.deepcopy(step['window_utc']),
             'disposition': 'suspicious', 'confidence': 0.8, 'event_ids': list(self.event_ids),
             'rationale': 'Synthetic rubric oracle: supported test assertion.'},
            {'finding_id': 'finding-unsupported', 'asset_id': step['asset_id'],
             'technique_id': 'T9999', 'window_utc': copy.deepcopy(step['window_utc']),
             'disposition': 'suspicious', 'confidence': 0.7, 'event_ids': list(self.event_ids),
             'rationale': 'Synthetic rubric oracle: unsupported test assertion.'},
        ]
        output['assessment_answers'] = [
            {'question_id': question['question_id'], 'probability_suspicious': None}
            for question in self.frozen['cases'][0]['evidence']['assessment_questions']]
        return output

    def workflow(self, advance_handoff=True, output=None):
        for stage in EARLY_STAGES:
            self.submit(stage=stage)
            self.advance_stage(stage)
        receipt = self.submit(stage='handoff', output=self.oracle() if output is None else output)
        if advance_handoff:
            self.advance_stage('handoff')
        return receipt

    def template(self, path=None, judge=True):
        path = path or self.adjudication
        adjudication_template(self.root, self.eid, path)
        document = decode_json(path.read_bytes())
        if judge:
            for output in document['outputs']:
                for item in output['items']:
                    document['verdicts'].append({
                        'trial_id': output['trial_id'], 'output_sha256': output['output_sha256'],
                        'item_kind': item['item_kind'], 'item_id': item['item_id'],
                        'verdict': 'insufficient' if item['item_id'] == 'finding-unsupported' else 'supported',
                        'event_ids': list(self.event_ids), 'by': TEST_ACTOR, 'note': TEST_NOTE,
                    })
            path.write_bytes(canonical_bytes(document))
        return document

    def score(self, human=False):
        return score_experiment(self.root, self.eid, self.truth_root, self.adjudication if human else None)

    def scores(self):
        return [event['payload']['score'] for event in self.benchmark_events('score_recorded')]


class BenchmarkAdjudicationTests(_AdjudicationFixture):
    def test_freeze_is_automatic_private_immutable_and_pre_reservation(self):
        result = self.freeze()
        self.assertEqual(self.freeze()['event_id'], result['event_id'])
        event = next(event for event in self.benchmark_events('evidence_sealed')
                     if event['payload'].get('record_type') == 'truth_frozen')
        record = event['payload']['cases'][0]
        self.assertEqual((event['actor'], event['payload']['by'], event['payload']['freeze_policy']),
                         (AUTO_FREEZE_ACTOR, AUTO_FREEZE_ACTOR, FREEZE_POLICY))
        self.assertNotIn('steps', event['payload'])
        self.assertNotIn('support_sets', event['payload'])
        self.assertNotIn('trials/', record['private_path'])
        self.assertEqual((self.root / record['private_path']).read_bytes(), self.truth_path.read_bytes())
        self.truth['truth_revision'] += 1
        self.write_truth()
        self.assert_code('fingerprint_conflict', self.freeze)
        self.assertEqual(len([event for event in self.benchmark_events('evidence_sealed')
                              if event['payload'].get('record_type') == 'truth_frozen']), 1)

    def test_reservation_prevents_posthoc_freeze(self):
        self.reserve()
        self.assert_code('truth_freeze_too_late', self.freeze)
        self.assertFalse((self.root / 'evaluator').exists())

    def test_reservation_and_freeze_share_atomic_order(self):
        barrier = threading.Barrier(2)
        spec = call_fixture(self.store, self.frozen, self.trial, self.authorization)
        truths = {self.trial['case_id']: self.truth_path.read_bytes()}

        def freeze_or_reserve(freezing):
            store = BenchmarkStore(self.root)
            barrier.wait()
            if freezing:
                try:
                    return store.freeze_truths(self.eid, truths)['seq']
                except Exception as exc:
                    return getattr(exc, 'code', type(exc).__name__)
            store.reserve_call('race-call', digest_bytes(canonical_bytes(spec)), spec)
            return 'reserved'

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(freeze_or_reserve, (True, False)))
        self.assertEqual(results[1], 'reserved')
        events = self.benchmark_events()
        frozen = [event for event in events if event['payload'].get('record_type') == 'truth_frozen']
        reserved = next(event for event in events if event['kind'] == 'dispatch_reserved')
        if frozen:
            self.assertLess(frozen[0]['seq'], reserved['seq'])
        else:
            self.assertEqual(results[0], 'truth_freeze_too_late')

    def test_mechanical_oracle_is_default_and_never_final(self):
        invisible = copy.deepcopy(self.truth['steps'][0])
        invisible.update(step_id='step-invisible', observability='absent', support_sets=[])
        self.truth['steps'].append(invisible)
        self.write_truth()
        self.freeze()
        receipt = self.workflow()
        before = len(self.store.calls(trial_id=self.tid))
        report = self.score()
        self.assertEqual((report['status'], report['adjudication']), ('mechanical', 'mechanical'))
        self.assertEqual((report['recorded_scores'], report['variant']), (1, 'team_output'))
        self.assertIn('mechanical_adjudication_not_human_verdicts', report['limitations'])
        self.assertNotIn('truth_not_frozen_before_answers', report['limitations'])
        self.assertTrue(report['truth_frozen'])
        self.assertEqual(len(self.store.calls(trial_id=self.tid)), before)
        score, = self.scores()
        self.assertEqual(score['output_sha256'], receipt['response_sha256'])
        self.assertEqual((score['status'], score['adjudication'], score['review_policy']),
                         ('mechanical', 'mechanical', 'auto_advance'))
        self.assertEqual((score['trial_status'], score['truth_attestation']), ('completed', 'human_attested'))
        self.assertTrue(score['completed'])
        self.assertNotIn('assisted', score)
        detection = score['metrics']['detection']
        self.assertEqual(detection['visibility_limited_steps'], 1)
        self.assertEqual((detection['tp'], detection['fp'], detection['fn']), (1, 1, 1))
        self.assertEqual((detection['precision'], detection['recall'], detection['f1']), (0.5, 0.5, 0.5))
        self.assertEqual(score['metrics']['claims']['semantic_support'], 'not_measured_mechanical')
        private = decode_json((self.root / 'evaluator' / 'adjudication' /
                               (score['adjudication_sha256'] + '.json')).read_bytes())
        self.assertEqual((private['adjudication'], private['rules']), ('mechanical', 'mechanical-rules-1'))
        self.assertNotIn('verdicts', private)
        self.store.snapshot(self.eid)
        # A mechanical score can never be recorded as final.
        forged = dict(score, status='final')
        self.assert_code('scope_mismatch', self.store.record_score, self.tid,
                         score['output_sha256'], forged, 'benchmark-scorer')

    def test_auto_advance_is_never_an_approval(self):
        self.workflow()
        kinds = {event['kind'] for event in self.events()}
        self.assertIn('auto_advance', kinds)
        self.assertNotIn('approve', kinds)
        self.assertEqual(self.benchmark_events('human_decision_observed'), [])
        self.assertEqual(len(self.benchmark_events('stage_auto_advanced')), 7)

    def test_human_adjudication_is_a_separate_final_cohort(self):
        self.freeze()
        self.workflow()
        self.template()
        report = self.score(human=True)
        self.assertEqual((report['status'], report['adjudication']), ('final', 'human'))
        score, = self.scores()
        self.assertEqual((score['status'], score['adjudication']), ('final', 'human'))
        detection = score['metrics']['detection']
        self.assertEqual((detection['tp'], detection['fp'], detection['fn']), (1, 1, 1))
        self.assertNotIn('semantic_support', score['metrics']['claims'])
        self.assertNotEqual(score['metrics']['claims']['null_reasons'].get('support_rate'),
                            'not_measured_mechanical')

    def test_unfrozen_truth_never_settles(self):
        self.workflow()
        self.assert_code('truth_freeze_too_late', self.freeze)
        report = self.score()
        self.assertFalse(report['truth_frozen'])
        self.assertEqual(report['status'], 'provisional')
        self.assertIn('truth_not_frozen_before_answers', report['limitations'])
        score, = self.scores()
        self.assertEqual((score['status'], score['truth_frozen']), ('provisional', False))

    def test_unreviewed_proposal_truth_is_scored_and_labelled(self):
        self.truth['attestation'] = 'unreviewed_proposal'
        self.write_truth()
        self.freeze()
        self.workflow()
        report = self.score()
        self.assertEqual(report['status'], 'mechanical')
        self.assertEqual(report['truth_attestation'], ['unreviewed_proposal'])
        self.assertIn('truth_unreviewed_proposal', report['limitations'])
        self.assertNotIn('truth_agent_consensus', report['limitations'])
        self.assertEqual(self.scores()[0]['truth_attestation'], 'unreviewed_proposal')

    def test_agent_consensus_truth_is_labelled_as_consensus(self):
        self.truth['attestation'] = 'agent_consensus'
        self.write_truth()
        self.freeze()
        self.workflow()
        report = self.score()
        self.assertEqual(report['truth_attestation'], ['agent_consensus'])
        self.assertIn('truth_agent_consensus', report['limitations'])
        self.assertNotIn('truth_unreviewed_proposal', report['limitations'])
        self.assertEqual(self.scores()[0]['truth_attestation'], 'agent_consensus')

    def test_human_attested_truth_has_no_truth_limitation(self):
        self.freeze()
        self.workflow()
        report = self.score()
        self.assertEqual(report['truth_attestation'], ['human_attested'])
        self.assertEqual([item for item in report['limitations'] if item.startswith('truth_')], [])

    def test_unadvanced_handoff_is_not_team_output(self):
        self.freeze()
        handoff = self.workflow(advance_handoff=False)
        self.assertEqual(self.score()['status'], 'provisional')
        score, = self.scores()
        self.assertIsNone(score['output_sha256'])
        self.assertFalse(score['completed'])
        self.assertEqual(score['trial_status'], 'review')
        self.assertEqual(score['metrics']['detection']['fn'], 2)
        self.assertNotEqual(handoff['response_sha256'], score['output_sha256'])
        self.assertEqual(ledger_snapshot(self.store, self.trial)['tasks']['handoff']['status'], 'review')

    def test_without_prior_freeze_human_quality_remains_provisional(self):
        self.workflow()
        self.template()
        result = self.score(human=True)
        self.assertFalse(result['truth_frozen'])
        self.assertEqual(result['status'], 'provisional')
        self.assertTrue(all(item['status'] == 'provisional' for item in self.scores()))

    def test_missing_human_adjudication_never_becomes_final(self):
        self.freeze()
        self.workflow()
        self.template(judge=False)
        self.assertEqual(self.score(human=True)['status'], 'provisional')
        self.assertTrue(self.scores()[0]['metrics']['missing_adjudications'])

    def test_all_pending_trials_get_honest_null_outputs(self):
        self.freeze()
        report = self.score()
        self.assertEqual((report['scheduled_trials'], report['recorded_scores']), (1, 1))
        self.assertEqual(report['status'], 'provisional')
        score, = self.scores()
        self.assertIsNone(score['output_sha256'])
        self.assertIsNone(score['offline_time_to_first_supported_finding_ms'])
        self.assertFalse(score['completed'])
        self.assertEqual(score['metrics']['detection']['fn'], 2)
        self.assertEqual(score['metrics']['detection']['f1'], 0)

    def test_terminal_failed_trial_is_zero_not_successful_benign(self):
        self.freeze()
        call_id, spec = self.reserve()
        failed = receipt_fixture(self.store, self.frozen, call_id, spec, 'failed')
        self.store.finish_call(call_id, failed)
        self.store.update_trial(self.tid, dict(self.trial, status='failed'), 'failed')
        self.assertEqual(self.score()['status'], 'mechanical')
        score, = self.scores()
        self.assertFalse(score['completed'])
        self.assertIsNone(score['output_sha256'])
        self.assertEqual(score['metrics']['detection']['f1'], 0)
        self.assertEqual(score['metrics']['controls']['benign']['evaluated'], 0)

    def test_terminated_trial_with_unadvanced_handoff_is_terminal_failure(self):
        self.freeze()
        self.workflow(advance_handoff=False)
        self.store.terminate_trial(self.tid, 'budget_exhausted', TEST_ACTOR, TEST_NOTE)
        self.assertEqual(self.score()['status'], 'mechanical')
        score, = self.scores()
        self.assertEqual((score['trial_status'], score['status']), ('terminated', 'mechanical'))
        self.assertFalse(score['completed'])
        self.assertIsNone(score['output_sha256'])
        self.assertEqual(score['metrics']['detection']['f1'], 0)

    def test_template_is_blind_new_only_and_does_not_read_truth(self):
        self.freeze()
        self.submit()
        event = next(event for event in self.benchmark_events('evidence_sealed')
                     if event['payload'].get('record_type') == 'truth_frozen')
        private_path = self.root / event['payload']['cases'][0]['private_path']
        private_path.write_bytes(b'changed-private-truth')
        document = self.template()
        self.assertEqual(len(document['outputs']), 1)
        self.assertEqual(set(document), {'schema_version', 'rubric_version', 'outputs', 'verdicts'})
        for item in document['outputs']:
            self.assertNotIn('team_id', item)
            self.assertNotIn('model_requested', item)
            self.assertNotIn('checker', item)
            self.assertEqual(item['blinding']['status'], 'not_guaranteed')
        self.assert_code('already_exists', adjudication_template, self.root, self.eid, self.adjudication)
        self.assert_code('artifact_corrupt', self.score)
        self.assert_code('artifact_corrupt', self.store.snapshot, self.eid)

    def test_self_identification_is_flagged_without_rewriting(self):
        output = response_fixture()
        identity = next(iter(self.frozen['experiment']['teams'][0]['roles'].values()))['model_requested']
        output['summary'] = 'Synthetic output identifies itself as ' + identity
        receipt = self.submit(output=output)
        document = self.template()
        item = document['outputs'][0]
        self.assertEqual(item['output'], output)
        self.assertEqual(item['output_sha256'], receipt['response_sha256'])
        self.assertEqual(item['blinding']['status'], 'compromised')

    def test_changed_source_truth_rejects_without_score_events(self):
        self.freeze()
        self.truth['truth_revision'] += 1
        self.write_truth()
        self.assert_code('fingerprint_conflict', self.score)
        self.assertEqual(self.scores(), [])

    def test_changed_artifact_aborts_before_truth_source_is_opened(self):
        receipt = self.submit()
        (self.root / 'trials' / self.tid / receipt['response_artifact']['path']).write_bytes(b'changed')
        with mock.patch('benchmark_adjudication.load_truths', side_effect=AssertionError('truth opened early')):
            self.assert_code('artifact_corrupt', self.score)
        self.assertEqual(self.scores(), [])

    def test_changed_ledger_stdout_aborts_before_truth_source_is_opened(self):
        self.submit()
        artifact = next(item for item in ledger_snapshot(self.store, self.trial)['artifacts']
                        if item['description'] == 'CLI stdout')
        Path(artifact['path']).write_bytes(b'changed')
        with mock.patch('benchmark_adjudication.load_truths', side_effect=AssertionError('truth opened early')):
            self.assert_code('unsealed_output', self.score)

    def test_stale_human_template_rejects_new_submission(self):
        self.submit()
        self.template()
        self.advance_stage('scope')
        self.submit(stage='endpoint_evidence')
        self.assert_code('stale_adjudication', self.score, human=True)

    def test_wrong_verdict_hash_and_model_judge_reject(self):
        output = response_fixture()
        output['claims'] = [{'claim_id': 'claim-a', 'kind': 'observation',
                             'text': 'Synthetic human verdict binding fixture.', 'event_ids': list(self.event_ids)}]
        self.submit(output=output)
        document = self.template()
        original = copy.deepcopy(document)
        document['verdicts'][0]['output_sha256'] = 'f' * 64
        self.adjudication.write_bytes(canonical_bytes(document))
        self.assert_code('scope_mismatch', self.score, human=True)
        document = copy.deepcopy(original)
        document['verdicts'][0]['by'] = next(iter(self.frozen['experiment']['teams'][0]['roles'].values()))['model_requested']
        self.adjudication.write_bytes(canonical_bytes(document))
        self.assert_code('human_adjudication_required', self.score, human=True)
        self.assertEqual(self.scores(), [])

    def test_wrong_rubric_and_duplicate_verdict_reject(self):
        output = response_fixture()
        output['claims'] = [{'claim_id': 'claim-a', 'kind': 'observation',
                             'text': 'Synthetic exact rubric fixture.', 'event_ids': list(self.event_ids)}]
        self.submit(output=output)
        document = self.template()
        original = copy.deepcopy(document)
        document['rubric_version'] = 'changed-rubric'
        self.adjudication.write_bytes(canonical_bytes(document))
        self.assert_code('scope_mismatch', self.score, human=True)
        original['verdicts'].append(copy.deepcopy(original['verdicts'][0]))
        self.adjudication.write_bytes(canonical_bytes(original))
        from benchmark_contracts import BenchmarkError
        with self.assertRaises(BenchmarkError):
            self.score(human=True)
        self.assertEqual(self.scores(), [])

    def test_fake_nonnull_output_and_false_completed_flag_reject(self):
        self.freeze()
        self.score()
        score = copy.deepcopy(self.scores()[0])
        score['output_sha256'] = 'f' * 64
        score['completed'] = True
        self.assert_code('unsealed_output', self.store.record_score, self.tid, 'f' * 64, score, 'benchmark-scorer')
        score['output_sha256'] = None
        self.assert_code('scope_mismatch', self.store.record_score, self.tid, None, score, 'benchmark-scorer')

    def test_direct_ledger_approval_is_a_manual_action_never_team_output(self):
        self.freeze()
        self.submit()
        self.cli('approve', self.trial['task_mapping']['scope'], '--by', TEST_ACTOR, '--note', TEST_NOTE)
        self.assertEqual(self.score()['status'], 'provisional')
        self.assertTrue(all(score['trial_status'] == 'manual_ledger_decision' for score in self.scores()))
        self.assertEqual(self.benchmark_events('human_decision_observed'), [])

    def test_empty_or_wrong_truth_layout_does_not_search_elsewhere(self):
        wrong = Path(self.temp.name) / 'wrong-layout'
        wrong.mkdir()
        (wrong / 'truth.json').write_bytes(canonical_bytes(self.truth))
        from benchmark_contracts import BenchmarkError
        with self.assertRaises(BenchmarkError):
            load_truths(wrong, self.frozen)
        self.assertFalse((self.root / 'evaluator').exists())

    def test_every_scheduled_repetition_gets_one_team_output_score(self):
        root = Path(self.temp.name) / 'multiple-state'
        store = BenchmarkStore(root, create=True)
        frozen = copy.deepcopy(self.frozen)
        frozen['experiment']['repetitions'] = 2
        store.create_experiment(frozen)
        trials = []
        for repetition in (1, 2):
            trial = trial_fixture(store, frozen, 'repetition-' + str(repetition), repetition)
            workspace = root / 'trials' / trial['trial_id'] / 'ledger'
            with redirect_stdout(io.StringIO()):
                bot.initialize(workspace)
                with closing(bot.connect(workspace)) as db:
                    bot.create_workflow(db, frozen['workflow'], WORKFLOW_TITLE,
                                        WORKFLOW_SCOPE, WORKFLOW_ACCEPTANCE)
            trials.append(trial)
        self.freeze(store)
        authorization = authorize_fixture(store, frozen, trials[0])
        spec = call_fixture(store, frozen, trials[0], authorization)
        store.reserve_call('scheduled-failure', digest_bytes(canonical_bytes(spec)), spec)
        store.finish_call('scheduled-failure', receipt_fixture(store, frozen, 'scheduled-failure', spec, 'failed'))
        store.update_trial(trials[0]['trial_id'], dict(trials[0], status='failed'), 'failed')
        report = score_experiment(root, self.eid, self.truth_root)
        self.assertEqual((report['scheduled_trials'], report['recorded_scores']), (2, 2))
        scores = [event for event in store.snapshot(self.eid)['events'] if event['kind'] == 'score_recorded']
        self.assertEqual({(event['trial_id'], event['payload']['score']['variant']) for event in scores},
                         {(trial['trial_id'], 'team_output') for trial in trials})
        self.assertEqual(sum(event['payload']['score']['status'] == 'mechanical' for event in scores), 1)

    def test_unknown_reservation_remains_provisional_with_zero_findings(self):
        self.freeze()
        self.reserve()
        self.store.update_trial(self.tid, dict(self.trial, status='unknown'), 'unknown')
        self.assertEqual(self.score()['status'], 'provisional')
        score, = self.scores()
        self.assertEqual(score['trial_status'], 'unknown')
        self.assertEqual(score['metrics']['detection']['f1'], 0)
        self.assertIsNone(score['output_sha256'])

    def test_private_adjudication_is_hashed_and_export_checks_corruption(self):
        self.freeze()
        self.template()
        self.score(human=True)
        sha = self.scores()[0]['adjudication_sha256']
        path = self.root / 'evaluator' / 'adjudication' / (sha + '.json')
        self.assertEqual(path.read_bytes(), self.adjudication.read_bytes())
        path.write_bytes(b'changed-private-verdicts')
        self.assert_code('artifact_corrupt', self.store.snapshot, self.eid)
        self.assert_code('artifact_corrupt', self.score, human=True)

    def test_score_batch_rolls_back_all_events_on_failure(self):
        root = Path(self.temp.name) / 'rollback-state'
        store = BenchmarkStore(root, create=True)
        frozen = copy.deepcopy(self.frozen)
        frozen['experiment']['repetitions'] = 2
        store.create_experiment(frozen)
        for repetition in (1, 2):
            trial = trial_fixture(store, frozen, 'rollback-' + str(repetition), repetition)
            workspace = root / 'trials' / trial['trial_id'] / 'ledger'
            with redirect_stdout(io.StringIO()):
                bot.initialize(workspace)
                with closing(bot.connect(workspace)) as db:
                    bot.create_workflow(db, frozen['workflow'], WORKFLOW_TITLE,
                                        WORKFLOW_SCOPE, WORKFLOW_ACCEPTANCE)
        original = BenchmarkStore.record_score
        calls = []

        def interrupted(store, *args, **kwargs):
            calls.append(args)
            if len(calls) == 2:
                raise RuntimeError('Disposable scoring-commit failure fixture.')
            return original(store, *args, **kwargs)

        with mock.patch.object(BenchmarkStore, 'record_score', interrupted):
            with self.assertRaises(RuntimeError):
                score_experiment(root, self.eid, self.truth_root)
        self.assertEqual([event for event in store.snapshot(self.eid)['events']
                          if event['kind'] == 'score_recorded'], [])

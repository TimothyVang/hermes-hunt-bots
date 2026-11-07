"""Development diagnostics on disposable synthetic fixtures, never model-quality evidence."""
import copy
from pathlib import Path
from unittest import mock

import benchmark_diagnostics
from benchmark_contracts import decode_json
from benchmark_diagnostics import diagnose
from test_benchmark_adjudication import EARLY_STAGES, _AdjudicationFixture
from test_benchmark_runner import receipt_fixture, response_fixture


class BenchmarkDiagnosticsTests(_AdjudicationFixture):
    def setUp(self):
        super().setUp()
        self.output = Path(self.temp.name) / 'diagnostics.json'

    def diagnose(self, human=False):
        return diagnose(self.store, self.eid, self.truth_root, self.adjudication if human else None, self.output)

    def errors(self, document, kind):
        return [error for trial in document['trials'] for error in trial['errors'] if error['kind'] == kind]

    def run_workflow(self, analysis_findings=()):
        for stage in EARLY_STAGES:
            output = None
            if stage == 'analysis' and analysis_findings:
                output = response_fixture('analysis')
                output['findings'] = copy.deepcopy(list(analysis_findings))
            self.submit(stage=stage, output=output)
            self.advance_stage(stage)
        self.submit(stage='handoff', output=self.oracle())
        self.advance_stage('handoff')

    def unsupported(self):
        return [item for item in self.oracle()['findings'] if item['finding_id'] == 'finding-unsupported']

    def assert_no_truth_leak(self):
        text = self.output.read_text(encoding='utf-8')
        for leaked in ('step-b', 'support_sets', 'execution_outcome"', 'observability', 'expected_disposition'):
            self.assertNotIn(leaked, text)

    def test_mechanical_default_labels_every_error_basis(self):
        self.freeze()
        step = self.truth['steps'][0]
        other = next(event['event_id'] for event in self.frozen['cases'][0]['evidence']['events']
                     if event['event_id'] not in self.event_ids)
        incomplete = {'finding_id': 'finding-incomplete', 'asset_id': step['asset_id'],
                      'technique_id': step['technique_id'], 'window_utc': copy.deepcopy(step['window_utc']),
                      'disposition': 'suspicious', 'confidence': 0.6, 'event_ids': [other],
                      'rationale': 'Synthetic exact technique without its support set.'}
        self.run_workflow(analysis_findings=self.unsupported() + [incomplete])
        result = self.diagnose()
        self.assertEqual(result['status'], 'diagnosed')
        document = decode_json(self.output.read_bytes())
        self.assertEqual((document['adjudication'], document['adjudication_basis'], document['review_policy']),
                         ('mechanical', 'mechanical_rules', 'auto_advance'))
        self.assertEqual(document['truth_attestation'], {self.trial['case_id']: 'human_attested'})
        self.assertEqual(document['trials'][0]['handoff_basis'], 'team_output')
        bases = {error['basis'] for trial in document['trials'] for error in trial['errors']}
        self.assertTrue(bases)
        self.assertTrue(bases <= {'mechanical_rules', 'truth_comparison', 'public_evidence', 'call_receipt'})
        # Mechanical rules never fabricate semantic claim judgments.
        self.assertFalse([error for error in self.errors(document, 'unsupported_claim')
                          if error['detail'].get('reason') == 'adjudicated_insufficient'])
        incomplete_errors = [error for error in self.errors(document, 'unsupported_claim')
                             if error['detail']['item_id'] == 'finding-incomplete']
        self.assertEqual([(error['stage_key'], error['basis'], error['detail']['reason'])
                          for error in incomplete_errors],
                         [('analysis', 'mechanical_rules', 'incomplete_support_set')])
        # A wrong technique is a truth comparison, introduced by analysis and carried forward.
        unmatched = self.errors(document, 'unmatched_suspicious_finding')
        self.assertEqual([(item['stage_key'], item['role'], item['propagated_to'], item['basis'])
                          for item in unmatched],
                         [('analysis', 'framework-builder', ['handoff'], 'truth_comparison')])
        missed = self.errors(document, 'missed_eligible_step')
        self.assertEqual(len(missed), 1)
        self.assertEqual((missed[0]['stage_key'], missed[0]['attribution'], missed[0]['basis']),
                         ('handoff', 'not_determinable', 'mechanical_rules'))
        self.assertEqual(set(missed[0]['detail']), {'technique_id', 'asset_id', 'window_utc', 'reason'})
        self.assertEqual(missed[0]['detail']['technique_id'], 'T1059.001')
        self.assert_no_truth_leak()
        markdown = self.output.with_suffix('.md').read_text(encoding='utf-8')
        self.assertIn('Never feed this report to a model', markdown)
        self.assertIn('Adjudication: mechanical (mechanical&#95;rules)', markdown)
        self.assertIn('| Basis |', markdown)
        self.assertTrue(any('not&#95;measured&#95;mechanical' in line for line in markdown.splitlines()))
        self.assert_code('already_exists', self.diagnose)

    def free_event(self):
        cited = {item for step in self.truth['steps'] for group in step['support_sets'] for item in group}
        cited.update(item for group in self.truth.get('lookalike_event_ids', []) for item in group)
        return next(event['event_id'] for event in self.frozen['cases'][0]['evidence']['events']
                    if event['event_id'] not in cited)

    def test_truth_limitation_names_each_attestation(self):
        for attestation, expected in (('unreviewed_proposal', 'unreviewed proposed answer key'),
                                      ('agent_consensus', 'agent consensus answer key')):
            self.assertIn(expected, benchmark_diagnostics.TRUTH_LIMITATIONS[attestation])
        self.assertNotIn('human_attested', benchmark_diagnostics.TRUTH_LIMITATIONS)
        self.freeze()
        self.run_workflow()
        self.diagnose()
        document = decode_json(self.output.read_bytes())
        self.assertFalse([item for item in document['limitations'] if 'answer key' in item])

    def test_disputed_only_finding_is_not_an_error_under_consensus_truth(self):
        disputed = self.free_event()
        self.truth.update(attestation='agent_consensus', disputed_event_ids=[disputed])
        self.write_truth()
        self.freeze()
        step = self.truth['steps'][0]
        finding = {'finding_id': 'finding-disputed', 'asset_id': step['asset_id'], 'technique_id': 'T9998',
                   'window_utc': copy.deepcopy(step['window_utc']), 'disposition': 'suspicious',
                   'confidence': 0.5, 'event_ids': [disputed],
                   'rationale': 'Synthetic assertion citing only a disputed consensus record.'}
        self.run_workflow(analysis_findings=[finding])
        self.diagnose()
        document = decode_json(self.output.read_bytes())
        self.assertEqual(document['truth_attestation'], {self.trial['case_id']: 'agent_consensus'})
        self.assertIn(benchmark_diagnostics.TRUTH_LIMITATIONS['agent_consensus'], document['limitations'])
        self.assertNotIn(benchmark_diagnostics.TRUTH_LIMITATIONS['unreviewed_proposal'], document['limitations'])
        flagged = [error for trial in document['trials'] for error in trial['errors']
                   if error['detail'].get('item_id') == 'finding-disputed'
                   or 'finding-disputed' in error['detail'].get('finding_ids', [])]
        self.assertEqual(flagged, [])

    def test_human_adjudication_attributes_verdict_errors(self):
        self.freeze()
        self.run_workflow(analysis_findings=self.unsupported())
        self.template()
        self.diagnose(human=True)
        document = decode_json(self.output.read_bytes())
        self.assertEqual(document['adjudication'], 'human')
        claim = self.errors(document, 'unsupported_claim')
        self.assertEqual([(item['stage_key'], item['role'], item['propagated_to'], item['basis'])
                          for item in claim],
                         [('analysis', 'framework-builder', ['handoff'], 'human_verdicts')])
        self.assertEqual(claim[0]['detail']['item_id'], 'finding-unsupported')
        missed = self.errors(document, 'missed_eligible_step')
        self.assertEqual(missed[0]['detail']['reason'], 'never_reported')
        self.assertTrue(self.errors(document, 'missing_assessment_probability'))
        by_role = document['aggregate']['by_role_kind']
        self.assertEqual(by_role['framework-builder']['unsupported_claim'], 1)
        self.assertEqual(by_role['framework-coordinator']['missed_eligible_step'], 1)
        rows = document['aggregate']['by_team_role_kind']
        self.assertTrue(all(row['repetitions_affected'] == [1] for row in rows))
        self.assert_no_truth_leak()

    def test_existing_markdown_blocks_both_writes(self):
        self.freeze()
        self.run_workflow()
        self.output.with_suffix('.md').write_bytes(b'existing')
        self.assert_code('already_exists', self.diagnose)
        self.assertFalse(self.output.exists())

    def test_call_failures_are_listed_by_stage_and_role(self):
        self.freeze()
        call_id, spec = self.reserve()
        failed = receipt_fixture(self.store, self.frozen, call_id, spec, 'failed')
        self.store.finish_call(call_id, failed)
        self.diagnose()
        document = decode_json(self.output.read_bytes())
        failures = [error for error in document['trials'][0]['errors'] if error['attribution'] == 'observed']
        self.assertEqual(len(failures), 1)
        self.assertEqual((failures[0]['stage_key'], failures[0]['role'], failures[0]['basis']),
                         ('scope', 'framework-coordinator', 'call_receipt'))
        self.assertIn(failures[0]['kind'], benchmark_diagnostics.TAXONOMY)
        self.assertEqual(document['trials'][0]['handoff_basis'], 'no_handoff_output')

    def test_holdout_feedback_is_refused_before_truth_is_read(self):
        self.freeze()
        snapshot, seals = benchmark_diagnostics._sealed_snapshot(self.store, self.eid)
        holdout = copy.deepcopy(snapshot)
        holdout['experiment']['cases'][0]['scenario']['split'] = 'holdout'
        with mock.patch.object(benchmark_diagnostics, '_sealed_snapshot', return_value=(holdout, seals)), \
                mock.patch.object(benchmark_diagnostics, 'load_truths', side_effect=AssertionError('truth read')):
            self.assert_code('holdout_feedback_refused', self.diagnose)
        self.assertFalse(self.output.exists())

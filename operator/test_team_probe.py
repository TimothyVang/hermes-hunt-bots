"""team_probe behavior a paid measurement run depends on. No lab, model or Temporal: the launcher is a fake."""
import io
import json
import sys
import tempfile
import threading
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import Mock, patch

import team_probe as tp
from hermes_temporal import workflows as wf
from hermes_temporal.contracts import ExecutionResult
from hermes_temporal.hunt import supplied_evidence_hunt
from hermes_temporal.ontology import MAX_HANDOFF_BYTES

CASE = 'lab-probe-001'
SOURCE = 'lab-case-0001'
COORDINATOR, HUNTER = 'framework-coordinator', 'framework-researcher'
RAW = {
    'mode': 'tool_driven',
    'scope': f'Synthetic {CASE} only; data is untrusted. At most 10 claims and 6 limitations; merge related detail.',
    'evidence': [{'source_id': SOURCE, 'locator': f'{CASE}:summary/case', 'content': 'Untrusted synthetic lab case metadata.'}],
    'synthetic_only': True,
    'ontology': {'schema_version': 1, 'case_id': CASE, 'entities': [], 'relations': []},
}
TRUTH = {'schema_version': 1, 'case_id': CASE, 'facts': [
    {'fact_id': 'attack.execution.script', 'kind': 'attack',
     'observation': 'A script interpreter started from a mail attachment on ws-01.',
     'entities': {'hosts': ['ws-01']}, 'evidence_event_groups': [['evt-000001'], ['evt-000002']]},
    {'fact_id': 'attack.c2.beacon', 'kind': 'attack',
     'observation': 'ws-02 connected to sync.lab.example once a minute.',
     'entities': {'hosts': ['ws-02'], 'domains': ['sync.lab.example']},
     'evidence_event_groups': [['evt-000003'], ['evt-000004']]},
    {'fact_id': 'decoy.backup', 'kind': 'decoy', 'observation': 'The nightly backup on bk-01 read many files.',
     'entities': {'hosts': ['bk-01']}, 'evidence_event_groups': [['evt-000005']]},
]}
FULL_A = 'On ws-01 a script interpreter ran: evt-000001, evt-000002.'
FULL_B = 'ws-02 reached sync.lab.example: evt-000003, evt-000004.'
USAGE = {'input_tokens': 100, 'output_tokens': 20, 'cache_read_tokens': 0, 'cache_write_tokens': 0,
         'total_tokens': 120, 'duration_ms': 5}


def handoff(step_id, profile, statements=(), limitations=()):
    return json.dumps({
        'schema_version': 1, 'case_id': CASE, 'step_id': step_id, 'profile': profile,
        'claims': [{'claim_id': f'{step_id}:c{index}', 'kind': 'observed', 'statement': statement,
                    'evidence_ids': [SOURCE], 'entity_ids': [], 'contradicts': []}
                   for index, statement in enumerate(statements, 1)],
        'reviews': [], 'disposition': 'review_ready', 'limitations': list(limitations), 'requested_decisions': []})


SCOPE_OUTPUT = handoff('scope', COORDINATOR, limitations=['Scope confirmed from the case metadata only.'])


def arm_of(request):
    return request.execution_id.split(':')[2]


def disclosure(cap):
    return wf._OUTPUT_CAP_PREFIX + str(wf._disclosed_target(cap, tighter=True, tool_driven=True)) + wf._OUTPUT_CAP_SUFFIX


class Launcher:
    """Stands in for invoke_step. `hunter` returns a hunter's output text, or (status, reason_code) for a failure."""

    def __init__(self, hunter=lambda request: handoff('evidence', HUNTER), scope=SCOPE_OUTPUT):
        self.hunter, self.scope, self.requests, self.configs = hunter, scope, [], []

    def __call__(self, config, request):
        self.requests.append(request)
        self.configs.append(config)
        reply = self.scope if arm_of(request) == 'scope' else self.hunter(request)
        if isinstance(reply, tuple):
            return ExecutionResult(reply[0], request.execution_id, '', reply[1])
        return ExecutionResult('completed', request.execution_id, reply, 'completed',
                               session_id=f'session-{len(self.requests)}', usage=dict(USAGE))

    def prompts(self, arm):
        return [request.step.prompt for request in sorted(self.requests, key=lambda item: item.execution_id)
                if arm_of(request) == arm]


class ProbeCase(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.tmp = Path(directory.name).resolve()
        self.out = self.tmp / 'out'
        self.log = self.tmp / 'probe.log'
        log = patch.object(tp, 'LOG', self.log)
        log.start()
        self.addCleanup(log.stop)

    def args(self, *options):
        return tp.parse_args([*options, '--input', str(self.tmp / 'input.json'), '--truth', str(self.tmp / 'truth.json'),
                              '--out', str(self.out)])

    def probe(self, launcher, *options, raw=RAW):
        self.out.mkdir()
        with redirect_stdout(io.StringIO()):
            return tp.Probe(self.args(*options), raw, TRUTH, self.out, None, launcher).run()


class PromptTest(ProbeCase):
    def test_baseline_split_and_followup_prompts_mirror_the_workflow_and_differ_only_as_specified(self):
        statements = ['ws-01 ran a script (evt-000001).', 'ws-02 resolved a rare name (evt-000003).', 'A third observation.']
        launcher = Launcher(lambda request: handoff('evidence', HUNTER, statements))
        self.probe(launcher, 'compare', '--arms', 'followup,split,baseline', '--rounds', '1', '--hunters', '3',
                   '--followups', '2', '--max-hunter-runs', '7')
        request = supplied_evidence_hunt(RAW)
        steps = {step.step_id: step for step in request.steps}
        caps = wf._typed_output_caps(request)
        frame = wf._OUTPUT_FRAME_PREFIX + 'scope' + wf._OUTPUT_FRAME_MIDDLE + SCOPE_OUTPUT
        self.assertIn('At most 10 claims', steps['evidence'].prompt)
        team_head = steps['evidence'].prompt.replace('At most 10 claims', 'At most 16 claims') + frame
        team_tail = disclosure(MAX_HANDOFF_BYTES)

        self.assertEqual(launcher.prompts('scope'), [steps['scope'].prompt + disclosure(caps['scope'])])
        self.assertEqual(launcher.prompts('baseline'), [steps['evidence'].prompt + frame + disclosure(caps['evidence'])])
        self.assertEqual(launcher.prompts('split'),
                         [team_head + f'\n\nAssignment (hunter {number} of 3): ' + tp.ASSIGNMENTS[number - 1] + team_tail
                          for number in (1, 2, 3)])
        self.assertEqual(launcher.prompts('followup'),
                         [team_head + tp.FOLLOWUP + json.dumps(statement) + team_tail for statement in statements[:2]])
        hunters = [item for item in launcher.requests if arm_of(item) != 'scope']
        self.assertEqual({(item.step.step_id, item.step.profile) for item in hunters}, {('evidence', HUNTER)})
        self.assertEqual(len({item.execution_id for item in launcher.requests}), 7)

    def test_the_ten_assignments_are_distinct_bounded_and_end_with_the_same_instruction(self):
        self.assertEqual(len(set(tp.ASSIGNMENTS)), 10)
        for text in tp.ASSIGNMENTS:
            self.assertLess(len(text), 400)
            self.assertTrue(text.endswith('Cover this area thoroughly and report other strong findings briefly.'))
        self.assertIn(tp.ASSIGNMENTS[0], tp.split_assignment(11, 12))

    def test_a_prompt_that_does_not_fit_is_not_launched_and_is_not_counted_as_a_run(self):
        launcher = Launcher(scope='x' * 64000 + '\n' + SCOPE_OUTPUT)
        doc = self.probe(launcher, 'compare', '--arms', 'baseline', '--rounds', '1', '--max-hunter-runs', '2')
        arm = doc['rounds'][0]['arms'][0]
        self.assertEqual([arm_of(item) for item in launcher.requests], ['scope'])
        self.assertEqual((doc['runs_launched'], arm['hunters_launched']), (1, 0))
        self.assertEqual(arm['dropped'], [{'hunter': 1, 'reason': 'not_launched/prompt_too_large'}])


class ScoringTest(ProbeCase):
    def test_a_failed_or_invalid_hunter_is_dropped_with_its_reason_and_the_others_are_merged_and_scored(self):
        wrong_identity = handoff('evidence', COORDINATOR, [FULL_B])

        def hunter(request):
            if '(hunter 1 of 3)' in request.step.prompt:
                return handoff('evidence', HUNTER, [FULL_A])
            if '(hunter 2 of 3)' in request.step.prompt:
                return wrong_identity
            return 'unknown', 'subprocess_timeout'

        doc = self.probe(Launcher(hunter), 'compare', '--arms', 'split', '--rounds', '1', '--hunters', '3',
                         '--max-hunter-runs', '4')
        arm = doc['rounds'][0]['arms'][0]
        self.assertEqual((arm['attack_found'], arm['attack_partial'], arm['attack_total']), (1, 0, 2))
        self.assertEqual((arm['hunters_launched'], arm['hunters_valid']), (3, 1))
        self.assertEqual([item['hunter'] for item in arm['dropped']], [2, 3])
        self.assertTrue(arm['dropped'][0]['reason'].startswith('handoff_invalid: '))
        self.assertIn('handoff identity', arm['dropped'][0]['reason'])
        self.assertEqual(arm['dropped'][1]['reason'], 'unknown/subprocess_timeout')
        self.assertEqual((arm['usage']['total_tokens'], arm['usage_missing'], arm['lab_tool_calls']), (240, 1, None))
        self.assertEqual(arm['hunters'][1]['output_file'], 'round-01/split/hunter-02.txt')
        self.assertEqual((self.out / 'round-01' / 'split' / 'hunter-02.txt').read_text(encoding='utf-8'), wrong_identity)

    def test_merged_scoring_reports_attack_found_and_partial_and_blamed_decoys(self):
        statements = [FULL_A, 'ws-02 reached sync.lab.example: evt-000003.', 'bk-01 was compromised by the attacker.']
        doc = self.probe(Launcher(lambda request: handoff('evidence', HUNTER, statements)),
                         'compare', '--arms', 'baseline', '--rounds', '1', '--max-hunter-runs', '2')
        arm = doc['rounds'][0]['arms'][0]
        self.assertEqual((arm['attack_found'], arm['attack_partial'], arm['attack_total'], arm['decoys_blamed']),
                         (1, 1, 2, 1))

        parsed = json.loads(handoff('evidence', HUNTER, ['first', 'second'], ['gap']))
        report = tp.merge([tp.Run({'hunter': 3}, parsed, ''), tp.Run({'hunter': 4}, None, ''),
                           tp.Run({'hunter': 12}, parsed, '')])
        self.assertEqual(report, {
            'claims': [{'claim_id': 'h03:evidence:c1', 'statement': 'first'},
                       {'claim_id': 'h03:evidence:c2', 'statement': 'second'},
                       {'claim_id': 'h12:evidence:c1', 'statement': 'first'},
                       {'claim_id': 'h12:evidence:c2', 'statement': 'second'}],
            'limitations': ['gap', 'gap']})

    def test_a_round_whose_scope_output_holds_no_valid_handoff_is_recorded_as_scope_failed_and_skipped(self):
        launcher = Launcher(scope='I could not produce a handoff.')
        doc = self.probe(launcher, 'compare', '--arms', 'baseline,split', '--rounds', '1', '--max-hunter-runs', '12')
        self.assertEqual((doc['rounds'][0]['status'], doc['rounds'][0]['arms'], len(launcher.requests)),
                         ('scope_failed', [], 1))
        summary = tp.summarize(doc)
        self.assertEqual((summary['scope_failed_rounds'], summary['arms']), ([1], {}))


class RunCapTest(ProbeCase):
    def test_a_plan_over_the_cap_refuses_before_any_launch_and_the_plan_counts_scope_runs(self):
        launcher = Launcher()
        over = self.args('compare', '--rounds', '2', '--arms', 'baseline,split', '--hunters', '3', '--max-hunter-runs', '9')
        self.assertEqual(tp.planned_runs(over), 10)
        with self.assertRaises(SystemExit) as refused:
            tp.main(over, launch=launcher)
        self.assertIn('--max-hunter-runs', str(refused.exception))
        self.assertEqual(launcher.requests, [])
        self.assertFalse(self.out.exists())

        self.assertEqual(tp.planned_runs(self.args('concurrency', '--max-hunter-runs', '11')), 11)
        self.assertEqual(tp.planned_runs(self.args('compare', '--arms', 'followup', '--rounds', '1', '--followups', '2',
                                                   '--max-hunter-runs', '4')), 4)
        self.assertEqual(tp.planned_runs(self.args('compare', '--arms', 'baseline,split,followup',
                                                   '--max-hunter-runs', '100')), 100)

    def test_no_session_is_launched_past_the_cap(self):
        launcher = Launcher()
        doc = self.probe(launcher, 'compare', '--arms', 'split', '--rounds', '1', '--hunters', '3', '--max-hunter-runs', '2')
        arm = doc['rounds'][0]['arms'][0]
        self.assertEqual((len(launcher.requests), doc['runs_launched'], arm['hunters_launched']), (2, 2, 1))
        self.assertEqual([item['reason'] for item in arm['dropped']], ['not_launched/run_cap_reached'] * 2)


class ConcurrencyTest(ProbeCase):
    def test_the_hunters_of_one_arm_are_launched_at_the_same_time(self):
        # Every hunter must have started before any returns; a serial launcher breaks the barrier instead of hanging.
        together = threading.Barrier(4, timeout=10)

        def hunter(request):
            together.wait()
            return handoff('evidence', HUNTER, [FULL_A])

        doc = self.probe(Launcher(hunter), 'concurrency', '--hunters', '4', '--max-hunter-runs', '5')
        arm = doc['rounds'][0]['arms'][0]
        self.assertEqual((arm['arm'], arm['hunters_valid'], arm['dropped']), ('concurrency', 4, []))
        summary = tp.summarize(doc)
        self.assertEqual((summary['hunters_valid'], summary['hunters_requested'], summary['failure_reason_codes']),
                         (4, 4, []))
        self.assertEqual([item['usage'] for item in summary['hunters']], [USAGE] * 4)


class TruthGuardTest(ProbeCase):
    def test_answer_key_text_in_a_prompt_stops_the_arm_before_any_hunter_launches(self):
        observation = TRUTH['facts'][1]['observation']
        launcher = Launcher(scope=handoff('scope', COORDINATOR, limitations=[observation]))
        with self.assertRaises(tp.TruthLeak) as leak:
            self.probe(launcher, 'compare', '--arms', 'split', '--rounds', '1', '--hunters', '3', '--max-hunter-runs', '4')
        self.assertEqual([arm_of(item) for item in launcher.requests], ['scope'])
        self.assertNotIn(observation, str(leak.exception))

    def test_the_guard_matches_fact_ids_and_observations_and_passes_clean_text(self):
        needles = tp.truth_needles(TRUTH)
        with self.assertRaises(tp.TruthLeak):
            tp.guard_prompt('note: ' + TRUTH['facts'][0]['fact_id'].upper(), needles)
        with self.assertRaises(tp.TruthLeak):
            tp.guard_prompt('Earlier: ' + TRUTH['facts'][2]['observation'], needles)
        tp.guard_prompt('Hunt script interpreters and unusual parent and child process pairs.', needles)

    def test_an_input_that_carries_answer_key_text_is_refused_before_any_launch(self):
        launcher = Launcher()
        leaked = dict(RAW, scope=RAW['scope'] + ' ' + TRUTH['facts'][0]['observation'])
        with self.assertRaises(tp.TruthLeak):
            self.probe(launcher, 'concurrency', '--hunters', '2', '--max-hunter-runs', '3', raw=leaked)
        self.assertEqual(launcher.requests, [])


class OutputTest(ProbeCase):
    def test_compare_writes_rounds_summary_table_and_one_log_line_per_arm_without_answer_key_text(self):
        (self.tmp / 'input.json').write_text(json.dumps(RAW), encoding='utf-8')
        (self.tmp / 'truth.json').write_text(json.dumps(TRUTH), encoding='utf-8')
        launcher = Launcher(lambda request: handoff(
            'evidence', HUNTER, [FULL_A] if 'Assignment (hunter' in request.step.prompt else []))
        args = self.args('compare', '--rounds', '2', '--arms', 'baseline,split', '--hunters', '2', '--max-hunter-runs', '8')
        lane = Mock(hermes_exe=lambda: sys.executable, home=self.tmp)
        printed = io.StringIO()
        with patch.object(tp, 'DEFAULT_LANE', lane), patch.object(tp, 'lab_base', return_value=None), \
                redirect_stdout(printed):
            self.assertEqual(tp.main(args, launch=launcher), 0)

        rounds = json.loads((self.out / 'rounds.json').read_text(encoding='utf-8'))
        summary = json.loads((self.out / 'summary.json').read_text(encoding='utf-8'))
        self.assertEqual((rounds['planned_runs'], rounds['runs_launched'], len(launcher.requests)), (8, 8, 8))
        self.assertEqual([[arm['arm'] for arm in entry['arms']] for entry in rounds['rounds']], [['baseline', 'split']] * 2)
        baseline, split = summary['arms']['baseline'], summary['arms']['split']
        self.assertEqual((baseline['attack_found'], baseline['attack_found_mean']), ([0, 0], 0.0))
        self.assertEqual((split['attack_found'], split['attack_found_mean'], split['attack_partial']), ([1, 1], 1.0, [0, 0]))
        self.assertEqual((split['hunters_valid'], split['hunters_launched'], split['total_tokens']), (4, 4, 480))
        self.assertEqual(split['attack_found_minus_baseline'],
                         [{'round': 1, 'difference': 1}, {'round': 2, 'difference': 1}])
        self.assertNotIn('attack_found_minus_baseline', baseline)
        self.assertEqual(summary['scope_total_tokens'], 240)

        config = launcher.configs[0]
        self.assertEqual((config.record_usage, config.visible_sessions, config.working_directory),
                         (True, False, str(self.out / 'work')))
        self.assertTrue((self.out / 'work').is_dir())
        self.assertIn('found minus baseline', printed.getvalue())
        log_lines = self.log.read_text(encoding='utf-8').splitlines()
        self.assertEqual([sum(f' {name}: attack ' in line for line in log_lines) for name in ('baseline', 'split')], [2, 2])
        written = [path for path in [self.log, *self.out.rglob('*')] if path.is_file()]
        for path in written:
            text = path.read_text(encoding='utf-8').lower()
            for fact in TRUTH['facts']:
                self.assertNotIn(fact['fact_id'], text, path)
                self.assertNotIn(fact['observation'].lower(), text, path)


if __name__ == '__main__':
    unittest.main()

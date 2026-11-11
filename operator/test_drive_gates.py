"""drive_gates behavior that an unattended loop round depends on."""
import argparse
import copy
import hashlib
import io
import json
import re
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import drive_gates as dg

CHILD = 'loop-wf:round:001'
RETRIED = {'step_id': 'evidence', 'reason': 'ValueError: unknown evidence ID reference: evt-x',
           'outcome': 'retried', 'result': {'status': 'completed', 'output': 'first try'}}


def child(stage, rejections=(), results=()):
    return {'stage': stage, 'step_id': 'evidence', 'execution_id': f'{CHILD}:1', 'temporal_status': 'RUNNING',
            'results': list(results), 'handoff_rejections': list(rejections)}


def step(step_id, state, execution_id=None, reason='', wave=2):
    return {'step_id': step_id, 'state': state, 'wave': wave, 'execution_id': execution_id, 'reason': reason}


def result(execution_id, output, status='completed', reason_code='completed'):
    return {'status': status, 'execution_id': execution_id, 'output': output, 'reason_code': reason_code,
            'session_id': None, 'usage': None}


def wave(stage, steps, results=(), rejections=(), gate='wave-2'):
    """A parallel hunt's status: every step is listed and the open gate is a wave, not a step."""
    return {'stage': stage, 'step_id': gate, 'execution_id': None, 'temporal_status': 'RUNNING',
            'results': list(results), 'handoff_rejections': list(rejections), 'steps': list(steps)}


NAMES = ('evidence', 'network', 'intel')
SCOPE = step('scope', 'done', 'x:scope', wave=1)
SCOPE_RESULT = result('x:scope', 'scope report')


COMPLETED_CHILD = {'stage': 'completed', 'step_id': None, 'execution_id': None, 'temporal_status': 'COMPLETED',
                   'results': [], 'handoff_rejections': []}


def run(states, args=None, on_status=None, sleep=None):
    """Run the driver over these child statuses; the parent reports completed once they are used up.
    Without args it runs in delegated mode with the note 'NOTE'. on_status(call number, decision folder) runs
    before each child status read is answered, as a bridge acting meanwhile would; sleep replaces time.sleep.
    Returns the exit code, decisions sent, saved outputs, log messages, printed text, decision-log lines,
    the pending records seen at each status read and the pending records left at the end."""
    states, decisions, seen = list(states), [], []
    folder = None

    def fake_cli(*args):
        if args[0] == 'practice-status':
            if states:
                return {'temporal_status': 'RUNNING', 'stage': 'running_round', 'child_workflow_id': CHILD}
            return {'temporal_status': 'COMPLETED', 'stage': 'completed'}
        if args[0] == 'status':
            seen.append({path.name: json.loads(path.read_text(encoding='utf-8'))
                         for path in (folder / 'pending').glob('*.json')})
            if on_status:
                on_status(len(seen), folder)
            return states.pop(0) if states else dict(COMPLETED_CHILD)
        options = dict(zip(args[2::2], args[3::2]))
        decisions.append((options['--step-id'], options['--phase'], options['--decision-id'],
                          options['--evidence-note']))
        return {'signal_sent': True}

    args = args or argparse.Namespace(workflow_id='loop-wf', delegated_by='Ada', reason='synthetic loop',
                                      operator=None, note='NOTE', card_summary=False)
    printed = io.StringIO()
    with tempfile.TemporaryDirectory() as tmp, patch.object(dg, 'GATE_RUNS', Path(tmp)), \
            patch.object(dg, 'LOG', Path(tmp) / 'driver.log'), patch.object(dg, 'cli', fake_cli), \
            patch.object(dg.time, 'sleep', side_effect=sleep), redirect_stdout(printed):
        folder = args.decision_dir = Path(tmp) / 'operator-decisions'
        code = dg.main(args)
        saved = {path.name: path.read_text(encoding='utf-8') for path in (Path(tmp) / 'outputs' / 'loop-wf').iterdir()}
        log = (Path(tmp) / 'driver.log').read_text(encoding='utf-8').splitlines()
        decision_log = folder / 'decisions.jsonl'
        lines = ([json.loads(line) for line in decision_log.read_text(encoding='utf-8').splitlines()]
                 if decision_log.exists() else [])
        left = sorted(path.name for path in (folder / 'pending').glob('*'))
    return SimpleNamespace(code=code, decisions=decisions, saved=saved, messages=[line.split(' ', 1)[1] for line in log],
                           printed=printed.getvalue(), lines=lines, seen=seen, left=left)


def drive(states, args=None):
    """(exit code, decisions sent, saved outputs by file name, log messages) of run()."""
    result = run(states, args)
    return result.code, result.decisions, result.saved, result.messages


class RetryGateTest(unittest.TestCase):
    def test_the_workflow_retry_gate_is_approved_once_as_a_retry_and_its_output_saved(self):
        corrected = {'status': 'completed', 'output': '{"corrected": true}', 'reason_code': 'completed'}
        states = [
            child('awaiting_execution_approval'),
            child('executing'),
            child('awaiting_execution_approval', [RETRIED]),
            child('awaiting_execution_approval', [RETRIED]),
            child('awaiting_review', [RETRIED], [corrected]),
        ]
        decisions = []

        def fake_cli(*args):
            if args[0] == 'practice-status':
                if states:
                    return {'temporal_status': 'RUNNING', 'stage': 'running_round', 'child_workflow_id': CHILD}
                return {'temporal_status': 'COMPLETED', 'stage': 'completed'}
            if args[0] == 'status':
                return states.pop(0)
            options = dict(zip(args[2::2], args[3::2]))
            decisions.append((options['--phase'], options['--decision-id'], options['--evidence-note']))
            return {'signal_sent': True}

        args = argparse.Namespace(workflow_id='loop-wf', delegated_by='Ada', reason='synthetic loop', operator=None,
                                  note='NOTE')
        with tempfile.TemporaryDirectory() as tmp, patch.object(dg, 'GATE_RUNS', Path(tmp)), \
                patch.object(dg, 'LOG', Path(tmp) / 'driver.log'), patch.object(dg, 'cli', fake_cli), \
                patch.object(dg.time, 'sleep'):
            args.decision_dir = Path(tmp) / 'operator-decisions'
            self.assertEqual(dg.main(args), 0)
            saved = (Path(tmp) / 'outputs' / 'loop-wf' / '001-evidence.txt').read_text(encoding='utf-8')
        self.assertEqual(decisions, [
            ('execute', f'{CHILD}:evidence:execute', 'NOTE'),
            ('execute', f'{CHILD}:evidence:execute:retry1', dg.RETRY_NOTE + 'NOTE'),
            ('review', f'{CHILD}:evidence:review', 'NOTE'),
        ])
        self.assertEqual(saved, corrected['output'])


class WaveGateTest(unittest.TestCase):
    def test_a_wave_gets_one_execute_and_one_review_approval_and_each_output_is_saved_under_its_own_step(self):
        waiting = wave('awaiting_execution_approval', [SCOPE] + [step(name, 'awaiting_approval') for name in NAMES],
                       [SCOPE_RESULT])
        working = wave('executing', [SCOPE] + [step(name, 'working', f'x:{name}') for name in NAMES], [SCOPE_RESULT])
        # The results are not in step order: only the execution ID says whose output each one is.
        reviewing = wave('awaiting_review', [SCOPE] + [step(name, 'awaiting_review', f'x:{name}') for name in NAMES],
                         [result('x:intel', 'intel report'), SCOPE_RESULT, result('x:evidence', 'evidence report'),
                          result('x:network', 'network report')])
        code, decisions, saved, _ = drive([waiting, waiting, working, reviewing, reviewing])
        self.assertEqual(code, 0)
        self.assertEqual(decisions, [
            ('wave-2', 'execute', f'{CHILD}:wave-2:execute', 'NOTE'),
            ('wave-2', 'review', f'{CHILD}:wave-2:review', 'NOTE'),
        ])
        self.assertEqual(saved, {'001-evidence.txt': 'evidence report', '001-network.txt': 'network report',
                                 '001-intel.txt': 'intel report'})

    def test_a_wave_retry_gate_is_approved_once_as_a_retry_and_the_first_opening_only_once(self):
        # scope was retried in wave 1; that must not make the first opening of wave 2 look like a retry.
        earlier = dict(RETRIED, step_id='scope')
        network = dict(RETRIED, step_id='network', reason='ValueError: handoff exceeds its byte limit')
        first = wave('awaiting_execution_approval', [SCOPE] + [step(name, 'awaiting_approval') for name in NAMES],
                     [SCOPE_RESULT], [earlier])
        working = wave('executing', [SCOPE] + [step(name, 'working', f'x:{name}') for name in NAMES],
                       [SCOPE_RESULT], [earlier])
        intel = result('x:intel', 'intel report')
        reopened = wave('awaiting_execution_approval',
                        [SCOPE, step('evidence', 'awaiting_approval'), step('network', 'awaiting_approval'),
                         step('intel', 'awaiting_review', 'x:intel')],
                        [SCOPE_RESULT, intel], [earlier, RETRIED, network])
        reviewing = wave('awaiting_review',
                         [SCOPE, step('evidence', 'awaiting_review', 'x:evidence:retry'),
                          step('network', 'awaiting_review', 'x:network:retry'),
                          step('intel', 'awaiting_review', 'x:intel')],
                         [SCOPE_RESULT, intel, result('x:network:retry', 'network corrected'),
                          result('x:evidence:retry', 'evidence corrected')], [earlier, RETRIED, network])
        code, decisions, saved, messages = drive([first, first, working, reopened, reopened, reopened, reviewing])
        self.assertEqual(code, 0)
        self.assertEqual(decisions, [
            ('wave-2', 'execute', f'{CHILD}:wave-2:execute', 'NOTE'),
            ('wave-2', 'execute', f'{CHILD}:wave-2:execute:retry1', dg.RETRY_NOTE + 'NOTE'),
            ('wave-2', 'review', f'{CHILD}:wave-2:review', 'NOTE'),
        ])
        self.assertEqual([message for message in messages if 'offers one retry' in message],
                         [f'{CHILD} wave-2 handoff rejected; the workflow offers one retry: '
                          f'evidence: {RETRIED["reason"]}; network: {network["reason"]}'])
        self.assertEqual(saved, {'001-evidence.txt': 'evidence corrected', '001-network.txt': 'network corrected',
                                 '001-intel.txt': 'intel report'})

    def test_a_dropped_optional_step_is_reported_once_and_does_not_stop_the_run(self):
        failed = result('x:intel', '', 'failed', 'timeout')
        dropped = step('intel', 'dropped', 'x:intel', 'timeout')
        evidence = result('x:evidence', 'evidence report')
        code, decisions, saved, messages = drive([
            wave('awaiting_execution_approval',
                 [SCOPE, step('evidence', 'awaiting_approval'), step('intel', 'awaiting_approval')], [SCOPE_RESULT]),
            wave('executing', [SCOPE, step('evidence', 'working', 'x:evidence'), dropped], [SCOPE_RESULT, failed]),
            wave('awaiting_review', [SCOPE, step('evidence', 'awaiting_review', 'x:evidence'), dropped],
                 [SCOPE_RESULT, evidence, failed]),
            wave('awaiting_execution_approval',
                 [SCOPE, step('evidence', 'done', 'x:evidence'), dropped,
                  step('analysis', 'awaiting_approval', wave=3)],
                 [SCOPE_RESULT, evidence, failed], gate='wave-3'),
        ])
        self.assertEqual(code, 0)
        self.assertEqual([message for message in messages if message.startswith('DROPPED')],
                         [f'DROPPED {CHILD} intel: timeout'])
        self.assertEqual(saved, {'001-evidence.txt': 'evidence report'})
        self.assertEqual([decision[:2] for decision in decisions],
                         [('wave-2', 'execute'), ('wave-2', 'review'), ('wave-3', 'execute')])

    def test_a_step_awaiting_review_without_a_completed_result_stops_the_run_with_nothing_saved_or_approved(self):
        steps = [SCOPE, step('evidence', 'awaiting_review', 'x:evidence'),
                 step('network', 'awaiting_review', 'x:network')]
        evidence = result('x:evidence', 'evidence report')
        cases = {'awaiting review without a result': [evidence, SCOPE_RESULT],
                 'result failed/timeout': [evidence, result('x:network', '', 'failed', 'timeout'), SCOPE_RESULT]}
        for reason, results in cases.items():
            with self.subTest(reason):
                code, decisions, saved, messages = drive([wave('awaiting_review', steps, results)])
                self.assertEqual((code, decisions, saved), (1, [], {}))
                self.assertEqual(messages[-1], f'STOP {CHILD} network: {reason}')

    def test_a_wave_review_gate_with_no_step_awaiting_review_is_not_approved(self):
        code, decisions, saved, messages = drive([wave(
            'awaiting_review', [SCOPE, step('evidence', 'done', 'x:evidence')],
            [SCOPE_RESULT, result('x:evidence', 'evidence report')])])
        self.assertEqual((code, decisions, saved), (1, [], {}))
        self.assertEqual(messages[-1], f'STOP {CHILD} wave-2: no step is awaiting review; nothing was approved')

    def test_a_required_step_awaiting_reconciliation_stops_the_run_undecided(self):
        code, decisions, _, messages = drive([wave(
            'needs_reconciliation', [SCOPE, step('analysis', 'working', 'x:analysis')],
            [SCOPE_RESULT, result('x:analysis', '', 'unknown', 'execution_error')], gate='analysis')])
        self.assertEqual((code, decisions), (1, []))
        self.assertTrue(messages[-1].startswith(f'STOP {CHILD} analysis: stage needs_reconciliation; no retry. '))


AUTOMATED = ('Automated approval under ADR 0002 (two human decisions per hunt) for operator Ada Lovelace; '
             'recorded automatically by operator/drive_gates.py; not a human review of this step.')
# A short parallel hunt: the scope wave, one hunter wave, then analysis and the final report.
PLAN = (('scope', 1), ('evidence', 2), ('network', 2), ('analysis', 3), ('incident', 4))


def two_decisions():
    return dg.parse_args(['loop-wf', '--two-decisions', '--operator', ' Ada  Lovelace '])


def hunt(stage, gate, **states):
    """A parallel hunt's status; steps not named are done before the open wave and not reached after it."""
    open_wave = int(gate.split('-')[1])
    steps, results = [], []
    for name, number in PLAN:
        state = states.get(name, 'done' if number < open_wave else 'not_reached')
        ran = state not in ('not_reached', 'awaiting_approval')
        steps.append(step(name, state, f'x:{name}' if ran else None, wave=number))
        if state in ('awaiting_review', 'done'):
            results.append(result(f'x:{name}', f'{name} report'))
    return wave(stage, steps, results, gate=gate)


def serial(stage, step_id, rejections=(), results=()):
    """A serial hunt's status: no step list, the open gate is the step itself."""
    return {'stage': stage, 'step_id': step_id, 'execution_id': f'{CHILD}:{step_id}', 'temporal_status': 'RUNNING',
            'results': list(results), 'handoff_rejections': list(rejections)}


def drive_two_decisions(states):
    result = run(states, two_decisions())
    return result.code, result.decisions, result.saved, result.messages, result.printed


def waiting(messages):
    """The WAITING lines, without the temporary output directory they end with."""
    lines = [message for message in messages if message.startswith('WAITING')]
    for line in lines:
        assert line.endswith(str(Path('outputs', 'loop-wf'))), line
    return [line.split('; outputs in ')[0] for line in lines]


class TwoDecisionModeTest(unittest.TestCase):
    def test_a_parallel_hunt_waits_for_the_operator_at_the_scope_and_report_reviews_and_automates_the_rest(self):
        scope_review = hunt('awaiting_review', 'wave-1', scope='awaiting_review')
        report_review = hunt('awaiting_review', 'wave-4', incident='awaiting_review')
        code, decisions, saved, messages, printed = drive_two_decisions([
            hunt('awaiting_execution_approval', 'wave-1', scope='awaiting_approval'),
            hunt('executing', 'wave-1', scope='working'),
            scope_review, scope_review, scope_review,
            # The operator approved the scope: the hunters' wave opens and the driver goes on.
            hunt('awaiting_execution_approval', 'wave-2', evidence='awaiting_approval', network='awaiting_approval'),
            hunt('awaiting_review', 'wave-2', evidence='awaiting_review', network='awaiting_review'),
            hunt('awaiting_execution_approval', 'wave-3', analysis='awaiting_approval'),
            hunt('awaiting_review', 'wave-3', analysis='awaiting_review'),
            hunt('awaiting_execution_approval', 'wave-4', incident='awaiting_approval'),
            report_review, report_review,
        ])
        self.assertEqual(code, 0)
        self.assertEqual(decisions, [
            ('wave-1', 'execute', f'{CHILD}:wave-1:execute', AUTOMATED),
            ('wave-2', 'execute', f'{CHILD}:wave-2:execute', AUTOMATED),
            ('wave-2', 'review', f'{CHILD}:wave-2:review', AUTOMATED),
            ('wave-3', 'execute', f'{CHILD}:wave-3:execute', AUTOMATED),
            ('wave-3', 'review', f'{CHILD}:wave-3:review', AUTOMATED),
            ('wave-4', 'execute', f'{CHILD}:wave-4:execute', AUTOMATED),
        ])
        self.assertEqual(waiting(messages), [
            f'WAITING FOR OPERATOR Ada Lovelace: scope review of {CHILD} wave-1',
            f'WAITING FOR OPERATOR Ada Lovelace: report review of {CHILD} wave-4',
        ])
        self.assertEqual(saved, {f'001-{name}.txt': f'{name} report' for name, _ in PLAN})
        for gate in ('wave-1', 'wave-4'):
            for choice in ('approve', 'deny'):
                self.assertIn(f'decision {CHILD} --step-id {gate} --phase review --choice {choice} '
                              f'--decision-id {CHILD}:{gate}:review --evidence-note ', printed)
        self.assertNotIn('approved (delegated', printed)

    def test_a_serial_hunt_waits_for_the_operator_at_the_scope_and_incident_reviews_and_automates_the_rest(self):
        evidence_retried = dict(RETRIED, step_id='evidence')
        code, decisions, saved, messages, _ = drive_two_decisions([
            serial('awaiting_execution_approval', 'scope'),
            serial('awaiting_review', 'scope', results=[result('x:scope', 'scope report')]),
            serial('awaiting_review', 'scope', results=[result('x:scope', 'scope report')]),
            serial('awaiting_execution_approval', 'evidence'),
            serial('awaiting_execution_approval', 'evidence', [evidence_retried]),
            serial('awaiting_review', 'evidence', [evidence_retried], [result('x:evidence', 'evidence report')]),
            serial('awaiting_execution_approval', 'incident', [evidence_retried]),
            serial('awaiting_review', 'incident', [evidence_retried], [result('x:incident', 'incident report')]),
            serial('awaiting_review', 'incident', [evidence_retried], [result('x:incident', 'incident report')]),
        ])
        self.assertEqual(code, 0)
        self.assertEqual(decisions, [
            ('scope', 'execute', f'{CHILD}:scope:execute', AUTOMATED),
            ('evidence', 'execute', f'{CHILD}:evidence:execute', AUTOMATED),
            ('evidence', 'execute', f'{CHILD}:evidence:execute:retry1', dg.RETRY_NOTE + AUTOMATED),
            ('evidence', 'review', f'{CHILD}:evidence:review', AUTOMATED),
            ('incident', 'execute', f'{CHILD}:incident:execute', AUTOMATED),
        ])
        self.assertEqual(waiting(messages), [
            f'WAITING FOR OPERATOR Ada Lovelace: scope review of {CHILD} scope',
            f'WAITING FOR OPERATOR Ada Lovelace: report review of {CHILD} incident',
        ])
        self.assertEqual(saved, {'001-scope.txt': 'scope report', '001-evidence.txt': 'evidence report',
                                 '001-incident.txt': 'incident report'})

    def test_an_operator_denial_of_the_scope_stops_the_run_with_nothing_sent_for_it(self):
        scope_review = hunt('awaiting_review', 'wave-1', scope='awaiting_review')
        code, decisions, _, messages, _ = drive_two_decisions([
            hunt('awaiting_execution_approval', 'wave-1', scope='awaiting_approval'),
            scope_review, scope_review,
            hunt('denied', 'wave-1', scope='awaiting_review'),
        ])
        self.assertEqual(code, 1)
        self.assertEqual([decision[:2] for decision in decisions], [('wave-1', 'execute')])
        self.assertTrue(messages[-1].startswith(f'STOP {CHILD} wave-1: stage denied; no retry. '))


class ModeChoiceTest(unittest.TestCase):
    def test_exactly_one_mode_must_be_chosen(self):
        rejected = {
            'neither': [],
            'both': ['--two-decisions', '--operator', 'Ada', '--delegated-by', 'Ada', '--reason', 'loop'],
            'two decisions with a reason': ['--two-decisions', '--operator', 'Ada', '--reason', 'loop'],
            'operator without two decisions': ['--operator', 'Ada'],
            'operator in delegated mode': ['--operator', 'Ada', '--delegated-by', 'Ada', '--reason', 'loop'],
            'two decisions without an operator': ['--two-decisions'],
            'blank operator': ['--two-decisions', '--operator', '  '],
            'delegated without a reason': ['--delegated-by', 'Ada'],
            'delegated with a blank reason': ['--delegated-by', 'Ada', '--reason', ' '],
            'card summary in delegated mode': ['--delegated-by', 'Ada', '--reason', 'loop', '--card-summary'],
        }
        for case, argv in rejected.items():
            with self.subTest(case), redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as stopped:
                dg.parse_args(['loop-wf', *argv])
            self.assertEqual(stopped.exception.code, 2)

    def test_each_mode_records_its_own_note(self):
        self.assertEqual((two_decisions().operator, two_decisions().note), ('Ada Lovelace', AUTOMATED))
        delegated = dg.parse_args(['loop-wf', '--delegated-by', 'Ada', '--reason', 'synthetic  loop'])
        self.assertIsNone(delegated.operator)
        self.assertEqual(delegated.note, 'Delegated approval by Ada: synthetic loop. Recorded automatically by '
                                         'operator/drive_gates.py on their behalf; this is not a human review of the '
                                         'content.')


SCOPE_RECORD = 'loop-wf_round_001__wave-1__review.json'
REPORT_RECORD = 'loop-wf_round_001__wave-4__review.json'
OUTSIDE = 'operator (outside driver)'


def parallel_hunt():
    """Status reads of a parallel hunt in which the operator decides both gates while the driver waits."""
    scope_review = hunt('awaiting_review', 'wave-1', scope='awaiting_review')
    report_review = hunt('awaiting_review', 'wave-4', incident='awaiting_review')
    return [hunt('awaiting_execution_approval', 'wave-1', scope='awaiting_approval'),
            scope_review, scope_review, scope_review,
            hunt('awaiting_execution_approval', 'wave-2', evidence='awaiting_approval', network='awaiting_approval'),
            hunt('awaiting_review', 'wave-2', evidence='awaiting_review', network='awaiting_review'),
            hunt('awaiting_execution_approval', 'wave-3', analysis='awaiting_approval'),
            hunt('awaiting_review', 'wave-3', analysis='awaiting_review'),
            hunt('awaiting_execution_approval', 'wave-4', incident='awaiting_approval'),
            report_review, report_review]


def with_output(state, name, text):
    state = copy.deepcopy(state)
    for item in state['results']:
        if item['execution_id'] == f'x:{name}':
            item['output'] = text
    return state


def outside(lines):
    return [(line['gate'], line['choice'], line['channel'], line['decision_id'])
            for line in lines if line['decided_by'] == OUTSIDE]


def slack_line(folder, nonce):
    dg.append_decision(folder, workflow='loop-wf', child=CHILD, gate='wave-1', phase='review', choice='approve',
                       decided_by='human: Ada Lovelace', channel='slack', slack_user='U0ADA',
                       decision_id=f'{CHILD}:wave-1:review:{nonce}', note_sha256='0' * 64)


class DecisionLogTest(unittest.TestCase):
    def test_every_decision_the_driver_sends_is_logged_with_who_decided_and_through_which_channel(self):
        hunted = run(parallel_hunt(), two_decisions())
        sent = [line for line in hunted.lines if line['channel'] == 'drive_gates']
        self.assertEqual([(line['gate'], line['phase'], line['decision_id']) for line in sent],
                         [decision[:3] for decision in hunted.decisions])
        for line, decision in zip(sent, hunted.decisions):
            self.assertEqual((line['workflow'], line['child'], line['choice'], line['decided_by']),
                             ('loop-wf', CHILD, 'approve', 'automated'))
            self.assertEqual(line['note_sha256'], hashlib.sha256(decision[3].encode('utf-8')).hexdigest())
            self.assertRegex(line['ts'], r'^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$')
        delegated = run([child('awaiting_execution_approval')])
        self.assertEqual([(line['decided_by'], line['channel'], line['phase'], line['decision_id'])
                          for line in delegated.lines],
                         [('delegated: Ada', 'drive_gates', 'execute', f'{CHILD}:evidence:execute')])

    def test_a_pending_record_is_written_once_per_operator_gate_and_deleted_when_the_gate_moves_on(self):
        hunted = run(parallel_hunt(), two_decisions())
        # Status read 2 opens the scope gate and read 5 shows wave 2; read 10 opens the report gate.
        self.assertEqual([SCOPE_RECORD in seen for seen in hunted.seen], [False] * 2 + [True] * 3 + [False] * 7)
        self.assertEqual([REPORT_RECORD in seen for seen in hunted.seen], [False] * 10 + [True] * 2)
        self.assertEqual(hunted.left, [])
        scope = [seen[SCOPE_RECORD] for seen in hunted.seen if SCOPE_RECORD in seen]
        report = [seen[REPORT_RECORD] for seen in hunted.seen if REPORT_RECORD in seen]
        self.assertEqual(len({record['nonce'] for record in scope}), 1)
        self.assertEqual(len({record['nonce'] for record in report}), 1)
        self.assertNotEqual(scope[0]['nonce'], report[0]['nonce'])
        for record, gate, kind in ((scope[0], 'wave-1', 'scope'), (report[0], 'wave-4', 'report')):
            self.assertRegex(record['nonce'], r'^[0-9a-f]{32}$')
            self.assertEqual({key: record[key] for key in ('child', 'workflow', 'gate', 'phase', 'kind')},
                             {'child': CHILD, 'workflow': 'loop-wf', 'gate': gate, 'phase': 'review', 'kind': kind})
            self.assertEqual(record['decision_cli'][-6:], ['decision', CHILD, '--step-id', gate, '--phase', 'review'])
            self.assertNotIn('--evidence-note', record['decision_cli'])
            self.assertNotIn('--choice', record['decision_cli'])
            self.assertTrue(record['outputs_dir'].endswith(str(Path('outputs', 'loop-wf'))))
            self.assertNotIn('summary', record)
        # Nobody logged these two decisions through the bridge, so the driver names them as made outside it.
        self.assertEqual(outside(hunted.lines), [('wave-1', 'approve', 'unknown', None),
                                                 ('wave-4', 'approve', 'unknown', None)])

    def test_a_decision_the_bridge_logged_gets_no_outside_driver_line(self):
        def bridge(call, folder):
            pending = folder / 'pending' / SCOPE_RECORD
            if call == 4:
                nonce = json.loads(pending.read_text(encoding='utf-8'))['nonce']
                pending.unlink()
                slack_line(folder, nonce)

        hunted = run(parallel_hunt(), two_decisions(), on_status=bridge)
        self.assertEqual(outside(hunted.lines), [('wave-4', 'approve', 'unknown', None)])
        self.assertEqual([line['channel'] for line in hunted.lines if line['decided_by'].startswith('human')],
                         ['slack'])
        self.assertIn(f'scope review of {CHILD} wave-1 decided via slack by human: Ada Lovelace: approve',
                      hunted.messages)

    def test_a_record_the_bridge_claimed_is_given_time_to_be_logged_before_anything_is_written(self):
        claim = {}

        def bridge_claims(call, folder):
            if call == 5:
                claim['path'] = folder / 'claimed' / SCOPE_RECORD
                claim['folder'] = folder
                claim['path'].parent.mkdir(parents=True, exist_ok=True)
                claim['nonce'] = json.loads((folder / 'pending' / SCOPE_RECORD).read_text(encoding='utf-8'))['nonce']
                (folder / 'pending' / SCOPE_RECORD).rename(claim['path'])

        def bridge_finishes(_seconds):
            if claim.get('path') and claim['path'].exists():
                slack_line(claim['folder'], claim['nonce'])
                claim['path'].unlink()

        hunted = run(parallel_hunt(), two_decisions(), on_status=bridge_claims, sleep=bridge_finishes)
        self.assertEqual(outside(hunted.lines), [('wave-4', 'approve', 'unknown', None)])
        self.assertEqual(len([line for line in hunted.lines if line['channel'] == 'slack']), 1)

    def test_the_observed_outcome_of_an_outside_decision_is_logged_and_a_timeout_is_not_a_decision(self):
        scope_review = hunt('awaiting_review', 'wave-1', scope='awaiting_review')
        for stage, expected in (('rejected', [('wave-1', 'deny', 'unknown', None)]), ('timed_out', [])):
            with self.subTest(stage):
                hunted = run([hunt('awaiting_execution_approval', 'wave-1', scope='awaiting_approval'),
                              scope_review, scope_review, hunt(stage, 'wave-1', scope='awaiting_review')],
                             two_decisions())
                self.assertEqual((hunted.code, outside(hunted.lines), hunted.left), (1, expected, []))

    def test_a_card_summary_is_written_only_with_card_summary_capped_and_without_control_characters(self):
        scope_text = 'Scope: hosts ws-01 and ws-02.\x1b[31m\u202e' + 'x' * 5000
        report_text = 'The report:\n' + json.dumps({'claims': [{'statement': f'claim {n}'} for n in range(1, 6)],
                                                    'disposition': 'review_ready'})
        states = [with_output(with_output(state, 'scope', scope_text), 'incident', report_text)
                  for state in parallel_hunt()]
        args = dg.parse_args(['loop-wf', '--two-decisions', '--operator', 'Ada', '--card-summary'])
        hunted = run(states, args)
        scope = next(seen[SCOPE_RECORD] for seen in hunted.seen if SCOPE_RECORD in seen)['summary']
        report = next(seen[REPORT_RECORD] for seen in hunted.seen if REPORT_RECORD in seen)['summary']
        self.assertTrue(scope.startswith('Bot-written, unverified: Scope: hosts ws-01 and ws-02.[31mxxx'), scope[:80])
        self.assertEqual(len(scope), dg.SUMMARY_LIMIT)
        self.assertFalse(re.search('[\x00-\x09\x0b-\x1f\x7f\u202a-\u202e\u2066-\u2069]', scope))
        self.assertEqual(report, 'Bot-written, unverified: Verdict: review_ready\n- claim 1\n- claim 2\n- claim 3')
        plain = run(states, two_decisions())
        self.assertFalse(any('summary' in record for seen in plain.seen for record in seen.values()))


class CliRetryTest(unittest.TestCase):
    def outcomes(self, *results):
        calls = []

        def fake_run(argv, **_kwargs):
            calls.append(argv)
            return results[len(calls) - 1]
        return calls, fake_run

    def test_a_transient_rpc_error_is_retried_and_a_lasting_one_fails(self):
        rpc = SimpleNamespace(returncode=2, stdout='', stderr='error: operation failed (RPCError)')
        ok = SimpleNamespace(returncode=0, stdout='{"stage": "executing"}', stderr='')
        calls, fake_run = self.outcomes(rpc, ok)
        with patch.object(dg.subprocess, 'run', fake_run), patch.object(dg.time, 'sleep'), patch.object(dg, 'log'):
            self.assertEqual(dg.cli('status', CHILD), {'stage': 'executing'})
        self.assertEqual(len(calls), 2)
        calls, fake_run = self.outcomes(rpc, rpc, rpc)
        with patch.object(dg.subprocess, 'run', fake_run), patch.object(dg.time, 'sleep'), patch.object(dg, 'log'):
            with self.assertRaisesRegex(RuntimeError, 'failed three times'):
                dg.cli('status', CHILD)
        self.assertEqual(len(calls), 3)

    def test_other_failures_are_not_retried(self):
        bad = SimpleNamespace(returncode=2, stdout='', stderr='error: operation failed (ValueError)')
        calls, fake_run = self.outcomes(bad)
        with patch.object(dg.subprocess, 'run', fake_run), patch.object(dg.time, 'sleep'), patch.object(dg, 'log'):
            with self.assertRaisesRegex(RuntimeError, 'status exit 2'):
                dg.cli('status', CHILD)
        self.assertEqual(len(calls), 1)


if __name__ == '__main__':
    unittest.main()

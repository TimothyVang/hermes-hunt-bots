"""drive_gates behavior that an unattended loop round depends on."""
import argparse
import tempfile
import unittest
from pathlib import Path
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


def drive(states):
    """Run the driver over these child statuses; the parent reports completed once they are used up.
    Returns (exit code, decisions sent, saved outputs by file name, log messages)."""
    states, decisions = list(states), []

    def fake_cli(*args):
        if args[0] == 'practice-status':
            if states:
                return {'temporal_status': 'RUNNING', 'stage': 'running_round', 'child_workflow_id': CHILD}
            return {'temporal_status': 'COMPLETED', 'stage': 'completed'}
        if args[0] == 'status':
            return states.pop(0)
        options = dict(zip(args[2::2], args[3::2]))
        decisions.append((options['--step-id'], options['--phase'], options['--decision-id'],
                          options['--evidence-note']))
        return {'signal_sent': True}

    args = argparse.Namespace(workflow_id='loop-wf', delegated_by='Ada', reason='synthetic loop', note='NOTE')
    with tempfile.TemporaryDirectory() as tmp, patch.object(dg, 'GATE_RUNS', Path(tmp)), \
            patch.object(dg, 'LOG', Path(tmp) / 'driver.log'), patch.object(dg, 'cli', fake_cli), \
            patch.object(dg.time, 'sleep'):
        code = dg.main(args)
        saved = {path.name: path.read_text(encoding='utf-8') for path in (Path(tmp) / 'outputs' / 'loop-wf').iterdir()}
        log = (Path(tmp) / 'driver.log').read_text(encoding='utf-8').splitlines()
    return code, decisions, saved, [line.split(' ', 1)[1] for line in log]


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

        args = argparse.Namespace(workflow_id='loop-wf', delegated_by='Ada', reason='synthetic loop', note='NOTE')
        with tempfile.TemporaryDirectory() as tmp, patch.object(dg, 'GATE_RUNS', Path(tmp)), \
                patch.object(dg, 'LOG', Path(tmp) / 'driver.log'), patch.object(dg, 'cli', fake_cli), \
                patch.object(dg.time, 'sleep'):
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


if __name__ == '__main__':
    unittest.main()

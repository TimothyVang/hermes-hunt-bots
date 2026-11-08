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


if __name__ == '__main__':
    unittest.main()

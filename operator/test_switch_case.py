"""switch_case: restarting the container project and readiness of the new case."""
import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import switch_case


class ReadyTest(unittest.TestCase):
    def test_only_the_named_case_with_events_counts_as_ready(self):
        # The resolver asks only the instance the case's state.json names, so a restarted lab's previous
        # instance never answers; readiness is the case, its ready flag and its events.
        served = {'ready': True, 'event_count': 20931, 'case_id': 'lab-med-001'}
        self.assertTrue(switch_case.ready(served))
        self.assertTrue(switch_case.ready(served, 'lab-med-001'))
        self.assertFalse(switch_case.ready(served, 'team-med-004'))
        self.assertFalse(switch_case.ready({**served, 'ready': False}, 'lab-med-001'))
        self.assertFalse(switch_case.ready({**served, 'event_count': 0}, 'lab-med-001'))


class SwitchTest(unittest.TestCase):
    def test_switch_restarts_the_container_project(self):
        with tempfile.TemporaryDirectory() as tmp:
            evidence = Path(tmp) / 'evidence'
            evidence.mkdir()
            (evidence / 'case.json').write_text('{"case_id": "lab-med-001"}', encoding='utf-8')
            commands = []

            def run(cmd, **kwargs):
                commands.append(cmd)
                action = cmd[cmd.index('hunt-lab') + 1]
                result = ({'origin': 'container', 'state': 'stopped', 'reason': 'stopped', 'case_id': 'team-med-004'}
                          if action == 'stop' else
                          {'origin': 'container', 'state': 'starting', 'reason': 'loading_case', 'case_id': 'lab-med-001'})
                return Mock(returncode=0, stdout=json.dumps(result) + '\n', stderr='')
            served = Mock(lab_url='http://127.0.0.1:41000', arkime_url='http://127.0.0.1:41002')
            served.get.return_value = {'ready': True, 'event_count': 20931, 'case_id': 'lab-med-001'}
            with patch.object(switch_case.subprocess, 'run', run), \
                    patch.object(switch_case, 'resolve', return_value=served) as resolve, \
                    patch.object(switch_case.DEFAULT_LANE.__class__, 'hermes_exe', lambda self: 'hermes'), \
                    patch.object(switch_case.time, 'sleep'), \
                    patch.object(sys, 'argv', ['switch_case.py', str(evidence)]), \
                    contextlib.redirect_stdout(io.StringIO()):
                switch_case.main()
        # Exactly these two hunt-lab calls: no other lab is chosen and no other child runs.
        hunt_lab = ['hermes', '-p', 'framework-network-analyst', 'hunt-lab']
        self.assertEqual(commands, [hunt_lab + ['stop'],
                                    hunt_lab + ['start', '--evidence-dir', str(evidence.resolve()),
                                                '--wait', str(switch_case.START_WAIT)]])
        resolve.assert_called_with(switch_case.DEFAULT_LANE.state_dir, 'lab-med-001', profile='hunt-board')


if __name__ == '__main__':
    unittest.main()

"""The operator lane refuses to name the lab's Hermes while a Hermes update holds its home. No lab is touched.

Run from the repository root: python -m unittest discover -s operator -p "test_lab_paths.py"
"""
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from lab_paths import Lane


class LaneUpdateGuardTest(unittest.TestCase):
    def test_hermes_exe_refuses_while_the_home_holds_an_update_marker(self):
        # Review of #51: switch_case, tool_loops, team_probe and film_loop reach the lab's Hermes through this.
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / 'lab-home'
            home.mkdir()
            lane = Lane(name='t', home=home, exe=sys.executable)
            with patch.dict(os.environ, {'LAB_HERMES_EXE': sys.executable}):
                self.assertEqual(Path(lane.hermes_exe()).resolve(), Path(sys.executable).resolve())
                marker = home / '.hermes-update-in-progress'
                dead = subprocess.Popen([sys.executable, '-c', 'pass'])
                dead.wait()
                head = f'{dead.pid}\n2026-11-11T16:06:00Z\nct:1.000\n'
                # Owner alive; owner gone but its delegate running; owner and delegate both gone.
                for body, message in ((f'{os.getpid()}\n', 'update is in progress'),
                                      (head + f'delegate:{os.getpid()} ct:2.000\n', 'update is in progress'),
                                      (head + f'delegate:{dead.pid} ct:2.000\n', 'stale Hermes update marker')):
                    marker.write_text(body)
                    with self.subTest(body=body), self.assertRaises(SystemExit) as caught:
                        lane.hermes_exe()
                    self.assertIn(message, str(caught.exception))
                    self.assertIn(str(marker), str(caught.exception))
            self.assertTrue(marker.exists())


if __name__ == '__main__':
    unittest.main()

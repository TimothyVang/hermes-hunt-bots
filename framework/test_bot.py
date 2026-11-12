from contextlib import closing
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


BOT = Path(__file__).with_name('bot.py')


class ExecutionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.workspace = Path(self.temp.name) / 'workspace'
        self.call('init')
        self.call('add', '--title', 'Example', '--role', 'researcher',
                  '--scope', 'A bounded task', '--acceptance', 'A real result')
        self.call('start', '1')

    def call(self, *args, success=True, env=None):
        result = subprocess.run([sys.executable, str(BOT), '-w', str(self.workspace), *args],
                                capture_output=True, text=True, env=env)
        self.assertEqual(result.returncode == 0, success, result.stderr)
        return result

    def state(self):
        with closing(sqlite3.connect(self.workspace / 'workflow.sqlite3')) as db:
            return db.execute('SELECT status FROM tasks WHERE id=1').fetchone()[0]


    def test_nonzero_exit_blocks_and_records_stderr(self):
        self.call('run', '--adapter', 'generic', '1', '--', sys.executable, '-m', 'json.tool', success=False)
        self.assertEqual(self.state(), 'blocked')
        with closing(sqlite3.connect(self.workspace / 'workflow.sqlite3')) as db:
            path = db.execute("SELECT path FROM artifacts WHERE description='CLI stderr'").fetchone()[0]
        self.assertTrue(Path(path).read_bytes())

    def test_timeout_blocks_instead_of_submitting(self):
        result = self.call('run', '--adapter', 'generic', '--timeout', '1', '1', '--',
                           sys.executable, '-c', 'import time; time.sleep(10)', success=False)
        self.assertIn('timed out', result.stderr)
        self.assertEqual(self.state(), 'blocked')

    def test_running_reservation_requires_explicit_recovery(self):
        with closing(sqlite3.connect(self.workspace / 'workflow.sqlite3')) as db, db:
            db.execute("UPDATE tasks SET status='running' WHERE id=1")
        self.call('run', '--adapter', 'generic', '1', '--', sys.executable, '-m', 'base64', success=False)
        self.assertEqual(self.state(), 'running')
        self.call('recover-run', '1', '--by', 'human', '--note', 'Checked process and output')
        self.assertEqual(self.state(), 'blocked')

    def test_missing_hermes_executable_is_refused_before_launch(self):
        missing = str(self.workspace / 'missing-hermes-executable')
        result = self.call('run', '--adapter', 'hermes', '--profile', 'researcher',
                           '--allow-profile-config', '--executable', missing, '1', success=False)
        self.assertIn(missing, result.stderr)
        self.assertEqual(self.state(), 'active')
        environment = {**os.environ, 'LAB_HERMES_EXE': missing}
        result = self.call('run', '--adapter', 'hermes', '--profile', 'researcher',
                           '--allow-profile-config', '1', success=False, env=environment)
        self.assertIn(f'LAB_HERMES_EXE: {missing}', result.stderr)
        self.assertEqual(self.state(), 'active')

    def test_run_uses_lab_hermes_exe(self):
        # A different `hermes` first on PATH must not run; Python stands in for the lab CLI and
        # names itself in its usage error for the Hermes arguments.
        on_path = Path(self.temp.name) / 'path-bin'
        on_path.mkdir()
        decoy = on_path / ('hermes.exe' if os.name == 'nt' else 'hermes')
        decoy.write_bytes(b'')
        decoy.chmod(0o755)
        environment = {**os.environ, 'PATH': str(on_path) + os.pathsep + os.environ.get('PATH', ''),
                       'LAB_HERMES_EXE': sys.executable}
        self.call('run', '--adapter', 'hermes', '--profile', 'researcher',
                  '--allow-profile-config', '1', success=False, env=environment)
        self.assertEqual(self.state(), 'blocked')
        with closing(sqlite3.connect(self.workspace / 'workflow.sqlite3')) as db:
            path = db.execute("SELECT path FROM artifacts WHERE description='CLI stderr'").fetchone()[0]
        stderr = Path(path).read_text(encoding='utf-8', errors='replace')
        self.assertIn('unknown option --profile', stderr)
        self.assertNotIn(str(decoy), stderr)

    def events(self):
        with closing(sqlite3.connect(self.workspace / 'workflow.sqlite3')) as db:
            return db.execute('SELECT kind, actor, note FROM events WHERE task_id=1 ORDER BY id').fetchall()

    def test_auto_resume_is_a_distinct_automated_transition(self):
        self.call('run', '--adapter', 'generic', '1', '--', sys.executable, '-m', 'json.tool', success=False)
        for actor in ('alice', 'operator', 'Benchmark-auto-reconcile'):
            with self.subTest(actor=actor):
                result = self.call('auto-resume', '--id', '1', '--by', actor, '--note', 'n', success=False)
                self.assertIn('benchmark-auto', result.stderr)
                self.assertEqual(self.state(), 'blocked')
        self.call('auto-resume', '--id', '1', '--by', 'benchmark-auto-reconcile', '--note', 'Automatic reconciliation')
        self.assertEqual(self.state(), 'active')
        self.assertEqual(self.events()[-1], ('auto_resume', 'benchmark-auto-reconcile', 'Automatic reconciliation'))
        self.assertNotIn('resume', [kind for kind, _, _ in self.events()])
        # Only blocked -> active; never from any other state.
        self.call('auto-resume', '--id', '1', '--by', 'benchmark-auto-reconcile', '--note', 'n', success=False)
        self.assertEqual(self.state(), 'active')

    def test_profile_options_rejected_before_reservation(self):
        cases = [
            ('--adapter', 'hermes', '1'),
            ('--adapter', 'hermes', '--model=-invalid', '1'),
            ('--adapter', 'hermes', '--profile', 'researcher', '--allow-profile-config',
             '--model', 'some-model', '1'),
            ('--adapter', 'generic', '--model', 'some-model', '1', '--', sys.executable),
            ('--adapter', 'hermes', '--profile', 'researcher', '1'),
            ('--adapter', 'hermes', '--allow-profile-config', '1'),
            ('--adapter', 'generic', '--profile', 'researcher', '--allow-profile-config',
             '1', '--', sys.executable),
            ('--adapter', 'hermes', '--profile', '../other', '--allow-profile-config', '1'),
            ('--adapter', 'hermes', '--profile=-bad', '--allow-profile-config', '1'),
            ('--adapter', 'hermes', '--profile', 'researcher', '--allow-profile-config',
             '1', '--', '--yolo'),
        ]
        # A resolvable LAB_HERMES_EXE, so only the option checks can keep the task active.
        environment = {**os.environ, 'LAB_HERMES_EXE': sys.executable}
        for options in cases:
            with self.subTest(options=options):
                self.call('run', *options, success=False, env=environment)
                self.assertEqual(self.state(), 'active')

    def test_generic_launch_failure_blocks_task(self):
        missing = str(self.workspace / 'missing-agent.exe')
        self.call('run', '--adapter', 'generic', '1', '--', missing, success=False)
        self.assertEqual(self.state(), 'blocked')


class AutoAdvanceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.workspace = Path(self.temp.name) / 'workspace'
        self.call('init')
        self.call('workflow', 'create', 'threat-hunt', '--title', 'Example', '--scope', 'Bounded scope',
                  '--acceptance', 'A real result')
        self.call('start', '1')
        self.call('submit', '1', '--by', 'test-only-runner', '--note', 'Synthetic submission')

    def call(self, *args, success=True):
        result = subprocess.run([sys.executable, str(BOT), '-w', str(self.workspace), *args],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode == 0, success, result.stderr)
        return result

    def events(self):
        with closing(sqlite3.connect(self.workspace / 'workflow.sqlite3')) as db:
            return db.execute('SELECT kind, actor, note FROM events WHERE task_id=1 ORDER BY id').fetchall()

    def state(self):
        with closing(sqlite3.connect(self.workspace / 'workflow.sqlite3')) as db:
            return db.execute('SELECT status FROM tasks WHERE id=1').fetchone()[0]

    def test_auto_advance_is_a_distinct_unreviewed_transition(self):
        self.call('auto-advance', '--id', '1', '--by', 'benchmark-auto-advance', '--note', 'unreviewed automatic advance')
        self.assertEqual(self.state(), 'done')
        self.assertEqual(self.events()[-1], ('auto_advance', 'benchmark-auto-advance', 'unreviewed automatic advance'))
        self.assertNotIn('approve', [kind for kind, _, _ in self.events()])
        self.assertIn('Status: done, auto-advanced (unreviewed)', self.call('show', '1').stdout)
        status = self.call('workflow', 'status', '1').stdout
        self.assertIn('[done, auto-advanced (unreviewed)]', status)
        # A dependent task may start exactly as after an approval.
        self.assertIn('2 [pending]', self.call('ready').stdout)

    def test_human_like_actor_is_refused(self):
        for actor in ('alice', 'operator', 'benchmark-runner', 'Benchmark-auto-advance'):
            with self.subTest(actor=actor):
                result = self.call('auto-advance', '--id', '1', '--by', actor, '--note', 'n', success=False)
                self.assertIn('benchmark-auto', result.stderr)
                self.assertEqual(self.state(), 'review')
        self.assertEqual(self.events()[-1][0], 'submit')

    def test_requires_review_status_and_approval_display_is_unchanged(self):
        self.call('approve', '1', '--by', 'human', '--note', 'Checked')
        self.call('auto-advance', '--id', '1', '--by', 'benchmark-auto-advance', '--note', 'n', success=False)
        show = self.call('show', '1').stdout
        self.assertIn('Status: done\n', show)
        self.assertNotIn('auto-advanced', show)


if __name__ == '__main__':
    unittest.main()

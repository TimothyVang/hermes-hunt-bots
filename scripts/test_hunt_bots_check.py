"""hunt_bots_check: the gate fails on a missing test package, runs every suite, and logs every test.

Run from the repository root: python -m unittest scripts.test_hunt_bots_check
Each case runs the gate's test stage against small throwaway suites, with stub modules standing in for
the required packages, so it needs no Temporal and takes seconds.
"""
import contextlib
import importlib.util
import io
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

SPEC = importlib.util.spec_from_file_location('hunt_bots_check', Path(__file__).with_name('hunt_bots_check.py'))
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)

PASSING = 'import unittest\n\nclass Good(unittest.TestCase):\n    def test_holds(self):\n        self.assertTrue(True)\n'


def failing(name):
    return f'import unittest\n\nclass Broken(unittest.TestCase):\n    def {name}(self):\n        self.assertEqual(1, 2)\n'


class GateTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        self.root = self.tmp / 'repo'
        self.stubs = self.tmp / 'stubs'
        for folder in (self.root / 'framework', self.root / 'operator', self.root / 'scripts', self.stubs):
            folder.mkdir(parents=True)
        for module in gate.REQUIRED_MODULES:
            (self.stubs / f'{module}.py').write_text('', encoding='utf-8')
        self.write('framework', 'test_good.py', PASSING)
        self.write('operator', 'test_good.py', PASSING)
        self.write('scripts', 'test_hunt_bots_check.py', PASSING)
        self.write('scripts', 'test_not_the_gate.py', failing('test_outside_the_gate_suite'))
        for patch in (mock.patch.object(gate, 'ROOT', self.root),
                      mock.patch.object(gate, 'policy_problems', return_value=(3, [])),
                      mock.patch.object(gate.shutil, 'which', side_effect=self.which_without_gitleaks),
                      mock.patch.dict(os.environ, {'PYTHONPATH': str(self.stubs)})):
            patch.start()
            self.addCleanup(patch.stop)

    @staticmethod
    def which_without_gitleaks(name, which=gate.shutil.which):
        return None if name == 'gitleaks' else which(name)

    def write(self, folder, name, text):
        (self.root / folder / name).write_text(text, encoding='utf-8')

    def run_gate(self, *argv, python=sys.executable):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = gate.main(['--python', python, *argv])
        lines = out.getvalue().splitlines()
        return code, lines[-1], out.getvalue()

    def test_passes_when_every_suite_passes(self):
        code, summary, _ = self.run_gate()
        self.assertEqual(code, 0, summary)
        self.assertIn('framework tests: Ran 1 test', summary)
        self.assertIn('operator tests: Ran 1 test', summary)
        self.assertIn('gate tests: Ran 1 test', summary)
        self.assertTrue(summary.endswith('-> PASS'), summary)

    def test_fails_when_temporalio_is_missing(self):
        (self.stubs / 'temporalio.py').write_text("raise ImportError('temporalio is not installed')\n", encoding='utf-8')
        with mock.patch.object(gate, 'run_suite') as run_suite:
            code, summary, _ = self.run_gate()
        self.assertEqual(code, 1)
        self.assertTrue(summary.endswith('missing: temporalio  -> FAIL'), summary)
        run_suite.assert_not_called()

    def test_fails_when_the_test_python_does_not_run(self):
        code, summary, _ = self.run_gate(python=str(self.tmp / 'no-such-python.exe'))
        self.assertEqual(code, 1)
        self.assertIn('does not run', summary)
        self.assertTrue(summary.endswith('-> FAIL'), summary)

    def test_relative_python_is_resolved_from_the_callers_folder(self):
        try:
            relative = os.path.relpath(sys.executable, self.tmp)
        except ValueError:
            self.skipTest('the interpreter and the temporary folder are on different drives')
        self.addCleanup(os.chdir, os.getcwd())
        os.chdir(self.tmp)
        code, summary, _ = self.run_gate(python=relative)
        self.assertEqual(code, 0, summary)

    def test_bare_python_name_is_resolved_on_path(self):
        folder, name = os.path.split(sys.executable)
        with mock.patch.dict(os.environ, {'PATH': folder + os.pathsep + os.environ.get('PATH', '')}):
            code, summary, out = self.run_gate(python=os.path.splitext(name)[0])
        self.assertEqual(code, 0, summary)
        self.assertIn(f'testing with {os.path.join(folder, name)}'.lower(), out.lower())

    def test_log_keeps_non_ascii_failure_text(self):
        self.write('framework', 'test_broken.py', failing('test_arrow').replace('1, 2', "'a \\u2192 b', 'a'"))
        log = self.tmp / 'gate.log'
        code, summary, _ = self.run_gate('--log', str(log))
        self.assertEqual(code, 1, summary)
        self.assertIn('a \u2192 b', log.read_text(encoding='utf-8'))

    def test_python_defaults_to_hunt_bots_python(self):
        with mock.patch.dict(os.environ, {'HUNT_BOTS_PYTHON': str(self.tmp / 'chosen-python.exe')}), \
                mock.patch.object(gate, 'run_tests', return_value=False) as run_tests, \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(gate.main([]), 0)
        self.assertEqual(run_tests.call_args.args[0], str(self.tmp / 'chosen-python.exe'))

    def test_operator_failure_fails_the_gate(self):
        self.write('operator', 'test_broken.py', failing('test_operator_breaks'))
        code, summary, out = self.run_gate()
        self.assertEqual(code, 1)
        self.assertIn('framework tests: Ran 1 test', summary)
        self.assertIn('operator tests: Ran 2 tests', summary)
        self.assertIn('FAILED (failures=1)', summary)
        self.assertTrue(summary.endswith('-> FAIL'), summary)
        self.assertIn('operator tests failed: FAIL: test_operator_breaks (test_broken.Broken', out)

    def test_log_names_the_failing_test(self):
        self.write('framework', 'test_broken.py', failing('test_framework_breaks'))
        log = self.tmp / 'new' / 'dir' / 'gate.log'
        code, summary, _ = self.run_gate('--log', str(log))
        self.assertEqual(code, 1)
        text = log.read_text(encoding='utf-8')
        self.assertIn('test_framework_breaks (test_broken.Broken', text)
        self.assertIn('FAIL: test_framework_breaks', text)
        for name in ('test_holds (test_good.Good', 'framework tests (framework/)', 'operator tests (operator/)'):
            self.assertIn(name, text)

    def test_policy_only_runs_no_tests(self):
        with mock.patch.object(gate, 'run_tests') as run_tests:
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(gate.main(['--policy']), 0)
        run_tests.assert_not_called()
        self.assertEqual(out.getvalue().strip(), 'hunt-bots-check: policy: 3 tracked files, 0 problem(s)  -> PASS')


if __name__ == '__main__':
    unittest.main()

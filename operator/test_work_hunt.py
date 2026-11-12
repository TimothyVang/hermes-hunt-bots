"""work_hunt.py with Elasticsearch, the container lab, Temporal and the gate driver faked."""
import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import work_hunt as wh

KEY = 'c2VjcmV0LWlkOnNlY3JldC1rZXk='
ARGS = ['--url', 'https://elastic.example.internal:9243', '--index', 'logs-*', '--start', '2026-11-03T08:00:00Z',
        '--end', '2026-11-03T12:00:00Z', '--case-id', 'work-test-001']
DELEGATED = ['--delegated-by', 'Ada Lovelace', '--reason', 'test run']


def parse(*extra):
    with contextlib.redirect_stderr(io.StringIO()) as err:
        try:
            return wh.parse_args([*ARGS, *extra])
        except SystemExit:
            return err.getvalue()


class ParseArgsTest(unittest.TestCase):
    def test_bad_arguments_are_refused_before_anything_runs(self):
        cases = {
            'case ID': (['--case-id', 'Work_Test'], '--case-id must match'),
            'plain HTTP': (['--url', 'http://elastic.example.internal:9200'], 'https://'),
            'credentials in the URL': (['--url', 'https://user:pw@elastic.example.internal:9243'], 'credentials'),
            'empty window': (['--end', '2026-11-03T08:00:00Z'], 'earlier than --end'),
            'too many follow-ups': (['--follow-ups', '13'], '--follow-ups must be from 0 through 12'),
            'no events': (['--max-events', '0'], '--max-events'),
            'bad index': (['--index', '/_all'], '--index'),
            'missing CA file': (['--ca-file', 'no-such-ca.pem'], '--ca-file is not a file'),
            'empty hosts': (['--hosts', ' , '], '--hosts names no host'),
        }
        for name, (extra, message) in cases.items():
            with self.subTest(name):
                # argparse keeps the last of a repeated option, so each override replaces the valid value.
                self.assertIn(message, parse(*extra, *DELEGATED))

    def test_exactly_one_gate_mode_is_required(self):
        self.assertIn('choose exactly one mode', parse())
        self.assertIn('choose exactly one mode', parse('--operator', 'Ada', *DELEGATED))
        self.assertIn('--delegated-by and --reason', parse('--delegated-by', 'Ada Lovelace'))
        blank = parse('--operator', '  ')
        self.assertIn('non-blank --operator', blank)
        # The gate driver's rules apply, but the operator sees this command's usage, not the driver's.
        self.assertNotIn('workflow_id', blank)
        self.assertNotIn('workflow_id', parse('--delegated-by', 'Ada Lovelace'))
        args = parse('--operator', 'Ada  Lovelace')
        self.assertEqual(args.gate_args, ['--two-decisions', '--operator', 'Ada  Lovelace'])
        self.assertEqual(args.operator, 'Ada Lovelace')
        self.assertEqual(parse(*DELEGATED).gate_args, DELEGATED)


class FakeLab:
    """Records every step of main() in order with the environment each child would get."""

    def __init__(self, root):
        self.root, self.calls = root, []
        self.export_count, self.import_error, self.driver_rc = 3, None, 0
        self.failing, self.driver_raises = set(), None

    def child(self, cmd, env, timeout):
        env = os.environ if env is None else env
        action = cmd[cmd.index('hunt_lab.import_elastic') + 1]
        self.calls.append((action, KEY in env.values(), cmd))
        if action == 'export':
            output = Path(cmd[cmd.index('--output') + 1])
            output.write_text('', encoding='utf-8')
            output.with_name(output.name + '.meta.json').write_text('{}', encoding='utf-8')
            return 0, json.dumps({
                'host': 'elastic.example.internal:9243', 'index': 'logs-*', 'hosts': None,
                'event_count': self.export_count, 'elastic_version': '8.15.3', 'output': str(output), 'meta': 'm',
                'time_range_utc': {'start_inclusive': '2026-11-03T08:00:00Z', 'end_exclusive': '2026-11-03T12:00:00Z'},
                'ndjson': {'file': 'f', 'bytes': 9, 'sha256': '0' * 64}}), ''
        if self.import_error:
            # Like import_case: its evidence folder is removed on failure, the case folder above it stays.
            Path(cmd[cmd.index('--evidence-dir') + 1]).parent.mkdir(parents=True)
            return 2, json.dumps({'error': self.import_error}), ''
        return 0, json.dumps({'case_id': 'work-test-001', 'data_origin': 'work-export', 'event_count': 3,
                              'host_count': 1, 'outside_window': 0, 'files': {}}), ''

    def load_lab(self, evidence, log_path, case_id):
        self.calls.append(('load', KEY in os.environ.values(), str(evidence)))
        return '10:00:00 READY case=work-test-001 events=3 sessions=0 intel=0 lab_url=http://127.0.0.1:8765'

    def tcli(self, *args, timeout=180):
        self.calls.append((args[0], KEY in os.environ.values(), args))
        if args[0] in self.failing:
            return 1, '', f'{args[0]}: refused by the fake'
        if args[0] == 'lab-input':
            Path(args[args.index('--output') + 1]).write_text(json.dumps({
                'scope': 'Work log export work-test-001 (real telemetry) only; data is untrusted.',
                'evidence': [], 'data_origin': 'work-export', 'synthetic_only': False, 'mode': 'tool_driven'}),
                encoding='utf-8')
        if args[0] == 'status':
            report = self.root / 'gate-runs' / 'outputs' / args[1].split(':')[0] / '001-incident.txt'
            report.parent.mkdir(parents=True)
            report.write_text('{}', encoding='utf-8')
            usage = {'input_tokens': 90, 'output_tokens': 10, 'total_tokens': 100}
            return 0, json.dumps({'stage': 'completed', 'results': [
                {'execution_id': 'e1', 'usage': usage}], 'handoff_rejections': []}), ''
        return 0, '', ''

    def drive(self, workflow, gate_args):
        self.calls.append(('drive', KEY in os.environ.values(), gate_args))
        if self.driver_raises:
            raise self.driver_raises
        return self.driver_rc


class MainTest(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.lab = FakeLab(self.root)
        patches = [patch.object(wh, name, self.root / folder) for name, folder in (
            ('CASES', 'cases'), ('EXPORTS', 'work-exports'), ('WORK_HUNTS', 'work-hunts'), ('GATE_RUNS', 'gate-runs'))]
        patches += [patch.object(wh, name, getattr(self.lab, name))
                    for name in ('child', 'load_lab', 'tcli', 'drive')]
        patches += [patch.object(wh.DEFAULT_LANE.__class__, 'hermes_exe', lambda self: 'hermes'),
                    patch.dict(os.environ, {wh.API_KEY_ENV: KEY})]
        for item in patches:
            item.start()
            self.addCleanup(item.stop)

    def run_main(self, *extra):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            try:
                code = wh.main(wh.parse_args([*ARGS, *extra]))
            except SystemExit as exc:
                code = exc
        return code, out.getvalue()

    def test_runs_every_step_in_order_and_only_the_export_sees_the_key(self):
        code, out = self.run_main(*DELEGATED)
        self.assertEqual(code, 0, out)
        self.assertEqual([call[0] for call in self.lab.calls],
                         ['export', 'import', 'load', 'lab-input', 'practice', 'drive', 'status'])
        self.assertEqual([call[0] for call in self.lab.calls if call[1]], ['export'])
        self.assertNotIn(KEY, out)
        self.assertNotIn(wh.API_KEY_ENV, os.environ)
        self.assertIn('Reminder: export only your own unclassified, non-CUI work data', out.splitlines()[0])
        export = self.lab.calls[0][2]
        self.assertNotIn(KEY, ' '.join(export))
        self.assertEqual(export[export.index('--output') + 1], str(self.root / 'work-exports' / 'work-test-001.ndjson'))
        evidence = self.root / 'cases' / 'work-test-001' / 'evidence'
        self.assertEqual(self.lab.calls[1][2][-3:-2], [str(evidence)])
        self.assertEqual(self.lab.calls[2][2], str(evidence))
        lab_input = self.lab.calls[3][2]
        self.assertEqual(lab_input[:4], ('lab-input', '--tool-driven', '--data-origin', 'work-export'))
        practice = self.lab.calls[4][2]
        self.assertEqual(practice[2:], ('--input', str(self.root / 'work-hunts' / 'work-test-001' / 'input.json'),
                                        '--rounds', '1'))
        hunt = json.loads(Path(practice[3]).read_text(encoding='utf-8'))
        self.assertEqual((hunt['parallel'], hunt['follow_ups'], hunt['data_origin']), (True, 6, 'work-export'))
        self.assertTrue(hunt['scope'].startswith('Work log export'))
        self.assertEqual(self.lab.calls[5][2], DELEGATED)
        self.assertIn('recorded as delegated', out)
        record = json.loads((self.root / 'work-hunts' / 'work-test-001' / 'hunt.json').read_text(encoding='utf-8'))
        self.assertTrue(record['completed'])
        self.assertEqual(record['usage']['total_tokens'], 100)
        self.assertEqual(record['workflow'], practice[1])
        self.assertIn('HUNT COMPLETED', out)

    def test_two_decision_mode_leaves_both_decisions_to_the_operator_and_names_the_slack_bridge(self):
        code, out = self.run_main('--operator', 'Ada Lovelace', '--follow-ups', '0')
        self.assertEqual(code, 0, out)
        self.assertEqual(self.lab.calls[5][2], ['--two-decisions', '--operator', 'Ada Lovelace'])
        self.assertIn('slack_gates.py --operator-name "Ada Lovelace"' if os.name == 'nt'
                      else "slack_gates.py --operator-name 'Ada Lovelace'", out)
        self.assertIn('recorded as automated', out)
        hunt = json.loads((self.root / 'work-hunts' / 'work-test-001' / 'input.json').read_text(encoding='utf-8'))
        self.assertEqual(hunt['follow_ups'], 0)

    def test_an_existing_case_is_refused_before_any_export(self):
        for existing in ('cases/work-test-001', 'work-exports/work-test-001.ndjson',
                         'work-exports/work-test-001.ndjson.meta.json', 'work-hunts/work-test-001'):
            with self.subTest(existing):
                path = self.root / existing
                path.parent.mkdir(parents=True, exist_ok=True)
                path.mkdir() if path.suffix == '' else path.write_text('', encoding='utf-8')
                code, _ = self.run_main(*DELEGATED)
                self.assertIn('already exists', str(code))
                self.assertEqual(self.lab.calls, [])
                self.assertEqual(os.environ.get(wh.API_KEY_ENV), KEY)
                path.rmdir() if path.is_dir() else path.unlink()

    def test_a_missing_key_is_refused(self):
        os.environ[wh.API_KEY_ENV] = ''
        code, _ = self.run_main(*DELEGATED)
        self.assertIn('holds no API key', str(code))
        self.assertEqual(self.lab.calls, [])

    def test_a_failed_export_stops_the_run_without_the_key_in_the_message(self):
        self.lab.child = Mock(return_value=(2, json.dumps({'error': 'search: Elasticsearch returned HTTP 401 '
                                                                    '(security_exception)'}), ''))
        with patch.object(wh, 'child', self.lab.child):
            code, out = self.run_main(*DELEGATED)
        self.assertIn('export failed: search: Elasticsearch returned HTTP 401', str(code))
        self.assertNotIn(KEY, str(code) + out)
        self.assertEqual(self.lab.child.call_count, 1)

    def test_an_empty_window_removes_its_export_and_stops_before_the_import(self):
        self.lab.export_count = 0
        code, _ = self.run_main(*DELEGATED)
        self.assertIn('the window holds no documents', str(code))
        self.assertEqual([call[0] for call in self.lab.calls], ['export'])
        self.assertEqual(list((self.root / 'work-exports').iterdir()), [])

    def test_a_failed_import_frees_the_case_folder_and_names_the_kept_export(self):
        self.lab.import_error = 'no records match the window'
        code, _ = self.run_main(*DELEGATED)
        self.assertIn('import failed: no records match the window', str(code))
        self.assertIn(str(self.root / 'work-exports' / 'work-test-001.ndjson'), str(code))
        self.assertFalse((self.root / 'cases' / 'work-test-001').exists())
        self.assertEqual([call[0] for call in self.lab.calls], ['export', 'import'])

    def record(self):
        return json.loads((self.root / 'work-hunts' / 'work-test-001' / 'hunt.json').read_text(encoding='utf-8'))

    def test_a_lab_that_never_loads_says_how_to_stop_it(self):
        def not_ready(evidence, log_path, case_id):
            raise SystemExit('the lab did not load work-test-001')
        with patch.object(wh, 'load_lab', not_ready):
            code, out = self.run_main(*DELEGATED)
        self.assertIn('the lab did not load work-test-001', str(code))
        self.assertIn('hunt-lab stop --case-id work-test-001', out)
        self.assertNotIn('resume the gate driver', out)
        self.assertEqual([call[0] for call in self.lab.calls], ['export', 'import'])
        self.assertEqual(self.record()['ended_early'], 'SystemExit: the lab did not load work-test-001')

    def test_a_failed_hunt_start_keeps_a_record_and_says_how_to_stop_the_lab(self):
        self.lab.failing = {'practice'}
        code, out = self.run_main('--operator', 'Ada Lovelace')
        self.assertIn('hunt start failed: practice: refused by the fake', str(code))
        self.assertIn('hunt-lab stop', out)
        self.assertNotIn('resume the gate driver', out)
        record = self.record()
        self.assertIn('hunt start failed', record['ended_early'])
        self.assertEqual(record['gates'], {'mode': 'two-decisions', 'operator': 'Ada Lovelace'})
        self.assertEqual(record['lab']['log'], str(self.root / 'work-hunts' / 'work-test-001' / 'lab.log'))
        self.assertNotIn('workflow', record)

    def test_ctrl_c_at_the_gate_driver_prints_how_to_resume_and_stop(self):
        self.lab.driver_raises = KeyboardInterrupt()
        out = io.StringIO()
        with contextlib.redirect_stdout(out), self.assertRaises(KeyboardInterrupt):
            wh.main(wh.parse_args([*ARGS, *DELEGATED]))
        out = out.getvalue()
        resume = out.split('resume the gate driver with: ')[1].splitlines()[0]
        workflow = self.record()['workflow']
        self.assertIn(f'drive_gates.py {workflow} --delegated-by', resume)
        self.assertIn('hunt-lab stop', out)
        self.assertEqual(self.record()['ended_early'], 'KeyboardInterrupt')
        self.assertEqual(self.record()['gates'], {'mode': 'delegated', 'delegated_by': 'Ada Lovelace', 'reason': 'test run'})

    def test_an_export_timeout_removes_the_partial_export(self):
        def slow_export(cmd, env, timeout):
            output = Path(cmd[cmd.index('--output') + 1])
            output.write_text('{"_source": {}}\n', encoding='utf-8')
            raise subprocess.TimeoutExpired(cmd, timeout)
        with patch.object(wh, 'child', slow_export):
            code, out = self.run_main(*DELEGATED)
        self.assertEqual(str(code), 'export timed out after 60 minutes; the partial export was removed. '
                                    'Narrow the window or --hosts')
        self.assertEqual(list((self.root / 'work-exports').iterdir()), [])
        self.assertNotIn(KEY, str(code) + out)

    def test_ctrl_c_during_the_export_removes_the_partial_export(self):
        def interrupted(cmd, env, timeout):
            Path(cmd[cmd.index('--output') + 1]).write_text('{"_source": {}}\n', encoding='utf-8')
            raise KeyboardInterrupt
        err = io.StringIO()
        with patch.object(wh, 'child', interrupted), contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(err), self.assertRaises(KeyboardInterrupt):
            wh.main(wh.parse_args([*ARGS, *DELEGATED]))
        self.assertEqual(list((self.root / 'work-exports').iterdir()), [])
        self.assertIn('export interrupted; the partial export was removed', err.getvalue())

    def test_a_partial_export_that_cannot_be_removed_is_named(self):
        export = self.root / 'work-exports' / 'work-test-001.ndjson'

        def slow_export(cmd, env, timeout):
            export.write_text('{"_source": {}}\n', encoding='utf-8')
            raise subprocess.TimeoutExpired(cmd, timeout)
        unlink = Path.unlink

        def held(path, missing_ok=False):
            if path == export:
                raise PermissionError(32, 'The process cannot access the file')
            return unlink(path, missing_ok=missing_ok)
        with patch.object(wh, 'child', slow_export), patch.object(Path, 'unlink', held):
            code, _ = self.run_main(*DELEGATED)
        self.assertIn('could not remove the partial export, which holds real work data; delete it yourself: '
                      + str(export), str(code))
        self.assertTrue(export.exists())

    def test_an_import_timeout_removes_the_partial_case_and_keeps_the_export(self):
        export_child = self.lab.child

        def slow_import(cmd, env, timeout):
            if 'import' not in cmd:
                return export_child(cmd, env, timeout)
            evidence = Path(cmd[cmd.index('--evidence-dir') + 1])
            evidence.mkdir(parents=True)
            (evidence / 'events.jsonl').write_text('{}\n', encoding='utf-8')
            raise subprocess.TimeoutExpired(cmd, timeout)
        with patch.object(wh, 'child', slow_import):
            code, _ = self.run_main(*DELEGATED)
        self.assertIn('import timed out after 60 minutes; the partial case was removed; the export is kept at', str(code))
        self.assertFalse((self.root / 'cases' / 'work-test-001').exists())
        self.assertTrue((self.root / 'work-exports' / 'work-test-001.ndjson').exists())

    def test_a_failed_gate_driver_prints_how_to_resume_it(self):
        self.lab.driver_rc = 2
        code, out = self.run_main(*DELEGATED)
        self.assertEqual(code, 0, out)
        self.assertIn('the gate driver failed; resume it with:', out)
        self.assertIn('drive_gates.py', out.split('resume it with:')[1].splitlines()[0])


class ChildTest(unittest.TestCase):
    def test_an_interrupted_child_has_exited_and_released_its_files_when_child_raises(self):
        # Seen in review: subprocess.run kills without waiting, and deleting a file the dying child still holds
        # fails on Windows (WinError 32), leaving partial work data behind.
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        held, opened = Path(temp.name) / 'partial.ndjson', Path(temp.name) / 'opened'
        script = (f'import pathlib, time\nf = open({str(held)!r}, "w")\nf.write("x")\nf.flush()\n'
                  f'pathlib.Path({str(opened)!r}).write_text("1")\ntime.sleep(60)\n')
        communicate, calls = subprocess.Popen.communicate, []

        def interrupted_once(process, *args, **kwargs):
            calls.append(kwargs)
            if len(calls) == 1:
                deadline = time.time() + 30
                while not opened.exists() and time.time() < deadline:
                    time.sleep(0.05)
                raise KeyboardInterrupt
            return communicate(process, *args, **kwargs)
        with patch.object(subprocess.Popen, 'communicate', interrupted_once), self.assertRaises(KeyboardInterrupt):
            wh.child([sys.executable, '-c', script], None, 120)
        self.assertTrue(opened.exists())
        held.unlink()
        self.assertFalse(held.exists())


class LoadLabTest(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.log = Path(temp.name) / 'lab.log'
        self.commands = []

    def load(self, output, returncode=0):
        self.log.unlink(missing_ok=True)
        def run(cmd, stdout, timeout, **kwargs):
            self.commands.append(cmd)
            stdout.write(output.encode('utf-8'))
            return Mock(returncode=returncode)
        with patch.object(wh.subprocess, 'run', run):
            return wh.load_lab(Path('evidence'), self.log, 'work-test-001')

    def test_ready_for_this_case_returns_the_line(self):
        line = self.load('10:00:00 stopped case=lab-med-001 (stopped)\n'
                         '10:05:00 READY case=work-test-001 events=3 sessions=0\n')
        self.assertIn('READY case=work-test-001', line)
        [cmd] = self.commands
        self.assertEqual(cmd[-2:], [str(Path(wh.__file__).with_name('switch_case.py')), 'evidence'])

    def test_ready_for_another_case_or_no_events_is_refused(self):
        for text in ('10:05:00 READY case=team-med-021 events=20000\n', '10:05:00 READY case=work-test-001 events=None\n'):
            with self.subTest(text):
                with self.assertRaisesRegex(SystemExit, 'did not load work-test-001'):
                    self.load(text)

    def test_a_switch_that_exits_before_ready_stops_the_run(self):
        with self.assertRaisesRegex(SystemExit, r'exited \(1\) before READY'):
            self.load('start failed: docker_unavailable\n', returncode=1)

    def test_a_switch_that_times_out_stops_the_run(self):
        def run(cmd, timeout, **kwargs):
            raise subprocess.TimeoutExpired(cmd, timeout)
        with patch.object(wh.subprocess, 'run', run), self.assertRaisesRegex(SystemExit, 'within 120 minutes'):
            wh.load_lab(Path('evidence'), self.log, 'work-test-001')


if __name__ == '__main__':
    unittest.main()

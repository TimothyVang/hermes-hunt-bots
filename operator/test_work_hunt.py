"""work_hunt.py with Elasticsearch, the lab VM, Temporal and the gate driver faked."""
import contextlib
import io
import json
import os
import tempfile
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
        self.assertIn('non-blank --operator', parse('--operator', '  '))
        args = parse('--operator', 'Ada  Lovelace')
        self.assertEqual(args.gate_args, ['--two-decisions', '--operator', 'Ada  Lovelace'])
        self.assertEqual(args.operator, 'Ada Lovelace')
        self.assertEqual(parse(*DELEGATED).gate_args, DELEGATED)


class FakeLab:
    """Records every step of main() in order with the environment each child would get."""

    def __init__(self, root):
        self.root, self.calls = root, []

    def child(self, cmd, env, timeout):
        env = os.environ if env is None else env
        action = cmd[cmd.index('hunt_lab.import_elastic') + 1]
        self.calls.append((action, KEY in env.values(), cmd))
        if action == 'export':
            return 0, json.dumps({
                'host': 'elastic.example.internal:9243', 'index': 'logs-*', 'hosts': None, 'event_count': 3,
                'elastic_version': '8.15.3', 'output': cmd[cmd.index('--output') + 1], 'meta': 'm',
                'time_range_utc': {'start_inclusive': '2026-11-03T08:00:00Z', 'end_exclusive': '2026-11-03T12:00:00Z'},
                'ndjson': {'file': 'f', 'bytes': 9, 'sha256': '0' * 64}}), ''
        return 0, json.dumps({'case_id': 'work-test-001', 'data_origin': 'work-export', 'event_count': 3,
                              'host_count': 1, 'outside_window': 0, 'files': {}}), ''

    def start_holder(self, evidence, log_path, reseed_python):
        self.calls.append(('holder', KEY in os.environ.values(), str(evidence)))
        return Mock(pid=4242)

    def wait_ready(self, holder, log_path, case_id):
        self.calls.append(('ready', KEY in os.environ.values(), case_id))
        return '10:00:00 READY case=work-test-001 events=3 sessions=0 intel=0 lab_url=http://127.0.0.1:8765'

    def tcli(self, *args, timeout=180):
        self.calls.append((args[0], KEY in os.environ.values(), args))
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
        return 0


class MainTest(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.lab = FakeLab(self.root)
        patches = [patch.object(wh, name, self.root / folder) for name, folder in (
            ('CASES', 'cases'), ('EXPORTS', 'work-exports'), ('WORK_HUNTS', 'work-hunts'), ('GATE_RUNS', 'gate-runs'))]
        patches += [patch.object(wh, name, getattr(self.lab, name))
                    for name in ('child', 'start_holder', 'wait_ready', 'tcli', 'drive')]
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
                         ['export', 'import', 'holder', 'ready', 'lab-input', 'practice', 'drive', 'status'])
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
        lab_input = self.lab.calls[4][2]
        self.assertEqual(lab_input[:4], ('lab-input', '--tool-driven', '--data-origin', 'work-export'))
        practice = self.lab.calls[5][2]
        self.assertEqual(practice[2:], ('--input', str(self.root / 'work-hunts' / 'work-test-001' / 'input.json'),
                                        '--rounds', '1'))
        hunt = json.loads(Path(practice[3]).read_text(encoding='utf-8'))
        self.assertEqual((hunt['parallel'], hunt['follow_ups'], hunt['data_origin']), (True, 6, 'work-export'))
        self.assertTrue(hunt['scope'].startswith('Work log export'))
        self.assertEqual(self.lab.calls[6][2], DELEGATED)
        self.assertIn('recorded as delegated', out)
        record = json.loads((self.root / 'work-hunts' / 'work-test-001' / 'hunt.json').read_text(encoding='utf-8'))
        self.assertTrue(record['completed'])
        self.assertEqual(record['usage']['total_tokens'], 100)
        self.assertEqual(record['workflow'], practice[1])
        self.assertIn('HUNT COMPLETED', out)

    def test_two_decision_mode_leaves_both_decisions_to_the_operator_and_names_the_slack_bridge(self):
        code, out = self.run_main('--operator', 'Ada Lovelace', '--follow-ups', '0')
        self.assertEqual(code, 0, out)
        self.assertEqual(self.lab.calls[6][2], ['--two-decisions', '--operator', 'Ada Lovelace'])
        self.assertIn('slack_gates.py --operator-name "Ada Lovelace"' if os.name == 'nt'
                      else "slack_gates.py --operator-name 'Ada Lovelace'", out)
        self.assertIn('recorded as automated', out)
        hunt = json.loads((self.root / 'work-hunts' / 'work-test-001' / 'input.json').read_text(encoding='utf-8'))
        self.assertEqual(hunt['follow_ups'], 0)

    def test_an_existing_case_is_refused_before_any_export(self):
        for existing in ('cases/work-test-001', 'work-exports/work-test-001.ndjson', 'work-hunts/work-test-001'):
            with self.subTest(existing):
                path = self.root / existing
                path.parent.mkdir(parents=True, exist_ok=True)
                path.mkdir() if path.suffix == '' else path.write_text('', encoding='utf-8')
                code, out = self.run_main(*DELEGATED)
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


class WaitReadyTest(unittest.TestCase):
    def setUp(self):
        self.log = Path(tempfile.mkdtemp()) / 'holder.log'

    def test_ready_for_this_case_returns_the_line(self):
        self.log.write_text('10:00:00 vm stopped\n10:05:00 READY case=work-test-001 events=3 sessions=0\n',
                            encoding='utf-8')
        line = wh.wait_ready(Mock(poll=lambda: None), self.log, 'work-test-001', poll=0)
        self.assertIn('READY case=work-test-001', line)

    def test_ready_for_another_case_or_no_events_is_refused(self):
        for text in ('10:05:00 READY case=team-med-021 events=20000\n', '10:05:00 READY case=work-test-001 events=None\n'):
            with self.subTest(text):
                self.log.write_text(text, encoding='utf-8')
                with self.assertRaisesRegex(SystemExit, 'did not load work-test-001'):
                    wh.wait_ready(Mock(poll=lambda: None), self.log, 'work-test-001', poll=0)

    def test_a_holder_that_exits_before_ready_stops_the_run(self):
        self.log.write_text('reseed failed\n', encoding='utf-8')
        with self.assertRaisesRegex(SystemExit, r'holder exited \(1\)'):
            wh.wait_ready(Mock(poll=lambda: 1, returncode=1), self.log, 'work-test-001', poll=0)


if __name__ == '__main__':
    unittest.main()

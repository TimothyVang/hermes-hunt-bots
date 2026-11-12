"""Offline guard tests; synthetic protocol children never invoke SSH or a lab."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import benchmark_linux as driver
from benchmark_contracts import BenchmarkError, canonical_bytes
from benchmark_paths import SOURCE_TREE

WORKER_PATH = SOURCE_TREE / 'hunt-range' / 'benchmark' / 'linux_worker.py'
worker = None
if WORKER_PATH.is_file():
    spec = importlib.util.spec_from_file_location('benchmark_linux_worker_fixture', WORKER_PATH)
    worker = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(worker)


def pin(path, version=False):
    value = {'path': str(path), 'sha256': hashlib.sha256(Path(path).read_bytes()).hexdigest()}
    if version:
        value['version'] = 'synthetic-fixture-only'
    return value


def manifest(root):
    for name, content in [('config', b'# no directives\n'), ('hosts', b'synthetic host keys\n'),
                          ('key', b'synthetic not-a-real-key\n'), ('linux_worker.py', b'# synthetic worker pin\n')]:
        (root / name).write_bytes(content)
        (root / name).chmod(0o600)
    route = {'host': '192.0.2.10', 'port': 22, 'user': 'range_action', 'machine_id': '1' * 32,
             'enrollment_sha256': '2' * 64, 'ssh_config': pin(root / 'config'),
             'known_hosts': pin(root / 'hosts'), 'identity_file': pin(root / 'key')}
    return {'recipe_id': 'linux-discovery-v1', 'targets': [
        {'target_id': 'victim', 'kind': 'linux', 'identity':
            {'host': '192.0.2.20', 'port': 22, 'user': 'exercise', 'machine_id': '3' * 32}}],
        'executor': {'transport': 'ssh_worker', 'executable': pin(Path(sys.executable), True),
                     'script_sha256': pin(root / 'linux_worker.py')['sha256'],
                     'environment_names': [], 'config': route}, 'collectors': [],
        'limits': {'max_export_bytes': 100000, 'max_phase_seconds': 15}}


def add_collector(value):
    route = copy.deepcopy(value['executor']['config'])
    route['user'] = 'range_reader'
    route['enrollment_sha256'] = '4' * 64
    route['identity_file']['sha256'] = '5' * 64
    item = {'source_id': 'journal', 'kind': 'linux', 'target_id': 'victim',
            'export_root': None, 'bucket': None, 'prefix': None,
            'window_utc': {'start_inclusive': '2026-01-01T00:00:00Z', 'end_exclusive': '2026-01-01T00:01:00Z'},
            'max_bytes': 100000, 'max_seconds': 10,
            'config': {'executable': value['executor']['executable'],
                       'script_sha256': value['executor']['script_sha256'],
                       'route': route, 'target_user': 'audit_reader'}}
    value['collectors'].append(item)
    return item


def protocol_response(request):
    facts = {'identity_verified': True, 'owned_sessions_remaining': 0}
    if request['operation'] == 'discovery':
        facts.update(id_verified=True, uname_verified=True, process_count=2)
    if request['operation'] == 'close_sessions':
        facts.update(account_processes_remaining=0, account_sessions_remaining=0, account_process_ids=[])
    if request['operation'] in ('collect', 'collector_identity'):
        facts.update(process_coverage=False, gaps=['missing_audit_export'])
    return {'schema_version': 1, 'operation': request['operation'], 'outcome': 'succeeded',
            'executor_identity': request['executor_identity'], 'target': request['target'],
            'effect_verified': True, 'facts': facts, 'records': [],
            'watermark_utc': '2026-01-01T00:01:00Z' if request['operation'] == 'collect' else None,
            'complete': True}


class ControllerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.manifest = manifest(self.root)

    def test_strict_configuration_and_fixed_phases(self):
        driver.validate_configuration(self.manifest)
        self.assertEqual(driver.phase_steps(self.manifest, 'run', {}), ['discovery'])
        for key, value in [('command', 'id'), ('ProxyCommand', 'bad'), ('extra_args', [])]:
            altered = copy.deepcopy(self.manifest)
            altered['executor']['config'][key] = value
            with self.assertRaises(BenchmarkError):
                driver.validate_configuration(altered)

    def test_identity_injection_and_dns_hosts_rejected(self):
        for field, value in [('user', 'user;id'), ('host', 'victim.test'), ('port', True),
                             ('machine_id', 'wrong'), ('host', '192.0.2.10%eth0')]:
            altered = copy.deepcopy(self.manifest)
            altered['targets'][0]['identity'][field] = value
            with self.assertRaises(BenchmarkError):
                driver.validate_configuration(altered)

    def test_collectors_use_separate_keys_accounts_and_enrollment(self):
        item = add_collector(self.manifest)
        driver.validate_collector(self.manifest, item)
        for name in ('user', 'identity_file', 'enrollment_sha256'):
            altered = copy.deepcopy(item)
            altered['config']['route'][name] = self.manifest['executor']['config'][name]
            with self.assertRaises(BenchmarkError):
                driver.validate_collector(self.manifest, altered)
        item['config']['target_user'] = 'exercise'
        with self.assertRaises(BenchmarkError):
            driver.validate_collector(self.manifest, item)

    def test_fixed_ssh_options_and_no_remote_command(self):
        with mock.patch.object(driver, '_checked_file', side_effect=lambda item, *args: Path(item['path'])):
            argv = driver.ssh_argv(self.manifest['executor']['executable'], self.manifest['executor']['config'])
        for option in ('BatchMode=yes', 'StrictHostKeyChecking=yes', 'IdentitiesOnly=yes', 'ForwardAgent=no',
                       'ClearAllForwardings=yes', 'RequestTTY=no', 'ProxyCommand=none', 'ProxyJump=none'):
            self.assertIn(option, argv)
        self.assertIn('-T', argv)
        self.assertEqual(argv[-1], '192.0.2.10')
        self.assertNotIn('id', argv)

    def test_config_directives_cannot_override_guards(self):
        for directive in ('Include /tmp/other', 'ProxyCommand bad', 'Host *', 'RequestTTY force',
                          'LocalForward 1 2', 'Match exec bad'):
            (self.root / 'config').write_text(directive)
            with mock.patch.object(driver, '_checked_file', side_effect=lambda item, *args: Path(item['path'])):
                with self.assertRaises(BenchmarkError):
                    driver.ssh_argv(self.manifest['executor']['executable'], self.manifest['executor']['config'])

    def test_changed_pin_blocks_before_transport(self):
        self.manifest['executor']['script_sha256'] = '0' * 64
        transport = mock.Mock()
        result = driver.execute_step(self.manifest, self.root, 'preflight', 'identity', {}, transport)
        self.assertEqual(result['execution_outcome'], 'blocked')
        transport.assert_not_called()

    def test_structured_fixture_process_and_private_action_output(self):
        # This is an actual benign Python protocol child, not a replacement SSH
        # invocation or a claimed lab observation. Its argv is never executed.
        fixture = self.root / 'synthetic_ssh.py'
        fixture.write_text('import json,sys\nr=json.load(sys.stdin)\n'
                           'o=' + repr(protocol_response({'operation': 'discovery',
                              'executor_identity': {'machine_id': '1' * 32, 'user': 'range_action'},
                              'target': self.manifest['targets'][0]['identity']})) + '\n'
                           'json.dump(o,sys.stdout)\n', encoding='utf-8')
        calls = []
        def transport(argv, **kwargs):
            calls.append((argv, kwargs))
            child = subprocess.run([sys.executable, '-I', str(fixture)], input=kwargs['input_bytes'],
                                   stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=5)
            return {'status': 'succeeded', 'exit_code': child.returncode, 'stdout': child.stdout}
        with mock.patch.object(driver, '_checked_file', side_effect=lambda item, *args: Path(item['path'])):
            result = driver.execute_step(self.manifest, self.root, 'run', 'discovery', {}, transport)
        self.assertEqual(result['execution_outcome'], 'succeeded')
        self.assertTrue(result['effect_verified'])
        self.assertEqual(result['raw_exports'], [])
        self.assertEqual(len(calls), 1)
        expected = {} if os.name != 'nt' else {key: os.environ['SystemRoot'] for key in ('SystemRoot', 'WINDIR')}
        if os.name == 'nt':
            expected['PATH'] = str(Path(os.environ['SystemRoot']) / 'System32')
        self.assertEqual(calls[0][1]['env'], expected)
        self.assertEqual(result['evidence']['transport_exit'], 0)
        self.assertEqual(calls[0][0][-1], '192.0.2.10')

    @unittest.skipUnless(os.name == 'nt', 'UNC paths exist only on Windows controllers')
    def test_unc_pin_paths_rejected(self):
        for value in (r'\\server\share\ssh.exe', r'\\?\C:\Windows\System32\OpenSSH\ssh.exe'):
            with self.subTest(value=value), self.assertRaises(BenchmarkError):
                driver._pin({'path': value, 'sha256': '0' * 64, 'version': 'fixture'}, True)

    def test_timeout_unknown_and_no_retry(self):
        transport = mock.Mock(return_value={'status': 'unknown', 'exit_code': None, 'stdout': b''})
        with mock.patch.object(driver, 'ssh_argv', return_value=['synthetic-not-executed']):
            result = driver.execute_step(self.manifest, self.root, 'run', 'discovery', {}, transport)
        self.assertEqual(result['execution_outcome'], 'unknown')
        self.assertEqual(transport.call_count, 1)

    def test_wrong_identity_and_unverified_exit_zero_rejected(self):
        def transport(argv, **kwargs):
            response = protocol_response(json.loads(kwargs['input_bytes']))
            response['target']['machine_id'] = 'a' * 32
            return {'status': 'succeeded', 'exit_code': 0, 'stdout': canonical_bytes(response)}
        with mock.patch.object(driver, 'ssh_argv', return_value=['synthetic-not-executed']):
            result = driver.execute_step(self.manifest, self.root, 'run', 'discovery', {}, transport)
        self.assertEqual(result['execution_outcome'], 'unknown')
        self.assertFalse(result['effect_verified'])

    def test_collector_preflight_is_not_collection(self):
        item = add_collector(self.manifest)
        seen = []
        def transport(argv, **kwargs):
            request = json.loads(kwargs['input_bytes'])
            seen.append(request)
            return {'status': 'succeeded', 'exit_code': 0, 'stdout': canonical_bytes(protocol_response(request))}
        with mock.patch.object(driver, 'ssh_argv', return_value=['synthetic-not-executed']):
            result = driver.execute_step(self.manifest, self.root, 'preflight', 'journal', {'collector': item}, transport)
        self.assertEqual(seen[0]['operation'], 'collector_identity')
        self.assertIsNone(seen[0]['window_utc'])
        self.assertEqual(result['raw_exports'], [])
        self.assertFalse(result['evidence']['process_coverage'])
        self.assertIn('missing_audit_export', result['evidence']['gaps'])

    def close_sessions(self, facts, outcome='succeeded'):
        def transport(argv, **kwargs):
            response = protocol_response(json.loads(kwargs['input_bytes']))
            response['facts'].update(facts)
            response['outcome'] = outcome
            response['effect_verified'] = outcome == 'succeeded'
            return {'status': 'succeeded', 'exit_code': 0, 'stdout': canonical_bytes(response)}
        with mock.patch.object(driver, 'ssh_argv', return_value=['synthetic-not-executed']):
            return driver.execute_step(self.manifest, self.root, 'cleanup', 'close_sessions', {}, transport)

    def test_close_sessions_leftovers_fail_cleanup(self):
        result = self.close_sessions({})
        self.assertEqual(result['execution_outcome'], 'succeeded')
        self.assertTrue(result['effect_verified'])
        result = self.close_sessions({'account_processes_remaining': 3, 'account_sessions_remaining': 2,
                                      'account_process_ids': [901, 902, 977], 'reason': 'owned_leftovers_found'}, 'failed')
        self.assertEqual(result['execution_outcome'], 'failed')
        self.assertFalse(result['effect_verified'])
        self.assertEqual(result['evidence']['account_process_ids'], [901, 902, 977])
        self.assertIsNotNone(result['observed_target_sha256'])

    def test_close_sessions_inconsistent_report_never_passes(self):
        for facts, outcome in (({'account_processes_remaining': 1, 'account_sessions_remaining': 1,
                                 'account_process_ids': [901]}, 'succeeded'),
                               ({'account_processes_remaining': 2, 'account_sessions_remaining': 1,
                                 'account_process_ids': [901], 'reason': 'owned_leftovers_found'}, 'failed'),
                               ({'account_processes_remaining': 1, 'account_sessions_remaining': 0,
                                 'account_process_ids': [901], 'reason': 'owned_leftovers_found'}, 'failed'),
                               ({'account_processes_remaining': None}, 'succeeded')):
            with self.subTest(facts=facts):
                result = self.close_sessions(facts, outcome)
                self.assertEqual(result['execution_outcome'], 'blocked')
                self.assertFalse(result['effect_verified'])

    def test_leftover_counts_only_belong_to_close_sessions(self):
        def transport(argv, **kwargs):
            response = protocol_response(json.loads(kwargs['input_bytes']))
            response['facts'].update(account_processes_remaining=0, account_sessions_remaining=0, account_process_ids=[])
            return {'status': 'succeeded', 'exit_code': 0, 'stdout': canonical_bytes(response)}
        with mock.patch.object(driver, 'ssh_argv', return_value=['synthetic-not-executed']):
            result = driver.execute_step(self.manifest, self.root, 'preflight', 'identity', {}, transport)
        self.assertEqual(result['execution_outcome'], 'blocked')


@unittest.skipIf(worker is None, 'separate range kit is intentionally not bundled')
class WorkerTests(unittest.TestCase):
    def enrollment(self, mode='action'):
        spec = {'path': '/opt/benchmark/pinned', 'sha256': 'a' * 64}
        return {'schema_version': 1, 'mode': mode,
                'executor_identity': {'machine_id': '1' * 32, 'user': 'range_action'},
                'target': {'host': '192.0.2.20', 'port': 22, 'user': 'exercise', 'machine_id': '3' * 32},
                'ssh': {'executable': dict(spec, version='fixture'), 'ssh_config': spec,
                        'known_hosts': spec, 'identity_file': spec},
                'journal_directory': None, 'audit_files': [],
                'watermark_file': '/srv/sealed/watermark.json' if mode == 'collector' else None}

    def request(self, enrollment, operation):
        return {'schema_version': 1, 'worker_sha256': 'b' * 64, 'enrollment_sha256': 'c' * 64,
                'executor_identity': enrollment['executor_identity'], 'target': enrollment['target'],
                'operation': operation, 'window_utc': None, 'max_bytes': 100000, 'max_seconds': 10}

    def test_duplicate_and_nonfinite_json_rejected(self):
        for value in (b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":Infinity}'):
            with self.assertRaises(worker.GuardError):
                worker.decode(value)

    def test_action_allowlist_and_read_identity_separation(self):
        enrollment = self.enrollment()
        worker.validate_enrollment(enrollment)
        for operation in ('shell', 'id;uname', 'collect'):
            with self.assertRaises(worker.GuardError):
                worker.validate_request(self.request(enrollment, operation), enrollment)
        enrollment['mode'] = 'collector'
        with self.assertRaises(worker.GuardError):
            worker.validate_request(self.request(enrollment, 'discovery'), enrollment)

    def test_process_records_sorted_before_cap(self):
        data = '    PID COMMAND\n' + ''.join('%d proc%d\n' % (number, number) for number in range(80, 0, -1))
        records = worker.parse_processes(data.encode())
        self.assertEqual(len(records), 50)
        self.assertEqual(records[0]['pid'], 1)
        self.assertEqual(records[-1]['pid'], 50)
        with self.assertRaises(worker.GuardError):
            worker.parse_processes(b'PID COMMAND\n1 init\n1 duplicate\n')

    def test_account_leftovers_exclude_only_this_checks_session(self):
        # Shell 500 (session 500) under its sshd 499; 600/601 are an older session.
        lines = ['self 500 499', '499 1 400', '500 499 500', '510 500 500', '600 1 600', '601 600 600']
        self.assertEqual(worker.account_leftovers(lines), {
            'account_processes_remaining': 2, 'account_sessions_remaining': 1, 'account_process_ids': [600, 601]})
        self.assertEqual(worker.account_leftovers(lines[:4])['account_processes_remaining'], 0)
        for invalid in ([], ['self 500'], ['self 500 499', '499 1 400'], ['self 500 499', '500 499 500', '500 499 500'],
                        ['self 500 499', '500 499 500', '600 bash 600']):
            with self.subTest(lines=invalid), self.assertRaises(worker.GuardError):
                worker.account_leftovers(invalid)
        command = worker.leftover_command('exercise')
        self.assertIn("ps -o pid=,ppid=,sid= -u 'exercise' -U 'exercise'", command)
        self.assertNotIn('kill', command)

    def test_remote_spool_paths_reject_shell_and_alias_components(self):
        for value in ('/var/log/../secret', '/var/log/x;id', '/var/log/$(id)', '/var/log//audit', 'relative'):
            with self.assertRaises(worker.GuardError):
                worker.remote_file_guard(value)
        result = worker.remote_file_guard('/srv/sealed/audit.jsonl')
        self.assertIn("test ! -L '/srv/sealed'", result)
        self.assertIn("test ! -w '/srv/sealed'", result)

    def test_journald_does_not_imply_process_coverage(self):
        enrollment = self.enrollment('collector')
        request = self.request(enrollment, 'collect')
        request['window_utc'] = {'start_inclusive': '2026-01-01T00:00:00Z', 'end_exclusive': '2026-01-01T00:01:00Z'}
        session = mock.Mock(remaining=100000)
        session.run.side_effect = [
            b'{"schema_version":1,"watermark_utc":"2026-01-01T00:02:00Z","files":[]}',
            b'{"__CURSOR":"fixture","__REALTIME_TIMESTAMP":"1767225630000000"}\n']
        records, watermark, complete, gaps = worker.collect(session, enrollment, request)
        self.assertTrue(complete)
        self.assertIn('missing_audit_export', gaps)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]['source_type'], 'journald')
        command = session.run.call_args[0][0]
        self.assertIn('--output=json --no-pager', command)
        self.assertNotIn('--vacuum', command)

    def test_partial_watermark_retains_private_records(self):
        enrollment = self.enrollment('collector')
        request = self.request(enrollment, 'collect')
        request['window_utc'] = {'start_inclusive': '2026-01-01T00:00:00Z', 'end_exclusive': '2026-01-01T00:01:00Z'}
        session = mock.Mock(remaining=100000)
        session.run.side_effect = [
            b'{"schema_version":1,"watermark_utc":"2026-01-01T00:00:40Z","files":[]}',
            b'{"__CURSOR":"fixture","__REALTIME_TIMESTAMP":"1767225630000000"}\n']
        records, watermark, complete, gaps = worker.collect(session, enrollment, request)
        self.assertFalse(complete)
        self.assertEqual(len(records), 1)
        self.assertEqual(watermark, '2026-01-01T00:00:40Z')
        self.assertIn('incomplete_export', gaps)

    def test_unenrolled_audit_file_is_not_read(self):
        enrollment = self.enrollment('collector')
        session = mock.Mock(remaining=100000)
        session.run.return_value = worker.encode({
            'schema_version': 1, 'watermark_utc': '2026-01-01T00:00:40Z',
            'files': [{'path': '/etc/shadow', 'sha256': 'a' * 64, 'byte_count': 1}]})
        with self.assertRaises(worker.GuardError):
            worker.read_watermark(session, enrollment)
        self.assertEqual(session.run.call_count, 1)

    @unittest.skipUnless(os.name == 'posix', 'executor identity uses Linux pwd database')
    def test_worker_checks_identity_before_every_fixed_action(self):
        enrollment = self.enrollment()
        request = self.request(enrollment, 'discovery')
        session = mock.Mock()
        session.run.side_effect = [
            ('3' * 32 + '\nexercise\n').encode(),
            b'uid=1001(exercise) gid=1001(exercise) groups=1001(exercise)\n',
            b'Linux synthetic-victim 6.0 fixture x86_64 GNU/Linux\n',
            b'PID COMMAND\n2 fixture-b\n1 fixture-a\n']
        machine_file = mock.Mock()
        machine_file.read_text.return_value = '1' * 32
        with mock.patch.object(worker, 'safe_file', return_value=machine_file), \
                mock.patch('pwd.getpwuid', return_value=mock.Mock(pw_name='range_action')), \
                mock.patch.object(worker, 'ssh_argv', return_value=['fixture-not-executed']):
            result = worker.execute(request, enrollment, session_factory=lambda *args: session)
        self.assertTrue(result['effect_verified'])
        self.assertEqual(result['facts']['process_count'], 2)
        self.assertEqual(result['records'], [])
        self.assertEqual(result['facts']['owned_sessions_remaining'], 0)
        for call in session.run.call_args_list:
            self.assertIn('test "$(cat /etc/machine-id)"', call.args[0])
            self.assertIn('test "$(id -un)"', call.args[0])
        session.close.assert_called_once()

    @unittest.skipUnless(os.name == 'posix', 'executor identity uses Linux pwd database')
    def test_close_sessions_lists_in_the_identity_connection_and_signals_nothing(self):
        enrollment = self.enrollment()
        request = self.request(enrollment, 'close_sessions')
        session = mock.Mock()
        session.run.return_value = ('3' * 32 + '\nexercise\nself 500 499\n500 499 500\n600 1 600\n').encode()
        machine_file = mock.Mock()
        machine_file.read_text.return_value = '1' * 32
        with mock.patch.object(worker, 'safe_file', return_value=machine_file), \
                mock.patch('pwd.getpwuid', return_value=mock.Mock(pw_name='range_action')), \
                mock.patch.object(worker, 'ssh_argv', return_value=['fixture-not-executed']):
            result = worker.execute(request, enrollment, session_factory=lambda *args: session)
        self.assertEqual(result['outcome'], 'failed')
        self.assertFalse(result['effect_verified'])
        self.assertEqual(result['facts']['reason'], 'owned_leftovers_found')
        self.assertEqual(result['facts']['account_process_ids'], [600])
        self.assertEqual(session.run.call_count, 1)
        command = session.run.call_args[0][0]
        self.assertIn('test "$(cat /etc/machine-id)"', command)
        self.assertNotIn('kill', command)

    @unittest.skipUnless(os.name == 'posix', 'executor identity uses Linux pwd database')
    def test_executor_identity_mismatch_dispatches_nothing(self):
        enrollment = self.enrollment()
        request = self.request(enrollment, 'discovery')
        machine_file = mock.Mock()
        machine_file.read_text.return_value = 'wrong'
        factory = mock.Mock()
        with mock.patch.object(worker, 'safe_file', return_value=machine_file):
            with self.assertRaises(worker.GuardError):
                worker.execute(request, enrollment, session_factory=factory)
        factory.assert_not_called()

    @unittest.skipUnless(os.name == 'posix', 'worker process containment is Linux-only')
    def test_benign_session_fixture_bounded_output_and_closed_sessions(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'synthetic_ssh.py'
            path.write_text('import sys\nsys.stdout.write("fixture:"+sys.argv[1])\n')
            session = worker.Session([sys.executable, '-I', str(path)], 5, 100)
            self.assertEqual(session.run('fixed-fixture'), b'fixture:fixed-fixture')
            self.assertIsNone(session.active)
            session = worker.Session([sys.executable, '-I', str(path)], 5, 2)
            with self.assertRaises(worker.GuardError):
                session.run('fixed-fixture')
            self.assertIsNone(session.active)


if __name__ == '__main__':
    unittest.main()

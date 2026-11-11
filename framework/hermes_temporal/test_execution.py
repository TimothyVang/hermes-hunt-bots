"""Durable dispatch boundaries without running Hermes or a provider."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing, redirect_stderr, redirect_stdout
from dataclasses import dataclass, replace
import importlib.util
import io
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

from . import execution as execution_module
from .contracts import ExecutionRequest, ExecutionResult, HermesStep
from .execution import ExecutionConfig, ReceiptStore, _ResultStream, _environment, _invoke, execute, invoke_step

RESULT = {'type': 'result', 'session_id': 'local-synthetic', 'exit_code': 0, 'text': 'READY',
          'tokens': {'input': 10514, 'output': 4, 'total': 10518, 'cache_read': 10512, 'cache_write': 0},
          'duration_ms': 2660, 'timestamp': 1794276152131}
USAGE = {'input_tokens': 10514, 'output_tokens': 4, 'cache_read_tokens': 10512, 'cache_write_tokens': 0,
         'total_tokens': 10518, 'duration_ms': 2660}
INIT = {'type': 'system', 'subtype': 'init'}


def request(prompt='synthetic prompt', execution_id='workflow/0', hunt_context=None):
    return ExecutionRequest(execution_id=execution_id, step=HermesStep(
        step_id='first', prompt=prompt, profile='framework-coordinator', timeout_seconds=10,
        hunt_context=hunt_context))


def stream(*lines):
    return b''.join((line if isinstance(line, bytes) else json.dumps(line).encode('utf-8')) + b'\n'
                    for line in lines)


def temporary_file(data=b''):
    file = tempfile.TemporaryFile()
    file.write(data)
    file.seek(0)
    return file


class StreamProcess:
    def __init__(self, output, returncode=0, errors=b''):
        self.returncode = returncode
        self.killed = False
        self.stdin = io.BytesIO()
        self.stdout = temporary_file(output)
        self.stderr = temporary_file(errors)

    def wait(self, timeout=None):
        return self.returncode

    def kill(self):
        self.killed = True


class ExecutionReceiptTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        home = root / 'separate-home'
        home.mkdir()
        self.path = str(root / 'receipts.sqlite3')
        self.config = ExecutionConfig(True, str(Path(sys.executable).resolve()), str(home), str(root), self.path)

    def run_stream(self, output, returncode=0, errors=b''):
        process = StreamProcess(output, returncode, errors)
        with patch.object(execution_module.subprocess, 'Popen', return_value=process) as popen:
            result = _invoke(replace(self.config, record_usage=True), request())
        return result, popen.call_args.args[0], process

    def test_default_refusal_does_not_create_receipt_or_dispatch(self):
        with patch.object(execution_module, '_invoke') as invoke:
            result = execute(ExecutionConfig(), request())
        self.assertEqual((result.status, result.reason_code), ('failed', 'execution_disabled'))
        invoke.assert_not_called()
        self.assertFalse(Path(self.path).exists())

    def test_operator_home_requires_explicit_opt_in(self):
        root = Path(self.tmp.name)
        live = root / 'localappdata' / 'hermes'
        live.mkdir(parents=True)
        fields = (True, self.config.executable, str(live), str(root), self.path)
        with patch.dict(os.environ, {'LOCALAPPDATA': str(root / 'localappdata')}):
            with patch.object(execution_module, '_invoke') as invoke:
                refused = execute(ExecutionConfig(*fields), request())
                self.assertTrue(execution_module._valid_config(ExecutionConfig(*fields, allow_operator_home=True)))
        self.assertEqual((refused.status, refused.reason_code), ('failed', 'invalid_configuration'))
        invoke.assert_not_called()
        self.assertFalse(Path(self.path).exists())

    def test_completed_receipt_survives_new_store_and_conflict_is_rejected(self):
        req = request()
        completed = ExecutionResult(status='completed', execution_id=req.execution_id,
                                    output='approved reply', reason_code='completed', session_id=None)
        with patch.object(execution_module, '_invoke', return_value=completed) as invoke:
            self.assertEqual(execute(self.config, req), completed)
            self.assertEqual(execute(self.config, request()), completed)
            conflict = execute(self.config, request('different content'))
        self.assertEqual((conflict.status, conflict.reason_code), ('failed', 'fingerprint_conflict'))
        self.assertEqual(invoke.call_count, 1)

    def test_same_execution_id_with_different_hunt_context_is_refused(self):
        snapshot = {
            "schema_version": 1, "case_id": "case-1",
            "entities": [{"entity_id": "host-1", "kind": "host", "label": "synthetic host",
                          "evidence_ids": ["source-1"]}],
            "relations": [],
        }
        first = {"snapshot": snapshot, "evidence_ids": ["source-1"]}
        second = {"snapshot": {**snapshot, "case_id": "case-2"}, "evidence_ids": ["source-1"]}
        with patch.object(execution_module, '_invoke', return_value=ExecutionResult(
                'completed', 'workflow/0', 'synthetic output', 'completed')) as invoke:
            self.assertEqual(execute(self.config, request(execution_id='workflow/0', hunt_context=first)).status,
                             'completed')
            conflict = execute(self.config, request(execution_id='workflow/0', hunt_context=second))
        self.assertEqual((conflict.status, conflict.reason_code), ('failed', 'fingerprint_conflict'))
        self.assertEqual(invoke.call_count, 1)

    def test_orphan_and_unknown_receipts_never_dispatch_again(self):
        req = request()
        self.assertIsNone(ReceiptStore(self.path).reserve(req))
        with patch.object(execution_module, '_invoke') as invoke:
            result = execute(self.config, req)
        self.assertEqual((result.status, result.reason_code), ('unknown', 'previous_dispatch_unknown'))
        invoke.assert_not_called()
        ReceiptStore(self.path).finish(ExecutionResult(status='unknown', execution_id=req.execution_id,
                                                       output='', reason_code='subprocess_timeout', session_id=None))
        self.assertEqual(execute(self.config, req).status, 'unknown')

    def test_concurrent_reservations_have_exactly_one_owner(self):
        req = request()
        # Initialize schema before racing the independent connections.
        ReceiptStore(self.path)._connect().close()
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda _: ReceiptStore(self.path).reserve(req), range(8)))
        self.assertEqual(sum(item is None for item in results), 1)
        self.assertTrue(all(item is None or item.status == 'unknown' for item in results))

    def test_invalid_profile_and_oversized_prompt_never_dispatch(self):
        with self.assertRaises(ValueError):
            HermesStep(step_id='first', prompt='synthetic prompt', profile='not-a-framework-role')
        with self.assertRaises(ValueError):
            request('x' * 65537)

    def test_environment_contains_only_explicit_home_and_system_paths(self):
        with patch.dict(os.environ, {'HOME': '/unapproved', 'OPENAI_API_KEY': 'not-a-real-key',
                                    'PATH': '/unapproved/bin', 'CODEX_HOME': '/unapproved/codex'}):
            env = _environment(self.config.hermes_home, self.config.executable)
        root = Path(self.config.hermes_home).resolve()
        for name in ('HOME', 'USERPROFILE', 'HERMES_REAL_HOME', 'APPDATA', 'LOCALAPPDATA',
                     'CODEX_HOME', 'XDG_CONFIG_HOME', 'XDG_DATA_HOME', 'XDG_CACHE_HOME',
                     'XDG_STATE_HOME', 'XDG_RUNTIME_DIR', 'PYTHONUSERBASE', 'TMP', 'TEMP', 'TMPDIR'):
            self.assertIn(root, Path(env[name]).resolve().parents)
        self.assertEqual(env['HERMES_HOME'], str(root))
        self.assertNotIn('OPENAI_API_KEY', env)
        self.assertNotIn('/unapproved/bin', env['PATH'])

    def test_empty_and_invalid_utf8_output_are_ambiguous(self):
        class ExitedProcess:
            returncode = 0

            def __init__(self, output):
                self.stdin = io.BytesIO()
                self.stdout = temporary_file(output)
                self.stderr = temporary_file()

            def wait(self, timeout=None):
                return 0

        for data in (b'', b'  \n', b'\xff'):
            with self.subTest(data=data):
                with patch.object(execution_module.subprocess, 'Popen',
                           return_value=ExitedProcess(data)):
                    result = _invoke(self.config, request())
                self.assertEqual((result.status, result.reason_code, result.output),
                                 ('unknown', 'output_unavailable', ''))

    def test_sessions_are_hidden_unless_visibility_is_opted_in(self):
        class Process:
            returncode = 0

            def __init__(self, *args, **kwargs):
                self.stdin = io.BytesIO()
                self.stdout = temporary_file(b'reply')
                self.stderr = temporary_file()

            def wait(self, timeout=None):
                return 0

        for visible, source in ((False, 'tool'), (True, 'cli')):
            config = replace(self.config, visible_sessions=visible)
            with patch.object(execution_module.subprocess, 'Popen', side_effect=Process) as popen:
                self.assertEqual(_invoke(config, request()).status, 'completed')
            command = popen.call_args.args[0]
            self.assertEqual(command[command.index('--source') + 1], source)

    def test_recorded_usage_comes_from_the_final_result_record(self):
        output = stream(INIT, {'type': 'tool_use', 'name': 'lab_search', 'input': {'query': 'synthetic'}},
                        {'type': 'tool_result', 'output': 'synthetic rows'},
                        {'type': 'tool_use', 'name': 'lab_read', 'input': {'evidence_id': 'source-1'}},
                        b'\xff not json', b'[1, 2]', {'type': 'text', 'text': 'READY'}, RESULT)
        result, command, _ = self.run_stream(output)
        self.assertEqual(result, ExecutionResult('completed', 'workflow/0', 'READY', 'completed',
                                                 'local-synthetic', USAGE))
        self.assertEqual(command[-2:], ['--format', 'stream-json'])

    def test_result_record_survives_any_read_boundary(self):
        data = stream(INIT, {**RESULT, 'text': 'EARLIER'}, b'not json', RESULT)[:-1]
        for cut in range(len(data) + 1):
            parsed = _ResultStream()
            parsed.feed(data[:cut])
            parsed.feed(data[cut:])
            parsed.end_line()
            self.assertEqual(parsed.record, RESULT, cut)

    def test_stream_without_usable_result_text_is_ambiguous(self):
        for output, usage in ((stream(INIT, {'type': 'text', 'text': 'READY'}), None), (b'', None),
                              (stream(INIT, {**RESULT, 'text': '  \n'}), USAGE),
                              (stream(INIT, {**RESULT, 'text': None}), USAGE)):
            with self.subTest(output=output):
                result, _, _ = self.run_stream(output)
                self.assertEqual((result.status, result.reason_code, result.output, result.usage),
                                 ('unknown', 'output_unavailable', '', usage))

    def test_nonzero_exit_keeps_recorded_spend(self):
        for record, returncode in (({**RESULT, 'exit_code': 1}, 0), (RESULT, 1)):
            with self.subTest(exit_code=record['exit_code'], returncode=returncode):
                result, _, _ = self.run_stream(stream(INIT, record), returncode)
                self.assertEqual(result, ExecutionResult('unknown', 'workflow/0', '', 'native_nonzero',
                                                         'local-synthetic', USAGE, 'exit code 1; no stderr'))

    def invoke_plain(self, process):
        with patch.object(execution_module.subprocess, 'Popen', return_value=process) as popen:
            result = _invoke(self.config, request())
        self.assertEqual(popen.call_args.kwargs['stderr'], execution_module.subprocess.PIPE)
        return result

    def test_nonzero_exit_reports_the_last_exception_line_of_stderr(self):
        errors = (b'INFO hermes: starting merge\n'
                  b'Traceback (most recent call last):\n'
                  b'  File "/opt/hermes/agent.py", line 12, in run\n'
                  b"    raise RuntimeError('provider closed the stream')\n"
                  b'RuntimeError: provider closed the stream\n'
                  b'INFO hermes: shutting down\n')
        plain = self.invoke_plain(StreamProcess(b'', 1, errors))
        streamed, _, _ = self.run_stream(b'', 1, errors)
        for result in (plain, streamed):
            self.assertEqual((result.status, result.reason_code, result.diagnostic),
                             ('unknown', 'native_nonzero', 'exit code 1: RuntimeError: provider closed the stream'))

    def test_a_refusal_logged_for_the_session_names_the_refusal(self):
        logs = Path(self.config.hermes_home) / 'profiles' / 'framework-coordinator' / 'logs'
        logs.mkdir(parents=True)
        refusal = ("2026-11-11 02:52:15,446 WARNING [{0}] agent.conversation_loop: Model declined to respond "
                   "(finish_reason=content_filter). model=m provider=p native_stop_reason=refusal "
                   "stop_details={{'category': 'cyber', 'explanation': 'flagged'}}\n")
        log = logs / 'agent.log'
        log.write_text(refusal.format('local-other'), encoding='utf-8')
        record = stream(INIT, {**RESULT, 'exit_code': 1})
        result, _, _ = self.run_stream(record, 1, b'RuntimeError: provider closed the stream\n')
        self.assertEqual(result.diagnostic, 'exit code 1: RuntimeError: provider closed the stream')
        log.write_text(refusal.format('local-other') + refusal.format('local-synthetic'), encoding='utf-8')
        result, _, _ = self.run_stream(record, 1, b'RuntimeError: provider closed the stream\n')
        self.assertEqual((result.reason_code, result.diagnostic), (
            'native_nonzero', 'exit code 1: model declined to respond (finish_reason=content_filter, category cyber)'))

    def test_secrets_in_stderr_are_redacted(self):
        value = 'synthetic' + 'Value' + 'q7'
        long_hex = 'ab12' * 10
        long_base64 = 'U3ludGhldGlj' + 'QmFzZTY0' * 4 + '=='
        lines = [
            f'RuntimeError: Authorization: Bearer {value}',
            f'httpx.HTTPStatusError: 401 for Bearer {value}',
            f'openai.AuthenticationError: Incorrect API key provided: sk-proj-{value}',
            f'SlackApiError: invalid_auth for xoxb-1234-{value}',
            f'ConnectionError: GET https://operator:{value}@api.example.test/v1?token={value}',
            f'HTTPError: 403 for https://api.example.test/v1/models?key={value}&alt=json',
            f'KeyError: api_key="{value}"',
            f'ValueError: OPENAI_API_KEY={value} rejected',
            f'ValueError: digest {long_hex}',
            f'ValueError: blob {long_base64}',
        ]
        for line in lines:
            with self.subTest(line=line):
                diagnostic = execution_module._diagnostic(1, (line + '\n').encode('utf-8'), False)
                self.assertTrue(diagnostic.startswith('exit code 1: ' + line.split(':')[0] + ':'), diagnostic)
                self.assertIn('[redacted]', diagnostic)
                for secret in (value, long_hex, long_base64):
                    self.assertNotIn(secret, diagnostic)
        result = self.invoke_plain(StreamProcess(b'', 2, ('\n'.join(lines) + '\n').encode('utf-8')))
        self.assertEqual(result.diagnostic, 'exit code 2: ValueError: blob [redacted]')

    def test_diagnostic_is_printable_ascii(self):
        errors = b'\x1b[31mRuntimeError: caf\xc3\xa9\t\xff failed\x1b[0m\n'
        self.assertEqual(execution_module._diagnostic(1, errors, False), 'exit code 1: RuntimeError: caf? ? failed')

    def test_huge_stderr_keeps_only_a_bounded_tail(self):
        noisy = b'noise ' * 1_000_000 + b'\nValueError: final cause\n'
        one_line = b'x9' * 1_000_000
        long_cause = b'\nRuntimeError: ' + b'detail ' * 280 + b'\n'
        for errors, expected in ((noisy, 'exit code 1: ValueError: final cause'),
                                 (one_line, 'exit code 1; no stderr')):
            with self.subTest(expected=expected):
                self.assertEqual(self.invoke_plain(StreamProcess(b'', 1, errors)).diagnostic, expected)
        diagnostic = self.invoke_plain(StreamProcess(b'', 1, long_cause)).diagnostic
        self.assertTrue(diagnostic.startswith('exit code 1: RuntimeError: detail detail'))
        self.assertTrue(diagnostic.endswith('...'))
        self.assertLessEqual(len(diagnostic), 640)

    def test_huge_stderr_is_drained_without_blocking_the_native_process(self):
        # A real child that fills the stderr pipe many times over; undrained, it would block until the timeout.
        script = ('import sys; sys.stdin.read(); sys.stdout.write("SYNTHETIC MODEL ANSWER"); sys.stdout.flush(); '
                  'sys.stderr.write("noise " * 400000); sys.stderr.write("\\nRuntimeError: synthetic crash\\n"); '
                  'sys.exit(3)')
        launch = execution_module.subprocess.Popen
        with patch.object(execution_module.subprocess, 'Popen',
                          side_effect=lambda command, **options: launch([sys.executable, '-c', script], **options)):
            result = _invoke(self.config, request())
        self.assertEqual((result.reason_code, result.diagnostic),
                         ('native_nonzero', 'exit code 3: RuntimeError: synthetic crash'))

    def test_timeout_reports_the_killed_exit_code_and_cause(self):
        class SlowProcess(StreamProcess):
            def wait(self, timeout=None):
                if timeout is not None and not self.killed:
                    raise execution_module.subprocess.TimeoutExpired('hermes', timeout)
                return self.returncode

            def kill(self):
                super().kill()
                self.returncode = -9

        result = self.invoke_plain(SlowProcess(b'partial', 0, b'TimeoutError: provider stalled\n'))
        self.assertEqual((result.status, result.reason_code, result.diagnostic),
                         ('unknown', 'subprocess_timeout', 'exit code -9: TimeoutError: provider stalled'))

    def test_empty_output_reports_a_diagnostic(self):
        result = self.invoke_plain(StreamProcess(b'  \n', 0, b'WARNING: provider returned no content\n'))
        self.assertEqual((result.reason_code, result.diagnostic),
                         ('output_unavailable', 'exit code 0: WARNING: provider returned no content'))

    def test_successful_and_output_limited_runs_carry_no_diagnostic(self):
        errors = b'Traceback (most recent call last):\nRuntimeError: retried and recovered\n'
        completed, _, _ = self.run_stream(stream(INIT, RESULT), errors=errors)
        limited, _, _ = self.run_stream(stream(INIT, {**RESULT, 'text': 'x' * 65537}), errors=errors)
        plain = self.invoke_plain(StreamProcess(b'reply', 0, errors))
        self.assertEqual(completed, ExecutionResult('completed', 'workflow/0', 'READY', 'completed',
                                                    'local-synthetic', USAGE))
        self.assertEqual(limited, ExecutionResult('unknown', 'workflow/0', '', 'output_limit',
                                                  'local-synthetic', USAGE))
        self.assertEqual(plain, ExecutionResult('completed', 'workflow/0', 'reply', 'completed'))

    def test_stdout_text_never_reaches_the_diagnostic(self):
        answer = 'SYNTHETIC MODEL ANSWER RuntimeError: written by the model'
        record = {**RESULT, 'exit_code': 1, 'text': answer}
        for errors, expected in ((b'', 'exit code 1; no stderr'),
                                 (b'ValueError: worker side\n', 'exit code 1: ValueError: worker side')):
            with self.subTest(errors=errors):
                plain = self.invoke_plain(StreamProcess(answer.encode('utf-8'), 1, errors))
                streamed, _, _ = self.run_stream(stream(INIT, record), 0, errors)
                for result in (plain, streamed):
                    self.assertEqual((result.reason_code, result.output, result.diagnostic),
                                     ('native_nonzero', '', expected))
                    self.assertNotIn('MODEL', result.diagnostic)

    def test_result_diagnostic_must_be_short_printable_ascii(self):
        ExecutionResult('unknown', 'workflow/0', '', 'native_nonzero', diagnostic='x' * 640)
        for diagnostic in ('exit code 1:\nsecond line', 'exit code 1: caf\u00e9', 'x' * 641, 7):
            with self.subTest(diagnostic=diagnostic), self.assertRaises(ValueError):
                ExecutionResult('unknown', 'workflow/0', '', 'native_nonzero', diagnostic=diagnostic)

    def test_malformed_token_values_leave_usage_unrecorded(self):
        tokens = RESULT['tokens']
        for record in ({**RESULT, 'tokens': {**tokens, 'input': -1}},
                       {**RESULT, 'tokens': {**tokens, 'output': True}},
                       {**RESULT, 'tokens': {**tokens, 'total': 1.5}},
                       {**RESULT, 'tokens': {**tokens, 'cache_read': '7'}},
                       {**RESULT, 'tokens': {key: value for key, value in tokens.items() if key != 'cache_write'}},
                       {**RESULT, 'tokens': None},
                       {**RESULT, 'duration_ms': None}):
            with self.subTest(record=record):
                result, _, _ = self.run_stream(stream(INIT, record))
                self.assertEqual((result.status, result.output, result.usage, result.session_id),
                                 ('completed', 'READY', None, 'local-synthetic'))

    def test_stream_over_its_bound_is_cut_off(self):
        output = stream(INIT, *[{'type': 'tool_use', 'name': 'lab_search', 'input': {'query': 'synthetic'}}] * 8,
                        RESULT)
        with patch.object(execution_module, 'MAX_STREAM_BYTES', 256):
            result, _, process = self.run_stream(output)
        self.assertEqual(result, ExecutionResult('unknown', 'workflow/0', '', 'output_limit'))
        self.assertTrue(process.killed)

    def test_final_text_over_the_output_cap_is_refused_with_its_spend(self):
        result, _, process = self.run_stream(stream(INIT, {**RESULT, 'text': 'x' * 65537}))
        self.assertEqual(result, ExecutionResult('unknown', 'workflow/0', '', 'output_limit',
                                                 'local-synthetic', USAGE))
        self.assertFalse(process.killed)

    def test_overlong_line_is_dropped_instead_of_buffered(self):
        with patch.object(execution_module, 'MAX_STREAM_LINE_BYTES', 512):
            kept, _, _ = self.run_stream(stream(INIT, {'type': 'tool_result', 'output': 'x' * 20000}, RESULT))
            lost, _, _ = self.run_stream(stream(INIT, {**RESULT, 'text': 'x' * 20000}))
        self.assertEqual(kept, ExecutionResult('completed', 'workflow/0', 'READY', 'completed',
                                               'local-synthetic', USAGE))
        self.assertEqual(lost, ExecutionResult('unknown', 'workflow/0', '', 'output_limit'))

    def test_usage_recording_off_keeps_command_and_raw_output(self):
        raw = stream(INIT, RESULT)
        with patch.object(execution_module.subprocess, 'Popen', return_value=StreamProcess(raw)) as popen:
            result = _invoke(self.config, request())
        self.assertEqual(popen.call_args.args[0], [
            self.config.executable, '-p', 'framework-coordinator', 'chat', '--oneshot', '--quiet',
            '--query-file', '-', '--source', 'tool', '--max-turns', '32'])
        self.assertEqual(result, ExecutionResult('completed', 'workflow/0', raw.decode('utf-8'), 'completed'))

    def test_receipt_returns_usage_and_session_on_repeat(self):
        req = request()
        completed = ExecutionResult('completed', req.execution_id, 'READY', 'completed', 'local-synthetic', USAGE)
        with patch.object(execution_module, '_invoke', return_value=completed) as invoke:
            self.assertEqual(execute(self.config, req), completed)
            self.assertEqual(execute(self.config, request()), completed)
        self.assertEqual(invoke.call_count, 1)

    def test_unknown_receipt_keeps_recorded_spend_without_dispatching_again(self):
        req = request()
        failed_run = ExecutionResult('unknown', req.execution_id, '', 'native_nonzero', 'local-synthetic', USAGE)
        with patch.object(execution_module, '_invoke', return_value=failed_run) as invoke:
            self.assertEqual(execute(self.config, req), failed_run)
            repeated = execute(self.config, req)
        self.assertEqual(repeated, ExecutionResult('unknown', req.execution_id, '', 'previous_dispatch_unknown',
                                                   'local-synthetic', USAGE))
        self.assertEqual(invoke.call_count, 1)

    def test_five_column_receipt_database_is_migrated_and_keeps_old_receipts(self):
        old = request()
        with closing(sqlite3.connect(self.path)) as db:
            db.execute('CREATE TABLE receipts ('
                       'execution_id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, '
                       'status TEXT NOT NULL, reason TEXT NOT NULL, output TEXT NOT NULL)')
            db.execute('INSERT INTO receipts VALUES (?, ?, ?, ?, ?)',
                       (old.execution_id, execution_module._fingerprint(old), 'completed', 'completed', 'old reply'))
            db.commit()
        new = request(execution_id='workflow/1')
        completed = ExecutionResult('completed', new.execution_id, 'READY', 'completed', 'local-synthetic', USAGE)
        with patch.object(execution_module, '_invoke', return_value=completed) as invoke:
            self.assertEqual(execute(self.config, old),
                             ExecutionResult('completed', old.execution_id, 'old reply', 'completed'))
            invoke.assert_not_called()
            self.assertEqual(execute(self.config, new), completed)
            self.assertEqual(execute(self.config, new), completed)
        self.assertEqual(invoke.call_count, 1)
        with closing(sqlite3.connect(self.path)) as db:
            columns = [row[1] for row in db.execute('PRAGMA table_info(receipts)')]
        self.assertEqual(columns, ['execution_id', 'fingerprint', 'status', 'reason', 'output', 'usage', 'session_id'])

    def test_invoke_step_dispatches_every_call_without_a_receipt(self):
        completed = ExecutionResult('completed', 'workflow/0', 'READY', 'completed', 'local-synthetic', USAGE)
        with patch.object(execution_module, '_invoke', return_value=completed) as invoke, \
                patch.object(execution_module, 'ReceiptStore') as store:
            self.assertEqual(invoke_step(self.config, request()), completed)
            self.assertEqual(invoke_step(self.config, request()), completed)
            disabled = invoke_step(ExecutionConfig(), request())
            misconfigured = invoke_step(replace(self.config, hermes_home=None), request())
        self.assertEqual(invoke.call_count, 2)
        self.assertEqual((disabled.status, disabled.reason_code), ('failed', 'execution_disabled'))
        self.assertEqual((misconfigured.status, misconfigured.reason_code), ('failed', 'invalid_configuration'))
        store.assert_not_called()
        self.assertFalse(Path(self.path).exists())


@unittest.skipUnless(importlib.util.find_spec('temporalio') is not None, 'Temporal SDK is optional')
class WorkerOptionTests(unittest.TestCase):
    def start_worker(self, *argv):
        from . import worker

        with patch.object(worker, 'Client') as client, patch.object(worker, 'Worker') as temporal_worker, \
                patch.object(worker, 'ThreadPoolExecutor') as pool, \
                patch.object(worker, 'HermesActivities') as activities, redirect_stdout(io.StringIO()):
            client.connect = AsyncMock()
            temporal_worker.return_value.run = AsyncMock()
            self.assertEqual(worker.main(list(argv)), 0)
        return pool.call_args.kwargs, temporal_worker.call_args.kwargs, activities.call_args.args[0]

    def test_defaults_keep_four_activity_threads_and_no_usage_recording(self):
        pool, options, config = self.start_worker()
        self.assertEqual((pool, options['max_concurrent_activities']), ({'max_workers': 4}, 4))
        self.assertIs(config.record_usage, False)

    def test_team_options_reach_the_pool_the_worker_and_the_execution_config(self):
        pool, options, config = self.start_worker('--record-usage', '--activity-threads', '10')
        self.assertEqual((pool, options['max_concurrent_activities']), ({'max_workers': 10}, 10))
        self.assertIs(config.record_usage, True)

    def test_activity_threads_outside_one_through_thirty_two_are_rejected(self):
        from . import worker

        for value in ('0', '33', '-1', 'many'):
            with self.subTest(value=value), patch.object(worker, '_run'), redirect_stderr(io.StringIO()), \
                    self.assertRaises(SystemExit):
                worker.main(['--activity-threads', value])


@unittest.skipUnless(importlib.util.find_spec('temporalio') is not None, 'Temporal SDK is optional')
class ResultPayloadTests(unittest.TestCase):
    """The diagnostic field is optional on the wire, so recorded histories replay either way."""
    def test_older_and_newer_result_payloads_decode(self):
        from temporalio.api.common.v1 import Payload
        from temporalio.converter import DataConverter

        @dataclass(frozen=True)
        class OlderResult:
            status: str
            execution_id: str
            output: str
            reason_code: str
            session_id: str | None = None
            usage: dict | None = None

        converter = DataConverter.default.payload_converter
        failed = ExecutionResult('unknown', 'workflow/0', '', 'native_nonzero',
                                 diagnostic='exit code 1: RuntimeError: synthetic')
        payloads = converter.to_payloads([failed])
        self.assertEqual(converter.from_payloads(payloads, [ExecutionResult]), [failed])
        self.assertEqual(converter.from_payloads(payloads, [OlderResult]),
                         [OlderResult('unknown', 'workflow/0', '', 'native_nonzero')])
        recorded = Payload(metadata={'encoding': b'json/plain'}, data=json.dumps(
            {'status': 'unknown', 'execution_id': 'workflow/0', 'output': '', 'reason_code': 'native_nonzero',
             'session_id': None, 'usage': None}).encode('utf-8'))
        self.assertEqual(converter.from_payloads([recorded], [ExecutionResult]),
                         [ExecutionResult('unknown', 'workflow/0', '', 'native_nonzero')])


if __name__ == '__main__':
    unittest.main()

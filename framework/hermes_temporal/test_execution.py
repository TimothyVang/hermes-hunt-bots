"""Durable dispatch boundaries without running Hermes or a provider."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import io
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from . import execution as execution_module
from .contracts import ExecutionRequest, ExecutionResult, HermesStep
from .execution import ExecutionConfig, ReceiptStore, _environment, _invoke, execute


def request(prompt='synthetic prompt', execution_id='workflow/0', hunt_context=None):
    return ExecutionRequest(execution_id=execution_id, step=HermesStep(
        step_id='first', prompt=prompt, profile='framework-coordinator', timeout_seconds=10,
        hunt_context=hunt_context))

class ExecutionReceiptTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        home = root / 'separate-home'
        home.mkdir()
        self.path = str(root / 'receipts.sqlite3')
        self.config = ExecutionConfig(True, str(Path(sys.executable).resolve()), str(home), str(root), self.path)

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
                self.stdout = tempfile.TemporaryFile()
                self.stdout.write(output)
                self.stdout.seek(0)

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
                self.stdout = tempfile.TemporaryFile()
                self.stdout.write(b'reply')
                self.stdout.seek(0)

            def wait(self, timeout=None):
                return 0

        for visible, source in ((False, 'tool'), (True, 'cli')):
            config = replace(self.config, visible_sessions=visible)
            with patch.object(execution_module.subprocess, 'Popen', side_effect=Process) as popen:
                self.assertEqual(_invoke(config, request()).status, 'completed')
            command = popen.call_args.args[0]
            self.assertEqual(command[command.index('--source') + 1], source)


if __name__ == '__main__':
    unittest.main()

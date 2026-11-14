"""Live loopback WebSocket and control-pipe tests for self-contained gateway transport."""
from __future__ import annotations

import asyncio
from contextlib import closing
from dataclasses import replace
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import threading
from typing import Any
import unittest
from unittest.mock import patch

if importlib.util.find_spec("websockets") is None:
    raise unittest.SkipTest("Install hermes_temporal/requirements.txt to run gateway transport tests.")

from websockets.asyncio.server import serve as ws_serve

from . import execution as execution_module
from . import transport as transport_module
from .contracts import ExecutionRequest, ExecutionResult, HermesStep
from .execution import ExecutionConfig, ReceiptStore, execute


class _MockGatewayServer:
    """In-process ``hermes-gateway-v1`` JSON-RPC 2.0 WebSocket authority for transport tests."""

    def __init__(self, *, valid_ticket: str | None = "test-ticket-abc123") -> None:
        self.valid_ticket = valid_ticket
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.negotiated_subprotocols: list[tuple[str, ...]] = []
        self.on_submit: Any = None
        self.delta_burst = 0
        self.complete_text = '{"claims": []}'
        self.receipt_text = '{"claims": []}'
        self.main_usage = {
            "input_tokens": 1000,
            "output_tokens": 200,
            "cache_read_tokens": 400,
            "cache_write_tokens": 50,
            "total_tokens": 1200,
            "duration_ms": 321,
        }
        self.aux_usage: dict[str, dict[str, int]] = {}
        self.emit_replay_gap = False
        self.hang_submit = False
        self.stale_interrupt_once = False
        self._stale_sent = False
        self.turn_started = asyncio.Event()
        self.detached = asyncio.Event()
        self._server: Any = None
        self.ws_url = ""

    async def __aenter__(self) -> _MockGatewayServer:
        def select_subprotocol(connection: Any, subprotocols: list[str]) -> str | None:
            self.negotiated_subprotocols.append(tuple(subprotocols))
            if transport_module.GATEWAY_SUBPROTOCOL not in subprotocols:
                return None
            if self.valid_ticket is not None:
                expected = transport_module.TICKET_SUBPROTOCOL_PREFIX + self.valid_ticket
                if expected not in subprotocols:
                    return None
            return transport_module.GATEWAY_SUBPROTOCOL

        self._server = await ws_serve(
            self._handle_client,
            "127.0.0.1",
            0,
            select_subprotocol=select_subprotocol,
        )
        port = self._server.sockets[0].getsockname()[1]
        self.ws_url = f"ws://127.0.0.1:{port}/ws"
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()

    async def _send_event(
        self, ws: Any, session_id: str, kind: str, payload: dict[str, Any], *, admission_id: str | None = None, gen: int = 1
    ) -> None:
        params: dict[str, Any] = {
            "session_id": session_id,
            "type": kind,
            "execution_generation": gen,
            "payload": payload,
        }
        if admission_id is not None:
            params["admission_id"] = admission_id
        await ws.send(json.dumps({"jsonrpc": "2.0", "method": "session.event", "params": params}))

    async def _handle_client(self, ws: Any) -> None:
        state = {"session_id": "gw-sess-001", "admission_id": "adm-001"}

        async def on_describe(req_id: Any, _params: dict[str, Any]) -> None:
            res = {"session_create": {"sources": ["cli", "tool", "oneshot"], "parameters": ["cwd", "max_turns", "toolsets", "client_env"]}}
            await ws.send(json.dumps({"jsonrpc": "2.0", "id": req_id, "result": res}))

        async def on_create(req_id: Any, params: dict[str, Any]) -> None:
            req_digest = str(params.get("request_id") or "")[:12]
            state["session_id"] = f"sess-{req_digest}"
            snap = {"stored_session_id": state["session_id"], "subscription_id": f"sub-{req_digest}", "execution_generation": 1}
            await ws.send(json.dumps({"jsonrpc": "2.0", "id": req_id, "result": snap}))

        async def on_submit(req_id: Any, params: dict[str, Any]) -> None:
            session_id, admission_id = state["session_id"], state["admission_id"]
            if self.on_submit is not None:
                self.on_submit(params)
            await ws.send(json.dumps({"jsonrpc": "2.0", "id": req_id, "result": {"admission_id": admission_id, "execution_generation": 2}}))
            self.turn_started.set()
            if self.hang_submit:
                usage = {"input_tokens": 500, "output_tokens": 50, "cache_read_tokens": 100, "cache_write_tokens": 0, "total_tokens": 550}
                await self._send_event(ws, session_id, "session.usage", usage, admission_id=admission_id, gen=2)
                return
            for idx in range(self.delta_burst):
                await self._send_event(ws, session_id, "message.delta", {"delta": f"chunk-{idx} "}, admission_id=admission_id, gen=2)
            if self.emit_replay_gap:
                await self._send_event(ws, session_id, "session.replay_gap", {}, admission_id=admission_id, gen=2)
                return
            await self._send_event(
                ws, session_id, "session.usage",
                {**self.main_usage, **({"auxiliary_usage": self.aux_usage} if self.aux_usage else {})},
                admission_id=admission_id, gen=2,
            )
            await self._send_event(
                ws, session_id, "message.complete",
                {"outcome": "completed", "text": self.complete_text, "admission_id": admission_id},
                admission_id=admission_id, gen=2,
            )

        async def on_resume(req_id: Any, _params: dict[str, Any]) -> None:
            snap = {"stored_session_id": state["session_id"], "subscription_id": "sub-resumed", "execution_generation": 2, "pending": []}
            await ws.send(json.dumps({"jsonrpc": "2.0", "id": req_id, "result": snap}))

        async def on_cancel(req_id: Any, _params: dict[str, Any]) -> None:
            await ws.send(json.dumps({"jsonrpc": "2.0", "id": req_id, "result": {"cancelled": True, "execution_generation": 3}}))

        async def on_interrupt(req_id: Any, _params: dict[str, Any]) -> None:
            if self.stale_interrupt_once and not self._stale_sent:
                self._stale_sent = True
                err = {"code": -32009, "message": "stale generation", "data": {"reason": "stale_generation", "execution_generation": 7}}
                await ws.send(json.dumps({"jsonrpc": "2.0", "id": req_id, "error": err}))
                return
            await ws.send(json.dumps({"jsonrpc": "2.0", "id": req_id, "result": {"interrupted": True}}))

        async def on_receipt(req_id: Any, _params: dict[str, Any]) -> None:
            receipt = {
                "status": "terminal",
                "outcome": "cancelled" if self.hang_submit else "completed",
                "result": {
                    "final_response": self.receipt_text,
                    "completed": not self.hang_submit,
                    "interrupted": self.hang_submit,
                    **(self.main_usage if not self.hang_submit else {}),
                    **({"auxiliary_usage": self.aux_usage} if self.aux_usage and not self.hang_submit else {}),
                },
            }
            await ws.send(json.dumps({"jsonrpc": "2.0", "id": req_id, "result": receipt}))

        async def on_detach(req_id: Any, _params: dict[str, Any]) -> None:
            self.detached.set()
            await ws.send(json.dumps({"jsonrpc": "2.0", "id": req_id, "result": {"detached": True}}))

        dispatch = {
            "runtime.describe": on_describe,
            "session.create": on_create,
            "prompt.submit": on_submit,
            "session.resume": on_resume,
            "prompt.cancel": on_cancel,
            "session.interrupt": on_interrupt,
            "prompt.receipt": on_receipt,
            "session.detach": on_detach,
        }
        async for raw in ws:
            frame = json.loads(raw)
            method = frame["method"]
            params = frame.get("params") or {}
            self.calls.append((method, params))
            handler = dispatch.get(method)
            if handler is not None:
                await handler(frame["id"], params)


def _serve_windows_control_pipe(control_home: Path, responses: list[dict[str, Any]], received: list[dict[str, Any]]) -> threading.Thread:
    """Serve a sequence of one-request Windows named-pipe control exchanges for ``control_home``."""
    import _winapi
    import ctypes

    pipe_name = rf"\\.\pipe\hermes-gateway-{transport_module._home_hash(control_home)}"
    max_instances = max(4, len(responses))
    ready = threading.Event()

    def _make_pipe() -> int:
        return _winapi.CreateNamedPipe(
            pipe_name,
            _winapi.PIPE_ACCESS_DUPLEX | _winapi.FILE_FLAG_OVERLAPPED,
            _winapi.PIPE_WAIT,
            max_instances,
            65536,
            65536,
            0,
            _winapi.NULL,
        )

    def _worker() -> None:
        kernel32 = ctypes.WinDLL("kernel32")
        current: int | None = None
        nxt: int | None = None
        try:
            current = _make_pipe()
            ready.set()
            for idx, reply in enumerate(responses):
                assert current is not None
                conn_ov = _winapi.ConnectNamedPipe(current, overlapped=True)
                if _winapi.WaitForSingleObject(conn_ov.event, 5000) != _winapi.WAIT_OBJECT_0:
                    conn_ov.cancel()
                    conn_ov.GetOverlappedResult(True)
                    return
                conn_ov.GetOverlappedResult(True)
                read_ov, _ = _winapi.ReadFile(current, 8192, True)
                if _winapi.WaitForSingleObject(read_ov.event, 5000) != _winapi.WAIT_OBJECT_0:
                    read_ov.cancel()
                    read_ov.GetOverlappedResult(True)
                    return
                count, _ = read_ov.GetOverlappedResult(True)
                raw = bytes(read_ov.getbuffer()[:count])
                received.append(json.loads(raw.decode("utf-8").splitlines()[0]))
                if idx + 1 < len(responses):
                    nxt = _make_pipe()
                wire = (json.dumps(reply) + "\n").encode("utf-8")
                write_ov, _ = _winapi.WriteFile(current, wire, True)
                if _winapi.WaitForSingleObject(write_ov.event, 5000) != _winapi.WAIT_OBJECT_0:
                    write_ov.cancel()
                    write_ov.GetOverlappedResult(True)
                    return
                write_ov.GetOverlappedResult(True)
                kernel32.FlushFileBuffers(current)
                _winapi.CloseHandle(current)
                current, nxt = nxt, None
        finally:
            ready.set()
            if current is not None:
                _winapi.CloseHandle(current)
            if nxt is not None:
                _winapi.CloseHandle(nxt)

    thread = threading.Thread(target=_worker, daemon=True)
    thread.start()
    ready.wait(timeout=5)
    return thread


class GatewayTransportTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.base = Path(self._tmp.name).resolve()
        self.hermes_home = self.base / "hermes-home"
        for profile in ("framework-coordinator", "framework-researcher"):
            (self.hermes_home / "profiles" / profile).mkdir(parents=True, exist_ok=True)
        self.work_dir = self.base / "work"
        self.work_dir.mkdir()
        self.exe = self.base / ("hermes.exe" if os.name == "nt" else "hermes")
        self.exe.write_bytes(b"stub")
        if os.name != "nt":
            self.exe.chmod(0o700)
        self.receipt_db = self.base / "receipts.sqlite3"
        self.config = ExecutionConfig(
            enabled=True,
            executable=str(self.exe),
            hermes_home=str(self.hermes_home),
            working_directory=str(self.work_dir),
            receipt_db=str(self.receipt_db),
            record_usage=True,
        )

    async def test_pre_submit_wal_checkpoint_unredacted_ioc_and_stall_free_6000_event_drain(self) -> None:
        ioc_sha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        secret_shaped_ioc = "sk-live-canary1234567890abcdef"
        unredacted = json.dumps({"ioc_sha256": ioc_sha, "canary": secret_shaped_ioc})
        checkpoint_seen_at_submit: list[tuple[str | None, str | None] | None] = []

        async with _MockGatewayServer() as server:
            server.delta_burst = 6000
            server.complete_text = unredacted
            server.receipt_text = '{"ioc_sha256": "[REDACTED]", "canary": "[REDACTED]"}'
            server.aux_usage = {"vision": {"input_tokens": 120, "output_tokens": 30, "cache_read_tokens": 10, "cache_write_tokens": 0}}

            def inspect_wal_before_turn(_submit_params: dict[str, Any]) -> None:
                store = ReceiptStore(str(self.receipt_db))
                checkpoint_seen_at_submit.append(store.checkpointed("hunt-alpha:0"))

            server.on_submit = inspect_wal_before_turn
            cfg = replace(self.config, gateway_ws_url=server.ws_url, gateway_ticket="test-ticket-abc123")
            req = ExecutionRequest(
                "hunt-alpha:0",
                HermesStep("scope", "Confirm scope only.", "framework-coordinator", timeout_seconds=30),
            )
            prior_env = os.environ.get("HERMES_HOME")
            res = await asyncio.to_thread(execute, cfg, req)
            self.assertEqual(os.environ.get("HERMES_HOME"), prior_env)

        expected_req_id = hashlib.sha256(b"hunt-alpha:0").hexdigest()
        expected_inp_id = hashlib.sha256(b"hunt-alpha:0:input").hexdigest()
        expected_sess = f"sess-{expected_req_id[:12]}"
        self.assertEqual(checkpoint_seen_at_submit, [(expected_sess, expected_inp_id)])
        self.assertEqual(res.status, "completed")
        self.assertEqual(res.output, unredacted, "live message.complete must bypass state.db redaction")
        self.assertEqual(res.session_id, expected_sess)
        self.assertEqual(res.usage, {
            "input_tokens": 1120,
            "output_tokens": 230,
            "cache_read_tokens": 410,
            "cache_write_tokens": 50,
            "total_tokens": 1350,
            "duration_ms": 321,
        })
        methods = [m for m, _ in server.calls]
        self.assertEqual(methods, ["runtime.describe", "session.create", "prompt.submit", "prompt.receipt", "session.detach"])
        create_params = dict(server.calls[1][1])
        self.assertEqual(create_params["request_id"], expected_req_id)
        self.assertEqual(create_params["max_turns"], 8)
        self.assertEqual(create_params["toolsets"], ["no_mcp"])
        self.assertEqual(create_params["client_env"], {"HUNT_RUN_ID": "hunt-alpha", "HUNT_STEP_ID": "scope"})
        submit_params = dict(server.calls[2][1])
        self.assertEqual((submit_params["finite"], submit_params["unattended"]), (True, True))
        detach_params = dict(server.calls[-1][1])
        self.assertEqual(detach_params["end_reason"], "cli_close")

    async def test_specialist_turn_budget_timeout_cancel_fenced_interrupt_and_db_aux_usage(self) -> None:
        profile_home = self.hermes_home / "profiles" / "framework-researcher"
        state_db = profile_home / "state.db"
        expected_sess = f"sess-{hashlib.sha256(b'hunt-beta:1').hexdigest()[:12]}"
        with closing(sqlite3.connect(state_db)) as conn:
            conn.execute(
                "CREATE TABLE session_model_usage ("
                "session_id TEXT, task TEXT, input_tokens INTEGER, output_tokens INTEGER, "
                "cache_read_tokens INTEGER, cache_write_tokens INTEGER)"
            )
            conn.execute(
                "INSERT INTO session_model_usage VALUES (?, 'summarizer', 200, 40, 25, 5)",
                (expected_sess,),
            )
            conn.commit()

        async with _MockGatewayServer() as server:
            server.hang_submit = True
            server.stale_interrupt_once = True
            cfg = replace(self.config, gateway_ws_url=server.ws_url, gateway_ticket="test-ticket-abc123")
            req = ExecutionRequest(
                "hunt-beta:1",
                HermesStep("evidence", "Search Elastic.", "framework-researcher", timeout_seconds=1),
            )
            res = await asyncio.to_thread(execute, cfg, req)

        self.assertEqual((res.status, res.reason_code, res.session_id), ("unknown", "subprocess_timeout", expected_sess))
        assert res.usage is not None
        self.assertEqual((res.usage["input_tokens"], res.usage["output_tokens"], res.usage["total_tokens"]), (700, 90, 790))
        methods = [m for m, _ in server.calls]
        self.assertEqual(
            methods,
            [
                "runtime.describe", "session.create", "prompt.submit",
                "prompt.cancel", "session.interrupt", "session.interrupt",
                "prompt.receipt", "session.detach",
            ],
        )
        create_params = dict(server.calls[1][1])
        self.assertEqual(create_params["max_turns"], 6)
        self.assertNotIn("toolsets", create_params)
        interrupts = [p for m, p in server.calls if m == "session.interrupt"]
        self.assertEqual([p["execution_generation"] for p in interrupts], [3, 7])

    async def test_cancelled_ws_turn_sends_cancel_interrupt_and_detach_and_replay_gap_recovers(self) -> None:
        async with _MockGatewayServer() as server:
            server.hang_submit = True
            endpoint = transport_module.discover_endpoint(
                self.hermes_home, "framework-researcher",
                gateway_ws_url=server.ws_url, gateway_ticket="test-ticket-abc123",
            )
            req = ExecutionRequest(
                "hunt-cancel:0",
                HermesStep("evidence", "Search Elastic.", "framework-researcher", timeout_seconds=60),
            )
            task = asyncio.create_task(
                transport_module._execute_over_ws(
                    endpoint, req,
                    working_directory=str(self.work_dir),
                    visible_sessions=False,
                    record_usage=True,
                    explicit_ws_url=True,
                    checkpoint=None,
                    redact_fn=None,
                )
            )
            await asyncio.wait_for(server.turn_started.wait(), timeout=5)
            await asyncio.sleep(0.05)
            task.cancel()
            cancelled = await task
            self.assertEqual((cancelled.status, cancelled.reason_code), ("unknown", "cancelled"))
            self.assertIn("prompt.cancel", [m for m, _ in server.calls])
            self.assertIn("session.interrupt", [m for m, _ in server.calls])
            self.assertIn("session.detach", [m for m, _ in server.calls])

        async with _MockGatewayServer() as gap_server:
            gap_server.emit_replay_gap = True
            gap_server.receipt_text = '{"recovered": true}'
            cfg = replace(self.config, gateway_ws_url=gap_server.ws_url, gateway_ticket="test-ticket-abc123")
            recovered = await asyncio.to_thread(
                execute,
                cfg,
                ExecutionRequest("hunt-gap:0", HermesStep("evidence", "Recover.", "framework-researcher")),
            )
        self.assertEqual((recovered.status, recovered.output), ("completed", '{"recovered": true}'))
        self.assertIn("session.resume", [m for m, _ in gap_server.calls])

    @unittest.skipUnless(os.name == "nt", "Windows named-pipe control socket test")
    async def test_windows_control_pipe_multiplexer_discovery_and_legacy_ticket_fallback(self) -> None:
        profile_home = (self.hermes_home / "profiles" / "framework-researcher").resolve()
        received: list[dict[str, Any]] = []
        async with _MockGatewayServer(valid_ticket="pipe-minted-ticket-99") as server:
            origin = server.ws_url.replace("ws://", "http://")[:-3]
            responses = [
                {
                    "ok": True,
                    "result": {
                        "runtime_protocol": 1,
                        "state": "ready",
                        "capabilities": ["session-authority-v1"],
                        "api_origin": origin,
                        "instance_id": "inst-mux-1",
                        "served_profiles": [{"id": "framework-researcher", "home": str(profile_home)}],
                    },
                },
                {"ok": False, "error": "PermissionError: invalid bootstrap parameters"},
                {
                    "ok": True,
                    "result": {
                        "runtime_protocol": 1,
                        "profile_id": "framework-researcher",
                        "instance_id": "inst-mux-1",
                        "ticket": "pipe-minted-ticket-99",
                    },
                },
            ]
            pipe_thread = _serve_windows_control_pipe(self.hermes_home, responses, received)
            res = await asyncio.to_thread(
                execute,
                self.config,
                ExecutionRequest("hunt-pipe:0", HermesStep("evidence", "Via mux pipe.", "framework-researcher")),
            )
            pipe_thread.join(timeout=5)
        self.assertEqual(res.status, "completed")
        self.assertEqual([r["verb"] for r in received], ["identify", "session-ticket", "session-ticket"])
        self.assertEqual(received[1]["params"]["restart_wait"], "refuse")
        self.assertNotIn("restart_wait", received[2]["params"])

    def test_missing_gateway_falls_back_cleanly_to_cli_subprocess(self) -> None:
        cli_res = ExecutionResult("completed", "hunt-fallback:0", "CLI-OK", "completed", "cli-sess")
        with patch.object(execution_module, "_invoke_cli", return_value=cli_res) as cli_mock:
            out = execute(
                self.config,
                ExecutionRequest("hunt-fallback:0", HermesStep("scope", "Fallback test.")),
            )
        self.assertEqual(out, cli_res)
        self.assertEqual(cli_mock.call_count, 1)

    def test_transport_imports_and_runs_with_core_hermes_modules_blocked(self) -> None:
        framework_dir = str(Path(__file__).resolve().parents[1])
        probe = (
            "import importlib.abc, sys\n"
            "BLOCKED = {'hermes_cli', 'gateway', 'agent', 'run_agent', 'hermes_constants', 'model_tools'}\n"
            "class Blocker(importlib.abc.MetaPathFinder):\n"
            "    def find_spec(self, fullname, path, target=None):\n"
            "        if fullname.split('.')[0] in BLOCKED:\n"
            "            raise ImportError(f'blocked import: {fullname}')\n"
            "        return None\n"
            "sys.meta_path.insert(0, Blocker())\n"
            "sys.path = [p for p in sys.path if 'swarm-pr2-temporal' not in p] + [sys.argv[1]]\n"
            "import hermes_temporal.transport as t\n"
            "import hermes_temporal.execution as e\n"
            "print(t.GATEWAY_SUBPROTOCOL, t.profile_max_turns('framework-coordinator'), "
            "t.profile_max_turns('framework-researcher'), t.step_toolsets('scope'))\n"
        )
        proc = subprocess.run(
            [sys.executable, "-P", "-c", probe, framework_dir],
            cwd=self.base,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout.strip(), "hermes-gateway-v1 8 6 ('no_mcp',)")


if __name__ == "__main__":
    unittest.main()

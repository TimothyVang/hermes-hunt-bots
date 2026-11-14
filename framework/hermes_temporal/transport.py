"""Self-contained gateway WebSocket transport for native Hermes execution.

Uses only the Python standard library and ``websockets`` (no ``hermes_cli`` or
``gateway`` imports), so the Temporal worker runs unchanged inside
``framework/.venv-temporal`` and the standalone portable package.
"""
from __future__ import annotations

import asyncio
from contextlib import closing, suppress
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import sqlite3
import stat
import time
from typing import Any, Callable
import urllib.parse

from .contracts import MAX_DIAGNOSTIC_CHARS, MAX_PROMPT_BYTES, USAGE_KEYS, ExecutionRequest, ExecutionResult

GATEWAY_SUBPROTOCOL = "hermes-gateway-v1"
TICKET_SUBPROTOCOL_PREFIX = "hermes-gateway-ticket."
DEFAULT_RPC_TIMEOUT = 30.0
CLEANUP_RPC_TIMEOUT = 5.0
MAX_CONTROL_RESPONSE_BYTES = 524288
MAX_WS_FRAME_BYTES = 8 * 1024 * 1024
MAX_OUTPUT_BYTES = MAX_PROMPT_BYTES
_UNKNOWN_TICKET_PARAMS = "PermissionError: invalid bootstrap parameters"
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})
_TICKET_SAFE = re.compile(r"[A-Za-z0-9._~+/=-]{1,512}\Z")
_ENV_SAFE = re.compile(r"[^A-Za-z0-9_.:-]+")
_PIPE_CLIENT_SQOS = 0x00100000 | 0x00010000
_ASYNC_TIMEOUT_ERRORS = tuple({TimeoutError, asyncio.TimeoutError})

# Aligned with framework/native_team.py per-profile turn budgets.
PROFILE_MAX_TURNS: dict[str, int] = {
    "framework-coordinator": 8,
    "framework-researcher": 6,
    "framework-builder": 6,
    "framework-reviewer": 6,
    "framework-librarian": 6,
    "framework-network-analyst": 6,
}


class GatewayNotAvailable(Exception):
    """Raised before dispatch when no ready local gateway serves the profile."""


class _ControlRefused(Exception):
    """Raised when the gateway control socket returns ``ok: false``."""


class _RpcError(Exception):
    """JSON-RPC error returned by the gateway authority."""

    def __init__(self, error: Any) -> None:
        data = error.get("data") if isinstance(error, dict) and isinstance(error.get("data"), dict) else {}
        message = error.get("message") if isinstance(error, dict) else str(error)
        self.code = error.get("code") if isinstance(error, dict) else None
        self.reason = str(data.get("reason") or message or "rpc_error")
        self.data = data
        super().__init__(str(message or self.reason))


@dataclass(frozen=True)
class GatewayEndpoint:
    ws_url: str
    ticket: str | None
    profile_home: Path
    control_home: Path | None
    profile_id: str
    instance_id: str


def profile_max_turns(profile: str) -> int:
    return PROFILE_MAX_TURNS.get(profile, 6)


def step_toolsets(step_id: str) -> tuple[str, ...] | None:
    """Block ``delegate_task`` on ``scope`` so scope confirmation stays metadata-only."""
    return ("no_mcp",) if step_id == "scope" else None


def hunt_env_for_request(request: ExecutionRequest) -> dict[str, str]:
    raw_id = request.execution_id.removesuffix(":retry")
    for sep in (":", "/"):
        head, found, tail = raw_id.rpartition(sep)
        if found and head and tail.isdigit():
            raw_id = head
            break
    run_id = _ENV_SAFE.sub("_", raw_id).strip("_")[:128] or "hunt"
    return {"HUNT_RUN_ID": run_id, "HUNT_STEP_ID": request.step.step_id}


def _home_hash(home: Path) -> str:
    normalized = os.path.normcase(str(Path(home).expanduser().resolve(strict=False)))
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:16]


def validate_loopback_ws_url(url: str) -> str:
    if not isinstance(url, str) or not url:
        raise ValueError("gateway_ws_url must be a non-empty loopback ws:// or wss:// URL")
    parsed = urllib.parse.urlsplit(url)
    host = (parsed.hostname or "").lower()
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("gateway_ws_url has an invalid port") from exc
    if (parsed.scheme not in ("ws", "wss") or parsed.username or parsed.password
            or host not in _LOOPBACK_HOSTS or port is None or not 1 <= port <= 65535):
        raise ValueError("gateway_ws_url must target a loopback ws:// or wss:// host:port")
    return url


def _ws_url_from_origin(api_origin: object) -> str | None:
    if not isinstance(api_origin, str) or not api_origin:
        return None
    parsed = urllib.parse.urlsplit(api_origin)
    host = (parsed.hostname or "").lower()
    try:
        port = parsed.port
    except ValueError:
        return None
    if (parsed.scheme not in ("http", "https") or parsed.username or parsed.password
            or host not in _LOOPBACK_HOSTS or port is None or not 1 <= port <= 65535):
        return None
    scheme = "wss" if parsed.scheme == "https" else "ws"
    return f"{scheme}://{parsed.netloc}/api/ws"


def _current_windows_sid() -> str:
    import ctypes
    from ctypes import wintypes

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel32.LocalFree.argtypes = (wintypes.HLOCAL,)
    advapi32.OpenProcessToken.argtypes = (wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE))
    advapi32.OpenProcessToken.restype = wintypes.BOOL
    advapi32.GetTokenInformation.argtypes = (
        wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD))
    advapi32.GetTokenInformation.restype = wintypes.BOOL
    advapi32.ConvertSidToStringSidW.argtypes = (wintypes.LPVOID, ctypes.POINTER(wintypes.LPWSTR))
    advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL

    token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), 0x0008, ctypes.byref(token)):
        raise OSError(ctypes.get_last_error(), "OpenProcessToken failed")
    try:
        needed = wintypes.DWORD()
        advapi32.GetTokenInformation(token, 1, None, 0, ctypes.byref(needed))
        buf = ctypes.create_string_buffer(needed.value)
        if not advapi32.GetTokenInformation(token, 1, buf, needed, ctypes.byref(needed)):
            raise OSError(ctypes.get_last_error(), "GetTokenInformation failed")
        sid_ptr = ctypes.cast(buf, ctypes.POINTER(wintypes.LPVOID)).contents
        str_ptr = wintypes.LPWSTR()
        if not advapi32.ConvertSidToStringSidW(sid_ptr, ctypes.byref(str_ptr)):
            raise OSError(ctypes.get_last_error(), "ConvertSidToStringSidW failed")
        try:
            return str(str_ptr.value)
        finally:
            kernel32.LocalFree(str_ptr)
    finally:
        kernel32.CloseHandle(token)


def _handle_owner_sid(handle: int) -> str:
    import ctypes
    from ctypes import wintypes

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.LocalFree.argtypes = (wintypes.HLOCAL,)
    advapi32.GetSecurityInfo.argtypes = (
        wintypes.HANDLE, ctypes.c_int, wintypes.DWORD, ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.LPVOID), ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.LPVOID), ctypes.POINTER(wintypes.LPVOID))
    advapi32.GetSecurityInfo.restype = wintypes.DWORD
    advapi32.ConvertSidToStringSidW.argtypes = (wintypes.LPVOID, ctypes.POINTER(wintypes.LPWSTR))
    advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL

    owner = wintypes.LPVOID()
    sd = wintypes.LPVOID()
    rc = advapi32.GetSecurityInfo(wintypes.HANDLE(handle), 6, 1, ctypes.byref(owner), None, None, None, ctypes.byref(sd))
    if rc != 0:
        raise OSError(rc, "GetSecurityInfo failed")
    try:
        str_ptr = wintypes.LPWSTR()
        if not advapi32.ConvertSidToStringSidW(owner, ctypes.byref(str_ptr)):
            raise OSError(ctypes.get_last_error(), "ConvertSidToStringSidW failed")
        try:
            return str(str_ptr.value)
        finally:
            kernel32.LocalFree(str_ptr)
    finally:
        if sd.value:
            kernel32.LocalFree(sd)


def _await_overlapped(overlapped: Any, deadline: float) -> tuple[int, int]:
    import _winapi

    try:
        remaining_ms = max(1, int((deadline - time.monotonic()) * 1000))
        if time.monotonic() >= deadline or _winapi.WaitForSingleObject(overlapped.event, remaining_ms) != _winapi.WAIT_OBJECT_0:
            raise TimeoutError("gateway control pipe timed out")
        return overlapped.GetOverlappedResult(False)
    except BaseException:
        overlapped.cancel()
        overlapped.GetOverlappedResult(True)
        raise


def _open_windows_pipe(pipe_name: str, deadline: float) -> int:
    import _winapi

    flags = _winapi.FILE_FLAG_OVERLAPPED | _PIPE_CLIENT_SQOS
    while True:
        try:
            return _winapi.CreateFile(pipe_name, 0xC0000000, 0, _winapi.NULL, _winapi.OPEN_EXISTING, flags, _winapi.NULL)
        except FileNotFoundError as exc:
            raise GatewayNotAvailable("gateway control pipe not present") from exc
        except OSError as exc:
            if getattr(exc, "winerror", None) != 231:
                raise GatewayNotAvailable("gateway control pipe unavailable") from exc
            remaining_ms = max(1, int((deadline - time.monotonic()) * 1000))
            if time.monotonic() >= deadline:
                raise GatewayNotAvailable("gateway control pipe busy") from exc
            try:
                _winapi.WaitNamedPipe(pipe_name, min(remaining_ms, 250))
            except OSError as wait_exc:
                raise GatewayNotAvailable("gateway control pipe unavailable") from wait_exc


def _query_control_windows(home: Path, request: bytes, timeout: float) -> bytes:
    import _winapi

    deadline = time.monotonic() + timeout
    pipe_name = rf"\\.\pipe\hermes-gateway-{_home_hash(home)}"
    handle = _open_windows_pipe(pipe_name, deadline)
    try:
        if _handle_owner_sid(handle) != _current_windows_sid():
            raise GatewayNotAvailable("gateway control pipe owner mismatch")
        write_ov, _ = _winapi.WriteFile(handle, request, True)
        written, _ = _await_overlapped(write_ov, deadline)
        if written != len(request):
            raise GatewayNotAvailable("incomplete gateway control write")
        data = bytearray()
        while b"\n" not in data:
            read_ov, _ = _winapi.ReadFile(handle, 4096, True)
            count, err = _await_overlapped(read_ov, deadline)
            chunk = read_ov.getbuffer()[:count]
            if not chunk or len(data) + len(chunk) > MAX_CONTROL_RESPONSE_BYTES:
                raise GatewayNotAvailable("invalid gateway control response")
            data.extend(chunk)
            if err not in (0, _winapi.ERROR_MORE_DATA) and b"\n" not in data:
                break
        return bytes(data)
    except TimeoutError as exc:
        raise GatewayNotAvailable("gateway control pipe timed out") from exc
    except OSError as exc:
        raise GatewayNotAvailable("gateway control pipe failed") from exc
    finally:
        _winapi.CloseHandle(handle)


def _resolve_posix_socket_path(home: Path) -> Path:
    pointer = home / "gateway.sock.path"
    try:
        if pointer.is_file() and not pointer.is_symlink():
            target = pointer.read_text(encoding="utf-8").strip()
            if target:
                return Path(target)
    except OSError:
        pass
    return home / "gateway.sock"


def _query_control_posix(home: Path, request: bytes, timeout: float) -> bytes:
    sock_path = _resolve_posix_socket_path(home)
    try:
        info = os.lstat(sock_path)
    except OSError as exc:
        raise GatewayNotAvailable("gateway control socket not present") from exc
    if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.getuid():
        raise GatewayNotAvailable("gateway control socket invalid owner or mode")
    deadline = time.monotonic() + timeout
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(timeout)
            client.connect(str(sock_path))
            client.sendall(request)
            data = bytearray()
            while b"\n" not in data:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise GatewayNotAvailable("gateway control socket timed out")
                client.settimeout(remaining)
                chunk = client.recv(4096)
                if not chunk or len(data) + len(chunk) > MAX_CONTROL_RESPONSE_BYTES:
                    raise GatewayNotAvailable("invalid gateway control response")
                data.extend(chunk)
            return bytes(data)
    except OSError as exc:
        raise GatewayNotAvailable("gateway control socket unavailable") from exc


def _control_query(home: Path, verb: str, params: dict[str, Any] | None = None, timeout: float = 5.0) -> dict[str, Any]:
    body: dict[str, Any] = {"protocol": 1, "id": 1, "verb": verb}
    if params is not None:
        body["params"] = params
    wire = json.dumps(body, separators=(",", ":")).encode("utf-8") + b"\n"
    raw = _query_control_windows(home, wire, timeout) if os.name == "nt" else _query_control_posix(home, wire, timeout)
    try:
        parsed = json.loads(raw.split(b"\n", 1)[0].decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise GatewayNotAvailable("malformed gateway control JSON") from exc
    if not isinstance(parsed, dict):
        raise GatewayNotAvailable("unexpected gateway control payload")
    if parsed.get("ok") is not True:
        raise _ControlRefused(str(parsed.get("error") or "control_refused"))
    result = parsed.get("result")
    if not isinstance(result, dict):
        raise GatewayNotAvailable("missing gateway control result")
    return result


def _norm_home(path: Path) -> str:
    return os.path.normcase(str(Path(path).resolve(strict=False)))


def _match_identify(result: dict[str, Any], profile_home: Path) -> tuple[str, str, str] | None:
    if result.get("runtime_protocol") != 1 or result.get("state") != "ready":
        return None
    capabilities = result.get("capabilities")
    if not isinstance(capabilities, list) or "session-authority-v1" not in capabilities:
        return None
    ws_url = _ws_url_from_origin(result.get("api_origin"))
    instance_id = result.get("instance_id")
    if ws_url is None or not isinstance(instance_id, str) or not instance_id:
        return None
    wanted = _norm_home(profile_home)
    served = result.get("served_profiles")
    if isinstance(served, list):
        matches: list[str] = []
        for entry in served:
            if not isinstance(entry, dict):
                continue
            entry_home = entry.get("home") or entry.get("profile_id")
            entry_id = entry.get("profile_id") or entry.get("id") or entry_home
            if isinstance(entry_home, str) and isinstance(entry_id, str) and entry_id and _norm_home(Path(entry_home)) == wanted:
                matches.append(entry_id)
        if len(matches) != 1:
            return None
        return ws_url, matches[0], instance_id
    direct_id = result.get("profile_id")
    if isinstance(direct_id, str) and direct_id and _norm_home(Path(direct_id)) == wanted:
        return ws_url, direct_id, instance_id
    return None


def _mint_ticket(control_home: Path, profile_id: str, instance_id: str) -> str:
    params: dict[str, Any] = {
        "profile_id": profile_id,
        "instance_id": instance_id,
        "purpose": "interactive",
        "restart_wait": "refuse",
    }
    try:
        grant = _control_query(control_home, "session-ticket", params)
    except _ControlRefused as exc:
        if str(exc) != _UNKNOWN_TICKET_PARAMS:
            raise GatewayNotAvailable(f"ticket refused: {exc}") from exc
        params.pop("restart_wait", None)
        try:
            grant = _control_query(control_home, "session-ticket", params)
        except _ControlRefused as retry_exc:
            raise GatewayNotAvailable(f"ticket refused: {retry_exc}") from retry_exc
    ticket = grant.get("ticket")
    if (grant.get("runtime_protocol") != 1 or grant.get("profile_id") != profile_id
            or grant.get("instance_id") != instance_id or not isinstance(ticket, str)
            or _TICKET_SAFE.fullmatch(ticket) is None):
        raise GatewayNotAvailable("invalid session ticket grant")
    return ticket


def discover_endpoint(
    root_home: Path,
    profile: str,
    *,
    gateway_ws_url: str | None = None,
    gateway_ticket: str | None = None,
) -> GatewayEndpoint:
    """Locate the local gateway serving ``profile_home`` without mutating ``os.environ``."""
    root = Path(root_home).resolve()
    profile_home = (root / "profiles" / profile).resolve()
    if gateway_ws_url is not None:
        ws_url = validate_loopback_ws_url(gateway_ws_url)
        if gateway_ticket is not None and (
                not isinstance(gateway_ticket, str) or _TICKET_SAFE.fullmatch(gateway_ticket) is None):
            raise ValueError("gateway_ticket contains invalid characters")
        return GatewayEndpoint(ws_url, gateway_ticket, profile_home, None, str(profile_home), "explicit")
    candidates: list[Path] = [profile_home]
    if _norm_home(root) != _norm_home(profile_home):
        candidates.append(root)
    for candidate in candidates:
        try:
            identified = _control_query(candidate, "identify")
        except (GatewayNotAvailable, _ControlRefused):
            continue
        matched = _match_identify(identified, profile_home)
        if matched is None:
            continue
        ws_url, profile_id, instance_id = matched
        ticket = _mint_ticket(candidate, profile_id, instance_id)
        return GatewayEndpoint(ws_url, ticket, profile_home, candidate, profile_id, instance_id)
    raise GatewayNotAvailable("no ready gateway serves this profile")


def _nonneg_int(value: object) -> int:
    if isinstance(value, bool):
        return 0
    if isinstance(value, int):
        return max(0, value)
    if isinstance(value, float) and value.is_integer():
        return max(0, int(value))
    return 0


def _strict_nonneg_int(value: object) -> int | None:
    if type(value) is int and value >= 0:
        return value
    if type(value) is float and value >= 0 and value.is_integer():
        return int(value)
    return None


def _read_db_auxiliary_usage(profile_home: Path, session_id: str | None) -> dict[str, dict[str, int]]:
    """Read auxiliary token rows committed to ``state.db`` (including mid-turn before settlement)."""
    if not session_id:
        return {}
    state_db = profile_home / "state.db"
    if not state_db.is_file():
        return {}
    uri = state_db.resolve().as_uri() + "?mode=ro"
    try:
        with closing(sqlite3.connect(uri, uri=True, timeout=2.0)) as conn:
            rows = conn.execute(
                "SELECT task, COALESCE(SUM(input_tokens), 0), COALESCE(SUM(output_tokens), 0), "
                "COALESCE(SUM(cache_read_tokens), 0), COALESCE(SUM(cache_write_tokens), 0) "
                "FROM session_model_usage WHERE session_id = ? AND task != '' GROUP BY task",
                (session_id,),
            ).fetchall()
    except sqlite3.Error:
        return {}
    return {
        str(task): {
            "input_tokens": _nonneg_int(inp),
            "output_tokens": _nonneg_int(out),
            "cache_read_tokens": _nonneg_int(cr),
            "cache_write_tokens": _nonneg_int(cw),
        }
        for task, inp, out, cr, cw in rows
        if task
    }


def _sum_auxiliary(by_task: dict[str, Any]) -> dict[str, int]:
    totals = {"input_tokens": 0, "output_tokens": 0, "cache_read_tokens": 0, "cache_write_tokens": 0, "total_tokens": 0}
    for counters in by_task.values():
        if not isinstance(counters, dict):
            continue
        inp = _nonneg_int(counters.get("input_tokens"))
        out = _nonneg_int(counters.get("output_tokens"))
        totals["input_tokens"] += inp
        totals["output_tokens"] += out
        totals["cache_read_tokens"] += _nonneg_int(counters.get("cache_read_tokens"))
        totals["cache_write_tokens"] += _nonneg_int(counters.get("cache_write_tokens"))
        explicit_total = _nonneg_int(counters.get("total_tokens"))
        totals["total_tokens"] += explicit_total if explicit_total > 0 else (inp + out)
    return totals


def _extract_main_tokens(sources: tuple[dict[str, Any], ...]) -> tuple[dict[str, int], bool]:
    keys = ("input_tokens", "output_tokens", "cache_read_tokens", "cache_write_tokens", "total_tokens")
    for source in sources:
        if not source or not any(k in source for k in keys):
            continue
        parsed = {k: _strict_nonneg_int(source.get(k, 0)) for k in keys}
        if any(v is None for v in parsed.values()):
            continue
        clean = {k: int(v) for k, v in parsed.items() if v is not None}
        if clean["total_tokens"] == 0 and (clean["input_tokens"] or clean["output_tokens"]):
            clean["total_tokens"] = clean["input_tokens"] + clean["output_tokens"]
        return clean, True
    return {k: 0 for k in keys}, False


def _build_usage(
    *,
    record_usage: bool,
    result_body: dict[str, Any],
    receipt_usage: dict[str, Any],
    live_usage: dict[str, int],
    saw_live_usage: bool,
    live_aux_usage: dict[str, Any],
    profile_home: Path,
    session_id: str | None,
    elapsed_ms: int,
    allow_zero: bool = True,
) -> dict[str, int] | None:
    if not record_usage:
        return None
    main_sources = (result_body, receipt_usage, live_usage if saw_live_usage else {})
    main, has_main = _extract_main_tokens(main_sources)
    aux_source = (
        result_body.get("auxiliary_usage")
        if isinstance(result_body.get("auxiliary_usage"), dict) and result_body.get("auxiliary_usage")
        else receipt_usage.get("auxiliary_usage")
        if isinstance(receipt_usage.get("auxiliary_usage"), dict) and receipt_usage.get("auxiliary_usage")
        else live_aux_usage
        if live_aux_usage
        else _read_db_auxiliary_usage(profile_home, session_id)
    )
    aux = _sum_auxiliary(aux_source if isinstance(aux_source, dict) else {})
    has_aux = any(v > 0 for v in aux.values())
    if not (has_main or has_aux or allow_zero):
        return None
    duration = _strict_nonneg_int(result_body.get("duration_ms"))
    usage = {
        "input_tokens": main["input_tokens"] + aux["input_tokens"],
        "output_tokens": main["output_tokens"] + aux["output_tokens"],
        "cache_read_tokens": main["cache_read_tokens"] + aux["cache_read_tokens"],
        "cache_write_tokens": main["cache_write_tokens"] + aux["cache_write_tokens"],
        "total_tokens": main["total_tokens"] + aux["total_tokens"],
        "duration_ms": duration if duration is not None else max(0, elapsed_ms),
    }
    return usage if set(usage) == USAGE_KEYS else None


class _GatewayWSConnection:
    """JSON-RPC 2.0 WebSocket client with a mandatory non-blocking event-drainer task.

    Incoming notifications are drained immediately in O(1) memory instead of sitting in
    a bounded consumer queue, preventing ``EVENT_STALL_TIMEOUT`` disconnects on long
    tool-heavy turns while preserving live unredacted ``message.complete`` text and
    live ``session.usage`` token counters.
    """

    def __init__(self, ws: Any) -> None:
        self.ws = ws
        self.sequence = 0
        self.pending_rpcs: dict[int, asyncio.Future[Any]] = {}
        self.session_id: str | None = None
        self.subscription_id: str | None = None
        self.generation: int = 0
        self.input_id: str | None = None
        self.admission_id: str | None = None
        self.pending_rows: list[dict[str, Any]] = []
        self.buffered_completions: list[tuple[str | None, dict[str, Any]]] = []
        self.completion: dict[str, Any] | None = None
        self.live_usage: dict[str, int] = {}
        self.saw_live_usage = False
        self.live_aux_usage: dict[str, Any] = {}
        self.last_receipt: dict[str, Any] = {}
        self.cleaned_up = False
        self.blocked_reason: str | None = None
        self.replay_gap = False
        self.disconnect_error: str | None = None
        self.drained_events = 0
        self.state_changed = asyncio.Event()
        self.drainer_task: asyncio.Task[None] | None = None

    def start_drainer(self) -> None:
        self.drainer_task = asyncio.create_task(self._drain_loop())

    async def stop_drainer(self) -> None:
        if self.drainer_task is not None:
            self.drainer_task.cancel()
            with suppress(asyncio.CancelledError):
                await self.drainer_task

    def bind_session(self, session_id: str, subscription_id: str | None, generation: int) -> None:
        self.session_id = session_id
        self.subscription_id = subscription_id
        self.generation = generation

    def bind_admission(self, admission_id: str, generation: object = None) -> None:
        self.admission_id = admission_id
        if type(generation) is int:
            self.generation = generation
        for event_adm, payload in self.buffered_completions:
            if event_adm in (None, admission_id) and self.completion is None:
                self.completion = payload
        self.buffered_completions.clear()
        self._check_pending_unknown()
        self.state_changed.set()

    def _check_pending_unknown(self) -> None:
        if not self.admission_id or self.completion is not None:
            return
        for row in self.pending_rows:
            if isinstance(row, dict) and row.get("admission_id") == self.admission_id and row.get("status") == "unknown":
                self.completion = {"outcome": "unknown", "text": ""}
                return

    async def _drain_loop(self) -> None:
        try:
            async for raw in self.ws:
                frame = json.loads(raw)
                if not isinstance(frame, dict):
                    continue
                req_id = frame.get("id")
                future = self.pending_rpcs.get(req_id) if type(req_id) is int else None
                if future is not None and not future.done():
                    if "error" in frame:
                        future.set_exception(_RpcError(frame["error"]))
                    else:
                        result = frame.get("result")
                        future.set_result(result if isinstance(result, dict) else {})
                elif isinstance(req_id, str) and req_id.startswith("srq-") and isinstance(frame.get("method"), str):
                    await self._reply_server_request(req_id, frame["method"])
                elif "method" in frame:
                    self._handle_event(frame)
        except Exception as exc:  # health: allow BLE001 -- WS reader boundary; wakes waiters on disconnect
            self.disconnect_error = f"{type(exc).__name__}: {exc}"
        finally:
            if self.disconnect_error is None:
                self.disconnect_error = "gateway_disconnected"
            err = ConnectionError(self.disconnect_error)
            for future in self.pending_rpcs.values():
                if not future.done():
                    future.set_exception(err)
            self.state_changed.set()

    async def _reply_server_request(self, req_id: str, method: str) -> None:
        result: dict[str, Any] = {"outcome": "cancelled"} if method == "clarify" else {"value": ""}
        with suppress(Exception):
            await self.ws.send(json.dumps({"jsonrpc": "2.0", "id": req_id, "result": result}))

    def _handle_event(self, frame: dict[str, Any]) -> None:
        self.drained_events += 1
        params = frame.get("params")
        if not isinstance(params, dict):
            return
        event_session = params.get("session_id")
        if self.session_id is not None and event_session is not None and event_session != self.session_id:
            return
        if type(params.get("execution_generation")) is int:
            self.generation = params["execution_generation"]
        kind = params.get("type")
        payload = params.get("payload") if isinstance(params.get("payload"), dict) else {}
        admission = params.get("admission_id") or payload.get("admission_id")
        handler = _EVENT_HANDLERS.get(str(kind))
        if handler is not None:
            handler(self, str(kind), payload, admission if isinstance(admission, str) else None)

    def _on_session_info(self, _kind: str, payload: dict[str, Any], _admission: str | None) -> None:
        if isinstance(payload.get("pending"), list):
            self.pending_rows = payload["pending"]
        if type(payload.get("execution_generation")) is int:
            self.generation = payload["execution_generation"]
        self._check_pending_unknown()
        self.state_changed.set()

    def _on_session_usage(self, _kind: str, payload: dict[str, Any], _admission: str | None) -> None:
        self._record_live_usage(payload)

    def _on_replay_gap(self, _kind: str, _payload: dict[str, Any], _admission: str | None) -> None:
        self.replay_gap = True
        self.state_changed.set()

    def _on_blocked_request(self, kind: str, _payload: dict[str, Any], _admission: str | None) -> None:
        self.blocked_reason = kind
        self.state_changed.set()

    def _on_message_complete(self, _kind: str, payload: dict[str, Any], admission: str | None) -> None:
        self._record_completion(admission, payload)

    def _record_live_usage(self, payload: dict[str, Any]) -> None:
        keys = ("input_tokens", "output_tokens", "cache_read_tokens", "cache_write_tokens", "total_tokens")
        parsed = {k: _strict_nonneg_int(payload.get(k, 0)) for k in keys}
        if all(v is not None for v in parsed.values()):
            self.live_usage = {k: int(v) for k, v in parsed.items() if v is not None}
            self.saw_live_usage = True
        if isinstance(payload.get("auxiliary_usage"), dict):
            self.live_aux_usage = payload["auxiliary_usage"]

    def _record_completion(self, admission: str | None, payload: dict[str, Any]) -> None:
        if self.admission_id is None:
            if len(self.buffered_completions) < 16:
                self.buffered_completions.append((admission, payload))
            return
        if admission in (None, self.admission_id):
            self.completion = payload
            self.state_changed.set()

    async def rpc(self, method: str, *, _timeout: float = DEFAULT_RPC_TIMEOUT, **params: Any) -> dict[str, Any]:
        if self.drainer_task is not None and self.drainer_task.done():
            raise ConnectionError(self.disconnect_error or "gateway_disconnected")
        self.sequence += 1
        req_id = self.sequence
        future: asyncio.Future[Any] = asyncio.get_running_loop().create_future()
        self.pending_rpcs[req_id] = future
        try:
            wire = json.dumps({"jsonrpc": "2.0", "id": req_id, "method": method, "params": params})
            await self.ws.send(wire)
            return await asyncio.wait_for(future, timeout=_timeout)
        finally:
            self.pending_rpcs.pop(req_id, None)
            if future.done() and not future.cancelled():
                future.exception()


_EVENT_HANDLERS: dict[str, Callable[[_GatewayWSConnection, str, dict[str, Any], str | None], None]] = {
    "session.info": _GatewayWSConnection._on_session_info,
    "session.usage": _GatewayWSConnection._on_session_usage,
    "session.replay_gap": _GatewayWSConnection._on_replay_gap,
    "approval.request": _GatewayWSConnection._on_blocked_request,
    "clarify.request": _GatewayWSConnection._on_blocked_request,
    "message.complete": _GatewayWSConnection._on_message_complete,
}


def _select_source(sources: set[str], visible_sessions: bool) -> str:
    if visible_sessions:
        return "cli"
    for candidate in ("tool", "oneshot", "cli"):
        if not sources or candidate in sources:
            return candidate
    return sorted(sources)[0]


def _build_create_policy(
    parameters: set[str],
    *,
    working_directory: str,
    profile: str,
    step_id: str,
    client_env: dict[str, str],
) -> dict[str, Any]:
    policy: dict[str, Any] = {}
    if not parameters or "cwd" in parameters:
        policy["cwd"] = str(Path(working_directory).resolve())
    if not parameters or "max_turns" in parameters:
        policy["max_turns"] = profile_max_turns(profile)
    toolsets = step_toolsets(step_id)
    if toolsets is not None and (not parameters or "toolsets" in parameters):
        policy["toolsets"] = list(toolsets)
    if not parameters or "client_env" in parameters:
        policy["client_env"] = client_env
    return policy


async def _recover_replay_gap(conn: _GatewayWSConnection) -> None:
    if conn.session_id is None:
        return
    snapshot = await conn.rpc("session.resume", session_id=conn.session_id, omit_messages=True)
    if isinstance(snapshot.get("subscription_id"), str):
        conn.subscription_id = snapshot["subscription_id"]
    if type(snapshot.get("execution_generation")) is int:
        conn.generation = snapshot["execution_generation"]
    if isinstance(snapshot.get("pending"), list):
        conn.pending_rows = snapshot["pending"]
    conn._check_pending_unknown()
    if conn.completion is not None or conn.admission_id is None:
        return
    still_pending = any(
        isinstance(row, dict) and row.get("admission_id") == conn.admission_id
        for row in conn.pending_rows
    )
    if still_pending:
        return
    receipt = await conn.rpc(
        "prompt.receipt", session_id=conn.session_id, admission_id=conn.admission_id, include_result=True
    )
    if receipt.get("status") == "terminal":
        conn.completion = {
            "outcome": receipt.get("outcome") or "completed",
            "_from_receipt": True,
            "_receipt": receipt,
        }
    else:
        conn.completion = {
            "outcome": "unknown",
            "_from_receipt": True,
            "_receipt": receipt,
        }


async def _fenced_interrupt(conn: _GatewayWSConnection) -> None:
    if conn.session_id is None:
        return
    try:
        await conn.rpc(
            "session.interrupt",
            _timeout=CLEANUP_RPC_TIMEOUT,
            session_id=conn.session_id,
            execution_generation=conn.generation,
        )
    except _RpcError as exc:
        fresh = exc.data.get("execution_generation")
        if exc.reason == "stale_generation" and type(fresh) is int and fresh != conn.generation:
            conn.generation = fresh
            with suppress(Exception):
                await conn.rpc(
                    "session.interrupt",
                    _timeout=CLEANUP_RPC_TIMEOUT,
                    session_id=conn.session_id,
                    execution_generation=conn.generation,
                )
    except Exception:  # health: allow BLE001 -- best-effort interrupt during timeout/cancel teardown
        return


async def _detach_session(conn: _GatewayWSConnection) -> None:
    if conn.session_id is None or not conn.subscription_id:
        return
    with suppress(Exception):
        await conn.rpc(
            "session.detach",
            _timeout=CLEANUP_RPC_TIMEOUT,
            session_id=conn.session_id,
            subscription_id=conn.subscription_id,
            end_reason="cli_close",
        )


async def _recover_admission_for_cancel(conn: _GatewayWSConnection) -> None:
    if conn.admission_id is not None or conn.session_id is None:
        return
    with suppress(Exception):
        snapshot = await conn.rpc(
            "session.resume",
            _timeout=CLEANUP_RPC_TIMEOUT,
            session_id=conn.session_id,
            omit_messages=True,
        )
        if isinstance(snapshot.get("subscription_id"), str):
            conn.subscription_id = snapshot["subscription_id"]
        if type(snapshot.get("execution_generation")) is int:
            conn.generation = snapshot["execution_generation"]
        if isinstance(snapshot.get("pending"), list):
            conn.pending_rows = snapshot["pending"]
    if not conn.input_id:
        return
    for row in conn.pending_rows:
        adm = row.get("admission_id") if isinstance(row, dict) else None
        if isinstance(row, dict) and row.get("input_id") == conn.input_id and isinstance(adm, str) and adm:
            conn.bind_admission(adm)
            return


async def _cancel_interrupt_and_detach(conn: _GatewayWSConnection) -> dict[str, Any]:
    """Cancel queued/running prompt, fenced-interrupt child delegation trees, read receipt, and detach."""
    await _recover_admission_for_cancel(conn)
    if conn.session_id is not None and conn.admission_id is not None:
        with suppress(Exception):
            cancel_res = await conn.rpc(
                "prompt.cancel",
                _timeout=CLEANUP_RPC_TIMEOUT,
                session_id=conn.session_id,
                admission_id=conn.admission_id,
            )
            if type(cancel_res.get("execution_generation")) is int:
                conn.generation = cancel_res["execution_generation"]
    await _fenced_interrupt(conn)
    receipt: dict[str, Any] = {}
    if conn.session_id is not None and conn.admission_id is not None:
        with suppress(Exception):
            receipt = await conn.rpc(
                "prompt.receipt",
                _timeout=CLEANUP_RPC_TIMEOUT,
                session_id=conn.session_id,
                admission_id=conn.admission_id,
                include_result=True,
            )
    await _detach_session(conn)
    conn.cleaned_up = True
    conn.last_receipt = receipt
    return receipt


def _sanitize_ws_diagnostic(prefix: str, detail: str, redact_fn: Callable[[str], str] | None) -> str:
    cleaned = "".join(ch if " " <= ch <= "~" else " " for ch in detail)
    if redact_fn is not None:
        cleaned = redact_fn(cleaned)
    compact = " ".join(cleaned.split())
    text = f"{prefix}: {compact}" if compact else prefix
    return text[:MAX_DIAGNOSTIC_CHARS]


async def _wait_turn_loop(conn: _GatewayWSConnection) -> None:
    while conn.completion is None:
        conn.state_changed.clear()
        if conn.replay_gap:
            conn.replay_gap = False
            await _recover_replay_gap(conn)
            if conn.completion is not None:
                return
        if conn.blocked_reason is not None or conn.disconnect_error is not None:
            return
        if conn.completion is None:
            await conn.state_changed.wait()


async def _await_turn(conn: _GatewayWSConnection, timeout_seconds: int) -> None:
    await asyncio.wait_for(_wait_turn_loop(conn), timeout=timeout_seconds)


def _resolve_completion_outcome(completion: dict[str, Any], receipt: dict[str, Any]) -> tuple[str, bool, bool]:
    raw_status = completion.get("status")
    raw_outcome = completion.get("outcome") or receipt.get("outcome")
    if raw_outcome:
        outcome = str(raw_outcome)
    elif raw_status in ("interrupted", "cancelled"):
        outcome = "cancelled"
    elif raw_status in ("error", "failed"):
        outcome = "native_nonzero"
    else:
        outcome = str(raw_status or "completed")
    interrupted = outcome in ("cancelled", "interrupted") or raw_status in ("interrupted", "cancelled")
    failed = interrupted or raw_status in ("error", "failed") or outcome != "completed"
    return outcome, interrupted, failed


def _finalize_settled_turn(
    request: ExecutionRequest,
    conn: _GatewayWSConnection,
    receipt: dict[str, Any],
    usage: dict[str, int] | None,
    redact_fn: Callable[[str], str] | None,
) -> ExecutionResult:
    completion = conn.completion or {}
    result_body = receipt.get("result") if isinstance(receipt.get("result"), dict) else {}
    outcome, comp_interrupted, comp_failed = _resolve_completion_outcome(completion, receipt)
    interrupted = bool(result_body.get("interrupted")) or comp_interrupted
    failed = (
        interrupted
        or comp_failed
        or bool(result_body.get("failed"))
        or bool(result_body.get("partial"))
        or result_body.get("completed") is False
    )
    if failed:
        fallback = "cancelled" if interrupted else outcome
        cause = str(result_body.get("error") or completion.get("error") or result_body.get("turn_exit_reason") or fallback)
        diag = _sanitize_ws_diagnostic("gateway turn failed", cause, redact_fn)
        return ExecutionResult(
            "unknown", request.execution_id, "", "native_nonzero",
            session_id=conn.session_id, usage=usage, diagnostic=diag,
        )
    if completion.get("_from_receipt"):
        diag = _sanitize_ws_diagnostic(
            "gateway replay gap",
            "live unredacted completion missed; receipt text is storage-redacted",
            redact_fn,
        )
        return ExecutionResult(
            "unknown", request.execution_id, "", "output_unavailable",
            session_id=conn.session_id, usage=usage, diagnostic=diag,
        )
    # Prefer live message.complete text from the event drainer so SHA-256 hashes and IOCs
    # are never mangled by state.db's storage-boundary redact_sensitive_text().
    live_text = completion.get("text")
    if not isinstance(live_text, str):
        live_text = completion.get("content") if isinstance(completion.get("content"), str) else ""
    if not live_text.strip():
        diag = _sanitize_ws_diagnostic("gateway turn empty", "no final response text", redact_fn)
        return ExecutionResult(
            "unknown", request.execution_id, "", "output_unavailable",
            session_id=conn.session_id, usage=usage, diagnostic=diag,
        )
    if len(live_text.encode("utf-8")) > MAX_OUTPUT_BYTES:
        return ExecutionResult(
            "unknown", request.execution_id, "", "output_limit",
            session_id=conn.session_id, usage=usage,
        )
    return ExecutionResult(
        "completed", request.execution_id, live_text, "completed",
        session_id=conn.session_id, usage=usage,
    )


def _usage_from_receipt(
    conn: _GatewayWSConnection,
    endpoint: GatewayEndpoint,
    receipt: dict[str, Any],
    *,
    record_usage: bool,
    started_at: float,
    allow_zero: bool = True,
) -> dict[str, int] | None:
    res_body = receipt.get("result") if isinstance(receipt.get("result"), dict) else {}
    rec_usage = receipt.get("usage") if isinstance(receipt.get("usage"), dict) else {}
    return _build_usage(
        record_usage=record_usage,
        result_body=res_body,
        receipt_usage=rec_usage,
        live_usage=conn.live_usage,
        saw_live_usage=conn.saw_live_usage,
        live_aux_usage=conn.live_aux_usage,
        profile_home=endpoint.profile_home,
        session_id=conn.session_id,
        elapsed_ms=int((time.monotonic() - started_at) * 1000),
        allow_zero=allow_zero,
    )


async def _prepare_ws_session(
    conn: _GatewayWSConnection,
    request: ExecutionRequest,
    *,
    working_directory: str,
    visible_sessions: bool,
) -> tuple[str, str]:
    desc = await conn.rpc("runtime.describe")
    create_contract = desc.get("session_create") if isinstance(desc.get("session_create"), dict) else {}
    sources = {str(s) for s in (create_contract.get("sources") or ()) if isinstance(s, str)}
    parameters = {str(p) for p in (create_contract.get("parameters") or ()) if isinstance(p, str)}
    policy = _build_create_policy(
        parameters,
        working_directory=working_directory,
        profile=request.step.profile,
        step_id=request.step.step_id,
        client_env=hunt_env_for_request(request),
    )
    request_id = hashlib.sha256(request.execution_id.encode()).hexdigest()
    input_id = hashlib.sha256(f"{request.execution_id}:input".encode()).hexdigest()
    snapshot = await conn.rpc("session.create", request_id=request_id, source=_select_source(sources, visible_sessions), **policy)
    session_id = snapshot.get("stored_session_id") or snapshot.get("session_id")
    if not isinstance(session_id, str) or not session_id:
        raise ValueError("missing stored_session_id")
    sub_id = snapshot.get("subscription_id") if isinstance(snapshot.get("subscription_id"), str) else None
    gen = snapshot.get("execution_generation") if type(snapshot.get("execution_generation")) is int else 0
    conn.bind_session(session_id, sub_id, gen)
    return session_id, input_id


async def _run_admitted_ws_turn(
    conn: _GatewayWSConnection,
    endpoint: GatewayEndpoint,
    request: ExecutionRequest,
    *,
    session_id: str,
    input_id: str,
    started_at: float,
    record_usage: bool,
    redact_fn: Callable[[str], str] | None,
) -> ExecutionResult:
    ack = await conn.rpc(
        "prompt.submit",
        session_id=session_id,
        input_id=input_id,
        text=request.step.prompt,
        finite=True,
        unattended=True,
    )
    admission_id = ack.get("admission_id")
    if not isinstance(admission_id, str) or not admission_id:
        receipt = await _cancel_interrupt_and_detach(conn)
        usage = await asyncio.to_thread(
            _usage_from_receipt,
            conn, endpoint, receipt, record_usage=record_usage, started_at=started_at, allow_zero=True,
        )
        return ExecutionResult(
            "unknown", request.execution_id, "", "output_unavailable",
            session_id=session_id, usage=usage,
            diagnostic=_sanitize_ws_diagnostic("gateway submit", "missing admission_id", redact_fn),
        )
    conn.bind_admission(admission_id, ack.get("execution_generation"))
    try:
        await _await_turn(conn, request.step.timeout_seconds)
    except _ASYNC_TIMEOUT_ERRORS:
        receipt = await asyncio.shield(_cancel_interrupt_and_detach(conn))
        usage = await asyncio.to_thread(
            _usage_from_receipt,
            conn, endpoint, receipt, record_usage=record_usage, started_at=started_at, allow_zero=True,
        )
        diag = _sanitize_ws_diagnostic(
            "gateway timeout", f"exceeded {request.step.timeout_seconds}s; cancelled and interrupted", redact_fn
        )
        return ExecutionResult(
            "unknown", request.execution_id, "", "subprocess_timeout",
            session_id=session_id, usage=usage, diagnostic=diag,
        )
    except asyncio.CancelledError:
        await asyncio.shield(_cancel_interrupt_and_detach(conn))
        raise

    if conn.blocked_reason is not None or (conn.completion is None and conn.disconnect_error is not None):
        why = conn.blocked_reason or conn.disconnect_error or "gateway_disconnected"
        receipt = await _cancel_interrupt_and_detach(conn)
        usage = await asyncio.to_thread(
            _usage_from_receipt, conn, endpoint, receipt, record_usage=record_usage, started_at=started_at, allow_zero=True
        )
        diag = _sanitize_ws_diagnostic("gateway interrupted", why, redact_fn)
        return ExecutionResult(
            "unknown", request.execution_id, "", "native_nonzero",
            session_id=session_id, usage=usage, diagnostic=diag,
        )

    saved = (conn.completion or {}).get("_receipt")
    receipt = saved if isinstance(saved, dict) else {}
    if not receipt:
        with suppress(Exception):
            receipt = await conn.rpc(
                "prompt.receipt", _timeout=CLEANUP_RPC_TIMEOUT,
                session_id=session_id, admission_id=admission_id, include_result=True,
            )
    await _detach_session(conn)
    usage = await asyncio.to_thread(
        _usage_from_receipt, conn, endpoint, receipt, record_usage=record_usage, started_at=started_at, allow_zero=True
    )
    return _finalize_settled_turn(request, conn, receipt, usage, redact_fn)


async def _open_ws(endpoint: GatewayEndpoint, explicit_ws_url: bool) -> tuple[Any, Any]:
    try:
        from websockets.asyncio.client import connect as ws_connect
    except ImportError as exc:
        raise GatewayNotAvailable("websockets package not installed") from exc
    subprotocols = [GATEWAY_SUBPROTOCOL]
    if endpoint.ticket:
        subprotocols.append(TICKET_SUBPROTOCOL_PREFIX + endpoint.ticket)
    try:
        ws_cm = ws_connect(
            endpoint.ws_url, subprotocols=subprotocols, open_timeout=10,
            close_timeout=5, max_size=MAX_WS_FRAME_BYTES, proxy=None,
        )
        ws = await ws_cm.__aenter__()
    except Exception as exc:  # health: allow BLE001 -- dial failure falls back or refuses launch
        if not explicit_ws_url:
            raise GatewayNotAvailable("gateway websocket unreachable") from exc
        return None, None
    return ws_cm, ws


async def _execute_over_ws(
    endpoint: GatewayEndpoint,
    request: ExecutionRequest,
    *,
    working_directory: str,
    visible_sessions: bool,
    record_usage: bool,
    explicit_ws_url: bool,
    checkpoint: Callable[[str, str], None] | None,
    redact_fn: Callable[[str], str] | None,
) -> ExecutionResult:
    ws_cm, ws = await _open_ws(endpoint, explicit_ws_url)
    if ws is None:
        return ExecutionResult("failed", request.execution_id, "", "launch_failed")
    conn = _GatewayWSConnection(ws)
    started_at = time.monotonic()
    admitted = False
    try:
        if ws.subprotocol != GATEWAY_SUBPROTOCOL:
            if not explicit_ws_url:
                raise GatewayNotAvailable("gateway subprotocol mismatch")
            return ExecutionResult("failed", request.execution_id, "", "launch_failed")
        conn.start_drainer()
        session_id, input_id = await _prepare_ws_session(
            conn, request, working_directory=working_directory, visible_sessions=visible_sessions
        )
        if checkpoint is not None:
            try:
                await asyncio.to_thread(checkpoint, session_id, input_id)
            except Exception:  # health: allow BLE001 -- receipt WAL failure aborts before prompt.submit
                await _detach_session(conn)
                return ExecutionResult("failed", request.execution_id, "", "receipt_unavailable")
        started_at = time.monotonic()
        conn.input_id = input_id
        admitted = True
        return await _run_admitted_ws_turn(
            conn, endpoint, request,
            session_id=session_id, input_id=input_id, started_at=started_at,
            record_usage=record_usage, redact_fn=redact_fn,
        )
    except GatewayNotAvailable:
        raise
    except asyncio.CancelledError:
        if not conn.cleaned_up:
            await asyncio.shield(_cancel_interrupt_and_detach(conn))
        usage = await asyncio.to_thread(
            _usage_from_receipt,
            conn, endpoint, conn.last_receipt, record_usage=record_usage,
            started_at=started_at, allow_zero=admitted,
        )
        return ExecutionResult("unknown", request.execution_id, "", "cancelled", session_id=conn.session_id, usage=usage)
    except Exception as exc:  # health: allow BLE001 -- pre-submit refuses cleanly; post-submit settles unknown
        if not admitted:
            await _detach_session(conn)
            if not explicit_ws_url:
                raise GatewayNotAvailable(f"gateway pre-submit failure: {exc}") from exc
            return ExecutionResult("failed", request.execution_id, "", "launch_failed")
        if not conn.cleaned_up:
            await asyncio.shield(_cancel_interrupt_and_detach(conn))
        usage = await asyncio.to_thread(
            _usage_from_receipt,
            conn, endpoint, conn.last_receipt, record_usage=record_usage,
            started_at=started_at, allow_zero=True,
        )
        diag = _sanitize_ws_diagnostic("gateway rpc error", f"{type(exc).__name__}: {exc}", redact_fn)
        return ExecutionResult(
            "unknown", request.execution_id, "", "native_nonzero",
            session_id=conn.session_id, usage=usage, diagnostic=diag,
        )
    finally:
        await conn.stop_drainer()
        with suppress(Exception):
            await ws_cm.__aexit__(None, None, None)


def invoke_gateway(
    config: Any,
    request: ExecutionRequest,
    *,
    checkpoint: Callable[[str, str], None] | None = None,
    redact_fn: Callable[[str], str] | None = None,
) -> ExecutionResult:
    """Execute ``request`` over the persistent gateway WS authority, or raise ``GatewayNotAvailable``."""
    gateway_ws_url = getattr(config, "gateway_ws_url", None)
    gateway_ticket = getattr(config, "gateway_ticket", None)
    endpoint = discover_endpoint(
        Path(config.hermes_home),
        request.step.profile,
        gateway_ws_url=gateway_ws_url,
        gateway_ticket=gateway_ticket,
    )
    return asyncio.run(
        _execute_over_ws(
            endpoint,
            request,
            working_directory=config.working_directory,
            visible_sessions=config.visible_sessions is True,
            record_usage=config.record_usage is True or request.record_usage is True,
            explicit_ws_url=gateway_ws_url is not None,
            checkpoint=checkpoint,
            redact_fn=redact_fn,
        )
    )

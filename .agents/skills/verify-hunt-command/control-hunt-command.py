#!/usr/bin/env python3
"""Executable verification harness CLI for Hunt Command Desktop (verify-hunt-command).

Provides machine-readable JSON subcommands for read-only doctor checks, unpacked
Hunt Command binary verification, loopback Hunt Board discovery + live MJPEG stream
probing, Temporal human-gate inspection/dry-run verification, log inspection, and
PID-scoped cleanup that never kills unrelated processes or deletes captured evidence.
"""
from __future__ import annotations

import argparse
import ctypes
from datetime import UTC, datetime
import importlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request


REPO_ROOT = Path(__file__).resolve().parents[3]
DESKTOP_DIR = REPO_ROOT / "apps" / "desktop"
FRAMEWORK_DIR = REPO_ROOT / "framework"
DEFAULT_BOARD_PORT = 8790
DEFAULT_TEMPORAL_ADDR = "127.0.0.1:7233"
MAX_STATE_BYTES = 524288
MAX_EVIDENCE_NOTE_BYTES = 4096
_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)
_SAFE_WORKFLOW_ID = re.compile(r"[A-Za-z0-9._:-]{1,160}\Z")
_SAFE_DECISION_ID = re.compile(r"[\x21-\x7e]{1,128}\Z")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        return None


_LOOPBACK_OPENER = urllib.request.build_opener(
    urllib.request.ProxyHandler({}),
    _NoRedirect(),
)


def _load_contracts():
    fw = str(FRAMEWORK_DIR)
    if fw not in sys.path:
        sys.path.insert(0, fw)
    return importlib.import_module("hermes_temporal.contracts")


def _load_hermes_constants():
    repo = str(REPO_ROOT)
    if repo not in sys.path:
        sys.path.insert(0, repo)
    return importlib.import_module("hermes_constants")


def _paths_overlap(first: Path, second: Path) -> bool:
    return first == second or first.is_relative_to(second) or second.is_relative_to(first)


def _default_hermes_homes(user_home: Path) -> tuple[Path, ...]:
    constants = _load_hermes_constants()
    dot_hermes = (user_home / ".hermes").resolve()  # health: allow HX001 -- reject literal ~/.hermes alongside account_default_hermes_home()
    return (constants.account_default_hermes_home().resolve(), dot_hermes)


def _validate_isolated_hermes_home(
    raw: str,
    *,
    forbid_git_worktree: bool = True,
    label: str = "HERMES_HOME",
) -> tuple[Path | None, str | None]:
    text = str(raw or "").strip()
    if not text or any(ord(ch) < 32 or ord(ch) == 127 for ch in text):
        return None, f"{label} must be a valid local path."
    expanded = os.path.expanduser(os.path.expandvars(text))
    cand = Path(os.path.abspath(expanded)).resolve()
    user_home = Path.home().resolve()
    temp_root = Path(tempfile.gettempdir()).resolve()
    if cand in (cand.parent, user_home, temp_root):
        return None, f"{label} ({cand}) must be a dedicated isolated directory, not root, HOME, or the shared temp root."
    for default_home in _default_hermes_homes(user_home):
        if _paths_overlap(cand, default_home):
            return None, f"{label} ({cand}) must not touch default user Hermes state ({default_home})."
    operator_only = (REPO_ROOT.parent / "runtime" / "operator-only").resolve()
    if (
        _paths_overlap(cand, operator_only)
        or any(part.lower() == "operator-only" for part in cand.parts)
        or (cand / "operator-only").exists()
    ):
        return None, f"{label} ({cand}) must never touch operator-only directories."
    in_git = _paths_overlap(cand, REPO_ROOT.resolve()) or any(
        (parent / ".git").exists() for parent in (cand, *cand.parents)
    )
    if in_git and (forbid_git_worktree or ".scratch" not in cand.parts):
        return None, f"{label} ({cand}) must be outside the repository/git worktree."
    return cand, None


def _strict_loopback_address(raw: str) -> str | None:
    contracts = _load_contracts()
    try:
        checked = contracts.validate_loopback_address(str(raw or "").strip())
    except ValueError:
        return None
    host, _, port_str = checked.rpartition(":")
    if host != "127.0.0.1" or port_str.startswith("0"):
        return None
    return f"127.0.0.1:{int(port_str)}"


def _emit(payload: dict, exit_code: int = 0) -> int:
    sys.stdout.write(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    return exit_code


def _resolve_lock_python(explicit: str | None) -> Path | None:
    candidates: list[Path] = []
    if explicit:
        candidates.append(Path(explicit))
    for env_key in ("HUNT_BOTS_PYTHON", "HERMES_HUNT_PYTHON", "HERMES_TEMPORAL_PYTHON"):
        val = os.environ.get(env_key)
        if val:
            candidates.append(Path(val))
    rel = Path("Scripts/python.exe") if os.name == "nt" else Path("bin/python")
    candidates.extend([
        FRAMEWORK_DIR / ".venv-temporal" / rel,
        REPO_ROOT / ".venv-temporal" / rel,
        REPO_ROOT.parent / "runtime" / "practice" / "gate-venv" / rel,
    ])
    for cand in candidates:
        if cand.is_file():
            # Preserve venv bin/python symlinks on POSIX so pyvenv.cfg stays active.
            return Path(os.path.abspath(cand))
    return None


def _packed_binary() -> Path:
    if os.name == "nt":
        return DESKTOP_DIR / "release" / "win-unpacked" / "Hunt Command.exe"
    if sys.platform == "darwin":
        return DESKTOP_DIR / "release" / "mac" / "Hunt Command.app" / "Contents" / "MacOS" / "Hunt Command"
    return DESKTOP_DIR / "release" / "linux-unpacked" / "hunt-command"


def _fetch_board(port: int) -> tuple[dict, dict] | None:
    if port < 1 or port > 65535:
        return None
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}/state.json",
        headers={"Accept": "application/json", "Host": f"127.0.0.1:{port}"},
        method="GET",
    )
    try:
        with _LOOPBACK_OPENER.open(req, timeout=5.0) as resp:
            server_hdr = resp.headers.get("Server", "")
            if resp.status != 200 or not server_hdr.startswith("HuntBoard"):
                return None
            raw_bytes = resp.read(MAX_STATE_BYTES + 1)
            if len(raw_bytes) > MAX_STATE_BYTES:
                return None
            body = json.loads(raw_bytes.decode("utf-8"))
            if not isinstance(body, dict):
                return None
            run = body.get("run") or {}
            parent = run.get("parent") if isinstance(run.get("parent"), dict) else {}
            child = run.get("child") if isinstance(run.get("child"), dict) else {}
            live = body.get("live")
            owners = live.get("owners") if isinstance(live, dict) else None
            live_profiles = (
                [o["profile"] for o in owners if isinstance(o, dict) and isinstance(o.get("profile"), str)]
                if isinstance(owners, list)
                else []
            )
            summary = {
                "port": port,
                "url": f"http://127.0.0.1:{port}/",
                "workflow_id": parent.get("workflow_id") or child.get("workflow_id") or "",
                "child_workflow_id": child.get("workflow_id"),
                "stage": child.get("stage"),
                "decisions": list(child.get("decisions") or []),
                "case_id": (body.get("case") or {}).get("case_id", ""),
                "mode": body.get("mode", "inline"),
                "live_enabled": live is not None,
                "live_profiles": live_profiles,
            }
            return summary, body
    except (OSError, ValueError, urllib.error.URLError):
        return None


def _probe_board(port: int) -> dict | None:
    fetched = _fetch_board(port)
    return fetched[0] if fetched is not None else None


def _check_lock_python_ready(lock_py: Path | None) -> bool:
    if not lock_py:
        return False
    try:
        probe = subprocess.run(
            [str(lock_py), "-c", "import temporalio, websockets, hermes_temporal.cli, hermes_temporal.board"],
            cwd=str(FRAMEWORK_DIR),
            env={**os.environ, "PYTHONPATH": str(FRAMEWORK_DIR)},
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=15,
            check=False,
            creationflags=_NO_WINDOW,
        )
    except OSError:
        return False
    return probe.returncode == 0


def cmd_doctor(args: argparse.Namespace) -> int:
    lock_py = _resolve_lock_python(args.python)
    lock_ready = _check_lock_python_ready(lock_py)
    binary = _packed_binary()
    plugin_workspace = FRAMEWORK_DIR / "desktop" / "cybersecurity-workspace" / "plugin.js"
    plugin_lab = FRAMEWORK_DIR / "hunt_lab" / "desktop" / "plugin.js"
    assets_dirty = subprocess.run(
        ["git", "-C", str(DESKTOP_DIR), "status", "--porcelain", "--", "assets"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=15,
        check=False,
        creationflags=_NO_WINDOW,
    ).stdout.strip()

    hermes_home: Path | None = None
    home_err: str | None = None
    if args.hermes_home is not None:
        hermes_home, home_err = _validate_isolated_hermes_home(args.hermes_home)
    discovered_boards: list[dict] = []
    seen_ports: set[int] = {DEFAULT_BOARD_PORT}
    if args.board_port:
        seen_ports.add(args.board_port)
    if hermes_home and (hermes_home / "hunt-board").is_dir():
        for item in sorted((hermes_home / "hunt-board").glob("board-*.json")):
            try:
                raw = json.loads(item.read_text(encoding="utf-8-sig"))
                if isinstance(raw.get("port"), int):
                    seen_ports.add(raw["port"])
            except (OSError, ValueError):
                continue
    for port in sorted(seen_ports):
        found = _probe_board(port)
        if found:
            discovered_boards.append(found)

    checks = {
        "lock_python_found": lock_py is not None,
        "lock_python_ready": lock_ready,
        "lock_python": str(lock_py) if lock_py else None,
        "hermes_home_isolated": home_err is None,
        "workspace_plugin_exists": plugin_workspace.is_file(),
        "hunt_lab_plugin_exists": plugin_lab.is_file(),
        "packed_binary_exists": binary.is_file(),
        "packed_binary": str(binary),
        "desktop_assets_clean": assets_dirty == "",
        "active_boards": discovered_boards,
    }
    ok = (
        checks["lock_python_found"]
        and checks["lock_python_ready"]
        and checks["hermes_home_isolated"]
        and checks["workspace_plugin_exists"]
        and checks["hunt_lab_plugin_exists"]
        and checks["desktop_assets_clean"]
        and (bool(getattr(args, "skip_packed_check", False)) or checks["packed_binary_exists"])
    )
    remediation = None
    if home_err:
        remediation = home_err
    elif not checks["lock_python_found"]:
        remediation = "Pass --python pointing to a venv with framework/requirements-hunt.lock installed."
    elif not checks["lock_python_ready"]:
        remediation = "Selected --python cannot import temporalio/websockets; install framework/requirements-hunt.lock."
    elif not checks["workspace_plugin_exists"] or not checks["hunt_lab_plugin_exists"]:
        remediation = "Confirm framework/desktop/cybersecurity-workspace/plugin.js and framework/hunt_lab/desktop/plugin.js exist."
    elif not checks["desktop_assets_clean"]:
        remediation = (
            "Inspect `git -C apps/desktop status -- assets` and remove unintended pack outputs "
            "without discarding tracked edits."
        )
    elif not checks["packed_binary_exists"] and not getattr(args, "skip_packed_check", False):
        remediation = (
            "Run `npm run pack:hunt` in apps/desktop before launching Desktop UI journeys "
            "(or pass --skip-packed-check for source/CLI-only checks)."
        )
    return _emit({"ok": ok, "checks": checks, "remediation": remediation}, 0 if ok else 1)


class _WinFileTime(ctypes.Structure):
    _fields_ = [("dwLowDateTime", ctypes.c_uint32), ("dwHighDateTime", ctypes.c_uint32)]


_PROCESS_TERMINATE = 0x0001
_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000


def _win_kernel32():
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
    kernel32.OpenProcess.restype = ctypes.c_void_p
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle.restype = ctypes.c_int
    kernel32.GetExitCodeProcess.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
    kernel32.GetExitCodeProcess.restype = ctypes.c_int
    kernel32.GetProcessTimes.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(_WinFileTime),
        ctypes.POINTER(_WinFileTime),
        ctypes.POINTER(_WinFileTime),
        ctypes.POINTER(_WinFileTime),
    ]
    kernel32.GetProcessTimes.restype = ctypes.c_int
    kernel32.QueryFullProcessImageNameW.argtypes = [
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_wchar_p,
        ctypes.POINTER(ctypes.c_uint32),
    ]
    kernel32.QueryFullProcessImageNameW.restype = ctypes.c_int
    kernel32.TerminateProcess.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
    kernel32.TerminateProcess.restype = ctypes.c_int
    return kernel32


def _win_open(kernel32, pid: int, access: int):
    handle = kernel32.OpenProcess(access, 0, pid)
    if handle:
        return handle, "alive"
    return None, "inaccessible" if ctypes.get_last_error() == 5 else "dead"


def _win_identity_from_handle(kernel32, handle) -> tuple[str, dict[str, str] | None]:
    exit_code = ctypes.c_uint32(0)
    if not kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)) or exit_code.value != 259:
        return ("dead", None)
    creation = _WinFileTime()
    exit_ft = _WinFileTime()
    kernel_ft = _WinFileTime()
    user_ft = _WinFileTime()
    if not kernel32.GetProcessTimes(
        handle,
        ctypes.byref(creation),
        ctypes.byref(exit_ft),
        ctypes.byref(kernel_ft),
        ctypes.byref(user_ft),
    ):
        return ("inaccessible", None)
    buf_len = ctypes.c_uint32(4096)
    buf = ctypes.create_unicode_buffer(buf_len.value)
    if not kernel32.QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(buf_len)):
        return ("inaccessible", None)
    ticks = (creation.dwHighDateTime << 32) | creation.dwLowDateTime
    return ("alive", {"binary": str(Path(buf.value).resolve()), "create_time": str(ticks)})


def _windows_process_identity(pid: int) -> tuple[str, dict[str, str] | None]:
    kernel32 = _win_kernel32()
    handle, state = _win_open(kernel32, pid, _PROCESS_QUERY_LIMITED_INFORMATION)
    if not handle:
        return (state, None)
    try:
        return _win_identity_from_handle(kernel32, handle)
    finally:
        kernel32.CloseHandle(handle)


def _windows_terminate_verified(pid: int, expected_binary: str, expected_create: str) -> str:
    # Verify and terminate through one handle so the PID cannot be recycled in between.
    kernel32 = _win_kernel32()
    handle, state = _win_open(kernel32, pid, _PROCESS_TERMINATE | _PROCESS_QUERY_LIMITED_INFORMATION)
    if not handle:
        return "dead" if state == "dead" else "mismatch"
    try:
        alive, ident = _win_identity_from_handle(kernel32, handle)
        if alive == "dead":
            return "dead"
        if alive != "alive" or not _pid_matches_recorded(ident, expected_binary, expected_create):
            return "mismatch"
        return "stopped" if kernel32.TerminateProcess(handle, 1) else f"error:WinError({ctypes.get_last_error()})"
    finally:
        kernel32.CloseHandle(handle)


def _posix_process_identity(pid: int) -> tuple[str, dict[str, str] | None]:
    try:
        os.kill(pid, 0)  # windows-footgun: ok
    except ProcessLookupError:
        return ("dead", None)
    except PermissionError:
        return ("inaccessible", None)

    stat_path = Path(f"/proc/{pid}/stat")
    exe_path = Path(f"/proc/{pid}/exe")
    if stat_path.is_file():
        try:
            raw_stat = stat_path.read_text(encoding="utf-8-sig", errors="replace")
            after_comm = raw_stat.rsplit(")", 1)[1].split()
            if after_comm[0] == "Z":
                return ("dead", None)
            resolved_exe = str(Path(os.readlink(exe_path)).resolve())
            return ("alive", {"binary": resolved_exe, "create_time": after_comm[19]})
        except (IndexError, OSError):
            return ("inaccessible", None)

    ps_time = subprocess.run(
        ["ps", "-p", str(pid), "-o", "lstart="],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=5,
        check=False,
        creationflags=_NO_WINDOW,
    )
    ps_comm = subprocess.run(
        ["ps", "-p", str(pid), "-o", "comm="],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=5,
        check=False,
        creationflags=_NO_WINDOW,
    )
    lstart = ps_time.stdout.strip()
    comm = ps_comm.stdout.strip()
    if ps_time.returncode != 0 or not lstart:
        return ("dead", None)
    if not comm:
        return ("inaccessible", None)
    resolved_comm = str(Path(comm).resolve()) if Path(comm).is_absolute() else comm
    return ("alive", {"binary": resolved_comm, "create_time": lstart})


def _process_identity(pid: int) -> tuple[str, dict[str, str] | None]:
    if pid <= 0:
        return ("dead", None)
    if os.name == "nt":
        return _windows_process_identity(pid)
    return _posix_process_identity(pid)


def _norm_exe(raw: str) -> str:
    resolved = str(Path(raw).resolve()) if Path(raw).is_absolute() else raw
    return os.path.normcase(resolved)


def _pid_matches_recorded(ident: dict[str, str] | None, expected_binary: str, expected_create: str) -> bool:
    if not ident or not expected_binary or not expected_create:
        return False
    if ident.get("create_time") != expected_create:
        return False
    actual_bin = ident.get("binary", "")
    if not actual_bin:
        return False
    if Path(actual_bin).is_absolute() or os.name == "nt":
        return _norm_exe(actual_bin) == _norm_exe(expected_binary)
    return Path(actual_bin).name == Path(expected_binary).name


def cmd_launch(args: argparse.Namespace) -> int:
    hermes_home, home_err = _validate_isolated_hermes_home(args.hermes_home)
    if home_err or hermes_home is None:
        return _emit({"ok": False, "error": home_err or "Invalid HERMES_HOME."}, 1)
    evidence_dir, ev_err = _validate_isolated_hermes_home(
        args.evidence_dir, forbid_git_worktree=False, label="evidence_dir"
    )
    if ev_err or evidence_dir is None:
        return _emit({"ok": False, "error": ev_err or "Invalid --evidence-dir."}, 1)
    if args.cdp_port and not (1 <= args.cdp_port <= 65535):
        return _emit({"ok": False, "error": "CDP port must be 1..65535 (Rule 2)."}, 1)
    binary = _packed_binary()
    cmd = [str(binary)]
    if args.cdp_port:
        cmd.append(f"--remote-debugging-port={args.cdp_port}")
    if args.dry_run:
        return _emit({
            "ok": True,
            "dry_run": True,
            "command": cmd,
            "env_overrides": {"HERMES_HOME": str(hermes_home)},
            "pid_file": str(evidence_dir / "hunt-command.pid"),
        })
    if not binary.is_file():
        return _emit({
            "ok": False,
            "error": f"Packed Hunt Command binary missing at {binary}. Run `npm run pack:hunt` in apps/desktop first.",
        }, 1)
    pid_file = evidence_dir / "hunt-command.pid"
    if pid_file.is_file():
        try:
            existing = json.loads(pid_file.read_text(encoding="utf-8-sig"))
            existing_pid = int(existing["pid"])
        except (OSError, ValueError, KeyError, TypeError):
            return _emit({
                "ok": False,
                "error": f"Existing PID file {pid_file} is unreadable; inspect or clean it up before launching again.",
            }, 1)
        ex_state, ex_ident = _process_identity(existing_pid)
        if ex_state == "inaccessible" or (
            ex_state == "alive"
            and _pid_matches_recorded(ex_ident, str(existing.get("binary") or ""), str(existing.get("create_time") or ""))
        ):
            return _emit({
                "ok": False,
                "error": (
                    f"Hunt Command is already running (pid={existing_pid}) in {pid_file}; "
                    f"run `cleanup --pid-file {pid_file}` or use a fresh --evidence-dir."
                ),
            }, 1)
    hermes_home.mkdir(parents=True, exist_ok=True)
    evidence_dir.mkdir(parents=True, exist_ok=True)
    env = {**os.environ, "HERMES_HOME": str(hermes_home)}
    proc = subprocess.Popen(cmd, cwd=str(DESKTOP_DIR), env=env, creationflags=_NO_WINDOW)
    _state, ident = _process_identity(proc.pid)
    if _state != "alive" or not ident or not ident.get("create_time"):
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
        return _emit({
            "ok": False,
            "error": "Launched process exited or could not record verified process identity.",
        }, 1)
    pid_file.write_text(
        json.dumps({
            "pid": proc.pid,
            "hermes_home": str(hermes_home),
            "binary": str(binary.resolve()),
            "create_time": ident["create_time"],
        }),
        encoding="utf-8",
    )
    return _emit({"ok": True, "pid": proc.pid, "pid_file": str(pid_file), "hermes_home": str(hermes_home)})


def _probe_mjpeg_stream(port: int, profile: str) -> dict:
    if not re.fullmatch(r"[a-z0-9-]+", profile):
        return {"status": 0, "ok": False, "error": "Invalid live profile slug."}
    mjpg_url = f"http://127.0.0.1:{port}/live/{profile}.mjpg"
    req = urllib.request.Request(
        mjpg_url,
        headers={"Host": f"127.0.0.1:{port}", "Sec-Fetch-Dest": "image"},
        method="GET",
    )
    status = 0
    ctype = ""
    buf = bytearray()
    try:
        with _LOOPBACK_OPENER.open(req, timeout=3.0) as resp:
            status = resp.status
            ctype = resp.headers.get("Content-Type", "")
            if status != 200 or "multipart/x-mixed-replace" not in ctype:
                return {"status": status, "content_type": ctype, "ok": False, "error": f"Unexpected response on {mjpg_url}"}
            while len(buf) < 4096:
                chunk = resp.read1(1024) if hasattr(resp, "read1") else resp.read(64)
                if not chunk:
                    break
                buf.extend(chunk)
                sep = buf.find(b"\r\n\r\n")
                if sep >= 0 and len(buf) >= sep + 6:
                    jpeg_frame = bytes(buf[sep + 4 : sep + 6]) == b"\xff\xd8"
                    return {
                        "status": status,
                        "content_type": ctype,
                        "bytes_sampled": len(buf),
                        "jpeg_frame": jpeg_frame,
                        "ok": jpeg_frame,
                        **({} if jpeg_frame else {"error": f"Stream payload on {mjpg_url} is not JPEG"}),
                    }
    except urllib.error.HTTPError as exc:
        return {"status": exc.code, "ok": False, "error": f"HTTP {exc.code} on {mjpg_url}"}
    except OSError as exc:
        if status == 200:
            return {
                "status": status,
                "content_type": ctype,
                "bytes_sampled": len(buf),
                "jpeg_frame": False,
                "ok": False,
                "error": f"No JPEG frame received on {mjpg_url} within timeout.",
            }
        return {"status": 0, "ok": False, "error": str(exc)}
    return {
        "status": status,
        "content_type": ctype,
        "bytes_sampled": len(buf),
        "jpeg_frame": False,
        "ok": False,
        "error": f"No JPEG frame received on {mjpg_url}.",
    }


def cmd_board_probe(args: argparse.Namespace) -> int:
    if args.port < 1 or args.port > 65535:
        return _emit({"ok": False, "error": "Board port must be 1..65535 (Rule 2)."}, 1)
    info = _probe_board(args.port)
    if not info:
        return _emit({
            "ok": False,
            "error": f"No active HuntBoard at http://127.0.0.1:{args.port}/. Start Hunt Board from /hunt-board or pass the active loopback --port.",
        }, 1)
    live_check = _probe_mjpeg_stream(args.port, args.profile) if args.profile else None
    ok = True if live_check is None else bool(live_check["ok"])
    return _emit({"ok": ok, "board": info, "live_stream": live_check}, 0 if ok else 1)


def _valid_phase_choice(phase: str, choice: str) -> bool:
    if phase == "reconcile":
        return choice in ("accept", "abort")
    return phase in ("execute", "review") and choice in ("approve", "deny")


def _normalize_operator_name(raw: str, contracts) -> str | None:
    trimmed = str(raw or "").strip()
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in trimmed):
        return None
    normalized = " ".join(trimmed.split())
    if not normalized or not contracts.valid_decider(normalized, "cli", ""):
        return None
    return normalized


def _normalize_check_note(raw: str) -> str | None:
    normalized = str(raw or "").strip().replace("\r\n", "\n")
    if not normalized or len(normalized) > 1000:
        return None
    for ch in normalized:
        code = ord(ch)
        if (code < 0x20 and ch not in ("\t", "\n")) or code == 0x7F:
            return None
        if ch not in ("\t", "\n") and not ch.isprintable():
            return None
    return normalized


def _validate_gate_inputs(
    args: argparse.Namespace,
) -> tuple[tuple[str, str, str, str, str, str] | None, str | None]:
    address = _strict_loopback_address(args.address)
    if not address:
        return None, "Temporal address must use 127.0.0.1:<1..65535> (Rule 2)."
    if not _valid_phase_choice(args.phase, args.choice):
        return None, (
            f"Invalid choice {args.choice!r} for {args.phase} gate "
            "(review/execute: approve|deny; reconcile: accept|abort)."
        )
    contracts = _load_contracts()
    workflow_id = str(args.workflow_id or "").strip()
    if _SAFE_WORKFLOW_ID.fullmatch(workflow_id) is None:
        return None, "Workflow ID must be 1..160 safe ASCII characters ([A-Za-z0-9._:-])."
    step_id = str(args.step_id or "").strip()
    if contracts.SAFE_STEP_ID.fullmatch(step_id) is None:
        return None, "Step ID must be a valid 1..64 character gate/step identifier."
    decision_id = str(args.decision_id or "").strip()
    if _SAFE_DECISION_ID.fullmatch(decision_id) is None:
        return None, "Decision ID must be 1..128 printable non-space ASCII characters."
    operator = _normalize_operator_name(args.operator, contracts)
    if not operator:
        return None, "Operator name must be 1..200 printable characters without control characters (Rule 3)."
    note = _normalize_check_note(args.note)
    if not note:
        return None, "Check note ('What did you check?') must be 1..1000 printable characters (Rule 3)."
    utc_iso = datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")
    evidence_note = f"Decided by {operator} via Hunt Command Desktop at {utc_iso}. Checked: {note}"
    if len(evidence_note.encode("utf-8")) > MAX_EVIDENCE_NOTE_BYTES:
        return None, f"Formatted evidence note exceeds {MAX_EVIDENCE_NOTE_BYTES} UTF-8 bytes."
    return (address, workflow_id, step_id, decision_id, operator, evidence_note), None


def _verify_recorded_decision(lock_py: Path, address: str, workflow_id: str, decision_id: str) -> tuple[bool, str | None]:
    status_argv = [str(lock_py), "-m", "hermes_temporal.cli", "--address", address, "status", workflow_id]
    last_err: str | None = None
    for attempt in range(6):
        res = subprocess.run(
            status_argv,
            cwd=str(FRAMEWORK_DIR),
            env={**os.environ, "PYTHONPATH": str(FRAMEWORK_DIR)},
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=15,
            check=False,
            creationflags=_NO_WINDOW,
        )
        if res.returncode == 0:
            try:
                parsed = json.loads(res.stdout.strip())
                decisions = parsed.get("decisions") if isinstance(parsed, dict) else None
                if isinstance(decisions, list) and any(
                    isinstance(d, dict) and d.get("decision_id") == decision_id for d in decisions
                ):
                    return True, None
            except ValueError as exc:
                last_err = f"Invalid workflow status JSON: {exc}"
        else:
            last_err = res.stderr.strip() or f"status exited {res.returncode}"
        if attempt < 5:
            time.sleep(0.4)
    return False, last_err


def cmd_gate_decide(args: argparse.Namespace) -> int:
    lock_py = _resolve_lock_python(args.python)
    if not lock_py:
        return _emit({"ok": False, "error": "Lock Python not found; pass --python."}, 1)
    checked, err = _validate_gate_inputs(args)
    if err or checked is None:
        return _emit({"ok": False, "error": err or "Invalid gate decision arguments."}, 1)
    address, workflow_id, step_id, decision_id, operator, evidence_note = checked
    argv = [
        str(lock_py), "-m", "hermes_temporal.cli",
        "--address", address,
        "decision", workflow_id,
        "--step-id", step_id,
        "--phase", args.phase,
        "--choice", args.choice,
        "--decision-id", decision_id,
        "--decided-by", operator,
        "--via", "cli",
        "--evidence-note", evidence_note,
    ]
    if args.dry_run:
        return _emit({"ok": True, "dry_run": True, "argv": argv})
    res = subprocess.run(
        argv,
        cwd=str(FRAMEWORK_DIR),
        env={**os.environ, "PYTHONPATH": str(FRAMEWORK_DIR)},
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
        check=False,
        creationflags=_NO_WINDOW,
    )
    if res.returncode != 0:
        return _emit({
            "ok": False,
            "exit_code": res.returncode,
            "stdout": res.stdout.strip(),
            "stderr": res.stderr.strip(),
        }, 1)
    recorded, status_err = _verify_recorded_decision(lock_py, address, workflow_id, decision_id)
    if not recorded:
        return _emit({
            "ok": False,
            "exit_code": 0,
            "decision_recorded": False,
            "stdout": res.stdout.strip(),
            "error": status_err or f"Decision signal sent, but workflow {workflow_id} did not record {decision_id}.",
        }, 1)
    return _emit({
        "ok": True,
        "exit_code": 0,
        "decision_recorded": True,
        "stdout": res.stdout.strip(),
        "stderr": res.stderr.strip(),
    }, 0)


def cmd_snapshot(args: argparse.Namespace) -> int:
    if args.port < 1 or args.port > 65535:
        return _emit({"ok": False, "error": "Board port must be 1..65535 (Rule 2)."}, 1)
    target: Path | None = None
    if args.out:
        target, out_err = _validate_isolated_hermes_home(args.out, forbid_git_worktree=False, label="out")
        if out_err or target is None:
            return _emit({"ok": False, "error": out_err or "Invalid --out path."}, 1)
    fetched = _fetch_board(args.port)
    if fetched is None:
        return _emit({
            "ok": False,
            "board": None,
            "state": None,
            "error": f"No active HuntBoard at http://127.0.0.1:{args.port}/.",
        }, 1)
    summary, raw_state = fetched
    out: dict[str, object] = {"ok": True, "board": summary, "state": raw_state}
    if target is not None:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(out, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        out["saved_to"] = str(target)
    return _emit(out, 0)


def cmd_logs(args: argparse.Namespace) -> int:
    hermes_home, home_err = _validate_isolated_hermes_home(args.hermes_home)
    if home_err or hermes_home is None:
        return _emit({"ok": False, "error": home_err or "Invalid HERMES_HOME."}, 1)
    log_dir = hermes_home / "logs"
    if not log_dir.is_dir():
        return _emit({"ok": True, "logs": [], "note": f"No logs directory at {log_dir}"})
    entries = []
    for log_file in sorted(log_dir.glob("*.log")):
        lines = log_file.read_text(encoding="utf-8-sig", errors="replace").splitlines()[-args.lines:]
        entries.append({"file": str(log_file), "tail": lines})
    return _emit({"ok": True, "logs": entries})


def cmd_cleanup(args: argparse.Namespace) -> int:
    pid_file = Path(args.pid_file).resolve()
    if not pid_file.is_file():
        return _emit({"ok": True, "stopped": False, "reason": f"No PID file at {pid_file}; evidence preserved."})
    data = json.loads(pid_file.read_text(encoding="utf-8-sig"))
    pid = int(data["pid"])
    expected_binary = str(data.get("binary") or "")
    expected_create = str(data.get("create_time") or "")
    state, ident = _process_identity(pid)
    if state == "dead":
        if args.dry_run:
            return _emit({"ok": True, "dry_run": True, "stopped": False, "pid": pid, "pid_file": str(pid_file)})
        pid_file.unlink(missing_ok=True)
        return _emit({"ok": True, "stopped": False, "pid": pid, "evidence_preserved": True})
    if state != "alive" or not _pid_matches_recorded(ident, expected_binary, expected_create):
        return _emit({"ok": False, "stopped": False, "pid": pid, "reason": "pid_identity_mismatch"}, 1)
    if args.dry_run:
        return _emit({"ok": True, "dry_run": True, "would_stop_pid": pid, "pid_file": str(pid_file)})
    outcome = _terminate_verified(pid, expected_binary, expected_create)
    if outcome == "mismatch":
        return _emit({"ok": False, "stopped": False, "pid": pid, "reason": "pid_identity_mismatch"}, 1)
    if outcome.startswith("error:"):
        return _emit({"ok": False, "stopped": False, "pid": pid, "error": outcome[6:]}, 1)
    pid_file.unlink(missing_ok=True)
    return _emit({"ok": True, "stopped": outcome == "stopped", "pid": pid, "evidence_preserved": True})


def _posix_terminate_verified(pid: int, expected_binary: str, expected_create: str) -> str:
    pidfd_open = getattr(os, "pidfd_open", None)
    pidfd_send = getattr(signal, "pidfd_send_signal", None)
    if callable(pidfd_open) and callable(pidfd_send):
        try:
            pidfd = pidfd_open(pid, 0)
        except ProcessLookupError:
            return "dead"
        except PermissionError:
            return "mismatch"
        except OSError:
            pidfd = None
        if pidfd is not None:
            try:
                alive, ident = _posix_process_identity(pid)
                if alive == "dead":
                    return "dead"
                if alive != "alive" or not _pid_matches_recorded(ident, expected_binary, expected_create):
                    return "mismatch"
                pidfd_send(pidfd, signal.SIGTERM)
                return "stopped"
            except ProcessLookupError:
                return "dead"
            except OSError as exc:
                return f"error:{exc}"
            finally:
                os.close(pidfd)
    alive, ident = _posix_process_identity(pid)
    if alive == "dead":
        return "dead"
    if alive != "alive" or not _pid_matches_recorded(ident, expected_binary, expected_create):
        return "mismatch"
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        return "dead"
    except OSError as exc:
        return f"error:{exc}"
    return "stopped"


def _terminate_verified(pid: int, expected_binary: str, expected_create: str) -> str:
    if os.name == "nt":
        outcome = _windows_terminate_verified(pid, expected_binary, expected_create)
        return "error:TerminateProcess failed" if outcome == "failed" else outcome
    return _posix_terminate_verified(pid, expected_binary, expected_create)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Control CLI for verifying Hunt Command Desktop.")
    sub = parser.add_subparsers(dest="subcommand", required=True)

    p_doc = sub.add_parser("doctor", help="Read-only readiness check for Hunt Command plugins, build, and loopback boards.")
    p_doc.add_argument("--python", help="Lock venv Python interpreter path.")
    p_doc.add_argument("--hermes-home", help="Isolated HERMES_HOME to inspect for board-<port>.json entries.")
    p_doc.add_argument("--board-port", type=int, help="Additional loopback Hunt Board port to probe.")
    p_doc.add_argument(
        "--skip-packed-check",
        action="store_true",
        help="Allow doctor to succeed in source/CLI-only environments before running `npm run pack:hunt`.",
    )
    p_doc.set_defaults(func=cmd_doctor)

    p_launch = sub.add_parser("launch", help="Launch unpacked Hunt Command against an isolated HERMES_HOME.")
    p_launch.add_argument("--hermes-home", required=True, help="Isolated HERMES_HOME directory (never ~/.hermes).")
    p_launch.add_argument("--evidence-dir", required=True, help="Directory where PID metadata and proof artifacts live.")
    p_launch.add_argument("--cdp-port", type=int, default=0, help="Optional loopback CDP debugging port.")
    p_launch.add_argument("--dry-run", action="store_true", help="Print launch plan without spawning.")
    p_launch.set_defaults(func=cmd_launch)

    p_board = sub.add_parser("board-probe", help="Probe loopback Hunt Board state.json and optional live MJPEG feed.")
    p_board.add_argument("--port", type=int, default=DEFAULT_BOARD_PORT, help="Loopback Hunt Board port.")
    p_board.add_argument("--profile", help="Optional bot profile slug (e.g. framework-network-analyst) for /live/<profile>.mjpg.")
    p_board.set_defaults(func=cmd_board_probe)

    p_gate = sub.add_parser("gate-decide", help="Send or dry-run a governed human gate decision via hermes_temporal.cli.")
    p_gate.add_argument("--python", help="Lock venv Python interpreter path.")
    p_gate.add_argument("--address", default=DEFAULT_TEMPORAL_ADDR, help="Loopback Temporal address (127.0.0.1:<port>).")
    p_gate.add_argument("--workflow-id", required=True, help="Round workflow ID receiving the decision.")
    p_gate.add_argument("--step-id", required=True, help="Gate step ID (e.g. wave-1 or scope).")
    p_gate.add_argument("--phase", choices=("execute", "review", "reconcile"), default="review")
    p_gate.add_argument("--choice", choices=("approve", "deny", "accept", "abort"), required=True)
    p_gate.add_argument("--decision-id", required=True, help="Idempotent ASCII decision ID.")
    p_gate.add_argument("--operator", required=True, help="Human operator identity (Rule 3).")
    p_gate.add_argument("--note", required=True, help="What did you check? note (Rule 3).")
    p_gate.add_argument("--dry-run", action="store_true", help="Validate and print CLI argv without sending.")
    p_gate.set_defaults(func=cmd_gate_decide)

    p_snap = sub.add_parser("snapshot", help="Capture read-only Hunt Board JSON state to stdout and optional artifact file.")
    p_snap.add_argument("--port", type=int, default=DEFAULT_BOARD_PORT)
    p_snap.add_argument("--out", help="Optional file path to persist snapshot JSON.")
    p_snap.set_defaults(func=cmd_snapshot)

    p_logs = sub.add_parser("logs", help="Read tail of logs inside an isolated HERMES_HOME.")
    p_logs.add_argument("--hermes-home", required=True)
    p_logs.add_argument("--lines", type=int, default=40)
    p_logs.set_defaults(func=cmd_logs)

    p_clean = sub.add_parser("cleanup", help="Stop only the PID recorded by launch while preserving evidence artifacts.")
    p_clean.add_argument("--pid-file", required=True, help="Path to hunt-command.pid written by launch.")
    p_clean.add_argument("--dry-run", action="store_true", help="Show which PID would be stopped.")
    p_clean.set_defaults(func=cmd_cleanup)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())

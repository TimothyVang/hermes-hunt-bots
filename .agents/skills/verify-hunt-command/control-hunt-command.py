#!/usr/bin/env python3
"""Executable verification harness CLI for Hunt Command Desktop (verify-hunt-command).

Provides machine-readable JSON subcommands for read-only doctor checks, unpacked
Hunt Command binary verification, loopback Hunt Board discovery + live MJPEG stream
probing, Temporal human-gate inspection/dry-run verification, log inspection, and
PID-scoped cleanup that never kills unrelated processes or deletes captured evidence.
"""
from __future__ import annotations

import argparse
from datetime import UTC, datetime
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import urllib.error
import urllib.request


REPO_ROOT = Path(__file__).resolve().parents[3]
DESKTOP_DIR = REPO_ROOT / "apps" / "desktop"
FRAMEWORK_DIR = REPO_ROOT / "framework"
DEFAULT_BOARD_PORT = 8790
DEFAULT_TEMPORAL_ADDR = "127.0.0.1:7233"


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
            return cand.resolve()
    return None


def _packed_binary() -> Path:
    if os.name == "nt":
        return DESKTOP_DIR / "release" / "win-unpacked" / "Hunt Command.exe"
    if sys.platform == "darwin":
        return DESKTOP_DIR / "release" / "mac" / "Hunt Command.app" / "Contents" / "MacOS" / "Hunt Command"
    return DESKTOP_DIR / "release" / "linux-unpacked" / "hunt-command"


def _probe_board(port: int) -> dict | None:
    if port < 1 or port > 65535:
        return None
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}/state.json",
        headers={"Accept": "application/json", "Host": f"127.0.0.1:{port}"},
        method="GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=5.0) as resp:
            server_hdr = resp.headers.get("Server", "")
            if resp.status != 200 or not server_hdr.startswith("HuntBoard"):
                return None
            body = json.loads(resp.read(524288).decode("utf-8"))
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
            return {
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
    except (OSError, ValueError, urllib.error.URLError):
        return None


def cmd_doctor(args: argparse.Namespace) -> int:
    lock_py = _resolve_lock_python(args.python)
    binary = _packed_binary()
    plugin_workspace = FRAMEWORK_DIR / "desktop" / "cybersecurity-workspace" / "plugin.js"
    plugin_lab = FRAMEWORK_DIR / "hunt_lab" / "desktop" / "plugin.js"
    assets_dirty = subprocess.run(
        ["git", "-C", str(DESKTOP_DIR), "status", "--porcelain", "--", "assets"],
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    ).stdout.strip()

    hermes_home = Path(args.hermes_home).resolve() if args.hermes_home else None
    discovered_boards: list[dict] = []
    seen_ports: set[int] = {DEFAULT_BOARD_PORT}
    if args.board_port:
        seen_ports.add(args.board_port)
    if hermes_home and (hermes_home / "hunt-board").is_dir():
        for item in sorted((hermes_home / "hunt-board").glob("board-*.json")):
            try:
                raw = json.loads(item.read_text(encoding="utf-8"))
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
        "lock_python": str(lock_py) if lock_py else None,
        "workspace_plugin_exists": plugin_workspace.is_file(),
        "hunt_lab_plugin_exists": plugin_lab.is_file(),
        "packed_binary_exists": binary.is_file(),
        "packed_binary": str(binary),
        "desktop_assets_clean": assets_dirty == "",
        "active_boards": discovered_boards,
    }
    ok = (
        checks["lock_python_found"]
        and checks["workspace_plugin_exists"]
        and checks["hunt_lab_plugin_exists"]
        and checks["desktop_assets_clean"]
    )
    remediation = None
    if not checks["lock_python_found"]:
        remediation = "Pass --python pointing to a venv with framework/requirements-hunt.lock installed."
    elif not checks["desktop_assets_clean"]:
        remediation = "Restore apps/desktop/assets with `git -C apps/desktop checkout -- assets` before packing."
    return _emit({"ok": ok, "checks": checks, "remediation": remediation}, 0 if ok else 1)


def cmd_launch(args: argparse.Namespace) -> int:
    binary = _packed_binary()
    hermes_home = Path(args.hermes_home).resolve()
    evidence_dir = Path(args.evidence_dir).resolve()
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
    hermes_home.mkdir(parents=True, exist_ok=True)
    evidence_dir.mkdir(parents=True, exist_ok=True)
    env = {**os.environ, "HERMES_HOME": str(hermes_home)}
    proc = subprocess.Popen(cmd, cwd=str(DESKTOP_DIR), env=env)
    pid_file = evidence_dir / "hunt-command.pid"
    pid_file.write_text(json.dumps({"pid": proc.pid, "hermes_home": str(hermes_home)}), encoding="utf-8")
    return _emit({"ok": True, "pid": proc.pid, "pid_file": str(pid_file), "hermes_home": str(hermes_home)})


def cmd_board_probe(args: argparse.Namespace) -> int:
    info = _probe_board(args.port)
    if not info:
        return _emit({
            "ok": False,
            "error": f"No active HuntBoard at http://127.0.0.1:{args.port}/. Start Hunt Board from /hunt-board or pass the active loopback --port.",
        }, 1)
    live_check = None
    if args.profile:
        mjpg_url = f"http://127.0.0.1:{args.port}/live/{args.profile}.mjpg"
        req = urllib.request.Request(
            mjpg_url,
            headers={"Host": f"127.0.0.1:{args.port}", "Sec-Fetch-Dest": "image"},
            method="GET",
        )
        try:
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                ctype = resp.headers.get("Content-Type", "")
                chunk = resp.read(44)
                live_check = {
                    "status": resp.status,
                    "content_type": ctype,
                    "bytes_sampled": len(chunk),
                    "ok": resp.status == 200 and "multipart/x-mixed-replace" in ctype and len(chunk) > 0,
                }
        except urllib.error.HTTPError as exc:
            live_check = {"status": exc.code, "ok": False, "error": f"HTTP {exc.code} on {mjpg_url}"}
        except OSError as exc:
            live_check = {"status": 0, "ok": False, "error": str(exc)}
    ok = True if live_check is None else bool(live_check["ok"])
    return _emit({"ok": ok, "board": info, "live_stream": live_check}, 0 if ok else 1)


def cmd_gate_decide(args: argparse.Namespace) -> int:
    lock_py = _resolve_lock_python(args.python)
    if not lock_py:
        return _emit({"ok": False, "error": "Lock Python not found; pass --python."}, 1)
    if not args.address.startswith("127.0.0.1:"):
        return _emit({"ok": False, "error": "Temporal address must use 127.0.0.1:<port> (Rule 2)."}, 1)
    operator = args.operator.strip()
    note = args.note.strip()
    if not operator or len(operator) > 200:
        return _emit({"ok": False, "error": "Operator name is required (1..200 chars, Rule 3)."}, 1)
    if not note or len(note) > 1000:
        return _emit({"ok": False, "error": "Check note ('What did you check?') is required (1..1000 chars, Rule 3)."}, 1)
    utc_iso = datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")
    evidence_note = f"Decided by {operator} via Hunt Command Desktop at {utc_iso}. Checked: {note}"
    argv = [
        str(lock_py), "-m", "hermes_temporal.cli",
        "--address", args.address,
        "decision", args.workflow_id,
        "--step-id", args.step_id,
        "--phase", args.phase,
        "--choice", args.choice,
        "--decision-id", args.decision_id,
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
        timeout=30,
        check=False,
    )
    return _emit({
        "ok": res.returncode == 0,
        "exit_code": res.returncode,
        "stdout": res.stdout.strip(),
        "stderr": res.stderr.strip(),
    }, 0 if res.returncode == 0 else 1)


def cmd_snapshot(args: argparse.Namespace) -> int:
    state = _probe_board(args.port)
    out = {"ok": state is not None, "board": state}
    if args.out and state is not None:
        target = Path(args.out).resolve()
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(out, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        out["saved_to"] = str(target)
    return _emit(out, 0 if state is not None else 1)


def cmd_logs(args: argparse.Namespace) -> int:
    hermes_home = Path(args.hermes_home).resolve()
    log_dir = hermes_home / "logs"
    if not log_dir.is_dir():
        return _emit({"ok": True, "logs": [], "note": f"No logs directory at {log_dir}"})
    entries = []
    for log_file in sorted(log_dir.glob("*.log")):
        lines = log_file.read_text(encoding="utf-8", errors="replace").splitlines()[-args.lines:]
        entries.append({"file": str(log_file), "tail": lines})
    return _emit({"ok": True, "logs": entries})


def cmd_cleanup(args: argparse.Namespace) -> int:
    pid_file = Path(args.pid_file).resolve()
    if not pid_file.is_file():
        return _emit({"ok": True, "stopped": False, "reason": f"No PID file at {pid_file}; evidence preserved."})
    data = json.loads(pid_file.read_text(encoding="utf-8"))
    pid = int(data["pid"])
    if args.dry_run:
        return _emit({"ok": True, "dry_run": True, "would_stop_pid": pid, "pid_file": str(pid_file)})
    stopped = False
    try:
        os.kill(pid, signal.SIGTERM)
        stopped = True
    except OSError:
        stopped = False
    pid_file.unlink(missing_ok=True)
    return _emit({"ok": True, "stopped": stopped, "pid": pid, "evidence_preserved": True})


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Control CLI for verifying Hunt Command Desktop.")
    sub = parser.add_subparsers(dest="subcommand", required=True)

    p_doc = sub.add_parser("doctor", help="Read-only readiness check for Hunt Command plugins, build, and loopback boards.")
    p_doc.add_argument("--python", help="Lock venv Python interpreter path.")
    p_doc.add_argument("--hermes-home", help="Isolated HERMES_HOME to inspect for board-<port>.json entries.")
    p_doc.add_argument("--board-port", type=int, help="Additional loopback Hunt Board port to probe.")
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

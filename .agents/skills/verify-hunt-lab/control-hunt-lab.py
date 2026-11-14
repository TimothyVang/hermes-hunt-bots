#!/usr/bin/env python3
"""Executable verification harness CLI for the Hunting Lab stack (verify-hunt-lab).

Provides machine-readable JSON subcommands for read-only doctor checks, lab status,
start/stop (--dry-run supported), read-only loopback evidence probes, tool-driven
Temporal lab-input export, live browser screencast verification, and cleanup.
"""
from __future__ import annotations

import argparse
import importlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys


REPO_ROOT = Path(__file__).resolve().parents[3]
FRAMEWORK_DIR = REPO_ROOT / "framework"


def _load_endpoints():
    fw = str(FRAMEWORK_DIR)
    if fw not in sys.path:
        sys.path.insert(0, fw)
    return importlib.import_module("hunt_lab.endpoints")


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


def _run_py(python_exe: Path, argv: list[str], env_extra: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    env = {**os.environ, "PYTHONPATH": str(FRAMEWORK_DIR)}
    if env_extra:
        env.update(env_extra)
    return subprocess.run(
        argv if Path(argv[0]).is_file() else [str(python_exe), *argv],
        cwd=str(FRAMEWORK_DIR),
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
        check=False,
    )


def cmd_doctor(args: argparse.Namespace) -> int:
    lock_py = _resolve_lock_python(args.python)
    docker_bin = shutil.which("docker")
    docker_ready = False
    if docker_bin:
        probe = subprocess.run(
            [docker_bin, "info"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=10,
            check=False,
        )
        docker_ready = probe.returncode == 0
    fixture_case = FRAMEWORK_DIR / "hunt_lab" / "fixtures" / "dns-lab-001" / "case.json"
    hermes_home = Path(args.hermes_home).resolve() if args.hermes_home else None
    analyst_vm = hermes_home / "profiles" / "framework-network-analyst" / "hunt-lab-vm" if hermes_home else None
    checks = {
        "lock_python_found": lock_py is not None,
        "lock_python": str(lock_py) if lock_py else None,
        "docker_cli_found": docker_bin is not None,
        "docker_daemon_ready": docker_ready,
        "fixture_case_exists": fixture_case.is_file(),
        "hermes_home": str(hermes_home) if hermes_home else None,
        "analyst_vm_dir_exists": bool(analyst_vm and analyst_vm.is_dir()),
    }
    ok = checks["lock_python_found"] and checks["fixture_case_exists"]
    remediation = None
    if not checks["lock_python_found"]:
        remediation = "Pass --python pointing to a Python with framework/requirements-hunt.lock installed."
    elif not docker_ready:
        remediation = "Start Docker Desktop before running live container lifecycle journeys (`launch` / `cleanup`)."
    return _emit({"ok": ok, "checks": checks, "remediation": remediation}, 0 if ok else 1)


def cmd_status(args: argparse.Namespace) -> int:
    lock_py = _resolve_lock_python(args.python)
    if not lock_py:
        return _emit({"ok": False, "error": "Lock Python not found; pass --python."}, 1)
    hermes_home = Path(args.hermes_home).resolve()
    argv = [str(lock_py), str(FRAMEWORK_DIR / "bot.py"), "lab", "status", "--home", str(hermes_home)]
    if args.hermes:
        argv.extend(["--hermes", args.hermes])
    res = _run_py(lock_py, argv)
    parsed = None
    for line in reversed(res.stdout.splitlines()):
        try:
            parsed = json.loads(line)
            break
        except ValueError:
            continue
    ok = res.returncode == 0 and parsed is not None
    return _emit({
        "ok": ok,
        "exit_code": res.returncode,
        "status": parsed,
        "stderr": res.stderr.strip(),
    }, 0 if ok else 1)


def cmd_launch(args: argparse.Namespace) -> int:
    lock_py = _resolve_lock_python(args.python)
    if not lock_py:
        return _emit({"ok": False, "error": "Lock Python not found; pass --python."}, 1)
    hermes_home = Path(args.hermes_home).resolve()
    env_extra: dict[str, str] | None = None
    if args.case:
        case_dir = str(Path(args.case).resolve())
        state_dir = str(hermes_home / "profiles" / "framework-network-analyst" / "hunt-lab-vm")
        if args.hermes:
            hermes_bin = shutil.which(args.hermes) or args.hermes
            argv = [hermes_bin, "-p", "framework-network-analyst", "hunt-lab", "start", "--evidence-dir", case_dir]
            env_extra = {"HERMES_HOME": str(hermes_home)}
        else:
            argv = [str(lock_py), "-m", "hunt_lab.lab_stack", "start", "--state-dir", state_dir, "--evidence-dir", case_dir]
    else:
        argv = [str(lock_py), str(FRAMEWORK_DIR / "bot.py"), "lab", "start", "--home", str(hermes_home)]
        if args.hermes:
            argv.extend(["--hermes", args.hermes])
    if args.dry_run:
        return _emit({"ok": True, "dry_run": True, "argv": argv})
    if args.case and args.hermes:
        res = subprocess.run(
            argv,
            cwd=str(FRAMEWORK_DIR),
            env={**os.environ, "PYTHONPATH": str(FRAMEWORK_DIR), **(env_extra or {})},
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=120,
            check=False,
        )
    else:
        res = _run_py(lock_py, argv, env_extra=env_extra)
    return _emit({
        "ok": res.returncode == 0,
        "exit_code": res.returncode,
        "stdout": res.stdout.strip(),
        "stderr": res.stderr.strip(),
    }, 0 if res.returncode == 0 else 1)


def _resolve_query_target(args: argparse.Namespace, endpoints):
    state_dir = None
    if getattr(args, "state_dir", None):
        state_dir = Path(args.state_dir).resolve()
    elif getattr(args, "hermes_home", None):
        state_dir = Path(args.hermes_home).resolve() / "profiles" / endpoints.LAB_OWNER / "hunt-lab-vm"

    if state_dir is not None:
        served = endpoints.resolve(state_dir, getattr(args, "case_id", None), profile=args.profile)
        if getattr(args, "lab_url", None):
            checked_url = endpoints.endpoint(args.lab_url)
            if checked_url != served.lab_url:
                raise endpoints.QueryFailure("case_endpoint_mismatch", served.lab_url)
        return served.lab_url, served.origin, served.instance, served.secret

    if getattr(args, "lab_url", None):
        base_url = endpoints.endpoint(args.lab_url)
        secret = args.secret if getattr(args, "secret", None) is not None else os.environ.get("HUNT_LAB_SECRET")
        return base_url, "direct", getattr(args, "instance", None), secret

    return None, None, None, None


def cmd_query(args: argparse.Namespace) -> int:
    endpoints = _load_endpoints()
    try:
        base_url, origin, instance, secret = _resolve_query_target(args, endpoints)
        if not base_url:
            return _emit({
                "ok": False,
                "error": "Pass --hermes-home (or --state-dir) to resolve the active lab with X-Hunt-Lab-Secret, or --lab-url with --secret.",
            }, 1)
        endpoint_path = "/" + args.endpoint.lstrip("/")
        payload = endpoints.get(
            base_url,
            endpoint_path,
            args.profile,
            timeout=10.0,
            instance=instance,
            secret=secret,
        )
    except endpoints.QueryFailure as exc:
        return _emit({"ok": False, "error": str(exc), "detail": exc.detail}, 1)

    result = {"ok": True, "lab_url": base_url, "origin": origin, "data": payload}
    if args.out:
        target = Path(args.out).resolve()
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        result["saved_to"] = str(target)
    return _emit(result)


def cmd_lab_input(args: argparse.Namespace) -> int:
    lock_py = _resolve_lock_python(args.python)
    if not lock_py:
        return _emit({"ok": False, "error": "Lock Python not found; pass --python."}, 1)
    state_dir = Path(args.state_dir).resolve()
    out_file = Path(args.out).resolve()
    argv = [str(lock_py), "-m", "hermes_temporal.cli", "lab-input", "--state-dir", str(state_dir), "--output", str(out_file)]
    if args.tool_driven:
        argv.append("--tool-driven")
    if args.case_id:
        argv.extend(["--case-id", args.case_id])
    if args.data_origin:
        argv.extend(["--data-origin", args.data_origin])
    if args.dry_run:
        return _emit({"ok": True, "dry_run": True, "argv": argv, "out": str(out_file)})
    out_file.parent.mkdir(parents=True, exist_ok=True)
    res = _run_py(lock_py, argv)
    if res.returncode != 0:
        return _emit({"ok": False, "exit_code": res.returncode, "stderr": res.stderr.strip()}, 1)
    parsed = json.loads(out_file.read_text(encoding="utf-8-sig"))
    return _emit({
        "ok": True,
        "out": str(out_file),
        "mode": parsed.get("mode", "inline"),
        "data_origin": parsed.get("data_origin", "synthetic"),
        "synthetic_only": parsed.get("synthetic_only"),
    })


def cmd_snapshot(args: argparse.Namespace) -> int:
    return cmd_query(
        argparse.Namespace(
            hermes_home=args.hermes_home,
            state_dir=args.state_dir,
            case_id=args.case_id,
            lab_url=args.lab_url,
            secret=args.secret,
            instance=args.instance,
            endpoint="/health",
            profile="hunt-board",
            out=args.out,
        )
    )


def cmd_logs(args: argparse.Namespace) -> int:
    hermes_home = Path(args.hermes_home).resolve()
    browser_root = hermes_home / "profiles" / "framework-network-analyst" / "hunt-lab-browser"
    audits = []
    if browser_root.is_dir():
        for audit_file in sorted(browser_root.glob("*/audit.jsonl")):
            lines = audit_file.read_text(encoding="utf-8-sig", errors="replace").splitlines()[-args.lines:]
            audits.append({"profile": audit_file.parent.name, "file": str(audit_file), "tail": lines})
    return _emit({"ok": True, "browser_audits": audits})


def cmd_cleanup(args: argparse.Namespace) -> int:
    lock_py = _resolve_lock_python(args.python)
    if not lock_py:
        return _emit({"ok": False, "error": "Lock Python not found; pass --python."}, 1)
    hermes_home = Path(args.hermes_home).resolve()
    argv = [str(lock_py), str(FRAMEWORK_DIR / "bot.py"), "lab", "stop", "--home", str(hermes_home)]
    if args.hermes:
        argv.extend(["--hermes", args.hermes])
    if args.dry_run:
        return _emit({"ok": True, "dry_run": True, "argv": argv, "evidence_preserved": True})
    res = _run_py(lock_py, argv)
    return _emit({
        "ok": res.returncode == 0,
        "exit_code": res.returncode,
        "stdout": res.stdout.strip(),
        "stderr": res.stderr.strip(),
        "evidence_preserved": True,
    }, 0 if res.returncode == 0 else 1)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Control CLI for verifying the Hunting Lab stack.")
    sub = parser.add_subparsers(dest="subcommand", required=True)

    p_doc = sub.add_parser("doctor", help="Read-only check of lock Python, Docker engine, and bundled synthetic fixture.")
    p_doc.add_argument("--python", help="Lock venv Python interpreter path.")
    p_doc.add_argument("--hermes-home", help="Optional isolated HERMES_HOME to check.")
    p_doc.set_defaults(func=cmd_doctor)

    p_stat = sub.add_parser("status", help="Read-only `bot.py lab status` against an isolated HERMES_HOME.")
    p_stat.add_argument("--python", help="Lock venv Python interpreter path.")
    p_stat.add_argument("--hermes-home", required=True)
    p_stat.add_argument("--hermes", help="Optional Hermes CLI executable.")
    p_stat.set_defaults(func=cmd_status)

    p_launch = sub.add_parser("launch", help="Start the local 127.0.0.1 Docker lab stack for an isolated HERMES_HOME.")
    p_launch.add_argument("--python", help="Lock venv Python interpreter path.")
    p_launch.add_argument("--hermes-home", required=True)
    p_launch.add_argument("--case", help="Optional path to synthetic case folder.")
    p_launch.add_argument("--hermes", help="Optional Hermes CLI executable.")
    p_launch.add_argument("--dry-run", action="store_true")
    p_launch.set_defaults(func=cmd_launch)

    p_query = sub.add_parser("query", help="Issue an authenticated, bounded read-only GET against a loopback lab endpoint.")
    p_query.add_argument("--hermes-home", help="Isolated HERMES_HOME used to resolve the active lab and its X-Hunt-Lab-Secret.")
    p_query.add_argument("--state-dir", help="Explicit analyst hunt-lab-vm state directory.")
    p_query.add_argument("--case-id", help="Optional case ID when resolving from --hermes-home or --state-dir.")
    p_query.add_argument("--lab-url", help="Optional loopback lab URL (http://127.0.0.1:<port>) validated via hunt_lab.endpoints.")
    p_query.add_argument(
        "--secret",
        help="Optional caller X-Hunt-Lab-Secret when querying --lab-url directly (hunt-board accepts master or subkey).",
    )
    p_query.add_argument("--instance", help="Optional expected X-Hunt-Lab-Instance header.")
    p_query.add_argument("--endpoint", default="/health", help="Endpoint path (e.g. /health, /activity, /es/search?q=*).")
    p_query.add_argument("--profile", default="hunt-board")
    p_query.add_argument("--out", help="Optional artifact path to write JSON response.")
    p_query.set_defaults(func=cmd_query)

    p_inp = sub.add_parser("lab-input", help="Export Temporal lab-input JSON (inline or --tool-driven).")
    p_inp.add_argument("--python", help="Lock venv Python interpreter path.")
    p_inp.add_argument("--state-dir", required=True, help="Analyst hunt-lab-vm state directory.")
    p_inp.add_argument("--out", required=True, help="New output JSON path in evidence/scratch dir.")
    p_inp.add_argument("--tool-driven", action="store_true")
    p_inp.add_argument("--case-id", help="Optional case ID.")
    p_inp.add_argument("--data-origin", choices=("public-dataset", "work-export", "work-connected"))
    p_inp.add_argument("--dry-run", action="store_true")
    p_inp.set_defaults(func=cmd_lab_input)

    p_snap = sub.add_parser("snapshot", help="Capture authenticated lab /health JSON snapshot to an evidence file.")
    p_snap.add_argument("--hermes-home", help="Isolated HERMES_HOME used to resolve the active lab and its X-Hunt-Lab-Secret.")
    p_snap.add_argument("--state-dir", help="Explicit analyst hunt-lab-vm state directory.")
    p_snap.add_argument("--case-id", help="Optional case ID when resolving from --hermes-home or --state-dir.")
    p_snap.add_argument("--lab-url", help="Optional loopback lab URL (http://127.0.0.1:<port>).")
    p_snap.add_argument("--secret", help="Optional X-Hunt-Lab-Secret when querying --lab-url directly.")
    p_snap.add_argument("--instance", help="Optional expected X-Hunt-Lab-Instance header.")
    p_snap.add_argument("--out", required=True)
    p_snap.set_defaults(func=cmd_snapshot)

    p_logs = sub.add_parser("logs", help="Read tail of lab_browser audit.jsonl files in isolated HERMES_HOME.")
    p_logs.add_argument("--hermes-home", required=True)
    p_logs.add_argument("--lines", type=int, default=30)
    p_logs.set_defaults(func=cmd_logs)

    p_clean = sub.add_parser("cleanup", help="Stop the isolated HERMES_HOME lab container project without deleting evidence.")
    p_clean.add_argument("--python", help="Lock venv Python interpreter path.")
    p_clean.add_argument("--hermes-home", required=True)
    p_clean.add_argument("--hermes", help="Optional Hermes CLI executable.")
    p_clean.add_argument("--dry-run", action="store_true")
    p_clean.set_defaults(func=cmd_cleanup)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())

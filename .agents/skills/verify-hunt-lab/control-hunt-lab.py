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
import re
import shutil
import subprocess
import sys
import tempfile


REPO_ROOT = Path(__file__).resolve().parents[3]
FRAMEWORK_DIR = REPO_ROOT / "framework"
_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


def _load_endpoints():
    fw = str(FRAMEWORK_DIR)
    if fw not in sys.path:
        sys.path.insert(0, fw)
    return importlib.import_module("hunt_lab.endpoints")


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


def _touches_operator_only(cand: Path) -> bool:
    operator_only = (REPO_ROOT.parent / "runtime" / "operator-only").resolve()
    return (
        _paths_overlap(cand, operator_only)
        or any(part.lower() == "operator-only" for part in cand.parts)
        or (cand / "operator-only").exists()
    )


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
    if _touches_operator_only(cand):
        return None, f"{label} ({cand}) must never touch operator-only directories."
    in_git = _paths_overlap(cand, REPO_ROOT.resolve()) or any(
        (parent / ".git").exists() for parent in (cand, *cand.parents)
    )
    if in_git and (forbid_git_worktree or ".scratch" not in cand.parts):
        return None, f"{label} ({cand}) must be outside the repository/git worktree."
    return cand, None


_COMPOSE_PROJECT = re.compile(r"hunt-lab-[a-z0-9-]{3,64}")
_DOCKER_DESKTOP_HOST = re.compile(r"^/(?:run/desktop/mnt/host|host_mnt|mnt/host)/([a-zA-Z])/(.*)$")


def _read_json_dict(path: Path) -> dict | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError):
        return None
    return value if isinstance(value, dict) else None


def _host_path_key(raw: str) -> str:
    """Comparable form of a host path as Docker reports it (C:\\x, /run/desktop/mnt/host/c/x, or /x)."""
    text = raw.replace("\\", "/").rstrip("/")
    desktop = _DOCKER_DESKTOP_HOST.match(text)
    if desktop:
        text = f"{desktop.group(1)}:/{desktop.group(2)}"
    return text.lower() if os.name == "nt" or re.match(r"^[a-zA-Z]:/", text) else text


def _home_lab_target(hermes_home: Path, *, fixture_fallback: bool) -> tuple[str, Path] | None:
    """(compose project, container-state root) for the case `bot.py lab start|stop` acts on.

    Docker Compose project names are engine-wide (hunt-lab-<case_id>), so an isolated HERMES_HOME does not isolate
    the stack: another home (the operator's) can run the same project.
    """
    endpoints = _load_endpoints()
    root = hermes_home / "profiles" / "framework-network-analyst" / endpoints.CONTAINER_STATE
    case_id = (_read_json_dict(root / "last.json") or {}).get("case_id")
    if case_id is None and fixture_fallback:
        case_id = (_read_json_dict(FRAMEWORK_DIR / "hunt_lab" / "fixtures" / "dns-lab-001" / "case.json") or {}).get("case_id")
    if not isinstance(case_id, str) or not endpoints.CASE_ID.fullmatch(case_id):
        return None
    project = endpoints.CONTAINER_PROJECT_PREFIX + case_id
    try:
        override = (root / case_id / "compose-project").read_text(encoding="ascii").strip()
    except (OSError, UnicodeDecodeError):
        override = ""
    if _COMPOSE_PROJECT.fullmatch(override):
        project = override
    return project, root


def _docker_lines(docker_bin: str, argv: list[str]) -> tuple[list[str] | None, str | None]:
    res = subprocess.run(
        [docker_bin, *argv],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=15,
        check=False,
        creationflags=_NO_WINDOW,
    )
    if res.returncode != 0:
        return None, f"docker {argv[0]} failed ({res.stderr.strip()[:200]}); cannot verify compose project ownership."
    return [line for line in res.stdout.splitlines() if line.strip()], None


def _check_project_ownership(hermes_home: Path, *, fixture_fallback: bool) -> str | None:
    """Refuse unless the target compose project is absent or every lab-state bind in it comes from this home.

    Stopped containers keep their mounts, and a reused port proves nothing. lab_stack bind-mounts the case's
    evidence, lab secret and instance-id from `<state>/hunt-lab-container/<case>/` into the lab, ingest, arkime and
    kibana-setup containers, so those bind sources name the home that started the project even when the lab
    container itself is gone (a failed warm switch).
    """
    target = _home_lab_target(hermes_home, fixture_fallback=fixture_fallback)
    if target is None:
        return None if not fixture_fallback else "Could not determine the lab case for this HERMES_HOME."
    project, root = target
    docker_bin = shutil.which("docker")
    if not docker_bin:
        return "Docker CLI not found; cannot verify compose project ownership."
    label = f"label=com.docker.compose.project={project}"
    ids, err = _docker_lines(docker_bin, ["ps", "-a", "-q", "--no-trunc", "--filter", label])
    if err or ids is None:
        return err
    refusal = (
        f"compose_project_in_use: Docker project {project} has containers or volumes this HERMES_HOME did not "
        "start (another Hermes home, the operator's lab, or leftovers); refusing to start or stop it."
    )
    if not ids:
        volumes, err = _docker_lines(docker_bin, ["volume", "ls", "-q", "--filter", label])
        if err or volumes is None:
            return err
        return refusal if volumes else None
    mounts, err = _docker_lines(docker_bin, ["inspect", "--format", "{{json .Mounts}}", *ids])
    if err or mounts is None:
        return err
    sources = []
    for line in mounts:
        try:
            entries = json.loads(line)
        except ValueError:
            return refusal
        sources.extend(
            _host_path_key(str(entry.get("Source") or ""))
            for entry in entries or ()
            if isinstance(entry, dict) and entry.get("Type") == "bind"
        )
    lab_state = [source for source in sources if f"/{root.name.lower()}/" in source.lower()]
    root_key = _host_path_key(str(root.resolve()))
    if lab_state and all(source.startswith(root_key + "/") for source in lab_state):
        return None
    return refusal


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


def _run_py(python_exe: Path, argv: list[str]) -> subprocess.CompletedProcess:
    env = {**os.environ, "PYTHONPATH": str(FRAMEWORK_DIR)}
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
        creationflags=_NO_WINDOW,
    )


def _check_lock_python_ready(lock_py: Path | None) -> bool:
    if not lock_py:
        return False
    try:
        probe = _run_py(lock_py, ["-c", "import temporalio, websockets, hermes_temporal.cli"])
    except OSError:
        return False
    return probe.returncode == 0


def cmd_doctor(args: argparse.Namespace) -> int:
    lock_py = _resolve_lock_python(args.python)
    lock_ready = _check_lock_python_ready(lock_py)
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
            creationflags=_NO_WINDOW,
        )
        docker_ready = probe.returncode == 0
    fixture_case = FRAMEWORK_DIR / "hunt_lab" / "fixtures" / "dns-lab-001" / "case.json"
    hermes_home: Path | None = None
    home_err: str | None = None
    if args.hermes_home is not None:
        hermes_home, home_err = _validate_isolated_hermes_home(args.hermes_home)
    analyst_vm = hermes_home / "profiles" / "framework-network-analyst" / "hunt-lab-vm" if hermes_home else None
    checks = {
        "lock_python_found": lock_py is not None,
        "lock_python_ready": lock_ready,
        "lock_python": str(lock_py) if lock_py else None,
        "hermes_home_isolated": home_err is None,
        "docker_cli_found": docker_bin is not None,
        "docker_daemon_ready": docker_ready,
        "fixture_case_exists": fixture_case.is_file(),
        "hermes_home": str(hermes_home) if hermes_home else None,
        "analyst_vm_dir_exists": bool(analyst_vm and analyst_vm.is_dir()),
    }
    ok = (
        checks["lock_python_found"]
        and checks["lock_python_ready"]
        and checks["hermes_home_isolated"]
        and checks["fixture_case_exists"]
    )
    remediation = None
    if home_err:
        remediation = home_err
    elif not checks["lock_python_found"]:
        remediation = "Pass --python pointing to a Python with framework/requirements-hunt.lock installed."
    elif not checks["lock_python_ready"]:
        remediation = "Selected --python cannot import temporalio/websockets; install framework/requirements-hunt.lock."
    elif not docker_ready:
        remediation = "Start Docker Desktop before running live container lifecycle journeys (`launch` / `cleanup`)."
    return _emit({"ok": ok, "checks": checks, "remediation": remediation}, 0 if ok else 1)


def cmd_status(args: argparse.Namespace) -> int:
    hermes_home, home_err = _validate_isolated_hermes_home(args.hermes_home)
    if home_err or hermes_home is None:
        return _emit({"ok": False, "error": home_err or "Invalid HERMES_HOME."}, 1)
    lock_py = _resolve_lock_python(args.python)
    if not lock_py:
        return _emit({"ok": False, "error": "Lock Python not found; pass --python."}, 1)
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
    hermes_home, home_err = _validate_isolated_hermes_home(args.hermes_home)
    if home_err or hermes_home is None:
        return _emit({"ok": False, "error": home_err or "Invalid HERMES_HOME."}, 1)
    lock_py = _resolve_lock_python(args.python)
    if not lock_py:
        return _emit({"ok": False, "error": "Lock Python not found; pass --python."}, 1)
    argv = [str(lock_py), str(FRAMEWORK_DIR / "bot.py"), "lab", "start", "--home", str(hermes_home)]
    if args.hermes:
        argv.extend(["--hermes", args.hermes])
    if args.dry_run:
        return _emit({"ok": True, "dry_run": True, "argv": argv})
    owner_err = _check_project_ownership(hermes_home, fixture_fallback=True)
    if owner_err:
        return _emit({"ok": False, "error": owner_err}, 1)
    res = _run_py(lock_py, argv)
    return _emit({
        "ok": res.returncode == 0,
        "exit_code": res.returncode,
        "stdout": res.stdout.strip(),
        "stderr": res.stderr.strip(),
    }, 0 if res.returncode == 0 else 1)


def _resolve_query_target(args: argparse.Namespace, endpoints):
    state_dir = None
    if getattr(args, "state_dir", None):
        checked_state, state_err = _validate_isolated_hermes_home(args.state_dir, label="state_dir")
        if state_err or checked_state is None:
            raise endpoints.QueryFailure("invalid_state_dir", state_err or "Invalid state_dir")
        state_dir = checked_state
    elif getattr(args, "hermes_home", None):
        checked_home, home_err = _validate_isolated_hermes_home(args.hermes_home)
        if home_err or checked_home is None:
            raise endpoints.QueryFailure("invalid_hermes_home", home_err or "Invalid HERMES_HOME")
        state_dir = checked_home / "profiles" / endpoints.LAB_OWNER / "hunt-lab-vm"

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
    target: Path | None = None
    if args.out:
        target, out_err = _validate_isolated_hermes_home(args.out, forbid_git_worktree=False, label="out")
        if out_err or target is None:
            return _emit({"ok": False, "error": out_err or "Invalid --out path."}, 1)
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
    if target is not None:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        result["saved_to"] = str(target)
    return _emit(result)


def cmd_lab_input(args: argparse.Namespace) -> int:
    state_dir, state_err = _validate_isolated_hermes_home(args.state_dir, label="state_dir")
    if state_err or state_dir is None:
        return _emit({"ok": False, "error": state_err or "Invalid --state-dir."}, 1)
    out_file, out_err = _validate_isolated_hermes_home(args.out, forbid_git_worktree=False, label="out")
    if out_err or out_file is None:
        return _emit({"ok": False, "error": out_err or "Invalid --out."}, 1)
    lock_py = _resolve_lock_python(args.python)
    if not lock_py:
        return _emit({"ok": False, "error": "Lock Python not found; pass --python."}, 1)
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
    hermes_home, home_err = _validate_isolated_hermes_home(args.hermes_home)
    if home_err or hermes_home is None:
        return _emit({"ok": False, "error": home_err or "Invalid HERMES_HOME."}, 1)
    browser_root = hermes_home / "profiles" / "framework-network-analyst" / "hunt-lab-browser"
    audits = []
    if browser_root.is_dir():
        for audit_file in sorted(browser_root.glob("*/audit.jsonl")):
            lines = audit_file.read_text(encoding="utf-8-sig", errors="replace").splitlines()[-args.lines:]
            audits.append({"profile": audit_file.parent.name, "file": str(audit_file), "tail": lines})
    return _emit({"ok": True, "browser_audits": audits})


def cmd_cleanup(args: argparse.Namespace) -> int:
    hermes_home, home_err = _validate_isolated_hermes_home(args.hermes_home)
    if home_err or hermes_home is None:
        return _emit({"ok": False, "error": home_err or "Invalid HERMES_HOME."}, 1)
    lock_py = _resolve_lock_python(args.python)
    if not lock_py:
        return _emit({"ok": False, "error": "Lock Python not found; pass --python."}, 1)
    argv = [str(lock_py), str(FRAMEWORK_DIR / "bot.py"), "lab", "stop", "--home", str(hermes_home)]
    if args.hermes:
        argv.extend(["--hermes", args.hermes])
    if args.dry_run:
        return _emit({"ok": True, "dry_run": True, "argv": argv, "evidence_preserved": True})
    owner_err = _check_project_ownership(hermes_home, fixture_fallback=False)
    if owner_err:
        return _emit({"ok": False, "error": owner_err, "evidence_preserved": True}, 1)
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

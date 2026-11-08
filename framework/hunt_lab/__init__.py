"""Native Hermes CLI controls. Importing/registering never starts a VM."""
from __future__ import annotations

import functools
import importlib
import json


# Only the analyst owns and operates the lab VM; every framework profile may
# register the read-only host tools, and native allowlists decide ownership.
LAB_OWNER = "framework-network-analyst"


def _failure(profile, state, reason):
    return {
        "profile": profile, "state": state, "reason": reason,
        "vm_name": None, "pid": None, "console_url": None,
        "console_websocket_url": None, "vnc_port": None, "qmp_port": None,
        "lab_url": None, "arkime_url": None, "kibana_url": None, "memory_mib": None, "accel": None,
    }


def _emit(result, code):
    print(json.dumps(result, ensure_ascii=True, allow_nan=False))
    return code


def _command(args):
    # Supported core helpers preserve -p identity after Hermes consumes that flag.
    # Imports are lazy so CLI registration needs no Desktop or QEMU dependencies.
    from hermes_cli.main import explicit_cli_profile
    from hermes_constants import get_hermes_home, profile_name_for_home

    requested = explicit_cli_profile()
    if requested != LAB_OWNER:
        return _emit(_failure(requested, "refused", "explicit_framework_profile_required"), 2)
    try:
        home = get_hermes_home()
        owner = profile_name_for_home(home)
    except (OSError, RuntimeError, ValueError):
        return _emit(_failure(requested, "refused", "profile_home_unavailable"), 2)
    if owner != requested:
        return _emit(_failure(requested, "refused", "profile_mismatch"), 2)
    state_dir = home / "hunt-lab-vm"
    operation = args.hunt_lab_operation
    try:
        runtime = importlib.import_module(f"{__name__}.runtime")
    except ImportError:
        return _emit(_failure(owner, "unavailable", "runtime_unavailable"), 4)
    if operation == "query":
        adapter = importlib.import_module(f"{__name__}.query_adapter")
        result = adapter.query_lab(
            {"case_id": args.case_id, "dataset": args.dataset, "q": args.q,
             "host": args.host, "limit": args.limit, "offset": args.offset},
            runtime=runtime, state_dir=state_dir, profile=owner,
        )
        return _emit(result, 0 if result["ok"] else 1)
    try:
        managed = importlib.import_module(f"{__name__}.managed")
        result = managed.invoke(operation, state_dir=state_dir, profile=owner)
    except Exception:
        # Do not echo environment, command lines, private paths, or exception data.
        return _emit(_failure(owner, "error", "runtime_failed"), 4)
    if not isinstance(result, dict) or result.get("profile") != owner:
        return _emit(_failure(owner, "error", "runtime_profile_mismatch"), 4)
    if (result.get("state") not in {"running", "stopped", "starting", "stopping", "preparing", "not_provisioned", "error"}
            or not (result.get("reason") is None or isinstance(result.get("reason"), str))):
        return _emit(_failure(owner, "error", "runtime_invalid_result"), 4)
    try:
        # Runtime owns detailed state/reason codes; never rewrite a failure as success.
        success = result["state"] != "error"
        return _emit(result, 0 if success else 1)
    except (ValueError, TypeError):
        return _emit(_failure(owner, "error", "runtime_invalid_result"), 4)


def _setup(parser):
    parser.add_argument("hunt_lab_operation", choices=("status", "prepare", "start", "stop", "query"))
    parser.add_argument("--case-id")
    parser.add_argument("--dataset", choices=("case", "events", "network"), default="case")
    parser.add_argument("--q", default="")
    parser.add_argument("--host", default="")
    parser.add_argument("--limit", type=int, default=50)
    parser.add_argument("--offset", type=int, default=0)


def register(ctx):
    ctx.register_cli_command(
        name="hunt-lab",
        help="Inspect, prepare, explicitly start, or shut down this profile's built-in hunting lab VM",
        setup_fn=_setup,
        handler_fn=_command,
        description="Explicit profile-owned lifecycle; model access is restricted to case-scoped evidence queries.",
    )
    from hermes_constants import get_hermes_home, profile_name_for_home
    adapter = importlib.import_module(f"{__name__}.query_adapter")
    home = get_hermes_home()
    owner = profile_name_for_home(home)
    if owner not in adapter.FRAMEWORK_PROFILES:
        return
    runtime = importlib.import_module(f"{__name__}.runtime")
    browser = importlib.import_module(f"{__name__}.lab_browser")
    state_dir = adapter.lab_state_dir(home, owner)

    def bind(call):
        def handler(arguments, **_kwargs):
            result = call(arguments, runtime=runtime, state_dir=state_dir, profile=owner)
            return json.dumps(result, ensure_ascii=True, allow_nan=False, separators=(",", ":"))
        return handler

    for name, schema in adapter.SCHEMAS.items():
        ctx.register_tool(name=name, toolset="hunt_lab", schema=schema, handler=bind(functools.partial(adapter.call, name)))
    ctx.register_tool(name="lab_browser", toolset="hunt_lab", schema=browser.SCHEMA, handler=bind(browser.call))

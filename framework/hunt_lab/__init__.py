"""Native Hermes CLI controls. Importing/registering never starts the lab."""
from __future__ import annotations

import functools
import importlib
import json


# Only the analyst owns and operates the lab. Each framework profile registers
# only the read-only host tools it owns (query_adapter.TOOL_OWNERSHIP), so Hermes
# refuses any other hunt_lab tool as unknown before it runs.
LAB_OWNER = "framework-network-analyst"


def _failure(profile, state, reason):
    return {
        "profile": profile, "origin": "container", "state": state, "reason": reason,
        "lab_url": None, "arkime_url": None, "kibana_url": None,
    }


def _emit(result, code):
    print(json.dumps(result, ensure_ascii=True, allow_nan=False))
    return code


def _command(args):
    # Supported core helpers preserve -p identity after Hermes consumes that flag.
    # Imports are lazy so CLI registration needs no Desktop or Docker dependencies.
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
    if operation == "query":
        adapter = importlib.import_module(f"{__name__}.query_adapter")
        result = adapter.query_lab(
            {"case_id": args.case_id, "dataset": args.dataset, "q": args.q,
             "host": args.host, "limit": args.limit, "offset": args.offset},
            state_dir=state_dir, profile=owner,
        )
        return _emit(result, 0 if result["ok"] else 1)
    try:
        stack = importlib.import_module(f"{__name__}.lab_stack")
        kwargs = {"cold": True} if getattr(args, "cold", False) else {}
        result = stack.invoke(operation, state_dir=state_dir, profile=owner, case_id=args.case_id,
                              evidence_dir=args.evidence_dir, wait=args.wait, **kwargs)
    except Exception:
        # Do not echo environment, command lines, private paths, or exception data.
        return _emit(_failure(owner, "error", "runtime_failed"), 4)
    if not isinstance(result, dict) or result.get("profile") != owner:
        return _emit(_failure(owner, "error", "runtime_profile_mismatch"), 4)
    if (result.get("state") not in {"running", "stopped", "starting", "error"}
            or not (result.get("reason") is None or isinstance(result.get("reason"), str))):
        return _emit(_failure(owner, "error", "runtime_invalid_result"), 4)
    try:
        # lab_stack owns detailed state/reason codes; never rewrite a failure as success.
        success = result["state"] != "error"
        return _emit(result, 0 if success else 1)
    except (ValueError, TypeError):
        return _emit(_failure(owner, "error", "runtime_invalid_result"), 4)


def _setup(parser):
    parser.add_argument("hunt_lab_operation", choices=("status", "start", "stop", "query"))
    parser.add_argument("--case-id")
    parser.add_argument("--dataset", choices=("case", "events", "network"), default="case")
    parser.add_argument("--q", default="")
    parser.add_argument("--host", default="")
    parser.add_argument("--limit", type=int, default=50)
    parser.add_argument("--offset", type=int, default=0)
    parser.add_argument("--evidence-dir",
                        help="start: the case folder to load into the container lab (default: the last one started, "
                             "else the bundled fixture)")
    parser.add_argument("--wait", type=int, default=0,
                        help="start: seconds to keep reading the container lab's status while it starts")
    parser.add_argument("--cold", action="store_true",
                        help="start: tear down any warm container stack first instead of reusing it")


def register(ctx):
    ctx.register_cli_command(
        name="hunt-lab",
        help="Inspect, explicitly start, or remove this profile's practice lab (host containers)",
        setup_fn=_setup,
        handler_fn=_command,
        description="Explicit profile-owned lifecycle; model access is restricted to case-scoped evidence queries.",
    )
    from hermes_constants import get_hermes_home, profile_name_for_home
    adapter = importlib.import_module(f"{__name__}.query_adapter")
    home = get_hermes_home()
    owner = profile_name_for_home(home)
    # Fail closed: a non-framework or unknown profile, or one that owns no hunt_lab tool, gets none.
    owned = set(adapter.TOOL_OWNERSHIP.get(owner, ())) if owner in adapter.FRAMEWORK_PROFILES else set()
    if not owned & (set(adapter.SCHEMAS) | {"lab_browser"}):
        return
    browser = importlib.import_module(f"{__name__}.lab_browser") if "lab_browser" in owned else None

    def bind(call):
        def handler(arguments, **_kwargs):
            from hermes_constants import get_hermes_home as _current_home, profile_name_for_home as _current_profile
            active_home = _current_home()
            active_owner = _current_profile(active_home)
            active_state_dir = adapter.lab_state_dir(active_home, active_owner)
            result = call(arguments, state_dir=active_state_dir, profile=active_owner)
            return json.dumps(result, ensure_ascii=True, allow_nan=False, separators=(",", ":"))
        return handler

    for name, schema in adapter.SCHEMAS.items():
        if name in owned:
            ctx.register_tool(name=name, toolset="hunt_lab", schema=schema,
                              handler=bind(functools.partial(adapter.call, name)))
    if browser is not None:
        ctx.register_tool(name="lab_browser", toolset="hunt_lab", schema=browser.SCHEMA, handler=bind(browser.call))

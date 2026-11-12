"""Explicit CLI for starting and observing synthetic-only Hermes workflows."""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from datetime import timedelta
from pathlib import Path

from temporalio.client import Client
from temporalio.common import WorkflowIDReusePolicy

from .contracts import (DATA_ORIGINS, HermesStep, WorkflowDecision, WorkflowRequest, valid_decider,
                        validate_loopback_address)
from .workflows import HermesWorkflow
from .hunt import supplied_evidence_hunt

DEFAULT_ADDRESS = "127.0.0.1:7233"
DEFAULT_TASK_QUEUE = "hermes-temporal"


def _strict_json(text: str) -> object:
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    def reject_constant(_value):
        raise ValueError("non-finite JSON number")

    return json.loads(text, object_pairs_hook=pairs, parse_constant=reject_constant)


def _strict_input(path: str) -> object:
    return _strict_json(Path(path).read_text(encoding="utf-8"))

def _practice_deadline_seconds(request) -> int:
    """Bound each round by every possible human wait plus every activity schedule window.

    A structured step may run twice (one handoff-correction retry), each run behind its own
    execute wait; one reconciliation and one review wait follow the last run."""
    approval = request.hunt.approval_timeout_seconds
    per_round = sum(
        (2 if step.hunt_context is not None else 1) * (approval + step.timeout_seconds + 140) + 2 * approval
        for step in request.hunt.steps
    )
    return request.rounds * per_round


class _Refusal(ValueError):
    """A refusal whose message names only fixed rules and labels, so the CLI shows it in full."""


async def _lab_input(args: argparse.Namespace) -> None:
    from .lab_input import LabInputError, collect_lab_input, collect_tool_input

    if args.data_origin is not None and not args.tool_driven:
        raise _Refusal("--data-origin applies only to --tool-driven")
    if args.case_id is not None and not args.tool_driven:
        raise _Refusal("--case-id applies only to --tool-driven")
    try:
        raw = (collect_tool_input(args.state_dir, data_origin=args.data_origin, case_id=args.case_id)
               if args.tool_driven else collect_lab_input(args.state_dir))
    except LabInputError as exc:
        # Its messages are fixed texts, the case's validated origin and the lab's fixed codes.
        raise _Refusal(str(exc)) from None
    text = json.dumps(raw, ensure_ascii=False, allow_nan=False, indent=2) + "\n"
    with Path(args.output).open("x", encoding="utf-8", newline="\n") as output:
        output.write(text)
    print(json.dumps({"output": args.output, "status": "exported"}, ensure_ascii=False))


async def _practice(args: argparse.Namespace) -> None:
    from .practice import PracticeRequest, PracticeWorkflow

    if not args.workflow_id or len(args.workflow_id.encode("utf-8")) > 480:
        raise ValueError("workflow_id must be nonempty and no more than 480 UTF-8 bytes")
    hunt = supplied_evidence_hunt(_strict_input(args.input))
    request = PracticeRequest(hunt=hunt, rounds=args.rounds)
    client = await _connect(args)
    await client.start_workflow(
        PracticeWorkflow.run, request, id=args.workflow_id, task_queue=args.task_queue,
        id_reuse_policy=WorkflowIDReusePolicy.REJECT_DUPLICATE,
        execution_timeout=timedelta(seconds=_practice_deadline_seconds(request)),
    )
    print(json.dumps({"workflow_id": args.workflow_id, "status": "started"}, ensure_ascii=False))


async def _practice_status(args: argparse.Namespace) -> None:
    from .practice import PracticeWorkflow

    client = await _connect(args)
    handle = client.get_workflow_handle(args.workflow_id)
    state = await handle.query(PracticeWorkflow.status)
    execution = await handle.describe()
    observed = {**vars(state), "workflow_id": args.workflow_id,
                "temporal_status": execution.status.name}
    print(json.dumps(observed, ensure_ascii=False, sort_keys=True))


async def _practice_stop(args: argparse.Namespace) -> None:
    from .practice import PracticeWorkflow

    client = await _connect(args)
    handle = client.get_workflow_handle(args.workflow_id)
    await handle.signal(PracticeWorkflow.stop)
    print(json.dumps({"workflow_id": args.workflow_id, "signal_sent": True}, ensure_ascii=False))


def _request_from_file(path: str) -> WorkflowRequest:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or set(raw) - {"steps", "approval_timeout_seconds", "synthetic_only", "parallel"}:
        raise ValueError("input must be a JSON object with only workflow request fields")
    steps_raw = raw.get("steps")
    if not isinstance(steps_raw, list):
        raise ValueError("steps must be a JSON list")
    steps = []
    for item in steps_raw:
        if not isinstance(item, dict) or set(item) - {
            "step_id", "prompt", "profile", "timeout_seconds", "depends_on", "hunt_context", "optional", "focus"
        }:
            raise ValueError(
                "each step must contain only step_id, prompt, profile, timeout_seconds, depends_on, "
                "hunt_context, optional, focus"
            )
        if "depends_on" in item:
            if not isinstance(item["depends_on"], list):
                raise ValueError("depends_on must be a JSON list")
            item = {**item, "depends_on": tuple(item["depends_on"])}
        if "focus" in item:
            if not isinstance(item["focus"], list):
                raise ValueError("focus must be a JSON list [step_id, claim index]")
            item = {**item, "focus": tuple(item["focus"])}
        steps.append(HermesStep(**item))
    return WorkflowRequest(
        steps=steps,
        approval_timeout_seconds=raw.get("approval_timeout_seconds", 3600),
        synthetic_only=raw.get("synthetic_only", True),
        parallel=raw.get("parallel", False),
    )


async def _connect(args: argparse.Namespace) -> Client:
    return await Client.connect(validate_loopback_address(args.address))


async def _start(args: argparse.Namespace) -> None:
    if not args.workflow_id or len(args.workflow_id.encode("utf-8")) > 500:
        raise ValueError("workflow_id must be nonempty and no more than 500 UTF-8 bytes")
    request = supplied_evidence_hunt(json.loads(Path(args.input).read_text(encoding="utf-8"))) if args.command == "hunt" else _request_from_file(args.input)
    client = await _connect(args)
    await client.start_workflow(
        HermesWorkflow.run,
        request,
        id=args.workflow_id,
        task_queue=args.task_queue,
        id_reuse_policy=WorkflowIDReusePolicy.REJECT_DUPLICATE,
    )
    print(json.dumps({"workflow_id": args.workflow_id, "status": "started"}, ensure_ascii=False))


async def _status(args: argparse.Namespace) -> None:
    client = await _connect(args)
    handle = client.get_workflow_handle(args.workflow_id)
    state = await handle.query(HermesWorkflow.status)
    execution = await handle.describe()
    observed = {**vars(state), "temporal_status": execution.status.name}
    print(json.dumps(observed, default=lambda value: value.__dict__, ensure_ascii=False, sort_keys=True))


_DECIDER_REFUSAL = ("--decided-by needs a name of 1 to 200 printable characters; --via and --slack-user need "
                    "--decided-by; --via slack needs a --slack-user Slack user ID (U or W, then 2 to 20 capital "
                    "letters or digits), and no other channel takes one")


def _decider(args: argparse.Namespace) -> tuple[str | None, str]:
    """(normalized name, channel) of a decision's identity; the name is None when the identity is refused."""
    decided_by = " ".join((args.decided_by or "").split())
    via = args.via or ("cli" if decided_by else "")
    if (args.decided_by is not None and not decided_by) or not valid_decider(decided_by, via, args.slack_user):
        return None, via
    return decided_by, via


async def _decision(args: argparse.Namespace) -> None:
    if args.phase == "reconcile" and not args.evidence_note.strip():
        raise ValueError("reconciliation requires a nonempty --evidence-note")
    decided_by, via = _decider(args)
    if decided_by is None:
        raise ValueError(_DECIDER_REFUSAL)
    item = WorkflowDecision(args.step_id, args.phase, args.choice, args.decision_id, args.evidence_note,
                            decided_by, via, args.slack_user)
    client = await _connect(args)
    handle = client.get_workflow_handle(args.workflow_id)
    await handle.signal(HermesWorkflow.decision, item)
    print(json.dumps({"workflow_id": args.workflow_id, "decision_id": args.decision_id, "signal_sent": True}))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Synthetic-only Temporal client for native Hermes execution")
    parser.add_argument("--address", default=DEFAULT_ADDRESS, type=validate_loopback_address,
                        help="loopback Temporal server host:port")
    parser.add_argument("--task-queue", default=DEFAULT_TASK_QUEUE)
    commands = parser.add_subparsers(dest="command", required=True)
    start = commands.add_parser("start", help="start a standalone-step workflow from an explicit synthetic JSON file")
    start.add_argument("workflow_id", help="stable, explicit workflow ID; duplicate reuse is rejected")
    start.add_argument("--input", required=True)
    start.set_defaults(handler=_start)
    hunt = commands.add_parser("hunt", help="start a strictly supplied-evidence synthetic hunt; evidence is inline and never fetched")
    hunt.add_argument("workflow_id", help="stable, explicit workflow ID; duplicate reuse is rejected")
    hunt.add_argument("--input", required=True, help="JSON file with scope and inline evidence source IDs, locators, and content")
    hunt.set_defaults(handler=_start)
    status = commands.add_parser("status", help="query fixed workflow status metadata")
    status.add_argument("workflow_id")
    status.set_defaults(handler=_status)
    decide = commands.add_parser("decision", help="signal an execute/review/reconcile decision")
    decide.add_argument("workflow_id")
    decide.add_argument("--step-id", required=True,
                        help="the gated step; in a parallel workflow the open wave's gate ID wave-<n>, "
                             "or the step awaiting reconciliation")
    decide.add_argument("--phase", choices=("execute", "review", "reconcile"), required=True)
    decide.add_argument("--choice", choices=("approve", "deny", "accept", "abort"), required=True)
    decide.add_argument("--decision-id", required=True)
    decide.add_argument("--evidence-note", default="")
    decide.add_argument("--decided-by",
                        help="who decides, recorded with the gate in the workflow status")
    decide.add_argument("--via", choices=("cli", "slack", "automated"),
                        help="channel of the decision, recorded with --decided-by (default: cli)")
    decide.add_argument("--slack-user", default="", help="with --via slack: the deciding Slack user ID")
    decide.set_defaults(handler=_decision)
    practice = commands.add_parser("practice", help="start finite serial rounds of a supplied-evidence hunt")
    practice.add_argument("workflow_id", help="stable parent workflow ID; duplicate reuse is rejected")
    practice.add_argument("--input", required=True, help="strict JSON supplied-evidence hunt")
    practice.add_argument("--rounds", type=int, choices=range(1, 11), default=3)
    practice.set_defaults(handler=_practice)
    practice_status = commands.add_parser("practice-status", help="query practice parent and current child status")
    practice_status.add_argument("workflow_id")
    practice_status.set_defaults(handler=_practice_status)
    practice_stop = commands.add_parser(
        "practice-stop",
        help="signal the parent to stop; does not promise an active child has terminated",
    )
    practice_stop.add_argument("workflow_id")
    practice_stop.set_defaults(handler=_practice_stop)
    lab_input = commands.add_parser("lab-input", help="export complete bounded synthetic lab summaries; no Temporal connection")
    lab_input.add_argument("--state-dir", required=True)
    lab_input.add_argument("--output", required=True, help="new path; existing files are never overwritten")
    lab_input.add_argument("--tool-driven", action="store_true",
                           help="export a tool-driven hunt for the loaded case: reads /case only; stages query with their own tools")
    lab_input.add_argument("--data-origin", choices=tuple(DATA_ORIGINS),
                           help="with --tool-driven: approve exporting a case whose case.json declares this data_origin "
                                "(public-dataset: a public research dataset; work-export: the operator's unclassified work "
                                "log export; work-connected: a window of the operator's work Elastic served live by "
                                "hunt_lab.connected); it must equal the case's origin, and such a case is refused without it")
    lab_input.add_argument("--case-id",
                           help="with --tool-driven: export this case from whichever lab serves it, a container lab "
                                "or a connected service (default: the one lab serving a case; two serving one is "
                                "refused as ambiguous)")
    lab_input.set_defaults(handler=_lab_input)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    if args.handler is _decision and _decider(args)[0] is None:
        # The refusal names only fixed rules, so it is shown in full, before any connection.
        parser.error(_DECIDER_REFUSAL)
    try:
        asyncio.run(args.handler(args))
    except _Refusal as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        # Avoid emitting SDK/server exception text, which may contain deployment details.
        print(f"error: operation failed ({type(exc).__name__})", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Read-only live board for a supplied-evidence practice hunt: the Hunt Live page.

The board renders only the supplied lab input and the actual Temporal status of a
practice parent and its current round. It never signals, approves, starts, or stops
a workflow; it only issues the same status queries as ``cli practice-status``/``status``,
plus a read of the round's own history for the real start and end time of each stage.
For a ``tool_driven`` input it also polls the loopback lab's read-only ``/activity`` ring
and looks up the events the bots cite by ``event.id``; it never runs any other lab query.
With ``--hermes-home`` it also shows the two browser owners' lab browsers live, through the
watch-only screencast client in ``hunt_lab.screencast`` (frames stay in memory only), and
reads each owner's newest ``lab_browser`` audit line for the caption under its frame.
"""
from __future__ import annotations

import argparse
import asyncio
import importlib.util
import json
import re
import sys
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Iterable
from urllib import parse

from hunt_lab import screencast

from .contracts import USAGE_KEYS, validate_loopback_address
from .hunt import supplied_evidence_hunt
from .lab_input import LabInputError, lab_endpoints, lab_get, loopback_base
from .workflows import _unwrap_single_fence

BIND_HOST = "127.0.0.1"
DEFAULT_PORT = 8790
POLL_INTERVAL_SECONDS = 2.0
_QUERY_TIMEOUT_SECONDS = 10.0
_RAW_EXCERPT_CHARS = 4000

ROLE_TITLES = {
    "framework-coordinator": "Incident Response Lead",
    "framework-researcher": "Threat Hunter",
    "framework-network-analyst": "Network Analyst",
    "framework-librarian": "Threat Intelligence Analyst",
    "framework-builder": "Detection Engineer",
    "framework-reviewer": "Purple Team Analyst",
}
MONOGRAMS = {
    "framework-coordinator": "IR",
    "framework-researcher": "TH",
    "framework-network-analyst": "NA",
    "framework-librarian": "TI",
    "framework-builder": "DE",
    "framework-reviewer": "PT",
}

# Child stages that leave a step open for a human or the worker; every other
# non-initial stage written by HermesWorkflow is terminal.
_OPEN_STAGES = {
    "awaiting_execution_approval": "awaiting_approval",
    "executing": "working",
    "awaiting_review": "awaiting_review",
    "needs_reconciliation": "awaiting_review",
}
_CITED_STATES = {"done", "awaiting_review"}
_EVENT_ID = re.compile(r"evt-\d{4,}")

# Tool-driven lab observation. Lookups use the guest's /es/search (q <= 500 characters);
# the board identifies itself so the guest keeps its own requests out of /activity.
BOARD_LAB_PROFILE = "hunt-board"
_LAB_TIMEOUT_SECONDS = 4.0
_ACTIVITY_KEEP = 2000
_ACTIVITY_PAGE = 100
_ACTIVITY_PAGES_PER_POLL = 5
_ACTIVITY_SHOWN_PER_LANE = 60
_LOOKUP_QUERY_CHARS = 480
_LOOKUP_BATCHES_PER_POLL = 3
_LOOKUP_MAX_EVENTS = 3000
_LOOKUP_FIELDS = ",".join((
    "event.id", "@timestamp", "host.name", "host.ip", "event.category", "event.type", "event.action", "event.code",
    "user.name", "process.entity_id", "process.pid", "process.name", "dns.question.name", "source.ip", "source.port",
    "destination.ip", "destination.port", "network.transport", "url.domain", "tls.server_name", "message",
    "labels.task_name", "labels.interval_seconds",
))


# ---------------------------------------------------------------------------
# Pure derivation


def _get(value: Any, *path: str | int) -> Any:
    for key in path:
        if isinstance(key, int):
            if not isinstance(value, list) or not -len(value) <= key < len(value):
                return None
            value = value[key]
        else:
            if not isinstance(value, dict):
                return None
            value = value.get(key)
    return value


def _text(value: Any) -> str | None:
    return value if isinstance(value, str) and value.strip() else None


def _texts(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value] if value.strip() else []
    return [item for item in value if isinstance(item, str)] if isinstance(value, list) else []


def _epoch_ms(timestamp: Any) -> int | None:
    if not isinstance(timestamp, str):
        return None
    try:
        parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return int(parsed.timestamp() * 1000)


def _cited_ids(*texts: str) -> list[str]:
    return sorted({match for text in texts for match in _EVENT_ID.findall(text)})


def _event_summary(row: dict, category: str, event_type: str | None, process: dict | None,
                   domain: str | None) -> str:
    message = _text(row.get("message"))
    if message:
        return message
    actor = f" by {process['name']}" if process and process.get("name") else ""
    if domain:
        answers = [item.get("data") for item in _get(row, "dns", "answers") or []
                   if isinstance(item, dict) and isinstance(item.get("data"), str)]
        answered = f" -> {', '.join(answers)}" if answers else ""
        return f"DNS query {domain}{answered}{actor}"
    if category == "process" and event_type == "start" and process:
        pid = f", pid {process['pid']}" if process.get("pid") is not None else ""
        return f"process start {process.get('name') or process.get('entity_id')}{pid}"
    source, destination = _get(row, "source", "ip"), _get(row, "destination", "ip")
    if source or destination:
        transport = _text(_get(row, "network", "transport")) or "network"
        return (f"{transport} connection {source}:{_get(row, 'source', 'port')} -> "
                f"{destination}:{_get(row, 'destination', 'port')}{actor}")
    code = row.get("event", {}).get("code") if isinstance(row.get("event"), dict) else None
    return " ".join(part for part in (category, event_type, f"code {code}" if code else None) if part)


def _first(value: Any) -> Any:
    """ECS allows a scalar or an array; lab search hits keep whichever the document had."""
    return _get(value, 0) if isinstance(value, list) else value


def _nest(hit: dict) -> dict:
    """Expand a lab search hit's flat dotted keys (``{"event.id": ..}``) into ECS objects."""
    row: dict[str, Any] = {}
    for key, value in hit.items():
        if not isinstance(key, str):
            continue
        *parents, leaf = key.split(".")
        target = row
        for name in parents:
            child = target.get(name)
            if not isinstance(child, dict):
                child = target[name] = {}
            target = child
        target[leaf] = value
    return row


def _event(row: Any, source_id: Any) -> dict | None:
    event_id = _text(_get(row, "event", "id"))
    if event_id is None:
        return None
    category = _text(_first(_get(row, "event", "category"))) or "unknown"
    event_type = _text(_first(_get(row, "event", "type")))
    process = None
    if isinstance(row.get("process"), dict) and _text(_get(row, "process", "entity_id")):
        process = {"entity_id": row["process"]["entity_id"], "name": _text(_get(row, "process", "name")),
                   "pid": _get(row, "process", "pid")}
    domain = _text(_get(row, "dns", "question", "name"))
    task = None
    if _text(_get(row, "labels", "task_name")):
        task = {"name": row["labels"]["task_name"], "interval_seconds": _get(row, "labels", "interval_seconds")}
    timestamp = row.get("@timestamp") if isinstance(row.get("@timestamp"), str) else None
    return {
        "id": event_id,
        "timestamp": timestamp,
        "t_ms": _epoch_ms(timestamp),
        "host": _text(_get(row, "host", "name")),
        "host_ip": _text(_first(_get(row, "host", "ip"))),
        "category": category,
        "type": event_type,
        "code": _get(row, "event", "code"),
        "process": process,
        "domain": domain,
        "task": task,
        "message": _text(row.get("message")),
        "summary": _event_summary(row, category, event_type, process, domain),
        "source_id": source_id if isinstance(source_id, str) else None,
    }


def _lab_evidence(raw: dict) -> tuple[dict, list[dict], list[dict], list[str]]:
    case: dict[str, Any] = {"case_id": None, "question": None, "start": None, "end": None}
    events: list[dict] = []
    sessions: list[dict] = []
    warnings: list[str] = []
    items = raw.get("evidence")
    for item in items if isinstance(items, list) else []:
        locator, content = _get(item, "locator"), _get(item, "content")
        if not isinstance(locator, str) or not isinstance(content, str):
            continue
        kind = locator.partition(":")[2]
        if not kind.startswith("summary/"):
            continue
        try:
            body = json.loads(content.partition("\n")[2])
        except (ValueError, RecursionError):
            warnings.append(f"{locator}: content is not a header line followed by JSON")
            continue
        if kind == "summary/case":
            info = _get(body, "case")
            case.update(case_id=_text(_get(info, "case_id")), question=_text(_get(info, "question")),
                        start=_text(_get(info, "time_range_utc", "start_inclusive")),
                        end=_text(_get(info, "time_range_utc", "end_exclusive")))
        elif kind.startswith("summary/events/") and isinstance(body, list):
            events.extend(event for event in (_event(row, item["source_id"]) for row in body
                                              if isinstance(row, dict)) if event)
        elif kind.startswith("summary/network/") and isinstance(body, list):
            for row in body:
                if isinstance(row, dict):
                    sessions.append({
                        "source_ip": _text(_get(row, "source", "ip")),
                        "source_port": _get(row, "source", "port"),
                        "destination_ip": _text(_get(row, "destination", "ip")),
                        "destination_port": _get(row, "destination", "port"),
                        "domain": _text(_get(row, "dns", 0, "host", 0)),
                        "first_ms": row.get("firstPacket") if isinstance(row.get("firstPacket"), int) else None,
                    })
    events.sort(key=lambda event: (event["t_ms"] is None, event["t_ms"] or 0, event["id"]))
    return case, events, sessions, warnings


def _entity_graph(events: list[dict], sessions: list[dict]) -> dict:
    nodes: dict[str, dict] = {}
    edges: dict[tuple[str, str, str], dict] = {}
    host_order: list[str] = []

    def node(node_id: str, kind: str, label: str, layer: int, host: str | None = None) -> dict:
        if node_id not in nodes:
            nodes[node_id] = {"id": node_id, "kind": kind, "label": label, "layer": layer, "host": host,
                              "detail": {}, "event_ids": [], "sessions": 0}
        return nodes[node_id]

    def involve(item: dict, event_id: str) -> None:
        if event_id not in item["event_ids"]:
            item["event_ids"].append(event_id)

    def link(source: str, target: str, kind: str, event_id: str) -> None:
        edge = edges.setdefault((source, target, kind),
                                {"source": source, "target": target, "kind": kind, "event_ids": []})
        if event_id not in edge["event_ids"]:
            edge["event_ids"].append(event_id)

    processes: dict[tuple[str, str], str] = {}
    for event in events:
        host = event["host"]
        if host is None:
            continue
        host_node = node(f"host:{host}", "host", host, 0, host)
        if host not in host_order:
            host_order.append(host)
        if event["host_ip"]:
            host_node["detail"].setdefault("ip", event["host_ip"])
        involve(host_node, event["id"])
        process = event["process"]
        if process and event["category"] == "process" and event["type"] == "start":
            node_id = f"process:{host}:{process['entity_id']}"
            item = node(node_id, "process", process.get("name") or process["entity_id"], 1, host)
            item["detail"].update(entity_id=process["entity_id"], pid=process.get("pid"))
            processes[(host, process["entity_id"])] = node_id
            link(host_node["id"], node_id, "started", event["id"])
        if event["task"]:
            task = event["task"]
            item = node(f"task:{host}:{task['name']}", "task", task["name"], 1, host)
            item["detail"]["interval_seconds"] = task["interval_seconds"]
            involve(item, event["id"])
            link(host_node["id"], item["id"], "configured", event["id"])
    for event in events:
        host, process = event["host"], event["process"]
        parent = processes.get((host, process["entity_id"])) if host and process else None
        if parent:
            involve(nodes[parent], event["id"])
        if event["domain"]:
            domain = node(f"domain:{event['domain']}", "domain", event["domain"], 2)
            involve(domain, event["id"])
            source = parent or (f"host:{host}" if host else None)
            if source:
                link(source, domain["id"], "queried", event["id"])
    domains = {item["label"]: item for item in nodes.values() if item["kind"] == "domain"}
    for event in events:
        # A task's stated DNS name is only linked when it exactly names an observed query domain.
        if event["task"] and event["message"] and event["host"]:
            task_id = f"task:{event['host']}:{event['task']['name']}"
            for name, domain in sorted(domains.items()):
                if name in event["message"]:
                    domain["detail"].setdefault("stated_by_tasks", []).append(event["task"]["name"])
                    nodes[task_id]["detail"]["stated_domain"] = name
                    link(task_id, domain["id"], "stated", event["id"])
    ip_hosts = {item["detail"].get("ip"): item for item in nodes.values() if item["kind"] == "host"}
    for session in sessions:
        if session["domain"] in domains:
            domains[session["domain"]]["sessions"] += 1
        if session["source_ip"] in ip_hosts:
            ip_hosts[session["source_ip"]]["sessions"] += 1

    rows: dict[str, float] = {}
    layered: list[list[dict]] = [[], [], []]
    for host in host_order:
        layered[0].append(nodes[f"host:{host}"])
    for host in host_order:
        layered[1].extend(item for item in nodes.values() if item["layer"] == 1 and item["host"] == host
                          and item["kind"] == "process")
        layered[1].extend(item for item in nodes.values() if item["layer"] == 1 and item["host"] == host
                          and item["kind"] == "task")
    for layer in layered[:2]:
        for index, item in enumerate(layer):
            rows[item["id"]] = index / max(len(layer) - 1, 1)

    def barycenter(item: dict) -> float:
        parents = [rows[edge["source"]] for edge in edges.values()
                   if edge["target"] == item["id"] and edge["source"] in rows]
        return sum(parents) / len(parents) if parents else 1.0

    layered[2] = sorted((item for item in nodes.values() if item["kind"] == "domain"),
                        key=lambda item: (barycenter(item), item["label"]))
    ordered = []
    for layer in layered:
        for index, item in enumerate(layer):
            item["row"] = index
            ordered.append(item)
    return {"nodes": ordered, "edges": list(edges.values()),
            "layer_sizes": [len(layer) for layer in layered]}


def parse_handoff(output: Any) -> tuple[dict | None, str | None]:
    """Tolerantly parse one result output; never raises."""
    if not isinstance(output, str) or not output.strip():
        return None, "output is empty"
    try:
        value = json.loads(_unwrap_single_fence(output, allow_leading_prose=True))
    except (ValueError, RecursionError):
        return None, "output is not a single JSON handoff"
    if not isinstance(value, dict):
        return None, "output JSON is not an object"
    claims = []
    for claim in value.get("claims") if isinstance(value.get("claims"), list) else []:
        if not isinstance(claim, dict):
            continue
        statement = claim.get("statement") if isinstance(claim.get("statement"), str) else ""
        claims.append({
            "claim_id": _text(claim.get("claim_id")),
            "kind": _text(claim.get("kind")),
            "statement": statement,
            "evidence_ids": _texts(claim.get("evidence_ids")),
            "entity_ids": _texts(claim.get("entity_ids")),
            "contradicts": _texts(claim.get("contradicts")),
            "cited_events": _cited_ids(statement),
        })
    reviews = []
    for review in value.get("reviews") if isinstance(value.get("reviews"), list) else []:
        if not isinstance(review, dict):
            continue
        rationale = review.get("rationale") if isinstance(review.get("rationale"), str) else ""
        reviews.append({
            "review_id": _text(review.get("review_id")),
            "claim_ids": _texts(review.get("claim_ids")),
            "disposition": _text(review.get("disposition")),
            "rationale": rationale,
            "evidence_ids": _texts(review.get("evidence_ids")),
            "cited_events": _cited_ids(rationale),
        })
    return {
        "step_id": _text(value.get("step_id")),
        "profile": _text(value.get("profile")),
        "case_id": _text(value.get("case_id")),
        "claims": claims,
        "reviews": reviews,
        "disposition": _text(value.get("disposition")),
        "limitations": _texts(value.get("limitations")),
        "requested_decisions": _texts(value.get("requested_decisions")),
    }, None


def _step_states(count: int, step_ids: list[str], child: dict | None) -> list[tuple[str, str | None]]:
    states: list[tuple[str, str | None]] = [("pending", None)] * count
    if not isinstance(child, dict) or count == 0:
        return states
    stage = child.get("stage")
    results = child.get("results") if isinstance(child.get("results"), list) else []
    temporal = child.get("temporal_status")
    if stage in (None, "initializing"):
        return states
    if stage == "completed":
        return [("done", None) if index < len(results) else ("pending", None) for index in range(count)]
    current = (step_ids.index(child["step_id"]) if child.get("step_id") in step_ids
               else min(len(results), count - 1))
    states[:current] = [("done", None)] * current
    open_state = _OPEN_STAGES.get(stage)
    if open_state and temporal in (None, "RUNNING"):
        states[current] = (open_state, stage if stage == "needs_reconciliation" else None)
    else:
        states[current] = ("stopped", stage if open_state is None else f"{stage} (Temporal {temporal})")
        states[current + 1:] = [("not_reached", None)] * (count - current - 1)
    return states


def _results(child: dict | None) -> list:
    return child["results"] if isinstance(child, dict) and isinstance(child.get("results"), list) else []


def _usage(result: Any) -> dict | None:
    """A result's token counts and wall time, when the worker recorded them."""
    usage = _get(result, "usage")
    if not isinstance(usage, dict) or any(type(usage.get(key)) is not int for key in USAGE_KEYS):
        return None
    return {key: usage[key] for key in USAGE_KEYS}


def _wave_steps(child: dict | None) -> dict[str, dict]:
    """A parallel round's own report of every step, by step ID; empty for a serial round."""
    steps = child.get("steps") if isinstance(child, dict) else None
    return {item["step_id"]: item for item in steps if isinstance(item, dict)
            and isinstance(item.get("step_id"), str)} if isinstance(steps, list) else {}


def _step_track(step_ids: list[str], child: dict | None) -> list[tuple[str, str, int, dict | None]]:
    """Per step in request order: board state, reason, wave and latest result.

    A serial round has one open step, found from its ``step_id``, and positional results. A parallel
    round reports each step itself: several can be open at once and its ``step_id`` is a wave gate,
    so each result is matched by execution ID."""
    results, reported = _results(child), _wave_steps(child)
    if not reported:
        states = _step_states(len(step_ids), step_ids, child)
        return [(state, reason or "", index + 1,
                 results[index] if index < len(results) and isinstance(results[index], dict) else None)
                for index, (state, reason) in enumerate(states)]
    by_execution = {result["execution_id"]: result for result in results
                    if isinstance(result, dict) and isinstance(result.get("execution_id"), str)}
    temporal = child.get("temporal_status")
    live = temporal in (None, "RUNNING")
    halted = not live or any(item.get("state") == "stopped" for item in reported.values())
    track = []
    for index, step_id in enumerate(step_ids):
        item = reported.get(step_id, {})
        state, reason = item.get("state"), ""
        if state in _OPEN_STATES and not live:
            state, reason = "stopped", f"{state} (Temporal {temporal})"
        elif state in ("dropped", "stopped"):
            reason = item["reason"] if isinstance(item.get("reason"), str) else ""
        elif state not in _OPEN_STATES and state != "done":
            state = "not_reached" if halted else "pending"
        execution_id = item.get("execution_id")
        track.append((state, reason, item["wave"] if type(item.get("wave")) is int else index + 1,
                      by_execution.get(execution_id) if isinstance(execution_id, str) else None))
    return track


def _run_summary(parent: dict | None, child: dict | None, step_views: list[dict]) -> dict:
    parent_keys = ("workflow_id", "stage", "temporal_status", "round_index", "rounds",
                   "completed_rounds", "last_result", "child_workflow_id")
    child_keys = ("stage", "step_id", "execution_id", "temporal_status")
    usages = [usage for usage in map(_usage, _results(child)) if usage]
    return {
        "parent": {key: parent.get(key) for key in parent_keys} if isinstance(parent, dict) else None,
        "child": {key: child.get(key) for key in child_keys} if isinstance(child, dict) else None,
        "usage_total": {key: sum(usage[key] for usage in usages) for key in USAGE_KEYS} if usages else None,
        "dropped": [{"step_id": view["step_id"], "reason": view["reason"]} for view in step_views
                    if view["state"] == "dropped"],
    }


_OPEN_STATES = set(_OPEN_STAGES.values())
_ACTIVITY_CLOSED = ("activity_task_completed_event_attributes", "activity_task_failed_event_attributes",
                    "activity_task_timed_out_event_attributes", "activity_task_canceled_event_attributes")


def activity_spans(events: Iterable[Any]) -> list[dict]:
    """Each activity in a round's Temporal history: execution ID, scheduled and closed time (epoch ms).

    ``events`` are ``HistoryEvent`` messages. The execution ID is read from the activity input
    (the JSON ``ExecutionRequest``); an activity that has not closed yet has ``closed_ms`` None."""
    spans: dict[int, dict] = {}
    for event in events:
        kind = event.WhichOneof("attributes")
        if kind == "activity_task_scheduled_event_attributes":
            payloads = event.activity_task_scheduled_event_attributes.input.payloads
            try:
                execution_id = json.loads(payloads[0].data).get("execution_id") if payloads else None
            except (ValueError, AttributeError, RecursionError):
                execution_id = None
            spans[event.event_id] = {"execution_id": execution_id if isinstance(execution_id, str) else None,
                                     "scheduled_ms": event.event_time.ToMilliseconds(), "closed_ms": None}
        elif kind in _ACTIVITY_CLOSED:
            span = spans.get(getattr(event, kind).scheduled_event_id)
            if span is not None:
                span["closed_ms"] = event.event_time.ToMilliseconds()
    return list(spans.values())


def _stage_timings(round_id: Any, count: int, spans: Any) -> list[dict]:
    """Per step: its first activity's scheduled time, its latest activity's close time, and attempts.

    Execution IDs are ``<round workflow ID>:<step index>``, with ``:retry`` for the one handoff retry."""
    timings = [{"started_ms": None, "ended_ms": None, "duration_ms": None, "attempts": 0} for _ in range(count)]
    if not isinstance(round_id, str) or not isinstance(spans, list):
        return timings
    prefix = round_id + ":"
    ordered = sorted((span for span in spans if isinstance(span, dict) and type(span.get("scheduled_ms")) is int),
                     key=lambda span: span["scheduled_ms"])
    for span in ordered:
        execution_id = span.get("execution_id")
        if not isinstance(execution_id, str) or not execution_id.startswith(prefix):
            continue
        index, _, rest = execution_id[len(prefix):].partition(":")
        if not (index.isascii() and index.isdigit()) or int(index) >= count or rest not in ("", "retry"):
            continue
        timing = timings[int(index)]
        if timing["started_ms"] is None:
            timing["started_ms"] = span["scheduled_ms"]
        timing["attempts"] += 1
        timing["ended_ms"] = span["closed_ms"] if type(span.get("closed_ms")) is int else None
    for timing in timings:
        if timing["started_ms"] is not None and timing["ended_ms"] is not None:
            timing["duration_ms"] = timing["ended_ms"] - timing["started_ms"]
    return timings


def _running_executions(child: dict) -> set:
    """Execution IDs the round reports as running now: one for a serial round, several in a parallel wave."""
    reported = _wave_steps(child)
    if reported:
        return {item.get("execution_id") for item in reported.values() if item.get("state") == "working"}
    return {child.get("execution_id")} if child.get("stage") == "executing" else set()


def _round_clock(child: dict | None, timings: list[dict]) -> dict:
    """The round's real start (Temporal, else its first stage) and end (Temporal close time)."""
    child = child if isinstance(child, dict) else {}
    started, source = _epoch_ms(child.get("start_time")), "temporal"
    if started is None:
        firsts = [timing["started_ms"] for timing in timings if timing["started_ms"] is not None]
        started, source = (min(firsts), "first_stage") if firsts else (None, None)
    return {"started_ms": started, "ended_ms": _epoch_ms(child.get("close_time")) if started is not None else None,
            "source": source}


def _wall_time(step_views: list[dict]) -> dict:
    """Wall time the steps cover, each moment counted once however many steps of a wave overlap it.

    A step covers its first activity's start to its last one's end, or to now while it is open. The
    result is the finished part and when the still-open part began; the page adds the time since."""
    open_since = min((view["timing"]["started_ms"] for view in step_views
                      if view["state"] in _OPEN_STATES and view["timing"]["started_ms"] is not None), default=None)
    spans = sorted((view["timing"]["started_ms"], view["timing"]["ended_ms"]) for view in step_views
                   if view["state"] not in _OPEN_STATES and view["timing"]["duration_ms"] is not None)
    closed, covered = 0, None
    for started, ended in spans:
        started = started if covered is None else max(started, covered)
        ended = ended if open_since is None else min(ended, open_since)
        if ended > started:
            closed += ended - started
            covered = ended
    return {"closed_ms": closed if spans else None, "open_since_ms": open_since}


_AUDIT_TAIL_BYTES = 512 * 1024
_BROWSER_VERBS = {"click": "clicked", "scroll": "scrolled", "press": "pressed", "read": "read a result",
                  "snapshot": "read the page"}


def _browser_action(entry: dict) -> dict:
    action = _text(entry.get("action")) or "unknown"
    query = entry.get("query") if action == "open" else entry.get("text") if action == "type" else None
    query = query if isinstance(query, str) and query.strip() else None
    if action == "open":
        verb = "typed" if query and entry.get("entered") == "typed" else "opened"
    else:
        verb = "typed" if action == "type" else _BROWSER_VERBS.get(action, action)
    detail = (_text(entry.get("key")) if action == "press"
              else _text(entry.get("direction")) if action == "scroll" else None)
    return {"t_ms": entry["t"], "action": action, "verb": verb, "query": query, "detail": detail,
            "submitted": action == "type" and entry.get("submit") is True, "page": _text(entry.get("page")),
            "ok": entry.get("ok") is True, "error": _text(entry.get("error"))}


def newest_browser_action(path: str | Path, profile: str, since_ms: int, case_id: str | None = None) -> dict | None:
    """The owner's newest ``lab_browser`` audit entry at or after ``since_ms`` (the round start), or None.

    Only the file's tail is read; the audit is append-only, so the scan stops at the first older entry."""
    try:
        with open(path, "rb") as handle:
            start = max(0, handle.seek(0, 2) - _AUDIT_TAIL_BYTES)
            handle.seek(start)
            lines = handle.read().split(b"\n")
    except OSError:
        return None
    for line in reversed(lines[1:] if start else lines):
        try:
            entry = json.loads(line)
        except (ValueError, RecursionError):
            continue
        if not isinstance(entry, dict) or type(entry.get("t")) is not int:
            continue
        if entry["t"] < since_ms:
            return None
        if entry.get("profile") == profile and (case_id is None or entry.get("case_id") == case_id):
            return _browser_action(entry)
    return None


def _norm_query(text: str) -> str:
    return " ".join(text.lower().split())


def _browser_view(profile: str, action: Any, activity: list[dict]) -> dict:
    """An owner's newest browser action, plus the newest API call it made with the same query (its count)."""
    action = action if isinstance(action, dict) else None
    api = None
    if action and action.get("query"):
        wanted = _norm_query(action["query"])
        for entry in activity:
            params = entry.get("params") if isinstance(entry.get("params"), dict) else {}
            query = _query_text({key: value for key, value in params.items() if isinstance(value, str)})
            if entry.get("profile") == profile and not entry.get("error") and _norm_query(query) == wanted:
                api = {"tool": _text(entry.get("tool")) or "unknown", "time": _text(entry.get("time")),
                       "result_count": entry.get("result_count") if type(entry.get("result_count")) is int else None,
                       "total": entry.get("total") if type(entry.get("total")) is int else None}
                break
    return {"profile": profile, "role": ROLE_TITLES.get(profile, profile), "action": action, "api": api}


def _team(step_views: list[dict]) -> list[dict]:
    team = []
    for profile, role in ROLE_TITLES.items():
        owned = [view for view in step_views if view["profile"] == profile]
        open_steps = [view for view in owned if view["state"] in _OPEN_STATES]
        team.append({"profile": profile, "role": role, "monogram": MONOGRAMS[profile],
                     "steps": [view["index"] for view in owned],
                     "current": open_steps[0]["index"] if open_steps else None,
                     "open_steps": [{"step_id": view["step_id"], "state": view["state"]} for view in open_steps],
                     "claims": sum(view["claims"] or 0 for view in owned)})
    return team


def _latest_conclusion(step_views: list[dict], handoffs: dict[int, dict]) -> dict | None:
    """The first claim of the newest done step that made one."""
    for view in reversed(step_views):
        claims = (handoffs.get(view["index"]) or {}).get("claims") or []
        if view["state"] == "done" and claims:
            claim = claims[0]
            return {"index": view["index"], "step_id": view["step_id"], "name": view["name"],
                    "profile": view["profile"], "role": view["role"], "claim_id": claim["claim_id"],
                    "kind": claim["kind"], "statement": claim["statement"]}
    return None


def build_state(raw_input: dict, parent: dict | None, child: dict | None, lab: dict | None = None,
                browser: dict | None = None) -> dict:
    """Derive the complete board view from the lab input and observed statuses.

    ``lab`` is a :meth:`LabObserver.snapshot` for a tool-driven input; it supplies the
    looked-up cited events and the lab's tool activity in place of inline evidence.
    ``browser`` maps each browser owner to its newest audit action this round (see
    :func:`newest_browser_action`); it is None when the board shows no live browsers.
    """
    raw = raw_input if isinstance(raw_input, dict) else {}
    input_errors: list[str] = []
    try:
        steps = list(supplied_evidence_hunt(raw).steps)
    except (ValueError, TypeError) as exc:
        steps = []
        input_errors.append(f"input is not a valid supplied-evidence hunt: {exc}")
    case, events, sessions, warnings = _lab_evidence(raw)
    input_errors.extend(warnings)
    tool_driven = raw.get("mode") == "tool_driven"
    lab = lab if isinstance(lab, dict) else {}
    missing_events: set[str] = set(lab.get("missing") or ()) if tool_driven else set()
    if tool_driven:
        looked_up = lab.get("events") if isinstance(lab.get("events"), dict) else {}
        events = [event for event in (_event(row, None) for row in looked_up.values()) if event]
        events.sort(key=lambda event: (event["t_ms"] is None, event["t_ms"] or 0, event["id"]))
        sessions = []
    track = _step_track([step.step_id for step in steps], child)
    rejections = (child.get("handoff_rejections") if isinstance(child, dict)
                  and isinstance(child.get("handoff_rejections"), list) else [])
    known_events = {event["id"] for event in events}
    round_id = child.get("workflow_id") if isinstance(child, dict) else None
    timings = _stage_timings(round_id, len(steps), child.get("activity_spans") if isinstance(child, dict) else None)
    handoffs: dict[int, dict] = {}

    step_views, feed = [], []
    citations: dict[str, list[str]] = {}
    claim_reviews: dict[str, list[dict]] = {}
    contradicted_by: dict[str, list[str]] = {}
    for index, step in enumerate(steps):
        state, reason, wave, result = track[index]
        role = ROLE_TITLES.get(step.profile, step.profile)
        view = {"index": index, "step_id": step.step_id, "name": step.step_id.replace("_", " ").title(),
                "profile": step.profile, "role": role,
                "monogram": MONOGRAMS.get(step.profile, step.profile[:2].upper()),
                "state": state, "reason": reason, "wave": wave, "optional": step.optional, "usage": _usage(result),
                "result": None, "claims": None, "timing": timings[index],
                "handoff_rejections": [{"outcome": item.get("outcome"), "reason": item.get("reason")}
                                       for item in rejections
                                       if isinstance(item, dict) and item.get("step_id") == step.step_id]}
        step_views.append(view)
        if result is None:
            continue
        status = result.get("status")
        view["result"] = {"status": status, "reason_code": result.get("reason_code")}
        handoff, error = (parse_handoff(result.get("output")) if status == "completed"
                          else (None, f"result status is {status}; no output to parse"))
        counted = handoff is not None and state in _CITED_STATES
        view["result"].update(parsed=handoff is not None, parse_error=error, counted=counted)
        output = result.get("output") if isinstance(result.get("output"), str) else ""
        item = {"index": index, "step_id": step.step_id, "profile": step.profile, "role": role,
                "state": state, "reason": reason, "result_status": status,
                "reason_code": result.get("reason_code"), "parsed": handoff is not None,
                "parse_error": error, "counted": counted, "output_chars": len(output),
                "raw_excerpt": output[:_RAW_EXCERPT_CHARS] if handoff is None else None,
                "handoff": handoff, "unknown_cited_ids": [], "pending_cited_ids": []}
        feed.append(item)
        if handoff is None:
            continue
        view["claims"] = len(handoff["claims"])
        handoffs[index] = handoff
        step_cited = _cited_ids(*(claim["statement"] for claim in handoff["claims"]),
                                *(review["rationale"] for review in handoff["reviews"]))
        unresolved = [event_id for event_id in step_cited if event_id not in known_events]
        if tool_driven:
            # Not yet looked up is not the same as absent from the lab.
            item["unknown_cited_ids"] = [event_id for event_id in unresolved if event_id in missing_events]
            item["pending_cited_ids"] = [event_id for event_id in unresolved if event_id not in missing_events]
        else:
            item["unknown_cited_ids"] = unresolved
        if not counted:
            continue
        for event_id in step_cited:
            citations.setdefault(event_id, []).append(step.step_id)
        for claim in handoff["claims"]:
            for target in claim["contradicts"]:
                if claim["claim_id"]:
                    contradicted_by.setdefault(target, []).append(claim["claim_id"])
        for review in handoff["reviews"]:
            for claim_id in review["claim_ids"]:
                claim_reviews.setdefault(claim_id, []).append({
                    "review_id": review["review_id"], "step_id": step.step_id, "role": role,
                    "disposition": review["disposition"], "rationale": review["rationale"]})
    for item in feed:
        for claim in (item["handoff"] or {}).get("claims", []):
            claim["verdicts"] = claim_reviews.get(claim["claim_id"], [])
            claim["contradicted_by"] = contradicted_by.get(claim["claim_id"], [])
    feed.reverse()

    cited = set(citations)
    for event in events:
        event["cited_by"] = citations.get(event["id"], [])
        event["cite_count"] = len(event["cited_by"])
    graph = _entity_graph(events, sessions)
    for collection in (graph["nodes"], graph["edges"]):
        for element in collection:
            element["cited_event_ids"] = [event_id for event_id in element["event_ids"] if event_id in cited]
    lanes: list[str | None] = []
    for event in events:
        if event["host"] not in lanes:
            lanes.append(event["host"])
    lanes.sort(key=lambda lane: (lane is None, lane or ""))
    start_ms, end_ms = _epoch_ms(case["start"]), _epoch_ms(case["end"])
    window_source = "case"
    if start_ms is None or end_ms is None or end_ms <= start_ms:
        stamped = [event["t_ms"] for event in events if event["t_ms"] is not None]
        start_ms, end_ms = (min(stamped), max(stamped) + 1) if stamped else (None, None)
        window_source = "events" if stamped else None
    by_domain: dict[str, int] = {}
    for session in sessions:
        if session["domain"]:
            by_domain[session["domain"]] = by_domain.get(session["domain"], 0) + 1
    pending = sorted({event_id for item in feed for event_id in item["pending_cited_ids"]})
    working: dict[str, int] = {}
    for view in step_views:
        if view["state"] == "working":
            working[view["profile"]] = working.get(view["profile"], 0) + 1
    activity = sorted((entry for entry in lab.get("activity") or () if isinstance(entry, dict)),
                      key=lambda entry: entry.get("seq") if type(entry.get("seq")) is int else -1, reverse=True)
    return {
        "board_version": 4,
        "mode": "tool_driven" if tool_driven else "inline",
        "case": case,
        "scope": _text(raw.get("scope")),
        "input_errors": input_errors,
        "run": _run_summary(parent, child, step_views),
        "round": _round_clock(child, timings),
        "stage_time": _wall_time(step_views),
        "waves": [{"wave": wave, **_wall_time([view for view in step_views if view["wave"] == wave])}
                  for wave in sorted({view["wave"] for view in step_views})],
        "steps": step_views,
        "team": _team(step_views),
        "latest_conclusion": _latest_conclusion(step_views, handoffs),
        "browsers": ([_browser_view(profile, action, activity if tool_driven else [])
                      for profile, action in browser.items()] if isinstance(browser, dict) else None),
        "timeline": {"start_ms": start_ms, "end_ms": end_ms, "window_source": window_source,
                     "lanes": lanes, "events": events, "source": "lab" if tool_driven else "input"},
        "graph": graph,
        "network": ({"session_count": None, "sessions_by_domain": {}} if tool_driven
                    else {"session_count": len(sessions), "sessions_by_domain": by_domain}),
        "feed": feed,
        "cited_event_count": len(cited & known_events),
        "pending_event_ids": pending,
        "tools": _tool_view(lab, case, working) if tool_driven else None,
    }


def _query_text(params: dict) -> str:
    """The bot's own query, expression or lookup values, as the lab recorded them."""
    for key in ("expression", "q", "values"):
        if isinstance(params.get(key), str):
            return params[key]
    return ""


def _arkime_ui_url(arkime_url: str | None, case: dict, expression: str, network_scope: str | None) -> str | None:
    """Arkime sessions URL with the same case scope, window and bounding the guest proxy applies.

    A case loaded before tagging (``/health`` ``network_scope == "window"``) is scoped by window only.
    """
    start_ms, end_ms = _epoch_ms(case.get("start")), _epoch_ms(case.get("end"))
    if not arkime_url or not case.get("case_id") or start_ms is None or end_ms is None:
        return None
    clauses = [] if network_scope == "window" else [f'tags == "case:{case["case_id"]}"']
    if expression.strip():
        clauses.append(f"({expression})")
    params = {"startTime": start_ms // 1000, "stopTime": -(-end_ms // 1000), "bounding": "first"}
    if clauses:
        params = {"expression": " && ".join(clauses), **params}
    return f"{arkime_url}/sessions?{parse.urlencode(params)}"


def _tool_view(lab: dict, case: dict, working: dict[str, int]) -> dict:
    """``working`` counts each profile's running steps. The lab logs tool calls per profile, so steps
    that share a profile share one lane."""
    entries = [entry for entry in lab.get("activity") or () if isinstance(entry, dict)]
    new_after = lab.get("new_after") if type(lab.get("new_after")) is int else None
    lanes: dict[str, dict] = {
        profile: {"profile": profile, "role": role, "count": 0, "errors": 0, "entries": [],
                  "working": profile in working, "working_steps": working.get(profile, 0), "active": False}
        for profile, role in ROLE_TITLES.items()
    }
    for entry in sorted(entries, key=lambda item: item.get("seq") if type(item.get("seq")) is int else -1,
                        reverse=True):
        profile = entry.get("profile") if entry.get("profile") in ROLE_TITLES else "unknown"
        lane = lanes.setdefault(profile, {"profile": "unknown", "role": "Unattributed", "count": 0, "errors": 0,
                                          "entries": [], "working": False, "working_steps": 0, "active": False})
        params = entry.get("params") if isinstance(entry.get("params"), dict) else {}
        params = {key: value for key, value in params.items() if isinstance(key, str) and isinstance(value, str)}
        endpoint = entry.get("endpoint") if isinstance(entry.get("endpoint"), str) else ""
        query = _query_text(params)
        is_new = new_after is not None and type(entry.get("seq")) is int and entry["seq"] > new_after
        lane["count"] += 1
        lane["errors"] += 1 if entry.get("error") else 0
        lane["active"] = lane["active"] or is_new
        if len(lane["entries"]) >= _ACTIVITY_SHOWN_PER_LANE:
            continue
        lane["entries"].append({
            "seq": entry.get("seq"),
            "time": _text(entry.get("time")),
            "tool": _text(entry.get("tool")) or endpoint or "unknown",
            "endpoint": endpoint,
            "query": query,
            "params": {key: value for key, value in sorted(params.items())
                       if key not in ("expression", "q", "values")},
            "result_count": entry.get("result_count") if type(entry.get("result_count")) is int else None,
            "total": entry.get("total") if type(entry.get("total")) is int else None,
            "error": _text(entry.get("error")),
            "new": is_new,
            "arkime_ui_url": (_arkime_ui_url(lab.get("arkime_url"), case, query, lab.get("network_scope"))
                              if endpoint.startswith("/arkime/") else None),
        })
    return {
        "lab": {key: lab.get(key) for key in ("reachable", "error", "observed_at", "last_success_at", "arkime_url")},
        "working_profile": next(iter(working), None),
        "lanes": [lane for lane in lanes.values() if lane["profile"] in ROLE_TITLES or lane["count"]],
        "entry_count": len(entries),
        "events_looked_up": len(lab.get("events") or {}),
        "events_not_found": len(lab.get("missing") or ()),
        "lookup_truncated": bool(lab.get("lookup_truncated")),
    }


# ---------------------------------------------------------------------------
# Temporal observation


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _plain(value: Any) -> Any:
    return json.loads(json.dumps(value, default=lambda item: item.__dict__, ensure_ascii=False))


class ObservationError(Exception):
    """A status observation failed; ``reachable`` says whether Temporal answered at all."""

    def __init__(self, message: str, reachable: bool) -> None:
        super().__init__(message)
        self.reachable = reachable


class TemporalObserver:
    """Query parent and current-child status through one persistent loopback client.

    The child also carries its Temporal start/close time and its history's activity spans
    (:func:`activity_spans`); history is re-read only when the round's status moved."""

    def __init__(self, address: str, workflow_id: str) -> None:
        self._address = validate_loopback_address(address)
        self._workflow_id = workflow_id
        self._client = None
        self._spans: tuple[tuple, list[dict]] | None = None
        self._loop = asyncio.new_event_loop()
        threading.Thread(target=self._loop.run_forever, name="hunt-board-temporal", daemon=True).start()

    def __call__(self) -> tuple[dict, dict | None]:
        future = asyncio.run_coroutine_threadsafe(self._observe(), self._loop)
        try:
            return future.result(timeout=_QUERY_TIMEOUT_SECONDS * 5)
        except ObservationError:
            raise
        except Exception as exc:
            future.cancel()
            raise ObservationError(f"observation failed ({type(exc).__name__})", False) from None

    async def _observe(self) -> tuple[dict, dict | None]:
        from temporalio.client import Client

        from .practice import PracticeWorkflow
        from .workflows import HermesWorkflow

        if self._client is None:
            try:
                self._client = await asyncio.wait_for(Client.connect(self._address), _QUERY_TIMEOUT_SECONDS)
            except Exception as exc:
                # SDK/server exception text may contain deployment details; report the type only.
                raise ObservationError(f"Temporal unreachable ({type(exc).__name__})", False) from None
        try:
            parent = await self._status(self._workflow_id, PracticeWorkflow.status)
            parent["workflow_id"] = self._workflow_id
        except Exception as exc:
            self._client = None
            raise ObservationError(f"parent status query failed ({type(exc).__name__})", True) from None
        child = None
        if isinstance(parent.get("child_workflow_id"), str):
            child_id = parent["child_workflow_id"]
            try:
                child = await self._status(child_id, HermesWorkflow.status)
            except Exception as exc:
                raise ObservationError(f"round status query failed ({type(exc).__name__})", True) from None
            child["workflow_id"] = child_id
            child["activity_spans"] = await self._activity_spans(child_id, child)
        return parent, child

    async def _status(self, workflow_id: str, query) -> dict:
        handle = self._client.get_workflow_handle(workflow_id)
        state = await asyncio.wait_for(handle.query(query), _QUERY_TIMEOUT_SECONDS)
        execution = await asyncio.wait_for(handle.describe(), _QUERY_TIMEOUT_SECONDS)
        status = execution.status.name if execution.status is not None else None
        times = {key: value.isoformat() if value is not None else None
                 for key, value in (("start_time", execution.start_time), ("close_time", execution.close_time))}
        return _plain({**vars(state), "temporal_status": status, **times})

    async def _activity_spans(self, workflow_id: str, child: dict) -> list[dict] | None:
        """The round's activity spans; None when its history could not be read (timings stay unknown)."""
        key = (workflow_id, child.get("stage"), child.get("step_id"), child.get("execution_id"),
               child.get("temporal_status"), len(child.get("results") or ()),
               len(child.get("handoff_rejections") or ()),
               tuple((item.get("state"), item.get("execution_id")) for item in _wave_steps(child).values()))
        cached = self._spans
        # A query can answer before a new activity's scheduled event is readable; re-read until it is.
        settled = _running_executions(child) <= {span["execution_id"] for span in (cached[1] if cached else ())}
        if cached and cached[0] == key and settled:
            return cached[1]
        try:
            handle = self._client.get_workflow_handle(workflow_id)
            history = await asyncio.wait_for(handle.fetch_history(skip_archival=True), _QUERY_TIMEOUT_SECONDS)
        except Exception:
            return cached[1] if cached and cached[0][0] == workflow_id else None
        spans = activity_spans(history.events)
        self._spans = (key, spans)
        return spans


def cited_event_ids(child: dict | None) -> list[str]:
    """Every event ID named in a parsed claim statement or review rationale of the round."""
    results = child.get("results") if isinstance(child, dict) and isinstance(child.get("results"), list) else []
    texts: list[str] = []
    for result in results:
        if not isinstance(result, dict) or result.get("status") != "completed":
            continue
        handoff, _error = parse_handoff(result.get("output"))
        if handoff:
            texts += [claim["statement"] for claim in handoff["claims"]]
            texts += [review["rationale"] for review in handoff["reviews"]]
    return _cited_ids(*texts)


class _LabRefused(Exception):
    """The lab answered with something the board will not display."""


class LabObserver:
    """Poll one loopback lab's ``/activity`` ring and look up cited events by ``event.id``.

    Every request is a bounded GET sent as ``hunt-board`` (the guest leaves those out of
    ``/activity``). Lookups are batched, capped per poll and cached, including misses.
    """

    def __init__(self, resolve: Callable[[], dict], case_id: str | None,
                 get: Callable[..., dict] = lab_get, activity_after: int = 0) -> None:
        self._resolve = resolve
        self._case_id = case_id
        self._get = get
        self._lab_url: str | None = None
        self._arkime_url: str | None = None
        self._network_scope: str | None = None
        # Entries at or before this /activity sequence (e.g. earlier checks or hunts)
        # are not this run's tool calls and are never shown.
        self._after = activity_after
        self._new_after: int | None = None
        self._activity: list[dict] = []
        self._events: dict[str, dict] = {}
        self._missing: set[str] = set()
        self._truncated = False
        self._status = {"reachable": None, "error": None, "observed_at": None, "last_success_at": None}

    def refresh(self, cited: Iterable[str]) -> None:
        """One observation; never raises. Endpoints are re-resolved after a failure (VM ports change)."""
        observed_at = _utc_now()
        try:
            if self._lab_url is None:
                endpoints = self._resolve()
                self._lab_url, self._arkime_url = endpoints["lab_url"], endpoints.get("arkime_url")
                scope = self._call("/health").get("network_scope")
                self._network_scope = scope if scope in ("tag", "window") else "tag"
            self._poll_activity()
            self._lookup(cited)
        except _LabRefused as exc:
            self._lab_url = None
            self._status.update(reachable=True, error=str(exc), observed_at=observed_at)
            return
        except Exception:
            self._lab_url = None
            self._status.update(reachable=False, error="lab unreachable or its response was refused",
                                observed_at=observed_at)
            return
        self._status.update(reachable=True, error=None, observed_at=observed_at, last_success_at=observed_at)

    def snapshot(self) -> dict:
        return {"events": dict(self._events), "missing": sorted(self._missing), "activity": list(self._activity),
                "new_after": self._new_after, "arkime_url": self._arkime_url, "network_scope": self._network_scope,
                "lookup_truncated": self._truncated, **self._status}

    def _call(self, path: str) -> dict:
        body = self._get(self._lab_url, path, profile=BOARD_LAB_PROFILE, timeout=_LAB_TIMEOUT_SECONDS)
        if self._case_id is not None and body.get("case_id") != self._case_id:
            raise _LabRefused("the lab has a different case loaded than this input")
        return body

    def _poll_activity(self) -> None:
        self._new_after = self._after
        for _page in range(_ACTIVITY_PAGES_PER_POLL):
            body = self._call(f"/activity?after={self._after}&limit={_ACTIVITY_PAGE}")
            next_seq, entries = body.get("next"), body.get("entries")
            if type(next_seq) is not int or not isinstance(entries, list):
                raise _LabRefused("lab activity response is malformed")
            if next_seq < self._after:
                # The lab service restarted with a new ring; start over from its beginning.
                self._after, self._activity, self._new_after = 0, [], None
                return
            fresh = [entry for entry in entries
                     if isinstance(entry, dict) and type(entry.get("seq")) is int and entry["seq"] > self._after]
            self._activity = (self._activity + fresh)[-_ACTIVITY_KEEP:]
            self._after = max([next_seq, self._after, *(entry["seq"] for entry in fresh)])
            if body.get("more") is not True or not fresh:
                return

    def _lookup(self, cited: Iterable[str]) -> None:
        wanted = [event_id for event_id in sorted(set(cited))
                  if event_id not in self._events and event_id not in self._missing]
        for _batch in range(_LOOKUP_BATCHES_PER_POLL):
            if not wanted:
                return
            if len(self._events) + len(self._missing) >= _LOOKUP_MAX_EVENTS:
                self._truncated = True
                return
            batch: list[str] = []
            for event_id in wanted:
                if len("event.id:(" + " OR ".join(f'"{item}"' for item in [*batch, event_id]) + ")") > _LOOKUP_QUERY_CHARS:
                    break
                batch.append(event_id)
            if not batch:
                self._missing.add(wanted.pop(0))  # an ID too long for any lookup query
                continue
            wanted = wanted[len(batch):]
            query = "event.id:(" + " OR ".join(f'"{item}"' for item in batch) + ")"
            body = self._call("/es/search?" + parse.urlencode({"q": query, "size": 200, "fields": _LOOKUP_FIELDS}))
            if not isinstance(body.get("hits"), list):
                raise _LabRefused("lab search response is malformed")
            for hit in body["hits"]:
                row = _nest(hit) if isinstance(hit, dict) else {}
                if _get(row, "event", "id") in batch:
                    self._events[row["event"]["id"]] = row
            self._missing.update(event_id for event_id in batch if event_id not in self._events)


class Board:
    """Cache one observation for ``interval`` seconds and serve the derived state.

    ``live`` adds the browser owners' live status, read fresh on every request, and their
    newest audit action of this round, read with each observation."""

    def __init__(self, raw_input: dict, observe: Callable[[], tuple[dict, dict | None]],
                 interval: float = POLL_INTERVAL_SECONDS, clock: Callable[[], float] = time.monotonic,
                 lab: LabObserver | None = None, live: LiveBrowsers | None = None) -> None:
        self._raw = raw_input
        self._observe = observe
        self._interval = interval
        self._clock = clock
        self._lab = lab
        self.live = live
        self._lock = threading.Lock()
        self._polled_at: float | None = None
        self._parent: dict | None = None
        self._child: dict | None = None
        self._temporal = {"reachable": None, "error": None, "observed_at": None, "last_success_at": None}
        self._state: dict | None = None
        self._case_id = _lab_evidence(raw_input if isinstance(raw_input, dict) else {})[0]["case_id"]

    def _browser_actions(self) -> dict | None:
        if self.live is None:
            return None
        since = _epoch_ms(self._child.get("start_time")) if isinstance(self._child, dict) else None
        return {profile: (newest_browser_action(self.live.root / profile / "audit.jsonl", profile, since,
                                                self._case_id) if since is not None else None)
                for profile in self.live.profiles}

    def state_bytes(self) -> bytes:
        with self._lock:
            now = self._clock()
            if self._polled_at is None or now - self._polled_at >= self._interval:
                self._polled_at = now
                self._poll()
                if self._lab is not None:
                    self._lab.refresh(cited_event_ids(self._child))
                self._state = None
            if self._state is None:
                lab = self._lab.snapshot() if self._lab is not None else None
                self._state = build_state(self._raw, self._parent, self._child, lab, self._browser_actions())
                self._state["temporal"] = dict(self._temporal)
            live = {"owners": self.live.status()} if self.live is not None else None
            return json.dumps({**self._state, "live": live}, ensure_ascii=False, sort_keys=True).encode("utf-8")

    def _poll(self) -> None:
        observed_at = _utc_now()
        try:
            parent, child = self._observe()
        except ObservationError as exc:
            self._temporal.update(reachable=exc.reachable, error=str(exc), observed_at=observed_at)
            return
        except Exception as exc:
            self._temporal.update(reachable=False, error=f"observation failed ({type(exc).__name__})",
                                  observed_at=observed_at)
            return
        self._parent, self._child = parent, child
        self._temporal.update(reachable=True, error=None, observed_at=observed_at, last_success_at=observed_at)


# ---------------------------------------------------------------------------
# Live browsers

# The two bots that drive a lab browser, as operator/film/actions.py OWNERS names them.
LIVE_PROFILES = ("framework-researcher", "framework-network-analyst")
LIVE_STREAMS_MAX = 4
_LIVE_WRITE_TIMEOUT_SECONDS = 10.0
_LIVE_PATH = re.compile(r"/live/([a-z0-9-]+)\.(jpg|mjpg)")
_MJPEG_BOUNDARY = "huntboardframe"


def browser_root(hermes_home: str | Path) -> Path:
    """The lane's lab_browser folder, as operator/lab_paths.py Lane.browser_root derives it."""
    return Path(hermes_home) / "profiles" / "framework-network-analyst" / "hunt-lab-browser"


class LiveBrowsers:
    """The latest screencast frame of each browser owner, in memory only.

    :meth:`add` is the frame sink; :meth:`start` runs the watch-only screencast client on ``root``.
    Each profile keeps one ``(jpeg, frame time, count)``; waiters wake on every new frame."""

    def __init__(self, root: str | Path, profiles: Iterable[str] = LIVE_PROFILES) -> None:
        self.root = Path(root)
        self.profiles = tuple(profiles)
        self._cond = threading.Condition()
        self._frames: dict[str, tuple[bytes, float, int]] = {}
        self._closed = False
        self._watcher: Any = None
        self.streams = threading.BoundedSemaphore(LIVE_STREAMS_MAX)

    def add(self, profile: str, t: float, jpeg: bytes) -> None:
        with self._cond:
            if profile not in self.profiles:
                return
            count = self._frames[profile][2] + 1 if profile in self._frames else 1
            self._frames[profile] = (jpeg, t, count)
            self._cond.notify_all()

    def latest(self, profile: str) -> tuple[bytes, float, int] | None:
        with self._cond:
            return self._frames.get(profile)

    def next_frame(self, profile: str, seen: int, timeout: float) -> tuple[bytes, float, int] | None:
        """The current frame once its count exceeds ``seen``; None on timeout or after :meth:`close`."""
        with self._cond:
            self._cond.wait_for(lambda: self._closed or self._frames.get(profile, (b"", 0.0, 0))[2] > seen, timeout)
            frame = self._frames.get(profile)
            return frame if not self._closed and frame and frame[2] > seen else None

    @property
    def closed(self) -> bool:
        return self._closed

    def status(self) -> list[dict]:
        owners = []
        for profile in self.profiles:
            frame = self.latest(profile)
            owners.append({
                "profile": profile,
                "role": ROLE_TITLES.get(profile, profile),
                "attached": bool(self._watcher and self._watcher.attached(profile)),
                "frames": frame[2] if frame else 0,
                "last_frame_at": int(frame[1] * 1000) if frame else None,
                "page": screencast.shown_page(self.root, profile),
            })
        return owners

    def start(self, connect: Callable[[str], Any] = screencast.websocket) -> "LiveBrowsers":
        self._watcher = screencast.Watcher(self.root, self.add, self.profiles, connect=connect,
                                           name="board-screencast").start()
        return self

    def close(self) -> None:
        with self._cond:
            self._closed = True
            self._cond.notify_all()
        if self._watcher is not None:
            self._watcher.stop()

# ---------------------------------------------------------------------------
# HTTP server


def content_security_policy(port: int) -> str:
    return ("default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
            f"img-src data: http://127.0.0.1:{port}; "
            f"connect-src http://127.0.0.1:{port}; base-uri 'none'; form-action 'none'")


def _handler(board: Board) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def version_string(self) -> str:
            return "HuntBoard"

        def parse_request(self) -> bool:
            if not super().parse_request():
                return False
            if self.command != "GET":
                self.close_connection = True
                self._send(405, b"method not allowed\n", "text/plain; charset=utf-8", {"Allow": "GET"})
                return False
            return True

        def do_GET(self) -> None:
            port = self.server.server_address[1]
            path = self.path.split("?", 1)[0]
            if self.headers.get("Host") != f"127.0.0.1:{port}":
                # Refuse other Host names so a rebinding page cannot read the board.
                self._send(404, b"not found\n", "text/plain; charset=utf-8")
            elif path == "/":
                csp = content_security_policy(port)
                self._send(200, PAGE.replace("__CSP__", csp).encode("utf-8"), "text/html; charset=utf-8",
                           {"Content-Security-Policy": csp})
            elif path == "/state.json":
                headers = {"Vary": "Origin"}
                if self.headers.get("Origin") == "null":
                    headers["Access-Control-Allow-Origin"] = "null"
                self._send(200, board.state_bytes(), "application/json; charset=utf-8", headers)
            elif live_path := _LIVE_PATH.fullmatch(path):
                self._live(*live_path.groups())
            else:
                self._send(404, b"not found\n", "text/plain; charset=utf-8")

        def _live(self, profile: str, kind: str) -> None:
            live = board.live
            if live is None or profile not in live.profiles:
                self._send(404, b"not found\n", "text/plain; charset=utf-8")
            elif kind == "jpg":
                frame = live.latest(profile)
                if frame is None:
                    self._send(404, b"no frame yet\n", "text/plain; charset=utf-8")
                else:
                    self._send(200, frame[0], "image/jpeg")
            elif not live.streams.acquire(blocking=False):
                self._send(503, b"too many live streams\n", "text/plain; charset=utf-8", {"Retry-After": "5"})
            else:
                try:
                    self._stream(live, profile)
                finally:
                    live.streams.release()

        def _stream(self, live: LiveBrowsers, profile: str) -> None:
            """multipart/x-mixed-replace: the current frame, then each new one until close or disconnect."""
            self.close_connection = True
            self.send_response(200)
            self.send_header("Content-Type", f"multipart/x-mixed-replace; boundary={_MJPEG_BOUNDARY}")
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.end_headers()
            # A client that stops reading must not hold a stream slot forever.
            self.connection.settimeout(_LIVE_WRITE_TIMEOUT_SECONDS)
            seen = 0
            # Chromium paints a part only once the next part's boundary and headers have arrived, so each frame
            # is followed by them at once (parts are delimited by the boundary, without Content-Length);
            # otherwise a page that stopped changing would never show its last frame.
            part_head = f"--{_MJPEG_BOUNDARY}\r\nContent-Type: image/jpeg\r\n\r\n".encode("ascii")
            try:
                self.wfile.write(part_head)
                self.wfile.flush()
                while not live.closed:
                    frame = live.next_frame(profile, seen, timeout=1.0)
                    if frame is None:
                        continue
                    jpeg, _, seen = frame
                    self.wfile.write(jpeg + b"\r\n" + part_head)
                    self.wfile.flush()
            except OSError:
                pass

        def _send(self, code: int, body: bytes, content_type: str, headers: dict | None = None) -> None:
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            for name, value in (headers or {}).items():
                self.send_header(name, value)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def log_message(self, format: str, *args: Any) -> None:
            pass

    return Handler


def make_server(board: Board, port: int) -> ThreadingHTTPServer:
    """Bind the read-only board to loopback only; ``port=0`` picks a free port."""
    server = ThreadingHTTPServer((BIND_HOST, port), _handler(board))
    server.daemon_threads = True
    return server


def _port(value: str) -> int:
    if not (value.isascii() and value.isdigit() and 1 <= int(value) <= 65535):
        raise argparse.ArgumentTypeError("port must be 1 through 65535")
    return int(value)


def _lab_url(value: str) -> str:
    try:
        return loopback_base(value)
    except LabInputError:
        raise argparse.ArgumentTypeError("must be exactly http://127.0.0.1:<port>") from None


def _parser() -> argparse.ArgumentParser:
    from .cli import DEFAULT_ADDRESS

    parser = argparse.ArgumentParser(description="Read-only live board for a supplied-evidence practice hunt")
    parser.add_argument("--address", default=DEFAULT_ADDRESS, type=validate_loopback_address,
                        help="loopback Temporal server host:port")
    parser.add_argument("--workflow-id", required=True, help="practice parent workflow ID")
    parser.add_argument("--input", required=True, help="the supplied-evidence hunt JSON the practice was started with")
    parser.add_argument("--port", type=_port, default=DEFAULT_PORT, help="loopback port to serve on")
    lab = parser.add_mutually_exclusive_group()
    lab.add_argument("--lab-state-dir",
                     help="tool-driven input: the Network Analyst's hunt-lab-vm state dir; its URLs are read from status")
    lab.add_argument("--lab-url", type=_lab_url, help="tool-driven input: the lab API, http://127.0.0.1:<port>")
    parser.add_argument("--arkime-url", type=_lab_url,
                        help="Arkime viewer for copyable session links, http://127.0.0.1:<port> (default: from status)")
    parser.add_argument("--activity-after", type=int, default=0,
                        help="tool-driven input: show only lab tool calls after this /activity sequence "
                             "(the lab's current 'next' value when the hunt starts)")
    parser.add_argument("--hermes-home",
                        help="show the Threat Hunter's and Network Analyst's lab browsers live (watch only): the lane's "
                             "Hermes home; frames are read from <home>/profiles/framework-network-analyst/"
                             "hunt-lab-browser/<profile>/ (needs websockets)")
    return parser


def _lab_observer(args: argparse.Namespace, case_id: str | None) -> LabObserver:
    override = {"arkime_url": args.arkime_url} if args.arkime_url else {}
    after = max(0, args.activity_after)
    if args.lab_url:
        endpoints = {"lab_url": args.lab_url, "arkime_url": None, **override}
        return LabObserver(lambda: endpoints, case_id, activity_after=after)
    return LabObserver(lambda: {**lab_endpoints(args.lab_state_dir), **override}, case_id, activity_after=after)


def main(argv: list[str] | None = None) -> int:
    from .cli import _strict_input

    args = _parser().parse_args(argv)
    try:
        raw = _strict_input(args.input)
    except (OSError, ValueError) as exc:
        print(f"error: cannot read input ({type(exc).__name__})", file=sys.stderr)
        return 2
    initial = build_state(raw, None, None)
    if initial["input_errors"]:
        print("error: input is not a readable supplied-evidence hunt", file=sys.stderr)
        return 2
    has_lab = bool(args.lab_state_dir or args.lab_url)
    if initial["mode"] == "tool_driven" and not has_lab:
        print("error: a tool-driven input needs --lab-state-dir or --lab-url", file=sys.stderr)
        return 2
    if initial["mode"] != "tool_driven" and (has_lab or args.arkime_url):
        print("error: lab options apply only to a tool-driven input", file=sys.stderr)
        return 2
    live = None
    if args.hermes_home:
        if importlib.util.find_spec("websockets") is None:
            print("error: --hermes-home needs the websockets package; install hermes_temporal/requirements.txt "
                  f"into {sys.executable}", file=sys.stderr)
            return 2
        if not Path(args.hermes_home).is_dir():
            print("error: --hermes-home is not a directory", file=sys.stderr)
            return 2
        live = LiveBrowsers(browser_root(args.hermes_home))
    lab = _lab_observer(args, initial["case"]["case_id"]) if has_lab else None
    board = Board(raw, TemporalObserver(args.address, args.workflow_id), lab=lab, live=live)
    try:
        server = make_server(board, args.port)
    except OSError as exc:
        print(f"error: cannot bind {BIND_HOST}:{args.port} ({type(exc).__name__})", file=sys.stderr)
        return 2
    if live is not None:
        live.start()
    print(json.dumps({"url": f"http://{BIND_HOST}:{server.server_address[1]}/", "status": "serving"}), flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        if live is not None:
            live.close()
        server.server_close()
    return 0


# ---------------------------------------------------------------------------
# Page (self-contained; every data value is inserted via textContent/attributes)

PAGE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="__CSP__">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Hermes Hunt Live</title>
<style>
:root{--paper:#f7f7f5;--ink:#1e211f;--muted:#666c68;--soft:#929993;--line:#dcdedb;--accent:#315c4c;--accent-soft:#e7eeea;
--live:#b3322d;--done:#8d9a90;--track:#e8ebe7;--hx-side:#f5f6f8;--hx-line:#e3e6ea;--hx-text:#1f2430;--hx-muted:#6b7280;--hx-soft:#9aa1ac;
--mono:ui-monospace,SFMono-Regular,Consolas,"Liberation Mono",monospace;--sans:"Inter",-apple-system,"Segoe UI",sans-serif;
--screen-h:clamp(240px,calc(100vh - 615px - var(--wf-extra,0px)),640px)}
*{box-sizing:border-box}
[hidden]{display:none!important}
html,body{margin:0;background:var(--paper);color:var(--ink);font:15px/1.45 var(--sans);-webkit-font-smoothing:antialiased}
code{font-family:var(--mono)}
.ic{width:16px;height:16px;flex:0 0 auto;fill:none;stroke:currentColor;stroke-width:1.4;stroke-linecap:round;stroke-linejoin:round}
.lbl{font-size:11.5px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:var(--muted)}
.none{color:var(--soft)}
/* status words: red only for LIVE */
.st{display:inline-flex;align-items:center;gap:7px;font-size:12px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;white-space:nowrap;color:var(--muted)}
.st.run{color:var(--accent)}
.st.wait{color:var(--soft)}
.st.stop{color:var(--ink)}
.st.drop{color:var(--soft)}
.st.drop::before{content:"\00d7";font-size:15px;line-height:1}
.st.live{color:var(--live)}
.st.live::before{content:"";width:8px;height:8px;border-radius:50%;background:var(--live);animation:breathe 2.4s ease-in-out infinite}
@keyframes breathe{50%{opacity:.48}}
.mg{display:inline-grid;place-items:center;flex:0 0 auto;width:30px;height:30px;border-radius:7px;background:#e9ece8;color:#3f4842;font-size:11px;font-weight:700;position:relative}
.mg.on{background:var(--ink);color:#fff}
.mg.xl{width:50px;height:50px;border-radius:10px;font-size:17px;border:1.5px solid var(--ink);background:#fff;color:var(--ink)}
.mg.xl.on{background:var(--ink);color:#fff}
.mg .scr{position:absolute;right:-4px;top:-4px;width:14px;height:11px;border:1.3px solid var(--accent);background:#fff;border-radius:2px}
.mg .scr::after{content:"";position:absolute;left:0;right:0;top:2px;border-top:1.3px solid var(--accent)}
.kind{display:inline-flex;align-items:center;gap:7px;font-size:12px;font-weight:700;letter-spacing:.07em;text-transform:uppercase;white-space:nowrap;color:var(--ink)}
.kind::before{content:"";width:10px;height:10px;display:block;box-sizing:border-box;flex:0 0 auto}
.kind.k-observed{color:var(--accent)}.kind.k-observed::before{background:var(--accent)}
.kind.k-hypothesis::before{border:1.5px solid var(--ink)}
.kind.k-inference::before{background:linear-gradient(90deg,var(--ink) 50%,transparent 50%);border:1.5px solid var(--ink)}
.kind.k-finding::before{background:var(--ink)}
.kind.k-other{color:var(--muted)}.kind.k-other::before{border:1.5px dashed var(--soft)}

/* Hunt Live: everything above the fold at 1920x1080 */
#live{min-height:100vh;display:flex;flex-direction:column;gap:14px;padding:18px 28px 16px}
.hd{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:40px;align-items:end;border-bottom:1px solid var(--ink);padding-bottom:12px}
.brand{display:flex;align-items:center;gap:10px;font-size:13px;font-weight:650;color:var(--muted)}
.brand-mark{width:24px;height:24px;display:grid;place-items:center;background:var(--ink);color:#fff;border-radius:6px;font-size:12px;font-weight:700}
.brand b{color:var(--ink);font-weight:650}
.title{display:flex;align-items:baseline;gap:18px;margin:6px 0 3px;min-width:0}
h1{font-size:34px;line-height:1.1;letter-spacing:-.04em;font-weight:650;margin:0;white-space:nowrap}
#round{color:var(--muted);font-size:15px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;min-width:0}
#question{margin:0;color:#474d49;font-size:16px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.clock{text-align:right;min-width:260px}
.clock .lbl{display:flex;justify-content:flex-end;gap:12px;align-items:center}
#clock{display:block;font:500 46px/1.05 var(--mono);letter-spacing:-.03em;margin-top:2px}
#conn{font-size:12px;color:var(--muted);margin-top:4px;white-space:nowrap;max-width:720px;overflow:hidden;text-overflow:ellipsis}
#conn.bad{color:var(--ink);font-weight:650}
#errors{margin:0;font-size:13px;font-weight:650}
.wf-h{display:flex;justify-content:space-between;align-items:baseline;gap:16px;margin-bottom:8px}
#wf-meta{font-size:13px;color:var(--muted);font-family:var(--mono)}
.tl-bar,.tl-num{display:flex}
.tl-bar{height:30px;background:var(--track)}
.tl-bar>span,.tl-num>span{flex:1 1 0;min-width:0}
.tl-bar>span{border-right:2px solid var(--paper);background:#d5dad6;position:relative;overflow:hidden}
.tl-bar>span:last-child,.tl-num>span:last-child{border-right:0}
.tl-bar>span.done{background:var(--done)}
.tl-bar>span.stop{background:var(--ink)}
.tl-bar>span.pend{background:repeating-linear-gradient(90deg,#c3cac5 0 1px,#eef0ed 1px 4px)}
.tl-bar>span.drop{background:repeating-linear-gradient(135deg,var(--done) 0 3px,#eef0ed 3px 6px)}
.tl-bar>span.on{background:var(--accent-soft);box-shadow:inset 0 0 0 2px var(--accent)}
.tl-bar>span.on>b{position:absolute;left:0;top:0;bottom:0;background:var(--accent)}
.tl-num{margin-top:5px;font:600 12px var(--mono);color:var(--soft)}
.tl-num>span{overflow:hidden;white-space:nowrap;padding-left:2px;border-right:2px solid transparent}
.tl-num>span.on{color:var(--accent)}
.stages{list-style:none;margin:8px 0 0;padding:0;display:grid;grid-template-columns:repeat(9,minmax(0,1fr));border-top:1px solid var(--line)}
.stage{padding:8px 10px 2px 0;min-width:0;border-top:3px solid transparent;margin-top:-2px}
.stage+.stage,.stages.par .stage:not(:first-child){padding-left:10px;border-left:1px solid var(--line)}
.stage.on{border-top-color:var(--accent)}
.stage .top,.wave-lane .top{display:flex;align-items:center;gap:8px;min-width:0}
.stage .n,.wave-lane .n{font:600 13px var(--mono);color:var(--soft)}
.stage.on .n,.wave-lane.on .n{color:var(--accent)}
.stage .nm,.wave-lane .nm{font-size:17px;font-weight:650;letter-spacing:-.02em;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;flex:1;min-width:0}
.stage .mg{width:28px;height:28px;font-size:10.5px}
.stage .meta,.wave-lane .meta{display:flex;justify-content:space-between;align-items:baseline;gap:6px;margin-top:5px;white-space:nowrap}
.stage .meta .st,.wave-lane .meta .st{overflow:hidden;text-overflow:ellipsis;min-width:0}
.stage .t,.wave-lane .t{font:500 14px var(--mono);color:var(--ink)}
.stage.dropped .nm,.wave-lane.dropped .nm{color:var(--soft);text-decoration:line-through}
.why{font-size:12px;color:var(--muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
/* A wave of several steps: one group behind one decision, its steps side by side as lanes. */
.stages.par{align-items:start}
.wave{min-width:0;margin:6px 10px 2px 0;padding:5px 10px 6px;background:#fff;border:1px solid var(--line);border-radius:8px}
.wave.on{border-color:var(--accent)}
.wave-h{display:flex;flex-wrap:wrap;align-items:baseline;gap:2px 12px;font-size:12px;color:var(--muted)}
.wave-g{margin-left:auto}
.wave-lanes{list-style:none;margin:4px 0 0;padding:0;display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:6px 10px}
.wave-lane{min-width:0;padding:1px 0 1px 8px;border-left:2px solid var(--line)}
.wave-lane.on{border-left-color:var(--accent)}
.wave-lane .nm{font-size:15px}
.wave-lane .mg{width:24px;height:24px;font-size:10px}
.wave-lane .sub{display:flex;justify-content:space-between;gap:8px;font-size:12px;color:var(--muted);white-space:nowrap}
.wave-lane .sub .role{overflow:hidden;text-overflow:ellipsis;min-width:0}
.wave-lane .sub .tok{font-family:var(--mono);color:var(--ink)}
.wave-lane .meta{margin-top:2px}
#bots{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);gap:20px}
.bot{background:#fff;border:1.5px solid var(--ink);border-radius:14px;padding:14px 16px 16px;min-width:0;display:flex;flex-direction:column;gap:12px}
.bot-h{display:flex;align-items:center;gap:14px;min-width:0}
.who{min-width:0}
.who strong{display:block;font-size:21px;letter-spacing:-.025em;line-height:1.15;white-space:nowrap}
.who small{display:block;font-size:13.5px;color:var(--muted)}
.cur{margin-left:auto;text-align:right;min-width:0}
.cur .v{display:block;font-size:16px;font-weight:650;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.bot-h>.st{font-size:13px;min-width:150px;justify-content:flex-end}
.bot-b{display:flex;gap:18px;min-width:0;align-items:flex-start}
.mc{flex:0 0 auto;max-width:100%;border:1px solid #d7dbe1;border-radius:8px;overflow:hidden;background:#fff;color:var(--hx-text);
box-shadow:0 14px 40px rgba(24,33,27,.08),0 2px 6px rgba(24,33,27,.04)}
.mc-bar{height:34px;display:flex;align-items:center;gap:10px;padding:0 12px;background:var(--hx-side);border-bottom:1px solid var(--hx-line);font-size:13.5px;color:var(--hx-muted)}
.mc-addr{flex:1;min-width:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;color:var(--hx-text);font-weight:600}
.mc-watch{display:inline-flex;gap:6px;align-items:center;white-space:nowrap;font-size:12.5px}
.mc-screen{position:relative;height:var(--screen-h);aspect-ratio:var(--ar,1249 / 954);background:#eef0f2;overflow:hidden}
.mc-screen img{display:block;width:100%;height:100%;object-fit:contain;object-position:top left}
.mc-empty{position:absolute;inset:0;display:grid;place-items:center;text-align:center;background:repeating-linear-gradient(0deg,#f6f7f9 0 22px,#f1f2f5 22px 23px);color:var(--hx-soft);font-size:15px}
.mc-empty div{background:#fff;border:1px solid var(--hx-line);border-radius:6px;padding:12px 18px;max-width:80%}
.mc-empty b{display:block;color:var(--hx-muted);font-weight:650;margin-bottom:2px}
.mc-foot{height:42px;padding:0 12px;border-top:1px solid var(--hx-line);color:var(--hx-muted);font-size:14.5px;display:flex;gap:8px;align-items:center;white-space:nowrap;overflow:hidden;min-width:0}
.mc-foot b{color:var(--hx-text);font-weight:650}
.mc-foot code{color:var(--hx-text);font-size:14px;overflow:hidden;text-overflow:ellipsis;min-width:0;flex:0 1 auto}
.mc-foot .res{color:var(--hx-text);font-weight:650}
/* The screen sets the window's width; the bar and caption never widen it. */
.mc-bar,.mc-foot{width:0;min-width:100%}
.mc-foot .tm{margin-left:auto;padding-left:8px;font:12.5px var(--mono);color:var(--hx-soft)}
.side{flex:1;min-width:0;display:flex;flex-direction:column;gap:14px}
.side ol{list-style:none;margin:6px 0 0;padding:0;border-top:1px solid var(--line)}
.side li{display:grid;grid-template-columns:30px minmax(0,1fr) auto;gap:4px 8px;padding:8px 0;border-bottom:1px solid var(--line);align-items:baseline}
.side li .n{font:600 13px var(--mono);color:var(--soft)}
.side li .nm{font-size:16px;font-weight:650;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.side li .t{font:14px var(--mono)}
.side li .st{grid-column:2}
.side li .c{font-size:13px;color:var(--muted);text-align:right}
.side dl{margin:6px 0 0;display:grid;grid-template-columns:auto minmax(0,1fr);gap:6px 14px;font-size:14px;border-top:1px solid var(--line);padding-top:8px}
.side dt{color:var(--muted)}
.side dd{margin:0;font-family:var(--mono);font-size:13.5px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.team{display:grid;grid-template-columns:repeat(6,minmax(0,1fr));border-top:1px solid var(--ink)}
.team>div{display:flex;gap:10px;align-items:flex-start;padding:10px 12px 0 0;min-width:0}
.team>div+div{padding-left:12px;border-left:1px solid var(--line)}
.team>div>div{min-width:0}
.team strong{display:block;font-size:14.5px;line-height:1.25;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.team small{display:block;font-size:13.5px;color:var(--muted);margin-top:2px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.team small.run{color:var(--accent);font-weight:650}
#conclusion{display:flex;align-items:baseline;gap:16px;border-top:1px solid var(--line);padding-top:10px;min-width:0}
#conclusion .src{font-size:14px;color:var(--muted);white-space:nowrap}
#conclusion p{margin:0;flex:1;min-width:0;font-size:17.5px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}

/* Record: below the fold */
#record{padding:26px 28px 10px;border-top:1px solid var(--ink)}
.rec-h{display:flex;justify-content:space-between;align-items:baseline;margin-bottom:16px}
.rec-h h2{font-size:24px;letter-spacing:-.03em;margin:0;font-weight:650}
section.sec{background:#fff;border:1px solid var(--line);padding:12px 14px;margin-bottom:16px;min-width:0}
.sec-h{display:flex;justify-content:space-between;align-items:baseline;gap:8px;margin-bottom:8px;flex-wrap:wrap}
.meta{font-size:12px;color:var(--muted)}
.meta.bad{color:var(--ink);font-weight:650}
main{display:grid;grid-template-columns:minmax(0,1.4fr) minmax(360px,1fr);gap:16px;align-items:start}
svg.plot{display:block;width:100%}
svg.plot text{fill:var(--ink);font:12px var(--sans)}
svg.plot .axis{fill:var(--muted);font-size:11px}
svg.plot .grid{stroke:#e6e8e5}
svg.plot .lane{fill:#f4f5f2}
.mark{cursor:default}
.mark circle{opacity:.3}
.mark.cited circle{opacity:1;stroke:var(--ink);stroke-width:1.2}
.mark .cnt{font-size:9px;font-weight:700;fill:#fff;text-anchor:middle;pointer-events:none}
.mark.hl circle{opacity:1;stroke:var(--ink);stroke-width:2.5}
#legend{display:flex;gap:14px;flex-wrap:wrap;font-size:12px;color:var(--muted);margin-bottom:4px}
.sw{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:5px;vertical-align:-1px}
.node rect{fill:#fff;stroke:#c9cdc9;stroke-width:1}
.node.cited rect{fill:var(--accent-soft);stroke:var(--accent);stroke-width:1.5}
.node.hl rect{stroke:var(--ink);stroke-width:2.5}
.node .nd{fill:var(--muted);font-size:10.5px}
.edge{fill:none;stroke:#c9cdc9;stroke-width:1.2}
.edge.cited{stroke:var(--muted);stroke-width:1.8}
.edge.stated{stroke-dasharray:4 3}
#feed-sec{max-height:calc(100vh - 24px);overflow:auto;position:sticky;top:12px}
.card{border-top:1px solid var(--ink);padding:9px 0 10px}
.card-h{display:flex;gap:10px;align-items:baseline;flex-wrap:wrap;margin-bottom:4px}
.card-h .sid{font-weight:650}
.card-h .role{color:var(--muted);font-size:13px}
.note{font-size:12.5px;color:var(--muted);margin:2px 0 4px}
.note.warn{color:var(--ink);font-weight:600}
.claim{border-top:1px solid var(--line);padding:7px 0 6px}
.claim.flash{background:var(--accent-soft)}
.claim-h{display:flex;gap:10px;align-items:baseline;font-size:12px;color:var(--muted)}
.stmt{margin:3px 0;white-space:pre-wrap;word-break:break-word;font-size:13.5px}
.chips{display:flex;flex-wrap:wrap;gap:4px;margin-top:3px}
.chip{font:11px var(--mono);padding:0 5px;background:var(--track);color:var(--ink);border:1px solid transparent;cursor:default}
.chip.unknown{border-color:var(--ink);background:#fff}
.chip.pending{border-color:var(--line);color:var(--muted);background:#fff}
.chip:hover{border-color:var(--accent)}
.links{font-size:12px;margin-top:2px;color:var(--muted)}
.links button{font:inherit;background:none;border:none;color:var(--accent);cursor:pointer;padding:0 2px;text-decoration:underline}
.verdict{font-size:12px;margin-top:3px;padding-left:8px;border-left:2px solid var(--accent)}
.verdict summary{cursor:pointer;color:var(--muted)}
.verdict .disp{color:var(--accent);font-weight:650}
details.more{margin-top:5px;font-size:12.5px}
details.more summary{cursor:pointer;color:var(--muted)}
details.more ul{margin:3px 0;padding-left:16px}
pre.raw{white-space:pre-wrap;word-break:break-word;font:11.5px var(--mono);background:var(--paper);padding:8px;max-height:260px;overflow:auto}
footer{color:var(--muted);font-size:12px;padding:6px 28px 16px}
#tip{position:fixed;z-index:10;max-width:380px;background:#fff;border:1px solid var(--ink);padding:7px 9px;font-size:12px;pointer-events:none;white-space:pre-wrap;word-break:break-word}
.empty{color:var(--muted);font-size:13px;padding:6px 0}
#tool-lanes{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:12px}
.lane-col{border-top:2px solid var(--line);padding:6px 0 0;min-width:0}
.lane-col.working{border-top-color:var(--accent)}
.lane-h{display:flex;justify-content:space-between;gap:6px;align-items:baseline}
.lane-h .role{font-weight:650;font-size:13px}
.lane-sub{font-size:11.5px;color:var(--muted);margin-bottom:3px}
ol.calls{list-style:none;margin:0;padding:0;max-height:320px;overflow:auto}
.call{border-top:1px solid var(--line);padding:4px 0}
.call.new{background:var(--accent-soft)}
.call-h{display:flex;gap:8px;align-items:baseline;font-size:11.5px;color:var(--muted);flex-wrap:wrap}
.call-h .tool{color:var(--ink);font-weight:650}
.call-h .err{color:var(--ink);font-weight:650}
.call code{display:block;font-size:11.5px;white-space:pre-wrap;word-break:break-all;color:var(--ink)}
.call .prm{font:10.5px var(--mono);color:var(--muted);word-break:break-all}
.ark{display:flex;gap:4px;align-items:center;margin-top:2px}
.ark input{flex:1;min-width:0;font:10.5px var(--mono);background:var(--paper);color:var(--ink);border:1px solid var(--line);padding:1px 4px}
.ark button,.ark a{font-size:11px;background:none;border:none;color:var(--accent);cursor:pointer;padding:0 2px;text-decoration:underline}
@media (max-width:1280px){#bots{grid-template-columns:minmax(0,1fr)}.stages{grid-template-columns:repeat(3,minmax(0,1fr))}
.stage:nth-child(3n+1){padding-left:0;border-left:0}.team{grid-template-columns:repeat(3,minmax(0,1fr))}
.team>div:nth-child(4){padding-left:0;border-left:0}main{grid-template-columns:minmax(0,1fr)}#feed-sec{position:static;max-height:none}
.wave{grid-column:1/-1!important}
:root{--screen-h:clamp(240px,50vh,620px)}}
@media (prefers-reduced-motion:reduce){*,*::before,*::after{animation:none!important;transition:none!important}}
</style>
</head>
<body>
<svg width="0" height="0" style="position:absolute" aria-hidden="true">
<symbol id="i-win" viewBox="0 0 16 16"><rect x="2" y="3" width="12" height="10" rx="1.5"/><path d="M2 6h12"/></symbol>
<symbol id="i-eye" viewBox="0 0 16 16"><path d="M1.5 8s2.4-4.5 6.5-4.5S14.5 8 14.5 8s-2.4 4.5-6.5 4.5S1.5 8 1.5 8z"/><circle cx="8" cy="8" r="2"/></symbol>
</svg>
<div id="live">
<header class="hd">
<div style="min-width:0">
<div class="brand"><span class="brand-mark">H</span><b>Hermes</b><span>/</span><span>Hunt Live</span></div>
<div class="title"><h1 id="case-id">Loading&hellip;</h1><span id="round"></span></div>
<p id="question"></p>
</div>
<div class="clock"><div class="lbl"><span id="clock-label">Round elapsed</span><span id="usage" hidden></span><span id="round-state" class="st wait"></span></div>
<span id="clock">--:--</span><div id="conn">Loading state&hellip;</div></div>
</header>
<p id="errors" hidden></p>
<section aria-label="Workflow">
<div class="wf-h"><span class="lbl">Workflow &middot; <span id="wf-count">nine</span> stages, sized by real duration</span><span id="wf-meta"></span></div>
<div id="tl-bar" class="tl-bar" role="img" aria-label="Stages sized by their recorded duration"></div>
<div id="tl-num" class="tl-num" aria-hidden="true"></div>
<ol id="stage-list" class="stages"></ol>
</section>
<section id="bots" aria-label="Bots driving a lab browser" hidden></section>
<section id="team" class="team" aria-label="Team"></section>
<section id="conclusion" aria-label="Latest conclusion"></section>
</div>
<div id="record">
<div class="rec-h"><h2>Round record</h2><span class="meta">Everything below is the same round, in full.</span></div>
<section id="tools-sec" class="sec" aria-label="Tool activity" hidden><div class="sec-h"><span class="lbl">Tool activity</span><span class="meta" id="tools-meta"></span></div><div id="tool-lanes"></div></section>
<main>
<div>
<section class="sec" aria-label="Event timeline"><div class="sec-h"><span class="lbl">Event timeline</span><span class="meta" id="tl-meta"></span></div><div id="legend"></div><svg id="timeline" class="plot" role="img" aria-label="Cited events by host over the case window"></svg></section>
<section class="sec" aria-label="Entity map"><div class="sec-h"><span class="lbl">Entity map</span><span class="meta" id="map-meta"></span></div><svg id="map" class="plot" role="img" aria-label="Hosts, processes, tasks and domains from cited events"></svg></section>
</div>
<section id="feed-sec" class="sec" aria-label="Claims feed"><div class="sec-h"><span class="lbl">Claims feed</span><span class="meta" id="feed-meta"></span></div><div id="feed"></div></section>
</main>
</div>
<footer>Synthetic lab data. Shows only what the bots wrote and what their lab browsers showed; watch-only; approvals are recorded separately.</footer>
<div id="tip" role="tooltip" hidden></div>
<script>
"use strict";
(function(){
const STATE_URL = new URL("/state.json", location.href).href;
const SVGNS = "http://www.w3.org/2000/svg";
const LIVE_FRESH_MS = 10000;
const CAT = {process:"#1e211f", network:"#315c4c", authentication:"#666c68", configuration:"#929993"};
const STATE_LABEL = {pending:"waiting", not_reached:"not reached", awaiting_approval:"waiting \u00b7 approval",
  working:"running", awaiting_review:"in review", done:"done", dropped:"dropped", stopped:"stopped"};
const OPEN = new Set(["working", "awaiting_approval", "awaiting_review"]);
const PAGE_LABEL = {kibana_discover:"Kibana Discover", arkime_sessions:"Arkime Sessions", arkime_spiview:"Arkime SPI View", lab_console:"lab console"};
const COUNT_NOUN = {elastic_search:"document", arkime_sessions:"session", arkime_unique:"unique value"};
const $ = (id) => document.getElementById(id);
let state = null, lastKey = null, fetchError = null, wfExtra = 0;

function el(tag, attrs, text){
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) node.setAttribute(k, v);
  if (text !== undefined && text !== null) node.textContent = String(text);
  return node;
}
function sv(tag, attrs, text){
  const node = document.createElementNS(SVGNS, tag);
  for (const [k, v] of Object.entries(attrs || {})) node.setAttribute(k, String(v));
  if (text !== undefined && text !== null) node.textContent = String(text);
  return node;
}
function icon(id){
  const s = sv("svg", {class:"ic", "aria-hidden":"true"}); s.appendChild(sv("use", {href:"#" + id})); return s;
}
function clear(node){ while (node.firstChild) node.removeChild(node.firstChild); }
function catColor(c){ return CAT[c] || "#b0b5b1"; }
function hhmmss(ms){ return new Date(ms).toISOString().slice(11, 19); }
function fit(text, chars){ text = String(text); return text.length > chars ? text.slice(0, Math.max(chars - 1, 1)) + "\u2026" : text; }
function pad2(n){ return String(n).padStart(2, "0"); }
function nn(index){ return pad2(index + 1); }
function dur(ms){
  if (ms === null || ms === undefined || ms < 0) return "";
  const s = Math.floor(ms / 1000), h = Math.floor(s / 3600), m = Math.floor(s % 3600 / 60);
  return (h ? h + ":" + pad2(m) : pad2(m)) + ":" + pad2(s % 60);
}
function ago(ms, now){
  const s = Math.max(0, Math.round((now - ms) / 1000));
  return s < 90 ? s + " s ago" : s < 5400 ? Math.round(s / 60) + " min ago" : Math.round(s / 3600) + " h ago";
}
function tok(n){ return n < 1000 ? String(n) : n < 1e6 ? (n / 1e3).toFixed(1) + "k" : (n / 1e6).toFixed(2) + "M"; }
function usageTip(u){
  const full = (n) => n.toLocaleString("en-US");
  return full(u.total_tokens) + " tokens: input " + full(u.input_tokens) + " \u00b7 output " + full(u.output_tokens) + " \u00b7 cache read " + full(u.cache_read_tokens);
}
function kindClass(kind){ return ["observed", "inference", "hypothesis", "finding"].includes(kind) ? kind : "other"; }

const tip = $("tip");
function showTip(evt, text){
  tip.textContent = text; tip.hidden = false;
  const pad = 14, w = tip.offsetWidth, h = tip.offsetHeight;
  let x = evt.clientX + pad, y = evt.clientY + pad;
  if (x + w > innerWidth - 4) x = Math.max(4, evt.clientX - w - pad);
  if (y + h > innerHeight - 4) y = Math.max(4, evt.clientY - h - pad);
  tip.style.left = x + "px"; tip.style.top = y + "px";
}
function hideTip(){ tip.hidden = true; }
function hover(node, textFn){
  node.addEventListener("mousemove", (e) => showTip(e, textFn()));
  node.addEventListener("mouseleave", hideTip);
}
function highlight(ids, on){
  const wanted = new Set(ids);
  document.querySelectorAll("[data-evt]").forEach((n) => { if (wanted.has(n.getAttribute("data-evt"))) n.classList.toggle("hl", on); });
  document.querySelectorAll("[data-evts]").forEach((n) => {
    if (n.getAttribute("data-evts").split(" ").some((i) => wanted.has(i))) n.classList.toggle("hl", on);
  });
}

// ---- Hunt Live (re-rendered every second from the last state) ----

function stepWord(s){
  if (s.state === "dropped") return {text:STATE_LABEL.dropped, cls:"drop"};
  const rejections = s.handoff_rejections || [];
  if (rejections.some((r) => r.outcome && r.outcome !== "retried")) return {text:"rejected", cls:"stop"};
  let text = STATE_LABEL[s.state] || s.state;
  const cls = s.state === "done" ? "" : OPEN.has(s.state) ? "run" : s.state === "stopped" ? "stop" : "wait";
  if (rejections.some((r) => r.outcome === "retried")) text = s.state === "done" ? "done \u00b7 1 retry" : "retry 1 of 1 \u00b7 " + text;
  return {text:text, cls:cls};
}
function stepTime(s, now){
  const t = s.timing || {};
  if (OPEN.has(s.state)) return t.started_ms === null || t.started_ms === undefined ? null : now - t.started_ms;
  return t.duration_ms;
}
// A bot can own several open steps in one wave; the one it is running comes first.
function workingStep(profile){
  const t = (state.team || []).find((m) => m.profile === profile);
  if (!t || t.current === null) return null;
  const busy = t.open_steps.find((o) => o.state === "working");
  return busy ? state.steps.find((s) => s.step_id === busy.step_id) : state.steps[t.current];
}

function renderHeader(now){
  const t = state.temporal || {}, run = state.run || {}, p = run.parent, c = run.child, r = state.round || {};
  $("case-id").textContent = state.case && state.case.case_id ? state.case.case_id : "case id not supplied";
  const bits = [];
  if (p) bits.push("Round " + (p.round_index || 0) + " of " + (p.rounds || "?"), p.workflow_id);
  else bits.push("practice status not observed");
  $("round").textContent = bits.filter(Boolean).join(" \u00b7 ");
  $("question").textContent = state.case && state.case.question ? state.case.question : "";
  $("question").title = $("question").textContent;
  const errs = state.input_errors || [];
  $("errors").hidden = errs.length === 0; $("errors").textContent = errs.join(" \u00b7 ");
  const ended = r.ended_ms !== null && r.ended_ms !== undefined;
  $("clock").textContent = r.started_ms === null || r.started_ms === undefined ? "--:--" : dur((ended ? r.ended_ms : now) - r.started_ms);
  $("clock-label").textContent = ended ? "Round time" : r.source === "first_stage" ? "Elapsed since first stage" : "Round elapsed";
  const u = run.usage_total, usage = $("usage");
  usage.hidden = !u;
  if (u){ usage.textContent = tok(u.total_tokens) + " tokens"; usage.title = usageTip(u); }
  const rs = $("round-state");
  if (c){
    const running = c.temporal_status === "RUNNING";
    rs.textContent = running ? "running" : (c.stage || "").replace(/_/g, " ") || (c.temporal_status || "").toLowerCase();
    rs.className = "st " + (running ? "run" : "stop");
  } else { rs.textContent = "not started"; rs.className = "st wait"; }
  const conn = $("conn"), parts = [];
  let bad = false;
  if (fetchError){ parts.push("board server unreachable (" + fetchError + "); showing last state"); bad = true; }
  if (t.error){ bad = true; parts.push(t.error + (t.last_success_at ? "; showing observation from " + t.last_success_at : "; no workflow status observed yet")); }
  else if (t.observed_at) parts.push("Temporal observed " + t.observed_at.slice(11, 19) + " UTC");
  if (c) parts.push("round " + (c.stage || "?").replace(/_/g, " "));
  conn.textContent = parts.join(" \u00b7 ") || "waiting for first status";
  conn.className = bad ? "bad" : "";
}

function stepCell(s, now, lane){
  const open = OPEN.has(s.state), word = stepWord(s), time = stepTime(s, now);
  const li = el("li", {class:(lane ? "wave-lane" : "stage") + (open ? " on" : "") + (s.state === "dropped" ? " dropped" : ""),
    "data-step":s.step_id, "data-state":s.state}), top = el("div", {class:"top"});
  top.appendChild(el("span", {class:"n"}, nn(s.index)));
  top.appendChild(el("span", {class:"nm", title:s.step_id}, s.name));
  top.appendChild(el("span", {class:"mg" + (s.state === "working" ? " on" : ""), title:s.role}, s.monogram));
  li.appendChild(top);
  if (lane){
    const sub = el("div", {class:"sub"});
    sub.appendChild(el("span", {class:"role", title:s.role}, s.role));
    if (s.usage) sub.appendChild(el("span", {class:"tok", title:usageTip(s.usage)}, tok(s.usage.total_tokens) + " tok"));
    li.appendChild(sub);
  }
  const meta = el("div", {class:"meta"});
  meta.appendChild(el("span", {class:"st " + word.cls, title:s.reason || word.text}, word.text));
  const t = el("span", {class:"t"}, time === null || time === undefined ? "" : dur(time));
  if (!lane && s.usage) t.title = usageTip(s.usage);
  meta.appendChild(t);
  li.appendChild(meta);
  if (s.state === "dropped" && s.reason) li.appendChild(el("div", {class:"why", title:s.reason}, s.reason.replace(/_/g, " ")));
  return li;
}
function wallMs(w, now){ return (w.closed_ms || 0) + (w.open_since_ms === null ? 0 : now - w.open_since_ms); }
function waveCounts(group){
  const count = (states) => group.filter((s) => states.includes(s.state)).length;
  const c = {done:count(["done"]), working:count(["working"]), awaiting:count(["awaiting_approval", "awaiting_review"]), dropped:count(["dropped"])};
  c.text = [[c.done, "done"], [c.working, "running"], [c.awaiting, "awaiting decision"], [c.dropped, "dropped"], [count(["stopped"]), "stopped"],
    [count(["pending", "not_reached"]), "waiting"]].filter((p) => p[0]).map((p) => p[0] + " " + p[1]).join(" \u00b7 ");
  return c;
}
function waveGroup(group, now){
  const c = waveCounts(group);
  const li = el("li", {class:"wave" + (c.working + c.awaiting ? " on" : ""), "data-wave":group[0].wave, "data-done":c.done,
    "data-working":c.working, "data-awaiting":c.awaiting, "data-dropped":c.dropped}), h = el("div", {class:"wave-h"});
  li.style.gridColumn = "span " + Math.min(group.length, 9);
  h.appendChild(el("span", {class:"lbl"}, "Wave " + group[0].wave));
  h.appendChild(el("span", {class:"wave-c"}, c.text));
  h.appendChild(el("span", {class:"wave-g"}, "one decision covers the wave"));
  li.appendChild(h);
  const lanes = el("ol", {class:"wave-lanes"});
  for (const s of group) lanes.appendChild(stepCell(s, now, true));
  li.appendChild(lanes);
  return li;
}
function renderWorkflow(now){
  const bar = $("tl-bar"), nums = $("tl-num"), list = $("stage-list");
  clear(bar); clear(nums); clear(list);
  const steps = state.steps;
  if (!steps.length){ list.appendChild(el("li", {class:"empty"}, "No steps (input could not be read).")); $("wf-meta").textContent = ""; return; }
  $("wf-count").textContent = steps.length === 9 ? "nine" : String(steps.length);
  const known = steps.filter((s) => s.state === "done" && s.timing && s.timing.duration_ms !== null).map((s) => s.timing.duration_ms / 1000);
  const placeholder = known.length ? known.reduce((a, b) => a + b, 0) / known.length : 120;
  const waves = new Map(), spans = new Map(state.waves.map((w) => [w.wave, w]));
  for (const s of steps){
    if (!waves.has(s.wave)) waves.set(s.wave, []);
    waves.get(s.wave).push(s);
  }
  const groups = Array.from(waves.keys()).sort((a, b) => a - b).map((w) => waves.get(w));
  const par = groups.some((g) => g.length > 1);
  list.className = "stages" + (par ? " par" : "");
  for (const group of groups){
    // One bar segment per wave, as wide as the wave's wall time: its steps overlap, so their times are not added.
    const first = group[0], last = group[group.length - 1], span = spans.get(first.wave), ms = wallMs(span, now);
    const open = group.some((s) => OPEN.has(s.state));
    let grow = placeholder, cls = "pend", fill = null, label = nn(first.index), title;
    if (open){ grow = Math.max(ms / 1000, placeholder); cls = "on"; fill = ms / 1000 / grow; }
    else if (span.closed_ms !== null){
      grow = ms / 1000; cls = group.some((s) => s.state === "done") && !group.some((s) => s.state === "stopped") ? "done" : "stop";
    }
    if (group.every((s) => s.state === "dropped")) cls = "drop";
    if (group.length > 1){
      label += last.index - first.index === group.length - 1 ? "\u2013" + nn(last.index) : " +" + (group.length - 1);
      title = "Wave " + first.wave + ": " + waveCounts(group).text + (ms > 0 ? " " + dur(ms) : "");
      list.appendChild(waveGroup(group, now));
    } else {
      const time = stepTime(first, now), li = stepCell(first, now, false);
      title = nn(first.index) + " " + first.name + ": " + stepWord(first).text + (time !== null && time !== undefined ? " " + dur(time) : "");
      li.setAttribute("data-wave", first.wave);
      list.appendChild(li);
    }
    const seg = el("span", {class:cls, title:title});
    seg.style.flexGrow = String(Math.max(grow, 1));
    if (fill !== null){ const b = el("b"); b.style.width = (fill * 100).toFixed(2) + "%"; seg.appendChild(b); }
    bar.appendChild(seg);
    const num = el("span", {class:open ? "on" : ""}, label); num.style.flexGrow = seg.style.flexGrow; nums.appendChild(num);
  }
  // The taller wave rows come out of the browser screens so Hunt Live still fits above the fold.
  const single = list.querySelector(".stage");
  const extra = par && single ? Math.max(0, list.offsetHeight - single.offsetHeight + 1) : 0;
  if (extra !== wfExtra){ wfExtra = extra; document.documentElement.style.setProperty("--wf-extra", extra + "px"); }
  const dropped = steps.filter((s) => s.state === "dropped").length, done = steps.filter((s) => s.state === "done").length + dropped;
  $("wf-meta").textContent = done + " of " + steps.length + " done" + (dropped ? " (" + dropped + " dropped)" : "") + " \u00b7 stage time " + dur(wallMs(state.stage_time, now)) + (known.length < steps.length ? " \u00b7 hatched: not reached yet, width is a placeholder" : "");
}

const frames = {};
function botFrame(profile){
  if (frames[profile]) return frames[profile];
  const art = el("article", {class:"bot"}), h = el("header", {class:"bot-h"});
  const mg = el("span", {class:"mg xl"}), mgText = document.createTextNode("");
  mg.appendChild(mgText); mg.appendChild(el("i", {class:"scr"}));
  const who = el("div", {class:"who"}), name = el("strong");
  who.appendChild(name); who.appendChild(el("small", null, "powered by Claude"));
  const cur = el("div", {class:"cur"}), curv = el("span", {class:"v"});
  cur.appendChild(el("span", {class:"lbl"}, "Current stage")); cur.appendChild(curv);
  const st = el("span", {class:"st"});
  h.appendChild(mg); h.appendChild(who); h.appendChild(cur); h.appendChild(st);
  const body = el("div", {class:"bot-b"}), mc = el("div", {class:"mc"});
  const bar = el("div", {class:"mc-bar"}), addr = el("span", {class:"mc-addr"}), watch = el("span", {class:"mc-watch"});
  bar.appendChild(icon("i-win")); bar.appendChild(addr);
  watch.appendChild(icon("i-eye")); watch.appendChild(document.createTextNode("Watch-only")); bar.appendChild(watch);
  const screen = el("div", {class:"mc-screen"}), empty = el("div", {class:"mc-empty"}), box = el("div");
  const emptyB = el("b"), emptyT = el("span");
  box.appendChild(emptyB); box.appendChild(emptyT); empty.appendChild(box); screen.appendChild(empty);
  const foot = el("div", {class:"mc-foot"});
  mc.appendChild(bar); mc.appendChild(screen); mc.appendChild(foot);
  const side = el("div", {class:"side"});
  body.appendChild(mc); body.appendChild(side);
  art.appendChild(h); art.appendChild(body);
  $("bots").appendChild(art);
  return frames[profile] = {mg:mg, mgText:mgText, name:name, curv:curv, st:st, addr:addr, screen:screen, empty:empty,
    emptyB:emptyB, emptyT:emptyT, foot:foot, side:side, img:null};
}
function frameImage(f, profile){
  if (f.img) return;
  const src = new URL("/live/" + encodeURIComponent(profile) + ".mjpg", location.href).href;
  const img = el("img", {alt:"", src:src});
  img.addEventListener("load", () => frameAspect(f));
  // The stream ends when the board restarts or a slot is busy; reconnect after a pause.
  img.addEventListener("error", () => setTimeout(() => img.setAttribute("src", src), 5000));
  f.screen.insertBefore(img, f.empty);
  f.img = img;
}
function frameAspect(f){
  if (f.img && f.img.naturalWidth && f.img.naturalHeight) f.screen.style.setProperty("--ar", f.img.naturalWidth + " / " + f.img.naturalHeight);
}
function countText(api){
  const n = api.total !== null ? api.total : api.result_count;
  return n === null ? null : n + " " + (COUNT_NOUN[api.tool] || "result") + (Number(n) === 1 ? "" : "s");
}
function renderCaption(f, b){
  clear(f.foot);
  const a = b && b.action;
  if (!a){ f.foot.appendChild(el("span", {class:"none"}, state.browsers ? "No browser action yet this round" : "Browser actions not read")); return; }
  f.foot.appendChild(el("b", null, a.verb.charAt(0).toUpperCase() + a.verb.slice(1)));
  if (a.query) f.foot.appendChild(el("code", {title:a.query}, a.query));
  else if (a.detail) f.foot.appendChild(el("span", null, a.detail));
  if (a.submitted) f.foot.appendChild(el("span", null, "+ Enter"));
  if (!a.ok) f.foot.appendChild(el("span", {class:"res"}, "refused" + (a.error ? ": " + a.error : "")));
  else if (b.api && countText(b.api)){
    const via = "count from the same query through the lab API " + b.api.tool + (b.api.time ? " at " + b.api.time : "");
    f.foot.appendChild(el("span", {class:"res", title:via}, "\u2192 " + countText(b.api)));
    f.foot.appendChild(el("span", {title:via}, "via " + b.api.tool));
  }
  f.foot.appendChild(el("span", {class:"tm", title:new Date(a.t_ms).toISOString()}, hhmmss(a.t_ms) + " UTC"));
}
function renderSide(f, o, team, now){
  clear(f.side);
  const stages = el("div");
  stages.appendChild(el("span", {class:"lbl"}, "Stages"));
  const ol = el("ol");
  for (const i of team ? team.steps : []){
    const s = state.steps[i], word = stepWord(s), time = stepTime(s, now), li = el("li");
    li.appendChild(el("span", {class:"n"}, nn(s.index)));
    li.appendChild(el("span", {class:"nm"}, s.name));
    li.appendChild(el("span", {class:"t"}, time === null || time === undefined ? "" : dur(time)));
    li.appendChild(el("span", {class:"st " + word.cls}, word.text));
    li.appendChild(el("span", {class:"c"}, s.claims === null ? "" : s.claims + " claim" + (s.claims === 1 ? "" : "s")));
    ol.appendChild(li);
  }
  stages.appendChild(ol); f.side.appendChild(stages);
  const lab = el("div");
  lab.appendChild(el("span", {class:"lbl"}, "Lab browser"));
  const dl = el("dl");
  const row = (k, v) => { dl.appendChild(el("dt", null, k)); dl.appendChild(el("dd", {title:v}, v)); };
  row("Screencast", o.attached ? "attached" : "not attached");
  row("Frames", String(o.frames));
  row("Last frame", o.last_frame_at === null ? "none yet" : hhmmss(o.last_frame_at) + " UTC");
  lab.appendChild(dl); f.side.appendChild(lab);
}
function renderBots(now){
  const live = state.live, sec = $("bots");
  sec.hidden = !live;
  if (!live) return;
  for (const o of live.owners){
    const f = botFrame(o.profile), team = (state.team || []).find((m) => m.profile === o.profile);
    const browser = (state.browsers || []).find((b) => b.profile === o.profile);
    const step = workingStep(o.profile), running = !!step && step.state === "working";
    const fresh = o.last_frame_at !== null && now - o.last_frame_at < LIVE_FRESH_MS;
    f.mgText.textContent = team ? team.monogram : o.profile.slice(0, 2).toUpperCase();
    f.mg.className = "mg xl" + (running ? " on" : "");
    f.name.textContent = o.role;
    const more = team ? team.open_steps.length - 1 : 0;
    if (step) f.curv.textContent = nn(step.index) + " " + step.name + " \u00b7 " + stepWord(step).text + (more > 0 ? " \u00b7 +" + more + " more" : "");
    else {
      const owned = team ? team.steps.map((i) => state.steps[i]) : [];
      const next = owned.find((s) => s.state === "pending"), done = owned.filter((s) => s.state === "done");
      f.curv.textContent = next ? "next " + nn(next.index) + " " + next.name : done.length ? done.map((s) => nn(s.index)).join(", ") + " done" : owned.length ? nn(owned[0].index) + " " + owned[0].name + " \u00b7 " + stepWord(owned[0]).text : "no stage";
    }
    if (o.attached && running && fresh){ f.st.textContent = "Live"; f.st.className = "st live"; }
    else if (o.last_frame_at !== null){ f.st.textContent = "idle \u00b7 last frame " + ago(o.last_frame_at, now); f.st.className = "st"; }
    else { f.st.textContent = "waiting for browser"; f.st.className = "st wait"; }
    const page = o.page ? (PAGE_LABEL[o.page] || o.page) : "page unknown";
    f.addr.textContent = "lab VM \u00b7 " + page;
    if (o.frames > 0) frameImage(f, o.profile);
    if (f.img){ f.img.setAttribute("alt", o.role + " lab browser, " + page); frameAspect(f); }
    f.empty.hidden = o.frames > 0;
    f.emptyB.textContent = "Waiting for browser";
    const waiting = team && team.steps.some((i) => state.steps[i].state === "pending");
    f.emptyT.textContent = o.attached ? "attached; no frame yet" : step ? "no lab browser open"
      : waiting ? "not this bot's turn yet" : "no frame since the board started";
    renderCaption(f, browser);
    renderSide(f, o, team, now);
  }
}

function teamLine(t, now){
  const owned = t.steps.map((i) => state.steps[i]);
  const claims = t.claims ? " \u00b7 " + t.claims + " claim" + (t.claims === 1 ? "" : "s") : "";
  if (!owned.length) return {text:"no stage in this hunt", cls:""};
  if (t.open_steps.length > 1){
    const running = t.open_steps.filter((o) => o.state === "working").length;
    return {text:t.open_steps.length + " stages open" + (running ? ", " + running + " running" : "") + ": " + t.open_steps.map((o) => o.step_id).join(", ") + claims, cls:"run"};
  }
  if (t.current !== null){
    const s = state.steps[t.current], time = stepTime(s, now);
    return {text:nn(s.index) + " " + s.name + " \u00b7 " + stepWord(s).text + (time ? " " + dur(time) : "") + claims, cls:"run"};
  }
  const done = owned.filter((s) => s.state === "done"), next = owned.find((s) => s.state === "pending"), parts = [];
  if (done.length) parts.push(done.map((s) => nn(s.index)).join(", ") + " done");
  if (next) parts.push(done.length ? "next " + nn(next.index) : nn(next.index) + " " + next.name + " \u00b7 waiting");
  if (!parts.length) parts.push(nn(owned[0].index) + " " + owned[0].name + " \u00b7 " + stepWord(owned[0]).text);
  return {text:parts.join(" \u00b7 ") + claims, cls:""};
}
function renderTeam(now){
  const box = $("team"); clear(box);
  const browsers = new Set(((state.live && state.live.owners) || []).map((o) => o.profile));
  for (const t of state.team || []){
    const cell = el("div"), step = workingStep(t.profile);
    const mg = el("span", {class:"mg" + (step && step.state === "working" ? " on" : "")}, t.monogram);
    if (browsers.has(t.profile)) mg.appendChild(el("i", {class:"scr"}));
    const line = teamLine(t, now), text = el("div");
    text.appendChild(el("strong", {title:t.role}, t.role));
    text.appendChild(el("small", {class:line.cls, title:line.text}, line.text));
    cell.appendChild(mg); cell.appendChild(text); box.appendChild(cell);
  }
}
function renderConclusion(){
  const box = $("conclusion"), c = state.latest_conclusion; clear(box);
  box.appendChild(el("span", {class:"lbl"}, "Latest conclusion"));
  if (!c){ box.appendChild(el("p", {class:"none"}, "No stage has completed with a claim yet.")); return; }
  box.appendChild(el("span", {class:"kind k-" + kindClass(c.kind)}, c.kind || "no kind"));
  box.appendChild(el("span", {class:"src"}, nn(c.index) + " " + c.name + " \u00b7 " + c.role));
  box.appendChild(el("p", {title:c.statement}, c.statement || "(empty statement)"));
}
function renderLive(){
  const now = Date.now();
  renderHeader(now); renderWorkflow(now); renderBots(now); renderTeam(now); renderConclusion();
}

// ---- Round record (re-rendered when the round's content changes) ----

function niceStep(span){
  const steps = [1e3,5e3,15e3,3e4,6e4,12e4,3e5,6e5,9e5,18e5,36e5,72e5,216e5,432e5,864e5];
  for (const s of steps) if (span / s <= 10) return s;
  return steps[steps.length - 1];
}

function renderLegend(){
  const legend = $("legend"); clear(legend);
  const cats = Array.from(new Set(state.timeline.events.map((e) => e.category)));
  for (const c of cats){
    const item = el("span"); const sw = el("span", {class:"sw"}); sw.style.background = catColor(c);
    item.appendChild(sw); item.appendChild(document.createTextNode(c)); legend.appendChild(item);
  }
  legend.appendChild(el("span", null, "solid mark = cited by an accepted or in-review step; number = steps citing it"));
}

function renderTimeline(){
  const svg = $("timeline"); clear(svg);
  const tl = state.timeline, events = tl.events;
  const W = Math.max(svg.clientWidth || 640, 420), LABEL = 118, RIGHT = 30, TOP = 8, AXIS = 22, SLOT = 16, GAP = 15;
  const lanes = tl.lanes.length ? tl.lanes : [];
  const meta = [];
  if (!events.length || tl.start_ms === null){
    svg.setAttribute("viewBox", "0 0 " + W + " 40"); svg.setAttribute("height", 40);
    svg.appendChild(sv("text", {x:8, y:24, class:"axis"}, fromLab() ? "No cited events looked up in the lab yet." : "No timestamped events in the supplied input."));
    $("tl-meta").textContent = events.length + (fromLab() ? " cited events looked up" : " events") + pendingNote(); return;
  }
  const t0 = tl.start_ms, t1 = tl.end_ms, plotW = W - LABEL - RIGHT;
  const x = (ms) => LABEL + (ms - t0) / (t1 - t0) * plotW;
  // Stack marks that would overlap horizontally into slots inside their host lane.
  const placed = lanes.map(() => []), slotEnds = lanes.map(() => []);
  let outside = 0, untimed = 0;
  for (const e of events){
    if (e.t_ms === null){ untimed++; continue; }
    if (e.t_ms < t0 || e.t_ms >= t1){ outside++; continue; }
    const lane = lanes.indexOf(e.host), cx = x(e.t_ms), ends = slotEnds[lane];
    let k = ends.findIndex((end) => cx - end >= GAP);
    if (k < 0){ k = ends.length; ends.push(cx); } else ends[k] = cx;
    placed[lane].push({e: e, cx: cx, k: k});
  }
  const laneH = slotEnds.map((ends) => Math.max(46, ends.length * SLOT + 16)), laneTop = [];
  let acc = TOP;
  for (const h of laneH){ laneTop.push(acc); acc += h; }
  const H = Math.max(acc, TOP + 46) + AXIS;
  svg.setAttribute("viewBox", "0 0 " + W + " " + H); svg.setAttribute("height", H);
  const step = niceStep(t1 - t0);
  for (let t = Math.ceil(t0 / step) * step; t <= t1; t += step){
    svg.appendChild(sv("line", {x1:x(t), x2:x(t), y1:TOP, y2:H - AXIS, class:"grid"}));
    svg.appendChild(sv("text", {x:x(t), y:H - 6, class:"axis", "text-anchor":"middle"}, hhmmss(t)));
  }
  lanes.forEach((lane, i) => {
    svg.appendChild(sv("rect", {x:LABEL, y:laneTop[i] + 2, width:plotW, height:laneH[i] - 4, class:"lane"}));
    svg.appendChild(sv("text", {x:LABEL - 8, y:laneTop[i] + laneH[i] / 2 + 4, "text-anchor":"end"}, fit(lane === null ? "(no host field)" : lane, 18)));
  });
  placed.forEach((marks, i) => {
    const mid = laneTop[i] + laneH[i] / 2, slots = slotEnds[i].length;
    for (const m of marks){
      const e = m.e, cy = mid + (m.k - (slots - 1) / 2) * SLOT;
      const g = sv("g", {class:"mark" + (e.cite_count ? " cited" : ""), "data-evt":e.id});
      g.appendChild(sv("circle", {cx:m.cx, cy:cy, r:e.cite_count ? 7 : 5, fill:catColor(e.category)}));
      if (e.cite_count) g.appendChild(sv("text", {x:m.cx, y:cy + 3.2, class:"cnt"}, e.cite_count));
      hover(g, () => [e.id + "  " + (e.timestamp || "no timestamp"), "host: " + (e.host || "(none)") + (e.host_ip ? " " + e.host_ip : ""),
        e.category + (e.type ? "/" + e.type : "") + (e.code ? " code " + e.code : ""), e.summary,
        e.cite_count ? "cited by " + e.cite_count + " step" + (e.cite_count === 1 ? "" : "s") + ": " + e.cited_by.join(", ")
          : "not cited by any accepted or in-review step"].join("\n"));
      svg.appendChild(g);
    }
  });
  const cited = events.filter((e) => e.cite_count).length;
  meta.push(events.length + (fromLab() ? " cited events looked up" + pendingNote() : " events"), cited + " cited", "window " + hhmmss(t0) + "\u2013" + hhmmss(t1) + " UTC" + (tl.window_source === "events" ? " (from event times; case window missing)" : ""));
  if (outside) meta.push(outside + " outside window");
  if (untimed) meta.push(untimed + " without timestamp");
  $("tl-meta").textContent = meta.join(" \u00b7 ");
}

function nodeDetail(n){
  const d = n.detail || {}, bits = [];
  if (n.kind === "host"){ if (d.ip) bits.push(d.ip); }
  if (n.kind === "process"){ if (d.pid !== null && d.pid !== undefined) bits.push("pid " + d.pid); if (d.entity_id) bits.push(d.entity_id); }
  if (n.kind === "task"){ if (d.interval_seconds !== null && d.interval_seconds !== undefined) bits.push("interval " + d.interval_seconds + " s"); if (d.stated_domain) bits.push("states " + d.stated_domain); }
  if (n.sessions) bits.push(n.sessions + " network session" + (n.sessions === 1 ? "" : "s"));
  return bits.join(" \u00b7 ");
}

function renderMap(){
  const svg = $("map"); clear(svg);
  const g = state.graph, nodes = g.nodes;
  const W = Math.max(svg.clientWidth || 640, 420);
  if (!nodes.length){
    svg.setAttribute("viewBox", "0 0 " + W + " 40"); svg.setAttribute("height", 40);
    svg.appendChild(sv("text", {x:8, y:24, class:"axis"}, fromLab() ? "No host, process, task or DNS entities in the looked-up cited events yet." : "No host, process, task or DNS entities in the supplied input."));
    $("map-meta").textContent = ""; return;
  }
  const ROW = 50, TOP = 24, NH = 36, maxRows = Math.max(...g.layer_sizes, 1);
  const H = TOP + maxRows * ROW + 6;
  svg.setAttribute("viewBox", "0 0 " + W + " " + H); svg.setAttribute("height", H);
  const NW = Math.min(220, (W - 40) / 3 - 24), gap = (W - 20 - 3 * NW) / 2;
  const pos = new Map();
  for (const n of nodes){
    const count = g.layer_sizes[n.layer] || 1, span = maxRows * ROW;
    const y = TOP + span * (n.row + 0.5) / count - NH / 2;
    pos.set(n.id, {x:10 + n.layer * (NW + gap), y:y});
  }
  ["Hosts", "Processes / tasks", "Domains"].forEach((h, i) => {
    if (g.layer_sizes[i]) svg.appendChild(sv("text", {x:10 + i * (NW + gap), y:13, class:"axis"}, h));
  });
  for (const e of g.edges){
    const a = pos.get(e.source), b = pos.get(e.target);
    if (!a || !b) continue;
    const x1 = a.x + NW, y1 = a.y + NH / 2, x2 = b.x, y2 = b.y + NH / 2, mx = (x1 + x2) / 2;
    const path = sv("path", {d:"M" + x1 + "," + y1 + " C" + mx + "," + y1 + " " + mx + "," + y2 + " " + x2 + "," + y2,
      class:"edge" + (e.cited_event_ids.length ? " cited" : "") + (e.kind === "stated" ? " stated" : "")});
    svg.appendChild(path);
  }
  const chars = Math.floor((NW - 14) / 6.6);
  for (const n of nodes){
    const p = pos.get(n.id);
    const grp = sv("g", {class:"node" + (n.cited_event_ids.length ? " cited" : ""), "data-evts":n.event_ids.join(" ")});
    grp.appendChild(sv("rect", {x:p.x, y:p.y, width:NW, height:NH}));
    grp.appendChild(sv("text", {x:p.x + 7, y:p.y + 15}, fit(n.label, chars)));
    const detail = nodeDetail(n);
    grp.appendChild(sv("text", {x:p.x + 7, y:p.y + 29, class:"nd"}, fit(detail || n.kind, chars + 4)));
    hover(grp, () => [n.kind + ": " + n.label, detail, n.event_ids.length + (fromLab() ? " looked-up cited events involve it" : " supplied events involve it"),
      n.cited_event_ids.length ? "cited: " + n.cited_event_ids.join(", ") : "none of its events cited yet"].filter(Boolean).join("\n"));
    svg.appendChild(grp);
  }
  const lit = nodes.filter((n) => n.cited_event_ids.length).length;
  $("map-meta").textContent = nodes.length + " entities \u00b7 " + lit + " lit by cited events" + (state.network.session_count === null ? "" : " \u00b7 " + state.network.session_count + " network sessions");
}

function fromLab(){ return state.mode === "tool_driven"; }
function pendingNote(){
  const n = (state.pending_event_ids || []).length;
  return n ? " (" + n + " lookup" + (n === 1 ? "" : "s") + " pending)" : "";
}
function chip(id, known){
  const pending = !known && (state.pending_event_ids || []).includes(id);
  const c = el("span", {class:"chip" + (known ? "" : pending ? " pending" : " unknown")}, id);
  c.addEventListener("mouseenter", () => highlight([id], true));
  c.addEventListener("mouseleave", () => highlight([id], false));
  if (pending) c.title = "lab lookup pending";
  else if (!known) c.title = fromLab() ? "not found in the lab case" : "not an event id in the supplied input";
  return c;
}
function claimLink(id){
  const b = el("button", {type:"button"}, id);
  b.addEventListener("click", () => {
    const target = document.querySelector('[data-claim="' + CSS.escape(id) + '"]');
    if (target){ target.scrollIntoView({block:"center"}); target.classList.add("flash"); setTimeout(() => target.classList.remove("flash"), 1200); }
  });
  return b;
}
function moreList(key, title, items){
  const d = el("details", {class:"more", "data-key":key}); d.appendChild(el("summary", null, title + " (" + items.length + ")"));
  const ul = el("ul"); for (const it of items) ul.appendChild(el("li", null, it)); d.appendChild(ul); return d;
}

function renderFeed(){
  const feed = $("feed"), open = new Set(Array.from(feed.querySelectorAll("details[open]")).map((d) => d.getAttribute("data-key")));
  const scroll = $("feed-sec").scrollTop; clear(feed);
  const known = new Set(state.timeline.events.map((e) => e.id));
  if (!state.feed.length) feed.appendChild(el("div", {class:"empty"}, "No step has returned output yet."));
  let claims = 0;
  for (const item of state.feed){
    const card = el("div", {class:"card"}), h = el("div", {class:"card-h"});
    h.appendChild(el("span", {class:"sid"}, nn(item.index) + " " + item.step_id));
    h.appendChild(el("span", {class:"role"}, item.role));
    const word = item.state === "done" ? "" : item.state === "stopped" ? "stop" : item.state === "dropped" ? "drop" : OPEN.has(item.state) ? "run" : "wait";
    h.appendChild(el("span", {class:"st " + word}, STATE_LABEL[item.state] || item.state));
    const ho = item.handoff;
    if (ho && ho.disposition) h.appendChild(el("span", {class:"st", title:"step disposition written by the bot"}, ho.disposition.replace(/_/g, " ")));
    card.appendChild(h);
    if (item.result_status !== "completed") card.appendChild(el("div", {class:"note warn"}, "Result status " + item.result_status + (item.reason_code ? " (" + item.reason_code + ")" : "")));
    if (item.state === "awaiting_review") card.appendChild(el("div", {class:"note"}, "Waiting for human review; not yet accepted."));
    if (item.state === "stopped") card.appendChild(el("div", {class:"note warn"}, "Workflow stopped at this step (" + (item.reason || "unknown") + "); its citations are not counted."));
    if (item.state === "dropped") card.appendChild(el("div", {class:"note warn"}, "Step dropped (" + (item.reason || "no reason given") + "); the hunt continued without it and its citations are not counted."));
    if (!ho){
      card.appendChild(el("div", {class:"note warn"}, "Output not shown as a handoff: " + (item.parse_error || "unparsed") + " (" + item.output_chars + " characters)."));
      if (item.raw_excerpt){
        const d = el("details", {class:"more", "data-key":"raw-" + item.step_id}); d.appendChild(el("summary", null, "raw output excerpt"));
        d.appendChild(el("pre", {class:"raw"}, item.raw_excerpt)); card.appendChild(d);
      }
      feed.appendChild(card); continue;
    }
    if (item.unknown_cited_ids.length){
      const n = el("div", {class:"note warn"}, fromLab() ? "Cites ids not found in the lab case: " : "Cites ids not in the supplied events: "); const cs = el("span", {class:"chips"});
      for (const id of item.unknown_cited_ids) cs.appendChild(chip(id, false)); n.appendChild(cs); card.appendChild(n);
    }
    for (const c of ho.claims){
      claims++;
      const div = el("div", {class:"claim", "data-claim":c.claim_id || ""}), ch = el("div", {class:"claim-h"});
      ch.appendChild(el("span", {class:"kind k-" + kindClass(c.kind)}, c.kind || "no kind"));
      ch.appendChild(el("span", null, c.claim_id || "(no claim id)"));
      div.appendChild(ch); div.appendChild(el("div", {class:"stmt"}, c.statement || "(empty statement)"));
      if (c.cited_events.length){ const cs = el("div", {class:"chips"}); for (const id of c.cited_events) cs.appendChild(chip(id, known.has(id))); div.appendChild(cs); }
      if (c.contradicts.length){ const l = el("div", {class:"links"}, "contradicts "); for (const id of c.contradicts) l.appendChild(claimLink(id)); div.appendChild(l); }
      if (c.contradicted_by && c.contradicted_by.length){ const l = el("div", {class:"links"}, "contradicted by "); for (const id of c.contradicted_by) l.appendChild(claimLink(id)); div.appendChild(l); }
      for (const v of c.verdicts || []){
        const d = el("details", {class:"verdict", "data-key":"v-" + c.claim_id + "-" + v.review_id}), s = el("summary");
        s.appendChild(el("span", {class:"disp"}, v.disposition || "no disposition"));
        s.appendChild(document.createTextNode(" \u2014 " + (v.review_id || "review") + " by " + v.role));
        d.appendChild(s); d.appendChild(el("div", {class:"stmt"}, v.rationale)); div.appendChild(d);
      }
      card.appendChild(div);
    }
    for (const r of ho.reviews){
      const div = el("div", {class:"claim"}), rh = el("div", {class:"claim-h"});
      rh.appendChild(el("span", {class:"kind k-other"}, "review"));
      rh.appendChild(el("span", null, (r.review_id || "(no review id)") + " \u2192 " + (r.disposition || "no disposition")));
      div.appendChild(rh);
      const l = el("div", {class:"links"}, "names "); for (const id of r.claim_ids) l.appendChild(claimLink(id)); div.appendChild(l);
      div.appendChild(el("div", {class:"stmt"}, r.rationale));
      if (r.cited_events.length){ const cs = el("div", {class:"chips"}); for (const id of r.cited_events) cs.appendChild(chip(id, known.has(id))); div.appendChild(cs); }
      card.appendChild(div);
    }
    if (ho.limitations.length) card.appendChild(moreList("lim-" + item.step_id, "Limitations", ho.limitations));
    if (ho.requested_decisions.length) card.appendChild(moreList("req-" + item.step_id, "Requested human decisions", ho.requested_decisions));
    feed.appendChild(card);
  }
  feed.querySelectorAll("details").forEach((d) => { if (open.has(d.getAttribute("data-key"))) d.open = true; });
  $("feed-sec").scrollTop = scroll;
  $("feed-meta").textContent = state.feed.length + " step outputs \u00b7 " + claims + " claims \u00b7 newest first";
}

function callCounts(e){
  if (e.error) return null;
  if (e.result_count !== null && e.total !== null) return e.result_count + " of " + e.total;
  if (e.result_count !== null) return e.result_count + " results";
  return e.total !== null ? e.total + " total" : "";
}
function arkimeLink(url){
  const box = el("div", {class:"ark"});
  const input = el("input", {type:"text", readonly:"", value:url, "aria-label":"Arkime UI URL", spellcheck:"false"});
  input.addEventListener("focus", () => input.select());
  const copy = el("button", {type:"button"}, "copy");
  copy.addEventListener("click", () => {
    const fallback = () => { input.focus(); input.select(); copy.textContent = "selected"; };
    if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(url).then(() => { copy.textContent = "copied"; }, fallback);
    else fallback();
  });
  box.appendChild(input); box.appendChild(copy);
  if (url.startsWith("http://127.0.0.1:")) box.appendChild(el("a", {href:url, target:"_blank", rel:"noopener noreferrer"}, "open"));
  return box;
}
function renderToolsMeta(){
  const t = state.tools;
  if (!t) return;
  const lab = t.lab || {}, meta = [];
  if (lab.error) meta.push(lab.error + (lab.last_success_at ? "; showing activity from " + lab.last_success_at : ""));
  else if (lab.observed_at) meta.push("lab observed " + lab.observed_at);
  else meta.push("lab not observed yet");
  meta.push(t.entry_count + " tool calls", t.events_looked_up + " cited events looked up" + (t.events_not_found ? ", " + t.events_not_found + " not found" : ""));
  if (t.lookup_truncated) meta.push("lookup cap reached");
  if (!lab.arkime_url) meta.push("Arkime URL unknown; links omitted");
  $("tools-meta").textContent = meta.join(" \u00b7 ");
  $("tools-meta").className = lab.error ? "meta bad" : "meta";
}
function renderTools(){
  const sec = $("tools-sec"), t = state.tools;
  sec.hidden = !t;
  if (!t) return;
  const host = $("tool-lanes"), scrolls = new Map();
  host.querySelectorAll("[data-lane]").forEach((n) => scrolls.set(n.getAttribute("data-lane"), n.scrollTop));
  clear(host);
  for (const lane of t.lanes){
    const col = el("div", {class:"lane-col" + (lane.working ? " working" : "")});
    const h = el("div", {class:"lane-h"});
    h.appendChild(el("span", {class:"role"}, lane.role));
    if (lane.working) h.appendChild(el("span", {class:"st run", title:"tool calls are logged per bot, so steps of one bot share this lane"}, "running" + (lane.working_steps > 1 ? " \u00b7 " + lane.working_steps + " steps" : "")));
    col.appendChild(h);
    col.appendChild(el("div", {class:"lane-sub"}, lane.profile + " \u00b7 " + lane.count + " call" + (lane.count === 1 ? "" : "s") + (lane.errors ? " \u00b7 " + lane.errors + " error" + (lane.errors === 1 ? "" : "s") : "")));
    const list = el("ol", {class:"calls", "data-lane":lane.profile});
    if (!lane.entries.length) list.appendChild(el("li", {class:"empty"}, "No tool calls yet."));
    for (const e of lane.entries){
      const li = el("li", {class:"call" + (e.new ? " new" : "")}), ch = el("div", {class:"call-h"});
      ch.appendChild(el("span", null, typeof e.time === "string" && e.time.length >= 19 ? e.time.slice(11, 19) : (e.time || "")));
      ch.appendChild(el("span", {class:"tool", title:e.endpoint}, e.tool));
      const counts = callCounts(e);
      if (e.error) ch.appendChild(el("span", {class:"err"}, "error " + e.error));
      else if (counts) ch.appendChild(el("span", null, counts));
      li.appendChild(ch);
      li.appendChild(el("code", {title:e.query}, e.query || "(empty query: all case data)"));
      const prm = Object.entries(e.params || {}).map(([k, v]) => k + "=" + v).join(" ");
      if (prm) li.appendChild(el("div", {class:"prm"}, prm));
      if (e.arkime_ui_url) li.appendChild(arkimeLink(e.arkime_ui_url));
      list.appendChild(li);
    }
    col.appendChild(list); host.appendChild(col);
    if (scrolls.has(lane.profile)) list.scrollTop = scrolls.get(lane.profile);
  }
}

function renderRecord(){
  renderTools(); renderLegend(); renderTimeline(); renderMap(); renderFeed();
}

async function poll(){
  try {
    const res = await fetch(STATE_URL, {cache:"no-store", credentials:"omit"});
    if (!res.ok) throw new Error("HTTP " + res.status);
    const next = await res.json();
    fetchError = null; state = next;
    // Observation timestamps change every poll; re-render the record only when its content changes.
    const tools = next.tools ? Object.assign({}, next.tools, {lab:null}) : null;
    const key = JSON.stringify(Object.assign({}, next, {temporal:null, tools:tools, live:null}));
    if (key !== lastKey){ lastKey = key; renderRecord(); }
  } catch (err){
    fetchError = err && err.message ? err.message : "fetch failed";
  }
  if (state){ renderLive(); renderToolsMeta(); } else { $("conn").textContent = "board server unreachable (" + fetchError + ")"; $("conn").className = "bad"; }
  setTimeout(poll, 2000);
}
// The clock, running stage and frame freshness move every second between polls.
setInterval(() => { if (state) renderLive(); }, 1000);
let resizeTimer = null;
addEventListener("resize", () => { clearTimeout(resizeTimer); resizeTimer = setTimeout(() => { if (state){ renderTimeline(); renderMap(); } }, 150); });
poll();
})();
</script>
</body>
</html>
"""


if __name__ == "__main__":
    raise SystemExit(main())

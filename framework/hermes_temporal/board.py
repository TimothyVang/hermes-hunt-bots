"""Read-only live board for a supplied-evidence practice hunt: the Hunt Command page.

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
import hmac
import json
import re
import secrets
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
from .lab_input import LabInputError, lab_get, loopback_base, resolve_lab
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
        status, diagnostic = result.get("status"), _text(result.get("diagnostic"))
        view["result"] = {"status": status, "reason_code": result.get("reason_code"), "diagnostic": diagnostic}
        handoff, error = (parse_handoff(result.get("output")) if status == "completed"
                          else (None, f"result status is {status}; no output to parse"))
        counted = handoff is not None and state in _CITED_STATES
        view["result"].update(parsed=handoff is not None, parse_error=error, counted=counted)
        output = result.get("output") if isinstance(result.get("output"), str) else ""
        item = {"index": index, "step_id": step.step_id, "profile": step.profile, "role": role,
                "state": state, "reason": reason, "result_status": status,
                "reason_code": result.get("reason_code"), "diagnostic": diagnostic, "parsed": handoff is not None,
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


_QUERY_KEYS = ("expression", "q", "filter", "values")


def _query_text(params: dict) -> str:
    """The bot's own query, expression, packet filter or lookup values, as the lab recorded them."""
    for key in _QUERY_KEYS:
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
                       if key not in _QUERY_KEYS},
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


_LAB_UP_NOT_THIS_INPUT = {
    "case_mismatch": "the lab has a different case loaded than this input",
    "ambiguous_lab": "both the VM and a connected service serve this case (ambiguous_lab)",
}


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
        self._instance: str | None = None
        self._secret: str | None = None
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
                self._instance, self._secret = endpoints.get("instance"), endpoints.get("secret")
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
        body = self._get(self._lab_url, path, profile=BOARD_LAB_PROFILE, timeout=_LAB_TIMEOUT_SECONDS,
                         instance=self._instance, secret=self._secret)
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
            for hit in self._search(batch):
                row = _nest(hit) if isinstance(hit, dict) else {}
                if _get(row, "event", "id") in batch:
                    self._events[row["event"]["id"]] = row
            self._missing.update(event_id for event_id in batch if event_id not in self._events)

    def _search(self, batch: list[str]) -> list:
        """The lab's hits for ``event.id:(batch)``.

        A connected service refuses a query naming any citation it never served (``unknown_citation``)
        rather than answer no hits, so such a batch is looked up one ID at a time.
        """
        query = "event.id:(" + " OR ".join(f'"{item}"' for item in batch) + ")"
        try:
            body = self._call("/es/search?" + parse.urlencode({"q": query, "size": 200, "fields": _LOOKUP_FIELDS}))
        except LabInputError as exc:
            if exc.code != "unknown_citation":
                raise
            return [] if len(batch) == 1 else [hit for event_id in batch for hit in self._search([event_id])]
        if not isinstance(body.get("hits"), list):
            raise _LabRefused("lab search response is malformed")
        return body["hits"]


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


def _handler(board: Board, token: str) -> type[BaseHTTPRequestHandler]:
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
            path, _, query = self.path.partition("?")
            if self.headers.get("Host") != f"127.0.0.1:{port}":
                # Refuse other Host names so a rebinding page cannot read the board.
                self._send(404, b"not found\n", "text/plain; charset=utf-8")
            elif path == "/":
                csp = content_security_policy(port)
                page = PAGE.replace("__CSP__", csp).replace("__BOARD_TOKEN__", token)
                self._send(200, page.encode("utf-8"), "text/html; charset=utf-8", {"Content-Security-Policy": csp})
            elif path == "/state.json":
                origin = self.headers.get("Origin")
                cross = origin is not None or self.headers.get("Sec-Fetch-Site", "none") not in ("same-origin", "none")
                if cross and not self._has_token(query):
                    # A read from another origin, the desktop's opaque sandbox included, needs this run's page token.
                    # Electron sends no Origin from a file:// page, so Sec-Fetch-Site is checked as well.
                    self._send(403, b"forbidden\n", "text/plain; charset=utf-8", {"Vary": "Origin"})
                    return
                headers = {"Vary": "Origin"}
                if origin == "null":
                    headers["Access-Control-Allow-Origin"] = "null"
                self._send(200, board.state_bytes(), "application/json; charset=utf-8", headers)
            elif live_path := _LIVE_PATH.fullmatch(path):
                # Without the token, only a plain <img> load: its pixels stay unreadable to another origin's script.
                if self._has_token(query) or (self.headers.get("Sec-Fetch-Dest") == "image"
                                              and self.headers.get("Origin") is None):
                    self._live(*live_path.groups())
                else:
                    self._send(403, b"forbidden\n", "text/plain; charset=utf-8")
            else:
                self._send(404, b"not found\n", "text/plain; charset=utf-8")

        def _has_token(self, query: str) -> bool:
            values = parse.parse_qs(query, keep_blank_values=True).get("token", [])
            return len(values) == 1 and hmac.compare_digest(values[0].encode("utf-8"), token.encode("utf-8"))

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
    """Bind the read-only board to loopback only; ``port=0`` picks a free port.

    Each server draws a new page token (``server.token``) that ``GET /`` writes into the page; see ``do_GET``."""
    token = secrets.token_urlsafe(32)
    server = ThreadingHTTPServer((BIND_HOST, port), _handler(board, token))
    server.daemon_threads = True
    server.token = token
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
    parser.add_argument("--lab-state-dir",
                        help="tool-driven input: the Network Analyst's hunt-lab-vm state dir; the lab serving the input's "
                             "case, and the caller secret it requires, are found from it (the VM's status, or a "
                             "connected service's state)")
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

    def resolve() -> dict:
        try:
            served = resolve_lab(args.lab_state_dir, case_id)
        except LabInputError as exc:
            if exc.code in _LAB_UP_NOT_THIS_INPUT:
                raise _LabRefused(_LAB_UP_NOT_THIS_INPUT[exc.code]) from None
            raise
        try:
            arkime = loopback_base(served.arkime_url)
        except LabInputError:
            arkime = None
        return {"lab_url": served.lab_url, "arkime_url": arkime, "instance": served.instance, "secret": served.secret,
                **override}

    return LabObserver(resolve, case_id, activity_after=after)


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
    has_lab = bool(args.lab_state_dir)
    if initial["mode"] == "tool_driven" and not has_lab:
        print("error: a tool-driven input needs --lab-state-dir", file=sys.stderr)
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


# Self-contained page; every data value is inserted via textContent/attributes.
PAGE = Path(__file__).with_name("board_page.html").read_text(encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())

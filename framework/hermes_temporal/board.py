"""Read-only live board for a supplied-evidence practice hunt.

The board renders only the supplied lab input and the actual Temporal status of a
practice parent and its current round. It never signals, approves, starts, or stops
a workflow; it only issues the same status queries as ``cli practice-status``/``status``.
For a ``tool_driven`` input it also polls the loopback lab's read-only ``/activity`` ring
and looks up the events the bots cite by ``event.id``; it never runs any other lab query.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import re
import sys
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Iterable
from urllib import parse

from .contracts import validate_loopback_address
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


def _run_summary(parent: dict | None, child: dict | None) -> dict:
    parent_keys = ("workflow_id", "stage", "temporal_status", "round_index", "rounds",
                   "completed_rounds", "last_result", "child_workflow_id")
    child_keys = ("stage", "step_id", "execution_id", "temporal_status")
    return {
        "parent": {key: parent.get(key) for key in parent_keys} if isinstance(parent, dict) else None,
        "child": {key: child.get(key) for key in child_keys} if isinstance(child, dict) else None,
    }


def build_state(raw_input: dict, parent: dict | None, child: dict | None, lab: dict | None = None) -> dict:
    """Derive the complete board view from the lab input and observed statuses.

    ``lab`` is a :meth:`LabObserver.snapshot` for a tool-driven input; it supplies the
    looked-up cited events and the lab's tool activity in place of inline evidence.
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
    step_ids = [step.step_id for step in steps]
    states = _step_states(len(steps), step_ids, child)
    results = child.get("results") if isinstance(child, dict) and isinstance(child.get("results"), list) else []
    rejections = (child.get("handoff_rejections") if isinstance(child, dict)
                  and isinstance(child.get("handoff_rejections"), list) else [])
    known_events = {event["id"] for event in events}

    step_views, feed = [], []
    citations: dict[str, list[str]] = {}
    claim_reviews: dict[str, list[dict]] = {}
    contradicted_by: dict[str, list[str]] = {}
    for index, step in enumerate(steps):
        state, reason = states[index]
        result = results[index] if index < len(results) and isinstance(results[index], dict) else None
        role = ROLE_TITLES.get(step.profile, step.profile)
        view = {"index": index, "step_id": step.step_id, "profile": step.profile, "role": role,
                "state": state, "reason": reason, "result": None,
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
    working = next((step.profile for step, (state, _reason) in zip(steps, states) if state == "working"), None)
    return {
        "board_version": 2,
        "mode": "tool_driven" if tool_driven else "inline",
        "case": case,
        "scope": _text(raw.get("scope")),
        "input_errors": input_errors,
        "run": _run_summary(parent, child),
        "steps": step_views,
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


def _tool_view(lab: dict, case: dict, working_profile: str | None) -> dict:
    entries = [entry for entry in lab.get("activity") or () if isinstance(entry, dict)]
    new_after = lab.get("new_after") if type(lab.get("new_after")) is int else None
    lanes: dict[str, dict] = {
        profile: {"profile": profile, "role": role, "count": 0, "errors": 0, "entries": [],
                  "working": profile == working_profile, "active": False}
        for profile, role in ROLE_TITLES.items()
    }
    for entry in sorted(entries, key=lambda item: item.get("seq") if type(item.get("seq")) is int else -1,
                        reverse=True):
        profile = entry.get("profile") if entry.get("profile") in ROLE_TITLES else "unknown"
        lane = lanes.setdefault(profile, {"profile": "unknown", "role": "Unattributed", "count": 0, "errors": 0,
                                          "entries": [], "working": False, "active": False})
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
        "working_profile": working_profile,
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
    """Query parent and current-child status through one persistent loopback client."""

    def __init__(self, address: str, workflow_id: str) -> None:
        self._address = validate_loopback_address(address)
        self._workflow_id = workflow_id
        self._client = None
        self._loop = asyncio.new_event_loop()
        threading.Thread(target=self._loop.run_forever, name="hunt-board-temporal", daemon=True).start()

    def __call__(self) -> tuple[dict, dict | None]:
        future = asyncio.run_coroutine_threadsafe(self._observe(), self._loop)
        try:
            return future.result(timeout=_QUERY_TIMEOUT_SECONDS * 3)
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
            try:
                child = await self._status(parent["child_workflow_id"], HermesWorkflow.status)
            except Exception as exc:
                raise ObservationError(f"round status query failed ({type(exc).__name__})", True) from None
        return parent, child

    async def _status(self, workflow_id: str, query) -> dict:
        handle = self._client.get_workflow_handle(workflow_id)
        state = await asyncio.wait_for(handle.query(query), _QUERY_TIMEOUT_SECONDS)
        execution = await asyncio.wait_for(handle.describe(), _QUERY_TIMEOUT_SECONDS)
        status = execution.status.name if execution.status is not None else None
        return _plain({**vars(state), "temporal_status": status})


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
    """Cache one observation for ``interval`` seconds and serve the derived state."""

    def __init__(self, raw_input: dict, observe: Callable[[], tuple[dict, dict | None]],
                 interval: float = POLL_INTERVAL_SECONDS, clock: Callable[[], float] = time.monotonic,
                 lab: LabObserver | None = None) -> None:
        self._raw = raw_input
        self._observe = observe
        self._interval = interval
        self._clock = clock
        self._lab = lab
        self._lock = threading.Lock()
        self._polled_at: float | None = None
        self._parent: dict | None = None
        self._child: dict | None = None
        self._temporal = {"reachable": None, "error": None, "observed_at": None, "last_success_at": None}
        self._body: bytes | None = None

    def state_bytes(self) -> bytes:
        with self._lock:
            now = self._clock()
            if self._polled_at is None or now - self._polled_at >= self._interval:
                self._polled_at = now
                self._poll()
                if self._lab is not None:
                    self._lab.refresh(cited_event_ids(self._child))
                self._body = None
            if self._body is None:
                lab = self._lab.snapshot() if self._lab is not None else None
                state = build_state(self._raw, self._parent, self._child, lab)
                state["temporal"] = dict(self._temporal)
                self._body = json.dumps(state, ensure_ascii=False, sort_keys=True).encode("utf-8")
            return self._body

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
# HTTP server


def content_security_policy(port: int) -> str:
    return ("default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data:; "
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
            else:
                self._send(404, b"not found\n", "text/plain; charset=utf-8")

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
    lab = _lab_observer(args, initial["case"]["case_id"]) if has_lab else None
    board = Board(raw, TemporalObserver(args.address, args.workflow_id), lab=lab)
    try:
        server = make_server(board, args.port)
    except OSError as exc:
        print(f"error: cannot bind {BIND_HOST}:{args.port} ({type(exc).__name__})", file=sys.stderr)
        return 2
    print(json.dumps({"url": f"http://{BIND_HOST}:{server.server_address[1]}/", "status": "serving"}), flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
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
<title>Hunt board</title>
<style>
:root{--bg:#0d1117;--panel:#161b22;--line:#30363d;--text:#d7dde4;--muted:#8b949e;--dim:#4b535d;
--auth:#d2a8ff;--conf:#e3b341;--proc:#58a6ff;--net:#3fb950;--other:#8b949e;--accent:#f0f6fc;
--pending:#6e7681;--approval:#d29922;--working:#388bfd;--review:#a371f7;--done:#2ea043;--stopped:#f85149}
*{box-sizing:border-box}
html,body{margin:0;background:var(--bg);color:var(--text);font:13px/1.4 system-ui,-apple-system,"Segoe UI",sans-serif}
body{padding:10px 14px 0}
h1{font-size:16px;margin:0}
h2{font-size:12px;margin:0;text-transform:uppercase;letter-spacing:.06em;color:var(--muted)}
header{display:flex;justify-content:space-between;align-items:baseline;gap:12px;flex-wrap:wrap}
.title{display:flex;gap:10px;align-items:baseline;flex-wrap:wrap}
#case{color:var(--muted)}
#conn{font-size:12px;color:var(--muted)}
#conn.bad{color:var(--stopped)}
#question{margin:4px 0 8px;color:var(--muted);font-size:12px}
#errors{color:var(--stopped);font-size:12px;margin:0 0 6px}
section{background:var(--panel);border:1px solid var(--line);border-radius:6px;padding:8px 10px;margin-bottom:10px;min-width:0}
.sec-h{display:flex;justify-content:space-between;align-items:baseline;gap:8px;margin-bottom:6px;flex-wrap:wrap}
.meta{font-size:11px;color:var(--muted)}
#stage-list{display:grid;grid-template-columns:repeat(9,minmax(0,1fr));gap:6px;list-style:none;margin:0;padding:0}
.stage{border:1px solid var(--line);border-left:4px solid var(--pending);border-radius:4px;padding:5px 6px;min-width:0}
.stage .sid{font-weight:600;font-size:12px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.stage .role{font-size:11px;color:var(--muted);min-height:2.8em}
.stage .st{font-size:11px;font-weight:600}
.stage .why{font-size:10.5px;color:var(--muted);word-break:break-word}
.s-pending{border-left-color:var(--pending)}.s-pending .st{color:var(--pending)}
.s-not_reached{border-left-color:var(--dim);opacity:.6}.s-not_reached .st{color:var(--dim)}
.s-awaiting_approval{border-left-color:var(--approval)}.s-awaiting_approval .st{color:var(--approval)}
.s-working{border-left-color:var(--working)}.s-working .st{color:var(--working)}
.s-awaiting_review{border-left-color:var(--review)}.s-awaiting_review .st{color:var(--review)}
.s-done{border-left-color:var(--done)}.s-done .st{color:var(--done)}
.s-stopped{border-left-color:var(--stopped)}.s-stopped .st{color:var(--stopped)}
main{display:grid;grid-template-columns:minmax(0,1.4fr) minmax(320px,1fr);gap:10px;align-items:start}
svg{display:block;width:100%}
svg text{fill:var(--text);font:11px system-ui,-apple-system,"Segoe UI",sans-serif}
svg .axis{fill:var(--muted);font-size:10px}
svg .grid{stroke:#21262d}
svg .lane{fill:#0f141a}
.mark{cursor:default}
.mark circle{opacity:.28}
.mark.cited circle{opacity:1;stroke:var(--accent);stroke-width:1.2}
.mark .cnt{font-size:9px;font-weight:700;fill:#0d1117;text-anchor:middle;pointer-events:none}
.mark.hl circle{opacity:1;stroke:#fff;stroke-width:2.5}
#legend{display:flex;gap:12px;flex-wrap:wrap;font-size:11px;color:var(--muted);margin-bottom:4px}
.sw{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:4px;vertical-align:-1px}
.node rect{fill:#0f141a;stroke:var(--dim);stroke-width:1}
.node.cited rect{fill:#1c2a3a;stroke:var(--accent);stroke-width:1.6}
.node.hl rect{stroke:#fff;stroke-width:2.5}
.node .nd{fill:var(--muted);font-size:10px}
.node .kind{font-size:9px;fill:var(--muted);text-transform:uppercase;letter-spacing:.05em}
.edge{fill:none;stroke:var(--dim);stroke-width:1.2}
.edge.cited{stroke:#8b949e;stroke-width:1.8}
.edge.stated{stroke-dasharray:4 3}
#feed-sec{max-height:calc(100vh - 24px);overflow:auto;position:sticky;top:10px}
.card{border:1px solid var(--line);border-radius:5px;padding:7px 8px;margin-bottom:8px}
.card-h{display:flex;gap:6px;align-items:baseline;flex-wrap:wrap;margin-bottom:4px}
.card-h .sid{font-weight:600}
.card-h .role{color:var(--muted);font-size:12px}
.pill{display:inline-block;font-size:10.5px;padding:0 6px;border-radius:9px;border:1px solid var(--line);color:var(--muted)}
.pill.st-done{color:var(--done);border-color:var(--done)}
.pill.st-awaiting_review{color:var(--review);border-color:var(--review)}
.pill.st-stopped{color:var(--stopped);border-color:var(--stopped)}
.note{font-size:11.5px;color:var(--muted);margin:2px 0 4px}
.note.warn{color:var(--approval)}
.claim{border-top:1px solid #21262d;padding:5px 0 4px}
.claim:target,.claim.flash{background:#1f2630}
.claim-h{display:flex;gap:6px;align-items:baseline;font-size:11px;color:var(--muted)}
.kind{font-size:10px;font-weight:700;text-transform:uppercase;padding:0 5px;border-radius:3px;color:#0d1117}
.k-observed{background:var(--net)}.k-inference{background:var(--proc)}.k-hypothesis{background:var(--conf)}.k-finding{background:var(--auth)}.k-other{background:var(--other)}
.stmt{margin:2px 0;white-space:pre-wrap;word-break:break-word}
.chips{display:flex;flex-wrap:wrap;gap:3px;margin-top:2px}
.chip{font:10.5px ui-monospace,Consolas,monospace;padding:0 4px;border-radius:3px;background:#21262d;color:var(--text);border:1px solid transparent;cursor:default}
.chip.unknown{border-color:var(--stopped);color:var(--stopped)}
.chip:hover{border-color:var(--accent)}
.links{font-size:11px;margin-top:2px;color:var(--muted)}
.links button{font:inherit;background:none;border:none;color:var(--proc);cursor:pointer;padding:0 2px;text-decoration:underline}
.verdict{font-size:11px;margin-top:3px;padding-left:6px;border-left:2px solid var(--review)}
.verdict summary{cursor:pointer;color:var(--muted)}
.verdict .disp{color:var(--review);font-weight:600}
details.more{margin-top:5px;font-size:11.5px}
details.more summary{cursor:pointer;color:var(--muted)}
details.more ul{margin:3px 0;padding-left:16px}
pre.raw{white-space:pre-wrap;word-break:break-word;font:11px ui-monospace,Consolas,monospace;background:#0f141a;padding:6px;border-radius:4px;max-height:260px;overflow:auto}
footer{color:var(--muted);font-size:11px;padding:4px 0 10px}
#tip{position:fixed;z-index:10;max-width:360px;background:#1c2128;border:1px solid var(--line);border-radius:5px;padding:6px 8px;font-size:11.5px;pointer-events:none;white-space:pre-wrap;word-break:break-word}
#tip[hidden]{display:none}
.empty{color:var(--muted);font-size:12px;padding:6px 0}
.chip.pending{border-color:var(--dim);color:var(--muted)}
.meta.bad{color:var(--stopped)}
#tool-lanes{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:8px}
.lane-col{border:1px solid var(--line);border-top:3px solid var(--dim);border-radius:4px;padding:5px 6px;min-width:0}
.lane-col.active{border-top-color:var(--review)}
.lane-col.working{border-color:var(--working);border-top-color:var(--working);box-shadow:0 0 0 1px var(--working)}
.lane-h{display:flex;justify-content:space-between;gap:6px;align-items:baseline}
.lane-h .role{font-weight:600;font-size:12px}
.lane-h .busy{font-size:10.5px;color:var(--working);font-weight:700;text-transform:uppercase}
.lane-sub{font-size:10.5px;color:var(--muted);margin-bottom:3px}
ol.calls{list-style:none;margin:0;padding:0;max-height:320px;overflow:auto}
.call{border-top:1px solid #21262d;padding:3px 0}
.call.new{background:#16202b}
.call-h{display:flex;gap:6px;align-items:baseline;font-size:10.5px;color:var(--muted);flex-wrap:wrap}
.call-h .tool{color:var(--text);font-weight:600}
.call-h .err{color:var(--stopped)}
.call code{display:block;font:10.5px ui-monospace,Consolas,monospace;white-space:pre-wrap;word-break:break-all;color:var(--text)}
.call .prm{font:10px ui-monospace,Consolas,monospace;color:var(--muted);word-break:break-all}
.ark{display:flex;gap:4px;align-items:center;margin-top:2px}
.ark input{flex:1;min-width:0;font:10px ui-monospace,Consolas,monospace;background:#0f141a;color:var(--text);border:1px solid var(--line);border-radius:3px;padding:1px 3px}
.ark button,.ark a{font-size:10.5px;background:none;border:none;color:var(--proc);cursor:pointer;padding:0 2px;text-decoration:underline}
@media (max-width:900px){main{grid-template-columns:minmax(0,1fr)}#feed-sec{position:static;max-height:none}#stage-list{grid-template-columns:repeat(3,minmax(0,1fr))}}
</style>
</head>
<body>
<header><div class="title"><h1>Hunt board</h1><span id="case"></span></div><div id="conn">Loading state&hellip;</div></header>
<p id="question"></p>
<p id="errors" hidden></p>
<section aria-label="Stage tracker"><div class="sec-h"><h2>Stages</h2><span class="meta" id="round"></span></div><ol id="stage-list"></ol></section>
<section id="tools-sec" aria-label="Tool activity" hidden><div class="sec-h"><h2>Tool activity</h2><span class="meta" id="tools-meta"></span></div><div id="tool-lanes"></div></section>
<main>
<div>
<section aria-label="Event timeline"><div class="sec-h"><h2>Event timeline</h2><span class="meta" id="tl-meta"></span></div><div id="legend"></div><svg id="timeline" role="img" aria-label="Supplied events by host over the case window"></svg></section>
<section aria-label="Entity map"><div class="sec-h"><h2>Entity map</h2><span class="meta" id="map-meta"></span></div><svg id="map" role="img" aria-label="Hosts, processes, tasks and domains from supplied events"></svg></section>
</div>
<section id="feed-sec" aria-label="Claims feed"><div class="sec-h"><h2>Claims feed</h2><span class="meta" id="feed-meta"></span></div><div id="feed"></div></section>
</main>
<footer>Synthetic lab data. Shows only what the bots wrote; approvals are recorded separately.</footer>
<div id="tip" role="tooltip" hidden></div>
<script>
"use strict";
(function(){
const STATE_URL = new URL("/state.json", location.href).href;
const SVGNS = "http://www.w3.org/2000/svg";
const CAT = {authentication:"var(--auth)", configuration:"var(--conf)", process:"var(--proc)", network:"var(--net)"};
const STATE_LABEL = {pending:"pending", not_reached:"not reached", awaiting_approval:"waiting for approval",
  working:"bot working", awaiting_review:"waiting review", done:"done", stopped:"stopped"};
const $ = (id) => document.getElementById(id);
let state = null, lastKey = null, fetchError = null;

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
function clear(node){ while (node.firstChild) node.removeChild(node.firstChild); }
function catColor(c){ return CAT[c] || "var(--other)"; }
function hhmmss(ms){ return new Date(ms).toISOString().slice(11, 19); }
function fit(text, chars){ text = String(text); return text.length > chars ? text.slice(0, Math.max(chars - 1, 1)) + "\u2026" : text; }

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

function renderHeader(){
  const t = state.temporal || {}, run = state.run || {}, p = run.parent, c = run.child;
  $("case").textContent = state.case && state.case.case_id ? "case " + state.case.case_id : "case id not supplied";
  $("question").textContent = state.case && state.case.question ? state.case.question : "";
  const errs = state.input_errors || [];
  $("errors").hidden = errs.length === 0; $("errors").textContent = errs.join(" \u00b7 ");
  const conn = $("conn"); const parts = [];
  let bad = false;
  if (fetchError){ parts.push("board server unreachable (" + fetchError + "); showing last state"); bad = true; }
  if (t.error){
    bad = true;
    parts.push(t.error + (t.last_success_at ? "; showing observation from " + t.last_success_at : "; no workflow status observed yet"));
  } else if (t.observed_at){ parts.push("Temporal status observed " + t.observed_at); }
  if (p) parts.push("parent " + (p.stage || "?") + " (" + (p.temporal_status || "?") + ")");
  if (c) parts.push("round " + (c.stage || "?") + " (" + (c.temporal_status || "?") + ")");
  conn.textContent = parts.join(" \u00b7 ") || "waiting for first status";
  conn.className = bad ? "bad" : "";
  if (p){
    const bits = ["Round " + (p.round_index || 0) + " of " + (p.rounds || "?"), (p.completed_rounds || 0) + " completed"];
    if (p.last_result) bits.push("last round result: " + p.last_result);
    if (p.child_workflow_id) bits.push(p.child_workflow_id);
    $("round").textContent = bits.join(" \u00b7 ");
  } else { $("round").textContent = "parent status not observed"; }
}

function renderStages(){
  const list = $("stage-list"); clear(list);
  if (!state.steps.length){ list.appendChild(el("li", {class:"empty"}, "No steps (input could not be read).")); return; }
  for (const s of state.steps){
    const li = el("li", {class:"stage s-" + s.state});
    li.appendChild(el("div", {class:"sid", title:s.step_id}, (s.index + 1) + ". " + s.step_id));
    li.appendChild(el("div", {class:"role"}, s.role));
    li.appendChild(el("div", {class:"st"}, STATE_LABEL[s.state] || s.state));
    const why = [];
    if (s.reason) why.push(s.reason);
    if (s.result && s.result.status !== "completed") why.push("result " + s.result.status + (s.result.reason_code ? " / " + s.result.reason_code : ""));
    for (const r of s.handoff_rejections || []) why.push("handoff " + (r.outcome === "retried" ? "retried" : "rejected, " + r.outcome) + ": " + r.reason);
    if (s.result && s.result.status === "completed" && !s.result.parsed) why.push("output unparsed");
    if (why.length) li.appendChild(el("div", {class:"why"}, why.join("; ")));
    list.appendChild(li);
  }
}

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
  legend.appendChild(el("span", null, "bright mark = cited by an accepted or in-review step; number = steps citing it"));
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
    svg.appendChild(sv("rect", {x:LABEL, y:laneTop[i] + 2, width:plotW, height:laneH[i] - 4, class:"lane", rx:3}));
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
  const chars = Math.floor((NW - 14) / 6.4);
  for (const n of nodes){
    const p = pos.get(n.id);
    const grp = sv("g", {class:"node" + (n.cited_event_ids.length ? " cited" : ""), "data-evts":n.event_ids.join(" ")});
    grp.appendChild(sv("rect", {x:p.x, y:p.y, width:NW, height:NH, rx:5}));
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
    h.appendChild(el("span", {class:"sid"}, (item.index + 1) + ". " + item.step_id));
    h.appendChild(el("span", {class:"role"}, item.role));
    h.appendChild(el("span", {class:"pill st-" + item.state}, STATE_LABEL[item.state] || item.state));
    const ho = item.handoff;
    if (ho && ho.disposition) h.appendChild(el("span", {class:"pill", title:"step disposition written by the bot"}, ho.disposition));
    card.appendChild(h);
    if (item.result_status !== "completed") card.appendChild(el("div", {class:"note warn"}, "Result status " + item.result_status + (item.reason_code ? " (" + item.reason_code + ")" : "")));
    if (item.state === "awaiting_review") card.appendChild(el("div", {class:"note"}, "Waiting for human review; not yet accepted."));
    if (item.state === "stopped") card.appendChild(el("div", {class:"note warn"}, "Workflow stopped at this step (" + (item.reason || "unknown") + "); its citations are not counted."));
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
      const kind = ["observed","inference","hypothesis","finding"].includes(c.kind) ? c.kind : "other";
      ch.appendChild(el("span", {class:"kind k-" + kind}, c.kind || "no kind"));
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
    if (ho.reviews.length){
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
    const col = el("div", {class:"lane-col" + (lane.working ? " working" : "") + (lane.active ? " active" : "")});
    const h = el("div", {class:"lane-h"});
    h.appendChild(el("span", {class:"role"}, lane.role));
    if (lane.working) h.appendChild(el("span", {class:"busy"}, "working"));
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

function renderAll(){
  renderStages(); renderTools(); renderLegend(); renderTimeline(); renderMap(); renderFeed();
}

async function poll(){
  try {
    const res = await fetch(STATE_URL, {cache:"no-store", credentials:"omit"});
    if (!res.ok) throw new Error("HTTP " + res.status);
    const next = await res.json();
    fetchError = null; state = next;
    // Observation timestamps change every poll; re-render the panels only when content changes.
    const tools = next.tools ? Object.assign({}, next.tools, {lab:null}) : null;
    const key = JSON.stringify(Object.assign({}, next, {temporal:null, tools:tools}));
    if (key !== lastKey){ lastKey = key; renderAll(); }
  } catch (err){
    fetchError = err && err.message ? err.message : "fetch failed";
  }
  if (state){ renderHeader(); renderToolsMeta(); } else { $("conn").textContent = "board server unreachable (" + fetchError + ")"; $("conn").className = "bad"; }
  setTimeout(poll, 2000);
}
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

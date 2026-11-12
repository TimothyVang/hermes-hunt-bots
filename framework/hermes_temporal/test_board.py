"""Consumer-visible behavior of the read-only hunt board (no Temporal server needed)."""
from __future__ import annotations

import asyncio
import copy
import http.client
import importlib.util
import json
import shutil
import subprocess
import tempfile
import threading
import types
import unittest
from datetime import datetime
from pathlib import Path
from unittest import mock
from urllib import parse

if importlib.util.find_spec("temporalio") is None:
    raise unittest.SkipTest("Install hermes_temporal/requirements.txt to run hunt board tests.")

from .board import (LIVE_STREAMS_MAX, Board, LabObserver, LiveBrowsers, ObservationError, TemporalObserver,  # noqa: E402
                    activity_spans, browser_root, build_state, main, make_server, newest_browser_action, parse_handoff)
from .test_hunt import tool_input  # noqa: E402
from .test_lab_input import FakeLab  # noqa: E402
from .workflows import _unwrap_single_fence  # noqa: E402

FIXTURES = Path(__file__).with_name("fixtures") / "board"
STEP_IDS = ["scope", "evidence", "hypotheses", "network", "intel", "analysis", "detection", "purple", "incident"]


def _load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


# Runs board_page.html's script in Node with a minimal DOM; its first /state.json poll answers with the given view
# and the page renders the view named in its URL hash. Prints the text and titles of each region it rendered.
_PAGE_HARNESS = r"""
const fs = require("fs"), vm = require("vm");
const [pagePath, statePath, view, phone] = process.argv.slice(2);
const html = fs.readFileSync(pagePath, "utf8");
const src = html.slice(html.indexOf("<script>") + 8, html.lastIndexOf("</script>"));
function el(tag){
  return {
    tagName: String(tag).toUpperCase(), nodeType: 1, children: [], parentNode: null, attrs: {}, dataset: {}, _text: "",
    className: "", style: new Proxy({}, {get: (t, k) => typeof k === "string" && k.endsWith("Property") ? () => "" : (t[k] ?? ""),
                                          set: (t, k, v) => { t[k] = v; return true; }}),
    classList: {add(){}, remove(){}, toggle(){}, contains(){ return false; }},
    get childNodes(){ return this.children; }, get firstChild(){ return this.children[0] || null; },
    get lastChild(){ return this.children[this.children.length - 1] || null; },
    appendChild(c){ if (c.parentNode) c.parentNode.removeChild(c); c.parentNode = this; this.children.push(c); return c; },
    removeChild(c){ this.children.splice(this.children.indexOf(c), 1); c.parentNode = null; return c; },
    insertBefore(c, ref){ if (!ref) return this.appendChild(c); if (c.parentNode) c.parentNode.removeChild(c);
                          c.parentNode = this; this.children.splice(this.children.indexOf(ref), 0, c); return c; },
    replaceChildren(...cs){ this.children = []; cs.forEach((c) => this.appendChild(c)); },
    remove(){ if (this.parentNode) this.parentNode.removeChild(this); },
    get textContent(){ return this._text + this.children.map((c) => c.textContent).join(""); },
    set textContent(v){ this.children = []; this._text = String(v); },
    get title(){ return this.attrs.title || ""; }, set title(v){ this.attrs.title = String(v); },
    setAttribute(k, v){ this.attrs[k] = String(v); }, getAttribute(k){ return k in this.attrs ? this.attrs[k] : null; },
    removeAttribute(k){ delete this.attrs[k]; }, hasAttribute(k){ return k in this.attrs; },
    addEventListener(){}, removeEventListener(){}, querySelector(){ return null; }, querySelectorAll(){ return []; },
    closest(){ return null; }, contains(){ return false; }, focus(){}, blur(){}, scrollIntoView(){}, scrollTo(){},
    getBoundingClientRect(){ return {x: 0, y: 0, top: 0, left: 0, right: 0, bottom: 0, width: 0, height: 0}; },
    scrollTop: 0, scrollLeft: 0, scrollHeight: 0, scrollWidth: 0, clientHeight: 0, clientWidth: 0, offsetWidth: 0, offsetHeight: 0,
  };
}
const ids = new Map();
const document = {
  createElement: el, createElementNS: (ns, tag) => el(tag), createTextNode: (v) => ({nodeType: 3, textContent: String(v), parentNode: null}),
  getElementById: (id) => { if (!ids.has(id)) ids.set(id, document.body.appendChild(el("div"))); return ids.get(id); },
  querySelector: () => null, querySelectorAll: () => [], addEventListener(){}, removeEventListener(){},
  body: el("body"), documentElement: el("html"), activeElement: null, hidden: false, title: "",
};
const noop = () => 0;
const body = fs.readFileSync(statePath, "utf8");
const ctx = {document, console, URL, URLSearchParams, history: {replaceState(){}},
  location: {hash: view ? "#view=" + view : "", href: "http://127.0.0.1:8790/"},
  matchMedia: () => ({matches: phone === "phone", addEventListener(){}, removeEventListener(){}}),
  addEventListener(){}, removeEventListener(){}, setInterval: noop, clearInterval: noop, setTimeout: noop, clearTimeout: noop,
  requestAnimationFrame: noop, cancelAnimationFrame: noop, fetch: async () => ({ok: true, status: 200, json: async () => JSON.parse(body)}),
  getComputedStyle: () => new Proxy({}, {get: () => ""}), innerWidth: phone === "phone" ? 390 : 1920, innerHeight: 1080, navigator: {}};
ctx.window = ctx;
vm.createContext(ctx);
vm.runInContext(src, ctx);
setTimeout(() => {
  const titles = (n) => [n.attrs && n.attrs.title].concat(...(n.children || []).map(titles)).filter(Boolean);
  // poll() catches a render error and only shows "Board unreachable"; surface it as a failure.
  const health = ids.get("health");
  if (health && health.textContent.includes("Board unreachable")){
    process.stderr.write("page render failed: " + titles(health).join("; ") + "\n");
    process.exit(1);
  }
  const out = {};
  for (const [id, node] of ids) out[id] = {text: node.textContent, titles: titles(node)};
  process.stdout.write(JSON.stringify(out));
}, 50);
"""


def _render_page(state: dict, view: str, phone: bool = False) -> dict:
    """The text and titles board_page.html renders per region id for ``state`` in ``view``."""
    node = shutil.which("node")
    if node is None:
        raise unittest.SkipTest("Node is required to run the board page")
    with tempfile.TemporaryDirectory() as folder:
        state_path = Path(folder) / "state.json"
        state_path.write_text(json.dumps(state), encoding="utf-8")
        result = subprocess.run([node, "-", str(Path(__file__).with_name("board_page.html")), str(state_path), view,
                                 "phone" if phone else "desktop"], input=_PAGE_HARNESS, capture_output=True,
                                text=True, encoding="utf-8", timeout=60)
    if result.returncode != 0:
        raise AssertionError(result.stderr)
    return json.loads(result.stdout)


def _mid_run(child: dict, results: int, stage: str, step_id: str, temporal: str = "RUNNING") -> dict:
    observed = copy.deepcopy(child)
    observed.update(stage=stage, step_id=step_id, temporal_status=temporal)
    observed["results"] = observed["results"][:results]
    return observed


def _states(state: dict) -> list[str]:
    return [step["state"] for step in state["steps"]]


def _events(state: dict) -> dict[str, dict]:
    return {event["id"]: event for event in state["timeline"]["events"]}


def _citing_steps(child: dict, event_id: str, upto: int) -> list[str]:
    """Independent count: steps whose claim statements or review rationales name the ID."""
    steps = []
    for result in child["results"][:upto]:
        handoff = json.loads(_unwrap_single_fence(result["output"], allow_leading_prose=True))
        texts = [claim["statement"] for claim in handoff["claims"]]
        texts += [review["rationale"] for review in handoff["reviews"]]
        if any(event_id in text for text in texts):
            steps.append(handoff["step_id"])
    return steps


class BoardDerivationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.raw = _load("lab-input.json")
        self.parent = _load("parent-status.json")
        self.child = _load("child-status.json")

    def test_input_events_lanes_and_window(self) -> None:
        state = build_state(self.raw, None, None)
        self.assertEqual(state["input_errors"], [])
        self.assertEqual(state["case"]["case_id"], "dns-lab-001")
        timeline = state["timeline"]
        self.assertEqual(len(timeline["events"]), 40)
        self.assertEqual(timeline["window_source"], "case")
        self.assertEqual(timeline["end_ms"] - timeline["start_ms"], 10 * 60 * 1000)
        self.assertEqual(timeline["lanes"], ["workstation-01", "workstation-02", None])
        events = _events(state)
        self.assertEqual(events["evt-0004"]["category"], "process")
        self.assertEqual(events["evt-0004"]["process"]["name"], "powershell.exe")
        self.assertEqual(events["evt-0006"]["domain"], "status-gateway.test")
        self.assertIsNone(events["evt-0038"]["host"])
        self.assertTrue(all(event["cite_count"] == 0 for event in events.values()))
        self.assertEqual(state["network"]["session_count"], 16)

    def test_entity_graph_is_layered_from_supplied_events(self) -> None:
        graph = build_state(self.raw, None, None)["graph"]
        nodes = {node["id"]: node for node in graph["nodes"]}
        self.assertEqual({node["kind"] for node in nodes.values()}, {"host", "process", "task", "domain"})
        self.assertEqual([nodes[f"host:workstation-0{i}"]["layer"] for i in (1, 2)], [0, 0])
        process = nodes["process:workstation-01:process-1"]
        self.assertEqual((process["label"], process["layer"], process["detail"]["pid"]), ("powershell.exe", 1, 4100))
        task = nodes["task:workstation-02:InventoryRefresh"]
        self.assertEqual(task["detail"], {"interval_seconds": "60", "stated_domain": "updates.vendor.test"})
        domain = nodes["domain:updates.vendor.test"]
        self.assertEqual((domain["layer"], domain["sessions"]), (2, 8))
        edges = {(edge["source"], edge["target"], edge["kind"]): edge for edge in graph["edges"]}
        queried = edges[("process:workstation-02:process-2", "domain:updates.vendor.test", "queried")]
        self.assertEqual(len(queried["event_ids"]), 8)
        self.assertIn(("host:workstation-02", "task:workstation-02:InventoryRefresh", "configured"), edges)
        self.assertIn(("task:workstation-02:InventoryRefresh", "domain:updates.vendor.test", "stated"), edges)
        self.assertEqual(graph, build_state(self.raw, None, None)["graph"])
        self.assertTrue(all(not node["cited_event_ids"] for node in graph["nodes"]))

    def test_completed_run_counts_citations_from_real_outputs(self) -> None:
        state = build_state(self.raw, self.parent, self.child)
        self.assertEqual(_states(state), ["done"] * 9)
        self.assertEqual([step["role"] for step in state["steps"]][:4],
                         ["Incident Response Lead", "Threat Hunter", "Threat Hunter", "Network Analyst"])
        self.assertEqual([item["step_id"] for item in state["feed"]], list(reversed(STEP_IDS)))
        self.assertTrue(all(item["parsed"] and item["counted"] for item in state["feed"]))
        events = _events(state)
        for event_id in ("evt-0001", "evt-0002", "evt-0003", "evt-0038"):
            expected = _citing_steps(self.child, event_id, 9)
            self.assertEqual(events[event_id]["cited_by"], expected)
            self.assertEqual(events[event_id]["cite_count"], len(expected))
        nodes = {node["id"]: node for node in state["graph"]["nodes"]}
        self.assertIn("evt-0004", nodes["process:workstation-01:process-1"]["cited_event_ids"])
        purple = next(item for item in state["feed"] if item["step_id"] == "purple")
        named = {claim_id for review in purple["handoff"]["reviews"] for claim_id in review["claim_ids"]}
        analysis = next(item for item in state["feed"] if item["step_id"] == "analysis")
        claim = next(claim for claim in analysis["handoff"]["claims"] if claim["claim_id"] in named)
        self.assertTrue(any(verdict["step_id"] == "purple" and verdict["disposition"] for verdict in claim["verdicts"]))
        self.assertEqual(state["run"]["parent"]["rounds"], 1)

    def test_mid_run_states_and_citations_follow_child_stage(self) -> None:
        parent = dict(self.parent, stage="running_round", temporal_status="RUNNING")
        reviewing = build_state(self.raw, parent, _mid_run(self.child, 5, "awaiting_review", "intel"))
        self.assertEqual(_states(reviewing), ["done"] * 4 + ["awaiting_review"] + ["pending"] * 4)
        self.assertTrue(reviewing["feed"][0]["counted"])
        early = build_state(self.raw, parent, _mid_run(self.child, 2, "awaiting_review", "evidence"))
        self.assertEqual(_events(early)["evt-0001"]["cited_by"], _citing_steps(self.child, "evt-0001", 2))
        self.assertEqual(len(early["feed"]), 2)
        approval = build_state(self.raw, parent, _mid_run(self.child, 3, "awaiting_execution_approval", "network"))
        self.assertEqual(_states(approval)[2:5], ["done", "awaiting_approval", "pending"])
        working = build_state(self.raw, parent, _mid_run(self.child, 3, "executing", "network"))
        self.assertEqual(_states(working)[3], "working")
        start = build_state(self.raw, parent, {"stage": "initializing", "step_id": None, "results": [],
                                               "temporal_status": "RUNNING"})
        self.assertEqual(_states(start), ["pending"] * 9)

    def test_stopped_states_report_reason_and_exclude_rejected_output(self) -> None:
        rejected = build_state(self.raw, self.parent,
                               _mid_run(self.child, 5, "handoff_validation_rejected", "intel", "COMPLETED"))
        self.assertEqual(_states(rejected), ["done"] * 4 + ["stopped"] + ["not_reached"] * 4)
        self.assertEqual(rejected["steps"][4]["reason"], "handoff_validation_rejected")
        self.assertFalse(rejected["feed"][0]["counted"])
        four_steps = build_state(self.raw, self.parent, _mid_run(self.child, 4, "awaiting_review", "network"))
        self.assertEqual({event_id: event["cited_by"] for event_id, event in _events(rejected).items()},
                         {event_id: event["cited_by"] for event_id, event in _events(four_steps).items()})
        terminated = build_state(self.raw, self.parent,
                                 _mid_run(self.child, 3, "awaiting_execution_approval", "network", "TERMINATED"))
        self.assertEqual(_states(terminated)[3], "stopped")
        self.assertIn("TERMINATED", terminated["steps"][3]["reason"])
        denied = build_state(self.raw, self.parent, _mid_run(self.child, 0, "rejected", "scope", "COMPLETED"))
        self.assertEqual(_states(denied), ["stopped"] + ["not_reached"] * 8)

    def test_retry_gate_shows_the_rejection_and_never_counts_the_rejected_output(self) -> None:
        child = _mid_run(self.child, 3, "awaiting_execution_approval", "network")
        rejected = dict(self.child["results"][3], execution_id="x:3")
        child["handoff_rejections"] = [{"step_id": "network", "reason": "ValueError: invalid handoff disposition",
                                        "outcome": "retried", "result": rejected}]
        state = build_state(self.raw, self.parent, child)
        self.assertEqual(_states(state)[2:5], ["done", "awaiting_approval", "pending"])
        self.assertEqual(state["steps"][3]["handoff_rejections"],
                         [{"outcome": "retried", "reason": "ValueError: invalid handoff disposition"}])
        self.assertEqual([step["handoff_rejections"] for step in state["steps"][:3]], [[], [], []])
        three_steps = build_state(self.raw, self.parent, _mid_run(self.child, 3, "awaiting_execution_approval",
                                                                   "network"))
        self.assertEqual({event_id: event["cited_by"] for event_id, event in _events(state).items()},
                         {event_id: event["cited_by"] for event_id, event in _events(three_steps).items()})

    def test_unknown_result_awaits_reconciliation_without_output(self) -> None:
        child = _mid_run(self.child, 3, "needs_reconciliation", "hypotheses")
        child["results"][2] = dict(child["results"][2], status="unknown", output="", reason_code="execution_error")
        state = build_state(self.raw, self.parent, child)
        self.assertEqual(state["steps"][2]["state"], "awaiting_review")
        self.assertEqual(state["steps"][2]["reason"], "needs_reconciliation")
        self.assertEqual(state["steps"][2]["result"]["status"], "unknown")
        self.assertFalse(state["feed"][0]["parsed"])

    def test_unparseable_output_is_reported_not_raised(self) -> None:
        child = _mid_run(self.child, 3, "awaiting_review", "hypotheses")
        child["results"][2] = dict(child["results"][2], output="Notes first.\n{\"claims\": [")
        child["results"][1] = dict(child["results"][1], output="[1, 2]")
        state = build_state(self.raw, self.parent, child)
        latest = state["feed"][0]
        self.assertEqual(latest["step_id"], "hypotheses")
        self.assertFalse(latest["parsed"])
        self.assertTrue(latest["parse_error"])
        self.assertTrue(latest["raw_excerpt"].startswith("Notes first."))
        self.assertFalse(state["steps"][1]["result"]["parsed"])
        self.assertEqual(state["steps"][2]["state"], "awaiting_review")
        for output in ("", "```json\n{\"claims\": 5}\n```", "{\"claims\": [\"x\", {\"statement\": 7}]}"):
            handoff, error = parse_handoff(output)
            self.assertTrue(handoff is None or isinstance(handoff["claims"], list), error)

    def test_fenced_output_with_leading_prose_parses(self) -> None:
        body = self.child["results"][0]["output"]
        handoff, error = parse_handoff("I checked the case.\n```json\n" + body + "\n```")
        self.assertIsNone(error)
        self.assertEqual(handoff["step_id"], "scope")

    def test_missing_observation_and_invalid_input_are_visible(self) -> None:
        state = build_state(self.raw, None, None)
        self.assertEqual(_states(state), ["pending"] * 9)
        self.assertIsNone(state["run"]["parent"])
        self.assertEqual(state["feed"], [])
        broken = build_state({"scope": "x"}, None, None)
        self.assertTrue(broken["input_errors"])
        self.assertEqual(broken["steps"], [])

    def test_serial_round_keeps_its_shape_and_gains_the_wave_keys_with_serial_defaults(self) -> None:
        child = _mid_run(self.child, 5, "awaiting_review", "intel")
        child["results"][1] = dict(child["results"][1], usage=_tokens(1500))
        state = build_state(self.raw, self.parent, child)
        self.assertEqual(set(state), {
            "board_version", "mode", "case", "scope", "input_errors", "run", "round", "steps", "team",
            "latest_conclusion", "browsers", "timeline", "graph", "network", "feed", "cited_event_count",
            "pending_event_ids", "tools", "stage_time", "waves"})
        steps = state["steps"]
        for step in steps:
            self.assertEqual(set(step), {
                "index", "step_id", "name", "profile", "role", "monogram", "state", "reason", "result", "claims",
                "timing", "handoff_rejections", "wave", "optional", "usage"})
        self.assertEqual([step["wave"] for step in steps], list(range(1, 10)))
        self.assertEqual([step["optional"] for step in steps], [False] * 9)
        self.assertEqual([step["reason"] for step in steps], [""] * 9)
        self.assertEqual([step["usage"] for step in steps], [None, _tokens(1500)] + [None] * 7)
        self.assertEqual(state["run"]["usage_total"], _tokens(1500))
        self.assertEqual(state["run"]["dropped"], [])
        self.assertEqual([member["open_steps"] for member in state["team"] if member["open_steps"]],
                         [[{"step_id": "intel", "state": "awaiting_review"}]])


ROUND = "practice-1:round:001"
START_ISO, START_MS = "2026-11-08T19:14:33.250000+00:00", 1_794_165_273_250


def _history_event(event_id: int, ms: int, kind: str):
    from temporalio.api.history.v1 import HistoryEvent

    event = HistoryEvent(event_id=event_id)
    event.event_time.FromMilliseconds(ms)
    getattr(event, kind).SetInParent()
    return event


def _scheduled(event_id: int, ms: int, execution_id: str):
    from temporalio.api.common.v1 import Payload

    event = _history_event(event_id, ms, "activity_task_scheduled_event_attributes")
    event.activity_task_scheduled_event_attributes.input.payloads.append(Payload(
        metadata={"encoding": b"json/plain"},
        data=json.dumps({"execution_id": execution_id, "step": {"prompt": "p"}}).encode()))
    return event


def _closed(event_id: int, ms: int, scheduled: int, kind: str = "activity_task_completed_event_attributes"):
    event = _history_event(event_id, ms, kind)
    getattr(event, kind).scheduled_event_id = scheduled
    return event


def _claims(child: dict, index: int) -> list[dict]:
    return json.loads(_unwrap_single_fence(child["results"][index]["output"], allow_leading_prose=True))["claims"]


class HuntLiveDerivationTests(unittest.TestCase):
    """The Hunt Live fields: real stage timings, round clock, team, latest conclusion, browser captions."""

    def setUp(self) -> None:
        self.raw = _load("lab-input.json")
        self.parent = _load("parent-status.json")
        self.child = _load("child-status.json")
        history = [
            _history_event(5, 500, "workflow_execution_signaled_event_attributes"),
            _scheduled(10, 1_000, f"{ROUND}:0"), _closed(12, 22_000, 10),
            _scheduled(20, 30_000, f"{ROUND}:1"), _closed(22, 90_000, 20),
            _scheduled(30, 95_000, f"{ROUND}:1:retry"), _closed(32, 150_000, 30),
            _scheduled(40, 160_000, f"{ROUND}:2"),
            _scheduled(50, 170_000, "another-round:3"),
            _closed(52, 171_000, 50, "activity_task_failed_event_attributes"),
        ]
        self.spans = activity_spans(history)

    def running(self, **extra) -> dict:
        child = _mid_run(self.child, 2, "executing", "hypotheses")
        child.update({"workflow_id": ROUND, "activity_spans": self.spans, "start_time": START_ISO, "close_time": None,
                      **extra})
        return child

    def test_activity_spans_read_execution_ids_and_close_times_from_history(self) -> None:
        self.assertEqual(self.spans, [
            {"execution_id": f"{ROUND}:0", "scheduled_ms": 1_000, "closed_ms": 22_000},
            {"execution_id": f"{ROUND}:1", "scheduled_ms": 30_000, "closed_ms": 90_000},
            {"execution_id": f"{ROUND}:1:retry", "scheduled_ms": 95_000, "closed_ms": 150_000},
            {"execution_id": f"{ROUND}:2", "scheduled_ms": 160_000, "closed_ms": None},
            {"execution_id": "another-round:3", "scheduled_ms": 170_000, "closed_ms": 171_000}])

    def test_stage_timings_span_every_attempt_and_leave_open_stages_without_an_end(self) -> None:
        timings = [step["timing"] for step in build_state(self.raw, self.parent, self.running())["steps"]]
        self.assertEqual(timings[0], {"started_ms": 1_000, "ended_ms": 22_000, "duration_ms": 21_000, "attempts": 1})
        self.assertEqual(timings[1], {"started_ms": 30_000, "ended_ms": 150_000, "duration_ms": 120_000, "attempts": 2})
        self.assertEqual(timings[2], {"started_ms": 160_000, "ended_ms": None, "duration_ms": None, "attempts": 1})
        unknown = {"started_ms": None, "ended_ms": None, "duration_ms": None, "attempts": 0}
        self.assertEqual(timings[3:], [unknown] * 6)
        unread = build_state(self.raw, self.parent, self.running(activity_spans=None))["steps"]
        self.assertEqual([step["timing"] for step in unread], [unknown] * 9)

    def test_serial_stage_time_is_the_sum_of_the_finished_stages_and_the_open_stages_start(self) -> None:
        state = build_state(self.raw, self.parent, self.running())
        self.assertEqual(state["stage_time"], {"closed_ms": 21_000 + 120_000, "open_since_ms": 160_000})
        self.assertEqual(state["waves"][:4], [{"wave": 1, "closed_ms": 21_000, "open_since_ms": None},
                                              {"wave": 2, "closed_ms": 120_000, "open_since_ms": None},
                                              {"wave": 3, "closed_ms": None, "open_since_ms": 160_000},
                                              {"wave": 4, "closed_ms": None, "open_since_ms": None}])
        self.assertEqual(build_state(self.raw, None, None)["stage_time"], {"closed_ms": None, "open_since_ms": None})

    def test_round_clock_is_temporal_start_and_close_else_first_stage(self) -> None:
        state = build_state(self.raw, self.parent, self.running())
        self.assertEqual(state["round"], {"started_ms": START_MS, "ended_ms": None, "source": "temporal"})
        closed = build_state(self.raw, self.parent, self.running(close_time="2026-11-08T19:36:55+00:00"))
        self.assertEqual(closed["round"]["ended_ms"] - START_MS, (22 * 60 + 21.75) * 1000)
        fallback = build_state(self.raw, self.parent, self.running(start_time=None))
        self.assertEqual(fallback["round"], {"started_ms": 1_000, "ended_ms": None, "source": "first_stage"})
        self.assertEqual(build_state(self.raw, None, None)["round"],
                         {"started_ms": None, "ended_ms": None, "source": None})

    def test_steps_carry_name_monogram_and_claim_count(self) -> None:
        steps = build_state(self.raw, self.parent, self.running())["steps"]
        self.assertEqual([(step["name"], step["monogram"]) for step in steps[:4]],
                         [("Scope", "IR"), ("Evidence", "TH"), ("Hypotheses", "TH"), ("Network", "NA")])
        self.assertEqual([step["claims"] for step in steps[:3]],
                         [len(_claims(self.child, 0)), len(_claims(self.child, 1)), None])

    def test_team_names_each_bots_stages_open_stage_and_claims(self) -> None:
        team = {member["profile"]: member for member in build_state(self.raw, self.parent, self.running())["team"]}
        self.assertEqual(list(team), ["framework-coordinator", "framework-researcher", "framework-network-analyst",
                                      "framework-librarian", "framework-builder", "framework-reviewer"])
        self.assertEqual([member["monogram"] for member in team.values()], ["IR", "TH", "NA", "TI", "DE", "PT"])
        self.assertEqual(team["framework-researcher"]["steps"], [1, 2])
        self.assertEqual(team["framework-researcher"]["current"], 2)
        self.assertEqual(team["framework-researcher"]["claims"], len(_claims(self.child, 1)))
        self.assertEqual(team["framework-coordinator"]["steps"], [0, 5, 8])
        self.assertIsNone(team["framework-coordinator"]["current"])
        self.assertEqual(team["framework-coordinator"]["claims"], len(_claims(self.child, 0)))

    def test_latest_conclusion_is_the_newest_done_stages_first_claim(self) -> None:
        mid = build_state(self.raw, self.parent, self.running())["latest_conclusion"]
        first = _claims(self.child, 1)[0]
        self.assertEqual(mid, {"index": 1, "step_id": "evidence", "name": "Evidence", "profile": "framework-researcher",
                               "role": "Threat Hunter", "claim_id": first["claim_id"], "kind": first["kind"],
                               "statement": first["statement"]})
        done = build_state(self.raw, self.parent, self.child)["latest_conclusion"]
        self.assertEqual((done["index"], done["statement"]), (8, _claims(self.child, 8)[0]["statement"]))
        self.assertIsNone(build_state(self.raw, None, None)["latest_conclusion"])

    def write_audit(self, *entries) -> Path:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = Path(tmp.name) / "audit.jsonl"
        path.write_text("".join((entry if isinstance(entry, str) else json.dumps(entry)) + "\n" for entry in entries),
                        encoding="utf-8")
        return path

    def test_newest_browser_action_is_this_rounds_newest_entry_for_the_owner_and_case(self) -> None:
        base = {"case_id": "lab-med-001", "ok": True, "error": None, "page": "kibana_discover", "entered": "typed"}
        path = self.write_audit(
            {**base, "t": 500, "profile": TH, "action": "open", "query": "before the round"},
            {**base, "t": 2_000, "profile": TH, "action": "open", "query": "process.parent.name:OUTLOOK.EXE"},
            {**base, "t": 2_500, "profile": NA, "action": "open", "page": "arkime_sessions", "query": "port.dst==3389"},
            {**base, "t": 2_600, "profile": TH, "case_id": "another-case", "action": "open", "query": "x"},
            "not json", "")
        self.assertEqual(newest_browser_action(path, TH, 1_000, "lab-med-001"), {
            "t_ms": 2_000, "action": "open", "verb": "typed", "query": "process.parent.name:OUTLOOK.EXE",
            "detail": None, "submitted": False, "page": "kibana_discover", "ok": True, "error": None})
        self.assertEqual(newest_browser_action(path, NA, 1_000, "lab-med-001")["query"], "port.dst==3389")
        self.assertIsNone(newest_browser_action(path, TH, 2_100, "lab-med-001"))
        self.assertIsNone(newest_browser_action(path.with_name("missing.jsonl"), TH, 0))

    def test_browser_action_verbs_and_refusals(self) -> None:
        cases = [({"action": "type", "text": "event.code:4625", "submit": True},
                  ("typed", "event.code:4625", None, True)),
                 ({"action": "open", "query": "q", "entered": "url"}, ("opened", "q", None, False)),
                 ({"action": "scroll", "direction": "down"}, ("scrolled", None, "down", False)),
                 ({"action": "press", "key": "Enter"}, ("pressed", None, "Enter", False)),
                 ({"action": "snapshot"}, ("read the page", None, None, False))]
        for entry, expected in cases:
            action = newest_browser_action(self.write_audit({"t": 5, "profile": TH, "ok": True, **entry}), TH, 0)
            self.assertEqual((action["verb"], action["query"], action["detail"], action["submitted"]), expected)
        refused = newest_browser_action(self.write_audit(
            {"t": 5, "profile": TH, "action": "click", "ok": False, "error": "refused_control"}), TH, 0)
        self.assertEqual((refused["ok"], refused["error"]), (False, "refused_control"))

    def test_browsers_pair_an_action_with_the_owners_api_call_for_the_same_query(self) -> None:
        lab = {"activity": ACTIVITY, "events": {}, "missing": []}
        action = {"t_ms": 1, "action": "open", "verb": "typed", "detail": None, "submitted": False,
                  "page": "kibana_discover", "ok": True, "error": None}
        browser = {TH: {**action, "query": "  Process.name:beacon.exe "},
                   NA: {**action, "query": "host.dns == other.test"}}
        state = build_state(tool_input(), None, None, lab, browser)
        th, na = state["browsers"]
        self.assertEqual((th["profile"], th["role"], th["action"]["query"]),
                         (TH, "Threat Hunter", "  Process.name:beacon.exe "))
        self.assertEqual(th["api"], {"tool": "elastic_search", "time": "2026-11-06T10:00:05Z", "result_count": 50,
                                     "total": 120})
        self.assertIsNone(na["api"])
        nothing = build_state(tool_input(), None, None, lab, {TH: None, NA: None})["browsers"]
        self.assertEqual([item["action"] for item in nothing], [None, None])
        self.assertIsNone(build_state(tool_input(), None, None, lab)["browsers"])


class BoardServerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.raw = _load("lab-input.json")
        self.calls = 0
        self.fail = False

        def observe():
            self.calls += 1
            if self.fail:
                raise ObservationError("Temporal unreachable (RPCError)", False)
            return _load("parent-status.json"), _load("child-status.json")

        self.now = 100.0
        self.board = Board(self.raw, observe, clock=lambda: self.now)
        self.server = make_server(self.board, 0)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(5)

    def request(self, method: str, path: str, headers: dict | None = None):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            connection.request(method, path, headers=headers or {})
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            connection.close()

    def test_binds_loopback_and_serves_page_and_state(self) -> None:
        self.assertEqual(self.server.server_address[0], "127.0.0.1")
        status, headers, body = self.request("GET", "/")
        self.assertEqual(status, 200)
        self.assertTrue(headers["Content-Type"].startswith("text/html"))
        self.assertIn("default-src 'none'", headers["Content-Security-Policy"])
        self.assertIn(f"connect-src http://127.0.0.1:{self.port}", headers["Content-Security-Policy"])
        self.assertNotIn(b"__CSP__", body)
        status, headers, body = self.request("GET", "/state.json")
        self.assertEqual(status, 200)
        state = json.loads(body)
        self.assertEqual(len(state["steps"]), 9)
        self.assertTrue(state["temporal"]["reachable"])
        self.assertIsNone(state["live"])
        self.assertEqual(self.request("GET", "/live/framework-researcher.jpg")[0], 404)

    def test_unknown_paths_404_and_other_methods_405(self) -> None:
        for path in ("/state", "/index.html", "/state.json/x"):
            self.assertEqual(self.request("GET", path)[0], 404)
        for method in ("POST", "PUT", "DELETE", "OPTIONS", "HEAD"):
            status, headers, _ = self.request(method, "/state.json")
            self.assertEqual(status, 405, method)
            self.assertEqual(headers["Allow"], "GET")
        self.assertEqual(self.request("GET", "/", {"Host": f"rebind.test:{self.port}"})[0], 404)

    def test_cors_header_only_for_opaque_origin(self) -> None:
        _, headers, _ = self.request("GET", "/state.json", {"Origin": "null"})
        self.assertEqual(headers.get("Access-Control-Allow-Origin"), "null")
        for origin in ({"Origin": "http://evil.test"}, {}):
            _, headers, _ = self.request("GET", "/state.json", origin)
            self.assertNotIn("Access-Control-Allow-Origin", headers)

    def test_polls_at_most_once_per_interval_and_reports_unreachable(self) -> None:
        self.request("GET", "/state.json")
        self.request("GET", "/state.json")
        self.assertEqual(self.calls, 1)
        self.fail = True
        self.now += 2.0
        state = json.loads(self.request("GET", "/state.json")[2])
        self.assertEqual(self.calls, 2)
        self.assertFalse(state["temporal"]["reachable"])
        self.assertTrue(state["temporal"]["error"])
        self.assertTrue(state["temporal"]["last_success_at"])
        self.assertEqual(_states(state), ["done"] * 9)

    def test_unreachable_before_any_observation_shows_pending(self) -> None:
        self.fail = True
        state = json.loads(self.request("GET", "/state.json")[2])
        self.assertFalse(state["temporal"]["reachable"])
        self.assertIsNone(state["temporal"]["last_success_at"])
        self.assertEqual(_states(state), ["pending"] * 9)


TH, NA = "framework-researcher", "framework-network-analyst"


class LiveBoardTests(unittest.TestCase):
    """Live browser frames through a fake frame sink; no browser or screencast client runs."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = browser_root(self.tmp.name)
        self.live = LiveBrowsers(self.root)
        self.board = Board(_load("lab-input.json"), lambda: (_load("parent-status.json"), _load("child-status.json")),
                           live=self.live)
        self.server = make_server(self.board, 0)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self) -> None:
        self.live.close()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(5)

    def request(self, path: str, headers: dict | None = None):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            connection.request("GET", path, headers=headers or {})
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            connection.close()

    def open_stream(self, profile: str):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        self.addCleanup(connection.close)
        connection.request("GET", f"/live/{profile}.mjpg")
        return connection.getresponse()

    def read_part(self, response, boundary: str, first: bool = False) -> tuple[dict, bytes]:
        """One part's headers and body. Its body ends where the next part's boundary is, which the board sends
        with the frame (Chromium paints a part only then), so this returns without waiting for another frame."""
        if first:
            self.assertEqual(response.readline(), f"--{boundary}\r\n".encode())
        headers = {}
        while (line := response.readline()) != b"\r\n":
            name, _, value = line.decode("ascii").partition(":")
            headers[name.strip()] = value.strip()
        delimiter, body = f"\r\n--{boundary}\r\n".encode(), b""
        while not body.endswith(delimiter):
            chunk = response.read(1)
            self.assertTrue(chunk, "the stream ended inside a part")
            body += chunk
        return headers, body[:-len(delimiter)]

    def test_board_derives_the_lane_browser_root_like_the_operator_lanes(self) -> None:
        self.assertEqual(browser_root("H"), Path("H", "profiles", "framework-network-analyst", "hunt-lab-browser"))

    def test_live_paths_refuse_other_hosts_and_unknown_profiles(self) -> None:
        self.live.add(TH, 1.0, b"jpeg")
        for path in (f"/live/{TH}.jpg", f"/live/{TH}.mjpg"):
            self.assertEqual(self.request(path, {"Host": f"rebind.test:{self.port}"})[0], 404)
            self.assertEqual(self.request(path, {"Host": f"localhost:{self.port}"})[0], 404)
        for path in ("/live/framework-coordinator.jpg", "/live/framework-coordinator.mjpg", "/live/../state.json",
                     f"/live/{TH}.png", f"/live/{TH}", "/live/"):
            self.assertEqual(self.request(path)[0], 404, path)
        self.live.add("framework-coordinator", 1.0, b"other")
        self.assertIsNone(self.live.latest("framework-coordinator"))

    def test_latest_jpg_is_404_until_a_frame_then_the_newest_frame(self) -> None:
        self.assertEqual(self.request(f"/live/{TH}.jpg")[0], 404)
        self.live.add(TH, 1.0, b"frame-1")
        self.live.add(TH, 2.0, b"frame-2")
        status, headers, body = self.request(f"/live/{TH}.jpg")
        self.assertEqual((status, headers["Content-Type"], body), (200, "image/jpeg", b"frame-2"))
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(self.request(f"/live/{NA}.jpg")[0], 404)

    def test_mjpeg_stream_sends_the_current_frame_then_each_new_one(self) -> None:
        self.live.add(NA, 1.0, b"current")
        response = self.open_stream(NA)
        self.assertEqual(response.status, 200)
        content_type = response.getheader("Content-Type")
        self.assertTrue(content_type.startswith("multipart/x-mixed-replace; boundary="), content_type)
        boundary = content_type.split("boundary=", 1)[1]
        self.assertIsNone(response.getheader("Content-Length"))
        self.assertEqual(response.getheader("X-Content-Type-Options"), "nosniff")
        headers, body = self.read_part(response, boundary, first=True)
        self.assertEqual((headers, body), ({"Content-Type": "image/jpeg"}, b"current"))
        self.live.add(NA, 2.0, b"next")
        self.assertEqual(self.read_part(response, boundary), ({"Content-Type": "image/jpeg"}, b"next"))

    def test_concurrent_streams_are_capped_and_close_ends_them(self) -> None:
        streams = [self.open_stream(TH) for _ in range(LIVE_STREAMS_MAX)]
        self.assertTrue(all(s.status == 200 for s in streams))
        self.assertEqual(self.request(f"/live/{TH}.mjpg")[0], 503)
        self.live.close()
        for s in streams:
            boundary = s.getheader("Content-Type").split("boundary=", 1)[1]
            # Only the first part's head went out before the close; no frame ever arrived.
            self.assertEqual(s.read(), f"--{boundary}\r\nContent-Type: image/jpeg\r\n\r\n".encode())

    def test_state_reports_each_owner_live_status_and_page(self) -> None:
        (self.root / NA).mkdir(parents=True)
        (self.root / NA / "session.json").write_text(json.dumps(
            {"ws_url": "ws://127.0.0.1:9/devtools/browser/x", "main_target": "T", "page": "arkime_sessions",
             "refs": {"e1": "secret"}}), encoding="utf-8")
        self.live.add(NA, 1_800_000_000.25, b"jpeg")
        self.live.add(NA, 1_800_000_001.5, b"jpeg")
        state = json.loads(self.request("/state.json")[2])
        self.assertEqual(state["live"], {"owners": [
            {"profile": TH, "role": "Threat Hunter", "attached": False, "frames": 0, "last_frame_at": None, "page": None},
            {"profile": NA, "role": "Network Analyst", "attached": False, "frames": 2,
             "last_frame_at": 1_800_000_001_500, "page": "arkime_sessions"}]})

    def test_page_falls_back_to_a_loopback_url_path_only(self) -> None:
        (self.root / TH).mkdir(parents=True)
        for url, page in (("http://127.0.0.1:5601/app/discover?_g=x", "/app/discover"),
                          ("https://127.0.0.1:5601/app/discover", None), ("http://evil.test/app", None)):
            (self.root / TH / "session.json").write_text(json.dumps({"page": "unknown", "url": url}), encoding="utf-8")
            self.assertEqual(self.live.status()[0]["page"], page, url)

    def test_page_csp_allows_live_images_from_the_board_only(self) -> None:
        _, headers, _ = self.request("/")
        csp = headers["Content-Security-Policy"]
        self.assertIn(f"img-src data: http://127.0.0.1:{self.port};", csp)
        self.assertIn(f"connect-src http://127.0.0.1:{self.port};", csp)

    def test_state_carries_each_owners_newest_audit_action_of_this_round(self) -> None:
        child = _load("child-status.json")
        child["start_time"] = START_ISO
        board = Board(_load("lab-input.json"), lambda: (_load("parent-status.json"), child), live=self.live)
        (self.root / TH).mkdir(parents=True)
        case = {"case_id": "dns-lab-001", "ok": True}
        (self.root / TH / "audit.jsonl").write_text("\n".join(json.dumps(entry) for entry in (
            {**case, "t": START_MS - 1, "profile": TH, "action": "open", "query": "an earlier round"},
            {**case, "t": START_MS + 5, "profile": TH, "action": "type", "text": "dns.question.name:x", "submit": True},
            {**case, "t": START_MS + 9, "profile": TH, "case_id": "another-case", "action": "open", "query": "y"},
        )) + "\n", encoding="utf-8")
        browsers = json.loads(board.state_bytes())["browsers"]
        self.assertEqual([item["profile"] for item in browsers], [TH, NA])
        action = browsers[0]["action"]
        self.assertEqual((action["query"], action["submitted"]), ("dns.question.name:x", True))
        self.assertIsNone(browsers[1]["action"])
        # The fixture round has no Temporal start time: no round, so no caption.
        self.assertEqual([item["action"] for item in json.loads(self.board.state_bytes())["browsers"]], [None, None])

    def test_cli_exits_when_websockets_is_missing(self) -> None:
        real = importlib.util.find_spec
        with mock.patch("importlib.util.find_spec", lambda name, *a: None if name == "websockets" else real(name, *a)), \
                mock.patch("sys.stderr") as stderr:
            code = main(["--workflow-id", "w", "--input", str(FIXTURES / "lab-input.json"),
                         "--hermes-home", self.tmp.name])
        self.assertEqual(code, 2)
        message = "".join(call.args[0] for call in stderr.write.call_args_list)
        self.assertIn("websockets", message)
        self.assertIn("hermes_temporal/requirements.txt", message)


ARKIME = "http://127.0.0.1:8005"
LAB_EVENTS = [
    {"event.id": "evt-000101", "@timestamp": "2025-10-14T05:00:00Z", "host.name": "ws-01",
     "event.category": ["process"], "event.type": ["start"], "process.entity_id": "p-1",
     "process.name": "beacon.exe", "process.pid": 100},
    {"event.id": "evt-000102", "@timestamp": "2025-10-14T05:01:00Z", "host.name": "ws-01",
     "event.category": "network", "process.entity_id": "p-1", "dns.question.name": "cdn.example.test"},
]
ACTIVITY = [
    {"seq": 1, "time": "2026-11-06T10:00:01Z", "profile": "framework-researcher", "tool": "elastic_aggregate",
     "endpoint": "/es/aggs", "params": {"q": "", "field": "host.name"}, "result_count": 3, "total": 500, "error": None},
    {"seq": 2, "time": "2026-11-06T10:00:05Z", "profile": "framework-researcher", "tool": "elastic_search",
     "endpoint": "/es/search", "params": {"q": "process.name:beacon.exe", "size": "50"}, "result_count": 50,
     "total": 120, "error": None},
    {"seq": 3, "time": "2026-11-06T10:01:00Z", "profile": "framework-network-analyst", "tool": "arkime_sessions",
     "endpoint": "/arkime/sessions", "params": {"expression": "host.dns == cdn.example.test", "length": "50"},
     "result_count": 12, "total": 12, "error": None},
    {"seq": 4, "time": "2026-11-06T10:01:30Z", "profile": "unknown", "tool": "elastic_search",
     "endpoint": "/es/search", "params": {"q": "bad:("}, "result_count": 0, "total": None, "error": "invalid_query"},
]


def _handoff(step_id: str, profile: str, *statements: str) -> str:
    return json.dumps({
        "schema_version": 1, "case_id": "lab-med-001", "step_id": step_id, "profile": profile,
        "claims": [{"claim_id": f"{step_id}:c{index}", "kind": "observed", "statement": statement,
                    "evidence_ids": ["lab-case-1"], "entity_ids": [], "contradicts": []}
                   for index, statement in enumerate(statements, 1)],
        "reviews": [], "disposition": "review_ready", "limitations": [], "requested_decisions": []})


def _tool_child(stage: str = "executing", step_id: str = "network") -> dict:
    outputs = [
        _handoff("scope", "framework-coordinator", "Scope set for lab-med-001."),
        _handoff("evidence", "framework-researcher",
                 "process.name:beacon.exe returned evt-000101 then evt-000102; evt-009999 was also named."),
        _handoff("hypotheses", "framework-researcher", "Disconfirming query found evt-000102 only."),
    ]
    return {"stage": stage, "step_id": step_id, "execution_id": "x", "temporal_status": "RUNNING",
            "results": [{"status": "completed", "output": output, "reason_code": None} for output in outputs]}


def _epoch_seconds(text: str) -> str:
    return str(int(datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp()))


class ToolDrivenBoardTests(unittest.TestCase):
    def setUp(self) -> None:
        self.raw = tool_input()
        self.lab = FakeLab(events=LAB_EVENTS, activity=ACTIVITY)
        self.addCleanup(self.lab.close)

    def observer(self, case_id: str = "lab-med-001") -> LabObserver:
        return LabObserver(lambda: {"lab_url": self.lab.url, "arkime_url": ARKIME}, case_id)

    def test_cited_ids_accept_four_or_more_digits(self) -> None:
        handoff, _ = parse_handoff(_handoff("scope", "framework-coordinator", "evt-0001, evt-000123 and evt-12."))
        self.assertEqual(handoff["claims"][0]["cited_events"], ["evt-0001", "evt-000123"])

    def test_timeline_map_and_tool_panel_come_from_the_lab(self) -> None:
        observer = self.observer()
        child = _tool_child()
        observer.refresh(["evt-000101", "evt-000102", "evt-009999"])
        state = build_state(self.raw, None, child, observer.snapshot())
        self.assertEqual(state["input_errors"], [])
        self.assertEqual(state["mode"], "tool_driven")
        self.assertEqual([event["id"] for event in state["timeline"]["events"]], ["evt-000101", "evt-000102"])
        events = _events(state)
        self.assertEqual(events["evt-000101"]["cited_by"], ["evidence"])
        self.assertEqual(events["evt-000102"]["cited_by"], ["evidence", "hypotheses"])
        self.assertEqual(events["evt-000102"]["category"], "network")
        evidence = next(item for item in state["feed"] if item["step_id"] == "evidence")
        self.assertEqual(evidence["unknown_cited_ids"], ["evt-009999"])
        nodes = {node["id"]: node for node in state["graph"]["nodes"]}
        self.assertEqual(nodes["process:ws-01:p-1"]["label"], "beacon.exe")
        self.assertEqual(nodes["domain:cdn.example.test"]["cited_event_ids"], ["evt-000102"])

        tools = state["tools"]
        lanes = {lane["profile"]: lane for lane in tools["lanes"]}
        self.assertEqual(list(lanes)[:6], ["framework-coordinator", "framework-researcher", "framework-network-analyst",
                                           "framework-librarian", "framework-builder", "framework-reviewer"])
        self.assertEqual(tools["working_profile"], "framework-network-analyst")
        self.assertEqual([lane["profile"] for lane in tools["lanes"] if lane["working"]], ["framework-network-analyst"])
        self.assertEqual([entry["seq"] for entry in lanes["framework-researcher"]["entries"]], [2, 1])
        self.assertEqual(lanes["framework-researcher"]["entries"][0]["query"], "process.name:beacon.exe")
        self.assertEqual((lanes["framework-researcher"]["entries"][0]["result_count"],
                          lanes["framework-researcher"]["entries"][0]["total"]), (50, 120))
        self.assertEqual((lanes["unknown"]["errors"], lanes["unknown"]["entries"][0]["error"]), (1, "invalid_query"))
        arkime = lanes["framework-network-analyst"]["entries"][0]
        self.assertEqual(arkime["query"], "host.dns == cdn.example.test")
        url = parse.urlsplit(arkime["arkime_ui_url"])
        self.assertEqual(f"{url.scheme}://{url.netloc}{url.path}", ARKIME + "/sessions")
        query = {key: values[0] for key, values in parse.parse_qs(url.query).items()}
        self.assertEqual(query["expression"], 'tags == "case:lab-med-001" && (host.dns == cdn.example.test)')
        self.assertEqual(query["startTime"], _epoch_seconds("2025-10-14T04:30:00Z"))
        self.assertEqual(query["stopTime"], _epoch_seconds("2025-10-14T10:30:00Z"))
        self.assertEqual(query["bounding"], "first")
        self.assertIsNone(lanes["framework-researcher"]["entries"][0]["arkime_ui_url"])

    def test_untagged_window_scoped_lab_links_without_case_tag(self) -> None:
        lab = FakeLab(activity=ACTIVITY, network_scope="window")
        self.addCleanup(lab.close)
        observer = LabObserver(lambda: {"lab_url": lab.url, "arkime_url": ARKIME}, "lab-med-001")
        observer.refresh([])
        lanes = {lane["profile"]: lane for lane in build_state(self.raw, None, None, observer.snapshot())["tools"]["lanes"]}
        url = parse.urlsplit(lanes["framework-network-analyst"]["entries"][0]["arkime_ui_url"])
        self.assertEqual(parse.parse_qs(url.query)["expression"], ["(host.dns == cdn.example.test)"])

    def test_unlooked_citations_are_pending_not_unknown(self) -> None:
        state = build_state(self.raw, None, _tool_child(), {"events": {}, "missing": [], "activity": []})
        evidence = next(item for item in state["feed"] if item["step_id"] == "evidence")
        self.assertEqual(evidence["unknown_cited_ids"], [])
        self.assertEqual(evidence["pending_cited_ids"], ["evt-000101", "evt-000102", "evt-009999"])
        self.assertEqual(state["timeline"]["events"], [])
        self.assertIsNone(build_state(_load("lab-input.json"), None, None)["tools"])

    def test_observer_skips_tool_calls_made_before_the_hunt(self) -> None:
        lab = FakeLab(events=[], activity=[dict(ACTIVITY[0], seq=seq) for seq in range(1, 8)])
        self.addCleanup(lab.close)
        observer = LabObserver(lambda: {"lab_url": lab.url, "arkime_url": None}, "lab-med-001", activity_after=5)
        observer.refresh([])
        self.assertEqual([entry["seq"] for entry in observer.snapshot()["activity"]], [6, 7])

    def test_observer_pages_activity_and_batches_cached_lookups(self) -> None:
        events = [{"event.id": f"evt-{number:06d}", "@timestamp": "2025-10-14T05:00:00Z", "host.name": "ws-02"}
                  for number in range(1, 61)]
        activity = [dict(ACTIVITY[0], seq=seq) for seq in range(1, 251)]
        lab = FakeLab(events=events, activity=activity)
        self.addCleanup(lab.close)
        observer = LabObserver(lambda: {"lab_url": lab.url, "arkime_url": None}, "lab-med-001")
        cited = [f"evt-{number:06d}" for number in range(1, 71)]
        observer.refresh(cited)
        snapshot = observer.snapshot()
        self.assertTrue(snapshot["reachable"])
        self.assertEqual([entry["seq"] for entry in snapshot["activity"]], list(range(1, 251)))
        self.assertEqual(sorted(snapshot["events"]), cited[:60])
        self.assertEqual(snapshot["missing"], cited[60:])
        searches = [query for path, query, _ in lab.requests if path == "/es/search"]
        self.assertGreater(len(searches), 1)
        self.assertTrue(all(len(query["q"]) <= 500 and int(query["size"]) <= 200 for query in searches))
        self.assertEqual({profile for _, _, profile in lab.requests}, {"hunt-board"})
        before = len(lab.requests)
        lab.activity.append(dict(ACTIVITY[0], seq=251))
        observer.refresh(cited)
        self.assertEqual(lab.paths()[before:], ["/activity"])
        self.assertEqual(lab.requests[before][1]["after"], "250")
        snapshot = observer.snapshot()
        self.assertEqual(snapshot["activity"][-1]["seq"], 251)
        self.assertEqual(snapshot["new_after"], 250)

    def test_other_case_or_unreachable_lab_is_reported_without_data(self) -> None:
        observer = self.observer("lab-other-001")
        observer.refresh(["evt-000101"])
        snapshot = observer.snapshot()
        self.assertTrue(snapshot["error"])
        self.assertEqual((snapshot["activity"], snapshot["events"]), ([], {}))
        resolved = []

        def closed_port():
            resolved.append(True)
            return {"lab_url": "http://127.0.0.1:9", "arkime_url": None}

        down = LabObserver(closed_port, "lab-med-001")
        down.refresh([])
        down.refresh([])
        self.assertFalse(down.snapshot()["reachable"])
        self.assertEqual(len(resolved), 2)

    def test_board_server_serves_tool_state(self) -> None:
        board = Board(self.raw, lambda: ({"stage": "running_round"}, _tool_child()), lab=self.observer())
        server = make_server(board, 0)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 5)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        connection = http.client.HTTPConnection("127.0.0.1", server.server_address[1], timeout=10)
        connection.request("GET", "/state.json")
        state = json.loads(connection.getresponse().read())
        connection.close()
        self.assertTrue(state["tools"]["lab"]["reachable"])
        self.assertEqual(state["tools"]["entry_count"], 4)
        self.assertEqual(state["cited_event_count"], 2)

    def test_cli_requires_lab_for_tool_input_only(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tool_path = Path(directory) / "tool.json"
            tool_path.write_text(json.dumps(self.raw), encoding="utf-8")
            inline_path = FIXTURES / "lab-input.json"
            self.assertEqual(main(["--workflow-id", "w", "--input", str(tool_path)]), 2)
            self.assertEqual(main(["--workflow-id", "w", "--input", str(inline_path), "--lab-url", self.lab.url]), 2)
            with self.assertRaises(SystemExit):
                main(["--workflow-id", "w", "--input", str(tool_path), "--lab-url", "http://localhost:8765"])
        self.assertEqual(self.lab.requests, [])


WAVES = {"scope": 1, "evidence": 2, "hypotheses": 2, "network": 2, "intel": 2, "analysis": 3, "detection": 4,
         "purple": 5, "incident": 6}


def _tokens(total: int) -> dict:
    return {"input_tokens": total - 300, "output_tokens": 200, "cache_read_tokens": 100, "cache_write_tokens": 0,
            "total_tokens": total, "duration_ms": total * 2}


def _wave_child(states: dict, results: list[dict], **extra) -> dict:
    """A parallel round's status as the board observes it: every step reported, wave 2 open.

    ``states`` maps a step to its state or ``(state, reason)``; other steps are not reached. A step's
    execution ID is set once it was dispatched, as the workflow reports it."""
    steps = []
    for index, step_id in enumerate(STEP_IDS):
        state = states.get(step_id, "not_reached")
        state, reason = state if isinstance(state, tuple) else (state, "")
        steps.append({"step_id": step_id, "state": state, "wave": WAVES[step_id], "reason": reason,
                      "execution_id": None if state in ("not_reached", "awaiting_approval") else f"{ROUND}:{index}"})
    return {"stage": "executing", "step_id": "wave-2", "execution_id": None, "temporal_status": "RUNNING",
            "results": results, "handoff_rejections": [], "steps": steps, **extra}


class _History:
    """A Temporal client and workflow handle whose history is ``events``; counts the reads."""

    def __init__(self) -> None:
        self.events: list = []
        self.reads = 0

    def get_workflow_handle(self, workflow_id: str) -> "_History":
        return self

    async def fetch_history(self, skip_archival: bool):
        self.reads += 1
        return types.SimpleNamespace(events=list(self.events))


class ParallelBoardTests(unittest.TestCase):
    """A parallel round: several steps open in one wave, results matched by execution ID, dropped steps, usage."""

    def setUp(self) -> None:
        self.raw = dict(_load("lab-input.json"), parallel=True)
        self.parent = _load("parent-status.json")
        self.outputs = [result["output"] for result in _load("child-status.json")["results"]]

    def result(self, index: int, **fields) -> dict:
        return {"status": "completed", "execution_id": f"{ROUND}:{index}", "output": self.outputs[index],
                "reason_code": "completed", "session_id": None, "usage": None, **fields}

    def test_wave_steps_take_state_wave_reason_and_usage_from_their_own_execution(self) -> None:
        failed = self.result(4, status="failed", output="", reason_code="native_failed", usage=_tokens(900))
        results = [failed, self.result(3, usage=_tokens(4000)), self.result(0, usage=_tokens(1500))]
        states = {"scope": "done", "evidence": "working", "hypotheses": "working", "network": "awaiting_review",
                  "intel": ("dropped", "native_failed")}
        spans = [{"execution_id": f"{ROUND}:1", "scheduled_ms": 30_000, "closed_ms": None},
                 {"execution_id": f"{ROUND}:2", "scheduled_ms": 30_500, "closed_ms": None},
                 {"execution_id": f"{ROUND}:3", "scheduled_ms": 31_000, "closed_ms": 60_000},
                 {"execution_id": f"{ROUND}:4", "scheduled_ms": 31_500, "closed_ms": 40_000}]
        state = build_state(self.raw, self.parent,
                            _wave_child(states, results, workflow_id=ROUND, activity_spans=spans))
        steps = state["steps"]
        self.assertEqual(_states(state), ["done", "working", "working", "awaiting_review", "dropped"] + ["pending"] * 4)
        self.assertEqual([step["wave"] for step in steps], [1, 2, 2, 2, 2, 3, 4, 5, 6])
        self.assertEqual([step["optional"] for step in steps], [False] + [True] * 4 + [False] * 4)
        self.assertEqual([step["reason"] for step in steps], [""] * 4 + ["native_failed"] + [""] * 4)
        self.assertEqual([step["usage"] for step in steps],
                         [_tokens(1500), None, None, _tokens(4000), _tokens(900)] + [None] * 4)
        self.assertEqual([step["result"] and step["result"]["status"] for step in steps],
                         ["completed", None, None, "completed", "failed"] + [None] * 4)
        self.assertEqual(steps[4]["result"]["reason_code"], "native_failed")
        self.assertEqual([(item["step_id"], item["handoff"] and item["handoff"]["step_id"], item["counted"])
                          for item in state["feed"]],
                         [("intel", None, False), ("network", "network", True), ("scope", "scope", True)])
        self.assertEqual(steps[1]["timing"],
                         {"started_ms": 30_000, "ended_ms": None, "duration_ms": None, "attempts": 1})
        self.assertEqual([steps[index]["timing"]["duration_ms"] for index in (3, 4)], [29_000, 8_500])
        states["network"] = "done"
        reviewed = build_state(self.raw, self.parent, _wave_child(states, results))
        self.assertEqual(_states(reviewed)[3:5], ["done", "dropped"])
        self.assertEqual(reviewed["steps"][3]["usage"], _tokens(4000))

    def test_a_dropped_step_carries_its_failure_diagnostic_to_its_view_and_card(self) -> None:
        cause = "exit code 1: model declined to respond (finish_reason=content_filter, category cyber)"
        refused = self.result(4, status="unknown", output="", reason_code="native_nonzero", diagnostic=cause)
        child = _wave_child({"scope": "done", "evidence": "awaiting_review", "intel": ("dropped", "native_nonzero")},
                            [self.result(0), self.result(1), refused])
        state = build_state(self.raw, self.parent, child)
        self.assertEqual([step["result"] and step["result"]["diagnostic"] for step in state["steps"][:5]],
                         [None, None, None, None, cause])
        self.assertEqual({item["step_id"]: item["diagnostic"] for item in state["feed"]},
                         {"scope": None, "evidence": None, "intel": cause})

    def test_the_page_names_a_dropped_steps_diagnostic_where_it_lists_the_step(self) -> None:
        cause = "exit code 1: model declined to respond (finish_reason=content_filter, category cyber)"
        refused = self.result(4, status="unknown", output="", reason_code="native_nonzero", diagnostic=cause)
        child = _wave_child({"scope": "done", "evidence": "awaiting_review", "intel": ("dropped", "native_nonzero")},
                            [self.result(0), self.result(1), refused])
        state = build_state(self.raw, self.parent, child)
        rail = _render_page(state, "agents")["rail"]
        self.assertIn("dropped \u00b7 native nonzero: " + cause, rail["text"])
        self.assertTrue(any(title.endswith("native nonzero: " + cause) for title in rail["titles"]), rail["titles"])
        inbox = _render_page(state, "", phone=True)["main"]
        self.assertIn("wave 2 \u00b7 dropped \u00b7 native nonzero: " + cause, inbox["text"])
        case = _render_page(state, "case")["main"]
        self.assertIn("dropped: native nonzero: " + cause, case["text"])
        self.assertIn("dropped: native nonzero: " + cause, case["titles"])

    def test_an_all_dropped_round_names_each_steps_cause_in_the_agents_rail(self) -> None:
        cause = "exit code 1: model declined to respond (finish_reason=content_filter, category cyber)"
        child = _wave_child({step_id: ("dropped", "native_nonzero") for step_id in STEP_IDS}, [])
        state = build_state(self.raw, self.parent, child)
        state["steps"][0]["result"] = {"status": "unknown", "reason_code": "native_nonzero", "diagnostic": cause}
        rail = _render_page(state, "agents")["rail"]
        self.assertIn("wave 1 \u00b7 dropped \u00b7 native nonzero: " + cause, rail["text"])
        self.assertIn("wave 2 \u00b7 dropped \u00b7 native nonzero", rail["text"])

    def test_a_wave_gate_id_marks_no_step_current(self) -> None:
        gate = _wave_child({"scope": "done", **dict.fromkeys(STEP_IDS[1:5], "awaiting_approval")}, [self.result(0)],
                           stage="awaiting_execution_approval")
        state = build_state(self.raw, self.parent, gate)
        self.assertEqual(state["run"]["child"]["step_id"], "wave-2")
        self.assertEqual(_states(state), ["done"] + ["awaiting_approval"] * 4 + ["pending"] * 4)
        # Four results would place a serial round's open step at index 4, the dropped step.
        later = _wave_child({**dict.fromkeys(STEP_IDS[:4], "done"), "intel": ("dropped", "timeout"),
                             "analysis": "awaiting_approval"}, [self.result(index) for index in (2, 0, 3, 1)],
                            stage="awaiting_execution_approval", step_id="wave-3")
        state = build_state(self.raw, self.parent, later)
        self.assertEqual(_states(state), ["done"] * 4 + ["dropped", "awaiting_approval"] + ["pending"] * 3)
        self.assertIsNone(state["steps"][4]["result"])
        self.assertEqual([step["result"]["parsed"] for step in state["steps"][:4]], [True] * 4)

    def test_a_stopped_or_closed_parallel_round_leaves_no_step_open(self) -> None:
        rejected = _wave_child({**dict.fromkeys(STEP_IDS[:5], "done"), "analysis": ("stopped", "retry_exhausted")}, [],
                               stage="handoff_validation_rejected", step_id="wave-3", temporal_status="COMPLETED")
        state = build_state(self.raw, self.parent, rejected)
        self.assertEqual(_states(state), ["done"] * 5 + ["stopped"] + ["not_reached"] * 3)
        self.assertEqual(state["steps"][5]["reason"], "retry_exhausted")
        terminated = _wave_child({"scope": "done", "evidence": "working", "hypotheses": "awaiting_review",
                                  "network": "awaiting_approval", "intel": ("dropped", "timeout")}, [],
                                 temporal_status="TERMINATED")
        state = build_state(self.raw, self.parent, terminated)
        self.assertEqual(_states(state), ["done"] + ["stopped"] * 3 + ["dropped"] + ["not_reached"] * 4)
        self.assertEqual(state["steps"][1]["reason"], "working (Temporal TERMINATED)")
        self.assertEqual([member["open_steps"] for member in state["team"]], [[]] * 6)

    def test_run_summary_totals_usage_and_lists_dropped_steps(self) -> None:
        results = [self.result(4, status="failed", output="", reason_code="timeout", usage=_tokens(900)),
                   self.result(0, usage=_tokens(1500)), self.result(1)]
        child = _wave_child({"scope": "done", "evidence": "awaiting_review", "intel": ("dropped", "timeout")}, results)
        run = build_state(self.raw, self.parent, child)["run"]
        self.assertEqual(run["usage_total"], {"input_tokens": 1800, "output_tokens": 400, "cache_read_tokens": 200,
                                              "cache_write_tokens": 0, "total_tokens": 2400, "duration_ms": 4800})
        self.assertEqual(run["dropped"], [{"step_id": "intel", "reason": "timeout"}])
        unmetered = build_state(_load("lab-input.json"), self.parent, _load("child-status.json"))["run"]
        self.assertIsNone(unmetered["usage_total"])
        self.assertEqual(unmetered["dropped"], [])
        self.assertEqual(build_state(self.raw, None, None)["run"],
                         {"parent": None, "child": None, "usage_total": None, "dropped": []})

    def test_stage_time_counts_the_overlapping_steps_of_a_wave_once(self) -> None:
        spans = [{"execution_id": f"{ROUND}:0", "scheduled_ms": 1_000, "closed_ms": 22_000},
                 *({"execution_id": f"{ROUND}:{index}", "scheduled_ms": 30_000, "closed_ms": 90_000}
                   for index in range(1, 5))]
        reviewed = build_state(self.raw, self.parent, _wave_child(dict.fromkeys(STEP_IDS[:5], "done"), [],
                                                                  workflow_id=ROUND, activity_spans=spans))
        self.assertEqual([step["timing"]["duration_ms"] for step in reviewed["steps"][:5]], [21_000] + [60_000] * 4)
        self.assertEqual(reviewed["stage_time"], {"closed_ms": 21_000 + 60_000, "open_since_ms": None})
        self.assertEqual(reviewed["waves"][:3], [{"wave": 1, "closed_ms": 21_000, "open_since_ms": None},
                                                 {"wave": 2, "closed_ms": 60_000, "open_since_ms": None},
                                                 {"wave": 3, "closed_ms": None, "open_since_ms": None}])
        # Three lanes still run; the dropped lane's 20 s lie inside their span and add nothing.
        open_spans = [spans[0], *(dict(span, closed_ms=None) for span in spans[1:4]), dict(spans[4], closed_ms=50_000)]
        states = {"scope": "done", **dict.fromkeys(STEP_IDS[1:4], "working"), "intel": ("dropped", "timeout")}
        running = build_state(self.raw, self.parent,
                              _wave_child(states, [], workflow_id=ROUND, activity_spans=open_spans))
        self.assertEqual(running["stage_time"], {"closed_ms": 21_000, "open_since_ms": 30_000})
        self.assertEqual(running["waves"][1], {"wave": 2, "closed_ms": 0, "open_since_ms": 30_000})

    def test_tool_lanes_follow_every_working_profile_and_count_its_steps(self) -> None:
        child = _wave_child({"scope": "done", "evidence": "working", "hypotheses": "working", "network": "working",
                             "intel": "awaiting_review"}, [])
        lab = {"activity": ACTIVITY, "events": {}, "missing": []}
        tools = build_state(tool_input(parallel=True), None, child, lab)["tools"]
        self.assertEqual([lane["profile"] for lane in tools["lanes"]].count(TH), 1)
        self.assertEqual({lane["profile"]: lane["working_steps"] for lane in tools["lanes"] if lane["working"]},
                         {TH: 2, NA: 1})
        self.assertEqual([lane["working_steps"] for lane in tools["lanes"] if not lane["working"]], [0] * 5)
        self.assertEqual(tools["working_profile"], TH)

    def test_team_lists_every_open_step_of_a_profile_and_keeps_current(self) -> None:
        child = _wave_child({"scope": "done", "evidence": "working", "hypotheses": "awaiting_review",
                             "network": "working", "intel": ("dropped", "timeout")}, [self.result(0), self.result(2)])
        team = {member["profile"]: member for member in build_state(self.raw, self.parent, child)["team"]}
        self.assertEqual(team[TH]["open_steps"], [{"step_id": "evidence", "state": "working"},
                                                  {"step_id": "hypotheses", "state": "awaiting_review"}])
        self.assertEqual(team[TH]["current"], 1)
        self.assertEqual(team[NA]["open_steps"], [{"step_id": "network", "state": "working"}])
        for profile in ("framework-coordinator", "framework-librarian"):
            self.assertEqual((team[profile]["open_steps"], team[profile]["current"]), ([], None))

    def test_history_is_re_read_until_every_running_activity_of_a_wave_is_readable(self) -> None:
        with mock.patch("threading.Thread"):
            observer = TemporalObserver("127.0.0.1:7233", "practice-1")
        self.addCleanup(observer._loop.close)
        observer._client = history = _History()

        def spans(child: dict) -> list[dict]:
            return asyncio.run(observer._activity_spans(ROUND, child))

        child = _wave_child({"scope": "done", "evidence": "working", "hypotheses": "working"}, [self.result(0)])
        history.events = [_scheduled(10, 1_000, f"{ROUND}:0"), _closed(12, 2_000, 10),
                          _scheduled(20, 3_000, f"{ROUND}:1")]
        self.assertEqual(len(spans(child)), 2)
        history.events.append(_scheduled(22, 3_100, f"{ROUND}:2"))
        self.assertEqual(len(spans(child)), 3)
        spans(child)
        self.assertEqual(history.reads, 2)
        # A step can leave the wave without a new result; its activity's close time is still read.
        spans(_wave_child({"scope": "done", "evidence": ("dropped", "timeout"), "hypotheses": "working"},
                          [self.result(0)]))
        self.assertEqual(history.reads, 3)


if __name__ == "__main__":
    unittest.main()

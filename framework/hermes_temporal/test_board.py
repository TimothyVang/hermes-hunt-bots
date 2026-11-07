"""Consumer-visible behavior of the read-only hunt board (no Temporal server needed)."""
from __future__ import annotations

import copy
import http.client
import importlib.util
import json
import tempfile
import threading
import unittest
from datetime import datetime
from pathlib import Path
from urllib import parse

if importlib.util.find_spec("temporalio") is None:
    raise unittest.SkipTest("Install hermes_temporal/requirements.txt to run hunt board tests.")

from .board import Board, LabObserver, ObservationError, build_state, main, make_server, parse_handoff  # noqa: E402
from .test_hunt import tool_input  # noqa: E402
from .test_lab_input import FakeLab  # noqa: E402
from .workflows import _unwrap_single_fence  # noqa: E402

FIXTURES = Path(__file__).with_name("fixtures") / "board"
STEP_IDS = ["scope", "evidence", "hypotheses", "network", "intel", "analysis", "detection", "purple", "incident"]


def _load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


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


if __name__ == "__main__":
    unittest.main()

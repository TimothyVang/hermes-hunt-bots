"""Offline tests for the bounded synthetic lab evidence exporter."""
from __future__ import annotations

import asyncio
import argparse
import importlib.util

import json
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import tempfile
import types
import unittest
from urllib import parse

from unittest.mock import patch
from . import lab_input
from .hunt import supplied_evidence_hunt

TOOL_CASE = {
    "case_id": "lab-med-001", "schema_version": 1,
    "question": "Which synthetic hosts beacon, and what limits the conclusion?",
    "sources": [{"artifact": "events.jsonl", "coverage": "invented endpoint events"},
                {"artifact": "intel.jsonl", "coverage": "invented indicators"}],
    "time_range_utc": {"start_inclusive": "2025-10-14T04:30:00Z", "end_exclusive": "2025-10-14T10:30:00Z"},
}
# As hunt_lab.import_dedale writes it; nothing in it calls the data synthetic.
PUBLIC_CASE = {
    "case_id": "dedale-001", "schema_version": 1, "network_capture": "none", "data_origin": "public-dataset",
    "question": "What happened in this environment during the window? Cite event.id values.",
    "sources": [{"artifact": "events.jsonl", "coverage": "Real Windows winlogbeat ECS records from 2 hosts of a lab network"}],
    "time_range_utc": {"start_inclusive": "2022-01-01T00:00:00Z", "end_exclusive": "2022-01-01T06:00:00Z"},
}
# As hunt_lab.import_elastic writes it; nothing in it calls the data synthetic.
WORK_CASE = {
    "case_id": "work-001", "schema_version": 1, "network_capture": "none", "data_origin": "work-export",
    "question": "What happened in this environment during the window? Cite event.id values.",
    "sources": [{"artifact": "events.jsonl", "coverage": "Real ECS records exported from the operator's work Elastic"}],
    "time_range_utc": {"start_inclusive": "2026-11-01T00:00:00Z", "end_exclusive": "2026-11-01T06:00:00Z"},
}
WORK_TEXT = "work log export (real telemetry from the operator's environment; unclassified work data)"
# As an operator writes it for hunt_lab.connected serve; names no cluster or index.
CONNECTED_CASE = {
    "case_id": "work-conn-001", "schema_version": 1, "network_capture": "none", "data_origin": "work-connected",
    "question": "What ran on ws-01 and ws-02 during the window? Cite event.id values.",
    "sources": [{"artifact": "work Elastic", "coverage": "Real Sysmon process events from the operator's work Elastic"}],
    "time_range_utc": {"start_inclusive": "2026-11-01T10:00:00Z", "end_exclusive": "2026-11-01T11:00:00Z"},
    "hosts": ["ws-01", "ws-02"],
}
CONNECTED_TEXT = ("work log connection (live read-only queries of the operator's work Elastic; "
                  "unclassified work data)")


class FakeLab:
    """A loopback stand-in for the guest lab API: /case, /health, paged /activity and /es/search by event.id."""

    def __init__(self, case=None, events=(), activity=(), *, redirect=False, body=None, network_scope="tag",
                 instance=None, refuse_unknown=False):
        self.case = dict(case or TOOL_CASE)
        self.instance = instance
        self.refuse_unknown = refuse_unknown
        self.network_scope = network_scope
        self.events = {event["event.id"]: event for event in events}
        self.activity = list(activity)
        self.requests: list[tuple[str, dict, str | None]] = []
        lab = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                url = parse.urlsplit(self.path)
                query = {key: values[-1] for key, values in parse.parse_qs(url.query).items()}
                lab.requests.append((url.path, query, self.headers.get("X-Hermes-Profile")))
                if redirect:
                    self.send_response(302)
                    self.send_header("Location", "http://127.0.0.1:9/case")
                    self.end_headers()
                    return
                answer = body if body is not None else lab.route(url.path, query)
                self._json(*(answer if isinstance(answer, tuple) else (200, answer)))

            def _json(self, status, value):
                data = json.dumps(value).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                if lab.instance:
                    self.send_header("X-Hunt-Lab-Instance", lab.instance)
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *_args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def route(self, path, query):
        case_id = self.case["case_id"]
        if path == "/case":
            return self.case
        if path == "/health":
            return {"case_id": case_id, "ready": True, "network_scope": self.network_scope}
        if path == "/activity":
            after, limit = int(query.get("after", 0)), int(query.get("limit", 100))
            page = [entry for entry in self.activity if entry["seq"] > after][:limit]
            more = len([entry for entry in self.activity if entry["seq"] > after]) > len(page)
            return {"case_id": case_id, "next": page[-1]["seq"] if page else after, "more": more, "entries": page}
        if path == "/es/search":
            cited = re.findall(r"evt-\d+", query.get("q", ""))
            if self.refuse_unknown and set(cited) - set(self.events):
                return 400, {"error": "unknown_citation"}
            hits = [self.events[event_id] for event_id in cited if event_id in self.events]
            return {"case_id": case_id, "total": len(hits), "total_relation": "eq", "returned": len(hits),
                    "hits": hits, "next_after": None}
        return {"case_id": case_id}

    def paths(self):
        return [path for path, _query, _profile in self.requests]

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(5)


def write_connected_state(analyst: Path, lab: FakeLab, case_id: str) -> str:
    """Write the state.json `hunt_lab.connected serve` writes for `lab`; returns the VM state dir beside it."""
    (analyst / "hunt-lab-connected").mkdir(parents=True, exist_ok=True)
    (analyst / "hunt-lab-connected" / "state.json").write_text(json.dumps({
        "version": 1, "pid": 1, "port": lab.server.server_address[1], "case_id": case_id,
        "instance": lab.instance, "api_key_env": "HUNT_ELASTIC_API_KEY"}), encoding="utf-8")
    return str(analyst / "hunt-lab-vm")


def fake_runtime(status):
    calls = []

    def invoke(action, *, state_dir, profile):
        calls.append((action, state_dir, profile))
        return dict(status)

    return types.SimpleNamespace(invoke=invoke, calls=calls)


class FixtureAdapter:
    def __init__(self, events=None, network=None, *, fault=None, case=None):
        self.events = events if events is not None else [
            {"@timestamp": f"2025-04-15T09:{number:02d}:00Z",
             "event": {"id": f"evt-{number:04d}", "dataset": "dns-lab-001"},
             "message": "Synthetic fixture event."}
            for number in range(1, 5)
        ]
        self.network = network if network is not None else [
            {
                "firstPacket": 1744707660000,
                "lastPacket": 1744707660001,
                "source": {"ip": "192.0.2.11", "port": 53000},
                "destination": {"ip": "192.0.2.53", "port": 53},
                "network": {"packets": 2, "bytes": 174},
                "node": "hermes-lab",
                "dns": [{"host": ["status-gateway.test"]}],
            },
            {"firstPacket": 1744707661000, "lastPacket": 1744707661001,
             "source.ip": "192.0.2.12", "destination.ip": "192.0.2.53",
             "dns.host": ["updates.vendor.test"]},
        ]
        self.case = case or {
            "case_id": "dns-lab-001", "schema_version": 1,
            "question": "Describe only observations and coverage limits.",
            "sources": [{"artifact": "events.jsonl", "coverage": "bounded synthetic events"}],
            "time_range_utc": {"start_inclusive": "2025-04-15T09:00:00Z",
                               "end_exclusive": "2025-04-15T10:00:00Z"},
        }
        self.fault = fault
        self.event_offsets = []

    def query_lab(self, arguments, *, runtime, state_dir, profile):
        case_id = "dns-lab-001"
        if self.fault == "owner_stopped":
            return {"ok": False, "profile": profile, "error": "owned_vm_not_running"}
        if self.fault == "wrong_owner":
            return {"ok": True, "profile": "wrong-owner", "case_id": case_id, "evidence": {}}
        if self.fault == "case_mismatch":
            case_id = "other-case"
        dataset = arguments["dataset"]
        if dataset == "events":
            self.event_offsets.append(arguments["offset"])
        if dataset == "case":
            evidence = dict(self.case)
            evidence["case_id"] = case_id
        else:
            rows = self.events if dataset == "events" else self.network
            offset = arguments["offset"]
            limit = arguments["limit"]
            selected = rows[offset:offset + limit]
            total = len(rows)
            evidence = {"case_id": case_id, "dataset": dataset, "total": total,
                        "total_relation": "eq", "offset": offset, "limit": limit,
                        "returned": len(selected), "more": offset + len(selected) < total,
                        "records": selected, "read_only": True}
            if self.fault == "incomplete" and offset == 0:
                evidence["returned"] += 1
        return {"ok": True, "profile": profile, "case_id": case_id, "evidence": evidence}


class LabInputTests(unittest.TestCase):
    def collect(self, adapter, case_id="dns-lab-001"):
        modules = {"hunt_lab.runtime": types.SimpleNamespace(), "hunt_lab.query_adapter": adapter}
        with patch.object(lab_input.importlib, "import_module", side_effect=modules.__getitem__):
            return lab_input.collect_lab_input("approved-state", case_id)

    def test_complete_fixture_is_hunt_valid_and_contains_all_ids_not_truth(self):
        raw = self.collect(FixtureAdapter())
        request = supplied_evidence_hunt(raw)
        self.assertEqual(len(request.steps), 9)
        source_ids = {item["source_id"] for item in raw["evidence"]}
        by_step = {step.step_id: step for step in request.steps}
        self.assertEqual(len(source_ids), len(raw["evidence"]))
        encoded_records = "\n".join(item["content"] for item in raw["evidence"])
        self.assertTrue(all(f"evt-{number:04d}" in encoded_records for number in range(1, 5)))
        self.assertIn("coverage", encoded_records)
        repeated = self.collect(FixtureAdapter())
        self.assertEqual(
            source_ids,
            {item["source_id"] for item in repeated["evidence"]},
        )
        self.assertNotIn('"truth":', json.dumps(raw).lower())
        network_content = "\n".join(
            item["content"] for item in raw["evidence"] if ":summary/network/" in item["locator"]
        )
        self.assertIn("status-gateway.test", network_content)
        self.assertIn('"source":{"ip":"192.0.2.11","port":53000}', network_content)
        self.assertIn('"network":{"bytes":174,"packets":2}', network_content)
        self.assertIn("updates.vendor.test", network_content)
        self.assertEqual(
            set(by_step["evidence"].hunt_context["evidence_ids"]),
            {item["source_id"] for item in raw["evidence"] if ":summary/case" in item["locator"]
             or ":summary/events/" in item["locator"]},
        )
        self.assertEqual(
            set(by_step["hypotheses"].hunt_context["evidence_ids"]),
            {item["source_id"] for item in raw["evidence"] if ":summary/case" in item["locator"]},
        )

    def test_complete_multipage_collection_fetches_every_event_record(self):
        adapter = FixtureAdapter(events=[
            {"event": {"id": f"evt-{number:04d}"}, "message": "x"}
            for number in range(1, 202)
        ])
        raw = self.collect(adapter)
        self.assertEqual(adapter.event_offsets, [0, 200])
        event_content = "\n".join(
            item["content"] for item in raw["evidence"] if ":summary/events/" in item["locator"]
        )
        self.assertTrue(all(f"evt-{number:04d}" in event_content for number in range(1, 202)))


    def test_bundled_range_fixture_fits_full_scoped_hunt(self):
        root = Path(__file__).resolve().parents[1] / "hunt_lab" / "fixtures" / "dns-lab-001"
        case = json.loads((root / "case.json").read_text(encoding="utf-8"))
        events = [json.loads(line) for line in (root / "events.jsonl").read_text(encoding="utf-8").splitlines()]
        network = [
            {
                "firstPacket": 1744707660000 + number * 1000,
                "lastPacket": 1744707660001 + number * 1000,
                "source": {"ip": f"192.0.2.{11 + number % 2}", "port": 53000 + number},
                "destination": {"ip": "192.0.2.53", "port": 53},
                "network": {"packets": 2, "bytes": 174 + number},
                "node": "hermes-lab",
                "dns": [{"host": [f"session-{number:02d}.test"]}],
            }
            for number in range(16)
        ]
        self.assertEqual(len(events), 40)
        raw = self.collect(FixtureAdapter(events, network, case=case))
        request = supplied_evidence_hunt(raw)
        self.assertEqual(len(request.steps), 9)
        all_content = "\n".join(item["content"] for item in raw["evidence"])
        self.assertTrue(all(event["event"]["id"] in all_content for event in events))
        network_content = "\n".join(
            item["content"] for item in raw["evidence"] if ":summary/network/" in item["locator"]
        )
        self.assertTrue(all(f"session-{number:02d}.test" in network_content for number in range(16)))
    def test_rejects_wrong_case_and_stopped_or_wrong_owner(self):
        for adapter in (FixtureAdapter(fault="case_mismatch"),
                        FixtureAdapter(fault="owner_stopped"),
                        FixtureAdapter(fault="wrong_owner")):
            with self.subTest(fault=adapter.fault), self.assertRaises(lab_input.LabInputError):
                self.collect(adapter)

    def test_rejects_incomplete_pagination_and_oversize_record(self):
        with self.assertRaises(lab_input.LabInputError):
            self.collect(FixtureAdapter(fault="incomplete"))
        huge = [{"event": {"id": "evt-large"}, "message": "x" * 9000}]
        with self.assertRaises(lab_input.LabInputError):
            self.collect(FixtureAdapter(events=huge))

    def test_refuses_nonfixed_case(self):
        with self.assertRaises(lab_input.LabInputError):
            self.collect(FixtureAdapter(), case_id="another-case")

    @unittest.skipUnless(importlib.util.find_spec("temporalio") is not None, "Temporal SDK is optional")
    def test_lab_input_cli_uses_exclusive_output(self):
        from . import cli

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "existing.json"
            path.write_text("keep", encoding="utf-8")
            with patch.object(lab_input, "collect_lab_input", return_value={"synthetic_only": True}):
                with self.assertRaises(FileExistsError):
                    asyncio.run(cli._lab_input(argparse.Namespace(state_dir="state", output=str(path), tool_driven=False,
                                                                  data_origin=None, case_id=None)))
            self.assertEqual(path.read_text(encoding="utf-8"), "keep")

    @unittest.skipUnless(importlib.util.find_spec("temporalio") is not None, "Temporal SDK is optional")
    def test_lab_input_cli_tool_driven_flag_exports_tool_input(self):
        from . import cli

        args = cli._parser().parse_args(["lab-input", "--state-dir", "state", "--output", "x.json", "--tool-driven"])
        self.assertTrue(args.tool_driven)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "tool.json"
            with patch.object(lab_input, "collect_tool_input", return_value={"mode": "tool_driven"}) as tool, \
                    patch.object(lab_input, "collect_lab_input") as inline:
                asyncio.run(cli._lab_input(argparse.Namespace(state_dir="state", output=str(path), tool_driven=True,
                                                              data_origin=None, case_id=None)))
            tool.assert_called_once_with("state", data_origin=None, case_id=None)
            inline.assert_not_called()
            self.assertEqual(json.loads(path.read_text(encoding="utf-8")), {"mode": "tool_driven"})

    @unittest.skipUnless(importlib.util.find_spec("temporalio") is not None, "Temporal SDK is optional")
    def test_lab_input_cli_passes_the_data_origin_only_for_tool_driven(self):
        from . import cli

        for origin in ("public-dataset", "work-export", "work-connected"):
            args = cli._parser().parse_args(["lab-input", "--state-dir", "state", "--output", "x.json", "--tool-driven",
                                             "--data-origin", origin])
            self.assertEqual(args.data_origin, origin)
        self.assertIsNone(cli._parser().parse_args(["lab-input", "--state-dir", "s", "--output", "x"]).data_origin)
        for origin in ("synthetic", "customer"):
            with self.subTest(origin=origin), self.assertRaises(SystemExit), \
                    patch("sys.stderr"):
                cli._parser().parse_args(["lab-input", "--state-dir", "s", "--output", "x", "--tool-driven",
                                          "--data-origin", origin])
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "tool.json"
            with patch.object(lab_input, "collect_tool_input", return_value={"mode": "tool_driven"}) as tool:
                asyncio.run(cli._lab_input(argparse.Namespace(state_dir="state", output=str(path), tool_driven=True,
                                                              data_origin="work-connected", case_id="work-conn-001")))
            tool.assert_called_once_with("state", data_origin="work-connected", case_id="work-conn-001")
            inline = Path(directory) / "inline.json"
            with patch.object(lab_input, "collect_lab_input") as collect, self.assertRaises(ValueError):
                asyncio.run(cli._lab_input(argparse.Namespace(state_dir="state", output=str(inline), tool_driven=False,
                                                              data_origin="public-dataset", case_id=None)))
            with patch.object(lab_input, "collect_lab_input") as collect_case, self.assertRaises(ValueError):
                asyncio.run(cli._lab_input(argparse.Namespace(state_dir="state", output=str(inline), tool_driven=False,
                                                              data_origin=None, case_id="work-conn-001")))
            collect.assert_not_called()
            collect_case.assert_not_called()
            self.assertFalse(inline.exists())
        args = cli._parser().parse_args(["lab-input", "--state-dir", "s", "--output", "x", "--tool-driven",
                                         "--case-id", "work-conn-001"])
        self.assertEqual(args.case_id, "work-conn-001")

    @unittest.skipUnless(importlib.util.find_spec("temporalio") is not None, "Temporal SDK is optional")
    def test_new_input_json_rejects_duplicate_and_nonfinite_values(self):
        from .cli import _strict_json

        for text in ('{"scope":1,"scope":2}', '{"value":NaN}'):
            with self.subTest(text=text), self.assertRaises(ValueError):
                _strict_json(text)


class ToolDrivenInputTests(unittest.TestCase):
    STATUS = {"profile": "framework-network-analyst", "state": "running"}

    def collect(self, lab, status=None, **options):
        runtime = fake_runtime({**self.STATUS, "lab_url": lab.url, **(status or {})})
        with patch.object(lab_input.importlib, "import_module", side_effect={"hunt_lab.runtime": runtime}.__getitem__):
            return lab_input.collect_tool_input("approved-state", **options), runtime

    def test_export_reads_only_case_metadata_for_the_loaded_case(self):
        lab = FakeLab(events=[{"event.id": "evt-000001", "message": "never exported"}])
        self.addCleanup(lab.close)
        raw, runtime = self.collect(lab)
        self.assertEqual(lab.paths(), ["/case"])
        self.assertEqual(runtime.calls, [("status", "approved-state", "framework-network-analyst")])
        self.assertEqual(raw["mode"], "tool_driven")
        self.assertEqual(raw["ontology"]["case_id"], "lab-med-001")
        [item] = raw["evidence"]
        self.assertEqual(item["locator"], "lab-med-001:summary/case")
        self.assertIn(TOOL_CASE["question"], item["content"])
        self.assertNotIn("evt-000001", json.dumps(raw))
        request = supplied_evidence_hunt(raw)
        self.assertEqual(len(request.steps), 9)
        for step in request.steps:
            self.assertEqual(step.hunt_context["evidence_ids"], [item["source_id"]])
            self.assertIn("lab-med-001", step.prompt)
        self.assertEqual(self.collect(lab)[0], raw)

    def test_a_log_only_case_is_exported_with_its_network_capture_field(self):
        lab = FakeLab(case={**TOOL_CASE, "network_capture": "none"})
        self.addCleanup(lab.close)
        raw, _runtime = self.collect(lab)
        self.assertIn('"network_capture":"none"', raw["evidence"][0]["content"])
        supplied_evidence_hunt(raw)

    def test_public_dataset_case_is_refused_without_operator_approval(self):
        lab = FakeLab(case=PUBLIC_CASE)
        self.addCleanup(lab.close)
        with self.assertRaisesRegex(lab_input.LabInputError, "--data-origin public-dataset"):
            self.collect(lab)
        raw, _runtime = self.collect(lab, data_origin="public-dataset")
        self.assertIs(raw["synthetic_only"], False)
        self.assertEqual(raw["data_origin"], "public-dataset")
        self.assertTrue(raw["scope"].startswith(
            "Public research dataset dedale-001 (real lab telemetry, no customer data) only; "))
        # Live: a report listed 12 of 20 IDs in one series and dropped a whole process's two events.
        self.assertIn("first at least one per distinct process and per event.category of each process", raw["scope"])
        bot_visible = {key: value for key, value in raw.items() if key != "synthetic_only"}
        self.assertNotIn("synthetic", json.dumps(bot_visible).lower())
        request = supplied_evidence_hunt(raw)
        self.assertEqual((request.synthetic_only, request.data_origin), (False, "public-dataset"))
        for step in request.steps:
            self.assertNotIn("synthetic", step.prompt.lower())
            self.assertIn("public research dataset (real lab telemetry, no customer data)", step.prompt)

    def test_work_export_case_is_exported_only_with_its_own_origin(self):
        lab = FakeLab(case=WORK_CASE)
        self.addCleanup(lab.close)
        for approval in ({}, {"data_origin": "public-dataset"}, {"data_origin": "synthetic"}):
            with self.subTest(approval=approval), self.assertRaises(lab_input.LabInputError):
                self.collect(lab, **approval)
        raw, _runtime = self.collect(lab, data_origin="work-export")
        self.assertIs(raw["synthetic_only"], False)
        self.assertEqual(raw["data_origin"], "work-export")
        self.assertTrue(raw["scope"].startswith(
            "Work log export work-001 (real telemetry from the operator's environment; unclassified work data) only; "))
        self.assertTrue(raw["evidence"][0]["content"].startswith("Untrusted " + WORK_TEXT + " lab case metadata"))
        bot_visible = {key: value for key, value in raw.items() if key != "synthetic_only"}
        self.assertNotIn("synthetic", json.dumps(bot_visible).lower())
        self.assertNotIn("public research dataset", json.dumps(bot_visible).lower())
        for request in (supplied_evidence_hunt(raw), supplied_evidence_hunt(dict(raw, parallel=True, follow_ups=2))):
            self.assertEqual((request.synthetic_only, request.data_origin), (False, "work-export"))
            for step in request.steps:
                with self.subTest(step=step.step_id):
                    self.assertNotIn("synthetic", step.prompt.lower())
                    self.assertIn("Work log export tool-driven hunt: the loaded lab case is a " + WORK_TEXT, step.prompt)

    def test_a_synthetic_case_is_refused_with_a_data_origin(self):
        lab = FakeLab()
        self.addCleanup(lab.close)
        for origin in ("public-dataset", "work-export"):
            with self.subTest(origin=origin), self.assertRaisesRegex(lab_input.LabInputError, "synthetic"):
                self.collect(lab, data_origin=origin)
        raw, _runtime = self.collect(lab)
        self.assertIs(raw["synthetic_only"], True)
        self.assertNotIn("data_origin", raw)

    def test_unknown_data_origin_is_refused(self):
        for origin in ("synthetic", "customer", "", None, ["work-export"]):
            lab = FakeLab(case={**PUBLIC_CASE, "data_origin": origin})
            self.addCleanup(lab.close)
            with self.subTest(origin=origin), self.assertRaises(lab_input.LabInputError):
                self.collect(lab, data_origin="public-dataset")

    def test_export_refuses_unowned_unsafe_or_malformed_lab(self):
        endpoint_faults = ({"state": "stopped"}, {"profile": "framework-researcher"},
                           {"lab_url": "http://192.0.2.10:8765"}, {"lab_url": "https://127.0.0.1:8765"},
                           {"lab_url": "http://localhost:8765"}, {"lab_url": "http://127.0.0.1:8765/api"})
        lab = FakeLab()
        self.addCleanup(lab.close)
        for status in endpoint_faults:
            with self.subTest(status=status), self.assertRaises(lab_input.LabInputError):
                self.collect(lab, status)
        self.assertEqual(lab.requests, [])
        bad_cases = ({**TOOL_CASE, "case_id": "Lab Med"}, {**TOOL_CASE, "truth": "x"},
                     {key: value for key, value in TOOL_CASE.items() if key != "schema_version"},
                     {**TOOL_CASE, "sources": "events.jsonl"}, {**TOOL_CASE, "network_capture": "full"})
        for case in bad_cases:
            bad = FakeLab(case=case)
            self.addCleanup(bad.close)
            with self.subTest(case=case), self.assertRaises(lab_input.LabInputError):
                self.collect(bad)
        for kwargs in ({"redirect": True}, {"body": ["not", "an", "object"]}, {"body": {"pad": "x" * (512 * 1024)}}):
            odd = FakeLab(**kwargs)
            self.addCleanup(odd.close)
            with self.subTest(kwargs=list(kwargs)), self.assertRaises(lab_input.LabInputError):
                self.collect(odd)


    def connected(self, case):
        """A connected service serving `case`, found through the state.json it writes beside the VM's state dir."""
        lab = FakeLab(case=case, instance="a" * 32)
        self.addCleanup(lab.close)
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        return lab, write_connected_state(Path(temp.name) / "framework-network-analyst", lab, case["case_id"])

    def test_export_finds_a_connected_case_while_the_vm_is_stopped_and_refuses_two_labs(self):
        lab, state_dir = self.connected(CONNECTED_CASE)
        runtime = fake_runtime({**self.STATUS, "state": "stopped"})
        modules = {"hunt_lab.runtime": runtime}.__getitem__
        with patch.object(lab_input.importlib, "import_module", side_effect=modules):
            raw = lab_input.collect_tool_input(state_dir, data_origin="work-connected")
        self.assertEqual(raw["ontology"]["case_id"], "work-conn-001")
        self.assertEqual(lab.paths(), ["/case"])
        vm = FakeLab()
        self.addCleanup(vm.close)
        runtime = fake_runtime({**self.STATUS, "lab_url": vm.url})
        with patch.object(lab_input.importlib, "import_module", side_effect={"hunt_lab.runtime": runtime}.__getitem__), \
                self.assertRaisesRegex(lab_input.LabInputError, "^lab input unavailable: ambiguous_lab$"):
            lab_input.collect_tool_input(state_dir, data_origin="work-connected")
        with patch.object(lab_input.importlib, "import_module", side_effect={"hunt_lab.runtime": runtime}.__getitem__):
            raw = lab_input.collect_tool_input(state_dir, data_origin="work-connected", case_id="work-conn-001")
            self.assertEqual(raw["ontology"]["case_id"], "work-conn-001")
            self.assertEqual(lab_input.collect_tool_input(state_dir, case_id="lab-med-001")["ontology"]["case_id"],
                             "lab-med-001")
        with patch.object(lab_input.importlib, "import_module", side_effect={"hunt_lab.runtime": runtime}.__getitem__):
            self.assertEqual(lab_input.resolve_lab(state_dir, "work-conn-001").origin, "connected")
            self.assertEqual(lab_input.resolve_lab(state_dir, "lab-med-001").origin, "vm")

    def test_a_connected_answer_must_carry_its_instance(self):
        lab, state_dir = self.connected(CONNECTED_CASE)
        lab.instance = "b" * 32
        runtime = fake_runtime({**self.STATUS, "state": "stopped"})
        with patch.object(lab_input.importlib, "import_module", side_effect={"hunt_lab.runtime": runtime}.__getitem__), \
                self.assertRaisesRegex(lab_input.LabInputError, "lab_instance_mismatch"):
            lab_input.collect_tool_input(state_dir, data_origin="work-connected")
        self.assertEqual(lab_input.lab_get(lab.url, "/case")["case_id"], "work-conn-001")
        with self.assertRaises(lab_input.LabInputError):
            lab_input.lab_get(lab.url, "/case", instance="a" * 32)

    def test_a_connected_case_is_exported_only_from_a_connected_service_with_its_origin(self):
        _lab, state_dir = self.connected(CONNECTED_CASE)
        runtime = fake_runtime({**self.STATUS, "state": "stopped"})
        with patch.object(lab_input.importlib, "import_module", side_effect={"hunt_lab.runtime": runtime}.__getitem__):
            for approval in (None, "work-export", "public-dataset"):
                with self.subTest(approval=approval), self.assertRaises(lab_input.LabInputError):
                    lab_input.collect_tool_input(state_dir, data_origin=approval)
            raw = lab_input.collect_tool_input(state_dir, data_origin="work-connected")
        self.assertEqual((raw["synthetic_only"], raw["data_origin"]), (False, "work-connected"))
        self.assertTrue(raw["scope"].startswith("Work log connection work-conn-001 (live read-only queries"))
        [item] = raw["evidence"]
        self.assertIn("Untrusted " + CONNECTED_TEXT + " lab case", item["content"])
        self.assertIn('"hosts":["ws-01","ws-02"]', item["content"])
        self.assertNotIn("synthetic", (raw["scope"] + item["content"]).lower())
        request = supplied_evidence_hunt(raw)
        self.assertEqual((request.synthetic_only, request.data_origin, request.tool_driven), (False, "work-connected", True))
        for step in request.steps:
            self.assertIn(CONNECTED_TEXT, step.prompt)
            self.assertNotIn("synthetic", step.prompt.lower())

    def test_a_vm_case_claiming_the_connected_origin_or_bad_hosts_is_refused(self):
        vm = FakeLab(case=CONNECTED_CASE)
        self.addCleanup(vm.close)
        with self.assertRaises(lab_input.LabInputError):
            self.collect(vm, data_origin="work-connected")
        hosted = FakeLab(case={**WORK_CASE, "hosts": ["ws-01"]})
        self.addCleanup(hosted.close)
        with self.assertRaises(lab_input.LabInputError):
            self.collect(hosted, data_origin="work-export")
        unlabelled, state_dir = self.connected({**TOOL_CASE, "case_id": "work-conn-002"})
        runtime = fake_runtime({**self.STATUS, "state": "stopped"})
        with self.assertRaises(lab_input.LabInputError), \
                patch.object(lab_input.importlib, "import_module", side_effect={"hunt_lab.runtime": runtime}.__getitem__):
            lab_input.collect_tool_input(state_dir)
        self.assertEqual(unlabelled.paths(), ["/case"])
        for hosts in ([], ["ws-01", "ws-01"], ["ws\n01"], [" ws-01"], "ws-01", [1], [f"h{n}" for n in range(51)]):
            _lab, state_dir = self.connected({**CONNECTED_CASE, "hosts": hosts})
            runtime = fake_runtime({**self.STATUS, "state": "stopped"})
            with self.subTest(hosts=hosts), self.assertRaises(lab_input.LabInputError), \
                    patch.object(lab_input.importlib, "import_module", side_effect={"hunt_lab.runtime": runtime}.__getitem__):
                lab_input.collect_tool_input(state_dir, data_origin="work-connected")


if __name__ == "__main__":
    unittest.main()

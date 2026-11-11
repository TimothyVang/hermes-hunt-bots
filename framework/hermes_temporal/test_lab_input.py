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


class FakeLab:
    """A loopback stand-in for the guest lab API: /case, /health, paged /activity and /es/search by event.id."""

    def __init__(self, case=None, events=(), activity=(), *, redirect=False, body=None, network_scope="tag"):
        self.case = dict(case or TOOL_CASE)
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
                self._json(body if body is not None else lab.route(url.path, query))

            def _json(self, value):
                data = json.dumps(value).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
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
            hits = [self.events[event_id] for event_id in re.findall(r"evt-\d+", query.get("q", ""))
                    if event_id in self.events]
            return {"case_id": case_id, "total": len(hits), "total_relation": "eq", "returned": len(hits),
                    "hits": hits, "next_after": None}
        return {"case_id": case_id}

    def paths(self):
        return [path for path, _query, _profile in self.requests]

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(5)


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
                                                                  allow_public_dataset=False)))
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
                                                              allow_public_dataset=False)))
            tool.assert_called_once_with("state", allow_public_dataset=False)
            inline.assert_not_called()
            self.assertEqual(json.loads(path.read_text(encoding="utf-8")), {"mode": "tool_driven"})

    @unittest.skipUnless(importlib.util.find_spec("temporalio") is not None, "Temporal SDK is optional")
    def test_lab_input_cli_passes_public_dataset_approval_only_for_tool_driven(self):
        from . import cli

        args = cli._parser().parse_args(["lab-input", "--state-dir", "state", "--output", "x.json", "--tool-driven",
                                         "--allow-public-dataset"])
        self.assertTrue(args.allow_public_dataset)
        self.assertFalse(cli._parser().parse_args(["lab-input", "--state-dir", "s", "--output", "x"]).allow_public_dataset)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "tool.json"
            with patch.object(lab_input, "collect_tool_input", return_value={"mode": "tool_driven"}) as tool:
                asyncio.run(cli._lab_input(argparse.Namespace(state_dir="state", output=str(path), tool_driven=True,
                                                              allow_public_dataset=True)))
            tool.assert_called_once_with("state", allow_public_dataset=True)
            inline = Path(directory) / "inline.json"
            with patch.object(lab_input, "collect_lab_input") as collect, self.assertRaises(ValueError):
                asyncio.run(cli._lab_input(argparse.Namespace(state_dir="state", output=str(inline), tool_driven=False,
                                                              allow_public_dataset=True)))
            collect.assert_not_called()
            self.assertFalse(inline.exists())

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
        with self.assertRaises(lab_input.LabInputError):
            self.collect(lab)
        raw, _runtime = self.collect(lab, allow_public_dataset=True)
        self.assertIs(raw["synthetic_only"], False)
        self.assertEqual(raw["data_origin"], "public-dataset")
        self.assertTrue(raw["scope"].startswith(
            "Public research dataset dedale-001 (real lab telemetry, no customer data) only; "))
        bot_visible = {key: value for key, value in raw.items() if key != "synthetic_only"}
        self.assertNotIn("synthetic", json.dumps(bot_visible).lower())
        request = supplied_evidence_hunt(raw)
        self.assertEqual((request.synthetic_only, request.data_origin), (False, "public-dataset"))
        for step in request.steps:
            self.assertNotIn("synthetic", step.prompt.lower())
            self.assertIn("public research dataset (real lab telemetry, no customer data)", step.prompt)

    def test_approval_does_not_change_a_synthetic_export(self):
        lab = FakeLab()
        self.addCleanup(lab.close)
        raw, _runtime = self.collect(lab, allow_public_dataset=True)
        self.assertEqual(raw, self.collect(lab)[0])
        self.assertIs(raw["synthetic_only"], True)
        self.assertNotIn("data_origin", raw)

    def test_unknown_data_origin_is_refused(self):
        for origin in ("synthetic", "customer", "", None):
            lab = FakeLab(case={**PUBLIC_CASE, "data_origin": origin})
            self.addCleanup(lab.close)
            with self.subTest(origin=origin), self.assertRaises(lab_input.LabInputError):
                self.collect(lab, allow_public_dataset=True)

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



if __name__ == "__main__":
    unittest.main()

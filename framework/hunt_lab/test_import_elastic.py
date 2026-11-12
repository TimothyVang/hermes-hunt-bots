"""Behavior tests for the work Elastic exporter and importer, on synthetic records only.

Run from framework/: python -m unittest -v hunt_lab.test_import_elastic
The exporter talks to an injected fake transport that plays Elasticsearch's point-in-time
search; no network connection is opened and no real cluster or work data is read.
"""

import contextlib
import hashlib
import io
import json
from pathlib import Path
import random
import tempfile
import unittest

from hunt_lab import case_files, import_dedale, import_elastic


URL = "https://elastic.example.test:9243"
KEY = "c2VjcmV0LWtleS1pZDpzZWNyZXQta2V5LXZhbHVl"
ENV = {"HUNT_ELASTIC_API_KEY": KEY}
START, END = "2026-11-01T10:00:00Z", "2026-11-01T11:00:00Z"


def doc(timestamp, host, number, **fields):
    return {"@timestamp": timestamp, "host": {"name": host}, "message": "fixture record %d" % number,
            "event": {"code": str(4600 + number), "module": "security"},
            "data_stream": {"dataset": "system.security"}, **fields}


DOCS = [
    ("logs-a", "id-%d" % number, doc("2026-11-01T10:%02d:00.000Z" % number, "WS1" if number % 2 else "WS2", number))
    for number in range(7)
]


def reply(status, value):
    return status, json.dumps(value).encode("utf-8")


class FakeElastic:
    """A point-in-time search over docs, filtered by the request's own range and host terms."""

    def __init__(self, docs=DOCS, version="8.13.4", distribution=None, total=None, fail=None):
        self.docs, self.version, self.distribution, self.total, self.fail = list(docs), version, distribution, total, fail
        self.calls = []
        self.pits = 0

    def paths(self):
        return [(method, url[len(URL):]) for method, url, _, _ in self.calls]

    def __call__(self, method, url, headers, body):
        value = json.loads(body) if body is not None else None
        self.calls.append((method, url, dict(headers), value))
        path = url[len(URL):]
        if self.fail:
            failure = self.fail(method, path, value, len(self.calls))
            if failure:
                return failure
        if (method, path) == ("GET", "/"):
            version = {"number": self.version}
            if self.distribution:
                version["distribution"] = self.distribution
            return reply(200, {"name": "node-1", "version": version})
        if method == "POST" and path.endswith("/_pit?keep_alive=2m"):
            self.pits += 1
            return reply(200, {"id": "pit-%d" % self.pits})
        if (method, path) == ("POST", "/_search"):
            return reply(200, self.search(value))
        if (method, path) == ("DELETE", "/_pit"):
            return reply(200, {"succeeded": True, "num_freed": 1})
        return reply(404, {"error": {"type": "unexpected_request"}})

    def search(self, body):
        window = body["query"]["bool"]["filter"][0]["range"]["@timestamp"]
        start, end = import_dedale.parse_time(window["gte"]), import_dedale.parse_time(window["lt"])
        hosts = body["query"]["bool"]["filter"][1]["terms"]["host.name"] if len(body["query"]["bool"]["filter"]) > 1 else None
        matched = [(import_dedale.parse_time(source["@timestamp"]), position, index, identifier, source)
                   for position, (index, identifier, source) in enumerate(self.docs)
                   if start <= import_dedale.parse_time(source["@timestamp"]) < end
                   and (hosts is None or source["host"]["name"] in hosts)]
        matched.sort()
        after = body.get("search_after")
        if after is not None:
            matched = [row for row in matched if [row[0], row[1]] > after]
        page = matched[:body["size"]]
        self.pits += 1
        hits = {"hits": [{"_index": index, "_id": identifier, "_score": None, "_source": source, "sort": [timestamp, position]}
                         for timestamp, position, index, identifier, source in page]}
        if body["track_total_hits"] is not False:
            count = self.total if self.total is not None else len(matched)
            limit = body["track_total_hits"]
            hits["total"] = {"value": min(count, limit), "relation": "gte" if count >= limit else "eq"}
        return {"pit_id": "pit-%d" % self.pits, "took": 1, "hits": hits}


class Export(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.output = self.root / "window.ndjson"
        self.meta = self.root / "window.ndjson.meta.json"

    def export(self, fake, **options):
        options.setdefault("environ", ENV)
        return import_elastic.export_window(URL, options.pop("index", "logs-*"), options.pop("start", START),
                                            options.pop("end", END), options.pop("output", self.output),
                                            transport=fake, **options)

    def assert_nothing_written(self):
        self.assertFalse(self.output.exists() or self.meta.exists())

    def test_pages_through_one_point_in_time_and_closes_it(self):
        fake = FakeElastic()
        summary = self.export(fake, page_size=3)
        self.assertEqual(fake.paths(), [("GET", "/"), ("POST", "/logs-*/_pit?keep_alive=2m"), ("POST", "/_search"),
                                        ("POST", "/_search"), ("POST", "/_search"), ("DELETE", "/_pit")])
        searches = [body for method, url, _, body in fake.calls if url.endswith("/_search")]
        # Each page continues from the previous page's last sort values inside the newest point-in-time id.
        self.assertEqual([body["pit"] for body in searches], [{"id": "pit-1", "keep_alive": "2m"},
                                                              {"id": "pit-2", "keep_alive": "2m"},
                                                              {"id": "pit-3", "keep_alive": "2m"}])
        self.assertEqual([body.get("search_after") for body in searches],
                         [None, [import_dedale.parse_time(DOCS[2][2]["@timestamp"]), 2],
                          [import_dedale.parse_time(DOCS[5][2]["@timestamp"]), 5]])
        self.assertEqual([body["track_total_hits"] for body in searches], [200001, False, False])
        self.assertEqual(fake.calls[-1][3], {"id": "pit-4"})
        lines = self.output.read_bytes().splitlines()
        self.assertEqual([json.loads(line) for line in lines],
                         [{"_id": identifier, "_index": index, "_source": source} for index, identifier, source in DOCS])
        data = self.output.read_bytes()
        meta = json.loads(self.meta.read_text(encoding="utf-8"))
        self.assertEqual(meta, {
            "schema_version": 1, "kind": "elastic-export", "host": "elastic.example.test:9243", "index": "logs-*",
            "time_range_utc": {"start_inclusive": START, "end_exclusive": END}, "hosts": None, "event_count": 7,
            "max_events": 200000, "elastic_version": "8.13.4",
            "ndjson": {"file": "window.ndjson", "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}})
        self.assertEqual(summary, dict(meta, output=str(self.output), meta=str(self.meta), point_in_time_closed=True))

    def test_query_holds_the_window_the_hosts_and_the_stable_sort(self):
        docs = DOCS + [("logs-a", "early", doc("2026-11-01T09:59:59.999Z", "WS1", 90)),
                       ("logs-a", "at-end", doc(END, "WS1", 91)),
                       ("logs-b", "other-host", doc("2026-11-01T10:30:00Z", "WS3", 92))]
        fake = FakeElastic(docs)
        summary = self.export(fake, hosts=["WS2", " WS1 ", "", "WS2"], start="2026-11-01T11:00:00+01:00")
        body = fake.calls[2][3]
        self.assertEqual(body["query"], {"bool": {"filter": [
            {"range": {"@timestamp": {"gte": START, "lt": END, "format": "strict_date_optional_time_nanos"}}},
            {"terms": {"host.name": ["WS1", "WS2"]}}]}})
        self.assertEqual(body["sort"], [{"@timestamp": {"order": "asc", "numeric_type": "date_nanos"}}, {"_shard_doc": "asc"}])
        self.assertEqual(body["size"], 5000)
        self.assertNotIn("index", json.dumps(body))
        self.assertEqual(summary["hosts"], ["WS1", "WS2"])
        self.assertEqual(summary["event_count"], 7)
        self.assertEqual([json.loads(line)["_id"] for line in self.output.read_bytes().splitlines()],
                         [identifier for _, identifier, _ in DOCS])

    def test_api_key_is_sent_but_never_written_printed_or_reported(self):
        fake = FakeElastic()
        self.export(fake)
        self.assertEqual({headers["Authorization"] for _, _, headers, _ in fake.calls}, {"ApiKey " + KEY})
        for path in (self.output, self.meta):
            self.assertNotIn(KEY, path.read_text(encoding="utf-8"))

        def unauthorized(method, path, body, number):
            return reply(401, {"error": {"type": "security_exception", "reason": "unable to authenticate with ApiKey " + KEY}})
        with self.assertRaises(import_elastic.ExportError) as caught:
            self.export(FakeElastic(fail=unauthorized), output=self.root / "denied.ndjson")
        self.assertEqual(str(caught.exception), "read cluster version: Elasticsearch returned HTTP 401 (security_exception)")

        def unreachable(method, path, body, number):
            raise OSError("connection reset while sending ApiKey " + KEY)
        with self.assertRaises(import_elastic.ExportError) as caught:
            self.export(FakeElastic(fail=unreachable), output=self.root / "unreachable.ndjson")
        self.assertNotIn(KEY, str(caught.exception))
        self.assertIn("cannot reach Elasticsearch at elastic.example.test:9243", str(caught.exception))

        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            status = import_elastic.main(["export", "--url", URL, "--index", "logs-*", "--start", START, "--end", END,
                                          "--output", str(self.root / "cli.ndjson")], transport=FakeElastic(), environ=ENV)
            failed = import_elastic.main(["export", "--url", URL, "--index", "logs-*", "--start", START, "--end", END,
                                          "--output", str(self.root / "cli-denied.ndjson")],
                                         transport=FakeElastic(fail=unauthorized), environ=ENV)
        self.assertEqual((status, failed), (0, 2))
        self.assertNotIn(KEY, stdout.getvalue())
        self.assertEqual(json.loads(stdout.getvalue().splitlines()[0])["event_count"], 7)

    def test_error_bodies_are_reduced_to_status_and_type(self):
        def broken(method, path, body, number):
            if path == "/_search":
                return 502, b"<html>gateway at 10.0.0.5 failed</html>"
        with self.assertRaises(import_elastic.ExportError) as caught:
            self.export(FakeElastic(fail=broken))
        self.assertEqual(str(caught.exception), "search: Elasticsearch returned HTTP 502")

        def odd_type(method, path, body, number):
            if path == "/_search":
                return reply(400, {"error": {"type": "Search failed: see host 10.0.0.5"}})
        with self.assertRaises(import_elastic.ExportError) as caught:
            self.export(FakeElastic(fail=odd_type))
        self.assertEqual(str(caught.exception), "search: Elasticsearch returned HTTP 400")

    def test_point_in_time_is_closed_and_partial_output_removed_on_error(self):
        def second_page_fails(method, path, body, number):
            if path == "/_search" and body.get("search_after") is not None:
                return reply(503, {"error": {"type": "search_phase_execution_exception"}})
        fake = FakeElastic(fail=second_page_fails)
        with self.assertRaisesRegex(import_elastic.ExportError, r"HTTP 503 \(search_phase_execution_exception\)"):
            self.export(fake, page_size=3)
        self.assertEqual(fake.paths()[-1], ("DELETE", "/_pit"))
        self.assertEqual(fake.calls[-1][3], {"id": "pit-2"})
        self.assert_nothing_written()

    def test_over_cap_window_is_refused_before_download(self):
        fake = FakeElastic()
        with self.assertRaisesRegex(import_elastic.ExportError,
                                    r"^the window holds more than --max-events 6 documents; nothing written"):
            self.export(fake, max_events=6)
        self.assertEqual(fake.paths()[-1], ("DELETE", "/_pit"))
        self.assertEqual(len([path for _, path in fake.paths() if path == "/_search"]), 1)
        self.assert_nothing_written()
        # A total that understates the hits still cannot exceed the cap.
        with self.assertRaisesRegex(import_elastic.ExportError, r"returned more than --max-events 6"):
            self.export(FakeElastic(total=1), max_events=6, page_size=4)
        self.assert_nothing_written()
        self.assertEqual(self.export(FakeElastic(), max_events=7)["event_count"], 7)

    def test_needs_point_in_time_search(self):
        for version, distribution in (("7.11.2", None), ("6.8.0", None), ("2.11.0", "opensearch"), ("x", None)):
            fake = FakeElastic(version=version, distribution=distribution)
            with self.subTest(version=version), self.assertRaises(import_elastic.ExportError):
                self.export(fake)
            self.assertEqual(fake.paths(), [("GET", "/")])
        self.assertEqual(self.export(FakeElastic(version="7.12.0"))["elastic_version"], "7.12.0")

    def test_refuses_unsafe_arguments_before_any_request(self):
        fake = FakeElastic()
        bad = (
            {"url": "http://elastic.example.test:9200"}, {"url": "https://user:pw@elastic.example.test"},
            {"url": URL + "/?api_key=x"}, {"url": URL + "#x"}, {"url": "https:///nohost"},
            {"index": "_all/_delete_by_query"}, {"index": "logs *"}, {"index": ""},
            {"environ": {}}, {"environ": {"HUNT_ELASTIC_API_KEY": KEY + "\r\nX-Other: 1"}},
            {"api_key_env": "NOT VALID"}, {"max_events": 0}, {"start": END, "end": START},
            {"start": "2026-11-01T10:00:00"}, {"hosts": [" "]}, {"ca_file": str(self.root / "missing.pem")},
        )
        for options in bad:
            url = options.pop("url", URL)
            with self.subTest(options=options, url=url), self.assertRaises(ValueError) as caught:
                options.setdefault("environ", ENV)
                import_elastic.export_window(url, options.pop("index", "logs-*"), options.pop("start", START),
                                             options.pop("end", END), self.output, transport=fake, **options)
            self.assertNotIn(KEY, str(caught.exception))
        self.assertEqual(fake.calls, [])
        self.assert_nothing_written()
        with self.assertRaisesRegex(import_elastic.ExportError, "HUNT_ELASTIC_API_KEY"):
            self.export(fake, environ={})

    def test_existing_output_or_sidecar_is_refused(self):
        for existing in (self.output, self.meta):
            with self.subTest(existing=existing.name):
                existing.write_text("keep", encoding="utf-8")
                fake = FakeElastic()
                with self.assertRaisesRegex(import_elastic.ExportError, "already exists"):
                    self.export(fake)
                self.assertEqual(fake.calls, [])
                self.assertEqual(existing.read_text(encoding="utf-8"), "keep")
                existing.unlink()

    def test_index_pattern_is_path_quoted(self):
        fake = FakeElastic()
        self.export(fake, index="logs-*,winlogbeat-*")
        self.assertEqual(fake.paths()[1], ("POST", "/logs-*,winlogbeat-*/_pit?keep_alive=2m"))


def raw_line(value):
    return json.dumps(value) + "\n"


class Import(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)

    def write(self, name, text):
        path = self.root / name
        path.write_text(text, encoding="utf-8")
        return path

    def run_import(self, source, name="case-evidence", **options):
        evidence = self.root / name
        summary = import_elastic.import_case(source, options.pop("case_id", "work-test-001"), options.pop("start", START),
                                             options.pop("end", END), evidence, **options)
        return summary, evidence

    def events(self, evidence):
        return [json.loads(line) for line in (evidence / "events.jsonl").read_text(encoding="utf-8").splitlines()]

    def test_window_sort_ids_and_dataset(self):
        records = [
            {"_index": "logs-b", "_id": "z", "_source": doc("2026-11-01T10:05:00Z", "WS2", 1)},
            {"_index": "logs-a", "_id": "y", "_source": doc("2026-11-01T10:05:00.000Z", "WS2", 2)},
            {"_index": "logs-a", "_id": "x", "_source": doc("2026-11-01T11:04:59+01:00", "WS1", 3,
                                                             event={"id": "src-77", "code": "1"})},
            {"_index": "logs-a", "_id": "w", "_source": doc("2026-11-01T09:59:59.999Z", "WS1", 4)},
            {"_index": "logs-a", "_id": "v", "_source": doc(END, "WS1", 5)},
            {"_index": "logs-a", "_id": "u", "_source": doc("2026-11-01T10:05:00Z", "WS1", 6)},
            {"_index": "logs-a", "_id": "t", "_source": doc(START, "WS3", 7)},
        ]
        source = self.write("export.ndjson", "".join(raw_line(record) for record in records))
        summary, evidence = self.run_import(source)
        events = self.events(evidence)
        # By instant (the +01:00 record is 10:04:59Z), then host.name, then _index, then _id.
        self.assertEqual([event["message"] for event in events],
                         ["fixture record 7", "fixture record 3", "fixture record 6", "fixture record 2", "fixture record 1"])
        self.assertEqual([event["event"]["id"] for event in events], ["evt-%06d" % number for number in range(1, 6)])
        self.assertEqual({event["event"]["dataset"] for event in events}, {"work-test-001"})
        self.assertEqual(events[1]["event"]["original_id"], "src-77")
        self.assertEqual([("original_id" in event["event"]) for event in events], [False, True, False, False, False])
        for event in events:
            self.assertFalse({"_index", "_id", "_source", "sort", "_score"} & set(event))
        self.assertEqual((summary["event_count"], summary["records_read"], summary["outside_window"], summary["host_count"]),
                         (5, 7, 2, 3))
        self.assertEqual(summary["data_origin"], "work-export")
        data = source.read_bytes()
        self.assertEqual(summary["input"], {"path": str(source), "sha256": hashlib.sha256(data).hexdigest()})

    def test_output_is_deterministic_whatever_the_input_order(self):
        records = [{"_index": "logs-a", "_id": "id-%d" % number,
                    "_source": doc("2026-11-01T10:%02d:00Z" % (number % 3), "WS%d" % (number % 2), number)}
                   for number in range(12)]
        records.append({"_index": "logs-a", "_id": "twin-1", "_source": doc("2026-11-01T10:01:00Z", "WS1", 50)})
        records.append({"_index": "logs-a", "_id": "twin-2", "_source": doc("2026-11-01T10:01:00Z", "WS1", 50)})
        first = self.write("first.ndjson", "".join(raw_line(record) for record in records))
        random.Random(7).shuffle(records)
        second = self.write("second.ndjson", "".join(raw_line(record) for record in records))
        _, one = self.run_import(first, "one")
        _, two = self.run_import(second, "two")
        _, again = self.run_import(first, "again")
        for name in ("events.jsonl", "case.json"):
            self.assertEqual((one / name).read_bytes(), (two / name).read_bytes())
            self.assertEqual((one / name).read_bytes(), (again / name).read_bytes())

    def test_three_input_shapes_give_the_same_case(self):
        exported = self.write("export.ndjson", "".join(raw_line({"_index": index, "_id": identifier, "_source": source})
                                                       for index, identifier, source in DOCS))
        raw = self.write("raw.ndjson", "\n" + "".join(raw_line(source) for _, _, source in DOCS))
        response = {"took": 3, "timed_out": False, "hits": {"total": {"value": 7, "relation": "eq"}, "hits": [
            {"_index": index, "_id": identifier, "_score": 1.0, "_source": source} for index, identifier, source in reversed(DOCS)]}}
        pretty = self.write("search.json", json.dumps(response, indent=2))
        compact = self.write("search-compact.json", json.dumps(response))
        outputs = []
        for number, path in enumerate((exported, raw, pretty, compact)):
            summary, evidence = self.run_import(path, "case-%d" % number)
            self.assertEqual(summary["event_count"], 7)
            outputs.append((evidence / "events.jsonl").read_bytes())
        self.assertEqual(len(set(outputs)), 1)

    def test_dotted_field_names_are_nested(self):
        record = {"@timestamp": "2026-11-01T10:10:00Z", "host.name": "WS9", "event.code": "4624", "event": {"kind": "event"},
                  "user": {"name": "alice", "domain.name": "CORP"}, "process.args": [{"a.b": 1}]}
        _, evidence = self.run_import(self.write("dotted.ndjson", raw_line(record)))
        [event] = self.events(evidence)
        self.assertEqual(event["host"], {"name": "WS9"})
        self.assertEqual(event["event"], {"kind": "event", "code": "4624", "id": "evt-000001", "dataset": "work-test-001"})
        self.assertEqual(event["user"], {"name": "alice", "domain": {"name": "CORP"}})
        self.assertEqual(event["process"], {"args": [{"a": {"b": 1}}]})
        conflict = dict(record, host="WS9")
        with self.assertRaisesRegex(ValueError, "line 1: field host is given twice"):
            self.run_import(self.write("conflict.ndjson", raw_line(conflict)), "conflict")
        self.assertFalse((self.root / "conflict").exists())

    def test_case_json_shape_passes_the_lab_and_has_no_answer_key(self):
        source = self.write("export.ndjson", "".join(raw_line({"_index": index, "_id": identifier, "_source": source})
                                                     for index, identifier, source in DOCS))
        summary, evidence = self.run_import(source)
        case = json.loads((evidence / "case.json").read_text(encoding="utf-8"))
        self.assertEqual(set(case), {"case_id", "schema_version", "question", "time_range_utc", "network_capture",
                                     "data_origin", "sources"})
        self.assertEqual((case["case_id"], case["schema_version"], case["network_capture"], case["data_origin"]),
                         ("work-test-001", 1, "none", "work-export"))
        self.assertEqual(case["question"], import_dedale.QUESTION)
        self.assertEqual(case["time_range_utc"], {"start_inclusive": START, "end_exclusive": END})
        self.assertEqual(case["sources"], [{"artifact": "events.jsonl", "coverage":
                                            "Real ECS records exported from the operator's work Elastic: 7 records from 2 hosts; "
                                            "datasets: system.security; no packet capture, no intel feed."}])
        self.assertEqual(case_files.case_metadata(evidence / "case.json"), case)
        self.assertEqual({path.name for path in evidence.iterdir()}, {"events.jsonl", "case.json"})
        text = ((evidence / "case.json").read_text(encoding="utf-8") + (evidence / "events.jsonl").read_text(encoding="utf-8"))
        for word in ("synthetic", "logs-a", "id-3", "_index"):
            self.assertNotIn(word, text.lower())
        for name in ("events.jsonl", "case.json"):
            info = summary["files"][name]
            data = Path(info["path"]).read_bytes()
            self.assertEqual((len(data), hashlib.sha256(data).hexdigest()), (info["bytes"], info["sha256"]))

    def test_refusals_write_nothing(self):
        good = self.write("good.ndjson", "".join(raw_line(source) for _, _, source in DOCS))
        existing = self.root / "exists"
        existing.mkdir()
        with self.assertRaisesRegex(ValueError, "already exists"):
            import_elastic.import_case(good, "work-test-001", START, END, existing)
        self.assertEqual(list(existing.iterdir()), [])
        cases = (
            ("over-cap", good, {"max_events": 6}, r"^7 records match the window, more than --max-events 6; nothing written"),
            ("empty-window", good, {"start": "2026-11-02T00:00:00Z", "end": "2026-11-02T01:00:00Z"}, "no records match"),
            ("bad-id", good, {"case_id": "Work_1"}, "case id"),
            ("bad-time", self.write("bad-time.ndjson", raw_line(doc("2026-11-01T10:00:00", "WS1", 1))), {},
             r"^line 1: unparseable timestamp"),
            ("no-time", self.write("no-time.ndjson", raw_line({"message": "x"})), {}, r"^line 1: unparseable timestamp"),
            ("bad-json", self.write("bad-json.ndjson", raw_line(DOCS[0][2]) + "{oops\n"), {}, r"^invalid JSON at line 2"),
            ("twice", self.write("twice.ndjson", raw_line({"_index": "a", "_id": "1", "_source": DOCS[0][2]}) * 2), {},
             r"^line 2: document a/1 appears twice"),
            ("no-source", self.write("no-source.json", json.dumps({"hits": {"hits": [{"_index": "a", "_id": "1"}]}})), {},
             r"hits.hits\[0\] has no _source"),
            ("bad-event", self.write("bad-event.ndjson", raw_line(dict(DOCS[0][2], event="x"))), {}, "non-object event"),
        )
        for name, source, options, message in cases:
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, message):
                self.run_import(source, name, **options)
            self.assertFalse((self.root / name).exists())
        self.assertEqual(self.run_import(good, "at-cap", max_events=7)[0]["event_count"], 7)

    def test_export_then_import_keeps_the_chain_of_hashes(self):
        export = self.root / "window.ndjson"
        meta = import_elastic.export_window(URL, "logs-*", START, END, export, transport=FakeElastic(), environ=ENV)
        summary, _ = self.run_import(export)
        self.assertEqual(summary["input"]["sha256"], meta["ndjson"]["sha256"])

    def test_cli_prints_summary_and_refuses_a_second_run(self):
        source = self.write("export.ndjson", "".join(raw_line(source) for _, _, source in DOCS))
        arguments = ["import", "--input", str(source), "--case-id", "work-test-001", "--start", START, "--end", END,
                     "--evidence-dir", str(self.root / "cli")]
        for expected in (0, 2):
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                status = import_elastic.main(arguments)
            self.assertEqual(status, expected)
            result = json.loads(stdout.getvalue())
            if expected == 0:
                self.assertEqual((result["case_id"], result["event_count"]), ("work-test-001", 7))
            else:
                self.assertIn("already exists", result["error"])
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            self.assertEqual(import_elastic.main(["import", "--input", str(source)]), 2)
        self.assertIn("required", json.loads(stdout.getvalue())["error"])


if __name__ == "__main__":
    unittest.main()

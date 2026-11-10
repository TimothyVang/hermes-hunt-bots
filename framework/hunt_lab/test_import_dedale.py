"""Behavior tests for the DEDALE real-data case importer on tiny synthetic fixtures.

Run from framework/: python -m unittest -v hunt_lab.test_import_dedale
Each test builds a miniature DEDALE tree (winlogbeat zip with bz2 hourly members,
labels zip, ground-truth CSVs) in the OS temporary directory; the real dataset is
never read.
"""

import bz2
import contextlib
import hashlib
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
import zipfile

from hunt_lab import import_dedale, scenario


SYSMON = "Microsoft-Windows-Sysmon/Operational"
PS_OPERATIONAL = "Microsoft-Windows-PowerShell/Operational"
PS_CLASSIC = "Windows PowerShell"
C1, C2, C3 = "CLIENT1.breach.local", "CLIENT2.breach.local", "CLIENT3.breach.local"
GUID_A = "{416dd0c5-a9ce-677b-3d02-000000001100}"
GUID_B = "{416dd0c5-b7b5-677b-e702-000000001100}"
HOST_ID = "25261487-cd49-4a75-81e5-fb761b1c6f2b"
SCVHOST = r"C:\Users\alice\AppData\Roaming\scvhost.exe"
POWERSHELL = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
START, END = "2025-01-06T10:30:00Z", "2025-01-06T11:30:00Z"


def evt(timestamp, host, channel, record_id, event, **objects):
    row = {"@timestamp": timestamp, "agent": {"type": "winlogbeat", "version": "7.10.2"}, "ecs": {"version": "1.5.0"},
           "host": {"name": host}, "message": "fixture record",
           "winlog": {"channel": channel, "record_id": record_id, "computer_name": host}, "event": dict(event, kind="event")}
    for key, value in objects.items():
        if key == "winlog":
            row["winlog"].update(value)
        else:
            row[key] = value
    return row


def sysmon(code, category):
    return {"code": code, "category": [category], "module": "sysmon", "provider": "Microsoft-Windows-Sysmon"}


BEFORE = evt("2025-01-06T10:20:00.000Z", C2, SYSMON, 90, sysmon(1, "process"),
             process={"entity_id": GUID_A, "pid": 2768, "name": "scvhost.exe", "executable": SCVHOST})
A_CREATE = evt("2025-01-06T10:40:00.500Z", C2, SYSMON, 100, sysmon(1, "process"),
               process={"entity_id": GUID_A, "pid": 2768, "name": "scvhost.exe", "executable": SCVHOST}, user={"name": "alice"})
C1_BENIGN = evt("2025-01-06T10:41:00Z", C1, SYSMON, 100, sysmon(1, "process"),
                process={"entity_id": "{c1-benign}", "pid": 2768, "name": "svchost.exe",
                         "executable": r"C:\Windows\System32\svchost.exe"}, user={"name": "SYSTEM"})
A_DNS = evt("2025-01-06T10:41:00.000Z", C2, SYSMON, 101, sysmon(22, "network"),
            process={"entity_id": "{416dd0c5-0000-0000-0000-00000000ffff}", "pid": 2768, "name": "scvhost.exe",
                     "executable": SCVHOST}, user={"name": "alice"}, dns={"question": {"name": "update.c2-example.test"}})
LOGON = evt("2025-01-06T10:42:00.000Z", C2, "Security", 5000,
            {"code": 4624, "category": ["authentication"], "module": "security"}, user={"name": "bob"})
CLASS_2 = evt("2025-01-06T10:44:00.000Z", C2, SYSMON, 102, sysmon(11, "file"),
              process={"entity_id": "{other}", "pid": 7777, "name": "cmd.exe"},
              file={"path": r"C:\Users\alice\AppData\Local\Temp\stage.txt"})
OTHER_HOST = evt("2025-01-06T10:45:00.000Z", C3, SYSMON, 7, sysmon(1, "process"),
                 process={"entity_id": "{c3}", "pid": 10, "name": "notepad.exe"})
B_CREATE = evt("2025-01-06T11:00:01.000Z", C2, SYSMON, 103, sysmon(1, "process"),
               process={"entity_id": GUID_B, "pid": 4100, "name": "powershell.exe", "executable": POWERSHELL},
               user={"name": "alice"})
B_SCRIPT = evt("2025-01-06T11:00:05.000Z", C2, PS_OPERATIONAL, 300,
               {"code": 4104, "category": ["process"], "module": "powershell"},
               process={"entity_id": "5b1fd2c0-0000-0000-0000-000000000000"}, winlog={"process": {"pid": 4100}})
HOST_ID_EVENT = evt("2025-01-06T11:01:00.000Z", C2, PS_CLASSIC, 400, {"code": 800, "module": "powershell"},
                    process={"entity_id": HOST_ID}, winlog={"process": {"pid": 1}})
B_MODULE = evt("2025-01-06T11:02:00.000Z", C2, PS_OPERATIONAL, 301, {"code": 4103, "module": "powershell"},
               winlog={"process": {"pid": 4100}})
AT_END = evt("2025-01-06T11:30:00.000Z", C2, SYSMON, 104, sysmon(1, "process"), process={"pid": 1})
LAST = evt("2025-01-06T11:29:59.999Z", "client1.BREACH.local", SYSMON, 101, sysmon(1, "process"), process={"pid": 2})

HOUR_10 = [OTHER_HOST, LOGON, A_DNS, BEFORE, C1_BENIGN, A_CREATE, CLASS_2]
HOUR_11 = [B_MODULE, AT_END, HOST_ID_EVENT, B_SCRIPT, LAST, B_CREATE]
CLASS_1 = [BEFORE, A_CREATE, A_DNS, A_CREATE, B_CREATE, B_SCRIPT, HOST_ID_EVENT, B_MODULE]
EXPECTED_ORDER = [A_CREATE, C1_BENIGN, A_DNS, LOGON, CLASS_2, B_CREATE, B_SCRIPT, HOST_ID_EVENT, B_MODULE, LAST]
GROUND_TRUTH = (
    "CLIENT2,%s,2768,2025-01-06T10:40:00.400Z,2025-01-06T10:50:00.000Z\n"
    "CLIENT2,%s,9999999,2025-01-06T00:00:00.000Z,2025-01-06T23:59:59.999Z\n"
    "\n"
    "CLIENT2,%s,4100,2025-01-06T11:00:00.900Z,2025-01-06T11:10:00.000Z\n"
    "CLIENT2,{416dd0c5-e47e-677c-9000-000000001200},5000,2025-01-07T12:00:00.000Z,2025-01-07T12:05:00.000Z\n"
) % (GUID_A, HOST_ID, GUID_B)


def jsonl(rows):
    return b"".join((json.dumps(row) + "\n").encode("utf-8") for row in rows)


def build_dataset(root, class_1=CLASS_1, class_2=(CLASS_2,), ground_truth=GROUND_TRUTH):
    root = Path(root)
    (root / "raw").mkdir(parents=True)
    with zipfile.ZipFile(root / "raw" / "system_logs_winlogbeat.zip", "w") as archive:
        # Corrupt neighbours: reading a member outside the window would fail the import.
        archive.writestr("daily_winlogbeat/D15_H09_2025-01-06T09_winlogbeat_F346.jsonl.bz2", b"not bzip2")
        archive.writestr("daily_winlogbeat/D15_H10_2025-01-06T10_winlogbeat_F347.jsonl.bz2", bz2.compress(jsonl(HOUR_10)))
        archive.writestr("daily_winlogbeat/D15_H11_2025-01-06T11_winlogbeat_F348.jsonl.bz2", bz2.compress(jsonl(HOUR_11)))
        archive.writestr("daily_winlogbeat/D15_H12_2025-01-06T12_winlogbeat_F349.jsonl.bz2", b"not bzip2")
        archive.writestr("winlogbeat_md5sum.sig", b"00  fixture\n")
    with zipfile.ZipFile(root / "raw" / "system_logs_labels.zip", "w") as archive:
        archive.writestr(import_dedale.LABELS_CLASS_1, jsonl(class_1))
        archive.writestr(import_dedale.LABELS_CLASS_1_AND_2, jsonl(list(class_1) + list(class_2)))
    folder = root / "labeling" / "system_log_labeling" / "ground_truth"
    folder.mkdir(parents=True)
    (folder / "gt_windows_client2_class_1.csv").write_text(ground_truth, encoding="utf-8")
    (folder / "gt_windows_client1_class_1.csv").write_text(
        "CLIENT1,{416dd0c5-999d-677e-8c04-000000001700},2768,2025-01-08T15:28:29.199Z,2025-01-08T18:06:56.200Z\n", encoding="utf-8")
    # Not a class-1 file: if read, it would make GUID_A ambiguous.
    (folder / "gt_windows_client2_class_1_and_2.csv").write_text(
        "CLIENT2,%s,2768,2025-01-06T10:40:00.400Z,2025-01-06T10:50:00.000Z\n" % GUID_A, encoding="utf-8")
    return root


class ImportCase(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="dedale-import-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.data = build_dataset(self.root / "dedale")

    def run_import(self, name="case", hosts=("CLIENT1", "CLIENT2"), data=None, **options):
        evidence, operator = self.root / (name + "-evidence"), self.root / (name + "-operator")
        summary = import_dedale.import_case(data or self.data, "dedale-test-001", START, END, evidence, operator,
                                            list(hosts) if hosts is not None else None, **options)
        return summary, evidence, operator

    def load(self, evidence, operator):
        events = [json.loads(line) for line in (evidence / "events.jsonl").read_text(encoding="utf-8").splitlines()]
        truth = json.loads((operator / "truth.json").read_text(encoding="utf-8"))
        case = json.loads((evidence / "case.json").read_text(encoding="utf-8"))
        return events, truth, case

    def invoke(self, arguments):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            status = import_dedale.main(arguments)
        return status, json.loads(output.getvalue())

    def test_window_host_filter_order_ids_and_dataset(self):
        summary, evidence, operator = self.run_import()
        events, _, _ = self.load(evidence, operator)
        self.assertEqual([event["event"]["id"] for event in events], ["evt-%06d" % n for n in range(1, 11)])
        self.assertEqual({event["event"]["dataset"] for event in events}, {"dedale-test-001"})
        for event, original in zip(events, EXPECTED_ORDER):
            stripped = json.loads(json.dumps(event))
            del stripped["event"]["id"], stripped["event"]["dataset"]
            self.assertEqual(stripped, original)
        self.assertEqual(summary["event_count"], 10)
        self.assertEqual(summary["winlogbeat_members_read"], 2)
        self.assertEqual(summary["host_records_outside_member_hour"], 0)
        self.assertEqual(summary["hosts"], ["CLIENT1", "CLIENT2", "client1"])

        _, evidence, operator = self.run_import("all-hosts", hosts=None)
        events, _, _ = self.load(evidence, operator)
        self.assertEqual(len(events), 11)
        self.assertEqual(events[5]["host"]["name"], C3)

    def test_events_file_is_canonical_json_with_lf(self):
        _, evidence, _ = self.run_import()
        data = (evidence / "events.jsonl").read_bytes()
        self.assertNotIn(b"\r", data)
        self.assertTrue(data.endswith(b"\n"))
        for line in data.decode("utf-8").splitlines():
            self.assertEqual(line, json.dumps(json.loads(line), sort_keys=True, separators=(",", ":"), ensure_ascii=False))

    def test_two_runs_are_byte_identical(self):
        first, evidence_1, operator_1 = self.run_import("first")
        second, evidence_2, operator_2 = self.run_import("second")
        for name in ("events.jsonl", "case.json"):
            self.assertEqual((evidence_1 / name).read_bytes(), (evidence_2 / name).read_bytes(), name)
        self.assertEqual((operator_1 / "truth.json").read_bytes(), (operator_2 / "truth.json").read_bytes())
        self.assertEqual({name: info["sha256"] for name, info in first["files"].items()},
                         {name: info["sha256"] for name, info in second["files"].items()})

    def test_every_in_window_label_maps_to_one_event_in_one_group(self):
        summary, evidence, operator = self.run_import()
        events, truth, _ = self.load(evidence, operator)
        by_key = {(e["host"]["name"], e["winlog"]["channel"], e["winlog"]["record_id"]): e["event"]["id"] for e in events}
        labelled = {by_key[(r["host"]["name"], r["winlog"]["channel"], r["winlog"]["record_id"])]
                    for r in CLASS_1 if r is not BEFORE}
        grouped = [eid for fact in truth["facts"] for group in fact["evidence_event_groups"] for eid in group]
        self.assertEqual(sorted(grouped), sorted(labelled))
        self.assertEqual(len(grouped), len(set(grouped)))
        self.assertEqual((summary["class_1_labelled"], summary["class_2_labelled"]), (6, 1))

    def test_unmatched_label_fails(self):
        missing = evt("2025-01-06T10:50:00.000Z", C2, SYSMON, 999, sysmon(1, "process"), process={"entity_id": GUID_A})
        data = build_dataset(self.root / "unmatched", class_1=CLASS_1 + [missing])
        with self.assertRaisesRegex(ValueError, r"^1 in-window class-1 labels match no imported event"):
            self.run_import(data=data)
        self.assertFalse((self.root / "case-evidence").exists() or (self.root / "case-operator").exists())

    def test_label_without_ground_truth_process_fails(self):
        data = build_dataset(self.root / "orphan", class_1=CLASS_1 + [LOGON])
        with self.assertRaisesRegex(ValueError, r"^1 class-1 labelled events match no ground-truth process"):
            self.run_import(data=data)
        duplicate = GROUND_TRUTH + "CLIENT2,%s,4100,2025-01-06T10:59:00.000Z,2025-01-06T11:20:00.000Z\n" % GUID_B
        data = build_dataset(self.root / "ambiguous", ground_truth=duplicate)
        with self.assertRaisesRegex(ValueError, r"match more than one ground-truth process"):
            self.run_import(data=data)

    def test_facts_group_by_category_or_code_with_entities(self):
        _, evidence, operator = self.run_import()
        _, truth, _ = self.load(evidence, operator)
        scenario.validate_truth(truth)
        self.assertEqual(truth["schema_version"], 1)
        self.assertEqual(truth["case_id"], "dedale-test-001")
        self.assertEqual(truth["interpretation_boundary"], import_dedale.INTERPRETATION_BOUNDARY)
        facts = {fact["fact_id"]: fact for fact in truth["facts"]}
        self.assertEqual([fact["fact_id"] for fact in truth["facts"]],
                         ["attack.client2.scvhost.2768", "attack.client2.powershell.4100", "attack.client2.process.9999999"])
        self.assertEqual({fact["kind"] for fact in truth["facts"]}, {"attack"})
        scv, ps, host_id = (facts[name] for name in facts)
        self.assertEqual(scv["evidence_event_groups"], [["evt-000001"], ["evt-000003"]])
        self.assertEqual(scv["entities"], {"hosts": ["CLIENT2"], "users": ["alice"], "processes": ["scvhost.exe"],
                                           "domains": ["update.c2-example.test"], "ips": []})
        # B_SCRIPT and B_MODULE carry no process.pid; only the winlog.process.pid rule assigns them.
        self.assertEqual(ps["evidence_event_groups"], [["evt-000006", "evt-000007"], ["evt-000009"]])
        self.assertEqual(ps["entities"], {"hosts": ["CLIENT2"], "users": ["alice"], "processes": ["powershell.exe"],
                                          "domains": [], "ips": []})
        self.assertEqual(host_id["evidence_event_groups"], [["evt-000008"]])
        self.assertEqual(host_id["entities"], {"hosts": ["CLIENT2"], "users": [], "processes": [], "domains": [], "ips": []})
        self.assertIn(SCVHOST, scv["observation"])
        self.assertIn("2025-01-06T10:40:00.500Z to 2025-01-06T10:41:00.000Z", scv["observation"])
        self.assertNotIn("\n", scv["observation"])

    def test_class_2_only_events_are_listed_not_facts(self):
        _, evidence, operator = self.run_import()
        _, truth, _ = self.load(evidence, operator)
        self.assertEqual(truth["labels_class_2_event_ids"], ["evt-000005"])
        grouped = {eid for fact in truth["facts"] for group in fact["evidence_event_groups"] for eid in group}
        self.assertNotIn("evt-000005", grouped)

    def test_perfect_report_finds_every_fact(self):
        _, evidence, operator = self.run_import()
        _, truth, _ = self.load(evidence, operator)
        report = {"claims": [{"statement": "Activity on %s." % fact["entities"]["hosts"][0],
                              "evidence_ids": [group[0] for group in fact["evidence_event_groups"]]}
                             for fact in truth["facts"]]}
        result = scenario.score_report(truth, report)
        self.assertEqual((result["found"], result["total"]), (3, 3))

    def test_case_json_shape_and_no_answer_key_in_evidence(self):
        _, evidence, operator = self.run_import()
        _, truth, case = self.load(evidence, operator)
        metadata = scenario.Scenario.case_metadata(SimpleNamespace(
            hosts=[], case_id="x", start=0, end=0, env={"org": "X"},
            EVENTS_COVERAGE=scenario.Scenario.EVENTS_COVERAGE, PCAP_COVERAGE=scenario.Scenario.PCAP_COVERAGE), 0, 0, 0, 0)
        self.assertEqual(case["question"], metadata["question"])
        self.assertEqual(set(case), {"case_id", "schema_version", "question", "time_range_utc", "network_capture", "sources"})
        self.assertEqual(case["case_id"], "dedale-test-001")
        self.assertEqual(case["network_capture"], "none")
        self.assertEqual(case["time_range_utc"], {"start_inclusive": START, "end_exclusive": END})
        self.assertEqual(len(case["sources"]), 1)
        self.assertEqual(case["sources"][0]["artifact"], "events.jsonl")
        coverage = case["sources"][0]["coverage"]
        for text in ("winlogbeat 7.10.2", "from 2 hosts", "; 10 records;", "no packet capture, no intel feed", SYSMON):
            self.assertIn(text, coverage)
        self.assertEqual(truth["source"], import_dedale.SOURCE)
        evidence_text = ((evidence / "case.json").read_text(encoding="utf-8")
                         + (evidence / "events.jsonl").read_text(encoding="utf-8")).lower()
        forbidden = ["malicious", "label", "attack.", "ground-truth", "ground truth", "class_1", "class 1",
                     "inria", "dedale dataset", truth["interpretation_boundary"].lower()]
        for fact in truth["facts"]:
            forbidden += [fact["fact_id"].lower(), fact["observation"].lower()]
        for text in forbidden:
            self.assertNotIn(text, evidence_text)
        self.assertEqual({path.name for path in evidence.iterdir()}, {"events.jsonl", "case.json"})
        self.assertEqual({path.name for path in operator.iterdir()}, {"truth.json"})

    def test_existing_output_directories_are_refused(self):
        for which in ("evidence", "operator"):
            with self.subTest(which=which):
                existing = self.root / ("exists-" + which)
                existing.mkdir()
                evidence = existing if which == "evidence" else self.root / "fresh-evidence"
                operator = existing if which == "operator" else self.root / "fresh-operator"
                with self.assertRaisesRegex(ValueError, "already exists"):
                    import_dedale.import_case(self.data, "dedale-test-001", START, END, evidence, operator)
                self.assertEqual(list(existing.iterdir()), [])
                self.assertFalse((self.root / "fresh-evidence").exists() or (self.root / "fresh-operator").exists())
        with self.assertRaises(ValueError):
            import_dedale.import_case(self.data, "dedale-test-001", START, END, self.root / "a", self.root / "a" / "b")

    def test_over_limit_window_is_refused_before_writing(self):
        with self.assertRaisesRegex(ValueError, r"^10 records match the window and hosts, more than --max-events 9"):
            self.run_import(max_events=9)
        self.assertFalse((self.root / "case-evidence").exists() or (self.root / "case-operator").exists())
        summary, _, _ = self.run_import("at-limit", max_events=10)
        self.assertEqual(summary["event_count"], 10)

    def test_cli_prints_summary_with_file_hashes(self):
        evidence, operator = self.root / "cli-evidence", self.root / "cli-operator"
        arguments = ["--data-dir", str(self.data), "--case-id", "dedale-test-001", "--start", START, "--end", END,
                     "--hosts", "CLIENT1,CLIENT2", "--evidence-dir", str(evidence), "--truth-dir", str(operator)]
        status, summary = self.invoke(arguments)
        self.assertEqual(status, 0)
        self.assertEqual((summary["case_id"], summary["event_count"], summary["facts"]), ("dedale-test-001", 10, 3))
        self.assertEqual((summary["class_1_labelled"], summary["class_2_labelled"]), (6, 1))
        for name in ("events.jsonl", "truth.json", "case.json"):
            info = summary["files"][name]
            data = Path(info["path"]).read_bytes()
            self.assertEqual((len(data), hashlib.sha256(data).hexdigest()), (info["bytes"], info["sha256"]))
        status, result = self.invoke(arguments)
        self.assertEqual(status, 2)
        self.assertIn("already exists", result["error"])
        status, result = self.invoke(arguments[:-4] + ["--evidence-dir", str(self.root / "x"), "--truth-dir",
                                                       str(self.root / "y"), "--max-events", "3"])
        self.assertEqual(status, 2)
        self.assertIn("10 records match", result["error"])

    def test_timestamps_compare_by_instant_not_text(self):
        self.assertEqual(import_dedale.parse_time("2025-01-06T10:41:00Z"), import_dedale.parse_time("2025-01-06T10:41:00.000Z"))
        self.assertEqual(import_dedale.parse_time("2025-01-06T11:41:00+01:00"), import_dedale.parse_time("2025-01-06T10:41:00Z"))
        self.assertEqual(import_dedale.format_time(import_dedale.parse_time("2025-01-06T10:40:00.500Z")), "2025-01-06T10:40:00.5Z")
        with self.assertRaises(ValueError):
            import_dedale.parse_time("2025-01-06T10:41:00")


if __name__ == "__main__":
    unittest.main()

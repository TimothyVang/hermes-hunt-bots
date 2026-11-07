"""Behavior tests for invented case generation and exact-observable scoring.

Run from framework/: python -m unittest -v test_hunt_lab_case
All generated artifacts use the OS temporary directory, never the workspace.
"""

import contextlib
import copy
import io
import ipaddress
import json
from pathlib import Path
import struct
import tempfile
import unittest


from hunt_lab import case


def perfect_findings():
    """Concrete analyst-normalized answer with explicit stable event citations."""
    return {
        "schema_version": 1,
        "case_id": "dns-lab-001",
        "findings": [
            {"fact_id": "workstation-01.dns.period-60s",
             "event_ids": ["evt-0006", "evt-0010", "evt-0014", "evt-0018",
                           "evt-0022", "evt-0026", "evt-0030", "evt-0034"]},
            {"fact_id": "workstation-01.process-dns-link",
             "event_ids": ["evt-0004", "evt-0006"]},
            {"fact_id": "workstation-02.dns.period-60s",
             "event_ids": ["evt-0008", "evt-0012", "evt-0016", "evt-0020",
                           "evt-0024", "evt-0028", "evt-0032", "evt-0036"]},
            {"fact_id": "workstation-02.schedule-correlation",
             "event_ids": ["evt-0003", "evt-0005", "evt-0008", "evt-0012"]},
            {"fact_id": "coverage.process-context-missing", "event_ids": ["evt-0038"]},
            {"fact_id": "coverage.logon-history-limited", "event_ids": ["evt-0039"]},
            {"fact_id": "coverage.dns-only", "event_ids": ["evt-0040"]},
        ],
    }


class CaseTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="synthetic-log-case-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.evidence = self.root / "evidence"
        self.operator = self.root / "operator"

    def generate(self):
        return case.generate(self.evidence, self.operator)

    def invoke(self, arguments):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            status = case.main(arguments)
        return status, json.loads(output.getvalue())

    def test_generation_is_deterministic_and_key_is_separate(self):
        result = self.generate()
        other_evidence = self.root / "other-evidence"
        other_operator = self.root / "other-operator"
        case.generate(other_evidence, other_operator)
        self.assertEqual(result["event_count"], 40)
        self.assertEqual(result["packet_count"], 32)
        self.assertEqual({path.name for path in self.evidence.iterdir()},
                         {"events.jsonl", "traffic.pcap", "case.json"})
        self.assertEqual({path.name for path in self.operator.iterdir()}, {"truth.json"})
        for name in ("events.jsonl", "traffic.pcap", "case.json"):
            self.assertEqual((self.evidence / name).read_bytes(),
                             (other_evidence / name).read_bytes())
        self.assertEqual((self.operator / "truth.json").read_bytes(),
                         (other_operator / "truth.json").read_bytes())
        metadata = case.load_json(self.evidence / "case.json")
        self.assertEqual(set(metadata), {"schema_version", "case_id", "time_range_utc", "sources", "question"})
        events = [json.loads(line) for line in (self.evidence / "events.jsonl").read_text().splitlines()]
        self.assertEqual([row["event"]["id"] for row in events],
                         ["evt-%04d" % number for number in range(1, 41)])
        self.assertEqual({row["event"]["dataset"] for row in events}, {"dns-lab-001"})
        self.assertTrue(all(row["@timestamp"].endswith("Z") for row in events))
        self.assertEqual(sum(row["event"]["provider"] == "lab.coverage" for row in events), 3)
        self.assertEqual(len(case.load_json(self.operator / "truth.json")["facts"]), 7)

    def test_same_or_nested_key_directories_are_refused_without_writes(self):
        for evidence, operator in ((self.evidence, self.evidence),
                                   (self.evidence, self.evidence / "hidden"),
                                   (self.operator / "evidence", self.operator)):
            with self.subTest(evidence=evidence, operator=operator):
                with self.assertRaises(ValueError):
                    case.generate(evidence, operator)
        self.assertFalse(self.evidence.exists())
        self.assertFalse(self.operator.exists())

    def test_existing_artifacts_are_never_overwritten(self):
        for directory, name in (("evidence", "events.jsonl"), ("evidence", "traffic.pcap"),
                                ("evidence", "case.json"), ("operator", "truth.json")):
            with self.subTest(name=name):
                base = self.root / name
                evidence = base / "evidence"
                operator = base / "operator"
                target = (evidence if directory == "evidence" else operator) / name
                target.parent.mkdir(parents=True)
                target.write_bytes(b"preserve-existing-artifact")
                with self.assertRaises(ValueError):
                    case.generate(evidence, operator)
                self.assertEqual(target.read_bytes(), b"preserve-existing-artifact")
                self.assertEqual(list(base.rglob("*.*")), [target])

    def test_pcap_matches_dns_events_and_has_valid_transport_checksums(self):
        self.generate()
        events = [json.loads(line) for line in (self.evidence / "events.jsonl").read_text().splitlines()]
        queries = [row for row in events if "dns" in row]
        data = (self.evidence / "traffic.pcap").read_bytes()
        self.assertEqual(struct.unpack("<IHHIIII", data[:24]),
                         (0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        offset = 24
        observed = []
        while offset < len(data):
            seconds, microseconds, captured, original = struct.unpack("<IIII", data[offset:offset + 16])
            offset += 16
            frame = data[offset:offset + captured]
            offset += captured
            self.assertEqual(captured, original)
            self.assertEqual(len(frame), captured)
            self.assertEqual(frame[12:14], b"\x08\x00")
            ip = frame[14:34]
            self.assertEqual(ip[0], 0x45)
            self.assertEqual(ip[9], 17)
            self.assertEqual(case.checksum(ip), 0)
            ip_length = struct.unpack("!H", ip[2:4])[0]
            udp = frame[34:14 + ip_length]
            source_port, destination_port, udp_length, _ = struct.unpack("!HHHH", udp[:8])
            self.assertEqual(udp_length, len(udp))
            pseudo = ip[12:20] + struct.pack("!BBH", 0, 17, len(udp))
            self.assertEqual(case.checksum(pseudo + udp), 0)
            transaction, flags, questions, answers, authority, additional = struct.unpack("!HHHHHH", udp[8:20])
            self.assertEqual((questions, authority, additional), (1, 0, 0))
            labels = []
            position = 20
            while udp[position]:
                length = udp[position]
                labels.append(udp[position + 1:position + 1 + length].decode("ascii"))
                position += 1 + length
            domain = ".".join(labels)
            self.assertTrue(domain.endswith(".test"))
            source_ip = str(ipaddress.IPv4Address(ip[12:16]))
            destination_ip = str(ipaddress.IPv4Address(ip[16:20]))
            self.assertTrue(ipaddress.ip_address(source_ip) in ipaddress.ip_network("192.0.2.0/24"))
            self.assertTrue(ipaddress.ip_address(destination_ip) in ipaddress.ip_network("192.0.2.0/24"))
            if flags == 0x0100:
                self.assertEqual((destination_port, answers, microseconds), (53, 0, 0))
                observed.append((seconds, source_ip, source_port, domain, transaction))
            else:
                self.assertEqual((flags, source_port, answers, microseconds), (0x8180, 53, 1, 1000))
                query = observed[-1]
                self.assertEqual((seconds, destination_ip, destination_port, domain, transaction), query)
                self.assertTrue(ipaddress.IPv4Address(udp[-4:]) in ipaddress.ip_network("198.51.100.0/24"))
        self.assertEqual(offset, len(data))
        self.assertEqual(len(observed), 16)
        expected = [(int(case.datetime.fromisoformat(row["@timestamp"].replace("Z", "+00:00")).timestamp()),
                     row["source"]["ip"], row["source"]["port"], row["dns"]["question"]["name"])
                    for row in queries]
        self.assertEqual([item[:4] for item in observed], expected)

    def test_concrete_perfect_cli_answer_scores_all_observations(self):
        status, result = self.invoke(["generate", "--evidence-dir", str(self.evidence),
                                      "--truth-dir", str(self.operator)])
        self.assertEqual(status, 0)
        self.assertEqual((result["event_count"], result["packet_count"]), (40, 32))
        findings_path = self.root / "findings.json"
        findings_path.write_text(json.dumps(perfect_findings()), encoding="utf-8")
        status, result = self.invoke(["score", "--truth", str(self.operator / "truth.json"),
                                      "--findings", str(findings_path)])
        self.assertEqual(status, 0)
        self.assertEqual((result["correct_findings"], result["false_findings"],
                          result["invalid_citations"], result["precision"], result["recall"]),
                         (7, 0, 0, 1.0, 1.0))

    def test_unknown_irrelevant_and_missing_citations_reduce_score(self):
        self.generate()
        truth = case.load_json(self.operator / "truth.json")
        for citation in ("evt-9999", "evt-0002"):
            with self.subTest(citation=citation):
                findings = perfect_findings()
                findings["findings"][0]["event_ids"].append(citation)
                result = case.score(truth, findings)
                self.assertEqual((result["correct_findings"], result["false_findings"],
                                  result["invalid_citations"]), (6, 1, 1))
                self.assertLess(result["precision"], 1)
                self.assertLess(result["recall"], 1)
        findings = perfect_findings()
        findings["findings"][0]["event_ids"].pop()
        result = case.score(truth, findings)
        self.assertEqual((result["correct_findings"], result["invalid_citations"]), (6, 0))
        findings = perfect_findings()
        findings["findings"].append({"fact_id": "compromise-confirmed", "event_ids": ["evt-0004"]})
        result = case.score(truth, findings)
        self.assertEqual((result["correct_findings"], result["false_findings"]), (7, 1))
        self.assertLess(result["precision"], 1)

    def test_empty_duplicate_and_malformed_findings_are_rejected(self):
        self.generate()
        truth = case.load_json(self.operator / "truth.json")
        invalid = []
        value = perfect_findings()
        value["findings"] = []
        invalid.append(value)
        value = perfect_findings()
        value["findings"].append(copy.deepcopy(value["findings"][0]))
        invalid.append(value)
        value = perfect_findings()
        value["findings"][0]["event_ids"] *= 2
        invalid.append(value)
        value = perfect_findings()
        value["findings"][0]["event_ids"] = []
        invalid.append(value)
        value = perfect_findings()
        value["findings"][0]["event_ids"] = "evt-0006"
        invalid.append(value)
        value = perfect_findings()
        value["case_id"] = "different-case"
        invalid.append(value)
        value = perfect_findings()
        value["schema_version"] = True
        invalid.append(value)
        value = perfect_findings()
        value["findings"][0]["explanation"] = "Unrecognized field"
        invalid.append(value)
        for number, findings in enumerate(invalid):
            with self.subTest(number=number), self.assertRaises(ValueError):
                case.score(truth, findings)
        empty_truth = copy.deepcopy(truth)
        empty_truth["facts"] = []
        with self.assertRaises(ValueError):
            case.score(empty_truth, perfect_findings())
        bad_truth = copy.deepcopy(truth)
        bad_truth["facts"][0]["evidence_id_groups"] = [["evt-9999"]]
        with self.assertRaises(ValueError):
            case.score(bad_truth, perfect_findings())

    def test_cli_rejects_duplicate_json_keys_and_reports_json_errors(self):
        self.generate()
        path = self.root / "malformed.json"
        for content in ('{"findings": [], "findings": []}', '{"value": NaN}', '{broken'):
            with self.subTest(content=content):
                path.write_text(content, encoding="utf-8")
                status, result = self.invoke(["score", "--truth", str(self.operator / "truth.json"),
                                              "--findings", str(path)])
                self.assertEqual(status, 2)
                self.assertEqual(set(result), {"error"})
        status, result = self.invoke(["generate", "--evidence-dir", str(self.evidence)])
        self.assertEqual(status, 2)
        self.assertIn("error", result)


if __name__ == "__main__":
    unittest.main()

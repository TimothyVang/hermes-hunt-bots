#!/usr/bin/env python3
"""Invented DNS workflow fixture; standard library only, never contacts a service.

CLI:
  python case.py generate --evidence-dir PATH --truth-dir PATH
  python case.py score --truth PATH/truth.json --findings PATH/findings.json

Generation writes events.jsonl (40 ECS-style records), traffic.pcap (32 DNS
Ethernet/IPv4/UDP packets), case.json, and a separately held truth.json. Paths
must be disjoint and all artifact files must be new. No runtime data is read.

Findings JSON (exact keys; at least one unique finding; citations are nonempty):
  {"schema_version": 1, "case_id": "dns-lab-001", "findings": [
    {"fact_id": "operator-normalized-observable-id", "event_ids": ["evt-0001"]}
  ]}
An operator maps an analyst's observations to the hidden key's exact fact IDs;
never distribute that key to the analyst. This is a workflow plumbing smoke,
not an autonomous natural-language evaluator or model-quality benchmark.

Truth JSON has schema_version, case_id, event_ids, facts, interpretation_boundary.
Each fact has fact_id, observation, evidence_id_groups. Each evidence group must
have at least one cited member (AND of OR groups). A finding is correct only if
its exact fact ID exists, every group is covered, and every citation is both a
known event and relevant to that fact. Unknown facts and unsupported findings
are false findings; unknown or irrelevant citations count as invalid citations.
Precision = correct/submitted; recall = correct/expected. Empty inputs, duplicate
findings/citations/JSON keys and malformed schemas fail instead of scoring.
Generate/score results and errors are JSON; errors have exit status 2. Scores
have exit status 0 even when incorrect. Scores measure observations, never intent.
"""

import argparse
from datetime import datetime, timedelta, timezone
import ipaddress
import json
from pathlib import Path
import struct
import sys


CASE_ID = "dns-lab-001"
START = datetime(2025, 4, 15, 9, 0, tzinfo=timezone.utc)
HOSTS = ("workstation-01", "workstation-02")
ADDRESSES = ("192.0.2.11", "192.0.2.12")
DOMAINS = ("status-gateway.test", "updates.vendor.test")
RESOLVER = "192.0.2.53"


def timestamp(seconds):
    return (START + timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")


def fixture():
    """Build wholly invented records and packet specifications in memory."""
    rows = []
    packets = []
    references = {}

    def add(key, seconds, host_index, dataset, category, event_type, fields):
        row = {
            "@timestamp": timestamp(seconds),
            "ecs": {"version": "8.11.0"},
            "event": {"kind": "event", "dataset": dataset,
                      "category": [category], "type": [event_type]},
        }
        if host_index is not None:
            row["host"] = {"name": HOSTS[host_index],
                           "ip": [ADDRESSES[host_index]],
                           "os": {"type": "windows", "name": "Windows (synthetic)"}}
        row.update(fields)
        rows.append((seconds, key, row))

    for index in range(2):
        add("logon-" + str(index), index * 5, index, "lab.windows.security",
            "authentication", "start", {
                "event": {"kind": "event", "dataset": "lab.windows.security",
                          "category": ["authentication"], "type": ["start"],
                          "code": "4624", "outcome": "success"},
                "winlog": {"channel": "Security"},
                "message": "Invented local interactive logon summary; no identity or authentication payload supplied.",
            })
        add("process-" + str(index), 20 + index * 10, index,
            "lab.windows.sysmon", "process", "start", {
                "event": {"kind": "event", "dataset": "lab.windows.sysmon",
                          "category": ["process"], "type": ["start"], "code": "1"},
                "winlog": {"channel": "Microsoft-Windows-Sysmon/Operational"},
                "process": {"pid": 4100 + index,
                            "entity_id": "process-" + str(index + 1),
                            "name": ("powershell.exe", "MaintenanceClient.exe")[index]},
            })
    add("schedule", 15, 1, "lab.windows.tasks", "configuration", "info", {
        "winlog": {"channel": "Microsoft-Windows-TaskScheduler/Operational"},
        "message": "InventoryRefresh task trigger recorded; configured interval 60 seconds, program MaintenanceClient.exe, DNS name updates.vendor.test.",
        "labels": {"task_name": "InventoryRefresh", "interval_seconds": "60"},
    })

    for index in range(2):
        for sequence in range(8):
            seconds = 60 + sequence * 60 + index * 15
            port = 53000 + index * 100 + sequence
            common = {
                "process": {"pid": 4100 + index,
                            "entity_id": "process-" + str(index + 1),
                            "name": ("powershell.exe", "MaintenanceClient.exe")[index]},
                "source": {"ip": ADDRESSES[index], "port": port},
                "destination": {"ip": RESOLVER, "port": 53},
                "network": {"transport": "udp", "protocol": "dns", "type": "ipv4"},
            }
            add("dns-%d-%d" % (index, sequence), seconds, index,
                "lab.windows.sysmon", "network", "protocol", {
                    **common,
                    "event": {"kind": "event", "dataset": "lab.windows.sysmon",
                              "category": ["network"], "type": ["protocol"], "code": "22"},
                    "dns": {"type": "query", "question": {"name": DOMAINS[index], "type": "A"},
                            "answers": [{"name": DOMAINS[index], "type": "A",
                                         "data": "198.51.100." + str(80 + index)}]},
                })
            add("network-%d-%d" % (index, sequence), seconds, index,
                "lab.windows.sysmon", "network", "connection", {
                    **common,
                    "event": {"kind": "event", "dataset": "lab.windows.sysmon",
                              "category": ["network"], "type": ["connection"], "code": "3"},
                })
            packets.append((seconds, index, sequence, port))

    gaps = (
        "Process command lines, parent processes, script content and file telemetry are not supplied for either host; process names do not establish executed content.",
        "Security coverage contains only two local logon summaries; prior logon history and later activity are not supplied.",
        "The supplied capture covers DNS exchanges only, not other application traffic; the endpoint events are selected records, not continuous collection.",
    )
    for index, message in enumerate(gaps):
        add("gap-" + str(index), 540 + index, None, "lab.coverage",
            "configuration", "info", {"message": message})
    rows.sort(key=lambda item: (item[0], item[1]))
    events = []
    for number, (_, key, row) in enumerate(rows, 1):
        event_id = "evt-%04d" % number
        row["event"]["provider"] = row["event"]["dataset"]
        row["event"]["dataset"] = CASE_ID
        row["event"]["id"] = event_id
        references[key] = event_id
        events.append(row)

    def groups(*keys):
        return [[references[key]] for key in keys]

    facts = [
        {"fact_id": "workstation-01.dns.period-60s",
         "observation": "Eight A queries for status-gateway.test from workstation-01 occur at 60-second intervals, 09:01:00 through 09:08:00 UTC.",
         "evidence_id_groups": groups(*["dns-0-%d" % n for n in range(8)])},
        {"fact_id": "workstation-01.process-dns-link",
         "observation": "The DNS records attribute the queries to the same process entity as the recorded powershell.exe start; this does not establish script content or intent.",
         "evidence_id_groups": groups("process-0", "dns-0-0")},
        {"fact_id": "workstation-02.dns.period-60s",
         "observation": "Eight A queries for updates.vendor.test from workstation-02 occur at 60-second intervals, 09:01:15 through 09:08:15 UTC.",
         "evidence_id_groups": groups(*["dns-1-%d" % n for n in range(8)])},
        {"fact_id": "workstation-02.schedule-correlation",
         "observation": "A recorded InventoryRefresh task specifies a 60-second interval, MaintenanceClient.exe and updates.vendor.test, matching the comparison host's process and DNS records; correlation alone does not prove causation.",
         "evidence_id_groups": groups("schedule", "process-1", "dns-1-0", "dns-1-1")},
        {"fact_id": "coverage.process-context-missing",
         "observation": gaps[0], "evidence_id_groups": groups("gap-0")},
        {"fact_id": "coverage.logon-history-limited",
         "observation": gaps[1], "evidence_id_groups": groups("gap-1")},
        {"fact_id": "coverage.dns-only",
         "observation": gaps[2], "evidence_id_groups": groups("gap-2")},
    ]
    truth = {
        "schema_version": 1, "case_id": CASE_ID,
        "event_ids": [row["event"]["id"] for row in events], "facts": facts,
        "interpretation_boundary": "Periodicity and process names are observations, not proof of compromise, command-and-control, exfiltration or intent. Scheduled software is a plausible alternative. This key scores observable facts only.",
    }
    metadata = {
        "schema_version": 1, "case_id": CASE_ID,
        "time_range_utc": {"start_inclusive": timestamp(0), "end_exclusive": timestamp(600)},
        "sources": [
            {"artifact": "events.jsonl", "coverage": "Selected invented Windows process, local logon, DNS, network, task and coverage records; 40 records."},
            {"artifact": "traffic.pcap", "coverage": "Invented DNS query/response pairs matching the endpoint DNS records; Ethernet/IPv4/UDP only; 32 packets."},
        ],
        "question": "What activity is observed, how does it compare across the two hosts, what alternative explanations remain, and which coverage gaps limit conclusions? Cite event.id values and separate observations from intent; do not assume compromise.",
    }
    return events, packets, metadata, truth


def checksum(data):
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535


def dns_frame(index, sequence, port, response):
    """Encode only an invented DNS A question/answer and transport framing."""
    name = b"".join(bytes([len(part)]) + part.encode("ascii")
                    for part in DOMAINS[index].split(".")) + b"\x00"
    question = name + struct.pack("!HH", 1, 1)
    dns = struct.pack("!HHHHHH", 1000 + index * 100 + sequence,
                      0x8180 if response else 0x0100, 1, int(response), 0, 0) + question
    if response:
        dns += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4)
        dns += ipaddress.IPv4Address("198.51.100." + str(80 + index)).packed
    client = ipaddress.IPv4Address(ADDRESSES[index]).packed
    resolver = ipaddress.IPv4Address(RESOLVER).packed
    source, destination = (resolver, client) if response else (client, resolver)
    udp = struct.pack("!HHHH", 53 if response else port,
                      port if response else 53, 8 + len(dns), 0)
    pseudo = source + destination + struct.pack("!BBH", 0, 17, len(udp) + len(dns))
    udp_sum = checksum(pseudo + udp + dns) or 65535
    udp = udp[:6] + struct.pack("!H", udp_sum) + dns
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp),
                     2000 + index * 100 + sequence * 2 + int(response),
                     0, 64, 17, 0, source, destination)
    ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
    client_mac = bytes.fromhex("0200000000") + bytes([index + 1])
    resolver_mac = bytes.fromhex("020000000035")
    ethernet = (client_mac + resolver_mac) if response else (resolver_mac + client_mac)
    frame = ethernet + b"\x08\x00" + ip + udp
    return frame + b"\x00" * max(0, 60 - len(frame))


def pcap_bytes(specifications):
    capture = bytearray(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    epoch = int(START.timestamp())
    for seconds, index, sequence, port in sorted(specifications):
        for response in (False, True):
            frame = dns_frame(index, sequence, port, response)
            capture.extend(struct.pack("<IIII", epoch + seconds,
                                       1000 if response else 0, len(frame), len(frame)))
            capture.extend(frame)
    return bytes(capture)


def json_bytes(value):
    return (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n").encode("utf-8")


def generate(evidence_dir, truth_dir):
    evidence = Path(evidence_dir).resolve()
    operator = Path(truth_dir).resolve()
    if evidence == operator or evidence in operator.parents or operator in evidence.parents:
        raise ValueError("evidence and truth directories must be separate, non-nested paths")
    events, packets, metadata, truth = fixture()
    artifacts = {
        evidence / "events.jsonl": b"".join((json.dumps(event, sort_keys=True) + "\n").encode("utf-8") for event in events),
        evidence / "traffic.pcap": pcap_bytes(packets),
        evidence / "case.json": json_bytes(metadata),
        operator / "truth.json": json_bytes(truth),
    }
    for path in artifacts:
        if path.exists() or path.is_symlink():
            raise ValueError("refusing to overwrite artifact: " + str(path))
    evidence.mkdir(parents=True, exist_ok=True)
    operator.mkdir(parents=True, exist_ok=True)
    for path, data in artifacts.items():
        with path.open("xb") as handle:
            handle.write(data)
    return {"schema_version": 1, "case_id": CASE_ID, "event_count": len(events),
            "packet_count": len(packets) * 2,
            "evidence_artifacts": [str(evidence / name) for name in ("events.jsonl", "traffic.pcap", "case.json")],
            "truth_artifact": str(operator / "truth.json")}


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key: " + key)
        result[key] = value
    return result


def load_json(path):
    def invalid_constant(value):
        raise ValueError("non-finite JSON number: " + value)
    with Path(path).open("r", encoding="utf-8") as handle:
        return json.load(handle, object_pairs_hook=unique_object, parse_constant=invalid_constant)


def require_keys(value, keys, description):
    if not isinstance(value, dict) or set(value) != set(keys):
        raise ValueError(description + " must have exactly these keys: " + ", ".join(sorted(keys)))


def require_text(value, description):
    if not isinstance(value, str) or not value or value.strip() != value:
        raise ValueError(description + " must be a nonempty string without surrounding whitespace")


def string_list(value, description):
    if not isinstance(value, list) or not value:
        raise ValueError(description + " must be a nonempty list")
    for item in value:
        require_text(item, description + " item")
    if len(set(value)) != len(value):
        raise ValueError(description + " contains duplicates")
    return set(value)


def validate_envelope(value, keys, description):
    require_keys(value, keys, description)
    if type(value["schema_version"]) is not int or value["schema_version"] != 1:
        raise ValueError(description + " schema_version must be integer 1")
    require_text(value["case_id"], description + " case_id")


def score(truth, findings):
    validate_envelope(truth, ("schema_version", "case_id", "event_ids", "facts", "interpretation_boundary"), "truth")
    require_text(truth["interpretation_boundary"], "truth interpretation_boundary")
    known_events = string_list(truth["event_ids"], "truth event_ids")
    if not isinstance(truth["facts"], list) or not truth["facts"]:
        raise ValueError("truth facts must be a nonempty list")
    expected = {}
    for fact in truth["facts"]:
        require_keys(fact, ("fact_id", "observation", "evidence_id_groups"), "truth fact")
        require_text(fact["fact_id"], "truth fact_id")
        require_text(fact["observation"], "truth observation")
        if fact["fact_id"] in expected:
            raise ValueError("duplicate truth fact_id: " + fact["fact_id"])
        if not isinstance(fact["evidence_id_groups"], list) or not fact["evidence_id_groups"]:
            raise ValueError("truth evidence_id_groups must be a nonempty list")
        groups = [string_list(group, "truth evidence group") for group in fact["evidence_id_groups"]]
        if any(not group <= known_events for group in groups):
            raise ValueError("truth evidence group references an unknown event")
        if len({frozenset(group) for group in groups}) != len(groups):
            raise ValueError("duplicate truth evidence group")
        expected[fact["fact_id"]] = groups

    validate_envelope(findings, ("schema_version", "case_id", "findings"), "findings")
    if findings["case_id"] != truth["case_id"]:
        raise ValueError("findings case_id does not match truth")
    if not isinstance(findings["findings"], list) or not findings["findings"]:
        raise ValueError("findings must be a nonempty list")
    seen = set()
    details = []
    for finding in findings["findings"]:
        require_keys(finding, ("fact_id", "event_ids"), "finding")
        fact_id = finding["fact_id"]
        require_text(fact_id, "finding fact_id")
        if fact_id in seen:
            raise ValueError("duplicate finding: " + fact_id)
        seen.add(fact_id)
        citations = string_list(finding["event_ids"], "finding event_ids")
        groups = expected.get(fact_id)
        relevant = set().union(*groups) if groups else set()
        invalid = citations - relevant
        supported = groups is not None and not invalid and all(citations & group for group in groups)
        details.append({"fact_id": fact_id, "correct": supported,
                        "invalid_citations": sorted(invalid),
                        "unknown_citations": sorted(citations - known_events),
                        "missing_evidence_groups": [] if groups is None else
                            [sorted(group) for group in groups if not citations & group]})
    details.sort(key=lambda detail: detail["fact_id"])
    correct = sum(detail["correct"] for detail in details)
    return {
        "schema_version": 1, "case_id": truth["case_id"],
        "scope": "workflow-plumbing-smoke; observations only; not model quality",
        "expected_findings": len(expected), "submitted_findings": len(details),
        "correct_findings": correct, "false_findings": len(details) - correct,
        "missed_findings": len(expected) - correct,
        "invalid_citations": sum(len(detail["invalid_citations"]) for detail in details),
        "precision": correct / len(details), "recall": correct / len(expected),
        "details": details,
    }


def main(argv=None):
    class JsonParser(argparse.ArgumentParser):
        def error(self, message):
            raise ValueError(message)

    parser = JsonParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("generate", help="Write a new invented case and separate operator key")
    create.add_argument("--evidence-dir", required=True)
    create.add_argument("--truth-dir", required=True)
    scoring = commands.add_parser("score", help="Score exact observable fact IDs and event citations")
    scoring.add_argument("--truth", required=True)
    scoring.add_argument("--findings", required=True)
    try:
        args = parser.parse_args(argv)
        if args.command == "generate":
            result = generate(args.evidence_dir, args.truth_dir)
        else:
            result = score(load_json(args.truth), load_json(args.findings))
    except (OSError, ValueError) as error:
        print(json.dumps({"error": str(error)}, sort_keys=True))
        return 2
    print(json.dumps(result, sort_keys=True, allow_nan=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())

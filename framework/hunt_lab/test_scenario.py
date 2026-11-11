"""Behavior tests for the invented medium/large scenario generator and operator scorer.

Run from framework/: python -m unittest -v hunt_lab.test_scenario
Generated artifacts go to the OS temporary directory, never the workspace. Most
checks use the internal test-only "tiny" size (same storylines, fewer hosts and
less noise) for both stories; one test generates real medium cases through the CLI.
Story a outputs are pinned by sha256 so adding stories can never change them; the
pins assume CPython's random.Random algorithms, which are stable across 3.x.
"""

import contextlib
import io
import ipaddress
import json
from pathlib import Path
import re
import struct
import tempfile
from types import SimpleNamespace
import unittest

from hunt_lab import scenario


ALLOWED_NETWORKS = [ipaddress.ip_network(net) for net in
                    ("10.0.0.0/8", "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]
EVIDENCE_FILES = ("events.jsonl", "traffic.pcap", "intel.jsonl", "case.json")
PINNED_TINY_A = {
    "events.jsonl": "c181d330cc90ec41aa17844bf3fe826012539cbec1fc05dd444adfa9e2ed3a82",
    "traffic.pcap": "7e4aff3de6f373253dfb873b4647a90a8a8de1ff077e5155fd311b0bb83743c8",
    "intel.jsonl": "a72e80d54060d5fa2ba17133827c007b3a5950e9078c1ca1c6b9a5342e2d15c6",
    "case.json": "34b75640a1b64421d2af9f6ab2282f27823c0220d03b1a66a9f63220c708b549",
    "truth.json": "7c4b5859e750c44a7456831abf7da1ee4968530b1af364fff58a30ad2b481587",
}
PINNED_MEDIUM_A = {
    "events.jsonl": "3aff6df769254ddb2aa5bf71fa006f1efb9c2e7c3b335a670204158590517060",
    "traffic.pcap": "b50612822339f4e95974c61fd94ff71fcd32e77034b37a629c1049c162e59d77",
    "intel.jsonl": "a17f8bf3e5604f4ae0063bbddfe8cc64704ac25736e0307199e66cb35b04924e",
    "case.json": "fbc0636ac931f0509a187a147e3d77324a28155fb2a0a631832628a77aa51811",
    "truth.json": "efbe22f0949a172832c2d536a15984ea7f350ef8c7ecebb6747abe9a82f6d74d",
}


def folded_checksum(data):
    """Independent struct-based RFC 1071 sum; a valid header/segment sums to zero."""
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def read_name(payload, offset):
    labels = []
    while payload[offset]:
        length = payload[offset]
        labels.append(payload[offset + 1:offset + 1 + length].decode("ascii"))
        offset += 1 + length
    return ".".join(labels), offset + 1


def client_hello_sni(payload):
    """Return the SNI host from a TLS ClientHello record, else None."""
    if len(payload) < 44 or payload[0] != 0x16 or payload[5] != 0x01:
        return None
    position = 43
    position += 1 + payload[position]
    position += 2 + struct.unpack("!H", payload[position:position + 2])[0]
    position += 1 + payload[position]
    end = position + 2 + struct.unpack("!H", payload[position:position + 2])[0]
    position += 2
    while position < end:
        kind, length = struct.unpack("!HH", payload[position:position + 4])
        if kind == 0:
            name_length = struct.unpack("!H", payload[position + 7:position + 9])[0]
            return payload[position + 9:position + 9 + name_length].decode("ascii")
        position += 4 + length
    return None


def parse_pcap(data, test):
    """Minimal classic-pcap reader that validates framing, lengths and checksums."""
    test.assertEqual(struct.unpack("<IHHIIII", data[:24]), (0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    offset, previous = 24, 0
    result = {"queries": set(), "responses": 0, "syns": set(), "sni": {}, "http": {}, "ips": set(),
              "qnames": set(), "times": [], "packets": 0, "frames": []}
    while offset < len(data):
        seconds, micros, captured, original = struct.unpack("<IIII", data[offset:offset + 16])
        offset += 16
        frame = data[offset:offset + captured]
        offset += captured
        test.assertEqual(captured, original)
        test.assertEqual(len(frame), captured)
        moment = seconds * 1000000 + micros
        test.assertGreaterEqual(moment, previous)
        previous = moment
        result["times"].append(moment)
        result["packets"] += 1
        test.assertEqual(frame[12:14], b"\x08\x00")
        ip = frame[14:34]
        test.assertEqual(ip[0], 0x45)
        test.assertEqual(folded_checksum(ip), 0)
        total = struct.unpack("!H", ip[2:4])[0]
        segment = frame[34:14 + total]
        source, destination = str(ipaddress.IPv4Address(ip[12:16])), str(ipaddress.IPv4Address(ip[16:20]))
        result["ips"].update((source, destination))
        pseudo = ip[12:20] + struct.pack("!BBH", 0, ip[9], len(segment))
        test.assertEqual(folded_checksum(pseudo + segment), 0)
        if ip[9] == 17:
            sport, dport, length, _ = struct.unpack("!HHHH", segment[:8])
            test.assertEqual(length, len(segment))
            payload = segment[8:]
            if 53 in (sport, dport):
                flags = struct.unpack("!H", payload[2:4])[0]
                name, _ = read_name(payload, 12)
                result["qnames"].add(name)
                if dport == 53:
                    test.assertEqual(flags, 0x0100)
                    result["queries"].add((moment // 1000, source, sport, name))
                else:
                    result["responses"] += 1
        else:
            test.assertEqual(ip[9], 6)
            sport, dport, _, _, offset_byte, flags = struct.unpack("!HHIIBB", segment[:14])
            payload = segment[(offset_byte >> 4) * 4:]
            key = (source, sport, destination, dport)
            if flags == 0x02:
                result["syns"].add((moment // 1000,) + key)
            if payload and key not in result["sni"]:
                sni = client_hello_sni(payload)
                if sni:
                    result["sni"][key] = sni
            if payload.startswith((b"GET ", b"POST ", b"PUT ")) and key not in result["http"]:
                host = re.search(rb"\r\nHost: ([^\r]+)\r\n", payload).group(1).decode("ascii")
                result["http"][key] = (payload.split(b" ", 1)[0].decode("ascii"), host)
        # frames[n - 1] is tshark's frame.number n: its endpoint pair, either direction.
        result["frames"].append(frozenset(((source, sport), (destination, dport))))
    test.assertEqual(offset, len(data))
    return result


def iso_ms(text):
    hours, minutes, seconds = text[11:].rstrip("Z").split(":")
    return scenario.DAY_SECONDS * 1000 + (int(hours) * 3600 + int(minutes) * 60) * 1000 + int(float(seconds) * 1000 + 0.5)


def domains_in(row):
    names = []
    dns = row.get("dns")
    if dns:
        names.append(dns["question"]["name"])
        names.extend(answer["name"] for answer in dns["answers"])
    if "url" in row:
        names.append(row["url"]["domain"])
    if "tls" in row:
        names.append(row["tls"]["server_name"])
    return names


def indicator_values(row):
    return domains_in(row) + [row[side]["ip"] for side in ("source", "destination") if side in row]


def generate_tiny(root, seed=11, name="case", story="a"):
    evidence, operator = Path(root) / (name + "-evidence"), Path(root) / (name + "-operator")
    summary = scenario.generate("tiny", seed, "lab-tiny-001", evidence, operator, story)
    return summary, evidence, operator


class GeneratedTinyCase(unittest.TestCase):
    """Story a (phishing -> beacon -> DNS tunnel); subclassed below for story b."""

    STORY = "a"
    REQUIRED_FAMILIES = ({(scenario.SEC, code) for code in ("4624", "4625", "4634", "4672", "4698")}
                         | {(scenario.SYSMON, code) for code in ("1", "3", "10", "11", "22")}
                         | {(scenario.PROXY, "access"), (scenario.COVERAGE, "coverage-gap")})
    OPTIONAL_FAMILIES = set()
    PORTS = {443, 80, 445, 5985, 3389}
    # (fact, group, indicator value): the C2 domain's intel record also cites the beacon's lookup group.
    INTEL_ALTERNATIVE = ("attack.c2.jittered-https-beacon", 0, scenario.C2)

    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="synthetic-scenario-")
        cls.summary, cls.evidence, cls.operator = generate_tiny(cls.temporary.name, story=cls.STORY)
        cls.events = [json.loads(line) for line in (cls.evidence / "events.jsonl").read_text(encoding="utf-8").splitlines()]
        cls.by_id = {row["event"]["id"]: row for row in cls.events}
        cls.truth = json.loads((cls.operator / "truth.json").read_text(encoding="utf-8"))
        cls.case = json.loads((cls.evidence / "case.json").read_text(encoding="utf-8"))
        cls.intel = [json.loads(line) for line in (cls.evidence / "intel.jsonl").read_text(encoding="utf-8").splitlines()]

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_outputs_are_separate_and_summary_hashes_match(self):
        self.assertEqual({path.name for path in self.evidence.iterdir()}, set(EVIDENCE_FILES))
        self.assertEqual({path.name for path in self.operator.iterdir()}, {"truth.json"})
        import hashlib
        for name, info in self.summary["files"].items():
            data = Path(info["path"]).read_bytes()
            self.assertEqual((len(data), hashlib.sha256(data).hexdigest()), (info["bytes"], info["sha256"]))
        self.assertEqual(self.summary["event_count"], len(self.events))
        self.assertEqual(sum(self.summary["events_by_family"].values()), len(self.events))
        self.assertEqual(self.summary["facts"]["total"], len(self.truth["facts"]))

    def test_events_have_unique_ordered_ids_and_case_dataset(self):
        ids = [row["event"]["id"] for row in self.events]
        self.assertEqual(ids, ["evt-%06d" % number for number in range(1, len(ids) + 1)])
        stamps = [row["@timestamp"] for row in self.events]
        self.assertEqual(stamps, sorted(stamps))
        window = self.case["time_range_utc"]
        self.assertTrue(all(window["start_inclusive"][:19] <= stamp[:19] < window["end_exclusive"][:19] for stamp in stamps))
        self.assertTrue(all(re.match(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$", stamp) for stamp in stamps))
        families = set()
        for row in self.events:
            event = row["event"]
            self.assertEqual(event["dataset"], "lab-tiny-001")
            self.assertTrue({"id", "kind", "category", "type", "code", "dataset", "provider", "action"} <= set(event))
            families.add((event["provider"], event["code"]))
            for side in ("source", "destination"):
                if side in row:
                    self.assertIs(type(row[side]["port"]), int)
            if "dns" in row:
                self.assertTrue(all(isinstance(answer, dict) and {"name", "type", "data"} <= set(answer)
                                    for answer in row["dns"]["answers"]))
            if "process" in row:
                self.assertIs(type(row["process"]["pid"]), int)
                if "parent" in row["process"]:
                    self.assertIs(type(row["process"]["parent"]["pid"]), int)
            if "http" in row:
                self.assertIs(type(row["http"]["response"]["status_code"]), int)
        self.assertTrue(self.REQUIRED_FAMILIES <= families, self.REQUIRED_FAMILIES - families)
        self.assertTrue(families <= self.REQUIRED_FAMILIES | self.OPTIONAL_FAMILIES, families - self.REQUIRED_FAMILIES)
        coverage = [row for row in self.events if row["event"]["provider"] == scenario.COVERAGE]
        self.assertTrue(all(row["event"]["category"] == ["configuration"] and row["message"] for row in coverage))

    def test_case_metadata_shape(self):
        self.assertEqual(set(self.case), {"schema_version", "case_id", "question", "sources", "time_range_utc"})
        self.assertEqual(self.case["case_id"], "lab-tiny-001")
        self.assertEqual([source["artifact"] for source in self.case["sources"]], ["events.jsonl", "traffic.pcap", "intel.jsonl"])
        self.assertEqual(set(self.case["time_range_utc"]), {"start_inclusive", "end_exclusive"})

    def test_truth_facts_are_grounded_in_existing_events(self):
        facts = self.truth["facts"]
        self.assertEqual(set(self.truth), {"schema_version", "case_id", "interpretation_boundary", "facts"})
        self.assertTrue(12 <= len(facts) <= 18)
        self.assertEqual(len({fact["fact_id"] for fact in facts}), len(facts))
        self.assertEqual({fact["kind"] for fact in facts}, {"attack", "decoy", "benign-pattern", "coverage"})
        for fact in facts:
            self.assertEqual(set(fact), {"fact_id", "kind", "observation", "entities", "evidence_event_groups",
                                         "evidence_frame_groups", "evidence_intel_groups", "evidence_sibling_groups"})
            self.assertEqual(len(fact["evidence_frame_groups"]), len(fact["evidence_event_groups"]))
            self.assertEqual(len(fact["evidence_intel_groups"]), len(fact["evidence_event_groups"]))
            self.assertEqual(len(fact["evidence_sibling_groups"]), len(fact["evidence_event_groups"]))
            self.assertEqual(set(fact["entities"]), {"hosts", "users", "processes", "domains", "ips"})
            self.assertTrue(fact["evidence_event_groups"])
            for group in fact["evidence_event_groups"]:
                self.assertTrue(group)
                for event_id in group:
                    self.assertIn(event_id, self.by_id, fact["fact_id"])
        self.check_story_truth(facts)

    def test_sibling_events_share_process_and_category_and_are_never_key_events(self):
        accepted = {eid for fact in self.truth["facts"] for group in fact["evidence_event_groups"] for eid in group}
        listed = []
        for fact in self.truth["facts"]:
            for group, siblings in zip(fact["evidence_event_groups"], fact["evidence_sibling_groups"]):
                if fact["kind"] != "attack":
                    self.assertEqual(siblings, [], fact["fact_id"])
                shapes = {(self.by_id[eid].get("process", {}).get("entity_id"), self.by_id[eid]["event"]["category"][0])
                          for eid in group}
                for eid in siblings:
                    row = self.by_id[eid]
                    self.assertIn((row["process"]["entity_id"], row["event"]["category"][0]), shapes, eid)
                    self.assertNotIn(eid, accepted)
                listed.extend(siblings)
        self.assertEqual(len(listed), len(set(listed)))

    def fact_events(self, fact_id, group=0):
        fact = next(fact for fact in self.truth["facts"] if fact["fact_id"] == fact_id)
        return [self.by_id[event_id] for event_id in fact["evidence_event_groups"][group]]

    def test_frame_alternatives_are_the_written_frames_of_each_groups_events(self):
        frames = parse_pcap((self.evidence / "traffic.pcap").read_bytes(), self)["frames"]
        listed = 0
        for fact in self.truth["facts"]:
            for events, cited in zip(fact["evidence_event_groups"], fact["evidence_frame_groups"]):
                rows = [self.by_id[event_id] for event_id in events]
                pairs = {frozenset(((row["source"]["ip"], row["source"]["port"]),
                                    (row["destination"]["ip"], row["destination"]["port"])))
                         for row in rows if "destination" in row}
                numbers = [int(item[len("frame-"):]) for item in cited]
                self.assertEqual(cited, ["frame-%d" % number for number in sorted(set(numbers))], fact["fact_id"])
                self.assertTrue(all(1 <= number <= len(frames) for number in numbers), fact["fact_id"])
                # Every listed frame number, counted in the written capture's order, is a packet of one of the
                # group's network events, and every network event of the group has its packets listed.
                self.assertEqual({frames[number - 1] for number in numbers}, pairs, fact["fact_id"])
                listed += len(numbers)
        self.assertGreater(listed, 0)

    def test_intel_alternatives_name_an_indicator_the_groups_events_carry(self):
        records = {doc["id"]: doc for doc in self.intel}
        for fact in self.truth["facts"]:
            named = {value.lower() for key in ("domains", "ips") for value in fact["entities"][key]}
            earlier = set()
            for events, cited in zip(fact["evidence_event_groups"], fact["evidence_intel_groups"]):
                carried = {value.lower() for event_id in events for value in indicator_values(self.by_id[event_id])}
                for record_id in cited:
                    indicator = records[record_id]["indicator"]
                    self.assertIn(indicator["type"], ("domain", "ip"), fact["fact_id"])
                    self.assertIn(indicator["value"].lower(), named & carried, fact["fact_id"])
                # Each intel ID is listed in one group of a fact only: the first whose sessions carry it.
                self.assertFalse(earlier & set(cited), fact["fact_id"])
                earlier |= set(cited)
        fact_id, group, value = self.INTEL_ALTERNATIVE
        fact = next(fact for fact in self.truth["facts"] if fact["fact_id"] == fact_id)
        expected = [doc["id"] for doc in self.intel if doc["indicator"]["value"] == value]
        self.assertTrue(expected)
        self.assertTrue(set(expected) <= set(fact["evidence_intel_groups"][group]), fact["evidence_intel_groups"])

    def check_story_truth(self, facts):
        names = [row["dns"]["question"]["name"] for row in self.fact_events("attack.exfiltration.dns-tunnel")]
        self.assertEqual(len(names), scenario.EXFIL_QUERIES)
        self.assertTrue(all(len(name) > 100 and name.endswith(scenario.EXFIL_ZONE) for name in names))
        powershell = self.fact_events("attack.execution.office-child-powershell", 1)[0]
        self.assertEqual(powershell["process"]["parent"]["name"], "WINWORD.EXE")

    def test_pcap_parses_and_matches_dns_connections_and_tls(self):
        capture = parse_pcap((self.evidence / "traffic.pcap").read_bytes(), self)
        self.assertEqual(capture["packets"], self.summary["packets"])
        self.assertEqual(len(capture["queries"]), capture["responses"])
        start = iso_ms(self.case["time_range_utc"]["start_inclusive"]) * 1000
        end = iso_ms(self.case["time_range_utc"]["end_exclusive"]) * 1000
        self.assertTrue(start <= capture["times"][0] and capture["times"][-1] < end)
        syn_tuples = {item[1:]: item[0] for item in capture["syns"]}
        dns_events = tls_events = http_events = 0
        for row in self.events:
            code, provider = row["event"]["code"], row["event"]["provider"]
            moment = iso_ms(row["@timestamp"])
            if code == "22":
                dns_events += 1
                self.assertIn((moment, row["source"]["ip"], row["source"]["port"], row["dns"]["question"]["name"]),
                              capture["queries"])
            elif code == "3" and row["network"]["transport"] == "tcp":
                key = (row["source"]["ip"], row["source"]["port"], row["destination"]["ip"], row["destination"]["port"])
                self.assertEqual(syn_tuples.get(key), moment)
            elif provider in (scenario.PROXY, scenario.IIS):
                key = (row["source"]["ip"], row["source"]["port"], row["destination"]["ip"], row["destination"]["port"])
                if row["url"]["scheme"] == "https":
                    tls_events += 1
                    self.assertEqual(capture["sni"].get(key), row["tls"]["server_name"])
                else:
                    http_events += 1
                    self.assertEqual(capture["http"].get(key), (row["http"]["request"]["method"], row["url"]["domain"]))
        self.assertTrue(dns_events and tls_events and http_events)
        ports = {key[3] for key in capture["sni"]} | {item[4] for item in capture["syns"]}
        self.assertTrue(self.PORTS <= ports, self.PORTS - ports)

    def test_no_truth_content_leaks_into_evidence(self):
        texts = {name: (self.evidence / name).read_text(encoding="utf-8").lower()
                 for name in ("events.jsonl", "intel.jsonl", "case.json")}
        for fact in self.truth["facts"]:
            for name, text in texts.items():
                self.assertNotIn(fact["fact_id"].lower(), text, name)
                self.assertNotIn(fact["observation"].lower(), text, name)
        for word in ("decoy", "planted", "fact_id", "truth", "benign-pattern", "interpretation_boundary",
                     "storyline", "evidence_event_groups", "evidence_frame_groups", "evidence_intel_groups"):
            for name, text in texts.items():
                self.assertNotIn(word, text, (word, name))
        self.assertFalse(list(self.evidence.rglob("truth*")))

    def test_only_invented_addresses_and_domains(self):
        def allowed_ip(value):
            address = ipaddress.ip_address(value)
            return any(address in network for network in ALLOWED_NETWORKS)

        def allowed_name(value):
            return value.lower().endswith(scenario.ALLOWED_SUFFIXES)

        for row in self.events:
            for value in row.get("host", {}).get("ip", []):
                self.assertTrue(allowed_ip(value), value)
            for side in ("source", "destination"):
                if side in row:
                    self.assertTrue(allowed_ip(row[side]["ip"]), row[side]["ip"])
            for answer in row.get("dns", {}).get("answers", []):
                if answer["type"] == "A":
                    self.assertTrue(allowed_ip(answer["data"]), answer["data"])
            for name in domains_in(row):
                self.assertTrue(allowed_name(name), name)
        for doc in self.intel:
            self.assertEqual(doc["case_id"], "lab-tiny-001")
            value = doc["indicator"]["value"]
            if doc["indicator"]["type"] == "ip":
                self.assertTrue(allowed_ip(value), value)
            elif doc["indicator"]["type"] == "domain":
                self.assertTrue(allowed_name(value), value)
        capture = parse_pcap((self.evidence / "traffic.pcap").read_bytes(), self)
        self.assertTrue(all(allowed_ip(value) for value in capture["ips"]))
        self.assertTrue(all(allowed_name(value) for value in capture["qnames"] | set(capture["sni"].values())))

    def test_intel_mixes_true_false_and_irrelevant_indicators(self):
        identities = [(doc["indicator"]["type"], doc["indicator"]["value"].lower(), doc["threat"]["feed"]["name"]) for doc in self.intel]
        self.assertEqual(len(identities), len(set(identities)))
        self.assertEqual(len({doc["id"] for doc in self.intel}), len(self.intel))
        values = {doc["indicator"]["value"]: doc for doc in self.intel}
        hashes = {row["process"].get("hash", {}).get("sha256") for row in self.events if "process" in row}
        self.check_story_intel(values, hashes)
        self.assertGreater(len(self.intel), 40)
        for doc in self.intel:
            self.assertEqual(set(doc), {"id", "case_id", "indicator", "threat", "confidence", "description", "first_seen"})
            self.assertIn(doc["confidence"], ("low", "medium", "high"))

    def check_story_intel(self, values, hashes):
        self.assertEqual(values[scenario.LOOKALIKE]["confidence"], "high")
        self.assertEqual(values[scenario.SYNCHOST_SHA256]["indicator"]["type"], "hash")
        self.assertEqual(values[scenario.UPDATER]["confidence"], "low")
        self.assertNotIn(scenario.EXFIL_ZONE, values)
        self.assertIn(scenario.SYNCHOST_SHA256, hashes)


class GeneratedTinyStoryB(GeneratedTinyCase):
    """Story b (public web server -> webshell -> account -> tunnel service -> RDP -> DB dump -> HTTPS POSTs)."""

    STORY = "b"
    REQUIRED_FAMILIES = ({(scenario.SEC, code) for code in ("4624", "4634", "4672", "4698", "4720", "4728", "4732")}
                         | {(scenario.SYSMON, code) for code in ("1", "3", "10", "11", "22")}
                         | {(scenario.PROXY, "access"), (scenario.COVERAGE, "coverage-gap"),
                            (scenario.IIS, "access"), (scenario.SYSTEM_LOG, "7045")})
    OPTIONAL_FAMILIES = {(scenario.SEC, "4625")}
    PORTS = {443, 80, 445, 3389, 9389}
    INTEL_ALTERNATIVE = ("attack.recon.portal-path-probing", 0, scenario.B_ATTACKER)

    def check_story_truth(self, facts):
        children = self.fact_events("attack.execution.webshell-commands", 1)
        self.assertTrue(children and all(row["process"]["parent"]["name"] == "w3wp.exe" for row in children))
        posts = self.fact_events("attack.exfiltration.https-post", 1)
        proxied = [row for row in posts if row["event"]["provider"] == scenario.PROXY]
        self.assertEqual(len(proxied), 10)
        self.assertTrue(all(row["http"]["request"]["method"] == "POST" and row["http"]["request"]["bytes"] > 1000000
                            for row in proxied))
        logon = self.fact_events("attack.lateral.rdp-to-database", 1)
        self.assertTrue(any(row["event"]["code"] == "4624" and row["winlog"]["event_data"]["LogonType"] == "10"
                            and row["user"]["name"] == "supportsvc" for row in logon))
        created = self.fact_events("attack.persistence.domain-account", 1)[0]
        self.assertEqual((created["event"]["code"], created["user"]["target"]["name"]), ("4720", "supportsvc"))

    def check_story_intel(self, values, hashes):
        self.assertEqual(values[scenario.B_STAGE]["confidence"], "high")
        self.assertEqual(values[scenario.TNLSVC_SHA256]["indicator"]["type"], "hash")
        self.assertEqual(values[scenario.B_CDN]["confidence"], "low")
        self.assertIn(scenario.TNLSVC_SHA256, hashes)


class GenerationRules(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="synthetic-scenario-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def invoke(self, arguments):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            status = scenario.main(arguments)
        return status, json.loads(output.getvalue())

    def test_same_seed_is_byte_identical_and_other_seed_differs(self):
        for story in ("a", "b"):
            with self.subTest(story=story):
                _, first, first_key = generate_tiny(self.root, 5, story + "1", story)
                _, second, second_key = generate_tiny(self.root, 5, story + "2", story)
                _, third, _ = generate_tiny(self.root, 6, story + "3", story)
                for name in EVIDENCE_FILES:
                    self.assertEqual((first / name).read_bytes(), (second / name).read_bytes(), name)
                self.assertEqual((first_key / "truth.json").read_bytes(), (second_key / "truth.json").read_bytes())
                self.assertNotEqual((first / "events.jsonl").read_bytes(), (third / "events.jsonl").read_bytes())

    def test_story_a_output_is_pinned(self):
        """Adding stories must never change story a: same size/seed/case id stays byte-identical."""
        summary, _, _ = generate_tiny(self.root, 11, "pinned")
        self.assertEqual({name: info["sha256"] for name, info in summary["files"].items()}, PINNED_TINY_A)

    def test_stories_use_distinct_entities(self):
        sets = {}
        for story in ("a", "b"):
            _, _, operator = generate_tiny(self.root, 3, "entities-" + story, story)
            truth = json.loads((operator / "truth.json").read_text(encoding="utf-8"))
            sets[story] = {kind: {value for fact in truth["facts"] for value in fact["entities"][kind]}
                           for kind in ("hosts", "users", "processes", "domains", "ips")}
        for kind in ("hosts", "users", "domains", "ips"):
            self.assertEqual(sets["a"][kind] & sets["b"][kind], set(), kind)
        self.assertTrue(sets["a"]["processes"] & sets["b"]["processes"] <= {"cmd.exe", "powershell.exe", "lsass.exe"})

    def test_existing_files_are_never_overwritten(self):
        for directory in ("evidence", "operator"):
            with self.subTest(directory=directory):
                base = self.root / directory
                evidence, operator = base / "evidence", base / "operator"
                target = (evidence if directory == "evidence" else operator) / "keep.txt"
                target.parent.mkdir(parents=True)
                target.write_bytes(b"preserve")
                with self.assertRaises(ValueError):
                    scenario.generate("tiny", 1, "lab-tiny-001", evidence, operator)
                self.assertEqual(target.read_bytes(), b"preserve")
                self.assertEqual([path for path in base.rglob("*") if path.is_file()], [target])
        file_path = self.root / "plain-file"
        file_path.write_bytes(b"x")
        with self.assertRaises(ValueError):
            scenario.generate("tiny", 1, "lab-tiny-001", file_path, self.root / "key")
        self.assertEqual(file_path.read_bytes(), b"x")

    def test_same_or_nested_directories_and_bad_ids_are_refused(self):
        evidence, operator = self.root / "evidence", self.root / "operator"
        for first, second in ((evidence, evidence), (evidence, evidence / "key"), (operator / "evidence", operator)):
            with self.assertRaises(ValueError):
                scenario.generate("tiny", 1, "lab-tiny-001", first, second)
        for case_id in ("AB", "Lab-001", "lab_001", "x" * 65):
            with self.assertRaises(ValueError):
                scenario.generate("tiny", 1, case_id, evidence, operator)
        self.assertFalse(evidence.exists() or operator.exists())
        status, result = self.invoke(["generate", "--size", "tiny", "--seed", "1", "--case-id", "lab-tiny-001",
                                      "--evidence-dir", str(evidence), "--truth-dir", str(operator)])
        self.assertEqual(status, 2)
        self.assertIn("error", result)

    def test_medium_cli_generation_hits_size_targets(self):
        for story, pinned in (("a", PINNED_MEDIUM_A), ("b", None)):
            with self.subTest(story=story):
                evidence, operator = self.root / ("evidence-" + story), self.root / ("operator-" + story)
                status, summary = self.invoke(["generate", "--size", "medium", "--story", story, "--seed", "7",
                                               "--case-id", "lab-med-001", "--evidence-dir", str(evidence),
                                               "--truth-dir", str(operator)])
                self.assertEqual(status, 0, summary)
                self.assertEqual((summary["hosts"], summary["story"]), (25, story))
                self.assertTrue(17000 <= summary["event_count"] <= 24000, summary["event_count"])
                self.assertTrue(3000 <= summary["sessions"]["total"] <= 6000, summary["sessions"])
                self.assertTrue(12 <= summary["facts"]["total"] <= 18)
                self.assertEqual(set(summary["files"]), set(EVIDENCE_FILES) | {"truth.json"})
                if pinned:
                    self.assertEqual({name: info["sha256"] for name, info in summary["files"].items()}, pinned)


def perfect_report(truth):
    claims = []
    for number, fact in enumerate(truth["facts"], 1):
        entity = next(value for values in fact["entities"].values() for value in values)
        cited = " ".join(group[0] for group in fact["evidence_event_groups"])
        qualifier = "legitimate and benign" if fact["kind"] in ("decoy", "benign-pattern") else "observed"
        claims.append({"claim_id": "final:c%d" % number, "kind": "finding",
                       "statement": "%s activity involving %s (%s): %s" % (qualifier, entity, fact["kind"], cited),
                       "evidence_ids": ["lab-case-1"], "entity_ids": [], "contradicts": []})
    return {"schema_version": 1, "case_id": truth["case_id"], "step_id": "final", "profile": "framework-coordinator",
            "claims": claims, "reviews": [], "disposition": "needs_validation", "limitations": [], "requested_decisions": []}


# A key written before frame and intel alternatives existed, a report that also carries such citations, and the
# result the event-only scorer gave for it: keys without alternatives must keep scoring exactly this way.
OLD_STYLE_KEY = {"schema_version": 1, "case_id": "lab-old-001", "facts": [
    {"fact_id": "attack.c2", "kind": "attack", "observation": "ws-01 beaconed to c2.example.test.",
     "entities": {"hosts": ["ws-01"], "domains": ["c2.example.test"]},
     "evidence_event_groups": [["evt-000001"], ["evt-000002", "evt-000003"]]},
    {"fact_id": "decoy.backup", "kind": "decoy", "observation": "bk-01 ran its nightly backup.",
     "entities": {"hosts": ["bk-01"]}, "evidence_event_groups": [["evt-000004"]]},
    {"fact_id": "coverage.mail", "kind": "coverage", "observation": "No mail logs.",
     "entities": {"processes": ["OUTLOOK.EXE"]}, "evidence_event_groups": [["evt-000005"]]},
]}
OLD_STYLE_REPORT = {"claims": [
    {"claim_id": "c1", "statement": "ws-01 beaconed to c2.example.test evt-000001 evt-000003 frame-7 ioc-00001"},
    {"claim_id": "c2", "statement": "The attacker compromised bk-01 evt-000004"},
], "limitations": ["No mail logs for OUTLOOK.EXE evt-000005"]}
OLD_STYLE_RESULT = {
    "found": 3, "total": 3, "decoys_cleared": 0,
    "by_kind": {kind: {"total": 1, "found": 1, "partial": 0} for kind in ("attack", "decoy", "coverage")},
    "facts": [
        {"fact_id": "attack.c2", "kind": "attack", "found": True, "cited_groups": [0, 1], "missing_groups": [],
         "cited_event_ids": ["evt-000001", "evt-000003"], "entities_named": ["c2.example.test", "ws-01"]},
        {"fact_id": "decoy.backup", "kind": "decoy", "found": True, "cited_groups": [0], "missing_groups": [],
         "cited_event_ids": ["evt-000004"], "entities_named": ["bk-01"]},
        {"fact_id": "coverage.mail", "kind": "coverage", "found": True, "cited_groups": [0], "missing_groups": [],
         "cited_event_ids": ["evt-000005"], "entities_named": ["OUTLOOK.EXE"]},
    ],
    "misattributed_decoys": [{"fact_id": "decoy.backup", "claim_id": "c2", "entities": ["bk-01"],
                              "terms": ["compromised", "attacker"]}],
    "method": "keyword and event-ID citation matching against the operator key; not human judgment",
}
# The same key with sibling lists: evt-000011/evt-000012 sit beside the attack fact's groups.
SIBLING_KEY = dict(OLD_STYLE_KEY, facts=[
    dict(OLD_STYLE_KEY["facts"][0], evidence_sibling_groups=[["evt-000011"], ["evt-000012"]]),
    dict(OLD_STYLE_KEY["facts"][1], evidence_sibling_groups=[[]]),
    dict(OLD_STYLE_KEY["facts"][2], evidence_sibling_groups=[[]]),
])


class Scoring(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="synthetic-scenario-score-")
        _, _, operator = generate_tiny(cls.temporary.name)
        cls.truth_path = operator / "truth.json"
        cls.truth = json.loads(cls.truth_path.read_text(encoding="utf-8"))

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def fact(self, fact_id):
        return next(fact for fact in self.truth["facts"] if fact["fact_id"] == fact_id)

    def test_perfect_report_finds_every_fact_without_misattribution(self):
        result = scenario.score_report(self.truth, perfect_report(self.truth))
        self.assertEqual((result["found"], result["total"]), (len(self.truth["facts"]), len(self.truth["facts"])))
        self.assertEqual(result["misattributed_decoys"], [])
        self.assertIn("not human judgment", result["method"])

    def detail(self, report, fact_id):
        return next(d for d in scenario.score_report(self.truth, report)["facts"] if d["fact_id"] == fact_id)

    def test_old_style_key_scores_exactly_as_before(self):
        self.assertEqual(scenario.score_report(OLD_STYLE_KEY, OLD_STYLE_REPORT), OLD_STYLE_RESULT)
        short = dict(OLD_STYLE_KEY["facts"][0], evidence_frame_groups=[["frame-7"]])
        with self.assertRaises(ValueError):
            scenario.score_report(dict(OLD_STYLE_KEY, facts=[short]), {"claims": []})

    def test_sibling_event_cites_its_group_only_in_the_with_siblings_score(self):
        report = {"claims": [{"claim_id": "c1", "statement": "ws-01 beaconed: evt-000001 evt-000012"},
                             {"claim_id": "c2", "statement": "bk-01 ran its routine backup evt-000004"}]}
        strict, wide = scenario.score_report(OLD_STYLE_KEY, report), scenario.score_report(SIBLING_KEY, report)
        siblings = wide.pop("with_siblings")
        attack = wide["facts"][0]
        self.assertEqual(attack.pop("cited_sibling_ids"), ["evt-000012"])
        self.assertEqual(attack.pop("with_siblings"), {"found": True, "cited_groups": [0, 1], "missing_groups": []})
        for detail in wide["facts"][1:]:
            self.assertEqual(detail.pop("cited_sibling_ids"), [])
            detail.pop("with_siblings")
        # The strict score is untouched by sibling lists: same as the key without them.
        self.assertEqual(wide, strict)
        self.assertEqual((strict["found"], strict["by_kind"]["attack"]), (1, {"total": 1, "found": 0, "partial": 1}))
        self.assertEqual((siblings["found"], siblings["by_kind"]["attack"]), (2, {"total": 1, "found": 1, "partial": 0}))
        self.assertEqual((siblings["by_kind"]["decoy"], siblings["decoys_cleared"]), (strict["by_kind"]["decoy"], strict["decoys_cleared"]))

    def test_sibling_of_one_group_does_not_cite_another_and_decoys_get_no_siblings(self):
        # evt-000011 sits beside group 0 only; citing it twice still leaves group 1 missing.
        report = {"claims": [{"claim_id": "c1", "statement": "ws-01 evt-000011 and again evt-000011"}]}
        detail = scenario.score_report(SIBLING_KEY, report)["facts"][0]["with_siblings"]
        self.assertEqual((detail["found"], detail["missing_groups"]), (False, [1]))
        decoy = scenario.score_report(SIBLING_KEY, {"claims": [{"claim_id": "c1", "statement": "bk-01 benign evt-000012"}]})
        self.assertEqual(decoy["with_siblings"]["decoys_cleared"], 0)
        malformed = dict(SIBLING_KEY["facts"][0], evidence_sibling_groups=[["evt-000011"]])
        with self.assertRaises(ValueError):
            scenario.score_report(dict(SIBLING_KEY, facts=[malformed]), {"claims": []})

    def test_event_citations_score_the_same_with_or_without_alternatives(self):
        stripped = dict(self.truth, facts=[{key: value for key, value in fact.items()
                                            if key not in ("evidence_frame_groups", "evidence_intel_groups")}
                                           for fact in self.truth["facts"]])
        lateral = self.fact("attack.lateral.winrm-helpdesk-account")["evidence_event_groups"]
        for report in (perfect_report(self.truth), {"claims": []},
                       {"claims": [{"claim_id": "c1", "statement": "hd.kestrel on srv-files-02: " + lateral[0][0]}]}):
            new, old = scenario.score_report(self.truth, report), scenario.score_report(stripped, report)
            for detail in new["facts"]:
                self.assertEqual((detail.pop("cited_frames"), detail.pop("cited_intel_ids")), ([], []))
            self.assertIn("frame- and intel-ID", new.pop("method"))
            self.assertIn("event-ID", old.pop("method"))
            self.assertEqual(new, old)

    def test_frame_citation_satisfies_its_group_and_a_wrong_frame_does_not(self):
        beacon = self.fact("attack.c2.jittered-https-beacon")
        events, frames = beacon["evidence_event_groups"], beacon["evidence_frame_groups"]
        self.assertTrue(frames[0] and frames[1])
        number = int(frames[0][0][len("frame-"):])
        # tshark's frame.number stands in for the lookup events, whatever its case or zero padding.
        cited = {"claims": [{"claim_id": "c1", "statement": "synchost.exe resolved %s (Frame-%06d) and posted %s"
                             % (scenario.C2, number, events[1][0])}]}
        detail = self.detail(cited, beacon["fact_id"])
        self.assertTrue(detail["found"], detail)
        self.assertEqual((detail["cited_frames"], detail["cited_event_ids"]), ([frames[0][0]], [events[1][0]]))
        listed = {item for group in frames for item in group}
        wrong = next("frame-%d" % n for n in range(1, len(listed) + 2) if "frame-%d" % n not in listed)
        uncited = {"claims": [{"claim_id": "c1", "statement": "synchost.exe resolved %s (%s) and posted %s"
                               % (scenario.C2, wrong, events[1][0])}]}
        detail = self.detail(uncited, beacon["fact_id"])
        self.assertFalse(detail["found"])
        self.assertEqual((detail["missing_groups"], detail["cited_frames"]), ([0], []))
        crossed = {"claims": [{"claim_id": "c1", "statement": "synchost.exe reached %s in %s" % (scenario.C2, frames[1][0])}]}
        self.assertEqual(self.detail(crossed, beacon["fact_id"])["missing_groups"], [0])

    def test_intel_id_citation_satisfies_an_indicator_group(self):
        beacon = self.fact("attack.c2.jittered-https-beacon")
        intel = beacon["evidence_intel_groups"]
        record = intel[0][0]
        self.assertEqual(intel[0], [record])
        self.assertNotIn(record, intel[1])
        # The C2 domain's record satisfies the lookup group only; the HTTPS group still needs its own citation.
        alone = {"claims": [{"claim_id": "c1", "statement": "%s matches threat intel %s" % (scenario.C2, record)}]}
        result = scenario.score_report(self.truth, alone)
        detail = next(d for d in result["facts"] if d["fact_id"] == beacon["fact_id"])
        self.assertEqual((detail["found"], detail["cited_groups"], detail["missing_groups"], detail["cited_intel_ids"]),
                         (False, [0], [1], [record]))
        self.assertEqual((result["by_kind"]["attack"]["found"], result["by_kind"]["attack"]["partial"]), (0, 1))
        post = beacon["evidence_event_groups"][1][0]
        detail = self.detail({"claims": [{"claim_id": "c1", "statement": "%s matches threat intel %s; POST %s"
                                          % (scenario.C2, record, post)}]}, beacon["fact_id"])
        self.assertTrue(detail["found"], detail)
        self.assertEqual((detail["cited_intel_ids"], detail["cited_event_ids"]), ([record], [post]))
        other = next(item for group in self.fact("attack.delivery.lookalike-download")["evidence_intel_groups"] for item in group)
        detail = self.detail({"claims": [{"claim_id": "c1", "statement": "%s matches threat intel %s" % (scenario.C2, other)}]},
                             beacon["fact_id"])
        self.assertEqual((detail["found"], detail["cited_groups"], detail["cited_intel_ids"]), (False, [], []))

    def test_missing_group_or_entity_is_not_found(self):
        lateral = self.fact("attack.lateral.winrm-helpdesk-account")
        groups = lateral["evidence_event_groups"]
        partial = {"claims": [{"claim_id": "c1", "statement": "hd.kestrel on srv-files-02: " + " ".join(g[0] for g in groups[:-1])}]}
        detail = next(d for d in scenario.score_report(self.truth, partial)["facts"] if d["fact_id"] == lateral["fact_id"])
        self.assertFalse(detail["found"])
        self.assertEqual(detail["missing_groups"], [len(groups) - 1])
        unnamed = {"claims": [{"claim_id": "c1", "statement": "Something happened: " + " ".join(g[0] for g in groups)}]}
        detail = next(d for d in scenario.score_report(self.truth, unnamed)["facts"] if d["fact_id"] == lateral["fact_id"])
        self.assertFalse(detail["found"])
        self.assertEqual(detail["missing_groups"], [])
        self.assertEqual(detail["entities_named"], [])

    def test_breakdown_separates_attack_facts_from_decoys(self):
        perfect = scenario.score_report(self.truth, perfect_report(self.truth))
        counts = {kind: sum(fact["kind"] == kind for fact in self.truth["facts"]) for kind in perfect["by_kind"]}
        self.assertEqual({kind: (bucket["found"], bucket["partial"], bucket["total"]) for kind, bucket in perfect["by_kind"].items()},
                         {kind: (count, 0, count) for kind, count in counts.items()})
        self.assertEqual(perfect["decoys_cleared"], counts["decoy"])
        lateral = self.fact("attack.lateral.winrm-helpdesk-account")
        one_group = {"claims": [{"claim_id": "c1", "statement": "hd.kestrel on srv-files-02: " + lateral["evidence_event_groups"][0][0]}]}
        attack = scenario.score_report(self.truth, one_group)["by_kind"]["attack"]
        self.assertEqual((attack["found"], attack["partial"]), (0, 1))
        admin = self.fact("decoy.it-admin-winrm")
        cited = " ".join(group[0] for group in admin["evidence_event_groups"])
        blamed = scenario.score_report(self.truth, {"claims": [{"claim_id": "c1", "statement": "The attacker used adm.halvorsen from wks-it-01 for lateral movement " + cited}]})
        self.assertEqual((blamed["by_kind"]["decoy"]["found"], blamed["decoys_cleared"]), (1, 0))

    def test_decoy_with_compromise_language_is_misattributed(self):
        admin = self.fact("decoy.it-admin-winrm")
        cited = " ".join(group[0] for group in admin["evidence_event_groups"])
        bad = {"claims": [{"claim_id": "c1", "statement": "The attacker used adm.halvorsen from wks-it-01 for lateral movement " + cited}]}
        result = scenario.score_report(self.truth, bad)
        flagged = [item for item in result["misattributed_decoys"] if item["fact_id"] == admin["fact_id"]]
        self.assertEqual(len(flagged), 1)
        self.assertIn("adm.halvorsen", flagged[0]["entities"])
        good = {"claims": [{"claim_id": "c1", "statement": "adm.halvorsen WinRM from wks-it-01 looks like lateral movement but is legitimate administration " + cited}]}
        self.assertEqual(scenario.score_report(self.truth, good)["misattributed_decoys"], [])
        shared = {"claims": [{"claim_id": "c1", "statement": "Malicious powershell.exe and wsmprovhost.exe activity " + cited}]}
        self.assertEqual(scenario.score_report(self.truth, shared)["misattributed_decoys"], [])

    def test_cli_scores_fenced_and_plain_reports(self):
        root = Path(self.temporary.name)
        plain, fenced = root / "plain.json", root / "fenced.json"
        report = perfect_report(self.truth)
        plain.write_text(json.dumps(report), encoding="utf-8")
        fenced.write_text("```json\n" + json.dumps({"claims": report["claims"][:3]}) + "\n```\n", encoding="utf-8")
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            status = scenario.main(["score", "--truth", str(self.truth_path), str(plain), str(fenced)])
        result = json.loads(output.getvalue())
        self.assertEqual(status, 0)
        self.assertEqual([item["found"] for item in result["reports"]], [len(self.truth["facts"]), 3])
        broken = root / "broken.json"
        broken.write_text("prose before ```json {}```", encoding="utf-8")
        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(scenario.main(["score", "--truth", str(self.truth_path), str(broken)]), 2)

    def test_scorer_works_unchanged_on_story_b(self):
        _, _, operator = generate_tiny(self.temporary.name, 11, "score-b", "b")
        truth = json.loads((operator / "truth.json").read_text(encoding="utf-8"))
        result = scenario.score_report(truth, perfect_report(truth))
        self.assertEqual((result["found"], result["total"], result["misattributed_decoys"]),
                         (len(truth["facts"]), len(truth["facts"]), []))
        cdn = next(fact for fact in truth["facts"] if fact["fact_id"] == "decoy.cdn-large-uploads")
        cited = " ".join(group[0] for group in cdn["evidence_event_groups"])
        bad = {"claims": [{"claim_id": "c1", "statement": "feupload.exe on pc-mkt-02 performed exfiltration " + cited}]}
        flagged = scenario.score_report(truth, bad)["misattributed_decoys"]
        self.assertEqual([item["fact_id"] for item in flagged], ["decoy.cdn-large-uploads"])


class SiblingDerivation(unittest.TestCase):
    def test_siblings_are_same_process_and_category_unclaimed_unambiguous_and_attack_lineage_only(self):
        # (process, category, tag) per seq; P is attack lineage (its start is accepted by attack fact a),
        # Q is a shared process (a user's mail client) whose start no attack group accepts, R a decoy's process.
        rows = [("P", "process", "a.start"), ("P", "file", "a.file"), ("P", "file", None), ("P", "process", None),
                ("P", "network", None), ("P", "network", "b.net"), ("P", "network", "c.net"), ("P", "file", "d.x"),
                ("Q", "file", "a.q"), ("Q", "file", None), ("R", "process", "d.start"), ("R", "process", None)]
        state = SimpleNamespace(tags={}, process_events={}, started={0: "P", 10: "R"},
                                event_ids={seq: "evt-%06d" % (seq + 1) for seq in range(len(rows))},
                                group_tags={"a": [("a.start",), ("a.file",), ("a.q",)], "b": [("b.net",)],
                                            "c": [("c.net",)], "d": [("d.x",), ("d.start",)]})
        for seq, (process, category, tag) in enumerate(rows):
            state.process_events.setdefault((process, category), []).append(seq)
            if tag:
                state.tags.setdefault(tag, []).append(seq)
        facts = [{"fact_id": "a", "kind": "attack"}, {"fact_id": "b", "kind": "attack"},
                 {"fact_id": "c", "kind": "attack"}, {"fact_id": "d", "kind": "decoy"}]
        scenario.Scenario.cite_siblings(state, facts)
        self.assertEqual({fact["fact_id"]: fact["evidence_sibling_groups"] for fact in facts}, {
            # seq 3 beside the start, seq 2 beside the file; seq 7 is a decoy's key event; Q lends nothing.
            "a": [["evt-000004"], ["evt-000003"], []],
            # seq 4 would sit beside both b's and c's groups, so it is listed in neither.
            "b": [[]], "c": [[]],
            "d": [[], []],
        })


if __name__ == "__main__":
    unittest.main()

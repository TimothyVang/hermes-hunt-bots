#!/usr/bin/env python3
"""Import one real-data hunt case from the public DEDALE dataset (Inria, CC BY 4.0); standard library only.

CLI (run from framework/):
  python -m hunt_lab.import_dedale --data-dir DEDALE_ROOT --case-id ID --start ISO --end ISO \
      [--hosts CLIENT1,CLIENT2] --evidence-dir DIR --truth-dir DIR [--max-events 200000]

Reads the hourly winlogbeat members of raw/system_logs_winlogbeat.zip whose hour
overlaps [start, end), streaming each bz2 member line by line, and keeps records
with @timestamp in [start, end) whose host.name short name (before the first dot,
case-insensitive) is in --hosts (default: every host present). Records are sorted
by (@timestamp, host.name, winlog.channel, winlog.record_id), given event.id
evt-NNNNNN in that order and event.dataset = case id; every other field is kept.
case.json says "data_origin": "public-dataset", so the case is never labelled synthetic.

The operator-only truth.json is derived mechanically from the publisher's labels
(raw/system_logs_labels.zip, clients_1_and_2) and ground-truth process lists
(labeling/system_log_labeling/ground_truth/gt_windows_client*_class_1.csv): each
in-window class-1 label must match exactly one imported event by (host.name,
winlog.channel, winlog.record_id) and is assigned to exactly one ground-truth
process with the precedence of label_dedale_winlogbeat/src/main.rs (process.entity_id,
then process.pid strictly inside the process lifetime, then winlog.process.pid for
event.module == "powershell"). One attack fact per process; class-2-only events
are listed as labels_class_2_event_ids. Each fact also lists evidence_sibling_groups:
per evidence group, the unlabelled events the same rule assigns to that process alone
that share the group's event.category (or event.code without one), plus Sysmon file
deletions winlogbeat failed to parse (no process or category fields), matched by their
winlog.event_data.ProcessGuid as category "file". They count only in the scorer's
separate with_siblings score. Nothing from the labels reaches events.jsonl or case.json.

Both output directories must not exist yet. Output is byte-identical for the same
arguments and data. A JSON summary is printed on stdout.
"""

import argparse
import bz2
from collections import defaultdict
from datetime import datetime, timedelta
import hashlib
import json
from pathlib import Path
import re
import sys
import zipfile

from hunt_lab.scenario import CASE_ID_PATTERN, SCHEMA_VERSION, json_bytes, validate_truth


WINLOGBEAT_ZIP = Path("raw") / "system_logs_winlogbeat.zip"
LABELS_ZIP = Path("raw") / "system_logs_labels.zip"
LABELS_CLASS_1 = "system_labels/clients_1_and_2/malicious_events_class_1.jsonl"
LABELS_CLASS_1_AND_2 = "system_labels/clients_1_and_2/malicious_events_class_1_and_2.jsonl"
GROUND_TRUTH_DIR = Path("labeling") / "system_log_labeling" / "ground_truth"
GROUND_TRUTH_FILE = re.compile(r"^gt_windows_client\d+_class_1\.csv$")
MEMBER = re.compile(r"^daily_winlogbeat/D\d+_H\d+_(\d{4}-\d{2}-\d{2}T\d{2})_winlogbeat_F\d+\.jsonl\.bz2$")
TIMESTAMP = re.compile(r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:\d{2})\Z")
EPOCH = datetime(1970, 1, 1)
SECOND = 10 ** 9
HOUR = 3600 * SECOND
DEFAULT_MAX_EVENTS = 200000
SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
UNPARSED_SYSMON_CATEGORY = {23: "file", 26: "file"}

QUESTION = "What happened in this environment during the window? Determine whether an intrusion occurred and reconstruct its sequence; state the scope and impact (hosts, accounts, data); explain which suspicious-looking activity has benign or alternative explanations; and name the coverage gaps that limit conclusions. Cite event.id values, separate observations from inferences, and do not assume compromise without evidence."
INTERPRETATION_BOUNDARY = "Publisher-labelled malicious processes in DEDALE (Inria, CC BY 4.0); facts derived mechanically from the labels; no decoys or coverage facts."
# Bot-visible: no dataset name or URL, since the public dataset documentation describes the attack.
COVERAGE = "Real Windows winlogbeat%s ECS records (%s) from %d hosts of a lab network; %d records; no packet capture, no intel feed."
SOURCE = "DEDALE dataset, Inria, CC BY 4.0, https://dedale.inria.fr/"


def parse_time(text):
    """ISO 8601 with Z or offset -> integer UTC nanoseconds (exact, unlike lexical order)."""
    match = TIMESTAMP.match(text) if isinstance(text, str) else None
    if not match:
        raise ValueError("unparseable timestamp: %r" % (text,))
    year, month, day, hour, minute, second = (int(part) for part in match.groups()[:6])
    seconds = (datetime(year, month, day, hour, minute, second) - EPOCH) // timedelta(seconds=1)
    zone = match.group(8)
    if zone != "Z":
        offset = int(zone[1:3]) * 3600 + int(zone[4:6]) * 60
        seconds -= offset if zone[0] == "+" else -offset
    return seconds * SECOND + int((match.group(7) or "")[:9].ljust(9, "0"))


def format_time(nanoseconds):
    seconds, fraction = divmod(nanoseconds, SECOND)
    text = (EPOCH + timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%S")
    if fraction:
        text += "." + ("%09d" % fraction).rstrip("0")
    return text + "Z"


def field(record, *path):
    for key in path:
        if not isinstance(record, dict):
            return None
        record = record.get(key)
    return record


def is_count(value):
    return type(value) is int and value >= 0


def short_host(name):
    return name.split(".", 1)[0].lower()


def label_key(record):
    name, channel, record_id = field(record, "host", "name"), field(record, "winlog", "channel"), field(record, "winlog", "record_id")
    if not isinstance(name, str) or not isinstance(channel, str) or not channel or not is_count(record_id):
        raise ValueError("label record lacks host.name, winlog.channel or winlog.record_id")
    return name, channel, record_id


def selected_members(archive, start, end):
    members = []
    for name in archive.namelist():
        match = MEMBER.match(name)
        if match:
            hour = parse_time(match.group(1) + ":00:00Z")
            if hour < end and hour + HOUR > start:
                members.append((hour, name))
    if not members:
        raise ValueError("no winlogbeat hourly member overlaps the window")
    return sorted(members)


def scan_events(data_dir, start, end, hosts, max_events):
    """Return (sorted rows, matched count, members read, host records outside their member hour).

    Each row is (timestamp ns, host.name, channel, record_id or -1, original line bytes);
    the line is the last sort key so equal keys still order deterministically.
    """
    tokens = None
    if hosts is not None:
        tokens = tuple(token for host in sorted(hosts) for token in ((host + ".").encode(), (host + '"').encode()))
    rows, matched, outside = [], 0, 0
    with zipfile.ZipFile(data_dir / WINLOGBEAT_ZIP) as archive:
        members = selected_members(archive, start, end)
        for hour, name in members:
            with archive.open(name) as packed, bz2.BZ2File(packed) as stream:
                for number, line in enumerate(stream, 1):
                    line = line.rstrip(b"\r\n")
                    if not line or (tokens is not None and not any(token in line.lower() for token in tokens)):
                        continue
                    where = "%s:%d" % (name, number)
                    try:
                        record = json.loads(line)
                    except ValueError as error:
                        raise ValueError("invalid JSON at %s: %s" % (where, error)) from None
                    host = field(record, "host", "name")
                    if not isinstance(host, str) or (hosts is not None and short_host(host) not in hosts):
                        continue
                    try:
                        timestamp = parse_time(record.get("@timestamp"))
                    except ValueError as error:
                        raise ValueError("%s at %s" % (error, where)) from None
                    outside += not hour <= timestamp < hour + HOUR
                    if not start <= timestamp < end:
                        continue
                    matched += 1
                    if matched > max_events:
                        continue
                    channel, record_id = field(record, "winlog", "channel"), field(record, "winlog", "record_id")
                    rows.append((timestamp, host, channel if isinstance(channel, str) else "",
                                 record_id if is_count(record_id) else -1, line))
    if matched > max_events:
        raise ValueError("%d records match the window and hosts, more than --max-events %d; nothing written" % (matched, max_events))
    rows.sort()
    return rows, matched, len(members), outside


def read_labels(data_dir, member, start, end, hosts):
    keys = set()
    with zipfile.ZipFile(data_dir / LABELS_ZIP) as archive:
        try:
            handle = archive.open(member)
        except KeyError:
            raise ValueError("labels archive lacks member " + member) from None
        with handle:
            for number, line in enumerate(handle, 1):
                line = line.rstrip(b"\r\n")
                if not line:
                    continue
                where = "%s:%d" % (member, number)
                try:
                    record = json.loads(line)
                    key = label_key(record)
                    timestamp = parse_time(record.get("@timestamp"))
                except ValueError as error:
                    raise ValueError("%s at %s" % (error, where)) from None
                if start <= timestamp < end and (hosts is None or short_host(key[0]) in hosts):
                    keys.add(key)
    return keys


def read_ground_truth(data_dir):
    folder = data_dir / GROUND_TRUTH_DIR
    files = sorted(path for path in folder.iterdir() if GROUND_TRUTH_FILE.match(path.name))
    if not files:
        raise ValueError("no gt_windows_client*_class_1.csv in " + str(folder))
    processes = []
    for path in files:
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            parts = [part.strip() for part in line.split(",")]
            where = "%s:%d" % (path.name, number)
            if len(parts) != 5 or not parts[2].isdigit():
                raise ValueError("ground-truth row is not host,process_guid,pid,start,end at " + where)
            try:
                created, terminated = parse_time(parts[3]), parse_time(parts[4])
            except ValueError as error:
                raise ValueError("%s at %s" % (error, where)) from None
            processes.append({"host": parts[0], "guid": parts[1], "pid": int(parts[2]),
                              "start": created, "end": terminated, "source": where})
    return processes


class ProcessMatcher:
    """The rule of label_dedale_winlogbeat/src/main.rs, restricted to the event's own host.

    main.rs ran once per host-filtered log file, so it never compared hosts; here all
    hosts share one run, so a ground-truth row only matches events of its own host.
    """

    def __init__(self, processes):
        self.by_guid, self.by_pid = defaultdict(list), defaultdict(list)
        for process in processes:
            host = process["host"].lower()
            self.by_guid[host, process["guid"]].append(process)
            self.by_pid[host, process["pid"]].append(process)

    def alive(self, host, pid, timestamp):
        # main.rs: dt_create_timestamp < dt_timestamp && dt_timestamp < dt_terminate_timestamp
        return [process for process in self.by_pid.get((host, pid), ())
                if process["start"] < timestamp < process["end"]]

    def match(self, record, host, timestamp):
        """Return (rule, candidates) for the first rule with any candidate, else (None, [])."""
        entity_id = field(record, "process", "entity_id")
        if isinstance(entity_id, str) and self.by_guid.get((host, entity_id)):
            return "process.entity_id", self.by_guid[host, entity_id]
        pid = field(record, "process", "pid")
        if is_count(pid):
            found = self.alive(host, pid, timestamp)
            if found:
                return "process.pid", found
        pid = field(record, "winlog", "process", "pid")
        if field(record, "event", "module") == "powershell" and is_count(pid):
            found = self.alive(host, pid, timestamp)
            if found:
                return "winlog.process.pid", found
        return None, []


def event_id(position):
    return "evt-%06d" % (position + 1)


def group_key(record, category=None):
    if category is None:
        category = field(record, "event", "category")
    if isinstance(category, list) and category:
        return "category:" + str(category[0])
    if isinstance(category, str) and category:
        return "category:" + category
    return "code:" + str(field(record, "event", "code"))


def image_token(image):
    if not image:
        return "process"
    base = re.split(r"[\\/]", image)[-1].lower()
    if "." in base:
        base = base.rsplit(".", 1)[0]
    return re.sub(r"[^a-z0-9_-]+", "-", base).strip("-") or "process"


def distinct(records, *path):
    return sorted({value for value in (field(record, *path) for record in records) if isinstance(value, str) and value})


def build_facts(assigned, siblings):
    """assigned: process index -> (process, [(position, record, rule)]) in position order;
    siblings: (process index, group key) -> positions of that process's unlabelled events with that key."""
    facts, used = [], set()
    for process, members in sorted(assigned.values(), key=lambda item: item[1][0][0]):
        records = [record for _, record, _ in members]
        image = next((value for _, record, rule in members if rule != "winlog.process.pid"
                      for value in (field(record, "process", "executable"), field(record, "process", "name"))
                      if isinstance(value, str) and value), None)
        fact_id = "attack.%s.%s.%d" % (process["host"].lower(), image_token(image), process["pid"])
        candidate, suffix = fact_id, 2
        while candidate in used:
            candidate, suffix = "%s.%d" % (fact_id, suffix), suffix + 1
        used.add(candidate)
        groups = {}
        for position, record, _ in members:
            groups.setdefault(group_key(record), []).append(position)
        first, last = members[0][1].get("@timestamp"), members[-1][1].get("@timestamp")
        ordered = sorted(groups.items(), key=lambda item: min(item[1]))
        facts.append({
            "fact_id": candidate, "kind": "attack",
            "evidence_event_groups": [[event_id(position) for position in sorted(group)] for _, group in ordered],
            "evidence_sibling_groups": [[event_id(position) for position in sorted(siblings.get((id(process), key), ()))]
                                        for key, _ in ordered],
            "entities": {"hosts": [process["host"]], "users": distinct(records, "user", "name"),
                         "processes": distinct(records, "process", "name"),
                         "domains": distinct(records, "dns", "question", "name"), "ips": []},
            "observation": "%s on %s (pid %d, ground-truth process %s): %d publisher-labelled malicious events from %s to %s." % (
                image or "Process with no recorded image", process["host"], process["pid"], process["guid"],
                len(members), first, last),
        })
    return facts


def unparsed_sysmon(record):
    """(ProcessGuid, ECS category) of a Sysmon record winlogbeat's pipeline failed to parse, else None.

    winlogbeat 7.10 rejects FileDeleteDetected (26) as an unexpected event_id and keeps only winlog.event_data,
    so the record has no process or event.category; ECS files Sysmon file deletions (23, 26) under "file"."""
    category = UNPARSED_SYSMON_CATEGORY.get(field(record, "event", "code"))
    guid = field(record, "winlog", "event_data", "ProcessGuid")
    if (category and isinstance(guid, str) and field(record, "winlog", "channel") == SYSMON_CHANNEL
            and not field(record, "event", "category") and not field(record, "process")):
        return guid, category
    return None


def sibling_positions(rows, matcher, assigned, labelled):
    """(process index, group key) -> positions of events that carry no class-1 or class-2 label and belong to exactly
    one fact process: by the rule that assigned its labelled events, unless the event's own process.entity_id names
    another process, or, for a Sysmon file deletion winlogbeat failed to parse, by its own ProcessGuid."""
    hosts = {process["host"].lower() for process, _ in assigned.values()}
    siblings = defaultdict(list)
    for position, (timestamp, host, _, _, line) in enumerate(rows):
        if position in labelled or short_host(host) not in hosts:
            continue
        record = json.loads(line)
        unparsed = unparsed_sysmon(record)
        if unparsed:
            found, key = matcher.by_guid.get((short_host(host), unparsed[0]), []), group_key(record, unparsed[1])
        else:
            own = field(record, "process", "entity_id")
            found = [process for process in matcher.match(record, short_host(host), timestamp)[1]
                     if not own or process["guid"] == own]
            key = group_key(record)
        if len(found) == 1 and id(found[0]) in assigned:
            siblings[id(found[0]), key].append(position)
    return siblings


def build_truth(case_id, rows, class_1, class_1_and_2, processes):
    index = defaultdict(list)
    for position, (_, host, channel, record_id, _) in enumerate(rows):
        index[host, channel, record_id].append(position)

    def positions(keys, name):
        unmatched = sorted(key for key in keys if not index.get(key))
        if unmatched:
            raise ValueError("%d in-window %s labels match no imported event (first: %s)" % (len(unmatched), name, list(unmatched[0])))
        repeated = sorted(key for key in keys if len(index[key]) > 1)
        if repeated:
            raise ValueError("%d in-window %s labels match more than one imported event (first: %s)" % (len(repeated), name, list(repeated[0])))
        return {index[key][0] for key in keys}

    malicious = positions(class_1, "class-1")
    related = positions(class_1_and_2, "class-1-and-2")
    matcher = ProcessMatcher(processes)
    assigned, unassigned, ambiguous = {}, [], []
    for position in sorted(malicious):
        timestamp, host, _, _, line = rows[position]
        record = json.loads(line)
        rule, found = matcher.match(record, short_host(host), timestamp)
        if not found:
            unassigned.append(event_id(position))
        elif len(found) > 1:
            ambiguous.append("%s (%s: %s)" % (event_id(position), rule, ", ".join(process["source"] for process in found)))
        else:
            process = found[0]
            assigned.setdefault(id(process), (process, []))[1].append((position, record, rule))
    if unassigned:
        raise ValueError("%d class-1 labelled events match no ground-truth process (first: %s)" % (len(unassigned), unassigned[0]))
    if ambiguous:
        raise ValueError("%d class-1 labelled events match more than one ground-truth process (first: %s)" % (len(ambiguous), ambiguous[0]))
    truth = {"schema_version": SCHEMA_VERSION, "case_id": case_id, "source": SOURCE, "interpretation_boundary": INTERPRETATION_BOUNDARY,
             "facts": build_facts(assigned, sibling_positions(rows, matcher, assigned, malicious | related)),
             "labels_class_2_event_ids": [event_id(position) for position in sorted(related - malicious)]}
    validate_truth(truth)
    return truth, len(malicious), len(related - malicious)


def prepare_outputs(evidence_dir, truth_dir):
    evidence, operator = Path(evidence_dir).resolve(), Path(truth_dir).resolve()
    if evidence == operator or evidence in operator.parents or operator in evidence.parents:
        raise ValueError("evidence and truth directories must be separate, non-nested paths")
    for path in (Path(evidence_dir), Path(truth_dir)):
        if path.exists() or path.is_symlink():
            raise ValueError("output directory already exists: " + str(path))
    return evidence, operator


def import_case(data_dir, case_id, start, end, evidence_dir, truth_dir, hosts=None, max_events=DEFAULT_MAX_EVENTS):
    if not isinstance(case_id, str) or not CASE_ID_PATTERN.match(case_id):
        raise ValueError("case id must match [a-z0-9-]{3,64}")
    if type(max_events) is not int or max_events < 1:
        raise ValueError("--max-events must be a positive integer")
    start_ns, end_ns = parse_time(start), parse_time(end)
    if start_ns >= end_ns:
        raise ValueError("--start must be earlier than --end")
    if hosts is not None:
        hosts = {short_host(host.strip()) for host in hosts if host.strip()}
        if not hosts:
            raise ValueError("--hosts names no host")
    data_dir = Path(data_dir)
    evidence, operator = prepare_outputs(evidence_dir, truth_dir)

    rows, matched, members, outside = scan_events(data_dir, start_ns, end_ns, hosts, max_events)
    if not rows:
        raise ValueError("no records match the window and hosts")
    class_1 = read_labels(data_dir, LABELS_CLASS_1, start_ns, end_ns, hosts)
    class_1_and_2 = read_labels(data_dir, LABELS_CLASS_1_AND_2, start_ns, end_ns, hosts)
    truth, malicious, related = build_truth(case_id, rows, class_1, class_1_and_2, read_ground_truth(data_dir))

    created = []
    written = []
    files = {}

    def record_file(path, size, digest):
        files[path.name] = {"path": str(path), "bytes": size, "sha256": digest}

    def write_file(path, data):
        with path.open("xb") as handle:
            written.append(path)
            handle.write(data)
        record_file(path, len(data), hashlib.sha256(data).hexdigest())

    try:
        for path in (evidence, operator):
            path.mkdir(parents=True)
            created.append(path)
        path = evidence / "events.jsonl"
        digest, size, channels, versions, host_names = hashlib.sha256(), 0, set(), set(), set()
        with path.open("xb") as handle:
            written.append(path)
            chunk = []
            for position, (_, host, channel, _, line) in enumerate(rows):
                record = json.loads(line)
                event = record.setdefault("event", {})
                if not isinstance(event, dict):
                    raise ValueError("record %s has a non-object event field" % event_id(position))
                event["id"] = event_id(position)
                event["dataset"] = case_id
                if channel:
                    channels.add(channel)
                if field(record, "agent", "type") == "winlogbeat" and isinstance(field(record, "agent", "version"), str):
                    versions.add(record["agent"]["version"])
                host_names.add(host.split(".", 1)[0])
                text = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
                try:
                    chunk.append((text + "\n").encode("utf-8"))
                except UnicodeEncodeError:
                    raise ValueError("record %s holds text that is not valid UTF-8" % event_id(position)) from None
                if len(chunk) >= 5000:
                    data = b"".join(chunk)
                    handle.write(data)
                    digest.update(data)
                    size += len(data)
                    chunk = []
            data = b"".join(chunk)
            handle.write(data)
            digest.update(data)
            size += len(data)
        record_file(path, size, digest.hexdigest())
        host_count = len({name.lower() for name in host_names})
        coverage = COVERAGE % ((" " + "/".join(sorted(versions))) if versions else "",
                               "channels: " + ", ".join(sorted(channels)), host_count, len(rows))
        write_file(operator / "truth.json", json_bytes(truth))
        write_file(evidence / "case.json", json_bytes({
            "schema_version": SCHEMA_VERSION, "case_id": case_id, "question": QUESTION,
            "time_range_utc": {"start_inclusive": format_time(start_ns), "end_exclusive": format_time(end_ns)},
            "network_capture": "none",
            # Real lab telemetry from a public dataset: lab-input exports it only with operator approval.
            "data_origin": "public-dataset",
            "sources": [{"artifact": "events.jsonl", "coverage": coverage}],
        }))
    except BaseException:
        for path in written:
            path.unlink(missing_ok=True)
        for path in reversed(created):
            try:
                path.rmdir()
            except OSError:
                pass
        raise

    return {
        "schema_version": SCHEMA_VERSION, "case_id": case_id,
        "time_range_utc": {"start_inclusive": format_time(start_ns), "end_exclusive": format_time(end_ns)},
        "event_count": len(rows), "hosts": sorted(host_names), "winlogbeat_members_read": members,
        "host_records_outside_member_hour": outside,
        "facts": len(truth["facts"]), "class_1_labelled": malicious, "class_2_labelled": related,
        "files": files,
    }


def main(argv=None):
    class JsonParser(argparse.ArgumentParser):
        def error(self, message):
            raise ValueError(message)

    parser = JsonParser(prog="python -m hunt_lab.import_dedale", description=__doc__,
                        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--data-dir", required=True)
    parser.add_argument("--case-id", required=True)
    parser.add_argument("--start", required=True)
    parser.add_argument("--end", required=True)
    parser.add_argument("--hosts", help="comma-separated short host names, e.g. CLIENT1,CLIENT2 (default: all hosts present)")
    parser.add_argument("--evidence-dir", required=True)
    parser.add_argument("--truth-dir", required=True)
    parser.add_argument("--max-events", type=int, default=DEFAULT_MAX_EVENTS)
    try:
        args = parser.parse_args(argv)
        hosts = args.hosts.split(",") if args.hosts is not None else None
        result = import_case(args.data_dir, args.case_id, args.start, args.end, args.evidence_dir, args.truth_dir,
                             hosts, args.max_events)
    except (OSError, ValueError, zipfile.BadZipFile, EOFError) as error:
        print(json.dumps({"error": str(error)}, sort_keys=True))
        return 2
    print(json.dumps(result, sort_keys=True, allow_nan=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())

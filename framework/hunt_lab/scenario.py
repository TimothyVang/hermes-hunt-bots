#!/usr/bin/env python3
"""Deterministic invented hunt scenario at lab scale; standard library only.

CLI (run from framework/):
  python -m hunt_lab.scenario generate --size medium|large --seed INT --case-id ID \
      --evidence-dir DIR --truth-dir DIR
  python -m hunt_lab.scenario score --truth DIR/truth.json REPORT [REPORT ...]

generate writes, into a new or empty evidence directory, events.jsonl (ECS rows,
event.id evt-NNNNNN in time order, event.dataset == case id), traffic.pcap
(classic pcap, Ethernet/IPv4: DNS, NTP, TLS ClientHello/opaque records,
plaintext HTTP, payload-free SMB/WinRM/RDP sessions), intel.jsonl (synthetic
indicators carrying case_id) and case.json; and, into a separate new or empty
truth directory, the operator-only truth.json. Directories must be disjoint
(not nested); no existing file is ever overwritten. A JSON summary (counts by
family, hosts, sessions, facts, sha256 per file) is printed on stdout.

Sizes: medium = 25 hosts, 2 hours, ~20k events; large = 100 hosts, 6 hours,
~200k events. Output is byte-identical for the same size, seed, case id and
Python version (random.Random is the only entropy source).

Everything is invented: internal 10.0.0.0/8, external 192.0.2.0/24,
198.51.100.0/24 and 203.0.113.0/24, names under .example/.test/.invalid.
Command lines describe behavior with placeholders; nothing is functional.

score reads one or more final incident handoff JSON reports (strict JSON, or a
single fenced ```json block) with claims[].statement / evidence_ids /
entity_ids and limitations[]. A fact counts as found when the citations cover
every evidence_event_groups entry (at least one per group) AND the text names
at least one of the fact's entities. A group is cited by one of its evt-IDs or,
when the key lists them (evidence_frame_groups / evidence_intel_groups, same
length as the event groups), by one of its capture frames written frame-<n>
(tshark frame.number of a packet of that group's sessions) or one of its intel
record IDs (ioc-NNNNN: a domain/IP record for an indicator of the fact that
those sessions carry, listed only in the first such group of the fact). Keys
without these lists score on event IDs alone. When the key also lists
evidence_sibling_groups (generate writes them for attack facts: the other events
of an attack-lineage process with the same process.entity_id and event.category
as one of the group's events; never an event any fact's groups accept, and never
one that would sit beside two groups), every report also gets a with_siblings
score in which those events cite their group too. The top-level found, by_kind
and decoys_cleared stay strict.
Citations and names are taken from claims; coverage facts also accept
limitations. A decoy fact is flagged misattributed when a claim names one of
its distinctive entities with compromise/malicious language and no benign
qualifier. This is keyword and citation matching, not human judgment of
analytic quality.
"""

import argparse
from bisect import bisect
from collections import Counter
from datetime import datetime, timezone
import base64
import hashlib
import heapq
import json
from pathlib import Path
import random
import re
import struct
import sys
import uuid


SCHEMA_VERSION = 1
CASE_ID_PATTERN = re.compile(r"^[a-z0-9-]{3,64}$")
DAY = datetime(2025, 10, 14, tzinfo=timezone.utc)
DAY_SECONDS = int(DAY.timestamp())
DAY_TEXT = DAY.strftime("%Y-%m-%d")
ID_PLACEHOLDER = '"evt-??????"'
ECS_VERSION = "8.11.0"

ORG = "QUORVANE"
ZONE = "quorvane.example"
RESOLVER = "10.10.0.10"
DC_NAME = "dc-01"
SCANNER = "10.10.5.20"
GATEWAY_MAC = bytes.fromhex("0200000000fe")

PORTAL = "portal." + ZONE
LOOKALIKE = "portal.quorvame.test"
LOOKALIKE_IP = "203.0.113.45"
C2 = "api.nimbus-telemetry.test"
C2_IP = "203.0.113.77"
EXFIL_ZONE = "t.relay-dnsmetrics.test"
EXFIL_QUERIES = 900
UPDATER = "update.tallyworks.example"
AV_DEFS = "defs.aegisfort.example"
BACKUP = "vault.coldstore-backup.example"
BACKUP_IP = "203.0.113.140"
OS_UPDATES = "dl.osvendor-updates.example"
CHAT = "chat.huddlehub.example"
PRINT_DRIVERS = "drivers.printvendor.example"
FIXED_EXTERNAL = {
    LOOKALIKE: LOOKALIKE_IP, C2: C2_IP, UPDATER: "198.51.100.23",
    AV_DEFS: "192.0.2.88", BACKUP: BACKUP_IP, OS_UPDATES: "198.51.100.61",
    CHAT: "192.0.2.140", PRINT_DRIVERS: "198.51.100.150",
}
ALLOWED_SUFFIXES = (".example", ".test", ".invalid")

SEC = "lab.windows.security"
SYSMON = "lab.windows.sysmon"
PROXY = "lab.proxy"
COVERAGE = "lab.coverage"
SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"

WINDOWS_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) LabBrowser/118.0"
PS_UA = "Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1"

SERVERS = {
    "srv-files-01": ("10.10.1.11", "files", True),
    "srv-files-02": ("10.10.1.12", "files", True),
    "srv-files-03": ("10.10.1.13", "files", True),
    "srv-files-04": ("10.10.1.14", "files", True),
    "srv-app-01": ("10.10.1.30", "app", True),
    "srv-app-02": ("10.10.1.31", "app", True),
    "srv-app-03": ("10.10.1.32", "app", True),
    "srv-app-04": ("10.10.1.33", "app", True),
    "srv-print-01": ("10.10.1.40", "print", False),
    "srv-db-01": ("10.10.1.50", "db", True),
    "srv-web-01": ("10.10.1.60", "web", True),
    "srv-mon-01": ("10.10.1.70", "mon", True),
}
INTERNAL_APPS = (("portal", "srv-app-01"), ("hr", "srv-app-02"), ("erp", "srv-app-03"))
DEPARTMENTS = {"it": 1, "fin": 2, "ops": 3, "hr": 4, "sales": 5, "eng": 6}


def hms(hours, minutes=0, seconds=0):
    return ((hours * 60 + minutes) * 60 + seconds) * 1000


SIZES = {
    # Test-only size: same storyline and window as medium, few hosts, low noise.
    "tiny": {"start": hms(4, 30), "hours": 2,
             "servers": ("srv-files-01", "srv-files-02", "srv-app-01", "srv-print-01"),
             "workstations": {"it": (1, 2), "fin": (6, 7), "ops": (3, 4)},
             "bg": 0.2, "user": 0.2, "sites": 30, "intel_noise": 40, "backup": ("srv-files-01",)},
    "medium": {"start": hms(4, 30), "hours": 2,
               "servers": ("srv-files-01", "srv-files-02", "srv-app-01", "srv-print-01"),
               "workstations": {"it": range(1, 3), "fin": range(1, 8), "ops": range(1, 6),
                                "hr": range(1, 4), "sales": range(1, 5)},
               "bg": 4.4, "user": 2.0, "sites": 120, "intel_noise": 300, "backup": ("srv-files-01",)},
    "large": {"start": hms(2, 0), "hours": 6,
              "servers": tuple(SERVERS),
              "workstations": {"it": range(1, 7), "fin": range(1, 17), "ops": range(1, 21),
                               "hr": range(1, 9), "sales": range(1, 19), "eng": range(1, 21)},
              "bg": 3.4, "user": 1.7, "sites": 320, "intel_noise": 1500,
              "backup": ("srv-files-01", "srv-files-03", "srv-db-01")},
}
PUBLIC_SIZES = ("medium", "large")

SURNAMES = ("ashby", "brindle", "corrow", "dunmere", "ellery", "fenwick", "galloway", "hartsell",
            "ivers", "jessop", "lowrie", "marlow", "norcott", "oakes", "pelham", "quill",
            "rowntree", "selwyn", "tallis", "upworth", "vantrell", "wexley", "yardley", "zorvan",
            "amberly", "blakemore", "carrow", "delaine", "eastwick", "farrant", "grimsby", "holloway",
            "ingram", "kettering", "linwood", "merriot", "nettleford", "orrin", "prestwick", "renshaw")
FIXED_USERS = {"wks-it-01": "t.halvorsen", "wks-it-02": "j.kestrel",
               "wks-fin-07": "r.ashgrove", "wks-ops-03": "m.thornvale"}
WORDS_A = ("news", "weather", "travel", "market", "recipe", "garden", "sports", "ledger", "cloud",
           "photo", "learn", "jobs", "maps", "video", "shop", "forum", "wiki", "music", "health", "auto")
WORDS_B = ("harbor", "summit", "river", "maple", "cedar", "atlas", "nova", "pixel", "orbit", "meadow",
           "ember", "quartz", "lumen", "cobalt", "willow", "granite", "sable", "tidal", "aurora", "vertex")

BG_PROCS = (
    ("svchost.exe", r"C:\Windows\System32\svchost.exe", r"C:\Windows\system32\svchost.exe -k netsvcs -p -s BITS", "services", "SYSTEM"),
    ("conhost.exe", r"C:\Windows\System32\conhost.exe", r"\??\C:\Windows\system32\conhost.exe 0xffffffff -ForceV1", "sched", "SYSTEM"),
    ("taskhostw.exe", r"C:\Windows\System32\taskhostw.exe", "taskhostw.exe", "sched", "SYSTEM"),
    ("WmiPrvSE.exe", r"C:\Windows\System32\wbem\WmiPrvSE.exe", r"C:\Windows\system32\wbem\wmiprvse.exe -secured -Embedding", "dcom", "NETWORK SERVICE"),
    ("dllhost.exe", r"C:\Windows\System32\dllhost.exe", r"C:\Windows\system32\DllHost.exe /Processid:{AB8902B4-09CA-4BB6-B78D-A8F59079A8D5}", "dcom", "SYSTEM"),
    ("SearchProtocolHost.exe", r"C:\Windows\System32\SearchProtocolHost.exe", r"C:\Windows\system32\SearchProtocolHost.exe Global\UsGthrFltPipeMssGthrPipe1", "services", "SYSTEM"),
    ("backgroundTaskHost.exe", r"C:\Windows\System32\backgroundTaskHost.exe", r"C:\Windows\system32\backgroundTaskHost.exe -ServerName:BackgroundTaskHost.WebAccountProvider", "dcom", "SYSTEM"),
    ("sppsvc.exe", r"C:\Windows\System32\sppsvc.exe", r"C:\Windows\system32\sppsvc.exe", "services", "NETWORK SERVICE"),
    ("afavscan.exe", r"C:\Program Files\Aegisfort\afavscan.exe", r'"C:\Program Files\Aegisfort\afavscan.exe" --quick --scheduled', "av", "SYSTEM"),
    ("gpupdate.exe", r"C:\Windows\System32\gpupdate.exe", "gpupdate.exe /target:computer", "sched", "SYSTEM"),
)
ATTACHMENTS = (("Q3_forecast.xlsx", "EXCEL.EXE"), ("Shift_roster.pdf", "pdfview.exe"),
               ("Meeting_notes.docx", "WINWORD.EXE"), ("Invoice_4471.pdf", "pdfview.exe"),
               ("Vendor_rates.xlsx", "EXCEL.EXE"), ("Policy_update.docx", "WINWORD.EXE"),
               ("Budget_rollup_v2.xlsm", "EXCEL.EXE"), ("Route_changes.docx", "WINWORD.EXE"))
APP_PATHS = {
    "WINWORD.EXE": r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
    "EXCEL.EXE": r"C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE",
    "OUTLOOK.EXE": r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE",
    "pdfview.exe": r"C:\Program Files\LumenPDF\pdfview.exe",
    "msedge.exe": r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    "huddle.exe": r"C:\Program Files\HuddleHub\huddle.exe",
    "notepad.exe": r"C:\Windows\System32\notepad.exe",
    "powershell.exe": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    "cmd.exe": r"C:\Windows\System32\cmd.exe",
    "mstsc.exe": r"C:\Windows\System32\mstsc.exe",
    "splwow64.exe": r"C:\Windows\splwow64.exe",
    "explorer.exe": r"C:\Windows\explorer.exe",
    "userinit.exe": r"C:\Windows\System32\userinit.exe",
    "schtasks.exe": r"C:\Windows\System32\schtasks.exe",
    "wsmprovhost.exe": r"C:\Windows\System32\wsmprovhost.exe",
    "sc.exe": r"C:\Windows\System32\sc.exe",
    "quser.exe": r"C:\Windows\System32\quser.exe",
}
TLS_PROFILES = {
    "browser": ((0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8),
                (b"h2", b"http/1.1"), (0x001D, 0x0017, 0x0018)),
    "schannel": ((0x1302, 0x1301, 0xC02C, 0xC02B, 0xC030, 0xC02F), (), (0x001D, 0x0017)),
    "agent": ((0x1301, 0x1303, 0xC02F, 0xC030), (b"http/1.1",), (0x001D,)),
}

COVERAGE_GAPS = (
    ("script", "PowerShell script block and module logging (event IDs 4103/4104) is not collected on any host; process command lines are the only record of script invocation."),
    ("dc", "Domain controller security logs, including Kerberos ticket and account-management events, are not collected; dc-01 (10.10.0.10) appears only as the DNS and NTP peer."),
    ("mail", "Mail gateway and mailbox audit logs are not collected; message senders, delivery and attachment origin are visible only through endpoint file-create and process records."),
    ("inbound", "Sysmon network-connect rules record outbound connections only; inbound connections are visible only in the packet capture and in Security logon records."),
    ("print", "srv-print-01 has no Sysmon agent; only its Security log is collected, although its traffic appears in the packet capture."),
    ("tls", "The packet capture holds no decrypted TLS content; HTTPS URL paths, methods and byte counts come only from the egress gateway access records, which cover internet-bound traffic only."),
    ("prior", "Records begin at the window start; logon sessions and processes that started earlier have no creation records in this case."),
    ("files", "Sysmon process-access rules record access to lsass.exe only; file-create rules cover user profile, ProgramData, Temp and Program Files paths only; file reads, deletions and share-level file access auditing (event IDs 5140/5145) are not collected."),
    ("capture", "The capture omits Kerberos, LDAP and RPC traffic to the domain controller and is taken at the core switch; host-local traffic is not captured."),
)

STORY_A = {
    "org": ORG, "zone": ZONE, "resolver": RESOLVER, "dc": DC_NAME, "servers": SERVERS, "apps": INTERNAL_APPS,
    "ws_name": "wks-%s-%02d", "ws_ip": "10.20.%d.%d", "departments": DEPARTMENTS, "fixed_users": FIXED_USERS,
    "surnames": SURNAMES, "admin_depts": ("it", "fin"), "prelogged_depts": ("it",), "prelogged_hosts": ("wks-ops-03",),
    "night_dept": "ops", "share": ("fin", "srv-files-02"), "macro_dept": "fin", "external": FIXED_EXTERNAL,
    "attachments": ATTACHMENTS, "coverage": COVERAGE_GAPS, "bg_procs": BG_PROCS,
    "sys_files": (r"C:\Windows\Temp\%08x.tmp", r"C:\ProgramData\Aegisfort\Quarantine\idx-%08x.dat",
                  r"C:\Windows\Temp\WinRM-%08x.log", r"C:\ProgramData\Package Cache\%08x.tmp"),
    "av": {"name": "afavsvc.exe", "exe": r"C:\Program Files\Aegisfort\afavsvc.exe",
           "log": r"C:\ProgramData\Aegisfort\Logs\scan-%06x.log", "domain": AV_DEFS, "path": "/defs/v2/delta-%d.bin",
           "file": r"C:\ProgramData\Aegisfort\Defs\delta-%d.vdb", "agent": "Aegisfort-Defs/2.0", "access": "0x1000"},
    "updater": {"name": "twupdate.exe", "exe": r"C:\Program Files\Tallyworks\Updater\twupdate.exe", "version": "4.2.0",
                "domain": UPDATER, "manifest": "/v3/manifest?channel=stable&ver=4.2.0",
                "package": "/v3/pkg/twupdate-4.2.1.bin", "agent": "Tallyworks-Updater/4.2",
                "new": r"C:\Program Files\Tallyworks\Updater\twupdate.new", "task": r"\Tallyworks\UpdateCheck"},
}


def iso(ms):
    seconds, milli = divmod(ms, 1000)
    hours, rest = divmod(seconds, 3600)
    minutes, sec = divmod(rest, 60)
    return "%sT%02d:%02d:%02d.%03dZ" % (DAY_TEXT, hours, minutes, sec, milli)


def clock(ms):
    seconds = ms // 1000
    return "%02d:%02d:%02d" % (seconds // 3600, seconds // 60 % 60, seconds % 60)


def fake_sha256(*parts):
    return hashlib.sha256(("lab-binary:" + "|".join(parts)).encode("utf-8")).hexdigest().upper()


SYNCHOST_PATH = r"C:\Users\r.ashgrove\AppData\Roaming\SyncHelper\synchost.exe"
SYNCHOST_SHA256 = fake_sha256(SYNCHOST_PATH, "viewer_update")


def checksum(data):
    """RFC 1071 ones' complement checksum computed via 2**16 == 1 (mod 65535)."""
    if len(data) % 2:
        data += b"\x00"
    number = int.from_bytes(data, "big")
    total = number % 65535
    if total == 0 and number:
        total = 65535
    return ~total & 0xFFFF


def packed_ip(address, cache={}):
    value = cache.get(address)
    if value is None:
        value = cache[address] = bytes(int(part) for part in address.split("."))
    return value


def is_internal(address):
    return address.startswith("10.")


def mac_for(address):
    return b"\x02\x00" + packed_ip(address) if is_internal(address) else GATEWAY_MAC


def dns_name(name):
    return b"".join(bytes([len(part)]) + part.encode("ascii") for part in name.split(".")) + b"\x00"


def client_hello(sni, profile, random_bytes, session_id, key):
    ciphers, alpn, groups = TLS_PROFILES[profile]

    def extension(kind, data):
        return struct.pack("!HH", kind, len(data)) + data

    name = sni.encode("ascii")
    group_bytes = b"".join(struct.pack("!H", group) for group in groups)
    signatures = b"".join(struct.pack("!H", value) for value in
                         (0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601))
    extensions = extension(0, struct.pack("!HBH", len(name) + 3, 0, len(name)) + name)
    extensions += extension(10, struct.pack("!H", len(group_bytes)) + group_bytes)
    extensions += extension(11, b"\x01\x00")
    extensions += extension(13, struct.pack("!H", len(signatures)) + signatures)
    if alpn:
        protocols = b"".join(bytes([len(item)]) + item for item in alpn)
        extensions += extension(16, struct.pack("!H", len(protocols)) + protocols)
    extensions += extension(43, b"\x04\x03\x04\x03\x03")
    extensions += extension(45, b"\x01\x01")
    extensions += extension(51, struct.pack("!HHH", 36, 0x001D, 32) + key)
    cipher_bytes = b"".join(struct.pack("!H", cipher) for cipher in ciphers)
    body = (b"\x03\x03" + random_bytes + bytes([len(session_id)]) + session_id
            + struct.pack("!H", len(cipher_bytes)) + cipher_bytes + b"\x01\x00"
            + struct.pack("!H", len(extensions)) + extensions)
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


def server_hello(random_bytes, session_id, key):
    extensions = struct.pack("!HHH", 43, 2, 0x0304) + struct.pack("!HHHH", 51, 36, 0x001D, 32) + key
    body = (b"\x03\x03" + random_bytes + bytes([len(session_id)]) + session_id + b"\x13\x01\x00"
            + struct.pack("!H", len(extensions)) + extensions)
    handshake = b"\x02" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x03" + struct.pack("!H", len(handshake)) + handshake + b"\x14\x03\x03\x00\x01\x01"


def http_request(method, host, path, user_agent, body_length):
    text = "%s %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nAccept: */*\r\nConnection: close\r\n" % (
        method, path, host, user_agent)
    if body_length:
        text += "Content-Type: application/octet-stream\r\nContent-Length: %d\r\n" % body_length
    return (text + "\r\n").encode("ascii")


REASONS = {200: "OK", 201: "Created", 204: "No Content", 302: "Found", 304: "Not Modified", 404: "Not Found"}


def http_response_head(status, body_length):
    text = "HTTP/1.1 %d %s\r\nServer: lab-httpd\r\nContent-Type: text/html\r\nContent-Length: %d\r\nConnection: close\r\n\r\n" % (
        status, REASONS[status], body_length)
    return text.encode("ascii")


FILLER = b"<p>Invented lab page content for defensive training only.</p>\n" * 64


def session_indicators(session):
    """Lowercased endpoint addresses and the DNS name, TLS SNI or HTTP Host a session spec carries."""
    _, _, kind, client, _, server, _, _, data = session
    values = {client, server}
    if kind in ("dns", "tls"):
        values.add(data[0].lower())
    elif kind == "http":
        values.add(re.search(rb"\r\nHost: ([^\r]+)\r\n", data[0]).group(1).decode("ascii").lower())
    return values


class Host:
    __slots__ = ("name", "ip", "kind", "role", "dept", "sysmon", "user", "admin", "port", "procs",
                 "ecs", "prelogged", "logon", "logoff", "fqdn")


class Scenario:
    """Builds rows, packet session specs and truth tags fully in memory-light form."""

    ENV = STORY_A
    SIZE_TABLE = SIZES

    def __init__(self, size, seed, case_id):
        profile = self.SIZE_TABLE[size]
        self.env = self.ENV
        self.size, self.seed, self.case_id = size, seed, case_id
        self.rng = random.Random(seed)
        self.start = profile["start"]
        self.end = profile["start"] + profile["hours"] * 3600 * 1000
        self.bg_scale = profile["bg"]
        self.user_scale = profile["user"]
        self.intel_noise = profile["intel_noise"]
        self.backup_hosts = profile["backup"]
        self.rows = []
        self.sessions = []
        self.session_of = {}
        self.tags = {}
        self.group_tags = {}
        self.process_events = {}
        self.started = {}
        self.family = Counter()
        self.used_external = set()
        self.ip_of = {}
        self.chain = {}
        self.dns_cache = {}
        self.hosts = []
        self.by_name = {}
        self._build_hosts(profile)
        self._build_sites(profile["sites"])

    # ----- primitives -------------------------------------------------
    def _build_hosts(self, profile):
        rng = self.rng
        env = self.env
        for name in profile["servers"]:
            address, role, sysmon = env["servers"][name]
            self._add_host(name, address, "server", role, None, sysmon)
        fixed = env["fixed_users"]
        used_users = set(fixed.values())
        for dept, numbers in profile["workstations"].items():
            for number in numbers:
                name = env["ws_name"] % (dept, number)
                host = self._add_host(name, env["ws_ip"] % (env["departments"][dept], 100 + number),
                                      "workstation", dept, dept, True)
                user = fixed.get(name)
                while user is None or (user in used_users and name not in fixed):
                    user = "%s.%s" % ("abcdefghjklmnprstvw"[rng.randrange(19)], rng.choice(env["surnames"]))
                used_users.add(user)
                host.user = user
                host.admin = dept in env["admin_depts"] or rng.random() < 0.15
        self.ip_of[env["dc"] + "." + env["zone"]] = env["resolver"]
        for label, server in env["apps"]:
            if server in self.by_name:
                self.ip_of[label + "." + env["zone"]] = self.by_name[server].ip

    def _add_host(self, name, address, kind, role, dept, sysmon):
        host = Host()
        host.name, host.ip, host.kind, host.role, host.dept, host.sysmon = name, address, kind, role, dept, sysmon
        host.user, host.admin, host.prelogged, host.logon, host.logoff = None, False, False, None, None
        host.port = 49152 + self.rng.randrange(4000)
        host.fqdn = name + "." + self.env["zone"]
        host.ecs = {"name": name, "ip": [address], "os": {"type": "windows", "name": "Windows (synthetic)"}}
        host.procs = {}
        self.hosts.append(host)
        self.by_name[name] = host
        self.ip_of[host.fqdn] = address
        return host

    def _build_sites(self, count):
        rng = self.rng
        combos = [(a, b) for a in WORDS_A for b in WORDS_B]
        chosen = rng.sample(combos, count)
        self.sites = []
        for index, (first, second) in enumerate(chosen):
            domain = (first + second if index % 2 else first + "-" + second) + (".test" if index % 3 == 0 else ".example")
            self.sites.append((domain, rng.random() < 0.88))
        total = 0.0
        self.site_weights = []
        for rank in range(count):
            total += 1.0 / (rank + 1) ** 0.9
            self.site_weights.append(total)
        reserved = set(self.env["external"].values()) | set(self.env.get("reserved", ()))
        self.external_pool = [prefix + str(last) for prefix in ("192.0.2.", "198.51.100.", "203.0.113.")
                              for last in range(1, 255) if prefix + str(last) not in reserved]

    def resolve(self, name):
        address = self.ip_of.get(name) or self.env["external"].get(name)
        if address is None:
            digest = int(hashlib.sha256(name.encode("ascii")).hexdigest()[:12], 16)
            address = self.external_pool[digest % len(self.external_pool)]
            self.ip_of[name] = address
        if not is_internal(address):
            self.used_external.add(address)
        return address

    def pick_site(self):
        point = self.rng.random() * self.site_weights[-1]
        return self.sites[min(bisect(self.site_weights, point), len(self.sites) - 1)]

    def times(self, per_hour, start, end, scale):
        rate = per_hour * scale / 3600000.0
        end = min(end, self.end - 10000)
        out = []
        if rate <= 0 or start >= end:
            return out
        moment = float(start)
        while True:
            moment += self.rng.expovariate(rate)
            if moment >= end:
                return out
            out.append(int(moment))

    def periodic(self, start, end, period, jitter):
        out = []
        end = min(end, self.end - 10000)
        moment = start + self.rng.randrange(period)
        while moment < end:
            out.append(moment)
            moment += period + self.rng.randint(-jitter, jitter)
        return out

    def port(self, host):
        host.port += self.rng.randint(1, 9)
        if host.port > 65000:
            host.port = 49152 + self.rng.randrange(1000)
        return host.port

    def guid(self):
        return "{%s}" % str(uuid.UUID(int=self.rng.getrandbits(128))).upper()

    def mark(self, tag, seq):
        if seq is not None:
            self.tags.setdefault(tag, []).append(seq)
        return seq

    def link(self, *seqs):
        """Tie events to the packet session appended last, so the key can list that session's frames."""
        for seq in seqs:
            if seq is not None:
                self.session_of[seq] = len(self.sessions) - 1

    def emit(self, ms, host, provider, code, category, kind, action, fields, family,
             outcome=None, channel=None, message=None):
        event = {"id": "evt-??????", "kind": "event", "category": category, "type": kind,
                 "code": code, "dataset": self.case_id, "provider": provider, "action": action}
        if outcome:
            event["outcome"] = outcome
        row = {"@timestamp": iso(ms), "ecs": {"version": ECS_VERSION}, "event": event}
        if host is not None:
            row["host"] = host.ecs
        row.update(fields)
        if channel:
            winlog = dict(row.get("winlog", {}))
            winlog["channel"] = channel
            row["winlog"] = winlog
        if message:
            row["message"] = message
        seq = len(self.rows)
        self.rows.append((ms, seq, json.dumps(row, sort_keys=True)))
        self.family[family] += 1
        entity_id = (fields.get("process") or {}).get("entity_id")
        if entity_id:
            self.process_events.setdefault((entity_id, category[0]), []).append(seq)
        return seq

    # ----- processes ----------------------------------------------------
    def spawn(self, ms, host, name, command, parent, user, executable=None, emit=True, sha=None):
        executable = executable or APP_PATHS.get(name) or ("C:\\Windows\\System32\\" + name)
        process = {"entity_id": self.guid(), "pid": self.rng.randrange(1000, 24000, 4), "name": name,
                   "executable": executable, "user": user}
        seq = None
        if emit and host.sysmon:
            fields = {"process": {
                "entity_id": process["entity_id"], "pid": process["pid"], "name": name,
                "executable": executable, "command_line": command,
                "parent": {"entity_id": parent["entity_id"], "pid": parent["pid"], "name": parent["name"],
                           "executable": parent["executable"]},
                "hash": {"sha256": sha or fake_sha256(executable)}},
                "user": self.user(user)}
            seq = self.emit(ms, host, SYSMON, "1", ["process"], ["start"], "Process Create (rule: ProcessCreate)",
                            fields, "sysmon:1", channel=SYSMON_CHANNEL, message="Process Create")
        if seq is not None:
            self.started[seq] = process["entity_id"]
        process["seq"] = seq
        return process

    def user(self, name):
        domain = "NT AUTHORITY" if name in ("SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE") else self.env["org"]
        return {"name": name, "domain": domain}

    @staticmethod
    def pref(process):
        return {"entity_id": process["entity_id"], "pid": process["pid"], "name": process["name"],
                "executable": process["executable"]}

    def base_processes(self, host):
        procs = host.procs
        procs["system"] = {"entity_id": self.guid(), "pid": 4, "name": "System", "executable": "System", "user": "SYSTEM"}
        for key, name, command in (("lsass", "lsass.exe", None), ("services", "services.exe", None),
                                   ("sched", "svchost.exe", "-k netsvcs -p -s Schedule"),
                                   ("dcom", "svchost.exe", "-k DcomLaunch -p"),
                                   ("time", "svchost.exe", "-k LocalService -s W32Time"),
                                   ("wu", "svchost.exe", "-k netsvcs -p -s wuauserv"),
                                   ("winrm", "svchost.exe", "-k NetworkService -p -s WinRM")):
            procs[key] = self.spawn(0, host, name, command, procs["system"], "SYSTEM", emit=False)
        procs["av"] = self.spawn(0, host, self.env["av"]["name"], None, procs["services"], "SYSTEM",
                                 executable=self.env["av"]["exe"], emit=False)

    def user_processes(self, ms, host, emit):
        user, procs = host.user, host.procs
        if emit:
            init = self.spawn(ms + 400, host, "userinit.exe", r"C:\Windows\system32\userinit.exe", procs["services"], user)
            procs["explorer"] = self.spawn(ms + 900, host, "explorer.exe", r"C:\Windows\Explorer.EXE", init, user)
        else:
            procs["explorer"] = self.spawn(0, host, "explorer.exe", None, procs["services"], user, emit=False)
        explorer = procs["explorer"]
        offset = 4000
        for key, name, command in (("outlook", "OUTLOOK.EXE", '"%s" ' % APP_PATHS["OUTLOOK.EXE"]),
                                   ("browser", "msedge.exe", '"%s" --no-startup-window' % APP_PATHS["msedge.exe"]),
                                   ("chat", "huddle.exe", '"%s" --autostart' % APP_PATHS["huddle.exe"])):
            procs[key] = self.spawn(ms + offset, host, name, command.strip(), explorer, user, emit=emit)
            offset += self.rng.randint(1500, 6000)

    # ----- Security log ----------------------------------------------------
    def logon(self, ms, host, user, logon_type, source_ip=None, auth="Kerberos", privileged=False,
              duration=None, workstation="-"):
        logon_id = "0x%x" % self.rng.getrandbits(36)
        process_name = {"Kerberos": "Kerberos", "NTLM": "NtLmSsp"}.get(auth, "User32" if logon_type in (2, 7, 10, 11) else "Advapi")
        data = {"LogonType": str(logon_type), "TargetLogonId": logon_id, "AuthenticationPackageName": auth,
                "LogonProcessName": process_name, "WorkstationName": workstation}
        fields = {"user": self.user(user), "winlog": {"event_data": data}}
        if source_ip:
            fields["source"] = {"ip": source_ip, "port": self.rng.randint(49152, 65000) if auth != "Kerberos" else 0}
        result = {"logon_id": logon_id, "4624": self.emit(ms, host, SEC, "4624", ["authentication"], ["start"], "logged-in", fields,
                                    "security:4624", outcome="success", channel="Security",
                                    message="An account was successfully logged on.")}
        if privileged:
            result["4672"] = self.emit(ms, host, SEC, "4672", ["iam"], ["admin"], "logged-in-special", {
                "user": self.user(user), "winlog": {"event_data": {
                    "SubjectLogonId": logon_id,
                    "PrivilegeList": "SeBackupPrivilege SeRestorePrivilege SeDebugPrivilege SeImpersonatePrivilege"}}},
                "security:4672", outcome="success", channel="Security",
                message="Special privileges assigned to new logon.")
        if duration is not None and ms + duration < self.end:
            result["4634"] = self.logoff(ms + duration, host, user, logon_type, logon_id)
        return result

    def logoff(self, ms, host, user, logon_type, logon_id):
        return self.emit(ms, host, SEC, "4634", ["authentication"], ["end"], "logged-out", {
            "user": self.user(user), "winlog": {"event_data": {"LogonType": str(logon_type), "TargetLogonId": logon_id}}},
            "security:4634", outcome="success", channel="Security", message="An account was logged off.")

    def failed_logon(self, ms, host, user, logon_type, sub_status, source_ip=None, auth="Negotiate"):
        reason = "%%2309" if sub_status == "0xC0000071" else "%%2313"
        fields = {"user": self.user(user), "winlog": {"event_data": {
            "LogonType": str(logon_type), "Status": "0xC000006D", "SubStatus": sub_status,
            "FailureReason": reason, "AuthenticationPackageName": auth}}}
        if source_ip:
            fields["source"] = {"ip": source_ip, "port": self.rng.randint(49152, 65000)}
        return self.emit(ms, host, SEC, "4625", ["authentication"], ["start"], "logon-failed", fields,
                         "security:4625", outcome="failure", channel="Security",
                         message="An account failed to log on.")

    def task_created(self, ms, host, user, task_name, content):
        return self.emit(ms, host, SEC, "4698", ["configuration"], ["creation"], "scheduled-task-created", {
            "user": self.user(user), "winlog": {"event_data": {"TaskName": task_name, "TaskContent": content}}},
            "security:4698", outcome="success", channel="Security", message="A scheduled task was created.")

    # ----- Sysmon -------------------------------------------------------------
    def file_create(self, ms, host, process, path):
        if not host.sysmon:
            return None
        return self.emit(ms, host, SYSMON, "11", ["file"], ["creation"], "File created (rule: FileCreate)", {
            "process": self.pref(process), "user": self.user(process["user"]),
            "file": {"path": path, "name": path.rsplit("\\", 1)[-1]}},
            "sysmon:11", channel=SYSMON_CHANNEL, message="File created")

    def process_access(self, ms, host, process, target, access):
        return self.emit(ms, host, SYSMON, "10", ["process"], ["access"], "Process accessed (rule: ProcessAccess)", {
            "process": self.pref(process), "user": self.user(process["user"]),
            "winlog": {"event_data": {"TargetImage": target["executable"], "TargetProcessId": str(target["pid"]),
                                      "TargetProcessGuid": target["entity_id"], "GrantedAccess": access}}},
            "sysmon:10", channel=SYSMON_CHANNEL, message="Process accessed")

    def netconn(self, ms, host, process, sport, destination, dport, transport, protocol):
        if not host.sysmon:
            return None
        return self.emit(ms, host, SYSMON, "3", ["network"], ["connection", "start"],
                         "Network connection detected (rule: NetworkConnect)", {
                             "process": self.pref(process), "user": self.user(process["user"]),
                             "source": {"ip": host.ip, "port": sport},
                             "destination": {"ip": destination, "port": dport},
                             "network": {"transport": transport, "protocol": protocol, "direction": "outbound"}},
                         "sysmon:3", channel=SYSMON_CHANNEL, message="Network connection detected")

    def dns(self, ms, host, process, name, qtype="A", answers=None, ttl=300, rcode="NOERROR"):
        """Sysmon 22 (when collected) plus a matching UDP query/response pair."""
        sport = self.port(host)
        if answers is None:
            answers = [] if rcode != "NOERROR" else [self.resolve(name)]
        seq = None
        if host.sysmon:
            seq = self.emit(ms, host, SYSMON, "22", ["network"], ["protocol", "info"], "Dns query (rule: DnsQuery)", {
                "process": self.pref(process), "user": self.user(process["user"]),
                "source": {"ip": host.ip, "port": sport}, "destination": {"ip": self.env["resolver"], "port": 53},
                "network": {"transport": "udp", "protocol": "dns", "direction": "outbound"},
                "dns": {"question": {"name": name, "type": qtype}, "response_code": rcode,
                        "answers": [{"name": name, "type": qtype, "data": value, "ttl": ttl} for value in answers]}},
                "sysmon:22", channel=SYSMON_CHANNEL, message="Dns query")
        delay = 1 if name.endswith("." + self.env["zone"]) else self.rng.randint(3, 40)
        if host.ip == self.env["resolver"]:
            return seq  # The resolver itself answers locally; nothing crosses the capture point.
        self.sessions.append((ms, len(self.sessions), "dns", host.ip, sport, self.env["resolver"], 53, delay,
                              (name, qtype, tuple(answers), rcode, ttl, self.rng.getrandbits(16))))
        self.link(seq)
        return seq

    def web(self, ms, host, process, domain, scheme, method, path, status, request_body, response_body,
            user_agent, profile="browser", proxy=True):
        """Sysmon 3 + egress gateway record + TLS/HTTP session. Returns (conn seq, proxy seq)."""
        destination = self.resolve(domain)
        dport = 443 if scheme == "https" else 80
        sport = self.port(host)
        rtt = 1 if is_internal(destination) else self.rng.randint(12, 45)
        conn = self.netconn(ms, host, process, sport, destination, dport, "tcp", "tls" if dport == 443 else "http")
        if scheme == "https":
            request_bytes, response_bytes = request_body + 420, response_body + 260
            data = (domain, profile, request_bytes, response_bytes)
            self.sessions.append((ms, len(self.sessions), "tls", host.ip, sport, destination, dport, rtt, data))
        else:
            request = http_request(method, domain, path, user_agent, request_body)
            head = http_response_head(status, response_body)
            request_bytes, response_bytes = len(request) + request_body, len(head) + response_body
            self.sessions.append((ms, len(self.sessions), "http", host.ip, sport, destination, dport, rtt,
                                  (request, request_body, head, response_body)))
        record = None
        if proxy:
            fields = {"source": {"ip": host.ip, "port": sport}, "destination": {"ip": destination, "port": dport},
                      "url": {"domain": domain, "full": "%s://%s%s" % (scheme, domain, path), "path": path.split("?")[0],
                              "scheme": scheme},
                      "http": {"request": {"method": method, "bytes": request_bytes},
                               "response": {"status_code": status, "bytes": response_bytes}},
                      "user_agent": {"original": user_agent},
                      "network": {"transport": "tcp", "protocol": "tls" if scheme == "https" else "http",
                                  "direction": "outbound"},
                      "observer": {"name": "egress-gw-01", "type": "proxy"}}
            if scheme == "https":
                fields["tls"] = {"server_name": domain}
            record = self.emit(ms + 2 * rtt + 1, host, PROXY, "access", ["network", "web"], ["access", "connection"],
                               "http-request", fields, "proxy:access",
                               outcome="success" if status < 400 else "failure",
                               message="%s %s://%s%s %d" % (method, scheme, domain, path, status))
        self.link(conn, record)
        return conn, record

    def bare(self, ms, host, process, destination, dport, duration, protocol, emit=True):
        """Payload-free TCP session (SMB/WinRM/RDP); Sysmon 3 on the client when collected."""
        sport = self.port(host)
        duration = max(5, min(duration, self.end - ms - 3000))
        conn = self.netconn(ms, host, process, sport, destination, dport, "tcp", protocol) if emit else None
        self.sessions.append((ms, len(self.sessions), "bare", host.ip, sport, destination, dport, 1, duration))
        self.link(conn)
        return conn

    # ----- background --------------------------------------------------------
    def background(self, host):
        rng, scale, start, end = self.rng, self.bg_scale, self.start, self.end
        procs, av = host.procs, self.env["av"]
        for ms in self.times(6, start, end, scale):
            self.logon(ms, host, "SYSTEM", 5, auth="Negotiate", privileged=True,
                       duration=rng.randint(500, 9000) if rng.random() < 0.4 else None)
        for ms in self.times(22, start, end, scale):
            name, executable, command, parent, user = rng.choice(self.env["bg_procs"])
            parent_proc = procs["av"] if parent == "av" else procs[parent]
            child = self.spawn(ms, host, name, command, parent_proc, user, executable=executable)
            if parent == "av":
                self.file_create(ms + rng.randint(200, 3000), host, child, av["log"] % rng.getrandbits(24))
        for ms in self.times(10, start, end, scale):
            owner = procs[rng.choice(("sched", "wu", "dcom", "av"))]
            path = rng.choice(self.env["sys_files"])
            self.file_create(ms, host, owner, path % rng.getrandbits(32))
        if host.sysmon:
            for ms in self.periodic(start, end, 20 * 60000, 40000):
                self.mark("av.lsass", self.process_access(ms, host, procs["av"], procs["lsass"], av["access"]))
        for ms in self.periodic(start, end, 60 * 60000, 90000):
            serial = rng.randrange(10000, 99999)
            self.dns(ms, host, procs["av"], av["domain"], ttl=600)
            self.web(ms + 4, host, procs["av"], av["domain"], "https", "GET", av["path"] % serial, 200,
                     0, rng.randint(6000, 14000), av["agent"], profile="schannel")
            self.file_create(ms + 900, host, procs["av"], av["file"] % serial)
        if host.role != "dc":
            for ms in self.periodic(start, end, 30 * 60000, 60000):
                sport = 123
                self.netconn(ms, host, procs["time"], sport, self.env["resolver"], 123, "udp", "ntp")
                self.sessions.append((ms, len(self.sessions), "ntp", host.ip, sport, self.env["resolver"], 123, 1, None))
        if host.kind == "workstation":
            self.updater(host)
            for ms in self.times(0.7, start, end, 1.0):
                serial = rng.randrange(100000, 999999)
                self.dns(ms, host, procs["wu"], OS_UPDATES)
                self.web(ms + 5, host, procs["wu"], OS_UPDATES, "http", "GET", "/dl/packages/osupd-%d.cab" % serial,
                         rng.choice((200, 304, 304)), 0, rng.randint(800, 4000), "Windows-Update-Agent/10.0")
        if host.role == "print":
            for ms in self.times(3, start, end, 1.0):
                self.dns(ms, host, procs["sched"], PRINT_DRIVERS)
                self.web(ms + 3, host, procs["sched"], PRINT_DRIVERS, "https", "GET", "/catalog/v1/check", 200,
                         0, rng.randint(900, 3000), "PrintVendor-Agent/3.1", profile="schannel")

    def updater(self, host):
        rng, procs, config = self.rng, host.procs, self.env["updater"]
        exe, name, domain, agent = config["exe"], config["name"], config["domain"], config["agent"]
        sha = fake_sha256(exe, config["version"])
        for ms in self.periodic(self.start, self.end, 600000, 3000):
            run = self.spawn(ms, host, name, '"%s" /check /quiet' % exe, procs["sched"], "SYSTEM", executable=exe, sha=sha)
            self.mark("updater.proc", run["seq"])
            self.mark("updater.dns", self.dns(ms + 120, host, run, domain))
            conn, record = self.web(ms + 125, host, run, domain, "https", "GET", config["manifest"],
                                    304 if rng.random() < 0.9 else 200, 0, rng.randint(200, 900), agent,
                                    profile="schannel")
            self.mark("updater.conn", conn)
            self.mark("updater.proxy", record)
        # Fleet self-update and task re-registration, staggered across workstations.
        ms = hms(5, 5) + self.hosts.index(host) * rng.randint(5000, 9000)
        if self.start <= ms < self.end - 60000:
            run = self.spawn(ms, host, name, '"%s" /selfupdate /channel stable' % exe, procs["sched"], "SYSTEM",
                             executable=exe, sha=sha)
            self.mark("updater.proc", run["seq"])
            self.mark("updater.dns", self.dns(ms + 150, host, run, domain))
            conn, record = self.web(ms + 155, host, run, domain, "https", "GET", config["package"], 200, 0,
                                    rng.randint(90000, 100000), agent, profile="schannel")
            self.mark("updater.conn", conn)
            self.mark("updater.proxy", record)
            self.file_create(ms + 6000, host, run, config["new"])
            self.mark("updater.task", self.task_created(
                ms + 7500, host, "SYSTEM", config["task"],
                "Trigger=Time, repeat every PT10M; Action=%s /check /quiet; RunAs=SYSTEM" % exe))

    # ----- user activity ---------------------------------------------------------
    def user_sessions(self):
        rng = self.rng
        for host in self.hosts:
            if host.kind != "workstation":
                continue
            if host.name in self.fixed_logons:
                host.logon = self.fixed_logons[host.name]
            elif (host.dept in self.env["prelogged_depts"] or host.name in self.env["prelogged_hosts"]
                  or (host.dept == self.env["night_dept"] and rng.random() < 0.5)):
                host.prelogged = True
                night = self.env["night_dept"]
                if host.dept == night and host.name not in self.env["prelogged_hosts"] and rng.random() < 0.6:
                    host.logoff = hms(6, 0) + rng.randrange(40 * 60000)
            else:
                host.logon = hms(5, 25) + rng.randrange(115 * 60000)
            if host.prelogged:
                self.user_processes(0, host, emit=False)
                active = self.start
            elif host.logon < self.end - 60000:
                result = self.logon(host.logon, host, host.user, 2, auth="Negotiate", privileged=host.admin,
                                    workstation=host.name.upper())
                host.procs["session_logon"] = result["4624"]
                self.user_processes(host.logon, host, emit=True)
                active = host.logon + 20000
            else:
                continue
            finish = host.logoff if host.logoff and host.logoff < self.end else self.end
            self.activity(host, active, finish)
            if finish < self.end:
                self.logoff(finish, host, host.user, 2, "0x%x" % rng.getrandbits(36))

    def activity(self, host, start, end):
        rng, scale, procs, user = self.rng, self.user_scale, host.procs, host.user
        for ms in self.times(30, start, end, scale):
            domain, https = self.pick_site()
            self.browse(ms, host, domain, https)
            if rng.random() < 0.55:
                self.browse(ms + rng.randint(80, 400), host, "static." + domain, https, asset=True)
        for ms in self.times(22, start, end, scale):
            choice = rng.random()
            if choice < 0.55:
                self.spawn(ms, host, "msedge.exe", '"%s" --type=renderer --lang=en-US --renderer-client-id=%d' % (
                    APP_PATHS["msedge.exe"], rng.randrange(5, 400)), procs["browser"], user)
            elif choice < 0.75:
                name = rng.choice(("EXCEL.EXE", "WINWORD.EXE"))
                document = r"C:\Users\%s\Documents\%s" % (user, rng.choice(
                    ("weekly_status.docx", "tracker.xlsx", "notes.docx", "inventory.xlsx", "schedule.xlsx")))
                app = self.spawn(ms, host, name, '"%s" "%s"' % (APP_PATHS[name], document), procs["explorer"], user)
                if name == "EXCEL.EXE" and rng.random() < 0.2:
                    later = min(ms + rng.randint(30000, 300000), self.end - 1000)
                    self.spawn(later, host, "splwow64.exe", r"C:\Windows\splwow64.exe 12288", app, user)
            elif choice < 0.85:
                self.spawn(ms, host, "notepad.exe", r'"C:\Windows\system32\notepad.exe" C:\Users\%s\Desktop\todo.txt' % user,
                           procs["explorer"], user)
            elif host.dept == "it":
                self.spawn(ms, host, "powershell.exe", '"%s"' % APP_PATHS["powershell.exe"], procs["explorer"], user)
            else:
                self.spawn(ms, host, "pdfview.exe", '"%s" "C:\\Users\\%s\\Downloads\\guide.pdf"' % (APP_PATHS["pdfview.exe"], user),
                           procs["explorer"], user)
        for ms in self.times(34, start, end, scale):
            choice = rng.random()
            if choice < 0.6:
                path = r"C:\Users\%s\AppData\Local\Microsoft\Edge\User Data\Default\Cache\Cache_Data\f_%06x" % (user, rng.getrandbits(24))
                owner = procs["browser"]
            elif choice < 0.8:
                path = r"C:\Users\%s\AppData\Local\Temp\%08x.tmp" % (user, rng.getrandbits(32))
                owner = procs["explorer"]
            elif choice < 0.9:
                path = r"C:\Users\%s\AppData\Roaming\HuddleHub\cache\msg-%08x.json" % (user, rng.getrandbits(32))
                owner = procs["chat"]
            else:
                path = r"C:\Users\%s\Downloads\%s" % (user, rng.choice(("report.pdf", "form.pdf", "photo.jpg", "agenda.docx")))
                owner = procs["browser"]
            self.file_create(ms, host, owner, path)
        file_servers = [h for h in self.hosts if h.role == "files"]
        for ms in self.times(3, start, end, scale):
            share_dept, share_server = self.env["share"]
            if host.dept == share_dept and share_server in self.by_name and rng.random() < 0.7:
                server = self.by_name[share_server]
            else:
                server = file_servers[0] if rng.random() < 0.6 else rng.choice(file_servers)
            self.smb(ms, host, server, user)
        for ms in self.times(5, start, end, scale):
            app = rng.choice([label for label, server in self.env["apps"] if server in self.by_name])
            name = app + "." + self.env["zone"]
            self.cached_dns(ms, host, procs["browser"], name)
            self.web(ms + 3, host, procs["browser"], name, "https", "GET", "/home", 200, 0, rng.randint(2000, 9000),
                     WINDOWS_UA, proxy=False)
        for ms in self.times(1.2, start, end, scale):
            self.benign_attachment(ms, host)
        for ms in self.times(0.8, start, end, scale):
            result = self.logon(ms, host, user, 7, auth="Negotiate", privileged=host.admin, workstation=host.name.upper())
            if rng.random() < 0.3:
                moment = ms + rng.randint(60000, 900000)
                if moment < self.end:
                    self.logoff(moment, host, user, 7, result["logon_id"])
        for index, ms in enumerate(self.periodic(start, end, 300000, 60000)):
            if index % 3 == 0:
                self.dns(ms, host, procs["chat"], CHAT, ttl=900)
            self.web(ms + 4, host, procs["chat"], CHAT, "https", "POST", "/v1/presence", 204, rng.randint(80, 200), 0,
                     "HuddleHub/5.4", profile="agent")

    def cached_dns(self, ms, host, process, name, ttl=300):
        """Resolve only when this host's cached answer has expired (per-name loops run in time order)."""
        key = (host.name, name)
        if self.dns_cache.get(key, -1) > ms:
            return None
        self.dns_cache[key] = ms + ttl * 1000
        return self.dns(ms, host, process, name, ttl=ttl)

    def browse(self, ms, host, domain, https, asset=False):
        rng = self.rng
        if rng.random() < 0.02:
            self.dns(ms, host, host.procs["browser"], domain.replace(".", "x", 1), rcode="NXDOMAIN")
            return
        self.cached_dns(ms, host, host.procs["browser"], domain)
        if asset:
            path = rng.choice(("/assets/app.%06x.js", "/img/%06x.jpg", "/css/site.%06x.css")) % rng.getrandbits(24)
        else:
            path = rng.choice(("/", "/article/%d" % rng.randrange(1000, 99999), "/api/v1/feed", "/search?q=lab",
                               "/section/%s" % rng.choice(WORDS_A)))
        method = "POST" if not asset and rng.random() < 0.05 else "GET"
        status = rng.choices((200, 304, 404, 302), (85, 8, 3, 4))[0]
        size = 0 if status in (304, 302) else min(int(rng.lognormvariate(7.4, 0.9)), 24000)
        self.web(ms + rng.randint(2, 30), host, host.procs["browser"], domain, "https" if https else "http", method, path,
                 status, rng.randint(40, 600) if method == "POST" else 0, size, WINDOWS_UA)

    def benign_attachment(self, ms, host):
        rng, procs, user = self.rng, host.procs, host.user
        name, app = rng.choice(self.env["attachments"])
        if name.endswith(".xlsm") and host.dept != self.env["macro_dept"]:
            name = self.env["attachments"][0][0]
        path = r"C:\Users\%s\AppData\Local\Microsoft\Windows\INetCache\Content.Outlook\%s\%s" % (
            user, "".join(rng.choice("ABCDEFGHJKLMNPQRSTUVWXYZ0123456789") for _ in range(8)), name)
        self.mark("benign.attachment", self.file_create(ms, host, procs["outlook"], path))
        later = min(ms + rng.randint(5000, 40000), self.end - 1000)
        self.spawn(later, host, app, '"%s" "%s"' % (APP_PATHS[app], path), procs["outlook"], user)

    def smb(self, ms, host, server, user, auth="Kerberos", duration=None):
        duration = duration or self.rng.randint(2000, 90000)
        conn = self.bare(ms, host, host.procs["system"], server.ip, 445, duration, "smb")
        result = self.logon(ms + 3, server, user, 3, source_ip=host.ip, auth=auth, duration=duration,
                            workstation=host.name.upper())
        return conn, result

    def rdp(self, ms, source, target, account, duration):
        mstsc = self.spawn(ms, source, "mstsc.exe", '"%s" /v:%s' % (APP_PATHS["mstsc.exe"], target.fqdn),
                           source.procs["explorer"], source.user)
        self.dns(ms + 300, source, mstsc, target.fqdn)
        conn = self.bare(ms + 310, source, mstsc, target.ip, 3389, duration, "rdp")
        result = self.logon(ms + 2500, target, account, 10, source_ip=source.ip, auth="Kerberos", privileged=True,
                            duration=duration - 3000, workstation=source.name.upper())
        return mstsc, conn, result

    # ----- storyline ----------------------------------------------------------------
    def plan_chain(self):
        self.t0 = hms(5, 48) + self.rng.randint(-90000, 30000)
        self.fixed_logons = {"wks-fin-07": self.t0 - 12 * 60000 + self.rng.randint(-20000, 20000)}

    def chain_events(self):
        rng = self.rng
        victim, server, helpdesk = self.by_name["wks-fin-07"], self.by_name["srv-files-02"], self.by_name["wks-it-02"]
        user, t0, procs = victim.user, self.t0, victim.procs
        self.mark("chain.victim_logon", procs.get("session_logon"))
        # Helpdesk remote session leaves privileged credential material on the workstation.
        rdp_start = t0 - 7 * 60000 + rng.randint(-20000, 20000)
        _, conn, result = self.rdp(rdp_start, helpdesk, victim, "hd.kestrel", 330000)
        self.mark("chain.rdp_conn", conn)
        self.mark("chain.rdp_logon", result["4624"])
        self.chain["rdp"] = rdp_start + 2500
        # Attachment open -> Office -> PowerShell -> lookalike download.
        attachment = r"C:\Users\%s\AppData\Local\Microsoft\Windows\INetCache\Content.Outlook\7KQ2XN4D\Remittance_Advice_0923.docm" % user
        self.mark("chain.docm", self.file_create(t0, victim, procs["outlook"], attachment))
        word = self.spawn(t0 + 18000 + rng.randint(0, 999), victim, "WINWORD.EXE",
                          '"%s" /n "%s" /o ""' % (APP_PATHS["WINWORD.EXE"], attachment), procs["outlook"], user)
        self.mark("chain.word", word["seq"])
        placeholder = "# lab placeholder only: fetch viewer component from %s, save under AppData, start it; no functional content" % LOOKALIKE
        encoded = base64.b64encode(placeholder.encode("utf-16-le")).decode("ascii")
        shell = self.spawn(t0 + 41000 + rng.randint(0, 999), victim, "powershell.exe",
                           "powershell.exe -NoP -W Hidden -EncodedCommand " + encoded, word, user)
        self.mark("chain.powershell", shell["seq"])
        ms = t0 + 43000 + rng.randint(0, 999)
        self.mark("chain.lookalike_dns", self.dns(ms, victim, shell, LOOKALIKE, ttl=60))
        conn, record = self.web(ms + 6, victim, shell, LOOKALIKE, "https", "GET", "/s/3f9a1c/viewer_update.bin", 200, 0,
                                241664, PS_UA, profile="schannel")
        self.mark("chain.lookalike_conn", conn)
        self.mark("chain.lookalike_proxy", record)
        self.mark("chain.synchost_file", self.file_create(t0 + 47000, victim, shell, SYNCHOST_PATH))
        implant = self.spawn(t0 + 49000 + rng.randint(0, 999), victim, "synchost.exe", '"%s" --background' % SYNCHOST_PATH,
                             shell, user, executable=SYNCHOST_PATH, sha=SYNCHOST_SHA256)
        self.mark("chain.synchost_proc", implant["seq"])
        task_command = 'schtasks.exe /Create /SC ONLOGON /TN "UserSyncHelper" /TR "\\"%s\\" --background" /F' % SYNCHOST_PATH
        schtasks = self.spawn(t0 + 52000 + rng.randint(0, 999), victim, "schtasks.exe", task_command, shell, user)
        self.mark("chain.schtasks", schtasks["seq"])
        self.mark("chain.task", self.task_created(
            t0 + 53000, victim, user, r"\UserSyncHelper",
            "Trigger=Logon of %s\\%s; Action=%s --background; RunAs=%s" % (ORG, user, SYNCHOST_PATH, user)))
        self.chain.update(docm=t0, implant=t0 + 49000)
        # Jittered HTTPS check-ins with short-TTL lookups for the whole remaining window.
        ms = t0 + 75000
        beacons = []
        while ms < self.end - 30000:
            self.mark("chain.c2_dns", self.dns(ms, victim, implant, C2, ttl=30))
            conn, record = self.web(ms + 5, victim, implant, C2, "https", "POST", "/v2/telemetry/sync", 200,
                                    rng.randint(380, 900), rng.randint(120, 600), WINDOWS_UA, profile="agent")
            self.mark("chain.c2_conn", conn)
            self.mark("chain.c2_proxy", record)
            beacons.append(ms)
            ms += int(60000 * rng.uniform(0.7, 1.3))
        gaps = [later - earlier for earlier, later in zip(beacons, beacons[1:])]
        self.chain.update(beacons=len(beacons), beacon_min=min(gaps) // 1000, beacon_max=max(gaps) // 1000)
        # Credential access against lsass.
        ms = t0 + 14 * 60000 + rng.randint(0, 20000)
        tool_path = r"C:\ProgramData\SyncHelper\dbgsvc.exe"
        self.mark("chain.dbgsvc_file", self.file_create(ms, victim, implant, tool_path))
        lsass = procs["lsass"]
        dumper = self.spawn(ms + 5000, victim, "dbgsvc.exe", '"%s" -p %d -o C:\\ProgramData\\SyncHelper\\tmp\\c.bin' % (
            tool_path, lsass["pid"]), implant, user, executable=tool_path)
        self.mark("chain.dbgsvc_proc", dumper["seq"])
        self.mark("chain.lsass", self.process_access(ms + 6000, victim, dumper, lsass, "0x1010"))
        self.mark("chain.dump_file", self.file_create(ms + 9000, victim, dumper, r"C:\ProgramData\SyncHelper\tmp\c.bin"))
        self.chain["lsass"] = ms + 6000
        # Lateral movement over WinRM with the helpdesk account (NTLM from the finance workstation).
        ms = t0 + 20 * 60000 + rng.randint(0, 20000)
        self.mark("chain.lateral_dns", self.dns(ms, victim, implant, server.fqdn))
        self.mark("chain.lateral_conn", self.bare(ms + 4, victim, implant, server.ip, 5985, 6 * 60000, "winrm"))
        result = self.logon(ms + 200, server, "hd.kestrel", 3, source_ip=victim.ip, auth="NTLM", privileged=True,
                            duration=6 * 60000, workstation=victim.name.upper())
        self.mark("chain.lateral_logon", result["4624"])
        self.mark("chain.lateral_priv", result["4672"])
        self.chain["lateral"] = ms + 200
        server_procs = server.procs
        host_proc = self.spawn(ms + 1500, server, "wsmprovhost.exe", r"C:\Windows\system32\wsmprovhost.exe -Embedding",
                               server_procs["dcom"], "hd.kestrel")
        self.mark("chain.wsmprovhost", host_proc["seq"])
        discovery = self.spawn(ms + 40000, server, "cmd.exe", r"cmd.exe /c dir /s /b D:\Shares\Finance\Close\Q3",
                               host_proc, "hd.kestrel")
        self.mark("chain.discovery", discovery["seq"])
        compress = self.spawn(ms + 190000, server, "powershell.exe",
                              r'powershell.exe -NoP -c "Compress-Archive -Path D:\Shares\Finance\Close\Q3\*.xlsx -DestinationPath C:\ProgramData\perfdiag\stg_01.zip"',
                              host_proc, "hd.kestrel")
        self.mark("chain.compress", compress["seq"])
        self.mark("chain.stage_server", self.file_create(ms + 205000, server, compress, r"C:\ProgramData\perfdiag\stg_01.zip"))
        self.mark("chain.stage_server", self.file_create(ms + 230000, server, compress, r"C:\ProgramData\perfdiag\stg_02.zip"))
        # Pull the archives back over SMB.
        ms = t0 + 24 * 60000 + 30000 + rng.randint(0, 10000)
        conn, result = self.smb(ms, victim, server, "hd.kestrel", auth="NTLM", duration=45000)
        self.mark("chain.smb_conn", conn)
        self.mark("chain.smb_logon", result["4624"])
        self.mark("chain.stage_victim", self.file_create(ms + 20000, victim, implant, r"C:\ProgramData\SyncHelper\tmp\stg_01.zip"))
        self.mark("chain.stage_victim", self.file_create(ms + 30000, victim, implant, r"C:\ProgramData\SyncHelper\tmp\stg_02.zip"))
        self.chain["staging"] = ms
        # DNS tunnelling: long random labels under one zone, TXT acknowledgements.
        ms = t0 + 26 * 60000 + rng.randint(0, 10000)
        self.chain["exfil_start"] = ms
        for index in range(EXFIL_QUERIES):
            name = "%s.%s.%04x.%s" % (rng.randbytes(26).hex(), rng.randbytes(16).hex(), index, EXFIL_ZONE)
            self.mark("chain.exfil", self.dns(ms, victim, implant, name, qtype="TXT", answers=["ok%04x" % index], ttl=0))
            last = ms
            ms += rng.randint(550, 1050)
        self.chain["exfil_end"] = last
        if last >= self.end - 2000:
            raise ValueError("storyline does not fit the window")

    def admin_winrm(self):
        rng = self.rng
        admin = self.by_name["wks-it-01"]
        ms = hms(5, 9, 30) + rng.randint(0, 20000)
        shell = self.spawn(ms, admin, "powershell.exe", '"%s"' % APP_PATHS["powershell.exe"], admin.procs["explorer"], admin.user)
        self.mark("admin.shell", shell["seq"])
        self.chain["admin_start"] = ms
        targets = [h for h in self.hosts if h.kind == "server"]
        ms += 30000
        for server in targets:
            self.mark("admin.dns", self.dns(ms, admin, shell, server.fqdn))
            self.mark("admin.conn", self.bare(ms + 3, admin, shell, server.ip, 5985, rng.randint(60000, 180000), "winrm"))
            result = self.logon(ms + 150, server, "adm.halvorsen", 3, source_ip=admin.ip, auth="Kerberos", privileged=True,
                                duration=rng.randint(60000, 170000), workstation="-")
            self.mark("admin.logon", result["4624"])
            if server.sysmon:
                host_proc = self.spawn(ms + 1200, server, "wsmprovhost.exe", r"C:\Windows\system32\wsmprovhost.exe -Embedding",
                                       server.procs["dcom"], "adm.halvorsen")
                self.mark("admin.wsmprovhost", host_proc["seq"])
                for offset, (name, command) in enumerate((("sc.exe", r"C:\Windows\system32\sc.exe query Spooler"),
                                                          ("quser.exe", r"C:\Windows\system32\quser.exe"))):
                    self.spawn(ms + 8000 + offset * 9000, server, name, command, host_proc, "adm.halvorsen")
            ms += rng.randint(45000, 110000)
        self.chain["admin_end"] = ms

    def helpdesk_rdp(self):
        rng = self.rng
        helpdesk = self.by_name["wks-it-02"]
        others = [h for h in self.hosts if h.kind == "workstation" and h.name not in FIXED_USERS]
        for target in rng.sample(others, min(2, len(others))):
            ms = rng.choice((hms(5, 15), hms(6, 12))) + rng.randint(0, 6 * 60000)
            self.rdp(ms, helpdesk, target, "hd.kestrel", rng.randint(120000, 420000))

    def scanner(self):
        rng = self.rng
        ms = hms(4, 50) + rng.randint(0, 30000)
        self.chain["scan_start"] = ms
        for host in self.hosts:
            open_ports = {135, 139, 445}
            if host.kind == "server":
                open_ports |= {3389, 5985}
                if host.role in ("app", "web"):
                    open_ports |= {80, 443}
                if host.role == "db":
                    open_ports.add(1433)
            for dport in (21, 22, 23, 25, 80, 135, 139, 443, 445, 1433, 3389, 5985, 8080):
                sport = rng.randint(40000, 60000)
                kind = "bare" if dport in open_ports else "rst"
                self.sessions.append((ms, len(self.sessions), kind, SCANNER, sport, host.ip, dport, 1,
                                      5 if kind == "bare" else None))
                ms += rng.randint(3, 25)
            result = self.logon(ms + 400, host, "svc.vulnscan", 3, source_ip=SCANNER, auth="NTLM", privileged=True,
                                duration=rng.randint(30000, 90000), workstation="SCAN-01")
            self.mark("scan.logon", result["4624"])
            ms += rng.randint(2500, 6000)
        self.chain["scan_end"] = ms

    def backup(self):
        rng = self.rng
        starts = {"srv-files-01": hms(4, 35), "srv-files-03": hms(2, 40), "srv-db-01": hms(3, 25)}
        for name in self.backup_hosts:
            host = self.by_name[name]
            ms = starts[name] + rng.randint(0, 20000)
            if ms < self.start:
                continue
            result = self.logon(ms, host, "svc.backup", 5, auth="Negotiate", privileged=True)
            self.mark("backup.logon", result["4624"])
            exe = r"C:\Program Files\Coldstore\Agent\csbackup.exe"
            job = name.replace("srv-", "nightly-")
            agent = self.spawn(ms + 800, host, "csbackup.exe", '"%s" --job %s --target %s' % (exe, job, BACKUP),
                               host.procs["sched"], "svc.backup", executable=exe)
            self.mark("backup.proc", agent["seq"])
            self.mark("backup.file", self.file_create(ms + 4000, host, agent, r"C:\ProgramData\Coldstore\cache\%s.idx" % job))
            self.mark("backup.dns", self.dns(ms + 6000, host, agent, BACKUP, ttl=3600))
            ms += 6100
            for chunk in range(1, 25):
                conn, record = self.web(ms, host, agent, BACKUP, "https", "PUT", "/v1/vaults/qv/%s/chunk-%04d" % (job, chunk),
                                        201, rng.randint(480000, 540000), rng.randint(90, 160), "Coldstore-Agent/7.1",
                                        profile="schannel")
                self.mark("backup.conn", conn)
                self.mark("backup.proxy", record)
                ms += rng.randint(90000, 130000)
            self.chain.setdefault("backup", []).append((name, starts[name], ms))

    def password_expiry(self):
        rng = self.rng
        host, server = self.by_name["wks-ops-03"], self.by_name["srv-files-01"]
        ms = hms(5, 45) + rng.randint(0, 30000)
        self.chain["expiry_start"] = ms
        for _ in range(8):
            self.bare(ms, host, host.procs["system"], server.ip, 445, 800, "smb")
            self.mark("expiry.failed", self.failed_logon(ms + 3, server, host.user, 3, "0xC0000071", source_ip=host.ip, auth="NTLM"))
            ms += rng.randint(60000, 100000)
        for _ in range(2):
            self.mark("expiry.failed", self.failed_logon(ms, host, host.user, 7, "0xC0000071"))
            ms += rng.randint(8000, 20000)
        ms += rng.randint(60000, 120000)
        result = self.logon(ms, host, host.user, 7, auth="Negotiate", privileged=host.admin, workstation=host.name.upper())
        self.mark("expiry.success", result["4624"])
        _, result = self.smb(ms + 15000, host, server, host.user)
        self.mark("expiry.success", result["4624"])
        self.chain["expiry_end"] = ms
        # Unrelated typing mistakes elsewhere keep 4625 from being unique to this account.
        others = [h for h in self.hosts if h.kind == "workstation" and h.logon and h.name not in FIXED_USERS]
        for other in rng.sample(others, min(3, len(others))):
            moment = other.logon - rng.randint(5000, 20000)
            if self.start < moment < self.end - 60000:
                self.failed_logon(moment, other, other.user, 2, "0xC000006A")

    def coverage(self):
        for index, (key, message) in enumerate(self.env["coverage"]):
            self.mark("gap." + key, self.emit(self.start + index, None, COVERAGE, "coverage-gap", ["configuration"], ["info"],
                                              "coverage-gap", {}, "coverage:info", message=message))

    def build(self):
        self.plan_chain()
        for host in self.hosts:
            self.base_processes(host)
        self.coverage()
        self.user_sessions()
        for host in self.hosts:
            self.background(host)
        self.scanner()
        self.backup()
        self.admin_winrm()
        self.helpdesk_rdp()
        self.password_expiry()
        self.chain_events()

    # ----- outputs --------------------------------------------------------------------
    def ordered_rows(self):
        self.rows.sort()
        if self.rows[0][0] < self.start or self.rows[-1][0] >= self.end:
            raise ValueError("generated event outside the case window")
        self.event_ids = {}
        for number, (_, seq, _) in enumerate(self.rows, 1):
            self.event_ids[seq] = "evt-%06d" % number

    def group(self, *tags):
        ids = sorted({self.event_ids[seq] for tag in tags for seq in self.tags.get(tag, ())})
        if not ids:
            raise ValueError("storyline tag produced no events: " + ",".join(tags))
        return ids

    def fact(self, fact_id, kind, observation, entities, groups):
        self.group_tags[fact_id] = groups
        full = {key: sorted(set(entities.get(key, ()))) for key in ("hosts", "users", "processes", "domains", "ips")}
        return {"fact_id": fact_id, "kind": kind, "observation": observation, "entities": full,
                "evidence_event_groups": [self.group(*tags) for tags in groups]}

    def group_sessions(self, tags):
        return {self.session_of[seq] for tag in tags for seq in self.tags.get(tag, ()) if seq in self.session_of}

    def link_sessions(self):
        """Sessions behind every key group and the indicator values each carries; call before rendering sorts them."""
        self.session_values = {index: session_indicators(self.sessions[index])
                               for groups in self.group_tags.values() for tags in groups
                               for index in self.group_sessions(tags)}
        return frozenset(self.session_values)

    def cite_alternatives(self, facts, frames, intel):
        """Per evidence group: the frames of its events' sessions, and the domain/IP intel records naming an
        indicator of the fact that those sessions carry. Either satisfies the group like one of its events.
        An intel ID is listed only in the first group that carries it, so it satisfies at most one group of a fact."""
        records = {}
        for doc in intel:
            if doc["indicator"]["type"] in ("domain", "ip"):
                records.setdefault(doc["indicator"]["value"].lower(), []).append(doc["id"])
        for fact in facts:
            named = {value.lower() for key in ("domains", "ips") for value in fact["entities"][key]}
            fact["evidence_frame_groups"], fact["evidence_intel_groups"] = [], []
            listed = set()
            for tags in self.group_tags[fact["fact_id"]]:
                sessions = self.group_sessions(tags)
                numbers = sorted(number for index in sessions for number in frames[index])
                fact["evidence_frame_groups"].append(["frame-%d" % number for number in numbers])
                touched = named & set().union(*(self.session_values[index] for index in sessions))
                ids = {key for value in touched for key in records.get(value, ())} - listed
                listed |= ids
                fact["evidence_intel_groups"].append(sorted(ids))

    def cite_siblings(self, facts):
        """Per evidence group of an attack fact: the other events of the same process (process.entity_id) and the
        same event.category as one of the group's events. Only processes whose start event an attack group
        accepts count, so a shared benign process (a user's OUTLOOK.EXE) lends nothing; an event any fact's
        groups accept, decoys included, is never a sibling; and an event that would be a sibling of two or more
        groups (synchost.exe's DNS lookup of the lateral-movement target sits beside its C2 and tunnel queries)
        is listed in none, so a sibling always points at one step."""
        groups = {fact["fact_id"]: [{seq for tag in tags for seq in self.tags.get(tag, ())} for tags in self.group_tags[fact["fact_id"]]]
                  for fact in facts}
        accepted = set().union(*(seqs for fact_groups in groups.values() for seqs in fact_groups))
        lineage = {self.started[seq] for fact in facts if fact["kind"] == "attack"
                   for seqs in groups[fact["fact_id"]] for seq in seqs if seq in self.started}
        key_of = {seq: key for key, seqs in self.process_events.items() if key[0] in lineage
                  for seq in seqs if seq in accepted}
        candidates = {fact["fact_id"]: [{sibling for seq in seqs if seq in key_of for sibling in self.process_events[key_of[seq]]} - accepted
                                        if fact["kind"] == "attack" else set() for seqs in groups[fact["fact_id"]]]
                      for fact in facts}
        counts = Counter(seq for fact_groups in candidates.values() for siblings in fact_groups for seq in siblings)
        for fact in facts:
            fact["evidence_sibling_groups"] = [sorted(self.event_ids[seq] for seq in siblings if counts[seq] == 1)
                                               for siblings in candidates[fact["fact_id"]]]

    def facts(self):
        c = self.chain
        victim, server = self.by_name["wks-fin-07"], self.by_name["srv-files-02"]

        fact = self.fact
        backup_text = "; ".join("%s from %s UTC until about %s UTC" % (name, clock(max(begin, self.start)), clock(end))
                                for name, begin, end in c.get("backup", []))
        facts = [
            fact("attack.initial-access.docm-attachment", "attack",
                 "At %s UTC OUTLOOK.EXE on wks-fin-07 (user r.ashgrove) wrote the macro-enabled attachment Remittance_Advice_0923.docm into the Outlook attachment cache, and about 18 seconds later WINWORD.EXE started with OUTLOOK.EXE as parent and opened that file." % clock(c["docm"]),
                 {"hosts": ["wks-fin-07"], "users": ["r.ashgrove"], "processes": ["OUTLOOK.EXE", "WINWORD.EXE"]},
                 [("chain.docm",), ("chain.word",)]),
            fact("attack.execution.office-child-powershell", "attack",
                 "WINWORD.EXE spawned powershell.exe with -NoP -W Hidden -EncodedCommand; the encoded text decodes to a placeholder describing a component download from the lookalike portal. No other Office process in the case spawns PowerShell.",
                 {"hosts": ["wks-fin-07"], "users": ["r.ashgrove"], "processes": ["WINWORD.EXE", "powershell.exe"],
                  "domains": [LOOKALIKE]},
                 [("chain.word",), ("chain.powershell",)]),
            fact("attack.delivery.lookalike-download", "attack",
                 "That powershell.exe resolved %s (one letter off the internal %s) to %s, fetched /s/3f9a1c/viewer_update.bin over HTTPS (241,664 response bytes at the gateway), wrote synchost.exe under the user's AppData\\Roaming\\SyncHelper and started it." % (LOOKALIKE, PORTAL, LOOKALIKE_IP),
                 {"hosts": ["wks-fin-07"], "users": ["r.ashgrove"], "processes": ["powershell.exe", "synchost.exe"],
                  "domains": [LOOKALIKE], "ips": [LOOKALIKE_IP]},
                 [("chain.lookalike_dns",), ("chain.lookalike_conn", "chain.lookalike_proxy"), ("chain.synchost_file", "chain.synchost_proc")]),
            fact("attack.persistence.logon-task", "attack",
                 "powershell.exe ran schtasks.exe to register the logon-triggered task \\UserSyncHelper that runs synchost.exe as r.ashgrove; the Security log records the task creation (4698).",
                 {"hosts": ["wks-fin-07"], "users": ["r.ashgrove"], "processes": ["schtasks.exe", "synchost.exe"]},
                 [("chain.schtasks",), ("chain.task",)]),
            fact("attack.c2.jittered-https-beacon", "attack",
                 "Only on wks-fin-07, synchost.exe resolved %s (TTL 30) and made %d HTTPS POSTs to /v2/telemetry/sync at %s with intervals of %d-%d seconds (60 s with jitter) until the window end, using a browser-like user agent from a non-browser process." % (C2, c["beacons"], C2_IP, c["beacon_min"], c["beacon_max"]),
                 {"hosts": ["wks-fin-07"], "users": ["r.ashgrove"], "processes": ["synchost.exe"], "domains": [C2], "ips": [C2_IP]},
                 [("chain.c2_dns",), ("chain.c2_conn", "chain.c2_proxy")]),
            fact("attack.credential-access.lsass", "attack",
                 "At %s UTC synchost.exe dropped dbgsvc.exe in C:\\ProgramData\\SyncHelper, which opened lsass.exe with GrantedAccess 0x1010 and wrote c.bin. Earlier (%s UTC) the helpdesk account hd.kestrel had an RDP (type 10) logon on wks-fin-07, leaving privileged credentials on the host." % (clock(c["lsass"]), clock(c["rdp"])),
                 {"hosts": ["wks-fin-07"], "users": ["r.ashgrove", "hd.kestrel"], "processes": ["dbgsvc.exe", "lsass.exe", "synchost.exe"]},
                 [("chain.dbgsvc_proc", "chain.dbgsvc_file"), ("chain.lsass",), ("chain.rdp_logon",)]),
            fact("attack.lateral.winrm-helpdesk-account", "attack",
                 "At %s UTC synchost.exe on wks-fin-07 connected to srv-files-02 on 5985 (WinRM); srv-files-02 logged a new type 3 NTLM logon for hd.kestrel from %s with special privileges, then wsmprovhost.exe ran as hd.kestrel. The helpdesk account normally connects from wks-it-02 with RDP, not from a finance workstation." % (clock(c["lateral"]), victim.ip),
                 {"hosts": ["wks-fin-07", "srv-files-02"], "users": ["hd.kestrel"], "processes": ["synchost.exe", "wsmprovhost.exe"],
                  "ips": [victim.ip, server.ip]},
                 [("chain.lateral_conn",), ("chain.lateral_logon", "chain.lateral_priv"), ("chain.wsmprovhost",)]),
            fact("attack.collection.staging", "attack",
                 "Under that WinRM session, cmd.exe listed D:\\Shares\\Finance\\Close\\Q3 and powershell.exe ran Compress-Archive into C:\\ProgramData\\perfdiag\\stg_01.zip and stg_02.zip; from %s UTC wks-fin-07 opened an SMB session to srv-files-02 as hd.kestrel and synchost.exe wrote both archives under C:\\ProgramData\\SyncHelper\\tmp." % clock(c["staging"]),
                 {"hosts": ["srv-files-02", "wks-fin-07"], "users": ["hd.kestrel"], "processes": ["cmd.exe", "powershell.exe", "synchost.exe"]},
                 [("chain.discovery", "chain.compress"), ("chain.stage_server",), ("chain.smb_conn", "chain.smb_logon"), ("chain.stage_victim",)]),
            fact("attack.exfiltration.dns-tunnel", "attack",
                 "From %s to %s UTC synchost.exe issued %d TXT queries for unique ~115-character names (two long hex labels plus a sequence counter) under %s, each answered with a short acknowledgement; no other process queries that zone. The staged archive content itself is not visible." % (clock(c["exfil_start"]), clock(c["exfil_end"]), EXFIL_QUERIES, EXFIL_ZONE),
                 {"hosts": ["wks-fin-07"], "processes": ["synchost.exe"], "domains": [EXFIL_ZONE]},
                 [("chain.exfil",)]),
            fact("decoy.it-admin-winrm", "decoy",
                 "Between %s and %s UTC t.halvorsen's interactive powershell.exe on wks-it-01 opened WinRM sessions to every server; each server logged a Kerberos type 3 logon for adm.halvorsen from %s and ran sc.exe/quser.exe under wsmprovhost.exe. This is routine administration from the IT admin workstation, not the intrusion." % (clock(c["admin_start"]), clock(c["admin_end"]), self.by_name["wks-it-01"].ip),
                 {"hosts": ["wks-it-01"], "users": ["adm.halvorsen", "t.halvorsen"], "processes": ["powershell.exe", "wsmprovhost.exe"],
                  "ips": [self.by_name["wks-it-01"].ip]},
                 [("admin.conn",), ("admin.logon",)]),
            fact("decoy.updater-periodic-task", "decoy",
                 "twupdate.exe runs every 10 minutes (+/-3 s) on every workstation via the scheduled task \\Tallyworks\\UpdateCheck, querying %s and fetching a manifest over HTTPS; around 05:05 UTC each workstation self-updated and re-registered the task (4698). Fleet-wide, regular and signed-vendor in shape: benign periodic traffic despite the low-confidence intel hit." % UPDATER,
                 {"processes": ["twupdate.exe"], "domains": [UPDATER], "ips": [FIXED_EXTERNAL[UPDATER]]},
                 [("updater.task",), ("updater.conn", "updater.proxy"), ("updater.dns",)]),
            fact("decoy.night-backup-upload", "decoy",
                 "The Coldstore backup agent csbackup.exe running as svc.backup uploaded 24 chunks of about 0.5 MB each over HTTPS PUT to %s (%s): %s. Large outbound volume at night, but it is the scheduled backup job." % (BACKUP, BACKUP_IP, backup_text),
                 {"hosts": list(name for name, _, _ in c.get("backup", [])), "users": ["svc.backup"], "processes": ["csbackup.exe"],
                  "domains": [BACKUP], "ips": [BACKUP_IP]},
                 [("backup.proc",), ("backup.conn", "backup.proxy")]),
            fact("decoy.vulnerability-scan", "decoy",
                 "From %s to %s UTC %s swept 13 TCP ports on every host (payload-free handshakes on open ports, resets on closed ones) and made an authenticated NTLM type 3 logon as svc.vulnscan on each host. It is the vulnerability scanner, not lateral movement." % (clock(c["scan_start"]), clock(c["scan_end"]), SCANNER),
                 {"users": ["svc.vulnscan"], "ips": [SCANNER]},
                 [("scan.logon",)]),
            fact("decoy.password-expiry-failures", "decoy",
                 "From %s UTC srv-files-01 and wks-ops-03 logged repeated 4625 failures for m.thornvale with SubStatus 0xC0000071 (password expired) from %s, followed at %s UTC by a successful unlock and SMB logon: an expired password, not password guessing." % (clock(c["expiry_start"]), self.by_name["wks-ops-03"].ip, clock(c["expiry_end"])),
                 {"hosts": ["wks-ops-03"], "users": ["m.thornvale"], "ips": [self.by_name["wks-ops-03"].ip]},
                 [("expiry.failed",), ("expiry.success",)]),
            fact("benign.av-lsass-access", "benign-pattern",
                 "afavsvc.exe (Aegisfort antivirus) opens lsass.exe with GrantedAccess 0x1000 about every 20 minutes on every Sysmon host; this baseline differs from the single 0x1010 access by dbgsvc.exe.",
                 {"processes": ["afavsvc.exe", "lsass.exe"]},
                 [("av.lsass",)]),
            fact("coverage.no-script-logging", "coverage",
                 "Without script block logging, the content run by the hidden powershell.exe on wks-fin-07 and by powershell.exe under WinRM on srv-files-02 is known only from command lines; the encoded command must be decoded from the process record.",
                 {"processes": ["powershell.exe"]}, [("gap.script",)]),
            fact("coverage.no-mail-logs", "coverage",
                 "Without mail gateway or mailbox logs, the sender and delivery of Remittance_Advice_0923.docm cannot be established, nor whether other recipients received it; only OUTLOOK.EXE writing the file is visible.",
                 {"processes": ["OUTLOOK.EXE"]}, [("gap.mail",)]),
            fact("coverage.no-file-access-auditing", "coverage",
                 "Without share-level file access auditing or file-read records, exactly which finance files went into the staged archives on srv-files-02 cannot be confirmed, and the lsass rule limits process-access visibility to that one target.",
                 {"hosts": ["srv-files-02"], "processes": ["lsass.exe"]}, [("gap.files",)]),
        ]
        return facts

    def intel(self):
        feeds = ("SynthIntel Open Feed", "Lab Community Blocklist", "Training Sandbox Reports", "Demo Reputation Service")
        docs = [
            ("domain", LOOKALIKE, "high", feeds[0], "Recently registered domain resembling a logistics customer portal; served document-viewer downloads in synthetic phishing reports.", "2025-10-09"),
            ("domain", C2, "medium", feeds[2], "Received periodic HTTPS POST check-ins from synthetic sandbox detonations.", "2025-09-28"),
            ("ip", C2_IP, "medium", feeds[1], "Hosting address associated with synthetic sandbox check-in traffic.", "2025-09-30"),
            ("hash", SYNCHOST_SHA256, "high", feeds[2], "Synthetic sample that installs a logon task and performs periodic HTTPS check-ins.", "2025-10-10"),
            ("file_name", "synchost.exe", "low", feeds[1], "File name reported in several unrelated synthetic samples; the name alone is weak evidence.", "2025-07-02"),
            ("domain", UPDATER, "low", feeds[3], "Shared hosting range previously listed for bundled unwanted software; unverified.", "2025-06-15"),
            ("ip", BACKUP_IP, "low", feeds[1], "Address reported for high-volume uploads in a synthetic abuse feed.", "2025-08-21"),
            ("file_name", "csbackup.exe", "low", feeds[3], "Name seen in a synthetic report about data-staging utilities; likely a generic collision.", "2025-05-30"),
            ("domain", self.sites[0][0], "low", feeds[3], "Parked-domain heuristic match; not confirmed.", "2025-09-02"),
        ]
        return self.intel_documents(docs, feeds)

    def intel_documents(self, docs, feeds):
        """Adds irrelevant indicators (never matching case data), shuffles and formats."""
        rng = self.rng
        wanted = len(docs) + self.intel_noise
        used_names = {site for site, _ in self.sites} | set(self.ip_of) | set(self.env["external"])
        free_ips = [address for address in self.external_pool if address not in self.used_external]
        seen = {(kind, value.lower(), feed) for kind, value, _, feed, _, _ in docs}
        while len(docs) < wanted:
            kind = rng.choices(("domain", "ip", "hash", "file_name"), (45, 25, 20, 10))[0]
            if kind == "domain":
                value = "%s%s-%d%s" % (rng.choice(WORDS_A), rng.choice(WORDS_B), rng.randrange(10, 999),
                                       rng.choice((".invalid", ".test", ".example")))
                if value in used_names:
                    continue
            elif kind == "ip":
                if not free_ips:
                    continue
                value = rng.choice(free_ips)
            elif kind == "hash":
                value = "%064X" % rng.getrandbits(256)
            else:
                value = "%s_%s.exe" % (rng.choice(("upd", "svc", "inst", "helper", "agent", "loader")), "%04x" % rng.getrandbits(16))
            feed = rng.choice(feeds)
            if (kind, value.lower(), feed) in seen:
                continue
            seen.add((kind, value.lower(), feed))
            docs.append((kind, value, rng.choice(("low", "low", "medium", "high")), feed,
                         rng.choice(("Observed in synthetic commodity campaign reporting.", "Listed by an automated synthetic reputation heuristic.",
                                     "Seen in synthetic sandbox output; context limited.", "Reported in a synthetic community submission.")),
                         "2025-%02d-%02d" % (rng.randint(1, 9), rng.randint(1, 28))))
        rng.shuffle(docs)
        return [{"id": "ioc-%05d" % number, "case_id": self.case_id,
                 "indicator": {"type": kind, "value": value}, "threat": {"feed": {"name": feed}},
                 "confidence": confidence, "description": description, "first_seen": first_seen + "T00:00:00Z"}
                for number, (kind, value, confidence, feed, description, first_seen) in enumerate(docs, 1)]

    EVENTS_COVERAGE = "Invented ECS records for %d Windows hosts of the %s environment: Security logon, logoff, special-privilege and scheduled-task records; Sysmon process create, network connect (outbound), DNS query, process access and file create records; transparent egress gateway HTTP/TLS access records; and coverage notes (event.provider lab.coverage). %d records."
    PCAP_COVERAGE = "Invented core-switch capture: DNS, NTP, TLS ClientHello plus opaque records, plaintext HTTP, and payload-free SMB/WinRM/RDP/scan sessions; Ethernet/IPv4. %d packets in %d sessions."

    def case_metadata(self, event_count, packet_count, session_count, intel_count):
        hosts = len(self.hosts)
        return {
            "schema_version": SCHEMA_VERSION, "case_id": self.case_id,
            "time_range_utc": {"start_inclusive": iso(self.start)[:-5] + "Z", "end_exclusive": iso(self.end)[:-5] + "Z"},
            "sources": [
                {"artifact": "events.jsonl",
                 "coverage": self.EVENTS_COVERAGE % (hosts, self.env["org"], event_count)},
                {"artifact": "traffic.pcap",
                 "coverage": self.PCAP_COVERAGE % (packet_count, session_count)},
                {"artifact": "intel.jsonl",
                 "coverage": "Invented threat-intelligence indicators (domain, ip, file_name, hash) from synthetic feeds of mixed confidence; %d indicators. A match is a lead, not proof." % intel_count},
            ],
            "question": "What happened in this environment during the window? Determine whether an intrusion occurred and reconstruct its sequence; state the scope and impact (hosts, accounts, data); explain which suspicious-looking activity has benign or alternative explanations; and name the coverage gaps that limit conclusions. Cite event.id values, separate observations from inferences, and do not assume compromise without evidence.",
        }


# ----- story b: exploited public web server -> account -> service tunnel -> RDP -> DB dump -> HTTPS POST exfil -----
B_ORG = "TALVERIN"
B_ZONE = "talverin.example"
B_RESOLVER = "10.50.0.10"
PUBLIC_SITE = "www.talverin.example"
B_ATTACKER = "198.51.100.66"
B_STAGE = "files.boxvau1t.test"
B_STAGE_IP = "203.0.113.91"
B_RELAY = "sync.boxvau1t.test"
B_RELAY_IP = "203.0.113.92"
B_STORAGE = "files.boxvault.example"
B_CDN = "ingest.fastedge-cdn.example"
B_CDN_IP = "198.51.100.200"
B_EDR = "intel.brightwall-edr.example"
B_UPDATER = "update.corvidsoft.example"
IIS = "lab.iis"
SYSTEM_LOG = "lab.windows.system"
W3WP_PATH = r"C:\Windows\System32\inetsrv\w3wp.exe"
WEBSHELL_PATH = r"C:\inetpub\wwwroot\portal\uploads\thumbs\t3.aspx"
TNLSVC_PATH = r"C:\ProgramData\ThumbCache\tnlsvc.exe"
TNLSVC_SHA256 = fake_sha256(TNLSVC_PATH, "thumbcache")
SQL_BINN = r"C:\Program Files\Microsoft SQL Server\MSSQL16.MSSQLSERVER\MSSQL\Binn"
SQLCMD_PATH = r"C:\Program Files\Microsoft SQL Server\Client SDK\ODBC\170\Tools\Binn\SQLCMD.EXE"
FEUPLOAD_PATH = r"C:\Program Files\FastEdge\Uploader\feupload.exe"
VIGILAGENT_PATH = r"C:\Program Files\Vigilmon\Agent\vigilagent.exe"
SERVERS_B = {
    "web-ext-01": ("10.70.1.20", "web", True), "web-ext-02": ("10.70.1.21", "webstage", True),
    "db-sql-01": ("10.50.2.11", "db", True), "db-sql-02": ("10.50.2.12", "db", True),
    "db-sql-03": ("10.50.2.13", "db", True), "fs-01": ("10.50.3.11", "files", True),
    "fs-02": ("10.50.3.12", "files", True), "app-erp-01": ("10.50.4.11", "app", True),
    "app-erp-02": ("10.50.4.12", "app", True), "app-mes-01": ("10.50.4.21", "app", True),
    "mon-01": ("10.50.5.11", "mon", True), "dc-tal-01": (B_RESOLVER, "dc", False),
}
COVERAGE_GAPS_B = (
    ("iis", "IIS access records hold the URI stem, query, status, byte counts and user agent only; request and response bodies for www.talverin.example are not recorded."),
    ("script", COVERAGE_GAPS[0][1]),
    ("sql", "SQL Server audit, query and error logs are not collected; database activity is visible only through process command lines and backup file creation."),
    ("rdp", "RDP session content (screen, clipboard, drive redirection, keystrokes) is not recorded; only connection, logon and process records exist."),
    ("dmz", "web-ext-01 sits in the DMZ behind NAT; the capture shows internet clients talking to its private address and the public address is not recorded."),
    ("tls", COVERAGE_GAPS[5][1]),
    ("prior", COVERAGE_GAPS[6][1]),
    ("files", "Sysmon process-access rules record access to lsass.exe only; file-create rules cover user profile, ProgramData, Temp, Program Files, web content and D:\\SQLBackup paths; file reads, deletions and share-level file access auditing (event IDs 5140/5145) are not collected."),
    ("dc", "dc-tal-01 contributes its Security and System logs only (no Sysmon); Kerberos, LDAP and ADWS payloads to it are not captured beyond connection records."),
)
STORY_B = {
    "org": B_ORG, "zone": B_ZONE, "resolver": B_RESOLVER, "dc": "dc-tal-01", "servers": SERVERS_B,
    "apps": (("erp", "app-erp-01"), ("mes", "app-mes-01"), ("intranet", "app-erp-02")),
    "ws_name": "pc-%s-%02d", "ws_ip": "10.40.%d.%d",
    "departments": {"it": 1, "eng": 2, "mfg": 3, "mkt": 4, "acct": 5, "qa": 6},
    "fixed_users": {"pc-it-01": "k.morrow", "pc-mkt-02": "l.ostrander"},
    "surnames": ("abernast", "bellwick", "caldmoor", "dravenly", "esterhal", "fallowmere", "gorstead", "hallowell",
                 "istvank", "jorvane", "kelderman", "lathbury", "mirabeau", "nethercott", "ondrasek", "pemberly",
                 "quayle", "rothwell", "sandoval", "tremaine", "ulverston", "varnado", "whitcombe", "yelverton",
                 "zandvoort", "ashcombe", "brackley", "cuthbert", "delacroix", "emberton", "fairholme", "glossop",
                 "hedley", "illingworth", "jarrow", "kingsley", "lockridge", "maddox", "northam", "ottley"),
    "admin_depts": ("it",), "prelogged_depts": ("it",), "prelogged_hosts": (), "night_dept": "mfg",
    "share": ("eng", "fs-02"), "macro_dept": "acct",
    "external": {B_STAGE: B_STAGE_IP, B_RELAY: B_RELAY_IP, B_STORAGE: "192.0.2.61", B_CDN: B_CDN_IP,
                 B_EDR: "192.0.2.99", B_UPDATER: "198.51.100.24", OS_UPDATES: FIXED_EXTERNAL[OS_UPDATES],
                 CHAT: FIXED_EXTERNAL[CHAT], PRINT_DRIVERS: FIXED_EXTERNAL[PRINT_DRIVERS]},
    "reserved": (B_ATTACKER,),
    "attachments": (("Shift_plan.xlsx", "EXCEL.EXE"), ("QA_report.pdf", "pdfview.exe"),
                    ("Supplier_quote.pdf", "pdfview.exe"), ("Line_changes.docx", "WINWORD.EXE"),
                    ("Cost_model.xlsm", "EXCEL.EXE"), ("Safety_briefing.docx", "WINWORD.EXE")),
    "coverage": COVERAGE_GAPS_B,
    "bg_procs": BG_PROCS[:8] + (("bwsweep.exe", r"C:\Program Files\Brightwall\bwsweep.exe",
                                 r'"C:\Program Files\Brightwall\bwsweep.exe" --sweep memory', "av", "SYSTEM"),) + BG_PROCS[9:],
    "sys_files": (r"C:\Windows\Temp\%08x.tmp", r"C:\ProgramData\Brightwall\Hold\obj-%08x.dat",
                  r"C:\Windows\Temp\MpCmd-%08x.log", r"C:\ProgramData\Package Cache\%08x.tmp"),
    "av": {"name": "bwsensor.exe", "exe": r"C:\Program Files\Brightwall\bwsensor.exe",
           "log": r"C:\ProgramData\Brightwall\Logs\sweep-%06x.log", "domain": B_EDR, "path": "/content/v6/pack-%d.bin",
           "file": r"C:\ProgramData\Brightwall\Content\pack-%d.dat", "agent": "Brightwall-Sensor/6.3", "access": "0x1400"},
    "updater": {"name": "cvupdate.exe", "exe": r"C:\Program Files\Corvid\Updater\cvupdate.exe", "version": "7.1.3",
                "domain": B_UPDATER, "manifest": "/api/v1/latest?product=desk&ver=7.1.3",
                "package": "/api/v1/pkg/cvupdate-7.1.4.bin", "agent": "Corvid-Updater/7.1",
                "new": r"C:\Program Files\Corvid\Updater\cvupdate.new", "task": r"\Corvid\AutoUpdate"},
}
SIZES_B = {
    "tiny": {"start": hms(4, 30), "hours": 2,
             "servers": ("web-ext-01", "db-sql-01", "fs-01", "app-erp-01", "mon-01", "dc-tal-01"),
             "workstations": {"it": (1, 2), "mkt": (2,), "eng": (1, 2)},
             "bg": 0.2, "user": 0.2, "web": 0.2, "scanners": 4, "sites": 30, "intel_noise": 40, "backup": ()},
    "medium": {"start": hms(4, 30), "hours": 2,
               "servers": ("web-ext-01", "db-sql-01", "db-sql-02", "fs-01", "app-erp-01", "mon-01", "dc-tal-01"),
               "workstations": {"it": range(1, 4), "eng": range(1, 6), "mfg": range(1, 5), "mkt": range(1, 4),
                                "acct": range(1, 4)},
               "bg": 4.4, "user": 2.0, "web": 0.6, "scanners": 10, "sites": 120, "intel_noise": 300, "backup": ()},
    "large": {"start": hms(2, 0), "hours": 6, "servers": tuple(SERVERS_B),
              "workstations": {"it": range(1, 7), "eng": range(1, 25), "mfg": range(1, 25), "mkt": range(1, 13),
                               "acct": range(1, 11), "qa": range(1, 13)},
              "bg": 3.4, "user": 1.7, "web": 0.6, "scanners": 40, "sites": 320, "intel_noise": 1500, "backup": ()},
}
RECON_PATHS = ("/.git/config", "/web.config.bak", "/admin/", "/portal/admin/", "/portal/upload/", "/backup.zip",
               "/portal/elmah.axd", "/trace.axd", "/portal/api/v1/", "/portal/uploads/", "/portal/upload/ImageHandler.ashx",
               "/portal/login.aspx", "/portal/web.config", "/portal/bin/", "/portal/uploads/thumbs/", "/aspnet_client/")
SCAN_PATHS = ("/wp-login.php", "/.env", "/phpmyadmin/", "/admin.php", "/cgi-bin/test.cgi", "/xmlrpc.php",
              "/vendor/phpunit/", "/solr/", "/actuator/health", "/.aws/credentials", "/server-status")
VISITOR_UAS = (WINDOWS_UA, "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5) LabBrowser/118.0",
               "Mozilla/5.0 (Linux; Android 14) LabBrowser/118.0 Mobile")


class StoryB(Scenario):
    """Public web server exploitation storyline with its own environment, decoys and coverage gaps."""

    ENV = STORY_B
    SIZE_TABLE = SIZES_B
    EVENTS_COVERAGE = "Invented ECS records for %d Windows hosts of the %s environment: Security logon, logoff, special-privilege, account-management (4720/4728/4732) and scheduled-task records; System service-install records (7045); Sysmon process create, network connect (outbound), DNS query, process access and file create records; IIS access records for the public web server; transparent egress gateway HTTP/TLS access records; and coverage notes (event.provider lab.coverage). %d records."
    PCAP_COVERAGE = "Invented core-switch capture including the DMZ after NAT: DNS, NTP, TLS ClientHello plus opaque records, plaintext HTTP, and payload-free SMB/RDP/ADWS sessions; Ethernet/IPv4. %d packets in %d sessions."

    def __init__(self, size, seed, case_id):
        super().__init__(size, seed, case_id)
        self.web_scale = SIZES_B[size]["web"]
        self.scanner_count = SIZES_B[size]["scanners"]
        self.web_host = self.by_name["web-ext-01"]

    def build(self):
        self.plan_chain()
        for host in self.hosts:
            self.base_processes(host)
        self.server_processes()
        self.coverage()
        self.user_sessions()
        self.storage_sync()
        for host in self.hosts:
            self.background(host)
        self.public_web()
        self.internet_scanners()
        self.dba_backup()
        self.account_decoy()
        self.monitoring_install()
        self.cdn_uploads()
        self.typo_failures()
        self.chain_events()

    def plan_chain(self):
        self.t0 = hms(4, 52) + self.rng.randint(-60000, 60000)
        self.fixed_logons = {"pc-mkt-02": hms(5, 31) + self.rng.randint(-30000, 30000)}

    def typo_failures(self):
        """A few mistyped passwords right before ordinary logons."""
        rng = self.rng
        candidates = [h for h in self.hosts if h.kind == "workstation" and h.logon and h.name not in self.env["fixed_users"]]
        for host in rng.sample(candidates, min(4, len(candidates))):
            moment = host.logon - rng.randint(5000, 20000)
            if self.start < moment < self.end - 60000:
                self.failed_logon(moment, host, host.user, 2, "0xC000006A")

    def server_processes(self):
        for host in self.hosts:
            procs = host.procs
            if host.role in ("web", "webstage"):
                procs["w3wp"] = self.spawn(0, host, "w3wp.exe", None, procs["services"], "svc_portal",
                                           executable=W3WP_PATH, emit=False)
            elif host.role == "db":
                procs["sql"] = self.spawn(0, host, "sqlservr.exe", None, procs["services"], "svc_sqlsvc",
                                          executable=SQL_BINN + r"\sqlservr.exe", emit=False)
                procs["agent"] = self.spawn(0, host, "SQLAGENT.EXE", None, procs["services"], "svc_sqlagent",
                                            executable=SQL_BINN + r"\SQLAGENT.EXE", emit=False)
            elif host.role == "mon":
                procs["vigil"] = self.spawn(0, host, "vigilsrv.exe", None, procs["services"], "svc_vigilmon",
                                            executable=r"C:\Program Files\Vigilmon\Server\vigilsrv.exe", emit=False)

    # ----- story b event families --------------------------------------------------------
    def inbound(self, ms, client_ip, path, method, status, request_body, response_body, user_agent):
        """Internet client -> DMZ web server over TLS, recorded by IIS and the capture."""
        rng, web = self.rng, self.web_host
        rtt = rng.randint(15, 80)
        cport = rng.randint(1024, 65000)
        self.used_external.add(client_ip)
        request_bytes, response_bytes = request_body + 420, response_body + 260
        self.sessions.append((ms, len(self.sessions), "tls", client_ip, cport, web.ip, 443, rtt,
                              (PUBLIC_SITE, "browser", request_bytes, response_bytes)))
        url = {"domain": PUBLIC_SITE, "full": "https://%s%s" % (PUBLIC_SITE, path), "path": path.split("?")[0],
               "scheme": "https"}
        if "?" in path:
            url["query"] = path.split("?", 1)[1]
        seq = self.emit(ms + 2 * rtt + 1, web, IIS, "access", ["web", "network"], ["access"], "http-request", {
            "source": {"ip": client_ip, "port": cport}, "destination": {"ip": web.ip, "port": 443}, "url": url,
            "http": {"request": {"method": method, "bytes": request_bytes},
                     "response": {"status_code": status, "bytes": response_bytes}},
            "user_agent": {"original": user_agent}, "tls": {"server_name": PUBLIC_SITE},
            "network": {"transport": "tcp", "protocol": "tls", "direction": "inbound"}},
            "iis:access", outcome="success" if status < 400 else "failure",
            message="%s %s %d" % (method, path, status))
        self.link(seq)
        return seq

    def account_created(self, ms, host, subject, target):
        return self.emit(ms, host, SEC, "4720", ["iam"], ["user", "creation"], "added-user-account", {
            "user": dict(self.user(subject), target={"name": target, "domain": B_ORG}),
            "winlog": {"event_data": {"SubjectUserName": subject, "TargetUserName": target, "TargetDomainName": B_ORG}}},
            "security:4720", outcome="success", channel="Security", message="A user account was created.")

    def member_added(self, ms, host, subject, member, group, code):
        scope = "global" if code == "4728" else "local"
        return self.emit(ms, host, SEC, code, ["iam"], ["group", "change"], "added-member-to-group", {
            "user": dict(self.user(subject), target={"name": member, "domain": B_ORG}), "group": {"name": group},
            "winlog": {"event_data": {"SubjectUserName": subject, "TargetUserName": group,
                                      "MemberName": "CN=%s,OU=Accounts,DC=talverin,DC=example" % member}}},
            "security:" + code, outcome="success", channel="Security",
            message="A member was added to a security-enabled %s group." % scope)

    def service_installed(self, ms, host, service, image):
        return self.emit(ms, host, SYSTEM_LOG, "7045", ["configuration"], ["installation"], "service-installed", {
            "service": {"name": service},
            "winlog": {"event_data": {"ServiceName": service, "ImagePath": image, "ServiceType": "user mode service",
                                      "StartType": "auto start", "AccountName": "LocalSystem"}}},
            "system:7045", outcome="success", channel="System", message="A service was installed in the system.")

    # ----- story b noise ------------------------------------------------------------------
    def storage_sync(self):
        rng = self.rng
        for host in self.hosts:
            if host.kind != "workstation" or not (host.prelogged or (host.logon and host.logon < self.end - 60000)):
                continue
            start = self.start if host.prelogged else host.logon + 20000
            end = host.logoff if host.logoff and host.logoff < self.end else self.end
            for ms in self.times(2, start, end, self.user_scale):
                self.cached_dns(ms, host, host.procs["browser"], B_STORAGE)
                method = "PUT" if rng.random() < 0.3 else "GET"
                self.web(ms + 4, host, host.procs["browser"], B_STORAGE, "https", method,
                         "/api/v2/files/%08x" % rng.getrandbits(32), 200,
                         rng.randint(2000, 60000) if method == "PUT" else 0, rng.randint(300, 20000), WINDOWS_UA)

    def public_web(self):
        rng, web = self.rng, self.web_host
        visitors = rng.sample(self.external_pool, 120)
        pages = ("/", "/products/%d", "/careers", "/contact", "/portal/login.aspx", "/portal/orders/status.aspx?id=%d",
                 "/news/%d")
        for ms in self.times(160, self.start, self.end, self.web_scale * self.user_scale):
            client = rng.choice(visitors)
            agent = rng.choice(VISITOR_UAS)
            page = rng.choice(pages)
            page = page % rng.randrange(100, 9999) if "%d" in page else page
            if rng.random() < 0.04:
                self.inbound(ms, client, "/portal/upload/ImageHandler.ashx?type=photo", "POST", 200,
                             rng.randint(30000, 400000), 310, agent)
                self.mark("web.upload", self.file_create(ms + 900, web, web.procs["w3wp"],
                                                         r"C:\inetpub\wwwroot\portal\uploads\images\%08x.jpg" % rng.getrandbits(32)))
                continue
            self.inbound(ms, client, page, "GET", rng.choices((200, 304, 302, 404), (86, 8, 3, 3))[0], 0,
                         rng.randint(1500, 20000), agent)
            for _ in range(rng.randint(0, 3)):
                ms += rng.randint(150, 900)
                self.inbound(ms, client, "/assets/site.%06x.%s" % (rng.getrandbits(24), rng.choice(("css", "js", "png"))),
                             "GET", 200, 0, rng.randint(800, 12000), agent)

    def internet_scanners(self):
        rng = self.rng
        reserved = set(self.env["external"].values()) | {B_ATTACKER}
        scanners = [ip for ip in rng.sample(self.external_pool, self.scanner_count + 5) if ip not in reserved][:self.scanner_count]
        self.scanner_ips = scanners
        for client in scanners:
            ms = self.start + rng.randrange(self.end - self.start - 20 * 60000)
            agent = rng.choice(("LabSurveyBot/2.1", "Mozilla/5.0 (compatible; LabCrawler/1.4)", WINDOWS_UA))
            for _ in range(rng.randint(3, 8)):
                self.mark("web.scan", self.inbound(ms, client, rng.choice(SCAN_PATHS), "GET", 404, 0,
                                                   rng.randint(200, 1200), agent))
                ms += rng.randint(500, 9000)

    # ----- story b decoys -------------------------------------------------------------------
    def dba_backup(self):
        rng = self.rng
        files = self.by_name["fs-01"]
        for index, host in enumerate(h for h in self.hosts if h.role == "db"):
            ms = hms(4, 40) + index * rng.randint(60000, 120000)
            if ms < self.start:
                continue
            procs = host.procs
            job = self.spawn(ms, host, "sqlcmd.exe", r"sqlcmd.exe -S localhost -E -i D:\Jobs\nightly_full.sql -o D:\Jobs\logs\nightly_full.log",
                             procs["agent"], "svc_sqlagent", executable=SQLCMD_PATH)
            self.mark("dba.job", job["seq"])
            moment = ms
            for database in ("CustomerOrders", "Inventory", "Payroll"):
                moment += rng.randint(60000, 150000)
                self.mark("dba.file", self.file_create(moment, host, procs["sql"], r"D:\SQLBackup\%s_FULL.bak" % database))
            moment += rng.randint(30000, 60000)
            copy = self.spawn(moment, host, "robocopy.exe", r"robocopy.exe D:\SQLBackup \\fs-01\sqlbackup$ *.bak /Z /R:2 /W:5",
                              procs["agent"], "svc_sqlagent")
            self.mark("dba.copy", copy["seq"])
            duration = rng.randint(180000, 300000)
            self.mark("dba.copy", self.bare(moment + 500, host, copy, files.ip, 445, duration, "smb"))
            result = self.logon(moment + 510, files, "svc_sqlagent", 3, source_ip=host.ip, duration=duration,
                                workstation=host.name.upper())
            self.mark("dba.copy_logon", result["4624"])
            self.chain.setdefault("dba", []).append((host.name, ms))

    def account_decoy(self):
        rng = self.rng
        admin, dc = self.by_name["pc-it-01"], self.by_name["dc-tal-01"]
        ms = hms(5, 14) + rng.randint(0, 60000)
        command = ("powershell.exe -NoProfile -Command \"New-ADUser -SamAccountName e.calloway -Description "
                   "'CHG-20417 approved new starter, Manufacturing' -Enabled $true; Add-ADGroupMember -Identity 'MFG Staff' -Members e.calloway\"")
        shell = self.spawn(ms, admin, "powershell.exe", command, admin.procs["explorer"], "adm.morrow")
        self.mark("acct.proc", shell["seq"])
        self.mark("acct.conn", self.bare(ms + 2000, admin, shell, dc.ip, 9389, 4000, "adws"))
        self.mark("acct.logon", self.logon(ms + 2100, dc, "adm.morrow", 3, source_ip=admin.ip, privileged=True,
                                           duration=5000, workstation=admin.name.upper())["4624"])
        self.mark("acct.created", self.account_created(ms + 2600, dc, "adm.morrow", "e.calloway"))
        self.mark("acct.group", self.member_added(ms + 2900, dc, "adm.morrow", "e.calloway", "MFG Staff", "4728"))
        self.chain["acct"] = ms

    def monitoring_install(self):
        rng = self.rng
        monitor = self.by_name["mon-01"]
        ms = hms(5, 20) + rng.randint(0, 60000)
        self.chain["mon_start"] = ms
        image = '"%s" --service' % VIGILAGENT_PATH
        for host in [h for h in self.hosts if h.kind == "server" and h is not monitor]:
            procs = host.procs
            self.mark("mon.conn", self.bare(ms, monitor, monitor.procs["vigil"], host.ip, 445, rng.randint(8000, 20000), "smb"))
            self.mark("mon.logon", self.logon(ms + 40, host, "svc_vigilmon", 3, source_ip=monitor.ip, privileged=True,
                                              duration=15000, workstation=monitor.name.upper())["4624"])
            if host.sysmon:
                self.file_create(ms + 2000, host, procs["system"], r"C:\Windows\Temp\vigilagent-8.2.msi")
                installer = self.spawn(ms + 4000, host, "msiexec.exe", r"msiexec.exe /i C:\Windows\Temp\vigilagent-8.2.msi /qn /norestart",
                                       procs["services"], "SYSTEM")
                self.mark("mon.msi", installer["seq"])
                self.file_create(ms + 9000, host, installer, VIGILAGENT_PATH)
            self.mark("mon.service", self.service_installed(ms + 11000, host, "VigilmonAgent", image))
            if host.sysmon:
                self.spawn(ms + 12000, host, "vigilagent.exe", image, procs["services"], "SYSTEM", executable=VIGILAGENT_PATH)
            ms += rng.randint(20000, 50000)
        self.chain["mon_end"] = ms

    def cdn_uploads(self):
        rng = self.rng
        host = self.by_name["pc-mkt-02"]
        ms = max(hms(5, 45), host.logon + 120000) + rng.randint(0, 60000)
        self.chain["cdn_start"] = ms
        uploader = self.spawn(ms, host, "feupload.exe", '"%s" --profile marketing --watch "C:\\Users\\%s\\Videos\\Exports"' % (
            FEUPLOAD_PATH, host.user), host.procs["explorer"], host.user, executable=FEUPLOAD_PATH)
        self.mark("cdn.proc", uploader["seq"])
        self.mark("cdn.dns", self.dns(ms + 800, host, uploader, B_CDN))
        ms += 900
        total = 0
        for part in range(1, 9):
            size = rng.randint(1000000, 1400000)
            total += size
            conn, record = self.web(ms, host, uploader, B_CDN, "https", "PUT", "/v2/assets/launch-teaser-%02d.mp4" % part, 201,
                                    size, rng.randint(150, 400), "FastEdge-Uploader/3.2", profile="schannel")
            self.mark("cdn.conn", conn)
            self.mark("cdn.proxy", record)
            ms += rng.randint(40000, 90000)
        self.chain.update(cdn_end=ms, cdn_bytes=total)

    # ----- story b intrusion ------------------------------------------------------------------
    def chain_events(self):
        rng, c = self.rng, self.chain
        web, db, dc = self.web_host, self.by_name["db-sql-01"], self.by_name["dc-tal-01"]
        w3wp, t0 = web.procs["w3wp"], self.t0
        probe_ua = "Mozilla/5.0 (compatible; LabProbe/0.9)"
        shell_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) LabBrowser/117.0"
        ms = t0
        c["recon_start"] = ms
        for index in range(45):
            path = "/portal/upload/ImageHandler.ashx" if index == 44 else rng.choice(RECON_PATHS)
            status = {"/portal/login.aspx": 200, "/portal/upload/ImageHandler.ashx": 405}.get(
                path, 403 if path.endswith("/") and rng.random() < 0.3 else 404)
            self.mark("chain.recon", self.inbound(ms, B_ATTACKER, path, "GET", status, 0, rng.randint(200, 1400), probe_ua))
            last = ms
            ms += rng.randint(1200, 4500)
        c["recon_end"] = last
        ms = t0 + 190000 + rng.randint(0, 5000)
        self.mark("chain.exploit", self.inbound(ms, B_ATTACKER, "/portal/upload/ImageHandler.ashx?type=thumb", "POST", 200,
                                                rng.randint(40000, 52000), 310, shell_ua))
        self.mark("chain.webshell_file", self.file_create(ms + 1200, web, w3wp, WEBSHELL_PATH))
        c["exploit"] = ms
        placeholder = "# lab placeholder only: fetch tunnel component from %s into C:\\ProgramData\\ThumbCache; no functional content" % B_STAGE
        encoded = base64.b64encode(placeholder.encode("utf-16-le")).decode("ascii")
        steps = (
            ("whoami", "cmd.exe", "cmd.exe /c whoami /all"),
            ("ipconfig", "cmd.exe", "cmd.exe /c ipconfig /all"),
            ("groups", "cmd.exe", 'cmd.exe /c net localgroup "SQL Server Admins" /domain'),
            ("download", "powershell.exe", "powershell.exe -nop -w hidden -enc " + encoded),
            ("create", "cmd.exe", 'cmd.exe /c sc create ThumbCacheSvc binPath= "%s" start= auto DisplayName= "Thumbnail Cache Helper"' % TNLSVC_PATH),
            ("start", "cmd.exe", "cmd.exe /c sc start ThumbCacheSvc"),
            ("user", "cmd.exe", "cmd.exe /c net user supportsvc /add /domain /passwordreq:yes"),
            ("group", "cmd.exe", 'cmd.exe /c net localgroup "SQL Server Admins" supportsvc /add /domain'),
        )
        ms = t0 + 240000 + rng.randint(0, 5000)
        c["shell_start"] = ms
        tunnel = None
        for key, name, command in steps:
            self.mark("chain.webshell_req", self.inbound(ms, B_ATTACKER, "/portal/uploads/thumbs/t3.aspx", "POST", 200,
                                                         rng.randint(300, 900), rng.randint(200, 4000), shell_ua))
            child = self.spawn(ms + 300, web, name, command, w3wp, "svc_portal")
            self.mark("chain.webshell_child", child["seq"])
            if key == "download":
                self.mark("chain.download_dns", self.dns(ms + 900, web, child, B_STAGE, ttl=60))
                conn, record = self.web(ms + 906, web, child, B_STAGE, "https", "GET", "/d/7c21/thumbcache.bin", 200, 0,
                                        180224, PS_UA, profile="schannel")
                self.mark("chain.download_conn", conn)
                self.mark("chain.download_proxy", record)
                self.mark("chain.tnl_file", self.file_create(ms + 4000, web, child, TNLSVC_PATH))
            elif key in ("create", "start"):
                sc = self.spawn(ms + 450, web, "sc.exe", command.split("/c ", 1)[1], child, "svc_portal")
                self.mark("chain.sc", sc["seq"])
                if key == "create":
                    self.mark("chain.service", self.service_installed(ms + 1200, web, "ThumbCacheSvc", TNLSVC_PATH))
                else:
                    tunnel = self.spawn(ms + 1500, web, "tnlsvc.exe", TNLSVC_PATH, web.procs["services"], "SYSTEM",
                                        executable=TNLSVC_PATH, sha=TNLSVC_SHA256)
                    self.mark("chain.tnl_proc", tunnel["seq"])
                    c["tunnel_start"] = ms + 1500
            elif key in ("user", "group"):
                net = self.spawn(ms + 450, web, "net.exe", command.split("/c ", 1)[1], child, "svc_portal")
                self.mark("chain.net", net["seq"])
                if key == "user":
                    self.logon(ms + 700, dc, "svc_portal", 3, source_ip=web.ip, duration=3000, workstation=web.name.upper())
                    self.mark("chain.acct_created", self.account_created(ms + 900, dc, "svc_portal", "supportsvc"))
                    c["account"] = ms + 900
                else:
                    self.mark("chain.acct_group", self.member_added(ms + 900, dc, "svc_portal", "supportsvc", "SQL Server Admins", "4732"))
            c["shell_end"] = ms + 300
            ms += rng.randint(20000, 60000)
        # Tunnel relay polling for the rest of the window.
        polls = []
        ms = c["tunnel_start"] + rng.randint(5000, 15000)
        while ms < self.end - 30000:
            self.mark("chain.relay_dns", self.dns(ms, web, tunnel, B_RELAY, ttl=60))
            conn, record = self.web(ms + 5, web, tunnel, B_RELAY, "https", "POST", "/api/session/poll", 200,
                                    rng.randint(300, 700), rng.randint(200, 1500), shell_ua, profile="agent")
            self.mark("chain.relay_conn", conn)
            self.mark("chain.relay_proxy", record)
            polls.append(ms)
            ms += rng.randint(80000, 160000)
        c["polls"] = len(polls)
        # RDP through the tunnel to the database server with the new account.
        ms = t0 + 25 * 60000 + rng.randint(0, 30000)
        self.mark("chain.rdp_conn", self.bare(ms, web, tunnel, db.ip, 3389, 30 * 60000, "rdp"))
        result = self.logon(ms + 2500, db, "supportsvc", 10, source_ip=web.ip, auth="Negotiate", privileged=True,
                            duration=30 * 60000 - 3000, workstation=web.name.upper())
        self.mark("chain.rdp_logon", result["4624"])
        self.mark("chain.rdp_priv", result["4672"])
        c["rdp"] = ms + 2500
        init = self.spawn(ms + 3000, db, "userinit.exe", r"C:\Windows\system32\userinit.exe", db.procs["services"], "supportsvc")
        explorer = self.spawn(ms + 3500, db, "explorer.exe", r"C:\Windows\Explorer.EXE", init, "supportsvc")
        self.spawn(ms + 5000, db, "rdpclip.exe", "rdpclip", explorer, "supportsvc")
        # Database dump staged in a public profile folder, then compressed.
        ms = t0 + 30 * 60000 + rng.randint(0, 30000)
        shell = self.spawn(ms, db, "cmd.exe", '"C:\\Windows\\system32\\cmd.exe"', explorer, "supportsvc")
        dump = self.spawn(ms + 40000, db, "sqlcmd.exe",
                          "sqlcmd.exe -S localhost -E -Q \"BACKUP DATABASE [CustomerOrders] TO DISK='C:\\Users\\Public\\Libraries\\co_full.bak' WITH COPY_ONLY, COMPRESSION\"",
                          shell, "supportsvc", executable=SQLCMD_PATH)
        self.mark("chain.dump_cmd", dump["seq"])
        self.mark("chain.dump_file", self.file_create(ms + 85000, db, db.procs["sql"], r"C:\Users\Public\Libraries\co_full.bak"))
        packer = self.spawn(ms + 200000, db, "powershell.exe",
                            r'powershell.exe -nop -c "Compress-Archive -Path C:\Users\Public\Libraries\co_full.bak -DestinationPath C:\Users\Public\Libraries\co_full.zip"',
                            shell, "supportsvc")
        self.mark("chain.zip_cmd", packer["seq"])
        self.mark("chain.zip_file", self.file_create(ms + 215000, db, packer, r"C:\Users\Public\Libraries\co_full.zip"))
        c["dump"] = ms + 40000
        # Exfiltration: large HTTPS POSTs to the lookalike storage host.
        ms = t0 + 38 * 60000 + rng.randint(0, 30000)
        sender = self.spawn(ms, db, "powershell.exe",
                            'powershell.exe -nop -w hidden -c "# lab placeholder only: send co_full.zip in parts to %s; no functional content"' % B_STAGE,
                            shell, "supportsvc")
        self.mark("chain.exfil_proc", sender["seq"])
        self.mark("chain.exfil_dns", self.dns(ms + 700, db, sender, B_STAGE, ttl=60))
        ms += 800
        c["exfil_start"], total = ms, 0
        for part in range(1, 11):
            size = rng.randint(1100000, 1300000)
            total += size
            conn, record = self.web(ms, db, sender, B_STAGE, "https", "POST", "/u/7c21/part-%02d" % part, 200, size,
                                    rng.randint(120, 300), PS_UA, profile="schannel")
            self.mark("chain.exfil_conn", conn)
            self.mark("chain.exfil_proxy", record)
            last = ms
            ms += rng.randint(25000, 45000)
        c.update(exfil_end=last, exfil_bytes=total)
        if last >= self.end - 60000:
            raise ValueError("storyline does not fit the window")

    def facts(self):
        c = self.chain
        web, db, dc = self.web_host, self.by_name["db-sql-01"], self.by_name["dc-tal-01"]
        dba_hosts = sorted(name for name, _ in c.get("dba", []))
        monitored = sorted(h.name for h in self.hosts if h.kind == "server" and h.name != "mon-01")

        fact = self.fact

        return [
            fact("attack.recon.portal-path-probing", "attack",
                 "From %s to %s UTC %s sent 45 GET requests for portal administration, upload and configuration paths on %s with a probing user agent; most returned 404/403, and the upload handler answered 405." % (clock(c["recon_start"]), clock(c["recon_end"]), B_ATTACKER, PUBLIC_SITE),
                 {"hosts": ["web-ext-01"], "domains": [PUBLIC_SITE], "ips": [B_ATTACKER]}, [("chain.recon",)]),
            fact("attack.initial-access.upload-handler-webshell", "attack",
                 "At %s UTC the same address POSTed about 45 KB to /portal/upload/ImageHandler.ashx?type=thumb and w3wp.exe then wrote t3.aspx into the thumbs upload folder; legitimate uploads only create .jpg files under uploads\\images." % clock(c["exploit"]),
                 {"hosts": ["web-ext-01"], "processes": ["w3wp.exe"], "ips": [B_ATTACKER]},
                 [("chain.exploit",), ("chain.webshell_file",)]),
            fact("attack.execution.webshell-commands", "attack",
                 "Between %s and %s UTC each POST to /portal/uploads/thumbs/t3.aspx from %s was followed within a second by w3wp.exe (svc_portal) starting cmd.exe or powershell.exe: whoami, ipconfig, SQL Server Admins group lookup, an encoded download, service creation and account creation." % (clock(c["shell_start"]), clock(c["shell_end"]), B_ATTACKER),
                 {"hosts": ["web-ext-01"], "users": ["svc_portal"], "processes": ["w3wp.exe", "cmd.exe", "powershell.exe"], "ips": [B_ATTACKER]},
                 [("chain.webshell_req",), ("chain.webshell_child",)]),
            fact("attack.persistence.tunnel-service", "attack",
                 "The webshell's powershell.exe resolved %s (%s), downloaded thumbcache.bin and wrote %s; sc.exe then created the auto-start service ThumbCacheSvc (7045) and started tnlsvc.exe as SYSTEM under services.exe." % (B_STAGE, B_STAGE_IP, TNLSVC_PATH),
                 {"hosts": ["web-ext-01"], "processes": ["powershell.exe", "sc.exe", "tnlsvc.exe"], "domains": [B_STAGE], "ips": [B_STAGE_IP]},
                 [("chain.download_dns",), ("chain.download_conn", "chain.download_proxy"), ("chain.tnl_file",),
                  ("chain.service",), ("chain.tnl_proc",)]),
            fact("attack.c2.tunnel-relay-polling", "attack",
                 "From %s UTC tnlsvc.exe on web-ext-01 resolved %s and made %d small HTTPS POSTs to /api/session/poll at %s every 80-160 seconds until the window end." % (clock(c["tunnel_start"]), B_RELAY, c["polls"], B_RELAY_IP),
                 {"hosts": ["web-ext-01"], "processes": ["tnlsvc.exe"], "domains": [B_RELAY], "ips": [B_RELAY_IP]},
                 [("chain.relay_dns",), ("chain.relay_conn", "chain.relay_proxy")]),
            fact("attack.persistence.domain-account", "attack",
                 "At %s UTC net.exe under the webshell created the domain account supportsvc; dc-tal-01 logged 4720 with subject svc_portal (the web application pool identity) and then 4732 adding supportsvc to the domain local group SQL Server Admins. There is no change ticket wording." % clock(c["account"]),
                 {"hosts": ["web-ext-01", "dc-tal-01"], "users": ["svc_portal", "supportsvc"], "processes": ["net.exe"]},
                 [("chain.net",), ("chain.acct_created",), ("chain.acct_group",)]),
            fact("attack.lateral.rdp-to-database", "attack",
                 "At %s UTC db-sql-01 logged a type 10 (RDP) logon with special privileges for the new supportsvc account from web-ext-01 (%s); on web-ext-01 the connection to %s:3389 was made by tnlsvc.exe, not by mstsc.exe." % (clock(c["rdp"]), web.ip, db.ip),
                 {"hosts": ["web-ext-01", "db-sql-01"], "users": ["supportsvc"], "processes": ["tnlsvc.exe"], "ips": [web.ip, db.ip]},
                 [("chain.rdp_conn",), ("chain.rdp_logon", "chain.rdp_priv")]),
            fact("attack.collection.database-dump", "attack",
                 "At %s UTC supportsvc ran sqlcmd.exe to back up CustomerOrders WITH COPY_ONLY to C:\\Users\\Public\\Libraries\\co_full.bak (written by sqlservr.exe), then powershell.exe compressed it to co_full.zip; the scheduled jobs write to D:\\SQLBackup instead." % clock(c["dump"]),
                 {"hosts": ["db-sql-01"], "users": ["supportsvc"], "processes": ["sqlcmd.exe", "sqlservr.exe", "powershell.exe"]},
                 [("chain.dump_cmd",), ("chain.dump_file",), ("chain.zip_cmd", "chain.zip_file")]),
            fact("attack.exfiltration.https-post", "attack",
                 "From %s to %s UTC powershell.exe on db-sql-01 resolved %s and sent 10 HTTPS POSTs to /u/7c21/part-NN totalling %d request bytes at the gateway; the domain imitates the %s file service used by staff." % (clock(c["exfil_start"]), clock(c["exfil_end"]), B_STAGE, c["exfil_bytes"], B_STORAGE),
                 {"hosts": ["db-sql-01"], "users": ["supportsvc"], "processes": ["powershell.exe"], "domains": [B_STAGE], "ips": [B_STAGE_IP]},
                 [("chain.exfil_dns",), ("chain.exfil_conn", "chain.exfil_proxy")]),
            fact("decoy.ticketed-account-creation", "decoy",
                 "At %s UTC adm.morrow on pc-it-01 ran New-ADUser for e.calloway with the description 'CHG-20417 approved new starter' and added it to MFG Staff; dc-tal-01 logged the matching Kerberos logon, 4720 and 4728. Normal IT provisioning, unlike the svc_portal-created account." % clock(c["acct"]),
                 {"hosts": ["pc-it-01"], "users": ["adm.morrow", "e.calloway"], "processes": ["powershell.exe"]},
                 [("acct.proc",), ("acct.created",), ("acct.group",)]),
            fact("decoy.monitoring-agent-service", "decoy",
                 "From %s to %s UTC mon-01 connected over SMB to every other server as svc_vigilmon, ran msiexec.exe for vigilagent-8.2.msi and installed the VigilmonAgent service (7045). A fleet-wide agent rollout from the monitoring server, not the tunnel service." % (clock(c["mon_start"]), clock(c["mon_end"])),
                 {"hosts": ["mon-01"], "users": ["svc_vigilmon"], "processes": ["msiexec.exe", "vigilagent.exe"]},
                 [("mon.service",), ("mon.logon",)]),
            fact("decoy.dba-scheduled-backup", "decoy",
                 "SQLAGENT.EXE on %s ran the nightly sqlcmd job as svc_sqlagent, wrote full backups to D:\\SQLBackup and copied them to fs-01 with robocopy. Scheduled database backups, not the dump." % ", ".join(dba_hosts),
                 {"hosts": dba_hosts + ["fs-01"], "users": ["svc_sqlagent"], "processes": ["SQLAGENT.EXE", "robocopy.exe"]},
                 [("dba.job",), ("dba.file",), ("dba.copy",)]),
            fact("decoy.cdn-large-uploads", "decoy",
                 "From %s UTC feupload.exe run by l.ostrander on pc-mkt-02 PUT eight ~1.2 MB video parts (%d bytes total) to %s (%s). Large outbound HTTPS from a marketing workstation, but it is the CDN uploader." % (clock(c["cdn_start"]), c["cdn_bytes"], B_CDN, B_CDN_IP),
                 {"hosts": ["pc-mkt-02"], "users": ["l.ostrander"], "processes": ["feupload.exe"], "domains": [B_CDN], "ips": [B_CDN_IP]},
                 [("cdn.proc",), ("cdn.conn", "cdn.proxy")]),
            fact("benign.edr-lsass-access", "benign-pattern",
                 "bwsensor.exe (Brightwall EDR) opens lsass.exe with GrantedAccess 0x1400 about every 20 minutes on every Sysmon host; there is no credential-dumping step in this intrusion.",
                 {"processes": ["bwsensor.exe", "lsass.exe"]}, [("av.lsass",)]),
            fact("benign.internet-background-scanning", "benign-pattern",
                 "%d unrelated internet addresses requested generic paths such as /wp-login.php and /.env on %s, all 404, with no follow-up; unlike %s they never touched portal upload paths." % (len(self.scanner_ips), PUBLIC_SITE, B_ATTACKER),
                 {"ips": self.scanner_ips}, [("web.scan",)]),
            fact("coverage.iis-no-bodies", "coverage",
                 "IIS records lack request and response bodies, so the exploit payload, the webshell's input and the command output cannot be read; only timing ties each t3.aspx POST to a w3wp.exe child process.",
                 {"hosts": ["web-ext-01"], "processes": ["w3wp.exe"]}, [("gap.iis",)]),
            fact("coverage.no-sql-audit", "coverage",
                 "Without SQL Server audit logs, which tables or rows left in co_full.bak cannot be confirmed beyond the database named on the sqlcmd.exe command line.",
                 {"hosts": ["db-sql-01"], "processes": ["sqlservr.exe"]}, [("gap.sql",)]),
            fact("coverage.no-rdp-content", "coverage",
                 "Nothing records what supportsvc saw or typed during the RDP session on db-sql-01; actions are inferred from process and file records only.",
                 {"hosts": ["db-sql-01"], "users": ["supportsvc"]}, [("gap.rdp",)]),
        ]

    def intel(self):
        feeds = ("SynthIntel Open Feed", "Lab Community Blocklist", "Training Sandbox Reports", "Demo Reputation Service")
        docs = [
            ("domain", B_STAGE, "high", feeds[0], "Recently registered domain imitating a file-sharing service; used for tool downloads and bulk uploads in synthetic reports.", "2025-10-06"),
            ("domain", B_RELAY, "medium", feeds[2], "Relay endpoint for a synthetic tunnelling utility that polls over HTTPS.", "2025-10-01"),
            ("ip", B_ATTACKER, "medium", feeds[1], "Source of web application path probing in a synthetic honeypot feed.", "2025-09-25"),
            ("hash", TNLSVC_SHA256, "high", feeds[2], "Synthetic tunnelling service binary that forwards inbound sessions through an HTTPS relay.", "2025-10-08"),
            ("file_name", "t3.aspx", "low", feeds[1], "Short ASPX file name reported in several synthetic web-shell write-ups; the name alone is weak evidence.", "2025-06-11"),
            ("domain", B_CDN, "low", feeds[3], "Content-delivery ingest host listed by a synthetic heuristic for large uploads; unverified.", "2025-07-19"),
            ("file_name", "vigilagent.exe", "low", feeds[3], "Monitoring agent name seen in a synthetic report on remote-administration tools; likely a collision.", "2025-04-22"),
            ("ip", self.scanner_ips[0], "low", feeds[1], "Internet-wide survey scanner address in a synthetic feed.", "2025-08-30"),
            ("domain", B_STORAGE, "low", feeds[3], "Popular file-sharing service flagged by an automated synthetic heuristic; not confirmed.", "2025-09-12"),
        ]
        return self.intel_documents(docs, feeds)


STORIES = {"a": Scenario, "b": StoryB}


class PcapRenderer:
    """Streams sessions as time-ordered Ethernet/IPv4 frames into a classic pcap."""

    def __init__(self, handle, seed):
        self.handle = handle
        self.rng = random.Random("pcap:%d" % seed)
        self.digest = hashlib.sha256()
        self.size = 0
        self.packets = 0
        self.ip_id = 0
        self._write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))

    def _write(self, data):
        self.handle.write(data)
        self.digest.update(data)
        self.size += len(data)

    def ip_frame(self, source, destination, protocol, payload):
        self.ip_id = (self.ip_id + 1) & 0xFFFF
        ttl = 128 if is_internal(source) else 54
        header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), self.ip_id, 0x4000, ttl, protocol, 0,
                             packed_ip(source), packed_ip(destination))
        header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
        frame = mac_for(destination) + mac_for(source) + b"\x08\x00" + header + payload
        return frame + b"\x00" * (60 - len(frame)) if len(frame) < 60 else frame

    def udp(self, source, sport, destination, dport, payload):
        header = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0)
        pseudo = packed_ip(source) + packed_ip(destination) + struct.pack("!BBH", 0, 17, 8 + len(payload))
        value = checksum(pseudo + header + payload) or 0xFFFF
        return self.ip_frame(source, destination, 17, header[:6] + struct.pack("!H", value) + payload)

    def tcp(self, source, sport, destination, dport, seq, ack, flags, payload=b"", syn=False):
        options = b"\x02\x04\x05\xb4\x01\x01\x04\x02" if syn else b""
        length = 20 + len(options)
        header = struct.pack("!HHIIBBHHH", sport, dport, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF, (length // 4) << 4,
                             flags, 64240, 0, 0) + options
        pseudo = packed_ip(source) + packed_ip(destination) + struct.pack("!BBH", 0, 6, length + len(payload))
        value = checksum(pseudo + header + payload)
        return self.ip_frame(source, destination, 6, header[:16] + struct.pack("!H", value) + header[18:] + payload)

    def records(self, count, record_type=0x17):
        out = []
        while count > 0:
            size = min(count, 16384)
            out.append(struct.pack("!BHH", record_type, 0x0303, size) + self.rng.randbytes(size))
            count -= size
        return b"".join(out)

    def render(self, session):
        start, _, kind, client, cport, server, sport, rtt, data = session
        t = start * 1000
        if kind == "dns":
            return self.render_dns(t, client, cport, server, rtt, data)
        if kind == "ntp":
            query = b"\x23" + b"\x00" * 39 + struct.pack("!II", DAY_SECONDS + 2208988800 + start // 1000, 0)
            reply = b"\x24\x03\x06\xec" + b"\x00" * 36 + struct.pack("!II", DAY_SECONDS + 2208988800 + start // 1000, 1)
            return [(t, self.udp(client, cport, server, sport, query)), (t + 600, self.udp(server, sport, client, cport, reply))]
        out = []
        r = rtt * 1000
        c_seq, s_seq = self.rng.getrandbits(32), self.rng.getrandbits(32)
        out.append((t, self.tcp(client, cport, server, sport, c_seq, 0, 0x02, syn=True)))
        if kind == "rst":
            out.append((t + r, self.tcp(server, sport, client, cport, 0, c_seq + 1, 0x14)))
            return out
        c_seq += 1
        out.append((t + r, self.tcp(server, sport, client, cport, s_seq, c_seq, 0x12, syn=True)))
        s_seq += 1
        out.append((t + r + 50, self.tcp(client, cport, server, sport, c_seq, s_seq, 0x10)))
        if kind == "bare":
            moment = t + data * 1000
        else:
            moment = t + r + 1000
            if kind == "tls":
                sni, profile, request_bytes, response_bytes = data
                hello = client_hello(sni, profile, self.rng.randbytes(32), self.rng.randbytes(32), self.rng.randbytes(32))
                c_seq, moment = self.data(out, moment, client, cport, server, sport, c_seq, s_seq, hello)
                flight = server_hello(self.rng.randbytes(32), hello[44:76], self.rng.randbytes(32)) + self.records(1100)
                s_seq, moment = self.data(out, moment + r, server, sport, client, cport, s_seq, c_seq, flight)
                upload = b"\x14\x03\x03\x00\x01\x01" + self.records(request_bytes)
                c_seq, moment = self.data(out, moment + 300, client, cport, server, sport, c_seq, s_seq, upload)
                s_seq, moment = self.data(out, moment + r, server, sport, client, cport, s_seq, c_seq, self.records(response_bytes))
            else:
                request, request_body, head, response_body = data
                body = (FILLER * (request_body // len(FILLER) + 1))[:request_body]
                c_seq, moment = self.data(out, moment, client, cport, server, sport, c_seq, s_seq, request + body)
                reply = head + (FILLER * (response_body // len(FILLER) + 1))[:response_body]
                s_seq, moment = self.data(out, moment + r, server, sport, client, cport, s_seq, c_seq, reply)
            out.append((moment + 100, self.tcp(client, cport, server, sport, c_seq, s_seq, 0x10)))
            moment += 1000
        out.append((moment, self.tcp(client, cport, server, sport, c_seq, s_seq, 0x11)))
        out.append((moment + r, self.tcp(server, sport, client, cport, s_seq, c_seq + 1, 0x11)))
        out.append((moment + r + 50, self.tcp(client, cport, server, sport, c_seq + 1, s_seq + 1, 0x10)))
        return out

    def data(self, out, moment, source, sport, destination, dport, seq, ack, payload):
        total = len(payload)
        for index, offset in enumerate(range(0, total, 1460)):
            segment = payload[offset:offset + 1460]
            last = offset + 1460 >= total
            out.append((moment, self.tcp(source, sport, destination, dport, seq, ack, 0x18 if last else 0x10, segment)))
            seq += len(segment)
            if index % 16 == 15 and not last:
                out.append((moment + 5, self.tcp(destination, dport, source, sport, ack, seq, 0x10)))
            moment += 15
        return seq, moment

    def render_dns(self, t, client, cport, server, delay, data):
        name, qtype, answers, rcode, ttl, txid = data
        code = 16 if qtype == "TXT" else 1
        question = dns_name(name) + struct.pack("!HH", code, 1)
        query = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0) + question
        flags = 0x8180 if rcode == "NOERROR" else 0x8183
        response = struct.pack("!HHHHHH", txid, flags, 1, len(answers), 0, 0) + question
        for value in answers:
            if code == 1:
                rdata = packed_ip(value)
            else:
                text = value.encode("ascii")
                rdata = bytes([len(text)]) + text
            response += b"\xc0\x0c" + struct.pack("!HHIH", code, 1, ttl, len(rdata)) + rdata
        return [(t, self.udp(client, cport, server, 53, query)),
                (t + delay * 1000, self.udp(server, 53, client, cport, response))]

    def write_all(self, sessions, window_end_us, tracked=frozenset()):
        """Write every frame; for sessions in tracked, record their 1-based frame numbers (tshark frame.number)."""
        self.frames = {index: [] for index in tracked}
        sessions.sort(key=lambda item: (item[0], item[1]))
        heap = []
        counter = 0
        for session in sessions:
            threshold = session[0] * 1000
            while heap and heap[0][0] <= threshold:
                self.emit(heapq.heappop(heap), window_end_us)
            for moment, frame in self.render(session):
                counter += 1
                heapq.heappush(heap, (moment, counter, session[1], frame))
        while heap:
            self.emit(heapq.heappop(heap), window_end_us)

    def emit(self, item, window_end_us):
        moment, _, session, frame = item
        if moment >= window_end_us:
            raise ValueError("packet outside the case window")
        seconds, micros = divmod(moment, 1000000)
        self._write(struct.pack("<IIII", DAY_SECONDS + seconds, micros, len(frame), len(frame)))
        self._write(frame)
        self.packets += 1
        if session in self.frames:
            self.frames[session].append(self.packets)


def json_bytes(value):
    return (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n").encode("utf-8")


def prepare_directory(path):
    if path.is_symlink() or (path.exists() and not path.is_dir()):
        raise ValueError("output path exists and is not a directory: " + str(path))
    if path.exists() and any(path.iterdir()):
        raise ValueError("refusing to write into a non-empty directory: " + str(path))


def generate(size, seed, case_id, evidence_dir, truth_dir, story="a"):
    if story not in STORIES:
        raise ValueError("unknown story: " + str(story))
    if size not in SIZES:
        raise ValueError("unknown size: " + str(size))
    if type(seed) is not int:
        raise ValueError("seed must be an integer")
    if not isinstance(case_id, str) or not CASE_ID_PATTERN.match(case_id):
        raise ValueError("case id must match [a-z0-9-]{3,64}")
    evidence = Path(evidence_dir).resolve()
    operator = Path(truth_dir).resolve()
    if evidence == operator or evidence in operator.parents or operator in evidence.parents:
        raise ValueError("evidence and truth directories must be separate, non-nested paths")
    prepare_directory(evidence)
    prepare_directory(operator)

    scenario = STORIES[story](size, seed, case_id)
    scenario.build()
    scenario.ordered_rows()
    facts = scenario.facts()
    scenario.cite_siblings(facts)
    intel = scenario.intel()
    tracked = scenario.link_sessions()
    truth = {"schema_version": SCHEMA_VERSION, "case_id": case_id, "facts": facts,
             "interpretation_boundary": "Operator-only key for an invented scenario. Facts describe observable records and the storyline behind them; benign alternatives are labelled decoy or benign-pattern. Scoring by citation and keyword matching is not a judgment of analytic quality."}

    created_dirs = [path for path in (evidence, operator) if not path.exists()]
    evidence.mkdir(parents=True, exist_ok=True)
    operator.mkdir(parents=True, exist_ok=True)
    written = []
    files = {}

    def write_file(path, data):
        with path.open("xb") as handle:
            written.append(path)
            handle.write(data)
        files[path.name] = {"path": str(path), "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}

    try:
        path = evidence / "events.jsonl"
        digest, size_bytes = hashlib.sha256(), 0
        with path.open("xb") as handle:
            written.append(path)
            chunk = []
            for _, seq, line in scenario.rows:
                chunk.append(line.replace(ID_PLACEHOLDER, '"%s"' % scenario.event_ids[seq], 1) + "\n")
                if len(chunk) >= 5000:
                    data = "".join(chunk).encode("utf-8")
                    handle.write(data)
                    digest.update(data)
                    size_bytes += len(data)
                    chunk = []
            data = "".join(chunk).encode("utf-8")
            handle.write(data)
            digest.update(data)
            size_bytes += len(data)
        files[path.name] = {"path": str(path), "bytes": size_bytes, "sha256": digest.hexdigest()}
        event_count = len(scenario.rows)
        scenario.rows = []

        session_kinds = Counter(session[2] for session in scenario.sessions)
        session_count = len(scenario.sessions)
        path = evidence / "traffic.pcap"
        with path.open("xb") as handle:
            written.append(path)
            renderer = PcapRenderer(handle, seed)
            renderer.write_all(scenario.sessions, scenario.end * 1000, tracked)
        files[path.name] = {"path": str(path), "bytes": renderer.size, "sha256": renderer.digest.hexdigest()}

        write_file(evidence / "intel.jsonl",
                   b"".join((json.dumps(doc, sort_keys=True) + "\n").encode("utf-8") for doc in intel))
        write_file(evidence / "case.json", json_bytes(scenario.case_metadata(event_count, renderer.packets, session_count, len(intel))))
        scenario.cite_alternatives(facts, renderer.frames, intel)
        write_file(operator / "truth.json", json_bytes(truth))
    except BaseException:
        for path in written:
            path.unlink(missing_ok=True)
        for path in created_dirs:
            try:
                path.rmdir()
            except OSError:
                pass
        raise

    return {
        "schema_version": SCHEMA_VERSION, "case_id": case_id, "story": story, "size": size, "seed": seed,
        "time_range_utc": {"start_inclusive": iso(scenario.start)[:-5] + "Z", "end_exclusive": iso(scenario.end)[:-5] + "Z"},
        "hosts": len(scenario.hosts), "event_count": event_count,
        "events_by_family": dict(sorted(scenario.family.items())),
        "sessions": {"total": session_count, "by_kind": dict(sorted(session_kinds.items()))},
        "packets": renderer.packets, "intel_indicators": len(intel),
        "facts": {"total": len(facts), "by_kind": dict(sorted(Counter(f["kind"] for f in facts).items()))},
        "files": files,
    }


# ----- operator scoring ----------------------------------------------------------------
EVENT_ID = re.compile(r"\bevt-\d{6,}\b")
FRAME_ID = re.compile(r"\bframe-(\d+)\b", re.IGNORECASE)
INTEL_ID = re.compile(r"\bioc-\d{5,}\b")
# Optional per-fact lists parallel to evidence_event_groups; each entry is another way to cite that group.
ALTERNATIVE_GROUPS = (("evidence_frame_groups", "cited_frames"), ("evidence_intel_groups", "cited_intel_ids"))
# Optional per-fact list parallel to evidence_event_groups: events of the same process and event category as a
# group's events. They count only toward the separate with_siblings score; the strict score never reads them.
SIBLING_GROUPS = "evidence_sibling_groups"
COMPROMISE_TERMS = ("malicious", "compromise", "compromised", "attacker", "adversary", "intrusion", "threat actor",
                    "command-and-control", "command and control", "c2", "exfiltration", "exfiltrate", "exfiltrated",
                    "lateral movement", "backdoor", "implant", "brute force", "brute-force", "password spray", "malware")
BENIGN_TERMS = ("benign", "legitimate", "authorized", "authorised", "expected", "false positive", "not malicious",
                "routine", "sanctioned", "scheduled backup", "administrative", "approved", "normal", "not an attack",
                "not compromise", "no evidence of compromise")


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key: " + key)
        result[key] = value
    return result


def load_json_text(text):
    stripped = text.strip()
    fence = re.match(r"^```[A-Za-z0-9_-]*\s*\n(.*)\n```$", stripped, re.S)
    if fence:
        stripped = fence.group(1)

    def invalid_constant(value):
        raise ValueError("non-finite JSON number: " + value)
    return json.loads(stripped, object_pairs_hook=unique_object, parse_constant=invalid_constant)


def text_of(value):
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return "\n".join(text_of(item) for item in value)
    if isinstance(value, dict):
        return "\n".join(text_of(item) for item in value.values())
    return ""


def names(text, value):
    return re.search(r"(?<![A-Za-z0-9_.-])%s(?![A-Za-z0-9_-]|\.[A-Za-z0-9])" % re.escape(value.lower()), text) is not None


def has_term(text, terms):
    return [term for term in terms if re.search(r"(?<![a-z0-9])%s(?![a-z0-9])" % re.escape(term), text)]


def cited_ids(text):
    """Event IDs, frame-<n> citations normalised to tshark's frame.number, and intel record IDs."""
    return (set(EVENT_ID.findall(text)) | {"frame-%d" % int(number) for number in FRAME_ID.findall(text)}
            | set(INTEL_ID.findall(text)))


def validate_truth(truth):
    if not isinstance(truth, dict) or truth.get("schema_version") != SCHEMA_VERSION or not isinstance(truth.get("facts"), list):
        raise ValueError("truth must be a scenario truth.json with schema_version 1 and facts")
    for fact in truth["facts"]:
        if not isinstance(fact, dict) or not {"fact_id", "kind", "entities", "evidence_event_groups"} <= set(fact):
            raise ValueError("truth fact is missing required keys")
        if not fact["evidence_event_groups"] or not all(isinstance(g, list) and g for g in fact["evidence_event_groups"]):
            raise ValueError("truth fact %s has empty evidence groups" % fact["fact_id"])
        for key in [key for key, _ in ALTERNATIVE_GROUPS] + [SIBLING_GROUPS]:
            if key in fact and not (isinstance(fact[key], list) and len(fact[key]) == len(fact["evidence_event_groups"])
                                    and all(isinstance(g, list) and all(isinstance(i, str) for i in g) for g in fact[key])):
                raise ValueError("truth fact %s has malformed %s" % (fact["fact_id"], key))


def tally(details, blamed, status):
    """(found, by_kind, decoys_cleared) over fact details, reading each fact's (found, cited_groups) via status."""
    found, by_kind, decoys_cleared = 0, {}, 0
    for detail in details:
        fact_found, cited_groups = status(detail)
        found += int(fact_found)
        bucket = by_kind.setdefault(detail["kind"], {"total": 0, "found": 0, "partial": 0})
        bucket["total"] += 1
        bucket["found"] += int(fact_found)
        bucket["partial"] += int(not fact_found and bool(cited_groups))
        decoys_cleared += int(detail["kind"] == "decoy" and fact_found and detail["fact_id"] not in blamed)
    return found, by_kind, decoys_cleared


def score_report(truth, report):
    validate_truth(truth)
    if not isinstance(report, dict) or not isinstance(report.get("claims"), list):
        raise ValueError("report must be a JSON object with a claims list")
    claims = [claim for claim in report["claims"] if isinstance(claim, dict)]
    claim_text = "\n".join(text_of(claim) for claim in claims)
    limitation_text = text_of(report.get("limitations", []))
    claim_ids = cited_ids(claim_text)
    limitation_ids = cited_ids(limitation_text)
    attack_entities = {value.lower() for fact in truth["facts"] if fact["kind"] == "attack"
                       for values in fact["entities"].values() for value in values}
    details, misattributed = [], []
    with_siblings = any(SIBLING_GROUPS in fact for fact in truth["facts"])
    for fact in truth["facts"]:
        coverage = fact["kind"] == "coverage"
        cited = claim_ids | limitation_ids if coverage else claim_ids
        text = (claim_text + "\n" + limitation_text if coverage else claim_text).lower()
        groups = fact["evidence_event_groups"]
        alternatives = [(key, label) for key, label in ALTERNATIVE_GROUPS if key in fact]
        accepted = [set(group).union(*(fact[key][index] for key, _ in alternatives)) for index, group in enumerate(groups)]
        covered = [index for index, ids in enumerate(accepted) if cited & ids]
        entities = sorted({value for values in fact["entities"].values() for value in values})
        named = [value for value in entities if names(text, value)]
        detail = {"fact_id": fact["fact_id"], "kind": fact["kind"],
                  "found": len(covered) == len(groups) and bool(named),
                  "cited_groups": covered, "missing_groups": [i for i in range(len(groups)) if i not in covered],
                  "cited_event_ids": sorted(cited & {eid for group in groups for eid in group}),
                  "entities_named": named}
        for key, label in alternatives:
            # (length, text) puts frame-9 before frame-10.
            detail[label] = sorted(cited & {item for group in fact[key] for item in group}, key=lambda item: (len(item), item))
        if with_siblings:
            siblings = fact.get(SIBLING_GROUPS) or [[] for _ in groups]
            wider = [index for index, ids in enumerate(accepted) if cited & (ids | set(siblings[index]))]
            detail["cited_sibling_ids"] = sorted(cited & {eid for group in siblings for eid in group})
            detail["with_siblings"] = {"found": len(wider) == len(groups) and bool(named), "cited_groups": wider,
                                       "missing_groups": [i for i in range(len(groups)) if i not in wider]}
        details.append(detail)
        if fact["kind"] != "decoy":
            continue
        distinctive = [value for value in entities if value.lower() not in attack_entities]
        for claim in claims:
            statement = text_of(claim.get("statement", "")).lower()
            hits = [value for value in distinctive if names(statement, value)]
            terms = has_term(statement, COMPROMISE_TERMS)
            if hits and terms and not has_term(statement, BENIGN_TERMS):
                misattributed.append({"fact_id": fact["fact_id"], "claim_id": claim.get("claim_id"),
                                      "entities": hits, "terms": terms})
    blamed = {item["fact_id"] for item in misattributed}
    found, by_kind, decoys_cleared = tally(details, blamed, lambda detail: (detail["found"], detail["cited_groups"]))
    method = ("keyword and event-, frame- and intel-ID citation matching" if any(
        key in fact for fact in truth["facts"] for key, _ in ALTERNATIVE_GROUPS) else "keyword and event-ID citation matching")
    result = {"found": found, "total": len(details), "by_kind": by_kind, "decoys_cleared": decoys_cleared,
              "facts": details, "misattributed_decoys": misattributed,
              "method": method + " against the operator key; not human judgment"}
    if with_siblings:
        found, by_kind, decoys_cleared = tally(details, blamed, lambda detail: (
            detail["with_siblings"]["found"], detail["with_siblings"]["cited_groups"]))
        result["with_siblings"] = {"found": found, "total": len(details), "by_kind": by_kind, "decoys_cleared": decoys_cleared,
                                   "method": "as found, but a group is also cited by an event the key lists beside it "
                                             "(evidence_sibling_groups: same process, same kind of event)"}
    return result


def score(truth_path, report_paths):
    truth = load_json_text(Path(truth_path).read_text(encoding="utf-8"))
    results = []
    for report_path in report_paths:
        result = score_report(truth, load_json_text(Path(report_path).read_text(encoding="utf-8")))
        result["report"] = str(report_path)
        results.append(result)
    return {"schema_version": SCHEMA_VERSION, "case_id": truth.get("case_id"), "reports": results}


def main(argv=None):
    class JsonParser(argparse.ArgumentParser):
        def error(self, message):
            raise ValueError(message)

    parser = JsonParser(prog="python -m hunt_lab.scenario", description=__doc__,
                        formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("generate", help="Write a new invented case and a separate operator key")
    create.add_argument("--size", required=True, choices=PUBLIC_SIZES)
    create.add_argument("--story", default="a", choices=tuple(STORIES),
                        help="a: phishing attachment -> beacon -> DNS tunnel (default); b: exploited public web server -> RDP -> database exfiltration")
    create.add_argument("--seed", required=True, type=int)
    create.add_argument("--case-id", required=True)
    create.add_argument("--evidence-dir", required=True)
    create.add_argument("--truth-dir", required=True)
    scoring = commands.add_parser("score", help="Score incident handoff reports against the operator key")
    scoring.add_argument("--truth", required=True)
    scoring.add_argument("reports", nargs="+")
    try:
        args = parser.parse_args(argv)
        if args.command == "generate":
            result = generate(args.size, args.seed, args.case_id, args.evidence_dir, args.truth_dir, args.story)
        else:
            result = score(args.truth, args.reports)
    except (OSError, ValueError) as error:
        print(json.dumps({"error": str(error)}, sort_keys=True))
        return 2
    print(json.dumps(result, sort_keys=True, allow_nan=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())

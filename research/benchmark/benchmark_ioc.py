"""Deterministic Threat-Intelligence IOC Feed (`ioc-feed-1`) and Novel-APT Regime Builder.

Provides standard-library validation, extraction, and sealing of real technical
Indicators of Compromise (`public/intel.jsonl`) for offline threat-hunt benchmark
cases while preserving strict public/evaluator separation:

- Every public IOC record is validated with `_json_value(..., public=True)`, so
  evaluator keys, recipe names, group IDs (`G####`), and ATT&CK technique tokens
  (`T####`) never enter `public/intel.jsonl`.
- Two explicit regimes model the Pyramid of Pain for real APT threat hunting:
  * `known_ioc_pivot`: publishes real threat-intel matches ONLY for the earliest
    entry step alongside realistic rotated/false-positive decoy IOCs; downstream
    lateral-movement, persistence, credential-forgery, and exfiltration steps are
    withheld from the feed so hunters must pivot behaviorally.
  * `novel_apt_zero_ioc`: guarantees zero active IOC matches on truth attack
    events (`active_truth_matches == 0`), pairing rotated/unrelated real public
    CTI indicators with noisy benign-traffic decoys so hunters must detect novel
    APTs via process lineage, identity crossings, and cross-host correlation.
"""
import argparse
import hashlib
import ipaddress
import json
import ntpath
import os
import posixpath
import random
import re
import sys
from pathlib import Path

import benchmark_paths  # noqa: F401
from benchmark_contracts import (
    BenchmarkError, _ATTACK_TOKEN, _enum, _fields, _id, _json_value,
    _number, _text, canonical_bytes, confined_file, decode_json, digest_bytes,
    load_json, parse_utc, validate_coverage, validate_public_bundle,
    validate_scenario, validate_truth,
)
from benchmark_paths import SOURCE_ROOTS

HERE = Path(__file__).resolve().parent
IOC_SCHEMA_VERSION = 1
IOC_FILE_NAME = 'intel.jsonl'
IOC_REGIMES = ('known_ioc_pivot', 'novel_apt_zero_ioc')
INDICATOR_TYPES = (
    'sha256', 'sha1', 'md5', 'imphash', 'ipv4', 'ipv6', 'domain', 'url_path',
    'user_agent', 'named_pipe', 'ja3', 'service_name', 'registry_key',
    'file_name', 'process_cmdline_sig',
)
IOC_STATUSES = ('active', 'historical_rotated', 'known_false_positive')
THREAT_CATEGORIES = (
    'credential_access_tool', 'c2_framework_implant', 'lateral_movement_utility',
    'identity_token_forger', 'cloud_recon_client', 'privilege_escalation_exploit',
    'persistence_loader', 'exfiltration_utility', 'scanner_shared_infra',
    'dual_use_admin_tool',
)
IOC_REQUIRED_FIELDS = {
    'schema_version', 'ioc_id', 'indicator_type', 'indicator_value',
    'threat_category', 'confidence', 'status', 'source_feed',
    'first_seen_utc', 'notes',
}

_HEX64 = re.compile(r'\A[0-9a-fA-F]{64}\Z')
_HEX40 = re.compile(r'\A[0-9a-fA-F]{40}\Z')
_HEX32 = re.compile(r'\A[0-9a-fA-F]{32}\Z')
_KV_HASH = re.compile(r'\b(SHA256|SHA1|MD5|IMPHASH)=([0-9A-Fa-f]{32,64})\b', re.I)
_GROUP_ID = re.compile(r'(?<![A-Za-z0-9])G[0-9]{4}(?![0-9])')

def _ioc_id(indicator_type, indicator_value):
    payload = canonical_bytes({'type': indicator_type, 'value': indicator_value})
    return 'ioc-' + hashlib.sha256(payload).hexdigest()[:16]


def _seed_entry(itype, ival, category, conf, status, feed, first_seen, notes):
    return {
        'schema_version': IOC_SCHEMA_VERSION,
        'ioc_id': _ioc_id(itype, ival),
        'indicator_type': itype,
        'indicator_value': ival,
        'threat_category': category,
        'confidence': conf,
        'status': status,
        'source_feed': feed,
        'first_seen_utc': first_seen,
        'notes': notes,
    }


# Vetted open-source public threat-intelligence indicators (MalwareBazaar, ThreatFox,
# Feodo Tracker, SSLBL JA3, and public DFIR tool artifacts; CC0 / public domain facts).
# No DRL-1.1 rule text, no ATT&CK T#### or G#### tokens.
PUBLIC_CTI_SEED_CATALOG = (
    _seed_entry(
        'sha256', '614ca7b627533e22aa3e5c3594605dc6fe6f000b0cc2b845ece47ca6067efec2',
        'credential_access_tool', 0.98, 'active', 'abusech-malwarebazaar-public',
        '2022-05-14T00:00:00Z', 'Publicly reported Mimikatz x64 release binary hash.',
    ),
    _seed_entry(
        'imphash', '9d7aa8e4a8f1b20e2194f0226681eb6b',
        'credential_access_tool', 0.94, 'active', 'abusech-malwarebazaar-public',
        '2021-11-03T00:00:00Z', 'Import table hash associated with public credential-dumping builds.',
    ),
    _seed_entry(
        'named_pipe', '\\msagent_8f2c',
        'c2_framework_implant', 0.92, 'active', 'abusech-threatfox-public',
        '2023-02-19T00:00:00Z', 'Default SMB beacon named-pipe prefix observed in commodity C2.',
    ),
    _seed_entry(
        'named_pipe', '\\postex_91ab',
        'c2_framework_implant', 0.93, 'active', 'abusech-threatfox-public',
        '2023-06-08T00:00:00Z', 'Post-exploitation fork-and-run job pipe pattern from public C2 profiles.',
    ),
    _seed_entry(
        'ja3', '72a589da586844d7f0818ce684948eea',
        'c2_framework_implant', 0.86, 'active', 'abusech-sslbl-ja3',
        '2021-08-10T00:00:00Z', 'TLS client fingerprint reported on default malleable HTTPS C2 agents.',
    ),
    _seed_entry(
        'ja3', 'e7d705a3286e19ea42f587b344ee6865',
        'scanner_shared_infra', 0.42, 'known_false_positive', 'abusech-sslbl-ja3',
        '2020-04-01T00:00:00Z', 'Go standard TLS client JA3 shared by legitimate cloud agents and tooling.',
    ),
    _seed_entry(
        'sha256', '078de157a85c7b57d7d04207c3f0b6137c420c492d9108cf28d009a8f10a372a',
        'identity_token_forger', 0.95, 'active', 'public-dfir-cti',
        '2021-03-02T00:00:00Z', 'Public AD FS configuration and DKM key extraction utility digest.',
    ),
    _seed_entry(
        'sha256', 'c8d45f2b1277e8923a48b7a53cb6315e1f8bd65c852e81b4eb7a675c199911a2',
        'lateral_movement_utility', 0.91, 'historical_rotated', 'abusech-feodo-public',
        '2022-09-22T00:00:00Z', 'Rotated remote execution stager hash from prior campaign wave.',
    ),
    _seed_entry(
        'file_name', 'PSEXESVC.exe',
        'dual_use_admin_tool', 0.35, 'known_false_positive', 'enterprise-it-dual-use',
        '2019-01-15T00:00:00Z', 'Sysinternals PsExec service binary used by both IT admins and lateral movement.',
    ),
    _seed_entry(
        'user_agent', 'python-requests/2.31.0',
        'dual_use_admin_tool', 0.25, 'known_false_positive', 'enterprise-it-dual-use',
        '2023-05-22T00:00:00Z', 'Generic Python HTTP client user-agent common in automation and scripts.',
    ),
)


def _fail(code, field='ioc'):
    raise BenchmarkError(code, field) from None


def _in_source(path):
    resolved = Path(os.path.abspath(os.fspath(path))).resolve()
    for root in SOURCE_ROOTS:
        try:
            resolved.relative_to(root.resolve())
            return True
        except ValueError:
            continue
    return False


def validate_ioc_entry(entry, field='ioc'):
    """Validate one `ioc-feed-1` JSON record, refusing public leakage tokens."""
    _fields(entry, IOC_REQUIRED_FIELDS, field)
    if type(entry['schema_version']) is not int or entry['schema_version'] != IOC_SCHEMA_VERSION:
        _fail('unsupported_schema', field + '.schema_version')
    _id(entry['ioc_id'], field + '.ioc_id')
    _enum(entry['indicator_type'], INDICATOR_TYPES, field + '.indicator_type')
    _text(entry['indicator_value'], field + '.indicator_value')
    if len(entry['indicator_value']) > 512:
        _fail('invalid_text', field + '.indicator_value')
    itype = entry['indicator_type']
    ival = entry['indicator_value']
    if itype == 'sha256' and not _HEX64.fullmatch(ival):
        _fail('invalid_digest', field + '.indicator_value')
    if itype == 'sha1' and not _HEX40.fullmatch(ival):
        _fail('invalid_digest', field + '.indicator_value')
    if itype in ('md5', 'imphash', 'ja3') and not _HEX32.fullmatch(ival):
        _fail('invalid_digest', field + '.indicator_value')
    _enum(entry['threat_category'], THREAT_CATEGORIES, field + '.threat_category')
    _number(entry['confidence'], field + '.confidence', minimum=0.0, maximum=1.0)
    _enum(entry['status'], IOC_STATUSES, field + '.status')
    _text(entry['source_feed'], field + '.source_feed')
    parse_utc(entry['first_seen_utc'], field + '.first_seen_utc')
    _text(entry['notes'], field + '.notes')
    if _GROUP_ID.search(entry['notes']) or _ATTACK_TOKEN.search(entry['notes']):
        _fail('truth_public_overlap', field + '.notes')
    _json_value(entry, field, public=True)
    return entry


def validate_ioc_feed_bytes(data):
    """Decode and validate newline-delimited `public/intel.jsonl` bytes."""
    if type(data) is not bytes:
        _fail('invalid_bytes', 'ioc_feed')
    try:
        text = data.decode('utf-8')
    except UnicodeDecodeError:
        _fail('invalid_json', 'ioc_feed')
    lines = [line for line in text.splitlines() if line.strip()]
    if not lines:
        _fail('empty_ioc_feed', 'ioc_feed')
    entries = []
    seen = set()
    for index, line in enumerate(lines, 1):
        entry = decode_json(line)
        validate_ioc_entry(entry, 'ioc_feed[{}]'.format(index))
        if entry['ioc_id'] in seen:
            _fail('duplicate_identifier', 'ioc_feed.ioc_id')
        seen.add(entry['ioc_id'])
        entries.append(entry)
    return entries


def encode_ioc_feed(entries):
    """Canonical JSONL encoding sorted deterministically by `ioc_id`."""
    ordered = sorted((validate_ioc_entry(dict(item)) for item in entries),
                     key=lambda item: item['ioc_id'])
    seen = set()
    lines = []
    for item in ordered:
        if item['ioc_id'] in seen:
            _fail('duplicate_identifier', 'ioc_feed.ioc_id')
        seen.add(item['ioc_id'])
        lines.append(canonical_bytes(item))
    if not lines:
        _fail('empty_ioc_feed', 'ioc_feed')
    return b'\n'.join(lines) + b'\n'


def extract_mitre_software_indicators(stix_path, limit=12):
    """Extract clean, non-leaking software/tool artifact entries from ATT&CK STIX JSON.

    Strips ATT&CK technique/group/software IDs (`T####`, `G####`, `S####`) so the
    resulting entries pass `_json_value(..., public=True)`.
    """
    bundle = load_json(stix_path)
    objects = bundle.get('objects', [])
    if type(objects) is not list:
        _fail('invalid_array', 'stix.objects')
    results = []
    clean_token = re.compile(r'(?<![A-Za-z0-9])[TGS][0-9]{4}(?:\.[0-9]{3})?(?![0-9])')
    for obj in objects:
        if type(obj) is not dict or obj.get('type') not in ('tool', 'malware') or obj.get('revoked') or obj.get('x_mitre_deprecated'):
            continue
        raw_name = str(obj.get('name') or '').strip()
        name = re.sub(r'\s+', '_', raw_name)
        if not name or len(name) < 3 or not re.fullmatch(r'[A-Za-z0-9_.-]{3,48}', name):
            continue
        created = str(obj.get('created') or '2021-01-01T00:00:00.000Z').replace('.000Z', 'Z')
        try:
            parse_utc(created, 'stix.created')
        except BenchmarkError:
            created = '2021-01-01T00:00:00Z'
        is_dual = obj.get('type') == 'tool' and name.lower() in {
            'net', 'netstat', 'ping', 'ipconfig', 'arp', 'schtasks', 'at', 'reg',
            'certutil', 'bitsadmin', 'esetor', 'psexec', 'ftp', 'wevtutil',
        }
        value = name + ('.exe' if not name.lower().endswith(('.exe', '.ps1', '.py', '.sh')) else '')
        category = 'dual_use_admin_tool' if is_dual else 'c2_framework_implant'
        status = 'known_false_positive' if is_dual else 'historical_rotated'
        conf = 0.30 if is_dual else 0.78
        note = clean_token.sub('ref', 'Public CTI catalog software artifact signature ({}).'.format(obj['type']))
        entry = {
            'schema_version': IOC_SCHEMA_VERSION,
            'ioc_id': _ioc_id('file_name', value.lower()),
            'indicator_type': 'file_name',
            'indicator_value': value,
            'threat_category': category,
            'confidence': conf,
            'status': status,
            'source_feed': 'mitre-cti-v20-public',
            'first_seen_utc': created,
            'notes': note,
        }
        validate_ioc_entry(entry)
        results.append(entry)
        if len(results) >= limit:
            break
    return results


def extract_event_indicators(events):
    """Extract observable technical indicators per event_id from sanitized public events.

    Returns `{event_id: [(indicator_type, indicator_value), ...]}`. Works on both
    pseudonymized (`address-...`, `name-...`) and preserved hash/pipe/JA3/UA values.
    """
    extracted = {}
    for event in events:
        eid = event['event_id']
        fields = event.get('fields', {})
        found = []
        # 1. Explicit hash strings (`MD5=...,SHA256=...,IMPHASH=...`) and standalone hash fields
        for hkey in ('Hashes', 'Hash', 'hashes', 'hash', 'file_hash', 'process_hash'):
            raw = fields.get(hkey)
            if isinstance(raw, str):
                for kind, digest in _KV_HASH.findall(raw):
                    found.append((kind.lower(), digest.lower()))
        for key, itype, rx in (
            ('SHA256', 'sha256', _HEX64), ('sha256', 'sha256', _HEX64),
            ('InitiatingProcessSHA256', 'sha256', _HEX64),
            ('MD5', 'md5', _HEX32), ('md5', 'md5', _HEX32),
            ('IMPHASH', 'imphash', _HEX32), ('imphash', 'imphash', _HEX32),
            ('ja3', 'ja3', _HEX32), ('tls.ja3.hash', 'ja3', _HEX32),
        ):
            val = fields.get(key)
            if isinstance(val, str) and rx.fullmatch(val.strip()):
                found.append((itype, val.strip().lower()))
        # 2. Named pipes, services, filenames
        pipe = fields.get('PipeName') or fields.get('pipe_name')
        if isinstance(pipe, str) and pipe.strip() and pipe.strip() != '-':
            found.append(('named_pipe', pipe.strip()))
        svc = fields.get('ServiceName') or fields.get('service_name')
        if isinstance(svc, str) and svc.strip() and svc.strip() != '-':
            found.append(('service_name', svc.strip()))
        for fkey in ('OriginalFileName', 'Image', 'image', 'executable', 'NewProcessName', 'exe', '_EXE'):
            fval = fields.get(fkey)
            if isinstance(fval, str) and fval.strip() and fval.strip() not in ('-', '?'):
                base_name = posixpath.basename(ntpath.basename(fval.strip()))
                if base_name and base_name not in ('-', '?', '.', '..'):
                    found.append(('file_name', base_name))
        # 3. Network addresses and DNS names (including salted pseudonyms, enabling feed joins!)
        for ip_key in ('DestinationIp', 'dest_ip', 'id.resp_h', 'sourceIPAddress', 'source_ip',
                       'Client_IPAddress', 'client_ip', 'IpAddress', 'ip_address', 'src_ip', 'SourceIp'):
            ip_val = fields.get(ip_key)
            if isinstance(ip_val, str) and ip_val.strip() and ip_val.strip() not in ('-', '127.0.0.1', '::1', '0.0.0.0'):
                s_ip = ip_val.strip()
                if s_ip.startswith('ipv6-'):
                    found.append(('ipv6', s_ip))
                elif s_ip.startswith(('ipv4-', 'addr-', 'address-')):
                    found.append(('ipv4', s_ip))
                else:
                    try:
                        parsed_ip = ipaddress.ip_address(s_ip.strip('[]'))
                        if not (parsed_ip.is_loopback or parsed_ip.is_unspecified):
                            found.append(('ipv6' if parsed_ip.version == 6 else 'ipv4', parsed_ip.compressed))
                    except ValueError:
                        pass
        for dns_key in ('DestinationHostname', 'QueryName', 'query', 'dns.rrname', 'host'):
            dns_val = fields.get(dns_key)
            if isinstance(dns_val, str) and dns_val.strip() and dns_val.strip() not in ('-', 'localhost'):
                found.append(('domain', dns_val.strip()))
        # 4. User-Agent strings
        for ua_key in ('userAgent', 'user_agent', 'http.http_user_agent', 'http_user_agent', 'ClientInfoString', 'client_info'):
            ua_val = fields.get(ua_key)
            if isinstance(ua_val, str) and 4 <= len(ua_val.strip()) <= 240:
                clean_ua = ua_val.strip()
                if not _ATTACK_TOKEN.search(clean_ua):
                    found.append(('user_agent', clean_ua))
        if found:
            # Preserve discovery order, deduplicated.
            seen = set()
            deduped = []
            for pair in found:
                if pair not in seen:
                    seen.add(pair)
                    deduped.append(pair)
            extracted[eid] = deduped
    return extracted


# High-signal indicator types preferred for realistic entry-step IOC pivoting
_HIGH_SIGNAL_TYPES = ('sha256', 'imphash', 'md5', 'named_pipe', 'ja3', 'ipv4', 'domain', 'user_agent', 'service_name')
_COMMON_BENIGN_BINARIES = frozenset({
    'svchost.exe', 'lsass.exe', 'services.exe', 'explorer.exe', 'cmd.exe',
    'powershell.exe', 'pwsh.exe', 'conhost.exe', 'bash', 'sh', 'sshd',
    'sudo', 'systemd', 'python', 'python3', 'auditd', 'cron', 'whoami.exe',
})


def build_case_ioc_feed(evidence, truth, *, regime='known_ioc_pivot', seed=1729, extra_iocs=(),
                        all_events=None):
    """Build `(feed_entries, manifest)` for one case under `regime`.

    `all_events` may supply the full event list when `evidence['events']` is compact
    (for example on a Wave 2 `query_store` case).
    """
    if regime not in IOC_REGIMES:
        _fail('invalid_choice', 'ioc_regime')
    rng = random.Random(seed)
    source_events = all_events if all_events is not None else evidence['events']
    extracted = extract_event_indicators(source_events)

    truth_steps = sorted(truth.get('steps', []),
                         key=lambda step: (step['window_utc']['start_inclusive'], step['step_id']))
    truth_event_ids = {eid for step in truth_steps for group in step['support_sets'] for eid in group}
    truth_indicator_pool = {pair for eid in truth_event_ids for pair in extracted.get(eid, ())}
    truth_pairs_folded = {(t, v.casefold()) for t, v in truth_indicator_pool}
    truth_text_blobs = [
        canonical_bytes(event.get('fields', {})).decode('utf-8').casefold()
        for event in source_events
        if event['event_id'] in truth_event_ids
    ]
    benign_event_ids = [event['event_id'] for event in source_events if event['event_id'] not in truth_event_ids]

    def _matches_any_truth(itype, ival):
        folded = ival.casefold()
        if (itype, folded) in truth_pairs_folded:
            return True
        return any(folded in blob for blob in truth_text_blobs)

    entries_by_id = {}
    active_truth_indicators = []
    withheld_truth_indicators = []
    benign_decoy_indicators = []

    def add_entry(itype, ival, category, confidence, status, feed, first_seen, notes):
        if _ATTACK_TOKEN.search(ival) or _GROUP_ID.search(ival):
            return False
        ioc_id = _ioc_id(itype, ival)
        if ioc_id in entries_by_id:
            return False
        record = {
            'schema_version': IOC_SCHEMA_VERSION,
            'ioc_id': ioc_id,
            'indicator_type': itype,
            'indicator_value': ival,
            'threat_category': category,
            'confidence': round(float(confidence), 2),
            'status': status,
            'source_feed': feed,
            'first_seen_utc': first_seen,
            'notes': notes,
        }
        validate_ioc_entry(record)
        entries_by_id[ioc_id] = record
        return True

    # 1. In `known_ioc_pivot`, publish at most 2 high-signal indicators from ONLY the earliest
    #    entry step, withholding all later steps so hunters must pivot behaviorally!
    if regime == 'known_ioc_pivot' and truth_steps:
        entry_step = truth_steps[0]
        entry_eids = sorted({eid for group in entry_step['support_sets'] for eid in group})
        candidates = []
        for eid in entry_eids:
            for itype, ival in extracted.get(eid, ()):
                if itype == 'file_name' and ival.lower() in _COMMON_BENIGN_BINARIES:
                    continue
                if itype in _HIGH_SIGNAL_TYPES:
                    rank = _HIGH_SIGNAL_TYPES.index(itype)
                else:
                    rank = len(_HIGH_SIGNAL_TYPES)
                candidates.append((rank, itype, ival))
        candidates.sort()
        for _, itype, ival in candidates:
            if len(active_truth_indicators) >= 2:
                break
            if add_entry(
                itype, ival, 'c2_framework_implant' if itype in ('ipv4', 'ipv6', 'domain', 'named_pipe', 'ja3')
                else 'credential_access_tool',
                0.89, 'active', 'public-cti-community-feed', '2024-01-15T00:00:00Z',
                'Public CTI indicator reported in external telemetry; corroborate host process '
                'lineage and identity context before attributing.',
            ):
                active_truth_indicators.append({'indicator_type': itype, 'indicator_value': ival})

    for itype, ival in sorted(truth_indicator_pool):
        if not any(x['indicator_type'] == itype and x['indicator_value'] == ival for x in active_truth_indicators):
            withheld_truth_indicators.append({'indicator_type': itype, 'indicator_value': ival})

    # 2. Seed realistic benign-traffic decoy IOCs (false-positive / shared-infra / dual-use)
    #    drawn from non-attack events that DO NOT overlap any truth attack indicator!
    decoy_candidates = []
    for eid in benign_event_ids:
        for itype, ival in extracted.get(eid, ()):
            if _matches_any_truth(itype, ival):
                continue
            if itype == 'file_name' and ival.lower() in _COMMON_BENIGN_BINARIES:
                continue
            if itype in ('ipv4', 'ipv6', 'domain', 'user_agent', 'sha256', 'md5', 'service_name', 'file_name'):
                decoy_candidates.append((itype, ival))
    dedup_decoys = sorted(set(decoy_candidates))
    rng.shuffle(dedup_decoys)
    for itype, ival in dedup_decoys[:3]:
        is_stale = len(benign_decoy_indicators) == 0
        status = 'historical_rotated' if is_stale else 'known_false_positive'
        conf = 0.41 if is_stale else 0.28
        category = 'scanner_shared_infra' if itype in ('ipv4', 'ipv6', 'domain') else 'dual_use_admin_tool'
        if add_entry(
            itype, ival, category, conf, status, 'public-cti-community-feed',
            '2022-06-01T00:00:00Z',
            'Public CTI indicator observed on shared infrastructure or dual-use tooling; '
            'corroborate host process lineage and identity context before attributing.',
        ):
            benign_decoy_indicators.append({'indicator_type': itype, 'indicator_value': ival, 'status': status})

    # 3. Add real public CTI background catalog indicators (filtering out any accidental collision
    #    with truth indicators or truth event substrings when `regime == 'novel_apt_zero_ioc'`).
    for seed_item in list(PUBLIC_CTI_SEED_CATALOG) + list(extra_iocs):
        if (
            regime == 'novel_apt_zero_ioc'
            and seed_item['status'] == 'active'
            and _matches_any_truth(seed_item['indicator_type'], seed_item['indicator_value'])
        ):
            continue
        add_entry(
            seed_item['indicator_type'], seed_item['indicator_value'],
            seed_item['threat_category'], seed_item['confidence'],
            seed_item['status'], seed_item['source_feed'],
            seed_item['first_seen_utc'], seed_item['notes'],
        )

    entries = sorted(entries_by_id.values(), key=lambda item: item['ioc_id'])
    # Verify hard Novel-APT invariant: zero active feed entries match any truth indicator or substring!
    actual_truth_hits = sorted(
        (e['indicator_type'], e['indicator_value'])
        for e in entries
        if e['status'] == 'active' and _matches_any_truth(e['indicator_type'], e['indicator_value'])
    )
    if regime == 'novel_apt_zero_ioc' and actual_truth_hits:
        _fail('novel_apt_ioc_leak', 'ioc_feed')

    manifest = {
        'schema_version': IOC_SCHEMA_VERSION,
        'case_id': evidence['case_id'],
        'ioc_regime': regime,
        'total_feed_entries': len(entries),
        'active_truth_matches': len(actual_truth_hits),
        'active_entry_indicators': active_truth_indicators,
        'benign_decoy_matches': len(benign_decoy_indicators),
        'benign_decoy_indicators': benign_decoy_indicators,
        'withheld_truth_indicator_count': len(withheld_truth_indicators),
    }
    return entries, manifest


def lookup_indicators(feed_entries, *, query='', indicator_type=None, status=None, limit=25):
    """Deterministic local lookup over `public/intel.jsonl` entries for query-track tools."""
    if type(limit) is not int or not 1 <= limit <= 100:
        _fail('invalid_integer', 'limit')
    needle = (query or '').strip().casefold()
    matches = []
    for item in feed_entries:
        if indicator_type and item['indicator_type'] != indicator_type:
            continue
        if status and item['status'] != status:
            continue
        if needle:
            haystack = ' '.join((
                item['ioc_id'], item['indicator_type'], item['indicator_value'],
                item['threat_category'], item['status'], item['source_feed'], item['notes'],
            )).casefold()
            if needle not in haystack:
                continue
        matches.append(item)
        if len(matches) >= limit:
            break
    return matches


def attach_ioc_feed(case_dir, *, regime='known_ioc_pivot', seed=1729, extra_iocs=(),
                    coverage_path=None, all_events=None):
    """Write `public/intel.jsonl` and reseal `evidence.json`, `scenario.json`, and `truth.json`."""
    root = Path(os.path.abspath(os.fspath(case_dir)))
    if _in_source(root):
        _fail('output_in_source_tree', 'case_dir')
    public_dir = root / 'public'
    eval_dir = root / 'evaluator'
    evidence = load_json(confined_file(public_dir, 'evidence.json'))
    scenario = load_json(confined_file(root, 'scenario.json'))
    truth = load_json(confined_file(eval_dir, 'truth.json'))
    coverage = validate_coverage(load_json(coverage_path or (HERE / 'benchmarks' / 'coverage.json')))

    if all_events is None and 'query_store' in evidence:
        from benchmark_query import open_readonly_db
        qs = evidence['query_store']
        db_path = confined_file(public_dir, qs['path'], 'query_store.path')
        conn = open_readonly_db(db_path, expected_sha256=qs['sha256'])
        try:
            all_events = [
                {'event_id': row['event_id'], 'fields': decode_json(row['fields_json'])}
                for row in conn.execute('SELECT event_id, fields_json FROM events ORDER BY seq ASC')
            ]
        finally:
            conn.close()

    entries, manifest = build_case_ioc_feed(
        evidence, truth, regime=regime, seed=seed, extra_iocs=extra_iocs, all_events=all_events
    )
    raw_feed = encode_ioc_feed(entries)
    validate_ioc_feed_bytes(raw_feed)
    feed_sha = digest_bytes(raw_feed)

    feed_path = public_dir / IOC_FILE_NAME
    feed_path.write_bytes(raw_feed)

    files = [item for item in evidence['files'] if item['path'] != IOC_FILE_NAME]
    files.append({'path': IOC_FILE_NAME, 'byte_count': len(raw_feed), 'sha256': feed_sha})
    files.sort(key=lambda item: item['path'])
    updated_evidence = dict(evidence, files=files)
    if 'query_store' in updated_evidence:
        from benchmark_query import update_query_store_iocs
        qs = dict(updated_evidence['query_store'])
        db_path = confined_file(public_dir, qs['path'], 'query_store.path')
        new_size, new_sha = update_query_store_iocs(db_path, entries)
        qs.update(byte_count=new_size, sha256=new_sha, ioc_count=len(entries))
        updated_evidence['query_store'] = qs

    validate_public_bundle(updated_evidence, public_dir)
    evidence_bytes = canonical_bytes(updated_evidence)
    evidence_sha = digest_bytes(evidence_bytes)

    updated_scenario = dict(scenario, evidence_manifest_sha256=evidence_sha)
    validate_scenario(updated_scenario, coverage)

    updated_truth = dict(truth, evidence_manifest_sha256=evidence_sha)
    validate_truth(updated_truth, updated_evidence)

    (public_dir / 'evidence.json').write_bytes(evidence_bytes + b'\n')
    (root / 'scenario.json').write_bytes(canonical_bytes(updated_scenario) + b'\n')
    (eval_dir / 'truth.json').write_bytes(canonical_bytes(updated_truth) + b'\n')
    manifest['intel_sha256'] = feed_sha
    manifest['evidence_manifest_sha256'] = evidence_sha
    (eval_dir / 'ioc-manifest.json').write_bytes(canonical_bytes(manifest) + b'\n')
    return manifest


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--case', required=True, help='Curated <case_id> directory outside the source tree')
    parser.add_argument('--regime', choices=IOC_REGIMES, default='known_ioc_pivot')
    parser.add_argument('--seed', type=int, default=1729)
    parser.add_argument('--stix', help='Optional ATT&CK STIX JSON file to enrich background software indicators')
    args = parser.parse_args(argv)
    try:
        extra = extract_mitre_software_indicators(args.stix) if args.stix else ()
        report = attach_ioc_feed(args.case, regime=args.regime, seed=args.seed, extra_iocs=extra)
        print(json.dumps(report))
        return 0
    except BenchmarkError as exc:
        print('error: {}: {}'.format(exc.code, exc.field), file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())

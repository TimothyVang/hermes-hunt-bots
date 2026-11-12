"""Import one OTRF Security-Datasets Windows export as a DEVELOPMENT benchmark case.

Input: an OTRF JSON-lines export (`*.json`, or the published `*.zip` that
contains exactly one such member), its metadata YAML, and optionally a
human-written curation JSON. Two record shapes are detected explicitly (see
RECORD_SHAPES); one file must use exactly one of them. Output: a NEW directory
`OUTPUT/<case_id>/` with

    scenario.json                      curated imports only
    public/evidence.json               public bundle (validated)
    public/records.jsonl               one line per ORIGINAL dataset line
    evaluator/truth.json               curated imports only
    evaluator/truth.DRAFT.json         uncurated imports only; NOT VALID FOR SCORING
    evaluator/curation-template.json   uncurated imports only
    evaluator/curation.json            exact curation bytes (curated imports)
    evaluator/import-report.json       digests, counts, drops, assumptions
    evaluator/locators.json            event_id -> original line/line digest
    evaluator/pseudonyms.json          original -> pseudonym map
    evaluator/salt.json                per-import HMAC salt

Safety decisions:
- The dataset is untrusted data. Nothing in it is executed, followed or fetched.
- Metadata YAML is parsed by a strict hand-written subset parser: only `id`,
  `title`, `type`, `platform`, `attack_mappings` and `files` are interpreted;
  other known top-level blocks are skipped by indentation without being
  parsed; unknown top-level keys, anchors, aliases, tags, flow collections,
  document markers and tab indentation are refused. No YAML library is used.
- Archives: one regular `.json` member, no path traversal, no symlinks, no
  nested archives, no encryption, stored/deflated only, bounded size and ratio,
  streamed decompression with a hard byte cap.
- Public fields are an explicit per-event-type allowlist
  (`benchmarks/importers/otrf-fields.json`); everything else is dropped.
  Content fields (command lines, script blocks, payloads, task XML, ...)
  use the `content` transform: `benchmark_sanitize.sanitize_text` redacts
  secrets, pseudonymizes identities with the same HMAC pseudonyms as the
  structured fields, masks ATT&CK tokens and bounds the length explicitly.
  An event type without an allowlist entry is imported metadata-only.
  Identifiers are replaced by HMAC-SHA256 pseudonyms keyed by a per-import salt
  that lives only in the evaluator area. Pseudonymization is not
  declassification: a human must still review and release the public bundle.
- Truth comes ONLY from the curation file. OTRF labels are per dataset, not per
  event, so the importer never infers steps or support sets. Without curation
  it writes a draft truth that the contract validator refuses.

Python 3.9 standard library only.
"""

import argparse
import errno
import hashlib
import hmac
import io
import ipaddress
import json
import os
import re
import secrets
import stat
import sys
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from benchmark_contracts import (ASSESSMENT_QUESTION, COVERAGE_AXES, BenchmarkError,
                                 canonical_bytes, decode_json, digest_bytes, load_json,
                                 parse_utc, validate_public_bundle, validate_scenario,
                                 validate_truth)
from benchmark_paths import SOURCE_ROOTS
from benchmark_sanitize import (ENCODED_PAYLOAD_MODES, MAX_CONTENT_BYTES, KnownIdentities, merge_reports, new_totals,
                               sanitize_text, scan_leaks)

IMPORTER_VERSION = 'otrf-import-3'
HERE = Path(__file__).resolve().parent
DEFAULT_FIELDS = HERE / 'benchmarks' / 'importers' / 'otrf-fields.json'
DEFAULT_COVERAGE = HERE / 'benchmarks' / 'coverage.json'

MAX_INPUT_BYTES = 64 * 1024 * 1024
MAX_MEMBER_BYTES = 256 * 1024 * 1024
MAX_RATIO = 200
MAX_ARCHIVE_ENTRIES = 16
MAX_LINE_BYTES = 1024 * 1024
MAX_RECORDS = 500000
MAX_METADATA_BYTES = 256 * 1024
MAX_SIDE_FILE_BYTES = 4 * 1024 * 1024
MAX_KEEP_CHARS = 4096
SALT_BYTES = 32
DRAFT_MARKER = 'DRAFT_NOT_VALID_FOR_SCORING'

TRANSFORMS = ('keep', 'basename', 'path', 'account', 'user', 'domain', 'host',
              'sid', 'guid', 'ip', 'dns', 'opaque', 'content')
# Pseudonym namespaces whose originals the content sanitizer replaces wherever they appear in content.
CONTENT_IDENTITY_NAMESPACES = ('user', 'netbios', 'dns', 'ip', 'guid', 'opaque')
MAX_CONTENT_PASSES = 4
# Metadata-only events (no allowlist entry for their type): the System-element fields each shape carries.
METADATA_FIELDS = ('SourceName', 'Level', 'Severity', 'Task', 'Opcode')
# Record shapes. `flat-timecreated`: the 2020-10+ flat exports (TimeCreated, no record number).
# `nxlog-eventtime`: the 2019-2020 NXLog im_msvistalog exports forwarded through a WEC collector and
# Logstash (EventTime local wall clock, RecordNumber, host/port/tags envelope, no TimeCreated).
SHAPE_FLAT = 'flat-timecreated'
SHAPE_NXLOG = 'nxlog-eventtime'
RECORD_SHAPES = (SHAPE_FLAT, SHAPE_NXLOG)
RESERVED_FIELDS = ('Channel', 'EventID', 'Hostname', 'TimeCreated', '@timestamp')
# NXLog/Logstash envelope used for detection, time, locators and collector identity; never imported.
NXLOG_RESERVED = ('Channel', 'EventID', 'Hostname', 'EventTime', 'EventReceivedTime', 'RecordNumber',
                  '@timestamp', '@version', 'SourceModuleName', 'SourceModuleType', 'host', 'port', 'tags')
# Names NXLog fills from the event's System element or its own metadata. An allowlisted EventData field with
# the same name cannot be told apart and is dropped, except EventType when the export moved NXLog's own value
# to `EventTypeOrignal` (spelling as exported), which leaves `EventType` holding the EventData value.
NXLOG_ENVELOPE = frozenset({'AccountName', 'AccountType', 'ActivityID', 'Category', 'Domain',
                            'ERROR_EVT_UNRESOLVED', 'EventType', 'EventTypeOrignal', 'ExecutionProcessID',
                            'Keywords', 'Message', 'Opcode', 'OpcodeValue', 'ProviderGuid', 'RelatedActivityID',
                            'Severity', 'SeverityValue', 'SourceName', 'Task', 'ThreadID', 'UserID', 'Version'})
NXLOG_TIME = re.compile(r'([0-9]{4}-[0-9]{2}-[0-9]{2}) ([0-9]{2}:[0-9]{2}:[0-9]{2})\Z')
FAMILY_ID = re.compile(r'otrf-t[0-9]{4}(?:-[0-9]{3})?(?:-t[0-9]{4}(?:-[0-9]{3})?)*\Z')
LDAP_DC_RUN = re.compile(r'(?i)(?<![a-z0-9])dc=[^,\\/=]+(?:,dc=[^,\\/=]+)*')
NESTED_ARCHIVE = re.compile(r'\.(?:zip|jar|tar|tgz|gz|bz2|xz|7z|rar|cab|iso|zst|lz|lzma|z)\Z', re.I)
ATTACK_TOKEN = re.compile(r'(?<![A-Za-z0-9])T[0-9]{4}(?:\.[0-9]{3})?(?![0-9])')
AWARE_TIME = re.compile(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?(?:Z|[+-][0-9]{2}:[0-9]{2})\Z')
NAIVE_TIME = re.compile(r'([0-9]{4}-[0-9]{2}-[0-9]{2})[ T]([0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?)\Z')
DOMAIN_SID = re.compile(r'S-1-5-21-[0-9]+-[0-9]+-[0-9]+', re.I)
WELL_KNOWN_NAMES = frozenset({
    'system', 'local system', 'local service', 'network service', 'nt authority',
    'builtin', 'nt service', 'nt virtual machine', 'window manager',
    'font driver host', 'anonymous logon', 'iis apppool', '-', ''})
WELL_KNOWN_NAME = re.compile(r'(?:dwm|umfd)-[0-9]+\Z')
PROFILE_SEGMENTS = frozenset({'public', 'default', 'default user', 'all users'})
YAML_TOP_KEYS = frozenset({
    'title', 'id', 'contributors', 'creation_date', 'modification_date', 'platform',
    'type', 'tags', 'description', 'attack_mappings', 'notebooks', 'files',
    'simulation', 'references', 'datasets'})
YAML_PARSED = frozenset({'id', 'title', 'type', 'platform', 'attack_mappings', 'files'})
_ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9_-]{0,127}\Z')
_HOST = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,254}\Z')


def _fail(code, field):
    raise BenchmarkError(code, field)


# ---------------------------------------------------------------- input files

def _read_regular(path, limit, field):
    """Read a bounded regular file; refuse links/reparse points/devices."""
    try:
        candidate = Path(os.path.abspath(os.fspath(path)))
        info = candidate.lstat()
    except (OSError, ValueError, TypeError):
        _fail('file_not_found', field)
    if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
        _fail('path_alias', field)
    if not stat.S_ISREG(info.st_mode):
        _fail('not_regular_file', field)
    if info.st_size > limit:
        _fail('input_too_large', field)
    try:
        with open(candidate, 'rb') as handle:
            data = handle.read(limit + 1)
    except OSError:
        _fail('file_unreadable', field)
    if len(data) > limit:
        _fail('input_too_large', field)
    return candidate, data


def _member_name_ok(name):
    if not name or len(name) > 255 or '\\' in name or ':' in name or name.startswith('/'):
        return False
    parts = name.rstrip('/').split('/')
    return all(part not in ('', '.', '..') and not any(ord(c) < 32 for c in part) for part in parts)


def read_dataset(path, max_member_bytes=MAX_MEMBER_BYTES, max_input_bytes=MAX_INPUT_BYTES):
    """Return (input_path, input_bytes, member_name, member_bytes)."""
    if type(max_member_bytes) is not int or not 0 < max_member_bytes <= MAX_MEMBER_BYTES:
        _fail('invalid_limit', 'max_member_bytes')
    candidate, data = _read_regular(path, max_input_bytes, 'dataset')
    suffix = candidate.suffix.casefold()
    is_zip = data[:4] == b'PK\x03\x04'
    if suffix == '.json':
        if is_zip or data[:2] == b'\x1f\x8b':
            _fail('unsupported_dataset_layout', 'dataset')
        if len(data) > max_member_bytes:
            _fail('member_too_large', 'dataset')
        return candidate, data, candidate.name, data
    if suffix != '.zip' or not is_zip:
        _fail('unsupported_dataset_layout', 'dataset')
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
        infos = archive.infolist()
    except (zipfile.BadZipFile, zipfile.LargeZipFile, OSError, ValueError):
        _fail('invalid_archive', 'dataset')
    if len(infos) > MAX_ARCHIVE_ENTRIES:
        _fail('too_many_members', 'dataset')
    files = []
    for info in infos:
        if not _member_name_ok(info.filename):
            _fail('unsafe_member_path', 'dataset.member')
        mode = (info.external_attr >> 16) & 0o170000
        if mode == stat.S_IFLNK:
            _fail('unsafe_member_path', 'dataset.member')
        if info.is_dir():
            continue
        if NESTED_ARCHIVE.search(info.filename):
            _fail('nested_archive', 'dataset.member')
        if not info.filename.casefold().endswith('.json'):
            _fail('unsupported_member', 'dataset.member')
        files.append(info)
    if len(files) != 1:
        _fail('ambiguous_archive', 'dataset')
    info = files[0]
    if info.flag_bits & 0x1:
        _fail('encrypted_member', 'dataset.member')
    if info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
        _fail('unsupported_compression', 'dataset.member')
    if info.file_size > max_member_bytes:
        _fail('member_too_large', 'dataset.member')
    if info.file_size > max(info.compress_size, 1) * MAX_RATIO:
        _fail('compression_ratio', 'dataset.member')
    chunks, total = [], 0
    try:
        with archive.open(info) as handle:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                # The header is not trusted: enforce the cap on actual output.
                if total > max_member_bytes or total > max(info.compress_size, 1) * MAX_RATIO:
                    _fail('member_too_large', 'dataset.member')
                chunks.append(chunk)
    except BenchmarkError:
        raise
    except (zipfile.BadZipFile, OSError, ValueError, EOFError, RuntimeError):
        _fail('invalid_archive', 'dataset.member')
    member = b''.join(chunks)
    if len(member) != info.file_size:
        _fail('invalid_archive', 'dataset.member')
    return candidate, data, info.filename.rsplit('/', 1)[-1], member


# --------------------------------------------------------- strict YAML subset

def _yaml_scalar(text, field):
    text = text.strip()
    if not text:
        return None
    if text[0] in '&*!{[|>%@`':
        _fail('unsupported_yaml', field)
    quoted = re.fullmatch(r'"([^"\\]*)"(?:\s+#.*)?', text) or re.fullmatch(r"'([^']*)'(?:\s+#.*)?", text)
    if quoted:
        return quoted.group(1)
    if text[0] in '"\'':
        _fail('unsupported_yaml', field)
    text = re.split(r'\s#', text, maxsplit=1)[0].strip()
    if ': ' in text or text.endswith(':'):
        _fail('unsupported_yaml', field)
    return None if text in ('', '~', 'null', 'Null', 'NULL') else text


def _yaml_sequence_item(text):
    return text == '-' or text.startswith('- ')


def _yaml_node(entries, index, field):
    indent, text = entries[index]
    if _yaml_sequence_item(text):
        return _yaml_sequence(entries, index, indent, field)
    return _yaml_mapping(entries, index, indent, field)


def _yaml_sequence(entries, index, indent, field):
    items = []
    while index < len(entries) and entries[index][0] == indent and _yaml_sequence_item(entries[index][1]):
        rest = entries[index][1][2:] if len(entries[index][1]) > 1 else ''
        if rest.startswith(' '):
            _fail('unsupported_yaml', field)
        if not rest:
            index += 1
            if index < len(entries) and entries[index][0] > indent:
                value, index = _yaml_node(entries, index, field)
            else:
                value = None
        elif re.match(r'[A-Za-z_][A-Za-z0-9_-]*:(?: |\Z)', rest):
            entries[index] = (indent + 2, rest)
            value, index = _yaml_mapping(entries, index, indent + 2, field)
        else:
            value = _yaml_scalar(rest, field)
            index += 1
        items.append(value)
    if index < len(entries) and entries[index][0] > indent:
        _fail('unsupported_yaml', field)
    return items, index


def _yaml_mapping(entries, index, indent, field):
    result = {}
    while index < len(entries) and entries[index][0] == indent and not _yaml_sequence_item(entries[index][1]):
        match = re.fullmatch(r'([A-Za-z_][A-Za-z0-9_-]*):(?: (.*))?', entries[index][1])
        if not match:
            _fail('unsupported_yaml', field)
        key = match.group(1)
        if key in result:
            _fail('duplicate_key', field)
        inline = (match.group(2) or '').strip()
        index += 1
        if inline:
            value = _yaml_scalar(inline, field)
        elif index < len(entries) and (entries[index][0] > indent or
                                       (entries[index][0] == indent and _yaml_sequence_item(entries[index][1]))):
            value, index = _yaml_node(entries, index, field)
        else:
            value = None
        result[key] = value
    if index < len(entries) and entries[index][0] > indent:
        _fail('unsupported_yaml', field)
    return result, index


def _yaml_block(inline, lines, field):
    entries = []
    for line in lines:
        stripped = line.lstrip(' ')
        if not stripped or stripped.startswith('#'):
            continue
        if '\t' in line:
            _fail('unsupported_yaml', field)
        entries.append((len(line) - len(stripped), stripped.rstrip()))
    if inline:
        if entries:
            _fail('unsupported_yaml', field)
        return _yaml_scalar(inline, field)
    if not entries:
        return None
    value, index = _yaml_node(entries, 0, field)
    if index != len(entries):
        _fail('unsupported_yaml', field)
    return value


def parse_metadata_yaml(data):
    """Parse the needed subset of an OTRF metadata YAML file. Never executes anything."""
    if type(data) is not bytes or len(data) > MAX_METADATA_BYTES:
        _fail('input_too_large', 'metadata')
    try:
        text = data.decode('utf-8')
    except UnicodeError:
        _fail('invalid_text', 'metadata')
    if text.startswith('\ufeff'):
        text = text[1:]
    if '\x00' in text:
        _fail('invalid_text', 'metadata')
    blocks, current = {}, None
    for raw in text.split('\n'):
        line = raw[:-1] if raw.endswith('\r') else raw
        if line[:1] in (' ', '-', '\t', '') or line.startswith('#'):
            if line.startswith('\t') or line.startswith('---'):
                _fail('unsupported_yaml', 'metadata')
            if current is None:
                if line.strip() and not line.startswith('#'):
                    _fail('unsupported_yaml', 'metadata')
                continue
            current[1].append(line)
            continue
        if line.startswith(('...', '%')):
            _fail('unsupported_yaml', 'metadata')
        match = re.fullmatch(r'([A-Za-z_][A-Za-z0-9_-]*):(?: (.*))?', line)
        if not match:
            _fail('unsupported_yaml', 'metadata')
        key = match.group(1)
        if key not in YAML_TOP_KEYS:
            _fail('unsupported_metadata_key', 'metadata')
        if key in blocks:
            _fail('duplicate_key', 'metadata')
        current = ((match.group(2) or '').strip(), [])
        blocks[key] = current
    parsed = {key: _yaml_block(inline, lines, 'metadata.' + key)
              for key, (inline, lines) in blocks.items() if key in YAML_PARSED}
    return _metadata(parsed)


def _metadata(parsed):
    for key in ('id', 'title', 'type', 'platform', 'attack_mappings', 'files'):
        if key not in parsed:
            _fail('missing_field', 'metadata.' + key)
    if type(parsed['id']) is not str or not _ID.fullmatch(parsed['id']):
        _fail('invalid_identifier', 'metadata.id')
    if type(parsed['title']) is not str or not parsed['title'].strip():
        _fail('invalid_text', 'metadata.title')
    if parsed['type'] not in ('atomic', 'compound'):
        _fail('invalid_choice', 'metadata.type')
    platform = parsed['platform']
    if type(platform) is not list or not all(type(item) is str for item in platform):
        _fail('invalid_array', 'metadata.platform')
    if 'windows' not in {item.casefold() for item in platform}:
        _fail('unsupported_platform', 'metadata.platform')
    mappings = parsed['attack_mappings']
    if type(mappings) is not list or not mappings:
        _fail('metadata_missing_technique', 'metadata.attack_mappings')
    techniques = []
    for item in mappings:
        if type(item) is not dict or 'technique' not in item or set(item) - {'technique', 'sub-technique', 'tactics'}:
            _fail('invalid_object', 'metadata.attack_mappings')
        base, sub = item['technique'], item.get('sub-technique')
        if type(base) is not str or not re.fullmatch(r'T[0-9]{4}', base):
            _fail('invalid_technique', 'metadata.attack_mappings.technique')
        if sub is None:
            technique = base
        elif type(sub) is str and re.fullmatch(r'[0-9]{3}', sub):
            technique = base + '.' + sub
        elif type(sub) is str and re.fullmatch(re.escape(base) + r'\.[0-9]{3}', sub):
            technique = sub
        else:
            _fail('invalid_technique', 'metadata.attack_mappings.sub-technique')
        tactics = item.get('tactics')
        if tactics is None:
            tactics = []
        if type(tactics) is not list or not all(type(t) is str and re.fullmatch(r'TA[0-9]{4}', t) for t in tactics):
            _fail('invalid_array', 'metadata.attack_mappings.tactics')
        techniques.append({'technique_id': technique, 'tactics': sorted(set(tactics))})
    files = parsed['files']
    if type(files) is not list or not files:
        _fail('invalid_array', 'metadata.files')
    links = []
    for item in files:
        if type(item) is not dict or 'link' not in item or set(item) - {'type', 'link'}:
            _fail('invalid_object', 'metadata.files')
        link = item['link']
        if type(link) is not str or not re.fullmatch(r'https://[A-Za-z0-9.-]+/[A-Za-z0-9._~/%-]+', link):
            _fail('invalid_url', 'metadata.files.link')
        links.append(link)
    merged = {}
    for item in techniques:
        merged.setdefault(item['technique_id'], set()).update(item['tactics'])
    return {'id': parsed['id'], 'title': parsed['title'].strip(), 'type': parsed['type'],
            'techniques': [{'technique_id': key, 'tactics': sorted(value)} for key, value in sorted(merged.items())],
            'links': sorted(set(links))}


def _bind_metadata(metadata, input_name, member_name):
    """The supplied dataset must be one of the metadata's declared files."""
    stems = {link.rsplit('/', 1)[-1].rsplit('.', 1)[0].casefold() for link in metadata['links']}
    names = {input_name.rsplit('.', 1)[0].casefold(), member_name.rsplit('.', 1)[0].casefold()}
    if not any(name == stem or name.startswith(stem + '_') for name in names for stem in stems):
        _fail('metadata_dataset_mismatch', 'metadata.files')


# --------------------------------------------------------------- pseudonyms

class Pseudonyms:
    """Deterministic HMAC-SHA256 pseudonyms; the salt never enters public output."""

    def __init__(self, salt):
        if type(salt) is not bytes or len(salt) != SALT_BYTES:
            _fail('invalid_salt', 'salt')
        self._salt = salt
        self.mapping = {}
        self._reverse = {}
        self._domains = frozenset()

    def register_domains(self, hosts):
        """DNS suffixes of the export's own FQDN hostnames; `path` pseudonymizes them inside paths."""
        self._domains = frozenset(host.casefold().split('.', 1)[1] for host in hosts if '.' in host.strip('.'))

    @property
    def domains(self):
        return self._domains

    def content(self, kind, original):
        """`pseudonymize(kind, original)` for benchmark_sanitize: the same namespaces as the structured fields."""
        if kind == 'sid':
            return self.sid(original)
        if kind == 'domain':
            return self.netbios('domain', original)
        if kind == 'user':
            return self.user(original)
        if kind == 'host':
            return self.netbios('host', original)
        if kind == 'netbios':
            # A name already seen keeps its published pseudonym (host- or domain- prefix, one digest).
            return self.mapping.get('netbios', {}).get(original.casefold()) or self.netbios('host', original)
        if kind == 'dns':
            return self.token('dns', 'dns', original.rstrip('.'))
        if kind == 'ip':
            return self.ip(original)
        if kind == 'guid':
            return self.guid(original)
        if kind == 'opaque':
            return self.token('value', 'opaque', original)
        _fail('invalid_choice', 'content.kind')

    def token(self, prefix, namespace, value):
        normalized = value.casefold()
        digest = hmac.new(self._salt, (namespace + '\x00' + normalized).encode('utf-8'),
                          hashlib.sha256).hexdigest()[:16]
        result = prefix + '-' + digest
        previous = self._reverse.setdefault((namespace, digest), normalized)
        if previous != normalized:
            _fail('pseudonym_collision', 'pseudonyms')
        self.mapping.setdefault(namespace, {})[normalized] = result
        return result

    def netbios(self, prefix, value):
        label = value.rstrip('.').split('.', 1)[0]
        if label.casefold() in WELL_KNOWN_NAMES or WELL_KNOWN_NAME.fullmatch(label.casefold()):
            return value
        return self.token(prefix, 'netbios', label)

    def user(self, value):
        if value.casefold() in WELL_KNOWN_NAMES or WELL_KNOWN_NAME.fullmatch(value.casefold()):
            return value
        if value.endswith('$'):
            return self.netbios('host', value[:-1]) + '$'
        return self.token('user', 'user', value)

    def segment(self, value):
        """Path segment; technique-labelled harness folders and the export's own DNS domains become opaque."""
        if ATTACK_TOKEN.search(value):
            return self.token('segment', 'segment', value)
        name = value.casefold().rstrip('.')
        if name and any(name == domain or name.endswith('.' + domain) for domain in self._domains):
            return self.token('dns', 'dns', name)
        for domain in self._domains:
            # Embedded domain, for example an ADSI schema cache file `<domain>.sch`.
            value = re.sub(r'(?i)(?<![a-z0-9-])' + re.escape(domain) + r'(?![a-z0-9-])',
                           lambda m: self.token('dns', 'dns', m.group(0)), value)
        # LDAP distinguished-name runs (for example ADSI registry cache keys): dc=a,dc=b -> one DNS pseudonym.
        return LDAP_DC_RUN.sub(lambda m: m.group(0)[:3] + self.token(
            'dns', 'dns', '.'.join(item.split('=', 1)[1] for item in m.group(0).split(','))), value)

    def sid(self, value):
        match = DOMAIN_SID.match(value)
        if not match:
            return value
        rest = value[match.end():]
        return self.token('sid', 'sid', match.group(0)) + rest

    def path(self, value):
        value = DOMAIN_SID.sub(lambda m: self.token('sid', 'sid', m.group(0)), value)
        if value.startswith('\\\\') and len(value) > 2:
            head, sep, tail = value[2:].partition('\\')
            value = '\\\\' + (self.netbios('host', head) if head and head not in ('?', '.') else head) + sep + tail
        parts = re.split(r'([\\/])', value)
        for index, part in enumerate(parts):
            if part in ('\\', '/'):
                continue
            if index >= 2 and parts[index - 2].casefold() == 'users' and part.casefold() not in PROFILE_SEGMENTS and part:
                parts[index] = self.user(part)
            else:
                parts[index] = self.segment(part)
        return ''.join(parts)

    def basename(self, value):
        name = re.split(r'[\\/]', value)[-1]
        return self.segment(name)

    def account(self, value):
        if '\\' in value:
            domain, _, name = value.partition('\\')
            return self.netbios('domain', domain) + '\\' + self.user(name)
        if '@' in value:
            name, _, domain = value.partition('@')
            return self.user(name) + '@' + self.token('dns', 'dns', domain.rstrip('.'))
        return self.user(value)

    def ip(self, value):
        if value in ('', '-'):
            return value
        try:
            address = ipaddress.ip_address(value.strip('[]'))
        except ValueError:
            return self.token('addr', 'ip', value)
        if getattr(address, 'ipv4_mapped', None):
            address = address.ipv4_mapped
        if address.is_loopback or address.is_unspecified:
            return str(address)
        return self.token('ipv%d' % address.version, 'ip', str(address))

    def guid(self, value):
        core = value.strip('{}')
        if not core or set(core) <= {'0', '-'}:
            return value
        return self.token('guid', 'guid', core)

    def apply(self, transform, value, field):
        if value is None or type(value) in (bool, int):
            return value
        if type(value) is not str:
            _fail('unsupported_record_shape', field)
        if transform == 'keep':
            if len(value) > MAX_KEEP_CHARS:
                _fail('field_too_long', field)
            return value
        if value in ('', '-'):
            return value
        if transform == 'basename':
            return self.basename(value)
        if transform == 'path':
            return self.path(value)
        if transform == 'account':
            return self.account(value)
        if transform == 'user':
            return self.user(value)
        if transform == 'domain':
            return self.netbios('domain', value)
        if transform == 'host':
            return self.netbios('host', value.lstrip('\\'))
        if transform == 'sid':
            return self.sid(value)
        if transform == 'guid':
            return self.guid(value)
        if transform == 'ip':
            return self.ip(value)
        if transform == 'dns':
            return self.token('dns', 'dns', value.rstrip('.'))
        return self.token('value', 'opaque', value)


# ----------------------------------------------------------------- field map

def load_field_map(path=DEFAULT_FIELDS):
    _, data = _read_regular(path, MAX_SIDE_FILE_BYTES, 'fields')
    value = decode_json(data)
    top = {'schema_version', 'version', 'note', 'channels', 'shape_aliases', 'message_fields'}
    if type(value) is not dict or not {'schema_version', 'version', 'note', 'channels'} <= set(value) or \
            set(value) - top:
        _fail('invalid_object', 'fields')
    if value['schema_version'] != 1 or type(value['version']) is not str or not _ID.fullmatch(value['version']):
        _fail('unsupported_schema', 'fields')
    if type(value['channels']) is not dict or not value['channels']:
        _fail('invalid_object', 'fields.channels')
    sources, folded = set(), set()
    for channel, spec in value['channels'].items():
        if type(spec) is not dict or set(spec) != {'source', 'telemetry', 'events'}:
            _fail('invalid_object', 'fields.channels')
        if type(spec['source']) is not str or not _ID.fullmatch(spec['source']) or spec['source'] in sources:
            _fail('invalid_identifier', 'fields.channels.source')
        sources.add(spec['source'])
        if channel.casefold() in folded:
            _fail('duplicate_item', 'fields.channels')
        folded.add(channel.casefold())
        # Null telemetry: the channel makes no coverage-catalog claim (application and product logs).
        if spec['telemetry'] is not None and spec['telemetry'] not in COVERAGE_AXES['telemetry']:
            _fail('invalid_choice', 'fields.channels.telemetry')
        if type(spec['events']) is not dict or not spec['events']:
            _fail('invalid_object', 'fields.channels.events')
        for event_id, fields in spec['events'].items():
            if not re.fullmatch(r'[0-9]{1,5}', event_id) or type(fields) is not dict:
                _fail('invalid_object', 'fields.channels.events')
            for name, transform in fields.items():
                if name in RESERVED_FIELDS or name in NXLOG_RESERVED or name == 'timestamp_original' or \
                        transform not in TRANSFORMS:
                    _fail('invalid_choice', 'fields.channels.events.field')
    aliases = value.get('shape_aliases', {})
    if type(aliases) is not dict or set(aliases) - set(RECORD_SHAPES):
        _fail('invalid_object', 'fields.shape_aliases')
    for shape, channels in aliases.items():
        if type(channels) is not dict or set(channels) - set(value['channels']):
            _fail('invalid_object', 'fields.shape_aliases')
        for channel, events in channels.items():
            allowed = value['channels'][channel]['events']
            if type(events) is not dict or set(events) - set(allowed):
                _fail('invalid_object', 'fields.shape_aliases')
            for event_id, names in events.items():
                # An alias renames one original field to an allowlisted name of the SAME Windows field.
                if type(names) is not dict or len(set(names.values())) != len(names):
                    _fail('invalid_object', 'fields.shape_aliases')
                for original, target in names.items():
                    if type(target) is not str or target not in allowed[event_id] or original in allowed[event_id] \
                            or original in RESERVED_FIELDS or original in NXLOG_RESERVED:
                        _fail('invalid_choice', 'fields.shape_aliases.field')
    parsers = value.get('message_fields', {})
    if type(parsers) is not dict or set(parsers) - set(value['channels']):
        _fail('invalid_object', 'fields.message_fields')
    for channel, events in parsers.items():
        if type(events) is not dict or set(events) - set(value['channels'][channel]['events']) or \
                any(parser not in MESSAGE_PARSERS for parser in events.values()):
            _fail('invalid_object', 'fields.message_fields')
    value['sha256'] = digest_bytes(data)
    return value


# ----------------------------------------------------------- message parsers
# Some exports carry an event's data only in its rendered `Message` (classic Windows PowerShell, and UserData
# events such as WMI-Activity and TerminalServices in the NXLog shape). A parser named in `message_fields`
# extracts named fields from it; they fill only names the record does not already carry, and then pass the
# allowlist and transforms like any record field. The Message itself is never published by a parser.

_PS_CLASSIC_KEY = re.compile(r'\t([A-Za-z][A-Za-z0-9]*)=(.*)\Z', re.S)
_WMI_PROVIDER = re.compile(r'(.+?) provider started with result code (\S+?)\. (.*)\Z', re.S)
_WMI_KEY = re.compile(r'(?:\A|[;,]\s*)([A-Za-z][A-Za-z0-9]*)\s*=\s*')
# Message keys of WMI-Activity 5860/5861 that differ from the event's own UserData names.
_WMI_RENAMES = {5860: {'Namespace': 'NamespaceName', 'NotificationQuery': 'Query', 'UserName': 'User',
                       'ClientProcessID': 'processid', 'ClientMachine': 'MachineName'},
                5861: {'Eventfilter': 'ESS', 'Consumer': 'CONSUMER'}}
_TS_LINES = {'User': 'User', 'Session ID': 'SessionID', 'Source Network Address': 'Address'}
_TS_LINE = re.compile(r'(User|Session ID|Source Network Address):[ \t]*(.*)\Z')
_TS_SENTENCES = (re.compile(r'Session (?P<TargetSession>[0-9]+) has been disconnected by session (?P<Source>[0-9]+)'),
                 re.compile(r'Session (?P<Session>[0-9]+) has been disconnected, reason code (?P<Reason>[0-9]+)'))


def _parse_powershell_classic(message, event_id):
    """Windows PowerShell 400/403/600/800: `\\tKey=Value` lines; 800 adds a raw `Details:` invocation block."""
    fields, last, details, context = {}, None, None, False
    for line in message.split('\r\n'):
        if details is not None:
            details.append(line)
            continue
        stripped = line.strip()
        if stripped == 'Context Information:':
            context, last = True, None
            continue
        if stripped == 'Details:':
            if context:
                details = []
            last = None
            continue
        match = _PS_CLASSIC_KEY.match(line)
        if match and match.group(1) not in fields:
            last = match.group(1)
            fields[last] = match.group(2)
        elif last is not None:
            fields[last] += '\r\n' + line
    if details is not None:
        fields['Details'] = '\r\n'.join(details)
    return {name: text.strip() for name, text in fields.items()}


def _parse_powershell_module(message, event_id):
    """PowerShell/Operational 4103: `<Payload>\\r\\n\\r\\n\\r\\nContext:\\r\\n<ContextInfo>[\\r\\n\\r\\nUser Data:...]`."""
    payload, marker, rest = message.partition('\r\n\r\n\r\nContext:\r\n')
    fields = {'Payload': payload.strip()}
    if marker:
        fields['ContextInfo'] = rest.split('\r\n\r\nUser Data:', 1)[0].rstrip()
    return fields


def _parse_wmi_activity(message, event_id):
    """WMI-Activity: optional `<provider> provider started with result code <code>. ` then `Key = value; ...`."""
    fields = {}
    match = _WMI_PROVIDER.match(message)
    if match:
        fields['ProviderName'], fields['Code'], message = match.groups()
    renames = _WMI_RENAMES.get(event_id, {})
    keys = list(_WMI_KEY.finditer(message))
    for index, key in enumerate(keys):
        name = key.group(1)
        # PossibleCause is free text (WMI 5861 embeds whole MOF instances): it runs to the end.
        end = len(message) if name == 'PossibleCause' or index + 1 == len(keys) else keys[index + 1].start()
        fields.setdefault(renames.get(name, name), message[key.end():end].strip())
        if name == 'PossibleCause':
            break
    return fields


def _parse_terminal_services(message, event_id):
    """TerminalServices-LocalSessionManager: `User:`/`Session ID:`/`Source Network Address:` lines or sentences."""
    fields = {}
    for line in message.split('\r\n'):
        match = _TS_LINE.match(line.strip())
        if match:
            fields.setdefault(_TS_LINES[match.group(1)], match.group(2).strip())
    for pattern in _TS_SENTENCES:
        match = pattern.search(message)
        if match:
            for name, text in match.groupdict().items():
                fields.setdefault(name, text)
    return fields


MESSAGE_PARSERS = {'powershell-classic': _parse_powershell_classic, 'powershell-module': _parse_powershell_module,
                   'wmi-activity': _parse_wmi_activity, 'terminal-services': _parse_terminal_services}


# ------------------------------------------------------------------- records

def _utc_text(moment):
    return moment.astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f+00:00')


def _parse_time(text, naive_utc, field):
    if type(text) is not str:
        _fail('invalid_timestamp', field)
    if AWARE_TIME.fullmatch(text):
        return parse_utc(text, field), False
    match = NAIVE_TIME.fullmatch(text)
    if not match:
        _fail('invalid_timestamp', field)
    if not naive_utc:
        _fail('naive_timestamp', field)
    return parse_utc(match.group(1) + 'T' + match.group(2) + 'Z', field), True


def _record_shape(record, field):
    """Classify one decoded record; anything outside the two inspected shapes is refused."""
    if type(record) is not dict:
        _fail('unsupported_record_shape', field)
    if 'TimeCreated' in record and 'EventTime' not in record:
        shape = SHAPE_FLAT
    elif 'EventTime' in record and 'TimeCreated' not in record and record.get('SourceModuleType') == 'im_msvistalog':
        shape = SHAPE_NXLOG
    else:
        _fail('unsupported_record_shape', field)
    for key, value in record.items():
        if shape == SHAPE_NXLOG and key == 'tags':
            if type(value) is not list or len(value) > 64 or not all(type(item) is str for item in value):
                _fail('unsupported_record_shape', field)
        elif type(value) not in (str, int, bool, type(None)):
            _fail('unsupported_record_shape', field)
    if shape == SHAPE_NXLOG and (type(record.get('RecordNumber')) is not int or record['RecordNumber'] < 0 or
                                 type(record['EventTime']) is not str):
        _fail('unsupported_record_shape', field)
    return shape


def parse_records(member, field_map, naive_utc=False):
    """Return (entries, shape): one entry per ORIGINAL line; nothing is silently dropped."""
    if member[:3] == b'\xef\xbb\xbf':
        member = member[3:]
    if member.lstrip()[:1] == b'[':
        _fail('unsupported_dataset_layout', 'dataset')
    lines = member.split(b'\n')
    if lines and lines[-1] == b'':
        lines.pop()
    if len(lines) > MAX_RECORDS:
        _fail('too_many_records', 'dataset')
    # Windows event log channel names are case-insensitive; match the allowlist that way and publish its spelling.
    channels = {name.casefold(): name for name in field_map['channels']}
    entries, shape = [], None
    for number, raw in enumerate(lines, 1):
        if raw.endswith(b'\r'):
            raw = raw[:-1]
        field = 'dataset.line.%d' % number
        if len(raw) > MAX_LINE_BYTES:
            _fail('line_too_large', field)
        entry = {'line': number, 'line_sha256': digest_bytes(raw)}
        if not raw.strip():
            entry['status'] = 'blank_line'
            entries.append(entry)
            continue
        try:
            record = decode_json(raw)
        except BenchmarkError:
            _fail('invalid_json', field)
        detected = _record_shape(record, field)
        if shape is None:
            shape = detected
            if shape == SHAPE_NXLOG and naive_utc:
                _fail('conflicting_arguments', 'naive_timestamps_utc')
        elif detected != shape:
            _fail('mixed_record_shapes', field)
        channel, event_id, host = record.get('Channel'), record.get('EventID'), record.get('Hostname')
        if type(event_id) is str and re.fullmatch(r'[0-9]{1,5}', event_id):
            event_id = int(event_id)
        if type(channel) is not str or type(event_id) is not int or type(host) is not str or not _HOST.fullmatch(host):
            _fail('unsupported_record_shape', field)
        if shape == SHAPE_FLAT:
            moment, naive = _parse_time(record.get('TimeCreated'), naive_utc, field)
            record_id = record.get('EventRecordID', record.get('RecordNumber'))
        else:
            # NXLog EventTime: zone-less collector wall clock, whole seconds. Read as a placeholder UTC value here;
            # build_case requires a Sysmon UtcTime reference to place it (see measure_clock).
            match = NXLOG_TIME.fullmatch(record['EventTime'])
            if not match:
                _fail('invalid_timestamp', field)
            moment, naive = parse_utc(match.group(1) + 'T' + match.group(2) + 'Z', field), False
            record_id = record['RecordNumber']
        canonical = channels.get(channel.casefold(), channel)
        spec = field_map['channels'].get(canonical)
        entry.update({'record': record, 'channel': canonical, 'channel_original': channel, 'event_id': event_id,
                      'host': host, 'time': moment, 'naive': naive,
                      'record_id': None if record_id is None else str(record_id)})
        # Every record is imported: allowlisted types with their fields, any other type metadata-only.
        entry['status'] = 'imported'
        entry['coverage'] = 'allowlisted' if spec is not None and str(event_id) in spec['events'] else \
            'metadata_only'
        entries.append(entry)
    if not any(entry['status'] == 'imported' for entry in entries):
        _fail('no_supported_records', 'dataset')
    return entries, shape


# ----------------------------------------------------------------- curation

# Curation locators: original line; record number alone (must be unique in the export); or record number
# qualified by channel and hostname (Windows record numbers are per log per computer).
_LOCATOR_KEYS = ({'line'}, {'record_id'}, {'record_id', 'channel', 'hostname'})


def _strict(value, required, field, optional=()):
    if type(value) is not dict:
        _fail('invalid_object', field)
    if not set(required) <= set(value):
        _fail('missing_field', field)
    if set(value) - set(required) - set(optional):
        _fail('unknown_field', field)


def _text(value, field, nullable=False):
    if nullable and value is None:
        return
    if type(value) is not str or not value.strip() or '\x00' in value:
        _fail('invalid_text', field)


def _asset_selector(value, hosts, field):
    _strict(value, {'hostname'}, field)
    if type(value['hostname']) is not str or value['hostname'].casefold() not in hosts:
        _fail('unknown_asset', field)
    return value['hostname'].casefold()


PROPOSAL_STATUS = 'PROPOSED_UNREVIEWED_NOT_FOR_SCORING'
UNREVIEWED_LIMITATION = ('Answer key is an UNREVIEWED agent proposal (truth attestation unreviewed_proposal): no '
                         'human curator validated its steps, support sets, controls or labels. Scores from it '
                         'carry truth_attestation unreviewed_proposal and are never compared with human-attested '
                         'truth.')
CONSENSUS_HINT = 'agent_consensus'
CONSENSUS_CURATOR = 'agent-consensus'
CONSENSUS_LIMITATION = ('Answer key is an AGENT CONSENSUS of two independent AI drafts merged mechanically; no human '
                        'reviewed it (truth attestation agent_consensus). Steps, controls and labels the drafts '
                        'disagreed on are dropped: disputed records are ignored by scoring and disputed questions '
                        'carry a null label. Scores from it carry truth_attestation agent_consensus and are never '
                        'compared with human-attested or proposal truth.')
_LIMITATION_BY_ATTESTATION = {'unreviewed_proposal': UNREVIEWED_LIMITATION, 'agent_consensus': CONSENSUS_LIMITATION}


def _proposal_attestation(value, field):
    """Classify a decoded curation: `unreviewed_proposal`, `agent_consensus` or `human_attested`.

    Proposals lose `status` and must still carry a null curator: nothing here attests them. An agent consensus
    loses `attestation_hint` and must name the fixed automation curator, never a human.
    """
    if type(value) is not dict:
        return 'human_attested'
    if 'attestation_hint' in value:
        if value.pop('attestation_hint') != CONSENSUS_HINT or 'status' in value:
            _fail('invalid_attestation_hint', field + '.attestation_hint')
        if value.get('curated_by') != CONSENSUS_CURATOR:
            _fail('consensus_curator_mismatch', field + '.curated_by')
        return 'agent_consensus'
    if 'status' not in value:
        return 'human_attested'
    if value.pop('status') != PROPOSAL_STATUS:
        _fail('invalid_proposal_status', field + '.status')
    if value.get('curated_by') is not None or value.get('curated_utc') is not None:
        _fail('proposal_has_curator', field + '.curated_by')
    return 'unreviewed_proposal'


def _check_curator(value, attestation, field):
    if 'excluded_locators' in value and attestation != 'agent_consensus':
        _fail('excluded_without_consensus', field + '.excluded_locators')
    if attestation == 'unreviewed_proposal':
        _text(value['note'], field + '.note', nullable=True)
        return
    for key in ('curated_by', 'note'):
        _text(value[key], field + '.' + key)
    if attestation == 'human_attested' and value['curated_by'].strip().casefold() == CONSENSUS_CURATOR:
        # Stripping the hint must never turn an automatic consensus into human attestation.
        _fail('consensus_hint_missing', field + '.curated_by')
    parse_utc(value['curated_utc'], field + '.curated_utc')


def load_curation(path):
    """Return (curation, bytes); curation['attestation'] is one of benchmark_contracts.TRUTH_ATTESTATIONS."""
    _, data = _read_regular(path, MAX_SIDE_FILE_BYTES, 'curation')
    value = decode_json(data)
    field = 'curation'
    attestation = _proposal_attestation(value, field)
    _strict(value, {'schema_version', 'dataset_sha256', 'metadata_sha256', 'curated_by', 'curated_utc',
                    'note', 'revision', 'truth_revision', 'attack_release', 'coverage', 'assets',
                    'steps', 'edges', 'controls', 'lookalike_event_ids', 'sophistication',
                    'source_references'}, field,
            {'assessment_windows', 'matched_control', 'family_id', 'excluded_locators'})
    if value['schema_version'] != 1:
        _fail('unsupported_schema', field + '.schema_version')
    for key in ('dataset_sha256', 'metadata_sha256'):
        if type(value[key]) is not str or not re.fullmatch(r'[0-9a-f]{64}', value[key]):
            _fail('invalid_digest', field + '.' + key)
    _check_curator(value, attestation, field)
    for key in ('revision', 'truth_revision'):
        if type(value[key]) is not int or value[key] < 1:
            _fail('invalid_integer', field + '.' + key)
    if 'family_id' in value:
        _family_override(value['family_id'], field + '.family_id')
    value['attestation'] = attestation
    return value, data


def _limitations(limitations, attestation, field):
    if type(limitations) is not list:
        _fail('invalid_array', field)
    extra = _LIMITATION_BY_ATTESTATION.get(attestation)
    return limitations + [extra] if extra else limitations


def _excluded_event_ids(curation, resolve, by_line, by_record, steps, lookalikes, field):
    """Public IDs of records only disputed consensus steps cited; never support or lookalike evidence."""
    field += '.excluded_locators'
    locators = curation.get('excluded_locators', [])
    if type(locators) is not list:
        _fail('invalid_array', field)
    ids = [resolve(locator, by_line, by_record, field)['event_id_public'] for locator in locators]
    if len(set(ids)) != len(ids):
        _fail('duplicate_item', field)
    cited = {item for step in steps for group in step['support_sets'] for item in group}
    cited.update(item for group in lookalikes for item in group)
    if cited & set(ids):
        _fail('excluded_overlap', field)
    return sorted(ids)


def _unlabeled(attestation, field):
    """A question no curated step or control covers: only an agent consensus may leave it disputed (null)."""
    if attestation != 'agent_consensus':
        _fail('unlabeled_question', field)
    return None


def _undisputed(truth, disputed_questions):
    """Truth as seen by difficulty measurement: a disputed question is disagreement, not an evidence gap."""
    if not disputed_questions:
        return truth
    return dict(truth, assessment_labels={key: label for key, label in truth['assessment_labels'].items()
                                          if key not in disputed_questions})


def _attest_truth(truth, curation, disputed_ids, disputed_questions, curated):
    """Record a non-human attestation on truth and the import report's curation section."""
    attestation = curation['attestation']
    if attestation != 'human_attested':
        truth['attestation'] = attestation
    if disputed_ids:
        truth['disputed_event_ids'] = disputed_ids
        curated['disputed_evidence'] = {
            'event_ids': len(disputed_ids),
            'note': 'records cited only by disputed agent-consensus steps; scoring ignores findings citing only these'}
    if attestation == 'agent_consensus':
        curated['disputed_questions'] = disputed_questions
    return truth


def _summarize_attestation(report, summary):
    attestation = report.get('curation', {}).get('attestation')
    if attestation is not None:
        summary['attestation'] = attestation
    if attestation == 'unreviewed_proposal':
        summary['warning'] = ('UNREVIEWED PROPOSAL: truth is attestation=unreviewed_proposal; '
                              'its scores form a separate cohort.')
    elif attestation == 'agent_consensus':
        summary['warning'] = ('AGENT CONSENSUS: truth is attestation=agent_consensus (two AI drafts merged '
                              'mechanically, no human review); its scores form a separate cohort.')


def _family_from_techniques(techniques):
    return 'otrf-' + '-'.join(t.casefold().replace('.', '-') for t in sorted(set(techniques)))


def _family_override(value, field):
    """A reviewer's family_id must look exactly like a metadata-derived one: sorted, unique technique tokens."""
    if type(value) is not str or not FAMILY_ID.fullmatch(value):
        _fail('invalid_identifier', field)
    tokens = re.findall(r't([0-9]{4})(?:-([0-9]{3}))?', value[len('otrf-'):])
    techniques = ['T' + base + ('.' + sub if sub else '') for base, sub in tokens]
    if _family_from_techniques(techniques) != value:
        _fail('invalid_identifier', field)


def _resolve(locator, by_line, by_record, field):
    if type(locator) is not dict or set(locator) not in _LOCATOR_KEYS:
        _fail('invalid_locator', field)
    if 'line' in locator:
        if type(locator['line']) is not int or locator['line'] < 1:
            _fail('invalid_locator', field)
        entry = by_line.get(locator['line'])
    else:
        if type(locator['record_id']) is not str or not locator['record_id']:
            _fail('invalid_locator', field)
        matches = by_record.get(locator['record_id'], [])
        if 'channel' in locator:
            if type(locator['channel']) is not str or type(locator['hostname']) is not str:
                _fail('invalid_locator', field)
            matches = [e for e in matches if e['channel'].casefold() == locator['channel'].casefold()
                       and e['host'].casefold() == locator['hostname'].casefold()]
        if len(matches) > 1:
            _fail('ambiguous_locator', field)
        entry = matches[0] if matches else None
    if entry is None:
        _fail('unknown_locator', field)
    if entry['status'] != 'imported':
        _fail('support_record_not_imported', field)
    return entry


def _locator_groups(groups, by_line, by_record, field, nonempty_groups=True):
    if type(groups) is not list:
        _fail('invalid_array', field)
    result = []
    for group in groups:
        if type(group) is not list or (nonempty_groups and not group):
            _fail('invalid_array', field)
        result.append([_resolve(locator, by_line, by_record, field) for locator in group])
    return result


def _receipt(dataset_sha, member_name, groups):
    lines = [[{'line': entry['line'], 'line_sha256': entry['line_sha256']}
              for entry in sorted(group, key=lambda e: e['line'])] for group in groups]
    return digest_bytes(canonical_bytes({'dataset_sha256': dataset_sha, 'member': member_name,
                                         'support_sets': sorted(lines, key=canonical_bytes)}))


def _overlaps(a, b):
    return a[0] < b[1] and b[0] < a[1]


def _window_tuple(value, field, outer):
    _strict(value, {'start_inclusive', 'end_exclusive'}, field)
    start = parse_utc(value['start_inclusive'], field + '.start_inclusive')
    end = parse_utc(value['end_exclusive'], field + '.end_exclusive')
    if start >= end or start < outer[0] or end > outer[1]:
        _fail('invalid_window', field)
    return start, end


def _normal_window(window):
    return {'start_inclusive': _utc_text(window[0]), 'end_exclusive': _utc_text(window[1])}


def _content_identities(names, hosts):
    """Every identity the import has pseudonymized so far, plus the export's own hostnames and DNS domains."""
    mapping = {namespace: set(names.mapping.get(namespace, {})) for namespace in CONTENT_IDENTITY_NAMESPACES}
    mapping['dns'].update(host for host in hosts if '.' in host.strip('.'))
    mapping['dns'].update(names.domains)
    mapping['netbios'].update(host.split('.', 1)[0] for host in hosts)
    return mapping


def _mapping_size(names):
    return sum(len(values) for values in names.mapping.values())


def _sanitize_content(pending, names, hosts, encoded_payloads):
    """Sanitize every pending content value; returns (per-field totals, truncations per source key, passes).

    A content value can name an identity first seen in a later record or another content value, so the values
    are re-sanitized from their originals until no new pseudonym appears (bounded by MAX_CONTENT_PASSES); any
    identity still raw afterwards fails the public leak check.
    """
    passes, results = 0, []
    while pending:
        passes += 1
        size = _mapping_size(names)
        known = KnownIdentities(_content_identities(names, hosts))
        results = [sanitize_text(original, names.content, identities=known, field=label,
                                 encoded_payloads=encoded_payloads)
                   for _, _, original, label, _, _ in pending]
        if _mapping_size(names) == size or passes == MAX_CONTENT_PASSES:
            break
    totals, truncated = {}, {}
    for (fields, name, _, _, key, entry), (text, report) in zip(pending, results):
        fields[name] = text
        merge_reports(totals.setdefault(key, new_totals()), report)
        if report['truncated']:
            truncated[entry['source_key']] = truncated.get(entry['source_key'], 0) + 1
    return dict(sorted(totals.items())), truncated, passes


def _rewrite_structured(rewritable, names, hosts):
    """Pseudonymize identities that content revealed inside kept/path structured values (else a leak refusal).

    Example: a profile user first seen in a command line also names a kernel object in a 4674 ObjectName.
    Returns {"Channel:EventID Field": rewritten value count}.
    """
    known = KnownIdentities(_content_identities(names, hosts))
    rewrites = {}
    for fields, name, key in rewritable:
        value = known.sub(fields[name], names.content)
        if value != fields[name]:
            fields[name] = value
            rewrites[key] = rewrites.get(key, 0) + 1
    return dict(sorted(rewrites.items()))


# ------------------------------------------------------------------ building

def measure_clock(entries, time_field='TimeCreated'):
    """Measure the export clock against Sysmon's own UtcTime field.

    Inspected flat OTRF exports format TimeCreated as LOCAL 12-hour time while
    labelling it `Z` (for example 11:28Z against Sysmon UtcTime 03:28 the next
    day). Inspected NXLog exports write EventTime as the WEC collector's zone-less
    local wall clock truncated to whole seconds (UTC-4 in all seven inspected
    datasets). Sysmon's UtcTime is documented UTC, so the offset
    `time_field`-UtcTime is measured per record. A consistent offset (rounded to
    the quarter-hour time-zone grid) is applied to every record of the export and
    published as the source clock offset with the measured residual as its
    uncertainty. An inconsistent offset (for example a 12-hour wrap inside the
    dataset) is refused rather than guessed. No Sysmon reference: offset stays
    unknown (build_case refuses that for NXLog exports).
    """
    deltas = []
    for entry in entries:
        value = entry['record'].get('UtcTime') if entry['channel'] == 'Microsoft-Windows-Sysmon/Operational' else None
        if type(value) is not str:
            continue
        match = NAIVE_TIME.fullmatch(value)
        if not match:
            continue
        reference = parse_utc(match.group(1) + 'T' + match.group(2) + 'Z', 'dataset.UtcTime')
        deltas.append((entry['time'] - reference).total_seconds())
    if not deltas:
        return {'offset_seconds': None, 'uncertainty_seconds': None, 'reference_records': 0,
                'note': 'absolute time unverified: no Sysmon UtcTime reference in this export'}
    deltas.sort()
    if deltas[-1] - deltas[0] > 300:
        _fail('inconsistent_timestamps', 'dataset.' + time_field)
    median = deltas[len(deltas) // 2]
    offset = int(round(median / 900.0)) * 900
    residual = max(abs(item - offset) for item in deltas)
    uncertainty = (int(residual * 1000) + 1) / 1000.0
    note = ('%s corrected by %d s measured against Sysmon UtcTime on %d records'
            % (time_field, offset, len(deltas))) if offset else '%s agrees with Sysmon UtcTime' % time_field
    return {'offset_seconds': offset, 'uncertainty_seconds': uncertainty,
            'reference_records': len(deltas), 'note': note}


def _attack_url(technique):
    return 'https://attack.mitre.org/techniques/' + technique.replace('.', '/') + '/'


def build_case(dataset_path, metadata_path, field_map, salt, curation_path=None,
               draft_os_family=None, naive_utc=False, max_member_bytes=MAX_MEMBER_BYTES,
               coverage=None, encoded_payloads='preview'):
    """Build every output in memory and validate it; returns {relative_path: bytes}."""
    if encoded_payloads not in ENCODED_PAYLOAD_MODES:
        _fail('invalid_choice', 'encoded_payloads')
    input_path, input_bytes, member_name, member = read_dataset(dataset_path, max_member_bytes)
    _, metadata_bytes = _read_regular(metadata_path, MAX_METADATA_BYTES, 'metadata')
    metadata = parse_metadata_yaml(metadata_bytes)
    _bind_metadata(metadata, input_path.name, member_name)
    dataset_sha, metadata_sha = digest_bytes(input_bytes), digest_bytes(metadata_bytes)
    member_sha = digest_bytes(member)
    curation = curation_bytes = None
    if curation_path is not None:
        if draft_os_family is not None:
            _fail('conflicting_arguments', 'draft_os_family')
        curation, curation_bytes = load_curation(curation_path)
        if curation['dataset_sha256'] != dataset_sha or curation['metadata_sha256'] != metadata_sha:
            _fail('curation_dataset_mismatch', 'curation')
    elif draft_os_family not in COVERAGE_AXES['os']:
        _fail('invalid_choice', 'draft_os_family')

    entries, shape = parse_records(member, field_map, naive_utc)
    time_field = 'TimeCreated' if shape == SHAPE_FLAT else 'EventTime'
    reserved = RESERVED_FIELDS if shape == SHAPE_FLAT else NXLOG_RESERVED
    names = Pseudonyms(salt)
    imported = [e for e in entries if e['status'] == 'imported']
    with_records = [e for e in entries if 'record' in e]
    hosts = sorted({e['host'].casefold() for e in with_records})
    names.register_domains(hosts)
    collectors = None
    if shape == SHAPE_NXLOG:
        # One forwarding collector renders every EventTime, so one measured offset applies to all hosts.
        collectors = len({e['record'].get('host') for e in with_records})
        if collectors != 1:
            _fail('multiple_collectors', 'dataset.host')
    clock = measure_clock(with_records, time_field)
    if shape == SHAPE_NXLOG and clock['offset_seconds'] is None:
        _fail('no_clock_reference', 'dataset.EventTime')
    if clock['offset_seconds'] is not None:
        shift = timedelta(seconds=clock['offset_seconds'])
        for entry in with_records:
            entry['time'] = entry['time'] - shift
    stamps = [e['time'] for e in with_records]
    outer = (min(stamps).replace(microsecond=0), max(stamps).replace(microsecond=0) + timedelta(seconds=1))
    window = _normal_window(outer)
    case_id = 'case-' + hmac.new(salt, ('case\x00' + dataset_sha).encode('utf-8'), hashlib.sha256).hexdigest()[:16]

    # Assets: explicit facts from curation, or one operator-declared OS for a draft.
    if curation is not None:
        facts = {}
        if type(curation['assets']) is not list:
            _fail('invalid_array', 'curation.assets')
        for item in curation['assets']:
            _strict(item, {'hostname', 'os_family', 'os_version', 'architecture', 'vendor'}, 'curation.assets')
            if type(item['hostname']) is not str or item['hostname'].casefold() in facts:
                _fail('duplicate_item', 'curation.assets')
            if item['os_family'] not in COVERAGE_AXES['os']:
                _fail('invalid_choice', 'curation.assets.os_family')
            for key in ('os_version', 'architecture', 'vendor'):
                _text(item[key], 'curation.assets.' + key, True)
            facts[item['hostname'].casefold()] = item
        if set(facts) != set(hosts):
            _fail('curation_assets_mismatch', 'curation.assets')
    else:
        facts = {host: {'os_family': draft_os_family, 'os_version': None, 'architecture': None, 'vendor': None}
                 for host in hosts}
    asset_ids = {host: names.token('asset', 'asset', host) for host in hosts}
    assets = [{'asset_id': asset_ids[host], 'os_family': facts[host]['os_family'],
               'os_version': facts[host]['os_version'], 'architecture': facts[host]['architecture'],
               'vendor': facts[host]['vendor']} for host in hosts]
    assets.sort(key=lambda a: a['asset_id'])

    # Events: allowlisted fields only, pseudonymized, original + normalized times. Unlisted event types and
    # channels are imported metadata-only. Content fields are sanitized after every structured field is known.
    dropped_fields, imported_counts, metadata_counts, metadata_dropped = {}, {}, {}, {}
    aliased, collisions, spellings, parsed_counts = {}, {}, {}, {}
    shape_aliases = field_map.get('shape_aliases', {}).get(shape, {})
    message_parsers = field_map.get('message_fields', {})
    naive_used = False
    events, source_keys, telemetry_of, pending, rewritable = [], {}, {}, [], []
    for entry in entries:
        if 'record' not in entry:
            continue
        if entry['channel_original'] != entry['channel']:
            spelling = entry['channel_original'] + ' -> ' + entry['channel']
            spellings[spelling] = spellings.get(spelling, 0) + 1
        type_key = entry['channel'] + ':' + str(entry['event_id'])
        spec = field_map['channels'].get(entry['channel'])
        source_name = spec['source'] if spec is not None else 'channel:' + entry['channel'].casefold()
        telemetry_of[source_name] = spec['telemetry'] if spec is not None else None
        record = entry['record']
        fields = {'timestamp_original': record[time_field], 'Channel': entry['channel'],
                  'EventID': entry['event_id']}
        if entry['coverage'] == 'metadata_only':
            metadata_counts[type_key] = metadata_counts.get(type_key, 0) + 1
            for key in sorted(record):
                if key in reserved:
                    continue
                if key not in METADATA_FIELDS:
                    metadata_dropped[key] = metadata_dropped.get(key, 0) + 1
                    continue
                value = names.apply('keep', record[key], source_name + '.' + str(entry['event_id']) + '.' + key)
                if type(value) is str and ATTACK_TOKEN.search(value):
                    _fail('attack_token_in_field', source_name + '.' + str(entry['event_id']) + '.' + key)
                fields[key] = value
                if type(value) is str:
                    rewritable.append((fields, key, type_key + ' ' + key))
        else:
            imported_counts[type_key] = imported_counts.get(type_key, 0) + 1
            allow = spec['events'][str(entry['event_id'])]
            renames = shape_aliases.get(entry['channel'], {}).get(str(entry['event_id']), {})
            parser = message_parsers.get(entry['channel'], {}).get(str(entry['event_id']))
            parsed = {}
            if parser is not None and type(record.get('Message')) is str:
                parsed = {name: text for name, text in MESSAGE_PARSERS[parser](record['Message'],
                                                                              entry['event_id']).items()
                          if name not in record and name not in reserved and name != 'timestamp_original'}
                if parsed:
                    parsed_counts[type_key] = parsed_counts.get(type_key, 0) + 1
            items = [(key, record[key], False) for key in sorted(record)] + \
                    [(key, parsed[key], True) for key in sorted(parsed)]
            for key, original, from_message in items:
                if key in reserved:
                    continue
                name = renames.get(key, key)
                label = spec['source'] + '.' + str(entry['event_id']) + '.' + name
                if name != key:
                    if name in record:
                        _fail('duplicate_field_alias', label)
                    alias = type_key + ' ' + key + ' -> ' + name
                    aliased[alias] = aliased.get(alias, 0) + 1
                if name not in allow:
                    dropped_fields[key] = dropped_fields.get(key, 0) + 1
                    continue
                if shape == SHAPE_NXLOG and not from_message and name in NXLOG_ENVELOPE and \
                        not (name == 'EventType' and 'EventTypeOrignal' in record):
                    collision = type_key + ' ' + name
                    collisions[collision] = collisions.get(collision, 0) + 1
                    dropped_fields[key] = dropped_fields.get(key, 0) + 1
                    continue
                if allow[name] == 'content' and type(original) is str:
                    fields[name] = None
                    pending.append((fields, name, original, label, type_key + ' ' + name, entry))
                    continue
                value = names.apply('keep' if allow[name] == 'content' else allow[name], original, label)
                if type(value) is str and ATTACK_TOKEN.search(value):
                    _fail('attack_token_in_field', label)
                fields[name] = value
                if type(value) is str and allow[name] in ('keep', 'path', 'basename', 'content'):
                    rewritable.append((fields, name, type_key + ' ' + name))
        naive_used = naive_used or entry['naive']
        host = entry['host'].casefold()
        source_key = (source_name, host)
        if source_key not in source_keys:
            source_keys[source_key] = names.token('source', 'source', source_name + '|' + host)
        entry['source_key'] = source_key
        entry['event_id_public'] = names.token('event', 'event', str(entry['line']))
        events.append({'event_id': entry['event_id_public'], 'timestamp_utc': _utc_text(entry['time']),
                       'source_id': source_keys[source_key], 'asset_id': asset_ids[host],
                       'event_type': source_name + ':' + str(entry['event_id']), 'fields': fields})
    content_totals, truncated, passes = _sanitize_content(pending, names, hosts, encoded_payloads)
    structured_rewrites = _rewrite_structured(rewritable, names, hosts)
    events.sort(key=lambda e: (e['timestamp_utc'], e['event_id']))

    # records.jsonl mirrors the ORIGINAL line structure: line N is original line N.
    by_event = {e['event_id']: e for e in events}
    lines = []
    for entry in entries:
        if entry['status'] == 'imported':
            lines.append(canonical_bytes(by_event[entry['event_id_public']]))
        else:
            lines.append(canonical_bytes({'line': entry['line'], 'status': 'not_imported', 'reason': entry['status']}))
    records = b''.join(line + b'\n' for line in lines)
    records_sha = digest_bytes(records)
    line_of = {entry['event_id_public']: entry['line'] for entry in imported}
    for event in events:
        event['locator'] = {'file_sha256': records_sha, 'record_id': str(line_of[event['event_id']])}

    # Sources; explicit gaps only where content was truncated (metadata-only events are imported, not gaps).
    sources, gaps = [], []
    notes = [clock['note']]
    if naive_used:
        notes.append('zone-less TimeCreated declared UTC by the importing operator')
    if shape == SHAPE_NXLOG:
        notes.append('EventTime is the forwarding collector\'s zone-less wall clock with whole-second resolution')
    config = '; '.join(notes)
    for (source, host), source_id in sorted(source_keys.items(), key=lambda item: item[1]):
        sources.append({'source_id': source_id, 'asset_ids': [asset_ids[host]], 'telemetry': telemetry_of[source],
                        'clock_offset_seconds': clock['offset_seconds'],
                        'clock_uncertainty_seconds': clock['uncertainty_seconds'],
                        'window_utc': window, 'sensor_version': None, 'config_version': config,
                        'completeness': 'partial' if (source, host) in truncated else 'complete',
                        'source_sha256': records_sha})
        if (source, host) in truncated:
            gaps.append({'source_id': source_id, 'asset_id': asset_ids[host], 'window_utc': window,
                         'reason': 'content_truncated: %d content field values exceeded %d bytes; each keeps its '
                                   'first %d bytes and ends with an explicit truncation marker'
                                   % (truncated[(source, host)], MAX_CONTENT_BYTES, MAX_CONTENT_BYTES)})
    gaps.sort(key=lambda g: (g['asset_id'], g['source_id'] or '', g['reason']))

    # Assessment grid: every asset x every declared window, including controls.
    if curation is not None and 'assessment_windows' in curation:
        if type(curation['assessment_windows']) is not list or not curation['assessment_windows']:
            _fail('invalid_array', 'curation.assessment_windows')
        windows = [_window_tuple(w, 'curation.assessment_windows', outer) for w in curation['assessment_windows']]
        if len(set(windows)) != len(windows):
            _fail('duplicate_item', 'curation.assessment_windows')
    else:
        windows = [outer]
    questions = []
    for asset in assets:
        for item in windows:
            normal = _normal_window(item)
            questions.append({'question_id': names.token('question', 'question', asset['asset_id'] + canonical_bytes(normal).decode('utf-8')),
                              'asset_id': asset['asset_id'], 'window_utc': normal, 'question': ASSESSMENT_QUESTION})
    questions.sort(key=lambda q: q['question_id'])

    bundle = {'schema_version': 1, 'case_id': case_id, 'window_utc': window, 'assets': assets,
              'sources': sources, 'events': events, 'known_gaps': gaps,
              'files': [{'path': 'records.jsonl', 'byte_count': len(records), 'sha256': records_sha}],
              'assessment_questions': questions}
    validate_public_bundle(bundle)
    public_bytes = canonical_bytes(bundle)
    _leak_check(public_bytes + records, metadata, input_path.name, member_name, names, hosts)
    manifest_sha = digest_bytes(public_bytes)

    by_line = {e['line']: e for e in entries}
    by_record = {}
    for entry in with_records:
        for key in ('EventRecordID', 'RecordNumber'):
            if key in entry['record'] and entry['record'][key] is not None:
                by_record.setdefault(str(entry['record'][key]), []).append(entry)
    # Evaluator locators: original line + line digest always; the export's own record number (RecordNumber /
    # EventRecordID) with its channel and computer when the shape carries one, else null.
    locators = {'schema_version': 1, 'dataset_sha256': dataset_sha, 'member': member_name,
                'member_sha256': member_sha, 'records_sha256': records_sha, 'record_shape': shape,
                'events': {e['event_id_public']: {'line': e['line'], 'line_sha256': e['line_sha256'],
                                                  'record_id': e['record_id'], 'channel': e['channel'],
                                                  'hostname': e['host']}
                           for e in imported}}
    report = {'schema_version': 1, 'importer_version': IMPORTER_VERSION,
              'status': 'curated' if curation is not None else DRAFT_MARKER,
              'split': 'development', 'provenance': 'public_replay',
              'dataset': {'file': input_path.name, 'sha256': dataset_sha, 'member': member_name,
                          'member_sha256': member_sha, 'byte_count': len(input_bytes),
                          'member_byte_count': len(member)},
              'metadata': {'file_sha256': metadata_sha, 'id': metadata['id'], 'title': metadata['title'],
                           'type': metadata['type'], 'declared_techniques': metadata['techniques'],
                           'links': metadata['links']},
              'field_map': {'version': field_map['version'], 'sha256': field_map['sha256']},
              'record_shape': {'shape': shape, 'time_field': time_field,
                               'record_id_field': 'RecordNumber' if shape == SHAPE_NXLOG else
                                                  ('EventRecordID|RecordNumber'
                                                   if any(e['record_id'] is not None for e in with_records) else None),
                               'collectors': collectors,
                               'channel_spellings_normalized': dict(sorted(spellings.items())),
                               'aliased_fields': dict(sorted(aliased.items())),
                               'envelope_collisions_dropped': dict(sorted(collisions.items())),
                               'message_fields_parsed': dict(sorted(parsed_counts.items()))},
              'sanitizer': {'module': 'benchmark_sanitize', 'max_bytes': MAX_CONTENT_BYTES, 'passes': passes,
                            'fields': content_totals,
                            'truncated_values': sum(item['truncated'] for item in content_totals.values()),
                            'structured_identity_rewrites': structured_rewrites},
              'license': 'OTRF Security-Datasets: MIT License, Copyright (c) 2021 Open Threat Research Forge. '
                         'Retain the copyright and permission notice with copies or substantial portions.',
              'contamination': 'Public dataset; likely present in model training data. Development split only; never holdout.',
              'assumptions': {'naive_timestamps_declared_utc': naive_used,
                              'encoded_payloads': encoded_payloads,
                              'clock': clock,
                              'asset_facts': 'curation file' if curation is not None else
                                             'operator-declared draft OS family applied to every host; unverified'},
              'counts': {'original_lines': len(entries), 'imported_events': len(events),
                         'not_imported': {'blank_line': sum(1 for e in entries if e['status'] == 'blank_line')},
                         'imported_by_type': dict(sorted(imported_counts.items())),
                         'metadata_only_by_type': dict(sorted(metadata_counts.items())),
                         'metadata_only_dropped_fields': dict(sorted(metadata_dropped.items())),
                         'dropped_fields': dict(sorted(dropped_fields.items())),
                         'assets': len(assets), 'sources': len(sources), 'known_gaps': len(gaps),
                         'assessment_questions': len(questions)},
              'public_bytes': {'evidence.json': len(public_bytes), 'records.jsonl': len(records)},
              'evidence_manifest_sha256': manifest_sha, 'case_id': case_id}
    outputs = {'public/evidence.json': public_bytes, 'public/records.jsonl': records,
               'evaluator/locators.json': canonical_bytes(locators),
               'evaluator/pseudonyms.json': canonical_bytes({'schema_version': 1, 'mapping': names.mapping}),
               'evaluator/salt.json': canonical_bytes({'schema_version': 1, 'salt_hex': salt.hex()})}

    if curation is None:
        draft = {'schema_version': 1, 'status': DRAFT_MARKER, 'case_id': case_id,
                 'evidence_manifest_sha256': manifest_sha, 'truth_revision': 0, 'attack_release': None,
                 'steps': [], 'edges': [], 'controls': [],
                 'assessment_labels': {q['question_id']: None for q in questions}}
        _refuse_draft_check(draft, bundle)
        outputs['evaluator/truth.DRAFT.json'] = canonical_bytes(draft)
        outputs['evaluator/curation-template.json'] = canonical_bytes(
            _template(metadata, dataset_sha, metadata_sha, hosts, imported, by_event, window, draft_os_family))
        report['counts']['steps'] = 0
        outputs['evaluator/import-report.json'] = canonical_bytes(report)
        return case_id, outputs

    truth, scenario, curated = _curated(curation, metadata, bundle, events, by_line, by_record, hosts,
                                         asset_ids, outer, dataset_sha, member_name, coverage)
    report['curation'] = dict(curated, sha256=digest_bytes(curation_bytes))
    report['counts']['steps'] = len(truth['steps'])
    outputs['evaluator/truth.json'] = canonical_bytes(truth)
    outputs['evaluator/curation.json'] = curation_bytes
    outputs['scenario.json'] = canonical_bytes(scenario)
    outputs['evaluator/import-report.json'] = canonical_bytes(report)
    return case_id, outputs


def _leak_check(public, metadata, input_name, member_name, names, hosts):
    """Refuse public output that still names the dataset, its labels or raw identifiers."""
    folded = re.sub(r'(?<![a-z0-9])(?:asset|source|event|question|user|host|domain|sid|guid|ipv4|ipv6|addr|'
                    r'dns|segment|value)-[0-9a-f]{16}', ' ', public.decode('utf-8').casefold())
    needles = {metadata['id'].casefold(), input_name.rsplit('.', 1)[0].casefold(),
               member_name.rsplit('.', 1)[0].casefold()}
    needles.update(link.rsplit('/', 1)[-1].rsplit('.', 1)[0].casefold() for link in metadata['links'])
    if len(metadata['title']) >= 12:
        needles.add(metadata['title'].casefold())
    if any(needle and needle in folded for needle in needles):
        _fail('forbidden_public_metadata', 'public_bundle')
    originals = set(hosts) | {host.split('.', 1)[0] for host in hosts}
    for namespace in ('user', 'netbios', 'dns', 'ip', 'sid', 'guid', 'opaque'):
        originals.update(names.mapping.get(namespace, {}))
    if scan_leaks(folded, originals):
        _fail('pseudonymization_leak', 'public_bundle')


def _refuse_draft_check(draft, bundle):
    """Contract guard: a draft must never pass validate_truth (and so never score)."""
    try:
        validate_truth(draft, bundle)
    except BenchmarkError:
        return
    _fail('draft_not_refused', 'truth')


def refuse_draft(truth, public_bundle=None):
    """Gate for imported truth before scoring: drafts and contract-invalid truth are refused."""
    if type(truth) is not dict or truth.get('status') == DRAFT_MARKER:
        _fail('draft_truth_refused', 'truth')
    return validate_truth(truth, public_bundle)


def _template(metadata, dataset_sha, metadata_sha, hosts, imported, by_event, window, os_family):
    candidates = []
    for entry in sorted(imported, key=lambda e: (e['time'], e['line'])):
        event = by_event[entry['event_id_public']]
        candidates.append({'line': entry['line'], 'record_id': entry['record_id'], 'channel': entry['channel'],
                           'event_id': event['event_id'], 'hostname': entry['host'],
                           'timestamp_utc': event['timestamp_utc'], 'event_type': event['event_type'],
                           'fields': event['fields']})
    steps = [{'step_id': 'step-%d' % (index + 1), 'technique_id': item['technique_id'],
              'asset': {'hostname': hosts[0]}, 'window_utc': window,
              'execution_outcome': None, 'observability': None, 'support_sets': [],
              'boundary_id': 'boundary-host', 'phase': 'initial'}
             for index, item in enumerate(metadata['techniques'])]
    return {
        'NOT_VALID_FOR_SCORING': 'Curation template. Every null and empty list must be decided by a human '
                                 'curator from the original records. Nothing here is truth.',
        'instructions': [
            'Copy "curation" to a new file and fill it in; do not edit this template in place.',
            'Each support set lists original records that TOGETHER prove the step: {"line": N}, or when the export '
            'has record numbers {"record_id": "N", "channel": "...", "hostname": "..."} ({"record_id": "N"} alone '
            'only if that number is unique in the export).',
            'Optional "family_id" overrides the metadata-derived bootstrap family (otrf-<sorted technique tokens>) '
            'when the OTRF mapping is wrong.',
            'Candidate events are ALL imported events for each declared technique; no heuristic selection was applied.',
            'Questions without a step must be covered by a control (benign or insufficient).',
            'lookalike_event_ids holds groups of original-line locators for curator-validated benign lookalikes.',
            'Re-run the importer with --curation and the same --salt-file to keep event/asset IDs stable.'],
        'declared_techniques': [dict(item, candidate_events=candidates) for item in metadata['techniques']],
        'hosts': hosts,
        'curation': {
            'schema_version': 1, 'dataset_sha256': dataset_sha, 'metadata_sha256': metadata_sha,
            'curated_by': None, 'curated_utc': None, 'note': None, 'revision': 1, 'truth_revision': 1,
            'attack_release': None,
            'coverage': {axis: [] for axis in COVERAGE_AXES},
            'assets': [{'hostname': host, 'os_family': os_family, 'os_version': None,
                        'architecture': None, 'vendor': None} for host in hosts],
            'steps': steps, 'edges': [], 'controls': [], 'lookalike_event_ids': [],
            'sophistication': {'band': None, 'boundaries': [{'boundary_id': 'boundary-host', 'kind': 'host'}],
                               'preconditions': [], 'emulation_limitations': [], 'group_ids': [],
                               'source_references': []},
            'source_references': [],
            'assessment_windows': [window]}}


def _curated(curation, metadata, bundle, events, by_line, by_record, hosts, asset_ids, outer,
             dataset_sha, member_name, coverage):
    field = 'curation'
    steps_in = curation['steps']
    if type(steps_in) is not list:
        _fail('invalid_array', field + '.steps')
    steps, step_assets, sophistication_steps = [], {}, []
    for item in steps_in:
        _strict(item, {'step_id', 'technique_id', 'asset', 'window_utc', 'execution_outcome',
                       'observability', 'support_sets', 'boundary_id', 'phase'}, field + '.steps')
        host = _asset_selector(item['asset'], hosts, field + '.steps.asset')
        window = _window_tuple(item['window_utc'], field + '.steps.window_utc', outer)
        groups = _locator_groups(item['support_sets'], by_line, by_record, field + '.steps.support_sets')
        support = [sorted({e['event_id_public'] for e in group}) for group in groups]
        steps.append({'step_id': item['step_id'], 'technique_id': item['technique_id'],
                      'asset_id': asset_ids[host], 'window_utc': _normal_window(window),
                      'execution_outcome': item['execution_outcome'], 'observability': item['observability'],
                      'support_sets': support, 'source_receipt_sha256': _receipt(dataset_sha, member_name, groups)})
        step_assets[item['step_id']] = (asset_ids[host], window, item['observability'])
        sophistication_steps.append({'step_id': item['step_id'], 'asset_id': asset_ids[host],
                                     'boundary_id': item['boundary_id'], 'phase': item['phase']})
    if type(curation['controls']) is not list:
        _fail('invalid_array', field + '.controls')
    controls = []
    for item in curation['controls']:
        _strict(item, {'control_id', 'asset', 'window_utc', 'expected_disposition'}, field + '.controls')
        host = _asset_selector(item['asset'], hosts, field + '.controls.asset')
        window = _window_tuple(item['window_utc'], field + '.controls.window_utc', outer)
        controls.append({'control_id': item['control_id'], 'asset_id': asset_ids[host],
                         'window_utc': _normal_window(window), 'expected_disposition': item['expected_disposition']})
    lookalikes = _locator_groups(curation['lookalike_event_ids'], by_line, by_record, field + '.lookalike_event_ids')
    lookalike_ids = [sorted({e['event_id_public'] for e in group}) for group in lookalikes]
    disputed_ids = _excluded_event_ids(curation, _resolve, by_line, by_record, steps, lookalike_ids, field)

    # Labels follow from curated steps/controls only; every question must be decided (agent consensus: or disputed).
    labels, disputed_questions = {}, set()
    for question in bundle['assessment_questions']:
        q_window = (parse_utc(question['window_utc']['start_inclusive'], 'question'),
                    parse_utc(question['window_utc']['end_exclusive'], 'question'))
        hits = [obs for asset, window, obs in step_assets.values()
                if asset == question['asset_id'] and _overlaps(window, q_window)]
        covering = [c for c in controls if c['asset_id'] == question['asset_id'] and
                    _overlaps((parse_utc(c['window_utc']['start_inclusive'], 'control'),
                               parse_utc(c['window_utc']['end_exclusive'], 'control')), q_window)]
        if hits and covering:
            _fail('control_step_overlap', field + '.controls')
        if hits:
            labels[question['question_id']] = 1 if 'sufficient' in hits else None
        elif covering:
            dispositions = {c['expected_disposition'] for c in covering}
            if len(dispositions) != 1:
                _fail('conflicting_controls', field + '.controls')
            labels[question['question_id']] = 0 if dispositions == {'benign'} else None
        else:
            labels[question['question_id']] = _unlabeled(curation['attestation'], field + '.controls')
            disputed_questions.add(question['question_id'])
    truth = {'schema_version': 1, 'case_id': bundle['case_id'],
             'evidence_manifest_sha256': digest_bytes(canonical_bytes(bundle)),
             'truth_revision': curation['truth_revision'], 'attack_release': curation['attack_release'],
             'steps': steps, 'edges': curation['edges'], 'controls': controls, 'assessment_labels': labels,
             'lookalike_event_ids': lookalike_ids}
    curated = {}
    _attest_truth(truth, curation, disputed_ids, len(disputed_questions), curated)
    validate_truth(truth, bundle)

    try:
        from benchmark_difficulty import measure_case
    except ImportError:
        _fail('difficulty_unavailable', 'benchmark_difficulty')
    matched = {'matched_control': curation['matched_control']} if 'matched_control' in curation else None
    # matched_control is required (measure_case enforces it) exactly when no step is sufficiently observable.
    if matched is not None and any(step['observability'] == 'sufficient' for step in steps):
        _fail('unexpected_matched_control', field + '.matched_control')
    difficulty = measure_case(bundle, events, _undisputed(truth, disputed_questions), matched)

    soph = curation['sophistication']
    _strict(soph, {'band', 'boundaries', 'preconditions', 'emulation_limitations', 'group_ids',
                   'source_references'}, field + '.sophistication')
    techniques = sorted({item['technique_id'] for item in metadata['techniques']})
    references = curation['source_references']
    if type(references) is not list or not references or not all(type(r) is str for r in references):
        _fail('invalid_array', field + '.source_references')
    derived_family = _family_from_techniques(techniques)
    family = curation.get('family_id', derived_family)
    scenario = {
        'schema_version': 1, 'scenario_id': 'otrf-' + metadata['id'].casefold(),
        'family_id': family,
        'revision': curation['revision'], 'split': 'development', 'provenance': 'public_replay',
        'coverage': curation['coverage'], 'difficulty': difficulty,
        'sophistication': {'band': soph['band'], 'steps': sophistication_steps, 'edges': curation['edges'],
                           'preconditions': soph['preconditions'], 'boundaries': soph['boundaries'],
                           'emulation_limitations': _limitations(soph['emulation_limitations'],
                                                                 curation['attestation'],
                                                                 field + '.sophistication.emulation_limitations'),
                           'group_ids': soph['group_ids'], 'source_references': soph['source_references']},
        'attack_release': curation['attack_release'],
        'source_references': sorted(set(references) | set(metadata['links']) |
                                    {_attack_url(t) for t in techniques} |
                                    {_attack_url(s['technique_id']) for s in steps}),
        'evidence_manifest_sha256': truth['evidence_manifest_sha256']}
    validate_scenario(scenario, coverage if coverage is not None else load_json(DEFAULT_COVERAGE))
    undeclared = sorted({s['technique_id'] for s in steps} - set(techniques))
    curated.update({'curated_by': curation['curated_by'], 'curated_utc': curation['curated_utc'],
                    'note': curation['note'], 'attestation': curation['attestation'],
                    'undeclared_step_techniques': undeclared,
                    'family_id': {'value': family, 'metadata_derived': derived_family,
                                  'source': 'curation_override' if 'family_id' in curation else 'metadata'}})
    return truth, scenario, curated


# -------------------------------------------------------------------- output

def _inside(path, root):
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _in_source(path):
    return any(_inside(path, root) for root in SOURCE_ROOTS)


# Windows reports a file that Defender (or another engine) quarantined as EINVAL or ERROR_VIRUS_INFECTED (225) /
# ERROR_VIRUS_DELETED (226). Exclusions are the operator's decision; the importer never adds any.
AV_WINERRORS = (225, 226)


def _refuse_blocked(error, relative):
    if error.errno == errno.EINVAL or getattr(error, 'winerror', None) in AV_WINERRORS:
        _fail('blocked_by_antivirus', relative)


def write_outputs(output, case_id, outputs):
    """Create NEW output/<case_id>/... exclusively; never overwrite anything."""
    target = Path(os.path.abspath(os.fspath(output)))
    if _in_source(target.resolve()):
        _fail('output_in_source_tree', 'output')
    if os.path.lexists(target):
        _fail('output_exists', 'output')
    if not target.parent.is_dir():
        _fail('invalid_directory', 'output')
    target.mkdir()
    created = [target]
    try:
        case = target / case_id
        for relative in sorted(outputs):
            path = case.joinpath(*relative.split('/'))
            for parent in reversed(path.parents):
                if _inside(parent, case.parent) and not parent.exists():
                    parent.mkdir()
                    created.append(parent)
            try:
                handle = open(path, 'xb')
            except OSError as error:
                _refuse_blocked(error, relative)
                raise
            created.append(path)
            try:
                with handle:
                    handle.write(outputs[relative])
                    handle.flush()
                    os.fsync(handle.fileno())
            except OSError as error:
                _refuse_blocked(error, relative)
                raise
        # Read every file back: an antivirus engine that quarantines content makes the read fail, not the write.
        written = {}
        for relative in sorted(outputs):
            try:
                with open(case.joinpath(*relative.split('/')), 'rb') as handle:
                    written[relative] = handle.read()
            except OSError as error:
                _refuse_blocked(error, relative)
                _fail('file_unreadable', relative)
            if written[relative] != outputs[relative]:
                _fail('readback_mismatch', relative)
        bundle = decode_json(written['public/evidence.json'])
        validate_public_bundle(bundle, case / 'public')
        if 'evaluator/truth.json' in written:
            validate_truth(decode_json(written['evaluator/truth.json']), bundle)
    except BaseException:
        for path in reversed(created):
            try:
                path.rmdir() if path.is_dir() else path.unlink()
            except OSError:
                pass
        raise
    return target / case_id


def load_salt(path):
    _, data = _read_regular(path, 4096, 'salt')
    value = decode_json(data)
    if type(value) is not dict or set(value) != {'schema_version', 'salt_hex'} or value['schema_version'] != 1:
        _fail('invalid_salt', 'salt')
    if type(value['salt_hex']) is not str or not re.fullmatch(r'[0-9a-f]{%d}' % (SALT_BYTES * 2), value['salt_hex']):
        _fail('invalid_salt', 'salt')
    return bytes.fromhex(value['salt_hex'])


# ------------------------------------------------------------------ signing
# `sign` turns a reviewed curation PROPOSAL into a curation file. Running it is
# the human reviewer's attestation; it never imports, never runs automatically
# and never ticks a checklist. A recorded name is self-reported, not
# authenticated.

_HEADING = re.compile(r'(#{1,6})[ \t]+(.*?)[ \t#]*\Z')
_CHECKBOX = re.compile(r'[ \t]*[-*+][ \t]+\[(.)\]')


def review_checklist(text):
    """Return the item count of the one 'Reviewer checklist' section if every item is ticked."""
    lines = text.splitlines()
    starts = [(index, len(match.group(1))) for index, match in
              ((i, _HEADING.match(line)) for i, line in enumerate(lines))
              if match and match.group(2).casefold().startswith('reviewer checklist')]
    if len(starts) != 1:
        _fail('review_checklist_missing' if not starts else 'review_checklist_ambiguous', 'review')
    start, level = starts[0]
    items = []
    for line in lines[start + 1:]:
        heading = _HEADING.match(line)
        if heading and len(heading.group(1)) <= level:
            break
        box = _CHECKBOX.match(line)
        if box:
            items.append(box.group(1))
    if not items:
        _fail('review_checklist_missing', 'review')
    if any(mark not in ('x', 'X') for mark in items):
        _fail('review_checklist_incomplete', 'review')
    return len(items)


def sign_curation(proposal_path, review_path, by, note, output_path, validate=None):
    """Write a NEW signed curation from a fully ticked review; return its SHA-256.

    `validate(path)` defaults to this importer's `load_curation`. The review sheet
    must name the proposal's dataset digest so a sheet cannot sign another case.
    """
    from benchmark_adjudication import _identity, _model_identities
    validate = load_curation if validate is None else validate
    _text(by, 'sign.by')
    _text(note, 'sign.note')
    if _identity(by) in _model_identities({'experiment': {'teams': []}}):
        _fail('human_curation_required', 'sign.by')
    output = Path(os.path.abspath(os.fspath(output_path)))
    if os.path.lexists(output):
        _fail('output_exists', 'output')
    if _in_source(output.resolve()):
        _fail('output_in_source_tree', 'output')
    if not output.parent.is_dir():
        _fail('invalid_directory', 'output')
    _, review = _read_regular(review_path, MAX_SIDE_FILE_BYTES, 'review')
    try:
        review_text = review.decode('utf-8')
    except UnicodeDecodeError:
        _fail('invalid_text', 'review')
    review_checklist(review_text)
    _, data = _read_regular(proposal_path, MAX_SIDE_FILE_BYTES, 'proposal')
    curation = decode_json(data)
    if type(curation) is not dict:
        _fail('invalid_object', 'proposal')
    if type(curation.get('dataset_sha256')) is not str or curation['dataset_sha256'] not in review_text:
        _fail('review_mismatch', 'review')
    # Signing is the human's attestation of a proposal or a consensus. An empty exclusion list records no dispute;
    # a non-empty one is refused (excluded_without_consensus) until the reviewer resolves those disputes.
    curation.pop('status', None)
    curation.pop('attestation_hint', None)
    if curation.get('excluded_locators') == []:
        del curation['excluded_locators']
    curation.update(curated_by=by.strip(), note=note.strip(),
                    curated_utc=datetime.now(timezone.utc).isoformat(timespec='seconds'))
    content = (json.dumps(curation, indent=2, ensure_ascii=False, allow_nan=False) + '\n').encode('utf-8')
    try:
        with open(output, 'xb') as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
    except FileExistsError:
        _fail('output_exists', 'output')
    except OSError:
        _fail('file_unwritable', 'output')
    try:
        validate(output)
    except BaseException:
        output.unlink()
        raise
    return digest_bytes(content)


def sign_main(argv):
    parser = argparse.ArgumentParser(
        prog='benchmark_import_otrf.py sign',
        description='Human attestation: sign a reviewed curation proposal into a NEW curation file. Every line '
                    'under the review sheet\'s "Reviewer checklist" heading must be ticked ("- [x]") by the '
                    'reviewer. Removes `status`, sets curated_by/curated_utc/note and validates the result. '
                    'It never imports; run the curated import yourself afterwards.')
    parser.add_argument('--proposal', required=True, help='curation.PROPOSED.json')
    parser.add_argument('--review', required=True, help='review sheet with every checklist line ticked')
    parser.add_argument('--by', required=True, help='your name; running this command is your attestation')
    parser.add_argument('--note', required=True, help='validation note, including decided open questions')
    parser.add_argument('--output', required=True, help='NEW curation file outside the source tree')
    parser.add_argument('--format', choices=('otrf', 'attackdata'), default='otrf',
                        help='curation schema to validate against (default: otrf)')
    args = parser.parse_args(argv)
    try:
        validate = None
        if args.format == 'attackdata':
            from benchmark_import_attackdata import load_curation as validate
        sha = sign_curation(args.proposal, args.review, args.by, args.note, args.output, validate)
    except BenchmarkError as error:
        print('error: {}: {}'.format(error.code, error.field), file=sys.stderr)
        return 2
    sys.stdout.write(canonical_bytes({'output': str(Path(os.path.abspath(args.output))),
                                      'curation_sha256': sha, 'curated_by': args.by.strip()}).decode('utf-8') + '\n')
    return 0


def main(argv=None):
    argv = sys.argv[1:] if argv is None else list(argv)
    if argv[:1] == ['sign']:
        return sign_main(argv[1:])
    parser = argparse.ArgumentParser(description='Import an OTRF Security-Datasets Windows export as a '
                                                 'DEVELOPMENT benchmark case (public_replay). Separate '
                                                 'subcommand: `sign --proposal P --review R --by NAME --note TEXT '
                                                 '--output NEW` (human attestation of a reviewed curation).')
    parser.add_argument('--dataset', required=True, help='OTRF .zip or extracted .json export')
    parser.add_argument('--metadata', required=True, help='matching OTRF metadata .yaml')
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--curation', help='human-written curation JSON (truth source)')
    mode.add_argument('--draft-os-family', choices=COVERAGE_AXES['os'],
                      help='no curation: emit a draft (NOT VALID FOR SCORING) with this declared OS family')
    parser.add_argument('--output', required=True, help='NEW directory; must not exist')
    parser.add_argument('--salt-file', help='evaluator/salt.json from an earlier import (stable IDs)')
    parser.add_argument('--fields', default=str(DEFAULT_FIELDS), help='field allowlist JSON')
    parser.add_argument('--coverage', default=str(DEFAULT_COVERAGE), help='coverage catalog JSON')
    parser.add_argument('--naive-timestamps-utc', action='store_true',
                        help='flat shape only: declare zone-less TimeCreated values to be UTC (recorded as an '
                             'assumption); refused for NXLog exports, whose EventTime is placed via Sysmon UtcTime')
    parser.add_argument('--max-member-bytes', type=int, default=MAX_MEMBER_BYTES)
    parser.add_argument('--encoded-payloads', choices=ENCODED_PAYLOAD_MODES, default='preview',
                        help='PowerShell -EncodedCommand payloads: `preview` (default) publishes length, digest and '
                             'a sanitized 512-character decoded preview; `full` keeps the base64 payload, which '
                             'antivirus may quarantine (write the output to a directory excluded from scanning)')
    args = parser.parse_args(argv)
    try:
        salt = load_salt(args.salt_file) if args.salt_file else secrets.token_bytes(SALT_BYTES)
        field_map = load_field_map(args.fields)
        coverage = load_json(args.coverage) if args.curation else None
        case_id, outputs = build_case(args.dataset, args.metadata, field_map, salt,
                                      curation_path=args.curation, draft_os_family=args.draft_os_family,
                                      naive_utc=args.naive_timestamps_utc,
                                      max_member_bytes=args.max_member_bytes, coverage=coverage,
                                      encoded_payloads=args.encoded_payloads)
        case_dir = write_outputs(args.output, case_id, outputs)
    except BenchmarkError as error:
        print('error: {}: {}'.format(error.code, error.field), file=sys.stderr)
        return 2
    report = decode_json(outputs['evaluator/import-report.json'])
    summary = {'case_id': case_id, 'case_directory': str(case_dir), 'status': report['status'],
               'counts': report['counts'], 'public_bytes': report['public_bytes']}
    if report['status'] == DRAFT_MARKER:
        summary['warning'] = 'DRAFT: truth.DRAFT.json is NOT VALID FOR SCORING; curate before use.'
    _summarize_attestation(report, summary)
    sys.stdout.write(canonical_bytes(summary).decode('utf-8') + '\n')
    return 0


if __name__ == '__main__':
    sys.exit(main())

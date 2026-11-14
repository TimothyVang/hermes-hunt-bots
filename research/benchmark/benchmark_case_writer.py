"""Shared deterministic case builder and sanitizer for curated real-telemetry importers.

Produces contract-validated Wave 1 inline cases (`public/records.jsonl` +
`public/evidence.json`) and Wave 2 SQLite query-track cases
(`public/events.sqlite3` + `public/overview.json` + `public/evidence.json`),
with per-case HMAC-SHA256 pseudonymization, `benchmark_sanitize.sanitize_text`
content scrubbing, optional `ioc-feed-1` attachment, and strict validation
against `validate_public_bundle`, `validate_scenario`, and `validate_truth`.

Python 3.9+ standard library only.
"""
import datetime as dt
import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import stat

import benchmark_paths  # noqa: F401
from benchmark_attack import ATTACK_RELEASE, canonical_technique, technique_status
from benchmark_contracts import (
    ASSESSMENT_QUESTION, BenchmarkError, _ATTACK_TOKEN, _PUBLIC_FORBIDDEN,
    _key_form, canonical_bytes, digest_bytes, load_json, parse_utc,
    validate_coverage, validate_public_bundle, validate_scenario, validate_truth,
)
from benchmark_ioc import attach_ioc_feed
from benchmark_paths import SOURCE_ROOTS
from benchmark_query import build_query_store
from benchmark_sanitize import KnownIdentities, merge_reports, new_totals, sanitize_text, scan_leaks

HERE = Path(__file__).resolve().parent
DEFAULT_COVERAGE = HERE / 'benchmarks' / 'coverage.json'

_KIND_PREFIX = {
    'host': 'host',
    'user': 'user',
    'domain': 'domain',
    'dns': 'dns',
    'ip': 'addr',
    'ipv4': 'ipv4',
    'ipv6': 'ipv6',
    'sid': 'sid',
    'guid': 'guid',
    'account': 'account',
    'role': 'role',
    'resource': 'resource',
    'key': 'key',
    'principal': 'principal',
    'opaque': 'value',
}

_SYSTEM_USERS = frozenset({
    '', '-', 'system', 'local system', 'local service', 'network service',
    'nt authority', 'builtin', 'anonymous logon', 'root', 'daemon', 'bin',
    'sys', 'sync', 'nobody', 'nogroup', 'www-data', 'sshd', 'syslog',
    'messagebus', 'systemd-network', 'systemd-resolve', 'systemd-timesync',
    'polkitd', '_apt', 'cron', 'unset', '(null)', '?',
})

_GROUP_ID_RE = re.compile(r'(?<![A-Za-z0-9])G[0-9]{4}(?![0-9])')
_PROTECTED_TOKEN_RE = re.compile(r'\A[a-z][a-z0-9]*-[0-9a-f]{16}\Z')
_PROTECTED_TOKEN_SCAN_RE = re.compile(r'\b[a-z][a-z0-9]*-[0-9a-f]{16}\b')

MAX_SMALL_INPUT_BYTES = 128 * 1024 * 1024
MAX_ARCHIVE_MEMBER_BYTES = 512 * 1024 * 1024
MAX_LINE_BYTES = 2 * 1024 * 1024
MAX_COMPRESSION_RATIO = 250

FORBIDDEN_PUBLIC_DATASET_TOKENS = (
    'simuland', 'stratus-red-team', 'attackmate', 'cam-lds', 'camlds',
    'apt29_evals', 'malicious_events_class_1', 'win_mal:', 'lin_mal:',
    'seed_event', 'fullapt', '-labeled.csv',
)


def _fail(code, field='case_writer'):
    raise BenchmarkError(code, field) from None


def check_regular_input(path, field='input'):
    """Verify `path` is an existing regular file with no symlink or reparse alias."""
    p = Path(os.path.abspath(os.fspath(path)))
    try:
        info = p.lstat()
    except FileNotFoundError:
        _fail('file_not_found', field)
    except OSError:
        _fail('file_unreadable', field)
    if stat.S_ISLNK(info.st_mode) or (getattr(info, 'st_file_attributes', 0) & 0x400):
        _fail('path_alias', field)
    if not stat.S_ISREG(info.st_mode):
        _fail('not_regular_file', field)
    return p, info.st_size


def read_regular_bytes(path, max_bytes=MAX_SMALL_INPUT_BYTES, field='input'):
    """Read a bounded regular file and return `(sha256_hex, raw_bytes)`."""
    p, size = check_regular_input(path, field)
    if size > max_bytes:
        _fail('file_too_large', field)
    try:
        data = p.read_bytes()
    except OSError:
        _fail('file_unreadable', field)
    if len(data) > max_bytes:
        _fail('file_too_large', field)
    return hashlib.sha256(data).hexdigest(), data


def stream_file_sha256(path, field='input'):
    """Compute the full-file SHA-256 digest in 1 MiB chunks without loading into RAM."""
    p, _size = check_regular_input(path, field)
    digest = hashlib.sha256()
    try:
        with open(p, 'rb') as handle:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
    except OSError:
        _fail('file_unreadable', field)
    return digest.hexdigest()


def validate_archive_member_name(name, field='archive_member'):
    """Reject traversal, absolute, drive-prefixed, or NUL-containing archive paths."""
    if not isinstance(name, str) or not name or '\x00' in name:
        _fail('unsafe_archive_member', field)
    norm = name.replace('\\', '/')
    if norm.startswith('/') or ':' in norm.split('/', 1)[0]:
        _fail('unsafe_archive_member', field)
    parts = [pt for pt in norm.split('/') if pt not in ('', '.')]
    if any(pt == '..' for pt in parts):
        _fail('unsafe_archive_member', field)
    return norm


def read_bounded_zip_member(zf, member_name, max_bytes=MAX_ARCHIVE_MEMBER_BYTES, field='zip_member'):
    """Read a single ZipFile member safely, enforcing uncompressed size and ratio bounds."""
    validate_archive_member_name(member_name, field)
    try:
        zinfo = zf.getinfo(member_name)
    except KeyError:
        _fail('missing_archive_member', field)
    if zinfo.file_size > max_bytes:
        _fail('member_too_large', field)
    if zinfo.file_size > 1024 * 1024 and zinfo.compress_size > 0:
        if (zinfo.file_size // max(zinfo.compress_size, 1)) > MAX_COMPRESSION_RATIO:
            _fail('decompression_ratio_exceeded', field)
    chunks = []
    total = 0
    with zf.open(zinfo, 'r') as handle:
        while True:
            chunk = handle.read(65536)
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                _fail('member_too_large', field)
            chunks.append(chunk)
    return b''.join(chunks)


def iter_bounded_lines(byte_stream, max_bytes=MAX_ARCHIVE_MEMBER_BYTES, max_line_bytes=MAX_LINE_BYTES,
                       field='archive_stream'):
    """Stream lines from a compressed archive member while enforcing cumulative and per-line byte caps."""
    total = 0
    line_no = 0
    while True:
        raw_line = byte_stream.readline(max_line_bytes + 1)
        if not raw_line:
            break
        if len(raw_line) > max_line_bytes:
            _fail('line_too_large', field)
        total += len(raw_line)
        if total > max_bytes:
            _fail('member_too_large', field)
        line_no += 1
        yield line_no, raw_line


def derive_sophistication_band(step_specs, boundaries, *, control_case=False):
    """Compute canonical `S0`..`S5` sophistication band from `step_specs` and `boundaries`."""
    if control_case or not step_specs:
        return 'S0'
    if len(step_specs) == 1:
        return 'S1'
    bnd_map = {b['boundary_id']: b['kind'] for b in boundaries}
    d_assets = {s['asset_id'] for s in step_specs}
    c_bnds = {s['boundary_id'] for s in step_specs}
    kinds = {bnd_map[b] for b in c_bnds if b in bnd_map}
    has_persist = any(s.get('phase') in ('persistence', 'reentry') for s in step_specs)
    if ({'on-prem', 'cloud'}.issubset(kinds) or {'it', 'ot'}.issubset(kinds)) and has_persist:
        return 'S5'
    if (len(d_assets) >= 2 and len(c_bnds) >= 2
            and kinds.intersection({'identity', 'privilege'})
            and kinds.intersection({'segment', 'domain'}) and has_persist):
        return 'S4'
    if (len(d_assets) >= 2 and len(c_bnds) >= 2
            and kinds.intersection({'identity', 'privilege'})):
        return 'S3'
    return 'S2'


def ensure_outside_source(path, field='output'):
    resolved = Path(os.path.abspath(os.fspath(path))).resolve()
    for root in SOURCE_ROOTS:
        try:
            resolved.relative_to(root.resolve())
            _fail('output_inside_source_tree', field)
        except ValueError:
            continue
    return resolved


def format_utc(stamp):
    utc = stamp.astimezone(dt.timezone.utc)
    if utc.microsecond:
        return utc.strftime('%Y-%m-%dT%H:%M:%S.%fZ')
    return utc.strftime('%Y-%m-%dT%H:%M:%SZ')


def compute_difficulty_band(factors):
    total = sum(int(item['score']) for item in factors.values())
    return 'D' + str(min(total // 2 + 1, 5))


def canonical_valid_technique(tech_id):
    """Map an ATT&CK ID to its v20 canonical ID, returning None if unknown/deprecated."""
    raw = str(tech_id or '').strip().upper()
    if not re.fullmatch(r'T[0-9]{4}(?:\.[0-9]{3})?', raw):
        return None
    status = technique_status(raw, ATTACK_RELEASE)
    if status in ('unknown', 'deprecated'):
        parent = raw.split('.')[0]
        if parent != raw and technique_status(parent, ATTACK_RELEASE) in ('current', 'revoked'):
            return canonical_technique(parent, ATTACK_RELEASE)
        return None
    return canonical_technique(raw, ATTACK_RELEASE)


class CasePseudonymizer:
    """Consistent per-case HMAC-SHA256 pseudonymizer and content sanitizer."""

    def __init__(self, salt=None):
        if salt is None:
            self.salt = secrets.token_bytes(32)
        elif isinstance(salt, (bytes, bytearray)) and len(salt) >= 16:
            self.salt = bytes(salt)
        elif isinstance(salt, str) and len(salt) >= 16:
            self.salt = hashlib.sha256(salt.encode('utf-8')).digest()
        else:
            _fail('invalid_salt', 'salt')
        self._forward = {}
        self._reverse = {}
        self._by_kind = {}
        self._short_host_fqdn = {}
        self._known_dirty = True
        self._known = KnownIdentities({})
        self.sanitize_totals = new_totals()

    def _token(self, prefix, normalized):
        digest = hmac.new(
            self.salt,
            (prefix + ':' + normalized).encode('utf-8'),
            hashlib.sha256,
        ).hexdigest()[:16]
        return '{}-{}'.format(prefix, digest)

    def register_alias(self, kind, original):
        if original is not None and str(original).strip():
            self.pseudonymize(kind, str(original).strip())

    def pseudonymize(self, kind, value):
        if value is None:
            return ''
        raw = str(value).strip()
        if not raw or _PROTECTED_TOKEN_RE.fullmatch(raw):
            return raw
        folded = raw.casefold()
        if kind == 'user' and folded in _SYSTEM_USERS:
            return raw
        existing = self._forward.get((kind, folded))
        if existing is not None:
            return existing
        if kind in ('ip', 'ipv4', 'ipv6'):
            try:
                addr = ipaddress.ip_address(raw)
                if addr.is_loopback or addr.is_unspecified:
                    return raw
                prefix = 'ipv4' if addr.version == 4 else 'ipv6'
                norm = addr.compressed.casefold()
            except ValueError:
                prefix = _KIND_PREFIX.get(kind, 'value')
                norm = folded
        else:
            prefix = _KIND_PREFIX.get(kind, 'value')
            norm = folded
            if kind == 'host' and '.' in norm and not re.fullmatch(r'[0-9.]+', norm):
                short = norm.split('.', 1)[0]
                if len(short) >= 2 and self._short_host_fqdn.setdefault(short, norm) == norm:
                    token = self._forward.get(('host', short)) or self._token('host', short)
                    self._record('host', short, token)
                    self._record('host', raw, token, overwrite=True)
                    self._record('dns', raw, token, overwrite=True)
                    return token
                token = self._token('host', norm)
                self._record('host', raw, token, overwrite=True)
                self._record('dns', raw, token, overwrite=True)
                return token
            if kind == 'dns' and '.' in norm and not re.fullmatch(r'[0-9.]+', norm):
                exact_host = self._forward.get(('host', norm))
                if exact_host is not None:
                    self._record('dns', raw, exact_host, overwrite=True)
                    return exact_host
                short, rest = norm.split('.', 1)
                if len(short) >= 2 and ('domain', rest) in self._forward:
                    return self.pseudonymize('host', raw)
                host_token = self._forward.get(('host', short))
                if host_token is not None and len(short) >= 2 and self._short_host_fqdn.setdefault(short, norm) == norm:
                    self._record('host', raw, host_token, overwrite=True)
                    self._record('dns', raw, host_token, overwrite=True)
                    return host_token

        token = self._token(prefix, norm)
        self._record(kind, raw, token)
        return token

    def _record(self, kind, raw, token, *, overwrite=False):
        folded = raw.casefold()
        key = (kind, folded)
        if key not in self._forward or overwrite:
            old = self._forward.get(key)
            self._forward[key] = token
            if old is not None and old != token and old not in self._forward.values():
                self._reverse.pop(old, None)
            if token not in self._reverse or kind == 'host':
                self._reverse[token] = {'kind': kind, 'original': raw}
            self._by_kind.setdefault(kind, set()).add(raw)
            self._known_dirty = True

    def known_identities(self):
        if self._known_dirty:
            self._known = KnownIdentities(self._by_kind)
            self._known_dirty = False
        return self._known

    def clean_content(self, value, max_bytes=8192):
        if value is None:
            return ''
        text = str(value).replace('\x00', '')
        if not text:
            return ''
        cleaned, report = sanitize_text(
            text,
            self.pseudonymize,
            identities=self.known_identities(),
            max_bytes=max_bytes,
            encoded_payloads='preview',
        )
        cleaned = _GROUP_ID_RE.sub('G####', cleaned)
        cleaned = _ATTACK_TOKEN.sub('T####', cleaned)
        merge_reports(self.sanitize_totals, report)
        return cleaned

    def clean_fields(self, raw_fields):
        out = {}
        for k, v in raw_fields.items():
            key = str(k).strip()
            if not key or _key_form(key) in _PUBLIC_FORBIDDEN or _ATTACK_TOKEN.search(key):
                continue
            if v is None:
                continue
            if isinstance(v, (bool, int)):
                out[key] = v
            elif isinstance(v, float):
                out[key] = v
            elif isinstance(v, str):
                sval = self.clean_content(v)
                if sval != '':
                    out[key] = sval
            elif isinstance(v, (list, dict)):
                serialized = json.dumps(v, sort_keys=True, ensure_ascii=False)
                sval = self.clean_content(serialized)
                if sval != '':
                    out[key] = sval
        return out

    def export_pseudonyms(self):
        return {
            token: meta
            for token, meta in sorted(self._reverse.items())
        }

    def forbidden_originals(self):
        """Return registered sensitive original literals (`len >= 4`) that must not appear raw in `public/`."""
        originals = set()
        for kind, values in self._by_kind.items():
            if kind in ('ip', 'ipv4', 'ipv6'):
                continue
            for val in values:
                s = str(val).strip()
                if len(s) < 4 or s.casefold() in _SYSTEM_USERS:
                    continue
                # Avoid flagging generic English words like 'admin' or 'john' that legitimately appear in OS descriptions
                if s.casefold() in {'admin', 'user', 'test', 'guest', 'ubuntu', 'debian', 'windows', 'microsoft', 'service'}:
                    continue
                originals.add(s)
        return sorted(originals)


def _windows_overlap(w_a, w_b):
    a0 = parse_utc(w_a['start_inclusive'], 'window.start')
    a1 = parse_utc(w_a['end_exclusive'], 'window.end')
    b0 = parse_utc(w_b['start_inclusive'], 'window.start')
    b1 = parse_utc(w_b['end_exclusive'], 'window.end')
    return a0 < b1 and b0 < a1


def partition_window(outer_window, count):
    start = parse_utc(outer_window['start_inclusive'], 'outer.start')
    end = parse_utc(outer_window['end_exclusive'], 'outer.end')
    total_s = max(int((end - start).total_seconds()), 1)
    n = max(1, min(int(count), total_s))
    windows = []
    for idx in range(n):
        w0 = start + dt.timedelta(seconds=(total_s * idx) // n)
        w1 = end if idx == n - 1 else start + dt.timedelta(seconds=(total_s * (idx + 1)) // n)
        if w1 <= w0:
            w1 = w0 + dt.timedelta(seconds=1)
        windows.append({
            'start_inclusive': format_utc(w0),
            'end_exclusive': format_utc(w1),
        })
    return windows


def build_questions_and_labels(assets, unassessed_ids, windows, steps):
    unassessed = set(unassessed_ids or ())
    questions = []
    labels = {}
    q_idx = 1
    for asset in assets:
        aid = asset['asset_id']
        if aid in unassessed:
            continue
        for win in windows:
            qid = 'q{:03d}'.format(q_idx)
            q_idx += 1
            questions.append({
                'question_id': qid,
                'asset_id': aid,
                'window_utc': dict(win),
                'question': ASSESSMENT_QUESTION,
            })
            sufficient_hit = any(
                step['asset_id'] == aid
                and step.get('observability', 'sufficient') == 'sufficient'
                and _windows_overlap(step['window_utc'], win)
                for step in steps
            )
            ambiguous_hit = any(
                step['asset_id'] == aid
                and step.get('observability', 'sufficient') != 'sufficient'
                and _windows_overlap(step['window_utc'], win)
                for step in steps
            )
            labels[qid] = 1 if sufficient_hit else (None if ambiguous_hit else 0)
    return questions, labels


def build_benign_controls(assets, unassessed_ids, windows, steps):
    """Create benign control entries for every assessed `(asset, window)` without a truth step."""
    unassessed = set(unassessed_ids or ())
    controls = []
    c_idx = 1
    for asset in assets:
        aid = asset['asset_id']
        if aid in unassessed:
            continue
        for win in windows:
            has_step = any(
                step['asset_id'] == aid and _windows_overlap(step['window_utc'], win)
                for step in steps
            )
            if not has_step:
                controls.append({
                    'control_id': 'ctrl-{:03d}'.format(c_idx),
                    'asset_id': aid,
                    'window_utc': dict(win),
                    'expected_disposition': 'benign',
                })
                c_idx += 1
    return controls


def write_curated_case(
    output_root,
    *,
    case_seed,
    pseudonymizer,
    split,
    provenance,
    family_id,
    coverage_tags,
    difficulty_factors,
    control_case,
    sophistication,
    source_references,
    assets,
    sources,
    raw_events,
    step_specs,
    edges,
    known_gaps=(),
    unassessed_asset_ids=(),
    lookalike_tags=(),
    attestation='publisher_labels',
    num_windows=2,
    track='inline',
    ioc_regime=None,
    extra_iocs=(),
    import_notes=None,
    coverage_path=DEFAULT_COVERAGE,
):
    """Build, seal, and contract-validate one complete benchmark case directory.

    `raw_events`: iterable of dicts with keys:
      `tag` (caller-unique id), `timestamp_utc`, `source_id`, `asset_id`,
      `event_type`, `fields` (already sanitized, must include `timestamp_original`),
      `record_id` (original record locator string), and optional `file_sha256` (for query track).
    `step_specs`: list of dicts with keys:
      `step_id`, `technique_id`, `asset_id`, `window_utc` (optional; computed from
      matching events if omitted), `execution_outcome`, `observability`,
      `support_tags` (list of `tag`s, each becoming a minimal `[event_id]` support set,
      or list of tag-lists), `source_receipt_sha256` (optional), `phase`, `boundary_id`.
    """
    out_root = ensure_outside_source(output_root, 'output_root')
    coverage = validate_coverage(load_json(coverage_path))
    if not raw_events:
        _fail('empty_events', 'raw_events')

    case_hash = hmac.new(
        pseudonymizer.salt,
        ('case:' + str(case_seed)).encode('utf-8'),
        hashlib.sha256,
    ).hexdigest()[:12]
    case_id = 'case-' + case_hash
    case_dir = out_root / case_id
    if os.path.lexists(case_dir):
        _fail('already_exists', str(case_dir))

    # Sort events deterministically by (UTC timestamp, source_id, asset_id, original index)
    decorated = []
    for orig_idx, item in enumerate(raw_events):
        stamp = parse_utc(item['timestamp_utc'], 'raw_events.timestamp_utc')
        decorated.append((stamp, item['source_id'], item['asset_id'], orig_idx, item))
    decorated.sort(key=lambda t: (t[0], t[1], t[2], t[3]))

    min_stamp = decorated[0][0]
    max_stamp = decorated[-1][0]
    outer_start = min_stamp - dt.timedelta(seconds=5)
    outer_end = max_stamp + dt.timedelta(seconds=5)
    outer_window = {
        'start_inclusive': format_utc(outer_start),
        'end_exclusive': format_utc(outer_end),
    }

    # Ensure every source window fits inside outer_window and covers its events
    source_list = []
    for src in sources:
        s_copy = dict(src)
        s_copy.setdefault('window_utc', dict(outer_window))
        source_list.append(s_copy)

    public_dir = case_dir / 'public'
    eval_dir = case_dir / 'evaluator'
    public_dir.mkdir(parents=True, exist_ok=False)
    eval_dir.mkdir(parents=True, exist_ok=False)
    try:
        return _populate_curated_case(
            case_id=case_id,
            case_hash=case_hash,
            case_dir=case_dir,
            public_dir=public_dir,
            eval_dir=eval_dir,
            family_id=family_id,
            split=split,
            provenance=provenance,
            coverage=coverage,
            coverage_tags=coverage_tags,
            difficulty_factors=difficulty_factors,
            sophistication=sophistication,
            source_references=source_references,
            assets=assets,
            source_list=source_list,
            outer_start=outer_start,
            outer_end=outer_end,
            outer_window=outer_window,
            decorated=decorated,
            step_specs=step_specs,
            edges=edges,
            pseudonymizer=pseudonymizer,
            known_gaps=known_gaps,
            unassessed_asset_ids=unassessed_asset_ids,
            lookalike_tags=lookalike_tags,
            control_case=control_case,
            attestation=attestation,
            num_windows=num_windows,
            track=track,
            ioc_regime=ioc_regime,
            extra_iocs=extra_iocs,
            import_notes=import_notes,
            coverage_path=coverage_path,
        )
    except BaseException:
        shutil.rmtree(str(case_dir), ignore_errors=True)
        raise


def _populate_curated_case(
    *,
    case_id,
    case_hash,
    case_dir,
    public_dir,
    eval_dir,
    family_id,
    split,
    provenance,
    coverage,
    coverage_tags,
    difficulty_factors,
    sophistication,
    source_references,
    assets,
    source_list,
    outer_start,
    outer_end,
    outer_window,
    decorated,
    step_specs,
    edges,
    pseudonymizer,
    known_gaps,
    unassessed_asset_ids,
    lookalike_tags,
    control_case,
    attestation,
    num_windows,
    track,
    ioc_regime,
    extra_iocs,
    import_notes,
    coverage_path,
):

    tag_to_eid = {}
    eid_to_stamp = {}
    assigned_events = []

    if track == 'inline':
        # Build records.jsonl first so every event's locator.file_sha256 points to records.jsonl
        record_lines = []
        for seq_idx, (stamp, _sid, _aid, _oidx, item) in enumerate(decorated, 1):
            rec_obj = {
                'seq': seq_idx,
                'record_id': str(item['record_id']),
                'source_id': item['source_id'],
                'asset_id': item['asset_id'],
                'timestamp_utc': format_utc(stamp),
                'event_type': str(item['event_type']),
            }
            record_lines.append(canonical_bytes(rec_obj))
        records_bytes = b'\n'.join(record_lines) + b'\n'
        records_sha = digest_bytes(records_bytes)
        (public_dir / 'records.jsonl').write_bytes(records_bytes)
        files_manifest = [{
            'path': 'records.jsonl',
            'byte_count': len(records_bytes),
            'sha256': records_sha,
        }]
        for seq_idx, (stamp, _sid, _aid, _oidx, item) in enumerate(decorated, 1):
            eid = 'e{:06d}'.format(seq_idx)
            tag_to_eid[item['tag']] = eid
            eid_to_stamp[eid] = stamp
            fields = dict(item['fields'])
            fields.setdefault('timestamp_original', format_utc(stamp))
            assigned_events.append({
                'event_id': eid,
                'timestamp_utc': format_utc(stamp),
                'source_id': item['source_id'],
                'asset_id': item['asset_id'],
                'event_type': str(item['event_type']),
                'fields': fields,
                'locator': {
                    'file_sha256': records_sha,
                    'record_id': str(item['record_id']),
                },
            })
        query_manifest = None
        query_scan_events = ()
    elif track == 'query':
        # Wave 2 SQLite query-track: overview.json + events.sqlite3, inline events=[]
        by_asset = {}
        by_source = {}
        by_type = {}
        for seq_idx, (stamp, sid, aid, _oidx, item) in enumerate(decorated, 1):
            eid = 'e{:06d}'.format(seq_idx)
            tag_to_eid[item['tag']] = eid
            eid_to_stamp[eid] = stamp
            by_asset[aid] = by_asset.get(aid, 0) + 1
            by_source[sid] = by_source.get(sid, 0) + 1
            et = str(item['event_type'])
            by_type[et] = by_type.get(et, 0) + 1
            fields = dict(item['fields'])
            fields.setdefault('timestamp_original', format_utc(stamp))
            fsha = item.get('file_sha256') or hashlib.sha256(sid.encode('utf-8')).hexdigest()
            assigned_events.append({
                'event_id': eid,
                'timestamp_utc': format_utc(stamp),
                'source_id': sid,
                'asset_id': aid,
                'event_type': et,
                'fields': fields,
                'locator': {
                    'file_sha256': fsha,
                    'record_id': str(item['record_id']),
                },
            })
        overview_obj = {
            'schema_version': 1,
            'track': 'query_store',
            'total_events': len(assigned_events),
            'window_utc': dict(outer_window),
            'counts_by_asset': dict(sorted(by_asset.items())),
            'counts_by_source': dict(sorted(by_source.items())),
            'top_event_types': [
                {'event_type': k, 'count': v}
                for k, v in sorted(by_type.items(), key=lambda kv: (-kv[1], kv[0]))[:25]
            ],
            'hunting_guidance': (
                'All sanitized telemetry events reside in query_store (events.sqlite3). '
                'Invoke count_events, search_events, asset_timeline, pivot_indicator, '
                'lookup_ioc, and get_events to retrieve exact event_ids before citing.'
            ),
        }
        overview_bytes = canonical_bytes(overview_obj) + b'\n'
        (public_dir / 'overview.json').write_bytes(overview_bytes)
        files_manifest = [{
            'path': 'overview.json',
            'byte_count': len(overview_bytes),
            'sha256': digest_bytes(overview_bytes),
        }]
        query_manifest = build_query_store(
            public_dir / 'events.sqlite3',
            assigned_events,
            prefix='e',
            width=6,
        )
        query_scan_events = assigned_events
        assigned_events = []
    else:
        _fail('invalid_choice', 'track')

    # Resolve truth steps and support sets
    truth_steps = []
    scen_steps = []
    for spec in step_specs:
        tech = canonical_valid_technique(spec['technique_id'])
        if tech is None:
            _fail('unknown_technique', spec['technique_id'])
        support_sets = []
        seen_sets = set()
        step_stamps = []
        for entry in spec.get('support_tags', ()):
            if isinstance(entry, (list, tuple)):
                eids = [tag_to_eid[t] for t in entry] if (entry and all(t in tag_to_eid for t in entry)) else []
            else:
                eids = [tag_to_eid[entry]] if entry in tag_to_eid else []
            if not eids:
                continue
            key = frozenset(eids)
            if key not in seen_sets:
                seen_sets.add(key)
                support_sets.append(sorted(eids))
                for eid in eids:
                    step_stamps.append(eid_to_stamp[eid])
            if len(support_sets) >= 64:
                break
        observability = spec.get('observability', 'sufficient')
        if observability == 'sufficient' and not support_sets:
            _fail('empty_support_sets', spec['step_id'])
        if 'window_utc' in spec and spec['window_utc'] is not None:
            swin = dict(spec['window_utc'])
        else:
            if not step_stamps:
                _fail('missing_step_window', spec['step_id'])
            s0 = max(outer_start, min(step_stamps) - dt.timedelta(seconds=2))
            s1 = min(outer_end, max(step_stamps) + dt.timedelta(seconds=2))
            if s1 <= s0:
                s1 = s0 + dt.timedelta(seconds=1)
            swin = {
                'start_inclusive': format_utc(s0),
                'end_exclusive': format_utc(s1),
            }
        receipt_sha = spec.get('source_receipt_sha256') or hashlib.sha256(
            (case_id + ':' + spec['step_id']).encode('utf-8')
        ).hexdigest()
        truth_steps.append({
            'step_id': spec['step_id'],
            'technique_id': tech,
            'asset_id': spec['asset_id'],
            'window_utc': swin,
            'execution_outcome': spec.get('execution_outcome', 'succeeded'),
            'observability': observability,
            'support_sets': support_sets,
            'source_receipt_sha256': receipt_sha,
        })
        scen_steps.append({
            'step_id': spec['step_id'],
            'asset_id': spec['asset_id'],
            'boundary_id': spec['boundary_id'],
            'phase': spec.get('phase', 'initial'),
        })

    q_windows = partition_window(outer_window, num_windows)
    questions, labels = build_questions_and_labels(
        assets, unassessed_asset_ids, q_windows, truth_steps
    )
    controls = build_benign_controls(
        assets, unassessed_asset_ids, q_windows, truth_steps
    )

    evidence = {
        'schema_version': 1,
        'case_id': case_id,
        'window_utc': outer_window,
        'assets': list(assets),
        'sources': source_list,
        'events': assigned_events,
        'known_gaps': list(known_gaps),
        'files': files_manifest,
        'assessment_questions': questions,
    }
    if unassessed_asset_ids:
        evidence['unassessed_asset_ids'] = list(unassessed_asset_ids)
    if query_manifest is not None:
        evidence['query_store'] = query_manifest

    evidence_bytes = canonical_bytes(evidence)
    evidence_sha = digest_bytes(evidence_bytes)
    (public_dir / 'evidence.json').write_bytes(evidence_bytes + b'\n')

    diff_obj = {
        'band': compute_difficulty_band(difficulty_factors),
        'control': bool(control_case),
        'factors': difficulty_factors,
    }
    soph_obj = {
        'band': sophistication['band'],
        'steps': scen_steps,
        'edges': [list(edge) for edge in edges],
        'preconditions': list(sophistication.get('preconditions', [])),
        'boundaries': list(sophistication.get('boundaries', [])),
        'emulation_limitations': list(sophistication.get('emulation_limitations', [])),
        'group_ids': list(sophistication.get('group_ids', [])),
        'source_references': list(source_references),
    }
    scenario = {
        'schema_version': 1,
        'scenario_id': 'scen-' + case_hash,
        'family_id': family_id,
        'revision': 1,
        'split': split,
        'provenance': provenance,
        'coverage': coverage_tags,
        'difficulty': diff_obj,
        'sophistication': soph_obj,
        'attack_release': ATTACK_RELEASE,
        'source_references': list(source_references),
        'evidence_manifest_sha256': evidence_sha,
    }
    (case_dir / 'scenario.json').write_bytes(canonical_bytes(scenario) + b'\n')

    support_eids = {
        eid for st in truth_steps for grp in st['support_sets'] for eid in grp
    }
    lookalike_groups = []
    seen_lk = set()
    for grp in lookalike_tags:
        tags = grp if isinstance(grp, (list, tuple)) else [grp]
        eids = [tag_to_eid[t] for t in tags if t in tag_to_eid and tag_to_eid[t] not in support_eids]
        if eids:
            key = frozenset(eids)
            if key not in seen_lk:
                seen_lk.add(key)
                lookalike_groups.append(sorted(eids))

    truth = {
        'schema_version': 1,
        'case_id': case_id,
        'evidence_manifest_sha256': evidence_sha,
        'truth_revision': 1,
        'attack_release': ATTACK_RELEASE,
        'attestation': attestation,
        'steps': truth_steps,
        'edges': [list(edge) for edge in edges],
        'controls': controls,
        'assessment_labels': labels,
    }
    if lookalike_groups:
        truth['lookalike_event_ids'] = lookalike_groups
    (eval_dir / 'truth.json').write_bytes(canonical_bytes(truth) + b'\n')

    (eval_dir / 'salt.json').write_bytes(
        canonical_bytes({'salt_hex': pseudonymizer.salt.hex()}) + b'\n'
    )
    (eval_dir / 'pseudonyms.json').write_bytes(
        canonical_bytes(pseudonymizer.export_pseudonyms()) + b'\n'
    )

    ioc_report = None
    if ioc_regime is not None:
        ioc_report = attach_ioc_feed(
            case_dir,
            regime=ioc_regime,
            extra_iocs=extra_iocs,
            coverage_path=coverage_path,
        )
        evidence = load_json(public_dir / 'evidence.json')
        scenario = load_json(case_dir / 'scenario.json')
        truth = load_json(eval_dir / 'truth.json')

    validate_public_bundle(evidence, root=public_dir)
    validate_scenario(scenario, coverage)
    validate_truth(truth, evidence)

    # Public leak & forbidden dataset-token check across public artifacts
    public_blobs = [canonical_bytes(evidence).decode('utf-8')]
    if query_scan_events:
        public_blobs.append(canonical_bytes(query_scan_events).decode('utf-8'))
    for rel_name in ('records.jsonl', 'overview.json', 'intel.jsonl'):
        cand = public_dir / rel_name
        if cand.is_file():
            public_blobs.append(cand.read_text(encoding='utf-8'))
    combined_public = '\n'.join(public_blobs).casefold()
    for bad_tok in FORBIDDEN_PUBLIC_DATASET_TOKENS:
        if bad_tok in combined_public:
            _fail('forbidden_public_metadata', 'public_bundle')
    masked_public = _PROTECTED_TOKEN_SCAN_RE.sub(' ', combined_public)
    leaked = scan_leaks(masked_public, pseudonymizer.forbidden_originals())
    if leaked:
        _fail('pseudonymization_leak', 'public_bundle')

    report = {
        'case_id': case_id,
        'case_dir': str(case_dir),
        'split': split,
        'track': track,
        'sophistication_band': scenario['sophistication']['band'],
        'difficulty_band': scenario['difficulty']['band'],
        'attestation': attestation,
        'inline_events': len(evidence['events']),
        'query_store_events': (evidence.get('query_store') or {}).get('event_count', 0),
        'steps': len(truth['steps']),
        'controls': len(truth['controls']),
        'questions': len(evidence['assessment_questions']),
        'sanitize_totals': pseudonymizer.sanitize_totals,
        'ioc_feed': ioc_report,
        'notes': import_notes or {},
    }
    (eval_dir / 'import-report.json').write_bytes(canonical_bytes(report) + b'\n')
    return report

"""Strict, secret-safe, standard-library contracts for offline benchmarks.

Validation never executes models, opens truth implicitly, or creates directories.
Public manifests are canonical JSON snapshots, not proofs of sanitization: release
still requires the separate human declassification gate.
"""
import hashlib
import ipaddress
import json
import math
import os
import re
import stat
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

from benchmark_paths import SOURCE_TREE


SCHEMA_VERSION = 1
MAX_BYTES = 1024 * 1024
ASSESSMENT_QUESTION = ('Does the supplied evidence support suspicious activity '
                       'on this asset in this window?')
ROLE_IDS = ('framework-coordinator', 'framework-researcher',
            'framework-network-analyst', 'framework-librarian',
            'framework-builder', 'framework-reviewer')
STAGE_KEYS = ('scope', 'endpoint_evidence', 'network_evidence', 'hypotheses',
              'analysis', 'review', 'handoff')
# `human_attested` (the default when absent), an unreviewed importer proposal, or
# a mechanical consensus of two independent agent drafts; a cohort control that
# every score carries, never upgraded to attested. Allowed for every split.
TRUTH_ATTESTATIONS = ('human_attested', 'unreviewed_proposal', 'agent_consensus')
# Runs are fully automatic: every validated stage output advances without a
# human gate, recorded under this distinct actor/note, never as an approval.
AUTO_ADVANCE_ACTOR = 'benchmark-auto-advance'
AUTO_ADVANCE_NOTE = 'unreviewed automatic advance'
REVIEW_POLICY = 'auto_advance'
# Truth is frozen by automation inside `init`, before any trial or dispatch. This
# records when it was frozen, never that a human attested it: attestation is the
# truth file's own `attestation` field.
AUTO_FREEZE_ACTOR = 'benchmark-auto-freeze'
AUTO_FREEZE_NOTE = 'Automatic truth freeze at init, before any trial or dispatch.'
FREEZE_POLICY = 'automatic_at_init'
DEFAULT_CONCURRENT_CALLS = 4
MAX_CONCURRENT_CALLS = 16
COVERAGE_AXES = {
    'os': ('windows-client', 'windows-server', 'linux', 'macos', 'bsd-unix',
           'android', 'ios', 'embedded-rtos', 'network-os', 'mainframe',
           'not-applicable'),
    'execution_platform': ('physical', 'virtual-machine', 'hypervisor',
                           'container', 'kubernetes', 'serverless',
                           'cloud-control-plane', 'saas', 'mobile', 'embedded'),
    'network': ('flat-lan', 'segmented-vlan', 'routed-wan', 'dmz',
                'vpn-remote-access', 'zero-trust', 'wireless', 'cloud-vpc',
                'hybrid', 'multicloud', 'container-overlay', 'ot-fieldbus',
                'iot-edge', 'isolated-airgap', 'ipv4', 'ipv6', 'dual-stack',
                'encrypted-traffic', 'proxy-nat', 'sdwan', 'cellular'),
    'identity_domain': ('workgroup-local', 'ad-single-domain', 'ad-multidomain',
                        'ad-cross-forest', 'entra-hybrid', 'ldap-kerberos',
                        'cloud-iam', 'federated-sso', 'machine-service-identity',
                        'multi-tenant'),
    'operational_domain': ('enterprise-it', 'cloud-saas', 'ot-ics', 'iot',
                           'telecom', 'healthcare', 'finance',
                           'government-defense', 'education', 'retail',
                           'energy-utilities', 'transport', 'manufacturing'),
    'dns_domain': ('internal-authoritative', 'split-horizon',
                   'delegated-subdomain', 'recursive-forwarder',
                   'owned-public-zone', 'encrypted-dns', 'cross-domain-trust',
                   'no-dns'),
    'telemetry': ('windows-security', 'sysmon', 'linux-audit', 'journald',
                  'macos-unified', 'identity-audit', 'dns', 'flow', 'zeek',
                  'suricata', 'firewall-proxy', 'cloud-audit',
                  'kubernetes-audit', 'saas-audit', 'mobile-device',
                  'ot-protocol'),
}
_ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9_-]{0,127}\Z')
_DIGEST = re.compile(r'[0-9a-f]{64}\Z')
_TECHNIQUE = re.compile(r'T[0-9]{4}(?:\.[0-9]{3})?\Z')
_TIMESTAMP = re.compile(r'([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})'
                        r'(?:\.([0-9]{1,9}))?(Z|[+-][0-9]{2}:[0-9]{2})\Z')
# ATT&CK-looking tokens; compact ISO timestamps (digit before T) do not match.
_ATTACK_TOKEN = re.compile(r'(?<![A-Za-z0-9])T[0-9]{4}(?:\.[0-9]{3})?(?![0-9])')
_CASE_ID = re.compile(r'case-[0-9a-f]{4,32}\Z')
_CREDENTIAL_ENV = re.compile(r'BENCH_MODEL_[A-Z0-9_]+\Z')


def _key_form(key):
    """Normalize a key for forbidden-name checks: casefold, then drop - and _."""
    return key.casefold().replace('-', '').replace('_', '')


_PUBLIC_FORBIDDEN = frozenset(_key_form(key) for key in (
    'truth', 'truth_path', 'truth_revision', 'assessment_labels',
    'support_sets', 'source_receipt_sha256', 'execution_outcome',
    'observability', 'evidence_manifest_sha256', 'recipe_id', 'recipe_name',
    'difficulty', 'sophistication', 'answer_key', 'answer_key_path',
    'group_ids', 'campaign_receipts', 'scorer_output', 'technique_id',
    'technique_ids', 'lookalike_event_ids', 'disputed_event_ids',
))
DETECTOR_ATTACK_KEY = 'detector_attack_ids'


class BenchmarkError(ValueError):
    """Safe validation failure: code and field are fixed schema identifiers."""

    def __init__(self, code, field):
        self.code = code
        self.field = field
        super().__init__('{}: {}'.format(code, field))


def _fail(code, field):
    raise BenchmarkError(code, field)


def _fields(value, required, field, optional=()):
    if type(value) is not dict:
        _fail('invalid_object', field)
    if not set(required).issubset(value):
        _fail('missing_field', field)
    if set(value) - set(required) - set(optional):
        _fail('unknown_field', field)


def _text(value, field, nullable=False):
    if nullable and value is None:
        return
    if type(value) is not str or not value.strip() or '\x00' in value:
        _fail('invalid_text', field)
    try:
        value.encode('utf-8')
    except UnicodeError:
        _fail('invalid_text', field)


def _id(value, field):
    if type(value) is not str or not _ID.fullmatch(value):
        _fail('invalid_identifier', field)


def _digest(value, field):
    if type(value) is not str or not _DIGEST.fullmatch(value):
        _fail('invalid_digest', field)


def _integer(value, field, minimum=0, maximum=None):
    if type(value) is not int or value < minimum or (maximum is not None and value > maximum):
        _fail('invalid_integer', field)


def _number(value, field, minimum=None, maximum=None, nullable=False):
    if nullable and value is None:
        return
    if type(value) not in (int, float):
        _fail('invalid_number', field)
    try:
        finite = math.isfinite(value)
    except OverflowError:
        finite = False
    if not finite or (minimum is not None and value < minimum) or (maximum is not None and value > maximum):
        _fail('invalid_number', field)


def _positive(value, field):
    _number(value, field, minimum=0)
    if value == 0:
        _fail('invalid_number', field)


def _enum(value, choices, field):
    if type(value) is not str or value not in choices:
        _fail('invalid_choice', field)


def _array(value, field, nonempty=False):
    if type(value) is not list or (nonempty and not value):
        _fail('invalid_array', field)


def _strings(value, field, validator=_text, nonempty=False):
    _array(value, field, nonempty)
    seen = set()
    for item in value:
        validator(item, field)
        if item in seen:
            _fail('duplicate_item', field)
        seen.add(item)
    return seen


def _version(value, field):
    if type(value) is not int or value != SCHEMA_VERSION:
        _fail('unsupported_schema', field)


def parse_utc(value, field):
    """Strict 3.9-safe UTC parser: 1-9 fractional digits, truncated to microseconds."""
    match = _TIMESTAMP.fullmatch(value) if type(value) is str else None
    if match is None:
        _fail('invalid_timestamp', field)
    year, month, day, hour, minute, second, fraction, zone = match.groups()
    micro = int((fraction or '0').ljust(6, '0')[:6])
    if zone == 'Z':
        offset = timedelta(0)
    else:
        hours, minutes = int(zone[1:3]), int(zone[4:6])
        if hours > 23 or minutes > 59:
            _fail('invalid_timestamp', field)
        offset = timedelta(hours=hours, minutes=minutes) * (-1 if zone[0] == '-' else 1)
    try:
        return datetime(int(year), int(month), int(day), int(hour), int(minute), int(second),
                        micro, timezone(offset)).astimezone(timezone.utc)
    except (ValueError, OverflowError):
        _fail('invalid_timestamp', field)


def _window(value, field, outer=None):
    _fields(value, {'start_inclusive', 'end_exclusive'}, field)
    start = parse_utc(value['start_inclusive'], field + '.start_inclusive')
    end = parse_utc(value['end_exclusive'], field + '.end_exclusive')
    if start >= end or (outer is not None and (start < outer[0] or end > outer[1])):
        _fail('invalid_window', field)
    return start, end


def _unique_objects(values, key, field, nonempty=False):
    _array(values, field, nonempty)
    result = {}
    for item in values:
        if type(item) is not dict or key not in item:
            _fail('invalid_object', field)
        _id(item[key], field + '.' + key)
        if item[key] in result:
            _fail('duplicate_identifier', field + '.' + key)
        result[item[key]] = item
    return result


def _reference(value, existing, field, nullable=False):
    if nullable and value is None:
        return
    _id(value, field)
    if value not in existing:
        _fail('unknown_reference', field)


def _json_value(value, field, public=False):
    """Validate JSON data; public data also refuses evaluator keys and ATT&CK tokens."""
    if value is None or type(value) is bool or type(value) is int:
        return
    if type(value) is float:
        _number(value, field)
    elif type(value) is str:
        try:
            value.encode('utf-8')
        except UnicodeError:
            _fail('invalid_text', field)
        if public and _ATTACK_TOKEN.search(value):
            _fail('truth_public_overlap', field)
    elif type(value) is list:
        for item in value:
            _json_value(item, field, public)
    elif type(value) is dict:
        for key, item in value.items():
            if type(key) is not str:
                _fail('invalid_object', field)
            _text(key, field)
            if public and (_key_form(key) in _PUBLIC_FORBIDDEN or _ATTACK_TOKEN.search(key)):
                _fail('truth_public_overlap', field)
            _json_value(item, field, public)
    else:
        _fail('invalid_json', field)


def _public_fields(fields, field):
    """Event fields: only top-level `detector_attack_ids` may carry ATT&CK IDs."""
    for key, item in fields.items():
        if key == DETECTOR_ATTACK_KEY:
            _strings(item, field + '.' + DETECTOR_ATTACK_KEY, _technique)
            continue
        _json_value({key: item}, field, public=True)


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _fail('duplicate_key', 'json')
        result[key] = value
    return result


def _constant(value):
    _fail('nonfinite_number', 'json')


def decode_json(value):
    """Decode UTF-8 JSON, rejecting duplicate keys and every nonfinite number."""
    if type(value) not in (bytes, str):
        _fail('invalid_json', 'json')
    try:
        text = value.decode('utf-8') if type(value) is bytes else value
        result = json.loads(text, object_pairs_hook=_pairs, parse_constant=_constant)
        _json_value(result, 'json')
        return result
    except BenchmarkError:
        raise
    except (ValueError, UnicodeError, RecursionError, OverflowError):
        _fail('invalid_json', 'json')


def canonical_bytes(value):
    """Canonical project encoding: sorted keys, compact UTF-8, no ASCII escaping."""
    try:
        _json_value(value, 'json')
        return json.dumps(value, sort_keys=True, ensure_ascii=False,
                          separators=(',', ':'), allow_nan=False).encode('utf-8')
    except BenchmarkError:
        raise
    except (ValueError, TypeError, UnicodeError, RecursionError, OverflowError):
        _fail('invalid_json', 'json')


def digest_bytes(value):
    if type(value) is not bytes:
        _fail('invalid_bytes', 'digest')
    return hashlib.sha256(value).hexdigest()


def campaign_manifest_digest(manifest):
    """Hash the signed payload, excluding only its self-referential digest field."""
    if type(manifest) is not dict or type(manifest.get('authorization')) is not dict:
        _fail('invalid_object', 'campaign.authorization')
    payload = dict(manifest)
    payload['authorization'] = {key: value for key, value in manifest['authorization'].items()
                                if key != 'manifest_sha256'}
    return digest_bytes(canonical_bytes(payload))


def load_json(path):
    try:
        value = decode_json(Path(path).read_bytes())
    except BenchmarkError:
        raise
    except (OSError, ValueError, TypeError):
        _fail('file_unreadable', 'json')
    if type(value) is not dict:
        _fail('invalid_object', 'json')
    return value


def _relative(value, field):
    _text(value, field)
    if '\\' in value or ':' in value or value.startswith('/'):
        _fail('unsafe_path', field)
    for part in value.split('/'):
        if part in ('', '.', '..') or part[-1:] in (' ', '.') or any(ord(c) < 32 or c in '<>"|?*' for c in part):
            _fail('unsafe_path', field)
        if re.search(r'~[0-9]', part):
            # Windows 8.3 short-name form; never a portable name.
            _fail('path_alias', field)
        stem = part.split('.')[0].upper()
        if stem in {'CON', 'PRN', 'AUX', 'NUL', 'CONIN$', 'CONOUT$'} or re.fullmatch(r'(?:COM|LPT)[0-9¹²³]', stem):
            _fail('unsafe_path', field)


def _no_alias(path, field):
    """lstat every existing component, including root ancestors on Windows."""
    for component in reversed((path,) + tuple(path.parents)):
        try:
            info = component.lstat()
        except FileNotFoundError:
            continue
        except (OSError, ValueError):
            _fail('unsafe_path', field)
        if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
            _fail('path_alias', field)
        if not stat.S_ISDIR(info.st_mode) and component != path:
            _fail('unsafe_path', field)


def confined_file(root, relative, field='path'):
    """Resolve an existing regular file without accepting any alias component.

    The resolved relative parts must equal the requested parts exactly, which
    rejects Windows 8.3 short names and case-insensitive name aliases.
    """
    _relative(relative, field)
    try:
        base = Path(os.path.abspath(os.fspath(root)))
        _no_alias(base, field)
        if not base.is_dir():
            _fail('invalid_directory', field)
        candidate = base.joinpath(*relative.split('/'))
        _no_alias(candidate, field)
        try:
            info = candidate.stat()
        except FileNotFoundError:
            _fail('file_not_found', field)
        if not stat.S_ISREG(info.st_mode):
            _fail('not_regular_file', field)
        if info.st_nlink > 1:
            _fail('path_alias', field)
        if candidate.resolve().relative_to(base.resolve()).parts != tuple(relative.split('/')):
            _fail('path_alias', field)
        return candidate
    except BenchmarkError:
        raise
    except (OSError, ValueError, TypeError):
        _fail('unsafe_path', field)


def _inside(path, root):
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def validate_state_root(path):
    """Validate without creating state or opening a preexisting user ledger."""
    try:
        candidate = Path(path)
        if not candidate.is_absolute() or '..' in candidate.parts:
            _fail('unsafe_state_root', 'state_root')
        for part in candidate.parts[1:]:
            _relative(part, 'state_root')
        _no_alias(candidate, 'state_root')
        candidate = candidate.resolve()
        source = SOURCE_TREE
        if _inside(candidate, source) or _inside(source, candidate):
            _fail('unsafe_state_root', 'state_root')
        home = Path.home().resolve()
        if candidate == home:
            _fail('unsafe_state_root', 'state_root')
        protected = {'downloads', '.config', '.ssh', '.aws', '.hermes',
                     '.cache', '.local', 'profiles', 'profile',
                     'browser-profiles', 'google', 'mozilla'}
        if any(part.casefold() in protected for part in candidate.parts):
            _fail('unsafe_state_root', 'state_root')
        # Windows' system temporary directory is under AppData, but is not a
        # profile. Permit disposable state there without permitting other
        # application/profile directories (including browser user data).
        temporary = Path(tempfile.gettempdir()).resolve()
        if any(part.casefold() == 'appdata' for part in candidate.parts) and not _inside(candidate, temporary):
            _fail('unsafe_state_root', 'state_root')
        for ancestor in (candidate,) + tuple(candidate.parents):
            if (ancestor / '.git').exists() or (ancestor / '.git').is_symlink():
                _fail('state_root_in_worktree', 'state_root')
        if candidate.exists():
            if not candidate.is_dir():
                _fail('invalid_directory', 'state_root')
            # Inspect bounded metadata only; never enter a private subtree. The
            # root was checked above and only non-alias directories are entered,
            # so each entry's own metadata covers its whole path.
            pending, inspected = [candidate], 0
            while pending:
                directory = pending.pop()
                with os.scandir(directory) as entries:
                    for entry in entries:
                        inspected += 1
                        if inspected > 10000:
                            _fail('state_root_scan_limit', 'state_root')
                        if entry.name.casefold() == '.git':
                            _fail('state_root_in_worktree', 'state_root')
                        if entry.name.casefold() in protected | {'appdata'}:
                            _fail('unsafe_state_root', 'state_root')
                        info = entry.stat(follow_symlinks=False)
                        if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
                            _fail('path_alias', 'state_root')
                        if stat.S_ISDIR(info.st_mode):
                            pending.append(entry.path)
        return candidate
    except BenchmarkError:
        raise
    except (OSError, ValueError, TypeError, RuntimeError):
        _fail('unsafe_state_root', 'state_root')


def _coverage_tags(value, axes, field):
    _fields(value, set(COVERAGE_AXES), field)
    for axis in COVERAGE_AXES:
        _strings(value[axis], field + '.' + axis, nonempty=True)
        if not set(value[axis]).issubset(axes[axis]):
            _fail('unknown_category', field + '.' + axis)


def validate_coverage(value):
    _fields(value, {'schema_version', 'catalog_version', 'axes', 'rows'}, 'coverage')
    _version(value['schema_version'], 'coverage.schema_version')
    _id(value['catalog_version'], 'coverage.catalog_version')
    _fields(value['axes'], set(COVERAGE_AXES), 'coverage.axes')
    for axis, categories in COVERAGE_AXES.items():
        _strings(value['axes'][axis], 'coverage.axes.' + axis, nonempty=True)
        if set(value['axes'][axis]) != set(categories):
            _fail('unknown_category', 'coverage.axes.' + axis)
    rows = _unique_objects(value['rows'], 'row_id', 'coverage.rows', True)
    covered = {axis: set() for axis in COVERAGE_AXES}
    for row in rows.values():
        _fields(row, {'row_id', 'coverage', 'owner', 'prerequisites', 'status', 'reason', 'evidence_references'}, 'coverage.rows')
        _coverage_tags(row['coverage'], value['axes'], 'coverage.rows.coverage')
        for key in ('owner', 'reason'):
            _text(row[key], 'coverage.rows.' + key)
        _strings(row['prerequisites'], 'coverage.rows.prerequisites', nonempty=True)
        _enum(row['status'], ('planned', 'blocked', 'synthetic_verified', 'replay_verified', 'live_verified', 'not_applicable'), 'coverage.rows.status')
        _strings(row['evidence_references'], 'coverage.rows.evidence_references', _relative, row['status'].endswith('_verified'))
        for axis in COVERAGE_AXES:
            covered[axis].update(row['coverage'][axis])
    if any(covered[axis] != set(value['axes'][axis]) for axis in COVERAGE_AXES):
        _fail('incomplete_coverage', 'coverage.rows')
    return value


def _https(value, field):
    _text(value, field)
    try:
        url = urlsplit(value)
        if url.scheme != 'https' or not url.hostname or url.username is not None or url.password is not None:
            _fail('invalid_url', field)
        url.port
    except ValueError:
        _fail('invalid_url', field)


def _attack_release(value, field):
    if type(value) is not str or not re.fullmatch(r'v?[0-9]+(?:\.[0-9]+){0,2}', value):
        _fail('invalid_attack_release', field)


def _edges(values, ids, field, acyclic=True):
    _array(values, field)
    seen = set()
    successors = {item: [] for item in ids}
    indegree = {item: 0 for item in ids}
    for edge in values:
        if type(edge) is not list or len(edge) != 2:
            _fail('invalid_edge', field)
        for item in edge:
            _reference(item, ids, field)
        pair = tuple(edge)
        if pair[0] == pair[1] or pair in seen:
            _fail('invalid_edge', field)
        seen.add(pair)
        successors[pair[0]].append(pair[1])
        indegree[pair[1]] += 1
    if acyclic:
        ready = [item for item in ids if indegree[item] == 0]
        count = 0
        while ready:
            item = ready.pop()
            count += 1
            for target in successors[item]:
                indegree[target] -= 1
                if indegree[target] == 0:
                    ready.append(target)
        if count != len(ids):
            _fail('cyclic_edges', field)


def _difficulty(value):
    field = 'scenario.difficulty'
    _fields(value, {'band', 'control', 'factors'}, field)
    _enum(value['band'], ('D1', 'D2', 'D3', 'D4', 'D5'), field + '.band')
    if type(value['control']) is not bool:
        _fail('invalid_boolean', field + '.control')
    factors = ('noise', 'joins', 'time_span', 'gaps', 'ambiguity')
    _fields(value['factors'], set(factors), field + '.factors')
    total = 0
    for factor in factors:
        item = value['factors'][factor]
        _fields(item, {'score', 'rationale'}, field + '.factors.' + factor)
        _integer(item['score'], field + '.factors.' + factor + '.score', 0, 2)
        _text(item['rationale'], field + '.factors.' + factor + '.rationale')
        total += item['score']
    if value['band'] != 'D' + str(min(total // 2 + 1, 5)):
        _fail('rubric_mismatch', field + '.band')


def _sophistication(value, difficulty):
    field = 'scenario.sophistication'
    _fields(value, {'band', 'steps', 'edges', 'preconditions', 'boundaries', 'emulation_limitations', 'group_ids', 'source_references'}, field)
    _enum(value['band'], ('S0', 'S1', 'S2', 'S3', 'S4', 'S5'), field + '.band')
    boundaries = _unique_objects(value['boundaries'], 'boundary_id', field + '.boundaries')
    for item in boundaries.values():
        _fields(item, {'boundary_id', 'kind'}, field + '.boundaries')
        _enum(item['kind'], ('host', 'identity', 'privilege', 'segment', 'domain', 'on-prem', 'cloud', 'it', 'ot'), field + '.boundaries.kind')
    steps = _unique_objects(value['steps'], 'step_id', field + '.steps')
    for item in steps.values():
        _fields(item, {'step_id', 'asset_id', 'boundary_id', 'phase'}, field + '.steps')
        _id(item['asset_id'], field + '.steps.asset_id')
        _reference(item['boundary_id'], boundaries, field + '.steps.boundary_id')
        _enum(item['phase'], ('initial', 'persistence', 'reentry'), field + '.steps.phase')
    _edges(value['edges'], steps, field + '.edges')
    for key in ('preconditions', 'emulation_limitations'):
        _strings(value[key], field + '.' + key)
    _strings(value['source_references'], field + '.source_references', _https)
    _strings(value['group_ids'], field + '.group_ids')
    if value['group_ids'] and not value['source_references']:
        _fail('missing_source_reference', field + '.source_references')
    if any(not re.fullmatch(r'G[0-9]{4}', item) for item in value['group_ids']):
        _fail('invalid_identifier', field + '.group_ids')
    tier = int(value['band'][1])
    if (tier == 0) != difficulty['control'] or (tier == 0 and steps) or (tier == 1 and (not steps or value['edges'])) or (tier >= 2 and (len(steps) < 2 or not value['edges'])):
        _fail('rubric_mismatch', field + '.band')
    used = {item['boundary_id'] for item in steps.values()}
    if tier in (1, 2) and (len({item['asset_id'] for item in steps.values()}) != 1 or len(used) != 1):
        _fail('rubric_mismatch', field + '.band')
    chain = list(steps.values())
    if tier >= 2:
        # The tier describes one causally linked chain; other independent atomic
        # steps may coexist but never raise the tier.
        edged = {step for edge in value['edges'] for step in edge}
        linked = {min(edged)}
        remaining = edged - linked
        while remaining:
            added = {right for left, right in value['edges'] if left in linked}
            added.update(left for left, right in value['edges'] if right in linked)
            added &= remaining
            if not added:
                _fail('rubric_mismatch', field + '.edges')
            linked.update(added)
            remaining.difference_update(added)
        chain = [steps[step] for step in sorted(linked)]
    chain_boundaries = {item['boundary_id'] for item in chain}
    kinds = {boundaries[item]['kind'] for item in chain_boundaries}
    if tier >= 3 and (len({item['asset_id'] for item in chain}) < 2 or len(chain_boundaries) < 2 or not kinds.intersection({'identity', 'privilege'})):
        _fail('rubric_mismatch', field + '.band')
    if tier >= 4 and (not kinds.intersection({'segment', 'domain'}) or not any(item['phase'] in ('persistence', 'reentry') for item in chain)):
        _fail('rubric_mismatch', field + '.band')
    if tier == 5 and (not ({'on-prem', 'cloud'}.issubset(kinds) or {'it', 'ot'}.issubset(kinds)) or not any(difficulty['factors'][key]['score'] > 0 for key in ('gaps', 'ambiguity'))):
        _fail('rubric_mismatch', field + '.band')


def validate_scenario(value, coverage):
    validate_coverage(coverage)
    _fields(value, {'schema_version', 'scenario_id', 'family_id', 'revision', 'split', 'provenance', 'coverage', 'difficulty', 'sophistication', 'attack_release', 'source_references', 'evidence_manifest_sha256'}, 'scenario')
    _version(value['schema_version'], 'scenario.schema_version')
    for key in ('scenario_id', 'family_id'):
        _id(value[key], 'scenario.' + key)
    _integer(value['revision'], 'scenario.revision', 1)
    _enum(value['split'], ('development', 'holdout'), 'scenario.split')
    _enum(value['provenance'], ('synthetic', 'lab_export', 'derived_replay', 'public_replay'), 'scenario.provenance')
    _coverage_tags(value['coverage'], coverage['axes'], 'scenario.coverage')
    _difficulty(value['difficulty'])
    _sophistication(value['sophistication'], value['difficulty'])
    _attack_release(value['attack_release'], 'scenario.attack_release')
    _strings(value['source_references'], 'scenario.source_references', _https)
    _digest(value['evidence_manifest_sha256'], 'scenario.evidence_manifest_sha256')
    return value


def _public_path(value, field):
    _relative(value, field)
    if any(re.search(r'(?:^|[^a-z0-9])(?:truth|answers?|answer[-_]?keys?|evaluator|private)(?:$|[^a-z0-9])', part.casefold()) for part in value.split('/')):
        _fail('truth_public_overlap', field)


def validate_public_bundle(value, root=None):
    field = 'public_bundle'
    _fields(value, {'schema_version', 'case_id', 'window_utc', 'assets', 'sources', 'events', 'known_gaps', 'files', 'assessment_questions'}, field, {'unassessed_asset_ids'})
    _version(value['schema_version'], field + '.schema_version')
    if type(value['case_id']) is not str or not _CASE_ID.fullmatch(value['case_id']):
        _fail('invalid_identifier', field + '.case_id')
    outer = _window(value['window_utc'], field + '.window_utc')
    assets = _unique_objects(value['assets'], 'asset_id', field + '.assets', True)
    for asset in assets.values():
        _fields(asset, {'asset_id', 'os_family', 'os_version', 'architecture', 'vendor'}, field + '.assets')
        _enum(asset['os_family'], COVERAGE_AXES['os'], field + '.assets.os_family')
        for key in ('os_version', 'architecture', 'vendor'):
            _text(asset[key], field + '.assets.' + key, True)
    sources = _unique_objects(value['sources'], 'source_id', field + '.sources', True)
    source_windows = {}
    for source in sources.values():
        _fields(source, {'source_id', 'asset_ids', 'telemetry', 'clock_offset_seconds', 'clock_uncertainty_seconds', 'window_utc', 'sensor_version', 'config_version', 'completeness', 'source_sha256'}, field + '.sources')
        _strings(source['asset_ids'], field + '.sources.asset_ids', _id, True)
        for asset_id in source['asset_ids']:
            _reference(asset_id, assets, field + '.sources.asset_ids')
        # Null: the source makes no coverage-catalog telemetry claim.
        if source['telemetry'] is not None:
            _enum(source['telemetry'], COVERAGE_AXES['telemetry'], field + '.sources.telemetry')
        _number(source['clock_offset_seconds'], field + '.sources.clock_offset_seconds', nullable=True)
        _number(source['clock_uncertainty_seconds'], field + '.sources.clock_uncertainty_seconds', minimum=0, nullable=True)
        if (source['clock_offset_seconds'] is None) != (source['clock_uncertainty_seconds'] is None):
            _fail('incomplete_clock', field + '.sources')
        for key in ('sensor_version', 'config_version'):
            _text(source[key], field + '.sources.' + key, True)
        _enum(source['completeness'], ('complete', 'partial', 'unknown'), field + '.sources.completeness')
        _digest(source['source_sha256'], field + '.sources.source_sha256')
        source_windows[source['source_id']] = _window(source['window_utc'], field + '.sources.window_utc', outer)
    _array(value['files'], field + '.files')
    file_hashes, paths = set(), set()
    for item in value['files']:
        _fields(item, {'path', 'byte_count', 'sha256'}, field + '.files')
        _public_path(item['path'], field + '.files.path')
        _integer(item['byte_count'], field + '.files.byte_count')
        _digest(item['sha256'], field + '.files.sha256')
        # Portable manifests cannot depend on case-sensitive path distinctions.
        path_key = item['path'].casefold()
        if path_key in paths:
            _fail('duplicate_item', field + '.files')
        paths.add(path_key)
        file_hashes.add(item['sha256'])
        if root is not None:
            path = confined_file(root, item['path'], field + '.files.path')
            try:
                if path.stat().st_size != item['byte_count']:
                    _fail('evidence_digest_mismatch', field + '.files')
                data = path.read_bytes()
            except OSError:
                _fail('file_unreadable', field + '.files')
            if len(data) != item['byte_count'] or digest_bytes(data) != item['sha256']:
                _fail('evidence_digest_mismatch', field + '.files')
    events = _unique_objects(value['events'], 'event_id', field + '.events')
    previous = None
    for event in events.values():
        _fields(event, {'event_id', 'timestamp_utc', 'source_id', 'asset_id', 'event_type', 'fields', 'locator'}, field + '.events')
        _reference(event['source_id'], sources, field + '.events.source_id')
        _reference(event['asset_id'], sources[event['source_id']]['asset_ids'], field + '.events.asset_id')
        stamp = parse_utc(event['timestamp_utc'], field + '.events.timestamp_utc')
        window = source_windows[event['source_id']]
        if not window[0] <= stamp < window[1]:
            _fail('invalid_window', field + '.events.timestamp_utc')
        key = (stamp, event['event_id'])
        if previous is not None and key < previous:
            _fail('unstable_event_order', field + '.events')
        previous = key
        _text(event['event_type'], field + '.events.event_type')
        if type(event['fields']) is not dict or 'timestamp_original' not in event['fields']:
            _fail('missing_field', field + '.events.fields')
        _text(event['fields']['timestamp_original'], field + '.events.fields.timestamp_original')
        try:
            _public_fields(event['fields'], field + '.events.fields')
        except RecursionError:
            _fail('invalid_json', field + '.events.fields')
        _fields(event['locator'], {'file_sha256', 'record_id'}, field + '.events.locator')
        _digest(event['locator']['file_sha256'], field + '.events.locator.file_sha256')
        if event['locator']['file_sha256'] not in file_hashes:
            _fail('unknown_reference', field + '.events.locator.file_sha256')
        _text(event['locator']['record_id'], field + '.events.locator.record_id')
    _array(value['known_gaps'], field + '.known_gaps')
    for gap in value['known_gaps']:
        _fields(gap, {'source_id', 'asset_id', 'window_utc', 'reason'}, field + '.known_gaps')
        _reference(gap['source_id'], sources, field + '.known_gaps.source_id', True)
        _reference(gap['asset_id'], assets, field + '.known_gaps.asset_id', True)
        _window(gap['window_utc'], field + '.known_gaps.window_utc', outer)
        _text(gap['reason'], field + '.known_gaps.reason')
    # Enrolled infrastructure (for example a network sensor) may be declared
    # unassessed: it may carry sources/events/gaps but receives no question.
    unassessed = set()
    if 'unassessed_asset_ids' in value:
        unassessed = _strings(value['unassessed_asset_ids'], field + '.unassessed_asset_ids', _id)
        for asset_id in unassessed:
            _reference(asset_id, assets, field + '.unassessed_asset_ids')
    questions = _unique_objects(value['assessment_questions'], 'question_id', field + '.assessment_questions', True)
    combinations, windows = set(), set()
    for question in questions.values():
        _fields(question, {'question_id', 'asset_id', 'window_utc', 'question'}, field + '.assessment_questions')
        _reference(question['asset_id'], assets, field + '.assessment_questions.asset_id')
        if question['asset_id'] in unassessed:
            _fail('unassessed_asset', field + '.assessment_questions.asset_id')
        window = _window(question['window_utc'], field + '.assessment_questions.window_utc', outer)
        if question['question'] != ASSESSMENT_QUESTION:
            _fail('invalid_question', field + '.assessment_questions.question')
        combination = (question['asset_id'], window)
        if combination in combinations:
            _fail('duplicate_question', field + '.assessment_questions')
        combinations.add(combination)
        windows.add(window)
    if len(combinations) != (len(assets) - len(unassessed)) * len(windows):
        _fail('incomplete_questions', field + '.assessment_questions')
    # Every public key/value outside event fields (checked above) is also
    # refused when it carries evaluator keys or ATT&CK-looking tokens.
    outside = dict(value, events=[dict(event, fields=None) for event in value['events']])
    try:
        _json_value(outside, field, public=True)
    except RecursionError:
        _fail('invalid_json', field)
    return value


def validate_truth(value, public_bundle=None):
    field = 'truth'
    _fields(value, {'schema_version', 'case_id', 'evidence_manifest_sha256', 'truth_revision', 'attack_release', 'steps', 'edges', 'controls', 'assessment_labels'}, field, {'lookalike_event_ids', 'attestation', 'disputed_event_ids'})
    _version(value['schema_version'], field + '.schema_version')
    _id(value['case_id'], field + '.case_id')
    _digest(value['evidence_manifest_sha256'], field + '.evidence_manifest_sha256')
    _integer(value['truth_revision'], field + '.truth_revision', 1)
    _attack_release(value['attack_release'], field + '.attack_release')
    if 'attestation' in value:
        _enum(value['attestation'], TRUTH_ATTESTATIONS, field + '.attestation')
    assets = events = questions = None
    outer = None
    if public_bundle is not None:
        validate_public_bundle(public_bundle)
        if value['case_id'] != public_bundle['case_id']:
            _fail('case_mismatch', field + '.case_id')
        if value['evidence_manifest_sha256'] != digest_bytes(canonical_bytes(public_bundle)):
            _fail('evidence_digest_mismatch', field + '.evidence_manifest_sha256')
        assets = {item['asset_id'] for item in public_bundle['assets']}
        events = {item['event_id'] for item in public_bundle['events']}
        questions = {item['question_id'] for item in public_bundle['assessment_questions']}
        outer = _window(public_bundle['window_utc'], 'public_bundle.window_utc')
    # Lazy: benchmark_attack imports this module. Pinned ATT&CK identity; revoked
    # IDs are accepted here and canonicalised at scoring.
    from benchmark_attack import technique_status
    steps = _unique_objects(value['steps'], 'step_id', field + '.steps')
    for step in steps.values():
        _fields(step, {'step_id', 'technique_id', 'asset_id', 'window_utc', 'execution_outcome', 'observability', 'support_sets', 'source_receipt_sha256'}, field + '.steps')
        _technique(step['technique_id'], field + '.steps.technique_id')
        if technique_status(step['technique_id']) == 'unknown':
            _fail('unknown_technique', field + '.steps.technique_id')
        _id(step['asset_id'], field + '.steps.asset_id')
        if assets is not None:
            _reference(step['asset_id'], assets, field + '.steps.asset_id')
        _window(step['window_utc'], field + '.steps.window_utc', outer)
        _enum(step['execution_outcome'], ('succeeded', 'blocked', 'failed', 'unknown'), field + '.steps.execution_outcome')
        _enum(step['observability'], ('sufficient', 'insufficient', 'absent', 'unknown'), field + '.steps.observability')
        _array(step['support_sets'], field + '.steps.support_sets', step['observability'] == 'sufficient')
        seen = set()
        for support in step['support_sets']:
            ids = _strings(support, field + '.steps.support_sets', _id, True)
            key = frozenset(ids)
            if key in seen:
                _fail('duplicate_item', field + '.steps.support_sets')
            seen.add(key)
            if events is not None and not ids.issubset(events):
                _fail('unknown_reference', field + '.steps.support_sets')
        _digest(step['source_receipt_sha256'], field + '.steps.source_receipt_sha256')
    _edges(value['edges'], steps, field + '.edges')
    controls = _unique_objects(value['controls'], 'control_id', field + '.controls')
    for control in controls.values():
        _fields(control, {'control_id', 'asset_id', 'window_utc', 'expected_disposition'}, field + '.controls')
        _id(control['asset_id'], field + '.controls.asset_id')
        if assets is not None:
            _reference(control['asset_id'], assets, field + '.controls.asset_id')
        _window(control['window_utc'], field + '.controls.window_utc', outer)
        _enum(control['expected_disposition'], ('benign', 'insufficient'), field + '.controls.expected_disposition')
    if type(value['assessment_labels']) is not dict:
        _fail('invalid_object', field + '.assessment_labels')
    for key, label in value['assessment_labels'].items():
        _id(key, field + '.assessment_labels')
        if label is not None and (type(label) is not int or label not in (0, 1)):
            _fail('invalid_label', field + '.assessment_labels')
    if questions is not None and set(value['assessment_labels']) != questions:
        _fail('incomplete_questions', field + '.assessment_labels')
    lookalike = set()
    support = {item for step in steps.values() for group in step['support_sets'] for item in group}
    if 'lookalike_event_ids' in value:
        # Each group is one curator-validated benign/contradictory explanation.
        _array(value['lookalike_event_ids'], field + '.lookalike_event_ids')
        groups = set()
        for group in value['lookalike_event_ids']:
            ids = frozenset(_strings(group, field + '.lookalike_event_ids', _id, True))
            if ids in groups:
                _fail('duplicate_item', field + '.lookalike_event_ids')
            groups.add(ids)
            if events is not None and not ids.issubset(events):
                _fail('unknown_reference', field + '.lookalike_event_ids')
            if ids & support:
                _fail('lookalike_support_overlap', field + '.lookalike_event_ids')
            lookalike |= ids
    if 'disputed_event_ids' in value:
        # Records cited only by steps the agent-consensus drafts disagreed on; scoring ignores findings citing
        # only these. A human-attested or proposal answer key has no disputes to record.
        if value.get('attestation') != 'agent_consensus':
            _fail('disputed_without_consensus', field + '.disputed_event_ids')
        disputed = _strings(value['disputed_event_ids'], field + '.disputed_event_ids', _id, True)
        if events is not None and not disputed.issubset(events):
            _fail('unknown_reference', field + '.disputed_event_ids')
        if disputed & (support | lookalike):
            _fail('disputed_support_overlap', field + '.disputed_event_ids')
    return value


def _base_url(value, field):
    _text(value, field)
    if any(c.isspace() or ord(c) < 32 for c in value) or '\\' in value:
        _fail('invalid_url', field)
    try:
        url = urlsplit(value)
        if not url.hostname or url.username is not None or url.password is not None or url.query or url.fragment:
            _fail('invalid_url', field)
        url.port
        if url.scheme == 'http':
            try:
                loopback = ipaddress.ip_address(url.hostname).is_loopback
            except ValueError:
                loopback = False
            if not loopback:
                _fail('invalid_url', field)
        elif url.scheme != 'https':
            _fail('invalid_url', field)
    except ValueError:
        _fail('invalid_url', field)


def route_is_paid(spec):
    """Derive paid status from the route, never from a deployment label.

    Only an `openai`-protocol langchain route to literal-loopback HTTP
    (127.0.0.0/8 or ::1) is unpaid; hostnames such as `localhost` and every
    other route, including the typesafe checker, are treated as paid.
    """
    if spec.get('adapter') != 'langchain' or spec.get('provider') != 'openai':
        return True
    try:
        url = urlsplit(spec.get('base_url') or '')
        return url.scheme != 'http' or not ipaddress.ip_address(url.hostname or '').is_loopback
    except ValueError:
        return True


def call_cost_bound(budget, spec, rates):
    """Worst-case USD for one call, or None when it cannot be computed.

    An explicit `per_call_cost_bound_usd` wins. Otherwise the pricing-snapshot
    rate (USD per million tokens) bounds input by `max_prompt_bytes` and output
    by `max_output_tokens` (the byte-capped typesafe checker uses
    `max_response_bytes`): a UTF-8 byte count is an upper bound on tokens.
    """
    if not route_is_paid(spec):
        return 0.0
    if 'per_call_cost_bound_usd' in budget:
        return budget['per_call_cost_bound_usd']
    matches = [rate for rate in rates
               if rate['provider'] == spec['provider'] and rate['model_requested'] == spec['model_requested']]
    if len(matches) != 1:
        return None
    output = spec['max_output_tokens'] if spec['max_output_tokens'] is not None else budget['max_response_bytes']
    return (matches[0]['input_per_million'] * budget['max_prompt_bytes']
            + matches[0]['output_per_million'] * output) / 1000000


def _checker_origin(value, field):
    from envision_protocol import BridgeError, origin
    try:
        origin(value, allow_loopback_http=True)
    except BridgeError:
        _fail('invalid_origin', field)


def _model(value, field, checker=False):
    _fields(value, {'adapter', 'provider', 'model_requested', 'base_url', 'credential_env', 'parameters', 'timeout_seconds', 'max_output_tokens', 'expected_model_ids'}, field)
    _enum(value['adapter'], ('typesafe',) if checker else ('langchain',), field + '.adapter')
    _enum(value['provider'], ('typesafe',) if checker else ('openai', 'anthropic'), field + '.provider')
    _text(value['model_requested'], field + '.model_requested')
    _base_url(value['base_url'], field + '.base_url')
    if checker:
        # The checker posts to `<origin>/v1/systemone`; refuse any path now,
        # before a paid narrative call could precede the failure.
        _checker_origin(value['base_url'], field + '.base_url')
    if value['credential_env'] is not None and (type(value['credential_env']) is not str or not _CREDENTIAL_ENV.fullmatch(value['credential_env'])):
        _fail('invalid_environment_name', field + '.credential_env')
    _fields(value['parameters'], {'temperature', 'seed'}, field + '.parameters', {'structured_output'})
    temperature, seed = value['parameters']['temperature'], value['parameters']['seed']
    _number(temperature, field + '.parameters.temperature', 0, 1 if value['provider'] == 'anthropic' else 2, True)
    if seed is not None:
        if value['provider'] != 'openai':
            _fail('unsupported_parameter', field + '.parameters.seed')
        _integer(seed, field + '.parameters.seed')
    # Optional schema-constrained decoding (`stage_output_schema`), a treatment
    # attribute of the narrative route. Only the OpenAI-compatible transport has
    # a verified request path; the typed checker never takes it.
    structured = value['parameters'].get('structured_output', False)
    if type(structured) is not bool:
        _fail('invalid_boolean', field + '.parameters.structured_output')
    if structured and (checker or value['provider'] != 'openai'):
        _fail('unsupported_parameter', field + '.parameters.structured_output')
    _positive(value['timeout_seconds'], field + '.timeout_seconds')
    if checker:
        if value['max_output_tokens'] is not None or temperature is not None:
            _fail('unsupported_parameter', field)
    else:
        _integer(value['max_output_tokens'], field + '.max_output_tokens', 1)
    _strings(value['expected_model_ids'], field + '.expected_model_ids', nonempty=True)


def validate_team(value):
    field = 'team'
    _fields(value, {'team_id', 'deployment', 'roles', 'runtime_facts'}, field, {'evidence_checker'})
    _id(value['team_id'], field + '.team_id')
    _enum(value['deployment'], ('cloud', 'local', 'hybrid'), field + '.deployment')
    _fields(value['roles'], set(ROLE_IDS), field + '.roles')
    for role in ROLE_IDS:
        _model(value['roles'][role], field + '.roles.' + role)
    if 'evidence_checker' in value:
        _model(value['evidence_checker'], field + '.evidence_checker', checker=True)
    if value['deployment'] == 'local':
        routes = list(value['roles'].values()) + ([value['evidence_checker']] if 'evidence_checker' in value else [])
        if any(route_is_paid(spec) for spec in routes):
            _fail('paid_route_in_local_team', field + '.deployment')
    facts = value['runtime_facts']
    _fields(facts, {'server', 'server_version', 'model_weight_sha256', 'quantization', 'context_configuration', 'cpu', 'gpu', 'ram_bytes', 'concurrency'}, field + '.runtime_facts')
    for key in ('server', 'server_version', 'quantization', 'cpu', 'gpu'):
        _text(facts[key], field + '.runtime_facts.' + key, True)
    if facts['model_weight_sha256'] is not None:
        _digest(facts['model_weight_sha256'], field + '.runtime_facts.model_weight_sha256')
    for key in ('ram_bytes', 'concurrency'):
        if facts[key] is not None:
            _integer(facts[key], field + '.runtime_facts.' + key, 1)
    if facts['context_configuration'] is not None:
        _fields(facts['context_configuration'], {'context_window_tokens'}, field + '.runtime_facts.context_configuration')
        _integer(facts['context_configuration']['context_window_tokens'], field + '.runtime_facts.context_configuration.context_window_tokens', 1)
    return value


def validate_experiment(value):
    field = 'experiment'
    _fields(value, {'schema_version', 'experiment_id', 'scenario_refs', 'teams', 'repetitions', 'schedule_seed', 'budgets', 'workflow_sha256', 'prompt_contract_sha256', 'coverage_sha256', 'rubric_version', 'pricing_snapshot'}, field)
    _version(value['schema_version'], field + '.schema_version')
    _id(value['experiment_id'], field + '.experiment_id')
    _array(value['scenario_refs'], field + '.scenario_refs', True)
    seen = set()
    for item in value['scenario_refs']:
        _fields(item, {'scenario', 'evidence'}, field + '.scenario_refs')
        for key in ('scenario', 'evidence'):
            _relative(item[key], field + '.scenario_refs.' + key)
            normalized = item[key].casefold()
            if normalized in seen:
                _fail('truth_public_overlap' if key == 'evidence' else 'duplicate_item', field + '.scenario_refs')
            seen.add(normalized)
        _public_path(item['evidence'], field + '.scenario_refs.evidence')
    teams = _unique_objects(value['teams'], 'team_id', field + '.teams', True)
    for team in teams.values():
        validate_team(team)
    _integer(value['repetitions'], field + '.repetitions', 1)
    _integer(value['schedule_seed'], field + '.schedule_seed')
    budgets = value['budgets']
    required = {'max_calls_per_trial', 'max_active_seconds_per_trial', 'max_prompt_bytes', 'max_response_bytes', 'max_attempts_per_stage'}
    _fields(budgets, required, field + '.budgets', {'max_api_cost_usd', 'per_call_cost_bound_usd', 'provider_spend_cap_ref', 'max_concurrent_calls'})
    for key in required:
        _integer(budgets[key], field + '.budgets.' + key, 1, MAX_BYTES if key in ('max_prompt_bytes', 'max_response_bytes') else None)
    if 'max_concurrent_calls' in budgets:
        _integer(budgets['max_concurrent_calls'], field + '.budgets.max_concurrent_calls', 1, MAX_CONCURRENT_CALLS)
    for key in ('max_api_cost_usd', 'per_call_cost_bound_usd'):
        if key in budgets:
            _positive(budgets[key], field + '.budgets.' + key)
    if 'provider_spend_cap_ref' in budgets:
        _text(budgets['provider_spend_cap_ref'], field + '.budgets.provider_spend_cap_ref')
    if 'per_call_cost_bound_usd' in budgets and 'max_api_cost_usd' in budgets and budgets['per_call_cost_bound_usd'] > budgets['max_api_cost_usd']:
        _fail('invalid_cost_bound', field + '.budgets.per_call_cost_bound_usd')
    for key in ('workflow_sha256', 'prompt_contract_sha256', 'coverage_sha256'):
        _digest(value[key], field + '.' + key)
    _enum(value['rubric_version'], ('hunt-rubric-1',), field + '.rubric_version')
    prices = value['pricing_snapshot']
    _fields(prices, {'as_of_utc', 'currency', 'rates'}, field + '.pricing_snapshot')
    parse_utc(prices['as_of_utc'], field + '.pricing_snapshot.as_of_utc')
    _enum(prices['currency'], ('USD',), field + '.pricing_snapshot.currency')
    _array(prices['rates'], field + '.pricing_snapshot.rates')
    rates = set()
    for rate in prices['rates']:
        _fields(rate, {'model_requested', 'provider', 'input_per_million', 'output_per_million'}, field + '.pricing_snapshot.rates')
        for key in ('model_requested', 'provider'):
            _text(rate[key], field + '.pricing_snapshot.rates.' + key)
        for key in ('input_per_million', 'output_per_million'):
            _number(rate[key], field + '.pricing_snapshot.rates.' + key, minimum=0)
        key = (rate['provider'], rate['model_requested'])
        if key in rates:
            _fail('duplicate_item', field + '.pricing_snapshot.rates')
        rates.add(key)
    # Paid status comes from each route; a provider spend cap is recorded as
    # extra protection but never replaces a computable per-call bound.
    for team in teams.values():
        routes = list(team['roles'].values()) + ([team['evidence_checker']] if 'evidence_checker' in team else [])
        for spec in routes:
            if not route_is_paid(spec):
                continue
            if 'max_api_cost_usd' not in budgets:
                _fail('missing_cost_bound', field + '.budgets.max_api_cost_usd')
            if call_cost_bound(budgets, spec, prices['rates']) is None:
                _fail('unbounded_paid_route', field + '.budgets')
    return value


def max_concurrent_calls(experiment):
    """In-flight model-call limit across trials and independent branches."""
    return experiment['budgets'].get('max_concurrent_calls', DEFAULT_CONCURRENT_CALLS)


def truth_attestation(truth):
    """`human_attested` unless a validated truth explicitly says otherwise."""
    return truth.get('attestation', 'human_attested')


def _technique(value, field, nullable=False):
    if nullable and value is None:
        return
    if type(value) is not str or not _TECHNIQUE.fullmatch(value):
        _fail('invalid_technique', field)


def validate_stage_output(value, stage_key=None, public_bundle=None):
    """Validate structure, retaining nonexistent citations for honest scoring."""
    field = 'stage_output'
    required = {'schema_version', 'stage_key', 'summary', 'claims', 'findings', 'hypotheses', 'gaps', 'limitations', 'requested_decision'}
    if type(value) is dict and value.get('stage_key') == 'handoff':
        required.update({'chain_edges', 'assessment_answers'})
    _fields(value, required, field)
    _version(value['schema_version'], field + '.schema_version')
    _enum(value['stage_key'], STAGE_KEYS, field + '.stage_key')
    if stage_key is not None and value['stage_key'] != stage_key:
        _fail('stage_mismatch', field + '.stage_key')
    _text(value['summary'], field + '.summary')
    _enum(value['requested_decision'], ('approve', 'revise', 'insufficient'), field + '.requested_decision')
    # Narrative lists may repeat lines: the prompt contract does not require
    # uniqueness, so a repeated limitation is not a format failure.
    for key in ('hypotheses', 'gaps', 'limitations'):
        _array(value[key], field + '.' + key)
        for item in value[key]:
            _text(item, field + '.' + key)
    claims = _unique_objects(value['claims'], 'claim_id', field + '.claims')
    for claim in claims.values():
        _fields(claim, {'claim_id', 'kind', 'text', 'event_ids'}, field + '.claims')
        _enum(claim['kind'], ('observation', 'inference', 'hypothesis'), field + '.claims.kind')
        _text(claim['text'], field + '.claims.text')
        _strings(claim['event_ids'], field + '.claims.event_ids', _id)
    findings = _unique_objects(value['findings'], 'finding_id', field + '.findings')
    for finding in findings.values():
        _fields(finding, {'finding_id', 'asset_id', 'technique_id', 'window_utc', 'disposition', 'confidence', 'event_ids', 'rationale'}, field + '.findings')
        _id(finding['asset_id'], field + '.findings.asset_id')
        _technique(finding['technique_id'], field + '.findings.technique_id', True)
        _window(finding['window_utc'], field + '.findings.window_utc')
        _enum(finding['disposition'], ('suspicious', 'benign', 'insufficient'), field + '.findings.disposition')
        _number(finding['confidence'], field + '.findings.confidence', 0, 1, True)
        _strings(finding['event_ids'], field + '.findings.event_ids', _id)
        _text(finding['rationale'], field + '.findings.rationale')
    if public_bundle is not None:
        validate_public_bundle(public_bundle)
    if value['stage_key'] == 'handoff':
        _edges(value['chain_edges'], findings, field + '.chain_edges', acyclic=False)
        answers = _unique_objects(value['assessment_answers'], 'question_id', field + '.assessment_answers')
        for answer in answers.values():
            _fields(answer, {'question_id', 'probability_suspicious'}, field + '.assessment_answers')
            _number(answer['probability_suspicious'], field + '.assessment_answers.probability_suspicious', 0, 1, True)
        if public_bundle is not None and set(answers) != {item['question_id'] for item in public_bundle['assessment_questions']}:
            _fail('incomplete_questions', field + '.assessment_answers')
    return value


# `stage_output_schema` emits only this draft 2020-12 subset, which OpenAI strict
# structured outputs and LM Studio's OpenAI-compatible `response_format` accept:
# type, enum, properties, required, additionalProperties, items, minItems,
# maxItems, anyOf, pattern, minimum and maximum. No `$ref`, `const`, `format`,
# `minLength` or `uniqueItems`.
SCHEMA_KEYWORDS = frozenset(('type', 'enum', 'properties', 'required', 'additionalProperties', 'items',
                             'minItems', 'maxItems', 'anyOf', 'pattern', 'minimum', 'maximum'))
# Public identifier sets (event IDs, cited twice, then asset and question IDs)
# become enums only up to this many values; a larger set falls back to the
# identifier pattern. 4 x 200 plus 11 fixed choices stays within OpenAI's
# documented 1,000 enum values per schema, and no enum exceeds the 250 values
# beyond which its 15,000-character enum limit applies.
SCHEMA_ENUM_LIMIT = 200
_SCHEMA_ID = '^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$'
_SCHEMA_TIMESTAMP = r'^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?(Z|\+00:00)$'
_SCHEMA_TECHNIQUE = r'^T[0-9]{4}(\.[0-9]{3})?$'
# Nonblank text that constrained decoders (e.g. llama.cpp grammars) can express:
# the first character is visible, so a whitespace-only string cannot be emitted.
_SCHEMA_TEXT = r'^[^ \t\r\n].*$'


def _schema_object(properties):
    return {'type': 'object', 'properties': properties, 'required': list(properties),
            'additionalProperties': False}


def _schema_identifier(values):
    values = sorted(set(values))
    if 0 < len(values) <= SCHEMA_ENUM_LIMIT:
        return {'type': 'string', 'enum': values}
    return {'type': 'string', 'pattern': _SCHEMA_ID}


def _schema_nullable(schema):
    return {'anyOf': [schema, {'type': 'null'}]}


def _schema_choice(values):
    return {'type': 'string', 'enum': list(values)}


def stage_output_schema(stage_key, evidence):
    """Strict JSON Schema guiding constrained decoding of one stage's output.

    `evidence` is the trial's validated public bundle; its event, asset and
    question IDs become enums within `SCHEMA_ENUM_LIMIT`. Every object is closed
    and lists every property as required. The schema cannot express uniqueness,
    window ordering, nonblank text, chain-edge endpoints or answer completeness:
    `validate_stage_output` stays the authoritative check of every response.
    """
    _enum(stage_key, STAGE_KEYS, 'stage_key')
    text = {'type': 'string', 'pattern': _SCHEMA_TEXT}
    texts = {'type': 'array', 'items': text}
    local_id = {'type': 'string', 'pattern': _SCHEMA_ID}
    probability = {'type': 'number', 'minimum': 0, 'maximum': 1}
    timestamp = {'type': 'string', 'pattern': _SCHEMA_TIMESTAMP}
    event_ids = {'type': 'array', 'items': _schema_identifier(item['event_id'] for item in evidence['events'])}
    claim = _schema_object({
        'claim_id': local_id, 'kind': _schema_choice(('observation', 'inference', 'hypothesis')),
        'text': text, 'event_ids': event_ids})
    finding = _schema_object({
        'finding_id': local_id,
        'asset_id': _schema_identifier(item['asset_id'] for item in evidence['assets']),
        'technique_id': _schema_nullable({'type': 'string', 'pattern': _SCHEMA_TECHNIQUE}),
        'window_utc': _schema_object({'start_inclusive': timestamp, 'end_exclusive': timestamp}),
        'disposition': _schema_choice(('suspicious', 'benign', 'insufficient')),
        'confidence': _schema_nullable(probability), 'event_ids': event_ids, 'rationale': text})
    properties = {
        'schema_version': {'type': 'integer', 'enum': [SCHEMA_VERSION]},
        'stage_key': _schema_choice((stage_key,)), 'summary': text,
        'claims': {'type': 'array', 'items': claim}, 'findings': {'type': 'array', 'items': finding},
        'hypotheses': texts, 'gaps': texts, 'limitations': texts,
        'requested_decision': _schema_choice(('approve', 'revise', 'insufficient'))}
    if stage_key == 'handoff':
        questions = [item['question_id'] for item in evidence['assessment_questions']]
        properties['chain_edges'] = {'type': 'array', 'items': {'type': 'array', 'items': local_id,
                                                                'minItems': 2, 'maxItems': 2}}
        properties['assessment_answers'] = {
            'type': 'array', 'minItems': len(questions), 'maxItems': len(questions),
            'items': _schema_object({'question_id': _schema_identifier(questions),
                                     'probability_suspicious': _schema_nullable(probability)})}
    return _schema_object(properties)

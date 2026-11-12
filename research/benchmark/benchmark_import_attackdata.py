"""Import one Splunk attack_data Linux auditd or AWS CloudTrail export as a DEVELOPMENT benchmark case.

Input: one published attack_data log file (Linux `auditd` text lines or AWS
CloudTrail JSON lines; plain files, never archives), the dataset YAML that
declares it, and optionally a human-written curation JSON. The declaring YAML
entry's `sourcetype` selects the record format and the content must match it.
Output: a NEW directory `OUTPUT/<case_id>/` with the same layout as
benchmark_import_otrf.py (public bundle, records.jsonl mirroring original lines,
evaluator-only truth/draft, template, report, locators, pseudonyms, salt).

Safety decisions (the OTRF importer's model):
- The dataset is untrusted data. Nothing in it is executed, followed or fetched.
- Dataset YAML is parsed by the strict OTRF subset parser: only `id`, `date`,
  `environment`, `directory`, `mitre_technique` and `datasets` are interpreted;
  `author` and `description` are skipped by indentation; unknown keys, anchors,
  aliases, tags, flow collections and tab indentation are refused.
- Bounded input: plain regular files only, no archives, size/line/record caps.
- Public fields come from an explicit per-format, per-record-type allowlist
  (`benchmarks/importers/attackdata-fields.json`); everything else is dropped
  and counted. A record type without an allowlist entry is imported as a
  metadata-only event (type, record identity, timestamp, asset and the
  format's `metadata_only` fields). Account IDs, ARNs, principals, IPs,
  user/group/role/resource names and host names are replaced by HMAC-SHA256
  pseudonyms keyed by a per-import salt kept in the evaluator area.
  Pseudonymization is not declassification: a human must still review and
  release the public bundle.
- Content fields (auditd command lines reassembled from EXECVE argv, PROCTITLE,
  CloudTrail userAgent/errorMessage/requestParameters/responseElements/
  additionalEventData) are evidence: known secret keys are dropped, then the
  text passes benchmark_sanitize.sanitize_text (secret redaction, identity
  pseudonyms consistent with the structured fields, ATT&CK masking, bounded
  size with an explicit truncation marker).
- Truth comes ONLY from the curation file. attack_data labels a whole dataset
  with techniques; without curation the importer writes a draft that the
  contract validator refuses.
- An optional explicit partition window (`--window-start/--window-end`, UTC)
  excludes every record outside it and states the excluded original lines as
  a known gap; nothing inside it is sampled. Partitions keep the dataset's
  family_id, and a curated import must declare the same `partition_window`.

Python 3.9 standard library only.
"""

import argparse
import hashlib
import hmac
import ipaddress
import math
import re
import secrets
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from benchmark_contracts import (ASSESSMENT_QUESTION, COVERAGE_AXES, BenchmarkError,
                                 canonical_bytes, decode_json, digest_bytes, load_json,
                                 parse_utc, validate_public_bundle, validate_scenario,
                                 validate_truth)
from benchmark_import_otrf import (ATTACK_TOKEN, DRAFT_MARKER, SALT_BYTES,
                                   Pseudonyms, _attest_truth, _check_curator, _excluded_event_ids, _limitations,
                                   _normal_window, _overlaps, _proposal_attestation, _read_regular,
                                   _refuse_draft_check, _strict, _summarize_attestation, _text, _undisputed,
                                   _unlabeled, _utc_text, _window_tuple, _yaml_block, load_salt, write_outputs)
from benchmark_sanitize import KnownIdentities, merge_reports, new_totals, sanitize_text

IMPORTER_VERSION = 'attackdata-import-2'
HERE = Path(__file__).resolve().parent
DEFAULT_FIELDS = HERE / 'benchmarks' / 'importers' / 'attackdata-fields.json'
DEFAULT_COVERAGE = HERE / 'benchmarks' / 'coverage.json'

MAX_INPUT_BYTES = 64 * 1024 * 1024
MAX_LINE_BYTES = 1024 * 1024
MAX_RECORDS = 500000
MAX_METADATA_BYTES = 256 * 1024
MAX_SIDE_FILE_BYTES = 4 * 1024 * 1024
MAX_KEEP_CHARS = 4096
CONTENT_MAX_BYTES = 16384
MAX_DECLARED_OFFSET = 14 * 3600
MAX_DECLARED_UNCERTAINTY = 24 * 3600

FORMAT_AUDITD = 'linux-auditd'
FORMAT_CLOUDTRAIL = 'aws-cloudtrail'
SOURCETYPES = {'auditd': FORMAT_AUDITD, 'aws:cloudtrail': FORMAT_CLOUDTRAIL}
# Record shapes. `auditd-raw-epoch`: raw audit.log lines, `msg=audit(<epoch>.<ms>:<serial>): `, numeric IDs,
# quoted or hex-encoded untrusted strings, optional enriched section after 0x1d. `auditd-interpreted-local`:
# `ausearch -i` output, `msg=audit(MM/DD/YYYY HH:MM:SS.mmm:<serial>) : `, names resolved, local wall clock of
# an undocumented zone. `cloudtrail-jsonl`: one CloudTrail event object per line.
SHAPE_AUDIT_RAW = 'auditd-raw-epoch'
SHAPE_AUDIT_INTERPRETED = 'auditd-interpreted-local'
SHAPE_CLOUDTRAIL = 'cloudtrail-jsonl'
FORMAT_OS = {FORMAT_AUDITD: 'linux', FORMAT_CLOUDTRAIL: 'not-applicable'}
# Coverage the record format itself determines (curated imports must declare exactly these OS/telemetry tags
# and include the listed platform/identity tags). A cloud control plane is never Windows or Linux evidence.
FORMAT_COVERAGE_EXACT = {FORMAT_AUDITD: {'os': ['linux'], 'telemetry': ['linux-audit']},
                         FORMAT_CLOUDTRAIL: {'os': ['not-applicable'], 'telemetry': ['cloud-audit']}}
FORMAT_COVERAGE_REQUIRED = {FORMAT_AUDITD: {},
                            FORMAT_CLOUDTRAIL: {'execution_platform': 'cloud-control-plane',
                                                'identity_domain': 'cloud-iam'}}
# One kernel writes one audit log; without `node=` prefixes the export names no host at all.
AUDIT_HOST = 'audit-host'

TRANSFORMS = ('keep', 'linux-path', 'linux-comm', 'linux-user', 'linux-group', 'aws-account', 'aws-arn',
              'aws-principal', 'aws-user', 'aws-role', 'aws-resource', 'aws-key', 'aws-source', 'content')
# Field names the importer itself writes into public event fields.
INJECTED_FIELDS = ('timestamp_original', 'type', 'audit_serial')
# auditd fields the importer derives from other records of the same audit event (same node, serial and
# timestamp): `command_line` from EXECVE argv, `proctitle` from PROCTITLE. Only the `content` transform applies.
AUDIT_DERIVED = frozenset({'command_line', 'proctitle'})
# Raw-format auditd fields that the kernel writes either quoted or hex-encoded ("untrusted strings").
AUDIT_UNTRUSTED = frozenset({'comm', 'exe', 'name', 'cwd'})
# EXECVE argv markers: `argc`, `aN`, `aN_len` and `aN[k]` chunks of one long argument.
EXECVE_MARKER = re.compile(r'(?:(?<= )|^)(argc|a([0-9]{1,6})(?:(_len)|\[([0-9]{1,6})\])?)=')
# Lenient key scan used only to count the dropped fields of a metadata-only record.
AUDIT_ANY_KEY = re.compile(r'(?:(?<=[ \x1d])|^)([A-Za-z_][A-Za-z0-9_-]{0,63}(?:\[[0-9]{1,6}\])?)=')
CONTROL_CHARS = re.compile(r'[\x00-\x08\x0b-\x1f\x7f]')
SHELL_SAFE = re.compile(r'[^\s\'"\\]+\Z')
# CloudTrail content: keys whose values are secrets are dropped before serialization (policy documents stay).
SECRET_KEYS = frozenset(key.casefold() for key in (
    'password', 'newPassword', 'oldPassword', 'masterUserPassword', 'secretAccessKey', 'sessionToken',
    'privateKey', 'certificateBody', 'certificateChain', 'secretString', 'secretBinary', 'clientSecret'))
# CloudTrail content: identity-bearing keys (any depth) use the structured fields' pseudonyms.
AWS_KEY_TRANSFORMS = {'username': 'aws-user', 'rolename': 'aws-role', 'groupname': 'aws-resource',
                      'bucketname': 'aws-resource', 's3bucketname': 'aws-resource', 'trailname': 'aws-resource',
                      'policyname': 'aws-resource', 'instanceprofilename': 'aws-resource',
                      'accountid': 'aws-account', 'principalid': 'aws-principal', 'accesskeyid': 'aws-key'}
ARN_IN_TEXT = re.compile(r'arn:(?:aws|aws-cn|aws-us-gov):[a-z0-9-]+:[a-z0-9-]*:(?:[0-9]{12}|aws)?:'
                         r'[^\s"\'<>,;()\[\]{}\\]*[^\s"\'<>,;()\[\]{}\\.]')
ACCOUNT_IN_TEXT = re.compile(r'(?<![0-9A-Za-z])[0-9]{12}(?![0-9A-Za-z])')
# Pseudonym namespaces whose originals are matched as whole tokens inside content (the leak-check set).
IDENTITY_NAMESPACES = ('account', 'principal', 'user', 'role', 'resource', 'key', 'group', 'netbios', 'dns', 'ip',
                       'segment', 'opaque')
LINUX_LITERALS = frozenset({'(null)', '?', '(none)', ''})
LINUX_WELL_KNOWN_USERS = frozenset({'root', 'unset', 'nobody', 'daemon', 'bin', 'sys', 'sync', 'man', 'lp',
                                    'mail', 'news', 'proxy', 'www-data', 'backup', 'syslog', 'messagebus',
                                    'sshd', '_apt', 'systemd-network', 'systemd-resolve', 'systemd-timesync',
                                    'polkitd'})
LINUX_WELL_KNOWN_GROUPS = frozenset({'root', 'unset', 'shadow', 'adm', 'sudo', 'wheel', 'nogroup', 'daemon',
                                     'sys', 'disk', 'tty', 'utmp', 'staff', 'users', 'crontab', 'ssh', '_ssh',
                                     'systemd-journal', 'syslog'})

YAML_TOP_KEYS = frozenset({'author', 'id', 'date', 'description', 'environment', 'directory',
                           'mitre_technique', 'datasets'})
YAML_PARSED = frozenset({'id', 'date', 'environment', 'directory', 'mitre_technique', 'datasets'})
UUID = re.compile(r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\Z')
DATASET_PATH = re.compile(r'/datasets(?:/[A-Za-z0-9._-]+)+\Z')
FAMILY_ID = re.compile(r'(?:attackdata|otrf)-t[0-9]{4}(?:-[0-9]{3})?(?:-t[0-9]{4}(?:-[0-9]{3})?)*\Z')
AUDIT_LINE = re.compile(r'(?:node=([A-Za-z0-9][A-Za-z0-9._-]{0,254}) )?type=([A-Z][A-Z0-9_]{0,63}) '
                        r'msg=audit\(([^()]{1,64})\)(: | : )(.*)\Z')
RAW_STAMP = re.compile(r'([0-9]{9,11})\.([0-9]{3}):([0-9]{1,20})\Z')
INTERPRETED_STAMP = re.compile(r'([0-9]{2})/([0-9]{2})/([0-9]{4}) ([0-9]{2}):([0-9]{2}):([0-9]{2})\.([0-9]{3})'
                               r':([0-9]{1,20})\Z')
AUDIT_TOKEN = re.compile(r'([A-Za-z_][A-Za-z0-9_-]{0,63})=("[^"\x00-\x1f\x7f]*"|[^ "\x00-\x1f\x7f]*)')
# `ausearch -i` renders errors as `exit=EACCES(Permission denied)`: the only interpreted value with a space.
AUDIT_TOKEN_INTERPRETED = re.compile(r'([A-Za-z_][A-Za-z0-9_-]{0,63})=("[^"\x00-\x1f\x7f]*"|'
                                     r'[A-Z][A-Z0-9]{1,31}\([A-Za-z][A-Za-z0-9 ,.\'/-]{0,127}\)(?= |\Z)|'
                                     r'[^ "\x00-\x1f\x7f]*)')
HEX = re.compile(r'(?:[0-9A-F]{2})+\Z')
CLOUDTRAIL_TIME = re.compile(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z\Z')
EVENT_RECORD_ID = re.compile(r'[A-Za-z0-9-]{1,64}\Z')
EVENT_TYPE = re.compile(r'[A-Za-z][A-Za-z0-9]{0,63}\Z')
ACCOUNT = re.compile(r'[0-9]{12}\Z')
AWS_SERVICE = re.compile(r'[a-z0-9-]+(?:\.[a-z0-9-]+)*\.amazonaws\.com\Z')
ARN = re.compile(r'arn:(aws|aws-cn|aws-us-gov):([a-z0-9-]+):([a-z0-9-]*):([0-9]{12}|aws)?:(.+)\Z')
TOKEN_FORM = re.compile(r'(?<![a-z0-9])(?:asset|source|event|question|user|group|host|domain|dns|ipv4|ipv6|'
                        r'addr|segment|value|account|principal|role|resource|key)-[0-9a-f]{16}')
LICENSE = ('Splunk attack_data (https://github.com/splunk/attack_data): Apache License 2.0 (LICENSE file; the '
           'README states "Copyright 2025 Splunk Inc."; the repository has no NOTICE file). This case is a '
           'MODIFIED derivative: records were filtered, pseudonymized and re-encoded by ' + IMPORTER_VERSION + '. '
           'Redistribution must include a copy of the Apache License 2.0, retain the attribution notices and state '
           'that the files were changed.')


def _fail(code, field):
    raise BenchmarkError(code, field)


# --------------------------------------------------------- strict YAML subset

def _normalize_sequence_items(lines):
    """Rewrite `-   key: v` sequence items (extra spaces after the dash, as some attack_data YAML files use) to
    the `- key: v` form the shared OTRF subset parser accepts, dedenting that item's lines by the same amount.
    Exactly semantics-preserving for one level; a nested over-indented item is refused."""
    out, region = [], None  # region: (original content column, shift)
    for line in lines:
        stripped = line.lstrip(' ')
        indent = len(line) - len(stripped)
        if region is not None and stripped and not stripped.startswith('#') and indent < region[0]:
            region = None
        if region is not None and stripped and not stripped.startswith('#'):
            line = line[region[1]:]
        match = re.match(r'-( {2,})(?=\S)', stripped)
        if match:
            if region is not None:
                _fail('unsupported_yaml', 'metadata')
            spaces = len(match.group(1))
            region = (indent + 1 + spaces, spaces - 1)
            line = line[:indent] + '- ' + stripped[1 + spaces:]
        out.append(line)
    return out


def parse_metadata_yaml(data):
    """Parse the needed subset of an attack_data dataset YAML file. Never executes anything."""
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
    for line in _normalize_sequence_items([raw[:-1] if raw.endswith('\r') else raw for raw in text.split('\n')]):
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
    for key in ('id', 'mitre_technique', 'datasets'):
        if key not in parsed:
            _fail('missing_field', 'metadata.' + key)
    if type(parsed['id']) is not str or not UUID.fullmatch(parsed['id']):
        _fail('invalid_identifier', 'metadata.id')
    for key in ('date', 'environment', 'directory'):
        value = parsed.get(key)
        if value is not None and (type(value) is not str or not re.fullmatch(r'[A-Za-z0-9._ -]{1,128}', value)):
            _fail('invalid_text', 'metadata.' + key)
    techniques = parsed['mitre_technique']
    if type(techniques) is not list or not techniques:
        _fail('metadata_missing_technique', 'metadata.mitre_technique')
    if not all(type(item) is str and re.fullmatch(r'T[0-9]{4}(?:\.[0-9]{3})?', item) for item in techniques):
        _fail('invalid_technique', 'metadata.mitre_technique')
    datasets = parsed['datasets']
    if type(datasets) is not list or not datasets:
        _fail('invalid_array', 'metadata.datasets')
    entries, basenames = [], set()
    for item in datasets:
        if type(item) is not dict or set(item) != {'name', 'path', 'sourcetype', 'source'}:
            _fail('invalid_object', 'metadata.datasets')
        if not all(type(item[key]) is str and item[key].strip() for key in item):
            _fail('invalid_text', 'metadata.datasets')
        path = item['path']
        if not DATASET_PATH.fullmatch(path) or any(part in ('.', '..') for part in path.split('/')):
            _fail('unsafe_path', 'metadata.datasets.path')
        basename = path.rsplit('/', 1)[-1]
        if basename.casefold() in basenames:
            _fail('duplicate_item', 'metadata.datasets.path')
        basenames.add(basename.casefold())
        entries.append({'name': item['name'].strip(), 'path': path, 'basename': basename,
                        'sourcetype': item['sourcetype'].strip(), 'source': item['source'].strip()})
    return {'id': parsed['id'].casefold(), 'date': parsed.get('date'), 'environment': parsed.get('environment'),
            'directory': parsed.get('directory'), 'techniques': sorted(set(techniques)), 'datasets': entries}


def _bind_metadata(metadata, input_name):
    """The supplied file must be exactly one declared dataset; its sourcetype selects the record format."""
    matches = [entry for entry in metadata['datasets'] if entry['basename'] == input_name]
    if len(matches) != 1:
        _fail('metadata_dataset_mismatch', 'metadata.datasets')
    entry = matches[0]
    if entry['sourcetype'] not in SOURCETYPES:
        _fail('unsupported_sourcetype', 'metadata.datasets.sourcetype')
    return entry, SOURCETYPES[entry['sourcetype']]


# ---------------------------------------------------------------- pseudonyms

class AttackDataPseudonyms(Pseudonyms):
    """OTRF HMAC pseudonyms plus Linux and AWS identifier transforms (shared namespaces correlate fields)."""

    def linux_path(self, value):
        if value in LINUX_LITERALS:
            return value
        parts = value.split('/')
        out = []
        for index, part in enumerate(parts):
            if part and index >= 1 and parts[index - 1] == 'home':
                out.append(self.linux_user(part))
            else:
                out.append(self.segment(part) if part else part)
        return '/'.join(out)

    def linux_comm(self, value):
        return value if value in LINUX_LITERALS else self.segment(value)

    def linux_user(self, value):
        if value in LINUX_LITERALS or value.isdigit() or value in LINUX_WELL_KNOWN_USERS:
            return value
        return self.token('user', 'user', value)

    def linux_group(self, value):
        if value in LINUX_LITERALS or value.isdigit() or value in LINUX_WELL_KNOWN_GROUPS:
            return value
        return self.token('group', 'group', value)

    def aws_account(self, value):
        if value == '':
            return value
        if ACCOUNT.fullmatch(value):
            return self.token('account', 'account', value)
        return self.token('value', 'opaque', value)

    def aws_arn(self, value):
        match = ARN.fullmatch(value)
        if not match:
            return self.token('value', 'opaque', value)
        partition, service, region, account, resource = match.groups()
        account = '' if account is None else (account if account == 'aws' else self.aws_account(account))
        return ':'.join(('arn', partition, service, region, account, self._arn_resource(service, resource)))

    def _arn_resource(self, service, resource):
        if service == 's3':
            bucket, sep, key = resource.partition('/')
            return self.aws_resource(bucket) + (sep + '/'.join(self.aws_resource(part) if part else part
                                                               for part in key.split('/')) if sep else '')
        if resource == 'root':
            return resource
        # `user/` (an IAM path prefix, as in an AccessDenied message for iam:ListUsers) has an empty name.
        match = re.fullmatch(r'([A-Za-z0-9-]+)([/:])(.*)', resource)
        if not match:
            return self.aws_resource(resource)
        kind, sep, rest = match.groups()
        segments = rest.split('/')
        if service == 'iam' and kind in ('user', 'role'):
            name = self.aws_user(segments[-1]) if kind == 'user' else self.aws_role(segments[-1])
            return kind + sep + '/'.join([self.aws_resource(part) if part else part for part in segments[:-1]] + [name])
        if service == 'sts' and kind == 'assumed-role' and len(segments) == 2:
            return kind + sep + self.aws_role(segments[0]) + '/' + self.account(segments[1])
        return kind + sep + '/'.join(self.aws_resource(part) if part else part for part in segments)

    def aws_principal(self, value):
        if value == '':
            return value
        if ACCOUNT.fullmatch(value):
            return self.aws_account(value)
        head, sep, session = value.partition(':')
        return self.token('principal', 'principal', head) + (sep + self.account(session) if sep else '')

    def aws_user(self, value):
        return value if value == '' else self.token('user', 'user', value)

    def aws_role(self, value):
        return value if value == '' else self.token('role', 'role', value)

    def aws_resource(self, value):
        if value == '' or set(value) == {'*'}:
            return value
        if value.startswith('arn:'):
            return self.aws_arn(value)
        return self.token('resource', 'resource', value)

    def aws_key(self, value):
        return value if value == '' else self.token('key', 'key', value)

    def aws_source(self, value):
        if value == 'AWS Internal' or AWS_SERVICE.fullmatch(value):
            return value
        try:
            ipaddress.ip_address(value.strip('[]'))
        except ValueError:
            return self.token('dns', 'dns', value.rstrip('.'))
        return self.ip(value)

    def transform(self, transform, value, field):
        if value is None or type(value) is bool or type(value) is int:
            return value
        if type(value) is float:
            if transform != 'keep' or not math.isfinite(value):
                _fail('unsupported_record_shape', field)
            return value
        if type(value) is not str:
            _fail('unsupported_record_shape', field)
        if len(value) > MAX_KEEP_CHARS:
            _fail('field_too_long', field)
        if transform == 'keep':
            return value
        method = getattr(self, transform.replace('-', '_'))
        return method(value)


# ----------------------------------------------------------------- field map

def load_field_map(path=DEFAULT_FIELDS):
    _, data = _read_regular(path, MAX_SIDE_FILE_BYTES, 'fields')
    value = decode_json(data)
    if type(value) is not dict or set(value) != {'schema_version', 'version', 'note', 'formats'}:
        _fail('invalid_object', 'fields')
    if value['schema_version'] != 1 or type(value['version']) is not str or \
            not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}', value['version']):
        _fail('unsupported_schema', 'fields')
    formats = value['formats']
    if type(formats) is not dict or set(formats) != {FORMAT_AUDITD, FORMAT_CLOUDTRAIL}:
        _fail('invalid_object', 'fields.formats')
    for name, spec in formats.items():
        if type(spec) is not dict or set(spec) != {'source', 'telemetry', 'record_types', 'metadata_only'}:
            _fail('invalid_object', 'fields.formats')
        if type(spec['source']) is not str or not re.fullmatch(r'[a-z][a-z0-9-]{0,31}', spec['source']):
            _fail('invalid_identifier', 'fields.formats.source')
        if spec['telemetry'] != FORMAT_COVERAGE_EXACT[name]['telemetry'][0]:
            _fail('invalid_choice', 'fields.formats.telemetry')
        if type(spec['record_types']) is not dict or not spec['record_types']:
            _fail('invalid_object', 'fields.formats.record_types')
        for record_type, fields in spec['record_types'].items():
            pattern = r'[A-Z][A-Z0-9_]{0,63}' if name == FORMAT_AUDITD else r'[A-Za-z][A-Za-z0-9]{0,63}'
            if not re.fullmatch(pattern, record_type) or type(fields) is not dict or not fields:
                _fail('invalid_object', 'fields.formats.record_types')
            _check_field_specs(name, fields, 'fields.formats.record_types.field', True)
        # Fields kept for a record type without an allowlist entry (metadata-only events); never content.
        if type(spec['metadata_only']) is not dict:
            _fail('invalid_object', 'fields.formats.metadata_only')
        _check_field_specs(name, spec['metadata_only'], 'fields.formats.metadata_only', False)
        # auditd bodies of unknown types are not tokenized (their syntax is not verified): metadata only.
        if name == FORMAT_AUDITD and spec['metadata_only']:
            _fail('invalid_choice', 'fields.formats.metadata_only')
    if formats[FORMAT_AUDITD]['source'] == formats[FORMAT_CLOUDTRAIL]['source']:
        _fail('duplicate_item', 'fields.formats.source')
    value['sha256'] = digest_bytes(data)
    return value


def _check_field_specs(record_format, fields, field, content_allowed):
    for field_name, transform in fields.items():
        path_ok = re.fullmatch(r'[A-Za-z_][A-Za-z0-9_-]{0,63}', field_name) if record_format == FORMAT_AUDITD else \
            re.fullmatch(r'[A-Za-z][A-Za-z0-9_-]{0,63}(?:\.[A-Za-z][A-Za-z0-9_-]{0,63}){0,5}', field_name)
        if not path_ok or field_name in INJECTED_FIELDS or transform not in TRANSFORMS:
            _fail('invalid_choice', field)
        if transform == 'content' and not content_allowed:
            _fail('invalid_choice', field)
        # auditd: only the derived argv fields are content, and they are always content.
        if record_format == FORMAT_AUDITD and (transform == 'content') != (field_name in AUDIT_DERIVED):
            _fail('invalid_choice', field)


# ------------------------------------------------------------------- records

def read_dataset(path, max_input_bytes=MAX_INPUT_BYTES):
    """Return (input_path, input_bytes). Plain .log/.json files only; archives are refused."""
    candidate, data = _read_regular(path, max_input_bytes, 'dataset')
    if candidate.suffix.casefold() not in ('.log', '.json') or data[:4] == b'PK\x03\x04' or data[:2] == b'\x1f\x8b':
        _fail('unsupported_dataset_layout', 'dataset')
    return candidate, data


def _split_lines(data):
    if data[:3] == b'\xef\xbb\xbf':
        data = data[3:]
    lines = data.split(b'\n')
    if lines and lines[-1] == b'':
        lines.pop()
    if len(lines) > MAX_RECORDS:
        _fail('too_many_records', 'dataset')
    return lines


def _audit_fields(body, shape, field):
    """Tokenize one auditd record body strictly: `key=value` separated by single spaces, nothing else."""
    main, separator, enriched = body.partition('\x1d')
    if separator and (shape != SHAPE_AUDIT_RAW or '\x1d' in enriched):
        _fail('unsupported_record_shape', field)
    result = {}
    for part, upper in ((main, False), (enriched, True)) if separator else ((main, False),):
        text, position = part.rstrip(' '), 0
        while position < len(text):
            match = (AUDIT_TOKEN_INTERPRETED if shape == SHAPE_AUDIT_INTERPRETED else AUDIT_TOKEN).match(text, position)
            if not match:
                _fail('unsupported_record_shape', field)
            key, value = match.group(1), match.group(2)
            ok = (key == key.upper() and key != key.lower()) if upper else key == key.lower()
            if not ok:
                _fail('unsupported_record_shape', field)
            if key in result:
                _fail('duplicate_key', field)
            quoted = value.startswith('"')
            result[key] = (value[1:-1] if quoted else value, quoted)
            position = match.end()
            if position < len(text):
                if text[position] != ' ':
                    _fail('unsupported_record_shape', field)
                position += 1
    return result


def _audit_value(key, value, quoted, shape, field, counters):
    """Raw-format untrusted strings are quoted or hex-encoded by the kernel; decode hex strictly."""
    if shape != SHAPE_AUDIT_RAW or key.lower() not in AUDIT_UNTRUSTED or quoted or value in LINUX_LITERALS:
        return value
    if not HEX.fullmatch(value):
        _fail('unsupported_record_shape', field)
    try:
        decoded = bytes.fromhex(value).decode('utf-8')
    except (ValueError, UnicodeError):
        _fail('invalid_text', field)
    if any(ord(c) < 32 or ord(c) == 127 for c in decoded):
        _fail('invalid_text', field)
    counters['hex_decoded_values'] = counters.get('hex_decoded_values', 0) + 1
    return decoded


def _count(counters, key, amount=1):
    counters[key] = counters.get(key, 0) + amount


def _argv_text(value):
    """Untrusted argv text: undecodable bytes and control characters other than tab/newline become escapes."""
    if type(value) is bytes:
        value = value.decode('utf-8', 'backslashreplace')
    return CONTROL_CHARS.sub(lambda match: '\\x%02x' % ord(match.group(0)), value)


def _raw_argv_bytes(value):
    """One raw-format argv value: kernel-quoted text, kernel hex (any byte), or a literal such as `(null)`."""
    if len(value) >= 2 and value[0] == value[-1] == '"':
        return value[1:-1].encode('utf-8')
    if HEX.fullmatch(value):
        return bytes.fromhex(value)
    return value.encode('utf-8')


def _execve_key(match):
    if match.group(1) == 'argc':
        return 'argc', -1, None
    index = int(match.group(2))
    if match.group(3):
        return 'len', index, None
    if match.group(4) is not None:
        return 'chunk', index, int(match.group(4))
    return 'arg', index, None


def _execve_follows(previous, current):
    """argv order: argc, a0, a1 | a1_len, a1[0], a1[1], a2 ... (continuation records start at any aN)."""
    kind, index, chunk = _execve_key(previous)
    next_kind, next_index, next_chunk = _execve_key(current)
    if kind == 'len':
        return next_kind == 'chunk' and next_index == index and next_chunk == 0
    if kind == 'chunk' and next_kind == 'chunk':
        return next_index == index and next_chunk == chunk + 1
    return next_kind in ('arg', 'len') and next_index == index + 1


def _execve(body, shape):
    """Arguments of one EXECVE record as {'argc': int or None, 'args': {index: text}}; None if not parseable.

    Markers are accepted only in argv order, so an interpreted (`ausearch -i`) value containing spaces, quotes or
    an out-of-order `aN=` stays inside its argument. Raw values are kernel-quoted or hex (decoded bytewise, chunks
    `aN[k]` joined before decoding)."""
    main = body.partition('\x1d')[0]
    if main.endswith(' '):
        main = main[:-1]
    accepted = []
    for match in EXECVE_MARKER.finditer(main):
        if not accepted:
            if match.start() != 0:
                break
        elif not _execve_follows(accepted[-1], match):
            continue
        accepted.append(match)
    if not accepted:
        return None
    argc, chunks = None, {}
    for position, match in enumerate(accepted):
        end = accepted[position + 1].start() - 1 if position + 1 < len(accepted) else len(main)
        value = main[match.end():end]
        kind, index, _ = _execve_key(match)
        if kind == 'argc':
            if not re.fullmatch(r'[0-9]{1,6}', value):
                return None
            argc = int(value)
        elif kind != 'len':
            chunks.setdefault(index, []).append(_raw_argv_bytes(value) if shape == SHAPE_AUDIT_RAW
                                                else value.encode('utf-8'))
    return {'argc': argc, 'args': {index: _argv_text(b''.join(parts)) for index, parts in chunks.items()}}


def _proctitle(body, shape):
    """PROCTITLE text: raw hex is argv joined by NUL (kernel-truncated at 128 bytes), shown space-separated like
    `ausearch -i`; interpreted values run to the end of the line. None if the body is not `proctitle=...`."""
    main = body.partition('\x1d')[0]
    if not main.startswith('proctitle='):
        return None
    value = main[len('proctitle='):]
    if shape == SHAPE_AUDIT_INTERPRETED:
        return _argv_text(value[:-1] if value.endswith(' ') else value)
    value = value.rstrip(' ')
    if HEX.fullmatch(value):
        parts = bytes.fromhex(value).split(b'\x00')
        if len(parts) > 1 and parts[-1] == b'':
            parts.pop()
        return ' '.join(_argv_text(part) for part in parts)
    return _argv_text(_raw_argv_bytes(value))


def _shell_word(value):
    """argv element for a readable command line: quoted (POSIX single quotes) only when it is empty or contains
    whitespace, quotes or backslashes, so argument boundaries survive the join."""
    if SHELL_SAFE.fullmatch(value):
        return value
    return "'" + value.replace("'", "'\\''") + "'"


def _audit_entry(text, entry, field):
    match = AUDIT_LINE.fullmatch(text)
    if not match:
        _fail('unsupported_record_shape', field)
    node, record_type, stamp, separator, body = match.groups()
    raw = RAW_STAMP.fullmatch(stamp)
    interpreted = INTERPRETED_STAMP.fullmatch(stamp)
    if raw and separator == ': ':
        seconds = int(raw.group(1))
        if not 946684800 <= seconds <= 4102444800:
            _fail('invalid_timestamp', field)
        moment = datetime.fromtimestamp(seconds, timezone.utc).replace(microsecond=int(raw.group(2)) * 1000)
        shape, serial, original = SHAPE_AUDIT_RAW, raw.group(3), raw.group(1) + '.' + raw.group(2)
    elif interpreted and separator == ' : ':
        month, day, year, hour, minute, second, milli, serial = interpreted.groups()
        try:
            # Placeholder: zone-less local wall clock read as UTC; build_case applies the declared offset.
            moment = datetime(int(year), int(month), int(day), int(hour), int(minute), int(second),
                              int(milli) * 1000, timezone.utc)
        except ValueError:
            _fail('invalid_timestamp', field)
        shape, original = SHAPE_AUDIT_INTERPRETED, stamp.rsplit(':', 1)[0]
    else:
        _fail('unsupported_record_shape', field)
    entry.update({'shape': shape, 'record_type': record_type, 'node': node, 'time': moment,
                  'timestamp_original': original, 'record_id': serial, 'body': body})


def _cloudtrail_entry(raw, entry, field):
    try:
        record = decode_json(raw)
    except BenchmarkError:
        _fail('invalid_json', field)
    except RecursionError:
        _fail('invalid_json', field)
    if type(record) is not dict:
        _fail('unsupported_record_shape', field)
    for key in ('eventTime', 'eventID', 'eventName', 'eventSource', 'eventType', 'recipientAccountId'):
        if type(record.get(key)) is not str:
            _fail('unsupported_record_shape', field)
    if not CLOUDTRAIL_TIME.fullmatch(record['eventTime']) or not EVENT_RECORD_ID.fullmatch(record['eventID']) or \
            not EVENT_TYPE.fullmatch(record['eventType']) or not ACCOUNT.fullmatch(record['recipientAccountId']):
        _fail('unsupported_record_shape', field)
    entry.update({'shape': SHAPE_CLOUDTRAIL, 'record_type': record['eventType'],
                  'node': record['recipientAccountId'], 'time': parse_utc(record['eventTime'], field),
                  'timestamp_original': record['eventTime'], 'record_id': record['eventID'], 'record': record})


def parse_records(data, record_format, field_map):
    """Return (entries, shape): one entry per ORIGINAL line; nothing is silently dropped."""
    if record_format == FORMAT_CLOUDTRAIL and data.lstrip(b'\xef\xbb\xbf \t\r\n')[:1] == b'[':
        _fail('unsupported_dataset_layout', 'dataset')
    spec = field_map['formats'][record_format]
    entries, shape = [], None
    for number, raw in enumerate(_split_lines(data), 1):
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
        if record_format == FORMAT_AUDITD:
            try:
                text = raw.decode('utf-8')
            except UnicodeError:
                _fail('invalid_text', field)
            _audit_entry(text, entry, field)
        else:
            _cloudtrail_entry(raw, entry, field)
        if shape is None:
            shape = entry['shape']
        elif entry['shape'] != shape:
            _fail('mixed_record_shapes', field)
        entry['status'] = 'imported'
        entry['metadata_only'] = entry['record_type'] not in spec['record_types']
        entries.append(entry)
    if not any(entry['status'] == 'imported' for entry in entries):
        _fail('no_supported_records', 'dataset')
    return entries, shape


def _leaves(value, prefix, out):
    if type(value) is dict and value:
        for key, item in value.items():
            _leaves(item, prefix + '.' + key if prefix else key, out)
    else:
        out.append(prefix)


def _lookup(record, path):
    value = record
    for part in path.split('.'):
        if type(value) is not dict or part not in value:
            return False, None
        value = value[part]
    return True, value


def _public_fields(entry, spec, names, shape, counters, dropped):
    """Allowlisted, transformed public fields of one record. Raw content values go to entry['content_raw']; they are
    sanitized after every structured field has registered its pseudonyms. A record type without an allowlist
    entry keeps only its metadata (metadata-only event); its other fields are dropped and counted."""
    allow = spec['metadata_only'] if entry['metadata_only'] else spec['record_types'][entry['record_type']]
    label = spec['source'] + '.' + entry['record_type']
    entry['content_raw'] = {}
    if shape == SHAPE_CLOUDTRAIL:
        fields = {'timestamp_original': entry['timestamp_original']}
        content = [name for name, transform in allow.items() if transform == 'content']
        leaves = []
        _leaves(entry['record'], '', leaves)
        for leaf in leaves:
            if leaf not in allow and not any(leaf.startswith(name + '.') for name in content):
                dropped[leaf] = dropped.get(leaf, 0) + 1
        for name in sorted(allow):
            present, value = _lookup(entry['record'], name)
            if not present:
                continue
            if allow[name] == 'content':
                if type(value) in (str, dict, list):
                    entry['content_raw'][name] = value
                else:
                    fields[name] = names.transform('keep', value, label + '.' + name)
                continue
            if type(value) in (dict, list):
                _fail('unsupported_record_shape', label + '.' + name)
            fields[name] = _checked(names.transform(allow[name], value, label + '.' + name), label + '.' + name)
        return fields
    body = entry.pop('body')
    fields = {'timestamp_original': entry['timestamp_original'], 'type': entry['record_type'],
              'audit_serial': entry['record_id']}
    if entry['metadata_only']:
        for match in AUDIT_ANY_KEY.finditer(body):
            dropped[match.group(1)] = dropped.get(match.group(1), 0) + 1
        return fields
    if entry['record_type'] == 'EXECVE':
        # argv is consumed into `command_line` (attached in _link_argv); only argc is a plain field.
        entry['execve'] = _execve(body, shape)
        _count(counters, 'execve_records')
        if entry['execve'] is None:
            _count(counters, 'execve_unparsed')
        elif entry['execve']['argc'] is not None and 'argc' in allow:
            fields['argc'] = entry['execve']['argc']
        return fields
    if entry['record_type'] == 'PROCTITLE':
        entry['proctitle'] = _proctitle(body, shape)
        _count(counters, 'proctitle_records')
        if entry['proctitle'] is None:
            _count(counters, 'proctitle_unparsed')
        return fields
    tokens = _audit_fields(body, shape, 'dataset.line.%d' % entry['line'])
    for key in sorted(tokens):
        if key not in allow or key in AUDIT_DERIVED:
            dropped[key] = dropped.get(key, 0) + 1
            continue
        value = _audit_value(key, tokens[key][0], tokens[key][1], shape, label + '.' + key, counters)
        fields[key] = _checked(names.transform(allow[key], value, label + '.' + key), label + '.' + key)
    return fields


def _link_argv(entries, spec, counters):
    """Reassemble EXECVE argv per audit event (asset, serial, timestamp) into `command_line` and attach it, and
    the event's PROCTITLE, to the records whose allowlist names them. Byte-identical duplicate EXECVE lines are
    used once; continuation records extend the argv of the first."""
    groups = {}
    for entry in entries:
        if entry['record_type'] in ('EXECVE', 'PROCTITLE') and not entry['metadata_only']:
            groups.setdefault((entry['asset'], entry['record_id'], entry['timestamp_original']), []).append(entry)
    commands, titles = {}, {}
    for key, members in groups.items():
        execs = [e for e in members if e.get('execve')]
        seen, args, argc = set(), {}, None
        for entry in execs:
            if entry['line_sha256'] in seen:
                _count(counters, 'execve_duplicate_records')
                continue
            seen.add(entry['line_sha256'])
            argc = entry['execve']['argc'] if argc is None else argc
            for index, text in entry['execve']['args'].items():
                args.setdefault(index, text)
        if args:
            missing = max(argc or 0, max(args) + 1) - len(args)
            if missing:
                _count(counters, 'execve_missing_args', missing)
            commands[key] = (execs[0]['line'], ' '.join(_shell_word(args[index]) for index in sorted(args)))
            _count(counters, 'command_lines')
        title = next((e['proctitle'] for e in members if e.get('proctitle') is not None), None)
        if title is not None:
            titles[key] = title
    for entry in entries:
        allow = {} if entry['metadata_only'] else spec['record_types'][entry['record_type']]
        key = (entry['asset'], entry['record_id'], entry['timestamp_original'])
        if 'command_line' in allow and key in commands and \
                (entry['record_type'] != 'EXECVE' or entry['line'] == commands[key][0]):
            entry['content_raw']['command_line'] = commands[key][1]
            if entry['record_type'] != 'EXECVE':
                _count(counters, 'command_lines_attached')
        if 'proctitle' in allow:
            title = entry.get('proctitle') if entry['record_type'] == 'PROCTITLE' else titles.get(key)
            if title is not None:
                entry['content_raw']['proctitle'] = title


def _aws_scrub(value, path, names, dropped, top=True):
    """CloudTrail object for content: secret keys dropped (counted), identity keys pseudonymized like the
    structured fields (top-level `name` like `requestParameters.name`). Returns (value, secrets_dropped)."""
    if type(value) is list:
        items = [_aws_scrub(item, path, names, dropped, False) for item in value]
        return [item for item, _ in items], sum(count for _, count in items)
    if type(value) is not dict:
        return value, 0
    out, secrets_dropped = {}, 0
    for key, item in value.items():
        child = path + '.' + key
        folded = key.casefold()
        if folded in SECRET_KEYS:
            dropped[child] = dropped.get(child, 0) + 1
            secrets_dropped += 1
            continue
        transform = AWS_KEY_TRANSFORMS.get(folded) or ('aws-resource' if top and key == 'name' else None)
        if transform and type(item) is str:
            out[key] = names.transform(transform, item, child)
        elif transform and type(item) is list and all(type(part) is str for part in item):
            out[key] = [names.transform(transform, part, child) for part in item]
        else:
            out[key], count = _aws_scrub(item, child, names, dropped, False)
            secrets_dropped += count
    return out, secrets_dropped


def _content_pseudonymizer(names, record_format, asset_tokens):
    """sanitize_text callback: `known:<namespace>` identities reuse the structured pseudonyms; detector kinds map
    onto the same namespaces (a Linux `/home/<name>` user equals the AUID user, an IP equals sourceIPAddress)."""
    def pseudonymize(kind, original):
        folded = original.casefold()
        if kind == 'known:asset':
            return asset_tokens[folded]
        if kind.startswith('known:'):
            token = names.mapping.get(kind[len('known:'):], {}).get(folded)
            if token is not None:
                return token
        if kind == 'ip':
            return names.ip(original)
        if kind == 'user':
            return names.linux_user(original) if record_format == FORMAT_AUDITD else names.user(original)
        if kind in ('domain', 'host'):
            return names.netbios(kind, original)
        if kind == 'dns':
            return names.token('dns', 'dns', original.rstrip('.'))
        if kind == 'sid':
            return names.token('sid', 'sid', original)
        return names.token('value', 'opaque', original)
    return pseudonymize


def _content(value, path, names, record_format, pseudonymize, identities, dropped):
    """One content value -> (sanitized text, sanitizer report, secret keys dropped). CloudTrail objects are
    serialized canonically after the secret-key drop; ARNs and account IDs inside the text get the structured
    pseudonyms before the shared sanitizer runs."""
    secrets_dropped = 0
    if record_format == FORMAT_CLOUDTRAIL:
        if type(value) in (dict, list):
            value, secrets_dropped = _aws_scrub(value, path, names, dropped)
            value = canonical_bytes(value).decode('utf-8')
        value = ARN_IN_TEXT.sub(lambda match: names.aws_arn(match.group(0)), value)
        value = ACCOUNT_IN_TEXT.sub(lambda match: names.aws_account(match.group(0)), value)
    text, report = sanitize_text(value, pseudonymize, max_bytes=CONTENT_MAX_BYTES, identities=identities,
                                 field=path)
    return text, report, secrets_dropped


def _sanitize_content(entries, names, record_format, asset_tokens, dropped):
    """Sanitize every content value. Pass 1 registers the pseudonyms that only content names (ARNs, /home users,
    IPs, ...); pass 2 also replaces every known original as a whole token, so a name first seen in a later record
    is never published raw in an earlier one. Returns {field: totals} and {asset: truncated values}."""
    pseudonymize = _content_pseudonymizer(names, record_format, asset_tokens)
    for entry in entries:
        for name, value in entry['content_raw'].items():
            _content(value, name, names, record_format, pseudonymize, None, {})
    # Each original is matched under its first namespace in IDENTITY_NAMESPACES order (a Linux user that is also
    # its own primary group stays a user pseudonym).
    identities, seen = {}, set()
    for namespace in IDENTITY_NAMESPACES:
        originals = sorted(set(names.mapping.get(namespace, {})) - seen)
        identities['known:' + namespace] = originals
        seen.update(originals)
    identities['known:asset'] = sorted(set(asset_tokens) - seen)
    known = KnownIdentities(identities)
    totals, truncated = {}, {}
    for entry in entries:
        for name, value in sorted(entry['content_raw'].items()):
            text, report, secrets_dropped = _content(value, name, names, record_format, pseudonymize, known, dropped)
            entry['fields'][name] = _checked(text, entry['event_type'] + '.' + name)
            total = totals.setdefault(name, dict(new_totals(), secret_fields_dropped=0))
            merge_reports(total, report)
            total['secret_fields_dropped'] += secrets_dropped
            if report['truncated']:
                truncated[entry['asset']] = truncated.get(entry['asset'], 0) + 1
    return totals, truncated


def _checked(value, field):
    if type(value) is str and ATTACK_TOKEN.search(value):
        _fail('attack_token_in_field', field)
    return value


# ----------------------------------------------------------------- curation

# Curation locators: original line; the export's own record ID alone (CloudTrail eventID, auditd serial; must be
# unique in the export); or the record ID qualified by record type (auditd records of one event share a serial).
_LOCATOR_KEYS = ({'line'}, {'record_id'}, {'record_id', 'record_type'})
_CURATION_KEYS = {'schema_version', 'dataset_sha256', 'metadata_sha256', 'curated_by', 'curated_utc', 'note',
                  'revision', 'truth_revision', 'attack_release', 'clock_declaration', 'coverage', 'assets', 'steps',
                  'edges', 'controls', 'lookalike_event_ids', 'sophistication', 'source_references'}


def load_curation(path):
    """Return (curation, bytes); curation['attestation'] is one of benchmark_contracts.TRUTH_ATTESTATIONS."""
    _, data = _read_regular(path, MAX_SIDE_FILE_BYTES, 'curation')
    value = decode_json(data)
    field = 'curation'
    attestation = _proposal_attestation(value, field)
    _strict(value, _CURATION_KEYS, field,
            {'assessment_windows', 'matched_control', 'family_id', 'partition_window', 'excluded_locators'})
    if value['schema_version'] != 1:
        _fail('unsupported_schema', field + '.schema_version')
    for key in ('dataset_sha256', 'metadata_sha256'):
        if type(value[key]) is not str or not re.fullmatch(r'[0-9a-f]{64}', value[key]):
            _fail('invalid_digest', field + '.' + key)
    _check_curator(value, attestation, field)
    for key in ('revision', 'truth_revision'):
        if type(value[key]) is not int or value[key] < 1:
            _fail('invalid_integer', field + '.' + key)
    if value['clock_declaration'] is not None:
        _strict(value['clock_declaration'], {'offset_seconds', 'uncertainty_seconds'}, field + '.clock_declaration')
        _declared_clock(value['clock_declaration']['offset_seconds'],
                        value['clock_declaration']['uncertainty_seconds'], field + '.clock_declaration')
    if 'partition_window' in value:
        _strict(value['partition_window'], {'start_inclusive', 'end_exclusive'}, field + '.partition_window')
        if not parse_utc(value['partition_window']['start_inclusive'], field + '.partition_window') < \
                parse_utc(value['partition_window']['end_exclusive'], field + '.partition_window'):
            _fail('invalid_window', field + '.partition_window')
    if 'family_id' in value:
        _family_override(value['family_id'], field + '.family_id')
    value['attestation'] = attestation
    return value, data


def _declared_clock(offset, uncertainty, field):
    for item in (offset, uncertainty):
        if type(item) not in (int, float) or not math.isfinite(item):
            _fail('invalid_number', field)
    if abs(offset) > MAX_DECLARED_OFFSET or not 0 <= uncertainty <= MAX_DECLARED_UNCERTAINTY:
        _fail('invalid_number', field)
    return offset, uncertainty


def _family_from_techniques(techniques):
    return 'attackdata-' + '-'.join(t.casefold().replace('.', '-') for t in sorted(set(techniques)))


def _family_override(value, field):
    """A reviewer's family_id: sorted unique technique tokens; `otrf-` joins an OTRF cluster deliberately."""
    if type(value) is not str or not FAMILY_ID.fullmatch(value):
        _fail('invalid_identifier', field)
    prefix, _, rest = value.partition('-')
    tokens = re.findall(r't([0-9]{4})(?:-([0-9]{3}))?', rest)
    expected = prefix + '-' + '-'.join('t' + base + ('-' + sub if sub else '')
                                       for base, sub in sorted(set(tokens), key=lambda t: (t[0], t[1])))
    if expected != value or len(set(tokens)) != len(tokens):
        _fail('invalid_identifier', field)


def _asset_selector(value, assets, field):
    _strict(value, {'asset_name'}, field)
    if type(value['asset_name']) is not str or value['asset_name'].casefold() not in assets:
        _fail('unknown_asset', field)
    return value['asset_name'].casefold()


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
        if 'record_type' in locator:
            if type(locator['record_type']) is not str:
                _fail('invalid_locator', field)
            matches = [e for e in matches if e['record_type'] == locator['record_type']]
        if len(matches) > 1:
            _fail('ambiguous_locator', field)
        entry = matches[0] if matches else None
    if entry is None:
        _fail('unknown_locator', field)
    if entry['status'] != 'imported':
        _fail('support_record_not_imported', field)
    return entry


def _locator_groups(groups, by_line, by_record, field):
    if type(groups) is not list:
        _fail('invalid_array', field)
    result = []
    for group in groups:
        if type(group) is not list or not group:
            _fail('invalid_array', field)
        result.append([_resolve(locator, by_line, by_record, field) for locator in group])
    return result


def _receipt(dataset_sha, file_name, groups):
    lines = [[{'line': entry['line'], 'line_sha256': entry['line_sha256']}
              for entry in sorted(group, key=lambda e: e['line'])] for group in groups]
    return digest_bytes(canonical_bytes({'dataset_sha256': dataset_sha, 'member': file_name,
                                         'support_sets': sorted(lines, key=canonical_bytes)}))


def _check_format_coverage(coverage, record_format):
    if type(coverage) is not dict:
        _fail('invalid_object', 'curation.coverage')
    for axis, values in FORMAT_COVERAGE_EXACT[record_format].items():
        if coverage.get(axis) != values:
            _fail('coverage_format_mismatch', 'curation.coverage.' + axis)
    for axis, value in FORMAT_COVERAGE_REQUIRED[record_format].items():
        if type(coverage.get(axis)) is not list or value not in coverage[axis]:
            _fail('coverage_format_mismatch', 'curation.coverage.' + axis)


# ------------------------------------------------------------------ building

def _clock(shape, declared):
    """Explicit clock: what the export's timestamps mean, the applied offset, and its uncertainty."""
    if shape == SHAPE_AUDIT_INTERPRETED:
        if declared is None:
            _fail('no_clock_reference', 'clock_declaration')
        offset, uncertainty = declared
        return {'offset_seconds': offset, 'uncertainty_seconds': uncertainty + 0.001,
                'basis': 'operator_declared',
                'note': 'ausearch -i local wall clock (MM/DD/YYYY, zone not recorded in the export) corrected by an '
                        'operator-declared offset of %s s (declared uncertainty %s s plus 1 ms resolution); '
                        'host clock synchronization not evidenced' % (offset, uncertainty)}
    if declared is not None:
        _fail('conflicting_arguments', 'clock_declaration')
    if shape == SHAPE_AUDIT_RAW:
        return {'offset_seconds': 0, 'uncertainty_seconds': 0.001, 'basis': 'format_definition',
                'note': 'kernel audit epoch timestamps (UTC by definition, 1 ms resolution); host clock '
                        'synchronization not evidenced'}
    return {'offset_seconds': 0, 'uncertainty_seconds': 1, 'basis': 'format_definition',
            'note': 'CloudTrail eventTime (UTC, whole seconds) as documented by AWS'}


def _line_ranges(lines):
    """Compact sorted original line numbers: [1, 2, 3, 7] -> '1-3, 7'."""
    ranges = []
    for line in sorted(lines):
        if ranges and line == ranges[-1][1] + 1:
            ranges[-1][1] = line
        else:
            ranges.append([line, line])
    return ', '.join(str(a) if a == b else '%d-%d' % (a, b) for a, b in ranges)


def _attack_url(technique):
    return 'https://attack.mitre.org/techniques/' + technique.replace('.', '/') + '/'


def build_case(dataset_path, metadata_path, field_map, salt, curation_path=None, clock=None, coverage=None,
               partition=None):
    """Build every output in memory and validate it; returns (case_id, {relative_path: bytes}).

    `clock` is the draft-mode operator declaration (offset_seconds, uncertainty_seconds) for interpreted auditd
    exports; curated imports take it from the curation's `clock_declaration` instead. `partition` is an explicit
    (start_inclusive, end_exclusive) UTC window applied to normalized time: every record outside it is excluded
    and stated as a known gap; nothing inside it is ever sampled away. A curated import must declare the same
    window as `partition_window`.
    """
    if partition is not None:
        if type(partition) not in (tuple, list) or len(partition) != 2:
            _fail('invalid_window', 'partition')
        partition = tuple(parse_utc(item, 'partition') if type(item) is str else item for item in partition)
        if not partition[0] < partition[1]:
            _fail('invalid_window', 'partition')
    input_path, input_bytes = read_dataset(dataset_path)
    _, metadata_bytes = _read_regular(metadata_path, MAX_METADATA_BYTES, 'metadata')
    metadata = parse_metadata_yaml(metadata_bytes)
    declared, record_format = _bind_metadata(metadata, input_path.name)
    dataset_sha, metadata_sha = digest_bytes(input_bytes), digest_bytes(metadata_bytes)
    curation = curation_bytes = None
    if curation_path is not None:
        if clock is not None:
            _fail('conflicting_arguments', 'clock')
        curation, curation_bytes = load_curation(curation_path)
        if curation['dataset_sha256'] != dataset_sha or curation['metadata_sha256'] != metadata_sha:
            _fail('curation_dataset_mismatch', 'curation')
        clock_declaration = curation['clock_declaration']
        declared_clock = None if clock_declaration is None else (clock_declaration['offset_seconds'],
                                                                  clock_declaration['uncertainty_seconds'])
        declared_partition = curation.get('partition_window')
        if (declared_partition is None) != (partition is None) or (partition is not None and (
                parse_utc(declared_partition['start_inclusive'], 'curation.partition_window') != partition[0] or
                parse_utc(declared_partition['end_exclusive'], 'curation.partition_window') != partition[1])):
            _fail('partition_mismatch', 'curation.partition_window')
    else:
        declared_clock = None if clock is None else _declared_clock(clock[0], clock[1], 'clock')

    spec = field_map['formats'][record_format]
    entries, shape = parse_records(input_bytes, record_format, field_map)
    clock_info = _clock(shape, declared_clock)
    with_records = [e for e in entries if 'record_type' in e]
    if declared_clock is not None:
        shift = timedelta(seconds=declared_clock[0])
        for entry in with_records:
            entry['time'] = entry['time'] - shift
    nodes = {e['node'] for e in with_records}
    if record_format == FORMAT_AUDITD:
        if None in nodes and len(nodes) > 1:
            _fail('mixed_node_attribution', 'dataset.node')
        for entry in with_records:
            entry['asset'] = (entry['node'] or AUDIT_HOST).casefold()
    else:
        for entry in with_records:
            entry['asset'] = entry['node']
    all_records = with_records
    excluded = []
    if partition is not None:
        for entry in all_records:
            if not partition[0] <= entry['time'] < partition[1]:
                entry['status'] = 'outside_partition_window'
                excluded.append(entry)
        with_records = [e for e in all_records if e['status'] != 'outside_partition_window']
        if not any(e['status'] == 'imported' for e in with_records):
            _fail('no_supported_records', 'partition')
    asset_names = sorted({e['asset'] for e in with_records})
    names = AttackDataPseudonyms(salt)
    if partition is None:
        stamps = [e['time'] for e in with_records]
        outer = (min(stamps).replace(microsecond=0), max(stamps).replace(microsecond=0) + timedelta(seconds=1))
        case_key = 'case\x00' + dataset_sha
    else:
        # The declared partition is the observation window of the case.
        outer = partition
        case_key = 'case\x00' + dataset_sha + '\x00' + _utc_text(partition[0]) + '\x00' + _utc_text(partition[1])
    window = _normal_window(outer)
    case_id = 'case-' + hmac.new(salt, case_key.encode('utf-8'), hashlib.sha256).hexdigest()[:16]

    # Assets: explicit facts from curation, or the format-determined OS family for a draft.
    os_family = FORMAT_OS[record_format]
    if curation is not None:
        facts = {}
        if type(curation['assets']) is not list:
            _fail('invalid_array', 'curation.assets')
        for item in curation['assets']:
            _strict(item, {'asset_name', 'os_family', 'os_version', 'architecture', 'vendor'}, 'curation.assets')
            if type(item['asset_name']) is not str or item['asset_name'].casefold() in facts:
                _fail('duplicate_item', 'curation.assets')
            if item['os_family'] != os_family:
                _fail('asset_format_mismatch', 'curation.assets.os_family')
            for key in ('os_version', 'architecture', 'vendor'):
                _text(item[key], 'curation.assets.' + key, True)
            facts[item['asset_name'].casefold()] = item
        if set(facts) != set(asset_names):
            _fail('curation_assets_mismatch', 'curation.assets')
    else:
        facts = {name: {'os_family': os_family, 'os_version': None, 'architecture': None, 'vendor': None}
                 for name in asset_names}
    asset_ids = {name: names.token('asset', 'asset', name) for name in asset_names}
    assets = sorted(({'asset_id': asset_ids[name], 'os_family': facts[name]['os_family'],
                      'os_version': facts[name]['os_version'], 'architecture': facts[name]['architecture'],
                      'vendor': facts[name]['vendor']} for name in asset_names), key=lambda a: a['asset_id'])

    # Events: allowlisted fields only, pseudonymized, original + normalized times. Unknown record types are
    # metadata-only events.
    dropped, counters, imported_counts, metadata_only_counts = {}, {}, {}, {}
    events, source_keys = [], {}
    for entry in with_records:
        type_key = spec['source'] + ':' + entry['record_type']
        imported_counts[type_key] = imported_counts.get(type_key, 0) + 1
        if entry['metadata_only']:
            metadata_only_counts[type_key] = metadata_only_counts.get(type_key, 0) + 1
        fields = _public_fields(entry, spec, names, shape, counters, dropped)
        entry['fields'], entry['event_type'] = fields, type_key
        source_key = (spec['source'], entry['asset'])
        if source_key not in source_keys:
            source_keys[source_key] = names.token('source', 'source', spec['source'] + '|' + entry['asset'])
        entry['event_id_public'] = names.token('event', 'event', str(entry['line']))
        events.append({'event_id': entry['event_id_public'], 'timestamp_utc': _utc_text(entry['time']),
                       'source_id': source_keys[source_key], 'asset_id': asset_ids[entry['asset']],
                       'event_type': type_key, 'fields': fields})
    events.sort(key=lambda e: (e['timestamp_utc'], e['event_id']))

    # Content fields, after every structured pseudonym exists. auditd node names inside content become the asset
    # pseudonym (the placeholder host has no name to hide).
    if record_format == FORMAT_AUDITD:
        _link_argv(with_records, spec, counters)
    asset_tokens = {}
    if record_format == FORMAT_AUDITD:
        for name in asset_names:
            if name != AUDIT_HOST:
                asset_tokens[name] = asset_ids[name]
                asset_tokens.setdefault(name.split('.', 1)[0], asset_ids[name])
    content_totals, truncated = _sanitize_content([e for e in with_records if e['content_raw']], names,
                                                  record_format, asset_tokens, dropped)

    # records.jsonl mirrors the ORIGINAL line structure: line N is original line N.
    by_event = {e['event_id']: e for e in events}
    imported = [e for e in entries if e['status'] == 'imported']
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

    # Sources and explicit gaps. Every attack_data file is a dataset-author extract of the original log.
    sources, gaps = [], []
    for (source, asset), source_id in sorted(source_keys.items(), key=lambda item: item[1]):
        sources.append({'source_id': source_id, 'asset_ids': [asset_ids[asset]], 'telemetry': spec['telemetry'],
                        'clock_offset_seconds': clock_info['offset_seconds'],
                        'clock_uncertainty_seconds': clock_info['uncertainty_seconds'],
                        'window_utc': window, 'sensor_version': None, 'config_version': clock_info['note'],
                        'completeness': 'unknown', 'source_sha256': records_sha})
        gaps.append({'source_id': source_id, 'asset_id': asset_ids[asset], 'window_utc': window,
                     'reason': 'The published file is an extract selected from the original log; the selection '
                               'criteria are not recorded, so a missing record is not evidence that the activity '
                               'did not occur.'})
        if truncated.get(asset):
            gaps.append({'source_id': source_id, 'asset_id': asset_ids[asset], 'window_utc': window,
                         'reason': 'content_truncated: %d content values exceeded %d UTF-8 bytes after sanitizing '
                                   'and end with an explicit truncation marker' % (truncated[asset],
                                                                                   CONTENT_MAX_BYTES)})
    # Partition: every excluded original line is stated, grouped by asset, never silently dropped.
    partition_info = None
    if partition is not None:
        by_asset = {}
        for entry in excluded:
            by_asset.setdefault(entry['asset'], []).append(entry['line'])
        for asset, excluded_lines in sorted(by_asset.items()):
            public_asset = asset_ids.get(asset)
            gaps.append({'source_id': source_keys.get((spec['source'], asset)) if public_asset else None,
                         'asset_id': public_asset, 'window_utc': window,
                         'reason': 'outside_partition_window: %d records outside the declared partition window were '
                                   'excluded (original lines %s); records.jsonl keeps a stub at each original line'
                                   % (len(excluded_lines), _line_ranges(excluded_lines))})
        partition_info = {'window_utc': window, 'excluded_records': len(excluded),
                          'excluded_line_ranges': _line_ranges([e['line'] for e in excluded]) or None}
    gaps.sort(key=lambda g: (g['asset_id'] or '', g['source_id'] or '', g['reason']))

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
            questions.append({'question_id': names.token('question', 'question',
                                                         asset['asset_id'] + canonical_bytes(normal).decode('utf-8')),
                              'asset_id': asset['asset_id'], 'window_utc': normal, 'question': ASSESSMENT_QUESTION})
    questions.sort(key=lambda q: q['question_id'])

    bundle = {'schema_version': 1, 'case_id': case_id, 'window_utc': window, 'assets': assets,
              'sources': sources, 'events': events, 'known_gaps': gaps,
              'files': [{'path': 'records.jsonl', 'byte_count': len(records), 'sha256': records_sha}],
              'assessment_questions': questions}
    validate_public_bundle(bundle)
    public_bytes = canonical_bytes(bundle)
    _leak_check(public_bytes + records, metadata, input_path.name, names,
                {e['node'].casefold() for e in all_records if e['node']})
    manifest_sha = digest_bytes(public_bytes)

    by_line = {e['line']: e for e in entries}
    by_record = {}
    for entry in all_records:
        by_record.setdefault(entry['record_id'], []).append(entry)
    locators = {'schema_version': 1, 'dataset_sha256': dataset_sha, 'file': input_path.name,
                'records_sha256': records_sha, 'record_shape': shape,
                'events': {e['event_id_public']: {'line': e['line'], 'line_sha256': e['line_sha256'],
                                                  'record_id': e['record_id'], 'record_type': e['record_type'],
                                                  'asset_name': e['asset']}
                           for e in imported}}
    report = {'schema_version': 1, 'importer_version': IMPORTER_VERSION,
              'status': 'curated' if curation is not None else DRAFT_MARKER,
              'split': 'development', 'provenance': 'public_replay',
              'dataset': {'file': input_path.name, 'sha256': dataset_sha, 'byte_count': len(input_bytes),
                          'declared_path': declared['path'], 'declared_name': declared['name'],
                          'sourcetype': declared['sourcetype'], 'source': declared['source']},
              'metadata': {'file_sha256': metadata_sha, 'id': metadata['id'], 'date': metadata['date'],
                           'environment': metadata['environment'], 'directory': metadata['directory'],
                           'declared_techniques': metadata['techniques']},
              'field_map': {'version': field_map['version'], 'sha256': field_map['sha256']},
              'partition': partition_info,
              'record_format': {'format': record_format, 'shape': shape, 'record_id_field':
                                'eventID' if shape == SHAPE_CLOUDTRAIL else 'audit serial',
                                'hex_decoded_values': counters.get('hex_decoded_values', 0),
                                'argv': {key: counters.get(key, 0) for key in (
                                    'execve_records', 'execve_unparsed', 'execve_duplicate_records',
                                    'execve_missing_args', 'command_lines', 'command_lines_attached',
                                    'proctitle_records', 'proctitle_unparsed')} if shape != SHAPE_CLOUDTRAIL else None,
                                'asset_attribution': 'recipientAccountId' if shape == SHAPE_CLOUDTRAIL else
                                                     ('node' if None not in nodes else
                                                      'single host (no node= prefix; name "%s" is a placeholder)'
                                                      % AUDIT_HOST)},
              'license': LICENSE,
              'contamination': 'Public dataset; likely present in model training data. Development split only; '
                               'never holdout.',
              'assumptions': {'clock': clock_info,
                              'asset_facts': 'curation file' if curation is not None else
                                             'format-determined OS family only; version/architecture/vendor unknown'},
              'counts': {'original_lines': len(entries), 'imported_events': len(events),
                         'not_imported': {status: sum(1 for e in entries if e['status'] == status)
                                          for status in ('blank_line', 'outside_partition_window')},
                         'imported_by_type': dict(sorted(imported_counts.items())),
                         'metadata_only_by_type': dict(sorted(metadata_only_counts.items())),
                         'content': {name: content_totals[name] for name in sorted(content_totals)},
                         'dropped_fields': dict(sorted(dropped.items())),
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
            _template(metadata, record_format, dataset_sha, metadata_sha, asset_names, imported, by_event, window,
                      declared_clock, partition_info))
        report['counts']['steps'] = 0
        outputs['evaluator/import-report.json'] = canonical_bytes(report)
        return case_id, outputs

    truth, scenario, curated = _curated(curation, metadata, declared, record_format, bundle, events, by_line,
                                        by_record, asset_names, asset_ids, outer, dataset_sha, input_path.name,
                                        coverage, partition_info)
    report['curation'] = dict(curated, sha256=digest_bytes(curation_bytes))
    report['counts']['steps'] = len(truth['steps'])
    outputs['evaluator/truth.json'] = canonical_bytes(truth)
    outputs['evaluator/curation.json'] = curation_bytes
    outputs['scenario.json'] = canonical_bytes(scenario)
    outputs['evaluator/import-report.json'] = canonical_bytes(report)
    return case_id, outputs


def _leak_check(public, metadata, input_name, names, nodes):
    """Refuse public output that still names the dataset, its labels or raw identifiers."""
    folded = TOKEN_FORM.sub(' ', public.decode('utf-8').casefold())
    needles = {metadata['id'], input_name.rsplit('.', 1)[0].casefold()}
    if metadata['directory']:
        needles.add(metadata['directory'].casefold())
    for entry in metadata['datasets']:
        needles.update({entry['name'].casefold(), entry['basename'].rsplit('.', 1)[0].casefold()})
    if any(len(needle) >= 6 and needle in folded for needle in needles):
        _fail('forbidden_public_metadata', 'public_bundle')
    originals = set(nodes) | {node.split('.', 1)[0] for node in nodes}
    for namespace in ('user', 'group', 'netbios', 'dns', 'ip', 'opaque', 'segment', 'account', 'principal',
                      'role', 'resource', 'key'):
        originals.update(names.mapping.get(namespace, {}))
    for original in originals:
        if len(original) >= 4 and re.search(r'(?<![a-z0-9])' + re.escape(original) + r'(?![a-z0-9])', folded):
            _fail('pseudonymization_leak', 'public_bundle')


def _template(metadata, record_format, dataset_sha, metadata_sha, asset_names, imported, by_event, window,
              declared_clock, partition_info):
    candidates = []
    for entry in sorted(imported, key=lambda e: (e['time'], e['line'])):
        event = by_event[entry['event_id_public']]
        candidates.append({'line': entry['line'], 'record_id': entry['record_id'], 'record_type': entry['record_type'],
                           'event_id': event['event_id'], 'asset_name': entry['asset'],
                           'timestamp_utc': event['timestamp_utc'], 'event_type': event['event_type'],
                           'fields': event['fields']})
    steps = [{'step_id': 'step-%d' % (index + 1), 'technique_id': technique,
              'asset': {'asset_name': asset_names[0]}, 'window_utc': window,
              'execution_outcome': None, 'observability': None, 'support_sets': [],
              'boundary_id': 'boundary-host', 'phase': 'initial'}
             for index, technique in enumerate(metadata['techniques'])]
    coverage = {axis: [] for axis in COVERAGE_AXES}
    coverage.update({axis: list(values) for axis, values in FORMAT_COVERAGE_EXACT[record_format].items()})
    for axis, value in FORMAT_COVERAGE_REQUIRED[record_format].items():
        coverage[axis] = [value]
    return {
        'NOT_VALID_FOR_SCORING': 'Curation template. Every null and empty list must be decided by a human '
                                 'curator from the original records. Nothing here is truth.',
        'instructions': [
            'Copy "curation" to a new file and fill it in; do not edit this template in place.',
            'Each support set lists original records that TOGETHER prove the step: {"line": N}, or '
            '{"record_id": "ID"} when that CloudTrail eventID / auditd serial is unique in the export, or '
            '{"record_id": "ID", "record_type": "SYSCALL"}.',
            'Coverage os/telemetry are fixed by the record format; the other axes must be decided.',
            'clock_declaration is the operator clock assumption for interpreted (ausearch -i) auditd exports and '
            'null for every other shape; it must equal the draft declaration to keep timestamps stable.',
            'Optional "family_id" overrides the metadata-derived bootstrap family (attackdata-<sorted technique '
            'tokens>), or joins an OTRF cluster (otrf-...) deliberately.',
            'Candidate events are ALL imported events; no heuristic selection was applied.',
            'Questions without a step must be covered by a control (benign or insufficient).',
            'lookalike_event_ids holds groups of original-line locators for curator-validated benign lookalikes.',
            'Re-run the importer with --curation and the same --salt-file to keep event/asset IDs stable.'],
        'declared_techniques': metadata['techniques'],
        'candidate_events': candidates,
        'asset_names': asset_names,
        'curation': {
            'schema_version': 1, 'dataset_sha256': dataset_sha, 'metadata_sha256': metadata_sha,
            'curated_by': None, 'curated_utc': None, 'note': None, 'revision': 1, 'truth_revision': 1,
            'attack_release': None,
            'clock_declaration': None if declared_clock is None else
            {'offset_seconds': declared_clock[0], 'uncertainty_seconds': declared_clock[1]},
            'coverage': coverage,
            'assets': [{'asset_name': name, 'os_family': FORMAT_OS[record_format], 'os_version': None,
                        'architecture': None, 'vendor': None} for name in asset_names],
            'steps': steps, 'edges': [], 'controls': [], 'lookalike_event_ids': [],
            'sophistication': {'band': None, 'boundaries': [{'boundary_id': 'boundary-host', 'kind': 'host'}],
                               'preconditions': [], 'emulation_limitations': [], 'group_ids': [],
                               'source_references': []},
            'source_references': [],
            'assessment_windows': [window],
            **({} if partition_info is None else {'partition_window': partition_info['window_utc']})}}


def _curated(curation, metadata, declared, record_format, bundle, events, by_line, by_record, asset_names,
             asset_ids, outer, dataset_sha, file_name, coverage, partition_info):
    field = 'curation'
    _check_format_coverage(curation['coverage'], record_format)
    if type(curation['steps']) is not list:
        _fail('invalid_array', field + '.steps')
    steps, step_assets, sophistication_steps = [], {}, []
    for item in curation['steps']:
        _strict(item, {'step_id', 'technique_id', 'asset', 'window_utc', 'execution_outcome',
                       'observability', 'support_sets', 'boundary_id', 'phase'}, field + '.steps')
        name = _asset_selector(item['asset'], asset_names, field + '.steps.asset')
        window = _window_tuple(item['window_utc'], field + '.steps.window_utc', outer)
        groups = _locator_groups(item['support_sets'], by_line, by_record, field + '.steps.support_sets')
        steps.append({'step_id': item['step_id'], 'technique_id': item['technique_id'],
                      'asset_id': asset_ids[name], 'window_utc': _normal_window(window),
                      'execution_outcome': item['execution_outcome'], 'observability': item['observability'],
                      'support_sets': [sorted({e['event_id_public'] for e in group}) for group in groups],
                      'source_receipt_sha256': _receipt(dataset_sha, file_name, groups)})
        step_assets[item['step_id']] = (asset_ids[name], window, item['observability'])
        sophistication_steps.append({'step_id': item['step_id'], 'asset_id': asset_ids[name],
                                     'boundary_id': item['boundary_id'], 'phase': item['phase']})
    if type(curation['controls']) is not list:
        _fail('invalid_array', field + '.controls')
    controls = []
    for item in curation['controls']:
        _strict(item, {'control_id', 'asset', 'window_utc', 'expected_disposition'}, field + '.controls')
        name = _asset_selector(item['asset'], asset_names, field + '.controls.asset')
        window = _window_tuple(item['window_utc'], field + '.controls.window_utc', outer)
        controls.append({'control_id': item['control_id'], 'asset_id': asset_ids[name],
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
    references = curation['source_references']
    if type(references) is not list or not references or not all(type(r) is str for r in references):
        _fail('invalid_array', field + '.source_references')
    techniques = metadata['techniques']
    derived_family = _family_from_techniques(techniques)
    family = curation.get('family_id', derived_family)
    slug = re.sub(r'[^a-z0-9_-]+', '-', declared['name'].casefold()).strip('-_')[:60] or 'dataset'
    limitations = soph['emulation_limitations']
    if type(limitations) is not list:
        _fail('invalid_array', field + '.sophistication.emulation_limitations')
    if partition_info is not None:
        # Partitions of one dataset keep its family_id: they are never independent attacks.
        slug += '-p' + digest_bytes(canonical_bytes(partition_info['window_utc']))[:12]
        limitations = limitations + ['Derived partition %s to %s of the published recording; %d records outside it '
                                     'are excluded and stated as an outside_partition_window known gap.'
                                     % (partition_info['window_utc']['start_inclusive'],
                                        partition_info['window_utc']['end_exclusive'],
                                        partition_info['excluded_records'])]
    limitations = _limitations(limitations, curation['attestation'], field + '.sophistication.emulation_limitations')
    scenario = {
        'schema_version': 1, 'scenario_id': 'attackdata-' + metadata['id'] + '-' + slug,
        'family_id': family,
        'revision': curation['revision'], 'split': 'development', 'provenance': 'public_replay',
        'coverage': curation['coverage'], 'difficulty': difficulty,
        'sophistication': {'band': soph['band'], 'steps': sophistication_steps, 'edges': curation['edges'],
                           'preconditions': soph['preconditions'], 'boundaries': soph['boundaries'],
                           'emulation_limitations': limitations,
                           'group_ids': soph['group_ids'], 'source_references': soph['source_references']},
        'attack_release': curation['attack_release'],
        'source_references': sorted(set(references) | {_attack_url(t) for t in techniques} |
                                    {_attack_url(s['technique_id']) for s in steps}),
        'evidence_manifest_sha256': truth['evidence_manifest_sha256']}
    validate_scenario(scenario, coverage if coverage is not None else load_json(DEFAULT_COVERAGE))
    undeclared = sorted({s['technique_id'] for s in steps} - set(techniques))
    curated.update({'curated_by': curation['curated_by'], 'curated_utc': curation['curated_utc'],
                    'note': curation['note'], 'attestation': curation['attestation'],
                    'undeclared_step_techniques': undeclared,
                    'clock_declaration': curation['clock_declaration'],
                    'family_id': {'value': family, 'metadata_derived': derived_family,
                                  'source': 'curation_override' if 'family_id' in curation else 'metadata'}})
    return truth, scenario, curated


# -------------------------------------------------------------------- output

def main(argv=None):
    parser = argparse.ArgumentParser(description='Import a Splunk attack_data Linux auditd or AWS CloudTrail '
                                                 'export as a DEVELOPMENT benchmark case (public_replay).')
    parser.add_argument('--dataset', required=True, help='attack_data .log (auditd) or .json (CloudTrail) file')
    parser.add_argument('--metadata', required=True, help='the dataset YAML that declares this file')
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--curation', help='human-written curation JSON (truth source)')
    mode.add_argument('--draft', action='store_true',
                      help='no curation: emit a draft (NOT VALID FOR SCORING) and a curation template')
    parser.add_argument('--output', required=True, help='NEW directory; must not exist')
    parser.add_argument('--salt-file', help='evaluator/salt.json from an earlier import (stable IDs)')
    parser.add_argument('--fields', default=str(DEFAULT_FIELDS), help='field allowlist JSON')
    parser.add_argument('--coverage', default=str(DEFAULT_COVERAGE), help='coverage catalog JSON')
    parser.add_argument('--clock-offset-seconds', type=float,
                        help='draft only, interpreted auditd only: local wall clock minus UTC (recorded as an '
                             'operator assumption and copied into the curation template)')
    parser.add_argument('--clock-uncertainty-seconds', type=float,
                        help='draft only, with --clock-offset-seconds: uncertainty of that declaration')
    parser.add_argument('--window-start', help='partition start (UTC with offset, inclusive) on normalized time')
    parser.add_argument('--window-end', help='partition end (UTC with offset, exclusive); records outside the '
                                             'window are excluded and stated as a known gap; a curated import '
                                             'must declare the same partition_window')
    args = parser.parse_args(argv)
    try:
        if (args.clock_offset_seconds is None) != (args.clock_uncertainty_seconds is None):
            _fail('conflicting_arguments', 'clock')
        clock = None if args.clock_offset_seconds is None else (args.clock_offset_seconds,
                                                                args.clock_uncertainty_seconds)
        if (args.window_start is None) != (args.window_end is None):
            _fail('conflicting_arguments', 'partition')
        partition = None if args.window_start is None else (args.window_start, args.window_end)
        salt = load_salt(args.salt_file) if args.salt_file else secrets.token_bytes(SALT_BYTES)
        field_map = load_field_map(args.fields)
        coverage = load_json(args.coverage) if args.curation else None
        case_id, outputs = build_case(args.dataset, args.metadata, field_map, salt, curation_path=args.curation,
                                      clock=clock, coverage=coverage, partition=partition)
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

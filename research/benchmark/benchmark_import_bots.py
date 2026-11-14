"""Import Splunk Boss of the SOC (BOTS v1, v2, v3) exports as DEVELOPMENT benchmark cases.

BOTS v1/v2/v3 are public, CC0-1.0 Splunk index exports of multi-host SOC exercises (Windows endpoints and servers,
Linux and AWS hosts, network sensors, firewalls, SaaS audit logs). The data was exported once, SIEM-agnostically;
Splunk is not used again. Layouts (inspected 2026-11-08):

- v1: `json/botsv1.<sourcetype>.json.gz`, Splunk search-export JSON lines `{"preview", "offset", "result": {..., "_raw",
  "_time", "host", "source", "sourcetype"}}`, one sourcetype per file, records in non-increasing `_time` order, `_time`
  rendered `YYYY-MM-DD HH:MM:SS.mmm MDT`; the last line may be a `{"preview":false,"lastrow":true}` marker.
- v2/v3: `botsv<N>-export/db_<latest>_<earliest>_<id>.csv.gz`, `splunk cmd exporttool -csv` buckets with the columns
  `_time` (UTC epoch), `source::…`, `host::…`, `sourcetype::…`, `_raw`, `_meta`; every row's `_time` lies inside the
  bucket's `[earliest, latest]` range from its file name.

`_time` (the time Splunk assigned to the record) is the event time; everything else is parsed from `_raw` per
sourcetype (`benchmarks/importers/bots-fields.json`). Unknown sourcetypes, and records whose `_raw` does not parse,
become metadata-only events. Content fields pass `benchmark_sanitize.sanitize_text`; identities are the OTRF/attack_data
HMAC pseudonyms (`AttackDataPseudonyms`); CloudTrail uses the attack_data allowlist and object handling.

Subcommands (exit 0 success, 2 validation failure `error: <code>: <field>`; values from the data are never echoed):

- `plan`: scan one explicit UTC window under a declared collection profile (`--host`, `--sourcetype` or
  `--exclude-sourcetype`) and split it into the fewest contiguous whole-second partitions whose prompt projection fits
  the 1 MiB cap; seconds too large to publish alone are listed as `unpublishable`. Imports nothing.
- `case`: import one partition window as a draft (`--draft`) or with a curation (`--curation`) into a NEW directory.

Every case is `split: development`, `provenance: public_replay`: BOTS answers are public and models were likely
trained on them. Python 3.9 standard library only. Nothing in the data is executed, followed or fetched.
"""

import argparse
import csv
import gzip
import hashlib
import hmac
import ipaddress
import json
import math
import os
import re
import secrets
import sys
import urllib.parse
import xml.etree.ElementTree as ElementTree
from datetime import datetime, timedelta, timezone
from pathlib import Path

import benchmark_paths  # noqa: F401
import benchmark_import_attackdata as attackdata
import benchmark_import_otrf as otrf
from benchmark_contracts import (ASSESSMENT_QUESTION, COVERAGE_AXES, MAX_BYTES, BenchmarkError, canonical_bytes,
                                 decode_json, digest_bytes, load_json, validate_public_bundle)
from benchmark_sanitize import (ENCODED_PAYLOAD_MODES, MAX_CONTENT_BYTES, KnownIdentities, merge_reports, new_totals,
                                sanitize_text, scan_leaks)

IMPORTER_VERSION = 'bots-import-1'
HERE = Path(__file__).resolve().parent
DEFAULT_FIELDS = HERE / 'benchmarks' / 'importers' / 'bots-fields.json'
DEFAULT_COVERAGE = HERE / 'benchmarks' / 'coverage.json'
MAX_PUBLIC_BYTES = MAX_BYTES
MAX_SIDE_FILE_BYTES = 4 * 1024 * 1024
MAX_RECORD_BYTES = 8 * 1024 * 1024
# A window holding more records than this (after the profile) is refused: choose a narrower window or profile.
MAX_WINDOW_RECORDS = 2000000
MAX_KEEP_CHARS = 4096
MAX_CONTENT_PASSES = 4
# Global record number ("line") = file number (1-based, sorted file names) * LINE_STRIDE + record ordinal in the file.
LINE_STRIDE = 100000000
VERSIONS = {
    'v1': {'folder': 'json', 'pattern': re.compile(r'botsv1\.[A-Za-z0-9._-]+\.json\.gz\Z'), 'format': 'search-json'},
    'v2': {'folder': 'botsv2-export', 'pattern': re.compile(r'db_([0-9]{9,11})_([0-9]{9,11})_[0-9]{1,6}\.csv\.gz\Z'),
           'format': 'exporttool-csv'},
    'v3': {'folder': 'botsv3-export', 'pattern': re.compile(r'db_([0-9]{9,11})_([0-9]{9,11})_[0-9]{1,6}\.csv\.gz\Z'),
           'format': 'exporttool-csv'},
}
# exporttool bucket names carry `db_<latest>_<earliest>_<id>`. Measured 2026-11-08 over every row of all 16 v3 and 49
# v2 buckets: no row precedes `earliest`; rows of the 31 v2 daily noise buckets run up to 3599 s past `latest`. Buckets
# are skipped only outside [earliest, latest + this slack]; a row of a read bucket outside it is refused.
BUCKET_SLACK_SECONDS = 3600
CSV_HEADER = ['_time', 'source', 'host', 'sourcetype', '_raw', '_meta']
# Zone abbreviations the v1 search export renders `_time` with (August 2016: MDT).
V1_ZONES = {'MDT': -6, 'MST': -7, 'UTC': 0, 'GMT': 0}
V1_TIME = re.compile(r'([0-9]{4})-([0-9]{2})-([0-9]{2}) ([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]{1,6}))? ([A-Z]{3})\Z')
V1_TIME_BYTES = re.compile(rb'"_time": ?"([^"\\]{10,40})"')
EPOCH = re.compile(r'[0-9]{9,11}(?:\.[0-9]{1,6})?\Z')
INCIDENT = re.compile(r'[a-z0-9][a-z0-9-]{0,39}\Z')
SURROGATES = re.compile('[\udc80-\udcff]')
LICENSE = ('Splunk Boss of the SOC (https://github.com/splunk/botsv1, botsv2, botsv3): CC0-1.0 (official/LICENSE in '
           'the data directory). Imported cases are modified derivatives (filtered, parsed, pseudonymized).')
CONTAMINATION = ('Public dataset with many public write-ups and answer walkthroughs; very likely present in model '
                 'training data. Development split only; never holdout.')
BACKGROUND_LIMITATION = {
    'v1': ('BOTS v1 background is generated noise (about 1,757 synthetic Windows hosts, sensors replaying traffic all '
           'month); it is labelled as such and is not real-user activity.'),
    'v2': ('BOTS v2 background includes generated daily template noise attributed to the real host names; it is not '
           'real-user activity.'),
    'v3': None,
}
SOURCE_REFERENCES = {'v1': 'https://github.com/splunk/botsv1', 'v2': 'https://github.com/splunk/botsv2',
                     'v3': 'https://github.com/splunk/botsv3'}
FORBIDDEN_PUBLIC = ('botsv1', 'botsv2', 'botsv3', 'boss of the soc')

TRANSFORMS = tuple(sorted(set(otrf.TRANSFORMS) | set(attackdata.TRANSFORMS)))
OTRF_STRUCTURED = frozenset({'basename', 'path', 'account', 'user', 'domain', 'host', 'guid', 'ip', 'dns', 'opaque'})
# Pseudonym namespaces whose originals are replaced inside content and kept text and refused by the leak check.
PLAIN_NAMESPACES = ('user', 'netbios', 'dns', 'ip', 'guid', 'opaque', 'sid')
KNOWN_NAMESPACES = ('account', 'principal', 'role', 'resource', 'key', 'group', 'segment')
TOKEN_FORM = re.compile(r'(?<![a-z0-9])(?:asset|source|event|question|user|group|host|domain|sid|guid|dns|ipv4|ipv6|'
                        r'addr|segment|value|account|principal|role|resource|key)-[0-9a-f]{16}')
# Distribution and package service accounts (passwd entries every Linux/macOS host carries, named after their own
# software and home paths): Windows-constant-like, never identities. Lab-created accounts are not listed.
SYSTEM_ACCOUNTS = frozenset({
    'root', 'bin', 'daemon', 'adm', 'lp', 'sync', 'shutdown', 'halt', 'mail', 'news', 'uucp', 'operator', 'games',
    'gopher', 'ftp', 'nobody', 'nfsnobody', 'dbus', 'rpc', 'rpcuser', 'ntp', 'sshd', 'postfix', 'saslauth', 'mailnull',
    'smmsp', 'apache', 'nginx', 'www-data', 'mysql', 'postgres', 'tcpdump', 'avahi', 'haldaemon', 'vcsa', 'abrt',
    'nscd', 'polkitd', 'systemd-network', 'systemd-resolve', 'systemd-timesync', 'syslog', 'messagebus', 'sys',
    'man', 'proxy', 'backup', 'list', 'irc', 'gnats', 'uuidd', 'landscape', 'pollinate', 'chrony', 'libstoragemgmt',
    'ec2-user', 'streamfwd', '_mysql', 'memcached', 'ossec', 'osquery', 'http', 'https', 'www',
    'admin', 'administrator'})
WINDOWS_CONSTANT_DOMAINS = frozenset({'builtin', 'nt authority', 'nt service', 'mandatory label', 'window manager',
                                      'font driver host', 'iis apppool', 'nt virtual machine', 'application package '
                                      'authority'})
# A single-label AWS service principal or endpoint (`autoscaling.amazonaws.com`): AWS-owned names the leak check skips;
# bucket hostnames (`<bucket>.s3.amazonaws.com`) have two labels and stay checked.
AWS_SERVICE_TEXT = re.compile(r'(?<![a-z0-9.-])[a-z0-9-]+\.amazonaws\.com(?![a-z0-9.-])')
PARSERS = ('winevent-classic', 'winevent-xml', 'json', 'kv', 'syslog', 'cisco-asa', 'columns', 'auditd', 'text',
           'metadata')
SPEC_KEYS = {'parser', 'source', 'telemetry', 'os', 'aws', 'type_field', 'record_id_field', 'events', 'metadata_only',
             'events_from', 'columns', 'split', 'strip_prefix', 'type_index', 'hex_argv'}
EVENTS_FROM = re.compile(r'(otrf|attackdata):([A-Za-z0-9 /._-]{1,96})\Z')
# `hex_argv`: json-parser field paths holding an audit-style argv (quoted words, hex-encoded words with spaces).
FIELD_NAME = re.compile(r'[A-Za-z0-9_@(][^\x00-\x1f]{0,127}\Z')
OS_HINTS = {'windows': 'windows-client', 'linux': 'linux', 'network': 'network-os', 'cloud': 'not-applicable',
            'macos': 'macos'}
ATTACK_TOKEN = otrf.ATTACK_TOKEN
AWS_SID = re.compile(r'(?i)S-1-12-1(?:-[0-9]+){4}\Z')


def _fail(code, field):
    raise BenchmarkError(code, field)


class _Unparsed(Exception):
    """A record whose `_raw` does not match its sourcetype's parser: it becomes a metadata-only event."""


# ----------------------------------------------------------------- field map

def load_field_map(path=DEFAULT_FIELDS):
    """Load and check `bots-fields.json`; `events_from` entries are resolved against the OTRF / attack_data maps."""
    _, data = otrf._read_regular(path, MAX_SIDE_FILE_BYTES, 'fields')
    value = decode_json(data)
    if type(value) is not dict or set(value) != {'schema_version', 'version', 'note', 'sourcetypes'}:
        _fail('invalid_object', 'fields')
    if value['schema_version'] != 1 or type(value['version']) is not str or \
            not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}', value['version']):
        _fail('unsupported_schema', 'fields')
    if type(value['sourcetypes']) is not dict or not value['sourcetypes']:
        _fail('invalid_object', 'fields.sourcetypes')
    external, sources, resolved = {}, set(), {}
    for sourcetype, spec in value['sourcetypes'].items():
        field = 'fields.sourcetypes'
        if type(sourcetype) is not str or not sourcetype or len(sourcetype) > 128 or \
                any(ord(c) < 32 for c in sourcetype):
            _fail('invalid_identifier', field)
        if type(spec) is not dict or not {'parser', 'source', 'telemetry'} <= set(spec) or set(spec) - SPEC_KEYS:
            _fail('invalid_object', field)
        if spec['parser'] not in PARSERS:
            _fail('invalid_choice', field + '.parser')
        if type(spec['source']) is not str or not re.fullmatch(r'[a-z][a-z0-9-]{0,47}', spec['source']) or \
                spec['source'] in sources or spec['source'].startswith('st-'):
            _fail('invalid_identifier', field + '.source')
        sources.add(spec['source'])
        if spec['telemetry'] is not None and spec['telemetry'] not in COVERAGE_AXES['telemetry']:
            _fail('invalid_choice', field + '.telemetry')
        if spec.get('os') is not None and spec['os'] not in OS_HINTS:
            _fail('invalid_choice', field + '.os')
        if type(spec.get('aws', False)) is not bool:
            _fail('invalid_choice', field + '.aws')
        for key in ('type_field', 'record_id_field', 'strip_prefix'):
            if key in spec and (type(spec[key]) is not str or not spec[key]):
                _fail('invalid_text', field + '.' + key)
        if 'strip_prefix' in spec:
            try:
                re.compile(spec['strip_prefix'])
            except re.error:
                _fail('invalid_text', field + '.strip_prefix')
        events, metadata_only = {}, {}
        if 'events_from' in spec:
            match = EVENTS_FROM.fullmatch(spec['events_from']) if type(spec['events_from']) is str else None
            if not match:
                _fail('invalid_choice', field + '.events_from')
            events, metadata_only = _external_events(match.group(1), match.group(2), external)
        if type(spec.get('events', {})) is not dict or type(spec.get('metadata_only', {})) is not dict:
            _fail('invalid_object', field + '.events')
        for type_key, fields in spec.get('events', {}).items():
            if type(type_key) is not str or not type_key or len(type_key) > 64 or type(fields) is not dict:
                _fail('invalid_object', field + '.events')
            events[type_key] = fields
        metadata_only = dict(metadata_only, **spec.get('metadata_only', {}))
        for type_key, fields in events.items():
            _check_fields(fields, field + '.events.field', True)
        _check_fields(metadata_only, field + '.metadata_only', False)
        if spec['parser'] == 'columns':
            _check_columns(spec, field)
        elif 'columns' in spec or 'split' in spec or 'type_index' in spec:
            _fail('invalid_object', field + '.columns')
        if spec['parser'] in ('text', 'metadata', 'auditd') and 'type_field' in spec:
            _fail('invalid_object', field + '.type_field')
        if 'hex_argv' in spec and (spec['parser'] != 'json' or type(spec['hex_argv']) is not list or
                                   not all(type(item) is str and FIELD_NAME.fullmatch(item)
                                           for item in spec['hex_argv'])):
            _fail('invalid_object', field + '.hex_argv')
        resolved[sourcetype] = dict(spec, events=events, metadata_only=metadata_only, aws=spec.get('aws', False),
                                    os=spec.get('os'))
    value['sourcetypes'] = resolved
    value['folded'] = {name.casefold(): name for name in resolved}
    if len(value['folded']) != len(resolved):
        _fail('duplicate_item', 'fields.sourcetypes')
    value['sha256'] = digest_bytes(data)
    value['external'] = {name: item['sha256'] for name, item in sorted(external.items())}
    return value


def _external_events(kind, name, external):
    """Reuse an existing allowlist: an OTRF channel's events, or an attack_data format's record types."""
    if kind == 'otrf':
        if 'otrf' not in external:
            external['otrf'] = otrf.load_field_map(otrf.DEFAULT_FIELDS)
        spec = external['otrf']['channels'].get(name)
        if spec is None:
            _fail('invalid_choice', 'fields.sourcetypes.events_from')
        return {key: dict(fields) for key, fields in spec['events'].items()}, {}
    if 'attackdata' not in external:
        external['attackdata'] = attackdata.load_field_map(attackdata.DEFAULT_FIELDS)
    spec = external['attackdata']['formats'].get(name)
    if spec is None:
        _fail('invalid_choice', 'fields.sourcetypes.events_from')
    return ({key: dict(fields) for key, fields in spec['record_types'].items()}, dict(spec['metadata_only']))


def _check_fields(fields, field, content_allowed):
    for name, transform in fields.items():
        if type(name) is not str or not (name == '*' or FIELD_NAME.fullmatch(name)) or \
                name == 'timestamp_original' or transform not in TRANSFORMS:
            _fail('invalid_choice', field)
        if transform == 'content' and not content_allowed:
            _fail('invalid_choice', field)


def _check_columns(spec, field):
    if spec.get('split') not in ('space', 'space-quoted', 'csv', 'tab'):
        _fail('invalid_choice', field + '.split')
    columns = spec.get('columns')
    if type(columns) is list:
        groups = [columns]
        if 'type_index' in spec:
            _fail('invalid_object', field + '.type_index')
    elif type(columns) is dict and columns and type(spec.get('type_index')) is int and spec['type_index'] >= 0:
        groups = list(columns.values())
    else:
        _fail('invalid_object', field + '.columns')
    for group in groups:
        if type(group) is not list or not group or not all(type(name) is str and name for name in group):
            _fail('invalid_object', field + '.columns')


def source_name(field_map, sourcetype):
    spec = field_map['sourcetypes'].get(sourcetype)
    if spec is not None:
        return spec['source']
    return 'st-' + (re.sub(r'[^a-z0-9]+', '-', sourcetype.casefold()).strip('-')[:44] or 'unknown')


# ------------------------------------------------------------------- parsers
# Each parser returns (type key or None, native record ID or None, {field: original value}); `_Unparsed` makes the
# record metadata-only. Values are strings, numbers, booleans, null, lists, or objects (only for content fields).

_CLASSIC_HEADER = re.compile(r'([A-Za-z]+)=(.*)\Z')
_CLASSIC_FIELD = re.compile(r"(\t*)([A-Za-z][A-Za-z0-9 ()/'.&,-]{0,80}?):(?:[ \t]+(.*?)|)[ \t]*\Z")
_SUBJECT = {'Security ID': 'SubjectUserSid', 'Account Name': 'SubjectUserName', 'Account Domain': 'SubjectDomainName',
            'Logon ID': 'SubjectLogonId'}
_TARGET = {'Security ID': 'TargetUserSid', 'Account Name': 'TargetUserName', 'Account Domain': 'TargetDomainName',
           'Logon ID': 'TargetLogonId', 'Logon GUID': 'TargetLogonGuid', 'Linked Logon ID': 'TargetLinkedLogonId',
           'Network Account Name': 'TargetOutboundUserName', 'Network Account Domain': 'TargetOutboundDomainName'}
_ATTRIBUTES = {'SAM Account Name': 'SamAccountName', 'Display Name': 'DisplayName',
               'User Principal Name': 'UserPrincipalName', 'Home Directory': 'HomeDirectory', 'Home Drive': 'HomePath',
               'Script Path': 'ScriptPath', 'Profile Path': 'ProfilePath', 'User Workstations': 'UserWorkstations',
               'Password Last Set': 'PasswordLastSet', 'Account Expires': 'AccountExpires',
               'Primary Group ID': 'PrimaryGroupId', 'Allowed To Delegate To': 'AllowedToDelegateTo',
               'Old UAC Value': 'OldUacValue', 'New UAC Value': 'NewUacValue',
               'User Account Control': 'UserAccountControl', 'User Parameters': 'UserParameters',
               'SID History': 'SidHistory', 'Logon Hours': 'LogonHours'}
# Classic WinEventLog message labels -> the event's own EventData names (the OTRF/Sysmon allowlist names).
CLASSIC_SECTIONS = {
    'subject': _SUBJECT, 'creator subject': _SUBJECT,
    'target subject': _TARGET, 'new logon': _TARGET, 'account for which logon failed': _TARGET,
    'target account': _TARGET, 'account whose credentials were used': _TARGET, 'logon account': _TARGET,
    'new account': dict(_TARGET, **{'Security ID': 'TargetSid'}),
    'account information': {'Account Name': 'TargetUserName', 'Supplied Realm Name': 'TargetDomainName',
                            'User ID': 'TargetSid', 'Security ID': 'TargetSid', 'Account Domain': 'TargetDomainName',
                            'Logon GUID': 'LogonGuid'},
    'member': {'Security ID': 'MemberSid', 'Account Name': 'MemberName'},
    'group': {'Security ID': 'TargetSid', 'Group Name': 'TargetUserName', 'Group Domain': 'TargetDomainName',
              'Account Name': 'TargetUserName', 'Account Domain': 'TargetDomainName'},
    'process information': {'New Process ID': 'NewProcessId', 'New Process Name': 'NewProcessName',
                            'Token Elevation Type': 'TokenElevationType', 'Mandatory Label': 'MandatoryLabel',
                            'Creator Process ID': 'ProcessId', 'Creator Process Name': 'ParentProcessName',
                            'Process Command Line': 'CommandLine', 'Process ID': 'ProcessId',
                            'Process Name': 'ProcessName', 'Caller Process ID': 'CallerProcessId',
                            'Caller Process Name': 'CallerProcessName', 'Exit Status': 'Status'},
    'network information': {'Workstation Name': 'WorkstationName', 'Source Network Address': 'IpAddress',
                            'Source Port': 'IpPort', 'Network Address': 'IpAddress', 'Port': 'IpPort',
                            'Client Address': 'IpAddress', 'Client Port': 'IpPort', 'Direction': 'Direction',
                            'Source Address': 'SourceAddress', 'Destination Address': 'DestAddress',
                            'Destination Port': 'DestPort', 'Protocol': 'Protocol'},
    'detailed authentication information': {'Logon Process': 'LogonProcessName',
                                            'Authentication Package': 'AuthenticationPackageName',
                                            'Transited Services': 'TransmittedServices',
                                            'Package Name (NTLM only)': 'LmPackageName', 'Key Length': 'KeyLength'},
    'logon information': {'Logon Type': 'LogonType', 'Restricted Admin Mode': 'RestrictedAdminMode',
                          'Virtual Account': 'VirtualAccount', 'Elevated Token': 'ElevatedToken'},
    'failure information': {'Failure Reason': 'FailureReason', 'Status': 'Status', 'Sub Status': 'SubStatus'},
    'object': {'Object Server': 'ObjectServer', 'Object Type': 'ObjectType', 'Object Name': 'ObjectName',
               'Handle ID': 'HandleId', 'Resource Attributes': 'ResourceAttributes'},
    'access request information': {'Accesses': 'AccessList', 'Access Mask': 'AccessMask',
                                   'Transaction ID': 'TransactionId',
                                   'Privileges Used for Access Check': 'PrivilegeList'},
    'share information': {'Share Name': 'ShareName', 'Share Path': 'ShareLocalPath',
                          'Relative Target Name': 'RelativeTargetName'},
    'service information': {'Service Name': 'ServiceName', 'Service File Name': 'ServiceFileName',
                            'Service Type': 'ServiceType', 'Service Start Type': 'ServiceStartType',
                            'Service Account': 'ServiceAccount', 'Service ID': 'ServiceSid'},
    'task information': {'Task Name': 'TaskName', 'Task Content': 'TaskContent', 'Task New Content': 'TaskContentNew'},
    'attributes': _ATTRIBUTES, 'changed attributes': _ATTRIBUTES,
    'additional information': {'Privileges': 'PrivilegeList', 'Ticket Options': 'TicketOptions',
                               'Ticket Encryption Type': 'TicketEncryptionType', 'Failure Code': 'Status',
                               'Result Code': 'Status', 'Pre-Authentication Type': 'PreAuthType',
                               'Transited Services': 'TransmittedServices'},
    'target server': {'Target Server Name': 'TargetServerName', 'Additional Information': 'TargetInfo'},
    'application information': {'Process ID': 'ProcessID', 'Application Name': 'Application'},
    'filter information': {'Filter Run-Time ID': 'FilterRTID', 'Layer Name': 'LayerName',
                           'Layer Run-Time ID': 'LayerRTID'},
}
CLASSIC_TOP = {'Logon Type': 'LogonType', 'Impersonation Level': 'ImpersonationLevel', 'Privileges': 'PrivilegeList',
               'Logon Account': 'TargetUserName', 'Source Workstation': 'Workstation', 'Error Code': 'Status',
               'Authentication Package': 'PackageName', 'Service Name': 'ServiceName',
               'Service File Name': 'ImagePath', 'Service Type': 'ServiceType', 'Service Start Type': 'StartType',
               'Service Account': 'AccountName', 'Process ID': 'ProcessId', 'Process Name': 'ProcessName',
               'Object Name': 'ObjectName'}
# Windows Filtering Platform events name the local endpoint `Source Address/Port` (EventData SourceAddress/Port).
CLASSIC_EVENT_OVERRIDES = {code: {('network information', 'Source Port'): 'SourcePort'}
                           for code in (5152, 5154, 5155, 5156, 5157, 5158, 5159)}
CLASSIC_HEADER_FIELDS = {'SourceName': 'SourceName', 'Type': 'Level', 'TaskCategory': 'Task', 'OpCode': 'Opcode',
                         'Keywords': 'Keywords', 'User': 'User', 'Sid': 'Sid', 'ComputerName': 'Computer'}
_PS_SCRIPTBLOCK = re.compile(r'Creating Scriptblock text \(([0-9]+) of ([0-9]+)\):\n(.*?)\n\nScriptBlock ID: '
                             r'([0-9A-Fa-f-]+)\n?(?:Path: ?(.*))?\Z', re.S)


def _classic_name(section, label, event_id):
    override = CLASSIC_EVENT_OVERRIDES.get(event_id, {}).get((section, label))
    if override:
        return override
    if section is None:
        name = CLASSIC_TOP.get(label)
    else:
        name = CLASSIC_SECTIONS.get(section, {}).get(label)
    if name:
        return name
    return re.sub(r'[^A-Za-z0-9]', '', (section or '').title()) + '_' + re.sub(r'[^A-Za-z0-9]', '', label.title())


def parse_classic_message(message, event_id):
    """Rendered message -> {EventData name: value}: `Section:` headers, `\\tLabel:\\tvalue` lines, continuations."""
    fields, section, last, blank = {}, None, None, False
    lines = message.split('\n')
    fields['Message'] = message
    for line in lines[1:]:
        if not line.strip():
            blank, last = True, None
            continue
        match = _CLASSIC_FIELD.fullmatch(line)
        if match:
            depth, label, value = len(match.group(1)), match.group(2).strip(), match.group(3)
            if depth == 0 and value is None:
                section, last, blank = label.casefold(), None, False
                continue
            if depth == 0 and blank:
                section = None
            name = _classic_name(section if depth else None, label, event_id)
            blank = False
            if name not in fields:
                fields[name] = (value or '').strip()
                last = name
            else:
                last = None
            continue
        if last is not None and not blank:
            fields[last] = (fields[last] + '\n' + line.strip()).strip()
    return fields


def parse_winevent_classic(raw, spec):
    text = raw.replace('\r\n', '\n').replace('\r', '\n')
    lines = text.split('\n')
    header, message = {}, None
    for index, line in enumerate(lines[1:], 1):
        if line.startswith('Message='):
            message = '\n'.join([line[len('Message='):]] + lines[index + 1:]).strip('\n')
            break
        match = _CLASSIC_HEADER.fullmatch(line.strip())
        if match and match.group(1) not in header:
            header[match.group(1)] = match.group(2).strip()
    code = header.get('EventCode', '')
    if not re.fullmatch(r'[0-9]{1,5}', code) or not header.get('LogName'):
        raise _Unparsed()
    event_id = int(code)
    fields = {name: header[key] for key, name in CLASSIC_HEADER_FIELDS.items() if key in header}
    fields['EventID'] = event_id
    if message is not None:
        if header['LogName'].casefold() == 'microsoft-windows-powershell/operational' and event_id == 4104:
            match = _PS_SCRIPTBLOCK.match(message)
            fields['Message'] = message
            if match:
                fields.update({'MessageNumber': match.group(1), 'MessageTotal': match.group(2),
                               'ScriptBlockText': match.group(3), 'ScriptBlockId': match.group(4),
                               'Path': (match.group(5) or '').strip()})
        elif header['LogName'].casefold() == 'microsoft-windows-powershell/operational' and event_id == 4103:
            fields['Message'] = message
            fields.update(otrf.MESSAGE_PARSERS['powershell-module'](message.replace('\n', '\r\n'), event_id))
        elif header['LogName'].casefold() == 'windows powershell':
            fields['Message'] = message
            fields.update(otrf.MESSAGE_PARSERS['powershell-classic'](message.replace('\n', '\r\n'), event_id))
        else:
            for name, value in parse_classic_message(message, event_id).items():
                fields.setdefault(name, value)
    record_id = header.get('RecordNumber') or None
    return str(event_id), record_id, fields


def parse_winevent_xml(raw, spec):
    if '<!' in raw:
        raise _Unparsed()  # no DTDs or entities: nothing is expanded
    try:
        root = ElementTree.fromstring(raw)
    except ElementTree.ParseError:
        raise _Unparsed()
    ns = '{http://schemas.microsoft.com/win/2004/08/events/event}'
    system = root.find(ns + 'System')
    if system is None:
        raise _Unparsed()
    fields = {}
    event_id = system.findtext(ns + 'EventID')
    if event_id is None or not re.fullmatch(r'[0-9]{1,5}', event_id.strip()):
        raise _Unparsed()
    event_id = int(event_id.strip())
    provider = system.find(ns + 'Provider')
    if provider is not None and provider.get('Name'):
        fields['SourceName'] = provider.get('Name')
    for tag in ('Level', 'Task', 'Opcode', 'Keywords', 'Computer'):
        value = system.findtext(ns + tag)
        if value is not None:
            fields[tag] = value
    fields['EventID'] = event_id
    record_id = (system.findtext(ns + 'EventRecordID') or '').strip() or None
    data = root.find(ns + 'EventData')
    if data is not None:
        for item in data.findall(ns + 'Data'):
            name = item.get('Name')
            if name and name not in fields:
                fields[name] = item.text or ''
    user_data = root.find(ns + 'UserData')
    if user_data is not None:
        for element in user_data.iter():
            if len(element) == 0 and element.tag.split('}')[-1] not in fields:
                fields[element.tag.split('}')[-1]] = element.text or ''
    return str(event_id), record_id, fields


def _lookup(record, path):
    value = record
    for part in path.split('.'):
        if type(value) is not dict or part not in value:
            return False, None
        value = value[part]
    return True, value


def _scalar_text(value):
    if value is None or type(value) in (str, bool, int, float):
        return value
    return canonical_bytes(value).decode('utf-8')


def _no_constant(name):
    raise ValueError(name)


# Splunk Stream writes binary payload bytes as `\xNN`, which is not a JSON escape; it is read as the literal text.
_BAD_ESCAPE = re.compile(r'(?<!\\)((?:\\\\)*)\\x')


def _json_objects(text):
    """One record's JSON objects: Splunk line merging can join several JSON lines into one record."""
    decoder = json.JSONDecoder(parse_constant=_no_constant)
    objects, index = [], 0
    while index < len(text):
        value, index = decoder.raw_decode(text, index)
        objects.append(value)
        while index < len(text) and text[index] in ' \t\r\n':
            index += 1
    return objects


def parse_json(raw, spec):
    text = raw.strip()
    try:
        objects = _json_objects(text)
    except (ValueError, RecursionError):
        try:
            objects = _json_objects(_BAD_ESCAPE.sub(lambda m: m.group(1) + '\\\\x', text))
        except (ValueError, RecursionError):
            raise _Unparsed()
    if not objects or type(objects[0]) is not dict:
        raise _Unparsed()
    record = objects[0]
    type_key = record_id = None
    if 'type_field' in spec:
        present, value = _lookup(record, spec['type_field'])
        if present and type(value) in (str, int) and str(value):
            type_key = str(value)[:64]
    if 'record_id_field' in spec:
        present, value = _lookup(record, spec['record_id_field'])
        if present and type(value) in (str, int) and str(value):
            record_id = str(value)[:128]
    notes = {'merged_json_objects_dropped': len(objects) - 1} if len(objects) > 1 else {}
    for path in spec.get('hex_argv', ()):
        _decode_hex_argv(record, path, notes)
    return type_key, record_id, record, notes


_ARGV_TOKEN = re.compile(r'"((?:[^"\\]|\\.)*)"|(\S+)')
_HEX_TOKEN = re.compile(r'(?:[0-9A-F]{2}){2,}\Z')


def _decode_hex_argv(record, path, notes):
    """osquery `process_events` (audit-backed) writes each argv element quoted, or hex-encoded when it holds spaces
    or quotes (`"bash" "-c" 2F62696E2F7368…`), like the kernel's EXECVE record. Such a quoted command line is rewritten
    as shell words with the attack_data argv rules (hex words decoded), so the sanitizer sees ordinary command text:
    `"useradd" "-p" "<pass>"` becomes `useradd -p <pass>`, which the password rules recognise."""
    parent, _, name = path.rpartition('.')
    container = record
    for part in parent.split('.') if parent else ():
        container = container.get(part) if type(container) is dict else None
    if type(container) is not dict or type(container.get(name)) is not str or '"' not in container[name]:
        return
    words, decoded = [], 0
    for match in _ARGV_TOKEN.finditer(container[name]):
        if match.group(1) is not None:
            words.append(attackdata._shell_word(match.group(1)))
        elif _HEX_TOKEN.fullmatch(match.group(2)):
            words.append(attackdata._shell_word(attackdata._argv_text(bytes.fromhex(match.group(2)))))
            decoded += 1
        else:
            words.append(match.group(2))
    container[name] = ' '.join(words)
    notes['argv_rewritten'] = notes.get('argv_rewritten', 0) + 1
    if decoded:
        notes['hex_argv_decoded'] = notes.get('hex_argv_decoded', 0) + decoded


_KV = re.compile(r'(?<![A-Za-z0-9_.@-])([A-Za-z_@][A-Za-z0-9_.@-]{0,63})=("(?:[^"\\\n]|\\.)*"|\'[^\'\n]*\'|[^\s,"]*)')


def _kv_pairs(text):
    fields = {}
    for match in _KV.finditer(text):
        value = match.group(2)
        if len(value) >= 2 and value[0] == value[-1] and value[0] in '"\'':
            value = value[1:-1]
        fields.setdefault(match.group(1), value)
    return fields


def parse_kv(raw, spec):
    fields = _kv_pairs(raw)
    if not fields:
        raise _Unparsed()
    type_key = None
    if 'type_field' in spec and fields.get(spec['type_field']):
        type_key = fields[spec['type_field']][:64]
    record_id = fields.get(spec['record_id_field']) if 'record_id_field' in spec else None
    return type_key, record_id or None, fields


_SYSLOG = re.compile(r'(?:<[0-9]{1,3}>)?([A-Z][a-z]{2} +[0-9]{1,2} [0-9]{2}:[0-9]{2}:[0-9]{2}) (\S+) +(.*)\Z', re.S)
_PROGRAM = re.compile(r'([^\s:\[\]]{1,64})(?:\[([0-9]{1,10})\])?: ?(.*)\Z', re.S)


def parse_syslog(raw, spec):
    match = _SYSLOG.match(raw.strip())
    if not match:
        raise _Unparsed()
    fields = {'hostname': match.group(2)}
    rest = match.group(3)
    pairs = _kv_pairs(rest)
    if len(pairs) >= 3 and len(re.findall(r'=["\']', rest)) >= 3:
        fields.update(pairs)
        return None, None, fields
    program = _PROGRAM.match(rest)
    if program:
        fields['program'] = program.group(1)
        if program.group(2):
            fields['pid'] = program.group(2)
        fields['message'] = program.group(3)
        return program.group(1)[:64], None, fields
    fields['message'] = rest
    return None, None, fields


_ASA = re.compile(r'%(?:ASA|FTD|PIX)-([0-7])-([0-9]{6}): ?(.*)\Z', re.S)


def parse_cisco_asa(raw, spec):
    match = _SYSLOG.match(raw.strip())
    rest = match.group(3) if match else raw.strip()
    asa = _ASA.search(rest)
    if not asa:
        raise _Unparsed()
    fields = {'asa_level': asa.group(1), 'message_id': asa.group(2), 'message': asa.group(3)}
    if match:
        fields['hostname'] = match.group(2)
    return asa.group(2), None, fields


_SPACE_QUOTED = re.compile(r'"((?:[^"\\]|\\.)*)"|\[([^\]]*)\]|(\S+)')


def _split_columns(text, mode):
    if mode == 'space':
        return text.split()
    if mode == 'tab':
        return text.split('\t')
    if mode == 'csv':
        try:
            return next(csv.reader([text]))
        except (csv.Error, StopIteration):
            raise _Unparsed()
    return [next(group for group in match.groups() if group is not None)
            for match in _SPACE_QUOTED.finditer(text)]


def parse_columns(raw, spec):
    text = raw.strip()
    if 'strip_prefix' in spec:
        match = re.match(spec['strip_prefix'], text, re.S)
        if not match:
            raise _Unparsed()
        text = text[match.end():]
    if not text or '\n' in text:
        raise _Unparsed()
    values = _split_columns(text, spec['split'])
    columns = spec['columns']
    type_key = None
    if type(columns) is dict:
        if len(values) <= spec['type_index']:
            raise _Unparsed()
        type_key = values[spec['type_index']]
        columns = columns.get(type_key)
        if columns is None:
            raise _Unparsed()
    if len(values) < min(len(columns), 4):
        raise _Unparsed()
    fields = {name: value for name, value in zip(columns, values) if name != '-'}
    if 'type_field' in spec and type_key is None and fields.get(spec['type_field']):
        type_key = fields[spec['type_field']][:64]
    record_id = fields.get(spec['record_id_field']) if 'record_id_field' in spec else None
    return type_key, record_id or None, fields


def parse_text(raw, spec):
    text = raw.strip('\r\n')
    if not text.strip():
        raise _Unparsed()
    return None, None, {'message': text}


def parse_metadata(raw, spec):
    raise _Unparsed()


def parse_auditd(raw, spec):
    """auditd records keep the attack_data entry shape; fields are built with its allowlist at import time."""
    text = raw.strip()
    entry = {'line': 0}
    try:
        attackdata._audit_entry(text, entry, 'record')
    except BenchmarkError:
        raise _Unparsed()
    return entry['record_type'], entry['record_id'], {'_audit': {key: entry[key] for key in (
        'shape', 'record_type', 'record_id', 'body', 'timestamp_original', 'node')}}


PARSER_FUNCTIONS = {'winevent-classic': parse_winevent_classic, 'winevent-xml': parse_winevent_xml,
                    'json': parse_json, 'kv': parse_kv, 'syslog': parse_syslog, 'cisco-asa': parse_cisco_asa,
                    'columns': parse_columns, 'auditd': parse_auditd, 'text': parse_text, 'metadata': parse_metadata}


def parse_record(field_map, sourcetype, raw):
    """(status, type key, record ID, fields, notes): status `parsed`, `unparsed` (parser refused), `metadata`
    (declared metadata-only sourcetype) or `unknown_sourcetype`; notes count parts of the record not imported."""
    spec = field_map['sourcetypes'].get(sourcetype)
    if spec is None:
        return 'unknown_sourcetype', None, None, {}, {}
    try:
        result = PARSER_FUNCTIONS[spec['parser']](raw, spec)
    except _Unparsed:
        return ('metadata' if spec['parser'] == 'metadata' else 'unparsed'), None, None, {}, {}
    type_key, record_id, fields = result[:3]
    if type_key is not None:
        # Type keys become public event types: printable, bounded, ATT&CK-looking tokens masked.
        type_key = ATTACK_TOKEN.sub('T####', re.sub(r'[^\x21-\x7e]+', '_', type_key))[:64] or None
    return 'parsed', type_key, record_id, fields, (result[3] if len(result) > 3 else {})


# ------------------------------------------------------------------- dataset

def _check_incident(value):
    if type(value) is not str or not INCIDENT.fullmatch(value):
        _fail('invalid_identifier', 'incident')
    return value


def _profile(hosts, sourcetypes, exclude_sourcetypes):
    if sourcetypes and exclude_sourcetypes:
        _fail('conflicting_arguments', 'sourcetypes')
    profile = {}
    for key, values in (('hosts', hosts), ('sourcetypes', sourcetypes), ('exclude_sourcetypes', exclude_sourcetypes)):
        if values:
            if any(type(item) is not str or not item.strip() or len(item) > 255 for item in values):
                _fail('invalid_text', 'profile.' + key)
            folded = sorted({item.strip().casefold() for item in values})
            profile[key] = folded
        else:
            profile[key] = None
    return profile


def discover(version, data_dir):
    """The version's export files (sorted names, sizes) and its provenance.json; nothing is read yet."""
    if version not in VERSIONS:
        _fail('invalid_choice', 'version')
    layout = VERSIONS[version]
    root = Path(os.path.abspath(os.fspath(data_dir)))
    folder = root / layout['folder']
    if not folder.is_dir():
        _fail('unsupported_dataset_layout', 'data')
    files = []
    for path in sorted(folder.iterdir(), key=lambda item: item.name):
        if not layout['pattern'].fullmatch(path.name):
            continue
        if path.is_symlink() or not path.is_file():
            _fail('unsupported_dataset_layout', 'data.' + path.name)
        item = {'name': path.name, 'byte_count': path.stat().st_size, 'path': path}
        match = layout['pattern'].fullmatch(path.name)
        if layout['format'] == 'exporttool-csv':
            item['latest'], item['earliest'] = int(match.group(1)), int(match.group(2))
            if item['earliest'] > item['latest']:
                _fail('unsupported_dataset_layout', 'data.' + path.name)
        files.append(item)
    if not files:
        _fail('unsupported_dataset_layout', 'data')
    if len(files) >= 1000:
        _fail('unsupported_dataset_layout', 'data')
    _, provenance = otrf._read_regular(root / 'provenance.json', MAX_SIDE_FILE_BYTES, 'metadata')
    return files, digest_bytes(provenance)


def descriptor(version, incident, files, profile):
    """The dataset identity a curation binds to (`dataset_sha256`): version, incident, file list and profile."""
    return {'dataset': 'splunk-bots', 'version': version, 'incident': incident,
            'files': [{'name': item['name'], 'byte_count': item['byte_count']} for item in files],
            'profile': profile}


def _epoch_time(text, field):
    if not EPOCH.fullmatch(text):
        _fail('invalid_timestamp', field)
    seconds, _, fraction = text.partition('.')
    return datetime.fromtimestamp(int(seconds), timezone.utc) + timedelta(microseconds=int((fraction + '000000')[:6]))


def _v1_time(text, field):
    match = V1_TIME.fullmatch(text)
    if not match or match.group(8) not in V1_ZONES:
        _fail('invalid_timestamp', field)
    year, month, day, hour, minute, second = (int(match.group(i)) for i in range(1, 7))
    micro = int(((match.group(7) or '') + '000000')[:6])
    try:
        local = datetime(year, month, day, hour, minute, second, micro,
                         timezone(timedelta(hours=V1_ZONES[match.group(8)])))
    except ValueError:
        _fail('invalid_timestamp', field)
    return local.astimezone(timezone.utc)


def _clean_text(value):
    """Undecodable input bytes (kept as surrogates while reading) become visible `\\xNN` escapes."""
    if SURROGATES.search(value):
        return value.encode('utf-8', 'surrogateescape').decode('utf-8', 'backslashreplace'), True
    return value, False


MAX_CSV_PHYSICAL_LINE_BYTES = len(CSV_HEADER) * 4 * MAX_RECORD_BYTES + 65536


def _bounded_csv_lines(binary_handle, field_name, *, max_line_bytes=None):
    """Yield UTF-8 CSV lines with a hard per-line decompressed byte ceiling before allocation."""
    cap = MAX_CSV_PHYSICAL_LINE_BYTES if max_line_bytes is None else int(max_line_bytes)
    while True:
        chunk = binary_handle.readline(cap + 1)
        if not chunk:
            break
        if len(chunk) > cap:
            _fail('invalid_csv', field_name)
        yield chunk.decode('utf-8', errors='surrogateescape')


def _csv_records(item, number, window):
    """(ordinal, time, host, sourcetype, raw, digest) of one exporttool bucket's rows inside `window`."""
    # One `_raw` may legitimately hold up to MAX_RECORD_BYTES (lsof/ps snapshots are ~1 MB); larger is refused.
    old_limit = csv.field_size_limit(MAX_RECORD_BYTES)
    try:
        with gzip.open(item['path'], 'rb') as compressed:
            reader = csv.reader(_bounded_csv_lines(compressed, 'data.' + item['name']))
            header = next(reader, None)
            if header != CSV_HEADER:
                _fail('unsupported_dataset_layout', 'data.' + item['name'])
            for ordinal, row in enumerate(reader, 1):
                if ordinal >= LINE_STRIDE:
                    _fail('too_many_records', 'data.' + item['name'])
                field = 'data.%s.%d' % (item['name'], ordinal)
                if len(row) != 6:
                    _fail('unsupported_record_shape', field)
                moment = _epoch_time(row[0], field)
                if not item['earliest'] <= moment.timestamp() < item['latest'] + BUCKET_SLACK_SECONDS + 1:
                    _fail('bucket_range_violation', field)
                if not window[0] <= moment < window[1]:
                    yield ordinal, moment, None, None, None, None, None
                    continue
                if not (row[2].startswith('host::') and row[3].startswith('sourcetype::')):
                    _fail('unsupported_record_shape', field)
                original = '\x1f'.join(row[:5]).encode('utf-8', 'surrogateescape')
                yield (ordinal, moment, row[2][len('host::'):], row[3][len('sourcetype::'):], row[4],
                       hashlib.sha256(original).hexdigest(), row[0])
    except csv.Error:
        # Malformed CSV or a field above MAX_RECORD_BYTES.
        _fail('invalid_csv', 'data.' + item['name'])
    except (OSError, EOFError):
        _fail('invalid_archive', 'data.' + item['name'])
    finally:
        csv.field_size_limit(old_limit)


def _json_records(item, number, window, state):
    """v1 search-export JSON lines inside `window`; the file is read newest first and stops before the window."""
    previous = None
    try:
        with gzip.open(item['path'], 'rb') as handle:
            ordinal = 0
            while True:
                line = handle.readline(MAX_RECORD_BYTES + 1)
                if not line:
                    break
                ordinal += 1
                if ordinal >= LINE_STRIDE:
                    _fail('too_many_records', 'data.' + item['name'])
                field = 'data.%s.%d' % (item['name'], ordinal)
                if len(line) > MAX_RECORD_BYTES:
                    _fail('line_too_large', field)
                match = V1_TIME_BYTES.search(line)
                if match is None:
                    if line.strip() and decode_json(line.strip()) != {'preview': False, 'lastrow': True}:
                        _fail('unsupported_record_shape', field)
                    continue
                raw_time = match.group(1).decode('ascii', 'replace')
                moment = _v1_time(raw_time, field)
                if previous is not None and moment > previous:
                    _fail('unsorted_export', field)
                previous = moment
                if moment < window[0]:
                    state['stopped_early'] = True
                    return
                if moment >= window[1]:
                    yield ordinal, moment, None, None, None, None, None
                    continue
                try:
                    outer = json.loads(line.decode('utf-8', 'surrogateescape'), parse_constant=_no_constant)
                except (ValueError, RecursionError):
                    _fail('invalid_json', field)
                result = outer.get('result') if type(outer) is dict else None
                if type(result) is not dict or type(result.get('_raw')) is not str:
                    _fail('unsupported_record_shape', field)
                single = {}
                for key in ('host', 'sourcetype'):
                    # A search-time multivalue field is a JSON list: the first value is the record's own, the
                    # rest are counted (`multivalue_dropped`).
                    value = result.get(key)
                    if type(value) is list and value and all(type(item) is str for item in value):
                        state['multivalue_dropped'] = state.get('multivalue_dropped', 0) + len(value) - 1
                        value = value[0]
                    if type(value) is not str:
                        _fail('unsupported_record_shape', field)
                    single[key] = value
                yield (ordinal, moment, single['host'], single['sourcetype'], result['_raw'],
                       hashlib.sha256(line.rstrip(b'\r\n')).hexdigest(), raw_time)
    except (OSError, EOFError):
        _fail('invalid_archive', 'data.' + item['name'])


def _v1_file_sourcetype(field_map, item):
    """v1 files hold one sourcetype each; the name is read from the first record."""
    try:
        with gzip.open(item['path'], 'rb') as handle:
            line = handle.readline(MAX_RECORD_BYTES)
    except (OSError, EOFError):
        _fail('invalid_archive', 'data.' + item['name'])
    match = re.search(rb'"sourcetype": ?\[?"([^"\\]{1,255})"', line)
    if not match:
        _fail('unsupported_record_shape', 'data.' + item['name'])
    return match.group(1).decode('utf-8', 'replace')


def scan(version, data_dir, field_map, window, incident, hosts=None, sourcetypes=None, exclude_sourcetypes=None):
    """Stream the export once and keep the parsed records of one UTC window under the declared profile.

    Records of other hosts or sourcetypes inside the window are counted per (host, sourcetype), never kept. v2/v3
    buckets outside the window are not opened; v1 files are read newest first until the window start, and a v1 file
    whose sourcetype the profile excludes is not read at all (stated as such).
    """
    window = otrf._partition_tuple(window, 'window')
    incident = _check_incident(incident)
    profile = _profile(hosts, sourcetypes, exclude_sourcetypes)
    files, metadata_sha = discover(version, data_dir)
    dataset = descriptor(version, incident, files, profile)
    layout = VERSIONS[version]

    def wanted_sourcetype(name):
        folded = name.casefold()
        if profile['sourcetypes'] is not None:
            return folded in profile['sourcetypes']
        return profile['exclude_sourcetypes'] is None or folded not in profile['exclude_sourcetypes']

    entries, excluded_hosts, excluded_types, files_read, not_read = [], {}, {}, [], []
    counters = {'unparsed': {}, 'unknown_sourcetype': {}, 'undecodable': 0, 'oversize': 0}
    for number, item in enumerate(files, 1):
        state = {'stopped_early': False}
        if layout['format'] == 'exporttool-csv':
            if item['latest'] + BUCKET_SLACK_SECONDS + 1 <= window[0].timestamp() or \
                    item['earliest'] >= window[1].timestamp():
                continue
            records = _csv_records(item, number, window)
        else:
            file_sourcetype = _v1_file_sourcetype(field_map, item)
            if not wanted_sourcetype(file_sourcetype):
                not_read.append({'file': item['name'], 'sourcetype': file_sourcetype})
                continue
            records = _json_records(item, number, window, state)
        read = {'file': item['name'], 'byte_count': item['byte_count'], 'records_read': 0, 'records_in_window': 0}
        for ordinal, moment, host, sourcetype, raw, digest, raw_time in records:
            read['records_read'] += 1
            if raw is None:
                continue
            read['records_in_window'] += 1
            folded_host = host.casefold()
            if profile['hosts'] is not None and folded_host not in profile['hosts']:
                key = (moment, folded_host, sourcetype)
                excluded_hosts[key] = excluded_hosts.get(key, 0) + 1
                continue
            if not wanted_sourcetype(sourcetype):
                key = (moment, folded_host, sourcetype)
                excluded_types[key] = excluded_types.get(key, 0) + 1
                continue
            if len(entries) >= MAX_WINDOW_RECORDS:
                _fail('window_too_large', 'window')
            raw, undecodable = _clean_text(raw)
            host, _ = _clean_text(host)
            counters['undecodable'] += undecodable
            if len(raw.encode('utf-8')) > MAX_RECORD_BYTES:
                counters['oversize'] += 1
                status, type_key, record_id, fields, notes = 'unparsed', None, None, {}, {}
            else:
                status, type_key, record_id, fields, notes = parse_record(field_map, sourcetype, raw)
            if status in ('unparsed', 'unknown_sourcetype'):
                counters[status][sourcetype] = counters[status].get(sourcetype, 0) + 1
            entries.append({'line': number * LINE_STRIDE + ordinal, 'file': item['name'], 'ordinal': ordinal,
                            'line_sha256': digest, 'time': moment, 'time_raw': raw_time, 'host': host,
                            'sourcetype': sourcetype, 'raw_bytes': len(raw.encode('utf-8')), 'parse': status,
                            'type': type_key, 'record_id': record_id, 'fields': fields, 'notes': notes})
        read['stopped_early'] = state['stopped_early']
        if state.get('multivalue_dropped'):
            read['multivalue_host_or_sourcetype_values_dropped'] = state['multivalue_dropped']
        files_read.append(read)
    if not entries:
        _fail('no_supported_records', 'window')
    entries.sort(key=lambda e: (e['time'], e['line']))
    return {'version': version, 'incident': incident, 'window': window, 'profile': profile, 'descriptor': dataset,
            'dataset_sha256': digest_bytes(canonical_bytes(dataset)), 'metadata_sha256': metadata_sha,
            'file_count': len(files), 'entries': entries, 'excluded_hosts': excluded_hosts,
            'excluded_sourcetypes': excluded_types, 'files_read': files_read, 'files_not_read': not_read,
            'counters': counters, 'family_id': 'bots-%s-%s' % (version, incident)}


# ------------------------------------------------------------------ building

def _is_ip(text):
    try:
        ipaddress.ip_address(text.strip('[]'))
    except ValueError:
        return False
    return True


def _sid(names, value):
    if AWS_SID.fullmatch(value):
        return names.token('sid', 'sid', value)
    if value.upper().startswith('S-1-'):
        return names.sid(value)
    if '\\' in value:
        # Classic WinEventLog renders a resolvable `Security ID` as DOMAIN\name; built-in principals and integrity
        # labels (`BUILTIN\Users`, `Mandatory Label\High Mandatory Level`) are Windows constants.
        if value.split('\\', 1)[0].casefold() in WINDOWS_CONSTANT_DOMAINS:
            return value
        return names.account(value)
    return names.apply('user', value, 'sid') if value not in ('', '-', 'NULL SID') else value


def _visible(text):
    """NUL (Stream payload bytes decoded from `\\u0000`) becomes the visible text `\\x00`; the sanitizer refuses NUL."""
    return text.replace('\x00', '\\x00') if '\x00' in text else text


def _structured(names, transform, value, label):
    """One non-content value through its transform; lists element-wise."""
    if type(value) is list:
        return [_structured(names, transform, item, label) for item in value]
    if value is None or type(value) in (bool, int):
        return value
    if type(value) is float:
        return value if math.isfinite(value) else str(value)
    if type(value) is not str:
        _fail('unsupported_record_shape', label)
    value = _visible(value)
    if transform == 'keep':
        return value
    if value in ('', '-'):
        return value
    if transform == 'sid':
        return _sid(names, value)
    if transform in OTRF_STRUCTURED:
        return names.apply(transform, value, label)
    return names.transform(transform, value, label)


def _is_structured_list(value):
    return type(value) is list and all(item is None or type(item) in (str, int, float, bool) for item in value)


def _needs_content(value):
    """Values a structured transform cannot carry go through the content sanitizer instead."""
    if type(value) is str:
        return len(value) > MAX_KEEP_CHARS
    if type(value) is list:
        return not _is_structured_list(value) or any(type(item) is str and len(item) > MAX_KEEP_CHARS
                                                     for item in value)
    return type(value) is dict


def _leaves(value, prefix, out):
    if type(value) is dict and value:
        for key, item in value.items():
            _leaves(item, prefix + '.' + key if prefix else key, out)
    else:
        out.append(prefix)


def _select_fields(record, allow):
    """(selected [(name, transform, value)], dropped leaf paths) for a record and an allowlist with `prefix.*`."""
    selected, covered = [], set()
    wildcards = sorted((name[:-2], transform) for name, transform in allow.items() if name.endswith('.*'))
    for name in sorted(allow):
        if name.endswith('.*') or name == '*':
            continue
        present, value = _lookup(record, name) if '.' in name and name not in record else (name in record,
                                                                                           record.get(name))
        if present:
            selected.append((name, allow[name], value))
            covered.add(name)
    leaves = []
    _leaves(record, '', leaves)
    dropped = []
    for leaf in leaves:
        if leaf in covered or any(leaf.startswith(name + '.') for name in covered):
            continue
        for prefix, transform in wildcards:
            if leaf.startswith(prefix + '.'):
                present, value = _lookup(record, leaf) if leaf not in record else (True, record[leaf])
                if present:
                    selected.append((leaf, transform, value))
                break
        else:
            if '*' in allow:
                selected.append((leaf, allow['*'], _lookup(record, leaf)[1] if leaf not in record else record[leaf]))
            else:
                dropped.append(leaf)
    return selected, dropped


def _time_text(entry, version):
    if version == 'v1':
        if entry.get('time_raw'):
            return entry['time_raw']
        return entry['time'].astimezone(timezone(timedelta(hours=-6))).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3] + ' MDT'
    seconds = entry['time'].timestamp()
    return str(int(seconds)) if seconds == int(seconds) else ('%.6f' % seconds).rstrip('0')


def _content_callback(names):
    def pseudonymize(kind, original):
        if kind.startswith('known:'):
            token = names.mapping.get(kind[len('known:'):], {}).get(original.casefold())
            return token if token is not None else names.token('value', 'opaque', original)
        if kind == 'sid':
            return _sid(names, original)
        return names.content(kind, original)
    return pseudonymize


def _identities(names, hosts):
    mapping = {kind: set(names.mapping.get(kind, {})) for kind in PLAIN_NAMESPACES}
    for namespace in KNOWN_NAMESPACES:
        mapping['known:' + namespace] = set(names.mapping.get(namespace, {}))
    named = [host for host in hosts if not _is_ip(host)]
    mapping['dns'].update(host for host in named if '.' in host.strip('.'))
    mapping['dns'].update(names.domains)
    mapping['netbios'].update(host.split('.', 1)[0] for host in named)
    return mapping


# Form posts and query strings name accounts as `[prefix_]user[name]=<name>` (`quick_username=`, `login=`), also
# percent-encoded inside a URL (`%26username%3D<name>%26`). The value is replaced by its user (or `user@dns`)
# pseudonym in place, because encoded text glues it to its neighbours and whole-token matching would miss it.
_FORM_USER = re.compile(r'(?i)(?:(?<=%[0-9a-f]{2})|(?<![\w.%-]))((?:[a-z0-9]+_)*(?:user|username|uname|login)'
                        r'(?:=|%%?3D))((?:%%?(?!26|22|27|3b|2c|20|3d)[0-9a-f]{2}|[^&\s;"\'<>=%])+)')
_FORM_LITERALS = frozenset({'true', 'false', 'null', 'none', 'yes', 'no', 'on', 'off', 'undefined'})


def _form_users(names, text):
    def replace(match):
        name = urllib.parse.unquote(match.group(2))
        if name.isdigit() or name.casefold() in _FORM_LITERALS or not name.strip() or '\x00' in name:
            return match.group(0)
        return match.group(1) + (names.account(name) if '@' in name else names.user(name))
    return _FORM_USER.sub(replace, text)


def _content_value(names, value, label, aws, dropped):
    secrets_dropped = 0
    if type(value) in (dict, list):
        value, secrets_dropped = attackdata._aws_scrub(value, label, names, dropped)
        value = canonical_bytes(value).decode('utf-8')
    elif type(value) is not str:
        value = _scalar_text(value)
    else:
        value = _form_users(names, _visible(value))
    if aws:
        value = attackdata.ARN_IN_TEXT.sub(lambda match: names.aws_arn(match.group(0)), value)
        value = attackdata.ACCOUNT_IN_TEXT.sub(lambda match: names.aws_account(match.group(0)), value)
    return value, secrets_dropped


def _sanitize_one(names, original, label, aws, known, callback, encoded_payloads):
    """(sanitized value, [reports], secrets dropped, dropped paths); a list of scalars is sanitized element-wise."""
    dropped = {}
    if _is_structured_list(original):
        out, reports = [], []
        for item in original:
            if type(item) is str:
                text, _ = _content_value(names, item, label, aws, dropped)
                item, report = sanitize_text(text, callback, identities=known, field=label,
                                             encoded_payloads=encoded_payloads)
                reports.append(report)
            out.append(item)
        return out, reports, 0, dropped
    text, secrets_dropped = _content_value(names, original, label, aws, dropped)
    out, report = sanitize_text(text, callback, identities=known, field=label, encoded_payloads=encoded_payloads)
    return out, [report], secrets_dropped, dropped


def _sanitize_pending(pending, names, hosts, encoded_payloads):
    """Sanitize every content value, re-running from the originals until no new pseudonym appears (OTRF rule)."""
    passes, results = 0, []
    callback = _content_callback(names)
    while pending:
        passes += 1
        size = sum(len(values) for values in names.mapping.values())
        known = KnownIdentities(_identities(names, hosts))
        results = [_sanitize_one(names, original, label, entry['aws'], known, callback, encoded_payloads)
                   for fields, name, original, label, key, entry in pending]
        if sum(len(values) for values in names.mapping.values()) == size or passes == MAX_CONTENT_PASSES:
            break
    totals, truncated, dropped_total = {}, {}, {}
    for (fields, name, _, _, key, entry), (value, reports, secrets_dropped, dropped) in zip(pending, results):
        for text in (value if type(value) is list else [value]):
            if type(text) is str and ATTACK_TOKEN.search(text):
                _fail('attack_token_in_field', key)
        fields[name] = value
        total = totals.setdefault(key, dict(new_totals(), secret_fields_dropped=0))
        for report in reports:
            merge_reports(total, report)
            if report['truncated']:
                truncated[entry['source_key']] = truncated.get(entry['source_key'], 0) + 1
        total['secret_fields_dropped'] += secrets_dropped
        for path, count in dropped.items():
            dropped_total[path] = dropped_total.get(path, 0) + count
    return dict(sorted(totals.items())), truncated, passes, dropped_total


def _rewrite_kept(rewritable, names, hosts):
    known = KnownIdentities(_identities(names, hosts))
    callback = _content_callback(names)
    rewrites = {}
    for fields, name, key in rewritable:
        value = fields[name]
        if type(value) is str:
            new = known.sub(value, callback)
        elif type(value) is list:
            new = [known.sub(item, callback) if type(item) is str else item for item in value]
        else:
            continue
        if new != value:
            fields[name] = new
            rewrites[key] = rewrites.get(key, 0) + 1
    return dict(sorted(rewrites.items()))


def _mask_kept(value, counters):
    if type(value) is str and ATTACK_TOKEN.search(value):
        counters['attack_masked_kept'] = counters.get('attack_masked_kept', 0) + 1
        return ATTACK_TOKEN.sub('T####', value)
    if type(value) is list:
        return [_mask_kept(item, counters) for item in value]
    return value


def _public_values(value, out):
    if type(value) is str:
        out.append(value)
    elif type(value) is list:
        for item in value:
            _public_values(item, out)
    elif type(value) is dict:
        for item in value.values():
            _public_values(item, out)
    return out


def _leak_check(bundle, records, names, hosts):
    """Refuse a bundle naming BOTS, or holding an original the import pseudonymized anywhere in data-derived text.

    Field names are allowlist schema (`login`, `user`) and the question, clock note and gap reasons are fixed
    importer vocabulary (`support`, `public`, `window`), so the identity scan covers the event and asset values; the
    BOTS-name scan covers every public byte.
    """
    public = canonical_bytes(bundle).decode('utf-8').casefold() + '\n' + records.decode('utf-8').casefold()
    if any(needle in public for needle in FORBIDDEN_PUBLIC):
        _fail('forbidden_public_metadata', 'public_bundle')
    # The source half of an event type (`stream-http`) is allowlist schema; only the type key after `:` is data.
    data = [{'fields': event['fields'], 'type': event['event_type'].partition(':')[2]} for event in bundle['events']]
    text = '\n'.join(_public_values({'events': data, 'assets': bundle['assets']}, [])).casefold()
    folded = AWS_SERVICE_TEXT.sub(' ', TOKEN_FORM.sub(' ', text))
    named = [host for host in hosts if not _is_ip(host)]
    originals = set(named) | {host.split('.', 1)[0] for host in named}
    for namespace in PLAIN_NAMESPACES + KNOWN_NAMESPACES:
        originals.update(names.mapping.get(namespace, {}))
    leaks = scan_leaks(folded, originals)
    if leaks:
        _fail('pseudonymization_leak', 'public_bundle (%d identities; %s)' % (len(leaks),
                                                                             _leak_location(bundle, names, leaks[0])))


def _leak_location(bundle, names, original):
    """Where a leaked original sits, as schema only (namespace, event type, field name); the value is never echoed."""
    namespaces = [ns for ns in PLAIN_NAMESPACES + KNOWN_NAMESPACES if original in names.mapping.get(ns, {})]
    namespace = '/'.join(namespaces) or 'host'
    for event in bundle['events']:
        for name, value in event['fields'].items():
            text = TOKEN_FORM.sub(' ', '\n'.join(_public_values(value, [])).casefold())
            if scan_leaks(text, [original]):
                return 'namespace %s, original length %d, in %s field %s' % (namespace, len(original),
                                                                              event['event_type'], name)
    return 'namespace %s, original length %d' % (namespace, len(original))


class BotsPseudonyms(attackdata.AttackDataPseudonyms):
    """attack_data pseudonyms; AWS service principals (`<service>.amazonaws.com`) are AWS constants, never resources."""

    def aws_resource(self, value):
        if attackdata.AWS_SERVICE.fullmatch(value):
            return value
        return super().aws_resource(value)

    def register_domains(self, hosts):
        """Only multi-label DNS suffixes are domains: `kutekitten.local` must not make the TLD `local` an identity
        (it would rewrite `NT AUTHORITY\\LOCAL SERVICE`), and `gacrux.i-0920…` is an instance name, not a domain."""
        super().register_domains(hosts)
        self._domains = frozenset(domain for domain in self._domains if '.' in domain.strip('.'))

    def user(self, value):
        return value if value.casefold() in SYSTEM_ACCOUNTS else super().user(value)

    def linux_user(self, value):
        return value if value.casefold() in SYSTEM_ACCOUNTS else super().linux_user(value)


class _BotsLines(dict):
    """Imported records by global line; any other well-formed line of the export is known but not imported."""

    def __init__(self, imported, file_count):
        super().__init__(imported)
        self.file_count = file_count

    def get(self, line, default=None):
        if line in self:
            return self[line]
        if type(line) is int and 1 <= line // LINE_STRIDE <= self.file_count and line % LINE_STRIDE >= 1:
            return {'line': line, 'status': 'excluded_from_partition'}
        return default


def _asset_facts(curation, hosts, derived):
    if curation is None:
        return {host: {'os_family': derived[host], 'os_version': None, 'architecture': None, 'vendor': None}
                for host in hosts}
    facts = {}
    if type(curation['assets']) is not list:
        _fail('invalid_array', 'curation.assets')
    for item in curation['assets']:
        otrf._strict(item, {'hostname', 'os_family', 'os_version', 'architecture', 'vendor'}, 'curation.assets')
        if type(item['hostname']) is not str or item['hostname'].casefold() in facts:
            _fail('duplicate_item', 'curation.assets')
        if item['os_family'] not in COVERAGE_AXES['os']:
            _fail('invalid_choice', 'curation.assets.os_family')
        for key in ('os_version', 'architecture', 'vendor'):
            otrf._text(item[key], 'curation.assets.' + key, True)
        facts[item['hostname'].casefold()] = item
    if set(facts) != set(hosts):
        _fail('curation_assets_mismatch', 'curation.assets')
    return facts


def _derived_os(field_map, entries):
    """Draft default OS per host from its sourcetypes' declared OS hints (a template default, never truth)."""
    hints = {}
    for entry in entries:
        spec = field_map['sourcetypes'].get(entry['sourcetype'])
        hint = spec['os'] if spec is not None else None
        if hint is not None:
            hints.setdefault(entry['host'].casefold(), set()).add(hint)
    result = {}
    for host in {entry['host'].casefold() for entry in entries}:
        found = hints.get(host, set())
        for hint in ('windows', 'macos', 'linux', 'network', 'cloud'):
            if hint in found:
                result[host] = OS_HINTS[hint]
                break
        else:
            result[host] = 'not-applicable'
    return result


def _audit_fields(entry, spec, names, counters, dropped):
    audit = dict(entry['fields']['_audit'], line=entry['line'], line_sha256=entry['line_sha256'],
                 metadata_only=entry['type'] not in spec['events'], asset=entry['host'].casefold(),
                 status='imported')
    ad_spec = {'source': spec['source'], 'record_types': spec['events'], 'metadata_only': spec['metadata_only']}
    try:
        fields = attackdata._public_fields(audit, ad_spec, names, audit['shape'], counters, dropped)
    except BenchmarkError:
        return None, audit
    audit['fields'] = fields
    return fields, audit


def _domain_hosts(scan_result, entries, hosts):
    """FQDNs whose DNS suffixes are the lab's own domains: the case's hosts, every host the scan saw in the window
    (also those the profile excluded, e.g. `splunk.froth.ly`) and Windows `Computer` names (`FYODOR-L.froth.ly`)."""
    names = set(hosts) | {host for _, host, _ in scan_result['excluded_hosts']}
    names.update(host for _, host, _ in scan_result['excluded_sourcetypes'])
    for entry in entries:
        computer = entry['fields'].get('Computer') if type(entry['fields']) is dict else None
        if type(computer) is str and computer.strip():
            names.add(computer.strip().casefold())
    return sorted(name for name in names if not _is_ip(name))


def build_case(scan_result, field_map, salt, partition, curation_path=None, draft=False, coverage=None,
               encoded_payloads='preview', max_public_bytes=MAX_PUBLIC_BYTES):
    """One partition of a scanned window as a case; returns (case_id, {relative_path: bytes}).

    `partition` must lie inside the scanned window. The prompt projection must fit `max_public_bytes`
    (`public_bundle_too_large` otherwise: choose smaller partitions, never sample).
    """
    if encoded_payloads not in ENCODED_PAYLOAD_MODES:
        _fail('invalid_choice', 'encoded_payloads')
    if max_public_bytes is not None and (type(max_public_bytes) is not int or
                                         not 0 < max_public_bytes <= MAX_PUBLIC_BYTES):
        _fail('invalid_limit', 'max_public_bytes')
    partition = otrf._partition_tuple(partition, 'partition')
    if partition[0] < scan_result['window'][0] or partition[1] > scan_result['window'][1]:
        _fail('invalid_window', 'partition')
    dataset_sha, metadata_sha = scan_result['dataset_sha256'], scan_result['metadata_sha256']
    if curation_path is None:
        if not draft:
            _fail('missing_field', 'curation')
        curation, curation_bytes = None, None
    else:
        if draft:
            _fail('conflicting_arguments', 'draft')
        curation, curation_bytes = otrf.load_curation(curation_path)
        if curation['dataset_sha256'] != dataset_sha or curation['metadata_sha256'] != metadata_sha:
            _fail('curation_dataset_mismatch', 'curation')
    entries = [e for e in scan_result['entries'] if partition[0] <= e['time'] < partition[1]]
    if not entries:
        _fail('no_supported_records', 'partition')
    version = scan_result['version']
    hosts = sorted({e['host'].casefold() for e in entries})
    names = BotsPseudonyms(salt)
    names.register_domains(_domain_hosts(scan_result, entries, hosts))
    window = otrf._normal_window(partition)
    case_key = '\x00'.join(('bots', dataset_sha, window['start_inclusive'], window['end_exclusive']))
    case_id = 'case-' + hmac.new(salt, case_key.encode('utf-8'), hashlib.sha256).hexdigest()[:16]
    facts = _asset_facts(curation, hosts, _derived_os(field_map, entries))
    asset_ids = {host: names.token('asset', 'asset', host) for host in hosts}
    assets = sorted(({'asset_id': asset_ids[host], 'os_family': facts[host]['os_family'],
                      'os_version': facts[host]['os_version'], 'architecture': facts[host]['architecture'],
                      'vendor': facts[host]['vendor']} for host in hosts), key=lambda a: a['asset_id'])

    counters, audit_counters = {}, {}
    dropped_fields, imported_counts, metadata_counts = {}, {}, {}
    events, source_keys, telemetry_of, pending, rewritable, audit_entries, unparsed_by_source = \
        [], {}, {}, [], [], [], {}
    for entry in entries:
        sourcetype = entry['sourcetype']
        spec = field_map['sourcetypes'].get(sourcetype)
        source = source_name(field_map, sourcetype)
        telemetry_of[source] = spec['telemetry'] if spec is not None else None
        host = entry['host'].casefold()
        source_key = (source, host)
        if source_key not in source_keys:
            source_keys[source_key] = names.token('source', 'source', source + '|' + host)
        work = {'source_key': source_key, 'aws': bool(spec and spec['aws'])}
        fields = {'timestamp_original': _time_text(entry, version)}
        type_key = entry['type']
        for note, count in entry['notes'].items():
            dropped_fields[note] = dropped_fields.get(note, 0) + count
        event_type = source + (':' + type_key if type_key else '')
        label_base = source + ('.' + type_key if type_key else '')
        allow = None
        if entry['parse'] == 'parsed':
            allow = spec['events'].get(type_key) if type_key is not None else None
            if allow is None:
                allow = spec['events'].get('*')
        if entry['parse'] == 'parsed' and spec['parser'] == 'auditd':
            audit_fields, audit = _audit_fields(entry, spec, names, audit_counters, dropped_fields)
            if audit_fields is not None:
                for key in ('type', 'audit_serial'):
                    if key in audit_fields:
                        fields[key] = audit_fields[key]
                for key, value in audit_fields.items():
                    if key not in ('timestamp_original', 'type', 'audit_serial'):
                        fields[key] = value
                audit['public_fields'] = fields
                audit['label'] = label_base
                audit['work'] = work
                audit_entries.append(audit)
                counts = metadata_counts if audit['metadata_only'] else imported_counts
                counts[event_type] = counts.get(event_type, 0) + 1
            else:
                unparsed_by_source[source_key] = unparsed_by_source.get(source_key, 0) + 1
                metadata_counts[event_type] = metadata_counts.get(event_type, 0) + 1
        elif allow is not None:
            imported_counts[event_type] = imported_counts.get(event_type, 0) + 1
            selected, dropped = _select_fields(entry['fields'], allow)
            for path in dropped:
                dropped_fields[path] = dropped_fields.get(path, 0) + 1
            for name, transform, value in selected:
                label = label_base + '.' + name
                if transform == 'content' or _needs_content(value):
                    if value is None or type(value) in (bool, int, float):
                        fields[name] = value
                        continue
                    fields[name] = None
                    pending.append((fields, name, value, label, event_type + ' ' + name, work))
                    continue
                value = _mask_kept(_structured(names, transform, value, label), counters)
                fields[name] = value
                if transform in ('keep', 'path', 'basename', 'sid'):
                    rewritable.append((fields, name, event_type + ' ' + name))
        else:
            metadata_counts[event_type] = metadata_counts.get(event_type, 0) + 1
            if entry['parse'] in ('unparsed',):
                unparsed_by_source[source_key] = unparsed_by_source.get(source_key, 0) + 1
            if entry['parse'] == 'parsed':
                record = entry['fields'] if spec['parser'] != 'auditd' else {}
                selected, dropped = _select_fields(record, spec['metadata_only'])
                for path in dropped:
                    dropped_fields[path] = dropped_fields.get(path, 0) + 1
                for name, transform, value in selected:
                    if _needs_content(value):
                        continue
                    value = _mask_kept(_structured(names, transform, value, label_base + '.' + name), counters)
                    fields[name] = value
                    rewritable.append((fields, name, event_type + ' ' + name))
        entry_id = names.token('event', 'event', str(entry['line']))
        work['event_id'] = entry_id
        events.append({'event_id': entry_id, 'timestamp_utc': otrf._utc_text(entry['time']),
                       'source_id': source_keys[source_key], 'asset_id': asset_ids[host], 'event_type': event_type,
                       'fields': fields})
    # auditd argv/proctitle reassembly per audit event, with the attack_data allowlist of each audit sourcetype.
    by_source = {}
    for audit in audit_entries:
        by_source.setdefault(audit['work']['source_key'][0], []).append(audit)
    for source, group in sorted(by_source.items()):
        spec = next(s for s in field_map['sourcetypes'].values() if s['source'] == source)
        attackdata._link_argv(group, {'record_types': spec['events'], 'metadata_only': spec['metadata_only']},
                              audit_counters)
        for audit in group:
            for name, value in sorted(audit['content_raw'].items()):
                audit['public_fields'][name] = None
                pending.append((audit['public_fields'], name, value, audit['label'] + '.' + name,
                                source + ':' + audit['record_type'] + ' ' + name, audit['work']))
    content_totals, truncated, passes, secret_paths = _sanitize_pending(pending, names, hosts, encoded_payloads)
    for path, count in secret_paths.items():
        dropped_fields[path] = dropped_fields.get(path, 0) + count
    structured_rewrites = _rewrite_kept(rewritable, names, hosts)
    events.sort(key=lambda e: (e['timestamp_utc'], e['event_id']))

    # records.jsonl is an index of the imported records in original order; fields are published once, in evidence.
    line_of = {}
    for entry in entries:
        line_of[names.token('event', 'event', str(entry['line']))] = entry['line']
    index = sorted(line_of.items(), key=lambda item: item[1])
    records = b''.join(canonical_bytes({'event_id': event_id, 'line': line}) + b'\n' for event_id, line in index)
    records_sha = digest_bytes(records)
    for event in events:
        event['locator'] = {'file_sha256': records_sha, 'record_id': str(line_of[event['event_id']])}

    sources, gaps = [], []
    # Public text never names the SIEM product: `splunk` is also a lab host label (a pseudonymized identity).
    config = ('indexer-assigned _time of a public SIEM index export (%s), UTC; raw-embedded timestamps are not '
              're-derived' % ('search export rendered in MDT' if version == 'v1' else 'epoch seconds'))
    for (source, host), source_id in sorted(source_keys.items(), key=lambda item: item[1]):
        sources.append({'source_id': source_id, 'asset_ids': [asset_ids[host]], 'telemetry': telemetry_of[source],
                        'clock_offset_seconds': 0, 'clock_uncertainty_seconds': 1,
                        'window_utc': window, 'sensor_version': None, 'config_version': config,
                        'completeness': 'partial' if (source, host) in truncated else 'complete',
                        'source_sha256': records_sha})
        if (source, host) in truncated:
            gaps.append({'source_id': source_id, 'asset_id': asset_ids[host], 'window_utc': window,
                         'reason': 'content_truncated: %d content field values exceeded %d bytes; each keeps its '
                                   'first %d bytes and ends with an explicit truncation marker'
                                   % (truncated[(source, host)], MAX_CONTENT_BYTES, MAX_CONTENT_BYTES)})
        if (source, host) in unparsed_by_source:
            gaps.append({'source_id': source_id, 'asset_id': asset_ids[host], 'window_utc': window,
                         'reason': 'unparsed_records: %d records of this source did not match its parser and are '
                                   'published metadata-only (time, type and asset only)'
                                   % unparsed_by_source[(source, host)]})
    gaps.extend(_profile_gaps(scan_result, partition, asset_ids, source_keys, field_map, window))
    gaps.sort(key=lambda g: (g['asset_id'] or '', g['source_id'] or '', g['reason']))

    if curation is not None and 'assessment_windows' in curation:
        if type(curation['assessment_windows']) is not list or not curation['assessment_windows']:
            _fail('invalid_array', 'curation.assessment_windows')
        windows = [otrf._window_tuple(w, 'curation.assessment_windows', partition)
                   for w in curation['assessment_windows']]
        if len(set(windows)) != len(windows):
            _fail('duplicate_item', 'curation.assessment_windows')
    else:
        windows = [partition]
    questions = []
    for asset in assets:
        for item in windows:
            normal = otrf._normal_window(item)
            questions.append({'question_id': names.token('question', 'question', asset['asset_id'] +
                                                         canonical_bytes(normal).decode('utf-8')),
                              'asset_id': asset['asset_id'], 'window_utc': normal, 'question': ASSESSMENT_QUESTION})
    questions.sort(key=lambda q: q['question_id'])
    bundle = {'schema_version': 1, 'case_id': case_id, 'window_utc': window, 'assets': assets, 'sources': sources,
              'events': events, 'known_gaps': gaps,
              'files': [{'path': 'records.jsonl', 'byte_count': len(records), 'sha256': records_sha}],
              'assessment_questions': questions}
    validate_public_bundle(bundle)
    public_bytes = canonical_bytes(bundle)
    _leak_check(bundle, records, names, hosts)
    from benchmark_corpus import prompt_projection_bytes
    prompt_bytes = prompt_projection_bytes(bundle, {'records.jsonl': records})
    if max_public_bytes is not None and prompt_bytes > max_public_bytes:
        _fail('public_bundle_too_large', 'partition')
    manifest_sha = digest_bytes(public_bytes)

    imported = {}
    for entry in entries:
        event_id = names.token('event', 'event', str(entry['line']))
        imported[entry['line']] = {'line': entry['line'], 'line_sha256': entry['line_sha256'], 'status': 'imported',
                                   'event_id_public': event_id, 'channel': entry['sourcetype'],
                                   'host': entry['host'], 'record_id': entry['record_id'], 'time': entry['time']}
    by_line = _BotsLines(imported, scan_result['file_count'])
    by_record = {}
    for item in imported.values():
        if item['record_id'] is not None:
            by_record.setdefault(item['record_id'], []).append(item)
    member = 'splunk-bots-%s-export' % version
    locators = {'schema_version': 1, 'dataset_sha256': dataset_sha, 'member': member, 'member_sha256': dataset_sha,
                'records_sha256': records_sha, 'record_shape': 'splunk-bots-' + version,
                'line_encoding': 'file_number * %d + record ordinal (file_number = 1-based position in the sorted '
                                 'file list of descriptor.files)' % LINE_STRIDE,
                'events': {item['event_id_public']: {'line': item['line'], 'line_sha256': item['line_sha256'],
                                                     'record_id': item['record_id'], 'channel': item['channel'],
                                                     'hostname': item['host'],
                                                     'file': scan_result['descriptor']['files'][
                                                         item['line'] // LINE_STRIDE - 1]['name'],
                                                     'ordinal': item['line'] % LINE_STRIDE}
                           for item in imported.values()}}
    scenario_key = {'window_utc': window, 'profile': scan_result['profile']}
    compound = {'profile': None, 'family_id': scan_result['family_id'],
                'scenario_id': scan_result['family_id'] + '-p' + digest_bytes(canonical_bytes(scenario_key))[:12]}
    report = {
        'schema_version': 1, 'importer_version': IMPORTER_VERSION,
        'status': 'curated' if curation is not None else otrf.DRAFT_MARKER,
        'split': 'development', 'provenance': 'public_replay',
        'dataset': {'descriptor': scan_result['descriptor'], 'sha256': dataset_sha,
                    'files_read': scan_result['files_read'], 'files_not_read': scan_result['files_not_read']},
        'metadata': {'file': 'provenance.json', 'sha256': metadata_sha},
        'field_map': {'version': field_map['version'], 'sha256': field_map['sha256'],
                      'external': field_map['external']},
        'sanitizer': {'module': 'benchmark_sanitize', 'max_bytes': MAX_CONTENT_BYTES, 'passes': passes,
                      'fields': content_totals,
                      'truncated_values': sum(item['truncated'] for item in content_totals.values()),
                      'structured_identity_rewrites': structured_rewrites,
                      'attack_masked_kept_values': counters.get('attack_masked_kept', 0)},
        'license': LICENSE, 'contamination': CONTAMINATION,
        'assumptions': {'encoded_payloads': encoded_payloads,
                        'clock': {'offset_seconds': 0, 'uncertainty_seconds': 1,
                                  'note': config},
                        'asset_facts': 'curation file' if curation is not None else
                                       'draft default OS per host derived from its sourcetypes; unverified'},
        'counts': {'imported_events': len(events),
                   'imported_by_type': dict(sorted(imported_counts.items())),
                   'metadata_only_by_type': dict(sorted(metadata_counts.items())),
                   'dropped_fields': dict(sorted(dropped_fields.items())),
                   'unparsed_by_sourcetype': _count_by_sourcetype(entries, 'unparsed'),
                   'unknown_sourcetypes': _count_by_sourcetype(entries, 'unknown_sourcetype'),
                   'audit_argv': dict(sorted(audit_counters.items())),
                   'assets': len(assets), 'sources': len(sources), 'known_gaps': len(gaps),
                   'assessment_questions': len(questions)},
        'public_bytes': {'evidence.json': len(public_bytes), 'records.jsonl': len(records),
                         'prompt_projection': prompt_bytes, 'max_public_bytes': max_public_bytes},
        'partition': {'window_utc': window, 'scan_window_utc': otrf._normal_window(scan_result['window']),
                      'imported_records': len(entries)},
        'collection_profile': _profile_report(scan_result, partition),
        'evidence_manifest_sha256': manifest_sha, 'case_id': case_id}
    outputs = {'public/evidence.json': public_bytes, 'public/records.jsonl': records,
               'evaluator/locators.json': canonical_bytes(locators),
               'evaluator/pseudonyms.json': canonical_bytes({'schema_version': 1, 'mapping': names.mapping}),
               'evaluator/salt.json': canonical_bytes({'schema_version': 1, 'salt_hex': salt.hex()})}
    by_event = {e['event_id']: e for e in events}
    if curation is None:
        draft_truth = {'schema_version': 1, 'status': otrf.DRAFT_MARKER, 'case_id': case_id,
                       'evidence_manifest_sha256': manifest_sha, 'truth_revision': 0, 'attack_release': None,
                       'steps': [], 'edges': [], 'controls': [],
                       'assessment_labels': {q['question_id']: None for q in questions}}
        otrf._refuse_draft_check(draft_truth, bundle)
        outputs['evaluator/truth.DRAFT.json'] = canonical_bytes(draft_truth)
        outputs['evaluator/curation-template.json'] = canonical_bytes(
            _template(scan_result, dataset_sha, metadata_sha, hosts, facts, imported, by_event, window))
        report['counts']['steps'] = 0
        outputs['evaluator/import-report.json'] = canonical_bytes(report)
        return case_id, outputs
    otrf._check_compound_curation(curation, partition, None)
    curated_input = json.loads(json.dumps(curation))
    soph = curated_input.get('sophistication')
    if type(soph) is dict and type(soph.get('emulation_limitations')) is list:
        soph['emulation_limitations'] = soph['emulation_limitations'] + _limitations(scan_result, partition)
    metadata = {'id': scan_result['family_id'], 'techniques': [], 'links': [SOURCE_REFERENCES[version]]}
    truth, scenario, curated = otrf._curated(curated_input, metadata, bundle, events, by_line, by_record, hosts,
                                             asset_ids, partition, dataset_sha, member,
                                             coverage if coverage is not None else load_json(DEFAULT_COVERAGE),
                                             compound)
    report['curation'] = dict(curated, sha256=digest_bytes(curation_bytes))
    report['counts']['steps'] = len(truth['steps'])
    outputs['evaluator/truth.json'] = canonical_bytes(truth)
    outputs['evaluator/curation.json'] = curation_bytes
    outputs['scenario.json'] = canonical_bytes(scenario)
    outputs['evaluator/import-report.json'] = canonical_bytes(report)
    return case_id, outputs


def _count_by_sourcetype(entries, status):
    counts = {}
    for entry in entries:
        if entry['parse'] == status:
            counts[entry['sourcetype']] = counts.get(entry['sourcetype'], 0) + 1
    return dict(sorted(counts.items()))


def _in_partition_counts(scan_result, partition, key):
    """{(host, sourcetype): count} of the records the profile excluded inside `partition` (exact per record time)."""
    counts = {}
    for (moment, host, sourcetype), count in scan_result[key].items():
        if partition[0] <= moment < partition[1]:
            counts[(host, sourcetype)] = counts.get((host, sourcetype), 0) + count
    return counts


def _profile_gaps(scan_result, partition, asset_ids, source_keys, field_map, window):
    gaps = []
    for host, asset_id in sorted(asset_ids.items()):
        gaps.append({'source_id': None, 'asset_id': asset_id, 'window_utc': window,
                     'reason': 'outside_partition_window: records of this asset outside the declared partition window '
                               'were excluded; nothing inside the window was sampled'})
    profile = scan_result['profile']
    if profile['sourcetypes'] is not None or profile['exclude_sourcetypes'] is not None:
        grouped = {}
        for (host, sourcetype), count in _in_partition_counts(scan_result, partition, 'excluded_sourcetypes').items():
            if host in asset_ids:
                grouped.setdefault(host, {})[sourcetype] = count
        for host, types in sorted(grouped.items()):
            gaps.append({'source_id': None, 'asset_id': asset_ids[host], 'window_utc': window,
                         'reason': 'collection_profile_filter: %d records of this asset inside the window are '
                                   'sourcetypes outside the declared collection profile and were excluded (%s)'
                                   % (sum(types.values()),
                                      ', '.join('%s x%d' % (name, types[name]) for name in sorted(types)))})
    hosts_excluded = _in_partition_counts(scan_result, partition, 'excluded_hosts')
    if hosts_excluded:
        gaps.append({'source_id': None, 'asset_id': None, 'window_utc': window,
                     'reason': 'collection_profile_filter: %d records of %d hosts outside the declared host profile '
                               'inside the window were excluded'
                               % (sum(hosts_excluded.values()), len({host for host, _ in hosts_excluded}))})
    if scan_result['files_not_read']:
        gaps.append({'source_id': None, 'asset_id': None, 'window_utc': window,
                     'reason': 'collection_profile_filter: export files of sourcetypes outside the declared profile '
                               'were not read (%s); their records in the window are not counted'
                               % ', '.join(sorted(item['sourcetype'] for item in scan_result['files_not_read']))})
    return gaps


def _profile_report(scan_result, partition):
    def listed(counts):
        out = {}
        for (host, sourcetype), count in sorted(counts.items()):
            out.setdefault(host, {})[sourcetype] = count
        return out
    return {'declared': scan_result['profile'],
            'excluded_sourcetypes_by_host': listed(_in_partition_counts(scan_result, partition,
                                                                        'excluded_sourcetypes')),
            'excluded_hosts': listed(_in_partition_counts(scan_result, partition, 'excluded_hosts')),
            'files_not_read': scan_result['files_not_read']}


def _limitations(scan_result, partition):
    window = otrf._normal_window(partition)
    profile = scan_result['profile']
    text = ['Splunk BOTS %s export, incident group %s: partition %s to %s; records outside it are excluded '
            '(outside_partition_window known gaps). Event time is the Splunk-assigned _time.'
            % (scan_result['version'], scan_result['incident'], window['start_inclusive'], window['end_exclusive'])]
    if profile['hosts'] is not None or profile['sourcetypes'] is not None or profile['exclude_sourcetypes'] is not None:
        parts = []
        if profile['hosts'] is not None:
            parts.append('%d declared hosts' % len(profile['hosts']))
        if profile['sourcetypes'] is not None:
            parts.append('sourcetypes ' + ', '.join(profile['sourcetypes']))
        if profile['exclude_sourcetypes'] is not None:
            parts.append('all sourcetypes except ' + ', '.join(profile['exclude_sourcetypes']))
        text.append('Declared collection profile (%s): other records inside the window are excluded and stated as '
                    'collection_profile_filter known gaps.' % '; '.join(parts))
    if BACKGROUND_LIMITATION[scan_result['version']]:
        text.append(BACKGROUND_LIMITATION[scan_result['version']])
    return text


def _template(scan_result, dataset_sha, metadata_sha, hosts, facts, imported, by_event, window):
    candidates = []
    for item in sorted(imported.values(), key=lambda e: (e['time'], e['line'])):
        event = by_event[item['event_id_public']]
        candidates.append({'line': item['line'], 'record_id': item['record_id'], 'channel': item['channel'],
                           'hostname': item['host'], 'event_id': event['event_id'],
                           'timestamp_utc': event['timestamp_utc'], 'event_type': event['event_type']})
    return {
        'NOT_VALID_FOR_SCORING': 'Curation template. Every null and empty list must be decided by a curator from the '
                                 'original records. Nothing here is truth.',
        'instructions': [
            'Copy "curation" to a new file and fill it in; do not edit this template in place.',
            'A support set lists records that TOGETHER prove the step: {"line": N} (the global line from '
            'public/records.jsonl and candidate_events), or {"record_id": "ID", "channel": "<sourcetype>", '
            '"hostname": "<host>"} with the record\'s own ID (Windows RecordNumber/EventRecordID, CloudTrail eventID, '
            '...); {"record_id": "ID"} alone only when that ID is unique in this partition.',
            'Keep partition_window exactly as written: it must equal the case window. Do not add collection_profile '
            'or family_id (the profile and incident are bound through dataset_sha256).',
            'Every asset x assessment window needs a step or a control (benign or insufficient).',
            'Steps cite only records present here; use observability insufficient when telemetry is missing. '
            'Technique IDs are canonicalised by benchmark_attack.canonical_technique.',
            'Re-run `benchmark_import_bots.py case` with --curation and the same --salt-file to keep IDs stable.'],
        'selection': scan_result['descriptor'],
        'hosts': hosts,
        'candidate_events': candidates,
        'curation': {
            'schema_version': 1, 'dataset_sha256': dataset_sha, 'metadata_sha256': metadata_sha,
            'curated_by': None, 'curated_utc': None, 'note': None, 'revision': 1, 'truth_revision': 1,
            'attack_release': None,
            'coverage': {axis: [] for axis in COVERAGE_AXES},
            'assets': [{'hostname': host, 'os_family': facts[host]['os_family'], 'os_version': None,
                        'architecture': None, 'vendor': None} for host in hosts],
            'steps': [], 'edges': [], 'controls': [], 'lookalike_event_ids': [],
            'sophistication': {'band': None, 'boundaries': [{'boundary_id': 'boundary-host', 'kind': 'host'}],
                               'preconditions': [], 'emulation_limitations': [], 'group_ids': [],
                               'source_references': []},
            'source_references': [SOURCE_REFERENCES[scan_result['version']]],
            'assessment_windows': [window],
            'partition_window': window}}


# ----------------------------------------------------------------- planning

def _measured_prompt_bytes(scan_result, field_map, salt, start, end):
    _, outputs = build_case(scan_result, field_map, salt, (start, end), draft=True, max_public_bytes=None)
    return decode_json(outputs['evaluator/import-report.json'])['public_bytes']['prompt_projection']


def _window_stats(scan_result, start, end):
    kept = [e for e in scan_result['entries'] if start <= e['time'] < end]
    hosts = {}
    for entry in kept:
        hosts[entry['host'].casefold()] = hosts.get(entry['host'].casefold(), 0) + 1
    return {'records': len(kept), 'raw_bytes': sum(e['raw_bytes'] for e in kept), 'records_by_host': hosts}


def plan(scan_result, field_map, max_public_bytes=MAX_PUBLIC_BYTES, salt=None):
    """Fewest contiguous whole-second partitions of the scanned window that each fit the prompt cap (greedy, binary
    search on measured sizes). A single second too large to publish is `unpublishable` (stated, never sampled)."""
    if type(max_public_bytes) is not int or not 0 < max_public_bytes <= MAX_PUBLIC_BYTES:
        _fail('invalid_limit', 'max_public_bytes')
    salt = secrets.token_bytes(otrf.SALT_BYTES) if salt is None else salt
    start, end = scan_result['window']
    second = timedelta(seconds=1)
    cuts = sorted({e['time'].replace(microsecond=0) + second for e in scan_result['entries']} | {end})
    cuts = [cut for cut in cuts if start < cut <= end]
    intervals = []
    while start < end:
        options = [cut for cut in cuts if cut > start]
        if not any(start <= e['time'] < end for e in scan_result['entries']):
            if intervals:
                intervals[-1].update(end=end, prompt_bytes=None)
            break
        low, high, best = 0, len(options) - 1, None
        while low <= high:
            middle = (low + high) // 2
            try:
                size = _measured_prompt_bytes(scan_result, field_map, salt, start, options[middle])
            except BenchmarkError as error:
                if error.code != 'no_supported_records':
                    raise
                size = 0
            if size <= max_public_bytes:
                best, low = (options[middle], size), middle + 1
            else:
                high = middle - 1
        if best is None:
            intervals.append({'start': start, 'end': options[0], 'prompt_bytes': None, 'publishable': False})
            start = options[0]
            continue
        intervals.append({'start': start, 'end': best[0], 'prompt_bytes': best[1], 'publishable': True})
        start = best[0]
    partitions, unpublishable = [], []
    for item in intervals:
        if item['prompt_bytes'] is None:
            item['prompt_bytes'] = _measured_prompt_bytes(scan_result, field_map, salt, item['start'], item['end'])
            if item['publishable'] and item['prompt_bytes'] > max_public_bytes:
                item['publishable'] = False
        stats = dict(_window_stats(scan_result, item['start'], item['end']),
                     window_utc=otrf._normal_window((item['start'], item['end'])), prompt_bytes=item['prompt_bytes'])
        (partitions if item['publishable'] else unpublishable).append(stats)
    return {'schema_version': 1, 'importer_version': IMPORTER_VERSION, 'version': scan_result['version'],
            'incident': scan_result['incident'], 'window_utc': otrf._normal_window(scan_result['window']),
            'profile': scan_result['profile'], 'dataset_sha256': scan_result['dataset_sha256'],
            'max_public_bytes': max_public_bytes, 'totals': _window_stats(scan_result, *scan_result['window']),
            'excluded_by_profile': _profile_report(scan_result, scan_result['window']),
            'unparsed_by_sourcetype': _count_by_sourcetype(scan_result['entries'], 'unparsed'),
            'unknown_sourcetypes': _count_by_sourcetype(scan_result['entries'], 'unknown_sourcetype'),
            'files_read': scan_result['files_read'], 'partitions': partitions, 'unpublishable': unpublishable}


# ---------------------------------------------------------------------- CLI

def _arguments(parser):
    parser.add_argument('--version', required=True, choices=sorted(VERSIONS), help='BOTS version')
    parser.add_argument('--data', required=True, help='the version\'s data directory (holds provenance.json and the '
                                                      'json/ or botsv<N>-export/ folder)')
    parser.add_argument('--incident', required=True,
                        help='incident group slug ([a-z0-9-], up to 40); every partition of one incident is one '
                             'bootstrap family bots-<version>-<incident>')
    parser.add_argument('--window-start', required=True, help='UTC with offset, inclusive (Splunk _time)')
    parser.add_argument('--window-end', required=True, help='UTC with offset, exclusive')
    parser.add_argument('--host', action='append', dest='hosts', help='collection profile: keep only this host '
                                                                      '(repeatable, case-insensitive)')
    profile = parser.add_mutually_exclusive_group()
    profile.add_argument('--sourcetype', action='append', dest='sourcetypes',
                         help='collection profile: keep only this sourcetype (repeatable)')
    profile.add_argument('--exclude-sourcetype', action='append', dest='exclude_sourcetypes',
                         help='collection profile: drop this sourcetype (repeatable)')
    parser.add_argument('--max-public-bytes', type=int, default=MAX_PUBLIC_BYTES,
                        help='cap on the prompt projection (evidence + records.jsonl); at most 1 MiB')
    parser.add_argument('--fields', default=str(DEFAULT_FIELDS), help='field allowlist JSON')


def _new_target(path):
    target = Path(os.path.abspath(path))
    if otrf._in_source(target.resolve()):
        _fail('output_in_source_tree', 'output')
    if os.path.lexists(target):
        _fail('output_exists', 'output')
    if not target.parent.is_dir():
        _fail('invalid_directory', 'output')
    return target


def _scan_args(args, field_map):
    return scan(args.version, args.data, field_map, (args.window_start, args.window_end), args.incident,
                args.hosts, args.sourcetypes, args.exclude_sourcetypes)


def plan_main(argv):
    parser = argparse.ArgumentParser(
        prog='benchmark_import_bots.py plan',
        description='Scan one BOTS window under a declared collection profile and split it into the fewest '
                    'contiguous whole-second partitions that fit the prompt cap. Writes a NEW plan JSON.')
    _arguments(parser)
    parser.add_argument('--output', required=True, help='NEW plan JSON file outside the source tree')
    args = parser.parse_args(argv)
    try:
        target = _new_target(args.output)
        field_map = load_field_map(args.fields)
        result = plan(_scan_args(args, field_map), field_map, args.max_public_bytes)
        with open(target, 'xb') as handle:
            handle.write(canonical_bytes(result))
    except BenchmarkError as error:
        print('error: {}: {}'.format(error.code, error.field), file=sys.stderr)
        return 2
    sys.stdout.write(canonical_bytes({'output': str(target), 'records': result['totals']['records'],
                                      'partitions': len(result['partitions']),
                                      'unpublishable': len(result['unpublishable'])}).decode('utf-8') + '\n')
    return 0


def case_main(argv):
    parser = argparse.ArgumentParser(
        prog='benchmark_import_bots.py case',
        description='Import ONE explicit UTC partition of a BOTS export as a DEVELOPMENT case (draft or curated).')
    _arguments(parser)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--curation', help='curation JSON (proposal, consensus or signed) with the same partition_window')
    mode.add_argument('--draft', action='store_true', help='emit a draft (NOT VALID FOR SCORING) and template')
    parser.add_argument('--output', required=True, help='NEW directory; must not exist')
    parser.add_argument('--salt-file', help='evaluator/salt.json from the draft of the same partition')
    parser.add_argument('--coverage', default=str(DEFAULT_COVERAGE), help='coverage catalog JSON')
    parser.add_argument('--encoded-payloads', choices=ENCODED_PAYLOAD_MODES, default='preview')
    args = parser.parse_args(argv)
    try:
        _new_target(args.output)
        salt = otrf.load_salt(args.salt_file) if args.salt_file else secrets.token_bytes(otrf.SALT_BYTES)
        field_map = load_field_map(args.fields)
        coverage = load_json(args.coverage) if args.curation else None
        scan_result = _scan_args(args, field_map)
        case_id, outputs = build_case(scan_result, field_map, salt, scan_result['window'],
                                      curation_path=args.curation, draft=args.draft, coverage=coverage,
                                      encoded_payloads=args.encoded_payloads, max_public_bytes=args.max_public_bytes)
        case_dir = otrf.write_outputs(args.output, case_id, outputs)
    except BenchmarkError as error:
        print('error: {}: {}'.format(error.code, error.field), file=sys.stderr)
        return 2
    report = decode_json(outputs['evaluator/import-report.json'])
    summary = {'case_id': case_id, 'case_directory': str(case_dir), 'status': report['status'],
               'imported_events': report['counts']['imported_events'], 'assets': report['counts']['assets'],
               'public_bytes': report['public_bytes'], 'partition': report['partition']['window_utc']}
    if report['status'] == otrf.DRAFT_MARKER:
        summary['warning'] = 'DRAFT: truth.DRAFT.json is NOT VALID FOR SCORING; curate before use.'
    otrf._summarize_attestation(report, summary)
    sys.stdout.write(canonical_bytes(summary).decode('utf-8') + '\n')
    return 0


def main(argv=None):
    argv = sys.argv[1:] if argv is None else list(argv)
    if argv[:1] == ['plan']:
        return plan_main(argv[1:])
    if argv[:1] == ['case']:
        return case_main(argv[1:])
    print('usage: benchmark_import_bots.py {plan|case} --help', file=sys.stderr)
    return 2


if __name__ == '__main__':
    sys.exit(main())

"""Offline, fail-closed materialization of independent sensor evidence.

API: materialize_evidence(private_root, manifest, snapshots, field_rules, mapping,
public_destination, *, phase_windows, private_markers) returns the strict public
evidence manifest. The caller holds exclusive campaign ownership and authorizes the
exact collector receipts; this module never discovers files or grants a model
release. private_root is an absolute campaign directory. public_destination is a
NEW directory below its public/ child.

snapshots is an exact list, one per frozen collector, of {source_id, path, sha256,
byte_count, exercise}. path/sha256/byte_count name the final (post-cleanup) driver
result raw/<sha256>.json; exercise is null or the {path, sha256, byte_count} of the
latest pre-cleanup driver result for the same collector. Each file is the actual
six-field driver result containing exactly one raw_exports entry {source_id,
records, window_utc, watermark_utc, complete, filter}. Original bytes are copied
and hashed in sealing/snapshots BEFORE JSON/XML normalization. Every exercise
record must be present, byte-identical, in the final export (same record identity
and canonical content); otherwise incomplete_export. Records lost between the two
collections are never silently dropped. The export byte budget is the SUM of
canonical export bytes over every final and exercise export, as in the controller.

Export filters are pinned: Windows exports carry {"event_ids": {channel:
supported_event_ids(channel)}} for exactly the declared channels, CloudTrail
exports carry {"event_names": supported_cloudtrail_events()}, journald/audit/Zeek
exports carry null. Any other recorded filter, or a record outside the recorded
filter, is filter_mismatch. Only records inside the filter are interpreted; one
inside the filter whose channel/provider/schema is not mapped is refused as
unsupported_source_schema, never sampled away.

mapping has exactly schema_version (integer 1), case_id (case-[a-f0-9]{4,32}),
assets, entity_aliases, known_gaps, assessment_windows, max_public_bytes.
assets contains exactly one {target_id,os_family,os_version,architecture,vendor}
per enrolled target; optional facts are null or bounded simple version tokens.
entity_aliases contains {kind,values}, with >=2 distinct nonempty strings per
entry, no overlap within a namespace. Kinds: host,account,address,domain,key,
process,session,service,resource. Host and DNS names share ONE namespace (DNS is
case-insensitive, so ASCII case and a trailing root dot are normalized), so an
FQDN query correlates with that host's events. IPv4-mapped IPv6 addresses
normalize to IPv4 and other IPv6 addresses to their exploded form. Otherwise
aliases are explicit: SID/name equivalence is never guessed. HMAC-SHA256
pseudonyms bind namespace and value using a persisted random campaign salt.
Host-local identifiers (LogonId, PipelineId, audit uid/auid/ses, journald
_UID/_BOOT_ID) also bind the public asset ID, so equal values on different
assets never correlate unless an explicit alias entry links them.

known_gaps entries are {source_id,target_id,reason}; allowed reasons are
missing_audit_export (Linux collectors; attached only to the linux-audit source,
whose completeness becomes unknown) and process_instrumentation_absent (Windows
collectors declaring neither Security nor Sysmon; attached to the asset with no
source). Each must also occur in the successful collector's safe evidence.gaps.
Verified gaps are added even if omitted from the mapping. A collector reporting
process_events_absent (process sources configured yet no process events) or any
other reason is an incomplete export and always fails.
assessment_windows is a nonempty unique list of strict UTC half-open windows,
contained in the normalized union window. Questions cover every assessed asset x
window; Zeek sensors are enrolled, non-assessed assets (unassessed_asset_ids).
max_public_bytes is a positive integer <=1 MiB and <=campaign max_export_bytes;
it bounds the SUM of evidence.json and records.jsonl, not just their payloads.

field_rules is the pinned collector-fields-2 schema: {schema_version,version,
sources}, source entries {format,allowed_fields,pseudonym_fields,basename_fields,
content_fields,supported_event_types}. pseudonym_fields MUST equal allowed_fields
that this module pseudonymizes, basename_fields MUST equal allowed_fields reduced
to a program basename and content_fields MUST equal allowed_fields kept as
free text after benchmark_sanitize.sanitize_text (the `content` transform:
secrets redacted, identities mapped onto this campaign's pseudonym namespaces,
ATT&CK tokens masked, bounded with an explicit truncation marker and a
content_truncated known gap), so the kit documents the actual transformation.
Journald MESSAGE is content only for _TRANSPORT=audit records; otherwise dropped.
Windows Event XML uses
the Microsoft event namespace, exact System metadata, allowlisted
channel/provider/event combinations and named EventData; "-" is Windows' absent
value. The Security channel declares identity-audit only for targets enrolled with
identity.domain_controller true. PowerShell (both channels), TaskScheduler, WMI-Activity
and System sources make no coverage-catalog telemetry claim (telemetry null). Journald requires
cursor/realtime metadata; audit is the worker's timestamped JSON, NOT arbitrary
audit text. Zeek is the controller's stream/record/file_sha256/record_id wrapper:
the collector's target is the sensor itself (own clock, never another collector's
endpoint) and events are attributed through the collector's explicit
config.address_assets enrolment (originator, then responder, else the sensor).
CloudTrail supports version 1.x and only the pinned API events with matching
service. Unrestricted extra raw fields are discarded, never copied.
Sysmon RuleName is a special detector-only channel: extract exact ATT&CK tokens,
never its surrounding prose; presence of detector_attack_ids denotes the separate
with_detector_alerts condition. The manifest itself has no extra condition field.

phase_windows is a list of {phase, window_utc} with phase in warmup/exercise/
cleanup (each at most once); it is frozen as the evaluator-only private record
sealing/phase-windows.json and never published. private_markers lists private
strings (for example the AWS correlation ID) that, like the campaign ID, recipe
ID, target IDs and source IDs, must not occur in public bytes.

Outputs are canonical evidence.json and newline-delimited sanitized records.jsonl.
Locators identify the latter's content hash and actual 1-based line number. Private
sealing/identity.json contains {schema_version,mapping_sha256,salt_hex}; it is
written first, then the full mapping sealing/mapping.json, so a crash between them
is recoverable. This binding is frozen after the first successful seal. Failed
normalization may retain private snapshots but never publishes a partial public
bundle. New destinations are mandatory.
Timestamps retain their original source representation; normalized time subtracts
the enrolled clock offset. Normalized source windows are shifted identically.
Sub-microsecond precision is retained in timestamp_original and adds one
microsecond to the source uncertainty. Source hashes refer to private snapshots.
Human inspection/release is REQUIRED: pseudonymization is not declassification.
"""
import datetime as dt
import hashlib
import hmac
import ipaddress
import math
import os
from pathlib import Path
import re
import secrets
import stat
import xml.etree.ElementTree as ET

from benchmark_contracts import (BenchmarkError, COVERAGE_AXES, canonical_bytes,
    confined_file, decode_json, digest_bytes, parse_utc, validate_public_bundle,
    _fields, _window)
from benchmark_sanitize import sanitize_text, scan_leaks

KINDS = {'host', 'account', 'address', 'domain', 'key', 'process', 'session', 'service', 'resource'}
NAME_KINDS = {'host', 'domain'}
GAPS = {'missing_audit_export': 'linux', 'process_instrumentation_absent': 'windows'}
PHASES = ('warmup', 'exercise', 'cleanup')
# Driver-result metadata allowance beyond the export budget, as in the controller.
FILE_METADATA_BYTES = 1024 * 1024
QUESTION = 'Does the supplied evidence support suspicious activity on this asset in this window?'
NS = '{http://schemas.microsoft.com/win/2004/08/events/event}'
FORMATS = {'windows-security': 'windows-event-xml-v1', 'sysmon': 'windows-event-xml-v1',
    'identity-audit': 'windows-event-xml-v1', 'windows-powershell': 'windows-event-xml-v1',
    'windows-powershell-classic': 'windows-event-xml-v1', 'windows-taskscheduler': 'windows-event-xml-v1',
    'windows-wmi': 'windows-event-xml-v1',
    'windows-system': 'windows-event-xml-v1', 'journald': 'journald-json-v1',
    'linux-audit': 'linux-audit-json-v1', 'zeek-conn': 'zeek-json-v1',
    'zeek-dns': 'zeek-json-v1', 'zeek-http': 'zeek-json-v1', 'cloud-audit': 'cloudtrail-json-v1'}
EVENTS = {'windows-security': {'4688','4624','4625','4627','4798','4799'}, 'sysmon': {'1','3','13','22'},
    'identity-audit': {'4768','4769','4771','4662'},
    'windows-powershell': {'4103','4104','4105','4106','40961','40962','53504'},
    'windows-powershell-classic': {'400','403','600','800'},
    'windows-taskscheduler': {'100','102','106','110','129','140','141','200','201'},
    'windows-wmi': {'5857','5858','5859','5860','5861'},
    'windows-system': {'7036'}, 'journald': {'journal_record'},
    'linux-audit': {'SYSCALL','EXECVE','USER_LOGIN','USER_START','USER_END'},
    'zeek-conn': {'conn'}, 'zeek-dns': {'dns'}, 'zeek-http': {'http'},
    'cloud-audit': {'StopLogging','StartLogging','CreateTrail','DeleteTrail','GetTrailStatus',
                    'CreateBucket','DeleteBucket','PutBucketPolicy','GetCallerIdentity'}}
# Windows channel -> (only accepted provider, sources it can carry).
CHANNELS = {
    'Security': ('Microsoft-Windows-Security-Auditing', ('windows-security', 'identity-audit')),
    'Microsoft-Windows-Sysmon/Operational': ('Microsoft-Windows-Sysmon', ('sysmon',)),
    'Microsoft-Windows-PowerShell/Operational': ('Microsoft-Windows-PowerShell', ('windows-powershell',)),
    'Windows PowerShell': ('PowerShell', ('windows-powershell-classic',)),
    'Microsoft-Windows-TaskScheduler/Operational': ('Microsoft-Windows-TaskScheduler', ('windows-taskscheduler',)),
    'Microsoft-Windows-WMI-Activity/Operational': ('Microsoft-Windows-WMI-Activity', ('windows-wmi',)),
    'System': ('Service Control Manager', ('windows-system',))}
# The classic Windows PowerShell channel writes unnamed positional EventData.
CLASSIC_DATA = {'400': ('NewEngineState', 'PreviousEngineState', 'HostDetails'),
    '403': ('NewEngineState', 'PreviousEngineState', 'HostDetails'),
    '600': ('ProviderName', 'NewProviderState', 'HostDetails'),
    '800': ('CommandLine', 'HostDetails', 'PipelineDetails')}
# Events whose XML legitimately carries no EventData element.
NO_EVENT_DATA = {'40961', '40962'}
# No coverage-catalog telemetry value describes PowerShell/System/TaskScheduler/WMI channels.
TELEMETRY = {'windows-security': 'windows-security', 'identity-audit': 'identity-audit',
    'sysmon': 'sysmon', 'windows-powershell': None, 'windows-powershell-classic': None,
    'windows-taskscheduler': None, 'windows-wmi': None, 'windows-system': None,
    'journald': 'journald', 'linux-audit': 'linux-audit', 'zeek-conn': 'zeek',
    'zeek-dns': 'dns', 'zeek-http': 'zeek', 'cloud-audit': 'cloud-audit'}
ENTITY_FIELDS = {
    'SubjectUserSid':'account', 'SubjectUserName':'account', 'TargetUserSid':'account',
    'TargetUserName':'account', 'SubjectDomainName':'domain', 'TargetDomainName':'domain',
    'IpAddress':'address', 'LogonId':'session', 'ProcessGuid':'process', 'ParentProcessGuid':'process',
    'User':'account', 'SourceIp':'address', 'DestinationIp':'address', 'ServiceName':'service',
    'ObjectName':'resource', 'RunspaceId':'session', 'PipelineId':'session', 'param1':'service',
    'TargetSid':'account', 'TargetLogonId':'session', 'ScriptBlockId':'session', 'QueryName':'domain',
    'UserContext':'account', 'UserName':'account', 'TaskInstanceId':'session', 'ClientMachine':'host',
    '_UID':'account', '_SYSTEMD_UNIT':'service', '_BOOT_ID':'session', '_MACHINE_ID':'host',
    'uid':'account', 'auid':'account', 'ses':'session', 'id.orig_h':'address',
    'id.resp_h':'address', 'query':'domain', 'host':'domain', 'eventID':'record',
    'sourceIPAddress':'address', 'userIdentity.principalId':'account', 'userIdentity.arn':'account',
    'userIdentity.accountId':'account', 'userIdentity.accessKeyId':'key',
    'requestParameters.name':'resource', 'requestParameters.trailName':'resource',
    'requestParameters.bucketName':'resource', 'resources':'resource', 'answers':'domain',
    'errorCode':'error'}
# Identifiers only unique on one host; Linux audit `uid` is host-local, Zeek `uid` is not.
HOST_LOCAL = {'LogonId', 'TargetLogonId', 'PipelineId', 'ses', 'auid', '_UID', '_BOOT_ID'}
BASENAMES = {'NewProcessName','ParentProcessName','Image','ParentImage','CallerProcessName',
    '_COMM','_EXE','exe','comm','SYSLOG_IDENTIFIER'}
# Free-text evidence (command lines, script text, payloads, query results, registry
# values, user agents, request parameters): kept after benchmark_sanitize.sanitize_text.
CONTENT_FIELDS = {'CommandLine','ParentCommandLine','CurrentDirectory','ScriptBlockText','Payload',
    'ContextInfo','Path','QueryResults','Details','TargetObject','EventType','GroupMembership',
    'NewEngineState','PreviousEngineState','NewProviderState','ProviderName','HostDetails',
    'PipelineDetails','TaskName','ActionName','Operation','Namespace','ESS','CONSUMER',
    'PossibleCause','Query','HostProcess','ProviderPath','_CMDLINE','MESSAGE','argv',
    'userAgent','requestParameters','errorMessage'}
# Identity kinds whose raw values are replaced by their structured pseudonym inside
# content before sanitize_text runs (session/process/record IDs are left alone).
CONTENT_IDENTITY_KINDS = {'account','domain','host','address','key','resource','service'}
# benchmark_sanitize pseudonymizer kinds -> this sealer's per-campaign namespaces.
SANITIZE_KINDS = {'sid':'account', 'user':'account', 'domain':'domain', 'dns':'domain',
    'host':'host', 'ip':'address'}
NUMBERS = {'NewProcessId','CreatorProcessId','ProcessId','ParentProcessId','ProcessID','ThreadID',
    'CallerProcessId','MessageNumber','MessageTotal','EnginePID','ClientProcessId',
    'IpPort','SourcePort','DestinationPort','_PID','PRIORITY','serial','pid','ppid','exit',
    'id.orig_p','id.resp_p','duration','orig_bytes','resp_bytes','missed_bytes','trans_id',
    'status_code','request_body_len','response_body_len','LogonType'}
STATUS_FIELDS = ('Status','SubStatus','TokenElevationType','MandatoryLabel','QueryStatus','ResultCode','Code')
ENUMS = {
    'IntegrityLevel': {'Low','Medium','High','System','AppContainer','Untrusted'},
    'Protocol': {'tcp','udp','icmp','TCP','UDP','ICMP'}, 'proto': {'tcp','udp','icmp','unknown'},
    'Initiated': {'true','false'}, 'success': {'yes','no','success','failed'},
    'param2': {'running','stopped','paused','start pending','stop pending'},
    'method': {'GET','HEAD','POST','PUT','DELETE','OPTIONS','CONNECT','TRACE','PATCH'},
    'conn_state': {'S0','S1','SF','REJ','S2','S3','RSTO','RSTR','RSTOS0','RSTRH','SH','SHR','OTH'},
    'qtype_name': {'A','AAAA','CNAME','PTR','NS','MX','SOA','TXT','SRV','ANY','CAA','HTTPS','SVCB'},
    'rcode_name': {'NOERROR','FORMERR','SERVFAIL','NXDOMAIN','NOTIMP','REFUSED'},
    'userIdentity.type': {'Root','IAMUser','AssumedRole','FederatedUser','AWSService','AWSAccount','IdentityCenterUser','Unknown'},
    'OperationType': {'%%14674','%%14675','%%14676','Object Access'},
}
# Zeek conn.log `service` entries: lowercased built-in protocol/tunnel analyzer names
# plus the script-added data-channel services. A leading "-" marks an analyzer
# removed after a protocol violation. Names outside this set are unmapped schemas.
ZEEK_SERVICES = {'ayiya','bittorrent','bittorrenttracker','dce_rpc','dhcp','dnp3_tcp','dnp3_udp',
    'dns','dtls','finger','ftp','ftp-data','ftp_data','geneve','gnutella','gssapi','gtpv1','http',
    'ident','imap','irc','irc-dcc-data','irc_data','krb','krb_tcp','ldap_tcp','ldap_udp','login',
    'modbus','mount','mqtt','mysql','ncp','netbiosssn','nfs','ntlm','ntp','pop3','portmapper',
    'postgresql','quic','radius','rdp','rdpeudp','redis','rfb','rlogin','rsh','sip','smb','smtp',
    'snmp','socks','ssh','ssl','syslog','telnet','teredo','vxlan','websocket','xmpp'}
SAFE_PROGRAMS = {'id','uname','ps','sshd','systemd','bash','sh','sudo','auditd','hostname',
    'whoami.exe','hostname.exe','powershell.exe','pwsh.exe','cmd.exe','svchost.exe','lsass.exe',
    'services.exe','explorer.exe','python','python3','curl'}


def fail(code='unsupported_source_schema', field='evidence'):
    raise BenchmarkError(code, field)


def exact(value, keys, field='evidence'):
    _fields(value, set(keys), field)


def text(value):
    if type(value) is not str or not value or len(value) > 4096 or any(ord(c) < 32 for c in value):
        fail('invalid_text')
    return value


def number(value):
    if type(value) not in (int, float) or not math.isfinite(value):
        fail('invalid_number')
    return value


def stamp(value):
    # Sensor XML commonly has 100 ns precision; the public contract has us.
    # The original string is retained separately and lost precision is bounded.
    return parse_utc(value, 'evidence.timestamp')


def utc(value):
    return value.isoformat(timespec='microseconds').replace('+00:00', 'Z')


def supported_event_ids(channel):
    """Pinned Windows event IDs for one collected channel (collector Id filter)."""
    if channel not in CHANNELS:
        fail('unsupported_source_schema', 'collector.channel')
    return sorted(int(event) for source in CHANNELS[channel][1] for event in EVENTS[source])


def supported_cloudtrail_events():
    """Pinned CloudTrail eventName values (collector eventName filter)."""
    return sorted(EVENTS['cloud-audit'])


def safe_path(path):
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts:
        fail('unsafe_path')
    for part in (path,) + tuple(path.parents):
        if part.exists() or part.is_symlink():
            info = part.lstat()
            if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
                fail('unsafe_path')
    return path


def new_bytes(path, data):
    """Create a new file atomically: a crash never leaves a partial target."""
    safe_path(path)
    if path.exists():
        raise FileExistsError(str(path))
    temporary = path.with_name('.' + path.name + '.' + secrets.token_hex(8) + '.tmp')
    try:
        with temporary.open('xb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def frozen_bytes(root, relative, data, code):
    """Write private state once; later calls must supply identical bytes."""
    path = safe_path(root / relative)
    if path.exists():
        if confined_file(root, relative).read_bytes() != data:
            fail(code, relative)
    else:
        new_bytes(path, data)


def namespace(kind):
    return 'name' if kind in NAME_KINDS else kind


def canonical_entity(kind, value):
    value = text(str(value))
    if kind == 'address':
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            return value  # CloudTrail can report AWS service identities instead of IPs.
        if address.version == 6:
            return str(address.ipv4_mapped) if address.ipv4_mapped is not None else address.exploded
        return str(address)
    if kind in NAME_KINDS:
        # DNS and Windows host names compare ASCII case-insensitively.
        value = ''.join(c.lower() if 'A' <= c <= 'Z' else c for c in value)
        return value[:-1] if len(value) > 1 and value.endswith('.') else value
    return value


class Identities:
    def __init__(self, salt, aliases):
        self.salt = salt
        self.aliases = {}
        for entry in aliases:
            exact(entry, ('kind','values'), 'mapping.entity_aliases')
            kind, values = entry['kind'], entry['values']
            if kind not in KINDS or type(values) is not list or len(values) < 2:
                fail('invalid_mapping', 'mapping.entity_aliases')
            normalized = [canonical_entity(kind, text(v)) for v in values]
            if len(set(normalized)) != len(normalized):
                fail('invalid_mapping', 'mapping.entity_aliases')
            representative = min(normalized)
            for value in normalized:
                key = (namespace(kind), value)
                if key in self.aliases:
                    fail('invalid_mapping', 'mapping.entity_aliases')
                self.aliases[key] = representative

    def alias(self, kind, value, scope=None):
        """Pseudonym; a scope (public asset ID) separates host-local values."""
        space = namespace(kind)
        value = canonical_entity(kind, value)
        if (space, value) in self.aliases:
            payload = [space, self.aliases[(space, value)]]
        elif scope is not None:
            payload = [space, scope, value]
        else:
            payload = [space, value]
        digest = hmac.new(self.salt, canonical_bytes(payload), hashlib.sha256).hexdigest()
        return space + '-' + digest[:32]


def validate_rules(rules):
    exact(rules, ('schema_version','version','sources'), 'field_rules')
    if type(rules['schema_version']) is not int or rules['schema_version'] != 1 or rules['version'] != 'collector-fields-2':
        fail('unsupported_source_schema', 'field_rules')
    if type(rules['sources']) is not dict or set(rules['sources']) != set(FORMATS):
        fail('unsupported_source_schema', 'field_rules.sources')
    known = set(ENTITY_FIELDS) | BASENAMES | CONTENT_FIELDS | NUMBERS | set(ENUMS) | set(STATUS_FIELDS) | {
        'type','rejected','readOnly','eventName','eventSource','awsRegion','service'}
    lists = ('allowed_fields','pseudonym_fields','basename_fields','content_fields','supported_event_types')
    for source, rule in rules['sources'].items():
        exact(rule, ('format',) + lists, 'field_rules.source')
        if rule['format'] != FORMATS[source]:
            fail('unsupported_source_schema', 'field_rules.format')
        for key in lists:
            values = rule[key]
            if type(values) is not list or any(type(v) is not str for v in values) or len(set(values)) != len(values):
                fail('unsupported_source_schema', 'field_rules.source')
        allowed = set(rule['allowed_fields'])
        if (not allowed <= known or set(rule['pseudonym_fields']) != allowed & set(ENTITY_FIELDS)
                or set(rule['basename_fields']) != allowed & BASENAMES
                or set(rule['content_fields']) != allowed & CONTENT_FIELDS
                or set(rule['supported_event_types']) != EVENTS[source]):
            fail('unsupported_source_schema', 'field_rules.source')


def lookup(record, key):
    if key in record:
        return record[key]
    value = record
    for part in key.split('.'):
        if type(value) is not dict or part not in value:
            return None
        value = value[part]
    return value


class Content:
    """The `content` transform for one campaign: benchmark_sanitize.sanitize_text
    with identities mapped onto this sealer's pseudonym namespaces."""
    def __init__(self, ids, known):
        self.ids = ids
        self.known = known  # [(original, token)] enrolled identities and aliases
        self.truncated = set()  # public source IDs with a truncated content value

    def pseudonymize(self, kind, original):
        if kind not in SANITIZE_KINDS:
            fail('unsupported_source_schema', 'content')
        return self.ids.alias(SANITIZE_KINDS[kind], original)

    def __call__(self, value, replacements, source_id):
        # The record's own structured identities (and the enrolled ones) become the
        # exact pseudonyms used in its structured fields, in one non-recursive pass.
        tokens = {}
        for original, token in list(self.known) + list(replacements):
            if len(original) >= 3 and not (original.isdigit() and len(original) < 6):
                tokens.setdefault(original.lower(), token)
        originals = sorted(tokens, key=lambda item: (-len(item), item))
        if originals:
            pattern = re.compile(r'(?<![A-Za-z0-9_])(?:' + '|'.join(re.escape(item) for item in originals)
                                 + r')(?![A-Za-z0-9_])', re.IGNORECASE)
            value = pattern.sub(lambda match: tokens.get(match.group(0).lower(), match.group(0)), value)
        # NUL raises BenchmarkError('invalid_text') inside sanitize_text.
        sanitized, report = sanitize_text(value, self.pseudonymize)
        if scan_leaks(sanitized, originals):
            fail('pseudonymization_leak')
        if report['truncated']:
            self.truncated.add(source_id)
        return sanitized


def sanitize(record, source, rule, ids, asset_id, content):
    result = {}
    texts = []
    windows = FORMATS[source] == 'windows-event-xml-v1'
    for key in rule['allowed_fields']:
        value = lookup(record, key)
        if value is None or (windows and value == '-'):
            continue  # Windows writes "-" for an absent EventData value.
        if key in CONTENT_FIELDS:
            if key == 'MESSAGE' and record.get('_TRANSPORT') != 'audit':
                continue  # Only journald's copy of an audit record is evidence text.
            if key == 'requestParameters':
                if type(value) is not dict:
                    fail()
                value = canonical_bytes(value).decode('utf-8')
            elif key == 'argv' and type(value) is list:
                if any(type(item) is not str for item in value):
                    fail()
                value = ' '.join(value)
            if type(value) is not str:
                fail()
            if value:
                texts.append((key, value))
            continue
        if key == 'resources':
            if type(value) is not list:
                fail()
            sanitized = []
            for resource in value:
                if type(resource) is not dict or not set(resource) <= {'ARN','accountId','type'} or 'ARN' not in resource:
                    fail()
                projected = {'ARN':ids.alias('resource', text(resource['ARN']))}
                if 'accountId' in resource:
                    projected['accountId'] = ids.alias('account', text(resource['accountId']))
                if 'type' in resource:
                    if resource['type'] not in ('AWS::CloudTrail::Trail', 'AWS::S3::Bucket', 'AWS::IAM::Role', 'AWS::IAM::User'):
                        fail()
                    projected['type'] = resource['type']
                sanitized.append(projected)
            result[key] = sanitized
        elif key == 'answers':
            if type(value) is not list:
                fail()
            result[key] = []
            for answer in value:
                text(answer)
                try:
                    ipaddress.ip_address(answer)
                    kind = 'address'
                except ValueError:
                    kind = 'domain'
                result[key].append(ids.alias(kind, answer))
        elif key in ENTITY_FIELDS:
            if type(value) not in (str, int) or type(value) is bool:
                fail()
            kind = 'session' if key == 'uid' and source.startswith('zeek-') else ENTITY_FIELDS[key]
            local = key in HOST_LOCAL or (key == 'uid' and source == 'linux-audit')
            result[key] = ids.alias(kind, value, asset_id if local else None)
        elif key in BASENAMES:
            basename = text(value).replace('\\', '/').rsplit('/', 1)[-1]
            result[key] = basename if basename in SAFE_PROGRAMS else ids.alias('process', basename)
        elif key in NUMBERS:
            if type(value) is str:
                if not re.fullmatch(r'-?(?:[0-9]+|0x[0-9a-fA-F]+)', value):
                    fail()
                value = int(value, 16 if '0x' in value else 10)
            result[key] = number(value)
        elif key in ENUMS:
            if type(value) is not str or value not in ENUMS[key]:
                fail()
            result[key] = value
        elif key == 'service':
            if type(value) is not str or any((part[1:] if part.startswith('-') else part) not in ZEEK_SERVICES
                                             for part in value.split(',')):
                fail()
            result[key] = value
        elif key in ('readOnly','rejected'):
            if type(value) is not bool:
                fail()
            result[key] = value
        elif key in STATUS_FIELDS:
            if type(value) is not str or not re.fullmatch(r'(?:0x[0-9a-fA-F]{1,16}|[0-9]{1,10}|%%[0-9]{1,10}|S-1-16-[0-9]{1,10})', value):
                fail()
            result[key] = value
        elif key == 'type':
            if value not in EVENTS['linux-audit']:
                fail()
            result[key] = value
        elif key == 'eventName':
            if value not in EVENTS['cloud-audit']:
                fail()
            result[key] = value
        elif key == 'eventSource':
            if value not in ('cloudtrail.amazonaws.com','s3.amazonaws.com','sts.amazonaws.com'):
                fail()
            result[key] = value
        elif key == 'awsRegion':
            if type(value) is not str or not re.fullmatch(r'(?:us|af|ap|ca|cn|eu|il|me|mx|sa)-(?:gov-)?[a-z]+-[1-9]', value):
                fail()
            result[key] = value
        else:
            fail()
    replacements = [(str(lookup(record, key)), result[key]) for key in rule['pseudonym_fields']
                    if key in result and ENTITY_FIELDS[key] in CONTENT_IDENTITY_KINDS
                    and type(lookup(record, key)) in (str, int)]
    for key, value in texts:
        result[key] = content(value, replacements)
    return result


def record_identity(kind, outer):
    """Stable source-record identity shared by duplicate and exercise checks."""
    if type(outer) is not dict:
        fail()
    if kind == 'windows':
        if type(outer.get('channel')) is not str or type(outer.get('record_id')) is not int or type(outer.get('xml')) is not str:
            fail()
        # Record IDs can reset; the collector also keys on the exact XML digest.
        return '{}:{}:{}'.format(outer['channel'], outer['record_id'], digest_bytes(outer['xml'].encode('utf-8')))
    if kind == 'linux':
        return '{}:{}'.format(text(outer.get('source_type')), text(outer.get('record_id')))
    if kind == 'zeek':
        return '{}:{}:{}'.format(text(outer.get('stream')), text(outer.get('file_sha256')), text(outer.get('record_id')))
    if kind == 'aws':
        return text(outer.get('eventID'))
    fail()


def windows_record(outer, event_filter):
    exact(outer, ('channel','provider','record_id','event_id','timestamp_utc','xml'))
    if type(outer['record_id']) is not int or outer['record_id'] < 0 or type(outer['event_id']) is not int:
        fail()
    xml = outer['xml']
    if type(xml) is not str or re.search(r'<!\s*(?:DOCTYPE|ENTITY)', xml, re.I):
        fail('unsafe_xml')
    try:
        root = ET.fromstring(xml)
    except (ET.ParseError, ValueError):
        fail('invalid_xml')
    if root.tag != NS + 'Event':
        fail()
    systems = root.findall(NS + 'System')
    if len(systems) != 1:
        fail()
    system = systems[0]
    def singleton(name):
        nodes = system.findall(NS + name)
        if len(nodes) != 1:
            fail()
        return nodes[0]
    if (singleton('Channel').text != outer['channel'] or singleton('EventID').text != str(outer['event_id'])
            or singleton('EventRecordID').text != str(outer['record_id'])
            or singleton('Provider').get('Name') != outer['provider']
            or stamp(singleton('TimeCreated').get('SystemTime')) != stamp(outer['timestamp_utc'])):
        fail('source_metadata_mismatch')
    channel, event = outer['channel'], str(outer['event_id'])
    if channel not in event_filter or outer['event_id'] not in event_filter[channel]:
        fail('filter_mismatch')
    provider, sources = CHANNELS[channel]
    if outer['provider'] != provider:
        fail()
    source = next(name for name in sources if event in EVENTS[name])
    data_nodes = root.findall(NS + 'EventData')
    user_nodes = root.findall(NS + 'UserData')
    record = {}
    if source == 'windows-wmi' and not data_nodes and len(user_nodes) == 1 and len(user_nodes[0]) == 1:
        # WMI-Activity writes one operation element of named leaf values in UserData.
        for node in user_nodes[0][0]:
            name = node.tag.rsplit('}', 1)[-1]
            if not name or name in record or len(node):
                fail()
            record[name] = node.text or ''
    elif user_nodes or len(data_nodes) > 1 or (not data_nodes and event not in NO_EVENT_DATA):
        fail()
    elif data_nodes and source == 'windows-powershell-classic':
        nodes = list(data_nodes[0])
        if len(nodes) > len(CLASSIC_DATA[event]) or any(node.tag != NS + 'Data' or node.get('Name') is not None or len(node) for node in nodes):
            fail()
        for name, node in zip(CLASSIC_DATA[event], nodes):
            record[name] = node.text or ''
    elif data_nodes:
        for node in data_nodes[0]:
            if node.tag != NS + 'Data' or not node.get('Name') or node.get('Name') in record or len(node):
                fail()
            record[node.get('Name')] = node.text or ''
    execution = system.find(NS + 'Execution')
    if execution is not None:
        for key in ('ProcessID','ThreadID'):
            if key in execution.attrib and key not in record:
                record[key] = execution.attrib[key]
    if system.find(NS + 'Computer') is not None:
        record['_computer'] = system.find(NS + 'Computer').text
    original = singleton('TimeCreated').get('SystemTime')
    labels = []
    if source == 'sysmon' and 'RuleName' in record:
        labels = sorted(set(re.findall(r'(?<![A-Za-z0-9_.])T[0-9]{4}(?:\.[0-9]{3})?(?![A-Za-z0-9_.])', record['RuleName'])))
    return source, event, original, stamp(original), record, labels


def parse_record(kind, outer, export_filter):
    if kind == 'windows':
        return windows_record(outer, export_filter['event_ids'])
    if kind == 'linux':
        exact(outer, ('source_type','record_id','timestamp_utc','record'))
        source, record = outer['source_type'], outer['record']
        text(outer['record_id'])
        if source not in ('journald','linux-audit') or type(record) is not dict:
            fail()
        observed = stamp(outer['timestamp_utc'])
        if source == 'journald':
            micros = record.get('__REALTIME_TIMESTAMP')
            if type(micros) is not str or not re.fullmatch(r'[0-9]{1,20}', micros) or record.get('__CURSOR') != outer['record_id']:
                fail()
            when = dt.datetime(1970,1,1,tzinfo=dt.timezone.utc) + dt.timedelta(microseconds=int(micros))
            if when != observed:
                fail('source_metadata_mismatch')
            event, original = 'journal_record', micros
        else:
            if record.get('timestamp_utc') != outer['timestamp_utc'] or record.get('type') not in EVENTS[source]:
                fail()
            event, original = record['type'], record['timestamp_utc']
        return source, event, original, observed, record, []
    if kind == 'zeek':
        exact(outer, ('stream','record','file_sha256','record_id'))
        if outer['stream'] not in ('conn','dns','http') or type(outer['record']) is not dict:
            fail()
        if type(outer['file_sha256']) is not str or not re.fullmatch('[a-f0-9]{64}', outer['file_sha256']):
            fail()
        if type(outer['record_id']) is not str or not re.fullmatch('[1-9][0-9]*', outer['record_id']):
            fail()
        record = outer['record']
        seconds = number(record.get('ts'))
        observed = dt.datetime.fromtimestamp(seconds, dt.timezone.utc)
        for required in ('uid','id.orig_h','id.resp_h'):
            text(record.get(required))
        return 'zeek-' + outer['stream'], outer['stream'], str(seconds), observed, record, []
    if kind == 'aws':
        record = outer
        if type(record) is not dict or type(record.get('eventVersion')) is not str or not re.fullmatch(r'1\.[0-9]{1,2}', record['eventVersion']):
            fail()
        event = record.get('eventName')
        if type(event) is not str or event not in export_filter['event_names']:
            fail('filter_mismatch')
        service = 'sts' if event == 'GetCallerIdentity' else ('s3' if 'Bucket' in event else 'cloudtrail')
        if record.get('eventSource') != service + '.amazonaws.com' or type(record.get('userIdentity')) is not dict:
            fail()
        for key in ('eventID','eventTime','recipientAccountId','awsRegion'):
            text(record.get(key))
        if type(record.get('requestParameters')) not in (dict, type(None)):
            fail()
        return 'cloud-audit', event, record['eventTime'], stamp(record['eventTime']), record, []
    fail()


def windows_channels(config):
    if type(config.get('channels')) is not list or type(config.get('evtx_files')) is not list:
        fail()
    channels = set(config['channels'])
    for entry in config['evtx_files']:
        if type(entry) is not dict:
            fail()
        channels.add(entry.get('channel'))
    if not channels or not channels <= set(CHANNELS):
        fail()
    return channels


def expected_filter(collector):
    kind = collector['kind']
    if kind == 'windows':
        return {'event_ids': {channel: supported_event_ids(channel)
                              for channel in sorted(windows_channels(collector['config']))}}
    if kind == 'aws':
        return {'event_names': supported_cloudtrail_events()}
    return None


def source_types(collector, target):
    kind, config = collector['kind'], collector['config']
    if kind == 'windows':
        sources = set()
        for channel in windows_channels(config):
            sources.update(CHANNELS[channel][1])
        # 4768/4769/4771/4662 are domain-controller audit; never claimed elsewhere.
        if target['identity'].get('domain_controller') is not True:
            sources.discard('identity-audit')
        return sources
    if kind == 'linux':
        # Both types are declared; a missing audit export makes linux-audit unknown.
        return {'journald','linux-audit'}
    if kind == 'zeek':
        if type(config.get('streams')) is not list or not config['streams'] or not set(config['streams']) <= {'conn','dns','http'}:
            fail()
        return {'zeek-' + stream for stream in config['streams']}
    if kind == 'aws':
        return {'cloud-audit'}
    fail()


def address_assets(collector, targets, sensors):
    """Explicit Zeek address enrolment: canonical address -> enrolled target ID."""
    entries = collector['config'].get('address_assets')
    if type(entries) is not list:
        fail('invalid_mapping', 'collector.zeek.address_assets')
    result = {}
    for entry in entries:
        exact(entry, ('address','target_id'), 'collector.zeek.address_assets')
        try:
            ipaddress.ip_address(entry['address'])
        except (ValueError, TypeError):
            fail('invalid_mapping', 'collector.zeek.address_assets')
        address = canonical_entity('address', entry['address'])
        if address in result or entry['target_id'] not in targets or entry['target_id'] in sensors:
            fail('invalid_mapping', 'collector.zeek.address_assets')
        result[address] = entry['target_id']
    return result


def validate_mapping(mapping, targets, export_limit):
    exact(mapping, ('schema_version','case_id','assets','entity_aliases','known_gaps','assessment_windows','max_public_bytes'), 'mapping')
    if type(mapping['schema_version']) is not int or mapping['schema_version'] != 1:
        fail('invalid_mapping', 'mapping.schema_version')
    if type(mapping['case_id']) is not str or not re.fullmatch(r'case-[a-f0-9]{4,32}', mapping['case_id']):
        fail('invalid_mapping', 'mapping.case_id')
    limit = mapping['max_public_bytes']
    if type(limit) is not int or not 0 < limit <= min(1048576, export_limit):
        fail('invalid_limit', 'mapping.max_public_bytes')
    for key in ('assets','entity_aliases','known_gaps','assessment_windows'):
        if type(mapping[key]) is not list:
            fail('invalid_mapping', 'mapping')
    seen = set()
    for asset in mapping['assets']:
        exact(asset, ('target_id','os_family','os_version','architecture','vendor'), 'mapping.assets')
        target_id = asset['target_id']
        if type(target_id) is not str or target_id not in targets or target_id in seen:
            fail('invalid_mapping', 'mapping.assets')
        seen.add(target_id)
        family = asset['os_family']
        if family not in COVERAGE_AXES['os']:
            fail('invalid_mapping', 'mapping.assets')
        allowed = {'aws': {'not-applicable'}, 'windows': {'windows-client','windows-server'}, 'linux': {'linux'}}
        if family not in allowed[targets[target_id]['kind']]:
            fail('scope_mismatch', 'mapping.assets')
        for key in ('os_version','architecture','vendor'):
            value = asset[key]
            if value is not None and (type(value) is not str or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9 ._()+-]{0,63}', value)):
                fail('invalid_mapping', 'mapping.assets')
    if seen != set(targets):
        fail('invalid_mapping', 'mapping.assets')
    if not mapping['assessment_windows']:
        fail('invalid_mapping', 'mapping.assessment_windows')
    for window in mapping['assessment_windows']:
        _window(window, 'mapping.assessment_windows')
    if len({canonical_bytes(w) for w in mapping['assessment_windows']}) != len(mapping['assessment_windows']):
        fail('invalid_mapping', 'mapping.assessment_windows')
    for gap in mapping['known_gaps']:
        exact(gap, ('source_id','target_id','reason'), 'mapping.known_gaps')
        if gap['reason'] not in GAPS:
            fail('invalid_mapping', 'mapping.known_gaps')
    if len({canonical_bytes(gap) for gap in mapping['known_gaps']}) != len(mapping['known_gaps']):
        fail('invalid_mapping', 'mapping.known_gaps')


def validate_phase_windows(phase_windows):
    if type(phase_windows) is not list:
        fail('invalid_mapping', 'phase_windows')
    seen = set()
    for entry in phase_windows:
        exact(entry, ('phase','window_utc'), 'phase_windows')
        if entry['phase'] not in PHASES or entry['phase'] in seen:
            fail('invalid_mapping', 'phase_windows')
        seen.add(entry['phase'])
        _window(entry['window_utc'], 'phase_windows.window_utc')
    return sorted(phase_windows, key=lambda item: PHASES.index(item['phase']))


def validate_markers(manifest, private_markers):
    if type(private_markers) is not list or any(type(m) is not str or not m for m in private_markers):
        fail('invalid_mapping', 'private_markers')
    markers = set(private_markers)
    for value in (manifest.get('campaign_id'), manifest.get('recipe_id')):
        if isinstance(value, str) and value:
            markers.add(value)
    markers.update(item['target_id'] for item in manifest['targets'])
    markers.update(item['source_id'] for item in manifest['collectors'])
    return sorted(markers)


def check_markers(markers, collectors, public_text):
    """Refuse controller identifiers in operator text or in any public byte."""
    for collector in collectors:
        for key in ('sensor_version', 'config_version'):
            value = text(collector[key]).casefold()
            if any(marker.casefold() in value for marker in markers):
                fail('forbidden_public_metadata', 'evidence')
    lowered = public_text.casefold()
    for marker in markers:
        if re.search(r'(?<![a-z0-9])' + re.escape(marker.casefold()) + r'(?![a-z0-9])', lowered):
            fail('forbidden_public_metadata', 'evidence')


def materialize_evidence(private_root, manifest, snapshots, field_rules, mapping, public_destination,
                         *, phase_windows, private_markers):
    """Materialize a new validated public bundle; never release or dispatch it."""
    try:
        return _materialize(private_root, manifest, snapshots, field_rules, mapping, public_destination,
                            phase_windows, private_markers)
    except BenchmarkError:
        raise
    except (OSError, ValueError, TypeError, KeyError, OverflowError, AttributeError):
        fail('invalid_evidence')


def freeze_snapshot(root, snapshot_root, descriptor, limit, field):
    sha, count = descriptor['sha256'], descriptor['byte_count']
    if type(sha) is not str or not re.fullmatch('[a-f0-9]{64}', sha) or descriptor['path'] != 'raw/' + sha + '.json':
        fail('unsafe_path', field)
    if type(count) is not int or count <= 0 or count > limit + FILE_METADATA_BYTES:
        fail('output_limit', field)
    with confined_file(root, descriptor['path']).open('rb') as stream:
        data = stream.read(count + 1)
    if len(data) != count or digest_bytes(data) != sha:
        fail('digest_mismatch', field)
    copied = snapshot_root / (sha + '.json')
    if copied.exists():
        if confined_file(root, 'sealing/snapshots/' + sha + '.json').read_bytes() != data:
            fail('digest_mismatch', field)
    else:
        new_bytes(copied, data)
    return data


def driver_export(data, collector, final):
    """One collector's single export; the final generation must be complete."""
    result = decode_json(data)
    exact(result, ('execution_outcome','observed_target_sha256','effect_verified','evidence','raw_exports','context_updates'))
    if type(result['raw_exports']) is not list or len(result['raw_exports']) != 1 or type(result['evidence']) is not dict:
        fail('incomplete_export')
    if final and (result['execution_outcome'] != 'succeeded' or result['effect_verified'] is not True):
        fail('incomplete_export')
    export = result['raw_exports'][0]
    exact(export, ('source_id','records','window_utc','watermark_utc','complete','filter'))
    if export['source_id'] != collector['source_id'] or export['window_utc'] != collector['window_utc']:
        fail('scope_mismatch')
    if export['filter'] != expected_filter(collector):
        fail('filter_mismatch', 'evidence.filter')
    if type(export['records']) is not list or len(canonical_bytes(export)) > collector['max_bytes']:
        fail('output_limit')
    return result, export


def _materialize(private_root, manifest, snapshots, field_rules, mapping, public_destination,
                 phase_windows, private_markers):
    root = safe_path(private_root)
    destination = safe_path(public_destination)
    if not root.is_dir() or '..' in destination.parts or destination.exists():
        fail('unsafe_path')
    try:
        relative = destination.relative_to(root / 'public')
    except ValueError:
        fail('unsafe_path')
    if not relative.parts:
        fail('unsafe_path')
    # Use the strict portable file checker to validate all proposed components.
    if any(not re.fullmatch(r'[A-Za-z0-9_-]+', part) or part.upper() in {'CON','PRN','AUX','NUL', *('COM'+str(i) for i in range(1,10)), *('LPT'+str(i) for i in range(1,10))} for part in relative.parts):
        fail('unsafe_path')
    validate_rules(field_rules)
    targets = {item['target_id']: item for item in manifest['targets']}
    collectors = {item['source_id']: item for item in manifest['collectors']}
    limit = manifest['limits']['max_export_bytes']
    validate_mapping(mapping, targets, limit)
    phases = validate_phase_windows(phase_windows)
    markers = validate_markers(manifest, private_markers)
    sensors = {item['target_id'] for item in collectors.values() if item['kind'] == 'zeek'}
    if sensors & {item['target_id'] for item in collectors.values() if item['kind'] != 'zeek'}:
        # A sensor never borrows an assessed endpoint's clock or identity.
        fail('scope_mismatch', 'collector.zeek')
    mapping_bytes = canonical_bytes(mapping)
    mapping_sha = digest_bytes(mapping_bytes)
    sealing = safe_path(root / 'sealing')
    sealing.mkdir(exist_ok=True)
    identity_path = sealing / 'identity.json'
    if identity_path.exists():
        identity = decode_json(confined_file(root, 'sealing/identity.json').read_bytes())
        exact(identity, ('schema_version','mapping_sha256','salt_hex'))
        if identity['schema_version'] != 1 or identity['mapping_sha256'] != mapping_sha:
            fail('mapping_conflict', 'mapping')
        if type(identity['salt_hex']) is not str or not re.fullmatch('[a-f0-9]{64}', identity['salt_hex']):
            fail('corrupt_state')
        salt = bytes.fromhex(identity['salt_hex'])
    else:
        salt = secrets.token_bytes(32)
    if (sealing / 'mapping.json').exists() and confined_file(root, 'sealing/mapping.json').read_bytes() != mapping_bytes:
        fail('mapping_conflict', 'mapping')
    phase_bytes = canonical_bytes({'schema_version':1, 'record_type':'evaluator_phase_windows', 'phases':phases})
    if (sealing / 'phase-windows.json').exists() and confined_file(root, 'sealing/phase-windows.json').read_bytes() != phase_bytes:
        fail('mapping_conflict', 'phase_windows')
    ids = Identities(salt, mapping['entity_aliases'])
    # Enrolled identities and alias values are replaced inside content with the
    # same per-campaign pseudonyms the structured fields use.
    known = [(text(value), ids.alias(entry['kind'], value)) for entry in mapping['entity_aliases']
             if entry['kind'] in CONTENT_IDENTITY_KINDS for value in entry['values']]
    for target in manifest['targets']:
        for key, kind in (('computer_name','host'), ('domain','domain'), ('account_id','account'), ('machine_id','host')):
            if isinstance(target['identity'].get(key), str) and target['identity'][key]:
                known.append((target['identity'][key], ids.alias(kind, target['identity'][key])))
    content = Content(ids, known)
    if type(snapshots) is not list or len(snapshots) != len(collectors):
        fail('incomplete_export')
    frozen, seen, total = [], set(), 0
    snapshot_root = safe_path(sealing / 'snapshots')
    snapshot_root.mkdir(exist_ok=True)
    for descriptor in snapshots:
        exact(descriptor, ('source_id','path','sha256','byte_count','exercise'), 'snapshots')
        source_id = descriptor['source_id']
        if source_id not in collectors or source_id in seen:
            fail('scope_mismatch', 'snapshots')
        seen.add(source_id)
        collector = collectors[source_id]
        data = freeze_snapshot(root, snapshot_root, descriptor, limit, 'snapshots')
        exercise = None
        if descriptor['exercise'] is not None:
            exact(descriptor['exercise'], ('path','sha256','byte_count'), 'snapshots.exercise')
            exercise = freeze_snapshot(root, snapshot_root, descriptor['exercise'], limit, 'snapshots.exercise')
        result, export = driver_export(data, collector, True)
        total += len(canonical_bytes(export))
        if exercise is not None:
            _, earlier = driver_export(exercise, collector, False)
            total += len(canonical_bytes(earlier))
            final_records = {}
            for outer in export['records']:
                final_records.setdefault(record_identity(collector['kind'], outer), canonical_bytes(outer))
            for outer in earlier['records']:
                if final_records.get(record_identity(collector['kind'], outer)) != canonical_bytes(outer):
                    fail('incomplete_export', 'snapshots.exercise')
        if total > limit:
            fail('output_limit', 'snapshots')
        frozen.append((descriptor, result, export))
    assets = []
    for asset in mapping['assets']:
        assets.append(dict({key: value for key, value in asset.items() if key != 'target_id'}, asset_id=ids.alias('asset', asset['target_id'])))
    assets.sort(key=lambda item: item['asset_id'])
    unassessed = sorted(ids.alias('asset', target_id) for target_id in sensors)
    sources, events, gaps, verified_gaps, windows = [], [], [], set(), []
    event_keys = set()
    for descriptor, result, export in frozen:
        collector = collectors[descriptor['source_id']]
        target = targets[collector['target_id']]
        asset_id = ids.alias('asset', collector['target_id'])
        start, end = _window(export['window_utc'], 'evidence.window')
        watermark = stamp(export['watermark_utc'])
        if export['complete'] is not True or watermark < end or watermark > dt.datetime.now(dt.timezone.utc):
            fail('incomplete_export')
        collector_gaps = result['evidence'].get('gaps', [])
        if type(collector_gaps) is not list or any(gap not in GAPS for gap in collector_gaps):
            # process_events_absent / incomplete_export are failed collections.
            fail('incomplete_export')
        if any(GAPS[gap] != collector['kind'] for gap in collector_gaps):
            fail('unverified_gap', 'evidence.gaps')
        collector_gaps = sorted(set(collector_gaps))
        offset = number(target['clock']['offset_seconds'])
        uncertainty = number(target['clock']['uncertainty_seconds'])
        if uncertainty < 0:
            fail('invalid_number')
        delta = dt.timedelta(seconds=offset)
        normalized_window = {'start_inclusive':utc(start-delta), 'end_exclusive':utc(end-delta)}
        windows.append((start-delta, end-delta))
        source_names = source_types(collector, target)
        source_assets = {asset_id}
        enrolled = {}
        if collector['kind'] == 'zeek':
            enrolled = address_assets(collector, targets, sensors)
            source_assets.update(ids.alias('asset', target_id) for target_id in enrolled.values())
        quantized, observed_sources = set(), set()
        for outer in export['records']:
            identity = record_identity(collector['kind'], outer)
            source, event_type, original, observed, record, labels = parse_record(collector['kind'], outer, export['filter'])
            if source not in source_names or not start <= observed < end:
                fail('scope_mismatch')
            observed_sources.add(source)
            if source == 'cloud-audit' and (record['recipientAccountId'] != target['identity']['account_id'] or record['awsRegion'] != collector['config']['region']):
                fail('source_metadata_mismatch')
            if source == 'journald':
                machine = target['identity'].get('machine_id')
                if not isinstance(machine, str) or record.get('_MACHINE_ID') != machine:
                    fail('source_metadata_mismatch')
            windows_source = FORMATS[source] == 'windows-event-xml-v1'
            if windows_source:
                computer = target['identity'].get('computer_name')
                domain = target['identity'].get('domain')
                observed_computer = record.get('_computer')
                if (not isinstance(computer, str) or not isinstance(domain, str)
                        or not isinstance(observed_computer, str)
                        or observed_computer.rstrip('.').casefold() not in {
                            computer.casefold(), (computer + '.' + domain).casefold()}):
                    fail('source_metadata_mismatch')
            key = (collector['source_id'], source, identity)
            if key in event_keys:
                fail('duplicate_record')
            event_keys.add(key)
            event_asset = asset_id
            if source.startswith('zeek-'):
                for endpoint in ('id.orig_h', 'id.resp_h'):
                    owner = enrolled.get(canonical_entity('address', record[endpoint]))
                    if owner is not None:
                        event_asset = ids.alias('asset', owner)
                        break
            source_id = ids.alias('source', collector['source_id'] + ':' + source)
            fields = sanitize(record, source, field_rules['sources'][source], ids, event_asset,
                              lambda value, pairs, source_id=source_id: content(value, pairs, source_id))
            fields['timestamp_original'] = original
            fields['source_format'] = FORMATS[source]
            if windows_source:
                fields['channel'] = outer['channel']
            if record.get('_computer'):
                fields['host_id'] = ids.alias('host', record['_computer'])
            if labels:
                fields['detector_attack_ids'] = labels
            if source.startswith('zeek-') or re.search(r'\.[0-9]{7,}', original):
                quantized.add(source)
            events.append({'event_id':ids.alias('event', canonical_bytes(list(key)).decode('utf-8')),
                'timestamp_utc':utc(observed-delta), 'source_id':source_id, 'asset_id':event_asset,
                'event_type':event_type, 'fields':fields})
        if 'missing_audit_export' in collector_gaps and 'linux-audit' in observed_sources:
            fail('source_metadata_mismatch', 'evidence.gaps')
        for reason in collector_gaps:
            verified_gaps.add((collector['source_id'], collector['target_id'], reason))
        for source in sorted(source_names):
            source_id = ids.alias('source', collector['source_id'] + ':' + source)
            missing = source == 'linux-audit' and 'missing_audit_export' in collector_gaps
            sources.append({'source_id':source_id, 'asset_ids':sorted(source_assets), 'telemetry':TELEMETRY[source],
                'clock_offset_seconds':offset, 'clock_uncertainty_seconds':uncertainty + (0.000001 if source in quantized or delta.total_seconds() != offset else 0),
                'window_utc':normalized_window, 'sensor_version':text(collector['sensor_version']),
                'config_version':text(collector['config_version']), 'completeness':'unknown' if missing else 'complete',
                'source_sha256':descriptor['sha256']})
            if missing:
                gaps.append({'source_id':source_id, 'asset_id':asset_id, 'window_utc':normalized_window, 'reason':'missing_audit_export'})
            if source_id in content.truncated:
                gaps.append({'source_id':source_id, 'asset_id':asset_id, 'window_utc':normalized_window, 'reason':'content_truncated'})
        if 'process_instrumentation_absent' in collector_gaps:
            gaps.append({'source_id':None, 'asset_id':asset_id, 'window_utc':normalized_window, 'reason':'process_instrumentation_absent'})
    for gap in mapping['known_gaps']:
        if (gap['source_id'], gap['target_id'], gap['reason']) not in verified_gaps:
            fail('unverified_gap', 'mapping.known_gaps')
    outer_window = (min(w[0] for w in windows), max(w[1] for w in windows))
    questions = []
    for window in mapping['assessment_windows']:
        _window(window, 'mapping.assessment_windows', outer_window)
        for asset in assets:
            if asset['asset_id'] in unassessed:
                continue
            questions.append({'question_id':ids.alias('question', canonical_bytes([asset['asset_id'],window]).decode('utf-8')),
                'asset_id':asset['asset_id'], 'window_utc':window, 'question':QUESTION})
    questions.sort(key=lambda item: item['question_id'])
    events.sort(key=lambda item: (stamp(item['timestamp_utc']), item['event_id']))
    records = b''.join(canonical_bytes(event) + b'\n' for event in events)
    records_sha = digest_bytes(records)
    for line, event in enumerate(events, 1):
        event['locator'] = {'file_sha256':records_sha, 'record_id':str(line)}
    bundle = {'schema_version':1, 'case_id':mapping['case_id'],
        'window_utc':{'start_inclusive':utc(outer_window[0]), 'end_exclusive':utc(outer_window[1])},
        'assets':assets, 'sources':sorted(sources, key=lambda item:item['source_id']), 'events':events,
        'known_gaps':sorted(gaps, key=lambda item:(item['source_id'] or '', item['reason'], item['asset_id'])),
        'files':[{'path':'records.jsonl','byte_count':len(records),'sha256':records_sha}],
        'assessment_questions':questions}
    if unassessed:
        bundle['unassessed_asset_ids'] = unassessed
    validate_public_bundle(bundle)
    public_bytes = canonical_bytes(bundle)
    check_markers(markers, collectors.values(), (public_bytes + records).decode('utf-8'))
    if len(public_bytes) + len(records) > mapping['max_public_bytes']:
        fail('output_limit', 'mapping.max_public_bytes')
    # All validation precedes publication. Identity (with the mapping hash) is
    # written before the mapping so an interrupted first seal stays recoverable.
    if not identity_path.exists():
        new_bytes(identity_path, canonical_bytes({'schema_version':1,'mapping_sha256':mapping_sha,'salt_hex':salt.hex()}))
    frozen_bytes(root, 'sealing/mapping.json', mapping_bytes, 'mapping_conflict')
    frozen_bytes(root, 'sealing/phase-windows.json', phase_bytes, 'mapping_conflict')
    destination.mkdir(parents=True, exist_ok=False)
    try:
        new_bytes(destination / 'records.jsonl', records)
        new_bytes(destination / 'evidence.json', public_bytes)
    except OSError:
        # Remove only this invocation's newly created incomplete public files.
        for name in ('evidence.json','records.jsonl'):
            candidate = destination / name
            if candidate.exists():
                candidate.unlink()
        destination.rmdir()
        raise
    return bundle

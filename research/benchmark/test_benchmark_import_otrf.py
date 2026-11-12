"""OTRF importer tests on the INVENTED OTRF-shaped sample; no downloads, no network."""
import base64
import errno
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import zipfile
from contextlib import redirect_stderr, redirect_stdout

import benchmark_import_otrf as otrf
from benchmark_contracts import (BenchmarkError, canonical_bytes, decode_json, load_json,
                                 validate_public_bundle, validate_scenario, validate_truth)
from benchmark_paths import FRAMEWORK

SAMPLE = Path(__file__).resolve().parent / 'benchmarks' / 'importers' / 'sample'
DATASET = SAMPLE / 'sample_owner_discovery_2026-01-0100000000.json'
METADATA = SAMPLE / 'SDWIN-990101000001.yaml'
CURATION = SAMPLE / 'curation.json'
MEMBER = DATASET.name
NX_DATASET = SAMPLE / 'sample_nxlog_discovery_2026-01-0100000000.json'
NX_METADATA = SAMPLE / 'SDWIN-990101000002.yaml'
NX_CURATION = SAMPLE / 'curation-nxlog.json'
NX_HOST = 'LABHOST03.lab.example.test'
SYSMON = 'Microsoft-Windows-Sysmon/Operational'
SALT = bytes(range(32))


def run_cli(*argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = otrf.main([str(item) for item in argv])
    return code, out.getvalue(), err.getvalue()


class ImporterTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.fields = otrf.load_field_map()
        self.salt_file = self.root / 'salt.json'
        self.salt_file.write_bytes(canonical_bytes({'schema_version': 1, 'salt_hex': SALT.hex()}))

    def tearDown(self):
        self.tmp.cleanup()

    def zip_with(self, members, name='sample_owner_discovery.zip', compression=zipfile.ZIP_DEFLATED):
        path = self.root / name
        with zipfile.ZipFile(path, 'w', compression) as archive:
            for member, data in members:
                info = zipfile.ZipInfo(member)
                info.compress_type = compression
                archive.writestr(info, data)
        return path

    def build(self, **kwargs):
        kwargs.setdefault('draft_os_family', None if 'curation_path' in kwargs else 'windows-client')
        return otrf.build_case(kwargs.pop('dataset', DATASET), METADATA, kwargs.pop('fields', self.fields),
                               SALT, **kwargs)

    def public(self, outputs):
        return decode_json(outputs['public/evidence.json'])

    def events_of(self, bundle, event_type):
        return [event for event in bundle['events'] if event['event_type'] == event_type]

    def assertCode(self, code, call, *args, **kwargs):
        with self.assertRaises(BenchmarkError) as caught:
            call(*args, **kwargs)
        self.assertEqual(caught.exception.code, code)
        return caught.exception

    # -------------------------------------------------------------- archives
    def test_zip_slip_members_are_refused(self):
        data = DATASET.read_bytes()
        for name in ('../evil.json', '/abs/evil.json', 'dir/../../evil.json', 'a\\..\\evil.json', 'C:evil.json'):
            with self.subTest(name=name):
                path = self.zip_with([(name, data)])
                self.assertCode('unsafe_member_path', otrf.read_dataset, path)

    def test_oversized_and_bomb_members_are_refused(self):
        data = DATASET.read_bytes()
        path = self.zip_with([(MEMBER, data)])
        self.assertCode('member_too_large', otrf.read_dataset, path, max_member_bytes=len(data) - 1)
        bomb = self.zip_with([(MEMBER, b' ' * (8 * 1024 * 1024))], name='bomb.zip')
        self.assertCode('compression_ratio', otrf.read_dataset, bomb)

    def test_nested_multiple_and_foreign_members_are_refused(self):
        data = DATASET.read_bytes()
        self.assertCode('nested_archive', otrf.read_dataset, self.zip_with([('inner.zip', b'PK')]))
        self.assertCode('ambiguous_archive', otrf.read_dataset,
                        self.zip_with([(MEMBER, data), ('second.json', data)]))
        self.assertCode('unsupported_member', otrf.read_dataset, self.zip_with([('run.ps1', b'x')]))

    def test_zip_member_reads_identically_to_json(self):
        path = self.zip_with([(MEMBER, DATASET.read_bytes())])
        _, _, member, data = otrf.read_dataset(path)
        self.assertEqual((member, data), (MEMBER, DATASET.read_bytes()))
        case_id, outputs = self.build(dataset=path)
        self.assertEqual(self.public(outputs)['case_id'], case_id)

    # -------------------------------------------------------------- metadata
    def test_metadata_subset_parser(self):
        parsed = otrf.parse_metadata_yaml(METADATA.read_bytes())
        self.assertEqual(parsed['id'], 'SDWIN-990101000001')
        self.assertEqual(parsed['techniques'], [{'technique_id': 'T1033', 'tactics': ['TA0007']}])
        base = METADATA.read_bytes()
        for bad in (base.replace(b'type: atomic', b'type: &anchor atomic'),
                    base.replace(b'- Windows', b'- *alias'),
                    base.replace(b'platform:\n- Windows', b'platform: [Windows]'),
                    base + b'unexpected_key: 1\n',
                    base.replace(b'  - technique: T1033', b'\t- technique: T1033')):
            with self.subTest(bad=bad[-40:]):
                with self.assertRaises(BenchmarkError):
                    otrf.parse_metadata_yaml(bad)
        sub = base.replace(b'    sub-technique:\n', b'    sub-technique: "003"\n')
        self.assertEqual(otrf.parse_metadata_yaml(sub)['techniques'][0]['technique_id'], 'T1033.003')

    # ------------------------------------------------------------- allowlist
    def test_content_fields_are_published_sanitized_and_labels_dropped(self):
        _, outputs = self.build()
        public = outputs['public/evidence.json'] + outputs['public/records.jsonl']
        for secret in (b'invented message text', b'technique_id=', b'Ignore previous instructions', b'RuleName',
                       b'CallTrace', b'Message'):
            self.assertNotIn(secret, public)
        bundle = self.public(outputs)
        process = [e['fields'] for e in self.events_of(bundle, 'windows-security:4688')
                   if e['fields']['NewProcessName'] == 'whoami.exe'][0]
        self.assertEqual(process['CommandLine'], 'whoami /all')
        sysmon = [e['fields'] for e in self.events_of(bundle, 'sysmon:1') if e['fields']['Image'] == 'whoami.exe'][0]
        self.assertEqual((sysmon['CommandLine'], sysmon['ParentCommandLine']), ('whoami /all', '"cmd.exe" /c whoami /all'))
        self.assertEqual(self.events_of(bundle, 'sysmon:13')[0]['fields']['Details'], 'whoami /all\\1')
        report = decode_json(outputs['evaluator/import-report.json'])
        self.assertEqual((report['importer_version'], report['field_map']['version']), ('otrf-import-3', 'otrf-fields-5'))
        self.assertNotIn('CommandLine', report['counts']['dropped_fields'])
        self.assertEqual(report['sanitizer']['fields']['Security:4688 CommandLine'],
                         {'values': 2, 'redactions': {}, 'pseudonymized': 0, 'attack_masked': 0, 'encoded_previewed': 0,
                          'truncated': 0,
                          'original_bytes': len('whoami /all') + len('hostname.exe')})

    def test_explicit_allowlist_can_release_a_field(self):
        fields = json.loads(otrf.DEFAULT_FIELDS.read_text(encoding='utf-8'))
        fields['channels']['Security']['events']['4688']['Message'] = 'keep'
        path = self.root / 'fields.json'
        path.write_text(json.dumps(fields), encoding='utf-8')
        _, outputs = self.build(fields=otrf.load_field_map(path))
        process = self.events_of(self.public(outputs), 'windows-security:4688')
        self.assertIn('invented message text that must never be published', {event['fields']['Message'] for event in process})
        fields['channels']['Security']['events']['4688']['Message'] = 'shell'
        path.write_text(json.dumps(fields), encoding='utf-8')
        self.assertCode('invalid_choice', otrf.load_field_map, path)
        fields['channels']['Security']['events']['4688']['Message'] = 'content'
        fields['message_fields'] = {'Security': {'4688': 'invented-parser'}}
        path.write_text(json.dumps(fields), encoding='utf-8')
        self.assertCode('invalid_object', otrf.load_field_map, path)

    def extended(self, extra):
        """The invented flat sample plus invented records appended after its last line."""
        path = self.root / MEMBER
        path.write_bytes(DATASET.read_bytes() + b''.join(json.dumps(item).encode('utf-8') + b'\r\n' for item in extra))
        return path

    def test_content_is_sanitized_and_correlates_with_structured_fields(self):
        # Invented records shaped like the OTRF flat exports; every name, secret and address is fictitious.
        base = {'Hostname': 'LABHOST01', 'Message': 'invented message text that must never be published'}
        sysmon = dict(base, Channel=SYSMON, SourceName='Microsoft-Windows-Sysmon', UtcTime='2026-01-01 09:00:21.000')
        script = 'Invoke-Atomic T1059.001; $c = ConvertTo-SecureString "Hunter2pass" -AsPlainText -Force'
        long_block = '# ' + 'x' * (otrf.MAX_CONTENT_BYTES + 10)
        extra = [dict(sysmon, EventID=1, TimeCreated='2026-01-01T04:00:21.000Z', Image='C:\\Windows\\System32\\net.exe',
                      User='LABHOST01\\analyst', ProcessGuid='{aaaa1111-0000-0000-0000-000000000099}',
                      CommandLine='net user backdoor Hunter2pass /add & dir C:\\Users\\analyst\\Desktop & ping 192.0.2.10',
                      ParentCommandLine='cmd /c start {aaaa1111-0000-0000-0000-000000000001}'),
                 dict(sysmon, EventID=22, TimeCreated='2026-01-01T04:00:22.000Z', QueryName='labhost02.example.test',
                      QueryResults='::ffff:192.0.2.10;', Image='C:\\Windows\\System32\\ping.exe'),
                 dict(base, Channel='Microsoft-Windows-PowerShell/Operational', EventID=4104,
                      TimeCreated='2026-01-01T04:00:23.000Z', MessageNumber='1', MessageTotal='2',
                      ScriptBlockId='cccc3333-0000-0000-0000-000000000001', ScriptBlockText=script),
                 dict(base, Channel='Microsoft-Windows-PowerShell/Operational', EventID=4104,
                      TimeCreated='2026-01-01T04:00:23.100Z', MessageNumber='2', MessageTotal='2',
                      ScriptBlockId='cccc3333-0000-0000-0000-000000000001', ScriptBlockText=long_block),
                 dict(base, Channel='System', EventID=7045, TimeCreated='2026-01-01T04:00:24.000Z',
                      ServiceName='invsvc', ImagePath='\\\\labhost02\\c$\\inv.exe -k analyst@example.test')]
        _, outputs = self.build(dataset=self.extended(extra))
        bundle, report = self.public(outputs), decode_json(outputs['evaluator/import-report.json'])
        public = (outputs['public/evidence.json'] + outputs['public/records.jsonl']).decode('utf-8')
        for raw in ('Hunter2pass', 'analyst', 'LABHOST02', 'labhost02', '192.0.2.10', 'T1059', 'Atomic', 'aaaa1111',
                    'invented message'):
            self.assertNotIn(raw, public)
        whoami = [e['fields'] for e in self.events_of(bundle, 'sysmon:1') if e['fields']['Image'] == 'whoami.exe'][0]
        user = whoami['User'].split('\\')[1]
        net = [e['fields'] for e in self.events_of(bundle, 'sysmon:1') if e['fields']['Image'] == 'net.exe'][0]
        address = self.events_of(bundle, 'sysmon:3')[0]['fields']['SourceIp']
        self.assertEqual(net['CommandLine'], 'net user backdoor [REDACTED:password] /add & dir C:\\Users\\%s\\Desktop & '
                                             'ping %s' % (user, otrf.Pseudonyms(SALT).ip('192.0.2.10')))
        self.assertNotEqual(address, otrf.Pseudonyms(SALT).ip('192.0.2.10'))
        shell = [e['fields'] for e in self.events_of(bundle, 'sysmon:1') if e['fields']['Image'] == 'cmd.exe'][0]
        self.assertEqual(net['ParentCommandLine'], 'cmd /c start {%s}' % shell['ProcessGuid'])
        blocks = self.events_of(bundle, 'windows-powershell:4104')
        first, second = blocks[0]['fields'], blocks[1]['fields']
        self.assertEqual(first['ScriptBlockText'], 'T#### T####; $c = ConvertTo-SecureString [REDACTED:password] '
                                                   '-AsPlainText -Force')
        self.assertEqual((first['MessageNumber'], first['MessageTotal'], second['MessageNumber']), ('1', '2', '2'))
        self.assertEqual(first['ScriptBlockId'], second['ScriptBlockId'])
        self.assertTrue(second['ScriptBlockText'].endswith(' \u2026[truncated 12 bytes]'))
        dns = self.events_of(bundle, 'sysmon:22')[0]['fields']
        self.assertEqual(dns['QueryResults'], '::ffff:%s;' % net['CommandLine'].rsplit(' ', 1)[1])
        service = self.events_of(bundle, 'windows-system:7045')[0]['fields']['ImagePath']
        self.assertRegex(service, r'\A\\\\host-[0-9a-f]{16}\\c\$\\inv\.exe -k %s@dns-[0-9a-f]{16}\Z' % user)
        totals = report['sanitizer']['fields']
        self.assertEqual(totals['Microsoft-Windows-PowerShell/Operational:4104 ScriptBlockText']['redactions'],
                         {'password': 1})
        self.assertEqual(totals['Microsoft-Windows-PowerShell/Operational:4104 ScriptBlockText']['truncated'], 1)
        self.assertEqual(report['sanitizer']['truncated_values'], 1)
        powershell = [s for s in bundle['sources'] if s['completeness'] == 'partial']
        self.assertEqual(len(powershell), 1)
        gap = [g for g in bundle['known_gaps'] if g['source_id'] == powershell[0]['source_id']]
        self.assertEqual(len(gap), 1)
        self.assertTrue(gap[0]['reason'].startswith('content_truncated: 1 content field values exceeded 16384 bytes'))

    def test_message_parsers_extract_classic_powershell_wmi_and_session_fields(self):
        # Invented rendered messages in the layouts of classic Windows PowerShell 800, WMI-Activity 5858 and
        # TerminalServices-LocalSessionManager 24, whose data the inspected exports carry only in Message.
        context = ('\r\n\tDetailSequence=1\r\n\tDetailTotal=1\r\n\r\n\tSequenceNumber=17\r\n\r\n\tUserId=LABHOST01\\analyst'
                   '\r\n\tHostName=ConsoleHost\r\n\tHostVersion=5.1\r\n\tHostId=dddd4444-0000-0000-0000-000000000001'
                   '\r\n\tHostApplication=powershell.exe -nop -c Get-Invented\r\n\tEngineVersion=5.1'
                   '\r\n\tRunspaceId=dddd4444-0000-0000-0000-000000000002\r\n\tPipelineId=1\r\n\tScriptName='
                   '\r\n\tCommandLine=  Get-Invented -Name x\n  | Out-Null\r\n')
        pipeline = ('Pipeline execution details for command line: Get-Invented -Name x. \r\n\r\nContext Information: '
                    + context + '\r\nDetails: \r\nCommandInvocation(Get-Invented): "Get-Invented"\r\n'
                    'ParameterBinding(Get-Invented): name="Name"; value="x"\r\n')
        extra = [{'Hostname': 'LABHOST02', 'Channel': 'Windows PowerShell', 'EventID': 800, 'SourceName': 'PowerShell',
                  'TimeCreated': '2026-01-01T04:00:21.000Z', 'Message': pipeline},
                 {'Hostname': 'LABHOST01', 'Channel': 'Microsoft-Windows-WMI-Activity/Operational', 'EventID': 5858,
                  'TimeCreated': '2026-01-01T04:00:22.000Z',
                  'Message': 'Id = {eeee5555-0000-0000-0000-000000000001}; ClientMachine = LABHOST02; User = '
                             'LABHOST01\\analyst; ClientProcessId = 42; Component = Unknown; Operation = Start '
                             'IWbemServices::ExecQuery - root\\cimv2 : SELECT * FROM Win32_Process WHERE Name = '
                             "'x.exe'; ResultCode = 0x80041032; PossibleCause = Unknown; still free text"},
                 {'Hostname': 'LABHOST01', 'TimeCreated': '2026-01-01T04:00:23.000Z', 'EventID': 24,
                  'Channel': 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational',
                  'Message': 'Remote Desktop Services: Session has been disconnected:\r\n\r\nUser: LABHOST01\\analyst'
                             '\r\nSession ID: 2\r\nSource Network Address: 192.0.2.77'}]
        _, outputs = self.build(dataset=self.extended(extra))
        bundle, report = self.public(outputs), decode_json(outputs['evaluator/import-report.json'])
        user = [e['fields'] for e in self.events_of(bundle, 'sysmon:1') if e['fields']['Image'] == 'whoami.exe'][0]['User']
        classic = self.events_of(bundle, 'windows-powershell-classic:800')[0]['fields']
        self.assertEqual(classic['UserId'], user)
        self.assertEqual(classic['HostApplication'], 'powershell.exe -nop -c Get-Invented')
        self.assertEqual(classic['CommandLine'], 'Get-Invented -Name x\n  | Out-Null')
        self.assertEqual(classic['Details'], 'CommandInvocation(Get-Invented): "Get-Invented"\r\n'
                                             'ParameterBinding(Get-Invented): name="Name"; value="x"')
        self.assertEqual((classic['DetailSequence'], classic['DetailTotal'], classic['PipelineId']), ('1', '1', '1'))
        self.assertTrue(classic['HostId'].startswith('guid-') and classic['RunspaceId'].startswith('guid-'))
        self.assertNotIn('Message', classic)
        wmi = self.events_of(bundle, 'windows-wmi-activity:5858')[0]['fields']
        self.assertEqual((wmi['User'], wmi['ClientProcessId'], wmi['ResultCode']), (user, '42', '0x80041032'))
        self.assertTrue(wmi['ClientMachine'].startswith('host-') and wmi['Id'].startswith('guid-'))
        self.assertEqual(wmi['Operation'], "Start IWbemServices::ExecQuery - root\\cimv2 : SELECT * FROM Win32_Process "
                                           "WHERE Name = 'x.exe'")
        self.assertEqual(wmi['PossibleCause'], 'Unknown; still free text')
        session = self.events_of(bundle, 'windows-terminal-services:24')[0]['fields']
        self.assertEqual((session['User'], session['SessionID']), (user, '2'))
        self.assertTrue(session['Address'].startswith('ipv4-'))
        self.assertEqual(report['record_shape']['message_fields_parsed'],
                         {'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational:24': 1,
                          'Microsoft-Windows-WMI-Activity/Operational:5858': 1, 'Windows PowerShell:800': 1})
        self.assertNotIn('analyst', (outputs['public/evidence.json'] + outputs['public/records.jsonl']).decode('utf-8'))

    def test_unlisted_event_types_and_channels_are_imported_metadata_only(self):
        extra = [{'Hostname': 'LABHOST01', 'Channel': 'Security', 'EventID': 4999, 'SourceName': 'Microsoft-Windows-'
                  'Security-Auditing', 'Level': '0', 'Task': '12345', 'TimeCreated': '2026-01-01T04:00:21.000Z',
                  'SubjectUserName': 'analyst', 'Message': 'invented message text that must never be published'},
                 {'Hostname': 'LABHOST02', 'Channel': 'Invented-Vendor/Operational', 'EventID': 7,
                  'SourceName': 'Invented-Vendor', 'Level': '4', 'TimeCreated': '2026-01-01T04:00:22.000Z',
                  'Secret': 'invented vendor payload'}]
        _, outputs = self.build(dataset=self.extended(extra))
        bundle, report = self.public(outputs), decode_json(outputs['evaluator/import-report.json'])
        unlisted = self.events_of(bundle, 'windows-security:4999')[0]
        self.assertEqual(set(unlisted['fields']), {'timestamp_original', 'Channel', 'EventID', 'SourceName', 'Level', 'Task'})
        vendor = self.events_of(bundle, 'channel:invented-vendor/operational:7')[0]
        self.assertEqual(vendor['fields']['SourceName'], 'Invented-Vendor')
        self.assertEqual([s['telemetry'] for s in bundle['sources'] if s['source_id'] == vendor['source_id']], [None])
        self.assertEqual(report['counts']['metadata_only_by_type'],
                         {'Invented-Vendor/Operational:7': 1, 'Security:4999': 1})
        self.assertEqual(report['counts']['metadata_only_dropped_fields'], {'Message': 1, 'Secret': 1, 'SubjectUserName': 1})
        self.assertEqual(bundle['known_gaps'], [])
        public = (outputs['public/evidence.json'] + outputs['public/records.jsonl']).decode('utf-8')
        for raw in ('invented vendor payload', 'invented message', 'analyst'):
            self.assertNotIn(raw, public)

    def test_firewall_rule_change_events_are_imported_with_pseudonymized_rule_name(self):
        # Invented MPSSVC rule add/delete records (Security 4946/4948), shaped like the OTRF exports. RuleId stays
        # literal: it is a random rule GUID that also appears in the firewall-rule registry key path.
        rule = {'SourceName': 'Microsoft-Windows-Security-Auditing', 'Hostname': 'LABHOST01', 'Task': '13571',
                'Channel': 'Security', 'ProfileChanged': 'All', 'RuleId': '{11111111-2222-3333-4444-555555555555}',
                'RuleName': 'invented inbound rule', 'Message': 'invented message text that must never be published'}
        extra = [dict(rule, EventID=4946, TimeCreated='2026-01-01T04:00:21.000Z'),
                 dict(rule, EventID=4948, TimeCreated='2026-01-01T04:00:22.000Z')]
        path = self.root / MEMBER
        path.write_bytes(DATASET.read_bytes() + b''.join(json.dumps(item).encode('utf-8') + b'\r\n' for item in extra))
        _, outputs = self.build(dataset=path)
        bundle = self.public(outputs)
        added = self.events_of(bundle, 'windows-security:4946')[0]['fields']
        deleted = self.events_of(bundle, 'windows-security:4948')[0]['fields']
        self.assertEqual((added['ProfileChanged'], added['RuleId']), ('All', '{11111111-2222-3333-4444-555555555555}'))
        self.assertEqual((added['RuleName'], added['RuleId']), (deleted['RuleName'], deleted['RuleId']))
        self.assertTrue(added['RuleName'].startswith('value-'))
        public = (outputs['public/evidence.json'] + outputs['public/records.jsonl']).decode('utf-8').casefold()
        for raw in ('invented inbound rule', 'invented message text'):
            self.assertNotIn(raw, public)

    def test_kerberos_ticket_user_correlates_and_access_reason_is_dropped(self):
        # Invented Security 4624 / 4769 / 5145 records shaped like the OTRF exports: 4769 TargetUserName is user@REALM.
        base = {'SourceName': 'Microsoft-Windows-Security-Auditing', 'Hostname': 'LABHOST01', 'Channel': 'Security',
                'Message': 'invented message text that must never be published'}
        extra = [dict(base, EventID=4624, TimeCreated='2026-01-01T04:00:21.000Z', TargetUserName='analyst',
                      TargetDomainName='LABDOM', LogonType='3', IpAddress='192.0.2.40'),
                 dict(base, EventID=4769, TimeCreated='2026-01-01T04:00:21.000Z', TargetUserName='analyst@LABDOM.EXAMPLE.TEST',
                      TargetDomainName='LABDOM.EXAMPLE.TEST', ServiceName='LABHOST02$', IpAddress='192.0.2.40'),
                 dict(base, EventID=5145, TimeCreated='2026-01-01T04:00:22.000Z', SubjectUserName='analyst',
                      ShareName='\\\\*\\IPC$', RelativeTargetName='samr', AccessMask='0x12019f',
                      AccessReason='%%1541:\t%%1801\tD:(A;;0x1200a9;;;S-1-5-21-1111111111-2222222222-3333333333-1001)')]
        path = self.root / MEMBER
        path.write_bytes(DATASET.read_bytes() + b''.join(json.dumps(item).encode('utf-8') + b'\r\n' for item in extra))
        _, outputs = self.build(dataset=path)
        bundle = self.public(outputs)
        logon = self.events_of(bundle, 'windows-security:4624')[0]['fields']
        ticket = self.events_of(bundle, 'windows-security:4769')[0]['fields']
        user, _, realm = ticket['TargetUserName'].partition('@')
        self.assertEqual(user, logon['TargetUserName'])
        self.assertTrue(user.startswith('user-') and realm.startswith('dns-'))
        self.assertEqual(ticket['TargetDomainName'], logon['TargetDomainName'])
        share = self.events_of(bundle, 'windows-security:5145')[0]['fields']
        self.assertNotIn('AccessReason', share)
        self.assertEqual(share['SubjectUserName'], user)
        public = (outputs['public/evidence.json'] + outputs['public/records.jsonl']).decode('utf-8')
        for raw in ('D:(A;', '0x1200a9', 'analyst', 'LABDOM'):
            self.assertNotIn(raw, public)
        self.assertEqual(decode_json(outputs['evaluator/import-report.json'])['counts']['dropped_fields']['AccessReason'], 1)
        fields = otrf.load_field_map()['channels']['Security']['events']
        self.assertNotIn('AccessReason', fields['5145'])
        self.assertNotIn('AccessReason', fields['4656'])
        self.assertEqual(fields['4769']['TargetUserName'], 'account')

    def test_records_mirror_original_lines_with_explicit_stubs(self):
        _, outputs = self.build()
        lines = outputs['public/records.jsonl'].decode('utf-8').splitlines()
        self.assertEqual(len(lines), 15)
        stubs = {index + 1: decode_json(line) for index, line in enumerate(lines) if 'not_imported' in line}
        self.assertEqual(stubs, {12: {'line': 12, 'status': 'not_imported', 'reason': 'blank_line'}})
        bundle = self.public(outputs)
        for event in bundle['events']:
            row = decode_json(lines[int(event['locator']['record_id']) - 1])
            self.assertEqual(row['event_id'], event['event_id'])
        # Line 10 (Security 5447) and line 11 (classic PowerShell 400 whose Message is a prompt injection) are
        # allowlisted types whose invented records carry no data fields: imported as events; Message never published.
        self.assertEqual(decode_json(lines[9])['fields'], {'timestamp_original': '2026-01-01T04:00:06.000Z',
                                                           'Channel': 'Security', 'EventID': 5447})
        self.assertEqual(decode_json(lines[10])['event_type'], 'windows-powershell-classic:400')
        self.assertEqual(bundle['known_gaps'], [])
        self.assertEqual({source['completeness'] for source in bundle['sources']}, {'complete'})

    def test_clock_is_measured_against_sysmon_utctime(self):
        _, outputs = self.build()
        bundle = self.public(outputs)
        self.assertEqual({s['clock_offset_seconds'] for s in bundle['sources']}, {-18000})
        whoami = [e for e in self.events_of(bundle, 'windows-security:4688') if e['fields']['NewProcessName'] == 'whoami.exe'][0]
        self.assertEqual(whoami['timestamp_utc'], '2026-01-01T09:00:02.300000+00:00')
        self.assertEqual(whoami['fields']['timestamp_original'], '2026-01-01T04:00:02.300Z')
        broken = DATASET.read_bytes().replace(b'"TimeCreated":"2026-01-01T04:00:20.000Z"', b'"TimeCreated":"2026-01-01T16:00:20.000Z"')
        path = self.root / MEMBER
        path.write_bytes(broken)
        self.assertCode('inconsistent_timestamps', self.build, dataset=path)

    # ------------------------------------------------------------ pseudonyms
    def test_pseudonyms_are_consistent_and_raw_identifiers_absent(self):
        _, outputs = self.build()
        bundle = self.public(outputs)
        public = (outputs['public/evidence.json'] + outputs['public/records.jsonl']).decode('utf-8').casefold()
        for raw in ('analyst', 'labhost01', 'labhost02', '1111111111', '192.0.2.10', 'example.test', 'aaaa1111'):
            self.assertNotIn(raw, public)
        security = [e for e in self.events_of(bundle, 'windows-security:4688') if e['fields']['NewProcessName'] == 'whoami.exe'][0]['fields']
        sysmon = [e for e in self.events_of(bundle, 'sysmon:1') if e['fields']['Image'] == 'whoami.exe'][0]['fields']
        domain, user = sysmon['User'].split('\\')
        self.assertEqual(user, security['SubjectUserName'])
        self.assertEqual(domain, security['SubjectDomainName'])
        self.assertTrue(user.startswith('user-') and domain.startswith('domain-'))
        self.assertIn('\\' + user + '\\', sysmon['CurrentDirectory'])
        self.assertTrue(security['SubjectUserSid'].startswith('sid-') and security['SubjectUserSid'].endswith('-1001'))
        access = self.events_of(bundle, 'sysmon:10')[0]['fields']
        load = self.events_of(bundle, 'sysmon:7')[0]['fields']
        self.assertEqual(access['TargetProcessGUID'], sysmon['ProcessGuid'])
        self.assertEqual(load['ProcessGuid'], sysmon['ProcessGuid'])
        machine = [e for e in self.events_of(bundle, 'windows-security:4688') if e['fields']['NewProcessName'] == 'hostname.exe'][0]
        self.assertTrue(machine['fields']['SubjectUserName'].startswith('host-') and machine['fields']['SubjectUserName'].endswith('$'))
        self.assertEqual(self.events_of(bundle, 'sysmon:1')[-1]['fields']['User'], 'NT AUTHORITY\\SYSTEM')
        created = self.events_of(bundle, 'sysmon:11')[0]['fields']['TargetFilename']
        self.assertNotIn('T1033', created)
        mapping = decode_json(outputs['evaluator/pseudonyms.json'])['mapping']
        self.assertEqual(mapping['user']['analyst'], user)

    # ----------------------------------------------------------------- drafts
    def test_draft_is_refused_for_scoring(self):
        case_id, outputs = self.build()
        self.assertNotIn('scenario.json', outputs)
        self.assertNotIn('evaluator/truth.json', outputs)
        draft = decode_json(outputs['evaluator/truth.DRAFT.json'])
        self.assertEqual(draft['status'], otrf.DRAFT_MARKER)
        self.assertEqual(draft['steps'], [])
        with self.assertRaises(BenchmarkError):
            validate_truth(draft, self.public(outputs))
        self.assertCode('draft_truth_refused', otrf.refuse_draft, draft)
        template = decode_json(outputs['evaluator/curation-template.json'])
        self.assertIn('NOT_VALID_FOR_SCORING', template)
        candidates = template['declared_techniques'][0]['candidate_events']
        self.assertEqual(template['declared_techniques'][0]['technique_id'], 'T1033')
        self.assertEqual(len(candidates), decode_json(outputs['evaluator/import-report.json'])['counts']['imported_events'])
        skeleton = self.root / 'skeleton.json'
        skeleton.write_bytes(canonical_bytes(template['curation']))
        with self.assertRaises(BenchmarkError):
            self.build(curation_path=skeleton)

    # ---------------------------------------------------------------- curated
    def test_curated_cli_import_validates(self):
        output = self.root / 'curated'
        code, stdout, stderr = run_cli('--dataset', DATASET, '--metadata', METADATA, '--curation', CURATION,
                                       '--output', output, '--salt-file', self.salt_file)
        self.assertEqual((code, stderr), (0, ''))
        summary = decode_json(stdout)
        case = output / summary['case_id']
        bundle = validate_public_bundle(load_json(case / 'public' / 'evidence.json'), case / 'public')
        truth = validate_truth(load_json(case / 'evaluator' / 'truth.json'), bundle)
        self.assertEqual(otrf.refuse_draft(truth, bundle), truth)
        scenario = validate_scenario(load_json(case / 'scenario.json'), load_json(otrf.DEFAULT_COVERAGE))
        self.assertEqual((scenario['split'], scenario['provenance']), ('development', 'public_replay'))
        self.assertEqual(scenario['family_id'], 'otrf-t1033')
        self.assertIn('https://attack.mitre.org/techniques/T1033/', scenario['source_references'])
        self.assertIn('https://example.test/otrf-sample/sample_owner_discovery.zip', scenario['source_references'])
        self.assertEqual(scenario['sophistication']['band'], 'S1')
        self.assertRegex(scenario['difficulty']['band'], r'D[1-5]\Z')
        locators = load_json(case / 'evaluator' / 'locators.json')['events']
        step = truth['steps'][0]
        self.assertEqual(sorted(locators[group[0]]['line'] for group in step['support_sets']), [3, 4])
        self.assertEqual(sorted(truth['assessment_labels'].values()), [0, 1])
        self.assertEqual(len(truth['lookalike_event_ids']), 1)
        self.assertFalse((case / 'evaluator' / 'truth.DRAFT.json').exists())
        self.assertEqual((case / 'evaluator' / 'curation.json').read_bytes(), CURATION.read_bytes())

    def test_curation_must_bind_dataset_and_decide_every_question(self):
        curation = load_json(CURATION)
        curation['dataset_sha256'] = '0' * 64
        path = self.root / 'mismatch.json'
        path.write_bytes(canonical_bytes(curation))
        self.assertCode('curation_dataset_mismatch', self.build, curation_path=path)
        curation = load_json(CURATION)
        curation['controls'] = []
        path.write_bytes(canonical_bytes(curation))
        self.assertCode('unlabeled_question', self.build, curation_path=path)
        curation = load_json(CURATION)
        curation['steps'][0]['support_sets'] = [[{'line': 12}]]
        path.write_bytes(canonical_bytes(curation))
        self.assertCode('support_record_not_imported', self.build, curation_path=path)

    def test_curation_without_sufficient_steps_needs_matched_family_difficulty(self):
        matched = decode_json(self.build(curation_path=CURATION)[1]['scenario.json'])['difficulty']
        curation = load_json(CURATION)
        curation['steps'][0]['observability'] = 'insufficient'
        path = self.root / 'insufficient.json'
        path.write_bytes(canonical_bytes(curation))
        self.assertCode('matched_family_required', self.build, curation_path=path)
        curation['matched_control'] = matched
        path.write_bytes(canonical_bytes(curation))
        _, outputs = self.build(curation_path=path)
        scenario, truth = decode_json(outputs['scenario.json']), decode_json(outputs['evaluator/truth.json'])
        self.assertEqual(scenario['difficulty'], dict(matched, control=False))
        self.assertEqual(scenario['sophistication']['band'], 'S1')
        self.assertEqual(truth['steps'][0]['observability'], 'insufficient')
        self.assertEqual(sorted(map(str, truth['assessment_labels'].values())), ['0', 'None'])
        curation['steps'][0]['observability'] = 'sufficient'
        path.write_bytes(canonical_bytes(curation))
        self.assertCode('unexpected_matched_control', self.build, curation_path=path)

    # ----------------------------------------------------------- determinism
    def test_fixed_salt_is_deterministic_and_outputs_are_new(self):
        first, second = self.root / 'one', self.root / 'two'
        for output in (first, second):
            code, _, stderr = run_cli('--dataset', DATASET, '--metadata', METADATA, '--curation', CURATION,
                                      '--output', output, '--salt-file', self.salt_file)
            self.assertEqual((code, stderr), (0, ''))
        files = sorted(p.relative_to(first) for p in first.rglob('*') if p.is_file())
        self.assertEqual(files, sorted(p.relative_to(second) for p in second.rglob('*') if p.is_file()))
        for relative in files:
            self.assertEqual((first / relative).read_bytes(), (second / relative).read_bytes(), str(relative))
        code, _, stderr = run_cli('--dataset', DATASET, '--metadata', METADATA, '--curation', CURATION,
                                  '--output', first, '--salt-file', self.salt_file)
        self.assertEqual((code, stderr.strip()), (2, 'error: output_exists: output'))
        other = self.root / 'other-salt.json'
        other.write_bytes(canonical_bytes({'schema_version': 1, 'salt_hex': 'ab' * 32}))
        code, stdout, _ = run_cli('--dataset', DATASET, '--metadata', METADATA, '--draft-os-family', 'windows-client',
                                  '--output', self.root / 'three', '--salt-file', other)
        self.assertEqual(code, 0)
        self.assertNotEqual(decode_json(stdout)['case_id'], files[0].parts[0])

    def test_output_inside_source_tree_is_refused(self):
        for root in (otrf.HERE, FRAMEWORK):
            with self.subTest(root=root):
                code, _, stderr = run_cli('--dataset', DATASET, '--metadata', METADATA,
                                          '--draft-os-family', 'windows-client',
                                          '--output', root / 'otrf-import-should-not-exist')
                self.assertEqual((code, stderr.strip()), (2, 'error: output_in_source_tree: output'))
                self.assertFalse((root / 'otrf-import-should-not-exist').exists())

    def blocked_open(self, error, mode, name='evidence.json'):
        """Patch the importer's `open` so one output file fails like an antivirus-quarantined file."""
        real = open

        def fake_open(path, flags='r', *args, **kwargs):
            if Path(path).name == name and flags == mode:
                raise error
            return real(path, flags, *args, **kwargs)
        return mock.patch('benchmark_import_otrf.open', fake_open, create=True)

    def test_antivirus_blocked_outputs_are_reported_and_cleaned_up(self):
        case_id, outputs = self.build()
        for mode in ('rb', 'xb'):
            with self.subTest(mode=mode):
                target = self.root / ('blocked-' + mode)
                with self.blocked_open(OSError(errno.EINVAL, 'Invalid argument'), mode):
                    error = self.assertCode('blocked_by_antivirus', otrf.write_outputs, target, case_id, outputs)
                self.assertEqual(error.field, 'public/evidence.json')
                self.assertFalse(target.exists())
        with self.blocked_open(OSError(errno.EACCES, 'Permission denied'), 'rb'):
            error = self.assertCode('file_unreadable', otrf.write_outputs, self.root / 'denied', case_id, outputs)
        self.assertFalse((self.root / 'denied').exists())

    @unittest.skipUnless(os.name == 'nt', 'winerror is Windows-only')
    def test_antivirus_winerror_is_reported(self):
        case_id, outputs = self.build()
        for winerror in otrf.AV_WINERRORS:
            with self.subTest(winerror=winerror):
                target = self.root / ('winerror-%d' % winerror)
                with self.blocked_open(OSError(None, 'Operation did not complete', None, winerror), 'rb'):
                    error = self.assertCode('blocked_by_antivirus', otrf.write_outputs, target, case_id, outputs)
                self.assertEqual(error.field, 'public/evidence.json')
                self.assertFalse(target.exists())

    def test_encoded_payload_mode_is_a_recorded_cli_choice(self):
        payload = base64.b64encode('Write-Output "invented stager stand-in"'.encode('utf-16-le')).decode('ascii')
        extra = [{'Hostname': 'LABHOST01', 'Channel': 'Security', 'EventID': 4688, 'TimeCreated': '2026-01-01T04:00:21.000Z',
                  'NewProcessName': 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
                  'CommandLine': 'powershell.exe -nop -w hidden -enc ' + payload}]
        dataset = self.extended(extra)
        commands = {}
        for mode in ('preview', 'full', None):
            output = self.root / ('mode-%s' % mode)
            args = ['--dataset', dataset, '--metadata', METADATA, '--draft-os-family', 'windows-client',
                    '--output', output, '--salt-file', self.salt_file] + (['--encoded-payloads', mode] if mode else [])
            code, stdout, stderr = run_cli(*args)
            self.assertEqual((code, stderr), (0, ''))
            case = output / decode_json(stdout)['case_id']
            report = load_json(case / 'evaluator' / 'import-report.json')
            self.assertEqual(report['assumptions']['encoded_payloads'], mode or 'preview')
            bundle = load_json(case / 'public' / 'evidence.json')
            commands[mode] = [e['fields']['CommandLine'] for e in self.events_of(bundle, 'windows-security:4688')
                              if e['fields']['CommandLine'].startswith('powershell')][0]
        self.assertEqual(commands['full'], 'powershell.exe -nop -w hidden -enc ' + payload)
        self.assertEqual(commands['preview'], commands[None])
        self.assertIn('-enc [ENCODED_COMMAND utf16le_chars=', commands['preview'])
        self.assertTrue(commands['preview'].endswith('decoded_preview="Write-Output "invented stager stand-in""'))
        with self.assertRaises(SystemExit) as caught:
            run_cli('--dataset', dataset, '--metadata', METADATA, '--draft-os-family', 'windows-client',
                    '--output', self.root / 'bad', '--encoded-payloads', 'decoded')
        self.assertEqual(caught.exception.code, 2)
        self.assertCode('invalid_choice', self.build, encoded_payloads='decoded')

    # ------------------------------------------------------- NXLog record shape
    def build_nx(self, dataset=NX_DATASET, **kwargs):
        kwargs.setdefault('draft_os_family', None if 'curation_path' in kwargs else 'windows-client')
        return otrf.build_case(dataset, NX_METADATA, kwargs.pop('fields', self.fields), SALT, **kwargs)

    def nx_lines(self):
        return [json.loads(line) for line in NX_DATASET.read_bytes().splitlines()]

    def write_nx(self, records):
        path = self.root / NX_DATASET.name
        path.write_bytes(b''.join(json.dumps(item).encode('utf-8') + b'\n' for item in records))
        return path

    def report(self, outputs):
        return decode_json(outputs['evaluator/import-report.json'])

    def test_record_shape_is_detected_and_reported(self):
        flat = self.report(self.build()[1])['record_shape']
        self.assertEqual((flat['shape'], flat['time_field'], flat['record_id_field']),
                         ('flat-timecreated', 'TimeCreated', None))
        nx = self.report(self.build_nx()[1])
        self.assertEqual(nx['importer_version'], 'otrf-import-3')
        self.assertEqual(nx['field_map']['version'], 'otrf-fields-5')
        shape = nx['record_shape']
        self.assertEqual((shape['shape'], shape['time_field'], shape['record_id_field'], shape['collectors']),
                         ('nxlog-eventtime', 'EventTime', 'RecordNumber', 1))
        self.assertEqual(nx['counts']['not_imported'], {'blank_line': 0})
        self.assertEqual(nx['counts']['imported_by_type']['Windows PowerShell:400'], 1)
        records = self.nx_lines()
        for change in ({'SourceModuleType': 'im_file'}, {'TimeCreated': '2026-01-01T04:00:01.000Z'},
                       {'RecordNumber': '5001'}, {'tags': [1]}, {'EventTime': '2026-01-01T04:00:01Z'}):
            with self.subTest(change=change):
                code = 'invalid_timestamp' if 'EventTime' in change else 'unsupported_record_shape'
                error = self.assertCode(code, self.build_nx, dataset=self.write_nx([dict(records[0], **change)] + records[1:]))
                self.assertEqual(error.field, 'dataset.line.1')

    def test_mixed_record_shapes_are_refused(self):
        flat_line = DATASET.read_bytes().splitlines()[1]
        nx_lines = NX_DATASET.read_bytes().splitlines()
        path = self.root / NX_DATASET.name
        for lines, bad in (([nx_lines[0], flat_line] + nx_lines[1:], 2), ([flat_line] + nx_lines, 2)):
            with self.subTest(bad=bad, first=lines[0][:20]):
                path.write_bytes(b'\n'.join(lines) + b'\n')
                error = self.assertCode('mixed_record_shapes', self.build_nx, dataset=path)
                self.assertEqual(error.field, 'dataset.line.%d' % bad)

    def test_nxlog_record_number_locators(self):
        output = self.root / 'nx-curated'
        code, stdout, stderr = run_cli('--dataset', NX_DATASET, '--metadata', NX_METADATA, '--curation', NX_CURATION,
                                       '--output', output, '--salt-file', self.salt_file)
        self.assertEqual((code, stderr), (0, ''))
        case = output / decode_json(stdout)['case_id']
        bundle = validate_public_bundle(load_json(case / 'public' / 'evidence.json'), case / 'public')
        truth = validate_truth(load_json(case / 'evaluator' / 'truth.json'), bundle)
        locators = load_json(case / 'evaluator' / 'locators.json')
        self.assertEqual(locators['record_shape'], 'nxlog-eventtime')
        step = truth['steps'][0]
        cited = sorted((locators['events'][group[0]]['line'], locators['events'][group[0]]['record_id'],
                        locators['events'][group[0]]['channel']) for group in step['support_sets'])
        self.assertEqual(cited, [(2, '7001', 'Security'), (3, '5002', SYSMON)])
        for event in bundle['events']:  # the public locator stays the original line (= records.jsonl line)
            self.assertEqual(int(event['locator']['record_id']), locators['events'][event['event_id']]['line'])
        curation = load_json(NX_CURATION)
        path = self.root / 'nx-curation.json'
        for locator, code in (({'record_id': '7001'}, 'ambiguous_locator'),
                              ({'record_id': '7001', 'channel': 'Security', 'hostname': 'LABHOST09'}, 'unknown_locator'),
                              ({'record_id': 5002}, 'invalid_locator'),
                              ({'record_id': '5002', 'channel': SYSMON}, 'invalid_locator')):
            with self.subTest(locator=locator):
                curation['steps'][0]['support_sets'] = [[locator]]
                path.write_bytes(canonical_bytes(curation))
                self.assertCode(code, self.build_nx, curation_path=path)
        curation['steps'][0]['support_sets'] = [[{'record_id': '5002'}], [{'line': 2}]]
        path.write_bytes(canonical_bytes(curation))
        _, outputs = self.build_nx(curation_path=path)
        self.assertEqual(len(decode_json(outputs['evaluator/truth.json'])['steps'][0]['support_sets']), 2)

    def test_nxlog_eventtime_is_normalized_with_measured_sysmon_offset(self):
        _, outputs = self.build_nx()
        bundle, report = self.public(outputs), self.report(outputs)
        self.assertEqual({s['clock_offset_seconds'] for s in bundle['sources']}, {-14400})
        self.assertEqual(report['assumptions']['clock']['uncertainty_seconds'], 0.4)
        self.assertFalse(report['assumptions']['naive_timestamps_declared_utc'])
        whoami = [e for e in self.events_of(bundle, 'windows-security:4688') if e['fields']['NewProcessName'] == 'whoami.exe'][0]
        self.assertEqual(whoami['timestamp_utc'], '2026-01-01T08:00:02.000000+00:00')
        self.assertEqual(whoami['fields']['timestamp_original'], '2026-01-01 04:00:02')
        records = self.nx_lines()
        wrapped = [dict(r, EventTime='2026-01-01 16:00:04') if r['RecordNumber'] == 5005 else r for r in records]
        error = self.assertCode('inconsistent_timestamps', self.build_nx, dataset=self.write_nx(wrapped))
        self.assertEqual(error.field, 'dataset.EventTime')
        no_sysmon = [r for r in records if r['Channel'] != SYSMON]
        self.assertCode('no_clock_reference', self.build_nx, dataset=self.write_nx(no_sysmon))
        self.assertCode('conflicting_arguments', self.build_nx, naive_utc=True)
        two = [dict(r, host='second-collector.example.test') if r['RecordNumber'] == 9001 else r for r in records]
        self.assertCode('multiple_collectors', self.build_nx, dataset=self.write_nx(two))

    def test_nxlog_fields_aliases_channel_case_and_envelope(self):
        _, outputs = self.build_nx()
        bundle, shape = self.public(outputs), self.report(outputs)['record_shape']
        connection = self.events_of(bundle, 'windows-security:5156')[0]['fields']
        self.assertEqual((connection['Channel'], connection['ProcessID']), ('Security', '4101'))
        self.assertNotIn('ProcessId', connection)
        self.assertEqual(shape['aliased_fields'], {'Security:5156 ProcessId -> ProcessID': 1})
        self.assertEqual(shape['channel_spellings_normalized'], {'security -> Security': 2})
        self.assertEqual(self.events_of(bundle, 'sysmon:13')[0]['fields']['EventType'], 'SetValue')
        self.assertNotIn('EventType', self.events_of(bundle, 'sysmon:12')[0]['fields'])
        self.assertEqual(shape['envelope_collisions_dropped'], {SYSMON + ':12 EventType': 1})
        public = (outputs['public/evidence.json'] + outputs['public/records.jsonl']).decode('utf-8').casefold()
        for raw in ('labhost03', 'lab.example.test', 'dc=lab', 'operator1', 'labdom', '192.0.2.30',
                    'collector.example.test', 'invented message', 'ignore previous', 'technique_id'):
            self.assertNotIn(raw, public)
        registry = self.events_of(bundle, 'sysmon:13')[0]['fields']['TargetObject']
        cache = self.events_of(bundle, 'sysmon:11')[0]['fields']['TargetFilename']
        token = cache.rsplit('\\', 1)[-1][:-len('.sch')]
        self.assertTrue(token.startswith('dns-'))
        self.assertIn('CN=Configuration,DC=' + token + '\\Time', registry)
        fields = json.loads(otrf.DEFAULT_FIELDS.read_text(encoding='utf-8'))
        path = self.root / 'fields.json'
        for bad in ({'Security': {'5156': {'ProcessId': 'CommandLine'}}}, {'Security': {'5156': {'Application': 'ProcessID'}}},
                    {'Security': {'5156': {'EventTime': 'ProcessID'}}}):
            with self.subTest(bad=bad):
                fields['shape_aliases'] = {'nxlog-eventtime': bad}
                path.write_text(json.dumps(fields), encoding='utf-8')
                self.assertCode('invalid_choice', otrf.load_field_map, path)
        fields['shape_aliases'] = {'winlogbeat-nested': {}}
        path.write_text(json.dumps(fields), encoding='utf-8')
        self.assertCode('invalid_object', otrf.load_field_map, path)

    # --------------------------------------------------------- family override
    def test_family_id_override_and_validation(self):
        curation = load_json(CURATION)
        path = self.root / 'family.json'
        curation['family_id'] = 'otrf-t1555'
        path.write_bytes(canonical_bytes(curation))
        _, outputs = self.build(curation_path=path)
        self.assertEqual(decode_json(outputs['scenario.json'])['family_id'], 'otrf-t1555')
        self.assertEqual(self.report(outputs)['curation']['family_id'],
                         {'value': 'otrf-t1555', 'metadata_derived': 'otrf-t1033', 'source': 'curation_override'})
        curation['family_id'] = 'otrf-t1003-001-t1555-004'
        path.write_bytes(canonical_bytes(curation))
        self.assertEqual(decode_json(self.build(curation_path=path)[1]['scenario.json'])['family_id'],
                         'otrf-t1003-001-t1555-004')
        _, outputs = self.build(curation_path=CURATION)
        self.assertEqual(self.report(outputs)['curation']['family_id']['source'], 'metadata')
        for bad in ('otrf-T1555', 'otrf-t1555.004', 'otrf-t1555-t1033', 'otrf-t1033-t1033', 'otrf-t1033-001-t1033',
                    'otrf-', 'family-t1555', 'otrf-t155', '', None, 1555):
            with self.subTest(bad=bad):
                curation['family_id'] = bad
                path.write_bytes(canonical_bytes(curation))
                error = self.assertCode('invalid_identifier', self.build, curation_path=path)
                self.assertEqual(error.field, 'curation.family_id')


class SignCurationTest(unittest.TestCase):
    """`sign` on an invented proposal; the ticked sheet is a test fixture, not a human review."""

    def setUp(self, source=CURATION):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        proposal = load_json(source)
        proposal = dict({'status': 'PROPOSED_UNREVIEWED_NOT_FOR_SCORING'}, **proposal)
        proposal.update(curated_by=None, curated_utc=None, note='PROPOSAL; not reviewed.')
        self.proposal = self.root / 'curation.PROPOSED.json'
        self.proposal.write_bytes(canonical_bytes(proposal))
        self.review = self.root / 'review.md'
        self.output = self.root / 'curation.json'
        self.digest = proposal['dataset_sha256']

    def sheet(self, ticks=('x', 'X'), heading='## Reviewer checklist (tick all before setting `curated_by`)'):
        lines = ['# Review sheet', '', '| Dataset SHA-256 | `{}` |'.format(self.digest), '', heading, '']
        lines += ['- [{}] Checklist item {}.'.format(mark, index) for index, mark in enumerate(ticks)]
        lines += ['', '## References', '- [ ] not part of the checklist']
        self.review.write_text('\n'.join(lines) + '\n', encoding='utf-8')

    def sign(self, by='  Invented Reviewer  ', *extra):
        return run_cli('sign', '--proposal', self.proposal, '--review', self.review, '--by', by,
                       '--note', 'Invented sample signing test.', '--output', self.output, *extra)

    def test_unticked_or_missing_checklist_is_refused(self):
        for kwargs, code in (({'ticks': ('x', ' ')}, 'review_checklist_incomplete'),
                             ({'heading': '## Checklist'}, 'review_checklist_missing'),
                             ({'ticks': ()}, 'review_checklist_missing')):
            with self.subTest(code=code, kwargs=kwargs):
                self.sheet(**kwargs)
                self.assertEqual(self.sign()[::2], (2, 'error: {}: review\n'.format(code)))
                self.assertFalse(self.output.exists())

    def test_existing_output_and_model_like_names_are_refused(self):
        self.sheet()
        self.output.write_bytes(b'keep')
        self.assertEqual(self.sign()[::2], (2, 'error: output_exists: output\n'))
        self.assertEqual(self.output.read_bytes(), b'keep')
        self.output.unlink()
        for name in ('framework-reviewer', 'Evidence Checker', '   '):
            with self.subTest(name=name):
                self.assertEqual(self.sign(name)[0], 2)
                self.assertFalse(self.output.exists())

    def test_signed_output_validates_and_imports(self):
        self.sheet()
        code, stdout, stderr = self.sign()
        self.assertEqual((code, stderr), (0, ''))
        summary = decode_json(stdout)
        data = self.output.read_bytes()
        self.assertEqual(summary['curation_sha256'], otrf.digest_bytes(data))
        signed, _ = otrf.load_curation(self.output)
        self.assertNotIn('status', signed)
        self.assertEqual((signed['curated_by'], signed['note']), ('Invented Reviewer', 'Invented sample signing test.'))
        otrf.parse_utc(signed['curated_utc'], 'curated_utc')
        salt = self.root / 'salt.json'
        salt.write_bytes(canonical_bytes({'schema_version': 1, 'salt_hex': SALT.hex()}))
        code, stdout, stderr = run_cli('--dataset', DATASET, '--metadata', METADATA, '--curation', self.output,
                                       '--output', self.root / 'cases', '--salt-file', salt)
        self.assertEqual((code, stderr), (0, ''))
        self.assertEqual(decode_json(stdout)['status'], 'curated')
        self.assertEqual(decode_json(stdout)['attestation'], 'human_attested')
        case = next((self.root / 'cases').iterdir())
        self.assertNotIn('attestation', load_json(case / 'evaluator' / 'truth.json'))
        self.assertEqual(load_json(case / 'evaluator' / 'import-report.json')['curation']['attestation'],
                         'human_attested')

    def test_unreviewed_proposal_imports_marked_without_flag(self):
        salt = self.root / 'salt.json'
        salt.write_bytes(canonical_bytes({'schema_version': 1, 'salt_hex': SALT.hex()}))
        args = ('--dataset', DATASET, '--metadata', METADATA, '--curation', self.proposal, '--salt-file', salt)
        code, stdout, stderr = run_cli(*args, '--output', self.root / 'cases')
        self.assertEqual((code, stderr), (0, ''))
        self.assertEqual(decode_json(stdout)['attestation'], 'unreviewed_proposal')
        case = next((self.root / 'cases').iterdir())
        self.assertEqual(load_json(case / 'evaluator' / 'truth.json')['attestation'], 'unreviewed_proposal')
        report = load_json(case / 'evaluator' / 'import-report.json')
        self.assertEqual((report['curation']['attestation'], report['curation']['curated_by']),
                         ('unreviewed_proposal', None))
        self.assertIn(otrf.UNREVIEWED_LIMITATION,
                      load_json(case / 'scenario.json')['sophistication']['emulation_limitations'])
        proposal = load_json(self.proposal)
        for key, value, code in (('status', 'SOMETHING_ELSE', 'invalid_proposal_status'),
                                 ('curated_by', 'Someone', 'proposal_has_curator')):
            with self.subTest(key=key):
                self.proposal.write_bytes(canonical_bytes(dict(proposal, **{key: value})))
                self.assertEqual(run_cli(*args, '--output', self.root / key)[::2],
                                 (2, 'error: {}: curation.{}\n'.format(code, 'status' if key == 'status'
                                                                      else 'curated_by')))
                self.assertFalse((self.root / key).exists())

    def test_review_for_another_dataset_is_refused(self):
        self.digest = '0' * 64
        self.sheet()
        self.assertEqual(self.sign()[::2], (2, 'error: review_mismatch: review\n'))

    def test_attackdata_format_uses_its_own_curation_validator(self):
        self.sheet()
        self.assertEqual(self.sign('Invented Reviewer', '--format', 'attackdata')[0], 2)
        self.assertFalse(self.output.exists())
        self.setUp(SAMPLE / 'curation-attackdata-auditd.json')
        self.sheet()
        self.assertEqual(self.sign('Invented Reviewer')[0], 2)
        self.assertFalse(self.output.exists())
        code, _, stderr = self.sign('Invented Reviewer', '--format', 'attackdata')
        self.assertEqual((code, stderr), (0, ''))
        import benchmark_import_attackdata
        self.assertEqual(benchmark_import_attackdata.load_curation(self.output)[0]['curated_by'], 'Invented Reviewer')


class ConsensusCurationTest(unittest.TestCase):
    """Agent-consensus curation of the invented sample; the 'consensus' is a hand-written fixture, not AI output."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.fields = otrf.load_field_map()
        self.base = json.loads(CURATION.read_text('utf-8'))
        _, outputs = otrf.build_case(DATASET, METADATA, self.fields, SALT, curation_path=CURATION)
        self.line_ids = {item['line']: event_id for event_id, item in
                         decode_json(outputs['evaluator/locators.json'])['events'].items()}
        # An imported record that neither the step (lines 3, 4) nor the lookalike group (8, 9) cites.
        self.spare = min(line for line in self.line_ids if line not in (3, 4, 8, 9))
        self.count = 0

    def tearDown(self):
        self.tmp.cleanup()

    def curation(self, drop=(), **changes):
        value = dict(self.base, attestation_hint='agent_consensus', curated_by='agent-consensus',
                     curated_utc='2026-11-04T12:00:00+00:00', note='Invented consensus fixture.',
                     excluded_locators=[{'line': self.spare}], controls=[])
        value.update(changes)
        for key in drop:
            value.pop(key)
        self.count += 1
        path = self.root / 'curation-{}.json'.format(self.count)
        path.write_bytes(canonical_bytes(value))
        return path

    def build(self, path):
        return otrf.build_case(DATASET, METADATA, self.fields, SALT, curation_path=path)

    def assertCode(self, code, path, field=None):
        with self.assertRaises(BenchmarkError) as caught:
            self.build(path)
        self.assertEqual(caught.exception.code, code)
        if field is not None:
            self.assertEqual(caught.exception.field, field)

    def test_consensus_import_marks_truth_disputes_and_report(self):
        _, outputs = self.build(self.curation())
        bundle = decode_json(outputs['public/evidence.json'])
        truth = validate_truth(decode_json(outputs['evaluator/truth.json']), bundle)
        self.assertEqual(truth['attestation'], 'agent_consensus')
        self.assertEqual(truth['disputed_event_ids'], [self.line_ids[self.spare]])
        # LABHOST02 lost its control (the drafts disagreed): its question is disputed, not failed.
        self.assertEqual(sorted(truth['assessment_labels'].values(), key=repr), [1, None])
        report = decode_json(outputs['evaluator/import-report.json'])['curation']
        self.assertEqual((report['attestation'], report['curated_by'], report['disputed_questions']),
                         ('agent_consensus', 'agent-consensus', 1))
        self.assertEqual(report['disputed_evidence']['event_ids'], 1)
        self.assertIn('scoring ignores findings citing only these', report['disputed_evidence']['note'])
        limitations = decode_json(outputs['scenario.json'])['sophistication']['emulation_limitations']
        self.assertIn(otrf.CONSENSUS_LIMITATION, limitations)
        self.assertNotIn(otrf.UNREVIEWED_LIMITATION, limitations)
        self.assertEqual(decode_json(outputs['scenario.json'])['provenance'], 'public_replay')
        # A disputed question is disagreement, not an evidence gap: difficulty matches the human key's.
        _, human = otrf.build_case(DATASET, METADATA, self.fields, SALT, curation_path=CURATION)
        self.assertEqual(decode_json(outputs['scenario.json'])['difficulty']['factors']['gaps'],
                         decode_json(human['scenario.json'])['difficulty']['factors']['gaps'])

    def test_empty_exclusions_record_no_disputed_evidence(self):
        _, outputs = self.build(self.curation(excluded_locators=[], controls=self.base['controls']))
        truth = decode_json(outputs['evaluator/truth.json'])
        self.assertEqual(truth['attestation'], 'agent_consensus')
        self.assertNotIn('disputed_event_ids', truth)
        report = decode_json(outputs['evaluator/import-report.json'])['curation']
        self.assertNotIn('disputed_evidence', report)
        self.assertEqual(report['disputed_questions'], 0)

    def test_cli_summary_warns_consensus(self):
        salt = self.root / 'salt.json'
        salt.write_bytes(canonical_bytes({'schema_version': 1, 'salt_hex': SALT.hex()}))
        code, stdout, stderr = run_cli('--dataset', DATASET, '--metadata', METADATA, '--curation', self.curation(),
                                       '--output', self.root / 'cases', '--salt-file', salt)
        self.assertEqual((code, stderr), (0, ''))
        summary = decode_json(stdout)
        self.assertEqual(summary['attestation'], 'agent_consensus')
        self.assertIn('AGENT CONSENSUS', summary['warning'])

    def test_load_curation_returns_consensus_attestation(self):
        value, _ = otrf.load_curation(self.curation())
        self.assertEqual(value['attestation'], 'agent_consensus')
        self.assertNotIn('attestation_hint', value)

    def test_hint_refusals(self):
        self.assertCode('invalid_attestation_hint', self.curation(attestation_hint='human_attested'),
                        'curation.attestation_hint')
        self.assertCode('invalid_attestation_hint', self.curation(status=otrf.PROPOSAL_STATUS),
                        'curation.attestation_hint')
        self.assertCode('consensus_curator_mismatch', self.curation(curated_by='Invented Reviewer'),
                        'curation.curated_by')
        self.assertCode('consensus_curator_mismatch', self.curation(curated_by=None), 'curation.curated_by')
        self.assertCode('invalid_text', self.curation(note='  '), 'curation.note')
        with self.assertRaises(BenchmarkError) as caught:
            self.build(self.curation(curated_utc='yesterday'))
        self.assertEqual(caught.exception.field, 'curation.curated_utc')

    def test_stripped_hint_never_becomes_human_attested(self):
        for curator in ('agent-consensus', ' Agent-Consensus '):
            with self.subTest(curator=curator):
                self.assertCode('consensus_hint_missing',
                                self.curation(drop=('attestation_hint', 'excluded_locators'), curated_by=curator,
                                              controls=self.base['controls']), 'curation.curated_by')

    def test_exclusions_require_consensus(self):
        human = dict(self.base, excluded_locators=[])
        path = self.root / 'human.json'
        path.write_bytes(canonical_bytes(human))
        self.assertCode('excluded_without_consensus', path, 'curation.excluded_locators')
        proposal = dict(self.base, status=otrf.PROPOSAL_STATUS, curated_by=None, curated_utc=None,
                        excluded_locators=[{'line': self.spare}])
        path.write_bytes(canonical_bytes(proposal))
        self.assertCode('excluded_without_consensus', path, 'curation.excluded_locators')

    def test_exclusion_refusals(self):
        field = 'curation.excluded_locators'
        for locators, code in (([{'line': 3}], 'excluded_overlap'), ([{'line': 8}], 'excluded_overlap'),
                               ([{'line': self.spare}, {'line': self.spare}], 'duplicate_item'),
                               ([{'line': 99999}], 'unknown_locator'), ([{'row': 1}], 'invalid_locator'),
                               ({'line': self.spare}, 'invalid_array')):
            with self.subTest(locators=locators):
                self.assertCode(code, self.curation(excluded_locators=locators), field)

    def test_unlabeled_questions_fail_outside_consensus(self):
        human = dict(self.base, controls=[])
        path = self.root / 'human.json'
        path.write_bytes(canonical_bytes(human))
        self.assertCode('unlabeled_question', path, 'curation.controls')

    def test_sign_turns_reviewed_consensus_into_human_attestation(self):
        proposal = self.curation(excluded_locators=[], controls=self.base['controls'])
        review = self.root / 'review.md'
        review.write_text('dataset {}\n\n## Reviewer checklist\n\n- [x] steps\n'.format(self.base['dataset_sha256']),
                          'utf-8')
        output = self.root / 'signed.json'
        code, _, stderr = run_cli('sign', '--proposal', proposal, '--review', review, '--by', 'Invented Reviewer',
                                  '--note', 'Invented signing test.', '--output', output)
        self.assertEqual((code, stderr), (0, ''))
        signed, _ = otrf.load_curation(output)
        self.assertEqual(signed['attestation'], 'human_attested')
        self.assertNotIn('attestation_hint', signed)
        self.assertNotIn('excluded_locators', signed)
        # Unresolved disputes cannot be signed away: the reviewer must decide them first.
        disputed = self.curation(controls=self.base['controls'])
        code, _, stderr = run_cli('sign', '--proposal', disputed, '--review', review, '--by', 'Invented Reviewer',
                                  '--note', 'Invented signing test.', '--output', self.root / 'signed-2.json')
        self.assertEqual((code, stderr), (2, 'error: excluded_without_consensus: curation.excluded_locators\n'))
        self.assertFalse((self.root / 'signed-2.json').exists())


if __name__ == '__main__':
    unittest.main()

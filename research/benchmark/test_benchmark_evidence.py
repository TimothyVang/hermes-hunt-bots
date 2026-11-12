"""Offline protocol fixtures, not live sensor or benchmark-quality claims."""
import copy
import datetime as dt
from pathlib import Path
import re
import tempfile
import unittest

from benchmark_paths import SOURCE_TREE
from benchmark_contracts import BenchmarkError, canonical_bytes, decode_json, digest_bytes, validate_public_bundle
from benchmark_evidence import (BASENAMES, CONTENT_FIELDS, ENTITY_FIELDS, materialize_evidence,
                                supported_cloudtrail_events, supported_event_ids, validate_rules)

WINDOW = {'start_inclusive':'2026-01-01T00:00:00Z','end_exclusive':'2026-01-01T00:10:00Z'}
TIME = '2026-01-01T00:01:00Z'
SECRET = 'UNRELEASED-SECRET-123'
CORRELATION = '6f1c2a34-5b6d-4e7f-8a9b-0c1d2e3f4a5b'
CHANNEL_IDS = {'Security':[4624,4625,4627,4662,4688,4768,4769,4771,4798,4799], 'System':[7036],
    'Microsoft-Windows-Sysmon/Operational':[1,3,13,22],
    'Microsoft-Windows-PowerShell/Operational':[4103,4104,4105,4106,40961,40962,53504],
    'Windows PowerShell':[400,403,600,800],
    'Microsoft-Windows-TaskScheduler/Operational':[100,102,106,110,129,140,141,200,201],
    'Microsoft-Windows-WMI-Activity/Operational':[5857,5858,5859,5860,5861]}
CLOUD_EVENTS = sorted(['StopLogging','StartLogging','CreateTrail','DeleteTrail','GetTrailStatus',
                       'CreateBucket','DeleteBucket','PutBucketPolicy','GetCallerIdentity'])
KIT_RULES = SOURCE_TREE / 'hunt-range' / 'benchmark' / 'collector-fields.json'


def fixture_rules():
    """Inert portable field map: no dependency on the separately installed kit."""
    types = {
        'windows-security': ('windows-event-xml-v1',['4688','4624','4625','4627','4798','4799'],['NewProcessName','SubjectUserName','IpAddress','IpPort','NewProcessId','LogonId','LogonType']),
        'identity-audit': ('windows-event-xml-v1',['4768','4769','4771','4662'],['SubjectUserName','TargetUserName','IpAddress']),
        'sysmon': ('windows-event-xml-v1',['1','3','13','22'],['Image','User','SourceIp','DestinationIp','ProcessGuid']),
        'windows-powershell': ('windows-event-xml-v1',['4103','4104','4105','4106','40961','40962','53504'],['ProcessID','RunspaceId','PipelineId']),
        'windows-powershell-classic': ('windows-event-xml-v1',['400','403','600','800'],['NewEngineState','HostDetails','CommandLine']),
        'windows-taskscheduler': ('windows-event-xml-v1',['100','102','106','110','129','140','141','200','201'],['TaskName','UserContext','ResultCode']),
        'windows-wmi': ('windows-event-xml-v1',['5857','5858','5859','5860','5861'],['Operation','User','ClientMachine','PossibleCause','ResultCode']),
        'windows-system': ('windows-event-xml-v1',['7036'],['param1','param2']),
        'journald': ('journald-json-v1',['journal_record'],['_UID','_MACHINE_ID','_COMM','SYSLOG_IDENTIFIER']),
        'linux-audit': ('linux-audit-json-v1',['SYSCALL','EXECVE','USER_LOGIN','USER_START','USER_END'],['uid','auid','ses','type','exe','pid']),
        'zeek-conn': ('zeek-json-v1',['conn'],['uid','id.orig_h','id.resp_h','proto','orig_bytes','service']),
        'zeek-dns': ('zeek-json-v1',['dns'],['uid','id.orig_h','id.resp_h','query','answers']),
        'zeek-http': ('zeek-json-v1',['http'],['uid','id.orig_h','id.resp_h','host','method','status_code']),
        'cloud-audit': ('cloudtrail-json-v1',CLOUD_EVENTS,
            ['eventID','eventName','eventSource','awsRegion','sourceIPAddress','userIdentity.arn','userIdentity.accessKeyId','requestParameters.name','resources'])}
    return {'schema_version':1,'version':'collector-fields-2','sources':{
        name:{'format':fmt,'supported_event_types':events,'allowed_fields':fields,
              'pseudonym_fields':sorted(set(fields) & set(ENTITY_FIELDS)),
              'basename_fields':sorted(set(fields) & BASENAMES),
              'content_fields':sorted(set(fields) & CONTENT_FIELDS)} for name,(fmt,events,fields) in types.items()}}


def allow_content(rules, source, *fields):
    """Opt one fixture source into content fields, keeping the lists consistent."""
    rule = rules['sources'][source]
    rule['allowed_fields'] = rule['allowed_fields'] + list(fields)
    rule['content_fields'] = sorted(set(rule['content_fields']) | set(fields))


def windows(channel='Security', provider='Microsoft-Windows-Security-Auditing', event=4688, fields=None, index=1,
            computer='private-host', time=TIME, body=None):
    if fields is None:
        fields = {'SubjectUserName':'private-user','NewProcessName':'C:\\private-host\\whoami.exe',
                  'NewProcessId':'0x1f','IpAddress':'192.0.2.12','CommandLine':SECRET}
    if body is None:
        body = '<EventData>{}</EventData>'.format(''.join('<Data Name="{}">{}</Data>'.format(k,v) for k,v in fields.items()))
    xml = ('<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">\n'
        '<System><Provider Name="{}"/><EventID>{}</EventID><EventRecordID>{}</EventRecordID>'
        '<TimeCreated SystemTime="{}"/><Channel>{}</Channel><Computer>{}</Computer></System>'
        '{}</Event>').format(provider,event,index,time,channel,computer,body)
    return {'channel':channel,'provider':provider,'record_id':index,'event_id':event,'timestamp_utc':time,'xml':xml}


def journal(cursor='private-cursor', **fields):
    micros = str(int(dt.datetime(2026,1,1,0,1,tzinfo=dt.timezone.utc).timestamp()) * 1000000)
    record = {'__CURSOR':cursor,'__REALTIME_TIMESTAMP':micros,'_UID':'1000',
              '_MACHINE_ID':'private-machine','_COMM':'sshd','MESSAGE':SECRET,'_CMDLINE':SECRET}
    record.update(fields)
    return {'source_type':'journald','record_id':cursor,'timestamp_utc':TIME,'record':record}


def audit(**fields):
    record = {'timestamp_utc':TIME,'type':'SYSCALL','uid':1000,'auid':'1000','ses':'secret-session',
              'exe':'/private-host/id','pid':42,'message':SECRET,'argv':SECRET}
    record.update(fields)
    return {'source_type':'linux-audit','record_id':'a'*64+':1','timestamp_utc':TIME,'record':record}


def zeek(stream, record_id='1', **fields):
    record = {'ts':dt.datetime(2026,1,1,0,1,tzinfo=dt.timezone.utc).timestamp(),
        'uid':'private-connection','id.orig_h':'192.0.2.12','id.resp_h':'192.0.2.20','proto':'tcp',
        'orig_bytes':123,'query':'private.test','answers':['192.0.2.20','private.test'],
        'host':'private.test','method':'GET','status_code':200,'uri':SECRET,'authorization':SECRET}
    record.update(fields)
    return {'stream':stream,'record':record,'file_sha256':'b'*64,'record_id':record_id}


def cloud(event='StopLogging'):
    service = 'sts' if event == 'GetCallerIdentity' else ('s3' if 'Bucket' in event else 'cloudtrail')
    return {'eventVersion':'1.11','eventID':'private-event','eventTime':TIME,'eventName':event,
        'eventSource':service+'.amazonaws.com','recipientAccountId':'123456789012','awsRegion':'us-east-1',
        'sourceIPAddress':'192.0.2.12','userIdentity':{'type':'AssumedRole','arn':'private-user',
            'accessKeyId':'private-key','sessionContext':{'secret':SECRET}},
        'requestParameters':{'name':'private-trail','credentials':SECRET},
        'resources':[{'ARN':'private-trail','type':'AWS::CloudTrail::Trail','accountId':'123456789012'}],
        'responseElements':{'secret':SECRET},'userAgent':SECRET}


def pinned_filter(kind, config):
    if kind == 'windows':
        return {'event_ids':{channel:CHANNEL_IDS[channel] for channel in config['channels']}}
    if kind == 'aws':
        return {'event_names':list(CLOUD_EVENTS)}
    return None


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / 'campaign'
        (self.root/'raw').mkdir(parents=True)
        self.rules = fixture_rules()
        self.manifest = {'targets':[], 'collectors':[], 'limits':{'max_export_bytes':1048576}}
        self.mapping = {'schema_version':1,'case_id':'case-abcd','assets':[],
            'entity_aliases':[{'kind':'account','values':['private-user','1000']}],
            'known_gaps':[], 'assessment_windows':[copy.deepcopy(WINDOW)], 'max_public_bytes':1048576}
        self.phases = [{'phase':'exercise','window_utc':{'start_inclusive':'2026-01-01T00:00:30Z',
                                                         'end_exclusive':'2026-01-01T00:02:00Z'}}]
        self.markers = [CORRELATION]
        self.snapshots = []
        self.results = {}
        self.exercises = {}

    def add(self, kind, records, gaps=(), target_kind=None, config=None, identity=None, offset=0):
        source = 'private-source-' + str(len(self.manifest['collectors']))
        target = 'private-target-' + str(len(self.manifest['targets']))
        target_kind = target_kind or ('linux' if kind == 'zeek' else kind)
        enrolled = {'account_id':'123456789012', 'machine_id':'private-machine',
                    'computer_name':'private-host', 'domain':'lab.test', 'domain_controller':True}
        enrolled.update(identity or {})
        self.manifest['targets'].append({'target_id':target,'kind':target_kind,'identity':enrolled,
            'clock':{'offset_seconds':offset,'uncertainty_seconds':0.01}})
        if config is None:
            config = {'region':'us-east-1'} if kind == 'aws' else {}
            if kind == 'windows':
                config = {'channels':['Security','System','Microsoft-Windows-Sysmon/Operational','Microsoft-Windows-PowerShell/Operational'],'evtx_files':[]}
            if kind == 'zeek':
                config = {'manifest_path':'manifest.json','streams':sorted({r['stream'] for r in records}) or ['conn'],
                          'address_assets':[]}
        self.manifest['collectors'].append({'source_id':source,'kind':kind,'target_id':target,
            'config':config,'window_utc':copy.deepcopy(WINDOW),'sensor_version':'sensor-1','config_version':'config-1','max_bytes':1048576})
        self.mapping['assets'].append({'target_id':target,'os_family':{'linux':'linux','windows':'windows-server','aws':'not-applicable'}[target_kind],
            'os_version':None,'architecture':None,'vendor':None})
        result = {'execution_outcome':'succeeded','observed_target_sha256':'c'*64,'effect_verified':True,
            'evidence':{'gaps':list(gaps)},'context_updates':{'recipe_id':SECRET},
            'raw_exports':[{'source_id':source,'records':records,'window_utc':copy.deepcopy(WINDOW),
                            'watermark_utc':WINDOW['end_exclusive'],'complete':True,
                            'filter':pinned_filter(kind, config)}]}
        self.results[source] = result
        self.freeze(source)
        return source

    def write_raw(self, value):
        raw = canonical_bytes(value)
        sha = digest_bytes(raw)
        path = self.root/'raw'/(sha+'.json')
        if not path.exists():
            path.write_bytes(raw)
        return {'path':'raw/'+sha+'.json','sha256':sha,'byte_count':len(raw)}

    def freeze(self, source):
        descriptor = dict(self.write_raw(self.results[source]), source_id=source, exercise=self.exercises.get(source))
        self.snapshots = [s for s in self.snapshots if s['source_id'] != source]
        self.snapshots.append(descriptor)

    def exercise(self, source, records, complete=False):
        earlier = copy.deepcopy(self.results[source])
        earlier['raw_exports'][0].update(records=records, complete=complete)
        self.exercises[source] = self.write_raw(earlier)
        self.freeze(source)

    def seal(self, name='bundle'):
        destination = self.root/'public'/name
        return materialize_evidence(self.root, self.manifest, self.snapshots, self.rules, self.mapping, destination,
                                    phase_windows=self.phases, private_markers=self.markers)

    def fails(self, code=None):
        with self.assertRaises(BenchmarkError) as caught:
            self.seal()
        if code:
            self.assertEqual(caught.exception.code, code)
        self.assertNotIn(SECRET, str(caught.exception))
        self.assertFalse((self.root/'public'/'bundle').exists())

    def public_bytes(self, name='bundle'):
        return (self.root/'public'/name/'evidence.json').read_bytes() + (self.root/'public'/name/'records.jsonl').read_bytes()

    def test_records_from_another_host_cannot_inherit_enrolled_asset(self):
        for kind, record, field in (('linux', journal(), 'machine_id'),
                                    ('windows', windows(), 'computer_name')):
            with self.subTest(kind=kind):
                self.manifest['targets'].clear()
                self.manifest['collectors'].clear()
                self.mapping['assets'].clear()
                self.snapshots.clear()
                self.add(kind, [record])
                self.manifest['targets'][0]['identity'][field] = 'different-enrolled-host'
                self.fails('source_metadata_mismatch')

    def test_recipe_label_in_sensor_metadata_blocks_publication(self):
        self.add('linux', [journal()])
        self.manifest['recipe_id'] = 'linux-discovery-v1'
        self.manifest['collectors'][0]['sensor_version'] = 'linux-discovery-v1'
        self.fails('forbidden_public_metadata')

    def test_controller_identifiers_and_correlation_id_block_publication(self):
        self.add('linux', [journal()])
        self.manifest['campaign_id'] = 'secret-campaign-77'
        for key, value in (('sensor_version', 'build-secret-campaign-77'),
                           ('config_version', 'stratus-' + CORRELATION.upper()),
                           ('sensor_version', 'private-target-0 sensor'),
                           ('config_version', 'cfg-private-source-0')):
            with self.subTest(value=value):
                original = self.manifest['collectors'][0][key]
                self.manifest['collectors'][0][key] = value
                self.fails('forbidden_public_metadata')
                self.manifest['collectors'][0][key] = original
        self.seal()

    def test_all_sensor_formats_materialize_correlated_private_aliases(self):
        self.add('windows', [windows(),
            windows('Security','Microsoft-Windows-Security-Auditing',4768,{'TargetUserName':'private-user'},2),
            windows('Microsoft-Windows-Sysmon/Operational','Microsoft-Windows-Sysmon',1,
                    {'Image':'C:\\private-host\\whoami.exe','User':'private-user','SourceIp':'192.0.2.12','RuleName':'technique_id=T1059.001,secret='+SECRET},3),
            windows('Microsoft-Windows-PowerShell/Operational','Microsoft-Windows-PowerShell',4104,
                    {'RunspaceId':'private-runspace','ScriptBlockText':SECRET},4),
            windows('System','Service Control Manager',7036,{'param1':'private-service','param2':'running'},5)])
        self.add('linux', [journal(),audit()])
        self.add('zeek', [zeek('conn'),zeek('dns'),zeek('http')],
                 config={'manifest_path':'manifest.json','streams':['conn','dns','http'],
                         'address_assets':[{'address':'192.0.2.12','target_id':'private-target-0'}]})
        self.add('aws', [cloud()])
        bundle = self.seal()
        validate_public_bundle(bundle, self.root/'public'/'bundle')
        self.assertEqual(len(bundle['events']),11)
        public = self.public_bytes()
        for private in (SECRET,'private-user','private-host','private-machine','private-key','private.test','192.0.2.12','123456789012','recipe_id','private-source','private-target'):
            self.assertNotIn(private.encode(),public)
        events = bundle['events']
        account_values = [e['fields'][k] for e in events for k in ('SubjectUserName','TargetUserName','User','_UID','uid','userIdentity.arn') if k in e['fields'] and not e['fields'][k].startswith('session-')]
        self.assertEqual(len(set(account_values)),1)
        addresses = [e['fields'][k] for e in events for k in ('IpAddress','SourceIp','id.orig_h','sourceIPAddress') if k in e['fields']]
        self.assertEqual(len(set(addresses)),1)
        self.assertEqual([e['fields']['detector_attack_ids'] for e in events if 'detector_attack_ids' in e['fields']], [['T1059.001']])
        lines = (self.root/'public'/'bundle'/'records.jsonl').read_bytes().splitlines()
        for event in events:
            actual = decode_json(lines[int(event['locator']['record_id'])-1])
            self.assertEqual(actual, {k:v for k,v in event.items() if k != 'locator'})
        cloud_asset = next(a for a in bundle['assets'] if a['os_family']=='not-applicable')
        cloud_source = next(s for s in bundle['sources'] if s['telemetry']=='cloud-audit')
        self.assertEqual(cloud_source['asset_ids'],[cloud_asset['asset_id']])
        # Four enrolled targets; the Zeek sensor is enrolled but not assessed.
        self.assertEqual(len(bundle['assets']),4)
        self.assertEqual(len(bundle['unassessed_asset_ids']),1)
        self.assertEqual(len(bundle['assessment_questions']),3)
        self.assertEqual(bundle,self.seal('second'))
        for descriptor in self.snapshots:
            self.assertEqual((self.root/descriptor['path']).read_bytes(),(self.root/'sealing'/'snapshots'/(descriptor['sha256']+'.json')).read_bytes())

    def test_supported_lists_are_the_pinned_collector_filters(self):
        for channel, ids in CHANNEL_IDS.items():
            self.assertEqual(supported_event_ids(channel), ids)
        self.assertEqual(supported_cloudtrail_events(), CLOUD_EVENTS)
        self.assertEqual(supported_cloudtrail_events(), sorted(self.rules['sources']['cloud-audit']['supported_event_types']))
        with self.assertRaises(BenchmarkError) as caught:
            supported_event_ids('Application')
        self.assertEqual(caught.exception.code, 'unsupported_source_schema')

    def test_security_4672_outside_pinned_filter_and_filter_drift_refused(self):
        source = self.add('windows', [windows(), windows(event=4672, fields={'SubjectUserName':'private-user'}, index=2)])
        self.fails('filter_mismatch')
        self.results[source]['raw_exports'][0]['records'] = [windows()]
        drifted = self.results[source]['raw_exports'][0]['filter']
        drifted['event_ids']['Security'] = sorted(drifted['event_ids']['Security'] + [4672])
        self.freeze(source)
        self.fails('filter_mismatch')
        self.results[source]['raw_exports'][0]['filter'] = None
        self.freeze(source)
        self.fails('filter_mismatch')
        self.results[source]['raw_exports'][0]['filter'] = pinned_filter('windows', self.manifest['collectors'][0]['config'])
        self.freeze(source)
        self.assertEqual(len(self.seal()['events']), 1)

    def test_powershell_outside_filter_refused_and_4104_and_40961_seal(self):
        ps = ('Microsoft-Windows-PowerShell/Operational', 'Microsoft-Windows-PowerShell')
        source = self.add('windows', [windows(*ps, 4104, {'RunspaceId':'r'}, 1),
                                      windows(*ps, 40961, body='', index=3),
                                      windows(*ps, 8193, {'RunspaceId':'r'}, 2)])
        self.fails('filter_mismatch')
        self.results[source]['raw_exports'][0]['records'].pop()
        self.freeze(source)
        self.assertEqual(sorted(e['event_type'] for e in self.seal()['events']), ['40961', '4104'])

    def test_unmapped_provider_inside_filter_is_unsupported(self):
        self.add('windows', [windows('System', 'Other-Provider', 7036, {'param1':'svc','param2':'running'})])
        self.fails('unsupported_source_schema')

    def test_cloudtrail_event_outside_filter_and_filter_drift_refused(self):
        record = cloud()
        other = cloud('StopLogging')
        other.update(eventName='DescribeTrails', eventID='other')
        source = self.add('aws', [record, other])
        self.fails('filter_mismatch')
        self.results[source]['raw_exports'][0]['records'] = [record]
        self.results[source]['raw_exports'][0]['filter']['event_names'].append('DescribeTrails')
        self.freeze(source)
        self.fails('filter_mismatch')

    def test_linux_and_zeek_exports_record_no_filter(self):
        source = self.add('linux', [journal()])
        self.results[source]['raw_exports'][0]['filter'] = {'event_names':[]}
        self.freeze(source)
        self.fails('filter_mismatch')

    def test_raw_telemetry_does_not_invent_detector_condition(self):
        self.add('windows',[windows(fields={'SubjectUserName':'private-user','CommandLine':'T1059.001 '+SECRET})])
        bundle = self.seal()
        self.assertFalse(any('detector_attack_ids' in e['fields'] for e in bundle['events']))

    def test_offset_original_precision_and_uncertainty(self):
        for digits in ('1234567', '123456789'):
            with self.subTest(digits=digits):
                self.setUp()
                original = '2026-01-01T00:01:00.' + digits + 'Z'
                self.add('windows',[windows(time=original)])
                self.manifest['targets'][0]['clock']['offset_seconds'] = 2
                self.mapping['assessment_windows'] = [{'start_inclusive':WINDOW['start_inclusive'],'end_exclusive':'2026-01-01T00:09:00Z'}]
                bundle = self.seal()
                event = bundle['events'][0]
                self.assertEqual(event['timestamp_utc'],'2026-01-01T00:00:58.123456Z')
                self.assertEqual(event['fields']['timestamp_original'],original)
                source = next(s for s in bundle['sources'] if s['source_id']==event['source_id'])
                self.assertAlmostEqual(source['clock_uncertainty_seconds'],0.010001)

    def test_ipv4_mapped_and_ipv6_spellings_share_one_pseudonym(self):
        self.add('windows', [windows(event=4768, fields={'TargetUserName':'private-user','IpAddress':'::ffff:192.0.2.12'}),
            windows('Microsoft-Windows-Sysmon/Operational','Microsoft-Windows-Sysmon',3,
                    {'SourceIp':'2001:db8::1','DestinationIp':'2001:0DB8:0000:0000:0000:0000:0000:0001'},2)])
        self.add('zeek', [zeek('conn')])
        events = self.seal()['events']
        kerberos = next(e for e in events if e['event_type'] == '4768')['fields']['IpAddress']
        conn = next(e for e in events if e['event_type'] == 'conn')['fields']['id.orig_h']
        self.assertEqual(kerberos, conn)
        sysmon = next(e for e in events if e['event_type'] == '3')['fields']
        self.assertEqual(sysmon['SourceIp'], sysmon['DestinationIp'])

    def test_host_local_identifiers_do_not_correlate_across_assets(self):
        ps = ('Microsoft-Windows-PowerShell/Operational', 'Microsoft-Windows-PowerShell')
        self.add('linux', [audit(ses='7')])
        self.add('windows', [windows(*ps, 4104, {'PipelineId':'7'}, 1, computer='host-b'),
                             windows(event=4624, fields={'LogonId':'0x3e7','LogonType':'5'}, index=2, computer='host-b')],
                 identity={'computer_name':'host-b'})
        self.add('windows', [windows(event=4624, fields={'LogonId':'0x3e7','LogonType':'5'}, computer='host-c')],
                 identity={'computer_name':'host-c'})
        events = self.seal()['events']
        session = next(e for e in events if e['event_type'] == 'SYSCALL')['fields']['ses']
        pipeline = next(e for e in events if e['event_type'] == '4104')['fields']['PipelineId']
        self.assertNotEqual(session, pipeline)
        logons = [e['fields']['LogonId'] for e in events if e['event_type'] == '4624']
        self.assertEqual(len(logons), 2)
        self.assertNotEqual(logons[0], logons[1])

    def test_fqdn_query_correlates_with_host_and_syslog_identifier_uses_basename(self):
        self.add('windows', [windows(computer='Private-Host.lab.test')])
        self.add('zeek', [zeek('dns', query='PRIVATE-HOST.LAB.TEST.')])
        self.add('linux', [journal(SYSLOG_IDENTIFIER='sshd'),
                           journal('private-cursor-2', SYSLOG_IDENTIFIER='/usr/sbin/private-daemon', _COMM='private-daemon')],
                 identity={'computer_name':'linux-host'})
        events = self.seal()['events']
        host = next(e for e in events if e['event_type'] == '4688')['fields']['host_id']
        query = next(e for e in events if e['event_type'] == 'dns')['fields']['query']
        self.assertEqual(host, query)
        journals = [e['fields'] for e in events if e['event_type'] == 'journal_record']
        literal = next(f for f in journals if f['_COMM'] == 'sshd')
        self.assertEqual(literal['SYSLOG_IDENTIFIER'], 'sshd')
        hidden = next(f for f in journals if f['_COMM'] != 'sshd')
        self.assertTrue(hidden['SYSLOG_IDENTIFIER'].startswith('process-'))
        self.assertEqual(hidden['SYSLOG_IDENTIFIER'], hidden['_COMM'])

    def test_windows_dash_is_absent_value(self):
        self.add('windows', [windows(event=4624, fields={'SubjectUserName':'private-user','LogonType':'2',
                                                         'IpAddress':'-','IpPort':'-','LogonId':'0x3e7'})])
        fields = self.seal()['events'][0]['fields']
        self.assertNotIn('IpPort', fields)
        self.assertNotIn('IpAddress', fields)
        self.assertEqual(fields['LogonType'], 2)

    def test_zeek_service_lists_use_complete_analyzer_names(self):
        records = [zeek('conn', str(i), uid='c'+str(i), service=service)
                   for i, service in enumerate(('krb_tcp', 'ssl,http', 'dce_rpc', 'ldap_tcp', '-ssl'), 1)]
        self.add('linux', [journal()])
        source = self.add('zeek', records)
        bundle = self.seal('accepted')
        self.assertEqual(sorted(e['fields']['service'] for e in bundle['events'] if e['event_type'] == 'conn'),
                         ['-ssl', 'dce_rpc', 'krb_tcp', 'ldap_tcp', 'ssl,http'])
        self.results[source]['raw_exports'][0]['records'] = [zeek('conn', service='bogus-analyzer')]
        self.freeze(source)
        self.fails('unsupported_source_schema')

    def test_zeek_sensor_has_own_clock_unassessed_asset_and_address_enrolment(self):
        self.add('linux', [journal()])
        endpoint = self.manifest['targets'][0]['target_id']
        config = {'manifest_path':'manifest.json','streams':['conn'],
                  'address_assets':[{'address':'192.0.2.12','target_id':endpoint}]}
        self.add('zeek', [zeek('conn'), zeek('conn', '2', uid='other', **{'id.orig_h':'198.51.100.7','id.resp_h':'198.51.100.8'})],
                 config=config, offset=5)
        bundle = self.seal()
        assets = {a['asset_id'] for a in bundle['assets']}
        sensor = bundle['unassessed_asset_ids'][0]
        endpoint_asset = (assets - {sensor}).pop()
        self.assertEqual({q['asset_id'] for q in bundle['assessment_questions']}, {endpoint_asset})
        conns = [e for e in bundle['events'] if e['event_type'] == 'conn']
        owners = {e['asset_id'] for e in conns}
        self.assertEqual(owners, {endpoint_asset, sensor})
        for event in conns:
            self.assertEqual(event['timestamp_utc'], '2026-01-01T00:00:55.000000Z')
        zeek_source = next(s for s in bundle['sources'] if s['telemetry'] == 'zeek')
        self.assertEqual(zeek_source['clock_offset_seconds'], 5)
        self.assertEqual(sorted(zeek_source['asset_ids']), sorted([endpoint_asset, sensor]))
        journal_event = next(e for e in bundle['events'] if e['event_type'] == 'journal_record')
        self.assertEqual(journal_event['timestamp_utc'], '2026-01-01T00:01:00.000000Z')
        # A sensor may not borrow an assessed endpoint's identity/clock.
        self.manifest['collectors'][1]['target_id'] = endpoint
        with self.assertRaises(BenchmarkError) as caught:
            self.seal('borrowed')
        self.assertEqual(caught.exception.code, 'scope_mismatch')
        self.manifest['collectors'][1]['target_id'] = 'private-target-1'
        config['address_assets'].append({'address':'192.0.2.13','target_id':'unenrolled'})
        with self.assertRaises(BenchmarkError) as caught:
            self.seal('unenrolled')
        self.assertEqual(caught.exception.code, 'invalid_mapping')

    def test_intended_gap_retained_but_not_an_incomplete_negative(self):
        source = self.add('linux',[journal()],['missing_audit_export'])
        self.mapping['known_gaps'] = [{'source_id':source,'target_id':self.manifest['targets'][0]['target_id'],'reason':'missing_audit_export'}]
        bundle = self.seal()
        completeness = {s['telemetry']:s['completeness'] for s in bundle['sources']}
        self.assertEqual(completeness, {'journald':'complete','linux-audit':'unknown'})
        audit_source = next(s['source_id'] for s in bundle['sources'] if s['telemetry'] == 'linux-audit')
        self.assertEqual([(g['source_id'], g['reason']) for g in bundle['known_gaps']], [(audit_source, 'missing_audit_export')])
        self.results[source]['raw_exports'][0]['complete'] = False
        self.freeze(source)
        with self.assertRaises(BenchmarkError) as caught:
            self.seal('incomplete')
        self.assertEqual(caught.exception.code,'incomplete_export')

    def test_audit_records_contradict_missing_audit_gap(self):
        self.add('linux',[journal(), audit()],['missing_audit_export'])
        self.fails('source_metadata_mismatch')

    def test_process_events_absent_is_failed_collection_not_gap(self):
        self.add('windows',[windows()],['process_events_absent'])
        self.fails('incomplete_export')

    def test_process_instrumentation_absent_is_asset_gap_without_source(self):
        config = {'channels':['System'],'evtx_files':[]}
        self.add('windows',[windows('System','Service Control Manager',7036,{'param1':'svc','param2':'running'})],
                 ['process_instrumentation_absent'], config=config)
        bundle = self.seal()
        self.assertEqual([(g['source_id'], g['reason']) for g in bundle['known_gaps']],
                         [(None, 'process_instrumentation_absent')])
        self.assertEqual([s['telemetry'] for s in bundle['sources']], [None])

    def test_gap_from_wrong_collector_kind_is_unverified(self):
        self.add('windows',[windows()],['missing_audit_export'])
        self.fails('unverified_gap')

    def test_identity_audit_declared_only_for_domain_controllers(self):
        source = self.add('windows', [windows()], identity={'domain_controller':False})
        bundle = self.seal()
        self.assertNotIn('identity-audit', {s['telemetry'] for s in bundle['sources']})
        self.results[source]['raw_exports'][0]['records'] = [windows(event=4768, fields={'TargetUserName':'private-user'})]
        self.freeze(source)
        with self.assertRaises(BenchmarkError) as caught:
            self.seal('member')
        self.assertEqual(caught.exception.code, 'scope_mismatch')

    def test_unverified_intended_gap_rejected(self):
        source = self.add('linux',[journal()])
        self.mapping['known_gaps'] = [{'source_id':source,'target_id':self.manifest['targets'][0]['target_id'],'reason':'missing_audit_export'}]
        self.fails('unverified_gap')

    def test_unknown_xml_event_and_external_entity_rejected(self):
        source = self.add('windows',[windows(event=99999)])
        self.fails('filter_mismatch')
        record = windows()
        record['xml'] = '<!DOCTYPE Event [<!ENTITY x SYSTEM "file:///private">]>'+record['xml']
        self.results[source]['raw_exports'][0]['records'] = [record]
        self.freeze(source)
        self.fails('unsafe_xml')

    def test_metadata_disagreement_rejected(self):
        source = self.add('windows',[windows()])
        for key, value in (('provider','other-provider'), ('channel','System'),
                           ('record_id',999), ('timestamp_utc','2026-01-01T00:02:00Z')):
            with self.subTest(key=key):
                record = windows()
                record[key] = value
                self.results[source]['raw_exports'][0]['records'] = [record]
                self.freeze(source)
                self.fails('source_metadata_mismatch')

    def test_duplicate_xml_metadata_and_fields_never_last_win(self):
        source = self.add('windows',[windows()])
        mutations = (
            ('<EventID>4688</EventID>', '<EventID>4688</EventID><EventID>4688</EventID>'),
            ('</System>', '</System><System/>'),
            ('</EventData>', '<Data Name="SubjectUserName">other-user</Data></EventData>'))
        for before, after in mutations:
            with self.subTest(before=before):
                record = windows()
                record['xml'] = record['xml'].replace(before,after)
                self.results[source]['raw_exports'][0]['records'] = [record]
                self.freeze(source)
                self.fails('unsupported_source_schema')

    def test_windows_duplicate_identity_includes_xml_digest(self):
        reset = windows(fields={'SubjectUserName':'other-user','NewProcessName':'C:\\x\\hostname.exe'})
        source = self.add('windows',[windows(), reset])
        self.assertEqual(len(self.seal('accepted')['events']), 2)
        self.results[source]['raw_exports'][0]['records'] = [windows(), windows()]
        self.freeze(source)
        self.fails('duplicate_record')

    def test_powershell_and_system_make_no_windows_security_claim(self):
        self.add('windows',[
            windows('Microsoft-Windows-PowerShell/Operational','Microsoft-Windows-PowerShell',
                    4104,{'ScriptBlockText':SECRET},1),
            windows('System','Service Control Manager',7036,{'param1':'private-service','param2':'running'},2)])
        bundle = self.seal()
        sources = {s['source_id']:s for s in bundle['sources']}
        self.assertEqual({e['event_type'] for e in bundle['events']},{'4104','7036'})
        self.assertEqual({e['fields']['channel'] for e in bundle['events']},
                         {'System','Microsoft-Windows-PowerShell/Operational'})
        for event in bundle['events']:
            self.assertIsNone(sources[event['source_id']]['telemetry'])

    def test_exercise_records_must_survive_unchanged_in_final_export(self):
        first, second = journal('cursor-1'), journal('cursor-2')
        source = self.add('linux', [first, second])
        self.exercise(source, [copy.deepcopy(first)])
        self.seal('accepted')
        for earlier in ([journal('cursor-3')], [journal('cursor-1', MESSAGE='changed')]):
            with self.subTest(earlier=earlier[0]['record_id']):
                self.exercise(source, earlier)
                self.fails('incomplete_export')
        self.exercise(source, [first])
        self.results[source]['raw_exports'][0]['records'] = [second]
        self.freeze(source)
        self.fails('incomplete_export')

    def test_export_budget_counts_export_bytes_not_driver_metadata(self):
        record = journal(MESSAGE='m' * 7000)
        source = self.add('linux', [record])
        self.manifest['limits']['max_export_bytes'] = 16000
        self.manifest['collectors'][0]['max_bytes'] = 8000
        self.mapping['max_public_bytes'] = 14000
        self.results[source]['evidence']['padding'] = 'p' * 30000
        self.exercise(source, [record])
        self.assertTrue(self.snapshots[0]['byte_count'] > 16000)
        self.seal()
        self.manifest['limits']['max_export_bytes'] = 14000
        with self.assertRaises(BenchmarkError) as caught:
            self.seal('over-budget')
        self.assertEqual(caught.exception.code, 'output_limit')

    def test_cloud_resources_are_nested_projection_not_raw_objects(self):
        source = self.add('aws',[cloud()])
        bundle = self.seal()
        resource = bundle['events'][0]['fields']['resources'][0]
        self.assertEqual(set(resource),{'ARN','accountId','type'})
        self.assertTrue(resource['ARN'].startswith('resource-'))
        self.assertTrue(resource['accountId'].startswith('account-'))
        self.assertEqual(resource['type'],'AWS::CloudTrail::Trail')
        self.results[source]['raw_exports'][0]['records'][0]['resources'][0]['credentials'] = SECRET
        self.freeze(source)
        with self.assertRaises(BenchmarkError) as caught:
            self.seal('unsupported-resource')
        self.assertEqual(caught.exception.code,'unsupported_source_schema')
        self.assertFalse((self.root/'public'/'unsupported-resource').exists())

    def test_unknown_audit_schema_rejected_without_blob_fallback(self):
        record = audit()
        record['record']['type'] = 'NEW_SENSOR_SCHEMA'
        self.add('linux',[record])
        self.fails('unsupported_source_schema')

    def test_unknown_cloud_schema_and_wrong_account_rejected(self):
        record = cloud()
        record['eventVersion'] = '2.0'
        source = self.add('aws',[record])
        self.fails('unsupported_source_schema')
        record['eventVersion'] = '1.11'
        record['recipientAccountId'] = '000000000000'
        self.freeze(source)
        self.fails('source_metadata_mismatch')

    def test_every_allowlisted_cloud_api_remains_context_without_phase(self):
        events = self.rules['sources']['cloud-audit']['supported_event_types']
        records = []
        for index,event in enumerate(events):
            record = cloud(event)
            record['eventID'] = str(index)
            record['phase'] = SECRET
            records.append(record)
        self.add('aws',records)
        bundle = self.seal()
        self.assertEqual({e['event_type'] for e in bundle['events']},set(events))
        self.assertNotIn(SECRET.encode(),canonical_bytes(bundle))

    def test_phase_windows_are_frozen_private_evaluator_record(self):
        self.add('linux',[journal()])
        self.phases = [{'phase':'warmup','window_utc':{'start_inclusive':'2026-01-01T00:00:05Z','end_exclusive':'2026-01-01T00:00:20Z'}},
                       {'phase':'cleanup','window_utc':{'start_inclusive':'2026-01-01T00:03:00Z','end_exclusive':'2026-01-01T00:04:00Z'}},
                       {'phase':'exercise','window_utc':{'start_inclusive':'2026-01-01T00:00:30Z','end_exclusive':'2026-01-01T00:02:00Z'}}]
        self.seal()
        record = decode_json((self.root/'sealing'/'phase-windows.json').read_bytes())
        self.assertEqual(record['record_type'], 'evaluator_phase_windows')
        self.assertEqual([p['phase'] for p in record['phases']], ['warmup','exercise','cleanup'])
        self.assertNotIn(b'warmup', self.public_bytes())
        self.assertNotIn(b'phase', self.public_bytes())
        self.phases = self.phases[:2]
        with self.assertRaises(BenchmarkError) as caught:
            self.seal('changed')
        self.assertEqual(caught.exception.code, 'mapping_conflict')
        self.phases = [{'phase':'run','window_utc':copy.deepcopy(WINDOW)}]
        with self.assertRaises(BenchmarkError) as caught:
            self.seal('invalid')
        self.assertEqual(caught.exception.code, 'invalid_mapping')

    def test_digest_mutation_and_descriptor_escape_rejected(self):
        self.add('linux',[journal()])
        path = self.root/self.snapshots[0]['path']
        path.write_bytes(path.read_bytes()+b' ')
        self.fails('digest_mismatch')
        self.snapshots[0]['path'] = '../private.json'
        self.fails('unsafe_path')

    def test_complete_watermark_must_cover_whole_window(self):
        source = self.add('linux',[journal()])
        self.results[source]['raw_exports'][0]['watermark_utc'] = TIME
        self.freeze(source)
        self.fails('incomplete_export')

    def test_out_of_window_and_duplicate_records_not_silently_filtered(self):
        record = journal()
        source = self.add('linux',[record,copy.deepcopy(record)])
        self.fails('duplicate_record')
        self.results[source]['raw_exports'][0]['records'] = [zeek('conn')]
        self.manifest['collectors'][0]['kind'] = 'zeek'
        self.manifest['collectors'][0]['config'] = {'manifest_path':'manifest.json','streams':['conn'],'address_assets':[]}
        self.results[source]['raw_exports'][0]['records'][0]['record']['ts'] -= 3600
        self.freeze(source)
        self.fails('scope_mismatch')

    def test_oversize_blocks_without_sampling(self):
        self.add('linux',[journal()])
        self.mapping['max_public_bytes'] = 100
        self.fails('output_limit')

    def test_mapping_frozen_and_public_destination_new_only(self):
        self.add('linux',[journal()])
        self.seal()
        with self.assertRaises(BenchmarkError):
            self.seal()
        self.mapping['entity_aliases'].append({'kind':'host','values':['other-host','other-machine']})
        with self.assertRaises(BenchmarkError) as caught:
            self.seal('changed')
        self.assertEqual(caught.exception.code,'mapping_conflict')

    def test_interrupted_first_seal_is_recoverable(self):
        self.add('linux',[journal()])
        first = self.seal()
        # Crash after identity.json but before mapping.json.
        (self.root/'sealing'/'mapping.json').unlink()
        self.assertEqual(self.seal('second'), first)
        self.assertEqual((self.root/'sealing'/'mapping.json').read_bytes(), canonical_bytes(self.mapping))
        # Crash after an identical mapping.json but before identity.json.
        (self.root/'sealing'/'identity.json').unlink()
        self.seal('third')
        self.assertTrue((self.root/'sealing'/'identity.json').exists())
        (self.root/'sealing'/'identity.json').unlink()
        (self.root/'sealing'/'mapping.json').write_bytes(b'{"different":true}')
        with self.assertRaises(BenchmarkError) as caught:
            self.seal('fourth')
        self.assertEqual(caught.exception.code, 'mapping_conflict')

    def test_alias_overlap_and_cloud_os_mislabel_block(self):
        self.add('aws',[cloud()])
        self.mapping['assets'][0]['os_family'] = 'windows-server'
        self.fails('scope_mismatch')
        self.mapping['assets'][0]['os_family'] = 'not-applicable'
        self.mapping['entity_aliases'].append({'kind':'account','values':['1000','other-user']})
        self.fails('invalid_mapping')
        self.mapping['entity_aliases'][-1] = {'kind':'host','values':['shared.lab.test','alias-a']}
        self.mapping['entity_aliases'].append({'kind':'domain','values':['SHARED.lab.test.','alias-b']})
        self.fails('invalid_mapping')

    def test_empty_complete_sensor_still_has_questions_and_source(self):
        self.add('linux',[],['missing_audit_export'])
        bundle = self.seal()
        self.assertEqual(bundle['events'],[])
        self.assertTrue(bundle['sources'])
        self.assertEqual(len(bundle['assessment_questions']),1)
        self.assertEqual(bundle['files'][0]['byte_count'],0)

    def test_unmapped_field_rule_cannot_publish_credentials(self):
        self.add('linux',[journal()])
        self.rules['sources']['journald']['allowed_fields'].append('MESSAGE')
        self.fails('unsupported_source_schema')

    def test_rule_transformation_lists_must_match_actual_behavior(self):
        self.add('linux',[journal()])
        allow_content(self.rules, 'journald', '_CMDLINE')
        for key in ('pseudonym_fields', 'basename_fields', 'content_fields'):
            with self.subTest(key=key):
                original = self.rules['sources']['journald'][key]
                self.rules['sources']['journald'][key] = []
                self.fails('unsupported_source_schema')
                self.rules['sources']['journald'][key] = original
        self.seal()

    @unittest.skipUnless(KIT_RULES.is_file(), 'separate range kit is not present')
    def test_shipped_kit_rules_are_accepted(self):
        validate_rules(decode_json(KIT_RULES.read_bytes()))

    def test_windows_channel_lists_are_in_lockstep(self):
        import benchmark_evidence
        import benchmark_windows
        self.assertEqual(set(benchmark_windows.CHANNELS), set(benchmark_evidence.CHANNELS))
        self.assertEqual(set(CHANNEL_IDS), set(benchmark_evidence.CHANNELS))
        script = KIT_RULES.parent / 'Invoke-BenchmarkAction.ps1'
        if script.is_file():
            allowed = re.search(r"\$allowed = @\(([^)]*)\)", script.read_text(encoding='utf-8')).group(1)
            self.assertEqual(set(re.findall(r"'([^']+)'", allowed)), set(benchmark_evidence.CHANNELS))

    def content_fields(self, command, parent='C:\\Windows\\explorer.exe'):
        allow_content(self.rules, 'windows-security', 'CommandLine', 'ParentCommandLine')
        self.add('windows', [windows(fields={'SubjectUserName':'private-user', 'NewProcessName':'C:\\Windows\\System32\\cmd.exe',
                                             'CommandLine':command, 'ParentCommandLine':parent})])
        bundle = self.seal()
        return bundle['events'][0]['fields'], self.public_bytes()

    def test_sealed_public_output_contains_sanitized_command_line(self):
        fields, public = self.content_fields('cmd.exe /c whoami /user private-user \\\\private-host\\share 192.0.2.12')
        self.assertTrue(fields['CommandLine'].startswith('cmd.exe /c whoami /user '))
        self.assertIn(fields['SubjectUserName'], fields['CommandLine'])
        self.assertEqual(fields['ParentCommandLine'], 'C:\\Windows\\explorer.exe')
        for raw in (b'private-user', b'private-host', b'192.0.2.12'):
            self.assertNotIn(raw, public)
        self.assertIn('address-', fields['CommandLine'])

    def test_password_in_command_line_is_redacted(self):
        fields, public = self.content_fields('net user svc /add /password:Hunter2Secret')
        self.assertIn('[REDACTED:', fields['CommandLine'])
        self.assertNotIn(b'Hunter2Secret', public)

    def test_campaign_id_in_command_line_is_still_refused(self):
        self.manifest['campaign_id'] = 'secret-campaign-77'
        allow_content(self.rules, 'windows-security', 'CommandLine')
        self.add('windows', [windows(fields={'SubjectUserName':'private-user', 'CommandLine':'cmd.exe /c echo secret-campaign-77'})])
        self.fails('forbidden_public_metadata')

    def test_attack_tokens_in_content_are_masked(self):
        fields, public = self.content_fields('powershell.exe -File C:\\AtomicRedTeam\\atomics\\T1059.001\\run.ps1 T1003')
        self.assertIn('T####', fields['CommandLine'])
        self.assertNotIn(b'T1059', public)
        self.assertNotIn(b'T1003', public)
        self.assertNotIn('detector_attack_ids', fields)

    def test_oversized_content_is_marked_and_gapped(self):
        fields, _ = self.content_fields('cmd.exe /c echo ' + 'A' * 20000)
        self.assertIn('truncated', fields['CommandLine'])
        bundle = decode_json((self.root/'public'/'bundle'/'evidence.json').read_bytes())
        self.assertIn('content_truncated', [gap['reason'] for gap in bundle['known_gaps']])

    def test_linux_and_cloud_content_fields(self):
        allow_content(self.rules, 'journald', '_CMDLINE', 'MESSAGE')
        allow_content(self.rules, 'linux-audit', 'argv')
        allow_content(self.rules, 'cloud-audit', 'userAgent', 'requestParameters', 'errorMessage')
        self.add('linux', [journal('cursor-a', _CMDLINE='/usr/bin/id -u'),
                           journal('cursor-b', _TRANSPORT='audit', _CMDLINE='/usr/sbin/auditd', MESSAGE='type=EXECVE argc=2 a0="id"'),
                           audit(type='EXECVE', argv=['id', '-u'])])
        record = cloud()
        record['requestParameters'] = {'name':'private-trail'}
        record['userAgent'] = 'aws-cli/2.15.0'
        record['errorMessage'] = 'denied'
        self.add('aws', [record])
        bundle = self.seal()
        by_type = {}
        for event in bundle['events']:
            by_type.setdefault(event['event_type'], []).append(event['fields'])
        journals = by_type['journal_record']
        self.assertEqual(sorted(f['_CMDLINE'] for f in journals), ['/usr/bin/id -u', '/usr/sbin/auditd'])
        self.assertEqual(sum('MESSAGE' in f for f in journals), 1)
        self.assertTrue(any(f.get('MESSAGE', '').startswith('type=EXECVE') for f in journals))
        self.assertNotIn(SECRET.encode(), self.public_bytes())
        self.assertEqual(by_type['EXECVE'][0]['argv'], 'id -u')
        trail = by_type['StopLogging'][0]
        self.assertEqual(trail['userAgent'], 'aws-cli/2.15.0')
        self.assertEqual(trail['errorMessage'], 'denied')
        self.assertIn(trail['requestParameters.name'], trail['requestParameters'])
        self.assertNotIn(b'private-trail', self.public_bytes())

    def test_classic_powershell_wmi_and_task_scheduler_channels(self):
        channels = ['Windows PowerShell', 'Microsoft-Windows-WMI-Activity/Operational', 'Microsoft-Windows-TaskScheduler/Operational']
        classic = windows('Windows PowerShell', 'PowerShell', 400, index=1, body=(
            '<EventData><Data>Available</Data><Data>None</Data>'
            '<Data>HostApplication=powershell.exe -NoProfile</Data></EventData>'))
        wmi = windows('Microsoft-Windows-WMI-Activity/Operational', 'Microsoft-Windows-WMI-Activity', 5861, index=2, body=(
            '<UserData><Operation_ESStoConsumerBinding xmlns="http://manifests.microsoft.com/win/2006/windows/WMI">'
            '<Namespace>//./root/subscription</Namespace><ESS>updater</ESS>'
            '<PossibleCause>Binding EventFilter to CommandLineEventConsumer</PossibleCause>'
            '</Operation_ESStoConsumerBinding></UserData>'))
        task = windows('Microsoft-Windows-TaskScheduler/Operational', 'Microsoft-Windows-TaskScheduler', 106, index=3,
                       fields={'TaskName':'\\Updater', 'UserContext':'private-user'})
        self.add('windows', [classic, wmi, task], config={'channels':channels, 'evtx_files':[]})
        bundle = self.seal()
        fields = {e['event_type']: e['fields'] for e in bundle['events']}
        self.assertEqual(set(fields), {'400', '5861', '106'})
        self.assertEqual(fields['400']['NewEngineState'], 'Available')
        self.assertEqual(fields['400']['HostDetails'], 'HostApplication=powershell.exe -NoProfile')
        self.assertEqual(fields['5861']['PossibleCause'], 'Binding EventFilter to CommandLineEventConsumer')
        self.assertEqual(fields['106']['TaskName'], '\\Updater')
        self.assertTrue(fields['106']['UserContext'].startswith('account-'))
        self.assertEqual({s['telemetry'] for s in bundle['sources']}, {None})

    def test_unnamed_event_data_outside_classic_channel_is_refused(self):
        self.add('windows', [windows(body='<EventData><Data>private-user</Data></EventData>')])
        self.fails('unsupported_source_schema')

    def test_source_symlink_is_rejected(self):
        self.add('linux',[journal()])
        path = self.root/self.snapshots[0]['path']
        original = self.root/'original.json'
        path.rename(original)
        try:
            path.symlink_to(original)
        except OSError:
            self.skipTest('host cannot create symbolic links')
        with self.assertRaises(BenchmarkError):
            self.seal()


if __name__ == '__main__':
    unittest.main()

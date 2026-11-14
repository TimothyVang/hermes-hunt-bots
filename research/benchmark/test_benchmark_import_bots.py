"""benchmark_import_bots tests on INVENTED BOTS-shaped samples only (no real BOTS data)."""
import contextlib
import copy
import gzip
import io
import json
import shutil
import tempfile
import unittest
from pathlib import Path

import benchmark_consensus
import benchmark_import_bots as bots
import benchmark_import_otrf as otrf
from benchmark_contracts import BenchmarkError, decode_json, validate_public_bundle, validate_truth
from benchmark_paths import FRAMEWORK
from benchmark_sanitize import scan_leaks

HERE = Path(__file__).resolve().parent
SAMPLE = HERE / 'benchmarks' / 'importers' / 'sample'
V3_SAMPLE = SAMPLE / 'bots-v3-sample.csv'
V1_SAMPLE = SAMPLE / 'bots-v1-sample.jsonl'
PROVENANCE = SAMPLE / 'bots-provenance.json'
CURATION = SAMPLE / 'curation-bots.json'
BASE = 1767348000  # 2026-01-02T10:00:00Z, the invented sample's first minute
START, END = '2026-01-02T10:00:00+00:00', '2026-01-02T10:01:00+00:00'
SALT = bytes(range(32))
SECRETS = ('Winter2026', 'Hunter2pass', 'AKIAEXAMPLEKEY000003', 'invented-cookie')


def gz(data):
    return gzip.compress(data, mtime=0)


class BotsTestBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.fields = bots.load_field_map()

    def v3_data(self, extra_buckets=(), csv_bytes=None):
        data = self.root / 'v3'
        (data / 'botsv3-export').mkdir(parents=True)
        shutil.copy(PROVENANCE, data / 'provenance.json')
        (data / 'botsv3-export' / ('db_%d_%d_1.csv.gz' % (BASE + 3700, BASE))).write_bytes(
            gz(csv_bytes if csv_bytes is not None else V3_SAMPLE.read_bytes()))
        for name, content in extra_buckets:
            (data / 'botsv3-export' / name).write_bytes(gz(content))
        return data

    def scan(self, data, window=(START, END), **profile):
        return bots.scan('v3', data, self.fields, window, 'sample', **profile)

    def draft(self, scan_result, partition=None, **kwargs):
        return bots.build_case(scan_result, self.fields, SALT, partition or scan_result['window'], draft=True,
                               **kwargs)


class FieldMapTest(BotsTestBase):
    def test_shipped_allowlist_reuses_otrf_and_attackdata_maps(self):
        security = self.fields['sourcetypes']['WinEventLog:Security']
        self.assertEqual(security['events']['4688']['CommandLine'], 'content')
        self.assertEqual(self.fields['sourcetypes']['aws:cloudtrail']['events']['AwsApiCall']['userIdentity.arn'],
                         'aws-arn')
        self.assertEqual(sorted(self.fields['external']), ['attackdata', 'otrf'])
        self.assertEqual(bots.source_name(self.fields, 'never:seen'), 'st-never-seen')

    def test_bad_field_maps_are_refused(self):
        base = json.loads((HERE / 'benchmarks' / 'importers' / 'bots-fields.json').read_text('utf-8'))
        cases = (({'parser': 'shell'}, 'invalid_choice'), ({'telemetry': 'made-up'}, 'invalid_choice'),
                 ({'events': {'*': {'x': 'eval'}}}, 'invalid_choice'),
                 ({'metadata_only': {'x': 'content'}}, 'invalid_choice'),
                 ({'events_from': 'otrf:NoSuchChannel'}, 'invalid_choice'), ({'source': 'Bad Name'}, 'invalid_identifier'))
        for change, code in cases:
            with self.subTest(change=change):
                value = copy.deepcopy(base)
                value['sourcetypes']['stream:http'].update(change)
                path = self.root / 'fields.json'
                path.write_text(json.dumps(value), encoding='utf-8')
                with self.assertRaises(BenchmarkError) as caught:
                    bots.load_field_map(path)
                self.assertEqual(caught.exception.code, code)
                path.unlink()


class ParserTest(BotsTestBase):
    def test_classic_message_labels_map_to_eventdata_names(self):
        message = ('A new process has been created.\n\nCreator Subject:\n\tSecurity ID:\t\tLAB\\ann\n'
                   '\tAccount Name:\t\tann\n\nProcess Information:\n\tNew Process Name:\tC:\\x\\a.exe\n'
                   '\tCreator Process Name:\tC:\\x\\b.exe\n\tProcess Command Line:\ta.exe -x\n\n'
                   'Privileges:\t\tSeA\n\t\t\tSeB\n\nToken Elevation Type indicates: a paragraph.')
        fields = bots.parse_classic_message(message, 4688)
        self.assertEqual((fields['SubjectUserSid'], fields['SubjectUserName'], fields['NewProcessName'],
                          fields['ParentProcessName'], fields['CommandLine'], fields['PrivilegeList']),
                         ('LAB\\ann', 'ann', 'C:\\x\\a.exe', 'C:\\x\\b.exe', 'a.exe -x', 'SeA\nSeB'))
        self.assertEqual(bots.parse_classic_message('Net.\n\nNetwork Information:\n\tSource Port:\t\t5\n', 5156)
                         ['SourcePort'], '5')

    def test_xml_refuses_entities_and_json_tolerates_stream_bytes(self):
        status = bots.parse_record(self.fields, 'XmlWinEventLog:Microsoft-Windows-Sysmon/Operational',
                                   '<!DOCTYPE x [<!ENTITY a "b">]><Event/>')[0]
        self.assertEqual(status, 'unparsed')
        status, _, record_id, fields, notes = bots.parse_record(
            self.fields, 'stream:udp', '{"src_ip":"192.0.2.1","flow_id":"f-1","dest_content":"\\xac\\x01"}\n{"a":1}')
        self.assertEqual((status, record_id, fields['dest_content'], notes),
                         ('parsed', 'f-1', '\\xac\\x01', {'merged_json_objects_dropped': 1}))

    def test_text_formats(self):
        _, type_key, _, fields, _ = bots.parse_record(
            self.fields, 'pan:traffic', 'Aug 03 11:02:32 10.0.1.1  1,2017/08/03 11:02:32,0001,TRAFFIC,end,1,'
            '2017/08/03 11:02:32,192.0.2.4,198.51.100.9,0.0.0.0,0.0.0.0,rule1,lab\\ann,,web-browsing')
        self.assertEqual((type_key, fields['src_ip'], fields['src_user'], fields['app']),
                         ('TRAFFIC', '192.0.2.4', 'lab\\ann', 'web-browsing'))
        _, type_key, _, fields, _ = bots.parse_record(
            self.fields, 'syslog', 'Aug 20 09:04:14 hwf.example.test  fv="nvzFlow_v3" pr="17" sa="192.0.2.5" '
            'da="192.0.2.6"')
        self.assertEqual((type_key, fields['sa'], 'message' in fields), (None, '192.0.2.5', False))
        _, type_key, _, fields, _ = bots.parse_record(
            self.fields, 'access_combined', '192.0.2.7 - - [20/Aug/2018:09:04:13 +0000] "GET / HTTP/1.1" 200 19 '
            '"-" "agent/1.0"')
        self.assertEqual((fields['request'], fields['status'], fields['useragent']), ('GET / HTTP/1.1', '200',
                                                                                       'agent/1.0'))
        _, type_key, _, fields, _ = bots.parse_record(
            self.fields, 'cisco:asa', 'Aug 20 09:04:13 FW %ASA-6-302014: Teardown TCP connection 1')
        self.assertEqual((type_key, fields['message']), ('302014', 'Teardown TCP connection 1'))
        self.assertEqual(bots.parse_record(self.fields, 'Perfmon:CPU', 'x=1')[0], 'metadata')
        self.assertEqual(bots.parse_record(self.fields, 'never:seen', 'x')[0], 'unknown_sourcetype')


class ScanBuildTest(BotsTestBase):
    def test_draft_publishes_sanitized_pseudonymized_evidence(self):
        data = self.v3_data()
        result = self.scan(data, exclude_sourcetypes=['WinRegistry'])
        self.assertEqual(len(result['entries']), 17)
        case_id, outputs = self.draft(result)
        public = outputs['public/evidence.json'].decode('utf-8')
        bundle = validate_public_bundle(decode_json(outputs['public/evidence.json']))
        for secret in SECRETS:
            self.assertNotIn(secret, public)
        self.assertIn('[REDACTED:password]', public)
        self.assertIn('[REDACTED:aws_access_key]', public)
        mapping = decode_json(outputs['evaluator/pseudonyms.json'])['mapping']
        originals = [o for values in mapping.values() for o in values if len(o) >= 4]
        self.assertTrue({'analyst', 'helpdesk2', '198.51.100.7', 'labdom'} <= set(originals))
        events = {e['event_type']: e for e in bundle['events']}
        self.assertEqual(scan_leaks(json.dumps([e['fields'] for e in bundle['events']]),
                                    originals + ['wkst-01', 'web-01', 'fw-01']), [])
        self.assertNotIn('RuleName', events['sysmon:1']['fields'])
        self.assertIn('[ENCODED_COMMAND', events['sysmon:1']['fields']['CommandLine'])
        self.assertEqual(events['windows-security:4732']['fields']['TargetSid'], 'BUILTIN\\Administrators')
        self.assertEqual(events['linux-audit:SYSCALL']['fields']['command_line'], 'useradd -o -u0 svcx')
        self.assertNotIn('key', events['linux-audit:SYSCALL']['fields'])
        self.assertNotIn('cookie', events['stream-http']['fields'])
        self.assertEqual(events['st-custom-inventory']['fields'], {'timestamp_original': str(BASE + 18)})
        self.assertNotIn('"password"', events['cloudtrail:AwsApiCall']['fields']['requestParameters'])
        report = decode_json(outputs['evaluator/import-report.json'])
        self.assertEqual(report['counts']['unparsed_by_sourcetype'], {'stream:udp': 1})
        self.assertEqual(report['counts']['dropped_fields']['merged_json_objects_dropped'], 1)
        reasons = [gap['reason'] for gap in bundle['known_gaps']]
        self.assertTrue(any(r.startswith('unparsed_records: 1 ') for r in reasons))
        self.assertTrue(any('WinRegistry x1' in r for r in reasons))
        self.assertEqual(sum(r.startswith('outside_partition_window') for r in reasons), len(bundle['assets']))
        # records.jsonl indexes every event by its global line: file 1 * stride + CSV row ordinal.
        lines = [decode_json(line) for line in outputs['public/records.jsonl'].splitlines()]
        self.assertEqual(sorted(item['event_id'] for item in lines), sorted(e['event_id'] for e in bundle['events']))
        self.assertTrue(all(bots.LINE_STRIDE < item['line'] < 2 * bots.LINE_STRIDE for item in lines))
        locators = decode_json(outputs['evaluator/locators.json'])
        self.assertTrue(all(item['file'].startswith('db_') for item in locators['events'].values()))
        # Same inputs and salt -> byte-identical outputs.
        self.assertEqual(self.draft(self.scan(data, exclude_sourcetypes=['WinRegistry']))[1], outputs)
        template = decode_json(outputs['evaluator/curation-template.json'])
        self.assertEqual(template['curation']['partition_window'], bundle['window_utc'])
        self.assertEqual({a['hostname']: a['os_family'] for a in template['curation']['assets']}['web-01'], 'linux')
        with self.assertRaises(BenchmarkError) as caught:
            validate_truth(decode_json(outputs['evaluator/truth.DRAFT.json']), bundle)
        self.assertIsNotNone(caught.exception.code)

    def test_profile_filters_and_bucket_selection(self):
        outside = b'_time,source,host,sourcetype,_raw,_meta\n%d,source::x,host::WKST-01,sourcetype::stream:ip,{},m\n' % (
            BASE - 86400)
        data = self.v3_data(extra_buckets=[('db_%d_%d_2.csv.gz' % (BASE - 86000, BASE - 86400), outside)])
        result = self.scan(data, hosts=['wkst-01'], sourcetypes=['WinEventLog:Security'])
        self.assertEqual({e['host'] for e in result['entries']}, {'WKST-01'})
        self.assertEqual([item['file'] for item in result['files_read']], ['db_%d_%d_1.csv.gz' % (BASE + 3700, BASE)])
        _, outputs = self.draft(result)
        reasons = [g['reason'] for g in decode_json(outputs['public/evidence.json'])['known_gaps']]
        self.assertTrue(any(r.startswith('collection_profile_filter: 8 records of 4 hosts') for r in reasons))
        self.assertNotEqual(result['dataset_sha256'], self.scan(data)['dataset_sha256'])
        with self.assertRaises(BenchmarkError) as caught:
            self.scan(data, sourcetypes=['a'], exclude_sourcetypes=['b'])
        self.assertEqual(caught.exception.code, 'conflicting_arguments')

    def test_bucket_rows_outside_the_named_range_are_refused(self):
        # The bucket overlaps the window, but one row precedes the `earliest` its name declares.
        early = b'_time,source,host,sourcetype,_raw,_meta\n%d,source::x,host::h,sourcetype::stream:ip,{},m\n' % (
            BASE + 10)
        data = self.v3_data(extra_buckets=[('db_%d_%d_3.csv.gz' % (BASE + 30, BASE + 20), early)])
        with self.assertRaises(BenchmarkError) as caught:
            self.scan(data)
        self.assertEqual(caught.exception.code, 'bucket_range_violation')

    def test_v1_reads_newest_first_and_stops_before_the_window(self):
        data = self.root / 'v1'
        (data / 'json').mkdir(parents=True)
        shutil.copy(PROVENANCE, data / 'provenance.json')
        (data / 'json' / 'botsv1.WinEventLog-Security.json.gz').write_bytes(gz(V1_SAMPLE.read_bytes()))
        other = {'preview': False, 'offset': 0, 'result': {'_raw': 'x', '_time': '2026-01-02 04:00:10.000 MDT',
                                                            'host': 'h', 'sourcetype': 'iis'}}
        (data / 'json' / 'botsv1.iis.json.gz').write_bytes(gz(json.dumps(other).encode('utf-8') + b'\n'))
        # A multivalue `host` (JSON list) keeps its first value; Stream payload NULs become visible `\x00` text.
        stream = {'preview': False, 'offset': 0, 'result': {
            '_raw': json.dumps({'src_ip': '192.0.2.10', 'dest_ip': '198.51.100.7', 'src_content': 'GET /a\u0000b'}),
            '_time': '2026-01-02 04:00:20.000 MDT', 'host': ['sensor-01', 'sensor-01'], 'sourcetype': 'stream:http'}}
        (data / 'json' / 'botsv1.stream-http.json.gz').write_bytes(gz(json.dumps(stream).encode('utf-8') + b'\n'))
        result = bots.scan('v1', data, self.fields, (START, END), 'sample', exclude_sourcetypes=['iis'])
        self.assertEqual(len(result['entries']), 3)
        self.assertEqual(result['files_not_read'], [{'file': 'botsv1.iis.json.gz', 'sourcetype': 'iis'}])
        self.assertTrue(result['files_read'][0]['stopped_early'])
        self.assertEqual(result['files_read'][1]['multivalue_host_or_sourcetype_values_dropped'], 1)
        _, outputs = bots.build_case(result, self.fields, SALT, result['window'], draft=True)
        public = outputs['public/evidence.json'].decode('utf-8')
        self.assertNotIn('Winter2026', public)
        self.assertIn('2026-01-02 04:00:30.000 MDT', public)
        self.assertIn('GET /a\\\\x00b', public)
        lines = V1_SAMPLE.read_bytes().splitlines()
        (data / 'json' / 'botsv1.WinEventLog-Security.json.gz').write_bytes(gz(b'\n'.join([lines[1], lines[0]])))
        with self.assertRaises(BenchmarkError) as caught:
            bots.scan('v1', data, self.fields, (START, END), 'sample', exclude_sourcetypes=['iis'])
        self.assertEqual(caught.exception.code, 'unsorted_export')

    def test_bots_names_in_public_text_are_refused(self):
        text = V3_SAMPLE.read_text('utf-8').replace('inventory ok', 'botsv3 inventory ok')
        data = self.v3_data(csv_bytes=text.encode('utf-8'))
        result = self.scan(data, sourcetypes=['custom:inventory', 'linux_secure'])
        self.draft(result)  # metadata-only: the raw text is never published
        text = V3_SAMPLE.read_text('utf-8').replace('Failed password', 'botsv3 Failed password')
        (data / 'botsv3-export' / ('db_%d_%d_1.csv.gz' % (BASE + 3700, BASE))).write_bytes(gz(text.encode('utf-8')))
        with self.assertRaises(BenchmarkError) as caught:
            self.draft(self.scan(data, sourcetypes=['linux_secure']))
        self.assertEqual(caught.exception.code, 'forbidden_public_metadata')


    def test_osquery_hex_argv_is_decoded_before_sanitizing(self):
        hexed = '/bin/sh -c nc 198.51.100.7 8088; useradd -p Winter2026 svcx'.encode('utf-8').hex().upper()
        raw = json.dumps({'name': 'pack_proc_events', 'columns': {'cmdline': '"bash" "-c" ' + hexed}})
        status, _, _, fields, notes = bots.parse_record(self.fields, 'osquery:results', raw)
        self.assertEqual((status, notes), ('parsed', {'argv_rewritten': 1, 'hex_argv_decoded': 1}))
        self.assertEqual(fields['columns']['cmdline'],
                         "bash -c '/bin/sh -c nc 198.51.100.7 8088; useradd -p Winter2026 svcx'")
        quoted = json.dumps({'columns': {'cmdline': '"useradd" "-ou" "svcx" "-p" "Winter2026!" "0"'}})
        self.assertEqual(bots.parse_record(self.fields, 'osquery:results', quoted)[3]['columns']['cmdline'],
                         'useradd -ou svcx -p Winter2026! 0')
        sanitized, _ = bots.sanitize_text('useradd -ou svcx -p Winter2026! 0', lambda kind, value: value)
        self.assertNotIn('Winter2026', sanitized)
        self.assertEqual(bots.parse_record(self.fields, 'osquery:results', json.dumps(
            {'columns': {'cmdline': 'ABCDEF01 plain'}}))[3]['columns']['cmdline'], 'ABCDEF01 plain')

    def test_lab_domains_come_from_every_scanned_host(self):
        result = self.scan(self.v3_data(), hosts=['wkst-01'], sourcetypes=['stream:dns'])
        bundle = decode_json(self.draft(result)[1]['public/evidence.json'])
        self.assertEqual([e['event_type'] for e in bundle['events']], ['stream-dns'])
        self.assertNotIn('example.test', json.dumps(bundle['events']))

    def test_system_accounts_and_single_label_suffixes_stay_literal(self):
        names = bots.BotsPseudonyms(SALT)
        names.register_domains(['laptop-07.local', 'wkst-01.lab.example.test'])
        self.assertEqual(names.domains, frozenset({'lab.example.test'}))
        self.assertEqual((names.linux_user('games'), names.user('postfix'), names.account('LAB\\mysql')),
                         ('games', 'postfix', names.netbios('domain', 'LAB') + '\\mysql'))
        self.assertTrue(names.linux_user('analyst').startswith('user-'))
        self.assertNotIn('games', names.mapping.get('user', {}))
        self.assertEqual(names.user('http'), 'http')
        self.assertEqual(names.user('Administrator'), 'Administrator')
        callback_names = bots.BotsPseudonyms(SALT)
        bots._content_value(callback_names, 'action=do_login&quick_username=ann', 'f', False, {})
        self.assertIn('ann', callback_names.mapping['user'])
        text, _ = bots._content_value(callback_names, 'q=%22%26username%3Danalyst%26password%3Dx&login=true', 'f',
                                      False, {})
        self.assertEqual(text, 'q=%22%26username%3D' + callback_names.user('analyst') + '%26password%3Dx&login=true')
        text, _ = bots._content_value(callback_names, 'q=%%26username%%3Danalyst%%26', 'f', False, {})
        self.assertEqual(text, 'q=%%26username%%3D' + callback_names.user('analyst') + '%%26')


class PlanTest(BotsTestBase):
    def test_partitions_fit_the_cap_and_oversized_seconds_are_unpublishable(self):
        data = self.v3_data()
        result = self.scan(data, exclude_sourcetypes=['WinRegistry'])
        size = decode_json(self.draft(result, max_public_bytes=None)[1]['evaluator/import-report.json'])[
            'public_bytes']['prompt_projection']
        plan = bots.plan(result, self.fields, max_public_bytes=size // 2, salt=SALT)
        self.assertGreaterEqual(len(plan['partitions']), 2)
        windows = [p['window_utc'] for p in plan['partitions'] + plan['unpublishable']]
        windows.sort(key=lambda w: w['start_inclusive'])
        self.assertEqual(windows[0]['start_inclusive'], '2026-01-02T10:00:00.000000+00:00')
        self.assertEqual(windows[-1]['end_exclusive'], '2026-01-02T10:01:00.000000+00:00')
        for left, right in zip(windows, windows[1:]):
            self.assertEqual(left['end_exclusive'], right['start_inclusive'])
        for item in plan['partitions']:
            self.assertLessEqual(item['prompt_bytes'], size // 2)
            partition = (otrf.parse_utc(item['window_utc']['start_inclusive'], 'w'),
                         otrf.parse_utc(item['window_utc']['end_exclusive'], 'w'))
            report = decode_json(self.draft(result, partition)[1]['evaluator/import-report.json'])
            self.assertEqual(report['public_bytes']['prompt_projection'], item['prompt_bytes'])
        tiny = bots.plan(result, self.fields, max_public_bytes=2000, salt=SALT)
        self.assertEqual(tiny['partitions'], [])
        self.assertTrue(tiny['unpublishable'])


class CuratedImportTest(BotsTestBase):
    def setUp(self):
        super().setUp()
        self.data = self.v3_data()
        self.result = self.scan(self.data, exclude_sourcetypes=['WinRegistry'])
        _, self.outputs = self.draft(self.result)
        self.template = decode_json(self.outputs['evaluator/curation-template.json'])
        self.lines = {(c['hostname'], c['event_type']): c['line'] for c in self.template['candidate_events']}

    def curation(self, **changes):
        value = json.loads(CURATION.read_text('utf-8'))
        value.update({key: self.template['curation'][key] for key in
                      ('dataset_sha256', 'metadata_sha256', 'partition_window', 'assessment_windows')})
        value['steps'][0]['support_sets'] = [[{'line': self.lines[('WKST-01', 'windows-security:4720')]}],
                                             [{'record_id': '9003', 'channel': 'WinEventLog:Security',
                                               'hostname': 'wkst-01'}]]
        value['steps'][0]['window_utc'] = self.template['curation']['partition_window']
        value['controls'] = [dict(c, window_utc=self.template['curation']['partition_window'])
                             for c in value['controls']]
        value.update(changes)
        path = self.root / ('curation-%d.json' % len(list(self.root.glob('curation-*.json'))))
        path.write_text(json.dumps(value), encoding='utf-8')
        return path

    def test_curated_case_validates_with_line_and_record_locators(self):
        case_id, outputs = bots.build_case(self.result, self.fields, SALT, self.result['window'],
                                           curation_path=self.curation())
        bundle = decode_json(outputs['public/evidence.json'])
        truth = validate_truth(decode_json(outputs['evaluator/truth.json']), bundle)
        self.assertEqual(len(truth['steps'][0]['support_sets']), 2)
        scenario = decode_json(outputs['scenario.json'])
        self.assertEqual((scenario['split'], scenario['provenance'], scenario['family_id']),
                         ('development', 'public_replay', 'bots-v3-sample'))
        self.assertTrue(any('incident group sample' in text
                            for text in scenario['sophistication']['emulation_limitations']))
        self.assertEqual(bundle, decode_json(self.outputs['public/evidence.json']))
        case_dir = otrf.write_outputs(self.root / 'cases', case_id, outputs)
        self.assertTrue((case_dir / 'scenario.json').is_file())

    def test_curations_bind_to_window_profile_and_records(self):
        cases = ((self.curation(partition_window={'start_inclusive': START,
                                                  'end_exclusive': '2026-01-02T10:00:30+00:00'}),
                  'partition_mismatch'),
                 (self.curation(collection_profile='live-collector'), 'partition_mismatch'),
                 (self.curation(dataset_sha256='0' * 64), 'curation_dataset_mismatch'))
        for path, code in cases:
            with self.subTest(code=code):
                with self.assertRaises(BenchmarkError) as caught:
                    bots.build_case(self.result, self.fields, SALT, self.result['window'], curation_path=path)
                self.assertEqual(caught.exception.code, code)
        other = self.scan(self.data, exclude_sourcetypes=['WinRegistry', 'cisco:asa'])
        with self.assertRaises(BenchmarkError) as caught:
            bots.build_case(other, self.fields, SALT, other['window'], curation_path=self.curation())
        self.assertEqual(caught.exception.code, 'curation_dataset_mismatch')
        missing = self.curation()
        value = json.loads(missing.read_text('utf-8'))
        value['steps'][0]['support_sets'] = [[{'line': bots.LINE_STRIDE + 1}]]  # the out-of-window row
        missing.write_text(json.dumps(value), encoding='utf-8')
        with self.assertRaises(BenchmarkError) as caught:
            bots.build_case(self.result, self.fields, SALT, self.result['window'], curation_path=missing)
        self.assertEqual(caught.exception.code, 'support_record_not_imported')

    def test_agent_consensus_merge_of_two_proposals_imports(self):
        drafts = []
        for label, outcome in (('a', 'succeeded'), ('b', 'unknown')):
            value = json.loads(self.curation().read_text('utf-8'))
            value.update(status=otrf.PROPOSAL_STATUS, curated_by=None, curated_utc=None, note=label)
            value['steps'][0]['execution_outcome'] = outcome
            path = self.root / ('draft-%s.json' % label)
            path.write_text(json.dumps(value), encoding='utf-8')
            drafts.append(path)
        side = self.root / 'side'
        side.mkdir()
        (side / 'locators.json').write_bytes(self.outputs['evaluator/locators.json'])
        (side / 'template.json').write_bytes(self.outputs['evaluator/curation-template.json'])
        merged = self.root / 'consensus.json'
        benchmark_consensus.merge(drafts[0], drafts[1], side / 'locators.json', side / 'template.json', merged)
        _, outputs = bots.build_case(self.result, self.fields, SALT, self.result['window'], curation_path=merged)
        self.assertEqual(decode_json(outputs['evaluator/truth.json'])['attestation'], 'agent_consensus')


class CliTest(BotsTestBase):
    def run_cli(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = bots.main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_plan_and_case_commands(self):
        data = self.v3_data()
        common = ['--version', 'v3', '--data', str(data), '--incident', 'sample', '--window-start', START,
                  '--window-end', END, '--exclude-sourcetype', 'WinRegistry']
        code, out, err = self.run_cli(['plan'] + common + ['--output', str(self.root / 'plan.json')])
        self.assertEqual((code, err), (0, ''))
        self.assertEqual(json.loads(out)['partitions'], 1)
        code, out, err = self.run_cli(['case'] + common + ['--draft', '--output', str(self.root / 'draft')])
        self.assertEqual((code, err), (0, ''))
        summary = json.loads(out)
        self.assertEqual(summary['status'], otrf.DRAFT_MARKER)
        self.assertTrue((Path(summary['case_directory']) / 'evaluator' / 'salt.json').is_file())
        for root in (HERE, FRAMEWORK):
            code, _, err = self.run_cli(['case'] + common + ['--draft', '--output', str(root / 'bots-case-output')])
            self.assertEqual((code, err.strip()), (2, 'error: output_in_source_tree: output'))
            self.assertFalse((root / 'bots-case-output').exists())
        code, _, err = self.run_cli(['case'] + common[:-2] + ['--incident', 'Bad Slug', '--draft', '--output',
                                                              str(self.root / 'x')])
        self.assertEqual((code, err.strip()), (2, 'error: invalid_identifier: incident'))

    def test_v1_json_records_and_csv_records_bound_single_readline_allocation(self):
        import gzip
        from unittest import mock
        gz_path = self.root / 'oversized.json.gz'
        with gzip.open(gz_path, 'wb') as handle:
            handle.write(b'{' + (b'a' * (bots.MAX_RECORD_BYTES + 128)))
        item = {'path': gz_path, 'name': 'oversized.json.gz'}
        win = (otrf.parse_utc(START, 'start'), otrf.parse_utc(END, 'end'))
        with self.assertRaises(bots.BenchmarkError) as ctx:
            list(bots._json_records(item, 1, win, {}))
        self.assertEqual(ctx.exception.code, 'line_too_large')

        quoted_csv_path = self.root / 'quoted.csv.gz'
        raw_quotes = '"' * 3500
        encoded_quotes = '"' + ('""' * 3500) + '"'
        in_win_epoch = str(int(win[0].timestamp()))
        with gzip.open(quoted_csv_path, 'wb') as handle:
            handle.write(b','.join(s.encode('ascii') for s in bots.CSV_HEADER) + b'\n')
            handle.write((in_win_epoch + ',src,host::h,sourcetype::c,' + encoded_quotes + ',m\n').encode('utf-8'))
        quoted_item = {'path': quoted_csv_path, 'name': 'quoted.csv.gz', 'earliest': 0, 'latest': 2000000000}
        with mock.patch.object(bots, 'MAX_RECORD_BYTES', 4096), \
                mock.patch.object(bots, 'MAX_CSV_PHYSICAL_LINE_BYTES', len(bots.CSV_HEADER) * 4 * 4096 + 512):
            rows = list(bots._csv_records(quoted_item, 1, win))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][4], raw_quotes)

        csv_gz_path = self.root / 'oversized.csv.gz'
        with gzip.open(csv_gz_path, 'wb') as handle:
            handle.write(b','.join(s.encode('ascii') for s in bots.CSV_HEADER) + b'\n')
            handle.write(b'1534785720,h,s,c,' + (b'x' * (65536 + 128)))
        csv_item = {'path': csv_gz_path, 'name': 'oversized.csv.gz', 'earliest': 0, 'latest': 2000000000}
        with mock.patch.object(bots, 'MAX_CSV_PHYSICAL_LINE_BYTES', 65536):
            with self.assertRaises(bots.BenchmarkError) as csv_ctx:
                list(bots._csv_records(csv_item, 1, win))
        self.assertEqual(csv_ctx.exception.code, 'invalid_csv')


if __name__ == '__main__':
    unittest.main()

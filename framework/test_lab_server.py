"""Guest lab API and ingest contracts with fake backends; no VM, Elasticsearch or Arkime.

Run from framework/: py -3 -B -m unittest -v test_lab_server
"""
import http.client
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode

GUEST = Path(__file__).resolve().parent / 'hunt_lab' / 'guest'


def load(name):
    spec = importlib.util.spec_from_file_location('guest_' + name, GUEST / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    sys.dont_write_bytecode = True
    spec.loader.exec_module(module)
    return module


lab_server = load('lab_server')
ARKIME_GET = lab_server.arkime_get
ingest = load('ingest')

CASE = {'case_id': 'lab-med-001', 'question': 'Synthetic question.',
        'time_range_utc': {'start_inclusive': '2026-03-02T00:00:00Z', 'end_exclusive': '2026-03-05T00:00:00Z'}}
START_S = 1772409600
END_S = 1772668800

# Fields of real winlogbeat/Sysmon/PowerShell logs (DEDALE); Sysmon spells TargetProcessGUID.
REAL_WINDOWS_KEYWORD_FIELDS = (
    'event.module', 'process.args', 'process.title', 'process.hash.md5', 'process.hash.sha1',
    'file.directory', 'file.extension', 'winlog.record_id', 'winlog.event_id', 'winlog.computer_name',
    'winlog.provider_name', 'winlog.task', 'winlog.process.pid', 'winlog.event_data.User',
    'winlog.event_data.IntegrityLevel', 'winlog.event_data.LogonId', 'winlog.event_data.ParentUser',
    'winlog.event_data.OriginalFileName', 'winlog.event_data.Description', 'winlog.event_data.Company',
    'winlog.event_data.Product', 'winlog.event_data.Signed', 'winlog.event_data.Signature',
    'winlog.event_data.SignatureStatus', 'winlog.event_data.RuleName', 'winlog.event_data.CreationUtcTime',
    'winlog.event_data.EventType', 'winlog.event_data.SourceUser', 'winlog.event_data.TargetUser',
    'winlog.event_data.TargetProcessGUID', 'winlog.event_data.TargetProcessGuid',
)


def es_hits(sources, total=None):
    hits = [{'_source': source, 'sort': [1772409600000 + n, source.get('event', {}).get('id', '')]}
            for n, source in enumerate(sources)]
    return {'hits': {'total': {'value': len(sources) if total is None else total, 'relation': 'eq'}, 'hits': hits}}


class FakeElastic:
    def __init__(self):
        self.calls = []
        self.response = None
        self.error = None

    def __call__(self, base, index, body, ignore_unavailable=False):
        self.calls.append(dict(index=index, body=body, ignore_unavailable=ignore_unavailable))
        if self.error:
            raise self.error
        if self.response is not None:
            return self.response
        return es_hits([])


class ServerCase(unittest.TestCase):
    scope = 'tag'
    case = CASE

    def setUp(self):
        self.elastic = FakeElastic()
        self.arkime = mock.Mock(return_value=b'{"recordsFiltered": 0, "data": []}')
        patches = [mock.patch.object(lab_server, 'es_search', self.elastic),
                   mock.patch.object(lab_server, 'arkime_get', self.arkime)]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)
        self.server = lab_server.make_server('127.0.0.1', 0, self.case, 'http://elastic.invalid:9200', self.scope)
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)

    def request(self, path, method='GET', profile=None):
        connection = http.client.HTTPConnection('127.0.0.1', self.server.server_address[1], timeout=10)
        try:
            connection.request(method, path, headers={'X-Hermes-Profile': profile} if profile else {})
            response = connection.getresponse()
            body = response.read()
        finally:
            connection.close()
        return response.status, (json.loads(body) if body else None)

    def page(self, path):
        connection = http.client.HTTPConnection('127.0.0.1', self.server.server_address[1], timeout=10)
        try:
            connection.request('GET', path)
            response = connection.getresponse()
            return response.status, response.getheader('Content-Type'), response.read().decode()
        finally:
            connection.close()


class EndpointTests(ServerCase):
    def test_search_is_case_scoped_flat_and_pages_with_search_after(self):
        self.elastic.response = es_hits([
            {'@timestamp': '2026-03-02T01:00:00.000Z', 'event': {'id': 'evt-000001'}, 'host': {'name': 'ws-01'},
             'user': {'name': 'alice'}, 'process': {'name': 'cmd.exe'}},
            {'@timestamp': '2026-03-02T01:00:01.000Z', 'event': {'id': 'evt-000002'}, 'host': {'name': 'ws-02'},
             'user': {'name': 'bob'}},
        ], total=9)
        status, value = self.request('/es/search?q=host.name:ws-01&size=2&sort=desc&fields=user.name')
        self.assertEqual(status, 200)
        body = self.elastic.calls[0]['body']
        self.assertEqual(self.elastic.calls[0]['index'], 'hunt-lab-events')
        filters = body['query']['bool']['filter']
        self.assertIn({'term': {'event.dataset': 'lab-med-001'}}, filters)
        self.assertFalse(filters[1]['query_string']['allow_leading_wildcard'])
        self.assertEqual(body['size'], 2)
        self.assertEqual(body['sort'][0], {'@timestamp': 'desc'})
        self.assertNotIn('script', json.dumps(body))
        self.assertEqual((value['case_id'], value['total'], value['returned']), ('lab-med-001', 9, 2))
        self.assertEqual(value['hits'][0], {'event.id': 'evt-000001', '@timestamp': '2026-03-02T01:00:00.000Z',
                                            'host.name': 'ws-01', 'user.name': 'alice'})
        self.assertIsNotNone(value['next_after'])
        self.request('/es/search?size=2&after=' + value['next_after'])
        self.assertEqual(self.elastic.calls[1]['body']['search_after'], [1772409600001, 'evt-000002'])
        self.assertNotIn('query_string', json.dumps(self.elastic.calls[1]['body']))

    def test_invalid_requests_are_rejected_before_any_backend_call_with_a_specific_code(self):
        long_values = ','.join('v%d' % n for n in range(51))
        field, wildcard = 'field_not_allowed', 'leading_wildcard_not_supported'
        for path, code in (
            ('/es/search?index=other', 'invalid_query'), ('/es/search?q=a&q=b', 'invalid_query'),
            ('/es/search?size=0', 'invalid_query'), ('/es/search?size=201', 'invalid_query'),
            ('/es/search?sort=up', 'invalid_query'), ('/es/search?fields=secret.field', field),
            ('/es/search?fields=ip.src', field), ('/es/search?fields=event.id,event.id', 'invalid_field_list'),
            ('/es/search?q=*evil', wildcard), ('/es/search?q=host.name:*evil', wildcard),
            ('/es/search?q=' + 'a' * 501, 'invalid_query'), ('/es/search?after=not-a-token!', 'invalid_query'),
            ('/es/aggs?field=message', field), ('/es/aggs?field=host.name&interval=1m', 'invalid_query'),
            ('/es/aggs?field=@timestamp&interval=1s', 'invalid_query'),
            ('/es/aggs?field=@timestamp&interval=1m', 'invalid_query'), ('/es/aggs?field=host.name&size=101', 'invalid_query'),
            ('/es/detect?q=a', 'invalid_query'), ('/es/detect?q=a&name=' + 'n' * 81, 'invalid_query'),
            ('/intel?values=' + long_values, 'invalid_query'), ('/intel?values=' + 'x' * 201, 'invalid_query'),
            ('/intel?values=a,,b', 'invalid_query'),
            ('/arkime/sessions?expression=ip.src==1.2.3.4)%20||%20(ip.src==5.6.7.8', 'invalid_query'),
            ('/arkime/sessions?expression=host.dns=="unterminated', 'invalid_query'),
            ('/arkime/sessions?length=201', 'invalid_query'), ('/arkime/sessions?start=10001', 'invalid_query'),
            ('/arkime/sessions?fields=rootId', field), ('/arkime/unique?field=file', field),
            ('/arkime/unique?field=ip.src&counts=2', 'invalid_query'),
            ('/activity?after=-1', 'invalid_query'), ('/activity?limit=101', 'invalid_query'),
        ):
            with self.subTest(path=path):
                self.assertEqual(self.request(path), (400, {'error': code}))
        self.assertEqual(self.elastic.calls, [])
        self.arkime.assert_not_called()

    def test_every_generated_event_field_is_returnable(self):
        # lsass access is only visible in winlog.event_data.TargetImage/GrantedAccess.
        self.elastic.response = es_hits([])
        status, _ = self.request('/es/search?fields=winlog.event_data.TargetImage,winlog.event_data.GrantedAccess,user.target.name')
        self.assertEqual(status, 200)
        self.assertIn('winlog.event_data.TargetImage', self.elastic.calls[0]['body']['_source'])
        self.elastic.response = {'hits': {'total': {'value': 0}}, 'aggregations': {'values': {'buckets': []}}}
        self.assertEqual(self.request('/es/aggs?field=winlog.event_data.TargetUserName')[0], 200)
        self.assertEqual(self.elastic.calls[-1]['body']['aggs']['values']['terms']['field'], 'winlog.event_data.TargetUserName')

    def test_real_windows_log_fields_are_returnable_and_keyword_ones_aggregatable(self):
        self.elastic.response = es_hits([{
            '@timestamp': '2026-03-02T01:00:00.000Z', 'event': {'id': 'evt-000001', 'module': 'powershell'},
            'process': {'args': ['powershell.exe', '-NoP'], 'hash': {'md5': 'a' * 32}},
            'winlog': {'record_id': 12813, 'event_data': {'TargetProcessGUID': '{416dd0c5-0000}'}},
            'powershell': {'file': {'script_block_text': 'Get-Process | Out-Null'}}}])
        fields = REAL_WINDOWS_KEYWORD_FIELDS + ('powershell.file.script_block_text',)
        status, value = self.request('/es/search?fields=' + ','.join(fields))
        self.assertEqual(status, 200)
        self.assertLessEqual(set(fields), set(self.elastic.calls[0]['body']['_source']))
        hit = value['hits'][0]
        self.assertEqual((hit['event.module'], hit['process.args'], hit['process.hash.md5'], hit['winlog.record_id']),
                         ('powershell', ['powershell.exe', '-NoP'], 'a' * 32, 12813))
        self.assertEqual(hit['winlog.event_data.TargetProcessGUID'], '{416dd0c5-0000}')
        self.assertEqual(hit['powershell.file.script_block_text'], 'Get-Process | Out-Null')
        self.elastic.response = {'hits': {'total': {'value': 0}}, 'aggregations': {'values': {'buckets': []}}}
        for field in REAL_WINDOWS_KEYWORD_FIELDS:
            with self.subTest(field=field):
                self.assertEqual(self.request('/es/aggs?field=' + field)[0], 200)
                self.assertEqual(self.elastic.calls[-1]['body']['aggs']['values']['terms']['field'], field)
        self.assertEqual(self.request('/es/aggs?field=powershell.file.script_block_text'),
                         (400, {'error': 'field_not_allowed'}))
        self.elastic.response = es_hits([])
        self.assertEqual(self.request('/events')[0], 200)
        self.assertIn('powershell', self.elastic.calls[-1]['body']['_source'])

    def test_non_get_methods_are_405_and_unknown_routes_404(self):
        for method in ('POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'):
            with self.subTest(method=method):
                self.assertEqual(self.request('/es/search', method)[0], 405)
        for path in ('/arkime/api/sessions', '/arkime/delete', '/api/sessions', '/es/_delete_by_query',
                     '/arkime/sessions/pcap', '/es', '/packets/pcap', '/pcap'):
            with self.subTest(path=path):
                self.assertEqual(self.request(path), (404, {'error': 'not_found'}))
        self.assertEqual(self.elastic.calls, [])
        self.arkime.assert_not_called()

    def test_arkime_sessions_force_case_tag_and_window_and_trim_fields(self):
        self.arkime.return_value = json.dumps({'recordsFiltered': 7, 'data': [
            {'id': 'secret-session-id', 'rootId': 'x', 'node': 'hermes-lab', 'firstPacket': 1772409600123,
             'lastPacket': 1772409601000, 'source': {'ip': '10.0.0.5', 'port': 50000},
             'destination': {'ip': '203.0.113.9', 'port': 443}, 'http': {'host': ['sni.example']}},
        ]}).encode()
        status, value = self.request('/arkime/sessions?expression=ip.dst%20==%20203.0.113.9&length=5'
                                     '&fields=firstPacket,destination.ip,http.host')
        self.assertEqual(status, 200)
        route, params = self.arkime.call_args.args
        self.assertEqual(route, '/api/sessions')
        self.assertEqual(params['expression'], 'tags == "case:lab-med-001" && (ip.dst == 203.0.113.9)')
        self.assertEqual((params['startTime'], params['stopTime'], params['length']), (START_S, END_S, 5))
        self.assertEqual(value, {'case_id': 'lab-med-001', 'recordsFiltered': 7, 'returned': 1, 'sessions': [
            {'firstPacket': '2026-03-02T00:00:00.123Z', 'destination.ip': '203.0.113.9', 'http.host': ['sni.example']}]})

    def test_arkime_unique_uses_expression_field_and_parses_counts(self):
        self.arkime.return_value = b'10.0.0.1, 5\n10.0.0.2, 9\n'
        status, value = self.request('/arkime/unique?field=ip.src')
        self.assertEqual(status, 200)
        route, params = self.arkime.call_args.args
        self.assertEqual((route, params['exp'], params['counts']), ('/api/unique', 'ip.src', '1'))
        self.assertEqual(params['expression'], 'tags == "case:lab-med-001"')
        self.assertEqual(value['values'], [{'value': '10.0.0.2', 'count': 9}, {'value': '10.0.0.1', 'count': 5}])

    def test_arkime_client_refuses_routes_outside_the_read_allowlist(self):
        with mock.patch.object(lab_server._ARKIME_OPENER, 'open') as opener:
            for route in ('/api/delete', '/api/sessions/addtags', '/api/hunt', '/api/user', '/api/session/x/pcap'):
                with self.subTest(route=route), self.assertRaises(RuntimeError):
                    ARKIME_GET(route, {})
        opener.assert_not_called()
        response = mock.MagicMock()
        response.__enter__.return_value.read.return_value = b'{}'
        with mock.patch.object(lab_server._ARKIME_OPENER, 'open', return_value=response) as opener:
            ARKIME_GET('/api/sessions', {'length': 1})
        request = opener.call_args.args[0]
        self.assertEqual((request.get_method(), request.full_url),
                         ('GET', 'http://127.0.0.1:8005/api/sessions?length=1'))

    def test_intel_is_case_filtered_and_reports_unmatched_values(self):
        self.elastic.response = es_hits([{'id': 'ioc-00001', 'indicator': {'type': 'domain', 'value': 'evil.example'},
                                          'threat': {'feed': {'name': 'feed-a'}}, 'confidence': 'high',
                                          'description': 'Invented.', 'first_seen': '2026-02-01T00:00:00Z'}])
        status, value = self.request('/intel?values=Evil.Example,198.51.100.7')
        self.assertEqual(status, 200)
        call = self.elastic.calls[0]
        self.assertEqual(call['index'], 'hunt-lab-intel')
        self.assertTrue(call['ignore_unavailable'])
        self.assertIn({'term': {'case_id': 'lab-med-001'}}, call['body']['query']['bool']['filter'])
        self.assertEqual(value['matches'][0]['threat.feed.name'], 'feed-a')
        self.assertIn('id', call['body']['_source'])
        self.assertEqual(value['matches'][0]['id'], 'ioc-00001')
        self.assertEqual(value['unmatched'], ['198.51.100.7'])

    def test_aggregations_terms_and_bounded_histogram(self):
        sample = {'hits': {'hits': [{'_source': {'event.id': 'evt-000007'}}]}}
        self.elastic.response = {'hits': {'total': {'value': 12, 'relation': 'eq'}, 'hits': []},
                                 'aggregations': {'values': {'sum_other_doc_count': 2, 'buckets': [
                                     {'key': 'ws-01', 'doc_count': 10, 'sample': sample}]}}}
        status, value = self.request('/es/aggs?field=host.name&size=5&q=event.action:logon')
        self.assertEqual(status, 200)
        self.assertEqual(self.elastic.calls[0]['body']['aggs']['values'], {
            'terms': {'field': 'host.name', 'size': 5},
            'aggs': {'sample': {'top_hits': {'size': 1, '_source': ['event.id'],
                                             'sort': [{'@timestamp': 'asc'}, {'event.id': 'asc'}]}}}})
        self.assertEqual((value['total'], value['buckets'], value['other']),
                         (12, [{'key': 'ws-01', 'count': 10, 'sample_event_id': 'evt-000007'}], 2))
        self.elastic.response = {'hits': {'total': {'value': 3, 'relation': 'eq'}, 'hits': []},
                                 'aggregations': {'values': {'buckets': [
                                     {'key': 1, 'key_as_string': '2026-03-02T00:00:00Z', 'doc_count': 3}]}}}
        status, value = self.request('/es/aggs?field=@timestamp&interval=1h')
        body = self.elastic.calls[1]['body']
        histogram = body['aggs']['values']['date_histogram']
        # Elasticsearch drops every bucket ending after hard_bounds.max: the window's last hour would vanish.
        self.assertNotIn('hard_bounds', histogram)
        self.assertEqual(body['query']['bool']['filter'][-1], {'range': {'@timestamp': {
            'gte': START_S * 1000, 'lt': END_S * 1000, 'format': 'epoch_millis'}}})
        self.assertIn('sample', self.elastic.calls[1]['body']['aggs']['values']['aggs'])
        self.assertEqual(value['buckets'], [{'key': '2026-03-02T00:00:00Z', 'count': 3, 'sample_event_id': None}])

    def test_a_bucket_sample_without_its_source_cites_nothing(self):
        sample = {'hits': {'hits': [{'_id': 'doc-1'}]}}
        self.elastic.response = {'hits': {'total': {'value': 4, 'relation': 'eq'}, 'hits': []},
                                 'aggregations': {'values': {'buckets': [
                                     {'key': 'ws-01', 'doc_count': 4, 'sample': sample}]}}}
        status, value = self.request('/es/aggs?field=host.name')
        self.assertEqual(status, 200, value)
        self.assertEqual(value['buckets'], [{'key': 'ws-01', 'count': 4, 'sample_event_id': None}])

    def test_detect_reports_hosts_bounds_and_sample(self):
        response = es_hits([{'@timestamp': '2026-03-02T01:00:00Z', 'event': {'id': 'evt-000003'},
                             'host': {'name': 'ws-01'}}], total=4)
        response['aggregations'] = {'hosts': {'buckets': [{'key': 'ws-01', 'doc_count': 4}]},
                                    'first': {'value': 1.0, 'value_as_string': '2026-03-02T01:00:00.000Z'},
                                    'last': {'value': 2.0, 'value_as_string': '2026-03-02T02:00:00.000Z'}}
        self.elastic.response = response
        status, value = self.request('/es/detect?q=process.name:rundll32.exe&name=rundll32%20use')
        self.assertEqual(status, 200)
        self.assertEqual((value['name'], value['total'], value['hosts']), ('rundll32 use', 4, [{'key': 'ws-01', 'count': 4}]))
        self.assertEqual((value['first'], value['last']), ('2026-03-02T01:00:00.000Z', '2026-03-02T02:00:00.000Z'))
        self.assertEqual(value['sample'][0]['event.id'], 'evt-000003')

    def test_backend_rejection_is_400_and_outage_is_503(self):
        self.elastic.error = lab_server.BackendQueryError('invalid_query')
        self.assertEqual(self.request('/es/search?q=a:(b'), (400, {'error': 'invalid_query'}))
        self.elastic.error = URLError('down')
        self.assertEqual(self.request('/es/search'), (503, {'error': 'backend_not_ready', 'partial_results': False}))
        self.arkime.side_effect = lab_server.BackendQueryError('invalid_expression')
        self.assertEqual(self.request('/arkime/sessions?expression=bogus'), (400, {'error': 'invalid_expression'}))

    def test_console_field_query_matches_es_search(self):
        self.elastic.response = es_hits([
            {'@timestamp': '2026-03-02T01:00:00.000Z', 'event': {'id': 'evt-000101'}, 'host': {'name': 'web-01'},
             'process': {'name': 'cmd.exe', 'parent': {'name': 'w3wp.exe'}}},
            {'@timestamp': '2026-03-02T01:00:05.000Z', 'event': {'id': 'evt-000102'}, 'host': {'name': 'web-01'},
             'process': {'name': 'powershell.exe', 'parent': {'name': 'w3wp.exe'}}},
        ], total=8)
        _, api = self.request('/es/search?q=process.parent.name:w3wp.exe')
        status, kind, body = self.page('/view?q=process.parent.name%3Aw3wp.exe')
        self.assertEqual((status, kind), (200, 'text/html; charset=utf-8'))
        search, console = (call['body'] for call in self.elastic.calls)
        self.assertEqual(console['query'], search['query'])
        self.assertEqual(console['sort'], search['sort'])
        self.assertEqual(console['query']['bool']['filter'][1]['query_string']['query'], 'process.parent.name:w3wp.exe')
        self.assertEqual((api['total'], api['returned']), (8, 2))
        self.assertIn('<strong>2 of 8 events</strong>', body)
        for hit in api['hits']:
            self.assertIn(hit['event.id'], body)
        self.assertIn('<label for="q">Search</label><input id="q" name="q"', body)
        self.assertIn('value="process.parent.name:w3wp.exe"', body)

    def test_console_shows_only_the_fixed_code_for_a_refused_query(self):
        status, kind, body = self.page('/view?q=process.parent.name:*w3wp')
        self.assertEqual((status, kind), (400, 'text/html; charset=utf-8'))
        self.assertIn('Query refused: leading_wildcard_not_supported', body)
        self.assertEqual(self.elastic.calls, [])
        status, _, body = self.page('/view?q=' + 'a' * 301)
        self.assertEqual(status, 400)
        self.assertIn('Query refused: invalid_query', body)
        self.assertNotIn('too long', body)
        self.elastic.error = lab_server.BackendQueryError('invalid_query')
        status, _, body = self.page('/?q=a:(b')
        self.assertEqual(status, 400)
        self.assertIn('Query refused: invalid_query', body)
        self.assertIn('<label for="q">Search</label>', body)

    def test_console_escapes_records_and_echoed_search(self):
        self.elastic.response = es_hits([{'@timestamp': '<i>t</i>', 'event': {'id': 'evt-000001'},
                                          'message': '<script>alert(1)</script>'}])
        status, _, body = self.page('/view?q=%22%3E%3Cb%3Ex&host=%3Cimg%3E')
        self.assertEqual(status, 200)
        for raw in ('<script>', '<i>t</i>', '"><b>x', '<img>'):
            self.assertNotIn(raw, body)
        for escaped in ('&lt;script&gt;alert(1)&lt;/script&gt;', '&lt;i&gt;t&lt;/i&gt;',
                        'value="&quot;&gt;&lt;b&gt;x"', 'value="&lt;img&gt;"'):
            self.assertIn(escaped, body)

    def test_events_route_keeps_plain_word_search_with_the_es_search_builder(self):
        self.elastic.response = es_hits([{'event': {'id': 'evt-000001'}, 'dns': {'question': {'name': 'a.example'}}}])
        status, value = self.request('/events?q=dns%20example&host=ws-01')
        self.assertEqual(status, 200)
        self.assertEqual(value['records'], [{'event': {'id': 'evt-000001'}, 'dns': {'question': {'name': 'a.example'}}}])
        filters = self.elastic.calls[0]['body']['query']['bool']['filter']
        clause = filters[1]['query_string']
        self.assertEqual((clause['query'], clause['default_operator']), ('dns example', 'AND'))
        # The fields the earlier simple_query_string searched are all still searched by unqualified words.
        self.assertLessEqual({'message', 'host.name', 'process.name', 'dns.question.name', 'event.id'}, set(clause['fields']))
        self.assertIn({'term': {'host.name': 'ws-01'}}, filters)
        self.assertEqual(self.request('/events?q=*evil'), (400, {'error': 'leading_wildcard_not_supported'}))

    def test_identity_web_and_file_fields_show_on_the_console_and_in_events(self):
        record = {'@timestamp': '2026-03-02T01:00:00.000Z', 'event': {'id': 'evt-000201'},
                  'user': {'name': 'r.ashgrove', 'domain': 'CORP'}, 'file': {'path': 'C:\\Users\\Public\\a.exe'},
                  'url': {'full': 'https://x.example/s', 'domain': 'x.example', 'path': '/s'},
                  'http': {'request': {'method': 'GET'}, 'response': {'status_code': 200}},
                  'tls': {'server_name': 'x.example'}}
        self.elastic.response = es_hits([record])
        _, value = self.request('/events?q=user.name:r.ashgrove')
        self.assertEqual(value['records'], [record])
        _, _, body = self.page('/view?q=user.name:r.ashgrove')
        for shown in ('&quot;name&quot;: &quot;r.ashgrove&quot;', '&quot;server_name&quot;: &quot;x.example&quot;',
                      '&quot;status_code&quot;: 200', 'https://x.example/s'):
            self.assertIn(shown, body)
        for call in self.elastic.calls:
            self.assertLessEqual({'user', 'group', 'file', 'service', 'url', 'http', 'tls', 'user_agent', 'observer'},
                                 set(call['body']['_source']))

    def test_activity_records_tool_calls_with_display_profile(self):
        self.request('/es/search?q=alice', profile='framework-researcher')
        self.request('/es/search?size=0', profile='framework-reviewer')
        self.arkime.return_value = b'203.0.113.9, 2\n'
        self.request('/arkime/unique?field=ip.dst', profile='made-up-profile')
        self.request('/es/search?q=board', profile='hunt-board')
        self.request('/case')
        status, value = self.request('/activity?after=0')
        self.assertEqual(status, 200)
        entries = value['entries']
        self.assertEqual([(e['profile'], e['tool'], e['endpoint'], e['error']) for e in entries], [
            ('framework-researcher', 'elastic_search', '/es/search', None),
            ('framework-reviewer', 'elastic_search', '/es/search', 'invalid_query'),
            ('unknown', 'arkime_unique', '/arkime/unique', None),
        ])
        self.assertEqual((entries[0]['params'], entries[0]['result_count'], entries[0]['total']), ({'q': 'alice'}, 0, 0))
        self.assertEqual((value['next'], value['more']), (3, False))
        self.assertEqual(self.request('/activity?after=3')[1]['entries'], [])
        page = self.request('/activity?after=0&limit=2')[1]
        self.assertEqual(([e['seq'] for e in page['entries']], page['next'], page['more']), ([1, 2], 2, True))
        # A cursor from before an API restart (beyond the current sequence) restarts at the beginning.
        self.assertEqual(len(self.request('/activity?after=500')[1]['entries']), 3)

    def test_activity_ring_keeps_only_the_newest_entries(self):
        ring = lab_server.Activity(limit=3)
        for n in range(5):
            ring.record(tool='elastic_search', n=n)
        cursor, entries, more = ring.since(0, 100)
        self.assertEqual(([e['seq'] for e in entries], cursor, more), ([3, 4, 5], 5, False))

    def test_health_reports_case_counts_with_tagged_network_scope(self):
        self.elastic.response = es_hits([{}], total=5)
        with mock.patch.object(lab_server, 'answers', return_value=True), \
             mock.patch.object(lab_server, 'kibana_case_ready', return_value=True):
            status, value = self.request('/health')
        self.assertEqual(status, 200)
        self.assertEqual({key: value[key] for key in ('case_id', 'event_count', 'network_session_count', 'intel_count')},
                         {'case_id': 'lab-med-001', 'event_count': 5, 'network_session_count': 5, 'intel_count': 5})
        network = next(call for call in self.elastic.calls if call['index'] == 'arkime_sessions3-*')
        self.assertIn({'term': {'tags': 'case:lab-med-001'}}, network['body']['query']['bool']['filter'])

    def test_health_is_not_ready_until_kibanas_data_view_names_the_loaded_case(self):
        self.elastic.response = es_hits([{}], total=5)
        view = mock.MagicMock()
        view.__enter__.return_value = io.BytesIO(json.dumps({'data_view': {'name': 'dns-lab-001 events'}}).encode())
        with mock.patch.object(lab_server, 'answers', return_value=True), \
             mock.patch.object(lab_server, 'urlopen', return_value=view):
            status, value = self.request('/health')
        self.assertEqual((status, value['ready'], value['kibana_ready']), (503, False, False))
        view.__enter__.return_value = io.BytesIO(json.dumps({'data_view': {'name': 'lab-med-001 events'}}).encode())
        with mock.patch.object(lab_server, 'answers', return_value=True), \
             mock.patch.object(lab_server, 'urlopen', return_value=view):
            status, value = self.request('/health')
        self.assertEqual((status, value['ready'], value['kibana_ready']), (200, True, True))


class InstanceIdTests(unittest.TestCase):
    def test_the_cloud_init_instance_id_is_read_and_junk_is_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'instance-id'
            path.write_text('hermes-framework-network-analyst-case-lab-med-001-6873a567-load2\n', encoding='ascii')
            self.assertEqual(lab_server.instance_id(path), 'hermes-framework-network-analyst-case-lab-med-001-6873a567-load2')
            path.write_text('bad id; rm -rf /', encoding='ascii')
            self.assertIsNone(lab_server.instance_id(path))
            self.assertIsNone(lab_server.instance_id(Path(temp) / 'missing'))


class KibanaGuestTests(unittest.TestCase):
    def test_discover_parses_lucene_with_the_same_query_string_options_as_elastic_search(self):
        config = (GUEST / 'kibana.yml').read_text(encoding='utf-8')
        options = json.loads(next(line for line in config.splitlines()
                                  if line.strip().startswith('query:queryString:options:')).split(': ', 1)[1].strip("'"))
        self.assertEqual(options, {key: value for key, value in lab_server.lucene('x')['query_string'].items() if key != 'query'})
        self.assertIn('search:queryLanguage: lucene', config)

    def test_setup_points_the_case_alias_data_view_and_window_at_the_loaded_case(self):
        setup = load('kibana_setup')
        calls = []

        def call(base, path, method='GET', data=None, kibana=False):
            calls.append((base, method, path, data))
            if path.startswith('/api/data_views/data_view/'):
                return {'data_view': {'title': setup.CASE_ALIAS, 'timeFieldName': '@timestamp'}}
            return {'count': 7} if path.endswith('/_count') else {}

        self.assertEqual(setup.configure('http://es', 'http://kb', CASE, call=call), 7)
        alias = calls[0][3]['actions'][0]['add']
        self.assertEqual((alias['alias'], alias['filter']), ('hunt-lab-case-events', {'term': {'event.dataset': 'lab-med-001'}}))
        view = next(data for _, _, path, data in calls if path == '/api/data_views/data_view')['data_view']
        self.assertEqual((view['id'], view['title'], view['timeFieldName'], view['name']),
                         ('hunt-lab-case-events', 'hunt-lab-case-events', '@timestamp', 'lab-med-001 events'))
        settings = next(data for _, _, path, data in calls if path == '/api/kibana/settings')['changes']
        self.assertEqual(json.loads(settings['timepicker:timeDefaults']),
                         {'from': '2026-03-02T00:00:00.000Z', 'to': '2026-03-04T23:59:59.999Z'})
        self.assertEqual(lab_server.KIBANA_DATA_VIEW, setup.DATA_VIEW_ID)


class LegacyWindowScopeTests(ServerCase):
    scope = 'window'

    def test_untagged_legacy_case_uses_only_the_case_window(self):
        self.request('/arkime/unique?field=host.dns')
        params = self.arkime.call_args.args[1]
        self.assertNotIn('expression', params)
        self.assertEqual((params['startTime'], params['stopTime']), (START_S, END_S))
        self.request('/network')
        self.assertNotIn('tags', json.dumps(self.elastic.calls[-1]['body']))


class NoCaptureTests(ServerCase):
    case = dict(CASE, network_capture='none')

    def test_health_is_ready_from_events_alone_and_reports_no_capture(self):
        self.elastic.response = es_hits([{}], total=5)
        with mock.patch.object(lab_server, 'answers', return_value=False), \
             mock.patch.object(lab_server, 'kibana_case_ready', return_value=True):
            status, value = self.request('/health')
        self.assertEqual((status, value['ready']), (200, True))
        self.assertEqual((value['network_capture'], value['network_session_count'], value['event_count']),
                         ('none', 0, 5))
        self.assertFalse(any(call['index'] == 'arkime_sessions3-*' for call in self.elastic.calls))
        self.elastic.response = es_hits([], total=0)
        with mock.patch.object(lab_server, 'answers', return_value=True), \
             mock.patch.object(lab_server, 'kibana_case_ready', return_value=True):
            self.assertEqual(self.request('/health')[0], 503)

    def test_network_queries_are_refused_with_a_fixed_code_before_any_backend_call(self):
        for path in ('/arkime/sessions', '/arkime/sessions?expression=ip.dst%3D%3D10.0.0.1',
                     '/arkime/unique?field=ip.src', '/network', '/network?q=dns&limit=5',
                     '/packets', '/packets?filter=dns&fields=dns.qry.name'):
            with self.subTest(path=path):
                self.assertEqual(self.request(path, profile='framework-network-analyst'),
                                 (400, {'error': 'no_network_capture'}))
        self.arkime.assert_not_called()
        self.assertEqual(self.elastic.calls, [])
        _, activity = self.request('/activity')
        self.assertEqual({entry['error'] for entry in activity['entries']}, {'no_network_capture'})
        self.assertEqual(self.request('/events')[0], 200)
        self.assertEqual(self.request('/case')[1]['network_capture'], 'none')

    def test_case_with_a_capture_still_queries_its_sessions(self):
        self.server.case = CASE
        self.assertEqual(self.request('/arkime/sessions')[0], 200)
        self.assertEqual(self.request('/network')[0], 200)
        self.arkime.assert_called_once()


# Packet fields that must never be returned or tested, whatever the request (ADR 0003).
DENIED_PACKET_FIELDS = ('http.cookie', 'http.authorization', 'data', 'http.file_data', 'ntlmssp.ntlmv2_response',
                        'http.proxy_authorization', 'http.set_cookie', 'tcp.payload', 'kerberos.cipher',
                        'http.request.full_uri', 'http.request.line', 'frame.protocols')


def frame(number, fields=None):
    return {'frame.number': str(number), 'frame.time_epoch': '%d.000000000' % (START_S + number), **(fields or {})}


class DataOriginConsoleTests(ServerCase):
    case = dict(CASE, network_capture='none', data_origin='public-dataset', question='What happened in the window?')

    def test_console_states_the_case_origin(self):
        self.elastic.response = es_hits([])
        status, _, body = self.page('/')
        self.assertEqual(status, 200)
        self.assertIn('Public research dataset (real lab telemetry, no customer data). Read-only.', body)
        self.assertNotIn('ynthetic', body)
        self.assertEqual(self.request('/case')[1]['data_origin'], 'public-dataset')
        self.server.case = dict(self.case, data_origin='work-export')
        body = self.page('/')[2]
        self.assertIn("<p>Work log export (real telemetry from the operator's environment; unclassified work data). "
                      'Read-only. No live capture.</p>', body)
        self.assertNotIn('ynthetic', body)
        self.assertEqual(self.request('/case')[1]['data_origin'], 'work-export')
        self.server.case = CASE
        self.assertIn('<p>Synthetic data only. Read-only. No live capture.</p>', self.page('/')[2])

    def test_console_wording_is_the_hunt_wording(self):
        from hermes_temporal.contracts import DATA_ORIGINS
        self.assertEqual(lab_server.DATA_ORIGINS, DATA_ORIGINS)


class CitingSource:
    """A source whose records carry no event.id: it scopes, orders, pages and cites by itself, as a host service would."""

    def __init__(self):
        self.calls = []

    def search(self, index, body, ignore_unavailable=False):
        self.calls.append(dict(index=index, body=body))
        hits = [{'_id': f'doc-{n}', '_source': {'@timestamp': f'2026-03-02T00:00:0{n}Z', 'host': {'name': 'ws-01'}},
                 'sort': [n, n + 100]} for n in (1, 2)]
        sample = {'hits': {'hits': hits[:1]}}
        return {'hits': {'total': {'value': 2, 'relation': 'eq'}, 'hits': hits},
                'aggregations': {'values': {'buckets': [{'key': 'ws-01', 'doc_count': 2, 'sample': sample}]},
                                 'hosts': {'buckets': [{'key': 'ws-01', 'doc_count': 2}]},
                                 'first': {'value': None}, 'last': {'value': None}}}

    def event_query(self, case, q):
        return {'bool': {'filter': [{'range': {'@timestamp': {'gte': case['time_range_utc']['start_inclusive']}}},
                                    {'citing': q}]}}

    def sort(self, order):
        return [{'@timestamp': order}, {'_shard_doc': order}]

    def document(self, hit):
        return dict(hit['_source'], event={'id': 'evt-9' + hit['_id'][-1]})

    def encode_after(self, sort):
        return f'p{sort[1]}'

    def decode_after(self, token):
        return [0, int(token[1:])]


class EventSourceTests(ServerCase):
    def setUp(self):
        super().setUp()
        self.source = CitingSource()
        self.server = lab_server.make_server('127.0.0.1', 0, CASE, self.source)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)

    def sent(self, path, q):
        status, value = self.request(path)
        self.assertEqual(status, 200, value)
        body = self.source.calls[-1]['body']
        self.assertEqual((self.source.calls[-1]['index'], body['query']), ('hunt-lab-events', self.source.event_query(CASE, q)))
        return value, body

    def test_another_source_scopes_orders_pages_and_cites_every_event_read(self):
        value, body = self.sent('/es/search?q=s&size=2&sort=desc&after=p7', 's')
        self.assertEqual((body['sort'], body['search_after']), ([{'@timestamp': 'desc'}, {'_shard_doc': 'desc'}], [0, 7]))
        self.assertEqual(([hit['event.id'] for hit in value['hits']], value['next_after']), (['evt-91', 'evt-92'], 'p102'))
        value, body = self.sent('/events?q=e', 'e')
        self.assertEqual(body['sort'], [{'@timestamp': 'asc'}, {'_shard_doc': 'asc'}])
        self.assertEqual([record['event']['id'] for record in value['records']], ['evt-91', 'evt-92'])
        value, body = self.sent('/es/aggs?q=a&field=host.name', 'a')
        self.assertEqual(body['aggs']['values']['aggs']['sample']['top_hits']['sort'], [{'@timestamp': 'asc'}, {'_shard_doc': 'asc'}])
        self.assertEqual(value['buckets'], [{'key': 'ws-01', 'count': 2, 'sample_event_id': 'evt-91'}])
        value, body = self.sent('/es/detect?name=x&q=d', 'd')
        self.assertEqual(body['sort'], [{'@timestamp': 'asc'}, {'_shard_doc': 'asc'}])
        self.assertEqual([row['event.id'] for row in value['sample']], ['evt-91', 'evt-92'])
        self.assertEqual(self.elastic.calls, [])

    def test_network_sessions_and_health_read_through_the_source_without_event_citations(self):
        sessions = self.request('/network')[1]['records']
        self.assertEqual((self.source.calls[-1]['index'], [session.get('event') for session in sessions]),
                         ('arkime_sessions3-*', [None, None]))
        with mock.patch.object(lab_server, 'answers', return_value=True), \
             mock.patch.object(lab_server, 'kibana_case_ready', return_value=True):
            status, value = self.request('/health')
        self.assertEqual((status, value['event_count'], value['network_session_count'], value['intel_count']), (200, 2, 2, 2))
        self.assertEqual(sorted({call['index'] for call in self.source.calls}),
                         ['arkime_sessions3-*', 'hunt-lab-events', 'hunt-lab-intel'])
        self.assertEqual(self.elastic.calls, [])

    def test_intel_reads_through_the_source(self):
        status, value = self.request('/intel?values=x')
        self.assertEqual(status, 200, value)
        self.assertEqual(self.source.calls[-1]['index'], 'hunt-lab-intel')
        self.assertEqual(self.elastic.calls, [])

class FakeTsharkPipe:
    def __init__(self, data, process):
        self.data, self.process = io.BytesIO(data), process

    def readline(self, limit=-1):
        if self.process.hang:
            self.process.killed.wait(5)
            return b''
        line = self.data.readline(limit)
        self.process.finished = not line
        return line

    def close(self):
        pass


class FakeTsharkProcess:
    def __init__(self, data, code, hang):
        self.code, self.hang, self.finished = code, hang, False
        self.killed = threading.Event()
        self.stdout = FakeTsharkPipe(data, self)

    def kill(self):
        # Like Popen.kill on an exited process: nothing to signal once the output ended.
        if not self.finished:
            self.killed.set()

    def wait(self):
        return -9 if self.killed.is_set() else self.code


class FakeTshark:
    """Stands in for the subprocess module: answers tshark -G fields and -r queries, records every call."""
    PIPE, DEVNULL = subprocess.PIPE, subprocess.DEVNULL

    def __init__(self):
        # As Ubuntu 22.04's tshark 3.6: no JA4, and column fields are not listed by -G fields.
        self.known = [name for name in lab_server.PACKET_FIELDS if name not in ('_ws.col.Protocol', 'tls.handshake.ja4')]
        self.rows, self.code, self.fields_code, self.hang, self.error = [], 0, 0, False, None
        self.calls, self.processes = [], []

    def Popen(self, args, **kwargs):
        self.calls.append((args, kwargs))
        if self.error:
            raise self.error
        if args[1:] == ['-G', 'fields']:
            data = b''.join(b'F\tLabel\t%s\tFT_STRING\tproto\t\t0x0\t\n' % name.encode() for name in self.known)
            process = FakeTsharkProcess(data + b'P\tDomain Name System\tdns\n', self.fields_code, False)
        else:
            columns = [args[index + 1] for index, arg in enumerate(args) if arg == '-e']
            data = b''.join(('\t'.join(row.get(column, '') for column in columns) + '\n').encode() for row in self.rows)
            process = FakeTsharkProcess(data, self.code, self.hang)
        self.processes.append(process)
        return process

    def queries(self):
        return [args for args, _kwargs in self.calls if args[1:] != ['-G', 'fields']]


class PacketFieldsTests(ServerCase):
    def setUp(self):
        super().setUp()
        self.tshark = FakeTshark()
        patch = mock.patch.object(lab_server, 'subprocess', self.tshark)
        patch.start()
        self.addCleanup(patch.stop)
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.capture = Path(temp.name) / 'evidence' / 'traffic.pcap'
        self.capture.parent.mkdir()
        self.capture.write_bytes(b'')
        self.server.capture = self.capture

    def packets(self, profile='framework-network-analyst', **params):
        return self.request('/packets' + ('?' + urlencode(params) if params else ''), profile=profile)

    def test_tshark_reads_only_the_case_capture_from_an_argument_list(self):
        self.tshark.rows = [frame(7, {'ip.src': '10.0.0.5', 'dns.qry.name': 'a.test'})]
        status, value = self.packets(fields='ip.src,dns.qry.name', length='5',
                                     filter='dns.qry.name == "a.test" and ip.src == 10.0.0.1')
        self.assertEqual(status, 200, value)
        self.assertEqual(value, {'case_id': 'lab-med-001', 'fields': ['frame.number', 'frame.time_epoch', 'ip.src', 'dns.qry.name'],
                                 'start': 0, 'returned': 1, 'more': False, 'truncated': False,
                                 'rows': [{'frame.number': 7, 'frame.time_epoch': '%d.000000000' % (START_S + 7),
                                           'ip.src': '10.0.0.5', 'dns.qry.name': 'a.test'}]})
        self.assertEqual([args for args, _ in self.tshark.calls][0], ['/usr/bin/tshark', '-G', 'fields'])
        [args] = self.tshark.queries()
        kwargs = self.tshark.calls[1][1]
        self.assertIsInstance(args, list)
        self.assertEqual(args[0], '/usr/bin/tshark')
        self.assertEqual(args[args.index('-r') + 1], str(self.capture))
        self.assertNotIn('-i', args)
        self.assertNotIn('-w', args)
        self.assertNotIn('shell', kwargs)
        self.assertEqual((kwargs['stdin'], kwargs['stderr']), (subprocess.DEVNULL, subprocess.DEVNULL))
        self.assertEqual(args[args.index('-Y') + 1], 'dns.qry.name == "a.test" and ip.src == 10.0.0.1')
        # The whole capture is read: a packet-count cutoff would turn a late match into a complete-looking negative.
        self.assertNotIn('-c', args)
        self.assertEqual([args[i + 1] for i, arg in enumerate(args) if arg == '-e'],
                         ['frame.number', 'frame.time_epoch', 'ip.src', 'dns.qry.name'])
        # The supported-field list is asked for once and then cached.
        self.assertEqual(self.packets()[0], 200)
        self.assertEqual(sum(args[1:] == ['-G', 'fields'] for args, _ in self.tshark.calls), 1)
        default = self.tshark.queries()[-1]
        self.assertEqual([default[i + 1] for i, arg in enumerate(default) if arg == '-e'],
                         list(lab_server.PACKET_ALWAYS_FIELDS + lab_server.PACKET_DEFAULT_FIELDS))
        self.assertNotIn('-Y', default)

    def test_server_main_points_packet_fields_at_the_capture_next_to_case_json(self):
        case = self.capture.parent / 'case.json'
        with mock.patch.object(lab_server, 'make_server') as make, \
                mock.patch.object(lab_server, 'load_case', return_value=CASE), \
                mock.patch.object(lab_server, 'instance_id', return_value=None), \
                mock.patch.object(sys, 'argv', ['lab_server.py', '--case', str(case)]):
            lab_server.main()
        self.assertEqual(make.call_args.kwargs['capture'], case.resolve().parent / 'traffic.pcap')

    def test_fields_outside_the_allowlist_are_refused_before_tshark_runs(self):
        for field in DENIED_PACKET_FIELDS:
            with self.subTest(field=field):
                self.assertNotIn(field, lab_server.PACKET_FIELDS)
                self.assertEqual(self.packets(fields='ip.src,' + field), (400, {'error': 'field_not_allowed'}))
        self.assertEqual(self.packets(fields='ip.src,ip.src'), (400, {'error': 'invalid_field_list'}))
        for params in ({'length': '0'}, {'length': '201'}, {'start': '100001'}, {'expression': 'x'}):
            with self.subTest(params=params):
                self.assertEqual(self.packets(**params), (400, {'error': 'invalid_query'}))
        self.assertEqual(self.tshark.calls, [])

    def test_filters_admit_only_the_closed_grammar(self):
        for raw, normalized in (
                ('dns.qry.name == "a.test" and ip.src == 10.0.0.1', 'dns.qry.name == "a.test" and ip.src == 10.0.0.1'),
                ('(tcp.dstport==445 || udp.dstport eq 53) && !ip.dst==10.0.0.0/8',
                 '( tcp.dstport == 445 || udp.dstport eq 53 ) && ! ip.dst == 10.0.0.0/8'),
                ('ipv6.src == fe80::1 or smb2 or not kerberos', 'ipv6.src == fe80::1 or smb2 or not kerberos'),
                ('tls.handshake.type == 1 and tls.record.version >= 0x0301',
                 'tls.handshake.type == 1 and tls.record.version >= 0x0301'),
                ('http.request.method != "GET" and frame.len gt 1500', 'http.request.method != "GET" and frame.len gt 1500')):
            with self.subTest(filter=raw):
                self.assertEqual(lab_server.packet_filter(raw)[0], normalized)
        self.assertEqual(lab_server.packet_filter('dns.qry.name == "a" or ip.dst')[1], ('dns.qry.name', 'ip.dst'))
        self.assertEqual(lab_server.packet_filter('  '), (None, ()))
        refused = list(DENIED_PACKET_FIELDS) + [field + ' == "x"' for field in DENIED_PACKET_FIELDS] + [
            'dns.qry.name contains "evil"', 'dns.qry.name matches "e.*"', 'dns.qry.name ~ "e"',
            'http.cookie contains "session"', 'ip.src[0:2] == 0a:00', 'http.cookie[0] == 41', 'ip.src == ${ip.dst}',
            'dns.qry.name == "a\\\\b"', 'dns.qry.name == "a\\"b"', "dns.qry.name == 'a'", 'ip.src == @x',
            'http.request.uri == "/a?token=x"', 'http.request.uri > "/a?t"', '_ws.col.Protocol == "DNS"',
            'http == "GET"', 'http > 47:45:54', 'len(dns.qry.name) > 3', 'upper(dns.qry.name) == "A"',
            'ip.src in {10.0.0.1}', 'ip.src == 10.0.0.1 xor ip.dst == 10.0.0.2', '"a.test" == dns.qry.name',
            'dns.qry.name ==', 'ip.src == 10.0.0.1)', '((ip.src)', 'ip.src == 10.0.0.1 and', 'dns.qry.name == "a" "b"',
            'ip.src == 1.2.3.4.5', 'tcp.dstport & 0x10', 'ip.src == 10.0.0.1\n', 'dns.qry.name == "\u00e9"',
            'not ' * 25 + 'ip', 'a' * 301, 'frame', 'eth.src == 00:11:22:33:44:55']
        for raw in refused:
            with self.subTest(filter=raw):
                with self.assertRaises(lab_server.BackendQueryError) as caught:
                    lab_server.packet_filter(raw)
                self.assertEqual(caught.exception.args, ('invalid_filter',))
        for field in ('http.cookie', 'http.authorization', 'data', 'http.file_data', 'ntlmssp.ntlmv2_response'):
            with self.subTest(field=field):
                self.assertEqual(self.packets(filter=field + ' == "x"'), (400, {'error': 'invalid_filter'}))
        self.assertEqual(self.packets(filter='dns.qry.name contains "x"'), (400, {'error': 'invalid_filter'}))
        self.assertEqual(self.tshark.calls, [])

    def test_uri_query_strings_fragments_and_userinfo_never_leave_the_guest(self):
        uris = ['/login?user=a&password=s3cret', '/a,/b?x=1,2', 'http://u:pw@proxy.example/x?y=1#z', '/plain',
                '/doc#token=abc', 'http://proxy.example/a@b?c=d']
        self.tshark.rows = [frame(n, {'http.request.uri': uri}) for n, uri in enumerate(uris, 1)]
        status, value = self.packets(fields='http.request.uri,http.host')
        self.assertEqual(status, 200, value)
        self.assertEqual([row['http.request.uri'] for row in value['rows']],
                         ['/login?[redacted]', '/a,/b?[redacted]', 'http://proxy.example/x?[redacted]', '/plain',
                          '/doc?[redacted]', 'http://proxy.example/a@b?[redacted]'])
        body = json.dumps(value)
        for secret in ('s3cret', 'password', 'u:pw', 'token', 'x=1', 'c=d'):
            self.assertNotIn(secret, body)
        self.assertNotIn('http.host', value['rows'][0])

    def test_allowlisted_fields_the_installed_tshark_lacks_are_field_unavailable(self):
        self.assertEqual(self.packets(fields='tls.handshake.ja4'), (400, {'error': 'field_unavailable'}))
        self.assertEqual(self.packets(filter='tls.handshake.ja4 == "t13d"'), (400, {'error': 'field_unavailable'}))
        self.assertEqual(self.tshark.queries(), [])
        # Column fields are resolved by tshark itself even though -G fields does not list them.
        self.assertEqual(self.packets(fields='_ws.col.Protocol,tls.handshake.ja3')[0], 200)

    def test_paging_reads_one_row_past_the_page_and_stops_tshark(self):
        self.tshark.rows = [frame(n) for n in range(1, 11)]
        status, value = self.packets(start='3', length='4', fields='frame.len')
        self.assertEqual(status, 200, value)
        self.assertEqual(([row['frame.number'] for row in value['rows']], value['returned'], value['more'],
                          value['truncated']), ([4, 5, 6, 7], 4, True, False))
        self.assertTrue(self.tshark.processes[-1].killed.is_set())
        status, value = self.packets(start='8', length='5', fields='frame.len')
        # A scan that reaches the end of the capture is complete: neither more nor truncated.
        self.assertEqual(([row['frame.number'] for row in value['rows']], value['more'], value['truncated']),
                         ([9, 10], False, False))
        self.assertFalse(self.tshark.processes[-1].killed.is_set())

    def test_output_cap_stops_tshark_and_reports_truncation(self):
        self.tshark.rows = [frame(n, {'dns.qry.name': 'host-%03d.example' % n}) for n in range(1, 101)]
        with mock.patch.object(lab_server, 'MAX_BACKEND_BYTES', 200):
            status, value = self.packets(fields='dns.qry.name', length='200')
        self.assertEqual(status, 200, value)
        self.assertTrue(value['truncated'])
        self.assertFalse(value['more'])
        self.assertLess(value['returned'], 10)
        self.assertLessEqual(sum(len('\t'.join(frame(row['frame.number'], {'dns.qry.name': row['dns.qry.name']}).values()))
                                 + 1 for row in value['rows']), 200)
        self.assertTrue(self.tshark.processes[-1].killed.is_set())

    def test_timeouts_and_failures_map_to_fixed_codes_without_tshark_text(self):
        self.tshark.hang = True
        with mock.patch.object(lab_server, 'TSHARK_TIMEOUT', 0.2):
            self.assertEqual(self.packets(), (503, {'error': 'packet_tool_timeout', 'partial_results': False}))
        self.assertTrue(self.tshark.processes[-1].killed.is_set())
        self.tshark.hang, self.tshark.code = False, 2
        self.assertEqual(self.packets(), (503, {'error': 'packet_tool_error', 'partial_results': False}))
        self.tshark.code = 4
        self.assertEqual(self.packets(filter='dns'), (400, {'error': 'invalid_filter'}))
        self.assertEqual(self.packets(), (503, {'error': 'packet_tool_error', 'partial_results': False}))
        # A row whose value holds an unescaped tab no longer matches the requested columns.
        self.tshark.code, self.tshark.rows = 0, [{'frame.number': '1\textra'}]
        self.assertEqual(self.packets(fields='frame.len'), (503, {'error': 'packet_tool_error', 'partial_results': False}))
        self.assertTrue(all(kwargs['stderr'] is subprocess.DEVNULL for _args, kwargs in self.tshark.calls))

    def test_a_missing_tshark_or_capture_is_packet_tool_error_and_the_field_list_is_retried(self):
        self.tshark.error = FileNotFoundError('/usr/bin/tshark')
        self.assertEqual(self.packets(), (503, {'error': 'packet_tool_error', 'partial_results': False}))
        self.tshark.error, self.tshark.fields_code = None, 1
        self.assertEqual(self.packets(), (503, {'error': 'packet_tool_error', 'partial_results': False}))
        self.tshark.fields_code = 0
        self.assertEqual(self.packets()[0], 200)
        self.assertEqual(sum(args[1:] == ['-G', 'fields'] for args, _ in self.tshark.calls), 3)
        self.capture.unlink()
        calls = len(self.tshark.calls)
        self.assertEqual(self.packets(), (503, {'error': 'packet_tool_error', 'partial_results': False}))
        self.assertEqual(len(self.tshark.calls), calls)

    def test_activity_log_records_packet_calls(self):
        self.tshark.rows = [frame(1, {'dns.qry.name': 'a.test'})]
        self.packets(filter='dns.qry.name == "a.test"', fields='dns.qry.name')
        self.packets(filter='http.cookie', profile='framework-researcher')
        self.packets(profile='hunt-board')
        entries = self.request('/activity?after=0')[1]['entries']
        self.assertEqual([(e['profile'], e['tool'], e['endpoint'], e['result_count'], e['total'], e['error'])
                          for e in entries], [
            ('framework-network-analyst', 'packet_fields', '/packets', 1, None, None),
            ('framework-researcher', 'packet_fields', '/packets', None, None, 'invalid_filter')])
        self.assertEqual(entries[0]['params'], {'filter': 'dns.qry.name == "a.test"', 'fields': 'dns.qry.name'})


class LoadCaseTests(unittest.TestCase):
    def load(self, **fields):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'case.json'
            path.write_text(json.dumps(dict(CASE, **fields)), encoding='utf-8')
            return lab_server.load_case(path)

    def test_network_capture_is_absent_or_none_and_nothing_else(self):
        self.assertNotIn('network_capture', self.load())
        self.assertEqual(self.load(network_capture='none')['network_capture'], 'none')
        for value in ('pcap', 'None', '', None, False):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.load(network_capture=value)

    def test_data_origin_is_absent_or_a_known_origin_and_nothing_else(self):
        self.assertNotIn('data_origin', self.load())
        for value in ('public-dataset', 'work-export'):
            self.assertEqual(self.load(data_origin=value)['data_origin'], value)
        for value in ('synthetic', 'customer', '', None, False, ['work-export']):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.load(data_origin=value)


class FakeIndexer:
    def __init__(self, current=None):
        self.calls = []
        self.current = current
        self.bulk_errors = None

    def __call__(self, base, path, method='GET', data=None, content_type='application/json'):
        self.calls.append((method, path, data))
        if method == 'GET' and path == '/hunt-lab-events':
            if self.current is None:
                raise HTTPError(path, 404, 'not found', {}, io.BytesIO(b'{}'))
            return self.current
        if path == '/_bulk':
            if self.bulk_errors:
                return {'errors': True, 'items': [{'index': {'error': {'type': self.bulk_errors}}}]}
            return {'errors': False, 'items': []}
        return {'deleted': 0}

    def bulks(self):
        return [[json.loads(line) for line in data.decode().splitlines()]
                for method, path, data in self.calls if path == '/_bulk']


class IngestTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='hermes-ingest-test-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def write(self, name, rows):
        path = self.root / name
        path.write_text(''.join(json.dumps(row) + '\n' for row in rows), encoding='utf-8')
        return path

    def events(self, count, dataset='lab-med-001'):
        return self.write('events.jsonl', ({'@timestamp': '2026-03-02T00:00:00Z',
                                            'event': {'id': 'evt-%06d' % n, 'dataset': dataset}}
                                           for n in range(count)))

    def test_events_are_bulk_loaded_in_bounded_chunks_with_case_ids(self):
        fake = FakeIndexer()
        with mock.patch.object(ingest, 'request', fake):
            result = ingest.ingest('http://es', self.events(12001), 'lab-med-001')
        bulks = fake.bulks()
        self.assertEqual([len(bulk) // 2 for bulk in bulks], [5000, 5000, 2001])
        self.assertEqual(bulks[0][0], {'index': {'_index': 'hunt-lab-events', '_id': 'lab-med-001:evt-000000'}})
        self.assertEqual(result['indexed_events'], 12001)
        created = next(data for method, path, data in fake.calls if method == 'PUT')
        properties = created['mappings']['properties']
        self.assertEqual(properties['host']['properties']['name']['type'], 'keyword')
        self.assertEqual(properties['source']['properties']['ip']['type'], 'ip')
        self.assertEqual(properties['@timestamp']['type'], 'date')
        self.assertIn(('POST', '/_aliases', {'actions': [{'add': {'index': 'hunt-lab-events-v2', 'alias': 'hunt-lab-events'}}]}),
                      fake.calls)
        # Stale documents of an earlier load of the same case are removed only after every chunk.
        method, path, data = fake.calls[-1]
        self.assertIn('_delete_by_query', path)
        self.assertEqual(data['query']['bool']['filter'], [{'term': {'event.dataset': 'lab-med-001'}}])

    def test_legacy_concrete_index_is_migrated_behind_the_alias(self):
        fake = FakeIndexer(current={'hunt-lab-events': {'mappings': {}}})
        with mock.patch.object(ingest, 'request', fake):
            self.assertEqual(ingest.ensure_event_index('http://es'), 'migrated')
        paths = [path for _, path, _ in fake.calls]
        self.assertTrue(any(path.startswith('/_reindex') for path in paths))
        actions = next(data for _, path, data in fake.calls if path == '/_aliases')['actions']
        self.assertIn({'remove_index': {'index': 'hunt-lab-events'}}, actions)
        fake = FakeIndexer(current={'hunt-lab-events-v2': {}})
        with mock.patch.object(ingest, 'request', fake):
            self.assertEqual(ingest.ensure_event_index('http://es'), 'ready')
        self.assertEqual(len(fake.calls), 1)

    def test_script_block_text_is_full_text_on_new_and_existing_stores(self):
        script = {'type': 'text'}
        fake = FakeIndexer()
        with mock.patch.object(ingest, 'request', fake):
            ingest.ingest('http://es', self.events(2), 'lab-med-001')
        mappings = next(data for method, path, data in fake.calls if method == 'PUT')['mappings']
        self.assertEqual(mappings['properties']['powershell']['properties']['file']['properties']['script_block_text'], script)
        # Every other string stays an aggregatable keyword.
        self.assertEqual(mappings['dynamic_templates'][0]['strings_as_keywords']['mapping'],
                         {'type': 'keyword', 'ignore_above': 1024})
        self.assertFalse(any(path.endswith('/_mapping') for _, path, _ in fake.calls))
        fake = FakeIndexer(current={'hunt-lab-events-v2': {}})
        with mock.patch.object(ingest, 'request', fake):
            ingest.ingest('http://es', self.events(2), 'lab-med-001')
        update = next(data for method, path, data in fake.calls
                      if (method, path) == ('PUT', '/hunt-lab-events-v2/_mapping'))
        self.assertEqual(update['properties']['powershell']['properties']['file']['properties']['script_block_text'], script)
        self.assertEqual(update['_meta'], mappings['_meta'])

    def test_events_from_another_case_or_rejected_documents_fail(self):
        fake = FakeIndexer()
        with mock.patch.object(ingest, 'request', fake), self.assertRaises(ValueError):
            ingest.ingest('http://es', self.events(3, dataset='dns-lab-001'), 'lab-med-001')
        self.assertEqual(fake.bulks(), [])
        fake = FakeIndexer()
        fake.bulk_errors = 'mapper_parsing_exception'
        with mock.patch.object(ingest, 'request', fake), self.assertRaises(ingest.Rejected) as raised:
            ingest.ingest('http://es', self.events(3), 'lab-med-001')
        self.assertEqual((raised.exception.count, raised.exception.types), (1, ['mapper_parsing_exception']))
        self.assertFalse(any('_delete_by_query' in path for _, path, _ in fake.calls))

    def test_intel_documents_are_case_scoped_and_idempotent(self):
        path = self.write('intel.jsonl', [
            {'id': 'ioc-00001', 'indicator': {'type': 'domain', 'value': 'evil.example'},
             'threat': {'feed': {'name': 'feed-a'}}, 'confidence': 'high'},
            {'indicator': {'type': 'ip', 'value': '198.51.100.7'}, 'threat': {'feed': {'name': 'feed-b'}}},
        ])
        identities = []
        for _ in range(2):
            fake = FakeIndexer()
            with mock.patch.object(ingest, 'request', fake):
                ingest.ingest_intel('http://es', path, 'lab-med-001')
            bulk = fake.bulks()[0]
            identities.append([line['index']['_id'] for line in bulk[0::2]])
            self.assertEqual({line['case_id'] for line in bulk[1::2]}, {'lab-med-001'})
            self.assertEqual({line['index']['_index'] for line in bulk[0::2]}, {'hunt-lab-intel'})
        self.assertEqual(identities[0], identities[1])
        self.assertEqual(identities[0][0], 'lab-med-001:ioc-00001')
        self.assertTrue(identities[0][1].startswith('lab-med-001:'))
        mismatched = self.write('other.jsonl', [{'case_id': 'dns-lab-001', 'indicator': {'type': 'ip', 'value': '1.2.3.4'}}])
        with mock.patch.object(ingest, 'request', FakeIndexer()), self.assertRaises(ValueError):
            ingest.ingest_intel('http://es', mismatched, 'lab-med-001')


if __name__ == '__main__':
    unittest.main()

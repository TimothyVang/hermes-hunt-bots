"""Guest lab API and ingest contracts with fake backends; no VM, Elasticsearch or Arkime.

Run from framework/: py -3 -B -m unittest -v test_lab_server
"""
import http.client
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest import mock
from urllib.error import HTTPError, URLError

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

    def setUp(self):
        self.elastic = FakeElastic()
        self.arkime = mock.Mock(return_value=b'{"recordsFiltered": 0, "data": []}')
        patches = [mock.patch.object(lab_server, 'es_search', self.elastic),
                   mock.patch.object(lab_server, 'arkime_get', self.arkime)]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)
        self.server = lab_server.make_server('127.0.0.1', 0, CASE, 'http://elastic.invalid:9200', self.scope)
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

    def test_non_get_methods_are_405_and_unknown_routes_404(self):
        for method in ('POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'):
            with self.subTest(method=method):
                self.assertEqual(self.request('/es/search', method)[0], 405)
        for path in ('/arkime/api/sessions', '/arkime/delete', '/api/sessions', '/es/_delete_by_query',
                     '/arkime/sessions/pcap', '/es'):
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
        self.elastic.response = es_hits([{'indicator': {'type': 'domain', 'value': 'evil.example'},
                                          'threat': {'feed': {'name': 'feed-a'}}, 'confidence': 'high',
                                          'description': 'Invented.', 'first_seen': '2026-02-01T00:00:00Z'}])
        status, value = self.request('/intel?values=Evil.Example,198.51.100.7')
        self.assertEqual(status, 200)
        call = self.elastic.calls[0]
        self.assertEqual(call['index'], 'hunt-lab-intel')
        self.assertTrue(call['ignore_unavailable'])
        self.assertIn({'term': {'case_id': 'lab-med-001'}}, call['body']['query']['bool']['filter'])
        self.assertEqual(value['matches'][0]['threat.feed.name'], 'feed-a')
        self.assertEqual(value['unmatched'], ['198.51.100.7'])

    def test_aggregations_terms_and_bounded_histogram(self):
        self.elastic.response = {'hits': {'total': {'value': 12, 'relation': 'eq'}, 'hits': []},
                                 'aggregations': {'values': {'sum_other_doc_count': 2, 'buckets': [
                                     {'key': 'ws-01', 'doc_count': 10}]}}}
        status, value = self.request('/es/aggs?field=host.name&size=5&q=event.action:logon')
        self.assertEqual(status, 200)
        self.assertEqual(self.elastic.calls[0]['body']['aggs']['values'], {'terms': {'field': 'host.name', 'size': 5}})
        self.assertEqual((value['total'], value['buckets'], value['other']), (12, [{'key': 'ws-01', 'count': 10}], 2))
        self.elastic.response = {'hits': {'total': {'value': 3, 'relation': 'eq'}, 'hits': []},
                                 'aggregations': {'values': {'buckets': [
                                     {'key': 1, 'key_as_string': '2026-03-02T00:00:00Z', 'doc_count': 3}]}}}
        status, value = self.request('/es/aggs?field=@timestamp&interval=1h')
        histogram = self.elastic.calls[1]['body']['aggs']['values']['date_histogram']
        self.assertEqual(histogram['hard_bounds'], {'min': START_S * 1000, 'max': END_S * 1000 - 1})
        self.assertEqual(value['buckets'], [{'key': '2026-03-02T00:00:00Z', 'count': 3}])

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
        viewer = mock.MagicMock()
        viewer.__enter__.return_value.status = 200
        with mock.patch.object(lab_server, 'urlopen', return_value=viewer):
            status, value = self.request('/health')
        self.assertEqual(status, 200)
        self.assertEqual({key: value[key] for key in ('case_id', 'event_count', 'network_session_count', 'intel_count')},
                         {'case_id': 'lab-med-001', 'event_count': 5, 'network_session_count': 5, 'intel_count': 5})
        network = next(call for call in self.elastic.calls if call['index'] == 'arkime_sessions3-*')
        self.assertIn({'term': {'tags': 'case:lab-med-001'}}, network['body']['query']['bool']['filter'])


class LegacyWindowScopeTests(ServerCase):
    scope = 'window'

    def test_untagged_legacy_case_uses_only_the_case_window(self):
        self.request('/arkime/unique?field=host.dns')
        params = self.arkime.call_args.args[1]
        self.assertNotIn('expression', params)
        self.assertEqual((params['startTime'], params['stopTime']), (START_S, END_S))
        self.request('/network')
        self.assertNotIn('tags', json.dumps(self.elastic.calls[-1]['body']))


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

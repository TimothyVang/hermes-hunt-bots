"""Behavior tests for the connected lab service (ADR 0005) against a fake Elasticsearch transport.

Run from framework/: python -m unittest -v hunt_lab.test_connected
The fake plays a secured cluster's point-in-time search on synthetic records; no network connection to any
cluster is opened. The bot side is the real hunt_lab.query_adapter talking to the service on 127.0.0.1.
"""

import base64
import contextlib
import io
import json
from pathlib import Path
import re
import tempfile
import threading
import time
import unittest
from urllib import parse, request

from hunt_lab import connected, query_adapter


KEY = 'cmVhZC1vbmx5LWtleS1pZDpyZWFkLW9ubHkta2V5LXZhbHVl'
URL = 'https://elastic.example.test:9243'
INDEX = 'logs-windows*'
START, END = '2026-11-01T10:00:00Z', '2026-11-01T11:00:00Z'
CASE_ID = 'work-conn-001'
DATA_STREAM = 'logs-windows.sysmon_operational-default'


class FakeElastic:
    """A secured cluster: version, privileges, field caps and point-in-time search over five documents."""

    def __init__(self):
        self.version = '8.15.3'
        self.index_grants = {}
        self.cluster_grants = {}
        self.omit_cluster = False
        self.docs = [{'_index': '.ds-logs-windows-000001', '_id': f'AbC{n}x_-', 'sort': [1761991200000000000 + n, n],
                      '_source': {'@timestamp': f'2026-11-01T10:0{n}:00Z', 'host': {'name': 'ws-01'},
                                  'event': {'id': 'source-id', 'code': '1'}, 'process': {'name': 'cmd.exe'}}}
                     for n in range(5)]
        self.requests = []
        self.pits = {'pit-0'}
        self.opened = 0
        self.fail_search = None
        self.rotate_pit = False
        self.lose_shard = False
        self.headers = []

    def privileges(self, value):
        index = {name: {privilege: self.index_grants.get(name, {}).get(privilege, privilege == 'read')
                        for privilege in entry['privileges']}
                 for entry in value['index'] for name in entry['names']}
        if self.omit_cluster:
            return {'index': index}
        return {'index': index, 'cluster': {name: self.cluster_grants.get(name, False) for name in value['cluster']}}

    def __call__(self, method, url, headers, body):
        self.headers.append(headers)
        path = url[len(URL):]
        value = json.loads(body) if body else None
        self.requests.append((method, path, value))
        if path == '/':
            return 200, json.dumps({'version': {'number': self.version}}).encode()
        if path == '/_resolve/index/' + INDEX:
            return 200, json.dumps({'indices': [], 'aliases': [], 'data_streams': [{'name': DATA_STREAM}]}).encode()
        if path == '/_security/user/_has_privileges':
            return 200, json.dumps(self.privileges(value)).encode()
        if path.endswith('/_field_caps?fields=*&include_unmapped=false'):
            return 200, json.dumps({'fields': {
                'host.name': {'keyword': {'aggregatable': True}}, 'process.name': {'keyword': {'aggregatable': True}},
                'message': {'text': {'aggregatable': False}}, '@timestamp': {'date': {'aggregatable': True}}}}).encode()
        if path.endswith('/_pit?keep_alive=30m'):
            self.opened += 1
            pit = f'pit-{self.opened}'
            self.pits.add(pit)
            return 200, json.dumps({'id': pit}).encode()
        if path == '/_pit':
            self.pits.discard(value['id'])
            return 200, b'{"succeeded":true}'
        if path == '/_search':
            return self.search(value)
        return 404, b'{}'

    def search(self, value):
        if self.fail_search:
            return self.fail_search
        if value['pit']['id'] not in self.pits:
            return 404, b'{"error":{"type":"search_phase_execution_exception"}}'
        if self.lose_shard:
            self.lose_shard = False
            return 200, json.dumps({'_shards': {'failed': 1, 'failures': [
                {'reason': {'type': 'search_context_missing_exception'}}]}, 'hits': {'hits': []}}).encode()
        pit = value['pit']['id']
        if self.rotate_pit:
            pit += '+'
            self.pits.add(pit)
        after = value.get('search_after', [0, -1])[1]
        docs = [doc for doc in self.docs if doc['sort'][1] > after]
        ids = re.findall(r'_id:"([^"]+)"', json.dumps(value['query']).replace('\\"', '"'))
        if ids:
            docs = [doc for doc in docs if doc['_id'] in ids]
        hits = docs[value.get('from', 0):][:value.get('size', 10)]
        sample = {'hits': {'hits': [{'_id': self.docs[0]['_id'], '_source': {}}]}}
        return 200, json.dumps({'pit_id': pit, 'timed_out': False, '_shards': {'failed': 0},
                                'hits': {'total': {'value': len(docs), 'relation': 'eq'}, 'hits': hits},
                                'aggregations': {'values': {'buckets': [{'key': 'ws-01', 'doc_count': 5, 'sample': sample}]},
                                                 'hosts': {'buckets': [{'key': 'ws-01', 'doc_count': 5}]},
                                                 'first': {'value': None}, 'last': {'value': None}}}).encode()

    def searches(self):
        return [value for method, path, value in self.requests if path == '/_search']


class Runtime:
    """The analyst VM is stopped, so the bot tools can reach the connected service only through its state file."""

    lab_url = None  # the connected service's, for this file's direct requests

    @classmethod
    def invoke(cls, action, **_):
        return {'profile': query_adapter.LAB_OWNER, 'state': 'stopped'}


class ConnectedCase(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__('shutil').rmtree(self.root, ignore_errors=True))
        self.home = self.root / 'hermes' / 'profiles' / connected.PROFILE
        self.home.mkdir(parents=True)
        (self.root / 'hermes' / 'profiles' / 'framework-researcher').mkdir()
        self.config = self.write('connect.json', {'url': URL, 'index': INDEX})
        self.case = {'case_id': CASE_ID, 'question': 'What ran on ws-01?', 'data_origin': 'work-connected',
                     'network_capture': 'none', 'hosts': ['ws-01'],
                     'time_range_utc': {'start_inclusive': START, 'end_exclusive': END}}
        self.case_path = self.write('case.json', self.case)
        self.elastic = FakeElastic()

    def write(self, name, value):
        path = self.root / name
        path.write_text(json.dumps(value), encoding='utf-8')
        return path

    def start(self, environ=None):
        environ = {'HUNT_ELASTIC_API_KEY': KEY} if environ is None else environ
        server, source, state = connected.start(self.config, self.case_path, self.home, environ=environ,
                                                transport=self.elastic)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(connected.stop, server, source, state)
        self.addCleanup(server.shutdown)
        Runtime.lab_url = f'http://127.0.0.1:{server.server_address[1]}'
        return server, source, state, environ

    def tool(self, tool_name, **arguments):
        return query_adapter.run_tool(tool_name, {'case_id': CASE_ID, **arguments}, runtime=Runtime,
                                      state_dir=self.home / 'hunt-lab-vm', profile='framework-researcher')

    def get(self, path):
        opener = request.build_opener(request.ProxyHandler({}))
        try:
            with opener.open(Runtime.lab_url + path, timeout=10) as response:
                return response.status, dict(response.headers), json.loads(response.read())
        except request.HTTPError as failure:
            with failure:
                return failure.code, dict(failure.headers), json.loads(failure.read())


class RefusalTests(ConnectedCase):
    def refused(self, *, environ=None, check=False):
        environ = {'HUNT_ELASTIC_API_KEY': KEY} if environ is None else environ
        with self.assertRaises(connected.ConnectError) as caught:
            if check:
                connected.check(self.config, self.case_path, environ=environ, transport=self.elastic)
            else:
                connected.start(self.config, self.case_path, self.home, environ=environ, transport=self.elastic)
        self.assertNotIn(KEY, str(caught.exception))
        self.assertFalse((self.home / connected.CONNECTED_STATE / 'state.json').exists())
        return str(caught.exception)

    def test_a_key_that_can_write_delete_or_manage_is_refused_before_serving(self):
        for setting, value in (('index_grants', {INDEX: {'write': True}}),
                               ('index_grants', {DATA_STREAM: {'delete_index': True}}),
                               ('index_grants', {INDEX: {'read': False}}),
                               ('cluster_grants', {'manage_security': True}),
                               ('cluster_grants', {'manage_slm': True}),
                               ('cluster_grants', {'cancel_task': True}),
                               ('omit_cluster', True)):
            with self.subTest(setting=setting, value=value):
                self.elastic = FakeElastic()
                setattr(self.elastic, setting, value)
                self.assertIn('key_not_read_only', self.refused(check=True))
                self.assertFalse(any(path.endswith('/_pit?keep_alive=30m') for _, path, _ in self.elastic.requests))
        asked = next(value for _, path, value in self.elastic.requests if path.endswith('_has_privileges'))
        self.assertEqual(asked['index'][0]['names'], [INDEX, DATA_STREAM])

    def test_a_cluster_older_than_7_12_is_refused(self):
        self.elastic.version = '7.11.2'
        self.assertIn('7.12', self.refused(check=True))

    def test_a_key_in_a_bot_profile_or_hermes_home_is_refused(self):
        for place in ('profiles/framework-researcher/.env', 'profiles/framework-network-analyst/config.yaml', '.env'):
            with self.subTest(place=place):
                path = self.root / 'hermes' / place
                path.write_text('HUNT_ELASTIC_API_KEY=' + KEY + '\n', encoding='utf-8')
                self.assertIn('key_in_bot_profile', self.refused())
                self.assertEqual(self.elastic.requests, [])
                path.unlink()

    def test_cases_and_configs_outside_the_connected_contract_are_refused(self):
        recent = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(time.time() - 60))
        for change, expected in ((dict(data_origin='work-export'), 'work-connected'),
                                 (dict(network_capture=None), 'network_capture'),
                                 (dict(time_range_utc={'start_inclusive': START, 'end_exclusive': recent}), 'window_not_closed'),
                                 (dict(time_range_utc={'start_inclusive': START, 'end_exclusive': '2026-11-01T11:00:00'}),
                                  'UTC offset'),
                                 (dict(hosts=[]), 'hosts'), (dict(hosts=['ws-01', 'ws-01']), 'hosts'),
                                 (dict(hosts=[{}]), 'hosts')):
            with self.subTest(change=change):
                self.case_path = self.write('case.json', {**self.case, **change})
                self.assertIn(expected, self.refused())
        self.case_path = self.write('case.json', self.case)
        for config in ({'url': URL, 'index': 'remote:logs-*'}, {'url': 'http://elastic.example.test', 'index': INDEX},
                       {'url': URL, 'index': INDEX, 'password': 'x'}):
            with self.subTest(config=config):
                self.config = self.write('connect.json', config)
                self.refused()
        self.config = self.write('connect.json', {'url': URL, 'index': INDEX})
        self.assertIn('holds no API key', self.refused(environ={}))

    def test_state_dir_must_be_the_analyst_profile_home_without_a_running_service(self):
        with self.assertRaises(connected.ConnectError):
            connected.start(self.config, self.case_path, self.root, environ={'HUNT_ELASTIC_API_KEY': KEY},
                            transport=self.elastic)
        state = self.home / connected.CONNECTED_STATE / 'state.json'
        state.parent.mkdir(parents=True)
        state.write_text('{"instance": "other"}', encoding='utf-8')
        with self.assertRaises(connected.ConnectError) as caught:
            connected.start(self.config, self.case_path, self.home, environ={'HUNT_ELASTIC_API_KEY': KEY},
                            transport=self.elastic)
        self.assertIn('already serves', str(caught.exception))
        self.assertEqual(self.elastic.requests, [])
        self.assertEqual(state.read_text(encoding='utf-8'), '{"instance": "other"}')
        state.unlink()

    def test_two_services_started_together_cannot_both_claim_the_state_dir(self):
        gate = threading.Barrier(2)
        fake = self.elastic

        def slow(method, url, headers, body):
            if url.endswith('/_has_privileges'):
                time.sleep(0.3)
            return fake(method, url, headers, body)

        outcomes = []

        def run():
            gate.wait()
            try:
                outcomes.append(connected.start(self.config, self.case_path, self.home,
                                                environ={'HUNT_ELASTIC_API_KEY': KEY}, transport=slow))
            except connected.ConnectError as failure:
                outcomes.append(str(failure))

        threads = [threading.Thread(target=run) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        started = [outcome for outcome in outcomes if isinstance(outcome, tuple)]
        self.assertEqual(len(started), 1, outcomes)
        self.assertIn('already serves', next(outcome for outcome in outcomes if isinstance(outcome, str)))
        connected.stop(*started[0])
        self.assertFalse((self.home / connected.CONNECTED_STATE / 'state.json').exists())

    def test_a_cluster_error_reports_status_and_type_only(self):
        original = self.elastic.__call__

        def unauthorized(method, url, headers, body):
            if url.endswith('/_has_privileges'):
                return 401, json.dumps({'error': {'type': 'security_exception', 'reason': 'secret detail ' + KEY}}).encode()
            return original(method, url, headers, body)

        self.elastic = unauthorized
        message = self.refused(check=True)
        self.assertIn('HTTP 401 (security_exception)', message)
        self.assertNotIn('secret detail', message)

    def test_check_reports_a_failed_count_as_an_error_line(self):
        self.elastic.fail_search = (500, b'{"error":{"type":"internal"}}')
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            code = connected.main(['check', '--config', str(self.config), '--case', str(self.case_path)],
                                  transport=self.elastic, environ={'HUNT_ELASTIC_API_KEY': KEY})
        self.assertEqual((code, json.loads(stdout.getvalue())['error']), (2, 'count the events in scope: backend_not_ready'))


class ServiceTests(ConnectedCase):
    def test_the_bot_tools_page_scope_and_cite_through_the_host_service(self):
        _server, _source, _state, environ = self.start()
        self.assertNotIn('HUNT_ELASTIC_API_KEY', environ)
        first = self.tool('elastic_search', q='process.name:cmd.exe', size=2)
        self.assertTrue(first['ok'], first)
        cited = [hit['event.id'] for hit in first['result']['hits']]
        self.assertEqual(cited, [connected.citation('AbC0x_-'), connected.citation('AbC1x_-')])
        self.assertTrue(all(re.fullmatch(r'evt-\d{16}', item) for item in cited))
        body = self.elastic.searches()[-1]
        self.assertEqual(body['query']['bool']['filter'][:2], [{'range': {'@timestamp': {'gte': START, 'lt': END}}},
                                                               {'terms': {'host.name': ['ws-01']}}])
        self.assertEqual(body['sort'], [{'@timestamp': {'order': 'asc', 'numeric_type': 'date_nanos'}}, {'_shard_doc': 'asc'}])
        self.assertEqual(body['pit'], {'id': 'pit-1', 'keep_alive': '30m'})
        second = self.tool('elastic_search', q='process.name:cmd.exe', size=2, after=first['result']['next_after'])
        self.assertEqual(self.elastic.searches()[-1]['search_after'], [1761991200000000001, 1])
        self.assertFalse(set(cited) & {hit['event.id'] for hit in second['result']['hits']})
        lookup = self.tool('elastic_search', q=f'event.id:("{cited[0]}" OR "{cited[1]}")', size=10)
        self.assertEqual(sorted(hit['event.id'] for hit in lookup['result']['hits']), sorted(cited))
        query = self.elastic.searches()[-1]['query']['bool']['filter'][-1]['query_string']['query']
        self.assertEqual(query, '(_id:"AbC0x_-" OR _id:"AbC1x_-")')
        self.assertEqual([hit['event.id'] for hit in self.tool('elastic_search', q=cited[0])['result']['hits']], [cited[0]])
        records = self.tool('elastic_aggregate', field='host.name')['result']['buckets']
        self.assertEqual(records[0]['sample_event_id'], cited[0])
        detect = self.tool('detection_test', q='process.name:cmd.exe', name='cmd')['result']
        self.assertEqual(detect['sample'][0]['event.id'], cited[0])
        lines = (self.home / connected.CONNECTED_STATE / CASE_ID / 'citations.jsonl').read_text(encoding='utf-8').splitlines()
        self.assertIn({'evt': cited[0], '_id': 'AbC0x_-'}, [json.loads(line) for line in lines])

    def test_refusals_reach_the_bot_as_fixed_codes(self):
        self.start()
        for name, arguments, code in (
                ('elastic_search', {'q': 'event.id:evt-0000000000000001'}, 'unknown_citation'),
                ('elastic_search', {'q': 'evt-000123'}, 'unknown_citation'),
                ('elastic_search', {'q': 'process.name:/cm.*/'}, 'regex_not_supported'),
                ('elastic_search', {'q': '_exists_:event.id'}, 'invalid_query'),
                ('elastic_aggregate', {'field': 'user.name'}, 'field_unavailable'),
                ('intel_lookup', {'values': '203.0.113.7'}, 'no_intel_source'),
                ('arkime_sessions', {}, 'no_network_capture'),
                ('packet_fields', {}, 'no_network_capture')):
            with self.subTest(tool=name, arguments=arguments):
                result = self.tool(name, **arguments)
                self.assertEqual((result['ok'], result.get('detail')), (False, code), result)
        self.assertEqual(self.tool('elastic_search', q='url.path:"/a/b" AND x\\/y')['ok'], True)
        self.elastic.fail_search = (400, b'{"error":{"type":"query_shard_exception"}}')
        self.assertEqual(self.tool('elastic_search', q='a')['detail'], 'invalid_query')
        self.elastic.fail_search = (500, b'{"error":{"type":"internal"}}')
        self.assertEqual(self.tool('elastic_search', q='a')['detail'], 'backend_not_ready')

    def test_citation_rewrites_keep_phrases_and_never_open_a_regex(self):
        self.start()
        cited = self.tool('elastic_search', size=1)['result']['hits'][0]['event.id']
        searches = len(self.elastic.searches())
        for q, code in ((f'event.id:("{cited}) /.*/ event.id:({cited}")', 'invalid_query'),
                        (f'{cited} OR /.*/', 'regex_not_supported'), (f'"{cited}" /.*/', 'regex_not_supported')):
            with self.subTest(q=q):
                self.assertEqual(self.tool('elastic_search', q=q).get('detail'), code)
        self.assertEqual(len(self.elastic.searches()), searches)
        for q in (f'"{cited} /.*/ {cited}"', f'message:"see {cited} here"'):
            with self.subTest(q=q):
                self.assertTrue(self.tool('elastic_search', q=q)['ok'])
                options = self.elastic.searches()[-1]['query']['bool']['filter'][-1]['query_string']
                self.assertEqual(options['query'], q)
        self.assertNotIn('event.id', options['fields'])
        for q, expected in ((r'a\" event.id:foo "b"', None), (rf'a\" {cited} "b"', r'a\" (_id:"AbC0x_-") "b"')):
            with self.subTest(q=q):
                result = self.tool('elastic_search', q=q)
                if expected is None:
                    self.assertEqual(result.get('detail'), 'invalid_query')
                else:
                    options = self.elastic.searches()[-1]['query']['bool']['filter'][-1]['query_string']
                    self.assertEqual((result['ok'], options['query']), (True, expected))

    def test_a_changed_point_in_time_id_is_used_next(self):
        self.start()
        self.elastic.rotate_pit = True
        self.tool('elastic_search', size=1)
        self.tool('elastic_search', size=1)
        self.assertEqual([body['pit']['id'] for body in self.elastic.searches()[-2:]], ['pit-1', 'pit-1+'])

    def test_a_node_losing_its_part_of_the_snapshot_reopens_it(self):
        _server, source, _state, _environ = self.start()
        generation = source.generation
        self.elastic.lose_shard = True
        self.assertTrue(self.tool('elastic_search', size=1)['ok'])
        self.assertEqual((source.generation, self.elastic.opened), (generation + 1, 2))

    def test_an_expired_snapshot_reopens_and_ends_open_pages_only(self):
        _server, source, _state, _environ = self.start()
        generation = source.generation
        first = self.tool('elastic_search', size=2)
        self.elastic.pits.clear()
        result = self.tool('elastic_search', size=2, after=first['result']['next_after'])
        self.assertEqual(result.get('detail'), 'cursor_expired')
        self.assertEqual((source.generation, self.elastic.opened), (generation + 1, 2))
        again = self.tool('elastic_search', size=2)
        self.assertTrue(again['ok'], again)
        self.elastic.pits.clear()
        self.assertTrue(self.tool('elastic_aggregate', field='host.name')['ok'])
        self.assertEqual(self.tool('elastic_search', size=2, after=first['result']['next_after'])['detail'], 'cursor_expired')

    def test_health_state_instance_header_and_no_console(self):
        server, _source, state, _environ = self.start()
        recorded = json.loads(state.read_text(encoding='utf-8'))
        self.assertEqual(recorded, {'version': 1, 'pid': recorded['pid'], 'port': server.server_address[1], 'case_id': CASE_ID,
                                    'instance': server.instance_id, 'api_key_env': 'HUNT_ELASTIC_API_KEY'})
        status, headers, value = self.get('/health')
        self.assertEqual((status, value['ready'], value['event_count'], value['backend'], value['network_capture']),
                         (200, True, 5, 'work-elastic', 'none'))
        self.assertEqual(headers['X-Hunt-Lab-Instance'], server.instance_id)
        status, headers, value = self.get('/case')
        self.assertEqual(value, self.case)
        self.assertNotIn('elastic.example.test', json.dumps(value))
        self.assertEqual(self.get('/')[::2], (404, {'error': 'not_found'}))
        self.assertEqual(self.get('/view?q=a')[0], 404)
        self.assertEqual(self.get('/health?x=1')[0], 400)

    def test_stop_removes_the_state_and_closes_the_snapshot_and_citations_survive_a_restart(self):
        server, source, state, _environ = self.start()
        first = self.tool('elastic_search', size=1)['result']
        cited = first['hits'][0]['event.id']
        server.shutdown()
        connected.stop(server, source, state)
        self.assertFalse(state.exists())
        self.assertIn(('DELETE', '/_pit', {'id': 'pit-1'}), self.elastic.requests)
        self.start()
        lookup = self.tool('elastic_search', q='event.id:' + cited)
        self.assertEqual([hit['event.id'] for hit in lookup['result']['hits']], [cited])
        self.assertEqual(self.tool('elastic_search', size=1, after=first['next_after']).get('detail'), 'cursor_expired')

    def test_the_key_appears_only_in_the_authorization_header(self):
        self.start()
        outputs = [self.tool(name, **arguments) for name, arguments in (
            ('elastic_search', {}), ('elastic_aggregate', {'field': 'host.name'}), ('intel_lookup', {'values': 'x'}),
            ('detection_test', {'q': 'a', 'name': 'b'}))]
        outputs += [self.get(path) for path in ('/health', '/case', '/activity', '/')]
        files = [path.read_text(encoding='utf-8') for path in (self.home / connected.CONNECTED_STATE).rglob('*') if path.is_file()]
        bodies = [json.dumps(value) for _method, _path, value in self.elastic.requests]
        self.assertFalse([text for text in [*map(json.dumps, outputs), *files, *bodies] if KEY in text])
        self.assertEqual({headers['Authorization'] for headers in self.elastic.headers}, {'ApiKey ' + KEY})

    def test_check_reports_version_privileges_coverage_and_count(self):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            code = connected.main(['check', '--config', str(self.config), '--case', str(self.case_path)],
                                  transport=self.elastic, environ={'HUNT_ELASTIC_API_KEY': KEY})
        self.assertEqual(code, 0)
        report = json.loads(stdout.getvalue())
        self.assertEqual((report['version'], report['read_only'], report['in_scope_events']), ('8.15.3', True, 5))
        self.assertIn('user.name', report['unavailable_fields'])
        self.assertIn('process.command_line.text', report['unsearched_query_fields'])
        self.assertNotIn('host.name', report['unsearched_query_fields'])
        self.assertNotIn(KEY, stdout.getvalue())
        self.assertEqual(self.elastic.pits, {'pit-0'})


if __name__ == '__main__':
    unittest.main()

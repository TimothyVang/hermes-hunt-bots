"""Host-side hunt_lab tools: owner-only registration, wiring, bounds, and guest calls."""
from contextlib import redirect_stdout
import inspect
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import shutil
import sys
import tempfile
import threading
import types
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

import hunt_lab
from hunt_lab import endpoints, lab_browser, query_adapter, scenario

CASE = 'lab-med-001'
ANALYST = 'framework-network-analyst'
HOST_TOOLS = {'elastic_search', 'elastic_aggregate', 'detection_test', 'intel_lookup',
              'arkime_sessions', 'arkime_unique', 'packet_fields'}
PLUGIN_TOOLS = HOST_TOOLS | {'hunt_lab_query', 'lab_browser', 'hunt_lab_batch'}
# Minimal valid arguments: each call passes local validation and stops at the lab resolver.
MINIMAL_ARGS = {
    'elastic_search': {}, 'elastic_aggregate': {'field': 'host.name'}, 'detection_test': {'q': 'a', 'name': 'b'},
    'intel_lookup': {'values': 'a'}, 'arkime_sessions': {}, 'arkime_unique': {'field': 'ip.src'},
    'packet_fields': {}, 'lab_browser': {'action': 'snapshot'},
}


def minimal_args_for(name, owner):
    if name == 'hunt_lab_batch':
        sub = 'arkime_sessions' if owner == ANALYST else 'elastic_search'
        return {'queries': [{'tool': sub}]}
    if name == 'hunt_lab_query':
        return {'dataset': 'events'}
    return MINIMAL_ARGS[name]


def owner_of(name):
    return next(profile for profile, tools in query_adapter.TOOL_OWNERSHIP.items() if name in tools)


def guest_lab_server():
    sys.path.insert(0, str(Path(query_adapter.__file__).parent / 'guest'))
    try:
        import lab_server
    finally:
        sys.path.pop(0)
    return lab_server


GUEST_INSTANCE = 'e' * 32
GUEST_SECRET = '5e' * 32
CONNECTED_SECRET = 'c0' * 32
CONTAINER_SECRET = 'd0' * 32


def stack(analyst, case_id, port, instance, secret, **changes):
    """Write a container lab's state.json as `hunt_lab.lab_stack start` does. Kibana and Arkime get two other
    valid ports (port ^ 1 and port ^ 2); the resolver never calls them."""
    state = {'version': 1, 'case_id': case_id, 'project': 'hunt-lab-' + case_id, 'instance': instance,
             'secret': secret, 'lab_port': port, 'kibana_port': port ^ 1, 'arkime_port': port ^ 2,
             'started_at': 1.0, **changes}
    folder = Path(analyst) / endpoints.CONTAINER_STATE / changes.get('case_id', case_id)
    folder.mkdir(parents=True, exist_ok=True)
    (folder / 'state.json').write_text(json.dumps(state), encoding='utf-8')
    return port


def stack_guest(analyst, guest, **changes):
    """`stack` for `guest`'s case, port, instance and secret; `changes` overrides any state field."""
    state = {'case_id': guest.case_id, 'port': guest.server.server_address[1], 'instance': guest.instance,
             'secret': guest.secret}
    fields = {key: changes.pop(key) for key in ('instance', 'secret') if key in changes}
    return stack(analyst, state['case_id'], state['port'], fields.get('instance', state['instance']),
                 fields.get('secret', state['secret']), **changes)


class GuestStub:
    """Loopback stand-in for the guest lab_server; records every request it receives and, like it, answers only
    a caller sending its secret."""

    def __init__(self, case_id=CASE, instance=GUEST_INSTANCE, secret=GUEST_SECRET):
        self.case_id = case_id
        self.instance = instance
        self.secret = secret
        self.requests = []
        self.secrets = []
        self.run_ids = []
        self.overrides = {}
        stub = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def do_GET(self):
                url = urlsplit(self.path)
                params = {key: values[0] for key, values in parse_qs(url.query, keep_blank_values=True).items()}
                profile = self.headers.get('X-Hermes-Profile')
                expected = endpoints.caller_secret(stub.secret, profile)
                stub.secrets.append(self.headers.get(endpoints.SECRET_HEADER))
                stub.run_ids.append(self.headers.get(endpoints.RUN_ID_HEADER))
                if expected is None or self.headers.get(endpoints.SECRET_HEADER) != expected:
                    status, body, headers = 401, {'error': 'caller_not_authorized'}, {}
                else:
                    stub.requests.append((url.path, params, profile))
                    status, body, headers = stub.overrides.get(url.path) or stub.default(url.path, params)
                if stub.instance:
                    headers = {'X-Hunt-Lab-Instance': stub.instance, **headers}
                data = body if isinstance(body, bytes) else json.dumps(body).encode()
                self.send_response(status)
                for key, value in headers.items():
                    self.send_header(key, value)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = f'http://127.0.0.1:{self.server.server_address[1]}'

    def default(self, path, params):
        if path == '/case':
            return 200, {'case_id': self.case_id, 'question': 'synthetic'}, {}
        if path == '/events':
            return 200, {'case_id': self.case_id, 'dataset': 'events', 'read_only': True,
                         'total': 1, 'records': [{'event': {'id': 'evt-000001'}}]}, {}
        return 200, {'case_id': self.case_id, 'path': path, 'echo': params}, {}

    def close(self):
        self.server.shutdown()
        self.server.server_close()

    def endpoint_calls(self):
        return [item for item in self.requests if item[0] != '/case']


class ToolCallTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.analyst = Path(temp.name) / 'profiles' / ANALYST
        self.state_dir = self.analyst / 'hunt-lab-vm'
        self.guest = GuestStub()
        self.addCleanup(self.guest.close)
        stack_guest(self.analyst, self.guest)

    def call(self, name, arguments, profile=..., state_dir=True):
        state_dir = self.state_dir if state_dir is True else state_dir
        chosen = owner_of(name) if profile is ... else profile
        return query_adapter.call(name, arguments, state_dir=state_dir, profile=chosen)

    def test_each_tool_reaches_only_its_guest_endpoint_with_caller_identity(self):
        cases = {
            'elastic_search': ({'q': 'host.name:ws-01', 'size': 25, 'sort': 'desc', 'after': 'abc==',
                                'fields': 'event.id,@timestamp,process.command_line'},
                               '/es/search', {'q': 'host.name:ws-01', 'size': '25', 'sort': 'desc',
                                              'after': 'abc==', 'fields': 'event.id,@timestamp,process.command_line'}),
            'elastic_aggregate': ({'field': '@timestamp', 'interval': '5m'},
                                  '/es/aggs', {'q': '', 'field': '@timestamp', 'size': '20', 'interval': '5m'}),
            'detection_test': ({'q': 'process.name:rundll32.exe', 'name': 'rundll32 outbound'},
                               '/es/detect', {'q': 'process.name:rundll32.exe', 'name': 'rundll32 outbound'}),
            'intel_lookup': ({'values': '203.0.113.7,bad.example'}, '/intel', {'values': '203.0.113.7,bad.example'}),
            'arkime_sessions': ({'expression': 'ip.dst == 203.0.113.7', 'length': 10, 'start': 20},
                                '/arkime/sessions', {'expression': 'ip.dst == 203.0.113.7', 'length': '10', 'start': '20'}),
            'arkime_unique': ({'field': 'host.dns'}, '/arkime/unique', {'expression': '', 'field': 'host.dns', 'counts': '1'}),
            'packet_fields': ({'fields': 'dns.qry.name,_ws.col.Protocol', 'filter': 'dns.qry.name == "a.test"',
                               'length': 10, 'start': 5},
                              '/packets', {'length': '10', 'start': '5', 'fields': 'dns.qry.name,_ws.col.Protocol',
                                           'filter': 'dns.qry.name == "a.test"'}),
        }
        self.assertEqual(set(cases), HOST_TOOLS)
        expected_secrets = set()
        for name, (arguments, path, params) in cases.items():
            owner = owner_of(name)
            expected_secrets.add(endpoints.profile_secret(GUEST_SECRET, owner))
            with self.subTest(tool=name):
                self.guest.requests.clear()
                result = self.call(name, {'case_id': CASE, **arguments}, profile=owner)
                self.assertTrue(result['ok'], result)
                self.assertEqual((result['tool'], result['case_id'], result['profile']),
                                 (name, CASE, owner))
                self.assertEqual(result['result']['path'], path)
                self.assertEqual(self.guest.endpoint_calls(), [(path, params, owner)])
                # The loaded case is confirmed before the scoped query.
                self.assertEqual(self.guest.requests[0][0], '/case')
        self.assertEqual(set(self.guest.secrets), expected_secrets)
        self.assertNotIn(GUEST_SECRET, self.guest.secrets)

    def test_non_owners_are_refused_before_any_guest_request(self):
        self.guest.requests.clear()
        for name, bad_profile in (
                ('arkime_sessions', 'framework-researcher'),
                ('intel_lookup', 'framework-researcher'),
                ('detection_test', 'framework-researcher'),
                ('hunt_lab_query', 'framework-researcher'),
                ('elastic_search', 'framework-builder'),
                ('elastic_search', 'framework-coordinator'),
                ('elastic_search', None),
                ('hunt_lab_batch', 'framework-builder'),
                ('hunt_lab_batch', 'framework-reviewer'),
        ):
            with self.subTest(tool=name, profile=bad_profile):
                extra = minimal_args_for(name, 'framework-researcher')
                res = self.call(name, {'case_id': CASE, **extra}, profile=bad_profile)
                self.assertEqual((res['ok'], res['error']), (False, 'tool_not_owned'))
        self.assertEqual(self.guest.requests, [])

    def test_hunt_lab_batch_enforces_bounds_ownership_exclusions_and_byte_cap(self):
        self.guest.requests.clear()
        batch_ok = self.call('hunt_lab_batch', {
            'case_id': CASE,
            'queries': [
                {'tool': 'elastic_search', 'arguments': {'q': 'host.name:ws-01'}},
                {'tool': 'elastic_aggregate', 'arguments': {'field': 'host.name', 'size': 25}},
            ],
        }, profile='framework-researcher')
        self.assertTrue(batch_ok['ok'], batch_ok)
        self.assertEqual(len(batch_ok['results']), 2)
        # /case is probed once for the entire batch, followed by the two item GETs.
        self.assertEqual([r[0] for r in self.guest.requests], ['/case', '/es/search', '/es/aggs'])
        self.assertEqual(self.guest.requests[1][1]['size'], '25')

        analyst_ok = self.call('hunt_lab_batch', {
            'case_id': CASE,
            'queries': [
                {'tool': 'arkime_sessions', 'arguments': {'expression': 'port == 53'}},
                {'tool': 'arkime_unique', 'arguments': {'field': 'ip.dst'}},
                {'tool': 'hunt_lab_query', 'arguments': {'dataset': 'events', 'limit': 25}},
            ],
        }, profile=ANALYST)
        self.assertTrue(analyst_ok['ok'], analyst_ok)
        self.assertEqual(len(analyst_ok['results']), 3)

        self.guest.requests.clear()
        for bad_args, expected_err in (
                ({'case_id': CASE, 'queries': []}, 'invalid_batch_size'),
                ({'case_id': CASE, 'queries': [{'tool': 'elastic_search'}] * 6}, 'invalid_batch_size'),
                ({'case_id': CASE, 'queries': [{'tool': 'packet_fields'}]}, 'tool_not_batchable'),
                ({'case_id': CASE, 'queries': [{'tool': 'lab_browser', 'arguments': {'action': 'snapshot'}}]}, 'tool_not_batchable'),
                ({'case_id': CASE, 'queries': [{'tool': 'hunt_lab_batch', 'arguments': {'queries': []}}]}, 'tool_not_batchable'),
                ({'case_id': CASE, 'queries': [{'tool': 'arkime_sessions'}]}, 'tool_not_owned'),
                ({'case_id': CASE, 'queries': [{'tool': 'intel_lookup', 'arguments': {'values': '1.1.1.1'}}]}, 'tool_not_owned'),
                ({'case_id': CASE, 'queries': [{'tool': 'elastic_search', 'arguments': {'size': 26}}]}, 'invalid_size'),
        ):
            with self.subTest(bad_args=bad_args):
                res = self.call('hunt_lab_batch', bad_args, profile='framework-researcher')
                self.assertEqual((res['ok'], res['error']), (False, expected_err), res)
        self.assertEqual(self.guest.requests, [])

        # Oversized aggregate response (>96 KiB) fails closed with batch_response_too_large.
        self.guest.overrides['/es/search'] = (200, {'case_id': CASE, 'pad': 'x' * (50 * 1024)}, {})
        big = self.call('hunt_lab_batch', {
            'case_id': CASE,
            'queries': [
                {'tool': 'elastic_search', 'arguments': {'q': 'a'}},
                {'tool': 'elastic_search', 'arguments': {'q': 'b'}},
            ],
        }, profile='framework-researcher')
        self.assertEqual((big['ok'], big['error']), (False, 'batch_response_too_large'))
        self.guest.overrides.pop('/es/search', None)

    def test_hunt_run_id_environment_is_forwarded_to_guest(self):
        self.guest.run_ids.clear()
        with patch.dict(os.environ, {'HUNT_RUN_ID': 'wf-42:round:001'}, clear=False):
            res = self.call('elastic_search', {'case_id': CASE}, profile='framework-researcher')
        self.assertTrue(res['ok'], res)
        self.assertEqual(self.guest.run_ids, ['wf-42:round:001', 'wf-42:round:001'])

    def test_a_case_with_no_lab_up_stops_before_any_scoped_query(self):
        result = self.call('elastic_search', {'case_id': 'dns-lab-001'})
        self.assertEqual((result['ok'], result['error']), (False, 'lab_not_running'))
        self.assertEqual(self.guest.endpoint_calls(), [])

    def test_case_mismatch_stops_before_any_scoped_query(self):
        # A container state.json filed for dns-lab-001 whose lab answers /case for another case.
        stack(self.analyst, 'dns-lab-001', self.guest.server.server_address[1], GUEST_INSTANCE, GUEST_SECRET)
        result = self.call('elastic_search', {'case_id': 'dns-lab-001'})
        self.assertEqual((result['ok'], result['error']), (False, 'case_mismatch'))
        self.assertEqual([path for path, _, _ in self.guest.requests], ['/case'])

    def test_out_of_bounds_arguments_never_reach_the_lab(self):
        invalid = [
            ('elastic_search', {'case_id': CASE, 'size': 201}),
            ('elastic_search', {'case_id': CASE, 'size': True}),
            ('elastic_search', {'case_id': CASE, 'q': 'x' * 501}),
            ('elastic_search', {'case_id': CASE, 'sort': 'random'}),
            ('elastic_search', {'case_id': CASE, 'fields': 'event.id,../etc'}),
            ('elastic_search', {'case_id': CASE, 'index': 'other'}),
            ('elastic_search', {'case_id': 'Not_A_Case'}),
            ('elastic_search', {'q': 'no case'}),
            ('elastic_aggregate', {'case_id': CASE, 'field': 'host.name', 'interval': '5m'}),
            ('elastic_aggregate', {'case_id': CASE, 'field': '@timestamp', 'interval': '2h'}),
            ('elastic_aggregate', {'case_id': CASE, 'field': 'host.name', 'size': 101}),
            ('elastic_aggregate', {'case_id': CASE}),
            ('detection_test', {'case_id': CASE, 'q': 'a', 'name': 'n' * 81}),
            ('detection_test', {'case_id': CASE, 'name': 'missing query'}),
            ('intel_lookup', {'case_id': CASE, 'values': ','.join(['v'] * 51)}),
            ('intel_lookup', {'case_id': CASE, 'values': 'a' * 201}),
            ('intel_lookup', {'case_id': CASE, 'values': 'a,,b'}),
            ('arkime_sessions', {'case_id': CASE, 'start': 10001}),
            ('arkime_sessions', {'case_id': CASE, 'length': 0}),
            ('arkime_sessions', {'case_id': CASE, 'expression': 'a\nb'}),
            ('arkime_unique', {'case_id': CASE, 'field': 'ip.dst; drop'}),
            ('packet_fields', {'case_id': CASE, 'length': 0}),
            ('packet_fields', {'case_id': CASE, 'length': 201}),
            ('packet_fields', {'case_id': CASE, 'length': True}),
            ('packet_fields', {'case_id': CASE, 'start': -1}),
            ('packet_fields', {'case_id': CASE, 'start': 100001}),
            ('packet_fields', {'case_id': CASE, 'filter': 'x' * 301}),
            ('packet_fields', {'case_id': CASE, 'filter': 'dns\nip'}),
            ('packet_fields', {'case_id': CASE, 'filter': 7}),
            ('packet_fields', {'case_id': CASE, 'fields': 'ip.src;id'}),
            ('packet_fields', {'case_id': CASE, 'interface': 'eth0'}),
            ('packet_fields', {'case_id': CASE, 'expression': 'ip.src == 10.0.0.1'}),
        ]
        for name, arguments in invalid:
            with self.subTest(tool=name, arguments=arguments):
                result = self.call(name, arguments)
                self.assertFalse(result['ok'])
        self.assertEqual(self.guest.requests, [])

    def test_guest_error_codes_are_relayed_but_free_text_is_not(self):
        self.guest.overrides['/es/search'] = (400, {'error': 'invalid_field'}, {})
        result = self.call('elastic_search', {'case_id': CASE, 'fields': 'unknown.field'})
        self.assertEqual((result['error'], result['detail']), ('lab_http_400', 'invalid_field'))
        self.guest.overrides['/es/search'] = (400, {'error': 'Traceback: C:/private/path'}, {})
        result = self.call('elastic_search', {'case_id': CASE})
        self.assertEqual(result['error'], 'lab_http_400')
        self.assertNotIn('detail', result)

    def test_advertised_fields_are_exactly_the_guest_allowlists(self):
        sys.path.insert(0, str(Path(query_adapter.__file__).parent / 'guest'))
        try:
            import lab_server
        finally:
            sys.path.pop(0)
        self.assertEqual(set(query_adapter.ES_AGG_FIELDS), set(lab_server.AGG_FIELDS))
        self.assertEqual(set(query_adapter.ES_RETURN_FIELDS), set(lab_server.SEARCH_FIELDS))
        self.assertEqual(query_adapter.ARKIME_SESSION_FIELDS, tuple(lab_server.ARKIME_SESSION_FIELDS))
        self.assertEqual(set(query_adapter.ARKIME_UNIQUE_FIELDS), set(lab_server.ARKIME_UNIQUE_FIELDS))
        self.assertEqual(query_adapter.PACKET_FIELDS, tuple(lab_server.PACKET_FIELDS))
        self.assertEqual(query_adapter.PACKET_DEFAULT_FIELDS, tuple(lab_server.PACKET_DEFAULT_FIELDS))
        self.assertEqual(set(query_adapter.PACKET_FILTER_PROTOCOLS), set(lab_server.PACKET_FILTER_PROTOCOLS))
        described = query_adapter.TOOLS['elastic_search'][2]['parameters']['properties']['fields']['description']
        self.assertIn('winlog.event_data.TargetImage', described)

    def test_packet_fields_schema_states_the_saved_capture_boundary(self):
        schema = query_adapter.SCHEMAS['packet_fields']
        properties = schema['parameters']['properties']
        self.assertEqual(set(properties), {'case_id', 'fields', 'filter', 'length', 'start'})
        self.assertEqual(schema['parameters']['required'], ['case_id'])
        self.assertFalse(schema['parameters']['additionalProperties'])
        self.assertEqual((properties['length']['minimum'], properties['length']['maximum']), (1, 200))
        self.assertEqual((properties['start']['minimum'], properties['start']['maximum']), (0, 100000))
        self.assertEqual(properties['filter']['maxLength'], 300)
        for field in query_adapter.PACKET_FIELDS:
            self.assertIn(field, properties['fields']['description'])
        for protocol in query_adapter.PACKET_FILTER_PROTOCOLS:
            self.assertIn(protocol, properties['filter']['description'])
        for phrase in ("this case's saved packet capture only", 'Never live traffic', 'no cookies, authorization headers',
                       '?[redacted]', 'Cite the matching evt- log events', 'frame numbers are supporting evidence'):
            self.assertIn(phrase, schema['description'])

    def test_static_bot_texts_do_not_call_the_loaded_case_synthetic(self):
        # Live (work-export proof hunt): six step outputs called real data synthetic, repeating these texts.
        # Only the stage prompts know a case's origin; static texts may name synthetic cases conditionally.
        from hunt_lab import lab_browser
        texts = {name: json.dumps(schema) for name, schema in query_adapter.SCHEMAS.items()}
        texts['lab_browser'] = json.dumps(lab_browser.SCHEMA)
        bots = Path(query_adapter.__file__).resolve().parents[1] / 'hermes-bots'
        souls = sorted(bots.glob('framework-*/SOUL.md'))
        self.assertEqual(len(souls), 6)
        texts.update({path.parent.name + '/SOUL.md': path.read_text(encoding='utf-8') for path in souls})
        for name, text in texts.items():
            with self.subTest(text=name):
                self.assertNotIn('synthetic', text.lower().replace("a synthetic case's feed", ''))

    def test_citation_forms_taught_by_the_tools_are_what_the_scorer_extracts(self):
        packets = query_adapter.SCHEMAS['packet_fields']['description']
        intel = query_adapter.SCHEMAS['intel_lookup']['description']
        self.assertIn('cited as frame-<frame.number>', packets)
        self.assertIn('Cite a match by its id', intel)
        self.assertEqual(scenario.cited_ids(packets), {'frame-1234'})
        self.assertEqual(scenario.cited_ids(intel), {'ioc-00012'})

    def test_packet_fields_waits_for_the_guest_field_listing_and_decode(self):
        with patch.object(endpoints, 'get', wraps=endpoints.get) as get:
            self.assertTrue(self.call('packet_fields', {'case_id': CASE})['ok'])
            self.assertTrue(self.call('arkime_sessions', {'case_id': CASE})['ok'])
        timeouts = [(call.args[1].split('?')[0], call.args[3] if len(call.args) > 3 else None) for call in get.call_args_list]
        self.assertEqual(timeouts, [('/case', None), ('/packets', 50), ('/case', None), ('/arkime/sessions', 12)])

    def test_real_windows_log_fields_are_advertised_on_both_sides(self):
        lab_server = guest_lab_server()
        keyword = ('event.module', 'process.args', 'process.hash.sha1', 'file.extension', 'winlog.record_id',
                   'winlog.process.pid', 'winlog.event_data.User', 'winlog.event_data.CreationUtcTime',
                   'winlog.event_data.TargetProcessGUID', 'winlog.event_data.TargetProcessGuid')
        for field in keyword:
            with self.subTest(field=field):
                self.assertIn(field, query_adapter.ES_AGG_FIELDS)
                self.assertIn(field, lab_server.AGG_FIELDS)
                self.assertIn(field, lab_server.SEARCH_FIELDS)
        script = 'powershell.file.script_block_text'
        self.assertIn(script, query_adapter.ES_RETURN_FIELDS)
        self.assertIn(script, lab_server.SEARCH_FIELDS)
        self.assertNotIn(script, query_adapter.ES_AGG_FIELDS)
        self.assertNotIn(script, lab_server.AGG_FIELDS)
        self.assertIn('powershell', lab_server.EVENT_FIELDS)
        described = query_adapter.TOOLS['elastic_search'][2]['parameters']['properties']['fields']['description']
        self.assertIn('winlog.event_data.TargetProcessGUID', described)
        self.assertIn(script, described)
        result = self.call('elastic_search', {'case_id': CASE, 'fields': 'event.id,winlog.event_data.TargetProcessGUID,' + script})
        self.assertTrue(result['ok'], result)

    def test_no_network_capture_code_reaches_the_bot_from_the_real_guest(self):
        lab_server = guest_lab_server()
        case = {'case_id': CASE, 'question': 'Synthetic question.', 'network_capture': 'none',
                'time_range_utc': {'start_inclusive': '2026-03-02T00:00:00Z', 'end_exclusive': '2026-03-05T00:00:00Z'}}
        # No backend exists: a refusal that touched Elasticsearch or Arkime would surface as backend_not_ready.
        server = lab_server.make_server('127.0.0.1', 0, case, 'http://elastic.invalid:9200', instance=GUEST_INSTANCE,
                                        secret=GUEST_SECRET)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        stack(self.analyst, CASE, server.server_address[1], GUEST_INSTANCE, GUEST_SECRET)
        for name, arguments in (('arkime_sessions', {'expression': 'ip.dst == 203.0.113.7'}),
                                ('arkime_unique', {'field': 'ip.dst'}),
                                ('packet_fields', {'filter': 'dns.qry.name == "a.test"'}),
                                ('hunt_lab_query', {'dataset': 'network'})):
            with self.subTest(tool=name):
                result = self.call(name, {'case_id': CASE, **arguments})
                self.assertEqual((result['ok'], result['error'], result.get('detail')),
                                 (False, 'lab_http_400', 'no_network_capture'))
        case_view = self.call('hunt_lab_query', {'case_id': CASE, 'dataset': 'case'})
        self.assertEqual(case_view['evidence']['network_capture'], 'none')

    def test_oversized_redirected_or_foreign_case_responses_are_refused(self):
        self.guest.overrides['/arkime/sessions'] = (200, b'{"case_id":"lab-med-001","x":"' + b'a' * (512 * 1024) + b'"}', {})
        self.assertEqual(self.call('arkime_sessions', {'case_id': CASE})['error'], 'lab_response_too_large')
        self.guest.overrides['/arkime/unique'] = (302, {}, {'Location': 'http://example.invalid/'})
        self.assertEqual(self.call('arkime_unique', {'case_id': CASE, 'field': 'ip.src'})['error'], 'lab_http_302')
        self.guest.overrides['/intel'] = (200, {'case_id': 'other-case', 'matches': []}, {})
        self.assertEqual(self.call('intel_lookup', {'case_id': CASE, 'values': 'x'})['error'], 'lab_invalid_response')

    def test_a_stopped_lab_or_unresolved_state_fail_closed(self):
        self.assertEqual(self.call('elastic_search', {'case_id': CASE}, state_dir=None)['error'],
                         'lab_state_unavailable')
        shutil.rmtree(self.analyst / endpoints.CONTAINER_STATE / CASE)
        self.assertEqual(self.call('elastic_search', {'case_id': CASE})['error'], 'lab_not_running')
        self.assertEqual(self.guest.requests, [])

    def test_existing_hunt_lab_query_behavior_is_kept(self):
        guest = GuestStub(case_id='dns-lab-001')
        self.addCleanup(guest.close)
        stack_guest(self.analyst, guest)
        result = self.call('hunt_lab_query', {'case_id': 'dns-lab-001', 'dataset': 'events', 'q': 'dns', 'limit': 200},
                           profile=ANALYST)
        self.assertTrue(result['ok'], result)
        self.assertEqual(result['evidence']['records'], [{'event': {'id': 'evt-000001'}}])
        self.assertEqual(guest.endpoint_calls(),
                         [('/events', {'q': 'dns', 'host': '', 'limit': '200', 'offset': '0'}, ANALYST)])
        case = self.call('hunt_lab_query', {'case_id': 'dns-lab-001', 'dataset': 'case'}, profile=ANALYST)
        self.assertEqual(case['evidence']['case_id'], 'dns-lab-001')
        self.assertFalse(self.call('hunt_lab_query', {'case_id': 'dns-lab-001', 'dataset': 'events', 'offset': 5001},
                                   profile=ANALYST)['ok'])


INSTANCE = 'a' * 32


class ResolverTests(unittest.TestCase):
    """endpoints.resolve: the host-side connected service or a container lab, whichever serves the case
    (ADR 0005)."""

    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.analyst = Path(temp.name) / 'profiles' / ANALYST
        self.state_dir = self.analyst / 'hunt-lab-vm'
        self.lab = GuestStub()
        self.addCleanup(self.lab.close)
        self.connected = GuestStub(case_id='work-conn-001', instance=INSTANCE, secret=CONNECTED_SECRET)
        self.addCleanup(self.connected.close)
        self.serve()
        environ = patch.dict('os.environ')
        environ.start()
        self.addCleanup(environ.stop)
        os.environ.pop('HUNT_ELASTIC_API_KEY', None)

    def up(self):
        """Start the container lab serving `self.lab`'s case."""
        stack_guest(self.analyst, self.lab)

    def down(self):
        shutil.rmtree(self.analyst / endpoints.CONTAINER_STATE / self.lab.case_id)

    def serve(self, **changes):
        """Write the connected service's state.json as `hunt_lab.connected serve` does."""
        state = {'version': 2, 'pid': 4242, 'port': self.connected.server.server_address[1], 'case_id': 'work-conn-001',
                 'instance': INSTANCE, 'secret': CONNECTED_SECRET, 'api_key_env': 'HUNT_ELASTIC_API_KEY', **changes}
        folder = self.analyst / endpoints.CONNECTED_STATE
        folder.mkdir(parents=True, exist_ok=True)
        (folder / 'state.json').write_text(json.dumps(state), encoding='utf-8')

    def call(self, name, arguments, case_id='work-conn-001', profile=...):
        chosen = owner_of(name) if profile is ... else profile
        return query_adapter.call(name, {'case_id': case_id, **arguments}, state_dir=self.state_dir,
                                  profile=chosen)

    def test_bots_reach_a_connected_case_through_its_state_file_with_no_container_lab(self):
        result = self.call('elastic_search', {'q': 'host.name:ws-01'})
        self.assertTrue(result['ok'], result)
        self.assertEqual([path for path, _, _ in self.connected.requests], ['/case', '/es/search'])
        self.assertEqual(self.connected.requests[1][2], 'framework-researcher')
        self.assertEqual(self.call('hunt_lab_query', {'dataset': 'case'})['evidence']['case_id'], 'work-conn-001')
        self.assertEqual(self.lab.requests, [])

    def test_each_case_goes_to_the_lab_serving_it(self):
        self.up()
        self.assertTrue(self.call('elastic_search', {})['ok'])
        self.assertTrue(self.call('elastic_search', {}, case_id=CASE)['ok'])
        self.assertEqual([path for path, _, _ in self.lab.endpoint_calls()], ['/es/search'])
        self.assertEqual([path for path, _, _ in self.connected.endpoint_calls()], ['/es/search'])
        self.assertEqual(self.call('elastic_search', {}, case_id='other-001')['error'], 'lab_not_running')

    def test_a_case_both_labs_serve_is_ambiguous_and_queries_neither(self):
        self.lab.case_id = 'work-conn-001'
        self.up()
        for name, arguments in (('elastic_search', {}), ('hunt_lab_query', {'dataset': 'case'})):
            with self.subTest(tool=name):
                self.assertEqual(self.call(name, arguments)['error'], 'ambiguous_lab')
        self.assertEqual(self.lab.endpoint_calls() + self.connected.endpoint_calls(), [])

    def test_a_port_answering_without_the_state_files_instance_is_refused(self):
        for instance in (None, 'b' * 32):
            with self.subTest(instance=instance):
                self.connected.instance = instance
                self.assertEqual(self.call('elastic_search', {})['error'], 'lab_instance_mismatch')

    def test_a_tool_answer_from_another_instance_is_refused_after_case_resolved(self):
        self.connected.overrides['/es/search'] = (200, {'case_id': 'work-conn-001'}, {'X-Hunt-Lab-Instance': 'c' * 32})
        self.assertEqual(self.call('elastic_search', {})['error'], 'lab_instance_mismatch')
        self.connected.overrides['/es/search'] = (400, {'error': 'unknown_citation'}, {'X-Hunt-Lab-Instance': 'c' * 32})
        self.assertEqual(self.call('elastic_search', {})['error'], 'lab_instance_mismatch')
        self.connected.overrides['/es/search'] = (400, {'error': 'unknown_citation'}, {})
        self.assertEqual(self.call('elastic_search', {}), {'ok': False, 'profile': 'framework-researcher',
                                                           'error': 'lab_http_400', 'detail': 'unknown_citation'})

    def test_a_port_that_does_not_speak_http_or_json_fails_only_its_own_lab(self):
        raw = socket.socket()
        raw.bind(('127.0.0.1', 0))
        raw.listen(4)
        self.addCleanup(raw.close)

        def garble():
            while True:
                try:
                    peer, _ = raw.accept()
                except OSError:
                    return
                with peer:
                    peer.recv(4096)
                    peer.sendall(b'NOT HTTP\r\n\r\n')

        threading.Thread(target=garble, daemon=True).start()
        self.serve(port=raw.getsockname()[1])
        self.up()
        self.assertTrue(self.call('elastic_search', {}, case_id=CASE)['ok'])
        self.assertEqual(self.call('elastic_search', {})['error'], 'lab_instance_mismatch')
        self.serve()
        self.lab.overrides['/case'] = (200, b'<html>not json</html>', {})
        self.assertTrue(self.call('elastic_search', {})['ok'])
        self.assertEqual(self.call('elastic_search', {}, case_id=CASE)['error'], 'lab_invalid_response')

    def test_a_bot_holding_the_work_key_variable_is_refused_a_connected_case_only(self):
        os.environ['HUNT_ELASTIC_API_KEY'] = 'not-a-real-key'
        self.assertEqual(self.call('elastic_search', {})['error'], 'key_in_bot_environment')
        self.assertEqual(self.connected.endpoint_calls(), [])
        self.up()
        self.assertTrue(self.call('elastic_search', {}, case_id=CASE)['ok'])
        del os.environ['HUNT_ELASTIC_API_KEY']
        self.serve(api_key_env='WORK_KEY')
        os.environ['WORK_KEY'] = 'not-a-real-key'
        self.assertEqual(self.call('elastic_search', {})['error'], 'key_in_bot_environment')

    def test_state_files_being_written_stale_or_malformed(self):
        state = self.analyst / endpoints.CONNECTED_STATE / 'state.json'
        state.write_text('', encoding='utf-8')
        self.assertEqual(self.call('elastic_search', {})['error'], 'lab_not_running')
        self.up()
        self.assertTrue(self.call('elastic_search', {}, case_id=CASE)['ok'])
        for bad in ({'version': 1}, {'version': True}, {'version': 2.0}, {'port': 0}, {'port': '80'},
                    {'instance': 'A' * 32}, {'case_id': 'Work'}, {'secret': 'C0' * 32}, {'secret': 'c0' * 31},
                    {'secret': None}, {'api_key_env': 'A B'}, {'extra': 1}):
            with self.subTest(state=bad):
                self.serve(**bad)
                self.assertEqual(self.call('elastic_search', {}, case_id=CASE)['error'], 'connected_state_invalid')
        state.write_text('{not json', encoding='utf-8')
        self.assertEqual(self.call('elastic_search', {}, case_id=CASE)['error'], 'connected_state_invalid')

    def test_a_crashed_service_s_state_file_leaves_the_container_lab_its_own_case(self):
        self.connected.close()
        self.up()
        self.assertTrue(self.call('elastic_search', {}, case_id=CASE)['ok'])
        self.assertEqual(self.call('elastic_search', {})['error'], 'lab_unreachable')

    def test_a_container_case_never_probes_a_connected_service_serving_another_case(self):
        self.up()
        self.assertTrue(self.call('elastic_search', {}, case_id=CASE)['ok'])
        self.assertEqual(self.connected.requests, [])
        self.down()
        self.assertEqual(self.call('elastic_search', {}, case_id=CASE)['error'], 'lab_not_running')
        self.assertEqual(self.connected.requests, [])
        self.assertTrue(self.call('elastic_search', {})['ok'])

    def test_lab_browser_refuses_a_connected_case_before_launching_a_browser(self):
        with patch.object(lab_browser, '_session') as session:
            result = lab_browser.call({'case_id': 'work-conn-001', 'action': 'snapshot'},
                                      state_dir=self.state_dir, profile='framework-researcher',
                                      browser_root=self.analyst / 'browser')
        self.assertEqual(result, {'ok': False, 'profile': 'framework-researcher', 'error': 'no_lab_browser'})
        session.assert_not_called()

    def test_each_lab_gets_only_its_own_secret(self):
        self.up()
        self.assertTrue(self.call('elastic_search', {})['ok'])
        self.assertTrue(self.call('elastic_search', {}, case_id=CASE)['ok'])
        self.assertEqual((set(self.lab.secrets), set(self.connected.secrets)),
                         ({endpoints.profile_secret(GUEST_SECRET, 'framework-researcher')},
                          {endpoints.profile_secret(CONNECTED_SECRET, 'framework-researcher')}))
        served = endpoints.resolve(self.state_dir, CASE)
        self.assertEqual((served.instance, served.secret), (GUEST_INSTANCE, GUEST_SECRET))
        self.assertNotIn(GUEST_SECRET, repr(served))

    def test_a_container_lab_answering_with_another_instance_or_refusing_the_secret_fails_closed(self):
        self.up()
        self.lab.instance = 'f' * 32
        self.assertEqual(self.call('elastic_search', {}, case_id=CASE)['error'], 'lab_instance_mismatch')
        self.lab.instance, self.lab.secret = GUEST_INSTANCE, '00' * 32
        self.assertEqual({key: value for key, value in self.call('elastic_search', {}, case_id=CASE).items()
                          if key != 'profile'},
                         {'ok': False, 'error': 'lab_http_401', 'detail': 'caller_not_authorized'})
        self.assertEqual(self.lab.endpoint_calls(), [])

    def stack(self, guest, **changes):
        """Write a container lab's state.json serving `guest`'s case."""
        return stack_guest(self.analyst, guest, **changes)

    def container(self, case_id='team-med-001'):
        guest = GuestStub(case_id=case_id, instance='d' * 32, secret=CONTAINER_SECRET)
        self.addCleanup(guest.close)
        return guest

    def test_resolver_finds_container_lab(self):
        guest = self.container()
        port = self.stack(guest)
        result = self.call('elastic_search', {'q': 'host.name:ws-01'}, case_id='team-med-001')
        self.assertTrue(result['ok'], result)
        self.assertEqual([path for path, _, _ in guest.requests], ['/case', '/es/search'])
        served = endpoints.resolve(self.state_dir, 'team-med-001')
        self.assertEqual((served.origin, served.lab_url, served.arkime_url, served.kibana_url, served.instance),
                         ('container', f'http://127.0.0.1:{port}', f'http://127.0.0.1:{port ^ 2}',
                          f'http://127.0.0.1:{port ^ 1}', 'd' * 32))
        self.assertEqual(served.secret, CONTAINER_SECRET)
        self.assertEqual(set(guest.secrets),
                         {CONTAINER_SECRET, endpoints.profile_secret(CONTAINER_SECRET, 'framework-researcher')})
        # The connected service serves another case, so it is never asked.
        self.assertEqual((self.lab.requests, self.connected.requests), ([], []))
        self.assertEqual(self.call('elastic_search', {}, case_id='other-001')['error'], 'lab_not_running')

    def test_container_and_connected_serving_one_case_is_ambiguous(self):
        connected_case = self.container('work-conn-001')
        self.stack(connected_case)
        self.assertEqual(self.call('elastic_search', {})['error'], 'ambiguous_lab')
        self.assertEqual(connected_case.endpoint_calls() + self.connected.endpoint_calls(), [])
        with self.assertRaises(endpoints.QueryFailure) as caught:
            endpoints.resolve(self.state_dir, None)
        self.assertEqual(str(caught.exception), 'ambiguous_lab')

    def test_container_state_files_malformed_named_for_another_case_or_down(self):
        guest = self.container()
        self.stack(guest)
        for bad in ({'version': 2}, {'version': True}, {'project': 'hunt-lab-other-001'}, {'instance': 'D' * 32},
                    {'secret': 'c0' * 31}, {'lab_port': 0}, {'kibana_port': '80'}, {'arkime_port': None},
                    {'started_at': 'now'}, {'extra': 1}):
            with self.subTest(state=bad):
                self.stack(guest, **bad)
                self.assertEqual(self.call('elastic_search', {}, case_id='team-med-001')['error'],
                                 'container_state_invalid')
        port = guest.server.server_address[1]
        self.stack(guest, kibana_port=port)
        self.assertEqual(self.call('elastic_search', {}, case_id='team-med-001')['error'], 'container_state_invalid')
        self.stack(guest)
        # A state file under another case's folder never answers for its own case.
        (self.analyst / endpoints.CONTAINER_STATE / 'team-med-002').mkdir()
        (self.analyst / endpoints.CONTAINER_STATE / 'team-med-002' / 'state.json').write_bytes(
            (self.analyst / endpoints.CONTAINER_STATE / 'team-med-001' / 'state.json').read_bytes())
        self.assertEqual(self.call('elastic_search', {}, case_id='team-med-002')['error'], 'container_state_invalid')
        # An empty state file is a start still writing it; a stopped stack fails only its own case.
        (self.analyst / endpoints.CONTAINER_STATE / 'team-med-002' / 'state.json').write_bytes(b'')
        self.assertEqual(self.call('elastic_search', {}, case_id='team-med-002')['error'], 'lab_not_running')
        guest.close()
        self.assertEqual(self.call('elastic_search', {}, case_id='team-med-001')['error'], 'lab_unreachable')
        self.assertTrue(self.call('elastic_search', {})['ok'])

    def test_lab_browser_opens_a_container_lab_on_its_published_urls(self):
        guest = self.container()
        guest.overrides['/case'] = (200, {'case_id': 'team-med-001', 'question': 'synthetic', 'time_range_utc': {
            'start_inclusive': '2026-03-02T00:00:00Z', 'end_exclusive': '2026-03-03T00:00:00Z'}}, {})
        port = self.stack(guest)
        opened = []

        def session(root, scope):
            opened.append(scope)
            raise endpoints.QueryFailure('session_recorded')

        with patch.object(lab_browser, '_session', side_effect=session):
            result = lab_browser.call({'case_id': 'team-med-001', 'action': 'snapshot'},
                                      state_dir=self.state_dir, profile='framework-researcher',
                                      browser_root=self.analyst / 'browser')
        self.assertEqual(result['error'], 'session_recorded')
        [scope] = opened
        self.assertEqual(scope.origins, (f'http://127.0.0.1:{port}', f'http://127.0.0.1:{port ^ 2}',
                                         f'http://127.0.0.1:{port ^ 1}'))
        self.assertEqual(scope.lab_secret, endpoints.profile_secret(CONTAINER_SECRET, 'framework-researcher'))

    def test_resolver_has_no_vm_origin(self):
        # A VM's leftover deployment.json and seed caller file name no lab: only container and connected labs resolve.
        seed = self.state_dir / 'media' / 'cidata-lab-med-001.iso'
        seed.parent.mkdir(parents=True, exist_ok=True)
        (self.state_dir / 'deployment.json').write_text(json.dumps({'seed': str(seed)}), encoding='utf-8')
        seed.with_name(seed.name + '.secret.json').write_text(
            json.dumps({'version': 1, 'instance': 'x' * 32, 'secret': '5e' * 32}), encoding='utf-8')
        self.assertNotIn('runtime', inspect.signature(endpoints.resolve).parameters)
        for gone in ('caller_file', 'write_vm_caller', 'vm_caller'):
            self.assertFalse(hasattr(endpoints, gone), gone)
        with self.assertRaises(endpoints.QueryFailure) as caught:
            endpoints.resolve(self.state_dir, CASE)
        self.assertEqual(str(caught.exception), 'lab_not_running')
        guest = self.container(CASE)
        self.stack(guest)
        self.assertEqual(endpoints.resolve(self.state_dir, CASE).origin, 'container')
        self.assertEqual(endpoints.resolve(self.state_dir, 'work-conn-001').origin, 'connected')


class RegistrationTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)

    def hermes_env(self, home, owner):
        constants = types.SimpleNamespace(get_hermes_home=lambda: home, profile_name_for_home=lambda _home: owner)
        return patch.dict(sys.modules, {'hermes_constants': constants})

    def register(self, home, owner):
        ctx = types.SimpleNamespace(tools={}, commands=[])
        ctx.register_cli_command = lambda **kwargs: ctx.commands.append(kwargs['name'])
        ctx.register_tool = lambda name, toolset, schema, handler: ctx.tools.__setitem__(name, (toolset, schema, handler))
        with self.hermes_env(home, owner):
            hunt_lab.register(ctx)
        return ctx

    def test_each_framework_profile_registers_exactly_its_owned_tools_against_the_analyst_lab(self):
        # Hermes refuses any tool name the profile did not register (unknown-tool check), so
        # registering only owned tools is what enforces each bot's tool limits at runtime.
        analyst_state = self.root / 'profiles' / ANALYST / 'hunt-lab-vm'
        for owner in query_adapter.FRAMEWORK_PROFILES:
            with self.subTest(profile=owner):
                ctx = self.register(self.root / 'profiles' / owner, owner)
                self.assertEqual(ctx.commands, ['hunt-lab'])
                self.assertEqual(set(ctx.tools), set(query_adapter.TOOL_OWNERSHIP[owner]) & PLUGIN_TOOLS)
                for name, (toolset, schema, _handler) in ctx.tools.items():
                    self.assertEqual(toolset, 'hunt_lab')
                    self.assertEqual(schema['name'], name)
                    self.assertIn('case_id', schema['parameters']['required'])
                    self.assertFalse(schema['parameters']['additionalProperties'])
                calls = []
                observed = lambda state_dir: calls.append(Path(state_dir))
                wired = sorted(ctx.tools)
                with self.hermes_env(self.root / 'profiles' / owner, owner), patch.object(
                        endpoints, 'connected_state', side_effect=observed):
                    outputs = [ctx.tools[name][2]({'case_id': CASE, **minimal_args_for(name, owner)}) for name in wired]
                self.assertEqual([json.loads(output)['error'] for output in outputs],
                                 ['lab_not_running'] * len(wired))
                self.assertEqual(calls, [analyst_state] * len(wired))

    def test_registered_tool_handlers_resolve_hermes_home_dynamically_per_call(self):
        # HX002/PS-P05: handlers must read get_hermes_home() at call time rather than pinning a boot-time closure.
        ctx = self.register(self.root / 'boot' / 'profiles' / 'framework-researcher', 'framework-researcher')
        observed = []
        active_home = self.root / 'active' / 'profiles' / 'framework-researcher'
        with self.hermes_env(active_home, 'framework-researcher'), patch.object(
                endpoints, 'connected_state', side_effect=lambda state_dir: observed.append(Path(state_dir))):
            out = json.loads(ctx.tools['elastic_search'][2]({'case_id': CASE}))
        self.assertEqual(out['error'], 'lab_not_running')
        self.assertEqual(observed, [self.root / 'active' / 'profiles' / ANALYST / 'hunt-lab-vm'])
        # If the active turn belongs to a profile that does not own elastic_search, call-time ownership fails closed.
        with self.hermes_env(self.root / 'active' / 'profiles' / 'framework-builder', 'framework-builder'), patch.object(
                endpoints, 'connected_state', side_effect=AssertionError('must refuse before endpoint lookup')):
            denied = json.loads(ctx.tools['elastic_search'][2]({'case_id': CASE}))
        self.assertEqual(denied, {'ok': False, 'profile': 'framework-builder', 'error': 'tool_not_owned'})

    def test_every_plugin_tool_has_an_owner_and_the_coordinator_registers_none(self):
        owned = {tool for tools in query_adapter.TOOL_OWNERSHIP.values() for tool in tools}
        self.assertEqual(owned & PLUGIN_TOOLS, PLUGIN_TOOLS)
        self.assertEqual(set(query_adapter.TOOL_OWNERSHIP), set(query_adapter.FRAMEWORK_PROFILES))
        self.assertEqual(self.register(self.root / 'profiles' / 'framework-coordinator',
                                       'framework-coordinator').tools, {})

    def test_builder_and_coordinator_never_register_elastic_search(self):
        for owner in ('framework-builder', 'framework-coordinator'):
            with self.subTest(profile=owner):
                self.assertNotIn('elastic_search', self.register(self.root / 'profiles' / owner, owner).tools)

    def test_unknown_profiles_register_no_tools(self):
        for owner in ('default', 'framework-intruder', '', None):
            with self.subTest(profile=owner):
                ctx = self.register(self.root / 'profiles' / str(owner), owner)
                self.assertEqual(ctx.tools, {})

    def test_plugin_manifest_lists_every_registered_tool(self):
        manifest = (Path(query_adapter.__file__).parent / 'plugin.yaml').read_text(encoding='utf-8')
        line = next(line for line in manifest.splitlines() if line.startswith('provides_tools:'))
        listed = {name.strip() for name in line.split('[', 1)[1].rstrip(']').split(',')}
        registered = set()
        for owner in query_adapter.FRAMEWORK_PROFILES:
            registered |= set(self.register(self.root / 'profiles' / owner, owner).tools)
        self.assertEqual(listed, registered)
        self.assertEqual(listed, PLUGIN_TOOLS)
        self.assertIn('packet_fields', listed)

    def test_non_framework_or_unanchored_homes_get_no_working_lab(self):
        self.assertEqual(self.register(self.root / 'profiles' / 'default', 'default').tools, {})
        ctx = self.register(self.root / 'elsewhere', 'framework-builder')
        with self.hermes_env(self.root / 'elsewhere', 'framework-builder'), patch.object(
                endpoints, 'connected_state', side_effect=AssertionError('no lookup without analyst state')):
            output = ctx.tools['detection_test'][2]({'case_id': CASE, 'q': 'a', 'name': 'b'})
        self.assertEqual(json.loads(output)['error'], 'lab_state_unavailable')

    def test_lab_lifecycle_cli_refuses_every_profile_but_the_analyst(self):
        for requested in sorted(query_adapter.FRAMEWORK_PROFILES - {ANALYST}):
            cli = types.SimpleNamespace(explicit_cli_profile=lambda requested=requested: requested)
            constants = types.SimpleNamespace(get_hermes_home=lambda: self.root, profile_name_for_home=lambda _h: requested)
            stdout = io.StringIO()
            with patch.dict(sys.modules, {'hermes_cli': types.ModuleType('hermes_cli'), 'hermes_cli.main': cli,
                                          'hermes_constants': constants}), redirect_stdout(stdout):
                code = hunt_lab._command(types.SimpleNamespace(hunt_lab_operation='start'))
            self.assertEqual(code, 2)
            self.assertEqual(json.loads(stdout.getvalue())['state'], 'refused')


if __name__ == '__main__':
    unittest.main()

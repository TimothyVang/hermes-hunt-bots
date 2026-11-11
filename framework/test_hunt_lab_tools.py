"""Host-side hunt_lab tools: owner-only registration, wiring, bounds, and guest calls."""
from contextlib import redirect_stdout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
from pathlib import Path
import sys
import tempfile
import threading
import types
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

import hunt_lab
from hunt_lab import query_adapter, runtime as lab_runtime, scenario

CASE = 'lab-med-001'
ANALYST = 'framework-network-analyst'
HOST_TOOLS = {'elastic_search', 'elastic_aggregate', 'detection_test', 'intel_lookup',
              'arkime_sessions', 'arkime_unique', 'packet_fields'}
PLUGIN_TOOLS = HOST_TOOLS | {'hunt_lab_query', 'lab_browser'}
# Minimal valid arguments: each call passes local validation and stops at the VM status check.
MINIMAL_ARGS = {
    'elastic_search': {}, 'elastic_aggregate': {'field': 'host.name'}, 'detection_test': {'q': 'a', 'name': 'b'},
    'intel_lookup': {'values': 'a'}, 'arkime_sessions': {}, 'arkime_unique': {'field': 'ip.src'},
    'packet_fields': {}, 'lab_browser': {'action': 'snapshot'},
}


def guest_lab_server():
    sys.path.insert(0, str(Path(query_adapter.__file__).parent / 'guest'))
    try:
        import lab_server
    finally:
        sys.path.pop(0)
    return lab_server


class GuestStub:
    """Loopback stand-in for the guest lab_server; records every request it receives."""

    def __init__(self, case_id=CASE):
        self.case_id = case_id
        self.requests = []
        self.overrides = {}
        stub = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def do_GET(self):
                url = urlsplit(self.path)
                params = {key: values[0] for key, values in parse_qs(url.query, keep_blank_values=True).items()}
                stub.requests.append((url.path, params, self.headers.get('X-Hermes-Profile')))
                status, body, headers = stub.overrides.get(url.path) or stub.default(url.path, params)
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


class Runtime:
    def __init__(self, lab_url, state='running'):
        self.lab_url, self.state, self.calls = lab_url, state, []

    def invoke(self, action, *, state_dir, profile):
        self.calls.append((action, state_dir, profile))
        return {'profile': ANALYST, 'state': self.state, 'lab_url': self.lab_url}


class ToolCallTests(unittest.TestCase):
    def setUp(self):
        self.guest = GuestStub()
        self.addCleanup(self.guest.close)
        self.runtime = Runtime(self.guest.url)

    def call(self, name, arguments, profile='framework-researcher', state_dir='analyst-state'):
        return query_adapter.call(name, arguments, runtime=self.runtime, state_dir=state_dir, profile=profile)

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
        for name, (arguments, path, params) in cases.items():
            with self.subTest(tool=name):
                self.guest.requests.clear()
                result = self.call(name, {'case_id': CASE, **arguments}, profile='framework-reviewer')
                self.assertTrue(result['ok'], result)
                self.assertEqual((result['tool'], result['case_id'], result['profile']),
                                 (name, CASE, 'framework-reviewer'))
                self.assertEqual(result['result']['path'], path)
                self.assertEqual(self.guest.endpoint_calls(), [(path, params, 'framework-reviewer')])
                # The loaded case is confirmed before the scoped query.
                self.assertEqual(self.guest.requests[0][0], '/case')
        self.assertTrue(all(call == ('status', 'analyst-state', ANALYST) for call in self.runtime.calls))

    def test_case_mismatch_stops_before_any_scoped_query(self):
        result = self.call('elastic_search', {'case_id': 'dns-lab-001'})
        self.assertEqual((result['ok'], result['error']), (False, 'case_mismatch'))
        self.assertEqual(self.guest.endpoint_calls(), [])

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
        self.assertEqual(self.runtime.calls, [])

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

    def test_citation_forms_taught_by_the_tools_are_what_the_scorer_extracts(self):
        packets = query_adapter.SCHEMAS['packet_fields']['description']
        intel = query_adapter.SCHEMAS['intel_lookup']['description']
        self.assertIn('cited as frame-<frame.number>', packets)
        self.assertIn('Cite a match by its id', intel)
        self.assertEqual(scenario.cited_ids(packets), {'frame-1234'})
        self.assertEqual(scenario.cited_ids(intel), {'ioc-00012'})

    def test_packet_fields_waits_for_the_guest_field_listing_and_decode(self):
        with patch.object(query_adapter, '_get', wraps=query_adapter._get) as get:
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
        server = lab_server.make_server('127.0.0.1', 0, case, 'http://elastic.invalid:9200')
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        self.runtime.lab_url = f'http://127.0.0.1:{server.server_address[1]}'
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

    def test_stopped_vm_non_loopback_url_or_unresolved_state_fail_closed(self):
        self.runtime.state = 'stopped'
        self.assertEqual(self.call('elastic_search', {'case_id': CASE})['error'], 'owned_vm_not_running')
        self.runtime.state, self.runtime.lab_url = 'running', 'http://192.0.2.10:8765'
        self.assertEqual(self.call('elastic_search', {'case_id': CASE})['error'], 'invalid_owned_endpoint')
        self.runtime.lab_url = self.guest.url
        self.assertEqual(self.call('elastic_search', {'case_id': CASE}, state_dir=None)['error'],
                         'lab_state_unavailable')
        self.assertEqual(self.guest.requests, [])

    def test_existing_hunt_lab_query_behavior_is_kept(self):
        guest = GuestStub(case_id='dns-lab-001')
        self.addCleanup(guest.close)
        self.runtime.lab_url = guest.url
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


class RegistrationTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)

    def register(self, home, owner):
        constants = types.SimpleNamespace(get_hermes_home=lambda: home, profile_name_for_home=lambda _home: owner)
        ctx = types.SimpleNamespace(tools={}, commands=[])
        ctx.register_cli_command = lambda **kwargs: ctx.commands.append(kwargs['name'])
        ctx.register_tool = lambda name, toolset, schema, handler: ctx.tools.__setitem__(name, (toolset, schema, handler))
        with patch.dict(sys.modules, {'hermes_constants': constants}):
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
                status = lambda action, *, state_dir, profile: calls.append((action, Path(state_dir), profile)) or {}
                wired = sorted(set(ctx.tools) & set(MINIMAL_ARGS))
                with patch.object(lab_runtime, 'invoke', side_effect=status):
                    outputs = [ctx.tools[name][2]({'case_id': CASE, **MINIMAL_ARGS[name]}) for name in wired]
                self.assertEqual([json.loads(output)['error'] for output in outputs],
                                 ['owned_vm_not_running'] * len(wired))
                self.assertEqual(calls, [('status', analyst_state, ANALYST)] * len(wired))

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
        with patch.object(lab_runtime, 'invoke', side_effect=AssertionError('no status without analyst state')):
            output = ctx.tools['detection_test'][2]({'case_id': CASE, 'q': 'a', 'name': 'b'})
        self.assertEqual(json.loads(output)['error'], 'lab_state_unavailable')

    def test_vm_lifecycle_cli_refuses_every_profile_but_the_analyst(self):
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

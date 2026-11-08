"""lab_browser: in-browser request enforcement, case scoping, refs, bounded output, refusals, audit.

A fake DevTools socket stands in for the browser, so no browser or network is needed.
"""
import base64
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import queue
import random
import tempfile
import threading
import time
import types
import unittest
from unittest.mock import patch
from urllib import parse

from hunt_lab import lab_browser
from hunt_lab.browser_policy import LabScope, decide, document_allowed

CASE = 'lab-med-001'
ANALYST = 'framework-network-analyst'
ARKIME = 'http://127.0.0.1:41002'
START, STOP = 1760416200, 1760423400  # 2025-10-14T04:30:00Z .. 06:30:00Z
TAG = 'tags == "case:%s"' % CASE
WINDOW = {'start_inclusive': '2025-10-14T04:30:00Z', 'end_exclusive': '2025-10-14T06:30:00Z'}
BOX = {'ok': True, 'x': 150, 'y': 120, 'left': 100, 'top': 110, 'right': 200, 'bottom': 130}


def scope(lab='http://127.0.0.1:41001'):
    return LabScope(CASE, lab, ARKIME, START, STOP)


def ax(node_id, role, name='', backend=None, children=(), parent=None, value=None, ignored=False, **flags):
    node = {'nodeId': node_id, 'ignored': ignored, 'role': {'value': role}, 'name': {'value': name},
            'childIds': list(children), 'properties': [{'name': key, 'value': {'value': on}} for key, on in flags.items()]}
    if backend is not None:
        node['backendDOMNodeId'] = backend
    if parent is not None:
        node['parentId'] = parent
    if value is not None:
        node['value'] = {'value': value}
    return node


# Listed out of document order on purpose, as Chrome does.
PAGE_TREE = [
    ax('5', 'button', 'Go', 14, children=['6'], parent='1'),
    ax('3', 'textbox', 'Search', 12, parent='1', value='ip.dst == 10.0.0.1', focused=True),
    ax('1', 'RootWebArea', 'Sessions', 1, children=['2', '3', '4', '5']),
    ax('2', 'link', 'Sessions', 11, parent='1'),
    ax('4', 'button', 'Hidden', 13, parent='1', ignored=True),
    ax('6', 'StaticText', 'Go', 15, parent='5'),
]


class FakeBrowser:
    """The DevTools socket of one browser: replies from a table, records every message, emits events."""

    def __init__(self, tree=PAGE_TREE, text='Showing 1 - 50 of 2,849 entries'):
        self.sent, self.inbox, self.lock = [], queue.Queue(), threading.Lock()
        self.tree, self.text, self.url = tree, text, 'about:blank'
        self.replies = {
            'Target.getTargets': {'targetInfos': [{'targetId': 'main', 'type': 'page'},
                                                  {'targetId': 'stray', 'type': 'page'}]},
            'Target.attachToTarget': {'sessionId': 'page'},
            'Runtime.evaluate': self.evaluate,
            'Runtime.callFunctionOn': self.call_on,
            'Accessibility.getFullAXTree': lambda _m: {'nodes': self.tree},
            'DOM.resolveNode': lambda m: {'object': {'objectId': 'obj-%d' % m['params']['backendNodeId']}},
            'Page.navigate': self.navigate,
        }

    def evaluate(self, message):
        expression = message['params']['expression']
        value = {'location.href': self.url, '[document.title, location.href]': ['Sessions', self.url],
                 '[innerWidth, innerHeight]': [1366, 860]}.get(expression, self.text)
        return {'result': {'value': value}}

    def call_on(self, message):
        if 'innerText' in message['params']['functionDeclaration']:
            return {'result': {'value': 'protocols == dns'}}
        point = [argument['value'] for argument in message['params'].get('arguments', [])]
        return {'result': {'value': dict(BOX, x=point[0], y=point[1]) if point else BOX}}

    def navigate(self, message):
        self.url = message['params']['url']
        self.emit('Page.loadEventFired', {}, 'page')
        return {'frameId': 'frame'}

    def send(self, text):
        message = json.loads(text)
        with self.lock:
            self.sent.append(message)
        reply = self.replies.get(message['method'], {})
        result = reply(message) if callable(reply) else reply
        self.inbox.put(json.dumps({'id': message['id'], 'result': result}))

    def recv(self):
        return self.inbox.get()

    def close(self):
        self.inbox.put(None)

    def emit(self, method, params, session=None):
        self.inbox.put(json.dumps({'method': method, 'params': params, 'sessionId': session}))

    def calls(self, method):
        with self.lock:
            return [message for message in self.sent if message['method'] == method]

    def wait_for(self, method, count):
        deadline = time.monotonic() + 3
        while len(self.calls(method)) < count and time.monotonic() < deadline:
            time.sleep(0.01)
        return self.calls(method)


def session(fake, lab='http://127.0.0.1:41001', root=None, demo=lab_browser.DEMO_OFF):
    return lab_browser.BrowserSession(root or Path('.'), scope(lab), fake, ws_url='ws://127.0.0.1:1/devtools/browser/x',
                                      pid=1, rng=random.Random(7), sleep=lambda _seconds: None, demo=demo)


class LabStub:
    """The guest lab service's /case endpoint for one loaded case."""

    def __init__(self, case_id=CASE):
        case = {'case_id': case_id, 'question': 'synthetic', 'time_range_utc': WINDOW}

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def do_GET(self):
                data = json.dumps(case).encode()
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = 'http://127.0.0.1:%d' % self.server.server_address[1]

    def close(self):
        self.server.shutdown()
        self.server.server_close()


class Runtime:
    def __init__(self, lab_url, state='running'):
        self.lab_url, self.state, self.calls = lab_url, state, []

    def invoke(self, action, *, state_dir, profile):
        self.calls.append((action, state_dir, profile))
        return {'profile': ANALYST, 'state': self.state, 'lab_url': self.lab_url, 'arkime_url': ARKIME}


def query(url):
    return dict(parse.parse_qsl(parse.urlsplit(url).query, keep_blank_values=True))


class PolicyTests(unittest.TestCase):
    def test_only_the_two_exact_lab_origins_are_reachable(self):
        lab = scope()
        for url in ('http://example.com/', 'https://127.0.0.1:41001/', 'http://localhost:41001/view',
                    'http://127.0.0.1:41003/', 'http://user:pw@127.0.0.1:41001/', 'ftp://127.0.0.1:41001/',
                    'http://10.0.0.5:41002/api/sessions', 'data:text/html,hi'):
            self.assertEqual(decide(lab, 'GET', url).block, 'origin_not_lab', url)
        self.assertIsNone(decide(lab, 'GET', 'http://127.0.0.1:41001/view?q=powershell').block)
        self.assertIsNone(decide(lab, 'GET', ARKIME + '/assets/main.js').block)
        self.assertTrue(decide(lab, 'POST', 'http://127.0.0.1:41001/view').block)

    def test_arkime_get_searches_always_carry_the_case_tag(self):
        empty = decide(scope(), 'GET', ARKIME + '/api/sessions?length=50&date=1')
        self.assertEqual(query(empty.url)['expression'], TAG)
        typed = decide(scope(), 'GET', ARKIME + '/api/unique?exp=ip.dst&expression=' + parse.quote('ip.dst == 10.0.0.1'))
        self.assertEqual(query(typed.url)['expression'], '(ip.dst == 10.0.0.1) && ' + TAG)
        self.assertEqual(query(typed.url)['exp'], 'ip.dst')
        page = decide(scope(), 'GET', ARKIME + '/sessions?expression=' + parse.quote('port.dst == 53'))
        self.assertEqual(query(page.url)['expression'], '(port.dst == 53) && ' + TAG)

    def test_arkime_post_searches_carry_the_case_tag_in_query_and_body(self):
        url = ARKIME + '/api/spiview?spi=ip.dst&expression=' + parse.quote('port.dst == 53')
        for body, expected in (('{"expression": "ip.src == 10.0.0.9", "date": -1}', '(ip.src == 10.0.0.9) && ' + TAG),
                               ('{"order": "firstPacket:asc"}', TAG),
                               ('expression=protocols+%3D%3D+dns&length=10', '(protocols == dns) && ' + TAG)):
            verdict = decide(scope(), 'POST', url, body)
            values = json.loads(verdict.body) if body.startswith('{') else query('?' + verdict.body)
            self.assertEqual(values['expression'], expected, body)
            self.assertEqual(query(verdict.url)['expression'], '(port.dst == 53) && ' + TAG)
        bodiless = decide(scope(), 'POST', ARKIME + '/api/spiview?spi=ip.dst', '')
        self.assertEqual(query(bodiless.url)['expression'], TAG)
        self.assertIsNone(bodiless.body)
        self.assertEqual(decide(scope(), 'POST', ARKIME + '/api/sessions', None).block, 'arkime_body_unavailable')

    def test_search_windows_are_clamped_to_the_case_window(self):
        def window(**params):
            verdict = decide(scope(), 'GET', ARKIME + '/api/sessions?' + parse.urlencode(params))
            values = query(verdict.url)
            self.assertNotIn('date', values)
            return int(values['startTime']), int(values['stopTime'])

        self.assertEqual(window(date=-1), (START, STOP))
        self.assertEqual(window(startTime=START - 86400, stopTime=STOP + 86400), (START, STOP))
        self.assertEqual(window(startTime=START + 600, stopTime=STOP - 600), (START + 600, STOP - 600))
        self.assertEqual(window(startTime=STOP + 10, stopTime=STOP + 900), (START, STOP))
        body = json.loads(decide(scope(), 'POST', ARKIME + '/api/sessions', '{"startTime": 1, "stopTime": 9999999999}').body)
        self.assertEqual((body['startTime'], body['stopTime']), (START, STOP))

    def test_expressions_that_could_escape_the_tag_or_repeat_are_refused(self):
        for expression in ('a) || (b', 'ip.dst == 1.2.3.4) || (tags != "x"', '"unterminated', 'x\n'):
            verdict = decide(scope(), 'GET', ARKIME + '/api/sessions?expression=' + parse.quote(expression))
            self.assertEqual(verdict.block, 'arkime_expression_rejected', expression)
        doubled = decide(scope(), 'GET', ARKIME + '/api/sessions?expression=a&expression=b')
        self.assertEqual(doubled.block, 'arkime_ambiguous_search')

    def test_arkime_writes_exports_payloads_and_admin_routes_fail(self):
        for method, path in (('POST', '/api/sessions/addtags'), ('POST', '/api/sessions/removetags'),
                             ('POST', '/api/delete'), ('POST', '/api/sessions/scrub'), ('GET', '/api/users'),
                             ('POST', '/api/user/settings'), ('GET', '/settings'), ('GET', '/api/hunts'),
                             ('POST', '/api/hunt'), ('POST', '/api/sessions/send'), ('POST', '/sendSessions'),
                             ('GET', '/api/sessions/pcap/sessions.pcap'), ('GET', '/node1/pcap/abc.pcap'),
                             ('GET', '/api/session/node1/abc/packets'), ('GET', '/node1/raw/abc'),
                             ('GET', '/api/sessions/csv'), ('POST', '/api/upload'), ('GET', '/api/files'),
                             ('PUT', '/api/user/state/fieldHistory'), ('POST', '/api/view'),
                             ('DELETE', '/api/view/1'), ('POST', '/api/user/state/fieldHistory')):
            self.assertTrue(decide(scope(), method, ARKIME + path, '{}').block, (method, path))

    def test_only_lab_pages_and_blank_may_stay_loaded(self):
        for url in ('about:blank', 'http://127.0.0.1:41001/view', ARKIME + '/sessions'):
            self.assertTrue(document_allowed(scope(), url), url)
        for url in ('chrome-error://chromewebdata/', 'file:///C:/Windows/win.ini', 'chrome://settings',
                    'data:text/html,x', 'https://example.com/', 'about:srcdoc'):
            self.assertFalse(document_allowed(scope(), url), url)


class EnforcementTests(unittest.TestCase):
    def setUp(self):
        self.fake = FakeBrowser()
        self.session = session(self.fake)
        self.addCleanup(self.fake.close)

    def paused(self, request_id, method, url, **request):
        self.fake.emit('Fetch.requestPaused', {'requestId': request_id, 'request': {'method': method, 'url': url, **request}}, 'page')

    def verdicts(self, count):
        self.fake.wait_for('Fetch.failRequest', 0)
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            found = {m['params']['requestId']: m for m in self.fake.calls('Fetch.failRequest') + self.fake.calls('Fetch.continueRequest')}
            if len(found) >= count:
                return found
            time.sleep(0.01)
        self.fail('browser never got a verdict for every paused request')

    def test_the_page_is_fenced_before_it_runs_and_downloads_are_denied(self):
        methods = [message['method'] for message in self.fake.sent]
        self.assertLess(methods.index('Fetch.enable'), methods.index('Page.enable'))
        fetch = self.fake.calls('Fetch.enable')[0]
        self.assertEqual((fetch['sessionId'], fetch['params']['patterns']), ('page', [{'urlPattern': '*', 'requestStage': 'Request'}]))
        self.assertEqual(self.fake.calls('Browser.setDownloadBehavior')[0]['params'], {'behavior': 'deny'})
        self.assertEqual([m['params'] for m in self.fake.calls('Target.closeTarget')], [{'targetId': 'stray'}])

    def test_requests_to_non_lab_origins_fail_in_the_browser(self):
        self.paused('r1', 'GET', 'http://example.com/beacon')
        self.paused('r2', 'GET', 'http://127.0.0.1:9222/json/version')
        self.paused('r3', 'GET', 'http://127.0.0.1:41001/view?q=x')
        found = self.verdicts(3)
        for request_id in ('r1', 'r2'):
            self.assertEqual(found[request_id]['method'], 'Fetch.failRequest')
            self.assertEqual(found[request_id]['params']['errorReason'], 'BlockedByClient')
            self.assertEqual(found[request_id]['sessionId'], 'page')
        self.assertEqual(found['r3']['method'], 'Fetch.continueRequest')
        self.assertEqual(found['r3']['params'], {'requestId': 'r3'})
        self.assertEqual(self.session.blocked, 2)

    def test_arkime_searches_leave_the_browser_with_the_case_tag(self):
        self.paused('s1', 'POST', ARKIME + '/api/sessions', postData='{"expression":"protocols == dns","date":-1}')
        entries = [{'bytes': base64.b64encode(b'{"expression":"port.dst == 53"}').decode()}]
        self.paused('s2', 'POST', ARKIME + '/api/spiview', hasPostData=True, postDataEntries=entries)
        self.paused('s3', 'POST', ARKIME + '/api/sessions', hasPostData=True)
        self.paused('s4', 'POST', ARKIME + '/api/sessions/addtags', postData='tags=x')
        found = self.verdicts(4)
        sent = {key: json.loads(base64.b64decode(found[key]['params']['postData'])) for key in ('s1', 's2')}
        self.assertEqual(sent['s1']['expression'], '(protocols == dns) && ' + TAG)
        self.assertEqual((sent['s1']['startTime'], sent['s1']['stopTime']), (START, STOP))
        self.assertEqual(sent['s2']['expression'], '(port.dst == 53) && ' + TAG)
        self.assertEqual(query(found['s1']['params']['url'])['expression'], TAG)
        self.assertEqual([found[key]['method'] for key in ('s3', 's4')], ['Fetch.failRequest'] * 2)

    def test_popups_close_and_child_frames_are_fenced_before_they_run(self):
        self.fake.emit('Target.targetCreated', {'targetInfo': {'targetId': 'popup', 'type': 'page'}})
        self.fake.emit('Target.attachedToTarget', {'sessionId': 'child', 'targetInfo': {'type': 'iframe'}}, 'page')
        self.fake.wait_for('Runtime.runIfWaitingForDebugger', 1)
        self.assertIn({'targetId': 'popup'}, [m['params'] for m in self.fake.calls('Target.closeTarget')])
        child = [m['method'] for m in self.fake.sent if m.get('sessionId') == 'child']
        self.assertEqual(child[0], 'Fetch.enable')
        self.assertLess(child.index('Fetch.enable'), child.index('Runtime.runIfWaitingForDebugger'))


class ToolTests(unittest.TestCase):
    def setUp(self):
        self.lab = LabStub()
        self.addCleanup(self.lab.close)
        self.runtime = Runtime(self.lab.url)
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.addCleanup(lab_browser.shutdown)

    def call(self, fake=None, **arguments):
        if fake is not None and not hasattr(fake, 'session'):
            fake.session = session(fake, self.lab.url, self.root)
        start = patch.object(lab_browser, '_start', return_value=fake.session) if fake else \
            patch.object(lab_browser, '_start', side_effect=AssertionError('no browser may start'))
        with start:
            return lab_browser.call({'case_id': CASE, **arguments}, runtime=self.runtime, state_dir='analyst-state',
                                    profile='framework-researcher', browser_root=self.root)

    def test_refused_without_a_running_lab_or_for_another_case(self):
        self.runtime.state = 'stopped'
        self.assertEqual(self.call(action='open', page='arkime_sessions')['error'], 'owned_vm_not_running')
        self.runtime.state = 'running'
        result = lab_browser.call({'case_id': 'dns-lab-001', 'action': 'snapshot'}, runtime=self.runtime,
                                  state_dir='analyst-state', profile=ANALYST, browser_root=self.root)
        self.assertEqual(result['error'], 'case_mismatch')
        self.assertEqual(self.call(action='snapshot', **{'case_id': None})['error'], 'explicit_case_id_required')
        self.assertFalse((self.root / 'audit.jsonl').exists())

    def test_bad_arguments_never_reach_the_lab(self):
        for arguments in ({'action': 'navigate'}, {'action': 'open', 'page': 'https://example.com'},
                          {'action': 'open', 'page': 'lab_console', 'expression': 'x'},
                          {'action': 'open', 'page': 'arkime_sessions', 'expression': 'a) || (b'},
                          {'action': 'click'}, {'action': 'click', 'ref': 'e0'}, {'action': 'click', 'ref': '#search'},
                          {'action': 'type', 'ref': 'e1', 'text': 'x' * 201}, {'action': 'type', 'ref': 'e1', 'text': 'a\nb'},
                          {'action': 'type', 'ref': 'e1', 'text': 'x', 'submit': 'yes'},
                          {'action': 'press', 'key': 'F12'}, {'action': 'scroll', 'direction': 'left'},
                          {'action': 'snapshot', 'url': 'http://example.com'}):
            with self.subTest(arguments=arguments):
                self.assertFalse(self.call(**arguments)['ok'])
        self.assertEqual(self.runtime.calls, [])

    def test_open_lands_on_the_lab_page_and_snapshot_refs_map_to_backend_nodes(self):
        fake = FakeBrowser()
        result = self.call(fake, action='open', page='arkime_sessions', expression='protocols == dns')
        self.assertTrue(result['ok'], result)
        navigated = fake.calls('Page.navigate')[-1]['params']['url']
        self.assertTrue(navigated.startswith(ARKIME + '/sessions?'))
        self.assertEqual(query(navigated), {'expression': 'protocols == dns', 'startTime': str(START), 'stopTime': str(STOP)})
        page = result['result']
        self.assertEqual(page['url'], navigated)
        self.assertEqual(page['elements'], [
            {'ref': 'e1', 'role': 'link', 'name': 'Sessions'},
            {'ref': 'e2', 'role': 'textbox', 'name': 'Search', 'value': 'ip.dst == 10.0.0.1', 'focused': True},
            {'ref': 'e3', 'role': 'button', 'name': 'Go'}])
        self.assertEqual(page['text'], 'Showing 1 - 50 of 2,849 entries')
        self.call(fake, action='click', ref='e2')
        self.assertEqual(fake.calls('DOM.resolveNode')[-1]['params'], {'backendNodeId': 12})

    def test_click_moves_the_pointer_along_a_path_and_presses_inside_the_element(self):
        fake = FakeBrowser()
        self.call(fake, action='snapshot')
        self.assertTrue(self.call(fake, action='click', ref='e3')['ok'])
        self.assertEqual(fake.calls('DOM.scrollIntoViewIfNeeded')[-1]['params'], {'backendNodeId': 14})
        mouse = [m['params'] for m in fake.calls('Input.dispatchMouseEvent')]
        moves, (press, release) = mouse[:-2], mouse[-2:]
        self.assertGreaterEqual(len(moves), 12)
        self.assertTrue(all(m['type'] == 'mouseMoved' for m in moves))
        self.assertEqual((press['type'], release['type']), ('mousePressed', 'mouseReleased'))
        self.assertEqual((press['x'], press['y']), (release['x'], release['y']))
        self.assertEqual((moves[-1]['x'], moves[-1]['y']), (press['x'], press['y']))
        self.assertTrue(100 < press['x'] < 200 and 110 < press['y'] < 130, press)
        self.assertEqual(self.call(fake, action='click', ref='e9')['error'], 'unknown_ref')

    def test_a_covered_or_disabled_element_is_not_clicked(self):
        fake = FakeBrowser()
        self.call(fake, action='snapshot')
        fake.replies['Runtime.callFunctionOn'] = {'result': {'value': {'ok': False, 'reason': 'covered'}}}
        ticks = iter(range(0, 1000))
        clock = types.SimpleNamespace(monotonic=lambda: next(ticks), time=time.time, sleep=time.sleep)
        with patch.object(lab_browser, 'time', clock):
            result = self.call(fake, action='click', ref='e3')
        self.assertEqual((result['error'], result['detail']), ('element_not_actionable', 'covered'))
        self.assertEqual(fake.calls('Input.dispatchMouseEvent'), [])

    def test_type_replaces_the_field_text_key_by_key_and_can_submit(self):
        fake = FakeBrowser()
        self.call(fake, action='snapshot')
        self.assertTrue(self.call(fake, action='type', ref='e2', text='port == 53', submit=True)['ok'])
        keys = [m['params'] for m in fake.calls('Input.dispatchKeyEvent')]
        self.assertEqual(keys[0]['commands'], ['selectAll'])
        self.assertEqual(''.join(k['text'] for k in keys if k['type'] == 'keyDown'), 'port == 53\r')
        self.assertEqual(keys[-1], {'type': 'keyUp', 'key': 'Enter', 'code': 'Enter', 'windowsVirtualKeyCode': 13})
        audit = json.loads((self.root / 'audit.jsonl').read_text().splitlines()[-1])
        self.assertEqual({key: audit[key] for key in ('profile', 'case_id', 'action', 'ref', 'text', 'submit', 'ok')},
                         {'profile': 'framework-researcher', 'case_id': CASE, 'action': 'type', 'ref': 'e2',
                          'text': 'port == 53', 'submit': True, 'ok': True})
        self.assertEqual(audit['blocked'], 0)
        self.assertEqual(json.loads((self.root / 'session.json').read_text())['refs']['e2'], 12)

    def audit(self):
        return json.loads((self.root / 'audit.jsonl').read_text().splitlines()[-1])

    def test_demo_open_loads_the_page_unfiltered_and_types_the_search_into_its_search_box(self):
        for page, name, value, unfiltered in (
                ('arkime_sessions', 'expression', 'protocols == dns', ARKIME + '/sessions?startTime=%d&stopTime=%d' % (START, STOP)),
                ('lab_console', 'q', 'event.code:4688', self.lab.url + '/view')):
            with self.subTest(page=page):
                lab_browser.shutdown()
                fake = FakeBrowser()
                fake.session = session(fake, self.lab.url, self.root, demo=lab_browser.Demo('on'))
                result = self.call(fake, action='open', page=page, **{name: value})
                self.assertTrue(result['ok'], result)
                self.assertEqual([m['params']['url'] for m in fake.calls('Page.navigate')], [unfiltered])
                self.assertEqual(fake.calls('DOM.resolveNode')[-1]['params'], {'backendNodeId': 12})
                mouse = [m['params']['type'] for m in fake.calls('Input.dispatchMouseEvent')]
                self.assertGreaterEqual(mouse.count('mouseMoved'), 12)
                self.assertEqual(mouse[-2:], ['mousePressed', 'mouseReleased'])
                keys = [m['params'] for m in fake.calls('Input.dispatchKeyEvent')]
                self.assertEqual(keys[0]['commands'], ['selectAll'])
                self.assertEqual(''.join(k['text'] for k in keys if k['type'] == 'keyDown'), value + '\r')
                self.assertEqual(keys[-1]['key'], 'Enter')
                self.assertEqual({key: result['result'][key] for key in ('action', 'title', 'url', 'blocked_requests')},
                                 {'action': 'open', 'title': 'Sessions', 'url': unfiltered, 'blocked_requests': 0})
                self.assertEqual(result['result']['elements'][1]['name'], 'Search')
                self.assertEqual(result['result']['text'], 'Showing 1 - 50 of 2,849 entries')
                audit = self.audit()
                self.assertEqual((audit['entered'], audit['demo'], audit['query']), ('typed', 'on', value))

    def test_without_demo_open_puts_the_search_in_the_url_and_types_nothing(self):
        fake = FakeBrowser()
        self.assertTrue(self.call(fake, action='open', page='arkime_sessions', expression='protocols == dns')['ok'])
        self.assertEqual([query(m['params']['url']) for m in fake.calls('Page.navigate')],
                         [{'expression': 'protocols == dns', 'startTime': str(START), 'stopTime': str(STOP)}])
        self.assertEqual(fake.calls('Input.dispatchKeyEvent') + fake.calls('Input.dispatchMouseEvent'), [])
        self.assertEqual((self.audit()['entered'], self.audit()['demo']), ('url', None))
        self.call(fake, action='snapshot')
        self.assertIsNone(self.audit()['entered'])

    def test_demo_open_without_a_search_box_falls_back_to_the_url_and_audits_why(self):
        tree = [ax('1', 'RootWebArea', 'Sessions', 1, children=['2', '3']),
                ax('2', 'link', 'Sessions', 11, parent='1'), ax('3', 'textbox', 'Host', 12, parent='1')]
        fake = FakeBrowser(tree=tree)
        fake.session = session(fake, self.lab.url, self.root, demo=lab_browser.Demo('on'))
        result = self.call(fake, action='open', page='lab_console', q='event.code:4688')
        self.assertTrue(result['ok'], result)
        self.assertEqual([m['params']['url'] for m in fake.calls('Page.navigate')],
                         [self.lab.url + '/view', self.lab.url + '/view?q=event.code%3A4688'])
        self.assertEqual(result['result']['url'], self.lab.url + '/view?q=event.code%3A4688')
        self.assertEqual(fake.calls('Input.dispatchKeyEvent') + fake.calls('Input.dispatchMouseEvent'), [])
        self.assertEqual(self.audit()['entered'], 'fallback:no_search_box')

    def test_results_stay_within_bounds_on_huge_pages(self):
        tree = [ax('root', 'RootWebArea', children=[str(i) for i in range(300)])]
        tree += [ax(str(i), 'button', 'n' * 500, 100 + i, parent='root') for i in range(300)]
        fake = FakeBrowser(tree=tree, text='\u00e9' * 50000)
        result = self.call(fake, action='snapshot')
        self.assertTrue(result['ok'], result)
        page = result['result']
        self.assertLessEqual(len(json.dumps(result, ensure_ascii=True, separators=(',', ':'))), 12 * 1024)
        self.assertTrue(page['elements_truncated'])
        self.assertLessEqual(len(page['elements']), 80)
        self.assertTrue(all(len(element['name']) <= 80 for element in page['elements']))
        self.assertLessEqual(len(page['text']), 3001)

    def test_a_page_that_left_the_lab_is_blanked_and_reported(self):
        fake = FakeBrowser()
        self.call(fake, action='snapshot')
        fake.url = 'chrome-error://chromewebdata/'
        result = self.call(fake, action='snapshot')
        self.assertEqual(result['error'], 'navigation_refused')
        self.assertEqual(fake.calls('Page.navigate')[-1]['params'], {'url': 'about:blank'})

    def test_launch_flags_fence_the_browser_to_the_lab_ports_and_a_private_profile(self):
        args = lab_browser.browser_args('edge', Path('state') / 'user-data', scope())
        self.assertIn('--proxy-server=http://127.0.0.1:1', args)
        self.assertIn('--proxy-bypass-list=<-loopback>;127.0.0.1:41001;127.0.0.1:41002', args)
        self.assertIn('--user-data-dir=' + str(Path('state') / 'user-data'), args)
        self.assertIn('--remote-debugging-address=127.0.0.1', args)
        self.assertIn('--headless=new', args)
        self.assertNotIn('--disable-features=CalculateNativeWinOcclusion', args)
        headed = lab_browser.browser_args('edge', Path('u'), scope(), window=(10, 20, 1280, 900))
        self.assertNotIn('--headless=new', headed)
        self.assertEqual(headed[-1], 'about:blank')
        for flag in ('--window-position=10,20', '--window-size=1280,900',
                     '--disable-features=CalculateNativeWinOcclusion', '--disable-backgrounding-occluded-windows'):
            self.assertIn(flag, headed)


class FakeProcess:
    """A launched browser that only announces its DevTools endpoint."""
    pid = 4242

    def __init__(self, args, **_options):
        self.args = args
        user_data = Path(next(arg for arg in args if arg.startswith('--user-data-dir=')).split('=', 1)[1])
        (user_data / 'DevToolsActivePort').write_text('9222\n/devtools/browser/fake\n', encoding='ascii')

    def poll(self):
        return None

    def wait(self, _timeout=None):
        return 0

    def kill(self):
        pass


class DemoModeTests(unittest.TestCase):
    """The operator's demo.json beside the bots' browser profiles decides headed mode, the cursor overlay and the page scale."""

    def setUp(self):
        self.lab = LabStub()
        self.addCleanup(self.lab.close)
        environment = patch.dict(os.environ)
        environment.start()
        self.addCleanup(environment.stop)
        os.environ.pop('HUNT_LAB_BROWSER_HEADED', None)

    def launch(self, marker=None):
        """One real lab_browser call through the launch path; returns the browser's flags, CDP traffic and audit line."""
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        browsers = Path(temp.name) / 'hunt-lab-browser'
        if marker is not None:
            browsers.mkdir()
            (browsers / 'demo.json').write_text(marker if isinstance(marker, str) else json.dumps(marker), encoding='utf-8')
        fake, launched = FakeBrowser(), []

        def popen(args, **options):
            launched.append(FakeProcess(args, **options))
            return launched[-1]

        with patch.object(lab_browser, '_browser_executable', return_value='edge'), \
                patch.object(lab_browser.subprocess, 'Popen', popen), \
                patch.object(lab_browser, '_WebSocket', lambda _url: fake):
            result = lab_browser.call({'case_id': CASE, 'action': 'snapshot'}, runtime=Runtime(self.lab.url),
                                      state_dir='analyst-state', profile='framework-researcher',
                                      browser_root=browsers / 'framework-researcher')
            lab_browser.shutdown()
        self.assertTrue(result['ok'], result)
        audit = json.loads((browsers / 'framework-researcher' / 'audit.jsonl').read_text().splitlines()[-1])
        return launched[0].args, fake.calls('Page.addScriptToEvaluateOnNewDocument'), audit

    def test_a_browser_is_relaunched_when_the_marker_changes_its_mode(self):
        # The gateway hosts the tool for hours: a browser it launched headless must not be reused,
        # invisibly, after the operator turns demo mode on (and vice versa).
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        browsers = Path(temp.name) / 'hunt-lab-browser'
        browsers.mkdir()
        fake, launched = FakeBrowser(), []

        def popen(args, **options):
            launched.append(FakeProcess(args, **options))
            return launched[-1]

        def snapshot():
            result = lab_browser.call({'case_id': CASE, 'action': 'snapshot'}, runtime=Runtime(self.lab.url),
                                      state_dir='analyst-state', profile='framework-researcher',
                                      browser_root=browsers / 'framework-researcher')
            self.assertTrue(result['ok'], result)

        with patch.object(lab_browser, '_browser_executable', return_value='edge'), \
                patch.object(lab_browser.subprocess, 'Popen', popen), \
                patch.object(lab_browser, '_WebSocket', lambda _url: fake):
            self.addCleanup(lab_browser.shutdown)
            snapshot()
            snapshot()
            self.assertEqual(len(launched), 1)
            (browsers / 'demo.json').write_text(json.dumps({'headed': True, 'window': [0, 0, 1280, 1080]}), encoding='utf-8')
            snapshot()
            (browsers / 'demo.json').write_text(json.dumps({'window': [0, 0, 1280, 1080], 'scale': 1.5}), encoding='utf-8')
            snapshot()
            snapshot()
            (browsers / 'demo.json').unlink()
            snapshot()
            lab_browser.shutdown()
        self.assertEqual(len(launched), 4)
        self.assertIn('--headless=new', launched[0].args)
        self.assertIn('--window-position=0,0', launched[1].args)
        self.assertNotIn('--force-device-scale-factor=1.5', launched[1].args)
        self.assertIn('--force-device-scale-factor=1.5', launched[2].args)
        self.assertIn('--headless=new', launched[3].args)

    def test_a_browser_left_by_a_restarted_host_is_reused_only_at_the_marker_scale(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        browsers = Path(temp.name) / 'hunt-lab-browser'
        browsers.mkdir()
        sockets, launched = [], []

        def socket(_url):
            sockets.append(FakeBrowser())
            self.addCleanup(sockets[-1].close)
            return sockets[-1]

        def popen(args, **options):
            launched.append(FakeProcess(args, **options))
            return launched[-1]

        def snapshot_after_host_restart(scale):
            (browsers / 'demo.json').write_text(json.dumps({'scale': scale}), encoding='utf-8')
            lab_browser._SESSIONS.clear()
            result = lab_browser.call({'case_id': CASE, 'action': 'snapshot'}, runtime=Runtime(self.lab.url),
                                      state_dir='analyst-state', profile='framework-researcher',
                                      browser_root=browsers / 'framework-researcher')
            self.assertTrue(result['ok'], result)

        with patch.object(lab_browser, '_browser_executable', return_value='edge'), \
                patch.object(lab_browser.subprocess, 'Popen', popen), \
                patch.object(lab_browser, '_WebSocket', socket), patch.object(lab_browser, '_owned', return_value=True):
            self.addCleanup(lab_browser.shutdown)
            snapshot_after_host_restart(1.5)
            snapshot_after_host_restart(1.5)
            self.assertEqual(len(launched), 1)
            snapshot_after_host_restart(1.25)
        self.assertEqual(len(launched), 2)
        self.assertIn('--force-device-scale-factor=1.25', launched[1].args)

    def test_without_a_marker_the_browser_is_headless_and_draws_no_cursor(self):
        args, scripts, audit = self.launch()
        self.assertIn('--headless=new', args)
        self.assertFalse(any(arg.startswith('--window-position=') for arg in args))
        self.assertEqual((scripts, audit['demo']), ([], None))
        os.environ['HUNT_LAB_BROWSER_HEADED'] = '1'
        args, scripts, audit = self.launch()
        self.assertNotIn('--headless=new', args)
        self.assertIn('--window-position=0,0', args)
        self.assertEqual((scripts, audit['demo']), ([], None))

    def test_a_valid_marker_opens_a_placed_window_with_the_cursor_overlay(self):
        args, scripts, audit = self.launch({'headed': True, 'window': [100, -40, 1280, 900], 'cursor': True})
        self.assertNotIn('--headless=new', args)
        self.assertIn('--window-position=100,-40', args)
        self.assertIn('--window-size=1280,900', args)
        self.assertFalse(any(arg.startswith('--force-device-scale-factor') for arg in args))
        self.assertEqual(audit['demo'], 'on')
        self.assertEqual(len(scripts), 1)
        self.assertEqual(scripts[0]['sessionId'], 'page')
        self.assertEqual(scripts[0]['params']['worldName'], 'hunt-lab-cursor')
        self.assertTrue(scripts[0]['params']['runImmediately'])
        overlay = scripts[0]['params']['source']
        self.assertIn('pointer-events:none!important', overlay)
        self.assertIn("attachShadow({mode: 'closed'})", overlay)
        self.assertNotRegex(overlay, r'https?:|url\(|@import')
        args, scripts, _audit = self.launch({})
        self.assertIn('--window-position=0,0', args)
        self.assertIn('--window-size=1600,1000', args)
        self.assertEqual(len(scripts), 1)
        args, scripts, _audit = self.launch({'headed': False})
        self.assertIn('--headless=new', args)
        self.assertEqual(len(scripts), 1)

    def test_a_marker_scale_renders_pages_larger_in_a_window_of_the_same_screen_size(self):
        # Chromium sizes windows in device-independent pixels, so a forced scale factor divides them.
        args, scripts, audit = self.launch({'window': [200, 100, 1280, 1080], 'scale': 1.5})
        self.assertEqual((audit['demo'], len(scripts)), ('on', 1))
        self.assertNotIn('--headless=new', args)
        for flag in ('--force-device-scale-factor=1.5', '--window-position=133,67', '--window-size=853,720'):
            self.assertIn(flag, args)
        args, _scripts, _audit = self.launch({'headed': False, 'scale': 2})
        for flag in ('--headless=new', '--force-device-scale-factor=2', '--window-size=683,430'):
            self.assertIn(flag, args)
        args, _scripts, _audit = self.launch({'scale': 1})
        for flag in ('--force-device-scale-factor=1', '--window-size=1600,1000'):
            self.assertIn(flag, args)

    def test_an_invalid_marker_is_ignored_whole_and_audited(self):
        for marker in ({'headed': 'yes'}, {'cursor': 1}, {'headed': True, 'record': True}, {'window': [0, 0, 1600]},
                       {'window': [0, 0, True, 1000]}, {'window': [0, 0, 1600.0, 1000]}, {'window': [0, 0, 50, 50]},
                       {'window': '0,0,1600,1000'}, {'scale': 0.99}, {'scale': 2.01}, {'scale': '1.5'},
                       {'scale': True}, {'scale': None}, {'scale': [1.5]}, '{"scale": NaN}', '{"scale": Infinity}',
                       '[]', 'headed', '{"headed": true', ' ' * 2000 + '{}'):
            with self.subTest(marker=marker):
                args, scripts, audit = self.launch(marker)
                self.assertIn('--headless=new', args)
                self.assertFalse(any(arg.startswith(('--window-position=', '--force-device-scale-factor')) for arg in args))
                self.assertEqual((scripts, audit['demo']), ([], 'invalid_marker'))

    def test_the_cursor_overlay_and_page_scale_leave_actionability_and_input_unchanged(self):
        # Input, hit tests and the overlay all work in CSS pixels, which a device scale factor leaves alone.
        traffic = []
        for demo in (lab_browser.DEMO_OFF, lab_browser.Demo('on', None, True), lab_browser.Demo('on', None, True, 1.5)):
            fake = FakeBrowser()
            self.addCleanup(fake.close)
            browser = session(fake, demo=demo)
            browser.run(lab_browser.parse_command({'action': 'snapshot'}))
            browser.run(lab_browser.parse_command({'action': 'click', 'ref': 'e3'}))
            traffic.append([(m['method'], m['params']) for m in fake.sent
                            if m['method'] in ('Runtime.callFunctionOn', 'Input.dispatchMouseEvent')])
        self.assertGreater(len(traffic[0]), 12)
        self.assertEqual(traffic[0], traffic[1])
        self.assertEqual(traffic[0], traffic[2])


if __name__ == '__main__':
    unittest.main()

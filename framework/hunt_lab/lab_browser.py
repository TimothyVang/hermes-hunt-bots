"""lab_browser host tool: a dedicated real browser on the lab's own web tools (Kibana Discover, Arkime, lab console).

Bots address elements by accessibility-tree refs and act through CDP Input events with human-like
pointer paths and typing cadence. Enforcement runs inside the browser: every request pauses in CDP
Fetch and browser_policy decides it; launch flags add a CDP-independent proxy fence that admits only
the lab's own ports. Nothing here reads cookies, credentials or answer keys.
"""
from __future__ import annotations

import atexit
import base64
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
import itertools
import json
import logging
import os
from pathlib import Path
import random
import re
import shutil
import subprocess
import threading
import time
from urllib import parse, request

from . import humanize
from .actionability import CLICK_ACTIONABLE
from .browser_policy import (KIBANA_INDEX, LabScope, Refused, check_expression, decide, document_allowed,
                             kibana_window, origin)
from .query_adapter import QueryFailure, _case_id, _failure, _lab_base, _schema, endpoint


@dataclass(frozen=True)
class Page:
    """One page a bot may open: which lab origin serves it, its path, the open argument that carries its search,
    the accessible name of the search box demo mode types that search into, and, for a page that keeps working
    after the network goes quiet, a script that is true once it has settled."""
    origin: str
    path: str
    query: str
    box: str
    ready: str | None = None


PAGES = {
    # Kibana runs its bundles between requests, so a quiet network alone does not mean Discover has its hits.
    'kibana_discover': Page('kibana', '/app/discover', 'q', 'Start typing to search and filter the discover page',
                            "location.pathname !== '/app/discover' || "
                            "!!document.querySelector('[data-test-subj=globalLoadingIndicator-hidden]') && "
                            "!!document.querySelector('[data-test-subj=discoverQueryHits],[data-test-subj=discoverNoResults]')"),
    'arkime_sessions': Page('arkime', '/sessions', 'expression', 'Search'),
    'arkime_spiview': Page('arkime', '/spiview', 'expression', 'Search'),
    'lab_console': Page('lab', '/view', 'q', 'Search'),
}
KEYS = {
    'Enter': {'key': 'Enter', 'code': 'Enter', 'windowsVirtualKeyCode': 13, 'text': '\r'},
    'Tab': {'key': 'Tab', 'code': 'Tab', 'windowsVirtualKeyCode': 9},
    'Escape': {'key': 'Escape', 'code': 'Escape', 'windowsVirtualKeyCode': 27},
    'Backspace': {'key': 'Backspace', 'code': 'Backspace', 'windowsVirtualKeyCode': 8},
    'ArrowDown': {'key': 'ArrowDown', 'code': 'ArrowDown', 'windowsVirtualKeyCode': 40},
    'ArrowUp': {'key': 'ArrowUp', 'code': 'ArrowUp', 'windowsVirtualKeyCode': 38},
    'PageDown': {'key': 'PageDown', 'code': 'PageDown', 'windowsVirtualKeyCode': 34},
    'PageUp': {'key': 'PageUp', 'code': 'PageUp', 'windowsVirtualKeyCode': 33},
    'Home': {'key': 'Home', 'code': 'Home', 'windowsVirtualKeyCode': 36},
    'End': {'key': 'End', 'code': 'End', 'windowsVirtualKeyCode': 35},
}
# action: (required arguments, optional arguments) besides case_id and action.
ACTIONS = {
    'open': ({'page'}, {'expression', 'q'}),
    'snapshot': (set(), set()),
    'click': ({'ref'}, set()),
    'type': ({'ref', 'text'}, {'submit'}),
    'press': ({'key'}, set()),
    'scroll': ({'direction'}, set()),
    'read': ({'ref'}, set()),
}
# Native <select> options stay in the tree while closed; their combobox carries the chosen value.
INTERACTIVE_ROLES = frozenset({
    'button', 'link', 'textbox', 'searchbox', 'combobox', 'checkbox', 'radio', 'switch', 'slider',
    'spinbutton', 'listbox', 'menuitem', 'menuitemcheckbox', 'menuitemradio', 'tab', 'treeitem',
})
SEARCH_ROLES = frozenset({'textbox', 'searchbox', 'combobox'})
ICON_GLYPHS = re.compile('[\ue000-\uf8ff]')
FLAGS = ('disabled', 'focused', 'checked', 'expanded', 'selected')
REF = re.compile(r'e[1-9][0-9]{0,3}')
REASON = re.compile(r'[a-z_]{1,32}')
MAX_RESULT = 12 * 1024
MAX_ELEMENTS = 80
MAX_LABEL = 80
MAX_TEXT = 3000
MAX_READ = 4000
MAX_TYPE = 200
MAX_QUERY = 500
IDLE_SECONDS = 600
VIEWPORT = (1366, 860)
CTRL = 2
# Characters Kibana's rison URL state uses unescaped; everything else in it is percent-encoded.
RISON_SAFE = "!'(),:*@$-._~/"
_LOG = logging.getLogger(__name__)
STATE_FILE = 'session.json'
AUDIT_FILE = 'audit.jsonl'
FETCH_ALL = {'patterns': [{'urlPattern': '*', 'requestStage': 'Request'}]}
AUTO_ATTACH = {'autoAttach': True, 'waitForDebuggerOnStart': True, 'flatten': True}
READ_TEXT = ('function () { if (this.type === "password") return ""; '
             'return String(this.innerText || this.value || this.textContent || ""); }')
DEMO_FILE = 'demo.json'
DEMO_MAX_BYTES = 1024
DEMO_WINDOW = (0, 0, 1600, 1000)
CURSOR_WORLD = 'hunt-lab-cursor'
# Demo only: draws the CDP pointer, which Chrome never paints. It runs in its own world so page scripts
# cannot see it, sits in a closed shadow root so page CSS cannot hide or restyle it, and is
# pointer-events:none so elementFromPoint, the actionability check and real input pass through it.
CURSOR_OVERLAY = r"""(() => {
  if (window.top !== window) return;
  const host = document.createElement('hunt-lab-cursor');
  host.setAttribute('aria-hidden', 'true');
  host.style.cssText = 'all:initial!important;display:block!important;position:fixed!important;' +
    'left:0!important;top:0!important;width:0!important;height:0!important;overflow:visible!important;' +
    'z-index:2147483647!important;pointer-events:none!important';
  const shadow = host.attachShadow({mode: 'closed'});
  shadow.innerHTML = '<style>*{pointer-events:none}i,svg{position:fixed;left:0;top:0;opacity:0}' +
    'i{width:28px;height:28px;margin:-16px;border:2px solid #f80;border-radius:50%;background:#fc08}</style>' +
    '<i></i><svg width="22" height="22" viewBox="0 0 22 22"><path d="M2 2v17l4.5-4.5 3 6.5 3-1.4-3-6.4H16z" ' +
    'fill="#111" stroke="#fff" stroke-width="1.5" stroke-linejoin="round"/></svg>';
  const [ring, arrow] = shadow.querySelectorAll('i, svg');
  const follow = event => {
    if (!host.isConnected && document.documentElement) {
      document.documentElement.append(host);
      try { host.popover = 'manual'; host.showPopover(); } catch (error) {}
    }
    arrow.style.opacity = '1';
    arrow.style.transform = `translate(${event.clientX - 2}px, ${event.clientY - 2}px)`;
  };
  addEventListener('mousemove', follow, {capture: true, passive: true});
  addEventListener('mousedown', event => {
    follow(event);
    ring.style.left = event.clientX + 'px';
    ring.style.top = event.clientY + 'px';
    ring.animate([{opacity: 1, scale: 0.4}, {opacity: 0, scale: 1.5}], {duration: 450, easing: 'ease-out'});
  }, {capture: true, passive: true});
})();"""

SCHEMA = _schema(
    'lab_browser',
    'Drive a real browser on the lab\'s own web tools: Kibana Discover over the case\'s events, Arkime\'s '
    'Sessions and SPI View pages, and the lab console. open a page, read the returned snapshot of interactive '
    'elements (refs e1, e2, ...), then click, type into or read an element by ref, press a key, or scroll; the '
    'pointer and keyboard move like a person\'s. Refs come from the latest snapshot only. type replaces the '
    'field\'s text; submit=true presses Enter after it. In Kibana Discover every search is held to the loaded '
    'case\'s events and its time window; saving, sharing, alerts, settings, Dev Tools and every other Kibana app '
    'are blocked. Every Arkime search is scoped to the loaded case (tag case:<id>) and its time window, and '
    'Arkime writes, exports, packets and admin pages are blocked. Requests to any other origin fail. Each result '
    'has the page title, URL, interactive elements, a visible-text excerpt and how many requests were blocked.',
    {'action': {'type': 'string', 'enum': list(ACTIONS)},
     'page': {'type': 'string', 'enum': list(PAGES), 'description': 'open only.'},
     'expression': {'type': 'string', 'maxLength': MAX_QUERY,
                    'description': 'open an Arkime page with this search expression already applied.'},
     'q': {'type': 'string', 'maxLength': MAX_QUERY,
           'description': 'open kibana_discover or lab_console with this Lucene search (the same syntax as '
                          'elastic_search).'},
     'ref': {'type': 'string', 'pattern': '^e[1-9][0-9]{0,3}$', 'description': 'Element ref from the latest snapshot.'},
     'text': {'type': 'string', 'maxLength': MAX_TYPE, 'description': 'type only.'},
     'submit': {'type': 'boolean', 'description': 'type only: press Enter after typing.'},
     'key': {'type': 'string', 'enum': list(KEYS)},
     'direction': {'type': 'string', 'enum': ['up', 'down']}},
    ('action',))


class CdpError(Exception):
    """The browser rejected one CDP command; args[0] is the method."""


@dataclass(frozen=True)
class Command:
    action: str
    page: str | None = None
    query: str = ''
    ref: str | None = None
    text: str = ''
    submit: bool = False
    key: str | None = None
    direction: str | None = None


@dataclass(frozen=True)
class Demo:
    """The operator's demo.json marker as parsed: its audit label, the headed window, the cursor overlay, and the
    forced device scale factor (None keeps the system's)."""
    marker: str | None = None
    window: tuple[int, int, int, int] | None = None
    cursor: bool = False
    scale: float | None = None


DEMO_OFF = Demo()
DEMO_INVALID = Demo('invalid_marker')


def _plain(value, limit):
    return isinstance(value, str) and len(value) <= limit and not any(ord(c) < 32 or ord(c) == 127 for c in value)


def _rison(value):
    """A rison string literal: quoted, with ! and ' escaped by !."""
    return "'" + value.replace('!', '!!').replace("'", "!'") + "'"


def parse_command(arguments):
    """Validate one tool call's arguments into a Command, before anything touches the lab."""
    if not isinstance(arguments, dict):
        raise QueryFailure('invalid_arguments')
    given = {name: value for name, value in arguments.items() if value is not None and name != 'case_id'}
    action = given.pop('action', None)
    if action not in ACTIONS:
        raise QueryFailure('invalid_action')
    required, optional = ACTIONS[action]
    if required - set(given) or set(given) - required - optional:
        raise QueryFailure('invalid_arguments')
    page = given.get('page')
    if page is not None and page not in PAGES:
        raise QueryFailure('invalid_page')
    query_name = PAGES[page].query if page else 'expression'
    if set(given) & ({'expression', 'q'} - {query_name}):
        raise QueryFailure('invalid_arguments')
    query = given.get(query_name, '')
    if not _plain(query, MAX_QUERY):
        raise QueryFailure('invalid_query')
    if query_name == 'expression':
        try:
            query = check_expression(query)
        except Refused:
            raise QueryFailure('invalid_expression') from None
    ref = given.get('ref')
    if ref is not None and not (isinstance(ref, str) and REF.fullmatch(ref)):
        raise QueryFailure('invalid_ref')
    text = given.get('text', '')
    if not _plain(text, MAX_TYPE):
        raise QueryFailure('invalid_text')
    submit = given.get('submit', False)
    key = given.get('key')
    direction = given.get('direction')
    if type(submit) is not bool or direction not in (None, 'up', 'down'):
        raise QueryFailure('invalid_arguments')
    if key is not None and key not in KEYS:
        raise QueryFailure('key_not_allowed')
    return Command(action, page, query.strip(), ref, text, submit, key, direction)


def _clip(value, limit):
    return ' '.join(ICON_GLYPHS.sub(' ', str(value)).split())[:limit] if value is not None else ''


def _excerpt(text, limit):
    lines = (' '.join(line.split()) for line in str(text or '').splitlines())
    text = '\n'.join(line for line in lines if line)
    return text if len(text) <= limit else text[:limit] + '…'


def _ax(node, key):
    value = node.get(key)
    return value.get('value') if isinstance(value, dict) else None


def _tree_order(nodes):
    """getFullAXTree lists nodes out of document order; walk childIds from the root instead."""
    by_id = {node.get('nodeId'): node for node in nodes}
    stack = [node for node in reversed(nodes) if node.get('parentId') not in by_id]
    seen = set()
    while stack:
        node = stack.pop()
        if id(node) in seen:
            continue
        seen.add(id(node))
        yield node
        stack.extend(by_id[child] for child in reversed(node.get('childIds') or ()) if child in by_id)


def build_snapshot(nodes):
    """Interactive elements of a CDP accessibility tree in document order: ([element], {ref: backend node id}, truncated)."""
    elements, refs = [], {}
    for node in _tree_order(nodes):
        role, backend = _ax(node, 'role'), node.get('backendDOMNodeId')
        if node.get('ignored') or role not in INTERACTIVE_ROLES or type(backend) is not int:
            continue
        if len(elements) == MAX_ELEMENTS:
            return elements, refs, True
        ref = 'e%d' % (len(elements) + 1)
        refs[ref] = backend
        element = {'ref': ref, 'role': role, 'name': _clip(_ax(node, 'name'), MAX_LABEL)}
        value = _ax(node, 'value')
        if value not in (None, ''):
            element['value'] = _clip(value, MAX_LABEL)
        for prop in node.get('properties') or ():
            if prop.get('name') in FLAGS and (prop.get('value') or {}).get('value') in (True, 'true'):
                element[prop['name']] = True
        elements.append(element)
    return elements, refs, False


def _post_data(req):
    """A paused request's body as text: '' when it has none, None when it has one that cannot be read.
    Chrome moves larger bodies into base64 postDataEntries."""
    if 'postData' in req:
        return req['postData']
    entries = req.get('postDataEntries')
    if entries:
        try:
            return b''.join(base64.b64decode(entry.get('bytes', '')) for entry in entries).decode('utf-8')
        except (ValueError, AttributeError):
            return None
    return None if req.get('hasPostData') else ''


class Cdp:
    """Minimal CDP client: one reader thread routes replies to waiting callers and events to a handler."""

    def __init__(self, transport, on_event):
        self._transport, self._on_event = transport, on_event
        self._ids = itertools.count(1)
        self._pending = {}
        self.closed = threading.Event()
        threading.Thread(target=self._read, daemon=True, name='lab-browser-cdp').start()

    def _send(self, message_id, method, params, session):
        message = {'id': message_id, 'method': method, 'params': params or {}}
        if session:
            message['sessionId'] = session
        self._transport.send(json.dumps(message))

    def post(self, method, params=None, session=None):
        self._send(next(self._ids), method, params, session)

    def call(self, method, params=None, session=None, timeout=20):
        message_id = next(self._ids)
        slot = self._pending[message_id] = [threading.Event(), None]
        self._send(message_id, method, params, session)
        if not slot[0].wait(timeout):
            self._pending.pop(message_id, None)
            raise QueryFailure('browser_timeout')
        if slot[1] is None:
            raise QueryFailure('browser_closed')
        if 'error' in slot[1]:
            raise CdpError(method)
        return slot[1].get('result') or {}

    def _read(self):
        try:
            while True:
                raw = self._transport.recv()
                if raw is None:
                    return
                message = json.loads(raw)
                if 'id' in message:
                    slot = self._pending.pop(message['id'], None)
                    if slot:
                        slot[1] = message
                        slot[0].set()
                    continue
                try:
                    self._on_event(message)
                except Exception:
                    # Fail closed: a request whose verdict failed stays paused, never continues.
                    pass
        finally:
            self.closed.set()
            for slot in list(self._pending.values()):
                slot[0].set()

    def close(self):
        self._transport.close()


class _WebSocket:
    def __init__(self, url):
        try:
            from websockets.sync.client import connect
        except ImportError:
            raise QueryFailure('browser_unavailable') from None
        options = {'max_size': 64 * 1024 * 1024, 'open_timeout': 10, 'compression': None}
        try:
            self._ws = connect(url, proxy=None, **options)
        except TypeError:
            # websockets < 15 has no proxy support to disable.
            self._ws = connect(url, **options)
        self._lock = threading.Lock()

    def send(self, text):
        with self._lock:
            self._ws.send(text)

    def recv(self):
        try:
            return self._ws.recv()
        except Exception:
            return None

    def close(self):
        self._ws.close()


class BrowserSession:
    """One bot profile's browser: its main page, element refs, pointer, and the Fetch enforcement."""

    def __init__(self, root, scope, transport, *, ws_url, pid, process=None, state=None, rng=None, sleep=time.sleep,
                 demo=DEMO_OFF, window=None):
        state = state or {}
        self.root, self.scope, self.ws_url, self.pid, self.process = root, scope, ws_url, pid, process
        self.demo = demo
        # The window this browser was launched with (None: headless); a reattach must match it.
        self.window = tuple(window) if window else None
        self.rng = rng or random.Random()
        self.sleep = sleep
        self.lock = threading.Lock()
        self.page_name = state.get('page')
        self.refs = {ref: node for ref, node in (state.get('refs') or {}).items() if REF.fullmatch(ref) and type(node) is int}
        pointer = state.get('pointer')
        self.pointer = tuple(pointer) if isinstance(pointer, list) and len(pointer) == 2 else (
            self.rng.uniform(300, 900), self.rng.uniform(200, 500))
        self.main_target = state.get('main_target')
        self.main_session = None
        self.dead = False
        self.blocked = 0
        self.entered = None
        self.requests = deque(maxlen=40)
        self.last_request = 0.0
        self.last_used = time.time()
        self.loaded = threading.Event()
        self._handlers = {
            'Fetch.requestPaused': self._paused,
            'Target.targetCreated': self._target_created,
            'Target.attachedToTarget': self._attached,
            'Target.targetDestroyed': self._destroyed,
            'Page.loadEventFired': self._loaded,
            'Page.javascriptDialogOpening': self._dialog,
        }
        self.cdp = Cdp(transport, self._event)
        self._attach()

    def _attach(self):
        pages = [info['targetId'] for info in self.cdp.call('Target.getTargets').get('targetInfos', [])
                 if info.get('type') == 'page']
        if self.main_target not in pages:
            self.main_target = pages[0] if pages else self.cdp.call('Target.createTarget', {'url': 'about:blank'})['targetId']
        for target in pages:
            if target != self.main_target:
                self.cdp.post('Target.closeTarget', {'targetId': target})
        self.cdp.call('Target.setDiscoverTargets', {'discover': True})
        self.cdp.call('Browser.setDownloadBehavior', {'behavior': 'deny'})
        self.main_session = self.cdp.call('Target.attachToTarget', {'targetId': self.main_target, 'flatten': True})['sessionId']
        self._page('Fetch.enable', FETCH_ALL)
        self._page('Target.setAutoAttach', AUTO_ATTACH)
        self._page('Page.enable')
        if self.demo.cursor:
            self._page('Page.addScriptToEvaluateOnNewDocument',
                       {'source': CURSOR_OVERLAY, 'worldName': CURSOR_WORLD, 'runImmediately': True})
        if not document_allowed(self.scope, self._evaluate('location.href') or ''):
            self._page('Page.navigate', {'url': 'about:blank'})

    def _event(self, message):
        handler = self._handlers.get(message.get('method'))
        if handler:
            handler(message.get('params') or {}, message.get('sessionId'))

    def _paused(self, params, session):
        req = params.get('request') or {}
        url = req.get('url', '')
        verdict = decide(self.scope, req.get('method', ''), url, _post_data(req))
        self.last_request = time.monotonic()
        record = {'method': str(req.get('method', ''))[:8]}
        source = origin(url)
        if source is not None and source in self.scope.origins:
            record['path'] = parse.urlsplit(url).path[:120]
        if verdict.block:
            self.blocked += 1
            record['blocked'] = verdict.block
            self.cdp.post('Fetch.failRequest', {'requestId': params['requestId'], 'errorReason': 'BlockedByClient'}, session)
        else:
            args = {'requestId': params['requestId']}
            if verdict.url:
                args['url'] = verdict.url
            if verdict.body is not None:
                args['postData'] = base64.b64encode(verdict.body.encode('utf-8')).decode('ascii')
            if verdict.expression is not None:
                record['scoped_expression'] = verdict.expression[:300]
            self.cdp.post('Fetch.continueRequest', args, session)
        self.requests.append(record)

    def _target_created(self, params, _session):
        info = params.get('targetInfo') or {}
        if info.get('type') == 'page' and info.get('targetId') != self.main_target:
            self.cdp.post('Target.closeTarget', {'targetId': info['targetId']})

    def _attached(self, params, session):
        # Frames and workers of the main page start paused; fence them before they run.
        child = params.get('sessionId')
        if session is None or not child:
            return
        self.cdp.post('Fetch.enable', FETCH_ALL, child)
        self.cdp.post('Target.setAutoAttach', AUTO_ATTACH, child)
        self.cdp.post('Runtime.runIfWaitingForDebugger', None, child)

    def _destroyed(self, params, _session):
        if params.get('targetId') == self.main_target:
            self.dead = True

    def _loaded(self, _params, session):
        if session == self.main_session:
            self.loaded.set()

    def _dialog(self, _params, session):
        self.cdp.post('Page.handleJavaScriptDialog', {'accept': False}, session)

    def alive(self):
        return not self.dead and not self.cdp.closed.is_set()

    def origins(self):
        return self.scope.origins

    def _page(self, method, params=None, timeout=20):
        return self.cdp.call(method, params, self.main_session, timeout)

    def _evaluate(self, expression):
        return self._page('Runtime.evaluate', {'expression': expression, 'returnByValue': True}).get('result', {}).get('value')

    def _settle(self, quiet=0.8, limit=10.0):
        self.sleep(0.25)
        deadline = time.monotonic() + limit
        ready = PAGES[self.page_name].ready if self.page_name in PAGES else None
        while time.monotonic() < deadline:
            if time.monotonic() - self.last_request >= quiet and (ready is None or self._evaluate(ready) is True):
                return
            self.sleep(0.05)

    def _location(self):
        values = self._evaluate('[document.title, location.href]')
        title, url = values if isinstance(values, list) and len(values) == 2 else ('', '')
        url = str(url or '')
        if not document_allowed(self.scope, url):
            self._page('Page.navigate', {'url': 'about:blank'})
            raise QueryFailure('navigation_refused')
        return {'title': _clip(title, 200), 'url': url[:500]}

    def run(self, command):
        self.last_used = time.time()
        self.entered = None
        return getattr(self, '_' + command.action)(command)

    def _url(self, page, query):
        spec = PAGES[page]
        if spec.origin == 'arkime':
            params = {'startTime': self.scope.start, 'stopTime': self.scope.stop}
            if query:
                params = {'expression': query, **params}
            return self.scope.arkime_origin + spec.path + '?' + parse.urlencode(params)
        if spec.origin == 'kibana':
            return self._discover_url(query)
        return self.scope.lab_origin + spec.path + ('?' + parse.urlencode({'q': query}) if query else '')

    def _discover_url(self, query):
        """Discover on the case data view and window with only this Lucene query: no filters or columns carried
        over from an earlier search (Discover would otherwise restore them)."""
        start, stop = kibana_window(self.scope)
        globals_ = '(filters:!(),refreshInterval:(pause:!t,value:60000),time:(from:%s,to:%s))' % (_rison(start), _rison(stop))
        app = ('(columns:!(),dataSource:(dataViewId:%s,type:dataView),filters:!(),interval:auto,'
               "query:(language:lucene,query:%s),sort:!(!('@timestamp',desc)))") % (_rison(KIBANA_INDEX), _rison(query))
        return '%s%s#/?_g=%s&_a=%s' % (self.scope.kibana_origin, PAGES['kibana_discover'].path,
                                      parse.quote(globals_, safe=RISON_SAFE), parse.quote(app, safe=RISON_SAFE))

    def _navigate(self, url):
        self.loaded.clear()
        result = self._page('Page.navigate', {'url': url})
        if result.get('errorText'):
            raise QueryFailure('navigation_failed')
        if not result.get('loaderId'):
            # Only the fragment changed, where Kibana keeps its state: reload so the page starts from the new URL.
            self._page('Page.reload')
        self.loaded.wait(20)
        self._settle()

    def _open(self, command):
        if PAGES[command.page].origin == 'kibana' and self.scope.kibana_origin is None:
            raise QueryFailure('kibana_unavailable')
        self.page_name = command.page
        self.entered = 'url' if command.query else None
        if self.demo.marker == 'on' and command.query:
            try:
                self._search_in_page(command)
            except QueryFailure as exc:
                self.entered = 'fallback:' + str(exc)
            else:
                self.entered = 'typed'
                return self._snapshot(command)
        self._navigate(self._url(command.page, command.query))
        return self._snapshot(command)

    def _search_in_page(self, command):
        """Demo only: load the page unfiltered, then type the search into its search box and press Enter on
        camera. The search still leaves the page as an ordinary request, so Fetch scopes it like any other."""
        self._navigate(self._url(command.page, ''))
        name = PAGES[command.page].box
        box = next((element['ref'] for element in self._snapshot(command)['elements']
                    if element['role'] in SEARCH_ROLES and element['name'] == name), None)
        if box is None:
            raise QueryFailure('no_search_box')
        self._enter(box, command.query, submit=True)

    def _snapshot(self, _command):
        place = self._location()
        nodes = self._page('Accessibility.getFullAXTree').get('nodes') or []
        elements, self.refs, truncated = build_snapshot(nodes)
        text = self._evaluate('document.body ? document.body.innerText : ""')
        return {**place, 'elements': elements, 'elements_truncated': truncated, 'text': _excerpt(text, MAX_TEXT)}

    def _node(self, ref):
        backend = self.refs.get(ref)
        if backend is None:
            raise QueryFailure('unknown_ref')
        try:
            self._page('DOM.scrollIntoViewIfNeeded', {'backendNodeId': backend})
            return self._page('DOM.resolveNode', {'backendNodeId': backend})['object']['objectId']
        except (CdpError, KeyError):
            raise QueryFailure('stale_ref') from None

    def _check(self, object_id, *point):
        return self._page('Runtime.callFunctionOn', {
            'objectId': object_id, 'functionDeclaration': CLICK_ACTIONABLE, 'returnByValue': True,
            'arguments': [{'value': value} for value in point]}).get('result', {}).get('value') or {}

    def _actionable(self, object_id):
        """Visible, enabled, in the viewport, not covered, and holding still across two checks."""
        previous, deadline = None, time.monotonic() + 2.5
        while True:
            result = self._check(object_id)
            if result.get('ok') and result == previous:
                return result
            if time.monotonic() > deadline:
                reason = 'moving' if result.get('ok') else result.get('reason')
                raise QueryFailure('element_not_actionable', reason if isinstance(reason, str) and REASON.fullmatch(reason) else 'unknown')
            previous = result
            self.sleep(0.05)

    def _mouse(self, kind, x, y, **extra):
        self._page('Input.dispatchMouseEvent', {'type': kind, 'x': x, 'y': y, **extra})

    def _key(self, kind, **spec):
        self._page('Input.dispatchKeyEvent', {'type': kind, **spec})

    def _move(self, x, y, width):
        elapsed = 0.0
        for px, py, at in humanize.mouse_path(self.pointer, (x, y), self.rng, width=width)[1:]:
            self.sleep((at - elapsed) / 1000)
            elapsed = at
            self._mouse('mouseMoved', px, py)
        self.pointer = (x, y)

    def _press_on(self, object_id):
        box = self._actionable(object_id)
        aimed = self._check(object_id, *humanize.aim_point(box['left'], box['top'], box['right'], box['bottom'], self.rng))
        x, y = (aimed['x'], aimed['y']) if aimed.get('ok') else (box['x'], box['y'])
        self._move(x, y, box['right'] - box['left'])
        self._mouse('mousePressed', x, y, button='left', buttons=1, clickCount=1)
        self.sleep(humanize.press_hold_ms(self.rng) / 1000)
        self._mouse('mouseReleased', x, y, button='left', buttons=0, clickCount=1)

    def _press_key(self, name):
        spec = KEYS[name]
        self._key('keyDown' if 'text' in spec else 'rawKeyDown', **spec)
        self.sleep(humanize.press_hold_ms(self.rng) / 1000)
        self._key('keyUp', **{field: value for field, value in spec.items() if field != 'text'})

    def _click(self, command):
        self._press_on(self._node(command.ref))
        self._settle()
        return self._snapshot(command)

    def _type(self, command):
        self._enter(command.ref, command.text, command.submit)
        return self._snapshot(command)

    def _enter(self, ref, text, submit):
        self._press_on(self._node(ref))
        select_all = {'key': 'a', 'code': 'KeyA', 'windowsVirtualKeyCode': 65, 'modifiers': CTRL}
        self._key('rawKeyDown', commands=['selectAll'], **select_all)
        self._key('keyUp', **select_all)
        for char, delay in zip(text, humanize.typing_delays(text, self.rng)):
            self.sleep(delay / 1000)
            if ' ' <= char <= '~':
                self._key('keyDown', key=char, text=char, unmodifiedText=char)
                self._key('keyUp', key=char)
            else:
                self._page('Input.insertText', {'text': char})
        if submit:
            self.sleep(self.rng.uniform(0.15, 0.4))
            self._press_key('Enter')
        self._settle()

    def _press(self, command):
        self._press_key(command.key)
        self._settle()
        return self._snapshot(command)

    def _scroll(self, command):
        size = self._evaluate('[innerWidth, innerHeight]')
        width, height = size if isinstance(size, list) and len(size) == 2 else VIEWPORT
        x, y = self.pointer
        if not (0 <= x < width and 0 <= y < height):
            x, y = width / 2, height / 2
            self._move(x, y, 200)
        for delta, pause in humanize.wheel_steps(command.direction, self.rng):
            self.sleep(pause / 1000)
            self._mouse('mouseWheel', x, y, deltaX=0, deltaY=delta)
        self._settle(quiet=0.3)
        return self._snapshot(command)

    def _read(self, command):
        object_id = self._node(command.ref)
        text = self._page('Runtime.callFunctionOn', {'objectId': object_id, 'functionDeclaration': READ_TEXT,
                                                    'returnByValue': True}).get('result', {}).get('value')
        return {**self._location(), 'ref': command.ref, 'text': _excerpt(text, MAX_READ)}

    def state(self):
        lab, arkime, kibana = self.origins()
        return {'pid': self.pid, 'ws_url': self.ws_url, 'lab_origin': lab, 'arkime_origin': arkime, 'kibana_origin': kibana,
                'main_target': self.main_target, 'page': self.page_name, 'refs': self.refs,
                'pointer': list(self.pointer), 'last_used': self.last_used, **_shape(self.window, self.demo)}

    def close(self):
        try:
            self.cdp.call('Browser.close', timeout=5)
        except Exception:
            pass
        self.cdp.close()
        if self.process is not None:
            try:
                self.process.wait(5)
            except subprocess.TimeoutExpired:
                self.process.kill()


def _demo_window(window):
    return (isinstance(window, list) and len(window) == 4 and all(type(value) is int for value in window)
            and all(abs(value) <= 32768 for value in window[:2]) and all(200 <= value <= 16384 for value in window[2:]))


def _demo_scale(scale):
    return type(scale) in (int, float) and 1.0 <= scale <= 2.0


def read_demo(path):
    """The operator's demo marker. The tool only ever reads it; a marker that fails validation is ignored whole."""
    try:
        with open(path, 'rb') as stream:
            raw = stream.read(DEMO_MAX_BYTES + 1)
    except FileNotFoundError:
        return DEMO_OFF
    except OSError:
        return DEMO_INVALID
    try:
        marker = json.loads(raw) if len(raw) <= DEMO_MAX_BYTES else None
    except ValueError:
        return DEMO_INVALID
    if not isinstance(marker, dict) or not set(marker) <= {'headed', 'window', 'cursor', 'scale'}:
        return DEMO_INVALID
    headed, cursor = marker.get('headed', True), marker.get('cursor', True)
    window = marker.get('window', list(DEMO_WINDOW))
    if (type(headed) is not bool or type(cursor) is not bool or not _demo_window(window)
            or ('scale' in marker and not _demo_scale(marker['scale']))):
        return DEMO_INVALID
    scale = float(marker['scale']) if 'scale' in marker else None
    return Demo('on', tuple(window) if headed else None, cursor, scale)


def _browser_executable():
    configured = os.environ.get('HUNT_LAB_BROWSER')
    if configured:
        candidates = [configured]
    elif os.name == 'nt':
        candidates = [r'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe',
                      r'C:\Program Files\Microsoft\Edge\Application\msedge.exe']
    else:
        candidates = ['chromium', 'chromium-browser', 'google-chrome']
    for candidate in candidates:
        found = shutil.which(candidate)
        if found:
            return found
    raise QueryFailure('browser_unavailable')


def browser_args(executable, user_data, scope, window=None, scale=None):
    """Launch flags; `window` (x, y, width, height) opens a visible window there, None runs headless. `scale` forces
    that device scale factor and keeps the window's size in screen pixels, so pages render larger in the same window."""
    ports = [parse.urlsplit(value).port for value in scope.origins if value]
    args = [
        executable, '--user-data-dir=' + str(user_data), '--remote-debugging-port=0',
        '--remote-debugging-address=127.0.0.1', '--no-first-run', '--no-default-browser-check',
        '--disable-extensions', '--disable-sync', '--disable-background-networking', '--disable-component-update',
        '--disable-default-apps', '--deny-permission-prompts',
        '--disable-features=Translate,MediaRouter,OptimizationHints,AutofillServerCommunication',
        # A fence that holds even with no CDP client attached: everything goes to a dead proxy
        # except the lab's own ports (<-loopback> drops Chrome's implicit loopback bypass).
        '--proxy-server=http://127.0.0.1:1',
        '--proxy-bypass-list=<-loopback>;' + ';'.join('127.0.0.1:%d' % port for port in ports),
    ]
    if scale:
        args.append('--force-device-scale-factor=%g' % scale)
    if window:
        # A visible window that another window covers stops rendering, and Arkime's search box
        # then ignores the submitted expression; headless has no window to cover.
        args += ['--window-position=%d,%d' % _dips(window[:2], scale), '--window-size=%d,%d' % _dips(window[2:], scale),
                 '--disable-features=CalculateNativeWinOcclusion', '--disable-backgrounding-occluded-windows',
                 '--disable-renderer-backgrounding', '--disable-background-timer-throttling',
                 '--hide-crash-restore-bubble']
    else:
        args += ['--window-size=%d,%d' % _dips(VIEWPORT, scale), '--headless=new']
    return args + ['about:blank']


def _dips(pixels, scale):
    # Chromium reads window flags in device-independent pixels, which a forced scale factor multiplies.
    return tuple(round(value / (scale or 1)) for value in pixels)


def _launch(root, scope, demo):
    user_data = root / 'user-data'
    user_data.mkdir(parents=True, exist_ok=True)
    port_file = user_data / 'DevToolsActivePort'
    port_file.unlink(missing_ok=True)
    window = _wanted_window(demo)
    args = browser_args(_browser_executable(), user_data, scope, window, demo.scale)
    process = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    deadline = time.monotonic() + 30
    while True:
        try:
            lines = port_file.read_text(encoding='ascii').split()
        except OSError:
            lines = []
        if len(lines) >= 2 and lines[0].isdigit():
            break
        if process.poll() is not None or time.monotonic() > deadline:
            if process.poll() is None:
                process.kill()
            raise QueryFailure('browser_unavailable')
        time.sleep(0.1)
    ws_url = 'ws://127.0.0.1:%s%s' % (lines[0], lines[1])
    return BrowserSession(root, scope, _WebSocket(ws_url), ws_url=ws_url, pid=process.pid, process=process, demo=demo,
                          window=window)


def _wanted_window(demo):
    return demo.window or (DEMO_WINDOW if os.environ.get('HUNT_LAB_BROWSER_HEADED') == '1' else None)


def _shape(window, demo):
    """How a browser was launched; one is reused only while the marker asks for the same shape."""
    return {'window': list(window) if window else None, 'cursor': demo.cursor, 'scale': demo.scale}


def _owned(ws_url):
    """True when ws_url is a live loopback DevTools endpoint answering with exactly this browser's id."""
    try:
        url = parse.urlsplit(ws_url)
        if url.scheme != 'ws' or url.hostname != '127.0.0.1' or not url.port:
            return False
        opener = request.build_opener(request.ProxyHandler({}))
        with opener.open('http://127.0.0.1:%d/json/version' % url.port, timeout=2) as response:
            return json.loads(response.read(65536)).get('webSocketDebuggerUrl') == ws_url
    except Exception:
        return False


def _read_state(root):
    try:
        value = json.loads((root / STATE_FILE).read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return None
    return value if isinstance(value, dict) else None


def _write_state(root, value):
    temp = root / ('.session-%d.tmp' % os.getpid())
    temp.write_text(json.dumps(value, ensure_ascii=True), encoding='utf-8')
    os.replace(temp, root / STATE_FILE)


def _start(root, scope):
    root.mkdir(parents=True, exist_ok=True)
    demo = read_demo(root.parent / DEMO_FILE)
    state = _read_state(root)
    if state and _owned(state.get('ws_url')):
        # Reuse only a browser launched the way the marker asks for now: a headless browser reattached
        # under a demo marker would be invisible while its audit lines claimed demo mode.
        window = _wanted_window(demo)
        wanted = _shape(window, demo)
        fresh = (time.time() - (state.get('last_used') or 0) < IDLE_SECONDS
                 and (state.get('lab_origin'), state.get('arkime_origin'), state.get('kibana_origin')) == scope.origins
                 and {key: state.get(key) for key in wanted} == wanted)
        session = BrowserSession(root, scope, _WebSocket(state['ws_url']), ws_url=state['ws_url'],
                                 pid=state.get('pid'), state=state if fresh else None, demo=demo, window=window)
        if fresh:
            return session
        session.close()
    (root / STATE_FILE).unlink(missing_ok=True)
    return _launch(root, scope, demo)


_SESSIONS = {}
_REGISTRY = threading.Lock()
_AUDIT = threading.Lock()
_watchdog = None


def _forget(key):
    session = _SESSIONS.pop(key)
    session.close()
    (session.root / STATE_FILE).unlink(missing_ok=True)


def _idle_watch():
    while True:
        time.sleep(30)
        with _REGISTRY:
            for key, session in list(_SESSIONS.items()):
                if time.time() - session.last_used > IDLE_SECONDS and session.lock.acquire(blocking=False):
                    try:
                        _forget(key)
                    finally:
                        session.lock.release()


def _session(root, scope):
    global _watchdog
    key = str(root)
    with _REGISTRY:
        session = _SESSIONS.get(key)
        # A long-lived tool host (the gateway) keeps its browser between calls; reuse it only while
        # the operator's marker still asks for the mode it was launched in.
        demo = read_demo(Path(root).parent / DEMO_FILE)
        if (session is not None and session.alive() and session.origins() == scope.origins
                and _shape(session.window, session.demo) == _shape(_wanted_window(demo), demo)):
            session.scope = scope
            return session
        if session is not None:
            _forget(key)
        session = _SESSIONS[key] = _start(root, scope)
        if _watchdog is None:
            _watchdog = threading.Thread(target=_idle_watch, daemon=True, name='lab-browser-idle')
            _watchdog.start()
        return session


def shutdown():
    """Close every lab browser this process drives; runs at exit so no browser outlives its fence."""
    with _REGISTRY:
        for key in list(_SESSIONS):
            _forget(key)


atexit.register(shutdown)


def _audit(root, entry):
    line = json.dumps(entry, ensure_ascii=True, separators=(',', ':'))
    with _AUDIT, open(root / AUDIT_FILE, 'a', encoding='utf-8') as stream:
        stream.write(line + '\n')


def _bounded(envelope):
    result = envelope['result']
    while len(json.dumps(envelope, ensure_ascii=True, separators=(',', ':'))) > MAX_RESULT:
        if len(result.get('text', '')) > 400:
            result['text'] = result['text'][:len(result['text']) // 2] + '…'
            result['text_truncated'] = True
        elif result.get('elements'):
            result['elements'].pop()
            result['elements_truncated'] = True
        else:
            result['text'] = ''
            break
    return envelope


def call(arguments, *, runtime, state_dir, profile, browser_root=None):
    """Run one lab_browser action for `profile`; returns JSON-safe data or a fixed error code."""
    session, command, case_id, outcome = None, None, None, None
    try:
        command = parse_command(arguments)
        case_id = _case_id(arguments)
        base, metadata, status = _lab_base(runtime, state_dir, profile, case_id)
        try:
            kibana = endpoint(status['kibana_url']) if status.get('kibana_url') else None
            scope = LabScope.from_case(metadata, base, endpoint(status.get('arkime_url')), kibana)
        except (KeyError, TypeError, ValueError, AttributeError):
            raise QueryFailure('lab_invalid_response') from None
        root = Path(browser_root) if browser_root else Path(state_dir).parent / 'hunt-lab-browser' / profile
        session = _session(root, scope)
        with session.lock:
            blocked_before = session.blocked
            session.requests.clear()
            try:
                result = session.run(command)
                outcome = {'ok': True, 'profile': profile, 'tool': 'lab_browser', 'case_id': case_id,
                           'result': {'action': command.action, **result,
                                      'blocked_requests': session.blocked - blocked_before}}
            except QueryFailure as exc:
                outcome = _failure(profile, exc)
            except CdpError:
                outcome = {'ok': False, 'profile': profile, 'error': 'browser_command_failed'}
            _write_state(root, session.state())
            _audit(root, {
                'time': datetime.now(timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z'),
                't': int(time.time() * 1000), 'profile': profile, 'case_id': case_id, 'action': command.action,
                'page': session.page_name, 'ref': command.ref, 'key': command.key, 'direction': command.direction,
                'query': command.query or None, 'text': command.text or None, 'submit': command.submit,
                'entered': session.entered,
                'url': (outcome.get('result') or {}).get('url'), 'blocked': session.blocked - blocked_before,
                'requests': list(session.requests)[-20:], 'demo': session.demo.marker,
                'ok': outcome['ok'], 'error': outcome.get('error')})
        return _bounded(outcome) if outcome['ok'] else outcome
    except QueryFailure as exc:
        return _failure(profile, exc)
    except (OSError, CdpError):
        return {'ok': False, 'profile': profile, 'error': 'browser_unavailable'}
    except Exception:
        # The bot only ever sees the fixed code; the operator needs the cause, which was invisible
        # when a filmed lane failed most of its browser calls inside the gateway.
        _LOG.exception('lab_browser %s failed for %s', getattr(command, 'action', None), profile)
        return {'ok': False, 'profile': profile, 'error': 'lab_browser_failed'}

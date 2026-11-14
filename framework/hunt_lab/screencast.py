"""Watch each browser owner's own lab_browser page with Page.startScreencast.

A second DevTools client attaches to each owner's browser under <root>/<profile>/ (root is the lab's
hunt-lab-browser folder) as soon as Chromium writes user-data/DevToolsActivePort, follows session.json's
main_target once lab_browser names it, and hands every screencast frame to a sink callable
sink(profile, t, jpeg_bytes) with the frame's own timestamp (epoch seconds). It re-attaches when a new
browser launches, the main target changes, or its connection drops. A page that does not change sends no
frames.

The client only watches: READ_ONLY lists every command it can send, and anything else raises.
The operator's film (operator/film/screencast.py) and the hunt board's live panel share this core.
"""
from __future__ import annotations

import base64
import json
import logging
import threading
import time
from pathlib import Path
from urllib import parse

from .lab_browser import PAGES, RUNS_DIR, STATE_FILE, Cdp, _WebSocket

READ_ONLY = frozenset({'Target.getTargets', 'Target.attachToTarget', 'Target.detachFromTarget', 'Page.startScreencast',
                       'Page.stopScreencast', 'Page.screencastFrameAck'})
SCREENCAST = {'format': 'jpeg', 'quality': 70, 'maxWidth': 1280, 'maxHeight': 1080, 'everyNthFrame': 1}
_LOG = logging.getLogger(__name__)


def websocket(ws_url):
    return _WebSocket(ws_url)


def candidate_session_dirs(root, profile):
    """Profile browser directory plus any parallel `(run_id, step_id)` subdirectories under `<profile>/runs/`."""
    base = Path(root) / profile
    dirs = [base]
    runs = base / RUNS_DIR
    try:
        children = sorted(child for child in runs.iterdir() if child.is_dir())
    except OSError:
        children = []
    return dirs + children


def _page_from_state(state):
    if not isinstance(state, dict):
        return None
    page = state.get('page')
    if isinstance(page, str) and page in PAGES:
        return page
    url = state.get('url')
    if isinstance(url, str):
        try:
            parts = parse.urlsplit(url)
            loopback = parts.scheme == 'http' and parts.hostname == '127.0.0.1' and parts.port is not None
        except ValueError:
            return None
        if loopback:
            return parts.path or '/'
    return None


def shown_page(root, profile):
    """The page an owner's browser shows, from its newest session.json (across `<profile>/` and `<profile>/runs/*`):
    the lab_browser page name, else the URL path of a loopback http URL; None when unknown."""
    found = []
    for folder in candidate_session_dirs(root, profile):
        path = folder / STATE_FILE
        try:
            mtime = path.stat().st_mtime
            state = json.loads(path.read_text(encoding='utf-8'))
        except (OSError, ValueError):
            continue
        page = _page_from_state(state)
        if page is not None:
            last_used = state.get('last_used') if isinstance(state, dict) else None
            rank = float(last_used) if isinstance(last_used, (int, float)) else mtime
            found.append((rank, mtime, page))
    if not found:
        return None
    return max(found)[2]


class ReadOnlyCdp:
    def __init__(self, transport, on_event):
        self._cdp = Cdp(transport, on_event)
        self.closed = self._cdp.closed

    def call(self, method, params=None, session=None, timeout=10):
        if method not in READ_ONLY:
            raise PermissionError(f'screencast client never sends {method}')
        return self._cdp.call(method, params, session, timeout)

    def post(self, method, params=None, session=None):
        if method not in READ_ONLY:
            raise PermissionError(f'screencast client never sends {method}')
        self._cdp.post(method, params, session)

    def close(self):
        self._cdp.close()


class Stream:
    """One owner's browser, attached from the moment Chromium writes its DevToolsActivePort.

    lab_browser writes session.json (ws_url, main_target) only after an action finishes, so following
    it alone misses the first search typed into a freshly launched browser. The port file names the
    live browser at launch; until session.json names that browser's main target, the first page
    target is watched (the one lab_browser keeps)."""

    def __init__(self, profile, root, sink, connect, log=_LOG.info, *, session_dir=None):
        self.profile, self.sink, self.connect, self.log = profile, sink, connect, log
        folder = Path(session_dir) if session_dir is not None else Path(root) / profile
        self.session_dir = folder
        self.state_file = folder / STATE_FILE
        self.port_file = folder / 'user-data' / 'DevToolsActivePort'
        self.key = self.client = self.session = None
        self.lost = threading.Event()
        self.failed_key = None
        self.failed_logged = 0.0

    @property
    def attached(self):
        return self.session is not None

    def _wanted(self):
        """(ws_url, main_target or None for any page) of the live browser; None when there is none. A read that
        races a writer keeps the current attachment."""
        try:
            lines = self.port_file.read_text(encoding='ascii').split()
        except FileNotFoundError:
            live = None
        except OSError:
            return self.key
        else:
            if len(lines) < 2 or not lines[0].isdigit():
                return self.key
            live = f'ws://127.0.0.1:{lines[0]}{lines[1]}'
        try:
            state = json.loads(self.state_file.read_text(encoding='utf-8'))
        except FileNotFoundError:
            state = {}
        except (OSError, ValueError):
            return self.key
        ws, target = (state.get('ws_url'), state.get('main_target')) if isinstance(state, dict) else (None, None)
        named = isinstance(ws, str) and ws and isinstance(target, str) and target
        if live and (not named or ws != live):
            return live, None
        return (ws, target) if named else None

    def _serves(self, want):
        return want is not None and want[0] == self.key[0] and want[1] in (None, self.key[1])

    def poll(self):
        want = self._wanted()
        if self.client and (not self._serves(want) or self.lost.is_set() or self.client.closed.is_set()):
            self.detach()
        if want and not self.client:
            self.attach(want)

    def attach(self, want):
        ws_url, target = want
        client = None
        try:
            client = ReadOnlyCdp(self.connect(ws_url), self._event)
            self.client = client
            self.lost.clear()
            if target is None:
                pages = [i['targetId'] for i in client.call('Target.getTargets').get('targetInfos', []) if i.get('type') == 'page']
                if not pages:
                    raise LookupError('the browser has no page yet')
                target = pages[0]
            self.key = (ws_url, target)
            self.session = client.call('Target.attachToTarget', {'targetId': target, 'flatten': True})['sessionId']
            client.call('Page.startScreencast', SCREENCAST, self.session)
        except Exception as exc:
            # Log the first failure for a browser, then every 30 s while it keeps failing, with its detail.
            now = time.monotonic()
            if self.failed_key != want or now - self.failed_logged >= 30:
                cause = exc.__cause__ or exc.__context__
                self.log(f'screencast {self.profile}: cannot attach ({type(exc).__name__}: {exc}'
                         + (f' <- {type(cause).__name__}: {cause}' if cause else '') + '); retrying')
                self.failed_logged = now
            self.failed_key = want
            if client:
                client.close()
            self.key = self.client = self.session = None
            return
        self.failed_key = None
        self.log(f'screencast {self.profile}: attached to {target[:12]}')

    def _event(self, message):
        method, params = message.get('method'), message.get('params') or {}
        if method == 'Target.detachedFromTarget' and params.get('sessionId') == self.session:
            self.lost.set()
            return
        if method != 'Page.screencastFrame' or message.get('sessionId') != self.session or self.session is None:
            return
        self.client.post('Page.screencastFrameAck', {'sessionId': params.get('sessionId')}, self.session)
        t = (params.get('metadata') or {}).get('timestamp') or time.time()
        self.sink(self.profile, float(t), base64.b64decode(params.get('data') or ''))

    def detach(self):
        client, session = self.client, self.session
        self.key = self.client = self.session = None
        if not client:
            return
        if session and not client.closed.is_set():
            for method, params in (('Page.stopScreencast', {}), ('Target.detachFromTarget', {'sessionId': session})):
                try:
                    client.call(method, params, session if method.startswith('Page.') else None, timeout=3)
                except Exception:
                    pass
        client.close()
        self.log(f'screencast {self.profile}: detached')


class Watcher:
    """Polls each profile's browser files (including `<profile>/runs/*` step subdirs) in a thread until stop()."""

    def __init__(self, root, sink, profiles, connect=websocket, poll=0.25, log=_LOG.info, name='lab-screencast'):
        self.root = Path(root)
        self.sink = sink
        self.profiles = tuple(profiles)
        self.connect = connect
        self.poll = poll
        self.log = log
        self._stream_map = {(p, self.root / p): Stream(p, self.root, sink, connect, log) for p in self.profiles}
        self.streams = list(self._stream_map.values())
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True, name=name)

    def _sync_streams(self):
        wanted = set()
        for profile in self.profiles:
            for folder in candidate_session_dirs(self.root, profile):
                key = (profile, folder)
                wanted.add(key)
                if key not in self._stream_map:
                    self._stream_map[key] = Stream(profile, self.root, self.sink, self.connect, self.log,
                                                   session_dir=folder)
        for key in list(self._stream_map):
            if key not in wanted:
                self._stream_map.pop(key).detach()
        self.streams = list(self._stream_map.values())

    def attached(self, profile):
        return any(s.attached for s in self.streams if s.profile == profile)

    def _run(self):
        while True:
            self._sync_streams()
            for s in list(self.streams):
                try:
                    s.poll()
                except Exception as exc:
                    self.log(f'screencast {s.profile}: poll failed ({type(exc).__name__}: {exc})')
            if self._stop.wait(self.poll):
                return

    def start(self):
        self._thread.start()
        return self

    def stop(self):
        self._stop.set()
        self._thread.join(timeout=10)
        for s in list(self.streams):
            s.detach()

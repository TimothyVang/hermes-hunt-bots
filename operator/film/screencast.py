"""Film each browser owner's own lab_browser page with Page.startScreencast.

Chromium will not keep its windows topmost, so a desktop capture cannot show the bots' browsers.
Instead a second DevTools client attaches to each owner's browser under hunt-lab-browser/<profile>/
as soon as Chromium writes user-data/DevToolsActivePort, follows session.json's main_target once
lab_browser names it, and saves every screencast frame as a JPEG with the frame's own timestamp. It
re-attaches when a new browser launches, the main target changes, or its connection drops.

The client only watches: READ_ONLY lists every command it can send, and anything else raises.

Output: <out>/<profile>/000001.jpg ... and <out>/index.jsonl, one {"t", "profile", "file"} line
per frame (t in epoch seconds, file relative to <out>). A page that does not change sends no frames,
so a frame stays on screen until the next one.
"""
import base64
import json
import sys
import threading
import time
from pathlib import Path

import tool_loops as tl
from film.actions import OWNERS
from lab_paths import FRAMEWORK, LAB_BROWSER

READ_ONLY = frozenset({'Target.getTargets', 'Target.attachToTarget', 'Target.detachFromTarget', 'Page.startScreencast',
                       'Page.stopScreencast', 'Page.screencastFrameAck'})
SCREENCAST = {'format': 'jpeg', 'quality': 70, 'maxWidth': 1280, 'maxHeight': 1080, 'everyNthFrame': 1}


def _cdp_class():
    sys.path.insert(0, str(FRAMEWORK))
    from hunt_lab.lab_browser import Cdp
    return Cdp


def websocket(ws_url):
    sys.path.insert(0, str(FRAMEWORK))
    from hunt_lab.lab_browser import _WebSocket
    return _WebSocket(ws_url)


class ReadOnlyCdp:
    def __init__(self, transport, on_event):
        self._cdp = _cdp_class()(transport, on_event)
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


class Index:
    """Frame files and their jsonl index, shared by every owner's stream."""

    def __init__(self, out):
        self.out = Path(out)
        self.out.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._counts = {}

    def add(self, profile, t, jpeg):
        with self._lock:
            n = self._counts[profile] = self._counts.get(profile, 0) + 1
            rel = f'{profile}/{n:06d}.jpg'
            (self.out / profile).mkdir(exist_ok=True)
            (self.out / rel).write_bytes(jpeg)
            with (self.out / 'index.jsonl').open('a', encoding='utf-8') as s:
                s.write(json.dumps({'t': t, 'profile': profile, 'file': rel}) + '\n')


def read_index(out):
    """{profile: [(t, path)]} sorted by time; unreadable lines are skipped."""
    frames = {}
    p = Path(out) / 'index.jsonl'
    if not p.exists():
        return frames
    for line in p.read_text(encoding='utf-8').splitlines():
        try:
            e = json.loads(line)
            frames.setdefault(e['profile'], []).append((float(e['t']), Path(out) / e['file']))
        except (ValueError, KeyError, TypeError):
            continue
    return {k: sorted(v) for k, v in frames.items()}


class Stream:
    """One owner's browser, attached from the moment Chromium writes its DevToolsActivePort.

    lab_browser writes session.json (ws_url, main_target) only after an action finishes, so following
    it alone misses the first search typed into a freshly launched browser. The port file names the
    live browser at launch; until session.json names that browser's main target, the first page
    target is filmed (the one lab_browser keeps)."""

    def __init__(self, profile, root, index, connect):
        self.profile, self.index, self.connect = profile, index, connect
        self.state_file = Path(root) / profile / 'session.json'
        self.port_file = Path(root) / profile / 'user-data' / 'DevToolsActivePort'
        self.key = self.client = self.session = None
        self.lost = threading.Event()
        self.failed_key = None
        self.failed_logged = 0.0

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
                tl.log(f'screencast {self.profile}: cannot attach ({type(exc).__name__}: {exc}'
                       + (f' <- {type(cause).__name__}: {cause}' if cause else '') + '); retrying')
                self.failed_logged = now
            self.failed_key = want
            if client:
                client.close()
            self.key = self.client = self.session = None
            return
        self.failed_key = None
        tl.log(f'screencast {self.profile}: attached to {target[:12]}')

    def _event(self, message):
        method, params = message.get('method'), message.get('params') or {}
        if method == 'Target.detachedFromTarget' and params.get('sessionId') == self.session:
            self.lost.set()
            return
        if method != 'Page.screencastFrame' or message.get('sessionId') != self.session or self.session is None:
            return
        self.client.post('Page.screencastFrameAck', {'sessionId': params.get('sessionId')}, self.session)
        t = (params.get('metadata') or {}).get('timestamp') or time.time()
        self.index.add(self.profile, float(t), base64.b64decode(params.get('data') or ''))

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
        tl.log(f'screencast {self.profile}: detached')


class Watcher:
    """Polls both owners' browser files in a thread until stop(); frames go to Index(out)."""

    def __init__(self, out, root=LAB_BROWSER, profiles=tuple(OWNERS), connect=websocket, poll=0.25):
        self.index = Index(out)
        self.streams = [Stream(p, root, self.index, connect) for p in profiles]
        self.poll = poll
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True, name='film-screencast')

    def _run(self):
        while True:
            for s in self.streams:
                try:
                    s.poll()
                except Exception as exc:
                    tl.log(f'screencast {s.profile}: poll failed ({type(exc).__name__}: {exc})')
            if self._stop.wait(self.poll):
                return

    def start(self):
        self._thread.start()
        return self

    def stop(self):
        self._stop.set()
        self._thread.join(timeout=10)
        for s in self.streams:
            s.detach()

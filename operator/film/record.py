"""Record one real hunt round on one lane by filming its Hunt Live board page, never the desktop.

For the round, the lane gets its own read-only board (python -m hermes_temporal.board with the round's
workflow ID and input, the lane's lab state dir and Hermes home) on a free loopback port. A dedicated
headless Chromium/Edge with its own temporary profile opens that page in a 1920x1080 viewport at device
scale 1, and its Page.startScreencast frames are saved with their own timestamps. The board's /state.json
is sampled every second for the stage timings the cut's chapter cards use. The bots' own browsers are
screencast as well (film/screencast.py), for the review's contact sheet. Both stop when the round ends.

Output in the lane directory d: board/000001.jpg ... and board-index.jsonl (the board frames),
board-state.jsonl (each change of the board's step states), board.log, screencast/ (the bots' browsers),
audit.jsonl (the owners' lab_browser actions during the round), run_config's input.json, activity.json and
result.json, and film.json tying them together. film.json's t0 is the epoch second the board screencast
started; recording of the round starts only once the board has sent its first frame.
"""
import base64
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
from pathlib import Path

import tool_loops as tl
from film import screencast
from film.actions import OWNERS
from lab_paths import DEFAULT_LANE, FILM_BROWSER, FRAMEWORK, PYTHON, TEMPORAL_ADDRESS

sys.path.insert(0, str(FRAMEWORK))
from hunt_lab import screencast as core  # noqa: E402
from hunt_lab.lab_browser import Cdp  # noqa: E402

BOARD = 'board'
BOARD_INDEX = 'board-index.jsonl'
BOARD_STATE = 'board-state.jsonl'
VIEWPORT = (1920, 1080)
BOARD_SCREENCAST = {'format': 'jpeg', 'quality': 80, 'maxWidth': VIEWPORT[0], 'maxHeight': VIEWPORT[1], 'everyNthFrame': 1}
STATE_POLL = 1.0


def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def board_command(port, workflow, input_path, lane, activity_after):
    cmd = [PYTHON, '-B', '-m', 'hermes_temporal.board', '--workflow-id', workflow, '--input', str(input_path),
           '--port', str(port), '--lab-state-dir', str(lane.state_dir), '--hermes-home', str(lane.home),
           '--activity-after', str(activity_after)]
    return cmd + (['--address', TEMPORAL_ADDRESS] if TEMPORAL_ADDRESS else [])


def board_state(url, timeout=5):
    """The board's /state.json, or None when it does not answer."""
    try:
        with tl.OPENER.open(url + 'state.json', timeout=timeout) as r:
            return json.loads(r.read())
    except (OSError, ValueError, urllib.error.URLError):
        return None


def wait_serving(proc, url, seconds=60):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise SystemExit(f'the Hunt Live board exited with code {proc.returncode} before serving {url}')
        if board_state(url) is not None:
            return
        time.sleep(0.5)
    raise SystemExit(f'the Hunt Live board did not serve {url} within {seconds}s')


def stop_process(proc):
    """Stop a child and, on Windows, its whole process tree (the browser's renderers)."""
    if proc.poll() is None:
        if os.name == 'nt':
            subprocess.run(['taskkill', '/PID', str(proc.pid), '/T', '/F'], capture_output=True)
        else:
            proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=10)


def steps_of(state):
    """The board's step states, the only part of /state.json the cut reads."""
    steps = state.get('steps') if isinstance(state, dict) else None
    if not isinstance(steps, list):
        return None
    return [{k: s.get(k) for k in ('index', 'step_id', 'role', 'profile', 'state', 'wave', 'reason')}
            for s in steps if isinstance(s, dict)]


class StatePoller:
    """Samples the board's step states every STATE_POLL seconds and appends each change, with its time, to path."""

    def __init__(self, url, path, fetch=board_state, poll=STATE_POLL):
        self.url, self.path, self.fetch, self.poll = url, Path(path), fetch, poll
        self.samples = 0
        self._last = None
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True, name='film-board-state')

    def sample(self):
        t = time.time()
        steps = steps_of(self.fetch(self.url))
        if steps is None or steps == self._last:
            return
        self._last = steps
        self.samples += 1
        with self.path.open('a', encoding='utf-8') as s:
            s.write(json.dumps({'t': t, 'steps': steps}) + '\n')

    def _run(self):
        while True:
            self.sample()
            if self._stop.wait(self.poll):
                return

    def start(self):
        self._thread.start()
        return self

    def stop(self):
        self._stop.set()
        self._thread.join(timeout=15)


def read_states(path):
    """[(t, steps)] from a board-state.jsonl, in time order; unreadable lines are skipped."""
    out = []
    p = Path(path)
    if not p.exists():
        return out
    for line in p.read_text(encoding='utf-8').splitlines():
        try:
            e = json.loads(line)
            out.append((float(e['t']), list(e['steps'])))
        except (ValueError, KeyError, TypeError):
            continue
    return sorted(out, key=lambda x: x[0])


class BoardCam:
    """A dedicated headless browser showing one board page, screencast into sink(BOARD, t, jpeg).

    The browser runs with its own temporary profile, a 1920x1080 viewport at device scale 1, and is never the
    user's browser. It is our own page, so unlike the bots' browsers it may be sized; it is never navigated or
    driven after launch."""

    def __init__(self, url, sink, browser=FILM_BROWSER, connect=core.websocket):
        self.url, self.sink, self.browser, self.connect = url, sink, browser, connect
        self.profile = Path(tempfile.mkdtemp(prefix='film-board-'))
        self.proc = self.cdp = self.session = None
        self.frames = 0
        self.first = threading.Event()
        self.started = None

    def _command(self):
        return [self.browser, '--headless=new', '--remote-debugging-port=0', f'--user-data-dir={self.profile}',
                f'--window-size={VIEWPORT[0]},{VIEWPORT[1]}', '--force-device-scale-factor=1', '--hide-scrollbars',
                '--no-first-run', '--no-default-browser-check', '--disable-extensions', '--disable-sync', '--mute-audio',
                '--disable-background-timer-throttling', '--disable-renderer-backgrounding',
                '--disable-backgrounding-occluded-windows', self.url]

    def _ws_url(self, seconds=30):
        port_file = self.profile / 'DevToolsActivePort'
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                raise SystemExit(f'the board browser {self.browser} exited with code {self.proc.returncode}')
            try:
                lines = port_file.read_text(encoding='ascii').split()
            except OSError:
                lines = []
            if len(lines) >= 2 and lines[0].isdigit():
                return f'ws://127.0.0.1:{lines[0]}{lines[1]}'
            time.sleep(0.2)
        raise SystemExit(f'the board browser {self.browser} wrote no DevToolsActivePort within {seconds}s')

    def _viewport(self):
        view = self.cdp.call('Page.getLayoutMetrics', {}, self.session).get('cssLayoutViewport') or {}
        return view.get('clientWidth'), view.get('clientHeight')

    def _size_viewport(self, target, seconds=10):
        """Grow the headless window by whatever its frame takes and wait until the page itself, which the
        screencast captures, is exactly VIEWPORT (a 1920x1080 window alone leaves a 1920x1001 page), so every
        board frame has one size."""
        width, height = self._viewport()
        if (width, height) == VIEWPORT:
            return
        window = self.cdp.call('Browser.getWindowForTarget', {'targetId': target})
        bounds = window['bounds']
        self.cdp.call('Browser.setWindowBounds', {'windowId': window['windowId'], 'bounds': {
            'width': bounds['width'] + VIEWPORT[0] - width, 'height': bounds['height'] + VIEWPORT[1] - height}})
        deadline = time.monotonic() + seconds
        while self._viewport() != VIEWPORT:
            if time.monotonic() > deadline:
                raise SystemExit(f'the board browser page stayed {self._viewport()}, not {VIEWPORT}')
            time.sleep(0.2)

    def start(self):
        try:
            self.proc = subprocess.Popen(self._command(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except OSError as exc:
            raise SystemExit(f'cannot start the board browser {self.browser} (set HUNT_LAB_BROWSER): {exc}') from exc
        self.cdp = Cdp(self.connect(self._ws_url()), self._event)
        deadline = time.monotonic() + 30
        target = None
        while target is None and time.monotonic() < deadline:
            pages = [i for i in self.cdp.call('Target.getTargets').get('targetInfos', []) if i.get('type') == 'page']
            target = next((i['targetId'] for i in pages if str(i.get('url', '')).startswith(self.url)), None)
            if target is None:
                time.sleep(0.3)
        if target is None:
            raise SystemExit(f'the board browser never opened {self.url}')
        self.session = self.cdp.call('Target.attachToTarget', {'targetId': target, 'flatten': True})['sessionId']
        self._size_viewport(target)
        self.cdp.call('Emulation.setDeviceMetricsOverride', {'width': VIEWPORT[0], 'height': VIEWPORT[1],
                                                             'deviceScaleFactor': 1, 'mobile': False}, self.session)
        self.started = time.time()
        self.cdp.call('Page.startScreencast', BOARD_SCREENCAST, self.session)
        return self

    def _event(self, message):
        if message.get('method') != 'Page.screencastFrame' or self.session is None or message.get('sessionId') != self.session:
            return
        params = message.get('params') or {}
        self.cdp.post('Page.screencastFrameAck', {'sessionId': params.get('sessionId')}, self.session)
        t = (params.get('metadata') or {}).get('timestamp') or time.time()
        self.sink(BOARD, float(t), base64.b64decode(params.get('data') or ''))
        self.frames += 1
        self.first.set()

    def wait_first_frame(self, seconds=30):
        if not self.first.wait(seconds):
            raise SystemExit(f'the board page {self.url} sent no screencast frame within {seconds}s')

    def stop(self):
        session, self.session = self.session, None
        if self.cdp is not None:
            for method, params, sid in (('Page.stopScreencast', {}, session), ('Browser.close', {}, None)):
                try:
                    self.cdp.call(method, params, sid, timeout=5)
                except Exception:
                    pass
            self.cdp.close()
        if self.proc is not None:
            stop_process(self.proc)
        for _ in range(20):
            shutil.rmtree(self.profile, ignore_errors=True)
            if not self.profile.exists():
                break
            time.sleep(0.5)


def demo_marker_problem(lane):
    from hunt_lab.lab_browser import DEMO_FILE, read_demo
    path = lane.browser_root / DEMO_FILE
    demo = read_demo(path)
    if demo.marker != 'on' or not demo.cursor:
        return (f'lab_browser demo marker {path} is missing or invalid (state: {demo.marker}, cursor: {demo.cursor}); '
                'the bots type searches on screen and show their cursor only in demo mode')
    return None


def screencast_problem():
    """Every screencast here talks CDP over websockets, which this Python must import."""
    try:
        import websockets.sync.client  # noqa: F401
    except ImportError:
        return (f'{sys.executable} cannot import websockets, so neither the board nor the bots\' browsers can be '
                'filmed; install it into this interpreter (python -m pip install websockets)')
    return None


def browser_problem():
    if not shutil.which(FILM_BROWSER):
        return f'{FILM_BROWSER} is not an executable browser; set HUNT_LAB_BROWSER to Chromium or Edge'
    return None


def copy_audit(dest, browser_root, start, end):
    lines = []
    for profile in OWNERS:
        p = browser_root / profile / 'audit.jsonl'
        if not p.exists():
            continue
        for line in p.read_text(encoding='utf-8', errors='replace').splitlines():
            try:
                t = json.loads(line)['t'] / 1000
            except (ValueError, KeyError, TypeError):
                continue
            if start <= t <= end:
                lines.append(line)
    dest.write_text('\n'.join(lines) + ('\n' if lines else ''), encoding='utf-8')


def clear(d):
    for name in (BOARD, 'screencast'):
        shutil.rmtree(d / name, ignore_errors=True)
    for name in (BOARD_INDEX, BOARD_STATE):
        (d / name).unlink(missing_ok=True)


def film(d, name, base, brief, guidance, case_id, truth, lane=DEFAULT_LANE):
    """Record one round of the hunt with this brief and guidance on this lane's lab; returns film.json's content."""
    problem = demo_marker_problem(lane) or screencast_problem() or browser_problem()
    if problem:
        raise SystemExit(problem)
    d.mkdir(parents=True, exist_ok=True)
    clear(d)
    workflow = tl.workflow_id(name, case_id, lane)
    # The board reads the round's input before run_config starts it; run_config rewrites the same file.
    (d / 'input.json').write_text(json.dumps(tl.build_input(base, brief, guidance, case_id), indent=2), encoding='utf-8')
    after = tl.last_seq(tl.serving_lab(lane, case_id))
    port = free_port()
    url = f'http://127.0.0.1:{port}/'
    rec = {'name': name, 'lane': lane.name, 'workflow': workflow, 'case_id': case_id, 'board_port': port,
           'board': BOARD, 'board_index': BOARD_INDEX, 'board_state': BOARD_STATE, 'screencast': 'screencast',
           'audit': 'audit.jsonl', 'activity': 'activity.json'}
    index = screencast.Index(d, BOARD_INDEX)
    with (d / 'board.log').open('w', encoding='utf-8') as log:
        board = subprocess.Popen(board_command(port, workflow, d / 'input.json', lane, after), cwd=FRAMEWORK,
                                 env=lane.env() | {'PYTHONUNBUFFERED': '1'}, stdout=log, stderr=subprocess.STDOUT)
        cam = poller = None
        try:
            wait_serving(board, url)
            cam = BoardCam(url, index.add).start()
            rec['t0'] = cam.started
            cam.wait_first_frame()
            poller = StatePoller(url, d / BOARD_STATE).start()
            watcher = screencast.Watcher(d / 'screencast', root=lane.browser_root).start()
            try:
                rec['round_start'] = time.time()
                result, _calls = tl.run_config(name, base, brief, guidance, case_id, truth, d=d, lane=lane)
                rec['round_end'] = time.time()
                rec['result'] = result
                time.sleep(3)
            finally:
                watcher.stop()
        finally:
            if poller:
                poller.stop()
            if cam:
                cam.stop()
            stop_process(board)
    rec['t_end'] = time.time()
    rec['board_frames'] = cam.frames
    rec['board_state_samples'] = poller.samples
    rec['screencast_frames'] = {p: len(v) for p, v in screencast.read_index(d / 'screencast').items()}
    copy_audit(d / 'audit.jsonl', lane.browser_root, rec['round_start'], rec['round_end'])
    (d / 'film.json').write_text(json.dumps(rec, indent=1), encoding='utf-8')
    tl.log(f'{workflow}: filmed the board on port {port} for {rec["t_end"] - rec["t0"]:.0f}s, {rec["board_frames"]} '
           f'board frames, {rec["board_state_samples"]} stage-state changes, browser frames {rec["screencast_frames"]}')
    return rec

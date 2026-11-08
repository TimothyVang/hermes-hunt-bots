"""Record one real hunt round on one lane: three pinned consoles on the desktop, the bots' browsers by screencast.

PRIVACY: the desktop capture covers the lane's 1920x1080 region only, and that region is tiled exactly by
the lane's three topmost console windows. Recording starts only after every console sits on its tile,
topmost, with no other window above it; a guard re-pins them every second while recording. If coverage
ever fails, the capture is stopped and the whole desktop file deleted, because its last second may hold
foreign pixels. The bots' browsers are never captured from the desktop; screencast.py films them. Lanes
recording at the same time use disjoint regions, so each lane's consoles stay outside the others' captures.

Output in the lane directory d: desktop.mp4 (the 1920x1080 region), screencast/, audit.jsonl (the
owners' lab_browser actions during the round), run_config's input.json, activity.json and
result.json, and film.json tying them together. film.json's t0 is the epoch second at which the
capture process was started; frames may begin up to a fraction of a second later.
"""
import ctypes
import json
import shutil
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path

import tool_loops as tl
from film import screencast
from film.actions import OWNERS
from lab_paths import DEFAULT_LANE, FFMPEG, FRAMEWORK, PYTHON, TEMPORAL_ADDRESS

HERE = Path(__file__).parent


@dataclass(frozen=True)
class Rect:
    x: int
    y: int
    w: int
    h: int

    def intersects(self, o):
        return self.x < o.x + o.w and o.x < self.x + self.w and self.y < o.y + o.h and o.y < self.y + self.h

    def inside(self, o):
        return o.x <= self.x and o.y <= self.y and self.x + self.w <= o.x + o.w and self.y + self.h <= o.y + o.h


@dataclass(frozen=True)
class Console:
    script: str
    title: str
    rect: Rect


# Tiles inside a lane's 1920x1080 region: the left tile is the backdrop the cut shows while no bot drives a
# browser; the right strip is kept whole.
CONSOLES = {
    'activity': Console('watch-activity.ps1', 'lab activity - bot tool calls', Rect(0, 0, 1280, 1080)),
    'audit': Console('watch-browser.ps1', 'lab_browser audit - bot actions', Rect(1280, 0, 640, 540)),
    'stages': Console('watch-hunt.ps1', 'stage progress', Rect(1280, 540, 640, 540)),
}


def region_of(lane):
    return Rect(*lane.region)


def tile(region, key):
    r = CONSOLES[key].rect
    return Rect(region.x + r.x, region.y + r.y, r.w, r.h)


def tiles(region, rects):
    """True when rects cover region exactly: each inside it, none overlapping, areas summing to it."""
    rects = list(rects)
    return (all(r.inside(region) for r in rects)
            and not any(a.intersects(b) for i, a in enumerate(rects) for b in rects[i + 1:])
            and sum(r.w * r.h for r in rects) == region.w * region.h)


@dataclass(frozen=True)
class Win:
    title: str
    rect: Rect
    shown: bool
    topmost: bool


def uncovered(windows, titles, region):
    """Why the capture region is not fully covered by our consoles, from top-level windows listed top
    of the z-order first; [] when it is. titles maps each CONSOLES key to its window's exact title."""
    problems, found, above = [], set(), []
    keys = {t: k for k, t in titles.items()}
    for w in windows:
        key = keys.get(w.title)
        if key is None:
            if w.shown and w.rect.intersects(region):
                above.append(w)
            continue
        found.add(key)
        want = tile(region, key)
        if not w.shown:
            problems.append(f'{key} console is hidden or minimized')
        if w.rect != want:
            problems.append(f'{key} console is at {w.rect}, not {want}')
        if not w.topmost:
            problems.append(f'{key} console is not topmost')
        problems += [f'window "{f.title}" is above the {key} console' for f in above if f.rect.intersects(want)]
    problems += [f'{k} console window not found' for k in titles if k not in found]
    return problems


class Desktop:
    """Win32 window listing and pinning; the process is made DPI-aware so pixels match gdigrab's."""
    TOPMOST, NOACTIVATE_SHOW = -1, 0x0010 | 0x0040

    def __init__(self):
        import ctypes.wintypes as wt
        self.wt, self.u = wt, ctypes.windll.user32
        self.dwm = ctypes.windll.dwmapi
        self.u.SetProcessDPIAware()

    def windows(self):
        wt, u, out = self.wt, self.u, []

        def cb(h, _):
            n = u.GetWindowTextLengthW(h)
            b = ctypes.create_unicode_buffer(n + 1)
            u.GetWindowTextW(h, b, n + 1)
            r = wt.RECT()
            u.GetWindowRect(h, ctypes.byref(r))
            cloaked = ctypes.c_int(0)
            self.dwm.DwmGetWindowAttribute(h, 14, ctypes.byref(cloaked), 4)
            ex = u.GetWindowLongW(h, -20)
            shown = bool(u.IsWindowVisible(h)) and not u.IsIconic(h) and not cloaked.value
            out.append((h, Win(b.value, Rect(r.left, r.top, r.right - r.left, r.bottom - r.top), shown, bool(ex & 0x8))))
            return True
        u.EnumWindows(ctypes.WINFUNCTYPE(ctypes.c_bool, wt.HWND, wt.LPARAM)(cb), 0)
        return out

    def pin(self, titles, region):
        """Re-pin every console topmost on its tile of region, then report what still leaves region uncovered."""
        keys = {t: k for k, t in titles.items()}
        for h, w in self.windows():
            if w.title in keys:
                r = tile(region, keys[w.title])
                self.u.SetWindowPos(h, self.wt.HWND(self.TOPMOST), r.x, r.y, r.w, r.h, self.NOACTIVATE_SHOW)
        return uncovered([w for _, w in self.windows()], titles, region)


def start_consoles(titles, workflow, lab_url, lane):
    args = {'activity': ['-LabUrl', lab_url],
            'audit': ['-Root', str(lane.browser_root)],
            'stages': ['-Workflow', workflow, '-Python', PYTHON, '-Framework', str(FRAMEWORK),
                       '-Address', TEMPORAL_ADDRESS or '', '-Queue', lane.task_queue or '']}
    return [subprocess.Popen(['conhost.exe', 'powershell', '-NoLogo', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-NoExit', '-File',
                              str(HERE / 'consoles' / c.script), '-Title', titles[k], *args[k]])
            for k, c in CONSOLES.items()]


def stop_consoles(procs):
    for p in procs:
        subprocess.run(['taskkill', '/PID', str(p.pid), '/T', '/F'], capture_output=True)


def demo_marker_problem(lane):
    sys.path.insert(0, str(FRAMEWORK))
    from hunt_lab.lab_browser import DEMO_FILE, read_demo
    path = lane.browser_root / DEMO_FILE
    demo = read_demo(path)
    if demo.marker != 'on' or not demo.cursor:
        return (f'lab_browser demo marker {path} is missing or invalid (state: {demo.marker}, cursor: {demo.cursor}); '
                'the bots type searches on screen and show their cursor only in demo mode')
    return None


def screencast_problem():
    """The browser is filmed only through the screencast client, which needs websockets in this Python."""
    try:
        import websockets.sync.client  # noqa: F401
    except ImportError:
        return (f'{sys.executable} cannot import websockets, so the bots\' browsers cannot be filmed; '
                'install it into this interpreter (python -m pip install websockets)')
    return None


class Guard:
    """Keeps the consoles pinned while recording; on the first coverage failure stops the capture."""

    def __init__(self, desktop, titles, region, ffmpeg):
        self.desktop, self.titles, self.region, self.ffmpeg = desktop, titles, region, ffmpeg
        self.abort = None
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True, name='film-privacy-guard')

    def _run(self):
        while not self._stop.wait(1.0):
            problems = self.desktop.pin(self.titles, self.region)
            if problems and self.ffmpeg.poll() is None:
                self.ffmpeg.kill()
                self.abort = '; '.join(problems)
                tl.log(f'PRIVACY: desktop capture stopped and will be deleted: {self.abort}')
                return

    def start(self):
        self._thread.start()
        return self

    def stop(self):
        self._stop.set()
        self._thread.join(timeout=10)


def wait_covered(desktop, titles, region, seconds=30):
    """Pin until coverage holds on three checks in a row; the last problems if it never does."""
    ok, problems, deadline = 0, ['not checked'], time.monotonic() + seconds
    while time.monotonic() < deadline:
        problems = desktop.pin(titles, region)
        ok = 0 if problems else ok + 1
        if ok >= 3:
            return []
        time.sleep(1)
    return problems


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


def film(d, name, base, brief, guidance, case_id, truth, lane=DEFAULT_LANE):
    """Record one round of the hunt with this brief and guidance on this lane's lab; returns film.json's content."""
    problem = demo_marker_problem(lane) or screencast_problem()
    if problem:
        raise SystemExit(problem)
    d.mkdir(parents=True, exist_ok=True)
    workflow = tl.workflow_id(name, case_id, lane)
    titles = {k: f'{c.title} [{workflow}]' for k, c in CONSOLES.items()}
    region = region_of(lane)
    desktop = Desktop()
    consoles = start_consoles(titles, workflow, tl.lab_url(lane), lane)
    raw = d / 'desktop.mp4'
    rec = {'name': name, 'lane': lane.name, 'workflow': workflow, 'case_id': case_id, 'raw': None, 'privacy_abort': None,
           'screencast': 'screencast', 'audit': 'audit.jsonl', 'activity': 'activity.json'}
    try:
        problems = wait_covered(desktop, titles, region)
        if problems:
            raise SystemExit(f'{workflow}: refusing to record, the capture region is not fully covered: ' + '; '.join(problems))
        ff = subprocess.Popen([FFMPEG, '-hide_banner', '-loglevel', 'error', '-y', '-f', 'gdigrab', '-framerate', '15',
                               '-offset_x', str(region.x), '-offset_y', str(region.y), '-video_size', f'{region.w}x{region.h}',
                               '-draw_mouse', '0', '-i', 'desktop', '-c:v', 'libx264', '-preset', 'veryfast', '-crf', '22',
                               '-pix_fmt', 'yuv420p', str(raw)], stdin=subprocess.PIPE)
        rec['t0'] = time.time()
        guard = Guard(desktop, titles, region, ff).start()
        shutil.rmtree(d / 'screencast', ignore_errors=True)
        watcher = screencast.Watcher(d / 'screencast', root=lane.browser_root).start()
        try:
            rec['round_start'] = time.time()
            result, _calls = tl.run_config(name, base, brief, guidance, case_id, truth, d=d, lane=lane)
            rec['round_end'] = time.time()
            rec['result'] = result
            time.sleep(3)
        finally:
            watcher.stop()
            if ff.poll() is None:
                try:
                    ff.communicate(b'q', timeout=120)
                except subprocess.TimeoutExpired:
                    ff.kill()
            guard.stop()
            rec['t_end'] = time.time()
            rec['privacy_abort'] = guard.abort
            if guard.abort:
                ff.wait()
                raw.unlink(missing_ok=True)
            elif raw.exists():
                rec['raw'] = raw.name
    finally:
        stop_consoles(consoles)
    copy_audit(d / 'audit.jsonl', lane.browser_root, rec['round_start'], rec['round_end'])
    (d / 'film.json').write_text(json.dumps(rec, indent=1), encoding='utf-8')
    tl.log(f'{workflow}: filmed {rec["t_end"] - rec["t0"]:.0f}s, desktop capture '
           f'{"DELETED (privacy)" if rec["privacy_abort"] else rec["raw"]}')
    return rec

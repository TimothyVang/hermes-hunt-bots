"""Film each browser owner's own lab_browser page with Page.startScreencast.

Chromium will not keep its windows topmost, so a desktop capture cannot show the bots' browsers.
Instead the watch-only DevTools client in framework/hunt_lab/screencast.py attaches to each owner's
browser under hunt-lab-browser/<profile>/ and this module saves every screencast frame as a JPEG with
the frame's own timestamp.

Output: <out>/<profile>/000001.jpg ... and <out>/index.jsonl, one {"t", "profile", "file"} line
per frame (t in epoch seconds, file relative to <out>). A page that does not change sends no frames,
so a frame stays on screen until the next one.
"""
import json
import sys
import threading
from pathlib import Path

import tool_loops as tl
from film.actions import OWNERS
from lab_paths import FRAMEWORK

sys.path.insert(0, str(FRAMEWORK))
from hunt_lab import screencast as core  # noqa: E402


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


class Watcher(core.Watcher):
    """Watches both owners' browsers under root until stop(); frames go to Index(out)."""

    def __init__(self, out, root, profiles=tuple(OWNERS), connect=core.websocket, poll=0.25):
        self.index = Index(out)
        super().__init__(root, self.index.add, profiles, connect=connect, poll=poll, log=tl.log, name='film-screencast')

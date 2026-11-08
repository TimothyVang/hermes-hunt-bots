"""Lanes for the filmed loop: independent labs that run the same round at the same time.

A lanes file is a JSON list, one object per lane:
  {"name": "l1", "hermes_home": "lab-home", "task_queue": "hermes-claude-practice", "region": [0, 0, 1920, 1080]}
plus an optional "hermes_exe" for that home. A relative hermes_home is under the runtime folder. Without a
lanes file the loop runs one lane: the lab that HUNT_BOTS_LAB_HOME, HUNT_BOTS_TASK_QUEUE and LAB_HERMES_EXE
name, filmed at the top-left of the screen, with today's workflow IDs and folders.
"""
import json
import re
from pathlib import Path

from lab_paths import DEFAULT_LANE, RUNTIME, Lane

NAME = re.compile(r'[a-z][a-z0-9]{0,11}')
SIZE = (1920, 1080)
KEYS = {'name', 'hermes_home', 'task_queue', 'region', 'hermes_exe'}


def parse(items):
    """Lanes from the decoded JSON list; raises ValueError naming the first malformed entry."""
    if not isinstance(items, list) or not items:
        raise ValueError('a lanes file is a non-empty JSON list of lane objects')
    lanes = []
    for i, item in enumerate(items):
        if not isinstance(item, dict) or set(item) - KEYS or not {'name', 'hermes_home', 'region'} <= set(item):
            raise ValueError(f'lane {i}: needs name, hermes_home and region, optional task_queue and hermes_exe, nothing else')
        name, home, queue, region, exe = (item.get(k) for k in ('name', 'hermes_home', 'task_queue', 'region', 'hermes_exe'))
        if not isinstance(name, str) or not NAME.fullmatch(name):
            raise ValueError(f'lane {i}: name must be 1-12 lowercase letters and digits, starting with a letter')
        if not isinstance(home, str) or not home:
            raise ValueError(f'lane {name}: hermes_home must be a path')
        if queue is not None and (not isinstance(queue, str) or not queue):
            raise ValueError(f'lane {name}: task_queue must be a non-empty string')
        if exe is not None and (not isinstance(exe, str) or not exe):
            raise ValueError(f'lane {name}: hermes_exe must be a path')
        if not (isinstance(region, list) and len(region) == 4 and all(type(v) is int for v in region)):
            raise ValueError(f'lane {name}: region must be [x, y, width, height] in whole pixels')
        lanes.append(Lane(name, (RUNTIME / home).resolve(), queue, exe, tuple(region)))
    return lanes


def load(path=None):
    if path is None:
        return [DEFAULT_LANE]
    return parse(json.loads(Path(path).read_text(encoding='utf-8')))


def _overlap(a, b):
    return a[0] < b[0] + b[2] and b[0] < a[0] + a[2] and a[1] < b[1] + b[3] and b[1] < a[1] + a[3]


def problems(lanes):
    """Why these lanes could interfere; [] when every lane has its own name, home, browser state, task
    queue and screen region, each region the 1920x1080 the cut is laid out for."""
    out = []
    for lane in lanes:
        if tuple(lane.region[2:]) != SIZE:
            out.append(f'lane {lane.name or "default"}: region must be {SIZE[0]}x{SIZE[1]}, not {lane.region[2]}x{lane.region[3]}')
    if len(lanes) > 1:
        out += [f'lane {lane.name or "default"}: several lanes need a name and their own task_queue'
                for lane in lanes if not lane.name or not lane.task_queue]
    for i, a in enumerate(lanes):
        for b in lanes[i + 1:]:
            pair = f'lanes {a.name or "default"} and {b.name or "default"}'
            for what, x, y in (('name', a.name, b.name), ('task_queue', a.task_queue, b.task_queue),
                               ('hermes_home', a.home, b.home), ('browser dir', a.browser_root, b.browser_root)):
                if x and x == y:
                    out.append(f'{pair} share their {what}')
            if _overlap(a.region, b.region):
                out.append(f'{pair} have overlapping screen regions')
    return out


def label(lane):
    return lane.name or 'default'

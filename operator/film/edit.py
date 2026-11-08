"""Cut a filmed round into a 1920x1080 video without staging anything.

Left 1280x1080: the acting bot's own browser (its screencast frames, letterboxed) while it drives
lab_browser, otherwise the desktop capture's activity console. Right 640x1080: the captured audit and
stage consoles. Browser stretches (each lab_browser action from pad_before before to pad_after after,
from the audit timestamps) play at 1x; everything else plays speed times faster under a label saying
so. A caption names the bot and tool acting. Intro and outro cards carry the round's real numbers.
Every video frame comes from desktop.mp4 or a screencast JPEG; a screencast frame stays on screen
until the next one, because Chromium sends frames only when the page changes.
"""
import bisect
import json
import subprocess
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path

from film import screencast
from lab_paths import FFMPEG, FFPROBE, TOOLCAM_FONT

MERGE_GAP = 8.0
MIN_GAP = 1.0
BROWSER_HOLD = 8.0
API_HOLD = 60.0
MIN_CAPTION = 0.4
INTRO_SECONDS, OUTRO_SECONDS = 5, 7
BAR = 104
BACKGROUND = '0x0b1220'


@dataclass(frozen=True)
class Knobs:
    speed: float = 12.0
    pad_before: float = 3.0
    pad_after: float = 6.0
    captions: bool = True
    intro_title: str = 'Six AI hunting bots, one real hunt'


# name: (type, low, high). Only these can be tuned; a title carries no digits so no number on a card is invented.
KNOB_RULES = {'speed': (float, 2, 30), 'pad_before': (float, 0, 10), 'pad_after': (float, 0, 15),
              'captions': (bool, None, None), 'intro_title': (str, 1, 80)}


def check_knobs(obj):
    """(changes, problems) for a proposed knob dict, validated against KNOB_RULES."""
    if not isinstance(obj, dict):
        return {}, ['knobs must be an object']
    changes, problems = {}, []
    for name, value in obj.items():
        rule = KNOB_RULES.get(name)
        if rule is None:
            problems.append(f'unknown knob {name}')
            continue
        kind, low, high = rule
        if kind is bool:
            if type(value) is not bool:
                problems.append(f'{name} must be true or false')
                continue
        elif kind is float:
            if type(value) not in (int, float) or not low <= value <= high:
                problems.append(f'{name} must be a number from {low} to {high}')
                continue
            value = float(value)
        else:
            value = ' '.join(str(value).split()) if isinstance(value, str) else None
            if value is None or not low <= len(value) <= high or any(c.isdigit() for c in value):
                problems.append(f'{name} must be {low}..{high} characters with no digits')
                continue
        changes[name] = value
    return changes, problems


def apply_knobs(knobs, changes):
    return replace(knobs, **changes)


@dataclass(frozen=True)
class Caption:
    start: float
    end: float
    text: str


@dataclass(frozen=True)
class Segment:
    start: float
    end: float
    speed: float
    screencast: str | None = None
    captions: tuple = field(default=())

    @property
    def out_seconds(self):
        return (self.end - self.start) / self.speed


def _windows(duration, browser, knobs):
    """Merged real-time windows [start, end, profile, last action] from (time, profile) browser actions."""
    windows = []
    for r, profile in browser:
        s, e = max(0.0, r - knobs.pad_before), min(duration, r + knobs.pad_after)
        if windows and windows[-1][2] == profile and s <= windows[-1][1] + MERGE_GAP:
            windows[-1][1], windows[-1][3] = max(windows[-1][1], e), r
            continue
        if windows and s < windows[-1][1]:
            s = max(s, windows[-1][3])
            windows[-1][1] = s
            if windows[-1][1] <= windows[-1][0]:
                windows.pop()
        windows.append([s, e, profile, r])
    for prev, nxt in zip(windows, windows[1:]):
        if nxt[0] - prev[1] < MIN_GAP:
            prev[1] = nxt[0]
    if windows and windows[0][0] < MIN_GAP:
        windows[0][0] = 0.0
    if windows and duration - windows[-1][1] < MIN_GAP:
        windows[-1][1] = duration
    return windows


def _caption_spans(times_texts, hold, duration):
    spans = []
    for i, (r, text) in enumerate(times_texts):
        end = min(r + hold, times_texts[i + 1][0] if i + 1 < len(times_texts) else duration, duration)
        if end > r:
            spans.append((r, end, text))
    return spans


def _clip_captions(spans, s, e, speed):
    out = []
    for cs, ce, text in spans:
        a, b = (max(cs, s) - s) / speed, (min(ce, e) - s) / speed
        if b - a >= MIN_CAPTION:
            out.append(Caption(round(a, 3), round(b, 3), text))
    return tuple(out)


def plan(duration, t0, actions, frames, knobs):
    """Segments covering [0, duration] seconds of the desktop capture that starts at epoch t0.
    frames maps each profile to its screencast frame epoch times."""
    rel = sorted((a.t - t0, a) for a in actions if 0 <= a.t - t0 <= duration)
    browser = [(r, a.profile) for r, a in rel if a.browser]
    browser_spans = _caption_spans([(r, a.caption) for r, a in rel if a.browser], BROWSER_HOLD, duration)
    api_spans = _caption_spans([(r, a.caption) for r, a in rel if not a.browser], API_HOLD, duration)
    first = {p: min(ts) - t0 for p, ts in frames.items() if ts}
    parts, pos = [], 0.0
    for s, e, profile, _ in _windows(duration, browser, knobs):
        if s > pos:
            parts.append((pos, s, knobs.speed, None))
        f0 = first.get(profile)
        if f0 is None or f0 >= e:
            parts.append((s, e, 1.0, None))
        elif f0 <= s:
            parts.append((s, e, 1.0, profile))
        else:
            parts += [(s, f0, 1.0, None), (f0, e, 1.0, profile)]
        pos = e
    if duration > pos:
        parts.append((pos, duration, knobs.speed, None))
    segments = []
    for s, e, speed, profile in parts:
        spans = browser_spans if speed == 1.0 else api_spans
        segments.append(Segment(round(s, 3), round(e, 3), speed, profile,
                                _clip_captions(spans, s, e, speed) if knobs.captions else ()))
    return segments


def frame_schedule(frames, s, e):
    """[(path, seconds)] showing, from s to e, the latest frame at or before each moment.
    frames is [(time, path)] sorted, in the same clock as s and e, with frames[0] at or before s."""
    times = [t for t, _ in frames]
    i = max(bisect.bisect_right(times, s) - 1, 0)
    starts = [(s, frames[i][1])] + [(t, p) for t, p in frames[i + 1:] if t < e]
    out = []
    for k, (t, p) in enumerate(starts):
        nxt = starts[k + 1][0] if k + 1 < len(starts) else e
        if nxt > t:
            out.append((p, round(nxt - t, 3)))
    return out


def to_output(segments, r):
    """Output-video second at which capture second r is shown (cards included)."""
    out = float(INTRO_SECONDS)
    for seg in segments:
        if r < seg.end:
            return out + max(0.0, r - seg.start) / seg.speed
        out += seg.out_seconds
    return out


def card_lines(result, cov, knobs, case_id):
    first = result['rounds'][0] if result.get('rounds') else {}
    owners = cov['owners']
    typed = sum(o['typed_searches'] for o in owners.values())
    intro = [knobs.intro_title, f'Case {case_id} · one real round of the six-bot hunt',
             'Threat Hunter drives the lab console (Elastic) · Network Analyst drives Arkime',
             'Every frame is a real capture · sped-up stretches are labelled']
    outro = [f'Found {first.get("found", 0)}/{first.get("total", 18)} facts · {result.get("misattributed", 0)} decoys blamed · '
             f'{result.get("halts", 0)} halted rounds',
             f'{result.get("minutes", 0)} min · {result.get("tool_calls", 0)} API tool calls · {typed} searches typed on screen',
             'Driving coverage ' + f'{cov["coverage"]:.0%}: ' + ', '.join(f'{o["role"]} {o["coverage"]:.0%}' for o in owners.values())]
    return intro, outro


def _q(path):
    return "'" + str(Path(path).resolve()).replace('\\', '/').replace(':', '\\:') + "'"


class Renderer:
    def __init__(self, work):
        self.work = Path(work)
        self.work.mkdir(parents=True, exist_ok=True)
        self.n = 0

    def text(self, value, x, y, size, color, enable=None):
        self.n += 1
        f = self.work / f'text-{self.n:04d}.txt'
        f.write_text(value, encoding='utf-8')
        font = f'fontfile={_q(TOOLCAM_FONT)}:' if TOOLCAM_FONT else ''
        on = f":enable='between(t,{enable[0]:.3f},{enable[1]:.3f})'" if enable else ''
        return f'drawtext={font}textfile={_q(f)}:expansion=none:x={x}:y={y}:fontsize={size}:fontcolor={color}{on}'

    def run(self, inputs, graph, out):
        script = out.with_suffix('.filter.txt')
        script.write_text(graph, encoding='utf-8')
        subprocess.run([FFMPEG, '-hide_banner', '-loglevel', 'error', '-y', *inputs, '-filter_complex_script', str(script),
                        '-map', '[v]', '-an', '-r', '30', '-c:v', 'libx264', '-preset', 'veryfast', '-crf', '20',
                        '-pix_fmt', 'yuv420p', str(out)], check=True)

    def card(self, lines, seconds, out):
        draws = ','.join(self.text(line, '(w-text_w)/2', f'(h/2)-{(len(lines) - 1) * 34}+{k * 68}', 52 if k == 0 else 34,
                                   'white' if k == 0 else '0xcbd5e1') for k, line in enumerate(lines))
        self.run(['-f', 'lavfi', '-i', f'color=c={BACKGROUND}:s=1920x1080:r=30:d={seconds}'], f'[0:v]{draws}[v]', out)

    def segment(self, raw, seg, frames, out):
        inputs = ['-ss', f'{seg.start:.3f}', '-t', f'{seg.end - seg.start:.3f}', '-i', str(raw)]
        if seg.screencast:
            listing = out.with_suffix('.ffconcat')
            lines = ['ffconcat version 1.0']
            sched = frame_schedule(frames, seg.start, seg.end)
            for path, seconds in sched:
                lines += [f"file '{Path(path).resolve().as_posix()}'", f'duration {seconds}']
            lines.append(f"file '{Path(sched[-1][0]).resolve().as_posix()}'")
            listing.write_text('\n'.join(lines) + '\n', encoding='utf-8')
            inputs += ['-f', 'concat', '-safe', '0', '-i', str(listing)]
            panels = ('[0:v]fps=30,crop=640:1080:1280:0[r];'
                      '[1:v]scale=1280:1080:force_original_aspect_ratio=decrease,'
                      f'pad=1280:1080:(ow-iw)/2:0:color={BACKGROUND},setsar=1,fps=30,setpts=PTS-STARTPTS[l];')
        else:
            panels = '[0:v]fps=30,split[a][b];[a]crop=1280:1080:0:0[l];[b]crop=640:1080:1280:0[r];'
        label, color = (('REAL TIME · bot driving its browser', '0x22c55e') if seg.speed == 1.0 else
                        (f'{seg.speed:g}x FASTER · every frame is real', '0xf59e0b'))
        draws = [f'drawbox=x=0:y=ih-{BAR}:w=iw:h={BAR}:color=black@0.72:t=fill',
                 self.text(label, 24, f'h-{BAR}+12', 28, color)]
        draws += [self.text(c.text, 24, f'h-{BAR}+56', 30, 'white', (c.start, c.end)) for c in seg.captions]
        self.run(inputs, panels + f'[l][r]hstack=inputs=2:shortest=1,setpts=(PTS-STARTPTS)/{seg.speed},fps=30,'
                 + ','.join(draws) + '[v]', out)


def duration_of(video):
    r = subprocess.run([FFPROBE, '-v', 'error', '-show_entries', 'format=duration', '-of', 'csv=p=0', str(video)],
                       capture_output=True, text=True, check=True)
    return float(r.stdout.strip())


def cut(d, rec, actions, knobs, cov):
    """Render d/video.mp4 from film.json's captures; returns (and writes) d/edit.json."""
    d = Path(d)
    raw = d / rec['raw']
    duration = duration_of(raw)
    frames = screencast.read_index(d / rec['screencast'])
    segments = plan(duration, rec['t0'], actions, {p: [t for t, _ in v] for p, v in frames.items()}, knobs)
    rel = {p: [(t - rec['t0'], path) for t, path in v] for p, v in frames.items()}
    intro, outro = card_lines(rec['result'], cov, knobs, rec['case_id'])
    work = d / 'edit-work'
    r = Renderer(work)
    parts = [work / 'intro.mp4']
    r.card(intro, INTRO_SECONDS, parts[0])
    for i, seg in enumerate(segments):
        parts.append(work / f'seg-{i:03d}.mp4')
        r.segment(raw, seg, rel.get(seg.screencast, []), parts[-1])
    parts.append(work / 'outro.mp4')
    r.card(outro, OUTRO_SECONDS, parts[-1])
    listing = work / 'parts.ffconcat'
    listing.write_text('ffconcat version 1.0\n' + ''.join(f"file '{p.resolve().as_posix()}'\n" for p in parts), encoding='utf-8')
    video = d / 'video.mp4'
    subprocess.run([FFMPEG, '-hide_banner', '-loglevel', 'error', '-y', '-f', 'concat', '-safe', '0', '-i', str(listing),
                    '-c', 'copy', '-movflags', '+faststart', str(video)], check=True)
    out, timeline = float(INTRO_SECONDS), []
    for seg in segments:
        timeline.append({**asdict(seg), 'out_start': round(out, 3), 'out_end': round(out + seg.out_seconds, 3)})
        out += seg.out_seconds
    edit = {'video': video.name, 'knobs': asdict(knobs), 'capture_seconds': round(duration, 3), 't0': rec['t0'],
            'out_seconds': round(out + OUTRO_SECONDS, 3), 'intro': intro, 'outro': outro, 'segments': timeline,
            'screencast_frames': {p: len(v) for p, v in frames.items()}}
    (d / 'edit.json').write_text(json.dumps(edit, indent=1), encoding='utf-8')
    return edit


def segments_of(edit):
    return [Segment(s['start'], s['end'], s['speed'], s['screencast'],
                    tuple(Caption(**c) for c in s['captions'])) for s in edit['segments']]

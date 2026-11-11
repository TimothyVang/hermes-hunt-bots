"""Cut a filmed round into two 1920x1080 videos of the Hunt Live board, without staging anything.

Option A, video-full.mp4: the whole round at 1x. Option B, video.mp4: the whole round at one constant
speed (knob speed, default 5x), the cut the film loop reviews. Both are the board's own screencast frames,
each held until the next one (the board repaints at least every 2 s), with a bar along the bottom that
carries a permanent label ("5x speed · every frame is real") and, when the captions knob is on, the bot and
tool acting, from the lab_browser audit and the lab's /activity log. A chapter card (CHAPTER_SECONDS) opens
each wave where its first step really started, from the board's step states sampled during the round: "Wave n
of N" with its step names, owner bots, wall-clock range, duration and any dropped or stopped step's reason (a
serial round has one step per wave). Intro and outro cards carry the round's real numbers; the outro also
counts the steps done and dropped. Cards add video time but never consume round time, so the board footage
of Option A lasts exactly as long as the round.

Every video is rendered in one ffmpeg pass from an ffconcat list of JPEG stills, each listed for its screen
time: board frames for their real hold divided by the speed, cards for their own seconds. The label is
drawn over every frame of that list.
"""
import bisect
import json
import subprocess
import time
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path

from film import screencast
from lab_paths import FFMPEG, TOOLCAM_FONT

BOARD = 'board'
INTRO_SECONDS, OUTRO_SECONDS, CHAPTER_SECONDS = 5.0, 7.0, 2.5
CAPTION_HOLD = 3.0  # screen seconds a caption stays at most
MIN_CAPTION = 0.4
BROWSER_HOLD = 8.0  # real seconds a bot's browser counts as live on the board after one of its frames
BAR = 64
BACKGROUND = '0x0b1220'
SIZE = (1920, 1080)
# Widest card lines, in characters, that fit 1920 px: Segoe UI Bold measured ~25 px a character at the
# title's 52 px and ~16 at the other lines' 34 px.
TITLE_CHARS, CARD_CHARS = 60, 90
WAITING = {'pending', 'not_reached'}
ENDED = {'done', 'stopped', 'dropped'}
# A blank page (about:blank, a page mid-load) encodes to ~7 KB at 1280x960; lab pages with content were 86 KB+.
MIN_FRAME_BYTES = 16_000


@dataclass(frozen=True)
class Knobs:
    speed: float = 5.0
    captions: bool = True
    intro_title: str = 'Six AI hunting bots, one real hunt'


# name: (type, low, high). Only these can be tuned; a title carries no digits so no number on a card is invented.
KNOB_RULES = {'speed': (float, 2, 30), 'captions': (bool, None, None), 'intro_title': (str, 1, 80)}


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


def label(speed):
    return 'Real time · every frame is real' if speed == 1 else f'{speed:g}x speed · every frame is real'


@dataclass(frozen=True)
class Caption:
    start: float
    end: float
    text: str


@dataclass(frozen=True)
class Stage:
    """One step as the board showed it: number (1-based), step, owner bot, wave, epoch start and end, whether it
    ended inside the round (else end is the round's end), and its last state and reason (a drop's or stop's code)."""
    number: int
    step_id: str
    role: str
    wave: int
    start: float
    end: float
    finished: bool
    state: str = ''
    reason: str = ''

    @property
    def seconds(self):
        return self.end - self.start


@dataclass(frozen=True)
class Segment:
    """Round seconds [start, end] of board footage at speed; captions in screen seconds from its own start."""
    start: float
    end: float
    speed: float
    captions: tuple = field(default=())

    @property
    def out_seconds(self):
        return (self.end - self.start) / self.speed


@dataclass(frozen=True)
class Chapter:
    """One card per wave, at its first step's start; a serial round has one step per wave."""
    at: float
    wave: int
    stages: tuple
    total: int

    out_seconds = CHAPTER_SECONDS


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


def _wave(step):
    # A serial status lists no waves: each step is its own wave, in step order.
    return step['wave'] if type(step.get('wave')) is int else int(step.get('index')) + 1


def stage_timings(samples, start, end):
    """Steps the board showed starting within [start, end] epoch seconds, in start order.

    A step starts at the first sample showing it past pending (its gate open, running, under review or over)
    after a sample showing it pending; one already under way at the first sample has no observed start and is
    left out. It ends at the first later sample showing it done, stopped or dropped."""
    waited, starts, ends, info = set(), {}, {}, {}
    for t, steps in samples:
        for s in steps:
            key = s.get('index')
            info[key] = s
            if s.get('state') in WAITING:
                waited.add(key)
                continue
            if key in waited and key not in starts:
                starts[key] = t
            if key in starts and key not in ends and s.get('state') in ENDED:
                ends[key] = t
    out = []
    for key, t in sorted(starts.items(), key=lambda kv: kv[1]):
        if not start <= t <= end:
            continue
        e = ends.get(key)
        finished = e is not None and e <= end
        s = info[key]
        out.append(Stage(int(key) + 1, str(s.get('step_id')), str(s.get('role')), _wave(s), round(t, 3),
                         round(e if finished else end, 3), finished, str(s.get('state')) if finished else '',
                         str(s.get('reason') or '') if finished else ''))
    return out


def stage_count(samples):
    return len(samples[-1][1]) if samples else 0


def wave_count(samples):
    return len({_wave(s) for s in samples[-1][1]}) if samples else 0


def _wrap(parts, sep, width=CARD_CHARS):
    """parts joined by sep into lines of at most width characters (a longer part gets its own line):
    drawtext never wraps, so a wider line would be cut at the frame's edges."""
    lines = []
    for part in parts:
        if lines and len(lines[-1]) + len(sep) + len(part) <= width:
            lines[-1] += sep + part
        else:
            lines.append(part)
    return lines


def steps_lines(steps):
    """The end card's count of the round's last board state: steps done, waves, and each dropped step's reason."""
    done = sum(1 for s in steps if s.get('state') == 'done')
    dropped = [s for s in steps if s.get('state') == 'dropped']
    waves = len({_wave(s) for s in steps})
    line = f'{done} of {len(steps)} steps done' + (f' in {waves} waves' if waves != len(steps) else '')
    if not dropped:
        return [line]
    return [line + f' · {len(dropped)} dropped:'] + _wrap(
        [f'{s.get("step_id")} ({str(s.get("reason") or "no reason given").replace("_", " ")})' for s in dropped], ', ')


def _clock(t):
    return time.strftime('%H:%M:%S', time.localtime(t))


def _span(seconds):
    m, s = divmod(int(round(seconds)), 60)
    return f'{m} min {s:02d} s' if m else f'{s} s'


def chapter_lines(chapter):
    stages = chapter.stages
    begin, end = min(s.start for s in stages), max(s.end for s in stages)
    open_ = not all(s.finished for s in stages)
    names = [s.step_id.capitalize() for s in stages]
    title = f'Wave {chapter.wave} of {chapter.total} · ' + ', '.join(names)
    lines = [title] if len(title) <= TITLE_CHARS else [f'Wave {chapter.wave} of {chapter.total} · {len(names)} steps',
                                                       *_wrap(names, ', ')]
    lines += _wrap(list(dict.fromkeys(s.role for s in stages)), ' · ')
    lines += [f'{_clock(begin)} – {_clock(end)}' + (' (round end, wave not finished)' if open_ else ''), _span(end - begin)]
    lines += [f'{s.step_id.capitalize()} {s.state} ({s.reason.replace("_", " ") or "no reason given"})'
              for s in stages if s.state in ('dropped', 'stopped')]
    return lines


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


def plan(duration, start, stages, actions, knobs, speed, total):
    """The round's [0, duration] seconds (epoch start) as board Segments at one constant speed, with a Chapter
    before the footage at each wave's real start (its first step's start); total is the round's wave count."""
    rel = sorted((a.t - start, a.caption) for a in actions if 0 <= a.t - start <= duration)
    spans = _caption_spans(rel, CAPTION_HOLD * speed, duration) if knobs.captions else []
    waves = {}
    for stage in sorted(stages, key=lambda s: (s.start, s.number)):
        waves.setdefault(stage.wave, []).append(stage)
    items, pos = [], 0.0
    for wave, group in sorted(waves.items(), key=lambda kv: kv[1][0].start):
        at = round(min(max(group[0].start - start, 0.0), duration), 3)
        if at > pos:
            items.append(Segment(round(pos, 3), at, speed, _clip_captions(spans, pos, at, speed)))
            pos = at
        items.append(Chapter(at, wave, tuple(group), total))
    if duration > pos:
        items.append(Segment(round(pos, 3), round(duration, 3), speed, _clip_captions(spans, pos, duration, speed)))
    return items


def timeline(items):
    """Each item as a dict with its output seconds, between the intro and the outro."""
    out, pos = [{'kind': 'intro', 'out_start': 0.0, 'out_end': INTRO_SECONDS}], INTRO_SECONDS
    for item in items:
        end = pos + item.out_seconds
        if isinstance(item, Chapter):
            out.append({'kind': 'chapter', 'at': item.at, 'wave': item.wave, 'step_ids': [s.step_id for s in item.stages],
                        'lines': chapter_lines(item), 'out_start': round(pos, 3), 'out_end': round(end, 3)})
        else:
            out.append({'kind': 'board', **asdict(item), 'out_start': round(pos, 3), 'out_end': round(end, 3)})
        pos = end
    out.append({'kind': 'outro', 'out_start': round(pos, 3), 'out_end': round(pos + OUTRO_SECONDS, 3)})
    return out


def to_output(segments, r):
    """Output-video second at which round second r is shown, from timeline() entries."""
    board = [s for s in segments if s['kind'] == 'board']
    for s in board:
        if r < s['end']:
            return s['out_start'] + max(0.0, r - s['start']) / s['speed']
    return board[-1]['out_end'] if board else INTRO_SECONDS


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


def listing(items, frames, cards, speed):
    """[(path, screen seconds)] for the whole video: intro, board frames and chapter cards, outro. frames is
    [(round second, path)]; cards maps 'intro', 'outro' and each Chapter to its still. Board frames are held
    for their real hold divided by speed."""
    out = [(cards['intro'], INTRO_SECONDS)]
    for item in items:
        if isinstance(item, Chapter):
            out.append((cards[item], CHAPTER_SECONDS))
        else:
            out += [(p, s / speed) for p, s in frame_schedule(frames, item.start, item.end)]
    return out + [(cards['outro'], OUTRO_SECONDS)]


def overlay(segments, speed):
    """(label, [(caption, out_start, out_end)]) for timeline() entries: what the bottom bar shows, the label on
    every frame."""
    captions = [(c['text'], s['out_start'] + c['start'], s['out_start'] + c['end'])
                for s in segments if s['kind'] == 'board' for c in s['captions']]
    return label(speed), captions


def card_lines(result, cov, knobs, case_id, steps=()):
    """Intro and outro lines; steps is the round's last board state, counted on the outro when known."""
    first = result['rounds'][0] if result.get('rounds') else {}
    owners = cov['owners']
    typed = sum(o['typed_searches'] for o in owners.values())
    intro = [knobs.intro_title, f'Case {case_id} · one real round of the six-bot hunt on the Hunt Live board',
             'Threat Hunter drives Kibana Discover (Elastic) · Network Analyst drives Arkime',
             'Every frame is a real capture of the board · the speed is on screen throughout']
    outro = [f'Found {first.get("found", 0)}/{first.get("total", 18)} facts · {result.get("misattributed", 0)} decoys blamed · '
             f'{result.get("halts", 0)} halted rounds',
             f'{result.get("minutes", 0)} min · {result.get("tool_calls", 0)} API tool calls · {typed} searches typed on screen',
             'Driving coverage ' + f'{cov["coverage"]:.0%}: ' + ', '.join(f'{o["role"]} {o["coverage"]:.0%}' for o in owners.values())]
    if steps:
        outro += steps_lines(steps)
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

    def card(self, lines, out):
        """One 1920x1080 JPEG still: the first line large, the rest under it."""
        draws = ','.join(self.text(line, '(w-text_w)/2', f'(h/2)-{(len(lines) - 1) * 34}+{k * 68}', 52 if k == 0 else 34,
                                   'white' if k == 0 else '0xcbd5e1') for k, line in enumerate(lines))
        subprocess.run([FFMPEG, '-hide_banner', '-loglevel', 'error', '-y', '-f', 'lavfi', '-i',
                        f'color=c={BACKGROUND}:s={SIZE[0]}x{SIZE[1]}:d=1', '-frames:v', '1', '-vf', draws,
                        '-pix_fmt', 'yuvj420p', '-q:v', '2', str(out)], check=True)

    def video(self, entries, speed, bar, out):
        """Play the still list at 30 fps under the bar: its label always, captions when on."""
        text, captions = bar
        concat = out.with_suffix('.ffconcat')
        lines = ['ffconcat version 1.0']
        for path, seconds in entries:
            lines += [f"file '{Path(path).resolve().as_posix()}'", f'duration {seconds:.6f}']
        # The concat demuxer plays the last listed still for one frame only: list it twice, then trim to the total.
        lines.append(f"file '{Path(entries[-1][0]).resolve().as_posix()}'")
        concat.write_text('\n'.join(lines) + '\n', encoding='utf-8')
        total = sum(seconds for _, seconds in entries)
        draws = [f'drawbox=x=0:y=ih-{BAR}:w=iw:h={BAR}:color=black@0.78:t=fill',
                 self.text(text, 24, f'h-{BAR}+16', 30, '0xf59e0b' if speed != 1 else '0x22c55e')]
        draws += [self.text(c, 620, f'h-{BAR}+18', 26, 'white', (a, b)) for c, a, b in captions]
        graph = (f'[0:v]scale={SIZE[0]}:{SIZE[1]}:force_original_aspect_ratio=decrease,'
                 f'pad={SIZE[0]}:{SIZE[1]}:(ow-iw)/2:(oh-ih)/2:color={BACKGROUND},setsar=1,'
                 f'fps=30,trim=duration={total:.6f},' + ','.join(draws) + '[v]')
        script = out.with_suffix('.filter.txt')
        script.write_text(graph, encoding='utf-8')
        subprocess.run([FFMPEG, '-hide_banner', '-loglevel', 'error', '-y', '-f', 'concat', '-safe', '0', '-i', str(concat),
                        '-filter_complex_script', str(script), '-map', '[v]', '-an', '-c:v', 'libx264', '-preset', 'veryfast',
                        '-crf', '20', '-pix_fmt', 'yuv420p', '-movflags', '+faststart', str(out)], check=True)


def shown_frames(frames):
    """Screencast frames worth showing: a blank or empty page is skipped, so the frame before it stays on screen."""
    return {p: kept for p, v in frames.items() if (kept := [(t, f) for t, f in v if f.stat().st_size >= MIN_FRAME_BYTES])}


def active_seconds(times, start, end, hold=BROWSER_HOLD):
    """Real seconds of [start, end] within hold seconds after one of times: how long a browser was live."""
    total, reach = 0.0, start
    for t in sorted(times):
        a, b = max(t, reach, start), min(t + hold, end)
        if b > a:
            total += b - a
            reach = b
    return round(total, 3)


def longest_hold(times, start, end):
    """Longest real stretch of [start, end] in which the board sent no new frame."""
    inside = [t for t in times if start < t < end]
    edges = [start, *inside, end]
    return round(max(b - a for a, b in zip(edges, edges[1:])), 3)


def render(r, name, items, frames, intro, outro, speed, out):
    cards = {'intro': r.work / f'{name}-intro.jpg', 'outro': r.work / f'{name}-outro.jpg'}
    r.card(intro, cards['intro'])
    r.card(outro, cards['outro'])
    for i, item in enumerate(x for x in items if isinstance(x, Chapter)):
        cards[item] = r.work / f'{name}-chapter-{i:02d}.jpg'
        r.card(chapter_lines(item), cards[item])
    segs = timeline(items)
    r.video(listing(items, frames, cards, speed), speed, overlay(segs, speed), out)
    return segs


def cut(d, rec, actions, knobs, cov, out_dir=None):
    """Render video-full.mp4 (Option A, 1x) and video.mp4 (Option B, knobs.speed) from film.json's board capture
    in d; returns (and writes) edit.json. Outputs go to out_dir (default d), so a capture can be re-cut without
    touching an earlier cut."""
    d = Path(d)
    out_dir = Path(out_dir or d)
    frames = screencast.read_index(d, rec['board_index']).get(BOARD, [])
    if not frames:
        raise ValueError(f'{d}: no board frames to cut')
    start, end = max(rec['round_start'], frames[0][0]), rec['round_end']
    duration = round(end - start, 3)
    samples = read_states(d / rec['board_state'])
    stages, total = stage_timings(samples, start, end), wave_count(samples)
    rel = [(t - start, p) for t, p in frames]
    intro, outro = card_lines(rec['result'], cov, knobs, rec['case_id'], samples[-1][1] if samples else ())
    r = Renderer(out_dir / 'edit-work')
    cuts = {}
    for name, speed, video in (('full', 1.0, 'video-full.mp4'), ('reviewed', knobs.speed, 'video.mp4')):
        items = plan(duration, start, stages, actions, knobs, speed, total)
        cuts[name] = {'video': video, 'speed': speed, 'label': label(speed),
                      'segments': render(r, name, items, rel, intro, outro, speed, out_dir / video)}
        cuts[name]['out_seconds'] = cuts[name]['segments'][-1]['out_end']
    browsers = shown_frames(screencast.read_index(d / rec['screencast']))
    times = [t for t, _ in frames]
    edit = {'video': 'video.mp4', 'video_full': 'video-full.mp4', 'knobs': asdict(knobs), 'speed': knobs.speed,
            'label': label(knobs.speed), 't0': rec['t0'], 'round_start': start, 'round_end': end,
            'round_seconds': duration, 'out_seconds': cuts['reviewed']['out_seconds'], 'intro': intro, 'outro': outro,
            'segments': cuts['reviewed']['segments'], 'full': cuts['full'],
            'stages': [asdict(s) | {'seconds': round(s.seconds, 3)} for s in stages], 'stage_count': stage_count(samples),
            'wave_count': total,
            'board_frames': len(frames), 'longest_board_hold_seconds': longest_hold(times, start, end),
            'screencast_frames': {p: len(v) for p, v in browsers.items()},
            'browser_active_seconds': {p: active_seconds([t for t, _ in v], start, end) for p, v in browsers.items()},
            'browser_any_active_seconds': active_seconds([t for v in browsers.values() for t, _ in v], start, end)}
    (out_dir / 'edit.json').write_text(json.dumps(edit, indent=1), encoding='utf-8')
    return edit

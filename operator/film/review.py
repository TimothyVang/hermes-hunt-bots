"""Have Claude Opus watch a cut: contact sheets plus measured metrics in, one strict JSON review out.

Hermes one-shot takes one image, so the browser-moment sheet (the left panel at the bots' typed
searches and other lab_browser actions) and the whole-video overview are stacked into review.png.
One call; one retry if the reply is not valid JSON in the schema; never more than two calls.
"""
import json
import subprocess
from pathlib import Path

import tool_loops as tl
from film import edit as cutter
from lab_paths import FFMPEG

BROWSER_TILES, OVERVIEW_TILES = 6, 8
TEXT_MAX = 600
SUGGESTIONS_MAX, SUGGESTION_MAX = 5, 400

REVIEW_RULES = (
    "You review a short video of a six-bot AI threat hunt in a synthetic lab, for an operator tuning both the hunt and "
    "the filming. The image stacks two contact sheets. TOP (6 tiles): the video's left panel at moments when a bot "
    "acted in its own browser through lab_browser: the Threat Hunter drives the lab console (Elastic search page), the "
    "Network Analyst drives Arkime (Sessions / SPI View). Each tile's label is its video time and the caption shown "
    "then. BOTTOM (8 tiles): the whole 1920x1080 video at even intervals; left 1280px is the acting bot's browser or, "
    "when no bot drives, the lab activity console; right 640px is the lab_browser audit console (top) and stage "
    "progress (bottom). A bottom bar labels 1x real-time stretches and sped-up ones. All frames are real captures. "
    "The metrics below are measured from the edit and the logs; trust them over guesses from small tiles.\n"
    "Judge: is each web tool visibly being driven (a search typed into its Search box, results on screen); are typing "
    "and the in-page cursor visible; is text readable at 1080p; how much dead time is there. Then suggest (a) changes "
    "to the bots' brief or stage guidance that would make them drive their tools on screen more and better, as general "
    "technique (no case names, hosts, users, IPs), and (b) at most a few knob changes from this exact set: "
    "speed (number 2-30, sped-up factor), pad_before (0-10 s of real time before each browser action), pad_after "
    "(0-15 s after), captions (true/false), intro_title (1-80 characters, no digits). Set ready=true only if both tools "
    "are clearly driven on screen and the video is watchable as is.\n"
    "Reply with ONE JSON object only, no prose, no fences:\n"
    '{"tools": {"elastic": {"driven": true|false, "evidence": "..."}, "arkime": {"driven": true|false, "evidence": "..."}}, '
    '"typing_visible": true|false, "cursor_visible": true|false, "readability": 1-5, "readability_notes": "...", '
    '"dead_time": "...", "brief_suggestions": ["..."], "knobs": {"<knob>": <value>}, "ready": true|false, "summary": "..."}')


def _text(v, limit=TEXT_MAX):
    return isinstance(v, str) and 0 < len(v.strip()) <= limit


def validate(obj):
    """(review, problems): the review normalized when problems is empty."""
    if not isinstance(obj, dict):
        return None, ['reply must be a JSON object']
    problems = []
    tools = obj.get('tools')
    if not isinstance(tools, dict) or set(tools) != {'elastic', 'arkime'}:
        problems.append('tools must have exactly "elastic" and "arkime"')
    else:
        for name, t in tools.items():
            if not isinstance(t, dict) or type(t.get('driven')) is not bool or not _text(t.get('evidence')):
                problems.append(f'tools.{name} needs driven (true/false) and evidence (1-{TEXT_MAX} characters)')
    for key in ('typing_visible', 'cursor_visible', 'ready'):
        if type(obj.get(key)) is not bool:
            problems.append(f'{key} must be true or false')
    if type(obj.get('readability')) is not int or not 1 <= obj['readability'] <= 5:
        problems.append('readability must be an integer 1-5')
    for key in ('readability_notes', 'dead_time', 'summary'):
        if not _text(obj.get(key)):
            problems.append(f'{key} must be 1-{TEXT_MAX} characters')
    sugg = obj.get('brief_suggestions')
    if not isinstance(sugg, list) or len(sugg) > SUGGESTIONS_MAX or not all(_text(s, SUGGESTION_MAX) for s in sugg):
        problems.append(f'brief_suggestions must be a list of at most {SUGGESTIONS_MAX} strings of 1-{SUGGESTION_MAX} characters')
    knobs, knob_problems = cutter.check_knobs(obj.get('knobs', {}))
    problems += knob_problems
    extra = set(obj) - {'tools', 'typing_visible', 'cursor_visible', 'readability', 'readability_notes', 'dead_time',
                        'brief_suggestions', 'knobs', 'ready', 'summary'}
    if extra:
        problems.append('unknown keys: ' + ', '.join(sorted(extra)))
    if problems:
        return None, problems
    return {**obj, 'knobs': knobs}, []


def metrics(edit, cov):
    segs = edit['segments']

    def seconds(pick):
        return round(sum(s['out_end'] - s['out_start'] for s in segs if pick(s)), 1)
    sped = [s['out_end'] - s['out_start'] for s in segs if s['speed'] != 1.0]
    return {'video_seconds': edit['out_seconds'], 'capture_seconds': edit['capture_seconds'],
            'real_time_seconds': seconds(lambda s: s['speed'] == 1.0),
            'browser_screencast_seconds': seconds(lambda s: s['screencast']),
            'real_time_without_screencast_seconds': seconds(lambda s: s['speed'] == 1.0 and not s['screencast']),
            'sped_up_seconds': round(sum(sped), 1), 'longest_sped_up_stretch_seconds': round(max(sped, default=0), 1),
            'real_time_stretches': sum(1 for s in segs if s['speed'] == 1.0),
            'captions': sum(len(s['captions']) for s in segs), 'screencast_frames': edit['screencast_frames'],
            'knobs': edit['knobs'], 'driving_coverage': cov}


def browser_moments(edit, actions, n=BROWSER_TILES):
    """(video second, caption) for up to n browser actions, typed searches first, spread over the round."""
    segs = cutter.segments_of(edit)
    t0, end = edit['t0'], edit['capture_seconds']
    acts = sorted((a for a in actions if a.browser and 0 <= a.t - t0 <= end), key=lambda a: a.t)
    typed = [a for a in acts if a.typed]
    pick = _spread(typed, n)
    pick += _spread([a for a in acts if a not in pick], n - len(pick))
    return [(cutter.to_output(segs, _on_page(segs, a.profile, max(0.0, a.t - t0 - 0.5))), a.caption)
            for a in sorted(pick, key=lambda a: a.t)]


def _on_page(segs, profile, r):
    """r, or the start of the actor's own page later in the same real-time stretch when r falls before it."""
    for seg, nxt in zip(segs, segs[1:]):
        if (seg.start <= r < seg.end and seg.speed == 1.0 and seg.screencast != profile
                and nxt.speed == 1.0 and nxt.screencast == profile):
            return nxt.start + 0.5
    return r


def _spread(items, n):
    if n <= 0 or not items:
        return []
    if len(items) <= n:
        return list(items)
    return [items[round(i * (len(items) - 1) / (n - 1))] for i in range(n)] if n > 1 else [items[0]]


def _stamp(t):
    return f'{int(t // 60):02d}:{int(t % 60):02d}'


def sheet(d, edit, actions):
    """review.png: browser moments (left panel, 3x2) over the overview (whole frame, 4x2), each tile labelled."""
    d = Path(d)
    work = d / 'review-work'
    r = cutter.Renderer(work)
    video = d / edit['video']
    total = edit['out_seconds']
    overview = [(total * (i + 0.5) / OVERVIEW_TILES, '') for i in range(OVERVIEW_TILES)]
    groups = {'browser': (browser_moments(edit, actions), 'crop=1280:1080:0:0,scale=640:540', 18, '3x2', 640, 540),
              'overview': (overview, 'scale=480:270', 16, '4x2', 480, 270)}
    sheets = {}
    for name, (moments, scale, size, layout, w, h) in groups.items():
        out = work / f'{name}.png'
        if not moments:
            _ffmpeg(['-f', 'lavfi', '-i', f'color=c={cutter.BACKGROUND}:s=1920x1080:d=1', '-frames:v', '1', '-vf',
                     r.text('no lab_browser action was filmed in this round', '(w-text_w)/2', '(h-text_h)/2', 40, 'white')], out)
        else:
            for i, (t, caption) in enumerate(moments):
                label = _stamp(t) + (' · ' + caption[:70] if caption else '')
                vf = f'{scale},drawbox=x=0:y=0:w=iw:h={size + 12}:color=black@0.75:t=fill,' + r.text(label, 6, 5, size, 'white')
                _ffmpeg(['-ss', f'{t:.3f}', '-i', str(video), '-frames:v', '1', '-vf', vf], work / f'{name}-{i:02d}.png')
            _ffmpeg(['-start_number', '0', '-i', str(work / f'{name}-%02d.png'), '-frames:v', '1', '-vf', f'tile={layout}'], out)
        sheets[name] = out
    png = d / 'review.png'
    head = [r.text('Browser moments: the acting bot\'s own page (left panel)', 12, 10, 28, 'white'),
            r.text('Whole video overview', 12, 10, 28, 'white')]
    graph = (f'[0:v]pad=1920:ih+48:0:48:color={cutter.BACKGROUND},{head[0]}[a];'
             f'[1:v]pad=1920:ih+48:0:48:color={cutter.BACKGROUND},{head[1]}[b];[a][b]vstack=inputs=2[v]')
    _ffmpeg(['-i', str(sheets['browser']), '-i', str(sheets['overview']), '-filter_complex', graph, '-map', '[v]',
             '-frames:v', '1'], png)
    return png


def _ffmpeg(args, out):
    subprocess.run([FFMPEG, '-hide_banner', '-loglevel', 'error', '-y', *args, str(out)], check=True)


def consult(prompt, d, png, ask=tl.opus):
    """Ask once, retry once on a reply that is not valid JSON in the schema: {'review', 'problems', 'calls'}."""
    out, note = {'review': None, 'problems': [], 'calls': 0}, ''
    for attempt in (1, 2):
        out['calls'] = attempt
        try:
            obj = tl.json_reply(ask(prompt + note, d, f'review-{attempt}', image=png), 'reviewer')
        except (ValueError, subprocess.TimeoutExpired) as exc:
            out['problems'] = [str(exc)]
        else:
            out['review'], out['problems'] = validate(obj)
            if out['review']:
                break
        note = ('\n\nYour previous reply was REJECTED: ' + '; '.join(out['problems'])
                + '. Reply again with the JSON object only, exactly in the schema.')
    return out


def review(d, edit, actions, cov, result):
    """Writes and returns d/review.json: consult()'s result plus the metrics and the sheet's name."""
    d = Path(d)
    png = sheet(d, edit, actions)
    m = metrics(edit, cov)
    first = result['rounds'][0] if result.get('rounds') else {}
    context = {'metrics': m, 'round': {'found': first.get('found', 0), 'total': first.get('total', 18),
                                       'misattributed_decoys': result.get('misattributed', 0), 'halts': result.get('halts', 0)},
               'captions_sample': [c['text'] for s in edit['segments'] for c in s['captions']][:30]}
    out = {**consult(REVIEW_RULES + '\n\n' + json.dumps(context, indent=1), d, png), 'metrics': m, 'sheet': png.name}
    (d / 'review.json').write_text(json.dumps(out, indent=1), encoding='utf-8')
    return out

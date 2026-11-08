"""Have Claude Opus watch a loop's cuts: contact sheets plus measured metrics in, one strict JSON review out.

Hermes one-shot takes one image, so each lane's browser-moment sheet (the bots' own browser screencast
frames at their typed searches and other lab_browser actions) and the overview of its reviewed cut (the
Hunt Live board at one constant speed) are stacked into its review.png, and the lanes' sheets are stacked
again, each under its lane's name, into the loop's review.png. One call; one retry if the reply is not
valid JSON in the schema; never more than two calls.
"""
import json
import subprocess
from pathlib import Path

import tool_loops as tl
from film import edit as cutter
from film import screencast
from lab_paths import FFMPEG

BROWSER_TILES, OVERVIEW_TILES = 6, 8
TEXT_MAX = 600
SUGGESTIONS_MAX, SUGGESTION_MAX = 5, 400

REVIEW_RULES = (
    "You review short videos of a six-bot AI threat hunt in a synthetic lab, for an operator tuning both the hunt and "
    "the filming. Each lane is an independent lab that ran the same brief at the same time; the image holds one block "
    "per lane, under its lane name when there are several, and each block stacks two contact sheets. TOP (6 tiles): "
    "the bots' own browsers, filmed by screencast, at moments when a bot acted through lab_browser: the Threat Hunter "
    "drives Kibana Discover (Elastic), the Network Analyst drives Arkime (Sessions / SPI View). Each tile's label is "
    "the video time and the caption shown then. BOTTOM (8 tiles): the whole reviewed 1920x1080 video at even "
    "intervals. That video is the Hunt Live board page (the 9-stage workflow, each bot's tool calls, the cited "
    "evidence, and both bots' live browsers) played at one constant speed, with a chapter card at each real stage "
    "start and a bottom bar holding the speed label and a caption naming the bot and tool acting. All frames are real "
    "captures. The metrics below are measured from the edits and the logs, per lane and as the mean over lanes; "
    "trust them over guesses from small tiles. Judge all lanes together.\n"
    "Judge: is each web tool visibly being driven (a search typed into its Search box, results on screen); are typing "
    "and the in-page cursor visible; is text readable at 1080p; how much dead time is there. Then suggest (a) changes "
    "to the bots' brief or stage guidance that would make them drive their tools on screen more and better, as general "
    "technique (no case names, hosts, users, IPs), and (b) at most a few knob changes from this exact set: "
    "speed (number 2-30, the constant speed of the reviewed video), captions (true/false), intro_title (1-80 "
    "characters, no digits). Set ready=true only if both tools are clearly driven on screen and the video is "
    "watchable as is.\n"
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
    """Measured from the reviewed cut (screen seconds) and the round (real seconds where named so)."""
    segs = edit['segments']
    board = [s for s in segs if s['kind'] == 'board']
    speed = edit['speed']

    def screen(real):
        return round(real / speed, 1)
    return {'video_seconds': edit['out_seconds'], 'round_seconds': edit['round_seconds'], 'speed': speed,
            'board_seconds': round(sum(s['out_end'] - s['out_start'] for s in board), 1),
            'chapter_cards': sum(1 for s in segs if s['kind'] == 'chapter'),
            'stages_filmed': len(edit['stages']), 'stages_finished': sum(1 for s in edit['stages'] if s['finished']),
            'longest_chapter_seconds': round(max((s['out_end'] - s['out_start'] for s in board), default=0), 1),
            'longest_frozen_board_seconds': screen(edit['longest_board_hold_seconds']),
            'browser_on_screen_seconds': screen(edit['browser_any_active_seconds']),
            'browser_on_screen_seconds_by_bot': {p: screen(v) for p, v in edit['browser_active_seconds'].items()},
            'captions': sum(len(s['captions']) for s in board), 'board_frames': edit['board_frames'],
            'screencast_frames': edit['screencast_frames'], 'knobs': edit['knobs'], 'driving_coverage': cov}


def browser_moments(edit, actions, browsers, n=BROWSER_TILES):
    """(video second, caption, screencast frame) for up to n browser actions, typed searches first, spread over the
    round. browsers is {profile: [(t, path)]}, the shown screencast frames; the frame is the actor's page just after
    the action or, before its first frame, its first one within a few seconds."""
    start, end = edit['round_start'], edit['round_end']
    acts = sorted((a for a in actions if a.browser and start <= a.t <= end and _frame(browsers, a)), key=lambda a: a.t)
    typed = [a for a in acts if a.typed]
    pick = _spread(typed, n)
    pick += _spread([a for a in acts if a not in pick], n - len(pick))
    return [(cutter.to_output(edit['segments'], a.t - start), a.caption, _frame(browsers, a))
            for a in sorted(pick, key=lambda a: a.t)]


def _frame(browsers, action, after=1.5, ahead=5.0):
    frames = browsers.get(action.profile) or []
    before = [p for t, p in frames if t <= action.t + after]
    if before:
        return before[-1]
    return next((p for t, p in frames if t <= action.t + ahead), None)


def _spread(items, n):
    if n <= 0 or not items:
        return []
    if len(items) <= n:
        return list(items)
    return [items[round(i * (len(items) - 1) / (n - 1))] for i in range(n)] if n > 1 else [items[0]]


def _stamp(t):
    return f'{int(t // 60):02d}:{int(t % 60):02d}'


def sheet(d, edit, actions):
    """review.png: browser moments (the bots' screencast frames, 3x2) over the reviewed video's overview (4x2),
    each tile labelled."""
    d = Path(d)
    work = d / 'review-work'
    r = cutter.Renderer(work)
    video = d / edit['video']
    total = edit['out_seconds']
    browsers = cutter.shown_frames(screencast.read_index(d / 'screencast'))
    overview = [(total * (i + 0.5) / OVERVIEW_TILES, '', video) for i in range(OVERVIEW_TILES)]
    fit = 'scale={w}:{h}:force_original_aspect_ratio=decrease,pad={w}:{h}:(ow-iw)/2:(oh-ih)/2:color=' + cutter.BACKGROUND
    groups = {'browser': (browser_moments(edit, actions, browsers), fit.format(w=640, h=540), 18, '3x2'),
              'overview': (overview, 'scale=480:270', 16, '4x2')}
    sheets = {}
    for name, (moments, scale, size, layout) in groups.items():
        out = work / f'{name}.png'
        if not moments:
            _ffmpeg(['-f', 'lavfi', '-i', f'color=c={cutter.BACKGROUND}:s=1920x1080:d=1', '-frames:v', '1', '-vf',
                     r.text('no lab_browser action was filmed in this round', '(w-text_w)/2', '(h-text_h)/2', 40, 'white')], out)
        else:
            for i, (t, caption, source) in enumerate(moments):
                label = _stamp(t) + (' · ' + caption[:70] if caption else '')
                vf = f'{scale},drawbox=x=0:y=0:w=iw:h={size + 12}:color=black@0.75:t=fill,' + r.text(label, 6, 5, size, 'white')
                seek = ['-ss', f'{t:.3f}'] if source == video else []
                _ffmpeg([*seek, '-i', str(source), '-frames:v', '1', '-vf', vf], work / f'{name}-{i:02d}.png')
            _ffmpeg(['-start_number', '0', '-i', str(work / f'{name}-%02d.png'), '-frames:v', '1', '-vf', f'tile={layout}'], out)
        sheets[name] = out
    png = d / 'review.png'
    head = [r.text('Browser moments: the acting bot\'s own browser', 12, 10, 28, 'white'),
            r.text('Reviewed video overview: the Hunt Live board', 12, 10, 28, 'white')]
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


def mean_metrics(per_lane):
    """Each numeric metric averaged over lanes."""
    keys = [k for k, v in next(iter(per_lane.values())).items() if type(v) in (int, float)]
    return {k: round(sum(m[k] for m in per_lane.values()) / len(per_lane), 2) for k in keys}


def stack(d, sheets):
    """d/review.png: the lanes' review sheets one under another, each under its lane's name."""
    r = cutter.Renderer(Path(d) / 'review-work')
    inputs, graph = [], []
    for i, (name, png) in enumerate(sheets.items()):
        inputs += ['-i', str(png)]
        graph.append(f'[{i}:v]pad=1920:ih+56:0:56:color=0x1e293b,{r.text(f"LANE {name}", 12, 10, 36, "0xfbbf24")}[l{i}]')
    png = Path(d) / 'review.png'
    _ffmpeg([*inputs, '-filter_complex', ';'.join(graph) + ';' + ''.join(f'[l{i}]' for i in range(len(sheets)))
             + f'vstack=inputs={len(sheets)}[v]', '-map', '[v]', '-frames:v', '1'], png)
    return png


def review(d, cuts, ask=tl.opus):
    """Writes and returns d/review.json: consult()'s result plus per-lane and mean metrics and the image's name.
    cuts: one {'lane', 'd', 'edit', 'actions', 'cov', 'result'} per lane that has a cut."""
    d = Path(d)
    sheets = {c['lane']: sheet(c['d'], c['edit'], c['actions']) for c in cuts}
    png = next(iter(sheets.values())) if len(sheets) == 1 else stack(d, sheets)
    per = {c['lane']: metrics(c['edit'], c['cov']) for c in cuts}
    lanes = {}
    for c in cuts:
        result, first = c['result'], (c['result'].get('rounds') or [{}])[0]
        lanes[c['lane']] = {'metrics': per[c['lane']],
                            'round': {'found': first.get('found', 0), 'total': first.get('total', 18),
                                      'misattributed_decoys': result.get('misattributed', 0), 'halts': result.get('halts', 0)},
                            'stages': c['edit']['stages'],
                            'captions_sample': [x['text'] for s in c['edit']['segments'] if s['kind'] == 'board'
                                                for x in s['captions']][:20]}
    m = {'lanes': per, 'mean': mean_metrics(per)}
    context = {'lanes': lanes, 'mean_over_lanes': m['mean']}
    out = {**consult(REVIEW_RULES + '\n\n' + json.dumps(context, indent=1), d, png, ask), 'metrics': m,
           'sheet': str(png.relative_to(d))}
    (d / 'review.json').write_text(json.dumps(out, indent=1), encoding='utf-8')
    return out

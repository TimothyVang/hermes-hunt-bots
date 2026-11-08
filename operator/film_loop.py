"""Filmed full-mode watcher loop (operator-only; reads answer keys).

Each loop runs one real round of the six-bot hunt with the Threat Hunter driving Kibana Discover
(Elastic) and the Network Analyst driving Arkime through lab_browser, films it (film/record.py),
scores it against the operator-only key (tool_loops.score), measures driving coverage from the
lab_browser audit and the lab's /activity log (film/actions.py), cuts a video (film/edit.py) and has
Claude Opus review the video (film/review.py). A watcher (tool_loops.watcher, Opus) then proposes
the next brief, stage guidance and drive note, seeing the score breakdown, the coverage and the
video review, never the key.

LANES (--lanes, see film/lanes.py): each loop runs the same round on every lane at the same time. A lane
is a fully separate lab (Hermes home, lab VM, lab_browser state, Temporal task queue and worker) filmed
in its own 1920x1080 screen region. The loop's found and coverage are the means over lanes; halts and
blamed decoys are summed, so a halt or blamed decoy in any lane fails the keep rule. Without --lanes
there is one lane, the lab the environment names, with the folders and workflow IDs of a single run.

Driving coverage: per browser owner, the share of its distinct API searches it also typed into its
web tool, or 0 if it skipped either; a lane's coverage is the two owners' mean.
KEEP: 0 decoys blamed and no halted round, and (found >= best and coverage > best) or
      (found > best and coverage >= best - 0.1) or (coverage >= best + 0.2 and found >= best - 2).
STOP: the best loop found 18/18 with coverage >= 0.8 and its review says ready; or --loops loops;
      or 3 loops in a row without a kept change.

Loop 0 films the best tool-loops config (tool-loops/BEST.json, else the base brief) with the
default drive note. Gates are approved by drive_gates.py on --delegated-by's behalf, as in
tool_loops.py, one driver per lane. State goes to runtime/practice/film-loops/: state.json, BEST.json,
BEST.mp4 (the kept loop's best lane's cut) and one film-NN directory per loop (review.png, review.json,
decision.json, and each lane's captures and video.mp4 in film-NN/<lane>/, or in film-NN/ for one unnamed lane).

Usage: python operator/film_loop.py <case> <truth> --delegated-by "<person>" --reason "<text>" [--loops 8] [--tag=-a]
       [--lanes lanes.json] [--resume]
"""
import argparse
import json
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from pathlib import Path

import tool_loops as tl
from film import actions as acts
from film import edit as cutter
from film import lanes as film_lanes
from film import record
from film import review as reviewer
from lab_paths import DEFAULT_LANE, FILM_LOOPS, FRAMEWORK, TOOL_LOOPS

BUDGET, PLATEAU, PERFECT_FOUND, READY_COVERAGE, COVERAGE_SLACK = 8, 3, 18, 0.8, 0.1
# One filmed round per loop: identical configs have scored 4-12 of 18 across rounds, so a large driving gain
# is kept when the score falls by no more than this one-round noise band.
COVERAGE_JUMP, FOUND_NOISE = 0.2, 2
DRIVE_MAX = 700
DRIVE_NOTE = (
    'Threat Hunter and Network Analyst, filmed run: show your hunt on screen with lab_browser. Threat Hunter: for '
    'each elastic_search that matters, also open the kibana_discover page with the same q (it is typed into Kibana\'s '
    'query bar), then expand a document or add a field filter. Network Analyst: do the same on arkime_sessions or '
    'arkime_spiview for your Arkime expressions. Choose the searches yourself; cite only what your tools returned.')
FILM_RULES = tl.WATCHER_RULES + (
    '\nTHIS LOOP IS FILMED IN FULL MODE. The Threat Hunter must run its Elastic hunt on screen in Kibana Discover and '
    'the Network Analyst its Arkime hunt in Arkime, both with lab_browser (open with a search types it into the page; '
    'type/click/scroll/read act on the page). Kibana\'s query bar takes the same Lucene query string as elastic_search. '
    'You also see the last loop\'s driving coverage (per owner: typed browser searches, the share of its distinct API '
    'searches it also ran in the browser, whether it used both), its score breakdown, and a review by a model that '
    'watched the cut video. Each loop runs the same configuration on one or more independent labs (lanes) at the same '
    'time; found, coverage and halts are judged on the mean over lanes (any halt or blamed decoy in any lane counts), '
    'and you see each lane\'s numbers. A change is kept only with 0 decoys blamed and no halt, and either more coverage at the same '
    'or better score, or a better score with coverage at most 0.1 lower, or a coverage gain of at least 0.2 with the '
    'score at most 2 lower (one-round noise). Your JSON object must also carry "drive_note": '
    'the full on-screen driving instruction for those two bots (1-700 characters, naming lab_browser), appended to the '
    'brief. It is part of your one change; keep it general technique too.')


def compose(brief, drive_note):
    return brief + ' ' + drive_note


def check_config(base, brief, guidance, drive_note, case_id, forbidden):
    """tool_loops' checks on the watcher's brief and guidance, plus the drive note and the composed input's caps."""
    problems = tl.check_candidate(base, brief, guidance, case_id, forbidden)
    if not 1 <= len(drive_note) <= DRIVE_MAX or 'lab_browser' not in drive_note:
        problems.append(f'drive_note must be 1..{DRIVE_MAX} characters and name lab_browser')
    hits = sorted(t for t in forbidden if t and t in drive_note.lower())
    if hits:
        problems.append('case-specific terms are not allowed in drive_note: ' + ', '.join(hits[:12]))
    try:
        sys.path.insert(0, str(FRAMEWORK))
        from hermes_temporal.hunt import supplied_evidence_hunt
        supplied_evidence_hunt(tl.build_input(base, compose(brief, drive_note), guidance, case_id))
    except Exception as exc:  # cap or validation failure, reported to the watcher
        problems.append(f'brief plus drive_note rejected: {exc}')
    return problems


def keep(new, best):
    if new['misattributed'] or new['halts']:
        return False
    return ((new['found'] >= best['found'] and new['coverage'] > best['coverage'])
            or (new['found'] > best['found'] and new['coverage'] >= best['coverage'] - COVERAGE_SLACK)
            or (new['coverage'] >= best['coverage'] + COVERAGE_JUMP and new['found'] >= best['found'] - FOUND_NOISE))


def finished(best):
    return (best['found'] >= PERFECT_FOUND and best['coverage'] >= READY_COVERAGE
            and bool((best.get('review') or {}).get('ready')))


def load_actions(d, rec):
    audit = (d / rec['audit']).read_text(encoding='utf-8').splitlines()
    activity = json.loads((d / rec['activity']).read_text(encoding='utf-8'))
    return acts.from_audit(audit, rec['round_start'], rec['round_end']) + acts.from_activity(activity), activity


def lane_dir(d, lane):
    """A lane's folder in a loop folder; the single default lane keeps the loop folder itself."""
    return d / lane.name if lane.name else d


def film_lane(n, lane, args, base, cfg, knobs):
    """Film, score, measure and cut one lane's round; returns (lane outcome, cut for the review or None, tool digest)."""
    name = f'film-{n:02d}'
    d = lane_dir(FILM_LOOPS / name, lane)
    rec = record.film(d, name, base, compose(cfg['brief'], cfg['drive_note']), cfg['guidance'], args.dev_case,
                      args.dev_truth, lane)
    result = rec['result']
    actions, activity = load_actions(d, rec)
    cov = acts.coverage(actions)
    edit = cutter.cut(d, rec, actions, knobs, cov) if rec['raw'] else None
    who = film_lanes.label(lane)
    out = {'lane': who, 'found': result['mean_found'], 'coverage': cov['coverage'], 'misattributed': result['misattributed'],
           'halts': result['halts'], 'result': result, 'driving': cov,
           'video': str(d / edit['video']) if edit else None, 'privacy_abort': rec['privacy_abort']}
    cut = {'lane': who, 'd': d, 'edit': edit, 'actions': actions, 'cov': cov, 'result': result} if edit else None
    return out, cut, tl.tool_digest(activity)


def aggregate(lane_outs):
    """A loop's numbers from its lanes: mean found and coverage; halts and blamed decoys summed, so one lane's
    halt or blamed decoy fails the keep rule for the loop."""
    outs = list(lane_outs.values())
    return {'found': round(sum(o['found'] for o in outs) / len(outs), 3),
            'coverage': round(sum(o['coverage'] for o in outs) / len(outs), 3),
            'halts': sum(o['halts'] for o in outs), 'misattributed': sum(o['misattributed'] for o in outs)}


def best_lane(lane_outs):
    """The lane whose cut stands for the loop: a clean lane (no halt, no blamed decoy) first, then most facts
    found, then most coverage; None when no lane has a cut."""
    filmed = [o for o in lane_outs.values() if o['video']]
    if not filmed:
        return None
    return max(filmed, key=lambda o: (not o['halts'] and not o['misattributed'], o['found'], o['coverage']))['lane']


def run_loop(n, args, bases, cfg, knobs, lanes):
    """Run one round on every lane at the same time, then review all the cuts together; returns the loop's outcome
    and each lane's tool digest."""
    name = f'film-{n:02d}'
    with ThreadPoolExecutor(max_workers=len(lanes), thread_name_prefix='film-lane') as pool:
        futures = [pool.submit(film_lane, n, lane, args, bases[film_lanes.label(lane)], cfg, knobs) for lane in lanes]
    done = [f.result() for f in futures]
    lane_outs = {o['lane']: o for o, _, _ in done}
    cuts = [c for _, c, _ in done if c]
    rv = (reviewer.review(FILM_LOOPS / name, cuts) if cuts
          else {'review': None, 'problems': ['no desktop capture to cut'], 'metrics': None})
    top = best_lane(lane_outs)
    out = {'loop': n, 'name': name, **cfg, **aggregate(lane_outs), 'lanes': lane_outs, 'best_lane': top,
           'review': rv['review'], 'review_problems': rv['problems'], 'video_metrics': rv['metrics'],
           'video': lane_outs[top]['video'] if top else None}
    tl.log(f'{name}: found {out["found"]:.1f}/18 coverage {out["coverage"]:.2f} halts {out["halts"]} '
           f'misattributed {out["misattributed"]} review ready={bool((rv["review"] or {}).get("ready"))} lanes '
           + ', '.join(f'{k}={o["found"]:.0f}/{o["coverage"]:.2f}' for k, o in lane_outs.items()))
    return out, {o['lane']: digest for o, _, digest in done}


def lane_numbers(outcome):
    return {k: {key: o[key] for key in ('found', 'coverage', 'halts', 'misattributed')} for k, o in outcome['lanes'].items()}


def context_for(state):
    best, last = state['best'], state['last']
    lanes = {k: {'found_of_18': o['found'], 'driving_coverage': o['driving'], 'misattributed_decoys': o['misattributed'],
                 'halts': o['halts'], 'score_breakdown': o['result']['rounds'], 'tool_calls_by_bot': state['last_calls'].get(k)}
             for k, o in last['lanes'].items()}
    return {'goal': 'find every attack step, decoy, benign pattern and coverage gap with full event.id citations; never '
                    'blame a decoy; complete all 9 stages; and show the hunt on screen: the Threat Hunter runs its key '
                    'Elastic searches in Kibana Discover and the Network Analyst its Arkime searches in Arkime',
            'best_so_far': {'loop': best['loop'], 'found_of_18_mean': best['found'], 'driving_coverage_mean': best['coverage'],
                            'lanes': lane_numbers(best), 'brief': best['brief'], 'stage_guidance': best['guidance'],
                            'drive_note': best['drive_note']},
            'last_evaluated': {'loop': last['loop'], 'found_of_18_mean': last['found'], 'driving_coverage_mean': last['coverage'],
                               'misattributed_decoys_all_lanes': last['misattributed'], 'halts_all_lanes': last['halts'],
                               'lanes': lanes, 'video_review': last['review'], 'video_review_problems': last['review_problems'],
                               'video_metrics': last['video_metrics'],
                               f'round1_reports_lane_{last["best_lane"] or next(iter(last["lanes"]))}': state['last_reports']},
            'history': [{k: h[k] for k in ('loop', 'found', 'coverage', 'kept', 'ready', 'hypothesis')} for h in state['history']]}


def propose(state, d, base, args, forbidden):
    note = ''
    for _ in range(3):
        try:
            obj = tl.watcher(context_for(state), d, note, rules=FILM_RULES)
        except (ValueError, subprocess.TimeoutExpired) as exc:
            note = f'\n\nYour previous reply could not be used ({exc}). Reply with the JSON object only.'
            continue
        cfg = {'brief': ' '.join(str(obj.get('brief', '')).split()),
               'guidance': {k: ' '.join(str(v).split()) for k, v in (obj.get('stage_guidance') or {}).items() if str(v).strip()},
               'drive_note': ' '.join(str(obj.get('drive_note', '')).split())}
        problems = check_config(base, cfg['brief'], cfg['guidance'], cfg['drive_note'], args.dev_case, forbidden)
        if not problems:
            (d / 'proposal.json').write_text(json.dumps(obj, indent=2), encoding='utf-8')
            return obj, cfg
        note = '\n\nYour previous proposal was REJECTED: ' + '; '.join(problems) + '. Fix these and reply again.'
    return None, None


def save(state):
    (FILM_LOOPS / 'state.json').write_text(json.dumps(state, indent=1), encoding='utf-8')
    best = state['best']
    (FILM_LOOPS / 'BEST.json').write_text(json.dumps(
        {k: best[k] for k in ('loop', 'brief', 'guidance', 'drive_note', 'found', 'coverage', 'review', 'best_lane', 'video')}
        | {'lanes': lane_numbers(best), 'finished': finished(best)}, indent=2), encoding='utf-8')


def adopt(state, outcome, digests):
    """Record a finished loop as the last evaluated, and the knob changes its review asked for."""
    state['last'], state['last_calls'] = outcome, digests
    lane = outcome['lanes'][outcome['best_lane'] or next(iter(outcome['lanes']))]
    state['last_reports'] = tl.report_digest(lane['result']['workflow'], 1)
    changes = (outcome['review'] or {}).get('knobs') or {}
    state['knobs'] = asdict(cutter.apply_knobs(cutter.Knobs(**state['knobs']), changes))


def promote(state, outcome):
    """Make the loop the best; BEST.mp4 becomes its best lane's cut (a side-by-side would halve each lane's size)."""
    state['best'] = outcome
    if outcome['video']:
        shutil.copyfile(outcome['video'], FILM_LOOPS / 'BEST.mp4')


def upgrade(state):
    """Give a state saved before lanes existed its one lane, so a resumed single-lane series carries on."""
    if 'lanes' in state['last']:
        return state
    for key in ('best', 'last'):
        o = state[key]
        o['lanes'] = {'default': {'lane': 'default', **{k: o.get(k) for k in (
            'found', 'coverage', 'misattributed', 'halts', 'result', 'driving', 'video', 'privacy_abort')}}}
        o['best_lane'] = 'default' if o.get('video') else None
    state['last_calls'] = {'default': state['last_calls']}
    return state


def rejudge_last(state, reason):
    """Re-apply the current keep rule to the last evaluated loop after the rule itself changed.

    Only a reverted loop that is still state['last'] qualifies; the best it was compared against is unchanged
    because a reverted loop never replaces it. Returns True when the loop is now kept."""
    entry = state['history'][-1] if state['history'] else None
    last = state.get('last')
    if not entry or entry['kept'] or not last or entry['loop'] != last['loop']:
        tl.log(f'rejudge: nothing to re-judge ({reason})')
        return False
    before = state['best']
    if not keep(last, before):
        tl.log(f'rejudge film-{last["loop"]:02d}: still reverted under the current rule ({reason})')
        return False
    entry['kept'] = True
    promote(state, last)
    state['no_gain'] = 0
    decision = FILM_LOOPS / f'film-{last["loop"]:02d}' / 'decision.json'
    if decision.exists():
        record = json.loads(decision.read_text(encoding='utf-8'))
        decision.write_text(json.dumps(record | {'kept': True, 'rejudged': reason}, indent=2), encoding='utf-8')
    tl.log(f'rejudge film-{last["loop"]:02d}: KEPT under the current rule (found {last["found"]:.0f} vs '
           f'{before["found"]:.0f}, coverage {last["coverage"]:.2f} vs {before["coverage"]:.2f}): {reason}')
    return True


def parse_args(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('dev_case', help='case ID loaded in the lab VM')
    ap.add_argument('dev_truth', help='operator-only answer key (truth.json) for dev_case')
    ap.add_argument('--delegated-by', required=True, help='person who delegated the gate approvals (see drive_gates.py)')
    ap.add_argument('--reason', required=True, help='their instruction, recorded in every approval note')
    ap.add_argument('--sealed-truth', help='optional extra forbidden-terms source')
    ap.add_argument('--loops', type=int, default=BUDGET, help='watcher loops after loop 0')
    ap.add_argument('--resume', action='store_true')
    ap.add_argument('--tag', default='', help='suffix for workflow IDs so a restarted series never reuses one')
    ap.add_argument('--lanes', metavar='JSON',
                    help='lanes file (see film/lanes.py): run each loop on these independent labs at the same time; '
                         'default one lane, the lab HUNT_BOTS_LAB_HOME and HUNT_BOTS_TASK_QUEUE name')
    ap.add_argument('--rejudge-last', metavar='REASON',
                    help='with --resume: re-apply the current keep rule to the last loop if it was reverted; REASON is logged')
    ap.add_argument('--reset-plateau', metavar='REASON',
                    help='with --resume: zero the no-gain counter after an infrastructure fix; REASON is logged')
    ap.add_argument('--seed', metavar='BEST_JSON',
                    help='new series only: start loop 0 from this BEST.json (a film-loop one with brief, guidance and '
                         'drive_note, or a tool-loop one with brief and stage_guidance); default the tool-loop BEST.json')
    args = ap.parse_args(argv)
    for name in ('dev_truth', 'sealed_truth'):
        truth = getattr(args, name)
        if truth:
            if not Path(truth).is_file():
                ap.error(f'answer key not found: {truth}')
            setattr(args, name, str(Path(truth).resolve()))
    if args.lanes and not Path(args.lanes).is_file():
        ap.error(f'lanes file not found: {args.lanes}')
    if args.seed and not Path(args.seed).is_file():
        ap.error(f'seed not found: {args.seed}')
    return args


def seed_config(seed, base):
    """Loop 0's config from a film-loop or tool-loop BEST.json (an empty dict means the case's own brief)."""
    return {'brief': seed.get('brief') or base['scope'].split(' only; ', 1)[1],
            'guidance': seed.get('guidance') or seed.get('stage_guidance') or {},
            'drive_note': seed.get('drive_note') or DRIVE_NOTE}


def start_lanes(args):
    """The lanes to run and each lane's hunt input, after checking they cannot interfere and all hold dev_case."""
    lanes = film_lanes.load(args.lanes)
    problems = film_lanes.problems(lanes) + film_lanes.gateway_problems(lanes)
    if problems:
        raise SystemExit('lanes rejected: ' + '; '.join(problems))
    bases = {}
    for lane in lanes:
        lane.hermes_exe()
        base = tl.base_input(args.dev_case, lane)
        if base['ontology']['case_id'] != args.dev_case:
            raise SystemExit(f"lane {film_lanes.label(lane)} has {base['ontology']['case_id']} loaded, not {args.dev_case}")
        bases[film_lanes.label(lane)] = base
    return lanes, bases


def main(args):
    tl.RUN_TAG, tl.ROUNDS, tl.LOG = args.tag, 1, FILM_LOOPS / 'loop.log'
    tl.GATE_ARGS[:] = ['--delegated-by', args.delegated_by, '--reason', args.reason]
    DEFAULT_LANE.hermes_exe()
    FILM_LOOPS.mkdir(parents=True, exist_ok=True)
    forbidden = tl.forbidden_terms(*[p for p in (args.dev_truth, args.sealed_truth) if p])
    lanes, bases = start_lanes(args)
    base = bases[film_lanes.label(lanes[0])]
    tl.log('lanes: ' + ', '.join(f'{film_lanes.label(x)} home={x.home} queue={x.task_queue} region={x.region}' for x in lanes))
    state_path = FILM_LOOPS / 'state.json'
    if args.resume and state_path.exists():
        state = upgrade(json.loads(state_path.read_text(encoding='utf-8')))
        if args.rejudge_last:
            rejudge_last(state, args.rejudge_last)
        if args.reset_plateau:
            tl.log(f'plateau counter reset from {state["no_gain"]}: {args.reset_plateau}')
            state['no_gain'] = 0
        save(state)
    else:
        start = Path(args.seed) if args.seed else TOOL_LOOPS / 'BEST.json'
        seed = json.loads(start.read_text(encoding='utf-8')) if start.exists() else {}
        cfg = seed_config(seed, base)
        tl.log(f'loop 0 config from {start if seed else "the case brief"}')
        problems = check_config(base, cfg['brief'], cfg['guidance'], cfg['drive_note'], args.dev_case, forbidden)
        if problems:
            raise SystemExit('starting config rejected: ' + '; '.join(problems))
        state = {'history': [], 'no_gain': 0, 'knobs': asdict(cutter.Knobs())}
        outcome, digest = run_loop(0, args, bases, cfg, cutter.Knobs(**state['knobs']), lanes)
        adopt(state, outcome, digest)
        promote(state, outcome)
        save(state)
    for n in range(len(state['history']) + 1, args.loops + 1):
        best = state['best']
        if finished(best):
            tl.log(f'FINISHED at loop {best["loop"]}: 18/18, coverage {best["coverage"]:.2f}, review ready')
            break
        if state['no_gain'] >= PLATEAU:
            tl.log(f'plateau: {PLATEAU} loops without a kept change; stopping')
            break
        d = FILM_LOOPS / f'film-{n:02d}'
        d.mkdir(parents=True, exist_ok=True)
        obj, cfg = propose(state, d, base, args, forbidden)
        if cfg is None:
            tl.log(f'film-{n:02d}: watcher produced no valid proposal; counted as no gain')
            state['history'].append({'loop': n, 'found': None, 'coverage': None, 'kept': False, 'ready': False,
                                     'hypothesis': 'no valid proposal'})
            state['no_gain'] += 1
            save(state)
            continue
        knobs = cutter.Knobs(**state['knobs'])
        outcome, digest = run_loop(n, args, bases, cfg, knobs, lanes)
        kept = keep(outcome, best)
        adopt(state, outcome, digest)
        state['history'].append({'loop': n, 'found': outcome['found'], 'coverage': outcome['coverage'], 'kept': kept,
                                 'ready': bool((outcome['review'] or {}).get('ready')), 'lanes': lane_numbers(outcome),
                                 'hypothesis': str(obj.get('hypothesis', ''))[:400]})
        if kept:
            promote(state, outcome)
            state['no_gain'] = 0
        else:
            state['no_gain'] += 1
        (d / 'decision.json').write_text(json.dumps(
            {'kept': kept, 'found': outcome['found'], 'coverage': outcome['coverage'],
             'misattributed': outcome['misattributed'], 'halts': outcome['halts'], 'lanes': lane_numbers(outcome),
             'best_lane': outcome['best_lane'],
             'best_before': {'loop': best['loop'], 'found': best['found'], 'coverage': best['coverage']},
             'knobs_used': asdict(knobs), 'knobs_next': state['knobs']}, indent=2), encoding='utf-8')
        tl.log(f'film-{n:02d}: {"KEPT" if kept else "reverted"} (found {outcome["found"]:.1f} vs {best["found"]:.1f}, '
               f'coverage {outcome["coverage"]:.2f} vs {best["coverage"]:.2f})')
        save(state)
    best = state['best']
    save(state)
    tl.log(f'done: best loop {best["loop"]} found {best["found"]:.0f}/18 coverage {best["coverage"]:.2f} '
           f'finished={finished(best)}')


if __name__ == '__main__':
    raise SystemExit(main(parse_args()) or 0)

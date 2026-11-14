"""Watcher improvement loop for the tool-driven six-bot hunt (operator-only; reads answer keys).

Each loop: run the hunt with the current brief + per-stage guidance (2 rounds), collect every
real tool call from the lab's /activity log and every stage report, score the final reports
against the operator-only key, then ask a watcher model (Claude Opus through the lab's own
Hermes default profile, no tools) for ONE focused change. A change is kept only if it raises
the mean score by >= 1 fact and does not add halts. The watcher never sees answer keys; it sees
case-agnostic fact categories, the bots' own tool calls and reports, and refusal reasons.

PERFECT (fixed before any run):
  dev:    two consecutive rounds each 18/18 found, 0 misattributed decoys, 0 halted stages;
  sealed: then the best config scores >= 16/18 per round on a different-story case the watcher
          never saw, with every attack fact found and 0 misattributed decoys.
STOP: perfect, or MAX_LOOPS loops, or PLATEAU loops in a row without a kept change.

Every hunt's gates are approved by operator/drive_gates.py, so the loop needs the same explicit
--delegated-by and --reason; each approval is recorded as delegated, not as a human review.
State and per-loop artifacts go to runtime/practice/tool-loops/.

Usage: python operator/tool_loops.py <dev_case> <dev_truth> --delegated-by "<person>" --reason "<text>" [--loops 8]
"""
import argparse
import json
import subprocess
import sys
import time
import urllib.request
from pathlib import Path
from urllib.parse import urlencode

from lab_paths import DEFAULT_LANE, FRAMEWORK, GATE_RUNS, PYTHON, TOOL_LOOPS
from switch_case import serving_lab

OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))
ROUNDS, MAX_LOOPS, PLATEAU, KEEP_MARGIN = 2, 8, 3, 1.0
RUN_TAG = ''
GATE_ARGS = []
LOG = TOOL_LOOPS / 'loop.log'
REQUIRED = ('untrusted', 'no truth, scoring, intent or outcome claims')
STEPS = ('scope', 'evidence', 'hypotheses', 'network', 'intel', 'analysis', 'detection', 'purple', 'incident')
# STEPS names serial results by position; follow and merge take guidance only in a hunt with follow_ups.
GUIDANCE_STAGES = STEPS + ('follow', 'merge')
GENERIC = {'powershell.exe', 'cmd.exe', 'svchost.exe', 'lsass.exe', 'explorer.exe', 'winword.exe', 'outlook.exe',
           'w3wp.exe', 'rundll32.exe', 'schtasks.exe', 'wmiprvse.exe', 'msedge.exe', 'chrome.exe', 'system'}


def log(msg):
    line = time.strftime('%H:%M:%S ') + msg
    LOG.parent.mkdir(parents=True, exist_ok=True)
    with LOG.open('a', encoding='utf-8') as s:
        s.write(line + '\n')
    print(line, flush=True)


def tcli(*args, lane=DEFAULT_LANE, timeout=180):
    r = subprocess.run([*lane.temporal_cli(), *args], cwd=FRAMEWORK, capture_output=True,
                       text=True, encoding='utf-8', errors='replace', timeout=timeout)
    return r.returncode, r.stdout, r.stderr


def lab_get(served, path, **q):
    return served.get(path + ('?' + urlencode(q) if q else ''), 'hunt-board', 60)


def activity_since(served, after):
    out = []
    while True:
        a = lab_get(served, '/activity', after=after, limit=100)
        es = a.get('entries') or []
        if not es:
            return out
        out += es
        after = max(e['seq'] for e in es)
        if not a.get('more'):
            return out


def last_seq(served):
    es = activity_since(served, 0)
    return max([e['seq'] for e in es] or [0])


def build_input(base, brief, guidance, case_id):
    raw = json.loads(json.dumps(base))
    # A real-data case (public dataset or work export) keeps the origin label lab-input gave it; never relabel it synthetic.
    origin = base['scope'].split(' only; ', 1)[0] if 'data_origin' in base else f'Synthetic {case_id}'
    raw['scope'] = f'{origin} only; ' + brief
    raw['parallel'] = True
    if guidance:
        raw['stage_guidance'] = guidance
    return raw


def check_candidate(base, brief, guidance, case_id, forbidden):
    problems = []
    low = brief.lower()
    problems += [f'brief must keep the phrase "{p}"' for p in REQUIRED if p not in low]
    if len(brief.encode()) > 1200:
        problems.append('brief over 1200 bytes')
    for step, text in (guidance or {}).items():
        if step not in GUIDANCE_STAGES:
            problems.append(f'unknown stage {step}')
        elif not isinstance(text, str) or not 1 <= len(text) <= 600:
            problems.append(f'guidance for {step} must be 1..600 characters')
    blob = (brief + ' ' + ' '.join((guidance or {}).values())).lower()
    hits = sorted(t for t in forbidden if t and t in blob)
    if hits:
        problems.append('case-specific terms are not allowed (write general hunting technique): ' + ', '.join(hits[:12]))
    try:
        sys.path.insert(0, str(FRAMEWORK))
        from hermes_temporal.hunt import supplied_evidence_hunt
        supplied_evidence_hunt(build_input(base, brief, guidance, case_id))
    except Exception as exc:  # budget or validation failure, reported to the watcher
        problems.append(f'input rejected: {exc}')
    return problems


def forbidden_terms(*truth_paths):
    terms = set()
    for p in truth_paths:
        t = json.loads(Path(p).read_text(encoding='utf-8'))
        for f in t['facts']:
            for vals in (f.get('entities') or {}).values():
                for v in vals:
                    v = str(v).lower()
                    if v not in GENERIC and len(v) >= 5:
                        terms.add(v)
    return terms


def score(truth, report):
    r = subprocess.run([PYTHON, '-B', '-m', 'hunt_lab.scenario', 'score', '--truth', str(truth), str(report)],
                       cwd=FRAMEWORK, capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=180)
    return json.loads(r.stdout)['reports'][0]


def category(fact_id):
    kind, _, rest = fact_id.partition('.')
    return kind + ':' + rest.split('.')[0] if kind == 'attack' else kind


def workflow_id(name, case_id, lane=DEFAULT_LANE):
    return f'{name}{RUN_TAG}-{lane.name + "-" if lane.name else ""}{case_id}'


def base_input(case_id, lane=DEFAULT_LANE, *, data_origin=None):
    """The case loaded in this lane's lab as a tool-driven hunt input, made once per case and lane and cached in TOOL_LOOPS.

    data_origin (public-dataset or work-export) is the operator's approval of a real-data case and must equal the
    case's declared origin; a cached input of another origin is refused."""
    TOOL_LOOPS.mkdir(parents=True, exist_ok=True)
    base_path = TOOL_LOOPS / f'base-{case_id}{"-" + lane.name if lane.name else ""}.json'
    if not base_path.exists():
        approval = ['--data-origin', data_origin] if data_origin else []
        r = subprocess.run([*lane.temporal_cli(), 'lab-input', '--tool-driven', *approval, '--state-dir', str(lane.state_dir),
                            '--output', str(base_path)], cwd=FRAMEWORK, capture_output=True, text=True,
                           encoding='utf-8', errors='replace', timeout=120)
        if r.returncode:
            raise SystemExit('lab-input failed: ' + r.stderr[-300:])
    base = json.loads(base_path.read_text(encoding='utf-8'))
    if base.get('data_origin') != data_origin:
        raise SystemExit(f'{base_path.name} has data origin {base.get("data_origin") or "synthetic"}; '
                         f'pass data_origin={base.get("data_origin")!r} to use it')
    return base


def result_sizes(st):
    """(step, status, reason code, output bytes) per step of a round's status. A parallel status lists every
    step and names its result by execution ID; a step without a result shows its state and reason with size 0.
    A serial status has only results, in the order of the fixed stages."""
    if not st.get('steps'):
        return [(STEPS[i], r['status'], r['reason_code'], len(r['output'].encode())) for i, r in enumerate(st['results'])]
    results = {r['execution_id']: r for r in st['results']}
    sizes = []
    for s in st['steps']:
        r = results.get(s['execution_id'])
        sizes.append((s['step_id'], r['status'], r['reason_code'], len(r['output'].encode())) if r
                     else (s['step_id'], s['state'], s['reason'], 0))
    return sizes


def usage_total(st):
    """Each usage key summed over every billed attempt of a round's status, with how many attempts recorded no
    usage and how many were rejected handoffs that the workflow retried; None when no attempt recorded usage.
    A retried attempt leaves status.results and survives only as its handoff rejection's result; a rejection
    whose result is still in status.results (it ended the round) is counted once."""
    kept = {r['execution_id'] for r in st['results']}
    retried = [item['result'] for item in st.get('handoff_rejections', [])
               if item.get('result') and item['result']['execution_id'] not in kept]
    attempts = [*st['results'], *retried]
    recorded = [r['usage'] for r in attempts if r.get('usage')]
    if not recorded:
        return None
    return ({key: sum(u[key] for u in recorded) for key in recorded[0]}
            | {'steps_without_usage': len(attempts) - len(recorded), 'retried_attempts': len(retried)})


def run_config(name, base, brief, guidance, case_id, truth, d=None, lane=DEFAULT_LANE):
    """Run ROUNDS rounds on this lane's lab and queue; return per-round scores and observations.
    Artifacts go to d (default TOOL_LOOPS/name)."""
    d = d or TOOL_LOOPS / name
    d.mkdir(parents=True, exist_ok=True)
    raw = build_input(base, brief, guidance, case_id)
    (d / 'input.json').write_text(json.dumps(raw, indent=2), encoding='utf-8')
    served = serving_lab(lane, case_id)
    seq0 = last_seq(served)
    wf = workflow_id(name, case_id, lane)
    rc, out, err = tcli('practice', wf, '--input', str(d / 'input.json'), '--rounds', str(ROUNDS), lane=lane)
    if rc:
        raise SystemExit(f'practice start failed: {err[-300:]}')
    t0 = time.time()
    drv = subprocess.run([sys.executable, '-B', str(Path(__file__).with_name('drive_gates.py')), wf, *GATE_ARGS],
                         env=lane.env(), capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=4 * 3600)
    calls = activity_since(serving_lab(lane, case_id), seq0)
    (d / 'activity.json').write_text(json.dumps(calls, indent=1), encoding='utf-8')
    rounds = []
    for n in range(1, ROUNDS + 1):
        rc, out, _ = tcli('status', f'{wf}:round:{n:03d}', lane=lane)
        if rc:
            rounds.append({'round': n, 'completed': False, 'stage': 'not_started', 'found': 0})
            continue
        st = json.loads(out)
        rep = GATE_RUNS / 'outputs' / wf / f'{n:03d}-incident.txt'
        entry = {'round': n, 'stage': st['stage'], 'halted_at': None if st['stage'] == 'completed' else st['step_id'],
                 'completed': st['stage'] == 'completed' and rep.exists(), 'sizes': result_sizes(st),
                 'handoff_rejections': [{key: item[key] for key in ('step_id', 'outcome', 'reason')}
                                        for item in st.get('handoff_rejections', [])]}
        if st.get('steps'):
            entry['dropped'] = [{'step_id': s['step_id'], 'reason': s['reason']}
                                for s in st['steps'] if s['state'] == 'dropped']
        usage = usage_total(st)
        if usage:
            entry['usage'] = usage
        if entry['completed']:
            s = score(truth, rep)
            entry.update(found=s['found'], total=s['total'], misattributed=len(s['misattributed_decoys']),
                         missed=[{'category': category(f['fact_id']), 'kind': f['kind'],
                                  'missing_evidence_groups': len(f['missing_groups']),
                                  'entities_named': bool(f['entities_named'])} for f in s['facts'] if not f['found']])
        else:
            entry.update(found=0, total=18, misattributed=0)
        rounds.append(entry)
    minutes = round((time.time() - t0) / 60, 1)
    result = {'name': name, 'workflow': wf, 'minutes': minutes, 'rounds': rounds, 'tool_calls': len(calls),
              'mean_found': sum(r['found'] for r in rounds) / ROUNDS,
              'halts': sum(1 for r in rounds if not r['completed']),
              'handoff_retries': sum(item['outcome'] == 'retried'
                                     for r in rounds for item in r.get('handoff_rejections', [])),
              'misattributed': sum(r.get('misattributed', 0) for r in rounds),
              'driver_tail': drv.stdout[-600:]}
    (d / 'result.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    dropped = [len(r['dropped']) for r in rounds if 'dropped' in r]
    tokens = [r['usage']['total_tokens'] for r in rounds if 'usage' in r]
    log(f'{name}: mean {result["mean_found"]:.1f}/18 rounds {[r["found"] for r in rounds]} halts {result["halts"]} '
        f'handoff retries {result["handoff_retries"]} misattributed {result["misattributed"]} calls {len(calls)} '
        + (f'dropped {sum(dropped)} ' if dropped else '') + (f'tokens {sum(tokens)} ' if tokens else '')
        + f'in {minutes} min')
    return result, calls


def tool_digest(calls):
    per = {}
    for e in calls:
        p = e['profile'].replace('framework-', '')
        b = per.setdefault(p, {'calls': 0, 'errors': [], 'tools': {}, 'sample': []})
        b['calls'] += 1
        b['tools'][e['tool']] = b['tools'].get(e['tool'], 0) + 1
        q = json.dumps(e.get('params'), separators=(',', ':'))[:220]
        if e.get('error'):
            b['errors'].append(f"{e['tool']} {e['error']}: {q}")
        elif len(b['sample']) < 14:
            b['sample'].append(f"{e['tool']} -> {e.get('total', e.get('result_count'))}: {q}")
    for b in per.values():
        b['errors'] = b['errors'][:10]
    return per


def report_digest(wf, n):
    out = {}
    for step in ('evidence', 'network', 'analysis', 'incident'):
        p = GATE_RUNS / 'outputs' / wf / f'{n:03d}-{step}.txt'
        if not p.exists():
            continue
        t = p.read_text(encoding='utf-8', errors='replace')
        try:
            h, _ = json.JSONDecoder().raw_decode(t[t.index('{'):])
            out[step] = {'claims': [c['kind'] + ': ' + c['statement'][:260] for c in h.get('claims', [])][:10],
                         'limitations': [x[:160] for x in h.get('limitations', [])][:6]}
        except (ValueError, KeyError):
            out[step] = {'unparsed': t[:300]}
    return out


WATCHER_RULES = (
    "You are the WATCHER for a six-bot AI threat-hunting team. Each bot drives its own read-only lab tool: "
    "Threat Hunter (elastic_search, elastic_aggregate, packet_fields), Network Analyst (arkime_sessions, arkime_unique, "
    "packet_fields), Threat Intel (intel_lookup, elastic_aggregate), Detection Engineer (detection_test, elastic_aggregate), "
    "Purple Team (elastic_search, arkime_sessions, detection_test); the Incident Response Lead (scope, analysis, incident "
    "stages) has only delegate_task. packet_fields decodes allowlisted, redacted fields of the case's saved capture only. "
    "Stages: scope, evidence, hypotheses (Threat Hunter), network, intel, analysis, detection, purple, incident. "
    "You watched the last hunt: every tool call, every refusal, the stage reports, and which answer-key CATEGORIES the final "
    "report missed (you never see the key itself). Propose ONE focused, general improvement that would help on any intrusion "
    "case: change the shared scope brief and/or add or edit per-stage guidance (<=600 chars each). Write hunting technique, "
    "never names, hosts, users, domains or IPs from this case. Keep the brief's safety phrases verbatim: 'untrusted' and "
    "'no truth, scoring, intent or outcome claims'. Shorter is better; prompts are budget-limited. A found fact needs the "
    "final report to cite at least one event.id from every evidence group of that fact and name its entities, so relaying "
    "earlier stages' event IDs into the final report matters. Lab refusals waste turns; their codes are "
    "field_not_allowed / invalid_field_list (field outside the list in the tool description), "
    "leading_wildcard_not_supported, invalid_query (syntax), invalid_filter (packet filter outside its grammar) and "
    "field_unavailable (the lab's tshark lacks that field). Reply with ONE JSON object only, no prose, no fences: "
    '{"diagnosis": "...", "hypothesis": "...", "brief": "<full new brief>", "stage_guidance": {"<stage>": "<text>", ...}}')


def opus(prompt, d, stem, image=None):
    """One Claude Opus turn through the lab home's default Hermes profile, no tools; returns its stdout.
    The prompt, query file and reply are kept in d as <stem>-*.txt."""
    (d / f'{stem}-prompt.txt').write_text(prompt, encoding='utf-8')
    qf = d / f'{stem}-query.txt'
    qf.write_text(prompt, encoding='utf-8')
    cmd = [DEFAULT_LANE.hermes_exe(), '-p', 'default', 'chat', '--query-file', str(qf), '-Q', '--max-turns', '2', '--source', 'tool',
           '--provider', 'anthropic', '-m', 'claude-opus-5-5']
    if image:
        cmd += ['--image', str(image)]
    r = subprocess.run(cmd, env=DEFAULT_LANE.env(), capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=900)
    (d / f'{stem}-response.txt').write_text(r.stdout + '\n--- stderr tail ---\n' + r.stderr[-800:], encoding='utf-8')
    return r.stdout


def json_reply(text, who='watcher'):
    start = text.find('{')
    if start < 0:
        raise ValueError(f'{who} returned no JSON')
    obj, _ = json.JSONDecoder().raw_decode(text[start:])
    return obj


def watcher(context, d, attempt_note='', rules=WATCHER_RULES):
    prompt = rules + '\n\n' + json.dumps(context, indent=1)[:60000] + attempt_note
    return json_reply(opus(prompt, d, 'watcher'))


def parse_args(argv=None, prog=None, description=__doc__):
    ap = argparse.ArgumentParser(prog=prog, description=description, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('dev_case', help='case ID loaded in the lab')
    ap.add_argument('dev_truth', help='operator-only answer key (truth.json) for dev_case')
    ap.add_argument('--delegated-by', required=True, help='person who delegated the gate approvals (see drive_gates.py)')
    ap.add_argument('--reason', required=True, help='their instruction, recorded in every approval note')
    ap.add_argument('--sealed-truth', help='optional extra forbidden-terms source; sealed runs are separate')
    ap.add_argument('--loops', type=int, default=MAX_LOOPS)
    ap.add_argument('--resume', action='store_true')
    ap.add_argument('--tag', default='', help='suffix for workflow IDs so a restarted series never reuses one')
    ap.add_argument('--reset-plateau', metavar='REASON',
                    help='with --resume: zero the no-gain counter after an infrastructure fix; REASON is logged')
    ap.add_argument('--sealed', action='store_true',
                    help='run BEST.json unchanged on dev_case/dev_truth, a case the watcher never saw; no watcher calls. '
                         'Passes when every round finds >= SEALED_MIN facts, misses no attack fact and blames no decoy')
    args = ap.parse_args(argv)
    # The scorer runs from framework/, so a key path relative to the caller's directory must be
    # made absolute here; otherwise every round fails to score after its hunt completes.
    for name in ('dev_truth', 'sealed_truth'):
        truth = getattr(args, name)
        if truth:
            if not Path(truth).is_file():
                ap.error(f'answer key not found: {truth}')
            setattr(args, name, str(Path(truth).resolve()))
    return args


def main(args):
    global RUN_TAG
    RUN_TAG = args.tag
    GATE_ARGS[:] = ['--delegated-by', args.delegated_by, '--reason', args.reason]
    DEFAULT_LANE.hermes_exe()
    if args.sealed:
        return sealed_test(args)
    TOOL_LOOPS.mkdir(parents=True, exist_ok=True)
    state_path = TOOL_LOOPS / 'state.json'
    forbidden = forbidden_terms(*[p for p in (args.dev_truth, args.sealed_truth) if p])
    base = base_input(args.dev_case)
    base_brief = base['scope'].split(' only; ', 1)[1]
    if args.resume and state_path.exists():
        state = json.loads(state_path.read_text(encoding='utf-8'))
        if args.reset_plateau:
            log(f'plateau counter reset from {state["no_gain"]}: {args.reset_plateau}')
            state['no_gain'] = 0
    else:
        res, calls = run_config('loop-00', base, base_brief, {}, args.dev_case, args.dev_truth)
        state = {'best': {'loop': 0, 'brief': base_brief, 'guidance': {}, 'result': res}, 'history': [], 'last': res,
                 'last_calls': tool_digest(calls), 'last_reports': report_digest(res['workflow'], 1), 'no_gain': 0}
        state_path.write_text(json.dumps(state, indent=1), encoding='utf-8')
    def perfect(res):
        return all(r['completed'] and r['found'] == 18 and r.get('misattributed', 0) == 0 for r in res['rounds'])
    start = len(state['history']) + 1
    for n in range(start, args.loops + 1):
        best = state['best']
        if perfect(best['result']):
            log(f'PERFECT on dev at loop {best["loop"]}; stopping dev loops')
            break
        if state['no_gain'] >= PLATEAU:
            log(f'plateau: {PLATEAU} loops without a kept change; stopping')
            break
        name = f'loop-{n:02d}'
        d = TOOL_LOOPS / name
        d.mkdir(parents=True, exist_ok=True)
        context = {'goal': 'find every attack step, decoy, benign pattern and coverage gap with full event.id citations; '
                           'never blame a decoy; complete all 9 stages',
                   'best_so_far': {'loop': best['loop'], 'mean_found_of_18': best['result']['mean_found'],
                                   'brief': best['brief'], 'stage_guidance': best['guidance'],
                                   'rounds': best['result']['rounds']},
                   'last_evaluated': {'mean_found_of_18': state['last']['mean_found'], 'rounds': state['last']['rounds'],
                                      'tool_calls_by_bot': state['last_calls'], 'round1_reports': state['last_reports']},
                   'history': [{k: h[k] for k in ('loop', 'mean_found', 'kept', 'hypothesis')} for h in state['history']]}
        note, cand = '', None
        for attempt in range(3):
            try:
                obj = watcher(context, d, note)
            except (ValueError, subprocess.TimeoutExpired) as exc:
                note = f'\n\nYour previous reply could not be used ({exc}). Reply with the JSON object only.'
                continue
            brief = ' '.join(str(obj.get('brief', '')).split())
            guidance = {k: ' '.join(str(v).split()) for k, v in (obj.get('stage_guidance') or {}).items() if str(v).strip()}
            problems = check_candidate(base, brief, guidance, args.dev_case, forbidden)
            if not problems:
                cand = (obj, brief, guidance)
                break
            note = '\n\nYour previous proposal was REJECTED: ' + '; '.join(problems) + '. Fix these and reply again.'
        if cand is None:
            log(f'{name}: watcher produced no valid proposal; counted as no gain')
            state['history'].append({'loop': n, 'mean_found': None, 'kept': False, 'hypothesis': 'no valid proposal'})
            state['no_gain'] += 1
            state_path.write_text(json.dumps(state, indent=1), encoding='utf-8')
            continue
        obj, brief, guidance = cand
        (d / 'proposal.json').write_text(json.dumps(obj, indent=2), encoding='utf-8')
        res, calls = run_config(name, base, brief, guidance, args.dev_case, args.dev_truth)
        b = best['result']
        kept = res['mean_found'] >= b['mean_found'] + KEEP_MARGIN and res['halts'] <= b['halts']
        if not kept and perfect(res):
            kept = True
        state['history'].append({'loop': n, 'mean_found': res['mean_found'], 'kept': kept,
                                 'hypothesis': str(obj.get('hypothesis', ''))[:400]})
        state['last'], state['last_calls'] = res, tool_digest(calls)
        state['last_reports'] = report_digest(res['workflow'], 1)
        if kept:
            state['best'] = {'loop': n, 'brief': brief, 'guidance': guidance, 'result': res}
            state['no_gain'] = 0
        else:
            state['no_gain'] += 1
        (d / 'decision.json').write_text(json.dumps({'kept': kept, 'mean_found': res['mean_found'],
                                                     'best_before': b['mean_found']}, indent=2), encoding='utf-8')
        log(f'{name}: {"KEPT" if kept else "reverted"} ({res["mean_found"]:.1f} vs best {b["mean_found"]:.1f})')
        state_path.write_text(json.dumps(state, indent=1), encoding='utf-8')
    best = state['best']
    (TOOL_LOOPS / 'BEST.json').write_text(json.dumps({'loop': best['loop'], 'brief': best['brief'], 'stage_guidance': best['guidance'],
                                                'dev_result': best['result'], 'perfect_on_dev': perfect(best['result'])},
                                               indent=2), encoding='utf-8')
    log(f'done: best loop {best["loop"]} mean {best["result"]["mean_found"]:.1f}/18 perfect_on_dev={perfect(best["result"])}')


SEALED_MIN = 16


def sealed_test(args):
    """The second half of PERFECT: the best dev config, unchanged, on a different-story case."""
    best = json.loads((TOOL_LOOPS / 'BEST.json').read_text(encoding='utf-8'))
    base = base_input(args.dev_case)
    if base['ontology']['case_id'] != args.dev_case:
        raise SystemExit(f"the lab has {base['ontology']['case_id']} loaded, not {args.dev_case}")
    res, _calls = run_config(f'sealed{RUN_TAG}', base, best['brief'], best['stage_guidance'], args.dev_case, args.dev_truth)
    rounds = [{'round': r['round'], 'found': r['found'], 'misattributed': r.get('misattributed', 0),
               'missed_attack': sorted({m['category'] for m in r.get('missed', []) if m['kind'] == 'attack'}),
               'passed': bool(r['completed'] and r['found'] >= SEALED_MIN and r.get('misattributed', 0) == 0
                              and not any(m['kind'] == 'attack' for m in r.get('missed', [])))} for r in res['rounds']]
    verdict = {'case': args.dev_case, 'best_loop': best['loop'], 'dev_mean_found': best['dev_result']['mean_found'],
               'sealed_mean_found': res['mean_found'], 'rounds': rounds, 'passed': all(r['passed'] for r in rounds)}
    (TOOL_LOOPS / f'SEALED-{args.dev_case}.json').write_text(json.dumps(verdict, indent=2), encoding='utf-8')
    log(f"sealed {args.dev_case}: mean {res['mean_found']:.1f}/18 rounds {[r['found'] for r in rounds]} "
        f"passed={verdict['passed']} (best loop {best['loop']}, dev mean {verdict['dev_mean_found']:.1f})")
    return 0 if verdict['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main(parse_args()) or 0)

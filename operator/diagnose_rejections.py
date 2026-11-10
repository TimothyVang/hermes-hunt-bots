"""Replay handoff validation for halted loop rounds and print the exact rejection reason (read-only).

A parallel round's results are matched to their steps by execution ID, and a rejected optional
step does not end the replay, because the workflow drops such a step and carries on.

Run it with a Python that has the framework's Temporal dependencies
(pip install -r framework/hermes_temporal/requirements.txt).

Usage: python operator/diagnose_rejections.py [--new] <loop_dir>=<child_workflow_id> ...
"""
import argparse
import json
import subprocess
import sys
from pathlib import Path

from lab_paths import DEFAULT_LANE, FRAMEWORK


def pair(text):
    loop_dir, sep, wid = text.rpartition('=')
    if not sep or not loop_dir or not wid:
        raise argparse.ArgumentTypeError(f'expected <loop_dir>=<child_workflow_id>, got {text!r}')
    return Path(loop_dir), wid


def status(wid):
    r = subprocess.run([*DEFAULT_LANE.temporal_cli(), 'status', wid], cwd=FRAMEWORK, capture_output=True, text=True, timeout=120)
    if r.returncode:
        raise SystemExit(f'status {wid} failed: {r.stderr.strip()[-300:]}')
    return json.loads(r.stdout)


def reached(steps, st):
    """(step, its latest result) for each step the status has a result for, in step order. A parallel
    status names each step's result by execution ID; a serial one lists its results in step order."""
    if not st.get('steps'):
        return list(zip(steps, st['results']))
    by_id = {step.step_id: step for step in steps}
    results = {result['execution_id']: result for result in st['results']}
    return [(by_id[item['step_id']], results[item['execution_id']])
            for item in st['steps'] if item['execution_id'] in results]


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--new', action='store_true',
                    help='use the surrounding-prose extractor instead of the leading-prose fence unwrap')
    ap.add_argument('pairs', nargs='+', type=pair, metavar='LOOP_DIR=CHILD_WORKFLOW_ID')
    args = ap.parse_args()
    sys.path.insert(0, str(FRAMEWORK))
    try:
        from hermes_temporal.hunt import supplied_evidence_hunt
        from hermes_temporal.ontology import validate_handoff
        from hermes_temporal import workflows as wf
    except ImportError as exc:
        raise SystemExit(f'{exc}: run this with a Python that has framework/hermes_temporal/requirements.txt installed')
    for loop_dir, wid in args.pairs:
        steps = supplied_evidence_hunt(json.loads((loop_dir / 'input.json').read_text(encoding='utf-8'))).steps
        # As in the workflow: only a step that no other step depends on gets the larger final-handoff limit.
        consumed = {dependency for step in steps for dependency in step.depends_on}
        st = status(wid)
        reviewed = {}
        rejected = False
        for step, result in reached(steps, st):
            text = result['output']
            try:
                text = wf._extract_single_handoff(text) if args.new else wf._unwrap_single_fence(text, allow_leading_prose=True)
                handoff = validate_handoff(
                    json.loads(text), snapshot=step.hunt_context['snapshot'], evidence_ids=step.hunt_context['evidence_ids'],
                    step_id=step.step_id, profile=step.profile,
                    predecessors=tuple(reviewed[d] for d in step.depends_on if d in reviewed),
                    note_limit=wf._NOTE_LIMIT_BYTES,
                    handoff_limit=wf._FINAL_HANDOFF_BYTES if step.step_id not in consumed else wf.MAX_HANDOFF_BYTES)
                reviewed[step.step_id] = handoff
            except Exception as exc:  # the rejection being diagnosed
                print(f'{wid} step {step.step_id}: {type(exc).__name__}: {str(exc)[:300]} ({len(result["output"].encode())} bytes)')
                rejected = True
                if not step.optional:
                    break
        if not rejected:
            print(f'{wid}: all {len(st["results"])} results validate')


if __name__ == '__main__':
    main()

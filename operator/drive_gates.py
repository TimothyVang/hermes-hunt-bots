"""Drive the execute and review gates of one practice run, in one of two opt-in modes.

Delegated mode (--delegated-by "<person>" --reason "<text>") approves every gate on that person's
behalf; every approval it records says it is a delegated approval by that person and not a human
review of the content.

Two-decision mode (--two-decisions --operator "<name>") follows the project's accepted decision
record on two human decisions per hunt: the operator approves the scope (the review of the scope
step) before any hunter queries data, and accepts or rejects the final report (the review of the
hunt's last step). The driver never decides those two gates: it saves their outputs, logs that
it is waiting for the operator, prints the decision command, and polls until the operator has
decided or the workflow ends. Every other gate is approved automatically with a note that says
so and that it is not a human review of the step.

Exactly one mode must be chosen. The driver never retries on its own and stops on the first
non-completed outcome of a required step. When the workflow re-offers a step once after handoff
validation rejected its output, that new execute gate is approved like any other, under its own
decision ID and a note that names it a retry approval. Stage outputs are saved under
runtime/practice/gate-runs/outputs/<workflow_id>/.

A parallel hunt gates a whole wave of steps at once (gate ID wave-<n>). The driver sends one
execute approval each time the wave's execute gate opens (once, and once more for the steps the
workflow retries) and one review approval, after saving the output of every step awaiting
review under that step's own ID. An optional step the workflow dropped is logged and the run
goes on.

Usage: python operator/drive_gates.py <practice_workflow_id> --delegated-by "<person>" --reason "<text>"
       python operator/drive_gates.py <practice_workflow_id> --two-decisions --operator "<name>"
"""
import argparse
import json
import os
import shlex
import subprocess
import sys
import time

from lab_paths import DEFAULT_LANE, FRAMEWORK, GATE_RUNS

LOG = GATE_RUNS / 'driver.log'
NOTE_LIMIT_BYTES = 4096  # the workflow silently ignores a decision whose note is larger
RETRY_NOTE = ('Retry approval: the workflow re-offered this step once because handoff validation rejected '
              'its previous output. ')
AUTOMATED_NOTE = ('Automated approval under ADR 0002 (two human decisions per hunt) for operator {operator}; '
                  'recorded automatically by operator/drive_gates.py; not a human review of this step.')
# A serial hunt's status names only the open step, so its first and last steps are known by ID.
SCOPE_STEP, REPORT_STEP = 'scope', 'incident'
shell_join = subprocess.list2cmdline if os.name == 'nt' else shlex.join


def log(message):
    line = time.strftime('%H:%M:%S ') + message
    with LOG.open('a', encoding='utf-8') as stream:
        stream.write(line + '\n')
    print(line, flush=True)


def cli(*args):
    # Status reads are side-effect free and the workflow ignores a repeated decision
    # once its gate has passed, so retrying a slow call cannot double-approve.
    for attempt in range(3):
        try:
            result = subprocess.run([*DEFAULT_LANE.temporal_cli(), *args], cwd=FRAMEWORK,
                                    capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=120)
            break
        except subprocess.TimeoutExpired:
            log(f'{args[0]} timed out (attempt {attempt + 1}/3)')
    else:
        raise RuntimeError(f'{args[0]} timed out three times')
    if result.returncode:
        raise RuntimeError(f'{args[0]} exit {result.returncode}: {result.stderr.strip()[-300:]}')
    return json.loads(result.stdout)


def decide(child, step, phase, note, retry=0, kind='delegated'):
    # The workflow ignores a reused decision ID, so the retry's gate needs its own.
    suffix, prefix = (f':retry{retry}', RETRY_NOTE) if retry else ('', '')
    cli('decision', child, '--step-id', step, '--phase', phase, '--choice', 'approve',
        '--decision-id', f'{child}:{step}:{phase}{suffix}', '--evidence-note', prefix + note)
    log(f'{child} {step} {phase} approved ({kind}{", retry " + str(retry) if retry else ""})')


def operator_review(step, steps):
    """'scope' or 'report' when this open review gate is one of the operator's two decisions, else None."""
    if not steps:
        return {SCOPE_STEP: 'scope', REPORT_STEP: 'report'}.get(step)
    reviewing = [item for item in steps if item['state'] == 'awaiting_review']
    if any(item['step_id'] == SCOPE_STEP for item in reviewing):
        return 'scope'
    # Every step is listed whatever its state, so the highest wave is the hunt's last one.
    last = max(item['wave'] for item in steps)
    return 'report' if any(item['wave'] == last for item in reviewing) else None


def wait_for_operator(args, child, step, which, out):
    log(f'WAITING FOR OPERATOR {args.operator}: {which} review of {child} {step}; outputs in {out}')
    print(f'Decide it yourself from {FRAMEWORK}, with your own note on what you checked:', flush=True)
    for choice in ('approve', 'deny'):
        print('  ' + shell_join([*DEFAULT_LANE.temporal_cli(), 'decision', child, '--step-id', step, '--phase',
                                 'review', '--choice', choice, '--decision-id', f'{child}:{step}:review',
                                 '--evidence-note', '<what you checked>']), flush=True)


def parse_args(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('workflow_id', help='the practice parent workflow ID')
    ap.add_argument('--delegated-by', help='delegated mode: the person who delegated these approvals')
    ap.add_argument('--reason', help='delegated mode: their instruction, recorded in every approval note')
    ap.add_argument('--two-decisions', action='store_true',
                    help='two-decision mode: the operator decides the scope and final report reviews')
    ap.add_argument('--operator', help='two-decision mode: the operator who makes those two decisions')
    args = ap.parse_args(argv)
    if args.two_decisions == (args.delegated_by is not None or args.reason is not None):
        ap.error('choose exactly one mode: --two-decisions --operator "<name>", or --delegated-by and --reason')
    if args.two_decisions:
        args.operator = ' '.join((args.operator or '').split())
        if not args.operator:
            ap.error('--two-decisions needs a non-blank --operator')
        args.note = AUTOMATED_NOTE.format(operator=args.operator)
        shorten = '--operator'
    else:
        if args.operator is not None:
            ap.error('--operator belongs to --two-decisions, not to --delegated-by')
        args.delegated_by = ' '.join((args.delegated_by or '').split())
        args.reason = ' '.join((args.reason or '').split())
        if not args.delegated_by or not args.reason:
            ap.error('--delegated-by and --reason must both be given and not blank')
        args.note = (f'Delegated approval by {args.delegated_by}: {args.reason}. Recorded automatically by '
                     'operator/drive_gates.py on their behalf; this is not a human review of the content.')
        shorten = '--reason'
    if len((RETRY_NOTE + args.note).encode('utf-8')) > NOTE_LIMIT_BYTES:
        ap.error(f'the approval note must fit in {NOTE_LIMIT_BYTES} bytes; shorten {shorten}')
    return args


def main(args):
    out = GATE_RUNS / 'outputs' / args.workflow_id
    out.mkdir(parents=True, exist_ok=True)
    kind = 'automated' if args.operator else 'delegated'
    if args.operator:
        log(f'TWO DECISIONS for {args.workflow_id}: operator {args.operator} approves the scope and accepts or '
            'rejects the final report; every other gate is approved automatically under ADR 0002 and recorded '
            'as automated, not as a human review.')
    else:
        log(f'DELEGATED APPROVALS for {args.workflow_id}: every execute and review gate is approved on behalf of '
            f'{args.delegated_by} ({args.reason}). These approvals are not human reviews of the content.')
    handled, dropped = set(), set()
    while True:
        parent = cli('practice-status', args.workflow_id)
        if parent['temporal_status'] != 'RUNNING':
            log('parent finished: ' + json.dumps(parent))
            return 0 if parent['stage'] == 'completed' else 1
        child = parent.get('child_workflow_id')
        if not child:
            time.sleep(3)
            continue
        state = cli('status', child)
        stage, step = state['stage'], state['step_id']
        # Only a parallel hunt lists its steps; its gate (step) is then a whole wave, wave-<n>.
        steps = state.get('steps') or []
        for item in steps:
            if item['state'] == 'dropped' and (child, item['step_id']) not in dropped:
                dropped.add((child, item['step_id']))
                log(f'DROPPED {child} {item["step_id"]}: {item["reason"]}')
        gated = {item['step_id'] for item in steps if item['state'] == 'awaiting_approval'} if steps else {step}
        retries = [item for item in state.get('handoff_rejections', [])
                   if item['step_id'] in gated and item['outcome'] == 'retried']
        # A step is retried once and a wave re-opens once for all its retried steps, so the retry number is 0 or 1.
        retry = int(bool(retries))
        key = (child, step, stage, retry)
        if key in handled:
            time.sleep(3)
            continue
        if stage == 'awaiting_execution_approval':
            if retry:
                why = ('; '.join(f'{item["step_id"]}: {item["reason"]}' for item in retries) if steps
                       else retries[-1]['reason'])
                log(f'{child} {step} handoff rejected; the workflow offers one retry: {why}')
            decide(child, step, 'execute', args.note, retry, kind)
            handled.add(key)
        elif stage == 'awaiting_review':
            if steps:
                results = {item['execution_id']: item for item in state['results']}
                reviews = [(item['step_id'], results.get(item['execution_id']))
                           for item in steps if item['state'] == 'awaiting_review']
                if not reviews:
                    log(f'STOP {child} {step}: no step is awaiting review; nothing was approved')
                    return 1
            else:
                reviews = [(step, state['results'][-1])]
            # Nothing of a wave is saved unless all of it can be approved, and nothing is approved unsaved.
            for step_id, result in reviews:
                if result is None or result['status'] != 'completed':
                    log(f'STOP {child} {step_id}: ' + (f'result {result["status"]}/{result["reason_code"]}'
                                                       if result else 'awaiting review without a result'))
                    return 1
            for step_id, result in reviews:
                name = f"{child.rsplit(':', 1)[-1]}-{step_id}.txt"
                (out / name).write_text(result['output'], encoding='utf-8')
                log(f'{child} {step_id} output saved ({len(result["output"].encode())} bytes) -> {out / name}')
            which = args.operator and operator_review(step, steps)
            if which:
                wait_for_operator(args, child, step, which, out)
            else:
                decide(child, step, 'review', args.note, kind=kind)
            handled.add(key)
        elif stage in ('needs_reconciliation', 'rejected', 'handoff_validation_rejected',
                       'output_limit_rejected', 'aborted', 'denied', 'timed_out'):
            log(f'STOP {child} {step}: stage {stage}; no retry. ' + json.dumps(state)[:600])
            return 1
        else:
            time.sleep(3)


if __name__ == '__main__':
    arguments = parse_args()
    try:
        sys.exit(main(arguments))
    except Exception as exc:
        log(f'driver error: {exc}')
        sys.exit(2)

"""Approve every execute and review gate of one practice run on a named person's behalf.

Opt-in only: it refuses to run without --delegated-by and --reason. Every approval it records
says it is a delegated approval by that person and not a human review of the content. It never
retries on its own and stops on the first non-completed outcome. When the workflow re-offers a
step once after handoff validation rejected its output, that new execute gate is approved like
any other, under its own decision ID and a note that names it a retry approval. Stage outputs
are saved under runtime/practice/gate-runs/outputs/<workflow_id>/.

Usage: python operator/drive_gates.py <practice_workflow_id> --delegated-by "<person>" --reason "<text>"
"""
import argparse
import json
import subprocess
import sys
import time

from lab_paths import FRAMEWORK, GATE_RUNS, temporal_cli

LOG = GATE_RUNS / 'driver.log'
NOTE_LIMIT_BYTES = 4096  # the workflow silently ignores a decision whose note is larger
RETRY_NOTE = ('Retry approval: the workflow re-offered this step once because handoff validation rejected '
              'its previous output. ')


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
            result = subprocess.run([*temporal_cli(), *args], cwd=FRAMEWORK,
                                    capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=120)
            break
        except subprocess.TimeoutExpired:
            log(f'{args[0]} timed out (attempt {attempt + 1}/3)')
    else:
        raise RuntimeError(f'{args[0]} timed out three times')
    if result.returncode:
        raise RuntimeError(f'{args[0]} exit {result.returncode}: {result.stderr.strip()[-300:]}')
    return json.loads(result.stdout)


def decide(child, step, phase, note, retry=0):
    # The workflow ignores a reused decision ID, so the retry's gate needs its own.
    suffix, prefix = (f':retry{retry}', RETRY_NOTE) if retry else ('', '')
    cli('decision', child, '--step-id', step, '--phase', phase, '--choice', 'approve',
        '--decision-id', f'{child}:{step}:{phase}{suffix}', '--evidence-note', prefix + note)
    log(f'{child} {step} {phase} approved (delegated{", retry " + str(retry) if retry else ""})')


def parse_args():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('workflow_id', help='the practice parent workflow ID')
    ap.add_argument('--delegated-by', required=True, help='the person who delegated these approvals')
    ap.add_argument('--reason', required=True, help='their instruction, recorded in every approval note')
    args = ap.parse_args()
    args.delegated_by, args.reason = ' '.join(args.delegated_by.split()), ' '.join(args.reason.split())
    if not args.delegated_by or not args.reason:
        ap.error('--delegated-by and --reason must not be blank')
    args.note = (f'Delegated approval by {args.delegated_by}: {args.reason}. Recorded automatically by '
                 'operator/drive_gates.py on their behalf; this is not a human review of the content.')
    if len((RETRY_NOTE + args.note).encode('utf-8')) > NOTE_LIMIT_BYTES:
        ap.error(f'the approval note must fit in {NOTE_LIMIT_BYTES} bytes; shorten --reason')
    return args


def main(args):
    out = GATE_RUNS / 'outputs' / args.workflow_id
    out.mkdir(parents=True, exist_ok=True)
    log(f'DELEGATED APPROVALS for {args.workflow_id}: every execute and review gate is approved on behalf of '
        f'{args.delegated_by} ({args.reason}). These approvals are not human reviews of the content.')
    handled = set()
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
        rejections = [item for item in state.get('handoff_rejections', []) if item['step_id'] == step]
        retry = sum(item['outcome'] == 'retried' for item in rejections)
        key = (child, step, stage, retry)
        if key in handled:
            time.sleep(3)
            continue
        if stage == 'awaiting_execution_approval':
            if retry:
                log(f'{child} {step} handoff rejected; the workflow offers one retry: {rejections[-1]["reason"]}')
            decide(child, step, 'execute', args.note, retry)
            handled.add(key)
        elif stage == 'awaiting_review':
            result = state['results'][-1]
            if result['status'] != 'completed':
                log(f'STOP {child} {step}: result {result["status"]}/{result["reason_code"]}')
                return 1
            name = f"{child.rsplit(':', 1)[-1]}-{step}.txt"
            (out / name).write_text(result['output'], encoding='utf-8')
            log(f'{child} {step} output saved ({len(result["output"].encode())} bytes) -> {out / name}')
            decide(child, step, 'review', args.note)
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

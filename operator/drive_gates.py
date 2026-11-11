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

Decision log (ADR 0004): every decision the driver sends is appended to <decision-dir>/decisions.jsonl
with who decided (automated, or delegated: <name>) and through which channel. In two-decision mode the
driver also writes pending/<child>__<gate>__<digest>__review.json (digest: 16 hex of SHA-256 over the exact
child and gate, so IDs that sanitize alike never share a record), with a one-time nonce, while it waits at one of
the operator's two gates; operator/slack_gates.py turns that record into a Slack card. When the gate moves
on, the driver deletes the record and, unless the bridge logged the decision, appends a line that says the
operator decided outside the driver.

Usage: python operator/drive_gates.py <practice_workflow_id> --delegated-by "<person>" --reason "<text>"
       python operator/drive_gates.py <practice_workflow_id> --two-decisions --operator "<name>" [--card-summary]
"""
import argparse
import hashlib
import json
import os
import re
import secrets
import shlex
import subprocess
import sys
import time
import unicodedata
from datetime import datetime, timezone
from pathlib import Path

from lab_paths import DEFAULT_LANE, FRAMEWORK, GATE_RUNS, PRACTICE

LOG = GATE_RUNS / 'driver.log'
DECISION_DIR = PRACTICE / 'operator-decisions'
NOTE_LIMIT_BYTES = 4096  # the workflow silently ignores a decision whose note is larger
RETRY_NOTE = ('Retry approval: the workflow re-offered this step once because handoff validation rejected '
              'its previous output. ')
AUTOMATED_NOTE = ('Automated approval under ADR 0002 (two human decisions per hunt) for operator {operator}; '
                  'recorded automatically by operator/drive_gates.py; not a human review of this step.')
# A serial hunt's status names only the open step, so its first and last steps are known by ID.
SCOPE_STEP, REPORT_STEP = 'scope', 'incident'
SUMMARY_LIMIT = 2500
SUMMARY_PREFIX = 'Bot-written, unverified: '
SUMMARY_CLAIMS = 3
# A bridge that claimed a record may still be sending its decision when the gate moves on; its CLI call
# gives up after 120 seconds.
BRIDGE_GRACE_SECONDS = 130
shell_join = subprocess.list2cmdline if os.name == 'nt' else shlex.join


def log(message):
    line = time.strftime('%H:%M:%S ') + message
    with LOG.open('a', encoding='utf-8') as stream:
        stream.write(line + '\n')
    print(line, flush=True)


def utc_now():
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def sha256_text(text):
    return hashlib.sha256(text.encode('utf-8')).hexdigest()


def _append_only(path):
    """A descriptor whose every write the operating system places at the end of the file."""
    if os.name != 'nt':
        return os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    # The C runtime emulates O_APPEND on Windows by seeking before each write, so two drivers could
    # overwrite each other's line; a handle opened with append-only access makes Windows append every write.
    import ctypes
    import msvcrt
    from ctypes import wintypes
    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.CreateFileW.argtypes = (wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
                                     wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE)
    kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    file_append_data, share_read_write, open_always, normal = 0x0004, 0x0001 | 0x0002, 4, 0x80
    handle = kernel32.CreateFileW(str(path), file_append_data, share_read_write, None, open_always, normal, None)
    if handle is None or handle == wintypes.HANDLE(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return msvcrt.open_osfhandle(handle, 0)
    except OSError:
        kernel32.CloseHandle(handle)
        raise


def append_decision(decision_dir, **entry):
    """Append one line to decisions.jsonl in a single write; the file is never rewritten."""
    decision_dir = Path(decision_dir)
    decision_dir.mkdir(parents=True, exist_ok=True)
    data = (json.dumps({'ts': utc_now(), **entry}, ensure_ascii=False) + '\n').encode('utf-8')
    fd = _append_only(decision_dir / 'decisions.jsonl')
    try:
        written = os.write(fd, data)
    finally:
        os.close(fd)
    if written != len(data):
        raise OSError(f'decisions.jsonl: wrote {written} of {len(data)} bytes')


def read_decisions(decision_dir):
    try:
        text = (Path(decision_dir) / 'decisions.jsonl').read_text(encoding='utf-8', errors='replace')
    except FileNotFoundError:
        return []
    lines = []
    for line in text.splitlines():
        try:
            item = json.loads(line)
        except ValueError:
            continue
        if isinstance(item, dict):
            lines.append(item)
    return lines


def retry_busy(action):
    # Windows refuses for a moment to replace or delete a file another process has open.
    for attempt in range(5):
        try:
            return action()
        except PermissionError:
            if attempt == 4:
                raise
            time.sleep(0.2)


def write_json_atomic(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f'.{path.name}.{os.getpid()}.{secrets.token_hex(4)}.tmp')
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=1), encoding='utf-8')
    try:
        retry_busy(lambda: os.replace(temporary, path))
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def record_name(child, gate):
    # The readable part replaces unsafe characters, so the digest of the exact IDs keeps names unique.
    unsafe = re.compile(r'[^A-Za-z0-9._-]')
    digest = hashlib.sha256(f'{child}\0{gate}'.encode()).hexdigest()[:16]
    return f'{unsafe.sub("_", child)[:120]}__{unsafe.sub("_", gate)[:64]}__{digest}__review.json'


def pending_record(workflow, child, gate, kind, outputs_dir, summary=None):
    """What the Slack bridge needs to put one of the operator's two decisions on a card."""
    record = {'child': child, 'workflow': workflow, 'gate': gate, 'phase': 'review', 'kind': kind,
              'nonce': secrets.token_hex(16), 'opened_at': utc_now(), 'outputs_dir': str(outputs_dir),
              'decision_cli': [*DEFAULT_LANE.temporal_cli(), 'decision', child, '--step-id', gate,
                               '--phase', 'review']}
    if summary is not None:
        record['summary'] = summary
    return record


def write_pending(decision_dir, record):
    path = Path(decision_dir) / 'pending' / record_name(record['child'], record['gate'])
    write_json_atomic(path, record)
    return path


def clean_text(text):
    """Text without control or invisible formatting characters (newlines kept), for a card a person reads."""
    return ''.join(char for char in text.replace('\t', ' ')
                   if char == '\n' or unicodedata.category(char) not in ('Cc', 'Cf'))


def read_handoff(text):
    """The JSON handoff with a claims list in a saved stage output, which may carry prose around it."""
    decoder = json.JSONDecoder()
    start = text.find('{')
    while start >= 0:
        try:
            value, _ = decoder.raw_decode(text, start)
        except ValueError:
            value = None
        if isinstance(value, dict) and isinstance(value.get('claims'), list):
            return value
        start = text.find('{', start + 1)
    return None


def card_summary(kind, outputs):
    """The scope text, or the report's verdict and first claims, labelled bot-written and capped."""
    if kind == 'scope':
        body = '\n\n'.join(outputs)
    else:
        parts = []
        for text in outputs:
            handoff = read_handoff(text)
            if handoff is None:
                parts.append(text)
                continue
            parts.append(f'Verdict: {handoff.get("disposition")}')
            claims = [claim for claim in handoff['claims'] if isinstance(claim, dict)]
            parts += [f'- {claim.get("statement")}' for claim in claims[:SUMMARY_CLAIMS]]
        body = '\n'.join(parts)
    summary = SUMMARY_PREFIX + clean_text(body).strip()
    return summary if len(summary) <= SUMMARY_LIMIT else summary[:SUMMARY_LIMIT - 1] + '\u2026'


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


def decide(args, child, step, phase, retry=0):
    # The workflow ignores a reused decision ID, so the retry's gate needs its own.
    suffix, prefix = (f':retry{retry}', RETRY_NOTE) if retry else ('', '')
    note, decision_id = prefix + args.note, f'{child}:{step}:{phase}{suffix}'
    cli('decision', child, '--step-id', step, '--phase', phase, '--choice', 'approve',
        '--decision-id', decision_id, '--evidence-note', note)
    kind = 'automated' if args.operator else 'delegated'
    append_decision(args.decision_dir, workflow=args.workflow_id, child=child, gate=step, phase=phase, choice='approve',
                    decided_by='automated' if args.operator else f'delegated: {args.delegated_by}',
                    channel='drive_gates', decision_id=decision_id, note_sha256=sha256_text(note))
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


def wait_for_operator(args, child, step, which, out, reviews):
    """Announce the operator's decision and open its pending record; returns the open gate."""
    log(f'WAITING FOR OPERATOR {args.operator}: {which} review of {child} {step}; outputs in {out}')
    print(f'Decide it yourself from {FRAMEWORK}, with your own note on what you checked:', flush=True)
    for choice in ('approve', 'deny'):
        print('  ' + shell_join([*DEFAULT_LANE.temporal_cli(), 'decision', child, '--step-id', step, '--phase',
                                 'review', '--choice', choice, '--decision-id', f'{child}:{step}:review',
                                 '--evidence-note', '<what you checked>']), flush=True)
    summary = None
    if args.card_summary:
        texts = [result['output'] for step_id, result in reviews if which == 'report' or step_id == SCOPE_STEP]
        summary = card_summary(which, texts or [result['output'] for _, result in reviews])
    path = write_pending(args.decision_dir, pending_record(args.workflow_id, child, step, which, out, summary))
    log(f'{child} {step} pending {which} decision recorded for the Slack bridge: {path.name}')
    return {'child': child, 'gate': step, 'kind': which, 'name': path.name}


def child_status(child):
    try:
        return cli('status', child)
    except Exception as exc:
        log(f'{child} status unreadable: {exc}')
        return None


def observed_choice(gate, state):
    """approve or deny as the workflow shows it after the gate moved on; None if nobody decided or it is unclear."""
    if state is None:
        return None
    if state.get('step_id') != gate['gate']:
        return 'approve'
    stage = state.get('stage')
    if stage in ('rejected', 'denied'):
        return 'deny'
    return 'approve' if stage in ('completed', 'executing', 'awaiting_execution_approval') else None


def close_pending(args, gate, state):
    """The operator's gate moved on: drop its pending record and make sure the decision log names who decided."""
    choice = observed_choice(gate, state)
    pending, claimed = (Path(args.decision_dir) / folder / gate['name'] for folder in ('pending', 'claimed'))
    retry_busy(lambda: pending.unlink(missing_ok=True))
    prefix = f'{gate["child"]}:{gate["gate"]}:review:'

    def bridge_lines():
        return [item for item in read_decisions(args.decision_dir)
                if str(item.get('decision_id') or '').startswith(prefix)]

    sent = bridge_lines()
    for _ in range(BRIDGE_GRACE_SECONDS):
        if sent or not claimed.exists():
            break
        time.sleep(1)
        sent = bridge_lines()
    where = f'{gate["kind"]} review of {gate["child"]} {gate["gate"]}'
    if sent:
        last = sent[-1]
        differs = choice is not None and choice != last.get('choice')
        log(f'{where} decided via {last.get("channel")} by {last.get("decided_by")}: {last.get("choice")}'
            + (f'; the workflow shows {choice}' if differs else ''))
        return
    retry_busy(lambda: claimed.unlink(missing_ok=True))
    if choice is None:
        log(f'{where} closed without an observed decision (stage {state.get("stage") if state else "unknown"})')
        return
    append_decision(args.decision_dir, workflow=args.workflow_id, child=gate['child'], gate=gate['gate'],
                    phase='review', choice=choice, decided_by='operator (outside driver)', channel='unknown',
                    decision_id=None, note_sha256=None)
    log(f'{where} decided outside the driver: {choice}')


def parse_args(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('workflow_id', help='the practice parent workflow ID')
    ap.add_argument('--delegated-by', help='delegated mode: the person who delegated these approvals')
    ap.add_argument('--reason', help='delegated mode: their instruction, recorded in every approval note')
    ap.add_argument('--two-decisions', action='store_true',
                    help='two-decision mode: the operator decides the scope and final report reviews')
    ap.add_argument('--operator', help='two-decision mode: the operator who makes those two decisions')
    ap.add_argument('--card-summary', action='store_true',
                    help='two-decision mode: put the scope text or the report verdict and first claims, labelled '
                         'bot-written, in the pending record for summary cards (synthetic lab cases only)')
    ap.add_argument('--decision-dir', type=Path, default=DECISION_DIR,
                    help='folder of decisions.jsonl and the pending/ records the Slack bridge reads '
                         '(default: %(default)s)')
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
        if args.card_summary:
            ap.error('--card-summary belongs to --two-decisions')
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
    if args.operator:
        log(f'TWO DECISIONS for {args.workflow_id}: operator {args.operator} approves the scope and accepts or '
            'rejects the final report; every other gate is approved automatically under ADR 0002 and recorded '
            'as automated, not as a human review.')
    else:
        log(f'DELEGATED APPROVALS for {args.workflow_id}: every execute and review gate is approved on behalf of '
            f'{args.delegated_by} ({args.reason}). These approvals are not human reviews of the content.')
    handled, dropped, gate = set(), set(), None
    while True:
        parent = cli('practice-status', args.workflow_id)
        if parent['temporal_status'] != 'RUNNING':
            if gate:
                close_pending(args, gate, child_status(gate['child']))
            log('parent finished: ' + json.dumps(parent))
            return 0 if parent['stage'] == 'completed' else 1
        child = parent.get('child_workflow_id')
        if not child:
            time.sleep(3)
            continue
        state = cli('status', child)
        stage, step = state['stage'], state['step_id']
        if gate and (child, step, stage) != (gate['child'], gate['gate'], 'awaiting_review'):
            close_pending(args, gate, state if child == gate['child'] else child_status(gate['child']))
            gate = None
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
            decide(args, child, step, 'execute', retry)
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
                gate = wait_for_operator(args, child, step, which, out, reviews)
            else:
                decide(args, child, step, 'review')
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

"""One command for a work hunt: export a window of the work Elastic, import it as a case, load it, hunt it.

Steps, each stopping the run on failure:
  1. export   hunt_lab.import_elastic export of [--start, --end) on --index (read-only, verified HTTPS)
              into runtime/work-exports/<case-id>.ndjson. The API key is read only from
              HUNT_ELASTIC_API_KEY, removed from this process's environment at start, and handed to
              the export child alone: no other child (lab, hunt, gate driver, so no bot) inherits it.
  2. import   hunt_lab.import_elastic import into runtime/cases/<case-id>/evidence ("data_origin":
              "work-export"). An existing case folder or export file is refused before any network call.
  3. load     operator/switch_case.py <evidence> --hold as a holder that outlives this command and keeps
              the VM up; its output goes to runtime/practice/work-hunts/<case-id>/holder.log.
  4. input    hermes_temporal.cli lab-input --tool-driven --data-origin work-export: the bots get only the
              loaded case, labelled a work log export, never the cluster address, index or key.
  5. hunt     one parallel practice round with --follow-ups follow-up hunters (default 6).
  6. gates    operator/drive_gates.py. With --operator it runs in two-decision mode: the operator approves
              the scope and accepts or rejects the final report (printed command or the Slack bridge with
              minimal cards); every other gate is approved and recorded as automated. --delegated-by and
              --reason instead approve every gate on that person's behalf, recorded as delegated.

Only the operator's own unclassified, non-CUI work data may be exported (planning tickets 01 and 12).
There is no answer key for work data, so nothing is scored: the operator's review of the report is the
evaluation. The run's record is runtime/practice/work-hunts/<case-id>/hunt.json.

Usage: python operator/work_hunt.py --url https://HOST:9200 --index PATTERN --start ISO --end ISO --case-id ID
           (--operator "<name>" | --delegated-by "<person>" --reason "<text>")
           [--hosts NAME,NAME] [--ca-file CA.pem] [--follow-ups 6] [--max-events N] [--reseed-python PATH]
"""
import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

from lab_paths import CASES, DEFAULT_LANE, FRAMEWORK, GATE_RUNS, PRACTICE, PYTHON, ROOT, RUNTIME
import drive_gates
from tool_loops import tcli, usage_total

# switch_case (imported by tool_loops) puts framework/ on sys.path.
from hermes_temporal.hunt import MAX_FOLLOW_UPS
from hunt_lab.import_elastic import (API_KEY_ENV, DATA_ORIGIN, DEFAULT_MAX_EVENTS, INDEX_PATTERN,
                                     cluster_base, host_names, window)
from hunt_lab.scenario import CASE_ID_PATTERN

EXPORTS = RUNTIME / 'work-exports'
WORK_HUNTS = PRACTICE / 'work-hunts'
REMINDER = ('Reminder: export only your own unclassified, non-CUI work data (planning tickets 01 and 12); '
            'CUI/NSS data never goes this way.')
READY_SECONDS = 2 * 3600


def say(message):
    print(time.strftime('%H:%M:%S ') + message, flush=True)


def parse_args(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--url', required=True, help='https://host:port of the work Elasticsearch')
    ap.add_argument('--index', required=True, help='index name or pattern, e.g. logs-*')
    ap.add_argument('--start', required=True, help='window start, ISO 8601 (inclusive)')
    ap.add_argument('--end', required=True, help='window end, ISO 8601 (exclusive)')
    ap.add_argument('--hosts', help='comma-separated exact host.name values (default: every host)')
    ap.add_argument('--ca-file', help='PEM CA bundle to verify the server with instead of the system trust store')
    ap.add_argument('--case-id', required=True, help='new case ID, [a-z0-9-]{3,64}; an existing case is refused')
    ap.add_argument('--follow-ups', type=int, default=6, help='follow-up hunters (0-%d, default 6)' % MAX_FOLLOW_UPS)
    ap.add_argument('--max-events', type=int, default=DEFAULT_MAX_EVENTS,
                    help='refuse a window holding more documents (default %(default)s)')
    ap.add_argument('--operator', help='two-decision mode: you approve the scope and decide the final report')
    ap.add_argument('--delegated-by', help='delegated mode: the person who delegated every gate approval')
    ap.add_argument('--reason', help='delegated mode: their instruction, recorded in every approval note')
    ap.add_argument('--reseed-python', default=PYTHON,
                    help='Python with pycdlib that reseeds the lab VM (default: HUNT_BOTS_PYTHON or this Python)')
    args = ap.parse_args(argv)
    if not CASE_ID_PATTERN.match(args.case_id):
        ap.error('--case-id must match [a-z0-9-]{3,64}')
    if not 0 <= args.follow_ups <= MAX_FOLLOW_UPS:
        ap.error(f'--follow-ups must be from 0 through {MAX_FOLLOW_UPS}')
    if args.max_events < 1:
        ap.error('--max-events must be a positive integer')
    if not INDEX_PATTERN.match(args.index):
        ap.error('--index must be an index name or pattern such as logs-*')
    try:
        cluster_base(args.url)
        window(args.start, args.end)
        args.hosts = host_names(args.hosts.split(',')) if args.hosts is not None else None
    except ValueError as exc:
        ap.error(str(exc))
    if args.ca_file:
        if not Path(args.ca_file).is_file():
            ap.error(f'--ca-file is not a file: {args.ca_file}')
        args.ca_file = str(Path(args.ca_file).resolve())
    # drive_gates owns the mode rules; checking them now refuses a bad mode before anything is exported.
    if args.operator is not None:
        args.gate_args = ['--two-decisions', '--operator', args.operator]
        if args.delegated_by is not None or args.reason is not None:
            ap.error('choose exactly one mode: --operator "<name>", or --delegated-by and --reason')
    else:
        args.gate_args = (['--delegated-by', args.delegated_by] if args.delegated_by is not None else []) + (
            ['--reason', args.reason] if args.reason is not None else [])
        if not args.gate_args:
            ap.error('choose exactly one mode: --operator "<name>", or --delegated-by and --reason')
    gate = drive_gates.parse_args(['preflight', *args.gate_args])
    args.operator, args.delegated_by = gate.operator, gate.delegated_by
    return args


def child(cmd, env, timeout):
    """(exit code, stdout, stderr) of one child run from framework/."""
    r = subprocess.run(cmd, cwd=FRAMEWORK, env=env, capture_output=True, text=True, encoding='utf-8',
                       errors='replace', timeout=timeout)
    return r.returncode, r.stdout, r.stderr


def last_json(text):
    line = next((line for line in reversed(text.splitlines()) if line.startswith('{')), '{}')
    return json.loads(line)


def start_holder(evidence, log_path, reseed_python):
    """switch_case.py --hold in its own process, logging to log_path; it keeps the VM up after this command ends."""
    log = log_path.open('ab')
    try:
        return subprocess.Popen([sys.executable, '-B', '-u', str(Path(__file__).with_name('switch_case.py')),
                                 str(evidence), '--hold'], cwd=ROOT, stdout=log, stderr=subprocess.STDOUT,
                                env=dict(DEFAULT_LANE.env(), HUNT_BOTS_PYTHON=reseed_python))
    finally:
        log.close()


def wait_ready(holder, log_path, case_id, timeout=READY_SECONDS, poll=5):
    """The holder's READY line once it names this case with events; SystemExit if it ends or times out first."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        text = log_path.read_text(encoding='utf-8', errors='replace') if log_path.exists() else ''
        ready = next((line for line in text.splitlines() if ' READY ' in line), None)
        if ready:
            fields = dict(part.split('=', 1) for part in ready.split() if '=' in part)
            if fields.get('case') != case_id or fields.get('events') in (None, 'None', '0'):
                raise SystemExit(f'the lab did not load {case_id}: {ready.strip()} (holder log {log_path})')
            return ready.strip()
        if holder.poll() is not None:
            raise SystemExit(f'the lab holder exited ({holder.returncode}) before READY; see {log_path}')
        time.sleep(poll)
    raise SystemExit(f'the lab did not report READY within {timeout // 60} minutes; see {log_path}')


def drive(workflow, gate_args):
    """Run the gate driver in the foreground so its WAITING FOR OPERATOR lines and decision commands show."""
    return subprocess.run([sys.executable, '-B', str(Path(__file__).with_name('drive_gates.py')), workflow, *gate_args],
                          env=DEFAULT_LANE.env()).returncode


def main(args):
    print(REMINDER, flush=True)
    case_dir = CASES / args.case_id
    evidence = case_dir / 'evidence'
    export = EXPORTS / f'{args.case_id}.ndjson'
    meta = export.with_name(export.name + '.meta.json')
    work = WORK_HUNTS / args.case_id
    for path in (case_dir, export, meta, work):
        if path.exists() or path.is_symlink():
            raise SystemExit(f'{path} already exists; choose a new --case-id (this never overwrites a case)')
    key = os.environ.pop(API_KEY_ENV, '')
    if not key:
        raise SystemExit(f'{API_KEY_ENV} holds no API key; set it for this shell only')
    DEFAULT_LANE.hermes_exe()
    EXPORTS.mkdir(parents=True, exist_ok=True)

    cmd = [PYTHON, '-B', '-m', 'hunt_lab.import_elastic', 'export', '--url', args.url, '--index', args.index,
           '--start', args.start, '--end', args.end, '--output', str(export), '--max-events', str(args.max_events)]
    cmd += ['--hosts', ','.join(args.hosts)] if args.hosts else []
    cmd += ['--ca-file', args.ca_file] if args.ca_file else []
    rc, out, err = child(cmd, dict(os.environ, **{API_KEY_ENV: key}), 3600)
    del key
    result = last_json(out)
    if rc or 'error' in result:
        raise SystemExit('export failed: ' + str(result.get('error') or err[-300:]))
    say(f"EXPORT {result['event_count']} events from {result['host']} {result['index']} "
        f"[{result['time_range_utc']['start_inclusive']}, {result['time_range_utc']['end_exclusive']}) "
        f"hosts={','.join(result['hosts']) if result['hosts'] else 'all'} elastic={result['elastic_version']} "
        f"sha256={result['ndjson']['sha256']} -> {export}")
    record = {'case_id': args.case_id, 'export': {name: result[name] for name in (
        'host', 'index', 'time_range_utc', 'hosts', 'event_count', 'elastic_version', 'ndjson', 'output', 'meta')}}

    rc, out, err = child([PYTHON, '-B', '-m', 'hunt_lab.import_elastic', 'import', '--input', str(export),
                          '--case-id', args.case_id, '--start', args.start, '--end', args.end,
                          '--evidence-dir', str(evidence), '--max-events', str(args.max_events)], None, 3600)
    result = last_json(out)
    if rc or 'error' in result:
        raise SystemExit('import failed: ' + str(result.get('error') or err[-300:]))
    say(f"IMPORT case {result['case_id']} data_origin={result['data_origin']} {result['event_count']} events "
        f"{result['host_count']} hosts ({result['outside_window']} outside the window) -> {evidence}")
    record['import'] = {name: result[name] for name in ('data_origin', 'event_count', 'host_count', 'outside_window', 'files')}

    work.mkdir(parents=True)
    holder_log = work / 'holder.log'
    holder = start_holder(evidence, holder_log, args.reseed_python)
    say(f'loading the lab VM (holder pid {holder.pid}, log {holder_log}); this takes several minutes')
    ready = wait_ready(holder, holder_log, args.case_id)
    say(ready)
    record['lab'] = {'ready': ready, 'holder_pid': holder.pid, 'holder_log': str(holder_log)}

    base_path = work / 'lab-input.json'
    rc, out, err = tcli('lab-input', '--tool-driven', '--data-origin', DATA_ORIGIN, '--state-dir',
                        str(DEFAULT_LANE.state_dir), '--output', str(base_path), timeout=120)
    if rc:
        raise SystemExit('lab-input failed: ' + err[-300:])
    base = json.loads(base_path.read_text(encoding='utf-8'))
    hunt = dict(base, parallel=True, follow_ups=args.follow_ups)
    input_path = work / 'input.json'
    input_path.write_text(json.dumps(hunt, indent=2), encoding='utf-8')
    workflow = f"work-hunt-{args.case_id}-{time.strftime('%Y%m%d%H%M%S')}"
    rc, out, err = tcli('practice', workflow, '--input', str(input_path), '--rounds', '1')
    if rc:
        raise SystemExit('hunt start failed: ' + err[-300:])
    child_id = f'{workflow}:round:001'
    say(f'HUNT STARTED {workflow} (parallel, {args.follow_ups} follow-ups) on case {args.case_id}')
    record.update(workflow=workflow, input=str(input_path), gate_mode=args.gate_args[0])
    if args.operator:
        print(f'Your two decisions (HUNT-BOTS.md rule 3) are yours alone, {args.operator}: approve the scope and '
              'accept or reject the final report. When the driver below prints WAITING FOR OPERATOR, run the '
              'decision command it prints with your own note, or answer on Slack after starting, in another shell '
              'with your Slack tokens:', flush=True)
        print('  ' + drive_gates.shell_join([sys.executable, str(Path(__file__).with_name('slack_gates.py')),
                                             '--operator-name', args.operator, '--operator-user', '<your Slack member ID>']),
              flush=True)
        print('Work data gets minimal ID-and-status cards only. Every other gate is approved automatically and '
              'recorded as automated, not as a human review.', flush=True)
    else:
        print(f'Every gate, including the scope and final report reviews, is approved on behalf of {args.delegated_by} '
              'and recorded as delegated, not as a human review.', flush=True)
    drive(workflow, args.gate_args)

    rc, out, err = tcli('status', child_id)
    status = json.loads(out) if not rc else {}
    report = GATE_RUNS / 'outputs' / workflow / '001-incident.txt'
    completed = status.get('stage') == 'completed' and report.exists()
    usage = usage_total(status) if status else None
    record.update(stage=status.get('stage', 'unknown'), completed=completed,
                  report=str(report) if report.exists() else None, usage=usage)
    (work / 'hunt.json').write_text(json.dumps(record, indent=2), encoding='utf-8')
    say(f"HUNT {'COMPLETED' if completed else 'ENDED'} {child_id} stage={record['stage']} "
        f"tokens={usage['total_tokens'] if usage else 'unknown'} "
        + (f'report={report}' if report.exists() else 'no final report'))
    say(f'the lab stays loaded while holder pid {holder.pid} runs; stop it when you are done '
        f"({'taskkill /PID %d /T /F' % holder.pid if os.name == 'nt' else 'kill %d' % holder.pid}). Record: {work / 'hunt.json'}")
    return 0 if completed else 1


if __name__ == '__main__':
    sys.exit(main(parse_args()))

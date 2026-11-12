"""Switch the lab to another case: stop the current case's container project, start one for the new case, and
wait for the lab health API to report it.

With no evidence_dir it only starts the last started case. The containers run detached from this process, so
the lab stays up after it exits; `hermes -p framework-network-analyst hunt-lab stop` removes them.

Usage: python operator/switch_case.py [<evidence_dir>]
"""
import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

from lab_paths import DEFAULT_LANE, FRAMEWORK

sys.path.insert(0, str(FRAMEWORK))
from hunt_lab.endpoints import QueryFailure, resolve  # noqa: E402

# Seconds `hunt-lab start` keeps reading status while the case loads; the health wait below continues after it.
START_WAIT = 120
READY_SECONDS = 2400


def lab(action, *options, timeout=600, lane=DEFAULT_LANE):
    r = subprocess.run([lane.hermes_exe(), '-p', 'framework-network-analyst', 'hunt-lab', action, *options],
                       env=lane.env(), capture_output=True, text=True, encoding='utf-8', errors='replace',
                       timeout=timeout)
    line = next((l for l in r.stdout.splitlines() if l.startswith('{')), '{}')
    return r.returncode, json.loads(line)


def say(msg):
    print(time.strftime('%H:%M:%S ') + msg, flush=True)


def serving_lab(lane=DEFAULT_LANE, case_id=None):
    """The lab serving the lane's case, with the caller secret its service requires (hunt_lab.endpoints.resolve).

    Raises hunt_lab.endpoints.QueryFailure with a fixed code when no lab serves one."""
    return resolve(lane.state_dir, case_id, profile='hunt-board')


def health(served):
    return served.get('/health', 'hunt-board', 30)


def ready(h, case_id=None):
    """Health says the case is served with its events. The resolver asks only the instance the case's state.json
    names, so a restarted lab's previous instance never answers here."""
    return (h.get('ready') is True and bool(h.get('event_count'))
            and (case_id is None or h.get('case_id') == case_id))


def start(*options):
    """`hunt-lab start` with options; the started case's ID, or SystemExit when the lab reports an error."""
    rc, st = lab('start', *options, '--wait', str(START_WAIT), timeout=START_WAIT + 300)
    say(f"start rc={rc} case={st.get('case_id')} {st.get('state')} {st.get('reason')}")
    if rc:
        raise SystemExit(f"start failed: {st.get('reason')}")
    return st.get('case_id')


def wait_ready(case_id, timeout=READY_SECONDS):
    """Print and return the READY line once the lab health API reports `case_id` ready; SystemExit on timeout."""
    deadline, failure = time.time() + timeout, None
    while True:
        try:
            served = serving_lab(case_id=case_id)
            h = health(served)
            if ready(h, case_id):
                break
        except QueryFailure as exc:
            failure = exc
        if time.time() > deadline:
            raise SystemExit(f'case {case_id} was not ready within {timeout // 60} minutes'
                             + (f' ({failure})' if failure else ''))
        time.sleep(15)
    line = (f"READY case={h.get('case_id')} events={h.get('event_count')} sessions={h.get('network_session_count')} "
            f"intel={h.get('intel_count')} lab_url={served.lab_url} arkime_url={served.arkime_url}")
    say(line)
    return line


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('evidence_dir', nargs='?', help='case evidence to load; omit to start the last started case')
    args = ap.parse_args()
    # hunt-lab runs with another working directory, so resolve a caller-relative evidence path first.
    options = []
    if args.evidence_dir:
        evidence = Path(args.evidence_dir).resolve()
        if not (evidence / 'case.json').is_file():
            ap.error(f'no case.json in {evidence}')
        options = ['--evidence-dir', str(evidence)]
    DEFAULT_LANE.hermes_exe()
    if args.evidence_dir:
        rc, st = lab('stop')
        if rc:
            raise SystemExit(f"stop failed: {st.get('reason')}")
        say(f"stopped case={st.get('case_id')} ({st.get('reason')})")
    wait_ready(start(*options))

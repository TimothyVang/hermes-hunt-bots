"""Switch the lab VM to another case: stop, reseed (fresh seed per load), start, wait for the health API.

With no evidence_dir it only starts the VM. Start waits until available memory covers the
deployment's memory_mib plus the runtime's 1,024 MiB headroom (and a small margin) instead of
failing once.

The VM process lives in the launching process tree: run this as a long-lived named service
with --hold so ending a check cannot take the VM down with it.

Usage: python operator/switch_case.py [<evidence_dir>] [--hold]
"""
import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

from lab_paths import DEFAULT_LANE, FRAMEWORK, PYTHON

sys.path.insert(0, str(FRAMEWORK))
from hunt_lab import runtime as lab_runtime  # noqa: E402
from hunt_lab.endpoints import resolve  # noqa: E402
from hunt_lab.runtime import _available_memory_mib as avail_mib  # noqa: E402  same probe the lab's start uses


def lab(action, timeout=600, lane=DEFAULT_LANE):
    # --vm: this tool drives the lab VM; without it hunt-lab acts on the container lab whenever Docker answers.
    r = subprocess.run([lane.hermes_exe(), '-p', 'framework-network-analyst', 'hunt-lab', action, '--vm'], env=lane.env(),
                       capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=timeout)
    line = next((l for l in r.stdout.splitlines() if l.startswith('{')), '{}')
    return r.returncode, json.loads(line)


def start_memory_mib():
    deployment = DEFAULT_LANE.state_dir / 'deployment.json'
    if not deployment.is_file():
        raise SystemExit(f'no lab deployment at {deployment}; prepare the lab VM first (framework/hunt_lab/prepare_guest.py)')
    return json.loads(deployment.read_text(encoding='utf-8'))['memory_mib'] + 1024 + 30


def say(msg):
    print(time.strftime('%H:%M:%S ') + msg, flush=True)


def serving_lab(lane=DEFAULT_LANE):
    """The lab serving the lane's case, with the caller secret its service requires (hunt_lab.endpoints.resolve).

    Raises hunt_lab.endpoints.QueryFailure with a fixed code when no lab serves one."""
    return resolve(lane.state_dir, runtime=lab_runtime, profile='hunt-board')


def health(served):
    return served.get('/health', 'hunt-board', 30)


def ready(h, instance=None, case_id=None):
    """Health says the case is served, and after a reseed it comes from that reseed's instance and case: the
    previous boot's lab server restarts first and reports ready for the old guest software, and the guest
    reports the new instance ID before setup has replaced the previous case's data."""
    return (h.get('ready') is True and bool(h.get('event_count'))
            and (instance is None or h.get('instance_id') == instance)
            and (case_id is None or h.get('case_id') == case_id))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('evidence_dir', nargs='?', help='case evidence to load; omit to start the current case')
    ap.add_argument('--hold', action='store_true', help='stay alive after READY so the VM keeps running')
    args = ap.parse_args()
    # The reseed runs from framework/, so resolve a caller-relative evidence path before the VM stops.
    if args.evidence_dir:
        evidence = Path(args.evidence_dir).resolve()
        if not (evidence / 'case.json').is_file():
            ap.error(f'no case.json in {evidence}')
        args.evidence_dir = str(evidence)
    DEFAULT_LANE.hermes_exe()
    if args.evidence_dir:
        lab('stop', 300)
        for _ in range(60):
            rc, st = lab('status', 180)
            if st.get('state') == 'stopped':
                break
            time.sleep(10)
        else:
            raise SystemExit('VM did not stop')
        say('vm stopped')
        r = subprocess.run([PYTHON, '-B', str(FRAMEWORK / 'hunt_lab' / 'prepare_guest.py'), 'reseed', '--state-dir', str(DEFAULT_LANE.state_dir),
                            '--evidence-dir', args.evidence_dir, '--profile', 'framework-network-analyst', '--update-deployment'],
                           cwd=FRAMEWORK, capture_output=True, text=True, timeout=1800)
        if r.returncode:
            raise SystemExit('reseed failed: ' + (r.stdout + r.stderr)[-600:])
        out = json.loads(r.stdout[r.stdout.index('{'):])
        say(f"reseed {out['status']} case {out['case_id']} load {out.get('load')} deployment_updated={out['deployment_updated']}")
    instance, case_id = (out.get('instance_id'), out.get('case_id')) if args.evidence_dir else (None, None)
    t0, rc = time.time(), 1
    while rc and time.time() - t0 < 3600:
        if avail_mib() >= start_memory_mib():
            rc, st = lab('start', 600)
            say(f"start rc={rc} {st.get('state')} {st.get('reason')} network={st.get('network')}")
        if rc:
            time.sleep(5)
    if rc:
        raise SystemExit('VM could not start within an hour (memory)')
    # Readiness comes only from the lab health API (setup reruns only for a new instance ID).
    t1, h = time.time(), {}
    while time.time() - t1 < 2400:
        rc, st = lab('status', 180)
        try:
            h = health(serving_lab())
            if ready(h, instance, case_id):
                break
        except Exception:
            pass
        time.sleep(15)
    say(f"READY case={h.get('case_id')} events={h.get('event_count')} sessions={h.get('network_session_count')} "
        f"intel={h.get('intel_count')} lab_url={st.get('lab_url')} arkime_url={st.get('arkime_url')}")
    while args.hold:
        time.sleep(3600)


if __name__ == '__main__':
    main()

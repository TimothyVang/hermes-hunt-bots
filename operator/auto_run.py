"""Start the lab VM whenever memory allows (no time limit), wait for the health API, then run
the watcher loop (tool_loops.py) as a child with the same arguments. Run as a long-lived named
service: the VM and the loop live in this process tree, so this process must stay alive until
the loop finishes. The loop's output goes to runtime/practice/tool-loops/auto-run.log.

Usage: python -u operator/auto_run.py <tool_loops args...>
"""
import subprocess
import sys
import time
from pathlib import Path

import switch_case as sc
import tool_loops
from lab_paths import TOOL_LOOPS

LOG = TOOL_LOOPS / 'auto-run.log'


def main():
    tool_loops.parse_args(sys.argv[1:], prog='auto_run.py', description=__doc__)
    LOG.parent.mkdir(parents=True, exist_ok=True)
    rc, st = sc.lab('status', 180)
    while st.get('state') != 'running':
        if sc.avail_mib() >= sc.start_memory_mib():
            rc, st = sc.lab('start', 600)
            sc.say(f"start rc={rc} {st.get('state')} {st.get('reason')}")
        else:
            time.sleep(5)
        rc, st = sc.lab('status', 180) if rc else (rc, st)
    h = {}
    for _ in range(160):
        rc, st = sc.lab('status', 180)
        try:
            h = sc.health(st['lab_url'])
            if h.get('status') == 'ok' and h.get('event_count'):
                break
        except Exception:
            pass
        time.sleep(15)
    sc.say(f"READY case={h.get('case_id')} events={h.get('event_count')} lab_url={st.get('lab_url')} arkime_url={st.get('arkime_url')}")
    with LOG.open('a', encoding='utf-8') as out:
        loop = subprocess.Popen([sys.executable, '-B', '-u', str(Path(__file__).with_name('tool_loops.py')), *sys.argv[1:]],
                                stdout=out, stderr=subprocess.STDOUT)
        sc.say(f'loop started pid={loop.pid}')
        code = loop.wait()
    sc.say(f'loop exited {code}; holding the VM')
    while True:
        time.sleep(3600)


if __name__ == '__main__':
    main()

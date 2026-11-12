"""Start the container lab for the loop's dev_case (the case switch_case.py loaded last, or the bundled fixture),
wait for the health API, then run the watcher loop (tool_loops.py) as a child with the same arguments. The lab
keeps running after the loop ends; `hermes -p framework-network-analyst hunt-lab stop` removes it. The loop's
output goes to runtime/practice/tool-loops/auto-run.log.

Usage: python -u operator/auto_run.py <tool_loops args...>
"""
import subprocess
import sys
from pathlib import Path

import switch_case as sc
import tool_loops
from lab_paths import TOOL_LOOPS

LOG = TOOL_LOOPS / 'auto-run.log'


def main():
    args = tool_loops.parse_args(sys.argv[1:], prog='auto_run.py', description=__doc__)
    LOG.parent.mkdir(parents=True, exist_ok=True)
    sc.start('--case-id', args.dev_case)
    sc.wait_ready(args.dev_case)
    with LOG.open('a', encoding='utf-8') as out:
        loop = subprocess.Popen([sys.executable, '-B', '-u', str(Path(__file__).with_name('tool_loops.py')), *sys.argv[1:]],
                                stdout=out, stderr=subprocess.STDOUT)
        sc.say(f'loop started pid={loop.pid}')
        code = loop.wait()
    sc.say(f'loop exited {code}; the lab stays up')
    return code


if __name__ == '__main__':
    sys.exit(main())

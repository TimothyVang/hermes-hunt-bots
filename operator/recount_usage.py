"""Recount a rounds file's token usage with the billed attempts that handoff retries left out (calls no model).

Rounds written before tool_loops.usage_total counted rejected handoff attempts sum only each round's latest
executions, so a round whose step was retried undercounts its tokens while still reporting steps_without_usage 0.
For each hunt line this queries its round's child workflow status (<workflow>:round:<round, default 001>) through
hermes_temporal.cli, recomputes the usage including every rejected attempt, prints the old and new total_tokens,
and writes a corrected copy next to the input as <name>.recounted.jsonl. The input is never changed.

A line whose status cannot be read, or whose status records no usage, loses its usage in the copy and gains
usage_recount_error, so cost_arms.py lists it as unmetered instead of trusting the old total; the exit code is
then 1. A line without a workflow is copied unchanged and reported.

Usage: python operator/recount_usage.py <rounds.jsonl>
"""
import argparse
import json
import sys
from pathlib import Path

import tool_loops


def recounted_path(path):
    return path.with_name(path.stem + '.recounted.jsonl')


def recount(item, tcli=tool_loops.tcli):
    """(corrected hunt, old total_tokens, new total_tokens, problem or None) for one rounds-file hunt."""
    old = (item.get('usage') or {}).get('total_tokens')
    workflow = item.get('workflow')
    if not isinstance(workflow, str) or not workflow:
        return item, old, old, 'no workflow; copied unchanged'
    round_number = item.get('round', 1)
    rc, out, err = tcli('status', f'{workflow}:round:{round_number:03d}')
    usage = None
    if rc:
        problem = f'status query failed: {(err or out).strip()[-300:]}'
    else:
        usage = tool_loops.usage_total(json.loads(out))
        problem = None if usage else 'status records no usage'
    fixed = {key: value for key, value in item.items() if key not in ('usage', 'usage_recount_error')}
    if usage:
        fixed['usage'] = usage
    else:
        fixed['usage_recount_error'] = problem
    return fixed, old, usage and usage['total_tokens'], problem


def run(path, tcli=tool_loops.tcli, out=sys.stdout):
    path = Path(path)
    lines, failed = [], 0
    for number, line in enumerate(path.read_text(encoding='utf-8').splitlines(), 1):
        if not line.strip():
            continue
        item = json.loads(line)
        fixed, old, new, problem = recount(item, tcli)
        failed += 'usage_recount_error' in fixed
        retried = (fixed.get('usage') or {}).get('retried_attempts')
        print(f'{number}: {item.get("case")} {item.get("workflow")} total_tokens {old} -> {new}'
              + (f' (retried attempts {retried})' if retried is not None else '')
              + (f' [{problem}]' if problem else ''), file=out)
        lines.append(json.dumps(fixed, ensure_ascii=False))
    target = recounted_path(path)
    target.write_text(''.join(line + '\n' for line in lines), encoding='utf-8')
    print(f'wrote {target}', file=out)
    return 1 if failed else 0


def main(argv=None):
    ap = argparse.ArgumentParser(prog='recount_usage.py', description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('rounds', type=Path, help='rounds JSONL; one hunt per line with its parent "workflow"')
    return run(ap.parse_args(argv).rounds)


if __name__ == '__main__':
    raise SystemExit(main())

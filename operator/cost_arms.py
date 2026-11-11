"""Q4 cost arms: the cheapest follow-up count K within one attack fact of the current team (calls no model).

Reads one rounds file per arm (--arm LABEL=PATH). Each line is a hunt as the team runner writes it:
{"case", "workflow", "completed", "halted_at", "usage": {input_tokens, output_tokens, cache_read_tokens,
cache_write_tokens, total_tokens, steps_without_usage}, "by_kind": {"attack": {"found", "partial", "total"}},
"decoys_blamed", "minutes_measured"}. Writes summary.json and prints a short table:

  G4.1  complete data: every --cases case has one completed hunt in every arm, and every step of every hunt
        recorded usage (steps_without_usage 0). Missing, incomplete and unmetered hunts are listed. A hunt's usage
        must include every retried handoff attempt (tool_loops.usage_total, which also records retried_attempts);
        rounds written before it counted them undercount retried steps, so run recount_usage.py on those first.
  G4.2  the rule, on the cases present in every arm (paired; the others are listed and left out): among the arms
        with mean attack facts fully evidenced at least the baseline's mean minus 1, no halt, and no more decoys
        blamed in total than the baseline, the chosen arm has the lowest mean tokens per hunt; otherwise "none
        qualifies". Equal means go to the arm named first. Totals over paired cases compare like means.
  G4.3  the cost of one hunt per arm at the --prices table, by token type, with the table's source.

Token types. A hunt's input_tokens include its cache reads and cache writes (as Hermes reports them), so the types
priced are uncached input (input - cache reads - cache writes, at the table's "input" rate), cache reads, cache
writes and output; they sum to total_tokens. Usage is not split by model, so every token is priced at the
table's one model.

Usage (one line):
  python operator/cost_arms.py --arm K0=k0.jsonl --arm K3=k3.jsonl --arm K6=k6.jsonl --prices prices.json
      [--baseline K6] [--cases team-med-011,...] [--out summary.json]
--cases defaults to team-med-011 through team-med-015, --baseline to K6, --out to
runtime/practice/cost/q4/summary.json. operator/prices.example.json shows the price table's shape.
"""
import argparse
import hashlib
import json
import re
from fractions import Fraction
from pathlib import Path

from lab_paths import PRACTICE

DEFAULT_OUT = PRACTICE / 'cost' / 'q4' / 'summary.json'
DEFAULT_CASES = tuple(f'team-med-{n:03d}' for n in range(11, 16))
DEFAULT_BASELINE = 'K6'
ARM_LABEL = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$')
FACT_MARGIN = 1
USAGE_KEYS = ('input_tokens', 'output_tokens', 'cache_read_tokens', 'cache_write_tokens', 'total_tokens')
# Priced token type -> the price table rate it is charged at.
TOKEN_TYPES = {'uncached_input': 'input', 'cache_read': 'cache_read', 'cache_write': 'cache_write',
               'output': 'output'}
PRICE_KEYS = ('input', 'output', 'cache_read', 'cache_write')


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False) + '\n',
                    encoding='utf-8')


def count(value):
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def token_types(usage):
    """(the four priced types plus total, or None; the reason the usage is incomplete, or None)."""
    if not isinstance(usage, dict):
        return None, 'no usage recorded'
    absent = [key for key in USAGE_KEYS if not count(usage.get(key))]
    if absent:
        return None, 'usage lacks ' + ', '.join(absent)
    uncached = usage['input_tokens'] - usage['cache_read_tokens'] - usage['cache_write_tokens']
    if uncached < 0:
        return None, 'input_tokens is below cache reads plus cache writes'
    types = {'uncached_input': uncached, 'cache_read': usage['cache_read_tokens'],
             'cache_write': usage['cache_write_tokens'], 'output': usage['output_tokens'],
             'total': usage['total_tokens']}
    missing = usage.get('steps_without_usage')
    if not count(missing):
        return types, 'steps_without_usage not recorded'
    if missing:
        return types, f'{missing} steps without usage'
    return types, None


def read_hunt(item, where):
    case = item.get('case')
    if not isinstance(case, str) or not case:
        raise ValueError(f'{where}: case must be a non-empty string')
    completed = item.get('completed') is True and item.get('halted_at') is None
    by_kind = item.get('by_kind')
    attack = by_kind.get('attack') if isinstance(by_kind, dict) else None
    if completed and not (isinstance(attack, dict) and count(attack.get('found'))):
        raise ValueError(f'{where}: completed hunt {case} has no by_kind.attack.found')
    if completed and not count(item.get('decoys_blamed')):
        raise ValueError(f'{where}: completed hunt {case} has no decoys_blamed')
    attack = attack if isinstance(attack, dict) else {}
    minutes = item.get('minutes_measured')
    tokens, problem = token_types(item.get('usage'))
    return {'case': case, 'workflow': item.get('workflow'), 'completed': completed,
            'halted_at': item.get('halted_at'), 'attack_found': attack.get('found') or 0,
            'attack_partial': attack.get('partial') or 0, 'attack_total': attack.get('total'),
            'decoys_blamed': item.get('decoys_blamed') or 0,
            'minutes': minutes if isinstance(minutes, (int, float)) and not isinstance(minutes, bool) else None,
            'tokens': tokens, 'usage_problem': problem}


def read_arm(path):
    """{case: hunt} for one rounds file; a case twice is refused, since the arm must name one hunt per case."""
    hunts = {}
    for number, line in enumerate(Path(path).read_text(encoding='utf-8').splitlines(), 1):
        if not line.strip():
            continue
        item = json.loads(line)
        if not isinstance(item, dict):
            raise ValueError(f'{path}:{number}: a hunt must be a JSON object')
        hunt = read_hunt(item, f'{path}:{number}')
        if hunt['case'] in hunts:
            raise ValueError(f'{path}:{number}: {hunt["case"]} appears twice; keep one hunt per case')
        hunts[hunt['case']] = hunt
    return hunts


def load_prices(path):
    prices = json.loads(Path(path).read_text(encoding='utf-8'))
    if not isinstance(prices, dict):
        raise ValueError(f'{path}: the price table must be a JSON object')
    for key in ('model', 'currency', 'source'):
        if not isinstance(prices.get(key), str) or not prices[key].strip():
            raise ValueError(f'{path}: {key} must be a non-empty string')
    rates = prices.get('per_million')
    if not isinstance(rates, dict) or set(rates) != set(PRICE_KEYS):
        raise ValueError(f'{path}: per_million must have exactly ' + ', '.join(PRICE_KEYS))
    for key, value in rates.items():
        if value is not None and not (isinstance(value, (int, float)) and not isinstance(value, bool) and value >= 0):
            raise ValueError(f'{path}: per_million.{key} must be a non-negative number or null')
    return prices


def completeness(arms, cases):
    """G4.1 over every (arm, case): one completed hunt with usage for every step."""
    missing, incomplete, unmetered, extra, ready = [], [], [], [], 0
    for arm, hunts in arms.items():
        extra += [{'arm': arm, 'case': case} for case in hunts if case not in cases]
        for case in cases:
            hunt = hunts.get(case)
            if hunt is None:
                missing.append({'arm': arm, 'case': case})
                continue
            if not hunt['completed']:
                incomplete.append({'arm': arm, 'case': case, 'workflow': hunt['workflow'],
                                   'halted_at': hunt['halted_at']})
            if hunt['usage_problem']:
                unmetered.append({'arm': arm, 'case': case, 'workflow': hunt['workflow'],
                                  'problem': hunt['usage_problem']})
            ready += hunt['completed'] and not hunt['usage_problem']
    expected = len(arms) * len(cases)
    return {'goal': 'Complete data: every case has a completed hunt in every arm, usage recorded for every step',
            'expected_hunts': expected, 'complete_hunts': ready, 'missing': missing, 'incomplete': incomplete,
            'usage_missing': unmetered, 'ignored_not_in_cases': extra,
            'pass': expected > 0 and ready == expected}


def mean(values):
    return Fraction(sum(values), len(values)) if values else None


def number(value, digits):
    return None if value is None else round(float(value), digits)


def arm_stats(hunts):
    """Means over one arm's paired hunts. Exact fractions are kept under '_exact' for the rule."""
    found = mean([hunt['attack_found'] for hunt in hunts])
    minutes = [hunt['minutes'] for hunt in hunts if hunt['minutes'] is not None]
    metered = all(hunt['tokens'] and not hunt['usage_problem'] for hunt in hunts)
    tokens = ({kind: mean([hunt['tokens'][kind] for hunt in hunts]) for kind in (*TOKEN_TYPES, 'total')}
              if hunts and metered else None)
    decoys = [hunt['decoys_blamed'] for hunt in hunts]
    return {'hunts': len(hunts), 'mean_attack_found': number(found, 4),
            'mean_attack_partial': number(mean([hunt['attack_partial'] for hunt in hunts]), 4),
            'halts': sum(not hunt['completed'] for hunt in hunts),
            'decoys_blamed_total': sum(decoys), 'decoys_blamed_max': max(decoys, default=0),
            'mean_minutes': number(sum(minutes) / len(minutes), 2) if minutes else None,
            'mean_tokens': None if tokens is None else {kind: number(value, 1) for kind, value in tokens.items()},
            'tokens_unknown_because': None if tokens is not None or not hunts
            else 'a paired hunt has incomplete usage',
            '_exact': {'found': found, 'tokens': tokens}}


def apply_rule(stats, order, baseline, paired):
    """G4.2: the qualifying arm with the lowest mean tokens per hunt, or 'none qualifies'."""
    if not paired:
        return {'goal': 'Rule applied: one chosen arm or "none qualifies"', 'chosen': None,
                'result': 'none qualifies', 'reason': 'no case is present in every arm', 'arms': {}, 'pass': False}
    base = stats[baseline]
    floor = base['_exact']['found'] - FACT_MARGIN
    verdicts, qualified = {}, []
    for arm in order:
        item = stats[arm]
        reasons = []
        if item['_exact']['found'] < floor:
            reasons.append(f'mean attack facts {item["mean_attack_found"]} below {number(floor, 4)}')
        if item['halts']:
            reasons.append(f'{item["halts"]} halts')
        if item['decoys_blamed_total'] > base['decoys_blamed_total']:
            reasons.append(f'{item["decoys_blamed_total"]} decoys blamed, baseline {base["decoys_blamed_total"]}')
        if item['_exact']['tokens'] is None:
            reasons.append('mean tokens unknown: a paired hunt has incomplete usage')
        verdicts[arm] = {'qualifies': not reasons, 'reasons': reasons}
        if not reasons:
            qualified.append(arm)
    chosen = min(qualified, key=lambda arm: (stats[arm]['_exact']['tokens']['total'], order.index(arm)),
                 default=None)
    return {'goal': 'Rule applied: one chosen arm or "none qualifies"', 'baseline': baseline,
            'attack_found_floor': number(floor, 4), 'baseline_decoys_blamed_total': base['decoys_blamed_total'],
            'arms': verdicts, 'chosen': chosen, 'result': chosen or 'none qualifies', 'pass': True}


def price_arms(stats, prices, prices_path):
    """G4.3: mean cost of one hunt per arm by token type at the price table."""
    if prices is None:
        return {'goal': 'Priced: cost of one hunt per arm by token type', 'table': None, 'arms': {},
                'reason': 'no --prices table given', 'pass': False}
    rates = prices['per_million']
    unpriced = [key for key in PRICE_KEYS if rates[key] is None]
    arms = {}
    for arm, item in stats.items():
        tokens = item['_exact']['tokens']
        if tokens is None:
            arms[arm] = {'by_type': None, 'total': None, 'reason': 'mean tokens unknown'}
            continue
        by_type = {kind: None if rates[rate] is None else round(float(tokens[kind]) * rates[rate] / 1_000_000, 6)
                   for kind, rate in TOKEN_TYPES.items()}
        total = None if None in by_type.values() else round(sum(by_type.values()), 6)
        arms[arm] = {'by_type': by_type, 'total': total}
    return {'goal': 'Priced: cost of one hunt per arm by token type',
            'table': {'path': str(prices_path), 'sha256': sha256(prices_path), 'model': prices['model'],
                      'currency': prices['currency'], 'source': prices['source'], 'per_million': rates},
            'unpriced_rates': unpriced, 'arms': arms,
            'pass': bool(arms) and not unpriced and all(cost['total'] is not None for cost in arms.values())}


def run(arm_paths, cases, baseline, prices_path, out):
    """arm_paths: [(label, rounds path)] in the order given. Writes and returns the summary."""
    order = [label for label, _ in arm_paths]
    if baseline not in order:
        raise ValueError(f'baseline {baseline} is not one of the arms ({", ".join(order)})')
    cases = list(dict.fromkeys(cases))
    arms = {label: read_arm(path) for label, path in arm_paths}
    prices = load_prices(prices_path) if prices_path else None
    paired = [case for case in cases if all(case in hunts for hunts in arms.values())]
    unpaired = [{'case': case, 'missing_from': [arm for arm in order if case not in arms[arm]]}
                for case in cases if case not in paired]
    stats = {arm: arm_stats([arms[arm][case] for case in paired]) for arm in order}
    goals = {'G4.1': completeness(arms, cases), 'G4.2': apply_rule(stats, order, baseline, paired),
             'G4.3': price_arms(stats, prices, prices_path)}
    goals['G4.2']['on_complete_data'] = goals['G4.1']['pass']
    for item in stats.values():
        del item['_exact']
    result = {'schema_version': 1, 'cases': cases, 'baseline': baseline, 'fact_margin': FACT_MARGIN,
              'arms': {label: {'rounds': str(path), 'rounds_sha256': sha256(path)} for label, path in arm_paths},
              'paired_cases': paired, 'unpaired': unpaired, 'per_arm': stats, 'goals': goals,
              'notes': ['input_tokens include cache reads and writes; uncached_input is the rest, priced at "input".',
                        'Usage is not split by model; every token is priced at the table\'s one model.']}
    write_json(Path(out), result)
    return result


def _cell(value, spec):
    return '-' if value is None else format(value, spec)


def table(result):
    costs = result['goals']['G4.3']['arms']
    currency = (result['goals']['G4.3']['table'] or {}).get('currency', '')
    lines = [f'{"arm":<6} {"hunts":>5} {"attack":>7} {"tokens/hunt":>12} {"halts":>5} {"decoys":>6} '
             f'{"minutes":>7} {"cost/hunt":>12}']
    for arm, item in result['per_arm'].items():
        tokens = item['mean_tokens']['total'] if item['mean_tokens'] else None
        cost = (costs.get(arm) or {}).get('total')
        cost = '-' if cost is None else f'{cost:.2f} {currency}'.strip()
        lines.append(f'{arm:<6} {item["hunts"]:>5} {_cell(item["mean_attack_found"], ".2f"):>7} '
                     f'{_cell(tokens, ",.0f"):>12} {item["halts"]:>5} {item["decoys_blamed_total"]:>6} '
                     f'{_cell(item["mean_minutes"], ".1f"):>7} {cost:>12}')
    goals = result['goals']
    lines.append(f'paired cases {len(result["paired_cases"])}; unpaired '
                 + (', '.join(item['case'] for item in result['unpaired']) or 'none'))
    lines.append(f'chosen: {goals["G4.2"]["result"]}')
    lines += [f'{key} {"pass" if goal["pass"] else "FAIL"}' for key, goal in goals.items()]
    return '\n'.join(lines)


def parse_arm(text):
    label, sep, path = text.partition('=')
    if not sep or not ARM_LABEL.match(label) or not path:
        raise argparse.ArgumentTypeError(f'expected LABEL=PATH, got {text!r}')
    return label, Path(path)


def parse_args(argv=None):
    ap = argparse.ArgumentParser(prog='cost_arms.py', description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--arm', type=parse_arm, action='append', required=True, metavar='LABEL=PATH',
                    help='One arm: its label and its rounds file (JSON lines, one hunt per case). Repeat per arm.')
    ap.add_argument('--baseline', default=DEFAULT_BASELINE, help='The arm the rule compares against (default K6)')
    ap.add_argument('--cases', default=','.join(DEFAULT_CASES), help='Comma-separated case IDs every arm hunts')
    ap.add_argument('--prices', type=Path, help='Price table JSON (see operator/prices.example.json)')
    ap.add_argument('--out', type=Path, default=DEFAULT_OUT, help='Summary file to write')
    return ap.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    try:
        labels = [label for label, _ in args.arm]
        if len(set(labels)) != len(labels):
            raise ValueError('each --arm label must be different')
        cases = [case.strip() for case in args.cases.split(',') if case.strip()]
        if not cases:
            raise ValueError('--cases names no case')
        result = run(args.arm, cases, args.baseline, args.prices, args.out)
    except (OSError, ValueError) as error:
        print(json.dumps({'error': str(error)}))
        return 2
    print(table(result))
    print(f'summary: {args.out}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

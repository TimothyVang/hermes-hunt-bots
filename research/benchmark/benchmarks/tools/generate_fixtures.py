"""Deterministic generator for the invented benchmark fixtures.

Authored cases live in `fixture_cases.py` with readable evaluator-side symbols.
This script turns each into a public bundle plus evaluator truth:

- Every public identifier (event, asset, source, question) and every
  reference written as `@kind:name` inside event fields becomes the opaque
  token `kind-` + the first 12 hex digits of
  HMAC-SHA256(case salt, canonical JSON [kind, name]). Each case commits its
  own fixed salt, so tokens are stable yet carry no authored meaning.
- Assets, sources and questions are ordered by opaque ID (a salt shuffle);
  events by (timestamp_utc, opaque event_id).
- `timestamp_utc = timestamp_original - clock_offset_seconds`: the authored
  time is true UTC and the original is what the skewed source clock printed.
- Step windows span the step's own records (or `window_events`).
- Assessment labels follow the attribution convention stated in
  prompt-contract.txt: 1 when a sufficiently observable step is attributed to
  the asset, null when nothing is attributed and a known gap covers the whole
  window, otherwise 0.
- source_receipt_sha256 = SHA-256 of canonical JSON of the array of the step's
  support records (records.jsonl rows for the union of its support-set event
  IDs, sorted by event_id); an unobservable step hashes the empty array.
- Difficulty is measured from the generated records by
  benchmark_difficulty.measure_case and must equal the authored expectation.

Usage, from research/benchmark/:
  py -3 -B benchmarks/tools/generate_fixtures.py             # rewrite fixtures + example digests
  py -3 -B benchmarks/tools/generate_fixtures.py --output DIR  # fixtures only, into DIR
Rerunning produces byte-identical files. Invented data only; no network.
"""
import argparse
import copy
import hashlib
import hmac
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
BENCHMARKS = TOOLS.parent
FRAMEWORK = BENCHMARKS.parent
for _path in (str(FRAMEWORK), str(TOOLS)):
    if _path not in sys.path:
        sys.path.insert(0, _path)

from benchmark_contracts import (  # noqa: E402
    ASSESSMENT_QUESTION, canonical_bytes, digest_bytes, load_json, parse_utc,
    validate_public_bundle, validate_scenario, validate_truth,
)
from benchmark_difficulty import measure_case  # noqa: E402
import fixture_cases  # noqa: E402

TOKEN_HEX = 12
EXAMPLES = ('experiment.json', 'experiment-graduated.json')


class Case:
    def __init__(self, spec):
        self.spec = spec
        self.salt = bytes.fromhex(spec['salt'])
        self.zulu = spec['zulu']

    def token(self, kind, name):
        mac = hmac.new(self.salt, canonical_bytes([kind, name]), hashlib.sha256)
        return kind + '-' + mac.hexdigest()[:TOKEN_HEX]

    def stamp(self, moment, zone=None):
        zone = timezone.utc if zone is None else zone
        text = moment.astimezone(zone).strftime('%Y-%m-%dT%H:%M:%S')
        if moment.microsecond:
            text += '.%06d' % moment.microsecond
        offset = moment.astimezone(zone).utcoffset()
        if offset == timedelta(0) and zone is timezone.utc:
            return text + ('Z' if self.zulu else '+00:00')
        minutes = int(offset.total_seconds() // 60)
        sign = '-' if minutes < 0 else '+'
        return text + '%s%02d:%02d' % (sign, abs(minutes) // 60, abs(minutes) % 60)


def utc(text):
    return datetime.strptime(text, '%Y-%m-%dT%H:%M:%S').replace(tzinfo=timezone.utc)


def zone(text):
    if text is None:
        return None
    sign = -1 if text[0] == '-' else 1
    return timezone(sign * timedelta(hours=int(text[1:3]), minutes=int(text[4:6])))


def render(case, value, originals):
    if isinstance(value, str) and value.startswith('@'):
        kind, _, name = value[1:].partition(':')
        if kind == 'time':
            return originals[name]
        return case.token(kind, name)
    if isinstance(value, list):
        return [render(case, item, originals) for item in value]
    if isinstance(value, dict):
        return {key: render(case, item, originals) for key, item in value.items()}
    return value


def window(case, start, end):
    return {'start_inclusive': case.stamp(start), 'end_exclusive': case.stamp(end)}


def build(spec, generated):
    case = Case(spec)
    start, end = utc(spec['window'][0]), utc(spec['window'][1])
    full = window(case, start, end)
    sources = {item['id']: item for item in spec['sources']}
    records = spec['records']()
    symbols = [record['id'] for record in records]
    if len(set(symbols)) != len(symbols):
        raise SystemExit(spec['case_id'] + ': duplicate authored record symbol')
    originals, times = {}, {}
    for record in records:
        source = sources[record['source']]
        moment = utc(record['t'])
        times[record['id']] = moment
        offset = timedelta(seconds=source.get('offset', 0))
        originals[record['id']] = case.stamp(moment + offset, zone(source.get('tz')))
    events = []
    for record in records:
        fields = {'timestamp_original': originals[record['id']]}
        fields.update(render(case, record['fields'], originals))
        events.append({
            'event_id': case.token('event', record['id']),
            'timestamp_utc': case.stamp(times[record['id']]),
            'source_id': case.token('source', record['source']),
            'asset_id': case.token('asset', record['asset']),
            'event_type': record['type'],
            'fields': fields,
        })
    events.sort(key=lambda item: (parse_utc(item['timestamp_utc'], 'timestamp_utc'), item['event_id']))
    rows = [canonical_bytes(event) for event in events]
    data = b''.join(row + b'\n' for row in rows)
    file_sha = digest_bytes(data)
    for number, event in enumerate(events, 1):
        event['locator'] = {'file_sha256': file_sha, 'record_id': str(number)}
    assets = sorted(({'asset_id': case.token('asset', item['id']), 'os_family': item['os_family'],
                      'os_version': item['os_version'], 'architecture': item['architecture'],
                      'vendor': item['vendor']} for item in spec['assets']),
                    key=lambda item: item['asset_id'])
    public_sources = []
    for item in spec['sources']:
        public_sources.append({
            'source_id': case.token('source', item['id']),
            'asset_ids': sorted(case.token('asset', asset) for asset in item['assets']),
            'telemetry': item['telemetry'],
            'clock_offset_seconds': item.get('offset', 0),
            'clock_uncertainty_seconds': item['uncertainty'],
            'window_utc': copy.deepcopy(full),
            'sensor_version': item['sensor'],
            'config_version': item['config'],
            'completeness': item['completeness'],
            'source_sha256': file_sha,
        })
    public_sources.sort(key=lambda item: item['source_id'])
    gaps = [{'source_id': case.token('source', gap['source']), 'asset_id': case.token('asset', gap['asset']),
             'window_utc': window(case, utc(gap['window'][0]), utc(gap['window'][1])) if gap.get('window') else copy.deepcopy(full),
             'reason': gap['reason']} for gap in spec.get('known_gaps', [])]
    questions = sorted(({'question_id': case.token('question', item['id']),
                         'asset_id': case.token('asset', item['id']),
                         'window_utc': copy.deepcopy(full), 'question': ASSESSMENT_QUESTION}
                        for item in spec['assets']), key=lambda item: item['question_id'])
    evidence = {
        'schema_version': 1, 'case_id': spec['case_id'], 'window_utc': full,
        'assets': assets, 'sources': public_sources, 'events': events, 'known_gaps': gaps,
        'files': [{'path': 'records.jsonl', 'byte_count': len(data), 'sha256': file_sha}],
        'assessment_questions': questions,
    }
    evidence_sha = digest_bytes(canonical_bytes(evidence))
    row_by_id = {event['event_id']: {k: v for k, v in event.items() if k != 'locator'} for event in events}
    authored = spec['truth']
    steps = []
    for step in authored['steps']:
        supports = [sorted(case.token('event', symbol) for symbol in support) for support in step['support_sets']]
        union = sorted({event_id for support in supports for event_id in support})
        if step.get('window'):
            step_window = window(case, utc(step['window'][0]), utc(step['window'][1]))
        else:
            chosen = step.get('window_events') or sorted({s for support in step['support_sets'] for s in support})
            moments = [times[symbol] for symbol in chosen]
            step_window = window(case, min(moments), max(moments) + timedelta(seconds=1))
        steps.append({
            'step_id': step['step_id'], 'technique_id': step['technique_id'],
            'asset_id': case.token('asset', step['asset']), 'window_utc': step_window,
            'execution_outcome': step['execution_outcome'], 'observability': step['observability'],
            'support_sets': supports,
            'source_receipt_sha256': digest_bytes(canonical_bytes([row_by_id[event_id] for event_id in union])),
        })
    attributed = {step['asset'] for step in authored['steps'] if step['observability'] == 'sufficient'}
    undecidable = {gap['asset'] for gap in spec.get('known_gaps', []) if not gap.get('window')}
    labels = {}
    for question in questions:
        symbol = next(item['id'] for item in spec['assets']
                      if case.token('question', item['id']) == question['question_id'])
        labels[question['question_id']] = (1 if symbol in attributed
                                           else None if symbol in undecidable else 0)
    truth = {
        'schema_version': 1, 'case_id': spec['case_id'], 'evidence_manifest_sha256': evidence_sha,
        'truth_revision': spec['revision'], 'attack_release': 'v20', 'steps': steps,
        'edges': [list(edge) for edge in authored['edges']],
        'controls': [{'control_id': item['control_id'], 'asset_id': case.token('asset', item['asset']),
                      'window_utc': copy.deepcopy(full), 'expected_disposition': item['expected_disposition']}
                     for item in authored['controls']],
        'assessment_labels': labels,
        'lookalike_event_ids': [sorted(case.token('event', symbol) for symbol in group)
                                for group in authored.get('lookalikes', [])],
    }
    curation = {}
    if spec.get('matched_control'):
        curation['matched_control'] = generated[spec['matched_control']]['scenario']['difficulty']
    difficulty = measure_case(evidence, [row_by_id[event['event_id']] for event in events], truth, curation)
    expected_band, expected_scores = spec['expect']
    scores = [difficulty['factors'][key]['score'] for key in ('noise', 'joins', 'time_span', 'gaps', 'ambiguity')]
    if difficulty['band'] != expected_band or scores != expected_scores:
        raise SystemExit('{}: measured {} {} != authored {} {}'.format(
            spec['case_id'], difficulty['band'], scores, expected_band, expected_scores))
    sophistication = copy.deepcopy(spec['sophistication'])
    for step in sophistication['steps']:
        step['asset_id'] = case.token('asset', step['asset_id'])
    scenario = {
        'schema_version': 1, 'scenario_id': spec['scenario_id'], 'family_id': spec['family_id'],
        'revision': spec['revision'], 'split': 'development', 'provenance': 'synthetic',
        'coverage': spec['coverage'], 'difficulty': difficulty, 'sophistication': sophistication,
        'attack_release': 'v20', 'source_references': spec['source_references'],
        'evidence_manifest_sha256': evidence_sha,
    }
    return {'scenario': scenario, 'evidence': evidence, 'truth': truth, 'records': data}


def pretty(value):
    return (json.dumps(value, indent=2, ensure_ascii=False) + '\n').encode('utf-8')


def generate(output):
    coverage = load_json(BENCHMARKS / 'coverage.json')
    generated = {}
    for spec in fixture_cases.CASES:
        result = build(spec, generated)
        generated[spec['case_id']] = result
        root = Path(output) / spec['case_id']
        (root / 'public').mkdir(parents=True, exist_ok=True)
        (root / 'evaluator').mkdir(parents=True, exist_ok=True)
        (root / 'public' / 'records.jsonl').write_bytes(result['records'])
        (root / 'public' / 'evidence.json').write_bytes(pretty(result['evidence']))
        (root / 'evaluator' / 'truth.json').write_bytes(pretty(result['truth']))
        (root / 'scenario.json').write_bytes(pretty(result['scenario']))
        validate_scenario(result['scenario'], coverage)
        validate_public_bundle(result['evidence'], root / 'public')
        validate_truth(result['truth'], result['evidence'])
    return generated


def refresh_examples():
    digests = {
        'coverage_sha256': digest_bytes(canonical_bytes(load_json(BENCHMARKS / 'coverage.json'))),
        'workflow_sha256': digest_bytes(canonical_bytes(load_json(BENCHMARKS / 'team-workflow.json'))),
        'prompt_contract_sha256': digest_bytes((BENCHMARKS / 'prompt-contract.txt').read_bytes()),
    }
    for name in EXAMPLES:
        path = BENCHMARKS / 'examples' / name
        experiment = load_json(path)
        experiment.update(digests)
        path.write_bytes(pretty(experiment))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--output', help='write fixtures here instead of benchmarks/fixtures')
    args = parser.parse_args(argv)
    generate(args.output or BENCHMARKS / 'fixtures')
    if not args.output:
        refresh_examples()
    return 0


if __name__ == '__main__':
    sys.exit(main())

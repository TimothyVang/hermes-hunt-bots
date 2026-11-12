"""Agent consensus: merge two independent curation drafts by deterministic agreement.

An automatic, honestly labelled replacement for human answer-key review. Two
curation proposals for the same dataset, written independently, are merged by
fixed rules. The output is a NEW curation with `attestation_hint:
"agent_consensus"`, which the importers record as truth `attestation:
"agent_consensus"`. That is stronger than one unreviewed draft, weaker than a
human attestation, and always its own cohort.

It reads the two drafts plus the draft import's locator map (to resolve every
locator to its original line) and curation template (default asset facts). It
never interprets event contents, calls a model or records a human action. It
cannot verify that the drafts were written independently; that is the
operator's claim, and the tool only refuses byte-identical drafts.

    py -3 benchmark_consensus.py merge --draft-a A.json --draft-b B.json --locators DRAFT/evaluator/locators.json --template DRAFT/evaluator/curation-template.json --output NEW.json [--report NEW_REPORT.json]

Exit codes: 0 success; 2 validation failure (`error: <code>: <field>`).
"""
import argparse
import json
import os
import sys
from datetime import datetime, timezone
from fractions import Fraction
from pathlib import Path

import benchmark_import_attackdata as attackdata
import benchmark_import_otrf as otrf
from benchmark_attack import ATTACK_RELEASE, canonical_technique, technique_status
from benchmark_contracts import (COVERAGE_AXES, BenchmarkError, _array, _attack_release, _digest, _edges, _enum,
                                 _fields, _id, _reference, _sophistication, _strings, _technique, _text,
                                 _unique_objects, _window, canonical_bytes, decode_json, digest_bytes)
from benchmark_scoring import _maximum_matching

TOOL_VERSION = 'agent-consensus-1'
ATTESTATION = 'agent_consensus'
CURATOR = 'agent-consensus'
# Most conservative first; a merged step keeps the lower of the two drafts' claims.
OBSERVABILITY_ORDER = ('unknown', 'absent', 'insufficient', 'sufficient')
OUTCOMES = ('succeeded', 'blocked', 'failed', 'unknown')
PHASES = ('initial', 'persistence', 'reentry')
DISPOSITIONS = ('benign', 'insufficient')
BANDS = ('S0', 'S1', 'S2', 'S3', 'S4', 'S5')
STEP_KEYS = {'step_id', 'technique_id', 'asset', 'window_utc', 'execution_outcome', 'observability',
             'support_sets', 'boundary_id', 'phase'}
CONTROL_KEYS = {'control_id', 'asset', 'window_utc', 'expected_disposition'}
SOPHISTICATION_KEYS = {'band', 'boundaries', 'preconditions', 'emulation_limitations', 'group_ids',
                       'source_references'}
ASSET_FACTS = ('os_version', 'architecture', 'vendor')
MAX_SUPPORT_SETS = 16
# The draft import's locator map and curation template scale with the dataset.
MAX_MAP_BYTES = 256 * 1024 * 1024
# Boundary kinds that satisfy the same hunt-rubric-1 condition.
BOUNDARY_CLASSES = (frozenset({'identity', 'privilege'}), frozenset({'segment', 'domain'}),
                    frozenset({'on-prem', 'cloud'}), frozenset({'it', 'ot'}))
FORMATS = {
    'otrf': {'asset_key': 'hostname', 'locators': otrf._LOCATOR_KEYS, 'folded': ('channel', 'hostname'),
             'load': otrf.load_curation},
    'attackdata': {'asset_key': 'asset_name', 'locators': attackdata._LOCATOR_KEYS, 'folded': (),
                   'load': attackdata.load_curation},
}
LIMITATIONS = (
    'Agreement is mechanical: two AI drafts that agree can share the same mistake. No human reviewed this '
    'answer key.',
    'Independence of the drafts is the operator\'s claim; the tool only refuses byte-identical drafts.',
    'Every locator is resolved to its original line through the draft import\'s locators.json; merged '
    'locators are written as {"line": N}.',
    'Merged support sets are the minimal unions of one support set from each draft (at most 16). Each is '
    'complete for both drafts, so a merged set can require more records than either draft alone. Jaccard values '
    'measure agreement only; they never filter steps.',
    'Kappa items are every technique either draft proposed crossed with every curated asset; techniques '
    'neither draft proposed are not counted.',
    'S5 survives only when both drafts claim it; the importer re-checks its sparse/ambiguous-trace condition '
    'against measured difficulty.',
    'A disputed os_family takes the value that differs from the draft template default (else draft A\'s), a '
    'disputed attack_release the newer version, a disputed matched_control draft A\'s (else draft B\'s), and '
    'disputed assessment_windows or clock_declaration the draft template\'s (unset windows: the whole bundle); '
    'all are reported as disputed.',
    'Technique IDs are compared and written in their canonical form for the pinned ATT&CK release (revoked IDs '
    'follow their replacement); a renamed ID raises the merged attack_release to that release.',
)


def _fail(code, field):
    raise BenchmarkError(code, field)


def _ratio(numerator, denominator):
    return None if not denominator else Fraction(numerator, denominator)


def _number(value):
    return None if value is None else round(float(value), 6)


def _mean(values):
    present = [value for value in values if value is not None]
    return sum(present, Fraction(0)) / len(present) if present else None


# --------------------------------------------------------------- side files

def _read_side_file(path, field):
    _, data = otrf._read_regular(path, MAX_MAP_BYTES, field)
    return decode_json(data), digest_bytes(data)


def locator_index(value):
    """Index a draft import's evaluator/locators.json: each imported event's original line and record ID."""
    if type(value) is not dict or type(value.get('events')) is not dict:
        _fail('invalid_object', 'locators')
    _digest(value.get('dataset_sha256'), 'locators.dataset_sha256')
    lines, records = set(), {}
    for entry in value['events'].values():
        if type(entry) is not dict or type(entry.get('line')) is not int or entry['line'] < 1 \
                or entry['line'] in lines or type(entry.get('record_id')) not in (str, type(None)):
            _fail('invalid_locator_map', 'locators.events')
        lines.add(entry['line'])
        # Older flat exports' maps carry no record_id/channel/hostname keys: missing means None.
        if entry.get('record_id') is not None:
            records.setdefault(entry['record_id'], []).append(entry)
    return {'dataset_sha256': value['dataset_sha256'], 'lines': lines, 'records': records}


def template_defaults(value):
    """Defaults of a draft import's evaluator/curation-template.json: per-asset os_family, windows, clock."""
    curation = value.get('curation') if type(value) is dict else None
    if type(curation) is not dict or type(curation.get('assets')) is not list:
        _fail('invalid_object', 'template.curation')
    _digest(curation.get('dataset_sha256'), 'template.curation.dataset_sha256')
    defaults = {}
    for item in curation['assets']:
        name = item.get('hostname', item.get('asset_name')) if type(item) is dict else None
        if type(name) is not str or not name:
            _fail('invalid_object', 'template.curation.assets')
        defaults[name.casefold()] = item.get('os_family')
    defaults = {'dataset_sha256': curation['dataset_sha256'], 'os_family': defaults}
    # The draft's own choices for fields two drafts may legitimately set differently; absent means unset.
    for key in ('assessment_windows', 'clock_declaration'):
        if key in curation:
            defaults[key] = curation[key]
    return defaults


def _matches(recorded, cited, folded):
    if type(recorded) is not str:
        return False
    return recorded.casefold() == cited.casefold() if folded else recorded == cited


def _resolve(locator, spec, index, field):
    """Original line of one locator in any of the importer's forms."""
    if type(locator) is not dict or set(locator) not in spec['locators']:
        _fail('invalid_locator', field)
    if 'line' in locator:
        if type(locator['line']) is not int or locator['line'] < 1:
            _fail('invalid_locator', field)
        if locator['line'] not in index['lines']:
            _fail('unresolved_locator', field)
        return locator['line']
    if any(type(item) is not str or not item for item in locator.values()):
        _fail('invalid_locator', field)
    found = [entry for entry in index['records'].get(locator['record_id'], [])
             if all(_matches(entry.get(key), locator[key], key in spec['folded'])
                    for key in locator if key != 'record_id')]
    if not found:
        _fail('unresolved_locator', field)
    if len(found) > 1:
        _fail('ambiguous_locator', field)
    return found[0]['line']


def _line_sets(value, spec, index, field):
    """Groups of locators as a set of line sets; repeated citations of one record collapse."""
    _array(value, field)
    result = set()
    for group in value:
        _array(group, field, nonempty=True)
        result.add(frozenset(_resolve(locator, spec, index, field) for locator in group))
    return result


# --------------------------------------------------------------------- drafts

def _selector(value, spec, names, field):
    _fields(value, {spec['asset_key']}, field)
    name = value[spec['asset_key']]
    if type(name) is not str or name.casefold() not in names:
        _fail('unknown_asset', field)
    return name.casefold()


def parse_draft(curation, fmt, sha256, label, index):
    """Validate a loaded proposal's truth fields and return its comparable, line-resolved form."""
    spec = FORMATS[fmt]
    field = 'draft_' + label
    _attack_release(curation['attack_release'], field + '.attack_release')
    names, assets = {}, {}
    _array(curation['assets'], field + '.assets', nonempty=True)
    for item in curation['assets']:
        _fields(item, {spec['asset_key'], 'os_family'} | set(ASSET_FACTS), field + '.assets')
        _text(item[spec['asset_key']], field + '.assets.' + spec['asset_key'])
        folded = item[spec['asset_key']].casefold()
        if folded in assets:
            _fail('duplicate_item', field + '.assets')
        _text(item['os_family'], field + '.assets.os_family')
        for key in ASSET_FACTS:
            _text(item[key], field + '.assets.' + key, nullable=True)
        assets[folded] = item
        names[folded] = item[spec['asset_key']]

    sophistication = curation['sophistication']
    _fields(sophistication, SOPHISTICATION_KEYS, field + '.sophistication')
    _enum(sophistication['band'], BANDS, field + '.sophistication.band')
    boundaries = {}
    for key, item in _unique_objects(sophistication['boundaries'], 'boundary_id',
                                     field + '.sophistication.boundaries').items():
        _fields(item, {'boundary_id', 'kind'}, field + '.sophistication.boundaries')
        _text(item['kind'], field + '.sophistication.boundaries.kind')
        boundaries[key] = item['kind']
    for key in SOPHISTICATION_KEYS - {'band', 'boundaries'}:
        _strings(sophistication[key], field + '.sophistication.' + key)
    _strings(curation['source_references'], field + '.source_references')
    _fields(curation['coverage'], set(COVERAGE_AXES), field + '.coverage')
    for axis in COVERAGE_AXES:
        _strings(curation['coverage'][axis], field + '.coverage.' + axis)

    steps = {}
    _array(curation['steps'], field + '.steps')
    for item in curation['steps']:
        where = field + '.steps'
        _fields(item, STEP_KEYS, where)
        _id(item['step_id'], where + '.step_id')
        if item['step_id'] in steps:
            _fail('duplicate_identifier', where + '.step_id')
        _technique(item['technique_id'], where + '.technique_id')
        if technique_status(item['technique_id']) == 'unknown':
            _fail('unknown_technique', where + '.technique_id')
        # Revoked IDs compare and merge under their replacement in the pinned ATT&CK release.
        technique = canonical_technique(item['technique_id'])
        _enum(item['execution_outcome'], OUTCOMES, where + '.execution_outcome')
        _enum(item['observability'], OBSERVABILITY_ORDER, where + '.observability')
        _enum(item['phase'], PHASES, where + '.phase')
        _reference(item['boundary_id'], boundaries, where + '.boundary_id')
        sets = _line_sets(item['support_sets'], spec, index, where + '.support_sets')
        if item['observability'] == 'sufficient' and not sets:
            _fail('invalid_array', where + '.support_sets')
        steps[item['step_id']] = {
            'step_id': item['step_id'], 'technique_id': technique, 'technique_written': item['technique_id'],
            'asset': _selector(item['asset'], spec, assets, where + '.asset'),
            'window': _window(item['window_utc'], where + '.window_utc'),
            'execution_outcome': item['execution_outcome'], 'observability': item['observability'],
            'sets': sets, 'boundary_id': item['boundary_id'], 'kind': boundaries[item['boundary_id']],
            'phase': item['phase']}
    _edges(curation['edges'], steps, field + '.edges')

    controls = {}
    for item in _unique_objects(curation['controls'], 'control_id', field + '.controls').values():
        where = field + '.controls'
        _fields(item, CONTROL_KEYS, where)
        _enum(item['expected_disposition'], DISPOSITIONS, where + '.expected_disposition')
        key = (_selector(item['asset'], spec, assets, where + '.asset'),
               _window(item['window_utc'], where + '.window_utc'), item['expected_disposition'])
        if key in controls:
            _fail('duplicate_item', where)
        controls[key] = item['control_id']
    lookalikes = _line_sets(curation['lookalike_event_ids'], spec, index, field + '.lookalike_event_ids')
    support = {line for step in steps.values() for group in step['sets'] for line in group}
    if support & {line for group in lookalikes for line in group}:
        _fail('lookalike_support_overlap', field + '.lookalike_event_ids')

    windows = None
    if 'assessment_windows' in curation:
        _array(curation['assessment_windows'], field + '.assessment_windows', nonempty=True)
        windows = frozenset(_window(item, field + '.assessment_windows') for item in curation['assessment_windows'])
    partition = None
    if 'partition_window' in curation:
        partition = _window(curation['partition_window'], field + '.partition_window')
    return {'label': label, 'sha256': sha256, 'format': fmt, 'curation': curation, 'assets': assets,
            'names': names, 'steps': steps, 'edges': {tuple(edge) for edge in curation['edges']},
            'controls': controls, 'lookalikes': lookalikes, 'boundaries': boundaries, 'windows': windows,
            'partition': partition}


def read_draft(path, label):
    """Load one proposal through its importer's own loader; return (curation, format, sha256)."""
    field = 'draft_' + label
    _, data = otrf._read_regular(path, otrf.MAX_SIDE_FILE_BYTES, field)
    value = decode_json(data)
    if type(value) is not dict:
        _fail('invalid_object', field)
    # attackdata curations require `clock_declaration`; OTRF curations refuse it.
    fmt = 'attackdata' if 'clock_declaration' in value else 'otrf'
    try:
        curation, loaded = FORMATS[fmt]['load'](path)
    except BenchmarkError as error:
        raise BenchmarkError(error.code, field + '.' + error.field) from None
    if loaded != data:
        _fail('draft_changed', field)
    if curation['attestation'] != 'unreviewed_proposal':
        _fail('draft_not_proposal', field)
    return curation, fmt, digest_bytes(data)


# ---------------------------------------------------------------------- merge

def support_agreement(sets_a, sets_b):
    """Merged support sets for one step pair: the minimal unions of one set from each draft.

    A set is complete for a draft when it contains one of that draft's support
    sets, so every union `a | b` is complete for both drafts. Supersets of another
    union add nothing and are dropped; at most MAX_SUPPORT_SETS remain, smallest
    first. If either draft cites nothing (a non-sufficient step) no set is kept.
    """
    lines_a = {line for group in sets_a for line in group}
    lines_b = {line for group in sets_b for line in group}
    result = {'set_jaccard': _ratio(len(sets_a & sets_b), len(sets_a | sets_b)),
              'locator_jaccard': _ratio(len(lines_a & lines_b), len(lines_a | lines_b)), 'capped': 0}
    if not sets_a or not sets_b:
        return dict(result, basis='both_empty' if not sets_a and not sets_b else 'one_empty', sets=[])
    unions = {left | right for left in sets_a for right in sets_b}
    minimal = sorted((group for group in unions if not any(other < group for other in unions)),
                     key=lambda group: (len(group), sorted(group)))
    return dict(result, basis='minimal_unions', sets=minimal[:MAX_SUPPORT_SETS],
                capped=max(len(minimal) - MAX_SUPPORT_SETS, 0))


def _overlap(left, right):
    return left[0] < right[1] and right[0] < left[1]


def _kappa(a, b, assets):
    """Cohen's kappa over the step/no-step decision per candidate technique and asset."""
    techniques = sorted({step['technique_id'] for draft in (a, b) for step in draft['steps'].values()})
    items = [(technique, asset) for technique in techniques for asset in sorted(assets)]
    yes_a = {(step['technique_id'], step['asset']) for step in a['steps'].values()}
    yes_b = {(step['technique_id'], step['asset']) for step in b['steps'].values()}
    counts = {'both': 0, 'neither': 0, 'only_draft_a': 0, 'only_draft_b': 0}
    for item in items:
        counts[{(True, True): 'both', (False, False): 'neither', (True, False): 'only_draft_a',
                (False, True): 'only_draft_b'}[(item in yes_a, item in yes_b)]] += 1
    result = dict(counts, items=len(items), candidate_techniques=techniques,
                  observed_agreement=None, expected_agreement=None, kappa=None, null_reason=None)
    if not items:
        result['null_reason'] = 'no_candidate_items'
        return result
    observed = Fraction(counts['both'] + counts['neither'], len(items))
    rate_a = Fraction(counts['both'] + counts['only_draft_a'], len(items))
    rate_b = Fraction(counts['both'] + counts['only_draft_b'], len(items))
    expected = rate_a * rate_b + (1 - rate_a) * (1 - rate_b)
    result.update(observed_agreement=_number(observed), expected_agreement=_number(expected))
    if expected == 1:
        result['null_reason'] = 'chance_agreement_is_one'
    else:
        result['kappa'] = _number((observed - expected) / (1 - expected))
    return result


def _release_order(value):
    return tuple(int(part) for part in value.lstrip('v').split('.'))


def _boundaries(merged, a, b):
    """Two merged steps share a boundary when either draft puts them in one boundary.

    Disagreeing kinds within one rubric class keep draft A's kind; across classes they become `host`.
    """
    parent = {item['step_id']: item['step_id'] for item in merged}

    def find(step_id):
        while parent[step_id] != step_id:
            parent[step_id] = parent[parent[step_id]]
            step_id = parent[step_id]
        return step_id

    for side, draft in (('a', a), ('b', b)):
        first = {}
        for item in merged:
            boundary = draft['steps'][item[side]]['boundary_id']
            if boundary in first:
                parent[find(item['step_id'])] = find(first[boundary])
            else:
                first[boundary] = item['step_id']
    components = {}
    for item in merged:
        components.setdefault(find(item['step_id']), []).append(item)
    boundaries, conflicts = [], []
    for index, members in enumerate(components.values()):
        kinds = {draft['steps'][item[side]]['kind'] for item in members for side, draft in (('a', a), ('b', b))}
        if len(kinds) == 1:
            kind = next(iter(kinds))
        elif any(kinds <= group for group in BOUNDARY_CLASSES):
            # Both qualify for the same rubric condition: keep it, deterministically draft A's type.
            kind = a['steps'][members[0]['a']]['kind']
        else:
            kind = 'host'
        boundary_id = 'boundary-%d' % (index + 1)
        boundaries.append({'boundary_id': boundary_id, 'kind': kind})
        for item in members:
            item['boundary_id'] = boundary_id
        if len(kinds) > 1:
            conflicts.append({'field': 'boundary_kind', 'boundary_id': boundary_id, 'drafts': sorted(kinds),
                              'merged': kind, 'step_ids': [item['step_id'] for item in members]})
    return boundaries, conflicts


def _sophistication_band(value, band_a, band_b, step_count):
    """Keep an agreed band the surviving steps support; otherwise recompute from them."""
    structural = {'control': step_count == 0, 'factors': {'gaps': {'score': 1}, 'ambiguity': {'score': 1}}}
    supported = []
    for band in BANDS:
        try:
            _sophistication(dict(value, band=band), structural)
        except BenchmarkError as error:
            if error.code != 'rubric_mismatch':
                raise BenchmarkError(error.code, error.field.replace('scenario.', 'curation.', 1)) from None
            continue
        supported.append(band)
    if not supported:
        _fail('sophistication_unsupported', 'curation.sophistication.band')
    if band_a == band_b and band_a in supported:
        return band_a, 'drafts_agree', supported
    # S5's evidence condition is measured at import; the merge never raises a band to S5 alone.
    return [band for band in supported if band != 'S5'][-1], 'recomputed_from_surviving_steps', supported


def _window_text(window):
    return {'start_inclusive': otrf._utc_text(window[0]), 'end_exclusive': otrf._utc_text(window[1])}


def _lines(groups):
    return [[{'line': line} for line in sorted(group)] for group in groups]


def _merge_assets(a, b, spec, os_defaults):
    """os_family: shared, else the deliberate change from the template default, else A's. Other facts: shared or null."""
    if set(a['assets']) != set(b['assets']):
        _fail('assets_mismatch', 'draft_b.assets')
    display = {folded: min(a['names'][folded], b['names'][folded]) for folded in a['assets']}
    assets, disputed = [], []
    for folded in sorted(a['assets']):
        left, right = a['assets'][folded], b['assets'][folded]
        item = {spec['asset_key']: display[folded], 'os_family': left['os_family']}
        if left['os_family'] != right['os_family']:
            default = os_defaults.get(folded)
            changed = [value for value in (left['os_family'], right['os_family']) if value != default]
            item['os_family'] = changed[0] if len(changed) == 1 else left['os_family']
            disputed.append({'asset': display[folded], 'field': 'os_family', 'draft_a': left['os_family'],
                             'draft_b': right['os_family'], 'template_default': default,
                             'merged': item['os_family']})
        for key in ASSET_FACTS:
            item[key] = left[key] if left[key] == right[key] else None
            if left[key] != right[key]:
                disputed.append({'asset': display[folded], 'field': key, 'draft_a': left[key],
                                 'draft_b': right[key], 'merged': None})
        assets.append(item)
    return display, assets, disputed


def _template_choice(a, b, key, defaults, same):
    """Equal draft values are kept; otherwise the template default (absent when unset), reported as disputed."""
    if same:
        return key in a['curation'], a['curation'].get(key), None
    return key in defaults, defaults.get(key), {'draft_a': a['curation'].get(key), 'draft_b': b['curation'].get(key),
                                                'merged': defaults.get(key), 'basis': 'template_default'}


def merge_drafts(a, b, defaults, now):
    """Return (curation, report) for two parsed drafts of one dataset (see `merge`).

    `defaults` is `template_defaults(...)` of the draft import's curation template.
    """
    spec = FORMATS[a['format']]
    # A partition window defines the case itself; two different partitions are a real conflict.
    if a['partition'] != b['partition']:
        _fail('draft_conflict', 'curation.partition_window')
    chosen, disputed_choices = {}, {}
    clock = [('clock_declaration' in draft['curation'], draft['curation'].get('clock_declaration')) for draft in (a, b)]
    sameness = {'assessment_windows': a['windows'] == b['windows'],  # compared as instants
                'clock_declaration': clock[0] == clock[1]}
    for key in ('assessment_windows', 'clock_declaration'):
        present, value, dispute = _template_choice(a, b, key, defaults, sameness[key])
        if present:
            chosen[key] = value
        disputed_choices[key] = dispute
    release_a, release_b = a['curation']['attack_release'], b['curation']['attack_release']
    disputed_release = None if release_a == release_b else {
        'draft_a': release_a, 'draft_b': release_b, 'merged': max((release_a, release_b), key=_release_order)}
    display, assets, disputed_facts = _merge_assets(a, b, spec, defaults['os_family'])
    # Descriptive environment tags: the shared tags, or (no shared tag) the union, reported as disputed.
    coverage, disputed_coverage = {}, []
    for axis in COVERAGE_AXES:
        tags_a, tags_b = set(a['curation']['coverage'][axis]), set(b['curation']['coverage'][axis])
        coverage[axis] = sorted(tags_a & tags_b) or sorted(tags_a | tags_b)
        if not tags_a & tags_b:
            disputed_coverage.append({'axis': axis, 'draft_a': sorted(tags_a), 'draft_b': sorted(tags_b),
                                      'merged': coverage[axis]})

    # Steps: both drafts propose the same exact technique on the same asset with
    # overlapping windows. One-to-one maximum matching with sorted IDs.
    pairs, candidates = {}, {}
    for a_id, left in sorted(a['steps'].items()):
        for b_id, right in sorted(b['steps'].items()):
            if (left['technique_id'], left['asset']) == (right['technique_id'], right['asset']) and \
                    _overlap(left['window'], right['window']):
                pairs[(a_id, b_id)] = support_agreement(left['sets'], right['sets'])
                candidates.setdefault(a_id, []).append(b_id)
    merged = []
    for a_id, b_id in _maximum_matching(candidates).items():
        left, right = a['steps'][a_id], b['steps'][b_id]
        window = (min(left['window'][0], right['window'][0]), max(left['window'][1], right['window'][1]))
        merged.append({'a': a_id, 'b': b_id, 'left': left, 'right': right, 'window': window,
                       'agreement': pairs[(a_id, b_id)]})
    merged.sort(key=lambda item: (item['window'], item['left']['technique_id'], item['left']['asset'],
                                  item['a'], item['b']))
    steps_out, step_reports, conflicts = [], [], []
    for index, item in enumerate(merged):
        left, right, agreement = item['left'], item['right'], item['agreement']
        item['step_id'] = 'step-%d' % (index + 1)
        observability = min(left['observability'], right['observability'], key=OBSERVABILITY_ORDER.index)
        outcome = left['execution_outcome'] if left['execution_outcome'] == right['execution_outcome'] else 'unknown'
        item['phase'] = left['phase'] if left['phase'] == right['phase'] else 'initial'
        if left['phase'] != right['phase']:
            conflicts.append({'field': 'phase', 'step_ids': [item['step_id']],
                              'drafts': sorted({left['phase'], right['phase']}), 'merged': 'initial'})
        item['observability'] = observability
        steps_out.append({'step_id': item['step_id'], 'technique_id': left['technique_id'],
                          'asset': {spec['asset_key']: display[left['asset']]},
                          'window_utc': _window_text(item['window']), 'execution_outcome': outcome,
                          'observability': observability, 'support_sets': _lines(agreement['sets'])})
        step_reports.append({
            'step_id': item['step_id'], 'draft_a_step_id': item['a'], 'draft_b_step_id': item['b'],
            'technique_id': left['technique_id'], 'asset': display[left['asset']],
            'technique_written': {'draft_a': left['technique_written'], 'draft_b': right['technique_written']},
            'window_utc': _window_text(item['window']), 'support_basis': agreement['basis'],
            'support_sets_capped': agreement['capped'],
            'support_set_jaccard': _number(agreement['set_jaccard']),
            'locator_jaccard': _number(agreement['locator_jaccard']),
            'observability': {'draft_a': left['observability'], 'draft_b': right['observability'],
                              'merged': observability},
            'execution_outcome': {'draft_a': left['execution_outcome'], 'draft_b': right['execution_outcome'],
                                  'merged': outcome}})
    boundaries, boundary_conflicts = _boundaries(merged, a, b)
    conflicts.extend(boundary_conflicts)
    for step, item in zip(steps_out, merged):
        step.update(boundary_id=item['boundary_id'], phase=item['phase'])

    disputed = []
    for side, draft in (('a', a), ('b', b)):
        matched = {item[side] for item in merged}
        for step_id, step in sorted(draft['steps'].items()):
            if step_id not in matched:
                rivals = [pair for pair in pairs if pair[0 if side == 'a' else 1] == step_id]
                disputed.append({'draft': side, 'step_id': step_id, 'technique_id': step['technique_id'],
                                 'technique_written': step['technique_written'],
                                 'asset': draft['names'][step['asset']],
                                 'reason': 'counterpart_matched_elsewhere' if rivals else 'no_counterpart'})

    by_merged = {(item['a'], item['b']): item['step_id'] for item in merged}
    a_to_b = {item['a']: item['b'] for item in merged}
    edges = sorted([by_merged[(x, a_to_b[x])], by_merged[(y, a_to_b[y])]]
                   for x, y in a['edges'] if x in a_to_b and y in a_to_b and (a_to_b[x], a_to_b[y]) in b['edges'])

    control_keys = sorted(set(a['controls']) & set(b['controls']))
    controls = [{'control_id': 'control-%d' % (index + 1), 'asset': {spec['asset_key']: display[asset]},
                 'window_utc': _window_text(window), 'expected_disposition': disposition}
                for index, (asset, window, disposition) in enumerate(control_keys)]
    lookalikes = _lines(sorted(sorted(group) for group in a['lookalikes'] & b['lookalikes']))
    # Records any draft cited as support that no merged support set keeps are disputed evidence.
    kept = {line for item in merged for group in item['agreement']['sets'] for line in group}
    excluded = sorted({line for draft in (a, b) for step in draft['steps'].values()
                       for group in step['sets'] for line in group} - kept)

    soph_a, soph_b = a['curation']['sophistication'], b['curation']['sophistication']
    asset_alias = {folded: 'asset-%d' % (index + 1) for index, folded in enumerate(sorted(a['assets']))}
    sophistication = {
        'boundaries': boundaries,
        'preconditions': sorted(set(soph_a['preconditions']) & set(soph_b['preconditions'])),
        'emulation_limitations': sorted(set(soph_a['emulation_limitations']) | set(soph_b['emulation_limitations'])),
        'group_ids': sorted(set(soph_a['group_ids']) & set(soph_b['group_ids'])),
        'source_references': sorted(set(soph_a['source_references']) | set(soph_b['source_references']))}
    rubric_view = dict(sophistication, edges=edges, steps=[
        {'step_id': item['step_id'], 'asset_id': asset_alias[item['left']['asset']],
         'boundary_id': item['boundary_id'], 'phase': item['phase']} for item in merged])
    band, basis, supported = _sophistication_band(rubric_view, soph_a['band'], soph_b['band'], len(merged))
    sophistication['band'] = band

    # The newer draft release; emitted IDs renamed by the pinned map also need the pinned release.
    attack_release = max((release_a, release_b), key=_release_order)
    release_decision = 'agreed' if disputed_release is None else 'newer_draft'
    renamed = any(item[side]['technique_written'] != item[side]['technique_id']
                  for item in merged for side in ('left', 'right'))
    if renamed and _release_order(ATTACK_RELEASE) > _release_order(attack_release):
        attack_release, release_decision = ATTACK_RELEASE, 'pinned_release_for_canonical_ids'
    if disputed_release is not None:
        disputed_release['merged'] = attack_release

    # matched_control: required exactly when no merged step is sufficient, forbidden otherwise.
    matched_control = disputed_matched = None
    if any(item['observability'] == 'sufficient' for item in merged):
        matched_decision = 'not_needed'
    else:
        present = [side for side, draft in (('draft_a', a), ('draft_b', b)) if 'matched_control' in draft['curation']]
        if not present:
            # Measuring it needs the evidence bundle, which the merge never reads.
            _fail('matched_control_unavailable', 'curation.matched_control')
        source = a if present[0] == 'draft_a' else b
        matched_control = source['curation']['matched_control']
        if len(present) == 2 and a['curation']['matched_control'] == b['curation']['matched_control']:
            matched_decision = 'agreed'
        else:
            matched_decision = present[0]
            disputed_matched = {'draft_a': a['curation'].get('matched_control'),
                                'draft_b': b['curation'].get('matched_control'), 'merged_from': present[0]}

    curated_utc = now.astimezone(timezone.utc).isoformat(timespec='seconds')
    summary = {'steps_kept': len(merged), 'draft_a_steps': len(a['steps']), 'draft_b_steps': len(b['steps']),
               'disputed_steps': len(disputed), 'controls_kept': len(controls),
               'draft_a_controls': len(a['controls']), 'draft_b_controls': len(b['controls']),
               'edges_kept': len(edges), 'draft_a_edges': len(a['edges']), 'draft_b_edges': len(b['edges']),
               'lookalike_groups_kept': len(lookalikes), 'draft_a_lookalike_groups': len(a['lookalikes']),
               'draft_b_lookalike_groups': len(b['lookalikes']), 'excluded_locators': len(excluded),
               'coverage_axes_disputed': len(disputed_coverage), 'asset_facts_disputed': len(disputed_facts),
               'attack_release_disputed': disputed_release is not None,
               'matched_control_disputed': disputed_matched is not None,
               'assessment_windows_disputed': disputed_choices['assessment_windows'] is not None,
               'clock_declaration_disputed': disputed_choices['clock_declaration'] is not None}
    disputed_names = ([item['axis'] for item in disputed_coverage] +
                      ['assets.' + item['field'] for item in disputed_facts] +
                      (['attack_release'] if disputed_release else []) +
                      (['matched_control'] if disputed_matched else []) +
                      [key for key, dispute in disputed_choices.items() if dispute is not None])
    note = ('Agent consensus ({}) of two independently written AI curation drafts (draft A sha256 {}, draft B '
            'sha256 {}). Kept {} steps both drafts propose (draft A proposed {}, draft B {}); {} unpaired steps were '
            'dropped and records no merged support set keeps are listed in excluded_locators. Kept {} controls, {} '
            'edges and {} lookalike groups by agreement. Disputed descriptive fields: {}. Sophistication {} ({}). '
            'Mechanical agreement only: no human reviewed this answer key, and draft independence is the '
            'operator\'s claim.').format(
        TOOL_VERSION, a['sha256'], b['sha256'], len(merged), len(a['steps']), len(b['steps']), len(disputed),
        len(controls), len(edges), len(lookalikes), ', '.join(sorted(set(disputed_names))) or 'none', band,
        basis.replace('_', ' '))
    curation = {
        'schema_version': 1, 'dataset_sha256': a['curation']['dataset_sha256'],
        'metadata_sha256': a['curation']['metadata_sha256'], 'curated_by': CURATOR, 'curated_utc': curated_utc,
        'note': note, 'attestation_hint': ATTESTATION,
        'revision': max(a['curation']['revision'], b['curation']['revision']),
        'truth_revision': max(a['curation']['truth_revision'], b['curation']['truth_revision']),
        'attack_release': attack_release, 'coverage': coverage, 'assets': assets,
        'steps': steps_out, 'edges': edges, 'controls': controls, 'lookalike_event_ids': lookalikes,
        'excluded_locators': [{'line': line} for line in excluded], 'sophistication': sophistication,
        'source_references': sorted(set(a['curation']['source_references']) |
                                    set(b['curation']['source_references']))}
    curation.update(chosen)
    if 'partition_window' in a['curation']:
        curation['partition_window'] = a['curation']['partition_window']
    family = (a['curation'].get('family_id'), b['curation'].get('family_id'))
    if family[0] is not None and family[0] == family[1]:
        curation['family_id'] = family[0]
    if matched_control is not None:
        curation['matched_control'] = matched_control

    pooled = [item['agreement'] for item in merged]
    report = {
        'schema_version': 1, 'tool_version': TOOL_VERSION, 'attestation': ATTESTATION,
        'curated_utc': curated_utc, 'format': a['format'],
        'dataset_sha256': curation['dataset_sha256'], 'metadata_sha256': curation['metadata_sha256'],
        'drafts': {'a': {'sha256': a['sha256']}, 'b': {'sha256': b['sha256']}},
        'summary': summary, 'steps': step_reports, 'disputed_steps': disputed,
        'candidate_pairs': [{'draft_a_step_id': x, 'draft_b_step_id': y, 'support_basis': value['basis'],
                             'support_set_jaccard': _number(value['set_jaccard']),
                             'locator_jaccard': _number(value['locator_jaccard'])}
                            for (x, y), value in sorted(pairs.items())],
        'kappa': _kappa(a, b, a['assets']),
        'support_jaccard': {
            'agreed_pairs': len(pooled),
            'mean_support_set_jaccard': _number(_mean([item['set_jaccard'] for item in pooled])),
            'mean_locator_jaccard': _number(_mean([item['locator_jaccard'] for item in pooled]))},
        'sophistication': {'draft_a': soph_a['band'], 'draft_b': soph_b['band'], 'merged': band, 'basis': basis,
                           'structurally_supported': supported, 'conflicts': conflicts},
        'disputed_fields': {'attack_release': disputed_release, 'coverage': disputed_coverage,
                            'asset_facts': disputed_facts, 'matched_control': disputed_matched,
                            'assessment_windows': disputed_choices['assessment_windows'],
                            'clock_declaration': disputed_choices['clock_declaration']},
        'field_decisions': {
            'family_id': 'kept' if 'family_id' in curation else (
                'absent' if family == (None, None) else 'dropped_disputed'),
            'attack_release': release_decision,
            'matched_control': matched_decision,
            'group_ids_dropped': sorted((set(soph_a['group_ids']) | set(soph_b['group_ids'])) -
                                        set(sophistication['group_ids'])),
            'preconditions_dropped': sorted((set(soph_a['preconditions']) | set(soph_b['preconditions'])) -
                                            set(sophistication['preconditions']))},
        'limitations': list(LIMITATIONS)}
    return curation, report


# --------------------------------------------------------------------- output

def _new_path(path, field):
    target = Path(os.path.abspath(os.fspath(path)))
    if os.path.lexists(target):
        _fail('output_exists', field)
    if otrf._in_source(target.resolve()):
        _fail('output_in_source_tree', field)
    if not target.parent.is_dir():
        _fail('invalid_directory', field)
    return target


def _write_new(path, content, field):
    try:
        with open(path, 'xb') as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
    except FileExistsError:
        _fail('output_exists', field)
    except OSError:
        _fail('file_unwritable', field)


def _document(value):
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False) + '\n').encode('utf-8')


def _check_output(fmt, path):
    """The written curation must load through its own importer as agent consensus."""
    try:
        loaded, _ = FORMATS[fmt]['load'](path)
    except BenchmarkError as error:
        raise BenchmarkError(error.code, 'output.' + error.field) from None
    if loaded['attestation'] != ATTESTATION:
        _fail('consensus_not_recognized', 'output')


def merge(draft_a, draft_b, locators, template, output, report=None, now=None):
    """Merge two proposals into a NEW curation (and optional NEW report); return (sha256, report).

    `locators` and `template` are the draft import's evaluator/locators.json and
    evaluator/curation-template.json for the same dataset.
    """
    curation_a, format_a, sha_a = read_draft(draft_a, 'a')
    curation_b, format_b, sha_b = read_draft(draft_b, 'b')
    if sha_a == sha_b:
        _fail('identical_drafts', 'draft_b')
    if format_a != format_b:
        _fail('format_mismatch', 'draft_b')
    for key in ('dataset_sha256', 'metadata_sha256'):
        if curation_a[key] != curation_b[key]:
            _fail('draft_dataset_mismatch', 'draft_b.' + key)
    locator_map, locators_sha = _read_side_file(locators, 'locators')
    index = locator_index(locator_map)
    if index['dataset_sha256'] != curation_a['dataset_sha256']:
        _fail('locators_dataset_mismatch', 'locators.dataset_sha256')
    template_value, template_sha = _read_side_file(template, 'template')
    defaults = template_defaults(template_value)
    if defaults['dataset_sha256'] != curation_a['dataset_sha256']:
        _fail('template_dataset_mismatch', 'template.curation.dataset_sha256')
    a = parse_draft(curation_a, format_a, sha_a, 'a', index)
    b = parse_draft(curation_b, format_b, sha_b, 'b', index)
    curation, document = merge_drafts(a, b, defaults, now or datetime.now(timezone.utc))
    document['inputs'] = {'locators_sha256': locators_sha, 'template_sha256': template_sha}
    target = _new_path(output, 'output')
    report_target = None if report is None else _new_path(report, 'report')
    if report_target == target:
        _fail('conflicting_arguments', 'report')
    content = _document(curation)
    _write_new(target, content, 'output')
    try:
        _check_output(format_a, target)
        document['curation_sha256'] = digest_bytes(content)
        if report_target is not None:
            _write_new(report_target, _document(document), 'report')
    except BaseException:
        target.unlink()
        raise
    return document['curation_sha256'], document


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog='benchmark_consensus.py',
        description='Agent consensus: merge two independently written curation proposals for one dataset into '
                    'a NEW curation by deterministic agreement. The answer key is attested "agent_consensus": '
                    'mechanical agreement of two AI drafts, never a human review.')
    commands = parser.add_subparsers(dest='command', required=True)
    merge_parser = commands.add_parser('merge', help='merge two curation proposals')
    merge_parser.add_argument('--draft-a', required=True, help='first curation.PROPOSED.json')
    merge_parser.add_argument('--draft-b', required=True, help='second, independently written proposal')
    merge_parser.add_argument('--locators', required=True,
                              help='the draft import\'s evaluator/locators.json (resolves every locator to its line)')
    merge_parser.add_argument('--template', required=True,
                              help='the draft import\'s evaluator/curation-template.json (asset defaults)')
    merge_parser.add_argument('--output', required=True, help='NEW curation file outside the source tree')
    merge_parser.add_argument('--report', help='NEW agreement report file outside the source tree')
    args = parser.parse_args(argv)
    try:
        sha, report = merge(args.draft_a, args.draft_b, args.locators, args.template, args.output, args.report)
    except BenchmarkError as error:
        print('error: {}: {}'.format(error.code, error.field), file=sys.stderr)
        return 2
    summary = {'output': str(Path(os.path.abspath(args.output))), 'curation_sha256': sha,
               'attestation': ATTESTATION, 'summary': report['summary'], 'kappa': report['kappa']['kappa'],
               'sophistication': report['sophistication']['merged'],
               'warning': 'AGENT CONSENSUS: two AI drafts agreed mechanically; no human reviewed this answer key. '
                          'Its scores form a separate truth_attestation cohort.'}
    sys.stdout.write(canonical_bytes(summary).decode('utf-8') + '\n')
    return 0


if __name__ == '__main__':
    sys.exit(main())

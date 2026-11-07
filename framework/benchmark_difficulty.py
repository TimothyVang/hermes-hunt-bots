"""Evidence-derived hunt-rubric-1 difficulty measurement for curated cases.

Facts come only from released records, curator-validated truth support sets and
curator-declared benign explanations; never from model results or labels such
as band names. Callers validate the bundle/truth pair before measuring.
"""
from benchmark_contracts import BenchmarkError, parse_utc
from benchmark_scoring import difficulty_from_measurements


def _fail(code, field):
    raise BenchmarkError(code, field)


def _list(value, field):
    if type(value) is not list:
        _fail('invalid_array', field)
    return value


def case_measurements(evidence, records, truth):
    """Return the raw rubric facts for one case.

    - relevant_events: union of every support set of every `sufficient` step.
    - benign_events: released records outside that union.
    - required_joins: for each sufficient step, the fewest distinct
      (source_id, asset_id) contexts among its complete support sets; the
      maximum over steps. An analyst needs only one complete alternative.
    - correlation_seconds: same aggregation over each support set's own
      first-to-last record time span (never the span of all relevant events).
    - missing_records: any declared known gap or any source not `complete`.
    - alternative_complete: every sufficient step keeps at least one support
      set whose events are all present in `records`, even when other records
      are missing.
    - unresolvable_questions: assessment labels frozen as null.
    - benign_lookalikes: curator-declared `lookalike_event_ids` groups (one
      group per validated benign/contradictory explanation) fully present.
    """
    if type(evidence) is not dict or type(truth) is not dict:
        _fail('invalid_object', 'measurement')
    by_id = {}
    for record in _list(records, 'records'):
        if type(record) is not dict or record.get('event_id') in by_id:
            _fail('invalid_record', 'records')
        by_id[record['event_id']] = record
    steps = [step for step in _list(truth.get('steps'), 'truth.steps')
             if step.get('observability') == 'sufficient']
    relevant, joins, spans = set(), [], []
    alternative_complete = bool(steps)
    for step in steps:
        complete = []
        for support in _list(step.get('support_sets'), 'truth.steps.support_sets'):
            relevant.update(support)
            if support and all(event_id in by_id for event_id in support):
                complete.append(support)
        if not complete:
            alternative_complete = False
            continue
        joins.append(min(len({(by_id[eid]['source_id'], by_id[eid]['asset_id']) for eid in support})
                         for support in complete))
        seconds = []
        for support in complete:
            times = [parse_utc(by_id[eid]['timestamp_utc'], 'records.timestamp_utc') for eid in support]
            seconds.append((max(times) - min(times)).total_seconds())
        spans.append(min(seconds))
    present_relevant = relevant & set(by_id)
    lookalikes = 0
    for group in _list(truth.get('lookalike_event_ids', []), 'truth.lookalike_event_ids'):
        group = _list(group, 'truth.lookalike_event_ids')
        if set(group) & relevant:
            _fail('lookalike_support_overlap', 'truth.lookalike_event_ids')
        lookalikes += int(bool(group) and all(event_id in by_id for event_id in group))
    labels = truth.get('assessment_labels')
    if type(labels) is not dict:
        _fail('invalid_object', 'truth.assessment_labels')
    sources = _list(evidence.get('sources'), 'evidence.sources')
    return {
        'benign_events': len(by_id) - len(present_relevant),
        'relevant_events': len(present_relevant),
        'required_joins': max(joins, default=0),
        'correlation_seconds': max(spans, default=0),
        'missing_records': bool(_list(evidence.get('known_gaps'), 'evidence.known_gaps'))
                           or any(source.get('completeness') != 'complete' for source in sources),
        'alternative_complete': alternative_complete,
        'unresolvable_questions': sum(label is None for label in labels.values()),
        'benign_lookalikes': lookalikes,
    }


def measure_case(evidence, records, truth, curation=None):
    """Scenario-ready difficulty ({band, control, factors}) for one case.

    `curation` may only carry `matched_control`: the matched attack family's
    difficulty, required (and only accepted) when no step is `sufficient`.
    A case without steps is a zero-positive control (`control: true`); a case
    whose steps are all non-sufficient inherits the same matched difficulty but
    keeps its attack steps, so it is not a control.
    """
    curation = {} if curation is None else curation
    if type(curation) is not dict or set(curation) - {'matched_control'}:
        _fail('invalid_object', 'curation')
    result = difficulty_from_measurements(**case_measurements(evidence, records, truth),
                                          matched_control=curation.get('matched_control'))
    if result['control'] and truth['steps']:
        result['control'] = False
    return result

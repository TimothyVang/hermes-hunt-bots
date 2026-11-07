"""Deterministic reference baselines: score floors, never teams.

Offline only: no state, ledger, model, network or lab. Each baseline builds one
final ``handoff`` stage output per case and runs it through the SAME
``benchmark_scoring.score_output`` (mechanical adjudication) and the same
scorecard aggregation (``benchmark_comparison._summary``) that real teams use,
so every metric keeps its scorecard name and macro rule (repetitions within a
scenario first, then equal-weight scenarios; attack-free scenarios excluded from
detection rates).

Baselines:

- ``silent``: no findings; every assessment probability 0.0.
- ``alarm_all``: one suspicious finding per asset/window question, with no
  technique and no citations; every probability 1.0.
- ``coin``: no findings; every probability 0.5.
- ``prior``: no findings; every probability is the pooled positive rate of the
  decidable assessment labels of the OTHER development-split cases
  (leave-one-out). A case's own labels are never read for its prior; with no
  other decidable development label the baseline abstains (null), never 0.

Every row is labelled ``reference_baseline``. It carries no team identity, is
``rankable: false`` and adds the ``reference_baseline`` ranking blocker to its
metrics, so a scorecard built from it is ``not_comparable`` and never ranked.
Reports may show these rows as floors beside real teams. Baselines read truth
only to score; nothing here feeds truth or results back into any trial.
"""
import os
from pathlib import Path

from benchmark_contracts import BenchmarkError, canonical_bytes, digest_bytes
from benchmark_scoring import MECHANICAL, MECHANICAL_RULES, RUBRIC_VERSION, score_output

REFERENCE_BASELINE = 'reference_baseline'
BASELINE_RULES = 'reference-baselines-1'
BASELINES = ('silent', 'alarm_all', 'coin', 'prior')
DEFINITIONS = {
    'silent': 'No findings; every assessment probability 0.0.',
    'alarm_all': 'One suspicious finding per asset/window question with no technique and no '
                 'citations; every assessment probability 1.0.',
    'coin': 'No findings; every assessment probability 0.5.',
    'prior': 'No findings; every assessment probability is the pooled positive rate of the '
             'decidable labels of the other development-split cases (leave-one-out).',
}
CONSTANT_PROBABILITY = {'silent': 0.0, 'alarm_all': 1.0, 'coin': 0.5}
LIMITATIONS = [
    'Reference baselines are deterministic floors, not teams: they are never ranked or paired with teams.',
    'Scored with mechanical adjudication (deterministic rules), never human verdicts.',
    'Each case has one deterministic output; scorecard trial counts here count baseline outputs, not model trials.',
    'The prior baseline reads labels of other development cases only (leave-one-out); it uses evaluator '
    'labels and is therefore an oracle-informed floor, not a deployable hunter.',
]


def _fail(code, field):
    raise BenchmarkError(code, field) from None


def leave_one_out_prior(case_id, development_labels):
    """Pooled positive rate of decidable labels of every development case except ``case_id``.

    ``development_labels`` maps case ID to its ``assessment_labels``. The entry for
    ``case_id`` is skipped before it is touched, so its own labels are never read.
    Returns ``(probability_or_None, basis)``.
    """
    positives = decidable = cases = 0
    for other in sorted(development_labels):
        if other == case_id:
            continue
        cases += 1
        for label in development_labels[other].values():
            if label is not None:
                decidable += 1
                positives += label
    basis = {'other_development_cases': cases, 'decidable_labels': decidable,
             'positive_labels': positives}
    if not decidable:
        basis['null_reason'] = 'no_other_development_labels'
        return None, basis
    return positives / decidable, basis


def baseline_output(name, evidence, probability):
    """The final handoff a baseline would submit; valid under the stage-output contract."""
    if name not in BASELINES:
        _fail('invalid_enum', 'baseline')
    questions = evidence['assessment_questions']
    findings = []
    if name == 'alarm_all':
        findings = [{'finding_id': 'alarm-' + question['question_id'],
                     'asset_id': question['asset_id'], 'technique_id': None,
                     'window_utc': dict(question['window_utc']), 'disposition': 'suspicious',
                     'confidence': None, 'event_ids': [],
                     'rationale': 'Reference baseline: alarm on every asset/window question.'}
                    for question in questions]
    return {'schema_version': 1, 'stage_key': 'handoff',
            'summary': 'Reference baseline {} (deterministic; not a team).'.format(name),
            'claims': [], 'findings': findings, 'hypotheses': [], 'gaps': [],
            'limitations': ['Deterministic reference baseline; no evidence was analysed.'],
            'requested_decision': 'insufficient', 'chain_edges': [],
            'assessment_answers': [{'question_id': question['question_id'],
                                    'probability_suspicious': probability}
                                   for question in questions]}


def _row(case, metrics):
    # Same row shape `build_comparison` feeds `_summary`; no calls, no team.
    from benchmark_comparison import _labels, _leaves, _null_reasons
    labels, _ = _labels(case)
    return {'scenario_id': case['scenario']['scenario_id'],
            'family_id': case['scenario']['family_id'],
            'score': {'metrics': metrics}, 'numeric_metrics': _leaves(metrics), 'calls': [],
            'labels': labels, 'settled': True, 'completed': True,
            'trial_status': REFERENCE_BASELINE, 'failed': 0, 'unknown': 0, 'timeout': 0,
            'format_error': 0, 'null_reasons': _null_reasons(metrics),
            'attack_free': metrics['detection']['eligible_steps'] == 0}


def _summary(rows):
    from benchmark_comparison import _summary as scorecard_summary
    summary = scorecard_summary(rows)
    summary['brier'] = summary['metrics'].get('calibration.brier', {}).get('macro_mean')
    return summary


def score_baselines(loaded, truths):
    """Score every baseline on every frozen case; pure, no writes.

    ``loaded`` is ``benchmark.load_experiment`` output and ``truths`` is
    ``benchmark_adjudication.load_truths`` output for the same cases.
    """
    cases = loaded['cases']
    development = {case['evidence']['case_id']: truths[case['evidence']['case_id']]['truth']['assessment_labels']
                   for case in cases if case['scenario']['split'] == 'development'}
    baselines = []
    for name in BASELINES:
        rows, per_case = [], []
        for case in cases:
            case_id = case['evidence']['case_id']
            truth = truths[case_id]
            extra = {}
            if name == 'prior':
                probability, basis = leave_one_out_prior(case_id, development)
                extra = {'prior_probability': probability, 'prior_basis': basis}
            else:
                probability = CONSTANT_PROBABILITY[name]
            output = baseline_output(name, case['evidence'], probability)
            output_sha256 = digest_bytes(canonical_bytes(output))
            metrics = score_output(output, truth['truth'], case['evidence'], None,
                                   trial_id='baseline-{}-{}'.format(name.replace('_', '-'), case_id),
                                   output_sha256=output_sha256, adjudication=MECHANICAL)
            metrics['ranking_eligible'] = False
            metrics['ranking_blockers'] = sorted(set(metrics['ranking_blockers']) | {REFERENCE_BASELINE})
            row = _row(case, metrics)
            rows.append(row)
            per_case.append(dict({
                'case_id': case_id, 'scenario_id': row['scenario_id'], 'family_id': row['family_id'],
                'split': case['scenario']['split'], 'kind': REFERENCE_BASELINE,
                'evidence_sha256': case['scenario']['evidence_manifest_sha256'],
                'truth_sha256': truth['sha256'], 'truth_attestation': truth['attestation'],
                'output_sha256': output_sha256, 'status': metrics['status'], 'metrics': metrics,
                'scorecard': _summary([row])}, **extra))
        baselines.append({'baseline_id': name, 'kind': REFERENCE_BASELINE, 'rankable': False,
                          'ranking_blockers': [REFERENCE_BASELINE], 'definition': DEFINITIONS[name],
                          'status': MECHANICAL, 'macro': _summary(rows), 'cases': per_case})
    experiment = loaded['experiment']
    return {'schema_version': 1, 'kind': REFERENCE_BASELINE, 'label': REFERENCE_BASELINE,
            'rankable': False, 'execution': 'offline_deterministic', 'model_calls': 0,
            'experiment_id': experiment['experiment_id'],
            'experiment_sha256': digest_bytes(canonical_bytes(experiment)),
            'rubric_version': RUBRIC_VERSION, 'baseline_rules': BASELINE_RULES,
            'adjudication': MECHANICAL, 'adjudication_rules': MECHANICAL_RULES,
            'truth_attestation': sorted({truths[case['evidence']['case_id']]['attestation'] for case in cases}),
            'baselines': baselines, 'limitations': LIMITATIONS}


def run_baselines(manifest, bundle_root, truth_directory, output):
    """CLI entry: validate inputs, score, then create ``output`` as a NEW file."""
    from benchmark import load_experiment
    from benchmark_adjudication import load_truths
    target = Path(os.path.abspath(os.fspath(output)))
    if os.path.lexists(target):
        _fail('already_exists', 'output')
    if not target.parent.is_dir():
        _fail('invalid_directory', 'output')
    loaded = load_experiment(manifest, bundle_root)
    report = score_baselines(loaded, load_truths(truth_directory, loaded))
    data = canonical_bytes(report)
    try:
        with target.open('xb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except FileExistsError:
        _fail('already_exists', 'output')
    return {'output': str(target), 'report_sha256': digest_bytes(data), 'kind': REFERENCE_BASELINE,
            'rankable': False, 'experiment_id': report['experiment_id'],
            'cases': len(loaded['cases']), 'baselines': list(BASELINES),
            'macro_f1': {item['baseline_id']: item['macro']['detection']['f1'] for item in report['baselines']},
            'macro_brier': {item['baseline_id']: item['macro']['brier'] for item in report['baselines']}}

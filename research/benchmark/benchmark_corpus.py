"""Build a development experiment manifest over a directory of curated cases.

Offline only: no state, ledger, model or network. The manifest is written as a
NEW file inside the cases directory (its bundle root) and only after the exact
bytes pass `benchmark.load_experiment`.

TEAM file (strict JSON, unknown keys refused)::

    {"schema_version": 1,
     "team": {...one team in the existing experiment contract shape...},
     "budgets": {...optional, the experiment budgets object...},
     "pricing_snapshot": {...optional, the experiment pricing snapshot...}}

Without `budgets`, DEFAULT_BUDGETS applies. It carries no API cost cap, so any
paid route (see `benchmark_contracts.route_is_paid`) is refused until the TEAM
file supplies its own budgets with `max_api_cost_usd` and a computable per-call
bound. Without `pricing_snapshot`, an empty USD snapshot dated now is used:
no rates are invented.

Every case's public prompt material (evidence plus record files, exactly as a
stage prompt embeds them) must fit the budget's `max_prompt_bytes`, else the
corpus is refused with `case_exceeds_prompt_cap: <case_id>`. With
`context_tokens`, a case whose estimated prompt tokens (bytes /
ESTIMATED_BYTES_PER_TOKEN) plus the team's largest `max_output_tokens` exceed it
is refused with `case_exceeds_context: <case_id>`.
"""
import base64
import datetime as dt
import os
from pathlib import Path
import re
import uuid

from benchmark_contracts import (
    BenchmarkError, MAX_BYTES, _fields, _integer, _version, canonical_bytes, confined_file,
    digest_bytes, load_json, validate_team,
)

HERE = Path(__file__).resolve().parent
DEFAULT_SEED = 1729
# Conservative defaults: they cap a local team's work and never authorize spend.
# - 16 calls: seven stages with at most two attempts each, plus two spare
#   (for example an evidence-checker call); a trial cannot loop.
# - 480 active seconds per trial.
# - 1 MiB prompts: the contract maximum, so released evidence is never sampled
#   away; an oversized bundle blocks rather than truncates.
# - 64 KiB responses and two attempts per stage (one explicitly reconciled retry).
# - max_concurrent_calls is absent, so the contract default applies.
DEFAULT_BUDGETS = {
    'max_calls_per_trial': 16,
    'max_active_seconds_per_trial': 480,
    'max_prompt_bytes': MAX_BYTES,
    'max_response_bytes': 65536,
    'max_attempts_per_stage': 2,
}
_CASE_DIR = re.compile(r'case-[0-9a-f]{4,32}\Z')
# Conservative bytes-per-token estimate for `--context-tokens`: typical
# tokenizers average about four bytes of English/JSON text per token, so three
# over-counts tokens for ordinary text. It is an estimate, not a tokenizer
# measurement: dense hex or base64 can tokenize at fewer bytes per token.
ESTIMATED_BYTES_PER_TOKEN = 3


def _fail(code, field):
    raise BenchmarkError(code, field) from None


def _source_digests():
    """The same frozen sources and encodings that `load_experiment` verifies."""
    root = HERE / 'benchmarks'
    return {'coverage_sha256': digest_bytes(canonical_bytes(load_json(root / 'coverage.json'))),
            'workflow_sha256': digest_bytes(canonical_bytes(load_json(root / 'team-workflow.json'))),
            'prompt_contract_sha256': digest_bytes((root / 'prompt-contract.txt').read_bytes())}


def _team_file(path):
    value = load_json(path)
    _fields(value, {'schema_version', 'team'}, 'team_file', {'budgets', 'pricing_snapshot'})
    _version(value['schema_version'], 'team_file.schema_version')
    validate_team(value['team'])
    return value


def scan_cases(cases_dir):
    """Curated case references, sorted by case ID; drafts refuse the whole corpus."""
    refs = []
    for entry in sorted(os.scandir(cases_dir), key=lambda item: item.name):
        if not _CASE_DIR.fullmatch(entry.name):
            continue
        if entry.is_symlink():
            _fail('path_alias', 'cases')
        if not entry.is_dir(follow_symlinks=False):
            _fail('invalid_directory', 'cases')
        case = Path(entry.path)
        evaluator = case / 'evaluator'
        has_truth = os.path.lexists(evaluator / 'truth.json')
        if os.path.lexists(evaluator / 'truth.DRAFT.json') and not has_truth:
            _fail('draft_truth_refused', 'cases')
        if not os.path.lexists(case / 'scenario.json'):
            _fail('missing_scenario', 'cases')
        if not has_truth:
            _fail('missing_truth', 'cases')
        refs.append({'scenario': entry.name + '/scenario.json',
                     'evidence': entry.name + '/public/evidence.json'})
    if not refs:
        _fail('no_cases', 'cases')
    return refs


def public_prompt_bytes(evidence, evidence_dir):
    """Exact byte length of the public evidence plus record files as a stage prompt embeds them.

    Mirrors the `untrusted_public_evidence` projection of
    `benchmark_runner.build_prompt` (bundle without `files`, then each file's
    digest, size, encoding and UTF-8 or base64 content), whose canonical JSON is
    embedded verbatim. Every real prompt is at least this long: the contract,
    role, stage and predecessor outputs are added on top.
    """
    public = {key: value for key, value in evidence.items() if key != 'files'}
    public['files'] = []
    for entry in evidence['files']:
        data = confined_file(evidence_dir, entry['path'], 'files').read_bytes()
        if digest_bytes(data) != entry['sha256'] or len(data) != entry['byte_count']:
            _fail('digest_mismatch', 'files')
        try:
            content, encoding = data.decode('utf-8'), 'utf-8'
        except UnicodeDecodeError:
            content, encoding = base64.b64encode(data).decode('ascii'), 'base64'
        public['files'].append({'sha256': entry['sha256'], 'byte_count': len(data),
                                'encoding': encoding, 'content': content})
    return len(canonical_bytes(public))


def estimated_tokens(byte_count):
    return -(-byte_count // ESTIMATED_BYTES_PER_TOKEN)


def check_prompt_sizes(cases, budgets, team, context_tokens=None):
    """Refuse the first case (sorted by case ID) whose public prompt material cannot fit.

    `case_exceeds_prompt_cap` when it exceeds `max_prompt_bytes`;
    `case_exceeds_context` when its estimated tokens plus the team's largest
    narrative `max_output_tokens` exceed `context_tokens`. Returns the sizes.
    """
    output_tokens = max(spec['max_output_tokens'] for spec in team['roles'].values())
    sizes = {}
    for case in sorted(cases, key=lambda item: item['evidence']['case_id']):
        case_id = case['evidence']['case_id']
        size = public_prompt_bytes(case['evidence'], case['evidence_path'].parent)
        if size > budgets['max_prompt_bytes']:
            _fail('case_exceeds_prompt_cap', case_id)
        if context_tokens is not None and estimated_tokens(size) + output_tokens > context_tokens:
            _fail('case_exceeds_context', case_id)
        sizes[case_id] = size
    return sizes


def build_corpus_experiment(cases_dir, team_path, experiment_id, repetitions, output,
                            seed=DEFAULT_SEED, holdout_registry=None, context_tokens=None):
    from benchmark import load_experiment
    if context_tokens is not None:
        _integer(context_tokens, 'context_tokens', 1)
    root = Path(os.path.abspath(os.fspath(cases_dir)))
    if not root.is_dir():
        _fail('invalid_directory', 'cases')
    target = Path(os.path.abspath(os.fspath(output)))
    if os.path.lexists(target):
        _fail('already_exists', 'output')
    if target.parent != root and root not in target.parents:
        _fail('path_escape', 'output')
    team_file = _team_file(team_path)
    experiment = dict({
        'schema_version': 1, 'experiment_id': experiment_id,
        'scenario_refs': scan_cases(root), 'teams': [team_file['team']],
        'repetitions': repetitions, 'schedule_seed': seed,
        'budgets': team_file.get('budgets', DEFAULT_BUDGETS),
        'rubric_version': 'hunt-rubric-1',
        'pricing_snapshot': team_file.get('pricing_snapshot', {
            'as_of_utc': dt.datetime.now(dt.timezone.utc).isoformat(timespec='seconds'),
            'currency': 'USD', 'rates': []}),
    }, **_source_digests())
    data = canonical_bytes(experiment)
    # Validate the exact bytes in place (references resolve against the cases
    # root), then create the requested file; it never exists unvalidated.
    staging = target.parent / '.corpus-experiment-{}.tmp'.format(uuid.uuid4().hex)
    try:
        with staging.open('xb') as stream:
            stream.write(data)
        loaded = load_experiment(staging, root)
    finally:
        if os.path.lexists(staging):
            staging.unlink()
    scenarios = [case['scenario'] for case in loaded['cases']]
    sizes = check_prompt_sizes(loaded['cases'], experiment['budgets'], team_file['team'], context_tokens)
    if holdout_registry is not None:
        from benchmark_holdout import check_unretired, load_registry
        check_unretired(load_registry(holdout_registry), scenarios)
    elif any(scenario['split'] == 'holdout' for scenario in scenarios):
        _fail('holdout_registry_required', 'holdout_registry')
    try:
        with target.open('xb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except FileExistsError:
        _fail('already_exists', 'output')
    return {'output': str(target), 'experiment_sha256': digest_bytes(data),
            'experiment_id': experiment_id, 'cases': len(scenarios),
            'splits': sorted({scenario['split'] for scenario in scenarios}),
            'budgets_source': 'team_file' if 'budgets' in team_file else 'defaults',
            'max_public_prompt_bytes': max(sizes.values()), 'context_tokens': context_tokens,
            'bundle_root': str(root)}

#!/usr/bin/env python3
"""Explicit framework-managed benchmark CLI; never defaults to execution."""
import argparse
import json
from pathlib import Path
import sys

import benchmark_paths  # noqa: F401
from benchmark_contracts import (BenchmarkError, canonical_bytes, confined_file, digest_bytes,
                                 load_json, validate_benchmark_workflow, validate_coverage,
                                 validate_experiment, validate_public_bundle, validate_scenario)
from workflows import validate_template

HERE = Path(__file__).resolve().parent


class SafeParser(argparse.ArgumentParser):
    def error(self, message):
        self.exit(2, 'invalid_arguments: arguments\n')


def _resolve_workflow_path(workflow_path):
    if workflow_path is None:
        return HERE / 'benchmarks' / 'team-workflow.json'
    candidate = Path(workflow_path)
    if not candidate.is_absolute():
        candidate = (HERE / candidate).resolve()
    else:
        candidate = candidate.resolve()
    try:
        rel = candidate.relative_to(HERE).as_posix()
    except ValueError:
        raise BenchmarkError('path_escape', 'workflow') from None
    if not rel.startswith('benchmarks/'):
        raise BenchmarkError('path_escape', 'workflow') from None
    return confined_file(HERE, rel, 'workflow')


def load_experiment(path, bundle_root=None, workflow_path=None):
    """Resolve a portable experiment without writes, imports of SDKs, or probes."""
    path = Path(path).absolute()
    root = Path(bundle_root).absolute() if bundle_root else path.parent
    try:
        relative = path.relative_to(root).as_posix()
    except ValueError:
        raise BenchmarkError('path_escape', 'experiment') from None
    path = confined_file(root, relative, 'experiment')
    experiment = validate_experiment(load_json(path))
    coverage_path = HERE / 'benchmarks' / 'coverage.json'
    resolved_workflow = _resolve_workflow_path(workflow_path)
    prompt_path = HERE / 'benchmarks' / 'prompt-contract.txt'
    for source, field in ((coverage_path, 'coverage_sha256'),
                          (resolved_workflow, 'workflow_sha256'),
                          (prompt_path, 'prompt_contract_sha256')):
        confined_file(HERE, source.relative_to(HERE).as_posix(), field)
        content = (canonical_bytes(load_json(source)) if source.suffix == '.json'
                   else source.read_bytes())
        if digest_bytes(content) != experiment[field]:
            raise BenchmarkError('digest_mismatch', field)
    coverage = validate_coverage(load_json(coverage_path))
    try:
        workflow = validate_template(load_json(resolved_workflow))
    except ValueError:
        raise BenchmarkError('invalid_workflow', 'workflow') from None
    validate_benchmark_workflow(workflow)
    cases = []
    seen = set()
    for reference in experiment['scenario_refs']:
        # Paths are relative to --bundle-root (default: the experiment's own
        # directory); a missing file names its field rather than guessing a root.
        scenario_path = confined_file(root, reference['scenario'], 'scenario_refs.scenario')
        evidence_path = confined_file(root, reference['evidence'], 'scenario_refs.evidence')
        if scenario_path == evidence_path:
            raise BenchmarkError('public_truth_overlap', 'scenario_refs')
        scenario = validate_scenario(load_json(scenario_path), coverage)
        evidence_data = load_json(evidence_path)
        if digest_bytes(canonical_bytes(evidence_data)) != scenario['evidence_manifest_sha256']:
            raise BenchmarkError('digest_mismatch', 'evidence_manifest_sha256')
        evidence = validate_public_bundle(evidence_data, evidence_path.parent)
        if scenario['scenario_id'] in seen:
            raise BenchmarkError('duplicate_identifier', 'scenario_id')
        seen.add(scenario['scenario_id'])
        cases.append({'scenario': scenario, 'evidence': evidence,
                      'evidence_path': evidence_path, 'scenario_path': scenario_path,
                      'reference': reference})
    if any('query_store' in case['evidence'] for case in cases):
        for team in experiment['teams']:
            for role_spec in team['roles'].values():
                if role_spec['adapter'] != 'openai_http':
                    raise BenchmarkError('query_store_requires_openai_http', 'experiment.teams')
    return {'experiment': experiment, 'coverage': coverage, 'workflow': workflow,
            'prompt_contract': prompt_path.read_text(encoding='utf-8'), 'cases': cases}


def parser():
    result = SafeParser(description=__doc__)
    result.add_argument('--state-root')
    commands = result.add_subparsers(dest='command', required=True)
    validate = commands.add_parser('validate')
    validate.add_argument('--experiment', required=True)
    validate.add_argument('--bundle-root')
    validate.add_argument('--workflow')
    export = commands.add_parser('export')
    export.add_argument('--experiment', required=True)
    export.add_argument('--output', required=True)
    export.add_argument('--holdout-registry')
    initialize = commands.add_parser('init')
    initialize.add_argument('--experiment', required=True)
    initialize.add_argument('--bundle-root')
    initialize.add_argument('--workflow')
    initialize.add_argument('--truth', required=True,
                            help='DIR/<case_id>/evaluator/truth.json; frozen automatically before any trial')
    initialize.add_argument('--holdout-registry',
                            help='required when any scenario is holdout; retired holdouts are refused')
    state = commands.add_parser('status')
    state.add_argument('--experiment', required=True)
    advance = commands.add_parser('advance')
    advance.add_argument('--experiment', required=True)
    advance.add_argument('--allow-model-execution', action='store_true')
    advance.add_argument('--retry-call')
    terminate = commands.add_parser('terminate', help='human abandonment of one trial; never dispatches')
    terminate.add_argument('--experiment', required=True)
    terminate.add_argument('--trial', required=True)
    terminate.add_argument('--by', required=True)
    terminate.add_argument('--note', required=True)
    snapshot = commands.add_parser(
        'snapshot-source', help='offline: copy the exact fingerprinted sources into a NEW directory for long runs')
    snapshot.add_argument('--output', required=True, help='NEW directory outside this source tree')
    corpus = commands.add_parser(
        'corpus-experiment', help='offline: write a NEW development manifest over DIR/<case_id>/ curated cases')
    corpus.add_argument('--cases', required=True, help='bundle root containing curated <case_id>/ directories')
    corpus.add_argument('--team', required=True,
                        help='JSON {schema_version, team[, budgets][, pricing_snapshot]} with exactly one team')
    corpus.add_argument('--experiment-id', required=True)
    corpus.add_argument('--repetitions', type=int, default=1)
    corpus.add_argument('--output', required=True, help='NEW manifest file inside --cases')
    corpus.add_argument('--seed', type=int, default=1729)
    corpus.add_argument('--holdout-registry', help='required when any scenario is holdout')
    corpus.add_argument('--context-tokens', type=int,
                        help='refuse a case whose estimated prompt (bytes / 3) plus max_output_tokens exceeds N')
    corpus.add_argument('--workflow', help='optional workflow template under benchmarks/ (default: team-workflow.json)')
    baselines = commands.add_parser(
        'baselines', help='offline: score deterministic reference baselines (floors, never teams) into a NEW file')
    baselines.add_argument('--experiment-manifest', required=True)
    baselines.add_argument('--bundle-root')
    baselines.add_argument('--workflow')
    baselines.add_argument('--truth', required=True, help='directory of <case_id>/evaluator/truth.json')
    baselines.add_argument('--output', required=True, help='NEW JSON report file')
    reconcile = commands.add_parser('reconcile')
    reconcile.add_argument('--experiment', required=True)
    reconcile.add_argument('--call', required=True)
    reconcile.add_argument('--by', required=True)
    reconcile.add_argument('--note', required=True)
    reconcile.add_argument('--outcome', choices=('failed', 'completed'), required=True)
    reconcile.add_argument('--evidence')
    adjudication = commands.add_parser('adjudication-template')
    adjudication.add_argument('--experiment', required=True)
    adjudication.add_argument('--output', required=True)
    score = commands.add_parser(
        'score', help='mechanical adjudication by default; --adjudication FILE forms a separate human cohort')
    score.add_argument('--experiment', required=True)
    score.add_argument('--truth', required=True)
    score.add_argument('--adjudication')
    diagnose = commands.add_parser('diagnose', help='development-split diagnostics; refuses holdout trials')
    diagnose.add_argument('--experiment', required=True)
    diagnose.add_argument('--truth', required=True)
    diagnose.add_argument('--adjudication')
    diagnose.add_argument('--output', required=True)
    holdout = commands.add_parser('holdout')
    holdout_commands = holdout.add_subparsers(dest='holdout_command', required=True)
    retire = holdout_commands.add_parser('retire')
    retire.add_argument('--experiment', required=True)
    retire.add_argument('--registry', required=True)
    retire.add_argument('--by', required=True)
    retire.add_argument('--note', required=True)
    retire.add_argument('--output', required=True)
    campaign = commands.add_parser('campaign')
    phases = campaign.add_subparsers(dest='campaign_command', required=True)
    plan = phases.add_parser('plan')
    plan.add_argument('--manifest', required=True)
    preflight = phases.add_parser('preflight')
    preflight.add_argument('--manifest', required=True)
    preflight.add_argument('--range-kit', required=True)
    preflight.add_argument('--allow-lab-read', action='store_true')
    authorize = phases.add_parser('authorize')
    authorize.add_argument('--campaign', required=True)
    authorize.add_argument('--by', required=True)
    authorize.add_argument('--note', required=True)
    authorize.add_argument('--expires', required=True)
    authorize.add_argument('--phases', nargs='+', required=True,
                           choices=('run', 'stop', 'collect', 'cleanup'))
    for name in ('run', 'status', 'stop', 'collect', 'cleanup'):
        action = phases.add_parser(name)
        action.add_argument('--campaign', required=True)
        if name == 'collect':
            action.add_argument('--allow-lab-read', action='store_true')
        elif name != 'status':
            action.add_argument('--allow-lab-mutation', action='store_true')
    recovery = phases.add_parser('reconcile')
    recovery.add_argument('--campaign', required=True)
    recovery.add_argument('--by', required=True)
    recovery.add_argument('--note', required=True)
    recovery.add_argument('--evidence', required=True)
    seal = phases.add_parser('seal')
    seal.add_argument('--campaign', required=True)
    seal.add_argument('--mapping', required=True)
    seal.add_argument('--output', required=True)
    release = phases.add_parser('release')
    release.add_argument('--campaign', required=True)
    release.add_argument('--by', required=True)
    release.add_argument('--note', required=True)
    release.add_argument('--destinations', required=True)
    return result


# Commands that can perform ledger, model or lab work before an unexpected
# error; such errors are execution failures (exit 1), not input refusals.
EXECUTING = frozenset(('advance', 'reconcile', 'terminate', 'campaign run',
                       'campaign stop', 'campaign collect', 'campaign cleanup',
                       'campaign preflight', 'campaign release', 'campaign seal'))


def _command_name(args):
    if args.command == 'campaign':
        return 'campaign ' + args.campaign_command
    if args.command == 'holdout':
        return 'holdout ' + args.holdout_command
    return args.command


def _campaign(args):
    from benchmark_campaigns import (
        plan, preflight, authorize, run, status, stop, collect, cleanup, reconcile, seal, release,
    )
    command = args.campaign_command
    if command == 'plan':
        return plan(args.manifest), 0
    if command == 'preflight':
        report = preflight(args.state_root, args.manifest, args.range_kit, args.allow_lab_read)
        return report, 2 if report.get('status') in ('blocked', 'failed', 'unknown') else 0
    if command == 'authorize':
        return authorize(args.state_root, args.campaign, args.by, args.note,
                         args.expires, args.phases), 0
    if command == 'status':
        return status(args.state_root, args.campaign), 0
    if command == 'reconcile':
        return reconcile(args.state_root, args.campaign, args.by, args.note, args.evidence), 0
    if command == 'seal':
        return seal(args.state_root, args.campaign, args.mapping, args.output), 0
    if command == 'release':
        return release(args.state_root, args.campaign, args.by, args.note, args.destinations), 0
    before = status(args.state_root, args.campaign)
    try:
        if command == 'collect':
            report = collect(args.state_root, args.campaign, args.allow_lab_read)
        else:
            action = {'run': run, 'stop': stop, 'cleanup': cleanup}[command]
            report = action(args.state_root, args.campaign, args.allow_lab_mutation)
    except BenchmarkError as exc:
        # A refusal before any dispatch is exit 2; a raise after lab state
        # changed is an execution failure.
        if status(args.state_root, args.campaign) != before:
            exc.executed = True
        raise
    if command == 'run':
        failed = report.get('status') in ('blocked', 'failed', 'unknown')
    elif command == 'cleanup':
        failed = report.get('cleanup_status') in ('failed', 'unknown')
    else:
        failed = report.get('status') in ('failed', 'unknown')
    return report, 1 if failed else 0


def main(argv=None):
    args = parser().parse_args(argv)
    name = _command_name(args)
    try:
        offline = (args.command in ('validate', 'corpus-experiment', 'baselines', 'snapshot-source')
                   or name == 'campaign plan')
        if not offline and args.state_root is None:
            raise BenchmarkError('state_root_required', 'state_root')
        code = 0
        if args.command == 'validate':
            loaded = load_experiment(args.experiment, args.bundle_root, workflow_path=args.workflow)
            report = {'valid': True, 'execution': 'framework-managed',
                      'experiment_id': loaded['experiment']['experiment_id'],
                      'cases': len(loaded['cases']), 'network_access': False}
        elif args.command == 'snapshot-source':
            from benchmark_runner import snapshot_source
            report = snapshot_source(args.output)
        elif args.command == 'export':
            from benchmark_store import BenchmarkStore
            from benchmark_reporting import export_snapshot
            export_snapshot(BenchmarkStore(args.state_root), args.experiment, args.output,
                            holdout_registry=args.holdout_registry)
            report = {'exported': True}
        elif args.command == 'init':
            from benchmark_runner import initialize_experiment
            report = initialize_experiment(args.state_root,
                                           load_experiment(args.experiment, args.bundle_root, workflow_path=args.workflow),
                                           args.truth, holdout_registry=args.holdout_registry)
        elif args.command == 'status':
            from benchmark_runner import status
            report = status(args.state_root, args.experiment)
        elif args.command == 'advance':
            from benchmark_runner import advance
            report = advance(args.state_root, args.experiment, args.allow_model_execution, args.retry_call)
            # A dry run or a status-only pass is an honest report (exit 0); a
            # dispatch or automatic advance that failed or became uncertain exits 1.
            if report.get('outcome') in ('failed', 'unknown'):
                code = 1
        elif args.command == 'terminate':
            from benchmark_runner import terminate
            report = terminate(args.state_root, args.experiment, args.trial, args.by, args.note)
        elif args.command == 'corpus-experiment':
            from benchmark_corpus import build_corpus_experiment
            report = build_corpus_experiment(args.cases, args.team, args.experiment_id, args.repetitions,
                                             args.output, seed=args.seed,
                                             holdout_registry=args.holdout_registry,
                                             context_tokens=args.context_tokens,
                                             workflow_path=args.workflow)
        elif args.command == 'baselines':
            from benchmark_baselines import run_baselines
            report = run_baselines(args.experiment_manifest, args.bundle_root, args.truth, args.output,
                                   workflow_path=args.workflow)
        elif args.command == 'reconcile':
            from benchmark_decisions import reconcile
            report = reconcile(args.state_root, args.experiment, args.call,
                               args.by, args.note, args.outcome, args.evidence)
        elif args.command == 'adjudication-template':
            from benchmark_adjudication import adjudication_template
            report = adjudication_template(args.state_root, args.experiment, args.output)
        elif args.command == 'score':
            from benchmark_adjudication import score_experiment
            report = score_experiment(args.state_root, args.experiment, args.truth, args.adjudication)
        elif args.command == 'diagnose':
            from benchmark_store import BenchmarkStore
            from benchmark_diagnostics import diagnose
            report = diagnose(BenchmarkStore(args.state_root), args.experiment, args.truth,
                              args.adjudication, args.output)
        elif args.command == 'holdout':
            from benchmark_store import BenchmarkStore
            from benchmark_holdout import retire
            snapshot = BenchmarkStore(args.state_root).snapshot(args.experiment, verify_truth=False)
            report = retire(args.registry, snapshot, args.by, args.note, args.output)
        else:
            report, code = _campaign(args)
        print(json.dumps(report))
        return code
    except BenchmarkError as exc:
        print(str(exc), file=sys.stderr)
        return 1 if getattr(exc, 'executed', False) else 2
    except (OSError, ValueError, TypeError, KeyError, RecursionError):
        if name in EXECUTING:
            print('execution_error: ' + name, file=sys.stderr)
            return 1
        print('invalid_input: ' + name, file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())

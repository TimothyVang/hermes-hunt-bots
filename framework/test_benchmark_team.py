"""Real ledger/offline scheduler tests; invented receipts are not model results.

The smoke tests drive the actual `advance -> bot.py run --adapter generic ->
benchmark child` chain against a disposable loopback HTTP fixture that speaks the
OpenAI-compatible protocol. Fixture responses are labeled synthetic transport
evidence, never model benchmark results. No test issues a human stage decision:
every stage output advances automatically and unreviewed.
"""
import contextlib
import copy
import http.server
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

import bot
import benchmark_decisions
import benchmark_models
import benchmark_runner
import benchmark_store
from benchmark import load_experiment, main as benchmark_main
from benchmark_contracts import (AUTO_ADVANCE_ACTOR, AUTO_ADVANCE_NOTE, BenchmarkError, canonical_bytes,
                                 decode_json, digest_bytes, load_json)
from benchmark_decisions import auto_advance, ledger_snapshot, stage_handoff
from benchmark_runner import (DEPENDENCIES, advance, build_prompt,
                              initialize_experiment, status, terminate)
from benchmark_store import EVENT_KINDS, BenchmarkStore, STAGE_ROLES
from test_benchmark_runner import (FIXTURES, authorize_fixture, call_fixture, frozen_fixture,
                                  receipt_fixture, response_fixture, trial_fixture)

HERE = Path(__file__).resolve().parent
TRUTH = FIXTURES / 'fixtures'


def cli(*args):
    """Run the real benchmark CLI in-process; returns (exit code, stdout)."""
    output = io.StringIO()
    with contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
        code = benchmark_main([str(arg) for arg in args])
    return code, output.getvalue()


def selected(report, trial):
    return [item['stage_key'] for item in report['selected_tasks'] if item['trial_id'] == trial['trial_id']]


def trial_report(report, trial):
    return next(item for item in report['trials'] if item['trial_id'] == trial['trial_id'])


class BenchmarkTeamTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        # These offline scheduler tests stub dispatch; the optional SDK is not
        # under test here (the preflight tests set it explicitly).
        self.real_route_prerequisite = benchmark_runner._route_prerequisite
        prerequisite = patch('benchmark_runner._route_prerequisite', return_value=True)
        self.prerequisite = prerequisite.start()
        self.addCleanup(prerequisite.stop)
        self.root = Path(self.temp.name) / 'state'
        self.loaded = load_experiment(FIXTURES / 'examples' / 'experiment.json', FIXTURES)
        self.loaded['cases'] = self.loaded['cases'][:1]
        self.loaded['experiment']['scenario_refs'] = self.loaded['experiment']['scenario_refs'][:1]
        self.loaded['experiment']['teams'] = self.loaded['experiment']['teams'][:1]
        self.loaded['experiment']['repetitions'] = 2
        self.eid = self.loaded['experiment']['experiment_id']
        self.initial = initialize_experiment(self.root, self.loaded, TRUTH)
        self.store = BenchmarkStore(self.root)
        self.trial = self.store.get_trial(self.initial['active_trial_id'])
        self.other = next(t for t in self.store.trials(self.eid) if t['trial_id'] != self.trial['trial_id'])
        self.frozen = self.store.get_experiment(self.eid)

    def ledger(self, trial=None):
        trial = trial or self.trial
        return contextlib.closing(bot.connect(self.root / 'trials' / trial['trial_id'] / 'ledger'))

    def assert_code(self, code, operation, *args, **kwargs):
        with self.assertRaises(BenchmarkError) as caught:
            operation(*args, **kwargs)
        self.assertEqual(caught.exception.code, code)

    def submitted(self, stage='scope', summary='Synthetic ledger fixture; no model call.', attempt=1):
        """Install a labeled receipt and exact native generic-submit linkage."""
        aid = 'test-auth-' + stage + '-' + str(attempt)
        authorization = authorize_fixture(self.store, self.frozen, self.trial, aid)
        spec = call_fixture(self.store, self.frozen, self.trial, authorization, stage, attempt)
        prompt = self.store.write_artifact(self.trial['trial_id'], 'prompt',
                                          build_prompt(self.store, self.trial, stage))
        spec.update(prompt_artifact=prompt, input_sha256=prompt['sha256'])
        cid = 'test-call-' + stage + '-' + str(attempt)
        self.store.reserve_call(cid, digest_bytes(canonical_bytes(spec)), spec)
        receipt = receipt_fixture(self.store, self.frozen, cid, spec)
        output = response_fixture(stage)
        output['summary'] = summary
        data = canonical_bytes(output)
        ref = self.store.write_artifact(self.trial['trial_id'], 'response', data)
        receipt.update(response_sha256=ref['sha256'], response_artifact=ref)
        self.store.finish_call(cid, receipt)
        root = self.root / 'trials' / self.trial['trial_id'] / 'ledger' / 'runs' / cid
        root.mkdir(parents=True)
        stdout, stderr = root / 'stdout.txt', root / 'stderr.txt'
        stdout.write_bytes(data)
        stderr.write_bytes(b'')
        task_id = self.trial['task_mapping'][stage]
        with self.ledger() as db, db:
            db.execute("UPDATE tasks SET status='review' WHERE id=?", (task_id,))
            bot.event(db, task_id, 'run-started', 'operator', 'Labeled synthetic offline test; no subprocess.')
            for path, description in ((stdout, 'CLI stdout'), (stderr, 'CLI stderr')):
                db.execute('INSERT INTO artifacts(task_id,path,description,added) VALUES(?,?,?,?)',
                           (task_id, str(path), description, bot.now()))
            bot.event(db, task_id, 'submit', 'generic',
                      'CLI exited successfully; authentic output handoff: {}; stderr: {}'.format(stdout, stderr))
        return receipt, stdout

    def advanced(self, stage='scope', **kwargs):
        receipt, stdout = self.submitted(stage, **kwargs)
        auto_advance(self.store, self.trial, stage)
        return receipt, stdout

    def reinitialize(self, loaded):
        self.root = Path(self.temp.name) / ('state-' + str(len(list(Path(self.temp.name).iterdir()))))
        self.loaded = loaded
        self.initial = initialize_experiment(self.root, loaded, TRUTH)
        self.store = BenchmarkStore(self.root)
        self.trial = self.store.get_trial(self.initial['active_trial_id'])
        self.other = next(t for t in self.store.trials(self.eid) if t['trial_id'] != self.trial['trial_id'])
        self.frozen = self.store.get_experiment(self.eid)

    def test_init_creates_seven_tasks_six_identities_and_exact_dependencies(self):
        self.assertEqual(len(self.initial['trials']), 2)
        self.assertEqual(set(STAGE_ROLES.values()), set(self.frozen['role_instructions']))
        self.assertEqual(len(set(STAGE_ROLES.values())), 6)
        for trial in self.store.trials(self.eid):
            snapshot = ledger_snapshot(self.store, trial)
            self.assertEqual(set(snapshot['tasks']), set(DEPENDENCIES))
            self.assertEqual({task['status'] for task in snapshot['tasks'].values()}, {'pending'})
            self.assertEqual(len(set(trial['task_mapping'].values())), 7)
        self.assertEqual(self.store.calls(experiment_id=self.eid), [])
        self.assertEqual(self.store.snapshot(self.eid)['approvals'], [])
        self.assertEqual((self.initial['review_policy'], self.initial['max_concurrent_calls'],
                          self.initial['timing_contended']), ('auto_advance', 4, True))

    def test_init_refuses_existing_experiment_without_reusing_ledger(self):
        before = self.store.snapshot(self.eid)
        self.assert_code('already_exists', initialize_experiment, self.root, self.loaded, TRUTH)
        self.assertEqual(before, self.store.snapshot(self.eid))

    def test_fresh_repetitions_have_separate_state_and_identical_initial_prompt(self):
        first, second = self.store.trials(self.eid)
        self.assertNotEqual(first['trial_id'], second['trial_id'])
        self.assertEqual(build_prompt(self.store, first, 'scope'), build_prompt(self.store, second, 'scope'))
        self.advanced()
        self.assertEqual(ledger_snapshot(self.store, self.other)['tasks']['scope']['status'], 'pending')
        self.assertEqual(self.store.calls(trial_id=self.other['trial_id']), [])

    def test_seeded_order_does_not_depend_on_random_trial_ids(self):
        second_root = Path(self.temp.name) / 'other-state'
        second = initialize_experiment(second_root, copy.deepcopy(self.loaded), TRUTH)
        key = lambda item: (item['case_id'], item['team_id'], item['repetition'])
        self.assertEqual(list(map(key, self.initial['trials'])), list(map(key, second['trials'])))
        # The same (case, team, repetition) is first in an independent state root.
        active = lambda report: next(key(item) for item in report['trials']
                                     if item['trial_id'] == report['active_trial_id'])
        self.assertEqual(active(self.initial), active(second))

    def test_concurrency_setting_is_validated(self):
        for value in (0, 17, True):
            loaded = copy.deepcopy(self.loaded)
            loaded['experiment']['budgets']['max_concurrent_calls'] = value
            with self.subTest(value=value):
                self.assert_code('invalid_integer', initialize_experiment,
                                 Path(self.temp.name) / 'refused-state', loaded, TRUTH)
                self.assertFalse((Path(self.temp.name) / 'refused-state').exists())

    def test_scheduler_never_exceeds_the_concurrency_limit(self):
        for limit in (1, 2):
            loaded = copy.deepcopy(self.loaded)
            loaded['experiment']['budgets']['max_concurrent_calls'] = limit
            self.reinitialize(loaded)
            lock, state = threading.Lock(), {'now': 0, 'peak': 0}
            # With two in flight, both trials' scope dispatches must overlap.
            barrier = threading.Barrier(limit, timeout=10)

            def recorded(store, experiment_id, item, identity, trial_lock):
                with lock:
                    state['now'] += 1
                    state['peak'] = max(state['peak'], state['now'])
                barrier.wait()
                with lock:
                    state['now'] -= 1
                return {'state': 'dispatched', 'call_id': None}

            with self.subTest(limit=limit), patch('benchmark_runner._dispatch', side_effect=recorded) as spy:
                result = advance(self.root, self.eid, True)
                self.assertEqual(state['peak'], limit)
                self.assertEqual(sorted(call.args[2]['trial_id'] for call in spy.call_args_list),
                                 sorted(t['trial_id'] for t in (self.trial, self.other)))
                self.assertEqual((result['outcome'], result['timing_contended']), ('ok', limit > 1))

    def test_independent_branches_of_one_trial_run_together_dependents_wait(self):
        self.advanced()
        terminate(self.root, self.eid, self.other['trial_id'], 'test-only-human', 'Synthetic isolation.')
        seen = []

        def recorded(store, experiment_id, item, identity, trial_lock):
            seen.append(item['stage_key'])
            return {'state': 'dispatched', 'call_id': None}

        with patch('benchmark_runner._dispatch', side_effect=recorded):
            result = advance(self.root, self.eid, True)
        # One wave of the three mutually independent branches; analysis waits.
        self.assertEqual(sorted(seen), ['endpoint_evidence', 'hypotheses', 'network_evidence'])
        self.assertEqual(result['outcome'], 'ok')

    def test_siblings_cancelled_by_a_failed_branch_are_dispatched_in_the_next_wave(self):
        loaded = copy.deepcopy(self.loaded)
        loaded['experiment']['budgets']['max_concurrent_calls'] = 1
        self.reinitialize(loaded)
        self.advanced()
        terminate(self.root, self.eid, self.other['trial_id'], 'test-only-human', 'Synthetic isolation.')
        seen = []

        def recorded(store, experiment_id, item, identity, trial_lock):
            seen.append(item['stage_key'])
            if len(seen) == 1:
                return {'state': 'failed', 'call_id': None,
                        'error': {'code': 'synthetic_failure', 'field': 'call'}}
            return {'state': 'dispatched', 'call_id': None}

        with patch('benchmark_runner._dispatch', side_effect=recorded):
            advance(self.root, self.eid, True)
        # The failure cancels the queued siblings of that wave; they must not be
        # silently abandoned for the rest of the run.
        self.assertEqual(sorted(seen), ['endpoint_evidence', 'hypotheses', 'network_evidence'])

    def test_budget_exhausted_trial_is_terminated_and_next_trial_proceeds(self):
        loaded = copy.deepcopy(self.loaded)
        loaded['experiment']['budgets']['max_calls_per_trial'] = 1
        self.reinitialize(loaded)
        self.advanced()
        report = advance(self.root, self.eid)
        stalled = trial_report(report, self.trial)
        self.assertEqual(stalled['budget_exhausted'][0], {'stage_key': 'endpoint_evidence', 'budget': 'calls'})
        self.assertEqual(selected(report, self.trial), [])
        dispatched = []

        def recorded(store, experiment_id, item, identity, lock):
            dispatched.append(item)
            return {'state': 'dispatched', 'call_id': None}

        with patch('benchmark_runner._dispatch', side_effect=recorded):
            result = advance(self.root, self.eid, True)
        self.assertEqual(result['terminated_trials'], [self.trial['trial_id']])
        self.assertEqual(dispatched, [{'trial_id': self.other['trial_id'], 'stage_key': 'scope',
                                       'attempt_index': 1, 'ledger_status': 'pending'}])
        terminated = self.store.get_trial(self.trial['trial_id'])
        self.assertEqual((terminated['status'], terminated['terminal_reason']), ('terminated', 'budget_exhausted'))
        events = [e for e in self.store.snapshot(self.eid)['events'] if e['kind'] == 'trial_terminated']
        self.assertEqual([(e['trial_id'], e['actor']) for e in events],
                         [(self.trial['trial_id'], 'benchmark-runner')])
        self.assertEqual(trial_report(result, self.trial)['status'], 'terminated')

    def test_human_termination_skips_blocked_trial(self):
        with self.ledger() as db, db:
            db.execute("UPDATE tasks SET scope='Changed scope' WHERE id=?", (self.trial['task_mapping']['scope'],))
        report = advance(self.root, self.eid)
        self.assertEqual(report['active_trial_id'], self.trial['trial_id'])
        self.assertEqual(trial_report(report, self.trial)['status'], 'blocked')
        # A blocked trial never stalls another one.
        self.assertEqual(report['selected_tasks'], [{'trial_id': self.other['trial_id'], 'stage_key': 'scope'}])
        code, output = cli('--state-root', self.root, 'terminate', '--experiment', self.eid,
                           '--trial', self.trial['trial_id'], '--by', 'test-only-human',
                           '--note', 'Synthetic abandonment of a tampered ledger.')
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output)['active_trial_id'], self.other['trial_id'])
        self.assertEqual(self.store.get_trial(self.trial['trial_id'])['terminal_reason'], 'human_abandoned')
        self.assert_code('scope_mismatch', terminate, self.root, 'other-experiment', self.other['trial_id'],
                         'test-only-human', 'Wrong experiment.')
        self.assertEqual(cli('--state-root', self.root, 'terminate', '--experiment', 'other-experiment',
                             '--trial', self.other['trial_id'], '--by', 'test-only-human',
                             '--note', 'Wrong experiment.')[0], 2)

    def test_dry_run_advance_reports_unknown_with_exit_zero(self):
        auth = authorize_fixture(self.store, self.frozen, self.trial)
        spec = call_fixture(self.store, self.frozen, self.trial, auth)
        self.store.reserve_call('uncertain-cli-call', digest_bytes(canonical_bytes(spec)), spec)
        code, output = cli('--state-root', self.root, 'advance', '--experiment', self.eid)
        self.assertEqual(code, 0)
        self.assertEqual(trial_report(json.loads(output), self.trial)['status'], 'unknown')

    def test_holdout_init_requires_registry_before_state(self):
        loaded = copy.deepcopy(self.loaded)
        loaded['cases'][0]['scenario']['split'] = 'holdout'
        target = Path(self.temp.name) / 'holdout-state'
        self.assert_code('holdout_registry_required', initialize_experiment, target, loaded, TRUTH)
        self.assertFalse(target.exists())

    def test_validate_names_missing_scenario_field(self):
        error = io.StringIO()
        with contextlib.redirect_stderr(error), contextlib.redirect_stdout(io.StringIO()):
            code = benchmark_main(['validate', '--experiment', str(FIXTURES / 'examples' / 'experiment.json')])
        self.assertEqual(code, 2)
        self.assertEqual(error.getvalue().strip(), 'file_not_found: scenario_refs.scenario')
        self.assertEqual(cli('validate', '--experiment', FIXTURES / 'examples' / 'experiment.json',
                             '--bundle-root', FIXTURES)[0], 0)

    def test_dryrun_has_no_writes_subprocess_or_authorization(self):
        self.submitted()
        before = {path.relative_to(self.root).as_posix(): digest_bytes(path.read_bytes())
                  for path in self.root.rglob('*') if path.is_file()}
        with patch('benchmark_runner.subprocess.run', side_effect=AssertionError('No dispatch permitted')):
            report = advance(self.root, self.eid)
        after = {path.relative_to(self.root).as_posix(): digest_bytes(path.read_bytes())
                 for path in self.root.rglob('*') if path.is_file()}
        self.assertEqual(before, after)
        self.assertTrue(report['dry_run'])
        self.assertFalse(report['dispatched'])
        # A dry run reports the validated output it would advance, but never advances.
        self.assertEqual(report['pending_advances'], [{'trial_id': self.trial['trial_id'], 'stage_key': 'scope'}])
        self.assertEqual(report['selected_tasks'], [{'trial_id': self.other['trial_id'], 'stage_key': 'scope'}])
        self.assertEqual(ledger_snapshot(self.store, self.trial)['tasks']['scope']['status'], 'review')
        self.assertFalse((self.root / 'runner.lock').exists())

    def test_prompt_contains_public_contents_not_runtime_or_evaluator_metadata(self):
        raw = build_prompt(self.store, self.trial, 'scope')
        prompt = decode_json(raw)
        self.assertTrue(prompt['untrusted_public_evidence']['files'])
        self.assertEqual(prompt['untrusted_immediate_predecessors'], [])
        self.assertEqual(set(prompt), {'prompt_contract', 'role_purpose', 'stage', 'untrusted_public_evidence',
                                       'untrusted_immediate_predecessors'})
        for forbidden in (self.trial['trial_id'], self.eid, str(self.root),
                          self.trial['scenario_id'], 'truth_revision', 'schedule_seed'):
            self.assertNotIn(forbidden, raw.decode('utf-8'))
        self.assertNotIn('difficulty', prompt['untrusted_public_evidence'])
        self.assertNotIn('scenario', prompt)
        for file in prompt['untrusted_public_evidence']['files']:
            self.assertNotIn('path', file)
            self.assertIn('content', file)

    def test_advanced_scope_unlocks_only_independent_branches(self):
        self.advanced(summary='Unique advanced scope fixture.')
        report = advance(self.root, self.eid)
        self.assertEqual(selected(report, self.trial), ['endpoint_evidence', 'network_evidence', 'hypotheses'])
        self.submitted('endpoint_evidence', summary='Sibling output must stay private.')
        network = decode_json(build_prompt(self.store, self.trial, 'network_evidence'))
        predecessors = network['untrusted_immediate_predecessors']
        self.assertEqual([item['stage_key'] for item in predecessors], ['scope'])
        self.assertEqual(predecessors[0]['output']['summary'], 'Unique advanced scope fixture.')
        self.assertNotIn('Sibling output must stay private.', canonical_bytes(network).decode())
        report = advance(self.root, self.eid)
        self.assertEqual(selected(report, self.trial), ['network_evidence', 'hypotheses'])
        self.assertEqual([item for item in report['pending_advances'] if item['trial_id'] == self.trial['trial_id']],
                         [{'trial_id': self.trial['trial_id'], 'stage_key': 'endpoint_evidence'}])

    def test_manual_ledger_approval_blocks_the_trial(self):
        self.submitted()
        with self.ledger() as db, db:
            task = self.trial['task_mapping']['scope']
            db.execute("UPDATE tasks SET status='done' WHERE id=?", (task,))
            bot.event(db, task, 'approve', 'test-only-reviewer', 'Synthetic manual ledger transition.')
        report = advance(self.root, self.eid)
        trial = trial_report(report, self.trial)
        self.assertEqual(trial['status'], 'blocked')
        self.assertEqual(trial['stages'][0]['blocker'], 'unsupported_ledger_transition')
        self.assertEqual(selected(report, self.trial), [])
        self.assertEqual(report['pending_advances'], [])

    def test_changed_advanced_stdout_invalidates_successor_prompt(self):
        _, stdout = self.advanced()
        stdout.write_bytes(stdout.read_bytes() + b' ')
        self.assert_code('digest_mismatch', build_prompt, self.store, self.trial, 'endpoint_evidence')
        self.assertEqual(selected(advance(self.root, self.eid), self.trial), [])

    def test_changed_public_artifact_is_rejected(self):
        ref = next(iter(self.trial['public_artifacts'].values()))
        path = self.root / 'trials' / self.trial['trial_id'] / ref['path']
        path.write_bytes(path.read_bytes() + b' ')
        self.assert_code('artifact_corrupt', build_prompt, self.store, self.trial, 'scope')

    def status_work(self):
        """Ledger opens, artifact hashes and frozen-experiment decodes of one status,
        starting without any memoized artifact proof."""
        opened, hashed, decoded = [], [], []
        ledger, read, frozen = (benchmark_decisions._ledger, BenchmarkStore.read_artifact,
                                benchmark_store._unpack_frozen)

        def count_ledger(store, trial):
            opened.append(trial['trial_id'])
            return ledger(store, trial)

        def count_read(store, trial_id, ref):
            hashed.append(trial_id)
            return read(store, trial_id, ref)

        def count_frozen(row):
            decoded.append(row['sha256'])
            return frozen(row)

        with patch.object(benchmark_decisions, '_ledger', count_ledger), \
                patch.object(BenchmarkStore, 'read_artifact', count_read), \
                patch.object(benchmark_store, '_unpack_frozen', count_frozen), \
                patch.object(benchmark_store, '_VERIFIED_ARTIFACTS', set()):
            report = status(self.root, self.eid)
        return report, opened, hashed, decoded

    def test_status_work_is_linear_in_trials(self):
        # One trial with an advanced stage, whose successors' prompts embed it.
        self.advanced()
        report, opened, hashed, decoded = self.status_work()
        self.assertEqual(selected(report, self.trial), ['endpoint_evidence', 'network_evidence', 'hypotheses'])
        trials = [trial['trial_id'] for trial in self.store.trials(self.eid)]
        # Every ledger opens exactly once, however many stages and predecessors it has.
        self.assertEqual(sorted(opened), sorted(trials))
        self.assertEqual(len(decoded), 1)
        small = len(hashed)
        loaded = copy.deepcopy(self.loaded)
        loaded['experiment']['repetitions'] = 6
        self.reinitialize(loaded)
        self.advanced()
        report, opened, hashed, decoded = self.status_work()
        self.assertEqual(sorted(opened), sorted(trial['trial_id'] for trial in self.store.trials(self.eid)))
        self.assertEqual(len(decoded), 1)
        # Four more pending trials add a fixed number of artifact hashes each;
        # a per-trial rescan of every trial's artifacts would grow quadratically.
        files = len(self.trial['public_artifacts'])
        self.assertEqual(len(hashed) - small, 4 * 2 * files)

    def test_routine_status_rehashes_an_artifact_rewritten_after_its_proof(self):
        status(self.root, self.eid)
        ref = next(iter(self.other['public_artifacts'].values()))
        path = self.root / 'trials' / self.other['trial_id'] / ref['path']
        data = path.read_bytes()
        path.write_bytes(bytes([data[0] ^ 1]) + data[1:])
        self.assert_code('artifact_corrupt', status, self.root, self.eid)

    def test_full_snapshot_rehashes_what_routine_reads_memoized(self):
        self.advanced()
        self.assertEqual(self.store.snapshot(self.eid, routine=True), self.store.snapshot(self.eid))
        ref = next(iter(self.other['public_artifacts'].values()))
        path = self.root / 'trials' / self.other['trial_id'] / ref['path']
        info, data = path.stat(), path.read_bytes()
        path.write_bytes(bytes([data[0] ^ 1]) + data[1:])
        # A forged identical size and mtime is the documented routine memo limit;
        # export, score, diagnose and release still re-hash every byte.
        os.utime(path, ns=(info.st_atime_ns, info.st_mtime_ns))
        self.assert_code('artifact_corrupt', self.store.snapshot, self.eid)

    def test_dispatch_authorization_reads_do_not_grow_with_other_trials(self):
        model = self.frozen['experiment']['teams'][0]['roles'][STAGE_ROLES['scope']]
        own = authorize_fixture(self.store, self.frozen, self.trial, 'own-authorization')

        def verified_rows():
            rows, unpack = [], benchmark_store._unpack

            def counting(row):
                rows.append(row)
                return unpack(row)

            with patch.object(benchmark_store, '_unpack', counting):
                sha = benchmark_models._current_authorization(self.store, self.trial, model)
                with self.store.connection() as db:
                    self.store._authorization(db, own)
            return sha, len(rows)

        before = verified_rows()
        self.assertEqual(before[0], own)
        # Other trials' authorizations add approval rows and events; the dispatch
        # decision for this trial must verify exactly the same rows as before.
        for index in range(5):
            authorize_fixture(self.store, self.frozen, self.other, 'other-authorization-{}'.format(index))
        self.assertEqual(verified_rows(), before)

    def test_targeted_authorization_read_still_rejects_a_forged_row(self):
        model = self.frozen['experiment']['teams'][0]['roles'][STAGE_ROLES['scope']]
        authorize_fixture(self.store, self.frozen, self.trial, 'forged-authorization')
        with self.store.connection(immediate=True) as db:
            row = db.execute("SELECT data FROM approvals WHERE approval_id='forged-authorization'").fetchone()
            item = decode_json(bytes(row['data']))
            item['expires_utc'] = '2199-01-01T00:00:00+00:00'
            data = canonical_bytes(item)
            # A consistent row digest, but the authorization digest no longer matches.
            db.execute("UPDATE approvals SET data=?, sha256=? WHERE approval_id='forged-authorization'",
                       (data, digest_bytes(data)))
        self.assert_code('corrupt_state', self.store.trial_authorizations, self.trial['trial_id'])
        self.assert_code('corrupt_state', benchmark_models._current_authorization, self.store, self.trial, model)

    def test_unrelated_task_is_never_selected_and_owned_task_mutation_blocks(self):
        with self.ledger() as db, db:
            db.execute("INSERT INTO tasks(title,role,scope,acceptance,status,created) VALUES(?,?,?,?,?,?)",
                       ('Unrelated task', 'builder', 'Unrelated', 'Unrelated', 'pending', bot.now()))
        self.assertEqual(selected(advance(self.root, self.eid), self.trial), ['scope'])
        with self.ledger() as db, db:
            db.execute("UPDATE tasks SET scope='Changed scope' WHERE id=?", (self.trial['task_mapping']['scope'],))
        report = advance(self.root, self.eid)
        self.assertEqual(selected(report, self.trial), [])
        self.assertEqual(trial_report(report, self.trial)['error']['code'], 'ledger_scope_mismatch')

    def test_unknown_reservation_blocks_redispatch_and_retains_budget(self):
        auth = authorize_fixture(self.store, self.frozen, self.trial)
        spec = call_fixture(self.store, self.frozen, self.trial, auth)
        self.store.reserve_call('uncertain-test-call', digest_bytes(canonical_bytes(spec)), spec)
        report = advance(self.root, self.eid)
        trial = trial_report(report, self.trial)
        self.assertEqual(trial['status'], 'unknown')
        self.assertEqual(selected(report, self.trial), [])
        budget = trial['budgets']
        self.assertIsNone(budget['measured_active_seconds'])
        self.assertEqual(budget['unknown_active_time_calls'], 1)
        self.assertEqual(budget['active_seconds_remaining'],
                         self.frozen['experiment']['budgets']['max_active_seconds_per_trial'] - spec['model']['timeout_seconds'])
        self.assert_code('reconciliation_required', advance, self.root, self.eid, False, 'uncertain-test-call')
        seen = []
        with patch('benchmark_runner._dispatch',
                   side_effect=lambda store, eid, item, *args: seen.append(item) or {'state': 'dispatched',
                                                                                    'call_id': None}):
            advance(self.root, self.eid, True)
        self.assertEqual([item['trial_id'] for item in seen], [self.other['trial_id']])

    def uncertain(self, ledger_status, stage='scope', status='unknown', reason='timeout'):
        """An invented unknown (timed-out) or failed call inside a real ledger run record."""
        task_id = self.trial['task_mapping'][stage]
        with self.ledger() as db, db:
            db.execute("UPDATE tasks SET status='running' WHERE id=?", (task_id,))
            bot.event(db, task_id, 'run-started', 'operator', 'Labeled synthetic offline test; no subprocess.')
        auth = authorize_fixture(self.store, self.frozen, self.trial, 'test-auth-uncertain-' + stage)
        spec = call_fixture(self.store, self.frozen, self.trial, auth, stage)
        call_id = 'uncertain-' + stage.replace('_', '-')
        self.store.reserve_call(call_id, digest_bytes(canonical_bytes(spec)), spec)
        outcome = receipt_fixture(self.store, self.frozen, call_id, spec, status)
        outcome.update(failure_reason=reason, elapsed_ms=spec['model']['timeout_seconds'] * 1000.0 + 7)
        self.store.finish_call(call_id, outcome)
        if ledger_status == 'blocked':
            # bot.py records run-failed only after its child returned or was reaped.
            with self.ledger() as db, db:
                db.execute("UPDATE tasks SET status='blocked' WHERE id=?", (task_id,))
                bot.event(db, task_id, 'run-failed', 'operator', 'Labeled synthetic offline child exit.')
        return call_id, spec

    def stub_dispatch(self):
        seen = []
        return seen, patch('benchmark_runner._dispatch', side_effect=lambda store, eid, item, *args: (
            seen.append(item) or {'state': 'dispatched', 'call_id': None}))

    def reconciliations(self):
        return [e for e in self.store.snapshot(self.eid)['events'] if e['kind'] == 'reconciliation_recorded']

    def test_known_model_failure_is_retried_only_after_a_proven_stop(self):
        call_id, _ = self.uncertain('running', status='failed', reason='invalid_response')
        seen, stub = self.stub_dispatch()
        with stub:
            result = advance(self.root, self.eid, True)
        # The child may still be running: nothing is retried automatically.
        self.assertEqual(result['auto_retried'], [])
        self.assertNotIn(self.trial['trial_id'], [item['trial_id'] for item in seen])
        with self.ledger() as db, db:
            task_id = self.trial['task_mapping']['scope']
            db.execute("UPDATE tasks SET status='blocked' WHERE id=?", (task_id,))
            bot.event(db, task_id, 'run-failed', 'operator', 'Labeled synthetic offline child exit.')
        dry = advance(self.root, self.eid)
        self.assertEqual(trial_report(dry, self.trial)['stages'][0]['blocker'], 'automatic_retry_pending')
        seen, stub = self.stub_dispatch()
        with stub:
            result = advance(self.root, self.eid, True)
        self.assertIn({'trial_id': self.trial['trial_id'], 'stage_key': 'scope', 'attempt_index': 2,
                       'ledger_status': 'active'}, seen)
        self.assertEqual([(item['call_id'], item['failure_reason']) for item in result['auto_retried']],
                         [(call_id, 'invalid_response')])
        self.assertEqual(self.reconciliations(), [])
        call = self.store.calls(trial_id=self.trial['trial_id'])[0]
        self.assertEqual((call['status'], call['receipt']['failure_reason']), ('failed', 'invalid_response'))
        self.assertIsNotNone(call['receipt']['elapsed_ms'])  # a known receipt is kept, never discarded
        ledger = [e for e in ledger_snapshot(self.store, self.trial)['events']
                  if e['task_id'] == self.trial['task_mapping']['scope']]
        self.assertEqual((ledger[-1]['kind'], ledger[-1]['actor']), ('auto_resume', 'benchmark-auto-retry'))

    def test_configuration_failure_is_reported_then_terminates_the_trial(self):
        call_id, _ = self.uncertain('blocked', status='failed', reason='authentication_failed')
        dry = advance(self.root, self.eid)
        report = trial_report(dry, self.trial)
        self.assertEqual((report['status'], report['stages'][0]['blocker'], report['unrecoverable']),
                         ('blocked', 'unrecoverable_configuration',
                          [{'stage_key': 'scope', 'call_id': call_id, 'failure_reason': 'authentication_failed'}]))
        seen, stub = self.stub_dispatch()
        with stub:
            result = advance(self.root, self.eid, True)
        self.assertEqual((result['terminated_trials'], result['auto_retried']), ([self.trial['trial_id']], []))
        self.assertEqual(self.store.get_trial(self.trial['trial_id'])['terminal_reason'], 'unrecoverable_stage')
        # The other trial continues.
        self.assertEqual([item['trial_id'] for item in seen], [self.other['trial_id']])

    CREDENTIAL = 'BENCH_MODEL_PREFLIGHT_TEST_KEY'
    SENTINEL = 'sentinel-credential-value-never-logged'

    def preflight_run(self):
        seen, stub = self.stub_dispatch()
        with stub:
            code, output = cli('--state-root', self.root, 'advance', '--experiment', self.eid,
                               '--allow-model-execution')
        return code, json.loads(output), seen

    def assert_team_terminated(self, report, seen, reason, role):
        self.assertEqual(seen, [])  # nothing dispatched, for any trial of the team
        self.assertEqual(report['route_preflight'][self.loaded['experiment']['teams'][0]['team_id']]['reason'],
                         reason)
        self.assertEqual(sorted(report['terminated_trials']), sorted([self.trial['trial_id'], self.other['trial_id']]))
        self.assertEqual({(item['state'], item['error']['code'], item['error']['field']) for item in report['failures']},
                         {('failed', reason, 'route.' + role)})
        for trial in (self.trial, self.other):
            self.assertEqual(self.store.get_trial(trial['trial_id'])['terminal_reason'], 'unrecoverable_stage')
        # Nothing is left waiting for a human reconciliation, and status names the reason.
        self.assertEqual(report['status'], 'finished')
        self.assertEqual(self.store.calls(experiment_id=self.eid), [])
        shown = trial_report(status(self.root, self.eid), self.trial)
        self.assertEqual(shown['terminal_reason'], 'unrecoverable_stage')
        self.assertIn(reason, shown['terminal_note'])

    def test_missing_credential_terminates_the_team_before_any_dispatch(self):
        loaded = copy.deepcopy(self.loaded)
        loaded['experiment']['teams'][0]['roles']['framework-researcher']['credential_env'] = self.CREDENTIAL
        with patch.dict(os.environ):
            os.environ.pop(self.CREDENTIAL, None)
            self.reinitialize(loaded)
            team = loaded['experiment']['teams'][0]['team_id']
            self.assertEqual(status(self.root, self.eid)['route_preflight'][team],
                             {'status': 'blocked', 'reason': 'credential_unavailable', 'role': 'framework-researcher',
                              'credential_env': self.CREDENTIAL, 'sdk_prerequisite': 'checked_on_execution'})
            code, report, seen = self.preflight_run()
        self.assertEqual(code, 1)
        self.assert_team_terminated(report, seen, 'credential_unavailable', 'framework-researcher')
        # Presence only: a set value is never read into status, events or logs.
        with patch.dict(os.environ, {self.CREDENTIAL: self.SENTINEL}):
            shown = status(self.root, self.eid)
        self.assertEqual(shown['route_preflight'][team]['status'], 'ok')
        self.assertNotIn(self.SENTINEL, json.dumps(shown))
        self.assertNotIn(self.SENTINEL.encode(), (self.root / 'benchmark.sqlite3').read_bytes())

    def test_missing_sdk_terminates_the_team_before_any_dispatch(self):
        self.prerequisite.return_value = False
        # Status and dry runs launch no subprocess: the SDK check waits for execution.
        dry = advance(self.root, self.eid)['route_preflight'][self.trial['team_id']]
        self.assertEqual(dry, {'status': 'ok', 'sdk_prerequisite': 'checked_on_execution'})
        self.prerequisite.assert_not_called()
        self.assertEqual(self.store.get_trial(self.trial['trial_id'])['status'], 'pending')
        code, report, seen = self.preflight_run()
        self.assertEqual(code, 1)
        preflight = report['route_preflight'][self.trial['team_id']]
        self.assertEqual(preflight['sdk_prerequisite'], 'checked')
        self.assert_team_terminated(report, seen, 'prerequisite_missing', preflight['role'])
        self.assertEqual({call.args[0] for call in self.prerequisite.call_args_list}, {'openai'})

    def test_sdk_check_runs_in_the_model_child_environment(self):
        # The real check, never mocked: Python 3.9 always lacks the optional adapter.
        env = benchmark_runner._environment(dict(self.frozen['experiment']['teams'][0]['roles']
                                                 ['framework-coordinator'], credential_env=None))
        result = self.real_route_prerequisite('openai', env)
        self.assertIs(type(result), bool)
        if sys.version_info < (3, 10):
            self.assertFalse(result)

    def test_unlisted_failure_reason_is_left_to_a_human(self):
        self.uncertain('blocked', status='failed', reason='execution_failed')
        seen, stub = self.stub_dispatch()
        with stub:
            result = advance(self.root, self.eid, True)
        self.assertEqual((result['auto_retried'], result['terminated_trials']), ([], []))
        self.assertEqual(trial_report(result, self.trial)['stages'][0]['blocker'], 'reconciliation_required')
        self.assertNotIn(self.trial['trial_id'], [item['trial_id'] for item in seen])

    def test_stopped_unknown_call_is_reconciled_and_retried_without_a_human(self):
        call_id, spec = self.uncertain('blocked')
        dry = advance(self.root, self.eid)
        self.assertEqual(dry['pending_auto_recovery'], [{'trial_id': self.trial['trial_id'], 'stage_key': 'scope'}])
        scope = trial_report(dry, self.trial)['stages'][0]
        self.assertEqual((scope['blocker'], scope['uncertain_call_id']), ('previous_dispatch_unknown', call_id))
        timing = scope['calls'][0]
        self.assertEqual((timing['elapsed_basis'], timing['timeout_seconds'], timing['timeout_margin_ms']),
                         ('receipt', spec['model']['timeout_seconds'], -7.0))
        self.assertEqual(self.reconciliations(), [])  # a dry run never reconciles
        seen, stub = self.stub_dispatch()
        with stub:
            result = advance(self.root, self.eid, True)
        self.assertIn({'trial_id': self.trial['trial_id'], 'stage_key': 'scope', 'attempt_index': 2,
                       'ledger_status': 'active'}, seen)
        self.assertEqual((result['outcome'], result['failures']), ('ok', []))
        self.assertEqual([(item['call_id'], item['policy'], item['prior_failure_reason'], item['charged_seconds'])
                          for item in result['auto_reconciled']],
                         [(call_id, 'automatic_model_call', 'timeout', spec['model']['timeout_seconds'])])
        call = next(c for c in self.store.calls(trial_id=self.trial['trial_id']) if c['call_id'] == call_id)
        self.assertEqual((call['status'], call['receipt']['failure_reason'], call['receipt']['elapsed_ms']),
                         ('failed', 'timeout', None))
        events = self.reconciliations()
        self.assertEqual([(e['actor'], e['payload']['policy'], e['payload']['observed_elapsed_ms'])
                          for e in events],
                         [('benchmark-auto-reconcile', 'automatic_model_call',
                           spec['model']['timeout_seconds'] * 1000.0 + 7)])
        self.assertIn('not a human review', events[0]['payload']['note'])
        ledger = [e for e in ledger_snapshot(self.store, self.trial)['events']
                  if e['task_id'] == self.trial['task_mapping']['scope']]
        self.assertEqual((ledger[-1]['kind'], ledger[-1]['actor']), ('auto_resume', 'benchmark-auto-reconcile'))
        self.assertFalse({'resume', 'recover-run', 'approve', 'reject'} & {e['kind'] for e in ledger})
        # The late response of the resolved call is never accepted, by any path.
        self.assert_code('state_conflict', self.store.finish_call, call_id,
                         receipt_fixture(self.store, self.frozen, call_id, spec))
        self.assertEqual(trial_report(status(self.root, self.eid), self.trial)['stages'][0]['calls'][0]
                         ['reconciliation_policy'], 'automatic_model_call')

    def test_unconfirmed_process_stop_blocks_without_reconciliation(self):
        call_id, _ = self.uncertain('running')
        seen, stub = self.stub_dispatch()
        with stub:
            result = advance(self.root, self.eid, True)
        self.assertNotIn(self.trial['trial_id'], [item['trial_id'] for item in seen])
        report = trial_report(result, self.trial)
        self.assertEqual((report['status'], report['stages'][0]['blocker']), ('unknown', 'process_stop_unconfirmed'))
        self.assertEqual(result['outcome'], 'unknown')
        self.assertIn({'trial_id': self.trial['trial_id'], 'stage_key': 'scope', 'state': 'unknown',
                       'call_id': call_id, 'error': {'code': 'process_stop_unconfirmed', 'field': 'process'}},
                      result['failures'])
        self.assertEqual(result['auto_reconciled'], [])
        self.assertEqual(self.reconciliations(), [])
        self.assertEqual(self.store.calls(trial_id=self.trial['trial_id'])[0]['status'], 'unknown')
        self.assertEqual(ledger_snapshot(self.store, self.trial)['tasks']['scope']['status'], 'running')

    def test_automatic_retry_stays_within_max_attempts(self):
        loaded = copy.deepcopy(self.loaded)
        loaded['experiment']['budgets']['max_attempts_per_stage'] = 1
        self.reinitialize(loaded)
        call_id, _ = self.uncertain('blocked')
        seen, stub = self.stub_dispatch()
        with stub:
            result = advance(self.root, self.eid, True)
        self.assertEqual([item['call_id'] for item in result['auto_reconciled']], [call_id])
        self.assertNotIn(self.trial['trial_id'], [item['trial_id'] for item in seen])
        self.assertIn(self.trial['trial_id'], result['terminated_trials'])
        self.assertEqual(self.store.get_trial(self.trial['trial_id'])['terminal_reason'], 'budget_exhausted')

    def test_campaign_unknown_is_never_auto_reconciled(self):
        manifest = dict(schema_version=1, campaign_id='campaign-a', recipe_id='windows-discovery-v1',
                        range_kit_sha256='1' * 64, targets=[{'asset_id': 'test-asset'}], executor={},
                        collectors=[], authorization={},
                        limits=dict(max_phase_seconds=10, max_campaign_seconds=60, max_export_bytes=1024,
                                    max_cloud_cost_usd=None, latest_cleanup_utc='2099-01-01T00:00:00+00:00'))
        stamp = '2026-01-01T00:00:00+00:00'
        campaign = dict(schema_version=1, campaign_id='campaign-a', experiment_id=self.eid, manifest=manifest,
                        manifest_sha256=digest_bytes(canonical_bytes(manifest)), status='draft',
                        cleanup_status='not_needed', owned_process=None, created_utc=stamp, updated_utc=stamp)
        self.store.create_campaign(campaign)
        state = self.store.update_campaign('campaign-a', dict(campaign, status='preflight_passed'),
                                           'draft', 'not_needed')
        auth = self.store.record_authorization(dict(
            approval_id='campaign-auth', experiment_id=self.eid, trial_id=None, campaign_id='campaign-a',
            by='test-human', note='Synthetic campaign; no lab action.', created_utc=stamp,
            expires_utc='2099-01-01T00:00:00+00:00', evidence_sha256=None, model_sha256s=[],
            manifest_sha256=campaign['manifest_sha256'], phases=['run']))
        self.store.update_campaign('campaign-a', dict(state, status='authorized'), 'preflight_passed', 'not_needed')
        spec = dict(schema_version=1, experiment_id=self.eid, manifest_sha256=campaign['manifest_sha256'],
                    authorization_sha256=auth, executor_sha256='1' * 64, input_sha256='1' * 64,
                    executor_version='synthetic-1', target_sha256='1' * 64, timeout_seconds=10)
        fingerprint = digest_bytes(canonical_bytes(spec))
        self.store.reserve_campaign_step('campaign-a', 'run', 'step-a', fingerprint, spec)
        self.store.finish_campaign_step('campaign-a', 'run', 'step-a', dict(
            schema_version=1, fingerprint=fingerprint, status='unknown', campaign_id='campaign-a', phase='run',
            step_id='step-a', executor_sha256='1' * 64, executor_version='synthetic-1',
            execution_outcome='unknown', start_utc=stamp, end_utc=stamp, elapsed_ms=1, exit_code=None,
            observed_target_sha256=None, effect_verified=False, evidence_sha256=None, failure_reason='timeout'))
        call_id, _ = self.uncertain('blocked')
        _, stub = self.stub_dispatch()
        with stub:
            result = advance(self.root, self.eid, True)
        # The model call in the same run is resolved; the lab step is not.
        self.assertEqual([item['call_id'] for item in result['auto_reconciled']], [call_id])
        snapshot = self.store.snapshot(self.eid)
        self.assertEqual([row['status'] for row in snapshot['campaigns']], ['unknown'])
        self.assertEqual([e['call_id'] for e in snapshot['events'] if e['kind'] == 'reconciliation_recorded'],
                         [call_id])
        self.assert_code('reserved_actor', self.store.reconcile_campaign_step, 'campaign-a', 'run', 'step-a',
                         'benchmark-auto-reconcile', 'n', {}, {})

    def test_bad_dag_is_rejected_before_state_creation(self):
        loaded = copy.deepcopy(self.loaded)
        loaded['workflow']['tasks'][2]['depends_on'] = ['scope', 'endpoint_evidence']
        target = Path(self.temp.name) / 'invalid-state'
        self.assert_code('invalid_workflow', initialize_experiment, target, loaded, TRUTH)
        self.assertFalse(target.exists())

    def test_init_freezes_truth_automatically_or_creates_nothing(self):
        snapshot = self.store.snapshot(self.eid)
        freezes = [e for e in snapshot['events'] if e['payload'].get('record_type') == 'truth_frozen']
        self.assertEqual(len(freezes), 1)
        self.assertEqual((freezes[0]['actor'], freezes[0]['payload']['freeze_policy']),
                         ('benchmark-auto-freeze', 'automatic_at_init'))
        # Frozen with the experiment, before any trial was sealed.
        first_trial = min(e['seq'] for e in snapshot['events'] if e['trial_id'] is not None)
        self.assertLess(freezes[0]['seq'], first_trial)
        self.assertTrue(self.initial['truth_frozen'])
        empty = Path(self.temp.name) / 'no-truth'
        empty.mkdir()
        target = Path(self.temp.name) / 'truthless-state'
        self.assert_code('file_not_found', initialize_experiment, target, copy.deepcopy(self.loaded), empty)
        self.assertFalse(target.exists())
        with self.assertRaises(SystemExit) as refused, contextlib.redirect_stderr(io.StringIO()):
            benchmark_main(['--state-root', str(target), 'init', '--experiment',
                            str(FIXTURES / 'examples' / 'experiment.json'), '--bundle-root', str(FIXTURES)])
        self.assertEqual(refused.exception.code, 2)
        self.assertFalse(target.exists())

    def test_execution_refuses_an_unfrozen_experiment(self):
        root = Path(self.temp.name) / 'unfrozen-state'
        store = BenchmarkStore(root, create=True)
        frozen = frozen_fixture()
        store.create_experiment(frozen)
        trial_fixture(store, frozen)
        eid = frozen['experiment']['experiment_id']
        self.assertFalse(advance(root, eid)['truth_frozen'])
        with patch('benchmark_runner._dispatch', side_effect=AssertionError('No dispatch permitted')):
            self.assert_code('truth_not_frozen', advance, root, eid, True)
        self.assertFalse((root / 'runner.lock').exists())


class _LoopbackFixture(http.server.BaseHTTPRequestHandler):
    """Disposable OpenAI-compatible loopback protocol fixture; no model inside."""

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers['Content-Length'])).decode('utf-8'))
        with self.server.lock:
            self.server.requests.append((self.path, body))
        if self.path != '/v1/chat/completions':
            self.send_error(404)
            return
        prompt = json.loads(body['messages'][-1]['content'])
        stage = prompt['stage']['key']
        with self.server.lock:
            delays, faults = self.server.delays.get(stage), self.server.faults.get(stage)
            delay = delays.pop(0) if delays else 0
            fault = faults.pop(0) if faults else None
        # A delayed reply outlives the caller's timeout; it is still sent, late,
        # to prove a resolved call never accepts it.
        time.sleep(delay)
        if fault == 'rejected_configuration':
            # The test-only child transport maps this status to the adapter's
            # configuration error, as a provider rejecting the configured route.
            self.send_error(418)
            return
        output = response_fixture(stage)
        output['summary'] = 'Labeled synthetic loopback fixture output; not a model result.'
        if stage == 'handoff':
            output['assessment_answers'] = [
                {'question_id': question['question_id'], 'probability_suspicious': None}
                for question in prompt['untrusted_public_evidence']['assessment_questions']]
        reply = json.dumps({
            'id': 'synthetic-fixture', 'object': 'chat.completion', 'model': body['model'],
            'choices': [{'index': 0, 'finish_reason': 'stop',
                         'message': {'role': 'assistant', 'content': ('Labeled synthetic invalid JSON {'
                                                                      if fault == 'invalid_json'
                                                                      else json.dumps(output))}}],
            'usage': {'prompt_tokens': 11, 'completion_tokens': 7, 'total_tokens': 18},
        }).encode('utf-8')
        try:
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(reply)))
            self.end_headers()
            self.wfile.write(reply)
        except OSError:
            if not delay:
                raise

    def log_message(self, *args):
        pass


# Test-only generic child: the real benchmark_runner/benchmark_models path with
# a standard-library loopback transport in place of the optional LangChain SDK.
CHILD = '''
import json, sys, urllib.error, urllib.request
sys.path.insert(0, {framework!r})
import langchain_adapter


class LoopbackResponse:
    tool_calls = []
    invalid_tool_calls = []

    def __init__(self, text, metadata, usage):
        self.text, self.response_metadata, self.usage_metadata = text, metadata, usage


def invoke_response(prompt, provider, model, base_url, request_timeout, *,
                    max_output_tokens=None, temperature=None, seed=None):
    if provider != 'openai' or not base_url.startswith('http://127.0.0.1:'):
        raise RuntimeError('loopback fixture only')
    body = json.dumps({{'model': model, 'max_tokens': max_output_tokens,
                       'messages': [{{'role': 'user', 'content': prompt}}]}}).encode('utf-8')
    request = urllib.request.Request(base_url.rstrip('/') + '/chat/completions', data=body,
                                     headers={{'Content-Type': 'application/json'}}, method='POST')
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({{}}))
    try:
        with opener.open(request, timeout=request_timeout) as reply:
            data = json.loads(reply.read().decode('utf-8'))
    except urllib.error.HTTPError as exc:
        if exc.code == 418:  # the fixture's labeled configuration rejection
            raise langchain_adapter.AdapterProblem('Labeled test-only configuration rejection.') from None
        raise
    choice, usage = data['choices'][0], data['usage']
    return LoopbackResponse(choice['message']['content'],
                            {{'model_name': data['model'], 'finish_reason': choice['finish_reason']}},
                            {{'input_tokens': usage['prompt_tokens'], 'output_tokens': usage['completion_tokens'],
                              'total_tokens': usage['total_tokens']}})


langchain_adapter.invoke_response = invoke_response
import benchmark_models
# The stdlib transport replaces the optional SDK, so its presence check does too.
benchmark_models.check_prerequisites = lambda provider: None
import benchmark_runner
sys.exit(benchmark_runner.child_main())
'''


class _LoopbackTeamCase(unittest.TestCase):
    """One seven-stage team over the loopback fixture; subclasses add tests."""

    MODEL = 'synthetic-loopback-fixture-1'

    def configure(self, experiment):
        """Hook: adjust the experiment before init."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), _LoopbackFixture)
        self.server.daemon_threads = True
        self.server.requests, self.server.lock = [], threading.Lock()
        self.server.delays, self.server.faults = {}, {}
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        port = self.server.server_address[1]
        self.root = (Path(self.temp.name) / 'state').resolve()
        loaded = load_experiment(FIXTURES / 'examples' / 'experiment.json', FIXTURES)
        loaded['cases'] = loaded['cases'][:1]
        experiment = loaded['experiment']
        experiment['scenario_refs'] = experiment['scenario_refs'][:1]
        experiment['teams'] = experiment['teams'][:1]
        # Two trials under the default concurrency (no max_concurrent_calls).
        experiment['repetitions'] = 2
        experiment['budgets'].pop('max_concurrent_calls', None)
        team = experiment['teams'][0]
        team['deployment'] = 'hybrid'
        for model in team['roles'].values():
            model.update(base_url='http://127.0.0.1:{}/v1'.format(port), model_requested=self.MODEL,
                         expected_model_ids=[self.MODEL])
        checker = copy.deepcopy(team['roles']['framework-coordinator'])
        checker.update(adapter='typesafe', provider='typesafe', model_requested='synthetic-checker-1',
                       expected_model_ids=['synthetic-checker-1'], max_output_tokens=None,
                       base_url='http://127.0.0.1:{}'.format(port))
        team['evidence_checker'] = checker
        experiment['budgets'].update(max_api_cost_usd=1, per_call_cost_bound_usd=0.01)
        experiment['pricing_snapshot']['rates'] = [
            {'provider': 'typesafe', 'model_requested': 'synthetic-checker-1',
             'input_per_million': 1, 'output_per_million': 1}]
        self.configure(experiment)
        self.eid = experiment['experiment_id']
        initialize_experiment(self.root, loaded, TRUTH)
        self.store = BenchmarkStore(self.root)
        self.trials = self.store.trials(self.eid)
        self.truth = TRUTH

    def execute(self):
        code, output = cli('--state-root', self.root, 'advance', '--experiment', self.eid,
                           '--allow-model-execution')
        self.assertEqual(code, 0, output)
        return json.loads(output)

    def chat_requests(self):
        return [body for path, body in self.server.requests if path == '/v1/chat/completions']

    @contextlib.contextmanager
    def injected_child(self):
        """The real dispatch chain with the stdlib loopback transport child.

        The stdlib transport replaces the optional SDK, so the route preflight's
        SDK check is replaced too, as in the child itself.
        """
        child = Path(self.temp.name) / 'loopback_child.py'
        child.write_text(CHILD.format(framework=str(HERE)), encoding='utf-8')
        original = benchmark_runner._source_identity

        def injected():
            identity, _, executable = original()
            return identity, child, executable

        with patch('benchmark_runner._source_identity', side_effect=injected), \
                patch('benchmark_runner._route_prerequisite', return_value=True):
            yield


class BenchmarkTeamSmokeTests(_LoopbackTeamCase):
    """Two seven-stage team trials, fully automatic: zero human commands."""

    def run_team(self):
        # Truth was frozen by automation inside init, before any trial existed.
        freezes = [e for e in self.store.snapshot(self.eid)['events']
                   if e['payload'].get('record_type') == 'truth_frozen']
        self.assertEqual([(e['actor'], e['payload']['freeze_policy']) for e in freezes],
                         [('benchmark-auto-freeze', 'automatic_at_init')])
        report = self.execute()
        self.assertEqual((report['status'], report['outcome']), ('finished', 'ok'))
        self.assertEqual((report['review_policy'], report['max_concurrent_calls'], report['timing_contended']),
                         ('auto_advance', 4, True))
        self.assertEqual(report['failures'], [])
        self.assertEqual(len(report['dispatched_calls']), 14)
        self.assertEqual(len(report['auto_advanced']), 14)
        self.assertEqual([trial['status'] for trial in report['trials']], ['completed', 'completed'])
        self.assertEqual({trial['status'] for trial in self.store.trials(self.eid)}, {'completed'})
        for item in report['trials']:
            self.assertTrue(all(stage['auto_advanced'] for stage in item['stages']))
            self.assertEqual(item['timing']['end_to_end_basis'], 'first_dispatch_to_final_auto_advance_utc')
            self.assertIsNotNone(item['timing']['end_to_end_wall_seconds'])
        for trial in self.trials:
            events = ledger_snapshot(self.store, trial)['events']
            advances = [e for e in events if e['kind'] == 'auto_advance']
            self.assertEqual(len(advances), 7)
            self.assertEqual({(e['actor'], e['note']) for e in advances}, {(AUTO_ADVANCE_ACTOR, AUTO_ADVANCE_NOTE)})
            self.assertEqual([e for e in events if e['kind'] in ('approve', 'reject')], [])
            # Dependent stages never overlap: every run starts after each
            # dependency's automatic advance.
            by_task = {task_id: stage for stage, task_id in trial['task_mapping'].items()}
            advanced_at = {by_task[e['task_id']]: e['id'] for e in advances}
            for e in events:
                if e['kind'] == 'run-started':
                    for dependency in DEPENDENCIES[by_task[e['task_id']]]:
                        self.assertLess(advanced_at[dependency], e['id'])
            # The checker appendix is registered before the ledger's automatic submit.
            analysis = [e for e in events if e['task_id'] == trial['task_mapping']['analysis']]
            registered = next(e['id'] for e in analysis
                              if e['kind'] == 'artifact' and e['note'].endswith('Benchmark evidence checker'))
            self.assertLess(registered, next(e['id'] for e in analysis if e['kind'] == 'submit'))
            self.assertEqual(stage_handoff(self.store, trial, 'analysis')['checker_output']['origin'], 'validator')
            shown = io.StringIO()
            with contextlib.closing(bot.connect(self.root / 'trials' / trial['trial_id'] / 'ledger')) as db, \
                    contextlib.redirect_stdout(shown):
                bot.workflow_status(db, trial['workflow_id'])
            self.assertEqual(shown.getvalue().count('auto-advanced (unreviewed)'), 7)
        calls = self.store.calls(experiment_id=self.eid)
        self.assertEqual(len(calls), 14)
        self.assertTrue(all(call['status'] == 'completed' for call in calls))
        keys = [(c['spec']['trial_id'], c['spec']['stage_key'], c['spec']['attempt_index'], c['spec']['component'])
                for c in calls]
        self.assertEqual(len(set(keys)), len(keys))
        self.assertEqual({call['spec']['role'] for call in calls}, set(STAGE_ROLES.values()))
        self.assertEqual({call['receipt']['identity_status'] for call in calls}, {'reported_match'})
        self.assertEqual(len(self.chat_requests()), 14)
        self.assertEqual([path for path, _ in self.server.requests if path != '/v1/chat/completions'], [])
        snapshot = self.store.snapshot(self.eid)
        kinds = [e['kind'] for e in snapshot['events']]
        reserved = [e['call_id'] for e in snapshot['events'] if e['kind'] == 'dispatch_reserved']
        self.assertEqual(sorted(reserved), sorted(call['call_id'] for call in calls))
        self.assertEqual(kinds.count('stage_auto_advanced'), 14)
        self.assertEqual(kinds.count('stage_submitted'), 14)
        self.assertNotIn('human_decision_observed', EVENT_KINDS)
        self.assertEqual({a['kind'] for a in snapshot['approvals']}, {'authorization'})
        self.assertEqual({e['actor'] for e in snapshot['events'] if e['kind'] == 'stage_auto_advanced'},
                         {AUTO_ADVANCE_ACTOR})
        # Nothing left: a second run neither dispatches nor advances.
        again = self.execute()
        self.assertEqual((again['status'], again['dispatched'], again['auto_advanced']), ('finished', False, []))
        # Mechanical scoring with no adjudication file, then diagnostics.
        code, output = cli('--state-root', self.root, 'score', '--experiment', self.eid, '--truth', self.truth)
        self.assertEqual(code, 0, output)
        scores = [e['payload']['score'] for e in self.store.snapshot(self.eid)['events']
                  if e['kind'] == 'score_recorded']
        self.assertEqual(len(scores), 2)
        # Mechanical verdicts are never labeled final/human; the frozen fixture key is attested.
        self.assertEqual({(s['variant'], s['adjudication'], s['status'], s['review_policy'], s['truth_attestation'])
                          for s in scores},
                         {('team_output', 'mechanical', 'mechanical', 'auto_advance', 'human_attested')})
        diagnosis = Path(self.temp.name) / 'diagnosis.json'
        code, output = cli('--state-root', self.root, 'diagnose', '--experiment', self.eid,
                           '--truth', self.truth, '--output', diagnosis)
        self.assertEqual(code, 0, output)
        self.assertTrue(diagnosis.is_file())
        destination = Path(self.temp.name) / 'export'
        code, _ = cli('--state-root', self.root, 'export', '--experiment', self.eid, '--output', destination)
        self.assertEqual(code, 0)
        exported = [json.loads(line) for line in (destination / 'calls.jsonl').read_text(encoding='utf-8').splitlines()]
        self.assertEqual({call['spec']['role'] for call in exported}, set(STAGE_ROLES.values()))
        exported_kinds = [json.loads(line)['kind']
                          for line in (destination / 'events.jsonl').read_text(encoding='utf-8').splitlines()]
        self.assertEqual(exported_kinds.count('stage_auto_advanced'), 14)
        for name in ('events.jsonl', 'campaigns.jsonl', 'scores.jsonl', 'coverage.csv', 'report.json', 'report.md'):
            self.assertTrue((destination / name).is_file(), name)

    def test_injected_stdlib_transport_runs_real_dispatch_chain(self):
        with self.injected_child():
            self.run_team()

    @unittest.skipIf(importlib.util.find_spec('langchain_openai') is None,
                     'optional LangChain OpenAI SDK not installed; the injected-transport '
                     'smoke covers the same dispatch chain')
    def test_optional_sdk_runs_real_dispatch_chain(self):
        self.run_team()

    def test_finished_state_directory_stays_valid_after_it_is_moved(self):
        with self.injected_child():
            self.assertEqual(self.execute()['status'], 'finished')
        moved = Path(self.temp.name) / 'relocated-state'
        shutil.move(str(self.root), str(moved))
        code, output = cli('--state-root', moved, 'status', '--experiment', self.eid)
        self.assertEqual(code, 0, output)
        report = json.loads(output)
        self.assertEqual(report['status'], 'finished')
        self.assertEqual([trial['status'] for trial in report['trials']], ['completed', 'completed'])
        store = BenchmarkStore(moved)
        for trial in store.trials(self.eid):
            self.assertEqual(stage_handoff(store, trial, 'handoff')['output']['stage_key'], 'handoff')
        code, output = cli('--state-root', moved, 'score', '--experiment', self.eid, '--truth', self.truth)
        self.assertEqual(code, 0, output)


class BenchmarkTeamTimeoutTests(_LoopbackTeamCase):
    """A stage's first call outlives its timeout; advance recovers with no human."""

    TIMEOUT = 2

    def configure(self, experiment):
        # endpoint_evidence is the only stage of the researcher role.
        experiment['teams'][0]['roles']['framework-researcher']['timeout_seconds'] = self.TIMEOUT
        self.server.delays['endpoint_evidence'] = [self.TIMEOUT + 3]

    def test_timed_out_call_is_reconciled_retried_and_exported_automatically(self):
        with self.injected_child():
            report = self.execute()  # exit 0: zero human commands
        self.assertEqual((report['status'], report['outcome'], report['failures']), ('finished', 'ok', []))
        self.assertEqual(len(report['dispatched_calls']), 15)
        self.assertEqual([(item['stage_key'], item['policy'], item['prior_failure_reason'], item['charged_seconds'])
                          for item in report['auto_reconciled']],
                         [('endpoint_evidence', 'automatic_model_call', 'timeout', self.TIMEOUT)])
        failed_id = report['auto_reconciled'][0]['call_id']
        trial = self.store.get_trial(report['auto_reconciled'][0]['trial_id'])
        stage = [c for c in self.store.calls(trial_id=trial['trial_id'])
                 if c['spec']['stage_key'] == 'endpoint_evidence']
        self.assertEqual(sorted((c['spec']['attempt_index'], c['status'], c['receipt']['failure_reason'],
                                 c['receipt']['elapsed_ms'] is None, c['call_id'] == failed_id) for c in stage),
                         [(1, 'failed', 'timeout', True, True), (2, 'completed', None, False, False)])
        self.assertEqual(len([body for body in self.chat_requests()
                              if json.loads(body['messages'][-1]['content'])['stage']['key']
                              == 'endpoint_evidence']), 3)
        # The ledger recovered through the distinct automated transition only.
        events = [e for e in ledger_snapshot(self.store, trial)['events']
                  if e['task_id'] == trial['task_mapping']['endpoint_evidence']]
        self.assertEqual([e['kind'] for e in events if e['kind'] in ('run-started', 'run-failed', 'auto_resume')],
                         ['run-started', 'run-failed', 'auto_resume', 'run-started'])
        self.assertEqual({e['actor'] for e in events if e['kind'] == 'auto_resume'}, {'benchmark-auto-reconcile'})
        self.assertFalse({'resume', 'recover-run', 'approve', 'reject'} & {e['kind'] for e in events})
        # Status shows each call's elapsed time against its timeout.
        calls = next(item for item in trial_report(status(self.root, self.eid), trial)['stages']
                     if item['stage_key'] == 'endpoint_evidence')['calls']
        self.assertEqual([(c['attempt_index'], c['elapsed_basis'], c['timeout_seconds'], c['charged_seconds'],
                           c['reconciliation_policy']) for c in calls][0],
                         (1, 'discarded_unknown_receipt', self.TIMEOUT, self.TIMEOUT, 'automatic_model_call'))
        self.assertGreaterEqual(calls[0]['elapsed_ms'], self.TIMEOUT * 1000)
        self.assertLessEqual(calls[0]['timeout_margin_ms'], 0)
        self.assertEqual(calls[1]['elapsed_basis'], 'receipt')
        self.assertGreater(calls[1]['timeout_margin_ms'], 0)
        # The export: automatic, charged worst case, and no human reconciliation.
        destination = Path(self.temp.name) / 'export'
        code, _ = cli('--state-root', self.root, 'export', '--experiment', self.eid, '--output', destination)
        self.assertEqual(code, 0)
        exported = [json.loads(line) for line in (destination / 'events.jsonl').read_text(encoding='utf-8').splitlines()]
        recorded = [e for e in exported if e['kind'] == 'reconciliation_recorded']
        self.assertEqual([(e['actor'], e['call_id'], e['payload']['policy'], e['payload']['outcome'],
                           e['payload']['charged_seconds'], e['payload']['timeout_seconds']) for e in recorded],
                         [('benchmark-auto-reconcile', failed_id, 'automatic_model_call', 'failed',
                           self.TIMEOUT, self.TIMEOUT)])
        exported_report = json.loads((destination / 'report.json').read_text(encoding='utf-8'))
        reconciliations = exported_report['reconciliations']
        self.assertEqual((reconciliations['automatic_model_call'], reconciliations['human_operator']), (1, 0))
        timeouts = exported_report['timeouts']
        self.assertEqual(timeouts['timed_out_calls'], 1)
        self.assertEqual([(item['call_id'], item['charged_seconds'], item['elapsed_basis'], item['reconciliation_policy'])
                          for item in timeouts['calls']],
                         [(failed_id, self.TIMEOUT, 'discarded_unknown_receipt', 'automatic_model_call')])
        self.assertIn('endpoint_evidence/narrative', timeouts['completed_margin_by_stage'])
        self.assertIn('1 automatic', (destination / 'report.md').read_text(encoding='utf-8'))


class BenchmarkTeamRetryTests(_LoopbackTeamCase):
    """Known model call failures: retried automatically, or ended when unfixable."""

    def stage_calls(self, trial, stage):
        return sorted((c for c in self.store.calls(trial_id=trial['trial_id']) if c['spec']['stage_key'] == stage),
                      key=lambda c: c['spec']['attempt_index'])

    def test_invalid_json_is_retried_to_completion_without_a_human(self):
        self.server.faults['network_evidence'] = ['invalid_json']
        with self.injected_child():
            report = self.execute()  # exit 0: zero human commands
        self.assertEqual((report['status'], report['outcome'], report['failures']), ('finished', 'ok', []))
        self.assertEqual((len(report['dispatched_calls']), report['auto_reconciled']), (15, []))
        self.assertEqual([(item['stage_key'], item['policy'], item['component'], item['failed_attempt_index'],
                           item['failure_reason']) for item in report['auto_retried']],
                         [('network_evidence', 'automatic_retry', 'narrative', 1, 'invalid_response')])
        trial = self.store.get_trial(report['auto_retried'][0]['trial_id'])
        first, second = self.stage_calls(trial, 'network_evidence')
        # Every attempt's receipt is kept, measured, and the first failure stays visible.
        self.assertEqual((first['status'], first['receipt']['failure_reason'], second['status']),
                         ('failed', 'invalid_response', 'completed'))
        self.assertIsNotNone(first['receipt']['elapsed_ms'])
        events = [e for e in ledger_snapshot(self.store, trial)['events']
                  if e['task_id'] == trial['task_mapping']['network_evidence']]
        self.assertEqual([(e['kind'], e['actor']) for e in events
                          if e['kind'] in ('run-failed', 'auto_resume')],
                         [('run-failed', 'operator'), ('auto_resume', 'benchmark-auto-retry')])
        self.assertFalse({'resume', 'recover-run', 'approve', 'reject'} & {e['kind'] for e in events})
        snapshot = self.store.snapshot(self.eid)
        retries = [e for e in snapshot['events'] if e['payload'].get('policy') == 'automatic_retry']
        self.assertEqual([(e['kind'], e['actor'], e['call_id'], e['payload']['failure_reason']) for e in retries],
                         [('trial_status_changed', 'benchmark-auto-retry', first['call_id'], 'invalid_response')])
        self.assertNotIn('reconciliation_recorded', [e['kind'] for e in snapshot['events']])
        destination = Path(self.temp.name) / 'export'
        code, _ = cli('--state-root', self.root, 'export', '--experiment', self.eid, '--output', destination)
        self.assertEqual(code, 0)
        exported = json.loads((destination / 'report.json').read_text(encoding='utf-8'))
        self.assertEqual(exported['automatic_retries']['count'], 1)
        self.assertEqual((exported['reconciliations']['automatic_model_call'],
                          exported['reconciliations']['human_operator']), (0, 0))
        # Format errors count every attempt, including the retried first one.
        self.assertEqual(exported['teams'][0]['measurements']['failure_reasons'], {'invalid_response': 1})
        # The rejected answer is an evaluator-only artifact with the validator's
        # reason, and no later prompt (retry or successor stage) ever carries it.
        rejected = first['receipt']['rejected_response']
        self.assertEqual((rejected['error_code'], rejected['error_field'], rejected['truncated']),
                         ('invalid_json', 'json', False))
        self.assertEqual(self.store.read_artifact(trial['trial_id'], rejected['artifact']),
                         b'Labeled synthetic invalid JSON {')
        self.assertEqual(len(self.chat_requests()), 15)
        self.assertFalse([body for body in self.chat_requests() if 'Labeled synthetic invalid JSON' in json.dumps(body)])
        self.assertEqual(exported['format_failures']['by_reason'],
                         [{'failure_reason': 'invalid_response', 'error_code': 'invalid_json',
                           'error_field': 'json', 'calls': 1}])
        self.assertEqual([item['rejected_response_artifact'] for item in exported['format_failures']['calls']],
                         [rejected['artifact']])
        self.assertIn('Format failures: 1', (destination / 'report.md').read_text(encoding='utf-8'))
        diagnosis = Path(self.temp.name) / 'diagnosis.json'
        code, output = cli('--state-root', self.root, 'diagnose', '--experiment', self.eid,
                           '--truth', self.truth, '--output', diagnosis)
        self.assertEqual(code, 0, output)
        report = json.loads(diagnosis.read_text(encoding='utf-8'))
        self.assertEqual([(row['role'], row['failure_reason'], row['error_code'], row['error_field'], row['calls'])
                          for row in report['aggregate']['format_failures_by_reason']],
                         [('framework-network-analyst', 'invalid_response', 'invalid_json', 'json', 1)])
        details = [error['detail'] for item in report['trials'] for error in item['errors']
                   if error['kind'] == 'format_failure']
        self.assertEqual([(d['error_code'], d['error_field'], d['rejected_response_artifact']) for d in details],
                         [('invalid_json', 'json', rejected['artifact'])])

    def test_configuration_failure_terminates_only_its_trial(self):
        self.server.faults['hypotheses'] = ['rejected_configuration']
        with self.injected_child():
            code, output = cli('--state-root', self.root, 'advance', '--experiment', self.eid,
                               '--allow-model-execution')
        report = json.loads(output)
        # The operator must fix the configuration: an honest failure exit, no retry.
        self.assertEqual((code, report['status'], report['outcome'], report['auto_retried']),
                         (1, 'finished', 'failed', []))
        self.assertEqual(len(report['terminated_trials']), 1)
        broken = self.store.get_trial(report['terminated_trials'][0])
        other = next(t for t in self.store.trials(self.eid) if t['trial_id'] != broken['trial_id'])
        self.assertEqual((broken['status'], broken['terminal_reason'], other['status']),
                         ('terminated', 'unrecoverable_stage', 'completed'))
        calls = self.stage_calls(broken, 'hypotheses')
        self.assertEqual([(c['spec']['attempt_index'], c['status'], c['receipt']['failure_reason']) for c in calls],
                         [(1, 'failed', 'configuration_invalid')])
        self.assertEqual([(item['trial_id'], item['state']) for item in report['failures']],
                         [(broken['trial_id'], 'failed')])
        terminated = [e for e in self.store.snapshot(self.eid)['events'] if e['kind'] == 'trial_terminated']
        self.assertEqual([(e['actor'], e['payload']['reason']) for e in terminated],
                         [('benchmark-runner', 'unrecoverable_stage')])
        self.assertIn('configuration_invalid', terminated[0]['payload']['note'])


# Drives init and a real execution from a snapshot: `advance -> bot.py run
# --adapter generic -> loopback child`, all loaded from the snapshot copy. An
# audit hook records every attempted open of a missing snapshot file.
SNAPSHOT_RUN = '''
import contextlib, io, json, os, sys
framework, state, bundle, manifest, child, experiment_id = sys.argv[1:7]
sys.path.insert(0, framework)
prefix = os.path.normcase(framework) + os.sep
missing = set()


def hook(event, args):
    if event == 'open' and isinstance(args[0], (str, bytes, os.PathLike)):
        path = os.path.abspath(os.fsdecode(args[0]))
        if (os.path.normcase(path).startswith(prefix) and '__pycache__' not in path
                and not os.path.exists(path)):  # bytecode-cache probes are optional
            missing.add(os.path.relpath(path, framework).replace(os.sep, '/'))


sys.addaudithook(hook)
import benchmark_runner
from benchmark import main
original = benchmark_runner._source_identity


def injected():
    identity, _, executable = original()
    return identity, child, executable


# The stdlib loopback child replaces the optional SDK, as in the team smoke.
benchmark_runner._source_identity = injected
benchmark_runner._route_prerequisite = lambda provider, env: True
outputs = []
for args in (['init', '--experiment', manifest, '--bundle-root', bundle,
              '--truth', os.path.join(bundle, 'fixtures')],
             ['advance', '--experiment', experiment_id, '--allow-model-execution']):
    captured = io.StringIO()
    with contextlib.redirect_stdout(captured):
        code = main(['--state-root', state] + args)
    outputs.append([code, captured.getvalue()])
print(json.dumps({'outputs': outputs, 'missing': sorted(missing), 'here': str(benchmark_runner.HERE)}))
'''


class SnapshotDispatchTests(unittest.TestCase):
    """Real stage dispatches from a `snapshot-source` copy; fixture output only."""

    MODEL = 'synthetic-loopback-fixture-1'

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), _LoopbackFixture)
        self.server.daemon_threads = True
        self.server.requests, self.server.lock = [], threading.Lock()
        self.server.delays, self.server.faults = {}, {}
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)

    def test_a_snapshot_runs_every_stage_through_real_ledger_dispatch(self):
        temp = Path(self.temp.name)
        framework = temp / 'snapshot' / 'framework'
        benchmark_runner.snapshot_source(temp / 'snapshot')
        bundle = temp / 'bundle'
        for name in ('examples', 'fixtures'):
            shutil.copytree(str(FIXTURES / name), str(bundle / name))
        experiment = load_json(bundle / 'examples' / 'experiment.json')
        experiment.update(repetitions=1, scenario_refs=experiment['scenario_refs'][:1],
                          teams=experiment['teams'][:1])
        for model in experiment['teams'][0]['roles'].values():
            model.update(base_url='http://127.0.0.1:{}/v1'.format(self.server.server_address[1]),
                         model_requested=self.MODEL, expected_model_ids=[self.MODEL])
        manifest = bundle / 'examples' / 'experiment-snapshot.json'
        manifest.write_bytes(canonical_bytes(experiment))
        child = temp / 'loopback_child.py'
        child.write_text(CHILD.format(framework=str(framework)), encoding='utf-8')
        environment = {key: value for key, value in os.environ.items() if key != 'PYTHONPATH'}
        result = subprocess.run([sys.executable, '-B', '-c', SNAPSHOT_RUN, str(framework), str(temp / 'state'),
                                 str(bundle), str(manifest), str(child), experiment['experiment_id']],
                                capture_output=True, text=True, cwd=str(temp), env=environment, timeout=900)
        self.assertEqual(result.returncode, 0, result.stderr)
        run = json.loads(result.stdout)
        self.assertEqual(Path(run['here']), framework.resolve())
        # No module, data file or role prompt was missing from the snapshot.
        self.assertEqual(run['missing'], [])
        (init_code, _), (code, output) = run['outputs']
        self.assertEqual((init_code, code), (0, 0), output)
        report = json.loads(output)
        self.assertEqual((report['status'], report['outcome'], report['failures']), ('finished', 'ok', []))
        self.assertEqual((len(report['dispatched_calls']), len(report['auto_advanced'])), (7, 7))
        self.assertEqual(len([path for path, _ in self.server.requests if path == '/v1/chat/completions']), 7)


if __name__ == '__main__':
    unittest.main()

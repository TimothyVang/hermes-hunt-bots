"""Invented higher-band data and offline consumer regressions; no model/lab calls."""
import copy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from benchmark import load_experiment
from benchmark_contracts import canonical_bytes, decode_json, digest_bytes, parse_utc
from benchmark_decisions import ledger_snapshot
from benchmark_difficulty import case_measurements, measure_case
from benchmark_runner import advance, build_prompt, initialize_experiment
from benchmark_scoring import edge_item_id, score_output
from benchmark_store import BenchmarkStore
from test_benchmark_fixtures_lower import (
    check_case_files, events, label_for, load_case, one, records, support_events,
)


ROOT = Path(__file__).resolve().parent / 'benchmarks'
CASES = ('case-9e44', 'case-af55', 'case-c070', 'case-e090')
MATCHES = {'case-c070': 'case-af55', 'case-e090': 'case-9e44'}


def timestamp(value):
    return parse_utc(value, 'timestamp_utc')


def handoff(public, truth, findings=None):
    eligible = [s for s in truth['steps'] if s['observability'] == 'sufficient']
    output = {
        'schema_version': 1, 'stage_key': 'handoff',
        'summary': 'Invented offline scoring oracle, not a model result.',
        'claims': [], 'findings': [], 'hypotheses': [], 'gaps': [],
        'limitations': ['Synthetic fixture only.'], 'requested_decision': 'approve',
        'chain_edges': [],
        'assessment_answers': [
            {'question_id': q['question_id'],
             'probability_suspicious': truth['assessment_labels'][q['question_id']]}
            for q in public['assessment_questions']],
    }
    if findings is not None:
        output['findings'] = findings
        return output
    for step in eligible:
        output['findings'].append({
            'finding_id': 'finding-' + step['step_id'], 'asset_id': step['asset_id'],
            'technique_id': step['technique_id'], 'window_utc': copy.deepcopy(step['window_utc']),
            'disposition': 'suspicious', 'confidence': 1,
            'event_ids': step['support_sets'][0],
            'rationale': 'Synthetic assertion supported by the full linked record set.',
        })
    ids = {step['step_id'] for step in eligible}
    output['chain_edges'] = [['finding-' + a, 'finding-' + b]
                             for a, b in truth['edges'] if a in ids and b in ids]
    return output


def score(public, truth, output, verdict='supported'):
    sha = digest_bytes(canonical_bytes(output))
    verdicts = []
    findings = {item['finding_id']: item for item in output['findings']}
    edge_evidence = [(edge_item_id(edge), sorted({
        event_id for endpoint in edge for event_id in findings[endpoint]['event_ids']}))
        for edge in output['chain_edges']]
    for kind, items in (
            ('finding', [(f['finding_id'], f['event_ids']) for f in output['findings']]),
            ('edge', edge_evidence)):
        for item_id, event_ids in items:
            verdicts.append({
                'trial_id': 'trial-fixture', 'output_sha256': sha,
                'item_kind': kind, 'item_id': item_id, 'verdict': verdict,
                'event_ids': event_ids, 'by': 'offline-test-reviewer',
                'note': 'Deterministic invented oracle, not actual human adjudication.',
            })
    return score_output(output, truth, public, verdicts,
                        trial_id='trial-fixture', output_sha256=sha)


def counts(result, key):
    return [result[key][k] for k in ('tp', 'fp', 'fn')]


class HigherFixtureDataTests(unittest.TestCase):
    def test_exact_schemas_digests_locators_and_question_scopes(self):
        for case_id in CASES:
            with self.subTest(case=case_id):
                check_case_files(self, case_id)

    def test_evidence_derived_difficulty_not_band_labels(self):
        expected = {
            'case-9e44': (147, 5, 2, 5400, True, True, 0, 1, [1, 1, 2, 1, 1], 'D4'),
            'case-af55': (650, 5, 4, 7800, True, True, 1, 2, [2, 2, 2, 2, 2], 'D5'),
        }
        keys = ('benign_events', 'relevant_events', 'required_joins', 'correlation_seconds',
                'missing_records', 'alternative_complete', 'unresolvable_questions', 'benign_lookalikes')
        for case_id, facts in expected.items():
            with self.subTest(case=case_id):
                scenario, public, truth = load_case(case_id)
                measured = case_measurements(public, records(case_id), truth)
                self.assertEqual([measured[k] for k in keys], list(facts[:8]))
                # Ratios sit well inside their noise bands, not one record over a threshold.
                ratio = measured['benign_events'] / measured['relevant_events']
                self.assertTrue(20 <= ratio <= 50 or ratio >= 125, ratio)
                difficulty = measure_case(public, records(case_id), truth)
                self.assertEqual(difficulty, scenario['difficulty'])
                self.assertEqual([difficulty['factors'][k]['score'] for k in
                                  ('noise', 'joins', 'time_span', 'gaps', 'ambiguity')], facts[8])
                self.assertEqual(difficulty['band'], facts[9])

    def test_controls_inherit_family_and_share_its_layout(self):
        for case_id, matched in MATCHES.items():
            with self.subTest(case=case_id):
                scenario, public, truth = load_case(case_id)
                parent, parent_public, _ = load_case(matched)
                self.assertEqual(scenario['family_id'], parent['family_id'])
                self.assertEqual(truth['steps'], [])
                self.assertEqual(truth['edges'], [])
                self.assertEqual(scenario['sophistication']['steps'], [])
                self.assertEqual(scenario['sophistication']['band'], 'S0')
                self.assertEqual(scenario['difficulty'], measure_case(
                    public, records(case_id), truth, {'matched_control': parent['difficulty']}))
                self.assertNotIn(1, truth['assessment_labels'].values())
                self.assertEqual(public['window_utc'], parent_public['window_utc'])
                self.assertEqual(sorted((s['telemetry'], s['completeness']) for s in public['sources']),
                                 sorted((s['telemetry'], s['completeness']) for s in parent_public['sources']))
                self.assertEqual([g['reason'] for g in public['known_gaps']],
                                 [g['reason'] for g in parent_public['known_gaps']])
                self.assertEqual(sorted(a['os_family'] for a in public['assets']),
                                 sorted(a['os_family'] for a in parent_public['assets']))

    def test_cross_domain_reentry_links_contexts_with_alternative_support(self):
        scenario, public, truth = load_case('case-9e44')
        rows = events(public)
        opened, logon = sorted(support_events(public, truth, 'step-a'), key=lambda e: e['timestamp_utc'])
        register = one(support_events(public, truth, 'step-b'), event_type='scheduled_task_registered')
        step_c = next(step for step in truth['steps'] if step['step_id'] == 'step-c')
        self.assertEqual(len(step_c['support_sets']), 2)
        first, second = [set(support) for support in step_c['support_sets']]
        (start,) = [rows[eid] for eid in first - second]
        (start_sec,) = [rows[eid] for eid in second - first]
        self.assertEqual(first & second, {opened['event_id'], logon['event_id'], register['event_id']})
        # The cross-forest crossing is evidenced in the step-a records it is attributed to.
        self.assertNotEqual(opened['fields']['origin_domain'], opened['fields']['destination_domain'])
        self.assertEqual(opened['fields']['destination_asset'], logon['asset_id'])
        self.assertEqual(logon['fields']['origin_asset'], opened['asset_id'])
        self.assertEqual(logon['fields']['account_domain'], opened['fields']['origin_domain'])
        self.assertEqual(opened['fields']['session_ref'], logon['fields']['session_ref'])
        self.assertEqual(logon['fields']['session_ref'], register['fields']['session_ref'])
        self.assertEqual(register['fields']['task_ref'], start['fields']['task_ref'])
        self.assertEqual(start['fields']['process_id'], start_sec['fields']['process_id'])
        self.assertEqual(start['fields']['account_ref'], start_sec['fields']['account_ref'])
        self.assertNotEqual(start['source_id'], start_sec['source_id'])
        self.assertLess(timestamp(register['timestamp_utc']), timestamp(start['timestamp_utc']))
        steps = {step['step_id']: step for step in truth['steps']}
        self.assertEqual(steps['step-a']['asset_id'], opened['asset_id'])
        self.assertEqual({steps['step-b']['asset_id'], steps['step-c']['asset_id']}, {logon['asset_id']})
        boundaries = {b['boundary_id']: b['kind'] for b in scenario['sophistication']['boundaries']}
        kinds = {s['step_id']: boundaries[s['boundary_id']] for s in scenario['sophistication']['steps']}
        self.assertEqual(kinds, {'step-a': 'domain', 'step-b': 'identity', 'step-c': 'identity'})
        self.assertEqual({s['phase'] for s in scenario['sophistication']['steps']},
                         {'initial', 'persistence', 'reentry'})
        self.assertEqual(truth['edges'], scenario['sophistication']['edges'])
        # The endpoint sensor gap removed records, not the alternative security-log path.
        (gap,) = public['known_gaps']
        sensor = next(s for s in public['sources'] if s['source_id'] == gap['source_id'])
        self.assertEqual((sensor['completeness'], gap['asset_id']), ('partial', logon['asset_id']))
        low, high = timestamp(gap['window_utc']['start_inclusive']), timestamp(gap['window_utc']['end_exclusive'])
        self.assertFalse(any(e['source_id'] == gap['source_id'] and e['asset_id'] == gap['asset_id']
                             and low <= timestamp(e['timestamp_utc']) < high for e in public['events']))
        self.assertTrue(low <= timestamp(register['timestamp_utc']) < high)
        # Cross-domain trust DNS is backed by an actual conditional-forwarder record.
        forward = one(public['events'], event_type='dns_query', resolution='conditional-forwarder')
        self.assertEqual(forward['fields']['forwarder_zone'], opened['fields']['destination_domain'])
        result = score(public, truth, handoff(public, truth))
        self.assertEqual(counts(result, 'detection'), [3, 0, 0])
        self.assertEqual(counts(result, 'chain_edges'), [2, 0, 0])
        output = handoff(public, truth)
        output['findings'][2]['event_ids'] = step_c['support_sets'][1]
        self.assertEqual(counts(score(public, truth, output), 'detection'), [3, 0, 0])

    def test_step_windows_are_the_steps_own_record_times(self):
        for case_id in ('case-9e44', 'case-af55'):
            with self.subTest(case=case_id):
                _, public, truth = load_case(case_id)
                output = handoff(public, truth)
                for finding in output['findings']:
                    finding['window_utc'] = {'start_inclusive': public['window_utc']['start_inclusive'],
                                             'end_exclusive': public['window_utc']['start_inclusive'][:-6]
                                             + '00:01Z'}
                result = score(public, truth, output)
                self.assertEqual(result['detection']['tp'], 0)

    def test_hybrid_joins_cloud_os_and_true_missing_resource_visibility(self):
        scenario, public, truth = load_case('case-af55')
        steps = {step['step_id']: step for step in truth['steps']}
        full = support_events(public, truth, 'step-e')
        opened = one(full, event_type='remote_session_open')
        register = one(full, event_type='scheduled_task_registered')
        start = one(full, event_type='scheduled_task_started')
        signin = one(full, event_type='federation_session_accepted')
        bind = one(full, event_type='role_binding_created')
        self.assertEqual(opened['fields']['session_ref'], register['fields']['session_ref'])
        self.assertEqual(register['fields']['task_ref'], start['fields']['task_ref'])
        self.assertEqual(start['fields']['process_ref'], signin['fields']['process_ref'])
        self.assertEqual(signin['fields']['origin_asset'], start['asset_id'])
        self.assertEqual(signin['fields']['session_ref'], bind['fields']['session_ref'])
        self.assertEqual([r['timestamp_utc'] for r in (opened, register, start, signin, bind)],
                         sorted(r['timestamp_utc'] for r in (opened, register, start, signin, bind)))
        # Attribution: the sign-in executes on its initiating host; the binding in the tenant.
        self.assertEqual(steps['step-d']['asset_id'], start['asset_id'])
        self.assertEqual(steps['step-e']['asset_id'], bind['asset_id'])
        cloud_assets = {aid for source in public['sources'] if source['telemetry'] == 'cloud-audit'
                        for aid in source['asset_ids']}
        self.assertEqual(len(cloud_assets), 2)
        for asset in public['assets']:
            if asset['asset_id'] in cloud_assets:
                self.assertEqual(asset['os_family'], 'not-applicable')
                self.assertIsNone(asset['os_version'])
                self.assertIsNone(asset['architecture'])
        self.assertEqual({b['kind'] for b in scenario['sophistication']['boundaries']},
                         {'domain', 'identity', 'on-prem', 'cloud', 'privilege'})
        self.assertIn('https://attack.mitre.org/techniques/T1098/001/', scenario['source_references'])
        (gap,) = public['known_gaps']
        self.assertEqual(bind['fields']['scope_asset'], gap['asset_id'])
        self.assertFalse(any(r['asset_id'] == gap['asset_id'] for r in public['events']))
        self.assertIsNone(label_for(public, truth, gap['asset_id']))
        absent = next(s for s in truth['steps'] if s['asset_id'] == gap['asset_id'])
        self.assertEqual((absent['observability'], absent['execution_outcome'], absent['support_sets']),
                         ('absent', 'unknown', []))
        # Routine records interleave with the attack on the same assets, before, during and after it.
        relevant = {e['event_id'] for e in full}
        for anchor in (start, bind):
            same = [timestamp(e['timestamp_utc']) for e in public['events']
                    if e['asset_id'] == anchor['asset_id'] and e['event_id'] not in relevant]
            moment = timestamp(anchor['timestamp_utc'])
            self.assertTrue(any(t < moment for t in same) and any(t > moment for t in same))
        between = [e for e in public['events'] if e['event_id'] not in relevant
                   and timestamp(start['timestamp_utc']) < timestamp(e['timestamp_utc']) < timestamp(bind['timestamp_utc'])]
        self.assertGreater(len(between), 5)
        # Split-horizon DNS is backed by internal and external views of actual queries.
        views = {e['fields'].get('view') for e in public['events'] if e['event_type'] == 'dns_query'}
        self.assertEqual(views, {'internal', 'external'})
        output = handoff(public, truth)
        result = score(public, truth, output)
        self.assertEqual(counts(result, 'detection'), [5, 0, 0])
        self.assertEqual(counts(result, 'chain_edges'), [4, 0, 0])
        self.assertEqual(result['calibration']['undecidable_questions'], 1)
        # Removing the federation bridge breaks the required four-context support,
        # even if a human supports the remaining local assertion.
        output['findings'][-1]['event_ids'] = [e['event_id'] for e in full if e is not signin]
        broken = score(public, truth, output)
        self.assertEqual(counts(broken, 'detection'), [4, 1, 1])

    def test_insufficient_control_needs_explicit_supported_abstention(self):
        _, public, truth = load_case('case-c070')
        (gap,) = public['known_gaps']
        output = handoff(public, truth, [])
        silent = score(public, truth, output)
        self.assertEqual(silent['controls']['insufficient']['correct_dispositions'], 0)
        self.assertIsNone(silent['detection']['recall'])
        self.assertEqual(silent['calibration']['undecidable_questions'], 1)
        self.assertEqual(silent['calibration']['eligible_questions'], 3)
        output['findings'] = [{
            'finding_id': 'finding-gap', 'asset_id': gap['asset_id'], 'technique_id': None,
            'window_utc': public['window_utc'], 'disposition': 'insufficient',
            'confidence': None, 'event_ids': [],
            'rationale': 'The resource audit source is absent for the complete question window.',
        }]
        explicit = score(public, truth, output)
        self.assertEqual(explicit['controls']['insufficient']['correct_dispositions'], 1)
        unsupported = score(public, truth, output, verdict='insufficient')
        self.assertEqual(unsupported['controls']['insufficient']['correct_dispositions'], 0)
        output['findings'][0].update(disposition='suspicious', technique_id='T1098.001')
        alarm = score(public, truth, output)
        self.assertEqual(counts(alarm, 'detection'), [0, 1, 0])
        self.assertFalse(alarm['ranking_eligible'])

    def test_instruction_text_is_not_host_compromise_ground_truth(self):
        _, public, truth = load_case('case-e090')
        annotation = next(e for e in public['events'] if e['event_type'] == 'application_annotation')
        self.assertEqual(annotation['fields']['annotation_origin'], 'untrusted-client-text')
        output = handoff(public, truth, [{
            'finding_id': 'finding-note', 'asset_id': annotation['asset_id'],
            'technique_id': 'T1059', 'window_utc': public['window_utc'],
            'disposition': 'suspicious', 'confidence': 1,
            'event_ids': [annotation['event_id']],
            'rationale': 'Deliberately incorrect synthetic assertion of executed instructions.',
        }])
        result = score(public, truth, output, verdict='contradicted')
        self.assertEqual(counts(result, 'detection'), [0, 1, 0])
        self.assertEqual(result['controls']['benign']['false_alarms'], 1)
        self.assertEqual(result['calibration']['eligible_questions'], 3)


class HigherFixturePromptTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.state = Path(self.temp.name) / 'state'
        loaded = load_experiment(ROOT / 'examples' / 'experiment.json', ROOT)
        loaded['experiment']['repetitions'] = 1
        loaded['experiment']['teams'] = loaded['experiment']['teams'][:1]
        loaded['experiment']['budgets']['max_prompt_bytes'] = 1048576
        loaded['cases'] = []
        loaded['experiment']['scenario_refs'] = []
        for case_id in CASES:
            scenario, public, _ = load_case(case_id)
            relative = 'fixtures/' + case_id
            reference = {'scenario': relative + '/scenario.json',
                         'evidence': relative + '/public/evidence.json'}
            loaded['cases'].append({
                'scenario': scenario, 'evidence': public,
                'scenario_path': ROOT / reference['scenario'],
                'evidence_path': ROOT / reference['evidence'], 'reference': reference,
            })
            loaded['experiment']['scenario_refs'].append(reference)
        initialize_experiment(self.state, loaded, ROOT / 'fixtures')
        self.store = BenchmarkStore(self.state)
        self.eid = loaded['experiment']['experiment_id']
        self.trials = {t['case_id']: t for t in self.store.trials(self.eid)}

    def test_public_prompt_budget_includes_records_and_six_predecessor_allowance(self):
        frozen = self.store.get_experiment(self.eid)
        response_cap = frozen['experiment']['budgets']['max_response_bytes']
        for case_id, trial in self.trials.items():
            with self.subTest(case=case_id):
                raw = build_prompt(self.store, trial, 'scope')
                prompt = decode_json(raw)
                _, public, _ = load_case(case_id)
                self.assertEqual(prompt['untrusted_public_evidence']['events'], public['events'])
                self.assertEqual(prompt['untrusted_public_evidence']['files'][0]['content'],
                                 (ROOT / 'fixtures' / case_id / 'public' / 'records.jsonl').read_text(encoding='utf-8'))
                # Structured predecessor JSON is embedded as JSON, not escaped a
                # second time; reserve each maximum output plus envelope overhead.
                self.assertLess(len(raw) + 6 * (response_cap + 1024), 1048576)
                self.assertEqual(prompt['untrusted_immediate_predecessors'], [])
                self.assertNotIn('difficulty', prompt['untrusted_public_evidence'])
                self.assertNotIn('sophistication', prompt['untrusted_public_evidence'])
                self.assertNotIn('assessment_labels', raw.decode('utf-8'))
                self.assertNotIn('source_receipt_sha256', raw.decode('utf-8'))

    def test_log_instruction_stays_untrusted_and_cannot_approve_or_dispatch(self):
        trial = self.trials['case-e090']
        _, public, _ = load_case('case-e090')
        annotation = next(e for e in public['events'] if e['event_type'] == 'application_annotation')
        instruction = annotation['fields']['user_supplied_label']
        before = self.store.snapshot(self.eid)
        with patch('benchmark_runner.subprocess.run', side_effect=AssertionError('No execution allowed')):
            prompt = decode_json(build_prompt(self.store, trial, 'scope'))
            dryrun = advance(self.state, self.eid)
        self.assertEqual(before, self.store.snapshot(self.eid))
        self.assertFalse(dryrun['dispatched'])
        self.assertEqual(self.store.calls(experiment_id=self.eid), [])
        self.assertEqual(self.store.snapshot(self.eid)['approvals'], [])
        self.assertEqual({t['status'] for t in ledger_snapshot(self.store, trial)['tasks'].values()},
                         {'pending'})
        rendered_annotation = next(e for e in prompt['untrusted_public_evidence']['events']
                                   if e['event_id'] == annotation['event_id'])
        self.assertEqual(rendered_annotation['fields']['user_supplied_label'], instruction)
        self.assertIn(instruction, prompt['untrusted_public_evidence']['files'][0]['content'])
        self.assertNotIn(instruction, canonical_bytes({
            k: v for k, v in prompt.items() if k != 'untrusted_public_evidence'}).decode('utf-8'))
        baseline = decode_json(build_prompt(self.store, self.trials['case-9e44'], 'scope'))
        for key in ('prompt_contract', 'role_purpose', 'stage'):
            self.assertEqual(prompt[key], baseline[key])
        # The actual public artifacts copied to the trial contain only the one
        # approved record file; evaluator metadata is not a hunter input.
        self.assertEqual(set(trial['public_artifacts']), {'records.jsonl'})


if __name__ == '__main__':
    unittest.main()

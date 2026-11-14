"""Offline contract tests; no provider, SDK, workspace initialization or lab."""
import copy
from datetime import timedelta
import os
import random
import re
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import benchmark_contracts as contracts


HASH = 'a' * 64
WINDOW = {'start_inclusive': '2026-01-01T00:00:00Z',
          'end_exclusive': '2026-01-01T00:05:00+00:00'}


def coverage():
    axes = {key: list(values) for key, values in contracts.COVERAGE_AXES.items()}
    # Validator unit data only, not an authored coverage/support claim.
    return {'schema_version': 1, 'catalog_version': 'unit-test', 'axes': axes,
            'rows': [{'row_id': 'row-1', 'coverage': copy.deepcopy(axes),
                      'owner': 'test', 'prerequisites': ['invented test data'],
                      'status': 'planned', 'reason': 'validator unit test',
                      'evidence_references': []}]}


def scenario():
    return {'schema_version': 1, 'scenario_id': 's1', 'family_id': 'f1',
            'revision': 1, 'split': 'development', 'provenance': 'synthetic',
            'coverage': {key: [values[0]] for key, values in contracts.COVERAGE_AXES.items()},
            'difficulty': {'band': 'D1', 'control': False, 'factors': {
                key: {'score': 0, 'rationale': 'unit test'}
                for key in ('noise', 'joins', 'time_span', 'gaps', 'ambiguity')}},
            'sophistication': {'band': 'S1',
                'steps': [{'step_id': 't1', 'asset_id': 'a1',
                           'boundary_id': 'b1', 'phase': 'initial'}],
                'edges': [], 'preconditions': [],
                'boundaries': [{'boundary_id': 'b1', 'kind': 'host'}],
                'emulation_limitations': ['invented'], 'group_ids': [],
                'source_references': []},
            'attack_release': 'v20', 'source_references': [],
            'evidence_manifest_sha256': HASH}


def public_bundle():
    return {'schema_version': 1, 'case_id': 'case-00c1', 'window_utc': copy.deepcopy(WINDOW),
            'assets': [{'asset_id': 'a1', 'os_family': 'windows-client',
                        'os_version': None, 'architecture': None, 'vendor': None}],
            'sources': [{'source_id': 'src1', 'asset_ids': ['a1'],
                         'telemetry': 'sysmon', 'clock_offset_seconds': 0,
                         'clock_uncertainty_seconds': 1,
                         'window_utc': copy.deepcopy(WINDOW),
                         'sensor_version': None, 'config_version': None,
                         'completeness': 'complete', 'source_sha256': HASH}],
            'events': [{'event_id': 'e1', 'timestamp_utc': '2026-01-01T00:01:00Z',
                        'source_id': 'src1', 'asset_id': 'a1',
                        'event_type': 'process',
                        'fields': {'timestamp_original': '2026-01-01T00:01:00Z',
                                   'process_name': 'hostname.exe'},
                        'locator': {'file_sha256': contracts.digest_bytes(b'event\n'),
                                    'record_id': '1'}}],
            'known_gaps': [], 'files': [{'path': 'events.jsonl', 'byte_count': 6,
                                       'sha256': contracts.digest_bytes(b'event\n')}],
            'assessment_questions': [{'question_id': 'q1', 'asset_id': 'a1',
                                      'window_utc': copy.deepcopy(WINDOW),
                                      'question': contracts.ASSESSMENT_QUESTION}]}


def truth(bundle=None):
    bundle = public_bundle() if bundle is None else bundle
    return {'schema_version': 1, 'case_id': bundle['case_id'],
            'evidence_manifest_sha256': contracts.digest_bytes(contracts.canonical_bytes(bundle)),
            'truth_revision': 1, 'attack_release': 'v20',
            'steps': [{'step_id': 't1', 'technique_id': 'T1033', 'asset_id': 'a1',
                       'window_utc': copy.deepcopy(WINDOW),
                       'execution_outcome': 'blocked', 'observability': 'sufficient',
                       'support_sets': [['e1']], 'source_receipt_sha256': HASH}],
            'edges': [], 'controls': [], 'assessment_labels': {'q1': 1}}


def model(checker=False):
    return {'adapter': 'typesafe' if checker else 'langchain',
            'provider': 'typesafe' if checker else 'openai',
            'model_requested': 'invented-version-1',
            'base_url': 'http://127.0.0.1:1' if checker else 'http://127.0.0.1:1/v1', 'credential_env': None,
            'parameters': {'temperature': None, 'seed': None},
            'timeout_seconds': 10, 'max_output_tokens': None if checker else 128,
            'expected_model_ids': ['invented-version-1']}


def team():
    return {'team_id': 'team1', 'deployment': 'local',
            'roles': {role: model() for role in contracts.ROLE_IDS},
            'runtime_facts': {key: None for key in (
                'server', 'server_version', 'model_weight_sha256', 'quantization',
                'context_configuration', 'cpu', 'gpu', 'ram_bytes', 'concurrency')}}


def experiment():
    return {'schema_version': 1, 'experiment_id': 'exp1',
            'scenario_refs': [{'scenario': 'cases/c1/scenario.json',
                               'evidence': 'cases/c1/public.json'}],
            'teams': [team()], 'repetitions': 5, 'schedule_seed': 1729,
            'budgets': {'max_calls_per_trial': 14, 'max_active_seconds_per_trial': 120,
                        'max_prompt_bytes': 4096, 'max_response_bytes': 4096,
                        'max_attempts_per_stage': 2},
            'workflow_sha256': HASH, 'prompt_contract_sha256': HASH,
            'coverage_sha256': HASH, 'rubric_version': 'hunt-rubric-1',
            'pricing_snapshot': {'as_of_utc': '2026-01-01T00:00:00Z',
                                 'currency': 'USD', 'rates': []}}


def stage(handoff=False):
    value = {'schema_version': 1, 'stage_key': 'handoff' if handoff else 'analysis',
             'summary': 'Invented validator test output.',
             'claims': [{'claim_id': 'claim1', 'kind': 'observation',
                         'text': 'An event exists.', 'event_ids': ['e1']}],
             'findings': [{'finding_id': 'finding1', 'asset_id': 'a1',
                           'technique_id': 'T1033', 'window_utc': copy.deepcopy(WINDOW),
                           'disposition': 'suspicious', 'confidence': 0.5,
                           'event_ids': ['e1'], 'rationale': 'Invented assertion.'}],
             'hypotheses': [], 'gaps': [], 'limitations': [],
             'requested_decision': 'approve'}
    if handoff:
        value.update(chain_edges=[], assessment_answers=[
            {'question_id': 'q1', 'probability_suspicious': None}])
    return value


class JsonContractsTests(unittest.TestCase):
    def test_canonical_encoding_and_digest(self):
        self.assertEqual(contracts.canonical_bytes({'z': 1, 'a': 'é'}),
                         '{"a":"é","z":1}'.encode('utf-8'))
        self.assertEqual(contracts.digest_bytes(b''),
                         'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
        self.assertEqual(contracts.decode_json(b'{"x":[1,null,true]}'), {'x': [1, None, True]})

    def test_reject_duplicate_nonfinite_and_invalid_json(self):
        for data in ('{"x":1,"x":2}', '{"a":{"x":1,"x":2}}',
                     'NaN', 'Infinity', '-Infinity', '1e9999', '{',
                     '"\\ud800"', b'\xff', '{"a": 1} trailing'):
            with self.subTest(data=repr(data)), self.assertRaises(contracts.BenchmarkError):
                contracts.decode_json(data)
        for data in ({'x': float('nan')}, {1: 'non-string-key'}, ('tuple',),
                     {'x': object()}, '\ud800'):
            with self.assertRaises(contracts.BenchmarkError):
                contracts.canonical_bytes(data)

    def test_errors_do_not_echo_values_or_unknown_keys(self):
        data = experiment()
        data['SECRET_CREDENTIAL_VALUE'] = 'NEVER_ECHO'
        with self.assertRaises(contracts.BenchmarkError) as caught:
            contracts.validate_experiment(data)
        self.assertEqual(str(caught.exception), 'unknown_field: experiment')
        self.assertEqual(caught.exception.code, 'unknown_field')
        self.assertEqual(caught.exception.field, 'experiment')
        with self.assertRaises(contracts.BenchmarkError) as caught:
            contracts.decode_json('{"SECRET_VALUE":1,"SECRET_VALUE":2}')
        self.assertNotIn('SECRET_VALUE', str(caught.exception))

    def test_load_json_only_objects_and_safe_file_errors(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'data.json'
            path.write_text('[]', encoding='utf-8')
            with self.assertRaises(contracts.BenchmarkError):
                contracts.load_json(path)
            path.write_text('{"schema_version":1}', encoding='utf-8')
            self.assertEqual(contracts.load_json(path), {'schema_version': 1})
            with self.assertRaises(contracts.BenchmarkError) as caught:
                contracts.load_json(Path(directory) / 'SECRET_PATH')
            self.assertNotIn('SECRET_PATH', str(caught.exception))


class ManifestContractsTests(unittest.TestCase):
    def test_valid_inputs_return_original_objects(self):
        catalog, case, public, answer, config, output = coverage(), scenario(), public_bundle(), truth(), experiment(), stage(True)
        self.assertIs(contracts.validate_coverage(catalog), catalog)
        self.assertIs(contracts.validate_scenario(case, catalog), case)
        self.assertIs(contracts.validate_public_bundle(public), public)
        self.assertIs(contracts.validate_truth(answer, public), answer)
        self.assertIs(contracts.validate_experiment(config), config)
        self.assertIs(contracts.validate_team(config['teams'][0]), config['teams'][0])
        self.assertIs(contracts.validate_stage_output(output, 'handoff', public), output)

    def test_unknown_fields_and_boolean_versions_rejected(self):
        cases = [(coverage, contracts.validate_coverage),
                 (public_bundle, contracts.validate_public_bundle),
                 (truth, contracts.validate_truth),
                 (experiment, contracts.validate_experiment),
                 (stage, contracts.validate_stage_output)]
        for factory, validator in cases:
            with self.subTest(factory=factory.__name__):
                data = factory()
                data['schema_version'] = True
                with self.assertRaises(contracts.BenchmarkError):
                    validator(data)
                data = factory()
                data['unexpected'] = 1
                with self.assertRaises(contracts.BenchmarkError):
                    validator(data)

    def test_coverage_taxonomy_and_denominators(self):
        data = coverage()
        data['axes']['os'].append('made-up-os')
        with self.assertRaises(contracts.BenchmarkError):
            contracts.validate_coverage(data)
        data = coverage()
        data['rows'][0]['coverage']['os'].remove('linux')
        with self.assertRaises(contracts.BenchmarkError):
            contracts.validate_coverage(data)
        data = coverage()
        data['rows'][0]['status'] = 'live_verified'
        with self.assertRaises(contracts.BenchmarkError):
            contracts.validate_coverage(data)
        data['rows'][0]['evidence_references'] = ['receipts/sealed.json']
        contracts.validate_coverage(data)

    def test_not_applicable_os_is_a_valid_distinct_category(self):
        case = scenario()
        case['coverage']['os'] = ['not-applicable']
        contracts.validate_scenario(case, coverage())
        case['coverage']['os'] = ['not-applicable', 'made-up-os']
        with self.assertRaises(contracts.BenchmarkError) as caught:
            contracts.validate_scenario(case, coverage())
        self.assertEqual(caught.exception.code, 'unknown_category')

    def test_group_ids_require_source_references(self):
        data = scenario()
        data['sophistication']['group_ids'] = ['G0016']
        with self.assertRaises(contracts.BenchmarkError) as caught:
            contracts.validate_scenario(data, coverage())
        self.assertEqual(caught.exception.code, 'missing_source_reference')
        data['sophistication']['source_references'] = ['https://attack.mitre.org/groups/G0016/']
        contracts.validate_scenario(data, coverage())

    def test_scenario_provenance_choices(self):
        data = scenario()
        for value in ('synthetic', 'lab_export', 'derived_replay', 'public_replay'):
            data['provenance'] = value
            contracts.validate_scenario(data, coverage())
        data['provenance'] = 'replay'
        with self.assertRaises(contracts.BenchmarkError) as caught:
            contracts.validate_scenario(data, coverage())
        self.assertEqual((caught.exception.code, caught.exception.field), ('invalid_choice', 'scenario.provenance'))

    def test_rubric_score_and_tier_consistency(self):
        data = scenario()
        data['difficulty']['band'] = 'D5'
        with self.assertRaises(contracts.BenchmarkError):
            contracts.validate_scenario(data, coverage())
        data = scenario()
        data['sophistication']['band'] = 'S3'
        with self.assertRaises(contracts.BenchmarkError):
            contracts.validate_scenario(data, coverage())
        data = scenario()
        data['difficulty']['control'] = True
        data['sophistication']['band'] = 'S0'
        data['sophistication']['steps'] = []
        contracts.validate_scenario(data, coverage())

    def test_s1_is_unlinked_atomic_steps_on_any_assets(self):
        data = scenario()
        steps = data['sophistication']['steps']
        steps.append({'step_id': 't2', 'asset_id': 'a2', 'boundary_id': 'b1', 'phase': 'initial'})
        contracts.validate_scenario(data, coverage())
        data['sophistication']['edges'] = [['t1', 't2']]
        with self.assertRaises(contracts.BenchmarkError) as caught:
            contracts.validate_scenario(data, coverage())
        self.assertEqual(caught.exception.code, 'rubric_mismatch')

    def test_tier_is_judged_on_strongest_chain_with_concurrent_activity(self):
        data = scenario()
        data['sophistication']['band'] = 'S2'
        data['sophistication']['boundaries'].append({'boundary_id': 'b2', 'kind': 'identity'})
        step = lambda name, asset, boundary='b1': {
            'step_id': name, 'asset_id': asset, 'boundary_id': boundary, 'phase': 'initial'}
        # Two concurrent, causally unrelated chains on two hosts plus an atomic step.
        data['sophistication']['steps'] = [step('t1', 'a1'), step('t2', 'a1'), step('u1', 'a2'),
                                           step('u2', 'a2'), step('side', 'a3')]
        data['sophistication']['edges'] = [['t1', 't2'], ['u1', 'u2']]
        contracts.validate_scenario(data, coverage())
        # Concurrent activity on other assets cannot make a single-host chain S3.
        data['sophistication']['band'] = 'S3'
        data['sophistication']['steps'][4] = step('side', 'a3', 'b2')
        with self.assertRaises(contracts.BenchmarkError) as caught:
            contracts.validate_scenario(data, coverage())
        self.assertEqual(caught.exception.code, 'rubric_mismatch')
        # One chain crossing an identity boundary between hosts supports S3 beside the other chain.
        data['sophistication']['steps'][3] = step('u2', 'a3', 'b2')
        contracts.validate_scenario(data, coverage())
        # An edge to an unknown step is still refused.
        data['sophistication']['edges'].append(['side', 'missing'])
        with self.assertRaises(contracts.BenchmarkError):
            contracts.validate_scenario(data, coverage())

    def test_public_digest_and_original_timestamp(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'events.jsonl'
            path.write_bytes(b'event\n')
            contracts.validate_public_bundle(public_bundle(), directory)
            path.write_bytes(b'changed\n')
            with self.assertRaises(contracts.BenchmarkError) as caught:
                contracts.validate_public_bundle(public_bundle(), directory)
            self.assertEqual(caught.exception.code, 'evidence_digest_mismatch')
            path.write_bytes(b'much larger replacement\n' * 100)
            with mock.patch.object(Path, 'read_bytes', side_effect=AssertionError('read before size check')):
                with self.assertRaises(contracts.BenchmarkError) as caught:
                    contracts.validate_public_bundle(public_bundle(), directory)
            self.assertEqual(caught.exception.code, 'evidence_digest_mismatch')
        data = public_bundle()
        del data['events'][0]['fields']['timestamp_original']
        with self.assertRaises(contracts.BenchmarkError):
            contracts.validate_public_bundle(data)

    def test_public_case_id_must_be_opaque(self):
        for case_id in ('c1', 'windows-discovery-v1-D1', 'case-XYZ1', 'case-123'):
            data = public_bundle()
            data['case_id'] = case_id
            with self.subTest(case_id=case_id), self.assertRaises(contracts.BenchmarkError) as caught:
                contracts.validate_public_bundle(data)
            self.assertEqual(caught.exception.code, 'invalid_identifier')

    def test_attack_labels_and_normalized_forbidden_keys_rejected(self):
        for mutate in (
            lambda d: d['events'][0]['fields'].update(technique_id='x'),
            lambda d: d['events'][0]['fields'].update(supportSets=[]),
            lambda d: d['events'][0]['fields'].update({'support-sets': []}),
            lambda d: d['events'][0]['fields'].update({'Truth_Path': 'x'}),
            lambda d: d['events'][0]['fields'].update(label='T1059.001'),
            lambda d: d['events'][0]['fields'].update(nested={'note': 'see T1033 here'}),
            lambda d: d['events'][0]['fields'].update(T1033='x'),
            lambda d: d['events'][0].update(event_type='T1033'),
            lambda d: d['known_gaps'].append({'source_id': None, 'asset_id': None,
                'window_utc': copy.deepcopy(WINDOW), 'reason': 'missing T1003 records'}),
            lambda d: d['events'][0]['fields'].update(detector_attack_ids=['not-a-technique']),
        ):
            data = public_bundle()
            mutate(data)
            with self.assertRaises(contracts.BenchmarkError):
                contracts.validate_public_bundle(data)
        data = public_bundle()
        data['events'][0]['fields'].update(detector_attack_ids=['T1033', 'T1059.001'],
                                          compact_time='20260101T000100Z')
        contracts.validate_public_bundle(data)

    def test_unassessed_assets_receive_no_questions(self):
        data = public_bundle()
        sensor = dict(data['assets'][0], asset_id='sensor1', os_family='linux')
        data['assets'].append(sensor)
        data['unassessed_asset_ids'] = ['sensor1']
        contracts.validate_public_bundle(data)
        question = dict(copy.deepcopy(data['assessment_questions'][0]), question_id='q2', asset_id='sensor1')
        data['assessment_questions'].append(question)
        with self.assertRaises(contracts.BenchmarkError) as caught:
            contracts.validate_public_bundle(data)
        self.assertEqual(caught.exception.code, 'unassessed_asset')
        data = public_bundle()
        data['unassessed_asset_ids'] = ['absent']
        with self.assertRaises(contracts.BenchmarkError):
            contracts.validate_public_bundle(data)

    def test_parse_utc_is_strict_and_truncates_to_microseconds(self):
        parsed = contracts.parse_utc('2026-01-01T01:00:00.123456789+01:00', 'x')
        self.assertEqual(parsed.isoformat(), '2026-01-01T00:00:00.123456+00:00')
        self.assertEqual(contracts.parse_utc('2026-01-01T00:00:00.5Z', 'x').microsecond, 500000)
        for invalid in ('2026-01-01T00:00:00', '2026-01-01T00:00:00.Z', '2026-01-01T00:00:00.1234567890Z',
                        '2026-02-30T00:00:00Z', '2026-01-01T00:00:00+24:00', '2026-01-01 00:00:00Z',
                        '２026-01-01T00:00:00Z', None):
            with self.subTest(value=invalid), self.assertRaises(contracts.BenchmarkError) as caught:
                contracts.parse_utc(invalid, 'x')
            self.assertEqual(caught.exception.code, 'invalid_timestamp')

    def test_public_truth_isolation(self):
        for mutate in (
            lambda d: d.update(assessment_labels={'q1': 1}),
            lambda d: d['files'][0].update(path='truth/answers.json'),
            lambda d: d['events'][0]['fields'].update(nested={'support_sets': [['e1']]}),
        ):
            data = public_bundle()
            mutate(data)
            with self.assertRaises(contracts.BenchmarkError):
                contracts.validate_public_bundle(data)
        data = experiment()
        data['scenario_refs'][0]['evidence'] = data['scenario_refs'][0]['scenario']
        with self.assertRaises(contracts.BenchmarkError):
            contracts.validate_experiment(data)

    def test_source_locator_and_time_constraints(self):
        mutations = (
            lambda d: d['events'][0].update(source_id='absent'),
            lambda d: d['events'][0].update(asset_id='absent'),
            lambda d: d['events'][0]['locator'].update(file_sha256=HASH),
            lambda d: d['events'][0].update(timestamp_utc=WINDOW['end_exclusive']),
            lambda d: d['window_utc'].update(start_inclusive='2026-01-01T00:00:00'),
            lambda d: d['sources'][0].update(clock_uncertainty_seconds=-1),
            lambda d: d['sources'][0].update(clock_offset_seconds=None),
            lambda d: d['files'][0].update(byte_count=True),
        )
        for mutate in mutations:
            data = public_bundle()
            mutate(data)
            with self.assertRaises(contracts.BenchmarkError):
                contracts.validate_public_bundle(data)

    def test_complete_assessment_asset_window_set(self):
        data = public_bundle()
        asset = copy.deepcopy(data['assets'][0])
        asset['asset_id'] = 'a2'
        data['assets'].append(asset)
        with self.assertRaises(contracts.BenchmarkError) as caught:
            contracts.validate_public_bundle(data)
        self.assertEqual(caught.exception.code, 'incomplete_questions')
        question = copy.deepcopy(data['assessment_questions'][0])
        question.update(question_id='q2', asset_id='a2')
        data['assessment_questions'].append(question)
        contracts.validate_public_bundle(data)
        question['question'] = 'Was technique T1033 malicious?'
        with self.assertRaises(contracts.BenchmarkError):
            contracts.validate_public_bundle(data)

    def test_truth_digest_labels_support_and_edges(self):
        mutations = (
            lambda d: d.update(case_id='wrong'),
            lambda d: d.update(evidence_manifest_sha256='b' * 64),
            lambda d: d.update(assessment_labels={}),
            lambda d: d.update(assessment_labels={'q1': True}),
            lambda d: d['steps'][0].update(support_sets=[['missing']]),
            lambda d: d['steps'][0].update(support_sets=[]),
            lambda d: d.update(edges=[['t1', 't1']]),
        )
        for mutate in mutations:
            data = truth()
            mutate(data)
            with self.assertRaises(contracts.BenchmarkError):
                contracts.validate_truth(data, public_bundle())
        data = truth()
        data['steps'][0].update(execution_outcome='unknown', observability='unknown', support_sets=[])
        data['assessment_labels']['q1'] = None
        contracts.validate_truth(data, public_bundle())
        self.assertIsNone(data['assessment_labels']['q1'])

    def test_truth_lookalike_groups(self):
        bundle = public_bundle()
        event = dict(copy.deepcopy(bundle['events'][0]), event_id='e2')
        bundle['events'].append(event)
        data = truth(bundle)
        data['lookalike_event_ids'] = [['e2']]
        contracts.validate_truth(data, bundle)
        for groups, code in (([['e2'], ['e2']], 'duplicate_item'), ([['absent']], 'unknown_reference'),
                             ([['e1']], 'lookalike_support_overlap'), ([[]], 'invalid_array')):
            data['lookalike_event_ids'] = groups
            with self.subTest(groups=groups), self.assertRaises(contracts.BenchmarkError) as caught:
                contracts.validate_truth(data, bundle)
            self.assertEqual(caught.exception.code, code)
        public = public_bundle()
        public['events'][0]['fields']['lookalike-event-ids'] = ['e1']
        with self.assertRaises(contracts.BenchmarkError):
            contracts.validate_public_bundle(public)

    def test_truth_disputed_event_ids_need_consensus_and_stay_apart(self):
        bundle = public_bundle()
        for event_id in ('e2', 'e3'):
            bundle['events'].append(dict(copy.deepcopy(bundle['events'][0]), event_id=event_id))
        data = truth(bundle)
        data.update(attestation='agent_consensus', lookalike_event_ids=[['e3']], disputed_event_ids=['e2'])
        contracts.validate_truth(data, bundle)
        for ids, code in ((['e2', 'e2'], 'duplicate_item'), (['absent'], 'unknown_reference'),
                          (['e1'], 'disputed_support_overlap'), (['e3'], 'disputed_support_overlap'),
                          ([], 'invalid_array'), ('e2', 'invalid_array')):
            data['disputed_event_ids'] = ids
            with self.subTest(ids=ids), self.assertRaises(contracts.BenchmarkError) as caught:
                contracts.validate_truth(data, bundle)
            self.assertEqual((caught.exception.code, caught.exception.field), (code, 'truth.disputed_event_ids'))
        data['disputed_event_ids'] = ['e2']
        for attestation in ('human_attested', 'unreviewed_proposal', None):
            if attestation is None:
                data.pop('attestation')
            else:
                data['attestation'] = attestation
            with self.subTest(attestation=attestation), self.assertRaises(contracts.BenchmarkError) as caught:
                contracts.validate_truth(data, bundle)
            self.assertEqual(caught.exception.code, 'disputed_without_consensus')
        public = public_bundle()
        public['events'][0]['fields']['disputed_event_ids'] = ['e1']
        with self.assertRaises(contracts.BenchmarkError):
            contracts.validate_public_bundle(public)

    def test_missing_roles_typesafe_narrative_and_runtime_fields(self):
        data = team()
        del data['roles'][contracts.ROLE_IDS[0]]
        with self.assertRaises(contracts.BenchmarkError):
            contracts.validate_team(data)
        data = team()
        narrative = model()
        narrative['adapter'] = 'typesafe'
        data['roles'][contracts.ROLE_IDS[0]] = narrative
        with self.assertRaises(contracts.BenchmarkError) as caught:
            contracts.validate_team(data)
        self.assertEqual((caught.exception.code, caught.exception.field),
                         ('invalid_choice', 'team.roles.' + contracts.ROLE_IDS[0] + '.adapter'))
        data = team()
        data['evidence_checker'] = model(True)
        with self.assertRaises(contracts.BenchmarkError) as caught:
            contracts.validate_team(data)
        self.assertEqual(caught.exception.code, 'paid_route_in_local_team')
        data['deployment'] = 'hybrid'
        contracts.validate_team(data)
        data['evidence_checker']['base_url'] = 'https://api.example.test/v1'
        with self.assertRaises(contracts.BenchmarkError) as caught:
            contracts.validate_team(data)
        self.assertEqual(caught.exception.code, 'invalid_origin')
        data['evidence_checker']['base_url'] = 'http://127.0.0.1:1'
        data['evidence_checker']['max_output_tokens'] = 64
        with self.assertRaises(contracts.BenchmarkError):
            contracts.validate_team(data)
        data = team()
        data['runtime_facts']['ram_bytes'] = 'unknown'
        with self.assertRaises(contracts.BenchmarkError):
            contracts.validate_team(data)

    def test_adapter_urls_credentials_and_sampling(self):
        invalid_urls = ('http://localhost:8000', 'http://example.test',
                        'https://user:password@example.test',
                        'https://example.test?api_key=SECRET',
                        'file:///tmp/socket', 'https://example.test/#secret',
                        'https://example.test:invalid', 'https://example.test\n')
        for url in invalid_urls:
            data = team()
            data['roles'][contracts.ROLE_IDS[0]]['base_url'] = url
            with self.assertRaises(contracts.BenchmarkError):
                contracts.validate_team(data)
        for key, value in (('credential_env', 'secret-with-hyphens'), ('credential_env', 'BENCH_GUEST_PASSWORD'),
                           ('credential_env', 'AWS_SECRET_ACCESS_KEY'), ('credential_env', 'BENCH_MODEL_'),
                           ('timeout_seconds', 0), ('max_output_tokens', True)):
            data = team()
            data['roles'][contracts.ROLE_IDS[0]][key] = value
            with self.assertRaises(contracts.BenchmarkError):
                contracts.validate_team(data)
        data = team()
        data['roles'][contracts.ROLE_IDS[0]]['parameters']['extra'] = 1
        with self.assertRaises(contracts.BenchmarkError):
            contracts.validate_team(data)
        data = team()
        data['roles'][contracts.ROLE_IDS[0]]['credential_env'] = 'BENCH_MODEL_LOCAL_KEY'
        contracts.validate_team(data)

    def test_provider_specific_sampling_parameters(self):
        for provider, parameters in (('anthropic', {'temperature': None, 'seed': 1729}),
                                     ('anthropic', {'temperature': 1.5, 'seed': None}),
                                     ('openai', {'temperature': None, 'seed': -1})):
            data = team()
            data['deployment'] = 'cloud'
            role = data['roles'][contracts.ROLE_IDS[0]]
            role.update(provider=provider, base_url='https://api.example.test', parameters=parameters)
            with self.subTest(provider=provider, parameters=parameters), self.assertRaises(contracts.BenchmarkError):
                contracts.validate_team(data)
        data = team()
        data['deployment'] = 'cloud'
        data['roles'][contracts.ROLE_IDS[0]].update(provider='anthropic', base_url='https://api.example.test',
                                                    parameters={'temperature': 1, 'seed': None})
        contracts.validate_team(data)

    def test_structured_output_is_an_optional_openai_narrative_boolean(self):
        def check(code, parameters, provider='openai', checker=False):
            data = team()
            data['deployment'] = 'hybrid'
            role = data['roles'][contracts.ROLE_IDS[0]]
            role.update(provider=provider, base_url='https://api.example.test')
            if checker:
                data['evidence_checker'] = dict(model(True), parameters=parameters)
            else:
                role['parameters'] = parameters
            if code is None:
                contracts.validate_team(data)
                return
            with self.assertRaises(contracts.BenchmarkError) as caught:
                contracts.validate_team(data)
            self.assertEqual(caught.exception.code, code)
        for value in (True, False):
            check(None, {'temperature': None, 'seed': None, 'structured_output': value})
        for value in (1, 'true', None):
            check('invalid_boolean', {'temperature': None, 'seed': None, 'structured_output': value})
        check('unsupported_parameter', {'temperature': None, 'seed': None, 'structured_output': True}, 'anthropic')
        check('unsupported_parameter', {'temperature': None, 'seed': None, 'structured_output': True}, checker=True)
        check(None, {'temperature': None, 'seed': None, 'structured_output': False}, checker=True)
        check('unknown_field', {'temperature': None, 'seed': None, 'json_mode': True})

    def test_paid_status_comes_from_route_not_label(self):
        def spec(**changes):
            return dict(model(), **changes)
        self.assertFalse(contracts.route_is_paid(spec()))
        self.assertFalse(contracts.route_is_paid(spec(base_url='http://[::1]:8000/v1')))
        for paid in (spec(base_url='http://localhost:8000/v1'), spec(base_url='https://api.example.test'),
                     spec(provider='anthropic'), model(True)):
            self.assertTrue(contracts.route_is_paid(paid))
        data = team()
        for role in data['roles'].values():
            role.update(provider='anthropic', base_url='https://api.anthropic.com', credential_env='BENCH_MODEL_ANTHROPIC')
        with self.assertRaises(contracts.BenchmarkError) as caught:
            contracts.validate_team(data)
        self.assertEqual(caught.exception.code, 'paid_route_in_local_team')

    def test_release_depends_on_provenance_and_route(self):
        from benchmark_runner import release_required
        paid = dict(model(), base_url='https://api.example.test')
        loopback = model()
        self.assertFalse(contracts.route_is_paid(loopback))
        for provenance, on_paid in (('public_replay', False), ('synthetic', False),
                                    ('derived_replay', True), ('lab_export', True)):
            with self.subTest(provenance=provenance):
                case = dict(scenario(), provenance=provenance)
                self.assertIs(release_required(case, paid), on_paid)
                self.assertIs(release_required(case, loopback), False)

    def test_call_cost_bound(self):
        budget = experiment()['budgets']
        paid = dict(model(), base_url='https://api.example.test')
        rates = [{'provider': 'openai', 'model_requested': 'invented-version-1',
                  'input_per_million': 2, 'output_per_million': 4}]
        self.assertEqual(contracts.call_cost_bound(budget, model(), []), 0.0)
        self.assertIsNone(contracts.call_cost_bound(budget, paid, []))
        self.assertAlmostEqual(contracts.call_cost_bound(budget, paid, rates), (2 * 4096 + 4 * 128) / 1e6)
        checker = dict(model(True), base_url='https://api.example.test')
        self.assertIsNone(contracts.call_cost_bound(budget, checker, rates))
        self.assertAlmostEqual(contracts.call_cost_bound(budget, checker, [dict(rates[0], provider='typesafe')]),
                               (2 * 4096 + 4 * 4096) / 1e6)
        self.assertEqual(contracts.call_cost_bound(dict(budget, per_call_cost_bound_usd=0.5), paid, []), 0.5)

    def test_max_concurrent_calls_defaults_and_bounds(self):
        data = experiment()
        data['budgets'].pop('max_concurrent_calls', None)
        self.assertEqual(contracts.max_concurrent_calls(contracts.validate_experiment(data)), 4)
        for value in (1, 16):
            data['budgets']['max_concurrent_calls'] = value
            self.assertEqual(contracts.max_concurrent_calls(contracts.validate_experiment(data)), value)
        for value in (0, 17, True, 2.0, '4', None):
            data['budgets']['max_concurrent_calls'] = value
            with self.subTest(value=value), self.assertRaises(contracts.BenchmarkError) as caught:
                contracts.validate_experiment(data)
            self.assertEqual(caught.exception.field, 'experiment.budgets.max_concurrent_calls')
        # There is no separate opt-in mode: the field is unknown.
        data = experiment()
        data['iteration_mode'] = 'fast_development'
        with self.assertRaises(contracts.BenchmarkError) as caught:
            contracts.validate_experiment(data)
        self.assertEqual(caught.exception.code, 'unknown_field')

    def test_truth_attestation_is_an_explicit_label(self):
        data = truth()
        self.assertEqual(contracts.truth_attestation(contracts.validate_truth(data, public_bundle())), 'human_attested')
        for value in contracts.TRUTH_ATTESTATIONS:
            data['attestation'] = value
            self.assertEqual(contracts.truth_attestation(contracts.validate_truth(data, public_bundle())), value)
        for value in ('attested', None, True, 'HUMAN_ATTESTED'):
            data['attestation'] = value
            with self.subTest(value=value), self.assertRaises(contracts.BenchmarkError) as caught:
                contracts.validate_truth(data, public_bundle())
            self.assertEqual((caught.exception.code, caught.exception.field), ('invalid_choice', 'truth.attestation'))

    def test_budget_caps_paid_bounds_and_pricing(self):
        for key in experiment()['budgets']:
            for invalid in (0, -1, True, '1'):
                data = experiment()
                data['budgets'][key] = invalid
                with self.assertRaises(contracts.BenchmarkError):
                    contracts.validate_experiment(data)
        data = experiment()
        data['budgets']['max_prompt_bytes'] = contracts.MAX_BYTES + 1
        with self.assertRaises(contracts.BenchmarkError):
            contracts.validate_experiment(data)
        data = experiment()
        data['teams'][0]['deployment'] = 'cloud'
        for role in data['teams'][0]['roles'].values():
            role['base_url'] = 'https://api.example.test/v1'
        with self.assertRaises(contracts.BenchmarkError) as caught:
            contracts.validate_experiment(data)
        self.assertEqual(caught.exception.code, 'missing_cost_bound')
        # Spend-cap-only is not a computable bound.
        data['budgets'].update(max_api_cost_usd=1, provider_spend_cap_ref='provider-console-cap-1')
        with self.assertRaises(contracts.BenchmarkError) as caught:
            contracts.validate_experiment(data)
        self.assertEqual(caught.exception.code, 'unbounded_paid_route')
        data['budgets']['per_call_cost_bound_usd'] = 2
        with self.assertRaises(contracts.BenchmarkError) as caught:
            contracts.validate_experiment(data)
        self.assertEqual(caught.exception.code, 'invalid_cost_bound')
        del data['budgets']['per_call_cost_bound_usd']
        data['pricing_snapshot']['rates'] = [{
            'provider': 'openai', 'model_requested': 'invented-version-1',
            'input_per_million': 0, 'output_per_million': 0}]
        contracts.validate_experiment(data)
        # A local-labelled team on a cloud route is rejected, even with no budget.
        data = experiment()
        for role in data['teams'][0]['roles'].values():
            role.update(provider='anthropic', base_url='https://api.anthropic.com', credential_env='BENCH_MODEL_KEY')
        with self.assertRaises(contracts.BenchmarkError) as caught:
            contracts.validate_experiment(data)
        self.assertEqual(caught.exception.code, 'paid_route_in_local_team')
        data = experiment()
        data['pricing_snapshot']['rates'] = [{
            'provider': 'openai', 'model_requested': 'invented-version-1',
            'input_per_million': 0, 'output_per_million': 0}]
        data['pricing_snapshot']['rates'][0]['input_per_million'] = float('inf')
        with self.assertRaises(contracts.BenchmarkError):
            contracts.validate_experiment(data)


class StageContractsTests(unittest.TestCase):
    def test_nonexistent_citations_and_assets_are_preserved(self):
        data = stage()
        data['claims'][0]['event_ids'] = ['not-present']
        data['findings'][0].update(event_ids=['not-present'], asset_id='not-present')
        before = copy.deepcopy(data)
        self.assertIs(contracts.validate_stage_output(data, 'analysis', public_bundle()), data)
        self.assertEqual(data, before)

    def test_confidence_and_probabilities_are_finite_and_not_booleans(self):
        for invalid in (float('nan'), float('inf'), -float('inf'), True, '0.5', -0.1, 1.1):
            data = stage()
            data['findings'][0]['confidence'] = invalid
            with self.assertRaises(contracts.BenchmarkError):
                contracts.validate_stage_output(data)
            data = stage(True)
            data['assessment_answers'][0]['probability_suspicious'] = invalid
            with self.assertRaises(contracts.BenchmarkError):
                contracts.validate_stage_output(data)
        for valid in (None, 0, 1, 0.5):
            data = stage()
            data['findings'][0]['confidence'] = valid
            contracts.validate_stage_output(data)

    def test_handoff_answers_exact_and_stage_specific(self):
        data = stage(True)
        data['assessment_answers'] = []
        with self.assertRaises(contracts.BenchmarkError):
            contracts.validate_stage_output(data, 'handoff', public_bundle())
        data = stage(True)
        data['assessment_answers'].append(copy.deepcopy(data['assessment_answers'][0]))
        with self.assertRaises(contracts.BenchmarkError):
            contracts.validate_stage_output(data)
        data = stage(True)
        del data['chain_edges']
        with self.assertRaises(contracts.BenchmarkError):
            contracts.validate_stage_output(data)
        data = stage()
        data['chain_edges'] = []
        with self.assertRaises(contracts.BenchmarkError):
            contracts.validate_stage_output(data)
        with self.assertRaises(contracts.BenchmarkError):
            contracts.validate_stage_output(stage(), 'review')

    def test_repeated_narrative_lines_are_not_format_errors(self):
        data = stage()
        for key in ('hypotheses', 'gaps', 'limitations'):
            data[key] = ['Same line.', 'Same line.']
        contracts.validate_stage_output(data)
        data['gaps'] = ['']
        with self.assertRaises(contracts.BenchmarkError):
            contracts.validate_stage_output(data)

    def test_duplicate_claims_and_bad_edges_rejected(self):
        data = stage()
        data['claims'].append(copy.deepcopy(data['claims'][0]))
        with self.assertRaises(contracts.BenchmarkError):
            contracts.validate_stage_output(data)
        data = stage(True)
        data['chain_edges'] = [['finding1', 'missing']]
        with self.assertRaises(contracts.BenchmarkError):
            contracts.validate_stage_output(data)
        data = stage(True)
        data['chain_edges'] = [['finding1', 'finding1']]
        with self.assertRaises(contracts.BenchmarkError):
            contracts.validate_stage_output(data)


def schema_errors(schema, value, path='$'):
    """Minimal checker for exactly `contracts.SCHEMA_KEYWORDS`; failing paths."""
    if 'anyOf' in schema:
        return [] if any(not schema_errors(option, value, path) for option in schema['anyOf']) else [path]
    kinds = {'object': dict, 'array': list, 'string': str, 'integer': int, 'null': type(None)}
    if schema['type'] == 'number':
        if type(value) not in (int, float):
            return [path]
    elif type(value) is not kinds[schema['type']]:
        return [path]
    errors = []
    if 'enum' in schema and value not in schema['enum']:
        errors.append(path)
    if 'pattern' in schema and not re.search(schema['pattern'], value):
        errors.append(path)
    if ('minimum' in schema and value < schema['minimum']) or ('maximum' in schema and value > schema['maximum']):
        errors.append(path)
    if schema['type'] == 'object':
        if set(value) - set(schema['properties']) or set(schema['required']) - set(value):
            errors.append(path)
        for key, item in value.items():
            if key in schema['properties']:
                errors.extend(schema_errors(schema['properties'][key], item, path + '.' + key))
    if schema['type'] == 'array':
        if len(value) < schema.get('minItems', 0) or len(value) > schema.get('maxItems', len(value)):
            errors.append(path)
        for index, item in enumerate(value):
            errors.extend(schema_errors(schema['items'], item, '{}[{}]'.format(path, index)))
    return errors


def _sample_pattern(pattern, rng):
    if pattern == contracts._SCHEMA_ID:
        alphabet = 'abcXYZ019_-'
        return rng.choice('aZ7') + ''.join(rng.choice(alphabet) for _ in range(rng.randint(0, 12)))
    if pattern == contracts._SCHEMA_TECHNIQUE:
        return 'T{:04d}'.format(rng.randint(1000, 1999)) + rng.choice(('', '.{:03d}'.format(rng.randint(1, 9))))
    if pattern == contracts._SCHEMA_TIMESTAMP:
        moment = contracts.parse_utc('2026-01-01T00:00:00Z', 'test') + timedelta(seconds=rng.randint(0, 86400))
        return moment.strftime('%Y-%m-%dT%H:%M:%S') + rng.choice(('', '.5', '.123456789')) + rng.choice(('Z', '+00:00'))
    if pattern == contracts._SCHEMA_TEXT:
        return rng.choice(('Synthetic text.', 'caf\u00e9 observation', 'trailing space ', 'x'))
    raise AssertionError('pattern without a sampler: ' + pattern)


def generate(schema, rng):
    """Random instance drawn from the schema; free text is drawn nonblank."""
    if 'anyOf' in schema:
        return generate(rng.choice(schema['anyOf']), rng)
    if 'enum' in schema:
        return rng.choice(schema['enum'])
    kind = schema['type']
    if kind == 'null':
        return None
    if kind == 'number':
        return rng.choice((schema['minimum'], schema['maximum'], round(rng.random(), 4)))
    if kind == 'string':
        if 'pattern' in schema:
            return _sample_pattern(schema['pattern'], rng)
        return rng.choice(('Synthetic text.', 'caf\u00e9 observation', ' padded ', 'x'))
    if kind == 'array':
        low = schema.get('minItems', 0)
        return [generate(schema['items'], rng) for _ in range(rng.randint(low, schema.get('maxItems', low + 3)))]
    return {key: generate(item, rng) for key, item in schema['properties'].items()}


def fit(output):
    """Apply only constraints a JSON Schema cannot express (see the docstring)."""
    for key in ('claims', 'findings'):
        for index, item in enumerate(output[key]):
            item[key[:-1] + '_id'] = '{}-{}'.format(key, index)
            item['event_ids'] = sorted(set(item['event_ids']))
    for finding in output['findings']:
        window = finding['window_utc']
        start = contracts.parse_utc(window['start_inclusive'], 'test')
        if contracts.parse_utc(window['end_exclusive'], 'test') <= start:
            window['end_exclusive'] = (start + timedelta(minutes=1)).strftime('%Y-%m-%dT%H:%M:%SZ')
    if 'chain_edges' in output:
        ids = [item['finding_id'] for item in output['findings']]
        output['chain_edges'] = [[ids[0], ids[1]]] if len(ids) > 1 else []
    return output


class StageSchemaTests(unittest.TestCase):
    """The schema guides decoding; `validate_stage_output` stays authoritative."""

    def walk(self, schema):
        yield schema
        for option in schema.get('anyOf', []):
            yield from self.walk(option)
        for item in schema.get('properties', {}).values():
            yield from self.walk(item)
        if 'items' in schema:
            yield from self.walk(schema['items'])

    def test_closed_strict_subset_with_contract_enums(self):
        bundle = public_bundle()
        for stage_key in contracts.STAGE_KEYS:
            schema = contracts.stage_output_schema(stage_key, bundle)
            with self.subTest(stage=stage_key):
                for node in self.walk(schema):
                    self.assertLessEqual(set(node), contracts.SCHEMA_KEYWORDS)
                    if node.get('type') == 'object':
                        self.assertIs(node['additionalProperties'], False)
                        self.assertEqual(node['required'], list(node['properties']))
                expected = {'schema_version', 'stage_key', 'summary', 'claims', 'findings', 'hypotheses',
                            'gaps', 'limitations', 'requested_decision'}
                if stage_key == 'handoff':
                    expected |= {'chain_edges', 'assessment_answers'}
                self.assertEqual(set(schema['properties']), expected)
                self.assertEqual(schema['properties']['stage_key']['enum'], [stage_key])
                self.assertEqual(schema['properties']['requested_decision']['enum'],
                                 ['approve', 'revise', 'insufficient'])
                claim = schema['properties']['claims']['items']['properties']
                finding = schema['properties']['findings']['items']['properties']
                self.assertEqual(claim['kind']['enum'], ['observation', 'inference', 'hypothesis'])
                self.assertEqual(finding['disposition']['enum'], ['suspicious', 'benign', 'insufficient'])
                self.assertEqual(claim['event_ids']['items']['enum'], ['e1'])
                self.assertEqual(finding['event_ids']['items']['enum'], ['e1'])
                self.assertEqual(finding['asset_id']['enum'], ['a1'])
        answers = contracts.stage_output_schema('handoff', bundle)['properties']['assessment_answers']
        self.assertEqual((answers['minItems'], answers['maxItems']), (1, 1))
        self.assertEqual(answers['items']['properties']['question_id']['enum'], ['q1'])
        with self.assertRaises(contracts.BenchmarkError):
            contracts.stage_output_schema('unknown', bundle)

    def test_identifier_enums_are_capped_then_use_the_identifier_pattern(self):
        limit = contracts.SCHEMA_ENUM_LIMIT
        for count, enumerated in ((limit, True), (limit + 1, False)):
            evidence = {'events': [{'event_id': 'e{}'.format(index)} for index in range(count)],
                        'assets': [{'asset_id': 'a1'}], 'assessment_questions': [{'question_id': 'q1'}]}
            items = contracts.stage_output_schema('scope', evidence)['properties']['claims']['items']
            event = items['properties']['event_ids']['items']
            with self.subTest(count=count):
                self.assertEqual('enum' in event, enumerated)
                self.assertEqual('pattern' in event, not enumerated)

    def test_random_schema_instances_pass_the_authoritative_validator(self):
        """Generated outputs are schema-valid and validator-valid.

        Free text is drawn nonblank, and `fit` applies only what the schema
        cannot express: unique claim/finding/event IDs, start before end, and
        chain edges between distinct existing findings. The next test shows the
        validator still rejects each of those schema-valid violations.
        """
        rng = random.Random(1729)
        bundle = public_bundle()
        for iteration in range(300):
            stage_key = contracts.STAGE_KEYS[iteration % len(contracts.STAGE_KEYS)]
            schema = contracts.stage_output_schema(stage_key, bundle)
            output = fit(generate(schema, rng))
            with self.subTest(iteration=iteration, stage=stage_key):
                self.assertEqual(schema_errors(schema, output), [])
                decoded = contracts.decode_json(contracts.canonical_bytes(output))
                self.assertIs(contracts.validate_stage_output(decoded, stage_key, bundle), decoded)

    def test_schema_valid_but_semantically_invalid_outputs_are_still_rejected(self):
        bundle = public_bundle()
        schema = contracts.stage_output_schema('handoff', bundle)
        def finding(identifier):
            return {'finding_id': identifier, 'asset_id': 'a1', 'technique_id': None,
                    'window_utc': copy.deepcopy(WINDOW), 'disposition': 'benign', 'confidence': None,
                    'event_ids': [], 'rationale': 'Invented.'}
        cases = []
        data = stage(True)
        data['summary'] = ' leading space is still accepted by the validator'
        self.assertEqual(schema_errors(schema, data), ['$.summary'])
        data['summary'] = '   '
        # The schema now prevents whitespace-only text; the validator still refuses it.
        self.assertEqual(schema_errors(schema, data), ['$.summary'])
        with self.assertRaises(contracts.BenchmarkError):
            contracts.validate_stage_output(data, 'handoff', bundle)
        data = stage(True)
        data['findings'][0]['window_utc']['end_exclusive'] = data['findings'][0]['window_utc']['start_inclusive']
        cases.append(('empty window', data))
        data = stage(True)
        data['claims'].append(copy.deepcopy(data['claims'][0]))
        cases.append(('duplicate claim', data))
        data = stage(True)
        data['findings'][0]['event_ids'] = ['e1', 'e1']
        cases.append(('duplicate citation', data))
        data = stage(True)
        data['findings'].append(finding('finding2'))
        data['chain_edges'] = [['finding1', 'absent']]
        cases.append(('dangling edge', data))
        for name, data in cases:
            with self.subTest(case=name):
                self.assertEqual(schema_errors(schema, data), [])
                with self.assertRaises(contracts.BenchmarkError):
                    contracts.validate_stage_output(data, 'handoff', bundle)

    def test_schema_rejects_unknown_and_missing_keys_at_every_level(self):
        bundle = public_bundle()
        schema = contracts.stage_output_schema('handoff', bundle)
        self.assertEqual(schema_errors(schema, stage(True)), [])
        locations = [lambda data: data, lambda data: data['claims'][0], lambda data: data['findings'][0],
                     lambda data: data['findings'][0]['window_utc'], lambda data: data['assessment_answers'][0]]
        for index, locate in enumerate(locations):
            with self.subTest(location=index):
                data = stage(True)
                locate(data)['unexpected'] = 'value'
                self.assertNotEqual(schema_errors(schema, data), [])
                data = stage(True)
                target = locate(data)
                del target[sorted(target)[0]]
                self.assertNotEqual(schema_errors(schema, data), [])
        # Final-only keys are unknown at every other stage.
        self.assertNotEqual(schema_errors(contracts.stage_output_schema('analysis', bundle), stage(True)), [])
        data = stage(True)
        data['assessment_answers'] = []
        self.assertNotEqual(schema_errors(schema, data), [])


class PathContractsTests(unittest.TestCase):
    def test_confined_files_and_portable_escape_rejection(self):
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / 'safe.txt').write_bytes(b'data')
            self.assertEqual(contracts.confined_file(directory, 'safe.txt'), Path(directory) / 'safe.txt')
            for path in ('../safe.txt', '/safe.txt', 'C:/safe.txt', 'a\\safe.txt',
                         './safe.txt', 'a//safe.txt', 'safe.txt:stream', 'NUL.txt',
                         'COM1', 'safe.txt.', 'safe.txt ', '', 'missing.txt'):
                with self.subTest(path=path), self.assertRaises(contracts.BenchmarkError):
                    contracts.confined_file(directory, path)
            with self.assertRaises(contracts.BenchmarkError):
                contracts.confined_file(directory, 'subdir')

    def test_symlink_file_directory_and_root_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / 'actual'
            target.mkdir()
            (target / 'safe.txt').write_bytes(b'data')
            try:
                (root / 'alias').symlink_to(target, target_is_directory=True)
                (target / 'alias.txt').symlink_to(target / 'safe.txt')
            except (OSError, NotImplementedError):
                self.skipTest('symlink creation unavailable on this host')
            for base, relative in ((root, 'alias/safe.txt'), (root / 'alias', 'safe.txt'),
                                   (target, 'alias.txt')):
                with self.assertRaises(contracts.BenchmarkError):
                    contracts.confined_file(base, relative)
            with self.assertRaises(contracts.BenchmarkError):
                contracts.validate_state_root(root / 'alias' / 'state')

    def test_missing_file_and_name_aliases_are_named_failures(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'Evaluator-Labels.json').write_bytes(b'{}')
            with self.assertRaises(contracts.BenchmarkError) as caught:
                contracts.confined_file(root, 'absent.json', 'scenario_refs.evidence')
            self.assertEqual((caught.exception.code, caught.exception.field), ('file_not_found', 'scenario_refs.evidence'))
            # Case alias: path_alias on case-insensitive hosts, file_not_found elsewhere.
            with self.assertRaises(contracts.BenchmarkError) as caught:
                contracts.confined_file(root, 'evaluator-labels.json')
            self.assertIn(caught.exception.code, ('path_alias', 'file_not_found'))
            with self.assertRaises(contracts.BenchmarkError) as caught:
                contracts.confined_file(root, 'EVALUA~1.JSO')
            self.assertEqual(caught.exception.code, 'path_alias')

    @unittest.skipUnless(os.name == 'nt', 'Windows 8.3 short names')
    def test_actual_windows_short_name_is_rejected(self):
        import ctypes
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'evaluator-labels-long-name.json'
            path.write_bytes(b'{}')
            buffer = ctypes.create_unicode_buffer(1024)
            if not ctypes.windll.kernel32.GetShortPathNameW(str(path), buffer, 1024):
                self.skipTest('short names unavailable')
            short = Path(buffer.value).name
            if short == path.name:
                self.skipTest('8.3 names disabled on this volume')
            # The validator refuses the short form before or after resolution.
            with self.assertRaises(contracts.BenchmarkError) as caught:
                contracts.confined_file(directory, short)
            self.assertEqual(caught.exception.code, 'path_alias')

    def test_reparse_attribute_rejected_without_windows_privileges(self):
        original = Path.lstat
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'safe.txt').write_bytes(b'data')

            def reparse(path, *args, **kwargs):
                info = original(path, *args, **kwargs)
                if path == root / 'safe.txt':
                    return mock.Mock(st_mode=info.st_mode, st_file_attributes=0x400)
                return info

            with mock.patch.object(Path, 'lstat', reparse):
                with self.assertRaises(contracts.BenchmarkError) as caught:
                    contracts.confined_file(root, 'safe.txt')
                self.assertEqual(caught.exception.code, 'path_alias')

    def test_hardlinked_files_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'first').write_bytes(b'data')
            try:
                os.link(root / 'first', root / 'second')
            except (OSError, NotImplementedError):
                self.skipTest('hardlink creation unavailable on this host')
            with self.assertRaises(contracts.BenchmarkError) as caught:
                contracts.confined_file(root, 'second')
            self.assertEqual(caught.exception.code, 'path_alias')

    def test_state_inspection_is_bounded_and_avoids_private_trees(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / 'Downloads').mkdir()
            with self.assertRaises(contracts.BenchmarkError):
                contracts.validate_state_root(root)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            entry = mock.Mock(name='entry')
            entry.name = 'ordinary'
            entry.path = str(root / 'ordinary')
            (root / 'ordinary').write_bytes(b'')
            entry.stat.return_value = (root / 'ordinary').stat()
            scan = mock.MagicMock()
            scan.__enter__.return_value = iter([entry] * 10001)
            with mock.patch.object(contracts.os, 'scandir', return_value=scan):
                with self.assertRaises(contracts.BenchmarkError) as caught:
                    contracts.validate_state_root(root)
            self.assertEqual(caught.exception.code, 'state_root_scan_limit')

    def test_state_root_boundaries_and_no_creation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            new = root / 'state'
            self.assertEqual(contracts.validate_state_root(new), new)
            self.assertFalse(new.exists())
            for path in ('relative-state', Path(contracts.__file__).parent / 'state',
                         Path(contracts.__file__).parent.parent,
                         root / 'Downloads' / 'state', root / '.hermes' / 'state'):
                with self.assertRaises(contracts.BenchmarkError):
                    contracts.validate_state_root(path)
            worktree = root / 'worktree'
            worktree.mkdir()
            (worktree / '.git').write_text('gitdir: unused', encoding='utf-8')
            with self.assertRaises(contracts.BenchmarkError):
                contracts.validate_state_root(worktree / 'state')
            with self.assertRaises(contracts.BenchmarkError):
                contracts.validate_state_root(root)


class WorkflowTemplateTests(unittest.TestCase):
    def test_shipped_workflows_validate_and_stay_in_snapshot_data(self):
        import benchmark_runner
        from workflows import validate_template
        here = Path(contracts.__file__).resolve().parent
        for rel in ('benchmarks/team-workflow.json', 'benchmarks/team-workflow-novel-apt.json'):
            with self.subTest(workflow=rel):
                self.assertIn(rel, benchmark_runner.SOURCE_DATA)
                tpl = validate_template(contracts.load_json(here / rel))
                benchmark_runner._workflow(tpl)


if __name__ == '__main__':
    unittest.main()

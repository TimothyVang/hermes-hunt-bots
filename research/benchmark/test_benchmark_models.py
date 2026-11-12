"""Synthetic transport regressions, never measurements of model quality.

Core cases use real durable state with a substituted response boundary. Optional
cases exercise the actual SDK and child CLI against a disposable loopback API.
"""
import copy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from benchmark import load_experiment
from benchmark_contracts import BenchmarkError, canonical_bytes, decode_json, digest_bytes, stage_output_schema
import benchmark_models as models
from langchain_adapter import PrerequisiteMissing
import benchmark_runner as runner
from benchmark_store import BenchmarkStore, STAGE_ROLES, call_timing
from test_benchmark_runner import FIXTURES, response_fixture

MODEL = 'synthetic-loopback-transport-fixture-v1'
SECRET = 'synthetic-test-only-credential-not-a-real-key'


class ModelFixture:
    def create_state(self, endpoint='http://127.0.0.1:9/v1', checker=False, timeout=5, sdk_stub=True,
                     structured=False, max_response_bytes=None):
        if sdk_stub:
            # Substituted response boundary: the optional SDK need not exist.
            prerequisites = patch('benchmark_models.check_prerequisites')
            prerequisites.start()
            self.addCleanup(prerequisites.stop)
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name) / 'state'
        loaded = load_experiment(FIXTURES / 'examples' / 'experiment.json', FIXTURES)
        loaded['experiment']['repetitions'] = 1
        if max_response_bytes is not None:
            loaded['experiment']['budgets']['max_response_bytes'] = max_response_bytes
        team = loaded['experiment']['teams'][0]
        parameters = {'temperature': 0.2, 'seed': 1729}
        if structured:
            parameters['structured_output'] = True
        for model in team['roles'].values():
            model.update(model_requested=MODEL, expected_model_ids=[MODEL], base_url=endpoint,
                         credential_env='BENCH_MODEL_TEST_KEY', timeout_seconds=timeout,
                         parameters=dict(parameters))
        if checker:
            team['deployment'] = 'hybrid'
            team['evidence_checker'] = dict(adapter='typesafe', provider='typesafe', model_requested='jev-1.14.0',
                expected_model_ids=['jev-1.14.0'], base_url='http://127.0.0.1:9', credential_env='BENCH_MODEL_CHECKER_KEY',
                parameters={'temperature': None, 'seed': None}, timeout_seconds=5, max_output_tokens=None)
            loaded['experiment']['budgets'].update(max_api_cost_usd=20, per_call_cost_bound_usd=1)
        loaded['experiment']['pricing_snapshot']['rates'] = [
            dict(provider='openai', model_requested=MODEL, input_per_million=2, output_per_million=4)]
        if checker:
            loaded['experiment']['pricing_snapshot']['rates'].append(
                dict(provider='typesafe', model_requested='jev-1.14.0', input_per_million=1, output_per_million=1))
        self.initial = runner.initialize_experiment(self.root, loaded, FIXTURES / 'fixtures')
        self.store = BenchmarkStore(self.root)
        self.trial = self.store.get_trial(self.initial['active_trial_id'])
        self.frozen = self.store.get_experiment(self.trial['experiment_id'])
        self.team = self.frozen['experiment']['teams'][0]
        self.evidence = self.frozen['cases'][0]['evidence']
        self.env = patch.dict(os.environ, {'BENCH_MODEL_TEST_KEY': SECRET, 'BENCH_MODEL_CHECKER_KEY': SECRET,
                                          'OPENAI_API_KEY': 'wrong-ambient-key', 'HTTPS_PROXY': 'http://127.0.0.1:1'})
        self.env.start()
        self.addCleanup(self.env.stop)

    def envelope(self, stage='scope'):
        model = self.team['roles'][STAGE_ROLES[stage]]
        authorization = runner._authorize(self.store, self.frozen, self.trial, model)
        if stage == 'analysis' and 'evidence_checker' in self.team:
            runner._authorize(self.store, self.frozen, self.trial, self.team['evidence_checker'])
        prompt = runner.build_prompt(self.store, self.trial, stage)
        ref = self.store.write_artifact(self.trial['trial_id'], 'prompts', prompt)
        identity, _, _ = runner._source_identity()
        spec = dict(identity, schema_version=1, trial_id=self.trial['trial_id'], stage_key=stage,
                    attempt_index=1, component='narrative', prompt_artifact=ref, input_sha256=ref['sha256'],
                    workflow_sha256=self.frozen['experiment']['workflow_sha256'],
                    prompt_contract_sha256=self.frozen['experiment']['prompt_contract_sha256'],
                    evidence_sha256=self.trial['case_evidence_sha256'], authorization_sha256=authorization,
                    model=model, role=STAGE_ROLES[stage])
        return dict(state_root=str(self.root), call_id='synthetic-call-' + stage, spec=spec), prompt

    def response(self, stage='scope', **changes):
        values = dict(text=canonical_bytes(response_fixture(stage)).decode('utf-8'), tool_calls=[], invalid_tool_calls=[],
                      response_metadata={'model_name': MODEL, 'finish_reason': 'stop'}, usage_metadata=None)
        values.update(changes)
        return SimpleNamespace(**values)

    def code(self, expected, operation, *args):
        with self.assertRaises(BenchmarkError) as caught:
            operation(*args)
        self.assertEqual(caught.exception.code, expected)

    def last_receipt(self):
        return self.store.calls(trial_id=self.trial['trial_id'])[-1]['receipt']


class BenchmarkModelTests(ModelFixture, unittest.TestCase):
    def setUp(self):
        self.create_state()

    def test_authentic_text_nullable_usage_caps_and_terminal_reuse(self):
        envelope, prompt = self.envelope()
        response = self.response(text=json.dumps(response_fixture(), indent=2))
        def invoke(actual_prompt, provider, model, base_url, timeout, **kwargs):
            self.assertEqual(actual_prompt.encode(), prompt)
            self.assertEqual(os.environ['OPENAI_API_KEY'], SECRET)
            self.assertNotIn('HTTPS_PROXY', os.environ)
            self.assertNotIn('BENCH_MODEL_CHECKER_KEY', os.environ)
            self.assertEqual(kwargs, {'max_output_tokens': 2048, 'temperature': 0.2, 'seed': 1729})
            return response
        with patch('langchain_adapter.invoke_response', side_effect=invoke) as transport:
            result = models.execute_call(envelope, prompt)
            again = models.execute_call(envelope, prompt)
        self.assertEqual(transport.call_count, 1)
        self.assertEqual(result, again)
        receipt = result['receipt']
        self.assertEqual(receipt['status'], 'completed')
        self.assertEqual(receipt['identity_status'], 'reported_match')
        self.assertEqual(receipt['usage'], dict.fromkeys(models.TOKEN_FIELDS))
        self.assertIsNone(receipt['cost']['api_cost_usd'])
        self.assertIsNone(result['checker'])
        self.assertEqual(self.store.read_artifact(self.trial['trial_id'], receipt['response_artifact']), response.text.encode())
        self.assertEqual(os.environ['OPENAI_API_KEY'], 'wrong-ambient-key')
        self.assertNotIn(SECRET, canonical_bytes(self.store.snapshot(self.trial['experiment_id'])).decode())

    def test_measured_usage_subsets_not_double_counted(self):
        envelope, prompt = self.envelope()
        response = self.response(usage_metadata={'input_tokens': 100, 'output_tokens': 20,
            'input_token_details': {'cache_read': 50}, 'output_token_details': {'reasoning': 10}})
        with patch('langchain_adapter.invoke_response', return_value=response):
            result = models.execute_call(envelope, prompt)
        self.assertEqual(result['receipt']['cost']['api_cost_usd'], 0.00028)
        self.assertEqual(result['receipt']['cost']['cost_basis'], 'computed')
        # A loopback route reserves a zero bound, so a priced cost is flagged.
        self.assertTrue(result['receipt']['cost']['bound_exceeded'])
        self.assertEqual(result['receipt']['usage']['reasoning_tokens'], 10)

    def test_unreported_model_is_not_requested_identity_attestation(self):
        envelope, prompt = self.envelope()
        with patch('langchain_adapter.invoke_response', return_value=self.response(response_metadata={'id': 'message-id'})):
            result = models.execute_call(envelope, prompt)
        self.assertIsNone(result['receipt']['model_returned'])
        self.assertEqual(result['receipt']['identity_status'], 'unreported')
        self.assertIsNone(result['receipt']['finish_reason'])

    def test_reported_mismatch_fails_and_retains_actual_metadata(self):
        envelope, prompt = self.envelope()
        with patch('langchain_adapter.invoke_response', return_value=self.response(response_metadata={'model_name': 'other-model', 'finish_reason': 'stop'})) as invoke:
            self.code('model_identity_mismatch', models.execute_call, envelope, prompt)
            self.code('model_identity_mismatch', models.execute_call, envelope, prompt)
        self.assertEqual(invoke.call_count, 1)
        self.assertEqual(self.last_receipt()['model_returned'], 'other-model')
        self.assertEqual(self.last_receipt()['identity_status'], 'reported_mismatch')
        self.assertEqual(self.last_receipt()['status'], 'failed')

    def test_identity_mismatch_precedes_output_validation(self):
        envelope, prompt = self.envelope()
        with patch('langchain_adapter.invoke_response', return_value=self.response(
                text='{broken', response_metadata={'model_name': 'other-model', 'finish_reason': 'stop'})):
            self.code('model_identity_mismatch', models.execute_call, envelope, prompt)
        self.assertEqual(self.last_receipt()['failure_reason'], 'model_identity_mismatch')
        self.assertIsNone(self.last_receipt()['response_artifact'])

    def test_missing_credential_is_not_a_model_format_error(self):
        envelope, prompt = self.envelope()
        with patch.dict(os.environ, {'BENCH_MODEL_TEST_KEY': ''}), patch('langchain_adapter.invoke_response') as invoke:
            self.code('credential_unavailable', models.execute_call, envelope, prompt)
        invoke.assert_not_called()
        self.assertEqual(self.last_receipt()['failure_reason'], 'credential_unavailable')

    def test_missing_sdk_refused_before_reservation(self):
        envelope, prompt = self.envelope()
        with patch('benchmark_models.check_prerequisites', side_effect=PrerequisiteMissing('synthetic')), \
                patch('langchain_adapter.invoke_response') as invoke:
            self.code('prerequisite_missing', models.execute_call, envelope, prompt)
        invoke.assert_not_called()
        self.assertEqual(self.store.calls(), [])

    def test_failure_mapping_separates_operator_and_model_failures(self):
        cases = {'missing_or_invalid_credential': 'credential_unavailable', 'permission_denied': 'authentication_failed',
                 'authentication_failed': 'authentication_failed', 'invalid_origin': 'configuration_invalid',
                 'invalid_limit': 'configuration_invalid', 'timeout': 'timeout', 'unexpected_code': 'invalid_response'}
        for code, reason in cases.items():
            self.assertEqual(models._failure(BenchmarkError(code, 'checker')), reason)
        from langchain_adapter import UnsupportedParameter
        self.assertEqual(models._failure(UnsupportedParameter('x')), 'unsupported_parameter')
        self.assertEqual(models._failure(PrerequisiteMissing('x')), 'prerequisite_missing')
        self.assertEqual(models._failure(type('AuthenticationError', (Exception,), {})()), 'authentication_failed')

    def test_anthropic_metadata_maps_model_and_stop_reason(self):
        spec = dict(provider='anthropic', expected_model_ids=['claude-test-1'])
        response = SimpleNamespace(response_metadata={'model': 'claude-test-1', 'stop_reason': 'end_turn'}, usage_metadata=None)
        metadata = models._metadata(response, spec)
        self.assertEqual((metadata['model_returned'], metadata['identity_status'], metadata['finish_reason']),
                         ('claude-test-1', 'reported_match', 'end_turn'))

    def test_invalid_tool_empty_truncated_and_oversized_are_not_handoffs(self):
        oversized = 'x' * (1024 * 1024 + 1)
        fixture = canonical_bytes(response_fixture())
        # (failure, response changes, rejected diagnostics: code, field, kept answer bytes or None)
        cases = [('invalid_response', {'text': '{broken'}, ('invalid_json', 'json', b'{broken')),
                 ('empty_response', {'text': ''}, None),
                 ('tool_response', {'tool_calls': [{'name': 'forbidden'}]}, None),
                 ('output_limit', {'response_metadata': {'model_name': MODEL, 'finish_reason': 'length'}},
                  ('output_limit', 'response.finish_reason', fixture)),
                 ('output_limit', {'text': oversized}, ('output_limit', 'response.bytes', oversized.encode())),
                 ('output_limit', {'text': '<think>deliberation never finished'},
                  ('output_limit', 'response.reasoning_block', None)),
                 ('empty_response', {'text': '<think>only deliberation</think>\n  '}, None)]
        for index, (reason, changes, diagnostics) in enumerate(cases):
            with self.subTest(reason=reason, index=index):
                if index:
                    self.create_state()
                envelope, prompt = self.envelope()
                with patch('langchain_adapter.invoke_response', return_value=self.response(**changes)) as invoke:
                    self.code(reason, models.execute_call, envelope, prompt)
                self.assertEqual(invoke.call_count, 1)
                receipt = self.last_receipt()
                self.assertEqual(receipt['failure_reason'], reason)
                self.assertIsNone(receipt['response_artifact'])
                if diagnostics is None:
                    self.assertNotIn('rejected_response', receipt)
                    continue
                code, field, answer = diagnostics
                rejected = receipt['rejected_response']
                self.assertEqual((rejected['error_code'], rejected['error_field']), (code, field))
                maximum = receipt['max_output_bytes']
                if answer is None:
                    # An unclosed reasoning block has no answer: nothing of it is kept.
                    self.assertEqual((rejected['artifact'], rejected['byte_count'], rejected['truncated']),
                                     (None, 0, False))
                    continue
                self.assertEqual((rejected['byte_count'], rejected['truncated']), (len(answer), len(answer) > maximum))
                self.assertEqual(self.store.read_artifact(self.trial['trial_id'], rejected['artifact']),
                                 answer[:maximum])
                self.store.snapshot(self.trial['experiment_id'])

    def test_rejected_answer_keeps_the_validator_reason_without_reasoning(self):
        output = response_fixture()
        output['unexpected'] = 'Synthetic extra key.'
        answer = canonical_bytes(output)
        envelope, prompt = self.envelope()
        text = '<think>\nsynthetic-reasoning-marker-91c2\n</think>\n' + answer.decode('utf-8')
        with patch('langchain_adapter.invoke_response', return_value=self.response(text=text)):
            self.code('invalid_response', models.execute_call, envelope, prompt)
        rejected = self.last_receipt()['rejected_response']
        self.assertEqual((rejected['error_code'], rejected['error_field']), ('unknown_field', 'stage_output'))
        stored = self.store.read_artifact(self.trial['trial_id'], rejected['artifact'])
        self.assertEqual(stored, answer)
        # No stored byte anywhere keeps the discarded reasoning block.
        self.assertFalse([path for path in self.root.rglob('*')
                          if path.is_file() and b'synthetic-reasoning-marker-91c2' in path.read_bytes()])
        # Status/advance call listings show the validator's reason too.
        call = self.store.calls(trial_id=self.trial['trial_id'])[0]
        self.assertEqual(call_timing(call, [], self.frozen['experiment'])['format_error'],
                         {'code': 'unknown_field', 'field': 'stage_output'})

    def test_oversized_rejected_answer_keeps_only_the_capped_prefix(self):
        self.create_state(max_response_bytes=64)
        envelope, prompt = self.envelope()
        text = '```json\n' + canonical_bytes(response_fixture()).decode('utf-8') + '\n```'
        with patch('langchain_adapter.invoke_response', return_value=self.response(text=text)):
            self.code('output_limit', models.execute_call, envelope, prompt)
        rejected = self.last_receipt()['rejected_response']
        self.assertEqual((rejected['error_code'], rejected['error_field'], rejected['byte_count'], rejected['truncated']),
                         ('output_limit', 'response.bytes', len(text.encode()), True))
        self.assertEqual(self.store.read_artifact(self.trial['trial_id'], rejected['artifact']), text.encode()[:64])

    def test_rejected_answer_never_reaches_a_later_prompt(self):
        marker = 'synthetic-rejected-marker-7f3a'
        envelope, prompt = self.envelope()
        with patch('langchain_adapter.invoke_response', return_value=self.response(text='{"' + marker + '": ')):
            self.code('invalid_response', models.execute_call, envelope, prompt)
        rejected = self.last_receipt()['rejected_response']
        self.assertIn(marker.encode(), self.store.read_artifact(self.trial['trial_id'], rejected['artifact']))
        # The next attempt's canonical prompt is rebuilt from frozen inputs only.
        retry = copy.deepcopy(envelope)
        retry['call_id'] = 'synthetic-call-scope-2'
        retry['spec']['attempt_index'] = 2
        sent = []
        def invoke(actual_prompt, *args, **kwargs):
            sent.append(actual_prompt)
            return self.response()
        with patch('langchain_adapter.invoke_response', side_effect=invoke):
            models.execute_call(retry, prompt)
        self.assertEqual(len(sent), 1)
        self.assertNotIn(marker, sent[0])
        self.assertEqual(sent[0].encode(), runner.build_prompt(self.store, self.trial, 'scope'))

    def test_structured_output_requests_the_stage_schema(self):
        self.create_state(structured=True)
        envelope, prompt = self.envelope()
        received = {}
        def invoke(actual_prompt, provider, model, base_url, timeout, **kwargs):
            received.update(kwargs)
            return self.response()
        with patch('langchain_adapter.invoke_response', side_effect=invoke):
            result = models.execute_call(envelope, prompt)
        self.assertEqual(result['receipt']['status'], 'completed')
        self.assertEqual(received.pop('response_schema'), stage_output_schema('scope', self.evidence))
        self.assertEqual(received, {'max_output_tokens': 2048, 'temperature': 0.2, 'seed': 1729})
        # The setting is part of the model spec, so of the call fingerprint.
        self.assertIs(envelope['spec']['model']['parameters']['structured_output'], True)
        self.assertEqual(self.store.calls()[0]['fingerprint'], digest_bytes(canonical_bytes(envelope['spec'])))

    def test_structured_output_still_validates_authoritatively(self):
        self.create_state(structured=True)
        envelope, prompt = self.envelope()
        output = response_fixture()
        output['findings'] = [dict(finding_id='f1', asset_id=self.evidence['assets'][0]['asset_id'], technique_id=None,
                                   window_utc={'start_inclusive': '2026-01-01T00:05:00Z',
                                               'end_exclusive': '2026-01-01T00:00:00Z'},
                                   disposition='benign', confidence=None, event_ids=[], rationale='Synthetic.')]
        with patch('langchain_adapter.invoke_response', return_value=self.response(text=canonical_bytes(output).decode())):
            self.code('invalid_response', models.execute_call, envelope, prompt)
        rejected = self.last_receipt()['rejected_response']
        self.assertEqual((rejected['error_code'], rejected['error_field']),
                         ('invalid_window', 'stage_output.findings.window_utc'))

    def test_inline_reasoning_block_is_discarded_before_validation_and_storage(self):
        envelope, prompt = self.envelope()
        answer = canonical_bytes(response_fixture()).decode('utf-8')
        with patch('langchain_adapter.invoke_response',
                   return_value=self.response(text='<think>\nprivate deliberation\n</think>\n\n' + answer)):
            result = models.execute_call(envelope, prompt)
        stored = self.store.read_artifact(self.trial['trial_id'], self.last_receipt()['response_artifact'])
        self.assertEqual(stored, answer.encode('utf-8').strip())
        self.assertNotIn(b'private deliberation', stored)
        self.assertEqual(result['output']['stage_key'], 'scope')

    def test_timeout_preserves_unknown_without_redispatch(self):
        envelope, prompt = self.envelope()
        with patch('langchain_adapter.invoke_response', side_effect=TimeoutError(SECRET)) as invoke:
            self.code('timeout', models.execute_call, envelope, prompt)
            self.code('previous_dispatch_unknown', models.execute_call, envelope, prompt)
        self.assertEqual(invoke.call_count, 1)
        self.assertEqual(self.last_receipt()['status'], 'unknown')
        self.assertIsNone(self.last_receipt()['usage']['input_tokens'])

    def test_transport_error_never_stores_exception_or_retries(self):
        envelope, prompt = self.envelope()
        with patch('langchain_adapter.invoke_response', side_effect=RuntimeError(SECRET)) as invoke:
            self.code('transport_failed', models.execute_call, envelope, prompt)
        self.assertEqual(invoke.call_count, 1)
        self.assertNotIn(SECRET, canonical_bytes(self.store.snapshot(self.trial['experiment_id'])).decode())

    def test_persistence_failure_leaves_reservation_unknown(self):
        envelope, prompt = self.envelope()
        with patch('langchain_adapter.invoke_response', return_value=self.response()) as invoke:
            with patch.object(BenchmarkStore, 'finish_call', side_effect=OSError('synthetic disk failure')):
                with self.assertRaises(OSError):
                    models.execute_call(envelope, prompt)
            self.code('previous_dispatch_unknown', models.execute_call, envelope, prompt)
        self.assertEqual(invoke.call_count, 1)
        self.assertEqual(self.store.calls()[0]['status'], 'reserved')
        self.assertIsNone(self.store.calls()[0]['receipt'])

    def test_fingerprint_canonical_prompt_and_runtime_fields_rejected_before_transport(self):
        envelope, prompt = self.envelope()
        with patch('langchain_adapter.invoke_response') as invoke:
            changed = copy.deepcopy(envelope)
            changed['spec']['adapter_sha256'] = '0' * 64
            self.code('fingerprint_conflict', models.execute_call, changed, prompt)
            self.code('fingerprint_conflict', models.execute_call, envelope, b'arbitrary ledger paths')
            self.code('invalid_fields', models.execute_call, dict(envelope, credentials=SECRET), prompt)
        invoke.assert_not_called()
        self.assertEqual(self.store.calls(), [])

    def test_reserved_call_never_dispatches(self):
        envelope, prompt = self.envelope()
        self.store.reserve_call(envelope['call_id'], digest_bytes(canonical_bytes(envelope['spec'])), envelope['spec'])
        with patch('langchain_adapter.invoke_response') as invoke:
            self.code('previous_dispatch_unknown', models.execute_call, envelope, prompt)
        invoke.assert_not_called()

    def test_concurrent_child_requests_have_one_dispatch_owner(self):
        envelope, prompt = self.envelope()
        entered, release = threading.Event(), threading.Event()
        outcomes = []
        def transport(*args, **kwargs):
            entered.set()
            if not release.wait(10):
                raise TimeoutError('Synthetic synchronization deadline')
            return self.response()
        def first():
            try:
                outcomes.append(models.execute_call(envelope, prompt))
            except BaseException as exc:
                outcomes.append(exc)
        with patch('langchain_adapter.invoke_response', side_effect=transport) as invoke:
            worker = threading.Thread(target=first)
            worker.start()
            try:
                self.assertTrue(entered.wait(10))
                self.code('previous_dispatch_unknown', models.execute_call, envelope, prompt)
            finally:
                release.set()
                worker.join(10)
        self.assertFalse(worker.is_alive())
        self.assertEqual(invoke.call_count, 1)
        self.assertEqual(len(outcomes), 1)
        self.assertIsInstance(outcomes[0], dict)

    def test_cli_rejects_unconfined_spec_without_parsing_stdin(self):
        process = subprocess.run([sys.executable, '-B', str(Path(models.__file__)), '--state-root', str(self.root),
                                  '--call-id', 'synthetic-call', '--call-spec', str(Path(models.__file__))],
                                 input=(SECRET + ' /untrusted/ledger/path').encode(), stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, timeout=30)
        self.assertEqual(process.returncode, 2)
        self.assertEqual(process.stdout, b'')
        self.assertNotIn(SECRET.encode(), process.stderr)
        self.assertEqual(self.store.calls(), [])

    def test_nonexistent_citations_remain_structured_model_errors(self):
        envelope, prompt = self.envelope()
        output = response_fixture()
        output['claims'] = [dict(claim_id='invented', kind='observation', text='Synthetic unsupported assertion.', event_ids=['absent'])]
        with patch('langchain_adapter.invoke_response', return_value=self.response(text=canonical_bytes(output).decode())):
            result = models.execute_call(envelope, prompt)
        self.assertEqual(result['output']['claims'][0]['event_ids'], ['absent'])


class BenchmarkCheckerConsumerTests(ModelFixture, unittest.TestCase):
    def setUp(self):
        self.create_state(checker=True)
        # Test the child consumer independently of prerequisite human decisions;
        # canonical prompt construction itself is exercised in core/runner tests.
        self.prompt = b'{"synthetic_checker_consumer_fixture":true}'
        self.prompt_patch = patch('benchmark_runner.build_prompt', return_value=self.prompt)
        self.prompt_patch.start()
        self.addCleanup(self.prompt_patch.stop)

    def candidate(self, valid=True):
        output = response_fixture('analysis')
        output['claims'] = [dict(claim_id='claim-a', kind='observation', text='Synthetic cited assertion.',
                                 event_ids=[self.evidence['events'][0]['event_id']] if valid else [])]
        return output

    def test_all_invalid_citations_never_dispatch_checker(self):
        envelope, prompt = self.envelope('analysis')
        with patch('langchain_adapter.invoke_response', return_value=self.response('analysis', text=canonical_bytes(self.candidate(False)).decode())), patch('benchmark_typesafe.invoke_checker') as checker:
            result = models.execute_call(envelope, prompt)
        checker.assert_not_called()
        self.assertEqual(len(self.store.calls()), 1)
        self.assertEqual(result['checker']['origin'], 'validator')
        self.assertEqual(result['checker']['results'][0]['reason'], 'invalid_or_missing_citation')

    def test_checker_has_separate_receipt_and_does_not_rewrite_narrative(self):
        envelope, prompt = self.envelope('analysis')
        candidate = self.candidate()
        normalized = dict(model_returned='jev-1.14.0', identity_status='reported_match', finish_reason=None,
                          usage=dict.fromkeys(models.TOKEN_FIELDS),
                          results=[dict(claim_id='claim-a', choice='supported', confidence=0.8,
                                        probabilities={'supported': 0.8, 'contradicted': 0.1, 'insufficient': 0.1},
                                        origin='typesafe', reason=None)])
        with patch('langchain_adapter.invoke_response', return_value=self.response('analysis', text=canonical_bytes(candidate).decode())) as narrative, patch('benchmark_typesafe.invoke_checker', return_value=normalized) as checker:
            result = models.execute_call(envelope, prompt)
            again = models.execute_call(envelope, prompt)
        self.assertEqual(narrative.call_count, 1)
        self.assertEqual(checker.call_count, 1)
        self.assertEqual(result, again)
        self.assertEqual(result['output'], candidate)
        calls = self.store.calls()
        self.assertEqual({call['spec']['component'] for call in calls}, {'narrative', 'evidence_checker'})
        checker_call = next(call for call in calls if call['spec']['component'] == 'evidence_checker')
        self.assertEqual(checker_call['status'], 'completed')
        self.assertEqual(result['checker']['narrative_sha256'], result['receipt']['response_sha256'])

    def test_checker_failure_fails_composite_but_retains_narrative(self):
        envelope, prompt = self.envelope('analysis')
        with patch('langchain_adapter.invoke_response', return_value=self.response('analysis', text=canonical_bytes(self.candidate()).decode())), patch('benchmark_typesafe.invoke_checker', side_effect=BenchmarkError('timeout', 'checker')) as checker:
            self.code('timeout', models.execute_call, envelope, prompt)
            self.code('previous_dispatch_unknown', models.execute_call, envelope, prompt)
        self.assertEqual(checker.call_count, 1)
        calls = {call['spec']['component']: call for call in self.store.calls()}
        self.assertEqual(calls['narrative']['status'], 'completed')
        self.assertEqual(calls['evidence_checker']['status'], 'unknown')
        self.assertIsNotNone(calls['narrative']['receipt']['response_artifact'])


SDK_AVAILABLE = (sys.version_info >= (3, 10) and all(importlib.util.find_spec(name) is not None
                 for name in ('langchain', 'langchain_openai')))


@unittest.skipUnless(SDK_AVAILABLE, 'optional LangChain OpenAI SDK is not installed')
class BenchmarkSDKLoopbackTests(ModelFixture, unittest.TestCase):
    def setUp(self):
        self.requests = []
        self.http_status = 200
        self.response_model = MODEL
        self.finish_reason = 'stop'
        self.delay = 0
        owner = self
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass
            def do_POST(self):
                payload = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                owner.requests.append((self.path, payload, self.headers.get('Authorization')))
                time.sleep(owner.delay)
                body = dict(id='synthetic-response', object='chat.completion', created=1, model=owner.response_model,
                            choices=[dict(index=0, message=dict(role='assistant', content=canonical_bytes(response_fixture()).decode()),
                                          finish_reason=owner.finish_reason)])
                if owner.http_status != 200:
                    body = {'error': {'message': SECRET, 'type': 'synthetic_rate_limit', 'code': 'rate_limit'}}
                data = canonical_bytes(body)
                self.send_response(owner.http_status)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(data)))
                self.end_headers()
                try:
                    self.wfile.write(data)
                except (BrokenPipeError, ConnectionResetError):
                    pass
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.create_state('http://127.0.0.1:%s/v1' % self.server.server_port, timeout=0.25, sdk_stub=False)

    def child(self):
        envelope, _ = self.envelope()
        ref = self.store.write_artifact(self.trial['trial_id'], 'specs', canonical_bytes(envelope['spec']))
        path = self.root / 'trials' / self.trial['trial_id'] / ref['path']
        return subprocess.run([sys.executable, '-B', str(Path(models.__file__)), '--state-root', str(self.root),
                               '--call-id', envelope['call_id'], '--call-spec', str(path)],
                              input=b'Untrusted ledger stdin /not/a/real/file', stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, env=runner._environment(envelope['spec']['model']), timeout=30)

    def test_actual_sdk_cli_authentic_output_and_one_request(self):
        process = self.child()
        self.assertEqual(process.returncode, 0, process.stderr.decode())
        self.assertEqual(decode_json(process.stdout), response_fixture())
        self.assertEqual(len(self.requests), 1)
        path, body, auth = self.requests[0]
        self.assertEqual(path, '/v1/chat/completions')
        self.assertEqual(auth, 'Bearer ' + SECRET)
        self.assertEqual(body['model'], MODEL)
        self.assertNotIn('tools', body)
        self.assertEqual(body.get('max_completion_tokens', body.get('max_tokens')), 2048)
        self.assertEqual(body['seed'], 1729)
        self.assertEqual(self.last_receipt()['identity_status'], 'reported_match')
        self.assertIsNone(self.last_receipt()['usage']['input_tokens'])
        self.assertNotIn(SECRET.encode(), process.stdout + process.stderr)

    def test_actual_sdk_structured_output_sends_the_stage_schema(self):
        self.create_state('http://127.0.0.1:%s/v1' % self.server.server_port, timeout=5, sdk_stub=False,
                          structured=True)
        process = self.child()
        self.assertEqual(process.returncode, 0, process.stderr.decode())
        self.assertEqual(len(self.requests), 1)
        _, body, _ = self.requests[0]
        self.assertEqual(body['response_format'], {'type': 'json_schema', 'json_schema': {
            'name': 'stage_output', 'strict': True, 'schema': stage_output_schema('scope', self.evidence)}})
        self.assertNotIn('extra_body', body)
        self.assertEqual(self.last_receipt()['status'], 'completed')

    def test_actual_sdk_structured_truncation_keeps_metadata_and_rejected_answer(self):
        self.create_state('http://127.0.0.1:%s/v1' % self.server.server_port, timeout=5, sdk_stub=False,
                          structured=True)
        self.finish_reason = 'length'
        process = self.child()
        self.assertEqual(process.returncode, 1)
        self.assertEqual(len(self.requests), 1)
        receipt = self.last_receipt()
        self.assertEqual((receipt['failure_reason'], receipt['finish_reason'], receipt['model_returned']),
                         ('output_limit', 'length', MODEL))
        rejected = receipt['rejected_response']
        self.assertEqual((rejected['error_code'], rejected['error_field']), ('output_limit', 'response.finish_reason'))
        self.assertEqual(self.store.read_artifact(self.trial['trial_id'], rejected['artifact']),
                         canonical_bytes(response_fixture()))

    def test_actual_sdk_429_does_not_retry_or_log_provider_body(self):
        self.http_status = 429
        process = self.child()
        self.assertEqual(process.returncode, 1)
        self.assertEqual(len(self.requests), 1)
        self.assertEqual(process.stdout, b'')
        self.assertNotIn(SECRET.encode(), process.stderr)
        self.assertEqual(self.last_receipt()['failure_reason'], 'transport_failed')

    def test_actual_sdk_model_mismatch_is_closed(self):
        self.response_model = 'wrong-version'
        process = self.child()
        self.assertEqual(process.returncode, 1)
        self.assertEqual(process.stdout, b'')
        self.assertEqual(len(self.requests), 1)
        self.assertEqual(self.last_receipt()['model_returned'], 'wrong-version')
        self.assertEqual(self.last_receipt()['failure_reason'], 'model_identity_mismatch')

    def test_actual_sdk_timeout_is_unknown_and_not_retried(self):
        self.delay = 1
        process = self.child()
        self.assertEqual(process.returncode, 1)
        self.assertEqual(process.stdout, b'')
        self.assertEqual(len(self.requests), 1)
        self.assertEqual(self.last_receipt()['status'], 'unknown')
        self.assertEqual(self.last_receipt()['failure_reason'], 'timeout')


if __name__ == '__main__':
    unittest.main()

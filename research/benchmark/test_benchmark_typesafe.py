"""Real loopback System One protocol fixtures, not model quality evidence."""
import copy
import io
import os
from contextlib import redirect_stderr, redirect_stdout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import threading
import time
import unittest
from unittest.mock import patch

from benchmark_contracts import BenchmarkError, validate_team
from benchmark_decisions import checker_validator_output
import benchmark_typesafe as checker
from envision_protocol import decode_json, encode_json


TOKEN = 'synthetic-checker-credential-not-a-live-key'
ENV_NAME = 'BENCH_MODEL_TYPESAFE_TEST_KEY'


def model(base='https://api.example.test'):
    return {'adapter': 'typesafe', 'provider': 'typesafe', 'model_requested': 'jev-1.14.0',
            'base_url': base, 'credential_env': ENV_NAME,
            'parameters': {'temperature': None, 'seed': None},
            'timeout_seconds': 2, 'max_output_tokens': None,
            'expected_model_ids': ['jev-1.14.0']}


def public_fixture():
    path = Path(__file__).parent / 'benchmarks/fixtures/case-8b42/public/evidence.json'
    return decode_json(path.read_bytes())


def candidate(public):
    event_id = public['events'][0]['event_id']
    return {'schema_version': 1, 'stage_key': 'analysis', 'summary': 'Synthetic transport fixture.',
            'claims': [{'claim_id': 'claim-a', 'kind': 'observation',
                        'text': 'Synthetic claim, not a model result.', 'event_ids': [event_id]}],
            'findings': [], 'hypotheses': [], 'gaps': [], 'limitations': [],
            'requested_decision': 'approve'}


def response(request):
    return {'model': 'jev-1.14.0', 'answers': {
        key: {'type': 'choice', 'choice': 'supported', 'confidence': 0.6,
              'probabilities': {'supported': 0.8, 'contradicted': 0.15, 'insufficient': 0.05}}
        for key in request['questions']}, 'usage': {'input_tokens': 42, 'output_tokens': 6}}


class RequestTests(unittest.TestCase):
    def setUp(self):
        self.public = public_fixture()
        self.candidate = candidate(self.public)
        self.model = model()

    def test_batch_is_bound_to_explicit_claim_and_only_its_cited_events(self):
        other = copy.deepcopy(self.candidate['claims'][0])
        other['claim_id'] = 'claim-b'
        other['event_ids'] = [self.public['events'][-1]['event_id']]
        self.candidate['claims'].append(other)
        request, invalid = checker.build_checker_request(self.candidate, self.public, self.model)
        self.assertEqual(invalid, [])
        self.assertEqual(set(request), {'model', 'state', 'questions'})
        self.assertEqual(set(request['state']), {'claims'})
        self.assertEqual(set(request['questions']), {'claim-a', 'claim-b'})
        for claim in self.candidate['claims']:
            key = claim['claim_id']
            item = request['state']['claims'][key]
            self.assertEqual(item['claim'], claim)
            self.assertEqual([event['event_id'] for event in item['events']], claim['event_ids'])
            self.assertIn('state.claims["' + key + '"]', request['questions'][key]['instructions'])
            self.assertEqual(set(request['questions'][key]['criteria']), set(checker.CHOICES))
        request['state']['claims']['claim-a']['events'][0]['event_type'] = 'mutated-copy'
        self.assertNotEqual(self.public['events'][0]['event_type'], 'mutated-copy')

    def test_empty_and_invalid_candidates_match_existing_validator_artifact(self):
        for citations in ([], ['unknown-event'], [self.public['events'][0]['event_id'], 'unknown-event']):
            with self.subTest(citations=citations):
                self.candidate['claims'][0]['event_ids'] = citations
                request, invalid = checker.build_checker_request(self.candidate, self.public, self.model)
                self.assertIsNone(request)
                appendix = checker.assemble_checker(self.candidate, self.public, 'a' * 64,
                                                    self.model, None, invalid, None)
                self.assertEqual(appendix, checker_validator_output(self.candidate, self.public, 'a' * 64))
        self.candidate['claims'] = []
        request, invalid = checker.build_checker_request(self.candidate, self.public, self.model)
        self.assertIsNone(request)
        self.assertEqual(invalid, [])

    def test_no_narrative_stage_or_generation_parameters(self):
        self.candidate['stage_key'] = 'scope'
        with self.assertRaises(BenchmarkError):
            checker.build_checker_request(self.candidate, self.public, self.model)
        self.candidate['stage_key'] = 'analysis'
        for changes in ({'max_output_tokens': 8}, {'parameters': {'temperature': 0.1, 'seed': None}},
                        {'adapter': 'langchain'}, {'provider': 'openai'}):
            with self.subTest(changes=changes), self.assertRaises(BenchmarkError):
                checker.build_checker_request(self.candidate, self.public, {**self.model, **changes})

    def test_typesafe_rejected_as_narrative_role(self):
        from benchmark_contracts import ROLE_IDS
        team = {'team_id': 'test-only', 'deployment': 'local',
                'roles': {role: self.model for role in ROLE_IDS},
                'runtime_facts': dict.fromkeys(('server', 'server_version', 'model_weight_sha256',
                                               'quantization', 'context_configuration', 'cpu', 'gpu',
                                               'ram_bytes', 'concurrency'))}
        with self.assertRaises(BenchmarkError):
            validate_team(team)


class TransportTests(unittest.TestCase):
    def setUp(self):
        self.public = public_fixture()
        self.candidate = candidate(self.public)
        self.hits = []
        self.status = 200
        self.raw = None
        self.delay = 0
        self.transform = lambda payload: payload
        fixture = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                request = decode_json(self.rfile.read(int(self.headers['Content-Length'])))
                fixture.hits.append({'path': self.path, 'method': self.command,
                                     'request': request, 'headers': set(self.headers.keys()),
                                     'authenticated': self.headers.get('Authorization') == 'Bearer ' + TOKEN})
                if fixture.delay:
                    time.sleep(fixture.delay)
                self.send_response(fixture.status)
                if fixture.status in (301, 302, 307, 308):
                    self.send_header('Location', fixture.base + '/must-not-follow')
                body = (fixture.raw if fixture.raw is not None
                        else encode_json(fixture.transform(response(request))))
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                try:
                    self.wfile.write(body)
                except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                    pass

        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.thread = threading.Thread(target=lambda: self.server.serve_forever(poll_interval=0.01), daemon=True)
        self.thread.start()
        self.base = 'http://127.0.0.1:' + str(self.server.server_address[1])
        self.model = model(self.base)
        self.environment = patch.dict(os.environ, {ENV_NAME: TOKEN})
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.addCleanup(self.stop)

    def stop(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    def invoke(self, cap=4096):
        request, invalid = checker.build_checker_request(self.candidate, self.public, self.model)
        if request is None:
            return None, invalid
        return checker.invoke_checker(self.model, request, cap), invalid

    def test_authentic_response_and_mixed_validator_appendix(self):
        self.candidate['claims'].append({'claim_id': 'invalid-claim', 'kind': 'inference',
                                         'text': 'Uncited synthetic assertion.', 'event_ids': []})
        result, invalid = self.invoke()
        self.assertEqual(result['results'][0]['confidence'], 0.6)
        self.assertEqual(result['results'][0]['probabilities']['supported'], 0.8)
        self.assertEqual(result['usage'], {'input_tokens': 42, 'output_tokens': 6,
                                           'cached_input_tokens': None, 'reasoning_tokens': None})
        self.assertIsNone(result['finish_reason'])
        self.assertEqual(result['identity_status'], 'reported_match')
        before = encode_json(self.candidate)
        appendix = checker.assemble_checker(self.candidate, self.public, 'b' * 64,
                                            self.model, result, invalid, 17)
        self.assertEqual(encode_json(self.candidate), before)
        self.assertEqual(appendix['narrative_sha256'], 'b' * 64)
        self.assertEqual(appendix['elapsed_ms'], 17)
        self.assertEqual(appendix['model_returned'], 'jev-1.14.0')
        self.assertEqual(appendix['results'][1], {
            'claim_id': 'invalid-claim', 'choice': 'insufficient', 'confidence': None,
            'probabilities': None, 'origin': 'validator', 'reason': 'invalid_or_missing_citation'})
        self.assertEqual(len(self.hits), 1)
        self.assertEqual(self.hits[0]['path'], '/v1/systemone')
        self.assertTrue(self.hits[0]['authenticated'])
        self.assertNotIn('TypeSafe-Danger-Zone-Images', self.hits[0]['headers'])
        self.assertNotIn('TypeSafe-Danger-Zone-Long-Context', self.hits[0]['headers'])
        self.assertEqual(set(self.hits[0]['request']['questions']), {'claim-a'})
        self.assertNotIn(TOKEN, encode_json(appendix).decode())

    def test_missing_usage_stays_null(self):
        for usage in ('absent', None, {}, {'input_tokens': 4}):
            def transform(payload):
                if usage == 'absent':
                    payload.pop('usage')
                else:
                    payload['usage'] = usage
                return payload
            self.transform = transform
            with self.subTest(usage=usage):
                result, _ = self.invoke()
                self.assertIsNone(result['usage']['output_tokens'])
                self.assertEqual(result['usage']['input_tokens'], 4 if usage == {'input_tokens': 4} else None)

    def test_mismatch_metadata_preserved_but_appendix_fails(self):
        self.transform = lambda payload: {**payload, 'model': 'jev-other-version'}
        result, invalid = self.invoke()
        self.assertEqual(result['identity_status'], 'reported_mismatch')
        self.assertEqual(result['model_returned'], 'jev-other-version')
        with self.assertRaises(BenchmarkError) as raised:
            checker.assemble_checker(self.candidate, self.public, 'a' * 64,
                                     self.model, result, invalid, 1)
        self.assertEqual(raised.exception.code, 'model_mismatch')
        self.assertEqual(len(self.hits), 1)

    def test_two_valid_claims_share_one_http_request(self):
        other = copy.deepcopy(self.candidate['claims'][0])
        other['claim_id'] = 'claim-b'
        other['event_ids'] = [self.public['events'][-1]['event_id']]
        self.candidate['claims'].append(other)
        result, invalid = self.invoke()
        self.assertEqual(invalid, [])
        self.assertEqual(len(self.hits), 1)
        self.assertEqual(set(self.hits[0]['request']['questions']), {'claim-a', 'claim-b'})
        self.assertEqual([item['claim_id'] for item in result['results']], ['claim-a', 'claim-b'])

    def test_appendix_rejects_tampered_results_and_binding(self):
        result, invalid = self.invoke()
        for field, value in (('confidence', True), ('choice', 'invented'),
                             ('origin', 'validator'), ('reason', 'invented')):
            changed = copy.deepcopy(result)
            changed['results'][0][field] = value
            with self.subTest(field=field), self.assertRaises(BenchmarkError):
                checker.assemble_checker(self.candidate, self.public, 'a' * 64,
                                         self.model, changed, invalid, 1)
        with self.assertRaises(BenchmarkError):
            checker.assemble_checker(self.candidate, self.public, 'invalid-digest',
                                     self.model, result, invalid, 1)
        with self.assertRaises(BenchmarkError):
            checker.assemble_checker(self.candidate, self.public, 'a' * 64,
                                     self.model, result, [{'claim_id': 'invented'}], 1)

    def test_http_failures_do_not_retry_redirect_or_leak(self):
        self.raw = TOKEN.encode()
        for status in (429, 307, 302, 401, 403, 500):
            self.status = status
            previous = len(self.hits)
            stdout, stderr = io.StringIO(), io.StringIO()
            with self.subTest(status=status), redirect_stdout(stdout), redirect_stderr(stderr):
                with self.assertRaises(BenchmarkError) as raised:
                    self.invoke()
                self.assertEqual(raised.exception.code,
                                 'authentication_failed' if status in (401, 403) else 'upstream_http_error')
                self.assertNotIn(TOKEN, str(raised.exception))
                self.assertEqual(stdout.getvalue() + stderr.getvalue(), '')
                self.assertEqual(len(self.hits), previous + 1)
                self.assertEqual(self.hits[-1]['path'], '/v1/systemone')

    def test_timeout_is_one_request_with_no_fallback(self):
        self.model['timeout_seconds'] = 0.05
        self.delay = 0.2
        with self.assertRaises(BenchmarkError) as raised:
            self.invoke()
        self.assertEqual(raised.exception.code, 'timeout')
        self.assertEqual(len(self.hits), 1)

    def test_response_cap_applies_to_wire_bytes_not_reserialized_json(self):
        self.raw = b' ' * 1025 + b'{}'
        with self.assertRaises(BenchmarkError) as raised:
            self.invoke(cap=1024)
        self.assertEqual(raised.exception.code, 'response_too_large')
        self.assertEqual(len(self.hits), 1)

    def test_malformed_duplicate_and_nonfinite_wire_json(self):
        for raw in (b'{', b'\xff', b'{"model":"x","model":"y"}', b'{"n":NaN}'):
            self.raw = raw
            with self.subTest(raw=raw), self.assertRaises(BenchmarkError):
                self.invoke()

    def test_strict_choice_shapes_and_probabilities(self):
        request, _ = checker.build_checker_request(self.candidate, self.public, self.model)
        valid = response(request)
        malformed = []
        for mutation in (
            lambda p: p.update(extra='forbidden'),
            lambda p: p.pop('model'),
            lambda p: p['answers'].update(extra=p['answers']['claim-a']),
            lambda p: p['answers'].clear(),
            lambda p: p['answers']['claim-a'].update(type='score'),
            lambda p: p['answers']['claim-a'].update(choice='maybe'),
            lambda p: p['answers']['claim-a'].update(confidence=True),
            lambda p: p['answers']['claim-a'].update(confidence=2),
            lambda p: p['answers']['claim-a'].update(extra='private'),
            lambda p: p['answers']['claim-a']['probabilities'].update(supported=0.7),
            lambda p: p['answers']['claim-a']['probabilities'].update(supported=-1),
            lambda p: p['answers']['claim-a']['probabilities'].update(supported=True),
            lambda p: p['answers']['claim-a']['probabilities'].update(extra=0),
            lambda p: p['usage'].update(input_tokens=True),
            lambda p: p['usage'].update(output_tokens=-1),
            lambda p: p['usage'].update(extra=1),
        ):
            payload = copy.deepcopy(valid)
            mutation(payload)
            malformed.append(encode_json(payload))
        malformed.append(encode_json(valid).replace(b'0.6', b'1e999'))
        malformed.append(encode_json(valid).replace(b'0.6', b'1' + b'0' * 400))
        for raw in malformed:
            self.raw = raw
            with self.subTest(raw=raw), self.assertRaises(BenchmarkError):
                self.invoke()

    def test_null_confidence_is_not_filled_from_probabilities(self):
        def transform(payload):
            payload['answers']['claim-a']['confidence'] = None
            return payload
        self.transform = transform
        result, _ = self.invoke()
        self.assertIsNone(result['results'][0]['confidence'])
        self.assertEqual(result['results'][0]['probabilities']['supported'], 0.8)

    def test_invalid_and_empty_claims_make_no_http_request(self):
        for citations in ([], ['missing']):
            self.candidate['claims'][0]['event_ids'] = citations
            result, _ = self.invoke()
            self.assertIsNone(result)
        self.candidate['claims'] = []
        self.assertIsNone(self.invoke()[0])
        self.assertEqual(self.hits, [])

    def test_invalid_origins_credentials_caps_and_request_fail_before_http(self):
        request, _ = checker.build_checker_request(self.candidate, self.public, self.model)
        for base in ('http://localhost:1234', 'http://192.0.2.1', self.base + '/v1',
                     self.base + '?key=private', 'https://user:private@example.test'):
            with self.subTest(base=base), self.assertRaises(BenchmarkError):
                checker.invoke_checker({**self.model, 'base_url': base}, request, 4096)
        for cap in (0, -1, True, 1024 * 1024 + 1):
            with self.subTest(cap=cap), self.assertRaises(BenchmarkError) as raised:
                checker.invoke_checker(self.model, request, cap)
            self.assertEqual(raised.exception.code, 'configuration_invalid')
        for token in ('', 'invalid\nheader'):
            with patch.dict(os.environ, {ENV_NAME: token}), self.assertRaises(BenchmarkError) as raised:
                checker.invoke_checker(self.model, request, 4096)
            self.assertEqual(raised.exception.code, 'credential_unavailable')
        for key, value in (('assets', {}), ('headers', {}), ('url', 'https://example.test')):
            with self.subTest(key=key), self.assertRaises(BenchmarkError):
                checker.invoke_checker(self.model, {**request, key: value}, 4096)
        self.assertEqual(self.hits, [])


if __name__ == '__main__':
    unittest.main()

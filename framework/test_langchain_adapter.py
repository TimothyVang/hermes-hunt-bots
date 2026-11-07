"""Bounded input/output and CLI safety tests; no mocked provider or model calls."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import threading
import unittest
from unittest.mock import patch

import langchain_adapter as adapter


ADAPTER = Path(__file__).resolve().with_name('langchain_adapter.py')


class AdapterInputTests(unittest.TestCase):
    def call(self, *args, prompt=b'Benign local task', no_site=True):
        command = [sys.executable]
        if no_site:
            command.append('-S')
        return subprocess.run([*command, str(ADAPTER), *args], input=prompt,
                              capture_output=True, timeout=30)

    def test_entire_utf8_prompt_is_preserved_and_never_truncated(self):
        prompt = '\nRole instructions\nUntrusted task: caf\u00e9\nFinal acceptance line\n'
        self.assertEqual(adapter.read_prompt(io.BytesIO(prompt.encode('utf-8'))), prompt)
        limit = b'x' * adapter.MAX_PROMPT_BYTES
        self.assertEqual(adapter.read_prompt(io.BytesIO(limit)), limit.decode('ascii'))
        for invalid in (b'', b'\n \t', b'\xff', limit + b'x'):
            with self.subTest(length=len(invalid)), self.assertRaises(adapter.AdapterProblem):
                adapter.read_prompt(io.BytesIO(invalid))

    def test_url_accepts_only_approved_transport_shape(self):
        for valid in ('https://api.example.org/v1', 'https://api.example.org:443/proxy/openai/v1',
                      'http://127.0.0.1:8000/v1', 'http://[::1]:8000/v1', 'http://localhost:8000/v1'):
            self.assertEqual(adapter.validate_base_url(valid), valid)
        for invalid in ('http://api.example.org/v1', 'http://localhost.example.org/v1',
                        'https://user:private-test-marker@api.example.org/v1',
                        'https://api.example.org/v1?token=private-test-marker',
                        'https://api.example.org/v1#private-test-marker',
                        'https://api.example.org:0/v1', 'https://api.example.org:99999/v1',
                        'https://api.example.org:bad/v1', 'file:///tmp/model',
                        'https:///v1', 'https://api.example.org/\nsecret',
                        'https://api.example.org\\@other.example.org/v1'):
            with self.subTest(url=invalid), self.assertRaises(adapter.AdapterProblem):
                adapter.validate_base_url(invalid)

    def test_cli_requires_explicit_provider_model_and_never_quotes_bad_values(self):
        marker = 'do-not-echo-this-test-marker'
        cases = [(), ('--provider', 'openai'), ('--model', 'local-model'),
                 ('--provider', marker, '--model', 'local-model'),
                 ('--provider', 'openai', '--model', 'local-model', '--api-key', marker),
                 ('--provider', 'openai', '--model', marker + '\ninvalid'),
                 ('--provider', 'openai', '--model', 'local-model', '--request-timeout', 'nan')]
        for arguments in cases:
            with self.subTest(arguments=arguments):
                result = self.call(*arguments)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, b'')
                self.assertNotIn(marker.encode(), result.stderr)
                self.assertNotIn(b'Traceback', result.stderr)

    def test_invalid_prompt_and_endpoint_fail_before_optional_imports(self):
        common = ('--provider', 'openai', '--model', 'local-model')
        for prompt in (b'\n ', b'\xff', b'x' * (adapter.MAX_PROMPT_BYTES + 1)):
            result = self.call(*common, prompt=prompt)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, b'')
            self.assertNotIn(b'optional dependencies', result.stderr)
            self.assertNotIn(b'Traceback', result.stderr)
        marker = 'do-not-echo-this-test-marker'
        result = self.call(*common, '--base-url', 'https://host.example/v1?key=' + marker)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn(marker.encode(), result.stderr)
        result = self.call('--provider', 'anthropic', '--model', 'local-model',
                           '--base-url', 'https://host.example/v1')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'only with --provider openai', result.stderr)

    def test_missing_optional_packages_fail_without_a_handoff(self):
        result = self.call('--provider', 'openai', '--model', 'local-model')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b'')
        self.assertTrue(b'optional dependencies unavailable' in result.stderr
                        or b'requires Python 3.10' in result.stderr, result.stderr)
        self.assertNotIn(b'Traceback', result.stderr)


class AdapterParameterTests(unittest.TestCase):
    """Pure validation; runs without the optional SDK and never sends anything."""

    def test_valid_parameters_are_accepted(self):
        adapter.validate_parameters('openai', 2048, 2, 0)
        adapter.validate_parameters('openai', None, None, None)
        adapter.validate_parameters('anthropic', 1024, 1, None)

    def test_unsupported_parameters_are_refused_not_dropped(self):
        cases = [('anthropic', None, None, 1729), ('anthropic', None, 1.5, None),
                 ('openai', None, None, -1), ('openai', None, None, True),
                 ('openai', None, 2.5, None), ('openai', None, float('nan'), None),
                 ('openai', 0, None, None), ('openai', True, None, None), ('other', None, None, None)]
        for provider, tokens, temperature, seed in cases:
            with self.subTest(provider=provider, tokens=tokens, temperature=temperature, seed=seed):
                with self.assertRaises(adapter.UnsupportedParameter):
                    adapter.validate_parameters(provider, tokens, temperature, seed)

    def test_structured_output_is_boolean_and_openai_only(self):
        adapter.validate_parameters('openai', None, None, None, True)
        adapter.validate_parameters('anthropic', None, None, None, False)
        for provider, value in (('anthropic', True), ('openai', 1), ('openai', None), ('openai', 'true')):
            with self.subTest(provider=provider, value=value), self.assertRaises(adapter.UnsupportedParameter):
                adapter.validate_parameters(provider, None, None, None, value)

    def test_invoke_refuses_anthropic_schema_and_non_object_schema_before_any_import(self):
        with patch.object(adapter, 'check_prerequisites') as prerequisites:
            for provider, schema in (('anthropic', {'type': 'object'}), ('openai', ['not', 'an', 'object'])):
                with self.subTest(provider=provider), self.assertRaises(adapter.UnsupportedParameter):
                    adapter.invoke_response('Benign', provider, 'model', None, 5, response_schema=schema)
        prerequisites.assert_not_called()

    def test_invoke_refuses_anthropic_seed_before_any_import(self):
        with patch.object(adapter, 'check_prerequisites') as prerequisites:
            with self.assertRaises(adapter.UnsupportedParameter):
                adapter.invoke_response('Benign', 'anthropic', 'model', None, 5, seed=1)
        prerequisites.assert_not_called()

    def test_missing_sdk_is_a_prerequisite_failure(self):
        with patch.object(adapter, 'find_spec', return_value=None):
            with self.assertRaises(adapter.PrerequisiteMissing):
                adapter.check_prerequisites('openai')


@unittest.skipUnless(sys.version_info >= (3, 10) and all(importlib.util.find_spec(name) is not None
                     for name in ('langchain', 'langsmith', 'langchain_openai')),
                     'install the optional LangChain OpenAI dependencies with Python 3.10+')
class AdapterSDKParameterTests(unittest.TestCase):
    def test_parameter_the_chat_model_did_not_apply_is_refused(self):
        class Chat:
            max_tokens = None
            def invoke(self, *_args, **_kwargs):
                raise AssertionError('must not dispatch')
        with patch('langchain.chat_models.init_chat_model', return_value=Chat()):
            with self.assertRaises(adapter.UnsupportedParameter):
                adapter.invoke_response('Benign', 'openai', 'model', 'http://127.0.0.1:9/v1', 1,
                                        max_output_tokens=16)


SCHEMA = {'type': 'object', 'properties': {'answer': {'type': 'string', 'enum': ['ok']}},
          'required': ['answer'], 'additionalProperties': False}


@unittest.skipUnless(sys.version_info >= (3, 10) and all(importlib.util.find_spec(name) is not None
                     for name in ('langchain', 'langsmith', 'langchain_openai')),
                     'install the optional LangChain OpenAI dependencies with Python 3.10+')
class AdapterSDKStructuredOutputTests(unittest.TestCase):
    """Real SDK against a loopback protocol fixture; no model inside."""

    def setUp(self):
        self.requests, self.finish_reason = [], 'stop'
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_POST(self):
                owner.requests.append(json.loads(self.rfile.read(int(self.headers['Content-Length']))))
                data = json.dumps({'id': 'synthetic', 'object': 'chat.completion', 'created': 1,
                                   'model': 'synthetic-fixture-1',
                                   'choices': [{'index': 0, 'finish_reason': owner.finish_reason,
                                                'message': {'role': 'assistant', 'content': '{"answer": "ok"}'}}],
                                   'usage': {'prompt_tokens': 3, 'completion_tokens': 2, 'total_tokens': 5}}).encode()
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(data)))
                self.end_headers()
                self.wfile.write(data)
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        self.base_url = 'http://127.0.0.1:{}/v1'.format(server.server_address[1])

    def invoke(self, **options):
        with patch.dict('os.environ', {'OPENAI_API_KEY': 'synthetic-test-only'}):
            return adapter.invoke_response('Benign', 'openai', 'synthetic-fixture-1', self.base_url, 5, **options)

    def test_schema_is_sent_as_strict_top_level_response_format(self):
        response = self.invoke(max_output_tokens=16, response_schema=SCHEMA)
        self.assertEqual(adapter.response_text(response), '{"answer": "ok"}')
        self.assertEqual(len(self.requests), 1)
        body = self.requests[0]
        self.assertEqual(body['response_format'], {'type': 'json_schema', 'json_schema': {
            'name': 'stage_output', 'strict': True, 'schema': SCHEMA}})
        self.assertNotIn('extra_body', body)
        self.assertNotIn('tools', body)

    def test_without_schema_no_response_format_is_sent(self):
        self.invoke()
        self.assertNotIn('response_format', self.requests[0])

    def test_truncated_structured_response_is_returned_not_raised(self):
        # The `parse` path model_kwargs/bind would select raises on `length` and
        # loses the response; the ordinary path keeps it for diagnostics.
        self.finish_reason = 'length'
        response = self.invoke(response_schema=SCHEMA)
        self.assertEqual(response.response_metadata['finish_reason'], 'length')
        self.assertEqual(response.response_metadata['model_name'], 'synthetic-fixture-1')
        self.assertEqual(response.usage_metadata['output_tokens'], 2)


@unittest.skipUnless(sys.version_info >= (3, 10) and importlib.util.find_spec('langchain_core') is not None,
                     'install the optional LangChain dependencies with Python 3.10+')
class AdapterResponseTests(unittest.TestCase):
    def test_empty_reasoning_and_tool_responses_are_not_handoffs(self):
        from langchain_core.messages import AIMessage
        cases = [AIMessage(content=''), AIMessage(content=' \n'),
                 AIMessage(content=[{'type': 'reasoning', 'reasoning': 'Internal reasoning only'}]),
                 AIMessage(content='', tool_calls=[{'name': 'unbound_tool', 'args': {}, 'id': 'call-local'}]),
                 AIMessage(content='Partial text', tool_calls=[{'name': 'unbound_tool', 'args': {}, 'id': 'call-local'}]),
                 AIMessage(content='Partial text', invalid_tool_calls=[{'name': 'unbound_tool',
                           'args': '{', 'id': 'call-local', 'error': 'Invalid fixture arguments'}])]
        for message in cases:
            with self.subTest(content=message.content), self.assertRaises(adapter.AdapterProblem):
                adapter.response_text(message)


if __name__ == '__main__':
    unittest.main()

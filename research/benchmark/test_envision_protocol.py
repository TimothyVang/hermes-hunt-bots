"""Secret-free bridge boundary tests using isolated loopback HTTP fixtures."""
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import envision_protocol as protocol


MODEL = protocol.MODEL_PREFIX + 'test-only'


class ValidationTests(unittest.TestCase):
    def test_cleartext_requires_explicit_literal_loopback(self):
        self.assertEqual(protocol.origin('https://api.example.org/'), 'https://api.example.org')
        self.assertEqual(protocol.origin('http://127.0.0.1:8765/', True), 'http://127.0.0.1:8765')
        for url, allow in (
            ('http://127.0.0.1:8765', False), ('http://localhost:8765', True),
            ('http://192.0.2.1:8765', True), ('https://user:fixture@api.example.org', False),
            ('https://api.example.org/path', False), ('https://api.example.org?key=fixture', False),
            ('https://api.example.org#fixture', False), ('https://api.example.org:0', False),
        ):
            with self.subTest(url=url), self.assertRaises(protocol.BridgeError):
                protocol.origin(url, allow)

    def test_job_does_not_accept_forwarding_or_unbounded_instructions(self):
        valid = {'operation': 'chat', 'model': MODEL, 'prompt': 'A benign fixture',
                 'max_output_tokens': 32}
        self.assertEqual(protocol.validate_job(valid, {MODEL}), valid)
        for updates in ({'url': 'https://example.org'}, {'tools': []},
                        {'model': protocol.MODEL_PREFIX + 'not-allowed'},
                        {'max_output_tokens': True}, {'max_output_tokens': 4097},
                        {'prompt': 'x' * (protocol.MAX_PROMPT_BYTES + 1)}):
            with self.subTest(fields=list(updates)), self.assertRaises(protocol.BridgeError):
                protocol.validate_job({**valid, **updates}, {MODEL})
        with self.assertRaises(protocol.BridgeError):
            protocol.validate_job({'operation': 'auth-check', 'prompt': 'ignored'}, {MODEL})

    def test_completion_cannot_report_error_as_success_or_arbitrary_data(self):
        valid = {'attempt_id': 'a' * 32, 'state': 'succeeded', 'result': {'text': 'fixture result'},
                 'error': None, 'upstream_status': 200}
        self.assertEqual(protocol.validate_completion(valid, 'chat'), valid)
        for updates in ({'state': []}, {'upstream_status': 401}, {'error': 'permission_denied'},
                        {'result': {'text': 'ok', 'private_metadata': 'fixture'}},
                        {'result': {'text': ' '}}, {'attempt_id': '../invalid'},
                        {'result': {'text': 'x' * (protocol.MAX_TEXT_BYTES + 1)}}):
            with self.subTest(fields=list(updates)), self.assertRaises(protocol.BridgeError):
                protocol.validate_completion({**valid, **updates}, 'chat')

    def test_json_rejects_ambiguous_keys_and_nonfinite_values(self):
        for raw in (b'{"operation":"auth-check","operation":"chat"}', b'{"n":NaN}',
                    b'{"n":Infinity}', b'{"n":1e9999}', b'\xff', b'{'):
            with self.subTest(raw=raw), self.assertRaises(protocol.BridgeError):
                protocol.decode_json(raw)


class TransportTests(unittest.TestCase):
    def setUp(self):
        hits = self.hits = []

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                hits.append(self.path)
                if self.path == '/redirect':
                    self.send_response(307)
                    self.send_header('Location', '/must-not-receive-credentials')
                    self.send_header('Content-Length', '0')
                    self.end_headers()
                    return
                if self.path == '/status-only':
                    self.send_response(200)
                    self.send_header('Content-Length', '99999999')
                    self.end_headers()
                    return
                if self.path == '/denied':
                    self.send_response(403)
                    body = b'Private upstream diagnostic must not become a bridge result'
                elif self.path == '/oversized':
                    self.send_response(200)
                    body = b' ' * (protocol.MAX_BODY_BYTES + 1)
                else:
                    self.send_response(200)
                    body = b'{"fixture":true}'
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = 'http://127.0.0.1:' + str(self.server.server_address[1])
        self.addCleanup(self.stop)

    def stop(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    def request(self, path, **kwargs):
        return protocol.request_json('GET', self.base + path, 'nonsecret-fixture-token',
                                     allow_loopback_http=True, timeout=2, **kwargs)

    def test_redirect_never_receives_the_request(self):
        self.assertEqual(self.request('/redirect'), (307, None))
        self.assertEqual(self.hits, ['/redirect'])

    def test_auth_check_ignores_even_an_unreadable_body(self):
        self.assertEqual(self.request('/status-only', read_body=False), (200, None))

    def test_upstream_error_body_is_not_returned(self):
        self.assertEqual(self.request('/denied'), (403, None))

    def test_successful_body_is_bounded_before_parsing(self):
        with self.assertRaises(protocol.BridgeError) as raised:
            self.request('/oversized')
        self.assertEqual(raised.exception.code, 'response_too_large')

    def test_per_request_limit_rejects_excess_without_changing_shared_default(self):
        size = len(b'{"fixture":true}')
        self.assertEqual(self.request('/bounded', max_response_bytes=size),
                         (200, {'fixture': True}))
        with self.assertRaises(protocol.BridgeError) as raised:
            self.request('/bounded', max_response_bytes=size - 1)
        self.assertEqual(raised.exception.code, 'response_too_large')
        self.assertEqual(self.request('/bounded'), (200, {'fixture': True}))
        hits = len(self.hits)
        for cap in (0, -1, True, protocol.MAX_BODY_BYTES + 1):
            with self.subTest(cap=cap), self.assertRaises(protocol.BridgeError):
                self.request('/bounded', max_response_bytes=cap)
        self.assertEqual(len(self.hits), hits)


if __name__ == '__main__':
    unittest.main()

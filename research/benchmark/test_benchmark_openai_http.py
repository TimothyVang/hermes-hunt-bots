"""Synthetic loopback HTTP tests for `benchmark_openai_http` and `benchmark_subscription_proxy`."""
import copy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import tempfile
import threading
import unittest

import urllib.error
import urllib.request

import benchmark_paths  # noqa: F401
from benchmark import load_experiment
from benchmark_contracts import (
    ASSESSMENT_QUESTION, BenchmarkError, canonical_bytes, decode_json,
    digest_bytes, load_json, validate_benchmark_workflow,
)
import benchmark_models as models
from benchmark_openai_http import AdapterProblem, _validate_http_loopback_or_https
from benchmark_query import build_query_store
import benchmark_runner as runner
from benchmark_store import BenchmarkStore, STAGE_ROLES
from benchmark_subscription_proxy import (
    STRIPPED_API_ENV_VARS, clean_subscription_env, start_background_server,
)
from test_benchmark_runner import FIXTURES, response_fixture

MODEL = 'synthetic-http-apt-hunter-v1'


class _LoopbackHandler(BaseHTTPRequestHandler):
    responses = []
    requests = []

    def log_message(self, fmt, *args):
        return

    def do_POST(self):
        length = int(self.headers.get('Content-Length') or '0')
        body = json.loads(self.rfile.read(length).decode('utf-8'))
        self.requests.append(body)
        idx = min(len(self.requests) - 1, len(self.responses) - 1)
        status, payload = self.responses[idx]
        raw = json.dumps(payload).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


class BenchmarkOpenAiHttpTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        _LoopbackHandler.requests = []
        _LoopbackHandler.responses = []
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), _LoopbackHandler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)

    def test_clean_subscription_env_strips_all_paid_api_keys(self):
        dirty = {
            'PATH': '/usr/bin',
            'ANTHROPIC_API_KEY': 'sk-ant-test',
            'OPENAI_API_KEY': 'sk-openai-test',
            'CODEX_API_KEY': 'sk-codex-test',
            'GEMINI_API_KEY': 'ai-test',
            'GOOGLE_API_KEY': 'ai-test-2',
            'UNAPPROVED_SECRET_TOKEN': 'should-not-leak',
        }
        cleaned = clean_subscription_env(dirty)
        for key in STRIPPED_API_ENV_VARS:
            self.assertNotIn(key, cleaned)
        self.assertNotIn('UNAPPROVED_SECRET_TOKEN', cleaned)
        self.assertEqual(cleaned['PATH'], '/usr/bin')

    def test_subscription_proxy_enforces_bearer_token_and_rejects_browser_origins(self):
        token = 'a1b2c3d4e5f60718293a4b5c6d7e8f90'
        proxy = start_background_server('127.0.0.1', 0, timeout_seconds=10, auth_token=token)
        self.addCleanup(proxy.server_close)
        self.addCleanup(proxy.shutdown)
        t = threading.Thread(target=proxy.serve_forever, daemon=True)
        t.start()
        base = f'http://127.0.0.1:{proxy.server_address[1]}'

        # Unauthenticated /v1/models rejected with 401
        with self.assertRaises(urllib.error.HTTPError) as ctx401:
            urllib.request.urlopen(f'{base}/v1/models', timeout=5)
        self.assertEqual(ctx401.exception.code, 401)
        ctx401.exception.close()

        # Browser Origin rejected with 403 even with valid Bearer token
        req_origin = urllib.request.Request(
            f'{base}/v1/models',
            headers={'Authorization': f'Bearer {token}', 'Origin': 'https://evil.example'},
        )
        with self.assertRaises(urllib.error.HTTPError) as ctx403:
            urllib.request.urlopen(req_origin, timeout=5)
        self.assertEqual(ctx403.exception.code, 403)
        ctx403.exception.close()

        # Authenticated loopback client succeeds
        req_ok = urllib.request.Request(
            f'{base}/v1/models',
            headers={'Authorization': f'Bearer {token}'},
        )
        with urllib.request.urlopen(req_ok, timeout=5) as resp:
            self.assertEqual(resp.status, 200)
            body = json.loads(resp.read().decode('utf-8'))
            self.assertEqual(body['billing'], 'oauth_subscription_only')

    def test_openai_http_rejects_non_literal_localhost_http(self):
        with self.assertRaises(AdapterProblem):
            _validate_http_loopback_or_https('http://localhost:18941/v1')
        self.assertEqual(
            _validate_http_loopback_or_https('http://127.0.0.1:18941/v1'),
            'http://127.0.0.1:18941/v1',
        )

    def test_end_to_end_query_track_trial_executes_tools_and_records_query_audit(self):
        # Build a disposable query-track case outside the source tree
        bundle_root = self.root / 'bundle'
        case_dir = bundle_root / 'case-feedcafe'
        pub = case_dir / 'public'
        ev_dir = case_dir / 'evaluator'
        pub.mkdir(parents=True)
        ev_dir.mkdir(parents=True)

        events = [{
            'event_id': f'e{i:06d}',
            'timestamp_utc': f'2026-03-01T00:00:{i:02d}Z',
            'source_id': 'sysmon',
            'asset_id': 'host1',
            'event_type': 'sysmon_1',
            'fields': {
                'timestamp_original': f'2026-03-01T00:00:{i:02d}Z',
                'CommandLine': 'mimikatz.exe sekurlsa::logonpasswords' if i == 7 else f'cmd-{i}',
            },
            'locator': {'file_sha256': 'd' * 64, 'record_id': i},
        } for i in range(1, 25)]
        qspec = build_query_store(pub / 'events.sqlite3', events, (), prefix='e', width=6)
        ov_bytes = canonical_bytes({'events': 24}) + b'\n'
        (pub / 'overview.json').write_bytes(ov_bytes)

        evidence = {
            'schema_version': 1,
            'case_id': 'case-feedcafe',
            'window_utc': {'start_inclusive': '2026-03-01T00:00:00Z', 'end_exclusive': '2026-03-01T00:05:00Z'},
            'assets': [{'asset_id': 'host1', 'os_family': 'windows-client', 'os_version': '11', 'architecture': 'x86_64', 'vendor': 'microsoft'}],
            'sources': [{
                'source_id': 'sysmon', 'asset_ids': ['host1'], 'telemetry': 'sysmon',
                'clock_offset_seconds': 0, 'clock_uncertainty_seconds': 1,
                'window_utc': {'start_inclusive': '2026-03-01T00:00:00Z', 'end_exclusive': '2026-03-01T00:05:00Z'},
                'sensor_version': '15', 'config_version': '1', 'completeness': 'complete', 'source_sha256': 'd' * 64,
            }],
            'events': [],
            'query_store': qspec,
            'known_gaps': [],
            'files': [{'path': 'overview.json', 'byte_count': len(ov_bytes), 'sha256': digest_bytes(ov_bytes)}],
            'assessment_questions': [{'question_id': 'q1', 'asset_id': 'host1',
                                      'window_utc': {'start_inclusive': '2026-03-01T00:00:00Z', 'end_exclusive': '2026-03-01T00:05:00Z'},
                                      'question': ASSESSMENT_QUESTION}],
        }
        ev_bytes = canonical_bytes(evidence)
        ev_sha = digest_bytes(ev_bytes)
        scenario = load_json(FIXTURES / 'fixtures' / 'case-8b42' / 'scenario.json')
        scenario.update(scenario_id='scen-feedcafe', evidence_manifest_sha256=ev_sha)
        truth = {
            'schema_version': 1, 'case_id': 'case-feedcafe', 'truth_revision': 1,
            'evidence_manifest_sha256': ev_sha, 'attack_release': scenario['attack_release'],
            'attestation': 'publisher_labels', 'steps': [], 'edges': [], 'controls': [],
            'assessment_labels': {'q1': 0},
        }
        (pub / 'evidence.json').write_bytes(ev_bytes + b'\n')
        (case_dir / 'scenario.json').write_bytes(canonical_bytes(scenario) + b'\n')
        (ev_dir / 'truth.json').write_bytes(canonical_bytes(truth) + b'\n')

        exp = load_json(FIXTURES / 'examples' / 'experiment.json')
        exp['experiment_id'] = 'exp-http-query-test'
        exp['repetitions'] = 1
        exp['scenario_refs'] = [{'scenario': 'case-feedcafe/scenario.json', 'evidence': 'case-feedcafe/public/evidence.json'}]
        exp['coverage_sha256'] = digest_bytes(canonical_bytes(load_json(FIXTURES / 'coverage.json')))
        exp['workflow_sha256'] = digest_bytes(canonical_bytes(load_json(FIXTURES / 'team-workflow.json')))
        exp['prompt_contract_sha256'] = digest_bytes((FIXTURES / 'prompt-contract.txt').read_bytes())
        exp['teams'] = exp['teams'][:1]
        for role_spec in exp['teams'][0]['roles'].values():
            role_spec.update(
                adapter='openai_http', provider='openai', model_requested=MODEL,
                expected_model_ids=[MODEL], base_url=f'http://127.0.0.1:{self.port}/v1',
                credential_env=None, timeout_seconds=15,
                parameters={'temperature': 0.0, 'seed': 1729, 'structured_output': True},
            )
        exp['pricing_snapshot']['rates'] = []
        exp_path = bundle_root / 'experiment.json'
        exp_path.write_bytes(canonical_bytes(exp) + b'\n')

        state_root = self.root / 'state'
        loaded = load_experiment(exp_path, bundle_root)
        init = runner.initialize_experiment(state_root, loaded, bundle_root)
        store = BenchmarkStore(state_root)
        trial = store.get_trial(init['active_trial_id'])
        frozen = store.get_experiment(trial['experiment_id'])
        model = frozen['experiment']['teams'][0]['roles'][STAGE_ROLES['scope']]
        auth = runner._authorize(store, frozen, trial, model)
        prompt = runner.build_prompt(store, trial, 'scope')
        pref = store.write_artifact(trial['trial_id'], 'prompts', prompt)
        identity, _, _ = runner._source_identity()
        spec = dict(
            identity, schema_version=1, trial_id=trial['trial_id'], stage_key='scope',
            attempt_index=1, component='narrative', prompt_artifact=pref, input_sha256=pref['sha256'],
            workflow_sha256=frozen['experiment']['workflow_sha256'],
            prompt_contract_sha256=frozen['experiment']['prompt_contract_sha256'],
            evidence_sha256=trial['case_evidence_sha256'], authorization_sha256=auth,
            model=model, role=STAGE_ROLES['scope'],
        )
        stage_out = response_fixture('scope')
        stage_out['claims'] = [{'claim_id': 'c1', 'kind': 'observation', 'text': 'Found mimikatz in e000007.', 'event_ids': ['e000007']}]
        _LoopbackHandler.responses = [
            (200, {
                'model': MODEL,
                'choices': [{'message': {'content': json.dumps({
                    'action': 'query',
                    'queries': [{'tool': 'search_events', 'args': {'text_query': 'mimikatz'}}],
                })}, 'finish_reason': 'stop'}],
                'usage': {'prompt_tokens': 120, 'completion_tokens': 25},
            }),
            (200, {
                'model': MODEL,
                'choices': [{'message': {'content': json.dumps(stage_out)}, 'finish_reason': 'stop'}],
                'usage': {'prompt_tokens': 180, 'completion_tokens': 65},
            }),
        ]
        result = models.execute_call({'state_root': str(state_root), 'call_id': 'qcall-1', 'spec': spec}, prompt)
        self.assertEqual(result['receipt']['status'], 'completed')
        self.assertEqual(result['receipt']['usage']['input_tokens'], 300)
        self.assertEqual(result['receipt']['usage']['output_tokens'], 90)
        self.assertIn('query_audit', result['receipt'])
        audit = decode_json(store.read_artifact(trial['trial_id'], result['receipt']['query_audit']))
        self.assertEqual(audit['queries_executed'], 1)
        self.assertEqual(audit['calls'][0]['tool'], 'search_events')
        self.assertEqual(len(_LoopbackHandler.requests), 2)
        self.assertIn('e000007', json.dumps(_LoopbackHandler.requests[1]['messages']))

        # Verify both load_experiment and execute_call refuse langchain on query_store before reserving any call row
        lc_exp = copy.deepcopy(exp)
        lc_exp['experiment_id'] = 'query-http-lc-1'
        for rname in lc_exp['teams'][0]['roles']:
            lc_exp['teams'][0]['roles'][rname]['adapter'] = 'langchain'
        lc_exp_path = bundle_root / 'experiment-lc.json'
        lc_exp_path.write_bytes(canonical_bytes(lc_exp) + b'\n')
        with self.assertRaises(BenchmarkError) as load_ctx:
            load_experiment(lc_exp_path, bundle_root)
        self.assertEqual(load_ctx.exception.code, 'query_store_requires_openai_http')
        lc_state = Path(self.temp.name) / 'state-lc'
        lc_loaded = dict(loaded, experiment=lc_exp)
        lc_init = runner.initialize_experiment(lc_state, lc_loaded, bundle_root)
        lc_store = BenchmarkStore(lc_state)
        lc_trial = lc_store.get_trial(lc_init['active_trial_id'])
        lc_frozen = lc_store.get_experiment(lc_trial['experiment_id'])
        lc_model = lc_frozen['experiment']['teams'][0]['roles'][STAGE_ROLES['scope']]
        lc_auth = runner._authorize(lc_store, lc_frozen, lc_trial, lc_model)
        lc_prompt = runner.build_prompt(lc_store, lc_trial, 'scope')
        lc_pref = lc_store.write_artifact(lc_trial['trial_id'], 'prompts', lc_prompt)
        lc_spec = dict(
            identity, schema_version=1, trial_id=lc_trial['trial_id'], stage_key='scope',
            attempt_index=1, component='narrative', prompt_artifact=lc_pref, input_sha256=lc_pref['sha256'],
            workflow_sha256=lc_frozen['experiment']['workflow_sha256'],
            prompt_contract_sha256=lc_frozen['experiment']['prompt_contract_sha256'],
            evidence_sha256=lc_trial['case_evidence_sha256'], authorization_sha256=lc_auth,
            model=lc_model, role=STAGE_ROLES['scope'],
        )
        orig_chk = models.check_prerequisites
        models.check_prerequisites = lambda _prov: None
        try:
            with self.assertRaises(BenchmarkError) as ctx:
                models.execute_call({'state_root': str(lc_state), 'call_id': 'qcall-lc', 'spec': lc_spec}, lc_prompt)
            self.assertEqual(ctx.exception.code, 'query_store_requires_openai_http')
        finally:
            models.check_prerequisites = orig_chk
        self.assertEqual(lc_store.calls(), [])

    def test_validate_benchmark_workflow_rejects_wrong_stage_dag(self):
        with self.assertRaises(BenchmarkError) as ctx:
            validate_benchmark_workflow({'tasks': [{'key': 'scope', 'depends_on': [], 'role': 'coordinator'}]})
        self.assertEqual(ctx.exception.code, 'invalid_workflow')


if __name__ == '__main__':
    unittest.main()

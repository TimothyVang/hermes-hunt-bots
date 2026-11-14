"""Stdlib OpenAI-compatible HTTP adapter + bounded Wave 2 Query-Track loop.

Runs natively on Python's standard library (`urllib.request`, `http.client`,
`json`, `socket`) with zero third-party SDK dependencies, honoring the exact
same origin, credential, parameter, byte-cap, and metadata invariants as
`langchain_adapter.py` and `benchmark_models.py`.

When `query_executor` is provided (`evidence.json['query_store']`), executes a
bounded multi-round read-only hunting loop over `QueryExecutor` (`count_events`,
`search_events`, `get_events`, `asset_timeline`, `pivot_indicator`, `lookup_ioc`)
before returning the final stage JSON response and aggregated token usage.
"""
import ipaddress
import json
import os
import socket
import time
from types import SimpleNamespace
import urllib.error
import urllib.parse
import urllib.request

import benchmark_paths  # noqa: F401
from benchmark_contracts import BenchmarkError, canonical_bytes, decode_json
from langchain_adapter import AdapterProblem, UnsupportedParameter, validate_base_url, validate_parameters

DEFAULT_OPENAI_BASE_URL = 'https://api.openai.com/v1'
MAX_QUERY_ROUNDS = 4
MAX_QUERIES_PER_ROUND = 6

QUERY_SYSTEM_INSTRUCTIONS = """You are executing a threat-hunting stage on a Wave 2 Query-Track case.
The inline `events` array in `untrusted_public_evidence` is intentionally empty because the full sanitized telemetry corpus is indexed in `query_store`.
Read `overview.json` and `intel.jsonl` in `untrusted_public_evidence.files` first.

You have six read-only parameterized hunting tools over `query_store`:
1. `count_events`: args `{"group_by": "asset_id"|"source_id"|"event_type", "asset_id"?: str, "source_id"?: str, "event_type"?: str, "start_utc"?: str, "end_utc"?: str, "text_query"?: str}`
2. `search_events`: args `{"asset_id"?: str, "source_id"?: str, "event_type"?: str, "start_utc"?: str, "end_utc"?: str, "text_query"?: str, "limit"?: int, "offset"?: int}`
3. `get_events`: args `{"event_ids": [str, ...]}`
4. `asset_timeline`: args `{"asset_id": str, "around_utc": str, "window_seconds"?: int, "limit"?: int}`
5. `pivot_indicator`: args `{"value": str, "exclude_asset_id"?: str, "limit"?: int}`
6. `lookup_ioc`: args `{"query"?: str, "indicator_type"?: str, "status"?: str, "limit"?: int}`

Protocol:
- To run queries (you may batch 1 to 6 tool calls per round while `calls_remaining > 0`), output ONLY a raw JSON object:
  `{"action": "query", "queries": [{"tool": "<tool_name>", "args": {...}}, ...]}`
- Once you have gathered concrete `event_id`s from tool results (or predecessor stage outputs), output ONLY the final raw JSON stage object required by `prompt_contract` (either directly `{"schema_version": 1, "stage_key": "...", ...}` or `{"action": "submit", "output": {"schema_version": 1, ...}}`).
- Never invent `event_id`s that you did not observe in tool results or predecessor outputs. Never wrap JSON in markdown fences."""


class _NoRedirect(urllib.request.HTTPErrorProcessor):
    def http_response(self, request, response):
        return response
    https_response = http_response


def _validate_http_loopback_or_https(url_text):
    validated = validate_base_url(url_text)
    parsed = urllib.parse.urlsplit(validated)
    if parsed.scheme == 'http':
        try:
            is_loop = ipaddress.ip_address(parsed.hostname or '').is_loopback
        except ValueError:
            is_loop = False
        if not is_loop:
            raise AdapterProblem('plain HTTP base_url must use a literal loopback IP address')
    return validated


def check_http_prerequisites(model):
    """Validate `openai_http` route configuration before call reservation."""
    if model['provider'] != 'openai':
        raise UnsupportedParameter('openai_http adapter requires provider openai')
    if model['base_url'] is not None:
        _validate_http_loopback_or_https(model['base_url'])


def _endpoint_url(base_url):
    root = _validate_http_loopback_or_https(base_url) if base_url is not None else DEFAULT_OPENAI_BASE_URL
    trimmed = root.rstrip('/')
    if trimmed.endswith('/chat/completions'):
        return trimmed
    return trimmed + '/chat/completions'


def _post_chat_completions(url, api_key, payload, timeout_seconds, max_wire_bytes, provenance=None):
    raw_req = canonical_bytes(payload)
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
    }
    if api_key:
        headers['Authorization'] = 'Bearer ' + api_key
    if isinstance(provenance, str) and provenance:
        headers['X-Benchmark-Provenance'] = provenance
    request = urllib.request.Request(url, data=raw_req, headers=headers, method='POST')
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPHandler(),
        urllib.request.HTTPSHandler(),
        _NoRedirect(),
    )
    try:
        with opener.open(request, timeout=max(1.0, float(timeout_seconds))) as resp:
            status = getattr(resp, 'status', None) or resp.getcode()
            body = resp.read(max_wire_bytes + 1)
    except urllib.error.HTTPError as exc:
        status = exc.code
        try:
            body = exc.read(4096)
        finally:
            exc.close()
    except (TimeoutError, socket.timeout) as exc:
        raise TimeoutError('openai_http request timed out') from exc
    except urllib.error.URLError as exc:
        reason = getattr(exc, 'reason', None)
        if isinstance(reason, (TimeoutError, socket.timeout)):
            raise TimeoutError('openai_http request timed out') from exc
        raise BenchmarkError('upstream_unreachable', 'model.base_url') from None
    except OSError:
        raise BenchmarkError('upstream_unreachable', 'model.base_url') from None

    if status == 403 and b'private_evidence_release_required' in body:
        raise BenchmarkError('release_required', 'authorization')
    if status in (401, 403):
        raise BenchmarkError('authentication_failed', 'model.credential_env')
    if status is None or status < 200 or status >= 300:
        raise BenchmarkError('upstream_http_error', 'model.base_url')
    if len(body) > max_wire_bytes:
        raise BenchmarkError('response_too_large', 'response.bytes')
    return decode_json(body)


def _extract_turn(wire):
    if type(wire) is not dict:
        raise BenchmarkError('invalid_response', 'response')
    returned_model = wire.get('model')
    choices = wire.get('choices')
    if type(choices) is not list or not choices or type(choices[0]) is not dict:
        raise BenchmarkError('invalid_response', 'response.choices')
    choice = choices[0]
    finish_reason = choice.get('finish_reason')
    message = choice.get('message')
    if type(message) is not dict:
        raise BenchmarkError('invalid_response', 'response.message')
    content = message.get('content')
    if content is None:
        text = ''
    elif isinstance(content, str):
        text = content
    elif isinstance(content, list):
        parts = []
        for block in content:
            if type(block) is dict and block.get('type') == 'text' and isinstance(block.get('text'), str):
                parts.append(block['text'])
        text = ''.join(parts)
    else:
        raise BenchmarkError('invalid_response', 'response.content')
    tool_calls = message.get('tool_calls') if type(message.get('tool_calls')) is list else []

    usage_meta = None
    raw_usage = wire.get('usage')
    if type(raw_usage) is dict:
        in_tok = raw_usage.get('prompt_tokens', raw_usage.get('input_tokens'))
        out_tok = raw_usage.get('completion_tokens', raw_usage.get('output_tokens'))
        usage_meta = {
            'input_tokens': in_tok if type(in_tok) is int else None,
            'output_tokens': out_tok if type(out_tok) is int else None,
        }
        p_details = raw_usage.get('prompt_tokens_details') or raw_usage.get('input_token_details')
        if type(p_details) is dict:
            cached = p_details.get('cached_tokens', p_details.get('cache_read'))
            if type(cached) is int:
                usage_meta['input_token_details'] = {'cache_read': cached}
        c_details = raw_usage.get('completion_tokens_details') or raw_usage.get('output_token_details')
        if type(c_details) is dict:
            reasoning = c_details.get('reasoning_tokens', c_details.get('reasoning'))
            if type(reasoning) is int:
                usage_meta['output_token_details'] = {'reasoning': reasoning}

    return {
        'text': text,
        'tool_calls': tool_calls,
        'model': returned_model,
        'finish_reason': finish_reason,
        'usage': usage_meta,
    }


def _merge_usage(accumulated, turn_usage):
    """Aggregate usage across query-track rounds; any missing round makes total usage unknown."""
    if accumulated is None or turn_usage is None:
        return None
    if type(turn_usage.get('input_tokens')) is not int or type(turn_usage.get('output_tokens')) is not int:
        return None
    merged = {
        'input_tokens': accumulated['input_tokens'] + turn_usage['input_tokens'],
        'output_tokens': accumulated['output_tokens'] + turn_usage['output_tokens'],
    }
    if 'input_token_details' in accumulated:
        merged['input_token_details'] = dict(accumulated['input_token_details'])
    if 'output_token_details' in accumulated:
        merged['output_token_details'] = dict(accumulated['output_token_details'])
    in_det = turn_usage.get('input_token_details', {})
    if type(in_det.get('cache_read')) is int:
        cur = merged.setdefault('input_token_details', {'cache_read': 0})
        cur['cache_read'] += in_det['cache_read']
    out_det = turn_usage.get('output_token_details', {})
    if type(out_det.get('reasoning')) is int:
        cur = merged.setdefault('output_token_details', {'reasoning': 0})
        cur['reasoning'] += out_det['reasoning']
    return merged


def _strip_optional_json_fence(text):
    stripped = text.strip()
    if stripped.startswith('```'):
        lines = stripped.splitlines()
        if len(lines) >= 3 and lines[-1].strip() == '```':
            inner = '\n'.join(lines[1:-1]).strip()
            if inner.startswith('{') and inner.endswith('}'):
                return inner
    return text


def _parse_query_action(turn):
    """Detect whether a query-track turn requested tool queries or submitted final stage output."""
    if turn['tool_calls']:
        queries = []
        for tc in turn['tool_calls'][:MAX_QUERIES_PER_ROUND]:
            fn = tc.get('function') if type(tc) is dict else None
            if type(fn) is dict and isinstance(fn.get('name'), str):
                try:
                    args = json.loads(fn.get('arguments') or '{}')
                except ValueError:
                    args = {}
                queries.append({'tool': fn['name'], 'args': args if type(args) is dict else {}})
        if queries:
            return 'query', queries

    cleaned = _strip_optional_json_fence(turn['text'])
    try:
        parsed = json.loads(cleaned)
    except ValueError:
        return 'final_raw', cleaned
    if type(parsed) is not dict:
        return 'final_raw', cleaned
    if parsed.get('action') == 'query' and type(parsed.get('queries')) is list:
        return 'query', parsed['queries'][:MAX_QUERIES_PER_ROUND]
    if parsed.get('action') == 'submit' and type(parsed.get('output')) is dict:
        return 'final_raw', canonical_bytes(parsed['output']).decode('utf-8')
    if 'queries' in parsed and 'stage_key' not in parsed and type(parsed.get('queries')) is list:
        return 'query', parsed['queries'][:MAX_QUERIES_PER_ROUND]
    return 'final_raw', cleaned


def invoke_openai_http(prompt, provider, model, base_url, request_timeout, *,
                       expected_model_ids=None, max_response_bytes=65536,
                       query_executor=None, stage_key=None, provenance=None,
                       max_output_tokens=None, temperature=None, seed=None, response_schema=None):
    """Invoke an OpenAI-compatible Chat Completions endpoint (single-shot or bounded query loop)."""
    validate_parameters(provider, max_output_tokens, temperature, seed, response_schema is not None)
    if response_schema is not None and type(response_schema) is not dict:
        raise UnsupportedParameter('response schema must be a JSON object')
    url = _endpoint_url(base_url)
    api_key = os.environ.get('OPENAI_API_KEY', '')
    max_wire_bytes = max(max_response_bytes * 6, 524288)
    deadline = time.monotonic() + float(request_timeout)

    def build_payload(messages, enforce_schema):
        body = {
            'model': model,
            'messages': messages,
        }
        if max_output_tokens is not None:
            body['max_tokens'] = max_output_tokens
        if temperature is not None:
            body['temperature'] = temperature
        if seed is not None:
            body['seed'] = seed
        if enforce_schema and response_schema is not None:
            body['response_format'] = {
                'type': 'json_schema',
                'json_schema': {
                    'name': 'stage_output',
                    'strict': True,
                    'schema': response_schema,
                },
            }
        return body

    if query_executor is None:
        messages = [
            {'role': 'system', 'content': 'Return ONLY the raw JSON object required by prompt_contract. Never wrap JSON in markdown fences.'},
            {'role': 'user', 'content': prompt},
        ]
        wire = _post_chat_completions(
            url, api_key, build_payload(messages, True), request_timeout, max_wire_bytes,
            provenance=provenance,
        )
        turn = _extract_turn(wire)
        final_text = _strip_optional_json_fence(turn['text'])
        return SimpleNamespace(
            text=final_text,
            tool_calls=turn['tool_calls'],
            invalid_tool_calls=[],
            response_metadata={'model_name': turn['model'], 'finish_reason': turn['finish_reason']},
            usage_metadata=turn['usage'],
        )

    messages = [
        {'role': 'system', 'content': QUERY_SYSTEM_INSTRUCTIONS},
        {'role': 'user', 'content': prompt},
    ]
    total_usage = {'input_tokens': 0, 'output_tokens': 0}
    last_turn = None
    for round_idx in range(MAX_QUERY_ROUNDS):
        remaining_time = deadline - time.monotonic()
        if remaining_time <= 1.0:
            raise TimeoutError('openai_http query-track budget timed out')
        is_last_round = (round_idx == MAX_QUERY_ROUNDS - 1) or (query_executor.calls_remaining == 0)
        wire = _post_chat_completions(
            url, api_key, build_payload(messages, is_last_round), remaining_time, max_wire_bytes,
            provenance=provenance,
        )
        turn = _extract_turn(wire)
        last_turn = turn
        total_usage = _merge_usage(total_usage, turn['usage'])

        if expected_model_ids and turn['model'] is not None and turn['model'] not in expected_model_ids:
            return SimpleNamespace(
                text=turn['text'],
                tool_calls=[],
                invalid_tool_calls=[],
                response_metadata={'model_name': turn['model'], 'finish_reason': turn['finish_reason']},
                usage_metadata=total_usage,
            )

        kind, payload = _parse_query_action(turn)
        if kind == 'final_raw':
            return SimpleNamespace(
                text=payload,
                tool_calls=[],
                invalid_tool_calls=[],
                response_metadata={'model_name': turn['model'], 'finish_reason': turn['finish_reason']},
                usage_metadata=total_usage,
            )

        if is_last_round:
            fallback_text = _strip_optional_json_fence(turn['text']).strip()
            if not fallback_text:
                fallback_text = canonical_bytes({'unanswered_queries': payload}).decode('utf-8')
            return SimpleNamespace(
                text=fallback_text,
                tool_calls=turn['tool_calls'],
                invalid_tool_calls=[],
                response_metadata={'model_name': turn['model'], 'finish_reason': turn['finish_reason']},
                usage_metadata=total_usage,
            )

        results = []
        for item in payload:
            if query_executor.calls_remaining <= 0:
                results.append({'ok': False, 'error': 'query_budget_exhausted', 'calls_remaining': 0})
                break
            tool_name = item.get('tool') if type(item) is dict else None
            tool_args = item.get('args', {}) if type(item) is dict else None
            results.append(query_executor.execute(tool_name, tool_args))

        assistant_echo = turn['text'].strip() or canonical_bytes({'action': 'query', 'queries': payload}).decode('utf-8')
        messages.append({'role': 'assistant', 'content': assistant_echo})
        next_is_last = (round_idx + 1 == MAX_QUERY_ROUNDS - 1) or (query_executor.calls_remaining == 0)
        instruction = (
            'Query phase complete. Emit ONLY the final raw stage JSON object for stage_key=' + str(stage_key) + ' now.'
            if next_is_last else
            'Issue another `{"action":"query","queries":[...]}` batch if needed, '
            'or emit the final raw stage JSON object for stage_key=' + str(stage_key) + '.'
        )
        messages.append({
            'role': 'user',
            'content': canonical_bytes({
                'tool_results': results,
                'calls_remaining': query_executor.calls_remaining,
                'instruction': instruction,
            }).decode('utf-8'),
        })

    fallback_text = _strip_optional_json_fence(last_turn['text']).strip() if last_turn else ''
    return SimpleNamespace(
        text=fallback_text,
        tool_calls=last_turn['tool_calls'] if last_turn else [],
        invalid_tool_calls=[],
        response_metadata={'model_name': last_turn['model'], 'finish_reason': last_turn['finish_reason']},
        usage_metadata=total_usage,
    )

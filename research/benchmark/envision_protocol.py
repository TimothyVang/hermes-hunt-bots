"""Bounded, secret-safe protocol helpers for the optional Envision bridge."""
import ipaddress
import json
import math
import os
import re
from http.client import HTTPException
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

import benchmark_paths
from langchain_adapter import AdapterProblem, validate_base_url


MAX_PROMPT_BYTES = 64 * 1024
MAX_TEXT_BYTES = 256 * 1024
MAX_BODY_BYTES = 2 * 1024 * 1024
MAX_OUTPUT_TOKENS = 4096
MODEL_PREFIX = 'ri.language-model-service..language-model.'
TERMINAL_STATES = frozenset(('succeeded', 'failed', 'unknown'))
ERROR_CODES = frozenset((
    'authentication_failed', 'permission_denied', 'upstream_http_error',
    'upstream_unreachable', 'invalid_response', 'response_too_large',
    'model_not_allowed', 'lease_expired', 'insufficient_lease',
))


class BridgeError(Exception):
    """Only fixed, framework-authored error codes may cross the CLI boundary."""

    def __init__(self, code):
        self.code = code
        super().__init__(code)


def origin(value, allow_loopback_http=False):
    """Accept an HTTPS origin, or explicitly enabled literal-loopback HTTP."""
    try:
        validate_base_url(value)
        parts = urlsplit(value)
        if parts.path not in ('', '/'):
            raise ValueError
        if parts.scheme == 'http':
            if not allow_loopback_http or not ipaddress.ip_address(parts.hostname).is_loopback:
                raise ValueError
        return value.rstrip('/')
    except (AdapterProblem, ValueError, TypeError, AttributeError):
        raise BridgeError('invalid_origin') from None


def secret_from_environment(name, minimum=32):
    """No .env loading, secret files, CLI secret arguments, or value diagnostics."""
    value = os.environ.get(name, '')
    if (not minimum <= len(value) <= 8192
            or any(ord(char) < 33 or ord(char) > 126 for char in value)):
        raise BridgeError('missing_or_invalid_credential')
    return value


def model_identifier(value):
    if (not isinstance(value, str) or len(value) > 256
            or not value.startswith(MODEL_PREFIX)
            or re.fullmatch(r'[A-Za-z0-9_.-]+', value[len(MODEL_PREFIX):]) is None):
        raise BridgeError('invalid_model')
    return value


def job_identifier(value):
    if not isinstance(value, str) or re.fullmatch(r'[0-9a-f]{32}', value) is None:
        raise BridgeError('invalid_job_id')
    return value


def text_value(value, maximum, code):
    if not isinstance(value, str) or not value.strip():
        raise BridgeError(code)
    try:
        if len(value.encode('utf-8')) > maximum:
            raise BridgeError(code)
    except UnicodeError:
        raise BridgeError(code) from None
    return value


def validate_job(payload, models):
    if not isinstance(payload, dict):
        raise BridgeError('invalid_job')
    if payload == {'operation': 'auth-check'}:
        return dict(payload)
    if set(payload) != {'operation', 'model', 'prompt', 'max_output_tokens'}:
        raise BridgeError('invalid_job')
    if payload['operation'] != 'chat':
        raise BridgeError('invalid_job')
    model = model_identifier(payload['model'])
    if model not in models:
        raise BridgeError('model_not_allowed')
    text_value(payload['prompt'], MAX_PROMPT_BYTES, 'invalid_prompt')
    count = payload['max_output_tokens']
    if type(count) is not int or not 1 <= count <= MAX_OUTPUT_TOKENS:
        raise BridgeError('invalid_output_limit')
    return dict(payload)


def validate_completion(payload, operation):
    expected = {'attempt_id', 'state', 'result', 'error', 'upstream_status'}
    if not isinstance(payload, dict) or set(payload) != expected:
        raise BridgeError('invalid_completion')
    job_identifier(payload['attempt_id'])
    state, result, error, status = (payload[key] for key in
                                    ('state', 'result', 'error', 'upstream_status'))
    if not isinstance(state, str) or state not in TERMINAL_STATES:
        raise BridgeError('invalid_completion')
    if status is not None and (type(status) is not int or not 100 <= status <= 599):
        raise BridgeError('invalid_completion')
    if state == 'succeeded':
        if error is not None or type(status) is not int or not 200 <= status <= 299:
            raise BridgeError('invalid_completion')
        if operation == 'auth-check':
            if (not isinstance(result, dict) or set(result) != {'http_status'}
                    or type(result['http_status']) is not int or result['http_status'] != status):
                raise BridgeError('invalid_completion')
        elif operation == 'chat':
            if not isinstance(result, dict) or set(result) != {'text'}:
                raise BridgeError('invalid_completion')
            text_value(result['text'], MAX_TEXT_BYTES, 'invalid_completion')
        else:
            raise BridgeError('invalid_completion')
    elif result is not None or not isinstance(error, str) or error not in ERROR_CODES:
        raise BridgeError('invalid_completion')
    return dict(payload)


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise BridgeError('invalid_json')
        result[key] = value
    return result


def _constant(_):
    raise BridgeError('invalid_json')


def _finite_float(value):
    number = float(value)
    if not math.isfinite(number):
        raise BridgeError('invalid_json')
    return number


def decode_json(raw):
    try:
        return json.loads(raw.decode('utf-8'), object_pairs_hook=_pairs,
                          parse_constant=_constant, parse_float=_finite_float)
    except (ValueError, UnicodeError, RecursionError):
        raise BridgeError('invalid_json') from None


def encode_json(value):
    try:
        return json.dumps(value, ensure_ascii=True, allow_nan=False,
                          separators=(',', ':')).encode('ascii')
    except (ValueError, TypeError, RecursionError):
        raise BridgeError('invalid_json') from None


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def request_json(method, url, token, payload=None, *, timeout=15,
                 allow_loopback_http=False, read_body=True, max_response_bytes=None):
    """Return (status, JSON); never follow redirects or expose upstream error bodies."""
    cap = MAX_BODY_BYTES if max_response_bytes is None else max_response_bytes
    if type(cap) is not int or not 1 <= cap <= MAX_BODY_BYTES:
        raise BridgeError('invalid_response_limit')
    try:
        parts = urlsplit(url)
        checked_origin = origin(f'{parts.scheme}://{parts.netloc}', allow_loopback_http)
        if parts.query or parts.fragment or any(ord(c) < 33 for c in url) or '\\' in url:
            raise BridgeError('invalid_origin')
        headers = {'Authorization': 'Bearer ' + token, 'Accept': 'application/json'}
        body = encode_json(payload) if payload is not None else None
        if body is not None:
            if len(body) > MAX_BODY_BYTES:
                raise BridgeError('request_too_large')
            headers['Content-Type'] = 'application/json'
        handlers = [_NoRedirect()]
        # A loopback smoke fixture must never receive real proxy credentials.
        if urlsplit(checked_origin).scheme == 'http':
            handlers.append(ProxyHandler({}))
        opener = build_opener(*handlers)
        request = Request(url, data=body, headers=headers, method=method)
        with opener.open(request, timeout=timeout) as response:
            status = response.status
            if not read_body or not 200 <= status <= 299 or status == 204:
                return status, None
            raw = response.read(cap + 1)
            if len(raw) > cap:
                raise BridgeError('response_too_large')
            try:
                return status, decode_json(raw)
            except BridgeError:
                raise BridgeError('invalid_response') from None
    except HTTPError as exc:
        status = exc.code
        exc.close()
        return status, None
    except (URLError, OSError, TimeoutError, ValueError, HTTPException):
        raise BridgeError('upstream_unreachable') from None

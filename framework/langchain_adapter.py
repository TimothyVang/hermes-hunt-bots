#!/usr/bin/env python3
"""Explicit, text-only LangChain model CLI for bot.py's existing generic adapter."""
import argparse
from contextlib import redirect_stderr, redirect_stdout
import ipaddress
import logging
import math
import os
import sys
from importlib.util import find_spec
from urllib.parse import urlsplit
import warnings


MAX_PROMPT_BYTES = 1024 * 1024
PROVIDERS = ('openai', 'anthropic')
PROVIDER_PACKAGES = {'openai': 'langchain_openai', 'anthropic': 'langchain_anthropic'}


class AdapterProblem(Exception):
    """A framework-authored, non-sensitive operator message."""


class UnsupportedParameter(AdapterProblem):
    """A requested sampling/limit parameter the provider route cannot honor."""


class PrerequisiteMissing(AdapterProblem):
    """The optional Python/SDK prerequisite for live adapters is absent."""


class SafeParser(argparse.ArgumentParser):
    def error(self, message):
        # argparse's normal errors quote supplied values, including unknown
        # secret-bearing arguments. Never echo arguments on failure.
        self.exit(2, 'Error: invalid adapter arguments; use --help; never pass credentials as arguments.\n')


def model_name(value):
    if not value.strip() or value.startswith('-') or any(character.isspace() or ord(character) < 32 for character in value):
        raise argparse.ArgumentTypeError('model must be a nonempty identifier')
    return value


def positive_timeout(value):
    try:
        number = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError('request timeout must be positive and finite') from None
    if not math.isfinite(number) or number <= 0:
        raise argparse.ArgumentTypeError('request timeout must be positive and finite')
    return number


def validate_base_url(value):
    """Allow HTTPS APIs, plus literal loopback HTTP for an authorized local API."""
    try:
        if any(character.isspace() or ord(character) < 32 for character in value) or '\\' in value:
            raise ValueError
        parts = urlsplit(value)
        if (parts.scheme not in ('https', 'http') or not parts.hostname
                or parts.username is not None or parts.password is not None
                or parts.query or parts.fragment or '?' in value or '#' in value):
            raise ValueError
        if parts.port is not None and not 1 <= parts.port <= 65535:
            raise ValueError
        if parts.scheme == 'http':
            # No DNS resolution: a hostname resolving remotely must never be
            # treated as local merely because of a suggestive name.
            if parts.hostname != 'localhost' and not ipaddress.ip_address(parts.hostname).is_loopback:
                raise ValueError
    except ValueError:
        raise AdapterProblem('base URL must be HTTPS or loopback HTTP, without credentials, query parameters, or fragments') from None
    return value


def read_prompt(stream):
    content = stream.read(MAX_PROMPT_BYTES + 1)
    if len(content) > MAX_PROMPT_BYTES:
        raise AdapterProblem('prompt exceeds the 1 MiB UTF-8 limit; reduce task/history context explicitly; nothing was sent')
    try:
        prompt = content.decode('utf-8')
    except UnicodeError:
        raise AdapterProblem('prompt must be valid UTF-8; nothing was sent') from None
    if not prompt.strip():
        raise AdapterProblem('prompt must contain non-whitespace text; nothing was sent')
    return prompt


def response_text(response):
    # Never execute tools or turn tool-only / reasoning-only output into a
    # success handoff. Mixed text/tool output is also rejected as incomplete.
    if response.tool_calls or response.invalid_tool_calls:
        raise AdapterProblem('model requested unsupported tools; no text handoff was submitted')
    text = response.text
    if not isinstance(text, str) or not text.strip():
        raise AdapterProblem('model returned no nonempty text handoff')
    return text


def validate_parameters(provider, max_output_tokens=None, temperature=None, seed=None, structured_output=False):
    """Pure parameter check; refuses rather than silently drops anything."""
    if provider not in PROVIDERS:
        raise UnsupportedParameter('unsupported provider')
    if max_output_tokens is not None and (type(max_output_tokens) is not int or max_output_tokens <= 0):
        raise UnsupportedParameter('output token limit must be a positive integer')
    maximum = 1 if provider == 'anthropic' else 2
    if temperature is not None and (type(temperature) not in (int, float)
                                    or not math.isfinite(temperature) or not 0 <= temperature <= maximum):
        raise UnsupportedParameter('temperature must be finite and within the provider range')
    if seed is not None and (provider != 'openai' or type(seed) is not int or seed < 0):
        raise UnsupportedParameter('requested seed is unsupported')
    # Schema-constrained decoding has a verified request path only for the
    # OpenAI-compatible Chat Completions transport (see invoke_response).
    if type(structured_output) is not bool or (structured_output and provider != 'openai'):
        raise UnsupportedParameter('requested structured output is unsupported')


def check_prerequisites(provider):
    """Locate (never import or install) the optional runtime for a provider."""
    if sys.version_info < (3, 10):
        raise PrerequisiteMissing('optional model adapter requires Python 3.10 or newer; the manual ledger still supports Python 3.9')
    try:
        missing = any(find_spec(name) is None for name in ('langchain', 'langsmith', PROVIDER_PACKAGES[provider]))
    except (ImportError, ValueError, KeyError):
        missing = True
    if missing:
        raise PrerequisiteMissing('optional dependencies unavailable; install requirements-orchestration.txt and the selected provider package')


def invoke_response(prompt, provider, model, base_url, request_timeout, *,
                    max_output_tokens=None, temperature=None, seed=None, response_schema=None):
    """Return the authentic response; callers choose allowlisted metadata only.

    `response_schema`, a strict JSON Schema object, requests schema-constrained
    decoding as `response_format` type `json_schema` (name `stage_output`,
    `strict: true`).
    """
    validate_parameters(provider, max_output_tokens, temperature, seed, response_schema is not None)
    if response_schema is not None and type(response_schema) is not dict:
        raise UnsupportedParameter('response schema must be a JSON object')
    if base_url is not None:
        base_url = validate_base_url(base_url)
    check_prerequisites(provider)
    for name in ('LANGSMITH_TRACING', 'LANGCHAIN_TRACING', 'LANGCHAIN_TRACING_V2'):
        os.environ[name] = 'false'
    # Provider diagnostics may contain request bodies, authentication headers
    # or raw upstream errors. Suppress them for this one-shot CLI invocation.
    previous_logging = logging.root.manager.disable
    logging.disable(logging.CRITICAL)
    try:
        with open(os.devnull, 'w', encoding='utf-8') as quiet, redirect_stdout(quiet), redirect_stderr(quiet), warnings.catch_warnings():
            warnings.simplefilter('ignore')
            try:
                from langchain.chat_models import init_chat_model
                from langsmith import tracing_context
            except ImportError:
                raise PrerequisiteMissing('optional dependencies unavailable; install requirements-orchestration.txt and the selected provider package') from None
            options = {'max_retries': 0, 'timeout': request_timeout}
            if base_url is not None:
                options['base_url'] = base_url
            requested = {'max_tokens': max_output_tokens, 'temperature': temperature, 'seed': seed}
            if response_schema is not None:
                # Sent as the top-level request field via `extra_body`, not
                # `model_kwargs`/`bind`: langchain_openai 1.x sends a payload
                # containing `response_format` through `chat.completions.parse`,
                # which raises on finish_reason `length`/`content_filter` instead
                # of returning the response (its text, finish reason, model and
                # usage). `extra_body` keeps the ordinary `create` path.
                requested['extra_body'] = {'response_format': {
                    'type': 'json_schema',
                    'json_schema': {'name': 'stage_output', 'strict': True, 'schema': response_schema}}}
            options.update({name: value for name, value in requested.items() if value is not None})
            if provider == 'openai':
                # Force the ordinary Chat Completions API; no hosted tools,
                # response state, or model-name-based Responses API selection.
                options['use_responses_api'] = False
            with tracing_context(enabled=False):
                try:
                    chat = init_chat_model(model, model_provider=provider, **options)
                except ImportError:
                    raise PrerequisiteMissing('selected provider package unavailable; install its documented optional package') from None
                for name, value in requested.items():
                    if value is not None and getattr(chat, name, None) != value:
                        raise UnsupportedParameter('requested model parameter is unsupported')
                response = chat.invoke(prompt, config={'callbacks': []})
            return response
    finally:
        logging.disable(previous_logging)


def main(argv=None):
    parser = SafeParser(description=__doc__)
    parser.add_argument('--provider', required=True, choices=PROVIDERS)
    parser.add_argument('--model', required=True, type=model_name)
    parser.add_argument('--base-url', help='OpenAI-compatible API base URL; HTTPS or loopback HTTP only; never include credentials')
    parser.add_argument('--request-timeout', type=positive_timeout, default=60.0,
                        help='SDK request timeout in seconds (default: 60); bot.py --timeout remains the outer deadline')
    args = parser.parse_args(argv)
    try:
        base_url = None
        if args.base_url is not None:
            if args.provider != 'openai':
                raise AdapterProblem('--base-url is supported only with --provider openai')
            base_url = validate_base_url(args.base_url)
        prompt = read_prompt(sys.stdin.buffer)
        text = response_text(invoke_response(prompt, args.provider, args.model, base_url, args.request_timeout))
        # The generic adapter stores bytes. Avoid the platform's console codec
        # losing Unicode or changing an authentic model handoff.
        sys.stdout.buffer.write(text.encode('utf-8'))
        sys.stdout.buffer.flush()
    except AdapterProblem as exc:
        print('Error: ' + str(exc), file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print('Error: model invocation interrupted; inspect the ledger run before any explicit retry.', file=sys.stderr)
        return 130
    except Exception:
        print('Error: model invocation failed; check the approved provider configuration, access, endpoint and model without exposing credentials; no automatic retry.', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())

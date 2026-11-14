#!/usr/bin/env python3
"""Local loopback OpenAI-compatible proxy backed by OAuth subscription CLIs (`claude` & `codex`).

Safety & billing invariants:
- Binds strictly to literal loopback (`127.0.0.1`) and requires a per-server
  `Authorization: Bearer <token>` header (`hmac.compare_digest`), `Content-Type:
  application/json`, and absence of browser `Origin` / `Sec-Fetch-Site` headers.
- Builds child environments from an explicit OS/CLI-auth allowlist and strips
  `ANTHROPIC_API_KEY`, `ANTHROPIC_AUTH_TOKEN`, `OPENAI_API_KEY`, `CODEX_API_KEY`,
  `GEMINI_API_KEY`, `GOOGLE_API_KEY`, and `AZURE_OPENAI_API_KEY` so runs execute
  against existing OAuth CLI subscriptions rather than API keys.
- Resolves native executables or Node JS entrypoints directly (never `cmd.exe /c`),
  validates model/effort identifiers against strict allowlists, passes prompts via
  `stdin` (avoiding OS command-line length limits), and disables CLI tool features
  (`claude --tools ""`, `codex --disable shell_tool --disable unified_exec
  --disable view_image -c mcp_servers={}`) while failing closed if any tool-call
  event appears in the CLI output stream.
"""
import argparse
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import time

STRIPPED_API_ENV_VARS = frozenset((
    'ANTHROPIC_API_KEY',
    'ANTHROPIC_AUTH_TOKEN',
    'OPENAI_API_KEY',
    'CODEX_API_KEY',
    'GEMINI_API_KEY',
    'GOOGLE_API_KEY',
    'AZURE_OPENAI_API_KEY',
))

ALLOWED_SUBSCRIPTION_ENV_VARS = frozenset((
    'PATH', 'PATHEXT', 'SYSTEMROOT', 'WINDIR', 'COMSPEC', 'SYSTEMDRIVE',
    'TEMP', 'TMP', 'TMPDIR',
    'HOME', 'USERPROFILE', 'HOMEDRIVE', 'HOMEPATH', 'APPDATA', 'LOCALAPPDATA',
    'XDG_CONFIG_HOME', 'XDG_DATA_HOME', 'XDG_STATE_HOME', 'XDG_CACHE_HOME',
    'SSL_CERT_FILE', 'SSL_CERT_DIR', 'NODE_EXTRA_CA_CERTS',
    'LANG', 'LC_ALL', 'TERM',
    'CODEX_HOME', 'CLAUDE_CONFIG_DIR',
))

ALLOWED_REASONING_EFFORTS = frozenset(('minimal', 'low', 'medium', 'high', 'xhigh'))
_MODEL_ID_RE = re.compile(r'\A[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}\Z')
_NPM_CMD_JS_RE = re.compile(r'"%dp0%[\\/]([^"\r\n]+?\.(?:js|mjs|cjs))"', re.IGNORECASE)
_FORBIDDEN_CODEX_ITEM_TYPES = frozenset((
    'command_execution', 'mcp_tool_call', 'tool_call', 'function_call',
    'custom_tool_call', 'web_search_call', 'file_change',
))


def clean_subscription_env(base_env=None):
    """Return a minimal allowlisted environment with all direct API-billing keys stripped."""
    source = os.environ if base_env is None else base_env
    env = {
        k: v for k, v in source.items()
        if k in ALLOWED_SUBSCRIPTION_ENV_VARS and k not in STRIPPED_API_ENV_VARS
    }
    env['NO_COLOR'] = '1'
    return env


def _validate_cli_model(raw_model):
    if not isinstance(raw_model, str) or not _MODEL_ID_RE.fullmatch(raw_model):
        raise ValueError('invalid model identifier')
    return raw_model


def _resolve_windows_cmd_shim(shim_path):
    """Resolve an npm `.cmd` wrapper to `[node_exe, script_js]` without `cmd.exe`."""
    shim = Path(shim_path).resolve()
    shim_dir = shim.parent
    exe_sibling = shim.with_suffix('.exe')
    if exe_sibling.is_file() and not exe_sibling.is_symlink():
        return [str(exe_sibling)]
    if shim.stat().st_size > 16384:
        raise RuntimeError('refusing oversized .cmd wrapper')
    text = shim.read_text(encoding='utf-8', errors='replace')
    match = _NPM_CMD_JS_RE.search(text)
    if match is None:
        raise RuntimeError('unable to resolve JS entrypoint from .cmd wrapper')
    rel_js = match.group(1).replace('\\', '/')
    js_path = (shim_dir / rel_js).resolve()
    try:
        js_path.relative_to(shim_dir)
    except ValueError:
        raise RuntimeError('resolved JS entrypoint escapes wrapper directory') from None
    if not js_path.is_file():
        raise RuntimeError('resolved JS entrypoint does not exist')
    bundled_node = shim_dir / 'node.exe'
    node_bin = str(bundled_node) if bundled_node.is_file() else (shutil.which('node.exe') or shutil.which('node'))
    if not node_bin:
        raise RuntimeError('node runtime not found for CLI JS entrypoint')
    return [node_bin, str(js_path)]


def resolve_cli_command(name):
    """Return a direct argv prefix `[executable, ...]` for `claude` or `codex` (never `cmd.exe`)."""
    candidates = []
    if os.name == 'nt':
        found_exe = shutil.which(name + '.exe')
        if found_exe:
            candidates.append(found_exe)
    found = shutil.which(name)
    if found:
        candidates.append(found)
    if os.name == 'nt':
        home = Path.home()
        if name == 'claude':
            candidates.extend([
                str(home / '.local' / 'bin' / 'claude.exe'),
                str(home / 'AppData' / 'Local' / 'Programs' / 'claude' / 'claude.exe'),
                str(home / 'AppData' / 'Roaming' / 'npm' / 'claude.cmd'),
            ])
        elif name == 'codex':
            candidates.extend([
                str(home / '.local' / 'bin' / 'codex.exe'),
                str(home / 'AppData' / 'Roaming' / 'npm' / 'codex.cmd'),
            ])
    for candidate in candidates:
        p = Path(candidate)
        if not p.is_file():
            continue
        if os.name == 'nt' and p.suffix.lower() in ('.cmd', '.bat'):
            return _resolve_windows_cmd_shim(p)
        return [str(p)]
    return None


def resolve_cli_binary(name):
    """Backward-compatible helper returning the primary executable path or None."""
    cmd = resolve_cli_command(name)
    return cmd[0] if cmd else None


def _render_messages(messages, response_format=None, max_tokens=None):
    system_parts = []
    convo_parts = []
    for msg in messages:
        if type(msg) is not dict:
            continue
        role = msg.get('role', 'user')
        content = msg.get('content', '')
        if isinstance(content, list):
            content = '\n'.join(
                b.get('text', '') for b in content if type(b) is dict and isinstance(b.get('text'), str)
            )
        content = str(content)
        if role == 'system':
            system_parts.append(content)
        elif role == 'assistant':
            convo_parts.append('<previous_assistant_turn>\n' + content + '\n</previous_assistant_turn>')
        else:
            convo_parts.append(content)

    if type(response_format) is dict and response_format.get('type') == 'json_schema':
        js = response_format.get('json_schema') or {}
        schema = js.get('schema')
        if type(schema) is dict:
            system_parts.append(
                'Your output MUST be a single raw JSON object conforming to this JSON Schema '
                '(no markdown fences, no commentary):\n' + json.dumps(schema, separators=(',', ':'))
            )
    if type(max_tokens) is int and max_tokens > 0:
        system_parts.append(
            'Keep your response concise and strictly within {} output tokens.'.format(max_tokens)
        )
    system_prompt = '\n\n'.join(p for p in system_parts if p.strip()) or (
        'Follow the user prompt exactly and output raw JSON without markdown fences.'
    )
    user_prompt = '\n\n'.join(p for p in convo_parts if p.strip())
    return system_prompt, user_prompt


def _enforce_output_budget(result, max_tokens):
    """Enforce `max_tokens` on subscription CLI responses that have no native token flag."""
    if type(max_tokens) is not int or max_tokens <= 0:
        return result
    content = str(result.get('content') or '')
    usage = result.get('usage')
    if type(usage) is dict and type(usage.get('completion_tokens')) is int:
        if usage['completion_tokens'] > max_tokens:
            return dict(result, finish_reason='length')
        return result
    # When the CLI omits token usage altogether, UTF-8 byte count is a strict upper bound on tokens.
    encoded = content.encode('utf-8')
    if len(encoded) > max_tokens:
        return dict(
            result,
            finish_reason='length',
            content=encoded[:max_tokens].decode('utf-8', 'ignore'),
        )
    return result


def invoke_claude_subscription(model_requested, messages, response_format=None, timeout_seconds=180,
                               max_tokens=None):
    """Run one stateless prompt through `claude -p` using OAuth subscription auth."""
    cmd_prefix = resolve_cli_command('claude')
    if not cmd_prefix:
        raise RuntimeError('claude CLI not found')
    system_prompt, user_prompt = _render_messages(messages, response_format, max_tokens=max_tokens)
    cli_model = model_requested
    if cli_model.startswith('claude-subscription/'):
        cli_model = cli_model.split('/', 1)[1]
    cli_model = _validate_cli_model(cli_model)

    # Deliver full system + user payload over stdin so large JSON Schemas never hit
    # Windows CreateProcessW 32 KiB command-line limits.
    combined_stdin = (
        '<system_instructions>\n' + system_prompt + '\n</system_instructions>\n\n' + user_prompt
    )
    short_sys = 'Follow <system_instructions> in the user message and output only valid raw JSON without markdown fences.'
    env = clean_subscription_env()
    with tempfile.TemporaryDirectory(prefix='bench-claude-empty-') as empty_dir:
        cmd = list(cmd_prefix) + [
            '-p',
            '--output-format', 'json',
            '--model', cli_model,
            '--tools', '',
            '--no-session-persistence',
            '--setting-sources', '',
            '--system-prompt', short_sys,
        ]
        proc = subprocess.run(
            cmd,
            input=combined_stdin.encode('utf-8'),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=empty_dir,
            env=env,
            timeout=timeout_seconds,
            check=False,
        )
    if proc.returncode != 0:
        raise RuntimeError('claude CLI exited {}'.format(proc.returncode))
    payload = json.loads(proc.stdout.decode('utf-8', 'replace'))
    if payload.get('is_error'):
        raise RuntimeError('claude CLI reported error')
    result_text = str(payload.get('result') or '')
    model_usage = payload.get('modelUsage') or {}
    actual_model = next(iter(model_usage.keys()), None)
    raw_usage = payload.get('usage')
    usage_obj = None
    if type(raw_usage) is dict and type(raw_usage.get('input_tokens')) is int and type(raw_usage.get('output_tokens')) is int:
        cached_in = int(raw_usage.get('cache_read_input_tokens') or 0)
        direct_in = int(raw_usage.get('input_tokens') or 0) + int(raw_usage.get('cache_creation_input_tokens') or 0)
        total_in = direct_in + cached_in
        out_tok = int(raw_usage.get('output_tokens') or 0)
        usage_obj = {
            'prompt_tokens': total_in,
            'completion_tokens': out_tok,
            'total_tokens': total_in + out_tok,
            'prompt_tokens_details': {'cached_tokens': cached_in},
        }
    stop_reason = 'length' if payload.get('stop_reason') == 'max_tokens' else 'stop'
    return _enforce_output_budget({
        'model': actual_model,
        'content': result_text,
        'finish_reason': stop_reason,
        'usage': usage_obj,
    }, max_tokens)


def _default_codex_model():
    cfg = Path.home() / '.codex' / 'config.toml'
    if cfg.is_file():
        for line in cfg.read_text(encoding='utf-8', errors='replace').splitlines():
            stripped = line.strip()
            if stripped.startswith('model') and '=' in stripped and not stripped.startswith('model_'):
                rhs = stripped.split('=', 1)[1].strip().strip('"').strip("'")
                if rhs and _MODEL_ID_RE.fullmatch(rhs):
                    return rhs
    return 'codex-subscription'


def invoke_codex_subscription(model_requested, messages, response_format=None, timeout_seconds=180,
                              max_tokens=None):
    """Run one stateless tool-disabled prompt through `codex exec --json` using OAuth."""
    cmd_prefix = resolve_cli_command('codex')
    if not cmd_prefix:
        raise RuntimeError('codex CLI not found')
    system_prompt, user_prompt = _render_messages(messages, response_format, max_tokens=max_tokens)
    combined_prompt = (
        '<system_instructions>\n' + system_prompt + '\n</system_instructions>\n\n' + user_prompt
    )
    cli_model = model_requested
    if cli_model.startswith('codex-subscription/'):
        cli_model = cli_model.split('/', 1)[1]
    effort = 'medium'
    if '@' in cli_model:
        cli_model, effort = cli_model.split('@', 1)
    if effort not in ALLOWED_REASONING_EFFORTS:
        raise ValueError('unsupported reasoning effort')
    if cli_model and cli_model not in ('codex-default', 'default'):
        cli_model = _validate_cli_model(cli_model)

    env = clean_subscription_env()
    with tempfile.TemporaryDirectory(prefix='bench-codex-empty-') as empty_dir:
        base_args = [
            'exec',
            '--skip-git-repo-check',
            '--ephemeral',
            '--disable', 'shell_tool',
            '--disable', 'unified_exec',
            '--disable', 'view_image',
            '-c', 'mcp_servers={}',
            '-s', 'read-only',
            '-C', empty_dir,
            '-c', 'model_reasoning_effort="{}"'.format(effort),
            '--json',
        ]
        if cli_model and cli_model not in ('codex-default', 'default'):
            base_args.extend(['-m', cli_model])
        base_args.append('-')
        proc = subprocess.run(
            list(cmd_prefix) + base_args,
            input=combined_prompt.encode('utf-8'),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=empty_dir,
            env=env,
            timeout=timeout_seconds,
            check=False,
        )
    if proc.returncode != 0:
        raise RuntimeError('codex CLI exited {}'.format(proc.returncode))

    last_text = ''
    in_tok = cached_tok = out_tok = 0
    saw_usage = False
    reported_model = None
    for line in proc.stdout.decode('utf-8', 'replace').splitlines():
        line = line.strip()
        if not line.startswith('{'):
            continue
        try:
            event = json.loads(line)
        except ValueError:
            continue
        etype = event.get('type', '')
        if isinstance(event.get('model'), str) and event['model'].strip():
            reported_model = event['model'].strip()
        item = event.get('item')
        if type(item) is dict:
            itype = str(item.get('type') or '')
            if itype in _FORBIDDEN_CODEX_ITEM_TYPES or itype.endswith(('_call', '_execution')):
                raise RuntimeError('codex CLI attempted forbidden tool execution: {}'.format(itype))
            if itype in ('agent_message', 'message'):
                if isinstance(item.get('text'), str) and item['text'].strip():
                    last_text = item['text']
                elif type(item.get('content')) is list:
                    joined = ''.join(
                        c.get('text', '') for c in item['content'] if type(c) is dict and isinstance(c.get('text'), str)
                    )
                    if joined.strip():
                        last_text = joined
        if etype == 'turn.completed' and type(event.get('usage')) is dict:
            u = event['usage']
            if type(u.get('input_tokens')) is int and type(u.get('output_tokens')) is int:
                saw_usage = True
                in_tok += u['input_tokens']
                cached_tok += int(u.get('cached_input_tokens') or 0)
                out_tok += u['output_tokens']

    if not last_text.strip():
        raise RuntimeError('codex CLI returned empty agent_message')
    usage_obj = None
    if saw_usage:
        usage_obj = {
            'prompt_tokens': in_tok,
            'completion_tokens': out_tok,
            'total_tokens': in_tok + out_tok,
            'prompt_tokens_details': {'cached_tokens': min(cached_tok, in_tok)},
        }
    return _enforce_output_budget({
        'model': reported_model,
        'content': last_text,
        'finish_reason': 'stop',
        'usage': usage_obj,
    }, max_tokens)


PUBLIC_PROVENANCE = ('synthetic', 'public_replay')


def _validate_generation_params(req):
    """Validate OpenAI Chat Completions generation parameters for CLI subscription dispatch."""
    temp = req.get('temperature')
    if temp is not None:
        raise ValueError('subscription proxy requires temperature null (CLI harnesses do not accept sampling temperature)')
    seed = req.get('seed')
    if seed is not None:
        raise ValueError('subscription proxy does not support sampling seed')
    raw_max = req.get('max_tokens') if req.get('max_tokens') is not None else req.get('max_completion_tokens')
    if raw_max is not None:
        if type(raw_max) is not int or type(raw_max) is bool or raw_max < 1:
            raise ValueError('invalid max_tokens')
    return raw_max


def dispatch_subscription_model(model_requested, messages, response_format=None, timeout_seconds=180,
                                max_tokens=None):
    if not isinstance(model_requested, str) or not model_requested.strip():
        raise ValueError('missing model identifier')
    lower = model_requested.lower()
    if lower.startswith('claude-subscription/'):
        return invoke_claude_subscription(
            model_requested, messages, response_format, timeout_seconds, max_tokens=max_tokens
        )
    if lower.startswith('codex-subscription/'):
        return invoke_codex_subscription(
            model_requested, messages, response_format, timeout_seconds, max_tokens=max_tokens
        )
    raise ValueError('subscription proxy requires explicit claude-subscription/ or codex-subscription/ model prefix')


_PATH_PROVENANCE_RE = re.compile(r'^/provenance/([a-z_]+)(/released)?/v1/chat/completions$')


class SubscriptionThreadingHTTPServer(ThreadingHTTPServer):
    def __init__(self, server_address, handler_class, auth_token, default_timeout=240,
                 allow_private_evidence=False):
        super().__init__(server_address, handler_class)
        self.auth_token = auth_token
        self.default_timeout = int(default_timeout)
        self.allow_private_evidence = bool(allow_private_evidence)


class SubscriptionProxyHandler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, fmt, *args):
        return

    def _send_json(self, status, payload):
        body = json.dumps(payload, separators=(',', ':')).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _check_request_guards(self):
        # Reject browser cross-origin requests outright regardless of credentials.
        if self.headers.get('Origin') is not None or self.headers.get('Sec-Fetch-Site') is not None:
            self._send_json(403, {'error': 'browser_origin_forbidden'})
            return False
        expected = getattr(self.server, 'auth_token', None)
        if not isinstance(expected, str) or not expected:
            self._send_json(500, {'error': 'server_auth_unconfigured'})
            return False
        auth_header = self.headers.get('Authorization') or ''
        if not auth_header.startswith('Bearer '):
            self._send_json(401, {'error': 'unauthorized'})
            return False
        supplied = auth_header[len('Bearer '):]
        if not hmac.compare_digest(supplied.encode('utf-8'), expected.encode('utf-8')):
            self._send_json(401, {'error': 'unauthorized'})
            return False
        return True

    def do_GET(self):
        if self.headers.get('Origin') is not None or self.headers.get('Sec-Fetch-Site') is not None:
            self._send_json(403, {'error': 'browser_origin_forbidden'})
            return
        if self.path.rstrip('/') == '/health':
            self._send_json(200, {'status': 'ok', 'billing': 'oauth_subscription_only'})
            return
        if self.path.rstrip('/') == '/v1/models':
            if not self._check_request_guards():
                return
            self._send_json(200, {'status': 'ok', 'billing': 'oauth_subscription_only'})
            return
        self._send_json(404, {'error': 'not_found'})

    def do_POST(self):
        clean_path = self.path.rstrip('/')
        if not clean_path.endswith('/chat/completions'):
            self._send_json(404, {'error': 'not_found'})
            return
        if not self._check_request_guards():
            return
        ctype = (self.headers.get('Content-Type') or '').split(';', 1)[0].strip().lower()
        if ctype != 'application/json':
            self._send_json(415, {'error': 'unsupported_media_type'})
            return
        try:
            length = int(self.headers.get('Content-Length') or '0')
            if length <= 0 or length > 4 * 1024 * 1024:
                self._send_json(400, {'error': 'invalid_content_length'})
                return
            raw = self.rfile.read(length)
            req = json.loads(raw.decode('utf-8'))
            if type(req) is not dict:
                self._send_json(400, {'error': 'invalid_json_object'})
                return
            model = str(req.get('model') or '')
            messages = req.get('messages') or []
            if type(messages) is not list:
                self._send_json(400, {'error': 'invalid_messages'})
                return
            path_match = _PATH_PROVENANCE_RE.match(clean_path)
            prov = (self.headers.get('X-Benchmark-Provenance') or '').strip()
            if not prov and path_match is not None:
                prov = path_match.group(1)
            rel_auth = (
                (self.headers.get('X-Benchmark-Release-Authorized') or '').strip().lower() == 'true'
                or (path_match is not None and bool(path_match.group(2)))
            )
            has_benchmark_evidence = any(
                type(m) is dict and '"untrusted_public_evidence"' in str(m.get('content') or '')
                for m in messages
            )
            if ((prov and prov not in PUBLIC_PROVENANCE) or (has_benchmark_evidence and prov not in PUBLIC_PROVENANCE)):
                if not (getattr(self.server, 'allow_private_evidence', False) and rel_auth):
                    self._send_json(403, {'error': 'private_evidence_release_required'})
                    return
            max_tokens = _validate_generation_params(req)
            response_format = req.get('response_format')
            timeout_s = getattr(self.server, 'default_timeout', 240)
            result = dispatch_subscription_model(
                model, messages, response_format=response_format, timeout_seconds=timeout_s,
                max_tokens=max_tokens,
            )
            self._send_json(200, {
                'id': 'subproxy-' + str(int(time.time() * 1000)),
                'object': 'chat.completion',
                'created': int(time.time()),
                'model': result['model'],
                'choices': [{
                    'index': 0,
                    'message': {'role': 'assistant', 'content': result['content']},
                    'finish_reason': result['finish_reason'],
                }],
                'usage': result['usage'],
            })
        except ValueError:
            self._send_json(400, {'error': 'invalid_request'})
        except Exception as exc:
            self._send_json(502, {'error': type(exc).__name__})


def start_background_server(host='127.0.0.1', port=0, timeout_seconds=240, auth_token=None,
                            allow_private_evidence=False):
    if host != '127.0.0.1':
        raise ValueError('Subscription proxy binds only to 127.0.0.1')
    token = auth_token if (isinstance(auth_token, str) and len(auth_token) >= 16) else secrets.token_hex(32)
    return SubscriptionThreadingHTTPServer(
        (host, port), SubscriptionProxyHandler, token, timeout_seconds,
        allow_private_evidence=allow_private_evidence,
    )


def main(argv=None):
    ap = argparse.ArgumentParser(description='Run OAuth subscription loopback OpenAI proxy.')
    ap.add_argument('--port', type=int, default=18941, help='Loopback TCP port on 127.0.0.1')
    ap.add_argument('--timeout', type=int, default=240, help='Per-CLI invocation timeout in seconds')
    ap.add_argument(
        '--token-env',
        default='BENCH_MODEL_SUBSCRIPTION_TOKEN',
        help='Environment variable holding the required Bearer token (>=16 chars); generates a fresh token if unset',
    )
    ap.add_argument(
        '--allow-released-private-evidence',
        action='store_true',
        help='Allow benchmark prompts with non-public provenance after runner release verification',
    )
    args = ap.parse_args(argv)
    env_tok = os.environ.get(args.token_env, '') if args.token_env else ''
    generated = False
    if len(env_tok) >= 16:
        token = env_tok
    else:
        token = secrets.token_hex(32)
        generated = True
    server = start_background_server(
        '127.0.0.1', args.port, timeout_seconds=args.timeout, auth_token=token,
        allow_private_evidence=args.allow_released_private_evidence,
    )
    actual_port = server.server_address[1]
    info = {
        'status': 'listening',
        'base_url': 'http://127.0.0.1:{}/v1'.format(actual_port),
        'billing': 'oauth_subscription_only',
        'token_env': args.token_env,
        'token_generated': generated,
    }
    if generated:
        info['bearer_token'] = token
    print(json.dumps(info), flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == '__main__':
    sys.exit(main())

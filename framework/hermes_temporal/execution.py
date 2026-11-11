"""Explicit native Hermes transport and local, at-most-once dispatch receipts.

Receipts coordinate workers sharing one durable SQLite file on one host; they
are not a sandbox, an authentication mechanism, or a distributed lock across
independent receipt stores. Losing that file loses the dispatch protection.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import threading

from .contracts import MAX_DIAGNOSTIC_CHARS, ExecutionRequest, ExecutionResult

PROFILES = frozenset({
    'framework-coordinator', 'framework-researcher', 'framework-builder',
    'framework-reviewer', 'framework-librarian', 'framework-network-analyst',
})
MAX_PROMPT_BYTES = 65536
MAX_OUTPUT_BYTES = 65536
MAX_TURNS = 32
# Raw stream-json stdout of one step; a tool-heavy step emits far more than its final text.
MAX_STREAM_BYTES = 16 * 1024 * 1024
# A result line still fits when all MAX_OUTPUT_BYTES of its text are \uXXXX escapes; longer lines are dropped unparsed.
MAX_STREAM_LINE_BYTES = 1024 * 1024
# Only the end of stderr is kept; the rest is drained and discarded so the child never blocks on it.
MAX_STDERR_TAIL_BYTES = 4096
MAX_CAUSE_CHARS = 600
_DIAGNOSED_REASONS = frozenset({'native_nonzero', 'output_unavailable', 'subprocess_timeout'})
# Hermes logs a provider refusal only in the profile's agent.log, tagged with the session ID; its
# stream record shows just a zero-token failure.
_DECLINED = re.compile(r"\[(?P<session>[A-Za-z0-9_-]{1,128})\] agent\.conversation_loop: Model declined to respond "
                       r"\(finish_reason=(?P<reason>[a-z_]{1,40})\)(?:.*?'category': '(?P<category>[a-z_]{1,40})')?")
_SESSION_ID = re.compile(r'[A-Za-z0-9_-]{1,128}\Z')
MAX_LOG_SCAN_BYTES = 4 * 1024 * 1024
_ANSI_ESCAPE = re.compile(r'\x1b\[[0-?]*[ -/]*[@-~]')
_EXCEPTION_LINE = re.compile(r'(?:[A-Za-z_]\w*\.)*\w*(?:Error|Exception|Exit|Interrupt|Failure)\b(?::.*)?\Z')
_ERROR_LINE = re.compile(r'(?i)\b(?:error|fatal|failed)\b')
_SECRETS = (
    (re.compile(r'(?i)\b((?:proxy-)?authorization|set-cookie|cookie)\b\s*[:=].*'), r'\1: [redacted]'),
    (re.compile(r'(?i)\b(bearer|basic)\s+[^\s,;]+'), r'\1 [redacted]'),
    (re.compile(r'(?i)\b([\w-]*(?:api[_-]?key|token|secret|password|passwd|credentials?|signature|sig))\b'
                r'(["\']?\s*[:=]\s*["\']?)[^\s"\',;&]+'), r'\1\2[redacted]'),
    (re.compile(r'://[^/\s@]+@'), '://[redacted]@'),
    (re.compile(r'(?i)(https?://[^\s?#]+)[?#]\S*'), r'\1?[redacted]'),
    (re.compile(r'(?i)\b(?:sk|pk|rk)-[A-Za-z0-9_-]{8,}'), '[redacted]'),
    (re.compile(r'(?i)\bxox[a-z]-[A-Za-z0-9-]+'), '[redacted]'),
    (re.compile(r'\b(?:gh[pousr]_|github_pat_|glpat-|hf_|AKIA|ASIA|AIza)[A-Za-z0-9_-]{8,}'), '[redacted]'),
    (re.compile(r'\beyJ[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]+)*'), '[redacted]'),
)
_LONG_RUN = re.compile(r'[A-Za-z0-9+/=_-]{32,}')
_USAGE_FIELDS = (('input_tokens', 'input'), ('output_tokens', 'output'), ('cache_read_tokens', 'cache_read'),
                 ('cache_write_tokens', 'cache_write'), ('total_tokens', 'total'))
_ADDED_RECEIPT_COLUMNS = ('usage', 'session_id')
_STEP_ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z')


@dataclass(frozen=True)
class ExecutionConfig:
    enabled: bool = False
    executable: str | None = None
    hermes_home: str | None = None
    working_directory: str | None = None
    receipt_db: str | None = None
    # Explicit operator opt-in to dispatch through their own signed-in Hermes home.
    allow_operator_home: bool = False
    # Hermes hides --source tool sessions from user session lists; 'cli' shows them.
    visible_sessions: bool = False
    # Run Hermes with stream-json output so each result carries token counts and wall time.
    record_usage: bool = False


def _result(request: ExecutionRequest, status: str, reason: str, output: str = '',
            session_id: str | None = None, usage: dict | None = None) -> ExecutionResult:
    return ExecutionResult(status=status, execution_id=request.execution_id, output=output,
                           reason_code=reason, session_id=session_id, usage=usage)


def _valid_request(request: ExecutionRequest) -> bool:
    try:
        step = request.step
        return (isinstance(request.execution_id, str) and bool(request.execution_id)
                and len(request.execution_id.encode('utf-8')) <= 512
                and isinstance(step.step_id, str) and _STEP_ID.fullmatch(step.step_id) is not None
                and isinstance(step.prompt, str) and bool(step.prompt.strip())
                and len(step.prompt.encode('utf-8')) <= MAX_PROMPT_BYTES
                and step.profile in PROFILES and type(step.timeout_seconds) is int
                and 1 <= step.timeout_seconds <= 3600)
    except (AttributeError, TypeError, UnicodeError):
        return False


def _valid_config(config: ExecutionConfig) -> bool:
    try:
        paths = [config.executable, config.hermes_home, config.working_directory, config.receipt_db]
        if not all(isinstance(p, str) and p and Path(p).is_absolute() for p in paths):
            return False
        executable, home, cwd, receipt = (Path(p).resolve() for p in paths)
        if (not executable.is_file() or executable.suffix.lower() in ('.bat', '.cmd')
                or not home.is_dir() or not cwd.is_dir() or not receipt.parent.is_dir()):
            return False
        # A separately provisioned home is mandatory unless the operator explicitly
        # opts in to their own live home (existing sign-in, no credential copying).
        if config.allow_operator_home is True:
            return True
        live_homes = [Path.home() / '.hermes']
        if os.environ.get('LOCALAPPDATA'):
            live_homes.append(Path(os.environ['LOCALAPPDATA']) / 'hermes')
        for live in live_homes:
            live = live.resolve()
            if home == live or live in home.parents or home in live.parents:
                return False
        return True
    except (OSError, RuntimeError, ValueError):
        return False


def _fingerprint(request: ExecutionRequest) -> str:
    step = request.step
    fields = [step.step_id, step.prompt, step.profile, step.timeout_seconds]
    if step.hunt_context is not None:
        fields.append(step.hunt_context)
    data = json.dumps(fields, ensure_ascii=True, sort_keys=True,
                      separators=(',', ':')).encode('ascii')
    return hashlib.sha256(data).hexdigest()


def _missing_receipt_columns(db: sqlite3.Connection) -> list[str]:
    present = {row[1] for row in db.execute('PRAGMA table_info(receipts)')}
    return [column for column in _ADDED_RECEIPT_COLUMNS if column not in present]


class ReceiptStore:
    """Reserve in an immediate, fully synchronous transaction before dispatch."""
    def __init__(self, path: str):
        self.path = path

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        db.execute('PRAGMA synchronous=FULL')
        db.execute('CREATE TABLE IF NOT EXISTS receipts ('
                   'execution_id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, '
                   'status TEXT NOT NULL, reason TEXT NOT NULL, output TEXT NOT NULL, '
                   'usage TEXT, session_id TEXT)')
        if _missing_receipt_columns(db):
            # Workers may open a five-column database together; recheck under the write lock
            # so each column is added once.
            db.execute('BEGIN IMMEDIATE')
            for column in _missing_receipt_columns(db):
                db.execute(f'ALTER TABLE receipts ADD COLUMN {column} TEXT')
            db.execute('COMMIT')
        return db

    def reserve(self, request: ExecutionRequest) -> ExecutionResult | None:
        fingerprint = _fingerprint(request)
        with closing(self._connect()) as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT fingerprint, status, reason, output, usage, session_id FROM receipts '
                             'WHERE execution_id = ?', (request.execution_id,)).fetchone()
            if row is None:
                db.execute('INSERT INTO receipts (execution_id, fingerprint, status, reason, output) '
                           'VALUES (?, ?, ?, ?, ?)', (request.execution_id, fingerprint, 'reserved', '', ''))
                db.execute('COMMIT')
                return None
            db.execute('COMMIT')
        old_fingerprint, status, reason, output, usage, session_id = row
        if old_fingerprint != fingerprint:
            return _result(request, 'failed', 'fingerprint_conflict')
        usage = None if usage is None else json.loads(usage)
        if status in ('completed', 'failed'):
            return _result(request, status, reason, output, session_id, usage)
        return _result(request, 'unknown', 'previous_dispatch_unknown', session_id=session_id, usage=usage)

    def finish(self, result: ExecutionResult) -> None:
        with closing(self._connect()) as db:
            db.execute('BEGIN IMMEDIATE')
            cursor = db.execute('UPDATE receipts SET status = ?, reason = ?, output = ?, usage = ?, session_id = ? '
                                'WHERE execution_id = ? AND status = ?',
                                (result.status, result.reason_code, result.output,
                                 None if result.usage is None else json.dumps(result.usage, sort_keys=True),
                                 result.session_id, result.execution_id, 'reserved'))
            if cursor.rowcount != 1:
                db.execute('ROLLBACK')
                raise RuntimeError('receipt state changed')
            db.execute('COMMIT')


def _environment(home: str, executable: str) -> dict[str, str]:
    # All user-specific discovery paths stay inside the explicitly approved home.
    root = Path(home).resolve()
    base = root / '.temporal-process'
    directories = {
        'HOME': base / 'home', 'APPDATA': base / 'appdata',
        'LOCALAPPDATA': base / 'localappdata', 'CODEX_HOME': base / 'codex',
        'XDG_CONFIG_HOME': base / 'xdg-config', 'XDG_DATA_HOME': base / 'xdg-data',
        'XDG_CACHE_HOME': base / 'xdg-cache', 'XDG_STATE_HOME': base / 'xdg-state',
        'XDG_RUNTIME_DIR': base / 'xdg-runtime', 'PYTHONUSERBASE': base / 'python-user',
        'TMP': base / 'tmp',
    }
    for directory in directories.values():
        if root not in directory.resolve().parents:
            raise ValueError('execution environment directory escapes approved home')
        directory.mkdir(parents=True, exist_ok=True)
        if root not in directory.resolve().parents:
            raise ValueError('execution environment directory escapes approved home')
    env = {key: str(value) for key, value in directories.items()}
    env.update({'HERMES_HOME': str(root), 'HERMES_REAL_HOME': env['HOME'],
                'USERPROFILE': env['HOME'], 'TEMP': env['TMP'], 'TMPDIR': env['TMP'],
                'PYTHONIOENCODING': 'utf-8'})
    # Do not inherit user PATH or provider secrets. Permit the explicit binary's
    # directory and conventional system tools, but never the current directory.
    system_root = os.environ.get('SYSTEMROOT')
    system_paths = ([str(Path(system_root) / 'System32'), system_root]
                    if os.name == 'nt' and system_root else ['/usr/bin', '/bin'])
    env['PATH'] = os.pathsep.join([str(Path(executable).resolve().parent), *system_paths])
    for name in ('SYSTEMROOT', 'WINDIR', 'COMSPEC', 'PATHEXT', 'LANG', 'LC_ALL'):
        if name in os.environ:
            env[name] = os.environ[name]
    return env


class _ResultStream:
    """Keep the last `result` record of stream-json stdout while holding at most one bounded line."""
    def __init__(self) -> None:
        self.record: dict | None = None
        self.dropped_line = False
        self._line = bytearray()
        self._dropping = False

    def feed(self, part: bytes) -> None:
        *complete, rest = part.split(b'\n')
        for piece in complete:
            self._extend(piece)
            self.end_line()
        self._extend(rest)

    def _extend(self, piece: bytes) -> None:
        if self._dropping:
            return
        if len(self._line) + len(piece) > MAX_STREAM_LINE_BYTES:
            self._line.clear()
            self._dropping = self.dropped_line = True
        else:
            self._line += piece

    def end_line(self) -> None:
        if not self._dropping:
            try:
                value = json.loads(self._line)
            except (ValueError, RecursionError):
                value = None
            if isinstance(value, dict) and value.get('type') == 'result':
                self.record = value
        self._line.clear()
        self._dropping = False


def _utf8_size(value: object) -> int | None:
    try:
        return len(value.encode('utf-8')) if isinstance(value, str) else None
    except UnicodeEncodeError:
        return None


def _usage(record: dict) -> dict | None:
    tokens = record.get('tokens')
    if not isinstance(tokens, dict):
        return None
    usage = {key: tokens.get(name) for key, name in _USAGE_FIELDS}
    usage['duration_ms'] = record.get('duration_ms')
    if any(type(value) is not int or value < 0 for value in usage.values()):
        return None
    return usage


def _stream_result(request: ExecutionRequest, stream: _ResultStream, returncode: int) -> ExecutionResult:
    record = stream.record
    if record is None:
        if returncode != 0:
            return _result(request, 'unknown', 'native_nonzero')
        return _result(request, 'unknown', 'output_limit' if stream.dropped_line else 'output_unavailable')
    session_id = record.get('session_id')
    spend = {'session_id': session_id if _utf8_size(session_id) is not None else None, 'usage': _usage(record)}
    exit_code = record.get('exit_code', 0)
    if returncode != 0 or type(exit_code) is not int or exit_code != 0:
        return _result(request, 'unknown', 'native_nonzero', **spend)
    text = record.get('text')
    size = _utf8_size(text)
    if size is None or not text.strip():
        return _result(request, 'unknown', 'output_unavailable', **spend)
    if size > MAX_OUTPUT_BYTES:
        return _result(request, 'unknown', 'output_limit', **spend)
    return _result(request, 'completed', 'completed', text, **spend)


def _plain_result(request: ExecutionRequest, chunks: list[bytes], returncode: int) -> ExecutionResult:
    if returncode != 0:
        return _result(request, 'unknown', 'native_nonzero')
    try:
        output = b''.join(chunks).decode('utf-8', errors='strict')
    except UnicodeDecodeError:
        return _result(request, 'unknown', 'output_unavailable')
    if not output.strip():
        return _result(request, 'unknown', 'output_unavailable')
    return _result(request, 'completed', 'completed', output)


def _redact(line: str) -> str:
    for pattern, replacement in _SECRETS:
        line = pattern.sub(replacement, line)
    # Long base64/hex runs with a digit are treated as keys; identifiers and paths rarely qualify.
    return _LONG_RUN.sub(lambda match: '[redacted]' if len(match[0]) >= 48 or any(
        character.isdigit() for character in match[0]) else match[0], line)


def _safe_line(line: str) -> str:
    printable = ''.join(character if ' ' <= character <= '~' else ' ' if character == '\t' else '?'
                        for character in _ANSI_ESCAPE.sub('', line))
    return ' '.join(_redact(printable).split())


def _diagnostic(exit_code: int, tail: bytes, cut: bool) -> str:
    """Exit code plus a redacted printable-ASCII cause from stderr's end, preferring the last exception line."""
    text = tail.decode('utf-8', errors='replace')
    if cut:
        # The first kept line may start inside a secret whose prefix the patterns need.
        text = text.partition('\n')[2]
    lines = [line for line in map(_safe_line, text.splitlines()) if line]
    cause = next((line for line in reversed(lines) if _EXCEPTION_LINE.match(line)), None)
    if cause is None:
        cause = next((line for line in reversed(lines) if _ERROR_LINE.search(line)), None)
    if cause is not None:
        cause = cause if len(cause) <= MAX_CAUSE_CHARS else cause[:MAX_CAUSE_CHARS - 3] + '...'
    else:
        cause = ' | '.join(lines[-3:])
        cause = cause if len(cause) <= MAX_CAUSE_CHARS else '...' + cause[3 - MAX_CAUSE_CHARS:]
    diagnostic = f'exit code {exit_code}: {cause}' if cause else f'exit code {exit_code}; no stderr'
    return diagnostic[:MAX_DIAGNOSTIC_CHARS]


def _invoke(config: ExecutionConfig, request: ExecutionRequest) -> ExecutionResult:
    step = request.step
    command = [config.executable, '-p', step.profile, 'chat', '--oneshot', '--quiet',
               '--query-file', '-', '--source', 'cli' if config.visible_sessions is True else 'tool',
               '--max-turns', str(MAX_TURNS)]
    stream = None
    limit = MAX_OUTPUT_BYTES
    if config.record_usage is True:
        command += ['--format', 'stream-json']
        stream = _ResultStream()
        limit = MAX_STREAM_BYTES
    try:
        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, cwd=config.working_directory,
                                   env=_environment(config.hermes_home, config.executable), shell=False)
    except (OSError, ValueError):
        return _result(request, 'failed', 'launch_failed')
    write_error = threading.Event()

    chunks: list[bytes] = []
    overflow = threading.Event()
    read_error = threading.Event()
    # (last bytes of stderr, whether earlier bytes were discarded), rebound whole so a snapshot is consistent.
    stderr_tail = (b'', False)

    def read_output() -> None:
        size = 0
        try:
            while True:
                part = os.read(process.stdout.fileno(), 8192)
                if not part:
                    if stream is not None:
                        stream.end_line()
                    break
                size += len(part)
                if size > limit:
                    overflow.set()
                    try:
                        process.kill()
                    except OSError:
                        pass
                    break
                if stream is None:
                    chunks.append(part)
                else:
                    stream.feed(part)
        except (OSError, ValueError):
            read_error.set()
        finally:
            try:
                process.stdout.close()
            except OSError:
                read_error.set()

    def read_errors() -> None:
        nonlocal stderr_tail
        try:
            while True:
                part = os.read(process.stderr.fileno(), 8192)
                if not part:
                    break
                kept = stderr_tail[0] + part
                stderr_tail = (kept[-MAX_STDERR_TAIL_BYTES:], stderr_tail[1] or len(kept) > MAX_STDERR_TAIL_BYTES)
        except (OSError, ValueError):
            pass
        finally:
            try:
                process.stderr.close()
            except OSError:
                pass

    def send_prompt() -> None:
        try:
            process.stdin.write(step.prompt.encode('utf-8'))
        except (OSError, ValueError):
            write_error.set()
        finally:
            try:
                process.stdin.close()
            except OSError:
                write_error.set()

    reader = threading.Thread(target=read_output, daemon=True)
    errors = threading.Thread(target=read_errors, daemon=True)
    writer = threading.Thread(target=send_prompt, daemon=True)
    reader.start()
    errors.start()
    writer.start()
    timed_out = False
    try:
        process.wait(timeout=step.timeout_seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
        try:
            process.kill()
        except OSError:
            pass
        process.wait()
    reader.join(timeout=1)
    writer.join(timeout=1)
    if timed_out:
        result = _result(request, 'unknown', 'subprocess_timeout')
    elif overflow.is_set():
        result = _result(request, 'unknown', 'output_limit')
    elif reader.is_alive() or writer.is_alive() or read_error.is_set() or write_error.is_set():
        result = _result(request, 'unknown', 'output_unavailable')
    elif stream is not None:
        result = _stream_result(request, stream, process.returncode)
    else:
        result = _plain_result(request, chunks, process.returncode)
    if result.reason_code not in _DIAGNOSED_REASONS:
        return result
    errors.join(timeout=1)
    exit_code = process.returncode
    if exit_code == 0 and stream is not None and stream.record is not None \
            and type(stream.record.get('exit_code')) is int:
        exit_code = stream.record['exit_code']
    declined = _declined(config.hermes_home, step.profile, result.session_id)
    if declined is not None:
        return replace(result, diagnostic=f'exit code {exit_code}: {declined}')
    return replace(result, diagnostic=_diagnostic(exit_code, *stderr_tail))


def _declined(home: str, profile: str, session_id: str | None) -> str | None:
    """The refusal Hermes logged for this session in the profile's agent.log, if any."""
    if not isinstance(session_id, str) or not _SESSION_ID.match(session_id):
        return None
    try:
        with open(Path(home) / 'profiles' / profile / 'logs' / 'agent.log', 'rb') as log:
            log.seek(0, os.SEEK_END)
            log.seek(max(0, log.tell() - MAX_LOG_SCAN_BYTES))
            text = log.read().decode('utf-8', errors='replace')
    except (OSError, TypeError, ValueError):
        return None
    found = [match for match in _DECLINED.finditer(text) if match['session'] == session_id]
    if not found:
        return None
    category = f", category {found[-1]['category']}" if found[-1]['category'] else ''
    return f"model declined to respond (finish_reason={found[-1]['reason']}{category})"


def _refusal(config: ExecutionConfig, request: ExecutionRequest) -> ExecutionResult | None:
    if not _valid_request(request):
        return _result(request, 'failed', 'invalid_request')
    if not config.enabled:
        return _result(request, 'failed', 'execution_disabled')
    if not _valid_config(config):
        return _result(request, 'failed', 'invalid_configuration')
    return None


def invoke_step(config: ExecutionConfig, request: ExecutionRequest) -> ExecutionResult:
    """Run one step directly, with no receipt and therefore no at-most-once protection.

    For operator probes outside a workflow only: a repeated call dispatches Hermes again.
    Workflow steps go through `execute`.
    """
    refusal = _refusal(config, request)
    return _invoke(config, request) if refusal is None else refusal


def execute(config: ExecutionConfig, request: ExecutionRequest) -> ExecutionResult:
    refusal = _refusal(config, request)
    if refusal is not None:
        return refusal
    store = ReceiptStore(config.receipt_db)
    try:
        existing = store.reserve(request)
    except (sqlite3.Error, OSError):
        return _result(request, 'failed', 'receipt_unavailable')
    if existing is not None:
        return existing
    try:
        result = _invoke(config, request)
    except Exception:
        # Once reserved, an unexpected failure cannot establish non-dispatch.
        result = _result(request, 'unknown', 'execution_error')
    try:
        store.finish(result)
    except (sqlite3.Error, OSError, RuntimeError):
        return _result(request, 'unknown', 'receipt_write_failed')
    return result

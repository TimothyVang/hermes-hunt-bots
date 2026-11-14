"""Wave 2 SQLite Query-Tool Track (`query_store`) for Whole-Campaign APT Benchmarks.

Whole multi-host intrusions (for example APT29 Day 2 at 587k events, DEDALE 8-day
Windows+Linux APT windows, and FullAPT-2025 multi-hundred-thousand-row campaigns)
cannot fit inline inside a 1 MiB prompt. A query-track case keeps `evidence.json`
compact while sealing all sanitized events into an immutable SQLite database
(`public/events.sqlite3`) pinned by SHA-256 inside `evidence.json['query_store']`.

Safety and determinism invariants:
- No raw SQL from models: hunters invoke six parameterized tools (`count_events`,
  `search_events`, `get_events`, `asset_timeline`, `pivot_indicator`, `lookup_ioc`).
- Connections open via `mode=ro`, set `PRAGMA query_only = ON`, and install a
  SQLite authorizer permitting only `SELECT`, `READ`, and pure functions.
- Every tool response is bounded by row count and UTF-8 byte cap, and every call
  is logged in a deterministic `query_audit` summary.
"""
import datetime as dt
import hashlib
import os
from pathlib import Path
import sqlite3
import time
import urllib.parse

import benchmark_paths  # noqa: F401
from benchmark_contracts import (
    BenchmarkError, _digest, _id, _json_value, _public_fields, _text, canonical_bytes,
    decode_json, parse_utc,
)
from benchmark_ioc import validate_ioc_entry

QUERY_SCHEMA_VERSION = 1
DEFAULT_MAX_QUERIES_PER_STAGE = 12
DEFAULT_MAX_ROWS_PER_QUERY = 35
DEFAULT_MAX_BYTES_PER_QUERY = 24576
TOOL_NAMES = (
    'count_events', 'search_events', 'get_events',
    'asset_timeline', 'pivot_indicator', 'lookup_ioc',
)
GROUP_COLUMNS = {
    'asset_id': 'asset_id',
    'source_id': 'source_id',
    'event_type': 'event_type',
}
_ALLOWED_AUTH = frozenset((
    sqlite3.SQLITE_SELECT,
    sqlite3.SQLITE_READ,
    sqlite3.SQLITE_FUNCTION,
))


def _fail(code, field='query_store'):
    raise BenchmarkError(code, field) from None


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _readonly_uri(path):
    resolved = Path(os.path.abspath(os.fspath(path))).resolve()
    posix = resolved.as_posix()
    if not posix.startswith('/'):
        posix = '/' + posix
    return 'file:' + urllib.parse.quote(posix, safe='/:') + '?mode=ro'


def _authorizer(action, arg1, arg2, dbname, source):
    if action in _ALLOWED_AUTH:
        return sqlite3.SQLITE_OK
    # FTS5 internally queries read-only `PRAGMA data_version` during `MATCH`.
    if action == sqlite3.SQLITE_PRAGMA and arg1 == 'data_version' and arg2 is None:
        return sqlite3.SQLITE_OK
    return sqlite3.SQLITE_DENY


def open_readonly_db(path, expected_sha256=None):
    """Open an existing SQLite query store in strict read-only mode after digest check."""
    target = Path(os.path.abspath(os.fspath(path)))
    if not target.is_file():
        _fail('file_not_found', 'query_store.path')
    if expected_sha256 is not None and sha256_file(target) != expected_sha256:
        _fail('evidence_digest_mismatch', 'query_store.sha256')
    conn = sqlite3.connect(_readonly_uri(target), uri=True, timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA query_only = ON')
    conn.set_authorizer(_authorizer)
    return conn


def build_query_store(path, events, ioc_entries=(), *, prefix='e', width=6):
    """Create a NEW deterministic `events.sqlite3` and return its `query_store` manifest."""
    target = Path(os.path.abspath(os.fspath(path)))
    if os.path.lexists(target):
        _fail('already_exists', 'query_store.path')
    if not events:
        _fail('invalid_array', 'query_store.events')
    _id(prefix, 'query_store.event_id_prefix')
    if prefix[-1:].isdigit() or type(width) is not int or not 1 <= width <= 16:
        _fail('invalid_identifier', 'query_store.event_id_prefix')

    fmt = '{}{:0' + str(width) + 'd}'
    previous_stamp = None
    validated_iocs = [validate_ioc_entry(dict(item)) for item in ioc_entries]

    conn = sqlite3.connect(str(target))
    try:
        conn.execute('PRAGMA page_size = 4096')
        conn.execute('PRAGMA journal_mode = DELETE')
        conn.execute('PRAGMA synchronous = FULL')
        conn.execute(
            'CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)'
        )
        conn.execute(
            'CREATE TABLE events ('
            'seq INTEGER PRIMARY KEY, '
            'event_id TEXT UNIQUE NOT NULL, '
            'timestamp_utc TEXT NOT NULL, '
            'epoch_us INTEGER NOT NULL, '
            'source_id TEXT NOT NULL, '
            'asset_id TEXT NOT NULL, '
            'event_type TEXT NOT NULL, '
            'fields_json TEXT NOT NULL, '
            'file_sha256 TEXT NOT NULL, '
            'record_id TEXT NOT NULL)'
        )
        conn.execute('CREATE INDEX idx_events_asset_time ON events(asset_id, epoch_us, seq)')
        conn.execute('CREATE INDEX idx_events_source_time ON events(source_id, epoch_us, seq)')
        conn.execute('CREATE INDEX idx_events_type_time ON events(event_type, epoch_us, seq)')
        conn.execute('CREATE INDEX idx_events_time ON events(epoch_us, seq)')
        conn.execute(
            'CREATE TABLE iocs ('
            'ioc_id TEXT PRIMARY KEY, '
            'indicator_type TEXT NOT NULL, '
            'indicator_value TEXT NOT NULL, '
            'threat_category TEXT NOT NULL, '
            'confidence REAL NOT NULL, '
            'status TEXT NOT NULL, '
            'source_feed TEXT NOT NULL, '
            'first_seen_utc TEXT NOT NULL, '
            'notes TEXT NOT NULL)'
        )
        conn.execute('CREATE INDEX idx_iocs_type_status ON iocs(indicator_type, status)')

        has_fts = True
        try:
            conn.execute(
                'CREATE VIRTUAL TABLE events_fts USING fts5('
                'event_id UNINDEXED, asset_id, source_id, event_type, fields_json)'
            )
        except sqlite3.OperationalError:
            has_fts = False

        batch = []
        fts_batch = []
        for index, event in enumerate(events, 1):
            expected_id = fmt.format(prefix, index)
            if event.get('event_id') != expected_id:
                _fail('unstable_event_order', 'query_store.events.event_id')
            stamp = parse_utc(event['timestamp_utc'], 'query_store.events.timestamp_utc')
            key = (stamp, expected_id)
            if previous_stamp is not None and key < previous_stamp:
                _fail('unstable_event_order', 'query_store.events')
            previous_stamp = key
            fields = event.get('fields')
            if type(fields) is not dict or 'timestamp_original' not in fields:
                _fail('missing_field', 'query_store.events.fields')
            _text(fields['timestamp_original'], 'query_store.events.fields.timestamp_original')
            _public_fields(fields, 'query_store.events.fields')
            if 'detector_attack_ids' in fields:
                _fail('forbidden_public_metadata', 'query_store.events.fields.detector_attack_ids')
            _text(event['event_type'], 'query_store.events.event_type')
            _json_value(event['event_type'], 'query_store.events.event_type', public=True)
            fields_json = canonical_bytes(fields).decode('utf-8')
            epoch_us = int(stamp.timestamp() * 1_000_000)
            locator = event['locator']
            rec_id_str = str(locator['record_id'])
            _text(rec_id_str, 'query_store.events.locator.record_id')
            _json_value(rec_id_str, 'query_store.events.locator.record_id', public=True)
            batch.append((
                index, expected_id, event['timestamp_utc'], epoch_us,
                event['source_id'], event['asset_id'], event['event_type'],
                fields_json, locator['file_sha256'], rec_id_str,
            ))
            if has_fts:
                fts_batch.append((
                    index, expected_id, event['asset_id'], event['source_id'],
                    event['event_type'], fields_json,
                ))
            if len(batch) >= 5000:
                conn.executemany('INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?,?)', batch)
                if has_fts:
                    conn.executemany(
                        'INSERT INTO events_fts(rowid, event_id, asset_id, source_id, event_type, fields_json) '
                        'VALUES (?,?,?,?,?,?)', fts_batch
                    )
                batch.clear()
                fts_batch.clear()
        if batch:
            conn.executemany('INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?,?)', batch)
            if has_fts:
                conn.executemany(
                    'INSERT INTO events_fts(rowid, event_id, asset_id, source_id, event_type, fields_json) '
                    'VALUES (?,?,?,?,?,?)', fts_batch
                )

        for item in sorted(validated_iocs, key=lambda x: x['ioc_id']):
            conn.execute(
                'INSERT INTO iocs VALUES (?,?,?,?,?,?,?,?,?)',
                (item['ioc_id'], item['indicator_type'], item['indicator_value'],
                 item['threat_category'], float(item['confidence']), item['status'],
                 item['source_feed'], item['first_seen_utc'], item['notes'])
            )

        conn.executemany('INSERT INTO meta VALUES (?,?)', [
            ('schema_version', str(QUERY_SCHEMA_VERSION)),
            ('event_count', str(len(events))),
            ('event_id_prefix', prefix),
            ('event_id_width', str(width)),
            ('fts5', '1' if has_fts else '0'),
        ])
        conn.commit()
        conn.execute('VACUUM')
    except BaseException:
        conn.close()
        if target.exists():
            target.unlink()
        raise
    conn.close()

    size = target.stat().st_size
    digest = sha256_file(target)
    return {
        'path': target.name,
        'byte_count': size,
        'sha256': digest,
        'event_count': len(events),
        'event_id_prefix': prefix,
        'event_id_width': width,
        'ioc_count': len(validated_iocs),
    }


def update_query_store_iocs(path, ioc_entries):
    """Replace the `iocs` table in an existing `events.sqlite3` during case sealing and return new `(size, sha256)`."""
    target = Path(os.path.abspath(os.fspath(path)))
    validated = [validate_ioc_entry(dict(item)) for item in ioc_entries]
    conn = sqlite3.connect(str(target))
    try:
        conn.execute('PRAGMA journal_mode = DELETE')
        conn.execute('DELETE FROM iocs')
        for item in sorted(validated, key=lambda x: x['ioc_id']):
            conn.execute(
                'INSERT INTO iocs VALUES (?,?,?,?,?,?,?,?,?)',
                (item['ioc_id'], item['indicator_type'], item['indicator_value'],
                 item['threat_category'], float(item['confidence']), item['status'],
                 item['source_feed'], item['first_seen_utc'], item['notes'])
            )
        conn.commit()
        conn.execute('VACUUM')
    finally:
        conn.close()
    return target.stat().st_size, sha256_file(target)


def verify_query_store(path, spec, sources=None, source_windows=None):
    """Verify file size, SHA-256, schema, row-level public contracts, and contiguous event-IDs."""
    target = Path(os.path.abspath(os.fspath(path)))
    try:
        actual_size = target.stat().st_size
    except OSError:
        _fail('file_unreadable', 'public_bundle.query_store')
    if actual_size != spec['byte_count']:
        _fail('evidence_digest_mismatch', 'public_bundle.query_store')
    if sha256_file(target) != spec['sha256']:
        _fail('evidence_digest_mismatch', 'public_bundle.query_store')

    conn = open_readonly_db(target)
    try:
        count = spec['event_count']
        row = conn.execute('SELECT COUNT(*) AS n, MIN(seq) AS lo, MAX(seq) AS hi FROM events').fetchone()
        if row is None or row['n'] != count or row['lo'] != 1 or row['hi'] != count:
            _fail('corrupt_query_store', 'public_bundle.query_store')
        fmt = '{}{:0' + str(spec['event_id_width']) + 'd}'
        previous = None
        cursor = conn.execute(
            'SELECT seq, event_id, timestamp_utc, source_id, asset_id, event_type, fields_json, '
            'file_sha256, record_id FROM events ORDER BY seq ASC'
        )
        try:
            for idx, ev in enumerate(cursor, 1):
                if ev['seq'] != idx or ev['event_id'] != fmt.format(spec['event_id_prefix'], idx):
                    _fail('corrupt_query_store', 'public_bundle.query_store.events.event_id')
                stamp = parse_utc(ev['timestamp_utc'], 'public_bundle.query_store.events.timestamp_utc')
                order_key = (stamp, ev['event_id'])
                if previous is not None and order_key < previous:
                    _fail('unstable_event_order', 'public_bundle.query_store.events')
                previous = order_key
                if sources is not None:
                    if ev['source_id'] not in sources:
                        _fail('unknown_reference', 'public_bundle.query_store.events.source_id')
                    if ev['asset_id'] not in sources[ev['source_id']]['asset_ids']:
                        _fail('unknown_reference', 'public_bundle.query_store.events.asset_id')
                if source_windows is not None:
                    win = source_windows[ev['source_id']]
                    if not win[0] <= stamp < win[1]:
                        _fail('invalid_window', 'public_bundle.query_store.events.timestamp_utc')
                _digest(ev['file_sha256'], 'public_bundle.query_store.events.file_sha256')
                _text(ev['event_type'], 'public_bundle.query_store.events.event_type')
                _json_value(ev['event_type'], 'public_bundle.query_store.events.event_type', public=True)
                _text(ev['record_id'], 'public_bundle.query_store.events.record_id')
                _json_value(ev['record_id'], 'public_bundle.query_store.events.record_id', public=True)
                decoded_fields = decode_json(ev['fields_json'].encode('utf-8'))
                if type(decoded_fields) is not dict or 'timestamp_original' not in decoded_fields:
                    _fail('missing_field', 'public_bundle.query_store.events.fields')
                _text(decoded_fields['timestamp_original'], 'public_bundle.query_store.events.fields.timestamp_original')
                _public_fields(decoded_fields, 'public_bundle.query_store.events.fields')
                if 'detector_attack_ids' in decoded_fields:
                    _fail('forbidden_public_metadata', 'public_bundle.query_store.events.fields.detector_attack_ids')
        finally:
            cursor.close()

        ioc_rows = conn.execute('SELECT * FROM iocs ORDER BY ioc_id ASC').fetchall()
        if len(ioc_rows) not in (0, spec['ioc_count']):
            _fail('corrupt_query_store', 'public_bundle.query_store.ioc_count')
        seen_ioc_ids = set()
        for ir in ioc_rows:
            entry = {
                'schema_version': 1,
                'ioc_id': ir['ioc_id'],
                'indicator_type': ir['indicator_type'],
                'indicator_value': ir['indicator_value'],
                'threat_category': ir['threat_category'],
                'confidence': ir['confidence'],
                'status': ir['status'],
                'source_feed': ir['source_feed'],
                'first_seen_utc': ir['first_seen_utc'],
                'notes': ir['notes'],
            }
            validate_ioc_entry(entry, 'public_bundle.query_store.iocs')
            if ir['ioc_id'] in seen_ioc_ids:
                _fail('duplicate_identifier', 'public_bundle.query_store.iocs.ioc_id')
            seen_ioc_ids.add(ir['ioc_id'])
    except sqlite3.Error:
        _fail('corrupt_query_store', 'public_bundle.query_store')
    finally:
        conn.close()


def _fts_token_query(raw):
    """Convert arbitrary user search text into safe quoted FTS5 phrase/token terms."""
    tokens = [tok.replace('"', '') for tok in str(raw).split() if tok.replace('"', '').strip()]
    if not tokens:
        return None
    return ' AND '.join('"' + tok[:80] + '"' for tok in tokens[:8])


def _opt_int(args, key, default, lo, hi=None):
    raw = args.get(key)
    if raw is None:
        val = default
    elif isinstance(raw, bool):
        raise ValueError('boolean is not an integer')
    else:
        val = int(raw)
    if val < lo:
        val = lo
    if hi is not None and val > hi:
        val = hi
    return val


class QueryExecutor:
    """Bounded read-only hunting tool executor over `events.sqlite3` + `intel.jsonl`."""

    def __init__(self, db_path, expected_sha256, *, fallback_iocs=(),
                 max_calls=DEFAULT_MAX_QUERIES_PER_STAGE,
                 max_rows=DEFAULT_MAX_ROWS_PER_QUERY,
                 max_bytes=DEFAULT_MAX_BYTES_PER_QUERY):
        self._conn = open_readonly_db(db_path, expected_sha256)
        self._max_calls = max_calls
        self._max_rows = max_rows
        self._max_bytes = max_bytes
        self._fallback_iocs = list(fallback_iocs)
        meta = {row['key']: row['value'] for row in self._conn.execute('SELECT key, value FROM meta')}
        self._has_fts = meta.get('fts5') == '1'
        self.audit = []

    def close(self):
        self._conn.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()

    @property
    def calls_remaining(self):
        return max(0, self._max_calls - len(self.audit))

    def overview(self):
        """Compact initial telemetry summary included in query-track stage prompts."""
        by_asset = [dict(r) for r in self._conn.execute(
            'SELECT asset_id, COUNT(*) AS event_count, MIN(timestamp_utc) AS first_utc, '
            'MAX(timestamp_utc) AS last_utc FROM events GROUP BY asset_id ORDER BY event_count DESC LIMIT 20'
        )]
        by_type = [dict(r) for r in self._conn.execute(
            'SELECT source_id, event_type, COUNT(*) AS event_count '
            'FROM events GROUP BY source_id, event_type ORDER BY event_count DESC LIMIT 25'
        )]
        return {'by_asset': by_asset, 'by_source_event_type': by_type}

    def execute(self, tool, args):
        """Execute one bounded hunting tool call; never raises on bad model arguments."""
        started = time.monotonic_ns()
        if len(self.audit) >= self._max_calls:
            return {'ok': False, 'error': 'query_budget_exhausted', 'calls_remaining': 0}
        if tool not in TOOL_NAMES or type(args) is not dict:
            elapsed = max(0, (time.monotonic_ns() - started) // 1_000_000)
            self.audit.append({
                'tool': str(tool) if isinstance(tool, str) else 'invalid',
                'ok': False, 'error': 'invalid_tool_or_args', 'rows_returned': 0,
                'bytes_returned': 0, 'truncated': False, 'elapsed_ms': elapsed,
            })
            return {'ok': False, 'error': 'invalid_tool_or_args', 'allowed_tools': list(TOOL_NAMES),
                    'calls_remaining': self.calls_remaining}
        try:
            result = getattr(self, '_tool_' + tool)(args)
            if len(result) == 3:
                rows, note, row_cap = result
            else:
                rows, note = result
                row_cap = self._max_rows
        except (BenchmarkError, sqlite3.Error, ValueError, TypeError, KeyError) as exc:
            elapsed = max(0, (time.monotonic_ns() - started) // 1_000_000)
            code = exc.code if isinstance(exc, BenchmarkError) else 'invalid_query_parameters'
            self.audit.append({'tool': tool, 'ok': False, 'error': code, 'rows_returned': 0,
                               'bytes_returned': 0, 'truncated': False, 'elapsed_ms': elapsed})
            return {'ok': False, 'error': code, 'calls_remaining': self.calls_remaining}

        effective_cap = min(max(1, int(row_cap)), self._max_rows)
        capped, truncated = [], False
        used_bytes = 0
        for item in rows[:effective_cap]:
            encoded = canonical_bytes(item)
            if used_bytes + len(encoded) > self._max_bytes and capped:
                truncated = True
                break
            capped.append(item)
            used_bytes += len(encoded)
        if len(rows) > len(capped):
            truncated = True
        elapsed = max(0, (time.monotonic_ns() - started) // 1_000_000)
        self.audit.append({
            'tool': tool, 'ok': True, 'rows_returned': len(capped),
            'bytes_returned': used_bytes, 'truncated': truncated, 'elapsed_ms': elapsed,
        })
        return {
            'ok': True, 'tool': tool, 'rows': capped, 'row_count': len(capped),
            'truncated': truncated, 'note': note, 'calls_remaining': self.calls_remaining,
        }

    def summary(self):
        return {
            'queries_executed': len(self.audit),
            'max_queries': self._max_calls,
            'rows_returned_total': sum(item['rows_returned'] for item in self.audit),
            'bytes_returned_total': sum(item['bytes_returned'] for item in self.audit),
            'ioc_lookups': sum(1 for item in self.audit if item['tool'] == 'lookup_ioc'),
            'calls': list(self.audit),
        }

    def _where_filters(self, args):
        clauses, params = [], []
        for col in ('asset_id', 'source_id', 'event_type'):
            val = args.get(col)
            if isinstance(val, str) and val.strip():
                clauses.append(f'e.{col} = ?')
                params.append(val.strip())
        if isinstance(args.get('start_utc'), str) and args['start_utc'].strip():
            st = parse_utc(args['start_utc'].strip(), 'start_utc')
            clauses.append('e.epoch_us >= ?')
            params.append(int(st.timestamp() * 1_000_000))
        if isinstance(args.get('end_utc'), str) and args['end_utc'].strip():
            et = parse_utc(args['end_utc'].strip(), 'end_utc')
            clauses.append('e.epoch_us < ?')
            params.append(int(et.timestamp() * 1_000_000))
        text_q = args.get('text_query')
        if isinstance(text_q, str) and text_q.strip():
            fts_q = _fts_token_query(text_q)
            if self._has_fts and fts_q:
                clauses.append('e.seq IN (SELECT rowid FROM events_fts WHERE events_fts MATCH ?)')
                params.append(fts_q)
            else:
                clauses.append('LOWER(e.fields_json) LIKE ?')
                params.append('%' + text_q.strip().lower()[:80] + '%')
        return (' WHERE ' + ' AND '.join(clauses)) if clauses else '', params

    @staticmethod
    def _format_event(row):
        return {
            'event_id': row['event_id'],
            'timestamp_utc': row['timestamp_utc'],
            'asset_id': row['asset_id'],
            'source_id': row['source_id'],
            'event_type': row['event_type'],
            'fields': decode_json(row['fields_json']),
        }

    def _tool_count_events(self, args):
        group_by = str(args.get('group_by') or 'event_type')
        if group_by not in GROUP_COLUMNS:
            _fail('invalid_choice', 'group_by')
        col = GROUP_COLUMNS[group_by]
        where, params = self._where_filters(args)
        sql = (f'SELECT e.{col} AS key, COUNT(*) AS count, MIN(e.timestamp_utc) AS first_utc, '
               f'MAX(e.timestamp_utc) AS last_utc FROM events e{where} '
               f'GROUP BY e.{col} ORDER BY count DESC, key ASC LIMIT ?')
        rows = [dict(r) for r in self._conn.execute(sql, params + [self._max_rows + 1])]
        return rows, f'grouped by {col}', self._max_rows

    def _tool_search_events(self, args):
        limit = _opt_int(args, 'limit', 20, 1, self._max_rows)
        offset = _opt_int(args, 'offset', 0, 0)
        where, params = self._where_filters(args)
        sql = (f'SELECT e.* FROM events e{where} ORDER BY e.epoch_us ASC, e.seq ASC LIMIT ? OFFSET ?')
        rows = [self._format_event(r) for r in self._conn.execute(sql, params + [limit + 1, offset])]
        return rows, f'offset={offset}', limit

    def _tool_get_events(self, args):
        ids = args.get('event_ids')
        if type(ids) is not list or not ids:
            _fail('invalid_array', 'event_ids')
        clean = [str(x).strip() for x in ids[:self._max_rows] if isinstance(x, str) and x.strip()]
        if not clean:
            return [], 'empty', self._max_rows
        placeholders = ','.join('?' for _ in clean)
        sql = f'SELECT * FROM events WHERE event_id IN ({placeholders}) ORDER BY epoch_us ASC, seq ASC'
        rows = [self._format_event(r) for r in self._conn.execute(sql, clean)]
        return rows, f'requested={len(clean)}', self._max_rows

    def _tool_asset_timeline(self, args):
        asset_id = str(args.get('asset_id') or '').strip()
        around = str(args.get('around_utc') or '').strip()
        if not asset_id or not around:
            _fail('missing_field', 'asset_timeline')
        center = parse_utc(around, 'around_utc')
        span = _opt_int(args, 'window_seconds', 300, 1, 86400)
        lo = int((center - dt.timedelta(seconds=span)).timestamp() * 1_000_000)
        hi = int((center + dt.timedelta(seconds=span)).timestamp() * 1_000_000)
        limit = _opt_int(args, 'limit', 25, 1, self._max_rows)
        sql = ('SELECT * FROM events WHERE asset_id = ? AND epoch_us >= ? AND epoch_us <= ? '
               'ORDER BY epoch_us ASC, seq ASC LIMIT ?')
        rows = [self._format_event(r) for r in self._conn.execute(sql, [asset_id, lo, hi, limit + 1])]
        return rows, f'+/-{span}s around {around}', limit

    def _tool_pivot_indicator(self, args):
        value = str(args.get('value') or '').strip()
        if len(value) < 3:
            _fail('invalid_text', 'value')
        exclude_asset = str(args.get('exclude_asset_id') or '').strip()
        limit = _opt_int(args, 'limit', 25, 1, self._max_rows)
        fts_q = _fts_token_query(value)
        params = []
        if self._has_fts and fts_q:
            clause = 'e.seq IN (SELECT rowid FROM events_fts WHERE events_fts MATCH ?)'
            params.append(fts_q)
        else:
            clause = 'LOWER(e.fields_json) LIKE ?'
            params.append('%' + value.lower()[:120] + '%')
        if exclude_asset:
            clause += ' AND e.asset_id != ?'
            params.append(exclude_asset)
        sql = f'SELECT e.* FROM events e WHERE {clause} ORDER BY e.epoch_us ASC, e.seq ASC LIMIT ?'
        rows = [self._format_event(r) for r in self._conn.execute(sql, params + [limit + 1])]
        return rows, f'pivot={value[:64]}', limit

    def _tool_lookup_ioc(self, args):
        needle = str(args.get('query') or '').strip().lower()
        itype = str(args.get('indicator_type') or '').strip()
        status = str(args.get('status') or '').strip()
        limit = _opt_int(args, 'limit', 25, 1, self._max_rows)

        db_count = self._conn.execute('SELECT COUNT(*) AS n FROM iocs').fetchone()['n']
        if db_count > 0:
            clauses, params = [], []
            if itype:
                clauses.append('indicator_type = ?')
            if itype:
                params.append(itype)
            if status:
                clauses.append('status = ?')
                params.append(status)
            if needle:
                clauses.append('(LOWER(indicator_value) LIKE ? OR LOWER(threat_category) LIKE ? OR LOWER(notes) LIKE ?)')
                like = '%' + needle[:120] + '%'
                params.extend([like, like, like])
            where = (' WHERE ' + ' AND '.join(clauses)) if clauses else ''
            sql = f'SELECT * FROM iocs{where} ORDER BY confidence DESC, ioc_id ASC LIMIT ?'
            rows = [dict(r) for r in self._conn.execute(sql, params + [limit + 1])]
            return rows, 'source=query_store.iocs', limit

        from benchmark_ioc import lookup_indicators
        rows = lookup_indicators(
            self._fallback_iocs, query=needle,
            indicator_type=itype or None, status=status or None, limit=limit + 1
        )
        return rows, 'source=public.intel.jsonl', limit

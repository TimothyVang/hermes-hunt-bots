#!/usr/bin/env python3
"""Serve one work-connected case from the lab PC: the lab service's tool routes over a read-only work Elastic.

The connected mode of ADR 0005 (planning notes): the lab service, not the bots, holds a read-only API key to
the operator's work Elastic and answers the bots' existing tools on 127.0.0.1. The VM is not involved. Standard
library only.

CLI (run from framework/, in the operator's own terminal; never from a bot or a Hermes profile):
  python -m hunt_lab.connected check --config CONNECT.json --case CASE.json
  python -m hunt_lab.connected serve --config CONNECT.json --case CASE.json \
      --state-dir <hermes home>/profiles/framework-network-analyst

CONNECT.json names the cluster and is never served: {"url": "https://HOST:PORT", "index": "logs-*",
"ca_file": optional PEM bundle, "api_key_env": optional, default HUNT_ELASTIC_API_KEY}. CASE.json is what
/case serves: case_id, question, time_range_utc, "data_origin": "work-connected", "network_capture": "none"
and optional "hosts" (exact host.name values); it names no cluster or index.

The key is read once from the environment variable and removed from this process's environment. It is
never written, logged or returned, and errors carry only an HTTP status and Elasticsearch error type. TLS
and redirects are handled as in hunt_lab.import_elastic (verified HTTPS, --ca-file alone when given, no
redirects). Before serving, the service refuses a key that holds any write, delete or manage privilege it
asks _has_privileges about (WRITE_INDEX_PRIVILEGES on the pattern and on every index, alias and data stream
it resolves to; WRITE_CLUSTER_PRIVILEGES), a key whose text sits in a Hermes profile's .env or config.yaml, a
cluster older than 7.12, and a case window ending less than 15 minutes ago (ingest could still change it).

Every query is scoped to the case window on @timestamp and, when listed, its hosts; the index pattern and
the key's role bound the rest. All reads run in one point in time (a frozen snapshot), sorted on @timestamp
and _shard_doc. A returned record's event.id is its citation, evt- and 16 digits from the SHA-256 of its
_id; event.id and bare evt- terms in a query resolve back to those documents, and the citations are kept in
<state-dir>/hunt-lab-connected/<case_id>/citations.jsonl (document IDs only) across restarts. Intel, Arkime,
packets and the console page are off; /health waits only for events. While serving,
<state-dir>/hunt-lab-connected/state.json names the port and an instance token that every response carries in
X-Hunt-Lab-Instance.
"""

import argparse
import base64
import copy
import hashlib
import http.client
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import sys
import threading
import time
from urllib import parse

from hunt_lab.endpoints import CONNECTED_STATE, INSTANCE_HEADER, STATE_VERSION
from hunt_lab.import_elastic import (API_KEY_ENV, ENV_NAME, ERROR_TYPE, check_version, cluster_base, https_transport,
                                     read_api_key)


def _guest_lab_server():
    path = Path(__file__).resolve().parent / 'guest' / 'lab_server.py'
    spec = importlib.util.spec_from_file_location('hunt_lab_connected_lab_server', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


lab_server = _guest_lab_server()

DATA_ORIGIN = 'work-connected'
PROFILE = 'framework-network-analyst'
KEEP_ALIVE = '30m'
SETTLE_SECONDS = 15 * 60
MAX_HOSTS = 50
MAX_PROFILE_FILE = 4 * 1024 * 1024
# A pattern on another cluster (remote:index) is outside what _has_privileges checks here.
INDEX_PATTERN = re.compile(r'[A-Za-z0-9*][A-Za-z0-9._*,+-]{0,254}\Z')
CONFIG_KEYS = frozenset({'url', 'index', 'ca_file', 'api_key_env'})
# Names valid on every Elasticsearch from 7.12 (an unknown name fails the whole check); the key must hold none.
WRITE_INDEX_PRIVILEGES = ('all', 'manage', 'write', 'index', 'create', 'create_doc', 'create_index', 'delete',
                          'delete_index', 'maintenance', 'manage_ilm', 'manage_follow_index', 'manage_leader_index',
                          'auto_configure')
WRITE_CLUSTER_PRIVILEGES = ('all', 'manage', 'manage_security', 'manage_api_key', 'manage_own_api_key',
                            'manage_index_templates', 'manage_ingest_pipelines', 'manage_ilm', 'manage_pipeline',
                            'manage_watcher', 'manage_ml', 'manage_transform', 'manage_rollup', 'manage_ccr',
                            'manage_slm', 'create_snapshot', 'manage_enrich', 'manage_token', 'manage_saml',
                            'manage_oidc', 'grant_api_key', 'delegate_pki', 'manage_autoscaling',
                            'manage_logstash_pipelines', 'cancel_task')
CITED = r'(?:"evt-(?:\d+)"|\bevt-(?:\d+)\b)'
# One pass, so _id values already put in by a rewrite are never scanned again.
CITATION = re.compile(r'\bevent\.id\s*:\s*\((?P<group>[^()]*)\)'
                      r'|(?:\bevent\.id\s*:\s*)?(?:"(?P<quoted>evt-\d+)"|\b(?P<bare>evt-\d+)\b)')
CITATION_GROUP_BODY = re.compile(r'\s*' + CITED + r'(?:\s+OR\s+' + CITED + r')*\s*\Z')
CITATION_FORM = re.compile(r'evt-\d{16}\Z')
# An escaped character is hidden like a phrase, so \" is never taken for a phrase's quote.
QUOTED = re.compile(r'\\.|"(?:\\.|[^"\\])*"')
HIDDEN = re.compile('\x00(\\d+)\x00')


class ConnectError(ValueError):
    """A refused start; the message never holds the API key or a response body."""


def _json_file(path, what):
    try:
        value = json.loads(Path(path).read_text(encoding='utf-8'))
    except (OSError, ValueError):
        raise ConnectError(f'{what} is not a readable JSON file: {path}') from None
    if not isinstance(value, dict):
        raise ConnectError(f'{what} must hold a JSON object')
    return value


def load_config(path):
    config = _json_file(path, 'the connect config')
    if set(config) - CONFIG_KEYS:
        raise ConnectError('the connect config may hold only ' + ', '.join(sorted(CONFIG_KEYS)))
    try:
        cluster_base(config.get('url'))
    except ValueError:
        raise ConnectError('the connect config url must be https://HOST:PORT without credentials, a query or a fragment') from None
    if not isinstance(config.get('index'), str) or not INDEX_PATTERN.match(config['index']):
        raise ConnectError('the connect config index must be an index name or pattern such as logs-*, on this cluster')
    if config.get('ca_file') is not None and not (isinstance(config['ca_file'], str) and Path(config['ca_file']).is_file()):
        raise ConnectError('the connect config ca_file is not a file')
    config.setdefault('api_key_env', API_KEY_ENV)
    if not isinstance(config['api_key_env'], str) or not ENV_NAME.match(config['api_key_env']):
        raise ConnectError('the connect config api_key_env must name an environment variable')
    return config


def load_case(path, now=None):
    case = _json_file(path, 'the case file')
    if not isinstance(case.get('case_id'), str) or not lab_server.CASE_ID.fullmatch(case['case_id']):
        raise ConnectError('case_id must match [a-z0-9-]{3,64}')
    if not isinstance(case.get('question'), str) or not case['question'].strip():
        raise ConnectError('the case needs a question')
    if case.get('data_origin') != DATA_ORIGIN:
        raise ConnectError(f'a connected case must say "data_origin": "{DATA_ORIGIN}"')
    if case.get('network_capture') != lab_server.NO_CAPTURE:
        raise ConnectError('a connected case has no packet capture: it must say "network_capture": "none"')
    try:
        bounds = [lab_server.datetime.fromisoformat(value.replace('Z', '+00:00')) for value in lab_server.window(case)]
    except (KeyError, TypeError, ValueError, AttributeError):
        raise ConnectError('time_range_utc needs ISO start_inclusive and end_exclusive') from None
    if any(bound.tzinfo is None for bound in bounds):
        raise ConnectError('time_range_utc times need a UTC offset, such as Z')
    start, end = (bound.timestamp() for bound in bounds)
    if start >= end:
        raise ConnectError('time_range_utc must be a nonempty window')
    if end > (time.time() if now is None else now) - SETTLE_SECONDS:
        raise ConnectError('window_not_closed: the case window must end at least 15 minutes ago')
    if 'hosts' in case:
        hosts = case['hosts']
        if (not isinstance(hosts, list) or not 1 <= len(hosts) <= MAX_HOSTS
                or not all(isinstance(host, str) and host.strip() == host and 0 < len(host) <= 100
                           and host.isprintable() for host in hosts) or len(set(hosts)) != len(hosts)):
            raise ConnectError(f'hosts must list 1 to {MAX_HOSTS} distinct exact host.name values')
    return case


def profile_home(state_dir):
    """The analyst's profile home, <hermes home>/profiles/framework-network-analyst, outside any Git checkout."""
    home = Path(state_dir).resolve()
    if home.name != PROFILE or home.parent.name != 'profiles':
        raise ConnectError(f'--state-dir must be <hermes home>/profiles/{PROFILE}')
    if any((ancestor / '.git').exists() for ancestor in (home, *home.parents)):
        raise ConnectError('--state-dir must not be inside a Git checkout')
    return home


def key_in_bot_profiles(home, key):
    """Whether the key's text sits in the Hermes home's or any profile's .env or config.yaml, where a bot loads it."""
    hermes = home.parent.parent
    candidates = [hermes / '.env', hermes / 'config.yaml',
                  *sorted(hermes.glob('profiles/*/.env')), *sorted(hermes.glob('profiles/*/config.yaml'))]
    needle = key.encode('ascii')
    for path in candidates:
        try:
            with open(path, 'rb') as handle:
                if needle in handle.read(MAX_PROFILE_FILE):
                    return True
        except OSError:
            continue
    return False


def citation(doc_id):
    return f"evt-{int.from_bytes(hashlib.sha256(doc_id.encode('utf-8')).digest()[:8], 'big') % 10**16:016d}"


def refuse_regex(text):
    """Lucene /regex/ terms can be costly on a shared production cluster; quoted and escaped slashes are text."""
    quoted = escaped = False
    for character in text:
        if escaped:
            escaped = False
        elif character == '\\':
            escaped = True
        elif character == '"':
            quoted = not quoted
        elif character == '/' and not quoted:
            raise lab_server.BackendQueryError('regex_not_supported')


def _terms_fields(aggs):
    for spec in aggs.values():
        if 'terms' in spec:
            yield spec['terms']['field']
        yield from _terms_fields(spec.get('aggs', {}))


def _snapshot_lost(status, value):
    """The point in time expired or was closed (404), or a node lost its part of it (search_context_missing)."""
    if status == 404:
        return True
    failures = value.get('_shards', {}).get('failures', []) if status == 200 and isinstance(value, dict) else []
    return any(isinstance(failure, dict) and isinstance(failure.get('reason'), dict)
               and failure['reason'].get('type') == 'search_context_missing_exception' for failure in failures)


class WorkElastic:
    """The lab service's event source for a work-connected case (see lab_server.LabElastic for the contract)."""

    def __init__(self, config, case, key, *, transport=None, citations=None):
        self.base, self.cluster = cluster_base(config['url'])
        self.index = config['index']
        self.authorization = 'ApiKey ' + key
        self.send = transport or https_transport(config.get('ca_file'), timeout=lab_server.ES_TIMEOUT)
        start, end = lab_server.window(case)
        self.scope = [{'range': {'@timestamp': {'gte': start, 'lt': end}}}]
        if case.get('hosts'):
            self.scope.append({'terms': {'host.name': list(case['hosts'])}})
        self.lock = threading.Lock()
        self.pit = None
        # Random per process, so a page token from an earlier run of the service never matches this snapshot.
        self.generation = secrets.randbelow(2**31)
        self.local = threading.local()
        self.version = None
        self.fields = frozenset()
        self.aggregatable = frozenset()
        self.citations = {}
        self.citation_file = citations
        if citations is not None and citations.is_file():
            for line in citations.read_text(encoding='utf-8').splitlines():
                record = json.loads(line)
                self.citations.setdefault(record['evt'], []).append(record['_id'])

    def call(self, method, path, body=None):
        """(status, JSON value or None); a failed connection is backend_not_ready, never its text."""
        headers = {'Accept': 'application/json', 'Authorization': self.authorization}
        data = None
        if body is not None:
            data = json.dumps(body, separators=(',', ':')).encode('utf-8')
            headers['Content-Type'] = 'application/json'
        try:
            status, payload = self.send(method, self.base + path, headers, data)
        except (OSError, http.client.HTTPException):
            raise RuntimeError('backend_not_ready') from None
        if len(payload) > lab_server.MAX_BACKEND_BYTES:
            raise RuntimeError('Oversized Elasticsearch response')
        try:
            return status, json.loads(payload)
        except ValueError:
            return status, None

    def require(self, method, path, body, action):
        try:
            status, value = self.call(method, path, body)
        except RuntimeError:
            raise ConnectError(f'{action}: cannot reach Elasticsearch at {self.cluster}') from None
        if not 200 <= status < 300 or not isinstance(value, dict):
            kind = value.get('error', {}).get('type') if isinstance(value, dict) and isinstance(value.get('error'), dict) else None
            detail = f' ({kind})' if isinstance(kind, str) and ERROR_TYPE.match(kind) else ''
            raise ConnectError(f'{action}: Elasticsearch returned HTTP {status}{detail}')
        return value

    def open(self):
        """Verify the cluster and the key, learn the mapping, and open the case's point in time."""
        info = self.require('GET', '/', None, 'read cluster version')
        try:
            self.version = check_version(info)
        except ValueError as failure:
            raise ConnectError(str(failure)) from None
        resolved = self.require('GET', '/_resolve/index/' + self._index_path(), None, 'resolve the index pattern')
        names = [self.index, *sorted({item['name'] for kind in ('indices', 'aliases', 'data_streams')
                                      for item in resolved.get(kind, []) if isinstance(item, dict)
                                      and isinstance(item.get('name'), str)})]
        granted = self.require('POST', '/_security/user/_has_privileges', {
            'cluster': list(WRITE_CLUSTER_PRIVILEGES),
            'index': [{'names': names, 'privileges': ['read', *WRITE_INDEX_PRIVILEGES]}]}, 'check key privileges')
        indices, cluster = granted.get('index', {}), granted.get('cluster', {})
        # Fail closed: every asked name must come back, and false.
        if (not isinstance(indices.get(self.index), dict) or indices[self.index].get('read') is not True
                or any(not isinstance(indices.get(name), dict) or indices[name].get(privilege) is not False
                       for name in names for privilege in WRITE_INDEX_PRIVILEGES)
                or any(cluster.get(privilege) is not False for privilege in WRITE_CLUSTER_PRIVILEGES)):
            raise ConnectError(f'key_not_read_only: the key must read {self.index} and hold no write, delete or manage privilege')
        caps = self.require('GET', '/' + self._index_path() + '/_field_caps?fields=*&include_unmapped=false', None,
                            'read field capabilities')
        fields = caps.get('fields', {})
        self.fields = frozenset(fields)
        self.aggregatable = frozenset(name for name, types in fields.items()
                                      if any(isinstance(kind, dict) and kind.get('aggregatable') for kind in types.values()))
        self.pit = self._open_pit()

    def _index_path(self):
        return parse.quote(self.index, safe='*,+')

    def _open_pit(self):
        pit = self.require('POST', '/' + self._index_path() + '/_pit?keep_alive=' + KEEP_ALIVE, None,
                           'open point in time').get('id')
        if not isinstance(pit, str) or not pit:
            raise ConnectError('open point in time: Elasticsearch returned no point-in-time id')
        return pit

    def close(self):
        if self.pit:
            try:
                self.call('DELETE', '/_pit', {'id': self.pit})
            except RuntimeError:
                pass
            self.pit = None

    def _reopen(self, generation):
        with self.lock:
            if self.generation == generation:
                try:
                    self.pit = self._open_pit()
                except ConnectError:
                    raise RuntimeError('backend_not_ready') from None
                self.generation += 1

    def search(self, index, body, ignore_unavailable=False):
        if index == lab_server.INTEL_INDEX:
            raise lab_server.BackendQueryError('no_intel_source')
        if index != lab_server.EVENT_INDEX:
            raise lab_server.BackendQueryError('no_network_capture')
        if any(field not in self.aggregatable for field in _terms_fields(body.get('aggs', {}))):
            raise lab_server.BackendQueryError('field_unavailable')
        for attempt in (1, 2):
            with self.lock:
                pit, generation = self.pit, self.generation
            status, value = self.call('POST', '/_search', dict(body, pit={'id': pit, 'keep_alive': KEEP_ALIVE}))
            # A new point in time is a new snapshot, so open pages end.
            if not _snapshot_lost(status, value) or attempt == 2:
                break
            self._reopen(generation)
            if 'search_after' in body:
                raise lab_server.BackendQueryError('cursor_expired')
        if status == 400:
            raise lab_server.BackendQueryError('invalid_query')
        if not 200 <= status < 300 or not isinstance(value, dict):
            raise RuntimeError('backend_not_ready')
        if value.get('timed_out') or value.get('_shards', {}).get('failed', 0):
            raise RuntimeError('Partial Elasticsearch response')
        with self.lock:
            if self.generation == generation and isinstance(value.get('pit_id'), str):
                self.pit = value['pit_id']
        self.local.generation = generation
        return value

    def event_query(self, case, q):
        filters = copy.deepcopy(self.scope)
        clause = lab_server.lucene(q)
        if clause:
            options = clause['query_string']
            # The cluster's own event.id is not what the bots see as event.id; a plain term must not match it.
            options['fields'] = [field for field in options['fields'] if field != 'event.id']
            options['query'] = text = self.resolve_citations(options['query'])
            refuse_regex(text)
            filters.append(clause)
        return {'bool': {'filter': filters}}

    def resolve_citations(self, text):
        """event.id:evt-N, evt-N and event.id:("evt-N" OR ...) become _id terms; quoted phrases stay as written."""
        def documents(citations):
            found = []
            for cited in citations:
                with self.lock:
                    ids = list(self.citations.get(cited, ())) if CITATION_FORM.match(cited) else []
                if not ids:
                    raise lab_server.BackendQueryError('unknown_citation')
                found += ids
            quoted = (doc_id.replace('\\', '\\\\').replace('"', '\\"') for doc_id in found)
            return '(' + ' OR '.join(f'_id:"{doc_id}"' for doc_id in quoted) + ')'

        def rewrite(match):
            if match.group('group') is None:
                return documents([match.group('quoted') or match.group('bare')])
            if not CITATION_GROUP_BODY.match(match.group('group')):
                raise lab_server.BackendQueryError('invalid_query')
            return documents(re.findall(r'evt-\d+', match.group('group')))

        phrases = []

        def hide(match):
            if re.fullmatch(r'"evt-\d+"', match.group(0)):
                return match.group(0)
            phrases.append(match.group(0))
            return f'\x00{len(phrases) - 1}\x00'

        text = CITATION.sub(rewrite, QUOTED.sub(hide, text))
        if re.search(r'\bevent\.id\b', text):
            raise lab_server.BackendQueryError('invalid_query')
        return HIDDEN.sub(lambda match: phrases[int(match.group(1))], text)

    def sort(self, order):
        return [{'@timestamp': {'order': order, 'numeric_type': 'date_nanos'}}, {'_shard_doc': order}]

    def document(self, hit):
        source = dict(hit['_source']) if isinstance(hit.get('_source'), dict) else {}
        source.pop('event.id', None)
        event = dict(source['event']) if isinstance(source.get('event'), dict) else {}
        event['id'] = self.cite(hit['_id'])
        source['event'] = event
        return source

    def cite(self, doc_id):
        cited = citation(doc_id)
        with self.lock:
            ids = self.citations.setdefault(cited, [])
            if doc_id not in ids:
                ids.append(doc_id)
                if self.citation_file is not None:
                    with open(self.citation_file, 'a', encoding='utf-8') as handle:
                        handle.write(json.dumps({'evt': cited, '_id': doc_id}, separators=(',', ':')) + '\n')
        return cited

    def encode_after(self, sort):
        """The page's last sort values plus the generation of the snapshot this thread's search read."""
        token = json.dumps([*sort, getattr(self.local, 'generation', self.generation)], separators=(',', ':')).encode()
        return base64.urlsafe_b64encode(token).decode().rstrip('=')

    def decode_after(self, token):
        token = lab_server.text(token, 400)
        if not re.fullmatch(r'[A-Za-z0-9_-]{1,400}', token):
            raise ValueError('Invalid after token')
        value = json.loads(base64.urlsafe_b64decode(token + '=' * (-len(token) % 4)))
        if not isinstance(value, list) or len(value) != 3 or any(type(item) is not int for item in value):
            raise ValueError('Invalid after token')
        if value[2] != self.generation:
            raise lab_server.BackendQueryError('cursor_expired')
        return value[:2]

    def in_scope_count(self):
        body = {'query': {'bool': {'filter': copy.deepcopy(self.scope)}}, 'size': 0,
                'track_total_hits': True, 'timeout': '10s'}
        return self.search(lab_server.EVENT_INDEX, body)['hits']['total']['value']


def health(server):
    """Ready once the case window holds events; there is no Arkime, Kibana or intel to wait for."""
    events = lab_server.query(server, 'events', {'limit': ['1']})
    ready = events['total'] > 0
    return ready, {'ready': ready, 'case_id': server.case['case_id'], 'event_count': events['total'],
                   'network_session_count': 0, 'intel_count': 0, 'network_scope': server.network_scope,
                   'arkime_viewer_ready': False, 'kibana_ready': False, 'read_only': True,
                   'instance_id': server.instance_id, 'network_capture': lab_server.NO_CAPTURE,
                   'backend': 'work-elastic'}


class ConnectedHandler(lab_server.Handler):
    """The lab service's routes, each answer naming this service's instance; its own /health and no console page."""

    def end_headers(self):
        self.send_header(INSTANCE_HEADER, self.server.instance_id)
        super().end_headers()

    def do_GET(self):
        target = parse.urlsplit(self.path)
        if target.path in ('/', '/view'):
            self.send(404, {'error': 'not_found'})
        elif target.path == '/health':
            if target.query:
                self.send(400, {'error': 'invalid_query'})
                return
            try:
                ready, value = health(self.server)
            except (OSError, KeyError, RuntimeError, ValueError, lab_server.BackendQueryError):
                self.send(503, {'error': 'backend_not_ready', 'partial_results': False})
            else:
                self.send(200 if ready else 503, value)
        else:
            super().do_GET()


def _open(config_path, case_path, environ, transport, home=None):
    """The validated case and an opened WorkElastic; the key leaves the environment before anything else runs."""
    config = load_config(config_path)
    case = load_case(case_path)
    try:
        key = read_api_key(environ, config['api_key_env'])
    except ValueError as failure:
        raise ConnectError(str(failure)) from None
    environ.pop(config['api_key_env'], None)
    citations = None
    if home is not None:
        if key_in_bot_profiles(home, key):
            raise ConnectError('key_in_bot_profile: the API key is in a Hermes .env or config.yaml, where a bot would load it')
        folder = home / CONNECTED_STATE / case['case_id']
        folder.mkdir(mode=0o700, parents=True, exist_ok=True)
        citations = folder / 'citations.jsonl'
    source = WorkElastic(config, case, key, transport=transport, citations=citations)
    source.open()
    return config, case, source


def check(config_path, case_path, *, environ=None, transport=None):
    """Read-only start-up proof without serving: cluster, key privileges, field coverage, in-scope count."""
    _config, case, source = _open(config_path, case_path, os.environ if environ is None else environ, transport)
    try:
        count = source.in_scope_count()
    except (RuntimeError, lab_server.BackendQueryError) as failure:
        raise ConnectError(f'count the events in scope: {failure.args[0]}') from None
    finally:
        source.close()
    missing = sorted(field for field in lab_server.AGG_FIELDS if field not in source.aggregatable)
    return {'case_id': case['case_id'], 'cluster': source.cluster, 'version': source.version, 'read_only': True,
            'in_scope_events': count, 'aggregatable_fields': len(lab_server.AGG_FIELDS) - len(missing),
            'unavailable_fields': missing,
            'unsearched_query_fields': sorted(field for field in lab_server.QUERY_FIELDS
                                              if field != 'event.id' and field not in source.fields)}


def _while_unread(change):
    """Replace or remove state.json; on Windows a bot tool reading it (hunt_lab.endpoints) blocks both for a moment."""
    for _ in range(40):
        try:
            return change()
        except PermissionError:
            time.sleep(0.05)
    return change()


def start(config_path, case_path, state_dir, *, environ=None, transport=None):
    """Open the source and bind the service on a free loopback port; returns (server, source, state path)."""
    folder = profile_home(state_dir) / CONNECTED_STATE
    folder.mkdir(mode=0o700, parents=True, exist_ok=True)
    state = folder / 'state.json'
    try:
        # Reserved before anything else, so two services started together cannot both claim this state dir.
        os.close(os.open(state, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600))
    except FileExistsError:
        raise ConnectError(f'a connected service already serves from this state dir; stop it, or delete {state} if it is stale') from None
    server = source = None
    try:
        config, case, source = _open(config_path, case_path, os.environ if environ is None else environ, transport,
                                     folder.parent)
        server = lab_server.make_server('127.0.0.1', 0, case, source, instance=secrets.token_hex(16))
        server.RequestHandlerClass = ConnectedHandler
        temporary = folder / f'state.{server.instance_id}.tmp'
        temporary.write_text(json.dumps({'version': STATE_VERSION, 'pid': os.getpid(), 'port': server.server_address[1],
                                         'case_id': case['case_id'], 'instance': server.instance_id,
                                         'api_key_env': config['api_key_env']}, sort_keys=True), encoding='utf-8')
        _while_unread(lambda: os.replace(temporary, state))
    except BaseException:
        if server is not None:
            server.server_close()
        if source is not None:
            source.close()
        _while_unread(lambda: state.unlink(missing_ok=True))
        raise
    return server, source, state


def stop(server, source, state):
    """Close the service and its point in time; remove state.json only while it still names this instance."""
    server.server_close()
    source.close()
    try:
        if json.loads(state.read_text(encoding='utf-8')).get('instance') == server.instance_id:
            _while_unread(state.unlink)
    except (FileNotFoundError, ValueError):
        pass


def main(argv=None, *, transport=None, environ=None):
    class JsonParser(argparse.ArgumentParser):
        def error(self, message):
            raise ValueError(message)

    parser = JsonParser(prog='python -m hunt_lab.connected', description=__doc__,
                        formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest='command', required=True)
    for name, text in (('check', 'verify the cluster, key and case without serving'),
                       ('serve', 'serve the case on 127.0.0.1 until interrupted')):
        command = commands.add_parser(name, help=text)
        command.add_argument('--config', required=True, help='CONNECT.json: url, index, ca_file, api_key_env')
        command.add_argument('--case', required=True, help='CASE.json with "data_origin": "work-connected"')
        if name == 'serve':
            command.add_argument('--state-dir', required=True, help=f'<hermes home>/profiles/{PROFILE}')
    try:
        args = parser.parse_args(argv)
        if args.command == 'check':
            print(json.dumps(check(args.config, args.case, environ=environ, transport=transport), sort_keys=True))
            return 0
        server, source, state = start(args.config, args.case, args.state_dir, environ=environ, transport=transport)
    except (OSError, ValueError) as failure:
        print(json.dumps({'error': str(failure)}, sort_keys=True))
        return 2
    print(json.dumps({'case_id': server.case['case_id'], 'lab_url': f'http://127.0.0.1:{server.server_address[1]}',
                      'state': str(state)}, sort_keys=True), flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        stop(server, source, state)
    return 0


if __name__ == '__main__':
    sys.exit(main())

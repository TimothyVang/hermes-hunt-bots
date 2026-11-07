#!/usr/bin/env python3
"""Read-only synthetic hunting API. Fixed indices, bounded results, no raw packet/auth APIs.

Every query is scoped server-side to the loaded case: events by event.dataset,
intel by case_id, network sessions by the Arkime case tag and the case window.
Arkime is reached only through two fixed read routes on guest loopback.
"""
import argparse
import base64
from collections import deque
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import html
import json
import math
import os
from pathlib import Path
import re
import threading
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener, urlopen

EVENT_INDEX = 'hunt-lab-events'
INTEL_INDEX = 'hunt-lab-intel'
NETWORK_INDEX = 'arkime_sessions3-*'
ARKIME = 'http://127.0.0.1:8005'
# Anonymous Arkime is superAdmin: only these read routes are ever requested.
ARKIME_ROUTES = frozenset({'/api/sessions', '/api/unique'})
PROFILES = frozenset({
    'framework-coordinator', 'framework-researcher', 'framework-network-analyst',
    'framework-librarian', 'framework-builder', 'framework-reviewer',
})
BOARD_PROFILE = 'hunt-board'
CASE_ID = re.compile(r'[a-z0-9-]{3,64}')
EVENT_FIELDS = ['@timestamp', 'ecs', 'event', 'host', 'process', 'source', 'destination', 'network', 'dns', 'winlog', 'message', 'labels']
NETWORK_FIELDS = ['firstPacket', 'lastPacket', 'source.ip', 'source.port', 'destination.ip', 'destination.port', 'network.packets', 'network.bytes', 'network.protocol', 'dns.host', 'node']
MAX_RESULT = 200
ES_TIMEOUT = 15
ARKIME_TIMEOUT = 20
MAX_BACKEND_BYTES = 8 * 1024 * 1024
ACTIVITY_LIMIT = 2000
MAX_HISTOGRAM_BUCKETS = 2000

# Aggregatable keyword/ip/numeric ECS paths (see ingest.py mapping).
KEYWORD_FIELDS = (
    'event.id', 'event.dataset', 'event.kind', 'event.category', 'event.type', 'event.action',
    'event.outcome', 'event.code', 'event.provider', 'host.name', 'host.ip', 'user.name',
    'user.domain', 'process.entity_id', 'process.pid', 'process.name', 'process.executable',
    'process.command_line', 'process.parent.entity_id', 'process.parent.pid',
    'process.parent.name', 'process.parent.executable', 'process.parent.command_line',
    'source.ip', 'source.port', 'destination.ip', 'destination.port', 'network.protocol',
    'network.transport', 'network.direction', 'network.type', 'dns.question.name',
    'dns.question.type', 'dns.answers.data', 'url.domain', 'url.full', 'http.request.method',
    'http.response.status_code', 'tls.server_name', 'file.path', 'file.name',
    'winlog.channel', 'user_agent.original',
    # Every other field the scenario generator writes (both stories), so bots can return them.
    'dns.response_code', 'group.name', 'host.os.name', 'host.os.type', 'http.request.bytes',
    'http.response.bytes', 'observer.name', 'observer.type', 'process.hash.sha256', 'service.name',
    'url.path', 'url.query', 'url.scheme', 'user.target.domain', 'user.target.name',
    'winlog.event_data.AccountName', 'winlog.event_data.AuthenticationPackageName',
    'winlog.event_data.FailureReason', 'winlog.event_data.GrantedAccess', 'winlog.event_data.ImagePath',
    'winlog.event_data.LogonProcessName', 'winlog.event_data.LogonType', 'winlog.event_data.MemberName',
    'winlog.event_data.PrivilegeList', 'winlog.event_data.ServiceName', 'winlog.event_data.ServiceType',
    'winlog.event_data.StartType', 'winlog.event_data.Status', 'winlog.event_data.SubStatus',
    'winlog.event_data.SubjectLogonId', 'winlog.event_data.SubjectUserName',
    'winlog.event_data.TargetDomainName', 'winlog.event_data.TargetImage', 'winlog.event_data.TargetLogonId',
    'winlog.event_data.TargetProcessGuid', 'winlog.event_data.TargetProcessId',
    'winlog.event_data.TargetUserName', 'winlog.event_data.TaskContent', 'winlog.event_data.TaskName',
    'winlog.event_data.WorkstationName',
)
AGG_FIELDS = frozenset(KEYWORD_FIELDS)
SEARCH_FIELDS = frozenset(KEYWORD_FIELDS + (
    '@timestamp', 'message', 'dns.answers', 'network.bytes', 'network.packets'))
LABEL_FIELD = re.compile(r'labels\.[a-z0-9_]{1,40}')
ALWAYS_FIELDS = ('event.id', '@timestamp', 'host.name')
DEFAULT_FIELDS = ALWAYS_FIELDS + (
    'event.category', 'event.action', 'user.name', 'process.name', 'process.command_line',
    'source.ip', 'destination.ip', 'destination.port', 'dns.question.name', 'url.domain', 'message')
# Unqualified query_string terms; .text subfields allow token search in long values.
QUERY_FIELDS = [
    'message', 'event.id', 'event.action', 'host.name', 'user.name', 'process.name',
    'process.parent.name', 'process.command_line.text', 'process.parent.command_line.text',
    'dns.question.name', 'url.domain', 'url.full.text', 'tls.server_name', 'file.path.text',
]
LEADING_WILDCARD = re.compile(r'(?:^|[\s(\[{:,"+!-])[*?]')
INTERVALS = {'1m': 60, '5m': 300, '15m': 900, '1h': 3600}
INTEL_FIELDS = ('indicator.type', 'indicator.value', 'threat.feed.name', 'confidence',
                'description', 'first_seen')
# Arkime database field names returned by /api/sessions (TLS SNI is stored in http.host).
ARKIME_SESSION_FIELDS = (
    'firstPacket', 'lastPacket', 'source.ip', 'source.port', 'destination.ip',
    'destination.port', 'ipProtocol', 'protocol', 'network.bytes', 'network.packets',
    'source.bytes', 'destination.bytes', 'dns.host', 'dns.qt', 'http.host', 'http.uri',
    'http.method', 'http.statuscode', 'http.useragent', 'tls.version', 'tls.cipher',
    'tls.ja3', 'tls.ja4', 'tags',
)
ARKIME_DEFAULT_FIELDS = (
    'firstPacket', 'lastPacket', 'source.ip', 'source.port', 'destination.ip',
    'destination.port', 'ipProtocol', 'protocol', 'network.bytes', 'network.packets',
    'dns.host', 'http.host',
)
# Arkime expression field names accepted by /api/unique.
ARKIME_UNIQUE_FIELDS = frozenset({
    'ip.src', 'ip.dst', 'port.src', 'port.dst', 'ip.protocol', 'protocols', 'host.dns',
    'host.http', 'http.uri', 'http.method', 'http.statuscode', 'http.user-agent',
    'dns.query.type', 'tls.version', 'tls.cipher', 'tls.ja3', 'tls.ja4', 'tags',
})
MAX_UNIQUE_VALUES = 1000
MISSING = object()


class BackendQueryError(Exception):
    """A refused query, with a fixed snake_case code the bot can act on; never echo backend text.

    invalid_query: the backend rejected the syntax; field_not_allowed / invalid_field_list: a field
    outside the allowlist; leading_wildcard_not_supported: a term starts with * or ?.
    """


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *_):
        return None


_ARKIME_OPENER = build_opener(ProxyHandler({}), _NoRedirect())


def es_search(base, index, body, ignore_unavailable=False):
    url = base.rstrip('/') + '/' + index + '/_search' + ('?ignore_unavailable=true' if ignore_unavailable else '')
    request = Request(url, data=json.dumps(body).encode(), method='POST',
                      headers={'Content-Type': 'application/json'})
    try:
        with urlopen(request, timeout=ES_TIMEOUT) as response:
            data = response.read(MAX_BACKEND_BYTES + 1)
    except HTTPError as exc:
        if exc.code == 400:
            raise BackendQueryError('invalid_query') from None
        raise
    if len(data) > MAX_BACKEND_BYTES:
        raise RuntimeError('Oversized Elasticsearch response')
    try:
        result = json.loads(data)
    except ValueError:
        raise RuntimeError('Invalid Elasticsearch response') from None
    if result.get('timed_out') or result.get('_shards', {}).get('failed', 0):
        raise RuntimeError('Partial Elasticsearch response')
    return result


def arkime_get(route, params):
    if route not in ARKIME_ROUTES:
        raise RuntimeError('Arkime route not allowlisted')
    request = Request(ARKIME + route + '?' + urlencode(params), method='GET')
    try:
        with _ARKIME_OPENER.open(request, timeout=ARKIME_TIMEOUT) as response:
            data = response.read(MAX_BACKEND_BYTES + 1)
    except HTTPError as exc:
        if 400 <= exc.code < 500:
            raise BackendQueryError('invalid_expression') from None
        raise
    if len(data) > MAX_BACKEND_BYTES:
        raise RuntimeError('Oversized Arkime response')
    return data


def epoch(value):
    return int(datetime.fromisoformat(value.replace('Z', '+00:00')).timestamp() * 1000)


def iso_millis(value):
    return datetime.fromtimestamp(value / 1000, timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'


def single(params, allowed):
    if set(params) - allowed or any(len(v) != 1 for v in params.values()):
        raise ValueError('Unknown or duplicate query parameter')
    return {key: values[0] for key, values in params.items()}


def bounded(value, default, low, high):
    if value is None:
        return default
    if not re.fullmatch(r'[0-9]{1,10}', value):
        raise ValueError('Expected a bounded integer')
    number = int(value)
    if not low <= number <= high:
        raise ValueError('Integer out of range')
    return number


def text(value, limit):
    value = value or ''
    if len(value) > limit or any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError('Text too long or contains control characters')
    return value


def field_list(value, allowed, default, maximum=40):
    if value is None:
        return list(default)
    fields = [item.strip() for item in value.split(',')]
    if not fields or len(fields) > maximum or len(set(fields)) != len(fields):
        raise BackendQueryError('invalid_field_list')
    for item in fields:
        if item not in allowed and not (allowed is SEARCH_FIELDS and LABEL_FIELD.fullmatch(item)):
            raise BackendQueryError('field_not_allowed')
    return fields


def pick(value, parts):
    if not parts:
        return value
    if isinstance(value, list):
        found = [item for item in (pick(entry, parts) for entry in value) if item is not MISSING]
        return found if found else MISSING
    if not isinstance(value, dict):
        return MISSING
    # Accept nested ECS objects and literal dotted keys.
    for size in range(len(parts), 0, -1):
        key = '.'.join(parts[:size])
        if key in value:
            found = pick(value[key], parts[size:])
            if found is not MISSING:
                return found
    return MISSING


def flatten(source, fields):
    row = {}
    for field in fields:
        value = pick(source, field.split('.'))
        if value is not MISSING:
            row[field] = value
    return row


def window(case):
    bounds = case['time_range_utc']
    return bounds['start_inclusive'], bounds['end_exclusive']


def lucene(q):
    q = text(q, 500)
    if not q.strip():
        return None
    if LEADING_WILDCARD.search(q):
        raise BackendQueryError('leading_wildcard_not_supported')
    return {'query_string': {'query': q, 'fields': QUERY_FIELDS, 'default_operator': 'AND',
                             'allow_leading_wildcard': False, 'analyze_wildcard': False,
                             'lenient': True}}


def event_query(case, q):
    filters = [{'term': {'event.dataset': case['case_id']}}]
    clause = lucene(q)
    if clause:
        filters.append(clause)
    return {'bool': {'filter': filters}}


def network_filters(server):
    start, end = window(server.case)
    filters = [{'range': {'firstPacket': {'gte': epoch(start), 'lt': epoch(end)}}}]
    if server.network_scope == 'tag':
        filters.append({'term': {'tags': 'case:' + server.case['case_id']}})
    return filters


def query(server, dataset, params):
    allowed = {'q', 'host', 'limit', 'offset'}
    values = single(params, allowed)
    limit = bounded(values.get('limit'), 50, 1, MAX_RESULT)
    offset = bounded(values.get('offset'), 0, 0, 5000)
    q = text(values.get('q'), 300)
    host = text(values.get('host'), 100)
    case = server.case
    if dataset == 'events':
        filters = [{'term': {'event.dataset': case['case_id']}}]
        if host:
            filters.append({'term': {'host.name': host}})
        index, fields, timefield = EVENT_INDEX, EVENT_FIELDS, '@timestamp'
        if q:
            filters.append({'simple_query_string': {'query': q, 'fields': ['message', 'host.name', 'process.name', 'dns.question.name', 'event.id'], 'default_operator': 'and'}})
    else:
        filters = network_filters(server)
        if host:
            filters.append({'bool': {'should': [{'term': {'source.ip': host}}, {'term': {'destination.ip': host}}], 'minimum_should_match': 1}})
        index, fields, timefield = NETWORK_INDEX, NETWORK_FIELDS, 'firstPacket'
        if q:
            filters.append({'simple_query_string': {'query': q, 'fields': ['dns.host', 'network.protocol'], 'default_operator': 'and'}})
    response = es_search(server.elastic, index, {'query': {'bool': {'filter': filters}}, 'size': limit, 'from': offset,
                                                 'sort': [{timefield: 'asc'}], '_source': fields, 'track_total_hits': True,
                                                 'timeout': '10s'})
    hits = response['hits']
    return {'case_id': case['case_id'], 'dataset': dataset, 'total': hits['total']['value'],
            'total_relation': hits['total']['relation'], 'offset': offset, 'limit': limit,
            'returned': len(hits['hits']), 'more': offset + len(hits['hits']) < hits['total']['value'],
            'records': [hit['_source'] for hit in hits['hits']], 'read_only': True}


def encode_after(sort):
    return base64.urlsafe_b64encode(json.dumps(sort, separators=(',', ':')).encode()).decode().rstrip('=')


def decode_after(token):
    token = text(token, 400)
    if not re.fullmatch(r'[A-Za-z0-9_-]{1,400}', token):
        raise ValueError('Invalid after token')
    value = json.loads(base64.urlsafe_b64decode(token + '=' * (-len(token) % 4)))
    if (not isinstance(value, list) or len(value) != 2 or type(value[0]) is not int
            or not isinstance(value[1], str) or len(value[1]) > 128):
        raise ValueError('Invalid after token')
    return value


def es_search_endpoint(server, params):
    values = single(params, {'q', 'size', 'sort', 'after', 'fields'})
    size = bounded(values.get('size'), 50, 1, MAX_RESULT)
    order = values.get('sort', 'asc')
    if order not in ('asc', 'desc'):
        raise ValueError('sort must be asc or desc')
    requested = field_list(values.get('fields'), SEARCH_FIELDS, DEFAULT_FIELDS)
    fields = list(ALWAYS_FIELDS) + [field for field in requested if field not in ALWAYS_FIELDS]
    body = {'query': event_query(server.case, values.get('q')), 'size': size,
            'sort': [{'@timestamp': order}, {'event.id': order}], '_source': fields,
            'track_total_hits': True, 'timeout': '10s'}
    if 'after' in values:
        body['search_after'] = decode_after(values['after'])
    hits = es_search(server.elastic, EVENT_INDEX, body)['hits']
    rows = hits['hits']
    return {'case_id': server.case['case_id'], 'total': hits['total']['value'],
            'total_relation': hits['total']['relation'], 'returned': len(rows),
            'hits': [flatten(hit['_source'], fields) for hit in rows],
            'next_after': encode_after(rows[-1]['sort']) if len(rows) == size else None}


def es_aggs_endpoint(server, params):
    values = single(params, {'q', 'field', 'size', 'interval'})
    field = values.get('field')
    size = bounded(values.get('size'), 20, 1, 100)
    if field == '@timestamp':
        interval = values.get('interval', '1h')
        if interval not in INTERVALS:
            raise ValueError('interval must be 1m, 5m, 15m or 1h')
        start, end = window(server.case)
        if math.ceil((epoch(end) - epoch(start)) / 1000 / INTERVALS[interval]) > MAX_HISTOGRAM_BUCKETS:
            raise ValueError('interval too fine for the case window')
        aggregation = {'date_histogram': {'field': '@timestamp', 'fixed_interval': interval, 'min_doc_count': 1,
                                          'format': "yyyy-MM-dd'T'HH:mm:ss'Z'",
                                          'hard_bounds': {'min': epoch(start), 'max': epoch(end) - 1}}}
    elif field in AGG_FIELDS:
        if 'interval' in values:
            raise ValueError('interval applies only to @timestamp')
        aggregation = {'terms': {'field': field, 'size': size}}
    else:
        raise BackendQueryError('field_not_allowed')
    response = es_search(server.elastic, EVENT_INDEX, {
        'query': event_query(server.case, values.get('q')), 'size': 0, 'track_total_hits': True,
        'timeout': '10s', 'aggs': {'values': aggregation}})
    result = response['aggregations']['values']
    buckets = [{'key': bucket.get('key_as_string', bucket['key']), 'count': bucket['doc_count']}
               for bucket in result['buckets']]
    value = {'case_id': server.case['case_id'], 'field': field, 'total': response['hits']['total']['value'],
             'buckets': buckets}
    if 'sum_other_doc_count' in result:
        value['other'] = result['sum_other_doc_count']
    return value


def es_detect_endpoint(server, params):
    values = single(params, {'q', 'name'})
    name = text(values.get('name'), 80).strip()
    if not name:
        raise ValueError('name is required')
    fields = list(DEFAULT_FIELDS)
    response = es_search(server.elastic, EVENT_INDEX, {
        'query': event_query(server.case, values.get('q')), 'size': 10,
        'sort': [{'@timestamp': 'asc'}, {'event.id': 'asc'}], '_source': fields,
        'track_total_hits': True, 'timeout': '10s',
        'aggs': {'hosts': {'terms': {'field': 'host.name', 'size': 20}},
                 'first': {'min': {'field': '@timestamp'}}, 'last': {'max': {'field': '@timestamp'}}}})
    aggs = response['aggregations']
    return {'case_id': server.case['case_id'], 'name': name, 'total': response['hits']['total']['value'],
            'hosts': [{'key': bucket['key'], 'count': bucket['doc_count']} for bucket in aggs['hosts']['buckets']],
            'first': aggs['first'].get('value_as_string') if aggs['first'].get('value') is not None else None,
            'last': aggs['last'].get('value_as_string') if aggs['last'].get('value') is not None else None,
            'sample': [flatten(hit['_source'], fields) for hit in response['hits']['hits']]}


def intel_endpoint(server, params):
    values = single(params, {'values'})
    requested = []
    for item in text(values.get('values'), 50 * 201).split(','):
        item = item.strip()
        if not item or len(item) > 200:
            raise ValueError('Each value must be 1..200 characters')
        if item not in requested:
            requested.append(item)
    if len(requested) > 50:
        raise ValueError('At most 50 values')
    response = es_search(server.elastic, INTEL_INDEX, {
        'query': {'bool': {'filter': [{'term': {'case_id': server.case['case_id']}},
                                      {'terms': {'indicator.value': requested}}]}},
        'size': 500, '_source': list(INTEL_FIELDS), 'timeout': '10s',
        'sort': [{'indicator.value': 'asc'}, {'threat.feed.name': 'asc'}]}, ignore_unavailable=True)
    matches = [flatten(hit['_source'], INTEL_FIELDS) for hit in response['hits']['hits']]
    found = {str(match.get('indicator.value', '')).lower() for match in matches}
    return {'case_id': server.case['case_id'], 'matches': matches,
            'unmatched': [item for item in requested if item.lower() not in found]}


def check_expression(expression):
    """Reject anything that could escape the server's `scope && (expression)` wrapper."""
    expression = text(expression, 500)
    depth = 0
    quote = None
    escaped = False
    for char in expression:
        if quote:
            if escaped:
                escaped = False
            elif char == '\\':
                escaped = True
            elif char == quote:
                quote = None
        elif char in '"/':
            quote = char
        elif char == '(':
            depth += 1
        elif char == ')':
            depth -= 1
            if depth < 0:
                raise ValueError('Unbalanced expression')
    if quote or depth:
        raise ValueError('Unbalanced expression')
    return expression.strip()


def arkime_scope(server, expression):
    start, end = window(server.case)
    clauses = []
    if server.network_scope == 'tag':
        clauses.append('tags == "case:%s"' % server.case['case_id'])
    expression = check_expression(expression)
    if expression:
        clauses.append('(' + expression + ')')
    scope = {'startTime': epoch(start) // 1000, 'stopTime': epoch(end) // 1000, 'bounding': 'first'}
    if clauses:
        scope['expression'] = ' && '.join(clauses)
    return scope


def arkime_sessions_endpoint(server, params):
    values = single(params, {'expression', 'length', 'start', 'fields'})
    length = bounded(values.get('length'), 50, 1, MAX_RESULT)
    start = bounded(values.get('start'), 0, 0, 10000)
    fields = field_list(values.get('fields'), frozenset(ARKIME_SESSION_FIELDS), ARKIME_DEFAULT_FIELDS)
    request = dict(arkime_scope(server, values.get('expression')), length=length, start=start,
                   fields=','.join(fields), order='firstPacket:asc')
    try:
        data = json.loads(arkime_get('/api/sessions', request))
    except ValueError:
        raise RuntimeError('Invalid Arkime response') from None
    if not isinstance(data, dict) or not isinstance(data.get('data', []), list):
        raise RuntimeError('Invalid Arkime response')
    if data.get('error'):
        raise BackendQueryError('invalid_expression')
    sessions = []
    for record in data.get('data', [])[:length]:
        row = flatten(record, fields)
        for key in ('firstPacket', 'lastPacket'):
            if type(row.get(key)) is int:
                row[key] = iso_millis(row[key])
        sessions.append(row)
    return {'case_id': server.case['case_id'], 'recordsFiltered': int(data.get('recordsFiltered', 0)),
            'returned': len(sessions), 'sessions': sessions}


def arkime_unique_endpoint(server, params):
    values = single(params, {'expression', 'field', 'counts'})
    field = values.get('field')
    if field not in ARKIME_UNIQUE_FIELDS:
        raise BackendQueryError('field_not_allowed')
    counts = values.get('counts', '1')
    if counts not in ('0', '1'):
        raise ValueError('counts must be 0 or 1')
    request = dict(arkime_scope(server, values.get('expression')), exp=field, counts=counts)
    lines = [line for line in arkime_get('/api/unique', request).decode('utf-8', 'replace').splitlines() if line]
    result = []
    for line in lines[:MAX_UNIQUE_VALUES]:
        if counts == '1':
            value, separator, count = line.rpartition(', ')
            if not separator or not count.isdigit():
                raise RuntimeError('Invalid Arkime unique response')
            result.append({'value': value, 'count': int(count)})
        else:
            result.append({'value': line})
    if counts == '1':
        result.sort(key=lambda item: (-item['count'], item['value']))
    return {'case_id': server.case['case_id'], 'field': field, 'returned': len(result),
            'truncated': len(lines) > MAX_UNIQUE_VALUES, 'values': result}


def events_endpoint(server, params):
    return query(server, 'events', params)


def network_endpoint(server, params):
    return query(server, 'network', params)


# path -> (tool name shown on the board, handler, (result_count key, total key))
TOOL_ROUTES = {
    '/es/search': ('elastic_search', es_search_endpoint, ('returned', 'total')),
    '/es/aggs': ('elastic_aggregate', es_aggs_endpoint, ('buckets', 'total')),
    '/es/detect': ('detection_test', es_detect_endpoint, ('sample', 'total')),
    '/intel': ('intel_lookup', intel_endpoint, ('matches', None)),
    '/arkime/sessions': ('arkime_sessions', arkime_sessions_endpoint, ('returned', 'recordsFiltered')),
    '/arkime/unique': ('arkime_unique', arkime_unique_endpoint, ('returned', None)),
    '/events': ('hunt_lab_query', events_endpoint, ('returned', 'total')),
    '/network': ('hunt_lab_query', network_endpoint, ('returned', 'total')),
}


class Activity:
    """In-memory ring of tool requests for display; never persisted."""

    def __init__(self, limit=ACTIVITY_LIMIT):
        self.entries = deque(maxlen=limit)
        self.sequence = 0
        self.lock = threading.Lock()

    def record(self, **entry):
        with self.lock:
            self.sequence += 1
            self.entries.append(dict(seq=self.sequence,
                                     time=datetime.now(timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z'),
                                     **entry))

    def since(self, after, limit):
        with self.lock:
            # A restarted server restarts numbering; a stale cursor sees the whole ring.
            if after > self.sequence:
                after = 0
            pending = [entry for entry in self.entries if entry['seq'] > after]
            entries = [dict(entry) for entry in pending[:limit]]
            return (entries[-1]['seq'] if entries else after), entries, len(pending) > limit


def counted(value):
    return len(value) if isinstance(value, list) else value


def health(server):
    events = query(server, 'events', {'limit': ['1']})
    network = query(server, 'network', {'limit': ['1']})
    intel = es_search(server.elastic, INTEL_INDEX, {
        'query': {'bool': {'filter': [{'term': {'case_id': server.case['case_id']}}]}},
        'size': 0, 'track_total_hits': True, 'timeout': '10s'}, ignore_unavailable=True)
    try:
        with urlopen(ARKIME + '/', timeout=5) as viewer:
            viewer_ready = viewer.status == 200
    except (OSError, HTTPError, URLError):
        viewer_ready = False
    ready = events['total'] > 0 and network['total'] > 0 and viewer_ready
    return ready, {'ready': ready, 'case_id': server.case['case_id'],
                   'event_count': events['total'], 'network_session_count': network['total'],
                   'intel_count': intel['hits']['total']['value'], 'network_scope': server.network_scope,
                   'arkime_viewer_ready': viewer_ready, 'read_only': True}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def send(self, status, value, kind='application/json'):
        body = (json.dumps(value, ensure_ascii=True).encode() if kind == 'application/json' else value.encode())
        self.send_response(status)
        self.send_header('Content-Type', kind + '; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'")
        self.end_headers()
        self.wfile.write(body)

    def tool(self, path, params):
        name, handler, (count_key, total_key) = TOOL_ROUTES[path]
        status, value, error = 200, None, None
        try:
            value = handler(self.server, params)
        except BackendQueryError as exc:
            status, error = 400, exc.args[0]
        except (ValueError, TypeError):
            status, error = 400, 'invalid_query'
        except (OSError, KeyError, RuntimeError):
            status, error = 503, 'backend_not_ready'
        claimed = self.headers.get('X-Hermes-Profile', '')
        if claimed != BOARD_PROFILE:
            self.server.activity.record(
                profile=claimed if claimed in PROFILES else 'unknown', tool=name, endpoint=path,
                params={key[:40]: values[-1][:300] for key, values in list(params.items())[:10]},
                result_count=counted(value[count_key]) if value else None,
                total=value.get(total_key) if value and total_key else None, error=error)
        if error is None:
            self.send(200, value)
        elif status == 400:
            self.send(400, {'error': error})
        else:
            self.send(503, {'error': error, 'partial_results': False})

    def do_GET(self):
        try:
            target = urlsplit(self.path)
            params = parse_qs(target.query, keep_blank_values=True)
            if target.path in TOOL_ROUTES:
                self.tool(target.path, params)
            elif target.path == '/health':
                if params:
                    raise ValueError('No health parameters supported')
                ready, value = health(self.server)
                self.send(200 if ready else 503, value)
            elif target.path == '/activity':
                values = single(params, {'after', 'limit'})
                after = bounded(values.get('after'), 0, 0, 10**9)
                limit = bounded(values.get('limit'), 100, 1, 100)
                cursor, entries, more = self.server.activity.since(after, limit)
                self.send(200, {'case_id': self.server.case['case_id'], 'next': cursor, 'more': more,
                                'entries': entries})
            elif target.path == '/case':
                if params:
                    raise ValueError('No case parameters supported')
                self.send(200, self.server.case)
            elif target.path in ('/', '/view'):
                result = query(self.server, 'events', params)
                records = ''.join('<tr><td>' + html.escape(str(row.get('@timestamp', ''))) + '</td><td><pre>' +
                                  html.escape(json.dumps(row, indent=2)) + '</pre></td></tr>' for row in result['records'])
                body = ('<!doctype html><html><head><meta charset="utf-8"><title>Hermes hunting lab</title>'
                        '<style>body{font:16px system-ui;margin:24px}td{vertical-align:top;border-bottom:1px solid #999}pre{white-space:pre-wrap}input{margin:6px}</style></head><body>'
                        '<h1>Hermes supplied-evidence lab</h1><p>Synthetic data only. Read-only. No live capture.</p>'
                        '<p>Case: ' + html.escape(self.server.case['case_id']) + '</p><p>' + html.escape(self.server.case['question']) + '</p>'
                        '<form action="/view" method="get"><label>Search <input name="q"></label><label>Host <input name="host"></label><button>Search logs</button></form>'
                        '<p><a href="/events">JSON events</a> · <a href="/network">Network metadata</a> · <a href="/case">Source coverage</a> · <a href="/health">Readiness</a></p>'
                        '<p>Showing %d of %d events; additional pages are available through the bounded API.</p><table>%s</table></body></html>' % (result['returned'], result['total'], records))
                self.send(200, body, 'text/html')
            else:
                self.send(404, {'error': 'not_found'})
        except (ValueError, TypeError, BackendQueryError):
            self.send(400, {'error': 'invalid_query'})
        except (OSError, HTTPError, URLError, KeyError, RuntimeError):
            self.send(503, {'error': 'backend_not_ready', 'partial_results': False})

    def do_POST(self):
        self.send(405, {'error': 'read_only'})

    do_PUT = do_POST
    do_DELETE = do_POST
    do_PATCH = do_POST
    do_HEAD = do_POST
    do_OPTIONS = do_POST
    do_TRACE = do_POST
    do_CONNECT = do_POST


def load_case(path):
    case = json.loads(Path(path).read_text(encoding='utf-8'))
    if not isinstance(case.get('case_id'), str) or not CASE_ID.fullmatch(case['case_id']):
        raise ValueError('case.json case_id must match [a-z0-9-]{3,64}')
    start, end = window(case)
    if epoch(start) >= epoch(end):
        raise ValueError('case.json time_range_utc must be a nonempty window')
    return case


def make_server(bind, port, case, elastic, network_scope='tag'):
    if network_scope not in ('tag', 'window'):
        raise ValueError('network_scope must be tag or window')
    server = ThreadingHTTPServer((bind, port), Handler)
    server.daemon_threads = True
    server.elastic = elastic
    server.case = case
    server.network_scope = network_scope
    server.activity = Activity()
    return server


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bind', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=8765)
    parser.add_argument('--case', required=True)
    # "window" only serves a legacy dns-lab-001 pcap imported before case tagging.
    parser.add_argument('--network-scope', choices=('tag', 'window'), default='tag')
    args = parser.parse_args()
    server = make_server(args.bind, args.port, load_case(args.case),
                         os.environ.get('LAB_ELASTICSEARCH', 'http://elasticsearch:9200'), args.network_scope)
    server.serve_forever()


if __name__ == '__main__':
    main()

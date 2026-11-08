"""What the lab browser lets a page request: lab origins only, the lab console read-only, Arkime read-only
with every search scoped to the loaded case, and Kibana's Discover with every search pinned to the case's
data view and window. Pure; lab_browser applies it through CDP Fetch."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
import re
from urllib import parse

SEARCH_KEYS = ('expression', 'date', 'startTime', 'stopTime')
MAX_EXPRESSION = 1000
# Anonymous Arkime is superAdmin, so the guest lab service only ever calls its /api/sessions and
# /api/unique reads (guest/lab_server.py ARKIME_ROUTES) and wraps every expression in the case tag
# and window (arkime_scope). The browser reaches Arkime directly, so the same limits live here:
# searches are rewritten to the case, and writes, exports, payloads and admin surfaces fail.
ARKIME_SEARCH_PREFIXES = (
    '/api/sessions', '/api/spiview', '/api/spigraph', '/api/unique', '/api/multiunique',
    '/api/connections', '/api/buildquery', '/sessions.json', '/spiview.json', '/spigraph.json',
    '/unique.txt', '/multiunique.txt', '/connections.json',
)
ARKIME_DENIED = re.compile(
    r'delete|scrub|tags|/users\b|settings|hunt|send|pcap|/raw|packets|upload|csv|entire|bodyhash'
    r'|/session/|/files|/history|/es(?:admin|indices|shards|tasks|recovery|nodes)|/parliament'
    r'|/cyberchef|/notifier|/cron|/shortcut|/lookup|/reindex', re.IGNORECASE)
# Kibana runs without security in the guest, so this fence is what keeps a bot's browser on a read-only
# Discover. guest/kibana_setup.py makes KIBANA_INDEX a filtered alias holding only the case's events and the
# id of the data view over it. Only the routes Discover 8.19 was observed to need pass; every other route,
# including saved-object and settings writes, the Console proxy, alerting, index management and every
# other app, fails.
KIBANA_INDEX = 'hunt-lab-case-events'
KIBANA_APP = '/app/discover'
KIBANA_TIME_FIELD = '@timestamp'
KIBANA_STATIC = re.compile(
    r'/(?:bootstrap\.js|[0-9a-f]{12}/(?:bundles|ui)/[\w@%+.,~/-]+|translations/[0-9a-f]{12}/[A-Za-z-]+\.json)')
# Discover asks for the alerting rule types to draw its Alerts menu and toasts an error when that read fails;
# creating or changing a rule stays refused.
KIBANA_READS = {
    'GET': re.compile(
        r'/app/discover|/api/(?:licensing/info|banners/info|spaces/space|alerting/rule_types)|/internal/(?:spaces/_active_space'
        r'|security/(?:me|session|user_profile)|core/pricing|fields_metadata|data_views/has_(?:data_views|es_data))'),
    'POST': re.compile(r'/api/core/capabilities'),
}
# Field lists, allowed only for the case's index pattern.
KIBANA_FIELDS = ('GET', '/internal/data_views/fields'), ('POST', '/internal/data_views/_fields_for_wildcard')
# Discover's searches; each is pinned to KIBANA_INDEX and the case window. ES|QL, SQL and EQL strategies fail.
KIBANA_SEARCH = '/internal/bsearch'
KIBANA_SEARCH_STRATEGIES = frozenset({'ese', 'es'})
# Search body keys Discover sends; suggest, knn and the like could read past the alias filter.
KIBANA_SEARCH_KEYS = frozenset({
    'query', 'sort', 'fields', 'size', 'from', 'version', '_source', 'highlight', 'stored_fields',
    'runtime_mappings', 'script_fields', 'aggs', 'aggregations', 'track_total_hits', 'docvalue_fields',
    'search_after', 'timeout', 'terminate_after'})
# Filter-editor value suggestions, run as an aggregation (terms_enum ignores the alias filter).
KIBANA_SUGGESTIONS = '/internal/kibana/suggestions/values/'
# Data view reads; create, update and delete fail.
KIBANA_CONTENT = re.compile(r'/api/content_management/rpc/(?:get|search|mSearch|bulkGet)')


class Refused(Exception):
    """A request the lab browser must fail; args[0] is a fixed snake_case reason."""


@dataclass(frozen=True)
class LabScope:
    case_id: str
    lab_origin: str
    arkime_origin: str
    start: int
    stop: int
    kibana_origin: str | None = None

    @classmethod
    def from_case(cls, case, lab_origin, arkime_origin, kibana_origin=None):
        bounds = case['time_range_utc']
        start, stop = (int(datetime.fromisoformat(bounds[key].replace('Z', '+00:00')).timestamp())
                       for key in ('start_inclusive', 'end_exclusive'))
        if start >= stop:
            raise ValueError('empty case window')
        return cls(case['case_id'], lab_origin, arkime_origin, start, stop, kibana_origin)

    @property
    def origins(self):
        return self.lab_origin, self.arkime_origin, self.kibana_origin


@dataclass(frozen=True)
class Verdict:
    block: str | None = None
    url: str | None = None
    body: str | None = None
    expression: str | None = None


ALLOW = Verdict()


def origin(url):
    """`scheme://host:port` for credential-free http(s) URLs, else None."""
    try:
        parts = parse.urlsplit(url)
        if parts.scheme not in ('http', 'https') or not parts.hostname or parts.username or parts.password:
            return None
        return '%s://%s:%d' % (parts.scheme, parts.hostname, parts.port or (443 if parts.scheme == 'https' else 80))
    except ValueError:
        return None


def document_allowed(scope, url):
    """Pages the main frame may show: the lab and Arkime anywhere, Kibana only in Discover."""
    if url == 'about:blank' or origin(url) in (scope.lab_origin, scope.arkime_origin):
        return True
    return (scope.kibana_origin is not None and origin(url) == scope.kibana_origin
            and parse.urlsplit(url).path.rstrip('/') == KIBANA_APP)


def check_expression(expression):
    """Reject text that could escape the `(expression) && tag` wrapper (as guest check_expression)."""
    if not isinstance(expression, str) or len(expression) > MAX_EXPRESSION \
            or any(ord(char) < 32 or ord(char) == 127 for char in expression):
        raise Refused('arkime_expression_rejected')
    depth, quote, escaped = 0, None, False
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
                raise Refused('arkime_expression_rejected')
    if quote or depth:
        raise Refused('arkime_expression_rejected')
    return expression.strip()


def scoped_expression(case_id, expression):
    tag = 'tags == "case:%s"' % case_id
    expression = check_expression(expression)
    return '(%s) && %s' % (expression, tag) if expression else tag


def _seconds(value):
    value = str(value) if isinstance(value, (str, int)) and not isinstance(value, bool) else ''
    return int(value) if re.fullmatch(r'[0-9]{1,12}', value) else None


def clamp_window(scope, start, stop):
    """The requested window cut to the case window; the whole case window when they do not overlap."""
    start, stop = _seconds(start), _seconds(stop)
    if start is not None and stop is not None:
        start, stop = max(start, scope.start), min(stop, scope.stop)
        if start < stop:
            return start, stop
    return scope.start, scope.stop


def _scoped(scope, values):
    """Search fields of one Arkime request rewritten to the case: expression tagged, window clamped,
    and relative `date` ranges replaced by explicit case-window bounds."""
    start, stop = clamp_window(scope, values.get('startTime'), values.get('stopTime'))
    return {'expression': scoped_expression(scope.case_id, values.get('expression') or ''),
            'startTime': start, 'stopTime': stop}


def _scoped_pairs(scope, pairs):
    names = [name for name, _ in pairs]
    if any(names.count(key) > 1 for key in SEARCH_KEYS):
        raise Refused('arkime_ambiguous_search')
    scoped = _scoped(scope, dict(pairs))
    rest = [(name, value) for name, value in pairs if name not in SEARCH_KEYS]
    return rest + [(name, str(value)) for name, value in scoped.items()], scoped['expression']


def _scoped_body(scope, body):
    if body.lstrip().startswith('{'):
        try:
            values = json.loads(body)
        except ValueError:
            raise Refused('arkime_body_rejected') from None
        if not isinstance(values, dict):
            raise Refused('arkime_body_rejected')
        scoped = _scoped(scope, values)
        rest = {name: value for name, value in values.items() if name not in SEARCH_KEYS}
        return json.dumps({**rest, **scoped}, separators=(',', ':')), scoped['expression']
    pairs, expression = _scoped_pairs(scope, parse.parse_qsl(body, keep_blank_values=True))
    return parse.urlencode(pairs), expression


def _json_body(body):
    if body is None:
        raise Refused('kibana_body_unavailable')
    try:
        values = json.loads(body)
    except ValueError:
        raise Refused('kibana_body_rejected') from None
    if not isinstance(values, dict):
        raise Refused('kibana_body_rejected')
    return values


def case_range(scope):
    """The case window as an Elasticsearch filter: start inclusive, end exclusive."""
    return {'range': {KIBANA_TIME_FIELD: {'gte': scope.start * 1000, 'lt': scope.stop * 1000, 'format': 'epoch_millis'}}}


def kibana_window(scope):
    """Kibana's absolute time range for the case: the start, and the last millisecond before the end."""
    def stamp(millis):
        return datetime.fromtimestamp(millis / 1000, timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
    return stamp(scope.start * 1000), stamp(scope.stop * 1000 - 1)


def _pinned_search(scope, body):
    """A Discover batch search with each search held to the case index and window, whatever the time picker says."""
    values = _json_body(body)
    batch = values.get('batch')
    if not isinstance(batch, list) or not batch:
        raise Refused('kibana_body_rejected')
    for item in batch:
        if not isinstance(item, dict) or not isinstance(item.get('options'), dict) \
                or item['options'].get('strategy') not in KIBANA_SEARCH_STRATEGIES:
            raise Refused('kibana_search_denied')
        params = item.get('request', {}).get('params') if isinstance(item.get('request'), dict) else None
        if not isinstance(params, dict) or params.get('index') != KIBANA_INDEX:
            raise Refused('kibana_index_denied')
        search = params.setdefault('body', {})
        if not isinstance(search, dict) or set(search) - KIBANA_SEARCH_KEYS:
            raise Refused('kibana_search_denied')
        query = search.get('query')
        search['query'] = {'bool': {'must': [query] if query else [], 'filter': [case_range(scope)]}}
    return json.dumps(values, separators=(',', ':'))


def _kibana(scope, method, parts, body):
    path = parts.path
    if method == 'GET' and KIBANA_STATIC.fullmatch(path):
        return ALLOW
    reads = KIBANA_READS.get(method)
    if reads and reads.fullmatch(path):
        return ALLOW
    if (method, path) in KIBANA_FIELDS:
        patterns = [value for name, value in parse.parse_qsl(parts.query, keep_blank_values=True) if name == 'pattern']
        return ALLOW if patterns == [KIBANA_INDEX] else Verdict(block='kibana_index_denied')
    if method != 'POST':
        return Verdict(block='kibana_route_denied')
    if path == KIBANA_SEARCH:
        return Verdict(body=_pinned_search(scope, body))
    if path == KIBANA_SUGGESTIONS + KIBANA_INDEX:
        return Verdict(body=json.dumps({**_json_body(body), 'method': 'terms_agg'}, separators=(',', ':')))
    if KIBANA_CONTENT.fullmatch(path):
        return ALLOW if _json_body(body).get('contentTypeId') == 'index-pattern' else Verdict(block='kibana_route_denied')
    return Verdict(block='kibana_route_denied')


def decide(scope, method, url, body=''):
    """The verdict for one paused browser request; body is None when it exists but could not be read."""
    try:
        source = origin(url)
        if source == scope.lab_origin:
            return ALLOW if method == 'GET' else Verdict(block='lab_read_only')
        if scope.kibana_origin is not None and source == scope.kibana_origin:
            return _kibana(scope, method, parse.urlsplit(url), body)
        if source != scope.arkime_origin:
            return Verdict(block='origin_not_lab')
        parts = parse.urlsplit(url)
        if ARKIME_DENIED.search(parse.unquote(parts.path)):
            return Verdict(block='arkime_route_denied')
        search = parts.path.startswith(ARKIME_SEARCH_PREFIXES)
        pairs = parse.parse_qsl(parts.query, keep_blank_values=True)
        if method == 'GET' and not search and not any(name in SEARCH_KEYS for name, _ in pairs):
            return ALLOW
        if method != 'GET' and not (method == 'POST' and search):
            return Verdict(block='arkime_read_only')
        # Arkime reads search fields from the query and, for POST, the body: scope both.
        pairs, expression = _scoped_pairs(scope, pairs)
        url = parse.urlunsplit(parts._replace(query=parse.urlencode(pairs)))
        if method == 'POST' and body is None:
            raise Refused('arkime_body_unavailable')
        if method == 'POST' and body.strip():
            body, expression = _scoped_body(scope, body)
            return Verdict(url=url, body=body, expression=expression)
        return Verdict(url=url, expression=expression)
    except Refused as exc:
        return Verdict(block=exc.args[0])

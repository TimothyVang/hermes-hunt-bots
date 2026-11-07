"""What the lab browser lets a page request: lab origins only, the lab console read-only, and Arkime
read-only with every search scoped to the loaded case. Pure; lab_browser applies it through CDP Fetch."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
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


class Refused(Exception):
    """A request the lab browser must fail; args[0] is a fixed snake_case reason."""


@dataclass(frozen=True)
class LabScope:
    case_id: str
    lab_origin: str
    arkime_origin: str
    start: int
    stop: int

    @classmethod
    def from_case(cls, case, lab_origin, arkime_origin):
        bounds = case['time_range_utc']
        start, stop = (int(datetime.fromisoformat(bounds[key].replace('Z', '+00:00')).timestamp())
                       for key in ('start_inclusive', 'end_exclusive'))
        if start >= stop:
            raise ValueError('empty case window')
        return cls(case['case_id'], lab_origin, arkime_origin, start, stop)


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
    return url == 'about:blank' or origin(url) in (scope.lab_origin, scope.arkime_origin)


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


def decide(scope, method, url, body=''):
    """The verdict for one paused browser request; body is None when it exists but could not be read."""
    try:
        source = origin(url)
        if source == scope.lab_origin:
            return ALLOW if method == 'GET' else Verdict(block='lab_read_only')
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

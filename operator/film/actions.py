"""What the bots did and when, as the film tools read it.

Two real sources: each browser owner's lab_browser audit.jsonl (actions on screen) and the lab's
/activity feed (every API tool call). Both become one list of Actions; driving coverage, the cut's
captions and the review's browser moments are all computed from it.
"""
import json
from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class Owner:
    role: str
    web_tool: str
    api_tools: frozenset
    pages: frozenset


# The two bots that own a browser: the web tool each drives and the API searches it should show there.
# The Threat Hunter's Elastic web tool is Kibana Discover; the lab console no longer counts.
OWNERS = {
    'framework-researcher': Owner('Threat Hunter', 'Elastic', frozenset({'elastic_search'}), frozenset({'kibana_discover'})),
    'framework-network-analyst': Owner('Network Analyst', 'Arkime', frozenset({'arkime_sessions', 'arkime_unique'}),
                                       frozenset({'arkime_sessions', 'arkime_spiview'})),
}
ROLES = {'framework-coordinator': 'IR Lead', 'framework-researcher': 'Threat Hunter',
         'framework-network-analyst': 'Network Analyst', 'framework-librarian': 'Threat Intel',
         'framework-builder': 'Detection Engineer', 'framework-reviewer': 'Purple Team'}
PAGES = {'kibana_discover': 'Kibana Discover (Elastic)', 'lab_console': 'lab console', 'arkime_sessions': 'Arkime Sessions',
         'arkime_spiview': 'Arkime SPI View'}
CAPTION_MAX = 110


@dataclass(frozen=True)
class Action:
    t: float
    profile: str
    browser: bool
    tool: str
    query: str
    typed: bool
    ok: bool
    caption: str


def norm(query):
    return ' '.join(str(query or '').lower().split())


def _clip(text):
    return text if len(text) <= CAPTION_MAX else text[:CAPTION_MAX - 1] + '…'


def _browser_caption(e, query):
    page = PAGES.get(e.get('page'), e.get('page') or 'browser')
    what = {'open': f'searches "{query}"' if query else 'opens the page',
            'type': f'types "{query}"' + (' + Enter' if e.get('submit') else ''),
            'click': 'clicks', 'scroll': f'scrolls {e.get("direction") or ""}'.strip(),
            'press': f'presses {e.get("key") or ""}'.strip(), 'read': 'reads a result',
            'snapshot': 'reads the page'}.get(e.get('action'), e.get('action') or '')
    refused = '' if e.get('ok') else f' (refused: {e.get("error") or "error"})'
    return _clip(f'{ROLES.get(e.get("profile"), e.get("profile"))} · {page} · {what}{refused}')


def from_audit(lines, start, end):
    """lab_browser audit lines (JSON strings) whose time falls in [start, end] epoch seconds."""
    out = []
    for line in lines:
        try:
            e = json.loads(line)
            t = e['t'] / 1000
        except (ValueError, KeyError, TypeError):
            continue
        if not start <= t <= end:
            continue
        action = e.get('action')
        query = (e.get('query') if action == 'open' else e.get('text') if action == 'type' else '') or ''
        typed = bool(e.get('ok')) and bool(query) and (
            (action == 'open' and e.get('entered') == 'typed') or (action == 'type' and bool(e.get('submit'))))
        out.append(Action(t, e.get('profile') or '', True, e.get('page') or '', query, typed, bool(e.get('ok')),
                          _browser_caption(e, query)))
    return out


def _epoch(iso):
    return datetime.fromisoformat(iso.replace('Z', '+00:00')).timestamp()


def from_activity(entries):
    """The lab's /activity entries (every API tool call), as returned by tool_loops.activity_since."""
    out = []
    for e in entries:
        try:
            t = _epoch(e['time'])
        except (KeyError, ValueError, AttributeError):
            continue
        params = e.get('params') or {}
        query = params.get('q') or params.get('expression') or ''
        detail = query or params.get('field') or params.get('value') or ''
        result = f'ERROR {e["error"]}' if e.get('error') else (
            f'{e.get("result_count")} of {e.get("total")}' if e.get('total') is not None else f'{e.get("result_count")} results')
        role = ROLES.get(e.get('profile'), e.get('profile') or 'unknown')
        out.append(Action(t, e.get('profile') or '', False, e.get('tool') or '', query, False, not e.get('error'),
                          _clip(f'{role} · {e.get("tool")} {detail} → {result}'.replace('  ', ' '))))
    return out


def coverage(actions):
    """Per browser owner: typed browser searches, the share of its distinct API searches it also ran on screen,
    and whether it used both its API tool and its web tool. Overall coverage is the owners' mean, where an owner
    that skipped either tool scores 0."""
    owners = {}
    for profile, owner in OWNERS.items():
        mine = [a for a in actions if a.profile == profile]
        typed = [a for a in mine if a.browser and a.typed and a.tool in owner.pages]
        api = {norm(a.query) for a in mine if not a.browser and a.ok and a.tool in owner.api_tools and norm(a.query)}
        shown = api & {norm(a.query) for a in typed}
        fraction = len(shown) / len(api) if api else 0.0
        both = bool(api) and bool(typed)
        owners[profile] = {'role': owner.role, 'web_tool': owner.web_tool, 'typed_searches': len(typed),
                           'api_searches': len(api), 'shown_in_browser': len(shown),
                           'shown_fraction': round(fraction, 3), 'both_tools': both,
                           'coverage': round(fraction if both else 0.0, 3)}
    return {'coverage': round(sum(o['coverage'] for o in owners.values()) / len(owners), 3), 'owners': owners}

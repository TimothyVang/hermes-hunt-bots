#!/usr/bin/env python3
"""Point the lab's Kibana at the loaded case: a case-filtered alias, its data view and the case window.

Runs in the container lab's one-shot kibana-setup service after ingest. Every step converges, so running it
again for another case switches Kibana to that case. The data view reads the alias `hunt-lab-case-events`, which
Elasticsearch filters to the case's event.dataset, so Discover shows only the loaded case.
"""
import argparse
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import re
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

EVENT_STORE = 'hunt-lab-events-v2'
CASE_ALIAS = 'hunt-lab-case-events'
DATA_VIEW_ID = 'hunt-lab-case-events'
CASE_VIEW_PREFIX = 'hunt-lab-case-'
TIME_FIELD = '@timestamp'
CASE_ID = re.compile(r'[a-z0-9-]{3,64}')
TIMEOUT = 60


def case_view_id(case_id):
    return CASE_VIEW_PREFIX + case_id


def request(base, path, method='GET', data=None, kibana=False):
    headers = {'Content-Type': 'application/json'}
    if kibana:
        headers['kbn-xsrf'] = 'hunt-lab'
    body = json.dumps(data).encode() if data is not None else None
    with urlopen(Request(base.rstrip('/') + path, data=body, method=method, headers=headers), timeout=TIMEOUT) as response:
        return json.load(response)


def case_window(case):
    """Kibana's absolute time range for the case: from the inclusive start to the last millisecond before the end."""
    bounds = case['time_range_utc']
    start, end = (datetime.fromisoformat(bounds[key].replace('Z', '+00:00')).astimezone(timezone.utc)
                  for key in ('start_inclusive', 'end_exclusive'))
    if start >= end:
        raise ValueError('empty case window')
    stamp = '%Y-%m-%dT%H:%M:%S.%f'
    return start.strftime(stamp)[:-3] + 'Z', (end - timedelta(milliseconds=1)).strftime(stamp)[:-3] + 'Z'


def wait_for_kibana(kibana, seconds, call=request, sleep=time.sleep):
    deadline = time.monotonic() + seconds
    while True:
        try:
            call(kibana, '/api/status')
            return
        except (HTTPError, URLError, OSError, ValueError):
            if time.monotonic() >= deadline:
                raise
            sleep(5)


def configure(elastic, kibana, case, call=request):
    """Apply the case to Elasticsearch and Kibana; returns the case's event count behind the data view."""
    case_id = case['case_id']
    if not isinstance(case_id, str) or not CASE_ID.fullmatch(case_id):
        raise ValueError('invalid case_id')
    start, end = case_window(case)
    per_case_view = case_view_id(case_id)
    case_filter = {'term': {'event.dataset': case_id}}
    # Maintain both the active-case alias/data view and an idempotent per-case alias/data view on warm stacks.
    call(elastic, '/_aliases', 'POST', {'actions': [
        {'add': {'index': EVENT_STORE, 'alias': CASE_ALIAS, 'filter': case_filter}},
        {'add': {'index': EVENT_STORE, 'alias': per_case_view, 'filter': case_filter}},
    ]})
    call(kibana, '/api/data_views/data_view', 'POST', {'override': True, 'data_view': {
        'id': DATA_VIEW_ID, 'title': CASE_ALIAS, 'name': case_id + ' events', 'timeFieldName': TIME_FIELD}}, kibana=True)
    call(kibana, '/api/data_views/data_view', 'POST', {'override': True, 'data_view': {
        'id': per_case_view, 'title': per_case_view, 'name': case_id + ' events', 'timeFieldName': TIME_FIELD}},
        kibana=True)
    call(kibana, '/api/data_views/default', 'POST', {'data_view_id': DATA_VIEW_ID, 'force': True}, kibana=True)
    call(kibana, '/api/kibana/settings', 'POST', {'changes': {
        'timepicker:timeDefaults': json.dumps({'from': start, 'to': end}),
        'timepicker:quickRanges': json.dumps([{'from': start, 'to': end, 'display': 'Case window (%s)' % case_id}]),
    }}, kibana=True)
    view = call(kibana, '/api/data_views/data_view/' + DATA_VIEW_ID, kibana=True)['data_view']
    if view.get('title') != CASE_ALIAS or view.get('timeFieldName') != TIME_FIELD:
        raise ValueError('data view not applied')
    case_view = call(kibana, '/api/data_views/data_view/' + per_case_view, kibana=True)['data_view']
    if case_view.get('title') not in (per_case_view, CASE_ALIAS) or case_view.get('timeFieldName') != TIME_FIELD:
        raise ValueError('per-case data view not applied')
    return call(elastic, '/' + CASE_ALIAS + '/_count', 'POST', {'query': {'range': {TIME_FIELD: {
        'gte': start, 'lte': end}}}})['count']


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--elasticsearch', required=True)
    parser.add_argument('--kibana', required=True)
    parser.add_argument('--case', required=True)
    parser.add_argument('--wait', type=int, default=900, help='seconds to wait for Kibana to answer /api/status')
    args = parser.parse_args(argv)
    try:
        case = json.loads(Path(args.case).read_text(encoding='utf-8'))
        print('stage=waiting_for_kibana case_id=%s' % case['case_id'], flush=True)
        try:
            wait_for_kibana(args.kibana, args.wait)
        except (HTTPError, URLError, OSError, ValueError):
            print('stage=failed_kibana_start')
            return 2
        events = configure(args.elasticsearch, args.kibana, case)
        if not events:
            print('stage=failed_kibana_case_empty')
            return 2
        print('stage=kibana_case_ready case_id=%s events=%d data_view=%s' % (case['case_id'], events, DATA_VIEW_ID))
        return 0
    except HTTPError as exc:
        # Backend text can echo evidence values; report only the status.
        print('stage=failed_kibana_setup backend_status=%d' % exc.code)
        return 2
    except (URLError, OSError, ValueError, KeyError, TypeError):
        print('stage=failed_kibana_setup')
        return 2


if __name__ == '__main__':
    sys.exit(main())

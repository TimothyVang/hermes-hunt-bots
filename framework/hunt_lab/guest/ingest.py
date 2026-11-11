#!/usr/bin/env python3
"""Operator-only ECS JSONL ingest into the fixed lab indices. No credentials or network capture.

Events go to the `hunt-lab-events` alias (concrete index `hunt-lab-events-v2`),
intel to `hunt-lab-intel`. Documents are idempotent by `<case>:<id>` _id and sent
in bounded bulk chunks; documents of an earlier load of the same case that are
absent from this load are removed only after every chunk succeeded.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
import uuid
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

INDEX = 'hunt-lab-events'
EVENT_STORE = 'hunt-lab-events-v2'
INTEL_INDEX = 'hunt-lab-intel'
BATCH = 5000
TIMEOUT = 180
CASE_ID = re.compile(r'[a-z0-9-]{3,64}')
RUN_FIELD = 'hunt_lab_ingest'

KEYWORD = {'type': 'keyword', 'ignore_above': 1024}
LONG_KEYWORD = {'type': 'keyword', 'ignore_above': 8192, 'fields': {'text': {'type': 'text'}}}
IP = {'type': 'ip'}
INTEGER = {'type': 'integer'}
LONG = {'type': 'long'}


def _object(**properties):
    return {'properties': properties}


# Added after mapping version 2; put onto an existing store so a full script block stays searchable.
ADDED_EVENT_PROPERTIES = {
    'powershell': _object(file=_object(script_block_text={'type': 'text'})),
}
EVENT_MAPPING_VERSION = 3

EVENT_MAPPING = {
    'settings': {'number_of_shards': 1, 'number_of_replicas': 0},
    'mappings': {
        '_meta': {'hermes_mapping_version': EVENT_MAPPING_VERSION},
        'date_detection': False,
        'dynamic_templates': [{'strings_as_keywords': {'match_mapping_type': 'string', 'mapping': KEYWORD}}],
        'properties': {
            '@timestamp': {'type': 'date'},
            'message': {'type': 'text'},
            RUN_FIELD: KEYWORD,
            'event': _object(id=KEYWORD, dataset=KEYWORD, kind=KEYWORD, category=KEYWORD, type=KEYWORD,
                             action=KEYWORD, outcome=KEYWORD, code=KEYWORD, provider=KEYWORD),
            'host': _object(name=KEYWORD, ip=IP),
            'user': _object(name=KEYWORD, domain=KEYWORD),
            'process': _object(entity_id=KEYWORD, pid=LONG, name=KEYWORD, executable=KEYWORD,
                               command_line=LONG_KEYWORD,
                               parent=_object(entity_id=KEYWORD, pid=LONG, name=KEYWORD,
                                              executable=KEYWORD, command_line=LONG_KEYWORD)),
            'source': _object(ip=IP, port=INTEGER),
            'destination': _object(ip=IP, port=INTEGER),
            'network': _object(protocol=KEYWORD, transport=KEYWORD, direction=KEYWORD, type=KEYWORD,
                               bytes=LONG, packets=LONG),
            'dns': _object(question=_object(name=KEYWORD, type=KEYWORD),
                           answers=_object(data=KEYWORD, name=KEYWORD, type=KEYWORD)),
            'url': _object(domain=KEYWORD, full=LONG_KEYWORD, path=KEYWORD),
            'http': _object(request=_object(method=KEYWORD), response=_object(status_code=INTEGER)),
            'tls': _object(server_name=KEYWORD),
            'file': _object(path=LONG_KEYWORD, name=KEYWORD),
            'winlog': _object(channel=KEYWORD),
            'user_agent': _object(original=LONG_KEYWORD),
            **ADDED_EVENT_PROPERTIES,
        },
    },
}

INTEL_MAPPING = {
    'settings': {'number_of_shards': 1, 'number_of_replicas': 0,
                 'analysis': {'normalizer': {'hermes_lowercase': {'type': 'custom', 'filter': ['lowercase']}}}},
    'mappings': {
        '_meta': {'hermes_mapping_version': 1},
        'date_detection': False,
        'dynamic_templates': [{'strings_as_keywords': {'match_mapping_type': 'string', 'mapping': KEYWORD}}],
        'properties': {
            'case_id': KEYWORD,
            RUN_FIELD: KEYWORD,
            'indicator': _object(type=KEYWORD, value={'type': 'keyword', 'ignore_above': 1024,
                                                       'normalizer': 'hermes_lowercase'}),
            'threat': _object(feed=_object(name=KEYWORD)),
            'confidence': KEYWORD,
            'description': {'type': 'text'},
            'first_seen': {'type': 'date'},
        },
    },
}


class Rejected(ValueError):
    """Elasticsearch rejected documents; only counts and error types are reported."""

    def __init__(self, count, types):
        super().__init__('documents_rejected')
        self.count = count
        self.types = types


def request(base, path, method='GET', data=None, content_type='application/json'):
    body = data if isinstance(data, bytes) else (json.dumps(data).encode() if data is not None else None)
    with urlopen(Request(base.rstrip('/') + path, data=body, method=method,
                         headers={'Content-Type': content_type}), timeout=TIMEOUT) as response:
        return json.load(response)


def _create(base, index, body):
    try:
        request(base, '/' + index, 'PUT', body)
    except HTTPError as exc:
        error = json.load(exc)
        if exc.code != 400 or error.get('error', {}).get('type') != 'resource_already_exists_exception':
            raise


def ensure_event_index(base):
    """Serve events through the alias; migrate a legacy concrete index once."""
    try:
        current = request(base, '/' + INDEX)
    except HTTPError as exc:
        if exc.code != 404:
            raise
        current = {}
    if EVENT_STORE in current:
        return 'ready'
    _create(base, EVENT_STORE, EVENT_MAPPING)
    actions = [{'add': {'index': EVENT_STORE, 'alias': INDEX}}]
    state = 'created'
    if INDEX in current:
        # Pre-v2 guests stored events in a concrete index with a sparse mapping.
        result = request(base, '/_reindex?wait_for_completion=true&refresh=true', 'POST',
                         {'source': {'index': INDEX}, 'dest': {'index': EVENT_STORE}})
        if result.get('failures') or result.get('timed_out'):
            raise ValueError('Legacy event migration failed; legacy index left in place')
        actions.append({'remove_index': {'index': INDEX}})
        state = 'migrated'
    elif current:
        raise ValueError('Unexpected event index layout')
    request(base, '/_aliases', 'POST', {'actions': actions})
    return state


def add_event_fields(base):
    """Add later-version fields to an existing store; Elasticsearch refuses a type change (no silent remap)."""
    request(base, '/' + EVENT_STORE + '/_mapping', 'PUT',
            {'_meta': {'hermes_mapping_version': EVENT_MAPPING_VERSION}, 'properties': ADDED_EVENT_PROPERTIES})


def _rows(path, identity):
    """Yield (_id, document) for each nonempty line; validation is per line."""
    seen = set()
    with Path(path).open(encoding='utf-8') as source:
        for number, line in enumerate(source, 1):
            if not line.strip():
                continue
            row = json.loads(line)
            if not isinstance(row, dict):
                raise ValueError('Line %d is not a JSON object' % number)
            key = identity(row, number)
            if key in seen:
                raise ValueError('Duplicate document identity at input line %d' % number)
            seen.add(key)
            yield key, row


def _bulk(base, index, rows, run):
    sent = 0
    batch = []

    def flush():
        result = request(base, '/_bulk', 'POST', b''.join(batch), 'application/x-ndjson')
        if result.get('errors'):
            failed = [item for item in result.get('items', [])
                      if 'error' in next(iter(item.values()), {})]
            types = sorted({next(iter(item.values()))['error'].get('type', 'unknown') for item in failed})
            raise Rejected(len(failed), types)
        batch.clear()

    for key, row in rows:
        row[RUN_FIELD] = run
        batch.append((json.dumps({'index': {'_index': index, '_id': key}}) + '\n'
                      + json.dumps(row, separators=(',', ':')) + '\n').encode())
        sent += 1
        if len(batch) >= BATCH:
            flush()
    if batch:
        flush()
    return sent


def _replace(base, index, scope, run):
    """Delete this case's documents from earlier loads, then make the load visible."""
    request(base, '/' + index + '/_refresh', 'POST')
    result = request(base, '/' + index + '/_delete_by_query?refresh=true&conflicts=proceed', 'POST', {
        'query': {'bool': {'filter': [scope], 'must_not': [{'term': {RUN_FIELD: run}}]}}})
    if result.get('failures'):
        raise ValueError('Stale document removal failed')
    return result.get('deleted', 0)


def ingest(base, evidence, case_id=None):
    datasets = set()

    def identity(row, number):
        event = row.get('event')
        if not isinstance(event, dict):
            raise ValueError('Missing event object at input line %d' % number)
        key = event.get('id')
        if not isinstance(key, str) or not key or len(key) > 128:
            raise ValueError('Missing or invalid event.id at input line %d' % number)
        if not isinstance(row.get('@timestamp'), str) or not isinstance(event.get('dataset'), str):
            raise ValueError('Every event requires @timestamp and event.dataset')
        if case_id is not None and event['dataset'] != case_id:
            raise ValueError('event.dataset differs from the case at input line %d' % number)
        datasets.add(event['dataset'])
        return event['dataset'] + ':' + key

    if ensure_event_index(base) == 'ready':
        add_event_fields(base)
    run = uuid.uuid4().hex
    count = _bulk(base, INDEX, _rows(evidence, identity), run)
    if not count:
        raise ValueError('No events supplied')
    removed = 0
    if case_id is not None:
        removed = _replace(base, INDEX, {'term': {'event.dataset': case_id}}, run)
    else:
        request(base, '/' + INDEX + '/_refresh', 'POST')
    return {'indexed_events': count, 'index': INDEX, 'datasets': sorted(datasets), 'removed_stale': removed}


def ingest_intel(base, path, case_id):
    def identity(row, number):
        indicator = row.get('indicator')
        if (not isinstance(indicator, dict) or not isinstance(indicator.get('type'), str)
                or not isinstance(indicator.get('value'), str) or not indicator['value']
                or len(indicator['value']) > 1024):
            raise ValueError('Missing indicator.type/value at intel line %d' % number)
        if row.get('case_id', case_id) != case_id:
            raise ValueError('Intel case_id differs from the case at intel line %d' % number)
        row['case_id'] = case_id
        if isinstance(row.get('id'), str) and 0 < len(row['id']) <= 128:
            return case_id + ':' + row['id']
        feed = ((row.get('threat') or {}).get('feed') or {}).get('name', '')
        material = '\0'.join((indicator['type'], indicator['value'].lower(), str(feed)))
        return case_id + ':' + hashlib.sha256(material.encode()).hexdigest()[:32]

    _create(base, INTEL_INDEX, INTEL_MAPPING)
    run = uuid.uuid4().hex
    count = _bulk(base, INTEL_INDEX, _rows(path, identity), run)
    removed = _replace(base, INTEL_INDEX, {'term': {'case_id': case_id}}, run)
    return {'indexed_intel': count, 'index': INTEL_INDEX, 'removed_stale': removed}


def load_case_id(path):
    case_id = json.loads(Path(path).read_text(encoding='utf-8')).get('case_id')
    if not isinstance(case_id, str) or not CASE_ID.fullmatch(case_id):
        raise ValueError('case.json case_id must match [a-z0-9-]{3,64}')
    return case_id


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--elasticsearch', required=True)
    parser.add_argument('--events')
    parser.add_argument('--intel')
    parser.add_argument('--case', help='case.json; scopes events, intel and stale removal to its case_id')
    args = parser.parse_args(argv)
    try:
        if not args.events and not args.intel:
            raise ValueError('Nothing to ingest')
        case_id = load_case_id(args.case) if args.case else None
        if args.intel and case_id is None:
            raise ValueError('Intel ingest requires --case')
        result = {}
        if args.events:
            result.update(ingest(args.elasticsearch, args.events, case_id))
        if args.intel:
            result.update(ingest_intel(args.elasticsearch, args.intel, case_id))
        print(json.dumps(result))
        return 0
    except HTTPError as exc:
        # The backend's raw reason can echo evidence values; never log that body.
        print(json.dumps({'error': 'ingest_failed', 'reason': 'backend_http_error',
                          'backend_status': exc.code}))
        return 2
    except URLError:
        print(json.dumps({'error': 'ingest_failed', 'reason': 'backend_unreachable'}))
        return 2
    except Rejected as exc:
        print(json.dumps({'error': 'ingest_failed', 'reason': 'documents_rejected',
                          'rejected': exc.count, 'error_types': exc.types}))
        return 2
    except (OSError, ValueError, KeyError):
        print(json.dumps({'error': 'ingest_failed', 'reason': 'invalid_input_or_backend_response'}))
        return 2


if __name__ == '__main__':
    sys.exit(main())

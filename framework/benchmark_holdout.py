"""Holdout retirement registry: an exposed holdout never returns to selection.

Plan section 8: any configuration change informed by holdout results retires
that holdout. Scoring a holdout experiment must therefore be followed by
``retire``. The registry is a separate evaluator-side JSON file, never part of
the store, and every retirement writes a NEW registry file; nothing is
overwritten. A recorded name is an operator attestation, not authentication.

Registry shape (an empty registry is ``{"schema_version": 1, "retired": []}``)::

    {"schema_version": 1,
     "retired": [{"family_id": ..., "revision": 1,
                  "reason": "retired_by_experiment",
                  "retired_by_experiment": ..., "scenario_ids": [...],
                  "by": ..., "note": ..., "retired_utc": "...Z"}]}
"""
import datetime as dt
import os
from pathlib import Path

from benchmark_contracts import (
    BenchmarkError, _fields, _id, _integer, _no_alias, _text, _version, canonical_bytes,
    confined_file, decode_json, digest_bytes, parse_utc,
)


REASON = 'retired_by_experiment'
_ENTRY_FIELDS = {'family_id', 'revision', 'reason', 'retired_by_experiment', 'scenario_ids',
                 'by', 'note', 'retired_utc'}


def _fail(code, field):
    raise BenchmarkError(code, field) from None


def validate_registry(value):
    _fields(value, {'schema_version', 'retired'}, 'holdout_registry')
    _version(value['schema_version'], 'holdout_registry.schema_version')
    if type(value['retired']) is not list:
        _fail('invalid_array', 'holdout_registry.retired')
    seen = set()
    for entry in value['retired']:
        field = 'holdout_registry.retired'
        _fields(entry, _ENTRY_FIELDS, field)
        _id(entry['family_id'], field + '.family_id')
        _integer(entry['revision'], field + '.revision', 1)
        if entry['reason'] != REASON:
            _fail('invalid_choice', field + '.reason')
        _id(entry['retired_by_experiment'], field + '.retired_by_experiment')
        ids = entry['scenario_ids']
        if type(ids) is not list or not ids or ids != sorted(set(ids)):
            _fail('invalid_array', field + '.scenario_ids')
        for scenario_id in ids:
            _id(scenario_id, field + '.scenario_ids')
        _text(entry['by'], field + '.by')
        _text(entry['note'], field + '.note')
        parse_utc(entry['retired_utc'], field + '.retired_utc')
        key = (entry['family_id'], entry['revision'])
        if key in seen:
            _fail('duplicate_item', field)
        seen.add(key)
    return value


def load_registry(path):
    path = Path(path)
    try:
        content = confined_file(path.parent, path.name, 'holdout_registry').read_bytes()
    except OSError:
        _fail('file_unavailable', 'holdout_registry')
    return validate_registry(decode_json(content))


def retired_keys(registry):
    """Map (family_id, scenario revision) to its retirement entry."""
    return {(entry['family_id'], entry['revision']): entry for entry in registry['retired']}


def check_unretired(registry, scenarios):
    """Refuse any holdout scenario whose family revision was already exposed."""
    retired = retired_keys(validate_registry(registry))
    for scenario in scenarios:
        if (scenario['split'] == 'holdout'
                and (scenario['family_id'], scenario['revision']) in retired):
            _fail('holdout_retired', 'scenario.family_id')


def write_new_file(path, data, field):
    """Create one new regular file; never overwrite, follow or replace an alias."""
    path = Path(os.path.abspath(os.fspath(path)))
    if path.exists() or path.is_symlink():
        _fail('already_exists', field)
    try:
        _no_alias(path.parent, field)
        with path.open('xb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except FileExistsError:
        _fail('already_exists', field)
    except OSError:
        _fail('file_unavailable', field)
    return path


def retire(registry_path, experiment_snapshot, by, note, output_path):
    """Write a NEW registry retiring every holdout family revision of one experiment."""
    from benchmark_adjudication import _human
    registry = load_registry(registry_path)
    frozen = experiment_snapshot['experiment']
    experiment_id = frozen['experiment']['experiment_id']
    _human(by, note, frozen)
    source = Path(os.path.abspath(os.fspath(registry_path)))
    if Path(os.path.abspath(os.fspath(output_path))) == source:
        _fail('already_exists', 'holdout_registry.output')
    groups = {}
    for case in frozen['cases']:
        scenario = case['scenario']
        if scenario['split'] == 'holdout':
            groups.setdefault((scenario['family_id'], scenario['revision']), set()).add(scenario['scenario_id'])
    if not groups:
        _fail('no_holdout_scenarios', 'experiment.scenario_refs')
    existing = retired_keys(registry)
    stamp = dt.datetime.now(dt.timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%fZ')
    added = [{'family_id': family_id, 'revision': revision, 'reason': REASON,
              'retired_by_experiment': experiment_id, 'scenario_ids': sorted(ids),
              'by': by.strip(), 'note': note.strip(), 'retired_utc': stamp}
             for (family_id, revision), ids in sorted(groups.items()) if (family_id, revision) not in existing]
    if not added:
        _fail('already_retired', 'holdout_registry')
    document = validate_registry({'schema_version': 1, 'retired': sorted(
        registry['retired'] + added, key=lambda entry: (entry['family_id'], entry['revision']))})
    data = canonical_bytes(document)
    path = write_new_file(output_path, data, 'holdout_registry.output')
    return {'status': 'retired', 'experiment_id': experiment_id,
            'retired': [{'family_id': entry['family_id'], 'revision': entry['revision']} for entry in added],
            'already_retired': sorted([family_id, revision] for family_id, revision in groups
                                      if (family_id, revision) in existing),
            'registry_sha256': digest_bytes(data), 'output': str(path)}

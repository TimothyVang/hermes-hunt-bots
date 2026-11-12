"""Finite, explicitly authorized lab control; never called by a hunting model.

Raw exports and driver receipts are private evaluator data. A completed collection
is only eligible for human release, never itself a release or live-coverage claim.
"""
import hashlib
import importlib
import ipaddress
import math
import os
import re
import stat
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

from benchmark_contracts import (
    BenchmarkError, _array, _digest, _enum, _fields, _id, _integer,
    _no_alias, _number, _positive, _strings, _text, parse_utc, _version,
    _window, canonical_bytes, campaign_manifest_digest, confined_file,
    decode_json, digest_bytes, validate_public_bundle, validate_state_root,
)
from benchmark_store import BenchmarkStore, FAILURES, _unpack

KIT_FILES = ('Invoke-BenchmarkAction.ps1', 'collector-fields.json',
             'linux_worker.py', 'recipes.json')
RECIPES = {'windows-discovery-v1': 'windows', 'ad-discovery-v1': 'windows',
           'internal-dns-http-v1': 'windows', 'linux-discovery-v1': 'linux',
           'aws-test-trail-stop-v1': 'aws'}
PHASES = ('run', 'stop', 'collect', 'cleanup')
MAX_METADATA_BYTES = 1024 * 1024
# Every dispatching AWS step must carry a bound entry, even when it creates nothing.
AWS_COST_STEPS = (('preflight', 'identity'), ('preflight', 'collector'), ('run', 'warmup'),
                  ('run', 'detonate'), ('collect', 'collector'), ('cleanup', 'cleanup'))
COST_ENFORCEMENT = 'local_precheck_not_billing_enforcement'
# Enrolled identity fields that name one machine/account across campaigns.
IMMUTABLE_IDENTITY = ('vm_id', 'machine_guid', 'machine_id', 'account_id')


def _fail(code, field):
    raise BenchmarkError(code, field)


def _now():
    return datetime.now(timezone.utc).isoformat()


def _hash(value):
    return digest_bytes(canonical_bytes(value))


def _driver(kind):
    return importlib.import_module('benchmark_' + kind)


def _steps(selected, manifest, phase, context):
    steps = selected.phase_steps(manifest, phase, context)
    _strings(steps, 'driver.phase_steps', validator=_id, nonempty=True)
    if len(steps) > 8:
        _fail('budget_exceeded', 'driver.phase_steps')
    return steps


def _absolute(value, field):
    _text(value, field)
    path = Path(value)
    if not path.is_absolute() or '..' in path.parts:
        _fail('unsafe_path', field)
    return path


def _read(path, limit=MAX_METADATA_BYTES):
    path = Path(path)
    path = confined_file(path.parent, path.name)
    try:
        with path.open('rb') as stream:
            data = stream.read(limit + 1)
        if len(data) > limit:
            _fail('output_limit', 'campaign.file')
        return data
    except OSError:
        _fail('file_unreadable', 'campaign.file')


def _json(path, limit=MAX_METADATA_BYTES):
    return decode_json(_read(path, limit))


def _descriptor(value, field):
    _fields(value, {'path', 'sha256', 'version'}, field)
    _absolute(value['path'], field + '.path')
    _digest(value['sha256'], field + '.sha256')
    _text(value['version'], field + '.version')
    if Path(value['path']).suffix.lower() in ('.cmd', '.bat'):
        _fail('unsupported_executable', field)


def validate_manifest(manifest):
    """Pure validation: no filesystem, process, credential, or network probes."""
    _fields(manifest, {'schema_version', 'campaign_id', 'recipe_id', 'range_kit_sha256',
                       'targets', 'executor', 'collectors', 'limits', 'authorization'}, 'manifest')
    _version(manifest['schema_version'], 'manifest.schema_version')
    _id(manifest['campaign_id'], 'manifest.campaign_id')
    _enum(manifest['recipe_id'], RECIPES, 'manifest.recipe_id')
    _digest(manifest['range_kit_sha256'], 'manifest.range_kit_sha256')
    _array(manifest['targets'], 'manifest.targets', nonempty=True)
    targets = {}
    displays = set()
    for target in manifest['targets']:
        _fields(target, {'target_id', 'display_id', 'kind', 'identity', 'network', 'clock'}, 'target')
        _id(target['target_id'], 'target.target_id')
        _id(target['display_id'], 'target.display_id')
        if target['target_id'] in targets or target['display_id'] in displays:
            _fail('duplicate_identifier', 'target')
        targets[target['target_id']] = target
        displays.add(target['display_id'])
        _enum(target['kind'], ('windows', 'linux', 'aws'), 'target.kind')
        if type(target['identity']) is not dict:
            _fail('invalid_object', 'target.identity')
        network = target['network']
        _fields(network, {'switch_id', 'isolation_review'}, 'target.network')
        _text(network['switch_id'], 'target.network.switch_id')
        review = network['isolation_review']
        _fields(review, {'by', 'checked_utc', 'expires_utc', 'evidence_sha256', 'owned_test_endpoints'}, 'isolation_review')
        _text(review['by'], 'isolation_review.by')
        checked = parse_utc(review['checked_utc'], 'isolation_review.checked_utc')
        if parse_utc(review['expires_utc'], 'isolation_review.expires_utc') <= checked:
            _fail('invalid_window', 'isolation_review')
        _digest(review['evidence_sha256'], 'isolation_review.evidence_sha256')
        _strings(review['owned_test_endpoints'], 'isolation_review.owned_test_endpoints', nonempty=True)
        for endpoint in review['owned_test_endpoints']:
            try:
                ipaddress.ip_address(endpoint)
            except ValueError:
                _fail('invalid_endpoint', 'isolation_review.owned_test_endpoints')
        clock = target['clock']
        _fields(clock, {'offset_seconds', 'uncertainty_seconds', 'checked_utc'}, 'target.clock')
        _number(clock['offset_seconds'], 'clock.offset_seconds')
        _number(clock['uncertainty_seconds'], 'clock.uncertainty_seconds', minimum=0)
        parse_utc(clock['checked_utc'], 'clock.checked_utc')
    executor = manifest['executor']
    _fields(executor, {'transport', 'executable', 'script_sha256', 'environment_names', 'config'}, 'executor')
    _enum(executor['transport'], ('powershell_direct', 'ssh_worker', 'aws_cli'), 'executor.transport')
    _descriptor(executor['executable'], 'executor.executable')
    if executor['script_sha256'] is not None:
        _digest(executor['script_sha256'], 'executor.script_sha256')
    _strings(executor['environment_names'], 'executor.environment_names')
    for name in executor['environment_names']:
        if not re.fullmatch(r'[A-Z][A-Z0-9_]{0,127}', name):
            _fail('invalid_identifier', 'executor.environment_names')
    limits = manifest['limits']
    _fields(limits, {'max_phase_seconds', 'max_campaign_seconds', 'max_export_bytes',
                    'max_cloud_cost_usd', 'latest_cleanup_utc'}, 'limits')
    for name in ('max_phase_seconds', 'max_campaign_seconds', 'max_export_bytes'):
        _integer(limits[name], 'limits.' + name, minimum=1)
    if limits['max_phase_seconds'] > limits['max_campaign_seconds']:
        _fail('budget_exceeded', 'limits.max_phase_seconds')
    if RECIPES[manifest['recipe_id']] == 'aws':
        _positive(limits['max_cloud_cost_usd'], 'limits.max_cloud_cost_usd')
    elif limits['max_cloud_cost_usd'] is not None:
        _fail('scope_mismatch', 'limits.max_cloud_cost_usd')
    parse_utc(limits['latest_cleanup_utc'], 'limits.latest_cleanup_utc')
    _array(manifest['collectors'], 'collectors', nonempty=True)
    seen = set()
    for collector in manifest['collectors']:
        _fields(collector, {'source_id', 'kind', 'target_id', 'export_root', 'bucket', 'prefix',
                           'window_utc', 'sensor_version', 'config_version', 'max_bytes',
                           'max_seconds', 'watermark_utc', 'config'}, 'collector')
        _id(collector['source_id'], 'collector.source_id')
        if collector['source_id'] in seen:
            _fail('duplicate_identifier', 'collector.source_id')
        seen.add(collector['source_id'])
        _enum(collector['kind'], ('windows', 'linux', 'zeek', 'aws'), 'collector.kind')
        if collector['target_id'] not in targets:
            _fail('unknown_reference', 'collector.target_id')
        if collector['export_root'] is not None:
            _absolute(collector['export_root'], 'collector.export_root')
        for key in ('sensor_version', 'config_version'):
            _text(collector[key], 'collector.' + key)
        _window(collector['window_utc'], 'collector.window_utc')
        parse_utc(collector['watermark_utc'], 'collector.watermark_utc')
        for key in ('max_bytes', 'max_seconds'):
            _integer(collector[key], 'collector.' + key, minimum=1)
        if collector['max_seconds'] > limits['max_phase_seconds']:
            _fail('budget_exceeded', 'collector')
        if collector['kind'] == 'zeek':
            _validate_zeek(manifest, collector)
        else:
            _driver(collector['kind']).validate_collector(manifest, collector)
    # Each source keeps one exercise and one final (cleanup) snapshot; both count.
    if sum(2 * collector['max_bytes'] for collector in manifest['collectors']) > limits['max_export_bytes']:
        _fail('budget_exceeded', 'collector.max_bytes')
    # A network sensor is its own enrolled asset with its own clock, never an assessed endpoint.
    sensors = {item['target_id'] for item in manifest['collectors'] if item['kind'] == 'zeek'}
    if sensors & {item['target_id'] for item in manifest['collectors'] if item['kind'] != 'zeek'}:
        _fail('scope_mismatch', 'collector.target_id')
    _driver(RECIPES[manifest['recipe_id']]).validate_configuration(manifest)
    authorization = manifest['authorization']
    _fields(authorization, {'by', 'note', 'expires_utc', 'manifest_sha256', 'allowed_phases'}, 'authorization')
    _strings(authorization['allowed_phases'], 'authorization.allowed_phases')
    for phase in authorization['allowed_phases']:
        _enum(phase, PHASES, 'authorization.allowed_phases')
    draft = all(authorization[key] is None for key in ('by', 'note', 'expires_utc', 'manifest_sha256'))
    if draft:
        if authorization['allowed_phases']:
            _fail('scope_mismatch', 'authorization')
    else:
        for key in ('by', 'note'):
            _text(authorization[key], 'authorization.' + key)
        parse_utc(authorization['expires_utc'], 'authorization.expires_utc')
        _digest(authorization['manifest_sha256'], 'authorization.manifest_sha256')
        if authorization['manifest_sha256'] != campaign_manifest_digest(manifest):
            _fail('digest_mismatch', 'authorization.manifest_sha256')
    return manifest


def plan(manifest_path):
    manifest = validate_manifest(_json(manifest_path))
    return {'campaign_id': manifest['campaign_id'], 'manifest_sha256': campaign_manifest_digest(manifest),
            'recipe_id': manifest['recipe_id'], 'status': 'draft', 'execution': 'not_dispatched',
            'required_gates': ['allow_lab_read', 'preflight', 'explicit_authorization', 'allow_lab_mutation'],
            'live_verified': False}


def _kit(path, expected):
    root = _absolute(str(path), 'range_kit')
    _no_alias(root, 'range_kit')
    hashes = {name: digest_bytes(_read(confined_file(root, name))) for name in KIT_FILES}
    if _hash(hashes) != expected:
        _fail('digest_mismatch', 'range_kit_sha256')
    return hashes


def _usd(value):
    """Round a bound up to a millionth of a dollar; never down."""
    return math.ceil(value * 1000000) / 1000000


def _cost_model(model):
    _fields(model, {'bound_version', 'priced_utc', 'currency', 'enforcement', 'prices', 'phases'}, 'cloud_cost_bound')
    _id(model['bound_version'], 'cloud_cost_bound.bound_version')
    parse_utc(model['priced_utc'], 'cloud_cost_bound.priced_utc')
    if model['currency'] != 'USD' or model['enforcement'] != COST_ENFORCEMENT:
        _fail('scope_mismatch', 'cloud_cost_bound')
    _array(model['prices'], 'cloud_cost_bound.prices', nonempty=True)
    prices = {}
    for price in model['prices']:
        _fields(price, {'price_id', 'unit', 'usd', 'per_quantity', 'source_url', 'source_text', 'unknown_reason'}, 'cloud_cost_bound.price')
        _id(price['price_id'], 'cloud_cost_bound.price.price_id')
        _id(price['unit'], 'cloud_cost_bound.price.unit')
        if price['price_id'] in prices:
            _fail('duplicate_identifier', 'cloud_cost_bound.price')
        # Only AWS's own pricing pages are an acceptable citation.
        if type(price['source_url']) is not str or not re.fullmatch(r'https://aws\.amazon\.com/[a-z0-9/-]+/', price['source_url']):
            _fail('invalid_source', 'cloud_cost_bound.price.source_url')
        if price['usd'] is None:
            if price['per_quantity'] is not None or price['source_text'] is not None:
                _fail('scope_mismatch', 'cloud_cost_bound.price')
            _id(price['unknown_reason'], 'cloud_cost_bound.price.unknown_reason')
        else:
            _number(price['usd'], 'cloud_cost_bound.price.usd', minimum=0)
            _integer(price['per_quantity'], 'cloud_cost_bound.price.per_quantity', minimum=1)
            _text(price['source_text'], 'cloud_cost_bound.price.source_text')
            if price['unknown_reason'] is not None:
                _fail('scope_mismatch', 'cloud_cost_bound.price')
        prices[price['price_id']] = price
    _array(model['phases'], 'cloud_cost_bound.phases')
    seen, referenced = set(), set()
    for phase in model['phases']:
        _fields(phase, {'phase', 'step_id', 'resources_created', 'charges'}, 'cloud_cost_bound.phase')
        key = (phase['phase'], phase['step_id'])
        if key not in AWS_COST_STEPS or key in seen:
            _fail('invalid_choice', 'cloud_cost_bound.phase')
        seen.add(key)
        _array(phase['resources_created'], 'cloud_cost_bound.resources_created')
        for resource in phase['resources_created']:
            _fields(resource, {'address', 'max_lifetime'}, 'cloud_cost_bound.resource')
            if type(resource['address']) is not str or not re.fullmatch(r'aws_[a-z0-9_]+\.[a-z0-9_]+', resource['address']):
                _fail('invalid_identifier', 'cloud_cost_bound.resource.address')
            _enum(resource['max_lifetime'], ('until_latest_cleanup_utc',), 'cloud_cost_bound.resource.max_lifetime')
        _array(phase['charges'], 'cloud_cost_bound.charges')
        for charge in phase['charges']:
            _fields(charge, {'price_id', 'basis', 'max_quantity', 'note'}, 'cloud_cost_bound.charge')
            if charge['price_id'] not in prices:
                _fail('unknown_reference', 'cloud_cost_bound.charge.price_id')
            referenced.add(charge['price_id'])
            _enum(charge['basis'], ('per_campaign', 'per_hour_until_latest_cleanup'), 'cloud_cost_bound.charge.basis')
            _number(charge['max_quantity'], 'cloud_cost_bound.charge.max_quantity', minimum=0, nullable=True)
            _text(charge['note'], 'cloud_cost_bound.charge.note')
    if seen != set(AWS_COST_STEPS):
        _fail('incomplete_cost_bound', 'cloud_cost_bound.phases')
    if referenced != set(prices):
        _fail('unknown_reference', 'cloud_cost_bound.prices')
    return prices


def _cloud_cost_bound(kit, manifest, computed_utc):
    """Worst-case USD bound from the pinned kit's dated, cited price snapshot.

    This is a local pre-dispatch check against `max_cloud_cost_usd`. It cannot
    cap, stop or observe AWS billing. An uncited price or a quantity without a
    ceiling leaves the bound unknown, and an unknown bound blocks.
    """
    data = _read(confined_file(kit, 'recipes.json'))
    recipes = decode_json(data)
    _fields(recipes, {'schema_version', 'kit_version', 'recipes'}, 'recipes')
    _version(recipes['schema_version'], 'recipes.schema_version')
    recipe = recipes['recipes'].get(manifest['recipe_id']) if type(recipes['recipes']) is dict else None
    if type(recipe) is not dict or 'cloud_cost_bound' not in recipe:
        _fail('missing_prerequisite', 'recipes.cloud_cost_bound')
    model = recipe['cloud_cost_bound']
    prices = _cost_model(model)
    computed = parse_utc(computed_utc, 'cloud_cost_bound.computed_utc')
    if parse_utc(model['priced_utc'], 'cloud_cost_bound.priced_utc') > computed:
        _fail('invalid_timestamp', 'cloud_cost_bound.priced_utc')
    seconds = (parse_utc(manifest['limits']['latest_cleanup_utc'], 'limits.latest_cleanup_utc') - computed).total_seconds()
    if seconds <= 0:
        _fail('cleanup_deadline', 'limits.latest_cleanup_utc')
    hours = math.ceil(seconds / 3600)
    unknown, phases, total = set(), [], 0.0
    for phase in model['phases']:
        amount, known = 0.0, True
        for charge in phase['charges']:
            price = prices[charge['price_id']]
            if price['usd'] is None:
                unknown.add(price['price_id'] + ':price_unknown')
            if charge['max_quantity'] is None:
                unknown.add('%s.%s.%s:quantity_unknown' % (phase['phase'], phase['step_id'], price['price_id']))
            if price['usd'] is None or charge['max_quantity'] is None:
                known = False
                continue
            value = price['usd'] * charge['max_quantity'] / price['per_quantity']
            amount += value * hours if charge['basis'] == 'per_hour_until_latest_cleanup' else value
        total += amount
        phases.append({'phase': phase['phase'], 'step_id': phase['step_id'],
                       'resources_created': [item['address'] for item in phase['resources_created']],
                       'usd': _usd(amount) if known else None})
    return {'bound_version': model['bound_version'], 'priced_utc': model['priced_utc'],
            'computed_utc': computed_utc, 'recipes_sha256': digest_bytes(data), 'lifetime_hours': hours,
            'status': 'unknown' if unknown else 'known', 'usd': None if unknown else _usd(total),
            'limit_usd': manifest['limits']['max_cloud_cost_usd'], 'unknown': sorted(unknown),
            'phases': phases, 'enforcement': COST_ENFORCEMENT}


def _check_cloud_cost(bound):
    if bound['status'] != 'known':
        _fail('cloud_cost_bound_unknown', 'recipes.cloud_cost_bound')
    if bound['limit_usd'] < bound['usd']:
        _fail('budget_exceeded', 'limits.max_cloud_cost_usd')


def _target_tokens(manifest):
    tokens = set()
    for target in manifest['targets']:
        identity = target['identity']
        keys = [key for key in IMMUTABLE_IDENTITY if key in identity]
        tokens.update((target['kind'], key, identity[key]) for key in keys)
        if not keys:
            tokens.add((target['kind'], 'identity', _hash(identity)))
    return tokens


def _quarantined(store, manifest, exclude=None):
    """Other campaigns whose failed/unknown cleanup quarantines any of these targets."""
    with store.connection() as db:
        rows = [_unpack(row) for row in db.execute(
            "SELECT * FROM campaign_state WHERE cleanup_status IN ('failed','unknown')")]
    mine = _target_tokens(manifest)
    return sorted(row['campaign_id'] for row in rows
                  if row['campaign_id'] != exclude and _target_tokens(row['manifest']) & mine)


def _pinned_executable(value, deadline, pins):
    """Hash a pinned binary once per step; later checks compare file identity only.

    Hard links are accepted for pinned executables (st_nlink > 1): inbox Windows
    binaries such as System32 powershell.exe/ssh.exe are WinSxS hard links. The
    SHA-256 pin binds the bytes, and every path component is still alias-checked.
    """
    path = _absolute(value['path'], 'executor.path')
    _no_alias(path, 'executor.path')
    try:
        info = path.stat()
    except OSError:
        _fail('file_not_found', 'executor.path')
    if not stat.S_ISREG(info.st_mode):
        _fail('not_regular_file', 'executor.path')
    identity = (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, value['sha256'])
    if pins.get(str(path)) == identity:
        return
    if info.st_size > 512 * 1024 * 1024:
        _fail('output_limit', 'executor.path')
    hasher = hashlib.sha256()
    try:
        with path.open('rb') as stream:
            while True:
                if time.monotonic() >= deadline:
                    _fail('timeout', 'executor.sha256')
                block = stream.read(1024 * 1024)
                if not block:
                    break
                hasher.update(block)
        after = path.stat()
    except OSError:
        _fail('file_unreadable', 'executor.path')
    if hasher.hexdigest() != value['sha256'] or (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) != identity[:4]:
        _fail('digest_mismatch', 'executor.sha256')
    pins[str(path)] = identity


def _check_descriptors(value, deadline, pins):
    if type(value) is dict:
        if 'path' in value and 'sha256' in value:
            _pinned_executable(value, deadline, pins)
        for key, child in value.items():
            # EVTX copy pins are guest-side paths, checked by the fixed worker.
            if key != 'evtx_files':
                _check_descriptors(child, deadline, pins)
    elif type(value) is list:
        for child in value:
            _check_descriptors(child, deadline, pins)


def _private_root(store, campaign_id, create=False):
    _id(campaign_id, 'campaign_id')
    root = store.root / 'campaigns' / campaign_id
    _no_alias(root, 'campaign.private_root')
    if create:
        root.mkdir(parents=True, exist_ok=False, mode=0o700)
        (root / 'raw').mkdir(mode=0o700)
    return root


def _persist(root, value):
    return _persist_bytes(root, canonical_bytes(value), '.json')


def _persist_bytes(root, data, suffix='.bin'):
    sha = digest_bytes(data)
    path = root / 'raw' / (sha + suffix)
    _no_alias(path, 'campaign.raw')
    try:
        fd = os.open(str(path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        if _read(path, len(data)) != data:
            _fail('digest_mismatch', 'campaign.raw')
        return sha
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except OSError:
        _fail('state_unavailable', 'campaign.raw')
    return sha


@contextmanager
def _lock(root):
    """An OS-released local lock; an interrupted dispatch remains reserved in SQL."""
    path = root / 'controller.lock'
    _no_alias(path, 'campaign.lock')
    fd = os.open(str(path), os.O_CREAT | os.O_RDWR, 0o600)
    locked = False
    try:
        if os.name == 'nt':
            import msvcrt
            if os.fstat(fd).st_size == 0:
                os.write(fd, b'0')
            os.lseek(fd, 0, os.SEEK_SET)
            try:
                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            except OSError:
                _fail('campaign_busy', 'campaign')
        else:
            import fcntl
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                _fail('campaign_busy', 'campaign')
        locked = True
        yield
    finally:
        if locked:
            if os.name == 'nt':
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def _rows(store, campaign_id, table):
    if table not in ('campaigns', 'events', 'approvals'):
        _fail('invalid_choice', 'campaign.table')
    with store.connection() as db:
        order = 'seq' if table == 'events' else 'rowid'
        return [_unpack(row) for row in db.execute(
            'SELECT * FROM ' + table + ' WHERE campaign_id=? ORDER BY ' + order, (campaign_id,))]


def _metadata(store, state):
    matches = [event['payload'] for event in _rows(store, state['campaign_id'], 'events')
               if event['payload'].get('record_type') == 'controller_configuration']
    if len(matches) != 1:
        _fail('corrupt_state', 'campaign.configuration')
    return matches[0]


def _change(store, state, **updates):
    updated = dict(state, **updates, updated_utc=_now())
    return store.update_campaign(state['campaign_id'], updated, state['status'], state['cleanup_status'])


def _authority(store, state, phase):
    candidates = [item for item in _rows(store, state['campaign_id'], 'approvals')
                  if item['kind'] == 'authorization' and phase in item['phases']
                  and item['manifest_sha256'] == state['manifest_sha256']]
    if not candidates:
        _fail('authorization_required', 'campaign.authorization')
    for item in reversed(candidates):
        if parse_utc(item['expires_utc'], 'authorization.expires_utc') > datetime.now(timezone.utc):
            with store.connection() as db:
                authority = store._authorization(db, item['authorization_sha256'])
            bound = _metadata(store, state)['cloud_cost_bound']
            if bound is not None and not any(
                    event['payload'].get('record_type') == 'cloud_cost_bound'
                    and event['payload']['authorization_sha256'] == authority['authorization_sha256']
                    and event['payload']['cloud_cost_bound'] == bound
                    for event in _rows(store, state['campaign_id'], 'events')):
                _fail('authorization_required', 'campaign.authorization.cloud_cost_bound')
            return authority
    _fail('authorization_expired', 'campaign.authorization')


def _authorize(store, state, by, note, expires, phases):
    """Record a decision; an AWS decision also records the cost bound it accepted."""
    _text(by, 'authorization.by')
    _text(note, 'authorization.note')
    parse_utc(expires, 'authorization.expires_utc')
    bound = _metadata(store, state)['cloud_cost_bound']
    spec = dict(approval_id='auth-' + uuid.uuid4().hex,
                experiment_id=state['experiment_id'], trial_id=None, campaign_id=state['campaign_id'],
                by=by, note=note, created_utc=_now(), expires_utc=expires, evidence_sha256=None,
                model_sha256s=[], manifest_sha256=state['manifest_sha256'], phases=phases)
    with store.connection(immediate=True) as db:
        sha = store._record_authorization(db, spec)
        if bound is not None:
            store.event('authorization_recorded', 'campaign-controller',
                        {'record_type': 'cloud_cost_bound', 'authorization_sha256': sha,
                         'cloud_cost_bound': bound},
                        experiment_id=state['experiment_id'], campaign_id=state['campaign_id'], db=db)
    return sha


def _result(store, state, row):
    sha = row['receipt']['evidence_sha256']
    data = _read(_private_root(store, state['campaign_id']) / 'raw' / (sha + '.json'),
                 state['manifest']['limits']['max_export_bytes'] + MAX_METADATA_BYTES)
    if digest_bytes(data) != sha:
        _fail('digest_mismatch', 'campaign.evidence')
    return decode_json(data)


def _context(store, state):
    metadata = _metadata(store, state)
    context = {'private_root': str(_private_root(store, state['campaign_id'])),
               'aws_correlation_id': metadata['aws_correlation_id'],
               'campaign_started_utc': state['created_utc'],
               'collection_generation': 'cleanup' if state['cleanup_status'] == 'succeeded' else 'exercise'}
    for row in _rows(store, state['campaign_id'], 'campaigns'):
        if row['status'] in ('completed', 'failed') and row['receipt'] is not None:
            result = _result(store, state, row)
            if row['status'] == 'completed' or result.get('raw_exports'):
                context.update(result.get('context_updates', {}))
    context['reconciled_steps'] = [
        {'phase': event['payload']['phase'], 'step_id': event['payload']['step_id'],
         'outcome': event['payload']['outcome'], 'observation': event['payload']['evidence']}
        for event in _rows(store, state['campaign_id'], 'events')
        if event['kind'] == 'reconciliation_recorded'
        and {'phase', 'step_id', 'outcome', 'evidence'} <= set(event['payload'])]
    return context


def _guard(store, state, phase, collector=None, pins=None):
    manifest = state['manifest']
    validate_manifest(manifest)
    if phase == 'run' and state['status'] != 'running':
        _fail('state_conflict', 'campaign.status')
    if phase != 'stop' and state['status'] == 'unknown':
        _fail('previous_dispatch_unknown', 'campaign.status')
    metadata = _metadata(store, state)
    _kit(metadata['range_kit'], manifest['range_kit_sha256'])
    bound = metadata['cloud_cost_bound']
    if (bound is None) != (RECIPES[manifest['recipe_id']] != 'aws'):
        _fail('corrupt_state', 'campaign.cloud_cost_bound')
    if bound is not None:
        if _cloud_cost_bound(metadata['range_kit'], manifest, bound['computed_utc']) != bound:
            _fail('digest_mismatch', 'campaign.cloud_cost_bound')
        _check_cloud_cost(bound)
    _check_descriptors(collector['config'] if collector else manifest['executor'],
                       time.monotonic() + manifest['limits']['max_phase_seconds'],
                       {} if pins is None else pins)
    now = datetime.now(timezone.utc)
    # Freshness gates new exercises only; collection and cleanup of owned
    # resources must stay possible after the frozen review/clock data ages.
    for target in manifest['targets'] if phase in ('preflight', 'run') else ():
        review = target['network']['isolation_review']
        if parse_utc(review['expires_utc'], 'isolation_review.expires_utc') <= now:
            _fail('isolation_expired', 'target.network')
        if parse_utc(review['checked_utc'], 'isolation_review.checked_utc') > now:
            _fail('invalid_timestamp', 'target.network')
        checked = parse_utc(target['clock']['checked_utc'], 'clock.checked_utc')
        if checked > now or (now - checked).total_seconds() > manifest['limits']['max_campaign_seconds']:
            _fail('clock_stale', 'target.clock')
    if phase == 'run':
        if parse_utc(manifest['limits']['latest_cleanup_utc'], 'limits.latest_cleanup_utc') <= now:
            _fail('cleanup_deadline', 'limits.latest_cleanup_utc')
        elapsed = (now - parse_utc(state['created_utc'], 'campaign.created_utc')).total_seconds()
        if elapsed >= manifest['limits']['max_campaign_seconds']:
            _fail('budget_exceeded', 'limits.max_campaign_seconds')
        if _quarantined(store, manifest, exclude=state['campaign_id']):
            _fail('target_quarantined', 'manifest.targets')
    return metadata, _authority(store, state, phase)


def _checked_result(value, target_sha):
    _fields(value, {'execution_outcome', 'observed_target_sha256', 'effect_verified',
                    'evidence', 'raw_exports', 'context_updates'}, 'driver.result')
    _enum(value['execution_outcome'], ('succeeded', 'blocked', 'failed', 'unknown'), 'driver.execution_outcome')
    if type(value['effect_verified']) is not bool or type(value['evidence']) is not dict or type(value['context_updates']) is not dict:
        _fail('invalid_response', 'driver.result')
    _array(value['raw_exports'], 'driver.raw_exports')
    if value['observed_target_sha256'] is not None:
        _digest(value['observed_target_sha256'], 'driver.observed_target_sha256')
    if len(value['raw_exports']) > 1:
        _fail('invalid_response', 'driver.raw_exports')
    if value['execution_outcome'] == 'succeeded' and (value['observed_target_sha256'] != target_sha or not value['effect_verified']):
        _fail('effect_unverified', 'driver.result')
    if any(key in value['context_updates'] for key in ('private_root', 'aws_correlation_id', 'campaign_started_utc', 'collector', 'collection_generation', 'authorization_expires_utc')):
        _fail('scope_mismatch', 'driver.context_updates')
    return value


def _quarantine(store, campaign_id):
    current = store.get_campaign(campaign_id)
    updates = {'status': 'unknown'}
    if current['cleanup_status'] in ('pending', 'running'):
        updates['cleanup_status'] = 'unknown'
    return _change(store, current, **updates)


def _execute(store, state, phase, step_id, driver_step=None, collector=None, deadline=None):
    state = store.get_campaign(state['campaign_id'])
    if any(row['status'] in ('reserved', 'unknown') for row in _rows(store, state['campaign_id'], 'campaigns')):
        _quarantine(store, state['campaign_id'])
        _fail('previous_dispatch_unknown', 'campaign.step')
    pins = {}
    try:
        metadata, authority = _guard(store, state, phase, collector, pins)
    except BenchmarkError as error:
        store.event('campaign_preflight', 'campaign-controller',
                    {'record_type': 'dispatch_guard_failed', 'phase': phase, 'reason': error.code},
                    campaign_id=state['campaign_id'])
        if state['status'] == 'draft':
            _change(store, state, status='blocked')
        raise
    context = _context(store, state)
    context['authorization_expires_utc'] = authority['expires_utc']
    if collector:
        context['collector'] = collector
        context['prior_collection_steps'] = [
            {'step_id': row['step_id'], 'fingerprint': row['fingerprint']}
            for row in _rows(store, state['campaign_id'], 'campaigns')
            if row['phase'] == 'collect']
    manifest = state['manifest']
    target_set = [target for target in manifest['targets'] if not collector or target['target_id'] == collector['target_id']]
    target_sha = _hash(target_set)
    timeout = min(manifest['limits']['max_phase_seconds'], collector['max_seconds'] if collector else manifest['limits']['max_phase_seconds'])
    if deadline is not None:
        timeout = min(timeout, deadline - time.monotonic())
    timeout = min(timeout, (parse_utc(authority['expires_utc'], 'authorization.expires_utc') - datetime.now(timezone.utc)).total_seconds())
    if timeout <= 0:
        _fail('budget_exceeded', 'campaign.phase')
    executable = collector['config'].get('executable', manifest['executor']['executable']) if collector else manifest['executor']['executable']
    bound = metadata['cloud_cost_bound']
    spec = dict(schema_version=1, experiment_id=state['experiment_id'], manifest_sha256=state['manifest_sha256'],
                authorization_sha256=authority['authorization_sha256'], executor_sha256=executable['sha256'],
                executor_version=executable['version'],
                input_sha256=_hash({'phase': phase, 'step_id': step_id, 'context': context, 'cloud_cost_bound': bound}),
                target_sha256=target_sha, timeout_seconds=timeout)
    fingerprint = _hash(spec)
    previous = store.reserve_campaign_step(state['campaign_id'], phase, step_id, fingerprint, spec)
    if previous is not None:
        _fail('already_dispatched', 'campaign.step')
    started, mono = _now(), time.monotonic()
    def on_started(identity):
        current = store.get_campaign(state['campaign_id'])
        if current['status'] != state['status'] or current['cleanup_status'] != state['cleanup_status']:
            _fail('state_conflict', 'campaign.status')
        store.record_owned_process(state['campaign_id'], phase, step_id, identity)
    def transport(argv, **kwargs):
        from benchmark_process import run_process
        current = store.get_campaign(state['campaign_id'])
        _guard(store, current, phase, collector, pins)
        remaining = timeout - (time.monotonic() - mono)
        if remaining <= 0:
            _fail('timeout', 'campaign.phase')
        kwargs['timeout'] = min(kwargs['timeout'], remaining)
        kwargs['max_output_bytes'] = min(kwargs['max_output_bytes'], manifest['limits']['max_export_bytes'])
        kwargs['on_started'] = on_started
        response = run_process(argv, **kwargs)
        # Verified local teardown clears ownership even when remote effects stay unknown.
        if response.get('local_stopped') is True and store.get_campaign(state['campaign_id'])['owned_process'] is not None:
            store.clear_owned_process(state['campaign_id'], step_id, {
                'local_stopped': True, 'source': 'run_process', 'remote_effects': 'unknown'})
        return response
    try:
        if collector and collector['kind'] == 'zeek':
            value = _zeek(manifest, collector, phase, context)
        else:
            selected = _driver(collector['kind'] if collector else RECIPES[manifest['recipe_id']])
            value = selected.execute_step(manifest, metadata['range_kit'], phase,
                                          driver_step or step_id, context, transport)
        value = _checked_result(value, target_sha)
        if not collector and value['raw_exports']:
            _fail('scope_mismatch', 'driver.raw_exports')
        if collector:
            _validate_exports(value['raw_exports'], collector)
        if time.monotonic() - mono > timeout:
            _fail('timeout', 'campaign.phase')
        if store.get_campaign(state['campaign_id'])['status'] == 'unknown':
            value = dict(value, execution_outcome='unknown', effect_verified=False)
    except Exception as error:
        reason = error.code if isinstance(error, BenchmarkError) else 'dispatch_interrupted'
        value = dict(execution_outcome='unknown', observed_target_sha256=None, effect_verified=False,
                     evidence={'reason': reason}, raw_exports=[], context_updates={})
    if bound is not None:
        # The receipt's evidence digest binds the exact accepted local cost bound.
        value = dict(value, evidence=dict(value['evidence'], cloud_cost_bound=bound))
    try:
        sha = _persist(_private_root(store, state['campaign_id']), value)
    except BenchmarkError:
        _quarantine(store, state['campaign_id'])
        raise
    outcome = value['execution_outcome']
    reason = value['evidence'].get('reason') or value['evidence'].get('failure_reason') or 'execution_failed'
    exit_code = value['evidence'].get('transport_exit')
    if type(exit_code) is not int:
        exit_code = None
    receipt = dict(schema_version=1, fingerprint=fingerprint,
        status='completed' if outcome == 'succeeded' else ('unknown' if outcome == 'unknown' else 'failed'),
        start_utc=started, end_utc=_now(), elapsed_ms=(time.monotonic() - mono) * 1000,
        campaign_id=state['campaign_id'], phase=phase, step_id=step_id,
        executor_sha256=spec['executor_sha256'], executor_version=spec['executor_version'],
        execution_outcome=outcome, exit_code=exit_code, observed_target_sha256=value['observed_target_sha256'],
        effect_verified=value['effect_verified'], evidence_sha256=sha,
        failure_reason=None if outcome == 'succeeded' else (reason if reason in FAILURES else 'execution_failed'))
    try:
        store.finish_campaign_step(state['campaign_id'], phase, step_id, receipt)
    except BenchmarkError:
        _quarantine(store, state['campaign_id'])
        raise
    if outcome == 'unknown':
        _quarantine(store, state['campaign_id'])
    return value


def preflight(state_root, manifest_path, range_kit, allow_lab_read=False):
    if not allow_lab_read:
        _fail('execution_flag_required', 'allow_lab_read')
    manifest = validate_manifest(_json(manifest_path))
    hashes = _kit(range_kit, manifest['range_kit_sha256'])
    stamp = _now()
    bound = None
    if RECIPES[manifest['recipe_id']] == 'aws':
        # Refused before any state exists: unknown bound or a lower ceiling.
        bound = _cloud_cost_bound(_absolute(str(range_kit), 'range_kit'), manifest, stamp)
        _check_cloud_cost(bound)
    validate_state_root(state_root)
    store = BenchmarkStore(state_root, create=not (Path(state_root) / 'benchmark.sqlite3').exists())
    if _quarantined(store, manifest):
        _fail('target_quarantined', 'manifest.targets')
    state = dict(schema_version=1, campaign_id=manifest['campaign_id'], experiment_id=None,
                 manifest=manifest, manifest_sha256=campaign_manifest_digest(manifest), status='draft',
                 cleanup_status='not_needed', owned_process=None, created_utc=stamp, updated_utc=stamp)
    store.create_campaign(state)
    root = _private_root(store, state['campaign_id'], create=True)
    store.event('campaign_preflight', 'operator-cli', {'record_type': 'controller_configuration',
                'range_kit': str(_absolute(str(range_kit), 'range_kit')), 'kit_files': hashes,
                'aws_correlation_id': str(uuid.uuid4()), 'exclusive_ownership_required': True,
                'cloud_cost_bound': bound}, campaign_id=state['campaign_id'])
    expires = (datetime.now(timezone.utc) + timedelta(seconds=manifest['limits']['max_phase_seconds'])).isoformat()
    _authorize(store, state, 'operator-cli', 'Explicit bounded read-only preflight flag', expires, ['preflight'])
    with _lock(root):
        deadline = time.monotonic() + manifest['limits']['max_phase_seconds']
        selected = _driver(RECIPES[manifest['recipe_id']])
        for step in _steps(selected, manifest, 'preflight', _context(store, state)):
            value = _execute(store, state, 'preflight', step, deadline=deadline)
            if value['execution_outcome'] != 'succeeded':
                break
        else:
            for collector in manifest['collectors']:
                value = _execute(store, state, 'preflight', 'sensor-' + _hash(collector['source_id'])[:24], collector['source_id'], collector, deadline)
                if value['execution_outcome'] != 'succeeded':
                    break
            else:
                current = store.get_campaign(state['campaign_id'])
                _change(store, current, status='preflight_passed')
                return status(state_root, state['campaign_id'])
        current = store.get_campaign(state['campaign_id'])
        if current['status'] != 'unknown':
            _change(store, current, status='blocked')
    return status(state_root, state['campaign_id'])


def authorize(state_root, campaign_id, by, note, expires, phases):
    store = BenchmarkStore(state_root)
    with _lock(_private_root(store, campaign_id)):
        state = store.get_campaign(campaign_id)
        _strings(phases, 'authorization.phases', nonempty=True)
        for phase in phases:
            _enum(phase, PHASES, 'authorization.phases')
        if state['status'] not in ('preflight_passed', 'authorized', 'awaiting_collection', 'awaiting_release', 'failed', 'blocked', 'unknown'):
            _fail('state_conflict', 'campaign.status')
        if state['status'] in ('failed', 'blocked', 'unknown') and 'run' in phases:
            _fail('state_conflict', 'authorization.phases')
        _kit(_metadata(store, state)['range_kit'], state['manifest']['range_kit_sha256'])
        _authorize(store, state, by, note, expires, phases)
        if state['status'] == 'preflight_passed':
            _change(store, state, status='authorized')
    return status(state_root, campaign_id)


def run(state_root, campaign_id, allow_lab_mutation=False):
    if not allow_lab_mutation:
        _fail('execution_flag_required', 'allow_lab_mutation')
    store = BenchmarkStore(state_root)
    with _lock(_private_root(store, campaign_id)):
        state = store.get_campaign(campaign_id)
        if state['status'] != 'authorized' or state['cleanup_status'] != 'not_needed':
            _fail('state_conflict', 'campaign.status')
        _authority(store, state, 'run')
        state = _change(store, state, status='running', cleanup_status='pending')
        selected = _driver(RECIPES[state['manifest']['recipe_id']])
        deadline = time.monotonic() + state['manifest']['limits']['max_phase_seconds']
        try:
            for step in _steps(selected, state['manifest'], 'run', _context(store, state)):
                _id(step, 'driver.step_id')
                value = _execute(store, state, 'run', step, deadline=deadline)
                if value['execution_outcome'] != 'succeeded':
                    current = store.get_campaign(campaign_id)
                    if current['status'] != 'unknown':
                        _change(store, current, status='blocked' if value['execution_outcome'] == 'blocked' else 'failed')
                    return status(state_root, campaign_id)
            _change(store, store.get_campaign(campaign_id), status='awaiting_collection')
        except BenchmarkError:
            current = store.get_campaign(campaign_id)
            if current['status'] == 'running':
                _change(store, current, status='blocked')
            raise
    return status(state_root, campaign_id)


def _validate_exports(exports, collector):
    for export in exports:
        _fields(export, {'source_id', 'records', 'window_utc', 'watermark_utc', 'complete', 'filter'}, 'raw_export')
        if export['source_id'] != collector['source_id'] or export['window_utc'] != collector['window_utc']:
            _fail('scope_mismatch', 'raw_export')
        _array(export['records'], 'raw_export.records')
        if export['filter'] is not None and type(export['filter']) is not dict:
            _fail('invalid_object', 'raw_export.filter')
        watermark = parse_utc(export['watermark_utc'], 'raw_export.watermark_utc')
        if watermark > datetime.now(timezone.utc):
            _fail('invalid_timestamp', 'raw_export.watermark_utc')
        if type(export['complete']) is not bool:
            _fail('invalid_boolean', 'raw_export.complete')
        if export['complete'] and watermark < _window(collector['window_utc'], 'collector.window_utc')[1]:
            _fail('incomplete_export', 'raw_export.watermark_utc')
        if len(canonical_bytes(export)) > collector['max_bytes']:
            _fail('output_limit', 'raw_export')


def _collections(store, state):
    """Latest snapshot per (generation, source); superseded partial snapshots do not count.

    `exercise` keeps the latest pre-cleanup snapshot (complete or partial) and
    `cleanup` only the complete, completed final one. Byte accounting is the sum of
    canonical export bytes of current snapshots, the same measure the sealer uses.
    """
    current = {'exercise': {}, 'cleanup': {}}
    for row in _rows(store, state['campaign_id'], 'campaigns'):
        if row['phase'] != 'collect' or row['receipt'] is None:
            continue
        value = _result(store, state, row)
        generation = row['step_id'].split('-', 1)[0]
        if generation not in current:
            _fail('corrupt_state', 'campaign.collection')
        for export in value.get('raw_exports', []):
            current[generation][export['source_id']] = (row, export)
    total = sum(len(canonical_bytes(export)) for items in current.values() for _, export in items.values())
    if total > state['manifest']['limits']['max_export_bytes']:
        _fail('output_limit', 'campaign.raw_exports')
    generations = {
        'exercise': {source: row['receipt']['evidence_sha256'] for source, (row, _) in current['exercise'].items()},
        'cleanup': {source: row['receipt']['evidence_sha256'] for source, (row, export) in current['cleanup'].items()
                    if export['complete'] and row['status'] == 'completed'}}
    required = {item['source_id'] for item in state['manifest']['collectors']}
    return generations, required <= set(generations['cleanup']), current


def collect(state_root, campaign_id, allow_lab_read=False):
    if not allow_lab_read:
        _fail('execution_flag_required', 'allow_lab_read')
    store = BenchmarkStore(state_root)
    with _lock(_private_root(store, campaign_id)):
        state = store.get_campaign(campaign_id)
        if state['status'] not in ('awaiting_collection', 'failed', 'blocked') or state['cleanup_status'] == 'unknown':
            _fail('state_conflict', 'campaign.status')
        _authority(store, state, 'collect')
        generation = 'cleanup' if state['cleanup_status'] == 'succeeded' else 'exercise'
        batches = sum(1 for row in _rows(store, campaign_id, 'campaigns') if row['phase'] == 'collect')
        deadline = time.monotonic() + state['manifest']['limits']['max_phase_seconds']
        for collector in state['manifest']['collectors']:
            _, _, current = _collections(store, state)
            latest = current[generation].get(collector['source_id'])
            if latest is not None and latest[1]['complete'] and latest[0]['status'] == 'completed':
                continue
            # The new snapshot supersedes this generation's partial one for this source.
            total = sum(len(canonical_bytes(export)) for items in current.values() for _, export in items.values())
            replaced = len(canonical_bytes(latest[1])) if latest is not None else 0
            if total - replaced + collector['max_bytes'] > state['manifest']['limits']['max_export_bytes']:
                _fail('budget_exceeded', 'campaign.raw_exports')
            step = generation + '-' + str(batches) + '-' + _hash(collector['source_id'])[:24]
            _execute(store, state, 'collect', step, collector['source_id'], collector, deadline)
            state = store.get_campaign(campaign_id)
            if state['status'] == 'unknown':
                break
        state = store.get_campaign(campaign_id)
        generations, complete, _ = _collections(store, state)
        if complete:
            mutation_rows = [row for row in _rows(store, campaign_id, 'campaigns')
                             if row['phase'] in ('run', 'cleanup') and row['receipt'] is not None]
            for collector in state['manifest']['collectors']:
                start, end = _window(collector['window_utc'], 'collector.window_utc')
                if any(parse_utc(row['receipt']['start_utc'], 'receipt.start_utc') < start or
                       parse_utc(row['receipt']['end_utc'], 'receipt.end_utc') >= end
                       for row in mutation_rows):
                    _fail('collection_window_mismatch', 'collector.window_utc')
        if complete and state['cleanup_status'] == 'succeeded' and state['status'] == 'awaiting_collection':
            seal = {'record_type': 'private_collection_complete', 'generations': generations,
                    'manifest_sha256': state['manifest_sha256'], 'human_release_required': True}
            store.event('evidence_sealed', 'campaign-controller', seal, campaign_id=campaign_id)
            _change(store, state, status='awaiting_release')
    return status(state_root, campaign_id)


def _seal_sources(store, state):
    """Authorize only final, receipt-bound, complete private collector snapshots."""
    if state['status'] not in ('awaiting_release', 'evidence_ready') or state['cleanup_status'] != 'succeeded' or state['owned_process'] is not None:
        _fail('state_conflict', 'campaign.seal')
    validate_manifest(state['manifest'])
    kit = _metadata(store, state)['range_kit']
    _kit(kit, state['manifest']['range_kit_sha256'])
    rows = _rows(store, state['campaign_id'], 'campaigns')
    if any(row['status'] not in ('completed', 'failed') or row['receipt'] is None or
           row['receipt']['execution_outcome'] == 'unknown' for row in rows):
        _fail('previous_dispatch_unknown', 'campaign.steps')
    generations, complete, _ = _collections(store, state)
    if not complete:
        _fail('incomplete_export', 'campaign.collection')
    events = [event for event in _rows(store, state['campaign_id'], 'events')
              if event['kind'] == 'evidence_sealed' and event['payload'].get('record_type') == 'private_collection_complete']
    if not events or events[-1]['payload']['generations'] != generations or events[-1]['payload']['manifest_sha256'] != state['manifest_sha256']:
        _fail('evidence_mismatch', 'campaign.collection')
    snapshots = []
    root = _private_root(store, state['campaign_id'])
    limit = state['manifest']['limits']['max_export_bytes'] + MAX_METADATA_BYTES
    for collector in state['manifest']['collectors']:
        sha = generations['cleanup'][collector['source_id']]
        matching = [row for row in rows if row['phase'] == 'collect' and
                    row['step_id'].startswith('cleanup-') and row['status'] == 'completed' and
                    row['receipt']['evidence_sha256'] == sha]
        if not matching:
            _fail('evidence_mismatch', 'campaign.collection')
        result = _result(store, state, matching[-1])
        exports = result.get('raw_exports')
        if type(exports) is not list or len(exports) != 1:
            _fail('incomplete_export', 'campaign.collection')
        _validate_exports(exports, collector)
        if exports[0]['complete'] is not True:
            _fail('incomplete_export', 'campaign.collection')
        start, end = _window(collector['window_utc'], 'collector.window_utc')
        if any(parse_utc(row['receipt']['start_utc'], 'receipt.start_utc') < start or
               parse_utc(row['receipt']['end_utc'], 'receipt.end_utc') >= end
               for row in rows if row['phase'] in ('run', 'cleanup')):
            _fail('collection_window_mismatch', 'collector.window_utc')
        item = _snapshot_file(root, sha, limit)
        item['source_id'] = collector['source_id']
        # The pre-cleanup exercise snapshot is kept; the sealer checks exercise ⊆ final.
        exercise = generations['exercise'].get(collector['source_id'])
        item['exercise'] = None if exercise is None else _snapshot_file(root, exercise, limit)
        snapshots.append(item)
    return snapshots, _json(confined_file(kit, 'collector-fields.json'))


def _snapshot_file(root, sha, limit):
    relative = 'raw/' + sha + '.json'
    content = _read(confined_file(root, relative), limit)
    if digest_bytes(content) != sha:
        _fail('digest_mismatch', 'campaign.evidence')
    return {'path': relative, 'sha256': sha, 'byte_count': len(content)}


def _phase_windows(store, state):
    """Evaluator-only phase windows from completed step receipts (warmup/exercise/cleanup)."""
    spans = {}
    for row in _rows(store, state['campaign_id'], 'campaigns'):
        if row['status'] != 'completed' or row['phase'] not in ('run', 'cleanup'):
            continue
        phase = 'cleanup' if row['phase'] == 'cleanup' else ('warmup' if row['step_id'] == 'warmup' else 'exercise')
        start = parse_utc(row['receipt']['start_utc'], 'receipt.start_utc')
        end = parse_utc(row['receipt']['end_utc'], 'receipt.end_utc')
        low, high = spans.get(phase, (start, end))
        spans[phase] = (min(low, start), max(high, end))
    windows = []
    for phase in ('warmup', 'exercise', 'cleanup'):
        if phase in spans:
            start, end = spans[phase]
            end = max(end, start + timedelta(microseconds=1))
            windows.append({'phase': phase, 'window_utc': {
                'start_inclusive': start.astimezone(timezone.utc).isoformat(timespec='microseconds').replace('+00:00', 'Z'),
                'end_exclusive': end.astimezone(timezone.utc).isoformat(timespec='microseconds').replace('+00:00', 'Z')}})
    return windows


def _seal_locked(store, state, selected, mapping, public_destination):
    snapshots, rules = _seal_sources(store, state)
    expected = [{'source_id': item['source_id'], 'sha256': item['sha256']} for item in snapshots]
    if selected is not None and sorted(selected, key=lambda item: item['source_id']) != sorted(expected, key=lambda item: item['source_id']):
        _fail('evidence_mismatch', 'raw_exports.snapshots')
    root = _private_root(store, state['campaign_id'])
    destination = _absolute(str(public_destination), 'public_destination')
    _no_alias(destination, 'public_destination')
    try:
        relative = destination.relative_to(root / 'public')
    except ValueError:
        _fail('path_escape', 'public_destination')
    if not relative.parts or destination.exists():
        _fail('already_exists', 'public_destination')
    from benchmark_contracts import _relative
    _relative(destination.relative_to(root).as_posix(), 'public_destination')
    mapping_sha = _hash(mapping)
    sealed = [event['payload'] for event in _rows(store, state['campaign_id'], 'events')
              if event['payload'].get('record_type') == 'public_evidence_sealed']
    if any(item['mapping_sha256'] != mapping_sha for item in sealed):
        _fail('fingerprint_conflict', 'mapping')
    from benchmark_evidence import materialize_evidence
    public = materialize_evidence(root, state['manifest'], snapshots, rules, mapping, destination,
                                  phase_windows=_phase_windows(store, state),
                                  private_markers=[_metadata(store, state)['aws_correlation_id']])
    validate_public_bundle(public, root=destination)
    content = _read(confined_file(destination, 'evidence.json'))
    if content != canonical_bytes(public):
        _fail('digest_mismatch', 'public_manifest')
    condition = 'with_detector_alerts' if any(event['fields'].get('detector_attack_ids') for event in public['events']) else 'raw_telemetry'
    store.event('evidence_sealed', 'campaign-controller', {
        'record_type': 'public_evidence_sealed', 'case_id': public['case_id'],
        'evidence_sha256': digest_bytes(content), 'mapping_sha256': mapping_sha,
        'public_manifest': (destination / 'evidence.json').relative_to(root).as_posix(),
        'condition': condition, 'sources': expected, 'human_release_required': True,
    }, campaign_id=state['campaign_id'])
    return public


def seal_evidence(raw_exports, mapping, public_destination):
    """Materialize approved private snapshots; this grants no model authority."""
    _fields(raw_exports, {'state_root', 'campaign_id', 'snapshots'}, 'raw_exports')
    _absolute(raw_exports['state_root'], 'raw_exports.state_root')
    _id(raw_exports['campaign_id'], 'raw_exports.campaign_id')
    _array(raw_exports['snapshots'], 'raw_exports.snapshots', nonempty=True)
    for item in raw_exports['snapshots']:
        _fields(item, {'source_id', 'sha256'}, 'raw_exports.snapshots')
        _id(item['source_id'], 'raw_exports.snapshots.source_id')
        _digest(item['sha256'], 'raw_exports.snapshots.sha256')
    store = BenchmarkStore(raw_exports['state_root'])
    with _lock(_private_root(store, raw_exports['campaign_id'])):
        state = store.get_campaign(raw_exports['campaign_id'])
        return _seal_locked(store, state, raw_exports['snapshots'], mapping, public_destination)


def seal(state_root, campaign_id, mapping_path, public_destination):
    """Offline sealing of the complete final collection, without human approval."""
    mapping = _json(mapping_path)
    store = BenchmarkStore(state_root)
    with _lock(_private_root(store, campaign_id)):
        state = store.get_campaign(campaign_id)
        public = _seal_locked(store, state, None, mapping, public_destination)
    return {'campaign_id': campaign_id, 'case_id': public['case_id'],
            'evidence_sha256': _hash(public), 'public_manifest': str(Path(public_destination) / 'evidence.json'),
            'condition': 'with_detector_alerts' if any(event['fields'].get('detector_attack_ids') for event in public['events']) else 'raw_telemetry',
            'status': state['status'], 'human_release_required': True, 'execution': 'not_dispatched'}


def release(state_root, campaign_id, by, note, destinations_path):
    """Release exact public bytes to named initialized destinations, atomically."""
    _text(by, 'release.by')
    _text(note, 'release.note')
    if by == 'operator-cli':
        _fail('human_release_required', 'release.by')
    destinations = _json(destinations_path)
    _fields(destinations, {'schema_version', 'evidence_sha256', 'expires_utc', 'trials'}, 'release')
    _version(destinations['schema_version'], 'release.schema_version')
    _digest(destinations['evidence_sha256'], 'release.evidence_sha256')
    if parse_utc(destinations['expires_utc'], 'release.expires_utc') <= datetime.now(timezone.utc):
        _fail('authorization_expired', 'release.expires_utc')
    _array(destinations['trials'], 'release.trials', nonempty=True)
    specs, seen = [], set()
    for item in destinations['trials']:
        _fields(item, {'experiment_id', 'trial_id', 'model_sha256s'}, 'release.trials')
        _id(item['experiment_id'], 'release.trials.experiment_id')
        _id(item['trial_id'], 'release.trials.trial_id')
        _strings(item['model_sha256s'], 'release.trials.model_sha256s', validator=_digest, nonempty=True)
        if item['trial_id'] in seen:
            _fail('duplicate_identifier', 'release.trials')
        seen.add(item['trial_id'])
        specs.append(dict(item, approval_id='auth-' + uuid.uuid4().hex, campaign_id=None,
                          by=by, note=note, created_utc=_now(), expires_utc=destinations['expires_utc'],
                          evidence_sha256=destinations['evidence_sha256'], manifest_sha256=None, phases=[]))
    store = BenchmarkStore(state_root)
    with _lock(_private_root(store, campaign_id)):
        state = store.get_campaign(campaign_id)
        snapshots, _ = _seal_sources(store, state)
        expected = [{'source_id': item['source_id'], 'sha256': item['sha256']} for item in snapshots]
        seals = [event for event in _rows(store, campaign_id, 'events')
                 if event['kind'] == 'evidence_sealed' and event['payload'].get('record_type') == 'public_evidence_sealed'
                 and event['payload']['evidence_sha256'] == destinations['evidence_sha256']]
        if not seals or seals[-1]['payload']['sources'] != expected:
            _fail('evidence_mismatch', 'release.evidence_sha256')
        grants = store.release_campaign_evidence(campaign_id, seals[-1]['event_id'], specs)
    return {'campaign_id': campaign_id, 'status': 'evidence_ready',
            'evidence_sha256': destinations['evidence_sha256'], 'destinations': grants,
            'execution': 'not_dispatched'}


def cleanup(state_root, campaign_id, allow_lab_mutation=False):
    if not allow_lab_mutation:
        _fail('execution_flag_required', 'allow_lab_mutation')
    store = BenchmarkStore(state_root)
    with _lock(_private_root(store, campaign_id)):
        state = store.get_campaign(campaign_id)
        if state['cleanup_status'] not in ('pending', 'failed') or state['status'] in ('running', 'unknown'):
            _fail('state_conflict', 'campaign.cleanup_status')
        # A still-owned local job means the controller itself has not finished.
        if state['owned_process'] is not None:
            _fail('process_not_stopped', 'campaign.owned_process')
        previous_cleanup = [row for row in _rows(store, campaign_id, 'campaigns') if row['phase'] == 'cleanup']
        context = _context(store, state)
        reconciled_cleanup = {item['step_id'] for item in context['reconciled_steps']
                              if item['phase'] == 'cleanup' and item['outcome'] == 'failed'}
        if previous_cleanup and any(row['status'] != 'failed' or row['step_id'] not in reconciled_cleanup for row in previous_cleanup):
            _fail('previous_dispatch_unknown', 'campaign.cleanup_status')
        _authority(store, state, 'cleanup')
        generations, _, _ = _collections(store, state)
        required = {collector['source_id'] for collector in state['manifest']['collectors']}
        preserved = required <= set(generations['exercise'])
        retained = state['manifest']['recipe_id'] == 'aws-test-trail-stop-v1' and context.get('aws_retention_verified') is True and context.get('aws_baseline_healthy') is True
        if not preserved and not retained:
            _fail('raw_evidence_required', 'campaign.cleanup')
        # Refusals (pins, kit, authority) happen before cleanup is marked running,
        # so an attempt that dispatched nothing never records cleanup failure.
        try:
            _guard(store, state, 'cleanup')
        except BenchmarkError as error:
            store.event('campaign_preflight', 'campaign-controller',
                        {'record_type': 'dispatch_guard_failed', 'phase': 'cleanup', 'reason': error.code},
                        campaign_id=campaign_id)
            raise
        state = _change(store, state, cleanup_status='running')
        deadline = time.monotonic() + state['manifest']['limits']['max_phase_seconds']
        selected = _driver(RECIPES[state['manifest']['recipe_id']])
        try:
            for step in _steps(selected, state['manifest'], 'cleanup', context):
                reservation = step if not previous_cleanup else step + '-reconciled-' + str(len(previous_cleanup))
                value = _execute(store, state, 'cleanup', reservation, step, deadline=deadline)
                if value['execution_outcome'] != 'succeeded':
                    current = store.get_campaign(campaign_id)
                    if current['cleanup_status'] != 'unknown':
                        _change(store, current, cleanup_status='failed')
                    return status(state_root, campaign_id)
            _change(store, store.get_campaign(campaign_id), cleanup_status='succeeded')
        except BenchmarkError:
            current = store.get_campaign(campaign_id)
            if current['cleanup_status'] == 'running':
                _change(store, current, cleanup_status='failed')
            raise
    return status(state_root, campaign_id)


def stop(state_root, campaign_id, allow_lab_mutation=False):
    if not allow_lab_mutation:
        _fail('execution_flag_required', 'allow_lab_mutation')
    store = BenchmarkStore(state_root)
    # Deliberately bypass the dispatch lock: a stop must interrupt its owner.
    state = store.get_campaign(campaign_id)
    authority = _authority(store, state, 'stop')
    if state['status'] not in ('running', 'awaiting_collection', 'unknown', 'failed', 'blocked'):
        _fail('state_conflict', 'campaign.status')
    state, identity = store.request_campaign_stop(campaign_id)
    rows = _rows(store, campaign_id, 'campaigns')
    attempt = sum(1 for row in rows if row['phase'] == 'stop') + 1
    step_id = 'owned-process-' + str(attempt)
    executable = state['manifest']['executor']['executable']
    spec = dict(schema_version=1, experiment_id=state['experiment_id'], manifest_sha256=state['manifest_sha256'],
                authorization_sha256=authority['authorization_sha256'], executor_sha256=executable['sha256'],
                executor_version=executable['version'], input_sha256=_hash({'attempt': attempt, 'identity': identity}),
                target_sha256=_hash(state['manifest']['targets']),
                timeout_seconds=state['manifest']['limits']['max_phase_seconds'])
    fingerprint = _hash(spec)
    reservation_error = None
    try:
        if store.reserve_campaign_step(campaign_id, 'stop', step_id, fingerprint, spec) is not None:
            reservation_error = 'already_dispatched'
    except BenchmarkError as error:
        reservation_error = error.code
    started = _now()
    monotonic_start = time.monotonic()
    # Stopping the owned local tree never waits on a durable reservation.
    from benchmark_process import stop_owned
    response = stop_owned(identity) if identity is not None else {'status': 'succeeded', 'local_stopped': True}
    local_stopped = response.get('local_stopped') is True
    if identity is not None and local_stopped:
        owner = step_id if reservation_error is None else next(
            (row['step_id'] for row in reversed(rows) if row['status'] in ('reserved', 'unknown')), None)
        if owner is not None:
            store.clear_owned_process(campaign_id, owner, {'local_stopped': True, 'source': 'stop_owned',
                                                           'remote_effects': 'unknown'})
    evidence = {'local_process_stopped': local_stopped, 'remote_effects': 'unknown',
                'reservation_error': reservation_error}
    bound = _metadata(store, state)['cloud_cost_bound']
    if bound is not None:
        evidence['cloud_cost_bound'] = bound
    value = {'execution_outcome': 'unknown', 'observed_target_sha256': None, 'effect_verified': False,
             'evidence': evidence, 'raw_exports': [], 'context_updates': {}}
    sha = _persist(_private_root(store, campaign_id), value)
    receipt = dict(schema_version=1, fingerprint=fingerprint, status='unknown', start_utc=started,
                   end_utc=_now(), elapsed_ms=(time.monotonic() - monotonic_start) * 1000,
                   campaign_id=campaign_id, phase='stop', step_id=step_id,
                   executor_sha256=spec['executor_sha256'], executor_version=spec['executor_version'],
                   execution_outcome='unknown', exit_code=None, observed_target_sha256=None,
                   effect_verified=False, evidence_sha256=sha, failure_reason='dispatch_interrupted')
    if reservation_error is None:
        store.finish_campaign_step(campaign_id, 'stop', step_id, receipt)
    else:
        store.event('dispatch_unknown', 'campaign-controller',
                    {'record_type': 'unreserved_stop_receipt', 'reservation_error': reservation_error,
                     'receipt': receipt}, campaign_id=campaign_id)
    return status(state_root, campaign_id)


def status(state_root, campaign_id):
    store = BenchmarkStore(state_root)
    state = store.get_campaign(campaign_id)
    rows = _rows(store, campaign_id, 'campaigns')
    reasons = []
    for row in rows:
        if row['status'] in ('reserved', 'unknown'):
            reasons.append('previous_dispatch_unknown')
        elif row['status'] == 'failed':
            reasons.append(row['receipt']['failure_reason'])
            private = _result(store, state, row)
            reason = private.get('evidence', {}).get('reason') or private.get('evidence', {}).get('failure_reason')
            if type(reason) is str and re.fullmatch(r'[a-z][a-z0-9_]{0,79}', reason):
                reasons.append(reason)
    configuration = []
    for event in _rows(store, campaign_id, 'events'):
        if event['payload'].get('record_type') == 'dispatch_guard_failed':
            reasons.append(event['payload']['reason'])
        if event['payload'].get('record_type') == 'controller_configuration':
            configuration.append(event['payload'])
    if state['cleanup_status'] in ('pending', 'running', 'failed', 'unknown'):
        reasons.append('cleanup_required')
    # A failed/unknown cleanup quarantines these targets for every campaign in this state.
    if state['cleanup_status'] in ('failed', 'unknown'):
        reasons.append('targets_quarantined')
    if parse_utc(state['manifest']['limits']['latest_cleanup_utc'], 'limits.latest_cleanup_utc') <= datetime.now(timezone.utc) and state['cleanup_status'] != 'succeeded':
        reasons.append('cleanup_deadline')
    return {'campaign_id': campaign_id, 'manifest_sha256': state['manifest_sha256'], 'status': state['status'],
            'cleanup_status': state['cleanup_status'], 'owned_process': state['owned_process'],
            'cloud_cost_bound': configuration[0]['cloud_cost_bound'] if len(configuration) == 1 else None,
            'steps': [{'phase': row['phase'], 'step_id': row['step_id'], 'status': row['status'],
                       'execution_outcome': row['receipt']['execution_outcome'] if row['receipt'] else 'unknown'} for row in rows],
            'reasons': sorted(set(reasons)), 'live_verified': False, 'human_release_required': state['status'] != 'evidence_ready'}


def reconcile(state_root, campaign_id, by, note, evidence_path):
    evidence = _json(evidence_path)
    _fields(evidence, {'schema_version', 'campaign_id', 'phase', 'step_id', 'fingerprint',
                       'outcome', 'process_stopped', 'observation'}, 'reconciliation', optional={'driver_evidence'})
    _version(evidence['schema_version'], 'reconciliation.schema_version')
    if evidence['campaign_id'] != campaign_id or evidence['process_stopped'] is not True:
        _fail('scope_mismatch', 'reconciliation')
    _enum(evidence['outcome'], ('completed', 'failed'), 'reconciliation.outcome')
    _text(by, 'reconciliation.by')
    _text(note, 'reconciliation.note')
    store = BenchmarkStore(state_root)
    with _lock(_private_root(store, campaign_id)):
        state = store.get_campaign(campaign_id)
        rows = [row for row in _rows(store, campaign_id, 'campaigns') if row['phase'] == evidence['phase'] and row['step_id'] == evidence['step_id']]
        if len(rows) != 1 or rows[0]['fingerprint'] != evidence['fingerprint']:
            _fail('fingerprint_conflict', 'reconciliation')
        row = rows[0]
        observation = evidence['observation']
        _fields(observation, {'observed_target_sha256', 'effect_verified', 'source_receipt_sha256', 'observed_utc'}, 'reconciliation.observation')
        for key in ('observed_target_sha256', 'source_receipt_sha256'):
            _digest(observation[key], 'reconciliation.observation.' + key)
        parse_utc(observation['observed_utc'], 'reconciliation.observation.observed_utc')
        if type(observation['effect_verified']) is not bool:
            _fail('invalid_boolean', 'reconciliation.observation.effect_verified')
        driver_evidence = evidence.get('driver_evidence', {})
        if 'driver_evidence' in evidence:
            if state['manifest']['recipe_id'] != 'aws-test-trail-stop-v1':
                _fail('scope_mismatch', 'reconciliation.driver_evidence')
            _fields(driver_evidence, {'aws_resources', 'aws_target_logging'}, 'reconciliation.driver_evidence')
            resources = driver_evidence['aws_resources']
            _fields(resources, {'trail_arn', 'trail_name', 'bucket', 'state_sha256'}, 'reconciliation.aws_resources')
            for key in ('trail_arn', 'trail_name', 'bucket'):
                _text(resources[key], 'reconciliation.aws_resources.' + key)
                if len(resources[key]) > 512:
                    _fail('output_limit', 'reconciliation.aws_resources')
            _digest(resources['state_sha256'], 'reconciliation.aws_resources.state_sha256')
            if type(driver_evidence['aws_target_logging']) is not bool or _hash(driver_evidence) != observation['source_receipt_sha256']:
                _fail('evidence_mismatch', 'reconciliation.driver_evidence')
        if observation['observed_target_sha256'] != row['spec']['target_sha256']:
            _fail('target_mismatch', 'reconciliation.observation')
        if state['owned_process'] is not None:
            _fail('process_not_stopped', 'reconciliation')
        completed = evidence['outcome'] == 'completed'
        receipt = dict(schema_version=1, fingerprint=row['fingerprint'], status=evidence['outcome'],
            start_utc=row['created_utc'], end_utc=_now(), elapsed_ms=None, campaign_id=campaign_id,
            phase=row['phase'], step_id=row['step_id'], executor_sha256=row['spec']['executor_sha256'],
            executor_version=row['spec']['executor_version'], execution_outcome='succeeded' if completed else 'failed',
            exit_code=None, observed_target_sha256=observation['observed_target_sha256'],
            effect_verified=observation['effect_verified'], evidence_sha256=_hash(observation),
            failure_reason=None if completed else 'human_reconciled')
        _persist(_private_root(store, campaign_id), observation)
        if row['status'] in ('reserved', 'unknown'):
            store.reconcile_campaign_step(campaign_id, row['phase'], row['step_id'], by, note, observation, receipt)
        elif row['status'] != evidence['outcome']:
            _fail('state_conflict', 'reconciliation.outcome')
        if driver_evidence or row['status'] in ('completed', 'failed'):
            store.event('reconciliation_recorded', by,
                        {'phase': row['phase'], 'step_id': row['step_id'], 'outcome': evidence['outcome'],
                         'note': note, 'evidence': dict(observation, **driver_evidence)},
                        campaign_id=campaign_id)
        state = store.get_campaign(campaign_id)
        updates = {}
        if row['phase'] == 'cleanup' and state['cleanup_status'] == 'unknown':
            updates['cleanup_status'] = 'succeeded' if completed else 'failed'
        elif state['cleanup_status'] == 'unknown':
            updates['cleanup_status'] = 'failed'
        state = _change(store, state, **updates)
        outstanding = [item for item in _rows(store, campaign_id, 'campaigns') if item['status'] in ('reserved', 'unknown')]
        if not outstanding and state['status'] in ('unknown', 'failed', 'blocked'):
            store.reconcile_campaign_state(campaign_id, state['status'], by, note, canonical_bytes(evidence))
    return status(state_root, campaign_id)


def _validate_zeek(manifest, collector):
    if collector['export_root'] is None or collector['bucket'] is not None or collector['prefix'] is not None:
        _fail('scope_mismatch', 'collector.zeek')
    config = collector['config']
    _fields(config, {'manifest_path', 'streams', 'address_assets'}, 'collector.zeek.config')
    from benchmark_contracts import _relative
    _relative(config['manifest_path'], 'collector.zeek.manifest_path')
    _strings(config['streams'], 'collector.zeek.streams', nonempty=True)
    for stream in config['streams']:
        _enum(stream, ('conn', 'dns', 'http'), 'collector.zeek.streams')
    # Explicit address-to-asset enrollment; unlisted addresses stay with the sensor asset.
    _array(config['address_assets'], 'collector.zeek.address_assets')
    targets = {target['target_id'] for target in manifest['targets']}
    addresses = set()
    for item in config['address_assets']:
        _fields(item, {'address', 'target_id'}, 'collector.zeek.address_assets')
        try:
            canonical = str(ipaddress.ip_address(item['address']))
        except (ValueError, TypeError):
            _fail('invalid_endpoint', 'collector.zeek.address_assets')
        if canonical != item['address'] or canonical in addresses:
            _fail('invalid_endpoint', 'collector.zeek.address_assets')
        addresses.add(canonical)
        if item['target_id'] not in targets or item['target_id'] == collector['target_id']:
            _fail('unknown_reference', 'collector.zeek.address_assets')


def _zeek(manifest, collector, phase, context):
    config = collector['config']
    raw = _read(confined_file(collector['export_root'], config['manifest_path']))
    spool = decode_json(raw)
    _fields(spool, {'schema_version', 'source_id', 'window_utc', 'watermark_utc', 'sealed', 'files'}, 'zeek.manifest')
    _version(spool['schema_version'], 'zeek.schema_version')
    if spool['source_id'] != collector['source_id'] or spool['window_utc'] != collector['window_utc'] or type(spool['sealed']) is not bool:
        _fail('scope_mismatch', 'zeek.manifest')
    watermark = parse_utc(spool['watermark_utc'], 'zeek.watermark_utc')
    if watermark > datetime.now(timezone.utc):
        _fail('invalid_timestamp', 'zeek.watermark_utc')
    start, end = _window(spool['window_utc'], 'zeek.window_utc')
    _array(spool['files'], 'zeek.files')
    records, seen, streams, consumed = [], set(), set(), 0
    deadline = time.monotonic() + collector['max_seconds']
    source_snapshots = []
    if phase == 'collect':
        snapshot_root = Path(context['private_root'])
        source_snapshots.append({'sha256': _persist_bytes(snapshot_root, raw), 'byte_count': len(raw)})
    for item in spool['files']:
        _fields(item, {'path', 'sha256', 'byte_count', 'stream'}, 'zeek.file')
        _digest(item['sha256'], 'zeek.file.sha256')
        _integer(item['byte_count'], 'zeek.file.byte_count', minimum=0)
        _enum(item['stream'], config['streams'], 'zeek.file.stream')
        if item['path'] in seen:
            _fail('duplicate_identifier', 'zeek.file.path')
        seen.add(item['path'])
        streams.add(item['stream'])
        consumed += item['byte_count']
        if consumed > collector['max_bytes'] or time.monotonic() > deadline:
            _fail('output_limit', 'zeek.files')
        data = _read(confined_file(collector['export_root'], item['path']), collector['max_bytes'])
        if len(data) != item['byte_count'] or digest_bytes(data) != item['sha256']:
            _fail('digest_mismatch', 'zeek.file')
        if phase == 'collect':
            source_snapshots.append({'sha256': _persist_bytes(snapshot_root, data), 'byte_count': len(data)})
        for line_number, line in enumerate(data.splitlines(), 1):
            record = decode_json(line)
            if type(record) is not dict or type(record.get('ts')) not in (int, float):
                _fail('unsupported_source_schema', 'zeek.record')
            _number(record['ts'], 'zeek.record.ts')
            try:
                stamp = datetime.fromtimestamp(record['ts'], timezone.utc)
            except (ValueError, OSError, OverflowError):
                _fail('invalid_timestamp', 'zeek.record.ts')
            if not start <= stamp < end:
                _fail('scope_mismatch', 'zeek.record.ts')
            records.append({'stream': item['stream'], 'record': record,
                            'file_sha256': item['sha256'], 'record_id': str(line_number)})
    complete = spool['sealed'] and watermark >= end and set(config['streams']) == streams
    ready = phase == 'preflight' or complete
    target = next(target for target in manifest['targets'] if target['target_id'] == collector['target_id'])
    export = {'source_id': collector['source_id'], 'records': records, 'window_utc': collector['window_utc'],
              'watermark_utc': spool['watermark_utc'], 'complete': complete, 'filter': None}
    return {'execution_outcome': 'succeeded' if ready else 'blocked',
            'observed_target_sha256': _hash([target]), 'effect_verified': ready,
            'evidence': {'spool_manifest_sha256': digest_bytes(raw), 'sealed': spool['sealed'],
                         'source_snapshots': source_snapshots,
                         'reason': 'complete' if complete else 'incomplete_export'},
            'raw_exports': [] if phase == 'preflight' else [export], 'context_updates': {}}

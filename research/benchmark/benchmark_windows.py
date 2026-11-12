"""Finite PowerShell Direct driver; no local probing occurs during validation.

The separately supplied range worker owns guest sessions. Collector credentials
are deliberately different from action credentials; collected XML stays private.
"""
import datetime as dt
import ipaddress
import os
from pathlib import Path, PureWindowsPath
import re
import stat
import uuid

from benchmark_contracts import BenchmarkError, canonical_bytes, confined_file, decode_json, digest_bytes, parse_utc

RECIPES = ('windows-discovery-v1', 'ad-discovery-v1', 'internal-dns-http-v1')
# Must equal benchmark_evidence.CHANNELS and the worker's allowlist (lockstep test).
CHANNELS = ('Security', 'System', 'Microsoft-Windows-Sysmon/Operational',
            'Microsoft-Windows-PowerShell/Operational', 'Windows PowerShell',
            'Microsoft-Windows-TaskScheduler/Operational', 'Microsoft-Windows-WMI-Activity/Operational')
ACTION_ENV = ('BENCH_GUEST_USER', 'BENCH_GUEST_PASSWORD')
COLLECTOR_ENV = ('BENCH_COLLECTOR_USER', 'BENCH_COLLECTOR_PASSWORD')
WORKER = 'Invoke-BenchmarkAction.ps1'
MAX_REQUEST_BYTES = 65536
MAX_RESPONSE_BYTES = 16 * 1024 * 1024
MAX_LEFTOVER_IDS = 50


def _fail(code, field):
    raise BenchmarkError(code, field)


def _keys(value, keys, field):
    if type(value) is not dict or set(value) != set(keys):
        _fail('invalid_fields', field)


def _text(value, pattern, field):
    if type(value) is not str or re.fullmatch(pattern, value, re.ASCII) is None:
        _fail('invalid_value', field)


def _uuid(value, field):
    try:
        if type(value) is not str or str(uuid.UUID(value)) != value:
            _fail('invalid_identity', field)
    except (ValueError, AttributeError):
        _fail('invalid_identity', field)


def _positive(value, maximum, field):
    if type(value) is not int or not 0 < value <= maximum:
        _fail('invalid_limit', field)


def _digest(value, field):
    _text(value, r'[0-9a-f]{64}', field)


def _windows_path(value, field):
    if type(value) is not str or len(value) > 240 or not re.fullmatch(r'[A-Za-z]:\\[^\x00-\x1f<>:"|?*]+', value):
        _fail('unsafe_path', field)
    path = PureWindowsPath(value)
    if any(part in ('.', '..') or part.endswith((' ', '.')) for part in path.parts[1:]):
        _fail('unsafe_path', field)
    return path


def _dns(value, field):
    _text(value, r'(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*', field)


def validate_identity(identity):
    keys = ('vm_id', 'machine_guid', 'computer_name', 'domain', 'synthetic_account', 'internal_endpoint')
    # Optional controller-side enrollment marker for a domain controller target.
    _keys(identity, keys + ('domain_controller',) if 'domain_controller' in identity else keys, 'windows.identity')
    if 'domain_controller' in identity and type(identity['domain_controller']) is not bool:
        _fail('invalid_identity', 'windows.domain_controller')
    _uuid(identity['vm_id'], 'windows.vm_id')
    _uuid(identity['machine_guid'], 'windows.machine_guid')
    _text(identity['computer_name'], r'[A-Za-z0-9][A-Za-z0-9-]{0,62}', 'windows.computer_name')
    _dns(identity['domain'], 'windows.domain')
    account = identity['synthetic_account']
    if account is not None:
        _keys(account, ('sam_account_name', 'sid'), 'windows.synthetic_account')
        _text(account['sam_account_name'], r'[A-Za-z0-9][A-Za-z0-9_.-]{0,19}', 'windows.sam_account_name')
        _text(account['sid'], r'S-1-5-21-[0-9]{1,10}-[0-9]{1,10}-[0-9]{1,10}-[0-9]{1,10}', 'windows.sid')
    endpoint = identity['internal_endpoint']
    if endpoint is not None:
        _keys(endpoint, ('label', 'zone', 'addresses', 'port', 'path'), 'windows.internal_endpoint')
        _text(endpoint['label'], r'[A-Za-z0-9][A-Za-z0-9-]{0,61}[A-Za-z0-9]|[A-Za-z0-9]', 'windows.label')
        _dns(endpoint['zone'], 'windows.zone')
        if '.' not in endpoint['zone']:
            _fail('invalid_identity', 'windows.zone')
        addresses = endpoint['addresses']
        if type(addresses) is not list or not 0 < len(addresses) <= 16 or any(type(address) is not str for address in addresses) or len(set(addresses)) != len(addresses):
            _fail('invalid_identity', 'windows.addresses')
        for address in addresses:
            try:
                parsed = ipaddress.ip_address(address)
                if (str(parsed) != address or parsed.is_unspecified or parsed.is_multicast or parsed.is_loopback
                        or parsed.is_link_local or parsed.is_global):
                    _fail('invalid_identity', 'windows.addresses')
            except (ValueError, TypeError):
                _fail('invalid_identity', 'windows.addresses')
        _positive(endpoint['port'], 65535, 'windows.port')
        _text(endpoint['path'], r'/(?:[A-Za-z0-9_/-]|\.(?!\.)){0,255}', 'windows.path')
        if '..' in endpoint['path']:
            _fail('invalid_value', 'windows.path')


def _executable(spec):
    _keys(spec, ('path', 'sha256', 'version'), 'windows.executable')
    path = _windows_path(spec['path'], 'windows.executable.path')
    if path.name.lower() != 'powershell.exe':
        _fail('unsupported_tool_version', 'windows.executable')
    _digest(spec['sha256'], 'windows.executable.sha256')
    _text(spec['version'], r'5\.1\.[0-9]+\.[0-9]+', 'windows.executable.version')


def _target(manifest, target_id=None):
    targets = manifest['targets']
    selected = targets if target_id is None else [item for item in targets if item['target_id'] == target_id]
    if len(selected) != 1 or selected[0]['kind'] != 'windows':
        _fail('invalid_target', 'windows.target')
    validate_identity(selected[0]['identity'])
    return selected[0]


def validate_configuration(manifest):
    if manifest['recipe_id'] not in RECIPES:
        _fail('unsupported_recipe', 'windows.recipe_id')
    target = _target(manifest)
    executor = manifest['executor']
    if executor['transport'] != 'powershell_direct':
        _fail('unsupported_transport', 'windows.executor')
    _executable(executor['executable'])
    _digest(executor['script_sha256'], 'windows.script_sha256')
    if executor['environment_names'] != list(ACTION_ENV):
        _fail('invalid_environment', 'windows.environment_names')
    _keys(executor['config'], (), 'windows.executor.config')
    if manifest['recipe_id'] == 'ad-discovery-v1' and (target['identity']['synthetic_account'] is None
                                                       or target['identity'].get('domain_controller') is not True):
        _fail('missing_prerequisite', 'windows.synthetic_account')
    if manifest['recipe_id'] == 'internal-dns-http-v1' and target['identity']['internal_endpoint'] is None:
        _fail('missing_prerequisite', 'windows.internal_endpoint')
    for collector in manifest['collectors']:
        if collector['kind'] == 'windows':
            validate_collector(manifest, collector)


def _timestamp(value):
    parsed = parse_utc(value, 'windows.window_utc')
    if parsed.utcoffset() != dt.timedelta(0):
        _fail('invalid_timestamp', 'windows.window_utc')
    return parsed


def event_filter(config):
    """Collected Windows event IDs per channel: exactly what the sealer can map."""
    from benchmark_evidence import supported_event_ids
    channels = set(config['channels']) | {item['channel'] for item in config['evtx_files']}
    return {channel: supported_event_ids(channel) for channel in sorted(channels)}


def validate_collector(manifest, collector):
    _target(manifest, collector['target_id'])
    config = collector['config']
    _keys(config, ('executable', 'script_sha256', 'environment_names', 'channels', 'evtx_files', 'require_process_events'), 'windows.collector.config')
    _executable(config['executable'])
    _digest(config['script_sha256'], 'windows.collector.script_sha256')
    if config['environment_names'] != list(COLLECTOR_ENV):
        _fail('invalid_environment', 'windows.collector.environment_names')
    channels = config['channels']
    if type(channels) is not list or len(channels) > len(CHANNELS) or any(type(item) is not str or item not in CHANNELS for item in channels) or len(set(channels)) != len(channels):
        _fail('unsupported_channel', 'windows.collector.channels')
    if type(config['require_process_events']) is not bool:
        _fail('invalid_boolean', 'windows.collector.require_process_events')
    files = config['evtx_files']
    if type(files) is not list or len(files) > 16 or (not files and not channels):
        _fail('invalid_export', 'windows.collector.evtx_files')
    if collector['bucket'] is not None or collector['prefix'] is not None:
        _fail('invalid_fields', 'windows.collector')
    root = _windows_path(collector['export_root'], 'windows.collector.export_root') if files else None
    if not files and collector['export_root'] is not None:
        _fail('invalid_fields', 'windows.collector.export_root')
    seen = set()
    for item in files:
        _keys(item, ('path', 'sha256', 'channel'), 'windows.collector.evtx_file')
        path = _windows_path(item['path'], 'windows.collector.evtx_file.path')
        if path.suffix.lower() != '.evtx' or item['channel'] not in CHANNELS:
            _fail('unsupported_channel', 'windows.collector.evtx_file')
        try:
            path.relative_to(root)
        except ValueError:
            _fail('path_escape', 'windows.collector.evtx_file')
        if str(path).lower() in seen:
            _fail('duplicate_file', 'windows.collector.evtx_file')
        seen.add(str(path).lower())
        _digest(item['sha256'], 'windows.collector.evtx_file.sha256')
    _positive(collector['max_bytes'], MAX_RESPONSE_BYTES, 'windows.collector.max_bytes')
    _positive(collector['max_seconds'], 3600, 'windows.collector.max_seconds')
    window = collector['window_utc']
    _keys(window, ('start_inclusive', 'end_exclusive'), 'windows.window_utc')
    if _timestamp(window['start_inclusive']) >= _timestamp(window['end_exclusive']):
        _fail('invalid_window', 'windows.window_utc')
    if collector['watermark_utc'] is not None:
        _timestamp(collector['watermark_utc'])


def phase_steps(manifest, phase, context):
    validate_configuration(manifest)
    if phase == 'preflight':
        return ['identity']
    if phase == 'run':
        return [manifest['recipe_id']]
    if phase == 'cleanup':
        return ['session_check']
    return []


def _since(target, context):
    """Campaign start, widened earlier by the target's recorded clock offset/uncertainty."""
    started = context.get('campaign_started_utc')
    if started is None:
        _fail('missing_prerequisite', 'windows.campaign_started_utc')
    clock = target.get('clock', {})
    margin = abs(clock.get('offset_seconds', 0)) + clock.get('uncertainty_seconds', 0)
    since = parse_utc(started, 'windows.campaign_started_utc') - dt.timedelta(seconds=margin)
    return since.astimezone(dt.timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%fZ')


def build_request(manifest, phase, step_id, context):
    """Pure fixed worker request, also used by offline contract tests."""
    collector = context.get('collector') if phase in ('collect', 'preflight') else None
    if collector is not None:
        validate_collector(manifest, collector)
        if step_id != collector['source_id']:
            _fail('unsupported_step', 'windows.step_id')
        target = _target(manifest, collector['target_id'])
        spec = collector['config']
        operation = 'collector_probe' if phase == 'preflight' else 'collect'
        seconds = min(collector['max_seconds'], manifest['limits']['max_phase_seconds'])
        maximum = min(collector['max_bytes'], manifest['limits']['max_export_bytes'], MAX_RESPONSE_BYTES)
        collection = {key: collector[key] for key in ('source_id', 'export_root', 'window_utc', 'watermark_utc')}
        collection.update({key: spec[key] for key in ('channels', 'evtx_files', 'require_process_events')})
        collection['event_ids'] = event_filter(spec)
    else:
        validate_configuration(manifest)
        if step_id not in phase_steps(manifest, phase, context):
            _fail('unsupported_step', 'windows.step_id')
        target = _target(manifest)
        spec = manifest['executor']
        operation = {'preflight': 'identity', 'run': manifest['recipe_id'], 'cleanup': 'session_check'}[phase]
        seconds = manifest['limits']['max_phase_seconds']
        maximum = min(manifest['limits']['max_export_bytes'], MAX_RESPONSE_BYTES)
        collection = None
    _positive(seconds, 3600, 'windows.max_seconds')
    _positive(maximum, MAX_RESPONSE_BYTES, 'windows.max_bytes')
    if maximum < 4096:
        _fail('invalid_limit', 'windows.max_bytes')
    # The guest-side request never carries controller-only enrollment markers.
    identity = {key: value for key, value in target['identity'].items() if key != 'domain_controller'}
    request = {'schema_version': 1, 'operation': operation, 'identity': identity,
               'powershell_version': spec['executable']['version'], 'max_seconds': seconds,
               'max_bytes': maximum, 'collector': collection,
               'since_utc': _since(target, context) if operation == 'session_check' else None}
    if len(canonical_bytes(request)) > MAX_REQUEST_BYTES:
        _fail('request_too_large', 'windows.request')
    return request


def _verified_local(path, expected):
    candidate = Path(path)
    if not candidate.is_absolute():
        _fail('unsafe_path', 'windows.executable')
    for part in (candidate,) + tuple(candidate.parents):
        try:
            info = part.lstat()
        except OSError:
            _fail('missing_prerequisite', 'windows.executable')
        if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
            _fail('path_alias', 'windows.executable')
    info = candidate.stat()
    # st_nlink > 1 is accepted: inbox System32 binaries are WinSxS hard links and
    # the SHA-256 pin binds the bytes; components are still symlink/reparse-checked.
    if not stat.S_ISREG(info.st_mode):
        _fail('path_alias', 'windows.executable')
    try:
        actual = digest_bytes(candidate.read_bytes())
    except OSError:
        _fail('missing_prerequisite', 'windows.executable')
    if actual != expected:
        _fail('digest_mismatch', 'windows.executable')
    return str(candidate)


def _environment(names):
    if os.name != 'nt':
        _fail('unsupported_platform', 'windows.transport')
    import ctypes
    buffer = ctypes.create_unicode_buffer(32768)
    if not ctypes.windll.kernel32.GetWindowsDirectoryW(buffer, len(buffer)):
        _fail('missing_prerequisite', 'windows.system_root')
    root = buffer.value
    name_size = ctypes.c_ulong(len(buffer))
    if not ctypes.windll.kernel32.GetComputerNameW(buffer, ctypes.byref(name_size)):
        _fail('missing_prerequisite', 'windows.computer_name')
    environment = {'SystemRoot': root, 'WINDIR': root, 'COMPUTERNAME': buffer.value,
                   'PATH': root + '\\System32;' + root + '\\System32\\WindowsPowerShell\\v1.0',
                   'PSModulePath': root + '\\System32\\WindowsPowerShell\\v1.0\\Modules'}
    for name in names:
        value = os.environ.get(name)
        if not value or len(value) > 4096 or '\x00' in value:
            _fail('missing_credential', 'windows.credentials')
        environment[name] = value
    return environment


def _result(outcome, reason=None, transport_exit=None):
    return {'execution_outcome': outcome, 'observed_target_sha256': None,
            'effect_verified': False, 'evidence': {'reason': reason, 'transport_exit': transport_exit},
            'raw_exports': [], 'context_updates': {}}


def _leftovers(response, operation):
    """Strict session_check report: counts and bounded guest PIDs, never names or command lines."""
    value = response['leftovers']
    if operation != 'session_check' or value is None:
        # A check that failed before inspection reports nothing; it is never a pass.
        if value is not None or (operation == 'session_check' and (
                response['execution_outcome'] == 'succeeded' or response['failure_reason'] == 'owned_leftovers_found')):
            _fail('invalid_response', 'windows.leftovers')
        return
    _keys(value, ('process_count', 'session_count', 'process_ids'), 'windows.leftovers')
    for key in ('process_count', 'session_count'):
        if type(value[key]) is not int or not 0 <= value[key] <= 1000000:
            _fail('invalid_response', 'windows.leftovers')
    ids = value['process_ids']
    if (type(ids) is not list or any(type(pid) is not int or pid < 0 for pid in ids) or ids != sorted(set(ids))
            or len(ids) != min(value['process_count'], MAX_LEFTOVER_IDS)):
        _fail('invalid_response', 'windows.leftovers')
    # A leftover session is a logon session that still holds account processes.
    if (value['session_count'] == 0) != (value['process_count'] == 0) or value['session_count'] > value['process_count']:
        _fail('invalid_response', 'windows.leftovers')
    found = value['process_count'] > 0
    if found != (response['failure_reason'] == 'owned_leftovers_found') or (found and response['execution_outcome'] != 'failed'):
        _fail('invalid_response', 'windows.leftovers')
    if response['effect_checks'].get('no_owned_leftovers') is not (not found):
        _fail('invalid_response', 'windows.leftovers')


def execute_step(manifest, range_kit, phase, step_id, context, transport):
    request = build_request(manifest, phase, step_id, context)
    collector = context.get('collector') if phase in ('collect', 'preflight') else None
    spec = collector['config'] if collector else manifest['executor']
    try:
        executable = _verified_local(spec['executable']['path'], spec['executable']['sha256'])
        worker = confined_file(range_kit, WORKER, 'windows.worker')
        if digest_bytes(worker.read_bytes()) != spec['script_sha256']:
            _fail('digest_mismatch', 'windows.script_sha256')
        environment = _environment(COLLECTOR_ENV if collector else ACTION_ENV)
    except BenchmarkError as error:
        # Nothing was launched: a refused prerequisite is blocked, not unknown.
        return _result('blocked', error.code)
    except OSError:
        return _result('blocked', 'missing_prerequisite')
    # Execution policy is bypassed only for this one pinned, SHA-256-verified
    # worker file; no profile, other script, or persistent policy change.
    process = transport([executable, '-NoLogo', '-NoProfile', '-NonInteractive',
                         '-ExecutionPolicy', 'Bypass', '-File', str(worker)],
                        input_bytes=canonical_bytes(request), env=environment,
                        timeout=request['max_seconds'], max_output_bytes=request['max_bytes'])
    if process['status'] != 'succeeded' or process['exit_code'] != 0:
        return _result('unknown' if process['status'] == 'unknown' else 'failed', 'worker_transport_failed', process.get('exit_code'))
    try:
        response = decode_json(process['stdout'])
        _keys(response, ('schema_version', 'execution_outcome', 'identity_verified', 'action_exits',
                         'effect_checks', 'gaps', 'records', 'complete', 'session_closed', 'watermark_utc',
                         'failure_reason', 'leftovers'), 'windows.response')
        if type(response['schema_version']) is not int or response['schema_version'] != 1 or response['execution_outcome'] not in ('succeeded', 'blocked', 'failed', 'unknown'):
            _fail('invalid_response', 'windows.response')
        for key in ('identity_verified', 'complete', 'session_closed'):
            if type(response[key]) is not bool:
                _fail('invalid_response', 'windows.response')
        if type(response['action_exits']) is not dict or type(response['effect_checks']) is not dict:
            _fail('invalid_response', 'windows.response')
        allowed_actions = {'whoami', 'hostname', 'processes', 'ad_domain', 'ad_user', 'dns', 'http'}
        if not set(response['action_exits']).issubset(allowed_actions) or any(type(value) is not int for value in response['action_exits'].values()):
            _fail('invalid_response', 'windows.response')
        allowed_effects = {'identity', 'whoami_identity', 'hostname_identity', 'process_snapshot', 'ad_domain_identity', 'ad_account_identity', 'dns_authorized', 'http_response', 'collector_read', 'session_cleanup', 'no_owned_leftovers'}
        if not set(response['effect_checks']).issubset(allowed_effects) or any(type(value) is not bool for value in response['effect_checks'].values()):
            _fail('invalid_response', 'windows.response')
        if type(response['gaps']) is not list or any(gap not in ('process_instrumentation_absent', 'process_events_absent', 'incomplete_export') for gap in response['gaps']):
            _fail('invalid_response', 'windows.response')
        reasons = (None, 'invalid_request', 'unsupported_tool_version', 'hyperv_prerequisite', 'identity_mismatch', 'credential_unavailable', 'guest_operation_failed', 'collector_unavailable', 'incomplete_export', 'output_limit', 'session_cleanup_failed', 'deadline_exceeded', 'owned_leftovers_found')
        if response['failure_reason'] not in reasons or type(response['records']) is not list:
            _fail('invalid_response', 'windows.response')
        if response['execution_outcome'] == 'succeeded' and response['failure_reason'] is not None:
            _fail('invalid_response', 'windows.response')
        _leftovers(response, request['operation'])
        if response['watermark_utc'] is not None:
            watermark = _timestamp(response['watermark_utc'])
            clock = _target(manifest, collector['target_id']).get('clock', {}) if collector else {}
            uncertainty = abs(clock.get('offset_seconds', 0)) + clock.get('uncertainty_seconds', 0)
            if not collector or watermark > dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=uncertainty) or collector['watermark_utc'] is None or watermark > _timestamp(collector['watermark_utc']):
                _fail('invalid_response', 'windows.watermark_utc')
        if phase == 'collect' and response['complete'] and (response['watermark_utc'] is None or _timestamp(response['watermark_utc']) < _timestamp(collector['window_utc']['end_exclusive'])):
            _fail('invalid_response', 'windows.watermark_utc')
        seen = set()
        for record in response['records']:
            _keys(record, ('channel', 'provider', 'record_id', 'event_id', 'timestamp_utc', 'xml'), 'windows.record')
            if record['channel'] not in CHANNELS or type(record['record_id']) is not int or type(record['event_id']) is not int or type(record['provider']) is not str or type(record['xml']) is not str:
                _fail('invalid_response', 'windows.record')
            when = _timestamp(record['timestamp_utc'])
            if not collector or not (_timestamp(collector['window_utc']['start_inclusive']) <= when < _timestamp(collector['window_utc']['end_exclusive'])):
                _fail('invalid_response', 'windows.record')
            if record['event_id'] not in request['collector']['event_ids'].get(record['channel'], ()):
                _fail('invalid_response', 'windows.record')
            # Same identity as the worker and the sealer: channel:record_id:sha256(xml).
            identity = (record['channel'], record['record_id'], digest_bytes(record['xml'].encode('utf-8')))
            if identity in seen:
                _fail('invalid_response', 'windows.record')
            seen.add(identity)
    except (BenchmarkError, UnicodeError):
        return _result('unknown', 'invalid_worker_response', process['exit_code'])
    outcome = response['execution_outcome']
    verified = response['identity_verified'] and response['session_closed'] and bool(response['effect_checks']) and all(response['effect_checks'].values())
    expected = {'windows-discovery-v1': {'whoami', 'hostname', 'processes'}, 'ad-discovery-v1': {'ad_domain', 'ad_user'}, 'internal-dns-http-v1': {'dns', 'http'}}.get(request['operation'], set())
    verified = verified and set(response['action_exits']) == expected and all(value == 0 for value in response['action_exits'].values())
    required_effects = {'identity', 'session_cleanup'}
    required_effects.update({
        'windows-discovery-v1': {'whoami_identity', 'hostname_identity', 'process_snapshot'},
        'ad-discovery-v1': {'ad_domain_identity', 'ad_account_identity'},
        'internal-dns-http-v1': {'dns_authorized', 'http_response'},
        'collect': {'collector_read'}, 'collector_probe': {'collector_read'},
        'session_check': {'no_owned_leftovers'},
    }.get(request['operation'], set()))
    verified = verified and required_effects.issubset(response['effect_checks'])
    if outcome == 'succeeded' and (not verified or (phase == 'collect' and not response['complete'])):
        outcome = 'unknown'
    # An unclosed or unverified guest session leaves remote state uncertain.
    if not response['session_closed']:
        outcome = 'unknown'
    result = _result(outcome, response['failure_reason'])
    result['effect_verified'] = verified and outcome == 'succeeded'
    target = _target(manifest, collector['target_id']) if collector else _target(manifest)
    if response['identity_verified'] and response['failure_reason'] != 'identity_mismatch':
        result['observed_target_sha256'] = digest_bytes(canonical_bytes([target]))
    result['evidence'].update({'action_exits': response['action_exits'], 'effect_checks': response['effect_checks'],
                               'gaps': response['gaps'], 'session_closed': response['session_closed'],
                               'transport_exit': process['exit_code'], 'worker_sha256': spec['script_sha256'],
                               'powershell_version': spec['executable']['version']})
    if response['leftovers'] is not None:
        result['evidence']['leftovers'] = response['leftovers']
    if not collector:
        declared_channels = set()
        for source in manifest['collectors']:
            if source['kind'] == 'windows' and source['target_id'] == target['target_id']:
                declared_channels.update(source['config']['channels'])
                declared_channels.update(item['channel'] for item in source['config']['evtx_files'])
        if not declared_channels.intersection(('Security', 'Microsoft-Windows-Sysmon/Operational')):
            result['evidence']['gaps'] = sorted(set(result['evidence']['gaps'] + ['process_instrumentation_absent']))
    if phase == 'collect' and collector and verified and outcome in ('succeeded', 'failed') and response['failure_reason'] in (None, 'incomplete_export'):
        result['raw_exports'] = [{'source_id': collector['source_id'], 'records': response['records'],
                                  'window_utc': collector['window_utc'], 'watermark_utc': response['watermark_utc'],
                                  'complete': response['complete'],
                                  'filter': {'event_ids': request['collector']['event_ids']}}]
    return result

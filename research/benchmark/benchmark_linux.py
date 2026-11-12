"""Pinned, explicitly provisioned two-hop Linux benchmark transport.

SSH configuration files must be empty or comment-only: all effective options are
fixed here. Provision forced-command logins with restrict,no-pty,no-port-forwarding
and a dedicated worker enrollment for each action/read identity. Nothing in this
module provisions a worker, key, account, host key, sensor, or firewall rule.
"""
import hashlib
import ipaddress
import os
import re
import stat
from pathlib import Path

from benchmark_contracts import BenchmarkError, canonical_bytes, decode_json, parse_utc

ROUTE_FIELDS = {'host', 'port', 'user', 'machine_id', 'enrollment_sha256',
                'ssh_config', 'known_hosts', 'identity_file'}
IDENTITY_FIELDS = {'host', 'port', 'user', 'machine_id'}
LEFTOVER_FACTS = {'account_processes_remaining', 'account_sessions_remaining', 'account_process_ids'}
MAX_PID = 4194304
_DIGEST = re.compile(r'[0-9a-f]{64}\Z')
_USER = re.compile(r'[a-z_][a-z0-9_-]{0,31}\Z')
_MACHINE = re.compile(r'[0-9a-f]{32}\Z')


def _fail(code='invalid_linux_configuration'):
    raise BenchmarkError(code, 'linux')


def _fields(value, fields):
    if type(value) is not dict or set(value) != set(fields):
        _fail()


def _digest(value):
    if type(value) is not str or not _DIGEST.fullmatch(value):
        _fail()


def _path(value):
    if type(value) is not str or not Path(value).is_absolute() or '\x00' in value:
        _fail()
    # Local pins only: a Windows drive path, never a UNC/device share.
    if os.name == 'nt' and (not re.fullmatch(r'[A-Za-z]:', Path(value).drive)
                            or any(':' in part for part in Path(value).parts[1:])):
        _fail('unsafe_path')


def _pin(value, executable=False):
    _fields(value, {'path', 'sha256', 'version'} if executable else {'path', 'sha256'})
    _path(value['path'])
    _digest(value['sha256'])
    if executable and (type(value['version']) is not str or not value['version']):
        _fail()
    if executable and Path(value['path']).suffix.lower() in ('.cmd', '.bat'):
        _fail()


def _identity(value):
    _fields(value, IDENTITY_FIELDS)
    if type(value['user']) is not str or not _USER.fullmatch(value['user']):
        _fail()
    if type(value['machine_id']) is not str or not _MACHINE.fullmatch(value['machine_id']):
        _fail()
    if type(value['port']) is not int or not 1 <= value['port'] <= 65535:
        _fail()
    try:
        address = ipaddress.ip_address(value['host'])
        if address.is_unspecified or address.is_multicast or '%' in value['host']:
            _fail()
    except (ValueError, TypeError):
        _fail()


def _route(value):
    _fields(value, ROUTE_FIELDS)
    _identity({key: value[key] for key in IDENTITY_FIELDS})
    _digest(value['enrollment_sha256'])
    for name in ('ssh_config', 'known_hosts', 'identity_file'):
        _pin(value[name])
    if len({value[key]['path'] for key in ('ssh_config', 'known_hosts', 'identity_file')}) != 3:
        _fail()


def validate_collector(manifest, collector):
    """Validate a Linux collector, including one used by a different recipe."""
    config = collector['config']
    _fields(config, {'executable', 'script_sha256', 'route', 'target_user'})
    _pin(config['executable'], True)
    _digest(config['script_sha256'])
    _route(config['route'])
    if type(config['target_user']) is not str or not _USER.fullmatch(config['target_user']):
        _fail()
    targets = [t for t in manifest['targets'] if t['target_id'] == collector['target_id']]
    if len(targets) != 1 or targets[0]['kind'] != 'linux':
        _fail()
    _identity(targets[0]['identity'])
    if config['target_user'] == targets[0]['identity']['user']:
        _fail('independent_collector_required')
    if collector['bucket'] is not None or collector['prefix'] is not None or collector['export_root'] is not None:
        _fail()
    executor = manifest['executor']
    if executor['transport'] == 'ssh_worker':
        action = executor['config']
        if (config['route']['user'] == action['user'] or
                config['route']['identity_file']['sha256'] == action['identity_file']['sha256'] or
                config['route']['enrollment_sha256'] == action['enrollment_sha256']):
            _fail('independent_collector_required')


def validate_configuration(manifest):
    if manifest['recipe_id'] != 'linux-discovery-v1' or len(manifest['targets']) != 1:
        _fail()
    target = manifest['targets'][0]
    if target['kind'] != 'linux':
        _fail()
    _identity(target['identity'])
    executor = manifest['executor']
    if executor['transport'] != 'ssh_worker' or executor['environment_names'] != []:
        _fail()
    _pin(executor['executable'], True)
    _digest(executor['script_sha256'])
    _route(executor['config'])
    for collector in manifest['collectors']:
        if collector['kind'] == 'linux':
            validate_collector(manifest, collector)


def phase_steps(manifest, phase, context):
    validate_configuration(manifest)
    steps = {'preflight': ['identity'], 'run': ['discovery'],
             'cleanup': ['close_sessions'], 'stop': ['close_sessions']}
    if phase == 'collect':
        return [c['source_id'] for c in manifest['collectors'] if c['kind'] == 'linux']
    if phase not in steps:
        _fail('unsupported_phase')
    return steps[phase]


def _windows_private_acl(path):
    """Require current ownership and no grants outside owner/SYSTEM/admins."""
    import ctypes
    from ctypes import wintypes as wt
    adv = ctypes.WinDLL('advapi32', use_last_error=True)
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    pointer = ctypes.c_void_p
    adv.GetNamedSecurityInfoW.argtypes = [wt.LPWSTR, wt.DWORD, wt.DWORD,
                                        ctypes.POINTER(pointer), pointer,
                                        ctypes.POINTER(pointer), pointer, ctypes.POINTER(pointer)]
    adv.GetNamedSecurityInfoW.restype = wt.DWORD
    adv.OpenProcessToken.argtypes = [wt.HANDLE, wt.DWORD, ctypes.POINTER(wt.HANDLE)]
    adv.GetTokenInformation.argtypes = [wt.HANDLE, ctypes.c_int, pointer, wt.DWORD, ctypes.POINTER(wt.DWORD)]
    adv.EqualSid.argtypes = [pointer, pointer]
    adv.GetAce.argtypes = [pointer, wt.DWORD, ctypes.POINTER(pointer)]
    adv.ConvertSidToStringSidW.argtypes = [pointer, ctypes.POINTER(wt.LPWSTR)]
    kernel.GetCurrentProcess.restype = wt.HANDLE
    kernel.CloseHandle.argtypes = [wt.HANDLE]
    kernel.LocalFree.argtypes = [pointer]
    token, owner, dacl, descriptor = wt.HANDLE(), pointer(), pointer(), pointer()
    try:
        if not adv.OpenProcessToken(kernel.GetCurrentProcess(), 8, ctypes.byref(token)):
            _fail('unsafe_permissions')
        needed = wt.DWORD()
        adv.GetTokenInformation(token, 1, None, 0, ctypes.byref(needed))
        user = ctypes.create_string_buffer(needed.value)
        if not adv.GetTokenInformation(token, 1, user, needed, ctypes.byref(needed)):
            _fail('unsafe_permissions')
        user_sid = ctypes.cast(user, ctypes.POINTER(pointer))[0]
        if adv.GetNamedSecurityInfoW(str(path), 1, 5, ctypes.byref(owner), None,
                                    ctypes.byref(dacl), None, ctypes.byref(descriptor)) != 0:
            _fail('unsafe_permissions')
        if not dacl or not adv.EqualSid(owner, user_sid):
            _fail('unsafe_permissions')
        # ACL header: revision, reserved byte, size WORD, ACE count WORD.
        count = ctypes.c_ushort.from_address(dacl.value + 4).value
        for index in range(count):
            ace = pointer()
            if not adv.GetAce(dacl, index, ctypes.byref(ace)):
                _fail('unsafe_permissions')
            kind = ctypes.c_ubyte.from_address(ace.value).value
            flags = ctypes.c_ubyte.from_address(ace.value + 1).value
            if flags & 8 or kind == 1:  # inherit-only or deny ACE
                continue
            if kind != 0:  # object/callback/conditional grants unsupported
                _fail('unsafe_permissions')
            sid = pointer(ace.value + 8)
            if adv.EqualSid(sid, user_sid):
                continue
            text = wt.LPWSTR()
            if not adv.ConvertSidToStringSidW(sid, ctypes.byref(text)):
                _fail('unsafe_permissions')
            try:
                if text.value not in ('S-1-5-18', 'S-1-5-32-544'):
                    _fail('unsafe_permissions')
            finally:
                kernel.LocalFree(ctypes.cast(text, pointer))
    finally:
        if descriptor:
            kernel.LocalFree(descriptor)
        if token:
            kernel.CloseHandle(token)


def _checked_file(pin, secret=False):
    path = Path(pin['path'])
    if not path.is_absolute():
        _fail('unsafe_path')
    for part in (path,) + tuple(path.parents):
        info = part.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
            _fail('unsafe_path')
        if os.name == 'posix' and info.st_mode & 0o022:
            trusted_sticky_root = stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and info.st_mode & stat.S_ISVTX
            if not trusted_sticky_root:
                _fail('unsafe_permissions')
    info = path.stat()
    if not stat.S_ISREG(info.st_mode):
        _fail('unsafe_path')
    if os.name == 'posix' and (info.st_uid not in (0, os.geteuid()) or
                               (secret and info.st_mode & 0o077) or info.st_mode & 0o022):
        _fail('unsafe_permissions')
    if os.name == 'nt' and secret:
        _windows_private_acl(path)
    with path.open('rb') as stream:
        digest = hashlib.sha256()
        while True:
            chunk = stream.read(65536)
            if not chunk:
                break
            digest.update(chunk)
    if digest.hexdigest() != pin['sha256']:
        _fail('tool_hash_mismatch')
    return path


def ssh_argv(executable, route):
    _checked_file(executable)
    config = _checked_file(route['ssh_config'], True)
    _checked_file(route['known_hosts'], True)
    _checked_file(route['identity_file'], True)
    if config.stat().st_size > 65536:
        _fail('unsafe_ssh_configuration')
    for line in config.read_text(encoding='utf-8').splitlines():
        if line.strip() and not line.lstrip().startswith('#'):
            _fail('unsafe_ssh_configuration')
    options = ('BatchMode=yes', 'StrictHostKeyChecking=yes', 'IdentitiesOnly=yes',
               'ForwardAgent=no', 'ClearAllForwardings=yes', 'RequestTTY=no',
               'PermitLocalCommand=no', 'ProxyCommand=none', 'ProxyJump=none',
               'PasswordAuthentication=no', 'KbdInteractiveAuthentication=no',
               'ControlMaster=no', 'ControlPath=none', 'ConnectionAttempts=1',
               'ConnectTimeout=10', 'UpdateHostKeys=no', 'VerifyHostKeyDNS=no')
    argv = [executable['path'], '-F', str(config), '-T']
    for option in options:
        argv.extend(['-o', option])
    argv.extend(['-o', 'UserKnownHostsFile=' + route['known_hosts']['path'],
                 '-o', 'GlobalKnownHostsFile=' + ('NUL' if os.name == 'nt' else '/dev/null'),
                 '-i', route['identity_file']['path'], '-p', str(route['port']),
                 '-l', route['user'], route['host']])
    # Deliberately no remote command. The enrolled login MUST force the worker.
    return argv


def _ssh_environment():
    """Minimal ssh environment: nothing inherited except the Windows system root
    (Winsock provider paths are stored as %SystemRoot%\\...)."""
    if os.name != 'nt':
        return {}
    root = os.environ.get('SystemRoot', '')
    if not re.fullmatch(r'[A-Za-z]:\\[^\x00-\x1f;]*', root):
        _fail('missing_prerequisite')
    return {'SystemRoot': root, 'WINDIR': root, 'PATH': str(Path(root) / 'System32')}


def _result(outcome, evidence, verified=False, observed=None, exports=None):
    return {'execution_outcome': outcome, 'observed_target_sha256': observed,
            'effect_verified': verified, 'evidence': evidence,
            'raw_exports': exports or [], 'context_updates': {}}


def _leftovers(data, operation):
    """close_sessions reports counts and bounded PIDs of the dedicated account only."""
    facts = data['facts']
    present = LEFTOVER_FACTS & set(facts)
    if operation != 'close_sessions' or facts.get('identity_verified') is not True:
        if present or facts.get('reason') == 'owned_leftovers_found':
            _fail('invalid_worker_response')
        return
    if present != LEFTOVER_FACTS:
        _fail('invalid_worker_response')
    processes, sessions, ids = (facts['account_processes_remaining'], facts['account_sessions_remaining'],
                                facts['account_process_ids'])
    if any(type(value) is not int or not 0 <= value <= MAX_PID for value in (processes, sessions)):
        _fail('invalid_worker_response')
    if (type(ids) is not list or any(type(pid) is not int or not 0 < pid <= MAX_PID for pid in ids)
            or ids != sorted(set(ids)) or len(ids) != min(processes, 50)):
        _fail('invalid_worker_response')
    if (sessions == 0) != (processes == 0) or sessions > processes:
        _fail('invalid_worker_response')
    found = processes > 0
    if found != (facts.get('reason') == 'owned_leftovers_found') or (found and data['outcome'] != 'failed'):
        _fail('invalid_worker_response')


def execute_step(manifest, range_kit, phase, step_id, context, transport):
    """Dispatch only after the controller has reserved this exact operation."""
    collector = context.get('collector') if phase in ('collect', 'preflight') else None
    if collector is not None:
        validate_collector(manifest, collector)
        if step_id != collector['source_id']:
            _fail('unsupported_step')
        config = collector['config']
        executable, route = config['executable'], config['route']
        script_hash = config['script_sha256']
        target = next(t for t in manifest['targets'] if t['target_id'] == collector['target_id'])
        identity = dict(target['identity'], user=config['target_user'])
        operation = 'collect' if phase == 'collect' else 'collector_identity'
        window = collector['window_utc'] if phase == 'collect' else None
        max_bytes = min(collector['max_bytes'], manifest['limits']['max_export_bytes'])
        seconds = min(collector['max_seconds'], manifest['limits']['max_phase_seconds'])
    else:
        if step_id not in phase_steps(manifest, phase, context):
            _fail('unsupported_step')
        executable = manifest['executor']['executable']
        route = manifest['executor']['config']
        script_hash = manifest['executor']['script_sha256']
        identity = manifest['targets'][0]['identity']
        operation, window = step_id, None
        max_bytes = manifest['limits']['max_export_bytes']
        seconds = manifest['limits']['max_phase_seconds']
    attempted = False
    try:
        if not 1024 <= max_bytes <= 64 * 1024 * 1024 or not 0 < seconds <= 3600:
            _fail('unsupported_linux_limits')
        try:
            _checked_file({'path': str(Path(range_kit) / 'linux_worker.py'), 'sha256': script_hash})
        except FileNotFoundError:
            _fail('range_kit_missing')
        argv = ssh_argv(executable, route)
        request = {'schema_version': 1, 'worker_sha256': script_hash,
                   'enrollment_sha256': route['enrollment_sha256'],
                   'executor_identity': {key: route[key] for key in ('machine_id', 'user')},
                   'target': identity, 'operation': operation, 'window_utc': window,
                   'max_bytes': max_bytes, 'max_seconds': seconds}
        environment = _ssh_environment()
        attempted = True
        response = transport(argv, input_bytes=canonical_bytes(request), env=environment,
                             timeout=seconds, max_output_bytes=max_bytes)
        if response['status'] != 'succeeded' or response['exit_code'] != 0:
            return _result('unknown' if operation == 'discovery' or response['status'] == 'unknown' else 'blocked',
                           {'reason': 'linux_transport_failed', 'remote_effects_unknown': operation == 'discovery',
                            'transport_exit': response.get('exit_code')})
        data = decode_json(response['stdout'])
        _fields(data, {'schema_version', 'operation', 'outcome', 'executor_identity',
                       'target', 'effect_verified', 'facts', 'records', 'watermark_utc', 'complete'})
        if (type(data['schema_version']) is not int or data['schema_version'] != 1 or data['operation'] != operation or
                data['executor_identity'] != request['executor_identity'] or data['target'] != identity or
                data['outcome'] not in ('succeeded', 'blocked', 'failed', 'unknown') or
                type(data['effect_verified']) is not bool or type(data['complete']) is not bool or
                type(data['facts']) is not dict or type(data['records']) is not list):
            _fail('invalid_worker_response')
        # Only explicit, finite facts can enter controller receipts, never remote
        # command output, arbitrary diagnostics or environment/authentication data.
        allowed = {'identity_verified', 'id_verified', 'uname_verified', 'process_count',
                   'owned_sessions_remaining', 'process_coverage', 'gaps', 'reason'} | LEFTOVER_FACTS
        if set(data['facts']) - allowed:
            _fail('invalid_worker_response')
        for key, value in data['facts'].items():
            if key in ('identity_verified', 'id_verified', 'uname_verified', 'process_coverage') and type(value) is not bool:
                _fail('invalid_worker_response')
            if key in ('process_count', 'owned_sessions_remaining') and (type(value) is not int or not 0 <= value <= 50):
                _fail('invalid_worker_response')
            if key == 'gaps' and (type(value) is not list or any(item not in ('missing_audit_export', 'incomplete_export') for item in value)):
                _fail('invalid_worker_response')
            if key == 'reason' and value not in ('invalid_request', 'identity_mismatch', 'unsupported_operation', 'unsafe_path', 'tool_hash_mismatch', 'unsafe_permissions', 'unsafe_ssh_configuration', 'worker_failed', 'incomplete_export', 'output_limit', 'timeout', 'enrollment_mismatch', 'owned_leftovers_found'):
                _fail('invalid_worker_response')
        success = data['outcome'] == 'succeeded' and data['effect_verified'] and data['facts'].get('identity_verified') is True
        if data['outcome'] == 'succeeded' and not success:
            _fail('invalid_worker_response')
        if success and data['facts'].get('owned_sessions_remaining') != 0:
            _fail('invalid_worker_response')
        if success and operation == 'discovery' and (
                data['facts'].get('id_verified') is not True or
                data['facts'].get('uname_verified') is not True or
                'process_count' not in data['facts']):
            _fail('invalid_worker_response')
        _leftovers(data, operation)
        if success and operation == 'collect' and not data['complete']:
            _fail('invalid_worker_response')
        exports = []
        if collector is not None and phase == 'collect' and data['facts'].get('identity_verified') is True:
            start = parse_utc(window['start_inclusive'], 'linux.window')
            end = parse_utc(window['end_exclusive'], 'linux.window')
            watermark = parse_utc(data['watermark_utc'], 'linux.watermark')
            if data['complete'] and watermark < end:
                _fail('invalid_worker_response')
            seen = set()
            for record in data['records']:
                _fields(record, {'source_type', 'record_id', 'timestamp_utc', 'record'})
                if (record['source_type'] not in ('journald', 'linux-audit') or
                        type(record['record_id']) is not str or not record['record_id'] or
                        type(record['record']) is not dict or
                        not start <= parse_utc(record['timestamp_utc'], 'linux.record') < end):
                    _fail('invalid_worker_response')
                key = (record['source_type'], record['record_id'])
                if key in seen:
                    _fail('invalid_worker_response')
                seen.add(key)
            exports.append({'source_id': collector['source_id'], 'records': data['records'],
                            'window_utc': window, 'watermark_utc': data['watermark_utc'],
                            'complete': data['complete'], 'filter': None})
        elif data['records']:
            _fail('invalid_worker_response')
        observed = hashlib.sha256(canonical_bytes(manifest['targets'])).hexdigest() if data['facts'].get('identity_verified') is True and len(manifest['targets']) == 1 else None
        return _result(data['outcome'], dict(data['facts'], transport_exit=response['exit_code']), success, observed, exports)
    except BenchmarkError as error:
        return _result('unknown' if attempted and operation == 'discovery' else 'blocked', {'reason': error.code})
    except (OSError, ValueError, KeyError, TypeError, StopIteration):
        return _result('unknown' if attempted and operation == 'discovery' else 'blocked', {'reason': 'invalid_worker_response'})

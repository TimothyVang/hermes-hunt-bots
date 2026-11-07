"""Explicit, human-owned first-use setup; status never downloads or repairs.

Only fixed public artifacts and the bundled synthetic fixture enter the guest.
There is no URL, command, credential, provider, or model configuration API.
"""
from __future__ import annotations

import contextlib
import ctypes
from ctypes import wintypes
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import struct
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
import uuid

if __package__:
    from . import runtime, prepare_guest
else:
    # -I child: never import the plugin entrypoint or ambient user packages.
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import runtime
    import prepare_guest

PROFILE = runtime.PROFILE
SOURCE = Path(__file__).resolve().parent
SETUP_SECONDS = 3600
BOOTSTRAP_GRACE = 15
PUBLIC_STAGES = {
    "queued", "preflight", "downloading_7zr", "downloading_7zip",
    "downloading_qemu", "downloading_ubuntu", "downloading_pycdlib",
    "extracting_runtime", "preparing_media", "publishing", "starting",
    "prepared", "failed", "cancelled",
}


class SetupFailure(Exception):
    """Nonsecret public reason code."""


def _read(path, maximum=65536):
    prepare_guest.source_file(path)
    with path.open('rb') as stream:
        data = stream.read(maximum + 1)
    if len(data) > maximum:
        raise SetupFailure('invalid_setup_state')
    value = json.loads(data)
    if not isinstance(value, dict):
        raise SetupFailure('invalid_setup_state')
    return value


def _atomic(path, value):
    prepare_guest.local_path(path)
    if path.exists():
        prepare_guest.source_file(path)
    temporary = path.parent / ('.write-' + uuid.uuid4().hex)
    try:
        with temporary.open('x', encoding='utf-8', newline='\n') as stream:
            json.dump(value, stream, ensure_ascii=True, allow_nan=False)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _root(state_dir, profile):
    if profile != PROFILE:
        raise SetupFailure('invalid_profile')
    return prepare_guest.state_location(state_dir)


def _deployment(root):
    path = root / 'deployment.json'
    if not os.path.lexists(path):
        return None
    try:
        value = _read(path, 16384)
        if set(value) != {'qemu', 'disk', 'seed', 'memory_mib', 'cpus', 'accel'}:
            raise ValueError
        for key in ('qemu', 'disk', 'seed'):
            prepare_guest.source_file(value[key])
        runtime._parameters(value['memory_mib'], value['cpus'], value['accel'])
        runtime._assets(value['qemu'], value['disk'], value['seed'])
        return value
    except (ValueError, TypeError, KeyError, OSError, prepare_guest.PreparationError, runtime.RuntimeFailure):
        raise SetupFailure('invalid_deployment') from None


def _preflight():
    if os.name != 'nt' or platform.machine().lower() not in ('amd64', 'x86_64') or struct.calcsize('P') != 8:
        raise SetupFailure('managed_setup_requires_windows_x64')
    try:
        capability = ctypes.WinDLL('WinHvPlatform.dll')
        function = capability.WHvGetCapability
        function.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32)]
        function.restype = ctypes.c_long
        present, written = ctypes.c_uint32(), ctypes.c_uint32()
        if function(0, ctypes.byref(present), 4, ctypes.byref(written)) != 0 or not present.value:
            raise SetupFailure('whpx_unavailable_enable_windows_hypervisor_platform')
    except (OSError, AttributeError):
        raise SetupFailure('whpx_unavailable_enable_windows_hypervisor_platform') from None
    if runtime._available_memory_mib() < 5120:
        raise SetupFailure('insufficient_memory')


def _identity(pid):
    """Read process creation time plus executable; never trust a reusable PID."""
    if type(pid) is not int or pid <= 0:
        return None
    if os.name != 'nt':
        raise SetupFailure('worker_identity_unavailable')
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
    kernel.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
    kernel.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    handle = kernel.OpenProcess(0x1000, False, pid)
    if not handle:
        if ctypes.get_last_error() == 87:
            return None
        raise SetupFailure('worker_identity_unavailable')
    try:
        code = wintypes.DWORD()
        if not kernel.GetExitCodeProcess(handle, ctypes.byref(code)):
            raise SetupFailure('worker_identity_unavailable')
        if code.value != 259:
            return None
        times = [wintypes.FILETIME() for _ in range(4)]
        name, length = ctypes.create_unicode_buffer(32768), wintypes.DWORD(32768)
        if not kernel.GetProcessTimes(handle, *[ctypes.byref(item) for item in times]):
            raise SetupFailure('worker_identity_unavailable')
        if not kernel.QueryFullProcessImageNameW(handle, 0, name, ctypes.byref(length)):
            raise SetupFailure('worker_identity_unavailable')
        return {'created': (times[0].dwHighDateTime << 32) | times[0].dwLowDateTime,
                'executable': str(Path(name.value).resolve()).casefold()}
    finally:
        kernel.CloseHandle(handle)


def _setup(root):
    path = root / 'managed' / 'setup.json'
    if not os.path.lexists(path):
        return None
    value = _read(path)
    try:
        uuid.UUID(hex=value['operation'])
        if len(value['operation']) != 32 or value['stage'] not in PUBLIC_STAGES:
            raise ValueError
        if not isinstance(value['started_at'], (int, float)) or not isinstance(value['deadline_at'], (int, float)):
            raise ValueError
        if value['deadline_at'] != value['started_at'] + SETUP_SECONDS:
            raise ValueError
        if value['state'] not in ('preparing', 'error', 'complete'):
            raise ValueError
        if value.get('reason') is not None and (not isinstance(value['reason'], str) or not value['reason'].replace('_', '').isalnum()):
            raise ValueError
        if value.get('pid') is not None and (type(value['pid']) is not int or value['pid'] <= 0):
            raise ValueError
    except (KeyError, TypeError, ValueError):
        raise SetupFailure('invalid_setup_state') from None
    return value


def _active(value):
    if not value or value['state'] != 'preparing':
        return False
    if value.get('pid') is None:
        return time.time() - value['started_at'] < BOOTSTRAP_GRACE
    actual = _identity(value['pid'])
    return actual is not None and actual == value.get('identity')


def _view(root, deployment, setup, profile=PROFILE):
    result = runtime.invoke('status', state_dir=root, profile=profile)
    result['prepared'] = deployment is not None
    result['setup'] = {key: setup[key] for key in ('stage', 'operation', 'started_at', 'deadline_at', 'reason') if setup and key in setup}
    if setup and setup['state'] == 'preparing':
        if _active(setup):
            if time.time() >= setup['deadline_at']:
                result.update(state='error', reason='setup_deadline_exceeded')
                result['setup'].update(stage='failed', reason='setup_deadline_exceeded')
            else:
                result.update(state='preparing', reason='setup_in_progress')
        else:
            result.update(state='error', reason='setup_interrupted')
            result['setup'].update(stage='failed', reason='setup_interrupted')
    elif setup and setup['state'] == 'error':
        result.update(state='error', reason=setup.get('reason', 'setup_failed'))
    return result


def _error(profile, reason):
    value = runtime._base(profile)
    value.update(state='error', reason=reason, prepared=False, setup={'stage': 'failed', 'reason': reason})
    return value


def _child_environment():
    # Public prerequisite tools need OS plumbing, not native provider credentials.
    allowed = {'SYSTEMROOT', 'WINDIR', 'TEMP', 'TMP', 'PATH', 'PATHEXT', 'COMSPEC'}
    return {key: value for key, value in os.environ.items() if key.upper() in allowed}


@contextlib.contextmanager
def _control(root):
    home = root / 'managed'
    prepare_guest.local_path(home)
    home.mkdir(mode=0o700, exist_ok=True)
    # Short bounded contention is ordinary when Start races the worker's
    # progress write. Never treat lock contention as permission to spawn again.
    with contextlib.ExitStack() as stack:
        deadline = time.monotonic() + 3
        while True:
            try:
                stack.enter_context(runtime._locked(home))
                break
            except runtime.RuntimeFailure as error:
                if error.args[0] != 'busy' or time.monotonic() >= deadline:
                    raise
                time.sleep(0.05)
        yield home


def invoke(action, *, state_dir, profile=PROFILE):
    """Return runtime metadata plus prepared:bool and nonsecret setup progress.

    prepare/start authorize pinned public downloads. Both return immediately
    while one detached finite worker prepares; start additionally requests boot.
    stop during setup requests cancellation, never terminates an unverified PID.
    Existing deployments are reused without downloading, replacing or repairing.
    """
    try:
        if action not in ('status', 'prepare', 'start', 'stop'):
            raise SetupFailure('invalid_action')
        root = _root(state_dir, profile)
        deployment, setup = _deployment(root), _setup(root)
        if action == 'status':
            return _view(root, deployment, setup, profile)
        if setup and _active(setup):
            with _control(root):
                current = _setup(root)
                if current and current['operation'] == setup['operation'] and _active(current):
                    if action in ('start', 'stop'):
                        _atomic(root / 'managed' / ('request-' + current['operation'] + '.json'), {'action': action})
                    return _view(root, deployment, current, profile)
            return invoke(action, state_dir=root, profile=profile)
        if deployment is not None:
            if action in ('status', 'prepare'):
                result = runtime.invoke('status', state_dir=root, profile=profile)
            else:
                result = runtime.invoke(action, state_dir=root, profile=profile, **deployment)
            if setup and action in ('start', 'stop') and result['state'] != 'error':
                with _control(root) as home:
                    current = _setup(root)
                    if current and current['operation'] == setup['operation'] and not _active(current):
                        current.update(state='complete', stage='prepared')
                        current.pop('reason', None)
                        _atomic(home / 'setup.json', current)
            result.update(prepared=True, setup={'stage': 'prepared'})
            return result
        if action == 'stop':
            return _view(root, None, setup, profile)
        _preflight()  # Refuse unsupported acceleration before creating paths/downloads.
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        with _control(root) as home:
            # Recheck under the process lock: concurrent starts share one worker.
            deployment, setup = _deployment(root), _setup(root)
            if deployment is not None:
                return _view(root, deployment, setup, profile)
            if setup and _active(setup):
                if action == 'start':
                    _atomic(home / ('request-' + setup['operation'] + '.json'), {'action': 'start'})
                return _view(root, None, setup, profile)
            operation = uuid.uuid4().hex
            started = time.time()
            setup = dict(operation=operation, started_at=started, deadline_at=started + SETUP_SECONDS,
                         state='preparing', stage='queued', pid=None, identity=None)
            _atomic(home / 'setup.json', setup)
            _atomic(home / ('request-' + operation + '.json'), {'action': action})
            options = dict(cwd=str(home), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, close_fds=True, shell=False, env=_child_environment(),
                           creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP)
            try:
                child = subprocess.Popen([sys.executable, '-I', str(SOURCE / 'managed.py'),
                                          '--worker', str(root), operation], **options)
                setup.update(pid=child.pid, identity=_identity(child.pid))
                if setup['identity'] is None:
                    raise SetupFailure('setup_worker_exited')
                _atomic(home / 'setup.json', setup)
            except (OSError, SetupFailure):
                setup.update(state='error', stage='failed', reason='setup_launch_failed')
                _atomic(home / 'setup.json', setup)
                raise SetupFailure('setup_launch_failed') from None
            return _view(root, None, setup, profile)
    except (SetupFailure, runtime.RuntimeFailure) as error:
        return _error(profile, error.args[0])
    except prepare_guest.PreparationError:
        return _error(profile, 'invalid_state_dir')
    except (OSError, ValueError, TypeError, OverflowError):
        return _error(profile, 'managed_io_error')


class _HTTPSOnly(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, newurl):
        parsed = urllib.parse.urlsplit(newurl)
        if parsed.scheme != 'https' or parsed.username or parsed.password:
            raise SetupFailure('unsafe_public_redirect')
        return super().redirect_request(request, fp, code, message, headers, newurl)


def _digest(path, algorithm):
    digest = hashlib.new(algorithm)
    with path.open('rb') as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def _fetch(spec, cache, deadline):
    """Publish only verified bytes; a bad response cannot replace a good cache."""
    target = cache / spec['filename']
    prepare_guest.local_path(target)
    if target.exists() and _digest(prepare_guest.source_file(target), spec['algorithm']) == spec['digest']:
        return target
    temporary = cache / ('.download-' + uuid.uuid4().hex)
    # No proxy/env credentials, netrc, cookie jar, or auth handlers.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _HTTPSOnly())
    try:
        parsed = urllib.parse.urlsplit(spec['url'])
        if parsed.scheme != 'https' or parsed.username or parsed.password:
            raise SetupFailure('unsafe_public_url')
        if time.time() >= deadline:
            raise SetupFailure('setup_deadline_exceeded')
        request = urllib.request.Request(spec['url'], headers={'User-Agent': 'Hermes-Hunt-Lab/1'})
        with opener.open(request, timeout=min(30, max(1, deadline - time.time()))) as response, temporary.open('xb') as output:
            count, digest = 0, hashlib.new(spec['algorithm'])
            while True:
                if time.time() >= deadline:
                    raise SetupFailure('setup_deadline_exceeded')
                block = response.read(1024 * 1024)
                if not block:
                    break
                count += len(block)
                if count > spec['max_bytes']:
                    raise SetupFailure('public_asset_too_large')
                digest.update(block)
                output.write(block)
            output.flush()
            os.fsync(output.fileno())
        if digest.hexdigest() != spec['digest']:
            raise SetupFailure('public_asset_checksum_mismatch')
        os.replace(temporary, target)
        return target
    finally:
        temporary.unlink(missing_ok=True)


def _job():
    """Own all preparation children; crashes/deadline cannot orphan extractors."""
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    class BASIC(ctypes.Structure):
        _fields_ = [('process_time', ctypes.c_int64), ('job_time', ctypes.c_int64),
                    ('flags', wintypes.DWORD), ('minimum', ctypes.c_size_t), ('maximum', ctypes.c_size_t),
                    ('active', wintypes.DWORD), ('affinity', ctypes.c_size_t),
                    ('priority', wintypes.DWORD), ('scheduling', wintypes.DWORD)]
    class EXTENDED(ctypes.Structure):
        _fields_ = [('basic', BASIC), ('io', ctypes.c_uint64 * 6),
                    ('process_memory', ctypes.c_size_t), ('job_memory', ctypes.c_size_t),
                    ('peak_process', ctypes.c_size_t), ('peak_job', ctypes.c_size_t)]
    kernel.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    kernel.CreateJobObjectW.restype = wintypes.HANDLE
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    kernel.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    handle = kernel.CreateJobObjectW(None, None)
    limits = EXTENDED()
    limits.basic.flags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    if not handle:
        raise SetupFailure('setup_job_unavailable')
    if not kernel.SetInformationJobObject(handle, 9, ctypes.byref(limits), ctypes.sizeof(limits)) or not kernel.AssignProcessToJobObject(handle, kernel.GetCurrentProcess()):
        kernel.CloseHandle(handle)
        raise SetupFailure('setup_job_unavailable')
    # Keep handle alive until the worker exits. The actual VM is launched by a
    # separate detached completion child, outside this job via explicit breakaway.
    limits.basic.flags |= 0x800  # JOB_OBJECT_LIMIT_BREAKAWAY_OK
    if not kernel.SetInformationJobObject(handle, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
        kernel.CloseHandle(handle)
        raise SetupFailure('setup_job_unavailable')
    return handle


def _run(argv, cwd, deadline):
    remaining = deadline - time.time()
    if remaining <= 0:
        raise SetupFailure('setup_deadline_exceeded')
    result = subprocess.run([str(item) for item in argv], cwd=str(cwd), stdin=subprocess.DEVNULL,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, shell=False,
                            env=_child_environment(), timeout=remaining, creationflags=subprocess.CREATE_NO_WINDOW)
    if result.returncode:
        raise SetupFailure('public_archive_extraction_failed')


def _worker(root, operation):
    root = _root(root, PROFILE)
    home = root / 'managed'
    setup = None
    # The launcher writes PID+creation identity while holding its short lock.
    end = time.monotonic() + BOOTSTRAP_GRACE
    while True:
        try:
            with _control(root):
                setup = _setup(root)
                if not setup or setup['operation'] != operation or setup['state'] != 'preparing':
                    return 2
                if setup.get('pid') == os.getpid() and setup.get('identity') == _identity(os.getpid()):
                    break
        except runtime.RuntimeFailure as error:
            if error.args[0] != 'busy':
                return 2
        if time.monotonic() >= end:
            return 2
        time.sleep(0.1)
    lease = home / ('worker-' + operation)
    lease.mkdir(mode=0o700)
    timer = None
    try:
        with runtime._locked(lease):
            job_handle = _job()
            deadline = setup['deadline_at']
            def expire():
                # Only this worker's record may be updated, never a successor.
                try:
                    current = _setup(root)
                    if current and current['operation'] == operation and current.get('identity') == _identity(os.getpid()):
                        current.update(state='error', stage='failed', reason='setup_deadline_exceeded')
                        _atomic(home / 'setup.json', current)
                finally:
                    os._exit(2)
            timer = threading.Timer(max(0, deadline - time.time()), expire)
            timer.daemon = True
            timer.start()
            def progress(stage):
                nonlocal setup
                with _control(root):
                    current = _setup(root)
                    if not current or current['operation'] != operation or current.get('identity') != _identity(os.getpid()):
                        raise SetupFailure('setup_ownership_mismatch')
                    request = _read(home / ('request-' + operation + '.json'))
                    if request.get('action') == 'stop':
                        raise SetupFailure('setup_cancelled')
                    setup = dict(current, stage=stage)
                    _atomic(home / 'setup.json', setup)
            progress('preflight')
            _preflight()
            if shutil.disk_usage(root).free < prepare_guest.DISK_BYTES + 5 * 1024**3:
                raise SetupFailure('insufficient_disk_space')
            cache = home / 'downloads'
            prepare_guest.local_path(cache)
            cache.mkdir(mode=0o700, exist_ok=True)
            specs = _read(SOURCE / 'assets.json')['assets']
            assets = {}
            for name in ('7zr', '7zip', 'qemu', 'ubuntu', 'pycdlib'):
                progress('downloading_' + name)
                assets[name] = _fetch(specs[name], cache, deadline)
            stage = home / ('operation-' + operation)
            stage.mkdir(mode=0o700)
            tools, qemu = stage / 'extractor', stage / 'qemu'
            tools.mkdir()
            qemu.mkdir()
            progress('extracting_runtime')
            _run([assets['7zr'], 'x', '-y', '-o' + str(tools), assets['7zip']], tools, deadline)
            extractor = prepare_guest.source_file(tools / '7z.exe')
            prepare_guest.source_file(tools / '7z.dll')
            _run([extractor, 'x', '-y', '-o' + str(qemu), assets['qemu']], qemu, deadline)
            prepare_guest.source_file(qemu / 'qemu-system-x86_64.exe')
            prepare_guest.source_file(qemu / 'qemu-img.exe')
            progress('preparing_media')
            # The wheel was checksum-verified above. Import only in this isolated
            # finite child; no pip/global installation or user site is involved.
            sys.path.insert(0, str(assets['pycdlib']))
            media_root = stage / 'prepared'
            args = prepare_guest.argparse.Namespace(state_dir=str(media_root), qemu_dir=str(qemu),
                cloud_image=str(assets['ubuntu']), images_tar=None, guest_pull=True,
                evidence_dir=str(SOURCE / 'fixtures' / 'dns-lab-001'), profile=PROFILE,
                accel='whpx', memory_mib=4096, cpus=2)
            prepare_guest.prepare(args)
            progress('publishing')
            with _control(root):
                if os.path.lexists(root / 'deployment.json'):
                    raise SetupFailure('deployment_appeared_during_setup')
                config = _read(media_root / 'deployment.json')
                # Publish immutable operation-owned paths via one exclusive hard
                # link. Existing/unknown files can never be replaced by setup.
                publish = stage / 'publish.json'
                _atomic(publish, config)
                os.link(publish, root / 'deployment.json')
                request = _read(home / ('request-' + operation + '.json'))
                if request.get('action') == 'start':
                    # Break away only the fixed completion command. Its PID
                    # and creation identity replace this worker atomically.
                    child = subprocess.Popen([sys.executable, '-I', str(SOURCE / 'managed.py'),
                        '--start-prepared', str(root), operation], cwd=str(home), stdin=subprocess.DEVNULL,
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, shell=False,
                        env=_child_environment(), close_fds=True, creationflags=subprocess.DETACHED_PROCESS |
                        subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_BREAKAWAY_FROM_JOB)
                    identity = _identity(child.pid)
                    if identity is None:
                        raise SetupFailure('setup_completion_exited')
                    setup.update(stage='starting', pid=child.pid, identity=identity)
                else:
                    setup.update(stage='prepared', state='complete')
                _atomic(home / 'setup.json', setup)
            return 0
    except Exception as error:
        reason = error.args[0] if isinstance(error, SetupFailure) else 'setup_failed'
        try:
            with _control(root):
                current = _setup(root)
                if current and current['operation'] == operation:
                    current.update(state='error', stage='cancelled' if reason == 'setup_cancelled' else 'failed', reason=reason)
                    _atomic(home / 'setup.json', current)
        except Exception:
            pass
        return 2
    finally:
        if timer is not None:
            timer.cancel()


def _start_prepared(root, operation):
    root = _root(root, PROFILE)
    home = root / 'managed'
    with _control(root):
        setup = _setup(root)
        if not setup or setup['operation'] != operation or setup.get('pid') != os.getpid() or setup.get('identity') != _identity(os.getpid()):
            return 2
        deployment = _deployment(root)
        request = _read(home / ('request-' + operation + '.json'))
    if deployment is None:
        return 2
    result = runtime.invoke('stop' if request.get('action') == 'stop' else 'start',
                            state_dir=root, profile=PROFILE, **deployment)
    with _control(root):
        current = _setup(root)
        if not current or current['operation'] != operation or current.get('identity') != _identity(os.getpid()):
            return 2
        request = _read(home / ('request-' + operation + '.json'))
        if request.get('action') == 'stop':
            result = runtime.invoke('stop', state_dir=root, profile=PROFILE)
        if result['state'] == 'error':
            current.update(state='error', stage='failed', reason=result['reason'])
        else:
            current.update(state='complete', stage='prepared')
        _atomic(home / 'setup.json', current)
    return int(result['state'] == 'error')


def main():
    # Internal fixed-shape worker entrypoints; no generic command/root broker.
    if len(sys.argv) == 4 and sys.argv[1] == '--worker':
        try:
            uuid.UUID(hex=sys.argv[3])
            return _worker(sys.argv[2], sys.argv[3])
        except Exception:
            return 2
    if len(sys.argv) == 4 and sys.argv[1] == '--start-prepared':
        try:
            uuid.UUID(hex=sys.argv[3])
            return _start_prepared(sys.argv[2], sys.argv[3])
        except Exception:
            return 2
    return 2


if __name__ == '__main__':
    raise SystemExit(main())

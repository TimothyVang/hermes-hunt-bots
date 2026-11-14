"""The practice lab as host containers: one Docker Compose project per case (guest/compose.stack.yaml).

`start` loads a case's evidence into a fresh stack and returns while it starts; `status` reads the project's
containers and the lab service's /health; `stop` removes the project's containers, networks and volumes and
the case's state. Each runs only on an explicit human action, and nothing is retried.

CLI (from framework/; `hermes -p framework-network-analyst hunt-lab start|status|stop` calls the same code):
  python -m hunt_lab.lab_stack start --state-dir <analyst home>/hunt-lab-vm [--evidence-dir DIR] [--wait 120]
  python -m hunt_lab.lab_stack status|stop --state-dir <analyst home>/hunt-lab-vm [--case-id ID]

State sits in `hunt-lab-container/` beside the analyst's `hunt-lab-vm` dir. Its folders are owner-only
(hunt_lab.endpoints.owner_only): only this user and SYSTEM can read the secret.
- `<case_id>/state.json`: the case, compose project, published ports, instance and caller secret. The resolver
  (hunt_lab.endpoints) reads it as the `container` origin.
- `<case_id>/evidence/`: the case folder's allowlisted evidence files (case_files.evidence_files), linked or
  copied, mounted read-only.
- `<case_id>/lab-secret` and `<case_id>/instance-id`: mounted into the lab service only.
- `<case_id>/compose.log` and `<case_id>/up.json`: the background `docker compose up` and its process.
- `last.json`: the case and evidence folder of the last start. Without --case-id, every action uses it; a first
  start without --evidence-dir loads the bundled fixture.

Ports are three free loopback ports, or, when HUNT_LAB_PORTS is `<first>-<last>`, the first free ones in that range.
"""
from __future__ import annotations

import argparse
import contextlib
import ctypes
from ctypes import wintypes
import hashlib
import json
import os
import re
from pathlib import Path
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import time
import uuid
from urllib import error, request

from . import case_files, endpoints

PROFILE = 'framework-network-analyst'
SOURCE = Path(__file__).resolve().parent
GUEST = SOURCE / 'guest'
COMPOSE_FILE = GUEST / 'compose.stack.yaml'
DOCKERFILE = GUEST / 'Dockerfile.lab'
FIXTURE = SOURCE / 'fixtures' / 'dns-lab-001'
PROJECT_PREFIX = endpoints.CONTAINER_PROJECT_PREFIX
PORTS_ENV = 'HUNT_LAB_PORTS'
# A case is loaded (ingest, capture import, Kibana data view) within this, or status reports the error.
START_SECONDS = 1800
DOCKER_SECONDS = 30
DOWN_SECONDS = 300
ONE_SHOTS = ('arkime-init', 'ingest', 'pcap-import', 'kibana-setup')
SERVICES = ('elasticsearch', 'netns', 'lab', 'kibana', 'arkime', 'relay')
WARM_CORE_SERVICES = ('elasticsearch', 'netns', 'kibana', 'relay')
COMPOSE_PROJECT_FILE = 'compose-project'
COMPOSE_PROJECT_RE = re.compile(r'hunt-lab-[a-z0-9-]{3,64}')
_PURGE_ARKIME_CASE = (
    "import json, sys, urllib.request; "
    "body = json.dumps({'query': {'term': {'tags': 'case:' + sys.argv[1]}}}).encode(); "
    "req = urllib.request.Request("
    "'http://elasticsearch:9200/arkime_sessions3-*/_delete_by_query?refresh=true&conflicts=proceed&ignore_unavailable=true', "
    "data=body, method='POST', headers={'Content-Type': 'application/json'}); "
    "urllib.request.urlopen(req, timeout=20).read()"
)
HEALTH_KEYS = ('ready', 'event_count', 'network_session_count', 'intel_count', 'arkime_viewer_ready',
               'kibana_ready', 'network_capture')
# A line `docker compose up` writes when it gives up (a port taken, a dependency that never became healthy).
COMPOSE_ERROR = re.compile(r'(?im)^\s*(error\b|.*error response from daemon|.*dependency failed to start)')
# The Docker CLI needs the OS and its own settings; no provider key or ambient COMPOSE_* setting reaches it.
CHILD_ENV = frozenset({'PATH', 'PATHEXT', 'SYSTEMROOT', 'WINDIR', 'COMSPEC', 'TEMP', 'TMP', 'USERPROFILE', 'HOME',
                       'HOMEDRIVE', 'HOMEPATH', 'APPDATA', 'LOCALAPPDATA', 'PROGRAMDATA', 'PROGRAMFILES',
                       'PROGRAMFILES(X86)', 'PROGRAMW6432', 'XDG_RUNTIME_DIR'})
NO_WINDOW = getattr(subprocess, 'CREATE_NO_WINDOW', 0)


class StackFailure(Exception):
    """Fixed public reason code."""


def _base(profile):
    return {'profile': PROFILE if profile == PROFILE else None, 'origin': 'container', 'state': 'stopped',
            'reason': 'not_started', 'case_id': None, 'project': None, 'lab_url': None, 'arkime_url': None,
            'kibana_url': None, 'lab_console_url': None, 'lab_port': None, 'arkime_port': None, 'kibana_port': None,
            'started_at': None, 'health': None, 'services': None}


def _child_env(extra=None):
    env = {key: value for key, value in os.environ.items()
           if key.upper() in CHILD_ENV or key.upper().startswith('DOCKER_')}
    env.update(extra or {})
    return env


def _docker(arguments, timeout=DOCKER_SECONDS):
    try:
        return subprocess.run(['docker', *arguments], stdin=subprocess.DEVNULL, capture_output=True, text=True,
                              encoding='utf-8', errors='replace', timeout=timeout, env=_child_env(),
                              creationflags=NO_WINDOW)
    except subprocess.TimeoutExpired:
        raise StackFailure('docker_timeout') from None
    except OSError:
        raise StackFailure('docker_unavailable') from None


def available():
    """Docker's CLI is installed and its engine answers."""
    try:
        answer = _docker(['version', '--format', '{{.Server.Version}}'], 15)
    except StackFailure:
        return False
    return answer.returncode == 0 and bool(answer.stdout.strip())


def project(case_id):
    return PROJECT_PREFIX + case_id


def lab_image():
    """The lab image's tag names its Dockerfile, so a changed Dockerfile builds a new image."""
    return 'hermes-hunt-lab:' + hashlib.sha256(DOCKERFILE.read_bytes()).hexdigest()[:12]


def _root(state_dir):
    return case_files.state_location(os.fspath(Path(state_dir).parent / endpoints.CONTAINER_STATE))


def _case_dir(root, case_id):
    if not isinstance(case_id, str) or not endpoints.CASE_ID.fullmatch(case_id):
        raise StackFailure('invalid_case_id')
    return root / case_id


def _evidence(evidence_dir):
    """The case id, folder, allowlisted (name, path) files, and validated case.json metadata."""
    try:
        folder = case_files.local_path(evidence_dir)
        files = case_files.evidence_files(folder)
        meta = case_files.case_metadata(folder / 'case.json')
    except (case_files.CaseError, OSError):
        raise StackFailure('invalid_evidence') from None
    return meta['case_id'], folder, files, meta


def _compose_project(case_dir, case_id):
    try:
        override = (case_dir / COMPOSE_PROJECT_FILE).read_text(encoding='ascii').strip()
    except FileNotFoundError:
        return project(case_id)
    except (OSError, UnicodeDecodeError):
        raise StackFailure('container_state_invalid') from None
    if not COMPOSE_PROJECT_RE.fullmatch(override):
        raise StackFailure('container_state_invalid')
    return override


def _stage(files, target):
    target.mkdir()
    for name, path in files:
        try:
            os.link(path, target / name)
        except OSError:
            shutil.copyfile(path, target / name)


def _write_new(path, data, mode=0o600):
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, 'O_BINARY', 0), mode)
    if os.name != 'nt':
        os.fchmod(descriptor, mode)
    try:
        os.write(descriptor, data)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_json(path, value):
    temporary = path.with_name('.write-' + uuid.uuid4().hex)
    try:
        _write_new(temporary, json.dumps(value, sort_keys=True).encode('ascii'))
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _read_json(path):
    try:
        with path.open('rb') as handle:
            data = handle.read(endpoints.MAX_STATE + 1)
        value = json.loads(data) if len(data) <= endpoints.MAX_STATE else None
    except FileNotFoundError:
        return None
    except (OSError, ValueError):
        raise StackFailure('container_state_invalid') from None
    if not isinstance(value, dict):
        raise StackFailure('container_state_invalid')
    return value


def _last(root):
    value = _read_json(root / 'last.json')
    if value is None:
        return None
    if (set(value) != {'case_id', 'evidence_dir'} or not isinstance(value['case_id'], str)
            or not endpoints.CASE_ID.fullmatch(value['case_id']) or not isinstance(value['evidence_dir'], str)):
        raise StackFailure('container_state_invalid')
    return value


def _recorded_ports(root):
    """The ports every container lab's state.json under `root` records."""
    ports = set()
    for case_dir in root.iterdir() if root.is_dir() else ():
        try:
            state = endpoints.container_state(case_dir / 'state.json') if case_dir.is_dir() else None
        except endpoints.QueryFailure:
            state = None
        if state is not None:
            ports.update(state[key] for key in ('lab_port', 'kibana_port', 'arkime_port'))
    return frozenset(ports)


def _compose_failed(case_dir):
    """`docker compose up` wrote that it gave up. Its process ending is not enough: a caller that ends the
    process tree of the CLI it ran (as the desktop's profile CLI request can) takes docker.exe, while the
    compose plugin it started goes on and finishes the stack."""
    try:
        with (case_dir / 'compose.log').open('rb') as log:
            log.seek(0, os.SEEK_END)
            log.seek(max(0, log.tell() - 16384))
            tail = log.read().decode('utf-8', 'replace')
    except OSError:
        return False
    return COMPOSE_ERROR.search(tail) is not None


def _ports(reserved=frozenset(), count=3):
    """Free 127.0.0.1 ports: any, or the first free ones of HUNT_LAB_PORTS (`<first>-<last>`), never one in
    `reserved` (the ports other cases' labs recorded, which their relay may not have bound yet)."""
    spec = os.environ.get(PORTS_ENV)
    if spec:
        try:
            first, last = (int(part) for part in spec.split('-'))
        except ValueError:
            raise StackFailure('invalid_port_range') from None
        if not 1024 <= first <= last <= 65535:
            raise StackFailure('invalid_port_range')
        candidates = range(first, last + 1)
    else:
        candidates = [0] * (count + len(reserved) + 8)
    listeners, ports = [], []
    try:
        for candidate in candidates:
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            if os.name == 'nt':
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            try:
                listener.bind(('127.0.0.1', candidate))
            except OSError:
                listener.close()
                continue
            listeners.append(listener)
            port = listener.getsockname()[1]
            if port in reserved:
                continue
            ports.append(port)
            if len(ports) == count:
                return ports
        raise StackFailure('ports_unavailable')
    finally:
        for listener in listeners:
            listener.close()


def _windows_identity(pid):
    """Creation time plus executable of a running process, or None once it has exited."""
    if type(pid) is not int or pid <= 0:
        return None
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
    kernel.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR,
                                                  ctypes.POINTER(wintypes.DWORD)]
    kernel.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    # PROCESS_QUERY_LIMITED_INFORMATION; error 87 is a PID with no process.
    handle = kernel.OpenProcess(0x1000, False, pid)
    if not handle:
        if ctypes.get_last_error() == 87:
            return None
        raise StackFailure('process_identity_unavailable')
    try:
        code = wintypes.DWORD()
        if not kernel.GetExitCodeProcess(handle, ctypes.byref(code)):
            raise StackFailure('process_identity_unavailable')
        if code.value != 259:
            return None
        times = [wintypes.FILETIME() for _ in range(4)]
        name, length = ctypes.create_unicode_buffer(32768), wintypes.DWORD(32768)
        if not kernel.GetProcessTimes(handle, *[ctypes.byref(item) for item in times]):
            raise StackFailure('process_identity_unavailable')
        if not kernel.QueryFullProcessImageNameW(handle, 0, name, ctypes.byref(length)):
            raise StackFailure('process_identity_unavailable')
        return {'created': (times[0].dwHighDateTime << 32) | times[0].dwLowDateTime,
                'executable': str(Path(name.value).resolve()).casefold()}
    finally:
        kernel.CloseHandle(handle)


def _identity(pid):
    """A process's creation identity, or None once it has exited; a reused PID never matches."""
    if os.name == 'nt':
        return _windows_identity(pid)
    try:
        return {'created': Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()[19]}
    except (OSError, IndexError):
        return None


def _up_running(case_dir):
    """Whether the background `docker compose up` this case's start launched is still running."""
    value = _read_json(case_dir / 'up.json')
    if value is None:
        return False
    if set(value) != {'pid', 'identity'} or type(value['pid']) is not int:
        raise StackFailure('container_state_invalid')
    return value['identity'] is not None and _identity(value['pid']) == value['identity']


def _services(name):
    """{service: (state, exit code)} of the project's containers, from `docker compose ps`."""
    answer = _docker(['compose', '-p', name, 'ps', '-a', '--format', 'json'])
    if answer.returncode:
        raise StackFailure('docker_ps_failed')
    text = answer.stdout.strip()
    try:
        rows = json.loads(text) if text.startswith('[') else [json.loads(line) for line in text.splitlines() if line]
        return {row['Service']: (row['State'], row.get('ExitCode')) for row in rows}
    except (ValueError, KeyError, TypeError):
        raise StackFailure('docker_ps_failed') from None


def _health(state):
    """(ready, the /health answer or None, reason) from the lab service, sending its secret."""
    opener = request.build_opener(request.ProxyHandler({}), endpoints.NoRedirect())
    req = request.Request('http://127.0.0.1:%d/health' % state['lab_port'],
                          headers={endpoints.SECRET_HEADER: state['secret']})
    try:
        response = opener.open(req, timeout=10)
    except error.HTTPError as exc:
        response = exc
    except (error.URLError, OSError, ValueError):
        return False, None, 'lab_unreachable'
    with response:
        if response.headers.get(endpoints.INSTANCE_HEADER) != state['instance']:
            return False, None, 'lab_instance_mismatch'
        try:
            value = json.loads(response.read(endpoints.MAX_RESPONSE))
        except (OSError, ValueError):
            return False, None, 'lab_invalid_response'
    if isinstance(value, dict) and response.status == 503 and isinstance(value.get('error'), str):
        return False, None, 'services_not_ready'
    if not isinstance(value, dict) or value.get('case_id') != state['case_id']:
        return False, None, 'lab_invalid_response'
    health = {key: value.get(key) for key in HEALTH_KEYS}
    ready = response.status == 200 and value.get('ready') is True
    return ready, health, None if ready else 'services_not_ready'


def _status(profile, root, case_id):
    result = _base(profile)
    if case_id is None:
        return result
    case_dir = _case_dir(root, case_id)
    result.update(case_id=case_id, project=project(case_id))
    try:
        state = endpoints.container_state(case_dir / 'state.json')
    except endpoints.QueryFailure:
        raise StackFailure('container_state_invalid') from None
    if state is None:
        if os.path.lexists(case_dir):
            raise StackFailure('container_state_invalid')
        return result
    lab_url = 'http://127.0.0.1:%d' % state['lab_port']
    result.update(lab_url=lab_url, arkime_url='http://127.0.0.1:%d' % state['arkime_port'],
                  kibana_url='http://127.0.0.1:%d' % state['kibana_port'], lab_port=state['lab_port'],
                  arkime_port=state['arkime_port'], kibana_port=state['kibana_port'], started_at=state['started_at'])
    services = _services(_compose_project(case_dir, case_id))
    result['services'] = {name: status if code is None or status != 'exited' else '%s(%s)' % (status, code)
                          for name, (status, code) in sorted(services.items())}
    ready, health, reason = _health(state)
    result['health'] = health
    if ready:
        # The console page takes the secret as ?key=, the one way a browser tab can send it.
        result.update(state='running', reason=None, lab_console_url=lab_url + '/?key=' + state['secret'])
        return result
    failed = [name for name in ONE_SHOTS if services.get(name, (None, 0))[0] == 'exited'
              and services[name][1] not in (0, None)]
    stopped = [name for name in SERVICES if services.get(name, (None,))[0] in ('exited', 'dead')]
    missing = [name for name in SERVICES + ONE_SHOTS if name not in services]
    # `up` creates every container before it starts any; one it left only created will not start on its own.
    created = [name for name in SERVICES + ONE_SHOTS if services.get(name, (None,))[0] == 'created']
    if failed:
        result.update(state='error', reason=failed[0].replace('-', '_') + '_failed')
    elif stopped:
        result.update(state='error', reason=stopped[0] + '_exited')
    elif (missing or created) and not _up_running(case_dir) and _compose_failed(case_dir):
        result.update(state='error', reason='compose_up_failed')
    else:
        loading = missing or any(services[name][0] != 'exited' for name in ONE_SHOTS)
        late = time.time() - state['started_at'] > START_SECONDS
        result.update(state='error' if late else 'starting', reason='loading_case' if loading else reason)
    return result


def _launch(argv, variables, log_path):
    """Start `argv` detached, so the stack goes on starting after this CLI exits; its output goes to log_path."""
    with log_path.open('ab') as log:
        child = subprocess.Popen(
            argv, cwd=GUEST, env=_child_env(variables), stdin=subprocess.DEVNULL, stdout=log,
            stderr=subprocess.STDOUT, close_fds=True,
            creationflags=(subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP if os.name == 'nt' else 0),
            start_new_session=os.name != 'nt')
    return child.pid


def _terminate(pid):
    """End the background `docker compose up` and, on Windows, the compose plugin process it started."""
    try:
        if os.name == 'nt':
            subprocess.run(['taskkill', '/PID', str(pid), '/T', '/F'], stdin=subprocess.DEVNULL,
                           capture_output=True, timeout=30, creationflags=NO_WINDOW)
        else:
            os.killpg(pid, signal.SIGTERM)
    except (OSError, subprocess.TimeoutExpired):
        pass


def _case_is_synthetic(case_dir):
    try:
        meta = json.loads((case_dir / 'evidence' / 'case.json').read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return False
    return isinstance(meta, dict) and 'data_origin' not in meta


def _warm_stack(root, incoming_case_id):
    """Find a running synthetic container stack under `root` whose warm core services can be reused."""
    if not root.is_dir():
        return None
    for other_dir in sorted(root.iterdir()):
        if (not other_dir.is_dir() or other_dir.name == incoming_case_id
                or not endpoints.CASE_ID.fullmatch(other_dir.name)):
            continue
        try:
            other_state = endpoints.container_state(other_dir / 'state.json')
        except endpoints.QueryFailure:
            continue
        if other_state is None or not _case_is_synthetic(other_dir):
            continue
        compose_proj = _compose_project(other_dir, other_state['case_id'])
        try:
            services = _services(compose_proj)
        except StackFailure:
            continue
        if all(services.get(name, (None,))[0] == 'running' for name in WARM_CORE_SERVICES):
            return other_dir, other_state, compose_proj
    return None


def _stop_up_launcher(case_dir):
    if os.path.lexists(case_dir / 'up.json') and _up_running(case_dir):
        _terminate(_read_json(case_dir / 'up.json')['pid'])
        deadline = time.monotonic() + 15
        while _up_running(case_dir):
            if time.monotonic() > deadline:
                raise StackFailure('compose_up_still_running')
            time.sleep(0.5)


def _unlink_ignoring_readonly(path):
    """Delete one NTFS hard link without clearing the read-only attribute it shares with the operator's source file."""
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
                                   wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    kernel.SetFileInformationByHandle.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD]
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    # DELETE access, share read/write/delete, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT.
    handle = kernel.CreateFileW(str(path), 0x00010000, 0x7, None, 3, 0x00200000, None)
    if handle is None or handle == wintypes.HANDLE(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        # FileDispositionInfoEx: DELETE | POSIX_SEMANTICS | IGNORE_READONLY_ATTRIBUTE.
        flags = wintypes.DWORD(0x1 | 0x2 | 0x10)
        if not kernel.SetFileInformationByHandle(handle, 21, ctypes.byref(flags), ctypes.sizeof(flags)):
            raise ctypes.WinError(ctypes.get_last_error())
    finally:
        kernel.CloseHandle(handle)


def _chmod_retry(func, path, *_):
    with contextlib.suppress(OSError):
        if func in (os.unlink, os.remove) and os.lstat(path).st_nlink > 1:
            # chmod on a hard link edits the mode every link shares, the operator's source evidence included.
            if os.name == 'nt':
                _unlink_ignoring_readonly(path)
            return
        os.chmod(path, 0o700)
        func(path)


def _force_rmtree(path):
    if not os.path.lexists(path):
        return
    if sys.version_info >= (3, 12):
        shutil.rmtree(path, onexc=_chmod_retry)
    else:
        shutil.rmtree(path, onerror=_chmod_retry)


def _prepare_warm_switch(warm_dir, compose_proj, loaded, meta):
    _stop_up_launcher(warm_dir)
    if meta.get('network_capture') != 'none':
        purged = _docker(['compose', '-p', compose_proj, 'exec', '-T', 'netns', 'python3', '-B', '-c',
                          _PURGE_ARKIME_CASE, loaded])
        if purged.returncode:
            raise StackFailure('arkime_purge_failed')


def _reset_warm_services(compose_proj):
    # Stop and remove case-bound containers before touching warm_dir so bind mounts release and _status sees loading_case.
    removed = _docker(['compose', '-p', compose_proj, 'rm', '-f', '-s', 'lab', 'arkime', *ONE_SHOTS], DOWN_SECONDS)
    if removed.returncode:
        raise StackFailure('warm_reset_failed')


def _retire_warm_dir(warm_dir):
    (warm_dir / 'state.json').unlink(missing_ok=True)
    retired = warm_dir.parent / f'.retired-{warm_dir.name}-{uuid.uuid4().hex[:8]}'
    try:
        os.replace(warm_dir, retired)
    except OSError:
        retired = warm_dir
    for _ in range(20):
        _force_rmtree(retired)
        if not os.path.lexists(retired):
            return
        time.sleep(0.05)


def _compose_variables(case_dir, case_id, compose_proj, lab_port, kibana_port, arkime_port):
    return {
        'PROJECT': compose_proj, 'LAB_IMAGE': lab_image(), 'CASE_ID': case_id,
        'EVIDENCE_DIR': (case_dir / 'evidence').as_posix(), 'SECRET_FILE': (case_dir / 'lab-secret').as_posix(),
        'INSTANCE_FILE': (case_dir / 'instance-id').as_posix(), 'LAB_PORT': str(lab_port),
        'KIBANA_PORT': str(kibana_port), 'ARKIME_PORT': str(arkime_port)}


def _restore_warm_stack(warm_dir, warm_state, compose_proj):
    """Bring the previous case back after a failed switch; on failure leave warm_dir for `status` and `stop`."""
    if (warm_dir / 'evidence' / 'traffic.pcap').is_file():
        # pcap-import runs again on `up`; drop the sessions it already wrote so they are not doubled.
        with contextlib.suppress(StackFailure):
            _docker(['compose', '-p', compose_proj, 'exec', '-T', 'netns', 'python3', '-B', '-c',
                     _PURGE_ARKIME_CASE, warm_state['case_id']])
    variables = _compose_variables(warm_dir, warm_state['case_id'], compose_proj,
                                   warm_state['lab_port'], warm_state['kibana_port'], warm_state['arkime_port'])
    try:
        restored = _launch(['docker', 'compose', '--ansi', 'never', '--progress', 'plain', '-f', str(COMPOSE_FILE),
                            '-p', compose_proj, 'up', '-d'], variables, warm_dir / 'compose.log')
        _write_json(warm_dir / 'up.json', {'pid': restored, 'identity': _identity(restored)})
    except OSError:
        with contextlib.suppress(OSError):
            (warm_dir / 'up.json').unlink(missing_ok=True)


def _project_shared_by_other_case(root, case_dir, compose_proj):
    if not root.is_dir():
        return False
    for other in root.iterdir():
        if (other == case_dir or not other.is_dir() or not endpoints.CASE_ID.fullmatch(other.name)
                or not (other / 'state.json').is_file()):
            continue
        if _compose_project(other, other.name) == compose_proj:
            return True
    return False


def _start(profile, root, evidence_dir, case_id, *, cold=False):
    if evidence_dir is None:
        last = _last(root)
        if last is not None and case_id in (None, last['case_id']):
            evidence_dir = last['evidence_dir']
        elif case_id is None or case_id == _evidence(FIXTURE)[0]:
            evidence_dir = FIXTURE
        else:
            raise StackFailure('evidence_dir_required')
    loaded, folder, files, meta = _evidence(evidence_dir)
    if case_id is not None and case_id != loaded:
        raise StackFailure('case_mismatch')
    case_dir = _case_dir(root, loaded)
    if cold and root.is_dir():
        for existing in sorted(root.iterdir()):
            if existing.is_dir() and endpoints.CASE_ID.fullmatch(existing.name):
                _stop(profile, root, existing.name)
    if os.path.lexists(case_dir):
        # Already started: report it. A failed stack is stopped before it is started again.
        return _status(profile, root, loaded)
    if not available():
        raise StackFailure('docker_unavailable')
    root.mkdir(parents=True, exist_ok=True)
    endpoints.owner_only(root)
    warm = None if (cold or 'data_origin' in meta) else _warm_stack(root, loaded)
    case_dir.mkdir()
    pid = None
    warm_reset = False
    try:
        endpoints.owner_only(case_dir)
        _stage(files, case_dir / 'evidence')
        secret, instance = secrets.token_hex(32), uuid.uuid4().hex
        # Mounted into the lab service, which runs as nobody. The case folder stays owner-only; on a Linux engine
        # the bind mount keeps the host mode, so these two are readable inside it.
        mounted = 0o600 if os.name == 'nt' else 0o644
        _write_new(case_dir / 'lab-secret', secret.encode('ascii'), mounted)
        _write_new(case_dir / 'instance-id', (instance + '\n').encode('ascii'), mounted)
        if warm is not None:
            warm_dir, warm_state, compose_proj = warm
            lab_port, kibana_port, arkime_port = (
                warm_state['lab_port'], warm_state['kibana_port'], warm_state['arkime_port'])
            if compose_proj != project(loaded):
                _write_new(case_dir / COMPOSE_PROJECT_FILE, (compose_proj + '\n').encode('ascii'))
        else:
            compose_proj = project(loaded)
            lab_port, kibana_port, arkime_port = _ports(_recorded_ports(root))
        state = {'version': endpoints.CONTAINER_VERSION, 'case_id': loaded, 'project': project(loaded),
                 'instance': instance, 'secret': secret, 'lab_port': lab_port, 'kibana_port': kibana_port,
                 'arkime_port': arkime_port, 'started_at': time.time()}
        _write_new(case_dir / 'state.json', json.dumps(state, sort_keys=True).encode('ascii'))
        if warm is not None:
            _prepare_warm_switch(warm_dir, compose_proj, loaded, meta)
            # A partly applied `rm` has already dismantled the previous case, so restore it on any failure from here.
            warm_reset = True
            _reset_warm_services(compose_proj)
        variables = _compose_variables(case_dir, loaded, compose_proj, lab_port, kibana_port, arkime_port)
        pid = _launch(['docker', 'compose', '--ansi', 'never', '--progress', 'plain', '-f', str(COMPOSE_FILE),
                       '-p', compose_proj, 'up', '-d'], variables, case_dir / 'compose.log')
        _write_json(case_dir / 'up.json', {'pid': pid, 'identity': _identity(pid)})
        if warm is not None:
            _retire_warm_dir(warm[0])
        _write_json(root / 'last.json', {'case_id': loaded, 'evidence_dir': str(folder)})
    except BaseException:
        if not (case_dir / 'up.json').exists():
            if pid is not None:
                _terminate(pid)
            _force_rmtree(case_dir)
            if warm_reset:
                _restore_warm_stack(*warm)
        raise
    return _status(profile, root, loaded)


def _stop(profile, root, case_id):
    result = _base(profile)
    if case_id is None:
        return result
    case_dir = _case_dir(root, case_id)
    compose_proj = _compose_project(case_dir, case_id)
    result.update(case_id=case_id, project=project(case_id))
    _stop_up_launcher(case_dir)
    if not _project_shared_by_other_case(root, case_dir, compose_proj):
        answer = _docker(['compose', '-p', compose_proj, 'down', '-v', '--remove-orphans', '--timeout', '10'],
                         DOWN_SECONDS)
        if answer.returncode:
            raise StackFailure('compose_down_failed')
        label = 'label=com.docker.compose.project=' + compose_proj
        for kind in ('container', 'volume', 'network'):
            listed = _docker([kind, 'ls', *(['-a'] if kind == 'container' else []), '-q', '--filter', label])
            if listed.returncode or listed.stdout.strip():
                raise StackFailure('stack_remains')
    _force_rmtree(case_dir)
    if os.path.lexists(case_dir):
        raise StackFailure('container_state_remains')
    result['reason'] = 'stopped'
    return result


def invoke(action, *, state_dir, profile=PROFILE, case_id=None, evidence_dir=None, wait=0, cold=False):
    """One lifecycle action on a case's container lab; returns the CLI's result dict, never raises.

    Without `case_id`, status and stop act on the last started case, and start loads `evidence_dir` (else the
    last started case's folder, else the bundled fixture). `wait` (seconds) keeps reading status after a start
    until the lab is no longer starting. `cold` forces teardown before starting instead of reusing a warm stack.
    """
    try:
        if action not in ('status', 'start', 'stop'):
            raise StackFailure('invalid_action')
        if profile != PROFILE:
            raise StackFailure('invalid_profile')
        root = _root(state_dir)
        if action == 'start':
            result = _start(profile, root, evidence_dir, case_id, cold=bool(cold))
            deadline = time.monotonic() + max(0, wait)
            while result['state'] == 'starting' and time.monotonic() < deadline:
                time.sleep(2)
                result = _status(profile, root, result['case_id'])
            return result
        if case_id is None:
            case_id = (_last(root) or {}).get('case_id')
        return (_status if action == 'status' else _stop)(profile, root, case_id)
    except StackFailure as failure:
        result = _base(profile)
        result.update(state='error', reason=failure.args[0], case_id=case_id)
        return result
    except case_files.CaseError:
        result = _base(profile)
        result.update(state='error', reason='invalid_state_dir', case_id=case_id)
        return result
    except OSError:
        result = _base(profile)
        result.update(state='error', reason='stack_io_error', case_id=case_id)
        return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('action', choices=('start', 'status', 'stop'))
    parser.add_argument('--state-dir', required=True, help="the analyst's hunt-lab-vm dir")
    parser.add_argument('--case-id')
    parser.add_argument('--evidence-dir')
    parser.add_argument('--wait', type=int, default=0, help='start: seconds to keep reading status while starting')
    parser.add_argument('--cold', action='store_true', help='start: tear down any running stack first instead of warm reuse')
    args = parser.parse_args(argv)
    result = invoke(args.action, state_dir=args.state_dir, case_id=args.case_id, evidence_dir=args.evidence_dir,
                    wait=args.wait, cold=args.cold)
    print(json.dumps(result, ensure_ascii=True, allow_nan=False))
    return 1 if result['state'] == 'error' else 0


if __name__ == '__main__':
    sys.exit(main())

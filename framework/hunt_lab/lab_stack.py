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
- `<case_id>/evidence/`: the evidence files the VM's seed would carry (prepare_guest.payload_sources), linked or
  copied, mounted read-only.
- `<case_id>/lab-secret` and `<case_id>/instance-id`: mounted into the lab service only.
- `<case_id>/compose.log` and `<case_id>/up.json`: the background `docker compose up` and its process.
- `last.json`: the case and evidence folder of the last start. Without --case-id, every action uses it; a first
  start without --evidence-dir loads the bundled fixture.

Ports are three free loopback ports, or, when HUNT_LAB_PORTS is `<first>-<last>`, the first free ones in that range.
"""
from __future__ import annotations

import argparse
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

from . import endpoints, prepare_guest

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
    return prepare_guest.state_location(os.fspath(Path(state_dir).parent / endpoints.CONTAINER_STATE))


def _case_dir(root, case_id):
    if not isinstance(case_id, str) or not endpoints.CASE_ID.fullmatch(case_id):
        raise StackFailure('invalid_case_id')
    return root / case_id


def _evidence(evidence_dir):
    """The case id and the (name, path) evidence files the VM's seed would carry for this folder."""
    try:
        folder = prepare_guest.local_path(evidence_dir)
        files = [(name.removeprefix('evidence/'), path) for name, path in prepare_guest.payload_sources(folder)
                 if name.startswith('evidence/')]
        case_id = prepare_guest.case_metadata(folder / 'case.json')['case_id']
    except (prepare_guest.PreparationError, OSError):
        raise StackFailure('invalid_evidence') from None
    return case_id, folder, files


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


def _identity(pid):
    """A process's creation identity, or None once it has exited; a reused PID never matches."""
    if os.name == 'nt':
        from . import managed
        try:
            return managed._identity(pid)
        except managed.SetupFailure:
            raise StackFailure('process_identity_unavailable') from None
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
    services = _services(state['project'])
    result['services'] = {name: status if code is None or status != 'exited' else '%s(%s)' % (status, code)
                          for name, (status, code) in sorted(services.items())}
    ready, health, reason = _health(state)
    result['health'] = health
    if ready:
        # The console page takes the secret as ?key=, the one way a browser tab can send it (as for the VM).
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


def _start(profile, root, evidence_dir, case_id):
    if evidence_dir is None:
        last = _last(root)
        if last is not None and case_id in (None, last['case_id']):
            evidence_dir = last['evidence_dir']
        elif case_id is None or case_id == _evidence(FIXTURE)[0]:
            evidence_dir = FIXTURE
        else:
            raise StackFailure('evidence_dir_required')
    loaded, folder, files = _evidence(evidence_dir)
    if case_id is not None and case_id != loaded:
        raise StackFailure('case_mismatch')
    case_dir = _case_dir(root, loaded)
    if os.path.lexists(case_dir):
        # Already started: report it. A failed stack is stopped before it is started again.
        return _status(profile, root, loaded)
    if not available():
        raise StackFailure('docker_unavailable')
    root.mkdir(parents=True, exist_ok=True)
    endpoints.owner_only(root)
    case_dir.mkdir()
    pid = None
    try:
        endpoints.owner_only(case_dir)
        _stage(files, case_dir / 'evidence')
        secret, instance = secrets.token_hex(32), uuid.uuid4().hex
        # Mounted into the lab service, which runs as nobody. The case folder stays owner-only; on a Linux engine
        # the bind mount keeps the host mode, so these two are readable inside it.
        mounted = 0o600 if os.name == 'nt' else 0o644
        _write_new(case_dir / 'lab-secret', secret.encode('ascii'), mounted)
        _write_new(case_dir / 'instance-id', (instance + '\n').encode('ascii'), mounted)
        lab_port, kibana_port, arkime_port = _ports(_recorded_ports(root))
        state = {'version': endpoints.CONTAINER_VERSION, 'case_id': loaded, 'project': project(loaded),
                 'instance': instance, 'secret': secret, 'lab_port': lab_port, 'kibana_port': kibana_port,
                 'arkime_port': arkime_port, 'started_at': time.time()}
        _write_new(case_dir / 'state.json', json.dumps(state, sort_keys=True).encode('ascii'))
        _write_json(root / 'last.json', {'case_id': loaded, 'evidence_dir': str(folder)})
        variables = {
            'PROJECT': state['project'], 'LAB_IMAGE': lab_image(), 'CASE_ID': loaded,
            'EVIDENCE_DIR': (case_dir / 'evidence').as_posix(), 'SECRET_FILE': (case_dir / 'lab-secret').as_posix(),
            'INSTANCE_FILE': (case_dir / 'instance-id').as_posix(), 'LAB_PORT': str(lab_port),
            'KIBANA_PORT': str(kibana_port), 'ARKIME_PORT': str(arkime_port)}
        pid = _launch(['docker', 'compose', '--ansi', 'never', '--progress', 'plain', '-f', str(COMPOSE_FILE),
                       '-p', state['project'], 'up', '-d'], variables, case_dir / 'compose.log')
        _write_json(case_dir / 'up.json', {'pid': pid, 'identity': _identity(pid)})
    except BaseException:
        if not (case_dir / 'up.json').exists():
            if pid is not None:
                _terminate(pid)
            shutil.rmtree(case_dir, ignore_errors=True)
        raise
    return _status(profile, root, loaded)


def _stop(profile, root, case_id):
    result = _base(profile)
    if case_id is None:
        return result
    case_dir = _case_dir(root, case_id)
    result.update(case_id=case_id, project=project(case_id))
    if os.path.lexists(case_dir / 'up.json') and _up_running(case_dir):
        # A start still in progress would go on creating containers after `down`.
        _terminate(_read_json(case_dir / 'up.json')['pid'])
        deadline = time.monotonic() + 15
        while _up_running(case_dir):
            if time.monotonic() > deadline:
                raise StackFailure('compose_up_still_running')
            time.sleep(0.5)
    answer = _docker(['compose', '-p', project(case_id), 'down', '-v', '--remove-orphans', '--timeout', '10'],
                     DOWN_SECONDS)
    if answer.returncode:
        raise StackFailure('compose_down_failed')
    label = 'label=com.docker.compose.project=' + project(case_id)
    for kind in ('container', 'volume', 'network'):
        listed = _docker([kind, 'ls', *(['-a'] if kind == 'container' else []), '-q', '--filter', label])
        if listed.returncode or listed.stdout.strip():
            raise StackFailure('stack_remains')
    shutil.rmtree(case_dir, ignore_errors=True)
    if os.path.lexists(case_dir):
        raise StackFailure('container_state_remains')
    result['reason'] = 'stopped'
    return result


def invoke(action, *, state_dir, profile=PROFILE, case_id=None, evidence_dir=None, wait=0):
    """One lifecycle action on a case's container lab; returns the CLI's result dict, never raises.

    Without `case_id`, status and stop act on the last started case, and start loads `evidence_dir` (else the
    last started case's folder, else the bundled fixture). `wait` (seconds) keeps reading status after a start
    until the lab is no longer starting.
    """
    try:
        if action not in ('status', 'start', 'stop'):
            raise StackFailure('invalid_action')
        if profile != PROFILE:
            raise StackFailure('invalid_profile')
        root = _root(state_dir)
        if action == 'start':
            result = _start(profile, root, evidence_dir, case_id)
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
    except prepare_guest.PreparationError:
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
    args = parser.parse_args(argv)
    result = invoke(args.action, state_dir=args.state_dir, case_id=args.case_id, evidence_dir=args.evidence_dir,
                    wait=args.wait)
    print(json.dumps(result, ensure_ascii=True, allow_nan=False))
    return 1 if result['state'] == 'error' else 0


if __name__ == '__main__':
    sys.exit(main())

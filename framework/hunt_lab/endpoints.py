"""The one read-only answer to "which loopback lab serves this case" (ADR 0005).

A case is served by the analyst VM's guest lab service, found through the runtime's read-only `status`; by
the host-side connected service (`hunt_lab.connected serve`), found through the `hunt-lab-connected/state.json`
it writes beside the VM's state dir; or by a container lab (`hunt_lab.lab_stack`), found through the
`hunt-lab-container/<case_id>/state.json` it writes there. Resolving never starts, stops or creates anything.
Every failure is a fixed snake_case code; a guest's own code is relayed only as `detail`, never its free text.

Each lab service answers only a caller that sends its instance secret in X-Hunt-Lab-Secret, and names its
instance in X-Hunt-Lab-Instance on every answer. The secret sits in a state file only the owning user can
read (`owner_only`): the connected service's or the container lab's state.json, or for the VM the
`<seed>.secret.json` written beside the seed ISO that deployment.json boots. The resolver reads it and `get`
sends it; it never reaches a bot's tool result. The operator's `hunt-lab` status, start and stop replies show
it in `lab_console_url`.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import http.client
import json
import os
from pathlib import Path
import re
import time
from urllib import error, parse, request

LAB_OWNER = 'framework-network-analyst'
CONNECTED_STATE = 'hunt-lab-connected'
STATE_VERSION = 2
INSTANCE_HEADER = 'X-Hunt-Lab-Instance'
SECRET_HEADER = 'X-Hunt-Lab-Secret'
MAX_RESPONSE = 512 * 1024
MAX_ERROR_BODY = 4096
MAX_STATE = 4096
DEFAULT_TIMEOUT = 12
ERROR_CODE = re.compile(r'[a-z0-9_]{1,64}')
CASE_ID = re.compile(r'[a-z0-9-]{3,64}')
INSTANCE = re.compile(r'[0-9a-f]{32}')
# The guest's instance is its cloud-init instance-id (prepare_guest), the same pattern lab_server accepts.
VM_INSTANCE = re.compile(r'[A-Za-z0-9._-]{1,128}')
SECRET = re.compile(r'[0-9a-f]{64}')
ENV_NAME = re.compile(r'[A-Za-z_][A-Za-z0-9_]{0,127}')
STATE_KEYS = frozenset({'version', 'pid', 'port', 'case_id', 'instance', 'secret', 'api_key_env'})
VM_CALLER_VERSION = 1
VM_CALLER_KEYS = frozenset({'version', 'instance', 'secret'})
DEPLOYMENT_MAX = 65536
CONTAINER_STATE = 'hunt-lab-container'
CONTAINER_VERSION = 1
CONTAINER_PROJECT_PREFIX = 'hunt-lab-'
CONTAINER_KEYS = frozenset({'version', 'case_id', 'project', 'instance', 'secret', 'lab_port', 'kibana_port',
                            'arkime_port', 'started_at'})


class QueryFailure(Exception):
    """Fixed public diagnostic; never initialized with raw exception data."""

    def __init__(self, code, detail=None):
        super().__init__(code)
        self.detail = detail


class NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        return None


@dataclass(frozen=True)
class LabEndpoint:
    """A lab service that answered `/case`: the VM's (`origin='vm'`), the connected one (`'connected'`) or a
    container lab's (`'container'`).

    `arkime_url` and `kibana_url` are the VM status's own values, unvalidated, or the container lab's published
    ports; each user checks them.
    `secret` is the caller secret `get` sends; it is left out of the repr.
    """

    lab_url: str
    origin: str
    case: dict
    instance: str | None = None
    arkime_url: str | None = None
    kibana_url: str | None = None
    api_key_env: str | None = None
    secret: str | None = field(default=None, repr=False)

    def get(self, path, profile=None, timeout=DEFAULT_TIMEOUT):
        """One bounded GET from this service, sending its secret; the answer must still name this instance."""
        return get(self.lab_url, path, profile, timeout, instance=self.instance, secret=self.secret)


def endpoint(value):
    """The `http://127.0.0.1:<port>` origin of a reported lab URL, or invalid_owned_endpoint."""
    try:
        url = parse.urlsplit(value or '')
        port = url.port
    except ValueError:
        raise QueryFailure('invalid_owned_endpoint') from None
    if (url.scheme != 'http' or url.hostname != '127.0.0.1' or not port
            or url.username or url.password or url.query or url.fragment or url.path not in ('', '/')):
        raise QueryFailure('invalid_owned_endpoint')
    return value.rstrip('/')


def _guest_error(exc):
    try:
        value = json.loads(exc.read(MAX_ERROR_BODY))
    except Exception:
        return None
    code = value.get('error') if isinstance(value, dict) else None
    # Relay only the guest's fixed snake_case code, never free text.
    return code if isinstance(code, str) and ERROR_CODE.fullmatch(code) else None


def get(base, path, profile=None, timeout=DEFAULT_TIMEOUT, *, instance=None, secret=None):
    """One bounded GET of a JSON object from a loopback lab; no proxies or redirects.

    With `secret`, it is sent in X-Hunt-Lab-Secret (a lab service answers nothing else; without it the
    answer is lab_http_401 with detail caller_not_authorized). With `instance`, the answer (an error answer
    too) must carry it in X-Hunt-Lab-Instance, so a port another process now holds is refused as
    lab_instance_mismatch.
    """
    # Ignore ambient proxy settings; neither proxy credentials nor redirects belong
    # on this explicitly local lab evidence path.
    opener = request.build_opener(request.ProxyHandler({}), NoRedirect())
    headers = {'X-Hermes-Profile': profile} if profile else {}
    if secret is not None:
        headers[SECRET_HEADER] = secret
    req = request.Request(base + path, headers=headers, method='GET')
    try:
        with opener.open(req, timeout=timeout) as response:
            if instance is not None and response.headers.get(INSTANCE_HEADER) != instance:
                raise QueryFailure('lab_instance_mismatch')
            data = response.read(MAX_RESPONSE + 1)
            if len(data) > MAX_RESPONSE:
                raise QueryFailure('lab_response_too_large')
            value = json.loads(data)
            if not isinstance(value, dict):
                raise QueryFailure('lab_invalid_response')
            return value
    except error.HTTPError as exc:
        if instance is not None and exc.headers.get(INSTANCE_HEADER) != instance:
            raise QueryFailure('lab_instance_mismatch') from None
        raise QueryFailure('lab_http_' + str(exc.code), _guest_error(exc)) from None
    except (error.URLError, TimeoutError, OSError):
        raise QueryFailure('lab_unreachable') from None
    except http.client.HTTPException:
        raise QueryFailure('lab_unreachable' if instance is None else 'lab_instance_mismatch') from None
    except ValueError:
        raise QueryFailure('lab_invalid_response') from None


def owner_only(path):
    """Let only the current user and SYSTEM open `path`: a protected DACL on Windows (inherited by what a
    directory later holds), mode 0700 or 0600 elsewhere."""
    if os.name != 'nt':
        os.chmod(path, 0o700 if os.path.isdir(path) else 0o600)
        return
    import ctypes
    from ctypes import wintypes

    advapi = ctypes.WinDLL('advapi32', use_last_error=True)
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    advapi.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    advapi.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
                                           ctypes.POINTER(wintypes.DWORD)]
    advapi.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p]
    advapi.GetSecurityDescriptorDacl.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.BOOL),
                                                 ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.BOOL)]
    advapi.SetNamedSecurityInfoW.argtypes = [wintypes.LPCWSTR, ctypes.c_int, wintypes.DWORD, ctypes.c_void_p,
                                             ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]

    def check(ok):
        if not ok:
            raise ctypes.WinError(ctypes.get_last_error())

    token = wintypes.HANDLE()
    check(advapi.OpenProcessToken(kernel.GetCurrentProcess(), 0x0008, ctypes.byref(token)))  # TOKEN_QUERY
    try:
        size = wintypes.DWORD()
        advapi.GetTokenInformation(token, 1, None, 0, ctypes.byref(size))  # TokenUser
        user = ctypes.create_string_buffer(size.value)
        check(advapi.GetTokenInformation(token, 1, user, size, ctypes.byref(size)))
    finally:
        kernel.CloseHandle(token)
    text = wintypes.LPWSTR()
    # TOKEN_USER starts with the SID pointer.
    check(advapi.ConvertSidToStringSidW(ctypes.c_void_p.from_buffer(user).value, ctypes.byref(text)))
    try:
        sid = text.value
    finally:
        kernel.LocalFree(text)
    descriptor = ctypes.c_void_p()
    check(advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        f'D:P(A;OICI;FA;;;{sid})(A;OICI;FA;;;SY)', 1, ctypes.byref(descriptor), None))
    try:
        present, defaulted, dacl = wintypes.BOOL(), wintypes.BOOL(), ctypes.c_void_p()
        check(advapi.GetSecurityDescriptorDacl(descriptor, ctypes.byref(present), ctypes.byref(dacl),
                                               ctypes.byref(defaulted)))
        # SE_FILE_OBJECT; DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION drops inherited entries.
        status = advapi.SetNamedSecurityInfoW(str(path), 1, 0x00000004 | 0x80000000, None, None, dacl, None)
        if status:
            raise ctypes.WinError(status)
    finally:
        kernel.LocalFree(descriptor)


def caller_file(seed):
    """Where the caller of the VM booted from `seed` finds its instance and secret."""
    seed = Path(seed)
    return seed.with_name(seed.name + '.secret.json')


def write_vm_caller(seed, instance, secret):
    """Write `caller_file(seed)` once, owner-only before any byte of the secret lands in it."""
    if not VM_INSTANCE.fullmatch(instance) or not SECRET.fullmatch(secret):
        raise ValueError('invalid lab instance or secret')
    path = caller_file(seed)
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, 'O_BINARY', 0), 0o600)
    try:
        owner_only(path)
        os.write(descriptor, json.dumps({'version': VM_CALLER_VERSION, 'instance': instance, 'secret': secret},
                                        sort_keys=True).encode('ascii'))
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return path


def _read_json(path, limit):
    with Path(path).open('rb') as handle:
        data = handle.read(limit + 1)
    if len(data) > limit:
        raise ValueError('too large')
    return json.loads(data)


def vm_caller(state_dir):
    """The running VM's (instance, secret): the caller file of the seed deployment.json boots, else
    lab_secret_unavailable (a seed written before lab services required a secret has none: reseed it)."""
    try:
        seed = _read_json(Path(state_dir) / 'deployment.json', DEPLOYMENT_MAX)['seed']
        value = _read_json(caller_file(seed), MAX_STATE)
    except (OSError, ValueError, KeyError, TypeError):
        raise QueryFailure('lab_secret_unavailable') from None
    if (not isinstance(value, dict) or set(value) != VM_CALLER_KEYS or type(value['version']) is not int
            or value['version'] != VM_CALLER_VERSION
            or not isinstance(value['instance'], str) or not VM_INSTANCE.fullmatch(value['instance'])
            or not isinstance(value['secret'], str) or not SECRET.fullmatch(value['secret'])):
        raise QueryFailure('lab_secret_unavailable')
    return value['instance'], value['secret']


def connected_state(state_dir):
    """The connected service's state.json beside the VM's state dir: None when absent or still being written.

    On Windows the service replacing the file blocks a read for a moment, which is waited out.
    """
    path = Path(state_dir).parent / CONNECTED_STATE / 'state.json'
    for attempt in range(20):
        try:
            with path.open('rb') as handle:
                data = handle.read(MAX_STATE + 1)
            break
        except FileNotFoundError:
            return None
        except PermissionError:
            if attempt == 19:
                raise QueryFailure('connected_state_invalid') from None
            time.sleep(0.05)
        except OSError:
            raise QueryFailure('connected_state_invalid') from None
    if not data:
        return None
    try:
        state = json.loads(data) if len(data) <= MAX_STATE else None
    except ValueError:
        state = None
    if (not isinstance(state, dict) or set(state) != STATE_KEYS or type(state['version']) is not int
            or state['version'] != STATE_VERSION
            or type(state['port']) is not int or not 0 < state['port'] < 65536 or type(state['pid']) is not int
            or not isinstance(state['case_id'], str) or not CASE_ID.fullmatch(state['case_id'])
            or not isinstance(state['instance'], str) or not INSTANCE.fullmatch(state['instance'])
            or not isinstance(state['secret'], str) or not SECRET.fullmatch(state['secret'])
            or not isinstance(state['api_key_env'], str) or not ENV_NAME.fullmatch(state['api_key_env'])):
        raise QueryFailure('connected_state_invalid')
    return state


def container_state(path):
    """One container lab's state.json (hunt_lab.lab_stack): None when absent or still empty, else validated."""
    try:
        with Path(path).open('rb') as handle:
            data = handle.read(MAX_STATE + 1)
    except FileNotFoundError:
        return None
    except OSError:
        raise QueryFailure('container_state_invalid') from None
    if not data:
        return None
    try:
        state = json.loads(data) if len(data) <= MAX_STATE else None
    except ValueError:
        state = None
    ports = [state.get(key) for key in ('lab_port', 'kibana_port', 'arkime_port')] if isinstance(state, dict) else []
    if (not isinstance(state, dict) or set(state) != CONTAINER_KEYS or type(state['version']) is not int
            or state['version'] != CONTAINER_VERSION
            or not isinstance(state['case_id'], str) or not CASE_ID.fullmatch(state['case_id'])
            or state['project'] != CONTAINER_PROJECT_PREFIX + state['case_id']
            or not isinstance(state['instance'], str) or not INSTANCE.fullmatch(state['instance'])
            or not isinstance(state['secret'], str) or not SECRET.fullmatch(state['secret'])
            or any(type(port) is not int or not 0 < port < 65536 for port in ports) or len(set(ports)) != 3
            or type(state['started_at']) not in (int, float)):
        raise QueryFailure('container_state_invalid')
    return state


def container_states(state_dir, case_id=None):
    """The container labs beside the VM's state dir: only `case_id`'s when given, else every case's."""
    root = Path(state_dir).parent / CONTAINER_STATE
    if case_id is not None:
        names = [case_id] if CASE_ID.fullmatch(case_id) else []
    else:
        try:
            names = sorted(child.name for child in root.iterdir() if child.is_dir())
        except FileNotFoundError:
            return []
        except OSError:
            raise QueryFailure('container_state_invalid') from None
    states = []
    for name in names:
        state = container_state(root / name / 'state.json')
        if state is not None:
            if state['case_id'] != name:
                raise QueryFailure('container_state_invalid')
            states.append(state)
    return states


def _vm(runtime, state_dir, profile):
    status = runtime.invoke('status', state_dir=state_dir, profile=LAB_OWNER)
    if status.get('profile') != LAB_OWNER or status.get('state') != 'running':
        return None
    base = endpoint(status.get('lab_url'))
    instance, secret = vm_caller(state_dir)
    return LabEndpoint(base, 'vm', get(base, '/case', profile, instance=instance, secret=secret), instance=instance,
                       arkime_url=status.get('arkime_url'), kibana_url=status.get('kibana_url'), secret=secret)


def _connected(state, profile):
    base = f"http://127.0.0.1:{state['port']}"
    case = get(base, '/case', profile, instance=state['instance'], secret=state['secret'])
    return LabEndpoint(base, 'connected', case, instance=state['instance'], api_key_env=state['api_key_env'],
                       secret=state['secret'])


def _container(state, profile):
    base = f"http://127.0.0.1:{state['lab_port']}"
    case = get(base, '/case', profile, instance=state['instance'], secret=state['secret'])
    return LabEndpoint(base, 'container', case, instance=state['instance'],
                       arkime_url=f"http://127.0.0.1:{state['arkime_port']}",
                       kibana_url=f"http://127.0.0.1:{state['kibana_port']}", secret=state['secret'])


def resolve(state_dir, case_id=None, *, runtime, profile=None, environ=None):
    """The one lab serving `case_id` (or, without one, the one lab serving any case), else a fixed code.

    - owned_vm_not_running: no lab is up (the VM, a connected service or a container lab); a connected service
      or container lab whose state.json names another case is not asked, so it counts as not up.
    - case_mismatch: a lab answered, but none for `case_id`.
    - ambiguous_lab: more than one lab serves it (any two of the VM, the connected service and container labs).
    - key_in_bot_environment: with `environ` (a bot's own process environment), a connected case is refused
      while that environment holds the variable the service read its API key from.
    A lab that fails to answer is skipped when another one serves the case; otherwise its code is raised.
    """
    if state_dir is None:
        raise QueryFailure('lab_state_unavailable')
    state = connected_state(state_dir)
    containers = container_states(state_dir, case_id)
    failures = []

    def answered(find):
        try:
            return find()
        except QueryFailure as exc:
            failures.append(exc)
            return None

    vm = answered(lambda: _vm(runtime, state_dir, profile))
    # A service serving another case is not asked: a stale state file would cost every VM tool call a timeout.
    probe = state is not None and (case_id is None or state['case_id'] == case_id)
    connected = answered(lambda: _connected(state, profile)) if probe else None
    stacks = [answered(lambda stack=stack: _container(stack, profile)) for stack in containers]
    found = [lab for lab in (vm, connected, *stacks) if lab is not None]
    matches = [lab for lab in found if case_id is None or lab.case.get('case_id') == case_id]
    if len(matches) > 1:
        raise QueryFailure('ambiguous_lab')
    if not matches:
        if failures:
            raise failures[0]
        raise QueryFailure('case_mismatch' if found else 'owned_vm_not_running')
    [lab] = matches
    if lab.origin == 'connected' and environ is not None and lab.api_key_env in environ:
        raise QueryFailure('key_in_bot_environment')
    return lab

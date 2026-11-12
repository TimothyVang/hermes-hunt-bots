"""The one read-only answer to "which loopback lab serves this case" (ADR 0005).

A case is served either by the analyst VM's guest lab service, found through the runtime's read-only
`status`, or by the host-side connected service (`hunt_lab.connected serve`), found through the
`hunt-lab-connected/state.json` it writes beside the VM's state dir. Resolving never starts, stops or
creates anything. Every failure is a fixed snake_case code; a guest's own code is relayed only as
`detail`, never its free text.
"""
from __future__ import annotations

from dataclasses import dataclass
import http.client
import json
from pathlib import Path
import re
import time
from urllib import error, parse, request

LAB_OWNER = 'framework-network-analyst'
CONNECTED_STATE = 'hunt-lab-connected'
STATE_VERSION = 1
INSTANCE_HEADER = 'X-Hunt-Lab-Instance'
MAX_RESPONSE = 512 * 1024
MAX_ERROR_BODY = 4096
MAX_STATE = 4096
DEFAULT_TIMEOUT = 12
ERROR_CODE = re.compile(r'[a-z0-9_]{1,64}')
CASE_ID = re.compile(r'[a-z0-9-]{3,64}')
INSTANCE = re.compile(r'[0-9a-f]{32}')
ENV_NAME = re.compile(r'[A-Za-z_][A-Za-z0-9_]{0,127}')
STATE_KEYS = frozenset({'version', 'pid', 'port', 'case_id', 'instance', 'api_key_env'})


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
    """A lab service that answered `/case`: the VM's (`origin='vm'`) or the connected one (`'connected'`).

    `arkime_url` and `kibana_url` are the VM status's own values, unvalidated; each user checks them.
    """

    lab_url: str
    origin: str
    case: dict
    instance: str | None = None
    arkime_url: str | None = None
    kibana_url: str | None = None
    api_key_env: str | None = None

    def get(self, path, profile=None, timeout=DEFAULT_TIMEOUT):
        """One bounded GET from this service; a connected answer must still name this instance."""
        return get(self.lab_url, path, profile, timeout, instance=self.instance)


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


def get(base, path, profile=None, timeout=DEFAULT_TIMEOUT, *, instance=None):
    """One bounded GET of a JSON object from a loopback lab; no proxies, redirects or credentials.

    With `instance`, the answer (an error answer too) must carry it in X-Hunt-Lab-Instance, so a port
    another process now holds is refused as lab_instance_mismatch.
    """
    # Ignore ambient proxy settings; neither proxy credentials nor redirects belong
    # on this explicitly local, credential-free lab evidence path.
    opener = request.build_opener(request.ProxyHandler({}), NoRedirect())
    headers = {'X-Hermes-Profile': profile} if profile else {}
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
            or not isinstance(state['api_key_env'], str) or not ENV_NAME.fullmatch(state['api_key_env'])):
        raise QueryFailure('connected_state_invalid')
    return state


def _vm(runtime, state_dir, profile):
    status = runtime.invoke('status', state_dir=state_dir, profile=LAB_OWNER)
    if status.get('profile') != LAB_OWNER or status.get('state') != 'running':
        return None
    base = endpoint(status.get('lab_url'))
    return LabEndpoint(base, 'vm', get(base, '/case', profile), arkime_url=status.get('arkime_url'),
                       kibana_url=status.get('kibana_url'))


def _connected(state, profile):
    base = f"http://127.0.0.1:{state['port']}"
    case = get(base, '/case', profile, instance=state['instance'])
    return LabEndpoint(base, 'connected', case, instance=state['instance'], api_key_env=state['api_key_env'])


def resolve(state_dir, case_id=None, *, runtime, profile=None, environ=None):
    """The one lab serving `case_id` (or, without one, the one lab serving any case), else a fixed code.

    - owned_vm_not_running: neither the VM nor a connected service is up; a connected service whose state.json
      names another case is not asked, so it counts as not up.
    - case_mismatch: a lab answered, but none for `case_id`.
    - ambiguous_lab: the VM and the connected service both serve it.
    - key_in_bot_environment: with `environ` (a bot's own process environment), a connected case is refused
      while that environment holds the variable the service read its API key from.
    A lab that fails to answer is skipped when the other one serves the case; otherwise its code is raised.
    """
    if state_dir is None:
        raise QueryFailure('lab_state_unavailable')
    state = connected_state(state_dir)
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
    found = [lab for lab in (vm, connected) if lab is not None]
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

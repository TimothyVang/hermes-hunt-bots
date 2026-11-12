"""Built-in lab installation and explicit local human CLI controls (stdlib only)."""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys

import install_desktop

ROOT = Path(__file__).absolute().parent
PROFILE = 'framework-network-analyst'
# Written into a Hermes home by the self-updating launcher while it updates and restarts that home's gateway.
UPDATE_MARKER = '.hermes-update-in-progress'
# Every authored profile receives the read-only hunt tools; only PROFILE owns the VM.
AUTHORED_PROFILES = (
    'framework-coordinator', 'framework-researcher', 'framework-builder',
    'framework-reviewer', 'framework-librarian', PROFILE,
)
LICENSES = (
    'noVNC-LICENSE.txt', 'noVNC-AUTHORS.txt', 'LICENSE.MPL-2.0',
    'LICENSE.BSD-2-Clause', 'LICENSE.BSD-3-Clause', 'LICENSE.OFL-1.1',
    'pako-LICENSE.MIT', 'regenerator-LICENSE.MIT', 'babel-LICENSE.MIT',
    'lucide-LICENSE.txt',
)
DESKTOP_FILES = ('plugin.js', 'package.json', 'console-provenance.json') + tuple(
    'licenses/' + name for name in LICENSES)
BACKEND_FILES = (
    '__init__.py', 'runtime.py', 'managed.py', 'prepare_guest.py',
    'query_adapter.py', 'endpoints.py', 'lab_browser.py', 'browser_policy.py', 'humanize.py',
    'actionability.py', 'plugin.yaml', 'assets.json',
    'guest/compose.yaml', 'guest/arkime.ini', 'guest/bootstrap_guest.sh',
    'guest/ingest.py', 'guest/lab_server.py', 'guest/image-lock.json',
    'guest/kibana.yml', 'guest/kibana_setup.py',
    'fixtures/dns-lab-001/events.jsonl', 'fixtures/dns-lab-001/traffic.pcap',
    'fixtures/dns-lab-001/case.json',
)
BUNDLE_FILES = BACKEND_FILES + tuple('desktop/' + name for name in DESKTOP_FILES)
# Native Hermes imports a plugin once per gateway process, and `plugins enable` on an already
# enabled plugin does not notify the gateway. A long-lived gateway (the default-profile multiplexer
# serves every profile) would keep the previous bundle's tools, so ask the gateway serving each
# profile to re-import its plugins: the profile's own socket, else the multiplexer's for this home.
GATEWAY_RELOAD = '\n'.join((
    'import json',
    'from pathlib import Path',
    'from gateway.control_socket import reload_gateway_plugins',
    'from hermes_constants import get_default_hermes_root, get_hermes_home',
    'home, root = Path(get_hermes_home()), Path(get_default_hermes_root())',
    'answer = reload_gateway_plugins(home)',
    'if answer is None and root.resolve() != home.resolve():',
    '    answer = reload_gateway_plugins(root, profile_home=home)',
    'print(json.dumps(answer))',
))


def resolve_home(home=None, *, create=False):
    """Resolve one standard root, never search other homes or read private config; `create` makes a missing one."""
    suffix = os.environ.get('HERMES_DATA_DIR_SUFFIX', '')
    if sys.platform == 'win32':
        base = Path(os.environ.get('LOCALAPPDATA') or Path.home() / 'AppData' / 'Local')
        standard = base / ('hermes' + suffix)
    else:
        standard = Path.home() / ('.hermes' + suffix)
    standard = Path(os.path.abspath(standard))
    raw = home if home is not None else os.environ.get('HERMES_HOME', '').strip()
    path = Path(os.path.expandvars(os.path.expanduser(str(raw)))) if raw else standard
    path = Path(os.path.abspath(path))
    # A profile-scoped process may supply its exact native home, not another root.
    if path.parent.name == 'profiles':
        if path.name != PROFILE:
            raise ValueError('Use the general Hermes home or the exact analyst profile home')
        path = path.parent.parent
    # Native Hermes anchors every descendant of its standard home back to that
    # root. Refuse a nested alternative rather than stage here and enable there.
    if path != standard and path.is_relative_to(standard):
        raise ValueError('Nested alternative Hermes roots are not supported; use the general native home')
    return install_desktop.ordinary_directory(path, create=create)


def registered_profile(home, name, *, required=True):
    """Check exact native distribution identity without opening SOUL or configuration."""
    if name not in AUTHORED_PROFILES:
        raise ValueError('Unknown authored profile')
    home = install_desktop.ordinary_directory(home)
    profiles = home / 'profiles'
    if not profiles.exists() and not profiles.is_symlink():
        if required:
            raise ValueError('Native analyst profile is not installed; run setup_hermes.py install')
        return None
    install_desktop.ordinary_directory(profiles)
    profile = profiles / name
    if not profile.exists() and not profile.is_symlink():
        if required:
            raise ValueError('Native authored profile is not installed; run setup_hermes.py install')
        return None
    install_desktop.ordinary_directory(profile)
    marker = profile / 'distribution.yaml'
    if not stat.S_ISREG(install_desktop.no_alias(marker).st_mode):
        raise ValueError('Unknown existing native profile owner')
    if marker.stat().st_size > 65536:
        raise ValueError('Invalid distribution identity metadata')
    text = marker.read_text(encoding='utf-8-sig')
    # Native profile install preserves and stamps this public manifest. Only the
    # canonical identity is inspected; private profile files are never opened.
    matches = re.findall(r'^name:\s*[\"\']?([a-z0-9-]+)[\"\']?\s*$', text, re.MULTILINE)
    tombstones = profiles / '.deleted'
    if tombstones.exists() or tombstones.is_symlink():
        install_desktop.ordinary_directory(tombstones)
    if matches != [name] or (tombstones / name).exists():
        raise ValueError('Native distribution identity does not match the exact owner')
    # Native discovery requires an identity marker; inspect only the authored
    # SOUL's file type, never its contents or other profile/configuration files.
    if not stat.S_ISREG(install_desktop.no_alias(profile / 'SOUL.md').st_mode):
        raise ValueError('Native authored identity marker missing')
    return profile


def bundle_source(kit_root=ROOT):
    root = install_desktop.ordinary_directory(Path(kit_root).absolute() / 'hunt_lab')
    files = {}
    for relative in BUNDLE_FILES:
        path = root / relative
        install_desktop.ordinary_directory(path.parent)
        if not stat.S_ISREG(install_desktop.no_alias(path).st_mode):
            raise ValueError('Regular authored lab asset required')
        files[relative] = path.read_bytes()
    return files


def hermes_python(executable):
    """The interpreter of the Hermes CLI's own environment (its console-script sibling)."""
    names = ('python.exe',) if os.name == 'nt' else ('python', 'python3')
    for folder in dict.fromkeys((Path(executable).absolute().parent, Path(executable).resolve().parent)):
        for name in names:
            if (folder / name).is_file():
                return folder / name
    raise ValueError('Hermes interpreter not found beside the CLI; cannot refresh a running gateway')


def reload_gateway(profile, python, runner):
    """Make a running gateway serve the installed bundle now; 'not_running' when none answered."""
    result = runner([str(python), '-I', '-c', GATEWAY_RELOAD], env=dict(os.environ, HERMES_HOME=str(profile)),
                    capture_output=True, text=True, timeout=120, check=False)
    refused = ValueError(f'The running Hermes gateway still serves the previous hunt-lab tools for {profile.name}; '
                         'restart it when no hunt is running (hermes gateway restart), then rerun install')
    if result.returncode != 0:
        raise refused
    try:
        answer = json.loads((result.stdout or '').strip().splitlines()[-1])
    except (IndexError, ValueError):
        raise refused from None
    if answer is None:
        return 'not_running'
    if not (isinstance(answer, dict) and answer.get('reloaded') is True
            and 'hunt-lab' in (answer.get('plugins') or ())):
        raise refused
    return 'reloaded'


def hermes_executable(explicit=None):
    """The Hermes CLI to run: --hermes, else LAB_HERMES_EXE, else `hermes` on PATH; never a fallback.

    The `hermes` on PATH may be a self-updating launcher, which drains the lab's gateway mid-hunt;
    LAB_HERMES_EXE names the lab install's own executable."""
    configured = os.environ.get('LAB_HERMES_EXE', '').strip()
    name = str(explicit) if explicit else configured or 'hermes'
    executable = shutil.which(name)
    if not executable:
        source = '--hermes' if explicit else 'LAB_HERMES_EXE' if configured else 'PATH'
        raise ValueError(f'Hermes CLI not found ({source}: {name}); install the framework Hermes prerequisite')
    return executable


def refuse_during_update(home):
    """Refuse while a Hermes update holds this home; running the CLI then can stop a hunt's gateway.

    The marker names its owner's pid on line 1 and may name a delegate (`delegate:<pid> ct:<n>`) on a
    later line (Hermes `hermes_cli/update_lock.py`); the update is live while either runs. A marker
    whose processes are all gone is named stale, with how to clear it; it is never deleted here."""
    marker = Path(home) / UPDATE_MARKER
    if not (marker.exists() or marker.is_symlink()):
        return
    pids = _marker_pids(marker)
    if pids and not any(_pid_alive(pid) for pid in pids):
        named = f'process {pids[0]}, which is' if len(pids) == 1 else f'processes {pids[0]} and {pids[1]}, which are'
        raise ValueError(f'A stale Hermes update marker blocks this home: {marker} names {named} not running. '
                         'If no Hermes update is running, delete that file, then retry.')
    raise ValueError(f'A Hermes update is in progress for this home ({marker} exists); retry after it finishes')


_DELEGATE_LINE = re.compile(r'delegate:([0-9]+) ct:[0-9]+(?:\.[0-9]+)?')


def _marker_pids(marker):
    """The owner pid (line 1) and any delegate pid; empty when unreadable or still being written."""
    try:
        with open(marker, 'rb') as handle:
            lines = handle.read(4096).decode('ascii', 'replace').splitlines()
    except OSError:
        return ()
    owner = lines[0].strip() if lines else ''
    if not (owner.isdigit() and 0 < int(owner) < 2 ** 32):
        return ()
    delegates = [int(match[1]) for match in map(_DELEGATE_LINE.fullmatch, lines[3:]) if match]
    return (int(owner), *[pid for pid in delegates if 0 < pid < 2 ** 32][:1])


def _pid_alive(pid):
    if os.name != 'nt':
        try:
            os.kill(pid, 0)
        except (ProcessLookupError, OverflowError):
            return False
        except PermissionError:
            return True
        return True
    import ctypes
    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel32.OpenProcess.restype = ctypes.c_void_p
    kernel32.OpenProcess.argtypes = (ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong)
    kernel32.GetExitCodeProcess.argtypes = (ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong))
    kernel32.CloseHandle.argtypes = (ctypes.c_void_p,)
    handle = kernel32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
    if not handle:
        return ctypes.get_last_error() == 5  # access denied: it exists
    try:
        code = ctypes.c_ulong()
        return bool(kernel32.GetExitCodeProcess(handle, ctypes.byref(code))) and code.value == 259  # STILL_ACTIVE
    finally:
        kernel32.CloseHandle(handle)


def registered_profiles(root):
    """The analyst (required) and every other registered authored profile: {name: profile dir}."""
    profiles = {PROFILE: registered_profile(root, PROFILE)}
    for name in AUTHORED_PROFILES:
        if name != PROFILE:
            profile = registered_profile(root, name, required=False)
            if profile is not None:
                profiles[name] = profile
    return profiles


def bundles(root, profiles, kit_root=ROOT):
    """Every hash-owned copy install writes, {destination folder: {relative path: bytes}}.

    The backend goes to each given profile, the standalone Hunting Lab page and the workspace companion to the
    general home. A backend desktop/ folder would make Hermes auto-copy a unified package with Desktop opt-in
    posture, so the page is installed as its own standalone SDK component instead."""
    files = bundle_source(kit_root)
    companion_root = Path(kit_root).absolute() / 'desktop' / install_desktop.PLUGIN
    install_desktop.ordinary_directory(companion_root)
    companion = companion_root / 'plugin.js'
    if not stat.S_ISREG(install_desktop.no_alias(companion).st_mode):
        raise ValueError('Regular companion source required')
    backend = {name: files[name] for name in BACKEND_FILES}
    result = {profile / 'plugins' / 'hunt-lab': backend for profile in profiles.values()}
    result[Path(root) / 'desktop-plugins' / 'hunt-lab'] = {name: files['desktop/' + name] for name in DESKTOP_FILES}
    result[Path(root) / 'desktop-plugins' / install_desktop.PLUGIN] = {'plugin.js': companion.read_bytes()}
    return result


def install(home=None, hermes=None, kit_root=ROOT, runner=subprocess.run):
    """Stage both native halves and the existing companion; no VM/download action.

    The backend goes to the analyst (required) and every other registered authored
    profile so each can load its read-only tools; VM lifecycle stays analyst-only.
    """
    root = resolve_home(home)
    refuse_during_update(root)
    profiles = registered_profiles(root)
    executable = hermes_executable(hermes)
    python = hermes_python(executable)
    # Only the human Start in the standalone page authorizes setup or VM execution.
    staged = {destination: install_desktop.sync_bundle(destination.parent, destination.name, files)
              for destination, files in bundles(root, profiles, kit_root).items()}
    backend = staged[profiles[PROFILE] / 'plugins' / 'hunt-lab']
    desktop = staged[root / 'desktop-plugins' / 'hunt-lab']
    env = dict(os.environ, HERMES_HOME=str(root))
    for name in profiles:
        result = runner([executable, '-p', name, 'plugins', 'enable', 'hunt-lab'],
                        env=env, check=False)
        if result.returncode != 0:
            raise ValueError('Native Hermes plugin enable failed; no VM operation was attempted')
    gateway = {name: reload_gateway(profile, python, runner) for name, profile in profiles.items()}
    return {'profile': PROFILE, 'tool_profiles': list(profiles), 'backend': str(backend),
            'desktop': str(desktop), 'gateway': gateway, 'state': 'installed', 'prepared': False}


def command(args):
    """Run one explicit native command before ledger access; never fall back."""
    home = resolve_home(args.home)
    refuse_during_update(home)
    registered_profile(home, PROFILE)
    executable = hermes_executable(args.hermes)
    if args.lab_operation == 'check':
        # Source and exact registered paths only; no enable, download, or VM RPC.
        bundle_source()
        print(json.dumps({'profile': PROFILE, 'state': 'available'}))
        return 0
    argv = [executable, '-p', PROFILE, 'hunt-lab', args.lab_operation]
    if args.lab_operation == 'query':
        argv += ['--dataset', args.dataset, '--q', args.q, '--host', args.host,
                 '--limit', str(args.limit), '--offset', str(args.offset)]
        if args.case_id is not None:
            argv += ['--case-id', args.case_id]
    return subprocess.run(argv, env=dict(os.environ, HERMES_HOME=str(home)), check=False).returncode

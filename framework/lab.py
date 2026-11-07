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
# Every authored profile receives the read-only hunt tools; only PROFILE owns the VM.
AUTHORED_PROFILES = (
    'framework-coordinator', 'framework-researcher', 'framework-builder',
    'framework-reviewer', 'framework-librarian', PROFILE,
)
LICENSES = (
    'noVNC-LICENSE.txt', 'noVNC-AUTHORS.txt', 'LICENSE.MPL-2.0',
    'LICENSE.BSD-2-Clause', 'LICENSE.BSD-3-Clause', 'LICENSE.OFL-1.1',
    'pako-LICENSE.MIT', 'regenerator-LICENSE.MIT', 'babel-LICENSE.MIT',
)
DESKTOP_FILES = ('plugin.js', 'package.json', 'console-provenance.json') + tuple(
    'licenses/' + name for name in LICENSES)
BACKEND_FILES = (
    '__init__.py', 'runtime.py', 'managed.py', 'prepare_guest.py',
    'query_adapter.py', 'lab_browser.py', 'browser_policy.py', 'humanize.py',
    'actionability.py', 'plugin.yaml', 'assets.json',
    'guest/compose.yaml', 'guest/arkime.ini', 'guest/bootstrap_guest.sh',
    'guest/ingest.py', 'guest/lab_server.py', 'guest/image-lock.json',
    'fixtures/dns-lab-001/events.jsonl', 'fixtures/dns-lab-001/traffic.pcap',
    'fixtures/dns-lab-001/case.json',
)
BUNDLE_FILES = BACKEND_FILES + tuple('desktop/' + name for name in DESKTOP_FILES)


def resolve_home(home=None):
    """Resolve one standard root, never search other homes or read private config."""
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
    return install_desktop.ordinary_directory(path)


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


def install(home=None, hermes=None, kit_root=ROOT, runner=subprocess.run):
    """Stage both native halves and the existing companion; no VM/download action.

    The backend goes to the analyst (required) and every other registered authored
    profile so each can load its read-only tools; VM lifecycle stays analyst-only.
    """
    root = resolve_home(home)
    profiles = {PROFILE: registered_profile(root, PROFILE)}
    for name in AUTHORED_PROFILES:
        if name != PROFILE:
            profile = registered_profile(root, name, required=False)
            if profile is not None:
                profiles[name] = profile
    executable = shutil.which(str(hermes) if hermes else 'hermes')
    if not executable:
        raise ValueError('Hermes CLI not found; install the framework Hermes prerequisite')
    files = bundle_source(kit_root)
    companion_root = Path(kit_root).absolute() / 'desktop' / install_desktop.PLUGIN
    install_desktop.ordinary_directory(companion_root)
    companion = companion_root / 'plugin.js'
    if not stat.S_ISREG(install_desktop.no_alias(companion).st_mode):
        raise ValueError('Regular companion source required')
    companion_data = companion.read_bytes()
    # A backend desktop/ folder makes Hermes auto-copy a unified package with
    # Desktop opt-in posture. Install the explicit standalone SDK component
    # instead; only its human Start authorizes setup or VM execution.
    backend_files = {name: files[name] for name in BACKEND_FILES}
    backends = {name: install_desktop.sync_bundle(profile / 'plugins', 'hunt-lab', backend_files)
                for name, profile in profiles.items()}
    desktop = install_desktop.sync_bundle(root / 'desktop-plugins', 'hunt-lab', {
        name: files['desktop/' + name] for name in DESKTOP_FILES})
    install_desktop.install(root, companion_data)
    env = dict(os.environ, HERMES_HOME=str(root))
    for name in profiles:
        result = runner([executable, '-p', name, 'plugins', 'enable', 'hunt-lab'],
                        env=env, check=False)
        if result.returncode != 0:
            raise ValueError('Native Hermes plugin enable failed; no VM operation was attempted')
    return {'profile': PROFILE, 'tool_profiles': list(profiles), 'backend': str(backends[PROFILE]),
            'desktop': str(desktop), 'state': 'installed', 'prepared': False}


def command(args):
    """Run one explicit native command before ledger access; never fall back."""
    home = resolve_home(args.home)
    registered_profile(home, PROFILE)
    executable = shutil.which(str(args.hermes) if args.hermes else 'hermes')
    if not executable:
        raise ValueError('Hermes CLI not found; install the framework Hermes prerequisite')
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

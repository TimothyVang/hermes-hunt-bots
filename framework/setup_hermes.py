#!/usr/bin/env python3
"""Validate and explicitly install this kit's authored Hermes distributions."""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys

HERE = Path(__file__).resolve().parent
BOTS = HERE / 'hermes-bots'
CATALOG = BOTS / 'catalog.json'
INSTALL_URL = 'https://hermes-agent.nousresearch.com/docs/getting-started/installation'
PLATFORM_URL = 'https://hermes-agent.nousresearch.com/docs/getting-started/platform-support'
EXPECTED_NAMES = frozenset((
    'framework-coordinator', 'framework-researcher', 'framework-builder',
    'framework-reviewer', 'framework-librarian', 'framework-network-analyst',
))
ENTRY_KEYS = frozenset(('name', 'title', 'description', 'soul_path', 'distribution_path', 'role'))
DISTRIBUTION_FILES = frozenset(('distribution.yaml', 'SOUL.md', '.gitignore'))


class SetupError(ValueError):
    """Authored kit or local runtime is not safe/ready for the requested action."""


def _regular_file(path):
    try:
        info = path.lstat()
    except OSError as exc:
        raise SetupError(f'Cannot inspect authored path {path}: {exc}') from None
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or _reparse_point(info):
        raise SetupError(f'Authored path must be a regular, non-linked file: {path}')


def _reparse_point(info):
    # Windows junctions and other reparse points are not reported as symlinks on
    # all supported Python versions. Reject them alongside symbolic links.
    return bool(getattr(info, 'st_file_attributes', 0) & getattr(stat, 'FILE_ATTRIBUTE_REPARSE_POINT', 0x400))


def _safe_relative(root, value, label):
    if not isinstance(value, str) or not value or '\\' in value:
        raise SetupError(f'Invalid {label} in catalog: {value!r}')
    relative = Path(value)
    if relative.is_absolute() or any(part in ('', '.', '..') for part in relative.parts):
        raise SetupError(f'{label} must be a normalized relative path inside hermes-bots: {value!r}')
    candidate = root / relative
    try:
        candidate.resolve(strict=True).relative_to(root.resolve(strict=True))
    except (OSError, ValueError):
        raise SetupError(f'{label} escapes the authored hermes-bots directory or is missing: {value!r}') from None
    return candidate


def _reject_json_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise SetupError(f'Duplicate catalog property: {key}')
        result[key] = value
    return result


def load_catalog(kit_root=HERE):
    """Read and fully validate every catalog distribution without side effects."""
    root = Path(kit_root).resolve()
    bots = root / 'hermes-bots'
    _regular_directory_chain(root, bots)
    _regular_file(bots / 'catalog.json')
    try:
        catalog = json.loads((bots / 'catalog.json').read_text(encoding='utf-8'), object_pairs_hook=_reject_json_duplicates)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise SetupError(f'Cannot read authored catalog: {exc}') from None
    if not isinstance(catalog, list) or not catalog:
        raise SetupError('Authored catalog must be a non-empty JSON array.')

    names = set()
    validated = []
    for entry in catalog:
        if not isinstance(entry, dict) or set(entry) != ENTRY_KEYS:
            raise SetupError('Each catalog entry must contain exactly name, title, description, soul_path, distribution_path, and role.')
        name = entry['name']
        if not isinstance(name, str) or name not in EXPECTED_NAMES:
            raise SetupError(f'Unknown authored profile name: {name!r}')
        if name in names:
            raise SetupError(f'Duplicate authored profile name: {name}')
        names.add(name)
        if any(not isinstance(entry[key], str) or not entry[key].strip() for key in ENTRY_KEYS):
            raise SetupError(f'Catalog entry {name} has an empty or invalid field.')
        if entry['distribution_path'] != name or entry['soul_path'] != name + '/SOUL.md':
            raise SetupError(f'Catalog paths for {name} do not identify its authored distribution and SOUL.')
        if entry['role'] not in ('coordinator', 'researcher', 'builder', 'reviewer', 'librarian'):
            raise SetupError(f'Unknown role for {name}: {entry["role"]!r}')
        directory = _safe_relative(bots, entry['distribution_path'], 'distribution_path')
        soul = _safe_relative(bots, entry['soul_path'], 'soul_path')
        _regular_directory_chain(bots, directory)
        actual = set()
        try:
            children = list(directory.iterdir())
        except OSError as exc:
            raise SetupError(f'Cannot inspect distribution {name}: {exc}') from None
        for child in children:
            info = child.lstat()
            if stat.S_ISLNK(info.st_mode) or _reparse_point(info):
                raise SetupError(f'Linked paths are forbidden in distribution {name}: {child.name}')
            if not stat.S_ISREG(info.st_mode):
                raise SetupError(f'Non-regular entries are forbidden in distribution {name}: {child.name}')
            actual.add(child.name)
        if actual != DISTRIBUTION_FILES:
            raise SetupError(f'Distribution {name} must contain exactly distribution.yaml, SOUL.md, and .gitignore (found: {", ".join(sorted(actual)) or "none"}).')
        for filename in DISTRIBUTION_FILES:
            _regular_file(directory / filename)
        if soul != directory / 'SOUL.md':
            raise SetupError(f'Catalog SOUL path does not match distribution for {name}.')
        _validate_manifest(directory / 'distribution.yaml', entry)
        validated.append((entry, directory.resolve()))
    if names != EXPECTED_NAMES:
        missing = ', '.join(sorted(EXPECTED_NAMES - names))
        raise SetupError('Catalog is missing known authored profiles: ' + missing)
    return validated


def _regular_directory_chain(root, directory):
    current = root
    for part in directory.relative_to(root).parts:
        current = current / part
        try:
            info = current.lstat()
        except OSError as exc:
            raise SetupError(f'Cannot inspect authored directory {current}: {exc}') from None
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or _reparse_point(info):
            raise SetupError(f'Authored distribution path must use ordinary directories: {current}')


def _validate_manifest(path, entry):
    try:
        text = path.read_text(encoding='utf-8')
    except (OSError, UnicodeError) as exc:
        raise SetupError(f'Cannot read manifest for {entry["name"]}: {exc}') from None
    # Match the deliberately simple authored YAML subset exactly; do not pretend
    # to parse general YAML or accept aliases, tags, duplicate/unknown keys.
    match = re.fullmatch(
        r'name: ([a-z0-9-]+)\nversion: "([0-9]+\.[0-9]+\.[0-9]+)"\n'
        r'description: "([^"\r\n]*)"\ndistribution_owned:\n  - SOUL\.md\n?', text)
    if not match or match.group(1) != entry['name'] or match.group(3) != entry['description']:
        raise SetupError(f'Manifest identity or ownership is invalid for {entry["name"]}; expected its matching name/description and ownership of SOUL.md only.')


def resolve_hermes(override=None):
    """--hermes, else LAB_HERMES_EXE, else `hermes` on PATH (lab.hermes_executable).

    Raises SetupError naming what was tried (for example a LAB_HERMES_EXE that does not exist)."""
    import lab
    try:
        return lab.hermes_executable(str(Path(override).expanduser()) if override else None)
    except ValueError as exc:
        raise SetupError(f'{exc}\n{missing_hermes_message()}') from None


def missing_hermes_message():
    return ('Hermes CLI was not found. Install Hermes using the official guide: ' + INSTALL_URL +
            '\nCheck whether your operating system and architecture are supported: ' + PLATFORM_URL)


def check(hermes_override=None, kit_root=HERE):
    catalog = load_catalog(kit_root)
    print(f'Validated {len(catalog)} authored Hermes distributions.')
    try:
        executable = resolve_hermes(hermes_override)
    except SetupError as exc:
        print(exc)
        return 1
    print(f'Hermes CLI available: {executable}')
    return 0


def _install_profiles(chosen, executable, root, process_factory):
    """Install each missing profile through Hermes' own confirmation; 0, or the exit status that stopped it."""
    import lab
    installed = []
    for entry, directory in chosen:
        if lab.registered_profile(root, entry['name'], required=False) is not None:
            print(f'Keeping existing native profile {entry["name"]}; identity and provider configuration are not reset.')
            continue
        print(f'Installing {entry["name"]} from {directory} through native confirmation (no overwrite requested).')
        try:
            # Hermes shares this terminal, so its preview and confirmation prompt reach the operator unchanged;
            # flush first so this helper's own lines stay in order when the output is saved to a file.
            sys.stdout.flush()
            returncode = process_factory([executable, 'profile', 'install', str(directory)],
                                         env=dict(os.environ, HERMES_HOME=str(root))).wait()
        except OSError as exc:
            print(f'Install failed for {entry["name"]}: {exc}', file=sys.stderr)
            _report_partial(installed)
            return 1
        # Hermes exits 0 when the operator declines, so the files it writes are the confirmation:
        # the profile's distribution.yaml naming it, beside its SOUL.md.
        try:
            confirmed = lab.registered_profile(root, entry['name'], required=False) is not None
        except (OSError, ValueError):
            confirmed = False
        if returncode != 0 or not confirmed:
            if returncode == 0:
                print(f'Hermes exited successfully but {entry["name"]} has no installed distribution.yaml and SOUL.md '
                      '(cancelled, or its files do not match); outcome is unconfirmed.', file=sys.stderr)
            else:
                print(f'Hermes refused or failed to install {entry["name"]} (exit status {returncode}).', file=sys.stderr)
            _report_partial(installed)
            return returncode if returncode > 0 else 1
        print()
        installed.append(entry['name'])
    print('Confirmed newly installed authored profiles: ' + (', '.join(installed) or 'none; existing profiles preserved'))
    return 0


def _report_lab(components):
    print('Built-in hunting lab and Desktop companion installed and enabled: ' + components['profile'])
    print('First explicit Start prepares public runtime assets automatically; no VM was started by setup.')
    print('Profile registration does not establish Desktop rendering or provider/model readiness.')


def install(selected=None, hermes_override=None, kit_root=HERE, process_factory=subprocess.Popen, home=None):
    catalog = load_catalog(kit_root)  # Validate all entries before any native command.
    requested = list(selected or ())
    known = {entry['name']: (entry, directory) for entry, directory in catalog}
    if len(requested) != len(set(requested)):
        raise SetupError('--profile names must not be repeated.')
    unknown = [name for name in requested if name not in known]
    if unknown:
        raise SetupError('Unknown --profile name(s): ' + ', '.join(unknown))
    chosen = [known[name] for name in requested] if requested else catalog
    import lab
    root = lab.resolve_home(home)
    # Refuse before `profile install` runs; lab.install checks again before it stages anything.
    lab.refuse_during_update(root)
    if not any(entry['name'] == lab.PROFILE for entry, _ in chosen):
        chosen.append(known[lab.PROFILE])
    executable = resolve_hermes(hermes_override)
    returncode = _install_profiles(chosen, executable, root, process_factory)
    if returncode:
        return returncode
    _report_lab(lab.install(root, executable, kit_root))
    return 0


def _report_partial(installed):
    if installed:
        print('Previously installed successfully (no rollback was attempted): ' + ', '.join(installed), file=sys.stderr)
    else:
        print('No installations were confirmed before this failure; the current native operation may have changed Hermes state.', file=sys.stderr)


DOCKER_URL = 'https://docs.docker.com/desktop/'
TEMPORAL_URL = 'https://docs.temporal.io/cli'


def _answers(runner, argv):
    """The first stdout line of a short version probe, or None when it fails or prints nothing."""
    try:
        result = runner(argv, stdin=subprocess.DEVNULL, capture_output=True, text=True, encoding='utf-8',
                        errors='replace', timeout=30, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None
    lines = (result.stdout or '').strip().splitlines()
    return lines[0].strip() if result.returncode == 0 and lines else None


def check_docker(runner=subprocess.run, which=shutil.which):
    docker = which('docker')
    if not docker:
        raise SetupError(f'Docker was not found on PATH. The practice lab runs as Docker containers: install Docker Desktop ({DOCKER_URL}), start it, then rerun setup.')
    version = _answers(runner, [docker, 'version', '--format', '{{.Server.Version}}'])
    if not version:
        raise SetupError(f'Docker is installed ({docker}) but its engine did not answer `docker version`. Start Docker Desktop, wait until it reports running, then rerun setup.')
    return f'Docker engine {version} ({docker})'


def check_temporal(runner=subprocess.run, which=shutil.which):
    temporal = which('temporal')
    if not temporal:
        raise SetupError(f'The Temporal CLI (`temporal`) was not found on PATH. Hunts run on its `temporal server start-dev`: install it ({TEMPORAL_URL}), then rerun setup.')
    version = _answers(runner, [temporal, '--version'])
    if not version:
        raise SetupError(f'The Temporal CLI at {temporal} did not answer `temporal --version`. Reinstall it ({TEMPORAL_URL}), then rerun setup.')
    return f'{version} ({temporal})'


def setup_all(hermes_override=None, home=None, kit_root=HERE, process_factory=subprocess.Popen,
              runner=subprocess.run, which=shutil.which):
    """Every setup step in order, stopping at the first failure: prerequisites, the six profiles, each new
    profile's reviewed policy file, the lab plugin and desktop pages, the remaining team policy, then check.

    A profile gets its policy file before plugins are enabled: enabling writes Hermes' default settings into
    a profile's config.yaml, which `apply` then keeps as custom conflicts."""
    import lab
    import native_team
    state = {}

    def prerequisites():
        catalog = load_catalog(kit_root)
        root = lab.resolve_home(home)
        lab.refuse_during_update(root)
        executable = resolve_hermes(hermes_override)
        state.update(catalog=catalog, root=root, executable=executable)
        print(f'Validated {len(catalog)} authored Hermes distributions.')
        print(f'Hermes executable: {executable}')
        print(f'Hermes home: {root}')
        print('Docker: ' + check_docker(runner, which))
        print('Temporal CLI: ' + check_temporal(runner, which))

    def profiles():
        if _install_profiles(state['catalog'], state['executable'], state['root'], process_factory):
            raise SetupError('A profile install did not complete; see the message above.')

    def policy_files():
        for profile in native_team.PROFILES:
            config = lab.registered_profile(state['root'], profile) / 'config.yaml'
            if config.exists() or config.is_symlink():
                print(f'Keeping the existing config.yaml of {profile}; apply fills in missing settings next and stops on any custom value.')
                continue
            native_team.initialize(profile, state['root'])
            print(f'Wrote the reviewed policy to {profile}/config.yaml.')

    def lab_components():
        _report_lab(lab.install(state['root'], state['executable'], kit_root))

    def team_policy():
        print(native_team.apply(state['executable'], state['root']))

    def policy_check():
        pending = native_team.not_ready(state['executable'], state['root'])
        if pending:
            raise SetupError('Native team policy is not ready: ' + '; '.join(pending))
        print(f'native_team check: every reviewed setting is ready in all {len(native_team.PROFILES)} profiles.')

    for name, step in (('prerequisites', prerequisites), ('profiles', profiles), ('policy files', policy_files),
                       ('lab plugin and desktop pages', lab_components), ('team policy', team_policy),
                       ('check', policy_check)):
        print(f'setup: {name}', flush=True)
        try:
            step()
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            print(f'setup: stopped at {name}: {exc}', file=sys.stderr)
            return 1
    print('setup: complete')
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(
        description='Check the authored Hermes kit, install native profiles plus the built-in lab and companion, or run every setup step (all). Existing exact authored profiles are preserved; new profiles use native confirmation. No provider sign-in or lab start.')
    parser.add_argument('--hermes', metavar='PATH', help='Hermes executable override (otherwise LAB_HERMES_EXE, '
                                                        'else hermes on PATH).')
    parser.add_argument('--home', metavar='PATH', help='General Hermes home (otherwise HERMES_HOME or the standard platform home).')
    subparsers = parser.add_subparsers(dest='command')
    subparsers.add_parser('check', help='validate all authored distributions and report Hermes CLI availability (default).')
    install_parser = subparsers.add_parser('install', help='explicitly install authored profiles through Hermes interactive confirmation.')
    install_parser.add_argument('--profile', action='append', metavar='NAME', help='select a profile; repeat to select multiple (default: all six).')
    subparsers.add_parser('all', help='check Hermes, Docker and the Temporal CLI, install the six profiles with their reviewed policy, '
                                      'the lab plugin and the desktop pages, apply the team policy and check it; stops at the first failure.')
    args = parser.parse_args(argv)
    command = args.command or 'check'
    try:
        if command == 'check':
            return check(args.hermes)
        if command == 'all':
            return setup_all(args.hermes, args.home)
        return install(args.profile, args.hermes, home=args.home)
    except (SetupError, OSError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())

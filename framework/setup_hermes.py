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
    # shutil.which checks both PATH lookup and executable suitability (including
    # Windows PATHEXT), unlike merely accepting an existing regular file.
    return shutil.which(str(Path(override).expanduser()) if override else 'hermes')


def missing_hermes_message():
    return ('Hermes CLI was not found. Install Hermes using the official guide: ' + INSTALL_URL +
            '\nCheck whether your operating system and architecture are supported: ' + PLATFORM_URL)


def check(hermes_override=None, kit_root=HERE):
    catalog = load_catalog(kit_root)
    executable = resolve_hermes(hermes_override)
    print(f'Validated {len(catalog)} authored Hermes distributions.')
    if executable:
        print(f'Hermes CLI available: {executable}')
        return 0
    print(missing_hermes_message())
    return 1


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
    if not any(entry['name'] == lab.PROFILE for entry, _ in chosen):
        chosen.append(known[lab.PROFILE])
    executable = resolve_hermes(hermes_override)
    if not executable:
        raise SetupError(missing_hermes_message())
    installed = []
    for entry, directory in chosen:
        if lab.registered_profile(root, entry['name'], required=False) is not None:
            print(f'Keeping existing native profile {entry["name"]}; identity and provider configuration are not reset.')
            continue
        print(f'Installing {entry["name"]} from {directory} through native confirmation (no overwrite requested).')
        try:
            process = process_factory(
                [executable, 'profile', 'install', str(directory)],
                stdout=subprocess.PIPE, text=True, encoding='utf-8', errors='replace',
                env=dict(os.environ, HERMES_HOME=str(root)))
            output = []
            # Relay every character immediately so a prompt without a newline is
            # visible while stdin remains connected to the operator's terminal.
            while True:
                character = process.stdout.read(1)
                if not character:
                    break
                output.append(character)
                try:
                    sys.stdout.write(character)
                    sys.stdout.flush()
                except UnicodeEncodeError:
                    encoding = getattr(sys.stdout, 'encoding', None) or 'utf-8'
                    sys.stdout.write(character.encode(encoding, errors='replace').decode(encoding))
                    sys.stdout.flush()
            returncode = process.wait()
        except OSError as exc:
            print(f'Install failed for {entry["name"]}: {exc}', file=sys.stderr)
            _report_partial(installed)
            return 1
        success_marker = re.search(
            r'✓\s+Installed\s+[\'"]' + re.escape(entry['name']) + r'[\'"]\s+v[^\s]+',
            ''.join(output))
        if returncode != 0 or not success_marker:
            if returncode == 0:
                print(f'Hermes exited successfully but did not confirm installation of {entry["name"]}; outcome is unconfirmed.', file=sys.stderr)
            else:
                print(f'Hermes refused or failed to install {entry["name"]} (exit status {returncode}).', file=sys.stderr)
            _report_partial(installed)
            return returncode if returncode > 0 else 1
        print()
        installed.append(entry['name'])
    components = lab.install(root, executable, kit_root)
    print('Confirmed newly installed authored profiles: ' + (', '.join(installed) or 'none; existing profiles preserved'))
    print('Built-in hunting lab and Desktop companion installed and enabled: ' + components['profile'])
    print('First explicit Start prepares public runtime assets automatically; no VM was started by setup.')
    print('Profile registration does not establish Desktop rendering or provider/model readiness.')
    return 0

def _report_partial(installed):
    if installed:
        print('Previously installed successfully (no rollback was attempted): ' + ', '.join(installed), file=sys.stderr)
    else:
        print('No installations were confirmed before this failure; the current native operation may have changed Hermes state.', file=sys.stderr)

def main(argv=None):
    parser = argparse.ArgumentParser(
        description='Check the authored Hermes kit or install native profiles plus the built-in lab and companion. Existing exact authored profiles are preserved; new profiles use native confirmation. No provider configuration or VM launch.')
    parser.add_argument('--hermes', metavar='PATH', help='Hermes executable override (otherwise resolve hermes from PATH).')
    parser.add_argument('--home', metavar='PATH', help='General Hermes home (otherwise HERMES_HOME or the standard platform home).')
    subparsers = parser.add_subparsers(dest='command')
    subparsers.add_parser('check', help='validate all authored distributions and report Hermes CLI availability (default).')
    install_parser = subparsers.add_parser('install', help='explicitly install authored profiles through Hermes interactive confirmation.')
    install_parser.add_argument('--profile', action='append', metavar='NAME', help='select a profile; repeat to select multiple (default: all six).')
    args = parser.parse_args(argv)
    command = args.command or 'check'
    try:
        if command == 'check':
            return check(args.hermes)
        return install(args.profile, args.hermes, home=args.home)
    except (SetupError, OSError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())

#!/usr/bin/env python3
"""Report where a Hermes home's installed hunt bots differ from this repository.

    python doctor.py --home <Hermes home> [--hermes <hermes executable>]

Compares each authored profile's installed SOUL.md, every plugin copy setup installs (the hunt-lab backend in each
profile, the Hunting Lab page and the workspace companion) and each profile's config.yaml model.default and
model.provider with the repo. Prints one line per drift, then `doctor: <n> drift`; exits 1 on any drift and 2 when
it cannot check. It reads files only and changes nothing. Hermes writes config.yaml as YAML, so the model settings
are read by the Python beside the Hermes executable (--hermes, else LAB_HERMES_EXE, else `hermes` on PATH), which
has PyYAML; it prints only those two settings, never the rest of the file.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys

import install_desktop
import lab
import native_team
import setup_hermes

HERE = Path(__file__).resolve().parent
# Runs in Hermes' own interpreter. Prints {path: {state, default, provider}}, the two model strings only.
MODEL_READER = '\n'.join((
    'import json, sys',
    'import yaml',
    'result = {}',
    'for path in sys.argv[1:]:',
    '    try:',
    "        with open(path, encoding='utf-8-sig') as handle:",
    '            data = yaml.safe_load(handle)',
    '    except FileNotFoundError:',
    "        result[path] = {'state': 'missing'}",
    '        continue',
    '    except (OSError, UnicodeDecodeError, yaml.YAMLError):',
    "        result[path] = {'state': 'unreadable'}",
    '        continue',
    "    model = data.get('model') if isinstance(data, dict) else None",
    '    if isinstance(model, dict):',
    "        result[path] = {'state': 'mapping', **{key: model[key] if isinstance(model.get(key), str) else None",
    "                                               for key in ('default', 'provider')}}",
    '    else:',
    "        result[path] = {'state': 'legacy' if isinstance(model, str) else 'unset'}",
    'print(json.dumps(result))',
))


class DoctorError(Exception):
    """The home or the repo could not be read, so drift is unknown."""


def hermes_model_reader(hermes=None, runner=subprocess.run):
    """read_models(paths) -> {path: {state, default, provider}}, run in the Hermes executable's own Python."""
    try:
        python = lab.hermes_python(lab.hermes_executable(hermes))
    except ValueError as exc:
        raise DoctorError(f'{exc}; config.yaml is read with the Python beside the Hermes executable') from None

    def read_models(paths):
        try:
            result = runner([str(python), '-I', '-c', MODEL_READER, *map(str, paths)], stdin=subprocess.DEVNULL,
                            capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=60,
                            check=False)
        except (OSError, subprocess.TimeoutExpired):
            result = None
        try:
            if result is None or result.returncode:
                raise ValueError
            return json.loads(result.stdout.strip().splitlines()[-1])
        except (IndexError, ValueError):
            raise DoctorError(f'{python} could not read the profiles\' config.yaml (it needs PyYAML, which Hermes installs)') from None
    return read_models


def _relative(root, path):
    return Path(path).relative_to(root).as_posix()


def _copy_drift(root, destination, files):
    name = _relative(root, destination)
    if not destination.is_dir():
        return [f'{name} is missing']
    drift = []
    for relative, data in sorted(files.items()):
        path = destination / relative
        if not path.is_file():
            drift.append(f'{name}/{relative} is missing')
        elif path.read_bytes() != data:
            drift.append(f'{name}/{relative} differs from the repo')
    for path in sorted(destination.rglob('*')):
        relative = path.relative_to(destination)
        if (path.is_file() and relative.as_posix() not in files and relative.name != install_desktop.MARKER
                and '__pycache__' not in relative.parts):
            drift.append(f'{name}/{relative.as_posix()} is not in the repo')
    return drift


def _model_drift(profile, observed):
    expected = {'default': native_team.PROFILES[profile]['model'], 'provider': native_team.PROVIDER}
    state = observed.get('state')
    if state == 'missing':
        return [f'profiles/{profile}/config.yaml is missing; expected model.default {expected["default"]}']
    if state == 'unreadable':
        return [f'profiles/{profile}/config.yaml is not readable YAML']
    if state != 'mapping':
        shape = 'a single string (legacy shape)' if state == 'legacy' else 'not set'
        return [f'{profile} model is {shape}; expected model.default {expected["default"]}']
    return [f'{profile} model.{key} is {observed.get(key)}, expected {value}'
            for key, value in expected.items() if observed.get(key) != value]


def diagnose(home, read_models, kit_root=HERE):
    """Every drift between the home and the repo, one line each; empty when they match."""
    try:
        root = lab.resolve_home(home)
    except (OSError, ValueError) as exc:
        raise DoctorError(f'The Hermes home cannot be read: {exc}') from None
    try:
        catalog = setup_hermes.load_catalog(kit_root)
    except (OSError, ValueError) as exc:
        raise DoctorError(f'The repo\'s bot distributions cannot be read: {exc}') from None
    drift, profiles = [], {}
    for entry, directory in catalog:
        name = entry['name']
        try:
            profile = lab.registered_profile(root, name, required=False)
        except (OSError, ValueError) as exc:
            drift.append(f'profiles/{name} is not this repo\'s {name}: {exc}')
            continue
        if profile is None:
            drift.append(f'profiles/{name} is not installed')
            continue
        profiles[name] = profile
        if (profile / 'SOUL.md').read_bytes() != (directory / 'SOUL.md').read_bytes():
            drift.append(f'profiles/{name}/SOUL.md differs from the repo\'s hermes-bots/{name}/SOUL.md')
    try:
        copies = lab.bundles(root, profiles, kit_root)
    except (OSError, ValueError) as exc:
        raise DoctorError(f'The repo\'s plugin sources cannot be read: {exc}') from None
    for destination, files in copies.items():
        drift.extend(_copy_drift(root, destination, files))
    if profiles:
        observed = read_models([profile / 'config.yaml' for profile in profiles.values()])
        for name, profile in profiles.items():
            drift.extend(_model_drift(name, observed.get(str(profile / 'config.yaml'), {})))
    return drift


def main(argv=None, read_models=None):
    parser = argparse.ArgumentParser(description='Report where a Hermes home\'s installed hunt bots differ from this repo.')
    parser.add_argument('--home', metavar='PATH', help='Hermes home to check (otherwise HERMES_HOME or the standard platform home).')
    parser.add_argument('--hermes', metavar='PATH', help='Hermes executable whose Python reads config.yaml '
                                                        '(otherwise LAB_HERMES_EXE, else hermes on PATH).')
    args = parser.parse_args(argv)
    try:
        drift = diagnose(args.home, read_models or hermes_model_reader(args.hermes))
    except (DoctorError, OSError) as exc:
        print(f'doctor: cannot check: {exc}', file=sys.stderr)
        return 2
    for line in drift:
        print('drift: ' + line)
    print(f'doctor: {len(drift)} drift')
    return 1 if drift else 0


if __name__ == '__main__':
    raise SystemExit(main())

"""Install the reviewed standalone Desktop UI into an explicit, existing home."""
import argparse
import hashlib
from pathlib import Path
import stat
import json
import os
import sys
import re

ROOT = Path(__file__).absolute().parent
PLUGIN = 'cybersecurity-workspace'


def no_alias(path):
    info = path.lstat()
    if (stat.S_ISLNK(info.st_mode) or
            getattr(info, 'st_file_attributes', 0) &
            getattr(stat, 'FILE_ATTRIBUTE_REPARSE_POINT', 0x400)):
        raise ValueError('Linked/reparse path refused')
    return info


def source():
    components = [ROOT, ROOT / 'desktop', ROOT / 'desktop' / PLUGIN]
    path = components[-1] / 'plugin.js'
    for part in components:
        if not stat.S_ISDIR(no_alias(part).st_mode):
            raise ValueError('Source directory required')
    if not stat.S_ISREG(no_alias(path).st_mode):
        raise ValueError('Regular plugin source required')
    return path.read_bytes()


MARKER = '.framework-managed.json'


def ordinary_directory(path, *, create=False):
    """Reject aliases before any operation, including aliases in ancestors."""
    path = Path(os.path.abspath(path))
    for component in (*reversed(path.parents), path):
        if create and not component.exists() and not component.is_symlink():
            component.mkdir()
        if not stat.S_ISDIR(no_alias(component).st_mode):
            raise ValueError('An ordinary directory without aliased ancestors is required')
    return path


def sync_bundle(parent, name, files):
    """Synchronize only a hash-owned bundle; never adopt unknown existing files."""
    if not files:
        raise ValueError('Empty bundle refused')
    if name not in {'hunt-lab', PLUGIN}:
        raise ValueError('Unknown framework bundle destination')
    parent = ordinary_directory(parent, create=True)
    destination = parent / name
    for relative, data in files.items():
        parts = Path(relative).parts
        if (not parts or Path(relative).is_absolute() or '\\' in relative
                or any(part in {'.', '..'} for part in parts)
                or relative == MARKER or not isinstance(data, bytes)):
            raise ValueError('Invalid authored bundle entry')
    hashes = {name: hashlib.sha256(data).hexdigest() for name, data in files.items()}
    old = {}
    if destination.exists() or destination.is_symlink():
        ordinary_directory(destination)
        marker = destination / MARKER
        if not stat.S_ISREG(no_alias(marker).st_mode):
            raise ValueError('Unowned existing bundle refused')
        metadata = json.loads(marker.read_text(encoding='utf-8'))
        if (not isinstance(metadata, dict) or set(metadata) != {'owner', 'bundle', 'files'}
                or metadata['owner'] != 'bot-framework' or metadata['bundle'] != name
                or not isinstance(metadata['files'], dict)):
            raise ValueError('Unowned existing bundle refused')
        old = metadata['files']
        for relative, digest in old.items():
            if (not isinstance(relative, str) or relative not in files
                    or not isinstance(digest, str) or len(digest) != 64
                    or any(character not in '0123456789abcdef' for character in digest)):
                raise ValueError('Invalid ownership marker')
        actual = set()
        for path in destination.rglob('*'):
            info = no_alias(path)
            if stat.S_ISREG(info.st_mode):
                relative = path.relative_to(destination)
                # Python's native loader creates bytecode beside installed
                # sources. Do not adopt, read, copy or delete those cache bytes.
                match = re.fullmatch(r'(.+)\.cpython-[0-9]+(?:\.opt-[012])?\.pyc', path.name)
                cached_source = relative.parent.parent / (match.group(1) + '.py') if match else None
                if (relative.parent.name == '__pycache__' and cached_source is not None
                        and cached_source.as_posix() in old):
                    continue
                actual.add(relative.as_posix())
            elif not stat.S_ISDIR(info.st_mode):
                raise ValueError('Non-regular bundle entry refused')
        if actual != set(old) | {MARKER}:
            raise ValueError('Unknown bundle files refused')
        for relative, digest in old.items():
            if (relative not in files or not isinstance(digest, str)
                    or hashlib.sha256((destination / relative).read_bytes()).hexdigest() != digest):
                raise ValueError('User-modified or obsolete bundle refused')
    else:
        destination.mkdir()
    # Validate the complete destination before replacing any managed bytes.
    for relative, data in files.items():
        path = destination / relative
        ordinary_directory(path.parent, create=True)
        if relative not in old and path.exists():
            raise ValueError('Unknown destination entry refused')
        temporary = path.with_name(path.name + '.framework-new')
        with temporary.open('xb') as out:
            out.write(data)
        os.replace(temporary, path)
    metadata = {'owner': 'bot-framework', 'bundle': name, 'files': hashes}
    temporary = destination / (MARKER + '.new')
    with temporary.open('x', encoding='utf-8') as out:
        json.dump(metadata, out, sort_keys=True)
        out.write('\n')
    os.replace(temporary, destination / MARKER)
    return destination


def install(home, data):
    home = ordinary_directory(home)
    return sync_bundle(home / 'desktop-plugins', PLUGIN, {'plugin.js': data}) / 'plugin.js'


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    commands.add_parser('check')
    install_parser = commands.add_parser('install')
    install_parser.add_argument('--home', required=True)
    args = parser.parse_args(argv)
    try:
        data = source()
        digest = hashlib.sha256(data).hexdigest()
        if args.command == 'install':
            print('Installed source:', install(args.home, data))
            print('Renderer mount is not verified by copying source.')
        else:
            print('Reviewed source is readable; host SDK and runtime not tested.')
        print('SHA256:', digest)
    except (OSError, ValueError):
        print('Desktop installation/check refused; inspect source and destination prerequisites. No overwrite attempted.', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())

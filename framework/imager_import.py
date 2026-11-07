#!/usr/bin/env python3
"""Import an imager JSON record into a ledger task; never acquires or approves.

The helper reads one record written by imager (`image` BASE.json, saved
`collect --json` output, or saved `verify --json` output), checks its
schema_version, re-hashes every referenced file with SHA-256, refuses on any
hash mismatch, and registers the files through `bot.py artifact`. When the task
is active it also records a factual `bot.py submit` note. A human must still
review and approve or reject the task with bot.py.
"""
import argparse
import hashlib
import json
from contextlib import closing
import sqlite3
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from bot import connect, nonempty, task  # noqa: E402

BOT = HERE / 'bot.py'
SUPPORTED_MAJOR = 1
CHUNK = 1 << 20


class Mismatch(Exception):
    """A referenced file or result does not match the record."""


def sha256_file(path, combined=None):
    """Return (sha256 hex, bytes); also feed `combined` when given."""
    digest = hashlib.sha256()
    size = 0
    with open(path, 'rb') as handle:
        for block in iter(lambda: handle.read(CHUNK), b''):
            digest.update(block)
            if combined is not None:
                combined.update(block)
            size += len(block)
    return digest.hexdigest(), size


def decode(raw):
    """Decode UTF-8 (with or without BOM) or UTF-16 with BOM.

    PowerShell 5 `>` redirection writes UTF-16LE, so saved `--json` output may
    arrive in either encoding.
    """
    if raw.startswith((b'\xff\xfe', b'\xfe\xff')):
        return raw.decode('utf-16')
    return raw.decode('utf-8-sig')


def schema_major(record):
    if not isinstance(record, dict):
        raise ValueError('imager record must be a JSON object')
    version = record.get('schema_version')
    if type(version) is int:
        major = version
    elif isinstance(version, str) and version.split('.', 1)[0].isdigit():
        major = int(version.split('.', 1)[0])
    else:
        raise ValueError('imager record has no valid schema_version; refusing')
    if major != SUPPORTED_MAJOR:
        raise ValueError(f'unsupported imager schema_version {version!r}; '
                         f'this helper understands major version {SUPPORTED_MAJOR}')
    return version


def detect_kind(record):
    if 'segments' in record and 'hashes' in record and 'format' in record:
        return 'image'
    if isinstance(record.get('result'), dict) and 'copy_log' in record['result']:
        return 'collect'
    if 'computed' in record and 'verified' in record:
        return 'verify'
    raise ValueError('cannot tell whether this is an image, collect or verify record; pass --kind')


def resolve(reference, base_dir):
    if not isinstance(reference, str) or not reference.strip():
        raise ValueError(f'record references an invalid path: {reference!r}')
    path = Path(reference).expanduser()
    if not path.is_absolute():
        path = base_dir / path
    path = path.resolve()
    if not path.is_file():
        raise ValueError(f'referenced file does not exist: {path}')
    return path


class Plan:
    """Files to register (in order) plus checks and facts for the note."""

    def __init__(self):
        self.files = []  # (path, label)
        self.facts = []
        self.mismatches = []
        self.raw_image = None  # (expected sha256, expected bytes) for raw images

    def add(self, path, label):
        if all(path != existing for existing, _ in self.files):
            self.files.append((path, label))


def lower(value):
    return value.lower() if isinstance(value, str) else ''


def plan_image(record, record_path, base_dir, plan, record_hash):
    # imager writes BASE.json and BASE.txt side by side.
    text = record_path.with_suffix('.txt')
    if record_path.suffix.lower() != '.json' or not text.is_file():
        raise ValueError(f'image record must be BASE.json with BASE.txt beside it; not found: {text}')
    plan.add(record_path, 'image record (BASE.json)')
    plan.add(text, 'image text log (BASE.txt)')
    segments = record.get('segments')
    if not isinstance(segments, list) or not segments:
        raise ValueError('image record lists no segments')
    for index, segment in enumerate(segments, 1):
        plan.add(resolve(segment, base_dir), f'image segment {index}/{len(segments)}')

    stored = record.get('hashes') or {}
    bad = record.get('bad_sectors') or []
    bad_sectors = sum(int(r.get('sector_count', 0)) for r in bad if isinstance(r, dict))
    plan.facts += [
        f"format={record.get('format')} bytes={record.get('bytes')} sectors={record.get('sectors')}",
        f"image md5={stored.get('md5')} sha1={stored.get('sha1')} sha256={stored.get('sha256')}",
        f'bad sector ranges={len(bad)} bad sectors={bad_sectors}',
    ]
    verification = record.get('verification')
    if isinstance(verification, dict):
        plan.facts.append(f"imager post-acquisition verification match={verification.get('match')}"
                          f" e01_stored_hash_match={verification.get('e01_stored_hash_match')}")
        if verification.get('match') is False or verification.get('e01_stored_hash_match') is False:
            plan.mismatches.append('imager post-acquisition verification reported a mismatch')
    else:
        plan.facts.append('imager post-acquisition verification: not run')
    if record.get('error'):
        plan.facts.append(f"imager error: {record['error']}")

    # BASE.txt carries the SHA-256 of BASE.json; a difference means either changed.
    # record_hash is the SHA-256 of the exact BASE.json bytes being imported.
    logged = [line.split(':', 1)[1].strip().lower()
              for line in decode(text.read_bytes()).splitlines() if line.startswith('Record SHA256:')]
    if not logged:
        plan.facts.append('BASE.txt has no Record SHA256 line; record hash not cross-checked')
    elif logged[-1] != record_hash:
        plan.mismatches.append(f'BASE.json SHA-256 {record_hash} differs from BASE.txt Record SHA256 {logged[-1]}')
    else:
        plan.facts.append('BASE.json SHA-256 matches the Record SHA256 in BASE.txt')

    if lower(record.get('format')) == 'raw':
        # Raw segments concatenate to the image; build_plan compares their hash.
        plan.raw_image = (lower(stored.get('sha256')), record.get('bytes'))
    else:
        plan.facts.append('E01 container hashes are checked by imager verify, not by this helper')


def plan_collect(record, record_path, base_dir, plan):
    result = record['result']
    plan.add(record_path, 'collect record (collect --json)')
    container = result.get('container')
    if container:
        path = resolve(container, base_dir)
        plan.add(path, 'collect container')
        plan.facts.append(f"logs inside container: {result.get('copy_log')}, {result.get('skip_log')}")
    else:
        for key, label in (('copy_log', 'CopyLog.csv'), ('skip_log', 'SkipLog.csv'), ('vss_log', 'VSS log')):
            if result.get(key):
                plan.add(resolve(result[key], base_dir), f'collect {label}')
        for shadow in result.get('vss') or []:
            for key, label in (('copy_log', 'CopyLog.csv'), ('skip_log', 'SkipLog.csv')):
                if isinstance(shadow, dict) and shadow.get(key):
                    plan.add(resolve(shadow[key], base_dir), f"collect shadow {shadow.get('number')} {label}")
    plan.facts.append(f"copied={result.get('copied')} skipped={result.get('skipped')} "
                      f"failed={result.get('failed')} bytes={result.get('bytes')}")
    return container and lower(result.get('container_sha256'))


def plan_verify(record, record_path, base_dir, plan):
    plan.add(record_path, 'verify record (verify --json)')
    image = resolve(record.get('image'), base_dir)
    plan.add(image, 'verified image')
    if record.get('sidecar'):
        plan.add(resolve(record['sidecar'], base_dir), 'image record used by verify')
    computed = record.get('computed') or {}
    plan.facts += [
        f"verify format={record.get('format')} bytes={record.get('bytes')}",
        f"computed md5={computed.get('md5')} sha1={computed.get('sha1')} sha256={computed.get('sha256')}",
        f"e01_stored_hash_match={record.get('e01_stored_hash_match')} verified={record.get('verified')}",
    ]
    for check in record.get('checks') or []:
        if isinstance(check, dict):
            plan.facts.append(f"{check.get('Name')} expected {check.get('Expected')} match={check.get('Match')}")
    if record.get('verified') is not True:
        plan.mismatches.append('imager verify did not report verified=true')
    if lower(record.get('format')) == 'raw':
        return image, lower(computed.get('sha256'))
    return None, None


def build_plan(record_path, kind, base_dir):
    raw = record_path.read_bytes()
    try:
        record = json.loads(decode(raw))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f'imager record is not valid JSON: {exc}') from exc
    version = schema_major(record)
    kind = kind or detect_kind(record)
    plan = Plan()
    record_hash = hashlib.sha256(raw).hexdigest()
    plan.facts.append(f'record {record_path} schema_version={version} sha256={record_hash} bytes={len(raw)}')
    expected = {}
    if kind == 'image':
        # Pre-hash the record bytes already read so BASE.txt can be compared.
        plan_image(record, record_path, base_dir, plan, record_hash)
    elif kind == 'collect':
        if not isinstance(record.get('result'), dict):
            raise ValueError('collect record has no result object')
        container_hash = plan_collect(record, record_path, base_dir, plan)
        if container_hash:
            expected[plan.files[1][0]] = container_hash
    else:
        path, digest = plan_verify(record, record_path, base_dir, plan)
        if path and digest:
            expected[path] = digest
    hashes = {}
    combined, total = hashlib.sha256(), 0
    for path, label in plan.files:
        segment = plan.raw_image is not None and label.startswith('image segment')
        hashes[path] = sha256_file(path, combined if segment else None)
        if segment:
            total += hashes[path][1]
        if path in expected and hashes[path][0] != expected[path]:
            plan.mismatches.append(f'{path} SHA-256 {hashes[path][0]} differs from the record {expected[path]}')
    if plan.raw_image is not None:
        want_sha, want_bytes = plan.raw_image
        if combined.hexdigest() != want_sha:
            plan.mismatches.append(f'raw image SHA-256 {combined.hexdigest()} differs from the record {want_sha or "(none)"}')
        elif type(want_bytes) is int and total != want_bytes:
            plan.mismatches.append(f'raw image is {total} bytes; the record says {want_bytes}')
        else:
            plan.facts.append(f'raw segments re-hashed: image SHA-256 {want_sha} matches the record')
    if hashes[record_path][0] != record_hash:
        plan.mismatches.append(f'{record_path} changed while it was being imported')
    return kind, plan, hashes


def bot(workspace, *args):
    result = subprocess.run([sys.executable, str(BOT), '-w', str(workspace), *map(str, args)],
                            capture_output=True, text=True, encoding='utf-8', errors='replace')
    if result.returncode:
        raise ValueError(f"bot.py {args[0]} failed: {result.stderr.strip() or result.stdout.strip()}")
    return result.stdout


def parser():
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument('-w', '--workspace', default='./bot-workspace', help='workspace directory (default: ./bot-workspace)')
    p.add_argument('id', type=int, help='ledger task that receives the artifacts')
    p.add_argument('record', help='imager BASE.json, or saved collect --json / verify --json output')
    p.add_argument('--kind', choices=('image', 'collect', 'verify'), help='record type (default: detect)')
    p.add_argument('--base-dir', help='directory for relative paths in the record (default: the record\'s directory)')
    p.add_argument('--by', default='operator', type=nonempty, help='person or role recording the import')
    p.add_argument('--no-submit', action='store_true', help='register artifacts only; never submit')
    return p


def main(argv=None):
    args = parser().parse_args(argv)
    record_path = Path(args.record).expanduser().resolve()
    if not record_path.is_file():
        raise ValueError(f'record does not exist: {record_path}')
    base_dir = Path(args.base_dir).expanduser().resolve() if args.base_dir else record_path.parent
    with closing(connect(args.workspace)) as db:
        status = task(db, args.id)['status']
    kind, plan, hashes = build_plan(record_path, args.kind, base_dir)
    if plan.mismatches:
        print('REFUSED: hash or verification mismatch; nothing was recorded.', file=sys.stderr)
        for line in plan.mismatches:
            print(f'  {line}', file=sys.stderr)
        return 3
    for path, label in plan.files:
        digest, size = hashes[path]
        bot(args.workspace, 'artifact', args.id, '--path', path,
            '--description', f'imager {label}: sha256={digest} bytes={size}')
        print(f'{digest}  {size:>12}  {path}')
    print(f'Registered {len(plan.files)} artifact(s) for task {args.id}')
    if args.no_submit:
        return 0
    if status != 'active':
        print(f'Task {args.id} is {status}, not active; no submit note recorded')
        return 0
    lines = [f'imager {kind} record imported by imager_import.py (factual; not an approval).']
    lines += plan.facts
    lines += [f'artifact {label}: {path} sha256={hashes[path][0]} bytes={hashes[path][1]}' for path, label in plan.files]
    lines.append('All referenced files re-hashed with SHA-256; no mismatch found. A human must review and approve or reject.')
    print(bot(args.workspace, 'submit', args.id, '--by', args.by, '--note', '\n'.join(lines)), end='')
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (ValueError, OSError, sqlite3.Error) as exc:
        print(f'Error: {exc}', file=sys.stderr)
        sys.exit(1)

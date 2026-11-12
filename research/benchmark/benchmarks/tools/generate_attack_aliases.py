"""Derive the pinned ATT&CK technique/alias map from an official STIX bundle.

Input is a locally downloaded `mitre-attack/attack-stix-data` Enterprise
bundle plus its `provenance.json` (written by the operator who downloaded it;
see benchmarks/README.md). The bundle is untrusted data: it is parsed as
strict JSON only, never executed, and must match the SHA-256 recorded in the
provenance file. Its LICENSE.txt must match the recorded digest too, because
the MITRE terms of use require copies to reproduce the copyright designation
and license; the output carries both.

Derivation, attack-pattern objects only:
- Every object must carry exactly one `mitre-attack` external ID of the form
  T#### or T####.###; an ID owned by two objects is refused.
- `techniques`: ID -> name for objects neither `revoked` nor
  `x_mitre_deprecated`.
- `aliases`: revoked object ID -> the ID named by its single in-force
  `revoked-by` relationship (the target may itself be revoked; consumers follow
  the chain). Deprecated objects with no `revoked-by` map to null and are also
  listed in `deprecated`.
- Anything ambiguous fails closed: a revoked object without exactly one
  replacement, a `revoked-by` source that is not revoked, a non-technique
  target, a revoked/deprecated relationship, a cycle, or a chain that ends
  neither at a current technique nor at a deprecated one.

Output is canonical JSON (sorted keys, compact UTF-8, no trailing newline), so
rerunning on the same bundle is byte-identical. After regenerating, update
`benchmark_attack.DATA_SHA256` to the printed digest.

Usage, from research/benchmark/:
  py -3 -B benchmarks/tools/generate_attack_aliases.py --provenance DIR/provenance.json
  py -3 -B benchmarks/tools/generate_attack_aliases.py --provenance FILE --output NEW_FILE
No network access.
"""
import argparse
import re
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
BENCHMARKS = TOOLS.parent
FRAMEWORK = BENCHMARKS.parent
if str(FRAMEWORK) not in sys.path:
    sys.path.insert(0, str(FRAMEWORK))

from benchmark_contracts import BenchmarkError, canonical_bytes, decode_json, digest_bytes  # noqa: E402

DEFAULT_OUTPUT = BENCHMARKS / 'attack-v20-techniques.json'
SCHEMA_VERSION = 1
TECHNIQUE = re.compile(r'T[0-9]{4}(?:\.[0-9]{3})?\Z')
COMMIT = re.compile(r'[0-9a-f]{40}\Z')
DIGEST = re.compile(r'[0-9a-f]{64}\Z')
VERSION = re.compile(r'([0-9]+)\.[0-9]+\Z')
PROVENANCE_KEYS = ('attack_version', 'release', 'repository', 'tag', 'commit', 'path', 'url', 'file', 'sha256')
LICENSE_KEYS = ('name', 'terms_url', 'license_file', 'license_file_sha256', 'copyright')
MAX_BUNDLE_BYTES = 256 * 1024 * 1024


def _fail(code, field):
    raise BenchmarkError(code, field)


def _text(value, field):
    if type(value) is not str or not value.strip():
        _fail('invalid_text', field)
    return value


def _provenance(value):
    if type(value) is not dict:
        _fail('invalid_object', 'provenance')
    for key in PROVENANCE_KEYS:
        _text(value.get(key), 'provenance.' + key)
    if not COMMIT.fullmatch(value['commit']):
        _fail('invalid_commit', 'provenance.commit')
    if not DIGEST.fullmatch(value['sha256']):
        _fail('invalid_digest', 'provenance.sha256')
    match = VERSION.fullmatch(value['attack_version'])
    if not match or value['release'] != 'v' + match.group(1):
        _fail('invalid_attack_release', 'provenance.release')
    if not value['url'].startswith('https://') or value['commit'] not in value['url']:
        _fail('invalid_url', 'provenance.url')
    license_info = value.get('license')
    if type(license_info) is not dict:
        _fail('invalid_object', 'provenance.license')
    for key in LICENSE_KEYS:
        _text(license_info.get(key), 'provenance.license.' + key)
    if not DIGEST.fullmatch(license_info['license_file_sha256']):
        _fail('invalid_digest', 'provenance.license.license_file_sha256')
    for key in ('file', 'license_file'):
        name = value['file'] if key == 'file' else license_info['license_file']
        if Path(name).name != name:
            _fail('path_escape', 'provenance.' + key)
    return value


def _attack_id(obj, field):
    ids = [ref.get('external_id') for ref in obj.get('external_references') or ()
           if type(ref) is dict and ref.get('source_name') == 'mitre-attack']
    if len(ids) != 1 or type(ids[0]) is not str or not TECHNIQUE.fullmatch(ids[0]):
        _fail('invalid_technique', field)
    return ids[0]


def build(bundle_bytes, provenance, license_bytes):
    """Return the alias document for verified bundle bytes; pure and deterministic."""
    _provenance(provenance)
    if digest_bytes(bundle_bytes) != provenance['sha256']:
        _fail('digest_mismatch', 'bundle')
    if digest_bytes(license_bytes) != provenance['license']['license_file_sha256']:
        _fail('digest_mismatch', 'license')
    bundle = decode_json(bundle_bytes)
    if type(bundle) is not dict or bundle.get('type') != 'bundle' or type(bundle.get('objects')) is not list:
        _fail('invalid_bundle', 'bundle')
    objects = bundle['objects']
    if not all(type(obj) is dict and type(obj.get('id')) is str and type(obj.get('type')) is str
               for obj in objects):
        _fail('invalid_bundle', 'bundle.objects')
    by_stix = {}
    for obj in objects:
        if obj['id'] in by_stix:
            _fail('duplicate_identifier', 'bundle.objects.id')
        by_stix[obj['id']] = obj

    versions = {obj.get('x_mitre_version') for obj in objects if obj['type'] == 'x-mitre-collection'}
    if versions != {provenance['attack_version']}:
        _fail('release_mismatch', 'bundle.x-mitre-collection')

    patterns = {}
    owner = {}
    for obj in objects:
        if obj['type'] != 'attack-pattern':
            continue
        technique = _attack_id(obj, 'bundle.attack-pattern.external_references')
        if technique in owner:
            _fail('duplicate_identifier', 'bundle.attack-pattern.external_id')
        for flag in ('revoked', 'x_mitre_deprecated'):
            if type(obj.get(flag, False)) is not bool:
                _fail('invalid_flag', 'bundle.attack-pattern.' + flag)
        owner[technique] = obj['id']
        patterns[obj['id']] = technique

    replacement = {}
    for obj in objects:
        if obj['type'] != 'relationship' or obj.get('relationship_type') != 'revoked-by':
            continue
        if obj.get('source_ref') not in patterns:
            continue
        if obj.get('revoked', False) is not False or obj.get('x_mitre_deprecated', False) is not False:
            _fail('ambiguous_revocation', 'bundle.relationship.revoked-by')
        source = by_stix[obj['source_ref']]
        if source.get('revoked') is not True:
            _fail('ambiguous_revocation', 'bundle.relationship.source_ref')
        if obj.get('target_ref') not in patterns:
            _fail('ambiguous_revocation', 'bundle.relationship.target_ref')
        old = patterns[obj['source_ref']]
        new = patterns[obj['target_ref']]
        if old in replacement and replacement[old] != new:
            _fail('ambiguous_revocation', 'bundle.relationship.revoked-by')
        replacement[old] = new

    techniques, aliases, deprecated = {}, {}, []
    for stix_id, technique in patterns.items():
        obj = by_stix[stix_id]
        if obj.get('revoked') is True:
            if technique not in replacement:
                _fail('ambiguous_revocation', 'bundle.attack-pattern.revoked')
            aliases[technique] = replacement[technique]
        elif obj.get('x_mitre_deprecated') is True:
            aliases[technique] = None
            deprecated.append(technique)
        else:
            techniques[technique] = _text(obj.get('name'), 'bundle.attack-pattern.name')

    for start in aliases:
        seen, current = {start}, start
        while current in aliases and aliases[current] is not None:
            current = aliases[current]
            if current in seen:
                _fail('alias_cycle', 'aliases')
            seen.add(current)
        if current not in techniques and current not in deprecated:
            _fail('alias_unresolved', 'aliases')

    license_info = provenance['license']
    try:
        license_text = license_bytes.decode('utf-8')
    except UnicodeError:
        _fail('invalid_text', 'license')
    return {
        'schema_version': SCHEMA_VERSION,
        'release': provenance['release'],
        'attack_version': provenance['attack_version'],
        'source': {'repository': provenance['repository'], 'tag': provenance['tag'],
                   'commit': provenance['commit'], 'path': provenance['path'], 'url': provenance['url'],
                   'sha256': provenance['sha256']},
        'license': {'name': license_info['name'], 'terms_url': license_info['terms_url'],
                    'copyright': license_info['copyright'],
                    'license_sha256': license_info['license_file_sha256'], 'license_text': license_text},
        'techniques': techniques,
        'aliases': aliases,
        'deprecated': sorted(deprecated),
    }


def render(document):
    return canonical_bytes(document)


def _read(path, field):
    try:
        if not path.is_file() or path.is_symlink() or path.stat().st_size > MAX_BUNDLE_BYTES:
            _fail('invalid_file', field)
        return path.read_bytes()
    except OSError:
        _fail('unreadable_file', field)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--provenance', required=True, help='provenance.json beside the downloaded bundle')
    parser.add_argument('--output', help='output file (default: the committed benchmarks map)')
    args = parser.parse_args(argv)
    try:
        provenance_path = Path(args.provenance).resolve()
        provenance = _provenance(decode_json(_read(provenance_path, 'provenance')))
        bundle = _read(provenance_path.parent / provenance['file'], 'bundle')
        license_bytes = _read(provenance_path.parent / provenance['license']['license_file'], 'license')
        content = render(build(bundle, provenance, license_bytes))
        output = Path(args.output) if args.output else DEFAULT_OUTPUT
        output.write_bytes(content)
    except BenchmarkError as exc:
        print('error: %s %s' % (exc.code, exc.field), file=sys.stderr)
        return 2
    except OSError:
        print('error: write_failed output', file=sys.stderr)
        return 2
    print('%s sha256=%s' % (output.name, digest_bytes(content)))
    return 0


if __name__ == '__main__':
    sys.exit(main())

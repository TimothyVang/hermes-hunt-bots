"""Pinned ATT&CK technique identity for scoring and truth validation.

ATT&CK revokes technique IDs and names replacements (v20: T1562.008 ->
T1685.002, T1070.001 -> T1685.005). Answer keys and models trained on older
releases mix old and new IDs, so comparisons use `canonical_technique`.

The map is `benchmarks/attack-v20-techniques.json`, derived from the official
Enterprise STIX bundle by `benchmarks/tools/generate_attack_aliases.py`. It is
loaded once and refused unless its bytes match `DATA_SHA256` and are canonical
JSON; regenerating it requires updating that constant. Nothing is guessed: an
ID absent from the map is `unknown` and is returned unchanged.
"""
import re
from functools import lru_cache
from pathlib import Path

from benchmark_contracts import BenchmarkError, canonical_bytes, decode_json, digest_bytes

ATTACK_RELEASE = 'v20'
DATA_PATH = Path(__file__).resolve().parent / 'benchmarks' / 'attack-v20-techniques.json'
DATA_SHA256 = 'e008300f8dbd098c88c6a706a4a601b9b8387aa7acaf1765e7102a354095e310'
STATUSES = ('current', 'revoked', 'deprecated', 'unknown')
_TECHNIQUE = re.compile(r'T[0-9]{4}(?:\.[0-9]{3})?\Z')
_KEYS = {'schema_version', 'release', 'attack_version', 'source', 'license', 'techniques', 'aliases', 'deprecated'}


def _fail(code, field):
    raise BenchmarkError(code, field)


def _check_id(value):
    if type(value) is not str or not _TECHNIQUE.fullmatch(value):
        _fail('invalid_technique', 'technique_id')


@lru_cache(maxsize=None)
def _load():
    try:
        content = DATA_PATH.read_bytes()
    except OSError:
        _fail('attack_data_unreadable', 'attack_data')
    if digest_bytes(content) != DATA_SHA256:
        _fail('attack_data_digest_mismatch', 'attack_data')
    data = decode_json(content)
    if type(data) is not dict or set(data) != _KEYS or canonical_bytes(data) != content:
        _fail('invalid_attack_data', 'attack_data')
    if data['schema_version'] != 1 or data['release'] != ATTACK_RELEASE:
        _fail('invalid_attack_data', 'attack_data.release')
    techniques, aliases, deprecated = data['techniques'], data['aliases'], data['deprecated']
    if type(techniques) is not dict or type(aliases) is not dict or type(deprecated) is not list:
        _fail('invalid_attack_data', 'attack_data')
    for key in list(techniques) + list(aliases):
        _check_id(key)
    if set(techniques) & set(aliases) or set(deprecated) - {k for k, v in aliases.items() if v is None}:
        _fail('invalid_attack_data', 'attack_data.aliases')
    resolved = {}
    for start in aliases:
        seen, current = {start}, start
        while aliases.get(current) is not None:
            current = aliases[current]
            if current in seen:
                _fail('invalid_attack_data', 'attack_data.aliases')
            seen.add(current)
        if current not in techniques and current not in deprecated:
            _fail('invalid_attack_data', 'attack_data.aliases')
        resolved[start] = current
    return frozenset(techniques), resolved, frozenset(deprecated)


def _release(release):
    if release != ATTACK_RELEASE:
        _fail('unsupported_attack_release', 'attack_release')


def canonical_technique(technique_id, release=ATTACK_RELEASE):
    """Current ID for `technique_id`, following revocation chains.

    Current, unknown and deprecated-without-replacement IDs come back unchanged;
    use `technique_status` to tell them apart.
    """
    _release(release)
    _check_id(technique_id)
    return _load()[1].get(technique_id, technique_id)


def canonical_parent(technique_id, release=ATTACK_RELEASE):
    """Canonical parent technique of the canonical ID (itself for a parent)."""
    return canonical_technique(canonical_technique(technique_id, release).split('.')[0], release)


def technique_status(technique_id, release=ATTACK_RELEASE):
    """`current`, `revoked`, `deprecated` or `unknown` in the pinned release."""
    _release(release)
    _check_id(technique_id)
    current, resolved, deprecated = _load()
    if technique_id in current:
        return 'current'
    if technique_id in deprecated:
        return 'deprecated'
    if technique_id in resolved:
        return 'revoked'
    return 'unknown'

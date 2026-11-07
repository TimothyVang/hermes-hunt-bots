"""Deterministic sanitizer for benchmark content fields (command lines, script text, payloads).

Content fields are hunting evidence, so they reach the hunter instead of being dropped. Before publication each
value passes `sanitize_text`, in this order:

1. Normalise to `str` (bytes are decoded as strict UTF-8). NUL is refused; newlines are kept.
2. Secrets become `[REDACTED:<kind>]`: password-style arguments and literals, NTLM/LM hashes, Kerberos tickets and
   keys, private-key PEM blocks, AWS access keys and secret keys, JWTs, `Authorization:`/`Cookie:` header values,
   URL and connection-string passwords. A PowerShell `-EncodedCommand` payload (any unambiguous prefix such as
   `-e`/`-enc`) is decoded to scan for secrets; a payload whose decoded text holds one becomes
   `[REDACTED:encoded_secret]`. Otherwise, with `encoded_payloads='preview'` (default), a UTF-16LE payload becomes
   `[ENCODED_COMMAND utf16le_chars=N sha256=<16 hex of the decoded bytes>] decoded_preview="<first 512 decoded
   characters, sanitized like any content, control characters escaped>"` plus ` …[preview of 512 chars]` when
   shorter than the whole: complete known stagers in an output file get it quarantined by antivirus.
   `encoded_payloads='full'` keeps the base64 payload.
3. Identities become pseudonyms through the caller's own `pseudonymize(kind, original)`, so content correlates
   with the structured fields: SIDs, `DOMAIN\\user`, `user@domain`, UNC `\\\\host\\`, `\\Users\\<name>\\` and
   `/home/<name>/` profile segments, IPv4/IPv6 literals (loopback/unspecified kept), plus every identity the
   caller has already seen (`identities`, matched whole-token and case-insensitively).
4. ATT&CK leakage is masked: `T####` replaces technique IDs and Atomic Red Team folder names.
5. The result is bounded: over `max_bytes` UTF-8 bytes it is cut and an explicit ` …[truncated N bytes]` marker is
   appended; truncation is never silent.

Python 3.9 standard library only. Nothing in the value is executed, followed or fetched.
"""

import base64
import binascii
import hashlib
import ipaddress
import re

from benchmark_contracts import BenchmarkError

MAX_CONTENT_BYTES = 16384
MIN_IDENTITY_CHARS = 4
MAX_ENCODED_DEPTH = 3
ATTACK_MASK = 'T####'
ENCODED_SECRET = '[REDACTED:encoded_secret]'
# 'preview': antivirus engines quarantine files that hold whole known stagers (raw or decoded), so by default a
# UTF-16LE -EncodedCommand payload is published as length + digest + a sanitized decoded preview.
ENCODED_PAYLOAD_MODES = ('preview', 'full')
ENCODED_PREVIEW_CHARS = 512
_CONTROL_ESCAPES = {'\r': '\\r', '\n': '\\n', '\t': '\\t'}

# Kinds the built-in identity detectors pass to pseudonymize(kind, original).
IDENTITY_KINDS = ('sid', 'domain', 'user', 'dns', 'host', 'ip')

_QUOTED = r"'[^'\r\n]*'|\"[^\"\r\n]*\""

# ------------------------------------------------------------------ secrets
# (kind, pattern, group). The group's text is replaced; every other group is kept.

_PS_ENCODED = re.compile(
    r'(?i)(?<![\w-])([-/]e(?:c|n(?:c(?:o(?:d(?:e(?:d(?:c(?:o(?:m(?:m(?:a(?:n(?:d)?)?)?)?)?)?)?)?)?)?)?)?)?\s+)'
    r'([A-Za-z0-9+/]{16,}={0,2})(?![A-Za-z0-9+/=])')
_TOOLS_DASH_P = (r'sshpass|runas|psexec(?:64)?|paexec|net1?|plink|pscp|smbclient|winexe|crackmapexec|cme|'
                 r'wmiexec|smbexec|atexec|dcomexec|mysql|mysqldump')
_SECRET_RULES = (
    ('private_key', re.compile(r'-----BEGIN ([A-Z0-9 ]*)PRIVATE KEY-----.*?(?:-----END \1PRIVATE KEY-----|\Z)',
                               re.S), 0),
    ('jwt', re.compile(r'(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*'), 0),
    ('authorization', re.compile(r'(?i)(?<![\w$.-])((?:proxy-)?authorization["\']?\s*[:=]\s*["\']?)([^"\'\r\n]+)'),
     2),
    ('cookie', re.compile(r'(?i)(?<![\w$.-])((?:set-)?cookie["\']?\s*[:=]\s*["\']?)([^"\'\r\n]+)'), 2),
    ('kerberos', re.compile(r'\$krb5(?:tgs|asrep|pa|tgt)\$[^\s"\']+'), 0),
    ('kerberos', re.compile(r'(?i)(?<![\w-])(/aes(?:128|256)\s*[:=]\s*)([0-9a-f]{64}|[0-9a-f]{32})(?![0-9a-f])'), 2),
    ('kerberos', re.compile(r'(?i)(?<![\w-])(/(?:ticket|tgt|tgs)\s*[:=]\s*)([A-Za-z0-9+/]{64,}={0,2})'), 2),
    ('kerberos', re.compile(r'(?<![A-Za-z0-9+/])doI[A-Za-z0-9+/]{60,}={0,2}'), 0),
    ('ntlm_hash', re.compile(r'(?i)(?<![0-9a-f])[0-9a-f]{32}:[0-9a-f]{32}(?![0-9a-f])'), 0),
    ('ntlm_hash', re.compile(r'(?i)(?<![\w])([-/]{0,2}(?:ntlm|nthash|lmhash|ntlmhash|nt_hash|lm_hash|rc4|hash|hashes)'
                             r'\s*[:=]?\s*["\']?|[-/]{0,2}(?:nt|lm)\s*[:=]\s*["\']?)([0-9a-f]{32})(?![0-9a-f])'), 2),
    ('ntlm_hash', re.compile(r'(?i)(?<=:)[0-9a-f]{32}(?=:|\s|$|["\'])'), 0),
    ('aws_access_key', re.compile(r'(?<![A-Z0-9])(?:AKIA|ASIA)[0-9A-Z]{16}(?![A-Z0-9])'), 0),
    ('aws_secret_key', re.compile(r'(?i)((?:aws_?secret_?access_?key|secret_?access_?key|aws_?secret_?key|secretkey|'
                                  r'secret-access-key)["\']?\s*[:=\s]\s*["\']?)([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])'),
     2),
    ('password', re.compile(r'(?i)\b([a-z][a-z0-9+.-]*://[^/\s:@\'"]+:)([^@\s/\'"]+)(?=@)'), 2),
    ('password', re.compile(r'(?i)(ConvertTo-SecureString(?:\s+-(?:AsPlainText|Force))*\s+(?:-String\s+)?)(' +
                            _QUOTED + ')'), 2),
    ('password', re.compile(r'(' + _QUOTED + r')(?=\s*\|\s*ConvertTo-SecureString\b)', re.I), 1),
    ('password', re.compile(r'(?i)(?<![\w-])(-(?:password|passwd|pass|pw)(?:\s*:\s*|\s+))(' + _QUOTED +
                            r'|(?![$(@])[^\s"\'|;)]+)'), 2),
    ('password', re.compile(r'(?i)(?<![\w/\\.:-])(/(?:p|pass|password|pwd|passwd)\s*:)(' + _QUOTED +
                            r'|[^\s"\']+)'), 2),
    ('password', re.compile(r'(?i)(?<![\w.-])((?:' + _TOOLS_DASH_P + r')(?:\.exe|\.py)?\b[^\r\n|;&]*?\s-p\s*)(' +
                            _QUOTED + r'|[^\s"\']+)'), 2),
    ('password', re.compile(r'(?i)(?<![\w.-])(net1?(?:\.exe)?\s+user\s+(?:"[^"\r\n]*"|[^\s"/;&|]+)\s+)(?![/*])(' +
                            r'"[^"\r\n]*"|[^\s"/;&|]+)'), 2),
    ('password', re.compile(r'(?i)(?<![\w.-])(net1?(?:\.exe)?\s+use\s+(?:[a-z*]:\s+)?\\\\[^\s";&|]+\s+)(?![/*])(' +
                            r'"[^"\r\n]*"|[^\s"/;&|]+)'), 2),
)
# password=/pwd=: connection strings, URLs, arguments. A PowerShell `$password = ...` assignment is redacted only
# when it assigns a string literal.
_ASSIGNED_PASSWORD = re.compile(r'(?i)(?<![\w])(\$?)((?:password|passwd|pwd)\s*=(?!=)\s*)(' + _QUOTED +
                                r'|[^;\s"\'&]+)')
_CONNECTION_CONTEXT = re.compile(r'(?i)(?:server|data source|uid|user id|initial catalog|provider|database)\s*=')

# --------------------------------------------------------------- identities

_SID = re.compile(r'(?i)(?<![\w-])S-1-(?:5-21(?:-[0-9]+){3}(?:-[0-9]+)?|12-1(?:-[0-9]+){4})(?![\w-])')
_UNC = re.compile(r'(?<![\\\w:/.$%-])(\\\\(?:\\\\)?)([A-Za-z0-9][A-Za-z0-9_.-]{0,254})(?=\\|/|\s|$|["\'])')
_PROFILE = re.compile(r'(?i)(?<![\w])((?:Users|home)(?:\\\\|\\|/))([^\\/:*?"<>|\r\n\t]+?)(?=\\|/|"|\'|\s|$)')
_ACCOUNT = re.compile(r'(?<![\w.\\/$%@-])([A-Za-z0-9][A-Za-z0-9-]{0,14})\\([A-Za-z0-9][A-Za-z0-9._-]{0,63}\$?)'
                      r'(?![\w\\/.$-])')
_EMAIL = re.compile(r'(?<![\w.%+@-])([A-Za-z0-9][A-Za-z0-9._%+-]{0,63})@([A-Za-z0-9][A-Za-z0-9-]{0,62}'
                    r'(?:\.[A-Za-z0-9-]{1,63})+)(?![\w-])')
_IPV6 = re.compile(r'(?<![\w:.])[0-9A-Fa-f:]{2,39}(?![\w:.])')
_IPV4 = re.compile(r'(?<![\w.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![\w]|\.[0-9])')
_PRODUCT_TOKEN = re.compile(r'(?:^|[\s(;,])[A-Za-z][A-Za-z0-9_.-]*/\Z')
_GUID = re.compile(r'(?<![0-9A-Fa-f-])[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}'
                   r'(?![0-9A-Fa-f-])')
# Already-produced pseudonym tokens and redaction markers are never rewritten again.
_PROTECTED = r'(?P<protected>(?<![A-Za-z0-9])[a-z][a-z0-9]*-[0-9a-f]{16}(?![A-Za-z0-9])|\[REDACTED:[a-z_]+\])'
_PROFILE_KEEP = frozenset({'public', 'default', 'default user', 'all users', 'defaultapppool'})
_ACCOUNT_DOMAIN_KEEP = frozenset({'hklm', 'hkcu', 'hkcr', 'hku', 'hkcc', 'builtin', 'authority', 'service',
                                  'apppool', 'hkey_local_machine', 'hkey_current_user', 'hkey_users',
                                  'hkey_classes_root', 'hkey_current_config'})
_FILE_LIKE = re.compile(r'\.[A-Za-z][A-Za-z0-9]{0,4}\Z')

# ----------------------------------------------------------------- ATT&CK

_ATTACK = re.compile(r'(?<![A-Za-z0-9])T[0-9]{4}(?:\.[0-9]{3})?(?![0-9])|'
                     r'(?i:atomic[-_ ]?red[-_ ]?team|invoke-atomic(?:test|redteam)?|(?<![A-Za-z0-9])atomics'
                     r'(?![A-Za-z0-9]))')


def _fail(code, field):
    raise BenchmarkError(code, field)


def empty_report(original_bytes=0):
    return {'redactions': {}, 'pseudonymized': 0, 'attack_masked': 0, 'encoded_previewed': 0, 'truncated': False,
            'original_bytes': original_bytes}


def new_totals():
    """Accumulator for merge_reports: per-field sanitizer totals for an import report."""
    return {'values': 0, 'redactions': {}, 'pseudonymized': 0, 'attack_masked': 0, 'encoded_previewed': 0,
            'truncated': 0, 'original_bytes': 0}


def merge_reports(totals, report):
    totals['values'] += 1
    for kind, count in report['redactions'].items():
        totals['redactions'][kind] = totals['redactions'].get(kind, 0) + count
    totals['pseudonymized'] += report['pseudonymized']
    totals['attack_masked'] += report['attack_masked']
    totals['encoded_previewed'] += report['encoded_previewed']
    totals['truncated'] += 1 if report['truncated'] else 0
    totals['original_bytes'] += report['original_bytes']
    return totals


class KnownIdentities:
    """Identities the caller has already seen, `{kind: iterable of originals}`, compiled once.

    A match (whole token at alphanumeric boundaries, case-insensitive, originals of at least four characters)
    calls `pseudonymize(kind, matched_text)` with the caller's kind string verbatim. The longest original wins.
    Names are compiled into one prefix-trie pattern and GUID-shaped originals are looked up by GUID shape, so
    thousands of identities stay cheap.
    """

    def __init__(self, mapping=None):
        self._kinds, self._guids = {}, {}
        for kind in sorted(mapping or {}):
            if type(kind) is not str:
                _fail('invalid_text', 'identities')
            for original in sorted(mapping[kind]):
                if type(original) is not str:
                    _fail('invalid_text', 'identities')
                folded = original.casefold().strip()
                if len(folded) < MIN_IDENTITY_CHARS or '\x00' in folded:
                    continue
                target = self._guids if _GUID.fullmatch(folded) else self._kinds
                target.setdefault(folded, kind)
        trie = _trie_pattern(self._kinds)
        pattern = _PROTECTED
        if trie:
            pattern += r'|(?P<known>(?<![A-Za-z0-9])' + trie + r'(?![A-Za-z0-9]))'
        self._pattern = re.compile(pattern, re.I)

    def sub(self, text, replace):
        def known(match):
            if match.group('protected') is not None:
                return match.group(0)
            return replace(self._kinds[match.group(0).casefold()], match.group(0))

        def guid(match):
            kind = self._guids.get(match.group(0).casefold())
            return match.group(0) if kind is None else replace(kind, match.group(0))

        if self._kinds:
            text = self._pattern.sub(known, text)
        if self._guids:
            text = _GUID.sub(guid, text)
        return text


def _trie_pattern(words):
    """Regex matching exactly `words`, factored by common prefix; greedy optional tails prefer longer words."""
    root = {}
    for word in words:
        node = root
        for char in word:
            node = node.setdefault(char, {})
        node[''] = {}

    def build(node):
        branches = [re.escape(char) + build(child) for char, child in sorted(node.items()) if char]
        if not branches:
            return ''
        body = branches[0] if len(branches) == 1 else '(?:' + '|'.join(branches) + ')'
        return '(?:' + body + ')?' if '' in node else body

    return build(root)


# ------------------------------------------------------------------ helpers

def _normalise(value, field):
    if type(value) is bytes:
        try:
            value = value.decode('utf-8')
        except UnicodeDecodeError:
            _fail('invalid_text', field)
    elif type(value) in (int, float):
        value = str(value)
    elif type(value) is not str:
        _fail('invalid_text', field)
    if '\x00' in value:
        _fail('invalid_text', field)
    return value


def _decode_payload(payload):
    """(decoded text, raw bytes, encoding) of a plausible -EncodedCommand payload, else None."""
    if len(payload) % 4:
        return None
    try:
        raw = base64.b64decode(payload, validate=True)
    except (binascii.Error, ValueError):
        return None
    for encoding in ('utf-16-le', 'utf-8'):
        try:
            text = raw.decode(encoding)
        except UnicodeDecodeError:
            continue
        # PowerShell source is overwhelmingly ASCII; arbitrary even-length bytes decode as printable UTF-16 (CJK).
        plausible = sum(1 for c in text if c in '\r\n\t' or (c.isprintable() and (ord(c) < 128 or encoding == 'utf-8')))
        if text and '\x00' not in text and plausible >= 0.9 * len(text):
            return text, raw, encoding
    return None


def _segments(text):
    """[(payload or False, chunk)]: decodable -EncodedCommand payloads separated from ordinary text."""
    parts, last = [], 0
    for match in _PS_ENCODED.finditer(text):
        payload = _decode_payload(match.group(2))
        if payload is None:
            continue
        start, end = match.span(2)
        parts.append((False, text[last:start]))
        parts.append((payload, text[start:end]))
        last = end
    parts.append((False, text[last:]))
    return parts


def _escape_controls(text):
    return ''.join(_CONTROL_ESCAPES.get(c) or ('\\x%02x' % ord(c) if ord(c) < 32 or ord(c) == 127 else c)
                   for c in text)


def _redact(text, counts):
    def rule_sub(kind, pattern, group):
        def repl(match):
            counts[kind] = counts.get(kind, 0) + 1
            if group == 0:
                return '[REDACTED:%s]' % kind
            start, end = match.span(group)
            base = match.start()
            whole = match.group(0)
            return whole[:start - base] + '[REDACTED:%s]' % kind + whole[end - base:]
        return pattern.sub(repl, text)

    for kind, pattern, group in _SECRET_RULES:
        text = rule_sub(kind, pattern, group)

    connection = bool(_CONNECTION_CONTEXT.search(text))

    def assigned(match):
        sigil, head, value = match.groups()
        if sigil and value[:1] not in ('"', "'"):
            return match.group(0)
        if value.startswith('[REDACTED:'):
            return match.group(0)
        kind = 'connection_string' if connection and not sigil else 'password'
        counts[kind] = counts.get(kind, 0) + 1
        return sigil + head + '[REDACTED:%s]' % kind

    return _ASSIGNED_PASSWORD.sub(assigned, text)


def _has_secret(text, depth):
    counts = {}
    for payload, chunk in _segments(text):
        if payload is not False:
            if depth < MAX_ENCODED_DEPTH and _has_secret(payload[0], depth + 1):
                return True
            continue
        _redact(chunk, counts)
        if counts:
            return True
    return False


def _ip_kept(address):
    return address.is_loopback or address.is_unspecified or address.is_multicast or \
        (address.version == 4 and str(address).startswith('255.'))


def _pseudonymize_chunk(text, replace, identities):
    text = _SID.sub(lambda m: replace('sid', m.group(0)), text)

    def unc(match):
        prefix, host = match.groups()
        if host.casefold() in ('localhost', '?', '.'):
            return match.group(0)
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            return prefix + replace('dns' if '.' in host.strip('.') else 'host', host)
        return match.group(0) if _ip_kept(address) else prefix + replace('ip', host)
    text = _UNC.sub(unc, text)

    def profile(match):
        head, name = match.groups()
        if name.casefold() in _PROFILE_KEEP or any(c in name for c in '%$*<>{}'):
            return match.group(0)
        return head + replace('user', name)
    text = _PROFILE.sub(profile, text)

    def account(match):
        domain, user = match.groups()
        folded = domain.casefold()
        if not domain.isupper() or folded in _ACCOUNT_DOMAIN_KEEP or len(domain) == 1 or _FILE_LIKE.search(user):
            return match.group(0)
        return replace('domain', domain) + '\\' + replace('user', user)
    text = _ACCOUNT.sub(account, text)

    def email(match):
        user, domain = match.groups()
        if not re.search(r'[A-Za-z]', domain.rsplit('.', 1)[-1]):
            return match.group(0)
        return replace('user', user) + '@' + replace('dns', domain)
    text = _EMAIL.sub(email, text)

    def ipv6(match):
        candidate = match.group(0)
        if candidate.count(':') < 2:
            return candidate
        try:
            address = ipaddress.IPv6Address(candidate)
        except ValueError:
            return candidate
        return candidate if _ip_kept(address) else replace('ip', candidate)
    text = _IPV6.sub(ipv6, text)

    def ipv4(match):
        candidate = match.group(0)
        before = text[max(0, match.start() - 64):match.start()]
        # Version numbers, not addresses: `Version=4.0.0.0`, product tokens such as `Chrome/103.0.0.0`.
        if 'version' in before[-16:].casefold() or _PRODUCT_TOKEN.search(before):
            return candidate
        try:
            address = ipaddress.IPv4Address(candidate)
        except ValueError:
            return candidate
        return candidate if _ip_kept(address) else replace('ip', candidate)
    text = _IPV4.sub(ipv4, text)

    if identities is not None:
        text = identities.sub(text, replace)
    return text


# --------------------------------------------------------------------- API

def sanitize_text(value, pseudonymize, *, max_bytes=MAX_CONTENT_BYTES, identities=None, field='content',
                  encoded_payloads='preview'):
    """Return (sanitized text, report) for one content value; see the module docstring for the steps.

    `pseudonymize(kind, original) -> str` is the caller's consistent HMAC pseudonymizer. Built-in detectors pass
    the kinds in IDENTITY_KINDS; `identities` (a KnownIdentities or a `{kind: originals}` dict) passes the caller's
    own kinds. Returning the original keeps it. None is returned unchanged with an empty report.
    `encoded_payloads`: 'preview' (default) replaces each UTF-16LE -EncodedCommand payload by its length, digest
    and a sanitized decoded preview; 'full' keeps the base64 payload.
    """
    if encoded_payloads not in ENCODED_PAYLOAD_MODES:
        _fail('invalid_choice', 'encoded_payloads')
    if value is None:
        return None, empty_report()
    if type(max_bytes) is not int or max_bytes < 1:
        _fail('invalid_number', 'max_bytes')
    text = _normalise(value, field)
    report = empty_report(len(text.encode('utf-8')))
    if identities is not None and not isinstance(identities, KnownIdentities):
        identities = KnownIdentities(identities)

    def replace(kind, original):
        token = pseudonymize(kind, original)
        if token is None:
            return original
        if type(token) is not str or '\x00' in token:
            _fail('invalid_text', field)
        if token != original:
            report['pseudonymized'] += 1
        return token

    counts = report['redactions']

    def process(chunk_text, depth):
        parts = []
        for payload, chunk in _segments(chunk_text):
            if payload is False:
                parts.append(_pseudonymize_chunk(_redact(chunk, counts), replace, identities))
                continue
            decoded, raw, encoding = payload
            if _has_secret(decoded, 1):
                counts['encoded_secret'] = counts.get('encoded_secret', 0) + 1
                parts.append(ENCODED_SECRET)
            elif encoded_payloads == 'preview' and encoding == 'utf-16-le':
                report['encoded_previewed'] += 1
                head = decoded[:ENCODED_PREVIEW_CHARS]
                preview = process(head, depth + 1) if depth < MAX_ENCODED_DEPTH else \
                    _pseudonymize_chunk(_redact(head, counts), replace, identities)
                marker = '[ENCODED_COMMAND utf16le_chars=%d sha256=%s] decoded_preview="%s"' % (
                    len(raw) // 2, hashlib.sha256(raw).hexdigest()[:16], _escape_controls(preview))
                if len(head) < len(decoded):
                    marker += ' \u2026[preview of %d chars]' % len(head)
                parts.append(marker)
            else:
                parts.append(chunk)
        return ''.join(parts)

    text = process(text, 1)

    def mask(match):
        report['attack_masked'] += 1
        return ATTACK_MASK
    text = _ATTACK.sub(mask, text)

    encoded = text.encode('utf-8')
    if len(encoded) > max_bytes:
        kept = encoded[:max_bytes].decode('utf-8', 'ignore')
        text = kept + ' \u2026[truncated %d bytes]' % (len(encoded) - len(kept.encode('utf-8')))
        report['truncated'] = True
    report['redactions'] = dict(sorted(counts.items()))
    return text, report


def scan_leaks(text, originals, *, min_length=MIN_IDENTITY_CHARS):
    """Sorted originals still present in text (case-insensitive, alphanumeric boundaries, at least min_length)."""
    folded = text.casefold()
    found = set()
    for original in originals:
        needle = original.casefold()
        if len(needle) >= min_length and needle in folded and \
                re.search(r'(?<![a-z0-9])' + re.escape(needle) + r'(?![a-z0-9])', folded):
            found.add(original)
    return sorted(found)

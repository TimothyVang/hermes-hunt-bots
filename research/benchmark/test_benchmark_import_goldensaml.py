"""Synthetic unit tests for `benchmark_import_goldensaml.py`."""
import json
from pathlib import Path
import tempfile
import unittest
import zipfile

from benchmark_contracts import load_json, validate_coverage, validate_public_bundle, validate_scenario, validate_truth
from benchmark_import_goldensaml import DEFAULT_COVERAGE, import_goldensaml_case


def _write_zip(path, member_name, rows):
    with zipfile.ZipFile(path, 'w', compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(member_name, '\n'.join(json.dumps(r) for r in rows) + '\n')


class GoldenSamlImporterTests(unittest.TestCase):

    def _build_fixture(self, root):
        ds = root / 'GoldenSAMLADFSMailAccess'
        ds.mkdir(parents=True)
        _write_zip(ds / 'WindowsEvents.Zip', 'WindowsEvents.json', [
            {
                'TimeGenerated': '2021-08-02T13:09:20.040Z',
                'Computer': 'ADFS01.simulandlabs.com',
                'EventID': 412,
                'Channel': 'Security',
                'EventSourceName': 'AD FS Auditing',
                'Activity': 'Token validation',
            },
            {
                'TimeGenerated': '2021-08-02T13:11:39.770Z',
                'Computer': 'DC01.simulandlabs.com',
                'EventID': 4662,
                'Channel': 'Security',
                'EventSourceName': 'Microsoft-Windows-Security-Auditing',
                'Account': 'SIMULANDLABS\\adfsadmin',
                'Activity': 'Object operation',
            },
        ])
        _write_zip(ds / 'Microsoft365DefenderEvents.Zip', 'Microsoft365DefenderEvents.json', [
            {
                'Timestamp': '2021-08-02T13:11:39.772Z',
                'DeviceName': 'adfs01.simulandlabs.com',
                'ActionType': 'LdapSearch',
                'InitiatingProcessFileName': 'powershell.exe',
                'InitiatingProcessCommandLine': 'powershell.exe -NoP',
                'AdditionalFields_dynamic': {
                    'AttributeList': ['thumbnailphoto'],
                    'DistinguishedName': 'CN=596f0e13-7a4b-49a1-a106-0cbcba66b065,CN=ADFS,CN=Microsoft,CN=Program Data,DC=simulandlabs,DC=com',
                },
            },
        ])
        _write_zip(ds / 'AADAuditEvents.Zip', 'AADAuditEvents.json', [
            {
                'TimeGenerated': '2021-08-02T13:27:20.017Z',
                'OperationName': 'Add delegated permission grant',
                'Category': 'ApplicationManagement',
                'ResultType': '0',
                'InitiatedBy': {'user': {'userPrincipalName': 'pgustavo@simulandlabs.com'}},
                'TargetResources': [{'displayName': 'SimuLandApp'}],
            },
        ])
        _write_zip(ds / 'OfficeActivityEvents.Zip', 'OfficeActivityEvents.json', [
            {
                'TimeGenerated': '2021-08-02T13:32:07Z',
                'Operation': 'MailItemsAccessed',
                'Workload': 'Exchange',
                'UserId': 'pgustavo@simulandlabs.com',
                'Client_IPAddress': '198.51.100.42',
                'ClientInfoString': 'Client=REST;;',
                'AppId': '00000003-0000-0000-c000-000000000000',
            },
        ])
        return ds

    def test_imports_valid_s5_hybrid_case_without_simuland_leaks(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ds = self._build_fixture(root)
            out_dir = root / 'cases'
            report = import_goldensaml_case(
                ds, out_dir, split='development', ioc_regime='novel_apt_zero_ioc'
            )
            self.assertEqual(report['sophistication_band'], 'S5')
            self.assertEqual(report['steps'], 4)
            self.assertEqual(report['ioc_feed']['active_truth_matches'], 0)

            case_dir = Path(report['case_dir'])
            pub_text = (case_dir / 'public' / 'evidence.json').read_text(encoding='utf-8').lower()
            self.assertNotIn('simuland', pub_text)
            self.assertNotIn('pgustavo', pub_text)

            cov = validate_coverage(load_json(DEFAULT_COVERAGE))
            ev = validate_public_bundle(load_json(case_dir / 'public' / 'evidence.json'), root=case_dir / 'public')
            validate_scenario(load_json(case_dir / 'scenario.json'), cov)
            validate_truth(load_json(case_dir / 'evaluator' / 'truth.json'), ev)


if __name__ == '__main__':
    unittest.main()

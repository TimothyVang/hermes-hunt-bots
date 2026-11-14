"""Synthetic unit tests for `benchmark_import_invictus.py`."""
import gzip
import json
from pathlib import Path
import tempfile
import unittest

from benchmark_contracts import load_json, validate_coverage, validate_public_bundle, validate_scenario, validate_truth
from benchmark_import_invictus import DEFAULT_COVERAGE, import_invictus_case


class InvictusImporterTests(unittest.TestCase):

    def test_gzip_input_and_max_records_subsampling_records_partial_completeness(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            gz_file = root / 'cloudtrail.json.gz'
            payload = {
                'Records': [
                    {
                        'eventID': 'gz-1',
                        'eventTime': '2023-07-10T12:00:01Z',
                        'eventSource': 'sts.amazonaws.com',
                        'eventName': 'AssumeRole',
                        'awsRegion': 'us-east-1',
                        'sourceIPAddress': '203.0.113.50',
                        'userAgent': 'stratus-red-team_12345678-aaaa-bbbb-cccc-1234567890ab',
                        'userIdentity': {'type': 'IAMUser', 'arn': 'arn:aws:iam::218007301253:user/u1'},
                    },
                    {
                        'eventID': 'gz-bg-1',
                        'eventTime': '2023-07-10T12:01:00Z',
                        'eventSource': 'ec2.amazonaws.com',
                        'eventName': 'DescribeInstances',
                        'awsRegion': 'us-east-1',
                        'sourceIPAddress': '198.51.100.10',
                        'userAgent': 'Terraform/1.5.0',
                        'userIdentity': {'type': 'IAMUser', 'arn': 'arn:aws:iam::218007301253:user/devops'},
                    },
                    {
                        'eventID': 'gz-bg-2',
                        'eventTime': '2023-07-10T12:02:00Z',
                        'eventSource': 'ec2.amazonaws.com',
                        'eventName': 'DescribeRegions',
                        'awsRegion': 'us-east-1',
                        'sourceIPAddress': '198.51.100.10',
                        'userAgent': 'Terraform/1.5.0',
                        'userIdentity': {'type': 'IAMUser', 'arn': 'arn:aws:iam::218007301253:user/devops'},
                    },
                ]
            }
            with gzip.open(gz_file, 'wb') as fh:
                fh.write(json.dumps(payload).encode('utf-8'))

            rep = import_invictus_case([gz_file], root / 'out_gz', max_records=2, ioc_regime='novel_apt_zero_ioc')
            cdir = Path(rep['case_dir'])
            ev = validate_public_bundle(load_json(cdir / 'public' / 'evidence.json'), root=cdir / 'public')
            self.assertEqual(ev['sources'][0]['completeness'], 'partial')
            self.assertEqual(len(ev['known_gaps']), 1)

    def test_strips_stratus_markers_and_builds_valid_intrusion_and_control_cases(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            raw_dir = root / 'raw'
            raw_dir.mkdir()

            attack_file = raw_dir / 'attack.json'
            attack_file.write_text(json.dumps({
                'Records': [
                    {
                        'eventID': 'ev-1',
                        'eventTime': '2023-07-10T12:00:01Z',
                        'eventSource': 'sts.amazonaws.com',
                        'eventName': 'AssumeRole',
                        'awsRegion': 'us-east-1',
                        'sourceIPAddress': '203.0.113.50',
                        'userAgent': 'aws-sdk-go-v2/1.17 stratus-red-team_12345678-aaaa-bbbb-cccc-1234567890ab',
                        'userIdentity': {
                            'type': 'IAMUser',
                            'arn': 'arn:aws:iam::218007301253:user/stratus-red-team-user',
                        },
                        'requestParameters': {
                            'roleArn': 'arn:aws:iam::218007301253:role/stratus-red-team-ec2-steal-credentials-role',
                        },
                    },
                    {
                        'eventID': 'ev-2',
                        'eventTime': '2023-07-10T12:01:10Z',
                        'eventSource': 'iam.amazonaws.com',
                        'eventName': 'AttachRolePolicy',
                        'awsRegion': 'us-east-1',
                        'sourceIPAddress': '203.0.113.50',
                        'userAgent': 'stratus-red-team_99999999-aaaa-bbbb-cccc-1234567890ab',
                        'userIdentity': {'type': 'AssumedRole', 'arn': 'arn:aws:sts::218007301253:assumed-role/admin/s1'},
                        'requestParameters': {'roleName': 'stratus-red-team-admin'},
                    },
                    {
                        'eventID': 'ev-3',
                        'eventTime': '2023-07-10T12:02:15Z',
                        'eventSource': 'secretsmanager.amazonaws.com',
                        'eventName': 'GetSecretValue',
                        'awsRegion': 'us-east-1',
                        'sourceIPAddress': '203.0.113.50',
                        'userAgent': 'stratus-red-team_99999999-aaaa-bbbb-cccc-1234567890ab',
                        'userIdentity': {'type': 'AssumedRole', 'arn': 'arn:aws:sts::218007301253:assumed-role/admin/s1'},
                        'requestParameters': {'secretId': 'stratus-red-team-retrieve-secret-0', 'password': 'ADMIN_PASS_7733'},
                        'responseElements': {
                            'secretString': 'SUPER_SECRET_DB_PWD_9911',
                            'credentials': {'sessionToken': 'SESSION_TOK_8822'},
                        },
                    },
                    {
                        'eventID': 'ev-4',
                        'eventTime': '2023-07-10T12:03:00Z',
                        'eventSource': 'ec2.amazonaws.com',
                        'eventName': 'DescribeInstances',
                        'awsRegion': 'us-east-1',
                        'sourceIPAddress': '198.51.100.10',
                        'userAgent': 'Terraform/1.5.0',
                        'userIdentity': {'type': 'IAMUser', 'arn': 'arn:aws:iam::218007301253:user/devops'},
                    },
                ]
            }), encoding='utf-8')

            out_attack = root / 'out_attack'
            rep_a = import_invictus_case(
                [attack_file], out_attack, split='development', ioc_regime='known_ioc_pivot'
            )
            self.assertEqual(rep_a['sophistication_band'], 'S4')
            self.assertEqual(rep_a['steps'], 3)
            pub_text = (Path(rep_a['case_dir']) / 'public' / 'evidence.json').read_text(encoding='utf-8')
            self.assertNotIn('stratus', pub_text.lower())
            self.assertNotIn('218007301253', pub_text)
            self.assertNotIn('SUPER_SECRET_DB_PWD_9911', pub_text)
            self.assertNotIn('SESSION_TOK_8822', pub_text)
            self.assertNotIn('ADMIN_PASS_7733', pub_text)
            self.assertIn('[REDACTED:secret]', pub_text)

            benign_file = raw_dir / 'benign.json'
            benign_file.write_text(json.dumps({
                'Records': [
                    {
                        'eventID': 'bv-1',
                        'eventTime': '2023-07-10T11:45:00Z',
                        'eventSource': 'ec2.amazonaws.com',
                        'eventName': 'DescribeInstances',
                        'awsRegion': 'us-east-1',
                        'sourceIPAddress': '198.51.100.10',
                        'userAgent': 'Terraform/1.5.0',
                        'userIdentity': {'type': 'IAMUser', 'arn': 'arn:aws:iam::218007301253:user/devops'},
                    }
                ]
            }), encoding='utf-8')
            out_ctrl = root / 'out_ctrl'
            rep_c = import_invictus_case(
                [benign_file], out_ctrl, control_only=True, ioc_regime='novel_apt_zero_ioc'
            )
            self.assertEqual(rep_c['sophistication_band'], 'S0')
            self.assertEqual(rep_c['steps'], 0)

            cov = validate_coverage(load_json(DEFAULT_COVERAGE))
            for rep in (rep_a, rep_c):
                cdir = Path(rep['case_dir'])
                ev = validate_public_bundle(load_json(cdir / 'public' / 'evidence.json'), root=cdir / 'public')
                validate_scenario(load_json(cdir / 'scenario.json'), cov)
                validate_truth(load_json(cdir / 'evaluator' / 'truth.json'), ev)


if __name__ == '__main__':
    unittest.main()

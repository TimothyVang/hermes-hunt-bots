"""attack_data importer tests on INVENTED auditd/CloudTrail samples; no downloads, no network."""
import copy
import io
import json
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

import benchmark_import_attackdata as ad
import benchmark_import_otrf as otrf
from benchmark_contracts import (BenchmarkError, decode_json, load_json, validate_public_bundle,
                                 validate_scenario, validate_truth)

SAMPLE = Path(__file__).resolve().parent / 'benchmarks' / 'importers' / 'sample'
COVERAGE = Path(__file__).resolve().parent / 'benchmarks' / 'coverage.json'
AUDIT = SAMPLE / 'attackdata_sample_auditd.log'
AUDIT_I = SAMPLE / 'attackdata_sample_auditd_interpreted.log'
LINUX_META = SAMPLE / 'attackdata-sample-linux.yml'
TRAIL = SAMPLE / 'attackdata_sample_cloudtrail.json'
TRAIL_META = SAMPLE / 'attackdata-sample-cloudtrail.yml'
AUDIT_CURATION = SAMPLE / 'curation-attackdata-auditd.json'
TRAIL_CURATION = SAMPLE / 'curation-attackdata-cloudtrail.json'
SALT = bytes(range(32))


def run_cli(*argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = ad.main([str(item) for item in argv])
    return code, out.getvalue(), err.getvalue()


class AttackDataImporterTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.fields = ad.load_field_map()
        self.coverage = load_json(COVERAGE)

    def tearDown(self):
        self.tmp.cleanup()

    def build(self, dataset=AUDIT, metadata=LINUX_META, fields=None, salt=SALT, **kwargs):
        return ad.build_case(dataset, metadata, fields or self.fields, salt, **kwargs)

    def public_bytes(self, outputs):
        return outputs['public/evidence.json'] + outputs['public/records.jsonl']

    def events(self, outputs):
        return decode_json(outputs['public/evidence.json'])['events']

    def assertCode(self, code, call, *args, **kwargs):
        with self.assertRaises(BenchmarkError) as caught:
            call(*args, **kwargs)
        self.assertEqual(caught.exception.code, code)
        return caught.exception

    def copy_with(self, source, data, name=None):
        path = self.root / (name or source.name)
        path.write_bytes(data)
        return path

    # -------------------------------------------------------------- metadata
    def test_metadata_subset_parser_and_dash_indentation(self):
        parsed = ad.parse_metadata_yaml(LINUX_META.read_bytes())
        self.assertEqual(parsed['techniques'], ['T1003.008', 'T1033'])
        self.assertEqual([d['sourcetype'] for d in parsed['datasets']], ['auditd', 'auditd'])
        # `-   name:` items parse exactly like `- name:` items.
        plain = LINUX_META.read_bytes().replace(b'-   name:', b'- name:').replace(b'\n    ', b'\n  ')
        self.assertEqual(ad.parse_metadata_yaml(plain), parsed)
        base = TRAIL_META.read_bytes()
        for bad in (base.replace(b'environment: invented_range', b'environment: &a invented_range'),
                    base.replace(b'- T1562.008', b'- *alias'),
                    base.replace(b'mitre_technique:\n- T1562.008', b'mitre_technique: [T1562.008]'),
                    base + b'unexpected_key: 1\n',
                    base.replace(b'  sourcetype:', b'\tsourcetype:'),
                    base.replace(b'- T1562.008', b'- T1562.8'),
                    base.replace(b'/datasets/attack_techniques', b'/datasets/../attack_techniques'),
                    base.replace(b'- name: invented', b'-   - name: invented')):
            with self.subTest(bad=bad[-60:]):
                self.assertRaises(BenchmarkError, ad.parse_metadata_yaml, bad)

    # ------------------------------------------------------ format detection
    def test_sourcetype_selects_format_and_content_must_match(self):
        self.assertEqual(json.loads(self.build()[1]['evaluator/import-report.json'])['record_format']['shape'],
                         ad.SHAPE_AUDIT_RAW)
        report = json.loads(self.build(TRAIL, TRAIL_META)[1]['evaluator/import-report.json'])
        self.assertEqual(report['record_format']['shape'], ad.SHAPE_CLOUDTRAIL)
        undeclared = self.copy_with(AUDIT, AUDIT.read_bytes(), 'other.log')
        self.assertCode('metadata_dataset_mismatch', self.build, undeclared)
        wrong_type = self.root / 'meta.yml'
        wrong_type.write_bytes(TRAIL_META.read_bytes().replace(b'sourcetype: aws:cloudtrail', b'sourcetype: XmlWinEventLog'))
        self.assertCode('unsupported_sourcetype', self.build, TRAIL, wrong_type)
        # CloudTrail bytes declared as auditd, and auditd bytes declared as CloudTrail.
        swapped = self.copy_with(AUDIT, TRAIL.read_bytes())
        self.assertCode('unsupported_record_shape', self.build, swapped)
        self.assertCode('invalid_json', self.build, self.copy_with(TRAIL, AUDIT.read_bytes()), TRAIL_META)
        self.assertCode('unsupported_dataset_layout', self.build,
                        self.copy_with(TRAIL, b'[' + TRAIL.read_bytes().split(b'\n')[0] + b']\n'), TRAIL_META)
        self.assertCode('unsupported_dataset_layout', self.build, self.copy_with(AUDIT, b'PK\x03\x04rest'))
        mixed = self.copy_with(AUDIT, AUDIT.read_bytes() + AUDIT_I.read_bytes())
        self.assertCode('mixed_record_shapes', self.build, mixed)
        duplicate = AUDIT.read_bytes().replace(b'tty=pts0 ses=1 comm="bash"', b'tty=pts0 tty=pts1 ses=1 comm="bash"')
        self.assertCode('duplicate_key', self.build, self.copy_with(AUDIT, duplicate))
        unencoded = AUDIT.read_bytes().replace(b'comm="bash"', b'comm=bash')
        self.assertCode('unsupported_record_shape', self.build, self.copy_with(AUDIT, unencoded))

    # ------------------------------------------------------------- allowlist
    def test_auditd_command_lines_are_sanitized_content_and_rule_keys_dropped(self):
        _, outputs = self.build()
        public = self.public_bytes(outputs)
        for secret in (b'Inv3ntedSecret', b'198.51.100.20', b'"key"', b'recon', b'etcshadow', b'T1059',
                       b'labuser', b'unconfined', b'55d0aa', b'6964206E6F77'):
            self.assertNotIn(secret, public)
        report = json.loads(outputs['evaluator/import-report.json'])
        self.assertEqual(report['counts']['dropped_fields']['key'], 4)
        self.assertEqual(report['counts']['metadata_only_by_type'], {'linux-audit:USER_CMD': 1})
        self.assertEqual(report['record_format']['hex_decoded_values'], 1)
        self.assertEqual((report['record_format']['argv']['command_lines'],
                          report['record_format']['argv']['command_lines_attached']), (1, 1))
        content = report['counts']['content']['command_line']
        self.assertEqual((content['values'], content['redactions'], content['truncated']), (2, {'password': 2}, 0))
        self.assertEqual(content['attack_masked'], 2)
        lines = outputs['public/records.jsonl'].decode('utf-8').splitlines()
        self.assertEqual(len(lines), len(AUDIT.read_bytes().splitlines()))
        # Only the blank line is a stub: unknown record types are metadata-only events.
        self.assertEqual([json.loads(line) for line in lines if '"not_imported"' in line],
                         [{'line': 5, 'status': 'not_imported', 'reason': 'blank_line'}])
        by_serial = {e['fields']['audit_serial'] + e['fields']['type']: e['fields'] for e in self.events(outputs)}
        user = by_serial['101SYSCALL']['AUID']
        command = by_serial['103SYSCALL']['command_line']
        # EXECVE argv (quoted, hex-encoded) joined on the SYSCALL of the same serial; password redacted, the
        # ATT&CK token masked, /home user and IP pseudonymized like the structured fields.
        self.assertEqual(command, by_serial['103EXECVE']['command_line'])
        self.assertTrue(command.startswith('sshpass -p [REDACTED:password] ssh %s@ipv4-' % user), command)
        self.assertTrue(command.endswith(" 'echo T#### done; ls /home/%s'" % user), command)
        self.assertEqual(by_serial['103EXECVE']['argc'], 6)
        self.assertEqual(by_serial['103SYSCALL']['comm'], 'id now')
        self.assertEqual((by_serial['104SYSCALL']['proctitle'], by_serial['104PROCTITLE']['proctitle']),
                         ('sudo cat /etc/shadow', 'sudo cat /etc/shadow'))
        self.assertNotIn('command_line', by_serial['104SYSCALL'])
        self.assertEqual(by_serial['104CWD']['cwd'], '/home/%s/work' % user)
        self.assertEqual(by_serial['104PATH']['name'], '/etc/shadow')
        self.assertEqual((by_serial['104SYSCALL']['EUID'], by_serial['104PATH']['OGID']), ('root', 'shadow'))
        self.assertEqual(set(by_serial['106USER_CMD']), {'timestamp_original', 'type', 'audit_serial'})
        sources = decode_json(outputs['public/evidence.json'])['sources']
        self.assertEqual([s['completeness'] for s in sources], ['unknown'])

    def test_execve_argv_reassembly_shapes(self):
        raw = ad.SHAPE_AUDIT_RAW
        # Chunked argument (hex chunks joined before decoding), quoted, (null) and control characters.
        chunks = 'argc=3 a0="python3" a1_len=8 a1[0]=2D63 a1[1]=0A7072696E74 a2=(null)'
        self.assertEqual(ad._execve(chunks, raw), {'argc': 3, 'args': {0: 'python3', 1: '-c\nprint', 2: '(null)'}})
        self.assertEqual(ad._execve('a3="tail" a4=FF00', raw), {'argc': None, 'args': {3: 'tail', 4: '\\xff\\x00'}})
        self.assertIsNone(ad._execve('garbage a0="x"', raw))
        # ausearch -i: values may contain spaces; an out-of-order `aN=` stays inside its argument.
        interpreted = ad._execve('argc=3 a0=printf a1=%s a5=y a2=two words ', ad.SHAPE_AUDIT_INTERPRETED)
        self.assertEqual(interpreted['args'], {0: 'printf', 1: '%s a5=y', 2: 'two words'})
        self.assertEqual(ad._proctitle('proctitle=6C73002D6C6100', raw), 'ls -la')
        self.assertEqual(ad._proctitle('proctitle="ls"', raw), 'ls')
        self.assertEqual(ad._proctitle('proctitle=cat a b ', ad.SHAPE_AUDIT_INTERPRETED), 'cat a b')
        self.assertIsNone(ad._proctitle('argc=2 a0="x"', raw))
        self.assertEqual([ad._shell_word(w) for w in ('ls', '', "it's", 'a b')], ['ls', "''", "'it'\\''s'", "'a b'"])
        # Continuation record, byte-identical duplicate and a missing argument in one audit event.
        first = 'type=EXECVE msg=audit(1767225601.300:103): argc=4 a0="python3" a1="-c"'
        data = AUDIT.read_bytes().replace(AUDIT.read_bytes().split(b'\n')[1], '\n'.join(
            (first, first, 'type=EXECVE msg=audit(1767225601.300:103): a3="x"')).encode())
        _, outputs = self.build(self.copy_with(AUDIT, data))
        report = json.loads(outputs['evaluator/import-report.json'])['record_format']['argv']
        self.assertEqual((report['execve_records'], report['execve_duplicate_records'], report['execve_missing_args']),
                         (3, 1, 1))
        commands = [e['fields'].get('command_line') for e in self.events(outputs)
                    if e['fields']['audit_serial'] == '103']
        self.assertEqual(sorted(c for c in commands if c), ['python3 -c x', 'python3 -c x'])

    def test_cloudtrail_content_fields_are_sanitized_and_secret_keys_dropped(self):
        _, outputs = self.build(TRAIL, TRAIL_META)
        public = self.public_bytes(outputs)
        for secret in (b'Inv3nted-Pa55word', b'wJalrXUtnFEMI', b'secretAccessKey', b'123456789012', b'AKIAEXAMPLE',
                       b'AIDAEXAMPLE', b'198.51.100.7', b'203.0.113.5', b'lab-operator', b'lab-admin-role',
                       b'lab-trail', b'example.test', b'Ignore previous', b'req-0002', b'0000000000a1', b'T1562'):
            self.assertNotIn(secret, public)
        events = {e['fields']['eventName']: e['fields'] for e in self.events(outputs)}
        create = events['CreateTrail']
        self.assertEqual(events['ListBuckets']['errorCode'], 'AccessDenied')
        self.assertEqual(events['ListBuckets']['errorMessage'],
                         'User: %s is not authorized to perform: s3:ListAllMyBuckets' % create['userIdentity.arn'])
        self.assertEqual(json.loads(events['CreateTrail']['requestParameters']),
                         {'isMultiRegionTrail': False, 'name': create['requestParameters.name'],
                          's3BucketName': create['requestParameters.s3BucketName']})
        self.assertEqual(json.loads(events['CreateLoginProfile']['requestParameters']),
                         {'passwordResetRequired': False, 'userName': create['userIdentity.userName']})
        key = json.loads(events['CreateAccessKey']['responseElements'])['accessKey']
        self.assertEqual(set(key), {'accessKeyId', 'createDate', 'status', 'userName'})
        self.assertTrue(key['accessKeyId'].startswith('key-'))
        # Policy documents stay; bucket and role names inside them use the structured pseudonyms.
        policy = json.loads(events['PutBucketPolicy']['requestParameters'])
        bucket = create['requestParameters.s3BucketName']
        self.assertEqual(policy['Host'], bucket + '.s3.us-east-1.amazonaws.com')
        statement = policy['bucketPolicy']['Statement'][0]
        self.assertEqual(statement['Resource'], 'arn:aws:s3:::%s/*' % bucket)
        signin = next(e['fields'] for e in self.events(outputs) if e['fields']['eventName'] == 'ConsoleLogin' and
                      'userIdentity.sessionContext.sessionIssuer.arn' in e['fields'])
        self.assertEqual(statement['Principal']['AWS'], signin['userIdentity.sessionContext.sessionIssuer.arn'])
        self.assertEqual(json.loads(events['PutBucketPolicy']['additionalEventData'])['SignatureVersion'], 'SigV4')
        self.assertEqual(events['CreateLoginProfile']['userAgent'], 'aws-cli/2.0 invented Mozilla/5.0 (X11) '
                                                                    'Chrome/103.0.0.0')
        self.assertEqual(events['GetCallerIdentity']['requestParameters'], None)
        self.assertEqual(json.loads(signin['responseElements']), {'ConsoleLogin': 'Success'})
        # Unknown event type: metadata only.
        self.assertEqual(set(events['InventedServiceEvent']), {'timestamp_original', 'eventName', 'eventSource',
                                                               'eventCategory', 'awsRegion', 'recipientAccountId'})
        report = json.loads(outputs['evaluator/import-report.json'])
        self.assertEqual(report['counts']['metadata_only_by_type'], {'cloudtrail:AwsServiceEvent': 1})
        dropped = report['counts']['dropped_fields']
        self.assertEqual((dropped['requestParameters.password'], dropped['responseElements.accessKey.secretAccessKey'],
                          dropped['serviceEventDetails.note']), (1, 1, 1))
        self.assertEqual(report['counts']['content']['requestParameters']['secret_fields_dropped'], 1)
        self.assertEqual(report['counts']['content']['responseElements']['secret_fields_dropped'], 1)
        self.assertIn('Apache License 2.0', report['license'])
        assets = decode_json(outputs['public/evidence.json'])['assets']
        self.assertEqual([a['os_family'] for a in assets], ['not-applicable'])

    def test_content_truncation_is_marked_and_stated_as_gap(self):
        lines = TRAIL.read_bytes().split(b'\n')
        lines[1] = lines[1].replace(b'"aws-cli/2.0 invented"', b'"aws-cli/2.0 ' + b'x' * 20000 + b'"')
        _, outputs = self.build(self.copy_with(TRAIL, b'\n'.join(lines)), TRAIL_META)
        agent = next(e['fields']['userAgent'] for e in self.events(outputs)
                     if e['fields']['eventName'] == 'GetCallerIdentity')
        self.assertIn('[truncated', agent)
        self.assertLessEqual(len(agent.encode('utf-8')), ad.CONTENT_MAX_BYTES + 64)
        report = json.loads(outputs['evaluator/import-report.json'])
        self.assertEqual(report['counts']['content']['userAgent']['truncated'], 1)
        gaps = [g['reason'] for g in decode_json(outputs['public/evidence.json'])['known_gaps']]
        self.assertEqual(len([g for g in gaps if g.startswith('content_truncated: 1 content values')]), 1)
        self.assertFalse(any(g.startswith('content_truncated') for g in
                             (g['reason'] for g in decode_json(self.build(TRAIL, TRAIL_META)[1]['public/evidence.json'])
                              ['known_gaps'])))

    def test_field_map_content_rules(self):
        for mutate in (lambda f: f['formats']['linux-auditd']['record_types']['SYSCALL'].__setitem__('comm', 'content'),
                       lambda f: f['formats']['linux-auditd']['record_types']['SYSCALL'].__setitem__('command_line',
                                                                                                   'keep'),
                       lambda f: f['formats']['aws-cloudtrail']['metadata_only'].__setitem__('userAgent', 'content'),
                       lambda f: f['formats']['linux-auditd']['metadata_only'].__setitem__('pid', 'keep'),
                       lambda f: f['formats']['aws-cloudtrail'].pop('metadata_only')):
            data = json.loads(ad.DEFAULT_FIELDS.read_text('utf-8'))
            mutate(data)
            path = self.root / 'fields.json'
            path.write_text(json.dumps(data), 'utf-8')
            with self.subTest(fields=data['formats']['linux-auditd']['metadata_only']):
                self.assertRaises(BenchmarkError, ad.load_field_map, path)

    # ------------------------------------------------------------ pseudonyms
    def test_pseudonyms_are_consistent_across_fields_and_records(self):
        _, outputs = self.build(TRAIL, TRAIL_META)
        events = {e['fields']['eventName'] + e['timestamp_utc']: e['fields'] for e in self.events(outputs)}
        create = next(v for k, v in events.items() if k.startswith('CreateTrail'))
        stop = next(v for k, v in events.items() if k.startswith('StopLogging'))
        signin = next(v for k, v in events.items() if k.startswith('ConsoleLogin2026-01-01T00:00:00'))
        account = create['recipientAccountId']
        self.assertTrue(account.startswith('account-'))
        self.assertEqual(stop['requestParameters.name'],
                         'arn:aws:cloudtrail:us-east-1:%s:trail/%s' % (account, create['requestParameters.name']))
        self.assertEqual(create['userIdentity.arn'],
                         'arn:aws:iam::%s:user/%s' % (account, create['userIdentity.userName']))
        self.assertEqual(create['userIdentity.accessKeyId'], stop['userIdentity.accessKeyId'])
        role = signin['userIdentity.sessionContext.sessionIssuer.userName']
        self.assertTrue(signin['userIdentity.arn'].startswith('arn:aws:sts::%s:assumed-role/%s/' % (account, role)))
        self.assertEqual(signin['userIdentity.sessionContext.sessionIssuer.arn'],
                         'arn:aws:iam::%s:role/%s' % (account, role))
        _, linux = self.build()
        fields = {e['fields']['audit_serial'] + e['fields']['type']: e['fields'] for e in self.events(linux)}
        user = fields['101SYSCALL']['AUID']
        self.assertTrue(user.startswith('user-'))
        self.assertEqual(fields['103SYSCALL']['exe'], '/home/%s/tools/id-helper' % user)
        self.assertEqual(fields['103PATH']['OUID'], user)

    def test_unpseudonymized_identifier_or_dataset_name_is_refused(self):
        leaky = copy.deepcopy(self.fields)
        leaky['formats']['aws-cloudtrail']['record_types']['AwsApiCall']['errorMessage'] = 'keep'
        self.assertCode('pseudonymization_leak', self.build, TRAIL, TRAIL_META, leaky)
        named = copy.deepcopy(self.fields)
        named['formats']['aws-cloudtrail']['record_types']['AwsApiCall']['userAgent'] = 'keep'
        renamed = self.root / 'meta.yml'
        renamed.write_bytes(TRAIL_META.read_bytes().replace(b'name: invented_cloudtrail-json',
                                                            b'name: stratus-red-team'))
        self.assertCode('forbidden_public_metadata', self.build, TRAIL, renamed, named)
        labelled = copy.deepcopy(self.fields)
        labelled['formats']['linux-auditd']['record_types']['SYSCALL']['key'] = 'keep'
        self.assertCode('attack_token_in_field', self.build, AUDIT, LINUX_META, labelled)

    # ----------------------------------------------------------------- clock
    def test_clock_offset_is_explicit_per_shape(self):
        self.assertCode('no_clock_reference', self.build, AUDIT_I)
        self.assertCode('conflicting_arguments', self.build, AUDIT, clock=(0, 1))
        self.assertCode('conflicting_arguments', self.build, TRAIL, TRAIL_META, clock=(0, 1))
        self.assertCode('invalid_number', self.build, AUDIT_I, clock=(0, float('nan')))
        _, outputs = self.build(AUDIT_I, clock=(3600, 30))
        bundle = decode_json(outputs['public/evidence.json'])
        first = bundle['events'][0]
        self.assertEqual((first['timestamp_utc'], first['fields']['timestamp_original']),
                         ('2026-01-01T00:00:00.100000+00:00', '01/01/2026 01:00:00.100'))
        self.assertEqual((bundle['sources'][0]['clock_offset_seconds'], bundle['sources'][0]['clock_uncertainty_seconds']),
                         (3600, 30.001))
        failed = next(e['fields'] for e in bundle['events'] if e['fields']['type'] == 'SYSCALL' and
                      e['fields']['audit_serial'] == '202')
        self.assertEqual(failed['exit'], 'EACCES(Permission denied)')
        # ausearch -i argv keeps the space inside its argument; the profile user matches the AUID pseudonym.
        self.assertEqual(failed['command_line'], "cat '/home/%s/my notes'" % failed['auid'])
        self.assertEqual(failed['proctitle'], 'cat /home/%s/notes' % failed['auid'])
        template = json.loads(outputs['evaluator/curation-template.json'])
        self.assertEqual(template['curation']['clock_declaration'], {'offset_seconds': 3600, 'uncertainty_seconds': 30})
        trail = decode_json(self.build(TRAIL, TRAIL_META)[1]['public/evidence.json'])['sources'][0]
        self.assertEqual((trail['clock_offset_seconds'], trail['clock_uncertainty_seconds']), (0, 1))

    # ----------------------------------------------------------------- draft
    def test_draft_truth_is_refused_and_template_fixes_format_coverage(self):
        for dataset, metadata in ((AUDIT, LINUX_META), (TRAIL, TRAIL_META)):
            with self.subTest(dataset=dataset.name):
                case_id, outputs = self.build(dataset, metadata)
                self.assertNotIn('scenario.json', outputs)
                self.assertNotIn('evaluator/truth.json', outputs)
                draft = json.loads(outputs['evaluator/truth.DRAFT.json'])
                bundle = decode_json(outputs['public/evidence.json'])
                self.assertEqual(draft['status'], otrf.DRAFT_MARKER)
                self.assertRaises(BenchmarkError, validate_truth, draft, bundle)
                self.assertCode('draft_truth_refused', otrf.refuse_draft, draft, bundle)
                template = json.loads(outputs['evaluator/curation-template.json'])
                fixed = ad.FORMAT_COVERAGE_EXACT[ad.FORMAT_AUDITD if dataset == AUDIT else ad.FORMAT_CLOUDTRAIL]
                for axis, values in fixed.items():
                    self.assertEqual(template['curation']['coverage'][axis], values)
                self.assertEqual(len(template['candidate_events']), len(bundle['events']))

    def test_proposal_status_and_wrong_format_coverage_are_refused(self):
        curation = json.loads(TRAIL_CURATION.read_text('utf-8'))
        proposal = dict(curation, status='PROPOSED_UNREVIEWED_NOT_FOR_SCORING')
        path = self.root / 'proposal.json'
        path.write_text(json.dumps(proposal), 'utf-8')
        self.assertCode('proposal_has_curator', self.build, TRAIL, TRAIL_META, curation_path=path,
                        coverage=self.coverage)
        for mutate, code in ((lambda c: c['coverage'].__setitem__('os', ['linux']), 'coverage_format_mismatch'),
                             (lambda c: c['coverage'].__setitem__('identity_domain', ['ad-single-domain']),
                              'coverage_format_mismatch'),
                             (lambda c: c['assets'][0].__setitem__('os_family', 'linux'), 'asset_format_mismatch'),
                             (lambda c: c.__setitem__('clock_declaration', {'offset_seconds': 0,
                                                                            'uncertainty_seconds': 1}),
                              'conflicting_arguments')):
            changed = copy.deepcopy(curation)
            mutate(changed)
            path.write_text(json.dumps(changed), 'utf-8')
            with self.subTest(code=code):
                self.assertCode(code, self.build, TRAIL, TRAIL_META, curation_path=path, coverage=self.coverage)

    def test_unreviewed_proposal_imports_marked(self):
        curation = json.loads(TRAIL_CURATION.read_text('utf-8'))
        proposal = dict(curation, status='PROPOSED_UNREVIEWED_NOT_FOR_SCORING', curated_by=None, curated_utc=None)
        path = self.root / 'curation.PROPOSED.json'
        path.write_text(json.dumps(proposal), 'utf-8')
        _, outputs = self.build(TRAIL, TRAIL_META, curation_path=path, coverage=self.coverage)
        self.assertEqual(json.loads(outputs['evaluator/truth.json'])['attestation'], 'unreviewed_proposal')
        self.assertEqual(json.loads(outputs['evaluator/import-report.json'])['curation']['attestation'],
                         'unreviewed_proposal')
        self.assertIn(otrf.UNREVIEWED_LIMITATION,
                      json.loads(outputs['scenario.json'])['sophistication']['emulation_limitations'])
        _, signed = self.build(TRAIL, TRAIL_META, curation_path=TRAIL_CURATION, coverage=self.coverage)
        self.assertNotIn('attestation', json.loads(signed['evaluator/truth.json']))
        self.assertEqual(json.loads(signed['evaluator/import-report.json'])['curation']['attestation'],
                         'human_attested')

    def test_agent_consensus_imports_marked_with_disputes(self):
        _, human = self.build(TRAIL, TRAIL_META, curation_path=TRAIL_CURATION, coverage=self.coverage)
        locators = json.loads(human['evaluator/locators.json'])['events']
        truth = json.loads(human['evaluator/truth.json'])
        cited = {locators[event_id]['line'] for step in truth['steps'] for group in step['support_sets']
                 for event_id in group} | {locators[event_id]['line'] for group in truth['lookalike_event_ids']
                                            for event_id in group}
        spare = min(item['line'] for item in locators.values() if item['line'] not in cited)
        spare_id = next(event_id for event_id, item in locators.items() if item['line'] == spare)
        curation = json.loads(TRAIL_CURATION.read_text('utf-8'))
        consensus = dict(curation, attestation_hint='agent_consensus', curated_by='agent-consensus',
                         curated_utc='2026-11-04T12:00:00+00:00', note='Invented consensus fixture.',
                         excluded_locators=[{'line': spare}], controls=[])
        path = self.root / 'curation.CONSENSUS.json'
        path.write_text(json.dumps(consensus), 'utf-8')
        self.assertEqual(ad.load_curation(path)[0]['attestation'], 'agent_consensus')
        _, outputs = self.build(TRAIL, TRAIL_META, curation_path=path, coverage=self.coverage)
        bundle = decode_json(outputs['public/evidence.json'])
        truth = validate_truth(decode_json(outputs['evaluator/truth.json']), bundle)
        self.assertEqual((truth['attestation'], truth['disputed_event_ids']), ('agent_consensus', [spare_id]))
        self.assertEqual(sorted(truth['assessment_labels'].values(), key=repr), [1, None])
        report = json.loads(outputs['evaluator/import-report.json'])['curation']
        self.assertEqual((report['attestation'], report['disputed_questions'], report['disputed_evidence']['event_ids']),
                         ('agent_consensus', 1, 1))
        scenario = json.loads(outputs['scenario.json'])
        self.assertIn(otrf.CONSENSUS_LIMITATION, scenario['sophistication']['emulation_limitations'])
        self.assertEqual(scenario['provenance'], 'public_replay')
        for changes, code in (({'excluded_locators': [{'line': 6}]}, 'excluded_overlap'),
                              ({'excluded_locators': [{'line': spare}, {'line': spare}]}, 'duplicate_item'),
                              ({'curated_by': 'Invented Reviewer'}, 'consensus_curator_mismatch'),
                              ({'attestation_hint': 'agent'}, 'invalid_attestation_hint')):
            path.write_text(json.dumps(dict(consensus, **changes)), 'utf-8')
            with self.subTest(code=code):
                self.assertCode(code, self.build, TRAIL, TRAIL_META, curation_path=path, coverage=self.coverage)
        for changes, code in (({'curated_by': 'agent-consensus'}, 'consensus_hint_missing'),
                              ({'excluded_locators': []}, 'excluded_without_consensus'),
                              ({'controls': []}, 'unlabeled_question')):
            path.write_text(json.dumps(dict(curation, **changes)), 'utf-8')
            with self.subTest(code=code):
                self.assertCode(code, self.build, TRAIL, TRAIL_META, curation_path=path, coverage=self.coverage)

    # --------------------------------------------------------------- curated
    def test_curated_imports_validate_with_measured_difficulty(self):
        for dataset, metadata, curation, family in (
                (AUDIT, LINUX_META, AUDIT_CURATION, 'attackdata-t1003-008-t1033'),
                (TRAIL, TRAIL_META, TRAIL_CURATION, 'attackdata-t1562-008')):
            with self.subTest(dataset=dataset.name):
                _, outputs = self.build(dataset, metadata, curation_path=curation, coverage=self.coverage)
                bundle = decode_json(outputs['public/evidence.json'])
                truth = decode_json(outputs['evaluator/truth.json'])
                scenario = decode_json(outputs['scenario.json'])
                validate_public_bundle(bundle)
                validate_truth(truth, bundle)
                validate_scenario(scenario, self.coverage)
                self.assertEqual((scenario['split'], scenario['provenance'], scenario['family_id']),
                                 ('development', 'public_replay', family))
                self.assertEqual(sorted(truth['assessment_labels'].values()), [0, 1])
                self.assertTrue(truth['lookalike_event_ids'])
                self.assertEqual(scenario['difficulty']['factors']['gaps']['score'], 1)

    def test_cli_round_trip_is_deterministic_with_reused_salt(self):
        code, out, err = run_cli('--dataset', TRAIL, '--metadata', TRAIL_META, '--draft', '--output', self.root / 'draft')
        self.assertEqual((code, err), (0, ''))
        summary = json.loads(out)
        case_dir = Path(summary['case_directory'])
        salt = case_dir / 'evaluator' / 'salt.json'
        code, out, err = run_cli('--dataset', TRAIL, '--metadata', TRAIL_META, '--curation', TRAIL_CURATION,
                                 '--salt-file', salt, '--output', self.root / 'cases')
        self.assertEqual((code, err), (0, ''))
        curated = self.root / 'cases' / summary['case_id']
        # Same salt: identical event and asset pseudonyms (questions differ: the curation declares two windows).
        curated_bundle = load_json(curated / 'public' / 'evidence.json')
        draft_bundle = load_json(case_dir / 'public' / 'evidence.json')
        self.assertEqual((curated_bundle['events'], [a['asset_id'] for a in curated_bundle['assets']]),
                         (draft_bundle['events'], [a['asset_id'] for a in draft_bundle['assets']]))
        self.assertEqual(len(curated_bundle['assessment_questions']), 2)
        validate_public_bundle(curated_bundle, curated / 'public')
        code, _, err = run_cli('--dataset', TRAIL, '--metadata', TRAIL_META, '--draft', '--output', self.root / 'draft')
        self.assertEqual((code, err), (2, 'error: output_exists: output\n'))
        code, _, err = run_cli('--dataset', AUDIT_I, '--metadata', LINUX_META, '--draft', '--output', self.root / 'x',
                               '--clock-offset-seconds', '0')
        self.assertEqual((code, err), (2, 'error: conflicting_arguments: clock\n'))
        first = self.build(TRAIL, TRAIL_META)
        self.assertEqual(first, self.build(TRAIL, TRAIL_META))
        other = self.build(TRAIL, TRAIL_META, salt=bytes(32))
        self.assertNotEqual(first[1]['public/evidence.json'], other[1]['public/evidence.json'])
        self.assertEqual(len(self.events(first[1])), len(self.events(other[1])))

    # ------------------------------------------------------------- partition
    def test_partition_excludes_and_states_original_lines(self):
        window = ('2026-01-01T00:00:00Z', '2026-01-01T00:01:00Z')
        case_id, outputs = self.build(TRAIL, TRAIL_META, partition=window)
        bundle = decode_json(outputs['public/evidence.json'])
        self.assertEqual(bundle['window_utc'], {'start_inclusive': '2026-01-01T00:00:00.000000+00:00',
                                                'end_exclusive': '2026-01-01T00:01:00.000000+00:00'})
        gaps = [g['reason'] for g in bundle['known_gaps'] if g['reason'].startswith('outside_partition_window')]
        self.assertEqual(len(gaps), 1)
        self.assertIn('3 records', gaps[0])
        self.assertIn('original lines 3-5', gaps[0])
        lines = outputs['public/records.jsonl'].decode('utf-8').splitlines()
        self.assertEqual(len(lines), len(TRAIL.read_bytes().splitlines()))
        self.assertEqual(json.loads(lines[3])['reason'], 'outside_partition_window')
        self.assertEqual(sorted(int(e['locator']['record_id']) for e in bundle['events']), [1, 2, 6, 7, 8, 9, 10])
        report = json.loads(outputs['evaluator/import-report.json'])
        self.assertEqual((report['partition']['excluded_records'], report['partition']['excluded_line_ranges']),
                         (3, '3-5'))
        self.assertEqual(json.loads(outputs['evaluator/curation-template.json'])['curation']['partition_window'],
                         bundle['window_utc'])
        self.assertNotEqual(case_id, self.build(TRAIL, TRAIL_META)[0])
        self.assertEqual((case_id, outputs), self.build(TRAIL, TRAIL_META, partition=window))
        self.assertCode('no_supported_records', self.build, TRAIL, TRAIL_META,
                        partition=('2026-01-02T00:00:00Z', '2026-01-02T00:01:00Z'))
        self.assertCode('invalid_window', self.build, TRAIL, TRAIL_META, partition=(window[1], window[0]))
        code, _, err = run_cli('--dataset', TRAIL, '--metadata', TRAIL_META, '--draft', '--output', self.root / 'x',
                               '--window-start', window[0])
        self.assertEqual((code, err), (2, 'error: conflicting_arguments: partition\n'))

    def test_partition_must_match_curation_and_keeps_family(self):
        window = ('2026-01-01T00:05:00Z', '2026-01-01T00:06:01Z')
        curation = json.loads(TRAIL_CURATION.read_text('utf-8'))
        curation.update({'partition_window': {'start_inclusive': window[0], 'end_exclusive': window[1]},
                         'controls': [], 'lookalike_event_ids': [],
                         'assessment_windows': [{'start_inclusive': window[0], 'end_exclusive': window[1]}]})
        path = self.root / 'partition.json'
        path.write_text(json.dumps(curation), 'utf-8')
        _, outputs = self.build(TRAIL, TRAIL_META, curation_path=path, coverage=self.coverage, partition=window)
        scenario = decode_json(outputs['scenario.json'])
        whole = decode_json(self.build(TRAIL, TRAIL_META, curation_path=TRAIL_CURATION,
                                       coverage=self.coverage)[1]['scenario.json'])
        self.assertEqual(scenario['family_id'], whole['family_id'])
        self.assertNotEqual(scenario['scenario_id'], whole['scenario_id'])
        self.assertTrue(any(item.startswith('Derived partition 2026-01-01T00:05:00')
                            for item in scenario['sophistication']['emulation_limitations']))
        for kwargs in ({'curation_path': path},
                       {'curation_path': path, 'partition': ('2026-01-01T00:05:00Z', '2026-01-01T00:06:02Z')},
                       {'curation_path': TRAIL_CURATION, 'partition': window}):
            with self.subTest(kwargs=kwargs):
                self.assertCode('partition_mismatch', self.build, TRAIL, TRAIL_META, coverage=self.coverage, **kwargs)
        curation['steps'][0]['support_sets'] = [[{'line': 6}]]
        path.write_text(json.dumps(curation), 'utf-8')
        self.assertCode('support_record_not_imported', self.build, TRAIL, TRAIL_META, curation_path=path,
                        coverage=self.coverage, partition=window)


if __name__ == '__main__':
    unittest.main()

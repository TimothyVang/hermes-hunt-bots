"""Offline scripted transport tests; no AWS, Stratus, SSO or network is invoked."""
import copy
import gzip
import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import benchmark_aws as aws
from benchmark_contracts import BenchmarkError, canonical_bytes


class ScriptedTransport:
    """Literal fixture responses and temporary files, never an executable runner."""
    def __init__(self, fixture):
        self.fixture = fixture
        self.calls = []
        self.logging = True
        self.baseline_logging = True
        self.deleted = False
        self.keep_bucket = False
        self.keep_trail = False
        self.account = fixture.identity['account_id']
        self.arn = fixture.assumed_arn
        self.retention = False
        self.unknown_detonate = False
        self.no_stop_effect = False
        self.objects = {}
        self.pages = None

    def __call__(self, argv, **kwargs):
        self.calls.append((list(argv), copy.deepcopy(kwargs)))
        f = self.fixture
        command = argv[1:]
        payload = None
        if argv[0] == f.config['terraform']['path']:
            assert command == ['version', '-json']
            payload = {'terraform_version': '1.9.0'}
        elif argv[0] == f.config['stratus']['path']:
            assert len(command) == 2 and command[1] == aws.TECHNIQUE
            if command[0] == 'warmup':
                f.write_state()
            elif command[0] == 'detonate':
                if self.unknown_detonate:
                    return {'status': 'unknown', 'exit_code': None, 'stdout': b'', 'failure_reason': 'timeout'}
                if not self.no_stop_effect:
                    self.logging = False
            elif command[0] == 'cleanup':
                self.deleted = True
            elif command[0] != 'status':
                raise AssertionError('Unexpected fixture action')
            return {'status': 'succeeded', 'exit_code': 0, 'stdout': b'COLD fixture output is not effect proof'}
        elif command == ['--version']:
            return {'status': 'succeeded', 'exit_code': 0, 'stdout': b'aws-cli/2.31.0 fixture'}
        elif command[:2] == ['sts', 'get-caller-identity']:
            payload = {'Account': self.account, 'Arn': self.arn, 'UserId': 'fixture'}
        elif command[:2] == ['cloudtrail', 'get-trail']:
            arn = command[command.index('--name') + 1]
            baseline = arn == f.identity['baseline_trail_arn']
            payload = {'Trail': {'TrailARN': arn, 'S3BucketName': f.collector['bucket'] if baseline else f.resources['bucket']}}
        elif command[:2] == ['cloudtrail', 'get-trail-status']:
            arn = command[command.index('--name') + 1]
            payload = {'IsLogging': self.baseline_logging if arn == f.identity['baseline_trail_arn'] else self.logging}
        elif command[:2] == ['cloudtrail', 'describe-trails']:
            payload = {'trailList': [{'TrailARN': f.resources['trail_arn']}] if self.keep_trail or not self.deleted else []}
        elif command[:2] == ['s3api', 'list-buckets']:
            payload = {'Buckets': [{'Name': f.resources['bucket']}] if self.keep_bucket or not self.deleted else []}
        elif command[:2] == ['s3api', 'get-bucket-versioning']:
            payload = {'Status': 'Enabled'}
        elif command[:2] == ['s3api', 'get-object-lock-configuration']:
            if not self.retention:
                return {'status': 'failed', 'exit_code': 1, 'stdout': b''}
            payload = {'ObjectLockConfiguration': {'ObjectLockEnabled': 'Enabled', 'Rule': {'DefaultRetention': {'Mode': 'COMPLIANCE', 'Days': 7}}}}
        elif command[:2] == ['s3api', 'head-object']:
            key = command[command.index('--key') + 1]
            if key not in self.objects:
                return {'status': 'failed', 'exit_code': 1, 'stdout': b''}
            payload = {'ContentLength': len(self.objects[key]), 'ETag': self.object_entry(key)['ETag']}
        elif command[:2] == ['s3api', 'list-objects-v2']:
            if self.pages is not None:
                index = 1 if '--continuation-token' in command else 0
                payload = self.pages[index]
            else:
                prefix = command[command.index('--prefix') + 1]
                payload = {'IsTruncated': False, 'Contents': [self.object_entry(key) for key in self.objects if key.startswith(prefix)]}
        elif command[:2] == ['s3api', 'get-object']:
            key = command[command.index('--key') + 1]
            data = self.objects[key]
            # The driver chooses a fresh path inside the test's private directory.
            output_path = Path(command[command.index('--range') + 2])
            output_path.write_bytes(data)
            payload = {'ContentLength': len(data), 'ETag': self.object_entry(key)['ETag'], 'VersionId': 'fixture-version'}
        else:
            raise AssertionError('Unexpected fixture command: ' + repr(command))
        return {'status': 'succeeded', 'exit_code': 0, 'stdout': canonical_bytes(payload)}

    def object_entry(self, key):
        return {'Key': key, 'ETag': '"' + hashlib.md5(self.objects[key]).hexdigest() + '"', 'Size': len(self.objects[key])}


class AWSFixture(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.home = self.root / 'home'
        self.home.mkdir()
        self.private = self.root / 'private'
        self.private.mkdir()
        self.identity = {'account_id': '123456789012', 'region': 'us-east-1',
                         'role_arn': 'arn:aws:iam::123456789012:role/Exercise', 'session_name': 'fixture-session',
                         'baseline_trail_arn': 'arn:aws:cloudtrail:us-east-1:123456789012:trail/baseline'}
        self.assumed_arn = 'arn:aws:sts::123456789012:assumed-role/Exercise/fixture-session'
        self.config = {'os_home': str(self.home), 'os_user': 'fixture-user', 'profile': 'exercise',
                       'sso_config': self.pin('sso-config', b'[fixture]'),
                       'sso_credentials': self.pin('sso-credentials', b''),
                       'stratus': self.pin('stratus', b'not executable: stratus fixture', 'source-build'),
                       'terraform': self.pin('terraform', b'not executable: terraform fixture', '1.9.0'),
                       'source_commit': aws.SOURCE_COMMIT}
        provenance = {'source_commit': aws.SOURCE_COMMIT,
                      'stratus_sha256': self.config['stratus']['sha256'], 'stratus_version': 'source-build',
                      'terraform_sha256': self.config['terraform']['sha256'], 'terraform_version': '1.9.0'}
        self.config['provenance'] = self.pin('provenance', canonical_bytes(provenance))
        self.binary = self.pin('aws', b'not executable: aws fixture', 'aws-cli/2.31.0')
        collector_config = {key: copy.deepcopy(self.config[key]) for key in aws.LOGIN_FIELDS}
        collector_config.update(self.identity)
        collector_config.update(profile='collector', role_arn='arn:aws:iam::123456789012:role/Reader',
                                executable=self.binary, poll_seconds=0.01)
        self.collector = {'source_id': 'cloudtrail', 'kind': 'aws', 'target_id': 'sandbox', 'export_root': None,
                          'bucket': 'baseline-fixture-bucket', 'prefix': 'AWSLogs/123456789012/CloudTrail/us-east-1/',
                          'window_utc': {'start_inclusive': '2026-01-01T00:00:00+00:00', 'end_exclusive': '2026-01-02T00:00:00+00:00'},
                          'sensor_version': 'fixture', 'config_version': 'fixture', 'max_bytes': 1024 * 1024,
                          'max_seconds': 30, 'watermark_utc': '2026-01-02T00:00:00+00:00', 'config': collector_config}
        collector_config['watermark_key'] = self.collector['prefix'] + '_benchmark/watermark.json'
        self.manifest = {'recipe_id': aws.RECIPE, 'targets': [{'target_id': 'sandbox', 'kind': 'aws', 'identity': self.identity}],
                         'executor': {'transport': 'aws_cli', 'executable': self.binary, 'script_sha256': None,
                                      'environment_names': [], 'config': self.config},
                         'collectors': [self.collector],
                         'limits': {'max_phase_seconds': 30, 'max_export_bytes': 1024 * 1024, 'max_cloud_cost_usd': 5,
                                    'latest_cleanup_utc': '2099-01-01T00:00:00+00:00'}}
        self.context = {'private_root': str(self.private), 'aws_correlation_id': '11111111-2222-4333-8444-555555555555',
                        'authorization_expires_utc': '2099-01-01T00:00:00+00:00'}
        name = 'stratus-red-team-ct-stop-11111111-trail'
        self.resources = {'trail_arn': 'arn:aws:cloudtrail:us-east-1:123456789012:trail/' + name,
                          'trail_name': name, 'bucket': 'stratus-red-team-ct-stop-11111111-bucket'}
        self.state = {'version': 4, 'outputs': {'cloudtrail_trail_name': {'value': self.resources['trail_name']}},
                      'resources': [
                          {'mode': 'managed', 'type': 'aws_cloudtrail', 'name': 'trail', 'instances': [{'attributes': {
                              'name': self.resources['trail_name'], 'arn': self.resources['trail_arn'], 's3_bucket_name': self.resources['bucket']}}]},
                          {'mode': 'managed', 'type': 'aws_s3_bucket', 'name': 'cloudtrail', 'instances': [{'attributes': {
                              'bucket': self.resources['bucket'], 'arn': 'arn:aws:s3:::' + self.resources['bucket']}}]}]}
        self.transport = ScriptedTransport(self)
        self.transport.objects[collector_config['watermark_key']] = canonical_bytes({
            'schema_version': 1, 'window_utc': self.collector['window_utc'],
            'watermark_utc': self.collector['watermark_utc']})
        self.environment_patch = mock.patch.object(aws, '_environment', return_value={'HOME': str(self.home), 'TF_PLUGIN_CACHE_DIR': '', 'AWS_PROFILE': 'fixture'})
        self.environment_patch.start()
        self.addCleanup(self.environment_patch.stop)

    def pin(self, name, data, version=None):
        path = self.home / name
        path.write_bytes(data)
        result = {'path': str(path), 'sha256': hashlib.sha256(data).hexdigest()}
        if version is not None:
            result['version'] = version
        return result

    def write_state(self):
        root = self.home / '.stratus-red-team' / aws.TECHNIQUE / self.context['aws_correlation_id']
        root.mkdir(parents=True, exist_ok=True)
        (root / 'terraform.tfstate').write_bytes(canonical_bytes(self.state))
        return root

    def execute(self, phase, step):
        result = aws.execute_step(self.manifest, None, phase, step, self.context, self.transport)
        self.context.update(result['context_updates'])
        return result

    def warmup(self):
        result = self.execute('run', 'warmup')
        self.assertEqual('succeeded', result['execution_outcome'], result)
        return result

    def detonate(self):
        self.warmup()
        result = self.execute('run', 'detonate')
        self.assertEqual('succeeded', result['execution_outcome'], result)
        return result

    def collect(self):
        self.context['collector'] = self.collector
        self.transport.arn = 'arn:aws:sts::123456789012:assumed-role/Reader/fixture-session'
        return self.execute('collect', self.collector['source_id'])

    def event(self, identifier='event-one', **changes):
        value = {'eventVersion': '1.09', 'eventID': identifier, 'eventTime': '2026-01-01T12:00:00Z',
                 'eventSource': 'cloudtrail.amazonaws.com', 'eventName': 'StopLogging',
                 'recipientAccountId': '123456789012', 'awsRegion': 'us-east-1',
                 'requestParameters': {'name': self.resources['trail_arn']}}
        value.update(changes)
        return value

    def object(self, name, records):
        key = self.collector['prefix'] + '2026/01/01/' + name + '.json.gz'
        self.transport.objects[key] = gzip.compress(canonical_bytes({'Records': records}), mtime=0)
        return key


class AWSDriverTests(AWSFixture):
    def test_offline_schema_and_fixed_steps(self):
        aws.validate_configuration(self.manifest)
        self.assertEqual(['warmup', 'detonate'], aws.phase_steps(self.manifest, 'run', {}))
        self.assertEqual([], self.transport.calls)
        self.config['command'] = 'forbidden'
        with self.assertRaises(BenchmarkError):
            aws.validate_configuration(self.manifest)

    def test_wrong_source_commit_is_blocked(self):
        self.config['source_commit'] = '0' * 40
        result = self.execute('preflight', 'identity')
        self.assertEqual('unsupported_tool_version', result['evidence']['failure_reason'])
        self.assertEqual([], self.transport.calls)

    def test_changed_binary_is_blocked_before_execution(self):
        Path(self.binary['path']).write_bytes(b'changed')
        result = self.execute('run', 'warmup')
        self.assertEqual('executable_hash_mismatch', result['evidence']['failure_reason'])
        self.assertEqual([], self.transport.calls)

    def test_wrong_account_and_root_are_rejected(self):
        self.transport.account = '999999999999'
        result = self.execute('run', 'warmup')
        self.assertEqual('target_identity_mismatch', result['evidence']['failure_reason'])
        self.assertFalse(any(call[0][0] == self.config['stratus']['path'] for call in self.transport.calls))
        self.transport.account = self.identity['account_id']
        self.transport.arn = 'arn:aws:iam::123456789012:root'
        result = self.execute('run', 'warmup')
        self.assertEqual('target_identity_mismatch', result['evidence']['failure_reason'])

    def test_expired_or_missing_authority_never_dispatches(self):
        self.context['authorization_expires_utc'] = '2000-01-01T00:00:00Z'
        self.assertEqual('authorization_expired', self.execute('run', 'warmup')['evidence']['failure_reason'])
        self.assertEqual([], self.transport.calls)
        self.context.pop('authorization_expires_utc')
        self.assertEqual('authorization_required', self.execute('run', 'warmup')['evidence']['failure_reason'])

    def test_real_effect_queries_and_exact_commands(self):
        self.detonate()
        actions = [argv for argv, _ in self.transport.calls if argv[0] == self.config['stratus']['path']]
        self.assertEqual([[self.config['stratus']['path'], action, aws.TECHNIQUE] for action in ('warmup', 'status', 'detonate', 'status')], actions)
        self.assertEqual(2, sum(argv[1:3] == ['sts', 'get-caller-identity'] for argv, _ in self.transport.calls))
        environments = [options['env'] for _, options in self.transport.calls]
        self.assertTrue(all(value == environments[0] for value in environments))
        self.assertEqual('', environments[0]['TF_PLUGIN_CACHE_DIR'])
        self.assertNotIn('STRATUS_HOME', environments[0])
        self.assertTrue(self.context['aws_stop_verified'])

    def test_exit_zero_without_stop_effect_is_unknown(self):
        self.warmup()
        self.transport.no_stop_effect = True
        result = self.execute('run', 'detonate')
        self.assertEqual('unknown', result['execution_outcome'])
        self.assertFalse(result['effect_verified'])
        self.assertEqual('effect_not_verified', result['evidence']['failure_reason'])
        self.assertEqual({}, result['context_updates'])

    def test_unknown_detonation_is_not_retried_and_records_no_effect(self):
        # Controller quarantine (unknown row) blocks all later dispatch; the
        # driver itself never retries and reports no verified context.
        self.warmup()
        self.transport.unknown_detonate = True
        result = self.execute('run', 'detonate')
        self.assertEqual('unknown', result['execution_outcome'])
        self.assertEqual('transport_unknown', result['evidence']['failure_reason'])
        self.assertEqual({}, result['context_updates'])
        self.assertEqual(1, sum(argv[1:2] == ['detonate'] for argv, _ in self.transport.calls))
        self.assertNotIn('aws_stop_verified', self.context)

    def test_reconciled_unknown_warmup_allows_only_verified_cleanup(self):
        root = self.write_state()
        resources = dict(self.resources, state_sha256=hashlib.sha256((root / 'terraform.tfstate').read_bytes()).hexdigest())
        driver_evidence = {'aws_resources': resources, 'aws_target_logging': True}
        observation = dict(driver_evidence,
                           observed_target_sha256=hashlib.sha256(canonical_bytes(self.manifest['targets'])).hexdigest(),
                           effect_verified=True, source_receipt_sha256=hashlib.sha256(canonical_bytes(driver_evidence)).hexdigest(),
                           observed_utc='2026-01-01T00:00:00Z')
        self.context.update(reconciled_steps=[
            {'phase': 'run', 'step_id': 'warmup', 'outcome': 'failed', 'observation': observation}])
        self.transport.retention = True
        self.assertEqual('state_already_exists', self.execute('run', 'warmup')['evidence']['failure_reason'])
        self.assertFalse(any(argv[1:2] == ['warmup'] for argv, _ in self.transport.calls))
        result = self.execute('cleanup', 'cleanup')
        self.assertEqual('succeeded', result['execution_outcome'], result)
        self.assertTrue(self.context['aws_cleanup_verified'])

    def test_state_and_available_provider_lock_are_preserved_privately(self):
        self.warmup()
        root = self.write_state()
        lock = b'# invented provider lock fixture'
        (root / '.terraform.lock.hcl').write_bytes(lock)
        result = self.execute('run', 'detonate')
        self.assertEqual('succeeded', result['execution_outcome'], result)
        digest = hashlib.sha256(lock).hexdigest()
        self.assertEqual(digest, self.context['aws_terraform_lock_sha256'])
        self.assertEqual(lock, (self.private / ('aws-terraform-lock-' + digest + '.bin')).read_bytes())

    def test_changed_state_cannot_detonate(self):
        self.warmup()
        self.state['serial'] = 2
        self.write_state()
        result = self.execute('run', 'detonate')
        self.assertEqual('resource_identity_mismatch', result['evidence']['failure_reason'])
        self.assertFalse(any(argv[1:2] == ['detonate'] for argv, _ in self.transport.calls))

    def test_ambiguous_or_wrong_resource_address_quarantines_warmup(self):
        self.state['resources'][0]['name'] = 'unexpected'
        result = self.execute('run', 'warmup')
        self.assertEqual('unknown', result['execution_outcome'])
        self.assertEqual('resource_identity_mismatch', result['evidence']['failure_reason'])

    def test_cleanup_requires_independent_export_or_durable_retention(self):
        self.detonate()
        result = self.execute('cleanup', 'cleanup')
        self.assertEqual('independent_export_required', result['evidence']['failure_reason'])
        self.assertFalse(self.transport.deleted)
        self.transport.retention = True
        result = self.execute('cleanup', 'cleanup')
        self.assertEqual('succeeded', result['execution_outcome'], result)
        self.assertTrue(result['evidence']['owned_bucket_absent'])
        self.assertTrue(result['evidence']['owned_trail_absent'])

    def test_cold_cleanup_output_does_not_prove_bucket_absence(self):
        self.detonate()
        self.context['aws_stop_exported'] = True
        self.transport.keep_bucket = True
        result = self.execute('cleanup', 'cleanup')
        self.assertEqual('unknown', result['execution_outcome'])
        self.assertEqual('cleanup_not_verified', result['evidence']['failure_reason'])

    def test_trail_presence_after_cleanup_is_unknown(self):
        self.detonate()
        self.context['aws_stop_exported'] = True
        self.transport.keep_trail = True
        result = self.execute('cleanup', 'cleanup')
        self.assertEqual('unknown', result['execution_outcome'])
        self.assertEqual('cleanup_not_verified', result['evidence']['failure_reason'])

    def test_correlation_short_id_is_bound_to_owned_names(self):
        self.state['resources'][0]['instances'][0]['attributes']['name'] = 'unrelated-trail'
        result = self.execute('run', 'warmup')
        self.assertEqual('unknown', result['execution_outcome'])
        self.assertEqual('resource_identity_mismatch', result['evidence']['failure_reason'])

    def test_baseline_failure_blocks_before_mutation(self):
        self.transport.baseline_logging = False
        result = self.execute('run', 'warmup')
        self.assertEqual('baseline_not_logging', result['evidence']['failure_reason'])
        self.assertFalse(any(argv[0] == self.config['stratus']['path'] for argv, _ in self.transport.calls))


class AWSCollectorTests(AWSFixture):
    def test_full_pagination_gzip_window_and_deduplication(self):
        self.detonate()
        first = self.object('first', [self.event(), self.event('outside', eventTime='2025-12-31T23:59:59Z')])
        second = self.object('second', [self.event(), self.event('second', eventName='GetTrailStatus')])
        self.transport.pages = [
            {'IsTruncated': True, 'NextContinuationToken': 'page-two', 'Contents': [self.transport.object_entry(first)]},
            {'IsTruncated': False, 'Contents': [self.transport.object_entry(first), self.transport.object_entry(second)]}]
        result = self.collect()
        self.assertEqual('succeeded', result['execution_outcome'], result)
        from benchmark_evidence import supported_cloudtrail_events
        allowed = supported_cloudtrail_events()
        self.assertIn('StopLogging', allowed)
        names = {'event-one': 'StopLogging', 'second': 'GetTrailStatus'}
        self.assertEqual([key for key in ('event-one', 'second') if names[key] in allowed],
                         [record['eventID'] for record in result['raw_exports'][0]['records']])
        self.assertEqual({'event_names': allowed}, result['raw_exports'][0]['filter'])
        self.assertEqual(sum(names[key] not in allowed for key in names), result['evidence']['filtered_record_count'])
        self.assertTrue(self.context['aws_stop_exported'])
        downloads = [argv for argv, _ in self.transport.calls
                     if argv[1:3] == ['s3api', 'get-object'] and argv[argv.index('--key') + 1].endswith('.json.gz')]
        self.assertEqual(2, len(downloads))
        self.assertTrue(all('--if-match' in argv and '--range' in argv for argv in downloads))
        self.assertNotIn('Records', result['evidence'])

    def test_collector_read_identity_is_distinct(self):
        self.object('first', [self.event()])
        self.context['collector'] = self.collector
        result = self.execute('collect', 'cloudtrail')
        self.assertEqual('target_identity_mismatch', result['evidence']['failure_reason'])

    def test_readiness_does_not_require_future_watermark(self):
        self.collector['watermark_utc'] = None
        self.transport.objects[self.collector['config']['watermark_key']] = canonical_bytes({
            'schema_version': 1, 'window_utc': self.collector['window_utc'], 'watermark_utc': None})
        self.context['collector'] = self.collector
        self.transport.arn = 'arn:aws:sts::123456789012:assumed-role/Reader/fixture-session'
        result = self.execute('preflight', 'cloudtrail')
        self.assertEqual('succeeded', result['execution_outcome'], result)
        self.assertEqual([], result['raw_exports'])

    def test_oversized_gzip_is_not_silently_truncated(self):
        self.collector['max_bytes'] = 2048
        self.object('large', [self.event(extra='x' * 100000)])
        result = self.collect()
        self.assertEqual('output_limit', result['evidence']['failure_reason'])
        self.assertFalse(result['effect_verified'])

    def test_gzip_trailing_members_rejected(self):
        data = gzip.compress(b'{}') + gzip.compress(b'{}')
        with self.assertRaises(BenchmarkError) as caught:
            aws._inflate(data, 100)
        self.assertEqual('invalid_gzip', caught.exception.code)

    def test_out_of_prefix_object_is_rejected(self):
        key = self.object('first', [self.event()])
        item = self.transport.object_entry(key)
        item['Key'] = 'another-account/first.json.gz'
        self.transport.pages = [{'IsTruncated': False, 'Contents': [item]}]
        self.assertEqual('object_outside_window', self.collect()['evidence']['failure_reason'])

    def test_repeated_pagination_token_is_rejected(self):
        key = self.object('first', [self.event()])
        self.transport.pages = [{'IsTruncated': True, 'NextContinuationToken': 'same', 'Contents': [self.transport.object_entry(key)]}] * 2
        self.assertEqual('invalid_pagination', self.collect()['evidence']['failure_reason'])

    def test_missing_watermark_is_incomplete_not_negative(self):
        self.collector['watermark_utc'] = None
        self.transport.objects.pop(self.collector['config']['watermark_key'])
        self.collector['config']['poll_seconds'] = 60
        result = self.collect()
        self.assertEqual('incomplete_export', result['evidence']['failure_reason'])
        self.assertFalse(result['effect_verified'])
        self.assertFalse(result['raw_exports'][0]['complete'])
        self.assertIsNone(result['raw_exports'][0]['watermark_utc'])
        self.assertTrue(result['context_updates']['aws_raw_preserved'])

    def test_failed_stoplogging_event_not_effect_proof(self):
        self.detonate()
        self.object('blocked', [self.event(errorCode='AccessDenied')])
        self.collector['config']['poll_seconds'] = 60
        result = self.collect()
        self.assertEqual('incomplete_export', result['evidence']['failure_reason'])
        self.assertNotIn('aws_stop_exported', self.context)

    def test_unhealthy_baseline_during_collection_quarantines(self):
        self.detonate()
        self.object('first', [self.event()])
        self.transport.baseline_logging = False
        result = self.collect()
        self.assertEqual('unknown', result['execution_outcome'])
        self.assertEqual('baseline_not_logging', result['evidence']['failure_reason'])
        self.assertFalse(result['effect_verified'])

    def test_hard_linked_executable_pin_accepted_but_not_config_file(self):
        linked = self.home / 'linked-aws'
        os.link(self.binary['path'], linked)
        aws._verify_pin(dict(self.binary, path=str(linked)), True)
        with self.assertRaises(BenchmarkError) as caught:
            aws._verify_pin(dict(self.binary, path=str(linked)))
        self.assertEqual('unsafe_file', caught.exception.code)


    def test_future_observed_watermark_never_proves_completeness(self):
        self.transport.objects[self.collector['config']['watermark_key']] = canonical_bytes({
            'schema_version': 1, 'window_utc': self.collector['window_utc'],
            'watermark_utc': '2099-01-01T00:00:00Z'})
        result = self.collect()
        self.assertEqual('future_watermark', result['evidence']['failure_reason'])
        self.assertFalse(result['effect_verified'])

    def test_incomplete_snapshot_preserves_actual_records(self):
        self.object('first', [self.event()])
        self.transport.objects[self.collector['config']['watermark_key']] = canonical_bytes({
            'schema_version': 1, 'window_utc': self.collector['window_utc'],
            'watermark_utc': '2026-01-01T13:00:00Z'})
        self.collector['config']['poll_seconds'] = 60
        result = self.collect()
        self.assertEqual('blocked', result['execution_outcome'])
        self.assertEqual('incomplete_export', result['evidence']['failure_reason'])
        self.assertEqual(1, len(result['raw_exports'][0]['records']))
        self.assertEqual('2026-01-01T13:00:00Z', result['raw_exports'][0]['watermark_utc'])


class AWSEnvironmentTests(unittest.TestCase):
    def test_ambient_keys_and_endpoints_rejected_before_home_access(self):
        for name in ('AWS_ACCESS_KEY_ID', 'AWS_CONTAINER_CREDENTIALS_FULL_URI', 'AWS_ENDPOINT_URL', 'AWS_WEB_IDENTITY_TOKEN_FILE', 'STRATUS_HOME'):
            with self.subTest(name=name), mock.patch.dict(os.environ, {name: 'fixture'}, clear=True):
                with self.assertRaises(BenchmarkError) as caught:
                    aws._environment({}, {})
                self.assertEqual('ambient_credentials_or_override', caught.exception.code)

    def test_unsafe_pin_extensions_and_paths(self):
        with self.assertRaises(BenchmarkError):
            aws._pin({'path': str(Path.cwd() / 'unsafe.cmd'), 'sha256': '0' * 64, 'version': 'fixture'}, True)
        with self.assertRaises(BenchmarkError):
            aws._pin({'path': 'relative', 'sha256': '0' * 64})


if __name__ == '__main__':
    unittest.main()

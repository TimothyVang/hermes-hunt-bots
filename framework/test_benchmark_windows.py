"""Offline driver contracts; fixture transports never start Hyper-V or PowerShell."""
import copy
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import benchmark_windows as windows
from benchmark_contracts import BenchmarkError, canonical_bytes, decode_json, digest_bytes


def manifest():
    executable = {'path': r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe',
                  'sha256': 'a' * 64, 'version': '5.1.26100.1'}
    return {
        'recipe_id': 'windows-discovery-v1',
        'targets': [{'target_id': 'guest', 'kind': 'windows', 'display_id': 'asset-a',
                     'identity': {'vm_id': '11111111-1111-4111-8111-111111111111',
                                  'machine_guid': '22222222-2222-4222-8222-222222222222',
                                  'computer_name': 'LABMEMBER', 'domain': 'lab.test',
                                  'synthetic_account': None, 'internal_endpoint': None}}],
        'executor': {'transport': 'powershell_direct', 'executable': executable,
                     'script_sha256': digest_bytes(b'# inert fixture'),
                     'environment_names': list(windows.ACTION_ENV), 'config': {}},
        'collectors': [],
        'limits': {'max_phase_seconds': 60, 'max_export_bytes': 65536},
    }


def collector(value):
    return {'source_id': 'events', 'kind': 'windows', 'target_id': 'guest',
            'export_root': None, 'bucket': None, 'prefix': None,
            'window_utc': {'start_inclusive': '2025-01-01T00:00:00.000000Z', 'end_exclusive': '2025-01-01T01:00:00.000000Z'},
            'watermark_utc': '2025-01-01T01:00:00.000000Z', 'max_bytes': 32768, 'max_seconds': 30,
            'config': {'executable': copy.deepcopy(value['executor']['executable']),
                       'script_sha256': value['executor']['script_sha256'],
                       'environment_names': list(windows.COLLECTOR_ENV),
                       'channels': ['Security'], 'evtx_files': [], 'require_process_events': False}}


def receipt():
    return {'schema_version': 1, 'execution_outcome': 'succeeded', 'identity_verified': True,
            'action_exits': {}, 'effect_checks': {'identity': True, 'session_cleanup': True},
            'gaps': [], 'records': [], 'complete': False, 'session_closed': True,
            'watermark_utc': None, 'failure_reason': None, 'leftovers': None}


def session_check(process_ids=(), sessions=0):
    response = receipt()
    response['effect_checks']['no_owned_leftovers'] = not process_ids
    response['leftovers'] = {'process_count': len(process_ids), 'session_count': sessions,
                             'process_ids': list(process_ids)}
    if process_ids:
        response.update(execution_outcome='failed', failure_reason='owned_leftovers_found')
    return response


# The executor kit is separately supplied and intentionally not bundled (see benchmarks/README.md).
KIT_WORKER = Path(__file__).resolve().parent.parent / 'hunt-range' / 'benchmark' / windows.WORKER

class WindowsConfigurationTests(unittest.TestCase):
    def test_only_fixed_actions_are_selected(self):
        value = manifest()
        windows.validate_configuration(value)
        self.assertEqual(windows.phase_steps(value, 'preflight', {}), ['identity'])
        self.assertEqual(windows.phase_steps(value, 'run', {}), ['windows-discovery-v1'])
        self.assertEqual(windows.phase_steps(value, 'cleanup', {}), ['session_check'])
        with self.assertRaises(BenchmarkError):
            windows.build_request(value, 'run', 'whoami /all; anything', {})
        value['executor']['config']['command'] = 'anything'
        with self.assertRaises(BenchmarkError):
            windows.validate_configuration(value)

    def test_request_contains_enrollment_not_commands_or_credentials(self):
        value = manifest()
        request = windows.build_request(value, 'run', value['recipe_id'], {})
        self.assertEqual(set(request), {'schema_version', 'operation', 'identity', 'powershell_version', 'max_seconds', 'max_bytes', 'collector', 'since_utc'})
        self.assertIsNone(request['since_utc'])
        self.assertEqual(request['identity'], value['targets'][0]['identity'])
        self.assertNotIn('BENCH_GUEST_PASSWORD', canonical_bytes(request).decode())
        self.assertIsNone(request['collector'])

    def test_machine_and_vm_guids_are_canonical(self):
        for key in ('vm_id', 'machine_guid'):
            for invalid in ('host-name', '{11111111-1111-4111-8111-111111111111}', None):
                with self.subTest(key=key, value=invalid):
                    value = manifest()
                    value['targets'][0]['identity'][key] = invalid
                    with self.assertRaises(BenchmarkError):
                        windows.validate_configuration(value)

    def test_unknown_identity_and_multiple_targets_rejected(self):
        value = manifest()
        value['targets'][0]['identity']['credential'] = 'not-allowed'
        with self.assertRaises(BenchmarkError):
            windows.validate_configuration(value)
        value = manifest()
        value['targets'].append(copy.deepcopy(value['targets'][0]))
        with self.assertRaises(BenchmarkError):
            windows.validate_configuration(value)

    def test_ad_requires_single_enrolled_account(self):
        value = manifest()
        value['recipe_id'] = 'ad-discovery-v1'
        with self.assertRaises(BenchmarkError):
            windows.validate_configuration(value)
        value['targets'][0]['identity']['synthetic_account'] = {'sam_account_name': 'synthetic-user', 'sid': 'S-1-5-21-1-2-3-1001'}
        with self.assertRaises(BenchmarkError):
            windows.validate_configuration(value)
        value['targets'][0]['identity']['domain_controller'] = True
        windows.validate_configuration(value)
        request = windows.build_request(value, 'run', 'ad-discovery-v1', {})
        self.assertNotIn('domain_controller', request['identity'])
        value['targets'][0]['identity']['synthetic_account']['filter'] = '*'
        with self.assertRaises(BenchmarkError):
            windows.validate_configuration(value)

    def test_dns_requires_exact_endpoint_and_no_url_or_query(self):
        value = manifest()
        value['recipe_id'] = 'internal-dns-http-v1'
        endpoint = {'label': 'benign', 'zone': 'lab.test', 'addresses': ['192.0.2.20'], 'port': 8080, 'path': '/health'}
        value['targets'][0]['identity']['internal_endpoint'] = endpoint
        windows.validate_configuration(value)
        for key, invalid in (('path', '/health?secret=value'), ('path', '/../../outside'), ('zone', 'https://lab.test'), ('addresses', ['127.0.0.1']), ('addresses', ['8.8.8.8']), ('addresses', ['192.0.2.20', '192.0.2.20']), ('port', True)):
            changed = copy.deepcopy(value)
            changed['targets'][0]['identity']['internal_endpoint'][key] = invalid
            with self.subTest(key=key, invalid=invalid), self.assertRaises(BenchmarkError):
                windows.validate_configuration(changed)

    def test_executable_and_environment_pins(self):
        for field, invalid in (('path', r'C:\tmp\launch.cmd'), ('path', r'\\server\powershell.exe'), ('version', '7.5.0'), ('sha256', 'x' * 64)):
            value = manifest()
            value['executor']['executable'][field] = invalid
            with self.subTest(field=field), self.assertRaises(BenchmarkError):
                windows.validate_configuration(value)
        value = manifest()
        value['executor']['environment_names'].append('AWS_SECRET_ACCESS_KEY')
        with self.assertRaises(BenchmarkError):
            windows.validate_configuration(value)

    def test_limits_are_positive_bounded_and_not_booleans(self):
        for name in ('max_phase_seconds', 'max_export_bytes'):
            for invalid in (0, -1, True):
                value = manifest()
                value['limits'][name] = invalid
                with self.subTest(name=name, invalid=invalid), self.assertRaises(BenchmarkError):
                    windows.build_request(value, 'run', value['recipe_id'], {})
        value = manifest()
        value['limits']['max_phase_seconds'] = 3601
        with self.assertRaises(BenchmarkError):
            windows.build_request(value, 'run', value['recipe_id'], {})

    def test_only_allowlisted_collector_channels(self):
        value = manifest()
        source = collector(value)
        windows.validate_collector(value, source)
        for invalid in (['Application'], ['Security', 'Security'], ['*'], 'Security', [None]):
            source['config']['channels'] = invalid
            with self.subTest(channels=invalid), self.assertRaises(BenchmarkError):
                windows.validate_collector(value, source)

    def test_evtx_copies_are_exact_confined_hashes(self):
        value = manifest()
        source = collector(value)
        source['export_root'] = r'C:\sealed'
        source['config']['channels'] = []
        source['config']['evtx_files'] = [{'path': r'C:\sealed\security.evtx', 'sha256': 'b' * 64, 'channel': 'Security'}]
        windows.validate_collector(value, source)
        for path in (r'C:\outside\security.evtx', r'C:\sealed\..\outside.evtx', r'C:\sealed\wrong.txt'):
            source['config']['evtx_files'][0]['path'] = path
            with self.subTest(path=path), self.assertRaises(BenchmarkError):
                windows.validate_collector(value, source)

    def test_collector_uses_own_pins_and_event_filter(self):
        value = manifest()
        source = collector(value)
        source['config']['executable']['sha256'] = 'c' * 64
        value['collectors'] = [source]
        windows.validate_configuration(value)
        request = windows.build_request(value, 'collect', 'events', {'collector': source})
        self.assertEqual(request['operation'], 'collect')
        self.assertEqual(request['max_bytes'], 32768)
        self.assertEqual(request['max_seconds'], 30)
        from benchmark_evidence import supported_event_ids
        self.assertEqual(request['collector']['event_ids'], {'Security': supported_event_ids('Security')})
        probe = windows.build_request(value, 'preflight', 'events', {'collector': source})
        self.assertEqual(probe['operation'], 'collector_probe')
        self.assertEqual(probe['collector']['channels'], ['Security'])

    def test_session_check_carries_clock_widened_campaign_start(self):
        value = manifest()
        value['targets'][0]['clock'] = {'offset_seconds': -5, 'uncertainty_seconds': 2, 'checked_utc': '2026-11-03T09:00:00Z'}
        request = windows.build_request(value, 'cleanup', 'session_check',
                                        {'campaign_started_utc': '2026-11-03T10:00:00+00:00'})
        self.assertEqual(request['operation'], 'session_check')
        self.assertEqual(request['since_utc'], '2026-11-03T09:59:53.000000Z')
        with self.assertRaises(BenchmarkError):
            windows.build_request(value, 'cleanup', 'session_check', {})


class WindowsReceiptTests(unittest.TestCase):
    def dispatch_fixture(self, value, response, phase='preflight', step='identity', context=None, transport_status='succeeded'):
        """Explicit inert fixture boundary; this is not live driver verification."""
        calls = []
        def transport(argv, **kwargs):
            calls.append((argv, kwargs))
            return {'status': transport_status, 'exit_code': 0 if transport_status == 'succeeded' else None,
                    'stdout': canonical_bytes(response), 'failure_reason': None, 'process_identity': None}
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, windows.WORKER).write_bytes(b'# inert fixture')
            with mock.patch.object(windows, '_verified_local', return_value='pinned-powershell.exe'), mock.patch.object(windows, '_environment', return_value={'fixture': 'no-credentials'}):
                result = windows.execute_step(value, directory, phase, step, context or {}, transport)
        return result, calls

    def test_transport_is_fixed_argv_and_stdin(self):
        value = manifest()
        result, calls = self.dispatch_fixture(value, receipt())
        self.assertEqual(result['execution_outcome'], 'succeeded')
        self.assertTrue(result['effect_verified'])
        self.assertEqual(len(calls), 1)
        argv, kwargs = calls[0]
        self.assertEqual(argv[1:7], ['-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File'])
        self.assertEqual(result['evidence']['transport_exit'], 0)
        self.assertEqual(decode_json(kwargs['input_bytes'])['identity'], value['targets'][0]['identity'])
        self.assertEqual(kwargs['env'], {'fixture': 'no-credentials'})
        self.assertEqual(result['raw_exports'], [])
        self.assertIn('process_instrumentation_absent', result['evidence']['gaps'])

    def test_identity_mismatch_cannot_be_effect_success(self):
        response = receipt()
        response.update(execution_outcome='blocked', identity_verified=False, effect_checks={}, failure_reason='identity_mismatch')
        result, calls = self.dispatch_fixture(manifest(), response)
        self.assertEqual(result['execution_outcome'], 'blocked')
        self.assertFalse(result['effect_verified'])
        self.assertIsNone(result['observed_target_sha256'])
        self.assertEqual(len(calls), 1)

    def test_exit_success_without_all_effects_is_unknown(self):
        response = receipt()
        response['effect_checks'] = {'identity': True}
        result, _ = self.dispatch_fixture(manifest(), response)
        self.assertEqual(result['execution_outcome'], 'unknown')
        self.assertFalse(result['effect_verified'])

    def test_run_requires_independent_output_checks_and_exits(self):
        response = receipt()
        response['action_exits'] = {'whoami': 0, 'hostname': 0, 'processes': 0}
        response['effect_checks'].update(whoami_identity=True, hostname_identity=True, process_snapshot=True)
        result, _ = self.dispatch_fixture(manifest(), response, 'run', 'windows-discovery-v1')
        self.assertTrue(result['effect_verified'])
        response['effect_checks']['hostname_identity'] = False
        result, _ = self.dispatch_fixture(manifest(), response, 'run', 'windows-discovery-v1')
        self.assertEqual(result['execution_outcome'], 'unknown')

    def test_unknown_transport_never_retries_or_exports(self):
        result, calls = self.dispatch_fixture(manifest(), receipt(), transport_status='unknown')
        self.assertEqual(result['execution_outcome'], 'unknown')
        self.assertEqual(len(calls), 1)
        self.assertEqual(result['raw_exports'], [])

    def test_unrecognized_worker_fields_never_reach_evidence(self):
        response = receipt()
        response['stderr'] = 'authentication material'
        result, _ = self.dispatch_fixture(manifest(), response)
        self.assertEqual(result['execution_outcome'], 'unknown')
        self.assertNotIn('authentication material', canonical_bytes(result).decode())

    def test_partial_independent_snapshot_survives_before_cleanup(self):
        value = manifest()
        source = collector(value)
        response = receipt()
        response.update(execution_outcome='failed', failure_reason='incomplete_export', watermark_utc='2025-01-01T00:30:00.000000Z', gaps=['incomplete_export'])
        response['effect_checks']['collector_read'] = True
        response['records'] = [{'channel': 'Security', 'provider': 'fixture-provider', 'record_id': 1,
                                'event_id': 4688, 'timestamp_utc': '2025-01-01T00:10:00.123456Z', 'xml': '<Event />'}]
        result, _ = self.dispatch_fixture(value, response, 'collect', 'events', {'collector': source})
        self.assertEqual(result['execution_outcome'], 'failed')
        self.assertEqual(len(result['raw_exports']), 1)
        self.assertFalse(result['raw_exports'][0]['complete'])
        self.assertEqual(result['raw_exports'][0]['watermark_utc'], response['watermark_utc'])
        self.assertEqual(result['raw_exports'][0]['filter'], {'event_ids': windows.event_filter(source['config'])})
        self.assertNotIn('xml', canonical_bytes(result['evidence']).decode())

    def test_complete_export_requires_watermark(self):
        value = manifest()
        source = collector(value)
        response = receipt()
        response['complete'] = True
        response['effect_checks']['collector_read'] = True
        result, _ = self.dispatch_fixture(value, response, 'collect', 'events', {'collector': source})
        self.assertEqual(result['execution_outcome'], 'unknown')
        self.assertFalse(result['raw_exports'])
        response['watermark_utc'] = '2025-01-01T01:00:00.000000Z'
        result, _ = self.dispatch_fixture(value, response, 'collect', 'events', {'collector': source})
        self.assertEqual(result['execution_outcome'], 'succeeded')
        self.assertTrue(result['raw_exports'][0]['complete'])

    def test_collect_rejects_unconfigured_window_records(self):
        value = manifest()
        source = collector(value)
        response = receipt()
        response.update(complete=True, watermark_utc='2025-01-01T01:00:00.000000Z')
        response['effect_checks']['collector_read'] = True
        response['records'] = [{'channel': 'Security', 'provider': 'fixture', 'record_id': 1,
                                'event_id': 4688, 'timestamp_utc': '2025-01-02T00:00:00.000000Z', 'xml': '<Event />'}]
        result, _ = self.dispatch_fixture(value, response, 'collect', 'events', {'collector': source})
        self.assertEqual(result['execution_outcome'], 'unknown')
        self.assertFalse(result['raw_exports'])

    def test_collect_rejects_filtered_out_and_duplicate_records(self):
        value = manifest()
        source = collector(value)
        record = {'channel': 'Security', 'provider': 'fixture', 'record_id': 1,
                  'event_id': 4688, 'timestamp_utc': '2025-01-01T00:10:00.000000Z', 'xml': '<Event />'}
        for records in ([dict(record, event_id=65000)], [record, dict(record)]):
            response = receipt()
            response.update(complete=True, watermark_utc='2025-01-01T01:00:00.000000Z', records=records)
            response['effect_checks']['collector_read'] = True
            with self.subTest(records=len(records)):
                result, _ = self.dispatch_fixture(value, response, 'collect', 'events', {'collector': source})
                self.assertEqual(result['execution_outcome'], 'unknown')
                self.assertFalse(result['raw_exports'])
        # Same channel:record_id with different XML (record-ID reset) is two records.
        response = receipt()
        response.update(complete=True, watermark_utc='2025-01-01T01:00:00.000000Z',
                        records=[record, dict(record, xml='<Event><System /></Event>')])
        response['effect_checks']['collector_read'] = True
        result, _ = self.dispatch_fixture(value, response, 'collect', 'events', {'collector': source})
        self.assertEqual(result['execution_outcome'], 'succeeded')
        self.assertEqual(len(result['raw_exports'][0]['records']), 2)

    @unittest.skipUnless(KIT_WORKER.is_file(), 'separate range kit is intentionally not bundled')
    def test_worker_emits_six_digit_utc_and_driver_parses_it(self):
        script = KIT_WORKER.read_text(encoding='utf-8')
        self.assertIn("yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'", script)
        self.assertNotIn("ToString('o')", script)
        # The old 7-digit worker form and the 6-digit form denote the same microsecond.
        self.assertEqual(windows._timestamp('2026-11-02T10:00:00.1234567+00:00'),
                         windows._timestamp('2026-11-02T10:00:00.123456Z'))
        value = manifest()
        source = collector(value)
        response = receipt()
        response.update(complete=True, watermark_utc='2025-01-01T01:00:00.000000Z')
        response['effect_checks']['collector_read'] = True
        response['records'] = [{'channel': 'Security', 'provider': 'fixture', 'record_id': 7,
                                'event_id': 4688, 'timestamp_utc': '2025-01-01T00:59:59.999999Z', 'xml': '<Event />'}]
        result, _ = self.dispatch_fixture(value, response, 'collect', 'events', {'collector': source})
        self.assertEqual(result['execution_outcome'], 'succeeded')

    def test_unclosed_session_is_unknown(self):
        response = receipt()
        response.update(session_closed=False, execution_outcome='failed', failure_reason='session_cleanup_failed')
        response['effect_checks']['session_cleanup'] = False
        result, _ = self.dispatch_fixture(manifest(), response)
        self.assertEqual(result['execution_outcome'], 'unknown')
        self.assertFalse(result['effect_verified'])

    def test_pre_transport_failure_is_blocked_without_launch(self):
        calls = []
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, windows.WORKER).write_bytes(b'# inert fixture')
            with mock.patch.object(windows, '_verified_local', side_effect=BenchmarkError('digest_mismatch', 'windows.executable')):
                result = windows.execute_step(manifest(), directory, 'preflight', 'identity', {}, lambda *a, **k: calls.append(a))
            self.assertEqual(result['execution_outcome'], 'blocked')
            with mock.patch.object(windows, '_verified_local', return_value='pinned-powershell.exe'), \
                    mock.patch.object(windows, '_environment', side_effect=BenchmarkError('missing_credential', 'windows.credentials')):
                result = windows.execute_step(manifest(), directory, 'preflight', 'identity', {}, lambda *a, **k: calls.append(a))
            self.assertEqual(result['execution_outcome'], 'blocked')
        self.assertEqual(calls, [])

    def test_session_check_leftovers_fail_and_clean_check_succeeds(self):
        context = {'campaign_started_utc': '2026-11-03T10:00:00+00:00'}
        result, calls = self.dispatch_fixture(manifest(), session_check(), 'cleanup', 'session_check', context)
        self.assertEqual(result['execution_outcome'], 'succeeded')
        self.assertTrue(result['effect_verified'])
        self.assertEqual(decode_json(calls[0][1]['input_bytes'])['since_utc'], '2026-11-03T10:00:00.000000Z')
        result, _ = self.dispatch_fixture(manifest(), session_check((812, 4410), 1), 'cleanup', 'session_check', context)
        self.assertEqual(result['execution_outcome'], 'failed')
        self.assertFalse(result['effect_verified'])
        self.assertEqual(result['evidence']['reason'], 'owned_leftovers_found')
        self.assertEqual(result['evidence']['leftovers'], {'process_count': 2, 'session_count': 1, 'process_ids': [812, 4410]})
        self.assertIsNotNone(result['observed_target_sha256'])

    def test_inconsistent_or_missing_leftover_report_is_unknown(self):
        context = {'campaign_started_utc': '2026-11-03T10:00:00+00:00'}
        found_but_passed = session_check((812,), 1)
        found_but_passed.update(execution_outcome='succeeded', failure_reason=None)
        unlisted = session_check((812, 4410), 1)
        unlisted['leftovers']['process_ids'] = [812]
        processes_without_session = session_check((812,), 0)
        silent_pass = receipt()
        silent_pass['effect_checks']['no_owned_leftovers'] = True
        for response in (found_but_passed, unlisted, processes_without_session, silent_pass):
            result, _ = self.dispatch_fixture(manifest(), response, 'cleanup', 'session_check', context)
            self.assertEqual(result['execution_outcome'], 'unknown')
            self.assertFalse(result['effect_verified'])
        leftovers_elsewhere = receipt()
        leftovers_elsewhere['leftovers'] = {'process_count': 0, 'session_count': 0, 'process_ids': []}
        result, _ = self.dispatch_fixture(manifest(), leftovers_elsewhere)
        self.assertEqual(result['execution_outcome'], 'unknown')

    @unittest.skipUnless(KIT_WORKER.is_file(), 'separate range kit is intentionally not bundled')
    def test_worker_session_check_is_read_only(self):
        script = KIT_WORKER.read_text(encoding='utf-8')
        start = script.index("'session_check' {")
        block = script[start:script.index("'windows-discovery-v1' {", start)]
        for forbidden in ('Stop-Process', 'Terminate', 'Remove-', 'Invoke-CimMethod', 'logoff', 'Start-Process'):
            self.assertNotIn(forbidden, block)
        self.assertIn('Win32_LoggedOnUser', block)
        self.assertIn("throw 'owned_leftovers_found'", block)

    def test_hard_linked_pinned_executable_is_accepted(self):
        with tempfile.TemporaryDirectory() as directory:
            original = Path(directory, 'original.exe')
            original.write_bytes(b'fixture executable bytes, never launched')
            linked = Path(directory, 'powershell.exe')
            os.link(original, linked)
            self.assertEqual(linked.stat().st_nlink, 2)
            expected = digest_bytes(original.read_bytes())
            self.assertEqual(windows._verified_local(str(linked), expected), str(linked))
            with self.assertRaises(BenchmarkError):
                windows._verified_local(str(linked), 'b' * 64)



if __name__ == '__main__':
    unittest.main()

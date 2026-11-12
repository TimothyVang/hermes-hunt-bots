"""Consumer edge contracts; no network, processes, or VM execution."""
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import time
import unittest
from unittest import mock

from hunt_lab import endpoints, managed, prepare_guest


class ManagedTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='hermes-managed-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.state = self.root / 'state'

    def worker_record(self, *, identity=None, pid=43210):
        home = self.state / 'managed'
        home.mkdir(parents=True)
        started = time.time()
        value = dict(operation='1' * 32, started_at=started,
                     deadline_at=started + managed.SETUP_SECONDS, state='preparing',
                     stage='preparing_media', pid=pid, identity=identity)
        managed._atomic(home / 'setup.json', value)
        managed._atomic(home / ('request-' + value['operation'] + '.json'), {'action': 'prepare'})
        return value

    def test_checksum_mismatch_preserves_previous_good_cache(self):
        cache = self.root / 'cache'
        cache.mkdir()
        target = cache / 'public.img'
        target.write_bytes(b'previous verified release')
        spec = dict(filename=target.name, url='https://example.org/public.img',
                    algorithm='sha256', digest=hashlib.sha256(b'new reviewed release').hexdigest(),
                    max_bytes=1024)
        opener = mock.Mock()
        opener.open.return_value = io.BytesIO(b'bad network response')
        with mock.patch.object(managed.urllib.request, 'build_opener', return_value=opener):
            with self.assertRaisesRegex(managed.SetupFailure, 'public_asset_checksum_mismatch'):
                managed._fetch(spec, cache, time.time() + 60)
        self.assertEqual(target.read_bytes(), b'previous verified release')
        self.assertEqual({path.name for path in cache.iterdir()}, {target.name})

    def test_status_on_absent_root_is_read_only(self):
        with mock.patch.object(managed, '_preflight') as preflight, \
             mock.patch.object(managed.subprocess, 'Popen') as launch:
            result = managed.invoke('status', state_dir=self.state)
        self.assertEqual(result['state'], 'stopped')
        self.assertFalse(result['prepared'])
        self.assertFalse(self.state.exists())
        preflight.assert_not_called()
        launch.assert_not_called()

    def test_unsupported_platform_and_invalid_profile_have_no_side_effects(self):
        for options, reason in (({}, 'managed_setup_requires_windows_x64'),
                                ({'profile': '../unapproved'}, 'invalid_profile')):
            with self.subTest(options=options), \
                 mock.patch.object(managed.platform, 'machine', return_value='arm64'), \
                 mock.patch.object(managed.subprocess, 'Popen') as launch, \
                 mock.patch.object(managed, '_fetch') as fetch:
                result = managed.invoke('start', state_dir=self.state, **options)
                self.assertEqual((result['state'], result['reason']), ('error', reason))
                self.assertFalse(self.state.exists())
                launch.assert_not_called()
                fetch.assert_not_called()

    def test_concurrent_start_joins_owned_worker_without_second_launch(self):
        identity = dict(created=12345, executable='approved-python.exe')
        flags = dict(DETACHED_PROCESS=8, CREATE_NEW_PROCESS_GROUP=512)
        with mock.patch.object(managed, '_identity', return_value=identity), \
             mock.patch.object(managed.subprocess, 'Popen') as launch, \
             mock.patch.object(managed, '_preflight') as preflight, \
             mock.patch.multiple(managed.subprocess, create=True, **flags):
            launch.return_value.pid = 43210
            initial = managed.invoke('prepare', state_dir=self.state)
            first = managed.invoke('start', state_dir=self.state)
            second = managed.invoke('start', state_dir=self.state)
        self.assertEqual(first['state'], 'preparing')
        self.assertEqual(second['setup']['operation'], initial['setup']['operation'])
        self.assertFalse(first['prepared'])
        request = self.state / 'managed' / ('request-' + initial['setup']['operation'] + '.json')
        self.assertEqual(json.loads(request.read_text())['action'], 'start')
        launch.assert_called_once()
        preflight.assert_called_once()

    def test_reused_pid_does_not_report_ready_or_change_state_on_status(self):
        self.worker_record(identity=dict(created=100, executable='approved-python.exe'))
        path = self.state / 'managed' / 'setup.json'
        before = path.read_bytes()
        with mock.patch.object(managed, '_identity', return_value=dict(created=200, executable='other.exe')), \
             mock.patch.object(managed.subprocess, 'Popen') as launch:
            result = managed.invoke('status', state_dir=self.state)
        self.assertEqual((result['state'], result['reason']), ('error', 'setup_interrupted'))
        self.assertFalse(result['prepared'])
        self.assertEqual(path.read_bytes(), before)
        launch.assert_not_called()

    def test_unknown_process_identity_refuses_restart(self):
        self.worker_record(identity=dict(created=100, executable='approved-python.exe'))
        with mock.patch.object(managed, '_identity', side_effect=managed.SetupFailure('worker_identity_unavailable')), \
             mock.patch.object(managed.subprocess, 'Popen') as launch:
            result = managed.invoke('start', state_dir=self.state)
        self.assertEqual(result['reason'], 'worker_identity_unavailable')
        launch.assert_not_called()

    def test_payload_is_explicit_public_allowlist_without_operator_material(self):
        fixtures = managed.SOURCE / 'fixtures' / 'dns-lab-001'
        sources = [(name, prepare_guest.LAB_SOURCE / name) for name in prepare_guest.PAYLOAD_FILES]
        sources.extend(('evidence/' + name, fixtures / name) for name in prepare_guest.EVIDENCE_FILES)
        with io.BytesIO() as stream:
            prepare_guest.write_payload(stream, sources)
            with tarfile.open(fileobj=stream, mode='r:') as archive:
                names = set(archive.getnames())
        self.assertEqual(names, {
            'compose.yaml', 'arkime.ini', 'bootstrap_guest.sh', 'lab_server.py',
            'ingest.py', 'image-lock.json', 'kibana.yml', 'kibana_setup.py', 'evidence/events.jsonl',
            'evidence/traffic.pcap', 'evidence/case.json',
        })
        self.assertFalse(any('key' in name or 'truth' in name or 'test' in name or name == 'case.py' for name in names))


class PayloadSourceTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix='hermes-payload-test-')
        self.addCleanup(temp.cleanup)
        self.evidence = Path(temp.name).resolve()
        fixtures = managed.SOURCE / 'fixtures' / 'dns-lab-001'
        for name in prepare_guest.EVIDENCE_FILES:
            (self.evidence / name).write_bytes((fixtures / name).read_bytes())
        self.case = json.loads((fixtures / 'case.json').read_text(encoding='utf-8'))

    def write_case(self, **fields):
        (self.evidence / 'case.json').write_text(json.dumps(dict(self.case, **fields)), encoding='utf-8')

    def evidence_names(self):
        return {name for name, _ in prepare_guest.payload_sources(self.evidence) if name.startswith('evidence/')}

    def test_case_without_the_field_ships_and_requires_the_pcap(self):
        self.assertEqual(self.evidence_names(),
                         {'evidence/events.jsonl', 'evidence/traffic.pcap', 'evidence/case.json'})
        (self.evidence / 'traffic.pcap').unlink()
        with self.assertRaises(FileNotFoundError):
            prepare_guest.payload_sources(self.evidence)

    def test_case_without_capture_is_accepted_without_a_pcap(self):
        (self.evidence / 'traffic.pcap').unlink()
        self.write_case(network_capture='none')
        self.assertEqual(self.evidence_names(), {'evidence/events.jsonl', 'evidence/case.json'})
        self.assertEqual(prepare_guest.case_metadata(self.evidence / 'case.json')['network_capture'], 'none')

    def test_case_saying_none_but_shipping_a_pcap_is_refused(self):
        self.write_case(network_capture='none')
        with self.assertRaisesRegex(prepare_guest.PreparationError, 'traffic.pcap is present'):
            prepare_guest.payload_sources(self.evidence)

    def test_any_other_network_capture_value_is_refused(self):
        for value in ('pcap', 'None', '', None, False, ['none']):
            with self.subTest(value=value):
                self.write_case(network_capture=value)
                with self.assertRaisesRegex(prepare_guest.PreparationError, 'network_capture'):
                    prepare_guest.case_metadata(self.evidence / 'case.json')
                with self.assertRaisesRegex(prepare_guest.PreparationError, 'network_capture'):
                    prepare_guest.payload_sources(self.evidence)

    def test_data_origin_is_absent_or_a_known_origin_and_nothing_else(self):
        for value in ('public-dataset', 'work-export'):
            self.write_case(data_origin=value)
            self.assertEqual(prepare_guest.case_metadata(self.evidence / 'case.json')['data_origin'], value)
        for value in ('synthetic', 'customer', '', None, ['public-dataset']):
            with self.subTest(value=value):
                self.write_case(data_origin=value)
                with self.assertRaisesRegex(prepare_guest.PreparationError, 'data_origin'):
                    prepare_guest.case_metadata(self.evidence / 'case.json')

    def test_a_work_connected_case_is_never_seeded_into_the_vm(self):
        self.write_case(data_origin='work-connected')
        with self.assertRaisesRegex(prepare_guest.PreparationError, 'never seeded into the VM'):
            prepare_guest.case_metadata(self.evidence / 'case.json')
        with self.assertRaisesRegex(prepare_guest.PreparationError, 'never seeded into the VM'):
            prepare_guest.payload_sources(self.evidence)

    def test_accepted_origins_are_the_hunt_origins(self):
        from hermes_temporal.contracts import DATA_ORIGINS
        self.assertEqual(prepare_guest.DATA_ORIGINS, tuple(DATA_ORIGINS))


try:
    import pycdlib
except ImportError:
    pycdlib = None


@unittest.skipIf(pycdlib is None, 'pycdlib host prerequisite is not installed')
class ReseedTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix='hermes-reseed-test-')
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        self.state = self.root / 'hunt-lab-vm'
        (self.state / 'media').mkdir(parents=True)
        self.evidence = self.root / 'case'
        self.evidence.mkdir()
        fixtures = managed.SOURCE / 'fixtures' / 'dns-lab-001'
        for name in prepare_guest.EVIDENCE_FILES:
            (self.evidence / name).write_bytes((fixtures / name).read_bytes())
        (self.evidence / 'intel.jsonl').write_text('{"indicator": {"type": "ip", "value": "198.51.100.7"}}\n')
        # Operator-only material beside the evidence must never enter the guest payload.
        (self.evidence / 'truth.json').write_text('{"facts": []}\n')

    def args(self, update=False):
        return prepare_guest.argparse.Namespace(state_dir=str(self.state), evidence_dir=str(self.evidence),
                                                profile=prepare_guest.PROFILE, update_deployment=update)

    def read_iso(self, seed):
        iso = pycdlib.PyCdlib()
        iso.open(str(seed))
        try:
            metadata, payload = io.BytesIO(), io.BytesIO()
            iso.get_file_from_iso_fp(metadata, rr_path='/meta-data')
            iso.get_file_from_iso_fp(payload, rr_path='/lab-payload.tar')
        finally:
            iso.close()
        payload.seek(0)
        with tarfile.open(fileobj=payload, mode='r:') as archive:
            return json.loads(metadata.getvalue()), set(archive.getnames())

    def deployment(self):
        qemu = self.root / 'qemu' / 'qemu-system-x86_64.exe'
        qemu.parent.mkdir()
        qemu.write_bytes(b'public qemu binary stand-in')
        disk = self.state / 'media' / 'lab.qcow2'
        disk.write_bytes(b'QFI\xfb\x00\x00\x00\x02' + bytes(72))
        old_seed = self.state / 'media' / 'cidata.iso'
        old_seed.write_bytes(b'existing seed')
        path = self.state / 'deployment.json'
        path.write_text(json.dumps({'qemu': str(qemu), 'disk': str(disk), 'seed': str(old_seed),
                                    'memory_mib': 4096, 'cpus': 2, 'accel': 'whpx'}, indent=2) + '\n')
        return path, old_seed

    def test_reseed_writes_new_case_iso_with_new_instance_and_allowlisted_payload(self):
        result = prepare_guest.reseed(self.args())
        seed = Path(result['seed'])
        self.assertEqual(seed.parent, self.state / 'media')
        metadata, names = self.read_iso(seed)
        self.assertRegex(metadata['instance-id'], r'^hermes-framework-network-analyst-case-dns-lab-001-[0-9a-f]{8}$')
        self.assertEqual(metadata['instance-id'], result['instance_id'])
        self.assertEqual(names, set(prepare_guest.PAYLOAD_FILES) | {
            'evidence/events.jsonl', 'evidence/traffic.pcap', 'evidence/case.json', 'evidence/intel.jsonl'})
        self.assertFalse(any('key' in name or 'truth' in name or 'test' in name for name in names))
        self.assertFalse(result['deployment_updated'])

    def test_each_seed_carries_a_new_secret_that_only_its_owner_can_read(self):
        seeds = [Path(prepare_guest.reseed(self.args())['seed']) for _ in range(2)]
        secrets = []
        for seed in seeds:
            iso = pycdlib.PyCdlib()
            iso.open(str(seed))
            try:
                carried = io.BytesIO()
                iso.get_file_from_iso_fp(carried, rr_path='/lab-secret')
            finally:
                iso.close()
            caller = json.loads(endpoints.caller_file(seed).read_text(encoding='ascii'))
            self.assertEqual(caller, {'version': 1, 'instance': self.read_iso(seed)[0]['instance-id'],
                                      'secret': carried.getvalue().decode('ascii').strip()})
            self.assertRegex(caller['secret'], r'^[0-9a-f]{64}$')
            secrets.append(caller['secret'])
            if os.name == 'nt':
                for path in (seed, endpoints.caller_file(seed)):
                    listing = subprocess.run(['icacls', str(path)], capture_output=True, text=True,
                                             check=True).stdout.replace(str(path), '')
                    self.assertEqual(len([line for line in listing.splitlines() if ':(' in line]), 2, listing)
                    self.assertIn('NT AUTHORITY\\SYSTEM:(F)', listing)
        self.assertNotEqual(*secrets)
        (self.state / 'deployment.json').write_text(json.dumps({'seed': str(seeds[1])}), encoding='utf-8')
        self.assertEqual(endpoints.vm_caller(self.state), (self.read_iso(seeds[1])[0]['instance-id'], secrets[1]))

    def test_reloading_a_case_writes_a_fresh_seed_and_never_overwrites(self):
        first = Path(prepare_guest.reseed(self.args())['seed'])
        before, first_id = first.read_bytes(), self.read_iso(first)[0]['instance-id']
        # cloud-init runs setup once per instance ID: switching back needs a new one.
        again = prepare_guest.reseed(self.args())
        self.assertEqual(again['load'], 2)
        self.assertNotEqual(Path(again['seed']), first)
        self.assertEqual(self.read_iso(Path(again['seed']))[0]['instance-id'], first_id + '-load2')
        self.assertEqual(first.read_bytes(), before)
        (self.evidence / 'intel.jsonl').write_text('{"indicator": {"type": "ip", "value": "198.51.100.8"}}\n')
        changed = prepare_guest.reseed(self.args())
        self.assertEqual(changed['load'], 1)
        self.assertNotIn(self.read_iso(Path(changed['seed']))[0]['instance-id'], (first_id, first_id + '-load2'))

    def test_reseed_rejects_invalid_case_metadata(self):
        (self.evidence / 'case.json').write_text(json.dumps({'case_id': '../Other', 'time_range_utc': {}}))
        with self.assertRaises(prepare_guest.PreparationError):
            prepare_guest.reseed(self.args())
        self.assertEqual(list((self.state / 'media').iterdir()), [])

    def test_reseed_of_a_case_without_capture_ships_no_pcap(self):
        case = json.loads((self.evidence / 'case.json').read_text())
        (self.evidence / 'case.json').write_text(json.dumps(dict(case, network_capture='none')))
        with self.assertRaises(prepare_guest.PreparationError):
            prepare_guest.reseed(self.args())
        self.assertEqual(list((self.state / 'media').iterdir()), [])
        (self.evidence / 'traffic.pcap').unlink()
        _, names = self.read_iso(Path(prepare_guest.reseed(self.args())['seed']))
        self.assertEqual(names, set(prepare_guest.PAYLOAD_FILES) | {
            'evidence/events.jsonl', 'evidence/case.json', 'evidence/intel.jsonl'})

    def test_deployment_switch_is_refused_while_the_vm_is_not_stopped(self):
        path, _ = self.deployment()
        before = path.read_bytes()
        for state in ('running', 'starting', 'error'):
            with self.subTest(state=state), \
                 mock.patch.object(prepare_guest._runtime(), 'invoke',
                                   return_value={'state': state, 'reason': 'test'}) as invoke:
                with self.assertRaisesRegex(prepare_guest.PreparationError, 'stop the VM'):
                    prepare_guest.reseed(self.args(update=True))
                invoke.assert_called_once_with('status', state_dir=self.state, profile=prepare_guest.PROFILE)
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(sorted(p.name for p in (self.state / 'media').iterdir()), ['cidata.iso', 'lab.qcow2'])

    def test_deployment_switch_when_stopped_replaces_only_seed_and_keeps_backup(self):
        path, old_seed = self.deployment()
        before = path.read_text()
        with mock.patch.object(prepare_guest._runtime(), 'invoke',
                               return_value={'state': 'stopped', 'reason': 'not_started'}):
            result = prepare_guest.reseed(self.args(update=True))
        updated = json.loads(path.read_text())
        self.assertEqual(updated, dict(json.loads(before), seed=result['seed']))
        self.assertEqual(Path(result['deployment_backup']).read_text(), before)
        self.assertEqual(result['previous_seed'], str(old_seed))
        self.assertEqual(old_seed.read_bytes(), b'existing seed')
        self.assertTrue(result['deployment_updated'])


class ConsoleUrlTests(unittest.TestCase):
    def test_a_running_status_names_the_console_with_the_deployed_seeds_secret_only(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            seed = root / 'media' / 'cidata.iso'
            seed.parent.mkdir()
            (root / 'deployment.json').write_text(json.dumps({'seed': str(seed)}), encoding='utf-8')
            status = {'state': 'running', 'lab_url': 'http://127.0.0.1:41001'}
            with mock.patch.object(managed.runtime, 'invoke', side_effect=lambda *_a, **_k: dict(status)):
                self.assertIsNone(managed._view(root, {}, None)['lab_console_url'])
                endpoints.write_vm_caller(seed, 'hermes-framework-network-analyst-native-v1', 'ab' * 32)
                self.assertEqual(managed._view(root, {}, None)['lab_console_url'],
                                 'http://127.0.0.1:41001/?key=' + 'ab' * 32)
                status['state'] = 'stopped'
                self.assertIsNone(managed._view(root, {}, None)['lab_console_url'])
                status.update(state='running', lab_url='http://192.0.2.1:41001')
                self.assertIsNone(managed._view(root, {}, None)['lab_console_url'])


if __name__ == '__main__':
    unittest.main()

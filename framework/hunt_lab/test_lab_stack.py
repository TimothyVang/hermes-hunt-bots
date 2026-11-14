"""The container lab (hunt_lab.lab_stack, guest/compose.stack.yaml) against a faked Docker CLI.

Run from framework/: python -B -m unittest hunt_lab.test_lab_stack
With Docker installed, the compose checks also read Docker's own rendering of the file (`docker compose config`).
"""
import argparse
from contextlib import redirect_stderr, redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

import hunt_lab
from hunt_lab import endpoints, lab_stack

GUEST = Path(lab_stack.__file__).parent / 'guest'
COMPOSE = GUEST / 'compose.stack.yaml'
FIXTURE = Path(lab_stack.__file__).parent / 'fixtures' / 'dns-lab-001'
SERVICES = set(lab_stack.SERVICES) | set(lab_stack.ONE_SHOTS)
VARIABLES = {'PROJECT': 'hunt-lab-unit-001', 'LAB_IMAGE': 'hermes-hunt-lab:unit', 'CASE_ID': 'unit-001',
             'EVIDENCE_DIR': 'C:/evidence', 'SECRET_FILE': 'C:/secret', 'INSTANCE_FILE': 'C:/instance',
             'LAB_PORT': '19340', 'KIBANA_PORT': '19341', 'ARKIME_PORT': '19342'}


def blocks(text, heading):
    """{name: block text} of the two-space-indented entries under a top-level `heading:` of the compose file."""
    section = text.split('\n' + heading + ':\n', 1)[1]
    section = re.split(r'\n(?=\S)', section, maxsplit=1)[0]
    parts = re.split(r'^  (?=[a-z][a-z-]*:)', section, flags=re.MULTILINE)
    return {part.split(':', 1)[0]: part for part in parts if part.strip()}


def rendered():
    """Docker's normalized model of the compose file, or None without a Docker CLI (it needs no engine)."""
    if shutil.which('docker') is None:
        return None
    env = {key: value for key, value in os.environ.items() if not key.upper().startswith('COMPOSE_')}
    answer = subprocess.run(['docker', 'compose', '-f', str(COMPOSE), 'config', '--format', 'json'],
                            capture_output=True, text=True, env={**env, **VARIABLES}, timeout=60)
    if answer.returncode:
        raise AssertionError('docker compose config refused the file: ' + answer.stderr[-500:])
    return json.loads(answer.stdout)


class ComposeFileTests(unittest.TestCase):
    def test_compose_project_has_no_host_network_and_no_published_elasticsearch(self):
        text = COMPOSE.read_text(encoding='utf-8')
        services = blocks(text, 'services')
        self.assertEqual(set(services), SERVICES)
        self.assertNotIn('network_mode: host', text)
        self.assertNotIn('privileged', text)
        self.assertNotIn('ipv4_address', text)
        self.assertNotIn('172.30.91', text)
        published = {name for name, block in services.items() if '\n    ports:' in block}
        self.assertEqual(published, {'relay'})
        self.assertEqual(re.findall(r'^      - (.*)$', services['relay'].split('\n    ports:\n', 1)[1], re.MULTILINE)[:3],
                         ['127.0.0.1:${LAB_PORT:?}:8765', '127.0.0.1:${KIBANA_PORT:?}:5601',
                          '127.0.0.1:${ARKIME_PORT:?}:8005'])
        self.assertIn('    networks: [backend]\n', services['elasticsearch'])
        for name in ('lab', 'kibana', 'arkime'):
            self.assertIn('    network_mode: service:netns\n', services[name], name)
        # Only the relay has a network with a route out.
        self.assertEqual({name for name, block in services.items() if 'edge' in block}, {'relay'})
        networks = blocks(text, 'networks')
        self.assertIn('internal: true', networks['backend'])
        model = rendered()
        if model is None:
            return
        self.assertEqual(set(model['services']), SERVICES)
        for name, service in model['services'].items():
            with self.subTest(service=name):
                self.assertNotEqual(service.get('network_mode'), 'host')
                self.assertFalse(service.get('privileged', False))
                if name == 'relay':
                    self.assertEqual(sorted(port['host_ip'] for port in service['ports']), ['127.0.0.1'] * 3)
                    self.assertEqual(set(service['networks']), {'backend', 'edge'})
                else:
                    self.assertNotIn('ports', service)
                    self.assertNotIn('edge', service.get('networks') or {})
        self.assertNotIn('ports', model['services']['elasticsearch'])
        self.assertTrue(model['networks']['backend']['internal'])
        self.assertFalse(model['networks']['backend'].get('ipam', {}).get('config'))

    def test_images_are_the_guest_pins_and_the_lab_image_matches_the_guest_tshark(self):
        text = COMPOSE.read_text(encoding='utf-8')
        lock = json.loads((GUEST / 'image-lock.json').read_text(encoding='utf-8'))
        pinned = {image['tag'] + '@' + image['manifest_digest'] for image in lock['images']}
        used = set(re.findall(r'^    image: (\S+)$', text, re.MULTILINE)) - {'${LAB_IMAGE:?}'}
        self.assertEqual(used, pinned)
        dockerfile = (GUEST / 'Dockerfile.lab').read_text(encoding='utf-8')
        self.assertRegex(dockerfile, r'(?m)^FROM ubuntu:22\.04@sha256:[0-9a-f]{64}$')
        self.assertIn('tshark=3.6.2-2', dockerfile)
        self.assertEqual(lab_stack.lab_image(),
                         'hermes-hunt-lab:' + hashlib.sha256((GUEST / 'Dockerfile.lab').read_bytes()).hexdigest()[:12])


class FakeDocker:
    """Stands in for the Docker CLI: records each call and answers `compose ps` with `services`."""

    def __init__(self):
        self.calls, self.services, self.remaining = [], {}, ''
        self.down_code = self.exec_code = self.rm_code = 0

    def __call__(self, arguments, timeout=lab_stack.DOCKER_SECONDS):
        self.calls.append(list(arguments))
        if arguments[:1] == ['compose'] and 'ps' in arguments:
            rows = [{'Service': name, 'State': state, 'ExitCode': code} for name, (state, code) in self.services.items()]
            return subprocess.CompletedProcess(arguments, 0, '\n'.join(json.dumps(row) for row in rows), '')
        if arguments[:1] == ['compose'] and 'exec' in arguments:
            return subprocess.CompletedProcess(arguments, self.exec_code, '', '')
        if arguments[:1] == ['compose'] and 'rm' in arguments:
            if self.rm_code == 0 and '-s' in arguments:
                for svc in arguments[arguments.index('-s') + 1:]:
                    self.services.pop(svc, None)
            return subprocess.CompletedProcess(arguments, self.rm_code, '', '')
        if arguments[:1] == ['compose'] and 'down' in arguments:
            self.services = {}
            return subprocess.CompletedProcess(arguments, self.down_code, '', '')
        if arguments[1:2] == ['ls']:
            return subprocess.CompletedProcess(arguments, 0, self.remaining, '')
        return subprocess.CompletedProcess(arguments, 0, '29.0.0\n', '')


class StackTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.home = Path(temp.name) / 'profiles' / lab_stack.PROFILE
        self.state_dir = self.home / 'hunt-lab-vm'
        self.root = self.home / endpoints.CONTAINER_STATE
        self.docker = FakeDocker()
        self.launched = []
        self.health = (False, None, 'lab_unreachable')
        self.up_running = True
        self.terminated = []
        test = self

        def launch(argv, variables, log_path):
            test.launched.append((argv, lab_stack._child_env(variables), log_path))
            return 4242

        def terminate(pid):
            test.terminated.append(pid)
            test.up_running = False

        for name, value in (('_docker', self.docker), ('_launch', launch), ('_terminate', terminate),
                            ('_identity', lambda pid: {'created': 1} if test.up_running else None),
                            ('_health', lambda state: test.health)):
            patcher = patch.object(lab_stack, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        environ = patch.dict(os.environ, {lab_stack.PORTS_ENV: '19340-19369'})
        environ.start()
        self.addCleanup(environ.stop)

    def invoke(self, action, **options):
        return lab_stack.invoke(action, state_dir=self.state_dir, **options)

    def evidence(self, **extra):
        folder = self.home.parent.parent / ('case-' + str(len(list(self.home.parent.parent.glob('case-*')))))
        shutil.copytree(FIXTURE, folder)
        for name, content in extra.items():
            (folder / name).write_text(content, encoding='utf-8')
        return folder

    def running(self):
        self.docker.services = {name: ('running', 0) for name in lab_stack.SERVICES}
        self.docker.services.update({name: ('exited', 0) for name in lab_stack.ONE_SHOTS})

    def test_start_stages_only_allowlisted_evidence_and_writes_a_state_the_resolver_accepts(self):
        folder = self.evidence(**{'answer-key.json': '{"facts": []}', 'notes.txt': 'operator only'})
        result = self.invoke('start', evidence_dir=str(folder))
        self.assertEqual((result['state'], result['reason'], result['origin'], result['case_id']),
                         ('starting', 'loading_case', 'container', 'dns-lab-001'))
        case_dir = self.root / 'dns-lab-001'
        self.assertEqual(sorted(path.name for path in (case_dir / 'evidence').iterdir()),
                         ['case.json', 'events.jsonl', 'traffic.pcap'])
        state = endpoints.container_state(case_dir / 'state.json')
        self.assertEqual(state['project'], 'hunt-lab-dns-lab-001')
        self.assertTrue(all(19340 <= state[key] <= 19369 for key in ('lab_port', 'kibana_port', 'arkime_port')))
        self.assertEqual((case_dir / 'lab-secret').read_text(encoding='ascii'), state['secret'])
        self.assertEqual((case_dir / 'instance-id').read_text(encoding='ascii'), state['instance'] + '\n')
        self.assertEqual(json.loads((self.root / 'last.json').read_text(encoding='utf-8')),
                         {'case_id': 'dns-lab-001', 'evidence_dir': str(folder)})
        [(argv, env, log_path)] = self.launched
        self.assertEqual(log_path, case_dir / 'compose.log')
        self.assertEqual(argv[:2] + argv[-4:], ['docker', 'compose', '-p', 'hunt-lab-dns-lab-001', 'up', '-d'])
        self.assertEqual(argv[argv.index('-f') + 1], str(COMPOSE))
        self.assertEqual({key: env[key] for key in ('PROJECT', 'CASE_ID', 'LAB_PORT', 'KIBANA_PORT', 'ARKIME_PORT')},
                         {'PROJECT': 'hunt-lab-dns-lab-001', 'CASE_ID': 'dns-lab-001', 'LAB_PORT': str(state['lab_port']),
                          'KIBANA_PORT': str(state['kibana_port']), 'ARKIME_PORT': str(state['arkime_port'])})
        self.assertEqual(env['EVIDENCE_DIR'], (case_dir / 'evidence').as_posix())
        self.assertEqual(env['SECRET_FILE'], (case_dir / 'lab-secret').as_posix())
        self.assertNotIn(state['secret'], json.dumps(argv) + json.dumps({k: v for k, v in env.items()}))
        # A second start of the same case reports it instead of launching another stack.
        self.assertEqual(self.invoke('start', evidence_dir=str(folder))['state'], 'starting')
        self.assertEqual(len(self.launched), 1)

    def test_start_keeps_the_owner_only_state_and_hands_docker_no_ambient_secrets(self):
        with patch.dict(os.environ, {'ANTHROPIC_API_KEY': 'not-a-real-key', 'COMPOSE_FILE': 'elsewhere.yaml',
                                     'DOCKER_CONTEXT': 'desktop-linux'}):
            self.invoke('start')
        [(argv, env, _log)] = self.launched
        self.assertNotIn('ANTHROPIC_API_KEY', env)
        self.assertNotIn('COMPOSE_FILE', env)
        self.assertEqual(env['DOCKER_CONTEXT'], 'desktop-linux')
        case_dir = self.root / 'dns-lab-001'
        if os.name != 'nt':
            self.assertEqual(case_dir.stat().st_mode & 0o777, 0o700)
            return
        user = subprocess.run(['whoami'], capture_output=True, text=True, check=True).stdout.strip().lower()
        for path in (self.root, case_dir, case_dir / 'state.json', case_dir / 'lab-secret'):
            listing = subprocess.run(['icacls', str(path)], capture_output=True, text=True, check=True).stdout
            listing = listing.replace(str(path), '')
            self.assertEqual({line.strip().split(':(')[0].lower() for line in listing.splitlines() if ':(' in line},
                             {user, 'nt authority\\system'}, path)

    def test_start_without_evidence_loads_the_last_case_else_the_fixture(self):
        self.assertEqual(self.invoke('start')['case_id'], 'dns-lab-001')
        self.assertEqual(self.invoke('stop')['state'], 'stopped')
        folder = self.evidence()
        case = json.loads((folder / 'case.json').read_text(encoding='utf-8'))
        case['case_id'] = 'team-med-901'
        (folder / 'case.json').write_text(json.dumps(case), encoding='utf-8')
        self.assertEqual(self.invoke('start', evidence_dir=str(folder))['case_id'], 'team-med-901')
        self.assertEqual(self.invoke('status')['case_id'], 'team-med-901')
        self.assertEqual(self.invoke('start', case_id='other-001')['reason'], 'evidence_dir_required')
        self.assertEqual(self.invoke('start', evidence_dir=str(folder), case_id='dns-lab-001')['reason'],
                         'case_mismatch')

    def test_start_refuses_evidence_the_case_rules_refuse(self):
        no_capture = self.evidence()
        case = json.loads((no_capture / 'case.json').read_text(encoding='utf-8'))
        (no_capture / 'case.json').write_text(json.dumps({**case, 'network_capture': 'none'}), encoding='utf-8')
        connected = self.evidence()
        (connected / 'case.json').write_text(json.dumps({**case, 'data_origin': 'work-connected'}), encoding='utf-8')
        missing = self.evidence()
        (missing / 'events.jsonl').unlink()
        for folder in (no_capture, connected, missing):
            with self.subTest(folder=folder.name):
                self.assertEqual(self.invoke('start', evidence_dir=str(folder))['reason'], 'invalid_evidence')
        self.assertEqual(self.launched, [])
        self.assertFalse((self.root / 'dns-lab-001').exists())

    def test_a_case_without_a_capture_stages_no_pcap(self):
        folder = self.evidence()
        case = json.loads((folder / 'case.json').read_text(encoding='utf-8'))
        (folder / 'case.json').write_text(json.dumps({**case, 'network_capture': 'none'}), encoding='utf-8')
        (folder / 'traffic.pcap').unlink()
        self.assertEqual(self.invoke('start', evidence_dir=str(folder))['state'], 'starting')
        self.assertEqual(sorted(path.name for path in (self.root / 'dns-lab-001' / 'evidence').iterdir()),
                         ['case.json', 'events.jsonl'])

    def test_status_is_running_only_when_the_lab_service_says_ready(self):
        self.invoke('start')
        self.running()
        self.health = (False, {'ready': False, 'kibana_ready': False}, 'services_not_ready')
        result = self.invoke('status')
        self.assertEqual((result['state'], result['reason'], result['lab_console_url']),
                         ('starting', 'services_not_ready', None))
        self.health = (True, {'ready': True}, None)
        result = self.invoke('status')
        state = endpoints.container_state(self.root / 'dns-lab-001' / 'state.json')
        self.assertEqual((result['state'], result['reason']), ('running', None))
        self.assertEqual(result['lab_url'], 'http://127.0.0.1:%d' % state['lab_port'])
        self.assertEqual(result['kibana_url'], 'http://127.0.0.1:%d' % state['kibana_port'])
        self.assertEqual(result['arkime_url'], 'http://127.0.0.1:%d' % state['arkime_port'])
        self.assertEqual(result['lab_console_url'], result['lab_url'] + '/?key=' + state['secret'])
        self.assertEqual(result['services']['ingest'], 'exited(0)')

    def test_start_replies_carry_the_console_url_once_running(self):
        # The desktop shows Open lab from the start reply itself, so a running start reply must carry the URL.
        ready = iter([(False, None, 'lab_unreachable'), (True, {'ready': True}, None)])
        with patch.object(lab_stack, '_health', lambda state: next(ready)), patch.object(lab_stack.time, 'sleep'):
            result = self.invoke('start', wait=60)
        state = endpoints.container_state(self.root / 'dns-lab-001' / 'state.json')
        self.assertEqual(result['state'], 'running')
        self.assertEqual(result['lab_console_url'], 'http://127.0.0.1:%d/?key=%s' % (state['lab_port'], state['secret']))
        # Start on a lab that already runs reports it, with the URL, and launches nothing.
        self.health = (True, {'ready': True}, None)
        again = self.invoke('start')
        self.assertEqual((again['state'], again['lab_console_url']), ('running', result['lab_console_url']))
        self.assertEqual(len(self.launched), 1)
        self.assertEqual(self.invoke('status')['lab_console_url'], result['lab_console_url'])

    def test_status_names_the_failed_step_and_a_stalled_start(self):
        self.invoke('start')
        log = self.root / 'dns-lab-001' / 'compose.log'
        gave_up = ' Container hunt-lab-dns-lab-001-relay-1  Starting\nError response from daemon: ports are not available\n'
        cases = (
            ({'ingest': ('exited', 1)}, True, '', 'error', 'ingest_failed'),
            ({'pcap-import': ('exited', 2)}, True, '', 'error', 'pcap_import_failed'),
            ({'lab': ('exited', 137)}, True, '', 'error', 'lab_exited'),
            ({'arkime': None}, False, gave_up, 'error', 'compose_up_failed'),
            ({'relay': ('created', None)}, False, gave_up, 'error', 'compose_up_failed'),
            # docker.exe gone with no failure written: a caller ended the CLI's process tree while the compose
            # plugin goes on (desktop, take 1). Still starting, not compose_up_failed.
            ({'arkime': ('created', None), 'kibana-setup': ('created', None)}, False, ' Container x  Waiting\n',
             'starting', 'loading_case'),
            ({'arkime': None}, True, '', 'starting', 'loading_case'),
            ({'kibana-setup': ('running', None)}, True, '', 'starting', 'loading_case'),
            ({}, True, '', 'starting', 'lab_unreachable'),
        )
        for change, up_running, written, state, reason in cases:
            with self.subTest(change=change, up_running=up_running, log=written):
                self.running()
                for name, value in change.items():
                    if value is None:
                        self.docker.services.pop(name)
                    else:
                        self.docker.services[name] = value
                self.up_running = up_running
                log.write_text(written, encoding='utf-8')
                result = self.invoke('status')
                self.assertEqual((result['state'], result['reason']), (state, reason))
        self.running()
        with patch.object(lab_stack.time, 'time', return_value=lab_stack.time.time() + lab_stack.START_SECONDS + 1):
            self.assertEqual((self.invoke('status')['state'], self.invoke('status')['reason']),
                             ('error', 'lab_unreachable'))

    def test_a_start_never_takes_ports_another_case_recorded(self):
        other = self.root / 'team-med-901'
        other.mkdir(parents=True)
        (other / 'state.json').write_text(json.dumps({
            'version': 1, 'case_id': 'team-med-901', 'project': 'hunt-lab-team-med-901', 'instance': 'a' * 32,
            'secret': 'b' * 64, 'lab_port': 19340, 'kibana_port': 19341, 'arkime_port': 19342, 'started_at': 1.0}),
            encoding='utf-8')
        self.invoke('start')
        state = endpoints.container_state(self.root / 'dns-lab-001' / 'state.json')
        ports = {state['lab_port'], state['kibana_port'], state['arkime_port']}
        self.assertFalse(ports & {19340, 19341, 19342}, ports)
        self.assertTrue(all(19343 <= port <= 19369 for port in ports), ports)

    def test_warm_start_reuses_running_synthetic_stack_until_cold_or_real_data_origin(self):
        first_ev = self.evidence()
        self.invoke('start', evidence_dir=str(first_ev))
        self.running()
        self.docker.services['lab'] = ('exited', 0)
        self.docker.services['arkime'] = ('exited', 1)
        self.docker.services['kibana-setup'] = ('exited', 2)
        ro_evidence = self.root / 'dns-lab-001' / 'evidence' / 'case.json'
        os.chmod(ro_evidence, 0o444)
        self.addCleanup(lambda: os.chmod(ro_evidence, 0o600) if ro_evidence.exists() else None)
        first_state = endpoints.container_state(self.root / 'dns-lab-001' / 'state.json')
        first_ports = (first_state['lab_port'], first_state['kibana_port'], first_state['arkime_port'])

        second_ev = self.evidence()
        case_two = json.loads((second_ev / 'case.json').read_text(encoding='utf-8'))
        case_two['case_id'] = 'team-med-902'
        (second_ev / 'case.json').write_text(json.dumps(case_two), encoding='utf-8')

        self.docker.exec_code = 1
        res = self.invoke('start', evidence_dir=str(second_ev))
        self.assertEqual((res['state'], res['reason']), ('error', 'arkime_purge_failed'))
        self.assertTrue((self.root / 'dns-lab-001' / 'state.json').is_file())
        self.assertFalse((self.root / 'team-med-902').exists())
        self.docker.exec_code = 0

        self.docker.rm_code = 1
        self.assertEqual(self.invoke('start', evidence_dir=str(second_ev))['reason'], 'warm_reset_failed')
        self.assertTrue((self.root / 'dns-lab-001' / 'state.json').is_file())
        self.assertFalse((self.root / 'team-med-902').exists())
        self.docker.rm_code = 0

        calls_seen = []

        def fail_once_then_restore(argv, variables, log_path):
            calls_seen.append(lab_stack._child_env(variables)['CASE_ID'])
            if len(calls_seen) == 1:
                raise OSError('spawn failed')
            return 7777

        with patch.object(lab_stack, '_launch', side_effect=fail_once_then_restore):
            self.assertEqual(self.invoke('start', evidence_dir=str(second_ev))['reason'], 'stack_io_error')
        self.assertEqual(calls_seen, ['team-med-902', 'dns-lab-001'])
        self.assertTrue((self.root / 'dns-lab-001' / 'state.json').is_file())
        self.assertEqual(json.loads((self.root / 'dns-lab-001' / 'up.json').read_text(encoding='utf-8'))['pid'], 7777)
        self.assertFalse((self.root / 'team-med-902').exists())
        self.assertEqual(json.loads((self.root / 'last.json').read_text(encoding='utf-8'))['case_id'], 'dns-lab-001')

        self.running()
        self.docker.services['arkime'] = ('exited', 1)
        switched = self.invoke('start', evidence_dir=str(second_ev))
        self.assertEqual((switched['state'], switched['reason'], switched['case_id']),
                         ('starting', 'loading_case', 'team-med-902'))
        self.assertFalse((self.root / 'dns-lab-001').exists())
        self.assertEqual([p.name for p in self.root.iterdir() if p.name.startswith('.retired-')], [])
        second_state = endpoints.container_state(self.root / 'team-med-902' / 'state.json')
        self.assertEqual((second_state['lab_port'], second_state['kibana_port'], second_state['arkime_port']),
                         first_ports)
        self.assertEqual(second_state['project'], 'hunt-lab-team-med-902')
        self.assertEqual((self.root / 'team-med-902' / 'compose-project').read_text(encoding='ascii').strip(),
                         'hunt-lab-dns-lab-001')
        argv_two, env_two, _log_two = self.launched[-1]
        self.assertEqual(argv_two[-4:], ['-p', 'hunt-lab-dns-lab-001', 'up', '-d'])
        self.assertEqual((env_two['PROJECT'], env_two['CASE_ID']), ('hunt-lab-dns-lab-001', 'team-med-902'))
        self.assertTrue(any(call[:8] == ['compose', '-p', 'hunt-lab-dns-lab-001', 'exec', '-T', 'netns', 'python3', '-B']
                            for call in self.docker.calls))
        self.assertIn(['compose', '-p', 'hunt-lab-dns-lab-001', 'rm', '-f', '-s', 'lab', 'arkime', *lab_stack.ONE_SHOTS],
                      self.docker.calls)

        # Stopping a retired/stale case folder whose compose project is actively shared by team-med-902 never runs compose down.
        (self.root / 'dns-lab-001').mkdir()
        downs_before = [c for c in self.docker.calls if 'down' in c]
        stopped_old = self.invoke('stop', case_id='dns-lab-001')
        self.assertEqual((stopped_old['state'], stopped_old['reason']), ('stopped', 'stopped'))
        self.assertEqual([c for c in self.docker.calls if 'down' in c], downs_before)
        self.assertFalse((self.root / 'dns-lab-001').exists())
        self.assertTrue((self.root / 'team-med-902' / 'state.json').is_file())

        # A real-data case (data_origin) or cold=True never reuses the warm synthetic stack.
        real_ev = self.evidence()
        case_real = json.loads((real_ev / 'case.json').read_text(encoding='utf-8'))
        case_real['case_id'] = 'work-med-001'
        case_real['data_origin'] = 'work-export'
        (real_ev / 'case.json').write_text(json.dumps(case_real), encoding='utf-8')
        self.invoke('start', evidence_dir=str(real_ev))
        real_state = endpoints.container_state(self.root / 'work-med-001' / 'state.json')
        self.assertNotEqual((real_state['lab_port'], real_state['kibana_port'], real_state['arkime_port']),
                            first_ports)
        self.assertTrue((self.root / 'team-med-902').exists())

    def test_stop_removes_the_project_and_its_state_and_ends_a_start_in_progress(self):
        self.invoke('start')
        self.running()
        result = self.invoke('stop')
        self.assertEqual((result['state'], result['reason'], result['case_id']), ('stopped', 'stopped', 'dns-lab-001'))
        self.assertEqual(self.terminated, [4242])
        self.assertIn(['compose', '-p', 'hunt-lab-dns-lab-001', 'down', '-v', '--remove-orphans', '--timeout', '10'],
                      self.docker.calls)
        self.assertFalse((self.root / 'dns-lab-001').exists())
        self.assertTrue((self.root / 'last.json').exists())
        self.assertEqual((self.invoke('status')['state'], self.invoke('status')['reason']), ('stopped', 'not_started'))

    def test_stop_reports_a_stack_that_remains(self):
        self.invoke('start')
        self.up_running = False
        self.docker.remaining = 'abc123\n'
        self.assertEqual(self.invoke('stop')['reason'], 'stack_remains')
        self.assertTrue((self.root / 'dns-lab-001' / 'state.json').exists())
        self.docker.remaining, self.docker.down_code = '', 1
        self.assertEqual(self.invoke('stop')['reason'], 'compose_down_failed')

    def test_state_inside_a_git_worktree_or_a_foreign_profile_is_refused(self):
        inside = Path(lab_stack.__file__).resolve().parent / 'hunt-lab-vm'
        self.assertEqual(lab_stack.invoke('status', state_dir=inside)['reason'], 'invalid_state_dir')
        self.assertEqual(self.invoke('status', profile='framework-builder')['reason'], 'invalid_profile')
        self.assertEqual(self.invoke('prepare')['reason'], 'invalid_action')


class CommandTests(unittest.TestCase):
    """`hermes -p framework-network-analyst hunt-lab ...` acts only on the container lab."""

    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.home = Path(temp.name) / 'profiles' / lab_stack.PROFILE

    def command(self, operation, **options):
        cli = types.SimpleNamespace(explicit_cli_profile=lambda: lab_stack.PROFILE)
        constants = types.SimpleNamespace(get_hermes_home=lambda: self.home,
                                          profile_name_for_home=lambda _home: lab_stack.PROFILE)
        args = types.SimpleNamespace(hunt_lab_operation=operation, case_id=None, evidence_dir=None, wait=0)
        args.__dict__.update(options)
        stack_calls = []
        stdout = io.StringIO()
        with patch.dict(sys.modules, {'hermes_cli': types.ModuleType('hermes_cli'), 'hermes_cli.main': cli,
                                      'hermes_constants': constants}), \
                patch.object(lab_stack, 'invoke', side_effect=lambda action, **kw: stack_calls.append((action, kw)) or {
                    'profile': lab_stack.PROFILE, 'origin': 'container', 'state': 'running', 'reason': None}), \
                redirect_stdout(stdout):
            code = hunt_lab._command(args)
        return code, json.loads(stdout.getvalue()), stack_calls

    def test_lifecycle_uses_the_container_lab(self):
        code, result, stack_calls = self.command('start', evidence_dir='C:/case', wait=120)
        self.assertEqual((code, result['origin'], result['state']), (0, 'container', 'running'))
        [(action, options)] = stack_calls
        self.assertEqual((action, options['evidence_dir'], options['wait'], options['state_dir']),
                         ('start', 'C:/case', 120, self.home / 'hunt-lab-vm'))

    def test_the_cli_offers_no_vm_operation(self):
        parser = argparse.ArgumentParser()
        hunt_lab._setup(parser)
        for argv in (['prepare'], ['start', '--vm']):
            with self.subTest(argv=argv), self.assertRaises(SystemExit), redirect_stderr(io.StringIO()):
                parser.parse_args(argv)
        for operation in ('status', 'start', 'stop'):
            with self.subTest(operation=operation):
                self.assertEqual(self.command(operation)[2][0][0], operation)


if __name__ == '__main__':
    unittest.main()

"""Hermes setup boundaries tested with isolated authored kits and local fakes."""
from contextlib import redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

import setup_hermes


NAMES = (
    ('framework-coordinator', 'coordinator', 'Plans bounded tasks and synthesizes evidence for human decisions.'),
    ('framework-researcher', 'researcher', 'Investigates approved supplied sources and produces traceable findings.'),
    ('framework-builder', 'builder', 'Implements explicitly approved local changes and records honest evidence.'),
    ('framework-reviewer', 'reviewer', 'Independently evaluates evidence and changes without approving or silently fixing them.'),
    ('framework-librarian', 'librarian', 'Drafts provenance-rich knowledge for human review without promoting trusted memory.'),
    ('framework-network-analyst', 'researcher', 'Analyzes approved sanitized network summaries.'),
)


class FakeProcess:
    def __init__(self, returncode=0):
        self.returncode = returncode

    def wait(self):
        return self.returncode


def native_install(home, *, cancel=(), returncode=0):
    """Fake `hermes profile install`: writes the profile's distribution.yaml and SOUL.md as Hermes does,
    printing nothing, unless the profile is in *cancel* (Hermes then exits 0 and writes nothing)."""
    def factory(argv, **_kwargs):
        source = Path(argv[3])
        if source.name not in cancel and returncode == 0:
            target = Path(home) / 'profiles' / source.name
            target.mkdir(parents=True)
            for name in ('distribution.yaml', 'SOUL.md'):
                shutil.copyfile(source / name, target / name)
        return FakeProcess(returncode)
    return Mock(side_effect=factory)


def version_probe(answers):
    """Fake subprocess.run for the Docker and Temporal probes: {program: stdout or None for a failure}."""
    def runner(argv, **_kwargs):
        stdout = answers[Path(argv[0]).stem]
        return subprocess.CompletedProcess(argv, 0 if stdout else 1, stdout or '', '')
    return runner


def on_path(*programs):
    return lambda name: f'C:/tools/{name}.exe' if name in programs else None


def create_kit(root):
    bots = root / 'hermes-bots'
    bots.mkdir()
    catalog = []
    for name, role, description in NAMES:
        directory = bots / name
        directory.mkdir()
        catalog.append({
            'name': name, 'title': 'Network Analyst' if name == 'framework-network-analyst' else name.replace('-', ' ').title(),
            'description': description, 'soul_path': name + '/SOUL.md',
            'distribution_path': name, 'role': role,
        })
        (directory / 'distribution.yaml').write_text(
            f'name: {name}\nversion: "1.0.0"\ndescription: "{description}"\ndistribution_owned:\n  - SOUL.md\n', encoding='utf-8')
        (directory / 'SOUL.md').write_text('Authored identity.\n', encoding='utf-8')
        (directory / '.gitignore').write_text('.env\n', encoding='utf-8')
    (bots / 'catalog.json').write_text(json.dumps(catalog), encoding='utf-8')
    return bots


class SetupHermesTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='kit with spaces ')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'portable kit'
        self.root.mkdir()
        self.bots = create_kit(self.root)
        self.home = Path(self.temp.name) / 'native-home'
        self.home.mkdir()

    def test_contaminated_distribution_fails_before_any_native_invocation(self):
        (self.bots / 'framework-builder' / '.env').write_text('not a credential', encoding='utf-8')
        factory = Mock()
        with self.assertRaises(setup_hermes.SetupError):
            setup_hermes.install(['framework-builder'], sys.executable, self.root, factory, self.home)
        factory.assert_not_called()

    def test_manifest_identity_mismatch_fails_before_native_invocation(self):
        manifest = self.bots / 'framework-reviewer' / 'distribution.yaml'
        manifest.write_text(manifest.read_text(encoding='utf-8').replace('framework-reviewer', 'other-profile', 1), encoding='utf-8')
        factory = Mock()
        with self.assertRaises(setup_hermes.SetupError):
            setup_hermes.install(['framework-coordinator'], sys.executable, self.root, factory, self.home)
        factory.assert_not_called()

    def test_invalid_and_duplicate_catalog_names_are_rejected(self):
        catalog_path = self.bots / 'catalog.json'
        catalog = json.loads(catalog_path.read_text(encoding='utf-8'))
        catalog[0]['name'] = 'unknown-profile'
        catalog_path.write_text(json.dumps(catalog), encoding='utf-8')
        with self.assertRaises(setup_hermes.SetupError):
            setup_hermes.load_catalog(self.root)
        catalog[0]['name'] = catalog[1]['name']
        catalog_path.write_text(json.dumps(catalog), encoding='utf-8')
        with self.assertRaises(setup_hermes.SetupError):
            setup_hermes.load_catalog(self.root)

    def test_missing_network_analyst_is_rejected_before_native_invocation(self):
        catalog_path = self.bots / 'catalog.json'
        catalog = json.loads(catalog_path.read_text(encoding='utf-8'))
        catalog = [entry for entry in catalog if entry['name'] != 'framework-network-analyst']
        catalog_path.write_text(json.dumps(catalog), encoding='utf-8')
        factory = Mock()
        with self.assertRaisesRegex(setup_hermes.SetupError, 'framework-network-analyst'):
            setup_hermes.install(['framework-coordinator'], sys.executable, self.root, factory, self.home)
        factory.assert_not_called()

    def test_native_cancellation_stops_and_reports_prior_confirmed_install(self):
        factory = native_install(self.home, cancel={'framework-researcher'})
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            result = setup_hermes.install(
                ['framework-coordinator', 'framework-researcher', 'framework-builder'],
                sys.executable, self.root, factory, self.home)
        self.assertEqual(result, 1)
        self.assertEqual(factory.call_count, 2)
        self.assertIn('framework-coordinator', stderr.getvalue())
        self.assertIn('framework-researcher has no installed distribution.yaml', stderr.getvalue())

    def test_installed_files_confirm_a_profile_without_any_console_text(self):
        # SF9: setup trusted Hermes' printed `✓ Installed '<name>' v<version>` line; it now reads the files Hermes wrote.
        factory = native_install(self.home)
        with patch.object(setup_hermes, '_report_lab'), patch('lab.install') as lab_install, \
                redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            result = setup_hermes.install(['framework-coordinator'], sys.executable, self.root, factory, self.home)
        self.assertEqual(result, 0)
        self.assertEqual(factory.call_count, 2)
        lab_install.assert_called_once()
        self.assertTrue((self.home / 'profiles' / 'framework-network-analyst' / 'distribution.yaml').is_file())

    def test_native_refusal_or_unconfirmed_exit_stops_before_later_profiles(self):
        for native_exit in (0, 2):
            with self.subTest(native_exit=native_exit):
                factory = Mock(return_value=FakeProcess(returncode=native_exit))
                with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                    result = setup_hermes.install(
                        ['framework-coordinator', 'framework-builder'],
                        sys.executable, self.root, factory, self.home)
                self.assertNotEqual(result, 0)
                self.assertEqual(factory.call_count, 1)

    def test_install_runs_lab_hermes_exe_and_refuses_before_any_native_call_during_an_update(self):
        # Review of #51: setup_hermes.install, the real entry to lab.install, still ran the `hermes` on PATH.
        folders = {}
        for name, stem in (('path-bin', 'hermes'), ('lab-bin', 'lab-hermes')):
            folder = Path(self.temp.name) / name
            folder.mkdir()
            cli = folder / (stem + ('.exe' if os.name == 'nt' else ''))
            cli.write_bytes(b'')
            cli.chmod(0o755)
            folders[name] = cli
        factory = Mock(return_value=FakeProcess(returncode=2))
        with patch.dict(os.environ, {'PATH': str(folders['path-bin'].parent), 'LAB_HERMES_EXE': str(folders['lab-bin'])}), \
                redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            setup_hermes.install(['framework-coordinator'], None, self.root, factory, self.home)
        self.assertEqual(Path(factory.call_args[0][0][0]).resolve(), folders['lab-bin'].resolve())
        factory.reset_mock()
        (self.home / '.hermes-update-in-progress').write_text('')
        with self.assertRaisesRegex(ValueError, 'update is in progress'):
            setup_hermes.install(['framework-coordinator'], sys.executable, self.root, factory, self.home)
        factory.assert_not_called()

    def test_missing_hermes_is_actionable_and_does_not_invoke_installer(self):
        factory = Mock()
        with self.assertRaises(setup_hermes.SetupError) as error:
            setup_hermes.install(['framework-builder'], str(self.root / 'missing hermes'), self.root, factory, self.home)
        self.assertIn(setup_hermes.INSTALL_URL, str(error.exception))
        self.assertIn(setup_hermes.PLATFORM_URL, str(error.exception))
        factory.assert_not_called()

    def test_check_names_a_lab_hermes_exe_that_does_not_exist(self):
        missing = str(self.root / 'gone' / 'hermes.exe')
        output = io.StringIO()
        with patch.dict(os.environ, {'LAB_HERMES_EXE': missing}), redirect_stdout(output):
            self.assertEqual(setup_hermes.check(None, self.root), 1)
        self.assertIn(f'(LAB_HERMES_EXE: {missing})', output.getvalue())
        self.assertIn(setup_hermes.INSTALL_URL, output.getvalue())

    def test_linked_distribution_file_is_rejected_before_install(self):
        external = self.root / 'external.txt'
        external.write_text('not a soul', encoding='utf-8')
        link = self.bots / 'framework-librarian' / 'SOUL.md'
        link.unlink()
        try:
            link.symlink_to(external)
        except (OSError, NotImplementedError):
            self.skipTest('symbolic links unavailable')
        with self.assertRaises(setup_hermes.SetupError):
            setup_hermes.load_catalog(self.root)

    def test_entrypoint_uses_its_source_root_from_an_unrelated_working_directory(self):
        script = Path(setup_hermes.__file__).resolve()
        result = subprocess.run(
            [sys.executable, str(script), '--hermes', str(self.root / 'missing executable')],
            cwd=str(self.root), capture_output=True, text=True, encoding='utf-8',
            errors='replace', timeout=30)
        self.assertEqual(result.returncode, 1)
        self.assertIn('Validated 6 authored Hermes distributions.', result.stdout)
        self.assertIn(setup_hermes.INSTALL_URL, result.stdout)


class SetupAllTests(unittest.TestCase):
    """`setup_hermes.py all`: every setup step in order, stopping at the first failure."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='setup all ')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'kit'
        self.root.mkdir()
        create_kit(self.root)
        # A fresh home does not exist until setup creates it, as on a new machine.
        self.home = Path(self.temp.name) / 'runtime' / 'lab-home'
        self.ready = version_probe({'docker': '29.1.3\n', 'temporal': 'temporal version 1.5.1\n'})
        self.lab_install = patch('lab.install', return_value={'profile': 'framework-network-analyst'})

    @staticmethod
    def native(pending=()):
        """Patch native_team's Hermes-backed apply and check; returns the patcher and its fresh mocks."""
        mocks = {'apply': Mock(return_value='applied'), 'not_ready': Mock(return_value=list(pending))}
        return patch.multiple('native_team', **mocks), mocks

    def run_all(self, factory, runner, which=on_path('docker', 'temporal')):
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = setup_hermes.setup_all(sys.executable, self.home, self.root, factory, runner, which)
        return code, stdout.getvalue(), stderr.getvalue()

    def test_all_stops_at_first_failure(self):
        stopped = {
            'Docker': (version_probe({'docker': None, 'temporal': 'temporal version 1.5.1'}), on_path('docker', 'temporal')),
            'Temporal CLI': (self.ready, on_path('docker')),
        }
        for named, (runner, which) in stopped.items():
            patcher, native = self.native()
            with self.subTest(missing=named), patcher, self.lab_install as lab_install:
                factory = native_install(self.home)
                code, stdout, stderr = self.run_all(factory, runner, which)
                self.assertEqual(code, 1)
                self.assertIn('setup: stopped at prerequisites: ', stderr)
                self.assertIn(named, stderr.split('setup: stopped at prerequisites: ', 1)[1])
                self.assertNotIn('setup: profiles', stdout)
                factory.assert_not_called()
                lab_install.assert_not_called()
                native['apply'].assert_not_called()
                self.assertFalse((self.home.parent).exists(), 'a failed prerequisite must leave no home behind')
        patcher, native = self.native()
        with patcher, self.lab_install as lab_install, patch('native_team.initialize') as initialize:
            factory = native_install(self.home, returncode=2)
            code, stdout, stderr = self.run_all(factory, self.ready)
        self.assertEqual(code, 1)
        self.assertIn('setup: stopped at profiles: ', stderr)
        self.assertEqual(factory.call_count, 1)
        for later in (initialize, lab_install, native['apply'], native['not_ready']):
            later.assert_not_called()
        self.assertNotIn('setup: complete', stdout)

    def test_all_writes_policy_files_before_plugins_and_ends_complete(self):
        def lab_install(root, executable, kit_root):
            # Enabling plugins writes Hermes defaults into config.yaml; each profile must have its policy first.
            configs = sorted(path.parent.name for path in Path(root, 'profiles').glob('*/config.yaml'))
            self.assertEqual(configs, sorted(name for name, _role, _description in NAMES))
            return {'profile': 'framework-network-analyst'}
        patcher, native = self.native()
        with patcher, patch('lab.install', side_effect=lab_install) as installed:
            factory = native_install(self.home)
            code, stdout, stderr = self.run_all(factory, self.ready)
            self.assertEqual((code, stderr), (0, ''))
            self.assertEqual(factory.call_count, 6)
            installed.assert_called_once()
            native['apply'].assert_called_once()
            native['not_ready'].assert_called_once()
        steps = [line for line in stdout.splitlines() if line.startswith('setup: ')]
        self.assertEqual(steps, ['setup: prerequisites', 'setup: profiles', 'setup: policy files',
                                 'setup: lab plugin and desktop pages', 'setup: team policy', 'setup: check',
                                 'setup: complete'])
        self.assertIn('Docker: Docker engine 29.1.3', stdout)
        self.assertIn('Temporal CLI: temporal version 1.5.1', stdout)

        # A second run installs no profile and rewrites no policy file.
        policy = {path: path.read_bytes() for path in self.home.glob('profiles/*/config.yaml')}
        with self.native()[0], self.lab_install, patch('native_team.initialize') as initialize:
            factory = native_install(self.home)
            code, stdout, _stderr = self.run_all(factory, self.ready)
        self.assertEqual(code, 0)
        factory.assert_not_called()
        initialize.assert_not_called()
        self.assertEqual({path: path.read_bytes() for path in self.home.glob('profiles/*/config.yaml')}, policy)

    def test_policy_left_unready_stops_before_complete(self):
        with self.native(['framework-builder model.default=custom_configuration_conflict'])[0], self.lab_install:
            code, stdout, stderr = self.run_all(native_install(self.home), self.ready)
        self.assertEqual(code, 1)
        self.assertIn('setup: stopped at check: Native team policy is not ready: framework-builder model.default', stderr)
        self.assertNotIn('setup: complete', stdout)


if __name__ == '__main__':
    unittest.main()

"""Hermes setup boundaries tested with isolated authored kits and local fakes."""
from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
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
    def __init__(self, output='', returncode=0):
        self.stdout = io.StringIO(output)
        self.returncode = returncode

    def wait(self):
        return self.returncode


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
        factory = Mock(side_effect=[
            FakeProcess('✓ Installed \'framework-coordinator\' v1.0.0\n'),
            FakeProcess('Install cancelled.\n'),
        ])
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            result = setup_hermes.install(
                ['framework-coordinator', 'framework-researcher', 'framework-builder'],
                sys.executable, self.root, factory, self.home)
        self.assertEqual(result, 1)
        self.assertEqual(factory.call_count, 2)
        self.assertIn('framework-coordinator', stderr.getvalue())

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

    def test_missing_hermes_is_actionable_and_does_not_invoke_installer(self):
        factory = Mock()
        with self.assertRaises(setup_hermes.SetupError) as error:
            setup_hermes.install(['framework-builder'], str(self.root / 'missing hermes'), self.root, factory, self.home)
        self.assertIn(setup_hermes.INSTALL_URL, str(error.exception))
        self.assertIn(setup_hermes.PLATFORM_URL, str(error.exception))
        factory.assert_not_called()

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


if __name__ == '__main__':
    unittest.main()

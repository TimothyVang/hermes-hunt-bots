"""Filesystem ownership and no-side-effect contracts for the built-in lab."""
from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

import install_desktop
import lab
import setup_hermes
from test_setup_hermes import create_kit


class LabInstallTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name).resolve() / 'home'
        self.home.mkdir()

    def profile(self, name=lab.PROFILE):
        profile = self.home / 'profiles' / name
        profile.mkdir(parents=True)
        (profile / 'distribution.yaml').write_text('name: ' + name + '\nversion: 1.0.0\n', encoding='utf-8')
        (profile / 'SOUL.md').write_text('Existing restricted identity; do not overwrite.\n', encoding='utf-8')
        return profile


    def test_install_stages_native_halves_without_touching_private_files_or_vm(self):
        profile = self.profile()
        canaries = {}
        for name in ('config.yaml', '.env', 'auth.json', 'state.db', 'SOUL.md'):
            path = profile / name
            if name != 'SOUL.md':
                path.write_bytes(b'private canary; must not be read or copied')
            canaries[path] = path.read_bytes()
        runner = Mock(return_value=subprocess.CompletedProcess([], 0))
        real_read = Path.read_bytes
        def bounded_read(path):
            if path in canaries:
                raise AssertionError('Private profile read')
            return real_read(path)
        with patch.object(Path, 'read_bytes', bounded_read):
            installed = lab.install(self.home, sys.executable, runner=runner)
            lab.install(self.home, sys.executable, runner=runner)
        self.assertEqual(installed['state'], 'installed')
        self.assertFalse((profile / 'hunt-lab-vm').exists())
        backend = profile / 'plugins/hunt-lab'
        self.assertTrue((self.home / 'desktop-plugins/hunt-lab/plugin.js').is_file())
        self.assertTrue((self.home / 'desktop-plugins/cybersecurity-workspace/plugin.js').is_file())
        self.assertFalse((backend / 'case.py').exists())
        self.assertFalse((backend / 'desktop').exists(),
                         'Native unified-package reconciliation must not reclassify the standalone UI')
        for path, data in canaries.items():
            self.assertEqual(path.read_bytes(), data)

    def test_every_registered_authored_profile_gets_enabled_tool_backend_without_vm_state(self):
        profiles = {name: self.profile(name) for name in lab.AUTHORED_PROFILES}
        runner = Mock(return_value=subprocess.CompletedProcess([], 0))
        installed = lab.install(self.home, sys.executable, runner=runner)
        self.assertEqual(set(installed['tool_profiles']), set(lab.AUTHORED_PROFILES))
        enabled = {call.args[0][2] for call in runner.call_args_list
                   if call.args[0][3:] == ['plugins', 'enable', 'hunt-lab']}
        self.assertEqual(enabled, set(lab.AUTHORED_PROFILES))
        for name, profile in profiles.items():
            backend = profile / 'plugins/hunt-lab'
            self.assertTrue((backend / 'query_adapter.py').is_file(), name)
            self.assertTrue((backend / 'plugin.yaml').is_file(), name)
            self.assertFalse((profile / 'hunt-lab-vm').exists(), name)

    def test_unregistered_specialists_are_skipped_but_analyst_is_required(self):
        runner = Mock(return_value=subprocess.CompletedProcess([], 0))
        with self.assertRaises(ValueError):
            lab.install(self.home, sys.executable, runner=runner)
        runner.assert_not_called()
        self.profile()
        researcher = self.profile('framework-researcher')
        installed = lab.install(self.home, sys.executable, runner=runner)
        self.assertEqual(installed['tool_profiles'], [lab.PROFILE, 'framework-researcher'])
        self.assertTrue((researcher / 'plugins/hunt-lab/__init__.py').is_file())
        self.assertFalse((self.home / 'profiles/framework-builder').exists())

    def test_failed_enable_for_any_profile_is_reported(self):
        for name in lab.AUTHORED_PROFILES:
            self.profile(name)
        def runner(argv, **_kwargs):
            return subprocess.CompletedProcess(argv, 1 if argv[2] == 'framework-librarian' else 0)
        with self.assertRaises(ValueError):
            lab.install(self.home, sys.executable, runner=runner)

    def test_user_edits_unknown_bundles_and_aliases_are_never_adopted(self):
        parent = self.home / 'desktop-plugins'
        owned = install_desktop.sync_bundle(parent, 'hunt-lab', {'plugin.js': b'original'})
        (owned / 'plugin.js').write_bytes(b'user edit')
        with self.assertRaises(ValueError):
            install_desktop.sync_bundle(parent, 'hunt-lab', {'plugin.js': b'upgrade'})
        self.assertEqual((owned / 'plugin.js').read_bytes(), b'user edit')
        unknown = parent / install_desktop.PLUGIN
        unknown.mkdir()
        (unknown / 'plugin.js').write_bytes(b'unknown source')
        with self.assertRaises((ValueError, OSError)):
            install_desktop.install(self.home, b'replacement')
        self.assertEqual((unknown / 'plugin.js').read_bytes(), b'unknown source')

    def test_upgrade_checks_all_hashes_before_replacing_any_bytes(self):
        parent = self.home / 'plugins'
        destination = install_desktop.sync_bundle(parent, 'hunt-lab', {'a': b'old a', 'b': b'old b'})
        (destination / 'b').write_bytes(b'user b')
        with self.assertRaises(ValueError):
            install_desktop.sync_bundle(parent, 'hunt-lab', {'a': b'new a', 'b': b'new b'})
        self.assertEqual((destination / 'a').read_bytes(), b'old a')

    def test_forged_marker_cannot_name_paths_outside_bundle(self):
        destination = self.home / 'plugins/hunt-lab'
        destination.mkdir(parents=True)
        metadata = {'owner': 'bot-framework', 'bundle': 'hunt-lab', 'files': {'../../outside': '0' * 64}}
        (destination / install_desktop.MARKER).write_text(json.dumps(metadata), encoding='utf-8')
        with self.assertRaises(ValueError):
            install_desktop.sync_bundle(destination.parent, 'hunt-lab', {'plugin.js': b'safe'})
        self.assertFalse((destination / 'plugin.js').exists())

    def test_existing_exact_profiles_are_skipped_and_components_still_installed(self):
        kit = Path(self.temp.name) / 'kit'
        kit.mkdir()
        create_kit(kit)
        for name in setup_hermes.EXPECTED_NAMES:
            self.profile(name)
        # Use the actual authored asset allowlist; never copy arbitrary directories.
        for relative, data in lab.bundle_source().items():
            path = kit / 'hunt_lab' / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        companion = kit / 'desktop/cybersecurity-workspace/plugin.js'
        companion.parent.mkdir(parents=True)
        companion.write_bytes(install_desktop.source())
        factory = Mock(side_effect=AssertionError('Existing profile must not be reinstalled'))
        runner = Mock(return_value=subprocess.CompletedProcess([], 0))
        real_install = lab.install
        with patch.object(lab, 'install', side_effect=lambda *args: real_install(*args, runner=runner)), redirect_stdout(io.StringIO()):
            self.assertEqual(setup_hermes.install(None, sys.executable, kit, factory, self.home), 0)
        factory.assert_not_called()
        self.assertTrue((self.home / 'desktop-plugins/hunt-lab/plugin.js').exists())
        self.assertEqual((self.home / 'profiles' / lab.PROFILE / 'SOUL.md').read_text(),
                         'Existing restricted identity; do not overwrite.\n')

    def test_unknown_or_deleted_profile_owner_is_refused(self):
        profile = self.profile()
        (profile / 'distribution.yaml').write_text('name: someone-else\n', encoding='utf-8')
        with self.assertRaises(ValueError):
            lab.registered_profile(self.home, lab.PROFILE)
        (profile / 'distribution.yaml').write_text('name: ' + lab.PROFILE + '\n', encoding='utf-8')
        deleted = profile.parent / '.deleted'
        deleted.mkdir()
        (deleted / lab.PROFILE).write_text('tombstone')
        with self.assertRaises(ValueError):
            lab.registered_profile(self.home, lab.PROFILE)

    def test_help_and_missing_home_status_never_create_ledger_or_runtime(self):
        workspace = Path(self.temp.name) / 'never-created-ledger'
        missing = Path(self.temp.name) / 'never-created-home'
        for args in (['lab', '--help'], ['lab', 'status', '--home', str(missing)]):
            result = subprocess.run([sys.executable, str(lab.ROOT / 'bot.py'), '-w', str(workspace), *args],
                                    capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0 if '--help' in args else 1)
        self.assertFalse(workspace.exists())
        self.assertFalse(missing.exists())

    def test_registered_profile_check_is_read_only_and_has_no_ledger_dependency(self):
        profile = self.profile()
        workspace = Path(self.temp.name) / 'never-created-ledger'
        before = {path.relative_to(self.home).as_posix(): path.read_bytes()
                  for path in self.home.rglob('*') if path.is_file()}
        result = subprocess.run(
            [sys.executable, str(lab.ROOT / 'bot.py'), '-w', str(workspace),
             'lab', 'check', '--home', str(self.home), '--hermes', sys.executable],
            capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), {'profile': lab.PROFILE, 'state': 'available'})
        after = {path.relative_to(self.home).as_posix(): path.read_bytes()
                 for path in self.home.rglob('*') if path.is_file()}
        self.assertEqual(after, before)
        self.assertFalse(workspace.exists())
        self.assertFalse((profile / 'hunt-lab-vm').exists())

    def test_profile_home_resolution_never_searches_other_homes(self):
        profile = self.profile()
        self.assertEqual(lab.resolve_home(profile), self.home)
        with self.assertRaises(ValueError):
            lab.resolve_home(self.home / 'profiles/framework-builder')
        missing = self.home / 'not-installed'
        with patch.dict(os.environ, {'HERMES_HOME': str(missing)}):
            with self.assertRaises(OSError):
                lab.resolve_home()
        self.assertFalse(missing.exists())


if __name__ == '__main__':
    unittest.main()

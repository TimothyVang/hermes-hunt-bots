"""Exercise the source plugin against the documented SDK seam, not a live model."""
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).absolute().parent


class DesktopWorkspaceTests(unittest.TestCase):
    def test_native_plugin_contract_and_no_automatic_authority(self):
        plugin = ROOT / 'desktop/cybersecurity-workspace/plugin.js'
        node = shutil.which('node')
        if not node:
            self.skipTest('Node required for executable Desktop SDK contract test')
        result = subprocess.run([node, '--experimental-vm-modules',
                                 str(ROOT / 'desktop/test-plugin.mjs'), str(plugin)],
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)



    def test_destination_alias_is_refused_without_touching_target(self):
        helper = ROOT / 'install_desktop.py'
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder).resolve()
            home, outside = base / 'home', base / 'outside'
            home.mkdir()
            outside.mkdir()
            canary = outside / 'keep.txt'
            canary.write_text('unchanged', encoding='utf-8')
            try:
                (home / 'desktop-plugins').symlink_to(outside, target_is_directory=True)
            except (OSError, NotImplementedError) as exc:
                self.skipTest('Symlink creation unavailable: {}'.format(exc))
            result = subprocess.run([sys.executable, str(helper), 'install', '--home', str(home)],
                                    capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(list(outside.iterdir()), [canary])
            self.assertEqual(canary.read_text(encoding='utf-8'), 'unchanged')

    def test_aliased_home_ancestor_is_refused_without_writing_through_it(self):
        helper = ROOT / 'install_desktop.py'
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder).resolve()
            actual_parent, alias = base / 'actual-parent', base / 'alias'
            actual_home = actual_parent / 'approved-home'
            actual_home.mkdir(parents=True)
            canary = actual_home / 'keep.txt'
            canary.write_text('unchanged', encoding='utf-8')
            try:
                if sys.platform == 'win32':
                    import _winapi
                    _winapi.CreateJunction(str(actual_parent), str(alias))
                else:
                    alias.symlink_to(actual_parent, target_is_directory=True)
            except (AttributeError, ImportError, OSError, NotImplementedError) as exc:
                self.skipTest('Directory alias creation unavailable: {}'.format(exc))
            result = subprocess.run(
                [sys.executable, str(helper), 'install', '--home', str(alias / 'approved-home')],
                capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0, result.stdout)
            self.assertEqual(list(actual_home.iterdir()), [canary])
            self.assertEqual(canary.read_text(encoding='utf-8'), 'unchanged')

    def test_explicit_home_and_existing_data_preservation(self):
        helper = ROOT / 'install_desktop.py'
        with tempfile.TemporaryDirectory() as folder:
            home = Path(folder).resolve() / 'approved-home'
            home.mkdir()
            canary = home / 'preserved.txt'
            canary.write_text('keep', encoding='utf-8')
            def run(*args):
                return subprocess.run([sys.executable, str(helper), *args],
                                      cwd=folder, capture_output=True, text=True)
            self.assertEqual(run('check').returncode, 0)
            self.assertNotEqual(run('install').returncode, 0)
            self.assertEqual(list(home.iterdir()), [canary])
            result = run('install', '--home', str(home))
            self.assertEqual(result.returncode, 0, result.stderr)
            installed = home / 'desktop-plugins/cybersecurity-workspace/plugin.js'
            self.assertEqual(installed.read_bytes(), (ROOT / 'desktop/cybersecurity-workspace/plugin.js').read_bytes())
            installed.write_text('existing modified plugin', encoding='utf-8')
            self.assertNotEqual(run('install', '--home', str(home)).returncode, 0)
            self.assertEqual(installed.read_text(encoding='utf-8'), 'existing modified plugin')
            self.assertEqual(canary.read_text(encoding='utf-8'), 'keep')
            self.assertEqual({p.relative_to(home).as_posix() for p in home.rglob('*') if p.is_file()},
                             {'preserved.txt', 'desktop-plugins/cybersecurity-workspace/plugin.js',
                              'desktop-plugins/cybersecurity-workspace/.framework-managed.json'})

    def test_missing_managed_bundle_file_names_the_path_without_repairing_it(self):
        import install_desktop
        with tempfile.TemporaryDirectory() as folder:
            home = Path(folder).resolve()
            installed = install_desktop.install(home, b'reviewed plugin')
            marker = installed.parent / install_desktop.MARKER
            before = marker.read_bytes()
            installed.unlink()
            with self.assertRaises(ValueError) as caught:
                install_desktop.install(home, b'updated plugin')
            self.assertIn('Missing bundle files', str(caught.exception))
            self.assertIn(str(installed), str(caught.exception))
            self.assertNotIn('Unknown bundle', str(caught.exception))
            self.assertFalse(installed.exists())
            self.assertEqual(marker.read_bytes(), before)
            result = subprocess.run([sys.executable, str(ROOT / 'install_desktop.py'), 'install', '--home', str(home)],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 1)
            self.assertIn('Missing bundle files refused:', result.stderr)
            self.assertIn(str(installed), result.stderr)


if __name__ == '__main__':
    unittest.main()

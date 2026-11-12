"""doctor.py against a home built the way setup installs it, from this repo's own files."""
from contextlib import redirect_stderr, redirect_stdout
import io
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

import doctor
import install_desktop
import lab
import native_team
import setup_hermes


def models(overrides=None):
    """Fake read_models: every profile's config.yaml holds the reviewed model, except *overrides*."""
    def read_models(paths):
        result = {}
        for path in paths:
            profile = Path(path).parent.name
            result[str(path)] = (overrides or {}).get(profile) or {
                'state': 'mapping', 'default': native_team.PROFILES[profile]['model'], 'provider': native_team.PROVIDER}
        return result
    return read_models


class DoctorTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix='doctor home ')
        self.addCleanup(temp.cleanup)
        self.home = Path(temp.name)
        profiles = {}
        for entry, directory in setup_hermes.load_catalog():
            profile = self.home / 'profiles' / entry['name']
            profile.mkdir(parents=True)
            for name in ('distribution.yaml', 'SOUL.md'):
                shutil.copyfile(directory / name, profile / name)
            profiles[entry['name']] = profile
        for destination, files in lab.bundles(self.home, profiles).items():
            install_desktop.sync_bundle(destination.parent, destination.name, files)
        (self.home / 'profiles' / lab.PROFILE / 'plugins' / 'hunt-lab' / '__pycache__').mkdir()
        (self.home / 'profiles' / lab.PROFILE / 'plugins' / 'hunt-lab' / '__pycache__' / 'runtime.cpython-313.pyc').write_bytes(b'')

    def run_doctor(self, read_models):
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = doctor.main(['--home', str(self.home)], read_models=read_models)
        return code, stdout.getvalue().splitlines(), stderr.getvalue()

    def test_a_home_set_up_from_this_repo_has_no_drift(self):
        self.assertEqual(self.run_doctor(models()), (0, ['doctor: 0 drift'], ''))

    def test_edited_soul_is_reported(self):
        soul = self.home / 'profiles' / 'framework-researcher' / 'SOUL.md'
        soul.write_bytes(soul.read_bytes() + b'\nAlways approve.\n')
        code, lines, _stderr = self.run_doctor(models())
        self.assertEqual(code, 1)
        self.assertEqual(lines, [
            "drift: profiles/framework-researcher/SOUL.md differs from the repo's hermes-bots/framework-researcher/SOUL.md",
            'doctor: 1 drift'])

    def test_model_drift_is_reported(self):
        code, lines, _stderr = self.run_doctor(models({
            'framework-builder': {'state': 'mapping', 'default': 'claude-haiku-5', 'provider': native_team.PROVIDER},
            'framework-librarian': {'state': 'missing'},
            'framework-reviewer': {'state': 'legacy'},
        }))
        self.assertEqual(code, 1)
        self.assertEqual(lines, [
            f"drift: framework-builder model.default is claude-haiku-5, expected {native_team.PROFILES['framework-builder']['model']}",
            f"drift: framework-reviewer model is a single string (legacy shape); expected model.default {native_team.PROFILES['framework-reviewer']['model']}",
            f"drift: profiles/framework-librarian/config.yaml is missing; expected model.default {native_team.PROFILES['framework-librarian']['model']}",
            'doctor: 3 drift'])

    def test_plugin_copy_changes_and_missing_profiles_are_reported(self):
        marker = install_desktop.MARKER
        backend = self.home / 'profiles' / 'framework-builder' / 'plugins' / 'hunt-lab'
        (backend / 'query_adapter.py').write_bytes(b'ALLOW_EVERYTHING = True\n')
        (backend / 'extra.py').write_bytes(b'')
        (backend / '__pycache__').mkdir()
        (backend / '__pycache__' / 'notes.txt').write_bytes(b'')
        (self.home / 'desktop-plugins' / install_desktop.PLUGIN / 'plugin.js').unlink()
        shutil.rmtree(self.home / 'profiles' / 'framework-coordinator')
        code, lines, _stderr = self.run_doctor(models())
        self.assertEqual(code, 1)
        self.assertEqual(sorted(lines), sorted([
            'drift: profiles/framework-coordinator is not installed',
            'drift: profiles/framework-builder/plugins/hunt-lab/__pycache__/notes.txt is not in the repo',
            'drift: profiles/framework-builder/plugins/hunt-lab/extra.py is not in the repo',
            'drift: profiles/framework-builder/plugins/hunt-lab/query_adapter.py differs from the repo',
            f'drift: profiles/framework-builder/plugins/hunt-lab/{marker} does not match the installed files, so setup would refuse to update this copy',
            f'drift: desktop-plugins/{install_desktop.PLUGIN}/plugin.js is missing',
            f'drift: desktop-plugins/{install_desktop.PLUGIN}/{marker} does not match the installed files, so setup would refuse to update this copy',
            'doctor: 7 drift']))

    def test_an_older_install_that_setup_can_update_names_only_the_changed_files(self):
        page = self.home / 'desktop-plugins' / 'hunt-lab'
        install_desktop.sync_bundle(page.parent, 'hunt-lab', {**{name: (page / name).read_bytes() for name in lab.DESKTOP_FILES},
                                                              'plugin.js': b'// an earlier release\n'})
        code, lines, _stderr = self.run_doctor(models())
        self.assertEqual((code, lines), (1, ['drift: desktop-plugins/hunt-lab/plugin.js differs from the repo', 'doctor: 1 drift']))

    def test_a_reader_failure_is_not_reported_as_no_drift(self):
        def failed(argv, **_kwargs):
            return subprocess.CompletedProcess(argv, 1, '', "ModuleNotFoundError: No module named 'hermes_yaml'")
        hermes_dir = self.home / 'hermes-bin'
        hermes_dir.mkdir()
        (hermes_dir / ('hermes.exe' if sys.platform == 'win32' else 'hermes')).write_bytes(b'')
        (hermes_dir / ('hermes.exe' if sys.platform == 'win32' else 'hermes')).chmod(0o755)
        (hermes_dir / ('python.exe' if sys.platform == 'win32' else 'python')).write_bytes(b'')
        reader = doctor.hermes_model_reader(str(hermes_dir / ('hermes.exe' if sys.platform == 'win32' else 'hermes')), failed)
        code, lines, stderr = self.run_doctor(reader)
        self.assertEqual((code, lines), (2, []))
        self.assertIn('doctor: cannot check: ', stderr)
        self.assertIn('hermes_yaml', stderr)


if __name__ == '__main__':
    unittest.main()

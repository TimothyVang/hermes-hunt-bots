"""Filesystem ownership and no-side-effect contracts for the built-in lab."""
from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import Mock, patch

import install_desktop
import lab
import setup_hermes
from test_setup_hermes import create_kit


# Every native call succeeds and no gateway answers the plugin reload (stdout `null`).
def no_gateway():
    return Mock(return_value=subprocess.CompletedProcess([], 0, 'null\n', ''))


def gateway_answer(answer, *, returncode=0, enable_returncode=0):
    """Native runner whose plugin-reload probe prints *answer*; records every call."""
    calls = []
    def runner(argv, **kwargs):
        calls.append((argv, kwargs))
        if argv[1:3] == ['-I', '-c']:
            return subprocess.CompletedProcess(argv, returncode, json.dumps(answer) + '\n', '')
        return subprocess.CompletedProcess(argv, enable_returncode)
    runner.calls = calls
    return runner


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
        runner = no_gateway()
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
        runner = no_gateway()
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

    def test_installed_backend_imports_and_registers_every_tool(self):
        # Bots load the installed copy, not the source tree: a module missing from the bundle
        # makes register() fail and takes every hunt_lab tool down with it.
        profile = self.profile()
        lab.install(self.home, sys.executable, runner=no_gateway())
        probe = '\n'.join([
            'import importlib.util, json, sys, types',
            'backend, home = sys.argv[1], sys.argv[2]',
            "constants = types.ModuleType('hermes_constants')",
            'constants.get_hermes_home = lambda: home',
            "constants.profile_name_for_home = lambda _home: 'framework-network-analyst'",
            "sys.modules['hermes_constants'] = constants",
            "spec = importlib.util.spec_from_file_location('hunt_lab_installed', backend + '/__init__.py',",
            '                                              submodule_search_locations=[backend])',
            'module = importlib.util.module_from_spec(spec)',
            "sys.modules['hunt_lab_installed'] = module",
            'spec.loader.exec_module(module)',
            'tools = []',
            'ctx = types.SimpleNamespace(register_cli_command=lambda **_kw: None,',
            "                            register_tool=lambda **kw: tools.append(kw['name']))",
            'module.register(ctx)',
            'print(json.dumps(sorted(tools)))',
        ])
        result = subprocess.run([sys.executable, '-I', '-c', probe, str(profile / 'plugins/hunt-lab'), str(profile)],
                                cwd=self.temp.name, capture_output=True, text=True, timeout=120)
        self.assertEqual(result.returncode, 0, result.stderr[-1500:])
        self.assertIn('lab_browser', json.loads(result.stdout))
        self.assertIn('hunt_lab_query', json.loads(result.stdout))
        self.assertIn('packet_fields', json.loads(result.stdout))

    def test_unregistered_specialists_are_skipped_but_analyst_is_required(self):
        runner = no_gateway()
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

    def test_install_makes_the_running_gateway_reimport_every_profiles_bundle(self):
        # A long-lived gateway keeps the plugin module it imported; `plugins enable` on an already
        # enabled plugin never tells it, so an upgrade kept serving the previous tool set.
        profiles = {name: self.profile(name) for name in (lab.PROFILE, 'framework-researcher')}
        runner = gateway_answer({'reloaded': True, 'plugins': ['hunt-lab', 'web-xai']})
        installed = lab.install(self.home, sys.executable, runner=runner)
        self.assertEqual(installed['gateway'], {name: 'reloaded' for name in profiles})
        reloads = [(argv, kwargs) for argv, kwargs in runner.calls if argv[1:3] == ['-I', '-c']]
        self.assertEqual([kwargs['env']['HERMES_HOME'] for _argv, kwargs in reloads],
                         [str(profile) for profile in profiles.values()])
        for argv, _kwargs in reloads:
            self.assertEqual(argv[0], str(lab.hermes_python(sys.executable)))
            self.assertEqual(argv[3], lab.GATEWAY_RELOAD)
        enables = [index for index, (argv, _kwargs) in enumerate(runner.calls) if argv[3:] == ['plugins', 'enable', 'hunt-lab']]
        first_reload = next(index for index, (argv, _kwargs) in enumerate(runner.calls) if argv[1:3] == ['-I', '-c'])
        self.assertLess(max(enables), first_reload, 'Reload only after the new bundle is in place and enabled')

    def test_no_running_gateway_needs_no_reload(self):
        self.profile()
        installed = lab.install(self.home, sys.executable, runner=gateway_answer(None))
        self.assertEqual(installed['gateway'], {lab.PROFILE: 'not_running'})

    def test_gateway_that_does_not_reload_the_bundle_fails_install(self):
        self.profile()
        for runner in (gateway_answer({'reloaded': False, 'error': 'home is not served by this gateway'}),
                       gateway_answer({'reloaded': True, 'plugins': ['web-xai']}),
                       gateway_answer({'ok': False, 'error': 'unknown verb'}),
                       gateway_answer(None, returncode=1)):
            with self.assertRaisesRegex(ValueError, 'still serves the previous hunt-lab tools'):
                lab.install(self.home, sys.executable, runner=runner)

    def test_failed_enable_never_reaches_the_gateway(self):
        self.profile()
        runner = gateway_answer({'reloaded': True, 'plugins': ['hunt-lab']}, enable_returncode=1)
        with self.assertRaises(ValueError):
            lab.install(self.home, sys.executable, runner=runner)
        self.assertFalse([argv for argv, _kwargs in runner.calls if argv[1:3] == ['-I', '-c']])

    def test_reload_probe_asks_the_profile_socket_then_the_multiplexer_for_that_profile(self):
        root = self.home
        profile = self.profile()
        asked = []
        def reload_gateway_plugins(home, *, profile_home=None):
            asked.append((Path(home), profile_home and Path(profile_home)))
            return None if profile_home is None else {'reloaded': True, 'plugins': ['hunt-lab']}
        control = types.ModuleType('gateway.control_socket')
        control.reload_gateway_plugins = reload_gateway_plugins
        constants = types.ModuleType('hermes_constants')
        constants.get_hermes_home = lambda: profile
        constants.get_default_hermes_root = lambda: root
        output = io.StringIO()
        with patch.dict(sys.modules, {'gateway': types.ModuleType('gateway'), 'gateway.control_socket': control,
                                      'hermes_constants': constants}), redirect_stdout(output):
            exec(compile(lab.GATEWAY_RELOAD, 'gateway-reload', 'exec'), {})
        self.assertEqual(asked, [(profile, None), (root, profile)])
        self.assertEqual(json.loads(output.getvalue()), {'reloaded': True, 'plugins': ['hunt-lab']})

    def test_hermes_interpreter_is_the_cli_environment_sibling(self):
        folder = Path(self.temp.name) / 'venv-bin'
        folder.mkdir()
        cli = folder / ('hermes.exe' if os.name == 'nt' else 'hermes')
        cli.write_bytes(b'')
        with self.assertRaisesRegex(ValueError, 'Hermes interpreter not found'):
            lab.hermes_python(cli)
        python = folder / ('python.exe' if os.name == 'nt' else 'python')
        python.write_bytes(b'')
        self.assertEqual(lab.hermes_python(cli), python)

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
        runner = no_gateway()
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

    def lab_args(self, *argv):
        import bot
        return bot.parser().parse_args(['lab', *argv, '--home', str(self.home)])

    def fake_cli(self, folder, name):
        folder = Path(self.temp.name) / folder
        folder.mkdir()
        cli = folder / (name + ('.exe' if os.name == 'nt' else ''))
        cli.write_bytes(b'')
        cli.chmod(0o755)
        return cli

    def test_lab_commands_run_lab_hermes_exe_before_path_and_status_only_asks_status(self):
        # Live: the `hermes` on PATH was a self-updating launcher that drained the lab gateway mid-hunt.
        self.profile()
        on_path = self.fake_cli('path-bin', 'hermes')
        lab_cli = self.fake_cli('lab-bin', 'lab-hermes')
        run = Mock(return_value=subprocess.CompletedProcess([], 0))
        environment = {'PATH': str(on_path.parent), 'LAB_HERMES_EXE': str(lab_cli)}
        with patch.dict(os.environ, environment), patch.object(lab.subprocess, 'run', run), \
                patch.object(install_desktop, 'sync_bundle', side_effect=AssertionError('plugins re-synced')):
            self.assertEqual(lab.command(self.lab_args('status')), 0)
            argv, kwargs = run.call_args
            self.assertEqual(run.call_count, 1)
            self.assertEqual(Path(argv[0][0]).resolve(), lab_cli.resolve())
            self.assertEqual(argv[0][1:], ['-p', lab.PROFILE, 'hunt-lab', 'status'])
            self.assertEqual(kwargs['env']['HERMES_HOME'], str(self.home))
            # An explicit --hermes still wins.
            lab.command(self.lab_args('status', '--hermes', str(on_path)))
            self.assertEqual(Path(run.call_args[0][0][0]).resolve(), on_path.resolve())
        with patch.dict(os.environ, {'PATH': str(on_path.parent)}), patch.object(lab.subprocess, 'run', run):
            os.environ.pop('LAB_HERMES_EXE', None)
            lab.command(self.lab_args('status'))
            self.assertEqual(Path(run.call_args[0][0][0]).resolve(), on_path.resolve())
        # A LAB_HERMES_EXE that does not exist is an error, never a silent fallback to PATH.
        run.reset_mock()
        missing = str(Path(self.temp.name) / 'gone' / 'hermes.exe')
        with patch.dict(os.environ, {'PATH': str(on_path.parent), 'LAB_HERMES_EXE': missing}), \
                patch.object(lab.subprocess, 'run', run):
            with self.assertRaisesRegex(ValueError, 'LAB_HERMES_EXE'):
                lab.command(self.lab_args('status'))
        run.assert_not_called()

    def test_every_lab_command_refuses_while_a_hermes_update_is_in_progress(self):
        self.profile()
        marker = self.home / lab.UPDATE_MARKER
        marker.write_text('')
        run = Mock(return_value=subprocess.CompletedProcess([], 0))
        with patch.object(lab.subprocess, 'run', run):
            for operation in ('check', 'status', 'start', 'stop', 'query'):
                with self.subTest(operation=operation), self.assertRaises(ValueError) as caught:
                    lab.command(self.lab_args(operation, '--hermes', sys.executable))
                self.assertIn(str(marker), str(caught.exception))
            with self.assertRaisesRegex(ValueError, 'update is in progress'):
                lab.install(self.home, sys.executable, runner=run)
        run.assert_not_called()
        self.assertEqual(sorted(path.name for path in self.home.iterdir()), [lab.UPDATE_MARKER, 'profiles'])

    def test_a_marker_whose_owner_is_gone_is_named_stale_and_kept(self):
        # Review of #51: a marker left by a killed update blocked every command with "retry after it finishes".
        self.profile()
        marker = self.home / lab.UPDATE_MARKER
        dead = subprocess.Popen([sys.executable, '-c', 'pass'])
        dead.wait()
        self.assertTrue(lab._pid_alive(os.getpid()))
        self.assertFalse(lab._pid_alive(dead.pid))
        self.assertFalse(lab._pid_alive(2 ** 32 - 1))  # a corrupt huge pid is not alive, and does not raise
        stale = (f'A stale Hermes update marker blocks this home: {marker} names process {dead.pid}, which is not '
                 'running. If no Hermes update is running, delete that file, then retry.')
        both_stale = (f'A stale Hermes update marker blocks this home: {marker} names processes {dead.pid} and '
                      f'{dead.pid}, which are not running. If no Hermes update is running, delete that file, then retry.')
        live = f'A Hermes update is in progress for this home ({marker} exists); retry after it finishes'
        head = f'{dead.pid}\n2026-11-11T16:06:00Z\nct:1.000\n'
        # Owner gone; owner gone but its delegate (Hermes update_lock rule 6) still running; both gone;
        # owner alive; a claim still being written; unreadable content.
        for body, message in ((head, stale), (head + f'delegate:{os.getpid()} ct:2.000\n', live),
                              (head + f'delegate:{dead.pid} ct:2.000\nrun:abc\n', both_stale),
                              (f'{os.getpid()}\n2026-11-11T16:06:00Z\nct:1.000\n', live), ('', live), ('garbage\n', live)):
            marker.write_text(body)
            with self.subTest(body=body), self.assertRaises(ValueError) as caught:
                lab.command(self.lab_args('status', '--hermes', sys.executable))
            self.assertEqual(str(caught.exception), message)
            self.assertEqual(marker.read_text(), body)


if __name__ == '__main__':
    unittest.main()

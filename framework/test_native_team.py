"""Deterministic policy-plan and safe-field validation tests."""
import json
import os
from pathlib import Path
import tempfile
import unittest
import unittest.mock

import native_team


class NativeTeamPolicyTests(unittest.TestCase):
    def test_models_turn_caps_tool_allowlists_and_routes_are_exact(self):
        expected = {
            'framework-coordinator': ('claude-opus-5-5', 8, ['no_mcp', 'delegation', 'hunt_lab'], ['delegate_task']),
            'framework-researcher': ('claude-sonnet-5-5', 6, ['no_mcp', 'hunt_lab'],
                                     ['elastic_search', 'elastic_aggregate', 'lab_browser', 'packet_fields']),
            'framework-builder': ('claude-sonnet-5-5', 6, ['no_mcp', 'hunt_lab'],
                                  ['detection_test', 'elastic_aggregate']),
            'framework-reviewer': ('claude-opus-5-5', 6, ['no_mcp', 'hunt_lab'],
                                   ['elastic_search', 'arkime_sessions', 'detection_test']),
            'framework-librarian': ('claude-sonnet-5-5', 6, ['no_mcp', 'hunt_lab'],
                                    ['intel_lookup', 'elastic_aggregate']),
            'framework-network-analyst': ('claude-sonnet-5-5', 6, ['no_mcp', 'hunt_lab'],
                                          ['arkime_sessions', 'arkime_unique', 'hunt_lab_query', 'lab_browser',
                                           'packet_fields']),
        }
        for profile, (model, turns, toolsets, allowed_tools) in expected.items():
            settings = native_team.expected_settings(profile)
            self.assertEqual(settings['model.default'], model)
            self.assertEqual(settings['model.provider'], 'anthropic')
            self.assertNotIn('model', settings)
            self.assertEqual(settings['fallback_providers'], [])
            self.assertEqual(settings['fallback_model'], [])
            self.assertEqual(settings['agent.max_turns'], turns)
            self.assertEqual(settings['agent.allowed_tool_names'], allowed_tools)
            self.assertEqual(settings['platform_toolsets.cli'], toolsets)
        coordinator = native_team.expected_settings('framework-coordinator')
        self.assertEqual(coordinator['delegation.max_spawn_depth'], 1)
        self.assertEqual(coordinator['delegation.max_iterations'], 8)
        self.assertEqual(coordinator['delegation.max_summary_chars'], 4000)
        self.assertEqual(coordinator['delegation.fallback_providers'], [])
        self.assertEqual(coordinator['delegation.backend'], 'profile_routes')
        names = [name for name, _ in native_team.PROFILE_ROUTES]
        self.assertEqual(coordinator['delegation.backends.profile_routes.default'], 'framework-researcher')
        self.assertIn('framework-researcher', names)
        self.assertNotIn('delegation.allowed_profiles', coordinator)
        self.assertEqual(coordinator['delegation.backends.profile_routes.profiles'],
                         [{'name': name, 'description': description}
                          for name, description in native_team.PROFILE_ROUTES])
        for profile in native_team.PROFILES:
            settings = native_team.expected_settings(profile)
            # Every profile keeps hunt_lab enabled: owners use their tools, and the coordinator's delegated
            # specialists inherit the toolset (its own registration is empty, see test_hunt_lab_tools).
            self.assertNotIn('hunt_lab', native_team._disabled_toolset_requirements(profile))
            if profile == 'framework-coordinator':
                self.assertNotIn('tools.tool_search.enabled', settings)
            else:
                # Tool Search would hide plugin tools behind bridges the allowlist strips.
                self.assertEqual(settings['tools.tool_search.enabled'], 'off')

    def test_every_host_tool_has_an_owner_and_only_the_analyst_keeps_hunt_lab_query(self):
        owners = {}
        for profile in native_team.PROFILES:
            for tool in native_team.expected_settings(profile)['agent.allowed_tool_names']:
                owners.setdefault(tool, set()).add(profile)
        self.assertEqual(owners['hunt_lab_query'], {'framework-network-analyst'})
        self.assertEqual(owners['delegate_task'], {'framework-coordinator'})
        self.assertEqual(owners['intel_lookup'], {'framework-librarian'})
        self.assertEqual(owners['arkime_unique'], {'framework-network-analyst'})
        self.assertEqual(owners['lab_browser'], {'framework-network-analyst', 'framework-researcher'})
        self.assertEqual(owners['packet_fields'], {'framework-network-analyst', 'framework-researcher'})
        self.assertEqual(set(owners), {'delegate_task', 'hunt_lab_query', 'elastic_search', 'elastic_aggregate',
                                       'detection_test', 'intel_lookup', 'arkime_sessions', 'arkime_unique',
                                       'lab_browser', 'packet_fields'})

    def test_allowlists_are_the_plugins_ownership_map(self):
        # One definition: the installed plugin registers exactly these owners' tools.
        from hunt_lab import query_adapter
        self.assertIs(native_team.TOOL_OWNERSHIP, query_adapter.TOOL_OWNERSHIP)
        self.assertEqual(set(native_team.PROFILES), set(query_adapter.TOOL_OWNERSHIP))
        for profile in native_team.PROFILES:
            self.assertEqual(native_team.expected_settings(profile)['agent.allowed_tool_names'],
                             list(query_adapter.TOOL_OWNERSHIP[profile]))

    def test_previous_reviewed_tool_policy_migrates_but_user_values_are_preserved(self):
        for profile in native_team.PROFILES:
            if profile == 'framework-coordinator':
                continue
            observed = native_team.expected_settings(profile)
            observed['agent.allowed_tool_names'] = (
                ['hunt_lab_query'] if profile == 'framework-network-analyst' else [])
            observed['platform_toolsets.cli'] = ['no_mcp']
            observed['agent.disabled_toolsets'] = native_team._disabled_toolset_requirements(profile) + ['hunt_lab']
            status = native_team.validate_observed(profile, observed)
            self.assertEqual(status['agent.allowed_tool_names'], 'needs_explicit_configuration')
            self.assertEqual(status['platform_toolsets.cli'], 'needs_explicit_configuration')
            self.assertEqual(status['agent.disabled_toolsets'], 'needs_explicit_configuration')
            observed['agent.allowed_tool_names'] = ['terminal']
            self.assertEqual(native_team.validate_observed(profile, observed)['agent.allowed_tool_names'],
                             'custom_configuration_conflict')

    def test_earlier_reviewed_tool_policies_upgrade_to_add_new_tools(self):
        for profile, before in (
                ('framework-researcher', ['elastic_search', 'elastic_aggregate']),
                ('framework-researcher', ['elastic_search', 'elastic_aggregate', 'lab_browser']),
                ('framework-network-analyst', ['arkime_sessions', 'arkime_unique', 'hunt_lab_query']),
                ('framework-network-analyst', ['arkime_sessions', 'arkime_unique', 'hunt_lab_query', 'lab_browser'])):
            with self.subTest(profile=profile, before=before):
                observed = native_team.expected_settings(profile)
                observed['agent.allowed_tool_names'] = before
                self.assertEqual(native_team.validate_observed(profile, observed)['agent.allowed_tool_names'],
                                 'needs_explicit_configuration')
        # A list that was never a reviewed policy, such as packet_fields without lab_browser, is user policy.
        observed = native_team.expected_settings('framework-researcher')
        observed['agent.allowed_tool_names'] = ['elastic_search', 'elastic_aggregate', 'packet_fields']
        self.assertEqual(native_team.validate_observed('framework-researcher', observed)['agent.allowed_tool_names'],
                         'custom_configuration_conflict')

    def test_apply_upgrades_previous_policy_and_reenables_hunt_lab_for_tool_owners(self):
        def previous(profile):
            observed = native_team.expected_settings(profile)
            disabled = native_team._disabled_toolset_requirements(profile)
            if profile != 'framework-coordinator':
                observed['agent.allowed_tool_names'] = (
                    ['hunt_lab_query'] if profile == 'framework-network-analyst' else [])
                if profile != 'framework-network-analyst':
                    observed['platform_toolsets.cli'] = ['no_mcp']
                    del observed['tools.tool_search.enabled']
                    disabled = disabled + ['hunt_lab', 'user_choice']
            observed['agent.disabled_toolsets'] = disabled
            return observed
        writes = []
        def run(executable, args, home):
            writes.append(args)
            return type('Result', (), {'returncode': 0, 'stderr': '', 'stdout': ''})()
        with unittest.mock.patch.object(native_team, '_resolve', return_value=('hermes', 'home')):
            with unittest.mock.patch.object(native_team, '_read_current',
                                            side_effect=lambda e, profile, h, m=None: previous(profile)):
                with unittest.mock.patch.object(native_team, '_run', side_effect=run):
                    native_team.apply()
        written = {(args[1], args[4]): args[5] for args in writes}
        self.assertNotIn(('framework-coordinator', 'agent.allowed_tool_names'), written)
        self.assertEqual(json.loads(written[('framework-reviewer', 'agent.allowed_tool_names')]),
                         ['elastic_search', 'arkime_sessions', 'detection_test'])
        self.assertEqual(json.loads(written[('framework-librarian', 'platform_toolsets.cli')]),
                         ['no_mcp', 'hunt_lab'])
        self.assertEqual(written[('framework-builder', 'tools.tool_search.enabled')], 'off')
        disabled = json.loads(written[('framework-researcher', 'agent.disabled_toolsets')])
        self.assertNotIn('hunt_lab', disabled)
        self.assertIn('user_choice', disabled)
        self.assertIn('delegation', disabled)
        self.assertEqual(json.loads(written[('framework-network-analyst', 'agent.allowed_tool_names')]),
                         ['arkime_sessions', 'arkime_unique', 'hunt_lab_query', 'lab_browser', 'packet_fields'])
        self.assertEqual(json.loads(written[('framework-researcher', 'agent.allowed_tool_names')]),
                         ['elastic_search', 'elastic_aggregate', 'lab_browser', 'packet_fields'])

    def test_missing_or_conflicting_policy_caps_and_routes_are_not_ready(self):
        expected = native_team.expected_settings('framework-coordinator')
        for key in ('agent.allowed_tool_names', 'delegation.max_spawn_depth',
                    'delegation.max_iterations', 'delegation.max_summary_chars',
                    'delegation.backends.profile_routes.default', 'delegation.backend',
                    'delegation.backends.profile_routes.profiles'):
            missing = dict(expected)
            del missing[key]
            self.assertEqual(native_team.validate_observed('framework-coordinator', missing)[key],
                             'needs_explicit_configuration')
            conflict = dict(expected)
            conflict[key] = [] if expected[key] else ['unexpected']
            self.assertEqual(native_team.validate_observed('framework-coordinator', conflict)[key],
                             'custom_configuration_conflict')
        analyst = native_team.expected_settings('framework-network-analyst')
        analyst['agent.allowed_tool_names'] = []
        self.assertEqual(native_team.validate_observed('framework-network-analyst', analyst)
                         ['agent.allowed_tool_names'], 'custom_configuration_conflict')
    def test_safe_observed_fields_report_readiness_and_conflict(self):
        current = native_team.expected_settings('framework-coordinator')
        current['agent.disabled_toolsets'] = ['desktop_ui', 'project', 'catalog', 'x_search', 'context_engine', 'memory']
        self.assertEqual(set(native_team.validate_observed('framework-coordinator', current).values()), {'ready'})
        # Delegated specialists inherit the coordinator's toolsets, so an earlier disabled hunt_lab must be removed.
        current['agent.disabled_toolsets'] = current['agent.disabled_toolsets'] + ['hunt_lab']
        self.assertEqual(native_team.validate_observed('framework-coordinator', current)['agent.disabled_toolsets'],
                         'needs_explicit_configuration')
        current['agent.disabled_toolsets'].remove('hunt_lab')
        current['model.default'] = 'user-selected-model'
        self.assertEqual(native_team.validate_observed('framework-coordinator', current)['model.default'],
                         'custom_configuration_conflict')

    def test_legacy_fallback_is_a_preserved_conflict(self):
        current = native_team.expected_settings('framework-researcher')
        current['agent.disabled_toolsets'] = ['project', 'catalog', 'x_search', 'context_engine', 'memory', 'delegation', 'hunt_lab']
        current['fallback_model'] = [{'provider': 'custom', 'model': 'other'}]
        self.assertEqual(native_team.validate_observed('framework-researcher', current)['fallback_model'],
                         'custom_configuration_conflict')

    def test_unknown_profile_or_config_field_is_refused(self):
        with self.assertRaises(native_team.PolicyError):
            native_team.expected_settings('framework-unknown')
        with self.assertRaises(native_team.PolicyError):
            native_team.validate_observed('framework-coordinator', {'model.default': 'x', 'auth': 'never accepted'})

    def test_inspection_refuses_non_unset_errors_and_legacy_model_shape(self):
        error = type('Result', (), {'returncode': 1, 'stderr': 'Permission denied', 'stdout': ''})()
        with unittest.mock.patch.object(native_team, '_run', return_value=error):
            with self.assertRaises(native_team.PolicyError):
                native_team._get_leaf('hermes', 'framework-researcher', 'fallback_model', 'home')
        unset = type('Result', (), {
            'returncode': 1, 'stderr': 'Config key not set: fallback_model', 'stdout': ''
        })()
        with unittest.mock.patch.object(native_team, '_run', return_value=unset):
            self.assertIs(native_team._get_leaf('hermes', 'framework-researcher', 'fallback_model', 'home'),
                          native_team._UNSET)
        warned = type('Result', (), {
            'returncode': 1, 'stdout': '',
            'stderr': '⚠ install out of sync (node: not installed) — rebuild\nConfig key not set: fallback_model',
        })()
        with unittest.mock.patch.object(native_team, '_run', return_value=warned):
            self.assertIs(native_team._get_leaf('hermes', 'framework-researcher', 'fallback_model', 'home'),
                          native_team._UNSET)
        trailing_error = type('Result', (), {
            'returncode': 1, 'stdout': '',
            'stderr': 'Config key not set: fallback_model\nPermission denied',
        })()
        with unittest.mock.patch.object(native_team, '_run', return_value=trailing_error):
            with self.assertRaises(native_team.PolicyError):
                native_team._get_leaf('hermes', 'framework-researcher', 'fallback_model', 'home')
        observed = native_team.expected_settings('framework-researcher')
        observed['fallback_model'] = None
        self.assertEqual(native_team.validate_observed('framework-researcher', observed)['fallback_model'],
                         'custom_configuration_conflict')
        valid = type('Result', (), {
            'returncode': 0, 'stderr': '', 'stdout': '["no_mcp", "delegation"]'
        })()
        with unittest.mock.patch.object(native_team, '_run', return_value=valid):
            self.assertEqual(
                native_team._get_leaf('hermes', 'framework-coordinator', 'platform_toolsets.cli', 'home'),
                ['no_mcp', 'delegation'])
        malformed = type('Result', (), {'returncode': 0, 'stderr': '', 'stdout': '{broken'})()
        with unittest.mock.patch.object(native_team, '_run', return_value=malformed):
            with self.assertRaises(native_team.PolicyError):
                native_team._get_leaf('hermes', 'framework-researcher', 'fallback_model', 'home')
        legacy = type('Result', (), {
            'returncode': 1, 'stderr': 'Config key not set: model.default', 'stdout': ''
        })()
        with unittest.mock.patch.object(native_team, '_run', return_value=legacy):
            with self.assertRaises(native_team.PolicyError):
                native_team._get_leaf('hermes', 'framework-researcher', 'model.default', 'home')

    def test_unknown_exact_profile_identity_refuses_before_cli(self):
        with unittest.mock.patch.object(native_team.lab, 'hermes_executable', return_value='hermes'):
            with unittest.mock.patch.object(native_team.lab, 'resolve_home', return_value='selected-home'):
                with unittest.mock.patch.object(native_team.lab, 'registered_profile', side_effect=ValueError):
                    with unittest.mock.patch.object(native_team, '_run') as run:
                        with self.assertRaises(native_team.PolicyError):
                            native_team.inspect(home='selected-home')
                        run.assert_not_called()

    def test_apply_preflights_all_profiles_before_first_write(self):
        observed = native_team.expected_settings('framework-coordinator')
        observed['agent.disabled_toolsets'] = native_team._disabled_toolset_requirements('framework-coordinator')
        observed['fallback_model'] = native_team._UNSET
        with unittest.mock.patch.object(native_team, '_resolve', return_value=('hermes', 'selected-home')):
            with unittest.mock.patch.object(native_team, '_read_current', side_effect=[
                observed, native_team.PolicyError('inspection failed')
            ]):
                with unittest.mock.patch.object(native_team, '_run') as run:
                    with self.assertRaises(native_team.PolicyError):
                        native_team.apply()
                    run.assert_not_called()

    def test_custom_model_route_is_not_overwritten(self):
        observed = native_team.expected_settings('framework-researcher')
        observed['model.default'] = 'custom-route'
        observed['agent.disabled_toolsets'] = native_team._disabled_toolset_requirements('framework-researcher')
        with unittest.mock.patch.object(native_team, '_resolve', return_value=('hermes', 'selected-home')):
            with unittest.mock.patch.object(native_team, '_read_current', return_value=observed):
                with unittest.mock.patch.object(native_team, '_run') as run:
                    with self.assertRaises(native_team.PolicyError):
                        native_team.apply()
                    run.assert_not_called()


    def test_apply_preserves_conflicting_tool_caps_and_routes(self):
        observed = native_team.expected_settings('framework-coordinator')
        observed['agent.disabled_toolsets'] = native_team._disabled_toolset_requirements('framework-coordinator')
        observed['delegation.max_iterations'] = 9
        with unittest.mock.patch.object(native_team, '_resolve', return_value=('hermes', 'selected-home')):
            with unittest.mock.patch.object(native_team, '_read_current', return_value=observed):
                with unittest.mock.patch.object(native_team, '_run') as run:
                    with self.assertRaises(native_team.PolicyError):
                        native_team.apply()
                    run.assert_not_called()

        observed = native_team.expected_settings('framework-coordinator')
        observed['agent.disabled_toolsets'] = native_team._disabled_toolset_requirements('framework-coordinator')
        observed['delegation.backends.profile_routes.default'] = 'framework-builder'
        with unittest.mock.patch.object(native_team, '_resolve', return_value=('hermes', 'selected-home')):
            with unittest.mock.patch.object(native_team, '_read_current', return_value=observed):
                with unittest.mock.patch.object(native_team, '_run') as run:
                    with self.assertRaises(native_team.PolicyError):
                        native_team.apply()
                    run.assert_not_called()
    def test_checked_native_calls_are_home_bound_bounded_and_leaf_only(self):
        completed = type('Result', (), {
            'returncode': 0, 'stderr': '', 'stdout': '"claude-sonnet-5-5"'
        })()
        with unittest.mock.patch.object(native_team.os, 'environ', {'HERMES_HOME': 'wrong-home'}):
            with unittest.mock.patch.object(native_team.subprocess, 'run', return_value=completed) as run:
                native_team._run(
                    'hermes', ['-p', 'framework-researcher', 'config', 'get', 'model.default', '--json'],
                    'approved-home')
        args, kwargs = run.call_args
        self.assertIn('model.default', args[0])
        self.assertNotIn('model', args[0])
        self.assertEqual(kwargs['env']['HERMES_HOME'], 'approved-home')
        self.assertEqual(kwargs['timeout'], 15)


    def _fake_cli(self, folder):
        folder.mkdir()
        path = folder / ('hermes.exe' if os.name == 'nt' else 'hermes')
        path.write_bytes(b'')
        path.chmod(0o755)
        return path

    def test_lab_hermes_exe_wins_over_path(self):
        with tempfile.TemporaryDirectory() as temp:
            on_path = self._fake_cli(Path(temp) / 'path-bin')
            lab_cli = self._fake_cli(Path(temp) / 'lab-bin')
            used = []
            def leaf(executable, profile, key, home):
                used.append(executable)
                return native_team._UNSET
            with unittest.mock.patch.dict(os.environ, {'PATH': str(on_path.parent), 'LAB_HERMES_EXE': str(lab_cli)}), \
                    unittest.mock.patch.object(native_team.lab, 'resolve_home', return_value='selected-home'), \
                    unittest.mock.patch.object(native_team, '_registered_profiles'), \
                    unittest.mock.patch.object(native_team, '_get_leaf', side_effect=leaf):
                result = native_team.inspect(home='selected-home')
            self.assertTrue(used)
            self.assertEqual({Path(executable).resolve() for executable in used}, {lab_cli.resolve()})
            first_line = result.splitlines()[0]
            self.assertTrue(first_line.startswith('Hermes executable: '), first_line)
            self.assertEqual(Path(first_line.split(': ', 1)[1]).resolve(), lab_cli.resolve())

    def test_explicit_hermes_wins_and_missing_lab_hermes_exe_is_an_error(self):
        with tempfile.TemporaryDirectory() as temp:
            on_path = self._fake_cli(Path(temp) / 'path-bin')
            explicit = self._fake_cli(Path(temp) / 'explicit-bin')
            missing = str(Path(temp) / 'gone' / 'hermes.exe')
            with unittest.mock.patch.dict(os.environ, {'PATH': str(on_path.parent), 'LAB_HERMES_EXE': missing}), \
                    unittest.mock.patch.object(native_team.lab, 'resolve_home', return_value='selected-home'), \
                    unittest.mock.patch.object(native_team, '_registered_profiles'):
                executable, _ = native_team._resolve(str(explicit), 'selected-home')
                self.assertEqual(Path(executable).resolve(), explicit.resolve())
                with unittest.mock.patch.object(native_team, '_run') as run:
                    with self.assertRaises(native_team.PolicyError) as caught:
                        native_team.inspect(home='selected-home')
                    run.assert_not_called()
            self.assertIn(f'LAB_HERMES_EXE: {missing}', str(caught.exception))

    def test_model_projection_option_is_gone(self):
        with unittest.mock.patch('sys.stderr'), self.assertRaises(SystemExit):
            native_team.main(['--model-projection-python', 'python', 'check'])
        self.assertFalse(hasattr(native_team, '_project_model'))

    def test_missing_fields_are_explicit_configuration_not_ready(self):
        observed = native_team.validate_observed('framework-network-analyst', {})
        self.assertEqual(set(observed.values()), {'needs_explicit_configuration'})

    def test_explicit_empty_list_is_not_the_policy_toolset(self):
        self.assertNotEqual(native_team.expected_settings('framework-researcher')['platform_toolsets.cli'], [])
        self.assertIn('no_mcp', native_team.expected_settings('framework-researcher')['platform_toolsets.cli'])

    def test_desktop_ui_is_required_disabled_for_every_framework_role(self):
        for profile in native_team.PROFILES:
            required = native_team._disabled_toolset_requirements(profile)
            observed = native_team.expected_settings(profile)
            observed['agent.disabled_toolsets'] = [name for name in required if name != 'desktop_ui']
            self.assertEqual(native_team.validate_observed(profile, observed)['agent.disabled_toolsets'],
                             'needs_explicit_configuration')
            observed['agent.disabled_toolsets'].append('desktop_ui')
            self.assertEqual(native_team.validate_observed(profile, observed)['agent.disabled_toolsets'], 'ready')


    def _registered_profile(self, root, profile='framework-builder', identity=None):
        profile_dir = Path(root) / 'profiles' / profile
        profile_dir.mkdir(parents=True)
        (profile_dir / 'distribution.yaml').write_text(
            f'name: {identity or profile}\nversion: 1\ndescription: test\n', encoding='utf-8')
        (profile_dir / 'SOUL.md').write_text('authored test identity\n', encoding='utf-8')
        return profile_dir

    def test_initialize_writes_only_supported_reviewed_yaml_mapping(self):
        with tempfile.TemporaryDirectory() as root:
            profile_dir = self._registered_profile(root)
            native_team.initialize('framework-builder', root)
            config = json.loads((profile_dir / 'config.yaml').read_text(encoding='utf-8'))
            self.assertEqual(config['model']['default'], 'claude-sonnet-5-5')
            self.assertEqual(config['model']['provider'], 'anthropic')
            self.assertEqual(config['fallback_providers'], [])
            self.assertEqual(config['fallback_model'], [])
            self.assertEqual(config['agent']['max_turns'], 6)
            self.assertEqual(config['agent']['allowed_tool_names'], ['detection_test', 'elastic_aggregate'])
            self.assertIn('desktop_ui', config['agent']['disabled_toolsets'])
            self.assertNotIn('hunt_lab', config['agent']['disabled_toolsets'])
            self.assertEqual(config['platform_toolsets']['cli'], ['no_mcp', 'hunt_lab'])
            self.assertEqual(config['tools'], {'tool_search': {'enabled': 'off'}})
            self.assertEqual(set(config), {'model', 'fallback_providers', 'fallback_model',
                                           'agent', 'platform_toolsets', 'tools'})

    def test_initialize_serializes_strict_coordinator_routes_and_tools(self):
        with tempfile.TemporaryDirectory() as root:
            profile_dir = self._registered_profile(root, profile='framework-coordinator')
            native_team.initialize('framework-coordinator', root)
            config = json.loads((profile_dir / 'config.yaml').read_text(encoding='utf-8'))
            self.assertEqual(config['agent']['allowed_tool_names'], ['delegate_task'])
            self.assertNotIn('allowed_profiles', config['delegation'])
            self.assertEqual(config['delegation']['backend'], 'profile_routes')
            self.assertEqual(config['delegation']['backends']['profile_routes']['profiles'],
                             [{'name': name, 'description': description}
                              for name, description in native_team.PROFILE_ROUTES])
            self.assertEqual(config['delegation']['backends']['profile_routes']['default'], 'framework-researcher')

    def test_initialize_requires_exact_identity_and_preserves_existing_file(self):
        with tempfile.TemporaryDirectory() as root:
            profile_dir = self._registered_profile(root, identity='framework-researcher')
            with self.assertRaises(native_team.PolicyError):
                native_team.initialize('framework-builder', root)
            self.assertFalse((profile_dir / 'config.yaml').exists())

        with tempfile.TemporaryDirectory() as root:
            profile_dir = self._registered_profile(root)
            path = profile_dir / 'config.yaml'
            path.write_bytes(b'user config including secrets: untouched\n')
            with self.assertRaises(native_team.PolicyError):
                native_team.initialize('framework-builder', root)
            self.assertEqual(path.read_bytes(), b'user config including secrets: untouched\n')

    def test_initialize_refuses_dangling_symlink_without_replacing_it(self):
        with tempfile.TemporaryDirectory() as root:
            profile_dir = self._registered_profile(root)
            path = profile_dir / 'config.yaml'
            target = Path(root) / 'missing-target'
            try:
                path.symlink_to(target)
            except (OSError, NotImplementedError):
                self.skipTest('symlink creation is unavailable')
            with self.assertRaises(native_team.PolicyError):
                native_team.initialize('framework-builder', root)
            self.assertTrue(path.is_symlink())
            self.assertFalse(target.exists())

    def test_initialize_exclusive_creation_refuses_race(self):
        with tempfile.TemporaryDirectory() as root:
            profile_dir = self._registered_profile(root)
            path = profile_dir / 'config.yaml'

            def create_racer_then_fail(staged, destination):
                with open(path, 'xb') as stream:
                    stream.write(b'racing user config\n')
                raise FileExistsError(destination)

            with unittest.mock.patch.object(native_team.os, 'link', side_effect=create_racer_then_fail):
                with self.assertRaises(native_team.PolicyError):
                    native_team.initialize('framework-builder', root)
            self.assertEqual(path.read_bytes(), b'racing user config\n')

    def test_initialize_publishes_complete_policy_or_leaves_no_config(self):
        with tempfile.TemporaryDirectory() as root:
            profile_dir = self._registered_profile(root)
            path = profile_dir / 'config.yaml'

            def fail_publication(staged, destination):
                self.assertFalse(path.exists())
                config = json.loads(Path(staged).read_text(encoding='utf-8'))
                self.assertEqual(config['model']['default'], 'claude-sonnet-5-5')
                self.assertIn('desktop_ui', config['agent']['disabled_toolsets'])
                raise OSError('synthetic publication failure')

            with unittest.mock.patch.object(native_team.os, 'link', side_effect=fail_publication):
                with self.assertRaises(native_team.PolicyError):
                    native_team.initialize('framework-builder', root)
            self.assertFalse(path.exists())
            self.assertEqual(set(item.name for item in profile_dir.iterdir()),
                             {'distribution.yaml', 'SOUL.md'})

if __name__ == '__main__':
    unittest.main()

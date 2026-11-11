#!/usr/bin/env python3
"""Plan and explicitly initialize/apply reviewed, nonsecret native Hermes policy.

The helper does not read whole existing config files. Ordinary Hermes calls
retain native startup effects; only the standalone model projection is isolated.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile

import lab
from hunt_lab.query_adapter import TOOL_OWNERSHIP


# Native Anthropic (Claude Pro/Max OAuth) routes. Hermes expects bare model IDs
# with an explicit provider; a slash-prefixed ID is resolved as an aggregator route.
PROVIDER = 'anthropic'
PROFILES = {
    'framework-coordinator': {'model': 'claude-opus-5-5', 'max_turns': 8},
    'framework-researcher': {'model': 'claude-sonnet-5', 'max_turns': 6},
    'framework-builder': {'model': 'claude-sonnet-5', 'max_turns': 6},
    'framework-reviewer': {'model': 'claude-opus-5-5', 'max_turns': 6},
    'framework-librarian': {'model': 'claude-sonnet-5', 'max_turns': 6},
    'framework-network-analyst': {'model': 'claude-sonnet-5', 'max_turns': 6},
}

# Exact choices and descriptions exposed by the pinned advanced-delegation
# profile_routes backend. Keep this list in sync with the reviewed plugin API.
PROFILE_ROUTES = (
    ('framework-researcher', 'Investigate only approved supplied evidence.'),
    ('framework-builder', 'Draft only explicitly authorized local changes.'),
    ('framework-reviewer', 'Independently review supplied evidence and changes.'),
    ('framework-librarian', 'Prepare provenance-rich drafts for human review.'),
    ('framework-network-analyst', 'Analyze only bounded, sanitized hunt_lab summaries.'),
)
# The narrowest specialist takes any delegated task that names no profile.
DEFAULT_ROUTE = 'framework-researcher'

HUNT_TOOL_PROFILES = tuple(name for name in PROFILES if name != 'framework-coordinator')

# Earlier reviewed values that apply may replace; any other differing value is user policy.
SUPERSEDED_SETTINGS = {
    **{
        profile: {
            'agent.allowed_tool_names': [
                ['hunt_lab_query'] if profile == 'framework-network-analyst' else [],
                [tool for tool in TOOL_OWNERSHIP[profile] if tool not in ('lab_browser', 'packet_fields')],
                [tool for tool in TOOL_OWNERSHIP[profile] if tool != 'packet_fields'],
            ],
            'platform_toolsets.cli': [['no_mcp']],
        }
        for profile in HUNT_TOOL_PROFILES
    },
    'framework-coordinator': {'platform_toolsets.cli': [['no_mcp', 'delegation']]},
}

def _allowed_tool_names(profile):
    # TOOL_OWNERSHIP (hunt_lab/query_adapter.py) is the one ownership map. The hunt_lab plugin
    # registers only the owner's tools, which is what limits them at runtime on stock Hermes.
    return list(TOOL_OWNERSHIP[profile])

def _profile_route_entries():
    return [{'name': name, 'description': description} for name, description in PROFILE_ROUTES]

POLICY_BLOCKERS = (
    'The pinned advanced-delegation plugin revision must be installed and enabled in the coordinator profile; this helper does not fetch, install, or activate plugins.',
    'Managed-worker sessions with frozen config cannot switch to another profile. Use a verified profile-capable native execution path; this helper does not add cross-profile worker routing or bypass that refusal.',
    'Native Hermes may ignore unsupported policy fields; persisted configuration alone does not establish runtime capabilities or readiness.',
    'Verify the exact plugin revision and actual runtime tool/routing behavior independently. No OS isolation or aggregate spending cap is provided; provider access and model execution remain unverified.',
)


_UNSET = object()


class PolicyError(ValueError):
    """Native profile state cannot be safely inspected or changed."""


def expected_settings(profile):
    if profile not in PROFILES:
        raise PolicyError('Unknown framework profile; no changes were made.')
    spec = PROFILES[profile]
    expected = {
        # Never request the whole `model` section: it may contain credentials/endpoints.
        'model.default': spec['model'],
        'model.provider': PROVIDER,
        'fallback_providers': [],
        # Hermes appends the legacy fallback_model chain after this modern list.
        # Explicitly empty both so the effective route cannot silently fall back.
        'fallback_model': [],
        'agent.max_turns': spec['max_turns'],
        'agent.allowed_tool_names': _allowed_tool_names(profile),
        # Bot Chat uses the CLI policy surface and adds Desktop client toolsets
        # after resolution. Explicit no_mcp is required: [] alone still admits
        # globally enabled MCP servers in native Hermes.
        # A delegated child's toolsets are a subset of its parent's (Hermes 0.23.0), so the coordinator
        # enables hunt_lab for the specialists it delegates to; the plugin registers no tool for the
        # coordinator itself, and each child registers only its own profile's tools.
        'platform_toolsets.cli': (
            ['no_mcp', 'delegation', 'hunt_lab'] if profile == 'framework-coordinator'
            else ['no_mcp', 'hunt_lab']
        ),
    }
    if profile == 'framework-coordinator':
        expected.update({
            'delegation.max_spawn_depth': 1,
            'delegation.max_iterations': 8,
            'delegation.max_summary_chars': 4000,
            'delegation.fallback_providers': [],
            'delegation.backend': 'profile_routes',
            'delegation.backends.profile_routes.profiles': _profile_route_entries(),
            # A task that names no profile would otherwise run as the coordinator itself.
            'delegation.backends.profile_routes.default': DEFAULT_ROUTE,
        })
    if profile in HUNT_TOOL_PROFILES:
        # Native Tool Search defers plugin tools behind tool_search/tool_call bridges,
        # which an exact allowlist then strips, hiding the owned hunt_lab tools entirely.
        expected['tools.tool_search.enabled'] = 'off'
    return expected


def _disabled_toolset_requirements(profile):
    # Suppress core toolsets injected outside the explicit selection (Desktop
    # client tools, xAI search on credential presence, and a configured context
    # engine/memory provider). hunt_lab plugin tools are limited by owner-only registration.
    blocked = ['desktop_ui', 'project', 'catalog', 'x_search', 'context_engine', 'memory']
    if profile != 'framework-coordinator':
        blocked.append('delegation')
    return blocked


def _enabled_toolset_requirements(profile):
    # Earlier reviewed policy disabled hunt_lab outside the analyst, and for the coordinator; tool owners
    # need it live, and the coordinator's delegated specialists inherit it.
    return ['hunt_lab']


def validate_observed(profile, observed):
    """Compare only whitelisted public config leaves; never accept arbitrary fields."""
    expected = expected_settings(profile)
    if not isinstance(observed, dict) or set(observed) - set(expected) - {'agent.disabled_toolsets'}:
        raise PolicyError('Unknown policy fields; no configuration data was accepted.')
    statuses = {}
    for key, value in expected.items():
        current = observed.get(key, _UNSET)
        if current == value:
            statuses[key] = 'ready'
        elif current is _UNSET or current in SUPERSEDED_SETTINGS.get(profile, {}).get(key, ()):
            statuses[key] = 'needs_explicit_configuration'
        else:
            statuses[key] = 'custom_configuration_conflict'
    disabled = observed.get('agent.disabled_toolsets', _UNSET)
    required_disabled = _disabled_toolset_requirements(profile)
    if disabled is _UNSET:
        statuses['agent.disabled_toolsets'] = 'needs_explicit_configuration'
    elif not isinstance(disabled, list) or not all(isinstance(item, str) for item in disabled):
        statuses['agent.disabled_toolsets'] = 'custom_configuration_conflict'
    elif set(required_disabled).issubset(disabled) and not set(_enabled_toolset_requirements(profile)) & set(disabled):
        statuses['agent.disabled_toolsets'] = 'ready'
    else:
        statuses['agent.disabled_toolsets'] = 'needs_explicit_configuration'
    return statuses


def plan_lines():
    lines = ['Native framework team policy (plan only; no profile or provider changes):']
    for profile, spec in PROFILES.items():
        settings = expected_settings(profile)
        tools = settings['platform_toolsets.cli']
        allowed = settings['agent.allowed_tool_names']
        disabled = _disabled_toolset_requirements(profile)
        enabled = _enabled_toolset_requirements(profile)
        search = settings.get('tools.tool_search.enabled')
        lines.append(
            f"{profile}: model={spec['model']}; fallback_providers=[]; fallback_model=[]; "
            f"agent.max_turns={spec['max_turns']}; platform_toolsets.cli={tools}; "
            f'agent.allowed_tool_names={allowed}; agent.disabled_toolsets adds {disabled}'
            + (f' and removes {enabled}' if enabled else '')
            + (f'; tools.tool_search.enabled={search}' if search else '')
        )
    lines.append('Coordinator output/turn controls: delegation.max_spawn_depth=1; delegation.max_iterations=8; delegation.max_summary_chars=4000; delegation.fallback_providers=[].')
    lines.append('Coordinator delegation policy: delegation.backend=profile_routes; delegation.backends.profile_routes.profiles is exactly the five authored specialists, which Hermes enforces at runtime as the task.profile enum; a task with no profile runs as ' + DEFAULT_ROUTE + '.')
    lines.extend(f"  {route['name']}: {route['description']}" for route in _profile_route_entries())
    lines.append('Native policy fields are planned and explicitly configurable, not runtime readiness evidence. The pinned official advanced-delegation plugin is a deployment prerequisite.')
    for blocker in POLICY_BLOCKERS:
        lines.append('BLOCKER: ' + blocker)
    return '\n'.join(lines)


def _run(executable, args, home):
    env = dict(os.environ)
    env['HERMES_HOME'] = str(home)
    try:
        return subprocess.run([executable, *args], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              text=True, encoding='utf-8', errors='replace', check=False,
                              timeout=15, env=env)
    except (OSError, subprocess.TimeoutExpired):
        raise PolicyError('Hermes command failed or timed out; no command output was displayed.') from None


def _registered_profiles(home):
    for profile in PROFILES:
        try:
            lab.registered_profile(home, profile)
        except (OSError, ValueError):
            raise PolicyError('Required exact authored profiles are not registered in the selected Hermes home; no changes were made.') from None



def _get_leaf(executable, profile, key, home):
    result = _run(executable, ['-p', profile, 'config', 'get', key, '--json'], home)
    if result.returncode:
        # The pinned native CLI reports unset leaves with this exact final
        # diagnostic; startup warnings (for example install-sync notices) may
        # precede it. Every other nonzero result is an inspection failure.
        lines = result.stderr.strip().splitlines()
        if lines and lines[-1].strip() == f'Config key not set: {key}':
            if key == 'model.default':
                raise PolicyError(f'Could not safely inspect {key} for {profile}; missing and legacy model shapes are refused.')
            return _UNSET
        raise PolicyError(f'Could not safely inspect {key} for {profile}; no changes were made.')
    try:
        return json.loads(result.stdout)
    except (TypeError, ValueError):
        raise PolicyError(f'Native Hermes returned an unreadable {key} value for {profile}; no changes were made.') from None


def _unique_projection_fields(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Ambiguous projection response.')
        result[key] = value
    return result


def _project_model(executable, profile, home):
    expected = expected_settings(profile)['model.default']
    result = _run(executable, [
        '-I', '-B', '-m', 'hermes_cli.config_model_projection',
        '--root', str(home), '--profile', profile, '--expected-model', expected,
    ], home)
    message = f'Could not certify the persisted model for {profile}; no changes were made.'
    if result.returncode or result.stderr.strip():
        raise PolicyError(message)
    try:
        projection = json.loads(result.stdout, object_pairs_hook=_unique_projection_fields)
    except (TypeError, ValueError):
        raise PolicyError(message) from None
    if (not isinstance(projection, dict)
            or set(projection) != {'shape', 'expected_model_match'}
            or projection['shape'] not in ('scalar', 'mapping')
            or projection['expected_model_match'] is not True):
        raise PolicyError(message)
    return expected


def _read_current(executable, profile, home, model_projection_python=None):
    keys = [*expected_settings(profile), 'agent.disabled_toolsets']
    observed = {}
    if model_projection_python is not None:
        # Certify the persisted model before any ordinary CLI startup. A match
        # prevents apply from migrating a legacy scalar to a mapping.
        observed['model.default'] = _project_model(model_projection_python, profile, home)
        keys.remove('model.default')
    observed.update((key, _get_leaf(executable, profile, key, home)) for key in keys)
    return observed


def _safe_set_value(value):
    return value if isinstance(value, str) else json.dumps(value, separators=(',', ':'), ensure_ascii=True)


def _resolve(executable_override, home):
    executable = shutil.which(executable_override or 'hermes')
    if not executable:
        raise PolicyError('Hermes CLI was not found. Install Hermes separately using its official installation guide.')
    try:
        root = lab.resolve_home(home)
    except (OSError, ValueError):
        raise PolicyError('The selected Hermes home is not a supported native home.') from None
    _registered_profiles(root)
    return executable, root


def inspect(hermes_override=None, home=None, model_projection_python=None):
    executable, root = _resolve(hermes_override, home)
    lines = ['Reviewed native profile settings (safe fields only):']
    for profile in PROFILES:
        status = validate_observed(profile, _read_current(executable, profile, root, model_projection_python))
        lines.append(profile + ': ' + ', '.join(f'{key}={value}' for key, value in status.items()))
    lines.append('Delegation routes: enforced by the profile_routes enum when the advanced-delegation plugin is enabled.')
    lines.extend('BLOCKER: ' + item for item in POLICY_BLOCKERS)
    return '\n'.join(lines)


def apply(hermes_override=None, home=None, model_projection_python=None):
    executable, root = _resolve(hermes_override, home)

    # Preflight every safe field before the first write. Existing differing values
    # are user policy, not ours to replace. No raw config or native output is surfaced.
    updates = []
    for profile in PROFILES:
        expected = expected_settings(profile)
        observed = _read_current(executable, profile, root, model_projection_python)
        status = validate_observed(profile, observed)
        conflicts = [key for key, value in status.items() if value == 'custom_configuration_conflict']
        if conflicts:
            conflict_names = ', '.join(conflicts)
            raise PolicyError(f'Custom policy conflicts in {profile} ({conflict_names}); preserve and resolve it manually.')
        disabled = observed.get('agent.disabled_toolsets', _UNSET)
        if disabled is _UNSET:
            disabled = []
        required_disabled = _disabled_toolset_requirements(profile)
        if status['agent.disabled_toolsets'] != 'ready':
            enabled = _enabled_toolset_requirements(profile)
            merged = [name for name in dict.fromkeys([*disabled, *required_disabled]) if name not in enabled]
            updates.append((profile, 'agent.disabled_toolsets', merged))
        for key, value in expected.items():
            if status[key] != 'ready':
                updates.append((profile, key, value))

    changed = []
    for profile, key, value in updates:
        result = _run(executable, ['-p', profile, 'config', 'set', key, _safe_set_value(value)], root)
        if result.returncode:
            raise PolicyError(f'Native config update failed for {profile} {key}; earlier successful safe fields remain applied. Native output was suppressed.')
        changed.append((profile, key))
    summary = ', '.join(f'{profile}:{key}' for profile, key in changed) or 'none (already matched)'
    return ('Applied only reviewed model, fallback, turn/output-control, allowlisted tool-name, delegation-route, and direct-surface toolset fields: ' + summary + '.\n'
            'Persisted values do not establish that native Hermes enforces these fields. This helper does not install or activate the required source patch or plugin and cannot establish runtime capability/readiness.\n' +
            '\n'.join('BLOCKER: ' + item for item in POLICY_BLOCKERS))


def _initial_config(profile):
    """Return the reviewed profile policy as JSON, which is YAML-compatible."""
    settings = expected_settings(profile)
    settings['agent.disabled_toolsets'] = _disabled_toolset_requirements(profile)
    nested = {}
    for dotted, value in settings.items():
        parts = dotted.split('.')
        current = nested
        for part in parts[:-1]:
            current = current.setdefault(part, {})
        current[parts[-1]] = value
    return json.dumps(nested, sort_keys=True, indent=2, ensure_ascii=True) + '\n'


def initialize(profile, home=None):
    """Exclusively create config.yaml for one exact registered authored profile."""
    if profile not in PROFILES:
        raise PolicyError('Unknown framework profile; no changes were made.')
    try:
        root = lab.resolve_home(home)
        profile_dir = lab.registered_profile(root, profile)
    except (OSError, ValueError):
        raise PolicyError('The exact authored profile is not safely registered in the selected Hermes home; no changes were made.') from None

    path = profile_dir / 'config.yaml'
    try:
        path.lstat()
    except FileNotFoundError:
        pass
    except OSError:
        raise PolicyError('Could not safely inspect the profile config path; no changes were made.') from None
    else:
        raise PolicyError('A config.yaml entry already exists; preserve it and resolve manually.')

    payload = _initial_config(profile).encode('utf-8')
    try:
        # Publish complete bytes without replacing a concurrent config. A gateway
        # must not observe an empty/partial policy and fall back to default tools.
        # Staging is beneath profile_dir so hard-link publication is same-filesystem.
        with tempfile.TemporaryDirectory(prefix='.framework-policy-', dir=profile_dir) as staging:
            staged = os.path.join(staging, 'config.yaml')
            fd = os.open(staged, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(payload)
            os.link(staged, path)
    except OSError:
        raise PolicyError('Exclusive config publication failed; no existing path was replaced. Same-filesystem hard-link support is required; a fully published new config may remain if staging cleanup failed.') from None
    return (f'Initialized reviewed nonsecret policy for {profile} at config.yaml. '
            'This does not install or activate the advanced-delegation plugin, or verify provider access, final tools, routes, or runtime readiness.')


def main(argv=None):
    parser = argparse.ArgumentParser(description='Inspect or explicitly configure reviewed nonsecret Hermes team policy fields.')
    parser.add_argument('--hermes', metavar='PATH', help='Hermes executable override.')
    parser.add_argument('--home', metavar='PATH', help='Explicit Hermes home to inspect or configure.')
    parser.add_argument('--model-projection-python', metavar='PATH',
                        help='Explicit native Python with the reviewed isolated projection installed; certifies persisted model only.')
    commands = parser.add_subparsers(dest='command')
    commands.add_parser('plan', help='print the policy without reading native state (default).')
    commands.add_parser('check', help='read only reviewed safe config leaves and report policy status.')
    commands.add_parser('apply', help='explicitly apply non-conflicting model, fallback, toolset, turn, and summary settings only.')
    init_parser = commands.add_parser('initialize', help='exclusively create reviewed config.yaml for one exact registered profile with no config.')
    init_parser.add_argument('profile', choices=tuple(PROFILES))
    args = parser.parse_args(argv)
    try:
        command = args.command or 'plan'
        print(plan_lines() if command == 'plan' else inspect(args.hermes, args.home, args.model_projection_python) if command == 'check' else apply(args.hermes, args.home, args.model_projection_python) if command == 'apply' else initialize(args.profile, args.home))
        return 0
    except (PolicyError, OSError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())

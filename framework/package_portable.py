"""Export the explicitly authored, provider-neutral Hermes framework kit."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import zipfile


ROOT = Path(__file__).absolute().parent
ARCHIVE_ROOT = 'hermes-bot-framework/'
PROFILES = (
    'framework-builder', 'framework-coordinator', 'framework-librarian',
    'framework-network-analyst', 'framework-researcher', 'framework-reviewer',
)
FILES = (
    '.gitignore', 'README.md', 'hermes-setup.md', 'optional-runtime.md',
    'LICENSE',
    'bot.py', 'workflows.py', 'orchestrate.py', 'langchain_adapter.py',
    'native_team.py',
    'requirements-orchestration.txt', 'setup_hermes.py', 'package_portable.py',
    'requirements-hunt.txt', 'requirements-hunt.lock',
    'test_bot.py', 'test_workflows.py', 'test_orchestration.py',
    'test_langchain_adapter.py', 'test_setup_hermes.py', 'test_package_portable.py',
    'test_native_team.py', 'imager_import.py', 'test_imager_import.py',
    'roles/coordinator.txt', 'roles/researcher.txt', 'roles/builder.txt',
    'roles/reviewer.txt', 'examples/meeting-notes.txt',
    'examples/synthetic-hunt-events.json', 'workflows/research-review.json',
    'workflows/build-review.json', 'workflows/threat-hunt.json',
    'workflows/evidence-acquisition.json',
    'hermes-skills/threat-hunt/SKILL.md',
    'hermes-skills/security-audit/SKILL.md',
    'hermes-skills/security-audit/PROVENANCE.md',
    'hermes-skills/security-audit/LICENSE',
    'hermes-skills/security-audit/RECONNAISSANCE.md',
    'hermes-skills/security-audit/HUNTING.md',
    'hermes-skills/security-audit/VALIDATION-AND-REPORTING.md',
    'hermes-skills/security-audit/ATTACK-CLASSES.md',
    'hermes-skills/security-audit/AI-AND-LLM.md',
    'hermes-skills/security-audit/CLIENT-SIDE.md',
    'hermes-skills/security-audit/CLOUD-AND-DEPLOYMENT.md',
    'hermes-skills/security-audit/DATA-ISOLATION-AND-LIFECYCLE.md',
    'hermes-skills/security-audit/DESKTOP-MOBILE-AND-LOCAL-IPC.md',
    'hermes-skills/security-audit/MEMORY-SAFETY-AND-BINARY.md',
    'hermes-skills/security-audit/PROTOCOLS-RPC-AND-MESSAGING.md',
    'hermes-skills/security-audit/RESOURCE-EXHAUSTION-AND-AVAILABILITY.md',
    'hermes-skills/security-audit/SUPPLY-CHAIN-AND-RELEASE.md',
    'hermes-skills/security-audit/WEB-PROTOCOL-AND-AUTH.md',
    'hermes-skills/security-audit/report-schema.json',
    'hermes-skills/security-audit/validate-findings.cjs',
    'hermes-skills/security-audit/validate-findings.test.cjs',
    'hermes-skills/security-audit/validate-coverage-ledger.cjs',
    'hermes-skills/security-audit/validate-coverage-ledger.test.cjs',
    'install_desktop.py', 'test_desktop_workspace.py',
    'desktop/cybersecurity-workspace/plugin.js', 'desktop/test-plugin.mjs',
    'desktop/VIDEO-INVENTORY.md', 'desktop/REVIEW.md', 'desktop/VERIFICATION.md',
    'desktop/HERMES-LICENSE.txt',
    'hermes-bots/README.md', 'hermes-bots/catalog.json',
    'desktop/BOT-MODE-COMPATIBILITY.md',
    'hermes_temporal/__init__.py', 'hermes_temporal/contracts.py',
    'hermes_temporal/workflows.py', 'hermes_temporal/cli.py',
    'hermes_temporal/execution.py', 'hermes_temporal/activities.py',
    'hermes_temporal/worker.py', 'hermes_temporal/requirements.txt',
    'hermes_temporal/README.md', 'hermes_temporal/test_execution.py',
    'hermes_temporal/test_workflows.py',
    'hermes_temporal/hunt.py',
    'hermes_temporal/practice.py', 'hermes_temporal/test_practice.py',
    'hermes_temporal/lab_input.py', 'hermes_temporal/test_lab_input.py',
    'hermes_temporal/ontology.py', 'hermes_temporal/test_ontology.py',
    'hermes_temporal/test_hunt.py',
    'hermes_temporal/board.py', 'hermes_temporal/board_page.html', 'hermes_temporal/test_board.py',
    'hermes_temporal/fixtures/board/lab-input.json',
    'hermes_temporal/fixtures/board/parent-status.json',
    'hermes_temporal/fixtures/board/child-status.json',
    'hermes_temporal/fixtures/replay/handoff-rejected-before-retry.json',
    'lab.py', 'test_hunt_lab_case.py', 'test_hunt_lab_runtime.py',
    'test_hunt_lab_managed.py', 'test_hunt_lab_install.py',
    'test_hunt_lab_tools.py', 'test_lab_server.py', 'test_lab_browser.py', 'test_humanize.py',
    'hunt_lab/__init__.py', 'hunt_lab/runtime.py', 'hunt_lab/managed.py',
    'hunt_lab/prepare_guest.py', 'hunt_lab/query_adapter.py', 'hunt_lab/endpoints.py',
    'hunt_lab/lab_browser.py', 'hunt_lab/browser_policy.py', 'hunt_lab/humanize.py',
    'hunt_lab/actionability.py',
    'hunt_lab/plugin.yaml', 'hunt_lab/assets.json', 'hunt_lab/case.py',
    'hunt_lab/scenario.py', 'hunt_lab/screencast.py', 'hunt_lab/test_scenario.py',
    'hunt_lab/guest/compose.yaml', 'hunt_lab/guest/arkime.ini',
    'hunt_lab/guest/bootstrap_guest.sh', 'hunt_lab/guest/ingest.py',
    'hunt_lab/guest/lab_server.py', 'hunt_lab/guest/image-lock.json',
    'hunt_lab/guest/kibana.yml', 'hunt_lab/guest/kibana_setup.py',
    'hunt_lab/fixtures/dns-lab-001/events.jsonl',
    'hunt_lab/fixtures/dns-lab-001/traffic.pcap',
    'hunt_lab/fixtures/dns-lab-001/case.json',
    'hunt_lab/desktop/plugin.js', 'hunt_lab/desktop/package.json',
    'hunt_lab/desktop/console-provenance.json',
    'hunt_lab/desktop/licenses/babel-LICENSE.MIT',
    'hunt_lab/desktop/licenses/regenerator-LICENSE.MIT',
    'hunt_lab/desktop/licenses/pako-LICENSE.MIT',
    'hunt_lab/desktop/licenses/LICENSE.OFL-1.1',
    'hunt_lab/desktop/licenses/LICENSE.BSD-3-Clause',
    'hunt_lab/desktop/licenses/LICENSE.BSD-2-Clause',
    'hunt_lab/desktop/licenses/LICENSE.MPL-2.0',
    'hunt_lab/desktop/licenses/noVNC-AUTHORS.txt',
    'hunt_lab/desktop/licenses/noVNC-LICENSE.txt',
    'hunt_lab/desktop/licenses/lucide-LICENSE.txt',
    'hunt_lab/desktop_src/build_console.py',
    'hunt_lab/desktop_src/console-frame.js',
    'hunt_lab/desktop_src/console-frontend.js',
    'hunt_lab/desktop_src/plugin.entry.js',
) + tuple('hermes-bots/{}/{}'.format(name, filename)
          for name in PROFILES for filename in ('.gitignore', 'SOUL.md', 'distribution.yaml'))


def read_source(relative):
    """Read an allowlisted regular file only through non-alias path components."""
    path = ROOT / relative
    # Reject aliases in the kit, not ordinary OS/user aliases above its root.
    components = [ROOT]
    for name in Path(relative).parts:
        components.append(components[-1] / name)
    for part in components:
        info = part.lstat()
        if stat.S_ISLNK(info.st_mode) or (getattr(info, 'st_file_attributes', 0) &
                                        getattr(stat, 'FILE_ATTRIBUTE_REPARSE_POINT', 0x400)):
            raise ValueError('Source path contains a symlink or reparse point: {}'.format(part))
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ValueError('Source is not a single-link regular file: {}'.format(path))
    with path.open('rb') as source:
        opened = os.fstat(source.fileno())
        if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1 or
                (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino)):
            raise ValueError('Source file identity or link count changed: {}'.format(path))
        return source.read()


def validate_catalog(data):
    catalog = json.loads(data)
    if not isinstance(catalog, list) or len(catalog) != len(PROFILES):
        raise ValueError('Catalog must contain exactly the six expected profiles')
    seen = set()
    for entry in catalog:
        if not isinstance(entry, dict):
            raise ValueError('Invalid catalog entry')
        name = entry.get('name')
        if (not isinstance(name, str) or name not in PROFILES or name in seen or
                entry.get('distribution_path') != name or
                entry.get('soul_path') != name + '/SOUL.md'):
            raise ValueError('Unexpected profile name or path in catalog')
        seen.add(name)
    if seen != set(PROFILES):
        raise ValueError('Catalog does not contain the expected profiles')


def package(output):
    """Create a new ZIP at output, returning its absolute path and SHA-256 digest."""
    # Gather and validate before creating the destination; archive exactly these bytes.
    contents = {name: read_source(name) for name in sorted(FILES)}
    validate_catalog(contents['hermes-bots/catalog.json'])
    sums = ''.join('{}  {}\n'.format(hashlib.sha256(contents[name]).hexdigest(), name)
                   for name in sorted(contents)).encode('utf-8')
    output = Path(os.path.abspath(output))
    created = False
    try:
        with output.open('xb') as destination:
            created = True
            with zipfile.ZipFile(destination, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
                for name, data in sorted((*contents.items(), ('SHA256SUMS', sums))):
                    info = zipfile.ZipInfo(ARCHIVE_ROOT + name, (1980, 1, 1, 0, 0, 0))
                    info.compress_type = zipfile.ZIP_DEFLATED
                    info.create_system = 3
                    info.external_attr = 0o100644 << 16
                    archive.writestr(info, data)
        digest = hashlib.sha256()
        with output.open('rb') as archive_file:
            for chunk in iter(lambda: archive_file.read(1024 * 1024), b''):
                digest.update(chunk)
        return output, digest.hexdigest()
    except BaseException:
        if created:
            try:
                output.unlink()
            except FileNotFoundError:
                pass
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, help='Path for a new ZIP archive (must not exist)')
    args = parser.parse_args(argv)
    try:
        path, digest = package(args.output)
    except (OSError, ValueError, zipfile.BadZipFile) as exc:
        print('Portable export failed: {}'.format(exc), file=sys.stderr)
        return 1
    print('Archive: {}'.format(path))
    print('SHA256: {}'.format(digest))
    return 0


if __name__ == '__main__':
    sys.exit(main())

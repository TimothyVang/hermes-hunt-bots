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
    'benchmark.py',
    'benchmark_adjudication.py',
    'benchmark_aws.py',
    'benchmark_campaigns.py',
    'benchmark_comparison.py',
    'benchmark_contracts.py',
    'benchmark_decisions.py',
    'benchmark_evidence.py',
    'benchmark_linux.py',
    'benchmark_models.py',
    'benchmark_process.py',
    'benchmark_reporting.py',
    'benchmark_runner.py',
    'benchmark_scoring.py',
    'benchmark_store.py',
    'benchmark_typesafe.py',
    'benchmark_windows.py',
    'benchmark_difficulty.py',
    'benchmark_diagnostics.py',
    'benchmark_holdout.py',
    'benchmark_import_otrf.py',
    'benchmark_corpus.py',
    'benchmark_baselines.py',
    'benchmark_consensus.py',
    'benchmark_attack.py',
    'benchmark_sanitize.py',
    'test_benchmark_sanitize.py',
    'benchmark_import_attackdata.py',
    'test_benchmark_adjudication.py',
    'test_benchmark_aws.py',
    'test_benchmark_campaigns.py',
    'test_benchmark_comparison.py',
    'test_benchmark_contracts.py',
    'test_benchmark_decisions.py',
    'test_benchmark_evidence.py',
    'test_benchmark_fixtures_lower.py',
    'test_benchmark_fixtures_higher.py',
    'test_benchmark_linux.py',
    'test_benchmark_models.py',
    'test_benchmark_process.py',
    'test_benchmark_release.py',
    'test_benchmark_reporting.py',
    'test_benchmark_runner.py',
    'test_benchmark_scoring.py',
    'test_benchmark_team.py',
    'test_benchmark_typesafe.py',
    'test_benchmark_windows.py',
    'test_benchmark_difficulty.py',
    'test_benchmark_diagnostics.py',
    'test_benchmark_holdout.py',
    'test_benchmark_import_otrf.py',
    'test_benchmark_store.py',
    'test_benchmark_corpus.py',
    'test_benchmark_baselines.py',
    'test_benchmark_consensus.py',
    'test_benchmark_attack.py',
    'test_benchmark_import_attackdata.py',
    'envision_protocol.py',
    'test_envision_protocol.py',
    'benchmarks/README.md',
    'benchmarks/coverage.json',
    'benchmarks/team-workflow.json',
    'benchmarks/prompt-contract.txt',
    'benchmarks/examples/experiment.json',
    'benchmarks/examples/experiment-graduated.json',
    'benchmarks/tools/fixture_cases.py',
    'benchmarks/tools/generate_fixtures.py',
    'benchmarks/tools/generate_attack_aliases.py',
    'benchmarks/attack-v20-techniques.json',
    'benchmarks/importers/README.md',
    'benchmarks/importers/otrf-fields.json',
    'benchmarks/importers/sample/curation.json',
    'benchmarks/importers/sample/SDWIN-990101000001.yaml',
    'benchmarks/importers/sample/sample_owner_discovery_2026-01-0100000000.json',
    'benchmarks/importers/sample/curation-nxlog.json',
    'benchmarks/importers/sample/SDWIN-990101000002.yaml',
    'benchmarks/importers/sample/sample_nxlog_discovery_2026-01-0100000000.json',
    'benchmarks/importers/attackdata-fields.json',
    'benchmarks/importers/sample/attackdata-sample-linux.yml',
    'benchmarks/importers/sample/attackdata-sample-cloudtrail.yml',
    'benchmarks/importers/sample/attackdata_sample_auditd.log',
    'benchmarks/importers/sample/attackdata_sample_auditd_interpreted.log',
    'benchmarks/importers/sample/attackdata_sample_cloudtrail.json',
    'benchmarks/importers/sample/curation-attackdata-auditd.json',
    'benchmarks/importers/sample/curation-attackdata-cloudtrail.json',
    'benchmarks/fixtures/case-8b42/scenario.json',
    'benchmarks/fixtures/case-8b42/public/evidence.json',
    'benchmarks/fixtures/case-8b42/public/records.jsonl',
    'benchmarks/fixtures/case-8b42/evaluator/truth.json',
    'benchmarks/fixtures/case-5c21/scenario.json',
    'benchmarks/fixtures/case-5c21/public/evidence.json',
    'benchmarks/fixtures/case-5c21/public/records.jsonl',
    'benchmarks/fixtures/case-5c21/evaluator/truth.json',
    'benchmarks/fixtures/case-7d33/scenario.json',
    'benchmarks/fixtures/case-7d33/public/evidence.json',
    'benchmarks/fixtures/case-7d33/public/records.jsonl',
    'benchmarks/fixtures/case-7d33/evaluator/truth.json',
    'benchmarks/fixtures/case-9e44/scenario.json',
    'benchmarks/fixtures/case-9e44/public/evidence.json',
    'benchmarks/fixtures/case-9e44/public/records.jsonl',
    'benchmarks/fixtures/case-9e44/evaluator/truth.json',
    'benchmarks/fixtures/case-af55/scenario.json',
    'benchmarks/fixtures/case-af55/public/evidence.json',
    'benchmarks/fixtures/case-af55/public/records.jsonl',
    'benchmarks/fixtures/case-af55/evaluator/truth.json',
    'benchmarks/fixtures/case-b060/scenario.json',
    'benchmarks/fixtures/case-b060/public/evidence.json',
    'benchmarks/fixtures/case-b060/public/records.jsonl',
    'benchmarks/fixtures/case-b060/evaluator/truth.json',
    'benchmarks/fixtures/case-c070/scenario.json',
    'benchmarks/fixtures/case-c070/public/evidence.json',
    'benchmarks/fixtures/case-c070/public/records.jsonl',
    'benchmarks/fixtures/case-c070/evaluator/truth.json',
    'benchmarks/fixtures/case-d080/scenario.json',
    'benchmarks/fixtures/case-d080/public/evidence.json',
    'benchmarks/fixtures/case-d080/public/records.jsonl',
    'benchmarks/fixtures/case-d080/evaluator/truth.json',
    'benchmarks/fixtures/case-e090/scenario.json',
    'benchmarks/fixtures/case-e090/public/evidence.json',
    'benchmarks/fixtures/case-e090/public/records.jsonl',
    'benchmarks/fixtures/case-e090/evaluator/truth.json',
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

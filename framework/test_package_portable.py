import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import zipfile


SOURCE = Path(__file__).absolute().parent
PREFIX = 'hermes-bot-framework/'

# Public release contract, independent of the exporter's allowlist.
APPROVED_FILES = frozenset({
    '.gitignore', 'README.md', 'hermes-setup.md', 'optional-runtime.md',
    'LICENSE',
    'bot.py', 'workflows.py', 'orchestrate.py', 'langchain_adapter.py',
    'native_team.py', 'doctor.py', 'test_doctor.py',
    'requirements-orchestration.txt', 'setup_hermes.py', 'package_portable.py',
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
    'hermes_temporal/practice.py',
    'hermes_temporal/test_practice.py',
    'hermes_temporal/lab_input.py',
    'hermes_temporal/test_lab_input.py',
    'hermes_temporal/ontology.py',
    'hermes_temporal/test_ontology.py',
    'hermes_temporal/test_hunt.py',
    'hermes_temporal/board.py',
    'hermes_temporal/board_page.html',
    'hermes_temporal/test_board.py',
    'hermes_temporal/fixtures/board/lab-input.json',
    'hermes_temporal/fixtures/board/parent-status.json',
    'hermes_temporal/fixtures/board/child-status.json',
    'hermes_temporal/fixtures/replay/handoff-rejected-before-retry.json',
    'lab.py',
    'test_hunt_lab_case.py',
    'test_hunt_lab_runtime.py',
    'test_hunt_lab_managed.py',
    'test_hunt_lab_install.py',
    'test_hunt_lab_tools.py',
    'test_lab_server.py',
    'test_lab_browser.py',
    'test_humanize.py',
    'hunt_lab/__init__.py',
    'hunt_lab/runtime.py',
    'hunt_lab/managed.py',
    'hunt_lab/prepare_guest.py',
    'hunt_lab/query_adapter.py',
    'hunt_lab/endpoints.py',
    'hunt_lab/lab_browser.py',
    'hunt_lab/browser_policy.py',
    'hunt_lab/humanize.py',
    'hunt_lab/actionability.py',
    'hunt_lab/plugin.yaml',
    'hunt_lab/assets.json',
    'hunt_lab/case.py',
    'hunt_lab/scenario.py',
    'hunt_lab/screencast.py',
    'hunt_lab/test_scenario.py',
    'hunt_lab/guest/compose.yaml',
    'hunt_lab/guest/arkime.ini',
    'hunt_lab/guest/bootstrap_guest.sh',
    'hunt_lab/guest/ingest.py',
    'hunt_lab/guest/lab_server.py',
    'hunt_lab/guest/image-lock.json',
    'hunt_lab/guest/kibana.yml',
    'hunt_lab/guest/kibana_setup.py',
    'hunt_lab/fixtures/dns-lab-001/events.jsonl',
    'hunt_lab/fixtures/dns-lab-001/traffic.pcap',
    'hunt_lab/fixtures/dns-lab-001/case.json',
    'hunt_lab/desktop/plugin.js',
    'hunt_lab/desktop/package.json',
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
    'hermes-bots/framework-builder/.gitignore',
    'hermes-bots/framework-builder/SOUL.md',
    'hermes-bots/framework-builder/distribution.yaml',
    'hermes-bots/framework-coordinator/.gitignore',
    'hermes-bots/framework-coordinator/SOUL.md',
    'hermes-bots/framework-coordinator/distribution.yaml',
    'hermes-bots/framework-librarian/.gitignore',
    'hermes-bots/framework-librarian/SOUL.md',
    'hermes-bots/framework-librarian/distribution.yaml',
    'hermes-bots/framework-network-analyst/.gitignore',
    'hermes-bots/framework-network-analyst/SOUL.md',
    'hermes-bots/framework-network-analyst/distribution.yaml',
    'hermes-bots/framework-researcher/.gitignore',
    'hermes-bots/framework-researcher/SOUL.md',
    'hermes-bots/framework-researcher/distribution.yaml',
    'hermes-bots/framework-reviewer/.gitignore',
    'hermes-bots/framework-reviewer/SOUL.md',
    'hermes-bots/framework-reviewer/distribution.yaml',
})


class PortablePackageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.source = self.base / 'source'
        for name in APPROVED_FILES:
            dest = self.source / name
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(SOURCE / name, dest)
        spec = importlib.util.spec_from_file_location('portable_export_test',
                                                      self.source / 'package_portable.py')
        self.exporter = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.exporter)

    def call(self, *args, cwd=None):
        return subprocess.run([sys.executable, str(self.source / 'package_portable.py'), *args],
                              cwd=cwd or self.base, capture_output=True, text=True)

    def test_archive_content_checksums_extract_and_reproducibility(self):
        canary = 'portable-' + 'private-' + 'canary-592811'
        for name in ('.env', 'auth.json', 'profiles/private.json', 'sessions/token',
                     'roles/.venv/secrets.txt', 'hermes-bots/framework-builder/auth.json',
                     'desktop/cybersecurity-workspace/.env', 'desktop/live-group.json',
                     'desktop/private-notes.txt',
                     'hunt_lab/managed/downloads/private.img',
                     'hunt_lab/hunt-lab-vm/deployment.json',
                     'hunt_lab/fixtures/dns-lab-001/truth.json',
                     'hermes_temporal/.env', '.temporal-tools/private.txt',
                     'temporal-runtime/temporal.db', 'hermes_temporal/receipts.sqlite3',
                     'benchmark.sqlite3', 'benchmark-state/benchmark.sqlite3',
                     'benchmark-state/trials/private/response.json',
                     'benchmark-state/campaigns/private/raw/export.json',
                     'benchmarks/examples/experiment-private.json',
                     'benchmarks/config/provider.json', 'benchmarks/.env',
                     'benchmarks/evaluator/real-truth.json',
                     'benchmarks/fixtures/case-real/evaluator/truth.json',
                     'benchmarks/fixtures/case-8b42/evaluator/private-map.json',
                     'benchmarks/fixtures/case-8b42/public/raw-export.json',
                     'hunt-range/benchmark/linux_worker.py',
                     'hunt-range/benchmark/Invoke-BenchmarkAction.ps1',
                     'hunt-range/benchmark/recipes.json',
                     'hunt-range/benchmark/collector-fields.json',
                     'range-kit/linux_worker.py', 'range-kit/stratus.exe',
                     'envision_queue.py', 'test_envision_queue.py',
                     'AGENTS.md', 'CLAUDE.md', 'bot-workspace/data.sqlite'):
            path = self.source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(canary, encoding='utf-8')
        external_runtime = self.base / 'hunt-range' / 'benchmark'
        external_runtime.mkdir(parents=True)
        for name in ('linux_worker.py', 'Invoke-BenchmarkAction.ps1', 'recipes.json',
                     'collector-fields.json', 'stratus.exe'):
            (external_runtime / name).write_text(canary, encoding='utf-8')
        first = self.base / 'first.zip'
        second = self.base / 'second.zip'
        result = self.call('--output', str(first))
        self.assertEqual(result.returncode, 0, result.stderr)
        digest = hashlib.sha256(first.read_bytes()).hexdigest()
        self.assertIn(str(first), result.stdout)
        self.assertIn(digest, result.stdout)
        self.assertEqual(self.call('--output', str(second)).returncode, 0)
        self.assertEqual(first.read_bytes(), second.read_bytes())
        extraction = self.base / 'extracted'
        with zipfile.ZipFile(first) as archive:
            members = archive.namelist()
            self.assertEqual(set(members), {PREFIX + name for name in APPROVED_FILES} |
                             {PREFIX + 'SHA256SUMS'})
            self.assertEqual(len(members), len(APPROVED_FILES) + 1)
            self.assertFalse(any(canary.encode('utf-8') in archive.read(name) for name in archive.namelist()))
            checksums = archive.read(PREFIX + 'SHA256SUMS').decode('utf-8').splitlines()
            expected_sums = ['{}  {}'.format(hashlib.sha256((self.source / name).read_bytes()).hexdigest(), name)
                             for name in sorted(APPROVED_FILES)]
            self.assertEqual(checksums, expected_sums)
            for name in APPROVED_FILES:
                self.assertEqual(archive.read(PREFIX + name), (self.source / name).read_bytes())
            archive.extractall(extraction)
        for name in APPROVED_FILES:
            self.assertEqual((extraction / PREFIX / name).read_bytes(), (self.source / name).read_bytes())
        kit = extraction / PREFIX
        # Disable site packages and inherited Python paths: imports must close
        # over the extracted source plus the standard library, without SDKs.
        modules = sorted(Path(name).stem for name in APPROVED_FILES
                         if '/' not in name and name.endswith('.py') and
                         (name.startswith(('benchmark', 'test_benchmark')) or
                          name in ('envision_protocol.py', 'test_envision_protocol.py')))
        import_script = (
            'import importlib, pathlib, sys\n'
            'root = pathlib.Path(sys.argv[1]).resolve()\n'
            'sys.path.insert(0, str(root))\n'
            'for name in sys.argv[2:]:\n'
            '    module = importlib.import_module(name)\n'
            '    assert pathlib.Path(module.__file__).resolve().parent == root, name\n'
        )
        imports = subprocess.run(
            [sys.executable, '-I', '-S', '-B', '-c', import_script, str(kit), *modules],
            cwd=self.base, capture_output=True, text=True)
        self.assertEqual(imports.returncode, 0, imports.stderr)

        def benchmark(*args):
            result = subprocess.run(
                [sys.executable, '-E', '-S', '-B', str(kit / 'benchmark.py'), *args],
                cwd=self.base, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            return json.loads(result.stdout)

        for example, case_count in (('experiment.json', 1),
                                    ('experiment-graduated.json', 9)):
            with self.subTest(example=example):
                manifest = kit / 'benchmarks' / 'examples' / example
                bundle = kit / 'benchmarks'
                config = json.loads(manifest.read_text(encoding='utf-8'))
                state = self.base / ('state-' + manifest.stem)
                validated = benchmark('validate', '--experiment', str(manifest),
                                      '--bundle-root', str(bundle))
                self.assertTrue(validated['valid'])
                self.assertFalse(validated['network_access'])
                self.assertEqual(validated['cases'], case_count)
                self.assertFalse(state.exists())
                initialized = benchmark('--state-root', str(state), 'init',
                                        '--experiment', str(manifest),
                                        '--bundle-root', str(bundle),
                                        '--truth', str(bundle / 'fixtures'))
                self.assertTrue(initialized['initialized'])
                report = benchmark('--state-root', str(state), 'status',
                                   '--experiment', config['experiment_id'])
                self.assertTrue(report['truth_frozen'])
                self.assertEqual(report['review_policy'], 'auto_advance')
                self.assertEqual(report['execution'], 'framework-managed')
                self.assertEqual(len(report['trials']),
                                 case_count * len(config['teams']) * config['repetitions'])
                self.assertEqual(report['execution_prerequisites'], [])
                for trial in report['trials']:
                    self.assertNotIn('error', trial)
                    self.assertEqual(len(trial['stages']), 7)
                    self.assertEqual(len({stage['role'] for stage in trial['stages']}), 6)
                    for stage in trial['stages']:
                        self.assertEqual(stage['ledger_status'], 'pending')
                        self.assertIsNone(stage['last_call_id'])
                        self.assertIsNone(stage['last_call_status'])

    def test_output_required_and_existing_file_preserved(self):
        self.assertNotEqual(self.call().returncode, 0)
        output = self.base / 'existing.zip'
        output.write_bytes(b'prior data')
        result = self.call('--output', str(output))
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(output.read_bytes(), b'prior data')

    def test_catalog_tampering_rejected_without_output(self):
        path = self.source / 'hermes-bots/catalog.json'
        original = json.loads(path.read_text(encoding='utf-8'))
        for key, value in (('name', 'other-profile'), ('distribution_path', '../private'),
                           ('soul_path', '../secret')):
            with self.subTest(key=key):
                data = [dict(entry) for entry in original]
                data[0][key] = value
                path.write_text(json.dumps(data), encoding='utf-8')
                output = self.base / (key + '.zip')
                self.assertNotEqual(self.call('--output', str(output)).returncode, 0)
                self.assertFalse(output.exists())
        path.write_text(json.dumps(original + [original[0]]), encoding='utf-8')
        self.assertNotEqual(self.call('--output', str(self.base / 'duplicate.zip')).returncode, 0)
        path.write_text(json.dumps([entry for entry in original
                                    if entry['name'] != 'framework-network-analyst']), encoding='utf-8')
        output = self.base / 'missing-network-analyst.zip'
        self.assertNotEqual(self.call('--output', str(output)).returncode, 0)
        self.assertFalse(output.exists())

    def test_missing_and_nonregular_sources_rejected(self):
        path = self.source / 'roles/coordinator.txt'
        path.unlink()
        output = self.base / 'missing.zip'
        self.assertNotEqual(self.call('--output', str(output)).returncode, 0)
        self.assertFalse(output.exists())
        path.mkdir()
        self.assertNotEqual(self.call('--output', str(output)).returncode, 0)
        self.assertFalse(output.exists())

    def test_allowlisted_hard_link_rejected_without_output(self):
        target = self.base / 'public-synthetic-outside.txt'
        canary = b'Public synthetic outside-kit canary; not private data.'
        target.write_bytes(canary)
        file_path = self.source / 'roles/coordinator.txt'
        file_path.unlink()
        try:
            os.link(target, file_path)
        except (OSError, NotImplementedError) as exc:
            self.skipTest('Creating hard links unavailable: {}'.format(exc))
        output = self.base / 'hard-link.zip'
        self.assertNotEqual(self.call('--output', str(output)).returncode, 0)
        self.assertFalse(output.exists())
        self.assertEqual(target.read_bytes(), canary)

    def test_source_file_and_directory_symlinks_rejected(self):
        target = self.base / 'outside.txt'
        target.write_text('private', encoding='utf-8')
        file_path = self.source / 'roles/coordinator.txt'
        file_path.unlink()
        try:
            file_path.symlink_to(target)
        except (OSError, NotImplementedError) as exc:
            self.skipTest('Creating symlinks unavailable: {}'.format(exc))
        output = self.base / 'link.zip'
        self.assertNotEqual(self.call('--output', str(output)).returncode, 0)
        self.assertFalse(output.exists())
        self.assertEqual(target.read_text(encoding='utf-8'), 'private')
        file_path.unlink()
        shutil.copyfile(SOURCE / 'roles/coordinator.txt', file_path)
        roles = self.source / 'roles'
        real_roles = self.base / 'real-roles'
        roles.rename(real_roles)
        try:
            roles.symlink_to(real_roles, target_is_directory=True)
        except (OSError, NotImplementedError) as exc:
            self.skipTest('Creating directory symlinks unavailable: {}'.format(exc))
        self.assertNotEqual(self.call('--output', str(output)).returncode, 0)
        self.assertFalse(output.exists())
        self.assertTrue((real_roles / 'coordinator.txt').is_file())

    def test_symlinked_parent_outside_kit_is_supported(self):
        parent_alias = self.base / 'parent-alias'
        try:
            parent_alias.symlink_to(self.base, target_is_directory=True)
        except (OSError, NotImplementedError) as exc:
            self.skipTest('Creating directory symlinks unavailable: {}'.format(exc))
        output = self.base / 'parent-alias.zip'
        result = subprocess.run(
            [sys.executable, str(parent_alias / 'source/package_portable.py'),
             '--output', str(output)],
            cwd=self.base, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        with zipfile.ZipFile(output) as archive:
            self.assertEqual(archive.read(PREFIX + 'roles/coordinator.txt'),
                             (self.source / 'roles/coordinator.txt').read_bytes())

    def test_kit_root_symlink_is_rejected(self):
        root_alias = self.base / 'kit-alias'
        try:
            root_alias.symlink_to(self.source, target_is_directory=True)
        except (OSError, NotImplementedError) as exc:
            self.skipTest('Creating directory symlinks unavailable: {}'.format(exc))
        output = self.base / 'root-alias.zip'
        result = subprocess.run(
            [sys.executable, str(root_alias / 'package_portable.py'),
             '--output', str(output)],
            cwd=self.base, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(output.exists())

    def test_partial_archive_removed_on_write_failure(self):
        output = self.base / 'partial.zip'
        unrelated = self.base / 'unrelated'
        unrelated.write_bytes(b'keep')
        with mock.patch.object(self.exporter.zipfile.ZipFile, 'writestr', side_effect=OSError('write failed')):
            with self.assertRaises(OSError):
                self.exporter.package(output)
        self.assertFalse(output.exists())
        self.assertEqual(unrelated.read_bytes(), b'keep')


if __name__ == '__main__':
    unittest.main()

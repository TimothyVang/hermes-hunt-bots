# Upstream provenance and local adaptations

This directory contains Cloudflare's `security-audit` skill, adapted for native Hermes. Upstream project: [cloudflare/security-audit-skill](https://github.com/cloudflare/security-audit-skill), MIT-licensed; copyright and license terms are preserved in [LICENSE](LICENSE).

## Pin

- Git commit: [`c1c8a8c1471069fb0e188eeaff69b8e8db6564a8`](https://github.com/cloudflare/security-audit-skill/commit/c1c8a8c1471069fb0e188eeaff69b8e8db6564a8)
- Commit API: <https://api.github.com/repos/cloudflare/security-audit-skill/commits/c1c8a8c1471069fb0e188eeaff69b8e8db6564a8>
- Retrieved from public raw URLs under `https://raw.githubusercontent.com/cloudflare/security-audit-skill/c1c8a8c1471069fb0e188eeaff69b8e8db6564a8/` without credentials.
- GitHub reports the commit as **unsigned** (`verified: false`, reason `unsigned`). The SHA pins the reviewed source identity; it is not a signature/authenticity claim.
- Upstream skill directory: `skills/security-audit/`. The upstream root `LICENSE` is copied here unchanged.

## Included upstream paths

All paths below are relative to upstream `skills/security-audit/` and pinned to the commit above:

- `AI-AND-LLM.md`
- `ATTACK-CLASSES.md`
- `CLIENT-SIDE.md`
- `CLOUD-AND-DEPLOYMENT.md`
- `DATA-ISOLATION-AND-LIFECYCLE.md`
- `DESKTOP-MOBILE-AND-LOCAL-IPC.md`
- `HUNTING.md`
- `MEMORY-SAFETY-AND-BINARY.md`
- `PROTOCOLS-RPC-AND-MESSAGING.md`
- `RECONNAISSANCE.md`
- `RESOURCE-EXHAUSTION-AND-AVAILABILITY.md`
- `SKILL.md`
- `SUPPLY-CHAIN-AND-RELEASE.md`
- `VALIDATION-AND-REPORTING.md`
- `WEB-PROTOCOL-AND-AUTH.md`
- `report-schema.json`
- `validate-coverage-ledger.cjs`
- `validate-coverage-ledger.test.cjs`
- `validate-findings.cjs`
- `validate-findings.test.cjs`

`SKILL.md` contains the upstream content with the local Hermes-native adaptation below. `LICENSE` is upstream `LICENSE`, not an upstream skill-directory file.

## Local adaptations

- Replaced generic platform terminology with Hermes native `delegate_task` coordinator, researcher, hunter, and fresh verifier responsibilities. Delegated tasks are explicitly bounded; unsupported `role` fields, provider SDKs, OMP runtime, implicit route substitution, and claims of model independence from labels are prohibited.
- Added an explicit pre-audit human authorization gate for repository root, approved paths, purpose, data boundary/exclusions, and output directory. Activation or current working directory never implies permission.
- Added untrusted-repository-content handling, no-secret/live-profile reading boundaries, prohibitions on fleet/ingest/schedule/retry/issue/remediation actions, and target baseline preservation.
- Made execution conditional on an independently approved OS-enforced sandbox with external network disabled, sanitized environment, read-only target/toolchain, scratch-only writes, and resource bounds. A bundled VM is not sufficient. Missing controls keep claims `needs_validation`; no seccomp/AppArmor weakening workaround.
- Clarified that fixtures must be synthetic, validators check structure rather than vulnerability truth, and Cloudflare's blog describes broader private fleet mechanisms not implemented here.
- Mapped responsibilities to the existing six cybersecurity roles and required a finite human-approved total-agent cap before reconnaissance; upstream unset-budget wording cannot authorize unlimited local work.
- Documented the validators' fail-closed Windows limitation and Linux runtime prerequisite; no upstream file-safety checks were weakened.
- Added only a scoped cross-reference in `../threat-hunt/SKILL.md`; evidence-supplied threat hunting does not gain audit/path/scan/execution authorization.
- Remaining guides, schema, validators, and their tests are pinned upstream copies. They are supporting audit material, not permission to bypass the local rules in `SKILL.md`.

## Local SHA-256 inventory

Hashes below identify the delivered local bytes (the locally adapted `SKILL.md` therefore differs from upstream). Recompute when updating the package. `PROVENANCE.md` and the cross-reference in `threat-hunt` are local additions and are not upstream files.

```text
7335a95c43554eadefcf03ece639291bb0e038c398a179299e3887ffe06bd2ef  AI-AND-LLM.md
3ee4f00c6e8c9dcf6dd02dd5ac2a4ceb322e2085f3e9fbe79cf0c6330bc7ef83  ATTACK-CLASSES.md
613f6b98f86083e045525c5b60154ffdab122bac35f1e05eb17488e6e453370c  CLIENT-SIDE.md
3c80f3088be22345e07b057c056d6ed99fe2b0304f794398964f7ccd5a496ca3  CLOUD-AND-DEPLOYMENT.md
307dcb3e24d292715c4a041190e7bb135646a37eb6187619ae01d000a634a4ad  DATA-ISOLATION-AND-LIFECYCLE.md
58eae8ee0ca6a46611c501ec5a3ab47fdff88dd7db0d8d74789bbf8bb19d8cb2  DESKTOP-MOBILE-AND-LOCAL-IPC.md
71c121decea1322c47c718f6e110f1a892980bb4266bd7ac55ef043a213ade09  HUNTING.md
e598e694aa506650c7192d5ea3be0e50aca0d356ea00551c53429f0b01eb6391  LICENSE
7c8b0dccfb35315cca2455509674d49632b2fe37e1f3aac16c1a496a7e9924a7  MEMORY-SAFETY-AND-BINARY.md
8b73816fa5b3697c9c40977f0c836b40f01d6e81929ff2720fe83ce089e9a619  PROTOCOLS-RPC-AND-MESSAGING.md
02ca887aca84de8ae137f1891bd2f0a54f28d3fa6da92a27f54734382b3381a2  RECONNAISSANCE.md
4326fab5c92a0b4c420a70196254040105cd794026562130b59bf1a6db3e4baa  RESOURCE-EXHAUSTION-AND-AVAILABILITY.md
80ce797ee38c9cf6f23542a30437e545491f16945cb68920a34d9b32a43bfdcc  SKILL.md
f372e919940e335468ba1ae09f99026c3986a345f7fe26f8068f132e199f52a5  SUPPLY-CHAIN-AND-RELEASE.md
b892470cb89bb31f33403e050d4bdfbe2cdaef940ade1496fa65e32b2e129449  VALIDATION-AND-REPORTING.md
4f3066dffa23c5635859187be9b96c32f2aff29a688186b91ff0c63e47d62b5c  WEB-PROTOCOL-AND-AUTH.md
6575c9de4a62255699ea052ebf9a49ebfb373a32891bcd89af6f55cc84b35519  report-schema.json
2eb280bd2e33c002916f86db9b29f9edfedb6454e5db973c766290465b868ac8  validate-coverage-ledger.cjs
cfb9df26b03469a4279a70e7664a2a5434dd6f8c2c204e91f9b0aeb9dd71e648  validate-coverage-ledger.test.cjs
e85f232e36bfac0f866f244da50376692d6b45c690beadcb00608b0e6c8b5283  validate-findings.cjs
b92001117a92c4161d43777a0ba2fa182a8a4d97f2304cc8c0cee5331497b73b  validate-findings.test.cjs
```

## Safe synthetic-only checks (for the integrating parent)

Do not direct these checks at an actual target or real findings. The tests construct synthetic records, temporary files, and validator inputs; they do not establish a vulnerability or sandbox capability. Run the complete validator suite on Linux with Node.js. Native Windows lacks the required no-follow/nonblocking input primitives and the pinned CLI intentionally refuses input there.

```sh
node --test framework/hermes-skills/security-audit/validate-findings.test.cjs framework/hermes-skills/security-audit/validate-coverage-ledger.test.cjs
```

The validators' CLI accepts a path to a JSON document, not a repository target. To smoke each validator without hand-authored real findings, use a temporary synthetic empty array created by the test suite or parent in a disposable temporary directory, then invoke:

```sh
node framework/hermes-skills/security-audit/validate-findings.cjs <TEMP>/synthetic-findings.json
node framework/hermes-skills/security-audit/validate-coverage-ledger.cjs <TEMP>/synthetic-coverage-ledger.json
```

`<TEMP>` must be a parent-created disposable directory; each JSON file must contain only `[]`. No audit, provider call, network access, target execution, install, live profile change, or output to a real target is part of these checks.

## Verification actually exercised

- On Windows: 65 tests ran; 46 passed, 7 failed, and 12 were skipped. The failing CLI assertions encountered the OS file-protection refusal before their intended input-validation branches. Both real CLIs independently refused synthetic `[]` input with that same protection error.
- In an Ubuntu WSL test environment with an empty allowlisted environment and disposable test directories: **65 tests passed, zero failed or skipped**. No system Node installation was changed; a temporary official Linux Node 24.22.2 binary was used. Its archive SHA-256 matched the publisher's `48cc0e21e048790e54c0cf5749c2725005313d652651c40b7a21feb9697aaf75`.
- Both actual Linux CLI commands returned exit 0 for parent-created synthetic empty arrays: `PASS: 0 findings valid` and `PASS: 0 coverage units valid`. Empty arrays are fixture input, not a claim that an audited repository has no vulnerabilities.
- This was not a run in the new portable VM, a real audit, provider inference, native bot delegation, or proof of an OS-enforced target-execution sandbox. Those claims remain unverified.

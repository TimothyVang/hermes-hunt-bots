# Hermes Hunt Bots

A fork of [NousResearch/hermes-agent](https://github.com/NousResearch/hermes-agent) that turns the Hermes desktop app into a six-bot threat-hunting team. Each bot drives its own read-only lab tool (Elastic, Arkime, a threat-intel feed, a detection tester) against invented data in a local QEMU lab VM, and hands its findings to the next bot through validated, human-gated handoffs.

Built in the open. This file is the project's rulebook: **every contributor, human or AI agent, follows it, and it overrides upstream guidance where they conflict.**

## What is here

| Path | What it is | License |
|---|---|---|
| `framework/` | The six-bot team: lab tools, Temporal workflows, hunting lab, scenario generator and scorer, Hunt Board, benchmarks, tests. Start with [framework/README.md](framework/README.md). | AGPL-3.0 ([framework/LICENSE](framework/LICENSE)) |
| `operator/` | Operator tools around the hunts: the watcher improvement loop, case switching, the opt-in delegated gate driver, rejection diagnosis, the tool cam and honest video assembly. They read operator-only answer keys, so nothing here feeds bot prompts. See [operator/README.md](operator/README.md). | AGPL-3.0 ([framework/LICENSE](framework/LICENSE)) |
| Everything else | Hermes 0.23.0 (upstream commit `2bd378ed`) plus our reviewed desktop fixes | MIT ([LICENSE](LICENSE)) |
| `../runtime/` (next to the clone, never inside it) | Your local lab: Hermes environments, the VM, cases, answer keys, runs. The lab refuses VM state inside any Git repository. | — |

Copied third-party code keeps its own license and notice, listed in `THIRD-PARTY-NOTICES.md`.

## Rules (enforced)

**Safety.** These are not negotiable and Greptile reviews every PR against them.

1. **Synthetic data only.** Never commit real logs, packet captures, customer data, credentials, tokens, cookies, session stores, or anything marked CUI/NSS. Generated cases and answer keys stay in `runtime/`, next to the clone.
2. **Tools stay read-only and lab-local.** Bot tools may only read the loaded case through the guest lab service on `127.0.0.1`. No tool may control the VM, capture live traffic, reach other hosts, or read an answer key. Browser automation may only open lab origins (`127.0.0.1` / `localhost` lab ports); a change that lets a bot browse elsewhere is rejected.
3. **Humans approve.** Execution and review gates stay human decisions. Never fabricate approvals, evidence, model output, scores, or test results. Simulated or scripted runs are labelled as such.
4. **No real-money trading** and no unattended external actions (messaging, schedules, posting) without explicit opt-in.
5. **Honest claims.** Docs and PR descriptions state what was actually run and observed. "Enforced" means enforced at runtime, with a test; anything else is "configured" or "prompt guidance".

**Change process.**

6. **Everything lands by pull request** into `hunt-bots`. There is no hosted CI (GitHub Actions is off to keep the project free to run). Before opening or updating a PR, run `python scripts/hunt_bots_check.py` and paste its summary line into the PR. Greptile reviews every PR. Code owners approve `framework/`, `.github/`, `scripts/hunt_bots_check.py`, and this file.
7. **Tests with behavior.** A behavior change ships with a test that fails before and passes after, plus the docs it affects. Do not weaken a guard, cap, or test to make a check pass.
8. **The public file list is explicit.** Every tracked file under `framework/` is listed in [framework/TRACKED-FILES.txt](framework/TRACKED-FILES.txt); `scripts/hunt_bots_check.py` fails on anything else. Add new files there in the same PR.
9. **Third-party code needs its license.** Copying code (for example from the MIT omp browser tool or Orca, or the Apache-2.0 Playwright/agent-browser code) requires keeping the original notice, adding an entry to `THIRD-PARTY-NOTICES.md`, and marking modified files. Code with an unknown or incompatible license is not accepted.
10. **Upstream stays syncable.** Keep fork changes small and isolated, prefer plugins and `framework/` over core edits, and label PRs that touch upstream files with `upstream-touch`.

## Known gaps (help wanted)

- **Per-bot tool limits are prompt guidance today.** `agent.allowed_tool_names` is configured, but runtime enforcement needs `framework/desktop/native-role-policy.diff` ported to 0.23.0.
- **Lab browser calls are not on the tool cam yet.** `lab_browser` (Threat Hunter and Network Analyst) drives a real browser on Arkime and the lab console with accessibility-tree refs, actionability checks and human-like input, inside a lab-origin allowlist and Arkime case scoping enforced in the browser (see [framework/README.md](framework/README.md)). Its Arkime requests bypass the guest service, so they are in each bot's `audit.jsonl`, not in `/activity`, and the tool cam does not follow them. A bot's browser closes when its process exits. Hermes's stock browser has only a blocklist and stays off for the bots.
- **Desktop rebrand** (`apps/desktop/product-identity.cjs`) and shipping the Hunting Lab page as a bundled desktop plugin.
- **Network and intel findings cannot be scored.** The scorer credits only `evt-` event IDs. Arkime sessions and intel feed matches carry none, and the lab exposes no session ID or key shared with events, so the Network Analyst's and Threat Intelligence Analyst's evidence is invisible to `hunt_lab.scenario score` unless they also cite the matching events (`hunt_lab_query` with `dataset=events` returns `event.id`).
- **Answer keys are narrow.** Most evidence groups of a generated attack fact accept one or two specific events, so a report that proves the same step through a neighbouring event is not credited. Keys have not been checked by a human.
- **Filming tools assume a serial hunt.** `operator/film/` and `operator/toolcam/` expect nine stages that start one at a time and do not know the `dropped` step state of a parallel hunt.
- **A failed native run leaves no cause.** The worker discards Hermes's stderr, so a step that ends `native_nonzero` (seen live: a `merge` step exited after 26 seconds with zero tokens) records no reason. The parallel engine drops such an optional step and the hunt goes on, but the failure cannot be diagnosed afterwards.

## Contributing

The workflow follows [pstack](https://github.com/cursor/plugins/tree/main/pstack)'s poteto-mode playbooks: small verified units, proof from the real app, honest PR briefings. pstack is vendored in `.agents/` (MIT), and the project skill **`hunt-bots-pr`** (`.agents/skills/hunt-bots-pr/SKILL.md`) walks you or your coding agent through every step below. Agents that read `.agents/skills/` (OMP, Codex and others) find it automatically; in Claude Code or Cursor, point the agent at that file.

0. New here? Follow [GETTING-STARTED.md](GETTING-STARTED.md) first: clone, check, generate a case, install the bots, run a hunt.
1. Branch from `hunt-bots` and open the PR against `hunt-bots`. Prefer several narrow PRs to one large one; stack dependent PRs on their parent branch. Open PRs ready, not as drafts.
2. Title in Conventional Commits form, `type(scope): subject`, for example `fix(hunt_lab): report field_not_allowed refusals`.
3. Prove it works on the real thing (the lab, the desktop app, a live hunt), not only with tests. A bug fix shows the failure before and the pass after.
4. Run `python scripts/hunt_bots_check.py` (policy gate, framework tests, gitleaks when installed).
5. Write the PR body with these sections, short sentences, and nothing invented: `## Why`, `## What changed`, `## Scope` (what it leaves out), `## Tradeoffs` (only if there was a real choice), `## Blast Radius`, `## Verification` (each real run and its outcome, plus the check summary line).
6. Greptile reviews automatically. Triage every comment on its merits: fix it, dismiss it with a concrete reason, or ask. Do not churn code for nitpicks.

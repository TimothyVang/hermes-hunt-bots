---
name: hunt-bots-pr
description: Ship a change to hermes-hunt-bots the project's way. Branch from hunt-bots, work in deep-mode, prove it on the real lab or app, run the local gate, self-review with deep-mode's PR review, and open a ready Conventional-Commits PR. Use for any PR, stacked PRs, or a multi-PR project in this repository.
---

# Ship a change to hermes-hunt-bots

The project rules are in `HUNT-BOTS.md` at the repository root, and they override upstream Hermes guidance. Read it, and `framework/AGENTS.md` when you touch `framework/`, before you change anything. This skill adds the steps that turn a change into a reviewable PR. It runs on the [deep-mode](https://github.com/TimothyVang/deep-mode) plugin; install it first (`HUNT-BOTS.md` § Contributing). Without the plugin, stop and ask the user to install it.

There is no hosted CI and no paid review service. The gate runs locally, and reviews run on your own agent through deep-mode's PR review.

## Steps

1. **Start in deep-mode.** Run `/deep-mode:poteto <task>`, or read `skill://deep-mode` and follow its Route. It restates the goal, picks the playbook (Bug fix, Feature, Refactoring, Multi-phase plan, and so on) and sizes the work. Open the PR's `## Why` with the same goal.
2. **Branch from `hunt-bots`.** `git fetch origin` then `git switch -c <type>/<short-topic> origin/hunt-bots`. A PR that builds on another one branches from that PR's branch, and its PR targets that branch (a stack).
3. **Keep to the rules while you work.**
   - Synthetic data only. Never add credentials, tokens, cookies, session stores, real logs, or CUI/NSS material. Lab state stays in `runtime/` next to the clone, never inside it.
   - Bot tools stay read-only and lab-local, and browser automation stays on lab origins.
   - Copied code keeps its license and gets a row in `THIRD-PARTY-NOTICES.md`.
   - A new file under `framework/` gets a line in `framework/TRACKED-FILES.txt`, and a shipped one also goes in the portable package lists.
   - A behavior change ships with a test that fails before and passes after, plus the docs it affects.
4. **Prove it works on the real thing.** Run the lab, the desktop app, or a live hunt, and observe the changed behavior. Tests alone are not proof. Note each run and its outcome.
5. **Run the gate.** `python scripts/hunt_bots_check.py` must print `-> PASS`. It runs the policy gate, the framework test suite, and gitleaks when installed. Fix failures at the root; never weaken a guard, cap, or test to pass.
6. **Self-review.** Run deep-mode's PR review in local mode (`skill://deep-mode/references/techniques/pr-review.md`) on the committed branch, with `HUNT-BOTS.md` § Review as the project constraints. Fix, dismiss with a concrete reason, or ask for each finding, then re-run the gate if code changed.
7. **Commit.** Small, ordered commits, each one landable. The subject line uses Conventional Commits, `type(scope): subject`, for example `feat(hunt_lab): add the lab-origin browser allowlist`.
8. **Open the PR, ready, not draft.**
   - `git push -u origin HEAD`
   - `gh pr create --repo TimothyVang/hermes-hunt-bots --base hunt-bots --title "<type(scope): subject>" --body-file <file>`
   - Write the body from `.github/PULL_REQUEST_TEMPLATE.md`, in short sentences: `## Why`, `## What changed`, `## Scope`, `## Tradeoffs` (only for a real choice), `## Blast Radius`, `## Verification`. Verification lists each real run and its outcome, the gate's summary line, and the review line from step 6. State only what you ran.
   - Post the PR URL and keep building. Do not babysit each PR until the stack is complete.
9. **Answer review.** A maintainer reviews with `/deep-mode:review-pr <number>`. Triage each finding and any human comment as deep-mode's Babysit playbook does: fix it, dismiss it with a concrete reason in a reply, or ask. Push fixes as new commits, re-run the gate, and expect a re-review of the new head.
10. **Land.** A maintainer's own PR lands with `/deep-mode:land-pr <number>` (HUNT-BOTS.md `## Landing`): bot review in the PR, a three-verifier panel, then a merge only with green required checks. A contributor's PR waits for a code owner. For a stack, land from the bottom up per deep-mode's Shipping playbook. Never force-push a shared branch.

## Done means

- The gate prints `-> PASS`, and the PR lists real verification and the self-review line.
- Every review finding has a fix, a reasoned dismissal, or an open question.
- Docs, `framework/TRACKED-FILES.txt`, the portable package lists and `THIRD-PARTY-NOTICES.md` match the change.

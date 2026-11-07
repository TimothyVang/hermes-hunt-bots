---
name: hunt-bots-pr
description: Ship a change to hermes-hunt-bots the project's way. Branch from hunt-bots, work in pstack poteto-mode, prove it on the real lab or app, run the local gate, open a ready Conventional-Commits PR with the pstack briefing sections, and triage Greptile's review. Use for any PR, stacked PRs, or a multi-PR project in this repository.
---

# Ship a change to hermes-hunt-bots

The project rules are in `HUNT-BOTS.md` at the repository root, and they override upstream Hermes guidance. Read it, and `framework/AGENTS.md` when you touch `framework/`, before you change anything. This skill adds the steps that turn a change into a reviewable PR. It uses the pstack skills vendored in `.agents/skills/`; in OMP read `.agents/docs/harness/omp.md` first.

There is no hosted CI. The gate runs locally, and Greptile reviews every PR.

## Steps

1. **Restate the goal.** In one or two sentences, say what the user wants, the problem it solves, and the smallest change you expect to meet it. Open the PR's `## Why` with the same goal.
2. **Pick the pstack playbook.** Work in `/skill:poteto-mode` and copy the matching playbook's steps into your todo list (Bug fix, Feature, Refactoring, Multi-phase plan, and so on). A project of several PRs uses the Multi-phase or multi-PR plan playbook.
3. **Branch from `hunt-bots`.** `git fetch origin` then `git switch -c <type>/<short-topic> origin/hunt-bots`. A PR that builds on another one branches from that PR's branch, and its PR targets that branch (a stack).
4. **Keep to the rules while you work.**
   - Synthetic data only. Never add credentials, tokens, cookies, session stores, real logs, or CUI/NSS material. Lab state stays in `runtime/`, which is never committed.
   - Bot tools stay read-only and lab-local, and browser automation stays on lab origins.
   - Copied code keeps its license and gets a row in `THIRD-PARTY-NOTICES.md`.
   - A new file under `framework/` gets a line in `framework/TRACKED-FILES.txt`.
   - A behavior change ships with a test that fails before and passes after, plus the docs it affects.
5. **Prove it works on the real thing.** Run the lab, the desktop app, or a live hunt, and observe the changed behavior. Tests alone are not proof. Note each run and its outcome.
6. **Run the gate.** `python scripts/hunt_bots_check.py` must print `-> PASS`. It runs the policy gate, the framework test suite, and gitleaks when installed. Fix failures at the root; never weaken a guard, cap, or test to pass.
7. **Commit.** Small, ordered commits, each one landable. The subject line uses Conventional Commits, `type(scope): subject`, for example `feat(hunt_lab): add the lab-origin browser allowlist`.
8. **Open the PR, ready, not draft.**
   - `git push -u origin HEAD`
   - `gh pr create --repo TimothyVang/hermes-hunt-bots --base hunt-bots --title "<type(scope): subject>" --body-file <file>`
   - Write the body from `.github/PULL_REQUEST_TEMPLATE.md`, in short sentences: `## Why`, `## What changed`, `## Scope`, `## Tradeoffs` (only for a real choice), `## Blast Radius`, `## Verification`. Verification lists each real run and its outcome and the gate's summary line. State only what you ran.
   - Post the PR URL and keep building. Do not babysit each PR until the stack is complete.
9. **Triage Greptile.** Read the review with `gh pr view <number> --comments` (or the Files tab). Treat it skeptically, as pstack's review triage does. Fix real issues, dismiss noise with a concrete reason in a reply, and ask when the intent is unclear. Push fixes as new commits and re-run the gate.
10. **Land.** A code owner approves. For a stack, land from the bottom up per pstack's Shipping playbook. Never force-push a shared branch.

## Done means

- The gate prints `-> PASS`, and the PR lists real verification.
- Every Greptile comment has a fix, a reasoned dismissal, or an open question.
- Docs, `framework/TRACKED-FILES.txt`, and `THIRD-PARTY-NOTICES.md` match the change.

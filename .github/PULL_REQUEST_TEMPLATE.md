<!-- Title: Conventional Commits, type(scope): subject. Rules: HUNT-BOTS.md. Short sentences; state only what you ran. -->

## Why

<!-- The problem and the approach, 1-3 sentences. -->

## What changed

- 

## Scope

<!-- What this covers and what it deliberately leaves out. -->

## Tradeoffs

<!-- Only rejected alternatives a reviewer would ask about. Delete if none. -->

## Blast Radius

<!-- Who or what this touches, and why that is safe or risky. -->

## Verification

- `python scripts/hunt_bots_check.py`: <paste the summary line>
- deepmodebot self-review: <paste the review line, e.g. `review: ready at <short sha>, 1 round, open P0/P1/P2 0/0/0, fixed 2, dismissed 1`>
- <real run path and what you observed>

<!--
Checklist (HUNT-BOTS.md):
- Commits carry synthetic data only (real or work data stays in runtime/); no credentials, tokens, cookies, session stores, CUI/NSS.
- Bot tools stay read-only and lab-local; browser automation stays on lab origins.
- No fabricated approvals, evidence, scores or test results; "enforced" claims have a runtime test.
- New framework/ files are in framework/TRACKED-FILES.txt; copied code has its license and a THIRD-PARTY-NOTICES.md entry.
-->

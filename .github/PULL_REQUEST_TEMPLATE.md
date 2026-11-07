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
- <real run path and what you observed>

<!--
Checklist (HUNT-BOTS.md):
- Synthetic data only; no credentials, tokens, cookies, session stores, CUI/NSS.
- Bot tools stay read-only and lab-local; browser automation stays on lab origins.
- No fabricated approvals, evidence, scores or test results; "enforced" claims have a runtime test.
- New framework/ files are in framework/TRACKED-FILES.txt; copied code has its license and a THIRD-PARTY-NOTICES.md entry.
-->

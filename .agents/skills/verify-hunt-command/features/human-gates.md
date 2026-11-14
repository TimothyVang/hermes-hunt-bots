# Governed Human Gates

`Cybersecurity workspace` (`#/cybersecurity-workspace`) provides governed **Approve / Reject** controls for Temporal human gates (`scope` and `incident`, plus `execute`/`reconcile`), replacing the former CLI-only advisory dead-end while strictly enforcing `HUNT-BOTS.md` Rules 2, 3, and 4.

## Sub-features

- Prefills `Workflow ID` and loopback `127.0.0.1:7233` address when navigated from `Hunt Board`.
- `Load gate status` queries `PracticeWorkflow` / `HermesWorkflow` over loopback without mutating state.
- Rule 4 visibility enforcement: previews bot handoff claims under **`Bot-written, unverified:`** ONLY when `syntheticOnly === true` and `dataOrigin === 'synthetic'`; withholds all bot-written text (`ID-and-status view only`) on `public-dataset`, `work-export`, and `work-connected`.
- Rule 3 human authority enforcement: never auto-approves `scope` or `incident`; disables Approve/Reject until both **Operator name** (`1..200` printable chars) and **What did you check?** (`1..1000` chars) are provided.
- Sends decisions via `hermes_temporal.cli decision --decided-by <name> --via cli --evidence-note ...` and immediately refreshes recorded `decisions`.

## How to get to it (user POV)

Click **Human gates** in the status bar, **Cybersecurity workspace** in the left sidebar (`#/cybersecurity-workspace`), or **Decide in Hunt Command -> Human gates** inside `Hunt Board`.

## Driving it with control-hunt-command

Preconditions: A Temporal `HermesWorkflow` or `PracticeWorkflow` paused at `awaiting_review` (`scope` or `incident`) on `127.0.0.1:<port>`.

1. Action: Validate the exact governed CLI decision payload in dry-run mode.
   Command: `python .agents/skills/verify-hunt-command/control-hunt-command.py gate-decide --python <lock-python> --address 127.0.0.1:7233 --workflow-id <child-workflow-id> --step-id wave-1 --phase review --choice approve --decision-id gate-check-1 --operator "Alice Analyst" --note "Checked case.json scope and evt-0001" --dry-run`
   Observable result: `"ok": true` with `argv` containing `--decided-by Alice Analyst --via cli` and `--evidence-note`.
2. Action: In Hunt Command Desktop (`#/cybersecurity-workspace`), click **Load gate status**, fill **Operator name** and **What did you check?**, and click **Approve gate** (or run `gate-decide` without `--dry-run` to test the CLI seam).
   Command: `python .agents/skills/verify-hunt-command/control-hunt-command.py snapshot --port <board-port> --out <evidence-dir>/post-gate-decision.json`
   Observable result: `run.child.decisions` records the decision with `decided_by: "Alice Analyst"` and `via: "cli"`, and the workflow advances past the gate.

## Gotchas

- `What did you check?` intentionally clears after each recorded decision so Gate 2 (`incident`) cannot accidentally reuse Gate 1's (`scope`) note.
- Non-loopback Temporal addresses are rejected by both the renderer validator and `hermes_temporal.contracts.validate_loopback_address`.

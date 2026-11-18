# Hunt Command Feature Map

Index of executable user journeys for **Hunt Command Desktop** (`HERMES_DESKTOP_VARIANT=hunt`).

## Baseline Preconditions

- Run `python .agents/skills/verify-hunt-command/control-hunt-command.py doctor --python <lock-python> --hermes-home <isolated-hermes-home>` and confirm `"ok": true`.
- Every network call stays on `127.0.0.1` (`HUNT-BOTS.md` Rule 2).
- Never read or touch `../runtime/operator-only/` or non-isolated user state.

## Driving Conventions

- Prefer ARIA roles and accessible labels (`Workflow ID`, `Operator name`, `What did you check?`, `Start & attach board`, `Attach active board`, `Load gate status`, `Approve gate`, `Reject gate`) and routes (`#/hunt-lab`, `#/hunt-board`, `#/cybersecurity-workspace`).
- Verify zero load-time RPC before clicking action buttons.

## Proof and Skip Reporting

- Record exact commands, HTTP status/headers, and JSON snapshots under `<evidence-dir>`.
- If Docker Desktop or Temporal loopback server is not running for a journey that requires it, report the exact skipped precondition rather than faking a pass.

## Features

- [Hunting Lab Page](hunting-lab-page.md) — click-driven `Find profiles` auto-selection and read-only `status` inspection (`#/hunt-lab`).
- [Live Hunt Board & LabBrowserCard](hunt-board.md) — UI board launcher, dynamic loopback port discovery, and live MJPEG thumbnails (`#/hunt-board`).
- [Governed Human Gates](human-gates.md) — `scope` and `incident` review gates with Rule 3 & Rule 4 enforcement (`#/cybersecurity-workspace`).
- [Fresh Session & Canonical Bot Chat](bot-chat.md) — fresh session creation and 2-bot canonical `Bot Chat` exchange without model-pin skew.

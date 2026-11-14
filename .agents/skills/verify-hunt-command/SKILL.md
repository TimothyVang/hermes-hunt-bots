---
name: verify-hunt-command
description: Verify Hunt Command Desktop boards, gates, and bot chats.
---

# Verify Hunt Command Skill

Executable verification harness and feature map for the **Hunt Command** Electron desktop variant (`HERMES_DESKTOP_VARIANT=hunt`) and its two bundled plugins (`framework/hunt_lab/desktop/plugin.js` and `framework/desktop/cybersecurity-workspace/plugin.js`). It drives real loopback surfaces against an isolated `HERMES_HOME` and never touches operator-only directories or default user state.

## When to Use

- Proving changes to Hunt Command Desktop, `Hunt Board`, `LabBrowserCard`, `Hunting Lab`, `Cybersecurity workspace`, or `Bot Chat`.
- Verifying zero load-time RPC, click-driven local profile auto-selection, dynamic loopback board attachment, or governed human gate approvals (`scope` and `incident`).

## Prerequisites

- Node `>=26` with root workspace dependencies installed (`npm ci` at repo root).
- Python environment with `framework/requirements-hunt.lock` installed (`temporalio`, `websockets`).
- Always use an isolated `HERMES_HOME` (never default user home state and never `../runtime/operator-only/`).

## Launch

1. Pack the Hunt Command desktop variant and confirm `apps/desktop/assets` stays clean:
   ```powershell
   Push-Location apps/desktop
   npm run pack:hunt
   git status --porcelain -- assets
   Pop-Location
   ```
2. Run a launch dry-run or start an isolated instance with `control-hunt-command.py`:
   ```powershell
   python .agents/skills/verify-hunt-command/control-hunt-command.py launch --hermes-home <isolated-hermes-home> --evidence-dir <evidence-dir> --cdp-port 9333
   ```

## Doctor

Run `doctor` before driving any UI journey and whenever state looks unexpected:

```powershell
python .agents/skills/verify-hunt-command/control-hunt-command.py doctor --python <lock-python> --hermes-home <isolated-hermes-home>
```

`doctor` is strictly read-only: it verifies the lock Python, both Desktop plugin sources, clean `apps/desktop/assets`, packed binary presence (pass `--skip-packed-check` for source/CLI-only checks before `npm run pack:hunt`), and any active loopback `HuntBoard` endpoints registered under `<hermes-home>/hunt-board/`.

## Drive

1. Verify the strict zero-load-RPC VM contract first:
   ```powershell
   node --experimental-vm-modules framework/desktop/test-plugin.mjs framework/desktop/cybersecurity-workspace/plugin.js
   ```
2. Follow the target journey in `features/README.md`:
   - `features/hunting-lab-page.md` — click-driven `Find profiles` auto-selection + read-only `status`.
   - `features/hunt-board.md` — UI `Start & attach board` / `Attach active board` + dynamic-port live MJPEG `LabBrowserCard` stream.
   - `features/human-gates.md` — governed `scope` & `incident` approvals in `Cybersecurity workspace` (`HUNT-BOTS.md` Rules 2, 3, and 4).
   - `features/bot-chat.md` — fresh session creation and 2-bot canonical `Bot Chat` exchange.

## Evidence

Save snapshots, response headers, and Temporal workflow histories to an explicit `<evidence-dir>` outside tracked repo folders:

```powershell
python .agents/skills/verify-hunt-command/control-hunt-command.py board-probe --port <port> --profile framework-network-analyst
python .agents/skills/verify-hunt-command/control-hunt-command.py snapshot --port <port> --out <evidence-dir>/board-state.json
```

## Cleanup

Stop only the PID recorded by `launch`—never kill processes by name, and never delete `<evidence-dir>`:

```powershell
python .agents/skills/verify-hunt-command/control-hunt-command.py cleanup --pid-file <evidence-dir>/hunt-command.pid
```

## Helpers

- `.agents/skills/verify-hunt-command/control-hunt-command.py` — JSON CLI (`doctor`, `launch`, `board-probe`, `gate-decide`, `snapshot`, `logs`, `cleanup`).
- `.agents/skills/verify-hunt-command/features/README.md` — index of user-facing journeys and preconditions.

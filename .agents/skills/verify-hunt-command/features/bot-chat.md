# Fresh Session & Canonical Bot Chat

Hunt Command Desktop creates fresh profile sessions and runs 2-bot canonical `Bot Chat` exchanges across the six cybersecurity specialist profiles without `MODEL_PIN_SKEW` (`5019`) or unauthorized profile overwrites.

## Sub-features

- Fresh session creation on a local framework profile (`framework-coordinator`, `framework-network-analyst`, `framework-researcher`, `framework-builder`, `framework-reviewer`, `framework-librarian`).
- Canonical `Bot Chat` relay exchange between two framework bots (`@framework-network-analyst` / `@framework-coordinator`) with `ui_meta.hermes-bots` enabled.
- `ScreenSelector` in `#/cybersecurity-workspace` auto-selects local `framework-coordinator` on `Find profiles` and reads `display.status` without opening a screen until **Open screen** is clicked.

## How to get to it (user POV)

Select a framework bot in **Bot Mode** / sidebar, click **New Chat** (or open canonical `Bot Chat`), and send a scoped prompt tagging a peer bot handle.

## Driving it with control-hunt-command

Preconditions: Isolated `<hermes-home>` provisioned with the six framework profiles and a configured model provider.

1. Action: Verify VM contract (`Open screen` never fires on load or during `Find profiles` without explicit selection + click).
   Command: `node --experimental-vm-modules framework/desktop/test-plugin.mjs framework/desktop/cybersecurity-workspace/plugin.js`
   Observable result: Prints `workspace contract passed` and exits `0`.
2. Action: Launch isolated Hunt Command Desktop and inspect gateway logs after creating a fresh session and sending a 2-bot `Bot Chat` turn.
   Command: `python .agents/skills/verify-hunt-command/control-hunt-command.py logs --hermes-home <hermes-home> --lines 60`
   Observable result: Session starts cleanly with zero `5019` (`MODEL_PIN_SKEW`) errors and clean relay delivery.

## Gotchas

- Never disable `native_team.py` profile conflict guards or overwrite user-modified profiles to force a session open.

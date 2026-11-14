# Hunting Lab Page

`Hunting Lab` (`#/hunt-lab`) manages the local `framework-network-analyst` Docker practice lab with zero load-time RPC and click-driven local route auto-selection.

## Sub-features

- Zero RPC on plugin registration and initial route mount.
- Clicking **Find profiles** discovers unambiguous local `framework-network-analyst` routes, auto-selects the route, and immediately runs read-only `hunt-lab status`.
- Displays structured case health (`state`, `origin`, `case_id`, `project`, event/session counts, loopback console/Kibana/Arkime links when `running`).
- Explicit human **Start lab** and **Stop lab** actions with bounded read-only start observation.

## How to get to it (user POV)

Click **Hunting Lab** in the left sidebar (`#/hunt-lab`) or run **Open Hunting Lab** from the command palette, then click **Find profiles**.

## Driving it with control-hunt-command

Preconditions: Isolated `<hermes-home>` with `framework-network-analyst` installed (`framework/setup_hermes.py`).

1. Action: Verify plugin sources and environment health.
   Command: `python .agents/skills/verify-hunt-command/control-hunt-command.py doctor --python <lock-python> --hermes-home <hermes-home>`
   Observable result: `"ok": true`, `"hunt_lab_plugin_exists": true`.
2. Action: Run the Desktop UI unit suite exercising `/hunt-lab` click-driven auto-selection and read-only status.
   Command: `npx --prefix apps/desktop vitest run src/contrib/variant-plugins.test.ts`
   Observable result: Test `auto-selects local framework routes and fetches read-only status only after clicking Find profiles` passes.

## Gotchas

- Remote routes and duplicate local owners are excluded by design; `Find profiles` never falls back to an active chat profile or remote connection.

# Read-Only Evidence Queries

The Hunting Lab service exposes bounded, case-scoped, read-only endpoints (`/health`, `/es/search`, `/events`, `/network`, `/arkime/sessions`, `/arkime/unique`, `/activity`) on `127.0.0.1` and records specialist tool activity while excluding `hunt-board` observer polls from `/activity`.

## Sub-features

- `/health` reports `case_id`, `event_count`, `network_capture`, `kibana_ready`, and `arkime_viewer_ready`.
- `/es/search` and `/arkime/sessions` enforce case window and case-tag scoping; write/admin/packet/export routes are refused.
- Requests carrying `X-Hermes-Profile: hunt-board` are omitted from `/activity` so board polling never pollutes bot tool lanes.

## How to get to it (user POV)

Specialists invoke read-only lab tools (`hunt_lab_query`, `zeek_summary`, `arkime_query`) during a hunt, or an operator runs `bot.py lab query`.

## Driving it with control-hunt-lab

Preconditions: Lab running under `<isolated-hermes-home>` (resolved via `hunt_lab.endpoints.resolve`, which sends `X-Hunt-Lab-Secret` and verifies `X-Hunt-Lab-Instance` over a proxy-free `127.0.0.1` opener).

1. Action: Capture `/health` to an evidence file.
   Command: `python .agents/skills/verify-hunt-lab/control-hunt-lab.py snapshot --hermes-home <isolated-hermes-home> --out <evidence-dir>/lab-health.json`
   Observable result: `"ok": true` and `<evidence-dir>/lab-health.json` contains `case_id` and `event_count`.
2. Action: Query `/es/search?q=*` as `framework-researcher`, then inspect `/activity`.
   Command: `python .agents/skills/verify-hunt-lab/control-hunt-lab.py query --hermes-home <isolated-hermes-home> --endpoint "/es/search?q=*" --profile framework-researcher` followed by `python .agents/skills/verify-hunt-lab/control-hunt-lab.py query --hermes-home <isolated-hermes-home> --endpoint "/activity" --profile hunt-board --out <evidence-dir>/lab-activity.json`
   Observable result: `/activity` records the `framework-researcher` search and omits the `hunt-board` read (whereas unowned bot routes return `403 tool_not_owned`).

## Gotchas

- `lab_server.py` requires `X-Hunt-Lab-Secret` on every API route (`/health`, `/case`, `/activity`, `/es/search`, `/arkime/*`); pass `--hermes-home` or `--state-dir` (or `--lab-url` + `--secret` validated via `hunt_lab.endpoints.endpoint()`).
- Non-loopback `--lab-url` values (including credentialed URLs or out-of-range ports) are refused immediately (`Rule 2`).

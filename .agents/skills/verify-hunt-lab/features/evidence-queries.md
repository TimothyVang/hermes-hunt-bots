# Read-Only Evidence Queries

The Hunting Lab service exposes bounded, case-scoped, read-only endpoints (`/health`, `/es/search`, `/arkime/sessions`, `/arkime/spi`, `/activity`) on `127.0.0.1` and records specialist tool activity while excluding `hunt-board` observer polls from `/activity`.

## Sub-features

- `/health` reports `case_id`, `event_count`, `network_capture`, `kibana_ready`, and `arkime_viewer_ready`.
- `/es/search` and `/arkime/sessions` enforce case window and case-tag scoping; write/admin/packet/export routes are refused.
- Requests carrying `X-Hermes-Profile: hunt-board` are omitted from `/activity` so board polling never pollutes bot tool lanes.

## How to get to it (user POV)

Specialists invoke read-only lab tools (`hunt_lab_query`, `zeek_summary`, `arkime_query`) during a hunt, or an operator runs `bot.py lab query`.

## Driving it with control-hunt-lab

Preconditions: Lab running at `<lab-url>` (`http://127.0.0.1:<port>`).

1. Action: Capture `/health` to an evidence file.
   Command: `python .agents/skills/verify-hunt-lab/control-hunt-lab.py snapshot --lab-url <lab-url> --out <evidence-dir>/lab-health.json`
   Observable result: `"ok": true` and `<evidence-dir>/lab-health.json` contains `case_id` and `event_count`.
2. Action: Query `/es/search?q=*` as `framework-network-analyst`, then inspect `/activity`.
   Command: `python .agents/skills/verify-hunt-lab/control-hunt-lab.py query --lab-url <lab-url> --endpoint "/activity" --profile hunt-board --out <evidence-dir>/lab-activity.json`
   Observable result: `/activity` records the `framework-network-analyst` search and omits the `hunt-board` read.

## Gotchas

- Non-loopback `--lab-url` values are refused immediately (`Rule 2`).

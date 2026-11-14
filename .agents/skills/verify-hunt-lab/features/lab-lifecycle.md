# Lab Stack Lifecycle

The local Hunting Lab starts one Docker Compose project per case under `framework-network-analyst`, binds the lab service, Kibana, and Arkime exclusively to `127.0.0.1`, never publishes Elasticsearch, and leaves no files behind on read-only `status` checks.

## Sub-features

- Read-only `status` on an unstarted or missing home never creates runtime state or ledgers.
- `launch` starts the synthetic fixture (or explicit `--case`) and reports `"state": "running"` once `/health` is ready.
- `cleanup` tears down the compose project for the isolated home while keeping captured proof artifacts intact.

## How to get to it (user POV)

Run `py -3 framework/bot.py lab status|start|stop --home <hermes-home>` from the terminal, or use the **Hunting Lab** page (`#/hunt-lab`) in Hunt Command Desktop.

## Driving it with control-hunt-lab

Preconditions: `doctor` reports `"ok": true` and `"docker_daemon_ready": true`; `<hermes-home>` has `framework-network-analyst` installed.

1. Action: Preview the exact start command without mutating containers.
   Command: `python .agents/skills/verify-hunt-lab/control-hunt-lab.py launch --python <lock-python> --hermes-home <hermes-home> --dry-run`
   Observable result: `"ok": true`, `"dry_run": true` with `bot.py lab start` argv.
2. Action: Start the lab stack and inspect read-only status.
   Command: `python .agents/skills/verify-hunt-lab/control-hunt-lab.py status --python <lock-python> --hermes-home <hermes-home>`
   Observable result: `status.state` is `"running"` and `lab_url`, `kibana_url`, and `arkime_url` all begin with `http://127.0.0.1:`.
3. Action: Tear down the lab stack when finished.
   Command: `python .agents/skills/verify-hunt-lab/control-hunt-lab.py cleanup --python <lock-python> --hermes-home <hermes-home>`
   Observable result: `"ok": true`, `"evidence_preserved": true`.

## Gotchas

- An active `.hermes-update-in-progress` marker blocks every lab command by design; never delete a live update marker.

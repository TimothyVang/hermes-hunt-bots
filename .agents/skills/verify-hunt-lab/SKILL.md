---
name: verify-hunt-lab
description: Verify the local 127.0.0.1 Hunting Lab stack and tools.
---

# Verify Hunt Lab Skill

Executable verification harness and feature map for the local **Hunting Lab** (`framework/hunt_lab/`), its `127.0.0.1`-only Docker stack, read-only evidence endpoints, case-scoped `lab_browser` screencasts, and Temporal `lab-input` integration.

## When to Use

- Proving changes to `framework/hunt_lab/`, `framework/lab.py`, `lab_server.py`, `lab_browser.py`, or Temporal `lab-input` / `board.py` tool-driven feeds.
- Checking Docker readiness, read-only endpoint isolation, case-scoped Arkime/ES queries, or live browser screencast frames.

## Prerequisites

- Python environment with `framework/requirements-hunt.lock` installed (`temporalio`, `websockets`).
- Docker Desktop (or local Docker daemon) running when exercising container `launch` / `cleanup`.
- Isolated `HERMES_HOME` directory (never default user home state and never `../runtime/operator-only/`).

## Launch

Start (or dry-run) the local container lab for an isolated `HERMES_HOME`:

```powershell
python .agents/skills/verify-hunt-lab/control-hunt-lab.py launch --python <lock-python> --hermes-home <isolated-hermes-home> --dry-run
python .agents/skills/verify-hunt-lab/control-hunt-lab.py launch --python <lock-python> --hermes-home <isolated-hermes-home>
```

Ready means `status` reports `"state": "running"` with validated `127.0.0.1` `lab_url`, `arkime_url`, and `kibana_url`.

## Doctor

Run `doctor` first and whenever lab or Docker behavior looks off:

```powershell
python .agents/skills/verify-hunt-lab/control-hunt-lab.py doctor --python <lock-python> --hermes-home <isolated-hermes-home>
```

`doctor` is strictly read-only: it checks the lock Python, Docker CLI/daemon availability, bundled synthetic fixture `dns-lab-001`, and analyst VM state directory presence.

## Drive

Follow the target journey in `features/README.md`:

- `features/lab-lifecycle.md` — `doctor`, read-only `status`, `launch`, and `cleanup` on `127.0.0.1`.
- `features/evidence-queries.md` — read-only `/health`, `/es/search`, `/arkime/sessions`, and `/activity` probes with profile attribution.
- `features/live-browser-feed.md` — `lab_browser` screencast frames (`latest.jpg`) and `Hunt Board` `/live/<profile>.mjpg` streaming.
- `features/temporal-lab-input.md` — `hermes_temporal.cli lab-input --tool-driven` export and `board.py` verification.

## Evidence

Persist `/health`, `/activity`, exported `lab-input` JSON, and `lab_browser` audit tails into an explicit `<evidence-dir>`:

```powershell
python .agents/skills/verify-hunt-lab/control-hunt-lab.py snapshot --hermes-home <isolated-hermes-home> --out <evidence-dir>/lab-health.json
python .agents/skills/verify-hunt-lab/control-hunt-lab.py logs --hermes-home <isolated-hermes-home>
```

## Cleanup

Stop the isolated case's container project while preserving `<evidence-dir>`:

```powershell
python .agents/skills/verify-hunt-lab/control-hunt-lab.py cleanup --python <lock-python> --hermes-home <isolated-hermes-home>
```

## Helpers

- `.agents/skills/verify-hunt-lab/control-hunt-lab.py` — JSON CLI (`doctor`, `status`, `launch`, `query`, `lab-input`, `snapshot`, `logs`, `cleanup`).
- `.agents/skills/verify-hunt-lab/features/README.md` — index of Hunting Lab verification journeys.

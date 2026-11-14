# Hunting Lab Feature Map

Index of executable verification journeys for the local **Hunting Lab** (`framework/hunt_lab/`).

## Baseline Preconditions

- Run `python .agents/skills/verify-hunt-lab/control-hunt-lab.py doctor --python <lock-python> --hermes-home <isolated-hermes-home>` and confirm `"ok": true`.
- Every published port stays bound to `127.0.0.1` (`HUNT-BOTS.md` Rule 2); Elasticsearch is never published to the host.
- Commit synthetic fixtures only (`HUNT-BOTS.md` Rule 1); never read or touch `../runtime/operator-only/`.

## Driving Conventions

- Drive lifecycle through `control-hunt-lab.py` (`status`, `launch`, `cleanup`) rather than raw `docker rm` commands so compose project state and ownership markers stay consistent.
- Always pass an explicit isolated `--hermes-home`.

## Proof and Skip Reporting

- Save JSON outputs into `<evidence-dir>` outside the git worktree (or clean scratch directory) and verify they survive `cleanup`.
- If `docker_daemon_ready` is `false`, report container-dependent journeys as skipped due to Docker engine unavailability rather than weakening assertions.

## Features

- [Lab Stack Lifecycle](lab-lifecycle.md) — `doctor`, read-only `status`, container `launch`, and `cleanup`.
- [Read-Only Evidence Queries](evidence-queries.md) — `/health`, `/es/search`, `/arkime/sessions`, and `/activity` attribution.
- [Live Browser Screencast Feed](live-browser-feed.md) — `lab_browser` frame capture and `Hunt Board` `/live/<profile>.mjpg` delivery.
- [Temporal Tool-Driven Lab Input](temporal-lab-input.md) — `lab-input --tool-driven` export and `board.py --lab-state-dir` compatibility.

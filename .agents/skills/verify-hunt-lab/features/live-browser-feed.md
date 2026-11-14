# Live Browser Screencast Feed

`lab_browser` publishes loopback CDP session metadata under `<hermes-home>/profiles/framework-network-analyst/hunt-lab-browser/<bot>/` (including `runs/<slug>-<hash12>/`) and appends action records to `audit.jsonl`, while `hunt_lab.screencast.Watcher` streams CDP screencast frames in memory only into `LiveBrowsers` so `hermes_temporal.board` (`--hermes-home <hermes-home>`) serves `/live/<bot>.jpg` and `/live/<bot>.mjpg` to `Hunt Board` and `LabBrowserCard`.

## Sub-features

- Case-scoped CDP `Fetch` allowlist restricting browser navigation to the running case's lab console and Arkime origins.
- Watch-only in-memory CDP screencast frame streaming (`hunt_lab.screencast`) consumed by `LiveBrowsers` in `hermes_temporal/board.py`.
- `audit.jsonl` per-profile action log (`open`, `click`, `type`, `scroll`, `blocked_requests`).

## How to get to it (user POV)

During a hunt, a bot calls `lab_browser`, and the operator watches the live MJPEG thumbnail inside `LabBrowserCard` in chat or inside `Hunt Board` (`#/hunt-board`).

## Driving it with control-hunt-lab

Preconditions: Isolated `<hermes-home>` with `hermes_temporal.board` running with `--hermes-home <hermes-home>`, and an active `lab_browser` session streaming JPEG frames when probing `--profile` or `/live/<profile>.jpg`.

1. Action: Inspect `lab_browser` audit trails in `<hermes-home>`.
   Command: `python .agents/skills/verify-hunt-lab/control-hunt-lab.py logs --hermes-home <hermes-home>`
   Observable result: JSON `"ok": true` listing each bot profile's `audit.jsonl` tail in `browser_audits`.
2. Action: Probe `/live/<profile>.mjpg` via `verify-hunt-command`'s `board-probe`.
   Command: `python .agents/skills/verify-hunt-command/control-hunt-command.py board-probe --port <board-port> --profile framework-network-analyst`
   Observable result: `live_stream.ok` is `true` with `status: 200`, `jpeg_frame: true`, and `multipart/x-mixed-replace`.

## Gotchas

- `hermes_temporal.board` only enables `LiveBrowsers` when `--hermes-home` is passed on startup; Hunt Command Desktop's `Start & attach board` passes both `--lab-state-dir` and `--hermes-home` automatically.

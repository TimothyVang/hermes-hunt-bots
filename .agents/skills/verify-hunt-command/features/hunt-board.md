# Live Hunt Board & LabBrowserCard

`Hunt Board` (`#/hunt-board`) embeds or launches `python -m hermes_temporal.board` on `127.0.0.1` with `--lab-state-dir` and `--hermes-home` so live workflow state and `LabBrowserCard` MJPEG browser streams (`/live/<profile>.mjpg` and `/live/<profile>.jpg`) load cleanly even on dynamic loopback ports.

## Sub-features

- Zero network/IPC requests while `Board hidden` is shown on initial load.
- `Attach active board` discovers running loopback boards via `<hermes-home>/hunt-board/board-<port>.json` and `/state.json`.
- `Start & attach board` exports tool-driven lab input when `--input` is blank, passes `--lab-state-dir` and `--hermes-home`, and attaches the board iframe.
- `LabBrowserCard` updates its `/live/<profile>.mjpg` and `.jpg` URLs to match the attached board port.
- `Human gates` button (and `Decide in Hunt Command -> Human gates` inside the board) hands off the active `workflowId` to `#/cybersecurity-workspace`.

## How to get to it (user POV)

Click **Hunt Board** in the left sidebar (`#/hunt-board`) or run **Open Hunt Board** from the command palette, then click **Attach active board** or enter a **Workflow ID** and click **Start & attach board**.

## Driving it with control-hunt-command

Preconditions: Temporal workflow running on `127.0.0.1:7233` (or active `hermes_temporal.board` server) and isolated `<hermes-home>` with `framework-network-analyst` lab state (plus an active `lab_browser` screencast session when passing `--profile` to `board-probe`).

1. Action: Check active loopback boards and plugin health.
   Command: `python .agents/skills/verify-hunt-command/control-hunt-command.py doctor --python <lock-python> --hermes-home <hermes-home>`
   Observable result: JSON `"ok": true` with `active_boards` listing any live board ports.
2. Action: Start or attach the board in UI (`Start & attach board` with `Workflow ID`), then probe `/state.json` and (when an active `lab_browser` session is streaming frames) the analyst MJPEG stream; omit `--profile` when probing `/state.json` before a browser frame has streamed.
   Command: `python .agents/skills/verify-hunt-command/control-hunt-command.py board-probe --port <port> --profile framework-network-analyst`
   Observable result: `"ok": true`, `board.live_enabled` is `true`, and `live_stream` reports `status: 200`, `jpeg_frame: true`, and `content_type` containing `multipart/x-mixed-replace` (no `404`).
3. Action: Save board state evidence.
   Command: `python .agents/skills/verify-hunt-command/control-hunt-command.py snapshot --port <port> --out <evidence-dir>/hunt-board.json`
   Observable result: Snapshot persisted at `<evidence-dir>/hunt-board.json`.

## Gotchas

- `hermes_temporal.board` requires `--port` in `1..65535` (never `0`) and requires `--lab-state-dir` iff the input JSON has `"mode": "tool_driven"`.
- When `--hermes-home` is passed, `/live/<profile>.mjpg` returns `200` (`multipart/x-mixed-replace`, up to 4 concurrent streams) and streams in-memory CDP screencast frames from `hunt_lab.screencast.Watcher` as they arrive (`/live/<profile>.jpg` returns `404` until the first frame arrives, then `200 image/jpeg`).

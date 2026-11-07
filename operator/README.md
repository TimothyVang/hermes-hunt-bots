# Operator tools

These scripts run the six-bot hunts and the watcher improvement loop against the local lab. They are for the person operating the lab, not for the bots. Several of them read the operator-only answer keys, so nothing here is ever wired into a bot prompt, profile, or tool.

Every path derives from this clone's root and its git-ignored `runtime/` folder. Environment variables override the defaults. `lab_paths.py` defines all of them, and the scripts share it.

## Tools

| Tool | What it does | Needs |
|---|---|---|
| `switch_case.py` | Stops the lab VM, reseeds it with another case (fresh seed per load), starts it once available memory covers the deployment plus headroom, and waits for the lab health API. With no case it only starts the VM. `--hold` keeps the process (and the VM it owns) alive. | Hermes, prepared lab VM |
| `tool_loops.py` | The watcher improvement loop. Runs the hunt for 2 rounds, scores the final reports against the answer key, and asks a watcher model (Claude Opus through the lab home's `default` Hermes profile, no tools) for one general change to the brief or per-stage guidance. A change is kept only if the mean score rises by at least one fact without adding halts. Stops on perfect, after `--loops`, or after 3 loops without a kept change. | Hermes, running lab, Temporal worker, answer key |
| `auto_run.py` | Starts the VM whenever memory allows, waits for the health API, then runs `tool_loops.py` as a child with the same arguments and holds the VM afterwards. Run it as a long-lived service. | Same as `tool_loops.py` |
| `drive_gates.py` | Approves every execute and review gate of one practice run on a named person's behalf, saves each stage output, never retries, and stops on the first non-completed outcome. Opt-in only. See Safety. | Temporal worker |
| `diagnose_rejections.py` | Replays handoff validation for halted loop rounds and prints the exact rejection reason. Read-only. | Temporal, the framework's Python dependencies in the running interpreter |
| `toolcam/toolcam.mjs` | Follows the lab's `/activity` log during a live hunt and shows each bot's tool call as it happens (Arkime calls in Arkime's UI, other calls as the exact query and the rows the lab returned). Captures timestamped 1920x1080 frames twice a second. Reads hunt progress from the Hunt Board on `127.0.0.1`. | Bun, Edge or Chromium, running lab and board |
| `toolcam/assemble.py` | Turns tool-cam frames into a 1080p video. Each tool call plays at real speed for 2.5 s; time when the bots are only thinking plays 20x faster under a visible "20x speed" badge. Frames are never reordered or invented. `--end-card` appends a still for `--end-seconds`. | ffmpeg |
| `toolcam/card.mjs` | Renders a 1920x1080 HTML card to PNG for `--end-card`. | Bun, Edge or Chromium |

Every Python tool answers `--help` without the lab running. When a tool needs Hermes and `LAB_HERMES_EXE` is unset, it stops with a message naming the variable.

## Environment

| Variable | Default | Used for |
|---|---|---|
| `HUNT_BOTS_RUNTIME` | `<repo>/runtime` | Root of all local state. Loop state goes to `practice/tool-loops/`, gate outputs to `practice/gate-runs/`. |
| `HUNT_BOTS_LAB_HOME` | `$HUNT_BOTS_RUNTIME/lab-home` | The Hermes home holding the six profiles and the lab VM state. |
| `LAB_HERMES_EXE` | none (required for lab and watcher calls) | The `hermes` executable for that home. A name on `PATH` or a full path. |
| `HUNT_BOTS_PYTHON` | the Python running the tool | Interpreter for framework modules (`hermes_temporal.cli`, `hunt_lab.scenario`, `prepare_guest.py`). Needs `framework/hermes_temporal/requirements.txt`. |
| `HUNT_BOTS_TEMPORAL_ADDRESS` | unset, so the CLI default `127.0.0.1:7233` | Temporal server the worker uses. |
| `HUNT_BOTS_TASK_QUEUE` | unset, so the CLI default `hermes-temporal` | Task queue the worker polls. |
| `FFMPEG` | `ffmpeg` on `PATH` | `assemble.py`. |
| `TOOLCAM_FONT` | Segoe UI Bold on Windows, ffmpeg's default font elsewhere | The speed badge in `assemble.py`. |
| `TOOLCAM_BROWSER` | Microsoft Edge at its standard Windows path, `chromium` elsewhere | `toolcam.mjs` and `card.mjs`. |
| `TOOLCAM_BOARD_PORT` | `8790`, the Hunt Board's default | Loopback port of the Hunt Board that `toolcam.mjs` polls. Match the board's `--port`. |

## Examples

PowerShell, from the repository root, with a case generated as in [GETTING-STARTED.md](../GETTING-STARTED.md):

```powershell
$env:LAB_HERMES_EXE = '<path to the lab home hermes.exe>'
$env:HUNT_BOTS_PYTHON = "$PWD\.venv-dev\Scripts\python.exe"
$env:HUNT_BOTS_TEMPORAL_ADDRESS = '127.0.0.1:7233'
$env:HUNT_BOTS_TASK_QUEUE = 'hermes-temporal'

# Load a case and keep the VM alive (run as a long-lived service)
python operator\switch_case.py runtime\cases\lab-med-001\evidence --hold

# Approve the gates of one practice run you started yourself
python operator\drive_gates.py my-first-hunt --delegated-by "Ada Lovelace" --reason "approve every gate of this synthetic practice run"

# Watcher loop on the loaded case
python operator\tool_loops.py lab-med-001 runtime\operator-only\lab-med-001\truth.json --delegated-by "Ada Lovelace" --reason "unattended synthetic watcher loop" --loops 8 --tag -a

# Same, but start the VM first whenever memory allows
python -u operator\auto_run.py lab-med-001 runtime\operator-only\lab-med-001\truth.json --delegated-by "Ada Lovelace" --reason "unattended synthetic watcher loop"

# Resume after an infrastructure fix without counting the broken loops against the plateau
python operator\tool_loops.py lab-med-001 runtime\operator-only\lab-med-001\truth.json --delegated-by "Ada Lovelace" --reason "unattended synthetic watcher loop" --resume --tag -b --reset-plateau "worker restarted"

# Why did loop 3 halt?
python operator\diagnose_rejections.py runtime\practice\tool-loops\loop-03=loop-03-lab-med-001:round:001

# Record a hunt and cut the video
bun operator\toolcam\toolcam.mjs runtime\practice\cam <lab_url> <arkime_url> lab-med-001 <startEpoch> <stopEpoch> <activityAfter>
bun operator\toolcam\card.mjs runtime\practice\end.html runtime\practice\end.png
python operator\toolcam\assemble.py runtime\practice\cam runtime\practice\hunt.mp4 --end-card runtime\practice\end.png
```

`--tag` suffixes every workflow ID so a restarted series never reuses one.

## Safety

- **Synthetic only.** Point these tools at generated cases under `runtime/`. Their outputs (scores, reports, frames, videos) stay in `runtime/`, which Git ignores.
- **Answer keys stay with the operator.** `tool_loops.py` reads `runtime/operator-only/` to score reports and to reject case-specific words in the watcher's proposals. The watcher sees only fact categories it missed, never the key, and its proposals must be general hunting technique. Nothing here feeds a key to a bot.
- **Delegated approvals are labelled.** Execution and review gates are human decisions (HUNT-BOTS.md rule 3). `drive_gates.py` refuses to run unless you name the person who delegated the approvals (`--delegated-by`) and their instruction (`--reason`). It prints that on start, and every approval note it records says it is a delegated approval by that person, recorded by the script, and not a human review of the content. `tool_loops.py` and `auto_run.py` require the same two flags because they run it for every hunt. Report runs driven this way as delegated, not human-reviewed.
- **The tool cam only opens lab origins.** It reads the lab, Arkime, and the Hunt Board on `127.0.0.1`.

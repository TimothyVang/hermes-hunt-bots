# Operator tools

These scripts run the six-bot hunts and the watcher improvement loop against the local lab. They are for the person operating the lab, not for the bots. Several of them read the operator-only answer keys, so nothing here is ever wired into a bot prompt, profile, or tool.

Every path derives from this clone's root and its git-ignored `runtime/` folder. Environment variables override the defaults. `lab_paths.py` defines all of them, and the scripts share it.

## Tools

| Tool | What it does | Needs |
|---|---|---|
| `switch_case.py` | Stops the lab VM, reseeds it with another case (fresh seed per load), starts it once available memory covers the deployment plus headroom, and waits for the lab health API to report the new seed's cloud-init instance (the previous boot's lab server answers first, for the old guest software). With no case it only starts the VM. `--hold` keeps the process (and the VM it owns) alive. | Hermes, prepared lab VM |
| `tool_loops.py` | The watcher improvement loop. Runs the hunt for 2 rounds, scores the final reports against the answer key, and asks a watcher model (Claude Opus through the lab home's `default` Hermes profile, no tools) for one general change to the brief or per-stage guidance. A change is kept only if the mean score rises by at least one fact without adding halts. Stops on perfect, after `--loops`, or after 3 loops without a kept change. Each round's record lists its handoff rejections (step, outcome, validator reason), and `result.json` counts the workflow's handoff retries. | Hermes, running lab, Temporal worker, answer key |
| `auto_run.py` | Starts the VM whenever memory allows, waits for the health API, then runs `tool_loops.py` as a child with the same arguments and holds the VM afterwards. Run it as a long-lived service. | Same as `tool_loops.py` |
| `film_loop.py` | The filmed full-mode loop. Each loop runs one round in which the Threat Hunter drives Kibana Discover (Elastic) and the Network Analyst drives Arkime through `lab_browser`, films the round's Hunt Live board, scores it, measures driving coverage, cuts a 1x master and a constant-speed video, and has Claude Opus review the constant-speed video. The watcher then proposes the next brief, stage guidance and drive note. A change is kept only with 0 decoys blamed, no halt, and either more coverage at the same or better score or a better score with coverage at most 0.1 lower, or a coverage gain of at least 0.2 with the score at most 2 lower (one round per loop scores within about 2 of noise). `--resume --rejudge-last REASON` re-applies the current rule to the last loop if it was reverted and logs REASON. `--resume --reset-plateau REASON` zeroes the no-gain counter after an infrastructure fix and logs REASON. Every lane's Hermes home needs a persistent gateway started the normal way (`HERMES_HOME=<home> hermes gateway run`): the bots' tools and browsers run inside it, and one a worker auto-starts inherits the worker's stripped environment and exits when idle (lab_browser failed most calls under it). `film_loop.py` refuses to start without one. A new series can start from an earlier series' best with `--seed path\to\BEST.json` (a film-loop or tool-loop one). Stops when the best loop finds 18/18 with coverage >= 0.8 and a review that says ready, after `--loops`, or after 3 loops without a kept change. | Hermes, running lab, Temporal worker, answer key, ffmpeg, the `lab_browser` demo marker, Chromium or Edge |
| `film/record.py` | Films one round on one lane from its Hunt Live board, never the desktop. It starts the lane's own board (`python -m hermes_temporal.board` with the round's `--workflow-id` and `--input`, the lane's `--lab-state-dir` and `--hermes-home`) on a free loopback port, opens it in a dedicated headless Chromium/Edge with its own temporary profile and a 1920x1080 page at device scale 1, and saves its `Page.startScreencast` frames with their timestamps (`board/`, `board-index.jsonl`). It samples the board's step states every second (`board-state.jsonl`), screencasts the lane's bots' browsers, and runs the round through `tool_loops.run_config` on the lane's lab and task queue. Browser and board stop when the round ends. Writes `film.json` (`t0`, `board_port`, `board_frames`, `board_state_samples`, `screencast_frames`). | Python `websockets`, Chromium or Edge |
| `film/screencast.py` | Saves each browser owner's `lab_browser` browser as screencast frames. The watch-only DevTools client itself lives in `framework/hunt_lab/screencast.py`, shared with the Hunt Board's live browsers: it attaches as soon as Chromium writes `hunt-lab-browser/<profile>/user-data/DevToolsActivePort`, so the first search typed into a fresh browser is filmed, then follows the main target that `session.json` names, and re-attaches when a new browser launches or the main target changes. It can send only target listing, attach, detach, screencast start/stop and frame acks. This module writes every `Page.startScreencast` frame with its timestamp and an `index.jsonl`. | Python `websockets` |
| `film/edit.py` | Cuts the board frames into `video-full.mp4` (Option A: the whole round at 1x) and `video.mp4` (Option B: the whole round at one constant `speed`, default 5x, the cut the loop reviews). Each frame is held until the next. A bottom bar carries a permanent label ("5x speed · every frame is real") and, with `captions`, the bot and tool acting. A chapter card opens each stage at its real start, as the board showed it: stage number and name, owner bot, wall-clock range and duration. Intro and outro cards carry the round's real numbers. Writes `edit.json` with the segments, per-stage timings and both cuts' timelines. `cut(..., out_dir=...)` re-cuts an earlier loop's captures without overwriting its first cut. | ffmpeg |
| `film/review.py` | Stacks a browser-moment contact sheet (the bots' own screencast frames at their browser actions) and an overview of the reviewed cut into one image. It sends that image with measured metrics (board seconds, chapters, longest frozen board, browser-on-screen seconds, captions) to Opus (one call, one retry on invalid JSON) and validates the reply: tools driven, typing and cursor visible, readability, dead time, brief suggestions, and knob changes from a fixed set (`speed`, `captions`, `intro_title`). | Hermes, ffmpeg |
| `film/lanes.py` | Reads a `--lanes` file for `film_loop.py` and refuses lanes that could interfere: shared name, Hermes home, browser state or task queue. | none |
| `drive_gates.py` | Drives the execute and review gates of one practice run in one of two opt-in modes; exactly one must be chosen. `--two-decisions --operator "<name>"` leaves the operator's two decisions per hunt (HUNT-BOTS.md rule 3) to the operator: at the review of the `scope` step (a parallel hunt's `wave-<n>` review while `scope` awaits review) and at the review of the hunt's last step (`incident`; in a parallel hunt the highest wave) it sends nothing, saves the outputs, logs `WAITING FOR OPERATOR <name>: <scope|report> review of <child> <gate>; outputs in <dir>` once, prints the `hermes_temporal.cli decision` command to approve or deny, and polls until the operator decides or the workflow ends. Every other gate is approved automatically with a note that names it an automated approval for that operator and not a human review of the step. `--delegated-by` and `--reason` instead approve every gate on that person's behalf. In both modes it saves each stage output and stops on the first non-completed outcome of a required step, including an operator's denial. It never retries on its own. When the workflow re-offers a step once after handoff validation rejected its output, the driver approves that new execute gate under its own decision ID, with a note that names it a retry approval, and saves the corrected output. A parallel hunt gates a whole wave at once (gate ID `wave-<n>`): the driver sends one execute approval each time the wave's execute gate opens (once, and once more for the steps being retried) and one review approval, after saving the output of every step awaiting review under that step's own ID, matched to results by execution ID. It never approves a wave it could not save in full. An optional step the workflow dropped is logged as `DROPPED` and the run goes on. See Safety. | Temporal worker |
| `diagnose_rejections.py` | Replays handoff validation for halted loop rounds and prints the exact rejection reason. A parallel hunt's results are matched to steps by execution ID. Read-only. | Temporal, the framework's Python dependencies in the running interpreter |
| `team_probe.py` | Measures a team of Threat Hunters on the loaded case without Temporal. `concurrency` runs the scope step, then `--hunters` copies of the hunter at the same time on one Hermes home, and reports how many returned a valid handoff, each one's seconds and tokens, and the failure reason codes. `compare` runs paired arms per round on one shared scope output: `baseline` (one hunter), `split` (`--hunters` hunters, each with one fixed, case-agnostic assignment such as persistence or exfiltration) and `followup` (one hunter, then one follow-up hunter per finding that pivots to complete its evidence). Each arm's valid handoffs are merged and scored at the hunter stage only: attack facts fully and partly evidenced and decoys blamed. A hunter without a valid handoff contributes nothing, as the parallel workflow would drop it. Every session is launched as the worker launches a step, with usage recording. `--max-hunter-runs` is required and is a hard cap on native sessions; the command refuses to start if its plan exceeds it. Writes `rounds.json` and `summary.json` under `--out` and a line per arm to `practice/team-probe/probe.log`. It launches live model sessions and costs money. | Hermes, running lab, answer key, the framework's Python dependencies |
| `toolcam/toolcam.mjs` | Follows the lab's `/activity` log during a live hunt and shows each bot's tool call as it happens (Arkime calls in Arkime's UI, other calls as the exact query and the rows the lab returned). Captures timestamped 1920x1080 frames twice a second. Reads hunt progress from the Hunt Board on `127.0.0.1`. | Bun, Edge or Chromium, running lab and board |
| `toolcam/assemble.py` | Turns tool-cam frames into a 1080p video. Each tool call plays at real speed for 2.5 s; time when the bots are only thinking plays 20x faster under a visible "20x speed" badge. Frames are never reordered or invented. `--end-card` appends a still for `--end-seconds`. | ffmpeg |
| `toolcam/card.mjs` | Renders a 1920x1080 HTML card to PNG for `--end-card`. | Bun, Edge or Chromium |

Every Python tool answers `--help` without the lab running. When a tool needs Hermes and `LAB_HERMES_EXE` is unset, it stops with a message naming the variable.

The film loop's tests use no lab, browser, Temporal or ffmpeg. Run them from the repository root with `python -m unittest discover -s operator -p "test_*.py"`.

## Environment

| Variable | Default | Used for |
|---|---|---|
| `HUNT_BOTS_RUNTIME` | `runtime/` next to the clone (`<repo>/../runtime`) | Root of all local state, outside the Git work tree on purpose: the lab refuses VM state inside any Git repository. Loop state goes to `practice/tool-loops/`, gate outputs to `practice/gate-runs/`. |
| `HUNT_BOTS_LAB_HOME` | `$HUNT_BOTS_RUNTIME/lab-home` | The Hermes home holding the six profiles and the lab VM state. |
| `LAB_HERMES_EXE` | none (required for lab and watcher calls) | The `hermes` executable for that home. A name on `PATH` or a full path. |
| `HUNT_BOTS_PYTHON` | the Python running the tool | Interpreter for framework modules (`hermes_temporal.cli`, `hunt_lab.scenario`, `prepare_guest.py`). Needs `framework/hermes_temporal/requirements.txt`. |
| `HUNT_BOTS_TEMPORAL_ADDRESS` | unset, so the CLI default `127.0.0.1:7233` | Temporal server the worker uses. |
| `HUNT_BOTS_TASK_QUEUE` | unset, so the CLI default `hermes-temporal` | Task queue the worker polls. |
| `FFMPEG` | `ffmpeg` on `PATH` | `assemble.py`, `film/edit.py`, `film/review.py`. |
| `TOOLCAM_FONT` | Segoe UI Bold on Windows, ffmpeg's default font elsewhere | The speed badge in `assemble.py`. |
| `TOOLCAM_BROWSER` | Microsoft Edge at its standard Windows path, `chromium` elsewhere | `toolcam.mjs` and `card.mjs`. |
| `HUNT_LAB_BROWSER` | `TOOLCAM_BROWSER`'s default | The headless browser `film/record.py` films the Hunt Live board in. |
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

# Filmed full-mode loop (needs the demo marker, see below); FFMPEG must point at ffmpeg.exe
$env:FFMPEG = "$PWD\..\runtime\tools\ffmpeg\bin\ffmpeg.exe"
python operator\film_loop.py lab-med-001 runtime\operator-only\lab-med-001\truth.json --delegated-by "Ada Lovelace" --reason "unattended synthetic film loop" --loops 8 --tag=-f1

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

`film_loop.py` needs the operator's demo marker `hunt-lab-browser\demo.json` (for example `{"headed": true, "window": [0, 0, 1280, 1080], "cursor": true}`) under the `framework-network-analyst` profile of the lab home. Without it the bots do not type searches on screen and `film/record.py` refuses to start. `HUNT_BOTS_PYTHON` must have `temporalio` and `websockets`, since it runs the board. Loop state goes to `runtime/practice/film-loops/`: `state.json`, `BEST.json`, `BEST.mp4`, `loop.log`, and one `film-NN` directory per loop holding the captures, `video.mp4`, `video-full.mp4`, `review.png`, `review.json` and `decision.json`.

**Parallel lanes.** `--lanes lanes.json` runs each loop's round on several independent labs at the same time and scores the loop on the mean over lanes (any halt or blamed decoy in any lane fails the keep rule). A lane is its own Hermes home with its own lab VM, demo marker and `lab_browser` state, its own Temporal worker on its own task queue, and its own Hunt Live board and headless browser for the film. The tools take the lane explicitly: Temporal calls use its queue, `hunt-lab status` runs against its home for the lab URL, and each lane's `drive_gates.py` runs with the lane's environment. Workflow IDs and folders carry the lane name (`film-03-f2-l2-lab-med-001`, `film-03/l2/`). The review sends one image with each lane's sheets stacked under its name. `BEST.mp4` is the kept loop's best lane's reviewed cut (a clean lane first, then most facts, then most coverage): a side-by-side would halve each lane. Example `lanes.json` (a relative `hermes_home` is under the runtime folder; `hermes_exe` is optional and defaults to `LAB_HERMES_EXE`):

```json
[{"name": "l1", "hermes_home": "lab-home", "task_queue": "hermes-claude-practice"},
 {"name": "l2", "hermes_home": "lab-home-2", "task_queue": "hermes-claude-practice-2"}]
```

```powershell
python operator\film_loop.py lab-med-001 runtime\operator-only\lab-med-001\truth.json --delegated-by "Ada Lovelace" --reason "unattended synthetic film loop" --tag=-p1 --lanes runtime\practice\film-loops\lanes.json
```

## Safety

- **Synthetic only.** Point these tools at generated cases under `runtime/`. Their outputs (scores, reports, frames, videos) stay in `runtime/`, which Git ignores.
- **Answer keys stay with the operator.** `tool_loops.py` and `film_loop.py` read `runtime/operator-only/` to score reports and to reject case-specific words in the watcher's proposals. The watcher and the video reviewer see only fact categories and counts, never the key, and proposals must be general hunting technique. Nothing here feeds a key to a bot.
- **Automated approvals are labelled.** The operator makes two decisions per hunt: the scope approval and the acceptance or rejection of the final report (HUNT-BOTS.md rule 3). `drive_gates.py` refuses to run unless you choose exactly one mode. With `--two-decisions --operator "<name>"` it never decides those two review gates; you send them yourself with the printed `hermes_temporal.cli decision` command and a note on what you checked. Every other approval it records says it is an automated approval under ADR 0002 for that operator, recorded by the script, and not a human review of the step. With `--delegated-by` and `--reason` it approves every gate, and every approval note says it is a delegated approval by that person, recorded by the script, and not a human review of the content. It prints its mode on start. `tool_loops.py`, `film_loop.py` and `auto_run.py` run it in delegated mode and require the same two flags because they run it for every hunt. Report runs driven in delegated mode as delegated, and runs in two-decision mode as automated apart from the operator's two decisions; never as human-reviewed throughout.
- **The tool cam only opens lab origins.** It reads the lab, Arkime, and the Hunt Board on `127.0.0.1`.
- **No desktop capture.** `film/record.py` films only the lane's own read-only Hunt Live board on `127.0.0.1`, in a headless browser with a temporary profile that is deleted afterwards, never the user's browser or screen. The bots' browsers are filmed through their own watch-only DevTools screencast. Do not use a desktop screenshot or capture anywhere.
- **Every frame is real.** The cuts use only board screencast frames and rendered cards. Each cut plays at one constant speed with that speed on screen throughout, and the cards show only measured numbers. The review may retitle the intro but never add digits.

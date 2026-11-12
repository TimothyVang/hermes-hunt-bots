# Getting started with hermes-hunt-bots

This is the shortest path from a fresh clone to a working setup, a first synthetic hunt, and a first PR. Each step links to the detailed docs. The rules for every change are in [HUNT-BOTS.md](HUNT-BOTS.md).

Use one project folder with two parts: `repo/`, the Git clone, and `runtime/` next to it for everything you generate (cases, answer keys, the lab's Hermes home and VM, runs). `runtime/` must stay outside the clone. The lab refuses to keep VM state inside any Git repository, so lab disks and logs can never be committed. The operator tools default to this layout.

## 1. Clone and check (5 minutes)

You need Git and Python 3.10 or newer (tested on 3.13).

```powershell
mkdir hermes-hunt-bots; cd hermes-hunt-bots; mkdir runtime
git clone -b hunt-bots https://github.com/TimothyVang/hermes-hunt-bots.git repo
cd repo
py -3 -m venv .venv-dev
.\.venv-dev\Scripts\python.exe -m pip install -r framework\hermes_temporal\requirements.txt pycdlib
.\.venv-dev\Scripts\python.exe scripts\hunt_bots_check.py
```

```sh
mkdir -p hermes-hunt-bots/runtime && cd hermes-hunt-bots
git clone -b hunt-bots https://github.com/TimothyVang/hermes-hunt-bots.git repo
cd repo
python3 -m venv .venv-dev
.venv-dev/bin/python -m pip install -r framework/hermes_temporal/requirements.txt pycdlib
.venv-dev/bin/python scripts/hunt_bots_check.py
```

The last line must end in `-> PASS`. On a fresh clone it runs about 1,090 framework tests in roughly five minutes; some are skipped because they need the private range kit, Windows, or a live lab. Install [gitleaks](https://github.com/gitleaks/gitleaks) to add the secret scan.

## 2. Generate a synthetic case (no VM, no model)

From `framework/`:

```powershell
..\.venv-dev\Scripts\python.exe -m hunt_lab.scenario generate --size medium --story a --seed 7 --case-id lab-med-001 --evidence-dir ..\..\runtime\cases\lab-med-001\evidence --truth-dir ..\..\runtime\operator-only\lab-med-001
```

That writes about 20,000 invented events, a packet capture, an intel feed, and a separate answer key. Story `a` is an Office-macro intrusion; story `b` is a different organization and a web-server exploit, used as a sealed test. `score --truth <truth.json> <report>` grades a final report against the key. Details: [framework/README.md, Loading a larger case](framework/README.md#built-in-local-hunting-lab).

## 3. Install the six bots into a separate Hermes home

The bots run on native Hermes. Use a Hermes home dedicated to this lab, never your everyday one. The examples use `..\..\runtime\lab-home`.

1. Install Hermes. This repository is a fork of Hermes 0.23.0; build it from source with the upstream [CONTRIBUTING.md](CONTRIBUTING.md), or use an official Hermes install of the same version.
2. Sign in to a model provider in that home.
3. Install the six profiles, the hunting-lab tools, and the cybersecurity workspace page:

   ```powershell
   ..\.venv-dev\Scripts\python.exe setup_hermes.py --home ..\..\runtime\lab-home install
   ..\.venv-dev\Scripts\python.exe native_team.py --home ..\..\runtime\lab-home apply
   ..\.venv-dev\Scripts\python.exe native_team.py --home ..\..\runtime\lab-home check
   ```

   `check` should report every setting `ready`. Details: [framework/hermes-setup.md](framework/hermes-setup.md).
4. Build the Hunt Bots desktop app, which ships the Hunting Lab and Hunt Board pages. From the repository root, with the Node version in `.nvmrc`:

   ```powershell
   npm ci
   $env:HERMES_DESKTOP_VARIANT = 'hunt-bots'; npm run pack --workspace apps/desktop
   ```

   That writes an unpacked, unsigned app to `apps\desktop\release\win-unpacked\Hunt Bots.exe`. It keeps its own app settings and single-instance lock, and does not replace or update an installed Hermes desktop app. Both apps answer `hermes://` links, and the one launched last wins; set `HERMES_DESKTOP_SKIP_PROTOCOL_REGISTRATION=1` when starting Hunt Bots to keep Hermes as the handler. It uses the same Hermes home as Hermes unless told otherwise, so start it on the lab home: `$env:HERMES_HOME = '<full path to runtime\lab-home>'; & '.\apps\desktop\release\win-unpacked\Hunt Bots.exe'`.

## 4. Build the hunting lab VM

The lab is a local QEMU VM running Elasticsearch, Arkime and the read-only lab service, reachable only on `127.0.0.1`. It needs QEMU, the pinned Ubuntu cloud image, and about 5 GB of free RAM while it runs. Prepare it with `framework/hunt_lab/prepare_guest.py`, load a case with `prepare_guest.py reseed --update-deployment`, and start it from the Network Analyst profile with `hermes -p framework-network-analyst hunt-lab start`. Details: [framework/README.md, Built-in local hunting lab](framework/README.md#built-in-local-hunting-lab).

## 5. Run a hunt

1. Start a Temporal development server on loopback (the [Temporal CLI](https://docs.temporal.io/cli) `temporal server start-dev`).
2. Create the run folders (`mkdir ..\..\runtime\work, ..\..\runtime\state, ..\..\runtime\inputs`), then start a worker with Hermes execution enabled for the lab home only:
   ```powershell
   ..\.venv-dev\Scripts\python.exe -m hermes_temporal.worker --enable-hermes --hermes-executable <lab hermes.exe> --hermes-home ..\..\runtime\lab-home --working-directory ..\..\runtime\work --receipt-db ..\..\runtime\state\hermes-receipts.sqlite3
   ```

3. Export a tool-driven input for the loaded case and start a practice run:

   ```powershell
   ..\.venv-dev\Scripts\python.exe -m hermes_temporal.cli lab-input --tool-driven --state-dir ..\..\runtime\lab-home\profiles\framework-network-analyst\hunt-lab-vm --output ..\..\runtime\inputs\tool-hunt.json
   ..\.venv-dev\Scripts\python.exe -m hermes_temporal.cli practice my-first-hunt --input ..\..\runtime\inputs\tool-hunt.json --rounds 1
   ```

4. Approve each stage as a human with `hermes_temporal.cli decision` (every stage has an execute gate and a review gate), and watch it live on the Hunt Board: `..\.venv-dev\Scripts\python.exe -m hermes_temporal.board --workflow-id my-first-hunt --input ..\..\runtime\inputs\tool-hunt.json --lab-state-dir ..\..\runtime\lab-home\profiles\framework-network-analyst\hunt-lab-vm`, then open `http://127.0.0.1:8790/`.

Details, including the exact gate commands: [framework/hermes_temporal/README.md](framework/hermes_temporal/README.md).

## 6. Make your first PR

Install the [deep-mode](https://github.com/TimothyVang/deep-mode) plugin once (commands in [HUNT-BOTS.md, Contributing](HUNT-BOTS.md#contributing)), then point your coding agent at the project skill [.agents/skills/hunt-bots-pr/SKILL.md](.agents/skills/hunt-bots-pr/SKILL.md). In short:

1. Branch from `hunt-bots`.
2. Prove the change on the real thing.
3. Run `scripts/hunt_bots_check.py`.
4. Self-review the branch with deep-mode's PR review.
5. Open a ready PR with the Why / What changed / Scope / Blast Radius / Verification sections.

A maintainer reviews it with `/deep-mode:review-pr`, and a code owner approves.

## 7. Optional: the operator tools

`operator/` holds the tools that run around the hunts. They include the watcher loop that tunes the bots' instructions and keeps only measured gains, case switching for the lab VM, an opt-in gate driver that labels every approval as delegated, and the tool cam and video assembler. Set `LAB_HERMES_EXE` to the lab's `hermes` executable first. Details and safety notes: [operator/README.md](operator/README.md).

## Where to help

The open work is listed in [HUNT-BOTS.md, Known gaps](HUNT-BOTS.md#known-gaps-help-wanted). The biggest items are bots that really drive Arkime and Kibana in a browser, runtime enforcement of per-bot tool limits, and connecting the bots to a graph context engine.

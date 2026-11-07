# Getting started with hermes-hunt-bots

This is the shortest path from a fresh clone to a working setup, a first synthetic hunt, and a first PR. Each step links to the detailed docs. The rules for every change are in [HUNT-BOTS.md](HUNT-BOTS.md).

Everything you generate (cases, answer keys, lab VM, runs) goes under `runtime/` in your clone. Git ignores it, so you can't commit it by accident.

## 1. Clone and check (5 minutes)

You need Git and Python 3.10 or newer (tested on 3.13).

```powershell
git clone -b hunt-bots https://github.com/TimothyVang/hermes-hunt-bots.git
cd hermes-hunt-bots
py -3 -m venv .venv-dev
.\.venv-dev\Scripts\python.exe -m pip install -r framework\hermes_temporal\requirements.txt pycdlib
.\.venv-dev\Scripts\python.exe scripts\hunt_bots_check.py
```

```sh
git clone -b hunt-bots https://github.com/TimothyVang/hermes-hunt-bots.git
cd hermes-hunt-bots
python3 -m venv .venv-dev
.venv-dev/bin/python -m pip install -r framework/hermes_temporal/requirements.txt pycdlib
.venv-dev/bin/python scripts/hunt_bots_check.py
```

The last line must end in `-> PASS`. On a fresh clone it runs about 1,090 framework tests in roughly five minutes; some are skipped because they need the private range kit, Windows, or a live lab. Install [gitleaks](https://github.com/gitleaks/gitleaks) to add the secret scan.

## 2. Generate a synthetic case (no VM, no model)

From `framework/`:

```powershell
..\.venv-dev\Scripts\python.exe -m hunt_lab.scenario generate --size medium --story a --seed 7 --case-id lab-med-001 --evidence-dir ..\runtime\cases\lab-med-001\evidence --truth-dir ..\runtime\operator-only\lab-med-001
```

That writes about 20,000 invented events, a packet capture, an intel feed, and a separate answer key. Story `a` is an Office-macro intrusion; story `b` is a different organization and a web-server exploit, used as a sealed test. `score --truth <truth.json> <report>` grades a final report against the key. Details: [framework/README.md, Loading a larger case](framework/README.md#built-in-local-hunting-lab).

## 3. Install the six bots into a separate Hermes home

The bots run on native Hermes. Use a Hermes home dedicated to this lab, never your everyday one.

1. Install Hermes. This repository is a fork of Hermes 0.23.0; build it from source with the upstream [CONTRIBUTING.md](CONTRIBUTING.md), or use an official Hermes install of the same version.
2. Sign in to a model provider in that home.
3. Install the six profiles, the hunting-lab plugin, and the desktop pages:

   ```powershell
   ..\.venv-dev\Scripts\python.exe setup_hermes.py --home <lab-hermes-home> install
   ..\.venv-dev\Scripts\python.exe native_team.py --home <lab-hermes-home> apply
   ..\.venv-dev\Scripts\python.exe native_team.py --home <lab-hermes-home> check
   ```

   `check` should report every setting `ready`. Details: [framework/hermes-setup.md](framework/hermes-setup.md).

## 4. Build the hunting lab VM

The lab is a local QEMU VM running Elasticsearch, Arkime and the read-only lab service, reachable only on `127.0.0.1`. It needs QEMU, the pinned Ubuntu cloud image, and about 5 GB of free RAM while it runs. Prepare it with `framework/hunt_lab/prepare_guest.py`, load a case with `prepare_guest.py reseed --update-deployment`, and start it from the Network Analyst profile with `hermes -p framework-network-analyst hunt-lab start`. Details: [framework/README.md, Built-in local hunting lab](framework/README.md#built-in-local-hunting-lab).

## 5. Run a hunt

1. Start a Temporal development server on loopback (the [Temporal CLI](https://docs.temporal.io/cli) `temporal server start-dev`).
2. Create the run folders (`mkdir ..\runtime\work, ..\runtime\state, ..\runtime\inputs`), then start a worker with Hermes execution enabled for the lab home only:
   ```powershell
   ..\.venv-dev\Scripts\python.exe -m hermes_temporal.worker --enable-hermes --hermes-executable <lab hermes.exe> --hermes-home <lab-hermes-home> --working-directory ..\runtime\work --receipt-db ..\runtime\state\hermes-receipts.sqlite3
   ```

3. Export a tool-driven input for the loaded case and start a practice run:

   ```powershell
   ..\.venv-dev\Scripts\python.exe -m hermes_temporal.cli lab-input --tool-driven --state-dir <lab-hermes-home>\profiles\framework-network-analyst\hunt-lab-vm --output ..\runtime\inputs\tool-hunt.json
   ..\.venv-dev\Scripts\python.exe -m hermes_temporal.cli practice my-first-hunt --input ..\runtime\inputs\tool-hunt.json --rounds 1
   ```

4. Approve each stage as a human with `hermes_temporal.cli decision` (every stage has an execute gate and a review gate), and watch it live on the Hunt Board: `..\.venv-dev\Scripts\python.exe -m hermes_temporal.board --workflow-id my-first-hunt --input ..\runtime\inputs\tool-hunt.json --lab-state-dir <lab-hermes-home>\profiles\framework-network-analyst\hunt-lab-vm`, then open `http://127.0.0.1:8790/`.

Details, including the exact gate commands: [framework/hermes_temporal/README.md](framework/hermes_temporal/README.md).

## 6. Make your first PR

Use the project skill: point your coding agent at [.agents/skills/hunt-bots-pr/SKILL.md](.agents/skills/hunt-bots-pr/SKILL.md). It follows pstack poteto-mode, which is vendored in `.agents/`. In short:

1. Branch from `hunt-bots`.
2. Prove the change on the real thing.
3. Run `scripts/hunt_bots_check.py`.
4. Open a ready PR with the Why / What changed / Scope / Blast Radius / Verification sections.

Greptile reviews it, and a code owner approves.

## 7. Optional: the operator tools

`operator/` holds the tools that run around the hunts. They include the watcher loop that tunes the bots' instructions and keeps only measured gains, case switching for the lab VM, an opt-in gate driver that labels every approval as delegated, and the tool cam and video assembler. Set `LAB_HERMES_EXE` to the lab's `hermes` executable first. Details and safety notes: [operator/README.md](operator/README.md).

## Where to help

The open work is listed in [HUNT-BOTS.md, Known gaps](HUNT-BOTS.md#known-gaps-help-wanted). The biggest items are bots that really drive Arkime and Kibana in a browser, runtime enforcement of per-bot tool limits, and connecting the bots to a graph context engine.

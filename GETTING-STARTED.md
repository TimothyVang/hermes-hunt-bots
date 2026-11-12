# Getting started with hermes-hunt-bots

This is the shortest path from a fresh clone to a working setup, a first synthetic hunt, and a first PR. Each step links to the detailed docs. The rules for every change are in [HUNT-BOTS.md](HUNT-BOTS.md).

Use one project folder with two parts: `repo/`, the Git clone, and `runtime/` next to it for everything you generate (cases, answer keys, the lab's Hermes home and VM, runs). `runtime/` must stay outside the clone. The lab refuses to keep VM state inside any Git repository, so lab disks and logs can never be committed. The operator tools default to this layout.

## 1. Clone and check (5 minutes)

You need Git and Python 3.10 or newer (tested on 3.13). On Windows, build the venv from a python.org Python, not the Microsoft Store Python: in a venv built from Store Python 3.13.14, two process-tree tests in `framework/test_benchmark_process.py` fail.

```powershell
mkdir hermes-hunt-bots; cd hermes-hunt-bots; mkdir runtime
git clone -b hunt-bots https://github.com/TimothyVang/hermes-hunt-bots.git repo
cd repo
py -3 -m venv .venv-dev
.\.venv-dev\Scripts\python.exe -m pip install --require-hashes --only-binary :all: -r framework\requirements-hunt.lock
.\.venv-dev\Scripts\python.exe scripts\hunt_bots_check.py
```

```sh
mkdir -p hermes-hunt-bots/runtime && cd hermes-hunt-bots
git clone -b hunt-bots https://github.com/TimothyVang/hermes-hunt-bots.git repo
cd repo
python3 -m venv .venv-dev
.venv-dev/bin/python -m pip install --require-hashes --only-binary :all: -r framework/requirements-hunt.lock
.venv-dev/bin/python scripts/hunt_bots_check.py
```

`framework/requirements-hunt.lock` pins every package the bots, the operator tools and the tests need, with the hash of each published file. pip refuses a download whose hash is not in the lock, and `--only-binary :all:` stops it from falling back to building a source archive. With uv, `uv pip sync --no-config --no-build --python .venv-dev framework/requirements-hunt.lock` does the same (`--no-config` keeps the `[tool.uv]` settings of the upstream `pyproject.toml`, such as `exclude-newer`, out of the install), and a venv made with `uv venv --no-config --python <python.org python.exe> .venv-dev` works too. To change a pin, edit `framework/requirements-hunt.txt` and regenerate the lock with the `uv pip compile` command at the top of that file. The lock does not cover the Temporal time-skipping test server that the workflow tests start: the SDK downloads that binary on first use without a hash check.

The last line must end in `-> PASS`. It runs the framework tests, the operator tests and the gate's own tests in about eight minutes; a few are skipped because they need the private range kit, the optional orchestration or LangChain OpenAI packages, another operating system, symbolic or hard links the host cannot create, `IMAGER_BIN` (a built imager binary), `BENCHMARK_ATTACK_PROVENANCE` (the pinned ATT&CK bundle outside the repository), or Node or Bun on `PATH` (the board page, Desktop contract and film tests). A Python without the lock installed fails at once with `missing: temporalio` (or another package) instead of skipping suites. The tests run with the Python given by `--python <python.exe>`, else the `HUNT_BOTS_PYTHON` environment variable, else the Python running the script, so another Python can start the gate as long as it points at this venv. `--log <file>` writes every test's name and output to that file, `--policy` runs only the file-list checks in seconds, and installing [gitleaks](https://github.com/gitleaks/gitleaks) adds the secret scan.

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
3. Install the six bots, their reviewed policy, the hunting-lab plugin and the desktop pages with one command. It needs [Docker Desktop](https://docs.docker.com/desktop/) running and the [Temporal CLI](https://docs.temporal.io/cli) (`temporal`) on PATH, and checks both before it changes anything. Pass the lab's `hermes` executable with `--hermes`, so no other `hermes` on PATH runs. From `framework/`:

   ```powershell
   ..\.venv-dev\Scripts\python.exe setup_hermes.py --hermes '<lab hermes.exe>' --home ..\..\runtime\lab-home all
   ```

   Answer `y` to each `profile install` prompt. The command checks Hermes, Docker and the Temporal CLI, creates the Hermes home if it does not exist yet, installs each missing profile, writes each new profile's policy file (`native_team.py initialize`), installs and enables the lab plugin and the desktop pages, applies the remaining policy (`native_team.py apply`), checks it (`native_team.py check`) and runs doctor. It ends `setup: complete` only with zero drift, or stops at the first failure with `setup: stopped at <step>: <reason>`. Running it again keeps what is already installed, including edited `SOUL.md` files, which doctor reports without overwriting them. Without `--hermes`, it uses `LAB_HERMES_EXE`, then `hermes` on PATH. Details: [framework/hermes-setup.md](framework/hermes-setup.md).

   Later, check that the installed bots still match the repo:

   ```powershell
   ..\.venv-dev\Scripts\python.exe doctor.py --hermes '<lab hermes.exe>' --home ..\..\runtime\lab-home
   ```

   It prints one `drift:` line for each installed `SOUL.md`, plugin file or `model.default`/`model.provider` setting that differs from the repo, then `doctor: <n> drift`, and exits non-zero on any drift. It reads files only.
4. Optional: build the Hunt Command desktop app, which has the Hunting Lab, Hunt Board and Cybersecurity workspace pages built in (copies installed by step 3 are then skipped in favour of the built-in ones). From the repository root, with the Node version in `.nvmrc`:

   ```powershell
   npm ci
   npm run pack:hunt --workspace apps/desktop
   ```

   That writes an unpacked, unsigned app to `apps\desktop\release\win-unpacked\Hunt Command.exe`. It keeps its own app settings and single-instance lock, so it runs beside an installed Hermes desktop app without replacing it, and it never updates itself: pull and rerun `pack:hunt` for a new version. When its Hermes home has no Hermes checkout yet, its first-run install clones this fork instead of upstream Hermes. Both apps answer `hermes://` links and the one launched last wins; starting Hunt Command with `HERMES_DESKTOP_SKIP_PROTOCOL_REGISTRATION=1` skips its registration and keeps whatever handler is current, without restoring Hermes. If Hunt Command already took the links, start stock Hermes once to take them back. It uses the same Hermes home as Hermes unless told otherwise, so start it on the lab home: `$env:HERMES_HOME = '<full path to runtime\lab-home>'; & '.\apps\desktop\release\win-unpacked\Hunt Command.exe'`. Details: [apps/desktop/BUILDING.md](apps/desktop/BUILDING.md#hunt-command-variant).

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

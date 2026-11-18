# Temporal Tool-Driven Lab Input

`python -m hermes_temporal.cli lab-input` builds a validated Temporal workflow request JSON (`inline` or `--tool-driven`) from the synthetic fixture or active lab case so `PracticeWorkflow`, `HermesWorkflow`, and `hermes_temporal.board` share one case contract.

## Sub-features

- `--tool-driven` emits `"mode": "tool_driven"` so bots query the live lab via tools rather than receiving inline log rows.
- `--data-origin` marks non-synthetic runs (`public-dataset`, `work-export`, `work-connected`) with `"synthetic_only": false` so `HUNT-BOTS.md` Rule 4 suppresses unverified bot text on external/status surfaces.

## How to get to it (user POV)

Run `python -m hermes_temporal.cli lab-input --tool-driven` from CLI, or leave `--input` blank in Hunt Command Desktop's **Hunt Board** launcher so Desktop exports it automatically.

## Driving it with control-hunt-lab

Preconditions: `doctor` reports `"lock_python_found": true`.

1. Action: Export a tool-driven synthetic lab input JSON into `<evidence-dir>`.
   Command: `python .agents/skills/verify-hunt-lab/control-hunt-lab.py lab-input --python <lock-python> --state-dir <hermes-home>/profiles/framework-network-analyst/hunt-lab-vm --tool-driven --out <evidence-dir>/tool-driven-input.json`
   Observable result: `"ok": true`, `"mode": "tool_driven"`, and `<evidence-dir>/tool-driven-input.json` exists.
2. Action: Export a `public-dataset` lab input JSON (against a case declaring `"data_origin": "public-dataset"`) and confirm non-synthetic marking.
   Command: `python .agents/skills/verify-hunt-lab/control-hunt-lab.py lab-input --python <lock-python> --state-dir <hermes-home>/profiles/framework-network-analyst/hunt-lab-vm --tool-driven --data-origin public-dataset --out <evidence-dir>/public-input.json`
   Observable result: `"ok": true` and the exported JSON carries `"data_origin": "public-dataset"` and `"synthetic_only": false`.

## Gotchas

- When starting `hermes_temporal.board` against a `"mode": "tool_driven"` input JSON, `--lab-state-dir` is mandatory; against an `"inline"` input JSON, `--lab-state-dir` must be omitted (`board.py` enforces both).

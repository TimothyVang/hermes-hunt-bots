---
name: principle-explain-the-number
description: "Apply before you measure, and before you trust, report, or act on a number you measured: a speedup, a regression, a throughput, a latency, or an eval result. Find what limits it, and rule out that it measured something other than the work you think."
disable-model-invocation: true
---

# Explain the Number

In OMP, read [the OMP adapter](../../docs/harness/omp.md) before following this skill. It explains how pstack host-specific instructions map to OMP.

For user-facing commands and copyable prompts, invoke discovered pstack skills as `/skill:<name>`, for example `/skill:poteto-mode`, `/skill:poteto-help`, and `/skill:how`. This OMP syntax takes precedence over shorthand in the source text, examples, recipes, and linked guides, even where the source says to trust those guides. Apply it in prose and code blocks. Do not invent skill commands for host built-ins or unavailable external skills.

- **Write the decision before you run.** Name the result that would change a decision, and the noise floor. Stop when the run-to-run spread is larger than the effect.
- **Ask "why not double?"** Name the resource or code path that bounds the result, such as a core, a lock, the disk, the network, or the load generator itself. Get it from a profile or from system counters taken during a run, then map it to source. A guess from reading the code is not a limiter. If you cannot say why the number is not twice as good, you do not know what you measured.
- **List what else the number could be measuring, and rule out each one with evidence.** The usual suspects are errors, skipped or cached work, code that never ran, an untuned side (one left on default settings), noise, and a piece too small to matter end to end.
- **Keep the evidence with the number.** Put the run count, the spread, and the limiter in the notes or a linked artifact.

For a performance number, run the full procedure with the [benchmark-checklist](../benchmark-checklist/SKILL.md) skill. For an eval result, ask the same of the trials: did every run do the task, does the gap hold across trials and models, and does the scenario matter.

You skipped this when a run started without the result that would change a decision, when the evidence behind a number has no run count, no spread, or no named limiter, or when the time saved is larger than the time the changed piece took.

Distinct from [Prove It Works](../principle-prove-it-works/SKILL.md), which checks that an output is real.

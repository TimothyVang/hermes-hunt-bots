---
name: principle-never-block-on-the-human
description: "Apply when tempted to ask 'should I do X?' on reversible work."
disable-model-invocation: true
---

# Never Block on the Human

In OMP, read [the OMP adapter](../../docs/harness/omp.md) before following this skill. It explains how pstack host-specific instructions map to OMP.

For user-facing commands and copyable prompts, invoke discovered pstack skills as `/skill:<name>`, for example `/skill:poteto-mode`, `/skill:poteto-help`, and `/skill:how`. This OMP syntax takes precedence over shorthand in the source text, examples, recipes, and linked guides, even where the source says to trust those guides. Apply it in prose and code blocks. Do not invent skill commands for host built-ins or unavailable external skills.

The human supervises asynchronously. Agents must stay unblocked. Make reasonable decisions, proceed, and let the human course-correct after the fact. Since code changes are reversible and reviewable, a wrong decision usually costs less than blocking.

- Proceed, then present. Do the work, show the result. Don't ask "should I do X?" Do X, explain why.
- Make the system self-healing. When you notice a problem, log it and fix it in the next round.
- Irreversible actions (force-push, delete production data, send external messages) still require confirmation.
- Reversible actions (write code, edit notes, split tasks) should proceed without blocking.
- Product direction comes from the human. Execution should not block.

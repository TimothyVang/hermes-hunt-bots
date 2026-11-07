---
name: principle-minimize-reader-load
description: "Apply when reviewing or shaping code that's hard to trace. Count layers between question and answer, and hidden state in the reader's head; collapse one-caller wrappers and shrink mutable scope."
disable-model-invocation: true
---

# Minimize Reader Load

In OMP, read [the OMP adapter](../../docs/harness/omp.md) before following this skill. It explains how pstack host-specific instructions map to OMP.

For user-facing commands and copyable prompts, invoke discovered pstack skills as `/skill:<name>`, for example `/skill:poteto-mode`, `/skill:poteto-help`, and `/skill:how`. This OMP syntax takes precedence over shorthand in the source text, examples, recipes, and linked guides, even where the source says to trust those guides. Apply it in prose and code blocks. Do not invent skill commands for host built-ins or unavailable external skills.

Maintainability is the work a reader must do to understand code. Track two axes: **layers to trace** (indirections between the question and the answer) and **state to hold** (hidden or mutable context the reader must keep in their head). LOC, cyclomatic complexity, and "clean architecture" are proxies. Reader load is the thing that matters. The two axes are independent. A flat file with 50 globals can be as hard to reason about as a 6-layer adapter stack. Guard both. This is the human analog of [Guard the Context Window](../principle-guard-the-context-window/SKILL.md). Working memory is finite for readers too.

- **Collapse layers** that cost more than they save: wrappers with one caller, adapters with no second implementation, speculative indirection that was never needed. Inline them.
- **Make adjacent layers change the abstraction.** A layer that repeats the same methods and arguments adds reader load without compression. Collapse pass-through layers.
- **Demand interface compression.** A broad interface that hides little complexity makes readers learn both the surface and the implementation. Prefer boundaries that hide meaningful decisions.
- **Shrink state scope:** prefer pure functions (returns over mutations), locals over fields, fields over module state, and module state over globals. Derive instead of sync.
- **Name the invariant at the boundary,** not in every consumer, so the reader learns it once.
- Before adding a layer or a piece of state, ask: does it reduce reader load elsewhere by at least as much?

**The test:** can a new reader answer "where does X come from?" and "what can change X?" in under 30 seconds? If not, cut layers or cut state.

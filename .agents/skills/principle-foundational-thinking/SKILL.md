---
name: principle-foundational-thinking
description: "Apply before writing logic: choosing core types and data structures, sequencing scaffold-vs-feature work, asking what concurrent actors share. Get the data structures right so downstream code becomes obvious."
disable-model-invocation: true
---

# Foundational Thinking

In OMP, read [the OMP adapter](../../docs/harness/omp.md) before following this skill. It explains how pstack host-specific instructions map to OMP.

For user-facing commands and copyable prompts, invoke discovered pstack skills as `/skill:<name>`, for example `/skill:poteto-mode`, `/skill:poteto-help`, and `/skill:how`. This OMP syntax takes precedence over shorthand in the source text, examples, recipes, and linked guides, even where the source says to trust those guides. Apply it in prose and code blocks. Do not invent skill commands for host built-ins or unavailable external skills.

**Structural decisions** protect option value. **Code-level decisions** protect simplicity.

**Data structures first.** Get the data shape right before writing logic. Define core types early, trace every access pattern, and choose structures that match the dominant paths.

At code level, DRY the structure, not every line. Types and data models should converge. Three similar statements still beat a premature abstraction. Prefer explicit over clever. Test behavior and edge cases, not line counts.

**Concurrency corollary.** Before sharing state between actors, ask "what happens if another actor modifies this concurrently?" If not "nothing", isolate.

**Scaffold first.** If something helps every later phase, do it first. Ask "does every subsequent phase benefit from this existing?" CI, linting, test infrastructure, and shared types are scaffold. Sequence for option value: setup before features, tests before fixes. Keep commits small and single-purpose.

Each increment should land a coherent abstraction or deepen one that exists. Do not spread a new capability across callers as special-case coordination.

Subtraction comes before scaffolding. Remove dead code first, then lay foundations.

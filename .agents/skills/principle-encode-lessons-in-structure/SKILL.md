---
name: principle-encode-lessons-in-structure
description: "Apply when you catch yourself writing the same instruction a second time, or notice a recurring correction. Encode the rule as a lint, metadata flag, runtime check, or script instead of more text."
disable-model-invocation: true
---

# Encode Lessons in Structure

In OMP, read [the OMP adapter](../../docs/harness/omp.md) before following this skill. It explains how pstack host-specific instructions map to OMP.

For user-facing commands and copyable prompts, invoke discovered pstack skills as `/skill:<name>`, for example `/skill:poteto-mode`, `/skill:poteto-help`, and `/skill:how`. This OMP syntax takes precedence over shorthand in the source text, examples, recipes, and linked guides, even where the source says to trust those guides. Apply it in prose and code blocks. Do not invent skill commands for host built-ins or unavailable external skills.

If the lesson needs judgment and cannot be encoded, make the instruction more prominent and add an example of the failure mode.

**Corollary:** If the fix is structural, only use the structural fix. The instruction is the symptom.

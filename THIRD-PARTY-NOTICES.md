# Third-party notices

Code copied into this repository from other projects keeps its original license and copyright notice. Each entry lists the source, its license, what was copied, and where it lives here. Files modified after copying say so in a header comment.

Hermes itself (everything outside `framework/`) is MIT, Copyright (c) 2025 Nous Research; see [LICENSE](LICENSE). Bundled components inside `framework/` (noVNC and its dependencies, the security-audit skill) carry their notices next to the code, under `framework/hunt_lab/desktop/licenses/` and `framework/hermes-skills/security-audit/LICENSE`.

| Source | License | Copied | Location here |
|---|---|---|---|
| [oh-my-pi](https://github.com/can1357/oh-my-pi) browser tool, commit `89833d37f43289f0c33a5658d8784b0086254cf8` | MIT, Copyright (c) 2025 Mario Zechner, Copyright (c) 2025-2026 Can Bölük, Copyright (c) 2026 Stencil Labs, Inc. (full notice in the file header) | The click actionability check (`checkClickActionable` and `composedContains` from `packages/coding-agent/src/tools/browser/interactions.ts`), modified: ported to one CDP page function, with a disabled check, fixed reason codes, the visible box, and a hit test at a caller-chosen point | `framework/hunt_lab/actionability.py` |

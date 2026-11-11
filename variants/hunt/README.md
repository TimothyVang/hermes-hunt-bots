# Hunt Command desktop variant

`HERMES_DESKTOP_VARIANT=hunt` builds Hermes Desktop as **Hunt Command** (`npm run pack:hunt` in `apps/desktop`; see `apps/desktop/BUILDING.md`).

- `brand/hunt-command-mark-mono.svg`: our monochrome mark, copied unchanged from `design/brand/` in the bot-framework workspace (2026-11-11). It replaced the coloured mark after the "looks AI" feedback; every icon here is rendered from it.
- `icons/apps/desktop/{assets,public}`: the generated icon tree, committed. The build's `--icons` hook copies it over `apps/desktop/assets` and the renderer's public dir.
- `generate_icons.py`: regenerates `icons/` from the mono mark with a Hermes runtime Python (Pillow + resvg-py): `<hermes venv python> variants/hunt/generate_icons.py`.

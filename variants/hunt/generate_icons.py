#!/usr/bin/env python3
"""Render the Hunt Command desktop icon tree from brand/hunt-command-mark-mono.svg.

Writes icons/apps/desktop/{assets,public}: the same files scripts/generate_icons.py
writes for the stock app, which `npm run build -- --icons ../../variants/hunt/icons`
copies over apps/desktop/assets and the renderer's public dir. The MSIX tile table is
imported from that script so both trees stay in step.

Run with a Hermes runtime interpreter (Pillow + resvg-py), from anywhere:
    <hermes venv python> variants/hunt/generate_icons.py
"""

from __future__ import annotations

import io
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(REPO / "scripts"))

from PIL import Image

from generate_icons import APPX_TARGETS, paste_centered, render_svg, save_png

OUT = HERE / "icons"
INK = "#FFFFFF"  # the plate: the mark's currentColor on the Hunt Command dark theme
KNOCKOUT = "#0B0C0E"  # the crosshair, as drawn in the mark
MONO = (HERE / "brand/hunt-command-mark-mono.svg").read_text(encoding="utf-8")
TILE = MONO.replace("currentColor", INK)
# macOS icns/Dock art sits on Apple's 824px grid centred in 1024, like the stock icons.
MAC = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1024 1024">'
    '<svg x="100" y="100" width="824" height="824" viewBox="0 0 24 24">'
    + TILE.split(">", 1)[1].rsplit("</svg>", 1)[0]
    + "</svg></svg>"
)


def crosshair(stroke: str) -> str:
    """The mark without its plate: an Icon Composer layer the system masks itself."""
    return MONO.replace('<rect width="24" height="24" rx="6" fill="currentColor"/>', "").replace(KNOCKOUT, stroke)


def png(svg: str, size: int) -> bytes:
    buf = io.BytesIO()
    save_png(render_svg(svg, size), buf)
    return buf.getvalue()


def container(svg: str, fmt: str, sizes: list[int]) -> bytes:
    buf = io.BytesIO()
    img = render_svg(svg, max(sizes))
    if fmt == "ICO":
        img.save(buf, format="ICO", sizes=[(s, s) for s in sizes])
    else:
        img.save(buf, format="ICNS", append_images=[img.resize((s, s), Image.LANCZOS) for s in sizes[1:]])
    return buf.getvalue()


def wide(w: int, h: int, tile: int) -> bytes:
    canvas = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    paste_centered(canvas, render_svg(TILE, tile))
    buf = io.BytesIO()
    canvas.save(buf, "PNG")
    return buf.getvalue()


def icon_manifest() -> bytes:
    """The stock Icon Composer manifest with this mark's plate colours (white; knockout in dark)."""
    manifest = json.loads((REPO / "apps/desktop/assets/icon.icon/icon.json").read_text(encoding="utf-8"))
    knockout = ",".join(f"{int(KNOCKOUT[i:i + 2], 16) / 255:.5f}" for i in (1, 3, 5))
    manifest["fill-specializations"] = [
        {"value": {"solid": "srgb:1.00000,1.00000,1.00000,1.00000"}},
        {"appearance": "dark", "value": {"solid": f"srgb:{knockout},1.00000"}},
    ]
    return (json.dumps(manifest, indent=2) + "\n").encode("utf-8")


ICO_SIZES = [16, 24, 32, 48, 64, 128, 256]
ICNS_SIZES = [1024, 16, 32, 64, 128, 256, 512]
TARGETS: dict[str, bytes] = {
    **{f"apps/desktop/assets/{name}.png": png(TILE, 1024) for name in ("icon", "icon-dark")},
    **{f"apps/desktop/assets/{name}.ico": container(TILE, "ICO", ICO_SIZES) for name in ("icon", "icon-dark")},
    **{f"apps/desktop/assets/{name}.icns": container(MAC, "ICNS", ICNS_SIZES) for name in ("icon", "icon-dark")},
    "apps/desktop/assets/icon-mac.png": png(MAC, 1024),
    "apps/desktop/assets/icon.icon/icon.json": icon_manifest(),
    "apps/desktop/assets/icon.icon/Assets/art-light.png": png(crosshair(KNOCKOUT), 1024),
    "apps/desktop/assets/icon.icon/Assets/art-dark.png": png(crosshair(INK), 1024),
    "apps/desktop/assets/icon.icon/Assets/mono.png": png(crosshair(INK), 1024),
    **{rel: wide(*arg) if kind == "wide" else png(TILE, arg) for rel, kind, arg in APPX_TARGETS},
    "apps/desktop/public/apple-touch-icon.png": png(TILE, 1024),
    # The in-app BrandMark (src/components/brand-mark.tsx) reads these two names.
    "apps/desktop/public/nous-girl.png": png(TILE, 256),
    "apps/desktop/public/nous-girl-dark.png": png(TILE, 256),
}

if __name__ == "__main__":
    for rel, data in TARGETS.items():
        path = OUT / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    print(f"wrote {len(TARGETS)} files under {OUT.relative_to(REPO)}")

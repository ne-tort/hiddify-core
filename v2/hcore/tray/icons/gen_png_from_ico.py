#!/usr/bin/env python3
"""Generate PNG systray icons from ICO sources (Linux/macOS)."""
from __future__ import annotations

from pathlib import Path

from PIL import Image

NAMES = (
    "tray_icon",
    "tray_icon_connected",
    "tray_icon_disconnected",
    "tray_icon_dark",
)
SIZE = 64


def main() -> None:
    here = Path(__file__).resolve().parent
    for name in NAMES:
        ico = here / f"{name}.ico"
        png = here / f"{name}.png"
        if not ico.is_file():
            raise SystemExit(f"missing {ico}")
        img = Image.open(ico)
        img = img.convert("RGBA")
        img = img.resize((SIZE, SIZE), Image.Resampling.LANCZOS)
        img.save(png, format="PNG")
        print(f"wrote {png.name} ({png.stat().st_size} bytes)")


if __name__ == "__main__":
    main()

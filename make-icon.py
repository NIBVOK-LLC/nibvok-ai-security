#!/usr/bin/env python3
"""Generate assets/icon.png for NIBVOK AI Security.

A shield mark: dark navy field, a shield outline, and a horizontal key/lock bar.
Deliberately plain — no text, so it reads at 32px. Well under the 512 KiB cap.
"""
from PIL import Image, ImageDraw

S = 512
BG = (11, 18, 32, 255)        # near-black navy
EDGE = (56, 189, 248, 255)    # cyan
CORE = (226, 232, 240, 255)   # near-white
ACCENT = (34, 197, 94, 255)   # green check

img = Image.new("RGBA", (S, S), BG)
d = ImageDraw.Draw(img)

# Shield silhouette, centred, with a generous margin.
cx, top, bot = S // 2, 92, 424
half = 150

pts = [
    (cx, top),
    (cx + half, top + 58),
    (cx + half, top + 176),
    (cx, bot),
    (cx - half, top + 176),
    (cx - half, top + 58),
]
d.polygon(pts, fill=(17, 27, 47, 255), outline=EDGE, width=14)

# Inner shield, thinner stroke, to give the mark depth.
inset = 34
ipts = [
    (cx, top + inset),
    (cx + half - inset, top + 58 + inset // 2),
    (cx + half - inset, top + 176),
    (cx, bot - inset),
    (cx - half + inset, top + 176),
    (cx - half + inset, top + 58 + inset // 2),
]
d.polygon(ipts, outline=(30, 58, 95, 255), width=6)

# A check mark: the decision that "allowed" means "checked".
d.line([(cx - 62, top + 168), (cx - 16, top + 216)], fill=CORE, width=26)
d.line([(cx - 16, top + 216), (cx + 74, top + 118)], fill=ACCENT, width=26)

# A bar across the lower shield: the enforcement point.
d.rounded_rectangle(
    [(cx - 84, top + 250), (cx + 84, top + 264)],
    radius=7, fill=EDGE,
)

img.save("assets/icon.png", "PNG", optimize=True)
import os
print("wrote assets/icon.png", os.path.getsize("assets/icon.png"), "bytes")
print("cap 524288 bytes ->", "OK" if os.path.getsize("assets/icon.png") <= 524288 else "TOO BIG")

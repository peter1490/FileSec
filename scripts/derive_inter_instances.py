#!/usr/bin/env python3
"""Derive the static Inter instances bundled in crates/filesec-gui/assets/fonts.

Inter is OFL-1.1 with no Reserved Font Name, so modified versions may keep the
name. The app used to embed the upstream variable font (InterVariable.ttf);
GPUI's Linux text stack renders only a variable font's default instance, so
bold/semibold text would silently fall back to regular there. Static instances
give the same weights on every platform.

Usage (fontTools >= 4.40):
    python3 scripts/derive_inter_instances.py InterVariable.ttf crates/filesec-gui/assets/fonts

Only Regular, SemiBold and Bold are bundled (the weights the UI uses; a
Medium request falls back to Regular).
"""
import sys
from fontTools.ttLib import TTFont
from fontTools.varLib import instancer

src, outdir = sys.argv[1], sys.argv[2]
for weight, style in [(400, "Regular"), (600, "SemiBold"), (700, "Bold")]:
    f = TTFont(src)
    inst = instancer.instantiateVariableFont(f, {"wght": weight, "opsz": 14})
    name = inst["name"]
    for rec in list(name.names):
        if rec.nameID in (1, 2, 3, 4, 6, 16, 17, 21, 22, 25):
            name.removeNames(nameID=rec.nameID)
    full = "Inter" if style == "Regular" else f"Inter {style}"
    ps = f"Inter-{style}"
    legacy_family = "Inter" if style in ("Regular", "Bold") else f"Inter {style}"
    legacy_style = style if style in ("Regular", "Bold") else "Regular"
    for nid, val in [(1, legacy_family), (2, legacy_style), (3, f"{ps};derived-from-InterVariable"),
                     (4, full), (6, ps), (16, "Inter"), (17, style)]:
        name.setName(val, nid, 3, 1, 0x409)
        name.setName(val, nid, 1, 0, 0)
    inst["OS/2"].usWeightClass = weight
    inst["OS/2"].fsSelection = (inst["OS/2"].fsSelection & ~0b1100001) | (0b100000 if style == "Bold" else 0b1000000)
    inst["head"].macStyle = 1 if style == "Bold" else 0
    for t in ("STAT",):
        if t in inst:
            del inst[t]
    inst.save(f"{outdir}/Inter-{style}.ttf")

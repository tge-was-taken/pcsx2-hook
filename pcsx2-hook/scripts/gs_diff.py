#!/usr/bin/env python3
"""Compare a capture manifest against the ground-truth GS draw trace.

Usage: scripts/gs_diff.py <capture-manifest.jsonl>          # the GS rows ride in the manifest
       scripts/gs_diff.py <gs-trace.jsonl> <manifest.jsonl> # a separate PCSX2HOOK_GS_TRACE file
"""
import collections
import json
import sys

TFX = {0: "MODULATE", 1: "DECAL", 2: "HIGHLIGHT", 3: "HIGHLIGHT2"}
ATST = {0: "NEVER", 1: "ALWAYS", 2: "LESS", 3: "LEQUAL", 4: "EQUAL", 5: "GEQUAL", 6: "GREATER", 7: "NOTEQUAL"}
AFAIL = {0: "KEEP", 1: "FB_ONLY", 2: "ZB_ONLY", 3: "RGB_ONLY"}


def load(path):
    out = []
    with open(path) as f:
        for line in f:
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return out


def one_complete_frame(rows):
    """The busiest frame of a multi-frame trace, skipping the first and last, which are partial."""
    if not rows or "f" not in rows[0]:
        return rows, None
    by_frame = collections.Counter(d["f"] for d in rows)
    interior = set(by_frame) - {min(by_frame), max(by_frame)}
    if not interior:
        return rows, None
    pick = max(interior, key=lambda f: by_frame[f])
    return [d for d in rows if d["f"] == pick], pick


def atest(ate, atst, aref, afail):
    return "off" if not ate else f"{ATST[atst]}:{aref}:{AFAIL[afail]}"


def gs_key(d):
    return (
        "tex" if d["tme"] else "flat",
        TFX[d["tfx"]] if d["tme"] else "-",
        f"tcc{d['tcc']}" if d["tme"] else "-",
        f"abe{d['abe']}",
        f"alpha{d['a']}{d['b']}{d['c']}{d['d']}",
        atest(d["ate"], d["atst"], d["aref"], d["afail"]),
        f"fbmsk{d['fbmsk']}",
    )


def fbmsk_from_colour_mask(cmask):
    fbmsk = 0
    for i, keep in enumerate(cmask):
        if not keep:
            fbmsk |= 0xFF << (8 * i)
    return fbmsk


def ours_key(d):
    alpha = int(d.get("gsAlpha", "0x0"), 16)
    test = int(d.get("gsTest", "0x0"), 16)
    a, b, c, dd = alpha & 3, (alpha >> 2) & 3, (alpha >> 4) & 3, (alpha >> 6) & 3
    ate, atst, aref, afail = test & 1, (test >> 1) & 7, (test >> 4) & 0xFF, (test >> 12) & 3
    fbmsk = fbmsk_from_colour_mask(d.get("cmask", [1, 1, 1, 1]))
    return (
        "tex" if d.get("textured") else "flat",
        "MODULATE" if d.get("textured") else "-",
        (f"tcc{d['tcc']}" if "tcc" in d else "tcc1") if d.get("textured") else "-",
        f"abe{1 if d.get('blend', True) else 0}",
        f"alpha{a}{b}{c}{dd}" if alpha else "alphaRW",
        atest(ate, atst, aref, afail),
        f"fbmsk0x{fbmsk:08X}",
    )


def is_z_clear(d):
    return d["fbmsk"] == "0xFFFFFFFF" and not d["tme"] and not d["abe"]


def main():
    if len(sys.argv) == 2:
        rows = load(sys.argv[1])
        gs = [d for d in rows if d.get("type") == "gs"]
        if not gs:
            raise SystemExit(f"{sys.argv[1]} carries no GS rows; pass a PCSX2HOOK_GS_TRACE file too")
        frame = gs[0].get("f")
        ours_rows = rows
    elif len(sys.argv) == 3:
        gs, frame = one_complete_frame(load(sys.argv[1]))
        ours_rows = load(sys.argv[2])
    else:
        print(__doc__)
        return 2
    clears = [d for d in gs if is_z_clear(d)]
    gs = [d for d in gs if d not in clears]
    ours = [d for d in ours_rows if d.get("type") in ("mesh", "im2d", "pass2")]
    print(f"GS batches: {len(gs)} (+{len(clears)} Z clears)   native draws: {len(ours)}"
          + (f"   (GS frame {frame})" if frame is not None else "   (whole trace: no frame stamps)"))
    print("Counts are NOT comparable: one GS FlushPrim aggregates a run of primitives sharing state,")
    print("and one renderer quad is two triangles. Compare which states exist, not how many.")

    print("\n--- GS state census (field, count) ---")
    gc = collections.Counter(gs_key(d) for d in gs)
    for k, n in gc.most_common():
        print(f"{n:5d}  {' '.join(k)}")

    print("\n--- the native renderer state census ---")
    oc = collections.Counter(ours_key(d) for d in ours)
    for k, n in oc.most_common():
        print(f"{n:5d}  {' '.join(k)}")

    print("\n--- per-field distribution, GS vs native ---")
    names = ["textured", "tfx", "tcc", "abe", "alpha", "atest", "fbmsk"]
    for i, name in enumerate(names):
        g = collections.Counter(gs_key(d)[i] for d in gs)
        o = collections.Counter(ours_key(d)[i] for d in ours)
        onlyGs = sorted(set(g) - set(o))
        onlyOurs = sorted(set(o) - set(g))
        if not onlyGs and not onlyOurs:
            print(f"  {name:9s} same value set: {sorted(g)}")
        else:
            print(f"  {name:9s} SET DIFFERS")
            if onlyGs:
                print(f"    GS only   : {onlyGs}  <- states the renderer never produced")
            if onlyOurs:
                print(f"    native only: {onlyOurs}  <- states the GS never used")
    return 0


if __name__ == "__main__":
    sys.exit(main())

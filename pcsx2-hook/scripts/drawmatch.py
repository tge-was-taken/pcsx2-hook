#!/usr/bin/env python3
"""Pair a capture's native draws with the GS batches in the same manifest.

Usage: drawmatch.py <capture-base> [--all]   (--all also lists the matched pairs)
"""
import json
import sys

MIN_MATCH_SCORE = 0.25
CONTAINED_SCORE = 0.5


def bbox_iou(a, b):
    ix0, iy0 = max(a[0], b[0]), max(a[1], b[1])
    ix1, iy1 = min(a[2], b[2]), min(a[3], b[3])
    if ix1 <= ix0 or iy1 <= iy0:
        return 0.0
    inter = (ix1 - ix0) * (iy1 - iy0)
    area_a = max(a[2] - a[0], 0) * max(a[3] - a[1], 0)
    area_b = max(b[2] - b[0], 0) * max(b[3] - b[1], 0)
    union = area_a + area_b - inter
    return inter / union if union > 0 else 0.0


def contained(inner, outer, slack=2.0):
    return (inner[0] >= outer[0] - slack and inner[1] >= outer[1] - slack
            and inner[2] <= outer[2] + slack and inner[3] <= outer[3] + slack)


def blend_of(d):
    a = d.get("alpha") or ""
    try:
        return int(a, 16) & 0xFF
    except ValueError:
        return None


def our_draws(rows):
    out = []
    for r in rows:
        if r.get("type") == "mesh":
            out.append({"i": r["i"], "kind": "mesh", "bbox": r["scr"], "textured": r["textured"],
                        "alpha": r.get("gsAlpha", ""), "pass": r["pass"],
                        "clipped": r.get("scrClipped", False)})
        elif r.get("type") == "im2d":
            out.append({"i": r["i"], "kind": r.get("pipe", "im2d"), "bbox": r["bbox"],
                        "textured": r["textured"], "alpha": r.get("gsAlpha", ""), "pass": r["pass"],
                        "clipped": False})
    return out


def vu_program_id(g):
    return g.get("vu", "0x0")[2:10]


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    base = sys.argv[1]
    show_all = "--all" in sys.argv
    rows = [json.loads(l) for l in open(base + "-manifest.jsonl")]
    gs = [r for r in rows if r.get("type") == "gs"]
    ours = our_draws(rows)
    if not gs:
        print("no GS rows in the manifest: run with the trace armed (gs_diff_all.sh does)")
        return 1
    frames = sorted({r["f"] for r in gs})
    if len(frames) > 1:
        print(f"note: {len(frames)} GS frames embedded {frames}; using all of them")

    claims = {id(g): [] for g in gs}
    unmatched, unusable = [], []
    for d in ours:
        best, best_score = None, 0.0
        for g in gs:
            if bool(g["tme"]) != bool(d["textured"]):
                continue
            if blend_of(d) is not None and blend_of(d) != int(g["alpha"], 16) & 0xFF:
                continue
            score = bbox_iou(d["bbox"], g["bbox"])
            if contained(d["bbox"], g["bbox"]) or (d["clipped"] and contained(g["bbox"], d["bbox"])):
                score = max(score, CONTAINED_SCORE)
            if score > best_score:
                best, best_score = g, score
        if best is not None and best_score >= MIN_MATCH_SCORE:
            claims[id(best)].append(d)
        elif d["clipped"]:
            unusable.append(d)
        else:
            unmatched.append(d)

    orphan = [g for g in gs if not claims[id(g)]]
    print(f"{len(ours)} draws, {len(gs)} GS batches: "
          f"{len(ours) - len(unmatched) - len(unusable)} matched, {len(unmatched)} unmatched, "
          f"{len(unusable)} with an unusable box, {len(orphan)} batches with no draw")

    if unmatched:
        print("\nour draws with no GS batch (the hardware did not run these):")
        for d in sorted(unmatched, key=lambda d: -(d['bbox'][2] - d['bbox'][0])):
            b = [int(v) for v in d["bbox"]]
            print(f"  i{d['i']:4d} pass{d['pass']:<3} {d['kind']:<6} tex{int(d['textured'])} "
                  f"alpha{d['alpha']:>8} bbox{b}")
    if orphan:
        print("\nGS batches with no draw of ours (we never submitted these):")
        for g in sorted(orphan, key=lambda g: -(g['bbox'][2] - g['bbox'][0])):
            b = [int(v) for v in g["bbox"]]
            print(f"  f{g['f']} b{g['i']:<4} nv{g['nverts']:<5} tme{g['tme']} "
                  f"alpha{g['alpha'][-4:]} rgba({g['r']},{g['g']},{g['b_']},{g['a_']}) "
                  f"vu{vu_program_id(g)} bbox{b}")
    if show_all:
        print("\nmatched:")
        for g in gs:
            if claims[id(g)]:
                ids = ",".join(str(d["i"]) for d in claims[id(g)])
                print(f"  f{g['f']} b{g['i']:<4} nv{g['nverts']:<5} vu{vu_program_id(g)} "
                      f"<- draws {ids}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

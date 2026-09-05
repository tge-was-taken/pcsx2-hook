#!/usr/bin/env python3
"""Aggregate the per-scene reports gs_diff_all.sh wrote into one table.

Usage: scripts/gs_diff_summary.py [dir]   (default /tmp/pcsx2hook-gsdiff)
"""
import collections
import glob
import re
import os
import sys

FIELDS = ["textured", "tfx", "tcc", "abe", "alpha", "atest", "fbmsk"]


def parse(path):
    """-> (batches, draws, {field: (only_gs, only_ours)}) for one scene report."""
    batches = draws = 0
    diffs, field = {}, None
    for line in open(path):
        if line.startswith("GS batches:"):
            nums = re.findall(r"\d+", line)
            batches, draws = int(nums[0]), int(nums[2])  # batches, clears, draws
        s = line.strip()
        for f in FIELDS:
            if s.startswith(f) and ("SET DIFFERS" in s or "same value set" in s):
                field = f
                diffs.setdefault(field, ([], []))
        if s.startswith("GS only") and field:
            diffs[field][0].extend(eval(s.split(":", 1)[1].split("<-")[0].strip()))
        elif s.startswith("native only") and field:
            diffs[field][1].extend(eval(s.split(":", 1)[1].split("<-")[0].strip()))
    return batches, draws, diffs


def main():
    root = sys.argv[1] if len(sys.argv) > 1 else "/tmp/pcsx2hook-gsdiff"
    reports = sorted(glob.glob(os.path.join(root, "*-diff.txt")))
    if not reports:
        raise SystemExit(f"no *-diff.txt under {root}")
    scenes = []
    for p in reports:
        name = os.path.basename(p)[: -len("-diff.txt")]
        scenes.append((name,) + parse(p))

    w = max(len(s[0]) for s in scenes) + 1
    print(f"{'scene':{w}} {'GS':>6} {'ours':>6}  " + "  ".join(f"{f:>9}" for f in FIELDS))
    for name, batches, draws, diffs in scenes:
        cells = []
        for f in FIELDS:
            g, o = diffs.get(f, ([], []))
            cells.append("." if not g and not o else f"{len(g)}g/{len(o)}o")
        print(f"{name:{w}} {batches:>6} {draws:>6}  " + "  ".join(f"{c:>9}" for c in cells))
    print("\n'.' = same value set. NgMo = N states only the GS produced, M only the renderer.")
    print("Counts are not comparable between the two columns; see gs_diff.py.")

    print("\n--- states only the GS produced, by field (scene count) ---")
    for f in FIELDS:
        c = collections.Counter()
        for _, _, _, diffs in scenes:
            for v in set(diffs.get(f, ([], []))[0]):
                c[v] += 1
        if c:
            print(f"  {f}: " + ", ".join(f"{v} x{n}" for v, n in c.most_common()))

    print("\n--- states only the renderer produced, by field (scene count) ---")
    for f in FIELDS:
        c = collections.Counter()
        for _, _, _, diffs in scenes:
            for v in set(diffs.get(f, ([], []))[1]):
                c[v] += 1
        if c:
            print(f"  {f}: " + ", ".join(f"{v} x{n}" for v, n in c.most_common()))
    return 0


if __name__ == "__main__":
    sys.exit(main())

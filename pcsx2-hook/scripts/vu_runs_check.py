#!/usr/bin/env python3
"""Check that each recorded VU run replays from its initial state to its recorded end state."""
import json
import sys
from collections import Counter

FIRST_CONTROL_VI = 24


def fnv1a(data):
    h = 1469598103934665603
    for b in data:
        h = ((h ^ b) * 1099511628211) & 0xFFFFFFFFFFFFFFFF
    return h


def replay(run):
    vf, vi, acc = list(run["in"]["vf"]), list(run["in"]["vi"]), run["in"]["acc"]
    mem = bytearray.fromhex(run["mem"])
    for step in run["steps"]:
        rec = step.get("ext", step)
        for d in rec.get("d", []):
            if d["f"] == "vf":
                vf[d["n"]] = d["v"]
            elif d["f"] == "vi":
                vi[d["n"]] = d["v"]
            else:
                acc = d["v"]
        for m in rec.get("m", []):
            q = int(m["q"], 16) * 16
            mem[q:q + 16] = bytes.fromhex(m["v"])
    out = run["out"]
    return (vf == out["vf"] and vi[:FIRST_CONTROL_VI] == out["vi"][:FIRST_CONTROL_VI] and acc == out["acc"]
            and fnv1a(mem) == int(out["memHash"], 16))


def main():
    counts = Counter()
    for path in sys.argv[1:]:
        for line in open(path):
            run = json.loads(line)
            if run["truncated"]:
                counts["truncated, skipped"] += 1
            elif replay(run):
                counts["replays to its end state"] += 1
            else:
                counts["MISMATCH"] += 1
                print(f"mismatch: {path} unit {run['unit']} entry {run['entry']} ee {run['ee']}")
    print(dict(counts))
    return 1 if counts["MISMATCH"] else 0


if __name__ == "__main__":
    sys.exit(main())

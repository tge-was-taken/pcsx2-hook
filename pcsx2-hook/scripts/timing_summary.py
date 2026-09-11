#!/usr/bin/env python3
"""Summarise timing traces, one row per scene directory."""
import json
import pathlib
import statistics
import sys


def median(values):
    return int(statistics.median(values)) if values else 0


def summarise(d):
    row = {"scene": d.name}
    spans, slices, sends = [], [], []
    starts, masked_stalls, path3_packets = {}, 0, 0
    timeline = d / "timing_timeline.jsonl"
    if timeline.exists():
        for line in timeline.open():
            e = json.loads(line)
            kind = e["ev"]
            if kind == "vu_start":
                starts[e["unit"]] = [e["ee"], 0]
            elif kind == "vu_slice" and e["unit"] in starts:
                starts[e["unit"]][1] += 1
            elif kind == "vu_end" and e["unit"] in starts:
                ee, n = starts.pop(e["unit"])
                spans.append(e["ee"] - ee)
                slices.append(n)
            elif kind == "xgkick_done" and e["chunks"]:
                sends.append(e["lastVu"] - e["issueVu"])
            elif kind == "gif_dma" and e["str"] and e["qwc"] and e["path3Masked"]:
                masked_stalls += 1
            elif kind == "gs_packet" and e["path"] == 3:
                path3_packets += 1
    row.update(runs=len(spans), spanMedian=median(spans), spanMax=max(spans, default=0),
               slicesMedian=median(slices), kickSendMedian=median(sends),
               path3Packets=path3_packets, maskedStalls=masked_stalls)

    tags, reads = {}, 0
    runs = d / "vu_runs.jsonl"
    if runs.exists():
        for line in runs.open():
            r = json.loads(line)
            for t in r["tags"]:
                tags[t] = tags.get(t, 0) + 1
            reads += sum(len(s.get("xr", [])) for s in r["steps"])
    row.update(kept=sum(1 for _ in runs.open()) if runs.exists() else 0, midRunReads=reads,
               tags=tags)
    hazards = d / "xgkick_hazards.jsonl"
    row["kickHazards"] = sum(1 for _ in hazards.open()) if hazards.exists() else 0
    return row


def main():
    dirs = [pathlib.Path(p) for p in sys.argv[1:] if (pathlib.Path(p) / "timing_timeline.jsonl").exists()]
    cols = ["scene", "runs", "spanMedian", "spanMax", "slicesMedian", "kept", "midRunReads",
            "kickSendMedian", "kickHazards", "path3Packets", "maskedStalls"]
    print("\t".join(cols + ["tags"]))
    for d in sorted(dirs):
        r = summarise(d)
        print("\t".join(str(r[c]) for c in cols) + "\t" +
              ",".join(f"{k}:{v}" for k, v in sorted(r["tags"].items())))


if __name__ == "__main__":
    main()

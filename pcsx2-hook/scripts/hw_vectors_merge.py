#!/usr/bin/env python3
"""Merge per-scene VU0, VU1, VIF and SPU2 vectors into one corpus per unit, deduped on inputs."""
import argparse
import collections
import json
import pathlib


def mem_in(quads):
    return tuple((q["addr"], q["before"]) for q in quads)


VU_UNIT = (
    lambda r: ["upper:" + r["uform"], "lower:" + r["lform"]],
    lambda r: (r["upper"], r["lower"], json.dumps(r["in"], sort_keys=True),
               json.dumps(r["pipeIn"], sort_keys=True), mem_in(r["mem"])),
)

UNITS = {
    "vu0_vectors.jsonl": VU_UNIT,
    "vu1_vectors.jsonl": VU_UNIT,
    "vif_vectors.jsonl": (
        lambda r: [r["form"]],
        lambda r: (r["code"], json.dumps(r["regsIn"], sort_keys=True), tuple(r["payload"]),
                   r.get("startAligned"), r.get("tail"), mem_in(r["mem"]), mem_in(r["micro"])),
    ),
    "spu_adpcm_vectors.jsonl": (
        lambda r: [r["form"]],
        lambda r: (r["block"], r["prev1"], r["prev2"]),
    ),
    "spu_adsr_vectors.jsonl": (
        lambda r: [r["form"]],
        lambda r: json.dumps(r["in"], sort_keys=True),
    ),
    "spu_volume_vectors.jsonl": (
        lambda r: [r["form"]],
        lambda r: json.dumps([r["leftIn"], r["rightIn"]], sort_keys=True),
    ),
    "spu_voice_vectors.jsonl": (
        lambda r: [r["form"]],
        lambda r: (r["form"], json.dumps(r["in"], sort_keys=True)),
    ),
    "spu_reg_vectors.jsonl": (
        lambda r: [r["form"]],
        lambda r: (r["form"], r["addr"], r["value"],
                   json.dumps(r.get("state") or [(d["field"], d["before"]) for d in r.get("deltas", [])])),
    ),
}


CAP_OVERRIDES = {"spu_voice_vectors.jsonl": 4096}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dirs", nargs="+")
    ap.add_argument("--out", required=True)
    ap.add_argument("--cap", type=int, default=256, help="max cases kept per form")
    args = ap.parse_args()
    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    scene_dirs = [d for d in args.dirs if pathlib.Path(d).resolve() != out.resolve()]

    index = []
    for name, (forms_of, key_of) in UNITS.items():
        kept, seen = [], set()
        count = collections.Counter()
        scenes = collections.defaultdict(set)
        read = 0
        cap = max(args.cap, CAP_OVERRIDES.get(name, 0))
        for d in sorted(scene_dirs):
            path = pathlib.Path(d) / name
            if not path.exists():
                continue
            for line in path.open():
                case = json.loads(line)
                read += 1
                forms = forms_of(case)
                for f in forms:
                    scenes[f].add(pathlib.Path(d).name)
                key = key_of(case)
                if key in seen or all(count[f] >= cap for f in forms):
                    continue
                seen.add(key)
                for f in forms:
                    count[f] += 1
                kept.append((forms[0], line if line.endswith("\n") else line + "\n"))
        if not read:
            continue
        kept.sort(key=lambda k: k[0])
        with (out / name).open("w") as f:
            f.writelines(line for _, line in kept)
        for form in sorted(count):
            index.append([name, form, count[form], len(scenes[form])])
        print(f"{name}: {len(kept)} cases over {len(count)} forms, from {read} read")

    with (out / "hw_forms.jsonl").open("w") as f:
        f.write(json.dumps(["file", "form", "cases", "scenes"]) + "\n")
        for row in index:
            f.write(json.dumps(row) + "\n")


if __name__ == "__main__":
    main()

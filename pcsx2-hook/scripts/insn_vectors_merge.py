#!/usr/bin/env python3
"""Merge per-scene instruction vectors into one corpus, deduplicated on the operands."""
import argparse
import collections
import json
import pathlib


def operand_key(case):
    return (case["code"], case["rsVal"], case["rtVal"], case.get("fsVal", ""),
            case.get("ftVal", ""), case.get("memBefore", ""),
            case.get("in", {}).get("hi", ""), case.get("in", {}).get("lo", ""))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dirs", nargs="+")
    ap.add_argument("--out", required=True)
    ap.add_argument("--cap", type=int, default=256, help="max cases kept per mnemonic")
    ap.add_argument("--file", default="insn_vectors.jsonl",
                    help="insn_vectors.jsonl or iop_vectors.jsonl")
    args = ap.parse_args()

    byForm = collections.defaultdict(list)
    seen = collections.defaultdict(set)
    scenes = collections.defaultdict(set)
    read = 0

    for d in sorted(args.dirs):
        path = pathlib.Path(d) / args.file
        if not path.exists():
            continue
        slug = pathlib.Path(d).name
        for line in path.open():
            case = json.loads(line)
            read += 1
            form = case["mnemonic"]
            scenes[form].add(slug)
            key = operand_key(case)
            if key in seen[form] or len(byForm[form]) >= args.cap:
                continue
            seen[form].add(key)
            case["scene"] = slug
            byForm[form].append(case)

    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    total = 0
    with (out / args.file).open("w") as f:
        for form in sorted(byForm):
            for case in byForm[form]:
                f.write(json.dumps(case, separators=(",", ":")) + "\n")
                total += 1
    with (out / "insn_forms.jsonl").open("w") as f:
        f.write(json.dumps(["mnemonic", "cases", "scenes", "withMem", "withDelta"]) + "\n")
        for form in sorted(byForm):
            cases = byForm[form]
            mem = sum(1 for c in cases if "memAddr" in c)
            delta = sum(1 for c in cases if c["deltas"])
            f.write(json.dumps([form, len(cases), len(scenes[form]), mem, delta]) + "\n")
    print(f"{len(byForm)} forms, {total} vectors kept of {read} read, into {out}")


if __name__ == "__main__":
    main()

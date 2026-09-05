#!/usr/bin/env python3
"""Union the per-scene execution traces into one index, per disc.

A single scene only ever exercises its own code; what bounds a native runtime's work is the union
over every scene plus the boot. Coverage unions, counts sum, and each function and syscall records
which scenes reached it, since "one scene needs this" and "everything needs this" are different facts.
"""
import argparse
import collections
import json
import pathlib
import sys


def readTable(path):
    """A JSONL table: a header array of column names, then one array per row."""
    if not path.exists():
        return []
    with path.open() as f:
        lines = [l for l in f if l.strip()]
    if not lines:
        return []
    header = json.loads(lines[0])
    return [dict(zip(header, json.loads(l))) for l in lines[1:]]


def writeTable(path, columns, rows):
    with path.open("w") as f:
        f.write(json.dumps(columns) + "\n")
        for row in rows:
            f.write(json.dumps(row) + "\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dirs", nargs="+", help="scene trace directories (and/or a boot trace directory)")
    ap.add_argument("--out", required=True, help="where to write the union")
    # Trace directories from several discs can share a parent, and their coverage must not be
    # unioned: the same address means different code. The prefix is whatever the caller names its
    # scenes with, so "--disc p4" keeps p4-* and drops the rest.
    ap.add_argument("--disc", help="only merge scenes whose directory name starts with this")
    args = ap.parse_args()

    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    coverage = set()
    opcodes = collections.Counter()
    functions = collections.Counter()
    functionName = {}
    functionScenes = collections.defaultdict(set)
    syscalls = collections.Counter()
    syscallName = {}
    syscallScenes = collections.defaultdict(set)
    sites = {}
    # Thread ids are assigned per run, so the same tid can mean different threads in two scenes.
    # Key the union on the entry point, which is stable.
    threadScenes = collections.defaultdict(set)
    threadPrio = {}
    threadName = {}
    perScene = []

    for d in args.dirs:
        path = pathlib.Path(d)
        if not path.is_dir():
            continue # a glob picks up the per-scene .log beside each directory
        slug = path.name
        if args.disc and not slug.startswith(args.disc):
            continue
        rows = readTable(path / "exec_coverage.jsonl")
        if not rows:
            print(f"skip {slug}: no coverage", file=sys.stderr)
            continue
        addrs = {int(r["addr"], 16) for r in rows}
        newHere = len(addrs - coverage)
        coverage |= addrs

        for r in readTable(path / "exec_opcodes.jsonl"):
            opcodes[r["mnemonic"]] += int(r["count"])
        funcs = readTable(path / "exec_functions.jsonl")
        for r in funcs:
            entry = int(r["entry"], 16)
            functions[entry] += int(r["count"])
            functionName[entry] = r["symbol"]
            functionScenes[entry].add(slug)
        scs = readTable(path / "exec_syscalls.jsonl")
        for r in scs:
            num = int(r["num"])
            syscalls[num] += int(r["count"])
            syscallName[num] = r["name"]
            syscallScenes[num].add(slug)
        for r in readTable(path / "exec_threads.jsonl"):
            entry = int(r["entry"], 16)
            threadScenes[entry].add(slug)
            threadPrio.setdefault(entry, set()).add(r["priority"])
            threadName[entry] = r["symbol"]
        for r in readTable(path / "exec_syscall_sites.jsonl"):
            sites[int(r["site"], 16)] = r.get("num", "0")
        perScene.append((slug, len(addrs), newHere, len(funcs), len(scs)))

    writeTable(out / "union_coverage.jsonl", ["addr"], [[f"{a:08X}"] for a in sorted(coverage)])
    writeTable(out / "union_opcodes.jsonl", ["count", "mnemonic"],
               [[n, mnem] for mnem, n in opcodes.most_common()])
    writeTable(out / "union_functions.jsonl", ["entry", "count", "scenes", "symbol"],
               [[f"{e:08X}", functions[e], len(functionScenes[e]), functionName[e]]
                for e in sorted(functions)])
    writeTable(out / "union_syscalls.jsonl", ["num", "name", "count", "scenes"],
               [[n, syscallName[n], syscalls[n], len(syscallScenes[n])] for n in sorted(syscalls)])
    writeTable(out / "union_threads.jsonl", ["entry", "scenes", "priorities", "symbol"],
               [[f"{e:08X}", len(threadScenes[e]), sorted(threadPrio[e], key=int), threadName[e]]
                for e in sorted(threadScenes, key=lambda e: -len(threadScenes[e]))])
    # Same shape the runtime reads back as PCSX2HOOK_EXEC_TRACE_SITES.
    writeTable(out / f"sites-{args.disc or 'all'}.jsonl", ["site", "num"],
               [[f"{s:08X}", sites[s]] for s in sorted(sites)])

    perScene.sort(key=lambda r: -r[2])
    print(f"{'scene':<28}{'covered':>9}{'new':>9}{'funcs':>8}{'syscalls':>10}")
    for slug, covered, new, nfuncs, nsys in perScene:
        print(f"{slug:<28}{covered:>9}{new:>9}{nfuncs:>8}{nsys:>10}")
    print(f"\n{args.disc or 'all'} union over {len(perScene)} traces: {len(coverage)} instructions, "
          f"{len(functions)} functions, {len(syscalls)} syscalls, {len(opcodes)} mnemonics, "
          f"{len(sites)} syscall sites, {len(threadScenes)} distinct threads")


if __name__ == "__main__":
    main()

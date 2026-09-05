#!/usr/bin/env python3
"""Union the per-scene execution traces into one index, per disc.

A single scene only ever exercises its own code; what bounds a native runtime's work is the union
over every scene plus the boot. Coverage unions, counts sum, and each function and syscall records
which scenes reached it, since "one scene needs this" and "everything needs this" are different facts.
"""
import argparse
import collections
import pathlib
import sys


def readTsv(path):
    if not path.exists():
        return []
    with path.open() as f:
        header = f.readline().rstrip("\n").split("\t")
        return [dict(zip(header, line.rstrip("\n").split("\t"))) for line in f if line.strip()]


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
        rows = readTsv(path / "exec_coverage.tsv")
        if not rows:
            print(f"skip {slug}: no coverage", file=sys.stderr)
            continue
        addrs = {int(r["addr"], 16) for r in rows}
        newHere = len(addrs - coverage)
        coverage |= addrs

        for r in readTsv(path / "exec_opcodes.tsv"):
            opcodes[r["mnemonic"]] += int(r["count"])
        funcs = readTsv(path / "exec_functions.tsv")
        for r in funcs:
            entry = int(r["entry"], 16)
            functions[entry] += int(r["count"])
            functionName[entry] = r["symbol"]
            functionScenes[entry].add(slug)
        scs = readTsv(path / "exec_syscalls.tsv")
        for r in scs:
            num = int(r["num"])
            syscalls[num] += int(r["count"])
            syscallName[num] = r["name"]
            syscallScenes[num].add(slug)
        for r in readTsv(path / "exec_threads.tsv"):
            entry = int(r["entry"], 16)
            threadScenes[entry].add(slug)
            threadPrio.setdefault(entry, set()).add(r["priority"])
            threadName[entry] = r["symbol"]
        for r in readTsv(path / "exec_syscall_sites.tsv"):
            sites[int(r["site"], 16)] = r.get("num", "0")
        perScene.append((slug, len(addrs), newHere, len(funcs), len(scs)))

    with (out / "union_coverage.tsv").open("w") as f:
        f.write("addr\n")
        for a in sorted(coverage):
            f.write(f"{a:08X}\n")
    with (out / "union_opcodes.tsv").open("w") as f:
        f.write("count\tmnemonic\n")
        for mnem, n in opcodes.most_common():
            f.write(f"{n}\t{mnem}\n")
    with (out / "union_functions.tsv").open("w") as f:
        f.write("entry\tcount\tscenes\tsymbol\n")
        for entry in sorted(functions):
            f.write(f"{entry:08X}\t{functions[entry]}\t{len(functionScenes[entry])}\t{functionName[entry]}\n")
    with (out / "union_syscalls.tsv").open("w") as f:
        f.write("num\tname\tcount\tscenes\n")
        for num in sorted(syscalls):
            f.write(f"{num}\t{syscallName[num]}\t{syscalls[num]}\t{len(syscallScenes[num])}\n")
    with (out / "union_threads.tsv").open("w") as f:
        f.write("entry\tscenes\tpriorities\tsymbol\n")
        for entry in sorted(threadScenes, key=lambda e: -len(threadScenes[e])):
            prios = ",".join(sorted(threadPrio[entry], key=int))
            f.write(f"{entry:08X}\t{len(threadScenes[entry])}\t{prios}\t{threadName[entry]}\n")
    # Same shape the runtime reads back as PCSX2HOOK_EXEC_TRACE_SITES.
    with (out / f"sites-{args.disc or 'all'}.tsv").open("w") as f:
        f.write("site\tnum\n")
        for site in sorted(sites):
            f.write(f"{site:08X}\t{sites[site]}\n")

    perScene.sort(key=lambda r: -r[2])
    print(f"{'scene':<28}{'covered':>9}{'new':>9}{'funcs':>8}{'syscalls':>10}")
    for slug, covered, new, nfuncs, nsys in perScene:
        print(f"{slug:<28}{covered:>9}{new:>9}{nfuncs:>8}{nsys:>10}")
    print(f"\n{args.disc or 'all'} union over {len(perScene)} traces: {len(coverage)} instructions, "
          f"{len(functions)} functions, {len(syscalls)} syscalls, {len(opcodes)} mnemonics, "
          f"{len(sites)} syscall sites, {len(threadScenes)} distinct threads")


if __name__ == "__main__":
    main()

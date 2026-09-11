#!/usr/bin/env python3
"""Check VU, VIF and SPU2 vector files or directories against independent models."""
import json
import pathlib
import re
import struct
import sys
from collections import Counter

INTERP_TABLE = pathlib.Path(__file__).resolve().parents[2] / "pcsx2" / "SPU2" / "interpolate_table.h"
MAX_ROUNDING_ULPS = 1
UNPACK_MASK_ROW, UNPACK_MASK_COL, UNPACK_MASK_KEEP = 1, 2, 3


def rows(path):
    with open(path) as f:
        return [json.loads(line) for line in f]


def s16(v):
    return v - 0x10000 if v & 0x8000 else v


def clamp(v, lo, hi):
    return max(lo, min(hi, v))


def lanes_xyzw(h):
    return [int(h[24 - 8 * i:32 - 8 * i], 16) for i in range(4)]


def f32(u):
    return struct.unpack("<f", struct.pack("<I", u))[0]


def u32(f):
    return struct.unpack("<I", struct.pack("<f", f))[0]


def is_normal(u):
    return 0 < ((u >> 23) & 0xFF) < 0xFF or (u & 0x7FFFFFFF) == 0


def delta(r, file, n):
    return next((d for d in r["deltas"] if d["file"] == file and d["n"] == n), None)


def check_vu(path, st):
    ops = {"ADD": lambda a, b: a + b, "SUB": lambda a, b: a - b, "MUL": lambda a, b: a * b}
    for r in rows(path):
        uf, upper = r["uform"], int(r["upper"], 16)
        base, bc = uf[:3], uf[3:]
        fd, fs, ft, dest = (upper >> 6) & 31, (upper >> 11) & 31, (upper >> 16) & 31, (upper >> 21) & 15
        if base in ops and bc in ("", "x", "y", "z", "w") and not r["ibit"] and fd:
            vf = [lanes_xyzw(h) for h in r["in"]["vf"]]
            s, t = vf[fs], vf[ft]
            if bc:
                t = [t["xyzw".index(bc)]] * 4
            d = delta(r, "vf", fd)
            after = lanes_xyzw(d["after"]) if d else vf[fd]
            for i in range(4):
                if not (dest >> (3 - i)) & 1 or not (is_normal(s[i]) and is_normal(t[i])):
                    continue
                want = ops[base](f32(s[i]), f32(t[i]))
                if want != 0 and not 1e-37 < abs(want) < 1e37:
                    continue
                ok = abs(u32(f32(after[i])) - u32(want)) <= MAX_ROUNDING_ULPS
                st["vu fmac lane " + ("ok" if ok else "MISMATCH")] += 1

        lower = int(r["lower"], 16)
        q = delta(r, "vi", 22)
        if r["lform"] == "DIV":
            pending = r["pipeOut"]["fdiv"]["enable"] == 1
            landing = r["pipeIn"]["fdiv"]
            explained = q is None or (landing["enable"] and int(q["after"], 16) == int(landing["reg"], 16))
            st["vu div issue " + ("ok" if pending and explained else "MISMATCH")] += 1
        if r["pipeIn"]["fdiv"]["enable"] and not r["pipeOut"]["fdiv"]["enable"] and r["lform"] != "DIV":
            landed = int(q["after"], 16) if q else int(r["in"]["vi"][22], 16)
            st["vu q commit " + ("ok" if landed == int(r["pipeIn"]["fdiv"]["reg"], 16) else "MISMATCH")] += 1

        mem = r["mem"]
        ldest = (lower >> 21) & 15
        if r["lform"] in ("LQ", "LQI", "LQD") and mem and (lower >> 16) & 31:
            rt = (lower >> 16) & 31
            quad = [int.from_bytes(bytes.fromhex(mem[0]["before"][8 * i:8 * i + 8]), "little") for i in range(4)]
            d = delta(r, "vf", rt)
            got = lanes_xyzw(d["after"]) if d else lanes_xyzw(r["in"]["vf"][rt])
            ok = all(got[i] == quad[i] for i in range(4) if (ldest >> (3 - i)) & 1)
            st["vu load " + ("ok" if ok else "MISMATCH")] += 1
        if r["lform"] in ("SQ", "SQI", "SQD") and mem:
            src = lanes_xyzw(r["in"]["vf"][(lower >> 11) & 31])
            quad = [int.from_bytes(bytes.fromhex(mem[0]["after"][8 * i:8 * i + 8]), "little") for i in range(4)]
            ok = all(quad[i] == src[i] for i in range(4) if (ldest >> (3 - i)) & 1)
            st["vu store " + ("ok" if ok else "MISMATCH")] += 1

        tpc = delta(r, "vi", 26)
        moved_on = tpc and int(tpc["after"], 16) >> 3 == int(r["pc"], 16) + 1
        st["vu tpc " + ("ok" if moved_on or r["pipeIn"]["branch"]["count"] == 1 else "MISMATCH")] += 1


def sext(v, bits):
    return v - (1 << bits) if v & (1 << (bits - 1)) else v


def predict_unpack(r):
    code = int(r["code"], 16)
    cmd = (code >> 24) & 0x7F
    vn, vl, masked, usn = (cmd >> 2) & 3, cmd & 3, cmd & 0x10, (code >> 14) & 1
    regs = r["regsIn"]
    mode = regs["mode"] & 3
    if vn in (1, 2) or mode == 3 or (vl == 3 and vn != 3):
        return None, "V2/V3 or mode 3"
    cl, wl = regs["cl"], regs["wl"] or 256
    if wl > cl:
        return None, "fill write"
    num = (code >> 16) & 0xFF or 256
    size = 0x400 if r["vif"] == 1 else 0x100
    addr = code & 0x3FF
    if r["vif"] == 1 and (code >> 15) & 1:
        addr += int(regs["tops"], 16)
    data = b"".join(int(w, 16).to_bytes(4, "little") for w in r["payload"][1:])
    row = [int(x, 16) for x in regs["maskRow"]]
    col = [int(x, 16) for x in regs["maskCol"]]
    mask = int(regs["mask"], 16)
    before = {int(q["addr"], 16): bytes.fromhex(q["before"]) for q in r["mem"]}
    comp, ncomp = {0: 4, 1: 2, 2: 1}.get(vl), 1 if vn == 0 else 4
    out = {}
    for i in range(num):
        if vl == 3:
            v = int.from_bytes(data[2 * i:2 * i + 2], "little")
            vals = [(v & 31) << 3, ((v >> 5) & 31) << 3, ((v >> 10) & 31) << 3, ((v >> 15) & 1) << 7]
        else:
            chunk = data[i * comp * ncomp:(i + 1) * comp * ncomp]
            if len(chunk) < comp * ncomp:
                return None, "payload truncated"
            vals = [int.from_bytes(chunk[k * comp:(k + 1) * comp], "little") for k in range(ncomp)]
            if comp < 4 and not usn:
                vals = [sext(v, comp * 8) & 0xFFFFFFFF for v in vals]
            vals = vals * 4 if vn == 0 else vals
        if mode == 1:
            vals = [(vals[k] + row[k]) & 0xFFFFFFFF for k in range(4)]
        elif mode == 2:
            row = [(vals[k] + row[k]) & 0xFFFFFFFF for k in range(4)]
            vals = row[:]
        qa = (addr + (i // wl) * cl + (i % wl)) % size
        if masked:
            mask_row = min(i % wl, 3)
            for k in range(4):
                m = (mask >> (mask_row * 8 + k * 2)) & 3
                if m == UNPACK_MASK_ROW:
                    vals[k] = row[k]
                elif m == UNPACK_MASK_COL:
                    vals[k] = col[mask_row]
                elif m == UNPACK_MASK_KEEP:
                    if qa not in before:
                        return None, "protected lane outside the window"
                    vals[k] = int.from_bytes(before[qa][4 * k:4 * k + 4], "little")
        out[qa] = b"".join(v.to_bytes(4, "little") for v in vals)
    return out, None


def check_vif(path, st):
    for r in rows(path):
        if any(q.get("outsideWindow") for q in r["mem"] + r["micro"]):
            st["vif write outside its window MISMATCH"] += 1
        form = r["form"].split(":")[1]
        code = int(r["code"], 16)
        imm, regs = code & 0xFFFF, r["regsOut"]
        if "UNPACK" in form:
            pred, why = predict_unpack(r)
            if pred is None:
                st["vif unpack not modelled (" + why + ")"] += 1
                continue
            mem = {int(q["addr"], 16): (bytes.fromhex(q["before"]), bytes.fromhex(q["after"])) for q in r["mem"]}
            ok = (all(a in mem and mem[a][1] == v for a, v in pred.items())
                  and all(mem[a][0] == mem[a][1] for a in mem if a not in pred))
            st["vif unpack " + ("ok" if ok else "MISMATCH")] += 1
        elif form == "MPG":
            num = ((code >> 16) & 0xFF) or 256
            want = b"".join(int(w, 16).to_bytes(4, "little") for w in r["payload"][1:1 + num * 2])
            micro = {int(q["addr"], 16): bytes.fromhex(q["after"]) for q in r["micro"]}
            start = imm * 8
            got = bytes(micro.get((start + i) // 16, bytes(16))[(start + i) % 16] for i in range(num * 8))
            st["vif mpg " + ("ok" if got == want else "MISMATCH")] += 1
        elif form in ("STCYCL", "ITOP", "OFFSET", "BASE", "STMOD", "STMASK"):
            want = {"STCYCL": ((regs["cl"], regs["wl"]), (imm & 0xFF, imm >> 8)),
                    "ITOP": (int(regs["itops"], 16), imm & 0x3FF),
                    "OFFSET": (int(regs["ofst"], 16), imm & 0x3FF),
                    "BASE": (int(regs["base"], 16), imm & 0x3FF),
                    "STMOD": (regs["mode"], imm & 3),
                    "STMASK": (int(regs["mask"], 16), int(r["payload"][1], 16) if len(r["payload"]) > 1 else None)}[form]
            st["vif " + form.lower() + " " + ("ok" if want[0] == want[1] else "MISMATCH")] += 1


ADPCM_FILTERS = [(0, 0), (60, 0), (115, -52), (98, -55), (122, -60)]


def check_spu(folder, st):
    adpcm = folder / "spu_adpcm_vectors.jsonl"
    if adpcm.exists():
        for r in rows(adpcm):
            b = bytes.fromhex(r["block"])
            shift, filt = b[0] & 15, (b[0] >> 4) & 15
            if filt > 4 or shift > 12:
                st["spu adpcm outside the documented range"] += 1
                continue
            f0, f1 = ADPCM_FILTERS[filt]
            p1, p2, out = r["prev1"], r["prev2"], []
            for byte in b[2:16]:
                for nib in (byte & 15, byte >> 4):
                    n = nib - 16 if nib & 8 else nib
                    s = clamp(((n << 12) >> shift) + ((f0 * p1 + f1 * p2 + 32) >> 6), -32768, 32767)
                    out.append(s)
                    p2, p1 = p1, s
            ok = [s16(x) for x in r["samples"]] == out and (p1, p2) == (r["prev1Out"], r["prev2Out"])
            st["spu adpcm " + ("ok" if ok else "MISMATCH")] += 1

    adsr = folder / "spu_adsr_vectors.jsonl"
    if adsr.exists():
        for r in rows(adsr):
            i, o, c = r["in"], r["out"], r["in"]["cached"]
            inc = 0x8000 >> max(0, c["shift"] - 11)
            step = c["step"] << max(0, 11 - c["shift"])
            if c["exp"] and not c["decr"] and i["value"] > 0x6000:
                inc >>= 2
            if c["exp"] and c["decr"]:
                step = s16(((step * i["value"]) >> 15) & 0xFFFF)
            counter, value = i["counter"] + max(1, inc), i["value"]
            if counter >= 0x8000:
                counter, value = 0, clamp(value + step, 0, 0x7FFF)
            phase = i["phase"]
            if phase != 3 and ((not c["decr"] and value >= c["target"]) or (c["decr"] and value <= c["target"])):
                phase += 1
            ok = (o["counter"], o["value"]) == (counter, value) and o["phase"] in (phase, 0)
            st["spu adsr " + ("ok" if ok else "MISMATCH")] += 1
            reg = int(i["reg"], 16)
            a1, a2 = reg & 0xFFFF, reg >> 16
            want = {1: (a1 >> 10 & 31, 7 - (a1 >> 8 & 3)), 2: (a1 >> 4 & 15, -8),
                    3: (a2 >> 8 & 31, (-8 + (a2 >> 6 & 3)) if a2 >> 14 & 1 else 7 - (a2 >> 6 & 3)),
                    4: (a2 & 31, -8)}[i["phase"]]
            st["spu adsr parameters " + ("ok" if (c["shift"], c["step"]) == want else "MISMATCH")] += 1

    voice = folder / "spu_voice_vectors.jsonl"
    if voice.exists():
        text = INTERP_TABLE.read_text().split("interpTable = {{")[1].split("}};")[0]
        flat = [int(x, 16) for x in re.findall(r"-?0x[0-9A-Fa-f]+", text)]
        table = [flat[k * 4:k * 4 + 4] for k in range(256)]
        for r in rows(voice):
            i, o = r["in"], r["out"]
            sp, pitch = int(i["sp"], 16), int(i["pitch"], 16)
            if r["form"] == "normal":
                phase, fifo = (sp & 0xFF0) >> 4, [s16(x) for x in i["fifo"]]
                outx = (sum((table[phase][k] * fifo[k]) >> 15 for k in range(4)) * o["adsr"]["value"]) >> 15
                ok = outx == o["outx"] and ((outx * i["volL"]) >> 15, (outx * i["volR"]) >> 15) == (o["outL"], o["outR"])
                st["spu voice output " + ("ok" if ok else "MISMATCH")] += 1
            if r["form"] in ("normal", "stopped", "noise"):
                nsp = sp + min(pitch, 0x3FFF)
                ok = (int(o["sp"], 16), o["decPosRead"]) == (nsp & 0xFFF, (i["decPosRead"] + (nsp >> 12)) & 0xFFFFFFFF)
                st["spu voice pitch " + ("ok" if ok else "MISMATCH")] += 1


def main():
    st = Counter()
    for arg in sys.argv[1:]:
        p = pathlib.Path(arg)
        files = sorted(p.glob("*.jsonl")) if p.is_dir() else [p]
        for f in files:
            if f.name in ("vu0_vectors.jsonl", "vu1_vectors.jsonl"):
                check_vu(f, st)
            elif f.name == "vif_vectors.jsonl":
                check_vif(f, st)
        folders = {f.parent for f in files if f.name.startswith("spu_") and f.name.endswith("_vectors.jsonl")}
        for folder in sorted(folders):
            check_spu(folder, st)
    for k in sorted(st):
        print(f"{st[k]:8}  {k}")
    return 1 if any("MISMATCH" in k for k in st) else 0


if __name__ == "__main__":
    sys.exit(main())

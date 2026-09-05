#!/usr/bin/env python3
"""Compare a native render against the emulated GS reference, at 640x448 only.

Usage: scripts/refdiff.py [--rect x0,y0,x1,y1] <base>   # <base>-emu.png vs <base>-native.ppm
       scripts/refdiff.py [--rect ...] <a.png|a.ppm> <b.ppm>
"""
import struct
import sys
import zlib

TILE = 32


def read_png(path):
    data = open(path, "rb").read()
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        raise SystemExit(f"{path}: not a PNG")
    w = h = depth = ctype = None
    idat = bytearray()
    at = 8
    while at < len(data):
        (length,) = struct.unpack(">I", data[at : at + 4])
        kind = data[at + 4 : at + 8]
        body = data[at + 8 : at + 8 + length]
        at += 12 + length
        if kind == b"IHDR":
            w, h, depth, ctype = struct.unpack(">IIBB", body[:10])
        elif kind == b"IDAT":
            idat += body
        elif kind == b"IEND":
            break
    if depth != 8 or ctype not in (2, 6):
        raise SystemExit(f"{path}: only 8-bit RGB/RGBA PNGs are supported (depth {depth} type {ctype})")
    nch = 3 if ctype == 2 else 4
    raw = zlib.decompress(bytes(idat))
    stride = w * nch
    out = bytearray(w * h * 3)
    prev = bytearray(stride)
    pos = 0
    for y in range(h):
        filt = raw[pos]
        pos += 1
        line = bytearray(raw[pos : pos + stride])
        pos += stride
        if filt == 1:
            for i in range(nch, stride):
                line[i] = (line[i] + line[i - nch]) & 0xFF
        elif filt == 2:
            for i in range(stride):
                line[i] = (line[i] + prev[i]) & 0xFF
        elif filt == 3:
            for i in range(stride):
                left = line[i - nch] if i >= nch else 0
                line[i] = (line[i] + ((left + prev[i]) >> 1)) & 0xFF
        elif filt == 4:
            for i in range(stride):
                a = line[i - nch] if i >= nch else 0
                b = prev[i]
                c = prev[i - nch] if i >= nch else 0
                p = a + b - c
                pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
                pred = a if (pa <= pb and pa <= pc) else (b if pb <= pc else c)
                line[i] = (line[i] + pred) & 0xFF
        elif filt != 0:
            raise SystemExit(f"{path}: bad row filter {filt}")
        prev = line
        for x in range(w):
            out[(y * w + x) * 3 : (y * w + x) * 3 + 3] = line[x * nch : x * nch + 3]
    return w, h, bytes(out)


def read_ppm(path):
    data = open(path, "rb").read()
    fields, at = [], 0
    while len(fields) < 4:
        while data[at : at + 1].isspace():
            at += 1
        if data[at : at + 1] == b"#":
            while data[at : at + 1] != b"\n":
                at += 1
            continue
        start = at
        while at < len(data) and not data[at : at + 1].isspace():
            at += 1
        fields.append(data[start:at])
    if fields[0] != b"P6":
        raise SystemExit(f"{path}: not a binary PPM")
    return int(fields[1]), int(fields[2]), data[at + 1 :]


def read_any(path):
    return read_ppm(path) if path.endswith(".ppm") else read_png(path)


def main():
    args = sys.argv[1:]
    rect = None
    if args and args[0] == "--rect":
        rect = [int(v) for v in args[1].split(",")]
        args = args[2:]
    if len(args) == 1:
        ref, ours = args[0] + "-emu.png", args[0] + "-native.ppm"
    elif len(args) == 2:
        ref, ours = args
    else:
        print(__doc__)
        return 2
    rw, rh, a = read_any(ref)
    ow, oh, b = read_ppm(ours)
    if (rw, rh) != (ow, oh):
        raise SystemExit(f"size mismatch: reference {rw}x{rh}, render {ow}x{oh}")
    x0, y0, x1, y1 = rect if rect else (0, 0, rw, rh)

    n = (x1 - x0) * (y1 - y0) * 3
    hist = [0] * 256
    signed = 0
    tiles = {}
    for y in range(y0, y1):
        for x in range(x0, x1):
            i = (y * rw + x) * 3
            t = (y // TILE, x // TILE)
            acc = tiles.setdefault(t, [0, 0])
            for c in range(3):
                d = b[i + c] - a[i + c]
                signed += d
                hist[abs(d)] += 1
                acc[0] += abs(d)
                acc[1] += 1

    total = sum(k * v for k, v in enumerate(hist))
    print(f"{ref}\n{ours}\n{rw}x{rh}" + (f" rect {x0},{y0}..{x1},{y1}" if rect else ""))
    print(f"  mean abs diff {total / n:.3f}   signed mean {signed / n:+.3f} (positive = ours brighter)")
    seen = 0
    for k, v in enumerate(hist):
        seen += v
        if seen * 2 >= n:
            print(f"  median abs diff {k}")
            break
    print(f"  exact {hist[0] * 100.0 / n:.1f}%   within 4 {sum(hist[:5]) * 100.0 / n:.1f}%   max {max(k for k, v in enumerate(hist) if v)}")
    worst = sorted(tiles.items(), key=lambda kv: -kv[1][0] / kv[1][1])[:8]
    print("  worst 32x32 tiles (y,x -> mean abs diff):")
    for (ty, tx), (s, c) in worst:
        print(f"    {ty * TILE:4d},{tx * TILE:4d}  {s / c:6.2f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

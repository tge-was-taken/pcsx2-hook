#!/usr/bin/env python3
"""Walk a capture's per-pass dumps, showing how a region builds up against the reference.

Usage: passdiff.py <capture-base> [x0 y0 x1 y1]

Each pass of a capture writes its target as an RGBA PNG (<base>-passNN.png) and the pass rows
name the file. A whole-frame mean says a scene is too dark; this says which pass made it so.
"""
import json
import os
import struct
import sys
import zlib


def read_png(path):
    """Returns (w, h, pixels, channels). Pass dumps are RGBA; the emu reference is RGB."""
    data = open(path, "rb").read()
    pos, idat, ctype = 8, b"", 2
    width = height = 0
    while pos < len(data):
        length = struct.unpack(">I", data[pos:pos + 4])[0]
        kind = data[pos + 4:pos + 8]
        chunk = data[pos + 8:pos + 8 + length]
        if kind == b"IHDR":
            width, height, _, ctype = struct.unpack(">IIBB", chunk[:10])
        elif kind == b"IDAT":
            idat += chunk
        pos += 12 + length
    raw = zlib.decompress(idat)
    bpp = 4 if ctype == 6 else 3
    stride = width * bpp
    out, prev, i = bytearray(), bytearray(stride), 0
    for _ in range(height):
        filt = raw[i]
        i += 1
        line = bytearray(raw[i:i + stride])
        i += stride
        for x in range(stride):
            a = line[x - bpp] if x >= bpp else 0
            b = prev[x]
            c = prev[x - bpp] if x >= bpp else 0
            if filt == 1:
                line[x] = (line[x] + a) & 255
            elif filt == 2:
                line[x] = (line[x] + b) & 255
            elif filt == 3:
                line[x] = (line[x] + (a + b) // 2) & 255
            elif filt == 4:
                p = a + b - c
                pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
                pred = a if (pa <= pb and pa <= pc) else (b if pb <= pc else c)
                line[x] = (line[x] + pred) & 255
        prev = line
        out += line
    return width, height, bytes(out), bpp


def region_mean(px, w, rect, stride_bytes):
    x0, y0, x1, y1 = rect
    total, n = [0, 0, 0, 0], 0
    for y in range(y0, y1):
        base = y * w
        for x in range(x0, x1):
            i = (base + x) * stride_bytes
            for k in range(min(4, stride_bytes)):
                total[k] += px[i + k]
            n += 1
    return [t / max(n, 1) for t in total]


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    base = sys.argv[1]
    rows = [json.loads(l) for l in open(base + "-manifest.jsonl")]
    passes = [r for r in rows if r.get("type") == "pass"]
    ref_path = base + "-emu.png"
    rect = None
    if len(sys.argv) >= 6:
        rect = tuple(int(v) for v in sys.argv[2:6])

    print(f"{'pass':>5} {'target':>9} {'size':>9} {'disp':>5} {'draws':>6}   "
          f"{'R':>7} {'G':>7} {'B':>7} {'A':>7}")
    for p in passes:
        if not p["dump"]:
            continue
        path = os.path.join(os.path.dirname(base) or ".",
                            os.path.basename(base) + "-" + p["dump"])
        if not os.path.exists(path):
            continue
        w, h, px, ch = read_png(path)
        r = rect or (0, 0, w, h)
        clipped = (max(0, r[0]), max(0, r[1]), min(w, r[2]), min(h, r[3]))
        m = region_mean(px, w, clipped, ch)
        # An off-screen target has its own pixel space, so a screen rect means nothing there. Print
        # the size and mark the row rather than quietly averaging its top-left corner.
        note = " (rect clipped)" if rect and clipped != tuple(rect) else ""
        print(f"{p['pass']:>5} {p['target'][-7:]:>9} {f'{w}x{h}':>9} {str(p['display']):>5} "
              f"{p['draws']:>6}   {m[0]:>7.1f} {m[1]:>7.1f} {m[2]:>7.1f} {m[3]:>7.1f}{note}")

    if os.path.exists(ref_path):
        w, h, px, ch = read_png(ref_path)
        r = rect or (0, 0, w, h)
        r = (max(0, r[0]), max(0, r[1]), min(w, r[2]), min(h, r[3]))
        m = region_mean(px, w, r, ch)
        print(f"{'EMU':>5} {'':>9} {f'{w}x{h}':>9} {'':>5} {'':>6}   "
              f"{m[0]:>7.1f} {m[1]:>7.1f} {m[2]:>7.1f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

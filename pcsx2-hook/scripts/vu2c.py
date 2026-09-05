#!/usr/bin/env python3
"""Translate the VU1 microprograms in a PCSX2HOOK_VU_TRACE dump into pseudo-C.

Instructions are decoded from the raw words, not from the disassembly text in the dump. The tables
mirror PCSX2's (DisVUmicro.h, VUops.cpp) and every operation follows its VU interpreter.
"""

USAGE = """usage: vu2c.py <vu1_programs.txt> [options]
  --list            one line per program, no code
  --all             translate every program (the default)
  --program HASH    translate this program (prefix of the dump's hash); repeatable
  --exec FILE       annotate from an execution trace: what never ran, branch counts, real targets
  --trace N         with --exec, print run N of each program in the order it executed
  --only-ran        with --exec, drop the instructions the trace never reached
  --mem FILE        substitute the quadwords a VU watch dump recorded into loads from them
  --instance N      which sample of that program to take the memory from (default 0)
  --split DIR       write one file per program into DIR, plus vu1_defs.h and an index
  --check           re-derive PCSX2's mnemonics from the decode and diff them against the dump
  --flow            print a branch as do/while or if where the shape is unambiguous
  --clean           fold vf00's constant lanes and ACC chains, inline branch conditions
  --keep-nops       keep instructions that do nothing
  --no-asm          drop the trailing mnemonic comments
  --no-addr         drop the address column
  --no-preamble     drop the header explaining the notation"""
import os
import re
import struct
import sys

VERSION = "1.0"  # bump when the emitted form changes

FIELDS = "xyzw"

# code & 0x3f, entries 0x3c-0x3f redirect to UPPER_FD[op & 3][(code >> 6) & 0x1f].
UPPER_MAIN = [
    "ADDx", "ADDy", "ADDz", "ADDw", "SUBx", "SUBy", "SUBz", "SUBw",
    "MADDx", "MADDy", "MADDz", "MADDw", "MSUBx", "MSUBy", "MSUBz", "MSUBw",
    "MAXx", "MAXy", "MAXz", "MAXw", "MINIx", "MINIy", "MINIz", "MINIw",
    "MULx", "MULy", "MULz", "MULw", "MULq", "MAXi", "MULi", "MINIi",
    "ADDq", "MADDq", "ADDi", "MADDi", "SUBq", "MSUBq", "SUBi", "MSUBi",
    "ADD", "MADD", "MUL", "MAX", "SUB", "MSUB", "OPMSUB", "MINI",
] + [None] * 12

UPPER_FD = [
    {0: "ADDAx", 1: "SUBAx", 2: "MADDAx", 3: "MSUBAx", 4: "ITOF0", 5: "FTOI0",
     6: "MULAx", 7: "MULAq", 8: "ADDAq", 9: "SUBAq", 10: "ADDA", 11: "SUBA"},
    {0: "ADDAy", 1: "SUBAy", 2: "MADDAy", 3: "MSUBAy", 4: "ITOF4", 5: "FTOI4",
     6: "MULAy", 7: "ABS", 8: "MADDAq", 9: "MSUBAq", 10: "MADDA", 11: "MSUBA"},
    {0: "ADDAz", 1: "SUBAz", 2: "MADDAz", 3: "MSUBAz", 4: "ITOF12", 5: "FTOI12",
     6: "MULAz", 7: "MULAi", 8: "ADDAi", 9: "SUBAi", 10: "MULA", 11: "OPMULA"},
    {0: "ADDAw", 1: "SUBAw", 2: "MADDAw", 3: "MSUBAw", 4: "ITOF15", 5: "FTOI15",
     6: "MULAw", 7: "CLIP", 8: "MADDAi", 9: "MSUBAi", 11: "NOP"},
]

# code >> 25, entry 0x40 redirects to LOWER_SPECIAL / LOWER_T3.
LOWER_MAIN = {
    0x00: "LQ", 0x01: "SQ", 0x04: "ILW", 0x05: "ISW", 0x08: "IADDIU", 0x09: "ISUBIU",
    0x10: "FCEQ", 0x11: "FCSET", 0x12: "FCAND", 0x13: "FCOR",
    0x14: "FSEQ", 0x15: "FSSET", 0x16: "FSAND", 0x17: "FSOR",
    0x18: "FMEQ", 0x1A: "FMAND", 0x1B: "FMOR", 0x1C: "FCGET",
    0x20: "B", 0x21: "BAL", 0x24: "JR", 0x25: "JALR", 0x28: "IBEQ", 0x29: "IBNE",
    0x2C: "IBLTZ", 0x2D: "IBGTZ", 0x2E: "IBLEZ", 0x2F: "IBGEZ",
}

LOWER_SPECIAL = {0x30: "IADD", 0x31: "ISUB", 0x32: "IADDI", 0x34: "IAND", 0x35: "IOR"}

LOWER_T3 = [
    {12: "MOVE", 13: "LQI", 14: "DIV", 15: "MTIR", 16: "RNEXT", 25: "MFP", 26: "XTOP",
     27: "XGKICK", 28: "ESADD", 29: "EATANxy", 30: "ESQRT", 31: "ESIN"},
    {12: "MR32", 13: "SQI", 14: "SQRT", 15: "MFIR", 16: "RGET", 26: "XITOP",
     28: "ERSADD", 29: "EATANxz", 30: "ERSQRT", 31: "EATAN"},
    {13: "LQD", 14: "RSQRT", 15: "ILWR", 16: "RINIT", 28: "ELENG", 29: "ESUM",
     30: "ERCPR", 31: "EEXP"},
    {13: "SQD", 14: "WAITQ", 15: "ISWR", 16: "RXOR", 28: "ERLENG", 30: "WAITP"},
]

# Lower ops whose mnemonic carries the field bits, and the names PCSX2's disassembler misspells.
DOTTED_LOWER = {"MOVE", "MFIR", "MTIR", "MR32", "LQ", "LQD", "LQI", "SQ", "SQD", "SQI",
                "ILW", "ISW", "ILWR", "ISWR", "RINIT", "RGET", "RNEXT", "RXOR", "MFP", "NOP"}
DIS_ALIAS = {"SUBAx": "SUBx", "SUBAy": "SUBy", "SUBAz": "SUBz", "SUBAw": "SUBw", "IBGEZ": "IBEZ"}

# VU1 micro memory is 16 KB, so a branch target wraps at 2048 instructions (PCSX2 masks the byte
# address with 0x3fff).
MICRO_MASK = 0x7FF

ARITH = re.compile(r"(ADD|SUB|MUL|MADD|MSUB|MAX|MINI)(A?)([xyzwiq]?)$")
ARITH_EXPR = {"ADD": "{a} + {b}", "SUB": "{a} - {b}", "MUL": "{a} * {b}",
              "MADD": "{acc} + {a} * {b}", "MSUB": "{acc} - {a} * {b}",
              "MAX": "max({a}, {b})", "MINI": "min({a}, {b})"}

BRANCH_COND = {"IBEQ": "{s} == {t}", "IBNE": "{s} != {t}", "IBLTZ": "{s} < 0",
               "IBGTZ": "{s} > 0", "IBLEZ": "{s} <= 0", "IBGEZ": "{s} >= 0"}
BRANCH_NOT = {"IBEQ": "{s} != {t}", "IBNE": "{s} == {t}", "IBLTZ": "{s} >= 0",
              "IBGTZ": "{s} <= 0", "IBLEZ": "{s} > 0", "IBGEZ": "{s} < 0"}

PREAMBLE = """\
/* Pseudo-C for VU1 microcode.  One statement per instruction.
 *
 *   vfNN         four 32-bit float lanes .x .y .z .w      viNN   16-bit integer, writes truncate
 *   ACC          upper-pipe accumulator                   I Q P R  immediate, divide, EFU, random
 *   mem[a]       VU1 data memory, quadword a              mem_w[a].x  the same word as an integer
 *   status mac clip    flag registers
 *
 *   as_float(v)      raw bit copy of an integer (MFIR, RGET), not a numeric conversion.  A value
 *                    read out of VU memory prints this way when the lane cannot be holding a
 *                    number: a denormal (the VU flushes those), an infinity, a NaN, or a magnitude
 *                    outside 1e-8 to 1e10.  Those lanes are packed fields, GIF tags among them.
 *   lo16(f)          low 16 bits of the float's bit pattern (MTIR), not a numeric conversion
 *   ftoiN(v)/itofN(v)  convert with N fraction bits; the result stays in the vf lane as raw bits,
 *                      which the macro below cannot express, so it carries the scale only
 *   mr32(v)          (v.y, v.z, v.w, v.x)
 *   opmul(a, b)      (a.y*b.z, a.z*b.x, a.x*b.y), the halves an OPMULA/OPMSUB pair crosses
 *   clip_bits(v, w)  x > w, x < -w, y > w, y < -w, z > w, z < -w, with w = |ft.w|
 *   xgkick(a)        start the GS packet transfer at mem[a]
 *   goto_micro(a)    jump to a micro address this file does not hold, and do not come back
 *
 * A statement reads all of its right side before it writes any lane, so a register that appears on
 * both sides means the value the instruction started with.  Both halves of a pair issue together and
 * read the register file as it stood before the pair, so where the lower half reads what the upper
 * half writes, the lower is printed first.  A branch takes effect after its delay slot, so the
 * condition is captured at the branch and the goto is printed after the delay-slot statements.
 *
 * The declarations below are here so an editor can parse the file.  Nothing is meant to link or
 * run: the helpers have no definitions, and a swizzle is declared as one float rather than as the
 * lanes it names, which is all a parser needs and keeps the file inside plain C.
 */
#include <stdbool.h>

typedef union {
    struct { float x, y, z, w; };
    float xy, xz, xw, yz, yw, zw, xyz, xyw, xzw, yzw, xyzw;
} vec4;

typedef union {
    struct { int x, y, z, w; };
    int xy, xz, xw, yz, yw, zw, xyz, xyw, xzw, yzw, xyzw;
} ivec4;

vec4 vf00, vf01, vf02, vf03, vf04, vf05, vf06, vf07, vf08, vf09, vf10, vf11, vf12, vf13, vf14, vf15;
vec4 vf16, vf17, vf18, vf19, vf20, vf21, vf22, vf23, vf24, vf25, vf26, vf27, vf28, vf29, vf30, vf31;
vec4 ACC;
int vi00, vi01, vi02, vi03, vi04, vi05, vi06, vi07, vi08, vi09, vi10, vi11, vi12, vi13, vi14, vi15;
float I, Q, P;
unsigned R, status, mac, clip;
int VIF1_TOP, VIF1_ITOP;
union { vec4 f[1024]; ivec4 w[1024]; } vu_mem;

#define mem vu_mem.f
#define mem_w vu_mem.w

float max(float a, float b), min(float a, float b), fabsf(float v), sqrtf(float v);
float ftoi0(float v), ftoi4(float v), ftoi12(float v), ftoi15(float v);
float itof0(float v), itof4(float v), itof12(float v), itof15(float v);
float as_float(int raw), opmul(vec4 a, vec4 b);
vec4 mr32(vec4 v);
int lo16(float v);
unsigned bits(float v), clip_bits(float v, float w), lfsr_next(unsigned r);
float esin(float v), eatan(float v), eexp(float v), eatan2(float a, float b);
float vec2f(float x, float y), vec3f(float x, float y, float z);
float vec4f(float x, float y, float z, float w);
void xgkick(int addr), goto_micro(int addr);
"""


def vf(n):
    return "vf%02d" % n


def vi(n):
    return "vi%02d" % n


def sw(reg, mask):
    return "%s.%s" % (reg, mask)


class Fields:
    def __init__(self, code):
        self.code = code
        self.ft = (code >> 16) & 0x1F
        self.fs = (code >> 11) & 0x1F
        self.fd = (code >> 6) & 0x1F
        self.it = self.ft & 15
        self.is_ = self.fs & 15
        self.id_ = self.fd & 15
        self.fsf = FIELDS[(code >> 21) & 3]
        self.ftf = FIELDS[(code >> 23) & 3]
        self.mask = "".join(c for i, c in enumerate(FIELDS) if (code >> (24 - i)) & 1)
        imm5 = (code >> 6) & 0x1F
        self.imm5 = imm5 - 32 if imm5 & 0x10 else imm5
        self.imm11 = (code & 0x3FF) - 1024 if code & 0x400 else code & 0x3FF
        self.imm15 = ((code >> 10) & 0x7800) | (code & 0x7FF)
        self.imm12 = (((code >> 21) & 1) << 11) | (code & 0x7FF)
        self.imm24 = code & 0xFFFFFF


def decode_upper(code):
    op = code & 0x3F
    if op < 0x3C:
        return UPPER_MAIN[op]
    return UPPER_FD[op & 3].get((code >> 6) & 0x1F)


def decode_lower(code):
    op = code >> 25
    if op != 0x40:
        return LOWER_MAIN.get(op)
    sub = code & 0x3F
    if sub < 0x3C:
        return LOWER_SPECIAL.get(sub)
    name = LOWER_T3[sub & 3].get((code >> 6) & 0x1F)
    if name == "MOVE" and ((code >> 16) & 0x1F) == 0 and ((code >> 11) & 0x1F) == 0:
        return "NOP"
    return name


def mnemonic(name, f, upper, dis=False):
    """The instruction's name; dis spells it as PCSX2 does, for cross-checking against the dump."""
    if not name:
        return "?"
    if dis:
        name = DIS_ALIAS.get(name, name)
    dotted = name != "NOP" if upper else name in DOTTED_LOWER
    return "%s.%s" % (name, f.mask) if dotted else name


def addr_expr(reg, imm=0):
    if reg == 0:
        return str(imm)
    if imm == 0:
        return vi(reg)
    return "%s %s %d" % (vi(reg), "+" if imm > 0 else "-", abs(imm))


def vf00_const(operand):
    """The constant an operand names when it is lanes of vf00, which reads as (0, 0, 0, 1)."""
    if not operand.startswith("vf00."):
        return None
    values = {1.0 if c == "w" else 0.0 for c in operand.split(".", 1)[1]}
    return values.pop() if len(values) == 1 else None


def fold_term(a, b):
    """`a * b` with vf00's lanes folded out, or None when the product is zero."""
    ca, cb = vf00_const(a), vf00_const(b)
    if ca == 0.0 or cb == 0.0:
        return None
    if cb == 1.0:
        return a
    if ca == 1.0:
        return b
    return "%s * %s" % (a, b)


def fold_arith(base, a, b, acc):
    """The expression with vf00 folded out, or None to keep it as written."""
    ca, cb = vf00_const(a), vf00_const(b)
    product = "%s * %s" % (a, b)
    if base in ("ADD", "SUB"):
        if ca is not None and cb is not None:
            return "%.1ff" % (ca + cb if base == "ADD" else ca - cb)
        if cb == 0.0:
            return a
        if ca == 0.0:
            return b if base == "ADD" else "-%s" % b
    elif base == "MUL":
        term = fold_term(a, b)
        if term is None:
            return "0.0f"
        if term != product:
            return term
    elif base in ("MADD", "MSUB"):
        term = fold_term(a, b)
        if term is None:
            return acc
        if term != product:
            return "%s %s %s" % (acc, "+" if base == "MADD" else "-", term)
    return None


READ_OPERAND = re.compile(r"(vf\d\d)\.([xyzw]+)")


def subst_reads(text, known):
    """Replace register reads whose lanes are all known with the value they hold."""
    if " = " not in text:
        return text
    lhs, rhs = text.split(" = ", 1)

    def swap(m):
        lanes = known.get(m.group(1), {})
        if not all(c in lanes for c in m.group(2)):
            return m.group(0)
        text = lanes_literal([lanes.get(c, 0) for c in FIELDS], m.group(2))
        # A negative literal can land after a unary minus or another operator.
        return "(%s)" % text if text.startswith("-") else text

    return lhs + " = " + READ_OPERAND.sub(swap, rhs)


def render_upper(name, f, clean=False):
    """(statements, reads, writes) for the upper half."""
    if not name:
        return ["/* undefined upper opcode 0x%08x */" % f.code], set(), set()
    if not f.mask and name not in ("CLIP", "OPMULA", "OPMSUB", "NOP"):
        return ["/* %s writes no fields */" % name], set(), set()
    m = ARITH.match(name)
    if m:
        base, acc, bc = m.groups()
        dst = "ACC" if acc else vf(f.fd)
        a = sw(vf(f.fs), f.mask)
        if bc == "i":
            b = "I"
        elif bc == "q":
            b = "Q"
        elif bc:
            b = "%s.%s" % (vf(f.ft), bc)
        else:
            b = sw(vf(f.ft), f.mask)
        expr = ARITH_EXPR[base].format(a=a, b=b, acc=sw("ACC", f.mask))
        if clean:
            expr = fold_arith(base, a, b, sw("ACC", f.mask)) or expr
        reads = {vf(f.fs), b.split(".")[0]}
        if base in ("MADD", "MSUB"):
            reads.add("ACC")
        return ["%s = %s;" % (sw(dst, f.mask), expr)], reads, {dst}
    if name == "ABS":
        return (["%s = fabsf(%s);" % (sw(vf(f.ft), f.mask), sw(vf(f.fs), f.mask))],
                {vf(f.fs)}, {vf(f.ft)})
    if name.startswith("FTOI") or name.startswith("ITOF"):
        conv = name.lower()
        return (["%s = %s(%s);" % (sw(vf(f.ft), f.mask), conv, sw(vf(f.fs), f.mask))],
                {vf(f.fs)}, {vf(f.ft)})
    if name == "CLIP":
        return (["clip = (clip << 6) | clip_bits(%s.xyz, %s.w);" % (vf(f.fs), vf(f.ft))],
                {vf(f.fs), vf(f.ft)}, {"clip"})
    if name == "OPMULA":
        return (["ACC.xyz = opmul(%s, %s);" % (vf(f.fs), vf(f.ft))],
                {vf(f.fs), vf(f.ft)}, {"ACC"})
    if name == "OPMSUB":
        return (["%s.xyz = ACC.xyz - opmul(%s, %s);" % (vf(f.fd), vf(f.fs), vf(f.ft))],
                {vf(f.fs), vf(f.ft), "ACC"}, {vf(f.fd)})
    return [], set(), set()


# A lane outside this range is a packed field rather than a number: VU geometry does not compute
# with magnitudes this small or this large.
FLOAT_RANGE = (1e-8, 1e10)


def fnum(bits):
    """A float32 word as a C literal, or its bit pattern when the lane is not holding a number.

    A denormal cannot be one: the VU flushes denormals to zero, so no arithmetic reads it. Nor can
    an infinity, a NaN, or a magnitude outside FLOAT_RANGE. Those print through as_float, which is
    the same bit copy MFIR does.
    """
    value = struct.unpack("<f", struct.pack("<I", bits))[0]
    exponent, magnitude = bits & 0x7F800000, abs(value)
    if not exponent and bits & 0x007FFFFF:
        return "as_float(%d)" % (bits & 0x007FFFFF)
    if exponent == 0x7F800000 or (magnitude and not FLOAT_RANGE[0] <= magnitude < FLOAT_RANGE[1]):
        return "as_float(0x%08X)" % bits
    text = "%.9g" % value
    return text + ("f" if "." in text or "e" in text else ".0f")


GIF_REGS = ["PRIM", "RGBAQ", "ST", "UV", "XYZF2", "XYZ2", "TEX0_1", "TEX0_2",
            "CLAMP_1", "CLAMP_2", "FOG", "?", "XYZF3", "XYZ3", "A+D", "NOP"]
GIF_FLG = ["PACKED", "REGLIST", "IMAGE", "DISABLE"]
GIF_PRIM = ["POINT", "LINE", "LINESTRIP", "TRI", "TRISTRIP", "TRIFAN", "SPRITE", "?"]
GIF_PRIM_BITS = ["IIP", "TME", "FGE", "ABE", "AA1", "FST", "CTXT", "FIX"]


def gif_tag(words):
    """The GIF tag a quadword holds, or None when the bits cannot be one.

    Both pad fields have to be zero and every named register has to be a real one, which is 30 bits
    of structure; a quadword of geometry does not pass by accident.
    """
    w0, w1, w2, w3 = words
    if w0 >> 16 or w1 & 0x3FFF:
        return None
    nloop, eop = w0 & 0x7FFF, (w0 >> 15) & 1
    pre, prim, flg, nreg = (w1 >> 14) & 1, (w1 >> 15) & 0x7FF, (w1 >> 26) & 3, (w1 >> 28) & 15
    regs = [(w2 >> (4 * i)) & 15 for i in range(8)] + [(w3 >> (4 * i)) & 15 for i in range(8)]
    used = regs[:nreg or 16]
    # A packet writes PRIM at most once, so a repeat means the quadword is a counter, not a tag.
    if not nloop or 0x0B in used or (flg != 2 and used.count(0x00) > 1):
        return None
    out = ["GIFtag NLOOP=%d" % nloop]
    if eop:
        out.append("EOP")
    if pre:
        flags = [n for i, n in enumerate(GIF_PRIM_BITS) if prim >> (i + 3) & 1]
        out.append("PRIM=%s" % "|".join([GIF_PRIM[prim & 7]] + flags))
    out.append("FLG=%s" % GIF_FLG[flg])
    if flg != 2:
        out.append("NREG=%d REGS=%s" % (nreg or 16, ",".join(GIF_REGS[r] for r in used)))
    return " ".join(out)


def lanes_literal(lanes, mask):
    values = ", ".join(fnum(lanes[FIELDS.index(c)]) for c in mask)
    return values if len(mask) == 1 else "vec%df(%s)" % (len(mask), values)


def render_lower(name, f, consts=None):
    """(statements, reads, writes) for a lower half that is not control flow."""
    dst_f, src_f = vf(f.ft), vf(f.fs)
    mask, out, reads, writes = f.mask, [], set(), set()
    consts = consts or {}

    def rw(r=(), w=()):
        reads.update(r)
        writes.update(w)

    if name in ("LQ", "LQI", "LQD"):
        if name == "LQ":
            addr = addr_expr(f.is_, f.imm11)
        else:
            addr = vi(f.is_)
            if name == "LQD":
                out.append("--%s;" % addr)
        if f.ft and mask:
            known = consts.get(f.imm11) if name == "LQ" and f.is_ == 0 else None
            if known and set(mask) & known[2]:
                known = None
            out.append("%s = %s;%s" % (sw(dst_f, mask),
                                       lanes_literal(known[0], mask) if known
                                       else sw("mem[%s]" % addr, mask),
                                       "  /* mem[%d]%s */"
                                       % (f.imm11, ", GIF tag" if gif_tag(known[0]) else "")
                                       if known else ""))
        if name == "LQI" and f.is_:
            out.append("%s++;" % vi(f.is_))
        rw({vi(f.is_), "mem"}, {dst_f} | ({vi(f.is_)} if name != "LQ" else set()))
    elif name in ("SQ", "SQI", "SQD"):
        if name == "SQ":
            addr = addr_expr(f.it, f.imm11)
        else:
            addr = vi(f.it)
            if name == "SQD":
                out.append("--%s;" % addr)
        if mask:
            out.append("%s = %s;" % (sw("mem[%s]" % addr, mask), sw(src_f, mask)))
        if name == "SQI" and f.ft:
            out.append("%s++;" % vi(f.it))
        rw({src_f, vi(f.it)}, {"mem"} | ({vi(f.it)} if name != "SQ" else set()))
    elif name in ("ILW", "ILWR"):
        addr = addr_expr(f.is_, f.imm11) if name == "ILW" else vi(f.is_)
        if mask:
            known = consts.get(f.imm11) if name == "ILW" and f.is_ == 0 else None
            if known and mask[-1] in known[2]:
                known = None
            out.append("%s = %s;%s" % (vi(f.it),
                "%d" % (known[0][FIELDS.index(mask[-1])] & 0xFFFF)
                if known else "mem_w[%s].%s" % (addr, mask[-1]),
                "  /* mem[%d].%s */" % (f.imm11, mask[-1]) if known else ""))
        rw({vi(f.is_), "mem"}, {vi(f.it)})
    elif name in ("ISW", "ISWR"):
        addr = addr_expr(f.is_, f.imm11) if name == "ISW" else vi(f.is_)
        for c in mask:
            out.append("mem_w[%s].%s = %s;" % (addr, c, vi(f.it)))
        rw({vi(f.is_), vi(f.it)}, {"mem"})
    elif name in ("IADD", "ISUB", "IAND", "IOR"):
        op = {"IADD": "+", "ISUB": "-", "IAND": "&", "IOR": "|"}[name]
        if name == "IAND" and not (f.is_ and f.it):
            expr = "0"
        elif not f.is_ and name in ("IADD", "IOR"):
            expr = vi(f.it)
        elif not f.it and name in ("IADD", "ISUB", "IOR"):
            expr = vi(f.is_)
        else:
            expr = "%s %s %s" % (vi(f.is_), op, vi(f.it))
        out.append("%s = %s;" % (vi(f.id_), expr))
        rw({vi(f.is_), vi(f.it)}, {vi(f.id_)})
    elif name in ("IADDI", "IADDIU", "ISUBIU"):
        imm = f.imm5 if name == "IADDI" else f.imm15
        if name == "ISUBIU":
            imm = -imm
        if f.is_ == 0:
            out.append("%s = %d;" % (vi(f.it), imm))
        elif imm == 0:
            out.append("%s = %s;" % (vi(f.it), vi(f.is_)))
        else:
            out.append("%s = %s %s %d;" % (vi(f.it), vi(f.is_), "+" if imm > 0 else "-", abs(imm)))
        rw({vi(f.is_)}, {vi(f.it)})
    elif name == "MOVE":
        if mask:
            out.append("%s = %s;" % (sw(dst_f, mask), sw(src_f, mask)))
        rw({src_f}, {dst_f})
    elif name == "MR32":
        if not mask:
            pass
        elif len(mask) == 1:
            out.append("%s.%s = %s.%s;" % (dst_f, mask, src_f, FIELDS[(FIELDS.index(mask) + 1) % 4]))
        else:
            out.append("%s = %s;" % (sw(dst_f, mask), sw("mr32(%s)" % src_f, mask)))
        rw({src_f}, {dst_f})
    elif name == "MFIR":
        if mask:
            out.append("%s = as_float(%s);" % (sw(dst_f, mask), vi(f.is_)))
        rw({vi(f.is_)}, {dst_f})
    elif name == "MTIR":
        out.append("%s = lo16(%s.%s);" % (vi(f.it), src_f, f.fsf))
        rw({src_f}, {vi(f.it)})
    elif name == "MFP":
        if mask:
            out.append("%s = P;" % sw(dst_f, mask))
        rw({"P"}, {dst_f})
    elif name == "DIV":
        out.append("Q = %s.%s / %s.%s;" % (src_f, f.fsf, dst_f, f.ftf))
        rw({src_f, dst_f}, {"Q"})
    elif name == "SQRT":
        out.append("Q = sqrtf(fabsf(%s.%s));" % (dst_f, f.ftf))
        rw({dst_f}, {"Q"})
    elif name == "RSQRT":
        out.append("Q = %s.%s / sqrtf(fabsf(%s.%s));" % (src_f, f.fsf, dst_f, f.ftf))
        rw({src_f, dst_f}, {"Q"})
    elif name in ("WAITQ", "WAITP"):
        out.append("/* %s */" % name)
    elif name in ("ESADD", "ERSADD", "ELENG", "ERLENG", "ESUM"):
        s = src_f
        sq = "%s.x * %s.x + %s.y * %s.y + %s.z * %s.z" % (s, s, s, s, s, s)
        expr = {"ESADD": sq,
                "ERSADD": "1.0f / (%s)" % sq,
                "ELENG": "sqrtf(%s)" % sq,
                "ERLENG": "1.0f / sqrtf(%s)" % sq,
                "ESUM": "%s.x + %s.y + %s.z + %s.w" % (s, s, s, s)}[name]
        out.append("P = %s;" % expr)
        rw({s}, {"P"})
    elif name in ("ERCPR", "ESQRT", "ERSQRT", "ESIN", "EATAN", "EEXP"):
        expr = {"ERCPR": "1.0f / %s.%s", "ESQRT": "sqrtf(%s.%s)",
                "ERSQRT": "1.0f / sqrtf(%s.%s)", "ESIN": "esin(%s.%s)",
                "EATAN": "eatan(%s.%s)", "EEXP": "eexp(%s.%s)"}[name]
        out.append("P = %s;" % (expr % (src_f, f.fsf)))
        rw({src_f}, {"P"})
    elif name in ("EATANxy", "EATANxz"):
        c = name[-2:]
        out.append("P = eatan2(%s.%s, %s.%s);" % (src_f, c[1], src_f, c[0]))
        rw({src_f}, {"P"})
    elif name == "RINIT":
        out.append("R = 0x3f800000 | (bits(%s.%s) & 0x7fffff);" % (src_f, f.fsf))
        rw({src_f}, {"R"})
    elif name == "RXOR":
        out.append("R = 0x3f800000 | ((R ^ bits(%s.%s)) & 0x7fffff);" % (src_f, f.fsf))
        rw({src_f, "R"}, {"R"})
    elif name in ("RGET", "RNEXT"):
        if name == "RNEXT":
            out.append("R = lfsr_next(R);")
        if mask:
            out.append("%s = as_float(R);" % sw(dst_f, mask))
        rw({"R"}, {dst_f, "R"})
    elif name == "FCAND":
        out.append("vi01 = (clip & 0x%06x) != 0;" % f.imm24)
        rw({"clip"}, {"vi01"})
    elif name == "FCEQ":
        out.append("vi01 = (clip & 0xffffff) == 0x%06x;" % f.imm24)
        rw({"clip"}, {"vi01"})
    elif name == "FCOR":
        out.append("vi01 = (clip | 0x%06x) == 0xffffff;" % f.imm24)
        rw({"clip"}, {"vi01"})
    elif name == "FCSET":
        out.append("clip = 0x%06x;" % f.imm24)
        rw((), {"clip"})
    elif name == "FCGET":
        out.append("%s = clip & 0xfff;" % vi(f.it))
        rw({"clip"}, {vi(f.it)})
    elif name in ("FSAND", "FSEQ", "FSOR"):
        expr = {"FSAND": "(status & 0xfff) & 0x%03x", "FSEQ": "(status & 0xfff) == 0x%03x",
                "FSOR": "(status & 0xfff) | 0x%03x"}[name]
        out.append("%s = %s;" % (vi(f.it), expr % f.imm12))
        rw({"status"}, {vi(f.it)})
    elif name == "FSSET":
        out.append("status = (status & 0x3f) | 0x%03x;" % (f.imm12 & 0xFC0))
        rw((), {"status"})
    elif name in ("FMAND", "FMEQ", "FMOR"):
        expr = {"FMAND": "%s & (mac & 0xffff)", "FMEQ": "(mac & 0xffff) == %s",
                "FMOR": "%s | (mac & 0xffff)"}[name]
        out.append("%s = %s;" % (vi(f.it), expr % vi(f.is_)))
        rw({"mac", vi(f.is_)}, {vi(f.it)})
    elif name in ("XTOP", "XITOP"):
        out.append("%s = VIF1_%s;" % (vi(f.it), "TOP" if name == "XTOP" else "ITOP"))
        rw((), {vi(f.it)})
    elif name == "XGKICK":
        out.append("xgkick(%s);" % vi(f.is_))
        rw({vi(f.is_), "mem"}, {"GS"})
    elif name == "NOP":
        pass
    else:
        out.append("/* undefined lower opcode 0x%08x */" % f.code)
    return out, reads, writes


class Ins:
    def __init__(self, addr, upper, lower):
        self.addr = addr
        self.upper_word = upper
        self.lower_word = lower
        self.uf = Fields(upper)
        self.uname = decode_upper(upper)
        self.ibit = bool(upper & (1 << 31))
        self.ebit = bool(upper & (1 << 30))
        self.lf = Fields(lower)
        self.lname = "LOI" if self.ibit else decode_lower(lower)
        self.branch = self.lname in BRANCH_COND or self.lname in ("B", "BAL", "JR", "JALR")
        self.target = None
        if self.lname in BRANCH_COND or self.lname in ("B", "BAL"):
            self.target = (addr + 1 + self.lf.imm11) & MICRO_MASK

    def reads_writes(self):
        reads, writes = render_upper(self.uname, self.uf)[1:]
        if self.ibit:
            return reads, writes | {"I"}
        lr, lw = branch_regs(self) if self.branch else render_lower(self.lname, self.lf)[1:]
        # vf00 and vi00 are constants: naming one as a destination discards the result.
        return reads | set(lr), (writes | set(lw)) - {"vf00", "vi00"}


def branch_regs(ins):
    """(reads, writes) for a control-flow lower half."""
    f, name = ins.lf, ins.lname
    if name in BRANCH_COND:
        return {vi(f.is_), vi(f.it)}, set()
    reads = {vi(f.is_)} if name in ("JR", "JALR") else set()
    writes = {vi(f.it)} if name in ("BAL", "JALR") and f.it else set()
    return reads, writes


def branch_parts(ins, negate=False):
    """(condition, link statement, target statement) for a control-flow lower half."""
    f, name = ins.lf, ins.lname
    cond = link = None
    if name in BRANCH_COND:
        table = BRANCH_NOT if negate else BRANCH_COND
        cond = table[name].format(s=vi(f.is_), t=vi(f.it))
    if name in ("BAL", "JALR") and f.it:
        link = "%s = 0x%04X;" % (vi(f.it), ins.addr + 2)
    if name in ("JR", "JALR"):
        target = "goto_micro(%s);" % vi(f.is_)
    else:
        target = "goto L_%04X;" % ins.target
    return cond, link, target


def pair_statements(ins, opts, upper=None):
    """The pair's statements in an order that keeps the read-before-write semantics."""
    ustmts, ureads, uwrites = render_upper(ins.uname, ins.uf, opts["clean"])
    if upper is not None:
        ustmts = [upper] if upper else []
    if ins.ibit:
        lstmts = ["I = %s;" % fnum(ins.lower_word)]
        lreads, lwrites = set(), {"I"}
    elif ins.branch:
        lstmts, lreads, lwrites = [], set(), set()
    else:
        lstmts, lreads, lwrites = render_lower(ins.lname, ins.lf, opts.get("consts"))
    notes = []
    uwrites, lwrites = uwrites - {"vf00"}, lwrites - {"vf00"}
    swap = bool(uwrites & lreads)
    if swap and (lwrites & ureads):
        notes.append("both halves overwrite what the other reads")
    elif uwrites & lwrites:
        notes.append("both halves write %s" % ", ".join(sorted(uwrites & lwrites)))
    out = []
    if swap:
        out += [(s, mnemonic(ins.lname, ins.lf, False)) for s in lstmts]
        out += [(s, mnemonic(ins.uname, ins.uf, True)) for s in ustmts]
    else:
        out += [(s, mnemonic(ins.uname, ins.uf, True)) for s in ustmts]
        out += [(s, mnemonic(ins.lname, ins.lf, False)) for s in lstmts]
    if not out and opts["nops"]:
        out = [("/* nop */", None)]
    return out, notes


def plural(count, word):
    return "%d %s%s" % (count, word, "" if count == 1 else "s")


def dead_ranges(code, ran):
    """{first address: last address} for each run of instructions the trace never reached."""
    ranges, start = {}, None
    for ins in code + [None]:
        if ins is not None and not ran["count"].get(ins.addr):
            start = ins.addr if start is None else start
            last = ins.addr
        elif start is not None:
            if last > start:
                ranges[start] = last
            start = None
    return ranges


def label_line(addr, sources):
    if not sources:
        return "L_%04X:" % addr
    return "L_%04X:  /* from %s */" % (addr, ", ".join("%04X" % a for a in sorted(sources)))


def emit_line(ins, text, mnem, indent, opts, head=True, note=None):
    """One output line: `/* addr upper lower mnemonic */ statement // note`."""
    if not opts["addr"]:
        prefix = ""
    elif not opts["asm"]:
        prefix = "/* %04X */ " % ins.addr if head else " " * 11
    elif head:
        prefix = "/* %04X %08X %08X %-11s */ " % (ins.addr, ins.upper_word, ins.lower_word,
                                                  mnem or "")
    else:
        prefix = "/* %s%-11s */ " % (" " * 23, mnem or "")
    line = "%s%s%s" % (prefix, " " * indent, text)
    if note:
        line = "%-78s // %s" % (line, note)
    return line.rstrip()


def chain_expr(chain, labels):
    """One expression for a run of ACC writes ending in a vf write, or None if that would lie."""
    mask = chain[0].uf.mask
    if any(c.uf.mask != mask for c in chain) or any(c.addr in labels for c in chain[1:]):
        return None
    if any(c.ebit for c in chain[:-1]):
        return None
    reads, writes = set(), set()
    for c in chain:
        reads |= render_upper(c.uname, c.uf)[1]
        writes |= render_lower(c.lname, c.lf)[2]
    dst = vf(chain[-1].uf.fd)
    if (reads | {dst}) & writes:  # an interleaved lower half moves one of the inputs
        return None
    parts = []
    for n, c in enumerate(chain):
        base, _, bc = ARITH.match(c.uname).groups()
        a = sw(vf(c.uf.fs), mask)
        b = {"i": "I", "q": "Q"}.get(bc) or ("%s.%s" % (vf(c.uf.ft), bc) if bc
                                             else sw(vf(c.uf.ft), mask))
        if n == 0 and base in ("ADD", "SUB"):
            parts += [("+", a), ("+" if base == "ADD" else "-", b)]
            continue
        term = fold_term(a, b)
        if term is None:
            if n == 0:
                parts.append(("+", "0.0f"))
        else:
            parts.append(("+" if base in ("MUL", "MADD") else "-", term))
    if len(parts) > 1 and parts[0][1] == "0.0f":
        parts.pop(0)
    if not parts:
        return None
    text = parts[0][1] if parts[0][0] == "+" else "-" + parts[0][1]
    for sign, term in parts[1:]:
        text += " %s %s" % (sign, term)
    return "%s = %s;" % (sw(dst, mask), text)


def acc_chains(code, labels):
    """{last address: (first address, statement)} and the addresses it folds away."""
    folds, dropped, run = {}, set(), []
    for ins in code:
        m = ARITH.match(ins.uname or "")
        usable = m and not ins.branch and not ins.ibit
        if usable and m.group(2):
            run = [ins] if m.group(1) in ("MUL", "ADD", "SUB") else run + [ins]
            continue
        if usable and run and m.group(1) in ("MADD", "MSUB"):
            chain = run + [ins]
            expr = chain_expr(chain, labels)
            if expr:
                folds[ins.addr] = (chain[0].addr, expr)
                dropped.update(c.addr for c in chain[:-1])
        run = []
    return folds, dropped


def flow_ranges(code, here, targets):
    """Ranges a branch can print as do/while or if, and the branches that are loop exits."""
    labels, branches = set(targets), {ins.addr for ins in code if ins.branch}
    cands = []
    for ins in code:
        if ins.lname not in BRANCH_COND or ins.target not in here:
            continue
        t, b = ins.target, ins.addr
        if t <= b:
            # The loop body runs from the branch target through the delay slot, entered by falling in.
            if targets.count(t) == 1 and not (labels & set(range(t + 1, b + 2))) \
                    and t - 1 not in branches:
                cands.append((t, b + 1, "do", b))
        elif t > b + 2:
            # The instructions the branch skips over become the body of an if.
            if not (labels & set(range(b + 2, t))) and b + 1 not in branches \
                    and t - 1 not in branches and b + 1 not in labels:
                cands.append((b + 2, t - 1, "if", b))
    cands.sort(key=lambda r: (r[0], -r[1], r[2] != "do"))
    kept, stack = [], []
    for r in cands:
        while stack and stack[-1][1] < r[0]:
            stack.pop()
        if stack and (r[1] > stack[-1][1] or (r[1] == stack[-1][1] and stack[-1][2] == "do")):
            continue  # it crosses the block it starts inside, so neither shape holds
        stack.append(r)
        kept.append(r)

    loops = [r for r in kept if r[2] == "do"]
    breaks = {}
    for ins in code:
        if ins.lname not in BRANCH_COND or ins.target not in here:
            continue
        inside = [r for r in loops if r[0] <= ins.addr < r[3]]
        if inside:
            loop = max(inside, key=lambda r: r[0])
            if ins.target == loop[1] + 1:  # the branch lands just past the loop
                breaks[ins.addr] = loop
    return [r for r in kept if not (r[2] == "if" and r[3] in breaks)], breaks


def elsewhere(addr, prog, others):
    """The other translated programs whose image covers an address, and whether they agree."""
    covering = [q for q in others
                if q["hash"] != prog["hash"] and q["base"] <= addr < q["base"] + len(q["ins"])]
    if not covering:
        return []
    windows = {tuple(q["ins"][addr - q["base"]:addr - q["base"] + 16][k][:2]
                     for k in range(min(16, len(q["ins"]) - (addr - q["base"])))): q
               for q in covering}
    names = ["vu1_%s" % q["hash"][:8].lower() for q in covering]
    return [names, "the same code in each" if len(windows) == 1 else "each holding different code"]


def dispatch_table(code, base):
    """{jump address: (register, candidate targets, where they are set, table reads)}.

    A dynamic jump reads a register, so the candidates are every constant the program ever puts in
    that register which is also an address inside it. That over-approximates, which is why the
    listing calls them candidates.
    """
    found = {}
    for ins in code:
        if ins.lname not in ("JR", "JALR"):
            continue
        reg = vi(ins.lf.is_)
        targets, written, reads = set(), [], []
        for other in code:
            if other.lname in ("IADDIU", "IADDI") and other.lf.is_ == 0 \
                    and vi(other.lf.it) == reg:
                value = other.lf.imm15 if other.lname == "IADDIU" else other.lf.imm5
                if base <= value < base + len(code):
                    targets.add(value)
                    written.append(other.addr)
            elif other.lname in ("ILW", "ILWR") and vi(other.lf.it) == reg:
                reads.append(other.addr)
        found[ins.addr] = (reg, sorted(targets), written, reads)
    return found


def translate(prog, others, opts):
    code = [Ins(prog["base"] + i, u, l) for i, (u, l, _) in enumerate(prog["ins"])]
    # A quadword the program stores to is not the one the sample recorded.
    stored = {}
    for ins in code:
        if ins.ibit:
            continue
        if ins.lname == "SQ" and ins.lf.it == 0:
            stored.setdefault(ins.lf.imm11, set()).update(ins.lf.mask)
        elif ins.lname == "ISW" and ins.lf.is_ == 0:
            stored.setdefault(ins.lf.imm11, set()).update(ins.lf.mask)
    consts = {addr: (lanes, distinct, stored.get(addr, set()))
              for addr, (lanes, distinct) in
              watch_consts(opts["watch"].get(prog["hash"], []), opts["instance"]).items()} \
        if opts["watch"] else {}
    opts = dict(opts, consts=consts)
    here = {ins.addr for ins in code}
    targets = [ins.target for ins in code if ins.target in here]
    ranges, breaks = flow_ranges(code, here, targets) if opts["flow"] else ([], {})
    ran = lookup_runs(prog, opts["runs"]) if opts["runs"] else None
    slicing = bool(ran and opts["only_ran"])
    if slicing:
        # A block with both ends unexecuted goes whole, so its braces cannot come apart.
        ranges = [r for r in ranges if ran["count"].get(r[0]) or ran["count"].get(r[3])]
        breaks = {a: r for a, r in breaks.items() if ran["count"].get(a)}
    shaped = {r[3]: r for r in ranges}
    opens, closes = {}, {}
    for r in ranges:  # nested blocks can share an address, so count them
        side = opens if r[2] == "do" else closes
        side[r[0] if r[2] == "do" else r[1]] = side.get(r[0] if r[2] == "do" else r[1], 0) + 1
    def jumps(ins):
        """Whether this branch still prints a goto, so its target still needs a label."""
        return (ins.target in here and ins.addr not in shaped and ins.addr not in breaks
                and not (slicing and not ran["count"].get(ins.addr)))

    labels = {ins.target for ins in code if jumps(ins)}
    incoming = {}
    for ins in code:
        if jumps(ins) and ins.target in labels:
            incoming.setdefault(ins.target, []).append(ins.addr)
    folds, dropped = acc_chains(code, labels) if opts["clean"] else ({}, set())

    def inlined(ins, nxt):
        """The branch condition, when the delay slot cannot change it before the branch takes."""
        if not opts["clean"] or ins.lname not in BRANCH_COND:
            return False
        if nxt is not None and nxt.addr in labels:
            return False
        regs = {vi(ins.lf.is_), vi(ins.lf.it)}
        return nxt is None or not (regs & nxt.reads_writes()[1])

    reads_first, written = [], set()
    for ins in code:
        r, w = ins.reads_writes()
        for reg in sorted(r):
            if reg not in written and reg not in reads_first and reg not in ("vf00", "vi00"):
                reads_first.append(reg)
        written |= w
    out = ["/* %s: micro 0x%04X..0x%04X, %d instructions, uploaded to 0x%04x %d times */"
           % (prog["hash"], code[0].addr, code[-1].addr, len(code), prog["addr"], prog["uploads"]),
           "/* reads before writing (linear scan): %s */" % " ".join(sorted(reads_first)),
           "/* writes: %s */" % " ".join(sorted(written))]
    dead = {}
    if opts["only_ran"] and not ran:
        out.append("/* no execution recorded for this program, so nothing was elided */")
    if ran:
        never = [ins.addr for ins in code if not ran["count"].get(ins.addr)]
        dead = dead_ranges(code, ran)
        out.append("/* execution: %s recorded, %d of %d instructions never ran%s */"
                   % (plural(ran["runs"], "run"), len(never), len(code),
                      "".join(", entered at %04X (%d)" % (a, n)
                              for a, n in sorted(ran["entries"].items()))))
    dispatch = dispatch_table(code, prog["base"])
    reached = {}
    for at, (reg, targets, _, _) in dispatch.items():
        for t in targets:
            reached.setdefault(t, []).append(at)
    for at, (reg, targets, written, reads) in sorted(dispatch.items()):
        detail = []
        if ran and ran["targets"].get(at):
            detail.append("went to %s in %d runs"
                          % (" ".join("%04X (%d)" % (t, n)
                                      for t, n in sorted(ran["targets"][at].items())),
                             ran["runs"]))
        if targets:
            detail.append("one of %s (set at %s)"
                          % (" ".join("%04X" % t for t in targets),
                             " ".join("%04X" % a for a in written)))
        if reads:
            detail.append("or a value read at %s" % " ".join("%04X" % a for a in reads))
        out.append("/* %04X jumps to %s: %s */"
                   % (at, reg, ", ".join(detail) if detail else "no constant reaches it"))
    leaving = sorted({ins.target for ins in code if ins.target is not None and ins.target not in here})
    for target in leaving:
        found = elsewhere(target, prog, others)
        out.append("/* %04X leaves this program (it ends at %04X): %s */"
                   % (target, code[-1].addr,
                      "%s, %s" % (", ".join(found[0]), found[1]) if found
                      else "no translated program covers it"))
    fixed = sorted({ins.lf.imm11 for ins in code
                    if ins.lname in ("LQ", "ILW") and ins.lf.is_ == 0 and not ins.ibit})
    if fixed:
        out.append("/* loads from fixed addresses: %s */"
                   % " ".join("mem[%d]" % a for a in fixed))
    if consts:
        samples = len(opts["watch"][prog["hash"]])
        out.append("/* memory from sample %d of %d in %s: */"
                   % (min(opts["instance"], samples - 1), samples, opts["mem"]))
        for addr, (lanes, distinct, written) in sorted(consts.items()):
            out.append("/*   mem[%d] = %s%s%s */"
                       % (addr, ", ".join(fnum(v) for v in lanes),
                          "" if distinct == 1 else
                          "   (%d distinct values across the samples)" % distinct,
                          "   (this program writes .%s, so those lanes are not substituted)"
                          % "".join(sorted(written)) if written else ""))
            tag = gif_tag(lanes)
            if tag:
                out.append("/*     %s */" % tag)
    out += ["void vu1_%s(void)" % prog["hash"][:8].lower(), "{"]
    take_at = len(out)
    out.append("  bool take = false;")

    known, entries = {}, set(targets)

    def enters(at):
        """Values do not survive a point control can jump to."""
        if at.addr in entries:
            known.clear()

    def leaves(at):
        for reg in at.reads_writes()[1]:
            known.pop(reg, None)
        if at.lname == "LQ" and at.lf.is_ == 0 and at.lf.ft and at.lf.imm11 in consts \
                and not set(at.lf.mask) & consts[at.lf.imm11][2]:
            lanes = consts[at.lf.imm11][0]
            known.setdefault(vf(at.lf.ft), {}).update(
                {c: lanes[FIELDS.index(c)] for c in at.lf.mask})

    depth = [0]

    def put(at, text, mnem, indent, first, note=None):
        if ran and first:
            counted = ran["count"].get(at.addr)
            if not counted:
                if not any(lo <= at.addr <= hi for lo, hi in dead.items()):
                    note = "never ran" if not note else "%s, never ran" % note
            elif at.lname in BRANCH_COND:
                note = "taken %d of %d" % (ran["taken"].get(at.addr, 0), counted)
        out.append(emit_line(at, text, mnem, indent + 2 * depth[0], opts, first, note))
        return False

    def elide(at):
        """Never-executed straight-line code can go; anything structural has to stay."""
        if not slicing or ran["count"].get(at.addr):
            return False
        return not (at.ebit or at.addr in labels or at.addr in opens
                    or at.addr in closes or at.addr in shaped or at.addr in breaks)

    i, ebit_at = 0, None
    while i < len(code):
        ins = code[i]
        for _ in range(opens.get(ins.addr, 0)):
            put(ins, "do {", None, 2, False)
            depth[0] += 1
        if ins.addr in dead:
            gone = sum(1 for a in range(ins.addr, dead[ins.addr] + 1)
                       if elide(code[a - prog["base"]]))
            out.append("/* %04X..%04X never ran%s */"
                       % (ins.addr, dead[ins.addr],
                          ", %s omitted" % plural(gone, "instruction") if gone else ""))
        if ins.addr in reached and not elide(ins):
            out.append("/* reached by the jump at %s */"
                       % " ".join("%04X" % a for a in reached[ins.addr]))
        if ins.addr in labels:
            out.append(label_line(ins.addr, incoming.get(ins.addr))
                       + ("  ;" if elide(ins) else ""))
        if ins.ebit:
            ebit_at = ins.addr
        fold = folds.get(ins.addr)
        stmts, notes = pair_statements(ins, opts, fold[1] if fold else
                                       ("" if ins.addr in dropped else None))
        if elide(ins):
            stmts, notes = [], []
        enters(ins)
        stmts = [(subst_reads(t, known) if consts else t, m) for t, m in stmts]
        leaves(ins)
        first = True
        for note in notes:
            first = put(ins, "/* %s */" % note, None, 2, first)
        for text, mnem in stmts:
            first = put(ins, text, mnem, 2, first,
                        "folds %04X..%04X" % (fold[0], ins.addr)
                        if fold and text == fold[1] else None)
        last = ins.addr
        if ins.branch and elide(ins):
            # Its delay slot goes with it, unless something still jumps to that address.
            if i + 1 < len(code) and elide(code[i + 1]):
                i += 1
                last = code[i].addr
        elif ins.branch:
            nxt = code[i + 1] if i + 1 < len(code) else None
            inline = inlined(ins, nxt)
            cond, link, target = branch_parts(ins)
            entered = nxt is not None and nxt.addr in labels
            note = None
            if ins.target is not None and ins.target not in here:
                target = "goto_micro(0x%04X);" % ins.target
                note = "leaves this program, see the header"
            shape = shaped.get(ins.addr)
            if cond and (shape or ins.addr in breaks):
                target = "break;" if ins.addr in breaks else None
            if cond and not inline:
                first = put(ins, "take = (%s);" % cond,
                            mnemonic(ins.lname, ins.lf, False), 2, first)
            if cond and target is not None:
                test = cond if inline else "take"
                # Clearing take keeps the test right for a delay slot the code also jumps into.
                target = ("if (take) { take = false; %s }" % target if entered
                          else "if (%s) %s" % (test, target))
            if link:
                first = put(ins, link, mnemonic(ins.lname, ins.lf, False), 2, first, "link register")
            if nxt is not None:
                if nxt.branch:
                    put(nxt, "/* branch in delay slot: this one is taken first */", None, 2, False)
                if entered:
                    out.append("L_%04X:  /* delay slot of %04X, reached with take clear */"
                               % (nxt.addr, ins.addr))
                dfold = folds.get(nxt.addr)
                dstmts, dnotes = pair_statements(nxt, opts, dfold[1] if dfold else
                                                 ("" if nxt.addr in dropped else None))
                if elide(nxt):
                    dstmts, dnotes = [], []
                enters(nxt)
                dstmts = [(subst_reads(t, known) if consts else t, m) for t, m in dstmts]
                leaves(nxt)
                dfirst = True
                for note in dnotes:
                    dfirst = put(nxt, "/* %s */" % note, None, 2, dfirst)
                for text, mnem in dstmts:
                    dfirst = put(nxt, text, mnem, 2, dfirst,
                                 "delay slot of %04X" % ins.addr if dfirst else None)
                if nxt.ebit:
                    ebit_at = nxt.addr
                last = nxt.addr
                i += 1
                for _ in range(closes.pop(nxt.addr, 0)):
                    depth[0] -= 1
                    put(nxt, "}", None, 2, False)
            mnem = mnemonic(ins.lname, ins.lf, False)
            if shape is None and ins.addr in breaks:
                put(ins, target if not entered else "{ take = false; break; }", mnem, 2, first)
            elif shape and shape[2] == "do":
                depth[0] -= 1
                put(ins, "} while (%s);" % (cond if inline else "take"), mnem, 2, first)
            elif shape:
                put(ins, "if (%s) {" % (branch_parts(ins, negate=True)[0] if inline else "!take"),
                    mnem, 2, first)
                depth[0] += 1
            else:
                put(ins, target, mnem, 2, first, note)
        i += 1
        for _ in range(closes.pop(last, 0)):
            depth[0] -= 1
            put(ins, "}", None, 2, False)
        if ebit_at is not None and last > ebit_at:
            put(ins, "return;  /* [E] at %04X */" % ebit_at, None, 2, False)
            ebit_at = None
    if ebit_at is not None:
        put(ins, "return;  /* [E] at %04X */" % ebit_at, None, 2, False)
    if not any(re.search(r"\btake\b", line) for line in out[take_at + 1:]):
        out.pop(take_at)
    out.append("}")
    return out


def provenance(path, argv, progs):
    return ("/* scripts/vu2c.py %s, from %s, options: %s.\n"
            " * %s, %s.  No timestamp: one input and one set of options\n"
            " * always give the same file. */"
            % (VERSION, path, " ".join(argv[2:]) or "none", plural(len(progs), "program"),
               plural(sum(len(p["ins"]) for p in progs), "instruction")))


def option_notes(opts):
    notes = []
    if opts["clean"]:
        notes.append("/* --clean: vf00 reads as (0, 0, 0, 1), so a term that names it is folded"
                     " away;\n * a run of ACC writes ending in one vf write prints as a single"
                     " expression, and\n * a branch condition is inlined where the delay slot"
                     " cannot change it. */")
    if opts["flow"]:
        notes.append("/* --flow: a branch whose shape is unambiguous is printed as do/while, if"
                     " or\n * break, and the rest stay gotos.  The delay slot is inside the loop"
                     " or before\n * the if either way, since it runs before the branch"
                     " takes. */")
    return notes


def write_split(outdir, path, picked, others, opts, argv):
    """One file per program, sharing one header, with an index listing them."""
    os.makedirs(outdir, exist_ok=True)
    with open(os.path.join(outdir, "vu1_defs.h"), "w") as f:
        f.write("#ifndef VU1_DEFS_H\n#define VU1_DEFS_H\n\n")
        f.write(PREAMBLE)
        for note in option_notes(opts):
            f.write("\n" + note + "\n")
        f.write("\n#endif\n")
    suffix = "_only-ran" if opts["only_ran"] else ""
    rows, written = [], set()
    for prog in picked:
        name = "vu1_%s%s.c" % (prog["hash"][:8].lower(), suffix)
        written.add(name)
        with open(os.path.join(outdir, name), "w") as f:
            f.write(provenance(path, argv, [prog]) + "\n")
            f.write('#include "vu1_defs.h"\n\n')
            f.write("\n".join(translate(prog, others, opts)) + "\n")
        rows.append("| [%s](%s) | %s | 0x%04X..0x%04X | %d | %d |"
                    % (name, name, prog["hash"], prog["base"],
                       prog["base"] + len(prog["ins"]) - 1, len(prog["ins"]), prog["uploads"]))
    stale = [f for f in os.listdir(outdir)
             if re.fullmatch(r"vu1_[0-9a-f]{8}%s\.c" % suffix, f) and f not in written]
    for f in stale:
        os.remove(os.path.join(outdir, f))
    with open(os.path.join(outdir, "index%s.md" % suffix), "w") as f:
        f.write("# VU1 microprograms from %s\n\n" % path)
        f.write("Written by `scripts/vu2c.py %s`, options: %s.\n\n"
                % (VERSION, " ".join(argv[2:]) or "none"))
        f.write("| file | program | micro range | instructions | uploads |\n")
        f.write("|---|---|---|---|---|\n")
        f.write("\n".join(rows) + "\n")
    print("%s -> %s%s"
          % (plural(len(picked), "program"), outdir,
             ", %s removed" % plural(len(stale), "stale file") if stale else ""))


def parse_watch(path):
    """{program: [{quadword: (w0, w1, w2, w3)}]}, one entry per sample, from a VU watch dump."""
    head = re.compile(r"^f(\d+) b(\d+)\s+vu(\w+)")
    cell = re.compile(r"^\s+mem\[(\d+)\]\s+hex=((?:[0-9A-F]{8} ?){4})")
    samples, current = {}, None
    for text in open(path):
        m = head.match(text)
        if m:
            current = {}
            samples.setdefault(m.group(3), []).append(current)
            continue
        m = cell.match(text)
        if m and current is not None:
            words = [int.from_bytes(bytes.fromhex(w), "little") for w in m.group(2).split()]
            current[int(m.group(1))] = tuple(words)
    return samples


def watch_consts(samples, instance):
    """{quadword: (lanes, how many distinct values the samples hold)} for one program."""
    if not samples:
        return {}
    chosen = samples[min(instance, len(samples) - 1)]
    return {addr: (lanes, len({s.get(addr) for s in samples}))
            for addr, lanes in chosen.items()}


def lookup_runs(prog, runs):
    """Runs for this program, merging every alias when the block is a resident image."""
    keys = [k for k in [prog["hash"]] + prog.get("aliases", []) if k in runs]
    if not keys:
        return None
    if len(keys) == 1:
        return runs[keys[0]]
    merged = {"runs": 0, "count": {}, "targets": {}, "taken": {}, "entries": {}, "sequence": []}
    for k in keys:
        r = runs[k]
        merged["runs"] += r["runs"]
        merged["sequence"] += r["sequence"]
        for field in ("count", "taken", "entries"):
            for a, n in r[field].items():
                merged[field][a] = merged[field].get(a, 0) + n
        for a, tgts in r["targets"].items():
            into = merged["targets"].setdefault(a, {})
            for t, n in tgts.items():
                into[t] = into.get(t, 0) + n
    return merged


def parse_exec(path):
    """{program: {"runs", "count", "targets", "taken", "entries"}} from a VU execution trace.

    Format, one run per `run` line and one row per executed address:

        run f12 b7 vu62BCC9E6481451C0 entry=0036
        0036 1
        01B3 1 target=0422
        04A0 120 taken=119
    """
    head = re.compile(r"^run\s+f(\d+)\s+b(\d+)\s+vu(\w+)(?:\s+entry=([0-9A-Fa-f]+))?")
    row = re.compile(r"^\s*([0-9A-Fa-f]{1,4})(?:\s+(\d+))?((?:\s+\S+=\S+)*)\s*$")
    runs, current, order = {}, None, None
    for text in open(path):
        m = head.match(text)
        if m:
            current = runs.setdefault(m.group(3), {"runs": 0, "count": {}, "targets": {},
                                                   "taken": {}, "entries": {}, "sequence": []})
            current["runs"] += 1
            order = []
            current["sequence"].append({"frame": int(m.group(1)), "batch": int(m.group(2)),
                                        "steps": order})
            if m.group(4):
                entry = int(m.group(4), 16)
                current["entries"][entry] = current["entries"].get(entry, 0) + 1
            continue
        m = row.match(text)
        if not m or current is None:
            continue
        addr, count = int(m.group(1), 16), int(m.group(2) or 1)
        current["count"][addr] = current["count"].get(addr, 0) + count
        wrote, jumped = {}, []
        for field in m.group(3).split():
            key, _, value = field.partition("=")
            if key == "target":
                for one in value.split(","):
                    seen = current["targets"].setdefault(addr, {})
                    seen[int(one, 16)] = seen.get(int(one, 16), 0) + count
                    jumped.append(int(one, 16))
            elif key == "taken":
                current["taken"][addr] = current["taken"].get(addr, 0) + int(value)
            else:
                wrote[key] = [int(w, 16) for w in value.split(",")]
        order.append((addr, wrote, jumped))
    return runs


TRACE_LIMIT = 4000


def render_trace(prog, run, index, opts):
    """One recorded run, in the order it executed, with the values it wrote."""
    code = {prog["base"] + i: Ins(prog["base"] + i, u, l)
            for i, (u, l, _) in enumerate(prog["ins"])}
    out = ["/* %s: run %d, frame %d batch %d, %s executed */"
           % (prog["hash"], index, run["frame"], run["batch"],
              plural(len(run["steps"]), "instruction")),
           "void vu1_%s_run%d(void)" % (prog["hash"][:8].lower(), index),
           "{"]
    known, last = {}, None
    for step, (addr, wrote, jumped) in enumerate(run["steps"]):
        if step == TRACE_LIMIT:
            out.append("/* %s not shown */" % plural(len(run["steps"]) - step, "further step"))
            break
        ins = code.get(addr)
        if ins is None:
            out.append("/* %04X is outside this program */" % addr)
            continue
        if last is not None and addr <= last:
            out.append("/* back to %04X from %04X */" % (addr, last))
        last = addr
        stmts, _ = pair_statements(ins, opts)
        if ins.branch:
            # The trace already holds the outcome, so a goto would say nothing the next line does not.
            # The recorded target is authoritative; otherwise the step past the delay slot is it.
            after = jumped[0] if jumped else (run["steps"][step + 2][0]
                                              if step + 2 < len(run["steps"]) else None)
            went = "-> %04X" % after if after is not None else "end of the trace"
            if ins.target is not None and after is not None:
                went += " (taken)" if after == ins.target else " (not taken)"
            stmts = stmts + [("/* %s %s */" % (mnemonic(ins.lname, ins.lf, False), went), None)]
        note = ", ".join("%s = %s" % (reg, ", ".join(fnum(w) for w in words))
                         if reg.startswith("vf") or reg in ("ACC", "I", "Q", "P")
                         else "%s = %d" % (reg, words[0])
                         for reg, words in sorted(wrote.items()))
        for n, (text, mnem) in enumerate(stmts):
            out.append(emit_line(ins, subst_reads(text, known), mnem, 2, opts, n == 0,
                                 note if n == 0 and note else None))
        for reg in ins.reads_writes()[1]:
            known.pop(reg, None)
        for reg, words in wrote.items():
            if reg.startswith("vf") and len(words) == 4:
                known[reg] = dict(zip(FIELDS, words))
    out.append("}")
    return out


def parse_dump(path):
    head = re.compile(r"^program (\w+)\s+addr=0x([0-9a-fA-F]+) words=(\d+) instrs=(\d+) "
                      r"uploads=(\d+)")
    line = re.compile(r"^\s+([0-9A-F]{4})\s+([0-9A-F]{8})\s+([0-9A-F]{8})\s\s+(.*)$")
    progs, cur = [], None
    for text in open(path):
        m = head.match(text)
        if m:
            cur = {"hash": m.group(1), "addr": int(m.group(2), 16), "uploads": int(m.group(5)),
                   "base": int(m.group(2), 16) // 8, "ins": [],
                   # A resident-image block carries the entry-program hashes an execution trace keys
                   # its runs by, since the image itself was never a run's program.
                   "aliases": re.search(r"aliases=(\S+)", text).group(1).split(",")
                              if "aliases=" in text else []}
            progs.append(cur)
            continue
        m = line.match(text)
        if m and cur is not None:
            cur["ins"].append((int(m.group(2), 16), int(m.group(3), 16), m.group(4).rstrip()))
    return progs


def check(progs):
    """Diff our decode against the dump's own PCSX2 disassembly."""
    regs = re.compile(r"v[fi]\d\d")
    bad = ibit = 0
    total = 0
    for prog in progs:
        for i, (u, l, text) in enumerate(prog["ins"]):
            ins = Ins(prog["base"] + i, u, l)
            total += 1
            um = mnemonic(ins.uname, ins.uf, True, dis=True) if ins.uname else None
            if um is None or not text.startswith(um):
                print("%s %04X: upper %s != %s" % (prog["hash"][:8], ins.addr, um, text))
                bad += 1
                continue
            upper_regs, uw = render_upper(ins.uname, ins.uf)[1:]
            ours = {r for r in (upper_regs | uw) if regs.fullmatch(r)}
            theirs = set(regs.findall(re.split(r"\s{2,}", text[len(um):].lstrip(), maxsplit=1)[0]))
            if ours != theirs and ins.uf.mask:
                print("%s %04X: upper regs %s != %s"
                      % (prog["hash"][:8], ins.addr, sorted(ours), sorted(theirs)))
                bad += 1
            if ins.ibit:
                ibit += 1
                continue
            lm = mnemonic(ins.lname or "?", ins.lf, False, dis=True)
            sep = text.rfind("  " + lm)
            if sep < len(um):
                print("%s %04X: lower %s not in %r" % (prog["hash"][:8], ins.addr, lm, text))
                bad += 1
                continue
            lr, lw = branch_regs(ins) if ins.branch else render_lower(ins.lname, ins.lf)[1:]
            ours = {r for r in (set(lr) | set(lw)) if regs.fullmatch(r)}
            theirs = set(regs.findall(text[sep:]))
            if ours != theirs and not (ins.lname in ("BAL", "JALR") and not ins.lf.it):
                print("%s %04X: lower %s regs %s != %s" % (prog["hash"][:8], ins.addr, lm,
                                                           sorted(ours), sorted(theirs)))
                bad += 1
    print("checked %d instructions in %d programs: %d mismatches, %d [I] pairs "
          "(the dump disassembles those immediates as instructions)" % (total, len(progs), bad, ibit))
    print("operand sets are skipped where the destination mask is empty: nothing is read or written")
    return bad


def main(argv):
    if len(argv) < 2:
        print(USAGE)
        return 2
    path = argv[1]
    wanted, do_list, do_check = [], False, False
    opts = {"addr": True, "asm": True, "nops": False, "preamble": True, "flow": False,
            "clean": False, "split": None, "mem": None, "watch": None, "instance": 0,
            "consts": None, "exec": None, "runs": None, "trace": None, "only_ran": False}
    i = 2
    while i < len(argv):
        a = argv[i]
        if a == "--list":
            do_list = True
        elif a == "--check":
            do_check = True
        elif a == "--all":
            wanted = []
        elif a == "--program":
            i += 1
            wanted.append(argv[i].upper())
        elif a == "--only-ran":
            opts["only_ran"] = True
        elif a == "--trace":
            i += 1
            opts["trace"] = int(argv[i])
        elif a == "--exec":
            i += 1
            opts["exec"] = argv[i]
        elif a == "--mem":
            i += 1
            opts["mem"] = argv[i]
        elif a == "--instance":
            i += 1
            opts["instance"] = int(argv[i])
        elif a == "--split":
            i += 1
            opts["split"] = argv[i]
        elif a == "--clean":
            opts["clean"] = True
        elif a == "--flow":
            opts["flow"] = True
        elif a == "--keep-nops":
            opts["nops"] = True
        elif a == "--no-asm":
            opts["asm"] = False
        elif a == "--no-addr":
            opts["addr"] = False
        elif a == "--no-preamble":
            opts["preamble"] = False
        else:
            print("unknown option %s" % a)
            return 2
        i += 1

    if opts["mem"]:
        opts["watch"] = parse_watch(opts["mem"])
    if opts["exec"]:
        opts["runs"] = parse_exec(opts["exec"])
    progs = parse_dump(path)
    if not progs:
        print("no programs in %s" % path)
        return 1
    if do_check:
        return 1 if check(progs) else 0
    if do_list:
        for p in progs:
            print("%s  0x%04X..0x%04X  %3d instructions  %d uploads"
                  % (p["hash"], p["base"], p["base"] + len(p["ins"]) - 1, len(p["ins"]),
                     p["uploads"]))
        return 0

    picked = [p for p in progs if not wanted or any(p["hash"].startswith(w) for w in wanted)]
    if not picked:
        print("no program matches %s" % ", ".join(wanted))
        return 1

    if opts["trace"] is not None:
        for prog in picked:
            recorded = (lookup_runs(prog, opts["runs"]) or {}).get("sequence", []) \
                   if opts["runs"] else []
            if opts["trace"] < len(recorded):
                print("\n".join(render_trace(prog, recorded[opts["trace"]], opts["trace"], opts)))
        return 0
    if opts["split"]:
        write_split(opts["split"], path, picked, picked, opts, argv)
        return 0
    if opts["preamble"]:
        print(provenance(path, argv, picked))
        print(PREAMBLE)
        for note in option_notes(opts):
            print(note + "\n")
    for n, p in enumerate(picked):
        if n:
            print()
        print("\n".join(translate(p, picked, opts)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

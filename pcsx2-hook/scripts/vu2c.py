#!/usr/bin/env python3
"""Translate the VU1 microprograms in a PCSX2HOOK_VU_TRACE dump into pseudo-C.

Instructions are decoded from the raw words, not from the disassembly text in the dump. The tables
mirror PCSX2's (DisVUmicro.h, VUops.cpp) and every operation follows its VU interpreter.
"""

USAGE = """usage: vu2c.py <vu1_programs.jsonl> [options]
  --list            one line per program, no code
  --all             translate every program (the default)
  --program HASH    translate this program (prefix of the dump's hash); repeatable
  --exec FILE       annotate from an execution trace: what never ran, branch counts, real targets
  --trace N         with --exec, print run N of each program in the order it executed
  --only-ran        with --exec, drop the instructions the trace never reached
  --mem FILE        substitute the quadwords a VU watch dump recorded into loads from them
  --names FILE      name fixed memory addresses from a `<quadword>[.lane] <name>` table
  --instance N      which sample of that program to take the memory from (default 0)
  --split DIR       write one file per program into DIR, plus vu1_defs.h and an index
  --check           re-derive PCSX2's mnemonics from the decode and diff them against the dump
  --selftest        run the built-in tests for every simplification and exit
  --keep-nops       keep instructions that do nothing
  --no-asm          drop the trailing mnemonic comments
  --no-addr         drop the address column
  --no-preamble     drop the header explaining the notation

Simplification.  Nothing is simplified unless asked for, every pass states the precondition it
checks, and no pass ever runs when its precondition fails.
  --simplify LIST   comma-separated pass names, or `all`; repeatable
  --no-simplify P   drop one pass from a group that enabled it
  --audit           print the statements each fold replaced, above the folded line
  --clean           shorthand for every pass that folds a value:
                    const,join,acc,mat,cross,ptr,clamp,branch
  --flow            shorthand for every pass that shapes control flow:
                    flow,else,loops,call

passes:
  const   fold known constants into operands: vf00's (0, 0, 0, 1), I from the nearest LOI, and
          integers a viNN was given by IADDIU/IADDI/ISUBIU.  Block-local: every value is dropped
          at a label, at a branch target and at any write to the register.
  join    carry a constant past a label when every path into it holds the same value, rather
          than dropping it there.  Needs const; --audit says which lines each value came from.
  alias   a register loaded from a named location prints under that name while it holds it, as
          `indexList_vi12`, through the steps that walk it and until it is loaded from something
          else.  Needs --names.
  acc     a run of ACC writes ending in one vf write prints as a single expression
  mat     an ACC chain over three or four consecutive vf registers, broadcast x, y, z (, w) of one
          source, prints as mul3x3/mul4x4
  cross   an OPMULA/OPMSUB pair with swapped operands prints as cross()
  ptr     LQI/SQI/LQD/SQD print as mem[viNN++] rather than as two statements
  clamp   an adjacent MAX/MINI pair on one register, both against constants, prints as clamp()
  flow    a branch whose shape is unambiguous prints as do/while, if or break
  else    an if block ending in an unconditional branch past the next block prints as if/else
  call    BAL prints as call, and JR on a register only ever written as a link prints as return
  loops   a comment over each loop naming its counter register and the step per iteration
  branch  inline a branch condition where the delay slot cannot change it"""
import json
import os
import textwrap
import re
import struct
import sys

VERSION = "1.1"  # bump when the emitted form changes

# Every pass name --simplify takes.  `all` means this list.
PASSES = ["const", "join", "alias", "acc", "mat", "cross", "ptr", "clamp", "flow", "else",
          "call", "loops", "branch"]

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
/* Pseudo-C for VU1 microcode, one statement per instruction.  Nothing here links or runs; the
 * declarations are what lets an editor parse it, and a swizzle is one float rather than the lanes
 * it names, which is all a parser needs.
 *
 *   vfNN four float lanes .x .y .z .w   viNN 16-bit integer, writes truncate   ACC accumulator
 *   I Q P R  immediate, divide, EFU, random      status mac clip  flag registers
 *   mem[a]  data memory, quadword a              mem_w[a].x  the same word as an integer
 *
 *   as_float(v)  a bit copy, not a conversion (MFIR, RGET).  A lane out of memory prints this way
 *                when it cannot be a number, so it is a packed field: a GIF tag among them
 *   lo16(f)      low 16 bits of the bit pattern (MTIR)      mr32(v)  (v.y, v.z, v.w, v.x)
 *   ftoiN/itofN  convert with N fraction bits; the result stays raw bits, so only the scale shows
 *   opmul(a, b)  (a.y*b.z, a.z*b.x, a.x*b.y), the halves an OPMULA/OPMSUB pair crosses
 *   cross(a, b)  the cross product those halves come to    clamp(v, lo, hi)  min(max(v, lo), hi)
 *   mul3x3(m, v) m[0]*v.x + m[1]*v.y + m[2]*v.z, m the registers from m[0] up; mul4x4 adds m[3]*v.w
 *   clip_bits(v, w)  x > w, x < -w, y > w, y < -w, z > w, z < -w, with w = |ft.w|
 *   xgkick(a)    start the GS transfer at mem[a]           goto_micro(a)  jump away for good
 *   subroutine(f, ...)  a routine entry: f, then what f reads before writing it, which is what
 *                a caller has to set.  A BAL to f prints as f().  The map above says where f ends.
 *
 * A statement reads all of its right side before writing any lane, so a register on both sides is
 * the value the instruction started with.  Both halves of a pair read the register file as it
 * stood before the pair, so where the lower half reads what the upper writes, the lower prints
 * first.  A branch takes after its delay slot, so the condition is captured at the branch and the
 * goto printed after the delay slot.
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
float clamp(float v, float lo, float hi), cross(vec4 a, vec4 b);
float mul3x3(vec4 m, float v), mul4x4(vec4 m, float v);
void xgkick(int addr), goto_micro(int addr);

/* This declares f and drops the rest, so `subroutine(f, vf13, vi06)` parses and f() below it
 * resolves; the registers are a macro argument nothing expands, read rather than resolved. */
#define subroutine(f, ...)  void f(void)
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
    elif base in ("MAX", "MINI"):
        if ca is not None and cb is not None:
            value = max(ca, cb) if base == "MAX" else min(ca, cb)
            return "%.1ff" % value
    return None


def merge_at(a, b):
    """The origins of two agreeing values: one address, or all of them."""
    if a == b:
        return a
    both = set()
    for side in (a, b):
        both |= set(side) if isinstance(side, tuple) else ({side} if side is not None else set())
    return tuple(sorted(both)) or None


def at_text(at):
    """An origin as addresses, for the note that says where a substituted value came from."""
    if at is None:
        return None
    return " ".join("%04X" % a for a in (at if isinstance(at, tuple) else (at,)))


class Consts:
    """The values known to hold at one point, each written by an instruction above it.

    Block-local by construction: `clear` runs at every label, branch target and unconditional
    jump, and `kill` at every write, so a substitution is checkable against the lines just above
    the one it changed.  Each entry carries the address that set it, which is what `--audit`
    prints.  vf00's lanes and vi00 are hardware constants and are never cleared.
    """

    def __init__(self, on=True):
        self.on = on
        self.lanes = {}  # vfNN -> {lane: (bits, set at)}
        self.ints = {}   # viNN -> (value, set at)
        self.i = None    # (bits, set at), from LOI
        self.alias = {}  # register -> the name of the location its value was loaded from
        self.linked = set()  # registers holding a return address

    def copy(self):
        out = Consts(self.on)
        out.lanes = {r: dict(v) for r, v in self.lanes.items()}
        out.ints = dict(self.ints)
        out.i = self.i
        out.alias = dict(self.alias)
        out.linked = set(self.linked)
        return out

    def clear(self):
        self.lanes.clear()
        self.ints.clear()
        self.i = None
        self.alias.clear()
        self.linked.clear()

    def key(self):
        return (tuple(sorted((r, tuple(sorted(v.items()))) for r, v in self.lanes.items())),
                tuple(sorted(self.ints.items())), self.i, tuple(sorted(self.alias.items())),
                tuple(sorted(self.linked)))

    def meet(self, other):
        """What both states agree on: the same value, with the origins of both.

        A value survives a join only when every path into the point carries it, so it still came
        from lines above, and the origins the audit prints name all of them.
        """
        if other is None:
            return self.copy()
        out = Consts(self.on)
        for reg, lanes in self.lanes.items():
            for lane, (bits, at) in lanes.items():
                theirs = other.lanes.get(reg, {}).get(lane)
                if theirs and theirs[0] == bits:
                    out.lanes.setdefault(reg, {})[lane] = (bits, merge_at(at, theirs[1]))
        for reg, (value, at) in self.ints.items():
            theirs = other.ints.get(reg)
            if theirs and theirs[0] == value:
                out.ints[reg] = (value, merge_at(at, theirs[1]))
        if self.i and other.i and self.i[0] == other.i[0]:
            out.i = (self.i[0], merge_at(self.i[1], other.i[1]))
        out.alias = {r: n for r, n in self.alias.items() if other.alias.get(r) == n}
        out.linked = self.linked & other.linked
        return out

    def kill(self, regs, keep_alias=()):
        for reg in regs:
            self.lanes.pop(reg, None)
            self.ints.pop(reg, None)
            if reg not in keep_alias:
                self.alias.pop(reg, None)
            self.linked.discard(reg)
            if reg == "I":
                self.i = None

    def set_lanes(self, reg, values, at):
        """values is {lane: bits}."""
        if reg != "vf00":
            self.lanes.setdefault(reg, {}).update({c: (v, at) for c, v in values.items()})

    def set_int(self, reg, value, at):
        if reg != "vi00":
            self.ints[reg] = (value & 0xFFFF, at)

    def int_at(self, reg):
        """(value, where it was set) for an integer register, or None."""
        if not self.on:
            return None
        return (0, None) if reg == "vi00" else self.ints.get(reg)

    def lane_at(self, reg, lane):
        """(bits, where it was set) for one float lane, or None."""
        if not self.on:
            return None
        if reg == "vf00":
            return (0x3F800000 if lane == "w" else 0, None)
        return self.lanes.get(reg, {}).get(lane)


# A read this substitutes has to be a read: a bare `viNN++`, `--viNN` or an assignment target is
# left alone, and on the left of an `=` only a memory subscript is rewritten.
READ_OPERAND = re.compile(r"(vf\d\d)\.([xyzw]+)")
READ_INT = re.compile(r"(?<!-)\bvi\d\d\b(?!\+\+)")
READ_I = re.compile(r"(?<![\w.])I(?![\w.])")
STEP_ONLY = re.compile(r"^\s*(--vi\d\d;|vi\d\d\+\+;)\s*$")
YODA = re.compile(r"\b(-?\d+) (==|!=) (vi\d\d)\b")
SUBSCRIPT = re.compile(r"(mem_w?\[)([^]]*)(\])")


def subst_reads(text, consts, provenance=None, skip=()):
    """Substitute the values `consts` knows into the reads of one statement.

    `provenance` collects "what = value, from ADDR" for --audit.  `skip` names registers this
    instruction writes before the statement reads them, which is LQD's and SQD's pre-decrement
    and nothing else.  Writes are never touched: a statement that only steps a pointer is
    returned as it stands, and on an assignment's left side only the memory subscript is
    rewritten, since that subscript is a read.
    """
    if STEP_ONLY.match(text):
        return text

    def swap_floats(m):
        reg, mask = m.group(1), m.group(2)
        if reg in skip:
            return m.group(0)
        found = [consts.lane_at(reg, c) for c in mask]
        if any(v is None for v in found):
            return m.group(0)
        if reg == "vf00" and len(mask) > 1:
            return m.group(0)  # fold_arith owns the multi-lane vf00 cases and keeps them short
        full = [0] * 4
        for c, value in zip(mask, found):
            full[FIELDS.index(c)] = value[0]
        out = lanes_literal(full, mask)
        if provenance is not None and reg != "vf00":
            where = sorted({t for t in (at_text(v[1]) for v in found) if t})
            provenance.append("%s.%s = %s%s" % (reg, mask, out,
                                                ", from %s" % " ".join(where) if where else ""))
        # A negative literal can land after a unary minus or another operator.
        return "(%s)" % out if out.startswith("-") else out

    def swap_ints(m):
        if m.group(0) in skip:
            return m.group(0)
        found = consts.int_at(m.group(0))
        if found is None:
            return m.group(0)
        if provenance is not None and found[1] is not None:
            provenance.append("%s = %d, from %s" % (m.group(0), found[0],
                                                             at_text(found[1])))
        return str(found[0])

    def swap_i(m):
        if not consts.on or consts.i is None:
            return m.group(0)
        if provenance is not None and consts.i[1] is not None:
            provenance.append("I = %s, from %s" % (fnum(consts.i[0]),
                                                           at_text(consts.i[1])))
        return fnum(consts.i[0])

    def reads(part):
        return READ_I.sub(swap_i, READ_INT.sub(swap_ints, READ_OPERAND.sub(swap_floats, part)))

    if " = " in text:
        lhs, rhs = text.split(" = ", 1)
        return SUBSCRIPT.sub(lambda m: m.group(1) + reads(m.group(2)) + m.group(3), lhs) \
            + " = " + reads(rhs)
    return reads(text)


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


def render_lower(name, f, watch=None, passes=()):
    """(statements, reads, writes) for a lower half that is not control flow."""
    dst_f, src_f = vf(f.ft), vf(f.fs)
    mask, out, reads, writes = f.mask, [], set(), set()
    watch = watch or {}
    # The stepping form is the same two statements on one line, so it needs a register to step.
    step = "ptr" in passes

    def rw(r=(), w=()):
        reads.update(r)
        writes.update(w)

    if name in ("LQ", "LQI", "LQD"):
        stepping = step and f.is_ and f.ft and mask and name != "LQ"
        if name == "LQ":
            addr = addr_expr(f.is_, f.imm11)
        elif stepping:
            addr = "%s++" % vi(f.is_) if name == "LQI" else "--%s" % vi(f.is_)
        else:
            addr = vi(f.is_)
            if name == "LQD":
                out.append("--%s;" % addr)
        if f.ft and mask:
            known = watch.get(f.imm11) if name == "LQ" and f.is_ == 0 else None
            if known and set(mask) & known[2]:
                known = None
            out.append("%s = %s;%s" % (sw(dst_f, mask),
                                       lanes_literal(known[0], mask) if known
                                       else sw("mem[%s]" % addr, mask),
                                       "  /* mem[%d]%s */"
                                       % (f.imm11, ", GIF tag" if gif_tag(known[0]) else "")
                                       if known else ""))
        if name == "LQI" and f.is_ and not stepping:
            out.append("%s++;" % vi(f.is_))
        rw({vi(f.is_), "mem"}, {dst_f} | ({vi(f.is_)} if name != "LQ" else set()))
    elif name in ("SQ", "SQI", "SQD"):
        stepping = step and f.ft and mask and name != "SQ"
        if name == "SQ":
            addr = addr_expr(f.it, f.imm11)
        elif stepping:
            addr = "%s++" % vi(f.it) if name == "SQI" else "--%s" % vi(f.it)
        else:
            addr = vi(f.it)
            if name == "SQD":
                out.append("--%s;" % addr)
        if mask:
            out.append("%s = %s;" % (sw("mem[%s]" % addr, mask), sw(src_f, mask)))
        if name == "SQI" and f.ft and not stepping:
            out.append("%s++;" % vi(f.it))
        rw({src_f, vi(f.it)}, {"mem"} | ({vi(f.it)} if name != "SQ" else set()))
    elif name in ("ILW", "ILWR"):
        addr = addr_expr(f.is_, f.imm11) if name == "ILW" else vi(f.is_)
        if mask:
            known = watch.get(f.imm11) if name == "ILW" and f.is_ == 0 else None
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


def prototype(entry, params, names):
    """A routine entry: its name, then what a caller has to set before calling it."""
    return "subroutine(%s);" % ", ".join([routine_name(entry, names)]
                                         + (sorted(params) or ["nothing"]))


def routine_name(entry, names):
    """What to call a routine: the table's name for it, or one made from its entry address."""
    return (names or {}).get(("@", entry)) or "sub_%04X" % entry


def branch_parts(ins, negate=False, links=None, resolved=None, here=(), passes=(), pure=(),
                 names=None):
    """(condition, link statement, target statement) for a control-flow lower half."""
    f, name = ins.lf, ins.lname
    cond = link = None
    if name in BRANCH_COND:
        table = BRANCH_NOT if negate else BRANCH_COND
        cond = table[name].format(s=vi(f.is_), t=vi(f.it))
    if name in ("BAL", "JALR") and f.it:
        link = "%s = 0x%04X;" % (vi(f.it), ins.addr + 2)
    if "call" in passes and name == "BAL" and links and ins.addr in links:
        return cond, link, "%s();" % routine_name(links[ins.addr][2], names)
    if name in ("JR", "JALR"):
        if name == "JR" and pure is True:
            return cond, link, "return;"
        where = (resolved or {}).get(ins.addr) if name == "JR" else None
        if where is not None:
            return cond, link, ("goto L_%04X;" % where if where in here
                                else "goto_micro(0x%04X);" % where)
        return cond, link, "goto_micro(%s);" % vi(f.is_)
    if ins.target not in here and here:
        return cond, link, "goto_micro(0x%04X);" % ins.target
    return cond, link, "goto L_%04X;" % ins.target


FOLDED_NOTE = re.compile(r" folded into [0-9A-F]{4}$")


def pair_statements(ins, opts, upper=None, folded_into=None):
    """The pair's statements in an order that keeps the read-before-write semantics."""
    passes = opts.get("passes", set())
    ustmts, ureads, uwrites = render_upper(ins.uname, ins.uf, "const" in passes)
    if upper is not None:
        ustmts = [upper] if upper else []
    if ins.ibit:
        lstmts = ["I = %s;" % fnum(ins.lower_word)]
        lreads, lwrites = set(), {"I"}
    elif ins.branch:
        lstmts, lreads, lwrites = [], set(), set()
    else:
        lstmts, lreads, lwrites = render_lower(ins.lname, ins.lf, opts.get("watch_consts"),
                                               passes)
    notes = []
    if upper == "" and folded_into is not None:
        # The upper half is not gone, it is part of the expression at another address.  Saying so
        # is the difference between a listing that can be checked and one that reads as a nop.
        notes.append("%s folded into %04X" % (mnemonic(ins.uname, ins.uf, True), folded_into))
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
    if not out and opts["nops"] and upper != "" and not ins.branch:
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


def chain_terms(chain):
    """(fs register, broadcast lane) per link of an ACC chain, or None where a link is not one."""
    out = []
    for c in chain:
        base, _, bc = ARITH.match(c.uname).groups()
        if base not in ("MUL", "MADD") or bc not in FIELDS:
            return None
        out.append((c.uf.fs, bc, c.uf.ft))
    return out


def matrix_expr(chain, mask, dst):
    """`mul3x3`/`mul4x4` for an ACC chain that is a matrix times a vector, or None.

    The chain has to be exactly three or four multiply-accumulates that broadcast x, y, z (and w)
    of one register against consecutive registers from one base, in either the column order
    x, y, z, w or the affine order w, x, y, z that puts the translation in the accumulator first.
    Anything else keeps the sum it was written as.
    """
    terms = chain_terms(chain)
    if terms is None or len(terms) not in (3, 4):
        return None
    if len({t[2] for t in terms}) != 1:
        return None
    src, lanes, bases = vf(terms[0][2]), [t[1] for t in terms], [t[0] for t in terms]
    orders = {("x", "y", "z"): 0, ("x", "y", "z", "w"): 0, ("w", "x", "y", "z"): 3}
    rotate = orders.get(tuple(lanes))
    if rotate is None:
        return None
    # The register a lane multiplies, in lane order, has to be the base plus that lane's index.
    first = bases[0] - rotate
    if any(b != first + FIELDS.index(c) for b, c in zip(bases, lanes)):
        return None
    if not 0 <= first <= 31 - (len(terms) - 1):
        return None
    call = "mul3x3" if len(terms) == 3 else "mul4x4"
    return "%s = %s(%s, %s);" % (sw(dst, mask), call, vf(first),
                                 sw(src, "xyz" if len(terms) == 3 else "xyzw"))


def chain_expr(chain, entries, passes=()):
    """One expression for a run of ACC writes ending in a vf write, or None if that would lie.

    `entries` is every address control can arrive at, not only the ones that still print a goto:
    a loop head --flow shaped into `do {` is still an entry, and a chain that crosses one would
    claim a term the second time round never accumulated.
    """
    mask = chain[0].uf.mask
    if any(c.uf.mask != mask for c in chain) or any(c.addr in entries for c in chain[1:]):
        return None
    if ARITH.match(chain[0].uname).group(1) not in ("MUL", "ADD", "SUB"):
        return None  # it adds to an accumulator something above it set
    if any(c.ebit for c in chain[:-1]):
        return None
    reads, writes = set(), set()
    for c in chain:
        reads |= render_upper(c.uname, c.uf)[1]
        writes |= render_lower(c.lname, c.lf)[2]
    dst = vf(chain[-1].uf.fd)
    if (reads | {dst}) & writes:  # an interleaved lower half moves one of the inputs
        return None
    if "mat" in passes:
        matrix = matrix_expr(chain, mask, dst)
        if matrix:
            return matrix
    if "acc" not in passes:
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


def acc_chains(code, labels, passes=()):
    """{last address: (first address, statement)} and the addresses it folds away.

    A chain has to begin with the instruction that *sets* the accumulator, MULA, ADDA or SUBA.
    A MADDA with no such instruction ahead of it adds to whatever the accumulator already held,
    and starting a chain there drops that term without saying so.
    """
    folds, dropped, run = {}, set(), []
    for ins in code:
        m = ARITH.match(ins.uname or "")
        usable = m and not ins.branch and not ins.ibit
        if usable and m.group(2):
            if m.group(1) in ("MUL", "ADD", "SUB"):
                run = [ins]
            else:
                run = run + [ins] if run else []
            continue
        if usable and run and m.group(1) in ("MADD", "MSUB"):
            chain = run + [ins]
            expr = chain_expr(chain, labels, passes)
            if expr:
                folds[ins.addr] = (chain[0].addr, expr)
                dropped.update(c.addr for c in chain[:-1])
        run = []
    return folds, dropped


def cross_pairs(code, entries):
    """{OPMSUB address: (OPMULA address, statement)} for the pairs that are a cross product.

    OPMULA(a, b) followed by OPMSUB(b, a) is the cross product and nothing else is, so the
    operands have to be the same two registers the other way round.  The two have to be adjacent
    with no label between them, or something could reach the OPMSUB with a different ACC.
    """
    folds = {}
    by_addr = {ins.addr: ins for ins in code}
    for ins in code:
        if ins.uname != "OPMULA" or ins.ibit:
            continue
        nxt = by_addr.get(ins.addr + 1)
        if nxt is None or nxt.uname != "OPMSUB" or nxt.ibit or nxt.addr in entries:
            continue
        if (nxt.uf.fs, nxt.uf.ft) != (ins.uf.ft, ins.uf.fs):
            continue
        moved = render_lower(ins.lname, ins.lf)[2] | render_lower(nxt.lname, nxt.lf)[2]
        if {vf(ins.uf.fs), vf(ins.uf.ft), "ACC"} & moved:
            continue
        folds[nxt.addr] = (ins.addr, "%s.xyz = cross(%s, %s);"
                           % (vf(nxt.uf.fd), vf(ins.uf.fs), vf(ins.uf.ft)))
    return folds


def clamp_pairs(code, entries, states):
    """{MINI address: (MAX address, statement)} for an adjacent MAX/MINI pair on one register.

    Both bounds have to be constants the scan already knows, and the MINI has to read exactly
    what the MAX wrote, so the pair is min(max(v, lo), hi) and cannot be anything else.
    """
    folds = {}
    by_addr = {ins.addr: ins for ins in code}
    for ins in code:
        m = ARITH.match(ins.uname or "")
        if not m or m.group(1) != "MAX" or m.group(2) or ins.ibit or ins.branch:
            continue
        nxt = by_addr.get(ins.addr + 1)
        if nxt is None or nxt.ibit or nxt.addr in entries:
            continue
        n = ARITH.match(nxt.uname or "")
        if not n or n.group(1) != "MINI" or n.group(2):
            continue
        if nxt.uf.mask != ins.uf.mask or nxt.uf.fd != ins.uf.fd or nxt.uf.fs != ins.uf.fd:
            continue
        moved = render_lower(ins.lname, ins.lf)[2]
        if {vf(ins.uf.fs), vf(ins.uf.fd), vf(ins.uf.ft), vf(nxt.uf.ft)} & moved:
            continue
        lo = bound_literal(ins, states.get(ins.addr))
        hi = bound_literal(nxt, states.get(nxt.addr))
        if lo is None or hi is None:
            continue
        folds[nxt.addr] = (ins.addr, "%s = clamp(%s, %s, %s);"
                           % (sw(vf(ins.uf.fd), ins.uf.mask), sw(vf(ins.uf.fs), ins.uf.mask),
                              lo, hi))
    return folds


def bound_literal(ins, consts):
    """The literal a MAX/MINI compares against, or None when it is not a known constant."""
    bc = ARITH.match(ins.uname).group(3)
    if bc == "i":
        return fnum(consts.i[0]) if consts and consts.i else None
    if bc == "q":
        return None
    lanes = bc or ins.uf.mask
    if consts is None:
        return None
    found = [consts.lane_at(vf(ins.uf.ft), c) for c in lanes]
    if any(v is None for v in found) or len({v[0] for v in found}) != 1:
        return None
    return fnum(found[0][0])


FLOAT_LITERAL = re.compile(r"^-?(?:\d+\.\d*|\d+)(?:e[-+]?\d+)?f$")


def literal_bits(text):
    """The float32 bits of a plain literal, or None when the text is an expression."""
    if not text or not FLOAT_LITERAL.match(text):
        return None
    return struct.unpack("<I", struct.pack("<f", float(text[:-1])))[0]


def upper_literal(ins):
    """The constant an upper half writes, when it folds to one, or None."""
    m = ARITH.match(ins.uname or "")
    if not m or m.group(2) or not ins.uf.mask or ins.ibit:
        return None
    base, _, bc = m.groups()
    a = sw(vf(ins.uf.fs), ins.uf.mask)
    b = {"i": "I", "q": "Q"}.get(bc) or ("%s.%s" % (vf(ins.uf.ft), bc) if bc
                                         else sw(vf(ins.uf.ft), ins.uf.mask))
    return literal_bits(fold_arith(base, a, b, sw("ACC", ins.uf.mask)))


def load_name(ins, names):
    """(register, name) when an instruction loads a register from a location the table names."""
    if not names or ins.ibit or ins.lname not in ("LQ", "ILW") or not ins.lf.mask:
        return None
    f, integer = ins.lf, ins.lname == "ILW"
    if not integer and not f.ft:
        return None
    reg = vi(f.it) if integer else vf(f.ft)
    if f.is_ == 0:
        for key in ((f.imm11, f.mask[-1] if integer else f.mask), (f.imm11, None)):
            if key in names:
                return (reg, names[key])
        return None
    near = [k[0] for k in names if len(k) == 2 and k[1] == "+"
            and abs(k[0] - f.imm11) <= BASE_WINDOW]
    return (reg, names[(near[0], "+")]) if len(near) == 1 else None


def keeps_alias(ins):
    """The register an instruction steps rather than reloads, which still holds what it held.

    A cursor walking an array is the array's still, which is why a transcription keeps calling it
    by the array's name after `index = index + 1`.
    """
    f, ln = ins.lf, ins.lname
    if ins.ibit:
        return set()
    out = set()
    if ln in ("IADDIU", "IADDI", "ISUBIU") and f.is_ == f.it and f.is_:
        out.add(vi(f.is_))
    if ln in ("LQI", "LQD") and f.is_:
        out.add(vi(f.is_))
    if ln in ("SQI", "SQD") and f.it:
        out.add(vi(f.it))
    # A float register updated from itself is still what it was, adjusted: the screen scale with
    # a term added is the screen scale, and a transcription goes on calling it that.
    m = ARITH.match(ins.uname or "")
    if m and not m.group(2) and ins.uf.mask:
        dst = vf(ins.uf.fd)
        if dst in (vf(ins.uf.fs), vf(ins.uf.ft)):
            out.add(dst)
    if (ins.uname or "").startswith(("FTOI", "ITOF")) or ins.uname == "ABS":
        if ins.uf.ft == ins.uf.fs:
            out.add(vf(ins.uf.ft))
    return out


def link_pointers(code, link_regs):
    """Pointer registers that nothing but a link register is ever stored through.

    A value loaded back through one of these is a link however long it was out in memory, which
    is what makes a JR after a stack pop a return.
    """
    stored, through = {}, set()
    for ins in code:
        if ins.ibit or ins.lname not in ("ISW", "ISWR"):
            continue
        through.add(ins.lf.is_)
        stored.setdefault(ins.lf.is_, set()).add(vi(ins.lf.it))
    return {p for p in through if stored[p] <= link_regs}


def const_step(ins, state, watch, names=None, links=None, pointers=()):
    """Apply one instruction to the constant state, reading the old values before writing."""
    lf, ln = ins.lf, ins.lname
    ints, lanes, immediate = {}, {}, None
    if ins.ibit:
        immediate = ins.lower_word
    elif ln in ("IADDIU", "IADDI", "ISUBIU"):
        imm = lf.imm5 if ln == "IADDI" else lf.imm15
        src = state.int_at(vi(lf.is_))
        if src is not None:
            ints[vi(lf.it)] = src[0] - imm if ln == "ISUBIU" else src[0] + imm
    elif ln in ("IADD", "ISUB", "IAND", "IOR"):
        a, b = state.int_at(vi(lf.is_)), state.int_at(vi(lf.it))
        if a is not None and b is not None:
            ints[vi(lf.id_)] = {"IADD": a[0] + b[0], "ISUB": a[0] - b[0],
                                "IAND": a[0] & b[0], "IOR": a[0] | b[0]}[ln]
    elif ln == "LQ" and lf.is_ == 0 and lf.ft and lf.mask and lf.imm11 in watch:
        values, _, stored = watch[lf.imm11]
        if not set(lf.mask) & stored:
            lanes[vf(lf.ft)] = {c: values[FIELDS.index(c)] for c in lf.mask}
    elif ln == "ILW" and lf.is_ == 0 and lf.mask and lf.imm11 in watch:
        values, _, stored = watch[lf.imm11]
        if lf.mask[-1] not in stored:
            ints[vi(lf.it)] = values[FIELDS.index(lf.mask[-1])] & 0xFFFF
    if not ins.ibit:
        bits = upper_literal(ins)
        if bits is not None:
            lanes.setdefault(vf(ins.uf.fd), {}).update({c: bits for c in ins.uf.mask})
    holds_link = None
    if links is not None and not ins.ibit:
        f, ln = ins.lf, ins.lname
        if ins.addr in links:
            holds_link = links[ins.addr][0]  # a BAL, or a link written straight in
        elif ln == "IADD" and (f.is_ == 0 or f.it == 0) and vi(f.id_) != "vi00":
            source = vi(f.it if f.is_ == 0 else f.is_)
            holds_link = vi(f.id_) if source in state.linked else None
        elif ln in ("ILW", "ILWR") and f.is_ in pointers:
            holds_link = vi(f.it)
    state.kill(ins.reads_writes()[1], keeps_alias(ins))
    if holds_link:
        state.linked.add(holds_link)
    loaded = load_name(ins, names)
    if loaded:
        state.alias[loaded[0]] = loaded[1]
    for reg, values in lanes.items():
        state.set_lanes(reg, values, ins.addr)
    for reg, value in ints.items():
        state.set_int(reg, value, ins.addr)
    if immediate is not None:
        state.i = (immediate, ins.addr)


def const_scan(code, entries, watch, on, names=None, clobber=None, links=None, pointers=()):
    """The constant state before each instruction, and the dynamic jumps it resolves.

    One linear walk.  The state is dropped at every address control can be entered at and after
    every unconditional jump, so a value that reaches an instruction reached it along the only
    path there is, which is what makes a substitution checkable against the lines above it.
    """
    state, snapshots, resolved = Consts(on), {}, {}
    stale, i = False, 0

    def visit(ins):
        nonlocal stale
        if ins.addr in entries or stale:
            state.clear()
            stale = False
        snapshots[ins.addr] = state.copy()
        if ins.lname in ("JR", "JALR"):
            found = state.int_at(vi(ins.lf.is_))
            if found is not None:
                resolved[ins.addr] = found[0]
        const_step(ins, state, watch, names, links, pointers)

    while i < len(code):
        ins = code[i]
        visit(ins)
        if ins.branch and i + 1 < len(code):
            visit(code[i + 1])
            i += 1
            # After an unconditional jump nothing the walk knows still holds.  After a call it
            # is what the routine writes that is gone, when the routine is one this could walk.
            stale = ins.lname in ("B", "JR", "JALR")
            if ins.lname == "BAL":
                wrote = (clobber or {}).get(ins.target, None)
                if wrote is None:
                    stale = True
                else:
                    state.kill(wrote)
        i += 1
    return snapshots, resolved


def successors(code, base, index, resolved):
    """Where control can go from one instruction, or None where the analysis cannot say.

    A branch's own successor is its delay slot, which always runs; the delay slot's successors
    are where the branch went.  A BAL's return point and an unresolved JR are the two places this
    gives up, and giving up means the caller keeps nothing across them.
    """
    ins = code[index]
    if ins.branch:
        return [ins.addr + 1]
    before = code[index - 1] if index else None
    if before is None or not before.branch:
        return [ins.addr + 1]
    if before.lname in BRANCH_COND:
        return [before.target, ins.addr + 1]
    if before.lname == "B":
        return [before.target]
    if before.lname == "BAL":
        return [before.target, ("call", before.target, ins.addr + 1)]
    where = resolved.get(before.addr)
    return [where] if before.lname == "JR" and where is not None else [None]


def const_flow(code, base, unknown, watch, resolved, names=None, clobber=None, links=None,
               pointers=()):
    """The constant state before each instruction, over every path that reaches it.

    A forward analysis run to a fixpoint: a block entry keeps exactly what all of its
    predecessors agree on.  `unknown` names the addresses a jump this cannot follow may land on,
    and those keep nothing, so a value that survives to a line was written on every path to it.
    """
    inn, frozen = {}, set()
    work = []
    unknown = set(unknown)
    # A branch in a delay slot has no settled order, so `successors` cannot enumerate the outer
    # branch's edges.  Everything either of them can reach keeps nothing instead.
    for n, ins in enumerate(code[:-1]):
        if ins.branch and code[n + 1].branch:
            unknown |= {ins.target, code[n + 1].target, code[n + 1].addr + 1} - {None}

    def seed(addr):
        inn[addr] = Consts(True)
        frozen.add(addr)
        work.append(addr)

    seed(code[0].addr)
    for addr in sorted(unknown):
        if base <= addr < base + len(code):
            seed(addr)
    limit = 64 * len(code)
    while limit > 0:
        while work and limit > 0:
            limit -= 1
            addr = work.pop()
            index = addr - base
            if not 0 <= index < len(code):
                continue
            state = inn[addr].copy()
            const_step(code[index], state, watch, names, links, pointers)
            for succ in successors(code, base, index, resolved):
                arriving = state
                if isinstance(succ, tuple):
                    # A call comes back to the address after the delay slot, having written what
                    # the routine writes and nothing else.
                    _, target, succ = succ
                    wrote = (clobber or {}).get(target, None)
                    if wrote is None:
                        continue
                    arriving = state.copy()
                    arriving.kill(wrote)
                if succ is None or succ in frozen or not base <= succ < base + len(code):
                    continue
                merged = arriving if succ not in inn else inn[succ].meet(arriving)
                if succ not in inn or merged.key() != inn[succ].key():
                    inn[succ] = merged.copy()
                    work.append(succ)
        # A block the walk never reached is reachable only through a jump this cannot follow, so
        # it starts over knowing nothing, exactly as the linear scan would have it.
        missing = [ins.addr for ins in code if ins.addr not in inn]
        if not missing:
            break
        seed(missing[0])
    return {ins.addr: inn.get(ins.addr) or Consts(True) for ins in code}


def link_writes(code, here):
    """{write address: (register, return address, target, branch address)} for every link write.

    A BAL is one by definition.  So is `IADDIU R, vi00, K` for an address K in the program when
    the unconditional branch it belongs to writes nothing else to R: that is the manual form of
    the same call, and this game's dispatch is built out of it.
    """
    links = {}
    for n, ins in enumerate(code):
        if ins.ibit:
            continue
        if ins.lname in ("BAL", "JALR") and ins.lf.it:
            links[ins.addr] = (vi(ins.lf.it), ins.addr + 2, ins.target, ins.addr)
            continue
        if ins.lname not in ("IADDIU", "IADDI") or ins.lf.is_ != 0 or not ins.lf.it:
            continue
        value = ins.lf.imm15 if ins.lname == "IADDIU" else ins.lf.imm5
        if value not in here:
            continue
        reg, branch = vi(ins.lf.it), None
        before = code[n - 1] if n else None
        if before is not None and before.branch and before.lname in ("B", "JR"):
            branch = before  # this instruction is that branch's delay slot
        else:
            for other in code[n + 1:n + 4]:
                if reg in other.reads_writes()[1]:
                    break
                if other.branch:
                    branch = other if other.lname in ("B", "JR") else None
                    break
        # A register the branch itself jumps through is that jump's target, not a link.
        if branch is not None and not (branch.lname in ("JR", "JALR")
                                       and vi(branch.lf.is_) == reg):
            links[ins.addr] = (reg, value, branch.target, branch.addr)
    return links


def link_analysis(code, here):
    """Which registers hold nothing but return addresses, and where each subroutine is called.

    A register qualifies when *every* write to it in the program is a link, so a JR on it can
    only go back to a caller.  A write from anywhere else, an ILW restoring a saved link among
    them, disqualifies it: the listing then says where the links are and leaves the jump alone.
    """
    links = link_writes(code, here)
    writes, other = {}, {}
    for ins in code:
        for reg in ins.reads_writes()[1]:
            if not reg.startswith("vi"):
                continue
            writes.setdefault(reg, []).append(ins.addr)
            if ins.addr not in links or links[ins.addr][0] != reg:
                other.setdefault(reg, []).append(ins.addr)
    pure = {reg for reg in writes if reg not in other}
    calls = {}
    for at, (reg, back, target, branch) in sorted(links.items()):
        if target is not None:  # a JALR's target is a register, so it names no routine
            calls.setdefault(target, []).append((branch, reg, back))
    return links, pure, calls


class Routine:
    """One entry point and the code reachable from it without returning.

    `complete` says the walk accounted for every way out.  A routine that is not complete has an
    exit this cannot follow, so its body is a lower bound and nothing may be concluded from what
    it does or does not write.
    """

    def __init__(self, entry):
        self.entry = entry
        self.body = set()
        self.returns = []    # JR on a link register
        self.tails = []      # (address, target) that leave without coming back
        self.calls = []      # (address, target) that come back
        self.unknown = []    # a jump this cannot follow
        self.complete = True

    def span(self):
        return (min(self.body), max(self.body)) if self.body else (self.entry, self.entry)

    def contiguous(self):
        lo, hi = self.span()
        return len(self.body) == hi - lo + 1

    def writes(self):
        return self.written


def walk_routine(entry, code, base, links, link_regs, resolved):
    """The body reachable from one entry, stopping at every return and tail call."""
    out, stack = Routine(entry), [entry]
    here, edges, cur = range(base, base + len(code)), {}, [entry]

    def push(addr):
        edges.setdefault(cur[0], set()).add(addr)
        if addr in here:
            stack.append(addr)
        else:
            out.unknown.append((addr, None))
            out.complete = False

    while stack:
        addr = stack.pop()
        if addr in out.body or addr not in here:
            continue
        out.body.add(addr)
        ins = code[addr - base]
        cur[0] = addr
        if not ins.branch:
            push(addr + 1)
            continue
        out.body.add(addr + 1)  # the delay slot always runs
        edges.setdefault(addr, set()).add(addr + 1)
        cur[0] = addr + 1
        after = addr + 2
        if ins.lname in BRANCH_COND:
            push(ins.target)
            push(after)
        elif ins.lname == "BAL":
            out.calls.append((addr, ins.target))
            push(after)
        elif ins.addr in links or (addr + 1) in links:
            # A link set here or in the delay slot makes this a call whose continuation is the
            # address that link names, which belongs to whoever runs next, not to this routine.
            at = addr if addr in links else addr + 1
            out.tails.append((addr, links[at][2]))
        elif ins.lname == "B":
            push(ins.target)
        elif ins.lname in ("JR", "JALR") and vi(ins.lf.is_) in link_regs:
            out.returns.append(addr)
        elif addr in resolved:
            push(resolved[addr])
        else:
            out.unknown.append((addr, vi(ins.lf.is_)))
            out.complete = False
    out.written, out.edges = set(), edges
    for addr in out.body:
        ins = code[addr - base]
        out.written |= {r for r in ins.reads_writes()[1] if r not in ("mem", "GS")}
        # A branch in a delay slot has no settled order, so the walk cannot claim to have
        # followed every edge out of the pair.
        if ins.branch and addr + 1 in out.body and code[addr + 1 - base].branch:
            out.complete = False
    return out


def live_in(r, code, base, callee_reads):
    """The registers a routine reads before writing them, which is what a caller has to set.

    A forward walk over the body carrying what has certainly been written: a register written on
    only some of the paths into a point is not written, so a read of it is still a read of the
    caller's value.  A call reads whatever its callee reads, less what this routine wrote first.
    """
    written = {r.entry: set()}
    reads, work = set(), [r.entry]
    rounds = 0
    while work and rounds < 64 * (len(r.body) + 1):
        rounds += 1
        addr = work.pop()
        if addr not in written:
            continue
        have = written[addr]
        ins = code[addr - base]
        was_read, wrote = ins.reads_writes()
        if ins.lname == "BAL" and ins.target is not None:
            was_read = set(was_read) | set(callee_reads.get(ins.target, ()))
        reads |= {x for x in was_read
                  if x not in have and x not in ("vf00", "vi00", "mem", "GS")}
        after = have | {x for x in wrote if x not in ("mem", "GS")}
        for succ in r.edges.get(addr, ()):
            if succ not in r.body:
                continue
            merged = after if succ not in written else (written[succ] & after)
            if succ not in written or merged != written[succ]:
                written[succ] = merged
                work.append(succ)
    return reads


def not_a_function(r, code, base, into):
    """Why a routine cannot be lifted out as a C function, or an empty list when it can.

    A function has one entry, one way in, and leaves only by returning.  SDF's code mostly does
    not: it enters the same body at several points to skip work, falls from one routine into the
    next, and transfers away without coming back.  Saying which routines are the exception is
    worth more than pretending the rest are.
    """
    why = []
    if not r.contiguous():
        why.append("its body is not one run")
    if not r.complete:
        why.append("the walk could not follow every exit")
    if r.tails:
        why.append("it leaves without coming back")
    other = sorted(a for a in r.body
                   if a != r.entry and any(s not in r.body for s in into.get(a, ())))
    if other:
        why.append("it is also entered at %s" % " ".join("%04X" % a for a in other))
    lo = r.span()[0]
    before = [code[lo - n - base] for n in (1, 2) if lo - n >= base]
    if before and not any(b.branch and b.lname in ("B", "JR") for b in before):
        why.append("the code above falls into it")
    out = sorted({s for a in r.body for s in r.edges.get(a, ()) if s not in r.body})
    if out:
        why.append("it jumps out to %s" % " ".join("%04X" % a for a in out))
    return why


def entered_from(code, here, resolved, dispatch):
    """{address: what can jump to it}, a computed jump counted as coming from anywhere."""
    into = {}
    for ins in code:
        if ins.target in here:
            into.setdefault(ins.target, set()).add(ins.addr)
    for at, target in resolved.items():
        if target in here:
            into.setdefault(target, set()).add(at)
    for _, candidates, _, _ in dispatch.values():
        for t in candidates:
            if t in here:
                into.setdefault(t, set()).add(None)
    return into


def routine_reads(rs, code, base, link_regs=()):
    """{entry: what a call to it reads}, to a fixpoint, since a routine's calls read too.

    The link register is left out: every routine takes one, so naming it says nothing.
    """
    out = {e: set() for e in rs}
    for _ in range(len(rs) + 1):
        changed = False
        for e, r in rs.items():
            found = live_in(r, code, base, out) - set(link_regs)
            if found != out[e]:
                out[e] = found
                changed = True
        if not changed:
            break
    return out


def routines(code, base, links, calls, dispatch, resolved):
    """{entry: Routine} for every address something enters at, the program's own start included."""
    link_regs = {reg for reg, _, _, _ in links.values()}
    entries = {code[0].addr} | set(calls)
    for _, candidates, _, _ in dispatch.values():
        entries |= {t for t in candidates if base <= t < base + len(code)}
    for reg, back, target, branch in links.values():
        if base <= back < base + len(code):
            entries.add(back)  # where a manual link says the callee will come back to
    return {e: walk_routine(e, code, base, links, link_regs, resolved) for e in sorted(entries)}


def clobbers(rs, entries):
    """{entry: the registers a call to it can write}, or None where that cannot be established.

    A routine qualifies only if the walk followed every way out of it, it does not leave without
    coming back, and every routine it calls qualifies too.  Anything else keeps nothing across
    the call, which is what the listing did before this could be worked out.
    """
    out = {e: (set(r.written) if r.complete and not r.tails and not r.unknown else None)
           for e, r in rs.items()}
    for _ in range(len(rs) + 1):
        changed = False
        for e, r in rs.items():
            if out[e] is None:
                continue
            for _, target in r.calls:
                if target not in out or out.get(target) is None:
                    out[e] = None
                    changed = True
                    break
                if not out[target] <= out[e]:
                    out[e] |= out[target]
                    changed = True
        if not changed:
            break
    else:
        return {e: None for e in rs}  # it did not settle, so nothing here is established
    return out


def routine_map(rs, calls, here):
    """The maximal routines, with the entries that are alternative ways into each."""
    bodies = {e: r.body for e, r in rs.items()}
    inner = {}
    for e, body in sorted(bodies.items()):
        # A body inside another's is a second entry into it; two equal bodies are the same
        # routine, and the lower address represents it.
        outer = [o for o, ob in bodies.items()
                 if o != e and e in ob and (body < ob or (body == ob and o < e))]
        if outer:
            inner.setdefault(max(outer, key=lambda o: (len(bodies[o]), -o)), []).append(e)
    return [e for e in sorted(bodies) if not any(e in v for v in inner.values())], inner


def stack_link_regs(code, links, link_regs):
    """Link registers whose every value is a link, the ones saved to memory included.

    A register written only by a link, or by a load through a pointer that nothing but a link is
    ever stored through, still holds nothing but return addresses however many times it goes out
    to memory and back.  That closes the induction a plain write check cannot.
    """
    out = set()
    for reg in sorted(link_regs):
        loads, ok = set(), True
        for ins in code:
            if ins.ibit or reg not in ins.reads_writes()[1]:
                continue
            if ins.addr in links and links[ins.addr][0] == reg:
                continue  # a link written straight into it
            if ins.lname in ("ILW", "ILWR"):
                loads.add(ins.lf.is_)  # the pointer it came back through
                continue
            ok = False  # written from somewhere this cannot account for
            break
        if not ok or not loads:
            continue
        for ins in code:
            if ins.ibit or ins.lname not in ("ISW", "ISWR") or ins.lf.is_ not in loads:
                continue
            if vi(ins.lf.it) not in link_regs:
                ok = False
                break
        if ok:
            out.add(reg)
    return out


def link_stack(code, reg):
    """Where a link register is stored to memory and read back, which is a return stack.

    This is the usual reason a register carries nothing but return addresses and still cannot be
    proved to: the value goes out to memory and comes back, and this does not follow it.
    """
    saved = [ins.addr for ins in code
             if not ins.ibit and ins.lname in ("ISW", "ISWR") and vi(ins.lf.it) == reg]
    restored = [ins.addr for ins in code
                if not ins.ibit and ins.lname in ("ILW", "ILWR") and vi(ins.lf.it) == reg]
    return saved, restored


def loop_note(code, base, loop, ran):
    """What one loop counts, from the register its branch tests and what the body does to it."""
    start, end, _, at = loop
    branch = code[at - base]
    tested = {vi(branch.lf.is_), vi(branch.lf.it)} - {"vi00"}
    steps = []
    for ins in code[start - base:end - base + 1]:
        if ins.ibit or ins.lname not in ("IADDIU", "IADDI", "ISUBIU"):
            continue
        reg = vi(ins.lf.it)
        if reg not in tested or vi(ins.lf.is_) != reg:
            continue
        imm = ins.lf.imm5 if ins.lname == "IADDI" else ins.lf.imm15
        if ins.lname == "ISUBIU":
            imm = -imm
        steps.append("%s %s %d per iteration (%04X)"
                     % (reg, "+=" if imm > 0 else "-=", abs(imm), ins.addr))
    if steps:
        detail = "; ".join(steps)
    elif tested:
        detail = "tests %s, which the body does not step by a constant" % " ".join(sorted(tested))
    else:
        detail = "no counter register"
    if ran:
        entered = ran["count"].get(start, 0)
        taken = ran["taken"].get(at, 0)
        if entered:
            detail += "; ran %s, went round %s" % (plural(entered, "time"), plural(taken, "time"))
    return "/* loop %04X..%04X: %s */" % (start, end, detail)


def else_blocks(code, base, ranges, here, labels):
    """{if range: (branch that jumps past the else, first address after it)}.

    An if whose body ends in an unconditional branch to somewhere past the block the if skipped
    over is an if/else, provided nothing else enters the second block.  The delay slot has to be
    the body's last instruction, or the branch is jumping out of the middle of something.
    """
    found = {}
    for r in ranges:
        start, end, kind, at = r
        if kind != "if":
            continue
        branch = code[end - 1 - base] if end - 1 >= base else None
        if branch is None or not branch.branch or branch.lname != "B":
            continue
        if branch.addr + 1 != end or branch.target is None:
            continue
        after = branch.target
        if after not in here or after <= end + 1:
            continue
        if any(a in labels for a in range(end + 1, after)):
            continue
        found[r] = (branch.addr, after)
    return found


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


def parse_names(path):
    """{key: name} from the table.

    Keys are (quadword, lane or None or "+") for an address, ("@", entry) for a routine,
    ("!", entry, register) for a record a routine's pointer parameter names, and
    ("#", record, offset) for one of that record's fields.
    """
    names = {}
    if not path:
        return names
    with open(path) as f:
        for line in f:
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            where, name = line.split(None, 1)
            if where.startswith("@"):  # a routine entry, as `@04F6 texcoordTransform`
                names[("@", int(where[1:], 16))] = name.strip()
                continue
            if where.startswith("!"):  # a record: `!00C2 vi02 matPacket`, then `matPacket.3 z`
                entry, reg = where[1:], name.split(None, 1)
                names[("!", int(entry, 16), reg[0])] = reg[1].strip()
                continue
            if "." in where and not where.split(".")[0].isdigit():
                record, _, offset = where.partition(".")
                names[("#", record, int(offset))] = name.strip()
                continue
            if where.endswith("+"):  # a base an index is added to, as `848+ texcoord`
                names[(int(where[:-1], 0), "+")] = name.strip()
                continue
            addr, _, lane = where.partition(".")
            names[(int(addr, 0), lane or None)] = name.strip()
    return names


# An offset this near a named base is that array, one element either side of the index: the
# bases in this image are 48 quadwords apart, so nothing else can fall inside the window.
BASE_WINDOW = 8

MEM_REF = re.compile(r"\b(mem_w|mem)\[(\d+)\](\.[xyzw]+)?")
MEM_BASE = re.compile(r"\b(mem_w|mem)\[(vi\d\d) \+ (\d+)\](\.[xyzw]+)?")
MEM_REG = re.compile(r"\b(mem_w|mem)\[(vi\d\d)( \+ (\d+))?\](\.[xyzw]+)?")


def unnamable(code, names):
    """The name keys no macro can stand for, because the lane is read both ways.

    mem[914].w and mem_w[914].w are the same word as a float and as an integer, so a name defined
    as one would be the wrong type at the other.  Lanes are what decide it: mem[896].xy and
    mem_w[896].w share an address and touch no lane in common, so naming the word is fine.
    """
    kinds = {}
    for ins in code:
        if ins.ibit or ins.lname not in ("LQ", "SQ", "ILW", "ISW"):
            continue
        f, container = ins.lf, "mem_w" if ins.lname in ("ILW", "ISW") else "mem"
        indexed = (f.it if ins.lname in ("SQ", "ISW") else f.is_) != 0
        lanes = {"+"} if indexed else ({f.mask[-1:]} if ins.lname == "ILW" else set(f.mask))
        for lane in lanes:
            kinds.setdefault((f.imm11, lane), set()).add(container)
    both = {key for key, seen in kinds.items() if len(seen) > 1}
    out = set()
    for addr, lane in [k for k in names if len(k) == 2]:
        if lane is None:  # a whole quadword takes every lane's answer
            if any((addr, c) in both for c in FIELDS):
                out.add((addr, lane))
        elif (addr, lane) in both:
            out.add((addr, lane))
    return out


def apply_record(text, records, names, used=None):
    """Rewrite `mem[vi02 + 3]` as `matPacket[3]` where a record says what that register points at.

    Scoped to the routine the record was declared in, since the register is only that pointer
    inside it, and the field name rides as a note rather than as more syntax.
    """
    if not records:
        return text, None
    field = []

    def swap(m):
        record = records.get(m.group(2))
        if not record:
            return m.group(0)
        offset = int(m.group(4) or 0)
        if used is not None:
            used[record] = m.group(2)
        got = names.get(("#", record, offset))
        if got:
            field.append(got)
        return "%s[%d]%s" % (record, offset, m.group(5) or "")

    return MEM_REG.sub(swap, text), (", ".join(dict.fromkeys(field)) if field else None)


def apply_names(text, names, used=None, skip=()):
    """Rewrite `mem[1003]`, `mem_w[903].w` and `mem[vi04 + 848]` as the table names them.

    `used` collects {name: (key, container)} so the caller can define each name as the subscript
    it replaced.  A name is a macro rather than a variable for exactly that reason: the definition
    carries the address and the element type, so the listing stays the C it was.
    """
    if not names:
        return text

    def take(key, container):
        if used is not None:
            used.setdefault(names[key], set()).add((key, container))
        return names[key]

    def swap(m):
        container, addr, lane = m.group(1), int(m.group(2)), (m.group(3) or "")[1:]
        for key in ((addr, lane), (addr, None)):
            if key in names and key not in skip:
                return take(key, container) + ("." + lane if key[1] is None and lane else "")
        # A fixed address inside a named array is an element of it.
        near = [k[0] for k in names if len(k) == 2 and k[1] == "+"
                and 0 <= addr - k[0] <= BASE_WINDOW]
        if len(near) == 1 and (near[0], "+") not in skip:
            return "%s[%d]%s" % (take((near[0], "+"), container), addr - near[0],
                                 "." + lane if lane else "")
        return m.group(0)

    def swap_base(m):
        offset = int(m.group(3))
        near = [k[0] for k in names if len(k) == 2 and k[1] == "+"
                and abs(k[0] - offset) <= BASE_WINDOW]
        if len(near) != 1:  # nothing close, or two bases whose windows overlap
            return m.group(0)
        key = (near[0], "+")
        if key in skip:
            return m.group(0)
        step = offset - near[0]
        index = m.group(2) if not step else "%s %s %d" % (m.group(2), "+-"[step < 0], abs(step))
        return "%s[%s]%s" % (take(key, m.group(1)), index, m.group(4) or "")

    return MEM_REF.sub(swap, MEM_BASE.sub(swap_base, text))


def name_defines(used, path, skipped=()):
    """The `#define` for every name the listing used, and what it left as a subscript."""
    if not used and not skipped:
        return []
    out = ["/* names from %s.  Each is the subscript it stands for, so the listing is still the"
           % path, " * same C it was without them. */"]
    for addr, lane in sorted(skipped):
        out.append("/* mem[%d]%s is read as a float and as an integer, so it keeps its"
                   " subscript */" % (addr, "." + lane if lane else ""))
    for name, sites in sorted(used.items(), key=lambda e: min(k[0][0] for k in e[1])):
        if len(sites) > 1:
            out.append("/* %s is read through more than one of %s: left undefined */"
                       % (name, ", ".join(sorted("%s[%d]" % (c, a) for (a, _), c in sites))))
            continue
        (addr, lane), container = next(iter(sites))
        if lane == "+":
            out.append("#define %-16s (%s + %d)" % (name, container, addr))
        else:
            out.append("#define %-16s %s[%d]%s"
                       % (name, container, addr, "." + lane if lane else ""))
    return out


def unnamed_report(code, names, path):
    """The fixed addresses the table does not name, by how often the listing reaches them.

    The worklist for the table, and for memory-map.md behind it: an address the code keeps
    reaching and nothing names is one nobody has identified yet.
    """
    fixed = {}
    for ins in code:
        if ins.ibit or ins.lname not in ("LQ", "SQ", "ILW", "ISW"):
            continue
        f = ins.lf
        if (f.it if ins.lname in ("SQ", "ISW") else f.is_) != 0:
            continue  # an offset off a register is a field of a record, not an address
        fixed[f.imm11] = fixed.get(f.imm11, 0) + 1
    named = {k[0] for k in names if len(k) == 2 and k[1] != "+"}
    bases = [k[0] for k in names if len(k) == 2 and k[1] == "+"]
    rest = sorted(((n, a) for a, n in fixed.items()
                   if a not in named and not any(0 <= a - b <= BASE_WINDOW for b in bases)),
                  reverse=True)
    if not rest:
        return []
    out, line = ["/* fixed addresses with no name in %s, by uses:" % path], " *  "
    for n, a in rest:
        cell = " mem[%d] (%d)" % (a, n)
        if len(line) + len(cell) > 96:
            out.append(line)
            line = " *  "
        line += cell
    return out + [line, " */"]


REG_TOKEN = re.compile(r"\b(v[fi]\d\d)\b")
SET_CONST = re.compile(r"^vi\d\d = (\d+);$")


def address_note(text, names):
    """The name of the address an integer constant is, when a register is loaded with one."""
    m = SET_CONST.match(text)
    if not m or not names:
        return None
    value = int(m.group(1))
    for key in ((value, "+"), (value, None)):
        if key in names:
            return "%s%s" % (names[key], ", the base" if key[1] == "+" else "")
    return None


def alias_worth(code, states, names):
    """The (register, name) pairs worth printing.

    A name earns its length by being read away from the load: once, on the line after it, it says
    what that line already says.  Read twice, or read anywhere but the next line, it carries.
    """
    made, read = {}, {}
    for ins in code:
        found = load_name(ins, names)
        if found:
            made.setdefault(found, set()).add(ins.addr)
        state = states.get(ins.addr)
        if not state or not state.alias:
            continue
        for reg in ins.reads_writes()[0]:
            if reg in state.alias:
                read.setdefault((reg, state.alias[reg]), set()).add(ins.addr)
    keep = set()
    for key, where in read.items():
        near = made.get(key, set())
        if len(where) >= 2 or any(all(abs(a - d) > 1 for d in near) for a in where):
            keep.add(key)
    return keep


def apply_alias(text, before, after, writes, used=None, keep=None):
    """Print a register under the name of the location it was loaded from, while it holds it.

    The alias is the register, not a copy of it: it is emitted as a macro for the register, so a
    line reads as what it works on and still says which register that is.
    """
    if not before.alias and not after.alias:
        return text

    def swap(m):
        reg = m.group(1)
        name = (after if reg in writes else before).alias.get(reg)
        if not name or (keep is not None and (reg, name) not in keep):
            return reg
        alias = "%s_%s" % (name, reg)
        if used is not None:
            used[alias] = reg
        return alias

    return REG_TOKEN.sub(swap, text)


def merge_folds(*sources):
    """One {last address: (first address, statement)} map, and every address it folds away.

    A later source only gets a span no earlier one has already taken, so two passes can never
    claim the same instruction and the listing keeps exactly one statement per fold.
    """
    folds, dropped = {}, set()
    for source in sources:
        for last, (first, statement) in sorted(source.items()):
            span = set(range(first, last + 1))
            if span & set(folds) or span & dropped:
                continue
            folds[last] = (first, statement)
            dropped |= span - {last}
    return folds, dropped


def translate(prog, others, opts):
    code = [Ins(prog["base"] + i, u, l) for i, (u, l, _) in enumerate(prog["ins"])]
    passes, base = opts["passes"], prog["base"]
    names = opts.get("names") or {}
    # A quadword the program stores to is not the one the sample recorded.
    stored = {}
    for ins in code:
        if ins.ibit:
            continue
        if ins.lname == "SQ" and ins.lf.it == 0:
            stored.setdefault(ins.lf.imm11, set()).update(ins.lf.mask)
        elif ins.lname == "ISW" and ins.lf.is_ == 0:
            stored.setdefault(ins.lf.imm11, set()).update(ins.lf.mask)
    watch = {addr: (lanes, distinct, stored.get(addr, set()))
             for addr, (lanes, distinct) in
             watch_consts(opts["watch"].get(prog["hash"], []), opts["instance"]).items()} \
        if opts["watch"] else {}
    opts = dict(opts, watch_consts=watch)
    here = {ins.addr for ins in code}
    targets = [ins.target for ins in code if ins.target in here]
    dispatch = dispatch_table(code, base)
    links, pure_links, calls = link_analysis(code, here)
    link_regs = {reg for reg, _, _, _ in links.values()}
    pointers = link_pointers(code, link_regs)
    alias_names = {k: v for k, v in names.items()
                   if k not in unnamable(code, names)} if "alias" in passes else None
    linked_at = {branch: (reg, back) for reg, back, _, branch in links.values()}

    # Anything a jump can reach starts a block, so the constant scan drops what it knows there.
    entries = set(targets) | {t for t in calls if t in here}
    for _, candidates, _, _ in dispatch.values():
        entries |= {t for t in candidates if t in here}
    states, resolved, routine, clobber = {}, {}, {}, {}
    for _ in range(4):
        states, resolved = const_scan(code, entries, watch, True, alias_names, clobber,
                                      links, pointers)
        new = {t for t in resolved.values() if t in here} - entries
        if not new:
            break
        entries |= new
    # The routines are what the resolved jumps make walkable, and what they write is what a call
    # to them takes away.  Without one, a call still takes everything.
    routine = routines(code, base, links, calls, dispatch, resolved)
    clobber = clobbers(routine, entries)
    takes = routine_reads(routine, code, base, link_regs) if "call" in passes else {}
    into = entered_from(code, here, resolved, dispatch)
    states, resolved = const_scan(code, entries, watch, True, alias_names, clobber,
                                  links, pointers)
    if "join" in passes:
        # The linear scan settled the dynamic jumps; the join then follows them as real edges.
        states = const_flow(code, base, entries - set(targets) | {code[0].addr}, watch,
                            resolved, alias_names, clobber, links, pointers)

    ranges, breaks = flow_ranges(code, here, targets) if "flow" in passes else ([], {})

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

    def is_call(ins):
        return "call" in passes and ins.lname == "BAL" and ins.addr in links

    def returns(ins):
        """Whether a JR is a return: the register holds a return address where it stands.

        Taken at the jump rather than over the whole program, so a link that went out to a stack
        or through a scratch register still reads as one.
        """
        if "call" not in passes or ins.lname != "JR":
            return False
        state = states.get(ins.addr)
        return vi(ins.lf.is_) in pure_links or bool(state and vi(ins.lf.is_) in state.linked)

    def resolved_target(ins):
        """Where a JR goes when the scan proves its register, which is a constant-fold result."""
        if "const" not in passes or ins.lname != "JR" or returns(ins):
            return None
        return resolved.get(ins.addr)

    def jumps(ins):
        """Whether this branch still prints a goto, so its target still needs a label."""
        if ins.addr in shaped or ins.addr in breaks or is_call(ins):
            return False
        if slicing and not ran["count"].get(ins.addr):
            return False
        return ins.target in here or resolved_target(ins) in here

    def goes_to(ins):
        return ins.target if ins.target in here else resolved_target(ins)

    def label_set(suppressed=()):
        found = {goes_to(ins) for ins in code if jumps(ins) and ins.addr not in suppressed}
        found.discard(None)
        return found

    # The else pass needs the labels to decide, and then absorbs one of them, so the set is taken
    # again without the branches it swallowed.  Dropping labels can only keep the test it made
    # true, never break it.
    labels = label_set()
    elses = else_blocks(code, base, ranges, here, labels) if "else" in passes else {}
    else_at, else_goto = {}, set()
    for r, (branch, after) in elses.items():
        else_at[r[1]] = r
        else_goto.add(branch)
        closes[after - 1] = closes.get(after - 1, 0) + 1
        closes[r[1]] = closes.get(r[1], 0) - 1
    labels = label_set(else_goto)
    incoming = {}
    for ins in code:
        if jumps(ins) and ins.addr not in else_goto and goes_to(ins) in labels:
            incoming.setdefault(goes_to(ins), []).append(ins.addr)

    # Folds are refused across `entries`, every address control can arrive at, rather than across
    # the labels that survive: --flow turns some of those entries into a `do {` with no label.
    folds, dropped = merge_folds(
        acc_chains(code, entries, passes)[0] if {"acc", "mat"} & passes else {},
        cross_pairs(code, entries) if "cross" in passes else {},
        clamp_pairs(code, entries, states) if "clamp" in passes else {})
    fold_span = {}
    for last, (first, _) in folds.items():
        for a in range(first, last):
            fold_span[a] = last

    def inlined(ins, nxt):
        """The branch condition, when the delay slot cannot change it before the branch takes."""
        if "branch" not in passes or ins.lname not in BRANCH_COND:
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
    if calls and "call" in passes:
        maximal, alternates = routine_map(routine, calls, here)
        out.append("/* routines: entry, name, size, returns, callers, callees, other entries,"
                   " what a call")
        out.append(" * writes, and whether one entry and a return are all there is to it. */")

        def shape_of(entry):
            r = routine[entry]
            lo, hi = r.span()
            words = ["%d instructions" % len(r.body)]
            if not r.contiguous():
                words.append("in %04X..%04X" % (lo, hi))
            if r.returns:
                words.append("returns at %s" % " ".join("%04X" % a for a in r.returns))
            for at, target in r.tails:
                words.append("leaves at %04X for %s"
                             % (at, "%04X" % target if target is not None else "a register"))
            if not r.complete:
                words.append("NOT complete: %s" % (" ".join("%04X" % a for a, _ in r.unknown)
                                                   or "a branch in a delay slot"))
            return words

        for entry in sorted(set(maximal) | set(calls) & here):
            r = routine[entry]
            lo, hi = r.span()
            why = not_a_function(routine[entry], code, base, into)
            wrote = clobber.get(entry)
            words = ["%d" % len(r.body)]
            if not r.contiguous():
                words.append("in %04X..%04X" % (lo, hi))
            if r.returns:
                words.append("ret %s" % " ".join("%04X" % a for a in r.returns))
            for at, target in r.tails:
                words.append("leaves %04X" % at)
            if entry in calls:
                words.append("from %s" % " ".join("%04X" % at for at, _, _ in calls[entry]))
            if r.calls:
                words.append("calls %s" % " ".join(sorted({routine_name(t, names)
                                                           for _, t in r.calls})))
            if alternates.get(entry):
                words.append("+%d entries" % len(alternates[entry]))
            words.append("writes %s" % (plural(len(wrote), "register") if wrote else "unknown"))
            words.append("function" if not why else "not a function: " + why[0])
            out.append("/*   %04X %-22s %s */"
                       % (entry, routine_name(entry, names), ", ".join(words)))
        rest = [e for e in maximal if e not in calls and e not in set(maximal) | set(calls)]
        if rest:
            out.append("/*   entry points nothing calls, reached by a jump or by falling in: %s */"
                       % " ".join("%04X (%d)" % (e, len(routine[e].body)) for e in rest))
        seen = set().union(*[r.body for r in routine.values()] or [set()])
        loose = sorted({ins.addr for ins in code} - seen)
        if loose:
            out.append("/*   %s no entry reaches: %s%s */"
                       % ("%d addresses" % len(loose),
                          " ".join("%04X" % a for a in loose[:16]),
                          " ..." if len(loose) > 16 else ""))
        for target in sorted(set(calls) - here):
            out.append("/*   %04X is called but lies outside this program */" % target)
    reached = {}
    for at, (reg, candidates, _, _) in dispatch.items():
        for t in candidates:
            reached.setdefault(t, []).append(at)
    by_reg = {}
    for at, (reg, candidates, set_at, reads) in sorted(dispatch.items()):
        by_reg.setdefault((reg, tuple(candidates), tuple(reads)), []).append(at)
    for (reg, candidates, reads), sites in sorted(by_reg.items(), key=lambda e: e[1][0]):
        out.append("/* %s at %s: %s%s */"
                   % (reg, " ".join("%04X" % a for a in sites),
                      "one of " + " ".join("%04X" % t for t in candidates)
                      if candidates else "no constant reaches it",
                      ", or a value loaded at " + " ".join("%04X" % a for a in reads)
                      if reads else ""))
        for at in sites:
            said = []
            if at in resolved and "const" in passes:
                said.append("%04X here" % resolved[at])
            if ran and ran["targets"].get(at):
                said.append("went to %s in %d runs"
                            % (" ".join("%04X (%d)" % (t, n)
                                        for t, n in sorted(ran["targets"][at].items())),
                               ran["runs"]))
            if said:
                out.append("/*   %04X: %s */" % (at, ", ".join(said)))
    leaving = sorted({ins.target for ins in code
                      if ins.target is not None and ins.target not in here})
    for target in leaving:
        found = elsewhere(target, prog, others)
        out.append("/* %04X leaves this program (it ends at %04X): %s */"
                   % (target, code[-1].addr,
                      "%s, %s" % (", ".join(found[0]), found[1]) if found
                      else "no translated program covers it"))
    fixed = sorted({ins.lf.imm11 for ins in code
                    if ins.lname in ("LQ", "ILW") and ins.lf.is_ == 0 and not ins.ibit})
    if fixed and not names:
        out.append("/* loads from fixed addresses: %s */"
                   % " ".join("mem[%d]" % a for a in fixed))
    if names:
        out += unnamed_report(code, names, opts["names_path"])
    if watch:
        samples = len(opts["watch"][prog["hash"]])
        out.append("/* memory from sample %d of %d in %s: */"
                   % (min(opts["instance"], samples - 1), samples, opts["mem"]))
        for addr, (lanes, distinct, written_lanes) in sorted(watch.items()):
            out.append("/*   mem[%d] = %s%s%s */"
                       % (addr, ", ".join(fnum(v) for v in lanes),
                          "" if distinct == 1 else
                          "   (%d distinct values across the samples)" % distinct,
                          "   (this program writes .%s, so those lanes are not substituted)"
                          % "".join(sorted(written_lanes)) if written_lanes else ""))
            tag = gif_tag(lanes)
            if tag:
                out.append("/*     %s */" % tag)
    named_here, name_slot = {}, len(out)
    no_name = unnamable(code, names) if names else set()
    aliased, records_used = {}, {}
    # A record only names a register inside the routine it was declared for.
    record_at = {}
    for key, name in (names or {}).items():
        if key[0] == "!" and key[1] in routine:
            for addr in routine[key[1]].body:
                record_at.setdefault(addr, {})[key[2]] = name
    # A name is only printed where the register is read under it more than once: read once, on
    # the line after the load, it says what that line already says.
    worth = alias_worth(code, states, alias_names) if "alias" in passes else None
    out += ["void vu1_%s(void)" % prog["hash"][:8].lower(), "{"]
    take_at = len(out)
    out.append("  bool take = false;")

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

    def replaced(at):
        """The statements a fold at this address stands in for, for --audit."""
        lines = []
        for a in range(folds[at.addr][0], at.addr + 1):
            other = code[a - base]
            lines += ["%04X %-11s %s" % (a, mnemonic(other.uname, other.uf, True), text)
                      for text in render_upper(other.uname, other.uf, "const" in passes)[0]]
        return lines

    def render(at, first, extra=None):
        """One instruction's statements, folded, substituted and named."""
        fold = folds.get(at.addr)
        stmts, notes = pair_statements(at, opts, fold[1] if fold else
                                       ("" if at.addr in dropped else None),
                                       fold_span.get(at.addr))
        if elide(at):
            return first
        state = states.get(at.addr) if "const" in passes else None
        state = state or Consts(False)
        skip = {vi(at.lf.is_ if at.lname == "LQD" else at.lf.it)} \
            if not at.ibit and at.lname in ("LQD", "SQD") else set()
        # An upper half that moved into another line rides as a trailing note where there is a
        # line to ride on, and takes one of its own where there is not.
        moved = [n for n in notes if FOLDED_NOTE.search(n)]
        for note in notes:
            if note in moved and stmts:
                continue
            first = put(at, "/* %s */" % note, None, 2, first)
        after = None
        if "alias" in passes:
            after = state.copy()
            const_step(at, after, watch, alias_names)
        for n, (text, mnem) in enumerate(stmts):
            note = "folds %04X..%04X" % (fold[0], at.addr) if fold and text == fold[1] else None
            if note is None and n == 0 and moved:
                note = moved[0]
            if note is None:
                note = address_note(text, names)
            if note is None and extra:
                note, extra = extra, None
            seen = []
            text = apply_names(subst_reads(text, state, seen, skip), names, named_here,
                               no_name)
            text, field = apply_record(text, record_at.get(at.addr), names, records_used)
            if field and note is None:
                note = field
            if after is not None:
                text = apply_alias(text, state, after, at.reads_writes()[1], aliased, worth)
            first = put(at, text, mnem, 2, first, note)
            if opts["audit"] and seen:
                put(at, "/* %s */" % "; ".join(dict.fromkeys(seen)), None, 2, False)
            if opts["audit"] and fold and text == apply_names(
                    subst_reads(fold[1], state, None, skip), names):
                for line in replaced(at):
                    put(at, "/*   %s */" % line, None, 2, False)
        return first

    i, ebit_at = 0, None
    while i < len(code):
        ins = code[i]
        for _ in range(opens.get(ins.addr, 0)):
            if "loops" in passes:
                loop = next((r for r in ranges if r[2] == "do" and r[0] == ins.addr), None)
                if loop:
                    out.append("  " * (depth[0] + 1) + loop_note(code, base, loop, ran))
            put(ins, "do {", None, 2, False)
            depth[0] += 1
        if ins.addr in dead:
            gone = sum(1 for a in range(ins.addr, dead[ins.addr] + 1)
                       if elide(code[a - base]))
            out.append("/* %04X..%04X never ran%s */"
                       % (ins.addr, dead[ins.addr],
                          ", %s omitted" % plural(gone, "instruction") if gone else ""))
        if ins.addr in calls and "call" in passes and not elide(ins):
            out.append("%-70s /* %04X, from %s */"
                       % (prototype(ins.addr, takes.get(ins.addr, ()), names), ins.addr,
                          " ".join("%04X" % at for at, _, _ in calls[ins.addr])))
        if ins.addr in reached and not elide(ins):
            sites = reached[ins.addr]
            out.append("/* a jump at %s%s can reach here */"
                       % (" ".join("%04X" % a for a in sites[:6]),
                          " and %d more" % (len(sites) - 6) if len(sites) > 6 else ""))
        if ins.addr in labels:
            out.append(label_line(ins.addr, incoming.get(ins.addr))
                       + ("  ;" if elide(ins) else ""))
        if ins.ebit:
            ebit_at = ins.addr
        first = render(ins, True)
        last = ins.addr
        if ins.branch and elide(ins):
            # Its delay slot goes with it, unless something still jumps to that address.
            if i + 1 < len(code) and elide(code[i + 1]):
                i += 1
                last = code[i].addr
        elif ins.branch:
            nxt = code[i + 1] if i + 1 < len(code) else None
            inline = inlined(ins, nxt)
            cond, link, target = branch_parts(
                ins, links=links, here=here, passes=passes, pure=returns(ins), names=names,
                resolved=resolved if "const" in passes else None)
            entered = nxt is not None and nxt.addr in labels
            note = None
            if resolved_target(ins) is not None:
                note = "vi%02d holds %04X here" % (ins.lf.is_, resolved[ins.addr])
            elif ins.target is not None and ins.target not in here:
                note = "leaves this program, see the header"
            if ins.addr in linked_at and "call" in passes and not is_call(ins):
                reg, back = linked_at[ins.addr]
                note = "call %s through %s, returns to %04X" % (
                    routine_name(ins.target, names) if ins.target in here else "away", reg, back)
            shape = shaped.get(ins.addr)
            if cond and (shape or ins.addr in breaks):
                target = "break;" if ins.addr in breaks else None
            if ins.addr in else_goto:
                target, note = None, None
            if cond:
                # A condition is all reads, taken at the branch and before the delay slot, so the
                # state above it is the one that decides.  Substituting can leave the constant on
                # the left, which an equality reads better without.
                cond = YODA.sub(r"\3 \2 \1",
                                subst_reads(cond, states.get(ins.addr) or Consts(False)
                                            if "const" in passes else Consts(False)))
            if cond and not inline:
                first = put(ins, "take = (%s);" % cond,
                            mnemonic(ins.lname, ins.lf, False), 2, first)
            if cond and target is not None:
                test = cond if inline else "take"
                # Clearing take keeps the test right for a delay slot the code also jumps into.
                target = ("if (take) { take = false; %s }" % target if entered
                          else "if (%s) %s" % (test, target))
            if link and not is_call(ins):
                first = put(ins, link, mnemonic(ins.lname, ins.lf, False), 2, first,
                            "link register")
            if nxt is not None:
                if nxt.branch:
                    put(nxt, "/* branch in delay slot: this one is taken first */", None, 2, False)
                if entered:
                    out.append("L_%04X:  /* delay slot of %04X, reached with take clear */"
                               % (nxt.addr, ins.addr))
                render(nxt, True, "delay slot of %04X" % ins.addr)
                if nxt.ebit:
                    ebit_at = nxt.addr
                last = nxt.addr
                i += 1
                for _ in range(max(0, closes.pop(nxt.addr, 0))):
                    depth[0] -= 1
                    put(nxt, "}", None, 2, False)
                if nxt.addr in else_at:
                    # The branch is what makes this an else, so the brace carries its mnemonic.
                    depth[0] -= 1
                    first = put(ins, "} else {", mnemonic(ins.lname, ins.lf, False), 2, first)
                    depth[0] += 1
            mnem = mnemonic(ins.lname, ins.lf, False)
            if shape is None and ins.addr in breaks:
                put(ins, target if not entered else "{ take = false; break; }", mnem, 2, first)
            elif shape and shape[2] == "do":
                depth[0] -= 1
                put(ins, "} while (%s);" % (cond if inline else "take"), mnem, 2, first)
            elif shape:
                negated = branch_parts(ins, negate=True)[0]
                if inline and "const" in passes:
                    negated = YODA.sub(r"\3 \2 \1",
                                       subst_reads(negated, states.get(ins.addr) or Consts(False)))
                put(ins, "if (%s) {" % (negated if inline else "!take"), mnem, 2, first)
                depth[0] += 1
            elif target is not None:
                put(ins, target, mnem, 2, first, note)
            elif note:
                put(ins, "/* %s */" % note, mnem, 2, first)
        i += 1
        for _ in range(max(0, closes.pop(last, 0))):
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
    defines = name_defines(named_here, opts["names_path"], no_name)
    called = sorted({links[ins.addr][2] for ins in code if is_call(ins)})
    if called:
        defines.append("/* the routines the calls below name, and what a caller has to set: */")
        defines += ["%-72s /* %04X */" % (prototype(t, takes.get(t, ()), names), t)
                    for t in called]
    if records_used:
        defines.append("/* a register a routine is handed a record through: */")
        defines += ["#define %-24s (mem + %s)" % (rec, reg)
                    for rec, reg in sorted(records_used.items())]
    if aliased:
        defines.append("/* while a register holds one of those, it prints under its name: */")
        defines += ["#define %-24s %s" % (alias, reg)
                    for alias, reg in sorted(aliased.items(), key=lambda e: (e[1], e[0]))]
    if defines:
        out[name_slot:name_slot] = defines + [""]
    return out

def provenance(path, argv, progs):
    return ("/* scripts/vu2c.py %s, from %s, options: %s.\n"
            " * %s, %s.  No timestamp: one input and one set of options\n"
            " * always give the same file. */"
            % (VERSION, path, " ".join(argv[2:]) or "none", plural(len(progs), "program"),
               plural(sum(len(p["ins"]) for p in progs), "instruction")))


# What each pass does and, in the same breath, the precondition that has to hold for it to fire.
# Read together with the instruction words the line still carries, this is what makes a
# simplification checkable rather than believable.
PASS_NOTES = {
    "const": "vf00 is (0, 0, 0, 1) and vi00 is 0; I comes from the nearest LOI and a viNN from"
             " the IADDIU that set it, dropped at every label and after every jump",
    "join": "a constant crosses a label when every path into it carries the same value",
    "alias": "a register loaded from a named location prints under that name until it is loaded"
             " from another, kept through a step and through an update from itself",
    "acc": "a run of ACC writes ending in one vf write prints as one expression",
    "mat": "an ACC chain over consecutive registers broadcasting x, y, z (, w) prints as"
           " mul3x3/mul4x4",
    "cross": "OPMULA(a, b) then OPMSUB(b, a) prints as cross(a, b)",
    "ptr": "LQI/SQI/LQD/SQD print as mem[viNN++] or mem[--viNN]",
    "clamp": "an adjacent MAX/MINI pair against known constants prints as clamp(v, lo, hi)",
    "flow": "a branch whose shape is unambiguous prints as do/while, if or break",
    "else": "an if whose body ends in a branch past the next block prints as if/else",
    "call": "a BAL prints as a call, the routine map above says what each entry reaches, and a"
            " JR on a register only ever written as a link prints as return",
    "loops": "a comment over each loop names its counter and step",
    "branch": "a branch condition is inlined where the delay slot cannot change it",
}

# The preconditions each pass checks are in `vu2c.py --help`; a fold is checkable on its own line
# without them, since the instruction words stay in the address column.


def option_notes(opts):
    """One line per pass.  What each one refuses is in --help, not in every file it writes."""
    on = [n for n in PASSES if n in opts["passes"]]
    if not on:
        return []
    notes = ["/* simplified, and nothing is folded that was not asked for:"]
    for n in on:
        wrapped = textwrap.wrap(PASS_NOTES[n], 84)
        notes.append(" *   %-7s %s" % (n, wrapped[0]))
        notes += [" *           %s" % line for line in wrapped[1:]]
    if opts["audit"]:
        notes.append(" *   --audit  every substituted value is printed under the line that used"
                     " it, with where it was set")
    return ["\n".join(notes) + " */"]


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


def read_jsonl(path):
    with open(path) as f:
        return [json.loads(l) for l in f if l.strip()]


def parse_watch(path):
    """{program: [{quadword: (w0, w1, w2, w3)}]}, one entry per sample, from a VU watch dump."""
    samples = {}
    for row in read_jsonl(path):
        if row.get("type") == "watchHeader":
            continue
        cells = {}
        for quad in row["quads"]:
            b = bytes(quad["u8"])
            cells[quad["mem"]] = tuple(int.from_bytes(b[i:i + 4], "little") for i in range(0, 16, 4))
        samples.setdefault(row["vu"], []).append(cells)
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
    runs = {}
    for entry in read_jsonl(path):
        if entry.get("type") != "run":
            continue
        current = runs.setdefault(entry["vu"], {"runs": 0, "count": {}, "targets": {},
                                                "taken": {}, "entries": {}, "sequence": []})
        current["runs"] += 1
        order = []
        current["sequence"].append({"frame": entry["frame"], "batch": entry["batch"],
                                    "steps": order})
        start = int(entry["entry"], 16)
        current["entries"][start] = current["entries"].get(start, 0) + 1
        for step in entry["rows"]:
            addr = int(step["addr"], 16)
            current["count"][addr] = current["count"].get(addr, 0) + 1
            jumped = []
            if "target" in step:
                target = int(step["target"], 16)
                seen = current["targets"].setdefault(addr, {})
                seen[target] = seen.get(target, 0) + 1
                jumped.append(target)
            if step.get("taken"):
                current["taken"][addr] = current["taken"].get(addr, 0) + 1
            wrote = {w["reg"]: [int(v, 16) for v in w["value"]] for w in step.get("wrote", [])}
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
    # The trace holds the values the hardware wrote, so this substitution needs no analysis: it
    # is a recording, and it is dropped at every write like any other.
    known, last = Consts(True), None
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
        known.kill(ins.reads_writes()[1])
        for reg, words in wrote.items():
            if reg.startswith("vf") and len(words) == 4:
                known.set_lanes(reg, dict(zip(FIELDS, words)), addr)
            elif reg.startswith("vi") and words:
                known.set_int(reg, words[0], addr)
    out.append("}")
    return out


def parse_dump(path):
    progs = []
    for row in read_jsonl(path):
        if row.get("type") not in ("program", "image"):
            continue
        addr = int(row.get("addr", "0"), 16) if isinstance(row.get("addr"), str) else 0
        prog = {"hash": row["hash"], "addr": addr, "uploads": row.get("uploads", 0),
                "base": addr // 8, "ins": [],
                # An image block carries the entry-program hashes an execution trace keys its runs
                # by, since the image itself was never a run's program.
                "aliases": row.get("aliases", [])}
        for ins in row["code"]:
            lower = ins.get("lowerDis")
            if lower is None and "immediate" in ins:
                lower = "[I] %g" % ins["immediate"]
            text = "%-36s %s" % (ins.get("upperDis", "").strip(), (lower or "").strip())
            prog["ins"].append((int(ins["upper"], 16), int(ins["lower"], 16), text.rstrip()))
        progs.append(prog)
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


UPPER_NOP, LOWER_NOP = 0x000002FF, 0x8000033C


def dest(mask):
    return sum(1 << (24 - i) for i, c in enumerate(FIELDS) if c in mask)


def up(op, mask="xyzw", fs=0, ft=0, fd=0, sub=None):
    """An upper word, with `sub` for the bits that pick an entry out of the 0x3C..0x3F tables."""
    return dest(mask) | (ft << 16) | (fs << 11) | ((sub if sub is not None else fd) << 6) | op


def lo(op, it=0, is_=0, imm=0, sub=None, bits=0, mask=""):
    """A lower word.  `sub` picks an entry out of the 0x3C..0x3F tables and replaces `op`."""
    if sub is not None:
        return (0x40 << 25) | (it << 16) | (is_ << 11) | (bits << 6) | sub | dest(mask)
    return (op << 25) | (it << 16) | (is_ << 11) | (imm & 0x7FF) | dest(mask)


def program(pairs):
    return {"hash": "SELFTEST", "addr": 0, "uploads": 0, "base": 0, "aliases": [],
            "ins": [(u, l, "") for u, l in pairs]}


def run_passes(pairs, spec, **extra):
    opts = {"addr": False, "asm": False, "nops": False, "preamble": False, "audit": False,
            "passes": {n.strip() for n in spec.split(",")} if spec else set(),
            "split": None, "mem": None, "watch": None, "instance": 0, "watch_consts": None,
            "names": None, "names_path": None, "exec": None, "runs": None, "trace": None,
            "only_ran": False}
    opts.update(extra)
    prog = program(pairs)
    return "\n".join(translate(prog, [prog], opts))


def selftest():
    """Every pass against the smallest program that shows it firing, and one that must not.

    A pass is only worth having if it refuses the near miss, so each case here is a pair: the
    shape the pass claims, and the shape one register away from it that has to come out unfolded.
    """
    mula_x = up(0x3C, fs=23, ft=3, sub=6)      # MULAx.xyzw ACC = vf23 * vf03.x
    madda_y = up(0x3D, fs=24, ft=3, sub=2)     # MADDAy.xyzw
    madd_z = up(10, fs=25, ft=3, fd=3)         # MADDz.xyzw vf03
    cases = [
        ("mat folds a matrix multiply",
         [(mula_x, LOWER_NOP), (madda_y, LOWER_NOP), (madd_z, LOWER_NOP)],
         "mat", ["vf03.xyzw = mul3x3(vf23, vf03.xyz);"], []),
        ("mat refuses registers that are not consecutive",
         [(mula_x, LOWER_NOP), (up(0x3D, fs=25, ft=3, sub=2), LOWER_NOP),
          (up(10, fs=24, ft=3, fd=3), LOWER_NOP)],
         "mat,acc", [], ["mul3x3"]),
        ("mat refuses a lane order that is not x, y, z",
         [(mula_x, LOWER_NOP), (up(0x3E, fs=24, ft=3, sub=2), LOWER_NOP), (madd_z, LOWER_NOP)],
         "mat,acc", [], ["mul3x3"]),
        # 0000 sets the accumulator, 0001 adds to it, 0002 is the MAXx that ends the run, and
        # 0003 and 0004 add to what 0000 and 0001 left there.  Folding 0003..0004 alone would
        # drop those two terms.
        ("acc refuses a chain that starts at a MADDA",
         [(mula_x, LOWER_NOP), (madda_y, LOWER_NOP), (up(16, fs=5, ft=0, fd=5), LOWER_NOP),
          (up(0x3E, fs=25, ft=3, sub=2), LOWER_NOP), (up(11, fs=26, ft=3, fd=3), LOWER_NOP)],
         "acc,mat", [], ["folds 0003..0004"]),
        # 0002 is the loop head, which --flow prints as `do {` and gives no label.  The chain
        # 0001..0003 crosses it, and every turn after the first arrives with a different
        # accumulator, so it is not one chain.
        ("acc refuses a chain crossing a loop head flow turned into a do",
         [(UPPER_NOP, LOWER_NOP), (mula_x, LOWER_NOP), (madda_y, LOWER_NOP),
          (madd_z, LOWER_NOP), (UPPER_NOP, lo(0x29, it=0, is_=2, imm=-3)),
          (UPPER_NOP, LOWER_NOP)],
         "acc,mat,flow", ["} while"], ["folds 0001..0003"]),
        ("cross folds the OPMULA/OPMSUB pair",
         [(up(0x3E, fs=1, ft=2, sub=11), LOWER_NOP), (up(46, fs=2, ft=1, fd=5), LOWER_NOP)],
         "cross", ["vf05.xyz = cross(vf01, vf02);"], []),
        ("cross refuses operands that are not swapped",
         [(up(0x3E, fs=1, ft=2, sub=11), LOWER_NOP), (up(46, fs=1, ft=2, fd=5), LOWER_NOP)],
         "cross", [], ["cross(vf"]),
        ("const carries an integer into the mask that uses it",
         [(UPPER_NOP, lo(0x08, it=1, is_=0, imm=128)),
          (UPPER_NOP, lo(0x40, it=1, is_=3, sub=0x34, bits=1))],
         "const", ["vi01 = vi03 & 128;"], []),
        ("const drops the integer at a label",
         [(UPPER_NOP, lo(0x08, it=1, is_=0, imm=128)), (UPPER_NOP, lo(0x20, imm=1)),
          (UPPER_NOP, LOWER_NOP), (UPPER_NOP, lo(0x40, it=1, is_=3, sub=0x34, bits=1))],
         "const", ["vi01 = vi03 & vi01;"], ["& 128"]),
        ("const carries I from the LOI above it",
         [(UPPER_NOP | (1 << 31), 0x437F0000),
          (up(31, fs=5, ft=0, fd=5), LOWER_NOP)],
         "const", ["min(vf05.xyzw, 255.0f)"], []),
        ("ptr puts the step in the subscript",
         [(UPPER_NOP, lo(0x40, it=3, is_=4, sub=0x3C, bits=13, mask="xyzw"))],
         "ptr", ["vf03.xyzw = mem[vi04++].xyzw;"], ["vi04++;\n"]),
        ("clamp folds an adjacent max and min",
         [(UPPER_NOP | (1 << 31), 0x437F0000),
          (up(16, fs=3, ft=0, fd=5), LOWER_NOP), (up(31, fs=5, ft=0, fd=5), LOWER_NOP)],
         "const,clamp", ["vf05.xyzw = clamp(vf03.xyzw, 0.0f, 255.0f);"], []),
        ("clamp refuses a min that reads another register",
         [(UPPER_NOP | (1 << 31), 0x437F0000),
          (up(16, fs=3, ft=0, fd=5), LOWER_NOP), (up(31, fs=6, ft=0, fd=6), LOWER_NOP)],
         "const,clamp", [], ["clamp("]),
        ("call names the routine a BAL enters",
         [(UPPER_NOP, lo(0x21, it=15, imm=2)), (UPPER_NOP, LOWER_NOP),
          (UPPER_NOP, LOWER_NOP), (UPPER_NOP, LOWER_NOP)],
         "call", ["sub_0003();", "subroutine(sub_0003, nothing);"], ["vi15 = 0x0002;"]),
        ("call leaves a JR alone when the register is written from elsewhere",
         [(UPPER_NOP, lo(0x21, it=15, imm=2)), (UPPER_NOP, LOWER_NOP),
          (UPPER_NOP, lo(0x08, it=15, is_=2, imm=1)), (UPPER_NOP, lo(0x24, is_=15)),
          (UPPER_NOP, LOWER_NOP)],
         "call", ["goto_micro(vi15);"], ["return;"]),
        # 0000 calls 0003, which pushes the link through vi14, pops it back and jumps on it.
        ("call follows a link out to a stack and back",
         [(UPPER_NOP, lo(0x21, it=15, imm=2)), (UPPER_NOP, LOWER_NOP), (UPPER_NOP, LOWER_NOP),
          (UPPER_NOP, lo(0x05, it=15, is_=14, mask="x")),
          (UPPER_NOP, lo(0x04, it=15, is_=14, mask="x")),
          (UPPER_NOP, lo(0x24, is_=15)), (UPPER_NOP, LOWER_NOP)],
         "const,call", ["return;"], ["goto_micro(vi15)"]),
        # 0000 sets vi01 and 0001 jumps through it: that is the target, not a link.
        ("call does not read a jump target as a link",
         [(UPPER_NOP, lo(0x08, it=1, is_=0, imm=3)), (UPPER_NOP, lo(0x24, is_=1)),
          (UPPER_NOP, LOWER_NOP), (UPPER_NOP, LOWER_NOP)],
         "const,call", ["goto L_0003;"], ["return;", "subroutine("]),
        ("call reads a JR as a return when nothing but a link writes the register",
         [(UPPER_NOP, lo(0x21, it=15, imm=2)), (UPPER_NOP, LOWER_NOP),
          (UPPER_NOP, lo(0x24, is_=15)), (UPPER_NOP, LOWER_NOP)],
         "call", ["return;"], ["goto_micro(vi15)"]),
        ("a folded instruction says where it went, and is not called a nop",
         [(mula_x, LOWER_NOP), (madda_y, LOWER_NOP), (madd_z, LOWER_NOP)],
         "mat", ["MULAx.xyzw folded into 0002"], ["nop"], {"nops": True}),
        # 0000 sets vi01, 0001 branches over 0003, 0002 is its delay slot, 0003 and 0004 are the
        # two arms, and both reach 0005 with vi01 unchanged.
        ("join carries a value both arms agree on past the label",
         [(UPPER_NOP, lo(0x08, it=1, is_=0, imm=7)), (UPPER_NOP, lo(0x29, it=0, is_=2, imm=2)),
          (UPPER_NOP, LOWER_NOP), (UPPER_NOP, LOWER_NOP), (UPPER_NOP, LOWER_NOP),
          (UPPER_NOP, lo(0x40, it=1, is_=3, sub=0x34, bits=1)), (UPPER_NOP, LOWER_NOP)],
         "const,join", ["vi01 = vi03 & 7;"], []),
        ("join drops a value the two arms disagree on",
         [(UPPER_NOP, lo(0x08, it=1, is_=0, imm=7)), (UPPER_NOP, lo(0x29, it=0, is_=2, imm=2)),
          (UPPER_NOP, LOWER_NOP), (UPPER_NOP, lo(0x08, it=1, is_=0, imm=9)),
          (UPPER_NOP, LOWER_NOP),
          (UPPER_NOP, lo(0x40, it=1, is_=3, sub=0x34, bits=1)), (UPPER_NOP, LOWER_NOP)],
         "const,join", ["vi01 = vi03 & vi01;"], ["& 7", "& 9"]),
        ("const alone drops it at the same label",
         [(UPPER_NOP, lo(0x08, it=1, is_=0, imm=7)), (UPPER_NOP, lo(0x29, it=0, is_=2, imm=2)),
          (UPPER_NOP, LOWER_NOP), (UPPER_NOP, LOWER_NOP), (UPPER_NOP, LOWER_NOP),
          (UPPER_NOP, lo(0x40, it=1, is_=3, sub=0x34, bits=1)), (UPPER_NOP, LOWER_NOP)],
         "const", ["vi01 = vi03 & vi01;"], ["& 7"]),
        # 0000 skips to 0004, 0002 jumps past 0005, so 0004..0005 is the else of 0002..0003.
        ("else pairs the two arms of one branch",
         [(UPPER_NOP, lo(0x29, it=0, is_=2, imm=3)), (UPPER_NOP, LOWER_NOP),
          (UPPER_NOP, lo(0x20, imm=3)), (UPPER_NOP, LOWER_NOP),
          (UPPER_NOP, LOWER_NOP), (UPPER_NOP, LOWER_NOP), (UPPER_NOP, LOWER_NOP)],
         "flow,else", ["} else {"], ["goto L_0006;"]),
        # 0002 steps the counter, 0003 branches back to it, 0004 is the delay slot.
        ("loops name the counter and its step",
         [(UPPER_NOP, LOWER_NOP), (UPPER_NOP, LOWER_NOP),
          (UPPER_NOP, lo(0x09, it=2, is_=2, imm=2)), (UPPER_NOP, lo(0x29, it=0, is_=2, imm=-2)),
          (UPPER_NOP, LOWER_NOP), (UPPER_NOP, LOWER_NOP)],
         "flow,loops", ["vi02 -= 2 per iteration (0002)", "} while"], []),
        # 0001 and 0002 are both branches, so which one takes is not settled and nothing they
        # reach may keep a value.  0003 is 0002's target and 0004 the address past the pair.
        ("join keeps nothing across a branch in a delay slot",
         [(UPPER_NOP, lo(0x08, it=1, is_=0, imm=7)), (UPPER_NOP, lo(0x20, imm=3)),
          (UPPER_NOP, lo(0x20, imm=0)), (UPPER_NOP, lo(0x40, it=1, is_=3, sub=0x34, bits=1)),
          (UPPER_NOP, lo(0x40, it=2, is_=3, sub=0x34, bits=2)), (UPPER_NOP, LOWER_NOP)],
         "const,join", ["vi01 = vi03 & vi01;", "vi02 = vi03 & vi02;"], ["& 7"]),
        # 0000 loads vi12 from a named word, 0001 steps it, 0002 reads it, 0003 loads it from
        # a different one, and 0004 reads that.
        ("alias renames a register for as long as it holds a named value",
         [(UPPER_NOP, lo(0x04, it=12, is_=0, imm=898, mask="w")),
          (UPPER_NOP, lo(0x08, it=12, is_=12, imm=1)),
          (UPPER_NOP, lo(0x04, it=4, is_=12, mask="x")),
          (UPPER_NOP, lo(0x04, it=12, is_=0, imm=1021, mask="w")),
          (UPPER_NOP, lo(0x04, it=5, is_=12, mask="x")),
          (UPPER_NOP, lo(0x04, it=6, is_=12, mask="y"))],
         "const,alias",
         ["indexList_vi12 = indexList;", "indexList_vi12 = indexList_vi12 + 1;",
          "vi04 = mem_w[indexList_vi12].x;", "retryHead_vi12 = retryHead;",
          "vi05 = mem_w[retryHead_vi12].x;", "#define indexList_vi12"],
         [],
         {"names": {(898, "w"): "indexList", (1021, "w"): "retryHead"}, "names_path": "t"}),
        ("alias leaves a name off where the register is read under it only once",
         [(UPPER_NOP, lo(0x04, it=12, is_=0, imm=898, mask="w")),
          (UPPER_NOP, lo(0x04, it=4, is_=12, mask="x"))],
         "const,alias", ["vi04 = mem_w[vi12].x;"], ["indexList_vi12"],
         {"names": {(898, "w"): "indexList"}, "names_path": "t"}),
        ("alias drops the name where the register is written from something else",
         [(UPPER_NOP, lo(0x04, it=12, is_=0, imm=898, mask="w")),
          (UPPER_NOP, lo(0x40, it=3, is_=7, sub=0x30, bits=12)),
          (UPPER_NOP, lo(0x04, it=4, is_=12, mask="x"))],
         "const,alias", ["vi04 = mem_w[vi12].x;"], ["mem_w[indexList_vi12]"],
         {"names": {(898, "w"): "indexList"}, "names_path": "t"}),
        ("alias drops the name at a label",
         [(UPPER_NOP, lo(0x04, it=12, is_=0, imm=898, mask="w")),
          (UPPER_NOP, lo(0x20, imm=1)), (UPPER_NOP, LOWER_NOP),
          (UPPER_NOP, lo(0x04, it=4, is_=12, mask="x"))],
         "const,alias", ["vi04 = mem_w[vi12].x;"], ["mem_w[indexList_vi12]"],
         {"names": {(898, "w"): "indexList"}, "names_path": "t"}),
        ("names replace the address and define themselves as it",
         [(UPPER_NOP, lo(0x00, it=3, is_=0, imm=1003, mask="xyzw"))],
         "", ["vf03.xyzw = lightBase.xyzw;", "#define lightBase        mem[1003]"],
         ["vf03.xyzw = mem[1003]."],
         {"names": {(1003, None): "lightBase"}, "names_path": "test"}),
        ("a lane name keeps the container it was read through",
         [(UPPER_NOP, lo(0x04, it=3, is_=0, imm=896, mask="w"))],
         "", ["vi03 = faceCount;", "#define faceCount        mem_w[896].w"], [],
         {"names": {(896, "w"): "faceCount"}, "names_path": "test"}),
        ("a base name becomes the pointer the index is added to",
         [(UPPER_NOP, lo(0x00, it=3, is_=4, imm=848, mask="xyzw"))],
         "", ["vf03.xyzw = texcoord[vi04].xyzw;", "#define texcoord         (mem + 848)"], [],
         {"names": {(848, "+"): "texcoord"}, "names_path": "test"}),
    ]
    bad = 0
    for case in cases:
        name, pairs, spec, want, unwanted = case[:5]
        text = run_passes(pairs, spec, **(case[5] if len(case) > 5 else {}))
        for fragment in want:
            if fragment not in text:
                print("FAIL %s: expected %r" % (name, fragment))
                print(text)
                bad += 1
        for fragment in unwanted:
            if fragment in text:
                print("FAIL %s: did not expect %r" % (name, fragment))
                print(text)
                bad += 1
    print("selftest: %s, %d failed" % (plural(len(cases), "case"), bad))
    return 1 if bad else 0


def main(argv):
    if "--selftest" in argv[1:]:
        return selftest()
    if len(argv) < 2:
        print(USAGE)
        return 2
    path = argv[1]
    wanted, do_list, do_check = [], False, False
    opts = {"addr": True, "asm": True, "nops": False, "preamble": True, "audit": False,
            "passes": set(), "split": None, "mem": None, "watch": None, "instance": 0,
            "watch_consts": None, "names": None, "names_path": None,
            "exec": None, "runs": None, "trace": None, "only_ran": False}
    i = 2

    def enable(spec):
        for name in spec.split(","):
            name = name.strip()
            if name == "all":
                opts["passes"].update(PASSES)
            elif name in PASSES:
                opts["passes"].add(name)
            else:
                raise SystemExit("unknown pass %s, expected one of: %s"
                                 % (name, " ".join(["all"] + PASSES)))

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
        elif a == "--names":
            i += 1
            opts["names_path"] = argv[i]
        elif a == "--simplify":
            i += 1
            enable(argv[i])
        elif a == "--no-simplify":
            i += 1
            opts["passes"].difference_update(n.strip() for n in argv[i].split(","))
        elif a == "--audit":
            opts["audit"] = True
        elif a == "--selftest":
            return selftest()
        elif a == "--clean":
            enable("const,join,alias,acc,mat,cross,ptr,clamp,branch")
        elif a == "--flow":
            enable("flow,else,loops,call")
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
        # Substituting a recorded quadword is the same operation as folding vf00, so --mem
        # brings the pass that does it rather than half of one.
        opts["watch"] = parse_watch(opts["mem"])
        enable("const")
    if opts["names_path"]:
        opts["names"] = parse_names(opts["names_path"])
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

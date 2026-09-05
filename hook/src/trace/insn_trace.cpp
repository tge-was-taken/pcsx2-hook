// SPDX-FileCopyrightText: 2002-2026 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#include "insn_trace.h"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "DebugTools/Debug.h"
#include "Memory.h"
#include "R5900.h"
#include "R5900OpcodeTables.h"
#include "VU.h"
#include "VUmicro.h"
#include "config.h"
#include "diagnostics.h"
#include "dump_dir.h"
#include "pcsx2/Hooks.h"
#include "symbols.h"

namespace pcsx2hook {

namespace {
// PSM maps through the emulator's own tables. The length check keeps a read from running off the
// end of main RAM, which PSM alone does not bound.
const void* readableHost(uint32_t addr, size_t len) {
    if ((addr & 0x1FFFFFFFu) + len > Ps2MemSize::MainRam) return nullptr;
    return PSM(addr);
}
}  // namespace

// 32 wide but aligned to 16, so an unaligned store that crosses a 16-byte boundary
// (swl/swr/sdl/sdr) still lands entirely inside the window. At 16 it did not, which is why swr
// recorded no result.

// A branch interprets its own delay slot through a nested execI, so the bracket re-enters. One
// frame per depth keeps the outer instruction's snapshot intact.

std::string InsnTrace::getOutputDir() {
    const char* env = Config::get().getValue("PCSX2HOOK_INSN_TRACE");
    if (!env || !*env || std::strcmp(env, "1") == 0)
        env = Config::get().getValue("PCSX2HOOK_INSN_SYNTH");
    if (!env || !*env || std::strcmp(env, "1") == 0) return Diagnostics::get().getDumps().getDir();
    return env;
}
bool InsnTrace::isEnabled() {
    static const bool on = Config::get().getValue("PCSX2HOOK_INSN_TRACE") != nullptr ||
                           Config::get().getValue("PCSX2HOOK_INSN_SYNTH") != nullptr;
    return on;
}

InsnTrace::Reg128 InsnTrace::getGpr(uint32_t n) {
    return {cpuRegs.GPR.r[n].UD[0], cpuRegs.GPR.r[n].UD[1]};
}
void InsnTrace::onMem(uint32_t addr, uint64_t value, uint32_t size, bool isRead) {
    for (uint32_t d = mDepth; d-- > 0;) {
        if (d >= kMaxDepth || !mFrames[d].pending) continue;
        if (mFrames[d].accesses.size() < 16)
            mFrames[d].accesses.push_back({addr, size, value, isRead});
        return;
    }
}

void InsnTrace::snapshotWide(Snapshot& s, uint32_t code) {
    const uint32_t op = code >> 26;
    if (op == 0x12 && vuRegs[0].Mem) {
        std::memcpy(s.vuMem, vuRegs[0].Mem, VU0_MEMSIZE);
        std::memcpy(s.vu1Regs, vuRegs[1].VF, sizeof(s.vu1Regs));
        s.hasVuMem = true;
    }
    if (op == 0x10) {
        std::memcpy(s.tlbRaw, tlb, kTlbBytes);
        s.hasTlb = true;
    }
}

void InsnTrace::snapshot(Snapshot& s) {
    for (uint32_t i = 0; i < 32; i++) {
        s.gpr[i] = getGpr(i);
        s.fpr[i] = fpuRegs.fpr[i].UL;
    }
    s.hi = {cpuRegs.HI.UD[0], cpuRegs.HI.UD[1]};
    s.lo = {cpuRegs.LO.UD[0], cpuRegs.LO.UD[1]};
    s.sa = cpuRegs.sa;
    s.fcr31 = fpuRegs.fprc[31];
    s.pc = cpuRegs.pc;
    s.facc = fpuRegs.ACC.UL;
    s.faccFlag = fpuRegs.ACCflag;
    std::memcpy(s.cop0, cpuRegs.CP0.r, sizeof(s.cop0));
    s.hasVuMem = false;
    s.hasTlb = false;
    const VURegs& vu = vuRegs[0];
    for (uint32_t i = 0; i < 32; i++) {
        s.vf[i] = {vu.VF[i].UD[0], vu.VF[i].UD[1]};
        s.vi[i] = vu.VI[i].UL;
    }
    s.acc = {vu.ACC.UD[0], vu.ACC.UD[1]};
    s.q = vu.q.UL;
    s.p = vu.p.UL;
}

// What the effective address actually reaches. Classified on the raw address, before any masking:
//  folds everything into the 32 MB window, so an uncached-mirror MMIO access like
// 0xB000F000 (INTC_STAT) would otherwise record the RAM shadow at 0xF000 as if it were the value
// the instruction saw. Only "ram" gets a recorded window; the rest say where they went instead.
const char* InsnTrace::getAddressRegion(uint32_t raw) {
    if (raw >= 0x70000000 && raw < 0x70004000)
        return "spr";  // scratchpad is not a RAM mirror, it is its own store
    if (raw >= 0xC0000000)
        return "tlb";  // kseg2/3 goes through the TLB, so the mapping is not knowable from the
                       // address
    const uint32_t phys = raw & 0x1FFFFFFF;
    if (phys < 0x02000000) return "ram";
    if (phys >= 0x10000000 && phys < 0x11000000) return "io";
    if (phys >= 0x11000000 && phys < 0x12000000) return "vumem";
    if (phys >= 0x1FC00000) return "bios";
    return "other";
}

bool InsnTrace::getMemoryOperand(uint32_t code, uint32_t& addr) {
    const uint32_t op = code >> 26;
    const bool isLoadStore = op == 0x1A || op == 0x1B || op == 0x1E || op == 0x1F ||
                             (op >= 0x20 && op <= 0x2E) || op == 0x30 || op == 0x31 || op == 0x36 ||
                             op == 0x37 || op == 0x38 || op == 0x39 || op == 0x3E || op == 0x3F;
    if (!isLoadStore) return false;
    const uint32_t base = (code >> 21) & 0x1F;
    const int32_t imm = static_cast<int16_t>(code & 0xFFFF);
    addr = cpuRegs.GPR.r[base].UL[0] + imm;
    return true;
}

void InsnTrace::readMem(uint32_t addr, uint8_t* out) {
    if (const void* p = readableHost(addr, kMemWindow))
        std::memcpy(out, p, kMemWindow);
    else
        std::memset(out, 0, kMemWindow);
}

const std::string& InsnTrace::getMnemonic(uint32_t pc, uint32_t code) {
    const auto it = mMnemonic.find(code);
    if (it != mMnemonic.end()) return it->second;
    std::string text;
    R5900::disR5900Fasm(text, code, pc, false);
    return mMnemonic.emplace(code, text.substr(0, text.find_first_of(" \t,"))).first->second;
}
void InsnTrace::init() {
    if (!isEnabled()) return;
    mArmed = true;
    Hooks::SetInsnSink(&insnBeforeSink, &insnAfterSink);
    Hooks::AddGuestMemSink(&insnMemSink);
    std::fprintf(stderr,
                 "[insn] armed; needs PCSX2HOOK_INTERP=1 (EE interpreter) to see anything\n");
}
void InsnTrace::onBefore(uint32_t pc, uint32_t code) {
    mInstructions++;
    for (uint32_t d = 0; d < mDepth && d < kMaxDepth; d++) {
        if (mFrames[d].pending && !mFrames[d].hasAfterOwn) {
            snapshot(mFrames[d].afterOwn);
            snapshotWide(mFrames[d].afterOwn, mFrames[d].code);
            mFrames[d].hasAfterOwn = true;
        }
        mFrames[d].nested++;
    }
    if (mDepth >= kMaxDepth) {
        mDepth++;
        return;
    }
    Frame& f = mFrames[mDepth++];
    f.pending = false;
    f.nested = 0;
    f.hasAfterOwn = false;
    f.accesses.clear();
    const std::string& mnem = getMnemonic(pc, code);
    if (mInSynth ? mSynthCases[mnem].size() >= kMaxSynthPerForm
                 : mCases[mnem].size() >= kMaxCasesPerForm)
        return;
    f.mnem = &mnem;
    f.code = code;
    snapshot(f.before);
    snapshotWide(f.before, code);
    f.hasMem = getMemoryOperand(code, f.memAddr);
    if (f.hasMem) {
        f.memRegion = getAddressRegion(f.memAddr);
        f.memWindow = f.memAddr & ~(kMemAlign - 1);
        if (std::strcmp(f.memRegion, "ram") == 0) readMem(f.memWindow, f.memBefore);
    }
    f.pending = true;
}
void InsnTrace::onAfter(uint32_t pc, uint32_t code) {
    if (mDepth == 0) return;
    mDepth--;
    if (mDepth >= kMaxDepth) return;
    Frame& f = mFrames[mDepth];
    if (!f.pending) return;
    f.pending = false;
    const Snapshot& sBefore = f.before;
    const std::string& mnem = *f.mnem;

    // Dedup on the operands, not the result: two cases with the same inputs teach nothing new, and
    // a form whose inputs repeat forever would otherwise fill its budget with one case.
    const uint32_t rs = (code >> 21) & 0x1F, rt = (code >> 16) & 0x1F;
    const uint32_t fs = (code >> 11) & 0x1F, ft = rt;
    const uint32_t fsIdx = fs;
    const Reg128 rsVal = sBefore.gpr[rs], rtVal = sBefore.gpr[rt];
    uint64_t key = rsVal.lo ^ (rsVal.hi * 31) ^ (rtVal.lo * 131) ^ (rtVal.hi * 8191);
    key ^= static_cast<uint64_t>(sBefore.fpr[fs]) * 65537;
    key ^= static_cast<uint64_t>(sBefore.fpr[ft]) * 262147;
    key ^= static_cast<uint64_t>(code) << 32;
    key ^= sBefore.hi.lo * 3 ^ sBefore.lo.lo * 7 ^ sBefore.acc.lo * 11;
    key ^= static_cast<uint64_t>(sBefore.sa) * 13 ^ static_cast<uint64_t>(sBefore.fcr31) * 17;
    key ^= static_cast<uint64_t>(sBefore.facc) * 19 ^ static_cast<uint64_t>(sBefore.q) * 23;
    key ^= sBefore.vf[fsIdx].lo * 29 ^ sBefore.vf[rt].lo * 31;
    if (!(mInSynth ? mSynthSeen : mSeen)[mnem].insert(key).second) return;

    Case c{};
    c.pc = pc;
    c.code = code;
    c.rsVal = rsVal;
    c.rtVal = rtVal;
    c.fsVal = sBefore.fpr[fs];
    c.ftVal = sBefore.fpr[ft];
    c.fs = fs;
    c.ft = ft;

    Snapshot after;
    snapshot(after);
    snapshotWide(after, code);
    const Snapshot& result = f.hasAfterOwn ? f.afterOwn : after;
    for (uint32_t i = 1; i < 32; i++) {
        if (!(result.gpr[i] == sBefore.gpr[i]))
            c.deltas.push_back({"gpr", i, sBefore.gpr[i], result.gpr[i]});
        if (result.fpr[i] != sBefore.fpr[i])
            c.deltas.push_back({"fpr", i, {sBefore.fpr[i], 0}, {result.fpr[i], 0}});
    }
    if (result.fpr[0] != sBefore.fpr[0])
        c.deltas.push_back({"fpr", 0, {sBefore.fpr[0], 0}, {result.fpr[0], 0}});
    if (!(result.hi == sBefore.hi)) c.deltas.push_back({"hi", 0, sBefore.hi, result.hi});
    if (!(result.lo == sBefore.lo)) c.deltas.push_back({"lo", 0, sBefore.lo, result.lo});
    if (result.sa != sBefore.sa) c.deltas.push_back({"sa", 0, {sBefore.sa, 0}, {result.sa, 0}});
    if (result.fcr31 != sBefore.fcr31)
        c.deltas.push_back({"fcr31", 0, {sBefore.fcr31, 0}, {result.fcr31, 0}});
    if (result.facc != sBefore.facc)
        c.deltas.push_back({"facc", 0, {sBefore.facc, 0}, {result.facc, 0}});
    if (result.faccFlag != sBefore.faccFlag)
        c.deltas.push_back({"faccflag", 0, {sBefore.faccFlag, 0}, {result.faccFlag, 0}});
    for (uint32_t i = 0; i < 32; i++) {
        if (!(result.vf[i] == sBefore.vf[i]))
            c.deltas.push_back({"vf", i, sBefore.vf[i], result.vf[i]});
        if (result.vi[i] != sBefore.vi[i])
            c.deltas.push_back({"vi", i, {sBefore.vi[i], 0}, {result.vi[i], 0}});
    }
    if (!(result.acc == sBefore.acc)) c.deltas.push_back({"acc", 0, sBefore.acc, result.acc});
    if (result.q != sBefore.q) c.deltas.push_back({"q", 0, {sBefore.q, 0}, {result.q, 0}});
    if (result.p != sBefore.p) c.deltas.push_back({"p", 0, {sBefore.p, 0}, {result.p, 0}});
    const uint32_t fd = (code >> 6) & 0x1F;
    c.hiVal = sBefore.hi;
    c.loVal = sBefore.lo;
    c.saVal = sBefore.sa;
    c.fcr31Val = sBefore.fcr31;
    c.faccVal = sBefore.facc;
    c.faccFlagVal = sBefore.faccFlag;
    std::memcpy(c.cop0In, sBefore.cop0, sizeof(c.cop0In));
    c.cop0StatusVal = sBefore.cop0[12];
    c.accVal = sBefore.acc;
    c.qVal = sBefore.q;
    c.pVal = sBefore.p;
    c.vfsVal = sBefore.vf[fs];
    c.vftVal = sBefore.vf[ft];
    c.vfdVal = sBefore.vf[fd];
    c.visVal = sBefore.vi[fs];
    c.vitVal = sBefore.vi[ft];
    c.vstatus = sBefore.vi[16];
    c.vmac = sBefore.vi[17];
    c.vclip = sBefore.vi[18];
    c.pcBefore = sBefore.pc;
    c.pcAfter = after.pc;
    c.nested = f.nested;

    c.accesses = f.accesses;
    c.hasMem = f.hasMem;
    c.memRegion = f.memRegion;
    c.memWindow = f.memWindow;
    c.memRam = f.hasMem && std::strcmp(f.memRegion, "ram") == 0;
    if (c.memRam) {
        c.memAddr = f.memAddr;
        std::memcpy(c.memBefore, f.memBefore, kMemWindow);
        readMem(f.memWindow, c.memAfter);
    }
    (mInSynth ? mSynthCases : mCases)[mnem].push_back(std::move(c));
}

static const uint64_t EDGE_INT[] = {
    0x0000000000000000ull, 0x0000000000000001ull, 0xFFFFFFFFFFFFFFFFull, 0x0000000000000002ull,
    0xFFFFFFFF80000000ull, 0x000000007FFFFFFFull, 0x00000000FFFFFFFFull, 0x0000000080000000ull,
    0x8000000000000000ull, 0x7FFFFFFFFFFFFFFFull, 0x00000000DEADBEEFull, 0x000000000000000Aull,
};
static const uint32_t EDGE_VI[] = {0x0000u, 0x0001u, 0xFFFFu, 0x7FFFu,
                                   0x8000u, 0x00FFu, 0x0100u, 0x1234u};
static const uint32_t EDGE_FLOAT[] = {
    0x00000000u, 0x80000000u, 0x3F800000u, 0xBF800000u, 0x40000000u, 0x3F000000u,
    0x7F7FFFFFu, 0xFF7FFFFFu, 0x7FFFFFFFu, 0xFFFFFFFFu, 0x7F800000u, 0xFF800000u,
    0x00800000u, 0x00000001u, 0x80000001u, 0x4B000000u,
};
bool InsnTrace::isSynthEnabled() {
    static const bool on = Config::get().getValue("PCSX2HOOK_INSN_SYNTH") != nullptr;
    return on;
}

void InsnTrace::runOne(uint32_t pc, uint32_t code) {
    mSynthRuns++;
    cpuRegs.code = code;
    cpuRegs.pc = pc + 4;
    InsnTrace::onBefore(pc, code);
    R5900::GetInstruction(code).interpret();
    InsnTrace::onAfter(pc, code);
}

bool InsnTrace::isSynthSafe(uint32_t code) {
    const uint32_t op = code >> 26;
    if (op == 0x02 || op == 0x03 || (op >= 0x04 && op <= 0x07) || (op >= 0x14 && op <= 0x17))
        return false;
    if (op == 0x01) return false;
    if (op == 0x10) return false;
    uint32_t unusedAddr = 0;
    if (getMemoryOperand(code, unusedAddr)) return false;
    if (op == 0x00) {
        const uint32_t funct = code & 0x3F;
        if (funct == 0x08 || funct == 0x09 || funct == 0x0C || funct == 0x0D) return false;
    }
    if (op == 0x11 || op == 0x12) {
        const uint32_t rs = (code >> 21) & 0x1F;
        if (rs == 0x08) return false;
    }
    return true;
}
bool InsnTrace::runSynth() {
    if (!isSynthEnabled()) return false;
    std::vector<uint32_t> words;
    std::unordered_set<std::string> covered;
    for (const auto& kv : mCases) {
        if (kv.second.empty()) continue;
        const uint32_t code = kv.second.front().code;
        if (isSynthSafe(code) && covered.insert(kv.first).second) words.push_back(code);
    }
    std::sort(words.begin(), words.end());
    mInSynth = true;
    std::fprintf(stderr, "[synth] driving %zu instruction words with edge operands\n",
                 words.size());
    size_t done = 0;
    mSynthRuns = 0;
    const auto t0 = std::chrono::steady_clock::now();

    const uint32_t pc = 0x00100000;
    for (uint32_t code : words) {
        const uint32_t op = code >> 26;
        const uint32_t rs = (code >> 21) & 0x1F, rt = (code >> 16) & 0x1F;
        const uint32_t fs = (code >> 11) & 0x1F;
        if (++done % 25 == 0)
            std::fprintf(stderr, "[synth] %zu/%zu, %zu runs\n", done, words.size(), mSynthRuns);

        if (op == 0x11) {
            for (uint32_t a : EDGE_FLOAT)
                for (uint32_t b : EDGE_FLOAT) {
                    fpuRegs.fpr[fs].UL = a;
                    fpuRegs.fpr[rt].UL = b;
                    fpuRegs.ACC.UL = a;
                    runOne(pc, code);
                }
        } else if (op == 0x12) {
            for (uint32_t a : EDGE_FLOAT)
                for (uint32_t b : EDGE_FLOAT) {
                    for (uint32_t lane = 0; lane < 4; lane++) {
                        vuRegs[0].VF[fs].UL[lane] = a;
                        vuRegs[0].VF[rt].UL[lane] = b;
                        vuRegs[0].ACC.UL[lane] = a;
                    }
                    runOne(pc, code);
                }
            for (uint32_t a : EDGE_VI)
                for (uint32_t b : EDGE_VI) {
                    vuRegs[0].VI[fs].UL = a;
                    vuRegs[0].VI[rt].UL = b;
                    runOne(pc, code);
                }
        } else {
            for (uint64_t a : EDGE_INT)
                for (uint64_t b : EDGE_INT) {
                    cpuRegs.GPR.r[rs].UD[0] = a;
                    cpuRegs.GPR.r[rs].UD[1] = 0;
                    cpuRegs.GPR.r[rt].UD[0] = b;
                    cpuRegs.GPR.r[rt].UD[1] = 0;
                    cpuRegs.HI.UD[0] = a;
                    cpuRegs.LO.UD[0] = b;
                    runOne(pc, code);
                }
        }
    }
    mInSynth = false;
    size_t n = 0;
    for (const auto& kv : mSynthCases) n += kv.second.size();
    std::fprintf(stderr, "[synth] %zu vectors over %zu forms\n", n, mSynthCases.size());
    return true;
}

void InsnTrace::writeHex(FILE* f, const uint8_t* b) {
    for (uint32_t i = 0; i < kMemWindow; i++) std::fprintf(f, "%02X", b[i]);
}

void InsnTrace::writeCase(FILE* f, const std::string& mnem, const Case& c, bool synthetic) {
    std::fprintf(
        f,
        "{\"mnemonic\":\"%s\",\"pc\":\"%08X\",\"code\":\"%08X\",\"sym\":\"%s\","
        "\"rs\":%u,\"rt\":%u,\"rsVal\":\"%016llX%016llX\",\"rtVal\":\"%016llX%016llX\","
        "\"fs\":%u,\"ft\":%u,\"fsVal\":\"%08X\",\"ftVal\":\"%08X\","
        "\"pcAfter\":\"%08X\",\"nested\":%u,\"in\":{"
        "\"hi\":\"%016llX%016llX\",\"lo\":\"%016llX%016llX\",\"sa\":\"%08X\","
        "\"fcr31\":\"%08X\",\"facc\":\"%08X\",\"faccflag\":\"%08X\",\"cop0status\":\"%08X\","
        "\"acc\":\"%016llX%016llX\",\"q\":\"%08X\",\"p\":\"%08X\",\"fd\":%u,"
        "\"vfs\":\"%016llX%016llX\",\"vft\":\"%016llX%016llX\",\"vfd\":\"%016llX%016llX\","
        "\"vis\":\"%08X\",\"vit\":\"%08X\",\"vstatus\":\"%08X\",\"vmac\":\"%08X\","
        "\"vclip\":\"%08X\"}",
        mnem.c_str(), c.pc, c.code,
        (c.pc & 0x1FFFFFFF) < 0x02000000 ? getSymbols().resolve(c.pc & 0x1FFFFFFF).c_str() : "-",
        (c.code >> 21) & 0x1F, (c.code >> 16) & 0x1F, static_cast<unsigned long long>(c.rsVal.hi),
        static_cast<unsigned long long>(c.rsVal.lo), static_cast<unsigned long long>(c.rtVal.hi),
        static_cast<unsigned long long>(c.rtVal.lo), c.fs, c.ft, c.fsVal, c.ftVal, c.pcAfter,
        c.nested, static_cast<unsigned long long>(c.hiVal.hi),
        static_cast<unsigned long long>(c.hiVal.lo), static_cast<unsigned long long>(c.loVal.hi),
        static_cast<unsigned long long>(c.loVal.lo), c.saVal, c.fcr31Val, c.faccVal, c.faccFlagVal,
        c.cop0StatusVal, static_cast<unsigned long long>(c.accVal.hi),
        static_cast<unsigned long long>(c.accVal.lo), c.qVal, c.pVal, (c.code >> 6) & 0x1F,
        static_cast<unsigned long long>(c.vfsVal.hi), static_cast<unsigned long long>(c.vfsVal.lo),
        static_cast<unsigned long long>(c.vftVal.hi), static_cast<unsigned long long>(c.vftVal.lo),
        static_cast<unsigned long long>(c.vfdVal.hi), static_cast<unsigned long long>(c.vfdVal.lo),
        c.visVal, c.vitVal, c.vstatus, c.vmac, c.vclip);
    std::fprintf(f, ",\"cop0\":[");
    for (uint32_t i = 0; i < 32; i++) std::fprintf(f, "%s\"%08X\"", i ? "," : "", c.cop0In[i]);
    std::fprintf(f, "]");
    if (c.hasMem) {
        std::fprintf(f, ",\"memAddr\":\"%08X\",\"memRegion\":\"%s\"", c.memAddr, c.memRegion);
        if (c.memRam) {
            std::fprintf(f, ",\"memWindow\":\"%08X\",\"memBefore\":\"", c.memWindow);
            writeHex(f, c.memBefore);
            std::fprintf(f, "\",\"memAfter\":\"");
            writeHex(f, c.memAfter);
            std::fprintf(f, "\"");
        }
    }
    if (!c.accesses.empty()) {
        std::fprintf(f, ",\"mem\":[");
        for (size_t i = 0; i < c.accesses.size(); i++) {
            const MemAccess& a = c.accesses[i];
            std::fprintf(f, "%s{\"addr\":\"%08X\",\"size\":%u,\"value\":\"%llX\",\"read\":%s}",
                         i ? "," : "", a.addr, a.size, static_cast<unsigned long long>(a.value),
                         a.isRead ? "true" : "false");
        }
        std::fprintf(f, "]");
    }
    std::fprintf(f, ",\"deltas\":[");
    for (size_t i = 0; i < c.deltas.size(); i++) {
        const RegDelta& d = c.deltas[i];
        std::fprintf(f,
                     "%s{\"file\":\"%s\",\"n\":%u,\"before\":\"%016llX%016llX\",\"after\":\"%"
                     "016llX%016llX\"}",
                     i ? "," : "", d.file, d.index, static_cast<unsigned long long>(d.before.hi),
                     static_cast<unsigned long long>(d.before.lo),
                     static_cast<unsigned long long>(d.after.hi),
                     static_cast<unsigned long long>(d.after.lo));
    }
    std::fprintf(f, "],\"synthetic\":%s}\n", synthetic ? "true" : "false");
    if (synthetic) std::fprintf(f, "");
}
void InsnTrace::write() {
    if (!isEnabled()) return;
    const std::string dir = getOutputDir();
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);

    std::vector<std::string> forms;
    size_t total = 0;
    for (const auto& kv : mCases) {
        if (kv.second.empty()) continue;
        forms.push_back(kv.first);
        total += kv.second.size();
    }
    std::sort(forms.begin(), forms.end());

    FILE* f = std::fopen((dir + "/insn_vectors.jsonl").c_str(), "w");
    if (!f) return;
    for (const std::string& mnem : forms)
        for (const Case& c : mCases[mnem]) writeCase(f, mnem, c, false);
    std::fclose(f);

    if (!mSynthCases.empty()) {
        std::vector<std::string> sf;
        for (const auto& kv : mSynthCases)
            if (!kv.second.empty()) sf.push_back(kv.first);
        std::sort(sf.begin(), sf.end());
        if (FILE* g = std::fopen((dir + "/insn_vectors_synth.jsonl").c_str(), "w")) {
            for (const std::string& mnem : sf)
                for (const Case& c : mSynthCases[mnem]) writeCase(g, mnem, c, true);
            std::fclose(g);
        }
    }

    if (FILE* g = std::fopen((dir + "/insn_forms.tsv").c_str(), "w")) {
        std::fprintf(g, "mnemonic\tcases\n");
        for (const std::string& mnem : forms)
            std::fprintf(g, "%s\t%zu\n", mnem.c_str(), mCases[mnem].size());
        std::fclose(g);
    }

    std::printf("[insn] %s: %zu forms, %zu vectors, over %llu interpreted instructions%s\n",
                dir.c_str(), forms.size(), total, static_cast<unsigned long long>(mInstructions),
                mInstructions == 0 ? " [nothing ran: is PCSX2HOOK_INTERP=1 set?]" : "");
}

void insnBeforeSink(uint32_t pc, uint32_t code) {
    Diagnostics::get().getInsn().onBefore(pc, code);
}

void insnAfterSink(uint32_t pc, uint32_t code) {
    Diagnostics::get().getInsn().onAfter(pc, code);
}

void insnMemSink(uint32_t addr, uint64_t value, uint32_t size, bool isRead) {
    Diagnostics::get().getInsn().onMem(addr, value, size, isRead);
}

}  // namespace pcsx2hook

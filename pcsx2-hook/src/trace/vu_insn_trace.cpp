// SPDX-FileCopyrightText: 2002-2026 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#include "trace/vu_insn_trace.h"
#include "trace/hash.h"
#include "trace/json.h"
#include "trace/table.h"

#include <algorithm>
#include <cstring>
#include <filesystem>

#include "DebugTools/Debug.h"
#include "VU.h"
#include "VUmicro.h"
#include "VUops.h"
#include "config.h"
#include "diagnostics.h"
#include "pcsx2/Hooks.h"

namespace pcsx2hook {

namespace {
constexpr uint32_t kIBit = 1u << 31;
constexpr uint32_t kEBit = 1u << 30;
constexpr uint32_t kMBit = 1u << 29;
constexpr uint32_t kDBit = 1u << 28;
constexpr uint32_t kTBit = 1u << 27;

const char* disassembleUpper(uint32_t unit, uint32_t word, uint32_t pc) {
    return unit ? disVU1MicroUF(word, pc) : disVU0MicroUF(word, pc);
}

const char* disassembleLower(uint32_t unit, uint32_t word, uint32_t pc) {
    return unit ? disVU1MicroLF(word, pc) : disVU0MicroLF(word, pc);
}

const char* skipInterpreterPcPrefix(const char* text) {
    const bool hasPcPrefix = std::strlen(text) > 18 && text[8] == ' ' && text[17] == ':';
    return hasPcPrefix ? text + 18 : text;
}

std::string formName(const char* text) {
    const std::string m = vuMnemonic(text);
    return m.substr(0, m.find('.'));
}
}  // namespace

std::string vuMnemonic(const char* text) {
    const char* c = skipInterpreterPcPrefix(text ? text : "");
    while (*c == ' ' || *c == '\t') c++;
    std::string m;
    while (*c && *c != ' ' && *c != '\t' && *c != ',') m += *c++;
    return m.empty() ? std::string("?") : m;
}

std::string VuInsnTrace::getOutputDir() {
    const char* env = Config::get().getValue("PCSX2HOOK_VU_INSN_TRACE");
    if (!env || !*env || std::strcmp(env, "1") == 0) return Diagnostics::get().getDumps().getDir();
    return env;
}

bool VuInsnTrace::isEnabled() {
    static const bool on = Config::get().getValue("PCSX2HOOK_VU_INSN_TRACE") != nullptr;
    return on;
}

void VuInsnTrace::init() {
    if (!isEnabled()) return;
    Hooks::AddVuInsnSink(&vuInsnBeforeSink, &vuInsnAfterSink);
    Hooks::AddVuMemSink(&vuMemSink);
    if (!CpuVU0->IsInterpreter && !CpuVU1->IsInterpreter)
        std::fprintf(stderr, "[vuinsn] enabled; needs PCSX2HOOK_VU0_INTERP=1 and/or "
                             "PCSX2HOOK_VU1_INTERP=1 to see anything\n");
}

uint32_t VuInsnTrace::addForm(Unit& u, const std::string& name, bool upper) {
    for (uint32_t i = 0; i < u.formNames.size(); i++)
        if (u.formIsUpper[i] == upper && u.formNames[i] == name) return i;
    u.formNames.push_back(name);
    u.formIsUpper.push_back(upper);
    u.formCases.push_back(0);
    return static_cast<uint32_t>(u.formNames.size() - 1);
}

uint32_t VuInsnTrace::getUpperForm(uint32_t unit, uint32_t word) {
    Unit& u = mUnits[unit];
    const auto it = u.upperForms.find(word);
    if (it != u.upperForms.end()) return it->second;
    const uint32_t id = addForm(u, formName(disassembleUpper(unit, word, 0)), true);
    u.upperForms.emplace(word, id);
    return id;
}

uint32_t VuInsnTrace::getLowerForm(uint32_t unit, uint32_t upper, uint32_t lower) {
    Unit& u = mUnits[unit];
    const uint32_t key = (upper & kIBit) ? 0xFFFFFFFFu : lower;
    const auto it = u.lowerForms.find(key);
    if (it != u.lowerForms.end()) return it->second;
    const std::string name = (upper & kIBit) ? std::string("LOI") : formName(disassembleLower(unit, lower, 0));
    const uint32_t id = addForm(u, name, false);
    u.lowerForms.emplace(key, id);
    return id;
}

uint64_t VuInsnTrace::getOperandKey(uint32_t unit, uint32_t upper, uint32_t lower) {
    VURegs& vu = vuRegs[unit];
    _VURegsNum uregs{}, lregs{};
    const u32 savedCode = vu.code;
    vu.code = upper;
    (unit ? VU1regs_UPPER_OPCODE : VU0regs_UPPER_OPCODE)[upper & 0x3f](&uregs);
    if (!(upper & kIBit)) {
        vu.code = lower;
        (unit ? VU1regs_LOWER_OPCODE : VU0regs_LOWER_OPCODE)[lower >> 25](&lregs);
    }
    vu.code = savedCode;

    uint64_t h = (static_cast<uint64_t>(upper) << 32) | lower;
    for (uint32_t r : {uregs.VFread0, uregs.VFread1, lregs.VFread0, lregs.VFread1}) {
        h = hashMix(h, r);
        h = hashMix(h, vu.VF[r].UD[0]);
        h = hashMix(h, vu.VF[r].UD[1]);
    }
    const uint32_t viRead = uregs.VIread | lregs.VIread;
    for (uint32_t r = 0; r < 16; r++)
        if (viRead & (1u << r)) h = hashMix(h, (static_cast<uint64_t>(r) << 32) | vu.VI[r].UL);
    for (uint32_t r = REG_STATUS_FLAG; r <= REG_P; r++) h = hashMix(h, vu.VI[r].UL);
    h = hashMix(h, vu.ACC.UD[0]);
    h = hashMix(h, vu.ACC.UD[1]);
    h = hashMix(h, (static_cast<uint64_t>(vu.fdiv.enable) << 32) | (vu.cycle - vu.fdiv.sCycle));
    h = hashMix(h, (static_cast<uint64_t>(vu.efu.enable) << 32) | (vu.cycle - vu.efu.sCycle));
    h = hashMix(h, (static_cast<uint64_t>(vu.fmaccount) << 32) | vu.ialucount);
    h = hashMix(h, (static_cast<uint64_t>(vu.VIBackupCycles) << 32) | vu.branch);
    return h;
}

void VuInsnTrace::snapshot(const VURegs& vu, State& s) {
    for (int i = 0; i < 32; i++) {
        std::memcpy(s.vf[i], vu.VF[i].UL, sizeof(s.vf[i]));
        s.vi[i] = vu.VI[i].UL;
    }
    std::memcpy(s.acc, vu.ACC.UL, sizeof(s.acc));
    s.q = vu.q.UL;
    s.p = vu.p.UL;
    s.statusflag = vu.statusflag;
    s.macflag = vu.macflag;
    s.clipflag = vu.clipflag;
    std::memcpy(s.fmac, vu.fmac, sizeof(s.fmac));
    s.fmacreadpos = vu.fmacreadpos;
    s.fmaccount = vu.fmaccount;
    s.fdiv = vu.fdiv;
    s.efu = vu.efu;
    std::memcpy(s.ialu, vu.ialu, sizeof(s.ialu));
    s.ialureadpos = vu.ialureadpos;
    s.ialucount = vu.ialucount;
    s.viBackupCycles = vu.VIBackupCycles;
    s.viOldValue = vu.VIOldValue;
    s.viRegNumber = vu.VIRegNumber;
    s.branch = vu.branch;
    s.branchpc = vu.branchpc;
    s.delaybranchpc = vu.delaybranchpc;
    s.takedelaybranch = vu.takedelaybranch;
    s.ebit = vu.ebit;
    s.cycle = vu.cycle;
}

void VuInsnTrace::onBefore(uint32_t unit, uint32_t pc) {
    if (unit > 1) return;
    Unit& u = mUnits[unit];
    u.steps++;
    u.pending = false;
    const uint8_t* micro = vuRegs[unit].Micro + pc * 8;
    uint32_t upper, lower;
    std::memcpy(&lower, micro, 4);
    std::memcpy(&upper, micro + 4, 4);
    const uint32_t uf = getUpperForm(unit, upper);
    const uint32_t lf = getLowerForm(unit, upper, lower);
    if (u.formCases[uf] >= kMaxCasesPerForm && u.formCases[lf] >= kMaxCasesPerForm) return;
    if (!u.seen.insert(getOperandKey(unit, upper, lower)).second) return;

    u.current.pc = pc;
    u.current.upper = upper;
    u.current.lower = lower;
    u.current.upperForm = uf;
    u.current.lowerForm = lf;
    u.current.mem.clear();
    snapshot(vuRegs[unit], u.current.before);
    u.pending = true;
}

void VuInsnTrace::onMem(uint32_t unit, uint32_t addr) {
    if (unit > 1 || !mUnits[unit].pending) return;
    Case& c = mUnits[unit].current;
    MemQuad m{};
    if (unit == 1) {
        m.addr = addr & 0x3ff0;
        m.host = vuRegs[1].Mem + m.addr;
    } else if (addr & 0x4000) {
        m.addr = 0x4000 | (addr & 0x3f0);
        m.host = reinterpret_cast<const uint8_t*>(vuRegs[1].VF) + (addr & 0x3f0);
    } else {
        m.addr = addr & 0xff0;
        m.host = vuRegs[0].Mem + m.addr;
    }
    for (const MemQuad& q : c.mem)
        if (q.addr == m.addr) return;
    if (c.mem.size() >= kMaxMemPerCase) return;
    std::memcpy(m.before, m.host, 16);
    c.mem.push_back(m);
}

void VuInsnTrace::onAfter(uint32_t unit, uint32_t pc) {
    if (unit > 1) return;
    Unit& u = mUnits[unit];
    if (!u.pending) return;
    u.pending = false;
    snapshot(vuRegs[unit], u.current.after);
    for (MemQuad& m : u.current.mem) std::memcpy(m.after, m.host, 16);
    u.formCases[u.current.upperForm]++;
    u.formCases[u.current.lowerForm]++;
    u.cases.push_back(u.current);
}

void VuInsnTrace::writePipe(JsonObject& row, const char* key, const State& s, uint32_t unit) {
    const uint32_t progMask = unit ? VU1_PROGMASK : VU0_PROGMASK;
    row.beginObject(key)
        .addHexDigits("q", s.q, 8)
        .addHexDigits("p", s.p, 8)
        .addHexDigits("status", s.statusflag, 8)
        .addHexDigits("mac", s.macflag, 8)
        .addHexDigits("clip", s.clipflag, 8);
    row.beginObject("fdiv")
        .addUint("enable", s.fdiv.enable)
        .addHexDigits("reg", s.fdiv.reg.UL, 8)
        .addUint("age", s.cycle - s.fdiv.sCycle)
        .addUint("latency", s.fdiv.Cycle)
        .addHexDigits("status", s.fdiv.statusflag, 8)
        .endObject();
    row.beginObject("efu")
        .addUint("enable", s.efu.enable)
        .addHexDigits("reg", s.efu.reg.UL, 8)
        .addUint("age", s.cycle - s.efu.sCycle)
        .addUint("latency", s.efu.Cycle)
        .endObject();
    row.beginArray("fmac");
    for (uint32_t i = 0; i < s.fmaccount; i++) {
        const fmacPipe& f = s.fmac[(s.fmacreadpos + i) & 3];
        row.beginObject()
            .addUint("regupper", f.regupper)
            .addUint("reglower", f.reglower)
            .addInt("flagreg", f.flagreg)
            .addUint("xyzwupper", f.xyzwupper)
            .addUint("xyzwlower", f.xyzwlower)
            .addUint("age", s.cycle - f.sCycle)
            .addUint("latency", f.Cycle)
            .addHexDigits("mac", f.macflag, 8)
            .addHexDigits("status", f.statusflag, 8)
            .addHexDigits("clip", f.clipflag, 8)
            .endObject();
    }
    row.endArray();
    row.beginArray("ialu");
    for (uint32_t i = 0; i < s.ialucount; i++) {
        const ialuPipe& a = s.ialu[(s.ialureadpos + i) & 3];
        row.beginObject()
            .addInt("reg", a.reg)
            .addUint("age", s.cycle - a.sCycle)
            .addUint("latency", a.Cycle)
            .endObject();
    }
    row.endArray();
    row.beginObject("vibackup")
        .addUint("cycles", s.viBackupCycles)
        .addUint("reg", s.viRegNumber)
        .addHexDigits("old", s.viOldValue, 8)
        .endObject();
    row.beginObject("branch")
        .addUint("count", s.branch)
        .addHexDigits("pc", (s.branchpc & progMask) >> 3, 4)
        .addHexDigits("delaypc", (s.delaybranchpc & progMask) >> 3, 4)
        .addBool("takedelay", s.takedelaybranch != 0)
        .endObject();
    row.addUint("ebit", s.ebit);
    row.endObject();
}

void VuInsnTrace::writeCase(FILE* f, uint32_t unit, const Case& c) {
    const Unit& u = mUnits[unit];
    const std::string upperText = vuMnemonic(disassembleUpper(unit, c.upper, c.pc * 8));
    const std::string lowerText =
        (c.upper & kIBit) ? std::string("LOI") : vuMnemonic(disassembleLower(unit, c.lower, c.pc * 8));

    JsonObject row;
    row.addHexDigits("pc", c.pc, 4)
        .addHexDigits("upper", c.upper, 8)
        .addHexDigits("lower", c.lower, 8)
        .addString("uform", u.formNames[c.upperForm].c_str())
        .addString("lform", u.formNames[c.lowerForm].c_str())
        .addString("umnem", upperText.c_str())
        .addString("lmnem", lowerText.c_str())
        .addBool("ibit", c.upper & kIBit)
        .addBool("ebit", c.upper & kEBit)
        .addBool("mbit", c.upper & kMBit)
        .addBool("dbit", c.upper & kDBit)
        .addBool("tbit", c.upper & kTBit)
        .addUint("cycles", c.after.cycle - c.before.cycle);

    row.beginObject("in").beginArray("vf");
    for (int i = 0; i < 32; i++) row.pushHex128(c.before.vf[i]);
    row.endArray().beginArray("vi");
    for (int i = 0; i < 32; i++) row.pushHexDigits(c.before.vi[i], 8);
    row.endArray();
    row.addHex128("acc", c.before.acc);
    row.endObject();
    writePipe(row, "pipeIn", c.before, unit);

    row.beginArray("deltas");
    for (int i = 0; i < 32; i++) {
        if (std::memcmp(c.before.vf[i], c.after.vf[i], 16) == 0) continue;
        row.beginObject().addString("file", "vf").addUint("n", i);
        row.addHex128("before", c.before.vf[i]);
        row.addHex128("after", c.after.vf[i]);
        row.endObject();
    }
    for (int i = 0; i < 32; i++) {
        if (c.before.vi[i] == c.after.vi[i]) continue;
        row.beginObject()
            .addString("file", "vi")
            .addUint("n", i)
            .addHexDigits("before", c.before.vi[i], 8)
            .addHexDigits("after", c.after.vi[i], 8)
            .endObject();
    }
    if (std::memcmp(c.before.acc, c.after.acc, 16) != 0) {
        row.beginObject().addString("file", "acc").addUint("n", 0);
        row.addHex128("before", c.before.acc);
        row.addHex128("after", c.after.acc);
        row.endObject();
    }
    row.endArray();
    writePipe(row, "pipeOut", c.after, unit);

    row.beginArray("mem");
    for (const MemQuad& m : c.mem) {
        row.beginObject().addHexDigits("addr", (m.addr & 0x3fff) >> 4, 4);
        if (m.addr & 0x4000) row.addString("space", "vu1regs");
        row.addHexBytes("before", m.before, 16)
            .addHexBytes("after", m.after, 16)
            .endObject();
    }
    row.endArray();

    const std::string text = row.take();
    std::fwrite(text.data(), 1, text.size(), f);
}

void VuInsnTrace::writeUnit(const std::string& dir, uint32_t unit) {
    const Unit& u = mUnits[unit];
    const std::string prefix = dir + "/vu" + std::to_string(unit);

    std::vector<size_t> order(u.cases.size());
    for (size_t i = 0; i < order.size(); i++) order[i] = i;
    std::stable_sort(order.begin(), order.end(), [&u](size_t a, size_t b) {
        const Case& x = u.cases[a];
        const Case& y = u.cases[b];
        return u.formNames[x.upperForm] + "/" + u.formNames[x.lowerForm] <
               u.formNames[y.upperForm] + "/" + u.formNames[y.lowerForm];
    });
    if (FILE* f = std::fopen((prefix + "_vectors.jsonl").c_str(), "w")) {
        for (size_t i : order) writeCase(f, unit, u.cases[i]);
        std::fclose(f);
    }

    std::vector<uint32_t> forms;
    for (uint32_t i = 0; i < u.formNames.size(); i++)
        if (u.formCases[i] > 0) forms.push_back(i);
    std::sort(forms.begin(), forms.end(), [&u](uint32_t a, uint32_t b) {
        if (u.formIsUpper[a] != u.formIsUpper[b]) return u.formIsUpper[a] > u.formIsUpper[b];
        return u.formNames[a] < u.formNames[b];
    });
    if (FILE* g = std::fopen((prefix + "_forms.jsonl").c_str(), "w")) {
        JsonTable t(g, {"form", "half", "cases"});
        for (uint32_t i : forms)
            t.addString(u.formNames[i].c_str())
                .addString(u.formIsUpper[i] ? "upper" : "lower")
                .addUint(u.formCases[i])
                .endRow();
        std::fclose(g);
    }

    const bool interpreted = unit ? CpuVU1->IsInterpreter : CpuVU0->IsInterpreter;
    std::printf("[vuinsn] %s: VU%u %zu forms, %zu vectors, over %llu interpreted steps%s\n",
                dir.c_str(), unit, forms.size(), u.cases.size(),
                static_cast<unsigned long long>(u.steps),
                interpreted ? "" : " [on the recompiler, so nothing is seen: interpret this unit]");
}

void VuInsnTrace::write() {
    if (!isEnabled()) return;
    const std::string dir = getOutputDir();
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);
    for (uint32_t unit = 0; unit < 2; unit++) writeUnit(dir, unit);
}

void vuInsnBeforeSink(uint32_t unit, uint32_t pc) {
    Diagnostics::get().getVuInsn().onBefore(unit, pc);
}

void vuInsnAfterSink(uint32_t unit, uint32_t pc) {
    Diagnostics::get().getVuInsn().onAfter(unit, pc);
}

void vuMemSink(uint32_t unit, uint32_t addr) {
    Diagnostics::get().getVuInsn().onMem(unit, addr);
}

}  // namespace pcsx2hook

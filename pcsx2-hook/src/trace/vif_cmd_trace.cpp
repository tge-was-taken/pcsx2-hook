// SPDX-FileCopyrightText: 2002-2026 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#include "trace/vif_cmd_trace.h"
#include "trace/hash.h"
#include "trace/json.h"
#include "trace/table.h"

#include <algorithm>
#include <cstring>
#include <filesystem>

#include "VU.h"
#include "VUmicro.h"
#include "Vif.h"
#include "Vif_Dma.h"
#include "config.h"
#include "diagnostics.h"
#include "pcsx2/Hooks.h"

namespace pcsx2hook {

namespace {
constexpr uint32_t kCmdMpg = 0x4A;

bool isUnpack(uint32_t cmd) {
    return (cmd & 0x60) == 0x60;
}

bool writesVuMemory(uint32_t cmd) {
    return isUnpack(cmd) || cmd == kCmdMpg;
}

vifStruct& getVif(uint32_t idx) {
    return idx ? vif1 : vif0;
}

VIFregisters& getVifRegs(uint32_t idx) {
    return idx ? vif1Regs : vif0Regs;
}

uint8_t* getDataMem(uint32_t idx, uint32_t& size) {
    size = idx ? VU1_MEMSIZE : VU0_MEMSIZE;
    return vuRegs[idx].Mem;
}

uint8_t* getMicroMem(uint32_t idx, uint32_t& size) {
    size = idx ? VU1_PROGSIZE : VU0_PROGSIZE;
    return vuRegs[idx].Micro;
}

}  // namespace

const char* VifCmdTrace::getCommandName(uint32_t cmd) {
    switch (cmd) {
        case 0x00: return "NOP";
        case 0x01: return "STCYCL";
        case 0x02: return "OFFSET";
        case 0x03: return "BASE";
        case 0x04: return "ITOP";
        case 0x05: return "STMOD";
        case 0x06: return "MSKPATH3";
        case 0x07: return "MARK";
        case 0x10: return "FLUSHE";
        case 0x11: return "FLUSH";
        case 0x13: return "FLUSHA";
        case 0x14: return "MSCAL";
        case 0x15: return "MSCALF";
        case 0x17: return "MSCNT";
        case 0x20: return "STMASK";
        case 0x30: return "STROW";
        case 0x31: return "STCOL";
        case 0x4A: return "MPG";
        case 0x50: return "DIRECT";
        case 0x51: return "DIRECTHL";
        default: break;
    }
    if (isUnpack(cmd)) {
        static const char* const kNames[16] = {
            "UNPACK_S_32", "UNPACK_S_16", "UNPACK_S_8", "UNPACK_S_5", "UNPACK_V2_32", "UNPACK_V2_16",
            "UNPACK_V2_8", "UNPACK_V2_5", "UNPACK_V3_32", "UNPACK_V3_16", "UNPACK_V3_8",
            "UNPACK_V3_5", "UNPACK_V4_32", "UNPACK_V4_16", "UNPACK_V4_8", "UNPACK_V4_5"};
        return kNames[cmd & 0xf];
    }
    return nullptr;
}

std::string VifCmdTrace::getOutputDir() {
    const char* env = Config::get().getValue("PCSX2HOOK_VIF_CMD_TRACE");
    if (!env || !*env || std::strcmp(env, "1") == 0) return Diagnostics::get().getDumps().getDir();
    return env;
}

bool VifCmdTrace::isEnabled() {
    static const bool on = Config::get().getValue("PCSX2HOOK_VIF_CMD_TRACE") != nullptr;
    return on;
}

void VifCmdTrace::init() {
    if (!isEnabled()) return;
    Hooks::AddVifCmdSink(&vifCmdBeforeSink, &vifCmdAfterSink);
    std::fprintf(stderr, "[vifcmd] recording VIFcode vectors\n");
}

void VifCmdTrace::snapshotRegs(uint32_t idx, Regs& r) {
    const VIFregisters& v = getVifRegs(idx);
    const vifStruct& x = getVif(idx);
    r.stat = v.stat._u32;
    r.err = v.err._u32;
    r.mark = v.mark;
    r.cl = v.cycle.cl;
    r.wl = v.cycle.wl;
    r.mode = v.mode;
    r.num = v.num;
    r.mask = v.mask;
    r.code = v.code;
    r.itops = v.itops;
    r.base = v.base;
    r.ofst = v.ofst;
    r.tops = v.tops;
    r.itop = v.itop;
    r.top = v.top;
    r.mskpath3 = v.mskpath3;
    const uint32_t row[4] = {v.r0, v.r1, v.r2, v.r3};
    const uint32_t col[4] = {v.c0, v.c1, v.c2, v.c3};
    std::memcpy(r.row, row, sizeof(r.row));
    std::memcpy(r.col, col, sizeof(r.col));
    std::memcpy(r.maskRow, &x.MaskRow, sizeof(r.maskRow));
    std::memcpy(r.maskCol, &x.MaskCol, sizeof(r.maskCol));
}

std::string VifCmdTrace::getFormName(uint32_t idx, uint32_t cmd, uint32_t code, const Regs& r) {
    const char* n = getCommandName(cmd);
    char buf[16];
    std::snprintf(buf, sizeof(buf), "CMD%02X", cmd);
    std::string name = std::string(idx ? "vif1:" : "vif0:") + (n ? n : buf);
    if (!isUnpack(cmd)) return name;
    if (cmd & 0x10) name += ".mask";
    if (code & (1u << 14)) name += ".usn";
    if (idx && (code & (1u << 15))) name += ".tops";
    name += ".mode" + std::to_string(r.mode & 3);
    const uint32_t wl = r.wl ? r.wl : 256;
    name += wl == r.cl ? ".normal" : (wl < r.cl ? ".skip" : ".fill");
    return name;
}

uint64_t VifCmdTrace::getStateKey(const Case& c) {
    const Regs& r = c.before;
    uint64_t h = c.code;
    for (uint32_t v : {r.cl, r.wl, r.mode, r.mask, r.tops, r.stat & 0x80u, c.startAligned})
        h = hashMix(h, v);
    for (int i = 0; i < 4; i++) h = hashMix(h, (static_cast<uint64_t>(r.maskRow[i]) << 32) | r.maskCol[i]);
    return h;
}

void VifCmdTrace::getWindow(uint32_t idx, uint32_t cmd, Case& c) {
    const vifStruct& x = getVif(idx);
    const uint32_t num = ((c.code >> 16) & 0xff) ? ((c.code >> 16) & 0xff) : 256;
    if (cmd == kCmdMpg) {
        const uint32_t start = (c.code & 0xffff) * 8;
        c.windowAddr = start & ~15u;
        c.windowQuads = (start + num * 8 - c.windowAddr + 15) / 16;
        return;
    }
    const uint32_t cl = c.before.cl;
    const uint32_t wl = c.before.wl ? c.before.wl : 256;
    c.windowAddr = x.tag.addr;
    c.windowQuads = wl <= cl ? ((num - 1) / wl) * cl + (num - 1) % wl + 1 : num;
}

void VifCmdTrace::startCommand(uint32_t idx, Pending& p) {
    mCommands++;
    p.active = true;
    p.skip = false;
    p.keyChecked = false;
    p.diffing = false;
    p.c = Case{};
    p.c.idx = idx;
    const uint32_t cmd = getVif(idx).cmd & 0x7f;
    snapshotRegs(idx, p.c.before);
    p.c.code = p.c.before.code;
    p.c.form = getFormName(idx, cmd, p.c.code, p.c.before);
    if (mFormCases[p.c.form] >= kMaxCasesPerForm) p.skip = true;
}

void VifCmdTrace::onBefore(uint32_t idx, const uint32_t* data, uint32_t pass) {
    if (idx > 1) return;
    Pending& p = mPending[idx];
    const bool stalledRetry = p.active && pass == 0 && data == p.lastData && p.lastConsumed == 0;
    const bool previousAbandoned = p.active && pass == 0 && !stalledRetry && p.c.passes > 0;
    if (previousAbandoned) {
        mAbandoned++;
        p.active = false;
    }
    if (!p.active) startCommand(idx, p);
    p.lastData = data;
    p.diffing = false;
    if (p.skip) return;
    p.c.passes++;

    const vifStruct& x = getVif(idx);
    const uint32_t cmd = x.cmd & 0x7f;
    if (pass < 1 || !writesVuMemory(cmd)) return;

    if (!p.keyChecked) {
        p.keyChecked = true;
        p.c.startAligned = x.start_aligned;
        uint64_t key = getStateKey(p.c);
        const uint32_t n = std::min<uint32_t>(std::min<uint32_t>(x.vifpacketsize, x.tag.size), 1024);
        for (uint32_t i = 0; i < n; i++) key = hashMix(key, data[i]);
        if (!mSeen.insert(key).second) {
            p.skip = true;
            return;
        }
    }
    uint32_t size = 0;
    p.diffMicro = cmd == kCmdMpg;
    const uint8_t* mem = p.diffMicro ? getMicroMem(idx, size) : getDataMem(idx, size);
    if (p.c.windowQuads == 0) {
        getWindow(idx, cmd, p.c);
        auto& quads = p.diffMicro ? p.c.micro : p.c.data;
        for (uint32_t i = 0; i < p.c.windowQuads && i < size / 16; i++) {
            Quad q{};
            q.addr = (p.c.windowAddr + i * 16) % size;
            std::memcpy(q.before, mem + q.addr, 16);
            std::memcpy(q.after, mem + q.addr, 16);
            q.inWindow = true;
            quads.emplace(q.addr, q);
        }
    }
    p.memBefore.assign(mem, mem + size);
    p.diffing = true;
}

void VifCmdTrace::onAfter(uint32_t idx, const uint32_t* data, uint32_t consumed, bool done) {
    if (idx > 1) return;
    Pending& p = mPending[idx];
    if (!p.active) return;
    p.lastConsumed = consumed;
    if (!p.skip) {
        for (uint32_t i = 0; i < consumed; i++) {
            if (p.c.payload.size() >= kMaxPayloadWords) {
                p.c.payloadTruncated = true;
                break;
            }
            p.c.payload.push_back(data[i]);
        }
        if (p.diffing) {
            uint32_t size = 0;
            const uint8_t* mem = p.diffMicro ? getMicroMem(idx, size) : getDataMem(idx, size);
            if (p.memBefore.size() == size) {
                auto& quads = p.diffMicro ? p.c.micro : p.c.data;
                for (uint32_t a = 0; a < size; a += 16) {
                    if (std::memcmp(mem + a, p.memBefore.data() + a, 16) == 0) continue;
                    auto it = quads.find(a);
                    if (it == quads.end()) {
                        Quad q{};
                        q.addr = a;
                        q.inWindow = false;
                        std::memcpy(q.before, p.memBefore.data() + a, 16);
                        it = quads.emplace(a, q).first;
                    }
                    std::memcpy(it->second.after, mem + a, 16);
                }
            }
            p.diffing = false;
        }
    }
    if (!done) return;
    p.active = false;
    if (p.skip) return;

    const uint32_t cmd = (p.c.code >> 24) & 0x7f;
    if (isUnpack(cmd)) {
        std::memcpy(p.c.tail, data + consumed, 16);
        p.c.hasTail = true;
    }
    snapshotRegs(idx, p.c.after);
    if (!p.keyChecked) {
        uint64_t key = getStateKey(p.c);
        for (uint32_t w : p.c.payload) key = hashMix(key, w);
        if (!mSeen.insert(key).second) return;
    }
    mFormCases[p.c.form]++;
    mCases.push_back(std::move(p.c));
}

namespace {
void writeRegs(JsonObject& row, const char* key, const VifCmdTrace::Regs& r) {
    row.beginObject(key)
        .addHexDigits("stat", r.stat, 8)
        .addHexDigits("err", r.err, 8)
        .addHexDigits("mark", r.mark, 4)
        .addUint("cl", r.cl)
        .addUint("wl", r.wl)
        .addUint("mode", r.mode)
        .addUint("num", r.num)
        .addHexDigits("mask", r.mask, 8)
        .addHexDigits("code", r.code, 8)
        .addHexDigits("itops", r.itops, 4)
        .addHexDigits("base", r.base, 4)
        .addHexDigits("ofst", r.ofst, 4)
        .addHexDigits("tops", r.tops, 4)
        .addHexDigits("itop", r.itop, 4)
        .addHexDigits("top", r.top, 4)
        .addHexDigits("mskpath3", r.mskpath3, 8);
    row.beginArray("row");
    for (uint32_t v : r.row) row.pushHexDigits(v, 8);
    row.endArray().beginArray("col");
    for (uint32_t v : r.col) row.pushHexDigits(v, 8);
    row.endArray().beginArray("maskRow");
    for (uint32_t v : r.maskRow) row.pushHexDigits(v, 8);
    row.endArray().beginArray("maskCol");
    for (uint32_t v : r.maskCol) row.pushHexDigits(v, 8);
    row.endArray().endObject();
}

void writeQuads(JsonObject& row, const char* key, const std::map<uint32_t, VifCmdTrace::Quad>& q) {
    row.beginArray(key);
    for (const auto& [addr, quad] : q) {
        row.beginObject()
            .addHexDigits("addr", addr >> 4, 4)
            .addHexBytes("before", quad.before, 16)
            .addHexBytes("after", quad.after, 16);
        if (!quad.inWindow) row.addBool("outsideWindow", true);
        row.endObject();
    }
    row.endArray();
}
}  // namespace

void VifCmdTrace::writeCase(FILE* f, const Case& c) {
    JsonObject row;
    row.addUint("vif", c.idx)
        .addString("form", c.form.c_str())
        .addHexDigits("code", c.code, 8)
        .addBool("irq", c.code >> 31)
        .addUint("passes", c.passes);
    if (c.hasTail) row.addUint("startAligned", c.startAligned);
    if (c.windowQuads)
        row.addHexDigits("windowAddr", c.windowAddr >> 4, 4).addUint("windowQuads", c.windowQuads);
    writeRegs(row, "regsIn", c.before);
    writeRegs(row, "regsOut", c.after);
    row.beginArray("payload");
    for (uint32_t w : c.payload) row.pushHexDigits(w, 8);
    row.endArray().addBool("payloadTruncated", c.payloadTruncated);
    if (c.hasTail) row.addHexBytes("tail", c.tail, 16);
    writeQuads(row, "mem", c.data);
    writeQuads(row, "micro", c.micro);
    const std::string text = row.take();
    std::fwrite(text.data(), 1, text.size(), f);
}

void VifCmdTrace::write() {
    if (!isEnabled()) return;
    const std::string dir = getOutputDir();
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);

    std::stable_sort(mCases.begin(), mCases.end(),
                     [](const Case& a, const Case& b) { return a.form < b.form; });
    if (FILE* f = std::fopen((dir + "/vif_vectors.jsonl").c_str(), "w")) {
        for (const Case& c : mCases) writeCase(f, c);
        std::fclose(f);
    }

    std::vector<std::string> forms;
    for (const auto& kv : mFormCases)
        if (kv.second > 0) forms.push_back(kv.first);
    std::sort(forms.begin(), forms.end());
    if (FILE* g = std::fopen((dir + "/vif_forms.jsonl").c_str(), "w")) {
        JsonTable t(g, {"form", "cases"});
        for (const std::string& form : forms) t.addString(form.c_str()).addUint(mFormCases[form]).endRow();
        std::fclose(g);
    }

    std::printf("[vifcmd] %s: %zu forms, %zu vectors, over %llu commands (%llu abandoned mid-command)\n",
                dir.c_str(), forms.size(), mCases.size(), static_cast<unsigned long long>(mCommands),
                static_cast<unsigned long long>(mAbandoned));
}

void vifCmdBeforeSink(uint32_t idx, const uint32_t* data, uint32_t pass) {
    Diagnostics::get().getVifCmd().onBefore(idx, data, pass);
}

void vifCmdAfterSink(uint32_t idx, const uint32_t* data, uint32_t consumed, bool done) {
    Diagnostics::get().getVifCmd().onAfter(idx, data, consumed, done);
}

}  // namespace pcsx2hook

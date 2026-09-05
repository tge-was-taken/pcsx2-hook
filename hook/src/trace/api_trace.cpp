// SPDX-FileCopyrightText: 2002-2026 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#include "api_trace.h"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <string>
#include <unordered_map>
#include <vector>

#include "Memory.h"
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

void ApiTrace::hashMix(uint64_t& h, uint64_t v) {
    h ^= v + 0x9E3779B97F4A7C15ull + (h << 6) + (h >> 2);
}

void ApiTrace::emitRun() {
    if (mRunLen == 0 || !mSeqFile) return;
    std::fprintf(mSeqFile, "%u\t%llu\n", mRunId, static_cast<unsigned long long>(mRunLen));
    mSeqRecords++;
    mRunLen = 0;
}
bool ApiTrace::isEnabled() {
    static const bool on = Config::get().getValue("PCSX2HOOK_API_TRACE") != nullptr;
    return on;
}

bool ApiTrace::isReadable(uint32_t addr) {
    const uint32_t phys = addr & 0x1FFFFFFF;
    return phys >= 0x1000 && phys < 0x02000000;
}

uint32_t ApiTrace::snapshotWindow(uint32_t addr, uint8_t* out) {
    const uint32_t base = addr & ~3u;
    const uint32_t phys = base & 0x01FFFFFFu;
    const uint32_t len = phys + kArgMax > 0x02000000u ? 0x02000000u - phys : kArgMax;
    if (const void* p = readableHost(base, len)) {
        std::memcpy(out, p, len);
        return len;
    }
    return 0;
}
void ApiTrace::onMem(uint32_t addr, uint64_t value, uint32_t size, bool isRead) {
    if (mDepth == 0 || mDepth > kMaxDepth) return;
    Call& c = mStack[mDepth - 1];
    if (c.accesses.size() >= kMaxAccesses) {
        c.truncated = true;
        return;
    }
    c.accesses.push_back({addr, size, value, isRead});
}

Hooks::Result ApiTrace::onEnter(Hooks::Context& ctx) {
    if (mDepth >= kMaxDepth) {
        mDepth++;
        return Hooks::Result::Continue;
    }
    mStack[mDepth].pc = 0;
    FnState& fn = mPerFn[ctx.pc];
    fn.calls++;
    if (fn.calls > kDenseCalls) {
        if (fn.calls < fn.nextAt) {
            mDepth++;
            return Hooks::Result::Continue;
        }
        fn.stride = fn.stride * 2 > kMaxStride ? kMaxStride : fn.stride * 2;
        fn.nextAt = fn.calls + fn.stride;
    }
    fn.recorded++;
    Call& c = mStack[mDepth++];
    c = Call{};
    c.pc = ctx.pc;
    c.ra = ctx.ra;
    c.sp = ctx.sp;
    for (uint32_t i = 0; i < kGprArgs; i++) c.gpr[i] = ctx.reg(4 + i);
    for (uint32_t i = 0; i < kFprArgs; i++) c.fpr[i] = ctx.freg(12 + i);
    for (uint32_t i = 0; i < kGprArgs; i++) {
        if (!isReadable(c.gpr[i])) continue;
        ArgWindow w{};
        w.reg = i;
        w.addr = c.gpr[i];
        w.before = mArgBuf[mDepth - 1][i];
        w.captured = snapshotWindow(w.addr, w.before);
        c.windows.push_back(w);
    }
    return Hooks::Result::Continue;
}

void ApiTrace::writeHex(FILE* f, const uint8_t* b, uint32_t n) {
    for (uint32_t i = 0; i < n;) {
        if (b[i] == 0) {
            uint32_t run = 0;
            while (i + run < n && b[i + run] == 0) run++;
            if (run >= 8) {
                std::fprintf(f, "*%u*", run);
                i += run;
                continue;
            }
        }
        std::fprintf(f, "%02X", b[i++]);
    }
}

void ApiTrace::onExit(Hooks::Context& ctx) {
    if (mDepth == 0) return;
    mDepth--;
    if (mDepth >= kMaxDepth || !mFile) return;
    Call& c = mStack[mDepth];
    if (c.pc == 0) return;
    for (ArgWindow& w : c.windows) {
        const uint32_t base = w.addr & ~3u;
        uint32_t span = 0;
        for (const Access& a : c.accesses) {
            if (a.addr < base) continue;
            const uint32_t end = a.addr - base + a.size;
            if (end <= w.captured && end > span) span = end;
        }
        w.span = span ? ((span + 3u) & ~3u) : 0;
    }

    uint64_t h = 1469598103934665603ull;
    hashMix(h, c.pc);
    for (uint32_t i = 0; i < 4; i++) hashMix(h, c.gpr[i]);
    for (uint32_t i = 0; i < 4; i++) {
        uint32_t bits;
        std::memcpy(&bits, &c.fpr[i], 4);
        hashMix(h, bits);
    }
    hashMix(h, ctx.v0);

    mCalls++;
    const auto it = mDataIds.find(h);
    uint32_t id;
    if (it != mDataIds.end()) {
        id = it->second;
    } else {
        id = mNextDataId++;
        mDataIds.emplace(h, id);
        std::fprintf(mFile, "{\"id\":%u,\"fn\":\"%s\",\"pc\":\"%08X\",\"args\":[", id,
                     getSymbols().resolve(c.pc).c_str(), c.pc);
        for (uint32_t i = 0; i < kGprArgs; i++)
            std::fprintf(mFile, "%s\"%08X\"", i ? "," : "", c.gpr[i]);
        std::fprintf(mFile, "],\"fargs\":[");
        for (uint32_t i = 0; i < kFprArgs; i++)
            std::fprintf(mFile, "%s%.9g", i ? "," : "", static_cast<double>(c.fpr[i]));
        std::fprintf(mFile, "],\"ret\":{\"v0\":\"%08X\",\"f0\":%.9g}", ctx.v0,
                     static_cast<double>(ctx.freg(0)));
        std::fprintf(mFile, ",\"argmem\":[");
        for (size_t i = 0; i < c.windows.size(); i++) {
            const ArgWindow& w = c.windows[i];
            uint32_t len = w.span > kArgMin ? w.span : kArgMin;
            if (len > w.captured) len = w.captured;
            if (len == 0) continue;
            std::vector<uint8_t> after(len);
            if (const void* p = readableHost(w.addr & ~3u, len)) std::memcpy(after.data(), p, len);
            const bool changed = std::memcmp(w.before, after.data(), len) != 0;
            std::fprintf(mFile,
                         "%s{\"reg\":%u,\"addr\":\"%08X\",\"len\":%u,\"touched\":%u,"
                         "\"changed\":%s,\"before\":\"",
                         i ? "," : "", w.reg, w.addr, len, w.span, changed ? "true" : "false");
            writeHex(mFile, w.before, len);
            std::fprintf(mFile, "\",\"after\":\"");
            writeHex(mFile, after.data(), len);
            std::fprintf(mFile, "\"}");
        }
        std::fprintf(mFile, "],\"mem\":[");
        for (size_t i = 0; i < c.accesses.size(); i++) {
            const Access& a = c.accesses[i];
            std::fprintf(mFile, "%s{\"addr\":\"%08X\",\"size\":%u,\"value\":\"%llX\",\"read\":%s}",
                         i ? "," : "", a.addr, a.size, static_cast<unsigned long long>(a.value),
                         a.isRead ? "true" : "false");
        }
        std::fprintf(mFile, "]%s}\n", c.truncated ? ",\"truncated\":true" : "");
        if (c.truncated) mTruncated++;
    }

    if (uint32_t& seen = mShapeMemCount[id]; seen < kMemSamplesPerShape && it != mDataIds.end()) {
        seen++;
        std::fprintf(mFile, "{\"id\":%u,\"memOnly\":true,\"mem\":[", id);
        for (size_t i = 0; i < c.accesses.size(); i++) {
            const Access& a = c.accesses[i];
            std::fprintf(mFile, "%s{\"addr\":\"%08X\",\"size\":%u,\"value\":\"%llX\",\"read\":%s}",
                         i ? "," : "", a.addr, a.size, static_cast<unsigned long long>(a.value),
                         a.isRead ? "true" : "false");
        }
        std::fprintf(mFile, "]}\n");
    }

    if (id == mRunId) {
        mRunLen++;
    } else {
        emitRun();
        mRunId = id;
        mRunLen = 1;
    }
}
void ApiTrace::init() {
    if (!isEnabled()) return;
    const char* listPath = Config::get().getValue("PCSX2HOOK_API_TRACE_FUNCS");
    if (!listPath) {
        std::fprintf(stderr,
                     "[api] PCSX2HOOK_API_TRACE_FUNCS=<file> is required: one symbol name or "
                     "0xADDR per line\n");
        return;
    }
    std::ifstream in(listPath);
    if (!in) {
        std::fprintf(stderr, "[api] cannot read %s\n", listPath);
        return;
    }
    getSymbols().load();
    const std::vector<std::pair<uint32_t, std::string>>& syms = getSymbols().getEntries();

    size_t armed = 0, missing = 0;
    std::string line;
    while (std::getline(in, line)) {
        while (!line.empty() && (line.back() == '\r' || line.back() == ' ')) line.pop_back();
        if (line.empty() || line[0] == '#') continue;
        uint32_t addr = 0;
        if (line.rfind("0x", 0) == 0 || line.rfind("0X", 0) == 0) {
            addr = static_cast<uint32_t>(std::strtoul(line.c_str() + 2, nullptr, 16));
        } else {
            for (const std::pair<uint32_t, std::string>& sym : syms) {
                if (sym.second == line) {
                    addr = sym.first;
                    break;
                }
            }
        }
        if (addr == 0) {
            std::fprintf(stderr, "[api] not in the symbol map: %s\n", line.c_str());
            missing++;
            continue;
        }
        if (Hooks::IsHooked(addr)) {
            std::fprintf(stderr, "[api] already hooked, skipping: %s\n", line.c_str());
            continue;
        }
        Hooks::Register(addr, &apiEnterHook, &apiExitHook);
        armed++;
    }

    const char* out = Config::get().getValue("PCSX2HOOK_API_TRACE");
    const std::string path = (!out || !*out || std::strcmp(out, "1") == 0)
                                 ? Diagnostics::get().getDumps().getPath("api_trace.jsonl")
                                 : std::string(out);
    mFile = std::fopen((path + ".data.jsonl").c_str(), "w");
    mSeqFile = std::fopen((path + ".seq.tsv").c_str(), "w");
    if (!mFile || !mSeqFile) {
        std::fprintf(stderr, "[api] cannot open %s.{data.jsonl,seq.tsv}\n", path.c_str());
        return;
    }
    std::fprintf(mSeqFile, "dataId\trepeat\n");
    Hooks::AddGuestMemSink(&apiMemSink);
    std::fprintf(stderr, "[api] armed %zu functions (%zu unresolved) -> %s\n", armed, missing,
                 path.c_str());
}
void ApiTrace::write() {
    if (!isEnabled() || !mFile) return;
    emitRun();
    std::fclose(mFile);
    mFile = nullptr;
    if (mSeqFile) {
        std::fclose(mSeqFile);
        mSeqFile = nullptr;
    }
    const std::string sum =
        std::string(Config::get().getValue("PCSX2HOOK_API_TRACE")) + ".summary.tsv";
    uint64_t total = 0, capped = 0;
    if (FILE* g = std::fopen(sum.c_str(), "w")) {
        std::fprintf(g, "pc\tfunction\tcalls\trecorded\trate\n");
        std::vector<uint32_t> pcs;
        for (const auto& kv : mPerFn) pcs.push_back(kv.first);
        std::sort(pcs.begin(), pcs.end());
        for (uint32_t pc : pcs) {
            const auto& c = mPerFn[pc];
            total += c.calls;
            if (c.recorded < c.calls) capped++;
            std::fprintf(g, "%08X\t%s\t%llu\t%llu\t1/%llu\n", pc, getSymbols().resolve(pc).c_str(),
                         static_cast<unsigned long long>(c.calls),
                         static_cast<unsigned long long>(c.recorded),
                         static_cast<unsigned long long>(c.recorded ? c.calls / c.recorded : 0));
        }
        std::fclose(g);
    }
    std::printf(
        "[api] %llu calls over %zu functions (%llu rate-limited), %llu recorded: "
        "%u distinct payloads, %llu sequence runs%s\n",
        static_cast<unsigned long long>(total), mPerFn.size(),
        static_cast<unsigned long long>(capped), static_cast<unsigned long long>(mCalls),
        mNextDataId, static_cast<unsigned long long>(mSeqRecords),
        mTruncated ? ", some access lists truncated" : "");
}

void apiMemSink(uint32_t addr, uint64_t value, uint32_t size, bool isRead) {
    Diagnostics::get().getApi().onMem(addr, value, size, isRead);
}

Hooks::Result apiEnterHook(Hooks::Context& ctx) {
    return Diagnostics::get().getApi().onEnter(ctx);
}

void apiExitHook(Hooks::Context& ctx) {
    Diagnostics::get().getApi().onExit(ctx);
}

}  // namespace pcsx2hook

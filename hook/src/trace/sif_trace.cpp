// SPDX-FileCopyrightText: 2002-2026 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#include "pcsx2hook/trace/sif_trace.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <string>
#include <vector>

#include "Memory.h"
#include "R5900.h"
#include "pcsx2hook/config.h"
#include "pcsx2hook/diagnostics.h"
#include "pcsx2hook/trace/dump_dir.h"
#include "pcsx2/Hooks.h"
#include "pcsx2hook/symbols.h"

namespace pcsx2hook {
constexpr uint32_t kMaxPacketWords = 8192;
constexpr uint32_t kMaxChain = 8;
constexpr size_t kMaxRecords = 400000;
bool SifTrace::isEnabled() {
    static const bool on = Config::get().getValue("PCSX2HOOK_SIF_TRACE") != nullptr;
    return on;
}

std::string SifTrace::resolveEE(uint32_t pc) {
    char buf[24];
    if (!getSymbols().isInCodeRange(pc)) {
        std::snprintf(buf, sizeof(buf), "0x%08X", pc);
        return buf;
    }
    return getSymbols().resolve(pc);
}
void SifTrace::onTransfer(uint32_t channel, bool toEE, uint32_t madr, uint32_t qwc,
                          const uint32_t* words, uint32_t count) {
    const std::lock_guard<std::mutex> lock(mMutex);
    if (!mFile) return;
    const uint32_t keep = count > kMaxPacketWords ? kMaxPacketWords : count;
    if (keep < count) mClipped++;
    const std::vector<uint32_t>& chain = mChain[channel & 1];
    std::fprintf(mFile,
                 "{\"i\":%llu,\"ch\":%u,\"dir\":\"%s\",\"madr\":\"%08X\",\"qwc\":%u,"
                 "\"words\":%u%s,\"chain\":[",
                 static_cast<unsigned long long>(mTotal), channel, toEE ? "iop2ee" : "ee2iop", madr,
                 qwc, count, keep < count ? ",\"clipped\":true" : "");
    for (size_t k = 0; k < chain.size(); k++)
        std::fprintf(mFile, "%s\"%s\"", k ? "," : "", resolveEE(chain[k]).c_str());
    std::fprintf(mFile, "],\"data\":[");
    for (uint32_t k = 0; words && k < keep; k++)
        std::fprintf(mFile, "%s\"%08X\"", k ? "," : "", words[k]);
    std::fprintf(mFile, "]}\n");
    mTotal++;
    mWords += count;
}
void SifTrace::onKick(uint32_t channel) {
    std::vector<uint32_t>& chain = mChain[channel & 1];
    chain.clear();
    chain.push_back(cpuRegs.pc);
    const uint32_t ra = cpuRegs.GPR.n.ra.UL[0];
    if (ra) chain.push_back(ra);
    const uint32_t sp = cpuRegs.GPR.n.sp.UL[0];
    if (!getSymbols().isLoaded() || sp == 0) return;
    for (uint32_t off = 0; off < 0x400 && chain.size() < kMaxChain; off += 4) {
        const uint32_t addr = (sp + off) & 0x01FFFFFC;
        const uint32_t word = memRead32(addr);
        if ((word & 3) != 0 || !getSymbols().isInCodeRange(word)) continue;
        const uint32_t callSite = (word - 8) & 0x01FFFFFC;
        const uint32_t insn = memRead32(callSite);
        const uint32_t op = insn >> 26;
        if ((op == 0x03 || (op == 0 && (insn & 0x3F) == 0x09)) && chain.back() != word)
            chain.push_back(word);
    }
}
void SifTrace::init() {
    if (!isEnabled()) return;
    const char* path = Config::get().getValue("PCSX2HOOK_SIF_TRACE");
    const std::string out = (!path || !*path || std::strcmp(path, "1") == 0)
                                ? Diagnostics::get().getDumps().getPath("sif_trace.jsonl")
                                : std::string(path);
    mFile = std::fopen(out.c_str(), "w");
    if (!mFile) {
        std::fprintf(stderr, "[sif] cannot open %s\n", out.c_str());
        return;
    }
    Hooks::SetSifTransferSink(&sifTransferSink);
    Hooks::SetSifKickSink(&sifKickSink);
}
void SifTrace::write() {
    if (!isEnabled()) return;
    const std::lock_guard<std::mutex> lock(mMutex);
    if (mFile) {
        std::fclose(mFile);
        mFile = nullptr;
    }
    std::printf("[sif] %llu transfers, %llu words%s\n", static_cast<unsigned long long>(mTotal),
                static_cast<unsigned long long>(mWords),
                mClipped ? " [some packets clipped: raise kMaxPacketWords]" : "");
}

void sifKickSink(uint32_t channel) {
    Diagnostics::get().getSif().onKick(channel);
}

void sifTransferSink(uint32_t channel, bool toEE, uint32_t madr, uint32_t qwc,
                     const uint32_t* words, uint32_t count) {
    Diagnostics::get().getSif().onTransfer(channel, toEE, madr, qwc, words, count);
}

}  // namespace pcsx2hook

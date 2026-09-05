// SPDX-FileCopyrightText: 2002-2026 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#include "pcsx2hook/trace/gs_tracker.h"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <unordered_map>
#include <vector>

#include "pcsx2hook/config.h"
#include "pcsx2hook/diagnostics.h"
#include "pcsx2/Hooks.h"
#include "pcsx2/R5900.h"
#include "pcsx2hook/symbols.h"

namespace pcsx2hook {
namespace {
const char* getChanName(uint32_t chan) {
    switch (chan) {
        case 1:
            return "VIF1";
        case 2:
            return "GIF";
        default:
            return "?";
    }
}

}  // namespace

void GsTracker::onKick(uint32_t chan, uint32_t eepc, uint32_t madr, uint32_t qwc) {
    const uint32_t ra = cpuRegs.GPR.n.ra.UL[0];
    const uint64_t key =
        (static_cast<uint64_t>(eepc) << 32) ^ (static_cast<uint64_t>(ra) << 4) ^ chan;
    Site& s = mSites[key];
    if (s.kicks == 0) {
        s.chan = chan;
        s.eepc = eepc;
        s.ra = ra;
        s.sampleMadr = madr;
    }
    s.kicks++;
    s.qwc += qwc;
}

void GsTracker::init() {
    if (Config::get().getValue(
            "PCSX2HOOK_NO_GSCOV"))  // on by default; opt out for parallel/CI runs
    {
        return;
    }
    mEnabled = true;
    getSymbols().load();
    Hooks::SetDmaKickSink(&gsKickSink);
    std::fprintf(stderr, "[gstrack] GS-submission coverage tracer active\n");
}

void GsTracker::report(const char* reason, std::FILE* out) {
    if (!mEnabled) {
        return;
    }
    std::vector<const Site*> sites;
    sites.reserve(mSites.size());
    uint64_t totalKicks = 0;
    for (const auto& kv : mSites) {
        sites.push_back(&kv.second);
        totalKicks += kv.second.kicks;
    }
    std::sort(sites.begin(), sites.end(),
              [](const Site* a, const Site* b) { return a->kicks > b->kicks; });
    std::fprintf(out, "[gstrack] GS submissions (%s): %llu kicks across %zu call sites\n",
                 reason ? reason : "", static_cast<unsigned long long>(totalKicks), sites.size());
    for (const Site* s : sites) {
        std::fprintf(out, "  %-4s kicks=%-6llu qwc=%-8llu %s  <-  %s  (madr=0x%08X)\n",
                     getChanName(s->chan), static_cast<unsigned long long>(s->kicks),
                     static_cast<unsigned long long>(s->qwc), getSymbols().resolve(s->eepc).c_str(),
                     getSymbols().resolve(s->ra).c_str(), s->sampleMadr);
    }
    mSites.clear();
}
void gsKickSink(uint32_t chan, uint32_t eepc, uint32_t madr, uint32_t qwc) {
    Diagnostics::get().getGsTracker().onKick(chan, eepc, madr, qwc);
}

}  // namespace pcsx2hook

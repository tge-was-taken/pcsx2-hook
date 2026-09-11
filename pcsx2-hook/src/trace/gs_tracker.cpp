// SPDX-FileCopyrightText: 2002-2026 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#include "trace/gs_tracker.h"
#include "trace/json.h"
#include "trace/table.h"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <unordered_map>
#include <vector>

#include "config.h"
#include "diagnostics.h"
#include "pcsx2/Hooks.h"
#include "pcsx2/R5900.h"
#include "symbols.h"

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
    Hooks::AddDmaKickSink(&gsKickSink);
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
    const std::string header = JsonObject()
                                   .addString("type", "gsKicks")
                                   .addString("reason", reason ? reason : "")
                                   .addUint("kicks", totalKicks)
                                   .addUint("sites", sites.size())
                                   .take();
    std::fwrite(header.data(), 1, header.size(), out);
    JsonTable table(out, {"channel", "kicks", "qwc", "symbol", "caller", "madr"});
    for (const Site* s : sites) {
        table.addString(getChanName(s->chan))
            .addUint(s->kicks)
            .addUint(s->qwc)
            .addString(getSymbols().resolve(s->eepc).c_str())
            .addString(getSymbols().resolve(s->ra).c_str())
            .addHex(s->sampleMadr, 8)
            .endRow();
    }
    mSites.clear();
}
void gsKickSink(uint32_t chan, uint32_t eepc, uint32_t madr, uint32_t qwc) {
    Diagnostics::get().getGsTracker().onKick(chan, eepc, madr, qwc);
}

}  // namespace pcsx2hook

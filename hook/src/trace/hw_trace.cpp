// SPDX-FileCopyrightText: 2002-2026 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#include "hw_trace.h"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <string>
#include <unordered_map>
#include <vector>

#include "R3000A.h"
#include "R5900.h"
#include "config.h"
#include "diagnostics.h"
#include "dump_dir.h"
#include "iop_trace.h"
#include "pcsx2/Hooks.h"
#include "symbols.h"

namespace pcsx2hook {
constexpr size_t kMaxValues = 8;

constexpr size_t kMaxSites = 32;

std::string HwTrace::getOutputDir() {
    const char* env = Config::get().getValue("PCSX2HOOK_HW_TRACE");
    if (!env || !*env || std::strcmp(env, "1") == 0) return Diagnostics::get().getDumps().getDir();
    return env;
}
bool HwTrace::isEnabled() {
    static const bool on = Config::get().getValue("PCSX2HOOK_HW_TRACE") != nullptr;
    return on;
}
void HwTrace::onAccess(bool iop, uint32_t addr, uint64_t value, uint32_t size, bool isRead) {
    mAccesses++;
    RegisterUse& r = mRegs[(static_cast<uint64_t>(iop) << 32) | addr];
    if (isRead)
        r.reads++;
    else
        r.writes++;
    r.size = std::max(r.size, size);
    if (std::find(r.values.begin(), r.values.end(), value) == r.values.end()) {
        r.distinctValues++;
        if (r.values.size() < kMaxValues) r.values.push_back(value);
    }

    const uint32_t pc = iop ? psxRegs.pc : cpuRegs.pc;
    auto it = std::find_if(r.sites.begin(), r.sites.end(),
                           [pc](const CallerSite& s) { return s.pc == pc; });
    if (it == r.sites.end()) {
        if (r.sites.size() >= kMaxSites) {
            r.sitesDropped++;
            return;
        }
        r.sites.push_back({pc, 0, 0});
        it = r.sites.end() - 1;
    }
    (isRead ? it->reads : it->writes)++;
}
void HwTrace::init() {
    if (!isEnabled()) return;
    Hooks::SetHwAccessSink(&hwAccessSink);
}
void HwTrace::write() {
    if (!isEnabled()) return;
    const std::string dir = getOutputDir();
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);

    std::vector<uint64_t> keys;
    for (const auto& kv : mRegs) keys.push_back(kv.first);
    std::sort(keys.begin(), keys.end());

    FILE* f = std::fopen((dir + "/hw_registers.tsv").c_str(), "w");
    if (!f) return;
    std::fprintf(f, "cpu\taddr\tsize\treads\twrites\tdistinct\tvalues\n");
    size_t eeCount = 0, iopCount = 0;
    for (uint64_t key : keys) {
        const RegisterUse& r = mRegs[key];
        const bool iop = (key >> 32) != 0;
        (iop ? iopCount : eeCount)++;
        std::fprintf(f, "%s\t%08X\t%u\t%llu\t%llu\t%llu\t", iop ? "iop" : "ee",
                     static_cast<uint32_t>(key & 0xFFFFFFFF), r.size,
                     static_cast<unsigned long long>(r.reads),
                     static_cast<unsigned long long>(r.writes),
                     static_cast<unsigned long long>(r.distinctValues));
        for (size_t i = 0; i < r.values.size(); i++)
            std::fprintf(f, "%s%llX", i ? "," : "", static_cast<unsigned long long>(r.values[i]));
        std::fprintf(f, "\n");
    }
    std::fclose(f);

    getSymbols().load();
    FILE* sf = std::fopen((dir + "/hw_sites.tsv").c_str(), "w");
    if (sf) {
        std::fprintf(sf, "cpu\taddr\tpc\tsymbol\treads\twrites\n");
        size_t siteCount = 0;
        uint64_t dropped = 0;
        for (uint64_t key : keys) {
            const RegisterUse& r = mRegs[key];
            const bool iop = (key >> 32) != 0;
            dropped += r.sitesDropped;
            std::vector<CallerSite> sites = r.sites;
            std::sort(sites.begin(), sites.end(), [](const CallerSite& a, const CallerSite& b) {
                return a.reads + a.writes > b.reads + b.writes;
            });
            for (const CallerSite& c : sites) {
                std::string name;
                if (iop) {
                    uint32_t off = 0;
                    const char* mod = Diagnostics::get().getIop().getModule(c.pc, &off);
                    name = mod ? std::string(mod) + "+0x" + std::to_string(off) : std::string("-");
                } else {
                    name = getSymbols().isInCodeRange(c.pc) ? getSymbols().resolve(c.pc)
                                                            : std::string("-");
                }
                std::fprintf(sf, "%s\t%08X\t%08X\t%s\t%llu\t%llu\n", iop ? "iop" : "ee",
                             static_cast<uint32_t>(key & 0xFFFFFFFF), c.pc, name.c_str(),
                             static_cast<unsigned long long>(c.reads),
                             static_cast<unsigned long long>(c.writes));
                siteCount++;
            }
        }
        std::fclose(sf);
        std::printf("[hw] %s: %zu caller sites (%llu accesses past the per-register cap)\n",
                    dir.c_str(), siteCount, static_cast<unsigned long long>(dropped));
    }

    std::printf("[hw] %s: %zu EE registers, %zu IOP registers, %llu accesses\n", dir.c_str(),
                eeCount, iopCount, static_cast<unsigned long long>(mAccesses));
}

void hwAccessSink(bool iop, uint32_t addr, uint64_t value, uint32_t size, bool isRead) {
    Diagnostics::get().getHw().onAccess(iop, addr, value, size, isRead);
}

}  // namespace pcsx2hook

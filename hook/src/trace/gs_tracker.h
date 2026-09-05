// SPDX-FileCopyrightText: 2002-2026 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#pragma once

#include <cstdint>
#include <cstdio>
#include <unordered_map>

namespace pcsx2hook {

class GsTracker {
public:
    void init();
    void onKick(uint32_t chan, uint32_t eepc, uint32_t madr, uint32_t qwc);
    void report(const char* reason, std::FILE* out = stderr);

private:
    struct Site {
        uint32_t chan = 0;
        uint32_t eepc = 0;
        uint32_t ra = 0;
        uint64_t kicks = 0;
        uint64_t qwc = 0;
        uint32_t sampleMadr = 0;
    };

    std::unordered_map<uint64_t, Site> mSites;
    bool mEnabled = false;
};

void gsKickSink(uint32_t chan, uint32_t eepc, uint32_t madr, uint32_t qwc);

}  // namespace pcsx2hook

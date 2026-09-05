// SPDX-FileCopyrightText: 2002-2026 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace pcsx2hook {

class HwTrace {
public:
    bool isEnabled();
    void init();
    void onAccess(bool iop, uint32_t addr, uint64_t value, uint32_t size, bool isRead);
    void write();

private:
    struct CallerSite {
        uint32_t pc = 0;
        uint64_t reads = 0, writes = 0;
    };

    struct RegisterUse {
        uint64_t reads = 0, writes = 0;
        uint64_t distinctValues = 0;
        uint32_t size = 0;
        std::vector<uint64_t> values;
        std::vector<CallerSite> sites;
        uint64_t sitesDropped = 0;
    };

    std::string getOutputDir();

    std::unordered_map<uint64_t, RegisterUse> mRegs;
    uint64_t mAccesses = 0;
};

void hwAccessSink(bool iop, uint32_t addr, uint64_t value, uint32_t size, bool isRead);

}  // namespace pcsx2hook

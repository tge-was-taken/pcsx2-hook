// SPDX-FileCopyrightText: 2002-2026 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#pragma once

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace pcsx2hook {
class Symbols {
public:
    void setSerial(std::string serial);
    void load();
    bool isLoaded() const;
    std::string resolve(uint32_t pc) const;
    bool isInCodeRange(uint32_t pc) const;
    const std::vector<std::pair<uint32_t, std::string>>& getEntries() const { return mSyms; }

private:
    std::string mSerial;
    std::vector<std::pair<uint32_t, std::string>> mSyms;
    bool mTried = false;
};

Symbols& getSymbols();
}  // namespace pcsx2hook

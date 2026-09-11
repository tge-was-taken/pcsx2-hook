// SPDX-FileCopyrightText: 2002-2026 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#pragma once

#include <string>
#include <unordered_map>
#include <vector>

namespace pcsx2hook {

class Config {
public:
    static Config& get();

    const char* getValue(const char* name) const;
    bool isSet(const char* name) const;
    std::string getString(const char* name, const char* fallback = "") const;
    int getInt(const char* name, int fallback = 0) const;

    void set(const char* name, const char* value);
    void unset(const char* name);

private:
    Config();

    std::vector<std::pair<std::string, std::string>> mVars;
    std::unordered_map<std::string, size_t> mIndex;
};

}  // namespace pcsx2hook

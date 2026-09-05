// SPDX-FileCopyrightText: 2002-2026 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#include "pcsx2hook/config.h"

#include <cstdlib>
#include <string_view>

extern char** environ;

namespace pcsx2hook {

Config::Config() {
    for (char** e = environ; e && *e; ++e) {
        const std::string_view entry(*e);
        const size_t eq = entry.find('=');
        if (eq == std::string_view::npos) continue;
        const std::string_view name = entry.substr(0, eq);
        if (name.rfind("PCSX2", 0) != 0) continue;
        mIndex.emplace(std::string(name), mVars.size());
        mVars.emplace_back(std::string(name), std::string(entry.substr(eq + 1)));
    }
}

Config& Config::get() {
    static Config instance;
    return instance;
}

void Config::set(const char* name, const char* value) {
    const auto it = mIndex.find(name);
    if (it != mIndex.end()) {
        mVars[it->second].second = value;
        return;
    }
    mIndex.emplace(name, mVars.size());
    mVars.emplace_back(name, value);
}

const char* Config::getValue(const char* name) const {
    const auto it = mIndex.find(name);
    return it == mIndex.end() ? nullptr : mVars[it->second].second.c_str();
}

bool Config::isSet(const char* name) const {
    return getValue(name) != nullptr;
}

std::string Config::getString(const char* name, const char* fallback) const {
    const char* v = getValue(name);
    return (v && *v) ? std::string(v) : std::string(fallback);
}

int Config::getInt(const char* name, int fallback) const {
    const char* v = getValue(name);
    return (v && *v) ? std::atoi(v) : fallback;
}

}  // namespace pcsx2hook

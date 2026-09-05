// SPDX-FileCopyrightText: 2002-2026 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#include "symbols.h"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <fstream>

#include "config.h"

namespace pcsx2hook {
namespace {
std::string getElfName(const std::string& serial) {
    const size_t dash = serial.find('-');
    if (dash == std::string::npos || serial.size() < dash + 6) return {};
    return serial.substr(0, dash) + "_" + serial.substr(dash + 1, 3) + "." +
           serial.substr(dash + 4, 2);
}

bool parseLine(std::string line, uint32_t& addr, std::string& name) {
    while (!line.empty() && (line.back() == '\r' || line.back() == ' ')) line.pop_back();
    if (const size_t eq = line.find(" = 0x"); eq != std::string::npos) {
        addr = static_cast<uint32_t>(std::strtoul(line.c_str() + eq + 5, nullptr, 16));
        name = line.substr(0, eq);
        return true;
    }
    const size_t start = line.find_first_not_of(' ');
    if (start == std::string::npos || line.size() < start + 14 || line[start + 4] != ':')
        return false;
    char* end = nullptr;
    const unsigned long a = std::strtoul(line.c_str() + start + 5, &end, 16);
    if (end == line.c_str() + start + 5) return false;
    const size_t nameStart = line.find_first_not_of(' ', static_cast<size_t>(end - line.c_str()));
    if (nameStart == std::string::npos || line.find(' ', nameStart) != std::string::npos)
        return false;
    addr = static_cast<uint32_t>(a);
    name = line.substr(nameStart);
    return true;
}
}  // namespace

void Symbols::setSerial(std::string serial) {
    mSerial = std::move(serial);
}

void Symbols::load() {
    if (mTried) return;
    mTried = true;

    std::string path;
    if (const char* env = Config::get().getValue("PCSX2HOOK_SYMBOLS"))
        path = env;
    else if (const std::string elf = getElfName(mSerial);
             !elf.empty() && std::ifstream("assets/" + elf + ".map"))
        path = "assets/" + elf + ".map";
    else {
        std::fprintf(stderr,
                     "[eesym] no symbol map for %s (PCs will be raw); drop one at "
                     "assets/%s.map or set PCSX2HOOK_SYMBOLS\n",
                     mSerial.c_str(), getElfName(mSerial).c_str());
        return;
    }

    std::ifstream in(path);
    if (!in) {
        std::fprintf(stderr, "[eesym] no symbol map at %s (PCs will be raw)\n", path.c_str());
        return;
    }
    std::string line;
    uint32_t addr = 0;
    std::string name;
    while (std::getline(in, line)) {
        if (parseLine(line, addr, name)) mSyms.emplace_back(addr, name);
    }
    std::sort(mSyms.begin(), mSyms.end());
    std::fprintf(stderr, "[eesym] isLoaded %zu EE getSymbols for %s from %s\n", mSyms.size(),
                 mSerial.c_str(), path.c_str());
}

bool Symbols::isLoaded() const {
    return !mSyms.empty();
}

bool Symbols::isInCodeRange(uint32_t pc) const {
    return !mSyms.empty() && pc >= mSyms.front().first && pc <= mSyms.back().first;
}

std::string Symbols::resolve(uint32_t pc) const {
    char buf[96];
    if (!mSyms.empty()) {
        auto it = std::upper_bound(mSyms.begin(), mSyms.end(), std::make_pair(pc, std::string()),
                                   [](const auto& a, const auto& b) { return a.first < b.first; });
        if (it != mSyms.begin()) {
            --it;
            // A linker map lists publics only, so a static function sits in the gap after one and
            // resolves as "thatPublic+0xNNN" while being a different function entirely. Past this
            // much, print the raw address too rather than assert a containment we cannot know.
            constexpr uint32_t kTrustSpan = 0x400;
            const uint32_t off = pc - it->first;
            if (off > kTrustSpan)
                std::snprintf(buf, sizeof(buf), "%s+0x%X (0x%08X)", it->second.c_str(), off, pc);
            else
                std::snprintf(buf, sizeof(buf), "%s+0x%X", it->second.c_str(), off);
            return buf;
        }
    }
    std::snprintf(buf, sizeof(buf), "0x%08X", pc);
    return buf;
}

Symbols& getSymbols() {
    static Symbols s;
    return s;
}
}  // namespace pcsx2hook

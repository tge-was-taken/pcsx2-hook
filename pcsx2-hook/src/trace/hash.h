// SPDX-FileCopyrightText: 2002-2026 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#pragma once

#include <cstdint>

namespace pcsx2hook {

inline uint64_t hashMix(uint64_t h, uint64_t v) {
    return h ^ (v + 0x9E3779B97F4A7C15ull + (h << 6) + (h >> 2));
}

}  // namespace pcsx2hook

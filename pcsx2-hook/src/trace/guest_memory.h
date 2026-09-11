// SPDX-FileCopyrightText: 2002-2026 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#pragma once

#include <cstddef>
#include <cstdint>

#include "Memory.h"

namespace pcsx2hook {

inline const void* readableHost(uint32_t addr, size_t len) {
    if ((addr & 0x1FFFFFFFu) + len > Ps2MemSize::MainRam) return nullptr;
    return PSM(addr);
}

}  // namespace pcsx2hook

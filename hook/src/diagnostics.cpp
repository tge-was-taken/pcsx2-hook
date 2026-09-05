// SPDX-FileCopyrightText: 2002-2026 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#include "diagnostics.h"

namespace pcsx2hook {

Diagnostics& Diagnostics::get() {
    static Diagnostics instance;
    return instance;
}

}  // namespace pcsx2hook

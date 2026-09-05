// SPDX-FileCopyrightText: 2002-2026 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#include "trace/dump_dir.h"

#include <cstdlib>
#include <filesystem>

#include "config.h"

namespace pcsx2hook {

const std::string& DumpDir::getDir() {
    if (mDir.empty()) {
        const char* env = Config::get().getValue("PCSX2HOOK_DUMP_DIR");
        mDir = (env && *env) ? env : "experiments/dumps";
        std::error_code ec;
        std::filesystem::create_directories(mDir, ec);
    }
    return mDir;
}

std::string DumpDir::getPath(const std::string& name) {
    return getDir() + "/" + name;
}

}  // namespace pcsx2hook

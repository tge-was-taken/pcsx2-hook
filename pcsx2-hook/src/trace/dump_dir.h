// SPDX-FileCopyrightText: 2002-2026 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#pragma once

#include <string>

namespace pcsx2hook {

class DumpDir {
public:
    const std::string& getDir();
    std::string getPath(const std::string& name);

private:
    std::string mDir;
};

}  // namespace pcsx2hook

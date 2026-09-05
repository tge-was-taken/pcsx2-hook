// SPDX-FileCopyrightText: 2002-2026 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#pragma once

#include <atomic>
#include <thread>

namespace pcsx2hook {

class Core;

class Pcsx2Host {
public:
    void setCore(Core& core);

    void earlyInit();

    bool init(int argc, char** argv);

    bool windowRequested();

    bool createWindow();

    void applySettingsOverride();

    std::thread startCpuThread(std::atomic<int>& ret);

    bool emulationFinished();

    void pumpWindow(bool forever);

    void requestStop();

    void shutdown();
};

}  // namespace pcsx2hook

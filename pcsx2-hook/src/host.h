// SPDX-FileCopyrightText: 2002-2026 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#pragma once

#include "common/WindowInfo.h"

#include <atomic>
#include <optional>
#include <thread>

namespace pcsx2hook {

class Core;

class Pcsx2Host {
public:
    void setCore(Core& core);
    void clearCore(Core& core);

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

/// Loads the font the overlay needs, which is created along with a graphics device.
bool setDefaultFont();

/// The window a host lends the renderer to draw into, instead of one of ours. Say it before
/// opening the GS; an empty optional gives our own window back.
void setBorrowedWindow(const std::optional<WindowInfo>& window);

/// Runs whatever Host::RunOnCPUThread queued. Call it where the VM is between executions: that is
/// the only point a savestate can be written from, since inside a frame callback the CPU is partway
/// through a recompiled block and the state it writes will not resume.
void drainCpuThreadQueue();

}  // namespace pcsx2hook

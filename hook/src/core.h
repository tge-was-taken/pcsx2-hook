// SPDX-FileCopyrightText: 2002-2026 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#pragma once

#include <atomic>
#include <string>
#include <cstdint>
#include <tuple>
#include <vector>

class MemorySettingsInterface;
struct VMBootParameters;

namespace pcsx2hook {

class Core {
public:
    virtual ~Core() = default;

    // == PadDualshock2::Inputs::LENGTH, asserted in the .cpp. Kept here so the pad state can be a
    // member without pulling the emulator's headers into this one.
    static constexpr int kPadButtonCount = 26;

    // Before LoadStartupSettings: EmuFolders resolves the BIOS location there, not with the rest.
    void applyBiosFolders(MemorySettingsInterface& si);
    void applyHeadlessSettings(MemorySettingsInterface& si);
    bool configureBoot(VMBootParameters& params);
    bool run(const VMBootParameters& params);
    void onFrame();

    void setPadButton(int bind, bool pressed);
    void setSpeedLimit(bool enabled);
    void requestSaveState();

    uint32_t getFrameCount() const { return mFrameCount; }

    // Read once at startup: the emulator's own accessor is not stable for the whole run.
    const std::string& getDiscSerial() const { return mDiscSerial; }

    // A host with a renderer of its own binds these; the library has nothing to capture.
    virtual void requestCapture() {}
    virtual void requestRecord() {}

protected:
    // A host with game-specific work extends the run loop here rather than reimplementing it.
    // Settings only the host knows about, applied with the rest before the VM starts.
    virtual void applyExtraSettings(MemorySettingsInterface& si) { (void)si; }
    virtual void onVmReady() {}
    virtual void onFrameExtra(uint32_t frame) { (void)frame; }
    virtual void onShutdown() {}



private:
    void applyInputToPad();

    std::string mDiscSerial;
    uint32_t mFrameCount = 0;
    bool mAutopress = false;
    std::vector<int> mAutopressButtons;
    std::vector<std::tuple<uint32_t, int, uint32_t>> mAutopressScript;
    uint32_t mSaveStateFrame = 0;
    bool mSaveStateDone = false;

    std::atomic<bool> mPadState[kPadButtonCount] = {};
    std::atomic<int> mPendingSpeedLimit{-1};
    std::atomic<bool> mSaveStateRequested{false};
};

}  // namespace pcsx2hook

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

    static constexpr int kPadButtonCount = 26;

    void applyBiosFolders(MemorySettingsInterface& si);
    void applyHeadlessSettings(MemorySettingsInterface& si);
    bool configureBoot(VMBootParameters& params);
    bool run(const VMBootParameters& params);
    void onFrame();

    void setPadButton(int bind, bool pressed);
    void setSpeedLimit(bool enabled);
    void requestSaveState();
    void requestStop();

    const std::string& getDiscSerial() const { return mDiscSerial; }

    virtual void requestCapture() {}
    virtual void requestRecord() {}

protected:
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
    uint32_t mFrameLimit = 0;
    bool mStopping = false;

    std::atomic<bool> mPadState[kPadButtonCount] = {};
    std::atomic<int> mPendingSpeedLimit{-1};
    std::atomic<bool> mSaveStateRequested{false};
    std::atomic<bool> mStopRequested{false};
};

}  // namespace pcsx2hook

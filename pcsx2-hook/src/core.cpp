// SPDX-FileCopyrightText: 2002-2026 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#include "core.h"

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>

#include "common/Console.h"
#include "common/Error.h"
#include "common/MemorySettingsInterface.h"
#include "config.h"
#include "pcsx2hook/pcsx2hook.h"
#include "diagnostics.h"
#include "fmt/format.h"
#include "pcsx2/CDVD/CDVD.h"
#include "pcsx2/GS.h"
#include "pcsx2/Hooks.h"
#include "pcsx2/SIO/Pad/Pad.h"
#include "pcsx2/SIO/Pad/PadDualshock2.h"
#include "pcsx2/VMManager.h"
#include "symbols.h"

namespace pcsx2hook {
namespace {

static_assert(Core::kPadButtonCount == PadDualshock2::Inputs::LENGTH,
              "pad state must cover every DualShock2 input");
static_assert(PCSX2HOOK_PAD_COUNT == PadDualshock2::Inputs::LENGTH,
              "the C pad enum must match the emulator's input order");

const std::pair<const char*, int> kPadNames[] = {
    {"select", PadDualshock2::Inputs::PAD_SELECT},
    {"start", PadDualshock2::Inputs::PAD_START},
    {"up", PadDualshock2::Inputs::PAD_UP},
    {"down", PadDualshock2::Inputs::PAD_DOWN},
    {"left", PadDualshock2::Inputs::PAD_LEFT},
    {"right", PadDualshock2::Inputs::PAD_RIGHT},
    {"cross", PadDualshock2::Inputs::PAD_CROSS},
    {"circle", PadDualshock2::Inputs::PAD_CIRCLE},
    {"square", PadDualshock2::Inputs::PAD_SQUARE},
    {"triangle", PadDualshock2::Inputs::PAD_TRIANGLE},
};

int findPadButton(const std::string& name) {
    for (const auto& [text, bind] : kPadNames) {
        if (name == text) return bind;
    }
    return -1;
}

std::vector<int> parseAutopressButtons(const std::string& spec) {
    std::vector<int> out;
    std::stringstream ss(spec);
    std::string item;
    while (std::getline(ss, item, ',')) {
        const int bind = findPadButton(item);
        if (bind >= 0) out.push_back(bind);
    }
    return out;
}

std::vector<std::tuple<uint32_t, int, uint32_t>> loadAutopressScript(const std::string& path) {
    std::vector<std::tuple<uint32_t, int, uint32_t>> out;
    std::ifstream in(path);
    if (!in) {
        Console.Error(fmt::format("[pcsx2hook] autopress script not found: {}", path));
        return out;
    }
    std::string line;
    while (std::getline(in, line)) {
        if (line.empty() || line[0] == '#') continue;
        std::stringstream ls(line);
        uint32_t frame = 0, hold = 4;
        std::string button;
        ls >> frame >> button >> hold;
        const int bind = findPadButton(button);
        if (bind >= 0) out.emplace_back(frame, bind, hold ? hold : 4);
    }
    std::sort(out.begin(), out.end());
    return out;
}

}  // namespace

void Core::applyBiosFolders(MemorySettingsInterface& si) {
    const Config& cfg = Config::get();
    if (const char* bios = cfg.getValue("PCSX2HOOK_BIOS")) {
        // The emulator wants the folder and the file name separately, and resolves a relative
        // Folders path against its own data root rather than the working directory.
        const std::filesystem::path path = std::filesystem::absolute(bios);
        si.SetStringValue("Folders", "Bios", path.parent_path().string().c_str());
        si.SetStringValue("Filenames", "BIOS", path.filename().string().c_str());
    }
    if (const char* patches = cfg.getValue("PCSX2HOOK_PATCHES")) {
        // Absolute: a relative Folders path resolves against the emulator's data root, not the cwd.
        si.SetStringValue("Folders", "Patches",
                          std::filesystem::absolute(patches).string().c_str());
        si.SetBoolValue("EmuCore", "EnablePatches", true);
    }
}

void Core::applyHeadlessSettings(MemorySettingsInterface& si) {
    const Config& cfg = Config::get();
    // Software by default: the hardware backends approximate the GS, so only this one is a
    // reference. Null drops rasterization entirely and fills no frame buffer.
    const bool nullGs = cfg.isSet("PCSX2HOOK_NULLGS");
    si.SetIntValue("EmuCore/GS", "Renderer",
                   static_cast<int>(nullGs                                  ? GSRendererType::Null
                                    : cfg.isSet("PCSX2HOOK_HWGS") ? GSRendererType::VK
                                                                            : GSRendererType::SW));

    si.SetBoolValue("EmuCore/Speedhacks", "vuThread", false);
    if (!cfg.isSet("PCSX2HOOK_SOUND")) {
        si.SetStringValue("SPU2/Output", "Backend", "Null");
    }

    si.SetBoolValue("Logging", "EnableEEConsole", true);
    si.SetBoolValue("Logging", "EnableIOPConsole", true);

    if (cfg.isSet("PCSX2HOOK_INTERP")) {
        si.SetBoolValue("EmuCore/CPU/Recompiler", "EnableEE", false);
        si.SetBoolValue("EmuCore/CPU/Recompiler", "EnableIOP", false);
        si.SetBoolValue("EmuCore/CPU/Recompiler", "EnableVU0", false);
        si.SetBoolValue("EmuCore/CPU/Recompiler", "EnableVU1", false);
    }
    // VU1 alone keeps the EE recompiler's idle-loop skip, so a savestate boot still reaches its
    // target frame quickly while hooks that only the interpreter calls back into still fire.
    if (cfg.isSet("PCSX2HOOK_VU1_INTERP")) {
        si.SetBoolValue("EmuCore/CPU/Recompiler", "EnableVU1", false);
    }
    if (cfg.isSet("PCSX2HOOK_NOFASTMEM")) {
        si.SetBoolValue("EmuCore/CPU/Recompiler", "EnableFastmem", false);
    }

    applyExtraSettings(si);
}

bool Core::configureBoot(VMBootParameters& params) {
    const Config& cfg = Config::get();
    if (cfg.isSet("PCSX2HOOK_NODISC")) {
        params.source_type = CDVD_SourceType::NoDisc;
        params.filename.clear();
        return true;
    }
    if (params.filename.empty()) {
        Console.Error("No game image provided.");
        return false;
    }
    params.source_type = CDVD_SourceType::Iso;
    params.fast_boot = !cfg.isSet("PCSX2HOOK_FULLBOOT");
    // The engine restores a savestate at the right point, unlike a mid-frame LoadState, which
    // corrupts the recompiler and TLB.
    if (const char* ls = cfg.getValue("PCSX2HOOK_STATE")) {
        params.save_state = ls;
    }
    return true;
}

bool Core::run(const VMBootParameters& params) {
    Error initError;
    if (VMManager::Initialize(params, &initError) != VMBootResult::StartupSuccess) {
        Console.Error(fmt::format("[pcsx2hook] VMManager::Initialize failed: {}",
                                  initError.GetDescription()));
        return false;
    }

    mDiscSerial = VMManager::GetDiscSerial();
    getSymbols().setSerial(mDiscSerial);

    const Config& cfg = Config::get();
    Diagnostics& diag = Diagnostics::get();
    // Before the recompiler compiles anything, so the block counters exist when it asks for them.
    diag.getExec().init();
    diag.getInsn().init();
    diag.getVuInsn().init();
    diag.getVifCmd().init();
    diag.getSpu().init();
    diag.getIop().init();
    diag.getHw().init();
    diag.getSif().init();
    diag.getGsDraws().init();
    diag.getGsTracker().init();
    diag.getExec().enableCalls();
    diag.getApi().init();  // after the rest, so their hooked addresses are left alone

    if (const char* ap = cfg.getValue("PCSX2HOOK_AUTOPRESS")) {
        mAutopress = true;
        mAutopressButtons = parseAutopressButtons(ap);
    }
    if (const char* aps = cfg.getValue("PCSX2HOOK_AUTOPRESS_SCRIPT")) {
        mAutopress = true;
        mAutopressScript = loadAutopressScript(aps);
    }
    mSaveStateFrame = uint32_t(cfg.getInt("PCSX2HOOK_SAVESTATE_FRAME", 0));

    // The two 'jr $ra; nop' stubs the hook registry returns through: one for a post-handler, one for
    // a guest call. They go in the kernel-reserved gap below the user ELF base (0x00100000), so they
    // clobber no program code, and are installed before onVmReady so a hook registered there works.
    const uint32_t sentinel =
        uint32_t(cfg.getInt("PCSX2HOOK_SENTINEL_BASE", 0x000FFF00));
    Hooks::SetReturnSentinel(sentinel);
    Hooks::SetCallMarker(sentinel + 8);

    onVmReady();

    VMManager::SetLimiterMode(cfg.isSet("PCSX2HOOK_EE_LIMIT")
                                  ? LimiterModeType::Nominal
                                  : LimiterModeType::Unlimited);
    VMManager::SetState(VMState::Running);

    for (;;) {
        VMManager::Execute();
        const VMState st = VMManager::GetState();
        if (st == VMState::Shutdown || st == VMState::Stopping) break;
        if (st == VMState::Paused) VMManager::SetState(VMState::Running);
    }

    onShutdown();
    diag.getGsDraws().close();
    diag.getGsTracker().report("shutdown");
    diag.getExec().write();
    diag.getInsn().write();
    diag.getVuInsn().write();
    diag.getVifCmd().write();
    diag.getSpu().write();
    diag.getIop().write();
    diag.getHw().write();
    diag.getSif().write();
    diag.getVif().write();
    diag.getApi().write();
    diag.getDraws().writeVuTrace();
    diag.getDraws().writeVuWatchTrace();
    diag.getDraws().writeVuJrTrace();
    diag.getDraws().writeVuExecTrace();
    diag.getDraws().writeDrawProbe();
    VMManager::Shutdown(false);
    return true;
}

void Core::onFrame() {
    mFrameCount++;
    onFrameExtra(mFrameCount);

    if (mAutopress && !mAutopressScript.empty()) {
        bool held[kPadButtonCount] = {};
        for (const auto& [frame, button, hold] : mAutopressScript) {
            held[button] |= mFrameCount >= frame && mFrameCount < frame + hold;
        }
        for (int i = 0; i < kPadButtonCount; i++) {
            mPadState[i].store(held[i], std::memory_order_relaxed);
        }
    } else if (mAutopress) {
        const bool down = (mFrameCount % 20) < 6;
        if (mAutopressButtons.empty()) {
            mPadState[PadDualshock2::Inputs::PAD_START].store(down, std::memory_order_relaxed);
            mPadState[PadDualshock2::Inputs::PAD_CROSS].store(down, std::memory_order_relaxed);
        } else {
            const size_t which = (mFrameCount / 20) % mAutopressButtons.size();
            for (size_t i = 0; i < mAutopressButtons.size(); i++) {
                mPadState[mAutopressButtons[i]].store(down && i == which,
                                                      std::memory_order_relaxed);
            }
        }
    }
    applyInputToPad();

    if (mSaveStateFrame && mFrameCount == mSaveStateFrame && !mSaveStateDone) {
        mSaveStateDone = true;
        if (const char* path = Config::get().getValue("PCSX2HOOK_SAVESTATE")) {
            VMManager::SaveState(path, false, false, {});
        }
    }

    // Written at shutdown, so a run that wants its trace has to reach the end rather than be
    // killed.
    if (Diagnostics::get().getExec().finish(mFrameCount)) {
        // Widens the mined forms with edge operands. Destroys guest state, so it runs at the end of
        // the session rather than alongside the game.
        Diagnostics::get().getInsn().runSynth();
        VMManager::SetState(VMState::Stopping);
    }
}

void Core::setPadButton(int bind, bool pressed) {
    if (bind >= 0 && bind < kPadButtonCount) {
        mPadState[bind].store(pressed, std::memory_order_relaxed);
    }
}

void Core::setSpeedLimit(bool enabled) {
    mPendingSpeedLimit.store(enabled ? 1 : 0, std::memory_order_relaxed);
}

void Core::requestSaveState() {
    mSaveStateRequested.store(true, std::memory_order_relaxed);
}

void Core::applyInputToPad() {
    const int speed = mPendingSpeedLimit.exchange(-1, std::memory_order_relaxed);
    if (speed >= 0) {
        VMManager::SetLimiterMode(speed ? LimiterModeType::Nominal : LimiterModeType::Unlimited);
    }
    for (int i = 0; i < kPadButtonCount; i++) {
        Pad::SetControllerState(0, i, mPadState[i].load(std::memory_order_relaxed) ? 1.0f : 0.0f);
    }
}

}  // namespace pcsx2hook

// SPDX-FileCopyrightText: 2002-2026 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#pragma once

#include <cstdint>

#include "trace/table.h"

namespace Hooks {
struct Context;
struct ExecBlockSlots;
}  // namespace Hooks
#include <cstddef>
#include <cstdio>
#include <string>
#include <unordered_map>
#include <vector>

#include "DebugTools/BiosDebugData.h"
#include "pcsx2/Hooks.h"

namespace pcsx2hook {

class ExecTrace {
public:
    struct BlockExtent {
        uint32_t startpc;
        uint32_t endpc;
        uint32_t wordOffset;
        bool ram;
    };

    struct CallSample {
        uint32_t a0, a1, a2, a3;
        uint32_t ra;
        uint32_t result;
    };

    struct CallSite {
        uint64_t count = 0;
        std::vector<CallSample> samples;
    };

    static constexpr size_t kMaxBlocks = 1u << 20;
    static constexpr size_t kMaxSamples = 4;
    static constexpr uint32_t kResultUnset = 0xFFFFFFFFu;
    static constexpr uint32_t kSegMask = 0x1FFFFFFFu;
    static constexpr uint32_t kMainRamEnd = 0x02000000u;
    static constexpr uint32_t kMaxThreads = 32;

    bool isEnabled();
    bool isArgsEnabled();
    void init();
    void enableCalls();
    bool finish(uint32_t frameCount);
    Hooks::ExecBlockSlots registerBlock(uint32_t startpc, uint32_t endpc);
    void onSyscall(uint32_t num, Hooks::Context& ctx);
    void write();
    Hooks::Result onSyscallReturn(Hooks::Context& ctx);
    Hooks::Result onFunctionEntry(Hooks::Context& ctx);

private:
    uint32_t getPhysAddr(uint32_t pc);
    bool isInMainRam(uint32_t pc);
    std::string getOutputDir();
    void refreshThread();
    void recordSample(CallSite& site, const Hooks::Context& ctx, uint32_t result);
    static void writeSamples(JsonTable& t, const CallSite& site, bool withResult);

    // Generated code holds these addresses, so the arrays must never move.
    uint64_t mBlockCounts[kMaxBlocks];
    uint32_t mBlockThreads[kMaxBlocks];
    uint32_t mExecThreadBit = 0;
    uint32_t mCurrentTid = 0;
    bool mThreadOverflow = false;
    std::unordered_map<uint32_t, EEInternalThread> mThreads;
    std::vector<BlockExtent> mBlocks;
    std::vector<uint32_t> mBlockWords;
    std::unordered_map<uint64_t, uint32_t> mBlockIndex;
    bool mBlocksOverflowed = false;
    std::unordered_map<uint32_t, CallSite> mSyscalls;
    std::unordered_map<uint32_t, CallSite> mSyscallSites;
    std::unordered_map<uint32_t, uint32_t> mSyscallReturnSite;
    std::unordered_map<uint32_t, uint32_t> mSyscallSiteNum;
    std::unordered_map<uint32_t, CallSite> mFunctions;
    size_t mSyscallSitesEnabled = 0;
    size_t mFunctionsEnabled = 0;
};

Hooks::Result execSyscallReturnHook(Hooks::Context& ctx);
Hooks::Result execFunctionEntryHook(Hooks::Context& ctx);
Hooks::ExecBlockSlots execBlockRegisterSink(uint32_t startpc, uint32_t endpc);
void execSyscallSink(uint32_t num, Hooks::Context& ctx);

}  // namespace pcsx2hook

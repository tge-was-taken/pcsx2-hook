// SPDX-FileCopyrightText: 2002-2026 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#pragma once

#include <cstdint>

namespace Hooks {
struct ExecBlockSlots;
}  // namespace Hooks
#include <cstddef>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "DebugTools/BiosDebugData.h"
#include "pcsx2/Hooks.h"

namespace pcsx2hook {

class IopTrace {
public:
    struct IopBlock {
        uint32_t startpc, endpc, wordOffset;
    };

    struct Import {
        std::string libname, funcname;
        uint32_t index;
        uint64_t count;
    };

    struct IopCase {
        uint32_t pc, code;
        uint32_t gpr[32], hi, lo;
        std::vector<std::pair<uint32_t, uint32_t>> deltas;
    };

    static constexpr size_t kMaxIopBlocks = 1u << 18;
    static constexpr size_t kMaxIopCases = 64;

    bool isEnabled();
    void init();
    Hooks::ExecBlockSlots registerBlock(uint32_t startpc, uint32_t endpc);
    void onImport(const char* libname, uint32_t index, const char* funcname);
    void onInsnBefore(uint32_t pc, uint32_t code);
    void onInsnAfter(uint32_t pc, uint32_t code);
    const char* getModule(uint32_t pc, uint32_t* offset);
    void write();

private:
    const IopMod* getModule(uint32_t pc);
    void refreshModules(uint32_t pc);
    std::string getOutputDir();
    const std::string& getMnemonic(uint32_t pc, uint32_t code);

    uint64_t mIopBlockCounts[kMaxIopBlocks];
    uint32_t mIopBlockThreads[kMaxIopBlocks];
    std::vector<IopBlock> mBlocks;
    std::vector<uint32_t> mBlockWords;
    std::unordered_map<uint64_t, uint32_t> mBlockIndex;
    bool mOverflowed = false;
    std::unordered_map<uint64_t, Import> mImports;
    std::unordered_map<uint32_t, std::string> mMnemonic;
    std::unordered_map<std::string, std::vector<IopCase>> mCases;
    std::unordered_map<std::string, std::unordered_set<uint64_t>> mSeen;
    uint64_t mInstructions = 0;
    std::vector<IopMod> mModules;
    IopCase mPendingCase;
    bool mPending = false;
};

Hooks::ExecBlockSlots iopBlockRegisterSink(uint32_t startpc, uint32_t endpc);
void iopImportSink(const char* libname, uint32_t index, const char* funcname);
void iopInsnBeforeSink(uint32_t pc, uint32_t code);
void iopInsnAfterSink(uint32_t pc, uint32_t code);

}  // namespace pcsx2hook

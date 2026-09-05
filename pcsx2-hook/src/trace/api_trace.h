// SPDX-FileCopyrightText: 2002-2026 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#pragma once

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include "pcsx2/Hooks.h"
#include "trace/table.h"

namespace pcsx2hook {

class ApiTrace {
public:
    static constexpr uint32_t kArgMax = 1u << 16;
    static constexpr uint32_t kArgMin = 128;
    static constexpr uint32_t kGprArgs = 8;
    static constexpr uint32_t kFprArgs = 8;
    static constexpr size_t kMaxAccesses = 4096;
    static constexpr size_t kMaxDepth = 16;
    static constexpr uint64_t kDenseCalls = 64;
    static constexpr uint64_t kMaxStride = 4096;
    static constexpr uint32_t kMemSamplesPerShape = 4;

    bool isEnabled();
    void init();
    void onMem(uint32_t addr, uint64_t value, uint32_t size, bool isRead);
    void write();
    Hooks::Result onEnter(Hooks::Context& ctx);
    void onExit(Hooks::Context& ctx);

private:
    struct Access {
        uint32_t addr, size;
        uint64_t value;
        bool isRead;
    };

    struct ArgWindow {
        uint32_t reg, addr;
        uint32_t captured;
        uint32_t span;
        uint8_t* before;
    };

    struct Call {
        uint32_t pc, ra, sp;
        uint32_t gpr[kGprArgs];
        float fpr[kFprArgs];
        std::vector<ArgWindow> windows;
        std::vector<Access> accesses;
        bool truncated;
    };

    struct FnState {
        uint64_t calls = 0;
        uint64_t recorded = 0;
        uint64_t nextAt = 0;
        uint64_t stride = 1;
    };

    void hashMix(uint64_t& h, uint64_t v);
    void emitRun();
    bool isReadable(uint32_t addr);
    uint32_t snapshotWindow(uint32_t addr, uint8_t* out);
    static std::string hexBlob(const uint8_t* b, uint32_t n);

    std::unordered_map<uint32_t, FnState> mPerFn;
    uint8_t mArgBuf[kMaxDepth][kGprArgs][kArgMax];
    FILE* mFile = nullptr;
    FILE* mSeqFile = nullptr;
    std::unique_ptr<JsonTable> mSeq;
    std::unordered_map<uint64_t, uint32_t> mDataIds;
    uint32_t mNextDataId = 0;
    uint32_t mRunId = 0xFFFFFFFFu;
    uint64_t mRunLen = 0;
    uint64_t mSeqRecords = 0;
    std::unordered_map<uint32_t, uint32_t> mShapeMemCount;
    Call mStack[kMaxDepth];
    uint32_t mDepth = 0;
    uint64_t mCalls = 0, mTruncated = 0;
};

// Hooks::Register takes plain function pointers.
void apiMemSink(uint32_t addr, uint64_t value, uint32_t size, bool isRead);
Hooks::Result apiEnterHook(Hooks::Context& ctx);
void apiExitHook(Hooks::Context& ctx);

}  // namespace pcsx2hook

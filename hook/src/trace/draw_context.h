// SPDX-FileCopyrightText: 2002-2026 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <map>
#include <mutex>
#include <set>
#include <string>
#include <vector>

namespace pcsx2hook {

enum class DrawKind : uint8_t {
    None,
    Atomic,
    Sector,
    PTank,
    Im2D,
    Im3D,
    Rt2d,
};
struct DrawContext {
    DrawKind kind = DrawKind::None;
    uint32_t object = 0;
    uint32_t material = 0;
    uint32_t pipeline = 0;
    uint32_t vuAddr = 0;
    uint32_t vuWords = 0;
    uint64_t vuHash = 0;
    uint32_t uploads = 0;
};
struct StreamPos {
    uint32_t frame = 0;
    uint32_t batch = 0;
};

class DrawTrace {
public:
    static constexpr size_t kMaxDepth = 8;
    static constexpr uint32_t kVu1Words = 4096;
    static constexpr uint32_t kVu1Instrs = kVu1Words / 2;
    static constexpr size_t kMaxStreamPos = 32;
    static constexpr size_t kMaxWatchSamples = 200000;
    static constexpr size_t kMaxExecSteps = 500000;

    struct Program {
        uint32_t addr = 0;
        uint32_t words = 0;
        uint32_t uploads = 0;
        std::vector<uint32_t> code;
        std::map<uint8_t, uint32_t> kinds;
        std::vector<StreamPos> at;
        std::set<uint32_t> getEntries;
    };

    struct MicroImage {
        std::vector<uint32_t> code;
        std::set<uint32_t> getEntries;
        uint32_t execs = 0;
    };

    struct WatchSample {
        StreamPos at;
        uint64_t programHash;
        std::vector<std::array<uint8_t, 16>> quads;
    };

    struct JrEdge {
        uint32_t pc, reg, target;
        bool operator<(const JrEdge& o) const {
            return std::tie(pc, reg, target) < std::tie(o.pc, o.reg, o.target);
        }
    };

    struct ExecRow {
        uint32_t addr;
        bool taken = false;
        uint32_t target = 0;
        std::vector<std::pair<std::string, std::vector<uint32_t>>> wrote;
    };

    struct ExecRun {
        uint64_t hash;
        uint32_t entry;
        uint32_t frame, batch;
        std::vector<ExecRow> rows;
    };

    void push(const DrawContext& ctx);
    void pop();
    DrawContext* getCurrent();
    const DrawContext& getLastPopped();
    bool isVuTraceEnabled();
    uint64_t resolveProgramAt(uint32_t pc);
    void setRunningProgramGs(uint64_t hash, StreamPos at);
    uint64_t getRunningProgram();
    void onVu1Upload(uint32_t addr, const uint32_t* words, uint32_t count, StreamPos at);
    void writeVuTrace();
    bool isVuWatchEnabled();
    const std::vector<uint32_t>& getVuWatchAddrs();
    std::vector<std::array<uint8_t, 16>> snapshotVuWatch(const uint8_t* vuMem, uint32_t vuMemSize);
    void recordVuWatchGs(uint64_t hash, const std::vector<std::array<uint8_t, 16>>& snapshot,
                         StreamPos at);
    void writeVuWatchTrace();
    bool isVuJrTraceEnabled();
    void onVu1Jr(uint32_t pc, uint32_t reg, uint32_t target);
    void writeVuJrTrace();
    bool isVuExecTraceEnabled();
    const std::string& getVuExecTraceFilter();
    void startVuExecRun(uint64_t hash, uint32_t entryAddr, StreamPos at);
    void onVu1Step(uint32_t addr, const uint32_t vf[32][4], const uint32_t vi[32],
                   const uint32_t acc[4], bool branchTaken, uint32_t branchTarget);
    void writeVuExecTrace();

private:
    void seedMicroFromVu();
    void writeVuImages();

    DrawContext mStack[kMaxDepth];
    DrawContext mLastPopped;
    std::map<uint64_t, Program> mPrograms;
    std::vector<uint32_t> mMicro = std::vector<uint32_t>(kVu1Words, 0);
    std::set<uint32_t> mUploadStarts;
    std::map<uint64_t, MicroImage> mImages;
    bool mMicroSeeded = false;
    uint32_t mLastUploadEnd = 0xFFFFFFFFu;
    std::mutex mMutex;
    uint64_t mRunning = 0;
    std::vector<WatchSample> mWatchSamples;
    bool mWatchOverflowed = false;
    std::mutex mWatchMutex;
    std::set<JrEdge> mJrEdges;
    std::mutex mJrMutex;
    std::vector<ExecRun> mExecRuns;
    bool mExecHaveLast = false;
    uint32_t mExecLastVF[32][4];
    uint32_t mExecLastVI[32];
    uint32_t mExecLastAcc[4];
    bool mExecOverflowed = false;
    std::mutex mExecMutex;
};

void vu1JrSink(uint32_t pc, uint32_t reg, uint32_t target);

}  // namespace pcsx2hook

// SPDX-FileCopyrightText: 2002-2026 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#pragma once

#include <array>
#include <bitset>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include "pcsx2/Hooks.h"
#include "trace/json.h"
#include "trace/vu_insn_trace.h"

namespace pcsx2hook {

class TimingTrace {
public:
    static constexpr size_t kMaxRuns = 256;
    static constexpr size_t kRunsPerEntry = 4;
    static constexpr size_t kRunsPerTag = 32;
    static constexpr size_t kRecordedPerEntry = 32;
    static constexpr size_t kMaxStepsPerRun = 65536;
    static constexpr uint64_t kStepBudget = 20'000'000;
    static constexpr size_t kMaxHazards = 20000;

    enum Tag : uint32_t {
        kTagStallCommit = 1,
        kTagDivInFlight = 2,
        kTagWaitqBusy = 4,
        kTagXgkickOverlap = 8,
        kTagExternal = 16,
        kTagExternalRead = 32,
    };
    static constexpr size_t kTagCount = 6;

    bool isEnabled();
    void init();
    void onEvent(Hooks::TimingEvent kind, uint32_t a, uint32_t b, uint32_t c);
    void onVuBefore(uint32_t unit, uint32_t pc);
    void onVuAfter(uint32_t unit, uint32_t pc);
    void onVuMem(uint32_t unit, uint32_t addr);
    void onVifBefore(uint32_t idx, const uint32_t* data, uint32_t pass);
    void onVifAfter(uint32_t idx, const uint32_t* data, uint32_t consumed, bool done);
    void onDmaKick(uint32_t chan, uint32_t eepc, uint32_t madr, uint32_t qwc);
    void write();

private:
    struct Run {
        bool active = false, recording = false, truncated = false;
        uint32_t entry = 0, tags = 0, lastPc = 0;
        size_t steps = 0;
        uint64_t startEe = 0, stepCycle = 0;
        VuInsnTrace::State prev;
        std::vector<uint8_t> memAsRunLeftIt;
        std::vector<std::pair<uint32_t, std::array<uint8_t, 16>>> touchedQuadsBefore;
        std::bitset<1024> externallyWritten;
        uint32_t vifTop = 0, vifItop = 0, vifTops = 0;
        std::unique_ptr<JsonObject> row;
    };

    struct Kick {
        bool pending = false;
        uint32_t addr = 0, pc = 0, chunks = 0, quads = 0, flushedQuads = 0, hazards = 0;
        std::vector<uint8_t> sentMem;
        std::bitset<1024> sent;
        uint64_t issueVu = 0, firstVu = 0, lastVu = 0;
        std::vector<uint8_t> memAtIssue;
        std::bitset<1024> vuStoredSinceIssue;
    };

    struct VifCommand {
        bool active = false;
        uint32_t code = 0, passes = 0, stalls = 0, words = 0, lastConsumed = 0;
        const uint32_t* lastData = nullptr;
        uint64_t startEe = 0;
    };

    std::string getOutputDir();
    bool isTimelineOpen() const;
    void emit(JsonObject& row);
    void startRun(uint32_t unit, uint32_t pc);
    void endRun(uint32_t unit, const char* reason);
    void recordExternal(uint32_t unit);
    uint32_t classifyLower(uint32_t unit, uint32_t upper, uint32_t lower);
    void finishKick();
    void measureRewrites();

    uint32_t mFrameLimit = 10;
    uint32_t mFrames = 0;
    FILE* mTimeline = nullptr;
    FILE* mRunFile = nullptr;
    FILE* mHazardFile = nullptr;
    FILE* mImageFile = nullptr;
    uint64_t mTimelineEvents = 0;

    Run mRuns[2];
    size_t mRunsKept = 0, mRunsSeen = 0;
    uint64_t mStepsRecorded = 0;
    std::unordered_map<uint32_t, size_t> mEntryKept, mEntryRecorded;
    size_t mTagKept[kTagCount] = {};
    size_t mTagSeen[kTagCount] = {};
    std::unordered_map<uint64_t, bool> mImagesWritten;
    std::unordered_map<uint32_t, uint32_t> mLowerClass[2];

    Kick mKick, mLastKick;
    uint64_t mKicks = 0, mHazards = 0, mRewrittenAfterSend = 0, mExternalReads = 0;
    VifCommand mVif[2];
};

void timingEventSink(Hooks::TimingEvent kind, uint32_t a, uint32_t b, uint32_t c);
void timingVuBeforeSink(uint32_t unit, uint32_t pc);
void timingVuAfterSink(uint32_t unit, uint32_t pc);
void timingVuMemSink(uint32_t unit, uint32_t addr);
void timingVifBeforeSink(uint32_t idx, const uint32_t* data, uint32_t pass);
void timingVifAfterSink(uint32_t idx, const uint32_t* data, uint32_t consumed, bool done);
void timingDmaKickSink(uint32_t chan, uint32_t eepc, uint32_t madr, uint32_t qwc);

}  // namespace pcsx2hook

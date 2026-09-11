// SPDX-FileCopyrightText: 2002-2026 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <deque>
#include <mutex>
#include <string>
#include <vector>

#include "pcsx2/Hooks.h"

namespace pcsx2hook {

class GsDraws {
public:
    static constexpr size_t kKeepFrames = 4;

    struct FrameRecords {
        uint32_t frame = 0;
        std::vector<std::string> rows;
    };

    struct FbTarget {
        void (*sync)(const void*) = nullptr;
        uint32_t (*read)(const void*, int, int) = nullptr;
        const void* ctx = nullptr;
        uint32_t fbp = 0, dispW = 0, dispH = 0;
    };

    void init();
    bool isEnabled();
    void setRecording(bool on);
    uint32_t getStandaloneFrames();
    void close();
    size_t writeLastFrame(std::FILE* out);
    void setDeferred(bool on);
    void enableCapture(int skip);
    void markCaptureStart();
    bool takeCapture(std::vector<uint32_t>& pixels, uint32_t& w, uint32_t& h, uint32_t& frame);
    std::string getRowsForFrame(uint32_t frame);
    uint32_t getFrame();
    uint64_t getBatch();

    void onVSync();
    void onDraw(const Hooks::GsDraw& d);

private:
    void dumpDrawBuffer(const Hooks::GsDraw& d, uint64_t batch, uint32_t frame);
    void captureFinishedFrame();

    std::FILE* mOut = nullptr;
    bool mRecording = false;
    uint64_t mIndex = 0;
    uint64_t mFrameIndex = 0;
    std::atomic<uint32_t> mGsFrame{0};
    std::mutex mMutex;
    std::deque<FrameRecords> mKept;
    bool mDeferred = false;
    int mDumpFirst = -1, mDumpLast = -1;
    std::string mDumpBase;
    FbTarget mLastTarget;
    std::vector<uint32_t> mDisplayFbps;
    int mCaptureSkip = -1;
    bool mMarked = false;
    uint32_t mBatchesSinceMark = 0;
    std::vector<uint32_t> mCapturePixels;
    uint32_t mCaptureW = 0, mCaptureH = 0, mCaptureFrame = 0;
};

void gsDrawSink(const Hooks::GsDraw& draw);
void gsVSyncSink();

}  // namespace pcsx2hook

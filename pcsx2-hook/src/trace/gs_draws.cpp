// SPDX-FileCopyrightText: 2002-2026 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#include "trace/gs_draws.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <mutex>
#include <string>
#include <vector>

#include "MTGS.h"
#include "config.h"
#include "diagnostics.h"
#include "trace/draw_context.h"
#include "trace/dump_dir.h"
#include "pcsx2/Hooks.h"
#include "trace/vif_trace.h"

namespace pcsx2hook {
void GsDraws::dumpDrawBuffer(const Hooks::GsDraw& d, uint64_t batch, uint32_t frame) {
    if (!d.readPixel) {
        return;
    }
    const int w = int(((d.scissor >> 16) & 0x7FF) + 1);
    const int h = int(((d.scissor >> 48) & 0x7FF) + 1);
    if (w <= 0 || h <= 0 || w > 4096 || h > 4096) {
        return;
    }
    char path[512];
    std::snprintf(path, sizeof(path), "%s_f%u_beforeB%03llu.ppm", mDumpBase.c_str(), frame,
                  static_cast<unsigned long long>(batch));
    std::FILE* f = std::fopen(path, "wb");
    if (!f) {
        return;
    }
    char apath[512];
    std::snprintf(apath, sizeof(apath), "%s_f%u_beforeB%03llu.pgm", mDumpBase.c_str(), frame,
                  static_cast<unsigned long long>(batch));
    std::FILE* af = std::fopen(apath, "wb");
    std::fprintf(f, "P6\n%d %d\n255\n", w, h);
    if (af) {
        std::fprintf(af, "P5\n%d %d\n255\n", w, h);
    }
    if (d.syncPixels) {
        d.syncPixels(d.readCtx);
    }
    std::vector<uint8_t> row(size_t(w) * 3), arow(size_t(w), 0);
    for (int y = 0; y < h; y++) {
        for (int x = 0; x < w; x++) {
            const uint32_t p = d.readPixel(d.readCtx, x, y);
            row[size_t(x) * 3 + 0] = uint8_t(p & 0xFF);
            row[size_t(x) * 3 + 1] = uint8_t((p >> 8) & 0xFF);
            row[size_t(x) * 3 + 2] = uint8_t((p >> 16) & 0xFF);
            arow[size_t(x)] = uint8_t((p >> 24) & 0xFF);
        }
        std::fwrite(row.data(), 1, row.size(), f);
        if (af) {
            std::fwrite(arow.data(), 1, arow.size(), af);
        }
    }
    std::fclose(f);
    if (af) {
        std::fclose(af);
    }
}

void GsDraws::captureFinishedFrame() {
    const FbTarget t = mLastTarget;
    if (!t.read || t.dispW == 0 || t.dispH == 0) {
        return;
    }
    if (t.sync) {
        t.sync(t.ctx);
    }
    std::vector<uint32_t> px(size_t(t.dispW) * t.dispH);
    for (uint32_t y = 0; y < t.dispH; y++) {
        for (uint32_t x = 0; x < t.dispW; x++) {
            px[size_t(y) * t.dispW + x] = t.read(t.ctx, int(x), int(y));
        }
    }
    const std::lock_guard<std::mutex> lock(mMutex);
    mCapturePixels = std::move(px);
    mCaptureW = t.dispW;
    mCaptureH = t.dispH;
    mCaptureFrame = mGsFrame.load();
}

void GsDraws::onVSync() {
    if (mCaptureSkip >= 0 && mLastTarget.read && mMarked && mBatchesSinceMark > 0) {
        if (mCaptureSkip-- == 0) {
            captureFinishedFrame();
            mMarked = false;
        }
        mBatchesSinceMark = 0;
    }
    mLastTarget = {};
    mGsFrame++;
    if (!mRecording) {
        return;
    }
    const std::lock_guard<std::mutex> lock(mMutex);
    mFrameIndex = 0;
    mKept.push_back({mGsFrame.load(), {}});
    while (mKept.size() > kKeepFrames) {
        mKept.pop_front();
    }
}

void GsDraws::onDraw(const Hooks::GsDraw& d) {
    const uint32_t fbp = unsigned((d.frame & 0x1FF) << 5);
    for (uint32_t disp : {d.dispFbp0, d.dispFbp1}) {
        if (disp != ~0u &&
            std::find(mDisplayFbps.begin(), mDisplayFbps.end(), disp) == mDisplayFbps.end()) {
            mDisplayFbps.push_back(disp);
        }
    }
    if (std::find(mDisplayFbps.begin(), mDisplayFbps.end(), fbp) != mDisplayFbps.end()) {
        mLastTarget = {d.syncPixels, d.readPixel, d.readCtx, fbp, d.dispW, d.dispH};
        mBatchesSinceMark += mMarked ? 1 : 0;
    }
    if (Config::get().getValue("PCSX2HOOK_SW_SEL")) {
        std::fprintf(stderr, "[gsrow] f%u b%llu test=0x%llX alpha=0x%llX nv=%u\n", mGsFrame.load(),
                     static_cast<unsigned long long>(mFrameIndex),
                     static_cast<unsigned long long>(d.test),
                     static_cast<unsigned long long>(d.alpha), d.nverts);
    }
    if (!mRecording) {
        return;
    }
    const uint64_t prim = d.prim, tex0 = d.tex0, tex1 = d.tex1, clamp = d.clamp;
    const uint64_t test = d.test, alpha = d.alpha, frame = d.frame, scissor = d.scissor;
    const float* bbox = d.bbox;
    const uint32_t rgbaq = d.rgbaq, nverts = d.nverts;
    const auto bits = [](uint64_t v, unsigned lo, unsigned n) {
        return unsigned((v >> lo) & ((1ull << n) - 1));
    };
    char row[1024];
    std::snprintf(
        row, sizeof(row),
        "{\"type\":\"gs\",\"i\":%llu,\"f\":%u,\"nverts\":%u,\"prim\":%u,\"ctxt\":%u,\"ac\":%u,"
        "\"iip\":%u,\"tme\":%u,\"fge\":%u,\"abe\":%u,\"aa1\":%u,"
        "\"tex0\":\"0x%016llX\",\"tbp\":%u,\"tbw\":%u,\"psm\":%u,\"tfx\":%u,\"tcc\":%u,"
        "\"tw\":%u,\"th\":%u,"
        "\"tex1\":\"0x%016llX\",\"lcm\":%u,\"mxl\":%u,\"mmag\":%u,\"mmin\":%u,\"lodl\":%u,\"lodk\":"
        "%d,"
        "\"clamp\":\"0x%016llX\",\"wms\":%u,\"wmt\":%u,"
        "\"test\":\"0x%016llX\",\"ate\":%u,\"atst\":%u,\"aref\":%u,\"afail\":%u,"
        "\"date\":%u,\"datm\":%u,\"zte\":%u,\"ztst\":%u,"
        "\"alpha\":\"0x%016llX\",\"a\":%u,\"b\":%u,\"c\":%u,\"d\":%u,\"fix\":%u,"
        "\"bbox\":[%.1f,%.1f,%.1f,%.1f],\"scissor\":[%u,%u,%u,%u],"
        "\"fbp\":%u,\"fbw\":%u,\"fpsm\":%u,\"fbmsk\":\"0x%08X\",\"rgbaq\":\"0x%08X\",\"r\":%u,"
        "\"g\":%u,\"b_\":%u,\"a_\":%u,"
        "\"zbp\":%u,\"zpsm\":%u,\"zmsk\":%u,\"zmin\":%u,\"zmax\":%u,"
        "\"pabe\":%u,\"colclamp\":%u,\"fba\":%u,\"dthe\":%u,"
        "\"dispW\":%u,\"dispH\":%u,\"disp0\":%d,\"disp1\":%d,"
        "\"fog\":%u,\"q\":%.6g,\"vu\":\"0x%016llX\"}\n",
        static_cast<unsigned long long>(mFrameIndex++), mGsFrame.load(), nverts, bits(prim, 0, 3),
        bits(prim, 9, 1), bits(prim, 32, 1), bits(prim, 3, 1), bits(prim, 4, 1), bits(prim, 5, 1),
        bits(prim, 6, 1), bits(prim, 7, 1), static_cast<unsigned long long>(tex0),
        bits(tex0, 0, 14), bits(tex0, 14, 6), bits(tex0, 20, 6), bits(tex0, 35, 2),
        bits(tex0, 34, 1), bits(tex0, 26, 4), bits(tex0, 30, 4),
        static_cast<unsigned long long>(tex1), bits(tex1, 0, 1), bits(tex1, 2, 3), bits(tex1, 5, 1),
        bits(tex1, 6, 3), bits(tex1, 19, 2), int(int32_t(bits(tex1, 32, 12) << 20) >> 20),
        static_cast<unsigned long long>(clamp), bits(clamp, 0, 2), bits(clamp, 2, 2),
        static_cast<unsigned long long>(test), bits(test, 0, 1), bits(test, 1, 3), bits(test, 4, 8),
        bits(test, 12, 2), bits(test, 14, 1), bits(test, 15, 1), bits(test, 16, 1),
        bits(test, 17, 2), static_cast<unsigned long long>(alpha), bits(alpha, 0, 2),
        bits(alpha, 2, 2), bits(alpha, 4, 2), bits(alpha, 6, 2), bits(alpha, 32, 8), bbox[0],
        bbox[1], bbox[2], bbox[3], bits(scissor, 0, 11), bits(scissor, 16, 11),
        bits(scissor, 32, 11), bits(scissor, 48, 11), bits(frame, 0, 9), bits(frame, 16, 6),
        bits(frame, 24, 6), unsigned(frame >> 32), rgbaq, rgbaq & 0xFF, (rgbaq >> 8) & 0xFF,
        (rgbaq >> 16) & 0xFF, (rgbaq >> 24) & 0xFF, bits(d.zbuf, 0, 9), bits(d.zbuf, 24, 4),
        bits(d.zbuf, 32, 1), d.zMin, d.zMax, d.pabe, d.colclamp, d.fba, d.dthe, d.dispW, d.dispH,
        int(d.dispFbp0), int(d.dispFbp1), d.fog, double(d.q),
        static_cast<unsigned long long>(Diagnostics::get().getDraws().getRunningProgram()));
    if (mOut) {
        mIndex++;
    }
    if (mDumpFirst >= 0 && int(mFrameIndex) > mDumpFirst && int(mFrameIndex) <= mDumpLast + 1) {
        dumpDrawBuffer(d, mFrameIndex - 1, mGsFrame.load());
    }
    const std::lock_guard<std::mutex> lock(mMutex);
    if (!mKept.empty()) {
        mKept.back().rows.emplace_back(row);
    }
}
void GsDraws::init() {
    const char* path = Config::get().getValue("PCSX2HOOK_GS_TRACE");
    if (path) {
        mOut = std::fopen(path, "w");
        if (!mOut) {
            std::fprintf(stderr, "[gsdraw] cannot open %s\n", path);
        } else {
            std::fprintf(stderr, "[gsdraw] GS draw trace -> %s\n", path);
        }
    }
    if (const char* range = Config::get().getValue("PCSX2HOOK_GS_DUMP")) {
        const char* dash = std::strchr(range, '-');
        mDumpFirst = std::atoi(range);
        mDumpLast = dash ? std::atoi(dash + 1) : mDumpFirst;
        const char* base = Config::get().getValue("PCSX2HOOK_GS_DUMP_OUT");
        mDumpBase = base ? base : Diagnostics::get().getDumps().getPath("gsbatch");
        std::fprintf(stderr,
                     "[gsdraw] dumping the draw buffer before batches %d..%d -> "
                     "%s_f<frame>_beforeB<i>.ppm\n",
                     mDumpFirst, mDumpLast, mDumpBase.c_str());
    }
    Hooks::SetGsDrawSink(&gsDrawSink);
    Hooks::SetGsVSyncSink(&gsVSyncSink);
    if (Diagnostics::get().getDraws().isVuTraceEnabled() ||
        Diagnostics::get().getDraws().isVuWatchEnabled() ||
        Diagnostics::get().getDraws().isVuExecTraceEnabled()) {
        Hooks::SetVu1UploadSink([](u32 addr, const u32* words, u32 count) {
            Diagnostics::get().getDraws().onVu1Upload(
                addr, words, count,
                {Diagnostics::get().getGsDraws().getFrame(),
                 uint32_t(Diagnostics::get().getGsDraws().getBatch())});
        });
        Hooks::SetVu1ExecSink([](u32 pc, const u8* vuMem, u32 vuMemSize) {
            const uint64_t hash = Diagnostics::get().getDraws().resolveProgramAt(pc);
            const uint32_t entry = pc & 0x3fff;
            std::vector<std::array<uint8_t, 16>> snapshot;
            if (Diagnostics::get().getDraws().isVuWatchEnabled()) {
                snapshot = Diagnostics::get().getDraws().snapshotVuWatch(vuMem, vuMemSize);
            }
            MTGS::RunOnGSThread([hash, entry, snapshot]() {
                const StreamPos at{Diagnostics::get().getGsDraws().getFrame(),
                                   uint32_t(Diagnostics::get().getGsDraws().getBatch())};
                Diagnostics::get().getDraws().setRunningProgramGs(hash, at);
                if (!snapshot.empty()) {
                    Diagnostics::get().getDraws().recordVuWatchGs(hash, snapshot, at);
                }
                if (Diagnostics::get().getDraws().isVuExecTraceEnabled()) {
                    Diagnostics::get().getDraws().startVuExecRun(hash, entry >> 3, at);
                }
            });
        });
        std::fprintf(stderr,
                     "[vu] tracing VU1 microprogram uploads against the open draw context\n");
    }
    if (Diagnostics::get().getDraws().isVuJrTraceEnabled()) {
        Hooks::SetVu1JrSink(&vu1JrSink);
        std::fprintf(
            stderr,
            "[vu] tracing VU1 JR targets (needs PCSX2HOOK_INTERP=1 to see the recompiler's "
            "resolved targets, since generated code does not call back here)\n");
    }
    if (Diagnostics::get().getDraws().isVuExecTraceEnabled()) {
        Hooks::SetVu1StepSink([](const Hooks::Vu1Step& step) {
            Diagnostics::get().getDraws().onVu1Step(step.addr, step.vf, step.vi, step.acc,
                                                    step.branchTaken, step.branchTarget);
        });
        std::fprintf(stderr,
                     "[vu] tracing VU1 instruction execution (needs PCSX2HOOK_VU1_INTERP=1, since "
                     "the recompiler never runs the stepped path this hooks)\n");
    }
    if (Diagnostics::get().getVif().isEnabled()) {
        Hooks::SetVifTagSink(&vifTagSink);
        Hooks::SetVifCodeSink(&vifCodeSink);
        std::fprintf(stderr, "[vif] tracing VIF1 DMA tags and code words\n");
    }
}
uint32_t GsDraws::getFrame() {
    return mGsFrame.load();
}
uint64_t GsDraws::getBatch() {
    return mFrameIndex;
}
bool GsDraws::isEnabled() {
    return true;
}
uint32_t GsDraws::getStandaloneFrames() {
    static const uint32_t frames = [] {
        if (!Config::get().getValue("PCSX2HOOK_GS_TRACE")) return 0u;
        const char* n = Config::get().getValue("PCSX2HOOK_GS_TRACE_FRAMES");
        const int v = n ? std::atoi(n) : 0;
        return v > 0 ? static_cast<uint32_t>(v) : 60u;
    }();
    return frames;
}
void GsDraws::setRecording(bool on) {
    mRecording = on;
}
void GsDraws::setDeferred(bool on) {
    const std::lock_guard<std::mutex> lock(mMutex);
    mDeferred = on;
}
void GsDraws::enableCapture(int skip) {
    const std::lock_guard<std::mutex> lock(mMutex);
    mCapturePixels.clear();
    mCaptureSkip = skip;
}
void GsDraws::markCaptureStart() {
    mMarked = true;
    mBatchesSinceMark = 0;
    std::fprintf(stderr, "[gsdraw] mark at GS frame %u, %llu batches into it\n", mGsFrame.load(),
                 static_cast<unsigned long long>(mFrameIndex));
}
bool GsDraws::takeCapture(std::vector<uint32_t>& pixels, uint32_t& w, uint32_t& h,
                          uint32_t& frame) {
    const std::lock_guard<std::mutex> lock(mMutex);
    if (mCapturePixels.empty()) {
        return false;
    }
    pixels = std::move(mCapturePixels);
    mCapturePixels.clear();
    w = mCaptureW;
    h = mCaptureH;
    frame = mCaptureFrame;
    mCaptureSkip = -1;
    return true;
}
std::string GsDraws::getRowsForFrame(uint32_t frame) {
    const std::lock_guard<std::mutex> lock(mMutex);
    std::string out;
    for (const FrameRecords& f : mKept) {
        if (f.frame != frame) {
            continue;
        }
        for (const std::string& row : f.rows) {
            out += row;
        }
    }
    return out;
}
std::string GsDraws::getCompletedRows() {
    const std::lock_guard<std::mutex> lock(mMutex);
    if (mKept.size() < 2) {
        return {};
    }
    for (auto it = mKept.rbegin() + 1; it != mKept.rend(); ++it) {
        if (it->rows.empty()) {
            continue;
        }
        std::string out;
        for (const std::string& row : it->rows) {
            out += row;
        }
        return out;
    }
    return {};
}
size_t GsDraws::writeLastFrame(std::FILE* out) {
    const std::lock_guard<std::mutex> lock(mMutex);
    if (mDeferred) {
        return 0;
    }
    if (!out || mKept.size() < 2) {
        return 0;
    }
    const FrameRecords* best = nullptr;
    for (size_t i = 0; i + 1 < mKept.size(); i++) {
        if (!best || mKept[i].rows.size() > best->rows.size()) {
            best = &mKept[i];
        }
    }
    for (const std::string& row : best->rows) {
        std::fputs(row.c_str(), out);
    }
    return best->rows.size();
}
void GsDraws::close() {
    if (mOut) {
        std::fprintf(stderr, "[gsdraw] wrote %llu GS draws\n",
                     static_cast<unsigned long long>(mIndex));
        std::fclose(mOut);
        mOut = nullptr;
    }
}

void gsDrawSink(const Hooks::GsDraw& draw) {
    Diagnostics::get().getGsDraws().onDraw(draw);
}

void gsVSyncSink() {
    Diagnostics::get().getGsDraws().onVSync();
}

}  // namespace pcsx2hook

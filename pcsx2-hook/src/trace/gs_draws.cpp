// SPDX-FileCopyrightText: 2002-2026 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#include "trace/gs_draws.h"
#include "trace/json.h"

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
    const std::string row =
        JsonObject()
            .addString("type", "gs")
            .addUint("i", mFrameIndex++)
            .addUint("f", mGsFrame.load())
            .addUint("nverts", nverts)
            .addUint("prim", bits(prim, 0, 3))
            .addUint("ctxt", bits(prim, 9, 1))
            .addUint("ac", bits(prim, 32, 1))
            .addUint("iip", bits(prim, 3, 1))
            .addUint("tme", bits(prim, 4, 1))
            .addUint("fge", bits(prim, 5, 1))
            .addUint("abe", bits(prim, 6, 1))
            .addUint("aa1", bits(prim, 7, 1))
            .addHex("tex0", tex0, 16)
            .addUint("tbp", bits(tex0, 0, 14))
            .addUint("tbw", bits(tex0, 14, 6))
            .addUint("psm", bits(tex0, 20, 6))
            .addUint("tfx", bits(tex0, 35, 2))
            .addUint("tcc", bits(tex0, 34, 1))
            .addUint("tw", bits(tex0, 26, 4))
            .addUint("th", bits(tex0, 30, 4))
            .addHex("tex1", tex1, 16)
            .addUint("lcm", bits(tex1, 0, 1))
            .addUint("mxl", bits(tex1, 2, 3))
            .addUint("mmag", bits(tex1, 5, 1))
            .addUint("mmin", bits(tex1, 6, 3))
            .addUint("lodl", bits(tex1, 19, 2))
            .addInt("lodk", int32_t(bits(tex1, 32, 12) << 20) >> 20)
            .addHex("clamp", clamp, 16)
            .addUint("wms", bits(clamp, 0, 2))
            .addUint("wmt", bits(clamp, 2, 2))
            .addHex("test", test, 16)
            .addUint("ate", bits(test, 0, 1))
            .addUint("atst", bits(test, 1, 3))
            .addUint("aref", bits(test, 4, 8))
            .addUint("afail", bits(test, 12, 2))
            .addUint("date", bits(test, 14, 1))
            .addUint("datm", bits(test, 15, 1))
            .addUint("zte", bits(test, 16, 1))
            .addUint("ztst", bits(test, 17, 2))
            .addHex("alpha", alpha, 16)
            .addUint("a", bits(alpha, 0, 2))
            .addUint("b", bits(alpha, 2, 2))
            .addUint("c", bits(alpha, 4, 2))
            .addUint("d", bits(alpha, 6, 2))
            .addUint("fix", bits(alpha, 32, 8))
            .addReals("bbox", {bbox[0], bbox[1], bbox[2], bbox[3]}, 1)
            .addUints("scissor", {bits(scissor, 0, 11), bits(scissor, 16, 11),
                                  bits(scissor, 32, 11), bits(scissor, 48, 11)})
            .addUint("fbp", bits(frame, 0, 9))
            .addUint("fbw", bits(frame, 16, 6))
            .addUint("fpsm", bits(frame, 24, 6))
            .addHex("fbmsk", unsigned(frame >> 32), 8)
            .addHex("rgbaq", rgbaq, 8)
            .addUint("r", rgbaq & 0xFF)
            .addUint("g", (rgbaq >> 8) & 0xFF)
            .addUint("b_", (rgbaq >> 16) & 0xFF)
            .addUint("a_", (rgbaq >> 24) & 0xFF)
            .addUint("zbp", bits(d.zbuf, 0, 9))
            .addUint("zpsm", bits(d.zbuf, 24, 4))
            .addUint("zmsk", bits(d.zbuf, 32, 1))
            .addUint("zmin", d.zMin)
            .addUint("zmax", d.zMax)
            .addUint("pabe", d.pabe)
            .addUint("colclamp", d.colclamp)
            .addUint("fba", d.fba)
            .addUint("dthe", d.dthe)
            .addUint("dispW", d.dispW)
            .addUint("dispH", d.dispH)
            .addInt("disp0", int(d.dispFbp0))
            .addInt("disp1", int(d.dispFbp1))
            .addUint("fog", d.fog)
            .addReal("q", double(d.q))
            .addHex("vu", Diagnostics::get().getDraws().getRunningProgram(), 16)
            .take();
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
    DrawTrace& draws = Diagnostics::get().getDraws();
    // The sinks outlive this scope, so each takes its own reference rather than capturing one.
    if (draws.isVuTraceEnabled() || draws.isVuWatchEnabled() || draws.isVuExecTraceEnabled()) {
        Hooks::SetVu1UploadSink([](u32 addr, const u32* words, u32 count) {
            GsDraws& gs = Diagnostics::get().getGsDraws();
            Diagnostics::get().getDraws().onVu1Upload(addr, words, count,
                                                      {gs.getFrame(), uint32_t(gs.getBatch())});
        });
        Hooks::SetVu1ExecSink([](u32 pc, const u8* vuMem, u32 vuMemSize) {
            DrawTrace& d = Diagnostics::get().getDraws();
            const uint64_t hash = d.resolveProgramAt(pc);
            const uint32_t entry = pc & 0x3fff;
            std::vector<std::array<uint8_t, 16>> snapshot;
            if (d.isVuWatchEnabled()) {
                snapshot = d.snapshotVuWatch(vuMem, vuMemSize);
            }
            MTGS::RunOnGSThread([hash, entry, snapshot]() {
                GsDraws& gs = Diagnostics::get().getGsDraws();
                DrawTrace& t = Diagnostics::get().getDraws();
                const StreamPos at{gs.getFrame(), uint32_t(gs.getBatch())};
                t.setRunningProgramGs(hash, at);
                if (!snapshot.empty()) {
                    t.recordVuWatchGs(hash, snapshot, at);
                }
                if (t.isVuExecTraceEnabled()) {
                    t.startVuExecRun(hash, entry >> 3, at);
                }
            });
        });
        std::fprintf(stderr,
                     "[vu] tracing VU1 microprogram uploads against the open draw context\n");
    }
    if (draws.isVuJrTraceEnabled()) {
        Hooks::SetVu1JrSink(&vu1JrSink);
        std::fprintf(
            stderr,
            "[vu] tracing VU1 JR targets (needs PCSX2HOOK_INTERP=1 to see the recompiler's "
            "resolved targets, since generated code does not call back here)\n");
    }
    if (draws.isVuExecTraceEnabled()) {
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

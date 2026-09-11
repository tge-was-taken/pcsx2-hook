// SPDX-FileCopyrightText: 2002-2026 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#include "trace/timing_trace.h"
#include "trace/vif_cmd_trace.h"

#include <cstring>
#include <filesystem>

#include "Config.h"
#include "DebugTools/Debug.h"
#include "Gif.h"
#include "R5900.h"
#include "VU.h"
#include "VUmicro.h"
#include "Vif.h"
#include "config.h"
#include "diagnostics.h"

namespace pcsx2hook {

namespace {
enum LowerClass : uint32_t { kLowerOther, kLowerDiv, kLowerWaitq, kLowerLoad };

const char* const kTagNames[TimingTrace::kTagCount] = {"stallCommit", "divInFlight", "waitqBusy",
                                                       "xgkickOverlap", "external", "externalRead"};

uint32_t getDataSize(uint32_t unit) {
    return unit ? VU1_MEMSIZE : VU0_MEMSIZE;
}

uint32_t getProgSize(uint32_t unit) {
    return unit ? VU1_PROGSIZE : VU0_PROGSIZE;
}

bool isRunning(uint32_t unit) {
    return VU0.VI[REG_VPU_STAT].UL & (unit ? 0x100u : 0x1u);
}

uint64_t hashBytes(const uint8_t* b, size_t n) {
    uint64_t h = 1469598103934665603ull;
    for (size_t i = 0; i < n; i++) h = (h ^ b[i]) * 1099511628211ull;
    return h;
}

const char* getTransferName(uint32_t type) {
    switch (type) {
        case GIF_TRANS_XGKICK: return "XGKICK";
        case GIF_TRANS_MTVU: return "MTVU";
        case GIF_TRANS_DIRECT: return "DIRECT";
        case GIF_TRANS_DIRECTHL: return "DIRECTHL";
        case GIF_TRANS_DMA: return "DMA";
        case GIF_TRANS_FIFO: return "FIFO";
        default: return "?";
    }
}

int64_t cyclesUntilResult(bool enabled, uint32_t latency, uint64_t now, uint64_t start) {
    return enabled ? static_cast<int64_t>(latency) - static_cast<int64_t>(now - start) : -1;
}

void addRegDeltas(JsonObject& row, const VuInsnTrace::State& from, const VuInsnTrace::State& to) {
    row.beginArray("d");
    for (int i = 0; i < 32; i++) {
        if (std::memcmp(from.vf[i], to.vf[i], 16) != 0)
            row.beginObject().addString("f", "vf").addUint("n", i).addHex128("v", to.vf[i]).endObject();
    }
    for (int i = 0; i < 32; i++) {
        if (from.vi[i] != to.vi[i])
            row.beginObject().addString("f", "vi").addUint("n", i).addHexDigits("v", to.vi[i], 8).endObject();
    }
    if (std::memcmp(from.acc, to.acc, 16) != 0)
        row.beginObject().addString("f", "acc").addUint("n", 0).addHex128("v", to.acc).endObject();
    row.endArray();
}
}  // namespace

std::string TimingTrace::getOutputDir() {
    const char* env = Config::get().getValue("PCSX2HOOK_TIMING_TRACE");
    if (!env || !*env || std::strcmp(env, "1") == 0) return Diagnostics::get().getDumps().getDir();
    return env;
}

bool TimingTrace::isEnabled() {
    static const bool on = Config::get().getValue("PCSX2HOOK_TIMING_TRACE") != nullptr;
    return on;
}

void TimingTrace::init() {
    if (!isEnabled()) return;
    const std::string dir = getOutputDir();
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);
    mFrameLimit = static_cast<uint32_t>(Config::get().getInt("PCSX2HOOK_TIMING_TRACE_FRAMES", 10));
    mTimeline = std::fopen((dir + "/timing_timeline.jsonl").c_str(), "w");
    mRunFile = std::fopen((dir + "/vu_runs.jsonl").c_str(), "w");
    mImageFile = std::fopen((dir + "/vu_run_images.jsonl").c_str(), "w");
    mHazardFile = std::fopen((dir + "/xgkick_hazards.jsonl").c_str(), "w");

    Hooks::SetTimingSink(&timingEventSink);
    Hooks::AddVuInsnSink(&timingVuBeforeSink, &timingVuAfterSink);
    Hooks::AddVuMemSink(&timingVuMemSink);
    Hooks::AddVifCmdSink(&timingVifBeforeSink, &timingVifAfterSink);
    Hooks::AddDmaKickSink(&timingDmaKickSink);

    std::fprintf(stderr, "[timing] recording %u frames of timeline to %s\n", mFrameLimit, dir.c_str());
    if (EmuConfig.Speedhacks.vu1Instant)
        std::fprintf(stderr, "[timing] Instant VU1 is on, so VU1 runs whole at MSCAL; set "
                             "PCSX2HOOK_TIMING=accurate for the interleaved order\n");
    if (!CpuVU1->IsInterpreter || !CpuVU0->IsInterpreter)
        std::fprintf(stderr, "[timing] VU runs and XGKICK need PCSX2HOOK_VU0_INTERP=1 and "
                             "PCSX2HOOK_VU1_INTERP=1; the recompilers never call back\n");
}

bool TimingTrace::isTimelineOpen() const {
    return mTimeline && mFrames < mFrameLimit;
}

void TimingTrace::emit(JsonObject& row) {
    const std::string text = row.take();
    std::fwrite(text.data(), 1, text.size(), mTimeline);
    mTimelineEvents++;
}

uint32_t TimingTrace::classifyLower(uint32_t unit, uint32_t upper, uint32_t lower) {
    const bool lowerIsImmediate = upper & (1u << 31);
    if (lowerIsImmediate) return kLowerOther;
    auto& cache = mLowerClass[unit];
    const auto it = cache.find(lower);
    if (it != cache.end()) return it->second;
    const std::string m = vuMnemonic(unit ? disVU1MicroLF(lower, 0) : disVU0MicroLF(lower, 0));
    const auto startsWith = [&m](const char* prefix) { return m.rfind(prefix, 0) == 0; };
    uint32_t cls = kLowerOther;
    if (startsWith("DIV") || startsWith("SQRT") || startsWith("RSQRT"))
        cls = kLowerDiv;
    else if (startsWith("WAITQ"))
        cls = kLowerWaitq;
    else if (startsWith("LQ") || startsWith("ILW"))
        cls = kLowerLoad;
    cache.emplace(lower, cls);
    return cls;
}

void TimingTrace::startRun(uint32_t unit, uint32_t pc) {
    Run& r = mRuns[unit];
    if (r.active) endRun(unit, "restart");
    mRunsSeen++;
    r.active = true;
    r.recording = false;
    r.truncated = false;
    r.entry = pc;
    r.tags = 0;
    r.steps = 0;
    r.lastPc = pc;
    r.externallyWritten.reset();
    r.startEe = cpuRegs.cycle;

    bool tagOpen = false;
    for (size_t t = 0; t < kTagCount; t++) tagOpen |= mTagKept[t] < kRunsPerTag;
    const uint32_t entryKey = (unit << 16) | pc;
    const bool entryOpen = mEntryKept[entryKey] < kRunsPerEntry;
    r.recording = mRunFile && mRunsKept < kMaxRuns && mStepsRecorded < kStepBudget &&
                  mEntryRecorded[entryKey] < kRecordedPerEntry && (entryOpen || tagOpen);
    if (!r.recording) return;
    mEntryRecorded[entryKey]++;

    const VURegs& vu = vuRegs[unit];
    VuInsnTrace::snapshot(vu, r.prev);
    r.memAsRunLeftIt.assign(vu.Mem, vu.Mem + getDataSize(unit));
    const uint64_t image = hashBytes(vu.Micro, getProgSize(unit));
    if (mImageFile && !mImagesWritten[image]) {
        mImagesWritten[image] = true;
        JsonObject img;
        img.addHexDigits("image", image, 16).addUint("unit", unit).addHexBytes("micro", vu.Micro, getProgSize(unit));
        const std::string text = img.take();
        std::fwrite(text.data(), 1, text.size(), mImageFile);
    }
    if (unit == 1) {
        r.vifTop = vif1Regs.top;
        r.vifItop = vif1Regs.itop;
        r.vifTops = vif1Regs.tops;
    }

    r.row = std::make_unique<JsonObject>();
    JsonObject& row = *r.row;
    row.addUint("unit", unit).addHexDigits("entry", pc, 4).addUint("ee", r.startEe).addHexDigits("image", image, 16);
    row.beginObject("in").beginArray("vf");
    for (int i = 0; i < 32; i++) row.pushHex128(r.prev.vf[i]);
    row.endArray().beginArray("vi");
    for (int i = 0; i < 32; i++) row.pushHexDigits(r.prev.vi[i], 8);
    row.endArray().addHex128("acc", r.prev.acc).endObject();
    VuInsnTrace::writePipe(row, "pipeIn", r.prev, unit);
    row.addHexBytes("mem", r.memAsRunLeftIt.data(), r.memAsRunLeftIt.size());
    if (unit == 1) {
        row.beginObject("vif")
            .addHexDigits("top", r.vifTop, 4)
            .addHexDigits("itop", r.vifItop, 4)
            .addHexDigits("tops", r.vifTops, 4)
            .endObject();
    }
    row.beginArray("steps");
}

void TimingTrace::endRun(uint32_t unit, const char* reason) {
    Run& r = mRuns[unit];
    if (!r.active) return;
    if (isTimelineOpen()) {
        JsonObject ev;
        ev.addString("ev", "vu_end")
            .addUint("ee", cpuRegs.cycle)
            .addUint("vu", vuRegs[unit].cycle)
            .addUint("unit", unit)
            .addHexDigits("pc", r.lastPc, 4)
            .addUint("steps", r.steps)
            .addString("end", reason);
        emit(ev);
    }
    if (r.recording) {
        bool keep = mEntryKept[(unit << 16) | r.entry] < kRunsPerEntry;
        for (size_t t = 0; t < kTagCount; t++) {
            if (!(r.tags & (1u << t))) continue;
            mTagSeen[t]++;
            keep |= mTagKept[t] < kRunsPerTag;
        }
        if (keep) {
            JsonObject& row = *r.row;
            row.endArray().addUint("stepCount", r.steps).addBool("truncated", r.truncated).addString("end", reason);
            VuInsnTrace::State end;
            VuInsnTrace::snapshot(vuRegs[unit], end);
            row.beginObject("out").beginArray("vf");
            for (int i = 0; i < 32; i++) row.pushHex128(end.vf[i]);
            row.endArray().beginArray("vi");
            for (int i = 0; i < 32; i++) row.pushHexDigits(end.vi[i], 8);
            row.endArray()
                .addHex128("acc", end.acc)
                .addHexDigits("memHash", hashBytes(vuRegs[unit].Mem, getDataSize(unit)), 16)
                .endObject();
            row.beginArray("tags");
            for (size_t t = 0; t < kTagCount; t++)
                if (r.tags & (1u << t)) row.pushString(kTagNames[t]);
            row.endArray();
            const std::string text = row.take();
            std::fwrite(text.data(), 1, text.size(), mRunFile);
            mRunsKept++;
            mEntryKept[(unit << 16) | r.entry]++;
            for (size_t t = 0; t < kTagCount; t++)
                if (r.tags & (1u << t)) mTagKept[t]++;
        }
    }
    r.active = false;
    r.recording = false;
    r.row.reset();
    r.memAsRunLeftIt.clear();
}

void TimingTrace::recordExternal(uint32_t unit) {
    Run& r = mRuns[unit];
    const VURegs& vu = vuRegs[unit];
    VuInsnTrace::State now;
    VuInsnTrace::snapshot(vu, now);
    for (int emulatorControlReg = REG_P + 1; emulatorControlReg < 32; emulatorControlReg++)
        now.vi[emulatorControlReg] = r.prev.vi[emulatorControlReg];
    std::vector<uint32_t> changed;
    for (uint32_t q = 0; q < r.memAsRunLeftIt.size(); q += 16)
        if (std::memcmp(vu.Mem + q, r.memAsRunLeftIt.data() + q, 16) != 0) changed.push_back(q);
    const bool regs = std::memcmp(now.vf, r.prev.vf, sizeof(now.vf)) != 0 ||
                      std::memcmp(now.vi, r.prev.vi, sizeof(now.vi)) != 0 ||
                      std::memcmp(now.acc, r.prev.acc, sizeof(now.acc)) != 0;
    const bool vif = unit == 1 && (vif1Regs.top != r.vifTop || vif1Regs.itop != r.vifItop || vif1Regs.tops != r.vifTops);
    if (changed.empty() && !regs && !vif) return;

    JsonObject& row = *r.row;
    row.beginObject().beginObject("ext").addUint("ee", cpuRegs.cycle).beginArray("m");
    for (uint32_t q : changed) {
        r.externallyWritten.set(q >> 4);
        row.beginObject().addHexDigits("q", q >> 4, 3).addHexBytes("v", vu.Mem + q, 16).endObject();
        std::memcpy(r.memAsRunLeftIt.data() + q, vu.Mem + q, 16);
    }
    row.endArray();
    if (regs) addRegDeltas(row, r.prev, now);
    if (vif) {
        r.vifTop = vif1Regs.top;
        r.vifItop = vif1Regs.itop;
        r.vifTops = vif1Regs.tops;
        row.beginObject("vif")
            .addHexDigits("top", r.vifTop, 4)
            .addHexDigits("itop", r.vifItop, 4)
            .addHexDigits("tops", r.vifTops, 4)
            .endObject();
    }
    row.endObject().endObject();
    r.prev = now;
    r.tags |= kTagExternal;
}

void TimingTrace::onVuBefore(uint32_t unit, uint32_t pc) {
    if (unit > 1) return;
    Run& r = mRuns[unit];
    r.stepCycle = vuRegs[unit].cycle;
    r.lastPc = pc;
    r.touchedQuadsBefore.clear();
}

void TimingTrace::onVuMem(uint32_t unit, uint32_t addr) {
    if (unit > 1) return;
    const bool vu1RegisterFile = unit == 0 && (addr & 0x4000);
    if (vu1RegisterFile) return;
    Run& r = mRuns[unit];
    if (!(r.active && r.recording) && !(unit == 1 && mKick.pending)) return;
    const uint32_t q = addr & (getDataSize(unit) - 16);
    for (const auto& t : r.touchedQuadsBefore)
        if (t.first == q) return;
    std::array<uint8_t, 16> before;
    std::memcpy(before.data(), vuRegs[unit].Mem + q, 16);
    r.touchedQuadsBefore.emplace_back(q, before);
}

void TimingTrace::onVuAfter(uint32_t unit, uint32_t pc) {
    if (unit > 1) return;
    Run& r = mRuns[unit];
    const VURegs& vu = vuRegs[unit];

    if (unit == 1 && mKick.pending) {
        for (const auto& [q, before] : r.touchedQuadsBefore)
            if (std::memcmp(vu.Mem + q, before.data(), 16) != 0) mKick.vuStoredSinceIssue.set(q >> 4);
        if (pc != mKick.pc && VU1.xgkickenable) r.tags |= kTagXgkickOverlap;
    }

    if (r.active) {
        r.steps++;
        if (r.recording && !r.truncated) {
            VuInsnTrace::State now;
            VuInsnTrace::snapshot(vu, now);
            const uint64_t cycles = vu.cycle - r.stepCycle;
            uint32_t upper, lower;
            std::memcpy(&lower, vu.Micro + pc * 8, 4);
            std::memcpy(&upper, vu.Micro + pc * 8 + 4, 4);
            const uint32_t cls = classifyLower(unit, upper, lower);
            const VuInsnTrace::State& was = r.prev;
            const bool readableMoved = now.vi[REG_Q] != was.vi[REG_Q] || now.vi[REG_P] != was.vi[REG_P] ||
                                       now.vi[REG_STATUS_FLAG] != was.vi[REG_STATUS_FLAG] ||
                                       now.vi[REG_MAC_FLAG] != was.vi[REG_MAC_FLAG] ||
                                       now.vi[REG_CLIP_FLAG] != was.vi[REG_CLIP_FLAG];
            if (cycles > 1 && readableMoved) r.tags |= kTagStallCommit;
            if (cls == kLowerDiv && was.fdiv.enable) r.tags |= kTagDivInFlight;
            if (cls == kLowerWaitq && (was.fmaccount || was.efu.enable || was.ialucount)) r.tags |= kTagWaitqBusy;

            JsonObject& row = *r.row;
            row.beginObject().addHexDigits("pc", pc, 4).addUint("c", cycles);
            addRegDeltas(row, was, now);
            bool readExternal = false;
            for (const auto& [q, before] : r.touchedQuadsBefore) {
                if (cls != kLowerLoad || !r.externallyWritten.test(q >> 4)) continue;
                if (!readExternal) row.beginArray("xr");
                readExternal = true;
                row.pushHexDigits(q >> 4, 3);
                mExternalReads++;
            }
            if (readExternal) {
                row.endArray();
                r.tags |= kTagExternalRead;
            }
            row.beginArray("m");
            for (const auto& [q, before] : r.touchedQuadsBefore) {
                if (std::memcmp(vu.Mem + q, r.memAsRunLeftIt.data() + q, 16) == 0) continue;
                row.beginObject().addHexDigits("q", q >> 4, 3).addHexBytes("v", vu.Mem + q, 16).endObject();
                std::memcpy(r.memAsRunLeftIt.data() + q, vu.Mem + q, 16);
            }
            row.endArray()
                .addInt("fdiv", cyclesUntilResult(now.fdiv.enable, now.fdiv.Cycle, now.cycle, now.fdiv.sCycle))
                .addInt("efu", cyclesUntilResult(now.efu.enable, now.efu.Cycle, now.cycle, now.efu.sCycle))
                .addUint("fmac", now.fmaccount)
                .addUint("ialu", now.ialucount)
                .endObject();
            r.prev = now;
            mStepsRecorded++;
            if (r.steps >= kMaxStepsPerRun) r.truncated = true;
        }
        if (!isRunning(unit)) endRun(unit, "ebit");
    }

    if (unit == 1 && mKick.pending && !VU1.xgkickenable) finishKick();
}

void TimingTrace::measureRewrites() {
    if (!mLastKick.sent.any()) return;
    for (uint32_t i = 0; i < 1024; i++)
        if (mLastKick.sent.test(i) && std::memcmp(VU1.Mem + i * 16, mLastKick.sentMem.data() + i * 16, 16) != 0)
            mRewrittenAfterSend++;
    mLastKick.sent.reset();
}

void TimingTrace::finishKick() {
    if (!mKick.pending) return;
    mKick.pending = false;
    mLastKick.sent = mKick.sent;
    mLastKick.sentMem = mKick.sentMem;
    if (!isTimelineOpen()) return;
    JsonObject ev;
    ev.addString("ev", "xgkick_done")
        .addUint("ee", cpuRegs.cycle)
        .addHexDigits("addr", mKick.addr >> 4, 3)
        .addHexDigits("pc", mKick.pc, 4)
        .addUint("issueVu", mKick.issueVu)
        .addUint("firstVu", mKick.firstVu)
        .addUint("lastVu", mKick.lastVu)
        .addUint("quads", mKick.quads)
        .addUint("flushedQuads", mKick.flushedQuads)
        .addUint("chunks", mKick.chunks)
        .addUint("hazards", mKick.hazards);
    emit(ev);
}

void TimingTrace::onEvent(Hooks::TimingEvent kind, uint32_t a, uint32_t b, uint32_t c) {
    using E = Hooks::TimingEvent;
    const bool open = isTimelineOpen();
    JsonObject ev;
    switch (kind) {
        case E::VSync:
            mFrames++;
            if (!open) return;
            ev.addString("ev", "vsync").addUint("ee", cpuRegs.cycle).addUint("frame", mFrames);
            break;
        case E::VuRunStart:
            if (a > 1) return;
            startRun(a, b);
            if (!open) return;
            ev.addString("ev", "vu_start").addUint("ee", cpuRegs.cycle).addUint("vu", vuRegs[a].cycle).addUint("unit", a).addHexDigits("pc", b, 4);
            break;
        case E::VuSlice:
            if (a > 1) return;
            if (mRuns[a].active && mRuns[a].recording && mRuns[a].steps) recordExternal(a);
            if (!open) return;
            ev.addString("ev", "vu_slice").addUint("ee", cpuRegs.cycle).addUint("vu", vuRegs[a].cycle).addUint("unit", a).addUint("budget", b);
            break;
        case E::XgkickIssue:
            finishKick();
            measureRewrites();
            mKicks++;
            mKick.pending = true;
            mKick.addr = a;
            mKick.pc = mRuns[1].lastPc;
            mKick.issueVu = VU1.cycle;
            mKick.chunks = mKick.quads = mKick.flushedQuads = mKick.hazards = 0;
            mKick.firstVu = mKick.lastVu = 0;
            mKick.memAtIssue.assign(VU1.Mem, VU1.Mem + VU1_MEMSIZE);
            mKick.sentMem.assign(VU1_MEMSIZE, 0);
            mKick.sent.reset();
            mKick.vuStoredSinceIssue.reset();
            if (!open) return;
            ev.addString("ev", "xgkick").addUint("ee", cpuRegs.cycle).addUint("vu", VU1.cycle).addHexDigits("addr", a >> 4, 3).addHexDigits("pc", mKick.pc, 4);
            break;
        case E::XgkickChunk: {
            if (!mKick.pending || b == 0) return;
            if (mKick.chunks++ == 0) mKick.firstVu = VU1.cycle;
            mKick.lastVu = VU1.cycle;
            mKick.quads += b / 16;
            if (c) mKick.flushedQuads += b / 16;
            for (uint32_t off = 0; off < b; off += 16) {
                const uint32_t q = (a + off) & 0x3ff0;
                mKick.sent.set(q >> 4);
                std::memcpy(mKick.sentMem.data() + q, VU1.Mem + q, 16);
                if (std::memcmp(VU1.Mem + q, mKick.memAtIssue.data() + q, 16) == 0) continue;
                mHazards++;
                mKick.hazards++;
                if (!mHazardFile || mHazards > kMaxHazards) continue;
                JsonObject hz;
                hz.addUint("ee", cpuRegs.cycle)
                    .addHexDigits("kickAddr", mKick.addr >> 4, 3)
                    .addHexDigits("kickPc", mKick.pc, 4)
                    .addUint("issueVu", mKick.issueVu)
                    .addUint("sentVu", VU1.cycle)
                    .addHexDigits("q", q >> 4, 3)
                    .addHexBytes("atKick", mKick.memAtIssue.data() + q, 16)
                    .addHexBytes("sent", VU1.Mem + q, 16)
                    .addString("writer", mKick.vuStoredSinceIssue.test(q >> 4) ? "vu" : "other")
                    .addBool("flush", c != 0);
                const std::string text = hz.take();
                std::fwrite(text.data(), 1, text.size(), mHazardFile);
            }
            return;
        }
        case E::GifTransfer:
            if (!open || (a == GIF_TRANS_XGKICK && c)) return;
            ev.addString("ev", "gif_offer").addUint("ee", cpuRegs.cycle).addUint("path", (a & 3) + 1)
                .addString("type", getTransferName(a)).addUint("bytes", b).addBool("taken", c != 0);
            break;
        case E::GsPacket:
            if (!open) return;
            ev.addString("ev", "gs_packet").addUint("ee", cpuRegs.cycle).addUint("path", a + 1).addUint("bytes", b);
            break;
        case E::Path3Mask:
            if (!open) return;
            ev.addString("ev", "path3_mask").addUint("ee", cpuRegs.cycle).addString("src", a ? "gif_mode" : "vif")
                .addUint("m3p", b).addUint("m3r", c);
            break;
        case E::GifDma:
            if (!open || (!b && !a)) return;
            ev.addString("ev", "gif_dma").addUint("ee", cpuRegs.cycle).addUint("qwc", a).addBool("str", b != 0)
                .addBool("path3Masked", c & 1).addBool("path3Ready", (c & 2) != 0);
            break;
        case E::DmaIrq:
            if (!open) return;
            ev.addString("ev", "dma_irq").addUint("ee", cpuRegs.cycle).addUint("chan", a);
            break;
        default:
            return;
    }
    emit(ev);
}

void TimingTrace::onVifBefore(uint32_t idx, const uint32_t* data, uint32_t pass) {
    if (idx > 1) return;
    VifCommand& v = mVif[idx];
    const bool stalledRetry = v.active && pass == 0 && data == v.lastData && v.lastConsumed == 0;
    if (v.active && pass == 0 && !stalledRetry && v.passes > 0) v.active = false;
    if (!v.active) {
        v.active = true;
        v.code = (idx ? vif1Regs : vif0Regs).code;
        v.passes = v.stalls = v.words = 0;
        v.startEe = cpuRegs.cycle;
    }
    v.passes++;
    v.lastData = data;
}

void TimingTrace::onVifAfter(uint32_t idx, const uint32_t* data, uint32_t consumed, bool done) {
    if (idx > 1) return;
    VifCommand& v = mVif[idx];
    if (!v.active) return;
    v.words += consumed;
    v.lastConsumed = consumed;
    if (consumed == 0) v.stalls++;
    if (!done) return;
    v.active = false;
    if (!isTimelineOpen()) return;
    const char* name = VifCmdTrace::getCommandName((v.code >> 24) & 0x7f);
    JsonObject ev;
    ev.addString("ev", "vif")
        .addUint("ee", cpuRegs.cycle)
        .addUint("start", v.startEe)
        .addUint("vif", idx)
        .addString("cmd", name ? name : "?")
        .addHexDigits("code", v.code, 8)
        .addUint("passes", v.passes)
        .addUint("stalls", v.stalls)
        .addUint("words", v.words);
    emit(ev);
}

void TimingTrace::onDmaKick(uint32_t chan, uint32_t eepc, uint32_t madr, uint32_t qwc) {
    if (!isTimelineOpen()) return;
    JsonObject ev;
    ev.addString("ev", "dma_kick")
        .addUint("ee", cpuRegs.cycle)
        .addUint("chan", chan)
        .addHexDigits("madr", madr, 8)
        .addUint("qwc", qwc)
        .addHexDigits("eepc", eepc, 8);
    emit(ev);
}

void TimingTrace::write() {
    if (!isEnabled()) return;
    for (uint32_t unit = 0; unit < 2; unit++) endRun(unit, "shutdown");
    finishKick();
    for (FILE* f : {mTimeline, mRunFile, mImageFile, mHazardFile})
        if (f) std::fclose(f);
    mTimeline = mRunFile = mImageFile = mHazardFile = nullptr;

    std::string tags;
    for (size_t t = 0; t < kTagCount; t++) {
        char buf[64];
        std::snprintf(buf, sizeof(buf), "%s%s %zu/%zu", t ? ", " : "", kTagNames[t], mTagKept[t], mTagSeen[t]);
        tags += buf;
    }
    std::printf("[timing] %s: %llu timeline events over %u frames; %zu of %zu VU runs kept (%llu steps "
                "recorded; tags kept/seen: %s); %llu XGKICKs, %llu quadwords changed before the GIF "
                "took them, %llu rewritten by the next kick; %llu reads of quadwords the VIF changed "
                "mid-run\n",
                getOutputDir().c_str(), static_cast<unsigned long long>(mTimelineEvents),
                std::min(mFrames, mFrameLimit), mRunsKept, mRunsSeen,
                static_cast<unsigned long long>(mStepsRecorded), tags.c_str(),
                static_cast<unsigned long long>(mKicks), static_cast<unsigned long long>(mHazards),
                static_cast<unsigned long long>(mRewrittenAfterSend),
                static_cast<unsigned long long>(mExternalReads));
}

void timingEventSink(Hooks::TimingEvent kind, uint32_t a, uint32_t b, uint32_t c) {
    Diagnostics::get().getTiming().onEvent(kind, a, b, c);
}

void timingVuBeforeSink(uint32_t unit, uint32_t pc) {
    Diagnostics::get().getTiming().onVuBefore(unit, pc);
}

void timingVuAfterSink(uint32_t unit, uint32_t pc) {
    Diagnostics::get().getTiming().onVuAfter(unit, pc);
}

void timingVuMemSink(uint32_t unit, uint32_t addr) {
    Diagnostics::get().getTiming().onVuMem(unit, addr);
}

void timingVifBeforeSink(uint32_t idx, const uint32_t* data, uint32_t pass) {
    Diagnostics::get().getTiming().onVifBefore(idx, data, pass);
}

void timingVifAfterSink(uint32_t idx, const uint32_t* data, uint32_t consumed, bool done) {
    Diagnostics::get().getTiming().onVifAfter(idx, data, consumed, done);
}

void timingDmaKickSink(uint32_t chan, uint32_t eepc, uint32_t madr, uint32_t qwc) {
    Diagnostics::get().getTiming().onDmaKick(chan, eepc, madr, qwc);
}

}  // namespace pcsx2hook

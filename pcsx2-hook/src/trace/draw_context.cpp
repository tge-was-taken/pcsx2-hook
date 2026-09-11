// SPDX-FileCopyrightText: 2002-2026 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#include "trace/draw_context.h"
#include "trace/json.h"
#include "trace/table.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <mutex>
#include <set>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include "DebugTools/Debug.h"
#include "config.h"
#include "diagnostics.h"
#include "trace/dump_dir.h"

namespace pcsx2hook {
size_t s_depth = 0;
size_t s_execTotalSteps = 0;

uint64_t hashWords(const uint32_t* words, uint32_t count) {
    uint64_t h = 0xCBF29CE484222325ull;
    for (uint32_t i = 0; i < count; i++) {
        for (int b = 0; b < 4; b++) {
            h ^= (words[i] >> (b * 8)) & 0xFFu;
            h *= 0x100000001B3ull;
        }
    }
    return h;
}

void DrawTrace::push(const DrawContext& ctx) {
    if (s_depth < kMaxDepth) {
        mStack[s_depth] = ctx;
    }
    s_depth++;
}
void DrawTrace::pop() {
    if (s_depth > 0) {
        s_depth--;
    }
}
const char* DrawTrace::getCurrentLabel() {
    return (s_depth > 0 && s_depth <= kMaxDepth) ? mStack[s_depth - 1].label : "";
}
bool DrawTrace::isVuTraceEnabled() {
    static const bool on = Config::get().getValue("PCSX2HOOK_VU_TRACE") != nullptr;
    return on;
}
void DrawTrace::onVu1Upload(uint32_t addr, const uint32_t* words, uint32_t count) {
    if (!words || count == 0) {
        return;
    }
    const std::lock_guard<std::mutex> lock(mMutex);
    const uint32_t start = (addr / 8) % kVu1Instrs;
    if (start != mLastUploadEnd) {
        mUploadStarts.insert(start);
    }
    mLastUploadEnd = (start + count / 2) % kVu1Instrs;
    for (uint32_t i = 0; i < count; i++) {
        mMicro[((addr / 4) + i) % kVu1Words] = words[i];
    }
}
uint64_t DrawTrace::resolveProgramAt(uint32_t pc) {
    if (pc >= kVu1Instrs) {
        return mRunning;
    }
    const std::lock_guard<std::mutex> lock(mMutex);
    constexpr uint32_t kEBit = 1u << 30;
    auto next = mUploadStarts.upper_bound(pc);
    const uint32_t limit = (next == mUploadStarts.end()) ? kVu1Instrs : *next;
    uint32_t last = pc;
    for (uint32_t i = pc; i < limit; i++) {
        last = i;
        if (mMicro[i * 2 + 1] & kEBit) {
            last = (i + 1 < limit) ? i + 1 : i;
            break;
        }
    }
    const uint32_t words = (last - pc + 1) * 2;
    const uint64_t hash = hashWords(&mMicro[pc * 2], words);
    Program& p = mPrograms[hash];
    if (p.code.empty()) {
        p.addr = pc * 8;
        p.words = words;
        p.code.assign(mMicro.begin() + pc * 2, mMicro.begin() + pc * 2 + words);
    }
    p.getEntries.insert(pc);
    if (const char* label = getCurrentLabel(); *label) {
        p.labels[label]++;
    }

    const uint64_t imageHash = hashWords(mMicro.data(), kVu1Words);
    MicroImage& img = mImages[imageHash];
    if (img.code.empty()) {
        img.code = mMicro;
    }
    img.getEntries.insert(pc);
    img.execs++;
    return hash;
}
void DrawTrace::setRunningProgramGs(uint64_t hash, StreamPos at) {
    mRunning = hash;
    const std::lock_guard<std::mutex> lock(mMutex);
    auto it = mPrograms.find(hash);
    if (it == mPrograms.end()) {
        return;
    }
    it->second.uploads++;
    if (it->second.at.size() < kMaxStreamPos) {
        it->second.at.push_back(at);
    }
}
uint64_t DrawTrace::getRunningProgram() {
    return mRunning;
}

void addCode(JsonObject& row, const std::vector<uint32_t>& code, uint32_t basePc, size_t last) {
    constexpr uint32_t kIBit = 1u << 31;
    const auto trim = [](const char* text) {
        while (text && *text == ' ') text++;
        return text ? text : "";
    };
    row.beginArray("code");
    for (size_t i = 0; i + 1 < last; i += 2) {
        const uint32_t pc = basePc + uint32_t(i / 2);
        const char* upper = disVU1MicroUF(code[i + 1], pc * 8);
        row.beginObject()
            .addHex("pc", pc, 4)
            .addHexDigits("upper", code[i + 1], 8)
            .addHexDigits("lower", code[i], 8)
            .addString("upperDis", trim(upper));
        if (code[i + 1] & kIBit) {
            float imm = 0.0f;
            std::memcpy(&imm, &code[i], sizeof(imm));
            row.addReal("immediate", double(imm));
        } else if (const char* lower = disVU1MicroLF(code[i], pc * 8)) {
            row.addString("lowerDis", trim(lower));
        }
        row.endObject();
    }
    row.endArray();
}

void DrawTrace::writeVuImages() {
    if (mImages.empty()) {
        return;
    }
    const std::string out = Diagnostics::get().getDumps().getPath("vu1_images.jsonl");
    FILE* f = std::fopen(out.c_str(), "w");
    if (!f) {
        return;
    }
    const auto emit = [f](const std::string& text) { std::fwrite(text.data(), 1, text.size(), f); };
    emit(JsonObject()
             .addString("type", "header")
             .addUint("images", mImages.size())
             .addUint("instructions", kVu1Instrs)
             .take());
    for (const auto& [hash, img] : mImages) {
        size_t last = img.code.size();
        while (last > 0 && img.code[last - 1] == 0) {
            last--;
        }
        JsonObject row;
        row.addString("type", "image")
            .addHexDigits("hash", hash, 16)
            .addUint("words", last)
            .addUint("instrs", last / 2)
            .addUint("execs", img.execs)
            .beginArray("entries");
        for (uint32_t e : img.getEntries) row.pushUint(e);
        row.endArray().beginArray("aliases");
        for (const auto& [phash, prog] : mPrograms) {
            for (uint32_t e : prog.getEntries) {
                if (img.getEntries.count(e)) {
                    row.pushHexDigits(phash, 16);
                    break;
                }
            }
        }
        row.endArray();
        addCode(row, img.code, 0, last);
        emit(row.take());
    }
    std::fclose(f);
    std::printf("[vu] wrote %s (%zu images)\n", out.c_str(), mImages.size());
}
void DrawTrace::writeVuTrace() {
    if (!isVuTraceEnabled() || mPrograms.empty()) {
        return;
    }
    const std::string out = Diagnostics::get().getDumps().getPath("vu1_programs.jsonl");
    FILE* f = std::fopen(out.c_str(), "w");
    if (!f) {
        return;
    }
    const auto emit = [f](const std::string& text) { std::fwrite(text.data(), 1, text.size(), f); };
    emit(JsonObject().addString("type", "header").addUint("programs", mPrograms.size()).take());

    std::map<uint32_t, std::vector<std::pair<uint32_t, uint64_t>>> byFrame;
    for (const auto& [hash, p] : mPrograms) {
        for (const StreamPos& sp : p.at) {
            byFrame[sp.frame].emplace_back(sp.batch, hash);
        }
    }
    for (auto& [frame, uploads] : byFrame) {
        std::sort(uploads.begin(), uploads.end());
        uploads.erase(std::unique(uploads.begin(), uploads.end()), uploads.end());
        JsonObject row;
        row.addString("type", "timeline").addUint("frame", frame).beginArray("batches");
        uint32_t at = 0xFFFFFFFFu;
        for (const auto& [batch, hash] : uploads) {
            if (batch != at) {
                if (at != 0xFFFFFFFFu) row.endArray().endObject();
                row.beginObject().addUint("batch", batch).beginArray("programs");
                at = batch;
            }
            row.pushHexDigits(hash, 16);
        }
        if (at != 0xFFFFFFFFu) row.endArray().endObject();
        row.endArray();
        emit(row.take());
    }

    for (const auto& [hash, p] : mPrograms) {
        JsonObject row;
        row.addString("type", "program")
            .addHexDigits("hash", hash, 16)
            .addHex("addr", p.addr, 4)
            .addUint("words", p.words)
            .addUint("instrs", p.words / 2)
            .addUint("uploads", p.uploads)
            .beginObject("under");
        for (const auto& [label, n] : p.labels) row.addUint(label.c_str(), n);
        row.endObject().beginArray("ranBefore");
        for (const StreamPos& sp : p.at) {
            row.beginObject().addUint("frame", sp.frame).addUint("batch", sp.batch).endObject();
        }
        row.endArray();
        addCode(row, p.code, p.addr / 8, p.code.size());
        emit(row.take());
    }
    std::fclose(f);
    std::printf("[vu] wrote %s (%zu programs)\n", out.c_str(), mPrograms.size());
    writeVuImages();
}
bool DrawTrace::isVuWatchEnabled() {
    static const bool on = Config::get().getValue("PCSX2HOOK_VU_WATCH") != nullptr;
    return on;
}
const std::vector<uint32_t>& DrawTrace::getVuWatchAddrs() {
    static const std::vector<uint32_t> addrs = [] {
        std::vector<uint32_t> result;
        const char* env = Config::get().getValue("PCSX2HOOK_VU_WATCH");
        if (!env) {
            return result;
        }
        const char* p = env;
        while (*p) {
            char* end = nullptr;
            const long v = std::strtol(p, &end, 0);
            if (end == p) {
                break;
            }
            result.push_back(static_cast<uint32_t>(v));
            p = (*end == ',') ? end + 1 : end;
        }
        return result;
    }();
    return addrs;
}
std::vector<std::array<uint8_t, 16>> DrawTrace::snapshotVuWatch(const uint8_t* vuMem,
                                                                uint32_t vuMemSize) {
    std::vector<std::array<uint8_t, 16>> out;
    if (!vuMem) {
        return out;
    }
    for (uint32_t addr : getVuWatchAddrs()) {
        std::array<uint8_t, 16> q{};
        if (static_cast<uint64_t>(addr) * 16 + 16 <= vuMemSize) {
            std::memcpy(q.data(), vuMem + addr * 16, 16);
        }
        out.push_back(q);
    }
    return out;
}
void DrawTrace::recordVuWatchGs(uint64_t hash, const std::vector<std::array<uint8_t, 16>>& snapshot,
                                StreamPos at) {
    const std::lock_guard<std::mutex> lock(mWatchMutex);
    if (mWatchSamples.size() >= kMaxWatchSamples) {
        mWatchOverflowed = true;
        return;
    }
    mWatchSamples.push_back(WatchSample{at, hash, snapshot});
}
void DrawTrace::writeVuWatchTrace() {
    if (!isVuWatchEnabled()) {
        return;
    }
    const std::vector<uint32_t>& addrs = getVuWatchAddrs();
    if (addrs.empty()) {
        std::printf("[vu] PCSX2HOOK_VU_WATCH set but names no addresses\n");
        return;
    }
    const std::string out = Diagnostics::get().getDumps().getPath("vu1_watch.jsonl");
    FILE* f = std::fopen(out.c_str(), "w");
    if (!f) {
        return;
    }
    std::vector<WatchSample> samples;
    bool overflowed;
    {
        const std::lock_guard<std::mutex> lock(mWatchMutex);
        samples = mWatchSamples;
        overflowed = mWatchOverflowed;
    }
    const auto emit = [f](const std::string& text) { std::fwrite(text.data(), 1, text.size(), f); };
    JsonObject head;
    head.addString("type", "watchHeader").addUint("samples", samples.size()).beginArray("watching");
    for (uint32_t a : addrs) head.pushUint(a);
    head.endArray();
    if (overflowed) head.addUint("droppedPast", kMaxWatchSamples);
    emit(head.take());

    for (const WatchSample& s : samples) {
        JsonObject row;
        row.addUint("frame", s.at.frame)
            .addUint("batch", s.at.batch)
            .addHexDigits("vu", s.programHash, 16)
            .beginArray("quads");
        for (size_t i = 0; i < s.quads.size() && i < addrs.size(); i++) {
            const std::array<uint8_t, 16>& q = s.quads[i];
            float fv[4];
            std::memcpy(fv, q.data(), sizeof(fv));
            row.beginObject().addUint("mem", addrs[i]).beginArray("u8");
            for (uint8_t b : q) row.pushUint(b);
            row.endArray().beginArray("f32");
            for (float v : fv) row.pushReal(double(v));
            row.endArray().endObject();
        }
        row.endArray();
        emit(row.take());
    }
    std::fclose(f);
    std::printf("[vu] wrote %s (%zu samples)\n", out.c_str(), samples.size());
}
bool DrawTrace::isVuJrTraceEnabled() {
    static const bool on = Config::get().getValue("PCSX2HOOK_VU_JR_TRACE") != nullptr;
    return on;
}
void DrawTrace::onVu1Jr(uint32_t pc, uint32_t reg, uint32_t target) {
    const std::lock_guard<std::mutex> lock(mJrMutex);
    mJrEdges.insert(JrEdge{pc, reg, target});
}
void DrawTrace::writeVuJrTrace() {
    if (!isVuJrTraceEnabled()) {
        return;
    }
    std::set<JrEdge> edges;
    {
        const std::lock_guard<std::mutex> lock(mJrMutex);
        edges = mJrEdges;
    }
    const std::string out = Diagnostics::get().getDumps().getPath("vu1_jr.jsonl");
    FILE* f = std::fopen(out.c_str(), "w");
    if (!f) {
        return;
    }
    JsonTable table(f, {"pc", "instr", "reg", "target", "targetInstr"});
    for (const JrEdge& e : edges) {
        table.addHex(e.pc, 4)
            .addHex(e.pc / 8, 4)
            .addUint(e.reg)
            .addHex(e.target, 4)
            .addHex(e.target / 8, 4)
            .endRow();
    }
    std::fclose(f);
    std::printf("[vu] wrote %s (%zu edges)\n", out.c_str(), edges.size());
}
bool DrawTrace::isVuExecTraceEnabled() {
    static const bool on = Config::get().getValue("PCSX2HOOK_VU_EXEC_TRACE") != nullptr;
    return on;
}
const std::string& DrawTrace::getVuExecTraceFilter() {
    static const std::string filter = [] {
        const char* env = Config::get().getValue("PCSX2HOOK_VU_EXEC_TRACE");
        std::string s = env ? env : "";
        for (char& c : s) {
            c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
        }
        return s;
    }();
    return filter;
}
void DrawTrace::startVuExecRun(uint64_t hash, uint32_t entryAddr, StreamPos at) {
    if (!isVuExecTraceEnabled()) {
        return;
    }
    char hex[17];
    std::snprintf(hex, sizeof(hex), "%016llX", static_cast<unsigned long long>(hash));
    const std::string& filter = getVuExecTraceFilter();
    const std::lock_guard<std::mutex> lock(mExecMutex);
    if (!filter.empty() && std::strncmp(hex, filter.c_str(), filter.size()) != 0) {
        mExecRuns.clear();
        return;
    }
    if (s_execTotalSteps >= kMaxExecSteps) {
        return;
    }
    mExecRuns.push_back(ExecRun{hash, entryAddr, at.frame, at.batch, {}});
}
void DrawTrace::onVu1Step(uint32_t addr, const uint32_t vf[32][4], const uint32_t vi[32],
                          const uint32_t acc[4], bool branchTaken, uint32_t branchTarget) {
    const std::lock_guard<std::mutex> lock(mExecMutex);
    if (mExecRuns.empty() || mExecOverflowed) {
        return;
    }
    if (s_execTotalSteps >= kMaxExecSteps) {
        mExecOverflowed = true;
        std::printf("[vu] PCSX2HOOK_VU_EXEC_TRACE hit %zu instructions, dropping the rest\n",
                    kMaxExecSteps);
        return;
    }
    ExecRow row;
    row.addr = addr;
    row.taken = branchTaken;
    row.target = branchTarget;
    if (mExecHaveLast) {
        for (int r = 0; r < 32; r++) {
            if (vf[r][0] != mExecLastVF[r][0] || vf[r][1] != mExecLastVF[r][1] ||
                vf[r][2] != mExecLastVF[r][2] || vf[r][3] != mExecLastVF[r][3]) {
                char name[8];
                std::snprintf(name, sizeof(name), "vf%02d", r);
                row.wrote.emplace_back(
                    name, std::vector<uint32_t>{vf[r][0], vf[r][1], vf[r][2], vf[r][3]});
            }
        }
        for (int r = 1; r <= 15; r++) {
            if (vi[r] != mExecLastVI[r]) {
                char name[8];
                std::snprintf(name, sizeof(name), "vi%02d", r);
                row.wrote.emplace_back(name, std::vector<uint32_t>{vi[r]});
            }
        }
        if (vi[21] != mExecLastVI[21]) {
            row.wrote.emplace_back("I", std::vector<uint32_t>{vi[21]});
        }
        if (vi[22] != mExecLastVI[22]) {
            row.wrote.emplace_back("Q", std::vector<uint32_t>{vi[22]});
        }
        if (vi[23] != mExecLastVI[23]) {
            row.wrote.emplace_back("P", std::vector<uint32_t>{vi[23]});
        }
        if (acc[0] != mExecLastAcc[0] || acc[1] != mExecLastAcc[1] || acc[2] != mExecLastAcc[2] ||
            acc[3] != mExecLastAcc[3]) {
            row.wrote.emplace_back("ACC", std::vector<uint32_t>{acc[0], acc[1], acc[2], acc[3]});
        }
    }
    std::memcpy(mExecLastVF, vf, sizeof(mExecLastVF));
    std::memcpy(mExecLastVI, vi, sizeof(uint32_t) * 32);
    std::memcpy(mExecLastAcc, acc, sizeof(mExecLastAcc));
    mExecHaveLast = true;
    mExecRuns.back().rows.push_back(std::move(row));
    s_execTotalSteps++;
}
void DrawTrace::writeVuExecTrace() {
    if (!isVuExecTraceEnabled()) {
        return;
    }
    std::vector<ExecRun> runs;
    bool overflowed;
    {
        const std::lock_guard<std::mutex> lock(mExecMutex);
        runs = mExecRuns;
        overflowed = mExecOverflowed;
    }
    const std::string out = Diagnostics::get().getDumps().getPath("vu1_exec.jsonl");
    FILE* f = std::fopen(out.c_str(), "w");
    if (!f) {
        return;
    }
    const auto emit = [f](const std::string& text) { std::fwrite(text.data(), 1, text.size(), f); };
    if (overflowed) {
        emit(JsonObject().addString("type", "overflow").addUint("keptSteps", kMaxExecSteps).take());
    }
    size_t totalRows = 0;
    for (const ExecRun& run : runs) {
        JsonObject out_;
        out_.addString("type", "run")
            .addUint("frame", run.frame)
            .addUint("batch", run.batch)
            .addHexDigits("vu", run.hash, 16)
            .addHex("entry", run.entry, 4)
            .beginArray("rows");
        for (const ExecRow& row : run.rows) {
            out_.beginObject().addHex("addr", row.addr, 4);
            if (row.taken) out_.addHex("target", row.target, 4).addBool("taken", true);
            if (!row.wrote.empty()) {
                out_.beginArray("wrote");
                for (const auto& [name, words] : row.wrote) {
                    out_.beginObject().addString("reg", name.c_str()).beginArray("value");
                    for (uint32_t w : words) out_.pushHexDigits(w, 8);
                    out_.endArray().endObject();
                }
                out_.endArray();
            }
            out_.endObject();
        }
        out_.endArray();
        emit(out_.take());
        totalRows += run.rows.size();
    }
    std::fclose(f);
    std::printf("[vu] wrote %s (%zu runs, %zu instructions)\n", out.c_str(), runs.size(),
                totalRows);
}

void vu1JrSink(uint32_t pc, uint32_t reg, uint32_t target) {
    Diagnostics::get().getDraws().onVu1Jr(pc, reg, target);
}

}  // namespace pcsx2hook

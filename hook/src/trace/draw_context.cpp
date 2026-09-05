// SPDX-FileCopyrightText: 2002-2026 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#include "pcsx2hook/trace/draw_context.h"

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

#include "DebugTools/Debug.h"  // disVU1MicroUF/LF: PCSX2's VU1 disassembler
#include "VUmicro.h"           // vuRegs[1].Micro: the resident VU1 microprogram image
#include "pcsx2hook/config.h"
#include "pcsx2hook/diagnostics.h"
#include "pcsx2hook/trace/dump_dir.h"

namespace pcsx2hook {
size_t s_depth = 0;
void DrawTrace::seedMicroFromVu() {
    if (mMicroSeeded) {
        return;
    }
    mMicroSeeded = true;
}

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

const char* getKindName(DrawKind k) {
    switch (k) {
        case DrawKind::Atomic:
            return "atomic";
        case DrawKind::Sector:
            return "sector";
        case DrawKind::PTank:
            return "ptank";
        case DrawKind::Im2D:
            return "im2d";
        case DrawKind::Im3D:
            return "im3d";
        case DrawKind::Rt2d:
            return "rt2d";
        default:
            return "none";
    }
}
void DrawTrace::push(const DrawContext& ctx) {
    if (s_depth < kMaxDepth) {
        mStack[s_depth] = ctx;
    }
    s_depth++;
}
void DrawTrace::pop() {
    if (s_depth == 0) {
        return;
    }
    s_depth--;
    if (s_depth < kMaxDepth) {
        mLastPopped = mStack[s_depth];
    }
}
DrawContext* DrawTrace::getCurrent() {
    return (s_depth > 0 && s_depth <= kMaxDepth) ? &mStack[s_depth - 1] : nullptr;
}
const DrawContext& DrawTrace::getLastPopped() {
    return mLastPopped;
}
bool DrawTrace::isVuTraceEnabled() {
    static const bool on = Config::get().getValue("PCSX2HOOK_VU_TRACE") != nullptr;
    return on;
}
void DrawTrace::onVu1Upload(uint32_t addr, const uint32_t* words, uint32_t count, StreamPos at) {
    (void)at;
    if (!words || count == 0) {
        return;
    }
    // addr is a byte offset, and the VIF wraps at the end of micro memory as PCSX2's own split
    // handling does. Chunks are merged rather than recorded: one MPG is as much of a program as
    // fit in that VIF packet, so a chunk is not a program and its length is not the length.
    const std::lock_guard<std::mutex> lock(mMutex);
    seedMicroFromVu();
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
    seedMicroFromVu();
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

void DrawTrace::writeVuImages() {
    if (mImages.empty()) {
        return;
    }
    const std::string out = Diagnostics::get().getDumps().getPath("vu1_images.txt");
    FILE* f = std::fopen(out.c_str(), "w");
    if (!f) {
        return;
    }
    std::fprintf(f, "%zu distinct VU1 micro-memory images (%u instructions each)\n\n",
                 mImages.size(), kVu1Instrs);
    for (const auto& [hash, img] : mImages) {
        std::string getEntries;
        for (uint32_t e : img.getEntries) {
            getEntries += (getEntries.empty() ? "" : " ");
            getEntries += "0x" + std::to_string(e);
        }
        std::string aliases;
        for (const auto& [phash, prog] : mPrograms) {
            for (uint32_t e : prog.getEntries) {
                if (img.getEntries.count(e)) {
                    aliases += (aliases.empty() ? "" : ",");
                    char buf[24];
                    std::snprintf(buf, sizeof(buf), "%016llX",
                                  static_cast<unsigned long long>(phash));
                    aliases += buf;
                    break;
                }
            }
        }
        size_t last = img.code.size();
        while (last > 0 && img.code[last - 1] == 0) {
            last--;
        }
        std::fprintf(f,
                     "program %016llX  addr=0x0000 words=%zu instrs=%zu uploads=%u  under image"
                     "  getEntries=%s aliases=%s\n",
                     static_cast<unsigned long long>(hash), last, last / 2, img.execs,
                     getEntries.c_str(), aliases.c_str());
        for (size_t i = 0; i + 1 < last; i += 2) {
            const uint32_t pc = static_cast<uint32_t>(i / 2);
            char upper[128] = {};
            if (const char* u = disVU1MicroUF(img.code[i + 1], pc * 8)) {
                std::snprintf(upper, sizeof(upper), "%s", u);
            }
            constexpr uint32_t kIBit = 1u << 31;
            char lower[128] = {};
            if (img.code[i + 1] & kIBit) {
                float imm = 0.0f;
                std::memcpy(&imm, &img.code[i], sizeof(imm));
                std::snprintf(lower, sizeof(lower), "[I] %g", double(imm));
            } else if (const char* l = disVU1MicroLF(img.code[i], pc * 8)) {
                std::snprintf(lower, sizeof(lower), "%s", l);
            }
            std::fprintf(f, "    %04X  %08X %08X   %-36s %s\n", pc, img.code[i + 1], img.code[i],
                         upper, lower);
        }
        std::fprintf(f, "\n");
    }
    std::fclose(f);
    std::printf("[vu] wrote %s (%zu images)\n", out.c_str(), mImages.size());
}
void DrawTrace::writeVuTrace() {
    if (!isVuTraceEnabled() || mPrograms.empty()) {
        return;
    }
    const std::string out = Diagnostics::get().getDumps().getPath("vu1_programs.txt");
    FILE* f = std::fopen(out.c_str(), "w");
    if (!f) {
        return;
    }
    std::fprintf(f, "%zu distinct VU1 microprograms\n\n", mPrograms.size());
    std::map<uint32_t, std::vector<std::pair<uint32_t, uint64_t>>> byFrame;
    for (const auto& [hash, p] : mPrograms) {
        for (const StreamPos& sp : p.at) {
            byFrame[sp.frame].emplace_back(sp.batch, hash);
        }
    }
    std::fprintf(f, "--- upload timeline (frame: batch -> program) ---\n");
    for (auto& [frame, uploads] : byFrame) {
        std::sort(uploads.begin(), uploads.end());
        uploads.erase(std::unique(uploads.begin(), uploads.end()), uploads.end());
        std::fprintf(f, "  f%u:", frame);
        uint32_t at = 0xFFFFFFFFu;
        for (const auto& [batch, hash] : uploads) {
            if (batch != at) {
                std::fprintf(f, "%s b%u:", at == 0xFFFFFFFFu ? "" : " |", batch);
                at = batch;
            }
            std::fprintf(f, " %08X", static_cast<uint32_t>(hash >> 32));
        }
        std::fprintf(f, "\n");
    }
    std::fprintf(f, "\n");
    for (const auto& [hash, p] : mPrograms) {
        std::string kinds;
        for (const auto& [k, n] : p.kinds) {
            kinds += (kinds.empty() ? "" : ", ");
            kinds += getKindName(static_cast<DrawKind>(k));
            kinds += ":" + std::to_string(n);
        }
        std::string where;
        for (const StreamPos& sp : p.at) {
            where += (where.empty() ? "" : " ");
            where += "f" + std::to_string(sp.frame) + "b" + std::to_string(sp.batch);
        }
        std::fprintf(f, "program %016llX  addr=0x%04X words=%u instrs=%u uploads=%u  under %s\n",
                     static_cast<unsigned long long>(hash), p.addr, p.words, p.words / 2, p.uploads,
                     kinds.c_str());
        std::fprintf(f, "  ran before: %s\n", where.c_str());
        for (size_t i = 0; i + 1 < p.code.size(); i += 2) {
            const uint32_t pc = static_cast<uint32_t>(p.addr / 8 + i / 2);
            char upper[128] = {};
            if (const char* u = disVU1MicroUF(p.code[i + 1], pc * 8)) {
                std::snprintf(upper, sizeof(upper), "%s", u);
            }
            constexpr uint32_t kIBit = 1u << 31;
            char lower[128] = {};
            if (p.code[i + 1] & kIBit) {
                float imm = 0.0f;
                std::memcpy(&imm, &p.code[i], sizeof(imm));
                std::snprintf(lower, sizeof(lower), "[I] %g", double(imm));
            } else if (const char* l = disVU1MicroLF(p.code[i], pc * 8)) {
                std::snprintf(lower, sizeof(lower), "%s", l);
            }
            std::fprintf(f, "    %04X  %08X %08X   %-36s %s\n", pc, p.code[i + 1], p.code[i], upper,
                         lower);
        }
        std::fprintf(f, "\n");
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
    const std::string out = Diagnostics::get().getDumps().getPath("vu1_watch.txt");
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
    std::fprintf(f, "%zu samples, watching quadwords:", samples.size());
    for (uint32_t a : addrs) {
        std::fprintf(f, " %u", a);
    }
    std::fprintf(f, "\n");
    if (overflowed) {
        std::fprintf(f, "dropped samples past %zu: raise kMaxWatchSamples if more are needed\n",
                     kMaxWatchSamples);
    }
    std::fprintf(f, "\n");
    for (const WatchSample& s : samples) {
        std::fprintf(f, "f%u b%u  vu%016llX\n", s.at.frame, s.at.batch,
                     static_cast<unsigned long long>(s.programHash));
        for (size_t i = 0; i < s.quads.size() && i < addrs.size(); i++) {
            const std::array<uint8_t, 16>& q = s.quads[i];
            float fv[4];
            std::memcpy(fv, q.data(), sizeof(fv));
            std::fprintf(
                f,
                "  mem[%u]  hex=%02X%02X%02X%02X %02X%02X%02X%02X %02X%02X%02X%02X %02X%02X%02X%02X"
                "  u8=[%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u]  f32=[%g,%g,%g,%g]\n",
                addrs[i], q[0], q[1], q[2], q[3], q[4], q[5], q[6], q[7], q[8], q[9], q[10], q[11],
                q[12], q[13], q[14], q[15], q[0], q[1], q[2], q[3], q[4], q[5], q[6], q[7], q[8],
                q[9], q[10], q[11], q[12], q[13], q[14], q[15], double(fv[0]), double(fv[1]),
                double(fv[2]), double(fv[3]));
        }
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
    const std::string out = Diagnostics::get().getDumps().getPath("vu1_jr.txt");
    FILE* f = std::fopen(out.c_str(), "w");
    if (!f) {
        return;
    }
    std::fprintf(f, "%zu distinct (pc, register) -> target edges\n", edges.size());
    for (const JrEdge& e : edges) {
        std::fprintf(f, "  pc=0x%04X (instr %04X)  vi%02u -> target=0x%04X (instr %04X)\n", e.pc,
                     e.pc / 8, e.reg, e.target, e.target / 8);
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
    const std::string out = Diagnostics::get().getDumps().getPath("vu1_exec.txt");
    FILE* f = std::fopen(out.c_str(), "w");
    if (!f) {
        return;
    }
    if (overflowed) {
        std::fprintf(f, "dropped steps past %zu: raise kMaxExecSteps if more are needed\n",
                     kMaxExecSteps);
    }
    size_t totalRows = 0;
    for (const ExecRun& run : runs) {
        std::fprintf(f, "run f%u b%u vu%016llX entry=%04X\n", run.frame, run.batch,
                     static_cast<unsigned long long>(run.hash), run.entry);
        for (const ExecRow& row : run.rows) {
            std::fprintf(f, "%04X", row.addr);
            if (row.taken) {
                std::fprintf(f, " target=%04X taken=1", row.target);
            }
            for (const auto& [name, words] : row.wrote) {
                std::fprintf(f, " %s=", name.c_str());
                for (size_t i = 0; i < words.size(); i++) {
                    std::fprintf(f, "%s%08X", i == 0 ? "" : ",", words[i]);
                }
            }
            std::fprintf(f, "\n");
        }
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

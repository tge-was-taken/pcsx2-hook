// SPDX-FileCopyrightText: 2002-2026 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#include "trace/exec_trace.h"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <string>
#include <unordered_map>
#include <vector>

#include "DebugTools/BiosDebugData.h"
#include "DebugTools/Debug.h"
#include "Memory.h"
#include "R5900.h"
#include "config.h"
#include "diagnostics.h"
#include "trace/dump_dir.h"
#include "pcsx2/Hooks.h"
#include "ps2/BiosTools.h"
#include "symbols.h"

namespace pcsx2hook {
// A block's counter address is baked into generated code, so the array must never move. One slot
// per distinct (startpc, endpc): a block recompiled with different bounds is a different extent
// and gets its own slot rather than polluting the first one's coverage.
// A kseg0 PC and its physical twin are the same instruction, so coverage counts them once.
uint32_t ExecTrace::getPhysAddr(uint32_t pc) {
    return pc & kSegMask;
}

bool ExecTrace::isInMainRam(uint32_t pc) {
    return getPhysAddr(pc) < kMainRamEnd;
}

// Addresses baked into generated code, so both arrays are fixed for the run.
std::string ExecTrace::getOutputDir() {
    const char* env = Config::get().getValue("PCSX2HOOK_EXEC_TRACE");
    if (!env || !*env || std::strcmp(env, "1") == 0) return Diagnostics::get().getDumps().getDir();
    return env;
}
bool ExecTrace::isEnabled() {
    static const bool on = Config::get().getValue("PCSX2HOOK_EXEC_TRACE") != nullptr;
    return on;
}
bool ExecTrace::isArgsEnabled() {
    static const bool on =
        ExecTrace::isEnabled() && Config::get().getValue("PCSX2HOOK_EXEC_TRACE_ARGS") != nullptr;
    return on;
}
bool ExecTrace::finish(uint32_t frameCount) {
    static const uint32_t limit = []() -> uint32_t {
        const char* env = Config::get().getValue("PCSX2HOOK_EXEC_TRACE_FRAMES");
        return env ? static_cast<uint32_t>(std::strtoul(env, nullptr, 10)) : 0;
    }();
    return ExecTrace::isEnabled() && limit != 0 && frameCount >= limit;
}

void ExecTrace::refreshThread() {
    if (CurrentBiosInformation.eeThreadListAddr == 0) return;
    const uint32_t base = CurrentBiosInformation.eeThreadListAddr & 0x3FFFFF;
    const auto* table = static_cast<const EEInternalThread*>(PSM(base));
    if (!table) return;
    if (table[mCurrentTid].status == static_cast<int>(ThreadStatus::THS_RUN)) {
        mThreads[mCurrentTid] = table[mCurrentTid];
        return;
    }
    for (uint32_t tid = 0; tid < 256; tid++) {
        if (table[tid].status != static_cast<int>(ThreadStatus::THS_RUN)) continue;
        mCurrentTid = tid;
        mThreads[tid] = table[tid];
        if (tid < kMaxThreads)
            mExecThreadBit = 1u << tid;
        else
            mThreadOverflow = true;
        return;
    }
}

void ExecTrace::recordSample(CallSite& site, const Hooks::Context& ctx, uint32_t result) {
    site.count++;
    if (site.samples.size() >= kMaxSamples) return;
    site.samples.push_back({ctx.a0, ctx.a1, ctx.a2, ctx.a3, ctx.ra, result});
}

Hooks::Result ExecTrace::onSyscallReturn(Hooks::Context& ctx) {
    const auto it = mSyscallReturnSite.find(ctx.pc);
    if (it == mSyscallReturnSite.end()) return Hooks::Result::Continue;
    CallSite& site = mSyscallSites[it->second];
    for (CallSample& sample : site.samples) {
        if (sample.result == kResultUnset) {
            sample.result = ctx.v0;
            break;
        }
    }
    return Hooks::Result::Continue;
}

Hooks::Result ExecTrace::onFunctionEntry(Hooks::Context& ctx) {
    recordSample(mFunctions[ctx.pc], ctx, kResultUnset);
    return Hooks::Result::Continue;
}
Hooks::ExecBlockSlots ExecTrace::registerBlock(uint32_t startpc, uint32_t endpc) {
    const uint64_t key = (static_cast<uint64_t>(startpc) << 32) | endpc;
    if (const auto it = mBlockIndex.find(key); it != mBlockIndex.end())
        return {&mBlockCounts[it->second], &mBlockThreads[it->second]};
    if (mBlocks.size() >= kMaxBlocks) {
        mBlocksOverflowed = true;
        return {nullptr, nullptr};
    }
    const uint32_t slot = static_cast<uint32_t>(mBlocks.size());
    const uint32_t wordOffset = static_cast<uint32_t>(mBlockWords.size());
    const bool ram = isInMainRam(startpc);
    if (ram) {
        for (uint32_t pc = startpc; pc < endpc; pc += 4) mBlockWords.push_back(memRead32(pc));
    }
    mBlocks.push_back({startpc, endpc, wordOffset, ram});
    mBlockIndex.emplace(key, slot);
    return {&mBlockCounts[slot], &mBlockThreads[slot]};
}
void ExecTrace::onSyscall(uint32_t num, Hooks::Context& ctx) {
    refreshThread();
    recordSample(mSyscalls[num], ctx, kResultUnset);
    recordSample(mSyscallSites[ctx.pc], ctx, kResultUnset);
    mSyscallSiteNum[ctx.pc] = num;
}
void ExecTrace::init() {
    if (!isEnabled()) return;
    Hooks::SetExecBlockRegister(&execBlockRegisterSink);
    Hooks::SetExecThreadBit(&mExecThreadBit);
    Hooks::SetSyscallSink(&execSyscallSink);
}
void ExecTrace::enableCalls() {
    if (!isEnabled()) return;
    getSymbols().load();

    if (const char* sitesFile = Config::get().getValue("PCSX2HOOK_EXEC_TRACE_SITES")) {
        if (FILE* f = std::fopen(sitesFile, "r")) {
            char line[512];
            std::fgets(line, sizeof(line), f);
            while (std::fgets(line, sizeof(line), f)) {
                const uint32_t site = static_cast<uint32_t>(std::strtoul(line, nullptr, 16));
                if (site == 0 || Hooks::IsHooked(site + 4)) continue;
                mSyscallReturnSite[site + 4] = site;
                Hooks::Register(site + 4, &execSyscallReturnHook, nullptr);
                mSyscallSitesEnabled++;
            }
            std::fclose(f);
        } else {
            std::fprintf(stderr, "[exec] no syscall site list at %s\n", sitesFile);
        }
    }

    if (isArgsEnabled()) {
        for (const std::pair<uint32_t, std::string>& sym : getSymbols().getEntries()) {
            if (Hooks::IsHooked(sym.first)) continue;
            Hooks::Register(sym.first, &execFunctionEntryHook, nullptr);
            mFunctionsEnabled++;
        }
    }
    if (mSyscallSitesEnabled || mFunctionsEnabled)
        std::fprintf(stderr, "[exec] enabled %zu syscall return sites, %zu function getEntries\n",
                     mSyscallSitesEnabled, mFunctionsEnabled);
}

void ExecTrace::writeSamples(FILE* f, const CallSite& site, bool withResult) {
    for (const CallSample& s : site.samples) {
        std::fprintf(f, "\t%08X,%08X,%08X,%08X", s.a0, s.a1, s.a2, s.a3);
        if (withResult && s.result != kResultUnset) std::fprintf(f, "->%08X", s.result);
    }
}
void ExecTrace::write() {
    if (!isEnabled()) return;
    const std::string dir = getOutputDir();
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);

    std::vector<uint32_t> executed;
    std::unordered_map<std::string, uint64_t> opcodes;
    uint64_t totalInstructions = 0;
    uint64_t coveredBlocks = 0;
    uint64_t biosBlocks = 0;
    if (FILE* f = std::fopen((dir + "/exec_blocks.tsv").c_str(), "w")) {
        std::fprintf(f, "startpc\tendpc\tinsns\tcount\tthreads\tregion\tsymbol\n");
        for (size_t i = 0; i < mBlocks.size(); i++) {
            const BlockExtent& b = mBlocks[i];
            const uint64_t count = mBlockCounts[i];
            const uint32_t insns = (b.endpc - b.startpc) / 4;
            if (count == 0) continue;
            coveredBlocks++;
            totalInstructions += count * insns;
            std::fprintf(f, "%08X\t%08X\t%u\t%llu\t%08X\t%s\t%s\n", b.startpc, b.endpc, insns,
                         static_cast<unsigned long long>(count), mBlockThreads[i],
                         b.ram ? "ram" : "bios",
                         b.ram ? getSymbols().resolve(getPhysAddr(b.startpc)).c_str() : "-");
            if (!b.ram) {
                biosBlocks++;
                continue;
            }
            for (uint32_t k = 0; k < insns; k++) {
                const uint32_t pc = getPhysAddr(b.startpc) + k * 4;
                executed.push_back(pc);
                std::string text;
                R5900::disR5900Fasm(text, mBlockWords[b.wordOffset + k], pc, false);
                opcodes[text.substr(0, text.find_first_of(" \t,"))] += count;
            }
        }
        std::fclose(f);
    }

    std::sort(executed.begin(), executed.end());
    executed.erase(std::unique(executed.begin(), executed.end()), executed.end());
    if (FILE* f = std::fopen((dir + "/exec_coverage.tsv").c_str(), "w")) {
        std::fprintf(f, "addr\n");
        for (uint32_t pc : executed) std::fprintf(f, "%08X\n", pc);
        std::fclose(f);
    }

    std::vector<std::pair<uint64_t, std::string>> ops;
    for (const auto& kv : opcodes) ops.emplace_back(kv.second, kv.first);
    std::sort(ops.rbegin(), ops.rend());
    if (FILE* f = std::fopen((dir + "/exec_opcodes.tsv").c_str(), "w")) {
        std::fprintf(f, "count\tmnemonic\n");
        for (const auto& op : ops)
            std::fprintf(f, "%llu\t%s\n", static_cast<unsigned long long>(op.first),
                         op.second.c_str());
        std::fclose(f);
    }

    if (FILE* f = std::fopen((dir + "/exec_syscalls.tsv").c_str(), "w")) {
        std::fprintf(f, "num\tname\tcount\tsamples(a0,a1,a2,a3)\n");
        std::vector<uint32_t> nums;
        for (const auto& kv : mSyscalls) nums.push_back(kv.first);
        std::sort(nums.begin(), nums.end());
        for (uint32_t num : nums) {
            const CallSite& site = mSyscalls[num];
            const char* name = R5900::bios[num & 0xFF];
            std::fprintf(f, "%u\t%s\t%llu", num, name ? name : "unnamed",
                         static_cast<unsigned long long>(site.count));
            writeSamples(f, site, false);
            std::fprintf(f, "\n");
        }
        std::fclose(f);
    }

    if (FILE* f = std::fopen((dir + "/exec_syscall_sites.tsv").c_str(), "w")) {
        std::fprintf(f, "site\tnum\tcount\tsymbol\tsamples(a0,a1,a2,a3->v0)\n");
        std::vector<uint32_t> sites;
        for (const auto& kv : mSyscallSites) sites.push_back(kv.first);
        std::sort(sites.begin(), sites.end());
        for (uint32_t site : sites) {
            const CallSite& s = mSyscallSites[site];
            std::fprintf(f, "%08X\t%u\t%llu\t%s", site, mSyscallSiteNum[site],
                         static_cast<unsigned long long>(s.count),
                         getSymbols().resolve(site).c_str());
            writeSamples(f, s, true);
            std::fprintf(f, "\n");
        }
        std::fclose(f);
    }

    if (FILE* f = std::fopen((dir + "/exec_threads.tsv").c_str(), "w")) {
        std::fprintf(f, "tid\tbit\tpriority\tentry\tstack\tstackSize\tsymbol\n");
        std::vector<uint32_t> tids;
        for (const auto& kv : mThreads) tids.push_back(kv.first);
        std::sort(tids.begin(), tids.end());
        for (uint32_t tid : tids) {
            const EEInternalThread& t = mThreads[tid];
            std::fprintf(f, "%u\t%08X\t%d\t%08X\t%08X\t%d\t%s\n", tid,
                         tid < kMaxThreads ? (1u << tid) : 0u, t.currentPriority, t.entry,
                         t.stackMem, t.stackSize, getSymbols().resolve(t.entry).c_str());
        }
        std::fclose(f);
    }

    if (isArgsEnabled()) {
        if (FILE* f = std::fopen((dir + "/exec_functions.tsv").c_str(), "w")) {
            std::fprintf(f, "entry\tcount\tsymbol\tsamples(a0,a1,a2,a3)\n");
            std::vector<uint32_t> addrs;
            for (const auto& kv : mFunctions) addrs.push_back(kv.first);
            std::sort(addrs.begin(), addrs.end());
            for (uint32_t addr : addrs) {
                const CallSite& s = mFunctions[addr];
                std::fprintf(f, "%08X\t%llu\t%s", addr, static_cast<unsigned long long>(s.count),
                             getSymbols().resolve(addr).c_str());
                writeSamples(f, s, false);
                std::fprintf(f, "\n");
            }
            std::fclose(f);
        }
    }

    std::printf(
        "[exec] %s: %llu blocks executed of %zu compiled (%llu in BIOS), %u guest "
        "instructions covered, %llu retired, %zu syscall numbers, %zu sites, %zu functions, "
        "%zu threads%s\n",
        dir.c_str(), static_cast<unsigned long long>(coveredBlocks), mBlocks.size(),
        static_cast<unsigned long long>(biosBlocks), static_cast<unsigned>(executed.size()),
        static_cast<unsigned long long>(totalInstructions), mSyscalls.size(), mSyscallSites.size(),
        mFunctions.size(), mThreads.size(),
        mBlocksOverflowed ? " [BLOCK TABLE OVERFLOWED: raise kMaxBlocks]"
        : mThreadOverflow ? " [thread id >= 32: mask incomplete]"
                          : "");
}

Hooks::Result execSyscallReturnHook(Hooks::Context& ctx) {
    return Diagnostics::get().getExec().onSyscallReturn(ctx);
}

Hooks::Result execFunctionEntryHook(Hooks::Context& ctx) {
    return Diagnostics::get().getExec().onFunctionEntry(ctx);
}

Hooks::ExecBlockSlots execBlockRegisterSink(uint32_t startpc, uint32_t endpc) {
    return Diagnostics::get().getExec().registerBlock(startpc, endpc);
}

void execSyscallSink(uint32_t num, Hooks::Context& ctx) {
    Diagnostics::get().getExec().onSyscall(num, ctx);
}

}  // namespace pcsx2hook

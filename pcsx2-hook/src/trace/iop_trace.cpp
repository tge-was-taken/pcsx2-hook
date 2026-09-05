// SPDX-FileCopyrightText: 2002-2026 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#include "trace/iop_trace.h"
#include "trace/json.h"
#include "trace/table.h"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "DebugTools/BiosDebugData.h"
#include "DebugTools/Debug.h"
#include "IopMem.h"
#include "R3000A.h"
#include "config.h"
#include "diagnostics.h"
#include "trace/dump_dir.h"
#include "pcsx2/Hooks.h"

namespace pcsx2hook {
const IopMod* IopTrace::getModule(uint32_t pc) {
    for (const IopMod& m : mModules) {
        if (pc >= m.text_addr && pc < m.text_addr + m.text_size) return &m;
    }
    return nullptr;
}

void IopTrace::refreshModules(uint32_t pc) {
    if (getModule(pc)) return;
    std::vector<IopMod> fresh = getIOPModules();
    if (!fresh.empty()) mModules = std::move(fresh);
}

std::string IopTrace::getOutputDir() {
    const char* env = Config::get().getValue("PCSX2HOOK_IOP_TRACE");
    if (!env || !*env || std::strcmp(env, "1") == 0) return Diagnostics::get().getDumps().getDir();
    return env;
}
bool IopTrace::isEnabled() {
    static const bool on = Config::get().getValue("PCSX2HOOK_IOP_TRACE") != nullptr;
    return on;
}
Hooks::ExecBlockSlots IopTrace::registerBlock(uint32_t startpc, uint32_t endpc) {
    const uint64_t key = (static_cast<uint64_t>(startpc) << 32) | endpc;
    if (const auto it = mBlockIndex.find(key); it != mBlockIndex.end())
        return {&mIopBlockCounts[it->second], &mIopBlockThreads[it->second]};
    if (mBlocks.size() >= kMaxIopBlocks) {
        mOverflowed = true;
        return {nullptr, nullptr};
    }
    refreshModules(startpc);
    const uint32_t slot = static_cast<uint32_t>(mBlocks.size());
    const uint32_t wordOffset = static_cast<uint32_t>(mBlockWords.size());
    for (uint32_t pc = startpc; pc < endpc; pc += 4) mBlockWords.push_back(iopMemRead32(pc));
    mBlocks.push_back({startpc, endpc, wordOffset});
    mBlockIndex.emplace(key, slot);
    return {&mIopBlockCounts[slot], &mIopBlockThreads[slot]};
}
void IopTrace::onImport(const char* libname, uint32_t index, const char* funcname) {
    if (!isEnabled() || !libname) return;
    std::string lib = libname;
    uint64_t key = index;
    for (char ch : lib) key = key * 131 + static_cast<unsigned char>(ch);
    Import& imp = mImports[key];
    if (imp.count == 0) {
        imp.libname = lib;
        imp.funcname = funcname ? funcname : "";
        imp.index = index;
    }
    imp.count++;
}

const std::string& IopTrace::getMnemonic(uint32_t pc, uint32_t code) {
    const auto it = mMnemonic.find(code);
    if (it != mMnemonic.end()) return it->second;
    std::string text = R3000A::disR3000AF(code, pc);
    const size_t colon = text.find(':');
    size_t begin = colon == std::string::npos ? 0 : text.find_first_not_of(" \t", colon + 1);
    if (begin == std::string::npos) begin = text.size();
    const size_t end = text.find_first_of(" \t,", begin);
    return mMnemonic.emplace(code, text.substr(begin, end - begin)).first->second;
}
void IopTrace::onInsnBefore(uint32_t pc, uint32_t code) {
    mInstructions++;
    mPending = false;
    const std::string& mnem = getMnemonic(pc, code);
    if (mCases[mnem].size() >= kMaxIopCases) return;
    mPendingCase = IopCase{};
    mPendingCase.pc = pc;
    mPendingCase.code = code;
    for (uint32_t i = 0; i < 32; i++) mPendingCase.gpr[i] = psxRegs.GPR.r[i];
    mPendingCase.hi = psxRegs.GPR.n.hi;
    mPendingCase.lo = psxRegs.GPR.n.lo;
    mPending = true;
}
void IopTrace::onInsnAfter(uint32_t pc, uint32_t code) {
    if (!mPending) return;
    mPending = false;
    const std::string& mnem = getMnemonic(pc, code);
    const uint32_t rs = (code >> 21) & 0x1F, rt = (code >> 16) & 0x1F;
    uint64_t key = mPendingCase.gpr[rs];
    key = key * 1000003 + mPendingCase.gpr[rt];
    key = key * 1000003 + code;
    key = key * 1000003 + mPendingCase.hi;
    key = key * 1000003 + mPendingCase.lo;
    if (!mSeen[mnem].insert(key).second) return;
    for (uint32_t i = 1; i < 32; i++) {
        if (psxRegs.GPR.r[i] != mPendingCase.gpr[i])
            mPendingCase.deltas.emplace_back(i, psxRegs.GPR.r[i]);
    }
    if (psxRegs.GPR.n.hi != mPendingCase.hi) mPendingCase.deltas.emplace_back(32, psxRegs.GPR.n.hi);
    if (psxRegs.GPR.n.lo != mPendingCase.lo) mPendingCase.deltas.emplace_back(33, psxRegs.GPR.n.lo);
    mCases[mnem].push_back(std::move(mPendingCase));
}
void IopTrace::init() {
    if (!isEnabled()) return;
    Hooks::SetIopBlockRegister(&iopBlockRegisterSink);
    Hooks::SetIrxImportSink(&iopImportSink);
    Hooks::SetIopInsnSink(&iopInsnBeforeSink, &iopInsnAfterSink);
}
const char* IopTrace::getModule(uint32_t pc, uint32_t* offset) {
    refreshModules(pc);
    const IopMod* m = getModule(pc);
    if (!m) return nullptr;
    if (offset) *offset = pc - m->text_addr;
    return m->name.c_str();
}
void IopTrace::write() {
    if (!isEnabled()) return;
    const std::string dir = getOutputDir();
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);

    std::vector<uint32_t> executed;
    std::unordered_map<std::string, uint64_t> opcodes;
    uint64_t retired = 0, covered = 0;
    if (FILE* f = std::fopen((dir + "/iop_blocks.jsonl").c_str(), "w")) {
        JsonTable t(f, {"startpc", "endpc", "insns", "count", "module", "offset"});
        for (size_t i = 0; i < mBlocks.size(); i++) {
            const IopBlock& b = mBlocks[i];
            const uint64_t n = mIopBlockCounts[i];
            if (n == 0) continue;
            const uint32_t insns = (b.endpc - b.startpc) / 4;
            covered++;
            retired += n * insns;
            const IopMod* mod = getModule(b.startpc);
            t.addHex(b.startpc, 8)
                .addHex(b.endpc, 8)
                .addUint(insns)
                .addUint(n)
                .addString(mod ? mod->name.c_str() : "-")
                .addHex(mod ? b.startpc - mod->text_addr : 0, 0)
                .endRow();
            for (uint32_t k = 0; k < insns; k++) {
                const uint32_t pc = b.startpc + k * 4;
                executed.push_back(pc);
                opcodes[getMnemonic(pc, mBlockWords[b.wordOffset + k])] += n;
            }
        }
        std::fclose(f);
    }

    std::sort(executed.begin(), executed.end());
    executed.erase(std::unique(executed.begin(), executed.end()), executed.end());
    if (FILE* f = std::fopen((dir + "/iop_coverage.jsonl").c_str(), "w")) {
        JsonTable t(f, {"addr"});
        for (uint32_t pc : executed) t.addHex(pc, 8).endRow();
        std::fclose(f);
    }

    std::vector<std::pair<uint64_t, std::string>> ops;
    for (const auto& kv : opcodes) ops.emplace_back(kv.second, kv.first);
    std::sort(ops.rbegin(), ops.rend());
    if (FILE* f = std::fopen((dir + "/iop_opcodes.jsonl").c_str(), "w")) {
        JsonTable t(f, {"count", "mnemonic"});
        for (const auto& op : ops)
            t.addUint(op.first).addString(op.second.c_str()).endRow();
        std::fclose(f);
    }

    std::vector<const Import*> imports;
    for (const auto& kv : mImports) imports.push_back(&kv.second);
    std::sort(imports.begin(), imports.end(), [](const Import* a, const Import* b) {
        return a->libname != b->libname ? a->libname < b->libname : a->index < b->index;
    });
    if (FILE* f = std::fopen((dir + "/iop_imports.jsonl").c_str(), "w")) {
        JsonTable t(f, {"library", "ordinal", "name", "calls"});
        for (const Import* imp : imports)
            t.addString(imp->libname.c_str())
                .addUint(imp->index)
                .addString(imp->funcname.empty() ? "?" : imp->funcname.c_str())
                .addUint(imp->count)
                .endRow();
        std::fclose(f);
    }

    if (FILE* f = std::fopen((dir + "/iop_modules.jsonl").c_str(), "w")) {
        JsonTable t(f, {"name", "version", "text", "textSize", "entry", "gp", "data", "bss"});
        for (const IopMod& m : mModules)
            t.addString(m.name.c_str())
                .addUint(m.version)
                .addHex(m.text_addr, 8)
                .addHex(m.text_size, 0)
                .addHex(m.entry, 8)
                .addHex(m.gp, 8)
                .addHex(m.data_size, 0)
                .addHex(m.bss_size, 0)
                .endRow();
        std::fclose(f);
    }

    size_t vectors = 0;
    if (FILE* f = std::fopen((dir + "/iop_vectors.jsonl").c_str(), "w")) {
        std::vector<std::string> forms;
        for (const auto& kv : mCases)
            if (!kv.second.empty()) forms.push_back(kv.first);
        std::sort(forms.begin(), forms.end());
        for (const std::string& mnem : forms) {
            for (const IopCase& c : mCases[mnem]) {
                const uint32_t rs = (c.code >> 21) & 0x1F, rt = (c.code >> 16) & 0x1F;
                const IopMod* mod = getModule(c.pc);
                JsonObject row;
                row.addString("mnemonic", mnem.c_str())
                    .addHexDigits("pc", c.pc, 8)
                    .addHexDigits("code", c.code, 8)
                    .addUint("rs", rs)
                    .addUint("rt", rt)
                    .addHexDigits("rsVal", c.gpr[rs], 8)
                    .addHexDigits("rtVal", c.gpr[rt], 8)
                    .addString("module", mod ? mod->name.c_str() : "-")
                    .beginObject("in")
                    .addHexDigits("hi", c.hi, 8)
                    .addHexDigits("lo", c.lo, 8)
                    .endObject()
                    .beginArray("deltas");
                for (const auto& [reg, after] : c.deltas) {
                    row.beginObject()
                        .addString("file", reg == 32 ? "hi" : reg == 33 ? "lo" : "gpr")
                        .addUint("n", reg)
                        .addHexDigits("after", after, 8)
                        .endObject();
                }
                row.endArray();
                const std::string text = row.take();
                std::fwrite(text.data(), 1, text.size(), f);
                vectors++;
            }
        }
        std::fclose(f);
    }

    std::printf(
        "[iop] %s: %llu blocks of %zu compiled, %u instructions covered, %llu retired, "
        "%zu imports, %zu modules, %zu forms, %zu vectors%s\n",
        dir.c_str(), static_cast<unsigned long long>(covered), mBlocks.size(),
        static_cast<unsigned>(executed.size()), static_cast<unsigned long long>(retired),
        mImports.size(), mModules.size(), mCases.size(), vectors,
        mOverflowed ? " [BLOCK TABLE OVERFLOWED]" : "");
}

Hooks::ExecBlockSlots iopBlockRegisterSink(uint32_t startpc, uint32_t endpc) {
    return Diagnostics::get().getIop().registerBlock(startpc, endpc);
}

void iopInsnBeforeSink(uint32_t pc, uint32_t code) {
    Diagnostics::get().getIop().onInsnBefore(pc, code);
}

void iopInsnAfterSink(uint32_t pc, uint32_t code) {
    Diagnostics::get().getIop().onInsnAfter(pc, code);
}

void iopImportSink(const char* libname, uint32_t index, const char* funcname) {
    Diagnostics::get().getIop().onImport(libname, index, funcname);
}

}  // namespace pcsx2hook

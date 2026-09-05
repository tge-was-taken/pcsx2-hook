// SPDX-FileCopyrightText: 2002-2026 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#pragma once

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "R5900.h"
#include "VU.h"
#include "VUmicro.h"

namespace pcsx2hook {

class InsnTrace {
public:
    static constexpr size_t kMaxCasesPerForm = 64;
    static constexpr uint32_t kMemWindow = 32;
    static constexpr uint32_t kMemAlign = 16;
    static constexpr uint32_t kTlbBytes = sizeof(tlbs) * 48;
    static constexpr uint32_t kMaxDepth = 4;
    static constexpr size_t kMaxSynthPerForm = 512;

    struct Reg128 {
        uint64_t lo, hi;
        bool operator==(const Reg128& o) const { return lo == o.lo && hi == o.hi; }
    };

    struct RegDelta {
        const char* file;
        uint32_t index;
        Reg128 before, after;
    };

    struct Snapshot {
        Reg128 gpr[32];
        uint32_t fpr[32];
        Reg128 hi, lo;
        uint32_t sa, fcr31, pc;
        uint32_t cop0[32];
        uint32_t facc, faccFlag;
        bool hasVuMem, hasTlb;
        uint8_t vuMem[VU0_MEMSIZE];
        uint8_t vu1Regs[0x400];
        uint8_t tlbRaw[kTlbBytes];
        Reg128 vf[32], acc;
        uint32_t vi[32], q, p;
    };

    struct MemAccess {
        uint32_t addr, size;
        uint64_t value;
        bool isRead;
    };

    struct Case {
        uint32_t pc, code;
        Reg128 rsVal, rtVal;
        uint32_t fsVal, ftVal;
        uint32_t fs, ft;
        std::vector<RegDelta> deltas;
        uint32_t pcBefore, pcAfter, nested;
        Reg128 hiVal, loVal, accVal, vfsVal, vftVal, vfdVal;
        uint32_t saVal, fcr31Val, faccVal, faccFlagVal, cop0StatusVal, qVal, pVal;
        uint32_t cop0In[32];
        uint32_t visVal, vitVal, vstatus, vmac, vclip;
        bool hasMem, memRam;
        uint32_t memAddr, memWindow;
        const char* memRegion;
        uint8_t memBefore[kMemWindow], memAfter[kMemWindow];
        std::vector<MemAccess> accesses;
    };

    struct Frame {
        Snapshot before;
        bool pending;
        bool hasMem;
        uint32_t memAddr, memWindow;
        const char* memRegion;
        uint8_t memBefore[kMemWindow];
        uint32_t nested;
        std::vector<MemAccess> accesses;
        Snapshot afterOwn;
        bool hasAfterOwn;
        const std::string* mnem;
        uint32_t code;
    };

    bool isEnabled();
    void init();
    void onBefore(uint32_t pc, uint32_t code);
    void onAfter(uint32_t pc, uint32_t code);
    void onMem(uint32_t addr, uint64_t value, uint32_t size, bool isRead);
    bool isSynthEnabled();
    bool runSynth();
    void write();

private:
    std::string getOutputDir();
    Reg128 getGpr(uint32_t n);
    void snapshotWide(Snapshot& s, uint32_t code);
    void snapshot(Snapshot& s);
    const char* getAddressRegion(uint32_t raw);
    bool getMemoryOperand(uint32_t code, uint32_t& addr);
    void readMem(uint32_t addr, uint8_t* out);
    const std::string& getMnemonic(uint32_t pc, uint32_t code);
    void runOne(uint32_t pc, uint32_t code);
    bool isSynthSafe(uint32_t code);
    static std::string hexWindow(const uint8_t* b);
    void writeCase(FILE* f, const std::string& mnem, const Case& c, bool synthetic);

    bool mEnabled = false;
    Frame mFrames[kMaxDepth];
    uint32_t mDepth = 0;
    std::unordered_map<uint32_t, std::string> mMnemonic;
    std::unordered_map<std::string, std::vector<Case>> mCases;
    std::unordered_map<std::string, std::unordered_set<uint64_t>> mSeen;
    uint64_t mInstructions = 0;
    bool mInSynth = false;
    std::unordered_map<std::string, std::vector<Case>> mSynthCases;
    std::unordered_map<std::string, std::unordered_set<uint64_t>> mSynthSeen;
    size_t mSynthRuns = 0;
};

void insnBeforeSink(uint32_t pc, uint32_t code);
void insnAfterSink(uint32_t pc, uint32_t code);
void insnMemSink(uint32_t addr, uint64_t value, uint32_t size, bool isRead);

}  // namespace pcsx2hook

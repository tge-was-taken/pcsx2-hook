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

#include "VU.h"

namespace pcsx2hook {

class JsonObject;

class VuInsnTrace {
public:
    static constexpr size_t kMaxCasesPerForm = 64;
    static constexpr size_t kMaxMemPerCase = 8;

    struct State {
        uint32_t vf[32][4];
        uint32_t vi[32];
        uint32_t acc[4];
        uint32_t q, p;
        uint32_t statusflag, macflag, clipflag;
        fmacPipe fmac[4];
        uint32_t fmacreadpos, fmaccount;
        fdivPipe fdiv;
        efuPipe efu;
        ialuPipe ialu[4];
        uint32_t ialureadpos, ialucount;
        uint32_t viBackupCycles, viOldValue, viRegNumber;
        uint32_t branch, branchpc, delaybranchpc, takedelaybranch, ebit;
        uint64_t cycle;
    };

    struct MemQuad {
        uint32_t addr;
        const uint8_t* host;
        uint8_t before[16], after[16];
    };

    struct Case {
        uint32_t pc, upper, lower;
        uint32_t upperForm, lowerForm;
        State before, after;
        std::vector<MemQuad> mem;
    };

    static void snapshot(const VURegs& vu, State& s);
    static void writePipe(JsonObject& row, const char* key, const State& s, uint32_t unit);

    bool isEnabled();
    void init();
    void onBefore(uint32_t unit, uint32_t pc);
    void onAfter(uint32_t unit, uint32_t pc);
    void onMem(uint32_t unit, uint32_t addr);
    void write();

private:
    struct Unit {
        bool pending = false;
        Case current;
        std::vector<Case> cases;
        std::unordered_set<uint64_t> seen;
        std::unordered_map<uint32_t, uint32_t> upperForms, lowerForms;
        std::vector<std::string> formNames;
        std::vector<bool> formIsUpper;
        std::vector<size_t> formCases;
        uint64_t steps = 0;
    };

    std::string getOutputDir();
    uint32_t getUpperForm(uint32_t unit, uint32_t word);
    uint32_t getLowerForm(uint32_t unit, uint32_t upper, uint32_t lower);
    static uint32_t addForm(Unit& u, const std::string& name, bool upper);
    static uint64_t getOperandKey(uint32_t unit, uint32_t upper, uint32_t lower);
    void writeCase(FILE* f, uint32_t unit, const Case& c);
    void writeUnit(const std::string& dir, uint32_t unit);

    Unit mUnits[2];
};

std::string vuMnemonic(const char* disassembly);

void vuInsnBeforeSink(uint32_t unit, uint32_t pc);
void vuInsnAfterSink(uint32_t unit, uint32_t pc);
void vuMemSink(uint32_t unit, uint32_t addr);

}  // namespace pcsx2hook

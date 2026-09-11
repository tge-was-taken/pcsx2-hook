// SPDX-FileCopyrightText: 2002-2026 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#pragma once

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <map>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace pcsx2hook {

class VifCmdTrace {
public:
    static constexpr size_t kMaxCasesPerForm = 64;
    static constexpr size_t kMaxPayloadWords = 1 + 256 * 4;

    struct Regs {
        uint32_t stat, err, mark, cl, wl, mode, num, mask, code;
        uint32_t itops, base, ofst, tops, itop, top, mskpath3;
        uint32_t row[4], col[4];
        uint32_t maskRow[4], maskCol[4];
    };

    struct Quad {
        uint32_t addr;
        uint8_t before[16], after[16];
        bool inWindow;
    };

    struct Case {
        uint32_t idx, code, passes, startAligned;
        uint32_t windowAddr, windowQuads;
        std::string form;
        Regs before, after;
        std::vector<uint32_t> payload;
        bool payloadTruncated, hasTail;
        uint8_t tail[16];
        std::map<uint32_t, Quad> data, micro;
    };

    static const char* getCommandName(uint32_t cmd);

    bool isEnabled();
    void init();
    void onBefore(uint32_t idx, const uint32_t* data, uint32_t pass);
    void onAfter(uint32_t idx, const uint32_t* data, uint32_t consumed, bool done);
    void write();

private:
    struct Pending {
        bool active = false, skip = false, keyChecked = false, diffing = false, diffMicro = false;
        const uint32_t* lastData = nullptr;
        uint32_t lastConsumed = 0;
        Case c;
        std::vector<uint8_t> memBefore;
    };

    std::string getOutputDir();
    static void snapshotRegs(uint32_t idx, Regs& r);
    static std::string getFormName(uint32_t idx, uint32_t cmd, uint32_t code, const Regs& r);
    static uint64_t getStateKey(const Case& c);
    static void getWindow(uint32_t idx, uint32_t cmd, Case& c);
    void startCommand(uint32_t idx, Pending& p);
    void writeCase(FILE* f, const Case& c);

    Pending mPending[2];
    std::vector<Case> mCases;
    std::unordered_map<std::string, size_t> mFormCases;
    std::unordered_set<uint64_t> mSeen;
    uint64_t mCommands = 0, mAbandoned = 0;
};

void vifCmdBeforeSink(uint32_t idx, const uint32_t* data, uint32_t pass);
void vifCmdAfterSink(uint32_t idx, const uint32_t* data, uint32_t consumed, bool done);

}  // namespace pcsx2hook

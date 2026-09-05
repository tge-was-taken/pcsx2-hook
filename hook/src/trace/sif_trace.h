// SPDX-FileCopyrightText: 2002-2026 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#pragma once

#include <cstdint>
#include <cstdio>
#include <mutex>
#include <string>
#include <vector>

namespace pcsx2hook {

class SifTrace {
public:
    bool isEnabled();
    void init();
    void onKick(uint32_t channel);
    void onTransfer(uint32_t channel, bool toEE, uint32_t madr, uint32_t qwc, const uint32_t* words,
                    uint32_t count);
    void write();

private:
    std::string resolveEE(uint32_t pc);

    std::vector<uint32_t> mChain[2];
    FILE* mFile = nullptr;
    uint64_t mTotal = 0, mWords = 0, mClipped = 0;
    std::mutex mMutex;
};

void sifKickSink(uint32_t channel);
void sifTransferSink(uint32_t channel, bool toEE, uint32_t madr, uint32_t qwc,
                     const uint32_t* words, uint32_t count);

}  // namespace pcsx2hook

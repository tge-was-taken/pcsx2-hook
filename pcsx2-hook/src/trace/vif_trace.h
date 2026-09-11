// SPDX-FileCopyrightText: 2002-2026 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#pragma once

#include <cstdint>
#include <mutex>
#include <vector>

namespace pcsx2hook {

class VifTrace {
public:
    bool isEnabled() const;
    void onTag(uint32_t tadr, uint32_t id, uint32_t madr, uint32_t qwc);
    void onCode(uint32_t idx, uint32_t codeWord);
    void write();

private:
    struct Record {
        bool isTag;
        uint32_t a, b, c, d;
        uint32_t raw;
    };

    std::vector<Record> mRecords;
    bool mOverflowed = false;
    std::mutex mMutex;
};

void vifTagSink(uint32_t tadr, uint32_t id, uint32_t madr, uint32_t qwc);
void vifCodeSink(uint32_t idx, uint32_t codeWord);

}  // namespace pcsx2hook

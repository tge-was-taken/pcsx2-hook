// SPDX-FileCopyrightText: 2002-2026 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#include "vif_trace.h"

#include <cstdio>
#include <cstdlib>
#include <mutex>
#include <string>
#include <vector>

#include "config.h"
#include "diagnostics.h"
#include "dump_dir.h"

namespace pcsx2hook {
namespace {
constexpr size_t kMaxVifRecords = 500000;
}  // namespace

bool VifTrace::isEnabled() const {
    static const bool on = Config::get().getValue("PCSX2HOOK_VIF_TRACE") != nullptr;
    return on;
}

void VifTrace::onTag(uint32_t tadr, uint32_t id, uint32_t madr, uint32_t qwc) {
    if (!isEnabled()) {
        return;
    }
    const std::lock_guard<std::mutex> lock(mMutex);
    if (mRecords.size() >= kMaxVifRecords) {
        mOverflowed = true;
        return;
    }
    mRecords.push_back(Record{true, tadr, id, madr, qwc, 0});
}

void VifTrace::onCode(uint32_t idx, uint32_t codeWord) {
    if (!isEnabled() || idx != 1) {
        return;
    }
    const std::lock_guard<std::mutex> lock(mMutex);
    if (mRecords.size() >= kMaxVifRecords) {
        mOverflowed = true;
        return;
    }
    const uint32_t cmd = (codeWord >> 24) & 0x7F;
    const uint32_t num = (codeWord >> 16) & 0xFF;
    const uint32_t imm = codeWord & 0xFFFF;
    mRecords.push_back(Record{false, cmd, num, imm, 0, codeWord});
}

void VifTrace::write() {
    if (!isEnabled()) {
        return;
    }
    std::vector<Record> records;
    bool overflowed;
    {
        const std::lock_guard<std::mutex> lock(mMutex);
        records = mRecords;
        overflowed = mOverflowed;
    }
    const std::string out = Diagnostics::get().getDumps().getPath("vif_trace.txt");
    FILE* f = std::fopen(out.c_str(), "w");
    if (!f) {
        return;
    }
    if (overflowed) {
        std::fprintf(f, "dropped records past %zu: raise kMaxVifRecords if more are needed\n",
                     kMaxVifRecords);
    }
    for (const Record& r : records) {
        if (r.isTag) {
            std::fprintf(f, "tag tadr=0x%X id=%u madr=0x%X qwc=%u\n", r.a, r.b, r.c, r.d);
        } else {
            std::fprintf(f, "code cmd=0x%02X num=%u imm=0x%X raw=0x%08X\n", r.a, r.b, r.c, r.raw);
        }
    }
    std::fclose(f);
    std::printf("[vif] wrote %s (%zu records)\n", out.c_str(), records.size());
}
void vifTagSink(uint32_t tadr, uint32_t id, uint32_t madr, uint32_t qwc) {
    Diagnostics::get().getVif().onTag(tadr, id, madr, qwc);
}

void vifCodeSink(uint32_t idx, uint32_t codeWord) {
    Diagnostics::get().getVif().onCode(idx, codeWord);
}

}  // namespace pcsx2hook

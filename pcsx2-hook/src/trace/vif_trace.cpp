// SPDX-FileCopyrightText: 2002-2026 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#include "trace/json.h"
#include "trace/vif_trace.h"

#include <cstdio>
#include <cstdlib>
#include <mutex>
#include <string>
#include <vector>

#include "config.h"
#include "diagnostics.h"
#include "trace/dump_dir.h"

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
    const std::string out = Diagnostics::get().getDumps().getPath("vif_trace.jsonl");
    FILE* f = std::fopen(out.c_str(), "w");
    if (!f) {
        return;
    }
    const auto emit = [f](const std::string& text) { std::fwrite(text.data(), 1, text.size(), f); };
    if (overflowed) {
        emit(JsonObject()
                 .addString("type", "overflow")
                 .addUint("kept", kMaxVifRecords)
                 .take());
    }
    for (const Record& r : records) {
        if (r.isTag) {
            emit(JsonObject()
                     .addString("type", "tag")
                     .addHexDigits("tadr", r.a, 8)
                     .addUint("id", r.b)
                     .addHexDigits("madr", r.c, 8)
                     .addUint("qwc", r.d)
                     .take());
        } else {
            emit(JsonObject()
                     .addString("type", "code")
                     .addHexDigits("cmd", r.a, 2)
                     .addUint("num", r.b)
                     .addHexDigits("imm", r.c, 4)
                     .addHexDigits("raw", r.raw, 8)
                     .take());
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

// SPDX-FileCopyrightText: 2002-2026 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#pragma once

#include <cstdint>
#include <cstdio>
#include <initializer_list>
#include <memory>
#include <string>

#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"

namespace pcsx2hook {

class JsonTable {
public:
    JsonTable(std::FILE* file, std::initializer_list<const char*> columns)
        : mFile(file), mColumns(columns.size()) {
        rapidjson::StringBuffer buf;
        rapidjson::Writer<rapidjson::StringBuffer> w(buf);
        w.StartArray();
        for (const char* c : columns) w.String(c);
        w.EndArray();
        write(buf.GetString(), buf.GetSize());
    }

    JsonTable& addUint(uint64_t value) {
        begin();
        mWriter->Uint64(value);
        return *this;
    }

    JsonTable& addInt(int64_t value) {
        begin();
        mWriter->Int64(value);
        return *this;
    }

    JsonTable& addBool(bool value) {
        begin();
        mWriter->Bool(value);
        return *this;
    }

    JsonTable& addReal(double value, int decimals = 6) {
        begin();
        mWriter->SetMaxDecimalPlaces(decimals);
        mWriter->Double(value);
        mWriter->SetMaxDecimalPlaces(324);
        return *this;
    }

    JsonTable& addString(const char* value) {
        begin();
        mWriter->String(value ? value : "");
        return *this;
    }

    JsonTable& addHex(uint64_t value, int digits) {
        char buf[24];
        std::snprintf(buf, sizeof(buf), "%0*llX", digits, static_cast<unsigned long long>(value));
        return addString(buf);
    }

    JsonTable& beginCellArray() {
        begin();
        mWriter->StartArray();
        return *this;
    }

    JsonTable& pushHex(uint64_t value, int digits) {
        char buf[24];
        std::snprintf(buf, sizeof(buf), "%0*llX", digits, static_cast<unsigned long long>(value));
        mWriter->String(buf);
        return *this;
    }

    JsonTable& pushUint(uint64_t value) {
        mWriter->Uint64(value);
        return *this;
    }

    JsonTable& pushString(const char* value) {
        mWriter->String(value ? value : "");
        return *this;
    }

    JsonTable& beginNested() {
        mWriter->StartArray();
        return *this;
    }

    JsonTable& endNested() {
        mWriter->EndArray();
        return *this;
    }

    JsonTable& endCellArray() {
        mWriter->EndArray();
        return *this;
    }

    void endRow() {
        if (!mWriter) return;
        if (mCell != mColumns) {
            std::fprintf(stderr, "[table] row has %zu cells, the header names %zu\n", mCell,
                         mColumns);
        }
        mWriter->EndArray();
        write(mBuffer.GetString(), mBuffer.GetSize());
        mWriter.reset();
        mBuffer.Clear();
        mCell = 0;
    }

private:
    void begin() {
        if (!mWriter) {
            mWriter = std::make_unique<rapidjson::Writer<rapidjson::StringBuffer>>(mBuffer);
            mWriter->StartArray();
        }
        mCell++;
    }

    void write(const char* data, size_t size) {
        if (!mFile) return;
        std::fwrite(data, 1, size, mFile);
        std::fputc('\n', mFile);
    }

    std::FILE* mFile;
    size_t mColumns;
    size_t mCell = 0;
    rapidjson::StringBuffer mBuffer;
    std::unique_ptr<rapidjson::Writer<rapidjson::StringBuffer>> mWriter;
};

}  // namespace pcsx2hook

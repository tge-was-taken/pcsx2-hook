// SPDX-FileCopyrightText: 2002-2026 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#pragma once

#include <cstdint>
#include <cstdio>
#include <initializer_list>
#include <string>

#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"

namespace pcsx2hook {

// One JSON object per trace row, written straight out rather than built as a document: a row is
// emitted per GS batch, so nothing here allocates a tree. Naming each field beside its value is the
// point, since the printf it replaces carried sixty specifiers and seventy positional arguments,
// where one insertion silently shifts every field after it into the wrong column.
class JsonObject {
public:
    JsonObject() : mWriter(mBuffer) { mWriter.StartObject(); }

    JsonObject& addUint(const char* key, uint64_t value) {
        mWriter.Key(key);
        mWriter.Uint64(value);
        return *this;
    }

    JsonObject& addInt(const char* key, int64_t value) {
        mWriter.Key(key);
        mWriter.Int64(value);
        return *this;
    }

    JsonObject& addBool(const char* key, bool value) {
        mWriter.Key(key);
        mWriter.Bool(value);
        return *this;
    }

    // Rounded rather than written at full precision: these read as measurements, and a reader
    // diffing two traces should not see a difference that is only float noise.
    JsonObject& addReal(const char* key, double value, int decimals = 6) {
        mWriter.Key(key);
        mWriter.SetMaxDecimalPlaces(decimals);
        mWriter.Double(value);
        mWriter.SetMaxDecimalPlaces(324);
        return *this;
    }

    JsonObject& addString(const char* key, const char* value) {
        mWriter.Key(key);
        mWriter.String(value ? value : "");
        return *this;
    }

    // Hex stays a string rather than becoming a number a reader has to reformat. The two spellings
    // are not interchangeable: each trace's readers expect the one that trace already wrote.
    JsonObject& addHex(const char* key, uint64_t value, int digits) {
        char buf[24];
        std::snprintf(buf, sizeof(buf), "0x%0*llX", digits, static_cast<unsigned long long>(value));
        return addString(key, buf);
    }

    // A 128-bit register reads as one 32-character field, not two halves a reader has to rejoin.
    JsonObject& addHex128(const char* key, uint64_t hi, uint64_t lo) {
        char buf[40];
        std::snprintf(buf, sizeof(buf), "%016llX%016llX", static_cast<unsigned long long>(hi),
                      static_cast<unsigned long long>(lo));
        return addString(key, buf);
    }

    JsonObject& addHexDigits(const char* key, uint64_t value, int digits) {
        char buf[24];
        std::snprintf(buf, sizeof(buf), "%0*llX", digits, static_cast<unsigned long long>(value));
        return addString(key, buf);
    }

    JsonObject& addUints(const char* key, std::initializer_list<uint64_t> values) {
        mWriter.Key(key);
        mWriter.StartArray();
        for (uint64_t v : values) mWriter.Uint64(v);
        mWriter.EndArray();
        return *this;
    }

    JsonObject& addReals(const char* key, std::initializer_list<double> values, int decimals = 6) {
        mWriter.Key(key);
        mWriter.SetMaxDecimalPlaces(decimals);
        mWriter.StartArray();
        for (double v : values) mWriter.Double(v);
        mWriter.EndArray();
        mWriter.SetMaxDecimalPlaces(324);
        return *this;
    }

    // Arrays and nested objects are built in place rather than assembled as a string first, so a
    // loop that writes elements cannot leave the row half-punctuated.
    JsonObject& beginArray(const char* key) {
        mWriter.Key(key);
        mWriter.StartArray();
        return *this;
    }

    JsonObject& endArray() {
        mWriter.EndArray();
        return *this;
    }

    JsonObject& beginObject(const char* key) {
        mWriter.Key(key);
        mWriter.StartObject();
        return *this;
    }

    JsonObject& beginObject() {
        mWriter.StartObject();
        return *this;
    }

    JsonObject& endObject() {
        mWriter.EndObject();
        return *this;
    }

    JsonObject& pushUint(uint64_t value) {
        mWriter.Uint64(value);
        return *this;
    }

    JsonObject& pushReal(double value, int decimals = 6) {
        mWriter.SetMaxDecimalPlaces(decimals);
        mWriter.Double(value);
        mWriter.SetMaxDecimalPlaces(324);
        return *this;
    }

    JsonObject& pushString(const char* value) {
        mWriter.String(value ? value : "");
        return *this;
    }

    JsonObject& pushHexDigits(uint64_t value, int digits) {
        char buf[24];
        std::snprintf(buf, sizeof(buf), "%0*llX", digits, static_cast<unsigned long long>(value));
        return pushString(buf);
    }

    // Closes the object and hands over the row, newline included: every consumer reads JSONL.
    std::string take() {
        mWriter.EndObject();
        return std::string(mBuffer.GetString(), mBuffer.GetSize()) + "\n";
    }

private:
    rapidjson::StringBuffer mBuffer;
    rapidjson::Writer<rapidjson::StringBuffer> mWriter;
};

}  // namespace pcsx2hook

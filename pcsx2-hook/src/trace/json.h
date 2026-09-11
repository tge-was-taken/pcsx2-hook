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

    JsonObject& addHex(const char* key, uint64_t value, int digits) {
        char buf[24];
        std::snprintf(buf, sizeof(buf), "0x%0*llX", digits, static_cast<unsigned long long>(value));
        return addString(key, buf);
    }

    JsonObject& addHex128(const char* key, uint64_t hi, uint64_t lo) {
        char buf[40];
        std::snprintf(buf, sizeof(buf), "%016llX%016llX", static_cast<unsigned long long>(hi),
                      static_cast<unsigned long long>(lo));
        return addString(key, buf);
    }

    JsonObject& addHex128(const char* key, const uint32_t words[4]) {
        return addHex128(key, (static_cast<uint64_t>(words[3]) << 32) | words[2],
                         (static_cast<uint64_t>(words[1]) << 32) | words[0]);
    }

    JsonObject& addHexDigits(const char* key, uint64_t value, int digits) {
        char buf[24];
        std::snprintf(buf, sizeof(buf), "%0*llX", digits, static_cast<unsigned long long>(value));
        return addString(key, buf);
    }

    JsonObject& addHexBytes(const char* key, const uint8_t* bytes, size_t count) {
        static const char kDigits[] = "0123456789ABCDEF";
        std::string hex(count * 2, '0');
        for (size_t i = 0; i < count; i++) {
            hex[i * 2] = kDigits[bytes[i] >> 4];
            hex[i * 2 + 1] = kDigits[bytes[i] & 15];
        }
        return addString(key, hex.c_str());
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

    JsonObject& pushHex128(const uint32_t words[4]) {
        char buf[40];
        std::snprintf(buf, sizeof(buf), "%08X%08X%08X%08X", words[3], words[2], words[1], words[0]);
        return pushString(buf);
    }

    JsonObject& pushHexDigits(uint64_t value, int digits) {
        char buf[24];
        std::snprintf(buf, sizeof(buf), "%0*llX", digits, static_cast<unsigned long long>(value));
        return pushString(buf);
    }

    std::string take() {
        mWriter.EndObject();
        return std::string(mBuffer.GetString(), mBuffer.GetSize()) + "\n";
    }

private:
    rapidjson::StringBuffer mBuffer;
    rapidjson::Writer<rapidjson::StringBuffer> mWriter;
};

}  // namespace pcsx2hook

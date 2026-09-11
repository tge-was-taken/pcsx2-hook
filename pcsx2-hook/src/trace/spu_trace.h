// SPDX-FileCopyrightText: 2002-2026 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "SPU2/defs.h"

namespace pcsx2hook {

class SpuTrace {
public:
    struct Unit {
        const char* file;
        size_t cap;
        std::unordered_map<std::string, size_t> forms;
        std::unordered_set<uint64_t> seen;
        std::vector<std::pair<std::string, std::string>> formRows;
    };

    bool isEnabled();
    void init();
    void onAdpcm(const uint8_t* block, int32_t prev1In, int32_t prev2In, const int16_t* samples,
                 int32_t prev1Out, int32_t prev2Out);
    void onVoice(uint32_t core, uint32_t voice, uint32_t stage, int32_t outL, int32_t outR);
    void onRegWrite(uint32_t addr, uint16_t value, bool after);
    void onRegRead(uint32_t addr, uint16_t value);
    void write();

private:
    struct VoiceStep {
        bool voicePending = false, adsrPending = false, volumePending = false;
        uint32_t voiceForm = 0, adsrForm = 0, volumeForm = 0;
        V_Voice before;
        V_VolumeSlideLR volumeBefore;
        int32_t prevOutX = 0;
        uint32_t noiseOut = 0;
    };

    std::string getOutputDir();
    static bool admit(Unit& u, const std::string& form, uint64_t key);
    static void accept(Unit& u, const std::string& form, std::string row);
    void snapshotFields(std::vector<int64_t>& out);

    Unit mAdpcm{"spu_adpcm_vectors.jsonl", 64, {}, {}, {}};
    Unit mAdsr{"spu_adsr_vectors.jsonl", 128, {}, {}, {}};
    Unit mVolume{"spu_volume_vectors.jsonl", 128, {}, {}, {}};
    Unit mVoice{"spu_voice_vectors.jsonl", 512, {}, {}, {}};
    Unit mReg{"spu_reg_vectors.jsonl", 64, {}, {}, {}};

    std::vector<size_t> mAdsrFormCases, mVolumeFormCases, mVoiceFormCases;
    VoiceStep mSteps[2][24];

    std::vector<std::string> mFieldNames;
    std::vector<int64_t> mRegBefore;
    bool mRegPending = false;
    uint64_t mVoiceSamples = 0, mRegWrites = 0, mRegReads = 0, mAdpcmBlocks = 0;
};

void spuAdpcmSink(const uint8_t* block, int32_t prev1In, int32_t prev2In, const int16_t* samples,
                  int32_t prev1Out, int32_t prev2Out);
void spuVoiceSink(uint32_t core, uint32_t voice, uint32_t stage, int32_t outL, int32_t outR);
void spuRegWriteSink(uint32_t addr, uint16_t value, bool after);
void spuRegReadSink(uint32_t addr, uint16_t value);

}  // namespace pcsx2hook

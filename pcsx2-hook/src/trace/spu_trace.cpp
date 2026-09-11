// SPDX-FileCopyrightText: 2002-2026 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#include "trace/spu_trace.h"
#include "trace/hash.h"
#include "trace/json.h"
#include "trace/table.h"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <iterator>
#include <filesystem>

#include "SPU2/defs.h"
#include "SPU2/regs.h"
#include "config.h"
#include "diagnostics.h"
#include "pcsx2/Hooks.h"

namespace pcsx2hook {

namespace {
const char* const kVoiceKindNames[] = {"stopped", "noise", "pmod", "normal"};
const char* const kPhaseNames[5] = {"stopped", "attack", "decay", "sustain", "release"};
const char* const kVoiceParams[8] = {"VOLL", "VOLR", "PITCH", "ADSR1", "ADSR2", "ENVX", "VOLXL", "VOLXR"};
const char* const kVoiceAddrs[6] = {"SSAH", "SSAL", "LSAH", "LSAL", "NAXH", "NAXL"};

std::string getRegName(uint32_t rmem, uint32_t& core, int& voice) {
    char buf[32];
    voice = -1;
    core = 0;
    if (rmem >> 16 == 0x1f80) {
        std::snprintf(buf, sizeof(buf), "PS1_%04X", rmem & 0xffff);
        return buf;
    }
    const uint32_t mem = rmem & 0x7FF;
    if (mem >= 0x760 && mem < 0x7B0) {
        uint32_t omem = mem;
        if (mem >= 0x788) {
            omem -= 0x28;
            core = 1;
        }
        static const char* const kShared[] = {"MVOLL", "MVOLR", "EVOLL", "EVOLR", "AVOLL",
                                              "AVOLR", "BVOLL", "BVOLR", "MVOLXL", "MVOLXR",
                                              "IIR_VOL", "COMB1_VOL", "COMB2_VOL", "COMB3_VOL",
                                              "COMB4_VOL", "WALL_VOL", "APF1_VOL", "APF2_VOL",
                                              "IN_COEF_L", "IN_COEF_R"};
        const uint32_t i = (omem - 0x760) / 2;
        if (i < std::size(kShared)) return kShared[i];
        std::snprintf(buf, sizeof(buf), "R_%03X", omem);
        return buf;
    }
    uint32_t omem = mem;
    if (mem & 0x400) {
        omem ^= 0x400;
        core = 1;
    }
    if (omem < 0x180) {
        voice = static_cast<int>((omem & 0x1F0) >> 4);
        return kVoiceParams[(omem & 0xF) >> 1];
    }
    if (omem >= 0x1C0 && omem < 0x2E0) {
        voice = static_cast<int>((omem - 0x1C0) / 12);
        return kVoiceAddrs[((omem - 0x1C0) % 12) >> 1];
    }
    static const char* const kReverb[] = {"APF1_SIZE", "APF2_SIZE", "SAME_L_DST", "SAME_R_DST",
                                          "COMB1_L_SRC", "COMB1_R_SRC", "COMB2_L_SRC",
                                          "COMB2_R_SRC", "SAME_L_SRC", "SAME_R_SRC", "DIFF_L_DST",
                                          "DIFF_R_DST", "COMB3_L_SRC", "COMB3_R_SRC",
                                          "COMB4_L_SRC", "COMB4_R_SRC", "DIFF_L_SRC",
                                          "DIFF_R_SRC", "APF1_L_DST", "APF1_R_DST", "APF2_L_DST",
                                          "APF2_R_DST"};
    if (omem >= R_APF1_SIZE && omem < REG_A_EEA) {
        const uint32_t i = (omem - R_APF1_SIZE) / 4;
        return std::string(kReverb[i]) + ((omem & 2) ? "L" : "H");
    }
    switch (omem & ~1u) {
        case REG_S_PMON: return "PMON0";
        case REG_S_PMON + 2: return "PMON1";
        case REG_S_NON: return "NON0";
        case REG_S_NON + 2: return "NON1";
        case REG_S_VMIXL: return "VMIXL0";
        case REG_S_VMIXL + 2: return "VMIXL1";
        case REG_S_VMIXEL: return "VMIXEL0";
        case REG_S_VMIXEL + 2: return "VMIXEL1";
        case REG_S_VMIXR: return "VMIXR0";
        case REG_S_VMIXR + 2: return "VMIXR1";
        case REG_S_VMIXER: return "VMIXER0";
        case REG_S_VMIXER + 2: return "VMIXER1";
        case REG_P_MMIX: return "MMIX";
        case REG_C_ATTR: return "ATTR";
        case REG_A_IRQA: return "IRQAH";
        case REG_A_IRQA + 2: return "IRQAL";
        case REG_S_KON: return "KON0";
        case REG_S_KON + 2: return "KON1";
        case REG_S_KOFF: return "KOFF0";
        case REG_S_KOFF + 2: return "KOFF1";
        case REG_A_TSA: return "TSAH";
        case REG_A_TSA + 2: return "TSAL";
        case REG__1AC: return "DATA";
        case REG__1AE: return "R_1AE";
        case REG_S_ADMAS: return "ADMAS";
        case REG_A_ESA: return "ESAH";
        case REG_A_ESA + 2: return "ESAL";
        case REG_A_EEA: return "EEA";
        case REG_S_ENDX: return "ENDX0";
        case REG_S_ENDX + 2: return "ENDX1";
        case REG_P_STATX: return "STATX";
        default: break;
    }
    std::snprintf(buf, sizeof(buf), "R_%03X", omem);
    return buf;
}

template <typename F>
void visitFields(F&& f) {
    for (uint32_t c = 0; c < 2; c++) {
        const V_Core& k = Cores[c];
        f(c, -1, "pmon", k.Regs.PMON);
        f(c, -1, "non", k.Regs.NON);
        f(c, -1, "vmixl", k.Regs.VMIXL);
        f(c, -1, "vmixr", k.Regs.VMIXR);
        f(c, -1, "vmixel", k.Regs.VMIXEL);
        f(c, -1, "vmixer", k.Regs.VMIXER);
        f(c, -1, "endx", k.Regs.ENDX);
        f(c, -1, "mmix", k.Regs.MMIX);
        f(c, -1, "statx", k.Regs.STATX);
        f(c, -1, "attr", k.Regs.ATTR);
        f(c, -1, "irqa", k.IRQA);
        f(c, -1, "tsa", k.TSA);
        f(c, -1, "activeTsa", k.ActiveTSA);
        f(c, -1, "irqEnable", k.IRQEnable);
        f(c, -1, "fxEnable", k.FxEnable);
        f(c, -1, "mute", k.Mute);
        f(c, -1, "admaInProgress", k.AdmaInProgress);
        f(c, -1, "dmaBits", k.DMABits);
        f(c, -1, "noiseClk", k.NoiseClk);
        f(c, -1, "autoDmaCtrl", k.AutoDMACtrl);
        f(c, -1, "keyOn", k.KeyOn);
        f(c, -1, "keyOff", k.KeyOff);
        f(c, -1, "effectsStartA", k.EffectsStartA);
        f(c, -1, "effectsEndA", k.EffectsEndA);
        f(c, -1, "coreEnabled", k.CoreEnabled);
        f(c, -1, "attrBit0", k.AttrBit0);
        f(c, -1, "dmaMode", k.DmaMode);
        f(c, -1, "masterVolL.reg", k.MasterVol.Left.Reg_VOL);
        f(c, -1, "masterVolL.value", k.MasterVol.Left.Value);
        f(c, -1, "masterVolR.reg", k.MasterVol.Right.Reg_VOL);
        f(c, -1, "masterVolR.value", k.MasterVol.Right.Value);
        f(c, -1, "extVolL", k.ExtVol.Left);
        f(c, -1, "extVolR", k.ExtVol.Right);
        f(c, -1, "inpVolL", k.InpVol.Left);
        f(c, -1, "inpVolR", k.InpVol.Right);
        f(c, -1, "fxVolL", k.FxVol.Left);
        f(c, -1, "fxVolR", k.FxVol.Right);
        const V_Reverb& r = k.Revb;
        f(c, -1, "revb.IN_COEF_L", r.IN_COEF_L);
        f(c, -1, "revb.IN_COEF_R", r.IN_COEF_R);
        f(c, -1, "revb.APF1_SIZE", r.APF1_SIZE);
        f(c, -1, "revb.APF2_SIZE", r.APF2_SIZE);
        f(c, -1, "revb.APF1_VOL", r.APF1_VOL);
        f(c, -1, "revb.APF2_VOL", r.APF2_VOL);
        f(c, -1, "revb.SAME_L_SRC", r.SAME_L_SRC);
        f(c, -1, "revb.SAME_R_SRC", r.SAME_R_SRC);
        f(c, -1, "revb.DIFF_L_SRC", r.DIFF_L_SRC);
        f(c, -1, "revb.DIFF_R_SRC", r.DIFF_R_SRC);
        f(c, -1, "revb.SAME_L_DST", r.SAME_L_DST);
        f(c, -1, "revb.SAME_R_DST", r.SAME_R_DST);
        f(c, -1, "revb.DIFF_L_DST", r.DIFF_L_DST);
        f(c, -1, "revb.DIFF_R_DST", r.DIFF_R_DST);
        f(c, -1, "revb.IIR_VOL", r.IIR_VOL);
        f(c, -1, "revb.WALL_VOL", r.WALL_VOL);
        f(c, -1, "revb.COMB1_L_SRC", r.COMB1_L_SRC);
        f(c, -1, "revb.COMB1_R_SRC", r.COMB1_R_SRC);
        f(c, -1, "revb.COMB2_L_SRC", r.COMB2_L_SRC);
        f(c, -1, "revb.COMB2_R_SRC", r.COMB2_R_SRC);
        f(c, -1, "revb.COMB3_L_SRC", r.COMB3_L_SRC);
        f(c, -1, "revb.COMB3_R_SRC", r.COMB3_R_SRC);
        f(c, -1, "revb.COMB4_L_SRC", r.COMB4_L_SRC);
        f(c, -1, "revb.COMB4_R_SRC", r.COMB4_R_SRC);
        f(c, -1, "revb.COMB1_VOL", r.COMB1_VOL);
        f(c, -1, "revb.COMB2_VOL", r.COMB2_VOL);
        f(c, -1, "revb.COMB3_VOL", r.COMB3_VOL);
        f(c, -1, "revb.COMB4_VOL", r.COMB4_VOL);
        f(c, -1, "revb.APF1_L_DST", r.APF1_L_DST);
        f(c, -1, "revb.APF1_R_DST", r.APF1_R_DST);
        f(c, -1, "revb.APF2_L_DST", r.APF2_L_DST);
        f(c, -1, "revb.APF2_R_DST", r.APF2_R_DST);
        for (int v = 0; v < 24; v++) {
            const V_Voice& x = k.Voices[v];
            f(c, v, "volL.reg", x.Volume.Left.Reg_VOL);
            f(c, v, "volL.value", x.Volume.Left.Value);
            f(c, v, "volL.counter", x.Volume.Left.Counter);
            f(c, v, "volR.reg", x.Volume.Right.Reg_VOL);
            f(c, v, "volR.value", x.Volume.Right.Value);
            f(c, v, "volR.counter", x.Volume.Right.Counter);
            f(c, v, "adsr.reg", x.ADSR.reg32);
            f(c, v, "adsr.phase", x.ADSR.Phase);
            f(c, v, "adsr.counter", x.ADSR.Counter);
            f(c, v, "adsr.value", x.ADSR.Value);
            f(c, v, "pitch", x.Pitch);
            f(c, v, "ssa", x.StartA);
            f(c, v, "lsa", x.LoopStartA);
            f(c, v, "nexta", x.NextA);
            f(c, v, "prev1", x.Prev1);
            f(c, v, "prev2", x.Prev2);
            f(c, v, "modulated", x.Modulated);
            f(c, v, "noise", x.Noise);
            f(c, v, "loopMode", x.LoopMode);
            f(c, v, "loopFlags", x.LoopFlags);
            f(c, v, "sp", x.SP);
            f(c, v, "outx", x.OutX);
            f(c, v, "decPosRead", x.DecPosRead);
            f(c, v, "decPosWrite", x.DecPosWrite);
        }
    }
}

std::string fieldName(uint32_t core, int voice, const char* name) {
    char buf[64];
    if (voice < 0)
        std::snprintf(buf, sizeof(buf), "c%u.%s", core, name);
    else
        std::snprintf(buf, sizeof(buf), "c%u.v%d.%s", core, voice, name);
    return buf;
}

uint32_t getAdsrForm(const V_ADSR& a) {
    const auto& p = a.CachedPhases.at(a.Phase);
    return ((((a.Phase - 1) * 2u + p.Exp) * 2u + p.Decr) * 32u) + (p.Shift & 31u);
}

std::string getAdsrFormName(uint32_t id) {
    const uint32_t shift = id % 32, decr = (id / 32) % 2, exp = (id / 64) % 2, phase = id / 128 + 1;
    return std::string(kPhaseNames[phase]) + (exp ? ".exp" : ".lin") + (decr ? ".dec" : ".inc") +
           ".s" + std::to_string(shift);
}

bool adsrCounterCarries(const V_ADSR& a) {
    const auto& p = a.CachedPhases.at(a.Phase);
    uint32_t inc = 0x8000u >> std::max(0, p.Shift - 11);
    if (p.Exp && !p.Decr && a.Value > 0x6000) inc >>= 2;
    return a.Counter + std::max<uint32_t>(1, inc) >= 0x8000;
}

uint32_t keyedVoicesPlaying(uint32_t core, const std::string& konOrKoff, uint16_t value) {
    const uint32_t first = konOrKoff.back() == '1' ? 16 : 0;
    uint32_t playing = 0;
    for (uint32_t b = 0; b < 16 && first + b < 24; b++)
        if ((value >> b) & 1) playing |= (Cores[core].Voices[first + b].ADSR.Phase > 0) << b;
    return playing;
}

void addAdsr(JsonObject& row, const char* key, const V_ADSR& a, bool cached) {
    row.beginObject(key)
        .addHexDigits("reg", a.reg32, 8)
        .addUint("phase", a.Phase)
        .addUint("counter", a.Counter)
        .addInt("value", a.Value);
    if (cached && a.Phase > 0 && a.Phase < V_ADSR::ADSR_PHASES) {
        const auto& p = a.CachedPhases.at(a.Phase);
        row.beginObject("cached")
            .addBool("decr", p.Decr)
            .addBool("exp", p.Exp)
            .addUint("shift", p.Shift)
            .addInt("step", p.Step)
            .addInt("target", p.Target)
            .endObject();
    }
    row.endObject();
}

void addSlide(JsonObject& row, const char* key, const V_VolumeSlide& v) {
    row.beginObject(key)
        .addHexDigits("reg", v.Reg_VOL, 4)
        .addUint("counter", v.Counter)
        .addInt("value", v.Value)
        .endObject();
}
}  // namespace

std::string SpuTrace::getOutputDir() {
    const char* env = Config::get().getValue("PCSX2HOOK_SPU_TRACE");
    if (!env || !*env || std::strcmp(env, "1") == 0) return Diagnostics::get().getDumps().getDir();
    return env;
}

bool SpuTrace::isEnabled() {
    static const bool on = Config::get().getValue("PCSX2HOOK_SPU_TRACE") != nullptr;
    return on;
}

void SpuTrace::init() {
    if (!isEnabled()) return;
    mAdsrFormCases.assign(4 * 2 * 2 * 32, 0);
    mVolumeFormCases.assign(8, 0);
    mVoiceFormCases.assign(std::size(kVoiceKindNames), 0);
    visitFields([this](uint32_t c, int v, const char* name, int64_t) {
        mFieldNames.push_back(fieldName(c, v, name));
    });
    Hooks::SetSpuAdpcmSink(&spuAdpcmSink);
    Hooks::SetSpuVoiceSink(&spuVoiceSink);
    Hooks::SetSpuRegSink(&spuRegWriteSink, &spuRegReadSink);
    std::fprintf(stderr, "[spu] recording SPU2 vectors\n");
}

bool SpuTrace::admit(Unit& u, const std::string& form, uint64_t key) {
    if (u.forms[form] >= u.cap) return false;
    return u.seen.insert(hashMix(key, std::hash<std::string>{}(form))).second;
}

void SpuTrace::accept(Unit& u, const std::string& form, std::string row) {
    u.forms[form]++;
    u.formRows.emplace_back(form, std::move(row));
}

void SpuTrace::snapshotFields(std::vector<int64_t>& out) {
    out.clear();
    visitFields([&out](uint32_t, int, const char*, int64_t value) { out.push_back(value); });
}

void SpuTrace::onAdpcm(const uint8_t* block, int32_t prev1In, int32_t prev2In,
                       const int16_t* samples, int32_t prev1Out, int32_t prev2Out) {
    mAdpcmBlocks++;
    const uint32_t shift = block[0] & 0xF, filter = (block[0] >> 4) & 0xF;
    const std::string form = "f" + std::to_string(filter) + ".s" + std::to_string(shift);
    uint64_t key = (static_cast<uint64_t>(static_cast<uint32_t>(prev1In)) << 32) |
                   static_cast<uint32_t>(prev2In);
    for (int i = 0; i < 16; i += 8) {
        uint64_t w;
        std::memcpy(&w, block + i, 8);
        key = hashMix(key, w);
    }
    if (!admit(mAdpcm, form, key)) return;

    char hex[40];
    for (int i = 0; i < 16; i++) std::snprintf(hex + i * 2, 3, "%02X", block[i]);
    JsonObject row;
    row.addString("form", form.c_str())
        .addString("block", hex)
        .addUint("filter", filter)
        .addUint("shift", shift)
        .addHexDigits("flags", block[1], 2)
        .addInt("prev1", prev1In)
        .addInt("prev2", prev2In)
        .beginArray("samples");
    for (int i = 0; i < 28; i++) row.pushUint(static_cast<uint16_t>(samples[i]));
    row.endArray().addInt("prev1Out", prev1Out).addInt("prev2Out", prev2Out);
    accept(mAdpcm, form, row.take());
}

void SpuTrace::onVoice(uint32_t core, uint32_t voice, uint32_t stage, int32_t outL, int32_t outR) {
    if (core > 1 || voice > 23) return;
    VoiceStep& s = mSteps[core][voice];
    const V_Core& k = Cores[core];
    const V_Voice& vc = k.Voices[voice];

    if (stage == 0) {
        s.volumePending = false;
        const V_VolumeSlide& side = vc.Volume.Left.Enable ? vc.Volume.Left : vc.Volume.Right;
        if (!side.Enable) return;
        s.volumeForm = side.Exp * 4u + side.Decr * 2u + side.Phase;
        if (mVolumeFormCases[s.volumeForm] >= mVolume.cap) return;
        const uint64_t key = hashMix((static_cast<uint64_t>(vc.Volume.Left.Reg_VOL) << 16) | vc.Volume.Right.Reg_VOL,
                                 (static_cast<uint64_t>(vc.Volume.Left.Value >> 9) << 32) |
                                     static_cast<uint32_t>(vc.Volume.Right.Value >> 9));
        const std::string form = std::string(side.Exp ? "exp" : "lin") + (side.Decr ? ".dec" : ".inc") +
                                 ".phase" + std::to_string(side.Phase);
        if (!admit(mVolume, form, key)) return;
        s.volumeBefore = vc.Volume;
        s.volumePending = true;
        return;
    }

    if (stage == 1) {
        mVoiceSamples++;
        if (s.volumePending) {
            s.volumePending = false;
            const std::string form = std::string((s.volumeForm & 4) ? "exp" : "lin") +
                                     ((s.volumeForm & 2) ? ".dec" : ".inc") + ".phase" +
                                     std::to_string(s.volumeForm & 1);
            JsonObject row;
            row.addUint("core", core).addUint("voice", voice).addString("form", form.c_str());
            addSlide(row, "leftIn", s.volumeBefore.Left);
            addSlide(row, "rightIn", s.volumeBefore.Right);
            addSlide(row, "leftOut", vc.Volume.Left);
            addSlide(row, "rightOut", vc.Volume.Right);
            accept(mVolume, form, row.take());
            mVolumeFormCases[s.volumeForm]++;
        }

        s.voicePending = s.adsrPending = false;
        const bool active = vc.ADSR.Phase > V_ADSR::PHASE_STOPPED;
        const bool pmod = vc.Modulated && voice > 0;
        const uint32_t kind = !active ? 0 : vc.Noise ? 1 : pmod ? 2 : 3;
        const uint32_t interpPhase = (vc.SP & 0x0ff0) >> 4;
        if (mVoiceFormCases[kind] < mVoice.cap) {
            uint64_t key = hashMix(kind, interpPhase);
            key = hashMix(key, (static_cast<uint64_t>(vc.Pitch >> 6) << 8) | vc.ADSR.Phase);
            if (pmod) key = hashMix(key, static_cast<uint32_t>(k.Voices[voice - 1].OutX >> 10));
            if (admit(mVoice, kVoiceKindNames[kind], key)) {
                s.voicePending = true;
                s.voiceForm = kind;
            }
        }
        if (active && vc.ADSR.Phase < V_ADSR::ADSR_PHASES) {
            const uint32_t form = getAdsrForm(vc.ADSR);
            if (mAdsrFormCases[form] < mAdsr.cap) {
                uint64_t key = hashMix(vc.ADSR.reg32, vc.ADSR.Phase);
                key = hashMix(key, (static_cast<uint64_t>(vc.ADSR.Value >> 9) << 1) | adsrCounterCarries(vc.ADSR));
                if (admit(mAdsr, getAdsrFormName(form), key)) {
                    s.adsrPending = true;
                    s.adsrForm = form;
                }
            }
        }
        if (s.voicePending || s.adsrPending) {
            s.before = vc;
            s.prevOutX = voice > 0 ? k.Voices[voice - 1].OutX : 0;
            s.noiseOut = k.NoiseOut;
        }
        return;
    }

    if (s.adsrPending) {
        s.adsrPending = false;
        const std::string form = getAdsrFormName(s.adsrForm);
        JsonObject row;
        row.addUint("core", core).addUint("voice", voice).addString("form", form.c_str());
        addAdsr(row, "in", s.before.ADSR, true);
        addAdsr(row, "out", vc.ADSR, false);
        accept(mAdsr, form, row.take());
        mAdsrFormCases[s.adsrForm]++;
    }
    if (s.voicePending) {
        s.voicePending = false;
        const V_Voice& b = s.before;
        JsonObject row;
        row.addUint("core", core).addUint("voice", voice).addString("form", kVoiceKindNames[s.voiceForm]);
        row.beginObject("in")
            .addHexDigits("pitch", b.Pitch, 4)
            .addBool("modulated", b.Modulated)
            .addBool("noise", b.Noise)
            .addInt("prevOutX", s.prevOutX)
            .addHexDigits("noiseOut", s.noiseOut, 8)
            .addHexDigits("sp", static_cast<uint32_t>(b.SP), 8)
            .addUint("decPosRead", b.DecPosRead)
            .beginArray("fifo");
        for (uint32_t i = 0; i < 4; i++) row.pushUint(static_cast<uint16_t>(b.DecodeFifo[(b.DecPosRead + i) % 32]));
        row.endArray();
        addAdsr(row, "adsr", b.ADSR, true);
        row.addInt("volL", b.Volume.Left.Value).addInt("volR", b.Volume.Right.Value).endObject();
        row.beginObject("out")
            .addHexDigits("sp", static_cast<uint32_t>(vc.SP), 8)
            .addUint("decPosRead", vc.DecPosRead)
            .addInt("outx", vc.OutX)
            .addInt("outL", outL)
            .addInt("outR", outR);
        addAdsr(row, "adsr", vc.ADSR, false);
        row.endObject();
        accept(mVoice, kVoiceKindNames[s.voiceForm], row.take());
        mVoiceFormCases[s.voiceForm]++;
    }
}

void SpuTrace::onRegWrite(uint32_t addr, uint16_t value, bool after) {
    uint32_t core = 0;
    int voice = -1;
    const std::string name = getRegName(addr, core, voice);
    const std::string form = "write:" + name;
    if (!after) {
        mRegWrites++;
        mRegPending = false;
        uint64_t key = hashMix(std::hash<std::string>{}(name), value);
        if (voice >= 0) key = hashMix(key, Cores[core].Voices[voice].ADSR.Phase);
        if (name.rfind("KO", 0) == 0) key = hashMix(key, keyedVoicesPlaying(core, name, value));
        if (!admit(mReg, form, key)) return;
        snapshotFields(mRegBefore);
        mRegPending = true;
        return;
    }
    if (!mRegPending) return;
    mRegPending = false;
    std::vector<int64_t> now;
    snapshotFields(now);
    char addrHex[16];
    std::snprintf(addrHex, sizeof(addrHex), "%08X", addr);
    JsonObject row;
    row.addString("form", form.c_str())
        .addString("addr", addrHex)
        .addString("name", name.c_str())
        .addUint("core", core)
        .addInt("voice", voice)
        .addHexDigits("value", value, 4)
        .beginArray("deltas");
    for (size_t i = 0; i < now.size() && i < mRegBefore.size(); i++) {
        if (now[i] == mRegBefore[i]) continue;
        row.beginObject()
            .addString("field", mFieldNames[i].c_str())
            .addInt("before", mRegBefore[i])
            .addInt("after", now[i])
            .endObject();
    }
    row.endArray();
    accept(mReg, form, row.take());
}

void SpuTrace::onRegRead(uint32_t addr, uint16_t value) {
    mRegReads++;
    uint32_t core = 0;
    int voice = -1;
    const std::string name = getRegName(addr, core, voice);
    const std::string form = "read:" + name;
    if (!admit(mReg, form, hashMix(std::hash<std::string>{}(name), value))) return;

    const std::string prefix = fieldName(core, voice, "");
    std::vector<int64_t> now;
    snapshotFields(now);
    char addrHex[16];
    std::snprintf(addrHex, sizeof(addrHex), "%08X", addr);
    JsonObject row;
    row.addString("form", form.c_str())
        .addString("addr", addrHex)
        .addString("name", name.c_str())
        .addUint("core", core)
        .addInt("voice", voice)
        .addHexDigits("value", value, 4)
        .beginObject("state");
    for (size_t i = 0; i < now.size(); i++) {
        const std::string& f = mFieldNames[i];
        if (f.compare(0, prefix.size(), prefix) != 0) continue;
        const bool voiceField = f.size() > prefix.size() + 1 && f[prefix.size()] == 'v' &&
                                std::isdigit(static_cast<unsigned char>(f[prefix.size() + 1]));
        if (voice < 0 && voiceField) continue;
        row.addInt(f.c_str() + prefix.size(), now[i]);
    }
    row.endObject();
    accept(mReg, form, row.take());
}

void SpuTrace::write() {
    if (!isEnabled()) return;
    const std::string dir = getOutputDir();
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);

    size_t total = 0;
    for (Unit* u : {&mAdpcm, &mAdsr, &mVolume, &mVoice, &mReg}) {
        std::stable_sort(u->formRows.begin(), u->formRows.end(),
                         [](const auto& a, const auto& b) { return a.first < b.first; });
        if (FILE* f = std::fopen((dir + "/" + u->file).c_str(), "w")) {
            for (const auto& [form, row] : u->formRows) std::fwrite(row.data(), 1, row.size(), f);
            std::fclose(f);
        }
        total += u->formRows.size();
    }

    if (FILE* g = std::fopen((dir + "/spu_forms.jsonl").c_str(), "w")) {
        JsonTable t(g, {"unit", "form", "cases"});
        for (Unit* u : {&mAdpcm, &mAdsr, &mVolume, &mVoice, &mReg}) {
            std::string unit(u->file);
            unit = unit.substr(4, unit.find("_vectors") - 4);
            std::vector<std::string> names;
            for (const auto& kv : u->forms)
                if (kv.second) names.push_back(kv.first);
            std::sort(names.begin(), names.end());
            for (const std::string& n : names)
                t.addString(unit.c_str()).addString(n.c_str()).addUint(u->forms[n]).endRow();
        }
        std::fclose(g);
    }

    std::printf("[spu] %s: %zu vectors (adpcm %zu, adsr %zu, volume %zu, voice %zu, reg %zu) over "
                "%llu voice samples, %llu blocks, %llu writes, %llu reads\n",
                dir.c_str(), total, mAdpcm.formRows.size(), mAdsr.formRows.size(), mVolume.formRows.size(),
                mVoice.formRows.size(), mReg.formRows.size(), static_cast<unsigned long long>(mVoiceSamples),
                static_cast<unsigned long long>(mAdpcmBlocks),
                static_cast<unsigned long long>(mRegWrites), static_cast<unsigned long long>(mRegReads));
}

void spuAdpcmSink(const uint8_t* block, int32_t prev1In, int32_t prev2In, const int16_t* samples,
                  int32_t prev1Out, int32_t prev2Out) {
    Diagnostics::get().getSpu().onAdpcm(block, prev1In, prev2In, samples, prev1Out, prev2Out);
}

void spuVoiceSink(uint32_t core, uint32_t voice, uint32_t stage, int32_t outL, int32_t outR) {
    Diagnostics::get().getSpu().onVoice(core, voice, stage, outL, outR);
}

void spuRegWriteSink(uint32_t addr, uint16_t value, bool after) {
    Diagnostics::get().getSpu().onRegWrite(addr, value, after);
}

void spuRegReadSink(uint32_t addr, uint16_t value) {
    Diagnostics::get().getSpu().onRegRead(addr, value);
}

}  // namespace pcsx2hook

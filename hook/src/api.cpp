// SPDX-FileCopyrightText: 2002-2026 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#include "pcsx2hook/pcsx2hook.h"

#include <cstring>
#include <string>
#include <unordered_map>
#include <vector>

#include "common/Error.h"
#include "config.h"
#include "core.h"
#include "diagnostics.h"
#include "pcsx2/Hooks.h"
#include "pcsx2/MTGS.h"
#include "pcsx2/VMManager.h"
#include "Memory.h"
#include "symbols.h"

using namespace pcsx2hook;

namespace {

struct HostHandler {
    pcsx2hook_pre_fn pre;
    pcsx2hook_post_fn post;
    void* user;
};

std::unordered_map<uint32_t, HostHandler> s_handlers;

pcsx2hook_regs viewOf(Hooks::Context& ctx) {
    return pcsx2hook_regs{ctx.gpr, ctx.fpr, ctx.pc};
}

Hooks::Result preThunk(Hooks::Context& ctx) {
    const auto it = s_handlers.find(ctx.pc);
    if (it == s_handlers.end() || !it->second.pre) return Hooks::Result::Continue;
    pcsx2hook_regs view = viewOf(ctx);
    return it->second.pre(&view, it->second.user) == PCSX2HOOK_EXIT ? Hooks::Result::Exit
                                                                   : Hooks::Result::Continue;
}

void postThunk(Hooks::Context& ctx) {
    const auto it = s_handlers.find(ctx.pc);
    if (it == s_handlers.end() || !it->second.post) return;
    pcsx2hook_regs view = viewOf(ctx);
    it->second.post(&view, it->second.user);
}

// One variable per trace, so arming through the API and arming through the environment reach the
// same switch rather than two that can disagree.
const char* traceVariable(pcsx2hook_trace which) {
    switch (which) {
        case PCSX2HOOK_TRACE_EXEC: return "PCSX2HOOK_EXEC_TRACE";
        case PCSX2HOOK_TRACE_INSN: return "PCSX2HOOK_INSN_TRACE";
        case PCSX2HOOK_TRACE_IOP: return "PCSX2HOOK_IOP_TRACE";
        case PCSX2HOOK_TRACE_HW: return "PCSX2HOOK_HW_TRACE";
        case PCSX2HOOK_TRACE_SIF: return "PCSX2HOOK_SIF_TRACE";
        case PCSX2HOOK_TRACE_VIF: return "PCSX2HOOK_VIF_TRACE";
        case PCSX2HOOK_TRACE_VU: return "PCSX2HOOK_VU_TRACE";
        case PCSX2HOOK_TRACE_GS: return "PCSX2HOOK_GS_TRACE";
        case PCSX2HOOK_TRACE_API: return "PCSX2HOOK_API_TRACE";
        default: return nullptr;
    }
}

}  // namespace

struct pcsx2hook_ctx {
    Core core;
    std::string error;
    bool booted = false;
};

extern "C" {

pcsx2hook_ctx* pcsx2hook_create(const pcsx2hook_config* config) {
    if (!config) return nullptr;
    auto* ctx = new pcsx2hook_ctx();
    Config& cfg = Config::get();
    if (config->bios_dir) cfg.set("PCSX2HOOK_BIOSDIR", config->bios_dir);
    if (config->bios_file) cfg.set("PCSX2HOOK_BIOS", config->bios_file);
    if (config->dump_dir) cfg.set("PCSX2HOOK_DUMP_DIR", config->dump_dir);
    if (config->symbols) cfg.set("PCSX2HOOK_SYMBOLS", config->symbols);
    if (config->interpreter) cfg.set("PCSX2HOOK_INTERP", "1");
    if (!config->software_gs) cfg.set("PCSX2HOOK_NULLGS", "1");
    return ctx;
}

void pcsx2hook_destroy(pcsx2hook_ctx* ctx) {
    delete ctx;
}

int pcsx2hook_arm(pcsx2hook_ctx* ctx, pcsx2hook_trace which) {
    if (!ctx) return 0;
    const char* name = traceVariable(which);
    if (!name) {
        ctx->error = "unknown trace";
        return 0;
    }
    if (ctx->booted) {
        ctx->error = "traces arm before boot: they hook code the recompiler has already compiled";
        return 0;
    }
    Config::get().set(name, "1");
    return 1;
}

int pcsx2hook_register(pcsx2hook_ctx* ctx, uint32_t addr, pcsx2hook_pre_fn pre,
                       pcsx2hook_post_fn post, void* user) {
    if (!ctx) return 0;
    s_handlers[addr] = HostHandler{pre, post, user};
    Hooks::Register(addr, pre ? &preThunk : nullptr, post ? &postThunk : nullptr);
    return 1;
}

uint32_t pcsx2hook_call_ee(pcsx2hook_ctx* ctx, uint32_t pc, const uint32_t* args, size_t count) {
    if (!ctx) return 0;
    std::initializer_list<uint32_t> empty{};
    if (!args || count == 0) return Hooks::CallEE(pc, empty, {});
    std::vector<uint32_t> gpr(args, args + count);
    switch (gpr.size()) {
        case 1: return Hooks::CallEE(pc, {gpr[0]}, {});
        case 2: return Hooks::CallEE(pc, {gpr[0], gpr[1]}, {});
        case 3: return Hooks::CallEE(pc, {gpr[0], gpr[1], gpr[2]}, {});
        default: return Hooks::CallEE(pc, {gpr[0], gpr[1], gpr[2], gpr[3]}, {});
    }
}

void* pcsx2hook_guest(pcsx2hook_ctx* ctx, uint32_t addr, uint32_t size) {
    if (!ctx) return nullptr;
    if ((addr & 0x1FFFFFFFu) + size > Ps2MemSize::MainRam) return nullptr;
    return PSM(addr);
}

int pcsx2hook_boot(pcsx2hook_ctx* ctx) {
    if (!ctx) return 0;
    ctx->error = "boot is driven by the host: build VMBootParameters and call Core::run";
    return 0;
}

int pcsx2hook_run_frames(pcsx2hook_ctx* ctx, uint32_t frames) {
    if (!ctx) return 0;
    (void)frames;
    ctx->error = "frame stepping needs the run loop to yield, which Core::run does not do yet";
    return 0;
}

int pcsx2hook_load_state(pcsx2hook_ctx* ctx, const char* path) {
    if (!ctx || !path) return 0;
    Error error;
    if (!VMManager::LoadState(path, &error)) {
        ctx->error = error.GetDescription();
        return 0;
    }
    return 1;
}

int pcsx2hook_save_state(pcsx2hook_ctx* ctx, const char* path) {
    if (!ctx || !path) return 0;
    VMManager::SaveState(path, false, false, {});
    return 1;
}

size_t pcsx2hook_read_framebuffer(pcsx2hook_ctx* ctx, void* out, size_t size, uint32_t* width,
                                  uint32_t* height) {
    if (!ctx) return 0;
    uint32_t w = 0, h = 0;
    std::vector<uint32_t> pixels;
    if (!MTGS::SaveMemorySnapshot(0, 0, false, false, &w, &h, &pixels)) {
        ctx->error = "no frame buffer to read: the null renderer fills none";
        return 0;
    }
    if (width) *width = w;
    if (height) *height = h;
    const size_t needed = pixels.size() * sizeof(uint32_t);
    if (out && size >= needed) std::memcpy(out, pixels.data(), needed);
    return needed;
}

void pcsx2hook_flush(pcsx2hook_ctx* ctx) {
    if (!ctx) return;
    Diagnostics& diag = Diagnostics::get();
    diag.getExec().write();
    diag.getInsn().write();
    diag.getIop().write();
    diag.getHw().write();
    diag.getSif().write();
    diag.getVif().write();
    diag.getApi().write();
    diag.getDraws().writeVuTrace();
    diag.getDraws().writeVuWatchTrace();
    diag.getDraws().writeVuJrTrace();
    diag.getDraws().writeVuExecTrace();
}

const char* pcsx2hook_last_error(pcsx2hook_ctx* ctx) {
    return ctx ? ctx->error.c_str() : "no context";
}

}  // extern "C"

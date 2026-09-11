// SPDX-FileCopyrightText: 2002-2026 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#include "pcsx2hook/pcsx2hook.h"

#include <atomic>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include "Memory.h"
#include "common/Error.h"
#include "common/MemorySettingsInterface.h"
#include "pcsx2/Hooks.h"
#include "pcsx2/MTGS.h"
#include "pcsx2/R5900.h"
#include "pcsx2/VMManager.h"
#include "config.h"
#include "core.h"
#include "diagnostics.h"
#include "trace/draw_context.h"
#include "host.h"
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

HostHandler s_observer{};

void observerThunk(Hooks::Context& ctx) {
    if (!s_observer.post) return;
    pcsx2hook_regs view = viewOf(ctx);
    s_observer.post(&view, s_observer.user);
}

void postThunk(Hooks::Context& ctx) {
    const auto it = s_handlers.find(ctx.pc);
    if (it == s_handlers.end() || !it->second.post) return;
    pcsx2hook_regs view = viewOf(ctx);
    it->second.post(&view, it->second.user);
}

// One variable per trace, so enabling through the API and enabling through the environment reach the
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
        case PCSX2HOOK_TRACE_VU_INSN: return "PCSX2HOOK_VU_INSN_TRACE";
        case PCSX2HOOK_TRACE_VIF_CMD: return "PCSX2HOOK_VIF_CMD_TRACE";
        case PCSX2HOOK_TRACE_SPU: return "PCSX2HOOK_SPU_TRACE";
        default: return nullptr;
    }
}

}  // namespace

// Forwards the run loop's extension points to the host's C callbacks.
struct pcsx2hook_ctx {
    class HostCore : public Core {
    public:
        explicit HostCore(pcsx2hook_ctx& owner) : mOwner(owner) {}

    protected:
        void applyExtraSettings(MemorySettingsInterface& si) override {
            mOwner.settings = &si;
            if (mOwner.config.on_settings) mOwner.config.on_settings(mOwner.config.user);
            mOwner.settings = nullptr;
        }
        void onVmReady() override {
            if (mOwner.config.on_vm_ready) mOwner.config.on_vm_ready(mOwner.config.user);
        }
        void onFrameExtra(uint32_t frame) override {
            if (mOwner.config.on_frame) mOwner.config.on_frame(frame, mOwner.config.user);
        }
        void onShutdown() override {
            if (mOwner.config.on_shutdown) mOwner.config.on_shutdown(mOwner.config.user);
        }

    private:
        pcsx2hook_ctx& mOwner;
    };

    pcsx2hook_ctx() : core(*this) {}

    pcsx2hook_config config{};
    HostCore core;
    Pcsx2Host host;
    MemorySettingsInterface* settings = nullptr;
    std::thread cpu;
    std::atomic<int> exitCode{1};
    std::string error;
    std::string serial;
    std::vector<uint32_t> frame;
    std::vector<uint32_t> capture;
    uint32_t captureWidth = 0, captureHeight = 0, captureFrame = 0;
    uint32_t frameWidth = 0;
    uint32_t frameHeight = 0;
};

extern "C" {

pcsx2hook_ctx* pcsx2hook_create(const pcsx2hook_config* config) {
    if (!config) return nullptr;
    auto* ctx = new pcsx2hook_ctx();
    ctx->config = *config;
    Config& cfg = Config::get();
    if (config->bios) cfg.set("PCSX2HOOK_BIOS", config->bios);
    if (config->dump_dir) cfg.set("PCSX2HOOK_DUMP_DIR", config->dump_dir);
    if (config->symbols) cfg.set("PCSX2HOOK_SYMBOLS", config->symbols);
    if (config->interpreter) cfg.set("PCSX2HOOK_INTERP", "1");
    if (!config->software_gs) cfg.set("PCSX2HOOK_NULLGS", "1");
    ctx->host.setCore(ctx->core);
    return ctx;
}

void pcsx2hook_destroy(pcsx2hook_ctx* ctx) {
    delete ctx;
}

int pcsx2hook_enable_trace(pcsx2hook_ctx* ctx, pcsx2hook_trace which) {
    if (!ctx) return 0;
    const char* name = traceVariable(which);
    if (!name) {
        ctx->error = "unknown trace";
        return 0;
    }
    Config::get().set(name, "1");
    return 1;
}

void pcsx2hook_early_init(pcsx2hook_ctx* ctx) {
    if (ctx) ctx->host.earlyInit();
}

int pcsx2hook_init(pcsx2hook_ctx* ctx, int argc, char** argv) {
    return ctx && ctx->host.init(argc, argv) ? 1 : 0;
}

int pcsx2hook_wants_window(pcsx2hook_ctx* ctx) {
    return ctx && ctx->host.windowRequested() ? 1 : 0;
}

int pcsx2hook_create_window(pcsx2hook_ctx* ctx) {
    return ctx && ctx->host.createWindow() ? 1 : 0;
}

void pcsx2hook_apply_settings(pcsx2hook_ctx* ctx) {
    if (ctx) ctx->host.applySettingsOverride();
}

int pcsx2hook_start(pcsx2hook_ctx* ctx) {
    if (!ctx) return 0;
    ctx->cpu = ctx->host.startCpuThread(ctx->exitCode);
    return 1;
}

int pcsx2hook_is_finished(pcsx2hook_ctx* ctx) {
    return ctx && ctx->host.emulationFinished() ? 1 : 0;
}

void pcsx2hook_pump_window(pcsx2hook_ctx* ctx, int forever) {
    if (ctx) ctx->host.pumpWindow(forever != 0);
}

void pcsx2hook_request_stop(pcsx2hook_ctx* ctx) {
    if (ctx) ctx->host.requestStop();
}

int pcsx2hook_join(pcsx2hook_ctx* ctx) {
    if (!ctx) return 1;
    if (ctx->cpu.joinable()) ctx->cpu.join();
    return ctx->exitCode.load();
}

void pcsx2hook_shutdown(pcsx2hook_ctx* ctx) {
    if (ctx) ctx->host.shutdown();
}

void pcsx2hook_set_pad_button(pcsx2hook_ctx* ctx, int bind, int pressed) {
    if (ctx) ctx->core.setPadButton(bind, pressed != 0);
}

void pcsx2hook_set_speed_limit(pcsx2hook_ctx* ctx, int enabled) {
    if (ctx) ctx->core.setSpeedLimit(enabled != 0);
}

void pcsx2hook_set_string_setting(pcsx2hook_ctx* ctx, const char* section, const char* key,
                          const char* value) {
    if (ctx && ctx->settings) ctx->settings->SetStringValue(section, key, value);
}

void pcsx2hook_set_bool_setting(pcsx2hook_ctx* ctx, const char* section, const char* key, int value) {
    if (ctx && ctx->settings) ctx->settings->SetBoolValue(section, key, value != 0);
}

void pcsx2hook_add_string_list_setting(pcsx2hook_ctx* ctx, const char* section, const char* key,
                               const char* value) {
    if (ctx && ctx->settings) ctx->settings->AddToStringList(section, key, value);
}

int pcsx2hook_add_hook(pcsx2hook_ctx* ctx, uint32_t addr, pcsx2hook_pre_fn pre,
                       pcsx2hook_post_fn post, void* user) {
    if (!ctx) return 0;
    s_handlers[addr] = HostHandler{pre, post, user};
    Hooks::Register(addr, pre ? &preThunk : nullptr, post ? &postThunk : nullptr);
    return 1;
}

void pcsx2hook_set_hook_observer(pcsx2hook_ctx* ctx, pcsx2hook_post_fn fn, void* user) {
    if (!ctx) return;
    s_observer = HostHandler{nullptr, fn, user};
    Hooks::SetObserver(fn ? &observerThunk : nullptr);
}

uint32_t pcsx2hook_call_ee(pcsx2hook_ctx* ctx, uint32_t pc, const uint32_t* args, size_t count) {
    if (!ctx) return 0;
    if (!args || count == 0) return Hooks::CallEE(pc, {}, {});
    switch (count) {
        case 1: return Hooks::CallEE(pc, {args[0]}, {});
        case 2: return Hooks::CallEE(pc, {args[0], args[1]}, {});
        case 3: return Hooks::CallEE(pc, {args[0], args[1], args[2]}, {});
        default: return Hooks::CallEE(pc, {args[0], args[1], args[2], args[3]}, {});
    }
}

void* pcsx2hook_map_guest(pcsx2hook_ctx* ctx, uint32_t addr, uint32_t size) {
    if (!ctx) return nullptr;
    if ((addr & 0x1FFFFFFFu) + size > Ps2MemSize::MainRam) return nullptr;
    return PSM(addr);
}

void* pcsx2hook_get_ram_base(pcsx2hook_ctx* ctx, uint32_t* size) {
    if (!ctx || !eeMem) return nullptr;
    if (size) *size = Ps2MemSize::MainRam;
    return eeMem->Main;
}

uint32_t pcsx2hook_get_ee_pc(pcsx2hook_ctx* ctx) {
    return ctx ? cpuRegs.pc : 0;
}

const char* pcsx2hook_get_disc_serial(pcsx2hook_ctx* ctx) {
    if (!ctx) return "";
    ctx->serial = ctx->core.getDiscSerial();
    return ctx->serial.c_str();
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

void pcsx2hook_run_on_gs_thread(pcsx2hook_ctx* ctx, pcsx2hook_void_fn fn, void* user) {
    if (!ctx || !fn) return;
    MTGS::RunOnGSThread([fn, user]() { fn(user); });
    MTGS::WaitGS(false, false, false);
}

// Asking for the size takes the snapshot and keeps it, so the fetch that follows returns that same
// frame rather than a second one taken a moment later.
size_t pcsx2hook_read_framebuffer(pcsx2hook_ctx* ctx, void* out, size_t size, uint32_t* width,
                                  uint32_t* height) {
    if (!ctx) return 0;
    if (ctx->frame.empty()) {
        uint32_t w = 0, h = 0;
        if (!MTGS::SaveMemorySnapshot(0, 0, false, false, &w, &h, &ctx->frame)) {
            ctx->error = "no frame buffer to read: the null renderer fills none";
            return 0;
        }
        ctx->frameWidth = w;
        ctx->frameHeight = h;
    }
    if (width) *width = ctx->frameWidth;
    if (height) *height = ctx->frameHeight;
    const size_t needed = ctx->frame.size() * sizeof(uint32_t);
    if (out && size >= needed) {
        std::memcpy(out, ctx->frame.data(), needed);
        ctx->frame.clear();
    }
    return needed;
}

size_t pcsx2hook_get_gs_rows(pcsx2hook_ctx* ctx, uint32_t frame, char* out, size_t size) {
    if (!ctx) return 0;
    const std::string rows = Diagnostics::get().getGsDraws().getRowsForFrame(frame);
    if (out && size >= rows.size() + 1) std::memcpy(out, rows.c_str(), rows.size() + 1);
    return rows.size() + 1;
}

void pcsx2hook_push_draw(pcsx2hook_ctx* ctx, const char* label, uint32_t object,
                         uint32_t pipeline) {
    if (!ctx) return;
    DrawContext c;
    if (label) {
        std::snprintf(c.label, sizeof(c.label), "%s", label);
    }
    c.object = object;
    c.pipeline = pipeline;
    Diagnostics::get().getDraws().push(c);
}

void pcsx2hook_pop_draw(pcsx2hook_ctx* ctx) {
    if (ctx) Diagnostics::get().getDraws().pop();
}

void pcsx2hook_set_config(pcsx2hook_ctx* ctx, const char* name, const char* value) {
    if (ctx && name && value) Config::get().set(name, value);
}

size_t pcsx2hook_resolve_symbol(pcsx2hook_ctx* ctx, uint32_t pc, char* out, size_t size) {
    if (!ctx) return 0;
    const std::string name = getSymbols().resolve(pc);
    if (out && size >= name.size() + 1) std::memcpy(out, name.c_str(), name.size() + 1);
    return name.size() + 1;
}

int pcsx2hook_is_in_code_range(pcsx2hook_ctx* ctx, uint32_t pc) {
    return ctx && getSymbols().isInCodeRange(pc) ? 1 : 0;
}

void pcsx2hook_load_symbols(pcsx2hook_ctx* ctx) {
    if (ctx) getSymbols().load();
}

void pcsx2hook_set_gs_recording(pcsx2hook_ctx* ctx, int on) {
    if (ctx) Diagnostics::get().getGsDraws().setRecording(on != 0);
}

void pcsx2hook_set_gs_deferred(pcsx2hook_ctx* ctx, int on) {
    if (ctx) Diagnostics::get().getGsDraws().setDeferred(on != 0);
}

void pcsx2hook_enable_gs_capture(pcsx2hook_ctx* ctx, int skip) {
    if (ctx) Diagnostics::get().getGsDraws().enableCapture(skip);
}

void pcsx2hook_mark_gs_capture_start(pcsx2hook_ctx* ctx) {
    if (ctx) Diagnostics::get().getGsDraws().markCaptureStart();
}

uint32_t pcsx2hook_get_gs_standalone_frames(pcsx2hook_ctx* ctx) {
    return ctx ? Diagnostics::get().getGsDraws().getStandaloneFrames() : 0;
}

void pcsx2hook_report_gs_tracker(pcsx2hook_ctx* ctx, const char* reason, const char* path) {
    if (!ctx) return;
    if (!path) {
        Diagnostics::get().getGsTracker().report(reason, stderr);
        return;
    }
    std::FILE* f = std::fopen(path, "ab");
    if (!f) {
        ctx->error = "cannot open the tracker report file";
        return;
    }
    Diagnostics::get().getGsTracker().report(reason, f);
    std::fclose(f);
}

size_t pcsx2hook_take_gs_capture(pcsx2hook_ctx* ctx, void* out, size_t size, uint32_t* width,
                                 uint32_t* height, uint32_t* frame) {
    if (!ctx) return 0;
    if (ctx->capture.empty()) {
        uint32_t w = 0, h = 0, f = 0;
        if (!Diagnostics::get().getGsDraws().takeCapture(ctx->capture, w, h, f)) return 0;
        ctx->captureWidth = w;
        ctx->captureHeight = h;
        ctx->captureFrame = f;
    }
    if (width) *width = ctx->captureWidth;
    if (height) *height = ctx->captureHeight;
    if (frame) *frame = ctx->captureFrame;
    const size_t needed = ctx->capture.size() * sizeof(uint32_t);
    if (out && size >= needed) {
        std::memcpy(out, ctx->capture.data(), needed);
        ctx->capture.clear();
    }
    return needed;
}

size_t pcsx2hook_write_gs_last_frame(pcsx2hook_ctx* ctx, const char* path) {
    if (!ctx || !path) return 0;
    std::FILE* f = std::fopen(path, "ab");
    if (!f) {
        ctx->error = "cannot open the GS row file";
        return 0;
    }
    const size_t n = Diagnostics::get().getGsDraws().writeLastFrame(f);
    std::fclose(f);
    return n;
}

void pcsx2hook_flush_traces(pcsx2hook_ctx* ctx) {
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

const char* pcsx2hook_get_last_error(pcsx2hook_ctx* ctx) {
    return ctx ? ctx->error.c_str() : "no context";
}

}  // extern "C"

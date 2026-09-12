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
#include "common/Console.h"
#include "common/Error.h"
#include "common/MemorySettingsInterface.h"
#include "pcsx2/Hooks.h"
#include "pcsx2/MTGS.h"
#include "GS/GSLocalMemory.h"
#include "GS/Renderers/Common/GSRenderer.h"
#include "pcsx2/R5900.h"
#include "pcsx2/Host.h"
#include "pcsx2/VMManager.h"
#include "fmt/format.h"

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
        case PCSX2HOOK_TRACE_TIMING: return "PCSX2HOOK_TIMING_TRACE";
        default: return nullptr;
    }
}

}  // namespace

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
    if (!ctx) return;
    if (ctx->cpu.joinable()) {
        ctx->host.requestStop();
        ctx->cpu.join();
    }
    ctx->host.clearCore(ctx->core);
    delete ctx;
}

int pcsx2hook_enable_trace(pcsx2hook_ctx* ctx, pcsx2hook_trace which) {
    if (!ctx) return 0;
    const char* name = traceVariable(which);
    if (!name) {
        ctx->error = "unknown trace";
        return 0;
    }
    // Several traces take a path in the same variable that switches them on, so a caller that has
    // already given one must not have it replaced by a bare flag.
    if (!Config::get().getValue(name)) {
        Config::get().set(name, "1");
    }
    return 1;
}

namespace {
void setOrUnset(const char* name, bool on, const char* value = "1") {
    if (on)
        Config::get().set(name, value);
    else
        Config::get().unset(name);
}
}  // namespace

void pcsx2hook_set_interpreter(pcsx2hook_ctx* ctx, unsigned cpus) {
    if (!ctx) return;
    setOrUnset("PCSX2HOOK_EE_INTERP", cpus & PCSX2HOOK_CPU_EE);
    setOrUnset("PCSX2HOOK_IOP_INTERP", cpus & PCSX2HOOK_CPU_IOP);
    setOrUnset("PCSX2HOOK_VU0_INTERP", cpus & PCSX2HOOK_CPU_VU0);
    setOrUnset("PCSX2HOOK_VU1_INTERP", cpus & PCSX2HOOK_CPU_VU1);
}

void pcsx2hook_set_accurate_timing(pcsx2hook_ctx* ctx, int enabled) {
    if (ctx) setOrUnset("PCSX2HOOK_TIMING", enabled != 0, "accurate");
}

void pcsx2hook_set_boot_state(pcsx2hook_ctx* ctx, const char* path) {
    if (ctx) setOrUnset("PCSX2HOOK_STATE", path && *path, path);
}

void pcsx2hook_set_frame_limit(pcsx2hook_ctx* ctx, uint32_t frames) {
    if (ctx) setOrUnset("PCSX2HOOK_FRAMES", frames != 0, std::to_string(frames).c_str());
}

void pcsx2hook_early_init(pcsx2hook_ctx* ctx) {
    if (ctx) ctx->host.earlyInit();
}

int pcsx2hook_init(pcsx2hook_ctx* ctx, int argc, char** argv) {
    if (!ctx) return 0;
    if (ctx->host.init(argc, argv)) return 1;
    // The host prints the detail to the log; a caller only asking last_error should still get told
    // something rather than an empty string.
    ctx->error = "init failed: no image, or the emulator could not configure itself";
    return 0;
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

// A call in flight holds the sentinel in $ra, and no savestate carries the host stack with the real
// one. Retried rather than refused: each drain runs the guest a slice further, so the call returns.
static void saveWhenNothingIsInFlight(const std::string& target, int attempt) {
    static const int kMaxAttempts = 64;
    if (Hooks::PendingReturns() != 0) {
        if (attempt >= kMaxAttempts) {
            Console.Error(fmt::format("pcsx2hook: {} hooked calls are still in flight after {} "
                                      "attempts; not writing {}, it could not be resumed",
                                      Hooks::PendingReturns(), attempt, target));
            return;
        }
        Host::RunOnCPUThread(
            [target, attempt]() { saveWhenNothingIsInFlight(target, attempt + 1); }, false);
        return;
    }
    if (attempt != 0)
        Console.WriteLn(fmt::format("pcsx2hook: {} waited {} VM slices for hooked calls to return",
                                    target, attempt));
    VMManager::SaveState(target.c_str(), false, false, {});
}

int pcsx2hook_save_state(pcsx2hook_ctx* ctx, const char* path) {
    if (!ctx || !path) return 0;
    // Through the CPU thread's queue, which is where the emulator runs its own save hotkey: taken
    // from inside a frame callback the VM is mid-block, and the state it writes cannot be resumed.
    const std::string target = path;
    Host::RunOnCPUThread([target]() { saveWhenNothingIsInFlight(target, 0); }, true);
    return 1;
}

void pcsx2hook_run_on_gs_thread(pcsx2hook_ctx* ctx, pcsx2hook_void_fn fn, void* user) {
    if (!ctx || !fn) return;
    MTGS::RunOnGSThread([fn, user]() { fn(user); });
    MTGS::WaitGS(false, false, false);
}

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

size_t pcsx2hook_read_gs_pixels(pcsx2hook_ctx* ctx, uint32_t tbp0, uint32_t tbw, uint32_t psm,
                                uint32_t width, uint32_t height, uint32_t* out, size_t count) {
    if (!ctx || psm >= 64) return 0;

    const size_t needed = size_t(width) * height;
    if (!out || count < needed) return needed;

    // Per-texel through the format's own reader, the way GSLocalMemory::SaveBMP does: it takes no
    // CLUT and leaves no state behind, so the emulated draws after this see what they did before.
    bool ok = false;
    MTGS::RunOnGSThread([&]() {
        if (!g_gs_renderer) return;
        GSLocalMemory& mem = g_gs_renderer->m_mem;
        const GSLocalMemory::readPixel read = GSLocalMemory::m_psm[psm].rp;
        for (uint32_t y = 0; y < height; y++) {
            for (uint32_t x = 0; x < width; x++) {
                out[size_t(y) * width + x] = (mem.*read)(int(x), int(y), tbp0, tbw);
            }
        }
        ok = true;
    });
    MTGS::WaitGS(false, false, false);
    if (!ok) {
        ctx->error = "no GS renderer to read from";
        return 0;
    }
    return needed;
}

size_t pcsx2hook_get_gs_rows(pcsx2hook_ctx* ctx, uint32_t frame, char* out, size_t size) {
    if (!ctx) return 0;
    const std::string rows = Diagnostics::get().getGsDraws().getRowsForFrame(frame);
    if (out && size >= rows.size() + 1) std::memcpy(out, rows.c_str(), rows.size() + 1);
    return rows.size() + 1;
}

namespace {

uint32_t png_crc32(const uint8_t* data, size_t length, uint32_t crc = 0) {
    static uint32_t table[256];
    static bool built = false;
    if (!built) {
        for (uint32_t i = 0; i < 256; i++) {
            uint32_t c = i;
            for (int k = 0; k < 8; k++) c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
            table[i] = c;
        }
        built = true;
    }
    crc = ~crc;
    for (size_t i = 0; i < length; i++) crc = table[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
    return ~crc;
}

void putBe32(std::vector<uint8_t>& out, uint32_t v) {
    out.push_back(uint8_t(v >> 24));
    out.push_back(uint8_t(v >> 16));
    out.push_back(uint8_t(v >> 8));
    out.push_back(uint8_t(v));
}

void putChunk(std::FILE* f, const char tag[4], const std::vector<uint8_t>& body) {
    std::vector<uint8_t> framed;
    putBe32(framed, uint32_t(body.size()));
    framed.insert(framed.end(), tag, tag + 4);
    framed.insert(framed.end(), body.begin(), body.end());
    const uint32_t crc = png_crc32(framed.data() + 4, framed.size() - 4);
    putBe32(framed, crc);
    std::fwrite(framed.data(), 1, framed.size(), f);
}

/// A zlib stream of stored blocks, which is a valid deflate stream that compresses nothing.
void putIdat(std::FILE* f, const std::vector<uint8_t>& raw) {
    std::vector<uint8_t> z{0x78, 0x01};
    uint32_t a = 1;
    uint32_t b = 0;
    for (uint8_t byte : raw) {
        a = (a + byte) % 65521;
        b = (b + a) % 65521;
    }
    for (size_t at = 0; at < raw.size() || raw.empty(); ) {
        const size_t left = raw.size() - at;
        const uint16_t block = uint16_t(left > 65535 ? 65535 : left);
        z.push_back(uint8_t(block == left ? 1 : 0));
        z.push_back(uint8_t(block & 0xFF));
        z.push_back(uint8_t(block >> 8));
        z.push_back(uint8_t(~block & 0xFF));
        z.push_back(uint8_t((~block >> 8) & 0xFF));
        z.insert(z.end(), raw.begin() + long(at), raw.begin() + long(at + block));
        at += block;
        if (at >= raw.size()) break;
    }
    putBe32(z, (b << 16) | a);
    putChunk(f, "IDAT", z);
}

void writePng(std::FILE* f, uint32_t width, uint32_t height, const std::vector<uint8_t>& raw) {
    static const uint8_t signature[8] = {0x89, 'P', 'N', 'G', '\r', '\n', 0x1A, '\n'};
    std::fwrite(signature, 1, sizeof(signature), f);

    std::vector<uint8_t> ihdr;
    putBe32(ihdr, width);
    putBe32(ihdr, height);
    ihdr.push_back(8);  // bit depth
    ihdr.push_back(2);  // truecolour
    ihdr.push_back(0);
    ihdr.push_back(0);
    ihdr.push_back(0);
    putChunk(f, "IHDR", ihdr);

    putIdat(f, raw);
    putChunk(f, "IEND", {});
}

}  // namespace

int pcsx2hook_write_framebuffer(pcsx2hook_ctx* ctx, const char* path) {
    if (!ctx || !path) return 0;
    uint32_t width = 0;
    uint32_t height = 0;
    const size_t needed = pcsx2hook_read_framebuffer(ctx, nullptr, 0, &width, &height);
    if (needed == 0 || width == 0 || height == 0) {
        ctx->error = "no frame buffer to read";
        return 0;
    }
    std::vector<uint32_t> pixels(needed / sizeof(uint32_t));
    if (pcsx2hook_read_framebuffer(ctx, pixels.data(), needed, &width, &height) != needed) {
        ctx->error = "the frame buffer changed size between the size query and the read";
        return 0;
    }
    std::FILE* f = std::fopen(path, "wb");
    if (!f) {
        ctx->error = "cannot open the frame buffer file";
        return 0;
    }
    // Uncompressed PNG: stored deflate blocks need no compression library, so the runner gains a
    // format every viewer opens without the API gaining a dependency.
    std::vector<uint8_t> raw;
    raw.reserve(size_t(height) * (1 + size_t(width) * 3));
    for (uint32_t y = 0; y < height; y++) {
        raw.push_back(0);  // filter: none
        for (uint32_t x = 0; x < width; x++) {
            const uint32_t pixel = pixels[size_t(y) * width + x];
            raw.push_back(uint8_t(pixel & 0xFF));
            raw.push_back(uint8_t((pixel >> 8) & 0xFF));
            raw.push_back(uint8_t((pixel >> 16) & 0xFF));
        }
    }
    writePng(f, width, height, raw);
    std::fclose(f);
    return 1;
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

uint32_t pcsx2hook_find_symbol(pcsx2hook_ctx* ctx, const char* name) {
    if (!ctx || !name) return 0;
    getSymbols().load();
    return getSymbols().find(name);
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

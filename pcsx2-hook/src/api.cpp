// SPDX-FileCopyrightText: 2002-2026 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#include "pcsx2hook/pcsx2hook.h"

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <mutex>
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
#include "pcsx2/VU.h"
#include "pcsx2/VUmicro.h"
#include "pcsx2/Host.h"
#include "pcsx2/VMManager.h"
#include "fmt/format.h"

#include "config.h"
#include "core.h"
#include "diagnostics.h"
#include "trace/draw_context.h"
#include "host.h"
#include "trace/gs_stream.h"
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

namespace {
struct WriteSink {
    pcsx2hook_write_fn fn;
    void* user;
    uint32_t lo, hi;
};
WriteSink s_writeSink;

void writeSinkTrampoline(u32 addr, u64 value, u32 size, bool isRead) {
    const WriteSink s = s_writeSink;
    if (isRead || !s.fn || addr < s.lo || addr >= s.hi) return;
    s.fn(addr, size, value, cpuRegs.pc - 4, s.user);
}
}  // namespace

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
    setOrUnset("PCSX2HOOK_EE_INTERP", (cpus & PCSX2HOOK_CPU_EE) || s_writeSink.fn);
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

void pcsx2hook_set_boot_elf(pcsx2hook_ctx* ctx, const char* path) {
    if (ctx) setOrUnset("PCSX2HOOK_ELF", path && *path, path);
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

int pcsx2hook_call_ee_ex(pcsx2hook_ctx* ctx, uint32_t pc, const uint32_t* args, size_t count,
                         const uint32_t* fargBits, size_t fcount, uint32_t* v0, uint32_t* f0Bits) {
    if (!ctx) return 0;
    if (count > 8 || fcount > 8 || (count && !args) || (fcount && !fargBits)) {
        ctx->error = "pcsx2hook_call_ee_ex: at most eight integer and eight float arguments";
        return 0;
    }
    if (!Hooks::HasCallMarker()) {
        ctx->error = "pcsx2hook_call_ee_ex: the call marker is not set up, call from on_vm_ready on";
        return 0;
    }
    const uint32_t ret = Hooks::CallEERaw(pc, args, static_cast<int>(count), fargBits,
                                          static_cast<int>(fcount), f0Bits);
    if (v0) *v0 = ret;
    return 1;
}

uint32_t pcsx2hook_call_ee(pcsx2hook_ctx* ctx, uint32_t pc, const uint32_t* args, size_t count) {
    uint32_t v0 = 0;
    return pcsx2hook_call_ee_ex(ctx, pc, args, count, nullptr, 0, &v0, nullptr) ? v0 : 0;
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

size_t pcsx2hook_read_scratchpad(pcsx2hook_ctx* ctx, void* out, size_t size) {
    if (!ctx || !eeMem || !out) return 0;
    const size_t n = size < Ps2MemSize::Scratch ? size : Ps2MemSize::Scratch;
    std::memcpy(out, eeMem->Scratch, n);
    return n;
}

size_t pcsx2hook_read_vu_memory(pcsx2hook_ctx* ctx, int unit, void* out, size_t size) {
    if (!ctx || !out || (unit != 0 && unit != 1) || !vuRegs[unit].Mem) return 0;
    const size_t have = unit == 0 ? VU0_MEMSIZE : VU1_MEMSIZE;
    const size_t n = size < have ? size : have;
    std::memcpy(out, vuRegs[unit].Mem, n);
    return n;
}

int pcsx2hook_read_vu_regs(pcsx2hook_ctx* ctx, int unit, pcsx2hook_vu_regs* out) {
    if (!ctx || !out || (unit != 0 && unit != 1)) return 0;
    const VURegs& v = vuRegs[unit];
    for (int i = 0; i < 32; i++) {
        std::memcpy(out->vf[i], &v.VF[i], 16);
        out->vi[i] = v.VI[i].UL;
    }
    std::memcpy(out->acc, &v.ACC, 16);
    out->q = v.q.UL;
    out->p = v.p.UL;
    return 1;
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
// one. So the save waits for the moment the last pending return is taken, when Hooks ends the slice.
static void saveWhenNothingIsInFlight(const std::string& target, int attempt) {
    static const int kMaxAttempts = 64;
    if (Hooks::PendingReturns() != 0) {
        if (attempt == 0)
            Console.WriteLn(fmt::format("pcsx2hook: {} waits for {} hooked calls to return", target,
                                        Hooks::PendingReturns()));
        if (attempt >= kMaxAttempts) {
            Console.Error(fmt::format("pcsx2hook: {} hooked calls are still in flight after {} "
                                      "attempts; not writing {}, it could not be resumed",
                                      Hooks::PendingReturns(), attempt, target));
            return;
        }
        pcsx2hook::queueOnCpuThread(
            [target, attempt]() { saveWhenNothingIsInFlight(target, attempt + 1); });
        Hooks::PauseWhenNoReturnsPending();
        return;
    }
    VMManager::SaveState(target.c_str(), false, false, [target](const std::string& error) {
        Console.Error(fmt::format("pcsx2hook: writing {} failed: {}", target, error));
    });
    Console.WriteLn(fmt::format("pcsx2hook: saved {} after {} waits", target, attempt));
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

size_t pcsx2hook_read_gs_memory(pcsx2hook_ctx* ctx, void* out, size_t size) {
    if (!ctx) return 0;
    const size_t needed = size_t(GSLocalMemory::m_vmsize);
    if (!out || size < needed) return needed;

    bool ok = false;
    MTGS::RunOnGSThread([&]() {
        if (!g_gs_renderer) return;
        std::memcpy(out, g_gs_renderer->m_mem.vm8(), needed);
        ok = true;
    });
    MTGS::WaitGS(false, false, false);
    if (!ok) {
        ctx->error = "no GS renderer to read from";
        return 0;
    }
    return needed;
}

size_t pcsx2hook_read_gs_registers(pcsx2hook_ctx* ctx, void* out, size_t size) {
    if (!ctx) return 0;
    /* The draw environment, by GS register number. Per context registers are the pair, so the
     * context register number is the first plus the context index. */
    static const uint32_t kGlobal[] = {0x00, 0x1A, 0x1B, 0x1C, 0x22, 0x3B,
                                       0x3D, 0x44, 0x45, 0x46, 0x49};
    static const uint32_t kPerContext[] = {0x06, 0x08, 0x14, 0x18, 0x34, 0x36,
                                           0x40, 0x42, 0x47, 0x4A, 0x4C, 0x4E};
    const size_t count = std::size(kGlobal) + 2 * std::size(kPerContext);
    const size_t needed = count * 16;
    if (!out || size < needed) return needed;

    bool ok = false;
    MTGS::RunOnGSThread([&]() {
        if (!g_gs_renderer) return;
        const GSDrawingEnvironment& env = g_gs_renderer->m_env;
        uint64_t values[0x50] = {};
        values[0x00] = env.PRIM.U64;
        values[0x1A] = env.PRMODECONT.U64;
        values[0x1B] = env.PRMODE.U64;
        values[0x1C] = env.TEXCLUT.U64;
        values[0x22] = env.SCANMSK.U64;
        values[0x3B] = env.TEXA.U64;
        values[0x3D] = env.FOGCOL.U64;
        values[0x44] = env.DIMX.U64;
        values[0x45] = env.DTHE.U64;
        values[0x46] = env.COLCLAMP.U64;
        values[0x49] = env.PABE.U64;
        for (uint32_t i = 0; i < 2; i++) {
            const GSDrawingContext& c = env.CTXT[i];
            values[0x06 + i] = c.TEX0.U64;
            values[0x08 + i] = c.CLAMP.U64;
            values[0x14 + i] = c.TEX1.U64;
            values[0x18 + i] = c.XYOFFSET.U64;
            values[0x34 + i] = c.MIPTBP1.U64;
            values[0x36 + i] = c.MIPTBP2.U64;
            values[0x40 + i] = c.SCISSOR.U64;
            values[0x42 + i] = c.ALPHA.U64;
            values[0x47 + i] = c.TEST.U64;
            values[0x4A + i] = c.FBA.U64;
            values[0x4C + i] = c.FRAME.U64;
            values[0x4E + i] = c.ZBUF.U64;
        }
        uint64_t* write = static_cast<uint64_t*>(out);
        for (uint32_t reg = 0; reg < 0x50; reg++) {
            bool wanted = false;
            for (const uint32_t at : kGlobal) wanted = wanted || at == reg;
            for (const uint32_t at : kPerContext)
                wanted = wanted || at == reg || at + 1 == reg;
            if (!wanted) continue;
            *write++ = values[reg];
            *write++ = reg;
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

int pcsx2hook_read_gs_display(pcsx2hook_ctx* ctx, pcsx2hook_gs_display* out) {
    if (!ctx || !out) return 0;

    bool ok = false;
    pcsx2hook_gs_display got{};
    MTGS::RunOnGSThread([&]() {
        if (!g_gs_renderer || !g_gs_renderer->m_regs) return;
        const GSPrivRegSet& regs = *g_gs_renderer->m_regs;
        // The second circuit first, which is the one a game that uses only one enables.
        for (int circuit = 1; circuit >= 0; circuit--) {
            const bool enabled = circuit == 0 ? regs.PMODE.EN1 != 0 : regs.PMODE.EN2 != 0;
            if (!enabled) continue;
            const GSRegDISPLAY& display = regs.DISP[circuit].DISPLAY;
            if (display.DW == 0 || display.DH == 0) continue;
            const GSRegDISPFB& buffer = regs.DISP[circuit].DISPFB;
            got.circuit = uint32_t(circuit);
            got.block = buffer.Block();
            got.fbw = buffer.FBW;
            got.psm = buffer.PSM;
            got.dbx = buffer.DBX;
            got.dby = buffer.DBY;
            got.magh = display.MAGH;
            got.magv = display.MAGV;
            got.dx = display.DX;
            got.dy = display.DY;
            got.dw = display.DW;
            got.dh = display.DH;
            got.interlace = regs.SMODE2.INT;
            got.ffmd = regs.SMODE2.FFMD;
            got.field = regs.CSR.rFIELD;
            got.width = uint32_t((display.DW + 1) / (display.MAGH + 1));
            got.height = uint32_t((display.DH + 1) / (display.MAGV + 1));
            ok = true;
            break;
        }
    });
    MTGS::WaitGS(false, false, false);
    if (!ok) {
        ctx->error = "no display circuit is reading a frame buffer";
        return 0;
    }
    *out = got;
    return 1;
}

/* The alpha byte is the one GS memory holds, in the GS's own units where 128 is opaque: a
 * destination alpha test reads it, so forcing it opaque would hide the test's input. The 24 and 16
 * bit readers supply the alpha their format does not store, 128 and the 1 bit value scaled, which
 * is what the GS itself reads. Runs on the GS thread, wherever it is called from.
 *
 * C linkage, like everything else in this block, so the name carries the prefix a namespace would
 * have given it. */
void pcsx2hookReadGsFrameHere(uint32_t block, uint32_t fbw, uint32_t psm, uint32_t x, uint32_t y,
                     uint32_t width, uint32_t height, uint32_t* out) {
    const GSLocalMemory& mem = g_gs_renderer->m_mem;
    for (uint32_t row = 0; row < height; row++) {
        const int line = int(y + row);
        for (uint32_t column = 0; column < width; column++) {
            const int at = int(x + column);
            uint32_t pixel;
            switch (psm) {
                case PSMCT24: pixel = mem.ReadFrame24(at, line, block, fbw); break;
                case PSMCT16: pixel = mem.ReadFrame16(at, line, block, fbw); break;
                case PSMCT16S: pixel = mem.ReadFrame16S(at, line, block, fbw); break;
                default: pixel = mem.ReadPixel32(at, line, block, fbw); break;
            }
            out[size_t(row) * width + column] = pixel;
        }
    }
}

size_t pcsx2hook_read_gs_frame(pcsx2hook_ctx* ctx, uint32_t block, uint32_t fbw, uint32_t psm,
                               uint32_t x, uint32_t y, uint32_t width, uint32_t height,
                               uint32_t* out, size_t count) {
    if (!ctx) return 0;

    const size_t needed = size_t(width) * height;
    if (!out || count < needed) return needed;

    bool ok = false;
    MTGS::RunOnGSThread([&]() {
        if (!g_gs_renderer) return;
        pcsx2hookReadGsFrameHere(block, fbw, psm, x, y, width, height, out);
        ok = true;
    });
    MTGS::WaitGS(false, false, false);
    if (!ok) {
        ctx->error = "no GS renderer to read from";
        return 0;
    }
    return needed;
}

namespace {

/* The draw target after one named batch of a chain, which no reader at a frame boundary can hold:
 * a later batch of the same chain writes over what the question is about. The bursts come from
 * PCSX2HOOK_GS_SNAP_AT and each is taken once. */
struct GsSnap {
    /* The host arms a frame's batches at its kick, on the EE thread, while the GS thread is still
     * drawing the chain before it, so the two lists are locked. The pixel buffer is not: only the
     * sink touches it. */
    std::mutex lock;
    std::vector<uint64_t> wanted;
    std::vector<uint8_t> taken;
    std::atomic<void (*)(const pcsx2hook_gs_snap*, void*)> sink{nullptr};
    void* user = nullptr;
    std::vector<uint32_t> pixels;
};

GsSnap s_snap;

/* The drawn field: the display's own width, and half its height when the read circuit is in field
 * mode, which is what says a buffer holds one field rather than a whole frame.
 *
 * Not the distance between the drawn base and the displayed one, which is how the frame reader at a
 * vsync tells a field pair from a single buffer: mid-chain DISPFB has not flipped yet and can still
 * name the buffer being drawn into, and the read then takes the field below it as well. Measured on
 * frame 0 of SMT3's opening field, where it read 448 rows of a 224 row target and the lower half
 * held the other buffer. SMODE2 is a mode register and does not move inside a frame. */
void snapGeometry(uint32_t block, uint32_t psm, uint32_t* width, uint32_t* height,
                  uint32_t* field) {
    (void)block;
    (void)psm;
    *width = 0;
    *height = 0;
    *field = 0;
    if (!g_gs_renderer || !g_gs_renderer->m_regs) return;
    const GSPrivRegSet& regs = *g_gs_renderer->m_regs;
    *field = regs.CSR.rFIELD;
    for (int circuit = 1; circuit >= 0; circuit--) {
        const bool enabled = circuit == 0 ? regs.PMODE.EN1 != 0 : regs.PMODE.EN2 != 0;
        if (!enabled) continue;
        const GSRegDISPLAY& display = regs.DISP[circuit].DISPLAY;
        if (display.DW == 0 || display.DH == 0) continue;
        const uint32_t shownWidth = uint32_t((display.DW + 1) / (display.MAGH + 1));
        const uint32_t shownHeight = uint32_t((display.DH + 1) / (display.MAGV + 1));
        const bool oneField = regs.SMODE2.INT != 0 && regs.SMODE2.FFMD != 0;
        *width = shownWidth;
        *height = oneField ? shownHeight / 2 : shownHeight;
        return;
    }
}

void gsDrawDoneSink(const Hooks::GsDrawDone& done) {
    void (*sink)(const pcsx2hook_gs_snap*, void*) = s_snap.sink.load(std::memory_order_acquire);
    if (!sink || done.burst < 0) return;
    size_t which = 0;
    {
        const std::lock_guard<std::mutex> held(s_snap.lock);
        which = s_snap.wanted.size();
        for (size_t i = 0; i < s_snap.wanted.size(); i++) {
            if (s_snap.wanted[i] == uint64_t(done.burst) && !s_snap.taken[i]) which = i;
        }
        if (which == s_snap.wanted.size()) return;
        /* Claimed under the lock, so one batch is taken once even if the burst names several. */
        s_snap.taken[which] = 1;
    }

    const uint32_t block = uint32_t(done.frame & 0x1FF) * 32;
    const uint32_t fbw = uint32_t((done.frame >> 16) & 0x3F);
    const uint32_t psm = uint32_t((done.frame >> 24) & 0x3F);
    uint32_t width = 0;
    uint32_t height = 0;
    uint32_t field = 0;
    snapGeometry(block, psm, &width, &height, &field);
    if (!fbw || !width || !height) {
        std::fprintf(stderr, "[gssnap] burst %lld: FRAME %016llX against a %ux%u display\n",
                     (long long)done.burst, (unsigned long long)done.frame, width, height);
        return;
    }
    // The software rasteriser draws on worker threads, so the batch is not in memory until this.
    if (done.syncPixels) done.syncPixels(done.readCtx);

    s_snap.pixels.resize(size_t(width) * height);
    pcsx2hookReadGsFrameHere(block, fbw, psm, 0, 0, width, height, s_snap.pixels.data());

    pcsx2hook_gs_snap out{};
    out.burst = uint64_t(done.burst);
    out.block = block;
    out.fbw = fbw;
    out.psm = psm;
    out.width = width;
    out.height = height;
    out.field = field;
    out.skipped = done.skipped;
    out.pixels = s_snap.pixels.data();
    sink(&out, s_snap.user);
}

}  // namespace

void pcsx2hookInstallGsSnap() {
    const char* at = Config::get().getValue("PCSX2HOOK_GS_SNAP_AT");
    if (!at || !*at) return;
    std::vector<uint64_t> bursts;
    for (const char* walk = at; *walk;) {
        bursts.push_back(std::strtoull(walk, nullptr, 10));
        const char* comma = std::strchr(walk, ',');
        walk = comma ? comma + 1 : walk + std::strlen(walk);
    }
    pcsx2hook_arm_gs_snap(nullptr, bursts.data(), bursts.size());
}

void pcsx2hook_arm_gs_snap(pcsx2hook_ctx* ctx, const uint64_t* bursts, size_t count) {
    (void)ctx;
    if (!bursts || !count) return;
    {
        const std::lock_guard<std::mutex> held(s_snap.lock);
        for (size_t i = 0; i < count; i++) {
            s_snap.wanted.push_back(bursts[i]);
            s_snap.taken.push_back(0);
            std::fprintf(stderr, "[gssnap] snapshot after the batch of burst %llu\n",
                         (unsigned long long)bursts[i]);
        }
    }
    Hooks::SetGsDrawDoneSink(&gsDrawDoneSink);
}

void pcsx2hook_set_gs_snap_sink(pcsx2hook_ctx* ctx,
                                void (*sink)(const pcsx2hook_gs_snap* snap, void* user),
                                void* user) {
    if (!ctx) return;
    s_snap.user = user;
    s_snap.sink.store(sink, std::memory_order_release);
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

void writePng(std::FILE* f, uint32_t width, uint32_t height, const std::vector<uint8_t>& raw,
              uint8_t colour = 2) {
    static const uint8_t signature[8] = {0x89, 'P', 'N', 'G', '\r', '\n', 0x1A, '\n'};
    std::fwrite(signature, 1, sizeof(signature), f);

    std::vector<uint8_t> ihdr;
    putBe32(ihdr, width);
    putBe32(ihdr, height);
    ihdr.push_back(8);  // bit depth
    ihdr.push_back(colour);  // 2 truecolour, 0 greyscale
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
    return pcsx2hook_write_png(ctx, path, pixels.data(), width, height);
}

int pcsx2hook_capture_frame(pcsx2hook_ctx* ctx, const char* directory) {
    if (!ctx) return 0;
    if (!directory || !*directory) {
        directory = Config::get().getValue("PCSX2HOOK_DUMP_DIR");
        if (!directory || !*directory) directory = "experiments/dumps";
    }
    const std::filesystem::path dir(directory);
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);
    if (ec) {
        ctx->error = "cannot create capture directory: " + ec.message();
        return 0;
    }
    if (!pcsx2hook_write_framebuffer(ctx, (dir / "display.png").string().c_str())) return 0;
    pcsx2hook_gs_display shown{};
    if (!pcsx2hook_read_gs_display(ctx, &shown)) return 0;
    std::vector<uint8_t> regs(pcsx2hook_read_gs_registers(ctx, nullptr, 0));
    if (regs.empty() || pcsx2hook_read_gs_registers(ctx, regs.data(), regs.size()) != regs.size()) {
        ctx->error = "cannot read drawing registers";
        return 0;
    }
    uint64_t frame[2] = {};
    bool found[2] = {};
    for (size_t at = 0; at + 16 <= regs.size(); at += 16) {
        uint64_t value, reg;
        std::memcpy(&value, regs.data() + at, 8);
        std::memcpy(&reg, regs.data() + at + 8, 8);
        if (reg == 0x4C || reg == 0x4D) {
            frame[reg - 0x4C] = value;
            found[reg - 0x4C] = true;
        }
    }
    if (!found[0] || !found[1] || frame[0] != frame[1]) {
        ctx->error = "capture requires matching FRAME_1 and FRAME_2 targets";
        return 0;
    }
    const uint32_t block = uint32_t(frame[0] & 0x1FF) * 32;
    const uint32_t fbw = uint32_t((frame[0] >> 16) & 0x3F);
    const uint32_t psm = uint32_t((frame[0] >> 24) & 0x3F);
    if (!fbw || !shown.width || !shown.height) {
        ctx->error = "invalid frame buffer or display dimensions";
        return 0;
    }
    switch (psm) {
        case PSMCT32: case PSMCT24: case PSMCT16: case PSMCT16S: break;
        default: ctx->error = "unsupported capture frame buffer format"; return 0;
    }
    // Match sdfport's corpus: magnify the drawn field, not the display's two-field weave.
    const uint32_t bytes = (psm == PSMCT16 || psm == PSMCT16S) ? 2 : 4;
    const uint32_t field = shown.width * (shown.height / 2) * bytes;
    const uint32_t apart = (block > shown.block ? block - shown.block : shown.block - block) * 256;
    const uint32_t rows = apart == field ? shown.height / 2 : shown.height;
    if (!rows) {
        ctx->error = "empty capture field";
        return 0;
    }
    const uint32_t magnify = shown.height / rows;
    const uint32_t phase = magnify == 2 && shown.interlace && shown.ffmd ? shown.field : 0;
    std::vector<uint32_t> pixels(size_t(shown.width) * rows);
    if (pcsx2hook_read_gs_frame(ctx, block, fbw, psm, 0, 0, shown.width, rows,
                              pixels.data(), pixels.size()) != pixels.size()) return 0;
    std::vector<uint32_t> framed(size_t(shown.width) * rows * magnify);
    for (uint32_t host = 0; host < rows * magnify; host++) {
        const int32_t from = int32_t(host) - int32_t(phase);
        const uint32_t row = from <= 0 ? 0 : uint32_t(from) / magnify;
        std::memcpy(framed.data() + size_t(host) * shown.width,
                    pixels.data() + size_t(row) * shown.width, size_t(shown.width) * 4);
    }
    if (!pcsx2hook_write_png(ctx, (dir / "frame.png").string().c_str(), framed.data(),
                             shown.width, rows * magnify)) return 0;
    std::vector<uint8_t> alpha(framed.size());
    for (size_t at = 0; at < framed.size(); at++) alpha[at] = uint8_t(framed[at] >> 24);
    return pcsx2hook_write_png_gray(ctx, (dir / "alpha.png").string().c_str(), alpha.data(),
                                    shown.width, rows * magnify);
}

int pcsx2hook_write_png(pcsx2hook_ctx* ctx, const char* path, const uint32_t* pixels,
                        uint32_t width, uint32_t height) {
    if (!ctx || !path || !pixels || width == 0 || height == 0) return 0;
    std::FILE* f = std::fopen(path, "wb");
    if (!f) {
        ctx->error = "cannot open the picture file";
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

int pcsx2hook_write_png_gray(pcsx2hook_ctx* ctx, const char* path, const uint8_t* values,
                             uint32_t width, uint32_t height) {
    if (!ctx || !path || !values || width == 0 || height == 0) return 0;
    std::FILE* f = std::fopen(path, "wb");
    if (!f) {
        ctx->error = "cannot open the picture file";
        return 0;
    }
    std::vector<uint8_t> raw;
    raw.reserve(size_t(height) * (1 + size_t(width)));
    for (uint32_t y = 0; y < height; y++) {
        raw.push_back(0);  // filter: none
        raw.insert(raw.end(), values + size_t(y) * width, values + size_t(y + 1) * width);
    }
    writePng(f, width, height, raw, 0);
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

namespace {
pcsx2hook_dma_kick_fn s_dmaKickFn = nullptr;
void* s_dmaKickUser = nullptr;

void dmaKickTrampoline(u32 chan, u32 eepc, u32 madr, u32 qwc) {
    if (s_dmaKickFn) s_dmaKickFn(chan, eepc, madr, qwc, s_dmaKickUser);
}
}  // namespace

void pcsx2hook_set_dma_kick_sink(pcsx2hook_ctx* ctx, pcsx2hook_dma_kick_fn fn, void* user) {
    if (!ctx) return;
    s_dmaKickFn = fn;
    s_dmaKickUser = user;
    Hooks::AddDmaKickSink(&dmaKickTrampoline);
}

int pcsx2hook_get_round_mode(pcsx2hook_ctx* ctx, const char* which) {
    if (!ctx || !which) return -1;
    if (std::strcmp(which, "ee") == 0) return static_cast<int>(EmuConfig.Cpu.FPUFPCR.GetRoundMode());
    if (std::strcmp(which, "eediv") == 0) return static_cast<int>(EmuConfig.Cpu.FPUDivFPCR.GetRoundMode());
    if (std::strcmp(which, "vu0") == 0) return static_cast<int>(EmuConfig.Cpu.VU0FPCR.GetRoundMode());
    if (std::strcmp(which, "vu1") == 0) return static_cast<int>(EmuConfig.Cpu.VU1FPCR.GetRoundMode());
    return -1;
}

int pcsx2hook_get_clamp_mode(pcsx2hook_ctx* ctx, const char* which) {
    if (!ctx || !which) return -1;
    const auto& r = EmuConfig.Cpu.Recompiler;
    if (std::strcmp(which, "ee") == 0)
        return r.fpuOverflow | (r.fpuExtraOverflow << 1) | (r.fpuFullMode << 2);
    if (std::strcmp(which, "vu0") == 0)
        return r.vu0Overflow | (r.vu0ExtraOverflow << 1) | (r.vu0SignOverflow << 2) | (r.vu0Underflow << 3);
    if (std::strcmp(which, "vu1") == 0)
        return r.vu1Overflow | (r.vu1ExtraOverflow << 1) | (r.vu1SignOverflow << 2) | (r.vu1Underflow << 3);
    return -1;
}

uint64_t pcsx2hook_get_gs_stream_transfers(pcsx2hook_ctx* ctx) {
    if (!ctx) return 0;
    return GsStream::get().getTransfers();
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

int pcsx2hook_set_write_sink(pcsx2hook_ctx* ctx, uint32_t lo, uint32_t hi, pcsx2hook_write_fn fn,
                             void* user) {
    if (!ctx) return 0;
    if (fn && (lo >= hi)) {
        ctx->error = "write sink: the range is empty";
        return 0;
    }
    if (fn && VMManager::HasValidVM()) {
        ctx->error = "write sink: arm it before the VM starts, fastmem is chosen at boot";
        return 0;
    }
    static bool registered = false;
    s_writeSink = {nullptr, user, lo, hi};
    if (!fn) {
        s_writeSink.fn = nullptr;
        return 1;
    }
    if (!registered) {
        Hooks::AddGuestMemSink(&writeSinkTrampoline);
        registered = true;
    }
    Config::get().set("PCSX2HOOK_EE_INTERP", "1");
    s_writeSink.fn = fn;
    return 1;
}

const char* pcsx2hook_get_last_error(pcsx2hook_ctx* ctx) {
    return ctx ? ctx->error.c_str() : "no context";
}

}  // extern "C"

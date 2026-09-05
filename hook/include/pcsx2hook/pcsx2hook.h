#ifndef PCSX2HOOK_H
#define PCSX2HOOK_H

#include <stddef.h>
#include <stdint.h>

#if defined(_WIN32)
#if defined(PCSX2HOOK_BUILDING)
#define PCSX2HOOK_API __declspec(dllexport)
#else
#define PCSX2HOOK_API __declspec(dllimport)
#endif
#else
#define PCSX2HOOK_API __attribute__((visibility("default")))
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct pcsx2hook_ctx pcsx2hook_ctx;

typedef void (*pcsx2hook_void_fn)(void* user);
typedef void (*pcsx2hook_frame_fn)(uint32_t frame, void* user);

typedef struct
{
	const char* bios_dir;
	const char* bios_file;
	const char* dump_dir;
	const char* symbols;   // "name = 0xADDR;" per line, or null
	int surfaceless;       // no window
	int interpreter;       // all four processors on the interpreter
	int software_gs;       // 0 = null GS, 1 = software rasterizer

	// The host's half of the run loop. on_settings runs while the emulator's settings are still
	// writable, the rest bracket the loop itself.
	pcsx2hook_void_fn on_settings;
	pcsx2hook_void_fn on_vm_ready;
	pcsx2hook_frame_fn on_frame;
	pcsx2hook_void_fn on_shutdown;
	void* user;
} pcsx2hook_config;

// The EE register file at a hooked call. gpr has a 128-bit stride, so register n's low word is at
// gpr[n * 4].
typedef struct
{
	uint32_t* gpr;
	float* fpr;
	uint32_t pc;
} pcsx2hook_regs;

enum
{
	PCSX2HOOK_CONTINUE = 0, // run the original body
	PCSX2HOOK_EXIT = 1      // skip it and return to the caller
};

typedef int (*pcsx2hook_pre_fn)(pcsx2hook_regs* regs, void* user);
typedef void (*pcsx2hook_post_fn)(pcsx2hook_regs* regs, void* user);

typedef enum
{
	PCSX2HOOK_TRACE_EXEC,
	PCSX2HOOK_TRACE_INSN,
	PCSX2HOOK_TRACE_IOP,
	PCSX2HOOK_TRACE_HW,
	PCSX2HOOK_TRACE_SIF,
	PCSX2HOOK_TRACE_VIF,
	PCSX2HOOK_TRACE_VU,
	PCSX2HOOK_TRACE_GS,
	PCSX2HOOK_TRACE_API
} pcsx2hook_trace;

PCSX2HOOK_API pcsx2hook_ctx* pcsx2hook_create(const pcsx2hook_config* config);
PCSX2HOOK_API void pcsx2hook_destroy(pcsx2hook_ctx* ctx);

PCSX2HOOK_API int pcsx2hook_arm(pcsx2hook_ctx* ctx, pcsx2hook_trace which);

// The run loop is split rather than blocking: a host drives its own window and event pump on the
// main thread while the emulator runs on its own.
PCSX2HOOK_API void pcsx2hook_early_init(pcsx2hook_ctx* ctx);
PCSX2HOOK_API int pcsx2hook_init(pcsx2hook_ctx* ctx, int argc, char** argv);
PCSX2HOOK_API int pcsx2hook_window_requested(pcsx2hook_ctx* ctx);
PCSX2HOOK_API int pcsx2hook_create_dev_window(pcsx2hook_ctx* ctx);
PCSX2HOOK_API void pcsx2hook_apply_settings_override(pcsx2hook_ctx* ctx);
PCSX2HOOK_API int pcsx2hook_start(pcsx2hook_ctx* ctx);
PCSX2HOOK_API int pcsx2hook_finished(pcsx2hook_ctx* ctx);
PCSX2HOOK_API void pcsx2hook_pump_dev_window(pcsx2hook_ctx* ctx, int forever);
PCSX2HOOK_API void pcsx2hook_request_stop(pcsx2hook_ctx* ctx);
PCSX2HOOK_API int pcsx2hook_join(pcsx2hook_ctx* ctx);
PCSX2HOOK_API void pcsx2hook_shutdown(pcsx2hook_ctx* ctx);

// Mirrors the emulator's DualShock2 input order, which is what set_pad_button indexes.
typedef enum
{
	PCSX2HOOK_PAD_UP = 0, PCSX2HOOK_PAD_RIGHT, PCSX2HOOK_PAD_DOWN, PCSX2HOOK_PAD_LEFT,
	PCSX2HOOK_PAD_TRIANGLE, PCSX2HOOK_PAD_CIRCLE, PCSX2HOOK_PAD_CROSS, PCSX2HOOK_PAD_SQUARE,
	PCSX2HOOK_PAD_SELECT, PCSX2HOOK_PAD_START,
	PCSX2HOOK_PAD_L1, PCSX2HOOK_PAD_L2, PCSX2HOOK_PAD_R1, PCSX2HOOK_PAD_R2,
	PCSX2HOOK_PAD_L3, PCSX2HOOK_PAD_R3,
	PCSX2HOOK_PAD_ANALOG, PCSX2HOOK_PAD_PRESSURE,
	PCSX2HOOK_PAD_L_UP, PCSX2HOOK_PAD_L_RIGHT, PCSX2HOOK_PAD_L_DOWN, PCSX2HOOK_PAD_L_LEFT,
	PCSX2HOOK_PAD_R_UP, PCSX2HOOK_PAD_R_RIGHT, PCSX2HOOK_PAD_R_DOWN, PCSX2HOOK_PAD_R_LEFT,
	PCSX2HOOK_PAD_COUNT
} pcsx2hook_pad_button;

PCSX2HOOK_API void pcsx2hook_set_pad_button(pcsx2hook_ctx* ctx, int bind, int pressed);
PCSX2HOOK_API void pcsx2hook_set_speed_limit(pcsx2hook_ctx* ctx, int enabled);

// Only from on_settings: the emulator reads these once, before the VM starts.
PCSX2HOOK_API void pcsx2hook_set_string(pcsx2hook_ctx* ctx, const char* section, const char* key,
	const char* value);
PCSX2HOOK_API void pcsx2hook_set_bool(pcsx2hook_ctx* ctx, const char* section, const char* key,
	int value);
PCSX2HOOK_API void pcsx2hook_add_string_list(pcsx2hook_ctx* ctx, const char* section,
	const char* key, const char* value);

// Registering a hook plants a trampoline, so it must happen before the address is first executed.
PCSX2HOOK_API int pcsx2hook_register(pcsx2hook_ctx* ctx, uint32_t addr, pcsx2hook_pre_fn pre,
	pcsx2hook_post_fn post, void* user);

// A `jr $ra; nop` stub in unused guest RAM that post-hooked calls return through, and a second one
// that pcsx2hook_call_ee returns through. Post-handlers and guest calls do nothing until these are set.
PCSX2HOOK_API void pcsx2hook_set_return_sentinel(pcsx2hook_ctx* ctx, uint32_t addr);
PCSX2HOOK_API void pcsx2hook_set_call_marker(pcsx2hook_ctx* ctx, uint32_t addr);

// Runs for every hooked call before its handler, for a host recording the whole stream.
PCSX2HOOK_API void pcsx2hook_set_observer(pcsx2hook_ctx* ctx, pcsx2hook_post_fn fn, void* user);

// Runs a guest function to completion from inside a handler and returns $v0. Non-blocking functions
// only: EE interrupts are masked for the duration.
PCSX2HOOK_API uint32_t pcsx2hook_call_ee(pcsx2hook_ctx* ctx, uint32_t pc, const uint32_t* args,
	size_t count);

// A host pointer into guest RAM, or null when the range is not mapped.
PCSX2HOOK_API void* pcsx2hook_guest(pcsx2hook_ctx* ctx, uint32_t addr, uint32_t size);

// The base of EE main RAM and its size, for a host that overlays its own structs on it.
PCSX2HOOK_API void* pcsx2hook_ram_base(pcsx2hook_ctx* ctx, uint32_t* size);

PCSX2HOOK_API uint32_t pcsx2hook_ee_pc(pcsx2hook_ctx* ctx);
PCSX2HOOK_API const char* pcsx2hook_disc_serial(pcsx2hook_ctx* ctx);

PCSX2HOOK_API int pcsx2hook_load_state(pcsx2hook_ctx* ctx, const char* path);
PCSX2HOOK_API int pcsx2hook_save_state(pcsx2hook_ctx* ctx, const char* path);

// Runs on the GS thread and waits for it, which is the only safe point to read GS-owned state.
PCSX2HOOK_API void pcsx2hook_run_on_gs_thread(pcsx2hook_ctx* ctx, pcsx2hook_void_fn fn, void* user);

// The emulated GS frame buffer as RGBA8. A null buffer asks for the size.
PCSX2HOOK_API size_t pcsx2hook_read_framebuffer(pcsx2hook_ctx* ctx, void* out, size_t size,
	uint32_t* width, uint32_t* height);

// One GS draw batch's resolved register state, in submission order for the last complete frame.
PCSX2HOOK_API size_t pcsx2hook_gs_rows(pcsx2hook_ctx* ctx, uint32_t frame, char* out, size_t size);

// Names the draw the host is inside, so traced work can be attributed to it. The label is the
// host's own word for what it is drawing, truncated past 31 characters; the library has no model of
// a renderer, so it never interprets one. Attribution only reaches work the guest does while the
// draw is open: an engine that queues its packets and kicks the DMA chain once per frame does most
// of its GS and VU work after the draw has been popped.
PCSX2HOOK_API void pcsx2hook_push_draw(pcsx2hook_ctx* ctx, const char* label, uint32_t object,
	uint32_t pipeline);
PCSX2HOOK_API void pcsx2hook_pop_draw(pcsx2hook_ctx* ctx);

// Any of the library's own settings, by the name the environment would use.
PCSX2HOOK_API void pcsx2hook_set_config(pcsx2hook_ctx* ctx, const char* name, const char* value);

// The symbol covering an address, or the raw address when no map is loaded. Returns the length
// needed including the terminator.
PCSX2HOOK_API size_t pcsx2hook_resolve_symbol(pcsx2hook_ctx* ctx, uint32_t pc, char* out,
	size_t size);
PCSX2HOOK_API int pcsx2hook_in_code_range(pcsx2hook_ctx* ctx, uint32_t pc);
PCSX2HOOK_API void pcsx2hook_load_symbols(pcsx2hook_ctx* ctx);

PCSX2HOOK_API void pcsx2hook_gs_set_recording(pcsx2hook_ctx* ctx, int on);
PCSX2HOOK_API void pcsx2hook_gs_set_deferred(pcsx2hook_ctx* ctx, int on);
PCSX2HOOK_API void pcsx2hook_gs_arm_capture(pcsx2hook_ctx* ctx, int skip);
PCSX2HOOK_API void pcsx2hook_gs_mark_capture_start(pcsx2hook_ctx* ctx);
PCSX2HOOK_API uint32_t pcsx2hook_gs_standalone_frames(pcsx2hook_ctx* ctx);
// Appends to `path`, or writes to stderr when it is null.
PCSX2HOOK_API void pcsx2hook_gs_report_tracker(pcsx2hook_ctx* ctx, const char* reason,
	const char* path);

// The captured GS frame buffer taken at the marked batch, as RGBA8. A null buffer asks for the size.
PCSX2HOOK_API size_t pcsx2hook_gs_take_capture(pcsx2hook_ctx* ctx, void* out, size_t size,
	uint32_t* width, uint32_t* height, uint32_t* frame);

// Appends the last complete frame's GS rows to a file, and returns how many were written.
PCSX2HOOK_API size_t pcsx2hook_gs_write_last_frame(pcsx2hook_ctx* ctx, const char* path);

// Writes whatever the armed tracers have collected.
PCSX2HOOK_API void pcsx2hook_flush(pcsx2hook_ctx* ctx);

PCSX2HOOK_API const char* pcsx2hook_last_error(pcsx2hook_ctx* ctx);

#ifdef __cplusplus
}
#endif

#endif

/**
 * @file pcsx2hook.h
 * @brief Drives PCSX2 as a diagnostic tool: hook guest functions, trace execution, read hardware.
 *
 * Call each function from the thread that owns the context unless it says otherwise. Callbacks and
 * hook handlers run on the emulator's CPU thread.
 */
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

/** @brief One driven emulator. Opaque; create with ::pcsx2hook_create. */
typedef struct pcsx2hook_ctx pcsx2hook_ctx;

/** @brief Callback carrying only the host's own pointer. */
typedef void (*pcsx2hook_void_fn)(void* user);

/** @brief Per-frame callback. @param frame 1-based frame counter since boot. */
typedef void (*pcsx2hook_frame_fn)(uint32_t frame, void* user);

/** @brief Boot settings and callbacks. Copied on create; the strings must outlive the context. */
typedef struct
{
	const char* bios;     /**< Full path to the BIOS image. */
	const char* dump_dir; /**< Where every enabled trace writes. Created if missing. */
	const char* symbols;  /**< A symbol map, or a directory of @c <ELF name>.map files. May be null. */
	int surfaceless;       /**< Non-zero to run with no window. */
	int interpreter;       /**< Non-zero to put all four processors on the interpreter. Much slower. */
	int software_gs;       /**< Non-zero for the software rasterizer, zero for the null renderer. */

	pcsx2hook_void_fn on_settings;  /**< The only place the @c set_*_setting calls work. */
	pcsx2hook_void_fn on_vm_ready;  /**< Guest RAM is mapped, the loop not started: register hooks. */
	pcsx2hook_frame_fn on_frame;    /**< Once per emulated frame. */
	pcsx2hook_void_fn on_shutdown;  /**< After the loop exits, before the VM is torn down. */
	void* user; /**< Passed back to each callback above. */
} pcsx2hook_config;

/** @brief The EE register file at a hooked call. Live state, valid only during the handler. */
typedef struct
{
	uint32_t* gpr; /**< 32 registers at a 128-bit stride: register @c n's low word is @c gpr[n * 4]. */
	float* fpr;    /**< 32 FP registers. */
	uint32_t pc;   /**< Entry address of the hooked function. */
} pcsx2hook_regs;

/** @brief What a pre-handler returns. */
enum
{
	PCSX2HOOK_CONTINUE = 0, /**< Run the original function body. */
	PCSX2HOOK_EXIT = 1      /**< Skip it and return to the caller. Set @c $v0 first. */
};

/** @brief Runs at a hooked function's entry. @return ::PCSX2HOOK_CONTINUE or ::PCSX2HOOK_EXIT. */
typedef int (*pcsx2hook_pre_fn)(pcsx2hook_regs* regs, void* user);

/** @brief Runs after a hooked function returns, with its result in @c $v0. */
typedef void (*pcsx2hook_post_fn)(pcsx2hook_regs* regs, void* user);

/** @brief The traces that can be enabled. */
typedef enum
{
	PCSX2HOOK_TRACE_EXEC, /**< EE block coverage, opcode histogram, syscalls, threads. */
	PCSX2HOOK_TRACE_INSN, /**< Per-instruction operand and result vectors. Interpreter only. */
	PCSX2HOOK_TRACE_IOP,  /**< IOP blocks, opcodes, and the IRX import surface. */
	PCSX2HOOK_TRACE_HW,   /**< Every hardware register access on both processors. */
	PCSX2HOOK_TRACE_SIF,  /**< SIF transfers and the code that kicks them. */
	PCSX2HOOK_TRACE_VIF,  /**< VIF1 tags and code words in processed order. */
	PCSX2HOOK_TRACE_VU,   /**< VU1 microprogram uploads and execution. */
	PCSX2HOOK_TRACE_GS,   /**< Every GS primitive batch with resolved register state. */
	PCSX2HOOK_TRACE_API,  /**< Named function entries with their arguments. */
	PCSX2HOOK_TRACE_VU_INSN, /**< VU0/VU1 micro-mode vectors. Interpreted VUs only. */
	PCSX2HOOK_TRACE_VIF_CMD, /**< VIF0/VIF1 command vectors. */
	PCSX2HOOK_TRACE_SPU,     /**< SPU2 vectors. */
	PCSX2HOOK_TRACE_TIMING   /**< VU runs and an EE-cycle event timeline. Interpreted VUs only. */
} pcsx2hook_trace;

/** @brief Processors for ::pcsx2hook_set_interpreter, as a bit mask. */
typedef enum
{
	PCSX2HOOK_CPU_EE = 1,
	PCSX2HOOK_CPU_IOP = 2,
	PCSX2HOOK_CPU_VU0 = 4,
	PCSX2HOOK_CPU_VU1 = 8
} pcsx2hook_cpu;

/** @brief Creates a context, or null for a null @p config. Free with ::pcsx2hook_destroy. */
PCSX2HOOK_API pcsx2hook_ctx* pcsx2hook_create(const pcsx2hook_config* config);

/** @brief Destroys a context. Call ::pcsx2hook_shutdown first if it was started. */
PCSX2HOOK_API void pcsx2hook_destroy(pcsx2hook_ctx* ctx);

/** @brief Enables a trace, before ::pcsx2hook_start. @return Zero only for an unknown @p which. */
PCSX2HOOK_API int pcsx2hook_enable_trace(pcsx2hook_ctx* ctx, pcsx2hook_trace which);

/** @name Run control
 *  Before ::pcsx2hook_apply_settings.
 *  @{ */

/** @brief Interprets the ::pcsx2hook_cpu processors in @p cpus; the rest stay recompiled. */
PCSX2HOOK_API void pcsx2hook_set_interpreter(pcsx2hook_ctx* ctx, unsigned cpus);

/** @brief Turns off Instant VU1 and the idle-loop and INTC_STAT skips. */
PCSX2HOOK_API void pcsx2hook_set_accurate_timing(pcsx2hook_ctx* ctx, int enabled);

/** @brief Boots into a savestate. Null boots the disc. */
PCSX2HOOK_API void pcsx2hook_set_boot_state(pcsx2hook_ctx* ctx, const char* path);

/** @brief Stops after @p frames frames and writes the traces. 0 means no limit. */
PCSX2HOOK_API void pcsx2hook_set_frame_limit(pcsx2hook_ctx* ctx, uint32_t frames);

/** @} */

/** @name Lifecycle
 *  Call in the order listed.
 *  @{ */

/** @brief Prepares logging and paths. Before ::pcsx2hook_init. */
PCSX2HOOK_API void pcsx2hook_early_init(pcsx2hook_ctx* ctx);

/**
 * @brief Parses the command line, whose one positional argument is the disc or ELF.
 * @return Non-zero on success.
 */
PCSX2HOOK_API int pcsx2hook_init(pcsx2hook_ctx* ctx, int argc, char** argv);

/** @brief Whether the run wants a window, given its configuration and arguments. */
PCSX2HOOK_API int pcsx2hook_wants_window(pcsx2hook_ctx* ctx);

/** @brief Opens the emulator's own GS window. */
PCSX2HOOK_API int pcsx2hook_create_window(pcsx2hook_ctx* ctx);

/** @brief Applies the headless GS and CPU settings, and invokes @c on_settings. */
PCSX2HOOK_API void pcsx2hook_apply_settings(pcsx2hook_ctx* ctx);

/** @brief Boots and starts the CPU thread. Returns immediately. */
PCSX2HOOK_API int pcsx2hook_start(pcsx2hook_ctx* ctx);

/** @brief Whether emulation has stopped. Poll from the host's event loop. */
PCSX2HOOK_API int pcsx2hook_is_finished(pcsx2hook_ctx* ctx);

/** @brief Pumps the emulator's window. Non-zero @p forever blocks until emulation ends. */
PCSX2HOOK_API void pcsx2hook_pump_window(pcsx2hook_ctx* ctx, int forever);

/** @brief Asks emulation to stop, from any thread. Returns at once; wait with ::pcsx2hook_join. */
PCSX2HOOK_API void pcsx2hook_request_stop(pcsx2hook_ctx* ctx);

/** @brief Waits for the CPU thread and returns the run's exit code. */
PCSX2HOOK_API int pcsx2hook_join(pcsx2hook_ctx* ctx);

/** @brief Releases the emulator's resources. After ::pcsx2hook_join. */
PCSX2HOOK_API void pcsx2hook_shutdown(pcsx2hook_ctx* ctx);

/** @} */

/** @brief DualShock2 inputs, in the order ::pcsx2hook_set_pad_button indexes. */
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

/** @brief Presses or releases a ::pcsx2hook_pad_button. Safe from the host's event loop. */
PCSX2HOOK_API void pcsx2hook_set_pad_button(pcsx2hook_ctx* ctx, int bind, int pressed);

/** @brief Runs at 1x speed when non-zero, or as fast as it will go when zero. */
PCSX2HOOK_API void pcsx2hook_set_speed_limit(pcsx2hook_ctx* ctx, int enabled);

/** @name Emulator settings
 *  Only from @c on_settings; ignored at any other time.
 *  @{ */

/** @brief Sets a string setting. */
PCSX2HOOK_API void pcsx2hook_set_string_setting(pcsx2hook_ctx* ctx, const char* section, const char* key,
	const char* value);

/** @brief Sets a boolean setting. */
PCSX2HOOK_API void pcsx2hook_set_bool_setting(pcsx2hook_ctx* ctx, const char* section, const char* key,
	int value);

/** @brief Appends to a list-valued setting. */
PCSX2HOOK_API void pcsx2hook_add_string_list_setting(pcsx2hook_ctx* ctx, const char* section,
	const char* key, const char* value);

/** @} */

/**
 * @brief Hooks a guest function: @p pre runs at entry, @p post after it returns. Both may be null.
 * @note Register from @c on_vm_ready. A post handler returns through a stub below the ELF base;
 *       @c PCSX2HOOK_SENTINEL_BASE moves it if a program uses that gap.
 */
PCSX2HOOK_API int pcsx2hook_add_hook(pcsx2hook_ctx* ctx, uint32_t addr, pcsx2hook_pre_fn pre,
	pcsx2hook_post_fn post, void* user);

/** @brief Observes every hooked call before its own handler, for recording the whole stream. */
PCSX2HOOK_API void pcsx2hook_set_hook_observer(pcsx2hook_ctx* ctx, pcsx2hook_post_fn fn, void* user);

/**
 * @brief Runs a guest function with up to four integer arguments and returns @c $v0.
 * @warning Hook handlers only, and non-blocking targets only: EE interrupts are masked.
 */
PCSX2HOOK_API uint32_t pcsx2hook_call_ee(pcsx2hook_ctx* ctx, uint32_t pc, const uint32_t* args,
	size_t count);

/** @brief Maps a guest address to a host pointer, or null if unmapped or past main RAM. */
PCSX2HOOK_API void* pcsx2hook_map_guest(pcsx2hook_ctx* ctx, uint32_t addr, uint32_t size);

/** @brief The base of EE main RAM, or null before the VM is up. @p size may be null. */
PCSX2HOOK_API void* pcsx2hook_get_ram_base(pcsx2hook_ctx* ctx, uint32_t* size);

/** @brief The EE program counter, for a sampler or a heartbeat. */
PCSX2HOOK_API uint32_t pcsx2hook_get_ee_pc(pcsx2hook_ctx* ctx);

/** @brief The disc serial, such as @c "SLUS-21621". Empty before boot, owned by the context. */
PCSX2HOOK_API const char* pcsx2hook_get_disc_serial(pcsx2hook_ctx* ctx);

/** @brief Loads a savestate. @return Non-zero on success; see ::pcsx2hook_get_last_error. */
PCSX2HOOK_API int pcsx2hook_load_state(pcsx2hook_ctx* ctx, const char* path);

/** @brief Writes a savestate. @return Non-zero on success. */
PCSX2HOOK_API int pcsx2hook_save_state(pcsx2hook_ctx* ctx, const char* path);

/** @brief Runs @p fn on the GS thread and waits, the only safe point to read GS-owned state. */
PCSX2HOOK_API void pcsx2hook_run_on_gs_thread(pcsx2hook_ctx* ctx, pcsx2hook_void_fn fn, void* user);

/**
 * @brief Reads the frame buffer as RGBA8. @return Bytes needed, or 0 under the null renderer.
 * @note A null @p out asks for the size and keeps that frame for the fetch that follows.
 */
PCSX2HOOK_API size_t pcsx2hook_read_framebuffer(pcsx2hook_ctx* ctx, void* out, size_t size,
	uint32_t* width, uint32_t* height);

/**
 * @brief Opens a draw context that traced work is attributed to. Pair with ::pcsx2hook_pop_draw.
 * @note @p label keeps 31 characters. Work the guest kicks after the pop is unattributed.
 */
PCSX2HOOK_API void pcsx2hook_push_draw(pcsx2hook_ctx* ctx, const char* label, uint32_t object,
	uint32_t pipeline);

/** @brief Closes the innermost draw context. */
PCSX2HOOK_API void pcsx2hook_pop_draw(pcsx2hook_ctx* ctx);

/** @brief Sets a library setting by its environment variable name, before ::pcsx2hook_start. */
PCSX2HOOK_API void pcsx2hook_set_config(pcsx2hook_ctx* ctx, const char* name, const char* value);

/** @name Symbols
 *  @{ */

/** @brief The symbol covering @p pc, or the raw address. A null @p out asks for the size. */
PCSX2HOOK_API size_t pcsx2hook_resolve_symbol(pcsx2hook_ctx* ctx, uint32_t pc, char* out,
	size_t size);

/** @brief Whether @p pc lies inside the program's own text, as opposed to the BIOS or a module. */
PCSX2HOOK_API int pcsx2hook_is_in_code_range(pcsx2hook_ctx* ctx, uint32_t pc);

/** @brief Loads the symbol map now rather than on first use. */
PCSX2HOOK_API void pcsx2hook_load_symbols(pcsx2hook_ctx* ctx);

/** @} */

/** @name GS trace
 *  Needs ::PCSX2HOOK_TRACE_GS enabled.
 *  @{ */

/** @brief Starts or stops recording GS batches. */
PCSX2HOOK_API void pcsx2hook_set_gs_recording(pcsx2hook_ctx* ctx, int on);

/** @brief Holds rows until the frame completes, instead of writing them as they arrive. */
PCSX2HOOK_API void pcsx2hook_set_gs_deferred(pcsx2hook_ctx* ctx, int on);

/** @brief Enables a capture @p skip drawing frames after the mark. One is usually right. */
PCSX2HOOK_API void pcsx2hook_enable_gs_capture(pcsx2hook_ctx* ctx, int skip);

/** @brief Marks the batch stream position a capture is relative to. */
PCSX2HOOK_API void pcsx2hook_mark_gs_capture_start(pcsx2hook_ctx* ctx);

/** @brief How many frames the trace has recorded on its own, outside a capture. */
PCSX2HOOK_API uint32_t pcsx2hook_get_gs_standalone_frames(pcsx2hook_ctx* ctx);

/** @brief Writes which code submitted each GS batch, appending to @p path or to stderr. */
PCSX2HOOK_API void pcsx2hook_report_gs_tracker(pcsx2hook_ctx* ctx, const char* reason,
	const char* path);

/** @brief Takes the capture as RGBA8, cached like ::pcsx2hook_read_framebuffer. 0 if not ready. */
PCSX2HOOK_API size_t pcsx2hook_take_gs_capture(pcsx2hook_ctx* ctx, void* out, size_t size,
	uint32_t* width, uint32_t* height, uint32_t* frame);

/** @brief The last complete frame's batches as JSON rows. A null @p out asks for the size. */
PCSX2HOOK_API size_t pcsx2hook_get_gs_rows(pcsx2hook_ctx* ctx, uint32_t frame, char* out, size_t size);

/** @brief Appends the last complete frame's rows to @p path. @return Rows written. */
PCSX2HOOK_API size_t pcsx2hook_write_gs_last_frame(pcsx2hook_ctx* ctx, const char* path);

/** @} */

/** @brief Writes out every enabled trace. A killed process writes none. */
PCSX2HOOK_API void pcsx2hook_flush_traces(pcsx2hook_ctx* ctx);

/** @brief Why the last call that reported failure failed. Owned by the context. */
PCSX2HOOK_API const char* pcsx2hook_get_last_error(pcsx2hook_ctx* ctx);

#ifdef __cplusplus
}
#endif

#endif

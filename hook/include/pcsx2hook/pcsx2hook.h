/**
 * @file pcsx2hook.h
 * @brief Driving PCSX2 as a diagnostic instrument: hook guest functions, trace what a PS2 program
 *        executes, and read the emulated hardware.
 *
 * This is the whole supported surface. Everything under @c hook/src is internal.
 *
 * @section lifecycle Lifecycle
 * The run loop is split rather than blocking, so a host can drive its own window and event pump on
 * the main thread while the emulator runs on its own:
 * @code
 * pcsx2hook_ctx* ctx = pcsx2hook_create(&config);
 * pcsx2hook_early_init(ctx);
 * pcsx2hook_init(ctx, argc, argv);
 * pcsx2hook_apply_settings(ctx);
 * pcsx2hook_start(ctx);
 * while (!pcsx2hook_is_finished(ctx)) { ... host event pump ... }
 * int code = pcsx2hook_join(ctx);
 * pcsx2hook_shutdown(ctx);
 * pcsx2hook_destroy(ctx);
 * @endcode
 *
 * @section threads Threads
 * Unless a function says otherwise, call it from the thread that owns the context. The callbacks in
 * ::pcsx2hook_config and every hook handler run on the emulator's CPU thread.
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

/**
 * @brief What to boot and how, plus the host's half of the run loop.
 *
 * ::pcsx2hook_create copies the struct but not the strings, which must outlive the context.
 */
typedef struct
{
	const char* bios_dir;  /**< BIOS folder. A relative path resolves against the working directory. */
	const char* bios_file; /**< BIOS file name within @c bios_dir. */
	const char* dump_dir;  /**< Where every armed trace writes. Created if missing. */
	const char* symbols;   /**< Symbol map, @c "name = 0xADDR;" per line, or null to find one by serial. */
	int surfaceless;       /**< Non-zero to run with no window. */
	int interpreter;       /**< Non-zero to put all four processors on the interpreter. Much slower. */
	int software_gs;       /**< Non-zero for the software rasterizer, zero for the null renderer. */

	/** While the emulator's settings are still writable. The only place the @c set_* settings
	 *  functions have any effect. */
	pcsx2hook_void_fn on_settings;
	/** After the VM is up and the traces are armed, before the loop starts. Guest RAM and the disc
	 *  serial are readable here, so this is where a host registers its hooks. */
	pcsx2hook_void_fn on_vm_ready;
	/** Once per emulated frame, on the CPU thread. */
	pcsx2hook_frame_fn on_frame;
	/** After the loop exits, before the VM is torn down. */
	pcsx2hook_void_fn on_shutdown;
	void* user; /**< Passed back to each callback above. */
} pcsx2hook_config;

/**
 * @brief The EE register file at a hooked call.
 *
 * Points at live emulator state, so it is valid only for the duration of the handler. The GPR file
 * has a 128-bit stride: register @c n's low word is at @c gpr[n * 4], its high word at
 * @c gpr[n * 4 + 1].
 */
typedef struct
{
	uint32_t* gpr; /**< 32 general-purpose registers, 128-bit stride. */
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

/**
 * @brief The traces that can be armed.
 *
 * Block coverage costs one memory increment per block execution, so it can stay on for a whole
 * boot. The per-instruction traces need @c interpreter and are meant to run from a savestate.
 */
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
	PCSX2HOOK_TRACE_API   /**< Named function entries with their arguments. */
} pcsx2hook_trace;

/**
 * @brief Creates a context.
 * @param config Required. Copied, except for its strings.
 * @return The context, or null if @p config is null. Free with ::pcsx2hook_destroy.
 */
PCSX2HOOK_API pcsx2hook_ctx* pcsx2hook_create(const pcsx2hook_config* config);

/** @brief Destroys a context. Call ::pcsx2hook_shutdown first if it was started. */
PCSX2HOOK_API void pcsx2hook_destroy(pcsx2hook_ctx* ctx);

/**
 * @brief Arms a trace.
 * @return Non-zero on success. Fails only for an unknown @p which; see ::pcsx2hook_get_last_error.
 * @note Before ::pcsx2hook_start, since a trace hooks code the recompiler compiles once.
 */
PCSX2HOOK_API int pcsx2hook_trace_arm(pcsx2hook_ctx* ctx, pcsx2hook_trace which);

/** @name Lifecycle
 *  Call in the order listed. See @ref lifecycle.
 *  @{ */

/** @brief Prepares logging and paths. Before ::pcsx2hook_init. */
PCSX2HOOK_API void pcsx2hook_early_init(pcsx2hook_ctx* ctx);

/**
 * @brief Parses the command line and readies the emulator.
 * @param argv The positional argument is the disc image or ELF to boot.
 * @return Non-zero on success.
 */
PCSX2HOOK_API int pcsx2hook_init(pcsx2hook_ctx* ctx, int argc, char** argv);

/** @brief Whether the run wants a window, given its configuration and arguments. */
PCSX2HOOK_API int pcsx2hook_wants_window(pcsx2hook_ctx* ctx);

/** @brief Opens the emulator's own GS window, for watching it beside a host renderer. */
PCSX2HOOK_API int pcsx2hook_create_dev_window(pcsx2hook_ctx* ctx);

/** @brief Applies the headless GS and CPU settings, and invokes @c on_settings. */
PCSX2HOOK_API void pcsx2hook_apply_settings(pcsx2hook_ctx* ctx);

/** @brief Boots and starts the CPU thread. Returns immediately. */
PCSX2HOOK_API int pcsx2hook_start(pcsx2hook_ctx* ctx);

/** @brief Whether emulation has stopped. Poll from the host's event loop. */
PCSX2HOOK_API int pcsx2hook_is_finished(pcsx2hook_ctx* ctx);

/**
 * @brief Pumps the emulator's own window.
 * @param forever Non-zero to block until emulation ends, for a host with no window of its own.
 */
PCSX2HOOK_API void pcsx2hook_pump_dev_window(pcsx2hook_ctx* ctx, int forever);

/** @brief Asks emulation to stop. Returns at once; wait with ::pcsx2hook_join. */
PCSX2HOOK_API void pcsx2hook_request_stop(pcsx2hook_ctx* ctx);

/** @brief Waits for the CPU thread and returns the run's exit code. */
PCSX2HOOK_API int pcsx2hook_join(pcsx2hook_ctx* ctx);

/** @brief Releases the emulator's resources. After ::pcsx2hook_join. */
PCSX2HOOK_API void pcsx2hook_shutdown(pcsx2hook_ctx* ctx);

/** @} */

/** @brief DualShock2 inputs, in the order ::pcsx2hook_pad_set_button indexes. */
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

/**
 * @brief Presses or releases a pad button.
 * @param bind A ::pcsx2hook_pad_button.
 * @note Applied on the CPU thread, so this is safe to call from a host's event loop.
 */
PCSX2HOOK_API void pcsx2hook_pad_set_button(pcsx2hook_ctx* ctx, int bind, int pressed);

/** @brief Runs at 1x speed when non-zero, or as fast as it will go when zero. */
PCSX2HOOK_API void pcsx2hook_set_speed_limit(pcsx2hook_ctx* ctx, int enabled);

/** @name Emulator settings
 *  Only from the @c on_settings callback: the emulator reads these once, before the VM starts.
 *  Calls made at any other time are ignored.
 *  @{ */

/** @brief Sets a string setting. */
PCSX2HOOK_API void pcsx2hook_setting_set_string(pcsx2hook_ctx* ctx, const char* section, const char* key,
	const char* value);

/** @brief Sets a boolean setting. */
PCSX2HOOK_API void pcsx2hook_setting_set_bool(pcsx2hook_ctx* ctx, const char* section, const char* key,
	int value);

/** @brief Appends to a list-valued setting. */
PCSX2HOOK_API void pcsx2hook_setting_add_string_list(pcsx2hook_ctx* ctx, const char* section,
	const char* key, const char* value);

/** @} */

/**
 * @brief Hooks a guest function.
 * @param addr Guest address of the function's entry.
 * @param pre  Runs at entry. May be null.
 * @param post Runs after it returns, with its result in @c $v0. May be null.
 * @param user Passed to both handlers.
 * @return Non-zero on success.
 * @note Registering plants a trampoline, so it must happen before @p addr is first executed:
 *       @c on_vm_ready is the place.
 * @note A post-handler works by returning through a @c "jr $ra; nop" stub the library installs in
 *       the kernel-reserved gap below the user ELF base. Override its address with the
 *       @c PCSX2HOOK_SENTINEL_BASE config key if a program happens to use that gap.
 */
PCSX2HOOK_API int pcsx2hook_hook_add(pcsx2hook_ctx* ctx, uint32_t addr, pcsx2hook_pre_fn pre,
	pcsx2hook_post_fn post, void* user);

/** @brief Observes every hooked call before its own handler, for recording the whole stream. */
PCSX2HOOK_API void pcsx2hook_hook_set_observer(pcsx2hook_ctx* ctx, pcsx2hook_post_fn fn, void* user);

/**
 * @brief Runs a guest function to completion and returns @c $v0.
 * @param args Up to four integer arguments, passed in @c $a0 to @c $a3.
 * @param count How many of @p args to pass.
 * @warning Only from inside a hook handler, and only for a function that does not block: EE
 *          interrupts are masked for the duration, so one waiting on an interrupt or a DMA hangs.
 */
PCSX2HOOK_API uint32_t pcsx2hook_call_ee(pcsx2hook_ctx* ctx, uint32_t pc, const uint32_t* args,
	size_t count);

/**
 * @brief Maps a guest address to a host pointer.
 * @return Null when the range is not mapped or would run past the end of main RAM.
 */
PCSX2HOOK_API void* pcsx2hook_mem_map(pcsx2hook_ctx* ctx, uint32_t addr, uint32_t size);

/**
 * @brief The base of EE main RAM, for a host that overlays its own structs on it.
 * @param size Receives the mapped size in bytes. May be null.
 * @return Null before the VM is initialized.
 */
PCSX2HOOK_API void* pcsx2hook_mem_get_ram_base(pcsx2hook_ctx* ctx, uint32_t* size);

/** @brief The EE program counter, for a sampler or a heartbeat. */
PCSX2HOOK_API uint32_t pcsx2hook_get_ee_pc(pcsx2hook_ctx* ctx);

/**
 * @brief The running disc's serial, for example @c "SLUS-21621".
 * @return Owned by the context and valid until the next call. Empty before boot.
 */
PCSX2HOOK_API const char* pcsx2hook_get_disc_serial(pcsx2hook_ctx* ctx);

/** @brief Loads a savestate. @return Non-zero on success; see ::pcsx2hook_get_last_error. */
PCSX2HOOK_API int pcsx2hook_state_load(pcsx2hook_ctx* ctx, const char* path);

/** @brief Writes a savestate. @return Non-zero on success. */
PCSX2HOOK_API int pcsx2hook_state_save(pcsx2hook_ctx* ctx, const char* path);

/** @brief Runs @p fn on the GS thread and waits, the only safe point to read GS-owned state. */
PCSX2HOOK_API void pcsx2hook_gs_run_on_thread(pcsx2hook_ctx* ctx, pcsx2hook_void_fn fn, void* user);

/**
 * @brief Reads the emulated frame buffer as RGBA8.
 * @param out Null to ask for the size.
 * @param width Receives the width in pixels. May be null.
 * @param height Receives the height in pixels. May be null.
 * @return Bytes needed, or 0 when there is nothing to read: the null renderer fills no buffer.
 * @note Asking for the size takes the snapshot and keeps it, so the fetch that follows returns that
 *       same frame rather than a second one taken a moment later.
 */
PCSX2HOOK_API size_t pcsx2hook_gs_read_framebuffer(pcsx2hook_ctx* ctx, void* out, size_t size,
	uint32_t* width, uint32_t* height);

/**
 * @brief Names the draw the host is inside, for attributing traced work to it.
 * @param label The host's own word for what it is drawing, truncated past 31 characters. The
 *              library has no model of a renderer, so it never interprets this.
 * @param object Host handle for the thing being drawn. Recorded as-is.
 * @param pipeline Host handle for the pipeline drawing it. Recorded as-is.
 * @note Every push needs a matching ::pcsx2hook_draw_pop.
 * @note Attribution only reaches work the guest does while the draw is open. An engine that queues
 *       its packets and kicks the DMA chain once per frame does most of its GS and VU work after
 *       the draw has been popped, and that work is left unattributed.
 */
PCSX2HOOK_API void pcsx2hook_draw_push(pcsx2hook_ctx* ctx, const char* label, uint32_t object,
	uint32_t pipeline);

/** @brief Closes the innermost draw context. */
PCSX2HOOK_API void pcsx2hook_draw_pop(pcsx2hook_ctx* ctx);

/**
 * @brief Sets one of the library's own settings by the name its environment variable uses.
 * @note Before ::pcsx2hook_start, since most are read once while arming.
 */
PCSX2HOOK_API void pcsx2hook_config_set(pcsx2hook_ctx* ctx, const char* name, const char* value);

/** @name Symbols
 *  @{ */

/**
 * @brief The symbol covering an address.
 * @param out Null to ask for the size.
 * @return Length needed including the terminator. Falls back to the raw address with no map loaded.
 */
PCSX2HOOK_API size_t pcsx2hook_symbols_resolve(pcsx2hook_ctx* ctx, uint32_t pc, char* out,
	size_t size);

/** @brief Whether @p pc lies inside the program's own text, as opposed to the BIOS or a module. */
PCSX2HOOK_API int pcsx2hook_symbols_is_in_code_range(pcsx2hook_ctx* ctx, uint32_t pc);

/** @brief Loads the symbol map now rather than on first use. */
PCSX2HOOK_API void pcsx2hook_symbols_load(pcsx2hook_ctx* ctx);

/** @} */

/** @name GS trace
 *  Needs ::PCSX2HOOK_TRACE_GS armed.
 *  @{ */

/** @brief Starts or stops recording GS batches. */
PCSX2HOOK_API void pcsx2hook_gs_set_recording(pcsx2hook_ctx* ctx, int on);

/** @brief Holds rows until the frame completes, instead of writing them as they arrive. */
PCSX2HOOK_API void pcsx2hook_gs_set_deferred(pcsx2hook_ctx* ctx, int on);

/**
 * @brief Arms a frame-buffer capture.
 * @param skip Drawing frames to let pass after the mark before capturing. One is usually right,
 *             since a frame's DMA chain is built while the previous one is still transmitting.
 */
PCSX2HOOK_API void pcsx2hook_gs_arm_capture(pcsx2hook_ctx* ctx, int skip);

/** @brief Marks the batch stream position a capture is relative to. */
PCSX2HOOK_API void pcsx2hook_gs_mark_capture_start(pcsx2hook_ctx* ctx);

/** @brief How many frames the trace has recorded on its own, outside a capture. */
PCSX2HOOK_API uint32_t pcsx2hook_gs_get_standalone_frames(pcsx2hook_ctx* ctx);

/**
 * @brief Writes which code submitted each GS batch.
 * @param path Appended to, or stderr when null.
 */
PCSX2HOOK_API void pcsx2hook_gs_report_tracker(pcsx2hook_ctx* ctx, const char* reason,
	const char* path);

/**
 * @brief Takes the capture armed by ::pcsx2hook_gs_arm_capture, as RGBA8.
 * @param out Null to ask for the size.
 * @param frame Receives the GS frame the capture came from. May be null.
 * @return Bytes needed, or 0 if no capture is ready. Caches like ::pcsx2hook_gs_read_framebuffer.
 */
PCSX2HOOK_API size_t pcsx2hook_gs_take_capture(pcsx2hook_ctx* ctx, void* out, size_t size,
	uint32_t* width, uint32_t* height, uint32_t* frame);

/**
 * @brief The last complete frame's batches, one JSON row each with its resolved register state.
 * @param out Null to ask for the size.
 * @return Length needed including the terminator.
 */
PCSX2HOOK_API size_t pcsx2hook_gs_get_rows(pcsx2hook_ctx* ctx, uint32_t frame, char* out, size_t size);

/**
 * @brief Appends the last complete frame's rows to a file.
 * @return How many rows were written.
 * @note By path rather than a @c FILE*, which cannot cross a library boundary safely: the two
 *       halves need not share a C runtime.
 */
PCSX2HOOK_API size_t pcsx2hook_gs_write_last_frame(pcsx2hook_ctx* ctx, const char* path);

/** @} */

/**
 * @brief Writes out whatever the armed traces have collected.
 * @note Killing the process loses them, so a run that wants its trace has to reach here.
 */
PCSX2HOOK_API void pcsx2hook_trace_flush(pcsx2hook_ctx* ctx);

/** @brief Why the last call that reported failure failed. Owned by the context. */
PCSX2HOOK_API const char* pcsx2hook_get_last_error(pcsx2hook_ctx* ctx);

#ifdef __cplusplus
}
#endif

#endif

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

/**
 * @brief Every DMA kick on any channel, with the EE address that started it.
 * @note Covers a channel started by a store to CHCR as well as one started through a library
 *       call, which is the only way to see the GIF's own channel: libgraph writes D2_CHCR itself.
 *       Runs on the emulator's CPU thread.
 */
typedef void (*pcsx2hook_dma_kick_fn)(uint32_t chan, uint32_t eepc, uint32_t madr, uint32_t qwc,
	void* user);

/** @brief Registers a ::pcsx2hook_dma_kick_fn. Register from @c on_vm_ready. */
PCSX2HOOK_API void pcsx2hook_set_dma_kick_sink(pcsx2hook_ctx* ctx, pcsx2hook_dma_kick_fn fn,
	void* user);

/** @brief Observes every hooked call before its own handler, for recording the whole stream. */
PCSX2HOOK_API void pcsx2hook_set_hook_observer(pcsx2hook_ctx* ctx, pcsx2hook_post_fn fn, void* user);

/**
 * @brief Runs a guest function with up to eight integer arguments and returns @c $v0, or 0
 *        when the count is over eight (see ::pcsx2hook_call_ee_ex for the error).
 * @warning Hook handlers only, and non-blocking targets only: EE interrupts are masked.
 */
PCSX2HOOK_API uint32_t pcsx2hook_call_ee(pcsx2hook_ctx* ctx, uint32_t pc, const uint32_t* args,
	size_t count);

/**
 * @brief Runs a guest function with up to eight integer arguments ($a0 to $a3, $t0 to $t3) and
 *        up to eight float arguments ($f12 to $f19, as raw bits), the EE eabi.
 * @param v0 receives $v0 when not null
 * @param f0Bits receives $f0 as raw bits when not null
 * @return Non-zero when it ran; zero with ::pcsx2hook_get_last_error set when an argument count
 *         is over eight or the call marker is not set up, in which case nothing ran.
 * @warning Hook handlers only, and non-blocking targets only: EE interrupts are masked.
 */
PCSX2HOOK_API int pcsx2hook_call_ee_ex(pcsx2hook_ctx* ctx, uint32_t pc, const uint32_t* args,
	size_t count, const uint32_t* fargBits, size_t fcount, uint32_t* v0, uint32_t* f0Bits);

/** @brief Maps a guest address to a host pointer, or null if unmapped or past main RAM. */
PCSX2HOOK_API void* pcsx2hook_map_guest(pcsx2hook_ctx* ctx, uint32_t addr, uint32_t size);

/** @brief The base of EE main RAM, or null before the VM is up. @p size may be null. */
PCSX2HOOK_API void* pcsx2hook_get_ram_base(pcsx2hook_ctx* ctx, uint32_t* size);

/** @brief A vector unit's register file, as raw words. */
typedef struct
{
	uint32_t vf[32][4]; /**< VF0 to VF31, x y z w. */
	uint32_t vi[32];    /**< VI0 to VI15, then the control registers: 16 status, 17 MAC, 18 clip,
	                         20 R, 21 I, 22 Q, 23 P, 26 TPC, 27 CMSAR0, 28 FBRST, 29 VPU_STAT. */
	uint32_t acc[4];    /**< ACC x y z w. */
	uint32_t q, p;      /**< The Q and P registers as the unit holds them. */
} pcsx2hook_vu_regs;

/**
 * @brief Copies the EE scratchpad (0x70000000, 16 KB), which ::pcsx2hook_map_guest cannot reach.
 * @return Bytes copied, at most 16384, zero before the VM is up.
 * @note From a hook handler or @c on_frame, the threads that own the EE.
 */
PCSX2HOOK_API size_t pcsx2hook_read_scratchpad(pcsx2hook_ctx* ctx, void* out, size_t size);

/**
 * @brief Copies a vector unit's data memory: VU0 4 KB, VU1 16 KB.
 * @param unit 0 or 1
 * @return Bytes copied; zero for another unit or before the VM is up.
 * @note The unit's state as the interpreter or recompiler last left it. For VU0 in macro mode
 *       that is the state at a COP2 instruction boundary, which a hook entry always is.
 */
PCSX2HOOK_API size_t pcsx2hook_read_vu_memory(pcsx2hook_ctx* ctx, int unit, void* out, size_t size);

/** @brief Copies a vector unit's registers. @return Non-zero on success, zero for another unit. */
PCSX2HOOK_API int pcsx2hook_read_vu_regs(pcsx2hook_ctx* ctx, int unit, pcsx2hook_vu_regs* out);

/** Called for each EE store in the armed range. @p pc is the storing instruction's address and
 *  @p value the low 64 bits stored. */
typedef void (*pcsx2hook_write_fn)(uint32_t addr, uint32_t size, uint64_t value, uint32_t pc,
                                   void* user);

/**
 * @brief Reports EE stores to [lo, hi) through @p fn. A NULL @p fn disarms.
 *
 * Arming runs the EE in the interpreter, so @p pc is exact (the recompiler only knows the
 * start of its block) and every store reaches the sink. The run is slower; an unarmed run pays
 * nothing. It sees stores the EE issues, not DMA, VIF or IOP writes. Resolve @p pc to a
 * function with pcsx2hook_resolve_symbol. Call before pcsx2hook_init, which reads the setting.
 * @return Zero with last_error set when lo >= hi or the VM is already running.
 */
PCSX2HOOK_API int pcsx2hook_set_write_sink(pcsx2hook_ctx* ctx, uint32_t lo, uint32_t hi,
                                           pcsx2hook_write_fn fn, void* user);

/** @brief The EE program counter, for a sampler or a heartbeat. */
PCSX2HOOK_API uint32_t pcsx2hook_get_ee_pc(pcsx2hook_ctx* ctx);

/** @brief The disc serial, such as @c "SLUS-21621". Empty before boot, owned by the context. */
PCSX2HOOK_API const char* pcsx2hook_get_disc_serial(pcsx2hook_ctx* ctx);

/** @brief The rounding mode the emulated unit runs under: 0 nearest, 1 toward
 *  negative, 2 toward positive, 3 chop, and -1 for a name this does not know.
 *  @p which is @c "ee", @c "eediv", @c "vu0" or @c "vu1". The game database
 *  overrides the EE's per title, so a capture that is a float reference has to
 *  record what it ran under rather than assume the default. */
PCSX2HOOK_API int pcsx2hook_get_round_mode(pcsx2hook_ctx* ctx, const char* which);

/** @brief The clamping modes of the recompiler for one unit, as a bit set: bit 0 overflow,
 *  bit 1 extra overflow, bit 2 sign overflow (VU) or full mode (EE), bit 3 underflow (VU, never
 *  set for the EE). @p which is @c "ee", @c "vu0" or @c "vu1"; -1 for a name this does not know.
 *  Interpreters clamp as the hardware does regardless, so this describes the recompiler. */
PCSX2HOOK_API int pcsx2hook_get_clamp_mode(pcsx2hook_ctx* ctx, const char* which);

/** @brief Boots this ELF instead of the disc's own, with the disc still mounted. */
PCSX2HOOK_API void pcsx2hook_set_boot_elf(pcsx2hook_ctx* ctx, const char* path);

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
 * @brief Writes the emulated frame buffer to an uncompressed PNG file.
 * @return Non-zero on success, zero when there is nothing to read or the file cannot be written.
 * @note Seeing where a run actually reached is often the fastest way to explain a trace, so this
 *       saves every host reimplementing the read-and-encode.
 */
PCSX2HOOK_API int pcsx2hook_write_framebuffer(pcsx2hook_ctx* ctx, const char* path);

/**
 * @brief Reads a texture out of GS memory, unswizzled and through its CLUT.
 *
 * The GS keeps a texture long after the game has dropped its own copy, which is the only way to
 * recover one a savestate was taken after the game uploaded.
 *
 * Values come back raw: a paletted format gives its indices, so the caller applies its own palette
 * and nothing here touches the renderer's CLUT cache. Reading through that cache instead leaves it
 * loaded for a TEX0 the game never asked for, and the emulated draws after it crash.
 *
 * @param tbp0 Word address of the buffer, in 64-word units, as GS TEX0 states it.
 * @param tbw Buffer width in 64-pixel units.
 * @param psm GS pixel storage mode.
 * @param width Texels per row to read.
 * @param height Rows to read.
 * @param out Receives width*height values, one per texel, or null to ask for the count.
 * @param count Values @p out can hold.
 * @return Values the read needs, or 0 if there is no GS to read.
 */
PCSX2HOOK_API size_t pcsx2hook_read_gs_pixels(pcsx2hook_ctx* ctx, uint32_t tbp0, uint32_t tbw,
	uint32_t psm, uint32_t width, uint32_t height, uint32_t* out, size_t count);

/**
 * @brief Reads the GS's local memory whole, the 4 MB a GS dump's state blob carries.
 * @param out Receives the bytes, or null to ask for the size.
 * @param size Bytes @p out can hold.
 * @return Bytes the read needs, or 0 when there is no renderer.
 * @note Runs on the GS thread and waits, so everything queued before the call has been drawn
 *       into it: called from a hook at a DMA kick, it is the memory the chain starts from.
 */
PCSX2HOOK_API size_t pcsx2hook_read_gs_memory(pcsx2hook_ctx* ctx, void* out, size_t size);

/**
 * @brief Reads the GS's drawing environment as a GIF A+D list: the register file a draw reads.
 *
 * One quadword per register, the value in the low 64 bits and the register number in the high
 * 64, which is the GIF's own A+D encoding, so a host replays them through whatever already
 * handles a register write. 35 registers in ascending order: PRIM, PRMODECONT, PRMODE, TEXCLUT,
 * SCANMSK, TEXA, FOGCOL, DIMX, DTHE, COLCLAMP, PABE, and per context TEX0, CLAMP, TEX1,
 * XYOFFSET, MIPTBP1, MIPTBP2, SCISSOR, ALPHA, TEST, FBA, FRAME and ZBUF. The transfer registers
 * are left out: they are the state of a transfer in flight, not of a draw.
 *
 * @param out Receives the quadwords, or null to ask for the size.
 * @param size Bytes @p out can hold.
 * @return Bytes the read needs, or 0 when there is no renderer.
 * @note Runs on the GS thread and waits, like ::pcsx2hook_read_gs_memory, so it is the state
 *       everything queued before the call left behind.
 */
PCSX2HOOK_API size_t pcsx2hook_read_gs_registers(pcsx2hook_ctx* ctx, void* out, size_t size);

/** @brief The buffer the display circuit is reading, and the size it is shown at. */
typedef struct
{
	uint32_t circuit; /**< 0 or 1, the circuit whose registers these are. */
	uint32_t block;   /**< DISPFB's base in 64-word blocks, as TEX0 and FRAME state a base. */
	uint32_t fbw;     /**< Buffer width in 64-pixel units. */
	uint32_t psm;     /**< Pixel storage mode. */
	uint32_t dbx;     /**< Where in the buffer the shown region starts. */
	uint32_t dby;
	uint32_t width;  /**< DISPLAY's own size, DW+1 over MAGH+1 by DH+1 over MAGV+1. */
	uint32_t height; /**< Rows the circuit shows, which an interlaced pair of fields fills. */
	uint32_t magh;
	uint32_t magv;
	uint32_t dx; /**< DISPLAY's own position on the screen, DX in VCK units and DY in scanlines. */
	uint32_t dy;
	uint32_t dw; /**< DISPLAY's DW and DH as stated, before MAGH and MAGV divide them. */
	uint32_t dh;
	uint32_t interlace; /**< SMODE2's INT, the interlaced output. */
	uint32_t ffmd;  /**< SMODE2's FFMD: 0 reads every other row of the buffer per field, 1 every
	                     row, so a FFMD 1 pair of buffers is woven by the field's own parity. */
	uint32_t field; /**< CSR's FIELD at the read, the field the circuit is showing. */
} pcsx2hook_gs_display;

/**
 * @brief Reads which frame buffer the display circuit shows. @return Non-zero on success.
 * @note The circuit's base is not the one a chain draws into: a game that flips reads one buffer
 *       while the GS writes the other, so this answers what is on screen while
 *       ::pcsx2hook_read_gs_registers' FRAME answers where a draw lands.
 */
PCSX2HOOK_API int pcsx2hook_read_gs_display(pcsx2hook_ctx* ctx, pcsx2hook_gs_display* out);

/**
 * @brief Reads a frame buffer out of GS local memory, the way the display circuit reads one.
 *
 * ::pcsx2hook_read_gs_pixels answers with a texture's own values; this answers with pixels, so a
 * 24 bit buffer comes back opaque rather than with the alpha the format does not carry.
 *
 * The alpha byte is the one GS memory holds, in the GS's own units where 128 is opaque, because a
 * destination alpha test reads it. ::pcsx2hook_write_png drops it; ::pcsx2hook_write_png_gray
 * writes it as a plane of its own.
 *
 * @param block Base in 64-word blocks, which is FRAME's FBP times 32.
 * @param fbw Buffer width in 64-pixel units, as FRAME states it.
 * @param psm GS pixel storage mode.
 * @param x First column to read, @p y first row.
 * @param width Pixels per row to read, @p height rows.
 * @param out Receives width*height pixels as RGBA8, or null to ask for the count.
 * @param count Pixels @p out can hold.
 * @return Pixels the read needs, or 0 if there is no GS to read.
 * @note Runs on the GS thread and waits, like ::pcsx2hook_read_gs_memory, so everything queued
 *       before the call has been drawn into it.
 */
PCSX2HOOK_API size_t pcsx2hook_read_gs_frame(pcsx2hook_ctx* ctx, uint32_t block, uint32_t fbw,
	uint32_t psm, uint32_t x, uint32_t y, uint32_t width, uint32_t height, uint32_t* out,
	size_t count);

/**
 * @brief Writes RGBA8 pixels as an uncompressed PNG, the encoder ::pcsx2hook_write_framebuffer
 *        uses. @return Non-zero on success.
 * @note The alpha is dropped. A host that reads a buffer of its own choosing needs the same
 *       encoder, and a second copy of it is a second thing to be wrong.
 */
PCSX2HOOK_API int pcsx2hook_write_png(pcsx2hook_ctx* ctx, const char* path,
	const uint32_t* pixels, uint32_t width, uint32_t height);

/** @brief One snapshot of a draw target, taken on the GS thread after a named batch drew. */
typedef struct
{
	uint64_t burst;  /**< The GIF burst the batch's primitives arrived in, as asked for. */
	uint32_t block;  /**< The batch's own FRAME: base in 64-word blocks, width, storage mode. */
	uint32_t fbw;
	uint32_t psm;
	uint32_t width;  /**< Pixels per row handed over, @p height rows, in @p pixels as RGBA8 with
	                      the alpha GS memory holds. */
	uint32_t height;
	uint32_t field;  /**< CSR's FIELD at the snapshot, which is the field on screen now and so the
	                      other one from the field this chain is drawing. */
	uint32_t skipped; /**< The batch was suppressed, so the buffer did not change. */
	const uint32_t* pixels; /**< Valid for the call only. */
} pcsx2hook_gs_snap;

/**
 * @brief Takes a snapshot of the draw target after each batch whose burst ::PCSX2HOOK_GS_SNAP_AT
 *        names, and hands it to @p sink.
 *
 * The frame reader answers what a chain left; this answers what one batch of it left, which is the
 * only way to see a value a later batch of the same chain writes over, such as the destination
 * alpha a stencil pass marks and the quad after it consumes.
 *
 * `PCSX2HOOK_GS_SNAP_AT` is a comma-separated list of absolute GIF burst ordinals, the ones the GS
 * trace's rows and the kick rows carry. Each is taken once, at the first batch of that burst.
 *
 * @note The sink runs on the GS thread with the rasteriser drained, inside the flush, so it must
 *       not call back into this API: everything here that reads the GS queues onto that thread and
 *       would deadlock. Write the pixels and return.
 */
PCSX2HOOK_API void pcsx2hook_set_gs_snap_sink(pcsx2hook_ctx* ctx,
	void (*sink)(const pcsx2hook_gs_snap* snap, void* user), void* user);

/**
 * @brief Adds burst ordinals to snapshot after, the same ones ::PCSX2HOOK_GS_SNAP_AT names.
 *
 * `PCSX2HOOK_GS_SNAP_AT` is read once, before the VM runs, so it can only carry an ordinal the
 * host knew then. **An absolute ordinal is not reproducible across runs of the same scene**: the
 * bursts the console's own boot sends vary, and the same frame of the same route measured 304
 * apart on two runs of SMT3's opening field. What is stable is a burst's offset inside a frame's
 * own chain, so a host that addresses a batch that way resolves the ordinal when the chain is
 * kicked and arms it here.
 */
PCSX2HOOK_API void pcsx2hook_arm_gs_snap(pcsx2hook_ctx* ctx, const uint64_t* bursts, size_t count);

/**
 * @brief Writes one byte per pixel as an 8 bit greyscale uncompressed PNG. @return Non-zero on
 *        success.
 * @note For a plane a colour picture cannot carry: the alpha
 *       ::pcsx2hook_read_gs_frame read, as stored.
 */
PCSX2HOOK_API int pcsx2hook_write_png_gray(pcsx2hook_ctx* ctx, const char* path,
	const uint8_t* values, uint32_t width, uint32_t height);

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

/**
 * @brief The address of a named symbol, for hooking by name rather than by a hardcoded address.
 * @return 0 when no map is loaded or it does not name @p name, which a caller must treat as "do not
 *         hook" rather than as an address.
 */
PCSX2HOOK_API uint32_t pcsx2hook_find_symbol(pcsx2hook_ctx* ctx, const char* name);

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

/** @} */

/** @name Command stream
 *  Needs @c PCSX2HOOK_GS_STREAM set.
 *  @{ */

/**
 * @brief Transfers the command stream has written so far.
 * @note Read from a hook handler to cut the file where the guest kicked
 *       something, instead of at the frame boundary the writer records. The
 *       GIF is fed from the EE thread, so the count is exact there.
 */
PCSX2HOOK_API uint64_t pcsx2hook_get_gs_stream_transfers(pcsx2hook_ctx* ctx);

/** @} */

/** @name GS trace, continued
 *  @{ */

/** @brief The last complete frame's batches as JSON rows. A null @p out asks for the size. */
PCSX2HOOK_API size_t pcsx2hook_get_gs_rows(pcsx2hook_ctx* ctx, uint32_t frame, char* out, size_t size);

/** @brief Appends the last complete frame's rows to @p path. @return Rows written. */
PCSX2HOOK_API size_t pcsx2hook_write_gs_last_frame(pcsx2hook_ctx* ctx, const char* path);

/** @} */

/**
 * @defgroup gs_software The software rasteriser on its own
 * @brief PCSX2's software GS, driven by a host that owns the graphics interface itself.
 *
 * No context: these do not boot or run a machine, they only rasterise what is handed to them, so a
 * host emulating its own PS2 can see what its graphics stream draws. There is no device behind the
 * renderer, which is why the picture comes back as pixels rather than being presented.
 * @code
 * pcsx2hook_gs_open(registers, PCSX2HOOK_GS_SOFTWARE, NULL, NULL, 0);
 * ... pcsx2hook_gs_transfer(path, data, bytes) as the interface hands packets over ...
 * pcsx2hook_gs_end_field(field);
 * pcsx2hook_gs_read_display(pixels, capacity, &width, &height);
 * @endcode
 * @{
 */

/** @brief Which renderer to draw with. Anything but ::PCSX2HOOK_GS_SOFTWARE needs a window. */
typedef enum
{
	PCSX2HOOK_GS_SOFTWARE = 0,
	PCSX2HOOK_GS_AUTO,     /**< Whatever the platform prefers. */
	PCSX2HOOK_GS_OPENGL,
	PCSX2HOOK_GS_VULKAN,
	PCSX2HOOK_GS_D3D11,
	PCSX2HOOK_GS_D3D12,
	PCSX2HOOK_GS_METAL,
} pcsx2hook_gs_renderer;

/** @brief What each field of ::pcsx2hook_window means. */
typedef enum
{
	PCSX2HOOK_WINDOW_NONE = 0, /**< Nothing is shown; the host reads the picture instead. */
	PCSX2HOOK_WINDOW_WIN32,    /**< @c handle is the HWND. */
	PCSX2HOOK_WINDOW_X11,      /**< @c display is the Display*, @c handle the window id. */
	PCSX2HOOK_WINDOW_WAYLAND,  /**< @c display is the wl_display*, @c handle the wl_surface*. */
	PCSX2HOOK_WINDOW_MACOS,    /**< @c handle is the NSView*, not the window. */
} pcsx2hook_window_type;

/** @brief A window the host owns and lends to the renderer. */
typedef struct
{
	int type; /**< One of ::pcsx2hook_window_type. */
	void* display;
	void* handle;
	uint32_t width;
	uint32_t height;
	float scale; /**< Pixels per point, 1.0 where the display is not scaled. */
} pcsx2hook_window;

/**
 * @brief Opens a renderer.
 * @param privileged_registers The 8192 byte register window, read as the renderer draws, so it
 *        must outlive the renderer and hold what the guest wrote.
 * @param renderer One of ::pcsx2hook_gs_renderer.
 * @param window The window to draw into, or NULL for none. Without one only the software renderer
 *        can be opened, and the picture comes back through ::pcsx2hook_gs_read_display.
 * @param resources PCSX2's resources directory, which a hardware renderer reads its shaders from.
 *        NULL looks for it beside the program, which is where a host that loaded this library is,
 *        not where the library came from.
 * @param threads Extra rasteriser threads for the software renderer; 0 draws on the calling thread.
 * @return Non-zero on success.
 * @note Call this, and everything else here, from one thread: a graphics device belongs to the
 *       thread that made it.
 */
PCSX2HOOK_API int pcsx2hook_gs_open(uint8_t* privileged_registers, int renderer,
	const pcsx2hook_window* window, const char* resources, int threads);

/** @brief Says the window changed size. Ignored when there is no window. */
PCSX2HOOK_API void pcsx2hook_gs_resize(uint32_t width, uint32_t height, float scale);

/** @brief Closes it, freeing local memory. */
PCSX2HOOK_API void pcsx2hook_gs_close(void);

/** @brief One burst of a graphics packet, down path 1, 2 or 3. */
PCSX2HOOK_API void pcsx2hook_gs_transfer(int path, const uint8_t* data, uint32_t bytes);

/** @brief Draws everything pending. @param field 0 or 1, as the interface reports it. */
PCSX2HOOK_API void pcsx2hook_gs_end_field(int field);

/**
 * @brief The displayed frame buffer, as 32 bit pixels.
 * @return Non-zero when a frame was written, zero when the registers point at nothing or the
 *         buffer is too small for it.
 */
PCSX2HOOK_API int pcsx2hook_gs_read_display(uint32_t* pixels, int capacity, int* width,
	int* height);

/** @brief The same frame, written as a PNG. @return Non-zero on success. */
PCSX2HOOK_API int pcsx2hook_gs_write_display(const char* path);

/**
 * @brief The frame as the renderer would show it, which is the only way to see one a hardware
 *        renderer drew: it keeps the picture on the graphics card rather than in local memory.
 * @return Non-zero when a frame was written.
 */
PCSX2HOOK_API int pcsx2hook_gs_snapshot(uint32_t* pixels, int capacity, int* width, int* height);

/** @} */

/** @brief Writes out every enabled trace. A killed process writes none. */
PCSX2HOOK_API void pcsx2hook_flush_traces(pcsx2hook_ctx* ctx);

/** @brief Why the last call that reported failure failed. Owned by the context. */
PCSX2HOOK_API const char* pcsx2hook_get_last_error(pcsx2hook_ctx* ctx);

#ifdef __cplusplus
}
#endif

#endif

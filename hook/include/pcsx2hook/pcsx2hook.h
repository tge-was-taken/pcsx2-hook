// SPDX-FileCopyrightText: 2002-2026 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

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

typedef struct
{
	const char* disc;
	const char* bios_dir;
	const char* bios_file;
	const char* dump_dir;
	const char* symbols;
	int surfaceless;
	int interpreter;
	int software_gs;
} pcsx2hook_config;

// The EE register file at a hooked call. gpr has a 128-bit stride, so register n's low word is at
// gpr[n * 4]; reg64 exists because the file is not 8-byte aligned in every host.
typedef struct
{
	uint32_t* gpr;
	float* fpr;
	uint32_t pc;
} pcsx2hook_regs;

enum
{
	PCSX2HOOK_CONTINUE = 0,
	PCSX2HOOK_EXIT = 1
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

PCSX2HOOK_API int pcsx2hook_register(pcsx2hook_ctx* ctx, uint32_t addr, pcsx2hook_pre_fn pre,
	pcsx2hook_post_fn post, void* user);

PCSX2HOOK_API uint32_t pcsx2hook_call_ee(pcsx2hook_ctx* ctx, uint32_t pc, const uint32_t* args, size_t count);

PCSX2HOOK_API void* pcsx2hook_guest(pcsx2hook_ctx* ctx, uint32_t addr, uint32_t size);

PCSX2HOOK_API int pcsx2hook_boot(pcsx2hook_ctx* ctx);
PCSX2HOOK_API int pcsx2hook_run_frames(pcsx2hook_ctx* ctx, uint32_t frames);
PCSX2HOOK_API int pcsx2hook_load_state(pcsx2hook_ctx* ctx, const char* path);
PCSX2HOOK_API int pcsx2hook_save_state(pcsx2hook_ctx* ctx, const char* path);

PCSX2HOOK_API size_t pcsx2hook_read_framebuffer(pcsx2hook_ctx* ctx, void* out, size_t size,
	uint32_t* width, uint32_t* height);

PCSX2HOOK_API void pcsx2hook_flush(pcsx2hook_ctx* ctx);

PCSX2HOOK_API const char* pcsx2hook_last_error(pcsx2hook_ctx* ctx);

#ifdef __cplusplus
}
#endif

#endif

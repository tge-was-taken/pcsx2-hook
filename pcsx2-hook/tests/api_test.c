// Compiled as C, not C++: the header has to be usable from a plain C host.
#include "pcsx2hook/pcsx2hook.h"

#include <stdio.h>
#include <string.h>

static int failures;

static void check(int ok, const char* what) {
	if (!ok) {
		fprintf(stderr, "FAIL %s\n", what);
		failures++;
	}
}

static void onFrame(uint32_t frame, void* user) {
	(void)frame;
	*(int*)user += 1;
}

int main(void) {
	check(pcsx2hook_create(NULL) == NULL, "create(NULL) returns NULL");

	// Every accessor has to tolerate a null context: a host that failed to create one should get an
	// error back, not a crash.
	check(pcsx2hook_mem_map(NULL, 0x100000, 4) == NULL, "mem_map(NULL)");
	check(pcsx2hook_mem_get_ram_base(NULL, NULL) == NULL, "mem_get_ram_base(NULL)");
	check(pcsx2hook_get_ee_pc(NULL) == 0, "get_ee_pc(NULL)");
	check(pcsx2hook_is_finished(NULL) == 0, "is_finished(NULL)");
	check(pcsx2hook_trace_arm(NULL, PCSX2HOOK_TRACE_GS) == 0, "trace_arm(NULL)");
	check(pcsx2hook_hook_add(NULL, 0x100000, NULL, NULL, NULL) == 0, "hook_add(NULL)");
	check(pcsx2hook_state_load(NULL, "x.p2s") == 0, "state_load(NULL)");
	check(pcsx2hook_gs_read_framebuffer(NULL, NULL, 0, NULL, NULL) == 0, "gs_read_framebuffer(NULL)");
	check(pcsx2hook_gs_get_rows(NULL, 0, NULL, 0) == 0, "gs_get_rows(NULL)");
	check(pcsx2hook_symbols_resolve(NULL, 0x100000, NULL, 0) == 0, "symbols_resolve(NULL)");
	pcsx2hook_draw_push(NULL, "test", 0, 0); // must not crash
	pcsx2hook_draw_pop(NULL);
	pcsx2hook_destroy(NULL);

	int frames = 0;
	pcsx2hook_config cfg;
	memset(&cfg, 0, sizeof(cfg));
	cfg.bios_dir = "assets";
	cfg.bios_file = "bios.bin";
	cfg.surfaceless = 1;
	cfg.on_frame = &onFrame;
	cfg.user = &frames;

	pcsx2hook_ctx* ctx = pcsx2hook_create(&cfg);
	check(ctx != NULL, "create returns a context");
	if (ctx) {
		// The config is copied, so a caller may reuse its own struct straight after.
		memset(&cfg, 0, sizeof(cfg));
		check(pcsx2hook_is_finished(ctx) == 0, "a fresh context is not finished");
		check(pcsx2hook_get_disc_serial(ctx) != NULL, "disc serial is never NULL");
		check(pcsx2hook_get_last_error(ctx) != NULL, "last error is never NULL");
		check(pcsx2hook_trace_arm(ctx, PCSX2HOOK_TRACE_EXEC) != 0, "arming a known trace succeeds");
		check(pcsx2hook_trace_arm(ctx, (pcsx2hook_trace)999) == 0, "arming an unknown trace fails");
		check(strlen(pcsx2hook_get_last_error(ctx)) > 0, "a failed call sets last_error");
		// Balanced push/pop against a real context, and a null label.
		pcsx2hook_draw_push(ctx, "atomic", 1, 2);
		pcsx2hook_draw_push(ctx, NULL, 0, 0);
		pcsx2hook_draw_pop(ctx);
		pcsx2hook_draw_pop(ctx);
		pcsx2hook_destroy(ctx);
	}

	printf(failures ? "%d failed\n" : "all passed\n", failures);
	return failures != 0;
}

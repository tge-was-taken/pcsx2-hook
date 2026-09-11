// Compiled as C, not C++: the header has to be usable from a plain C host.
//
// Covers what a caller can reach without booting a disc, which is mostly symbol resolution and the
// size-query buffer contract every string and pixel getter shares.
#include "pcsx2hook/pcsx2hook.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int failures;

static void check(int ok, const char* what) {
	if (!ok) {
		fprintf(stderr, "FAIL %s\n", what);
		failures++;
	}
}

static void checkStr(const char* got, const char* want, const char* what) {
	if (strcmp(got, want) != 0) {
		fprintf(stderr, "FAIL %s: got \"%s\", want \"%s\"\n", what, got, want);
		failures++;
	}
}

static char mapPath[512];

// Both formats the loader accepts, deliberately out of address order so the sort is exercised: the
// resolver binary-searches and would return a neighbour if the entries were left as read.
static int writeMap(void) {
	snprintf(mapPath, sizeof(mapPath), "%s/pcsx2hook_test_%d.map",
	         getenv("TMPDIR") ? getenv("TMPDIR") : "/tmp", (int)getpid());
	FILE* f = fopen(mapPath, "w");
	if (!f) return 0;
	fputs("third = 0x00200000;\n", f);
	fputs("first = 0x00100000;\n", f);
	fputs(" 0001:00100100       second\n", f); // linker-map form
	fputs("not a symbol line\n", f);           // must be skipped, not parsed as an entry
	fclose(f);
	return 1;
}

static void resolve(pcsx2hook_ctx* ctx, uint32_t pc, char* out, size_t size) {
	out[0] = '\0';
	pcsx2hook_resolve_symbol(ctx, pc, out, size);
}

static void testSymbols(pcsx2hook_ctx* ctx) {
	char buf[128];

	pcsx2hook_load_symbols(ctx);

	resolve(ctx, 0x00100000, buf, sizeof(buf));
	checkStr(buf, "first+0x0", "an exact hit reads as offset zero");

	resolve(ctx, 0x00100010, buf, sizeof(buf));
	checkStr(buf, "first+0x10", "an interior address reads as an offset");

	// Both formats loaded, and the out-of-order entries got sorted.
	resolve(ctx, 0x00100100, buf, sizeof(buf));
	checkStr(buf, "second+0x0", "the linker-map form parses and sorts with the rest");

	resolve(ctx, 0x00200000, buf, sizeof(buf));
	checkStr(buf, "third+0x0", "the entry written first by address resolves");

	// The next symbol wins wherever there is one, so the trust span is measured past the last.
	resolve(ctx, 0x00100400, buf, sizeof(buf));
	checkStr(buf, "second+0x300", "the nearest symbol below wins, not the first");

	// A linker map lists publics only, so past the trust span the resolver stops asserting
	// containment and prints the raw address too.
	resolve(ctx, 0x00200000 + 0x400, buf, sizeof(buf));
	checkStr(buf, "third+0x400", "at the trust span the offset alone is still claimed");
	resolve(ctx, 0x00200000 + 0x401, buf, sizeof(buf));
	checkStr(buf, "third+0x401 (0x00200401)", "past the trust span the raw address is printed too");

	// Below the first symbol there is nothing to attribute it to.
	resolve(ctx, 0x00000010, buf, sizeof(buf));
	checkStr(buf, "0x00000010", "an address below every symbol reads as a raw address");

	check(pcsx2hook_is_in_code_range(ctx, 0x00100000) == 1, "the first symbol is in range");
	check(pcsx2hook_is_in_code_range(ctx, 0x00200000) == 1, "the last symbol is in range");
	check(pcsx2hook_is_in_code_range(ctx, 0x00000010) == 0, "below the map is out of range");
	check(pcsx2hook_is_in_code_range(ctx, 0x00300000) == 0, "above the map is out of range");
}

// Every string and pixel getter shares one contract: a null buffer asks for the size, the answer
// includes the terminator, and a buffer too small to hold it is left untouched.
static void testSizeContract(pcsx2hook_ctx* ctx) {
	const size_t need = pcsx2hook_resolve_symbol(ctx, 0x00100000, NULL, 0);
	check(need == strlen("first+0x0") + 1, "a null buffer returns the length plus the terminator");

	char small[4] = {'\xAA', '\xAA', '\xAA', '\xAA'};
	check(pcsx2hook_resolve_symbol(ctx, 0x00100000, small, sizeof(small)) == need,
	      "a short buffer still reports what was needed");
	check(small[0] == '\xAA', "a short buffer is not written to");

	char exact[16];
	check(pcsx2hook_resolve_symbol(ctx, 0x00100000, exact, need) == need,
	      "a buffer of exactly the needed size is accepted");
	checkStr(exact, "first+0x0", "an exactly-sized buffer gets the whole string");
}

static void testErrors(pcsx2hook_ctx* ctx) {
	check(pcsx2hook_get_last_error(ctx) != NULL, "last_error is never null");

	check(pcsx2hook_enable_trace(ctx, PCSX2HOOK_TRACE_EXEC) != 0, "enabling a known trace succeeds");
	check(pcsx2hook_enable_trace(ctx, PCSX2HOOK_TRACE_VU_INSN) != 0, "the VU vector trace is known");
	check(pcsx2hook_enable_trace(ctx, PCSX2HOOK_TRACE_VIF_CMD) != 0, "the VIF vector trace is known");
	check(pcsx2hook_enable_trace(ctx, PCSX2HOOK_TRACE_SPU) != 0, "the SPU2 vector trace is known");
	check(pcsx2hook_enable_trace(ctx, PCSX2HOOK_TRACE_TIMING) != 0, "the timing trace is known");
	check(pcsx2hook_enable_trace(ctx, (pcsx2hook_trace)999) == 0, "enabling an unknown trace fails");
	check(strlen(pcsx2hook_get_last_error(ctx)) > 0, "a failed call leaves a reason behind");

	// Only the calls that answer from host state belong here. Anything that reaches the VM or the
	// GS thread waits on something that was never started, so the boot test covers those.
	check(pcsx2hook_map_guest(ctx, 0x00100000, 4) == NULL, "no guest memory before the VM is up");
	check(pcsx2hook_get_ram_base(ctx, NULL) == NULL, "no RAM base before the VM is up");
}

// A null context must be tolerated everywhere: a host whose create failed should get an error back
// rather than a crash on the next call.
static void testNullContext(void) {
	check(pcsx2hook_create(NULL) == NULL, "create(NULL) returns NULL");
	check(pcsx2hook_map_guest(NULL, 0x100000, 4) == NULL, "mem_map");
	check(pcsx2hook_get_ram_base(NULL, NULL) == NULL, "mem_get_ram_base");
	check(pcsx2hook_get_ee_pc(NULL) == 0, "get_ee_pc");
	check(pcsx2hook_is_finished(NULL) == 0, "is_finished");
	check(pcsx2hook_enable_trace(NULL, PCSX2HOOK_TRACE_GS) == 0, "enable_trace");
	check(pcsx2hook_add_hook(NULL, 0x100000, NULL, NULL, NULL) == 0, "hook_add");
	check(pcsx2hook_load_state(NULL, "x.p2s") == 0, "state_load");
	check(pcsx2hook_read_framebuffer(NULL, NULL, 0, NULL, NULL) == 0, "gs_read_framebuffer");
	check(pcsx2hook_get_gs_rows(NULL, 0, NULL, 0) == 0, "gs_get_rows");
	check(pcsx2hook_resolve_symbol(NULL, 0x100000, NULL, 0) == 0, "symbols_resolve");
	check(pcsx2hook_take_gs_capture(NULL, NULL, 0, NULL, NULL, NULL) == 0, "gs_take_capture");
	pcsx2hook_set_interpreter(NULL, PCSX2HOOK_CPU_VU1);
	pcsx2hook_set_accurate_timing(NULL, 1);
	pcsx2hook_set_boot_state(NULL, "x.p2s");
	pcsx2hook_set_frame_limit(NULL, 1);
	pcsx2hook_push_draw(NULL, "test", 0, 0);
	pcsx2hook_pop_draw(NULL);
	pcsx2hook_flush_traces(NULL);
	pcsx2hook_destroy(NULL);
}

// The draw stack is write-only from out here, so this asserts only that it survives the shapes a
// host can hand it: a null label, one longer than the buffer, and more pops than pushes.
static void testDrawStack(pcsx2hook_ctx* ctx) {
	char longLabel[128];
	memset(longLabel, 'x', sizeof(longLabel) - 1);
	longLabel[sizeof(longLabel) - 1] = '\0';

	pcsx2hook_push_draw(ctx, "atomic", 1, 2);
	pcsx2hook_push_draw(ctx, NULL, 0, 0);
	pcsx2hook_push_draw(ctx, longLabel, 0, 0);
	pcsx2hook_pop_draw(ctx);
	pcsx2hook_pop_draw(ctx);
	pcsx2hook_pop_draw(ctx);
	pcsx2hook_pop_draw(ctx); // unbalanced: must not underflow
	check(1, "the draw stack survives null, oversized and unbalanced use");
}

// Real boot, only when the caller supplies a BIOS and something to boot. Everything above answers
// from host state; this is the only part that proves the lifecycle and the callbacks actually run.
//   PCSX2HOOK_TEST_BIOS=<path to a BIOS image>  PCSX2HOOK_TEST_IMAGE=<disc or ELF>
struct BootState {
	int settings, vmReady, frames, shutdown;
	pcsx2hook_ctx* ctx;
};

static struct BootState boot;

static void bootOnSettings(void* user) { ((struct BootState*)user)->settings++; }

static void bootOnVmReady(void* user) {
	struct BootState* b = user;
	b->vmReady++;
	// Guest RAM is mapped by now, which is the contract on_vm_ready exists to provide.
	uint32_t size = 0;
	check(pcsx2hook_get_ram_base(b->ctx, &size) != NULL, "ram base is mapped at on_vm_ready");
	check(size >= 32u * 1024 * 1024, "main RAM is at least 32 MB");
	check(pcsx2hook_map_guest(b->ctx, 0x00100000, 16) != NULL, "a mapped guest address resolves");
	check(pcsx2hook_map_guest(b->ctx, 0xFFFFFFF0, 16) == NULL, "an unmapped guest address does not");
}

static void bootOnFrame(uint32_t frame, void* user) {
	struct BootState* b = user;
	b->frames++;
	check(frame == (uint32_t)b->frames, "the frame counter increments by one per callback");
	if (b->frames >= 20) pcsx2hook_request_stop(b->ctx);
}

static void bootOnShutdown(void* user) { ((struct BootState*)user)->shutdown++; }

static int testBoot(void) {
	const char* bios = getenv("PCSX2HOOK_TEST_BIOS");
	const char* image = getenv("PCSX2HOOK_TEST_IMAGE");
	if (!bios || !image) {
		printf("skipping the boot test: set PCSX2HOOK_TEST_BIOS and PCSX2HOOK_TEST_IMAGE\n");
		return 0;
	}

	pcsx2hook_config cfg;
	memset(&cfg, 0, sizeof(cfg));
	cfg.bios = bios;
	cfg.surfaceless = 1;
	cfg.on_settings = &bootOnSettings;
	cfg.on_vm_ready = &bootOnVmReady;
	cfg.on_frame = &bootOnFrame;
	cfg.on_shutdown = &bootOnShutdown;
	cfg.user = &boot;

	boot.ctx = pcsx2hook_create(&cfg);
	if (!boot.ctx) {
		check(0, "create for the boot test");
		return 1;
	}

	char* argv[] = {(char*)"pcsx2hook_api_test", (char*)image, NULL};
	pcsx2hook_early_init(boot.ctx);
	if (!pcsx2hook_init(boot.ctx, 2, argv)) {
		// Going on from here reaches the CPU thread with no settings layer and crashes there
		// instead of reporting, which hides whatever init actually objected to.
		check(0, "init accepts the image");
		pcsx2hook_destroy(boot.ctx);
		return 1;
	}
	pcsx2hook_apply_settings(boot.ctx);
	check(boot.settings == 1, "on_settings ran once, from apply_settings");

	check(pcsx2hook_enable_trace(boot.ctx, PCSX2HOOK_TRACE_EXEC) != 0, "the exec trace is enabled");
	// start returns as soon as the CPU thread is running, so on_vm_ready has not necessarily fired
	// yet; it is checked after the join instead.
	check(pcsx2hook_start(boot.ctx) != 0, "start boots and returns");

	pcsx2hook_pump_window(boot.ctx, 1);
	pcsx2hook_join(boot.ctx);

	// The regression this exists for: the per-frame callback was declared, overridden and never
	// called, so a host's per-frame work silently never ran.
	check(boot.vmReady == 1, "on_vm_ready ran once");
	check(boot.frames >= 20, "on_frame ran for every emulated frame");
	check(strlen(pcsx2hook_get_disc_serial(boot.ctx)) > 0, "a booted disc reports a serial");

	pcsx2hook_flush_traces(boot.ctx);
	pcsx2hook_shutdown(boot.ctx);
	check(boot.shutdown == 1, "on_shutdown ran once");
	pcsx2hook_destroy(boot.ctx);
	return 1;
}

static void testDestroyWhileRunning(void) {
	const char* bios = getenv("PCSX2HOOK_TEST_BIOS");
	const char* image = getenv("PCSX2HOOK_TEST_IMAGE");
	if (!bios || !image) {
		printf("skipping the destroy-while-running test: set PCSX2HOOK_TEST_BIOS and _IMAGE\n");
		return;
	}

	pcsx2hook_config cfg;
	memset(&cfg, 0, sizeof(cfg));
	cfg.bios = bios;
	cfg.surfaceless = 1;

	pcsx2hook_ctx* ctx = pcsx2hook_create(&cfg);
	check(ctx != NULL, "create for the destroy test");
	if (!ctx) return;

	char* argv[] = {(char*)"pcsx2hook_api_test", (char*)image, NULL};
	pcsx2hook_early_init(ctx);
	if (!pcsx2hook_init(ctx, 2, argv)) {
		check(0, "init for the destroy test");
		pcsx2hook_destroy(ctx);
		return;
	}
	pcsx2hook_apply_settings(ctx);
	check(pcsx2hook_start(ctx) != 0, "start for the destroy test");

	pcsx2hook_destroy(ctx);
	check(1, "destroying a running context returns rather than terminating");
}

enum { kFrameLimit = 10, kFallbackStopFrame = 100 };

struct RunControl {
	uint32_t lastFrame;
	pcsx2hook_ctx* ctx;
};

static void runControlOnFrame(uint32_t frame, void* user) {
	struct RunControl* r = user;
	r->lastFrame = frame;
	if (frame >= kFallbackStopFrame) pcsx2hook_request_stop(r->ctx);
}

static long fileSize(const char* dir, const char* name) {
	char path[640];
	snprintf(path, sizeof(path), "%s/%s", dir, name);
	FILE* f = fopen(path, "rb");
	if (!f) return -1;
	fseek(f, 0, SEEK_END);
	const long size = ftell(f);
	fclose(f);
	return size;
}

static int fileContains(const char* dir, const char* name, const char* text) {
	char path[640], line[4096];
	snprintf(path, sizeof(path), "%s/%s", dir, name);
	FILE* f = fopen(path, "r");
	if (!f) return 0;
	int found = 0;
	while (!found && fgets(line, sizeof(line), f)) found = strstr(line, text) != NULL;
	fclose(f);
	return found;
}

static const char* const kRunControlFiles[] = {
	"timing_timeline.jsonl", "vu_runs.jsonl", "vu_run_images.jsonl", "xgkick_hazards.jsonl",
	"vu0_vectors.jsonl", "vu0_forms.jsonl", "vu1_vectors.jsonl", "vu1_forms.jsonl",
};

static void testRunControl(void) {
	const char* bios = getenv("PCSX2HOOK_TEST_BIOS");
	const char* image = getenv("PCSX2HOOK_TEST_IMAGE");
	const char* state = getenv("PCSX2HOOK_TEST_STATE");
	if (!bios || !image) {
		printf("skipping the run-control test: set PCSX2HOOK_TEST_BIOS and _IMAGE\n");
		return;
	}

	char dir[512];
	snprintf(dir, sizeof(dir), "%s/pcsx2hook_test_%d", getenv("TMPDIR") ? getenv("TMPDIR") : "/tmp",
	         (int)getpid());

	struct RunControl rc = {0};
	pcsx2hook_config cfg;
	memset(&cfg, 0, sizeof(cfg));
	cfg.bios = bios;
	cfg.dump_dir = dir;
	cfg.surfaceless = 1;
	cfg.on_frame = &runControlOnFrame;
	cfg.user = &rc;

	rc.ctx = pcsx2hook_create(&cfg);
	check(rc.ctx != NULL, "create for the run-control test");
	if (!rc.ctx) return;

	pcsx2hook_set_config(rc.ctx, "PCSX2HOOK_NOMEMCARD", "1");
	pcsx2hook_set_frame_limit(rc.ctx, kFrameLimit);
	pcsx2hook_set_accurate_timing(rc.ctx, 1);
	pcsx2hook_set_interpreter(rc.ctx, PCSX2HOOK_CPU_VU0 | PCSX2HOOK_CPU_VU1);
	pcsx2hook_set_boot_state(rc.ctx, state);
	check(pcsx2hook_enable_trace(rc.ctx, PCSX2HOOK_TRACE_TIMING) != 0, "the timing trace is enabled");
	check(pcsx2hook_enable_trace(rc.ctx, PCSX2HOOK_TRACE_VU_INSN) != 0, "the VU vector trace is enabled");

	char* argv[] = {(char*)"pcsx2hook_api_test", (char*)image, NULL};
	pcsx2hook_early_init(rc.ctx);
	if (!pcsx2hook_init(rc.ctx, 2, argv)) {
		check(0, "init for the run-control test");
		pcsx2hook_destroy(rc.ctx);
		return;
	}
	pcsx2hook_apply_settings(rc.ctx);
	check(pcsx2hook_start(rc.ctx) != 0, "start for the run-control test");
	pcsx2hook_pump_window(rc.ctx, 1);
	pcsx2hook_join(rc.ctx);
	pcsx2hook_shutdown(rc.ctx);
	pcsx2hook_destroy(rc.ctx);

	check(rc.lastFrame == kFrameLimit, "the frame limit ends the run on the frame it names");
	check(fileContains(dir, "timing_timeline.jsonl", "\"ev\":\"vsync\""),
	      "the timing trace writes its timeline into dump_dir");
	check(fileSize(dir, "vu_runs.jsonl") >= 0, "the timing trace writes its run file");
	check(fileSize(dir, "vu1_forms.jsonl") >= 0, "the VU vector trace writes at shutdown");
	if (state) check(fileSize(dir, "vu1_vectors.jsonl") > 0, "an interpreted VU1 records vectors");
	else printf("skipping the VU1 checks: set PCSX2HOOK_TEST_STATE\n");

	char path[640];
	for (size_t i = 0; i < sizeof(kRunControlFiles) / sizeof(kRunControlFiles[0]); i++) {
		snprintf(path, sizeof(path), "%s/%s", dir, kRunControlFiles[i]);
		remove(path);
	}
	remove(dir);
}

static int report(void) {
	printf(failures ? "%d failed\n" : "all passed\n", failures);
	return failures != 0;
}

// The library keeps process-global state (the settings layer, the active core), so a process drives
// one context. The two modes therefore run as separate ctest entries rather than in sequence here.
int main(int argc, char** argv) {
	const char* mode = argc > 1 ? argv[1] : "";
	if (strcmp(mode, "boot") == 0) {
		testBoot();
		return report();
	}
	if (strcmp(mode, "destroy") == 0) {
		testDestroyWhileRunning();
		return report();
	}
	if (strcmp(mode, "run-control") == 0) {
		testRunControl();
		return report();
	}

	testNullContext();

	if (!writeMap()) {
		fprintf(stderr, "FAIL could not write a temporary symbol map\n");
		return 1;
	}

	pcsx2hook_config cfg;
	memset(&cfg, 0, sizeof(cfg));
	cfg.surfaceless = 1;
	cfg.symbols = mapPath;

	pcsx2hook_ctx* ctx = pcsx2hook_create(&cfg);
	check(ctx != NULL, "create returns a context");
	if (ctx) {
		// The config is copied, so a caller may scribble on its own struct straight after. The
		// strings are not, which is why mapPath outlives this.
		memset(&cfg, 0, sizeof(cfg));
		check(pcsx2hook_is_finished(ctx) == 0, "a fresh context is not finished");
		check(pcsx2hook_get_disc_serial(ctx) != NULL, "disc serial is never null");

		testSymbols(ctx);
		testSizeContract(ctx);
		testErrors(ctx);
		testDrawStack(ctx);
		pcsx2hook_destroy(ctx);
	}

	remove(mapPath);
	return report();
}

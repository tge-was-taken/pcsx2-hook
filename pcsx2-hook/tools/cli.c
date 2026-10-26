// SPDX-FileCopyrightText: 2002-2026 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#include "pcsx2hook/pcsx2hook.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const struct
{
	const char* name;
	pcsx2hook_trace trace;
} kTraces[] = {
	{"exec", PCSX2HOOK_TRACE_EXEC},
	{"insn", PCSX2HOOK_TRACE_INSN},
	{"iop", PCSX2HOOK_TRACE_IOP},
	{"hw", PCSX2HOOK_TRACE_HW},
	{"sif", PCSX2HOOK_TRACE_SIF},
	{"vif", PCSX2HOOK_TRACE_VIF},
	{"vu", PCSX2HOOK_TRACE_VU},
	{"gs", PCSX2HOOK_TRACE_GS},
	{"api", PCSX2HOOK_TRACE_API},
	{"vu-insn", PCSX2HOOK_TRACE_VU_INSN},
	{"vif-cmd", PCSX2HOOK_TRACE_VIF_CMD},
	{"spu", PCSX2HOOK_TRACE_SPU},
	{"timing", PCSX2HOOK_TRACE_TIMING},
};
enum
{
	kTraceCount = sizeof(kTraces) / sizeof(kTraces[0])
};

static const char* const kButtons[PCSX2HOOK_PAD_COUNT] = {
	"up", "right", "down", "left",
	"triangle", "circle", "cross", "square",
	"select", "start",
	"l1", "l2", "r1", "r2", "l3", "r3",
	"analog", "pressure",
	"lup", "lright", "ldown", "lleft",
	"rup", "rright", "rdown", "rleft",
};

/* A scheduled button press: held from one frame for a number of frames. A
 * program that waits for input needs driving to reach the state a trace is
 * about, and a schedule keeps that reproducible where a human cannot. */
typedef struct
{
	unsigned frame;
	unsigned hold;
	int button;
} press;

enum
{
	kMaxPresses = 1024,
	kDefaultHold = 6
};

static press s_presses[kMaxPresses];
static int s_pressCount;
static pcsx2hook_ctx* s_ctx;

static int parsePress(const char* text)
{
	char name[32];
	unsigned frame, hold = kDefaultHold;
	int n = 0;

	if (s_pressCount == kMaxPresses)
		return 0;
	if (sscanf(text, "%u:%31[^:]:%u%n", &frame, name, &hold, &n) < 3)
	{
		hold = kDefaultHold;
		if (sscanf(text, "%u:%31[^:]%n", &frame, name, &n) < 2)
			return 0;
	}
	if (text[n] != '\0')
		return 0;
	for (int b = 0; b < PCSX2HOOK_PAD_COUNT; b++)
	{
		if (strcmp(kButtons[b], name) != 0)
			continue;
		s_presses[s_pressCount].frame = frame;
		s_presses[s_pressCount].hold = hold ? hold : 1;
		s_presses[s_pressCount].button = b;
		s_pressCount++;
		return 1;
	}
	fprintf(stderr, "unknown button '%s'\n", name);
	return 0;
}

static int readScript(const char* path)
{
	char line[128];
	FILE* f = fopen(path, "r");

	if (!f)
	{
		fprintf(stderr, "cannot read %s\n", path);
		return 0;
	}
	while (fgets(line, sizeof(line), f))
	{
		char token[96];
		unsigned frame, hold;
		char name[32];
		char* hash = strchr(line, '#');

		if (hash)
			*hash = '\0';
		if (sscanf(line, "%u %31s %u", &frame, name, &hold) == 3)
			snprintf(token, sizeof(token), "%u:%s:%u", frame, name, hold);
		else if (sscanf(line, "%u %31s", &frame, name) == 2)
			snprintf(token, sizeof(token), "%u:%s", frame, name);
		else
			continue;
		if (!parsePress(token))
		{
			fclose(f);
			return 0;
		}
	}
	fclose(f);
	return 1;
}

/* A register fed a different value at each call of one function.
 *
 * A program decides for itself what it asks for, which is a problem for a
 * trace meant to cover everything it can ask for. Substituting the argument
 * at entry turns whatever call the program makes on its own into the next
 * case, and the call still runs on the program's own thread, so a target that
 * blocks or waits for hardware behaves as it always does. */
typedef struct
{
	uint32_t addr;
	int reg;
	int count;
	int next;
	unsigned hits;
	uint32_t values[512];
} argFeed;

enum
{
	kMaxFeeds = 8
};

static argFeed s_feeds[kMaxFeeds];
static int s_feedCount;

static int feedPre(pcsx2hook_regs* regs, void* user)
{
	argFeed* f = (argFeed*)user;

	f->hits++;
	if (f->count)
	{
		regs->gpr[f->reg * 4] = f->values[f->next];
		f->next = (f->next + 1) % f->count;
	}
	return PCSX2HOOK_CONTINUE;
}

static int parseFeed(const char* text)
{
	argFeed* f;
	const char* p;
	char* end;

	if (s_feedCount == kMaxFeeds)
		return 0;
	f = &s_feeds[s_feedCount];
	memset(f, 0, sizeof(*f));
	f->addr = (uint32_t)strtoul(text, &end, 0);
	if (*end != ':')
		return 0;
	f->reg = (int)strtol(end + 1, &end, 0);
	if (*end != ':' || f->reg < 0 || f->reg > 31)
		return 0;
	for (p = end + 1; *p && f->count < (int)(sizeof(f->values) / sizeof(f->values[0])); )
	{
		f->values[f->count++] = (uint32_t)strtoul(p, &end, 0);
		if (end == p)
			return 0;
		p = *end == ',' ? end + 1 : end;
		if (*end && *end != ',')
			return 0;
	}
	if (!f->count)
		return 0;
	s_feedCount++;
	return 1;
}

static int parseWatch(const char* text)
{
	argFeed* f;
	char* end;

	if (s_feedCount == kMaxFeeds)
		return 0;
	f = &s_feeds[s_feedCount];
	memset(f, 0, sizeof(*f));
	f->addr = (uint32_t)strtoul(text, &end, 0);
	if (*end != '\0' || !f->addr)
		return 0;
	s_feedCount++;
	return 1;
}

static int readList(const char* path, char* out, size_t n)
{
	size_t used = 0;
	char line[512];
	FILE* f = fopen(path, "r");

	if (!f)
	{
		fprintf(stderr, "cannot read %s\n", path);
		return 0;
	}
	while (fgets(line, sizeof(line), f))
	{
		char* hash = strchr(line, '#');
		char* tok;
		/* A line too long for the buffer arrives in pieces, and a piece after
		 * the first carries no '#', so the tail of a comment would be read as
		 * values. Drop whatever did not fit. */
		const int whole = strchr(line, '\n') != NULL;

		if (hash)
			*hash = '\0';
		for (tok = strtok(line, " \t\r\n,"); tok; tok = strtok(NULL, " \t\r\n,"))
		{
			const size_t len = strlen(tok);

			if (used + len + 2 >= n)
			{
				fclose(f);
				fprintf(stderr, "%s has too many values\n", path);
				return 0;
			}
			if (used)
				out[used++] = ',';
			memcpy(out + used, tok, len);
			used += len;
		}
		if (!whole)
		{
			int c;

			while ((c = fgetc(f)) != '\n' && c != EOF)
				;
		}
	}
	out[used] = '\0';
	fclose(f);
	return used != 0;
}

static void onVmReady(void* user)
{
	(void)user;
	for (int i = 0; i < s_feedCount; i++)
	{
		if (!pcsx2hook_add_hook(s_ctx, s_feeds[i].addr, feedPre, NULL, &s_feeds[i]))
			fprintf(stderr, "cannot hook %08X\n", s_feeds[i].addr);
	}
}

/* Report what each hook saw. A substitution that never fires looks exactly
 * like one that worked, and reading the result of a run that did nothing is
 * worse than reading no result. */
static void onShutdown(void* user)
{
	(void)user;
	for (int i = 0; i < s_feedCount; i++)
	{
		fprintf(stderr, "[arg] %08X called %u times", s_feeds[i].addr, s_feeds[i].hits);
		if (s_feeds[i].count)
			fprintf(stderr, ", fed $%d from %d values", s_feeds[i].reg, s_feeds[i].count);
		fprintf(stderr, "\n");
	}
}

static void onFrame(uint32_t frame, void* user)
{
	(void)user;
	for (int i = 0; i < s_pressCount; i++)
	{
		if (frame == s_presses[i].frame)
			pcsx2hook_set_pad_button(s_ctx, s_presses[i].button, 1);
		else if (frame == s_presses[i].frame + s_presses[i].hold)
			pcsx2hook_set_pad_button(s_ctx, s_presses[i].button, 0);
	}
}

static void usage(FILE* f)
{
	fprintf(f,
		"usage: pcsx2hook_cli --bios FILE [options] DISC\n"
		"\n"
		"  --state FILE        boot into a savestate instead of the disc's start\n"
		"  --frames N          stop after N frames and write the traces (default 60)\n"
		"  --out DIR           where the traces are written (default pcsx2hook_out)\n"
		"  --symbols PATH      symbol map, or a directory holding <ELF>.map files\n"
		"  --trace NAME        enable a trace; repeat for more\n"
		"  --interp LIST       interpret these processors: all, or a comma list of ee,iop,vu0,vu1\n"
		"  --accurate-timing   turn off Instant VU1 and the idle-loop and INTC_STAT skips\n"
		"  --software-gs       rasterize with the software GS instead of the null renderer\n"
		"  --set NAME=VALUE    any other library setting, by its PCSX2HOOK_ variable name\n"
		"  --press F:BUTTON[:N]  press BUTTON at frame F for N frames; repeat for more\n"
		"  --script FILE       the same as lines of \"FRAME BUTTON [HOLD]\", # comments\n"
		"  --arg ADDR:REG:LIST   feed register REG a different value from LIST at each\n"
		"                      call of the function at ADDR, cycling\n"
		"  --arg-file ADDR:REG:FILE  the same, with the values read from FILE\n"
		"  --watch ADDR        only count calls of the function at ADDR\n"
		"\n"
		"traces:");
	for (int i = 0; i < kTraceCount; i++)
		fprintf(f, " %s", kTraces[i].name);
	fprintf(f, "\n");
}

static int parseInterp(const char* list, unsigned* cpus)
{
	if (strcmp(list, "all") == 0)
	{
		*cpus = PCSX2HOOK_CPU_EE | PCSX2HOOK_CPU_IOP | PCSX2HOOK_CPU_VU0 | PCSX2HOOK_CPU_VU1;
		return 1;
	}
	char buf[64];
	snprintf(buf, sizeof(buf), "%s", list);
	for (char* tok = strtok(buf, ","); tok; tok = strtok(NULL, ","))
	{
		if (strcmp(tok, "ee") == 0)
			*cpus |= PCSX2HOOK_CPU_EE;
		else if (strcmp(tok, "iop") == 0)
			*cpus |= PCSX2HOOK_CPU_IOP;
		else if (strcmp(tok, "vu0") == 0)
			*cpus |= PCSX2HOOK_CPU_VU0;
		else if (strcmp(tok, "vu1") == 0)
			*cpus |= PCSX2HOOK_CPU_VU1;
		else
			return 0;
	}
	return 1;
}

int main(int argc, char** argv)
{
	const char* bios = NULL;
	const char* state = NULL;
	const char* out = "pcsx2hook_out";
	const char* symbols = NULL;
	const char* disc = NULL;
	unsigned long frames = 60;
	unsigned cpus = 0;
	int accurate = 0, softwareGs = 0;
	int traces[kTraceCount] = {0};
	const char* sets[64];
	int setCount = 0;

	for (int i = 1; i < argc; i++)
	{
		const char* a = argv[i];
		const char* v = i + 1 < argc ? argv[i + 1] : NULL;
		if (strcmp(a, "--help") == 0 || strcmp(a, "-h") == 0)
		{
			usage(stdout);
			return 0;
		}
		else if (strcmp(a, "--accurate-timing") == 0)
			accurate = 1;
		else if (strcmp(a, "--software-gs") == 0)
			softwareGs = 1;
		else if (a[0] == '-' && a[1] == '-' && !v)
		{
			fprintf(stderr, "%s needs a value\n", a);
			return 2;
		}
		else if (strcmp(a, "--bios") == 0)
			bios = argv[++i];
		else if (strcmp(a, "--state") == 0)
			state = argv[++i];
		else if (strcmp(a, "--out") == 0)
			out = argv[++i];
		else if (strcmp(a, "--symbols") == 0)
			symbols = argv[++i];
		else if (strcmp(a, "--frames") == 0)
			frames = strtoul(argv[++i], NULL, 10);
		else if (strcmp(a, "--interp") == 0)
		{
			if (!parseInterp(argv[++i], &cpus))
			{
				fprintf(stderr, "--interp takes all, or a comma list of ee,iop,vu0,vu1\n");
				return 2;
			}
		}
		else if (strcmp(a, "--trace") == 0)
		{
			const char* name = argv[++i];
			int found = 0;
			for (int t = 0; t < kTraceCount; t++)
			{
				if (strcmp(name, kTraces[t].name) == 0)
				{
					traces[t] = 1;
					found = 1;
				}
			}
			if (!found)
			{
				fprintf(stderr, "unknown trace '%s'\n", name);
				usage(stderr);
				return 2;
			}
		}
		else if (strcmp(a, "--set") == 0)
		{
			if (!strchr(v, '=') || setCount == (int)(sizeof(sets) / sizeof(sets[0])))
			{
				fprintf(stderr, "--set takes NAME=VALUE\n");
				return 2;
			}
			sets[setCount++] = argv[++i];
		}
		else if (strcmp(a, "--arg") == 0)
		{
			if (!v || !parseFeed(v))
			{
				fprintf(stderr, "--arg takes ADDR:REG:V1[,V2...]\n");
				return 2;
			}
			i++;
		}
		else if (strcmp(a, "--arg-file") == 0)
		{
			static char spec[8][8192];
			char list[7000];
			const char* colon = v ? strchr(v, ':') : NULL;
			const char* second = colon ? strchr(colon + 1, ':') : NULL;

			if (!second || s_feedCount >= kMaxFeeds || !readList(second + 1, list, sizeof(list)))
			{
				fprintf(stderr, "--arg-file takes ADDR:REG:FILE\n");
				return 2;
			}
			snprintf(spec[s_feedCount], sizeof(spec[0]), "%.*s%s",
				(int)(second + 1 - v), v, list);
			if (!parseFeed(spec[s_feedCount]))
			{
				fprintf(stderr, "--arg-file: bad address, register or values\n");
				return 2;
			}
			i++;
		}
		else if (strcmp(a, "--watch") == 0)
		{
			if (!v || !parseWatch(v))
			{
				fprintf(stderr, "--watch takes ADDR\n");
				return 2;
			}
			i++;
		}
		else if (strcmp(a, "--press") == 0)
		{
			if (!v || !parsePress(v))
			{
				fprintf(stderr, "--press takes FRAME:BUTTON[:HOLD]\n");
				return 2;
			}
			i++;
		}
		else if (strcmp(a, "--script") == 0)
		{
			if (!v || !readScript(v))
				return 2;
			i++;
		}
		else if (a[0] == '-')
		{
			fprintf(stderr, "unknown option %s\n", a);
			usage(stderr);
			return 2;
		}
		else
			disc = a;
	}
	if (!bios || !disc)
	{
		usage(stderr);
		return 2;
	}

	pcsx2hook_config cfg;
	memset(&cfg, 0, sizeof(cfg));
	cfg.bios = bios;
	cfg.dump_dir = out;
	cfg.symbols = symbols;
	cfg.surfaceless = 1;
	cfg.software_gs = softwareGs;
	if (s_pressCount)
		cfg.on_frame = onFrame;
	if (s_feedCount)
	{
		cfg.on_vm_ready = onVmReady;
		cfg.on_shutdown = onShutdown;
	}
	pcsx2hook_ctx* ctx = pcsx2hook_create(&cfg);
	if (!ctx)
		return 1;
	s_ctx = ctx;

	for (int i = 0; i < setCount; i++)
	{
		char name[128];
		const char* eq = strchr(sets[i], '=');
		snprintf(name, sizeof(name), "%.*s", (int)(eq - sets[i]), sets[i]);
		pcsx2hook_set_config(ctx, name, eq + 1);
	}
	pcsx2hook_set_interpreter(ctx, cpus);
	pcsx2hook_set_accurate_timing(ctx, accurate);
	pcsx2hook_set_boot_state(ctx, state);
	pcsx2hook_set_frame_limit(ctx, (uint32_t)frames);
	for (int t = 0; t < kTraceCount; t++)
	{
		if (traces[t] && !pcsx2hook_enable_trace(ctx, kTraces[t].trace))
		{
			fprintf(stderr, "cannot enable %s: %s\n", kTraces[t].name, pcsx2hook_get_last_error(ctx));
			pcsx2hook_destroy(ctx);
			return 1;
		}
	}

	pcsx2hook_early_init(ctx);
	char* bootArgv[] = {argv[0], (char*)disc, NULL};
	if (!pcsx2hook_init(ctx, 2, bootArgv))
	{
		fprintf(stderr, "init failed: %s\n", pcsx2hook_get_last_error(ctx));
		pcsx2hook_destroy(ctx);
		return 1;
	}
	pcsx2hook_apply_settings(ctx);
	if (!pcsx2hook_start(ctx))
	{
		fprintf(stderr, "start failed: %s\n", pcsx2hook_get_last_error(ctx));
		pcsx2hook_destroy(ctx);
		return 1;
	}
	pcsx2hook_pump_window(ctx, 1);
	const int rc = pcsx2hook_join(ctx);
	pcsx2hook_shutdown(ctx);
	pcsx2hook_destroy(ctx);
	return rc;
}

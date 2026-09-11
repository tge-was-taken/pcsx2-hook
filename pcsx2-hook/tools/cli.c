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
	pcsx2hook_ctx* ctx = pcsx2hook_create(&cfg);
	if (!ctx)
		return 1;

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

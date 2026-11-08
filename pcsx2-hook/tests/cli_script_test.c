// SPDX-FileCopyrightText: 2002-2026 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

/* Parser and runtime checks for cli.c's script steps against a fake guest. cli.c is
 * included so its statics are reachable, and the library calls it makes are
 * answered here; nothing in this file boots a game. */

#define main cli_main
#include "../tools/cli.c"
#undef main

static int s_failures;

#define CHECK(cond) \
	do { if (!(cond)) { fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); s_failures++; } } while (0)

enum { kBase = 0x100000, kMemSize = 0x10000 };
static uint8_t s_mem[kMemSize];

static const struct { const char* name; uint32_t addr; } kSymbols[] = {
	{"evtLoadUnit", 0x2000},
	{"evtGetUnitHandle", 0x2010},
	{"sdfChipAllocDirect", 0x2020},
	{"sdfMemAllocDirect", 0x2030},
	{"unitSlot", kBase + 0x100},
	{"sdfMotionSeek", 0x2040},
	{"dds3AdminiCallSequence", 0x2050},
	{"mdlSetMotionSpeedEx", 0x2060},
};
enum { kLoadUnit = 0x2000, kGetHandle = 0x2010, kAlloc = 0x2020, kSeek = 0x2040, kSequence = 0x2050,
	kSpeed = 0x2060 };

/* The fake EE's float registers: call_ee_ex puts float argument k in $f12+k, as the eabi does,
 * and the fake guest functions read them from here rather than from the argument list. */
static uint32_t s_fpr[32];

static uint32_t s_allocResult;
static uint32_t s_lastArgs[8];
static int s_lastArgc;
static int s_callCountSeen;
static uint32_t s_serial = 7;

uint32_t pcsx2hook_find_symbol(pcsx2hook_ctx* ctx, const char* name)
{
	(void)ctx;
	for (size_t i = 0; i < sizeof(kSymbols) / sizeof(kSymbols[0]); i++)
	{
		if (strcmp(kSymbols[i].name, name) == 0)
			return kSymbols[i].addr;
	}
	return 0;
}

void* pcsx2hook_map_guest(pcsx2hook_ctx* ctx, uint32_t addr, uint32_t size)
{
	(void)ctx;
	if (addr < kBase || addr + size > kBase + kMemSize || addr + size < addr)
		return NULL;
	return s_mem + (addr - kBase);
}

uint32_t pcsx2hook_call_ee(pcsx2hook_ctx* ctx, uint32_t pc, const uint32_t* args, size_t argc)
{
	(void)ctx;
	s_callCountSeen++;
	s_lastArgc = (int)argc;
	for (size_t i = 0; i < argc && i < 8; i++)
		s_lastArgs[i] = args[i];
	if (pc == kAlloc)
		return s_allocResult;
	if (pc == kLoadUnit)
		return s_serial;
	if (pc == kGetHandle)
		return args[0] == s_serial ? kBase + 0x200 : 0;
	return 0;
}

int pcsx2hook_call_ee_ex(pcsx2hook_ctx* ctx, uint32_t pc, const uint32_t* args, size_t count,
	const uint32_t* fargBits, size_t fcount, uint32_t* v0, uint32_t* f0Bits)
{
	(void)ctx;
	(void)f0Bits;
	memset(s_fpr, 0, sizeof(s_fpr));
	for (size_t i = 0; i < fcount; i++)
		s_fpr[12 + i] = fargBits[i];
	*v0 = pcsx2hook_call_ee(ctx, pc, args, count);
	/* sdfMotionSeek(ctrlr, f32 frame) stores $f12 at ctrlr+0; mdlSetMotionSpeedEx(h, group, f32
	 * speed) stores $f12 at h+32 */
	if (pc == kSeek && count >= 1)
		memcpy(s_mem + (args[0] - kBase), &s_fpr[12], 4);
	if (pc == kSpeed && count >= 1)
		memcpy(s_mem + (args[0] - kBase) + 32, &s_fpr[12], 4);
	return 1;
}

const char* pcsx2hook_get_last_error(pcsx2hook_ctx* ctx)
{
	(void)ctx;
	return "fake";
}

void pcsx2hook_request_stop(pcsx2hook_ctx* ctx)
{
	(void)ctx;
}

static void resetScript(void)
{
	memset(s_steps, 0, sizeof(s_steps));
	memset(s_binds, 0, sizeof(s_binds));
	memset(s_mem, 0, sizeof(s_mem));
	s_stepCount = s_stepCursor = s_bindCount = s_vecCount = 0;
	s_stepFailed = s_vecBase = s_vecUsed = s_sampleCount = 0;
	s_sampleFrame = (unsigned)-1;
	s_stepWaits = s_waitsDone = 0;
	s_allocResult = kBase + 0x1008;
	s_callCountSeen = 0;
	s_curStep = NULL;
	memset(s_fpr, 0, sizeof(s_fpr));
	s_lastArgc = 0;
	memset(s_lastArgs, 0, sizeof(s_lastArgs));
}

/* Parses lines and runs the whole-script check, as readScript does. */
static int load(const char* const* lines, int count)
{
	char buf[192];

	resetScript();
	for (int i = 0; i < count; i++)
	{
		snprintf(buf, sizeof(buf), "%s\n", lines[i]);
		if (parseStep(buf) != 1)
			return 0;
	}
	return checkBindings();
}

static int loadOne(const char* line)
{
	return load(&line, 1);
}

static uint32_t word(uint32_t guest)
{
	uint32_t v;

	memcpy(&v, s_mem + (guest - kBase), 4);
	return v;
}

static void testParse(void)
{
	const char* sample[] = {
		"call evtLoadUnit 3 3 -> serial",
		"call evtGetUnitHandle $serial -> unit",
		"sample *$unit+4:2",
		"vec v 1 2 0x3 0xFFFFFFFF",
		"call evtLoadUnit &unitSlot,$v",
	};

	CHECK(load(sample, 5));
	CHECK(s_steps[0].kind == kStepCall && s_steps[0].argCount == 2 && s_steps[0].args[1] == 3);
	CHECK(strcmp(s_steps[0].bind, "serial") == 0);
	CHECK(strcmp(s_steps[1].argVar[0], "serial") == 0 && strcmp(s_steps[1].bind, "unit") == 0);
	CHECK(s_steps[2].kind == kStepSample && strcmp(s_steps[2].addr, "*$unit+4:2") == 0);
	CHECK(s_steps[3].kind == kStepVec && s_steps[3].words[3] == 0xFFFFFFFFu && s_steps[3].words[2] == 3);
	CHECK(strcmp(s_steps[4].argSym[0], "unitSlot") == 0 && strcmp(s_steps[4].argVar[1], "v") == 0);

	/* the existing forms */
	CHECK(loadOne("call evtLoadUnit 1,2,3,4") && s_steps[0].argCount == 4 && s_steps[0].bind[0] == 0);
	CHECK(loadOne("call evtLoadUnit &unitSlot") && s_steps[0].argSym[0][0]);
	CHECK(loadOne("call evtLoadUnit"));
	CHECK(loadOne("write *unitSlot+8:2 5") && loadOne("wait 4 @evtLoadUnit ge 1"));

	/* malformed */
	CHECK(!loadOne("call evtLoadUnit 1 2 3 4 5"));
	CHECK(!loadOne("call evtLoadUnit 1 -> "));
	CHECK(!loadOne("call evtLoadUnit 1 -> a b"));
	CHECK(!loadOne("call evtLoadUnit 1x"));
	CHECK(!loadOne("call evtLoadUnit 1 -> 9bad"));
	CHECK(!loadOne("vec v 1 2 3"));
	CHECK(!loadOne("vec v 1 2 3 4 5"));
	CHECK(!loadOne("vec v 1 2 3 zz"));
}

static void testFloatArgs(void)
{
	float one = 1.0f, half;
	uint32_t bits;

	memcpy(&half, &(uint32_t){0x3F000000}, 4);
	CHECK(loadOne("call sdfMotionSeek &unitSlot f:0x3F800000"));
	CHECK(s_steps[0].argCount == 1 && s_steps[0].fargCount == 1 && s_steps[0].fargs[0] == 0x3F800000u);
	CHECK(loadOne("call sdfMotionSeek &unitSlot f:1.0"));
	memcpy(&bits, &one, 4);
	CHECK(s_steps[0].fargs[0] == bits);
	/* counted apart: the float's position among the arguments does not move the ints */
	CHECK(loadOne("call mdlSetMotionSpeedEx 5 f:0.5 2") && s_steps[0].argCount == 2);
	CHECK(s_steps[0].args[0] == 5 && s_steps[0].args[1] == 2 && s_steps[0].fargs[0] == 0x3F000000u);
	CHECK(loadOne("call mdlSetMotionSpeedEx 1 2 3 4 f:1 f:2 f:3 f:4"));
	CHECK(!loadOne("call mdlSetMotionSpeedEx f:1 f:2 f:3 f:4 f:5"));
	CHECK(!loadOne("call mdlSetMotionSpeedEx f:"));
	CHECK(!loadOne("call mdlSetMotionSpeedEx f:abc"));

	/* a float lands in $f12 and the int in $a0, where sdfMotionSeek reads them */
	CHECK(loadOne("call sdfMotionSeek 0x100400 f:0x3F800000"));
	runSteps();
	CHECK(!s_stepFailed && s_fpr[12] == 0x3F800000u && s_lastArgc == 1 && s_lastArgs[0] == 0x100400);
	CHECK(word(0x100400) == 0x3F800000u);
	CHECK(loadOne("call mdlSetMotionSpeedEx 0x100400 3 f:0.5"));
	runSteps();
	CHECK(s_fpr[12] == 0x3F000000u && s_lastArgc == 2 && s_lastArgs[1] == 3 && word(0x100420) == 0x3F000000u);
	(void)half;
	/* with no float argument the plain call runs and $f12 stays clear */
	CHECK(loadOne("call evtLoadUnit 3 3"));
	runSteps();
	CHECK(s_fpr[12] == 0 && s_lastArgc == 2);
}

static void testSequence(void)
{
	CHECK(loadOne("sequence 6"));
	CHECK(strcmp(s_steps[0].symbol, "dds3AdminiCallSequence") == 0 && s_steps[0].argCount == 4);
	CHECK(s_steps[0].args[0] == 6 && !s_steps[0].args[1] && !s_steps[0].args[2] && !s_steps[0].args[3]);
	CHECK(loadOne("sequence 6 1 2 3") && s_steps[0].args[1] == 1 && s_steps[0].args[3] == 3);
	CHECK(loadOne("sequence 6 1") && s_steps[0].args[1] == 1 && s_steps[0].args[2] == 0);
	CHECK(strcmp(s_steps[0].line, "sequence 6 1") == 0);
	CHECK(!loadOne("sequence"));   /* a bare verb is an error, not a skipped line */
	CHECK(!loadOne("call") && !loadOne("vec"));
	CHECK(!loadOne("sequence 6 1 2 3 4"));
	CHECK(!loadOne("sequence 6x"));
	CHECK(loadOne("sequence 6 1 0 0"));
	runSteps();
	CHECK(!s_stepFailed && s_lastArgc == 4 && s_lastArgs[0] == 6 && s_lastArgs[1] == 1);
}

/* # starts a comment anywhere: a commented-out step is not a step. */
static void testComments(void)
{
	char path[] = "/tmp/cli_script_test_XXXXXX";
	int fd = mkstemp(path);
	FILE* f;

	CHECK(fd >= 0);
	f = fdopen(fd, "w");
	fputs("# call evtLoadUnit 1\n   # sequence 6\ncall evtLoadUnit 2 # trailing\n\n#vec v 1 2 3 4\n", f);
	fclose(f);
	resetScript();
	CHECK(readScript(path));
	CHECK(s_stepCount == 1 && s_steps[0].args[0] == 2 && s_steps[0].argCount == 1);
	remove(path);
}

static void testLimits(void)
{
	char names[20][40];
	const char* lines[20];

	for (int i = 0; i < 17; i++)
	{
		snprintf(names[i], sizeof(names[i]), "call evtLoadUnit 1 -> n%d", i);
		lines[i] = names[i];
	}
	CHECK(!load(lines, 17));   /* the 17th binding */
	CHECK(load(lines, 16));
	for (int i = 0; i < 9; i++)
	{
		snprintf(names[i], sizeof(names[i]), "vec v%d 0 0 0 0", i);
		lines[i] = names[i];
	}
	CHECK(!load(lines, 9));    /* the 9th vec */
	CHECK(load(lines, 8));
	{
		const char* twice[] = {"call evtLoadUnit -> a", "call evtLoadUnit -> a"};

		CHECK(!load(twice, 2));
	}
}

/* Negative controls: each must be refused, and the legal ordering beside it accepted. */
static void testBindingErrors(void)
{
	const char* unknown[] = {"call evtGetUnitHandle $nope -> unit"};
	const char* unknownAddr[] = {"sample *$nope+4"};
	const char* before[] = {"call evtGetUnitHandle $serial -> unit", "call evtLoadUnit 3 3 -> serial"};
	const char* self[] = {"call evtLoadUnit $a -> a"};
	const char* ok[] = {"call evtLoadUnit 3 3 -> serial", "call evtGetUnitHandle $serial -> unit"};
	const char* beforeAddr[] = {"write $v+4 1", "vec v 0 0 0 0"};

	CHECK(!load(unknown, 1));
	CHECK(!load(unknownAddr, 1));
	CHECK(!load(before, 2));
	CHECK(!load(self, 1));
	CHECK(!load(beforeAddr, 2));
	CHECK(load(ok, 2));
}

/* The runtime backstop, for a step list that skipped the parse-time check. */
static void testRuntimeBackstop(void)
{
	const char* lines[] = {"call evtGetUnitHandle $serial -> unit"};

	CHECK(load(lines, 1) == 0);
	resetScript();
	CHECK(parseStep("call evtGetUnitHandle $serial -> unit\n") == 1);
	declareBinding("serial", "x");
	runSteps();
	CHECK(s_stepFailed);
	CHECK(s_callCountSeen == 0);

	resetScript();
	CHECK(parseStep("call evtGetUnitHandle $ghost\n") == 1);
	runSteps();
	CHECK(s_stepFailed);
}

static void testRun(void)
{
	const char* lines[] = {
		"call evtLoadUnit 3 3 -> serial",
		"call evtGetUnitHandle $serial -> unit",
		"vec a 0x11 0x22 0x33 0x44",
		"vec b 0x55 0x66 0x77 0x88",
		"write $a+4 0xAA",
		"call evtLoadUnit $unit,$b",
	};
	uint32_t a, b;

	CHECK(load(lines, 6));
	runSteps();
	CHECK(!s_stepFailed && s_stepCursor == s_stepCount);
	CHECK(s_lastArgc == 2 && s_lastArgs[0] == kBase + 0x200);
	a = (kBase + 0x1008 + 15) & ~15u;
	b = a + 16;
	CHECK(s_lastArgs[1] == b);
	CHECK((a & 15) == 0 && word(a) == 0x11 && word(a + 4) == 0xAA && word(a + 12) == 0x44);
	CHECK(word(b) == 0x55 && word(b + 12) == 0x88);

	/* *$unit loads the pointer stored at the unit, then adds the offset, as *SYM does */
	memcpy(s_mem + 0x200, &(uint32_t){kBase + 0x300}, 4);
	memcpy(s_mem + 0x308, &(uint32_t){0xBEEF}, 4);
	{
		uint32_t have = 0;
		const char* more[] = {"call evtLoadUnit 3 3 -> serial", "call evtGetUnitHandle $serial -> unit"};

		CHECK(load(more, 2));
		memcpy(s_mem + 0x200, &(uint32_t){kBase + 0x300}, 4);
		memcpy(s_mem + 0x308, &(uint32_t){0xBEEF}, 4);
		runSteps();
		CHECK(readStepValue("*$unit+8", &have) && have == 0xBEEF);
		CHECK(readStepValue("$unit", &have) && have == kBase + 0x300);   /* the word at the unit */
		CHECK(!readStepValue("$serial", &have));                         /* 7 is not mapped */
		CHECK(!sampleIsNull("*$unit"));
		memset(s_mem + 0x200, 0, 4);
		CHECK(sampleIsNull("*$unit"));
		CHECK(!readStepValue("*$unit+8", &have));
	}
}

/* An allocation that returns 0 ends the run, and nothing is bound after it. */
static void testAllocFailure(void)
{
	const char* lines[] = {"vec a 1 2 3 4", "call evtLoadUnit $a"};

	CHECK(load(lines, 2));
	s_allocResult = 0;
	runSteps();
	CHECK(s_stepFailed && s_vecBase == 0 && !s_binds[0].bound);
	CHECK(s_callCountSeen == 1);   /* the allocator only */

	CHECK(load(lines, 2));
	s_vecAllocSym = "noSuchAllocator";
	runSteps();
	CHECK(s_stepFailed && s_callCountSeen == 0);
	s_vecAllocSym = "sdfChipAllocDirect";
}

static void testAllocOption(void)
{
	CHECK(parseVecAlloc("sdfMemAllocDirect:size"));
	CHECK(!s_vecAllocAlign && strcmp(s_vecAllocSym, "sdfMemAllocDirect") == 0);
	CHECK(parseVecAlloc("sdfChipAllocDirect:size,align") && s_vecAllocAlign);
	{
		const char* lines[] = {"vec a 1 2 3 4"};

		CHECK(load(lines, 1));
		runSteps();
		CHECK(s_lastArgc == 2 && s_lastArgs[0] == 144 && s_lastArgs[1] == 16);
	}
	CHECK(!parseVecAlloc("x:bogus") && !parseVecAlloc(":size"));
	CHECK(parseVecAlloc("sdfChipAllocDirect") && !s_vecAllocAlign);
}

int main(void)
{
	testParse();
	testFloatArgs();
	testSequence();
	testComments();
	testLimits();
	testBindingErrors();
	testRuntimeBackstop();
	testRun();
	testAllocFailure();
	testAllocOption();
	if (s_failures)
	{
		fprintf(stderr, "%d failed\n", s_failures);
		return 1;
	}
	printf("cli script: all passed\n");
	return 0;
}

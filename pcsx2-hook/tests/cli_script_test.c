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
	s_stepFailed = s_vecBase = s_scratchUsed = s_scratchPlanned = s_sampleCount = 0;
	s_sampleFrame = (unsigned)-1;
	s_stepWaits = s_waitsDone = 0;
	s_ticksSeen = s_ticksStarted = 0;
	s_ticksTarget = 0;
	s_frame = 0;
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
	char buf[1300];

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

static void testPeekParse(void)
{
	const char* chain[] = {
		"call evtGetUnitHandle 1 -> effect",
		"peek work $effect+0x18",
		"peek handle $work+0xC",
		"peek sym unitSlot+4",
		"peek deref *unitSlot+8",
	};

	CHECK(load(chain, 5));
	CHECK(s_steps[1].kind == kStepPeek && strcmp(s_steps[1].bind, "work") == 0 &&
	      strcmp(s_steps[1].addr, "$effect+0x18") == 0);
	CHECK(strcmp(s_steps[2].addr, "$work+0xC") == 0 && strcmp(s_steps[4].addr, "*unitSlot+8") == 0);
	CHECK(!loadOne("peek"));
	CHECK(!loadOne("peek a"));
	CHECK(!loadOne("peek a unitSlot b"));
	CHECK(!loadOne("peek a unitSlot:2"));        /* a word, not a byte or a half */
	CHECK(!loadOne("peek 9a unitSlot"));
	CHECK(!loadOne("peek a $ghost+4"));          /* unbound: unknown */
	{
		const char* before[] = {"peek a $b+4", "call evtLoadUnit -> b"};
		const char* twice[] = {"peek a unitSlot", "peek a unitSlot"};

		CHECK(!load(before, 2));                 /* used before its step binds it */
		CHECK(!load(twice, 2));
	}
}

static void testPeekRun(void)
{
	const char* chain[] = {
		"call evtGetUnitHandle 7 -> effect",   /* effect = kBase + 0x200 */
		"peek work $effect+0x18",
		"peek handle $work+0xC",
		"peek viaSym unitSlot+4",
		"peek viaPtr *unitSlot+8",
		"call evtLoadUnit $handle,$viaSym",
	};

	CHECK(load(chain, 6));
	memcpy(s_mem + 0x218, &(uint32_t){kBase + 0x400}, 4);   /* work */
	memcpy(s_mem + 0x40C, &(uint32_t){0xCAFE}, 4);          /* handle */
	memcpy(s_mem + 0x104, &(uint32_t){0x1234}, 4);          /* unitSlot+4 */
	memcpy(s_mem + 0x100, &(uint32_t){kBase + 0x500}, 4);   /* unitSlot holds a pointer */
	memcpy(s_mem + 0x508, &(uint32_t){0x77}, 4);
	runSteps();
	CHECK(!s_stepFailed && s_stepCursor == s_stepCount);
	CHECK(s_lastArgs[0] == 0xCAFE && s_lastArgs[1] == 0x1234);
	CHECK(s_binds[1].value == kBase + 0x400 && s_binds[4].value == 0x77);
}

/* An unreadable address, and a binding that is not bound when the step runs, each stop the run. */
static void testPeekErrors(void)
{
	const char* unmapped[] = {"call evtGetUnitHandle 7 -> effect", "peek w $effect+0x9000000", "call evtLoadUnit $w"};
	const char* nullPtr[] = {"peek w *unitSlot", "call evtLoadUnit $w"};

	CHECK(load(unmapped, 3));
	runSteps();
	CHECK(s_stepFailed && s_stepCursor == 1 && !s_binds[1].bound);
	CHECK(s_callCountSeen == 1);                 /* the peek stopped it before the last call */
	CHECK(load(nullPtr, 2));                     /* unitSlot holds 0: *unitSlot is null */
	runSteps();
	CHECK(s_stepFailed && s_callCountSeen == 0);

	/* runtime backstop for an unbound name, past the parse check */
	resetScript();
	CHECK(parseStep("peek w $ghost+4\n") == 1);
	runSteps();
	CHECK(s_stepFailed && !s_binds[0].bound);
}

static void testStr(void)
{
	char big[1100];
	char line[1200];
	const char* lines[] = {
		"str path \"effect/e0001.pak\"",
		"vec v 1 2 3 4",
		"str other \"x\"",
		"call evtLoadUnit $path,$other",
	};
	uint32_t a, v, o;

	CHECK(load(lines, 4));
	CHECK(s_steps[0].kind == kStepStr && strcmp(s_steps[0].text, "effect/e0001.pak") == 0);
	runSteps();
	CHECK(!s_stepFailed && s_stepCursor == s_stepCount);
	a = (kBase + 0x1008 + 15) & ~15u;
	v = a + 32;                                   /* "effect/e0001.pak" is 17 bytes with its NUL */
	o = v + 16;
	CHECK(s_lastArgs[0] == a && s_lastArgs[1] == o && (a & 15) == 0 && (o & 15) == 0);
	CHECK(strcmp((char*)s_mem + (a - kBase), "effect/e0001.pak") == 0);
	CHECK(word(v) == 1 && word(v + 12) == 4);     /* the str did not run into the vec */
	CHECK(strcmp((char*)s_mem + (o - kBase), "x") == 0);
	CHECK(s_mem[a - kBase + 17] == 0 && s_mem[a - kBase + 31] == 0);

	/* the longest string that fits, and one byte more */
	memset(big, 'p', sizeof(big));
	big[kScratchUsable - 1] = '\0';              /* 1007 characters + NUL = 1008 */
	snprintf(line, sizeof(line), "str long \"%s\"", big);
	CHECK(loadOne(line) && strlen(s_steps[0].text) == kScratchUsable - 1);
	runSteps();
	CHECK(!s_stepFailed && strlen((char*)s_mem + (((kBase + 0x1008 + 15) & ~15u) - kBase)) == kScratchUsable - 1);
	big[kScratchUsable - 1] = 'p';
	big[kScratchUsable] = '\0';
	snprintf(line, sizeof(line), "str long \"%s\"", big);
	CHECK(!loadOne(line));
	CHECK(loadOne("str empty \"\"") && s_steps[0].text[0] == 0);

	/* the scratch budget is shared with vecs */
	{
		const char* full[] = {"str a \"p\"", "vec b 0 0 0 0"};

		CHECK(load(full, 2) && s_scratchPlanned == 32);
	}
	memset(big, 'p', 900);
	big[900] = '\0';
	snprintf(line, sizeof(line), "str s1 \"%s\"", big);
	{
		const char* over[3];

		over[0] = line;
		over[1] = "vec v 0 0 0 0";
		over[2] = "vec w 0 0 0 0";                 /* 912 + 32 fits; one more does not */
		CHECK(load(over, 3));
		over[2] = "str s2 \"0123456789abcde\"";    /* 16 bytes with its NUL: 912+16+16 = 944 */
		CHECK(load(over, 3));
		{
			char more[100];
			const char* many[5];

			snprintf(more, sizeof(more), "str s3 \"%s\"", "0123456789012345678901234567890123456789012345678901234567890123456789");
			many[0] = line; many[1] = over[1]; many[2] = over[2]; many[3] = more; many[4] = "vec z 0 0 0 0";
			CHECK(!load(many, 4));                  /* 944 + 80 > 1008 */
		}
	}

	/* malformed */
	CHECK(!loadOne("str"));
	CHECK(!loadOne("str a"));
	CHECK(!loadOne("str a text"));
	CHECK(!loadOne("str a \"unclosed"));
	CHECK(!loadOne("str a \"x\" junk"));
	CHECK(!loadOne("str \"x\""));
	CHECK(!loadOne("str 1a \"x\""));

	/* unbound-name control: a str's name is unknown before its step */
	{
		const char* before[] = {"call evtLoadUnit $s", "str s \"x\""};

		CHECK(!load(before, 2));
		CHECK(!loadOne("call evtLoadUnit $s"));
	}
	/* a full buffer at run time refuses by step: the allocation is smaller than the plan */
	resetScript();
	CHECK(parseStep("str a \"x\"\n") == 1);
	s_scratchUsed = kScratchUsable - 8;
	s_vecBase = kBase + 0x1010;
	runSteps();
	CHECK(s_stepFailed && !s_binds[0].bound);
	/* an allocation that returns 0 still stops a str */
	CHECK(load(lines, 1));
	s_allocResult = 0;
	runSteps();
	CHECK(s_stepFailed && !s_binds[0].bound);
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

/* Writes TEXT to a file and loads it through readScript. */
static int loadFile(const char* text)
{
	char path[] = "/tmp/cli_script_test_XXXXXX";
	int fd = mkstemp(path);
	FILE* f;
	int ok;

	CHECK(fd >= 0);
	f = fdopen(fd, "w");
	fputs(text, f);
	fclose(f);
	resetScript();
	s_pressCount = 0;
	ok = readScript(path);
	remove(path);
	return ok;
}

/* A line that is neither a step nor a press fails the load; comments and blanks do not. */
static void testUnknownLines(void)
{
	CHECK(!loadFile("wait 30\n"));
	CHECK(!loadFile("bogus\n"));
	CHECK(!loadFile("call evtLoadUnit 1\nbogus\n"));
	CHECK(loadFile("# a comment\n\n   \n\t# indented\ncall evtLoadUnit 1 # trailing\n\n"));
	CHECK(s_stepCount == 1);
	CHECK(loadFile("at 5\n30 cross\n40 cross 3\n"));
	CHECK(s_pressCount == 2);
}

static void testTicks(void)
{
	/* ticks 0 lands on the frame its predecessors finish; ticks 5 lands 5 frames later */
	CHECK(loadFile("at 10\nticks 0\n"));
	CHECK(s_stepCount == 2 && s_steps[1].kind == kStepTicks && s_steps[1].value == 0);
	s_frame = 9;
	runSteps();
	CHECK(s_stepCursor == 0);
	s_frame = 12;
	runSteps();
	CHECK(s_stepCursor == s_stepCount && s_ticksTarget == 12 && !s_stepFailed);

	CHECK(loadFile("at 10\nticks 5\n"));
	s_frame = 12;
	runSteps();
	CHECK(s_stepCursor == 1 && s_ticksTarget == 17);
	s_frame = 16;
	runSteps();
	CHECK(s_stepCursor == 1);
	s_frame = 17;
	runSteps();
	CHECK(s_stepCursor == 2 && !s_stepFailed);

	/* refused: a second ticks, a step after ticks, a bad count */
	CHECK(!loadFile("ticks 1\nticks 2\n"));
	CHECK(!loadFile("ticks 1\nat 3\n"));
	CHECK(!loadFile("ticks\n") && !loadFile("ticks x\n") && !loadFile("ticks -1\n"));
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
		CHECK(s_lastArgc == 2 && s_lastArgs[0] == kScratchBytes && s_lastArgs[1] == 16);
	}
	CHECK(!parseVecAlloc("x:bogus") && !parseVecAlloc(":size"));
	CHECK(parseVecAlloc("sdfChipAllocDirect") && !s_vecAllocAlign);
}

int main(void)
{
	testParse();
	testPeekParse();
	testPeekRun();
	testPeekErrors();
	testStr();
	testFloatArgs();
	testSequence();
	testComments();
	testUnknownLines();
	testTicks();
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

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
	unsigned frame;   /* absolute, or after the segment's wait when segment > 0 */
	unsigned hold;
	int button;
	int segment;
	int state;        /* 0 waiting, 1 held, 2 released */
	unsigned from;
} press;

enum
{
	kMaxPresses = 1024,
	kDefaultHold = 6
};

static press s_presses[kMaxPresses];
static int s_pressCount;

/* Script steps run in order from the call anchor. A wait ends when its
 * condition holds, and `+N` presses count frames from that arrival. */
typedef enum
{
	kStepWait,
	kStepWrite,
	kStepCall,
	kStepAt,
	kStepSample,
	kStepVec
} stepKind;

typedef struct
{
	stepKind kind;
	char addr[96];       /* wait, write: [*]SYM[+OFF][:SIZE], or @FN for a call's result;
	                      * SYM may be $NAME for a binding */
	char symbol[64];     /* call */
	char argSym[4][64];  /* call: a nonempty entry is the address of that symbol */
	char argVar[4][32];  /* call: a nonempty entry is the value of that binding */
	char bind[32];       /* call: names the result; vec: names the buffer's address */
	uint32_t words[4];   /* vec */
	char line[96];       /* the step as written, for messages */
	uint32_t args[4];
	int argCount;
	uint32_t fargs[4];   /* call: float arguments as raw bits, in $f12 up; counted apart from args */
	int fargCount;
	int op;
	uint32_t value;
	unsigned bound;
	int orBits;          /* write: OR the value into the old one */
	int relative;        /* at: frames after the last wait's arrival */
} scriptStep;

enum { kMaxSteps = 32 };
static scriptStep s_steps[kMaxSteps];
static int s_stepCount;
static int s_stepCursor;
static int s_waitsDone;
static unsigned s_arrivals[kMaxSteps + 1];
static unsigned s_waitStart;
static int s_waitStarted;
static int s_stepFailed;
static int s_stepWaits;
static const char* const kOps[] = { "eq", "ne", "ge", "le", "gt", "lt" };

/* A scheduled call into the guest: a game's own entry point, run at a chosen
 * frame with chosen arguments. The game's sequence manager is the reason this
 * exists: dds3AdminiCallSequence(6, 0, 0, 0) puts SMT3 in a field, so a scene
 * is a call rather than a savestate, and the same call drives a native port. */
typedef struct
{
	unsigned frame;
	char symbol[64];
	uint32_t args[4];
	int argCount;
	int done;
} guestCall;

enum { kMaxCalls = 16 };
static guestCall s_calls[kMaxCalls];
static int s_callCount;
static uint32_t s_frame;

/* A scheduled write into guest memory, made from the same anchor as a call and
 * just before it, so a scene can be selected before the sequence that reads it
 * starts. */
typedef struct
{
	unsigned frame;
	uint32_t addr;
	uint32_t value;
	uint32_t size;
	int done;
} guestPoke;

enum { kMaxPokes = 32 };
static guestPoke s_pokes[kMaxPokes];
static int s_pokeCount;

/* FRAME:ADDR:VALUE[:SIZE] */
static int addPoke(const char* text)
{
	guestPoke* poke;

	if (s_pokeCount == kMaxPokes)
		return 0;
	poke = &s_pokes[s_pokeCount];
	memset(poke, 0, sizeof(*poke));
	poke->size = 4;
	if (sscanf(text, "%u:%x:%i:%u", &poke->frame, &poke->addr, (int*)&poke->value,
			&poke->size) < 3)
	{
		if (sscanf(text, "%u:%x:%i", &poke->frame, &poke->addr, (int*)&poke->value) < 3)
			return 0;
		poke->size = 4;
	}
	if (poke->size != 1 && poke->size != 2 && poke->size != 4)
		return 0;
	s_pokeCount++;
	return 1;
}
/* Where a scheduled call is made from. pcsx2hook_call_ee is for hook handlers
 * only, because it masks EE interrupts and needs the processor stopped at a
 * known point; made from the frame callback the call runs and its effects do
 * not stick. So the calls are fired from a hook on a function the game reaches
 * every frame. */
static const char* s_callAnchor = "sdfWaitVblank";

/* FRAME:SYMBOL[:a0[,a1[,a2[,a3]]]] */
static int addCall(const char* text)
{
	guestCall* call;
	int n = 0;

	if (s_callCount == kMaxCalls)
		return 0;
	call = &s_calls[s_callCount];
	memset(call, 0, sizeof(*call));
	if (sscanf(text, "%u:%63[^:]%n", &call->frame, call->symbol, &n) < 2)
		return 0;
	if (text[n] == ':')
	{
		const char* at = text + n + 1;
		while (*at && call->argCount < 4)
		{
			call->args[call->argCount++] = (uint32_t)strtoul(at, (char**)&at, 0);
			if (*at == ',')
				at++;
			else
				break;
		}
	}
	s_callCount++;
	return 1;
}
static pcsx2hook_ctx* s_ctx;

static int parsePress(const char* text, int segment)
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
		s_presses[s_pressCount].segment = segment;
		s_presses[s_pressCount].hold = hold ? hold : 1;
		s_presses[s_pressCount].button = b;
		s_pressCount++;
		return 1;
	}
	fprintf(stderr, "unknown button '%s'\n", name);
	return 0;
}

enum { kMaxSamples = 4 };
static char s_samples[kMaxSamples][96];
static int s_sampleCount;
static unsigned s_sampleFrame = (unsigned)-1;

static int addStep(const scriptStep* step)
{
	if (s_stepCount == kMaxSteps)
	{
		fprintf(stderr, "a script holds at most %d steps\n", kMaxSteps);
		return 0;
	}
	s_steps[s_stepCount++] = *step;
	return 1;
}

/* Names bound by "call ... -> NAME" and "vec NAME ...", set as those steps run. A
 * name used before it is bound, or never bound, ends the run naming the step. */
enum
{
	kMaxBinds = 16,
	kMaxVecs = 8,
	kVecBytes = 16,
	kNameLen = 32
};
typedef struct
{
	char name[kNameLen];
	uint32_t value;
	int bound;
} binding;
static binding s_binds[kMaxBinds];
static int s_bindCount;
static int s_vecCount;
static const scriptStep* s_curStep;
static int s_curIndex;

/* The guest allocator that backs "vec" steps. sdfChipAllocDirect(size) returns the
 * pointer itself, where sdfMemAllocDirect returns a handle that needs sdfMemLock. */
static const char* s_vecAllocSym = "sdfChipAllocDirect";
static int s_vecAllocAlign;   /* the allocator takes (size, align) rather than (size) */
static uint32_t s_vecBase;
static int s_vecUsed;

static int validName(const char* name)
{
	size_t len = strlen(name);

	if (len == 0 || len >= kNameLen || (name[0] >= '0' && name[0] <= '9'))
		return 0;
	for (size_t i = 0; i < len; i++)
	{
		char c = name[i];

		if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_'))
			return 0;
	}
	return 1;
}

static int declareBinding(const char* name, const char* line)
{
	if (!validName(name))
	{
		fprintf(stderr, "[script] bad binding name '%s' in: %s\n", name, line);
		return 0;
	}
	for (int i = 0; i < s_bindCount; i++)
	{
		if (strcmp(s_binds[i].name, name) == 0)
		{
			fprintf(stderr, "[script] $%s is bound twice, second in: %s\n", name, line);
			return 0;
		}
	}
	if (s_bindCount == kMaxBinds)
	{
		fprintf(stderr, "[script] at most %d bindings: %s\n", kMaxBinds, line);
		return 0;
	}
	snprintf(s_binds[s_bindCount++].name, kNameLen, "%s", name);
	return 1;
}

/* The binding named by an address's [*]$NAME[+OFF][:SIZE] base, or "" when it names a symbol. */
static void addrVar(const char* text, char* out)
{
	int len;

	out[0] = '\0';
	if (*text == '*')
		text++;
	if (*text != '$')
		return;
	len = (int)strcspn(text + 1, "+:");
	if (len >= kNameLen)
		len = kNameLen - 1;
	snprintf(out, kNameLen, "%.*s", len, text + 1);
}

static int stepIndexOf(const char* name)
{
	for (int i = 0; i < s_stepCount; i++)
	{
		const scriptStep* s = &s_steps[i];

		if ((s->kind == kStepVec || (s->kind == kStepCall && s->bind[0])) &&
		    strcmp(s->bind, name) == 0)
			return i;
	}
	return -1;
}

static int checkUse(const char* name, int use)
{
	int def = stepIndexOf(name);

	if (def < 0)
	{
		fprintf(stderr, "[script] step %d (%s): unknown binding $%s\n", use + 1, s_steps[use].line, name);
		return 0;
	}
	if (def >= use)
	{
		fprintf(stderr, "[script] step %d (%s): $%s is used before its step %d binds it\n", use + 1,
			s_steps[use].line, name, def + 1);
		return 0;
	}
	return 1;
}

/* Checks every $NAME in the steps, once the whole script is read so that a name
 * bound later is told apart from one never bound. */
static int checkBindings(void)
{
	for (int i = 0; i < s_stepCount; i++)
	{
		const scriptStep* s = &s_steps[i];
		char var[kNameLen];

		for (int a = 0; a < s->argCount; a++)
		{
			if (s->argVar[a][0] && !checkUse(s->argVar[a], i))
				return 0;
		}
		if (s->kind == kStepWait || s->kind == kStepWrite || s->kind == kStepSample)
		{
			addrVar(s->addr, var);
			if (var[0] && !checkUse(var, i))
				return 0;
		}
	}
	return 1;
}

static int lookupBinding(const char* name, uint32_t* value, int quiet)
{
	for (int i = 0; i < s_bindCount; i++)
	{
		if (strcmp(s_binds[i].name, name) != 0)
			continue;
		if (!s_binds[i].bound)
		{
			if (!quiet)
				fprintf(stderr, "[step] %s: $%s is used before its call has run\n",
					s_curStep ? s_curStep->line : "sample", name);
			return 0;
		}
		*value = s_binds[i].value;
		return 1;
	}
	if (!quiet)
		fprintf(stderr, "[step] %s: unknown binding $%s\n", s_curStep ? s_curStep->line : "sample", name);
	return 0;
}

static void setBinding(const char* name, uint32_t value)
{
	for (int i = 0; i < s_bindCount; i++)
	{
		if (strcmp(s_binds[i].name, name) == 0)
		{
			s_binds[i].value = value;
			s_binds[i].bound = 1;
		}
	}
}

/* Splits "A, B C" on spaces and commas, in place. */
static int splitArgs(char* text, char** out, int max)
{
	int n = 0;
	char* tok = strtok(text, " \t\r\n,");

	while (tok)
	{
		if (n == max)
			return -1;
		out[n++] = tok;
		tok = strtok(NULL, " \t\r\n,");
	}
	return n;
}

/* Raw bits when written 0x..., else a decimal float: f:0x3F800000 and f:1.0 are the same. */
static int parseFloatArg(const char* text, uint32_t* bits)
{
	char* end;

	if (text[0] == '0' && (text[1] == 'x' || text[1] == 'X'))
		*bits = (uint32_t)strtoul(text, &end, 16);
	else
	{
		float f = strtof(text, &end);

		memcpy(bits, &f, sizeof(*bits));
	}
	return text[0] != '\0' && *end == '\0';
}

static int isVerb(const char* line, const char* verb)
{
	size_t len = strlen(verb);

	line += strspn(line, " \t");
	return strncmp(line, verb, len) == 0 && strchr(" \t\r\n", line[len]) != NULL;
}

/* wait BOUND ADDR OP VALUE | write|or ADDR VALUE | sample ADDR | at [+]FRAME |
 * vec NAME W0 W1 W2 W3 | call SYM [A0 A1 ..] [-> NAME], where an argument is a
 * number, &SYMBOL or $NAME (commas between arguments are allowed), and an ADDR may
 * use $NAME as its symbol. Returns -1 on a bad line, 0 when the line is not a step. */
static int parseStep(const char* line)
{
	scriptStep step;
	char op[8];

	memset(&step, 0, sizeof(step));
	{
		const char* from = line + strspn(line, " \t");
		size_t len = strcspn(from, "\r\n");

		snprintf(step.line, sizeof(step.line), "%.*s", (int)len, from);
	}
	if (sscanf(line, " wait %u %95s %7s %i", &step.bound, step.addr, op, (int*)&step.value) == 4)
	{
		step.kind = kStepWait;
		step.op = -1;
		for (int i = 0; i < 6; i++)
		{
			if (strcmp(op, kOps[i]) == 0)
				step.op = i;
		}
		if (step.op < 0 || step.bound == 0)
			return -1;
		s_stepWaits++;
		return addStep(&step) ? 1 : -1;
	}
	if (sscanf(line, " write %95s %i", step.addr, (int*)&step.value) == 2)
	{
		step.kind = kStepWrite;
		return addStep(&step) ? 1 : -1;
	}
	if (sscanf(line, " or %95s %i", step.addr, (int*)&step.value) == 2)
	{
		step.kind = kStepWrite;
		step.orBits = 1;
		return addStep(&step) ? 1 : -1;
	}
	if (sscanf(line, " sample %95s", step.addr) == 1)
	{
		step.kind = kStepSample;
		return addStep(&step) ? 1 : -1;
	}
	if (sscanf(line, " at +%u", &step.value) == 1 || sscanf(line, " at %u", &step.value) == 1)
	{
		step.kind = kStepAt;
		step.relative = strchr(line, '+') != NULL;
		return addStep(&step) ? 1 : -1;
	}
	if (isVerb(line, "vec"))
	{
		char text[160];
		char* tok[8];
		int count;

		snprintf(text, sizeof(text), "%s", line + strspn(line, " \t") + 3);
		count = splitArgs(text, tok, 8);
		if (count != 5 || s_vecCount == kMaxVecs)
		{
			fprintf(stderr, "[script] vec takes NAME and 4 words, at most %d vecs: %s\n", kMaxVecs, step.line);
			return -1;
		}
		for (int w = 0; w < 4; w++)
		{
			char* end;

			step.words[w] = (uint32_t)strtoul(tok[1 + w], &end, 0);
			if (*end)
			{
				fprintf(stderr, "[script] bad vec word '%s': %s\n", tok[1 + w], step.line);
				return -1;
			}
		}
		step.kind = kStepVec;
		snprintf(step.bind, sizeof(step.bind), "%s", tok[0]);
		if (!declareBinding(step.bind, step.line))
			return -1;
		s_vecCount++;
		return addStep(&step) ? 1 : -1;
	}
	if (isVerb(line, "sequence"))
	{
		char text[160];
		char* tok[8];
		char synth[192] = "call dds3AdminiCallSequence";
		int count;
		int ok;

		snprintf(text, sizeof(text), "%s", line + strspn(line, " \t") + 8);
		count = splitArgs(text, tok, 8);
		if (count < 1 || count > 4)
		{
			fprintf(stderr, "[script] sequence takes N and up to 3 arguments: %s\n", step.line);
			return -1;
		}
		for (int t = 0; t < 4; t++)
		{
			strncat(synth, " ", sizeof(synth) - strlen(synth) - 1);
			strncat(synth, t < count ? tok[t] : "0", sizeof(synth) - strlen(synth) - 1);
		}
		ok = parseStep(synth) == 1;
		if (ok)
			snprintf(s_steps[s_stepCount - 1].line, sizeof(step.line), "%s", step.line);
		return ok ? 1 : -1;
	}
	if (isVerb(line, "call"))
	{
		char text[192];
		char* tok[16];
		int count;
		int stop;

		snprintf(text, sizeof(text), "%s", line + strspn(line, " \t") + 4);
		count = splitArgs(text, tok, 16);
		if (count < 1)
			return -1;
		snprintf(step.symbol, sizeof(step.symbol), "%s", tok[0]);
		stop = count;
		for (int t = 1; t < count; t++)
		{
			if (strcmp(tok[t], "->") == 0)
				stop = t;
		}
		step.kind = kStepCall;
		for (int t = 1; t < stop; t++)
		{
			const char* at = tok[t];
			int a = step.argCount;

			if (strncmp(at, "f:", 2) == 0)
			{
				if (step.fargCount == 4 || !parseFloatArg(at + 2, &step.fargs[step.fargCount]))
				{
					fprintf(stderr, "[script] bad float argument '%s': %s\n", at, step.line);
					return -1;
				}
				step.fargCount++;
				continue;
			}
			if (a == 4)
				return -1;
			if (*at == '&' || *at == '$')
			{
				char* dst = *at == '&' ? step.argSym[a] : step.argVar[a];
				size_t cap = *at == '&' ? sizeof(step.argSym[0]) : sizeof(step.argVar[0]);

				if (at[1] == '\0' || strlen(at + 1) >= cap)
					return -1;
				snprintf(dst, cap, "%s", at + 1);
			}
			else
			{
				char* end;

				step.args[a] = (uint32_t)strtoul(at, &end, 0);
				if (*end)
					return -1;
			}
			step.argCount++;
		}
		if (stop < count)
		{
			if (stop + 2 != count)
			{
				fprintf(stderr, "[script] \"->\" takes one name: %s\n", step.line);
				return -1;
			}
			snprintf(step.bind, sizeof(step.bind), "%s", tok[stop + 1]);
			if (!declareBinding(step.bind, step.line))
				return -1;
		}
		return addStep(&step) ? 1 : -1;
	}
	return 0;
}

static int readScript(const char* path)
{
	char line[192];
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
		int segment = 0;
		const char* at = line;
		int step;

		if (hash)
			*hash = '\0';
		step = parseStep(line);
		if (step < 0)
		{
			fprintf(stderr, "%s: cannot read the step: %s", path, line);
			fclose(f);
			return 0;
		}
		if (step > 0)
			continue;
		at += strspn(line, " ");
		if (*at == '+')
		{
			at++;
			segment = 1;
		}
		if (sscanf(at, "%u %31s %u", &frame, name, &hold) == 3)
			snprintf(token, sizeof(token), "%u:%s:%u", frame, name, hold);
		else if (sscanf(at, "%u %31s", &frame, name) == 2)
			snprintf(token, sizeof(token), "%u:%s", frame, name);
		else
			continue;
		if (segment)
		{
			segment = s_stepWaits;
			if (segment == 0)
			{
				fprintf(stderr, "%s: +N needs a wait before it: %s", path, line);
				fclose(f);
				return 0;
			}
		}
		if (!parsePress(token, segment))
		{
			fclose(f);
			return 0;
		}
	}
	fclose(f);
	return checkBindings();
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

static uint32_t s_writeLo, s_writeHi;

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

static int onCallAnchor(pcsx2hook_regs* regs, void* user);

static void onVmReady(void* user)
{
	(void)user;
	for (int i = 0; i < s_feedCount; i++)
	{
		if (!pcsx2hook_add_hook(s_ctx, s_feeds[i].addr, feedPre, NULL, &s_feeds[i]))
			fprintf(stderr, "cannot hook %08X\n", s_feeds[i].addr);
	}
	if (s_callCount || s_pokeCount || s_stepCount)
	{
		uint32_t anchor = pcsx2hook_find_symbol(s_ctx, s_callAnchor);

		if (anchor == 0)
			fprintf(stderr, "[call] no symbol named %s to call from\n", s_callAnchor);
		else if (!pcsx2hook_add_hook(s_ctx, anchor, onCallAnchor, NULL, NULL))
			fprintf(stderr, "[call] cannot hook %s at %08X\n", s_callAnchor, anchor);
		else
			fprintf(stderr, "[call] calling from %s at %08X\n", s_callAnchor, anchor);
	}
}

/* Report what each hook saw. A substitution that never fires looks exactly
 * like one that worked, and reading the result of a run that did nothing is
 * worse than reading no result. */
/* One row per distinct storing pc: the first store is printed, the rest are counted. */
static struct
{
	uint32_t pc;
	unsigned count;
} s_writers[256];
static int s_writerCount;

static void onWrite(uint32_t addr, uint32_t size, uint64_t value, uint32_t pc, void* user)
{
	char name[256];
	int i;

	(void)user;
	for (i = 0; i < s_writerCount; i++)
	{
		if (s_writers[i].pc == pc)
		{
			s_writers[i].count++;
			return;
		}
	}
	if (s_writerCount == 256)
	{
		fprintf(stderr, "[write] more than 256 distinct storing pcs, the rest are not listed\n");
		s_writerCount++;
		return;
	}
	if (s_writerCount > 256)
		return;
	s_writers[s_writerCount].pc = pc;
	s_writers[s_writerCount++].count = 1;
	pcsx2hook_resolve_symbol(s_ctx, pc, name, sizeof(name));
	fprintf(stderr, "[write] frame %u first store %08X size %u value %llx pc %08X in %s\n", s_frame,
	        addr, size, (unsigned long long)value, pc, name);
}

static void onShutdown(void* user)
{
	(void)user;
	for (int i = 0; i < s_writerCount && i < 256; i++)
		fprintf(stderr, "[write] pc %08X stored %u times\n", s_writers[i].pc, s_writers[i].count);
	for (int i = 0; i < s_feedCount; i++)
	{
		fprintf(stderr, "[arg] %08X called %u times", s_feeds[i].addr, s_feeds[i].hits);
		if (s_feeds[i].count)
			fprintf(stderr, ", fed $%d from %d values", s_feeds[i].reg, s_feeds[i].count);
		fprintf(stderr, "\n");
	}
}


/* [*]BASE[+OFF][:SIZE], where BASE is a symbol or a $binding. */
typedef struct
{
	char name[64];
	int deref;
	int var;
	uint32_t off;
	uint32_t size;
} addrRef;

static int parseAddrRef(const char* text, addrRef* ref)
{
	const char* at = text;
	int len;

	memset(ref, 0, sizeof(*ref));
	ref->size = 4;
	if (*at == '*')
	{
		ref->deref = 1;
		at++;
	}
	if (*at == '$')
	{
		ref->var = 1;
		at++;
	}
	len = (int)strcspn(at, "+:");
	if (len == 0 || len >= (int)sizeof(ref->name))
		return 0;
	snprintf(ref->name, sizeof(ref->name), "%.*s", len, at);
	at += len;
	if (*at == '+')
		ref->off = (uint32_t)strtoul(at + 1, (char**)&at, 0);
	if (*at == ':')
		ref->size = (uint32_t)strtoul(at + 1, (char**)&at, 0);
	return 1;
}

static int refBase(const addrRef* ref, uint32_t* guest, int quiet)
{
	if (ref->var)
		return lookupBinding(ref->name, guest, quiet);
	*guest = pcsx2hook_find_symbol(s_ctx, ref->name);
	if (*guest == 0)
	{
		if (!quiet)
			fprintf(stderr, "[step] no symbol named %s; is a map loaded?\n", ref->name);
		return 0;
	}
	return 1;
}

/* Resolves [*]BASE[+OFF][:SIZE] to a host pointer, or NULL with the reason
 * printed. */
static void* resolveAddr(const char* text, uint32_t* size)
{
	addrRef ref;
	uint32_t guest;
	void* host;

	*size = 4;
	if (!parseAddrRef(text, &ref))
	{
		fprintf(stderr, "[step] cannot read the address '%s'\n", text);
		return NULL;
	}
	*size = ref.size;
	if (!refBase(&ref, &guest, 0))
		return NULL;
	if (ref.deref)
	{
		uint32_t* pointer = (uint32_t*)pcsx2hook_map_guest(s_ctx, guest, 4);

		if (!pointer || *pointer == 0)
		{
			fprintf(stderr, "[step] *%s%s is null or unmapped\n", ref.var ? "$" : "", ref.name);
			return NULL;
		}
		guest = *pointer;
	}
	host = pcsx2hook_map_guest(s_ctx, guest + ref.off, ref.size);
	if (!host)
		fprintf(stderr, "[step] %s%s+%u is not mapped\n", ref.var ? "$" : "", ref.name, ref.off);
	return host;
}

/* A dereferenced sample of a null pointer reads as null; a wait on one is still an error. */
static int sampleIsNull(const char* text)
{
	addrRef ref;
	uint32_t guest;
	uint32_t* pointer;

	if (!parseAddrRef(text, &ref) || !ref.deref || !refBase(&ref, &guest, 1))
		return 0;
	pointer = (uint32_t*)pcsx2hook_map_guest(s_ctx, guest, 4);
	return pointer && *pointer == 0;
}

static int readStepValue(const char* text, uint32_t* value)
{
	uint32_t size;
	void* at;

	if (text[0] == '@')
	{
		uint32_t pc = pcsx2hook_find_symbol(s_ctx, text + 1);

		if (pc == 0)
		{
			fprintf(stderr, "[step] no function named %s; is a map loaded?\n", text + 1);
			return 0;
		}
		*value = pcsx2hook_call_ee(s_ctx, pc, NULL, 0);
		return 1;
	}
	at = resolveAddr(text, &size);
	if (!at)
		return 0;
	*value = 0;
	memcpy(value, at, size);
	return 1;
}

static int compareValue(int op, uint32_t have, uint32_t want)
{
	switch (op)
	{
		case 0: return have == want;
		case 1: return have != want;
		case 2: return have >= want;
		case 3: return have <= want;
		case 4: return have > want;
		case 5: return have < want;
	}
	return 0;
}

static void failScript(void)
{
	s_stepFailed = 1;
	pcsx2hook_request_stop(s_ctx);
}

/* One allocation carves every vec: the first vec step calls the allocator from the anchor,
 * for room for kMaxVecs plus the slack to align the start to 16. */
static int allocVecBuffer(void)
{
	uint32_t pc, args[2], got;
	int argc = 1;

	if (s_vecBase)
		return 1;
	pc = pcsx2hook_find_symbol(s_ctx, s_vecAllocSym);
	if (pc == 0)
	{
		fprintf(stderr, "[step] %s: no allocator named %s; is a map loaded?\n", s_curStep->line, s_vecAllocSym);
		return 0;
	}
	args[0] = kMaxVecs * kVecBytes + kVecBytes;
	if (s_vecAllocAlign)
	{
		args[1] = kVecBytes;
		argc = 2;
	}
	got = pcsx2hook_call_ee(s_ctx, pc, args, argc);
	if (got == 0)
	{
		fprintf(stderr, "[step] %s: %s(%u) returned 0\n", s_curStep->line, s_vecAllocSym, args[0]);
		return 0;
	}
	s_vecBase = (got + kVecBytes - 1) & ~(uint32_t)(kVecBytes - 1);
	fprintf(stderr, "[step] %s(%u) = %08X, vecs from %08X\n", s_vecAllocSym, args[0], got, s_vecBase);
	return 1;
}

/* Runs the steps that are due. A wait that has not come true holds the rest,
 * and one past its bound ends the run with exit code 1. */
static void runSteps(void)
{
	while (s_stepCursor < s_stepCount && !s_stepFailed)
	{
		scriptStep* step = &s_steps[s_stepCursor];

		s_curStep = step;
		s_curIndex = s_stepCursor + 1;
		if (step->kind == kStepWait)
		{
			uint32_t have;

			if (!s_waitStarted)
			{
				s_waitStarted = 1;
				s_waitStart = s_frame;
			}
			if (!readStepValue(step->addr, &have))
			{
				failScript();
				return;
			}
			if (compareValue(step->op, have, step->value))
			{
				fprintf(stderr, "[step] frame %u: %s %s %u held after %u frame(s)\n", s_frame,
					step->addr, kOps[step->op], step->value, s_frame - s_waitStart);
				s_waitsDone++;
				s_arrivals[s_waitsDone] = s_frame;
				s_waitStarted = 0;
				s_stepCursor++;
				continue;
			}
			if (s_frame - s_waitStart > step->bound)
			{
				fprintf(stderr, "[step] frame %u: %s %s %u did not hold within %u frames; read %u\n",
					s_frame, step->addr, kOps[step->op], step->value, step->bound, have);
				failScript();
			}
			return;
		}
		if (step->kind == kStepSample)
		{
			if (s_sampleCount == kMaxSamples)
			{
				fprintf(stderr, "at most %d sample steps\n", kMaxSamples);
				failScript();
				return;
			}
			strcpy(s_samples[s_sampleCount++], step->addr);
		}
		else if (step->kind == kStepAt)
		{
			if (s_frame < step->value + (step->relative ? s_arrivals[s_waitsDone] : 0))
				return;
		}
		else if (step->kind == kStepWrite)
		{
			uint32_t size;
			void* at = resolveAddr(step->addr, &size);

			if (!at || (size != 1 && size != 2 && size != 4))
			{
				failScript();
				return;
			}
			if (step->orBits)
			{
				uint32_t old = 0;

				memcpy(&old, at, size);
				old |= step->value;
				memcpy(at, &old, size);
			}
			else
				memcpy(at, &step->value, size);
			fprintf(stderr, "[step] frame %u: %s %s %u\n", s_frame, step->addr,
				step->orBits ? "|=" : "=", step->value);
		}
		else if (step->kind == kStepVec)
		{
			uint32_t guest;
			void* at;

			if (!allocVecBuffer())
			{
				failScript();
				return;
			}
			guest = s_vecBase + (uint32_t)s_vecUsed * kVecBytes;
			at = pcsx2hook_map_guest(s_ctx, guest, kVecBytes);
			if (!at)
			{
				fprintf(stderr, "[step] %s: scratch %08X is not mapped\n", step->line, guest);
				failScript();
				return;
			}
			memcpy(at, step->words, kVecBytes);
			s_vecUsed++;
			setBinding(step->bind, guest);
			fprintf(stderr, "[step] frame %u: vec %s at %08X = %08X %08X %08X %08X\n", s_frame,
				step->bind, guest, step->words[0], step->words[1], step->words[2], step->words[3]);
		}
		else
		{
			uint32_t pc = pcsx2hook_find_symbol(s_ctx, step->symbol);
			uint32_t args[4];
			uint32_t result;

			if (pc == 0)
			{
				fprintf(stderr, "[step] no function named %s; is a map loaded?\n", step->symbol);
				failScript();
				return;
			}
			for (int a = 0; a < step->argCount; a++)
			{
				args[a] = step->args[a];
				if (step->argSym[a][0])
				{
					args[a] = pcsx2hook_find_symbol(s_ctx, step->argSym[a]);
					if (args[a] == 0)
					{
						fprintf(stderr, "[step] no symbol named %s\n", step->argSym[a]);
						failScript();
						return;
					}
				}
				else if (step->argVar[a][0] && !lookupBinding(step->argVar[a], &args[a], 0))
				{
					failScript();
					return;
				}
			}
			if (step->fargCount)
			{
				if (!pcsx2hook_call_ee_ex(s_ctx, pc, args, (size_t)step->argCount, step->fargs,
						(size_t)step->fargCount, &result, NULL))
				{
					fprintf(stderr, "[step] %s: the call did not run: %s\n", step->line,
						pcsx2hook_get_last_error(s_ctx));
					failScript();
					return;
				}
			}
			else
				result = pcsx2hook_call_ee(s_ctx, pc, args, step->argCount);
			if (step->bind[0])
			{
				setBinding(step->bind, result);
				fprintf(stderr, "[step] frame %u: %s = %u -> %s\n", s_frame, step->symbol, result, step->bind);
			}
			else
				fprintf(stderr, "[step] frame %u: %s = %u\n", s_frame, step->symbol, result);
		}
		s_stepCursor++;
	}
}

/* The anchor's pre-handler: the EE is stopped here, which is the only place a
 * guest call is allowed. */
static int onCallAnchor(pcsx2hook_regs* regs, void* user)
{
	(void)regs;
	(void)user;
	runSteps();
	if (s_sampleCount && s_frame != s_sampleFrame)
	{
		s_sampleFrame = s_frame;
		s_curStep = NULL;
		for (int i = 0; i < s_sampleCount; i++)
		{
			uint32_t have;

			if (sampleIsNull(s_samples[i]))
			{
				fprintf(stderr, "[sample] frame %u: %s = null\n", s_frame, s_samples[i]);
				continue;
			}
			if (!readStepValue(s_samples[i], &have))
			{
				failScript();
				return 0;
			}
			fprintf(stderr, "[sample] frame %u: %s = %u\n", s_frame, s_samples[i], have);
		}
	}
	for (int i = 0; i < s_pokeCount; i++)
	{
		guestPoke* poke = &s_pokes[i];
		void* at;

		if (poke->done || s_frame < poke->frame)
			continue;
		poke->done = 1;
		at = pcsx2hook_map_guest(s_ctx, poke->addr, poke->size);
		if (!at)
		{
			fprintf(stderr, "[poke] %08X is not mapped\n", poke->addr);
			continue;
		}
		memcpy(at, &poke->value, poke->size);
		fprintf(stderr, "[poke] frame %u: %08X = %u (%u byte(s))\n", s_frame,
			poke->addr, poke->value, poke->size);
	}
	for (int i = 0; i < s_callCount; i++)
	{
		guestCall* call = &s_calls[i];
		uint32_t pc;

		if (call->done || s_frame < call->frame)
			continue;
		call->done = 1;
		pc = pcsx2hook_find_symbol(s_ctx, call->symbol);
		if (pc == 0)
		{
			fprintf(stderr, "[call] no symbol named %s; is a map loaded?\n", call->symbol);
			continue;
		}
		fprintf(stderr, "[call] frame %u: %s(", s_frame, call->symbol);
		for (int a = 0; a < call->argCount; a++)
			fprintf(stderr, a ? ", %u" : "%u", call->args[a]);
		fprintf(stderr, ") = ");
		fprintf(stderr, "%u\n", pcsx2hook_call_ee(s_ctx, pc, call->args, call->argCount));
	}
	return PCSX2HOOK_CONTINUE;
}

static void onFrame(uint32_t frame, void* user)
{
	(void)user;
	s_frame = frame;
	for (int i = 0; i < s_pressCount; i++)
	{
		press* p = &s_presses[i];

		if (p->state == 0 && p->segment <= s_waitsDone)
		{
			unsigned base = p->segment ? s_arrivals[p->segment] : 0;

			if (frame >= base + p->frame)
			{
				p->state = 1;
				p->from = frame;
				pcsx2hook_set_pad_button(s_ctx, p->button, 1);
			}
		}
		else if (p->state == 1 && frame >= p->from + p->hold)
		{
			p->state = 2;
			pcsx2hook_set_pad_button(s_ctx, p->button, 0);
		}
	}
}

static void usage(FILE* f)
{
	fprintf(f,
		"usage: pcsx2hook_cli --bios FILE [options] DISC\n"
		"\n"
		"  --state FILE        boot into a savestate instead of the disc's start\n"
		"  --elf FILE          boot this ELF, with the disc still mounted\n"
		"  --frames N          stop after N frames and write the traces (default 60)\n"
		"  --out DIR           where the traces are written (default pcsx2hook_out)\n"
		"  --symbols PATH      symbol map, or a directory holding <ELF>.map files\n"
		"  --trace NAME        enable a trace; repeat for more\n"
		"  --interp LIST       interpret these processors: all, or a comma list of ee,iop,vu0,vu1\n"
		"  --accurate-timing   turn off Instant VU1 and the idle-loop and INTC_STAT skips\n"
		"  --software-gs       rasterize with the software GS instead of the null renderer\n"
		"  --set NAME=VALUE    any other library setting, by its PCSX2HOOK_ variable name\n"
		"  --press F:BUTTON[:N]  press BUTTON at frame F for N frames; repeat for more\n"
		"  --script FILE       lines of \"FRAME BUTTON [HOLD]\", # comments, plus in-order steps from the\n"
		"                      call anchor: \"wait BOUND ADDR OP VALUE\", \"write ADDR VALUE\",\n"
		"                      \"or ADDR VALUE\", \"at [+]FRAME\",\n"
		"                      \"call SYM [ARGS] [-> NAME]\" (an arg f:0x3F800000 or f:1.5 is a float, in $f12 up, counted apart from the\n"
		"                      ints; \"sequence N [A B C]\" is dds3AdminiCallSequence(N, A, B, C); ADDR is [*]SYM[+OFF][:SIZE] or @FN, OP is\n"
		"                      eq ne ge le gt lt, an arg may be &SYM or $NAME, a bound name; $NAME stands\n"
		"                      for SYM in an ADDR), \"vec NAME W0 W1 W2 W3\" (16 aligned guest bytes, NAME\n"
		"                      is their address) and \"+N BUTTON [HOLD]\" after a wait.\n"
		"                      A wait past BOUND frames, or a run ending first, exits 1\n"
		"  --vec-alloc SYM[:size|:size,align]  the guest allocator for vec steps, returning a\n"
		"                      pointer (default sdfChipAllocDirect:size)\n"
		"  --call F:SYM[:a0,a1,..]  call the guest function SYM at frame F; repeat for more\n"
		"  --poke F:ADDR:VAL[:SIZE]  write guest memory at frame F, before any --call\n"
		"  --call-anchor SYM   where those calls are made from, a function the game\n"
		"                      reaches every frame (default sdfWaitVblank)\n"
		"  --arg ADDR:REG:LIST   feed register REG a different value from LIST at each\n"
		"                      call of the function at ADDR, cycling\n"
		"  --arg-file ADDR:REG:FILE  the same, with the values read from FILE\n"
		"  --watch ADDR        only count calls of the function at ADDR\n"
		"  --watch-writes LO:HI  list each pc that stores into [LO, HI), with its function and\n"
		"                      a count at the end; runs the EE interpreted, so it is slow\n"
		"\n"
		"traces:");
	for (int i = 0; i < kTraceCount; i++)
		fprintf(f, " %s", kTraces[i].name);
	fprintf(f, "\n");
}

/* SYMBOL[:size|:size,align]: the allocator for vec steps, called with the byte count and
 * optionally the alignment, and returning the guest pointer. */
static int parseVecAlloc(const char* text)
{
	const char* colon = strchr(text, ':');
	static char sym[64];
	size_t len = colon ? (size_t)(colon - text) : strlen(text);

	if (len == 0 || len >= sizeof(sym))
		return 0;
	if (colon && strcmp(colon, ":size") != 0 && strcmp(colon, ":size,align") != 0)
		return 0;
	snprintf(sym, sizeof(sym), "%.*s", (int)len, text);
	s_vecAllocSym = sym;
	s_vecAllocAlign = colon && strcmp(colon, ":size,align") == 0;
	return 1;
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
	const char* elf = NULL;
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
		else if (strcmp(a, "--elf") == 0)
		{
			if (!v)
			{
				fprintf(stderr, "--elf takes a path\n");
				return 2;
			}
			elf = argv[++i];
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
		else if (strcmp(a, "--watch-writes") == 0)
		{
			char* end = NULL;
			s_writeLo = v ? (uint32_t)strtoul(v, &end, 0) : 0;
			if (!v || *end != ':' || (s_writeHi = (uint32_t)strtoul(end + 1, NULL, 0)) <= s_writeLo)
			{
				fprintf(stderr, "--watch-writes takes LO:HI with LO < HI\n");
				return 2;
			}
			i++;
		}
		else if (strcmp(a, "--poke") == 0)
		{
			if (!v || !addPoke(v))
			{
				fprintf(stderr, "--poke takes FRAME:ADDR:VALUE[:SIZE]\n");
				return 2;
			}
			i++;
		}
		else if (strcmp(a, "--call-anchor") == 0)
		{
			if (!v)
			{
				fprintf(stderr, "--call-anchor takes a symbol name\n");
				return 2;
			}
			s_callAnchor = v;
			i++;
		}
		else if (strcmp(a, "--vec-alloc") == 0)
		{
			if (!v || !parseVecAlloc(v))
			{
				fprintf(stderr, "--vec-alloc takes SYMBOL[:size|:size,align]\n");
				return 2;
			}
			i++;
		}
		else if (strcmp(a, "--call") == 0)
		{
			if (!v || !addCall(v))
			{
				fprintf(stderr, "--call takes FRAME:SYMBOL[:a0,a1,a2,a3]\n");
				return 2;
			}
			i++;
		}
		else if (strcmp(a, "--press") == 0)
		{
			if (!v || !parsePress(v, 0))
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
	if (s_pressCount || s_callCount || s_pokeCount || s_stepCount || s_writeHi)
		cfg.on_frame = onFrame;
	if (s_feedCount || s_callCount || s_pokeCount || s_stepCount || s_writeHi)
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
	if (s_writeHi && !pcsx2hook_set_write_sink(ctx, s_writeLo, s_writeHi, onWrite, NULL))
	{
		fprintf(stderr, "--watch-writes: %s\n", pcsx2hook_get_last_error(ctx));
		pcsx2hook_destroy(ctx);
		return 1;
	}
	pcsx2hook_set_interpreter(ctx, cpus);
	pcsx2hook_set_accurate_timing(ctx, accurate);
	pcsx2hook_set_boot_state(ctx, state);
	pcsx2hook_set_boot_elf(ctx, elf);
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
	int rc = pcsx2hook_join(ctx);
	if (s_stepCursor < s_stepCount && !s_stepFailed)
	{
		fprintf(stderr, "[step] the run ended at step %d of %d\n", s_stepCursor + 1, s_stepCount);
		s_stepFailed = 1;
	}
	if (s_stepFailed)
		rc = 1;
	pcsx2hook_shutdown(ctx);
	pcsx2hook_destroy(ctx);
	return rc;
}

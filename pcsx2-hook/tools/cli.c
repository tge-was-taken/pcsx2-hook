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
	kStepCall
} stepKind;

typedef struct
{
	stepKind kind;
	char addr[96];       /* wait, write: [*]SYM[+OFF][:SIZE], or @FN for a call's result */
	char symbol[64];     /* call */
	char argSym[4][64];  /* call: a nonempty entry is the address of that symbol */
	uint32_t args[4];
	int argCount;
	int op;
	uint32_t value;
	unsigned bound;
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

/* wait BOUND ADDR OP VALUE | write ADDR VALUE [SIZE] | call SYM [A0[,A1..]],
 * where an argument is a number or &SYMBOL. Returns -1 on a bad line, 0 when
 * the line is not a step. */
static int parseStep(const char* line)
{
	scriptStep step;
	char op[8];
	char list[160];
	int n;

	memset(&step, 0, sizeof(step));
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
	n = sscanf(line, " call %63s %159s", step.symbol, list);
	if (n >= 1 && strncmp(line + strspn(line, " "), "call", 4) == 0)
	{
		const char* at = n == 2 ? list : "";

		step.kind = kStepCall;
		while (*at && step.argCount < 4)
		{
			if (*at == '&')
			{
				int len = (int)strcspn(at + 1, ",");

				if (len == 0 || len >= (int)sizeof(step.argSym[0]))
					return -1;
				snprintf(step.argSym[step.argCount], sizeof(step.argSym[0]), "%.*s", len, at + 1);
				at += 1 + len;
			}
			else
				step.args[step.argCount] = (uint32_t)strtoul(at, (char**)&at, 0);
			step.argCount++;
			if (*at == ',')
				at++;
			else
				break;
		}
		return *at == '\0' && addStep(&step) ? 1 : -1;
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


/* Resolves [*]SYM[+OFF][:SIZE] to a host pointer, or NULL with the reason
 * printed. */
static void* resolveAddr(const char* text, uint32_t* size)
{
	char sym[64];
	const char* at = text;
	int deref = 0;
	uint32_t off = 0;
	uint32_t guest;
	void* host;

	*size = 4;
	if (*at == '*')
	{
		deref = 1;
		at++;
	}
	int len = (int)strcspn(at, "+:");
	if (len == 0 || len >= (int)sizeof(sym))
		return NULL;
	snprintf(sym, sizeof(sym), "%.*s", len, at);
	at += len;
	if (*at == '+')
		off = (uint32_t)strtoul(at + 1, (char**)&at, 0);
	if (*at == ':')
		*size = (uint32_t)strtoul(at + 1, (char**)&at, 0);
	guest = pcsx2hook_find_symbol(s_ctx, sym);
	if (guest == 0)
	{
		fprintf(stderr, "[step] no symbol named %s; is a map loaded?\n", sym);
		return NULL;
	}
	if (deref)
	{
		uint32_t* pointer = (uint32_t*)pcsx2hook_map_guest(s_ctx, guest, 4);

		if (!pointer || *pointer == 0)
		{
			fprintf(stderr, "[step] *%s is null or unmapped\n", sym);
			return NULL;
		}
		guest = *pointer;
	}
	host = pcsx2hook_map_guest(s_ctx, guest + off, *size);
	if (!host)
		fprintf(stderr, "[step] %s+%u is not mapped\n", sym, off);
	return host;
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

/* Runs the steps that are due. A wait that has not come true holds the rest,
 * and one past its bound ends the run with exit code 1. */
static void runSteps(void)
{
	while (s_stepCursor < s_stepCount && !s_stepFailed)
	{
		scriptStep* step = &s_steps[s_stepCursor];

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
		if (step->kind == kStepWrite)
		{
			uint32_t size;
			void* at = resolveAddr(step->addr, &size);

			if (!at || (size != 1 && size != 2 && size != 4))
			{
				failScript();
				return;
			}
			memcpy(at, &step->value, size);
			fprintf(stderr, "[step] frame %u: %s = %u\n", s_frame, step->addr, step->value);
		}
		else
		{
			uint32_t pc = pcsx2hook_find_symbol(s_ctx, step->symbol);
			uint32_t args[4];

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
			}
			fprintf(stderr, "[step] frame %u: %s = %u\n", s_frame, step->symbol,
				pcsx2hook_call_ee(s_ctx, pc, args, step->argCount));
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
		"                      \"call SYM [ARGS]\" (ADDR is [*]SYM[+OFF][:SIZE] or @FN, OP is eq ne ge\n"
		"                      le gt lt, an arg may be &SYM) and \"+N BUTTON [HOLD]\" after a wait.\n"
		"                      A wait past BOUND frames, or a run ending first, exits 1\n"
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

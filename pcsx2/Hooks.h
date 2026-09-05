// SPDX-FileCopyrightText: 2002-2026 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#pragma once

#include "common/Pcsx2Types.h"

#include <initializer_list>

struct cpuRegisters;

namespace Hooks
{
	enum class Result
	{
		Continue,
		Exit
	};

	struct Context
	{
		u32* gpr; // 128-bit stride: register n's low word is at gpr[n * 4]
		float* fpr;
		u32 pc;

		u32 &a0, &a1, &a2, &a3, &t0, &t1, &t2, &t3, &sp, &ra, &v0;

		Context(u32* g, float* f, u32 p)
			: gpr(g)
			, fpr(f)
			, pc(p)
			, a0(g[4 * 4])
			, a1(g[5 * 4])
			, a2(g[6 * 4])
			, a3(g[7 * 4])
			, t0(g[8 * 4])
			, t1(g[9 * 4])
			, t2(g[10 * 4])
			, t3(g[11 * 4])
			, sp(g[29 * 4])
			, ra(g[31 * 4])
			, v0(g[2 * 4])
		{
		}

		u32& reg(int n) { return gpr[n * 4]; }
		float& freg(int n) { return fpr[n]; }

		// By value rather than a u64& through a cast: the replay scratch file is a plain u32 array
		// with no 8-byte alignment.
		u64 reg64(int n) const { return u64(gpr[n * 4]) | (u64(gpr[n * 4 + 1]) << 32); }
	};

	struct CallArgs
	{
		u32 callee;
		u32 a0, a1, a2, a3, t0, t1;
		u32 ra, v0, sp;
		// This ee-gcc build fills the FP and GPR argument slots from independent counters, so a float
		// parameter lands here instead of shifting the pointers after it out of $a2/$a3.
		float f12, f13, f14, f15;
		u32 a0hi, a1hi, a2hi, a3hi;

		// Appended rather than widening a0-a3 in place, which would pad the struct and write
		// indeterminate bytes into a recording.
		u64 arg64(int i) const { return u64((&a0)[i]) | (u64((&a0hi)[i]) << 32); }
	};

	using Handler = Result (*)(Context& ctx);

	using PostHandler = void (*)(Context& ctx);

	void Register(u32 pc, Handler pre, PostHandler post = nullptr);
	void Clear();
	bool IsHooked(u32 pc); // called while every block is compiled, so it has to stay cheap

	void SetReturnSentinel(u32 addr);

	// Only valid from the EE thread inside a hook handler, and only for a function that does not
	// block: the target runs to completion with EE interrupts masked, so one waiting on an interrupt
	// or DMA hangs. Requires SetCallMarker.
	u32 CallEE(u32 pc, std::initializer_list<u32> gpr = {}, std::initializer_list<float> fpr = {});

	void SetCallMarker(u32 addr);

	using Observer = void (*)(Context& ctx);
	void SetObserver(Observer observer);

	int Dispatch();

	using DmaKickSink = void (*)(u32 chan, u32 eepc, u32 madr, u32 qwc);
	void SetDmaKickSink(DmaKickSink sink);
	void OnDmaKick(u32 chan, u32 eepc, u32 madr, u32 qwc);

	struct GsDraw
	{
		u64 prim, tex0, tex1, clamp, test, alpha, frame, scissor, zbuf;
		u32 rgbaq, nverts, fog, zMin, zMax;
		// Nothing else in the register set says a batch blends per pixel.
		u32 pabe, colclamp, fba, dthe;
		// The game draws into the buffer the read circuits are not showing, so dumping the frame the
		// batches built needs both.
		u32 dispW, dispH, dispFbp0, dispFbp1;
		float q;
		float bbox[4];
		// The software rasterizer runs batches on worker threads, so an unsynced read lands at no
		// batch boundary at all. syncPixels waits for them: call it once, not per pixel.
		void (*syncPixels)(const void* ctx);
		u32 (*readPixel)(const void* ctx, int x, int y);
		const void* readCtx;
	};
	// Nothing else the game does reveals which microprogram is running.
	using Vu1UploadSink = void (*)(u32 addr, const u32* words, u32 count);
	void SetVu1UploadSink(Vu1UploadSink sink);
	void OnVu1Upload(u32 addr, const u32* words, u32 count);
	// Several programs are resident at once, so the MSCAL entry point is what says which one runs.
	// vuMem is live VU state rather than a copy, valid only for the duration of the call.
	using Vu1ExecSink = void (*)(u32 pc, const u8* vuMem, u32 vuMemSize);
	void SetVu1ExecSink(Vu1ExecSink sink);
	void OnVu1Exec(u32 pc, const u8* vuMem, u32 vuMemSize);
	// Interpreter only: the recompiler resolves a computed jump in generated code and never calls back.
	using Vu1JrSink = void (*)(u32 pc, u32 reg, u32 target);
	void SetVu1JrSink(Vu1JrSink sink);
	void OnVu1Jr(u32 pc, u32 reg, u32 target);

	// The whole register file, so a sink recovers what one instruction wrote by diffing against its
	// last call rather than modelling VU arithmetic. Interpreter only.
	struct Vu1Step
	{
		u32 addr;
		u32 vf[32][4];
		u32 vi[32];
		u32 acc[4];
		u32 branchTarget;
		bool branchTaken;
	};
	using Vu1StepSink = void (*)(const Vu1Step& step);
	void SetVu1StepSink(Vu1StepSink sink);
	bool HasVu1StepSink();
	void OnVu1Step(const Vu1Step& step);

	using GsDrawSink = void (*)(const GsDraw& draw);
	using GsVSyncSink = void (*)();
	void SetGsVSyncSink(GsVSyncSink sink);
	void OnGsVSync();
	void SetGsDrawSink(GsDrawSink sink);
	void OnGsDraw(const GsDraw& draw);

	using VifTagSink = void (*)(u32 tadr, u32 id, u32 madr, u32 qwc);
	void SetVifTagSink(VifTagSink sink);
	void OnVifTag(u32 tadr, u32 id, u32 madr, u32 qwc);

	using VifCodeSink = void (*)(u32 idx, u32 codeWord);
	void SetVifCodeSink(VifCodeSink sink);
	void OnVifCode(u32 idx, u32 codeWord);
	struct ExecBlockSlots
	{
		u64* count;
		u32* threads;
	};
	using ExecBlockRegister = ExecBlockSlots (*)(u32 startpc, u32 endpc);
	void SetExecBlockRegister(ExecBlockRegister fn);
	ExecBlockSlots ExecBlockCounter(u32 startpc, u32 endpc);

	u32* ExecThreadBit();
	void SetExecThreadBit(u32* addr);

	using InsnSink = void (*)(u32 pc, u32 code);
	void SetInsnSink(InsnSink before, InsnSink after);
	bool HasInsnSink();
	void OnInsnBefore(u32 pc, u32 code);
	void OnInsnAfter(u32 pc, u32 code);

	using SifKickSink = void (*)(u32 channel);
	void SetSifKickSink(SifKickSink sink);
	void OnSifKick(u32 channel);

	using SifTransferSink = void (*)(u32 channel, bool toEE, u32 madr, u32 qwc, const u32* words, u32 count);
	void SetSifTransferSink(SifTransferSink sink);
	bool HasSifTransferSink();
	void OnSifTransfer(u32 channel, bool toEE, u32 madr, u32 qwc, const u32* words, u32 count);

	using GuestMemSink = void (*)(u32 addr, u64 value, u32 size, bool isRead);
	void AddGuestMemSink(GuestMemSink sink);
	void SetGuestMemSink(GuestMemSink sink);
	bool HasGuestMemSink();
	void OnGuestMem(u32 addr, u64 value, u32 size, bool isRead);

	void SetMemTraceSuppressed(bool on);
	bool MemTraceSuppressed();

	using HwAccessSink = void (*)(bool iop, u32 addr, u64 value, u32 size, bool isRead);
	void SetHwAccessSink(HwAccessSink sink);
	bool HasHwAccessSink();
	void OnHwAccess(bool iop, u32 addr, u64 value, u32 size, bool isRead);

	using IopBlockRegister = ExecBlockSlots (*)(u32 startpc, u32 endpc);
	void SetIopBlockRegister(IopBlockRegister fn);
	ExecBlockSlots IopBlockCounter(u32 startpc, u32 endpc);

	using IrxImportSink = void (*)(const char* libname, u32 index, const char* funcname);
	void SetIrxImportSink(IrxImportSink sink);
	void OnIrxImport(const char* libname, u32 index, const char* funcname);

	using IopInsnSink = void (*)(u32 pc, u32 code);
	void SetIopInsnSink(IopInsnSink before, IopInsnSink after);
	bool HasIopInsnSink();
	void OnIopInsnBefore(u32 pc, u32 code);
	void OnIopInsnAfter(u32 pc, u32 code);

	using SyscallSink = void (*)(u32 num, Context& ctx);
	void SetSyscallSink(SyscallSink sink);
	void OnSyscall(u32 num);
} // namespace Hooks

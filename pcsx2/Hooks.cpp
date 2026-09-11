// SPDX-FileCopyrightText: 2002-2026 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#include "Hooks.h"

#include "Memory.h"
#include "R5900.h"

#include <iterator>
#include <unordered_map>
#include <vector>

namespace
{
	struct HookPair
	{
		Hooks::Handler pre = nullptr;
		Hooks::PostHandler post = nullptr;
	};
	std::unordered_map<u32, HookPair> s_hooks;
	Hooks::Observer s_observer = nullptr;
	Hooks::DmaKickSink s_dmaSinks[2] = {};
	u32 s_dmaSinkCount = 0;
	Hooks::GsDrawSink s_gsDrawSink = nullptr;
	Hooks::Vu1UploadSink s_vu1UploadSink = nullptr;
	Hooks::Vu1ExecSink s_vu1ExecSink = nullptr;
	Hooks::Vu1JrSink s_vu1JrSink = nullptr;
	Hooks::Vu1StepSink s_vu1StepSink = nullptr;
	Hooks::VifTagSink s_vifTagSink = nullptr;
	Hooks::VifCodeSink s_vifCodeSink = nullptr;
	Hooks::GsVSyncSink s_gsVSyncSink = nullptr;

	u32 s_returnSentinel = 0;
	u32 s_callMarker = 0;

	struct PendingReturn
	{
		u32 callee;
		Hooks::PostHandler post;
		u32 realRa;
		u32 sp;
	};
	std::vector<PendingReturn> s_returnStack;

	Hooks::Context liveContext(u32 pc)
	{
		return Hooks::Context{reinterpret_cast<u32*>(cpuRegs.GPR.r), reinterpret_cast<float*>(fpuRegs.fpr), pc};
	}
} // namespace

void Hooks::Register(u32 pc, Handler pre, PostHandler post)
{
	s_hooks[pc] = {pre, post};
}

bool Hooks::IsHooked(u32 pc)
{
	return !s_hooks.empty() && s_hooks.find(pc) != s_hooks.end();
}

void Hooks::SetReturnSentinel(u32 addr)
{
	s_returnSentinel = addr;
	*reinterpret_cast<u32*>(&eeMem->Main[addr & (Ps2MemSize::MainRam - 1)]) = 0x03E00008;
	*reinterpret_cast<u32*>(&eeMem->Main[(addr + 4) & (Ps2MemSize::MainRam - 1)]) = 0x00000000;
	s_hooks[addr];
}

void Hooks::SetCallMarker(u32 addr)
{
	s_callMarker = addr;
	*reinterpret_cast<u32*>(&eeMem->Main[addr & (Ps2MemSize::MainRam - 1)]) = 0x03E00008;
	*reinterpret_cast<u32*>(&eeMem->Main[(addr + 4) & (Ps2MemSize::MainRam - 1)]) = 0x00000000;
	s_hooks[addr];
}

u32 Hooks::CallEE(u32 pc, std::initializer_list<u32> gpr, std::initializer_list<float> fpr)
{
	if (s_callMarker == 0)
		return 0;
	u32 g[8] = {};
	int ng = 0;
	for (u32 v : gpr)
		if (ng < 8)
			g[ng++] = v;
	float f[8] = {};
	int nf = 0;
	for (float v : fpr)
		if (nf < 8)
			f[nf++] = v;
	return eeRunFunctionSync(pc, g, ng, f, nf, s_callMarker);
}

void Hooks::SetObserver(Observer observer)
{
	s_observer = observer;
}

int Hooks::Dispatch()
{
	const u32 pc = cpuRegs.pc;

	if (s_callMarker != 0 && pc == s_callMarker)
		eeSyncCallReturn();

	if (eeInSyncCall())
		return 0;

	if (s_returnSentinel != 0 && pc == s_returnSentinel)
	{
		const u32 sp = cpuRegs.GPR.n.sp.UL[0];
		for (size_t i = s_returnStack.size(); i-- > 0;)
		{
			if (s_returnStack[i].sp != sp)
				continue;
			const PendingReturn pr = s_returnStack[i];
			s_returnStack.erase(s_returnStack.begin() + i);
			cpuRegs.GPR.n.ra.UL[0] = pr.realRa;
			if (pr.post)
			{
				Context ctx = liveContext(pr.callee);
				pr.post(ctx);
			}
			cpuRegs.pc = pr.realRa;
			return 1;
		}
		cpuRegs.pc = cpuRegs.GPR.n.ra.UL[0];
		return 1;
	}

	const auto it = s_hooks.find(pc);
	if (it == s_hooks.end())
		return 0;
	const HookPair& h = it->second;
	Context ctx = liveContext(pc);
	if (s_observer)
		s_observer(ctx);
	if (h.pre && h.pre(ctx) == Result::Exit)
	{
		cpuRegs.pc = cpuRegs.GPR.n.ra.UL[0];
		return 1;
	}
	if (h.post && s_returnSentinel != 0)
	{
		s_returnStack.push_back({pc, h.post, cpuRegs.GPR.n.ra.UL[0], cpuRegs.GPR.n.sp.UL[0]});
		cpuRegs.GPR.n.ra.UL[0] = s_returnSentinel;
	}
	return 0;
}

void Hooks::AddDmaKickSink(DmaKickSink sink)
{
	if (sink && s_dmaSinkCount < std::size(s_dmaSinks))
		s_dmaSinks[s_dmaSinkCount++] = sink;
}

void Hooks::OnDmaKick(u32 chan, u32 eepc, u32 madr, u32 qwc)
{
	for (u32 i = 0; i < s_dmaSinkCount; i++)
		s_dmaSinks[i](chan, eepc, madr, qwc);
}

void Hooks::SetGsVSyncSink(GsVSyncSink sink)
{
	s_gsVSyncSink = sink;
}

void Hooks::OnGsVSync()
{
	if (s_gsVSyncSink)
		s_gsVSyncSink();
}

void Hooks::SetVu1UploadSink(Vu1UploadSink sink)
{
	s_vu1UploadSink = sink;
}

void Hooks::OnVu1Upload(u32 addr, const u32* words, u32 count)
{
	if (s_vu1UploadSink)
		s_vu1UploadSink(addr, words, count);
}

void Hooks::SetVu1ExecSink(Vu1ExecSink sink)
{
	s_vu1ExecSink = sink;
}

void Hooks::OnVu1Exec(u32 pc, const u8* vuMem, u32 vuMemSize)
{
	if (s_vu1ExecSink)
		s_vu1ExecSink(pc, vuMem, vuMemSize);
}

void Hooks::SetVu1JrSink(Vu1JrSink sink)
{
	s_vu1JrSink = sink;
}

void Hooks::OnVu1Jr(u32 pc, u32 reg, u32 target)
{
	if (s_vu1JrSink)
		s_vu1JrSink(pc, reg, target);
}

void Hooks::SetVu1StepSink(Vu1StepSink sink)
{
	s_vu1StepSink = sink;
}

bool Hooks::HasVu1StepSink()
{
	return s_vu1StepSink != nullptr;
}

void Hooks::OnVu1Step(const Vu1Step& step)
{
	if (s_vu1StepSink)
		s_vu1StepSink(step);
}

void Hooks::SetVifTagSink(VifTagSink sink)
{
	s_vifTagSink = sink;
}

void Hooks::OnVifTag(u32 tadr, u32 id, u32 madr, u32 qwc)
{
	if (s_vifTagSink)
		s_vifTagSink(tadr, id, madr, qwc);
}

void Hooks::SetVifCodeSink(VifCodeSink sink)
{
	s_vifCodeSink = sink;
}

void Hooks::OnVifCode(u32 idx, u32 codeWord)
{
	if (s_vifCodeSink)
		s_vifCodeSink(idx, codeWord);
}

void Hooks::SetGsDrawSink(GsDrawSink sink)
{
	s_gsDrawSink = sink;
}

void Hooks::OnGsDraw(const GsDraw& draw)
{
	if (s_gsDrawSink)
		s_gsDrawSink(draw);
}
namespace
{
	Hooks::ExecBlockRegister s_execBlockRegister = nullptr;
	u32* s_execThreadBit = nullptr;
	Hooks::InsnSink s_insnBefore = nullptr;
	Hooks::IopBlockRegister s_iopBlockRegister = nullptr;
	Hooks::HwAccessSink s_hwAccessSink = nullptr;
	Hooks::GuestMemSink s_guestMemSinks[4] = {};
	u32 s_guestMemSinkCount = 0;
	Hooks::SifTransferSink s_sifTransferSink = nullptr;
	Hooks::SifKickSink s_sifKickSink = nullptr;
	bool s_memTraceSuppressed = false;
	Hooks::IrxImportSink s_irxImportSink = nullptr;
	Hooks::IopInsnSink s_iopInsnBefore = nullptr;
	Hooks::IopInsnSink s_iopInsnAfter = nullptr;
	Hooks::InsnSink s_insnAfter = nullptr;
	Hooks::SyscallSink s_syscallSink = nullptr;
	Hooks::VuInsnSink s_vuInsnBefore[2] = {};
	Hooks::VuInsnSink s_vuInsnAfter[2] = {};
	u32 s_vuInsnSinkCount = 0;
	Hooks::VuMemSink s_vuMemSinks[2] = {};
	u32 s_vuMemSinkCount = 0;
	Hooks::VifCmdBeforeSink s_vifCmdBefore[2] = {};
	Hooks::VifCmdAfterSink s_vifCmdAfter[2] = {};
	u32 s_vifCmdSinkCount = 0;
	Hooks::TimingSink s_timingSink = nullptr;
	Hooks::SpuAdpcmSink s_spuAdpcmSink = nullptr;
	Hooks::SpuVoiceSink s_spuVoiceSink = nullptr;
	Hooks::SpuRegWriteSink s_spuRegWrite = nullptr;
	Hooks::SpuRegReadSink s_spuRegRead = nullptr;
} // namespace

void Hooks::SetSpuAdpcmSink(SpuAdpcmSink sink)
{
	s_spuAdpcmSink = sink;
}

bool Hooks::HasSpuAdpcmSink()
{
	return s_spuAdpcmSink != nullptr;
}

void Hooks::OnSpuAdpcm(const u8* block, s32 prev1In, s32 prev2In, const s16* samples, s32 prev1Out,
	s32 prev2Out)
{
	if (s_spuAdpcmSink)
		s_spuAdpcmSink(block, prev1In, prev2In, samples, prev1Out, prev2Out);
}

void Hooks::SetSpuVoiceSink(SpuVoiceSink sink)
{
	s_spuVoiceSink = sink;
}

bool Hooks::HasSpuVoiceSink()
{
	return s_spuVoiceSink != nullptr;
}

void Hooks::OnSpuVoice(u32 core, u32 voice, u32 stage, s32 outL, s32 outR)
{
	if (s_spuVoiceSink)
		s_spuVoiceSink(core, voice, stage, outL, outR);
}

void Hooks::SetSpuRegSink(SpuRegWriteSink write, SpuRegReadSink read)
{
	s_spuRegWrite = write;
	s_spuRegRead = read;
}

bool Hooks::HasSpuRegSink()
{
	return s_spuRegWrite != nullptr;
}

void Hooks::OnSpuRegWrite(u32 addr, u16 value, bool after)
{
	if (s_spuRegWrite)
		s_spuRegWrite(addr, value, after);
}

void Hooks::OnSpuRegRead(u32 addr, u16 value)
{
	if (s_spuRegRead)
		s_spuRegRead(addr, value);
}

void Hooks::AddVifCmdSink(VifCmdBeforeSink before, VifCmdAfterSink after)
{
	if (before && after && s_vifCmdSinkCount < std::size(s_vifCmdBefore))
	{
		s_vifCmdBefore[s_vifCmdSinkCount] = before;
		s_vifCmdAfter[s_vifCmdSinkCount++] = after;
	}
}

bool Hooks::HasVifCmdSink()
{
	return s_vifCmdSinkCount != 0;
}

void Hooks::OnVifCmdBefore(u32 idx, const u32* data, u32 pass)
{
	for (u32 i = 0; i < s_vifCmdSinkCount; i++)
		s_vifCmdBefore[i](idx, data, pass);
}

void Hooks::OnVifCmdAfter(u32 idx, const u32* data, u32 consumed, bool done)
{
	for (u32 i = 0; i < s_vifCmdSinkCount; i++)
		s_vifCmdAfter[i](idx, data, consumed, done);
}

void Hooks::SetTimingSink(TimingSink sink)
{
	s_timingSink = sink;
}

bool Hooks::HasTimingSink()
{
	return s_timingSink != nullptr;
}

void Hooks::OnTimingEvent(TimingEvent kind, u32 a, u32 b, u32 c)
{
	if (s_timingSink)
		s_timingSink(kind, a, b, c);
}

void Hooks::AddVuInsnSink(VuInsnSink before, VuInsnSink after)
{
	if (before && after && s_vuInsnSinkCount < std::size(s_vuInsnBefore))
	{
		s_vuInsnBefore[s_vuInsnSinkCount] = before;
		s_vuInsnAfter[s_vuInsnSinkCount++] = after;
	}
}

bool Hooks::HasVuInsnSink()
{
	return s_vuInsnSinkCount != 0;
}

void Hooks::OnVuInsnBefore(u32 unit, u32 pc)
{
	for (u32 i = 0; i < s_vuInsnSinkCount; i++)
		s_vuInsnBefore[i](unit, pc);
}

void Hooks::OnVuInsnAfter(u32 unit, u32 pc)
{
	for (u32 i = 0; i < s_vuInsnSinkCount; i++)
		s_vuInsnAfter[i](unit, pc);
}

void Hooks::AddVuMemSink(VuMemSink sink)
{
	if (sink && s_vuMemSinkCount < std::size(s_vuMemSinks))
		s_vuMemSinks[s_vuMemSinkCount++] = sink;
}

bool Hooks::HasVuMemSink()
{
	return s_vuMemSinkCount != 0;
}

void Hooks::OnVuMem(u32 unit, u32 addr)
{
	for (u32 i = 0; i < s_vuMemSinkCount; i++)
		s_vuMemSinks[i](unit, addr);
}

void Hooks::SetExecBlockRegister(ExecBlockRegister fn)
{
	s_execBlockRegister = fn;
}

Hooks::ExecBlockSlots Hooks::ExecBlockCounter(u32 startpc, u32 endpc)
{
	return s_execBlockRegister ? s_execBlockRegister(startpc, endpc) : ExecBlockSlots{nullptr, nullptr};
}

u32* Hooks::ExecThreadBit()
{
	return s_execThreadBit;
}

void Hooks::SetExecThreadBit(u32* addr)
{
	s_execThreadBit = addr;
}

void Hooks::SetSifKickSink(SifKickSink sink)
{
	s_sifKickSink = sink;
}

void Hooks::OnSifKick(u32 channel)
{
	if (s_sifKickSink)
		s_sifKickSink(channel);
}

void Hooks::SetSifTransferSink(SifTransferSink sink)
{
	s_sifTransferSink = sink;
}

void Hooks::OnSifTransfer(u32 channel, bool toEE, u32 madr, u32 qwc, const u32* words, u32 count)
{
	if (s_sifTransferSink)
		s_sifTransferSink(channel, toEE, madr, qwc, words, count);
}

void Hooks::AddGuestMemSink(GuestMemSink sink)
{
	if (sink && s_guestMemSinkCount < std::size(s_guestMemSinks))
		s_guestMemSinks[s_guestMemSinkCount++] = sink;
}

bool Hooks::HasGuestMemSink()
{
	return s_guestMemSinkCount != 0;
}

void Hooks::OnGuestMem(u32 addr, u64 value, u32 size, bool isRead)
{
	if (s_memTraceSuppressed)
		return;
	for (u32 i = 0; i < s_guestMemSinkCount; i++)
		s_guestMemSinks[i](addr, value, size, isRead);
}

void Hooks::SetMemTraceSuppressed(bool on)
{
	s_memTraceSuppressed = on;
}

void Hooks::SetHwAccessSink(HwAccessSink sink)
{
	s_hwAccessSink = sink;
}

bool Hooks::HasHwAccessSink()
{
	return s_hwAccessSink != nullptr;
}

void Hooks::OnHwAccess(bool iop, u32 addr, u64 value, u32 size, bool isRead)
{
	if (s_hwAccessSink)
		s_hwAccessSink(iop, addr, value, size, isRead);
}

void Hooks::SetIopBlockRegister(IopBlockRegister fn)
{
	s_iopBlockRegister = fn;
}

Hooks::ExecBlockSlots Hooks::IopBlockCounter(u32 startpc, u32 endpc)
{
	return s_iopBlockRegister ? s_iopBlockRegister(startpc, endpc) : ExecBlockSlots{nullptr, nullptr};
}

void Hooks::SetIrxImportSink(IrxImportSink sink)
{
	s_irxImportSink = sink;
}

void Hooks::OnIrxImport(const char* libname, u32 index, const char* funcname)
{
	if (s_irxImportSink)
		s_irxImportSink(libname, index, funcname);
}

void Hooks::SetIopInsnSink(IopInsnSink before, IopInsnSink after)
{
	s_iopInsnBefore = before;
	s_iopInsnAfter = after;
}

bool Hooks::HasIopInsnSink()
{
	return s_iopInsnBefore != nullptr;
}

void Hooks::OnIopInsnBefore(u32 pc, u32 code)
{
	if (s_iopInsnBefore)
		s_iopInsnBefore(pc, code);
}

void Hooks::OnIopInsnAfter(u32 pc, u32 code)
{
	if (s_iopInsnAfter)
		s_iopInsnAfter(pc, code);
}

void Hooks::SetInsnSink(InsnSink before, InsnSink after)
{
	s_insnBefore = before;
	s_insnAfter = after;
}

bool Hooks::HasInsnSink()
{
	return s_insnBefore != nullptr;
}

void Hooks::OnInsnBefore(u32 pc, u32 code)
{
	if (s_insnBefore)
		s_insnBefore(pc, code);
}

void Hooks::OnInsnAfter(u32 pc, u32 code)
{
	if (s_insnAfter)
		s_insnAfter(pc, code);
}

void Hooks::SetSyscallSink(SyscallSink sink)
{
	s_syscallSink = sink;
}

void Hooks::OnSyscall(u32 num)
{
	if (!s_syscallSink)
		return;
	Context ctx = liveContext(cpuRegs.pc - 4);
	s_syscallSink(num, ctx);
}

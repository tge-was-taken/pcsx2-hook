// SPDX-FileCopyrightText: 2002-2026 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#pragma once

#include "trace/api_trace.h"
#include "trace/draw_context.h"
#include "trace/dump_dir.h"
#include "trace/exec_trace.h"
#include "trace/gs_draws.h"
#include "trace/gs_tracker.h"
#include "trace/hw_trace.h"
#include "trace/insn_trace.h"
#include "trace/iop_trace.h"
#include "trace/sif_trace.h"
#include "trace/vif_trace.h"

namespace pcsx2hook {

// The emulator's sinks are plain function pointers, so the tracers need one reachable owner rather
// than an instance threaded through a C boundary.
class Diagnostics {
public:
    static Diagnostics& get();

    DumpDir& getDumps() { return mDumps; }
    GsTracker& getGsTracker() { return mGsTracker; }
    SifTrace& getSif() { return mSif; }
    HwTrace& getHw() { return mHw; }
    ApiTrace& getApi() { return mApi; }
    IopTrace& getIop() { return mIop; }
    ExecTrace& getExec() { return mExec; }
    InsnTrace& getInsn() { return mInsn; }
    GsDraws& getGsDraws() { return mGsDraws; }
    DrawTrace& getDraws() { return mDraws; }
    VifTrace& getVif() { return mVif; }

private:
    DumpDir mDumps;
    GsTracker mGsTracker;
    SifTrace mSif;
    HwTrace mHw;
    ApiTrace mApi;
    IopTrace mIop;
    ExecTrace mExec;
    InsnTrace mInsn;
    GsDraws mGsDraws;
    DrawTrace mDraws;
    VifTrace mVif;
};

}  // namespace pcsx2hook

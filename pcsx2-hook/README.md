# pcsx2hook

A PCSX2 fork you can drive as a diagnostic tool: hook guest functions, trace what a PS2 program
executes, and read the emulated hardware, from a host process that links one shared library.

Base: PCSX2 master `773f96a312ad69ac6b388b498ea163759ea153be`. `upstream` points at the PCSX2 repo,
so this rebases onto a newer master rather than diverging.

## Build

```sh
cmake -B build -DPCSX2HOOK=ON -DPCSX2HOOK_LIBRARY=ON
cmake --build build
ctest --test-dir build
```

Both options are needed: `PCSX2HOOK` compiles the emulator changes, `PCSX2HOOK_LIBRARY` builds
`libpcsx2hook.so` on top of them.

## Use

The API is `pcsx2-hook/include/pcsx2hook/pcsx2hook.h`, which is documented. The shape is:

```c
pcsx2hook_ctx* ctx = pcsx2hook_create(&config);
pcsx2hook_early_init(ctx);
pcsx2hook_init(ctx, argc, argv);
pcsx2hook_apply_settings(ctx);
pcsx2hook_enable_trace(ctx, PCSX2HOOK_TRACE_GS);
pcsx2hook_start(ctx);
while (!pcsx2hook_is_finished(ctx)) { /* your event pump */ }
pcsx2hook_join(ctx);
pcsx2hook_shutdown(ctx);
pcsx2hook_destroy(ctx);
```

The run loop is split rather than blocking so your thread stays free. Register hooks from the
`on_vm_ready` callback, and do per-frame work in `on_frame`.

## What the fork adds

- **An EE hook registry.** A handler runs at a guest function's entry with the live register file,
  and can run the original body or skip it. A post-handler runs after it returns. Same behaviour
  under the recompiler and the interpreter.
- **Synchronous guest calls** from inside a handler.
- **Traces**: EE coverage and syscalls, per-instruction reference vectors, the IOP equivalents
  plus the IRX import surface, hardware register access on both CPUs, SIF, VIF1, VU1, GS batches,
  EE memory access, VU/VIF/SPU2 reference vectors, and timing.
- **Headless software and null rendering.** Upstream needs a window for those; presenting through
  Vulkan is what makes a surfaceless run work.

Coverage costs one increment per basic block, so leave it enabled for a whole boot. The
per-instruction traces need the interpreter and are meant to run from a savestate.

Reference vectors for three more units, each a `pcsx2hook_trace` value or the variable in
the first column:

| variable | writes | one case is |
|---|---|---|
| `PCSX2HOOK_VU_INSN_TRACE` | `vu0_vectors.jsonl`, `vu1_vectors.jsonl` | one micro-mode instruction pair, with the delay pipelines either side (needs `PCSX2HOOK_VU0_INTERP=1` or `PCSX2HOOK_VU1_INTERP=1` for that unit) |
| `PCSX2HOOK_VIF_CMD_TRACE` | `vif_vectors.jsonl` | one VIFcode on VIF0 or VIF1, with its payload and the VU memory it wrote |
| `PCSX2HOOK_SPU_TRACE` | `spu_*_vectors.jsonl` | an ADPCM block, an envelope step, a volume slide step, one voice sample, or a register access |

`scripts/hw_vectors_merge.py` unions them across runs, and `scripts/hw_vectors_check.py` checks
them against models that do not come from the emulator's code.

`PCSX2HOOK_TIMING_TRACE` records what those isolated cases cannot show, order and
cycle, and wants accurate timing (Instant VU1, WaitLoop and IntcStat off) plus both VU interpreters.
`PCSX2HOOK_TIMING_TRACE_FRAMES` bounds the timeline, 10 frames by default:

| file | one row is |
|---|---|
| `vu_runs.jsonl` | a whole VU program from its initial state: per step the stall cycles, register and memory writes and pipeline occupancy, and any change the VIF or EE made between slices. `scripts/vu_runs_check.py` replays each to its recorded end state |
| `vu_run_images.jsonl` | the micro-memory image a run executed, by hash |
| `timing_timeline.jsonl` | one event, EE-cycle stamped: VIF commands, VU start/slice/end, XGKICK and its send, GIF path offers and finished packets, PATH3 mask writes, GIF DMA service, DMA kicks and interrupts, vsync |
| `xgkick_hazards.jsonl` | a kicked quadword that changed before the GIF took it |

`scripts/timing_summary.py` puts one row per scene directory.

## Layout

| path | what |
|---|---|
| `pcsx2-hook/include/` | the public C API |
| `pcsx2-hook/src/` | the library: host, traces, symbols |
| `pcsx2-hook/tests/` | API tests, run by ctest |
| `pcsx2-hook/scripts/` | analysis tools for what the traces write (take paths, not a game) |
| `pcsx2/Hooks.{h,cpp}` | the registry inside the emulator |

## Working on it

Every emulator change is behind `#ifdef PCSX2HOOK`, so `unifdef -UPCSX2HOOK <file>` should give back
the upstream file. That is what keeps a rebase cheap; check it when you touch one.

`pcsx2-hook/check.sh` syntax-checks every source in a couple of seconds with no configure step. It
does not link, so it narrows what the real build has to catch rather than replacing it.

`-Wl,--no-undefined` is on the library on purpose: a shared library links with unresolved symbols by
default, so without it a successful link tells you nothing.

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

Without a BIOS the tests cover only what answers without booting. `PCSX2HOOK_TEST_BIOS` and
`PCSX2HOOK_TEST_IMAGE` add a real boot and the run-control calls; `PCSX2HOOK_TEST_STATE`, a
savestate for that image, adds the checks that need VU1 running.

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
`on_vm_ready` callback, and do per-frame work in `on_frame`. Before `pcsx2hook_apply_settings`,
`pcsx2hook_set_interpreter`, `_set_accurate_timing`, `_set_boot_state` and `_set_frame_limit`
choose which processors are interpreted, whether the timing speed hacks stay on, a savestate to
boot into, and when the run stops and writes its traces.

## Run from the command line

`pcsx2hook_cli`, built beside the library, is a host made of nothing but those calls, so running a
trace needs no program of your own:

```sh
pcsx2hook_cli --bios bios.bin --state scene.p2s --frames 30 --out traces \
    --trace timing --accurate-timing --interp vu0,vu1 disc.iso
```

`--help` lists every trace. `--set NAME=VALUE` reaches any other setting by the variable name the
tables below use. Traces are written when the run stops, so let `--frames` end it.

A trace about anything past a title screen needs the program driven there, which `--press
FRAME:BUTTON[:HOLD]` and `--script FILE` do on a schedule rather than by hand, so the run repeats:

```sh
pcsx2hook_cli --bios bios.bin --frames 40000 --out traces --trace spu \
    --script skip-to-gameplay.txt disc.iso
```

A script line is `FRAME BUTTON [HOLD]`, `#` starts a comment, and `--help` lists the button
names. Nothing reads the schedule but the pad, so getting somewhere is a matter of what the
program does with the input, not of the host knowing anything about it.

Input only reaches what the program chooses to do. `--arg ADDR:REG:V1,V2,...` and `--arg-file
ADDR:REG:FILE` cover the rest, feeding a register a different value at each call of one
function, so whatever call the program makes on its own becomes the next case:

```sh
pcsx2hook_cli --bios bios.bin --frames 40000 --trace spu \
    --arg-file 0x002C1670:4:every-track.txt disc.iso
```

The register is a number, 4 for `$a0`, and the substitution happens at entry, so the function
still runs on the program's own thread. That matters for a target that blocks or waits on
hardware, which `pcsx2hook_call_ee` cannot drive because it masks EE interrupts.

Both report how many times each hook fired when the run ends, because a substitution that never
fires looks exactly like one that worked. `--watch ADDR` counts without substituting, which is
how to find out whether a function is called at all before deciding to feed it.

`--watch-writes LO:HI` lists each pc that stores into the range, with its function, the frame and
a count at the end, and `pcsx2hook_set_write_sink` does the same for a library caller.
Arming it runs the EE in the interpreter, so the pc is exact and every store is seen, which makes
the run slower; a run that does not arm it pays nothing. It sees stores the EE issues, not DMA, VIF or IOP writes.
`pcsx2hook_read_scratchpad`, `pcsx2hook_read_vu_memory` and `pcsx2hook_read_vu_regs` copy the
memories outside main RAM, and `pcsx2hook_call_ee_ex` passes up to eight integer and eight float
arguments and returns `$v0` and `$f0`.

`--elf FILE` boots an executable of your own with the disc still mounted, which is how a build of
a program runs against the data it shipped with. Note that a decompilation's link product is not
usually the bootable file: the one to pass is whatever reproduces the original executable, headers
and entry point included.

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

Reference vectors for three more units, each a `pcsx2hook_trace` value (`--trace vu-insn`,
`vif-cmd`, `spu`) or the variable in the first column:

| variable | writes | one case is |
|---|---|---|
| `PCSX2HOOK_VU_INSN_TRACE` | `vu0_vectors.jsonl`, `vu1_vectors.jsonl` | one micro-mode instruction pair, with the delay pipelines either side (needs `PCSX2HOOK_VU0_INTERP=1` or `PCSX2HOOK_VU1_INTERP=1` for that unit) |
| `PCSX2HOOK_VIF_CMD_TRACE` | `vif_vectors.jsonl` | one VIFcode on VIF0 or VIF1, with its payload and the VU memory it wrote |
| `PCSX2HOOK_SPU_TRACE` | `spu_*_vectors.jsonl` | an ADPCM block, an envelope step, a volume slide step, one voice sample, a register access, or one reverb cycle |

`scripts/hw_vectors_merge.py` unions them across runs, and `scripts/hw_vectors_check.py` checks
them against models that do not come from the emulator's code.

`PCSX2HOOK_GS_STREAM` writes the graphics command stream instead of a trace of it: every burst the
GIF receives, as PCSX2's own GS dump packets, so a host emulating its own PS2 can replay what the
hardware was sent and compare its own stream against it, and `pcsx2hook_gs_transfer` takes the same
three arguments. `PCSX2HOOK_GS_STREAM_FRAMES` bounds it. The frame boundary is the EE thread's, so
one thread writes the file in order, and `pcsx2hook_get_gs_stream_transfers` reads the transfer
count from a hook handler for a host cutting the file where the guest kicked something.

`PCSX2HOOK_SPU_FORCE` holds voices 20 to 23 of both cores in states the running program may never
ask for, so a trace can cover them anyway: bit 0 noise, bit 1 pitch modulation, bit 2 a volume in
sweep mode, with the exponential and decreasing bits varied per voice. A program that sets none of
them leaves those paths unrecorded, and then there is nothing for an implementation of them to be
checked against. It changes what the program sounds like, so use it for a corpus run and not for a
comparison. Note that noise takes precedence over modulation when a case is labelled, so a voice
given both reports as noise and still takes the modulated pitch step.

`spu_reverb_vectors.jsonl` is one cycle of the reverb network per row, and it is recorded as a
closed case: the ten words it read with their addresses, the nine coefficients, the downsampled
input, and the four words it wrote plus the sample it returned. That is deliberate. The work area
is up to 64KB per core, so recording state rather than taps would make a row unusable; with just
the taps a reader can replay a cycle with no work area and no address arithmetic, which is what
makes the filter checkable at all.

`PCSX2HOOK_TIMING_TRACE` (`--trace timing`) records what those isolated cases cannot show, order and
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

Open: `check.sh` fails on `src/core.cpp`, `src/gs.cpp` and `src/host.cpp` (`host.h` uses `std::function`
without including `<functional>`); it did so before the CLI script work too, at `6eb9068db`.

`-Wl,--no-undefined` is on the library on purpose: a shared library links with unresolved symbols by
default, so without it a successful link tells you nothing.

# pcsx2hook

A PCSX2 fork that can be driven as a diagnostic tool: hook guest functions, trace what a PS2 program
executes, and read the emulated hardware, from a host process that links one shared library.

Base: PCSX2 master, `773f96a312ad69ac6b388b498ea163759ea153be`. `upstream` points at the PCSX2
repository, so the fork rebases onto a newer master rather than diverging.

## What the fork adds to the emulator

Twenty-one commits on top of that base, each one concern:

- **An EE hook registry.** `Hooks::Register(addr, pre, post)` makes the recompiler call the handler at
  a function's entry with the live register file. The pre-handler returns `Continue` to run the
  original body or `Exit` to skip it; the post-handler runs after it returns, with `$v0` in place. The
  same dispatch runs under the interpreter, so a hooked function behaves identically under either CPU.
- **Synchronous guest calls.** `Hooks::CallEE(pc, args)` runs a guest function to completion from
  inside a handler and returns `$v0`.
- **Ten independent traces**, each a hook the emulator calls and a sink that writes it out: EE block
  coverage and syscalls, per-instruction reference vectors, the IOP equivalents plus the IRX import
  surface, every hardware register access on both processors, SIF transfers with the code that kicked
  them, the VIF1 tag and code stream, VU1 uploads and per-instruction execution, every GS primitive
  batch with the register state the rasterizer resolved, and every EE guest memory access.
- **Headless software and null rendering.** Upstream falls back to OpenGL for those renderers, which
  needs a window. Presenting them through Vulkan is what makes a surfaceless run possible, and the
  software rasterizer is what makes a capture authoritative.

Coverage costs one `add qword [slot], 1` per basic block and no call, so it can stay armed for a whole
boot. The per-instruction traces need the interpreter and are meant to run from a savestate.

## Layout

Everything the fork adds to an upstream source sits behind `#ifdef PCSX2HOOK`, so what is ours is
visible without a comment claiming it, and `unifdef -UPCSX2HOOK` reduces all 27 touched files to
upstream byte for byte. Turning the `PCSX2HOOK` option off builds an unmodified emulator from the
same tree.

```
pcsx2/, common/, 3rdparty/   the emulator, upstream plus the commits above
pcsx2/Hooks.{h,cpp}          the hook registry, inside the emulator because it has to be
hook/                        this library, which upstream never touches
  include/pcsx2hook/         the C API a host links against
  src/                       the headless host, the symbol map, the tracers
  scripts/                   merging and diffing the traces
```

`hook/` is a separate top-level directory on purpose: an upstream rebase touches the emulator and
leaves it alone. It also keeps its own `.clang-format`: the emulator follows PCSX2's style because
that is where those files came from, and this library follows ps2-runtime's, which is where it is
going. One `pcsx2hook` namespace covers all of it.

## Environment

Every tracer is armed by an environment variable and writes into `PCSX2HOOK_DUMP_DIR`, which each
tracer's own path variable overrides:

```
PCSX2HOOK_EXEC_TRACE  PCSX2HOOK_INSN_TRACE  PCSX2HOOK_IOP_TRACE  PCSX2HOOK_HW_TRACE
PCSX2HOOK_SIF_TRACE   PCSX2HOOK_VIF_TRACE   PCSX2HOOK_VU_TRACE   PCSX2HOOK_GS_TRACE
PCSX2HOOK_API_TRACE   PCSX2HOOK_INTERP      PCSX2HOOK_VU1_INTERP PCSX2HOOK_SYMBOLS
```

## Building it

```
cmake -B build -S . -G Ninja -DCMAKE_BUILD_TYPE=Release -DENABLE_QT_UI=OFF -DPCSX2HOOK_LIBRARY=ON
ninja -C build pcsx2hook
```

`-Wl,--no-undefined` is on the target on purpose: a shared library links with unresolved symbols by
default, so without it the link says nothing about whether the sources are complete.

`hook/check.sh` is the fast gate. It syntax-checks every source against the vendored headers with no
configure step, and flags the one way an `#ifdef PCSX2HOOK` guard is known to go wrong: folding the
upstream line it should have preceded into a trailing comment. It never links, and `hook/stubs/`
stands in for headers the build generates, so it narrows what the build has to catch rather than
replacing it.

## Status

The emulator fork is complete and is what a working port builds against today.

The library builds and links: `libpcsx2hook.so`, exporting all thirteen `pcsx2hook_*` entry points,
with nothing unresolved at load. One `pcsx2hook` namespace, a class per module owned by
`Diagnostics`, every environment read behind `Config`, and a C API in `pcsx2hook.h`.

`Core::run` owns a blocking run loop that never yields, so there is no call that steps a fixed number
of frames: a host drives the emulator through the split lifecycle (`pcsx2hook_start`, then poll
`pcsx2hook_is_finished`) and does its per-frame work from the `on_frame` callback. Everything else on
the API works: arming traces, registering hooks, calling into the guest, reading guest memory and the
frame buffer, savestates, and flushing the traces.

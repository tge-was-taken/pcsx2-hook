#!/usr/bin/env bash
# Syntax-checks the library without configuring a full PCSX2 build, which is slow enough that it
# stops being run. Not a substitute for the build: it never links, and it compiles against the
# vendored headers rather than the generated ones.
set -u
cd "$(dirname "$0")/.."

inc=(-Ipcsx2-hook/src -Ipcsx2-hook/include -Ipcsx2-hook/stubs -I. -Ipcsx2 -Icommon
     -I3rdparty/fmt/include -I3rdparty/include -I3rdparty/imgui/include
     -I3rdparty/rapidjson/include -I3rdparty/simpleini/include -I3rdparty/fast_float/include)

# The off path was verified with unifdef, but that says nothing about the on path. A guard that
# swallowed an upstream line still reduces correctly with the macro off, so look for the fingerprint:
# an #else branch whose code was folded into a trailing comment on the line above it.
# Swallowed code, not prose: the folded line still ends in a semicolon or is a declaration.
swallowed=$(grep -rnE "Hooks::[A-Za-z]+\(.*\); // .*(;|=)" pcsx2 3rdparty 2>/dev/null || true)
if [ -n "$swallowed" ]; then
    echo "guard swallowed upstream code:"
    echo "$swallowed" | sed 's/^/     /'
fi

ok=0
fail=0
for f in $(find pcsx2-hook/src -name '*.cpp' | sort); do
    if g++ -std=c++20 -msse4.1 -mfxsr -fsyntax-only "${inc[@]}" "$f" 2>/tmp/pcsx2hook-check.err; then
        ok=$((ok + 1))
    else
        fail=$((fail + 1))
        echo "FAIL $f"
        head -5 /tmp/pcsx2hook-check.err | sed 's/^/     /'
    fi
done
echo "$ok clean, $fail failed"
[ "$fail" -eq 0 ]

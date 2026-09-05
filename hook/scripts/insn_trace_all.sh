#!/bin/bash
# Mine per-instruction reference vectors from sample savestates, one directory per scene. Needs the EE
# interpreter, which is why this runs from savestates: PCSX2HOOK_INTERP's idle-loop hang is in the BIOS
# boot and a savestate starts past it.
# Usage: [OUT=dir] [FRAMES=n] scripts/insn_trace_all.sh [slug...]
set -u

cd "$(dirname "${BASH_SOURCE[0]}")/.."
root=$PWD
out=${OUT:-$root/experiments/dumps/insn_scenes}
frames=${FRAMES:-120}
mkdir -p "$out"

mapfile -t states < <(ls "$root"/experiments/dumps/samples/*.p2s)
for state in "${states[@]}"; do
	slug=$(basename "$state" .p2s)
	slug=${slug#*_capture_f*-}
	if [ $# -gt 0 ] && ! printf '%s\n' "$@" | grep -qx "$slug"; then
		continue
	fi
	case $(basename "$state") in
	*-p4-*) disc=${P4_ISO:-$root/assets/SLUS_217.82.iso} ;;
	*-sonic-*) disc=${SONIC_ISO:-$root/assets/SLES_519.50.iso} ;;
	*-shadow-*) disc=${SHADOW_ISO:-$root/assets/SLUS_212.61.iso} ;;
	*) disc=$ISO ;;
	esac
	[ -f "$disc" ] || { echo "== $slug: skipped (no $disc)"; continue; }
	echo "== $slug"
	timeout 1800 env LD_LIBRARY_PATH=vendor/deps-prefix/lib \
		VK_DRIVER_FILES=/usr/share/vulkan/icd.d/lvp_icd.json \
		PCSX2HOOK_BIOSDIR="$root/assets" PCSX2HOOK_BIOS=bios.bin \
		PCSX2HOOK_NATIVE_RENDERER=0 PCSX2HOOK_NULLGS=1 PCSX2HOOK_INTERP=1 PCSX2HOOK_STATE="$state" \
		PCSX2HOOK_INSN_TRACE="$out/$slug" PCSX2HOOK_EXEC_TRACE="$out/$slug" \
		PCSX2HOOK_IOP_TRACE="$out/$slug" PCSX2HOOK_HW_TRACE="$out/$slug" \
		PCSX2HOOK_EXEC_TRACE_FRAMES="$frames" \
		build/bin/pcsx2hook "$disc" -surfaceless >"$out/$slug.log" 2>&1
	grep -hoE "[0-9]+ forms, .*" "$out/$slug.log" || echo "   (no vectors)"
done

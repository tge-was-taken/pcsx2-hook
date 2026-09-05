#!/bin/bash
# Capture an execution trace for every sample savestate, one directory per scene. Savestates are real
# in-game states, so this covers what a boot never reaches: field, battle, menus, effects.
# Usage: [OUT=dir] [FRAMES=n] [SITES=dir] scripts/exec_trace_all.sh [slug...]
set -u

cd "$(dirname "${BASH_SOURCE[0]}")/.."
root=$PWD
out=${OUT:-$root/experiments/dumps/exec_scenes}
frames=${FRAMES:-1800}
sites=${SITES:-$out/sites}
mkdir -p "$out"

mapfile -t states < <(ls "$root"/experiments/dumps/samples/*.p2s)
for state in "${states[@]}"; do
	slug=$(basename "$state" .p2s)
	slug=${slug#*_capture_f*-}
	if [ $# -gt 0 ] && ! printf '%s\n' "$@" | grep -qx "$slug"; then
		continue
	fi
	# A savestate only restores against its own disc, so pick the ISO from the slug.
	case $(basename "$state") in
	*-p4-*) disc=${P4_ISO:-$root/assets/SLUS_217.82.iso}; serial=SLUS-21782 ;;
	*-sonic-*) disc=${SONIC_ISO:-$root/assets/SLES_519.50.iso}; serial=SLES-51950 ;;
	*-shadow-*) disc=${SHADOW_ISO:-$root/assets/SLUS_212.61.iso}; serial=SLUS-21261 ;;
	*) disc=$ISO ;;
	esac
	if [ ! -f "$disc" ]; then
		echo "== $slug: skipped (no $disc)"
		continue
	fi
	# Syscall results need the site list a previous pass discovered; without one the args still land.
	siteArg=()
	[ -f "$sites/$serial.tsv" ] && siteArg=(PCSX2HOOK_EXEC_TRACE_SITES="$sites/$serial.tsv")
	echo "== $slug"
	timeout 900 env LD_LIBRARY_PATH=vendor/deps-prefix/lib \
		VK_DRIVER_FILES=/usr/share/vulkan/icd.d/lvp_icd.json \
		PCSX2HOOK_BIOSDIR="$root/assets" PCSX2HOOK_BIOS=bios.bin \
		PCSX2HOOK_NATIVE_RENDERER=0 PCSX2HOOK_NULLGS=1 PCSX2HOOK_STATE="$state" \
		PCSX2HOOK_EXEC_TRACE="$out/$slug" PCSX2HOOK_EXEC_TRACE_FRAMES="$frames" \
		PCSX2HOOK_EXEC_TRACE_ARGS=1 "${siteArg[@]}" \
		build/bin/pcsx2hook "$disc" -surfaceless >"$out/$slug.log" 2>&1
	grep -hoE "[0-9]+ blocks executed.*" "$out/$slug.log" || echo "   (no trace written)"
done

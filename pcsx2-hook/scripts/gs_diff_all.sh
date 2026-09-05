#!/bin/bash
# Run every sample savestate and diff its capture manifest against the GS ground truth the same
# manifest carries. Usage: [OUT_DIR=...] scripts/gs_diff_all.sh [slug...]; no args does all of them.
# Software GL and lavapipe throughout, since a comparison must not depend on the driver.
set -u

cd "$(dirname "${BASH_SOURCE[0]}")/.."
root=$PWD
out=${OUT_DIR:-/tmp/pcsx2hook-gsdiff}
iso=$ISO
frame=${PCSX2HOOK_COMPARE_FRAME:-30}
mkdir -p "$out"

mapfile -t states < <(ls "$root"/experiments/dumps/samples/*.p2s)
for state in "${states[@]}"; do
	# Keep the game prefix: both discs are in the suite and several slugs would otherwise collide.
	slug=$(basename "$state" .p2s)
	slug=${slug#*_capture_f*-}
	if [ $# -gt 0 ] && ! printf '%s\n' "$@" | grep -qx "$slug"; then
		continue
	fi
	# A savestate only restores against its own disc, so pick the ISO from the slug.
	case $(basename "$state") in
	*-p4-*) disc=${P4_ISO:-$root/assets/SLUS_217.82.iso} ;;
	*-sonic-*) disc=${SONIC_ISO:-$root/assets/SLES_519.50.iso} ;;
	*-shadow-*) disc=${SHADOW_ISO:-$root/assets/SLUS_212.61.iso} ;;
	*) disc=$iso ;;
	esac
	if [ ! -f "$disc" ]; then
		echo "== $slug: skipped (no $disc)"
		continue
	fi
	base=$out/$slug
	echo "== $slug"
	timeout 400 env LD_LIBRARY_PATH=vendor/deps-prefix/lib \
		VK_DRIVER_FILES=/usr/share/vulkan/icd.d/lvp_icd.json \
		PCSX2HOOK_BIOSDIR="$root/assets" PCSX2HOOK_BIOS=bios.bin PCSX2HOOK_NATIVE_RENDERER=1 \
		PCSX2HOOK_STATE="$state" PCSX2HOOK_COMPARE=1 PCSX2HOOK_COMPARE_FRAME="$frame" \
		PCSX2HOOK_COMPARE_OUT="$base" PCSX2HOOK_NOMEMCARD=1 \
		build/bin/pcsx2hook "$disc" -surfaceless >"$base.log" 2>&1
	if [ ! -s "$base-manifest.jsonl" ]; then
		echo "   FAILED (see $base.log)"
		continue
	fi
	python3 scripts/gs_diff.py "$base-manifest.jsonl" >"$base-diff.txt" 2>&1
	sed -n '1p' "$base-diff.txt"
done
echo "done -> $out"

// SPDX-FileCopyrightText: 2002-2026 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#pragma once

#include <cstdint>
#include <cstdio>
#include <mutex>

namespace pcsx2hook {

/* The graphics command stream, written as the GIF receives it.
 *
 * Not the GS draw trace, which records resolved register state per batch and is
 * for reading. This is the bursts themselves, so a host that emulates its own
 * PS2 can replay what the hardware was sent and compare its own stream against
 * it. pcsx2hook_gs_transfer takes the same three arguments, so one file drives
 * the software rasteriser too.
 *
 * The record shape is PCSX2's own GS dump packet stream, which is what makes a
 * dump of transfers alone a GS dump once a header is put in front of it:
 *
 *   transfer  [0][path/1][bytes/4][data/bytes]
 *   vsync     [1][field/1]
 */
class GsStream {
public:
    enum : std::uint8_t { kTransfer = 0, kVSync = 1, kRegisters = 3 };

    /* The privileged register window, which PCSX2's dump format carries whole
     * and which a rasteriser needs: DISPFB and DISPLAY never come down the
     * GIF, so without them there is nothing to present. */
    enum : std::uint32_t { kRegisterBytes = 0x2000 };

    static GsStream& get();

    bool isEnabled() const;

    /* Opens the file and registers the sink. Does nothing when not enabled. */
    void install();

    void onTransfer(std::uint32_t path, const std::uint8_t* data, std::uint32_t bytes);

    /* Which VU1 program start each path 1 burst was produced under, one JSON
     * row per burst: {"burst":n,"kick":m}, both absolute over the run. A
     * packet can hold several MSCALs and every XGKICK of each is a path 1
     * burst, so the packet alone cannot say which program drew one. Written
     * only when PCSX2HOOK_GS_KICKS names a file, and never into stream.bin,
     * whose format does not change. */
    void writeKick(std::uint64_t burst);

    /* Transfers written so far. The GIF is fed from the EE thread, so a hook
     * handler on that thread reads the ordinal of the next transfer and can
     * cut the file at a point of its own rather than at a frame boundary. */
    std::uint64_t getTransfers() const { return mTransfers; }
    void onVSync(int field);

    /* The register window as it stands, written ahead of the frame it belongs
     * to. */
    void writeRegisters(const std::uint8_t* registers);
    void close();

private:
    /* The GIF is fed from the EE thread and, with MTVU on, from the VU thread
     * too. Two writers interleaving produce a stream that parses until it does
     * not, which is a worse failure than a dropped record. */
    std::mutex mLock;
    std::FILE* mOut = nullptr;
    std::FILE* mKicks = nullptr;
    std::uint64_t mKickRows = 0;
    std::uint64_t mUnattributedKicks = 0;
    std::uint64_t mTransfers = 0;
    std::uint64_t mBytes = 0;
    std::uint32_t mFrames = 0;
    std::uint32_t mFrameLimit = 0;
};

}  // namespace pcsx2hook

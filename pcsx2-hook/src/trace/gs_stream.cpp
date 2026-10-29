// SPDX-FileCopyrightText: 2002-2026 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#include "gs_stream.h"

#include "config.h"

#include "Hooks.h"
#include "GS.h"

#include <cstdio>
#include <cstring>
#include <string>

namespace pcsx2hook {

namespace {

GsStream* s_instance = nullptr;

void gifTransferSink(u32 path, const u8* data, u32 bytes) {
    if (s_instance) {
        s_instance->onTransfer(path, data, bytes);
    }
}

}  // namespace

GsStream& GsStream::get() {
    static GsStream instance;
    return instance;
}

bool GsStream::isEnabled() const {
    return Config::get().getValue("PCSX2HOOK_GS_STREAM") != nullptr;
}

void GsStream::install() {
    if (!isEnabled()) {
        return;
    }

    const std::string path = Config::get().getValue("PCSX2HOOK_GS_STREAM");

    mOut = std::fopen(path.c_str(), "wb");
    if (!mOut) {
        std::fprintf(stderr, "[gsstream] cannot open %s\n", path.c_str());
        return;
    }
    if (const char* frames = Config::get().getValue("PCSX2HOOK_GS_STREAM_FRAMES")) {
        mFrameLimit = u32(std::atoi(frames));
    }

    s_instance = this;
    Hooks::SetGifTransferSink(&gifTransferSink);
    std::fprintf(stderr, "[gsstream] graphics command stream -> %s%s\n", path.c_str(),
                 mFrameLimit != 0 ? " (frame limited)" : "");
}

void GsStream::onTransfer(u32 path, const u8* data, u32 bytes) {
    // A burst with no data says nothing and a path outside 1..3 is not the
    // GIF's, so neither belongs in a stream a replayer trusts.
    if (!mOut || data == nullptr || bytes == 0 || path < 1 || path > 3) {
        return;
    }
    if (mFrameLimit != 0 && mFrames >= mFrameLimit) {
        return;
    }

    const std::lock_guard<std::mutex> held(mLock);
    const u8 id = kTransfer;
    const u8 pathByte = u8(path);

    if (!mOut) {
        return;
    }
    std::fwrite(&id, 1, 1, mOut);
    std::fwrite(&pathByte, 1, 1, mOut);
    std::fwrite(&bytes, 4, 1, mOut);
    std::fwrite(data, 1, bytes, mOut);

    mTransfers++;
    mBytes += bytes;
}

void GsStream::writeRegisters(const u8* registers) {
    const u8 id = kRegisters;

    /* Called with the lock already held, from onVSync. */
    if (!mOut || registers == nullptr) {
        return;
    }
    std::fwrite(&id, 1, 1, mOut);
    std::fwrite(registers, 1, kRegisterBytes, mOut);
}

void GsStream::onVSync(int field) {
    const std::lock_guard<std::mutex> held(mLock);

    if (!mOut) {
        return;
    }
    if (mFrameLimit != 0 && mFrames >= mFrameLimit) {
        return;
    }

    // Ahead of the boundary, so a replayer has the window the frame it is about
    // to finish was displayed under.
    writeRegisters(g_RealGSMem);

    const u8 id = kVSync;
    const u8 fieldByte = u8(field & 1);

    std::fwrite(&id, 1, 1, mOut);
    std::fwrite(&fieldByte, 1, 1, mOut);
    mFrames++;
    // A run without a frame limit is ended by the host rather than by this, and
    // the hook library has no shutdown of its own to close the file in, so the
    // stream has to be whole at every frame boundary.
    std::fflush(mOut);

    if (mFrameLimit != 0 && mFrames >= mFrameLimit) {
        close();
    }
}

void GsStream::close() {
    /* Called with the lock held, from onVSync at the frame limit. */
    if (!mOut) {
        return;
    }
    std::fclose(mOut);
    mOut = nullptr;
    std::fprintf(stderr, "[gsstream] %llu transfers, %llu bytes, %u frame(s)\n",
                 (unsigned long long)mTransfers, (unsigned long long)mBytes, mFrames);
}

}  // namespace pcsx2hook

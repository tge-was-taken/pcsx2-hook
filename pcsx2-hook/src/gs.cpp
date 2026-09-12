#include "pcsx2hook/pcsx2hook.h"

#include "host.h"

#include "Config.h"

#include "GS/GS.h"
#include "GS/GSLocalMemory.h"
#include "GS/GSRegs.h"
#include "GS/Renderers/Common/GSRenderer.h"

#include "common/Console.h"
#include "common/Image.h"

#include "common/WindowInfo.h"

#include <optional>
#include <vector>

namespace {

// The circuit the display registers point at, and the size it is shown at.
const GSRegDISPFB* displayedBuffer(const GSPrivRegSet& regs, int& width, int& height)
{
	for (int circuit = 1; circuit >= 0; --circuit)
	{
		const bool enabled = circuit == 0 ? regs.PMODE.EN1 != 0 : regs.PMODE.EN2 != 0;
		if (!enabled)
			continue;

		const GSRegDISPLAY& display = regs.DISP[circuit].DISPLAY;
		if (display.DW == 0 || display.DH == 0)
			continue;

		width = static_cast<int>((display.DW + 1) / (display.MAGH + 1));
		height = static_cast<int>((display.DH + 1) / (display.MAGV + 1));
		return &regs.DISP[circuit].DISPFB;
	}
	return nullptr;
}

bool readDisplay(std::vector<u32>& pixels, int& width, int& height)
{
	if (!g_gs_renderer)
		return false;

	const GSRegDISPFB* buffer = displayedBuffer(*g_gs_renderer->m_regs, width, height);
	if (buffer == nullptr)
		return false;

	pixels.resize(static_cast<size_t>(width) * height);

	const GSLocalMemory& mem = g_gs_renderer->m_mem;
	const u32 base = buffer->Block();
	const u32 stride = buffer->FBW;
	for (int y = 0; y < height; ++y)
	{
		const int line = y + static_cast<int>(buffer->DBY);
		for (int x = 0; x < width; ++x)
		{
			const int column = x + static_cast<int>(buffer->DBX);
			u32 pixel;
			switch (buffer->PSM)
			{
				case PSMCT24: pixel = mem.ReadFrame24(column, line, base, stride); break;
				case PSMCT16: pixel = mem.ReadFrame16(column, line, base, stride); break;
				case PSMCT16S: pixel = mem.ReadFrame16S(column, line, base, stride); break;
				default: pixel = mem.ReadPixel32(column, line, base, stride); break;
			}
			pixels[static_cast<size_t>(y) * width + x] = pixel | 0xFF000000u;
		}
	}
	return true;
}

GSRendererType rendererOf(int renderer)
{
	switch (renderer)
	{
		case PCSX2HOOK_GS_AUTO: return GSRendererType::Auto;
		case PCSX2HOOK_GS_OPENGL: return GSRendererType::OGL;
		case PCSX2HOOK_GS_VULKAN: return GSRendererType::VK;
		case PCSX2HOOK_GS_D3D11: return GSRendererType::DX11;
		case PCSX2HOOK_GS_D3D12: return GSRendererType::DX12;
		case PCSX2HOOK_GS_METAL: return GSRendererType::Metal;
		default: return GSRendererType::SW;
	}
}

std::optional<WindowInfo> windowOf(const pcsx2hook_window* window)
{
	if (window == nullptr || window->type == PCSX2HOOK_WINDOW_NONE)
		return std::nullopt;

	WindowInfo info;
	switch (window->type)
	{
		case PCSX2HOOK_WINDOW_WIN32: info.type = WindowInfo::Type::Win32; break;
		case PCSX2HOOK_WINDOW_X11: info.type = WindowInfo::Type::X11; break;
		case PCSX2HOOK_WINDOW_WAYLAND: info.type = WindowInfo::Type::Wayland; break;
		case PCSX2HOOK_WINDOW_MACOS: info.type = WindowInfo::Type::MacOS; break;
		default: return std::nullopt;
	}
	info.display_connection = window->display;
	info.window_handle = window->handle;
	info.surface_width = window->width;
	info.surface_height = window->height;
	info.surface_scale = window->scale;
	return info;
}

} // namespace

extern "C" {

int pcsx2hook_gs_open(uint8_t* privileged_registers, int renderer,
	const pcsx2hook_window* window, const char* resources, int threads)
{
	// A renderer that will not open says why, and nothing else here would.
	Log::SetConsoleOutputLevel(LOGLEVEL_ERROR);
	if (EmuFolders::Resources.empty())
	{
		EmuFolders::SetAppRoot();
		if (resources != nullptr && *resources != '\0')
			EmuFolders::Resources = resources;
		else
			EmuFolders::SetResourcesDirectory();
		EmuFolders::SetDataDirectory(nullptr);
	}

	const std::optional<WindowInfo> borrowed = windowOf(window);
	if (borrowed.has_value() && !pcsx2hook::setDefaultFont())
		return 0;

	pcsx2hook::setBorrowedWindow(borrowed);
	return GSopenForHost(privileged_registers, rendererOf(renderer), threads,
			   borrowed.has_value()) ?
			   1 :
			   0;
}

void pcsx2hook_gs_close()
{
	GScloseForHost();
	pcsx2hook::setBorrowedWindow(std::nullopt);
}

void pcsx2hook_gs_resize(uint32_t width, uint32_t height, float scale)
{
	if (g_gs_device)
		GSResizeDisplayWindow(static_cast<int>(width), static_cast<int>(height), scale);
}

void pcsx2hook_gs_transfer(int path, const uint8_t* data, uint32_t bytes)
{
	const u32 quadwords = bytes / 16;
	switch (path)
	{
		case 1: g_gs_renderer->Transfer<0>(data, quadwords); break;
		case 2: g_gs_renderer->Transfer<1>(data, quadwords); break;
		case 3: g_gs_renderer->Transfer<2>(data, quadwords); break;
		default: break;
	}
}

void pcsx2hook_gs_end_field(int field)
{
	GSvsync(static_cast<u32>(field), true);
}

int pcsx2hook_gs_read_display(uint32_t* pixels, int capacity, int* width, int* height)
{
	std::vector<u32> frame;
	int w = 0;
	int h = 0;
	if (!readDisplay(frame, w, h) || w * h > capacity)
		return 0;

	std::copy(frame.begin(), frame.end(), pixels);
	*width = w;
	*height = h;
	return 1;
}

int pcsx2hook_gs_snapshot(uint32_t* pixels, int capacity, int* width, int* height)
{
	if (!g_gs_renderer)
		return 0;

	std::vector<u32> frame;
	u32 w = 0;
	u32 h = 0;
	if (!g_gs_renderer->SaveSnapshotToMemory(0, 0, true, false, &w, &h, &frame) ||
		static_cast<int>(w * h) > capacity)
		return 0;

	std::copy(frame.begin(), frame.end(), pixels);
	*width = static_cast<int>(w);
	*height = static_cast<int>(h);
	return 1;
}

int pcsx2hook_gs_write_display(const char* path)
{
	std::vector<u32> frame;
	int width = 0;
	int height = 0;
	if (g_gs_device)
	{
		u32 w = 0;
		u32 h = 0;
		if (!g_gs_renderer || !g_gs_renderer->SaveSnapshotToMemory(0, 0, true, false, &w, &h, &frame))
			return 0;
		width = static_cast<int>(w);
		height = static_cast<int>(h);
	}
	else if (!readDisplay(frame, width, height))
	{
		return 0;
	}

	RGBA8Image image(width, height, frame.data());
	return image.SaveToFile(path) ? 1 : 0;
}

} // extern "C"

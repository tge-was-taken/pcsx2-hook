# Built as a shared library so a host loads it rather than compiling it in: the tracers and the hook
# registry are useful to anything that wants to look at a PS2 program, not only to a port.
add_library(pcsx2hook SHARED
	src/api.cpp
	src/config.cpp
	src/core.cpp
	src/diagnostics.cpp
	src/host.cpp
	src/symbols.cpp
	src/trace/api_trace.cpp
	src/trace/draw_context.cpp
	src/trace/dump_dir.cpp
	src/trace/exec_trace.cpp
	src/trace/gs_draws.cpp
	src/trace/gs_tracker.cpp
	src/trace/hw_trace.cpp
	src/trace/insn_trace.cpp
	src/trace/iop_trace.cpp
	src/trace/sif_trace.cpp
	src/trace/vif_trace.cpp)

target_include_directories(pcsx2hook
	PUBLIC include
	PUBLIC src
	PRIVATE src/trace
	# The "pcsx2/" and "common/" include prefixes the emulator sources use.
	PRIVATE ${PROJECT_SOURCE_DIR} ${PROJECT_SOURCE_DIR}/pcsx2)

set_target_properties(pcsx2hook PROPERTIES
	CXX_STANDARD 20
	CXX_STANDARD_REQUIRED ON)

# The emulator's own flags hide every symbol, which is right for it and wrong here: a host that
# links this in-process uses the C++ classes, not only the C API, so they have to be exported.
target_compile_options(pcsx2hook PRIVATE -fvisibility=default)

target_compile_definitions(pcsx2hook PRIVATE PCSX2HOOK_BUILDING)

target_link_options(pcsx2hook PRIVATE -Wl,--no-undefined)

target_link_libraries(pcsx2hook PRIVATE PCSX2_FLAGS PCSX2)

install(TARGETS pcsx2hook LIBRARY DESTINATION lib)
install(DIRECTORY include/ DESTINATION include)

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
	src/trace/spu_trace.cpp
	src/trace/timing_trace.cpp
	src/trace/vif_cmd_trace.cpp
	src/trace/vif_trace.cpp
	src/trace/vu_insn_trace.cpp)

target_include_directories(pcsx2hook
	PUBLIC include
	PRIVATE src
	# The "pcsx2/" and "common/" include prefixes the emulator sources use.
	PRIVATE ${PROJECT_SOURCE_DIR} ${PROJECT_SOURCE_DIR}/pcsx2)

set_target_properties(pcsx2hook PROPERTIES
	CXX_STANDARD 20
	CXX_STANDARD_REQUIRED ON)

target_compile_definitions(pcsx2hook PRIVATE PCSX2HOOK_BUILDING)

target_link_options(pcsx2hook PRIVATE -Wl,--no-undefined)

target_link_libraries(pcsx2hook PRIVATE PCSX2_FLAGS PCSX2)

install(TARGETS pcsx2hook LIBRARY DESTINATION lib)
install(DIRECTORY include/ DESTINATION include)

# Compiled as C so the public header is checked for C compatibility, which a C++-only host would
# never exercise. Covers the contract a caller can reach without booting: null handling, the config
# copy, and the error string.
add_executable(pcsx2hook_api_test tests/api_test.c)
target_link_libraries(pcsx2hook_api_test PRIVATE pcsx2hook)
set_target_properties(pcsx2hook_api_test PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON)
add_test(NAME pcsx2hook_api COMMAND pcsx2hook_api_test)

# A real boot, skipped unless PCSX2HOOK_TEST_BIOS and PCSX2HOOK_TEST_IMAGE point at a BIOS folder and
# something to boot. Separate from the test above because the library keeps process-global state, so
# a process drives one context.
add_test(NAME pcsx2hook_boot COMMAND pcsx2hook_api_test boot)

# The emulator looks for resources/ beside the running binary, so the test needs its own link.
add_custom_command(TARGET pcsx2hook_api_test POST_BUILD
	COMMAND ${CMAKE_COMMAND} -E create_symlink
		"${PROJECT_SOURCE_DIR}/bin/resources" "$<TARGET_FILE_DIR:pcsx2hook_api_test>/resources")

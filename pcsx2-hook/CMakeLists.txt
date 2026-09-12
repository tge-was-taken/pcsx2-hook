add_library(pcsx2hook SHARED
	src/api.cpp
	src/config.cpp
	src/core.cpp
	src/diagnostics.cpp
	src/gs.cpp
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
	PRIVATE ${PROJECT_SOURCE_DIR} ${PROJECT_SOURCE_DIR}/pcsx2)

set_target_properties(pcsx2hook PROPERTIES
	CXX_STANDARD 20
	CXX_STANDARD_REQUIRED ON)

target_compile_definitions(pcsx2hook PRIVATE PCSX2HOOK_BUILDING)

target_link_options(pcsx2hook PRIVATE -Wl,--no-undefined)

target_link_libraries(pcsx2hook PRIVATE PCSX2_FLAGS PCSX2)

install(TARGETS pcsx2hook LIBRARY DESTINATION lib)
install(DIRECTORY include/ DESTINATION include)

add_executable(pcsx2hook_cli tools/cli.c)
target_link_libraries(pcsx2hook_cli PRIVATE pcsx2hook)
set_target_properties(pcsx2hook_cli PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON)
install(TARGETS pcsx2hook_cli RUNTIME DESTINATION bin)

add_executable(pcsx2hook_api_test tests/api_test.c)
target_link_libraries(pcsx2hook_api_test PRIVATE pcsx2hook)
set_target_properties(pcsx2hook_api_test PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON)
add_test(NAME pcsx2hook_api COMMAND pcsx2hook_api_test)

add_test(NAME pcsx2hook_boot COMMAND pcsx2hook_api_test boot)
add_test(NAME pcsx2hook_destroy_running COMMAND pcsx2hook_api_test destroy)
add_test(NAME pcsx2hook_run_control COMMAND pcsx2hook_api_test run-control)

add_custom_target(pcsx2hook_resources
	COMMAND ${CMAKE_COMMAND} -E create_symlink
		"${PROJECT_SOURCE_DIR}/bin/resources" "$<TARGET_FILE_DIR:pcsx2hook_cli>/resources")
add_dependencies(pcsx2hook_cli pcsx2hook_resources)
add_dependencies(pcsx2hook_api_test pcsx2hook_resources)

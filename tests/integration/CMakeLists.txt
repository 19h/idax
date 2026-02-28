# tests/integration/CMakeLists.txt
# Integration tests: idalib executables that exercise idax APIs.

if(WIN32)
    set(IDAX_IDALIB_LIB_NAME "idalib.lib")
    set(IDAX_IDA_LIB_NAME "ida.lib")
elseif(APPLE)
    set(IDAX_IDALIB_LIB_NAME "libidalib.dylib")
    set(IDAX_IDA_LIB_NAME "libida.dylib")
else()
    set(IDAX_IDALIB_LIB_NAME "libidalib.so")
    set(IDAX_IDA_LIB_NAME "libida.so")
endif()

# ── Locate IDA installation ─────────────────────────────────────────────
# The IDA SDK ships stub dylibs with different symbol exports than the real
# IDA runtime dylibs. On macOS with two-level namespace linking, this causes
# symbols (like qvector_reserve) to be bound to the wrong dylib, resulting
# in null-pointer crashes at runtime. We MUST link against the real IDA
# dylibs from the installation for correct two-level namespace bindings.
#
# On Windows and Linux, we only strictly need the IDADIR to run the tests,
# but we can optionally link against the installation libs if available.
if(DEFINED ENV{IDADIR})
    set(IDA_INSTALL_DIR "$ENV{IDADIR}")
elseif(APPLE)
    # Try common macOS locations.
    foreach(_ver 9.3 9.2)
        set(_try "/Applications/IDA Professional ${_ver}.app/Contents/MacOS")
        if(EXISTS "${_try}/${IDAX_IDALIB_LIB_NAME}")
            set(IDA_INSTALL_DIR "${_try}")
            break()
        endif()
    endforeach()
endif()

if(NOT IDA_INSTALL_DIR)
    message(WARNING "IDA installation not found — integration tests cannot be run.\n"
                    "Set IDADIR environment variable to your IDA installation directory.")
    if(NOT COMMAND ida_add_idalib)
        return()
    endif()
else()
    message(STATUS "IDA installation: ${IDA_INSTALL_DIR}")
endif()

# ── Helper function to reduce boilerplate ────────────────────────────────
# Creates an integration test executable linked against real IDA dylibs,
# registers it as a CTest with the fixture binary as argument.
function(idax_add_integration_test TEST_NAME SOURCE_FILE)
    set(TARGET_NAME "idax_${TEST_NAME}_test")

    # On macOS, we MUST link against the actual installation dylibs.
    # On other platforms we use the SDK's ida_add_idalib macro, which automatically
    # links the correct stubs from the SDK (e.g. IDASDK/lib/x64_win_vc_64/idalib.lib).
    if(APPLE AND IDA_INSTALL_DIR)
        add_executable(${TARGET_NAME} ${SOURCE_FILE})
        target_link_libraries(${TARGET_NAME}
            PRIVATE
                idax
                "${IDA_INSTALL_DIR}/${IDAX_IDALIB_LIB_NAME}"
                "${IDA_INSTALL_DIR}/${IDAX_IDA_LIB_NAME}"
        )
        target_compile_definitions(${TARGET_NAME} PRIVATE __EA64__ IDALIB_IMPL)
        target_include_directories(${TARGET_NAME} PRIVATE "${IDASDK}/include")
        set_target_properties(${TARGET_NAME} PROPERTIES
            BUILD_RPATH "${IDA_INSTALL_DIR}"
            INSTALL_RPATH "${IDA_INSTALL_DIR}"
        )
    elseif(COMMAND ida_add_idalib)
        ida_add_idalib(${TARGET_NAME}
            TYPE EXECUTABLE
            SOURCES ${SOURCE_FILE}
            LIBRARIES idax::idax
        )
    else()
        add_executable(${TARGET_NAME} ${SOURCE_FILE})
        target_link_libraries(${TARGET_NAME}
            PRIVATE
                idax
                "${IDA_INSTALL_DIR}/${IDAX_IDALIB_LIB_NAME}"
                "${IDA_INSTALL_DIR}/${IDAX_IDA_LIB_NAME}"
        )
        target_compile_definitions(${TARGET_NAME} PRIVATE __EA64__ IDALIB_IMPL)
        target_include_directories(${TARGET_NAME} PRIVATE "${IDASDK}/include")
    endif()

    if(IDA_INSTALL_DIR)
        add_test(
            NAME ${TEST_NAME}
            COMMAND ${TARGET_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/../fixtures/simple_appcall_linux64"
        )
        set_tests_properties(${TEST_NAME} PROPERTIES
            ENVIRONMENT "IDADIR=${IDA_INSTALL_DIR}"
        )
    endif()
endfunction()

# ── Register integration tests ───────────────────────────────────────────

idax_add_integration_test(smoke                           smoke_test.cpp)
idax_add_integration_test(name_comment_xref_search        name_comment_xref_search_test.cpp)
idax_add_integration_test(data_mutation_safety             data_mutation_safety_test.cpp)
idax_add_integration_test(segment_function_edge_cases      segment_function_edge_cases_test.cpp)
idax_add_integration_test(instruction_decode_behavior      instruction_decode_behavior_test.cpp)
idax_add_integration_test(type_roundtrip                   type_roundtrip_test.cpp)
idax_add_integration_test(fixup_relocation                 fixup_relocation_test.cpp)
idax_add_integration_test(operand_and_text                 operand_and_text_test.cpp)
idax_add_integration_test(decompiler_storage_hardening     decompiler_storage_hardening_test.cpp)
idax_add_integration_test(debugger_ui_graph_event          debugger_ui_graph_event_test.cpp)
idax_add_integration_test(loader_processor_scenario        loader_processor_scenario_test.cpp)
idax_add_integration_test(event_stress                      event_stress_test.cpp)
idax_add_integration_test(decompiler_edge_cases            decompiler_edge_cases_test.cpp)
idax_add_integration_test(performance_benchmark            performance_benchmark_test.cpp)

# ── Torture tests (expanded coverage) ────────────────────────────────────
idax_add_integration_test(analysis_entry_lines_torture     analysis_entry_lines_torture_test.cpp)
idax_add_integration_test(cross_domain_torture             cross_domain_torture_test.cpp)
idax_add_integration_test(type_data_comment_torture        type_data_comment_torture_test.cpp)
idax_add_integration_test(operand_function_torture         operand_function_torture_test.cpp)

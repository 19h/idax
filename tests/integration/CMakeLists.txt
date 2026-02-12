# tests/integration/CMakeLists.txt
# Integration tests: idalib executables that exercise idax APIs.

# ── Locate IDA installation ─────────────────────────────────────────────
# The IDA SDK ships stub dylibs with different symbol exports than the real
# IDA runtime dylibs. On macOS with two-level namespace linking, this causes
# symbols (like qvector_reserve) to be bound to the wrong dylib, resulting
# in null-pointer crashes at runtime. We MUST link against the real IDA
# dylibs from the installation for correct two-level namespace bindings.
if(DEFINED ENV{IDADIR})
    set(IDA_INSTALL_DIR "$ENV{IDADIR}")
elseif(APPLE)
    # Try common macOS locations.
    foreach(_ver 9.3 9.2)
        set(_try "/Applications/IDA Professional ${_ver}.app/Contents/MacOS")
        if(EXISTS "${_try}/libidalib.dylib")
            set(IDA_INSTALL_DIR "${_try}")
            break()
        endif()
    endforeach()
endif()

if(NOT IDA_INSTALL_DIR)
    message(WARNING "IDA installation not found — integration tests cannot be built.\n"
                    "Set IDADIR environment variable to your IDA installation directory.")
    return()
endif()

message(STATUS "IDA installation: ${IDA_INSTALL_DIR}")

# ── Helper function to reduce boilerplate ────────────────────────────────
# Creates an integration test executable linked against real IDA dylibs,
# registers it as a CTest with the fixture binary as argument.
function(idax_add_integration_test TEST_NAME SOURCE_FILE)
    set(TARGET_NAME "idax_${TEST_NAME}_test")

    add_executable(${TARGET_NAME} ${SOURCE_FILE})

    target_link_libraries(${TARGET_NAME}
        PRIVATE
            idax
            "${IDA_INSTALL_DIR}/libidalib.dylib"
            "${IDA_INSTALL_DIR}/libida.dylib"
    )

    target_compile_definitions(${TARGET_NAME} PRIVATE __EA64__ IDALIB_IMPL)
    target_include_directories(${TARGET_NAME} PRIVATE "${IDASDK}/include")

    if(APPLE)
        set_target_properties(${TARGET_NAME} PROPERTIES
            BUILD_RPATH "${IDA_INSTALL_DIR}"
            INSTALL_RPATH "${IDA_INSTALL_DIR}"
        )
    endif()

    add_test(
        NAME ${TEST_NAME}
        COMMAND ${TARGET_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/../fixtures/simple_appcall_linux64"
    )
    set_tests_properties(${TEST_NAME} PROPERTIES
        ENVIRONMENT "IDADIR=${IDA_INSTALL_DIR}"
    )
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

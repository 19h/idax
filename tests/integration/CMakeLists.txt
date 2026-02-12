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

# ── Build the smoke test using real IDA dylibs ──────────────────────────
# We avoid ida_add_idalib() because it links against the SDK stub dylibs.
# Instead we manually create the target with the same settings but link
# against the real dylibs from the IDA installation directory.
add_executable(idax_smoke_test smoke_test.cpp)

target_link_libraries(idax_smoke_test
    PRIVATE
        idax
        "${IDA_INSTALL_DIR}/libidalib.dylib"
        "${IDA_INSTALL_DIR}/libida.dylib"
)

# Apply the same compile definitions as idasdk::idalib would.
target_compile_definitions(idax_smoke_test PRIVATE __EA64__ IDALIB_IMPL)

# Include SDK headers.
target_include_directories(idax_smoke_test PRIVATE "${IDASDK}/include")

# Set rpath so the real IDA dylibs are found at runtime.
if(APPLE)
    set_target_properties(idax_smoke_test PROPERTIES
        BUILD_RPATH "${IDA_INSTALL_DIR}"
        INSTALL_RPATH "${IDA_INSTALL_DIR}"
    )
endif()

add_executable(idax_name_comment_xref_search_test
    name_comment_xref_search_test.cpp
)

add_executable(idax_data_mutation_safety_test
    data_mutation_safety_test.cpp
)

add_executable(idax_segment_function_edge_cases_test
    segment_function_edge_cases_test.cpp
)

add_executable(idax_instruction_decode_behavior_test
    instruction_decode_behavior_test.cpp
)

target_link_libraries(idax_name_comment_xref_search_test
    PRIVATE
        idax
        "${IDA_INSTALL_DIR}/libidalib.dylib"
        "${IDA_INSTALL_DIR}/libida.dylib"
)

target_link_libraries(idax_data_mutation_safety_test
    PRIVATE
        idax
        "${IDA_INSTALL_DIR}/libidalib.dylib"
        "${IDA_INSTALL_DIR}/libida.dylib"
)

target_link_libraries(idax_segment_function_edge_cases_test
    PRIVATE
        idax
        "${IDA_INSTALL_DIR}/libidalib.dylib"
        "${IDA_INSTALL_DIR}/libida.dylib"
)

target_link_libraries(idax_instruction_decode_behavior_test
    PRIVATE
        idax
        "${IDA_INSTALL_DIR}/libidalib.dylib"
        "${IDA_INSTALL_DIR}/libida.dylib"
)

target_compile_definitions(idax_name_comment_xref_search_test PRIVATE __EA64__ IDALIB_IMPL)
target_include_directories(idax_name_comment_xref_search_test PRIVATE "${IDASDK}/include")

target_compile_definitions(idax_data_mutation_safety_test PRIVATE __EA64__ IDALIB_IMPL)
target_include_directories(idax_data_mutation_safety_test PRIVATE "${IDASDK}/include")

target_compile_definitions(idax_segment_function_edge_cases_test PRIVATE __EA64__ IDALIB_IMPL)
target_include_directories(idax_segment_function_edge_cases_test PRIVATE "${IDASDK}/include")

target_compile_definitions(idax_instruction_decode_behavior_test PRIVATE __EA64__ IDALIB_IMPL)
target_include_directories(idax_instruction_decode_behavior_test PRIVATE "${IDASDK}/include")

if(APPLE)
    set_target_properties(idax_name_comment_xref_search_test PROPERTIES
        BUILD_RPATH "${IDA_INSTALL_DIR}"
        INSTALL_RPATH "${IDA_INSTALL_DIR}"
    )

    set_target_properties(idax_data_mutation_safety_test PROPERTIES
        BUILD_RPATH "${IDA_INSTALL_DIR}"
        INSTALL_RPATH "${IDA_INSTALL_DIR}"
    )

    set_target_properties(idax_segment_function_edge_cases_test PROPERTIES
        BUILD_RPATH "${IDA_INSTALL_DIR}"
        INSTALL_RPATH "${IDA_INSTALL_DIR}"
    )

    set_target_properties(idax_instruction_decode_behavior_test PROPERTIES
        BUILD_RPATH "${IDA_INSTALL_DIR}"
        INSTALL_RPATH "${IDA_INSTALL_DIR}"
    )
endif()

# Register as CTest (manual execution — requires IDA license).
add_test(
    NAME smoke_test
    COMMAND idax_smoke_test "${CMAKE_CURRENT_SOURCE_DIR}/../fixtures/simple_appcall_linux64"
)
set_tests_properties(smoke_test PROPERTIES
    ENVIRONMENT "IDADIR=${IDA_INSTALL_DIR}"
)

add_test(
    NAME name_comment_xref_search_behavior
    COMMAND idax_name_comment_xref_search_test "${CMAKE_CURRENT_SOURCE_DIR}/../fixtures/simple_appcall_linux64"
)
set_tests_properties(name_comment_xref_search_behavior PROPERTIES
    ENVIRONMENT "IDADIR=${IDA_INSTALL_DIR}"
)

add_test(
    NAME data_mutation_safety
    COMMAND idax_data_mutation_safety_test "${CMAKE_CURRENT_SOURCE_DIR}/../fixtures/simple_appcall_linux64"
)
set_tests_properties(data_mutation_safety PROPERTIES
    ENVIRONMENT "IDADIR=${IDA_INSTALL_DIR}"
)

add_test(
    NAME segment_function_edge_cases
    COMMAND idax_segment_function_edge_cases_test "${CMAKE_CURRENT_SOURCE_DIR}/../fixtures/simple_appcall_linux64"
)
set_tests_properties(segment_function_edge_cases PROPERTIES
    ENVIRONMENT "IDADIR=${IDA_INSTALL_DIR}"
)

add_test(
    NAME instruction_decode_behavior
    COMMAND idax_instruction_decode_behavior_test "${CMAKE_CURRENT_SOURCE_DIR}/../fixtures/simple_appcall_linux64"
)
set_tests_properties(instruction_decode_behavior PROPERTIES
    ENVIRONMENT "IDADIR=${IDA_INSTALL_DIR}"
)

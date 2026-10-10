# tests/CMakeLists.txt
# Integration tests for idax — built as idalib executables.

add_subdirectory(unit)
add_subdirectory(integration)

option(IDAX_BUILD_HOST_EVIDENCE_MODULE "Build the opt-in interactive IDA UI assertion module" OFF)
if(IDAX_BUILD_HOST_EVIDENCE_MODULE)
    add_subdirectory(host)
endif()

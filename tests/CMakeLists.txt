# tests/CMakeLists.txt
# Integration tests for idax — built as idalib executables.

add_subdirectory(unit)
add_subdirectory(integration)

option(IDAX_BUILD_LUMINA_NETWORK_PROBE "Build the opt-in connected Lumina lifecycle probe" OFF)
if(IDAX_BUILD_LUMINA_NETWORK_PROBE)
    add_subdirectory(network)
endif()

option(IDAX_BUILD_HOST_EVIDENCE_MODULE "Build the opt-in interactive IDA UI assertion module" OFF)
if(IDAX_BUILD_HOST_EVIDENCE_MODULE)
    add_subdirectory(host)
endif()

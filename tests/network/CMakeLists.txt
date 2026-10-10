# A separately invoked positive network probe; the default CTest roster stays
# independent of service availability and credentials.
if(APPLE)
    if(NOT EXISTS "$ENV{IDADIR}/libidalib.dylib")
        message(FATAL_ERROR "Lumina evidence requires IDADIR with the actual idalib runtime")
    endif()
    add_executable(idax_lumina_connected_probe lumina_connected_probe.cpp)
    target_link_libraries(idax_lumina_connected_probe PRIVATE idax::idax
        "$ENV{IDADIR}/libidalib.dylib" "$ENV{IDADIR}/libida.dylib")
    set_target_properties(idax_lumina_connected_probe PROPERTIES BUILD_RPATH "$ENV{IDADIR}")
else()
    ida_add_idalib(idax_lumina_connected_probe TYPE EXECUTABLE
        SOURCES lumina_connected_probe.cpp LIBRARIES idax::idax)
endif()
idax_remap_build_paths(idax_lumina_connected_probe)
file(GENERATE OUTPUT "${CMAKE_BINARY_DIR}/lumina-probe-path-$<CONFIG>.txt"
    CONTENT "$<TARGET_FILE:idax_lumina_connected_probe>\n")

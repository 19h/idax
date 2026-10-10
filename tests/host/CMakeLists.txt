# Explicit opt-in module called from IDA's GUI Python console on the UI thread.
add_library(idax_codedump_ui_host_gates SHARED
    codedump_ui_host_gates.cpp
    ../integration/codedump_parity_host_gates_test.cpp)
target_compile_definitions(idax_codedump_ui_host_gates PRIVATE IDAX_CODEDUMP_UI_HOST=1)
target_link_libraries(idax_codedump_ui_host_gates PRIVATE idax::idax)
idax_remap_build_paths(idax_codedump_ui_host_gates)

if(APPLE)
    if(NOT EXISTS "$ENV{IDADIR}/libida.dylib")
        message(FATAL_ERROR "Interactive host evidence requires IDADIR with the actual libida runtime")
    endif()
    target_link_libraries(idax_codedump_ui_host_gates PRIVATE "$ENV{IDADIR}/libida.dylib")
    set_target_properties(idax_codedump_ui_host_gates PROPERTIES
        BUILD_RPATH "$ENV{IDADIR}"
        INSTALL_NAME_DIR "@rpath"
        BUILD_WITH_INSTALL_NAME_DIR TRUE)
else()
    target_link_libraries(idax_codedump_ui_host_gates PRIVATE idasdk::plugin)
endif()

add_library(idax_appcall_host_gates SHARED appcall_host_gates.cpp)
target_link_libraries(idax_appcall_host_gates PRIVATE idax::idax)
idax_remap_build_paths(idax_appcall_host_gates)
if(APPLE)
    target_link_libraries(idax_appcall_host_gates PRIVATE "$ENV{IDADIR}/libida.dylib")
    set_target_properties(idax_appcall_host_gates PROPERTIES
        BUILD_RPATH "$ENV{IDADIR}"
        INSTALL_NAME_DIR "@rpath"
        BUILD_WITH_INSTALL_NAME_DIR TRUE)
else()
    target_link_libraries(idax_appcall_host_gates PRIVATE idasdk::plugin)
endif()

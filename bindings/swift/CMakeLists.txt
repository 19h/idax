# The Swift package consumes this complete C transport archive via pkg-config.
# Compile the canonical Rust transport directly; do not copy or fork its ABI.
if(NOT APPLE AND NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
    message(FATAL_ERROR "The Swift native build currently supports macOS and Linux.")
endif()

set(IDAX_SWIFT_RUNTIME_DIR "$ENV{IDADIR}" CACHE PATH "IDA 9.4 runtime library directory")
if(APPLE)
    set(_idax_swift_library_suffix dylib)
    set(_idax_swift_cxx_library c++)
else()
    set(_idax_swift_library_suffix so)
    set(_idax_swift_cxx_library stdc++)
endif()
foreach(_library ida idalib)
    if(NOT EXISTS "${IDAX_SWIFT_RUNTIME_DIR}/lib${_library}.${_idax_swift_library_suffix}")
        message(FATAL_ERROR "Swift requires real IDA runtime libraries. Set IDADIR or IDAX_SWIFT_RUNTIME_DIR to the IDA 9.4 runtime directory.")
    endif()
endforeach()

set(_idax_swift_native_sources
    ${IDAX_SOURCES}
    ../rust/idax-sys/shim/idax_shim.cpp
    bridge/support.cpp
    bridge/data_custom.cpp
    bridge/data_values.cpp
    bridge/decompiler.cpp
    bridge/decompiler_events.cpp
    bridge/forms.cpp
    bridge/microcode.cpp
    bridge/type_extra.cpp
    bridge/values.cpp
    bridge/values_extra.cpp
    bridge/lifecycle.cpp
)
add_library(idax_swift_native STATIC ${_idax_swift_native_sources})
# ida-cmake makes SDK modules hidden by default. The shared Swift support image
# also provides the C transport and C++ adapter methods to separately linked
# addon entries, so those definitions must remain visible at that boundary.
set_source_files_properties(${_idax_swift_native_sources}
    PROPERTIES COMPILE_OPTIONS "-fvisibility=default")
target_include_directories(idax_swift_native PRIVATE
    "${PROJECT_SOURCE_DIR}/include"
    "${PROJECT_SOURCE_DIR}/src"
)
target_link_libraries(idax_swift_native PRIVATE idasdk_headers)
target_compile_features(idax_swift_native PRIVATE cxx_std_23)
set_target_properties(idax_swift_native PROPERTIES
    POSITION_INDEPENDENT_CODE ON
    INTERPROCEDURAL_OPTIMIZATION OFF
    ARCHIVE_OUTPUT_DIRECTORY "$<1:${CMAKE_CURRENT_BINARY_DIR}>"
)

# Only standard -L/-l options are needed, so clients can consume the Swift
# product transitively without unsafe build flags in its package manifest.
file(MAKE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/pkgconfig")
configure_file(idax-swift.pc.in "${CMAKE_CURRENT_BINARY_DIR}/pkgconfig/idax-swift.pc" @ONLY)

# Analyze a deterministic source-built fixture rather than a host utility with
# architecture-dependent instruction selection and no semantic test symbols.
add_executable(idax_swift_runtime_fixture
    "${PROJECT_SOURCE_DIR}/tests/fixtures/decompiler_semantic_metadata_host.cpp")
set_target_properties(idax_swift_runtime_fixture PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "$<1:${CMAKE_CURRENT_BINARY_DIR}>")
if(APPLE)
    set_target_properties(idax_swift_runtime_fixture PROPERTIES OSX_ARCHITECTURES x86_64)
endif()
target_compile_options(idax_swift_runtime_fixture PRIVATE -O1 -fno-inline -g0)

# Optional addon entry archive consumed by scripts/build-module.py. The entry
# contains a real canonical SDK export macro; Swift supplies a C bootstrap.
set(IDAX_SWIFT_MODULE_KIND "" CACHE STRING "Swift addon kind: plugin, loader, or processor")
set(IDAX_SWIFT_MODULE_SYMBOL "" CACHE STRING "Swift @_cdecl module bootstrap symbol")
if(IDAX_SWIFT_MODULE_KIND)
    if(NOT IDAX_SWIFT_MODULE_SYMBOL MATCHES "^[A-Za-z_][A-Za-z0-9_]*$")
        message(FATAL_ERROR "IDAX_SWIFT_MODULE_SYMBOL must be a C identifier.")
    endif()
    if(IDAX_SWIFT_MODULE_KIND STREQUAL "plugin")
        set(_idax_swift_adapter PluginAdapter)
        set(_idax_swift_export_call
            "IDAX_PLUGIN_WITH_FLAGS(SwiftModule, idax::swift::plugin_export_flags(${IDAX_SWIFT_MODULE_SYMBOL}))")
        set(_idax_swift_descriptor_type plugin_t)
        set(_idax_swift_descriptor_name PLUGIN)
    elseif(IDAX_SWIFT_MODULE_KIND STREQUAL "loader")
        set(_idax_swift_adapter LoaderAdapter)
        set(_idax_swift_export_call "IDAX_LOADER(SwiftModule)")
        set(_idax_swift_descriptor_type loader_t)
        set(_idax_swift_descriptor_name LDSC)
    elseif(IDAX_SWIFT_MODULE_KIND STREQUAL "processor")
        set(_idax_swift_adapter ProcessorAdapter)
        set(_idax_swift_export_call "IDAX_PROCESSOR(SwiftModule)")
        set(_idax_swift_descriptor_type processor_t)
        set(_idax_swift_descriptor_name LPH)
    else()
        message(FATAL_ERROR "Unknown IDAX_SWIFT_MODULE_KIND.")
    endif()
    configure_file(module_entry.cpp.in "${CMAKE_CURRENT_BINARY_DIR}/module_entry.cpp" @ONLY)
    configure_file(module_bridge.cpp.in "${CMAKE_CURRENT_BINARY_DIR}/module_bridge.cpp" @ONLY)
    add_library(idax_swift_module_entry STATIC
        "${CMAKE_CURRENT_BINARY_DIR}/module_entry.cpp"
        "${CMAKE_CURRENT_BINARY_DIR}/module_bridge.cpp")
    target_include_directories(idax_swift_module_entry PRIVATE
        "${PROJECT_SOURCE_DIR}/include" "${PROJECT_SOURCE_DIR}/src"
        "${CMAKE_CURRENT_SOURCE_DIR}/bridge")
    # Each addon owns its SDK factory and descriptor. Only the descriptor is
    # exported; factory state cannot interpose across other loaded addons.
    set_source_files_properties("${CMAKE_CURRENT_BINARY_DIR}/module_bridge.cpp"
        PROPERTIES COMPILE_OPTIONS "-fvisibility=hidden;-fvisibility-inlines-hidden")
    target_link_libraries(idax_swift_module_entry PRIVATE idasdk_headers)
    target_compile_features(idax_swift_module_entry PRIVATE cxx_std_23)
    set_target_properties(idax_swift_module_entry PROPERTIES
        POSITION_INDEPENDENT_CODE ON INTERPROCEDURAL_OPTIMIZATION OFF
        ARCHIVE_OUTPUT_DIRECTORY "$<1:${CMAKE_CURRENT_BINARY_DIR}>")
endif()

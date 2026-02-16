cmake_minimum_required(VERSION 3.27)

# Example sources demonstrate realistic idax wrapper usage patterns,
# from minimal quick-start skeletons to comprehensive domain examples.

option(IDAX_BUILD_EXAMPLE_ADDONS "Build sample IDA addon modules" OFF)
option(IDAX_BUILD_EXAMPLE_TOOLS "Build sample idalib-based tools" OFF)

set(IDAX_EXAMPLE_SOURCES
    # Minimal examples (quick-start reference).
    plugin/action_plugin.cpp
    loader/minimal_loader.cpp
    procmod/minimal_procmod.cpp

    # Advanced examples (realistic analysis tools).
    plugin/deep_analysis_plugin.cpp
    plugin/decompiler_plugin.cpp
    plugin/event_monitor_plugin.cpp
    plugin/storage_metadata_plugin.cpp
    plugin/lifter_port_plugin.cpp
    plugin/qtform_renderer_plugin.cpp
    plugin/qtform_renderer_widget.hpp
    plugin/qtform_renderer_widget.cpp
    plugin/abyss_port_plugin.cpp
    loader/advanced_loader.cpp
    procmod/advanced_procmod.cpp

    # Full parity example (real-world port pattern).
    full/jbc_common.hpp
    loader/jbc_full_loader.cpp
    procmod/jbc_full_procmod.cpp

    # idalib tool port examples.
    tools/idalib_dump_port.cpp
    tools/idalib_lumina_port.cpp
    tools/ida2py_port.cpp
)

add_custom_target(idax_examples SOURCES ${IDAX_EXAMPLE_SOURCES})

if(IDAX_BUILD_EXAMPLE_ADDONS)
    # ── Minimal examples ─────────────────────────────────────────────────

    ida_add_loader(idax_example_loader
        SOURCES loader/minimal_loader.cpp
        LIBRARIES idax::idax
    )

    ida_add_procmod(idax_example_procmod
        SOURCES procmod/minimal_procmod.cpp
        LIBRARIES idax::idax
    )

    ida_add_plugin(idax_example_plugin
        SOURCES plugin/action_plugin.cpp
        LIBRARIES idax::idax
    )

    # ── Advanced examples ────────────────────────────────────────────────

    ida_add_plugin(idax_audit_plugin
        SOURCES plugin/deep_analysis_plugin.cpp
        LIBRARIES idax::idax
    )

    ida_add_plugin(idax_complexity_plugin
        SOURCES plugin/decompiler_plugin.cpp
        LIBRARIES idax::idax
    )

    ida_add_plugin(idax_change_tracker_plugin
        SOURCES plugin/event_monitor_plugin.cpp
        LIBRARIES idax::idax
    )

    ida_add_plugin(idax_fingerprint_plugin
        SOURCES plugin/storage_metadata_plugin.cpp
        LIBRARIES idax::idax
    )

    ida_add_plugin(idax_lifter_port_plugin
        SOURCES plugin/lifter_port_plugin.cpp
        LIBRARIES idax::idax
    )

    ida_add_plugin(idax_abyss_port_plugin
        SOURCES plugin/abyss_port_plugin.cpp
        LIBRARIES idax::idax
    )

    ida_add_loader(idax_xbin_loader
        SOURCES loader/advanced_loader.cpp
        LIBRARIES idax::idax
    )

    ida_add_loader(idax_jbc_full_loader
        SOURCES loader/jbc_full_loader.cpp
        LIBRARIES idax::idax
    )

    ida_add_procmod(idax_xrisc_procmod
        SOURCES procmod/advanced_procmod.cpp
        LIBRARIES idax::idax
    )

    ida_add_procmod(idax_jbc_full_procmod
        SOURCES procmod/jbc_full_procmod.cpp
        LIBRARIES idax::idax
    )
endif()

if(IDAX_BUILD_EXAMPLE_TOOLS)
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

    set(IDAX_EXAMPLE_IDA_RUNTIME_DIR "")
    if(DEFINED ENV{IDADIR})
        set(_ida_dir "$ENV{IDADIR}")
        if(EXISTS "${_ida_dir}/${IDAX_IDALIB_LIB_NAME}" AND EXISTS "${_ida_dir}/${IDAX_IDA_LIB_NAME}")
            set(IDAX_EXAMPLE_IDA_RUNTIME_DIR "${_ida_dir}")
        endif()
    endif()

    if(NOT IDAX_EXAMPLE_IDA_RUNTIME_DIR AND APPLE)
        foreach(_ver 9.3 9.2)
            set(_try "/Applications/IDA Professional ${_ver}.app/Contents/MacOS")
            if(EXISTS "${_try}/${IDAX_IDALIB_LIB_NAME}" AND EXISTS "${_try}/${IDAX_IDA_LIB_NAME}")
                set(IDAX_EXAMPLE_IDA_RUNTIME_DIR "${_try}")
                break()
            endif()
        endforeach()
    endif()

    function(idax_add_idalib_tool TARGET_NAME SOURCE_FILE)
        if(IDAX_EXAMPLE_IDA_RUNTIME_DIR)
            add_executable(${TARGET_NAME} ${SOURCE_FILE})
            target_link_libraries(${TARGET_NAME}
                PRIVATE
                    idax
                    "${IDAX_EXAMPLE_IDA_RUNTIME_DIR}/${IDAX_IDALIB_LIB_NAME}"
                    "${IDAX_EXAMPLE_IDA_RUNTIME_DIR}/${IDAX_IDA_LIB_NAME}"
            )

            if(APPLE)
                set_target_properties(${TARGET_NAME} PROPERTIES
                    BUILD_RPATH "${IDAX_EXAMPLE_IDA_RUNTIME_DIR}"
                    INSTALL_RPATH "${IDAX_EXAMPLE_IDA_RUNTIME_DIR}"
                )
            endif()
        elseif(COMMAND ida_add_idalib)
            ida_add_idalib(${TARGET_NAME}
                TYPE EXECUTABLE
                SOURCES ${SOURCE_FILE}
                LIBRARIES idax::idax
            )
        endif()
    endfunction()

    if(IDAX_EXAMPLE_IDA_RUNTIME_DIR)
        message(STATUS "idax tool examples use IDA runtime: ${IDAX_EXAMPLE_IDA_RUNTIME_DIR}")
    elseif(COMMAND ida_add_idalib)
        message(STATUS "idax tool examples use SDK idalib stubs (set IDADIR for runtime-linked binaries)")
    else()
        message(WARNING "ida_add_idalib() is unavailable; skipping idalib tool examples")
    endif()

    if(COMMAND ida_add_idalib OR IDAX_EXAMPLE_IDA_RUNTIME_DIR)
        idax_add_idalib_tool(idax_idalib_dump_port tools/idalib_dump_port.cpp)
        idax_add_idalib_tool(idax_idalib_lumina_port tools/idalib_lumina_port.cpp)
        idax_add_idalib_tool(idax_ida2py_port tools/ida2py_port.cpp)
    endif()
endif()

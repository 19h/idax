cmake_minimum_required(VERSION 3.27)

# Example sources demonstrate realistic idax wrapper usage patterns,
# from minimal quick-start skeletons to comprehensive domain examples.

option(IDAX_BUILD_EXAMPLE_ADDONS "Build sample IDA addon modules" OFF)

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
    loader/advanced_loader.cpp
    procmod/advanced_procmod.cpp
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

    ida_add_loader(idax_xbin_loader
        SOURCES loader/advanced_loader.cpp
        LIBRARIES idax::idax
    )

    ida_add_procmod(idax_xrisc_procmod
        SOURCES procmod/advanced_procmod.cpp
        LIBRARIES idax::idax
    )
endif()

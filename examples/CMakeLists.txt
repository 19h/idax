cmake_minimum_required(VERSION 3.27)

# Example sources are intentionally lightweight and primarily serve as
# reference implementations. Build targets are opt-in.

option(IDAX_BUILD_EXAMPLE_ADDONS "Build sample IDA addon modules" OFF)

set(IDAX_EXAMPLE_SOURCES
    plugin/action_plugin.cpp
    loader/minimal_loader.cpp
    procmod/minimal_procmod.cpp
)

add_custom_target(idax_examples SOURCES ${IDAX_EXAMPLE_SOURCES})

if(IDAX_BUILD_EXAMPLE_ADDONS)
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
endif()

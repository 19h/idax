cmake_minimum_required(VERSION 3.27)
project(integration_fetch_content LANGUAGES CXX)

include(FetchContent)

# Fetch idax from the local directory.
FetchContent_Declare(
    idax
    SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../..
)

# This will trigger idax's CMakeLists.txt to run, which in turn
# fetches ida-sdk and includes bootstrap.cmake if IDASDK isn't set.
FetchContent_MakeAvailable(idax)

# ida_add_plugin is a macro provided by ida-cmake (which idax bootstraps).
# The IDAX_PLUGIN macro requires idax::idax library.
ida_add_plugin(hello_world_fetch
    SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/../hello_world.cpp
    LIBRARIES idax::idax
)

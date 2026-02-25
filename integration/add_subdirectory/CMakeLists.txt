cmake_minimum_required(VERSION 3.27)
project(integration_add_subdir LANGUAGES CXX)

# Simulate idax being a subdirectory (like a git submodule)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../.. ${CMAKE_CURRENT_BINARY_DIR}/idax_build)

ida_add_plugin(hello_world_subdir
    SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/../hello_world.cpp
    LIBRARIES idax::idax
)

cmake_minimum_required(VERSION 3.27)
project(idax VERSION 0.1.0 LANGUAGES CXX)

# ── Bootstrap ida-cmake ──────────────────────────────────────────────────
# IDASDK env var must point to the ida-sdk root (GitHub clone or zip)
include($ENV{IDASDK}/ida-cmake/bootstrap.cmake)
find_package(idasdk REQUIRED)

# ── C++23 standard for idax itself ───────────────────────────────────────
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ── Collect sources ──────────────────────────────────────────────────────
file(GLOB_RECURSE IDAX_SOURCES CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp"
)

# ── SDK headers-only target for compilation ──────────────────────────────
# idax needs the SDK headers and __EA64__ to compile, but does NOT
# propagate a specific link target (plugin/loader/idalib) to consumers.
# Consumers must link their own idasdk::plugin, idasdk::idalib, etc.
if(NOT TARGET idasdk_headers)
    add_library(idasdk_headers INTERFACE IMPORTED)
    set_target_properties(idasdk_headers PROPERTIES
        INTERFACE_INCLUDE_DIRECTORIES "${IDASDK}/include"
    )
    target_compile_definitions(idasdk_headers INTERFACE __EA64__)
    target_link_libraries(idasdk_headers INTERFACE
        ida_platform_settings
        ida_compiler_settings)
endif()

# ── idax static library ─────────────────────────────────────────────────
# Built as a static library that IDA addons link against alongside idasdk::*
add_library(idax STATIC ${IDAX_SOURCES})
add_library(idax::idax ALIAS idax)

target_include_directories(idax
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

# idax compiles against SDK headers but does NOT force a link target.
# Consumers bring their own idasdk::plugin / idasdk::idalib / etc.
target_link_libraries(idax PUBLIC idasdk_headers)

# C++23 for idax consumers
target_compile_features(idax PUBLIC cxx_std_23)

# Platform-specific compile options
if(MSVC)
    target_compile_options(idax PRIVATE /W4 /permissive-)
else()
    target_compile_options(idax PRIVATE -Wall -Wextra -Wpedantic)
endif()

# ── Examples (optional) ──────────────────────────────────────────────────
option(IDAX_BUILD_EXAMPLES "Build idax example addons" OFF)
if(IDAX_BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()

# ── Tests (optional) ────────────────────────────────────────────────────
option(IDAX_BUILD_TESTS "Build idax tests" OFF)
if(IDAX_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

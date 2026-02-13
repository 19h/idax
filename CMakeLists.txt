cmake_minimum_required(VERSION 3.27)
project(idax VERSION 0.1.0 LANGUAGES CXX)

# ── Bootstrap ida-cmake ──────────────────────────────────────────────────
# IDASDK may point either to an SDK root that contains `ida-cmake/`, or to
# a GitHub checkout root where SDK contents live under `src/`.
set(IDASDK_BOOTSTRAP_ROOT "$ENV{IDASDK}")

if(NOT IDASDK_BOOTSTRAP_ROOT)
    message(FATAL_ERROR "IDASDK is not set. Set IDASDK to your IDA SDK path.")
endif()

if(EXISTS "${IDASDK_BOOTSTRAP_ROOT}/ida-cmake/bootstrap.cmake")
    set(IDASDK_BOOTSTRAP_FILE "${IDASDK_BOOTSTRAP_ROOT}/ida-cmake/bootstrap.cmake")
elseif(EXISTS "${IDASDK_BOOTSTRAP_ROOT}/cmake/bootstrap.cmake")
    set(IDASDK_BOOTSTRAP_FILE "${IDASDK_BOOTSTRAP_ROOT}/cmake/bootstrap.cmake")
elseif(EXISTS "${IDASDK_BOOTSTRAP_ROOT}/src/ida-cmake/bootstrap.cmake")
    set(IDASDK_BOOTSTRAP_ROOT "${IDASDK_BOOTSTRAP_ROOT}/src")
    set(IDASDK_BOOTSTRAP_FILE "${IDASDK_BOOTSTRAP_ROOT}/ida-cmake/bootstrap.cmake")
elseif(EXISTS "${IDASDK_BOOTSTRAP_ROOT}/src/cmake/bootstrap.cmake")
    set(IDASDK_BOOTSTRAP_ROOT "${IDASDK_BOOTSTRAP_ROOT}/src")
    set(IDASDK_BOOTSTRAP_FILE "${IDASDK_BOOTSTRAP_ROOT}/cmake/bootstrap.cmake")
else()
    message(FATAL_ERROR
        "Could not find ida-cmake bootstrap under IDASDK='${IDASDK_BOOTSTRAP_ROOT}'.\n"
        "Expected one of:\n"
        "  ${IDASDK_BOOTSTRAP_ROOT}/ida-cmake/bootstrap.cmake\n"
        "  ${IDASDK_BOOTSTRAP_ROOT}/cmake/bootstrap.cmake\n"
        "  ${IDASDK_BOOTSTRAP_ROOT}/src/ida-cmake/bootstrap.cmake\n"
        "  ${IDASDK_BOOTSTRAP_ROOT}/src/cmake/bootstrap.cmake")
endif()

set(ENV{IDASDK} "${IDASDK_BOOTSTRAP_ROOT}")
include("${IDASDK_BOOTSTRAP_FILE}")

find_package(idasdk REQUIRED)

if(DEFINED IDASDK AND EXISTS "${IDASDK}/include")
    set(IDAX_SDK_ROOT "${IDASDK}")
elseif(EXISTS "$ENV{IDASDK}/include")
    set(IDAX_SDK_ROOT "$ENV{IDASDK}")
else()
    message(FATAL_ERROR
        "Could not resolve SDK include directory after bootstrap.\n"
        "IDASDK='${IDASDK}', ENV{IDASDK}='$ENV{IDASDK}'.")
endif()

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
        INTERFACE_INCLUDE_DIRECTORIES "${IDAX_SDK_ROOT}/include"
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

# ── Install / packaging ──────────────────────────────────────────────────
include(GNUInstallDirs)

install(TARGETS idax
    EXPORT idaxTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

install(DIRECTORY include/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(FILES
    docs/api_reference.md
    docs/tutorial/first_contact.md
    DESTINATION ${CMAKE_INSTALL_DATADIR}/idax/docs
    OPTIONAL
)

install(EXPORT idaxTargets
    FILE idaxTargets.cmake
    NAMESPACE idax::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/idax
)

include(CMakePackageConfigHelpers)

configure_package_config_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/idaxConfig.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/idaxConfig.cmake"
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/idax
)

write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/idaxConfigVersion.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/idaxConfig.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/idaxConfigVersion.cmake"
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/idax
)

# ── CPack ────────────────────────────────────────────────────────────────
set(CPACK_PACKAGE_NAME "idax")
set(CPACK_PACKAGE_VENDOR "idax")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_PACKAGE_FILE_NAME "idax-${PROJECT_VERSION}-${CMAKE_SYSTEM_NAME}")
set(CPACK_GENERATOR "TGZ")
include(CPack)

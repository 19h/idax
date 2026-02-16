cmake_minimum_required(VERSION 3.27)

project(idax-node LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ── Locate Node.js and NAN ───────────────────────────────────────────────

# cmake-js populates these variables for us
include_directories(${CMAKE_JS_INC})

# Find NAN headers
execute_process(
    COMMAND node -e "require('nan')"
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    RESULT_VARIABLE NAN_CHECK_RESULT
    OUTPUT_QUIET ERROR_QUIET
)
execute_process(
    COMMAND node -e "console.log(require('path').dirname(require.resolve('nan/nan.h')))"
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    OUTPUT_VARIABLE NAN_INCLUDE_DIR
    OUTPUT_STRIP_TRAILING_WHITESPACE
)
if(NAN_INCLUDE_DIR)
    message(STATUS "NAN include dir: ${NAN_INCLUDE_DIR}")
    include_directories(${NAN_INCLUDE_DIR})
else()
    message(FATAL_ERROR "Could not find NAN headers. Run 'npm install' first.")
endif()

# ── Locate idax ──────────────────────────────────────────────────────────

# idax lives two directories up from bindings/node
set(IDAX_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../..")
set(IDAX_INCLUDE_DIR "${IDAX_ROOT}/include")

if(NOT EXISTS "${IDAX_INCLUDE_DIR}/ida/idax.hpp")
    message(FATAL_ERROR "Cannot find idax headers at ${IDAX_INCLUDE_DIR}")
endif()

include_directories(${IDAX_INCLUDE_DIR})

# ── Locate idax static library ───────────────────────────────────────────

# Try the build directory first, then installed locations
set(IDAX_LIB_SEARCH_PATHS
    "${IDAX_ROOT}/build"
    "${IDAX_ROOT}/build/Release"
    "${IDAX_ROOT}/build/Debug"
    "${IDAX_ROOT}/build/RelWithDebInfo"
    "${CMAKE_INSTALL_PREFIX}/lib"
)

find_library(IDAX_LIBRARY
    NAMES idax libidax
    PATHS ${IDAX_LIB_SEARCH_PATHS}
    NO_DEFAULT_PATH
)

if(NOT IDAX_LIBRARY)
    message(WARNING "idax static library not found. The addon will compile but not link until idax is built.")
    set(IDAX_LIBRARY "")
endif()

# ── IDA SDK headers (needed transitively by idax) ────────────────────────

if(DEFINED ENV{IDASDK})
    set(IDASDK_DIR "$ENV{IDASDK}")
    include_directories("${IDASDK_DIR}/include")
    add_compile_definitions(__EA64__)
    message(STATUS "IDA SDK: ${IDASDK_DIR}")
else()
    message(WARNING "IDASDK environment variable not set. Build may fail.")
endif()

# ── idalib link target ──────────────────────────────────────────────────

if(DEFINED ENV{IDADIR})
    set(IDADIR "$ENV{IDADIR}")
elseif(DEFINED ENV{IDASDK})
    # Common: SDK sibling to IDA install
    get_filename_component(IDADIR "$ENV{IDASDK}/.." ABSOLUTE)
endif()

if(IDADIR)
    if(APPLE)
        find_library(IDALIB_LIBRARY
            NAMES ida libida ida64 libida64
            PATHS "${IDADIR}" "${IDADIR}/lib"
            NO_DEFAULT_PATH
        )
    elseif(UNIX)
        find_library(IDALIB_LIBRARY
            NAMES ida ida64
            PATHS "${IDADIR}" "${IDADIR}/lib"
            NO_DEFAULT_PATH
        )
    endif()
endif()

# ── Native addon target ─────────────────────────────────────────────────

set(BINDING_SOURCES
    src/addon.cpp
    src/helpers.cpp
    src/database_bind.cpp
    src/address_bind.cpp
    src/segment_bind.cpp
    src/function_bind.cpp
    src/instruction_bind.cpp
    src/name_bind.cpp
    src/xref_bind.cpp
    src/comment_bind.cpp
    src/data_bind.cpp
    src/search_bind.cpp
    src/analysis_bind.cpp
    src/type_bind.cpp
    src/entry_bind.cpp
    src/fixup_bind.cpp
    src/event_bind.cpp
    src/storage_bind.cpp
    src/diagnostics_bind.cpp
    src/lumina_bind.cpp
    src/lines_bind.cpp
    src/decompiler_bind.cpp
)

add_library(${PROJECT_NAME} SHARED ${BINDING_SOURCES})

set_target_properties(${PROJECT_NAME} PROPERTIES
    PREFIX ""
    SUFFIX ".node"
    OUTPUT_NAME "idax_native"
)

target_include_directories(${PROJECT_NAME} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(${PROJECT_NAME} PRIVATE ${CMAKE_JS_LIB})

if(IDAX_LIBRARY)
    target_link_libraries(${PROJECT_NAME} PRIVATE ${IDAX_LIBRARY})
endif()

if(IDALIB_LIBRARY)
    target_link_libraries(${PROJECT_NAME} PRIVATE ${IDALIB_LIBRARY})
endif()

# Compiler warnings
if(CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
    target_compile_options(${PROJECT_NAME} PRIVATE -Wall -Wextra -Wpedantic)
elseif(MSVC)
    target_compile_options(${PROJECT_NAME} PRIVATE /W4 /permissive-)
endif()

# Suppress NAN deprecation warnings on newer V8
target_compile_definitions(${PROJECT_NAME} PRIVATE
    V8_REVERSE_JSARGS=1
    BUILDING_NODE_EXTENSION
)

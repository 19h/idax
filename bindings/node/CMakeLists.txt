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

# ── IDA installation (runtime dylibs) ────────────────────────────────────
#
# The IDA SDK ships stub dylibs with different symbol exports than the real
# IDA runtime dylibs. On macOS with two-level namespace linking, this causes
# symbols (like callui, qvector_reserve) to be bound to the wrong dylib,
# resulting in null-pointer crashes at runtime. We MUST link against the
# real IDA dylibs from the installation for correct symbol resolution.
#
# The addon needs both:
#   - libidalib.dylib  (idalib entry points: open_database, etc.)
#   - libida.dylib     (IDA kernel symbols: callui, add_func_ex, etc.)

if(DEFINED ENV{IDADIR})
    set(IDA_INSTALL_DIR "$ENV{IDADIR}")
elseif(APPLE)
    # Try common macOS locations.
    foreach(_ver 9.3 9.2 9.1 9.0)
        set(_try "/Applications/IDA Professional ${_ver}.app/Contents/MacOS")
        if(EXISTS "${_try}/libidalib.dylib")
            set(IDA_INSTALL_DIR "${_try}")
            break()
        endif()
    endforeach()
    # Also check the hexrays development build.
    if(NOT IDA_INSTALL_DIR)
        set(_dev_try "$ENV{HOME}/hexrays/ida/bin/arm64_mac_clang_opt/ida.app/Contents/MacOS")
        if(EXISTS "${_dev_try}/libidalib.dylib")
            set(IDA_INSTALL_DIR "${_dev_try}")
        endif()
    endif()
endif()

if(NOT IDA_INSTALL_DIR)
    message(WARNING "IDA installation not found. Set IDADIR environment variable.\n"
                    "The addon will compile but fail to load at runtime.")
else()
    message(STATUS "IDA installation: ${IDA_INSTALL_DIR}")
endif()

# Locate the two required dylibs.
if(IDA_INSTALL_DIR)
    find_library(IDALIB_LIBRARY
        NAMES idalib libidalib
        PATHS "${IDA_INSTALL_DIR}"
        NO_DEFAULT_PATH
    )
    find_library(LIBIDA_LIBRARY
        NAMES ida libida
        PATHS "${IDA_INSTALL_DIR}"
        NO_DEFAULT_PATH
    )

    if(IDALIB_LIBRARY)
        message(STATUS "idalib: ${IDALIB_LIBRARY}")
    else()
        message(WARNING "libidalib.dylib not found in ${IDA_INSTALL_DIR}")
    endif()
    if(LIBIDA_LIBRARY)
        message(STATUS "libida: ${LIBIDA_LIBRARY}")
    else()
        message(WARNING "libida.dylib not found in ${IDA_INSTALL_DIR}")
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

# Link against the real IDA dylibs for symbol resolution.
if(IDALIB_LIBRARY)
    target_link_libraries(${PROJECT_NAME} PRIVATE ${IDALIB_LIBRARY})
endif()
if(LIBIDA_LIBRARY)
    target_link_libraries(${PROJECT_NAME} PRIVATE ${LIBIDA_LIBRARY})
endif()

# idalib definition — idax uses this to select idalib-specific code paths.
target_compile_definitions(${PROJECT_NAME} PRIVATE IDALIB_IMPL)

# Set rpath so the addon can find IDA dylibs at runtime.
if(APPLE AND IDA_INSTALL_DIR)
    set_target_properties(${PROJECT_NAME} PROPERTIES
        BUILD_RPATH "${IDA_INSTALL_DIR}"
        INSTALL_RPATH "${IDA_INSTALL_DIR}"
    )
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

cmake_minimum_required(VERSION 3.27)

find_package(Python 3.10 COMPONENTS Interpreter Development.Module REQUIRED)
find_package(pybind11 3 CONFIG REQUIRED)

set(IDAX_PYTHON_SOURCES
    src/native/module.cpp
    src/native/common.cpp
    src/native/core_bind.cpp
    src/native/address_bind.cpp
    src/native/database_bind.cpp
    src/native/path_bind.cpp
    src/native/analysis_bind.cpp
    src/native/undo_bind.cpp
    src/native/problem_bind.cpp
    src/native/bookmark_bind.cpp
    src/native/navigation_bind.cpp
    src/native/exception_bind.cpp
    src/native/parser_bind.cpp
    src/native/directory_bind.cpp
    src/native/registry_bind.cpp
    src/native/registers_bind.cpp
    src/native/diagnostics_bind.cpp
    src/native/comment_bind.cpp
    src/native/entry_bind.cpp
    src/native/name_bind.cpp
    src/native/search_bind.cpp
    src/native/segment_bind.cpp
    src/native/xref_bind.cpp
    src/native/offset_bind.cpp
    src/native/lines_bind.cpp
    src/native/lumina_bind.cpp
    src/native/type_bind.cpp
    src/native/fixup_bind.cpp
    src/native/function_bind.cpp
    src/native/instruction_bind.cpp
    src/native/storage_bind.cpp
    src/native/event_bind.cpp
    src/native/data_bind.cpp
    src/native/debugger_bind.cpp
    src/native/graph_bind.cpp
    src/native/decompiler_bind.cpp
    src/native/decompiler_microcode_bind.cpp
    src/native/decompiler_ctree_bind.cpp
    src/native/plugin_bind.cpp
    src/native/loader_bind.cpp
    src/native/processor_bind.cpp
    src/native/ui_bind.cpp
    src/native/ui_events_bind.cpp
)

pybind11_add_module(idax_python_native MODULE NO_EXTRAS ${IDAX_PYTHON_SOURCES})
set_target_properties(idax_python_native PROPERTIES
    OUTPUT_NAME "_native"
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON
    INTERPROCEDURAL_OPTIMIZATION FALSE
)

target_compile_features(idax_python_native PRIVATE cxx_std_23)
target_include_directories(idax_python_native PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/src/native"
)
target_link_libraries(idax_python_native PRIVATE idax::idax)

if(MSVC)
    target_compile_options(idax_python_native PRIVATE /W4 /permissive- /Zc:__cplusplus)
    target_compile_definitions(idax_python_native PRIVATE NOMINMAX)
else()
    target_compile_options(idax_python_native PRIVATE -Wall -Wextra -Wpedantic)
endif()

# The IDA runtime is supplied by the user and is intentionally never bundled
# into the Python wheel. IDADIR should name the directory containing libida
# and libidalib (or the corresponding Windows import libraries).
set(IDAX_PYTHON_IDA_RUNTIME_DIR "$ENV{IDADIR}" CACHE PATH
    "Directory containing the installed IDA runtime libraries")

if(NOT IDAX_PYTHON_IDA_RUNTIME_DIR AND APPLE)
    foreach(_version 9.4)
        set(_candidate "/Applications/IDA Professional ${_version}.app/Contents/MacOS")
        if(EXISTS "${_candidate}/libida.dylib"
           AND EXISTS "${_candidate}/libidalib.dylib")
            set(IDAX_PYTHON_IDA_RUNTIME_DIR "${_candidate}")
            break()
        endif()
    endforeach()
endif()

if(WIN32)
    set(_idax_python_library_dirs)
    if(IDAX_SDK_ROOT)
        get_filename_component(_idax_sdk_parent "${IDAX_SDK_ROOT}" DIRECTORY)
        list(APPEND _idax_python_library_dirs
            "${IDAX_SDK_ROOT}/lib/x64_win_64"
            "${IDAX_SDK_ROOT}/lib/x64_win_64_s"
            "${_idax_sdk_parent}/lib/x64_win_64"
            "${_idax_sdk_parent}/lib/x64_win_64_s")
    endif()
    if(IDAX_PYTHON_IDA_RUNTIME_DIR)
        list(APPEND _idax_python_library_dirs
            "${IDAX_PYTHON_IDA_RUNTIME_DIR}"
            "${IDAX_PYTHON_IDA_RUNTIME_DIR}/lib")
    endif()

    find_library(IDAX_PYTHON_IDA_LIBRARY NAMES ida ida64
        PATHS ${_idax_python_library_dirs} NO_DEFAULT_PATH)
    find_library(IDAX_PYTHON_IDALIB_LIBRARY NAMES idalib
        PATHS ${_idax_python_library_dirs} NO_DEFAULT_PATH)
    find_library(IDAX_PYTHON_PRO_LIBRARY NAMES pro
        PATHS ${_idax_python_library_dirs} NO_DEFAULT_PATH)

    if(NOT IDAX_PYTHON_IDA_LIBRARY
       OR NOT IDAX_PYTHON_IDALIB_LIBRARY
       OR NOT IDAX_PYTHON_PRO_LIBRARY)
        message(FATAL_ERROR
            "Python binding requires ida, idalib, and pro import libraries. "
            "Set IDADIR or IDAX_PYTHON_IDA_RUNTIME_DIR.")
    endif()
    target_link_libraries(idax_python_native PRIVATE
        "${IDAX_PYTHON_IDA_LIBRARY}"
        "${IDAX_PYTHON_IDALIB_LIBRARY}"
        "${IDAX_PYTHON_PRO_LIBRARY}")
else()
    if(NOT IDAX_PYTHON_IDA_RUNTIME_DIR)
        message(FATAL_ERROR
            "Python binding requires an installed IDA runtime. Set IDADIR or "
            "IDAX_PYTHON_IDA_RUNTIME_DIR to its library directory.")
    endif()

    find_library(IDAX_PYTHON_IDA_LIBRARY NAMES ida libida
        PATHS "${IDAX_PYTHON_IDA_RUNTIME_DIR}" NO_DEFAULT_PATH REQUIRED)
    find_library(IDAX_PYTHON_IDALIB_LIBRARY NAMES idalib libidalib
        PATHS "${IDAX_PYTHON_IDA_RUNTIME_DIR}" NO_DEFAULT_PATH REQUIRED)
    target_link_libraries(idax_python_native PRIVATE
        "${IDAX_PYTHON_IDA_LIBRARY}"
        "${IDAX_PYTHON_IDALIB_LIBRARY}")
endif()

install(TARGETS idax_python_native
    LIBRARY DESTINATION idax
        COMPONENT python
    RUNTIME DESTINATION idax
        COMPONENT python
    ARCHIVE DESTINATION idax
        COMPONENT python
)

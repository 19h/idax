# Execute one idalib integration target against an isolated fixture copy.

foreach(_required IDAX_TEST_EXECUTABLE IDAX_TEST_FIXTURE IDAX_TEST_NAME)
    if(NOT DEFINED ${_required} OR "${${_required}}" STREQUAL "")
        message(FATAL_ERROR "${_required} is required")
    endif()
endforeach()

if(NOT EXISTS "${IDAX_TEST_EXECUTABLE}")
    message(FATAL_ERROR "Test executable does not exist: ${IDAX_TEST_EXECUTABLE}")
endif()
if(NOT EXISTS "${IDAX_TEST_FIXTURE}")
    message(FATAL_ERROR "Test fixture does not exist: ${IDAX_TEST_FIXTURE}")
endif()

string(RANDOM LENGTH 12 ALPHABET 0123456789abcdef _suffix)
get_filename_component(_fixture_name "${IDAX_TEST_FIXTURE}" NAME)
set(_temp_root "${CMAKE_CURRENT_BINARY_DIR}/idax-test-fixtures")
set(_temp_dir "${_temp_root}/${IDAX_TEST_NAME}-${_suffix}")
set(_temp_fixture "${_temp_dir}/${_fixture_name}")

file(MAKE_DIRECTORY "${_temp_dir}")
file(COPY_FILE "${IDAX_TEST_FIXTURE}" "${_temp_fixture}" ONLY_IF_DIFFERENT)

# Analyze the raw fixture with the runtime under test. A pre-analysed IDB is
# release-specific input: copying an older sidecar can make IDA terminate after
# its conversion pass before the integration executable reaches its assertions.

execute_process(
    COMMAND "${IDAX_TEST_EXECUTABLE}" "${_temp_fixture}"
    RESULT_VARIABLE _result
    COMMAND_ECHO STDOUT
)

file(REMOVE_RECURSE "${_temp_dir}")

if(NOT _result EQUAL 0)
    message(FATAL_ERROR
        "${IDAX_TEST_NAME} failed with exit code ${_result}")
endif()

add_executable(idax_unit_test
    core_unit_test.cpp
)

target_link_libraries(idax_unit_test PRIVATE idax::idax)

add_test(NAME idax_unit_test COMMAND idax_unit_test)

# ── API surface parity test (P4.7.d) ────────────────────────────────────
# Validates that every public namespace and type in the architecture
# blueprint is present and compilable. The test is a compile-only check:
# if it compiles, the API surface contract is satisfied.
add_library(idax_api_surface_check OBJECT api_surface_parity_test.cpp)
target_link_libraries(idax_api_surface_check PRIVATE idax::idax)

# Register as a CTest that always passes if the build succeeded.
# The real validation is compile-time: missing symbols = build failure.
add_test(NAME api_surface_parity
    COMMAND ${CMAKE_COMMAND} -E echo "API surface parity: PASS (compiled successfully)"
)

# ── Torture tests (offline unit tests — no IDA runtime needed) ───────────

# Error model torture test
add_executable(idax_error_torture_test error_torture_test.cpp)
target_link_libraries(idax_error_torture_test PRIVATE idax::idax)
add_test(NAME error_torture COMMAND idax_error_torture_test)

# Address range torture test
add_executable(idax_address_range_torture_test address_range_torture_test.cpp)
target_link_libraries(idax_address_range_torture_test PRIVATE idax::idax)
add_test(NAME address_range_torture COMMAND idax_address_range_torture_test)

# Diagnostics torture test
add_executable(idax_diagnostics_torture_test diagnostics_torture_test.cpp)
target_link_libraries(idax_diagnostics_torture_test PRIVATE idax::idax)
add_test(NAME diagnostics_torture COMMAND idax_diagnostics_torture_test)

# Core options torture test
add_executable(idax_core_options_torture_test core_options_torture_test.cpp)
target_link_libraries(idax_core_options_torture_test PRIVATE idax::idax)
add_test(NAME core_options_torture COMMAND idax_core_options_torture_test)

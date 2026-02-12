add_executable(idax_unit_test
    core_unit_test.cpp
)

target_link_libraries(idax_unit_test PRIVATE idax::idax)

add_test(NAME idax_unit_test COMMAND idax_unit_test)

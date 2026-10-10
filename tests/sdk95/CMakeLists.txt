if(NOT IDAX_IDA_SDK_VERSION STREQUAL "950")
    message(FATAL_ERROR "The native SDK 9.5 producers require actual SDK 950")
endif()

if(APPLE)
    add_executable(idax_sdk95_member_producer member_offset_producer.cpp)
    target_link_libraries(idax_sdk95_member_producer PRIVATE idax::idax
        "$ENV{IDADIR}/libidalib.dylib" "$ENV{IDADIR}/libida.dylib")
    set_target_properties(idax_sdk95_member_producer PROPERTIES BUILD_RPATH "$ENV{IDADIR}")
else()
    ida_add_idalib(idax_sdk95_member_producer TYPE EXECUTABLE
        SOURCES member_offset_producer.cpp LIBRARIES idax::idax)
endif()
target_include_directories(idax_sdk95_member_producer PRIVATE "${IDAX_SDK_ROOT}/include")
idax_remap_build_paths(idax_sdk95_member_producer)

add_executable(idax_sdk95_member_fixture ../fixtures/member_offsets95_host.cpp)
if(MSVC)
    target_compile_options(idax_sdk95_member_fixture PRIVATE /O1 /Ob0)
else()
    target_compile_options(idax_sdk95_member_fixture PRIVATE -O1 -fno-inline)
endif()
idax_remap_build_paths(idax_sdk95_member_fixture)

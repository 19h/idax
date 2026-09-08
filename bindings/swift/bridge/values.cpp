#include "values.h"
#include "support.hpp"
#include <ida/search.hpp>
#include <ida/type.hpp>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <stdexcept>
#include <vector>

extern "C" void idax_swift_free_array(void* array) { std::free(array); }

namespace {
char* copy_string(const std::string& value) {
    auto* result = static_cast<char*>(std::malloc(value.size() + 1));
    if (result == nullptr) throw std::bad_alloc();
    std::memcpy(result, value.c_str(), value.size() + 1);
    return result;
}
int invalid(IdaxSwiftError* error, const char* message) {
    return idax::swift::write_error(ida::Error::validation(message), error);
}
template <typename T>
void require_array(const T* values, std::size_t count) {
    if ((count != 0 && values == nullptr) || count > SIZE_MAX / sizeof(T))
        throw ida::Error::validation("Invalid input array extent");
}
ida::type::TypeRenderOptions render_options(const IdaxSwiftTypeRenderOptions* value) {
    ida::type::TypeRenderOptions result;
    if (value == nullptr) return result;
    result.size_comments = value->size_comments != 0;
    result.trim_unreferenced = value->trim_unreferenced != 0;
    require_array(value->used_offsets, value->used_offset_count);
    for (std::size_t i = 0; i < value->used_offset_count; ++i) {
        const auto& input = value->used_offsets[i];
        require_array(input.byte_offsets, input.offset_count);
        if (input.type_name == nullptr) throw ida::Error::validation("Type name is null");
        ida::type::UsedMemberOffsets offsets;
        offsets.type_name = input.type_name;
        if (input.offset_count != 0)
            offsets.byte_offsets.assign(input.byte_offsets, input.byte_offsets + input.offset_count);
        result.used_offsets.push_back(std::move(offsets));
    }
    return result;
}
template <typename Options>
Options search_options(const IdaxSwiftSearchOptions* value) {
    Options result;
    if (value == nullptr) return result;
    if (value->direction < 0 || value->direction > 1)
        throw ida::Error::validation("Invalid search direction");
    result.direction = static_cast<ida::search::Direction>(value->direction);
    result.skip_start = value->skip_start != 0;
    result.no_break = value->no_break != 0;
    result.no_show = value->no_show != 0;
    result.break_on_cancel = value->break_on_cancel != 0;
    return result;
}
template <typename Value>
int take_result(ida::Result<Value> result, Value* output, IdaxSwiftError* error) {
    if (!result) return idax::swift::write_error(result.error(), error);
    *output = std::move(*result);
    return 0;
}
int take_string(ida::Result<std::string> result, char** output, IdaxSwiftError* error) {
    if (!result) return idax::swift::write_error(result.error(), error);
    *output = copy_string(*result);
    return 0;
}
}
extern "C" int idax_swift_search_text(const char* query, uint64_t start, const IdaxSwiftSearchOptions* input, uint64_t* output, IdaxSwiftError* error) {
    if (output != nullptr) *output = 0;
    return idax::swift::protect(error, [&] {
        if (idax::swift::require_runtime_thread(error) != 0) return -1;
        if (query == nullptr || output == nullptr) return invalid(error, "Null text search input/output");
        auto options = search_options<ida::search::TextOptions>(input);
        if (input != nullptr) {
            options.case_sensitive = input->case_sensitive != 0;
            options.regex = input->regex != 0;
            options.identifier = input->identifier != 0;
        }
        return take_result(ida::search::text(query, start, options), output, error);
    });
}
extern "C" int idax_swift_search_immediate(uint64_t value, uint64_t start, const IdaxSwiftSearchOptions* input, uint64_t* output, IdaxSwiftError* error) {
    if (output != nullptr) *output = 0;
    return idax::swift::protect(error, [&] {
        if (idax::swift::require_runtime_thread(error) != 0) return -1;
        if (output == nullptr) return invalid(error, "Null immediate search output");
        return take_result(ida::search::immediate(value, start, search_options<ida::search::ImmediateOptions>(input)), output, error);
    });
}
extern "C" int idax_swift_search_binary(const char* pattern, uint64_t start, const IdaxSwiftSearchOptions* input, uint64_t* output, IdaxSwiftError* error) {
    if (output != nullptr) *output = 0;
    return idax::swift::protect(error, [&] {
        if (idax::swift::require_runtime_thread(error) != 0) return -1;
        if (pattern == nullptr || output == nullptr) return invalid(error, "Null binary search input/output");
        return take_result(ida::search::binary_pattern(pattern, start, search_options<ida::search::BinaryPatternOptions>(input)), output, error);
    });
}
extern "C" int idax_swift_type_render_named(const char* const* names, size_t count, int max_depth, const IdaxSwiftTypeRenderOptions* input, char** output, IdaxSwiftError* error) {
    if (output != nullptr) *output = nullptr;
    return idax::swift::protect(error, [&] {
        if (idax::swift::require_runtime_thread(error) != 0) return -1;
        if (output == nullptr) return invalid(error, "Null type rendering output");
        require_array(names, count);
        std::vector<std::string> values;
        for (std::size_t i = 0; i < count; ++i) {
            if (names[i] == nullptr) return invalid(error, "Null type name");
            values.emplace_back(names[i]);
        }
        return take_string(ida::type::render_named_declarations(values, max_depth, render_options(input)), output, error);
    });
}
extern "C" int idax_swift_type_render_ordinals(const uint32_t* ordinals, size_t count, const IdaxSwiftTypeRenderOptions* input, char** output, IdaxSwiftError* error) {
    if (output != nullptr) *output = nullptr;
    return idax::swift::protect(error, [&] {
        if (idax::swift::require_runtime_thread(error) != 0) return -1;
        if (output == nullptr) return invalid(error, "Null type rendering output");
        require_array(ordinals, count);
        std::vector<std::uint32_t> values;
        if (count != 0) values.assign(ordinals, ordinals + count);
        return take_string(ida::type::render_ordinal_declarations(values, render_options(input)), output, error);
    });
}
extern "C" int idax_swift_type_render_graph(const char* name, int mode, int max_depth, int include_enums, int include_typedefs, char** output, IdaxSwiftError* error) {
    if (output != nullptr) *output = nullptr;
    return idax::swift::protect(error, [&] {
        if (idax::swift::require_runtime_thread(error) != 0) return -1;
        if (name == nullptr || output == nullptr) return invalid(error, "Null type graph input/output");
        if (mode < 0 || mode > 1) return invalid(error, "Invalid type graph mode");
        ida::type::TypeGraphOptions options;
        options.mode = static_cast<ida::type::TypeGraphOptions::Mode>(mode);
        options.max_depth = max_depth;
        options.include_enums = include_enums != 0;
        options.include_typedefs = include_typedefs != 0;
        return take_string(ida::type::render_type_graph(name, options), output, error);
    });
}
extern "C" void idax_swift_type_declarations_free(IdaxSwiftTypeDeclaration* values, size_t count) {
    if (values == nullptr) return;
    for (std::size_t i = 0; i < count; ++i) { std::free(values[i].name); std::free(values[i].declaration); }
    std::free(values);
}
extern "C" int idax_swift_type_declarations(const uint32_t* ordinals, size_t count, IdaxSwiftTypeDeclaration** output, size_t* output_count, IdaxSwiftError* error) {
    if (output != nullptr) *output = nullptr;
    if (output_count != nullptr) *output_count = 0;
    return idax::swift::protect(error, [&] {
        if (idax::swift::require_runtime_thread(error) != 0) return -1;
        if (output == nullptr || output_count == nullptr) return invalid(error, "Null declaration output");
        require_array(ordinals, count);
        std::vector<std::uint32_t> values;
        if (count != 0) values.assign(ordinals, ordinals + count);
        auto result = ida::type::declarations_for_ordinals(values);
        if (!result) return idax::swift::write_error(result.error(), error);
        if (result->empty()) return 0;
        auto release = [size = result->size()](IdaxSwiftTypeDeclaration* pointer) { idax_swift_type_declarations_free(pointer, size); };
        std::unique_ptr<IdaxSwiftTypeDeclaration, decltype(release)> records(
            static_cast<IdaxSwiftTypeDeclaration*>(std::calloc(result->size(), sizeof(IdaxSwiftTypeDeclaration))), release);
        if (!records) throw std::bad_alloc();
        for (std::size_t i = 0; i < result->size(); ++i) {
            records.get()[i].ordinal = (*result)[i].ordinal;
            records.get()[i].name = copy_string((*result)[i].name);
            records.get()[i].declaration = copy_string((*result)[i].declaration);
        }
        *output_count = result->size();
        *output = records.release();
        return 0;
    });
}

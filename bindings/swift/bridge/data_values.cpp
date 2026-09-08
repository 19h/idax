#include "data_values.h"
#include "support.hpp"
#include <ida/data.hpp>
#include <ida/type.hpp>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <memory>

namespace {
using idax::swift::protect;
using idax::swift::require_runtime_thread;
using idax::swift::write_error;
constexpr size_t maximum_depth = 64; // Matches the canonical typed-value limit.

void checked_extent(const void* pointer, size_t count, size_t stride) {
    if ((count != 0 && pointer == nullptr) || count > SIZE_MAX / stride)
        throw ida::Error::validation("Invalid typed-value array extent");
}
uint8_t* copy_bytes(const void* bytes, size_t count) {
    if (count == 0) return nullptr;
    auto* output = static_cast<uint8_t*>(std::malloc(count));
    if (output == nullptr) throw std::bad_alloc();
    std::memcpy(output, bytes, count);
    return output;
}
void fill(const ida::data::TypedValue& value, IdaxSwiftDataValue& output, size_t depth = 0) {
    if (depth > maximum_depth) throw ida::Error::internal("Native typed-value depth exceeds the supported limit");
    output.kind = static_cast<int>(value.kind);
    output.unsigned_value = value.unsigned_value;
    output.signed_value = value.signed_value;
    output.floating_value = value.floating_value;
    output.pointer_value = value.pointer_value;
    output.text = copy_bytes(value.string_value.data(), value.string_value.size());
    output.text_count = value.string_value.size();
    output.bytes = copy_bytes(value.bytes.data(), value.bytes.size());
    output.byte_count = value.bytes.size();
    if (!value.elements.empty()) {
        if (value.elements.size() > SIZE_MAX / sizeof(IdaxSwiftDataValue)) throw std::bad_alloc();
        auto* elements = static_cast<IdaxSwiftDataValue*>(std::calloc(value.elements.size(), sizeof(IdaxSwiftDataValue)));
        if (elements == nullptr) throw std::bad_alloc();
        output.elements = elements;
        output.element_count = value.elements.size();
        for (size_t i = 0; i < value.elements.size(); ++i) fill(value.elements[i], elements[i], depth + 1);
    }
}
ida::data::TypedValue decode(const IdaxSwiftDataValue& value, size_t depth = 0) {
    if (depth > maximum_depth) throw ida::Error::validation("Maximum typed-value recursion depth exceeded");
    if (value.kind < 0 || value.kind > static_cast<int>(ida::data::TypedValueKind::Array))
        throw ida::Error::validation("Invalid typed-value kind");
    checked_extent(value.text, value.text_count, 1);
    checked_extent(value.bytes, value.byte_count, 1);
    checked_extent(value.elements, value.element_count, sizeof(IdaxSwiftDataValue));
    ida::data::TypedValue output;
    output.kind = static_cast<ida::data::TypedValueKind>(value.kind);
    output.unsigned_value = value.unsigned_value;
    output.signed_value = value.signed_value;
    output.floating_value = value.floating_value;
    output.pointer_value = value.pointer_value;
    if (value.text_count) output.string_value.assign(reinterpret_cast<const char*>(value.text), value.text_count);
    if (value.byte_count) output.bytes.assign(value.bytes, value.bytes + value.byte_count);
    output.elements.reserve(value.element_count);
    for (size_t i = 0; i < value.element_count; ++i) output.elements.push_back(decode(value.elements[i], depth + 1));
    return output;
}
}

void idax_swift_data_value_free(IdaxSwiftDataValue* value) {
    if (value == nullptr) return;
    std::free(const_cast<uint8_t*>(value->text));
    std::free(const_cast<uint8_t*>(value->bytes));
    auto* elements = const_cast<IdaxSwiftDataValue*>(value->elements);
    for (size_t i = 0; i < value->element_count; ++i) idax_swift_data_value_free(&elements[i]);
    std::free(elements);
    *value = {};
}
int idax_swift_data_read_typed(uint64_t address, void* type, IdaxSwiftDataValue* output, IdaxSwiftError* error) {
    if (output) *output = {};
    return protect(error, [&] {
        if (!type || !output) return write_error(ida::Error::validation("Typed read type or output is null"), error);
        if (require_runtime_thread(error)) return -1;
        auto result = ida::data::read_typed(address, *static_cast<ida::type::TypeInfo*>(type));
        if (!result) return write_error(result.error(), error);
        try { fill(*result, *output); }
        catch (...) { idax_swift_data_value_free(output); throw; }
        return 0;
    });
}
int idax_swift_data_write_typed(uint64_t address, void* type, const IdaxSwiftDataValue* value, IdaxSwiftError* error) {
    return protect(error, [&] {
        if (!type || !value) return write_error(ida::Error::validation("Typed write type or value is null"), error);
        if (require_runtime_thread(error)) return -1;
        auto result = ida::data::write_typed(address, *static_cast<ida::type::TypeInfo*>(type), decode(*value));
        return result ? 0 : write_error(result.error(), error);
    });
}
int idax_swift_data_read_string(uint64_t address, uint64_t maximum_length, int32_t string_type,
    int conversion_flags, uint8_t** bytes, size_t* count, IdaxSwiftError* error) {
    if (bytes) *bytes = nullptr;
    if (count) *count = 0;
    return protect(error, [&] {
        if (!bytes || !count) return write_error(ida::Error::validation("String outputs are null"), error);
        if (require_runtime_thread(error)) return -1;
        auto result = ida::data::read_string(address, maximum_length, string_type, conversion_flags);
        if (!result) return write_error(result.error(), error);
        *bytes = copy_bytes(result->data(), result->size());
        *count = result->size();
        return 0;
    });
}
int idax_swift_data_find_binary_pattern(uint64_t start, uint64_t end, const char* pattern,
    int forward, int skip_start, int case_sensitive, int radix, int string_literal_encoding,
    uint64_t* output, IdaxSwiftError* error) {
    if (output) *output = ida::BadAddress;
    return protect(error, [&] {
        if (!pattern || !output) return write_error(ida::Error::validation("Binary pattern input or output is null"), error);
        if (require_runtime_thread(error)) return -1;
        auto result = ida::data::find_binary_pattern(start, end, pattern, forward != 0, skip_start != 0,
                                                     case_sensitive != 0, radix, string_literal_encoding);
        if (!result) return write_error(result.error(), error);
        *output = *result;
        return 0;
    });
}

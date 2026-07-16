/// \file data.cpp
/// \brief Implementation of ida::data — read, write, patch, define operations.

#include "detail/sdk_bridge.hpp"
#include "detail/type_impl.hpp"
#include <ida/data.hpp>
#include <ida/type.hpp>

#include <search.hpp>

#include <algorithm>
#include <bit>
#include <limits>
#include <map>
#include <memory>

namespace ida::data {

namespace {

constexpr std::size_t kMaxTypedDepth = 64;
constexpr int kMaximumCustomDataId =
    static_cast<int>(std::numeric_limits<std::uint16_t>::max()) - 1;

Status validate_definition_count(Address address, AddressSize count) {
    if (count != 0)
        return ida::ok();
    return std::unexpected(Error::validation(
        "Definition element count must be greater than zero",
        "address=" + std::to_string(address) + ", count=0"));
}

Result<asize_t> checked_definition_length(Address address,
                                          AddressSize count,
                                          AddressSize element_width) {
    auto valid_count = validate_definition_count(address, count);
    if (!valid_count)
        return std::unexpected(valid_count.error());
    const std::string context = "address=" + std::to_string(address)
        + ", count=" + std::to_string(count)
        + ", element_width=" + std::to_string(element_width);
    if (count > std::numeric_limits<AddressSize>::max() / element_width) {
        return std::unexpected(Error::validation(
            "Definition byte length overflow", context));
    }

    const AddressSize byte_length = count * element_width;
    if (byte_length > std::numeric_limits<asize_t>::max()) {
        return std::unexpected(Error::validation(
            "Definition length exceeds SDK size range", context));
    }
    if (byte_length > BadAddress - address) {
        return std::unexpected(Error::validation(
            "Definition address range overflow", context));
    }
    return static_cast<asize_t>(byte_length);
}

template <typename Create>
Status define_fixed_width(Address address,
                          AddressSize count,
                          AddressSize element_width,
                          const char* sdk_operation,
                          Create create) {
    auto byte_length = checked_definition_length(address, count, element_width);
    if (!byte_length)
        return std::unexpected(byte_length.error());
    if (!create(address, *byte_length)) {
        return std::unexpected(Error::sdk(
            std::string(sdk_operation) + " failed", std::to_string(address)));
    }
    return ida::ok();
}

Result<AddressSize> extended_real_element_size(bool packed_real) {
    const processor_t* processor = ::get_ph();
    const asm_t* assembler = ::get_ash();
    const char* kind = packed_real ? "packed real" : "tbyte";
    if (processor == nullptr || assembler == nullptr) {
        return std::unexpected(Error::unsupported(
            std::string(kind) + " metadata is unavailable"));
    }

    const char* directive = packed_real ? assembler->a_packreal
                                        : assembler->a_tbyte;
    if (directive == nullptr || directive[0] == '\0'
        || processor->tbyte_size == 0) {
        return std::unexpected(Error::unsupported(
            std::string(kind) + " is unavailable for the active processor/assembler"));
    }
    return static_cast<AddressSize>(processor->tbyte_size);
}

struct RegisteredCustomDataType {
    int id{-1};
    CustomDataTypeDefinition definition;
    data_type_t sdk{};
};

struct RegisteredCustomDataFormat {
    int id{-1};
    CustomDataFormatDefinition definition;
    data_format_t sdk{};
};

std::map<int, std::shared_ptr<RegisteredCustomDataType>>
    g_custom_data_types;
std::map<int, std::shared_ptr<RegisteredCustomDataFormat>>
    g_custom_data_formats;

std::shared_ptr<RegisteredCustomDataType> retain_custom_data_type(
        RegisteredCustomDataType* registration) {
    if (registration == nullptr || registration->id <= 0)
        return {};
    auto found = g_custom_data_types.find(registration->id);
    if (found == g_custom_data_types.end()
        || found->second.get() != registration) {
        return {};
    }
    return found->second;
}

std::shared_ptr<RegisteredCustomDataFormat> retain_custom_data_format(
        RegisteredCustomDataFormat* registration) {
    if (registration == nullptr || registration->id <= 0)
        return {};
    auto found = g_custom_data_formats.find(registration->id);
    if (found == g_custom_data_formats.end()
        || found->second.get() != registration) {
        return {};
    }
    return found->second;
}

bool idaapi custom_data_may_create_at(void* user_data,
                                      ea_t address,
                                      size_t byte_length) noexcept {
    auto registration = retain_custom_data_type(
        static_cast<RegisteredCustomDataType*>(user_data));
    if (!registration || !registration->definition.may_create_at)
        return false;
    try {
        return registration->definition.may_create_at(
            static_cast<Address>(address),
            static_cast<AddressSize>(byte_length));
    } catch (...) {
        return false;
    }
}

asize_t idaapi custom_data_calculate_size(void* user_data,
                                          ea_t address,
                                          asize_t maximum_size) noexcept {
    auto registration = retain_custom_data_type(
        static_cast<RegisteredCustomDataType*>(user_data));
    if (!registration || !registration->definition.calculate_size)
        return 0;
    try {
        const AddressSize size = registration->definition.calculate_size(
            static_cast<Address>(address),
            static_cast<AddressSize>(maximum_size));
        if (size == 0 || size > static_cast<AddressSize>(maximum_size)
            || size > std::numeric_limits<asize_t>::max()) {
            return 0;
        }
        return static_cast<asize_t>(size);
    } catch (...) {
        return 0;
    }
}

bool idaapi custom_data_render(void* user_data,
                               qstring* output,
                               const void* value,
                               asize_t size,
                               ea_t address,
                               int operand_index,
                               int type_id) noexcept {
    auto registration = retain_custom_data_format(
        static_cast<RegisteredCustomDataFormat*>(user_data));
    if (!registration || !registration->definition.render || value == nullptr)
        return false;
    try {
        CustomDataFormatContext context;
        context.address = static_cast<Address>(address);
        context.operand_index = operand_index;
        if (type_id >= 0
            && type_id <= kMaximumCustomDataId) {
            context.type_id.value = static_cast<std::uint16_t>(type_id);
        }
        auto rendered = registration->definition.render(
            std::span<const std::uint8_t>(
                static_cast<const std::uint8_t*>(value),
                static_cast<std::size_t>(size)),
            context);
        if (!rendered)
            return false;
        if (output != nullptr)
            *output = qstring(rendered->data(), rendered->size());
        return true;
    } catch (...) {
        return false;
    }
}

bool idaapi custom_data_scan(void* user_data,
                             bytevec_t* value,
                             const char* input,
                             ea_t address,
                             int operand_index,
                             qstring* error_text) noexcept {
    auto registration = retain_custom_data_format(
        static_cast<RegisteredCustomDataFormat*>(user_data));
    if (!registration || !registration->definition.scan || input == nullptr)
        return false;
    try {
        CustomDataFormatContext context;
        context.address = static_cast<Address>(address);
        context.operand_index = operand_index;
        auto scanned = registration->definition.scan(input, context);
        if (!scanned) {
            if (error_text != nullptr) {
                *error_text = qstring(scanned.error().message.data(),
                                      scanned.error().message.size());
            }
            return false;
        }
        if (value != nullptr) {
            value->qclear();
            if (!scanned->empty())
                value->append(scanned->data(), scanned->size());
        }
        return true;
    } catch (...) {
        if (error_text != nullptr)
            *error_text = "Custom data scan callback threw an exception";
        return false;
    }
}

void idaapi custom_data_analyze(void* user_data,
                                ea_t address,
                                int operand_index) noexcept {
    auto registration = retain_custom_data_format(
        static_cast<RegisteredCustomDataFormat*>(user_data));
    if (!registration || !registration->definition.analyze)
        return;
    try {
        CustomDataFormatContext context;
        context.address = static_cast<Address>(address);
        context.operand_index = operand_index;
        registration->definition.analyze(context);
    } catch (...) {
        // Exceptions must not cross the IDA SDK callback ABI.
    }
}

bool has_embedded_null(const std::string& value) {
    return value.find('\0') != std::string::npos;
}

const char* optional_string(const std::string& value) {
    return value.empty() ? nullptr : value.c_str();
}

std::string copy_sdk_string(const char* value) {
    return value == nullptr ? std::string{} : std::string(value);
}

Result<int> checked_custom_type_id(CustomDataTypeId type_id) {
    if (type_id.value == 0 || type_id.value > kMaximumCustomDataId) {
        return std::unexpected(Error::validation(
            "Custom data type id must be in 1..65534"));
    }
    const int sdk_id = static_cast<int>(type_id.value);
    if (::get_custom_data_type(sdk_id) == nullptr) {
        return std::unexpected(Error::not_found(
            "Custom data type is not registered", std::to_string(sdk_id)));
    }
    return sdk_id;
}

Result<int> checked_custom_format_id(CustomDataFormatId format_id) {
    if (format_id.value == 0 || format_id.value > kMaximumCustomDataId) {
        return std::unexpected(Error::validation(
            "Custom data format id must be in 1..65534"));
    }
    const int sdk_id = static_cast<int>(format_id.value);
    if (::get_custom_data_format(sdk_id) == nullptr) {
        return std::unexpected(Error::not_found(
            "Custom data format is not registered", std::to_string(sdk_id)));
    }
    return sdk_id;
}

CustomDataTypeInfo make_custom_type_info(int id,
                                         const data_type_t& sdk) {
    CustomDataTypeInfo info;
    info.id.value = static_cast<std::uint16_t>(id);
    info.name = copy_sdk_string(sdk.name);
    info.menu_name = copy_sdk_string(sdk.menu_name);
    info.hotkey = copy_sdk_string(sdk.hotkey);
    info.assembler_keyword = copy_sdk_string(sdk.asm_keyword);
    info.value_size = static_cast<AddressSize>(sdk.value_size);
    info.allow_duplicates = (sdk.props & DTP_NODUP) == 0;
    info.visible_in_menu = sdk.is_present_in_menus();
    info.has_creation_filter = sdk.may_create_at != nullptr;
    info.variable_size = sdk.calc_item_size != nullptr;
    return info;
}

CustomDataFormatInfo make_custom_format_info(int id,
                                             const data_format_t& sdk) {
    CustomDataFormatInfo info;
    info.id.value = static_cast<std::uint16_t>(id);
    info.name = copy_sdk_string(sdk.name);
    info.menu_name = copy_sdk_string(sdk.menu_name);
    info.hotkey = copy_sdk_string(sdk.hotkey);
    info.value_size = static_cast<AddressSize>(sdk.value_size);
    info.text_width = sdk.text_width;
    info.visible_in_menu = sdk.is_present_in_menus();
    info.can_render = sdk.print != nullptr;
    info.can_scan = sdk.scan != nullptr;
    info.can_analyze = sdk.analyze != nullptr;
    return info;
}

Result<std::vector<CustomDataFormatInfo>> custom_data_formats_for_sdk_id(
        int type_id) {
    intvec_t ids;
    const int count = ::get_custom_data_formats(&ids, type_id);
    if (count < 0) {
        return std::unexpected(Error::sdk(
            "get_custom_data_formats failed", std::to_string(type_id)));
    }
    std::vector<CustomDataFormatInfo> formats;
    formats.reserve(ids.size());
    for (int id : ids) {
        if (id <= 0 || id > kMaximumCustomDataId)
            continue;
        const data_format_t* sdk = ::get_custom_data_format(id);
        if (sdk != nullptr)
            formats.push_back(make_custom_format_info(id, *sdk));
    }
    return formats;
}

Status validate_custom_data_range(Address address, AddressSize byte_length) {
    if (byte_length == 0) {
        return std::unexpected(Error::validation(
            "Custom data byte length must be greater than zero"));
    }
    if (byte_length > std::numeric_limits<asize_t>::max()) {
        return std::unexpected(Error::validation(
            "Custom data byte length exceeds SDK size range"));
    }
    if (address == BadAddress || byte_length > BadAddress - address) {
        return std::unexpected(Error::validation(
            "Custom data address range overflow"));
    }
    return ida::ok();
}

bool fits_unsigned_width(std::size_t width, std::uint64_t value) {
    switch (width) {
        case 1:
            return value <= std::numeric_limits<std::uint8_t>::max();
        case 2:
            return value <= std::numeric_limits<std::uint16_t>::max();
        case 4:
            return value <= std::numeric_limits<std::uint32_t>::max();
        case 8:
            return true;
        default:
            return false;
    }
}

bool fits_signed_width(std::size_t width, std::int64_t value) {
    switch (width) {
        case 1:
            return value >= std::numeric_limits<std::int8_t>::min()
                && value <= std::numeric_limits<std::int8_t>::max();
        case 2:
            return value >= std::numeric_limits<std::int16_t>::min()
                && value <= std::numeric_limits<std::int16_t>::max();
        case 4:
            return value >= std::numeric_limits<std::int32_t>::min()
                && value <= std::numeric_limits<std::int32_t>::max();
        case 8:
            return true;
        default:
            return false;
    }
}

Result<std::uint64_t> read_unsigned_fixed(Address address, std::size_t width) {
    switch (width) {
        case 1: {
            auto value = read_byte(address);
            if (!value)
                return std::unexpected(value.error());
            return static_cast<std::uint64_t>(*value);
        }
        case 2: {
            auto value = read_word(address);
            if (!value)
                return std::unexpected(value.error());
            return static_cast<std::uint64_t>(*value);
        }
        case 4: {
            auto value = read_dword(address);
            if (!value)
                return std::unexpected(value.error());
            return static_cast<std::uint64_t>(*value);
        }
        case 8: {
            auto value = read_qword(address);
            if (!value)
                return std::unexpected(value.error());
            return *value;
        }
        default:
            return std::unexpected(Error::unsupported(
                "Unsupported fixed-width integer size",
                std::to_string(width)));
    }
}

Status write_unsigned_fixed(Address address,
                            std::size_t width,
                            std::uint64_t value) {
    if (!fits_unsigned_width(width, value)) {
        return std::unexpected(Error::validation(
            "Unsigned value does not fit target width",
            std::to_string(value) + " for width=" + std::to_string(width)));
    }

    switch (width) {
        case 1:
            return write_byte(address, static_cast<std::uint8_t>(value));
        case 2:
            return write_word(address, static_cast<std::uint16_t>(value));
        case 4:
            return write_dword(address, static_cast<std::uint32_t>(value));
        case 8:
            return write_qword(address, value);
        default:
            return std::unexpected(Error::unsupported(
                "Unsupported fixed-width integer size",
                std::to_string(width)));
    }
}

Status write_signed_fixed(Address address,
                          std::size_t width,
                          std::int64_t value) {
    if (!fits_signed_width(width, value)) {
        return std::unexpected(Error::validation(
            "Signed value does not fit target width",
            std::to_string(value) + " for width=" + std::to_string(width)));
    }

    switch (width) {
        case 1:
            return write_byte(address, static_cast<std::uint8_t>(static_cast<std::int8_t>(value)));
        case 2:
            return write_word(address, static_cast<std::uint16_t>(static_cast<std::int16_t>(value)));
        case 4:
            return write_dword(address, static_cast<std::uint32_t>(static_cast<std::int32_t>(value)));
        case 8:
            return write_qword(address, static_cast<std::uint64_t>(value));
        default:
            return std::unexpected(Error::unsupported(
                "Unsupported fixed-width integer size",
                std::to_string(width)));
    }
}

Result<std::int64_t> read_signed_fixed(Address address, std::size_t width) {
    auto value = read_unsigned_fixed(address, width);
    if (!value)
        return std::unexpected(value.error());

    switch (width) {
        case 1:
            return static_cast<std::int64_t>(static_cast<std::int8_t>(*value));
        case 2:
            return static_cast<std::int64_t>(static_cast<std::int16_t>(*value));
        case 4:
            return static_cast<std::int64_t>(static_cast<std::int32_t>(*value));
        case 8:
            return static_cast<std::int64_t>(*value);
        default:
            return std::unexpected(Error::unsupported(
                "Unsupported fixed-width integer size",
                std::to_string(width)));
    }
}

Result<std::size_t> checked_type_size(const ida::type::TypeInfo& type_info) {
    auto type_size = type_info.size();
    if (!type_size)
        return std::unexpected(type_size.error());
    if (*type_size == 0) {
        return std::unexpected(Error::validation(
            "Type size must be greater than zero"));
    }
    return *type_size;
}

bool is_signed_integer(const ida::type::TypeInfo& type_info) {
    const auto* impl = ida::type::TypeInfoAccess::get(type_info);
    return impl != nullptr && impl->ti.is_signed();
}

Result<ida::type::TypeInfo> resolve_if_typedef(const ida::type::TypeInfo& type_info) {
    if (!type_info.is_typedef())
        return type_info;
    return type_info.resolve_typedef();
}

bool is_byte_integer(const ida::type::TypeInfo& type_info) {
    if (!type_info.is_integer())
        return false;
    auto size = type_info.size();
    return size && *size == 1;
}

bool is_printable_ascii(std::uint8_t byte) {
    return byte >= 0x20 && byte <= 0x7e;
}

Result<TypedValue> read_typed_impl(Address address,
                                   const ida::type::TypeInfo& type_info,
                                   std::size_t depth);

Status write_typed_impl(Address address,
                        const ida::type::TypeInfo& type_info,
                        const TypedValue& value,
                        std::size_t depth);

Result<TypedValue> read_typed_impl(Address address,
                                   const ida::type::TypeInfo& type_info,
                                   std::size_t depth) {
    if (depth > kMaxTypedDepth) {
        return std::unexpected(Error::validation(
            "Maximum typed-value recursion depth exceeded"));
    }

    auto effective_type = resolve_if_typedef(type_info);
    if (!effective_type)
        return std::unexpected(effective_type.error());

    if (effective_type->is_array()) {
        auto element_type = effective_type->array_element_type();
        if (!element_type)
            return std::unexpected(element_type.error());

        auto length = effective_type->array_length();
        if (!length)
            return std::unexpected(length.error());

        TypedValue out;
        if (is_byte_integer(*element_type)) {
            auto raw = read_bytes(address, static_cast<AddressSize>(*length));
            if (!raw)
                return std::unexpected(raw.error());

            auto nul_it = std::find(raw->begin(), raw->end(), static_cast<std::uint8_t>(0));
            std::size_t text_len = static_cast<std::size_t>(std::distance(raw->begin(), nul_it));
            bool printable = text_len > 0
                && std::all_of(raw->begin(), raw->begin() + static_cast<std::ptrdiff_t>(text_len),
                               [](std::uint8_t b) { return is_printable_ascii(b); });
            if (printable) {
                out.kind = TypedValueKind::String;
                out.string_value.assign(raw->begin(), raw->begin() + static_cast<std::ptrdiff_t>(text_len));
                out.bytes = *raw;
                return out;
            }

            out.kind = TypedValueKind::Bytes;
            out.bytes = std::move(*raw);
            return out;
        }

        auto element_size = checked_type_size(*element_type);
        if (!element_size)
            return std::unexpected(element_size.error());

        out.kind = TypedValueKind::Array;
        out.elements.reserve(*length);
        for (std::size_t i = 0; i < *length; ++i) {
            if (i != 0 && *element_size > (std::numeric_limits<Address>::max() / i)) {
                return std::unexpected(Error::validation(
                    "Typed array read address overflow"));
            }
            Address offset = static_cast<Address>(*element_size * i);
            if (address > BadAddress - offset) {
                return std::unexpected(Error::validation(
                    "Typed array read address overflow"));
            }
            Address element_address = address + offset;
            auto element_value = read_typed_impl(element_address, *element_type, depth + 1);
            if (!element_value)
                return std::unexpected(element_value.error());
            out.elements.push_back(std::move(*element_value));
        }
        return out;
    }

    auto type_size = checked_type_size(*effective_type);
    if (!type_size)
        return std::unexpected(type_size.error());

    TypedValue out;

    if (effective_type->is_pointer()) {
        auto raw = read_unsigned_fixed(address, *type_size);
        if (!raw)
            return std::unexpected(raw.error());
        out.kind = TypedValueKind::Pointer;
        out.pointer_value = static_cast<Address>(*raw);
        out.unsigned_value = *raw;
        return out;
    }

    if (effective_type->is_floating_point()) {
        out.kind = TypedValueKind::FloatingPoint;
        if (*type_size == 4) {
            auto raw = read_dword(address);
            if (!raw)
                return std::unexpected(raw.error());
            out.floating_value = static_cast<double>(std::bit_cast<float>(*raw));
            return out;
        }
        if (*type_size == 8) {
            auto raw = read_qword(address);
            if (!raw)
                return std::unexpected(raw.error());
            out.floating_value = std::bit_cast<double>(*raw);
            return out;
        }

        auto raw = read_bytes(address, static_cast<AddressSize>(*type_size));
        if (!raw)
            return std::unexpected(raw.error());
        out.kind = TypedValueKind::Bytes;
        out.bytes = std::move(*raw);
        return out;
    }

    if (effective_type->is_integer() || effective_type->is_enum()) {
        if (*type_size > 8) {
            auto raw = read_bytes(address, static_cast<AddressSize>(*type_size));
            if (!raw)
                return std::unexpected(raw.error());
            out.kind = TypedValueKind::Bytes;
            out.bytes = std::move(*raw);
            return out;
        }

        if (is_signed_integer(*effective_type)) {
            auto value = read_signed_fixed(address, *type_size);
            if (!value)
                return std::unexpected(value.error());
            out.kind = TypedValueKind::SignedInteger;
            out.signed_value = *value;
            return out;
        }

        auto value = read_unsigned_fixed(address, *type_size);
        if (!value)
            return std::unexpected(value.error());
        out.kind = TypedValueKind::UnsignedInteger;
        out.unsigned_value = *value;
        return out;
    }

    auto raw = read_bytes(address, static_cast<AddressSize>(*type_size));
    if (!raw)
        return std::unexpected(raw.error());
    out.kind = TypedValueKind::Bytes;
    out.bytes = std::move(*raw);
    return out;
}

Status write_typed_impl(Address address,
                        const ida::type::TypeInfo& type_info,
                        const TypedValue& value,
                        std::size_t depth) {
    if (depth > kMaxTypedDepth) {
        return std::unexpected(Error::validation(
            "Maximum typed-value recursion depth exceeded"));
    }

    auto effective_type = resolve_if_typedef(type_info);
    if (!effective_type)
        return std::unexpected(effective_type.error());

    if (effective_type->is_array()) {
        auto element_type = effective_type->array_element_type();
        if (!element_type)
            return std::unexpected(element_type.error());

        auto length = effective_type->array_length();
        if (!length)
            return std::unexpected(length.error());

        if (is_byte_integer(*element_type)
            && (value.kind == TypedValueKind::Bytes
                || value.kind == TypedValueKind::String)) {
            std::vector<std::uint8_t> raw(*length, 0);
            if (value.kind == TypedValueKind::Bytes) {
                if (value.bytes.size() != *length) {
                    return std::unexpected(Error::validation(
                        "Byte-array write size mismatch",
                        std::to_string(value.bytes.size()) + " != " + std::to_string(*length)));
                }
                raw = value.bytes;
            } else {
                if (value.string_value.size() > *length) {
                    return std::unexpected(Error::validation(
                        "String does not fit destination array",
                        std::to_string(value.string_value.size()) + " > " + std::to_string(*length)));
                }
                for (std::size_t i = 0; i < value.string_value.size(); ++i)
                    raw[i] = static_cast<std::uint8_t>(value.string_value[i]);
            }
            return write_bytes(address, raw);
        }

        if (value.kind != TypedValueKind::Array) {
            return std::unexpected(Error::validation(
                "Typed array write requires array/bytes/string value"));
        }
        if (value.elements.size() != *length) {
            return std::unexpected(Error::validation(
                "Array element count mismatch",
                std::to_string(value.elements.size()) + " != " + std::to_string(*length)));
        }

        auto element_size = checked_type_size(*element_type);
        if (!element_size)
            return std::unexpected(element_size.error());

        for (std::size_t i = 0; i < *length; ++i) {
            if (i != 0 && *element_size > (std::numeric_limits<Address>::max() / i)) {
                return std::unexpected(Error::validation(
                    "Typed array write address overflow"));
            }
            Address offset = static_cast<Address>(*element_size * i);
            if (address > BadAddress - offset) {
                return std::unexpected(Error::validation(
                    "Typed array write address overflow"));
            }
            Address element_address = address + offset;
            auto status = write_typed_impl(element_address,
                                           *element_type,
                                           value.elements[i],
                                           depth + 1);
            if (!status)
                return status;
        }
        return ida::ok();
    }

    auto type_size = checked_type_size(*effective_type);
    if (!type_size)
        return std::unexpected(type_size.error());

    if (effective_type->is_pointer()) {
        std::uint64_t raw = 0;
        if (value.kind == TypedValueKind::Pointer) {
            raw = static_cast<std::uint64_t>(value.pointer_value);
        } else if (value.kind == TypedValueKind::UnsignedInteger) {
            raw = value.unsigned_value;
        } else {
            return std::unexpected(Error::validation(
                "Pointer write requires pointer or unsigned integer value"));
        }
        return write_unsigned_fixed(address, *type_size, raw);
    }

    if (effective_type->is_floating_point()) {
        if (value.kind != TypedValueKind::FloatingPoint) {
            return std::unexpected(Error::validation(
                "Floating-point write requires floating-point value"));
        }
        if (*type_size == 4) {
            float f = static_cast<float>(value.floating_value);
            return write_dword(address, std::bit_cast<std::uint32_t>(f));
        }
        if (*type_size == 8) {
            return write_qword(address, std::bit_cast<std::uint64_t>(value.floating_value));
        }
        return std::unexpected(Error::unsupported(
            "Unsupported floating-point width",
            std::to_string(*type_size)));
    }

    if (effective_type->is_integer() || effective_type->is_enum()) {
        bool is_signed = is_signed_integer(*effective_type);
        if (is_signed) {
            if (value.kind == TypedValueKind::SignedInteger)
                return write_signed_fixed(address, *type_size, value.signed_value);
            if (value.kind == TypedValueKind::UnsignedInteger) {
                if (value.unsigned_value > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())) {
                    return std::unexpected(Error::validation(
                        "Unsigned value cannot be represented as signed integer"));
                }
                return write_signed_fixed(address,
                                          *type_size,
                                          static_cast<std::int64_t>(value.unsigned_value));
            }
            return std::unexpected(Error::validation(
                "Signed integer write requires signed/unsigned integer value"));
        }

        if (value.kind == TypedValueKind::UnsignedInteger)
            return write_unsigned_fixed(address, *type_size, value.unsigned_value);
        if (value.kind == TypedValueKind::SignedInteger) {
            if (value.signed_value < 0) {
                return std::unexpected(Error::validation(
                    "Negative value cannot be written to unsigned integer type"));
            }
            return write_unsigned_fixed(address,
                                        *type_size,
                                        static_cast<std::uint64_t>(value.signed_value));
        }
        return std::unexpected(Error::validation(
            "Unsigned integer write requires signed/unsigned integer value"));
    }

    if (value.kind != TypedValueKind::Bytes) {
        return std::unexpected(Error::validation(
            "Unsupported typed write: use byte payload for this type"));
    }
    if (value.bytes.size() != *type_size) {
        return std::unexpected(Error::validation(
            "Byte write size mismatch",
            std::to_string(value.bytes.size()) + " != " + std::to_string(*type_size)));
    }
    return write_bytes(address, value.bytes);
}

} // namespace

// ── Read family ─────────────────────────────────────────────────────────

Result<std::uint8_t> read_byte(Address ea) {
    if (!is_loaded(ea))
        return std::unexpected(Error::not_found("Address not loaded", std::to_string(ea)));
    return static_cast<std::uint8_t>(get_byte(ea));
}

Result<std::uint16_t> read_word(Address ea) {
    if (!is_loaded(ea))
        return std::unexpected(Error::not_found("Address not loaded", std::to_string(ea)));
    return static_cast<std::uint16_t>(get_word(ea));
}

Result<std::uint32_t> read_dword(Address ea) {
    if (!is_loaded(ea))
        return std::unexpected(Error::not_found("Address not loaded", std::to_string(ea)));
    return static_cast<std::uint32_t>(get_dword(ea));
}

Result<std::uint64_t> read_qword(Address ea) {
    if (!is_loaded(ea))
        return std::unexpected(Error::not_found("Address not loaded", std::to_string(ea)));
    return static_cast<std::uint64_t>(get_qword(ea));
}

Result<std::vector<std::uint8_t>> read_bytes(Address ea, AddressSize count) {
    if (count == 0)
        return std::vector<std::uint8_t>{};
    std::vector<std::uint8_t> buf(count);
    ssize_t got = get_bytes(buf.data(), static_cast<ssize_t>(count), ea);
    if (got < 0)
        return std::unexpected(Error::sdk("get_bytes failed", std::to_string(ea)));
    buf.resize(static_cast<std::size_t>(got));
    return buf;
}

Result<std::string> read_string(Address ea,
                                AddressSize max_length,
                                std::int32_t string_type,
                                int conversion_flags) {
    if (!is_loaded(ea))
        return std::unexpected(Error::not_found("Address not loaded", std::to_string(ea)));

    qstring out;
    size_t len = max_length == 0
               ? size_t(-1)
               : static_cast<size_t>(max_length);
    ssize_t got = get_strlit_contents(&out, ea, len, static_cast<int32>(string_type),
                                      nullptr, conversion_flags);
    if (got < 0)
        return std::unexpected(Error::not_found("String literal not found", std::to_string(ea)));
    return ida::detail::to_string(out);
}

Result<StringListOptions> string_list_options() {
    const strwinsetup_t* options = ::get_strlist_options();
    if (options == nullptr) {
        return std::unexpected(Error::sdk(
            "get_strlist_options returned null"));
    }

    StringListOptions snapshot;
    const std::size_t first_type = !options->strtypes.empty()
        && options->strtypes.front() == 0 ? 1 : 0;
    snapshot.string_types.reserve(options->strtypes.size() - first_type);
    for (std::size_t index = first_type; index < options->strtypes.size(); ++index) {
        snapshot.string_types.push_back(
            static_cast<std::int32_t>(options->strtypes[index]));
    }
    snapshot.minimum_length = static_cast<std::int64_t>(options->minlen);
    snapshot.only_7bit = options->only_7bit != 0;
    snapshot.ignore_instructions = options->ignore_heads != 0;
    snapshot.display_only_existing_strings =
        options->display_only_existing_strings != 0;
    return snapshot;
}

Status configure_string_list(const StringListOptions& options) {
    if (options.string_types.empty()) {
        return std::unexpected(Error::validation(
            "String-list string_types cannot be empty"));
    }
    if (options.minimum_length < 0
        || static_cast<std::uint64_t>(options.minimum_length)
            > static_cast<std::uint64_t>(std::numeric_limits<sval_t>::max())) {
        return std::unexpected(Error::validation(
            "String-list minimum_length is outside the SDK range",
            std::to_string(options.minimum_length)));
    }

    bytevec_t string_types;
    string_types.reserve(options.string_types.size());
    for (const std::int32_t string_type : options.string_types) {
        if (string_type < 0 || string_type > 0xff) {
            return std::unexpected(Error::validation(
                "String-list type code must be in 0..255",
                std::to_string(string_type)));
        }
        string_types.push_back(static_cast<uchar>(string_type));
    }

    const strwinsetup_t* shared = ::get_strlist_options();
    if (shared == nullptr) {
        return std::unexpected(Error::sdk(
            "get_strlist_options returned null"));
    }

    // The SDK exposes this process-global configuration as const in C++, while
    // its official IDAPython Strings.setup adapter mutates the same object.
    // Keep that cast inside the opaque semantic boundary.
    auto* mutable_options = const_cast<strwinsetup_t*>(shared);
    mutable_options->strtypes.swap(string_types);
    mutable_options->minlen = static_cast<sval_t>(options.minimum_length);
    mutable_options->only_7bit = options.only_7bit ? 1 : 0;
    mutable_options->ignore_heads = options.ignore_instructions ? 1 : 0;
    mutable_options->display_only_existing_strings =
        options.display_only_existing_strings ? 1 : 0;
    ::build_strlist();
    return ida::ok();
}

Status rebuild_string_list() {
    ::build_strlist();
    return ida::ok();
}

Status clear_string_list() {
    ::clear_strlist();
    return ida::ok();
}

Result<std::vector<StringLiteral>> string_literals(bool rebuild) {
    if (rebuild)
        ::build_strlist();

    const std::size_t count = ::get_strlist_qty();
    std::vector<StringLiteral> literals;
    literals.reserve(count);
    for (std::size_t index = 0; index < count; ++index) {
        string_info_ex_t info;
        if (!::get_strlist_item(&info, index)) {
            return std::unexpected(Error::sdk(
                "get_strlist_item failed", std::to_string(index)));
        }
        if (info.ea == BADADDR || info.length < 0) {
            return std::unexpected(Error::sdk(
                "String-list item contains invalid metadata",
                std::to_string(index)));
        }
        Result<std::string> text;
        if (info.type == STRTYPE_DECOMP) {
            if (info.decompiler_string.empty()) {
                return std::unexpected(Error::sdk(
                    "Decompiler string-list item contains no copied text",
                    std::to_string(index)));
            }
            text = ida::detail::to_string(info.decompiler_string);
        } else {
            text = read_string(static_cast<Address>(info.ea),
                               static_cast<AddressSize>(info.length),
                               static_cast<std::int32_t>(info.type));
        }
        if (!text)
            return std::unexpected(text.error());
        literals.push_back({
            .address = static_cast<Address>(info.ea),
            .byte_length = static_cast<AddressSize>(info.length),
            .string_type = static_cast<std::int32_t>(info.type),
            .text = std::move(*text),
        });
    }
    return literals;
}

Result<TypedValue> read_typed(Address address, const ida::type::TypeInfo& type_info) {
    return read_typed_impl(address, type_info, 0);
}

// ── Write family ────────────────────────────────────────────────────────

Status write_byte(Address ea, std::uint8_t value) {
    put_byte(ea, value);
    return ida::ok();
}

Status write_word(Address ea, std::uint16_t value) {
    put_word(ea, value);
    return ida::ok();
}

Status write_dword(Address ea, std::uint32_t value) {
    put_dword(ea, value);
    return ida::ok();
}

Status write_qword(Address ea, std::uint64_t value) {
    put_qword(ea, value);
    return ida::ok();
}

Status write_bytes(Address ea, std::span<const std::uint8_t> bytes) {
    if (bytes.empty())
        return ida::ok();
    put_bytes(ea, bytes.data(), bytes.size());
    return ida::ok();
}

Status write_typed(Address address,
                   const ida::type::TypeInfo& type_info,
                   const TypedValue& value) {
    return write_typed_impl(address, type_info, value, 0);
}

// ── Patch family ────────────────────────────────────────────────────────

Status patch_byte(Address ea, std::uint8_t value) {
    if (!::patch_byte(ea, value))
        return std::unexpected(Error::sdk("patch_byte failed", std::to_string(ea)));
    return ida::ok();
}

Status patch_word(Address ea, std::uint16_t value) {
    if (!::patch_word(ea, value))
        return std::unexpected(Error::sdk("patch_word failed", std::to_string(ea)));
    return ida::ok();
}

Status patch_dword(Address ea, std::uint32_t value) {
    if (!::patch_dword(ea, value))
        return std::unexpected(Error::sdk("patch_dword failed", std::to_string(ea)));
    return ida::ok();
}

Status patch_qword(Address ea, std::uint64_t value) {
    if (!::patch_qword(ea, value))
        return std::unexpected(Error::sdk("patch_qword failed", std::to_string(ea)));
    return ida::ok();
}

Status patch_bytes(Address ea, std::span<const std::uint8_t> bytes) {
    if (bytes.empty())
        return ida::ok();
    ::patch_bytes(ea, bytes.data(), bytes.size());
    return ida::ok();
}

Status revert_patch(Address ea) {
    if (!::revert_byte(ea))
        return std::unexpected(Error::not_found("No patch to revert at address",
                                                std::to_string(ea)));
    return ida::ok();
}

Result<AddressSize> revert_patches(Address ea, AddressSize count) {
    if (count == 0)
        return AddressSize{0};
    if (ea > (BadAddress - count))
        return std::unexpected(Error::validation("Address range overflow"));

    AddressSize reverted = 0;
    for (AddressSize i = 0; i < count; ++i) {
        if (::revert_byte(ea + i))
            ++reverted;
    }
    if (reverted == 0) {
        return std::unexpected(Error::not_found("No patches to revert in range",
                                                std::to_string(ea)));
    }
    return reverted;
}

// ── Original values ─────────────────────────────────────────────────────

Result<std::uint8_t> original_byte(Address ea) {
    if (!is_loaded(ea))
        return std::unexpected(Error::not_found("Address not loaded", std::to_string(ea)));
    return static_cast<std::uint8_t>(get_original_byte(ea));
}

Result<std::uint16_t> original_word(Address ea) {
    if (!is_loaded(ea))
        return std::unexpected(Error::not_found("Address not loaded", std::to_string(ea)));
    return static_cast<std::uint16_t>(get_original_word(ea));
}

Result<std::uint32_t> original_dword(Address ea) {
    if (!is_loaded(ea))
        return std::unexpected(Error::not_found("Address not loaded", std::to_string(ea)));
    return static_cast<std::uint32_t>(get_original_dword(ea));
}

Result<std::uint64_t> original_qword(Address ea) {
    if (!is_loaded(ea))
        return std::unexpected(Error::not_found("Address not loaded", std::to_string(ea)));
    return static_cast<std::uint64_t>(get_original_qword(ea));
}

// ── Define / undefine ───────────────────────────────────────────────────

Status define_byte(Address ea, AddressSize count) {
    return define_fixed_width(ea, count, 1, "create_byte",
        [](ea_t address, asize_t length) { return ::create_byte(address, length); });
}

Status define_word(Address ea, AddressSize count) {
    return define_fixed_width(ea, count, 2, "create_word",
        [](ea_t address, asize_t length) { return ::create_word(address, length); });
}

Status define_dword(Address ea, AddressSize count) {
    return define_fixed_width(ea, count, 4, "create_dword",
        [](ea_t address, asize_t length) { return ::create_dword(address, length); });
}

Status define_qword(Address ea, AddressSize count) {
    return define_fixed_width(ea, count, 8, "create_qword",
        [](ea_t address, asize_t length) { return ::create_qword(address, length); });
}

Status define_oword(Address ea, AddressSize count) {
    return define_fixed_width(ea, count, 16, "create_oword",
        [](ea_t address, asize_t length) { return ::create_oword(address, length); });
}

Status define_yword(Address ea, AddressSize count) {
    return define_fixed_width(ea, count, 32, "create_yword",
        [](ea_t address, asize_t length) { return ::create_yword(address, length); });
}

Status define_zword(Address ea, AddressSize count) {
    return define_fixed_width(ea, count, 64, "create_zword",
        [](ea_t address, asize_t length) { return ::create_zword(address, length); });
}

Result<AddressSize> tbyte_element_size() {
    return extended_real_element_size(false);
}

Status define_tbyte(Address ea, AddressSize count) {
    auto valid_count = validate_definition_count(ea, count);
    if (!valid_count)
        return valid_count;
    auto width = tbyte_element_size();
    if (!width)
        return std::unexpected(width.error());
    return define_fixed_width(ea, count, *width, "create_tbyte",
        [](ea_t address, asize_t length) { return ::create_tbyte(address, length); });
}

Result<AddressSize> packed_real_element_size() {
    return extended_real_element_size(true);
}

Status define_packed_real(Address ea, AddressSize count) {
    auto valid_count = validate_definition_count(ea, count);
    if (!valid_count)
        return valid_count;
    auto width = packed_real_element_size();
    if (!width)
        return std::unexpected(width.error());
    return define_fixed_width(ea, count, *width, "create_packed_real",
        [](ea_t address, asize_t length) {
            return ::create_packed_real(address, length);
        });
}

Status define_float(Address ea, AddressSize count) {
    return define_fixed_width(ea, count, 4, "create_float",
        [](ea_t address, asize_t length) { return ::create_float(address, length); });
}

Status define_double(Address ea, AddressSize count) {
    return define_fixed_width(ea, count, 8, "create_double",
        [](ea_t address, asize_t length) { return ::create_double(address, length); });
}

Status define_string(Address ea, AddressSize length, std::int32_t string_type) {
    if (!create_strlit(ea, static_cast<asize_t>(length), static_cast<uint32>(string_type)))
        return std::unexpected(Error::sdk("create_strlit failed", std::to_string(ea)));
    return ida::ok();
}

Status define_struct(Address ea, AddressSize length, std::uint64_t structure_id) {
    if (length == 0)
        return std::unexpected(Error::validation("Structure length must be > 0"));
    if (!create_struct(ea,
                       static_cast<asize_t>(length),
                       static_cast<tid_t>(structure_id))) {
        return std::unexpected(Error::sdk("create_struct failed",
                                          std::to_string(ea)));
    }
    return ida::ok();
}

Result<CustomDataTypeId> register_custom_data_type(
        const CustomDataTypeDefinition& definition) {
    if (definition.name.empty()) {
        return std::unexpected(Error::validation(
            "Custom data type name cannot be empty"));
    }
    if (has_embedded_null(definition.name)
        || has_embedded_null(definition.menu_name)
        || has_embedded_null(definition.hotkey)
        || has_embedded_null(definition.assembler_keyword)) {
        return std::unexpected(Error::validation(
            "Custom data type strings cannot contain null bytes"));
    }
    if (definition.value_size == 0
        || definition.value_size > std::numeric_limits<asize_t>::max()) {
        return std::unexpected(Error::validation(
            "Custom data type value size is outside the SDK range"));
    }

    auto registration = std::make_shared<RegisteredCustomDataType>();
    registration->definition = definition;
    registration->sdk.cbsize = sizeof(data_type_t);
    registration->sdk.ud = registration.get();
    registration->sdk.props = definition.allow_duplicates ? 0 : DTP_NODUP;
    registration->sdk.name = registration->definition.name.c_str();
    registration->sdk.menu_name = optional_string(
        registration->definition.menu_name);
    registration->sdk.hotkey = optional_string(
        registration->definition.hotkey);
    registration->sdk.asm_keyword = optional_string(
        registration->definition.assembler_keyword);
    registration->sdk.value_size = static_cast<asize_t>(definition.value_size);
    registration->sdk.may_create_at = definition.may_create_at
        ? &custom_data_may_create_at : nullptr;
    registration->sdk.calc_item_size = definition.calculate_size
        ? &custom_data_calculate_size : nullptr;

    const int id = ::register_custom_data_type(&registration->sdk);
    if (id <= 0) {
        return std::unexpected(Error::conflict(
            "Custom data type registration failed", definition.name));
    }
    if (id > kMaximumCustomDataId) {
        ::unregister_custom_data_type(id);
        return std::unexpected(Error::unsupported(
            "Custom data type id exceeds the packed item range",
            std::to_string(id)));
    }
    registration->id = id;
    g_custom_data_types[id] = std::move(registration);
    return CustomDataTypeId{static_cast<std::uint16_t>(id)};
}

Status unregister_custom_data_type(CustomDataTypeId type_id) {
    if (type_id.value == 0 || type_id.value > kMaximumCustomDataId) {
        return std::unexpected(Error::validation(
            "Custom data type id must be in 1..65534"));
    }
    const int id = static_cast<int>(type_id.value);
    auto found = g_custom_data_types.find(id);
    if (found == g_custom_data_types.end()) {
        return std::unexpected(Error::not_found(
            "Custom data type is not owned by idax", std::to_string(id)));
    }
    const bool removed = ::unregister_custom_data_type(id);
    g_custom_data_types.erase(found);
    if (!removed) {
        return std::unexpected(Error::not_found(
            "Custom data type is no longer registered", std::to_string(id)));
    }
    return ida::ok();
}

Result<CustomDataTypeInfo> custom_data_type(CustomDataTypeId type_id) {
    auto id = checked_custom_type_id(type_id);
    if (!id)
        return std::unexpected(id.error());
    return make_custom_type_info(*id, *::get_custom_data_type(*id));
}

Result<CustomDataTypeId> find_custom_data_type(std::string_view name) {
    if (name.empty()) {
        return std::unexpected(Error::validation(
            "Custom data type name cannot be empty"));
    }
    if (name.find('\0') != std::string_view::npos) {
        return std::unexpected(Error::validation(
            "Custom data type name cannot contain null bytes"));
    }
    const std::string owned_name(name);
    const int id = ::find_custom_data_type(owned_name.c_str());
    if (id <= 0) {
        return std::unexpected(Error::not_found(
            "Custom data type not found", owned_name));
    }
    if (id > kMaximumCustomDataId) {
        return std::unexpected(Error::unsupported(
            "Custom data type id exceeds the packed item range",
            std::to_string(id)));
    }
    return CustomDataTypeId{static_cast<std::uint16_t>(id)};
}

Result<std::vector<CustomDataTypeInfo>> custom_data_types(
        AddressSize minimum_size,
        AddressSize maximum_size) {
    if (minimum_size > maximum_size
        || maximum_size > std::numeric_limits<asize_t>::max()) {
        return std::unexpected(Error::validation(
            "Invalid custom data type size range"));
    }
    intvec_t ids;
    const int count = ::get_custom_data_types(
        &ids, static_cast<asize_t>(minimum_size),
        static_cast<asize_t>(maximum_size));
    if (count < 0) {
        return std::unexpected(Error::sdk(
            "get_custom_data_types failed"));
    }
    std::vector<CustomDataTypeInfo> types;
    types.reserve(ids.size());
    for (int id : ids) {
        if (id <= 0 || id > kMaximumCustomDataId)
            continue;
        const data_type_t* sdk = ::get_custom_data_type(id);
        if (sdk != nullptr)
            types.push_back(make_custom_type_info(id, *sdk));
    }
    return types;
}

Result<CustomDataFormatId> register_custom_data_format(
        const CustomDataFormatDefinition& definition) {
    if (definition.name.empty()) {
        return std::unexpected(Error::validation(
            "Custom data format name cannot be empty"));
    }
    if (has_embedded_null(definition.name)
        || has_embedded_null(definition.menu_name)
        || has_embedded_null(definition.hotkey)) {
        return std::unexpected(Error::validation(
            "Custom data format strings cannot contain null bytes"));
    }
    if (definition.value_size > std::numeric_limits<asize_t>::max()) {
        return std::unexpected(Error::validation(
            "Custom data format value size exceeds the SDK range"));
    }
    if (definition.text_width < 0) {
        return std::unexpected(Error::validation(
            "Custom data format text width cannot be negative"));
    }

    auto registration = std::make_shared<RegisteredCustomDataFormat>();
    registration->definition = definition;
    registration->sdk.cbsize = sizeof(data_format_t);
    registration->sdk.ud = registration.get();
    registration->sdk.props = 0;
    registration->sdk.name = registration->definition.name.c_str();
    registration->sdk.menu_name = optional_string(
        registration->definition.menu_name);
    registration->sdk.hotkey = optional_string(
        registration->definition.hotkey);
    registration->sdk.value_size = static_cast<asize_t>(definition.value_size);
    registration->sdk.text_width = definition.text_width;
    registration->sdk.print = definition.render ? &custom_data_render : nullptr;
    registration->sdk.scan = definition.scan ? &custom_data_scan : nullptr;
    registration->sdk.analyze = definition.analyze
        ? &custom_data_analyze : nullptr;

    const int id = ::register_custom_data_format(&registration->sdk);
    if (id <= 0) {
        return std::unexpected(Error::conflict(
            "Custom data format registration failed", definition.name));
    }
    if (id > kMaximumCustomDataId) {
        ::unregister_custom_data_format(id);
        return std::unexpected(Error::unsupported(
            "Custom data format id exceeds the packed item range",
            std::to_string(id)));
    }
    registration->id = id;
    g_custom_data_formats[id] = std::move(registration);
    return CustomDataFormatId{static_cast<std::uint16_t>(id)};
}

Status unregister_custom_data_format(CustomDataFormatId format_id) {
    if (format_id.value == 0 || format_id.value > kMaximumCustomDataId) {
        return std::unexpected(Error::validation(
            "Custom data format id must be in 1..65534"));
    }
    const int id = static_cast<int>(format_id.value);
    auto found = g_custom_data_formats.find(id);
    if (found == g_custom_data_formats.end()) {
        return std::unexpected(Error::not_found(
            "Custom data format is not owned by idax", std::to_string(id)));
    }
    const bool removed = ::unregister_custom_data_format(id);
    g_custom_data_formats.erase(found);
    if (!removed) {
        return std::unexpected(Error::not_found(
            "Custom data format is no longer registered", std::to_string(id)));
    }
    return ida::ok();
}

Result<CustomDataFormatInfo> custom_data_format(CustomDataFormatId format_id) {
    auto id = checked_custom_format_id(format_id);
    if (!id)
        return std::unexpected(id.error());
    return make_custom_format_info(*id, *::get_custom_data_format(*id));
}

Result<CustomDataFormatId> find_custom_data_format(std::string_view name) {
    if (name.empty()) {
        return std::unexpected(Error::validation(
            "Custom data format name cannot be empty"));
    }
    if (name.find('\0') != std::string_view::npos) {
        return std::unexpected(Error::validation(
            "Custom data format name cannot contain null bytes"));
    }
    const std::string owned_name(name);
    const int id = ::find_custom_data_format(owned_name.c_str());
    if (id <= 0) {
        return std::unexpected(Error::not_found(
            "Custom data format not found", owned_name));
    }
    if (id > kMaximumCustomDataId) {
        return std::unexpected(Error::unsupported(
            "Custom data format id exceeds the packed item range",
            std::to_string(id)));
    }
    return CustomDataFormatId{static_cast<std::uint16_t>(id)};
}

Result<std::vector<CustomDataFormatInfo>> custom_data_formats(
        CustomDataTypeId type_id) {
    auto id = checked_custom_type_id(type_id);
    if (!id)
        return std::unexpected(id.error());
    return custom_data_formats_for_sdk_id(*id);
}

Result<std::vector<CustomDataFormatInfo>> standard_custom_data_formats() {
    return custom_data_formats_for_sdk_id(0);
}

Status attach_custom_data_format(CustomDataTypeId type_id,
                                 CustomDataFormatId format_id) {
    auto type = checked_custom_type_id(type_id);
    if (!type)
        return std::unexpected(type.error());
    auto format = checked_custom_format_id(format_id);
    if (!format)
        return std::unexpected(format.error());
    if (::is_attached_custom_data_format(*type, *format)) {
        return std::unexpected(Error::conflict(
            "Custom data format is already attached"));
    }
    if (!::attach_custom_data_format(*type, *format)) {
        return std::unexpected(Error::sdk(
            "attach_custom_data_format failed"));
    }
    return ida::ok();
}

Status detach_custom_data_format(CustomDataTypeId type_id,
                                 CustomDataFormatId format_id) {
    auto type = checked_custom_type_id(type_id);
    if (!type)
        return std::unexpected(type.error());
    auto format = checked_custom_format_id(format_id);
    if (!format)
        return std::unexpected(format.error());
    if (!::is_attached_custom_data_format(*type, *format)) {
        return std::unexpected(Error::not_found(
            "Custom data format is not attached"));
    }
    if (!::detach_custom_data_format(*type, *format)) {
        return std::unexpected(Error::sdk(
            "detach_custom_data_format failed"));
    }
    return ida::ok();
}

Result<bool> is_custom_data_format_attached(CustomDataTypeId type_id,
                                            CustomDataFormatId format_id) {
    auto type = checked_custom_type_id(type_id);
    if (!type)
        return std::unexpected(type.error());
    auto format = checked_custom_format_id(format_id);
    if (!format)
        return std::unexpected(format.error());
    return ::is_attached_custom_data_format(*type, *format);
}

Status attach_custom_data_format_to_standard_types(
        CustomDataFormatId format_id) {
    auto format = checked_custom_format_id(format_id);
    if (!format)
        return std::unexpected(format.error());
    if (::is_attached_custom_data_format(0, *format)) {
        return std::unexpected(Error::conflict(
            "Custom data format is already attached to standard types"));
    }
    if (!::attach_custom_data_format(0, *format)) {
        return std::unexpected(Error::sdk(
            "attach_custom_data_format for standard types failed"));
    }
    return ida::ok();
}

Status detach_custom_data_format_from_standard_types(
        CustomDataFormatId format_id) {
    auto format = checked_custom_format_id(format_id);
    if (!format)
        return std::unexpected(format.error());
    if (!::is_attached_custom_data_format(0, *format)) {
        return std::unexpected(Error::not_found(
            "Custom data format is not attached to standard types"));
    }
    if (!::detach_custom_data_format(0, *format)) {
        return std::unexpected(Error::sdk(
            "detach_custom_data_format for standard types failed"));
    }
    return ida::ok();
}

Result<bool> is_custom_data_format_attached_to_standard_types(
        CustomDataFormatId format_id) {
    auto format = checked_custom_format_id(format_id);
    if (!format)
        return std::unexpected(format.error());
    return ::is_attached_custom_data_format(0, *format);
}

Result<AddressSize> custom_data_item_size(CustomDataTypeId type_id,
                                          Address address,
                                          AddressSize maximum_size) {
    auto id = checked_custom_type_id(type_id);
    if (!id)
        return std::unexpected(id.error());
    if (maximum_size == 0
        || maximum_size > std::numeric_limits<asize_t>::max()) {
        return std::unexpected(Error::validation(
            "Custom data maximum size is outside the SDK range"));
    }
    const data_type_t* sdk = ::get_custom_data_type(*id);
    if (sdk->calc_item_size == nullptr) {
        const AddressSize size = static_cast<AddressSize>(sdk->value_size);
        if (size == 0 || size > maximum_size) {
            return std::unexpected(Error::validation(
                "Fixed custom data type does not fit the maximum size"));
        }
        return size;
    }
    const asize_t calculated = sdk->calc_item_size(
        sdk->ud, static_cast<ea_t>(address),
        static_cast<asize_t>(maximum_size));
    if (calculated == 0 || calculated > maximum_size) {
        return std::unexpected(Error::sdk(
            "Custom data size callback rejected the item",
            std::to_string(address)));
    }
    return static_cast<AddressSize>(calculated);
}

Status define_custom(Address address,
                     AddressSize byte_length,
                     CustomDataTypeId type_id,
                     CustomDataFormatId format_id) {
    auto valid_range = validate_custom_data_range(address, byte_length);
    if (!valid_range)
        return valid_range;
    auto type = checked_custom_type_id(type_id);
    if (!type)
        return std::unexpected(type.error());
    auto format = checked_custom_format_id(format_id);
    if (!format)
        return std::unexpected(format.error());
    if (!::is_attached_custom_data_format(*type, *format)) {
        return std::unexpected(Error::conflict(
            "Custom data format is not attached to the type"));
    }
    if (!::create_custdata(static_cast<ea_t>(address),
                           static_cast<asize_t>(byte_length),
                           *type, *format)) {
        return std::unexpected(Error::sdk(
            "create_custdata failed", std::to_string(address)));
    }
    return ida::ok();
}

Status define_custom_inferred(Address address,
                              CustomDataTypeId type_id,
                              CustomDataFormatId format_id,
                              AddressSize maximum_size) {
    auto size = custom_data_item_size(type_id, address, maximum_size);
    if (!size)
        return std::unexpected(size.error());
    return define_custom(address, *size, type_id, format_id);
}

Result<CustomDataItemInfo> custom_data_at(Address address) {
    custom_data_type_ids_t ids{};
    if (::get_custom_data_type_ids(&ids, static_cast<ea_t>(address)) <= 0) {
        return std::unexpected(Error::not_found(
            "No custom data item at address", std::to_string(address)));
    }
    const auto type = static_cast<std::uint16_t>(ids.dtid);
    const auto format = static_cast<std::uint16_t>(ids.fids[0]);
    if (type == 0 || type == std::numeric_limits<std::uint16_t>::max()
        || format == 0
        || format == std::numeric_limits<std::uint16_t>::max()) {
        return std::unexpected(Error::not_found(
            "Custom data item has no complete type/format identity",
            std::to_string(address)));
    }
    CustomDataItemInfo info;
    info.type_id.value = type;
    info.format_id.value = format;
    info.byte_length = static_cast<AddressSize>(
        ::get_item_size(static_cast<ea_t>(address)));
    return info;
}

Result<std::string> render_custom_data(
        CustomDataFormatId format_id,
        std::span<const std::uint8_t> value,
        const CustomDataFormatContext& context) {
    auto id = checked_custom_format_id(format_id);
    if (!id)
        return std::unexpected(id.error());
    if (value.empty()) {
        return std::unexpected(Error::validation(
            "Custom data render value cannot be empty"));
    }
    const data_format_t* sdk = ::get_custom_data_format(*id);
    if (sdk->print == nullptr) {
        return std::unexpected(Error::unsupported(
            "Custom data format has no render callback"));
    }
    qstring output;
    if (!sdk->print(sdk->ud, &output, value.data(),
                    static_cast<asize_t>(value.size()),
                    static_cast<ea_t>(context.address),
                    context.operand_index,
                    static_cast<int>(context.type_id.value))) {
        return std::unexpected(Error::sdk(
            "Custom data render callback rejected the value"));
    }
    return detail::to_string(output);
}

Result<std::vector<std::uint8_t>> scan_custom_data(
        CustomDataFormatId format_id,
        std::string_view text,
        const CustomDataFormatContext& context) {
    auto id = checked_custom_format_id(format_id);
    if (!id)
        return std::unexpected(id.error());
    if (text.find('\0') != std::string_view::npos) {
        return std::unexpected(Error::validation(
            "Custom data scan text cannot contain null bytes"));
    }
    const data_format_t* sdk = ::get_custom_data_format(*id);
    if (sdk->scan == nullptr) {
        return std::unexpected(Error::unsupported(
            "Custom data format has no scan callback"));
    }
    const std::string owned_text(text);
    bytevec_t value;
    qstring error_text;
    if (!sdk->scan(sdk->ud, &value, owned_text.c_str(),
                   static_cast<ea_t>(context.address),
                   context.operand_index, &error_text)) {
        return std::unexpected(Error::sdk(
            "Custom data scan callback rejected the text",
            detail::to_string(error_text)));
    }
    return std::vector<std::uint8_t>(value.begin(), value.end());
}

Status analyze_custom_data(CustomDataFormatId format_id,
                           const CustomDataFormatContext& context) {
    auto id = checked_custom_format_id(format_id);
    if (!id)
        return std::unexpected(id.error());
    const data_format_t* sdk = ::get_custom_data_format(*id);
    if (sdk->analyze == nullptr) {
        return std::unexpected(Error::unsupported(
            "Custom data format has no analyze callback"));
    }
    sdk->analyze(sdk->ud, static_cast<ea_t>(context.address),
                 context.operand_index);
    return ida::ok();
}

Status undefine(Address ea, AddressSize count) {
    if (!del_items(ea, DELIT_SIMPLE, static_cast<asize_t>(count)))
        return std::unexpected(Error::sdk("del_items failed", std::to_string(ea)));
    return ida::ok();
}

Result<Address> find_binary_pattern(Address start,
                                    Address end,
                                    std::string_view pattern,
                                    bool forward,
                                    bool skip_start,
                                    bool case_sensitive,
                                    int radix,
                                    int strlits_encoding) {
    if (pattern.empty())
        return std::unexpected(Error::validation("Binary pattern cannot be empty"));

    int sflag = forward ? SEARCH_DOWN : SEARCH_UP;
    if (skip_start)
        sflag |= SEARCH_NEXT;
    if (case_sensitive)
        sflag |= SEARCH_CASE;

    std::string pat(pattern);
    ea_t found = find_binary(start, end, pat.c_str(), radix, sflag, strlits_encoding);
    if (found == BADADDR)
        return std::unexpected(Error::not_found("Binary pattern not found", pat));
    return static_cast<Address>(found);
}

} // namespace ida::data

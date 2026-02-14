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

namespace ida::data {

namespace {

constexpr std::size_t kMaxTypedDepth = 64;

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
    if (!create_byte(ea, static_cast<asize_t>(count)))
        return std::unexpected(Error::sdk("create_byte failed", std::to_string(ea)));
    return ida::ok();
}

Status define_word(Address ea, AddressSize count) {
    if (!create_word(ea, static_cast<asize_t>(count)))
        return std::unexpected(Error::sdk("create_word failed", std::to_string(ea)));
    return ida::ok();
}

Status define_dword(Address ea, AddressSize count) {
    if (!create_dword(ea, static_cast<asize_t>(count)))
        return std::unexpected(Error::sdk("create_dword failed", std::to_string(ea)));
    return ida::ok();
}

Status define_qword(Address ea, AddressSize count) {
    if (!create_qword(ea, static_cast<asize_t>(count)))
        return std::unexpected(Error::sdk("create_qword failed", std::to_string(ea)));
    return ida::ok();
}

Status define_oword(Address ea, AddressSize count) {
    if (!create_oword(ea, static_cast<asize_t>(count)))
        return std::unexpected(Error::sdk("create_oword failed", std::to_string(ea)));
    return ida::ok();
}

Status define_tbyte(Address ea, AddressSize count) {
    if (!create_tbyte(ea, static_cast<asize_t>(count)))
        return std::unexpected(Error::sdk("create_tbyte failed", std::to_string(ea)));
    return ida::ok();
}

Status define_float(Address ea, AddressSize count) {
    if (!create_float(ea, static_cast<asize_t>(count)))
        return std::unexpected(Error::sdk("create_float failed", std::to_string(ea)));
    return ida::ok();
}

Status define_double(Address ea, AddressSize count) {
    if (!create_double(ea, static_cast<asize_t>(count)))
        return std::unexpected(Error::sdk("create_double failed", std::to_string(ea)));
    return ida::ok();
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

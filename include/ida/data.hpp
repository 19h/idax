/// \file data.hpp
/// \brief Byte-level read, write, patch, and define operations.
///
/// Wraps the SDK's bytes.hpp into clearly separated operation families:
///   - read_*   : non-mutating byte access
///   - write_*  : direct byte mutation (put_*)
///   - patch_*  : patching (original values preserved)
///   - define_* : item creation (create_byte, create_strlit, ...)
///   - undefine : item destruction (del_items)

#ifndef IDAX_DATA_HPP
#define IDAX_DATA_HPP

#include <ida/error.hpp>
#include <ida/address.hpp>
#include <cstdint>
#include <cstring>
#include <functional>
#include <limits>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

namespace ida::type {
class TypeInfo;
}

namespace ida::data {

enum class TypedValueKind {
    UnsignedInteger,
    SignedInteger,
    FloatingPoint,
    Pointer,
    String,
    Bytes,
    Array,
};

/// Generic typed value container used by read_typed()/write_typed().
///
/// Exactly one payload field is meaningful based on `kind`:
/// - UnsignedInteger: `unsigned_value`
/// - SignedInteger:   `signed_value`
/// - FloatingPoint:   `floating_value`
/// - Pointer:         `pointer_value`
/// - String:          `string_value`
/// - Bytes:           `bytes`
/// - Array:           `elements`
struct TypedValue {
    TypedValueKind kind{TypedValueKind::Bytes};

    std::uint64_t unsigned_value{0};
    std::int64_t signed_value{0};
    double floating_value{0.0};
    Address pointer_value{BadAddress};

    std::string string_value;
    std::vector<std::uint8_t> bytes;
    std::vector<TypedValue> elements;
};

/// Configuration for IDA's process-global, explicitly rebuilt string list.
///
/// String type codes use IDA's stable byte-sized string-type encoding. Common
/// values are 0 for one-byte C strings and 1 for two-byte C strings.
struct StringListOptions {
    std::vector<std::int32_t> string_types{0};
    std::int64_t minimum_length{5};
    bool only_7bit{true};
    bool ignore_instructions{false};
    bool display_only_existing_strings{false};
};

/// Owned string-list entry. `byte_length` is measured in octets.
struct StringLiteral {
    Address address{BadAddress};
    AddressSize byte_length{0};
    std::int32_t string_type{0};
    std::string text;
};

/// Opaque custom-data type identifier. Zero is reserved for standard types.
struct CustomDataTypeId {
    std::uint16_t value{0};

    friend constexpr bool operator==(CustomDataTypeId,
                                     CustomDataTypeId) = default;
};

/// Opaque custom-data format identifier. Zero is not a registered format.
struct CustomDataFormatId {
    std::uint16_t value{0};

    friend constexpr bool operator==(CustomDataFormatId,
                                     CustomDataFormatId) = default;
};

/// Context supplied to custom data format callbacks.
struct CustomDataFormatContext {
    Address address{BadAddress};
    int operand_index{-1};
    /// Zero means a standard type or an unknown type, depending on callback.
    CustomDataTypeId type_id{};
};

using CustomDataCreationFilter =
    std::function<bool(Address address, AddressSize byte_length)>;
using CustomDataSizeCallback =
    std::function<AddressSize(Address address, AddressSize maximum_size)>;
using CustomDataRenderCallback =
    std::function<Result<std::string>(std::span<const std::uint8_t> value,
                                      const CustomDataFormatContext& context)>;
using CustomDataScanCallback =
    std::function<Result<std::vector<std::uint8_t>>(
        std::string_view text,
        const CustomDataFormatContext& context)>;
using CustomDataAnalyzeCallback =
    std::function<void(const CustomDataFormatContext& context)>;

/// Owned configuration for a custom data type registration.
struct CustomDataTypeDefinition {
    std::string name;
    std::string menu_name;
    std::string hotkey;
    std::string assembler_keyword;
    /// Exact width for fixed types; minimum width when calculate_size is set.
    AddressSize value_size{0};
    bool allow_duplicates{true};
    CustomDataCreationFilter may_create_at;
    CustomDataSizeCallback calculate_size;
};

/// Copied metadata snapshot for a registered custom data type.
struct CustomDataTypeInfo {
    CustomDataTypeId id;
    std::string name;
    std::string menu_name;
    std::string hotkey;
    std::string assembler_keyword;
    AddressSize value_size{0};
    bool allow_duplicates{true};
    bool visible_in_menu{false};
    bool has_creation_filter{false};
    bool variable_size{false};
};

/// Owned configuration for a custom data format registration.
struct CustomDataFormatDefinition {
    std::string name;
    std::string menu_name;
    std::string hotkey;
    /// Zero accepts any value width.
    AddressSize value_size{0};
    std::int32_t text_width{0};
    CustomDataRenderCallback render;
    CustomDataScanCallback scan;
    CustomDataAnalyzeCallback analyze;
};

/// Copied metadata snapshot for a registered custom data format.
struct CustomDataFormatInfo {
    CustomDataFormatId id;
    std::string name;
    std::string menu_name;
    std::string hotkey;
    AddressSize value_size{0};
    std::int32_t text_width{0};
    bool visible_in_menu{false};
    bool can_render{false};
    bool can_scan{false};
    bool can_analyze{false};
};

/// Custom type/format identity stored on an existing data item.
struct CustomDataItemInfo {
    CustomDataTypeId type_id;
    CustomDataFormatId format_id;
    AddressSize byte_length{0};
};

// ── Read family ─────────────────────────────────────────────────────────

Result<std::uint8_t>  read_byte(Address address);
Result<std::uint16_t> read_word(Address address);
Result<std::uint32_t> read_dword(Address address);
Result<std::uint64_t> read_qword(Address address);
Result<std::vector<std::uint8_t>> read_bytes(Address address, AddressSize count);

/// Read a string literal as UTF-8 text.
/// If \\p max_length is 0, IDA computes the length automatically.
Result<std::string> read_string(Address address,
                                AddressSize max_length = 0,
                                std::int32_t string_type = 0,
                                int conversion_flags = 0);

/// Return a copied snapshot of the shared string-list configuration.
Result<StringListOptions> string_list_options();

/// Replace the shared string-list configuration and rebuild the cache.
///
/// This intentionally affects IDA's process-global Strings-window state.
Status configure_string_list(const StringListOptions& options);

/// Rebuild IDA's string-list cache using its current shared configuration.
Status rebuild_string_list();

/// Clear IDA's persisted string-list cache.
Status clear_string_list();

/// Enumerate copied string-list entries, optionally rebuilding first.
Result<std::vector<StringLiteral>> string_literals(bool rebuild = true);

/// Materialize a value at \\p address using the given semantic \\p type.
///
/// Supports integers, floating-point, pointers, byte arrays, and recursive
/// array element materialization.
Result<TypedValue> read_typed(Address address, const ida::type::TypeInfo& type);

/// Read a trivially-copyable value from the database.
template <typename T>
Result<T> read_value(Address address) {
    static_assert(std::is_trivially_copyable_v<T>,
                  "read_value<T> requires trivially-copyable T");
    auto bytes = read_bytes(address, static_cast<AddressSize>(sizeof(T)));
    if (!bytes)
        return std::unexpected(bytes.error());
    if (bytes->size() != sizeof(T)) {
        return std::unexpected(Error::sdk("read_value truncated",
                                          std::to_string(address)));
    }
    T value{};
    std::memcpy(&value, bytes->data(), sizeof(T));
    return value;
}

// ── Write family (direct mutation, no undo-friendly patching) ───────────

Status write_byte(Address address, std::uint8_t  value);
Status write_word(Address address, std::uint16_t value);
Status write_dword(Address address, std::uint32_t value);
Status write_qword(Address address, std::uint64_t value);
Status write_bytes(Address address, std::span<const std::uint8_t> bytes);

/// Write a semantic value at \\p address using the given \\p type.
///
/// Supports integers, floating-point, pointers, byte arrays/strings, and
/// recursive array writes.
Status write_typed(Address address,
                   const ida::type::TypeInfo& type,
                   const TypedValue& value);

/// Write a trivially-copyable value into the database.
template <typename T>
Status write_value(Address address, const T& value) {
    static_assert(std::is_trivially_copyable_v<T>,
                  "write_value<T> requires trivially-copyable T");
    auto* ptr = reinterpret_cast<const std::uint8_t*>(&value);
    return write_bytes(address, std::span<const std::uint8_t>(ptr, sizeof(T)));
}

// ── Patch family (original values preserved for revert) ─────────────────

Status patch_byte(Address address, std::uint8_t  value);
Status patch_word(Address address, std::uint16_t value);
Status patch_dword(Address address, std::uint32_t value);
Status patch_qword(Address address, std::uint64_t value);
Status patch_bytes(Address address, std::span<const std::uint8_t> bytes);

/// Revert a patched byte at \p address back to its original value.
Status revert_patch(Address address);

/// Revert patched bytes in [address, address + count).
/// Returns the number of bytes that were reverted.
Result<AddressSize> revert_patches(Address address, AddressSize count);

// ── Original (pre-patch) values ─────────────────────────────────────────

Result<std::uint8_t>  original_byte(Address address);
Result<std::uint16_t> original_word(Address address);
Result<std::uint32_t> original_dword(Address address);
Result<std::uint64_t> original_qword(Address address);

// ── Define / undefine items ─────────────────────────────────────────────

/// Define one or more fixed-width data elements.
/// `count` is an element count, not a byte length, and must be greater than 0.
/// The wrapper performs checked conversion to the SDK's total-byte-length API.
Status define_byte(Address address, AddressSize count = 1);
Status define_word(Address address, AddressSize count = 1);
Status define_dword(Address address, AddressSize count = 1);
Status define_qword(Address address, AddressSize count = 1);
/// Define 128-bit elements.
Status define_oword(Address address, AddressSize count = 1);
/// Define 256-bit elements.
Status define_yword(Address address, AddressSize count = 1);
/// Define 512-bit elements.
Status define_zword(Address address, AddressSize count = 1);
/// Return the active processor's tbyte element size.
/// Returns Unsupported when the active processor/assembler has no tbyte form.
Result<AddressSize> tbyte_element_size();
/// Define processor-sized extended floating-point elements.
Status define_tbyte(Address address, AddressSize count = 1);
/// Return the active processor's packed-real element size.
/// Returns Unsupported when the active processor/assembler has no packed-real form.
Result<AddressSize> packed_real_element_size();
/// Define processor-sized packed-decimal-real elements.
Status define_packed_real(Address address, AddressSize count = 1);
/// Define 32-bit floating-point elements.
Status define_float(Address address, AddressSize count = 1);
/// Define 64-bit floating-point elements.
Status define_double(Address address, AddressSize count = 1);
/// Define a string using an explicit byte length.
Status define_string(Address address, AddressSize length, std::int32_t string_type = 0);
/// Define a structure using an explicit byte length.
Status define_struct(Address address, AddressSize length, std::uint64_t structure_id);
/// Register a custom type and retain all callback state until unregister.
/// Explicit unregister is required before the owning plugin/module unloads.
Result<CustomDataTypeId> register_custom_data_type(
    const CustomDataTypeDefinition& definition);
/// Unregister a type registered through idax and release its callbacks.
Status unregister_custom_data_type(CustomDataTypeId type_id);
/// Return a copied metadata snapshot for a registered custom type.
Result<CustomDataTypeInfo> custom_data_type(CustomDataTypeId type_id);
/// Resolve a registered custom type by its unique name.
Result<CustomDataTypeId> find_custom_data_type(std::string_view name);
/// Enumerate custom types whose declared value size is within [minimum, maximum].
Result<std::vector<CustomDataTypeInfo>> custom_data_types(
    AddressSize minimum_size = 0,
    AddressSize maximum_size = std::numeric_limits<AddressSize>::max());

/// Register a custom format and retain all callback state until unregister.
/// Explicit unregister is required before the owning plugin/module unloads.
Result<CustomDataFormatId> register_custom_data_format(
    const CustomDataFormatDefinition& definition);
/// Unregister a format registered through idax and release its callbacks.
Status unregister_custom_data_format(CustomDataFormatId format_id);
/// Return a copied metadata snapshot for a registered custom format.
Result<CustomDataFormatInfo> custom_data_format(CustomDataFormatId format_id);
/// Resolve a registered custom format by its unique name.
Result<CustomDataFormatId> find_custom_data_format(std::string_view name);
/// Enumerate formats attached to a custom type.
Result<std::vector<CustomDataFormatInfo>> custom_data_formats(
    CustomDataTypeId type_id);
/// Enumerate formats attached globally to standard data types.
Result<std::vector<CustomDataFormatInfo>> standard_custom_data_formats();

Status attach_custom_data_format(CustomDataTypeId type_id,
                                 CustomDataFormatId format_id);
Status detach_custom_data_format(CustomDataTypeId type_id,
                                 CustomDataFormatId format_id);
Result<bool> is_custom_data_format_attached(CustomDataTypeId type_id,
                                            CustomDataFormatId format_id);
Status attach_custom_data_format_to_standard_types(
    CustomDataFormatId format_id);
Status detach_custom_data_format_from_standard_types(
    CustomDataFormatId format_id);
Result<bool> is_custom_data_format_attached_to_standard_types(
    CustomDataFormatId format_id);

/// Calculate one custom value's exact byte width within a positive maximum.
Result<AddressSize> custom_data_item_size(CustomDataTypeId type_id,
                                          Address address,
                                          AddressSize maximum_size);
/// Define custom data using an explicit total byte length.
Status define_custom(Address address,
                     AddressSize byte_length,
                     CustomDataTypeId type_id,
                     CustomDataFormatId format_id);
/// Calculate and define one fixed- or variable-size custom value.
Status define_custom_inferred(Address address,
                              CustomDataTypeId type_id,
                              CustomDataFormatId format_id,
                              AddressSize maximum_size);
/// Return the registered custom identity stored on an existing item.
Result<CustomDataItemInfo> custom_data_at(Address address);

/// Invoke a registered format's render callback.
Result<std::string> render_custom_data(
    CustomDataFormatId format_id,
    std::span<const std::uint8_t> value,
    const CustomDataFormatContext& context = {});
/// Invoke a registered format's scan callback.
Result<std::vector<std::uint8_t>> scan_custom_data(
    CustomDataFormatId format_id,
    std::string_view text,
    const CustomDataFormatContext& context = {});
/// Invoke a registered format's analyze callback.
Status analyze_custom_data(CustomDataFormatId format_id,
                           const CustomDataFormatContext& context = {});
/// Undefine a byte count beginning at `address`.
Status undefine(Address address, AddressSize count = 1);

// ── Binary pattern search ────────────────────────────────────────────────

/// Search for an IDA binary pattern string (e.g. "55 48 89 E5").
/// Returns the first matching address or not_found.
Result<Address> find_binary_pattern(Address start,
                                    Address end,
                                    std::string_view pattern,
                                    bool forward = true,
                                    bool skip_start = false,
                                    bool case_sensitive = true,
                                    int radix = 16,
                                    int strlits_encoding = 0);

} // namespace ida::data

#endif // IDAX_DATA_HPP

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
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

namespace ida::data {

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

// ── Original (pre-patch) values ─────────────────────────────────────────

Result<std::uint8_t>  original_byte(Address address);
Result<std::uint16_t> original_word(Address address);
Result<std::uint32_t> original_dword(Address address);
Result<std::uint64_t> original_qword(Address address);

// ── Define / undefine items ─────────────────────────────────────────────

Status define_byte(Address address, AddressSize count = 1);
Status define_word(Address address, AddressSize count = 1);
Status define_dword(Address address, AddressSize count = 1);
Status define_qword(Address address, AddressSize count = 1);
Status define_string(Address address, AddressSize length, std::int32_t string_type = 0);
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

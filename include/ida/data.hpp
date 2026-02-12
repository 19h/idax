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
#include <span>
#include <vector>

namespace ida::data {

// ── Read family ─────────────────────────────────────────────────────────

Result<std::uint8_t>  read_byte(Address ea);
Result<std::uint16_t> read_word(Address ea);
Result<std::uint32_t> read_dword(Address ea);
Result<std::uint64_t> read_qword(Address ea);
Result<std::vector<std::uint8_t>> read_bytes(Address ea, AddressSize count);

// ── Write family (direct mutation, no undo-friendly patching) ───────────

Status write_byte(Address ea, std::uint8_t  value);
Status write_word(Address ea, std::uint16_t value);
Status write_dword(Address ea, std::uint32_t value);
Status write_qword(Address ea, std::uint64_t value);
Status write_bytes(Address ea, std::span<const std::uint8_t> bytes);

// ── Patch family (original values preserved for revert) ─────────────────

Status patch_byte(Address ea, std::uint8_t  value);
Status patch_word(Address ea, std::uint16_t value);
Status patch_dword(Address ea, std::uint32_t value);
Status patch_qword(Address ea, std::uint64_t value);
Status patch_bytes(Address ea, std::span<const std::uint8_t> bytes);

// ── Original (pre-patch) values ─────────────────────────────────────────

Result<std::uint8_t>  original_byte(Address ea);
Result<std::uint16_t> original_word(Address ea);
Result<std::uint32_t> original_dword(Address ea);
Result<std::uint64_t> original_qword(Address ea);

// ── Define / undefine items ─────────────────────────────────────────────

Status define_byte(Address ea, AddressSize count = 1);
Status define_word(Address ea, AddressSize count = 1);
Status define_dword(Address ea, AddressSize count = 1);
Status define_qword(Address ea, AddressSize count = 1);
Status define_string(Address ea, AddressSize length, std::int32_t string_type = 0);
Status undefine(Address ea, AddressSize count = 1);

} // namespace ida::data

#endif // IDAX_DATA_HPP

/// \file data.cpp
/// \brief Implementation of ida::data — read, write, patch, define operations.

#include "detail/sdk_bridge.hpp"
#include <ida/data.hpp>

namespace ida::data {

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

Status define_string(Address ea, AddressSize length, std::int32_t string_type) {
    if (!create_strlit(ea, static_cast<asize_t>(length), static_cast<uint32>(string_type)))
        return std::unexpected(Error::sdk("create_strlit failed", std::to_string(ea)));
    return ida::ok();
}

Status undefine(Address ea, AddressSize count) {
    if (!del_items(ea, DELIT_SIMPLE, static_cast<asize_t>(count)))
        return std::unexpected(Error::sdk("del_items failed", std::to_string(ea)));
    return ida::ok();
}

} // namespace ida::data

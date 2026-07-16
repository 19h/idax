/// \file registry.cpp
/// \brief Implementation of scoped persistent registry values.

#include "detail/sdk_bridge.hpp"

#include <ida/registry.hpp>

#include <registry.hpp>

#include <algorithm>
#include <type_traits>

namespace ida::registry {

namespace {

static_assert(static_cast<std::uint8_t>(ValueKind::String) == reg_sz);
static_assert(static_cast<std::uint8_t>(ValueKind::Binary) == reg_binary);
static_assert(static_cast<std::uint8_t>(ValueKind::Integer) == reg_dword);
static_assert(reg_unknown == 0);
using NativeUpdateStringList = void (idaapi *)(
    const char*, const char*, size_t, const char*, bool);
using NativeBinaryOperation = bool (idaapi *)(
    const char*, bool, void*, size_t, const char*, int);
using NativeStringRead = bool (idaapi *)(
    qstring*, const char*, const char*);
using NativeStringWrite = void (idaapi *)(
    const char*, const char*, const char*);
using NativeIntegerOperation = int (idaapi *)(
    const char*, bool, int, const char*);
using NativeDeleteKey = bool (idaapi *)(const char*);
using NativeDeleteValue = bool (idaapi *)(const char*, const char*);
using NativeExists = bool (idaapi *)(const char*, const char*);
using NativeChildren = bool (idaapi *)(qstrvec_t*, const char*, bool);
using NativeDataType = bool (idaapi *)(
    regval_type_t*, const char*, const char*);
using NativeReadStringList = void (idaapi *)(qstrvec_t*, const char*);
using NativeWriteStringList = void (idaapi *)(const qstrvec_t&, const char*);
using NativeSetRegistryName = bool (idaapi *)(const char*);
static_assert(std::is_same_v<decltype(&::reg_bin_op), NativeBinaryOperation>);
static_assert(std::is_same_v<decltype(&::reg_str_get), NativeStringRead>);
static_assert(std::is_same_v<decltype(&::reg_str_set), NativeStringWrite>);
static_assert(std::is_same_v<decltype(&::reg_int_op), NativeIntegerOperation>);
static_assert(std::is_same_v<decltype(&::reg_delete_subkey), NativeDeleteKey>);
static_assert(std::is_same_v<decltype(&::reg_delete_tree), NativeDeleteKey>);
static_assert(std::is_same_v<decltype(&::reg_delete), NativeDeleteValue>);
static_assert(std::is_same_v<decltype(&::reg_subkey_exists), NativeDeleteKey>);
static_assert(std::is_same_v<decltype(&::reg_exists), NativeExists>);
static_assert(std::is_same_v<decltype(&::reg_subkey_children), NativeChildren>);
static_assert(std::is_same_v<decltype(&::reg_data_type), NativeDataType>);
static_assert(std::is_same_v<decltype(&::reg_read_strlist), NativeReadStringList>);
static_assert(std::is_same_v<decltype(&::reg_write_strlist), NativeWriteStringList>);
static_assert(std::is_same_v<decltype(&::reg_update_strlist),
                             NativeUpdateStringList>);
static_assert(std::is_same_v<decltype(&::set_registry_name),
                             NativeSetRegistryName>);

Status validate_text(std::string_view value, std::string_view field,
                     bool allow_empty = false) {
    if (!allow_empty && value.empty()) {
        return std::unexpected(Error::validation(
            std::string(field) + " cannot be empty"));
    }
    if (value.find('\0') != std::string_view::npos) {
        return std::unexpected(Error::validation(
            std::string(field) + " contains an embedded NUL byte"));
    }
    return ok();
}

Status validate_name(std::string_view name) {
    return validate_text(name, "Registry value name");
}

Result<ValueKind> semantic_kind(regval_type_t kind) {
    switch (kind) {
        case reg_sz: return ValueKind::String;
        case reg_binary: return ValueKind::Binary;
        case reg_dword: return ValueKind::Integer;
        default:
            return std::unexpected(Error::unsupported(
                "Registry value has an unsupported native kind",
                std::to_string(static_cast<int>(kind))));
    }
}

Result<std::optional<ValueKind>> queried_kind(std::string_view key,
                                              std::string_view name) {
    regval_type_t native = reg_unknown;
    if (!::reg_data_type(&native, std::string(name).c_str(),
                         std::string(key).c_str())) {
        return std::optional<ValueKind>{};
    }
    auto semantic = semantic_kind(native);
    if (!semantic)
        return std::unexpected(semantic.error());
    return std::optional<ValueKind>{*semantic};
}

Status require_kind(std::string_view key, std::string_view name,
                    ValueKind expected, bool& exists) {
    auto kind = queried_kind(key, name);
    if (!kind)
        return std::unexpected(kind.error());
    exists = kind->has_value();
    if (!exists)
        return ok();
    if (**kind != expected) {
        return std::unexpected(Error::conflict(
            "Registry value kind does not match the requested operation",
            std::string(name)));
    }
    return ok();
}

std::vector<std::string> copy_strings(const qstrvec_t& native) {
    std::vector<std::string> result;
    result.reserve(native.size());
    for (const auto& value : native)
        result.push_back(detail::to_string(value));
    return result;
}

qstrvec_t native_strings(std::span<const std::string> values) {
    qstrvec_t result;
    result.reserve(values.size());
    for (const auto& value : values)
        result.push_back(qstring(value.data(), value.size()));
    return result;
}

} // namespace

Result<Store> Store::open(std::string_view key) {
    if (auto status = validate_text(key, "Registry key"); !status)
        return std::unexpected(status.error());
    return Store(std::string(key));
}

Result<Store> Store::child(std::string_view name) const {
    if (auto status = validate_text(name, "Registry child name"); !status)
        return std::unexpected(status.error());
    if (name.find('\\') != std::string_view::npos
        || name.find('/') != std::string_view::npos) {
        return std::unexpected(Error::validation(
            "Registry child name must be one path component",
            std::string(name)));
    }
    return Store(key_ + "\\" + std::string(name));
}

Result<bool> Store::exists() const {
    return ::reg_subkey_exists(key_.c_str());
}

Result<std::vector<std::string>> Store::child_keys() const {
    qstrvec_t native;
    if (!::reg_subkey_subkeys(&native, key_.c_str())) {
        return std::unexpected(Error::not_found(
            "Registry key was not found", key_));
    }
    return copy_strings(native);
}

Result<std::vector<std::string>> Store::value_names() const {
    qstrvec_t native;
    if (!::reg_subkey_values(&native, key_.c_str())) {
        return std::unexpected(Error::not_found(
            "Registry key was not found", key_));
    }
    return copy_strings(native);
}

Result<bool> Store::contains(std::string_view name) const {
    if (auto status = validate_name(name); !status)
        return std::unexpected(status.error());
    const std::string owned(name);
    return ::reg_exists(owned.c_str(), key_.c_str());
}

Result<std::optional<ValueKind>> Store::value_kind(std::string_view name) const {
    if (auto status = validate_name(name); !status)
        return std::unexpected(status.error());
    return queried_kind(key_, name);
}

Result<std::optional<std::string>> Store::read_string(
    std::string_view name) const {
    if (auto status = validate_name(name); !status)
        return std::unexpected(status.error());
    bool exists = false;
    if (auto status = require_kind(key_, name, ValueKind::String, exists);
        !status) {
        return std::unexpected(status.error());
    }
    if (!exists)
        return std::optional<std::string>{};
    qstring native;
    const std::string owned(name);
    if (!::reg_read_string(&native, owned.c_str(), key_.c_str())) {
        return std::unexpected(Error::sdk(
            "Failed to read registry string", owned));
    }
    return std::optional<std::string>{detail::to_string(native)};
}

Status Store::write_string(std::string_view name,
                           std::string_view value) const {
    if (auto status = validate_name(name); !status)
        return status;
    if (auto status = validate_text(value, "Registry string", true); !status)
        return status;
    const std::string owned_name(name);
    const std::string owned_value(value);
    ::reg_write_string(owned_name.c_str(), owned_value.c_str(), key_.c_str());
    auto readback = read_string(name);
    if (!readback || !readback->has_value() || **readback != value) {
        return std::unexpected(readback
            ? Error::sdk("Registry string write could not be verified",
                         owned_name)
            : readback.error());
    }
    return ok();
}

Result<std::optional<std::vector<std::uint8_t>>> Store::read_binary(
    std::string_view name) const {
    if (auto status = validate_name(name); !status)
        return std::unexpected(status.error());
    bool exists = false;
    if (auto status = require_kind(key_, name, ValueKind::Binary, exists);
        !status) {
        return std::unexpected(status.error());
    }
    if (!exists)
        return std::optional<std::vector<std::uint8_t>>{};
    bytevec_t native;
    const std::string owned(name);
    if (!::reg_read_binary(owned.c_str(), &native, key_.c_str())) {
        return std::unexpected(Error::sdk(
            "Failed to read registry binary value", owned));
    }
    std::vector<std::uint8_t> copied(native.begin(), native.end());
    return std::optional<std::vector<std::uint8_t>>{std::move(copied)};
}

Status Store::write_binary(std::string_view name,
                           std::span<const std::uint8_t> value) const {
    if (auto status = validate_name(name); !status)
        return status;
    const std::string owned(name);
    const std::uint8_t dummy = 0;
    const void* data = value.empty() ? static_cast<const void*>(&dummy)
                                     : static_cast<const void*>(value.data());
    if (!::reg_bin_op(owned.c_str(), true, const_cast<void*>(data),
                      value.size(), key_.c_str())) {
        return std::unexpected(Error::sdk(
            "Failed to write registry binary value", owned));
    }
    auto readback = read_binary(name);
    if (!readback || !readback->has_value()
        || !std::equal(value.begin(), value.end(), (**readback).begin(),
                       (**readback).end())) {
        return std::unexpected(readback
            ? Error::sdk("Registry binary write could not be verified", owned)
            : readback.error());
    }
    return ok();
}

Result<std::optional<std::int32_t>> Store::read_integer(
    std::string_view name) const {
    if (auto status = validate_name(name); !status)
        return std::unexpected(status.error());
    bool exists = false;
    if (auto status = require_kind(key_, name, ValueKind::Integer, exists);
        !status) {
        return std::unexpected(status.error());
    }
    if (!exists)
        return std::optional<std::int32_t>{};
    const std::string owned(name);
    const int value = ::reg_read_int(owned.c_str(), 0, key_.c_str());
    static_assert(sizeof(int) == sizeof(std::int32_t));
    return std::optional<std::int32_t>{static_cast<std::int32_t>(value)};
}

Status Store::write_integer(std::string_view name, std::int32_t value) const {
    if (auto status = validate_name(name); !status)
        return status;
    const std::string owned(name);
    ::reg_write_int(owned.c_str(), static_cast<int>(value), key_.c_str());
    auto readback = read_integer(name);
    if (!readback || !readback->has_value() || **readback != value) {
        return std::unexpected(readback
            ? Error::sdk("Registry integer write could not be verified", owned)
            : readback.error());
    }
    return ok();
}

Result<std::optional<bool>> Store::read_boolean(std::string_view name) const {
    auto integer = read_integer(name);
    if (!integer)
        return std::unexpected(integer.error());
    if (!integer->has_value())
        return std::optional<bool>{};
    return std::optional<bool>{**integer != 0};
}

Status Store::write_boolean(std::string_view name, bool value) const {
    return write_integer(name, value ? 1 : 0);
}

Result<bool> Store::erase_value(std::string_view name) const {
    if (auto status = validate_name(name); !status)
        return std::unexpected(status.error());
    const std::string owned(name);
    return ::reg_delete(owned.c_str(), key_.c_str());
}

Result<bool> Store::erase_key() const {
    return ::reg_delete_subkey(key_.c_str());
}

Result<bool> Store::erase_tree() const {
    return ::reg_delete_tree(key_.c_str());
}

Result<std::vector<std::string>> Store::read_string_list() const {
    if (!::reg_subkey_exists(key_.c_str())) {
        return std::unexpected(Error::not_found(
            "Registry key was not found", key_));
    }
    qstrvec_t native;
    ::reg_read_strlist(&native, key_.c_str());
    return copy_strings(native);
}

Status Store::write_string_list(std::span<const std::string> values) const {
    for (const auto& value : values) {
        if (auto status = validate_text(value, "Registry list value", true);
            !status) {
            return status;
        }
    }
    const qstrvec_t native = native_strings(values);
    ::reg_write_strlist(native, key_.c_str());
    auto readback = read_string_list();
    if (!readback || *readback != std::vector<std::string>(values.begin(),
                                                           values.end())) {
        return std::unexpected(readback
            ? Error::sdk("Registry string-list write could not be verified",
                         key_)
            : readback.error());
    }
    return ok();
}

Status Store::update_string_list(const StringListUpdate& update) const {
    if (update.max_records == 0 || update.max_records > 1000) {
        return std::unexpected(Error::validation(
            "Registry string-list limit must be in the range 1..1000",
            std::to_string(update.max_records)));
    }
    if (update.add) {
        if (auto status = validate_text(*update.add, "Registry list addition",
                                        true); !status) {
            return status;
        }
    }
    if (update.remove) {
        if (auto status = validate_text(*update.remove,
                                        "Registry list removal", true);
            !status) {
            return status;
        }
    }
    const auto equal = [&](const std::string& left,
                           const std::string& right) {
        return update.ignore_case
            ? ::stricmp(left.c_str(), right.c_str()) == 0
            : left == right;
    };
    if (update.add && update.remove && equal(*update.add, *update.remove)) {
        return std::unexpected(Error::validation(
            "Registry list update cannot add and remove the same value"));
    }

    std::vector<std::string> values;
    if (::reg_subkey_exists(key_.c_str())) {
        auto current = read_string_list();
        if (!current)
            return std::unexpected(current.error());
        values = std::move(*current);
    }
    if (update.remove) {
        std::erase_if(values, [&](const std::string& value) {
            return equal(value, *update.remove);
        });
    }
    if (update.add) {
        std::erase_if(values, [&](const std::string& value) {
            return equal(value, *update.add);
        });
        values.insert(values.begin(), *update.add);
    }
    if (values.size() > update.max_records)
        values.resize(update.max_records);
    return write_string_list(values);
}

} // namespace ida::registry

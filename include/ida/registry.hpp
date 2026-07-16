/// \file registry.hpp
/// \brief Opaque, scoped access to persistent IDA configuration values.

#ifndef IDAX_REGISTRY_HPP
#define IDAX_REGISTRY_HPP

#include <ida/error.hpp>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace ida::registry {

/// Semantic kinds supported by the persistent registry boundary.
enum class ValueKind : std::uint8_t {
    String = 1,  ///< UTF-8 string value.
    Binary = 3,  ///< Arbitrary copied octets.
    Integer = 4, ///< Signed 32-bit integer; booleans use this storage kind.
};

/// One deterministic ordered string-list update.
struct StringListUpdate {
    /// Value to front-insert after removing its existing matching positions.
    std::optional<std::string> add;
    /// Value whose matching positions are removed.
    std::optional<std::string> remove;
    /// Maximum retained records, in the closed range 1..1000.
    std::size_t max_records{100};
    /// Apply the SDK's UTF-8 case-insensitive comparison to add/remove matches.
    bool ignore_case{false};
};

/// Copyable semantic handle to one nonempty persistent registry key.
///
/// The handle owns only the key text. It exposes no native registry object and
/// does not mutate IDA's process-global registry root.
class Store {
public:
    /// Open a scoped key. The key need not exist yet.
    static Result<Store> open(std::string_view key);

    /// Return the owned registry key text.
    [[nodiscard]] const std::string& key() const noexcept { return key_; }
    /// Derive a store for one nonempty child path component.
    Result<Store> child(std::string_view name) const;

    /// Report whether this key currently exists.
    Result<bool> exists() const;
    /// Copy direct child-key names; a missing key returns `NotFound`.
    Result<std::vector<std::string>> child_keys() const;
    /// Copy direct value names; a missing key returns `NotFound`.
    Result<std::vector<std::string>> value_names() const;

    /// Report whether a nonempty value name exists under this key.
    Result<bool> contains(std::string_view name) const;
    /// Return the semantic kind, or empty optional when the value is absent.
    Result<std::optional<ValueKind>> value_kind(std::string_view name) const;

    /// Copy a string, return empty optional when absent, or `Conflict` on kind mismatch.
    Result<std::optional<std::string>> read_string(std::string_view name) const;
    /// Persist a string and verify exact typed readback.
    Status write_string(std::string_view name, std::string_view value) const;
    /// Copy binary octets, return empty optional when absent, or `Conflict` on kind mismatch.
    Result<std::optional<std::vector<std::uint8_t>>> read_binary(
        std::string_view name) const;
    /// Persist binary octets, including an empty value, and verify readback.
    Status write_binary(std::string_view name,
                        std::span<const std::uint8_t> value) const;
    /// Copy a signed 32-bit integer, with optional absence and checked kind.
    Result<std::optional<std::int32_t>> read_integer(
        std::string_view name) const;
    /// Persist a signed 32-bit integer and verify exact readback.
    Status write_integer(std::string_view name, std::int32_t value) const;
    /// Read integer storage as a semantic boolean; any nonzero value is true.
    Result<std::optional<bool>> read_boolean(std::string_view name) const;
    /// Persist a boolean through the SDK integer convention and verify readback.
    Status write_boolean(std::string_view name, bool value) const;

    /// Delete one named value and report whether it was removed.
    Result<bool> erase_value(std::string_view name) const;
    /// Request nonrecursive key deletion and report whether it was removed.
    Result<bool> erase_key() const;
    /// Delete this key and all descendants and report whether state was removed.
    Result<bool> erase_tree() const;

    /// Copy the ordered string list; a missing key returns `NotFound`.
    Result<std::vector<std::string>> read_string_list() const;
    /// Replace the ordered string list and verify exact readback.
    Status write_string_list(std::span<const std::string> values) const;
    /// Remove matches, front-insert an addition, and trim deterministically.
    ///
    /// The SDK exposes no transaction token. Callers sharing a key must
    /// serialize compound updates across threads or processes.
    Status update_string_list(const StringListUpdate& update) const;

private:
    explicit Store(std::string key) : key_(std::move(key)) {}
    std::string key_;
};

} // namespace ida::registry

#endif // IDAX_REGISTRY_HPP

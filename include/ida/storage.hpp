/// \file storage.hpp
/// \brief Low-level persistent key-value storage (advanced).

#ifndef IDAX_STORAGE_HPP
#define IDAX_STORAGE_HPP

#include <ida/error.hpp>
#include <ida/address.hpp>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace ida::storage {

/// Opaque node abstraction for persistent database storage.
class Node {
public:
    static Result<Node> open(std::string_view name, bool create = false);

    Result<std::uint64_t>           alt(Address index, std::uint8_t tag = 'A') const;
    Status                          set_alt(Address index, std::uint64_t value, std::uint8_t tag = 'A');
    Status                          remove_alt(Address index, std::uint8_t tag = 'A');

    Result<std::vector<std::uint8_t>> sup(Address index, std::uint8_t tag = 'S') const;
    Status                            set_sup(Address index, std::span<const std::uint8_t> data, std::uint8_t tag = 'S');

    Result<std::string>             hash(std::string_view key, std::uint8_t tag = 'H') const;
    Status                          set_hash(std::string_view key, std::string_view value, std::uint8_t tag = 'H');

    // ── Blob operations (arbitrary binary data) ─────────────────────────

    /// Get the size of a blob at the given index.
    /// Returns 0 if no blob exists.
    Result<std::size_t>               blob_size(Address index, std::uint8_t tag = 'B') const;

    /// Read a blob from the node.
    Result<std::vector<std::uint8_t>> blob(Address index, std::uint8_t tag = 'B') const;

    /// Write a blob to the node.
    Status                            set_blob(Address index, std::span<const std::uint8_t> data, std::uint8_t tag = 'B');

    /// Remove a blob.
    Status                            remove_blob(Address index, std::uint8_t tag = 'B');

    /// Read a blob as a string (null-terminated).
    Result<std::string>               blob_string(Address index, std::uint8_t tag = 'B') const;

    Node() = default;
    ~Node();
    Node(const Node&);
    Node& operator=(const Node&);
    Node(Node&&) noexcept;
    Node& operator=(Node&&) noexcept;

    struct Impl;

private:
    Impl* impl_{nullptr};
};

} // namespace ida::storage

#endif // IDAX_STORAGE_HPP

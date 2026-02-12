/// \file storage.cpp
/// \brief Implementation of ida::storage — netnode-backed opaque storage.

#include "detail/sdk_bridge.hpp"
#include <ida/storage.hpp>

namespace ida::storage {

// ── Pimpl definition ────────────────────────────────────────────────────

struct Node::Impl {
    netnode nn;

    Impl() = default;
    explicit Impl(const netnode& n) : nn(n) {}
};

// ── Lifecycle ───────────────────────────────────────────────────────────

Node::~Node() {
    delete impl_;
}

Node::Node(const Node& other)
    : impl_(other.impl_ ? new Impl(other.impl_->nn) : nullptr) {}

Node& Node::operator=(const Node& other) {
    if (this != &other) {
        delete impl_;
        impl_ = other.impl_ ? new Impl(other.impl_->nn) : nullptr;
    }
    return *this;
}

Node::Node(Node&& other) noexcept : impl_(other.impl_) {
    other.impl_ = nullptr;
}

Node& Node::operator=(Node&& other) noexcept {
    if (this != &other) {
        delete impl_;
        impl_ = other.impl_;
        other.impl_ = nullptr;
    }
    return *this;
}

// ── Factory ─────────────────────────────────────────────────────────────

Result<Node> Node::open(std::string_view name, bool create) {
    Node node;
    node.impl_ = new Impl();
    qstring qname = ida::detail::to_qstring(name);

    if (create) {
        if (!node.impl_->nn.create(qname.c_str())) {
            // Already exists; open the existing netnode.
            node.impl_->nn = netnode(qname.c_str(), 0, false);
            if (node.impl_->nn == BADNODE) {
                delete node.impl_;
                node.impl_ = nullptr;
                return std::unexpected(Error::sdk("Failed to create or open netnode",
                                                  std::string(name)));
            }
        }
    } else {
        // Open existing netnode by name. The constructor takes name and
        // namlen; size 0 means strlen-based.
        node.impl_->nn = netnode(qname.c_str(), 0, false);
        if (node.impl_->nn == BADNODE) {
            delete node.impl_;
            node.impl_ = nullptr;
            return std::unexpected(Error::not_found("Netnode not found",
                                                    std::string(name)));
        }
    }
    return node;
}

// ── Alt values ──────────────────────────────────────────────────────────

Result<std::uint64_t> Node::alt(Address index, std::uint8_t tag) const {
    if (!impl_)
        return std::unexpected(Error::internal("Node has null impl"));
    nodeidx_t idx = static_cast<nodeidx_t>(index);
    uval_t val = impl_->nn.altval(idx, tag);
    // altval returns 0 if not found; there's no way to distinguish 0 from
    // missing, so we just return the value as-is.
    return static_cast<std::uint64_t>(val);
}

Status Node::set_alt(Address index, std::uint64_t value, std::uint8_t tag) {
    if (!impl_)
        return std::unexpected(Error::internal("Node has null impl"));
    nodeidx_t idx = static_cast<nodeidx_t>(index);
    if (!impl_->nn.altset(idx, static_cast<uval_t>(value), tag))
        return std::unexpected(Error::sdk("altset failed"));
    return ida::ok();
}

Status Node::del_alt(Address index, std::uint8_t tag) {
    if (!impl_)
        return std::unexpected(Error::internal("Node has null impl"));
    nodeidx_t idx = static_cast<nodeidx_t>(index);
    if (!impl_->nn.altdel(idx, tag))
        return std::unexpected(Error::sdk("altdel failed"));
    return ida::ok();
}

// ── Supval values ───────────────────────────────────────────────────────

Result<std::vector<std::uint8_t>> Node::sup(Address index, std::uint8_t tag) const {
    if (!impl_)
        return std::unexpected(Error::internal("Node has null impl"));
    nodeidx_t idx = static_cast<nodeidx_t>(index);

    // First get the size.
    ssize_t sz = impl_->nn.supval(idx, nullptr, 0, tag);
    if (sz <= 0)
        return std::unexpected(Error::not_found("No supval at index"));

    std::vector<std::uint8_t> buf(static_cast<std::size_t>(sz));
    impl_->nn.supval(idx, buf.data(), buf.size(), tag);
    return buf;
}

Status Node::set_sup(Address index, std::span<const std::uint8_t> data, std::uint8_t tag) {
    if (!impl_)
        return std::unexpected(Error::internal("Node has null impl"));
    nodeidx_t idx = static_cast<nodeidx_t>(index);
    if (!impl_->nn.supset(idx, data.data(), data.size(), tag))
        return std::unexpected(Error::sdk("supset failed"));
    return ida::ok();
}

// ── Hash values ─────────────────────────────────────────────────────────

Result<std::string> Node::hash(std::string_view key, std::uint8_t tag) const {
    if (!impl_)
        return std::unexpected(Error::internal("Node has null impl"));
    qstring qkey = ida::detail::to_qstring(key);

    // hashval writes to a buffer.
    char buf[MAXSPECSIZE];
    ssize_t sz = impl_->nn.hashval(qkey.c_str(), buf, sizeof(buf), tag);
    if (sz <= 0)
        return std::unexpected(Error::not_found("No hash value for key",
                                                std::string(key)));
    return std::string(buf, static_cast<std::size_t>(sz));
}

Status Node::set_hash(std::string_view key, std::string_view value, std::uint8_t tag) {
    if (!impl_)
        return std::unexpected(Error::internal("Node has null impl"));
    qstring qkey = ida::detail::to_qstring(key);
    qstring qval = ida::detail::to_qstring(value);
    if (!impl_->nn.hashset(qkey.c_str(), qval.c_str(), qval.length(), tag))
        return std::unexpected(Error::sdk("hashset failed"));
    return ida::ok();
}

} // namespace ida::storage

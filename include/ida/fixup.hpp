/// \file fixup.hpp
/// \brief Fixup / relocation information.

#ifndef IDAX_FIXUP_HPP
#define IDAX_FIXUP_HPP

#include <ida/error.hpp>
#include <ida/address.hpp>
#include <cstdint>
#include <iterator>
#include <string>
#include <string_view>

namespace ida::fixup {

enum class Type {
    Off8, Off16, Seg16, Ptr16,
    Off32, Ptr32,
    Hi8, Hi16, Low8, Low16,
    Off64,
    Custom,
};

struct Descriptor {
    Address       source{};         ///< Address of the fixup site.
    Type          type{Type::Off32};
    std::uint16_t selector{};
    Address       offset{};         ///< Target offset.
    AddressDelta  displacement{};
};

Result<Descriptor> at(Address source);
Status set(Address source, const Descriptor& fixup);
Status remove(Address source);

/// Check whether a fixup exists at the given address.
bool exists(Address source);

/// Check whether an address range contains any fixups.
bool contains(Address start, AddressSize size);

// ── Traversal ───────────────────────────────────────────────────────────

/// First fixup address, or BadAddress if none.
Result<Address> first();
/// Next fixup address after \p address, or BadAddress if none.
Result<Address> next(Address address);
/// Previous fixup address before \p address, or BadAddress if none.
Result<Address> prev(Address address);

class FixupIterator {
public:
    using iterator_category = std::input_iterator_tag;
    using value_type        = Descriptor;
    using difference_type   = std::ptrdiff_t;
    using pointer           = const Descriptor*;
    using reference         = Descriptor;

    FixupIterator() = default;
    explicit FixupIterator(Address address) : ea_(address) {}

    reference operator*() const;
    FixupIterator& operator++();
    FixupIterator  operator++(int);

    friend bool operator==(const FixupIterator& a, const FixupIterator& b) noexcept {
        return a.ea_ == b.ea_;
    }
    friend bool operator!=(const FixupIterator& a, const FixupIterator& b) noexcept {
        return !(a == b);
    }

private:
    Address ea_{BadAddress};
};

class FixupRange {
public:
    FixupRange() = default;
    explicit FixupRange(Address start, Address end_sentinel)
        : start_(start), end_(end_sentinel) {}
    [[nodiscard]] FixupIterator begin() const { return FixupIterator(start_); }
    [[nodiscard]] FixupIterator end()   const { return FixupIterator(end_); }
private:
    Address start_{BadAddress};
    Address end_{BadAddress};
};

/// Iterable range of all fixups.
FixupRange all();

// ── Custom fixup registration ────────────────────────────────────────────

/// Properties for custom fixup handlers.
enum class HandlerProperty : std::uint32_t {
    Verify     = 0x0001,
    Code       = 0x0002,
    ForceCode  = 0x0004,
    AbsoluteOp = 0x0008,
    SignedOp   = 0x0010,
};

/// Configuration for registering a custom fixup handler.
struct CustomHandler {
    std::string name;
    std::uint32_t properties{0};
    std::uint8_t size{4};
    std::uint8_t width{32};
    std::uint8_t shift{0};
    std::uint32_t reference_type{0};
};

/// Register a custom fixup handler and return its fixup type id (FIXUP_CUSTOM|N).
Result<std::uint16_t> register_custom(const CustomHandler& handler);

/// Unregister a previously registered custom fixup handler.
Status unregister_custom(std::uint16_t custom_type);

/// Resolve a custom fixup handler name to its type id.
Result<std::uint16_t> find_custom(std::string_view name);

} // namespace ida::fixup

#endif // IDAX_FIXUP_HPP

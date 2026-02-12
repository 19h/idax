/// \file segment.hpp
/// \brief Segment operations: creation, query, traversal, properties.
///
/// Every segment is represented by an opaque Segment value object.
/// No SDK segment_t pointers leak into the public interface.

#ifndef IDAX_SEGMENT_HPP
#define IDAX_SEGMENT_HPP

#include <ida/error.hpp>
#include <ida/address.hpp>
#include <cstdint>
#include <iterator>
#include <string>
#include <string_view>

namespace ida::segment {

// ── Enums ───────────────────────────────────────────────────────────────

/// Segment type classification.
enum class Type {
    Normal,
    External,
    Code,
    Data,
    Bss,
    AbsoluteSymbols,
    Common,
    Null,
    Undefined,
};

/// Readable permission flags.
struct Permissions {
    bool read    = false;
    bool write   = false;
    bool execute = false;
};

// ── Segment value object ────────────────────────────────────────────────

/// Opaque snapshot of a segment.  Obtained via at(), by_name(), etc.
/// Modifications are made through free functions (set_name, set_permissions, ...).
class Segment {
public:
    [[nodiscard]] Address     start()      const noexcept { return start_; }
    [[nodiscard]] Address     end()        const noexcept { return end_; }
    [[nodiscard]] AddressSize size()       const noexcept { return end_ - start_; }
    [[nodiscard]] int         bitness()    const noexcept { return bitness_; }
    [[nodiscard]] Permissions permissions() const noexcept { return perm_; }

    [[nodiscard]] std::string name()       const { return name_; }
    [[nodiscard]] std::string class_name() const { return class_; }

    [[nodiscard]] bool is_visible() const noexcept { return visible_; }

    /// Re-read this segment from the database to pick up any changes.
    Status refresh();

private:
    // Allow implementation code (in segment.cpp) to populate fields.
    friend struct SegmentAccess;

    Address     start_{};
    Address     end_{};
    int         bitness_{};
    Permissions perm_{};
    std::string name_;
    std::string class_;
    bool        visible_{true};
};

// ── CRUD ────────────────────────────────────────────────────────────────

Result<Segment> create(Address start, Address end,
                       std::string_view name,
                       std::string_view class_name = {},
                       Type type = Type::Normal);

Status remove(Address address);

// ── Lookup ──────────────────────────────────────────────────────────────

/// Segment containing the given address.
Result<Segment> at(Address address);

/// Segment with the given name.
Result<Segment> by_name(std::string_view name);

/// Segment by its positional index (0-based).
Result<Segment> by_index(std::size_t index);

/// Total number of segments.
Result<std::size_t> count();

// ── Property mutation ───────────────────────────────────────────────────

Status set_name(Address address, std::string_view name);
Status set_class(Address address, std::string_view class_name);
Status set_permissions(Address address, Permissions perm);
Status set_bitness(Address address, int bits);

// ── Traversal ───────────────────────────────────────────────────────────

/// Forward iterator over all segments.
class SegmentIterator {
public:
    using iterator_category = std::input_iterator_tag;
    using value_type        = Segment;
    using difference_type   = std::ptrdiff_t;
    using pointer           = const Segment*;
    using reference         = Segment;

    SegmentIterator() = default;
    explicit SegmentIterator(std::size_t index, std::size_t total);

    reference operator*() const;
    SegmentIterator& operator++();
    SegmentIterator  operator++(int);

    friend bool operator==(const SegmentIterator& a, const SegmentIterator& b) noexcept {
        return a.idx_ == b.idx_;
    }
    friend bool operator!=(const SegmentIterator& a, const SegmentIterator& b) noexcept {
        return !(a == b);
    }

private:
    std::size_t idx_{0};
    std::size_t total_{0};
};

class SegmentRange {
public:
    SegmentRange();
    [[nodiscard]] SegmentIterator begin() const;
    [[nodiscard]] SegmentIterator end()   const;
private:
    std::size_t total_{0};
};

/// Iterable range of all segments.
SegmentRange all();

} // namespace ida::segment

#endif // IDAX_SEGMENT_HPP

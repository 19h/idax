/// \file segment.hpp
/// \brief Segment operations: creation, query, traversal, properties.
///
/// Every segment is represented by an opaque Segment value object.
/// No internal pointers leak into the public interface.

#ifndef IDAX_SEGMENT_HPP
#define IDAX_SEGMENT_HPP

#include <ida/error.hpp>
#include <ida/address.hpp>
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace ida::segment {

// ── Enums ───────────────────────────────────────────────────────────────

/// Segment type classification.
enum class Type {
    Normal,
    External,         ///< External symbols (SEG_XTRN).
    Code,             ///< Pure code segment.
    Data,             ///< Pure data segment.
    Bss,              ///< Uninitialized data.
    AbsoluteSymbols,  ///< Absolute symbols table.
    Common,           ///< Common block.
    Null,             ///< Zero-length or placeholder.
    Undefined,        ///< Unknown/other.
    Import,           ///< Import table (alias for External in some contexts).
    InternalMemory,   ///< Processor internal memory.
    Group,            ///< Group of segments.
};

/// Readable permission flags.
struct Permissions {
    bool read    = false;
    bool write   = false;
    bool execute = false;
};

/// Origin of one segment-register range value.
enum class SegmentRegisterSource {
    Inherited,              ///< Inherited from the preceding range.
    User,                   ///< Explicitly supplied by a user or plugin.
    Analysis,               ///< Derived by processor analysis.
    AnalysisAtSegmentStart, ///< Analysis-derived value at a segment start.
};

/// Owned semantic description of one processor segment register.
struct SegmentRegisterDescriptor {
    std::string name;
    std::size_t bit_width{0};
    bool is_code{false};
    bool is_data{false};

    bool operator==(const SegmentRegisterDescriptor&) const = default;
};

/// Owned half-open range over which a segment-register value is stable.
struct SegmentRegisterRange {
    Address start{};
    Address end{};
    std::optional<std::uint64_t> value;
    SegmentRegisterSource source{SegmentRegisterSource::Inherited};

    bool operator==(const SegmentRegisterRange&) const = default;
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
    [[nodiscard]] Type        type()       const noexcept { return type_; }
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
    Type        type_{Type::Normal};
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
Status set_type(Address address, Type type);
Status set_permissions(Address address, Permissions perm);
Status set_bitness(Address address, int bits);

// ── Segment-register state ─────────────────────────────────────────────

/// Discover the active processor's segment registers in processor order.
Result<std::vector<SegmentRegisterDescriptor>> segment_registers();

/// Effective segment-register value at an address. Unknown is std::nullopt.
Result<std::optional<std::uint64_t>> segment_register_value(
    Address address, std::string_view register_name);

/// Segment default used when no range value is known. Unknown is std::nullopt.
Result<std::optional<std::uint64_t>> default_segment_register_value(
    Address address, std::string_view register_name);

/// Range containing an address.
Result<SegmentRegisterRange> segment_register_range(
    Address address, std::string_view register_name);

/// Range preceding the one containing an address, if any.
Result<std::optional<SegmentRegisterRange>> previous_segment_register_range(
    Address address, std::string_view register_name);

/// All ranges for one named segment register, in address order.
Result<std::vector<SegmentRegisterRange>> segment_register_ranges(
    std::string_view register_name);

/// Positional index of the range containing an address, if any.
Result<std::optional<std::size_t>> segment_register_range_index(
    Address address, std::string_view register_name);

/// Start or replace a range at an address and verify the exact post-state.
Status split_segment_register_range(
    Address address,
    std::string_view register_name,
    std::optional<std::uint64_t> value,
    SegmentRegisterSource source = SegmentRegisterSource::User);

/// Remove the range that starts exactly at an address.
Status remove_segment_register_range(
    Address range_start, std::string_view register_name);

/// Set or clear the default for the containing segment.
Status set_default_segment_register(
    Address address,
    std::string_view register_name,
    std::optional<std::uint64_t> value);

/// Set or clear one named default for every segment.
Status set_default_segment_register_for_all(
    std::string_view register_name,
    std::optional<std::uint64_t> value);

/// Set or clear the active processor's semantic data-register default.
Status set_default_data_segment(std::optional<std::uint64_t> value);

/// Bound a change by assigning the value at the next instruction.
Status set_segment_register_at_next_code(
    Address search_start,
    Address maximum,
    std::string_view register_name,
    std::optional<std::uint64_t> value);

/// Replace destination ranges with copies of source ranges.
Status copy_segment_register_ranges(
    std::string_view destination_register,
    std::string_view source_register,
    bool map_selectors_to_addresses = false);

/// Seed default value of one segment register for the segment containing
/// \p address. Legacy raw-ordinal overload retained for source compatibility.
Status set_default_segment_register(Address address,
                                    int register_index,
                                    std::uint64_t value);

/// Legacy raw-ordinal overload retained for source compatibility.
Status set_default_segment_register_for_all(int register_index,
                                            std::uint64_t value);

/// Set segment comment text at the segment containing \p address.
Result<std::string> comment(Address address, bool repeatable = false);
Status set_comment(Address address, std::string_view text, bool repeatable = false);

/// Resize the segment containing \p address to [new_start, new_end).
Status resize(Address address, Address new_start, Address new_end);

/// Move the segment containing \p address so it starts at \p new_start.
Status move(Address address, Address new_start);

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

/// First segment in database order.
Result<Segment> first();

/// Last segment in database order.
Result<Segment> last();

/// Segment immediately after the one containing \p address.
Result<Segment> next(Address address);

/// Segment immediately before the one containing \p address.
Result<Segment> prev(Address address);

} // namespace ida::segment

#endif // IDAX_SEGMENT_HPP

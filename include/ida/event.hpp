/// \file event.hpp
/// \brief Typed event subscription and RAII scoped subscriptions.
///
/// All callbacks are registered against IDB events (database changes).
/// The event system uses the modern event_listener_t SDK mechanism internally.

#ifndef IDAX_EVENT_HPP
#define IDAX_EVENT_HPP

#include <ida/error.hpp>
#include <ida/address.hpp>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>

namespace ida::event {

/// Opaque subscription handle.
using Token = std::uint64_t;

/// Event kind used by generic event routing callbacks.
enum class EventKind {
    SegmentAdded = 0,
    SegmentDeleted = 1,
    FunctionAdded = 2,
    FunctionDeleted = 3,
    Renamed = 4,
    BytePatched = 5,
    CommentChanged = 6,
    SegmentMoved = 7,
    FunctionUpdated = 8,
    ItemTypeChanged = 9,
    OperandTypeChanged = 10,
    CodeCreated = 11,
    DataCreated = 12,
    ItemsDestroyed = 13,
    ExtraCommentChanged = 14,
    LocalTypesChanged = 15,
};

/// Logical placement of an anterior/posterior extra comment line.
enum class ExtraCommentPlacement {
    Unknown = 0,
    Anterior = 1,
    Posterior = 2,
};

/// Normalized local-type library mutation kind.
enum class LocalTypeChangeKind {
    None = 0,
    Added = 1,
    Deleted = 2,
    Edited = 3,
    Aliased = 4,
    CompilerChanged = 5,
    LibraryLoaded = 6,
    LibraryUnloaded = 7,
    OrdinalsCompacted = 8,
};

/// Snapshot delivered after a segment has moved.
/// Payload references are callback-scoped; copy the value to retain it.
struct SegmentMovedEvent {
    Address from{BadAddress};
    Address to{BadAddress};
    std::size_t size{0};
    bool address_mapping_changed{false};
};

/// Snapshot delivered after an instruction or data item has been created.
/// Payload references are callback-scoped; copy the value to retain it.
struct ItemCreatedEvent {
    Address address{BadAddress};
    std::size_t size{0};
};

/// Snapshot delivered after instructions/data have been destroyed.
/// Payload references are callback-scoped; copy the value to retain it.
struct ItemsDestroyedEvent {
    Address start{BadAddress};
    Address end{BadAddress};
    bool will_disable_range{false};
};

/// Snapshot delivered after an anterior/posterior comment line changes.
/// Payload references are callback-scoped; copy the value to retain it.
struct ExtraCommentChangedEvent {
    Address address{BadAddress};
    ExtraCommentPlacement placement{ExtraCommentPlacement::Unknown};
    int line_index{-1};
    std::string text;
};

/// Snapshot delivered after the local type library changes.
/// Payload references are callback-scoped; copy the value to retain it.
struct LocalTypesChangedEvent {
    LocalTypeChangeKind change{LocalTypeChangeKind::None};
    std::uint32_t ordinal{0};
    std::string name;
};

/// Generic IDB event payload for filtering/routing helpers.
struct Event {
    EventKind kind{};
    Address address{BadAddress};
    Address secondary_address{BadAddress};

    std::string new_name;
    std::string old_name;

    std::uint32_t old_value{0};
    bool repeatable{false};

    std::size_t size{0};
    int operand_index{-1};
    int line_index{-1};
    std::string text;
    bool will_disable_range{false};
    bool address_mapping_changed{false};
    ExtraCommentPlacement extra_comment_placement{ExtraCommentPlacement::Unknown};
    LocalTypeChangeKind local_type_change{LocalTypeChangeKind::None};
    std::uint32_t type_ordinal{0};
    std::string type_name;
};

/// Unsubscribe a previously registered callback.
Status unsubscribe(Token token);

// ── Typed subscription functions ────────────────────────────────────────
// Each returns a Token that can be used to unsubscribe.

/// Called after a segment is created.  Callback receives the segment start address.
Result<Token> on_segment_added(std::function<void(Address start)> callback);

/// Called after a segment is deleted.  Receives the former start and end addresses.
Result<Token> on_segment_deleted(std::function<void(Address start, Address end)> callback);

/// Called after a function is created.  Receives the function entry address.
Result<Token> on_function_added(std::function<void(Address entry)> callback);

/// Called after a function is deleted.  Receives the former entry address.
Result<Token> on_function_deleted(std::function<void(Address entry)> callback);

/// Called after a byte is renamed.  Receives the address, new name, and old name.
/// Either name may be empty if the name was removed/didn't exist.
Result<Token> on_renamed(std::function<void(Address ea, std::string new_name,
                                            std::string old_name)> callback);

/// Called after a byte is patched.  Receives the address and old value.
Result<Token> on_byte_patched(std::function<void(Address ea, std::uint32_t old_value)> callback);

/// Called after a comment is changed.  Receives the address and whether it is repeatable.
Result<Token> on_comment_changed(std::function<void(Address ea, bool repeatable)> callback);

/// Called after a segment is moved. The payload owns all required metadata.
Result<Token> on_segment_moved(
    std::function<void(const SegmentMovedEvent&)> callback);

/// Called after the kernel updates a function. Receives its entry address.
Result<Token> on_function_updated(std::function<void(Address entry)> callback);

/// Called after an item's type information changes. Query `ida::type` for the new type.
Result<Token> on_item_type_changed(std::function<void(Address ea)> callback);

/// Called after an operand representation/type changes.
Result<Token> on_operand_type_changed(
    std::function<void(Address ea, int operand_index)> callback);

/// Called after an instruction is created.
Result<Token> on_code_created(
    std::function<void(const ItemCreatedEvent&)> callback);

/// Called after a data item is created.
Result<Token> on_data_created(
    std::function<void(const ItemCreatedEvent&)> callback);

/// Called after instructions/data are destroyed in `[start, end)`.
Result<Token> on_items_destroyed(
    std::function<void(const ItemsDestroyedEvent&)> callback);

/// Called after an anterior/posterior comment line changes.
Result<Token> on_extra_comment_changed(
    std::function<void(const ExtraCommentChangedEvent&)> callback);

/// Called after the local type library changes.
Result<Token> on_local_types_changed(
    std::function<void(const LocalTypesChangedEvent&)> callback);

// ── Generic filtering/routing helpers ───────────────────────────────────

/// Subscribe to all supported IDB events through one callback.
Result<Token> on_event(std::function<void(const Event&)> callback);

/// Subscribe to all supported IDB events with a predicate filter.
/// Callback is invoked only when `filter(event)` is true.
Result<Token> on_event_filtered(std::function<bool(const Event&)> filter,
                                std::function<void(const Event&)> callback);

// ── RAII subscription guard ─────────────────────────────────────────────

/// RAII subscription guard: unsubscribes on destruction.
class ScopedSubscription {
public:
    ScopedSubscription() = default;
    explicit ScopedSubscription(Token token) : token_(token) {}
    ~ScopedSubscription();

    ScopedSubscription(const ScopedSubscription&) = delete;
    ScopedSubscription& operator=(const ScopedSubscription&) = delete;
    ScopedSubscription(ScopedSubscription&& o) noexcept : token_(o.token_) { o.token_ = 0; }
    ScopedSubscription& operator=(ScopedSubscription&&) noexcept;

    [[nodiscard]] Token token() const noexcept { return token_; }

private:
    Token token_{0};
};

} // namespace ida::event

#endif // IDAX_EVENT_HPP

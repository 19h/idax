/// \file event.hpp
/// \brief Typed event subscription and RAII scoped subscriptions.
///
/// All callbacks are registered against IDB events (database changes).
/// The event system uses the modern event_listener_t SDK mechanism internally.

#ifndef IDAX_EVENT_HPP
#define IDAX_EVENT_HPP

#include <ida/error.hpp>
#include <ida/address.hpp>
#include <cstdint>
#include <functional>
#include <string>

namespace ida::event {

/// Opaque subscription handle.
using Token = std::uint64_t;

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

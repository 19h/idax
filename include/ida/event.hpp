/// \file event.hpp
/// \brief Typed event subscription and RAII scoped subscriptions.

#ifndef IDAX_EVENT_HPP
#define IDAX_EVENT_HPP

#include <ida/error.hpp>
#include <ida/address.hpp>
#include <cstdint>
#include <functional>

namespace ida::event {

/// Opaque subscription handle.
using Token = std::uint64_t;

/// Unsubscribe a previously registered callback.
Status unsubscribe(Token token);

/// RAII subscription guard: unsubscribes on destruction.
class ScopedSubscription {
public:
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

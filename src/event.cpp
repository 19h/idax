/// \file event.cpp
/// \brief Implementation of ida::event — stub for typed event subscription.
///
/// Event subscription requires IDP/HT notification hooking. This file provides
/// stub implementations that return appropriate errors until the full event
/// infrastructure is built.

#include "detail/sdk_bridge.hpp"
#include <ida/event.hpp>

namespace ida::event {

// ── Stub implementations ────────────────────────────────────────────────

Status unsubscribe(Token /*token*/) {
    return std::unexpected(Error::unsupported("Event system not yet implemented"));
}

ScopedSubscription::~ScopedSubscription() {
    if (token_ != 0)
        (void)unsubscribe(token_);
}

ScopedSubscription& ScopedSubscription::operator=(ScopedSubscription&& o) noexcept {
    if (this != &o) {
        if (token_ != 0)
            (void)unsubscribe(token_);
        token_ = o.token_;
        o.token_ = 0;
    }
    return *this;
}

} // namespace ida::event

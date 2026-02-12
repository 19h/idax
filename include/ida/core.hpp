/// \file core.hpp
/// \brief Shared option and configuration structs used across idax domains.

#ifndef IDAX_CORE_HPP
#define IDAX_CORE_HPP

#include <ida/address.hpp>

#include <cstdint>

namespace ida {

/// Common operation policy flags.
struct OperationOptions {
    bool strict_validation{true};
    bool allow_partial_results{false};
    bool cancel_on_user_break{true};
    bool quiet{true};
};

/// Reusable address range options.
struct RangeOptions {
    Address start{BadAddress};
    Address end{BadAddress};
    bool inclusive_end{false};
};

/// Generic wait/poll policy used by blocking operations.
struct WaitOptions {
    std::uint32_t timeout_ms{0};      ///< 0 means no timeout.
    std::uint32_t poll_interval_ms{10};
};

} // namespace ida

#endif // IDAX_CORE_HPP

/// \file analysis.cpp
/// \brief Implementation of ida::analysis — auto-analysis control.

#include "detail/sdk_bridge.hpp"
#include <ida/analysis.hpp>

namespace ida::analysis {

bool is_enabled() {
    return ::is_auto_enabled();
}

Status set_enabled(bool enabled) {
    ::enable_auto(enabled);
    return ida::ok();
}

bool is_idle() {
    return ::auto_is_ok();
}

Status wait() {
    bool ok = ::auto_wait();
    if (!ok)
        return std::unexpected(Error::sdk("auto_wait failed or was cancelled"));
    return ida::ok();
}

Status wait_range(Address start, Address end) {
    ssize_t rc = ::auto_wait_range(start, end);
    if (rc < 0)
        return std::unexpected(Error::sdk("auto_wait_range failed"));
    return ida::ok();
}

Status schedule(Address ea) {
    ::auto_mark_range(ea, ea + 1, AU_CODE);
    return ida::ok();
}

Status schedule_range(Address start, Address end) {
    ::auto_mark_range(start, end, AU_CODE);
    return ida::ok();
}

} // namespace ida::analysis

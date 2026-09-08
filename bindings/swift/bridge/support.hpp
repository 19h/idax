#ifndef IDAX_SWIFT_SUPPORT_HPP
#define IDAX_SWIFT_SUPPORT_HPP

#include "bridge.h"
#include <ida/error.hpp>
#include <exception>
#include <utility>

namespace idax::swift {
void clear_error(IdaxSwiftError* error) noexcept;
int write_error(const ida::Error& error, IdaxSwiftError* output) noexcept;
int require_runtime_thread(IdaxSwiftError* error) noexcept;

template <typename Function>
int protect(IdaxSwiftError* error, Function&& function) noexcept {
    clear_error(error);
    try {
        return std::forward<Function>(function)();
    } catch (const ida::Error& failure) {
        return write_error(failure, error);
    } catch (const std::exception& failure) {
        idax_swift_error_set(error, 6, 0, failure.what(), "Swift native bridge");
    } catch (...) {
        idax_swift_error_set(error, 6, 0, "Unknown native exception", "Swift native bridge");
    }
    return -1;
}
}
#endif

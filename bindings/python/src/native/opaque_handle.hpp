#ifndef IDAX_PYTHON_OPAQUE_HANDLE_HPP
#define IDAX_PYTHON_OPAQUE_HANDLE_HPP

#include "common.hpp"

#include <memory>

namespace idax::python {

struct OpaqueHandleState {
    bool valid{true};
};

class OpaqueHostHandle {
public:
    OpaqueHostHandle() = default;

    OpaqueHostHandle(void* pointer, std::string kind,
                     std::shared_ptr<OpaqueHandleState> state)
        : pointer_(pointer), kind_(std::move(kind)), state_(std::move(state)) {}

    [[nodiscard]] bool valid() const noexcept {
        return pointer_ != nullptr && state_ && state_->valid;
    }

    [[nodiscard]] const std::string& kind() const noexcept { return kind_; }

    void* get(std::string_view operation) const {
        if (!valid()) {
            throw_error(ida::Error::conflict(
                "Opaque host handle is no longer valid", std::string(operation)));
        }
        return pointer_;
    }

private:
    void* pointer_{nullptr};
    std::string kind_;
    std::shared_ptr<OpaqueHandleState> state_;
};

} // namespace idax::python

#endif // IDAX_PYTHON_OPAQUE_HANDLE_HPP

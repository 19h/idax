#ifndef IDAX_PYTHON_DECOMPILER_PYTHON_HPP
#define IDAX_PYTHON_DECOMPILER_PYTHON_HPP

#include "common.hpp"

#include <memory>

namespace idax::python {

struct CallbackPointer {
    void* pointer{nullptr};
    bool valid{true};

    void* get(std::string_view operation) const {
        if (!valid || pointer == nullptr) {
            throw_error(ida::Error::conflict(
                "Decompiler callback handle is no longer valid",
                std::string(operation)));
        }
        return pointer;
    }

    void invalidate() noexcept {
        valid = false;
        pointer = nullptr;
    }
};

struct PythonPseudocodeEvent {
    explicit PythonPseudocodeEvent(const ida::decompiler::PseudocodeEvent& event)
        : function_address(event.function_address),
          cfunc(std::make_shared<CallbackPointer>(
              CallbackPointer{event.cfunc_handle, true})) {}

    ida::Address function_address{ida::BadAddress};
    std::shared_ptr<CallbackPointer> cfunc;
};

struct PythonCursorPositionEvent {
    explicit PythonCursorPositionEvent(
        const ida::decompiler::CursorPositionEvent& event)
        : function_address(event.function_address),
          cursor_address(event.cursor_address),
          view(std::make_shared<CallbackPointer>(
              CallbackPointer{event.view_handle, true})) {}

    ida::Address function_address{ida::BadAddress};
    ida::Address cursor_address{ida::BadAddress};
    std::shared_ptr<CallbackPointer> view;
};

struct PythonHintRequestEvent {
    explicit PythonHintRequestEvent(
        const ida::decompiler::HintRequestEvent& event)
        : function_address(event.function_address),
          item_address(event.item_address),
          view(std::make_shared<CallbackPointer>(
              CallbackPointer{event.view_handle, true})) {}

    ida::Address function_address{ida::BadAddress};
    ida::Address item_address{ida::BadAddress};
    std::shared_ptr<CallbackPointer> view;
};

struct PythonPopulatingPopupEvent {
    explicit PythonPopulatingPopupEvent(
        const ida::decompiler::PopulatingPopupEvent& event)
        : function_address(event.function_address),
          widget(std::make_shared<CallbackPointer>(
              CallbackPointer{event.widget_handle, true})),
          popup(std::make_shared<CallbackPointer>(
              CallbackPointer{event.popup_handle, true})),
          view(std::make_shared<CallbackPointer>(
              CallbackPointer{event.view_handle, true})) {}

    ida::Address function_address{ida::BadAddress};
    std::shared_ptr<CallbackPointer> widget;
    std::shared_ptr<CallbackPointer> popup;
    std::shared_ptr<CallbackPointer> view;
};

void bind_decompiler_microcode(py::module_& decompiler);
void bind_decompiler_ctree(py::module_& decompiler);

} // namespace idax::python

#endif // IDAX_PYTHON_DECOMPILER_PYTHON_HPP

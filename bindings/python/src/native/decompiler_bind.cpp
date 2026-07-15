#include "decompiler_python.hpp"

namespace idax::python {

namespace {

template <typename... Arguments>
void invoke_decompiler_callback(const py::function& callback,
                                Arguments&&... arguments) noexcept {
    py::gil_scoped_acquire acquire;
    try {
        callback(std::forward<Arguments>(arguments)...);
    } catch (py::error_already_set& error) {
        error.discard_as_unraisable(callback);
    } catch (...) {
        PyErr_SetString(PyExc_RuntimeError, "non-Python decompiler callback failure");
        PyErr_WriteUnraisable(callback.ptr());
    }
}

template <typename Adapter, typename Native>
void invoke_ephemeral(const py::function& callback, const Native& native) noexcept {
    py::gil_scoped_acquire acquire;
    Adapter event(native);
    try {
        callback(event);
    } catch (py::error_already_set& error) {
        error.discard_as_unraisable(callback);
    } catch (...) {
        PyErr_SetString(PyExc_RuntimeError, "non-Python decompiler callback failure");
        PyErr_WriteUnraisable(callback.ptr());
    }
    if constexpr (std::is_same_v<Adapter, PythonPseudocodeEvent>) {
        event.cfunc->invalidate();
    } else if constexpr (std::is_same_v<Adapter, PythonCursorPositionEvent>
                         || std::is_same_v<Adapter, PythonHintRequestEvent>) {
        event.view->invalidate();
    } else {
        event.widget->invalidate();
        event.popup->invalidate();
        event.view->invalidate();
    }
}

ida::decompiler::HintResult invoke_hint(
    const py::function& callback,
    const ida::decompiler::HintRequestEvent& native) noexcept {
    py::gil_scoped_acquire acquire;
    PythonHintRequestEvent event(native);
    try {
        auto result = callback(event).cast<ida::decompiler::HintResult>();
        event.view->invalidate();
        return result;
    } catch (py::error_already_set& error) {
        error.discard_as_unraisable(callback);
    } catch (...) {
        PyErr_SetString(PyExc_RuntimeError, "non-Python decompiler hint failure");
        PyErr_WriteUnraisable(callback.ptr());
    }
    event.view->invalidate();
    return {};
}

} // namespace

void bind_decompiler(py::module_& module) {
    py::module_ decompiler = module.def_submodule(
        "decompiler", "Hex-Rays sessions, ctree, microcode, and pseudocode.");

    py::native_enum<ida::decompiler::Maturity>(decompiler, "Maturity", "enum.Enum")
        .value("ZERO", ida::decompiler::Maturity::Zero)
        .value("BUILT", ida::decompiler::Maturity::Built)
        .value("TRANS1", ida::decompiler::Maturity::Trans1)
        .value("NICE", ida::decompiler::Maturity::Nice)
        .value("TRANS2", ida::decompiler::Maturity::Trans2)
        .value("CPA", ida::decompiler::Maturity::Cpa)
        .value("TRANS3", ida::decompiler::Maturity::Trans3)
        .value("CASTED", ida::decompiler::Maturity::Casted)
        .value("FINAL", ida::decompiler::Maturity::Final)
        .finalize();

    py::class_<ida::decompiler::MaturityEvent>(decompiler, "MaturityEvent")
        .def(py::init<>())
        .def_readwrite("function_address",
                       &ida::decompiler::MaturityEvent::function_address)
        .def_readwrite("new_maturity",
                       &ida::decompiler::MaturityEvent::new_maturity);
    py::class_<ida::decompiler::HintResult>(decompiler, "HintResult")
        .def(py::init<>())
        .def_readwrite("text", &ida::decompiler::HintResult::text)
        .def_readwrite("lines", &ida::decompiler::HintResult::lines);
    py::class_<PythonPseudocodeEvent>(decompiler, "PseudocodeEvent")
        .def_readonly("function_address", &PythonPseudocodeEvent::function_address)
        .def("raw_lines", [](const PythonPseudocodeEvent& self) {
            return runtime_result("decompiler.PseudocodeEvent.raw_lines", [&] {
                return ida::decompiler::raw_pseudocode_lines(
                    self.cfunc->get("raw_lines"));
            });
        })
        .def("set_raw_line", [](const PythonPseudocodeEvent& self,
                                  std::size_t index, std::string text) {
            runtime_status("decompiler.PseudocodeEvent.set_raw_line", [&] {
                return ida::decompiler::set_pseudocode_line(
                    self.cfunc->get("set_raw_line"), index, text);
            });
        }, py::arg("line_index"), py::arg("tagged_text"))
        .def_property_readonly("header_line_count", [](
            const PythonPseudocodeEvent& self) {
            return runtime_result("decompiler.PseudocodeEvent.header_line_count", [&] {
                return ida::decompiler::pseudocode_header_line_count(
                    self.cfunc->get("header_line_count"));
            });
        });
    py::class_<PythonCursorPositionEvent>(decompiler, "CursorPositionEvent")
        .def_readonly("function_address",
                      &PythonCursorPositionEvent::function_address)
        .def_readonly("cursor_address", &PythonCursorPositionEvent::cursor_address);
    py::class_<PythonHintRequestEvent>(decompiler, "HintRequestEvent")
        .def_readonly("function_address", &PythonHintRequestEvent::function_address)
        .def_readonly("item_address", &PythonHintRequestEvent::item_address);
    py::class_<PythonPopulatingPopupEvent>(decompiler, "PopulatingPopupEvent")
        .def_readonly("function_address",
                      &PythonPopulatingPopupEvent::function_address);

    py::class_<ida::decompiler::ScopedSession>(decompiler, "ScopedSession")
        .def_property_readonly("valid", &ida::decompiler::ScopedSession::valid)
        .def("close", [](ida::decompiler::ScopedSession& self) {
            runtime_status("decompiler.ScopedSession.close", [&] {
                return self.close();
            });
        })
        .def("__bool__", &ida::decompiler::ScopedSession::valid)
        .def("__enter__", [](ida::decompiler::ScopedSession& self)
             -> ida::decompiler::ScopedSession& { return self; },
             py::return_value_policy::reference_internal)
        .def("__exit__", [](ida::decompiler::ScopedSession& self,
                             py::object, py::object, py::object) {
            if (self.valid())
                unwrap(self.close());
            return false;
        });
    py::class_<ida::decompiler::ScopedSubscription>(
        decompiler, "ScopedSubscription")
        .def(py::init<ida::decompiler::Token>(), py::arg("token") = 0)
        .def_property_readonly("token", &ida::decompiler::ScopedSubscription::token)
        .def_property_readonly("valid", &ida::decompiler::ScopedSubscription::valid)
        .def("close", &ida::decompiler::ScopedSubscription::reset)
        .def("reset", &ida::decompiler::ScopedSubscription::reset)
        .def("__enter__", [](ida::decompiler::ScopedSubscription& self)
             -> ida::decompiler::ScopedSubscription& { return self; },
             py::return_value_policy::reference_internal)
        .def("__exit__", [](ida::decompiler::ScopedSubscription& self,
                             py::object, py::object, py::object) {
            self.reset();
            return false;
        });

    decompiler.def("initialize", [] {
        return runtime_result("decompiler.initialize", ida::decompiler::initialize);
    });
    decompiler.def("available", [] {
        return runtime_result("decompiler.available", ida::decompiler::available);
    });
    decompiler.def("unsubscribe", [](ida::decompiler::Token token) {
        runtime_status("decompiler.unsubscribe", [=] {
            return ida::decompiler::unsubscribe(token);
        });
    }, py::arg("token"));
    decompiler.def("mark_dirty", [](ida::Address address, bool close_views) {
        runtime_status("decompiler.mark_dirty", [=] {
            return ida::decompiler::mark_dirty(address, close_views);
        });
    }, py::arg("function_address"), py::arg("close_views") = false);
    decompiler.def("mark_dirty_with_callers", [](
        ida::Address address, bool close_views) {
        runtime_status("decompiler.mark_dirty_with_callers", [=] {
            return ida::decompiler::mark_dirty_with_callers(address, close_views);
        });
    }, py::arg("function_address"), py::arg("close_views") = false);

    decompiler.def("on_maturity_changed", [](py::function callback) {
        return runtime_result("decompiler.on_maturity_changed", [&] {
            return ida::decompiler::on_maturity_changed(
                [callback = std::move(callback)](
                    const ida::decompiler::MaturityEvent& event) {
                    invoke_decompiler_callback(callback, event);
                });
        });
    }, py::arg("callback"));
#define IDAX_PY_DECOMPILER_PSEUDOCODE_EVENT(fn)                          \
    decompiler.def(#fn, [](py::function callback) {                      \
        return runtime_result("decompiler." #fn, [&] {                  \
            return ida::decompiler::fn([callback = std::move(callback)]( \
                const ida::decompiler::PseudocodeEvent& event) {         \
                invoke_ephemeral<PythonPseudocodeEvent>(callback, event); \
            });                                                           \
        });                                                               \
    }, py::arg("callback"))
    IDAX_PY_DECOMPILER_PSEUDOCODE_EVENT(on_func_printed);
    IDAX_PY_DECOMPILER_PSEUDOCODE_EVENT(on_refresh_pseudocode);
    IDAX_PY_DECOMPILER_PSEUDOCODE_EVENT(on_switch_pseudocode);
#undef IDAX_PY_DECOMPILER_PSEUDOCODE_EVENT
    decompiler.def("on_curpos_changed", [](py::function callback) {
        return runtime_result("decompiler.on_curpos_changed", [&] {
            return ida::decompiler::on_curpos_changed(
                [callback = std::move(callback)](
                    const ida::decompiler::CursorPositionEvent& event) {
                    invoke_ephemeral<PythonCursorPositionEvent>(callback, event);
                });
        });
    }, py::arg("callback"));
    decompiler.def("on_create_hint", [](py::function callback) {
        return runtime_result("decompiler.on_create_hint", [&] {
            return ida::decompiler::on_create_hint(
                [callback = std::move(callback)](
                    const ida::decompiler::HintRequestEvent& event) {
                    return invoke_hint(callback, event);
                });
        });
    }, py::arg("callback"));
    decompiler.def("on_populating_popup", [](py::function callback) {
        return runtime_result("decompiler.on_populating_popup", [&] {
            return ida::decompiler::on_populating_popup(
                [callback = std::move(callback)](
                    const ida::decompiler::PopulatingPopupEvent& event) {
                    invoke_ephemeral<PythonPopulatingPopupEvent>(callback, event);
                });
        });
    }, py::arg("callback"));

    bind_decompiler_microcode(decompiler);
    bind_decompiler_ctree(decompiler);
}

} // namespace idax::python

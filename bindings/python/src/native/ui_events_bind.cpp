#include "ui_python.hpp"

#include <memory>

namespace idax::python {

namespace {

template <typename... Arguments>
void invoke_ui_event(const py::function& callback,
                     Arguments&&... arguments) noexcept {
    py::gil_scoped_acquire acquire;
    try {
        callback(std::forward<Arguments>(arguments)...);
    } catch (py::error_already_set& error) {
        error.discard_as_unraisable(callback);
    } catch (...) {
        PyErr_SetString(PyExc_RuntimeError, "Non-Python UI event callback failure");
        PyErr_WriteUnraisable(callback.ptr());
    }
}

template <typename... Arguments>
bool invoke_ui_filter(const py::function& callback,
                      Arguments&&... arguments) noexcept {
    py::gil_scoped_acquire acquire;
    try {
        return callback(std::forward<Arguments>(arguments)...).template cast<bool>();
    } catch (py::error_already_set& error) {
        error.discard_as_unraisable(callback);
    } catch (...) {
        PyErr_SetString(PyExc_RuntimeError, "Non-Python UI event filter failure");
        PyErr_WriteUnraisable(callback.ptr());
    }
    return false;
}

class PythonPopupEvent {
public:
    PythonPopupEvent(const ida::ui::PopupEvent& event,
                     std::shared_ptr<OpaqueHandleState> state)
        : widget(event.widget),
          popup(event.popup, "popup", std::move(state)),
          type(event.type) {}

    ida::ui::Widget widget;
    OpaqueHostHandle popup;
    ida::ui::WidgetType type{ida::ui::WidgetType::Unknown};
};

class PythonRenderingEvent {
public:
    explicit PythonRenderingEvent(const ida::ui::RenderingEvent& event)
        : widget(event.widget), type(event.type), entries(event.entries) {}

    ida::ui::Widget widget;
    ida::ui::WidgetType type{ida::ui::WidgetType::Unknown};
    std::vector<ida::ui::LineRenderEntry> entries;
};

template <typename Function>
void bind_ui_subscription(py::module_& ui, const char* name,
                          Function&& function) {
    ui.def(name, std::forward<Function>(function), py::arg("callback"));
}

} // namespace

void bind_ui_events(py::module_& ui) {
    py::native_enum<ida::ui::EventKind>(ui, "EventKind", "enum.Enum")
        .value("DATABASE_INITED", ida::ui::EventKind::DatabaseInited)
        .value("DATABASE_CLOSED", ida::ui::EventKind::DatabaseClosed)
        .value("READY_TO_RUN", ida::ui::EventKind::ReadyToRun)
        .value("CURRENT_WIDGET_CHANGED", ida::ui::EventKind::CurrentWidgetChanged)
        .value("SCREEN_ADDRESS_CHANGED", ida::ui::EventKind::ScreenAddressChanged)
        .value("WIDGET_VISIBLE", ida::ui::EventKind::WidgetVisible)
        .value("WIDGET_INVISIBLE", ida::ui::EventKind::WidgetInvisible)
        .value("WIDGET_CLOSING", ida::ui::EventKind::WidgetClosing)
        .value("VIEW_ACTIVATED", ida::ui::EventKind::ViewActivated)
        .value("VIEW_DEACTIVATED", ida::ui::EventKind::ViewDeactivated)
        .value("VIEW_CREATED", ida::ui::EventKind::ViewCreated)
        .value("VIEW_CLOSED", ida::ui::EventKind::ViewClosed)
        .value("CURSOR_CHANGED", ida::ui::EventKind::CursorChanged)
        .finalize();

    py::class_<ida::ui::Event>(ui, "Event")
        .def(py::init<>())
        .def_readwrite("kind", &ida::ui::Event::kind)
        .def_readwrite("address", &ida::ui::Event::address)
        .def_readwrite("previous_address", &ida::ui::Event::previous_address)
        .def_readwrite("previous_widget", &ida::ui::Event::previous_widget)
        .def_readwrite("is_new_database", &ida::ui::Event::is_new_database)
        .def_readwrite("startup_script", &ida::ui::Event::startup_script)
        .def_readwrite("widget", &ida::ui::Event::widget)
        .def_readwrite("widget_title", &ida::ui::Event::widget_title);
    py::class_<ida::ui::ScopedSubscription>(ui, "ScopedSubscription")
        .def(py::init<ida::ui::Token>(), py::arg("token") = 0)
        .def_property_readonly("token", &ida::ui::ScopedSubscription::token)
        .def("close", [](ida::ui::ScopedSubscription& self) {
            self = ida::ui::ScopedSubscription{};
        })
        .def("__enter__", [](ida::ui::ScopedSubscription& self)
             -> ida::ui::ScopedSubscription& { return self; },
             py::return_value_policy::reference_internal)
        .def("__exit__", [](ida::ui::ScopedSubscription& self,
                              py::object, py::object, py::object) {
            self = ida::ui::ScopedSubscription{};
            return false;
        });
    py::class_<PythonPopupEvent>(ui, "PopupEvent")
        .def_readonly("widget", &PythonPopupEvent::widget)
        .def_readonly("popup", &PythonPopupEvent::popup)
        .def_readonly("type", &PythonPopupEvent::type);
    py::class_<ida::ui::LineRenderEntry>(ui, "LineRenderEntry")
        .def(py::init<>())
        .def_readwrite("line_number", &ida::ui::LineRenderEntry::line_number)
        .def_readwrite("background_color", &ida::ui::LineRenderEntry::bg_color)
        .def_readwrite("start_column", &ida::ui::LineRenderEntry::start_column)
        .def_readwrite("length", &ida::ui::LineRenderEntry::length)
        .def_readwrite("character_range", &ida::ui::LineRenderEntry::character_range);
    py::class_<PythonRenderingEvent>(ui, "RenderingEvent")
        .def_readonly("widget", &PythonRenderingEvent::widget)
        .def_readonly("type", &PythonRenderingEvent::type)
        .def_readwrite("entries", &PythonRenderingEvent::entries);

    bind_ui_subscription(ui, "on_database_closed", [](py::function callback) {
        return runtime_result("ui.on_database_closed", [&] {
            return ida::ui::on_database_closed(
                [callback = std::move(callback)] {
                    invoke_ui_event(callback);
                });
        });
    });
    bind_ui_subscription(ui, "on_database_inited", [](py::function callback) {
        return runtime_result("ui.on_database_inited", [&] {
            return ida::ui::on_database_inited(
                [callback = std::move(callback)](bool is_new, std::string script) {
                    invoke_ui_event(callback, is_new, std::move(script));
                });
        });
    });
    bind_ui_subscription(ui, "on_ready_to_run", [](py::function callback) {
        return runtime_result("ui.on_ready_to_run", [&] {
            return ida::ui::on_ready_to_run(
                [callback = std::move(callback)] {
                    invoke_ui_event(callback);
                });
        });
    });
    bind_ui_subscription(ui, "on_screen_ea_changed", [](py::function callback) {
        return runtime_result("ui.on_screen_ea_changed", [&] {
            return ida::ui::on_screen_ea_changed(
                [callback = std::move(callback)](
                    ida::Address current, ida::Address previous) {
                    invoke_ui_event(callback, current, previous);
                });
        });
    });
    bind_ui_subscription(ui, "on_current_widget_changed", [](
        py::function callback) {
        return runtime_result("ui.on_current_widget_changed", [&] {
            return ida::ui::on_current_widget_changed(
                [callback = std::move(callback)](
                    ida::ui::Widget current, ida::ui::Widget previous) {
                    invoke_ui_event(callback, current, previous);
                });
        });
    });

#define IDAX_PY_UI_TITLE_SUBSCRIPTION(name)                              \
    ui.def(#name, [](py::function callback) {                            \
        return runtime_result("ui." #name, [&] {                        \
            return ida::ui::name([callback = std::move(callback)](       \
                std::string title) {                                     \
                invoke_ui_event(callback, std::move(title));             \
            });                                                          \
        });                                                              \
    }, py::arg("callback"));                                             \
    ui.def(#name, [](const ida::ui::Widget& widget, py::function callback) { \
        return runtime_result("ui." #name, [&] {                        \
            return ida::ui::name(widget, [callback = std::move(callback)]( \
                ida::ui::Widget value) {                                 \
                invoke_ui_event(callback, value);                        \
            });                                                          \
        });                                                              \
    }, py::arg("widget"), py::arg("callback"))
    IDAX_PY_UI_TITLE_SUBSCRIPTION(on_widget_visible);
    IDAX_PY_UI_TITLE_SUBSCRIPTION(on_widget_invisible);
    IDAX_PY_UI_TITLE_SUBSCRIPTION(on_widget_closing);
#undef IDAX_PY_UI_TITLE_SUBSCRIPTION

    bind_ui_subscription(ui, "on_cursor_changed", [](py::function callback) {
        return runtime_result("ui.on_cursor_changed", [&] {
            return ida::ui::on_cursor_changed(
                [callback = std::move(callback)](ida::Address address) {
                    invoke_ui_event(callback, address);
                });
        });
    });
#define IDAX_PY_UI_VIEW_SUBSCRIPTION(name)                               \
    bind_ui_subscription(ui, #name, [](py::function callback) {          \
        return runtime_result("ui." #name, [&] {                        \
            return ida::ui::name([callback = std::move(callback)](       \
                ida::ui::Widget widget) {                                \
                invoke_ui_event(callback, widget);                       \
            });                                                          \
        });                                                              \
    })
    IDAX_PY_UI_VIEW_SUBSCRIPTION(on_view_activated);
    IDAX_PY_UI_VIEW_SUBSCRIPTION(on_view_deactivated);
    IDAX_PY_UI_VIEW_SUBSCRIPTION(on_view_created);
    IDAX_PY_UI_VIEW_SUBSCRIPTION(on_view_closed);
#undef IDAX_PY_UI_VIEW_SUBSCRIPTION

    bind_ui_subscription(ui, "on_event", [](py::function callback) {
        return runtime_result("ui.on_event", [&] {
            return ida::ui::on_event(
                [callback = std::move(callback)](const ida::ui::Event& event) {
                    invoke_ui_event(callback, ida::ui::Event(event));
                });
        });
    });
    ui.def("on_event_filtered", [](py::function filter,
                                      py::function callback) {
        return runtime_result("ui.on_event_filtered", [&] {
            return ida::ui::on_event_filtered(
                [filter = std::move(filter)](const ida::ui::Event& event) {
                    return invoke_ui_filter(filter, ida::ui::Event(event));
                },
                [callback = std::move(callback)](const ida::ui::Event& event) {
                    invoke_ui_event(callback, ida::ui::Event(event));
                });
        });
    }, py::arg("filter"), py::arg("callback"));
    ui.def("unsubscribe", [](ida::ui::Token token) {
        runtime_status("ui.unsubscribe", [=] { return ida::ui::unsubscribe(token); });
    }, py::arg("token"));

    bind_ui_subscription(ui, "on_popup_ready", [](py::function callback) {
        return runtime_result("ui.on_popup_ready", [&] {
            return ida::ui::on_popup_ready(
                [callback = std::move(callback)](const ida::ui::PopupEvent& event) {
                    py::gil_scoped_acquire acquire;
                    auto state = std::make_shared<OpaqueHandleState>();
                    PythonPopupEvent adapter(event, state);
                    try {
                        callback(adapter);
                    } catch (py::error_already_set& error) {
                        error.discard_as_unraisable(callback);
                    } catch (...) {
                        PyErr_SetString(
                            PyExc_RuntimeError,
                            "Non-Python popup callback failure");
                        PyErr_WriteUnraisable(callback.ptr());
                    }
                    state->valid = false;
                });
        });
    });
    ui.def("attach_dynamic_action", [](const OpaqueHostHandle& popup,
        const ida::ui::Widget& widget, std::string action_id,
        std::string label, py::function handler, std::string menu_path,
        int icon) {
        runtime_status("ui.attach_dynamic_action", [&] {
            return ida::ui::attach_dynamic_action(
                popup.get("ui.attach_dynamic_action"), widget, action_id,
                label, [handler = std::move(handler)] {
                    invoke_ui_event(handler);
                }, menu_path, icon);
        });
    }, py::arg("popup"), py::arg("widget"), py::arg("action_id"),
       py::arg("label"), py::arg("handler"), py::arg("menu_path") = "",
       py::arg("icon") = -1);
    ui.def("attach_registered_action", [](const OpaqueHostHandle& popup,
        py::object widget, std::string action_id, std::string menu_path) {
        runtime_status("ui.attach_registered_action", [&] {
            if (py::isinstance<ida::ui::Widget>(widget)) {
                return ida::ui::attach_registered_action(
                    popup.get("ui.attach_registered_action"),
                    widget.cast<const ida::ui::Widget&>(), action_id, menu_path);
            }
            return ida::ui::attach_registered_action(
                popup.get("ui.attach_registered_action"),
                widget.cast<const OpaqueHostHandle&>().get(
                    "ui.attach_registered_action.widget"),
                action_id, menu_path);
        });
    }, py::arg("popup"), py::arg("widget"), py::arg("action_id"),
       py::arg("menu_path") = "");
    bind_ui_subscription(ui, "on_rendering_info", [](py::function callback) {
        return runtime_result("ui.on_rendering_info", [&] {
            return ida::ui::on_rendering_info(
                [callback = std::move(callback)](ida::ui::RenderingEvent& event) {
                    py::gil_scoped_acquire acquire;
                    PythonRenderingEvent adapter(event);
                    try {
                        callback(adapter);
                        event.entries = std::move(adapter.entries);
                    } catch (py::error_already_set& error) {
                        error.discard_as_unraisable(callback);
                    } catch (...) {
                        PyErr_SetString(
                            PyExc_RuntimeError,
                            "Non-Python rendering callback failure");
                        PyErr_WriteUnraisable(callback.ptr());
                    }
                });
        });
    });
}

} // namespace idax::python

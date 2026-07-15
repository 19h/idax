#include "opaque_handle.hpp"

#include <memory>
#include <unordered_map>

namespace idax::python {

namespace {

template <typename... Arguments>
ida::Status invoke_python_status(const py::object& callback,
                                 std::string_view operation,
                                 Arguments&&... arguments) noexcept {
    py::gil_scoped_acquire acquire;
    try {
        callback(std::forward<Arguments>(arguments)...);
        return ida::ok();
    } catch (py::error_already_set& error) {
        std::string detail = error.what();
        error.discard_as_unraisable(callback);
        return std::unexpected(ida::Error::internal(
            "Python callback failed", std::string(operation) + ":" + detail));
    } catch (...) {
        return std::unexpected(ida::Error::internal(
            "Non-Python callback failure", std::string(operation)));
    }
}

template <typename... Arguments>
bool invoke_python_bool(const py::object& callback,
                        std::string_view operation,
                        bool fallback,
                        Arguments&&... arguments) noexcept {
    py::gil_scoped_acquire acquire;
    try {
        return callback(std::forward<Arguments>(arguments)...)
            .template cast<bool>();
    } catch (py::error_already_set& error) {
        error.discard_as_unraisable(callback);
    } catch (...) {
        PyErr_SetString(PyExc_RuntimeError, std::string(operation).c_str());
        PyErr_WriteUnraisable(callback.ptr());
    }
    return fallback;
}

class PythonActionContext {
public:
    explicit PythonActionContext(const ida::plugin::ActionContext& context)
        : action_id(context.action_id),
          widget_title(context.widget_title),
          widget_type(context.widget_type),
          current_address(context.current_address),
          current_value(context.current_value),
          has_selection(context.has_selection),
          is_external_address(context.is_external_address),
          register_name(context.register_name),
          type_ref(context.type_ref),
          widget_(context.widget_handle),
          focused_widget_(context.focused_widget_handle),
          decompiler_view_(context.decompiler_view_handle),
          state_(std::make_shared<OpaqueHandleState>()) {}

    void invalidate() noexcept { state_->valid = false; }

    OpaqueHostHandle widget_host() const {
        if (widget_ == nullptr)
            throw_error(ida::Error::not_found(
                "Action context does not include widget host"));
        return OpaqueHostHandle(widget_, "widget", state_);
    }
    OpaqueHostHandle focused_widget_host() const {
        return OpaqueHostHandle(focused_widget_, "focused_widget", state_);
    }
    OpaqueHostHandle decompiler_view_host() const {
        if (decompiler_view_ == nullptr)
            throw_error(ida::Error::not_found(
                "Action context does not include decompiler view host"));
        return OpaqueHostHandle(decompiler_view_, "decompiler_view", state_);
    }

    std::string action_id;
    std::string widget_title;
    int widget_type{-1};
    ida::Address current_address{ida::BadAddress};
    std::uint64_t current_value{0};
    bool has_selection{false};
    bool is_external_address{false};
    std::string register_name;
    std::optional<ida::plugin::TypeRef> type_ref;

private:
    void* widget_{nullptr};
    void* focused_widget_{nullptr};
    void* decompiler_view_{nullptr};
    std::shared_ptr<OpaqueHandleState> state_;
};

class PythonAction {
public:
    std::string id;
    std::string label;
    std::string hotkey;
    std::string tooltip;
    int icon{-1};
    py::object handler{py::none()};
    py::object handler_with_context{py::none()};
    py::object enabled{py::none()};
    py::object enabled_with_context{py::none()};

    ida::plugin::Action native() const {
        ida::plugin::Action action;
        action.id = id;
        action.label = label;
        action.hotkey = hotkey;
        action.tooltip = tooltip;
        action.icon = icon;
        if (!handler.is_none()) {
            py::object callback = handler;
            action.handler = [callback = std::move(callback)] {
                return invoke_python_status(callback, "plugin.Action.handler");
            };
        }
        if (!handler_with_context.is_none()) {
            py::object callback = handler_with_context;
            action.handler_with_context = [callback = std::move(callback)](
                const ida::plugin::ActionContext& context) {
                PythonActionContext adapter(context);
                auto status = invoke_python_status(
                    callback, "plugin.Action.handler_with_context", adapter);
                adapter.invalidate();
                return status;
            };
        }
        if (!enabled.is_none()) {
            py::object callback = enabled;
            action.enabled = [callback = std::move(callback)] {
                return invoke_python_bool(
                    callback, "plugin.Action.enabled", false);
            };
        }
        if (!enabled_with_context.is_none()) {
            py::object callback = enabled_with_context;
            action.enabled_with_context = [callback = std::move(callback)](
                const ida::plugin::ActionContext& context) {
                PythonActionContext adapter(context);
                const bool result = invoke_python_bool(
                    callback, "plugin.Action.enabled_with_context", false, adapter);
                adapter.invalidate();
                return result;
            };
        }
        return action;
    }
};

std::unordered_map<std::string, py::object>& action_roots() {
    static std::unordered_map<std::string, py::object> roots;
    return roots;
}

class PythonPlugin final : public ida::plugin::Plugin {
public:
    using ida::plugin::Plugin::Plugin;

    ida::plugin::Info info() const override {
        py::gil_scoped_acquire acquire;
        py::function override = py::get_override(this, "info");
        if (!override)
            return {};
        try {
            return override().cast<ida::plugin::Info>();
        } catch (py::error_already_set& error) {
            error.discard_as_unraisable(override);
            return {};
        } catch (...) {
            PyErr_SetString(PyExc_RuntimeError,
                            "Python Plugin.info must return Info");
            PyErr_WriteUnraisable(override.ptr());
            return {};
        }
    }

    bool init() override {
        py::gil_scoped_acquire acquire;
        py::function override = py::get_override(this, "init");
        if (!override)
            return ida::plugin::Plugin::init();
        return invoke_python_bool(
            override, "plugin.Plugin.init", false);
    }

    void term() override {
        py::gil_scoped_acquire acquire;
        py::function override = py::get_override(this, "term");
        if (override)
            (void)invoke_python_status(override, "plugin.Plugin.term");
    }

    ida::Status run(std::size_t argument) override {
        py::gil_scoped_acquire acquire;
        py::function override = py::get_override(this, "run");
        if (!override) {
            return std::unexpected(ida::Error::unsupported(
                "Python Plugin.run override is required"));
        }
        return invoke_python_status(override, "plugin.Plugin.run", argument);
    }
};

} // namespace

void bind_plugin(py::module_& module) {
    py::module_ plugin = module.def_submodule(
        "plugin", "Plugin lifecycle, actions, hotkeys, and host contexts.");

    py::class_<OpaqueHostHandle>(plugin, "HostHandle")
        .def_property_readonly("valid", &OpaqueHostHandle::valid)
        .def_property_readonly("kind", &OpaqueHostHandle::kind);

#define IDAX_PY_PLUGIN_VALUE(type_name)                                  \
    py::class_<ida::plugin::type_name>(plugin, #type_name).def(py::init<>())
    IDAX_PY_PLUGIN_VALUE(Info)
        .def_readwrite("name", &ida::plugin::Info::name)
        .def_readwrite("hotkey", &ida::plugin::Info::hotkey)
        .def_readwrite("comment", &ida::plugin::Info::comment)
        .def_readwrite("help", &ida::plugin::Info::help)
        .def_readwrite("icon", &ida::plugin::Info::icon);
    IDAX_PY_PLUGIN_VALUE(ExportFlags)
        .def_readwrite("modifies_database", &ida::plugin::ExportFlags::modifies_database)
        .def_readwrite("requests_redraw", &ida::plugin::ExportFlags::requests_redraw)
        .def_readwrite("segment_scoped", &ida::plugin::ExportFlags::segment_scoped)
        .def_readwrite("unload_after_run", &ida::plugin::ExportFlags::unload_after_run)
        .def_readwrite("hidden", &ida::plugin::ExportFlags::hidden)
        .def_readwrite("debugger_only", &ida::plugin::ExportFlags::debugger_only)
        .def_readwrite("processor_specific", &ida::plugin::ExportFlags::processor_specific)
        .def_readwrite("load_at_startup", &ida::plugin::ExportFlags::load_at_startup)
        .def_readwrite("extra_raw_flags", &ida::plugin::ExportFlags::extra_raw_flags);
    IDAX_PY_PLUGIN_VALUE(TypeRef)
        .def_readwrite("name", &ida::plugin::TypeRef::name)
        .def_readwrite("type", &ida::plugin::TypeRef::type);
#undef IDAX_PY_PLUGIN_VALUE

    py::class_<PythonActionContext>(plugin, "ActionContext")
        .def_readonly("action_id", &PythonActionContext::action_id)
        .def_readonly("widget_title", &PythonActionContext::widget_title)
        .def_readonly("widget_type", &PythonActionContext::widget_type)
        .def_readonly("current_address", &PythonActionContext::current_address)
        .def_readonly("current_value", &PythonActionContext::current_value)
        .def_readonly("has_selection", &PythonActionContext::has_selection)
        .def_readonly("is_external_address", &PythonActionContext::is_external_address)
        .def_readonly("register_name", &PythonActionContext::register_name)
        .def_readonly("type_ref", &PythonActionContext::type_ref)
        .def_property_readonly("widget_host", &PythonActionContext::widget_host)
        .def_property_readonly("focused_widget_host",
                               &PythonActionContext::focused_widget_host)
        .def_property_readonly("decompiler_view_host",
                               &PythonActionContext::decompiler_view_host);
    py::class_<PythonAction>(plugin, "Action")
        .def(py::init<>())
        .def_readwrite("id", &PythonAction::id)
        .def_readwrite("label", &PythonAction::label)
        .def_readwrite("hotkey", &PythonAction::hotkey)
        .def_readwrite("tooltip", &PythonAction::tooltip)
        .def_readwrite("icon", &PythonAction::icon)
        .def_readwrite("handler", &PythonAction::handler)
        .def_readwrite("handler_with_context", &PythonAction::handler_with_context)
        .def_readwrite("enabled", &PythonAction::enabled)
        .def_readwrite("enabled_with_context", &PythonAction::enabled_with_context);

    py::class_<ida::plugin::Plugin, PythonPlugin,
               std::shared_ptr<ida::plugin::Plugin>>(plugin, "Plugin")
        .def(py::init<>())
        .def("info", &ida::plugin::Plugin::info)
        .def("init", &ida::plugin::Plugin::init)
        .def("term", &ida::plugin::Plugin::term)
        .def("run", [](ida::plugin::Plugin& self, std::size_t argument) {
            unwrap(self.run(argument));
        }, py::arg("argument") = 0);

    py::class_<ida::plugin::ScopedHotkey>(plugin, "ScopedHotkey")
        .def_property_readonly("active", &ida::plugin::ScopedHotkey::active)
        .def_property_readonly("hotkey", [](const ida::plugin::ScopedHotkey& self) {
            return std::string(self.hotkey());
        })
        .def("activate", [](const ida::plugin::ScopedHotkey& self) {
            runtime_status("plugin.ScopedHotkey.activate", [&] {
                return self.activate();
            });
        })
        .def("release", [](ida::plugin::ScopedHotkey& self) {
            runtime_status("plugin.ScopedHotkey.release", [&] {
                return self.release();
            });
        })
        .def("close", [](ida::plugin::ScopedHotkey& self) {
            if (self.active())
                runtime_status("plugin.ScopedHotkey.close", [&] {
                    return self.release();
                });
        })
        .def("__enter__", [](ida::plugin::ScopedHotkey& self)
             -> ida::plugin::ScopedHotkey& { return self; },
             py::return_value_policy::reference_internal)
        .def("__exit__", [](ida::plugin::ScopedHotkey& self,
                              py::object, py::object, py::object) {
            if (self.active())
                unwrap(self.release());
            return false;
        });

    plugin.def("widget_host", [](const PythonActionContext& context) {
        ensure_runtime_thread("plugin.widget_host");
        return context.widget_host();
    }, py::arg("context"));
    plugin.def("with_widget_host", [](const PythonActionContext& context,
                                         py::function callback) {
        ensure_runtime_thread("plugin.with_widget_host");
        callback(context.widget_host());
    }, py::arg("context"), py::arg("callback"));
    plugin.def("decompiler_view_host", [](const PythonActionContext& context) {
        ensure_runtime_thread("plugin.decompiler_view_host");
        return context.decompiler_view_host();
    }, py::arg("context"));
    plugin.def("with_decompiler_view_host", [](
        const PythonActionContext& context, py::function callback) {
        ensure_runtime_thread("plugin.with_decompiler_view_host");
        callback(context.decompiler_view_host());
    }, py::arg("context"), py::arg("callback"));

    plugin.def("register_action", [](py::object action_object) {
        ensure_runtime_thread("plugin.register_action");
        const auto& action = action_object.cast<const PythonAction&>();
        unwrap(ida::plugin::register_action(action.native()));
        action_roots().insert_or_assign(action.id, std::move(action_object));
    }, py::arg("action"));
    plugin.def("unregister_action", [](std::string action_id) {
        runtime_status("plugin.unregister_action", [&] {
            return ida::plugin::unregister_action(action_id);
        });
        action_roots().erase(action_id);
    }, py::arg("action_id"));
    plugin.def("activate_action", [](std::string action_id) {
        runtime_status("plugin.activate_action", [&] {
            return ida::plugin::activate_action(action_id);
        });
    }, py::arg("action_id"));
    plugin.def("register_hotkey", [](std::string hotkey, py::function callback) {
        return runtime_result("plugin.register_hotkey", [&] {
            return ida::plugin::register_hotkey(hotkey, [callback = std::move(callback)] {
                return invoke_python_status(callback, "plugin.hotkey");
            });
        });
    }, py::arg("hotkey"), py::arg("callback"));

#define IDAX_PY_PLUGIN_ATTACHMENT(fn)                                    \
    plugin.def(#fn, [](std::string target, std::string action_id) {      \
        runtime_status("plugin." #fn, [&] {                             \
            return ida::plugin::fn(target, action_id);                   \
        });                                                              \
    }, py::arg("target"), py::arg("action_id"))
    IDAX_PY_PLUGIN_ATTACHMENT(attach_to_menu);
    IDAX_PY_PLUGIN_ATTACHMENT(attach_to_toolbar);
    IDAX_PY_PLUGIN_ATTACHMENT(attach_to_popup);
    IDAX_PY_PLUGIN_ATTACHMENT(detach_from_menu);
    IDAX_PY_PLUGIN_ATTACHMENT(detach_from_toolbar);
    IDAX_PY_PLUGIN_ATTACHMENT(detach_from_popup);
#undef IDAX_PY_PLUGIN_ATTACHMENT
}

} // namespace idax::python

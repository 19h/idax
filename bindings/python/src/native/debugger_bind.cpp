#include "common.hpp"

#include <unordered_map>

namespace idax::python {

namespace {

template <typename... Arguments>
void invoke_debugger_callback(const py::function& callback,
                              Arguments&&... arguments) noexcept {
    py::gil_scoped_acquire acquire;
    try {
        callback(std::forward<Arguments>(arguments)...);
    } catch (py::error_already_set& error) {
        error.discard_as_unraisable(callback);
    } catch (...) {
        PyErr_SetString(PyExc_RuntimeError, "non-Python debugger callback failure");
        PyErr_WriteUnraisable(callback.ptr());
    }
}

template <typename... Arguments>
bool invoke_debugger_filter(const py::function& callback,
                            Arguments&&... arguments) noexcept {
    py::gil_scoped_acquire acquire;
    try {
        return callback(std::forward<Arguments>(arguments)...)
            .template cast<bool>();
    } catch (py::error_already_set& error) {
        error.discard_as_unraisable(callback);
    } catch (...) {
        PyErr_SetString(PyExc_RuntimeError, "non-Python debugger filter failure");
        PyErr_WriteUnraisable(callback.ptr());
    }
    return false;
}

class PythonAppcallExecutor final : public ida::debugger::AppcallExecutor {
public:
    using ida::debugger::AppcallExecutor::AppcallExecutor;

    ida::Result<ida::debugger::AppcallResult> execute(
        const ida::debugger::AppcallRequest& request) override {
        py::gil_scoped_acquire acquire;
        py::function override = py::get_override(this, "execute");
        if (!override) {
            return std::unexpected(ida::Error::internal(
                "Python AppcallExecutor.execute override is required"));
        }
        try {
            return override(request).cast<ida::debugger::AppcallResult>();
        } catch (py::error_already_set& error) {
            std::string message = error.what();
            error.discard_as_unraisable(override);
            return std::unexpected(ida::Error::internal(
                "Python AppcallExecutor.execute failed", message));
        }
    }
};

std::unordered_map<std::string, py::object>& executor_roots() {
    static std::unordered_map<std::string, py::object> roots;
    return roots;
}

} // namespace

void bind_debugger(py::module_& module) {
    py::module_ debugger = module.def_submodule(
        "debugger", "Debugger lifecycle, memory, appcalls, and events.");

    py::native_enum<ida::debugger::ProcessState>(
        debugger, "ProcessState", "enum.Enum")
        .value("NO_PROCESS", ida::debugger::ProcessState::NoProcess)
        .value("RUNNING", ida::debugger::ProcessState::Running)
        .value("SUSPENDED", ida::debugger::ProcessState::Suspended)
        .finalize();
    py::native_enum<ida::debugger::AppcallValueKind>(
        debugger, "AppcallValueKind", "enum.Enum")
        .value("SIGNED_INTEGER", ida::debugger::AppcallValueKind::SignedInteger)
        .value("UNSIGNED_INTEGER", ida::debugger::AppcallValueKind::UnsignedInteger)
        .value("FLOATING_POINT", ida::debugger::AppcallValueKind::FloatingPoint)
        .value("STRING", ida::debugger::AppcallValueKind::String)
        .value("ADDRESS", ida::debugger::AppcallValueKind::Address)
        .value("BOOLEAN", ida::debugger::AppcallValueKind::Boolean)
        .finalize();
    py::native_enum<ida::debugger::BreakpointChange>(
        debugger, "BreakpointChange", "enum.Enum")
        .value("ADDED", ida::debugger::BreakpointChange::Added)
        .value("REMOVED", ida::debugger::BreakpointChange::Removed)
        .value("CHANGED", ida::debugger::BreakpointChange::Changed)
        .finalize();

#define IDAX_PY_DEBUGGER_VALUE(type_name)                                \
    py::class_<ida::debugger::type_name>(debugger, #type_name).def(py::init<>())
    IDAX_PY_DEBUGGER_VALUE(BackendInfo)
        .def_readwrite("name", &ida::debugger::BackendInfo::name)
        .def_readwrite("display_name", &ida::debugger::BackendInfo::display_name)
        .def_readwrite("remote", &ida::debugger::BackendInfo::remote)
        .def_readwrite("supports_appcall", &ida::debugger::BackendInfo::supports_appcall)
        .def_readwrite("supports_attach", &ida::debugger::BackendInfo::supports_attach)
        .def_readwrite("loaded", &ida::debugger::BackendInfo::loaded);
    IDAX_PY_DEBUGGER_VALUE(ThreadInfo)
        .def_readwrite("id", &ida::debugger::ThreadInfo::id)
        .def_readwrite("name", &ida::debugger::ThreadInfo::name)
        .def_readwrite("is_current", &ida::debugger::ThreadInfo::is_current);
    IDAX_PY_DEBUGGER_VALUE(RegisterInfo)
        .def_readwrite("name", &ida::debugger::RegisterInfo::name)
        .def_readwrite("read_only", &ida::debugger::RegisterInfo::read_only)
        .def_readwrite("instruction_pointer", &ida::debugger::RegisterInfo::instruction_pointer)
        .def_readwrite("stack_pointer", &ida::debugger::RegisterInfo::stack_pointer)
        .def_readwrite("frame_pointer", &ida::debugger::RegisterInfo::frame_pointer)
        .def_readwrite("may_contain_address", &ida::debugger::RegisterInfo::may_contain_address)
        .def_readwrite("custom_format", &ida::debugger::RegisterInfo::custom_format);
    IDAX_PY_DEBUGGER_VALUE(AppcallValue)
        .def_readwrite("kind", &ida::debugger::AppcallValue::kind)
        .def_readwrite("signed_value", &ida::debugger::AppcallValue::signed_value)
        .def_readwrite("unsigned_value", &ida::debugger::AppcallValue::unsigned_value)
        .def_readwrite("floating_value", &ida::debugger::AppcallValue::floating_value)
        .def_readwrite("string_value", &ida::debugger::AppcallValue::string_value)
        .def_readwrite("address_value", &ida::debugger::AppcallValue::address_value)
        .def_readwrite("boolean_value", &ida::debugger::AppcallValue::boolean_value);
    IDAX_PY_DEBUGGER_VALUE(AppcallOptions)
        .def_readwrite("thread_id", &ida::debugger::AppcallOptions::thread_id)
        .def_readwrite("manual", &ida::debugger::AppcallOptions::manual)
        .def_readwrite("include_debug_event", &ida::debugger::AppcallOptions::include_debug_event)
        .def_readwrite("timeout_milliseconds", &ida::debugger::AppcallOptions::timeout_milliseconds);
    IDAX_PY_DEBUGGER_VALUE(AppcallRequest)
        .def_readwrite("function_address", &ida::debugger::AppcallRequest::function_address)
        .def_readwrite("function_type", &ida::debugger::AppcallRequest::function_type)
        .def_readwrite("arguments", &ida::debugger::AppcallRequest::arguments)
        .def_readwrite("options", &ida::debugger::AppcallRequest::options);
    IDAX_PY_DEBUGGER_VALUE(AppcallResult)
        .def_readwrite("return_value", &ida::debugger::AppcallResult::return_value)
        .def_readwrite("diagnostics", &ida::debugger::AppcallResult::diagnostics);
    IDAX_PY_DEBUGGER_VALUE(ModuleInfo)
        .def_readwrite("name", &ida::debugger::ModuleInfo::name)
        .def_readwrite("base", &ida::debugger::ModuleInfo::base)
        .def_readwrite("size", &ida::debugger::ModuleInfo::size);
    IDAX_PY_DEBUGGER_VALUE(ExceptionInfo)
        .def_readwrite("address", &ida::debugger::ExceptionInfo::ea)
        .def_readwrite("code", &ida::debugger::ExceptionInfo::code)
        .def_readwrite("can_continue", &ida::debugger::ExceptionInfo::can_continue)
        .def_readwrite("message", &ida::debugger::ExceptionInfo::message);
#undef IDAX_PY_DEBUGGER_VALUE

    py::class_<ida::debugger::AppcallExecutor, PythonAppcallExecutor,
               std::shared_ptr<ida::debugger::AppcallExecutor>>(
        debugger, "AppcallExecutor")
        .def(py::init<>())
        .def("execute", [](ida::debugger::AppcallExecutor& self,
                             const ida::debugger::AppcallRequest& request) {
            return unwrap(self.execute(request));
        }, py::arg("request"));
    py::class_<ida::debugger::ScopedSubscription>(debugger, "ScopedSubscription")
        .def(py::init<ida::debugger::Token>(), py::arg("token"))
        .def_property_readonly("token", &ida::debugger::ScopedSubscription::token)
        .def("close", [](ida::debugger::ScopedSubscription& self) {
            self = ida::debugger::ScopedSubscription{0};
        })
        .def("__enter__", [](ida::debugger::ScopedSubscription& self)
             -> ida::debugger::ScopedSubscription& { return self; },
             py::return_value_policy::reference_internal)
        .def("__exit__", [](ida::debugger::ScopedSubscription& self,
                             py::object, py::object, py::object) {
            self = ida::debugger::ScopedSubscription{0};
            return false;
        });

#define IDAX_PY_DEBUGGER_NOARG_RESULT(fn)                                \
    debugger.def(#fn, [] { return runtime_result("debugger." #fn, ida::debugger::fn); })
    IDAX_PY_DEBUGGER_NOARG_RESULT(available_backends);
    IDAX_PY_DEBUGGER_NOARG_RESULT(current_backend);
    IDAX_PY_DEBUGGER_NOARG_RESULT(state);
    IDAX_PY_DEBUGGER_NOARG_RESULT(instruction_pointer);
    IDAX_PY_DEBUGGER_NOARG_RESULT(stack_pointer);
    IDAX_PY_DEBUGGER_NOARG_RESULT(thread_count);
    IDAX_PY_DEBUGGER_NOARG_RESULT(current_thread_id);
    IDAX_PY_DEBUGGER_NOARG_RESULT(threads);
#undef IDAX_PY_DEBUGGER_NOARG_RESULT
#define IDAX_PY_DEBUGGER_NOARG_STATUS(fn)                                \
    debugger.def(#fn, [] { runtime_status("debugger." #fn, ida::debugger::fn); })
    IDAX_PY_DEBUGGER_NOARG_STATUS(detach);
    IDAX_PY_DEBUGGER_NOARG_STATUS(terminate);
    IDAX_PY_DEBUGGER_NOARG_STATUS(suspend);
    IDAX_PY_DEBUGGER_NOARG_STATUS(resume);
    IDAX_PY_DEBUGGER_NOARG_STATUS(step_into);
    IDAX_PY_DEBUGGER_NOARG_STATUS(step_over);
    IDAX_PY_DEBUGGER_NOARG_STATUS(step_out);
    IDAX_PY_DEBUGGER_NOARG_STATUS(run_requests);
    IDAX_PY_DEBUGGER_NOARG_STATUS(request_suspend);
    IDAX_PY_DEBUGGER_NOARG_STATUS(request_resume);
    IDAX_PY_DEBUGGER_NOARG_STATUS(request_step_into);
    IDAX_PY_DEBUGGER_NOARG_STATUS(request_step_over);
    IDAX_PY_DEBUGGER_NOARG_STATUS(request_step_out);
#undef IDAX_PY_DEBUGGER_NOARG_STATUS
    debugger.def("is_request_running", [] {
        return runtime_call("debugger.is_request_running", ida::debugger::is_request_running);
    });
    debugger.def("load_backend", [](std::string name, bool remote) {
        runtime_status("debugger.load_backend", [&] {
            return ida::debugger::load_backend(name, remote);
        });
    }, py::arg("backend_name"), py::arg("use_remote") = false);
#define IDAX_PY_DEBUGGER_START(fn)                                       \
    debugger.def(#fn, [](std::string path, std::string args, std::string cwd) { \
        runtime_status("debugger." #fn, [&] { return ida::debugger::fn(path, args, cwd); }); \
    }, py::arg("path") = "", py::arg("args") = "", py::arg("working_dir") = "")
    IDAX_PY_DEBUGGER_START(start);
    IDAX_PY_DEBUGGER_START(request_start);
#undef IDAX_PY_DEBUGGER_START
    debugger.def("attach", [](int pid) {
        runtime_status("debugger.attach", [=] { return ida::debugger::attach(pid); });
    }, py::arg("pid"));
    debugger.def("request_attach", [](int pid, int event_id) {
        runtime_status("debugger.request_attach", [=] {
            return ida::debugger::request_attach(pid, event_id);
        });
    }, py::arg("pid"), py::arg("event_id") = -1);
#define IDAX_PY_DEBUGGER_ADDRESS_STATUS(fn)                              \
    debugger.def(#fn, [](ida::Address address) {                         \
        runtime_status("debugger." #fn, [=] { return ida::debugger::fn(address); }); \
    }, py::arg("address"))
    IDAX_PY_DEBUGGER_ADDRESS_STATUS(run_to);
    IDAX_PY_DEBUGGER_ADDRESS_STATUS(add_breakpoint);
    IDAX_PY_DEBUGGER_ADDRESS_STATUS(remove_breakpoint);
    IDAX_PY_DEBUGGER_ADDRESS_STATUS(request_run_to);
#undef IDAX_PY_DEBUGGER_ADDRESS_STATUS
    debugger.def("has_breakpoint", [](ida::Address address) {
        return runtime_result("debugger.has_breakpoint", [=] {
            return ida::debugger::has_breakpoint(address);
        });
    }, py::arg("address"));
    debugger.def("register_value", [](std::string name) {
        return runtime_result("debugger.register_value", [&] {
            return ida::debugger::register_value(name);
        });
    }, py::arg("register_name"));
    debugger.def("set_register", [](std::string name, std::uint64_t value) {
        runtime_status("debugger.set_register", [&] {
            return ida::debugger::set_register(name, value);
        });
    }, py::arg("register_name"), py::arg("value"));
    debugger.def("read_memory", [](ida::Address address, ida::AddressSize size) {
        return python_bytes(runtime_result("debugger.read_memory", [=] {
            return ida::debugger::read_memory(address, size);
        }));
    }, py::arg("address"), py::arg("size"));
    debugger.def("write_memory", [](ida::Address address, py::handle value) {
        auto bytes = buffer_bytes(value);
        runtime_status("debugger.write_memory", [&] {
            return ida::debugger::write_memory(address, bytes);
        });
    }, py::arg("address"), py::arg("data"));
    debugger.def("thread_id_at", [](std::size_t index) {
        return runtime_result("debugger.thread_id_at", [=] {
            return ida::debugger::thread_id_at(index);
        });
    }, py::arg("index"));
    debugger.def("thread_name_at", [](std::size_t index) {
        return runtime_result("debugger.thread_name_at", [=] {
            return ida::debugger::thread_name_at(index);
        });
    }, py::arg("index"));
#define IDAX_PY_DEBUGGER_THREAD_STATUS(fn)                               \
    debugger.def(#fn, [](int thread_id) {                                \
        runtime_status("debugger." #fn, [=] { return ida::debugger::fn(thread_id); }); \
    }, py::arg("thread_id"))
    IDAX_PY_DEBUGGER_THREAD_STATUS(select_thread);
    IDAX_PY_DEBUGGER_THREAD_STATUS(request_select_thread);
    IDAX_PY_DEBUGGER_THREAD_STATUS(suspend_thread);
    IDAX_PY_DEBUGGER_THREAD_STATUS(request_suspend_thread);
    IDAX_PY_DEBUGGER_THREAD_STATUS(resume_thread);
    IDAX_PY_DEBUGGER_THREAD_STATUS(request_resume_thread);
#undef IDAX_PY_DEBUGGER_THREAD_STATUS
#define IDAX_PY_DEBUGGER_REGISTER_RESULT(fn)                             \
    debugger.def(#fn, [](std::string name) {                             \
        return runtime_result("debugger." #fn, [&] { return ida::debugger::fn(name); }); \
    }, py::arg("register_name"))
    IDAX_PY_DEBUGGER_REGISTER_RESULT(register_info);
    IDAX_PY_DEBUGGER_REGISTER_RESULT(is_integer_register);
    IDAX_PY_DEBUGGER_REGISTER_RESULT(is_floating_register);
    IDAX_PY_DEBUGGER_REGISTER_RESULT(is_custom_register);
#undef IDAX_PY_DEBUGGER_REGISTER_RESULT
    debugger.def("appcall", [](const ida::debugger::AppcallRequest& request) {
        return runtime_result("debugger.appcall", [&] {
            return ida::debugger::appcall(request);
        });
    }, py::arg("request"));
    debugger.def("cleanup_appcall", [](std::optional<int> thread_id) {
        runtime_status("debugger.cleanup_appcall", [=] {
            return ida::debugger::cleanup_appcall(thread_id);
        });
    }, py::arg("thread_id") = py::none());
    debugger.def("register_executor", [](std::string name, py::object executor_object) {
        auto executor = executor_object.cast<
            std::shared_ptr<ida::debugger::AppcallExecutor>>();
        runtime_status("debugger.register_executor", [&] {
            return ida::debugger::register_executor(name, std::move(executor));
        });
        executor_roots().insert_or_assign(name, std::move(executor_object));
    }, py::arg("name"), py::arg("executor"));
    debugger.def("unregister_executor", [](std::string name) {
        runtime_status("debugger.unregister_executor", [&] {
            return ida::debugger::unregister_executor(name);
        });
        executor_roots().erase(name);
    }, py::arg("name"));
    debugger.def("appcall_with_executor", [](
        std::string name, const ida::debugger::AppcallRequest& request) {
        return runtime_result("debugger.appcall_with_executor", [&] {
            return ida::debugger::appcall_with_executor(name, request);
        });
    }, py::arg("name"), py::arg("request"));

#define IDAX_PY_DEBUGGER_EVENT_STRUCT(fn, type_name)                     \
    debugger.def(#fn, [](py::function callback) {                        \
        return runtime_result("debugger." #fn, [&] {                    \
            return ida::debugger::fn([callback = std::move(callback)](   \
                const ida::debugger::type_name& value) {                 \
                invoke_debugger_callback(callback, value);               \
            });                                                           \
        });                                                               \
    }, py::arg("callback"))
    IDAX_PY_DEBUGGER_EVENT_STRUCT(on_process_started, ModuleInfo);
    IDAX_PY_DEBUGGER_EVENT_STRUCT(on_exception, ExceptionInfo);
    IDAX_PY_DEBUGGER_EVENT_STRUCT(on_library_loaded, ModuleInfo);
#undef IDAX_PY_DEBUGGER_EVENT_STRUCT
#define IDAX_PY_DEBUGGER_EVENT_ONE(fn, value_type)                       \
    debugger.def(#fn, [](py::function callback) {                        \
        return runtime_result("debugger." #fn, [&] {                    \
            return ida::debugger::fn([callback = std::move(callback)](value_type value) { \
                invoke_debugger_callback(callback, value);               \
            });                                                           \
        });                                                               \
    }, py::arg("callback"))
    IDAX_PY_DEBUGGER_EVENT_ONE(on_process_exited, int);
    IDAX_PY_DEBUGGER_EVENT_ONE(on_process_suspended, ida::Address);
    IDAX_PY_DEBUGGER_EVENT_ONE(on_library_unloaded, std::string);
#undef IDAX_PY_DEBUGGER_EVENT_ONE
    debugger.def("on_breakpoint_hit", [](py::function callback) {
        return runtime_result("debugger.on_breakpoint_hit", [&] {
            return ida::debugger::on_breakpoint_hit(
                [callback = std::move(callback)](int thread_id, ida::Address address) {
                    invoke_debugger_callback(callback, thread_id, address);
                });
        });
    }, py::arg("callback"));
    debugger.def("on_trace", [](py::function callback) {
        return runtime_result("debugger.on_trace", [&] {
            return ida::debugger::on_trace(
                [callback = std::move(callback)](int thread_id, ida::Address address) {
                    return invoke_debugger_filter(callback, thread_id, address);
                });
        });
    }, py::arg("callback"));
#define IDAX_PY_DEBUGGER_EVENT_TWO_INT(fn)                               \
    debugger.def(#fn, [](py::function callback) {                        \
        return runtime_result("debugger." #fn, [&] {                    \
            return ida::debugger::fn([callback = std::move(callback)](int first, int second) { \
                invoke_debugger_callback(callback, first, second);       \
            });                                                           \
        });                                                               \
    }, py::arg("callback"))
    IDAX_PY_DEBUGGER_EVENT_TWO_INT(on_thread_exited);
#undef IDAX_PY_DEBUGGER_EVENT_TWO_INT
    debugger.def("on_thread_started", [](py::function callback) {
        return runtime_result("debugger.on_thread_started", [&] {
            return ida::debugger::on_thread_started(
                [callback = std::move(callback)](int id, std::string name) {
                    invoke_debugger_callback(callback, id, name);
                });
        });
    }, py::arg("callback"));
    debugger.def("on_breakpoint_changed", [](py::function callback) {
        return runtime_result("debugger.on_breakpoint_changed", [&] {
            return ida::debugger::on_breakpoint_changed(
                [callback = std::move(callback)](
                    ida::debugger::BreakpointChange change, ida::Address address) {
                    invoke_debugger_callback(callback, change, address);
                });
        });
    }, py::arg("callback"));
    debugger.def("unsubscribe", [](ida::debugger::Token token) {
        runtime_status("debugger.unsubscribe", [=] {
            return ida::debugger::unsubscribe(token);
        });
    }, py::arg("token"));
}

} // namespace idax::python

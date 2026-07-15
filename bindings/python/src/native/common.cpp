#include "common.hpp"

#include <Python.h>

#include <array>
#include <mutex>
#include <optional>
#include <sstream>
#include <thread>

namespace idax::python {

namespace {

struct ExceptionTypes {
    PyObject* base{nullptr};
    PyObject* validation{nullptr};
    PyObject* not_found{nullptr};
    PyObject* conflict{nullptr};
    PyObject* unsupported{nullptr};
    PyObject* sdk_failure{nullptr};
    PyObject* internal{nullptr};
};

ExceptionTypes g_exception_types;
std::mutex g_runtime_mutex;
std::optional<std::thread::id> g_runtime_thread;

PyObject* exception_type(ida::ErrorCategory category) noexcept {
    switch (category) {
        case ida::ErrorCategory::Validation:  return g_exception_types.validation;
        case ida::ErrorCategory::NotFound:    return g_exception_types.not_found;
        case ida::ErrorCategory::Conflict:    return g_exception_types.conflict;
        case ida::ErrorCategory::Unsupported: return g_exception_types.unsupported;
        case ida::ErrorCategory::SdkFailure:  return g_exception_types.sdk_failure;
        case ida::ErrorCategory::Internal:    return g_exception_types.internal;
    }
    return g_exception_types.base;
}

py::object create_exception_type(py::module_& module,
                                 const char* name,
                                 const char* qualified_name,
                                 const char* doc,
                                 PyObject* base) {
    PyObject* raw = PyErr_NewExceptionWithDoc(qualified_name, doc, base, nullptr);
    if (raw == nullptr)
        throw py::error_already_set();
    py::object type = py::reinterpret_steal<py::object>(raw);
    module.attr(name) = type;
    return type;
}

std::string format_error(const ida::Error& error) {
    std::ostringstream stream;
    stream << error.message;
    if (!error.context.empty())
        stream << " [" << error.context << ']';
    return stream.str();
}

void set_attribute(py::handle object, const char* name, py::handle value) {
    if (PyObject_SetAttrString(object.ptr(), name, value.ptr()) < 0)
        throw py::error_already_set();
}

} // namespace

BindingError::BindingError(ida::Error error)
    : error_(std::move(error)), display_(format_error(error_)) {}

[[noreturn]] void throw_error(ida::Error error) {
    throw BindingError(std::move(error));
}

void bind_error_types(py::module_& module) {
    py::native_enum<ida::ErrorCategory>(module, "ErrorCategory", "enum.Enum")
        .value("VALIDATION", ida::ErrorCategory::Validation)
        .value("NOT_FOUND", ida::ErrorCategory::NotFound)
        .value("CONFLICT", ida::ErrorCategory::Conflict)
        .value("UNSUPPORTED", ida::ErrorCategory::Unsupported)
        .value("SDK_FAILURE", ida::ErrorCategory::SdkFailure)
        .value("INTERNAL", ida::ErrorCategory::Internal)
        .export_values()
        .finalize();

    py::class_<ida::Error>(module, "ErrorInfo")
        .def(py::init<>())
        .def(py::init<ida::ErrorCategory, int, std::string, std::string>(),
             py::arg("category"), py::arg("code"), py::arg("message"),
             py::arg("context") = std::string{})
        .def_readwrite("category", &ida::Error::category)
        .def_readwrite("code", &ida::Error::code)
        .def_readwrite("message", &ida::Error::message)
        .def_readwrite("context", &ida::Error::context)
        .def_static("validation", &ida::Error::validation,
                    py::arg("message"), py::arg("context") = std::string{})
        .def_static("not_found", &ida::Error::not_found,
                    py::arg("message"), py::arg("context") = std::string{})
        .def_static("conflict", &ida::Error::conflict,
                    py::arg("message"), py::arg("context") = std::string{})
        .def_static("unsupported", &ida::Error::unsupported,
                    py::arg("message"), py::arg("context") = std::string{})
        .def_static("sdk_failure", &ida::Error::sdk,
                    py::arg("message"), py::arg("context") = std::string{})
        .def_static("internal", &ida::Error::internal,
                    py::arg("message"), py::arg("context") = std::string{})
        .def("__repr__", [](const ida::Error& error) {
            return "ErrorInfo(category="
                + std::to_string(static_cast<int>(error.category))
                + ", code=" + std::to_string(error.code)
                + ", message=" + py::repr(py::str(error.message)).cast<std::string>()
                + ", context=" + py::repr(py::str(error.context)).cast<std::string>()
                + ")";
        });

    py::object base = create_exception_type(
        module, "IdaxError", "idax._native.IdaxError",
        "Base exception for errors returned by IDAX.", PyExc_RuntimeError);
    g_exception_types.base = base.ptr();

    py::object validation = create_exception_type(
        module, "ValidationError", "idax._native.ValidationError",
        "Caller-supplied input failed IDAX validation.", base.ptr());
    py::object not_found = create_exception_type(
        module, "NotFoundError", "idax._native.NotFoundError",
        "The requested IDA object was not found.", base.ptr());
    py::object conflict = create_exception_type(
        module, "ConflictError", "idax._native.ConflictError",
        "The operation conflicts with existing IDA state.", base.ptr());
    py::object unsupported = create_exception_type(
        module, "UnsupportedError", "idax._native.UnsupportedError",
        "The operation is unavailable in the current host context.", base.ptr());
    py::object sdk_failure = create_exception_type(
        module, "SdkError", "idax._native.SdkError",
        "The underlying IDA SDK operation failed.", base.ptr());
    py::object internal = create_exception_type(
        module, "InternalError", "idax._native.InternalError",
        "An internal IDAX invariant failed.", base.ptr());

    g_exception_types.validation = validation.ptr();
    g_exception_types.not_found = not_found.ptr();
    g_exception_types.conflict = conflict.ptr();
    g_exception_types.unsupported = unsupported.ptr();
    g_exception_types.sdk_failure = sdk_failure.ptr();
    g_exception_types.internal = internal.ptr();

    py::register_exception_translator([](std::exception_ptr exception) {
        if (!exception)
            return;
        try {
            std::rethrow_exception(exception);
        } catch (const BindingError& binding_error) {
            const ida::Error& error = binding_error.error();
            PyObject* type = exception_type(error.category);
            if (type == nullptr)
                type = PyExc_RuntimeError;

            py::object instance = py::reinterpret_steal<py::object>(
                PyObject_CallFunction(type, "s", binding_error.what()));
            if (!instance)
                throw py::error_already_set();

            py::object category = py::cast(error.category);
            py::object code = py::int_(error.code);
            py::object message = py::str(error.message);
            py::object context = py::str(error.context);
            set_attribute(instance, "category", category);
            set_attribute(instance, "code", code);
            set_attribute(instance, "message", message);
            set_attribute(instance, "context", context);
            PyErr_SetObject(type, instance.ptr());
        }
    });
}

void mark_runtime_thread() {
    std::lock_guard lock(g_runtime_mutex);
    const std::thread::id current = std::this_thread::get_id();
    if (g_runtime_thread && *g_runtime_thread != current) {
        throw_error(ida::Error::conflict(
            "IDA runtime was initialized on another thread",
            "database.init"));
    }
    g_runtime_thread = current;
}

void ensure_runtime_thread(std::string_view operation) {
    std::lock_guard lock(g_runtime_mutex);
    if (g_runtime_thread && *g_runtime_thread != std::this_thread::get_id()) {
        throw_error(ida::Error::conflict(
            "IDA runtime calls must remain on the initializing thread",
            std::string(operation)));
    }
}

std::string filesystem_path(py::handle value) {
    PyObject* raw_path = PyOS_FSPath(value.ptr());
    if (raw_path == nullptr)
        throw py::error_already_set();
    py::object path = py::reinterpret_steal<py::object>(raw_path);

    py::object text;
    if (PyUnicode_Check(path.ptr())) {
        text = std::move(path);
    } else if (PyBytes_Check(path.ptr())) {
        char* bytes = nullptr;
        Py_ssize_t size = 0;
        if (PyBytes_AsStringAndSize(path.ptr(), &bytes, &size) < 0)
            throw py::error_already_set();
        PyObject* decoded = PyUnicode_DecodeFSDefaultAndSize(bytes, size);
        if (decoded == nullptr)
            throw py::error_already_set();
        text = py::reinterpret_steal<py::object>(decoded);
    } else {
        throw py::type_error("path must implement os.PathLike[str] or be str/bytes");
    }

    std::string result = py::cast<std::string>(text);
    if (result.find('\0') != std::string::npos)
        throw py::value_error("path must not contain NUL bytes");
    return result;
}

std::vector<std::uint8_t> buffer_bytes(py::handle value) {
    if (!PyObject_CheckBuffer(value.ptr()))
        throw py::type_error("expected a bytes-like object");
    PyObject* raw_bytes = PyObject_Bytes(value.ptr());
    if (raw_bytes == nullptr)
        throw py::error_already_set();
    py::bytes bytes = py::reinterpret_steal<py::bytes>(raw_bytes);
    std::string copied = bytes;
    return {copied.begin(), copied.end()};
}

py::bytes python_bytes(const std::vector<std::uint8_t>& value) {
    return py::bytes(
        reinterpret_cast<const char*>(value.data()),
        static_cast<py::ssize_t>(value.size()));
}

} // namespace idax::python

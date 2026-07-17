/// \file script.cpp
/// \brief Implementation of opaque IDC values and synchronous execution.

#include "detail/sdk_bridge.hpp"

#include <ida/script.hpp>

#include <expr.hpp>

#include <algorithm>
#include <climits>
#include <limits>
#include <new>
#include <string>
#include <type_traits>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace ida::script {

struct Value::Impl {
    idc_value_t value;
};

namespace {

Status validate_c_string(std::string_view value, std::string_view field,
                         bool allow_empty = false) {
    if (!allow_empty && value.empty()) {
        return std::unexpected(Error::validation(
            std::string(field) + " cannot be empty"));
    }
    if (value.find('\0') != std::string_view::npos) {
        return std::unexpected(Error::validation(
            std::string(field) + " contains an embedded NUL byte"));
    }
    return ok();
}

Error native_value_error(std::string message, error_t code,
                         std::string context = {}) {
    return {ErrorCategory::SdkFailure, static_cast<int>(code),
            std::move(message), std::move(context)};
}

Error kind_error(std::string_view expected, int actual) {
    return Error::unsupported(
        "IDC value does not have the requested exact kind",
        std::string(expected) + ":" + std::to_string(actual));
}

Status validate_address(Address where) {
    if (where == BadAddress)
        return ok();
    if (where > static_cast<Address>(std::numeric_limits<ea_t>::max())) {
        return std::unexpected(Error::validation(
            "Expression address is outside the SDK address range",
            std::to_string(where)));
    }
    return ok();
}

Result<std::unordered_map<std::string, uval_t>> resolver_map(
    const std::vector<ResolvedName>& entries) {
    std::unordered_map<std::string, uval_t> result;
    result.reserve(entries.size());
    for (const auto& entry : entries) {
        if (auto status = validate_c_string(
                entry.name, "Resolved name", false); !status) {
            return std::unexpected(status.error());
        }
        if (entry.value > static_cast<std::uint64_t>(
                              std::numeric_limits<uval_t>::max())) {
            return std::unexpected(Error::validation(
                "Resolved value is outside the SDK unsigned range",
                entry.name));
        }
        if (static_cast<uval_t>(entry.value) == BADADDR) {
            return std::unexpected(Error::validation(
                "Resolved value collides with the native unresolved sentinel",
                entry.name));
        }
        if (!result.emplace(entry.name, static_cast<uval_t>(entry.value)).second) {
            return std::unexpected(Error::validation(
                "Resolved names contain a duplicate", entry.name));
        }
    }
    return result;
}

class MapResolver final : public idc_resolver_t {
public:
    explicit MapResolver(std::unordered_map<std::string, uval_t> values)
        : values_(std::move(values)) {}

    uval_t idaapi resolve_name(const char* name) override {
        try {
            if (name == nullptr)
                return BADADDR;
            const auto found = values_.find(name);
            return found == values_.end() ? BADADDR : found->second;
        } catch (...) {
            return BADADDR;
        }
    }

private:
    std::unordered_map<std::string, uval_t> values_;
};

Result<int> file_compile_flags(const FileCompileOptions& options) {
    int flags = 0;
    if (options.delete_macros_after_compilation) flags |= CPL_DEL_MACROS;
    if (options.allow_program_labels) flags |= CPL_USE_LABELS;
    if (options.only_safe_functions) flags |= CPL_ONLY_SAFE;
    return flags;
}

Status validate_include_paths(const std::vector<std::string>& paths) {
    for (const auto& path : paths) {
        if (auto status = validate_c_string(path, "IDC include path", false);
            !status) {
            return status;
        }
        if (path.find(';') != std::string::npos) {
            return std::unexpected(Error::validation(
                "IDC include path contains the native list separator", path));
        }
    }
    return ok();
}

std::string join_include_paths(const std::vector<std::string>& paths) {
    std::string result;
    for (std::size_t index = 0; index < paths.size(); ++index) {
        if (index != 0)
            result.push_back(';');
        result += paths[index];
    }
    return result;
}

} // namespace

namespace detail {

class ValueAccess {
public:
    static const idc_value_t& native(const Value& value) {
        return value.read_state().value;
    }

    static Value copy_native(const idc_value_t& native) {
        auto impl = std::make_unique<Value::Impl>();
        copy_idcv(&impl->value, native);
        return Value(std::move(impl));
    }

    static Value move_native(idc_value_t& native) {
        auto impl = std::make_unique<Value::Impl>();
        move_idcv(&impl->value, &native);
        return Value(std::move(impl));
    }
};

} // namespace detail

Value::Value() : impl_(std::make_unique<Impl>()) {}

Value::Value(std::int64_t value) : impl_(std::make_unique<Impl>()) {
    impl_->value.set_int64(static_cast<int64>(value));
}

Value::Value(std::string_view value) : impl_(std::make_unique<Impl>()) {
    const char* data = value.empty() ? "" : value.data();
    impl_->value.set_string(data, value.size());
}

Value::Value(std::unique_ptr<Impl> impl) : impl_(std::move(impl)) {}

const Value::Impl& Value::read_state() const noexcept {
    static const Impl zero;
    return impl_ ? *impl_ : zero;
}

Value::Impl& Value::write_state() {
    if (!impl_)
        impl_ = std::make_unique<Impl>();
    return *impl_;
}

Value::Value(const Value& other) : impl_(std::make_unique<Impl>()) {
    copy_idcv(&impl_->value, other.read_state().value);
}

Value::Value(Value&& other) noexcept = default;

Value& Value::operator=(const Value& other) {
    if (this != &other) {
        if (!impl_)
            impl_ = std::make_unique<Impl>();
        copy_idcv(&impl_->value, other.read_state().value);
    }
    return *this;
}

Value& Value::operator=(Value&& other) noexcept = default;
Value::~Value() = default;

Result<Value> Value::floating(double value) {
    fpvalue_t native;
    const auto status = native.from_double(value);
    if (status != REAL_ERROR_OK) {
        return std::unexpected(Error::validation(
            "Floating-point value cannot be represented by IDC",
            std::to_string(value)));
    }
    Value result;
    result.impl_->value.set_float(native);
    return result;
}

Result<Value> Value::object() {
    Value result;
    const error_t status = idcv_object(&result.impl_->value);
    if (status != eOk) {
        return std::unexpected(native_value_error(
            "Failed to construct IDC object", status));
    }
    return result;
}

Result<ValueKind> Value::kind() const {
    const auto& native = read_state().value;
    switch (native.vtype) {
        case VT_LONG:
        case VT_INT64: return ValueKind::Integer;
        case VT_FLOAT: return ValueKind::FloatingPoint;
        case VT_OBJ: return ValueKind::Object;
        case VT_FUNC: return ValueKind::Function;
        case VT_STR: return ValueKind::String;
        case VT_PVOID: return ValueKind::OpaquePointer;
        case VT_REF: return ValueKind::Reference;
        default:
            return std::unexpected(Error::unsupported(
                "IDC value has an unknown native kind",
                std::to_string(native.vtype)));
    }
}

Result<std::int64_t> Value::as_integer() const {
    const auto& native = read_state().value;
    if (native.vtype == VT_LONG)
        return static_cast<std::int64_t>(native.num);
    if (native.vtype == VT_INT64)
        return static_cast<std::int64_t>(native.i64);
    return std::unexpected(kind_error("integer", native.vtype));
}

Result<double> Value::as_floating() const {
    const auto& native = read_state().value;
    if (native.vtype != VT_FLOAT)
        return std::unexpected(kind_error("floating", native.vtype));
    double result = 0.0;
    if (native.e.to_double(&result) != REAL_ERROR_OK) {
        return std::unexpected(Error::unsupported(
            "IDC floating value cannot be represented as double"));
    }
    return result;
}

Result<std::string> Value::as_string() const {
    const auto& native = read_state().value;
    if (native.vtype != VT_STR)
        return std::unexpected(kind_error("string", native.vtype));
    return ida::detail::to_string(native.qstr());
}

Result<std::int64_t> Value::coerce_integer() const {
    idc_value_t copy(read_state().value);
    const error_t status = idcv_int64(&copy);
    if (status != eOk) {
        return std::unexpected(native_value_error(
            "IDC integer coercion failed", status));
    }
    if (copy.vtype == VT_LONG)
        return static_cast<std::int64_t>(copy.num);
    if (copy.vtype == VT_INT64)
        return static_cast<std::int64_t>(copy.i64);
    return std::unexpected(Error::internal(
        "IDC integer coercion returned a non-integer kind",
        std::to_string(copy.vtype)));
}

Result<double> Value::coerce_floating() const {
    idc_value_t copy(read_state().value);
    const error_t status = idcv_float(&copy);
    if (status != eOk) {
        return std::unexpected(native_value_error(
            "IDC floating coercion failed", status));
    }
    double result = 0.0;
    if (copy.vtype != VT_FLOAT || copy.e.to_double(&result) != REAL_ERROR_OK) {
        return std::unexpected(Error::unsupported(
            "Coerced IDC floating value cannot be represented as double"));
    }
    return result;
}

Result<std::string> Value::coerce_string() const {
    idc_value_t copy(read_state().value);
    const error_t status = idcv_string(&copy);
    if (status != eOk) {
        return std::unexpected(native_value_error(
            "IDC string coercion failed", status));
    }
    if (copy.vtype != VT_STR) {
        return std::unexpected(Error::internal(
            "IDC string coercion returned a non-string kind",
            std::to_string(copy.vtype)));
    }
    return ida::detail::to_string(copy.qstr());
}

Result<std::string> Value::render(
    std::optional<std::string_view> name, std::size_t indent) const {
    if (indent > static_cast<std::size_t>(INT_MAX)) {
        return std::unexpected(Error::validation(
            "IDC render indentation exceeds the native range",
            std::to_string(indent)));
    }
    std::string owned_name;
    const char* native_name = nullptr;
    if (name) {
        if (auto status = validate_c_string(*name, "IDC render name", true);
            !status) {
            return std::unexpected(status.error());
        }
        owned_name.assign(*name);
        native_name = owned_name.c_str();
    }
    qstring output;
    if (!print_idcv(&output, read_state().value, native_name,
                    static_cast<int>(indent))) {
        return std::unexpected(Error::sdk("Failed to render IDC value"));
    }
    return ida::detail::to_string(output);
}

Result<Value> Value::deep_copy() const {
    idc_value_t copy;
    const error_t status = deep_copy_idcv(&copy, read_state().value);
    if (status != eOk) {
        return std::unexpected(native_value_error(
            "Failed to deep-copy IDC value", status));
    }
    return detail::ValueAccess::move_native(copy);
}

Result<std::string> Value::class_name() const {
    const auto& native = read_state().value;
    if (native.vtype != VT_OBJ)
        return std::unexpected(kind_error("object", native.vtype));
    qstring output;
    const error_t status = get_idcv_class_name(&output, &native);
    if (status != eOk) {
        return std::unexpected(native_value_error(
            "Failed to query IDC object class", status));
    }
    return ida::detail::to_string(output);
}

Result<Value> Value::attribute(std::string_view name, bool use_handler) const {
    const auto& native = read_state().value;
    if (native.vtype != VT_OBJ)
        return std::unexpected(kind_error("object", native.vtype));
    if (auto status = validate_c_string(name, "IDC attribute name", false);
        !status) {
        return std::unexpected(status.error());
    }
    const std::string owned_name(name);
    idc_value_t result;
    const error_t status = get_idcv_attr(
        &result, &native, owned_name.c_str(), use_handler);
    if (status != eOk) {
        Error error = native_value_error(
            "Failed to read IDC object attribute", status, owned_name);
        if (!use_handler) {
            auto names = attribute_names();
            if (!names)
                return std::unexpected(names.error());
            if (std::find(names->begin(), names->end(), name) == names->end()) {
                error.category = ErrorCategory::NotFound;
                error.message = "IDC object attribute was not found";
            }
        }
        return std::unexpected(std::move(error));
    }
    return detail::ValueAccess::move_native(result);
}

Status Value::set_attribute(std::string_view name, const Value& value,
                            bool use_handler) {
    const auto& native = read_state().value;
    if (native.vtype != VT_OBJ)
        return std::unexpected(kind_error("object", native.vtype));
    if (auto status = validate_c_string(name, "IDC attribute name", false);
        !status) {
        return status;
    }
    const std::string owned_name(name);
    const error_t status = set_idcv_attr(
        &write_state().value, owned_name.c_str(), value.read_state().value,
        use_handler);
    if (status != eOk) {
        return std::unexpected(native_value_error(
            "Failed to set IDC object attribute", status, owned_name));
    }
    return ok();
}

Result<std::vector<std::string>> Value::attribute_names() const {
    const auto& native = read_state().value;
    if (native.vtype != VT_OBJ)
        return std::unexpected(kind_error("object", native.vtype));
    std::vector<std::string> result;
    std::unordered_set<std::string> seen;
    const char* current = first_idcv_attr(&native);
    while (current != nullptr) {
        std::string name(current);
        if (!seen.emplace(name).second) {
            return std::unexpected(Error::sdk(
                "IDC attribute enumeration repeated an entry", name));
        }
        result.push_back(name);
        current = next_idcv_attr(&native, name.c_str());
    }
    return result;
}

Result<bool> Value::remove_attribute(std::string_view name) {
    const auto& native = read_state().value;
    if (native.vtype != VT_OBJ)
        return std::unexpected(kind_error("object", native.vtype));
    if (auto status = validate_c_string(name, "IDC attribute name", false);
        !status) {
        return std::unexpected(status.error());
    }
    auto names = attribute_names();
    if (!names)
        return std::unexpected(names.error());
    if (std::find(names->begin(), names->end(), name) == names->end())
        return false;
    const std::string owned_name(name);
    const error_t status = del_idcv_attr(
        &write_state().value, owned_name.c_str());
    if (status != eOk) {
        return std::unexpected(native_value_error(
            "Failed to remove IDC object attribute", status, owned_name));
    }
    return true;
}

Result<Value> Value::slice(std::size_t begin, std::size_t end) const {
    if (begin > end) {
        return std::unexpected(Error::validation(
            "IDC slice begin exceeds end"));
    }
    idc_value_t result;
    const error_t status = get_idcv_slice(
        &result, &read_state().value, static_cast<uval_t>(begin),
        static_cast<uval_t>(end));
    if (status != eOk) {
        return std::unexpected(native_value_error(
            "Failed to read IDC slice", status));
    }
    return detail::ValueAccess::move_native(result);
}

Status Value::replace_slice(std::size_t begin, std::size_t end,
                            const Value& replacement) {
    if (begin > end) {
        return std::unexpected(Error::validation(
            "IDC slice begin exceeds end"));
    }
    const error_t status = set_idcv_slice(
        &write_state().value, static_cast<uval_t>(begin),
        static_cast<uval_t>(end), replacement.read_state().value);
    if (status != eOk) {
        return std::unexpected(native_value_error(
            "Failed to replace IDC slice", status));
    }
    return ok();
}

Result<Value> Value::dereference(DereferenceMode mode) const {
    const auto& native = read_state().value;
    if (native.vtype != VT_REF)
        return std::unexpected(kind_error("reference", native.vtype));
    idc_value_t copy(native);
    int flags = 0;
    switch (mode) {
        case DereferenceMode::Once: flags = VREF_ONCE; break;
        case DereferenceMode::Recursive: flags = VREF_LOOP; break;
        default:
            return std::unexpected(Error::validation(
                "Unknown IDC dereference mode"));
    }
    idc_value_t* result = deref_idcv(&copy, flags);
    if (result == nullptr) {
        return std::unexpected(Error::sdk(
            "Failed to dereference IDC value",
            std::to_string(get_qerrno())));
    }
    return detail::ValueAccess::copy_native(*result);
}

namespace {

template <typename Evaluator>
Result<ExecutionResult> evaluate_common(
    std::string_view expression, Address where, Evaluator evaluator) {
    if (auto status = validate_c_string(
            expression, "IDC expression", false); !status) {
        return std::unexpected(status.error());
    }
    if (auto status = validate_address(where); !status)
        return std::unexpected(status.error());
    const std::string owned_expression(expression);
    idc_value_t native_value;
    qstring error;
    const bool succeeded = evaluator(
        &native_value, static_cast<ea_t>(where), owned_expression.c_str(),
        &error);
    ExecutionResult result;
    result.succeeded = succeeded;
    result.value = detail::ValueAccess::move_native(native_value);
    result.error = ida::detail::to_string(error);
    return result;
}

template <typename Compiler>
CompilationResult compile_common(Compiler compiler) {
    qstring error;
    const bool succeeded = compiler(&error);
    return {succeeded, ida::detail::to_string(error)};
}

} // namespace

Result<ExecutionResult> evaluate(std::string_view expression, Address where) {
    return evaluate_common(expression, where, ::eval_expr);
}

Result<ExecutionResult> evaluate_idc(
    std::string_view expression, Address where) {
    return evaluate_common(expression, where, ::eval_idc_expr);
}

Result<IntegerExecutionResult> evaluate_integer(
    std::string_view expression, Address where) {
    if (auto status = validate_c_string(
            expression, "IDC integer expression", false); !status) {
        return std::unexpected(status.error());
    }
    if (auto status = validate_address(where); !status)
        return std::unexpected(status.error());
    const std::string owned_expression(expression);
    sval_t value = 0;
    qstring error;
    const bool succeeded = eval_expr_long(
        &value, static_cast<ea_t>(where), owned_expression.c_str(), &error);
    return IntegerExecutionResult{
        succeeded, static_cast<std::int64_t>(value),
        ida::detail::to_string(error)};
}

Result<CompilationResult> compile_file(
    std::string_view path, const FileCompileOptions& options) {
    if (auto status = validate_c_string(path, "IDC file path", false); !status)
        return std::unexpected(status.error());
    auto flags = file_compile_flags(options);
    if (!flags)
        return std::unexpected(flags.error());
    const std::string owned_path(path);
    return compile_common([&](qstring* error) {
        return compile_idc_file(owned_path.c_str(), error, *flags);
    });
}

Result<CompilationResult> compile_text(
    std::string_view source, const CompileOptions& options) {
    if (auto status = validate_c_string(source, "IDC source text", false);
        !status) {
        return std::unexpected(status.error());
    }
    auto values = resolver_map(options.resolved_names);
    if (!values)
        return std::unexpected(values.error());
    MapResolver resolver(std::move(*values));
    const std::string owned_source(source);
    return compile_common([&](qstring* error) {
        return compile_idc_text(
            owned_source.c_str(), error,
            options.resolved_names.empty() ? nullptr : &resolver,
            options.only_safe_functions);
    });
}

Result<CompilationResult> compile_snippet(
    std::string_view function_name, std::string_view body,
    const CompileOptions& options) {
    if (auto status = validate_c_string(
            function_name, "IDC snippet function name", false); !status) {
        return std::unexpected(status.error());
    }
    if (auto status = validate_c_string(body, "IDC snippet body", false);
        !status) {
        return std::unexpected(status.error());
    }
    auto values = resolver_map(options.resolved_names);
    if (!values)
        return std::unexpected(values.error());
    MapResolver resolver(std::move(*values));
    const std::string owned_name(function_name);
    const std::string owned_body(body);
    return compile_common([&](qstring* error) {
        return compile_idc_snippet(
            owned_name.c_str(), owned_body.c_str(), error,
            options.resolved_names.empty() ? nullptr : &resolver,
            options.only_safe_functions);
    });
}

Result<ExecutionResult> call(
    std::string_view function_name, const std::vector<Value>& arguments,
    const std::vector<ResolvedName>& resolved_names) {
    if (auto status = validate_c_string(
            function_name, "IDC function name", false); !status) {
        return std::unexpected(status.error());
    }
    auto values = resolver_map(resolved_names);
    if (!values)
        return std::unexpected(values.error());
    MapResolver resolver(std::move(*values));
    std::vector<idc_value_t> native_arguments;
    native_arguments.reserve(arguments.size());
    for (const auto& argument : arguments)
        native_arguments.emplace_back(detail::ValueAccess::native(argument));
    const std::string owned_name(function_name);
    idc_value_t native_result;
    qstring error;
    const bool succeeded = call_idc_func(
        &native_result, owned_name.c_str(),
        native_arguments.empty() ? nullptr : native_arguments.data(),
        native_arguments.size(), &error,
        resolved_names.empty() ? nullptr : &resolver);
    ExecutionResult result;
    result.succeeded = succeeded;
    result.value = detail::ValueAccess::move_native(native_result);
    result.error = ida::detail::to_string(error);
    return result;
}

Result<ExecutionResult> execute_script(
    std::string_view path, std::string_view function_name,
    const std::vector<Value>& arguments,
    const FileCompileOptions& options) {
    if (auto status = validate_c_string(
            function_name, "IDC function name", false); !status) {
        return std::unexpected(status.error());
    }
    auto compilation = compile_file(path, options);
    if (!compilation)
        return std::unexpected(compilation.error());
    if (!compilation->succeeded) {
        ExecutionResult result;
        result.succeeded = false;
        result.error = compilation->error;
        return result;
    }
    return call(function_name, arguments);
}

Result<ExecutionResult> evaluate_snippet(
    std::string_view source,
    const std::vector<ResolvedName>& resolved_names) {
    if (auto status = validate_c_string(source, "IDC snippet source", false);
        !status) {
        return std::unexpected(status.error());
    }
    auto values = resolver_map(resolved_names);
    if (!values)
        return std::unexpected(values.error());
    MapResolver resolver(std::move(*values));
    const std::string owned_source(source);
    idc_value_t native_result;
    qstring error;
    const bool succeeded = eval_idc_snippet(
        &native_result, owned_source.c_str(), &error,
        resolved_names.empty() ? nullptr : &resolver);
    ExecutionResult result;
    result.succeeded = succeeded;
    result.value = detail::ValueAccess::move_native(native_result);
    result.error = ida::detail::to_string(error);
    return result;
}

Status set_include_paths(const std::vector<std::string>& paths) {
    if (auto status = validate_include_paths(paths); !status)
        return status;
    const std::string joined = join_include_paths(paths);
    if (!set_header_path(joined.c_str(), false))
        return std::unexpected(Error::sdk("Failed to replace IDC include paths"));
    return ok();
}

Status append_include_paths(const std::vector<std::string>& paths) {
    if (auto status = validate_include_paths(paths); !status)
        return status;
    if (paths.empty())
        return ok();
    const std::string joined = join_include_paths(paths);
    if (!set_header_path(joined.c_str(), true))
        return std::unexpected(Error::sdk("Failed to append IDC include paths"));
    return ok();
}

Result<std::optional<std::string>> resolve_file(std::string_view file) {
    if (auto status = validate_c_string(file, "IDC filename", false); !status)
        return std::unexpected(status.error());
    const std::string owned_file(file);
    std::vector<char> buffer(QMAXPATH, '\0');
    if (get_idc_filename(
            buffer.data(), buffer.size(), owned_file.c_str()) == nullptr) {
        return std::optional<std::string>{};
    }
    return std::optional<std::string>{buffer.data()};
}

Status execute_system_script(std::string_view file, bool complain_if_missing) {
    if (auto status = validate_c_string(
            file, "IDC system script filename", false); !status) {
        return status;
    }
    const std::string owned_file(file);
    if (!exec_system_script(owned_file.c_str(), complain_if_missing)) {
        return std::unexpected(Error::sdk(
            "Failed to execute IDC system script", owned_file));
    }
    return ok();
}

Result<std::vector<std::string>> function_names(
    std::string_view prefix, std::size_t maximum) {
    if (auto status = validate_c_string(prefix, "IDC function prefix", true);
        !status) {
        return std::unexpected(status.error());
    }
    if (maximum == 0 || maximum > static_cast<std::size_t>(INT_MAX)) {
        return std::unexpected(Error::validation(
            "IDC function result limit must be in [1, INT_MAX]",
            std::to_string(maximum)));
    }
    const std::string owned_prefix(prefix);
    std::vector<std::string> result;
    result.reserve(std::min<std::size_t>(maximum, 64));
    for (std::size_t index = 0; index < maximum; ++index) {
        qstring name;
        if (!find_idc_func(
                &name, owned_prefix.c_str(), static_cast<int>(index))) {
            break;
        }
        result.push_back(ida::detail::to_string(name));
    }
    return result;
}

Result<std::optional<Value>> global(std::string_view name) {
    if (auto status = validate_c_string(name, "IDC global name", false); !status)
        return std::unexpected(status.error());
    const std::string owned_name(name);
    const idc_value_t* value = find_idc_gvar(owned_name.c_str());
    if (value == nullptr)
        return std::optional<Value>{};
    return std::optional<Value>{detail::ValueAccess::copy_native(*value)};
}

Result<bool> set_global(std::string_view name, const Value& value) {
    if (auto status = validate_c_string(name, "IDC global name", false); !status)
        return std::unexpected(status.error());
    const std::string owned_name(name);
    idc_value_t copied_value;
    const error_t copy_status = copy_idcv(
        &copied_value, detail::ValueAccess::native(value));
    if (copy_status != eOk) {
        return std::unexpected(native_value_error(
            "Failed to copy IDC global value", copy_status, owned_name));
    }
    idc_value_t* target = find_idc_gvar(owned_name.c_str());
    const bool created = target == nullptr;
    if (created)
        target = add_idc_gvar(owned_name.c_str());
    if (target == nullptr) {
        return std::unexpected(Error::sdk(
            "Failed to create IDC global", owned_name));
    }
    swap_idcvs(target, &copied_value);
    return created;
}

Result<Value> reference_global(std::string_view name) {
    if (auto status = validate_c_string(name, "IDC global name", false); !status)
        return std::unexpected(status.error());
    const std::string owned_name(name);
    const idc_value_t* target = find_idc_gvar(owned_name.c_str());
    if (target == nullptr) {
        return std::unexpected(Error::not_found(
            "IDC global was not found", owned_name));
    }
    idc_value_t reference;
    if (!create_idcv_ref(&reference, target)) {
        return std::unexpected(Error::sdk(
            "Failed to create IDC global reference", owned_name));
    }
    return detail::ValueAccess::move_native(reference);
}

static_assert(VT_LONG == 2);
static_assert(VT_FLOAT == 3);
static_assert(VT_OBJ == 5);
static_assert(VT_FUNC == 6);
static_assert(VT_STR == 7);
static_assert(VT_PVOID == 8);
static_assert(VT_INT64 == 9);
static_assert(VT_REF == 10);
static_assert(CPL_DEL_MACROS == 0x0001);
static_assert(CPL_USE_LABELS == 0x0002);
static_assert(CPL_ONLY_SAFE == 0x0004);
static_assert(std::is_nothrow_move_constructible_v<Value>);
static_assert(std::is_nothrow_move_assignable_v<Value>);
static_assert(std::is_same_v<decltype(&::eval_expr),
                             bool (*)(idc_value_t*, ea_t, const char*, qstring*)>);
static_assert(std::is_same_v<decltype(&::eval_idc_expr),
                             bool (*)(idc_value_t*, ea_t, const char*, qstring*)>);
static_assert(std::is_same_v<
              decltype(static_cast<bool (*)(sval_t*, ea_t, const char*, qstring*)>(
                  &::eval_expr_long)),
              bool (*)(sval_t*, ea_t, const char*, qstring*)>);
static_assert(std::is_same_v<decltype(&::compile_idc_file),
                             bool (*)(const char*, qstring*, int)>);
static_assert(std::is_same_v<decltype(&::compile_idc_text),
                             bool (*)(const char*, qstring*, idc_resolver_t*, bool)>);
static_assert(std::is_same_v<decltype(&::compile_idc_snippet),
                             bool (*)(const char*, const char*, qstring*,
                                      idc_resolver_t*, bool)>);
static_assert(std::is_same_v<decltype(&::call_idc_func),
                             bool (*)(idc_value_t*, const char*,
                                      const idc_value_t*, size_t, qstring*,
                                      idc_resolver_t*)>);
static_assert(std::is_same_v<decltype(&::eval_idc_snippet),
                             bool (*)(idc_value_t*, const char*, qstring*,
                                      idc_resolver_t*)>);

} // namespace ida::script

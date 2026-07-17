/// \file script.hpp
/// \brief Opaque IDC values and synchronous script execution.

#ifndef IDAX_SCRIPT_HPP
#define IDAX_SCRIPT_HPP

#include <ida/address.hpp>
#include <ida/error.hpp>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace ida::script {

/// Stable semantic kinds retained by an IDC value.
enum class ValueKind : std::uint8_t {
    Integer,
    FloatingPoint,
    Object,
    Function,
    String,
    OpaquePointer,
    Reference,
};

/// Reference traversal policy.
enum class DereferenceMode : std::uint8_t {
    Once,
    Recursive,
};

namespace detail {
class ValueAccess;
}

/// Copyable owned IDC value with no public SDK representation.
class Value {
public:
    /// Construct integer zero.
    Value();
    explicit Value(std::int64_t value);
    explicit Value(std::string_view value);

    Value(const Value& other);
    /// Move the retained value and leave `other` as integer zero.
    Value(Value&& other) noexcept;
    Value& operator=(const Value& other);
    /// Move-assign the retained value and leave `other` as integer zero.
    Value& operator=(Value&& other) noexcept;
    ~Value();

    /// Construct an IDC floating-point value.
    static Result<Value> floating(double value);

    /// Construct an instance of the default IDC object class.
    static Result<Value> object();

    /// Return the exact retained value kind.
    Result<ValueKind> kind() const;

    /// Exact kind-checked accessors; these never invoke IDC coercion.
    Result<std::int64_t> as_integer() const;
    Result<double> as_floating() const;
    Result<std::string> as_string() const;

    /// Explicit SDK coercions. These preserve IDC conversion semantics.
    Result<std::int64_t> coerce_integer() const;
    Result<double> coerce_floating() const;
    Result<std::string> coerce_string() const;

    /// Produce an IDC textual representation.
    Result<std::string> render(std::optional<std::string_view> name = std::nullopt,
                               std::size_t indent = 0) const;

    /// Deep-copy an object; non-object values use ordinary copy semantics.
    Result<Value> deep_copy() const;

    /// Return an object's copied class name.
    Result<std::string> class_name() const;

    /// Read, write, enumerate, and delete object attributes.
    Result<Value> attribute(std::string_view name,
                            bool use_handler = false) const;
    Status set_attribute(std::string_view name, const Value& value,
                         bool use_handler = false);
    Result<std::vector<std::string>> attribute_names() const;
    Result<bool> remove_attribute(std::string_view name);

    /// Read or replace a half-open string/object slice `[begin, end)`.
    Result<Value> slice(std::size_t begin, std::size_t end) const;
    Status replace_slice(std::size_t begin, std::size_t end,
                         const Value& replacement);

    /// Copy the value reached through an IDC reference.
    Result<Value> dereference(
        DereferenceMode mode = DereferenceMode::Recursive) const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;

    const Impl& read_state() const noexcept;
    Impl& write_state();

    explicit Value(std::unique_ptr<Impl> impl);
    friend class detail::ValueAccess;
};

/// One compile-time name resolved to an unsigned IDC constant.
struct ResolvedName {
    std::string name;
    std::uint64_t value{0};
};

/// Options for in-memory IDC compilation.
struct CompileOptions {
    bool only_safe_functions{false};
    std::vector<ResolvedName> resolved_names;
};

/// IDC file-compilation options.
struct FileCompileOptions {
    bool delete_macros_after_compilation{true};
    bool allow_program_labels{true};
    bool only_safe_functions{false};
};

/// Boolean compilation outcome with copied diagnostic text.
struct CompilationResult {
    bool succeeded{false};
    std::string error;
};

/// Boolean execution outcome. `value` retains an exception object on failure.
struct ExecutionResult {
    bool succeeded{false};
    Value value;
    std::string error;
};

/// Numeric expression outcome from the SDK's integer entry point.
struct IntegerExecutionResult {
    bool succeeded{false};
    std::int64_t value{0};
    std::string error;
};

/// Evaluate using the selected expression language.
Result<ExecutionResult> evaluate(
    std::string_view expression, Address where = BadAddress);

/// Evaluate using IDC even when another expression language is selected.
Result<ExecutionResult> evaluate_idc(
    std::string_view expression, Address where = BadAddress);

/// Evaluate through the selected language's integer entry point.
Result<IntegerExecutionResult> evaluate_integer(
    std::string_view expression, Address where = BadAddress);

/// Compile IDC definitions from a file, source text, or a named snippet.
Result<CompilationResult> compile_file(
    std::string_view path,
    const FileCompileOptions& options = FileCompileOptions{});
Result<CompilationResult> compile_text(
    std::string_view source,
    const CompileOptions& options = CompileOptions{});
Result<CompilationResult> compile_snippet(
    std::string_view function_name, std::string_view body,
    const CompileOptions& options = CompileOptions{});

/// Invoke a compiled, built-in, or plugin-defined IDC function.
Result<ExecutionResult> call(
    std::string_view function_name, const std::vector<Value>& arguments = {},
    const std::vector<ResolvedName>& resolved_names = {});

/// Compile an IDC file and invoke one function when compilation succeeds.
Result<ExecutionResult> execute_script(
    std::string_view path, std::string_view function_name,
    const std::vector<Value>& arguments = {},
    const FileCompileOptions& options = FileCompileOptions{});

/// Compile and execute IDC statements or expressions.
Result<ExecutionResult> evaluate_snippet(
    std::string_view source,
    const std::vector<ResolvedName>& resolved_names = {});

/// Replace or append IDC include-search path components.
Status set_include_paths(const std::vector<std::string>& paths);
Status append_include_paths(const std::vector<std::string>& paths);

/// Resolve one IDC filename through the interpreter search path.
Result<std::optional<std::string>> resolve_file(std::string_view file);

/// Compile and execute `main` from an IDC system script.
Status execute_system_script(std::string_view file,
                             bool complain_if_missing = false);

/// Enumerate copied registered/built-in IDC function names matching a prefix.
Result<std::vector<std::string>> function_names(
    std::string_view prefix = {}, std::size_t maximum = 1024);

/// Read a copied global, assign/create a global, or reference an existing global.
Result<std::optional<Value>> global(std::string_view name);
Result<bool> set_global(std::string_view name, const Value& value);
Result<Value> reference_global(std::string_view name);

} // namespace ida::script

#endif // IDAX_SCRIPT_HPP

/// \file script_roundtrip_test.cpp
/// \brief Isolated IDC value and synchronous execution evidence.

#include <ida/idax.hpp>

#include <climits>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

int passed = 0;
int failed = 0;

#define CHECK(expression)                                                   \
    do {                                                                    \
        if (expression) {                                                   \
            ++passed;                                                       \
        } else {                                                            \
            ++failed;                                                       \
            std::cerr << "FAIL: " #expression " (" << __FILE__ << ':'      \
                      << __LINE__ << ")\n";                                \
        }                                                                   \
    } while (false)

template <typename T>
bool require(const ida::Result<T>& result, std::string_view operation) {
    if (result)
        return true;
    ++failed;
    std::cerr << "FAIL: " << operation << ": " << result.error().message
              << " [" << result.error().context << "]\n";
    return false;
}

bool require_status(const ida::Status& status, std::string_view operation) {
    if (status)
        return true;
    ++failed;
    std::cerr << "FAIL: " << operation << ": " << status.error().message
              << " [" << status.error().context << "]\n";
    return false;
}

void expect_integer(const ida::script::Value& value, std::int64_t expected) {
    auto integer = value.as_integer();
    CHECK(integer.has_value());
    if (integer)
        CHECK(*integer == expected);
}

} // namespace

int main(int argc, char* argv[]) {
    using namespace ida::script;

    if (argc < 2) {
        std::cerr << "Usage: script_roundtrip_test <fixture>\n";
        return 1;
    }
    if (!require_status(ida::database::init(argc, argv), "database init"))
        return 1;
    if (!require_status(ida::database::open(argv[1], true), "database open"))
        return 1;

    CHECK(static_cast<int>(ValueKind::Integer) == 0);
    CHECK(static_cast<int>(ValueKind::Reference) == 6);

    Value zero;
    expect_integer(zero, 0);
    Value integer(std::int64_t{42});
    expect_integer(integer, 42);
    Value string(std::string_view("ab\0cd", 5));
    auto exact_string = string.as_string();
    CHECK(exact_string.has_value());
    if (exact_string)
        CHECK(exact_string->size() == 5 && (*exact_string)[2] == '\0');
    Value empty_string(std::string_view{});
    auto exact_empty_string = empty_string.as_string();
    CHECK(exact_empty_string.has_value() && exact_empty_string->empty());
    Value moved_source(17);
    Value moved_value(std::move(moved_source));
    expect_integer(moved_value, 17);
    expect_integer(moved_source, 0);
    Value assigned_source(23);
    moved_value = std::move(assigned_source);
    expect_integer(moved_value, 23);
    expect_integer(assigned_source, 0);
    Value copied_moved_source = assigned_source;
    expect_integer(copied_moved_source, 0);

    auto floating = Value::floating(1.5);
    CHECK(floating.has_value());
    if (floating) {
        auto exact_float = floating->as_floating();
        CHECK(exact_float.has_value());
        if (exact_float)
            CHECK(*exact_float == 1.5);
    }
    CHECK(!integer.as_string().has_value());
    auto coercion = Value("not-a-number").coerce_integer();
    CHECK(coercion.has_value());
    if (coercion)
        CHECK(*coercion == 0);
    auto coerced_string = integer.coerce_string();
    CHECK(coerced_string.has_value());

    Value mutable_string("abcdef");
    Value copied_string = mutable_string;
    CHECK(require_status(copied_string.replace_slice(2, 4, Value("XY")),
                         "replace copied string slice"));
    auto original_text = mutable_string.as_string();
    auto copied_text = copied_string.as_string();
    CHECK(original_text.has_value() && *original_text == "abcdef");
    CHECK(copied_text.has_value() && *copied_text == "abXYef");
    auto slice = copied_string.slice(1, 5);
    CHECK(slice.has_value());
    if (slice) {
        auto slice_text = slice->as_string();
        CHECK(slice_text.has_value() && *slice_text == "bXYe");
    }
    CHECK(!copied_string.slice(5, 4).has_value());
    CHECK(!copied_string.replace_slice(5, 4, Value("x")).has_value());
    CHECK(!integer.render(std::nullopt,
                          static_cast<std::size_t>(INT_MAX) + 1).has_value());

    auto object = Value::object();
    CHECK(object.has_value());
    if (object) {
        CHECK(require_status(object->set_attribute("answer", Value(7)),
                             "set object attribute"));
        Value shallow = *object;
        CHECK(require_status(shallow.set_attribute("answer", Value(9)),
                             "mutate shallow object copy"));
        auto original_answer = object->attribute("answer");
        CHECK(original_answer.has_value());
        if (original_answer)
            expect_integer(*original_answer, 9);

        auto deep = object->deep_copy();
        CHECK(deep.has_value());
        if (deep) {
            CHECK(require_status(deep->set_attribute("answer", Value(11)),
                                 "mutate deep object copy"));
            auto deep_answer = deep->attribute("answer");
            CHECK(deep_answer.has_value());
            if (deep_answer)
                expect_integer(*deep_answer, 11);
            auto still_original = object->attribute("answer");
            CHECK(still_original.has_value());
            if (still_original)
                expect_integer(*still_original, 9);
        }
        auto names = object->attribute_names();
        CHECK(names.has_value() && names->size() == 1
              && names->front() == "answer");
        CHECK(!object->attribute("missing").has_value());
        CHECK(!object->attribute(std::string_view("bad\0name", 8)).has_value());
        auto removed_missing = object->remove_attribute("missing");
        CHECK(removed_missing.has_value() && !*removed_missing);
        auto removed = object->remove_attribute("answer");
        CHECK(removed.has_value() && *removed);
        auto class_name = object->class_name();
        CHECK(class_name.has_value() && !class_name->empty());
        auto rendered = object->render("probe", 1);
        CHECK(rendered.has_value() && !rendered->empty());
    }

    auto falsey = evaluate_idc("0");
    CHECK(falsey.has_value() && falsey->succeeded && falsey->error.empty());
    if (falsey)
        expect_integer(falsey->value, 0);
    auto arithmetic = evaluate_idc("6 * 7");
    CHECK(arithmetic.has_value() && arithmetic->succeeded);
    if (arithmetic)
        expect_integer(arithmetic->value, 42);
    auto selected = evaluate("40 + 2");
    CHECK(selected.has_value() && selected->succeeded);
    if (selected)
        expect_integer(selected->value, 42);
    auto integer_result = evaluate_integer("21 * 2");
    CHECK(integer_result.has_value() && integer_result->succeeded
          && integer_result->value == 42);

    auto syntax_error = evaluate_idc("1 +");
    CHECK(syntax_error.has_value() && !syntax_error->succeeded
          && !syntax_error->error.empty());
    auto runtime_error = evaluate_idc("1 / 0");
    CHECK(runtime_error.has_value() && !runtime_error->succeeded
          && !runtime_error->error.empty());
    if (runtime_error) {
        auto exception_kind = runtime_error->value.kind();
        CHECK(exception_kind.has_value()
              && *exception_kind == ValueKind::Object);
        auto exception_class = runtime_error->value.class_name();
        CHECK(exception_class.has_value() && !exception_class->empty());
    }

    CompileOptions compile_options;
    compile_options.resolved_names.push_back({"IDAX_PHASE71_CONST", 40});
    auto compiled = compile_text(
        "static idax_phase71_add(a, b) { return a + b + IDAX_PHASE71_CONST; }",
        compile_options);
    CHECK(compiled.has_value() && compiled->succeeded && compiled->error.empty());
    auto called = call("idax_phase71_add", {Value(1), Value(1)});
    CHECK(called.has_value() && called->succeeded);
    if (called)
        expect_integer(called->value, 42);

    auto snippet_compilation = compile_snippet(
        "idax_phase71_snippet", "return IDAX_PHASE71_CONST + 2;",
        compile_options);
    CHECK(snippet_compilation.has_value() && snippet_compilation->succeeded);
    auto snippet_call = call("idax_phase71_snippet");
    CHECK(snippet_call.has_value() && snippet_call->succeeded);
    if (snippet_call)
        expect_integer(snippet_call->value, 42);
    auto snippet = evaluate_snippet(
        "return IDAX_PHASE71_CONST + 2;",
        compile_options.resolved_names);
    CHECK(snippet.has_value() && snippet->succeeded);
    if (snippet)
        expect_integer(snippet->value, 42);

    auto missing_call = call("__idax_phase71_missing__");
    CHECK(missing_call.has_value() && !missing_call->succeeded
          && !missing_call->error.empty());
    auto duplicate_resolver = compile_text(
        "static idax_phase71_duplicate() { return DUP; }",
        CompileOptions{false, {{"DUP", 1}, {"DUP", 2}}});
    CHECK(!duplicate_resolver.has_value());
    auto sentinel_resolver = compile_text(
        "static idax_phase71_sentinel() { return SENTINEL; }",
        CompileOptions{false, {{"SENTINEL", ida::BadAddress}}});
    CHECK(!sentinel_resolver.has_value());
    CHECK(!evaluate_idc(std::string_view("1\0+2", 4)).has_value());
    CHECK(!evaluate_idc("").has_value());
    CHECK(!compile_file("").has_value());
    CHECK(!compile_text("").has_value());
    CHECK(!compile_snippet("", "return 0;").has_value());
    CHECK(!compile_snippet("idax_phase71_empty", "").has_value());
    CHECK(!call("").has_value());
    CHECK(!evaluate_snippet("").has_value());
    CHECK(!set_include_paths({"invalid;component"}).has_value());
    CHECK(!resolve_file("").has_value());
    CHECK(!execute_system_script("").has_value());
    CHECK(!reference_global("__idax_phase71_missing_global__").has_value());

    const std::string global_name = "idax_phase71_global";
    auto missing_global = global(global_name);
    CHECK(missing_global.has_value() && !missing_global->has_value());
    auto created = set_global(global_name, Value(123));
    CHECK(created.has_value() && *created);
    auto copied_global = global(global_name);
    CHECK(copied_global.has_value() && copied_global->has_value());
    if (copied_global && *copied_global)
        expect_integer(**copied_global, 123);
    auto reference = reference_global(global_name);
    CHECK(reference.has_value());
    if (reference) {
        auto kind = reference->kind();
        CHECK(kind.has_value() && *kind == ValueKind::Reference);
        auto dereferenced = reference->dereference();
        CHECK(dereferenced.has_value());
        if (dereferenced)
            expect_integer(*dereferenced, 123);
    }
    auto updated = set_global(global_name, Value(456));
    CHECK(updated.has_value() && !*updated);

    const auto directory = std::filesystem::path(argv[1]).parent_path();
    const auto script_path = directory / "idax_phase71_file.idc";
    {
        std::ofstream script(script_path, std::ios::binary | std::ios::trunc);
        script << "static idax_phase71_file(x) { return x * 2; }\n";
        CHECK(script.good());
    }
    CHECK(require_status(set_include_paths({directory.string()}),
                         "set IDC include path"));
    auto resolved = resolve_file(script_path.filename().string());
    CHECK(resolved.has_value() && resolved->has_value());
    auto file_result = execute_script(
        script_path.string(), "idax_phase71_file", {Value(21)});
    CHECK(file_result.has_value() && file_result->succeeded);
    if (file_result)
        expect_integer(file_result->value, 42);
    std::error_code remove_error;
    std::filesystem::remove(script_path, remove_error);
    CHECK(!remove_error);
    auto now_missing = resolve_file(script_path.filename().string());
    CHECK(now_missing.has_value() && !now_missing->has_value());

    auto functions = function_names("", 16);
    CHECK(functions.has_value() && !functions->empty());
    CHECK(!function_names("", 0).has_value());
    CHECK(!function_names("", static_cast<std::size_t>(INT_MAX) + 1)
               .has_value());

    ida::database::close(false);
    if (object) {
        auto retained_class = object->class_name();
        CHECK(retained_class.has_value() && !retained_class->empty());
    }

    std::cout << "script roundtrip: " << passed << " passed, " << failed
              << " failed\n";
    return failed == 0 ? 0 : 1;
}

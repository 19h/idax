# IDC Values and Script Execution

`ida::script` owns IDC values without exposing `idc_value_t`, bytecode,
interpreter records, or resolver pointers. Interpreter failure is represented
inside an `ExecutionResult`; wrapper validation and SDK-adapter failure remain
the outer `ida::Result` error.

```cpp
using namespace ida::script;

auto evaluated = evaluate_idc("6 * 7");
if (!evaluated)
    return std::unexpected(evaluated.error());
if (!evaluated->succeeded)
    return std::unexpected(ida::Error::sdk(evaluated->error));

auto answer = evaluated->value.as_integer(); // exact kind check
```

Do not infer execution success from value truthiness: IDC integer zero is a
successful result. A runtime error such as division by zero returns
`succeeded == false`, diagnostic text, and an object-valued exception that can
be inspected through `class_name()` and `attribute()`.

Exact access and coercion are intentionally separate. `as_integer()` rejects a
string, while `coerce_integer()` applies IDC conversion rules; a nonnumeric IDC
string can therefore coerce successfully to zero.

## Compile and call

```cpp
ida::script::CompileOptions options;
options.resolved_names.push_back({"CONFIG_BASE", 40});

auto compiled = ida::script::compile_snippet(
    "compute_answer", "return CONFIG_BASE + 2;", options);
if (!compiled || !compiled->succeeded) {
    // Report transport or compilation diagnostics.
}

auto called = ida::script::call("compute_answer");
if (called && called->succeeded) {
    auto value = called->value.as_integer();
}
```

Resolved names must be unique, nonempty, and different from the native
unresolved sentinel. They are copied into a synchronous resolver whose lifetime
ends when compilation or invocation returns. `evaluate_snippet` accepts the
resolved-name list directly because its native SDK entry point has no
safe-functions compilation flag.

## Objects, globals, and files

Ordinary object copies share native object identity; use `deep_copy()` when
subsequent attribute mutation must be isolated. String and object slice bounds
are half-open `[begin, end)`. `global()` returns a copied optional value,
`set_global()` reports whether it created the name, and `reference_global()`
returns an opaque reference that can be dereferenced once or recursively.

`compile_file()` only compiles. `execute_script()` compiles then calls the named
function. Include paths are explicit string components; semicolons are rejected
because the native SDK uses them as its path-list separator. `resolve_file()`
returns absence for a missing file rather than an SDK error.

External IDC-function registration and third-party language installation retain
host callbacks beyond one call and are intentionally outside this synchronous
domain.

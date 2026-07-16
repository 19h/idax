# Source-parser selection and type ingestion

`ida::parser` is the opaque boundary for the third-party parser registry in
`srclang.hpp`. It is separate from `ida::type::parse_declarations`: the parser
domain selects an installed parser by name or supported language, configures
parser-owned arguments/options, reads source text or a source file, and imports
successful declarations into the current database's local type library.

## C++: select by language and parse memory

```cpp
#include <ida/idax.hpp>

auto selected = ida::parser::select_for(
    ida::parser::Language::C | ida::parser::Language::Cpp);
if (!selected)
    return std::unexpected(selected.error());

auto parser_name = ida::parser::selected_name();
if (!parser_name)
    return std::unexpected(parser_name.error());

auto report = ida::parser::parse_for(
    ida::parser::Language::Cpp,
    "struct packet_header { unsigned size; };",
    ida::parser::InputKind::SourceText);
if (!report)
    return std::unexpected(report.error());
if (!report->ok())
    return std::unexpected(ida::Error::sdk("source contained parser errors"));
```

`select_for()` requires a nonempty set containing only the six declared
language bits. `selected_name()` returns a copied optional string. Absence
means the host returned unnamed default state; selecting the default does not
guarantee absence because the host may resolve it to an explicitly named
parser.

## C++: named parser, extended options, and files

```cpp
ida::parser::ParseOptions options;
options.input_kind = ida::parser::InputKind::FilePath;
options.suppress_warnings = true;
options.allow_redeclarations = true;
options.pack_alignment = 4;

auto report = ida::parser::parse_with_options("clang", "types.hpp", options);
```

Valid packing values are `0` (parser default), `1`, `2`, `4`, `8`, and `16`
bytes. High-level and lowered-prototype transformations are mutually exclusive.
The wrapper validates strings, enums, masks, and options before calling IDA;
syntax diagnostics remain a successful `ParseReport` with a nonzero
`error_count`.

## Parser-owned configuration

```cpp
auto configured = ida::parser::set_arguments("clang", "-DIDAX_BUILD=1");
auto old_value = ida::parser::option("clang", "CLANG_APPLY_TINFO");
if (old_value)
    ida::parser::set_option("clang", "CLANG_APPLY_TINFO", *old_value);
```

Option keys and accepted values belong to each installed parser. An unavailable
key returns `NotFound`; argument configuration can additionally return
`Unsupported`. Configuration-file variables are not necessarily registered
parser options.

## Binding equivalents

Python:

```python
from idax import parser

parser.select_for([parser.Language.C, parser.Language.CPP])
report = parser.parse_for(
    parser.Language.CPP,
    "struct packet_header { unsigned size; };",
)
assert report.ok
```

Node:

```javascript
idax.parser.selectFor(['c', 'cpp']);
const report = idax.parser.parseFor(
  'cpp',
  'struct packet_header { unsigned size; };',
);
if (!report.ok) throw new Error(`${report.errorCount} parser errors`);
```

Rust:

```rust,no_run
use idax::parser::{self, InputKind, Language};

parser::select_for(Language::C | Language::Cpp)?;
let report = parser::parse_for(
    Language::Cpp,
    "struct packet_header { unsigned size; };",
    InputKind::SourceText,
)?;
assert!(report.is_ok());
# Ok::<(), idax::error::Error>(())
```

All four surfaces copy returned identity/configuration strings, store parsed
types in the current local type library, and expose no parser pointer, `til_t`,
`qstring`, `srclang_t`, or raw `HTI_*` flags.

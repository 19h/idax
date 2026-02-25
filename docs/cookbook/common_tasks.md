# Cookbook: Common Analysis Tasks

## End-to-end: list all functions and iterate addresses (C++)

```cpp
#include <ida/idax.hpp>

#include <iostream>

int list_functions(const char* path) {
  if (auto s = ida::database::init(); !s) return 1;
  if (auto s = ida::database::open(path, true); !s) return 1;
  if (auto s = ida::analysis::wait(); !s) {
    (void) ida::database::close(false);
    return 1;
  }

  auto total = ida::function::count();
  if (!total) {
    (void) ida::database::close(false);
    return 1;
  }

  std::cout << *total << " functions\n";
  for (std::size_t i = 0; i < *total; ++i) {
    auto f = ida::function::by_index(i);
    if (!f) continue;
    std::cout << "  #" << i
              << " " << std::hex << f->start() << ".." << f->end()
              << " " << f->name() << "\n";
  }

  (void) ida::database::close(false);
  return 0;
}
```

## End-to-end: extract and process strings from data segments (C++)

```cpp
#include <ida/idax.hpp>

#include <cctype>
#include <string>
#include <vector>

bool looks_interesting(std::string_view s) {
  if (s.size() < 6) return false;
  for (char c : s) {
    unsigned char uc = static_cast<unsigned char>(c);
    if (!(std::isprint(uc) || c == ' ')) return false;
  }
  return true;
}

std::vector<std::pair<ida::Address, std::string>> collect_strings(const char* path) {
  std::vector<std::pair<ida::Address, std::string>> out;

  if (auto s = ida::database::init(); !s) return out;
  if (auto s = ida::database::open(path, true); !s) return out;
  if (auto s = ida::analysis::wait(); !s) {
    (void) ida::database::close(false);
    return out;
  }

  for (auto seg : ida::segment::all()) {
    if (seg.permissions().execute || seg.type() == ida::segment::Type::Code) {
      continue;
    }

    for (auto ea : ida::address::data_items(seg.start(), seg.end())) {
      auto s = ida::data::read_string(ea, 256);
      if (!s) continue;
      if (looks_interesting(*s)) {
        out.emplace_back(ea, *s);
      }
    }
  }

  (void) ida::database::close(false);
  return out;
}

ida::Result<std::string> define_then_read_string(ida::Address ea, ida::AddressSize len) {
  auto s = ida::data::define_string(ea, len, 0);
  if (!s) return std::unexpected(s.error());
  return ida::data::read_string(ea, len);
}
```

## End-to-end: rename functions and variables (C++)

```cpp
#include <ida/idax.hpp>

int rename_symbols(const char* path) {
  if (auto s = ida::database::init(); !s) return 1;
  if (auto s = ida::database::open(path, true); !s) return 1;
  if (auto s = ida::analysis::wait(); !s) {
    (void) ida::database::close(false);
    return 1;
  }

  auto fn_ea = ida::name::resolve("sub_401000", ida::BadAddress);
  if (!fn_ea) {
    (void) ida::database::close(false);
    return 1;
  }

  // Function rename.
  (void) ida::name::set(*fn_ea, "decode_header");

  // Register-variable rename (if any register variable exists).
  if (auto vars = ida::function::register_variables(*fn_ea); vars && !vars->empty()) {
    const auto& first = vars->front();
    (void) ida::function::rename_register_variable(
      *fn_ea,
      first.range_start,
      first.canonical_name,
      "packet_len");
  }

  // Stack-variable define/rename path.
  if (auto var = ida::function::frame_variable_by_name(*fn_ea, "var_10")) {
    auto ty = ida::type::TypeInfo::int32();
    (void) ida::function::define_stack_variable(
      *fn_ea,
      "decoded_size",
      static_cast<std::int32_t>(var->byte_offset),
      ty);
  }

  (void) ida::database::close(false);
  return 0;
}
```

If you specifically need safe-Rust variants for these tasks, see
`bindings/rust/idax/README.md` and the Rust-focused scenario tutorials in
`docs/tutorial/`.

## C++ quick snippets

### Rename a function

```cpp
auto ea = ida::name::resolve("sub_401000");
if (ea) ida::name::set(*ea, "decode_header");
```

### Add comment block around an address

```cpp
ida::comment::set(ea, "entry validation path");
ida::comment::set_anterior_lines(ea, {"-- begin validation --", "checks checksum"});
ida::comment::set_posterior_lines(ea, {"-- end validation --"});
```

### Find call xrefs to symbol

```cpp
auto target = ida::name::resolve("main");
if (target) {
  auto refs = ida::xref::code_refs_to(*target);
  for (const auto &r : *refs) {
    // r.from is caller site
  }
}
```

### Find pattern and patch byte

```cpp
auto lo = ida::database::min_address();
auto hi = ida::database::max_address();
if (lo && hi) {
  auto hit = ida::data::find_binary_pattern(*lo, *hi, "90 90 C3");
  if (hit) ida::data::patch_byte(*hit, 0xCC);
}
```

### Queue analysis and wait

```cpp
ida::analysis::schedule(ea);
ida::analysis::wait();
```

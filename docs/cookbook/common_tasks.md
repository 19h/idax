# Cookbook: Common Analysis Tasks

## Rename a function

```cpp
auto ea = ida::name::resolve("sub_401000");
if (ea) ida::name::set(*ea, "decode_header");
```

## Add comment block around an address

```cpp
ida::comment::set(ea, "entry validation path");
ida::comment::set_anterior_lines(ea, {"-- begin validation --", "checks checksum"});
ida::comment::set_posterior_lines(ea, {"-- end validation --"});
```

## Find call xrefs to symbol

```cpp
auto target = ida::name::resolve("main");
if (target) {
  auto refs = ida::xref::code_refs_to(*target);
  for (const auto &r : *refs) {
    // r.from is caller site
  }
}
```

## Find pattern and patch byte

```cpp
auto lo = ida::database::min_address();
auto hi = ida::database::max_address();
if (lo && hi) {
  auto hit = ida::data::find_binary_pattern(*lo, *hi, "90 90 C3");
  if (hit) ida::data::patch_byte(*hit, 0xCC);
}
```

## Queue analysis and wait

```cpp
ida::analysis::schedule(ea);
ida::analysis::wait();
```

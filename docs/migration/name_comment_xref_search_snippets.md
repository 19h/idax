# Migration Snippets: Name / Comment / Xref / Search

## Name operations

```cpp
// Legacy: set_name(ea, "foo", SN_NOWARN);
ida::name::set(ea, "foo");
```

## Comment operations

```cpp
// Legacy: set_cmt(ea, "note", 0);
ida::comment::set(ea, "note", false);

// Legacy extra comments
ida::comment::set_anterior_lines(ea, {"line1", "line2"});
```

## Xref operations

```cpp
// Legacy: add_cref(from, to, fl_CN);
ida::xref::add_code(from, to, ida::xref::CodeType::CallNear);
```

## Search operations

```cpp
// Legacy: find_text(..., SEARCH_REGEX)
ida::search::TextOptions o;
o.regex = true;
auto hit = ida::search::text("main", start, o);
```

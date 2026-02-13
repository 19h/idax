# Legacy SDK -> idax Migration Map

## Quick reference table

| Legacy SDK | idax |
|---|---|
| `getseg(ea)` | `ida::segment::at(ea)` |
| `get_segm_qty()` | `ida::segment::count()` |
| `get_next_seg(ea)` | iterate `ida::segment::all()` |
| `set_segm_name(seg, n)` | `seg.set_name(n)` |
| `add_func(start, end)` | `ida::function::create(start, end)` |
| `del_func(ea)` | `ida::function::remove(ea)` |
| `get_func_name(&buf, ea)` | `func.name()` |
| `decode_insn(&insn, ea)` | `ida::instruction::decode(ea)` |
| `create_insn(ea)` | `ida::instruction::create(ea)` |
| `get_byte(ea)` | `ida::data::read_byte(ea)` |
| `put_byte(ea, v)` | `ida::data::write_byte(ea, v)` |
| `patch_byte(ea, v)` | `ida::data::patch_byte(ea, v)` |
| `del_items(ea, ...)` | `ida::data::undefine(ea, size)` |
| `set_name(ea, n, SN_NOWARN)` | `ida::name::set(ea, n)` |
| `force_name(ea, n)` | `ida::name::force_set(ea, n)` |
| `set_cmt(ea, txt, rpt)` | `ida::comment::set(ea, txt, rpt)` |
| `add_cref(from, to, fl_CN)` | `ida::xref::add_code(from, to, CodeType::CallNear)` |
| `add_dref(from, to, dr_R)` | `ida::xref::add_data(from, to, DataType::Read)` |
| `find_text(...)` | `ida::search::text(query, start, options)` |
| `auto_wait()` | `ida::analysis::wait()` |
| `plan_ea(ea)` | `ida::analysis::schedule(ea)` |
| `open_linput(path, false)` | `ida::loader::InputFile` (provided in callbacks) |
| `file2base(li, off, ea1, ea2, p)` | `ida::loader::file_to_database(handle, off, ea, size, p)` |
| `mem2base(ptr, ea1, ea2, fpos)` | `ida::loader::memory_to_database(ptr, ea, size)` |

## Entry-point migration

```cpp
// Legacy: iterating entry points
// for (size_t i = 0; i < get_entry_qty(); i++) {
//     ea_t ea = get_entry(get_entry_ordinal(i));
//     qstring name; get_entry_name(&name, get_entry_ordinal(i));
// }

// idax:
auto cnt = ida::entry::count();
if (cnt) {
    for (std::size_t i = 0; i < *cnt; ++i) {
        auto ep = ida::entry::by_index(i);
        if (ep) {
            // ep->address, ep->name, ep->ordinal
        }
    }
}
```

## Module authoring

```cpp
// Loader skeleton
class MyLoader : public ida::loader::Loader {
    Result<std::optional<AcceptResult>> accept(InputFile& f) override { ... }
    Status load(InputFile& f, std::string_view fmt) override { ... }
};
IDAX_LOADER(MyLoader)

// Processor skeleton
class MyProc : public ida::processor::Processor {
    ProcessorInfo info() const override { ... }
    Result<int> analyze(Address ea) override { ... }
    EmulateResult emulate(Address ea) override { ... }
    void output_instruction(Address ea) override { ... }
    OutputOperandResult output_operand(Address ea, int idx) override { ... }
};
IDAX_PROCESSOR(MyProc)
```

---

## Type system migration

The IDA SDK type system (`tinfo_t`, `til_t`, `udt_member_t`) is one of the most
complex areas. idax wraps it behind `ida::type::TypeInfo`, which is a
fully-opaque value type.

### Creating primitive types

```cpp
// Legacy:
// tinfo_t ti;
// ti.create_simple_type(BT_INT32);

// idax:
auto i32 = ida::type::TypeInfo::int32();
auto u64 = ida::type::TypeInfo::uint64();
auto f64 = ida::type::TypeInfo::float64();
```

### Creating composite types

```cpp
// Legacy:
// tinfo_t ti;
// ti.create_ptr(int32_tinfo);

// idax:
auto ptr = ida::type::TypeInfo::pointer_to(ida::type::TypeInfo::int32());
auto arr = ida::type::TypeInfo::array_of(ida::type::TypeInfo::uint8(), 256);
```

### Struct creation and member access

```cpp
// Legacy:
// struc_t *s = get_struc(add_struc(BADADDR, "my_struct"));
// add_struc_member(s, "field_a", 0, dword_flag(), nullptr, 4);
// add_struc_member(s, "field_b", 4, qword_flag(), nullptr, 8);

// idax:
auto st = ida::type::TypeInfo::create_struct("my_struct");
if (st) {
    st->add_member("field_a", ida::type::TypeInfo::int32());
    st->add_member("field_b", ida::type::TypeInfo::int64());

    // Access members:
    auto count = st->member_count();  // -> 2
    auto members = st->members();     // -> vector<MemberInfo>
    auto by_name = st->member_by_name("field_a");
    auto by_off  = st->member_by_offset(4);  // field_b
}
```

### Applying types to addresses

```cpp
// Legacy:
// apply_tinfo(ea, &ti, TINFO_GUESSED);

// idax:
auto ti = ida::type::TypeInfo::int32();
ti.apply(ea);  // apply to address

// Or apply a named type from the type library:
ida::type::apply_named_type(ea, "my_struct");
```

### Type library operations

```cpp
// Legacy:
// add_til("ntapi", ADDTIL_DEFAULT);
// import_type(get_idati(), -1, "HANDLE");

// idax:
ida::type::load_type_library("ntapi");
ida::type::import_type("HANDLE");

auto count = ida::type::local_type_count();
auto name  = ida::type::local_type_name(1);
```

### Roundtrip: parse declaration -> inspect -> save

```cpp
auto ti = ida::type::TypeInfo::from_declaration("struct foo { int x; char y; };");
if (ti) {
    auto mc = ti->member_count();    // 2
    auto s  = ti->size();            // platform-dependent
    auto decl = ti->to_string();     // "struct foo { int x; char y; }"

    // Save to the local type library:
    ti->save_as("foo");

    // Later retrieve by name:
    auto loaded = ida::type::TypeInfo::by_name("foo");
}
```

---

## Storage / netnode migration

Netnodes are IDA's low-level key-value store. idax wraps them behind
`ida::storage::Node`. The API supports alt (integer), sup (binary blob),
hash (string key-value), and blob operations.

### Opening and creating nodes

```cpp
// Legacy:
// netnode n("my_plugin_data", 0, true);  // create

// idax:
auto node = ida::storage::Node::open("my_plugin_data", true);
if (!node) { /* handle error */ }
```

### Alt values (integer key-value at Address indices)

```cpp
// Legacy:
// n.altset(100, 42);
// uval_t v = n.altval(100);

// idax:
node->set_alt(100, 42);
auto v = node->alt(100);  // -> Result<uint64_t>
node->remove_alt(100);
```

### Sup values (binary blobs at Address indices)

```cpp
// Legacy:
// n.supset(200, data, size);
// ssize_t sz = n.supval(200, buf, bufsize);

// idax:
std::vector<std::uint8_t> data = {0x01, 0x02, 0x03};
node->set_sup(200, data);
auto read = node->sup(200);  // -> Result<vector<uint8_t>>
```

### Hash values (string key -> string value)

```cpp
// Legacy:
// n.hashset("version", "1.0");
// ssize_t sz = n.hashval("version", buf, bufsize);

// idax:
node->set_hash("version", "1.0");
auto val = node->hash("version");  // -> Result<string>
```

### Blob operations (large binary data)

```cpp
// Legacy:
// n.setblob(data, size, 100, 'B');
// ssize_t sz = n.getblob(buf, &bufsize, 100, 'B');

// idax — use indices >= 100 to avoid idalib crashes at index 0:
std::vector<std::uint8_t> blob = { /* ... */ };
node->set_blob(100, blob);
auto sz = node->blob_size(100);  // -> Result<size_t>
auto rd = node->blob(100);       // -> Result<vector<uint8_t>>
node->remove_blob(100);

// String convenience:
node->set_blob_string(101, "hello world");
auto s = node->blob_string(101);  // -> Result<string>
```

### Multi-tag isolation

Different tag characters create independent value spaces on the same node:

```cpp
node->set_alt(300, 100, 'A');  // tag 'A'
node->set_alt(300, 200, 'X');  // tag 'X' — independent
auto a = node->alt(300, 'A');  // -> 100
auto x = node->alt(300, 'X');  // -> 200
```

### Copy/move semantics

```cpp
auto n1 = ida::storage::Node::open("test_node", true);
auto n2 = *n1;          // copy — shares same underlying netnode
auto n3 = std::move(n2); // move — n2 is invalidated
```

### Common pitfall: index 0 crashes

Netnode blob operations at index 0 can trigger crashes in idalib mode.
Always use indices >= 100 for blob/alt/sup operations in plugins.

---

## Decompiler migration

The Hex-Rays SDK uses `hexrays_failure_t`, `cfuncptr_t`, `ctree_visitor_t`,
and manual `va_list` dispatch. idax provides a fully opaque API.

### Availability check and basic decompilation

```cpp
// Legacy:
// if (!init_hexrays_plugin()) return;
// cfuncptr_t cf = decompile(get_func(ea));
// const strvec_t &sv = cf->get_pseudocode();

// idax:
auto avail = ida::decompiler::available();
if (!avail || !*avail) return;

auto result = ida::decompiler::decompile(func_ea);
if (!result) return;  // DecompiledFunction is move-only
auto& df = *result;

auto code = df.pseudocode();       // -> Result<string>
auto lines = df.lines();           // -> Result<vector<string>>
auto decl = df.declaration();      // -> Result<string>
```

### Local variable inspection and renaming

```cpp
// Legacy:
// lvars_t *vars = cf->get_lvars();
// lvar_t &v = (*vars)[i];
// cf->rename_lvar(v, "better_name");

// idax:
auto vc = df.variable_count();
auto vars = df.variables();
if (vars) {
    for (auto& v : *vars) {
        // v.name, v.type_name, v.is_argument, v.width
    }
}
df.rename_variable("old_name", "new_name");
```

### Ctree traversal with visitor

```cpp
// Legacy:
// struct my_visitor : ctree_visitor_t {
//     int visit_expr(cexpr_t *e) override { ... }
//     int visit_insn(cinsn_t *i) override { ... }
// };
// my_visitor v; v.apply_to(&cf->body, nullptr);

// idax — class-based:
class MyVisitor : public ida::decompiler::CtreeVisitor {
public:
    int call_count = 0;
    VisitAction visit_expression(ExpressionView expr) override {
        if (expr.type() == ItemType::ExprCall) ++call_count;
        return VisitAction::Continue;
    }
};
MyVisitor v;
df.visit(v);
// v.call_count now has the number of function calls

// idax — functional style:
int calls = 0;
ida::decompiler::for_each_expression(df, [&](auto expr) {
    if (expr.type() == ida::decompiler::ItemType::ExprCall)
        ++calls;
    return ida::decompiler::VisitAction::Continue;
});
```

### User comments in pseudocode

```cpp
// Legacy:
// treeloc_t loc; loc.ea = ea; loc.itp = ITP_SEMI;
// cf->set_user_cmt(loc, "note");
// cf->save_user_cmts();

// idax:
df.set_comment(ea, "note");
df.save_comments();

auto cmt = df.get_comment(ea);  // -> Result<string>
df.set_comment(ea, "");         // remove
df.save_comments();
```

### Address mapping (pseudocode <-> binary)

```cpp
// Legacy:
// ctree_item_t *item = cf->treeitems[line - cf->hdrlines];
// ea_t addr = item->ea;

// idax:
auto entry = df.entry_address();          // function entry
auto map = df.address_map();              // vector<AddressMapping>
auto addr = df.line_to_address(5);        // line 5 -> binary address
```

### Post-order traversal and early termination

```cpp
// Legacy:
// struct my_visitor : ctree_visitor_t {
//     my_visitor() : ctree_visitor_t(CV_POST) {}
//     int leave_expr(cexpr_t *e) override { ... }
// };

// idax:
class PostVisitor : public ida::decompiler::CtreeVisitor {
    VisitAction leave_expression(ExpressionView expr) override {
        // called after children are visited
        return VisitAction::Continue;
    }
};
PostVisitor v;
df.visit(v, {.post_order = true});

// Early termination:
df.visit(v);  // visitor returns VisitAction::Stop to abort
```

## 19) Legacy-to-Wrapper Naming Normalization Examples

This mapping is non-exhaustive but representative of expected direction.

| Legacy SDK | Wrapper Concept |
|---|---|
| `getseg(ea)` | `ida::segment::at(address)` |
| `get_segm_qty()` | `ida::segment::count()` |
| `get_next_seg(ea)` | `ida::segment::next(address)` |
| `set_segm_name(seg, name)` | `segment.set_name(name)` |
| `add_func(ea1, ea2)` | `ida::function::create(start, end)` |
| `del_func(ea)` | `ida::function::remove(address)` |
| `get_func_name(qstring*, ea)` | `function.name()` / `ida::function::name_at(address)` |
| `decode_insn(insn*, ea)` | `ida::instruction::decode(address)` |
| `insn.get_canon_feature()` + `CF_USEn` / `CF_CHGn` | `Operand::is_read()` / `Operand::is_written()` (Node `isRead` / `isWritten`; Rust `is_read` / `is_written`) |
| `create_insn(ea)` | `ida::instruction::create(address)` |
| `op_enum(ea, n, tid, serial)` / `get_enum_id(...)` | `ida::instruction::set_operand_enum(address, index, enum_name, serial)` / `operand_enum(address, index)` |
| `get_byte(ea)` | `ida::data::read_byte(address)` |
| `get_strlist_options()` / `build_strlist()` / `get_strlist_item()` | `ida::data::string_list_options()` / `configure_string_list()` / `string_literals()` |
| `put_byte(ea, v)` | `ida::data::write_byte(address, value)` |
| `patch_byte(ea, v)` | `ida::data::patch_byte(address, value)` |
| `del_items(ea, ...)` | `ida::data::undefine(address, size)` |
| `set_name(ea, name, flags)` | `ida::name::set(address, name, options)` |
| `force_name(ea, name, flags)` | `ida::name::force_set(address, name, options)` |
| `get_name_ea(from, name)` | `ida::name::resolve(name, context)` |
| `get_nlist_*` iteration | `ida::name::all(options)` |
| `add_cref(from, to, type)` | `ida::xref::add_code_ref(from, to, type)` |
| `add_dref(from, to, type)` | `ida::xref::add_data_ref(from, to, type)` |
| `get_first_cref_from(ea)` loop | `for (auto x : ida::xref::refs_from(ea))` |
| `set_cmt(ea, cmt, rpt)` | `ida::comment::set(address, text, repeatable)` |
| `find_text(...)` | `ida::search::text(options)` |
| `auto_wait()` | `ida::analysis::wait()` |
| `plan_ea(ea)` | `ida::analysis::schedule_reanalysis(address)` |
| `add_sourcefile` / `get_sourcefile` / `del_sourcefile` | `ida::lines::add_source_file` / `source_file_at` / `remove_source_file` |
| copy `func_type_data_t`, edit `funcarg_t::type`, `create_func(...)` | `TypeInfo::with_function_argument_type(index, replacement)` |
| copy `func_type_data_t`, edit `funcarg_t::name`, `create_func(...)` | `TypeInfo::with_function_argument_name(index, name)` |
| copy `func_type_data_t`, edit `rettype`, `create_func(...)` | `TypeInfo::with_function_return_type(replacement)` |
| copy `udt_type_data_t`, edit `TAUDT_CPPOBJ`/`TAUDT_VFTABLE`, `create_udt(...)` | `TypeInfo::set_udt_semantics(is_cpp_object, is_vftable)` |
| `get_ptr_details`, set `TAPTR_SHIFTED`/`parent`/`delta`, `create_ptr(...)` | `TypeInfo::pointer_details()` / `with_shifted_parent(parent, byte_delta)` |
| `is_forward_decl`/`get_forward_type`; copied `set_numbered_type(..., NTF_REPLACE | NTF_COPY)` | `TypeInfo::is_forward_declaration()` / `forward_declaration_kind()` / `replace_forward_declaration(name)` |
| `gen_microcode(...)` + `mba_t::build_graph()` + native block/operand traversal | `ida::decompiler::generate_microcode(address, options)` returning an owned `MicrocodeFunction` |
| pre-decompile direct callees + `mba_t::analyze_calls(ACFL_GUESS)` | `MicrocodeGenerationOptions::analyze_calls` (Node: `analyzeCalls`) |
| `loader_t::accept_file` | `ida::loader::Loader::accept(file)` |
| `loader_t::load_file` | `ida::loader::Loader::load(file, format)` |
| `plugin_t::init/run/term` | `ida::plugin::Plugin` lifecycle methods |
| IDAPython `add_hotkey` / `del_hotkey` | `ida::plugin::register_hotkey` / `ScopedHotkey::release` |
| `process_ui_action(name)` | `ida::plugin::activate_action(action_id)` |
| `PH.id` + `inf_get_procname()` + `inf_is_be()` + ABI/bitness queries | `ida::database::processor_profile()` |
| `processor_t::ana/emu/out` | `ida::processor::Processor` lifecycle methods |

Normalization policy:
- Expand abbreviations (`segm` -> `segment`, `func` -> `function`, `cmt` -> `comment`).
- Keep technical terms where established (`xref`, `ctree`, `fixup`) but define consistent wrappers.
- Replace ambiguous suffixes with explicit nouns (`*_qty` -> `count`, `*_ea` -> `address`).

---

# Legacy SDK -> idax Migration Map

## Core examples

| Legacy SDK | idax |
|---|---|
| `getseg(ea)` | `ida::segment::at(ea)` |
| `add_func(start, end)` | `ida::function::create(start, end)` |
| `decode_insn(&insn, ea)` | `ida::instruction::decode(ea)` |
| `set_name(ea, n, SN_NOWARN)` | `ida::name::set(ea, n)` |
| `set_cmt(ea, txt, rpt)` | `ida::comment::set(ea, txt, rpt)` |
| `find_text(...)` | `ida::search::text(query, start, options)` |
| `auto_wait()` | `ida::analysis::wait()` |

## Entry-point migration notes (P4.5.d)

- Use `ida::entry::count()` instead of direct ordinal/index loops.
- Use `ida::entry::by_index()` for stable iteration.
- Use `ida::entry::by_ordinal()` for explicit ordinal lookups.
- Use `ida::entry::add()/rename()/set_forwarder()` for mutation.

## Module authoring notes

- Loader skeleton: `ida::loader::Loader` + `IDAX_LOADER(...)`
- Processor skeleton: `ida::processor::Processor` + `IDAX_PROCESSOR(...)`
- Plugin actions: `ida::plugin::Action` registration helpers

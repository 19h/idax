//! Integration tests for the idax Rust bindings.
//!
//! These tests require a real IDA installation (IDADIR set) and the test fixture
//! binary at `tests/fixtures/simple_appcall_linux64` relative to the repo root.
//!
//! Run with: cargo test --test integration -- --test-threads=1
//!
//! The idalib runtime is single-threaded, so ALL tests in this file share a
//! single database session initialized via `std::sync::Once`.  Tests must NOT
//! call `database::close()` — that happens in the static destructor.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Once};

use idax::address::BAD_ADDRESS;
use idax::{
    analysis, comment, data, database, decompiler, entry, event, fixup, function, graph,
    instruction, lines, name, search, segment, storage, types, xref,
};

// ---------------------------------------------------------------------------
// Shared one-time database initialization
// ---------------------------------------------------------------------------

static INIT: Once = Once::new();
static mut INIT_OK: bool = false;

/// Path to the test fixture, resolved relative to the workspace root.
fn fixture_path() -> String {
    // The integration test binary runs from somewhere under target/;
    // we locate the fixture relative to the manifest directory.
    let manifest = env!("CARGO_MANIFEST_DIR"); // .../bindings/rust/idax
    let repo_root = std::path::Path::new(manifest)
        .parent() // .../bindings/rust
        .unwrap()
        .parent() // .../bindings
        .unwrap()
        .parent() // repo root
        .unwrap();
    repo_root
        .join("tests/fixtures/simple_appcall_linux64")
        .to_string_lossy()
        .into_owned()
}

fn ensure_init() {
    INIT.call_once(|| {
        // Skip gracefully if IDADIR is not set (CI unit-only runs).
        if std::env::var("IDADIR").is_err() {
            eprintln!("IDADIR not set — skipping integration tests");
            return;
        }
        database::init().expect("database::init failed");
        let path = fixture_path();
        database::open(&path, true).expect("database::open failed");
        analysis::wait().expect("analysis::wait failed");
        unsafe { INIT_OK = true };
    });
}

/// Returns true if the database was successfully opened.
/// Tests should call this at the top and return early if false.
fn db_ready() -> bool {
    ensure_init();
    unsafe { INIT_OK }
}

/// Convenience macro: skip the test if the database is not ready.
macro_rules! require_db {
    () => {
        if !db_ready() {
            eprintln!("  [skipped — no IDA runtime]");
            return;
        }
    };
}

// ===========================================================================
// Database metadata
// ===========================================================================

#[test]
fn database_input_file_path() {
    require_db!();
    let path = database::input_file_path().unwrap();
    assert!(!path.is_empty(), "input_file_path should not be empty");
    assert!(
        path.contains("simple_appcall_linux64"),
        "expected fixture name in path: {path}"
    );
}

#[test]
fn database_file_type_name() {
    require_db!();
    let name = database::file_type_name().unwrap();
    assert!(!name.is_empty(), "file_type_name should not be empty");
}

#[test]
fn database_input_md5() {
    require_db!();
    let md5 = database::input_md5().unwrap();
    assert_eq!(md5.len(), 32, "MD5 should be 32 hex chars, got: {md5}");
    assert!(
        md5.chars().all(|c| c.is_ascii_hexdigit()),
        "MD5 should be hex: {md5}"
    );
}

#[test]
fn database_address_bitness() {
    require_db!();
    let bits = database::address_bitness().unwrap();
    assert!(
        bits == 16 || bits == 32 || bits == 64,
        "unexpected bitness: {bits}"
    );
}

#[test]
fn database_set_address_bitness_idempotent() {
    require_db!();
    let bits = database::address_bitness().unwrap();
    database::set_address_bitness(bits).unwrap();
    assert_eq!(database::address_bitness().unwrap(), bits);
}

#[test]
fn database_processor_name() {
    require_db!();
    let pname = database::processor_name().unwrap();
    assert!(!pname.is_empty(), "processor_name should not be empty");
}

#[test]
fn database_address_bounds() {
    require_db!();
    let bounds = database::address_bounds().unwrap();
    assert!(bounds.start < bounds.end, "bounds should be non-empty");
    let min = database::min_address().unwrap();
    let max = database::max_address().unwrap();
    assert_eq!(bounds.start, min);
    assert_eq!(bounds.end, max);
}

#[test]
fn database_image_base() {
    require_db!();
    let base = database::image_base().unwrap();
    assert_ne!(base, BAD_ADDRESS, "image_base should not be BAD_ADDRESS");
}

#[test]
fn database_endianness() {
    require_db!();
    // ELF x86-64 is little-endian
    let big = database::is_big_endian().unwrap();
    assert!(!big, "x86-64 fixture should be little-endian");
}

#[test]
fn database_abi_name() {
    require_db!();
    // abi_name() may return an error for some binaries — just verify it doesn't crash
    match database::abi_name() {
        Ok(abi) => assert!(!abi.is_empty(), "abi_name should not be empty if available"),
        Err(_) => {} // acceptable — not all binaries have ABI info
    }
}

#[test]
fn database_processor_typed() {
    require_db!();
    let proc = database::processor().unwrap();
    // x86/x64 fixture
    let raw = database::processor_id().unwrap();
    assert!(raw >= 0, "processor_id should be non-negative");
    let _ = proc; // just verify it's a valid ProcessorId variant
}

#[test]
fn database_compiler_info() {
    require_db!();
    let ci = database::compiler_info().unwrap();
    let _ = ci; // struct existence is the check
}

#[test]
fn database_import_modules() {
    require_db!();
    let mods = database::import_modules().unwrap();
    // ELF binaries may or may not have import modules — just don't crash
    let _ = mods;
}

#[test]
fn database_snapshots() {
    require_db!();
    let snaps = database::snapshots().unwrap();
    let _ = snaps; // may be empty for a fresh analysis
}

// ===========================================================================
// Segments
// ===========================================================================

#[test]
fn segment_count_nonzero() {
    require_db!();
    let n = segment::count().unwrap();
    assert!(n > 0, "should have at least one segment");
}

#[test]
fn segment_all_iterator() {
    require_db!();
    let segs: Vec<_> = segment::all().collect();
    assert!(!segs.is_empty(), "all() iterator should yield segments");
    let n = segment::count().unwrap();
    assert_eq!(segs.len(), n, "all() count should match count()");
}

#[test]
fn segment_by_index() {
    require_db!();
    let seg = segment::by_index(0).unwrap();
    assert!(seg.size() > 0, "first segment should have nonzero size");
    assert!(!seg.name().is_empty(), "first segment should have a name");
}

#[test]
fn segment_at_address() {
    require_db!();
    let first = segment::first().unwrap();
    let same = segment::at(first.start()).unwrap();
    assert_eq!(first.start(), same.start());
    assert_eq!(first.end(), same.end());
}

#[test]
fn segment_first_last() {
    require_db!();
    let first = segment::first().unwrap();
    let last = segment::last().unwrap();
    assert!(first.start() <= last.start(), "first <= last");
}

#[test]
fn segment_next_prev() {
    require_db!();
    let n = segment::count().unwrap();
    if n >= 2 {
        let first = segment::first().unwrap();
        let second = segment::next(first.start()).unwrap();
        assert!(second.start() > first.start());
        let back = segment::prev(second.start()).unwrap();
        assert_eq!(back.start(), first.start());
    }
}

#[test]
fn segment_properties() {
    require_db!();
    let seg = segment::first().unwrap();
    let _ = seg.bitness();
    let _ = seg.seg_type();
    let _ = seg.permissions();
    let _ = seg.class_name();
    let _ = seg.is_visible();
}

// ===========================================================================
// Functions
// ===========================================================================

#[test]
fn function_count_nonzero() {
    require_db!();
    let n = function::count().unwrap();
    assert!(n > 0, "should have at least one function");
}

#[test]
fn function_all_iterator() {
    require_db!();
    let funcs: Vec<_> = function::all().collect();
    assert!(!funcs.is_empty());
    let n = function::count().unwrap();
    assert_eq!(funcs.len(), n, "all() count should match count()");
}

#[test]
fn function_by_index_and_at() {
    require_db!();
    let f = function::by_index(0).unwrap();
    assert!(f.size() > 0);
    assert!(!f.name().is_empty());
    let same = function::at(f.start()).unwrap();
    assert_eq!(f.start(), same.start());
}

#[test]
fn function_properties() {
    require_db!();
    let f = function::by_index(0).unwrap();
    let _ = f.bitness();
    let _ = f.returns();
    let _ = f.is_library();
    let _ = f.is_thunk();
    let _ = f.is_visible();
    let _ = f.frame_local_size();
    let _ = f.frame_regs_size();
    let _ = f.frame_args_size();
}

#[test]
fn function_callers_callees() {
    require_db!();
    let f = function::by_index(0).unwrap();
    let _ = function::callers(f.start()).unwrap();
    let _ = function::callees(f.start()).unwrap();
}

#[test]
fn function_chunks() {
    require_db!();
    let f = function::by_index(0).unwrap();
    let chunks = function::chunks(f.start()).unwrap();
    assert!(
        !chunks.is_empty(),
        "function should have at least one chunk"
    );
    for c in &chunks {
        assert!(c.size() > 0);
    }
}

#[test]
fn function_code_addresses() {
    require_db!();
    let f = function::by_index(0).unwrap();
    let addrs = function::code_addresses(f.start()).unwrap();
    assert!(!addrs.is_empty(), "function should have code addresses");
    // All addresses should be within the function bounds
    for &a in &addrs {
        assert!(
            a >= f.start(),
            "code addr {a:#x} < func start {:#x}",
            f.start()
        );
    }
}

#[test]
fn function_frame() {
    require_db!();
    let f = function::by_index(0).unwrap();
    // Not all functions have frames — just don't crash
    let _ = function::frame(f.start());
}

// ===========================================================================
// Instructions
// ===========================================================================

#[test]
fn instruction_decode_first() {
    require_db!();
    let f = function::by_index(0).unwrap();
    let insn = instruction::decode(f.start()).unwrap();
    assert_eq!(insn.address(), f.start());
    assert!(insn.size() > 0);
    assert!(!insn.mnemonic().is_empty());
}

#[test]
fn instruction_text() {
    require_db!();
    let f = function::by_index(0).unwrap();
    let text = instruction::text(f.start()).unwrap();
    assert!(!text.is_empty());
}

#[test]
fn instruction_operands() {
    require_db!();
    let f = function::by_index(0).unwrap();
    let insn = instruction::decode(f.start()).unwrap();
    let ops = insn.operands();
    for op in ops {
        let _ = op.op_type();
        let _ = op.index();
        let _ = op.byte_width();
    }
}

#[test]
fn instruction_classification() {
    require_db!();
    let f = function::by_index(0).unwrap();
    // Walk a few instructions and check classification doesn't crash
    let mut addr = f.start();
    for _ in 0..10 {
        let _ = instruction::is_call(addr);
        let _ = instruction::is_return(addr);
        let _ = instruction::is_jump(addr);
        let _ = instruction::is_conditional_jump(addr);
        let _ = instruction::has_fall_through(addr);
        match instruction::next(addr) {
            Ok(next) => addr = next.address(),
            Err(_) => break,
        }
    }
}

#[test]
fn instruction_code_refs() {
    require_db!();
    let f = function::by_index(0).unwrap();
    let _ = instruction::code_refs_from(f.start()).unwrap();
    let _ = instruction::data_refs_from(f.start()).unwrap();
}

#[test]
fn instruction_next_prev() {
    require_db!();
    let f = function::by_index(0).unwrap();
    if let Ok(next) = instruction::next(f.start()) {
        assert!(next.address() > f.start());
        if let Ok(prev) = instruction::prev(next.address()) {
            assert_eq!(prev.address(), f.start());
        }
    }
}

// ===========================================================================
// Names
// ===========================================================================

#[test]
fn name_get_first_function() {
    require_db!();
    let f = function::by_index(0).unwrap();
    let n = name::get(f.start()).unwrap();
    assert!(!n.is_empty(), "first function should have a name");
}

#[test]
fn name_set_and_remove() {
    require_db!();
    let f = function::by_index(0).unwrap();
    let original = name::get(f.start()).unwrap();

    // Set a custom name
    name::force_set(f.start(), "idax_rust_test_name").unwrap();
    let custom = name::get(f.start()).unwrap();
    assert_eq!(custom, "idax_rust_test_name");

    // Restore original
    name::force_set(f.start(), &original).unwrap();
    let restored = name::get(f.start()).unwrap();
    assert_eq!(restored, original);
}

#[test]
fn name_resolve() {
    require_db!();
    let f = function::by_index(0).unwrap();
    let n = name::get(f.start()).unwrap();
    let resolved = name::resolve(&n, 0).unwrap();
    assert_eq!(resolved, f.start(), "resolve should find the function");
}

#[test]
fn name_predicates() {
    require_db!();
    let f = function::by_index(0).unwrap();
    let _ = name::is_public(f.start());
    let _ = name::is_weak(f.start());
    let _ = name::is_user_defined(f.start());
    let _ = name::is_auto_generated(f.start());
}

#[test]
fn name_validation() {
    require_db!();
    assert!(name::is_valid_identifier("hello_world").unwrap());
    let sanitized = name::sanitize_identifier("hello world!").unwrap();
    assert!(!sanitized.is_empty());
}

// ===========================================================================
// Comments
// ===========================================================================

#[test]
fn comment_set_get_remove() {
    require_db!();
    let f = function::by_index(0).unwrap();
    let addr = f.start();

    // Regular comment
    comment::set(addr, "rust_test_comment", false).unwrap();
    let got = comment::get(addr, false).unwrap();
    assert_eq!(got, "rust_test_comment");
    comment::remove(addr, false).unwrap();

    // Repeatable comment
    comment::set(addr, "rust_test_repeatable", true).unwrap();
    let got = comment::get(addr, true).unwrap();
    assert_eq!(got, "rust_test_repeatable");
    comment::remove(addr, true).unwrap();
}

#[test]
fn comment_append() {
    require_db!();
    let f = function::by_index(0).unwrap();
    let addr = f.start();

    comment::set(addr, "first", false).unwrap();
    comment::append(addr, " second", false).unwrap();
    let got = comment::get(addr, false).unwrap();
    assert!(got.contains("first"), "should contain first part: {got}");
    assert!(
        got.contains("second"),
        "should contain appended part: {got}"
    );
    comment::remove(addr, false).unwrap();
}

#[test]
fn comment_anterior_posterior() {
    require_db!();
    let f = function::by_index(0).unwrap();
    let addr = f.start();

    comment::add_anterior(addr, "anterior_test").unwrap();
    // Reading anterior lines may vary; just don't crash
    let _ = comment::anterior_lines(addr);
    comment::clear_anterior(addr).unwrap();

    comment::add_posterior(addr, "posterior_test").unwrap();
    let _ = comment::posterior_lines(addr);
    comment::clear_posterior(addr).unwrap();
}

// ===========================================================================
// Cross-References
// ===========================================================================

#[test]
fn xref_refs_to_from() {
    require_db!();
    let f = function::by_index(0).unwrap();
    let refs_from = xref::refs_from(f.start()).unwrap();
    let _ = refs_from; // may be empty for first instruction

    // entry point likely has refs_to
    let refs_to = xref::refs_to(f.start()).unwrap();
    let _ = refs_to;
}

#[test]
fn xref_code_data_refs() {
    require_db!();
    let f = function::by_index(0).unwrap();
    let _ = xref::code_refs_from(f.start()).unwrap();
    let _ = xref::code_refs_to(f.start()).unwrap();
    let _ = xref::data_refs_from(f.start()).unwrap();
    let _ = xref::data_refs_to(f.start()).unwrap();
}

// ===========================================================================
// Data
// ===========================================================================

#[test]
fn data_read_byte() {
    require_db!();
    let bounds = database::address_bounds().unwrap();
    let byte = data::read_byte(bounds.start).unwrap();
    // ELF magic: 0x7f
    assert_eq!(byte, 0x7f, "first byte of ELF should be 0x7f");
}

#[test]
fn data_read_bytes() {
    require_db!();
    let bounds = database::address_bounds().unwrap();
    let bytes = data::read_bytes(bounds.start, 4).unwrap();
    assert_eq!(bytes.len(), 4);
    assert_eq!(&bytes, &[0x7f, b'E', b'L', b'F'], "should read ELF magic");
}

#[test]
fn data_read_word_dword_qword() {
    require_db!();
    let bounds = database::address_bounds().unwrap();
    let w = data::read_word(bounds.start).unwrap();
    assert_eq!(w & 0xff, 0x7f, "low byte should be 0x7f");
    let d = data::read_dword(bounds.start).unwrap();
    assert_eq!(d & 0xff, 0x7f);
    let q = data::read_qword(bounds.start).unwrap();
    assert_eq!(q & 0xff, 0x7f);
}

#[test]
fn data_patch_and_revert() {
    require_db!();
    let f = function::by_index(0).unwrap();
    let addr = f.start();
    let original = data::read_byte(addr).unwrap();

    data::patch_byte(addr, 0xCC).unwrap();
    let patched = data::read_byte(addr).unwrap();
    assert_eq!(patched, 0xCC);

    let orig_read = data::original_byte(addr).unwrap();
    assert_eq!(
        orig_read, original,
        "original_byte should return pre-patch value"
    );

    data::revert_patch(addr).unwrap();
    let restored = data::read_byte(addr).unwrap();
    assert_eq!(restored, original, "should be restored after revert");
}

// ===========================================================================
// Search
// ===========================================================================

#[test]
fn search_next_code() {
    require_db!();
    let bounds = database::address_bounds().unwrap();
    let code_addr = search::next_code(bounds.start).unwrap();
    assert_ne!(code_addr, BAD_ADDRESS);
}

#[test]
fn search_next_data() {
    require_db!();
    let bounds = database::address_bounds().unwrap();
    // May or may not find data — just don't crash
    let _ = search::next_data(bounds.start);
}

// ===========================================================================
// Analysis
// ===========================================================================

#[test]
fn analysis_is_idle() {
    require_db!();
    // After wait(), analysis should be idle
    assert!(analysis::is_idle(), "should be idle after wait()");
}

#[test]
fn analysis_enable_disable() {
    require_db!();
    let was_enabled = analysis::is_enabled();
    analysis::set_enabled(false).unwrap();
    assert!(!analysis::is_enabled());
    analysis::set_enabled(was_enabled).unwrap();
}

// ===========================================================================
// Entry points
// ===========================================================================

#[test]
fn entry_count_and_enumerate() {
    require_db!();
    let n = entry::count().unwrap();
    assert!(n > 0, "ELF binary should have at least one entry point");
    for i in 0..n {
        let ep = entry::by_index(i).unwrap();
        assert_ne!(ep.address, BAD_ADDRESS);
    }
}

// ===========================================================================
// Type system
// ===========================================================================

#[test]
fn types_primitive_constructors() {
    require_db!();
    let i32t = types::TypeInfo::int32();
    assert!(i32t.is_integer());
    assert!(!i32t.is_pointer());
    assert_eq!(i32t.size().unwrap(), 4);

    let f64t = types::TypeInfo::float64();
    assert!(f64t.is_floating_point());

    let vt = types::TypeInfo::void_type();
    assert!(vt.is_void());
}

#[test]
fn types_pointer_and_array() {
    require_db!();
    let i32t = types::TypeInfo::int32();
    let ptr = types::TypeInfo::pointer_to(&i32t);
    assert!(ptr.is_pointer());
    let pointee = ptr.pointee_type().unwrap();
    assert!(pointee.is_integer());

    let arr = types::TypeInfo::array_of(&i32t, 10);
    assert!(arr.is_array());
    assert_eq!(arr.array_length().unwrap(), 10);
    let elem = arr.array_element_type().unwrap();
    assert!(elem.is_integer());
}

#[test]
fn types_struct_creation() {
    require_db!();
    let s = types::TypeInfo::create_struct();
    assert!(s.is_struct());
    let i32t = types::TypeInfo::int32();
    s.add_member("field_a", &i32t, 0).unwrap();
    s.add_member("field_b", &i32t, 4).unwrap();
    assert_eq!(s.member_count().unwrap(), 2);
    let members = s.members().unwrap();
    assert_eq!(members.len(), 2);
}

#[test]
fn types_from_declaration() {
    require_db!();
    let ti = types::TypeInfo::from_declaration("int (*)(const char *, ...)").unwrap();
    assert!(
        ti.is_pointer() || ti.is_function(),
        "should parse function pointer decl"
    );
}

#[test]
fn types_retrieve_at_function() {
    require_db!();
    let f = function::by_index(0).unwrap();
    // May or may not have type info — just don't crash
    let _ = types::retrieve(f.start());
}

#[test]
fn types_local_type_count() {
    require_db!();
    let n = types::local_type_count().unwrap();
    let _ = n; // may be 0 for simple binaries
}

// ===========================================================================
// Lines (color tags — runtime SDK calls)
// ===========================================================================

#[test]
fn lines_tag_operations() {
    require_db!();
    let tagged = lines::colstr("hello", lines::Color::Default);
    let plain = lines::tag_remove(&tagged);
    assert_eq!(plain, "hello");
    let len = lines::tag_strlen(&tagged);
    assert_eq!(len, 5, "visible length should be 5");
}

#[test]
fn lines_addr_tag_roundtrip() {
    require_db!();
    let tag = lines::make_addr_tag(42);
    assert!(!tag.is_empty());
    let decoded = lines::decode_addr_tag(&tag, 0);
    assert_eq!(decoded, Some(42));
}

// ===========================================================================
// Decompiler
// ===========================================================================

#[test]
fn decompiler_available() {
    require_db!();
    // Just check we can query without crashing
    let _ = decompiler::available();
}

#[test]
fn decompiler_decompile() {
    require_db!();
    if !decompiler::available().unwrap_or(false) {
        eprintln!("  [skipped — decompiler not available]");
        return;
    }
    let f = function::by_index(0).unwrap();
    let df = decompiler::decompile(f.start()).unwrap();
    let pseudo = df.pseudocode().unwrap();
    assert!(!pseudo.is_empty(), "pseudocode should not be empty");
    let lines_vec = df.lines().unwrap();
    assert!(
        !lines_vec.is_empty(),
        "decompiled lines should not be empty"
    );
    let decl = df.declaration().unwrap();
    assert!(!decl.is_empty(), "declaration should not be empty");
}

#[test]
fn decompiler_variables() {
    require_db!();
    if !decompiler::available().unwrap_or(false) {
        eprintln!("  [skipped — decompiler not available]");
        return;
    }
    let f = function::by_index(0).unwrap();
    let df = decompiler::decompile(f.start()).unwrap();
    let vars = df.variables().unwrap();
    // May or may not have variables — just don't crash
    let _ = vars;
    let _ = df.variable_count();
}

#[test]
fn decompiler_microcode() {
    require_db!();
    if !decompiler::available().unwrap_or(false) {
        eprintln!("  [skipped — decompiler not available]");
        return;
    }
    let f = function::by_index(0).unwrap();
    let df = decompiler::decompile(f.start()).unwrap();
    // Microcode may or may not be available for all functions
    let _ = df.microcode();
}

#[test]
fn decompiler_microcode_filter_context_introspection() {
    require_db!();
    if !decompiler::available().unwrap_or(false) {
        eprintln!("  [skipped — decompiler not available]");
        return;
    }

    let f = function::by_index(0).unwrap();
    let saw_match = Arc::new(AtomicBool::new(false));
    let saw_apply = Arc::new(AtomicBool::new(false));

    let saw_match_cb = Arc::clone(&saw_match);
    let saw_apply_cb = Arc::clone(&saw_apply);
    let token = decompiler::register_microcode_filter_with_context(
        move |_address, _itype| {
            saw_match_cb.store(true, Ordering::SeqCst);
            true
        },
        move |context| {
            saw_apply_cb.store(true, Ordering::SeqCst);
            let _ = context.address();
            let _ = context.instruction_type();
            let _ = context.instruction();
            if let Ok(count) = context.block_instruction_count() {
                if count > 0 {
                    let _ = context.has_instruction_at_index(0);
                    let _ = context.instruction_at_index(0);
                }
            }
            if context.has_last_emitted_instruction().unwrap_or(false) {
                let _ = context.last_emitted_instruction();
            }
            decompiler::MicrocodeApplyResult::NotHandled
        },
    )
    .unwrap();

    let decompile_result = decompiler::decompile(f.start());
    let _ = decompiler::unregister_microcode_filter(token);

    let df = decompile_result.unwrap();
    let _ = df.pseudocode().unwrap_or_default();
    assert!(
        saw_match.load(Ordering::SeqCst),
        "expected microcode filter match callback to be invoked"
    );
    assert!(
        saw_apply.load(Ordering::SeqCst),
        "expected microcode filter apply callback to be invoked"
    );
}

#[test]
fn decompiler_item_type_names() {
    require_db!();
    // Pure function that maps ItemType -> string
    for it in [
        decompiler::ItemType::ExprEmpty,
        decompiler::ItemType::StmtEmpty,
    ] {
        let name = decompiler::item_type_name(it).unwrap();
        assert!(!name.is_empty());
    }
}

// ===========================================================================
// Storage (netnode)
// ===========================================================================

#[test]
fn storage_node_lifecycle() {
    require_db!();
    let node = storage::Node::open("idax_rust_integration_test", true).unwrap();
    let id = node.id().unwrap();
    assert!(id > 0, "node ID should be positive");
    let name = node.name().unwrap();
    assert_eq!(name, "idax_rust_integration_test");

    // alt values
    node.set_alt(0, 12345, b'A').unwrap();
    let val = node.alt(0, b'A').unwrap();
    assert_eq!(val, 12345);
    node.remove_alt(0, b'A').unwrap();

    // hash values
    node.set_hash("key1", "value1", b'H').unwrap();
    let hval = node.hash("key1", b'H').unwrap();
    assert_eq!(hval, "value1");

    // sup (binary) values
    node.set_sup(0, b"binary_data", b'S').unwrap();
    let sval = node.sup(0, b'S').unwrap();
    assert_eq!(sval, b"binary_data");

    // blob values
    let blob_data = vec![1u8, 2, 3, 4, 5, 6, 7, 8];
    node.set_blob(0, &blob_data, b'B').unwrap();
    let bval = node.blob(0, b'B').unwrap();
    assert_eq!(bval, blob_data);
    let bsize = node.blob_size(0, b'B').unwrap();
    assert_eq!(bsize, 8);
    node.remove_blob(0, b'B').unwrap();
}

// ===========================================================================
// Fixups
// ===========================================================================

#[test]
fn fixup_enumerate() {
    require_db!();
    // ELF binaries typically have fixups/relocations
    let all_fixups: Vec<_> = fixup::all().collect();
    // May be empty for some fixture builds — just don't crash
    if !all_fixups.is_empty() {
        let first_addr = fixup::first().unwrap();
        assert!(fixup::exists(first_addr));
        let desc = fixup::at(first_addr).unwrap();
        let _ = desc;
    }
}

// ===========================================================================
// Events
// ===========================================================================

#[test]
fn event_subscribe_unsubscribe() {
    require_db!();
    let token = event::on_renamed(|_addr, _old, _new| {
        // callback — won't fire during this test
    })
    .unwrap();
    event::unsubscribe(token).unwrap();
}

#[test]
fn event_scoped_subscription() {
    require_db!();
    {
        let token = event::on_byte_patched(|_addr, _old_val| {}).unwrap();
        let _scoped = event::ScopedSubscription::new(token);
        // auto-unsubscribes on drop
    }
}

// ===========================================================================
// Graph
// ===========================================================================

#[test]
fn graph_flowchart() {
    require_db!();
    let f = function::by_index(0).unwrap();
    let blocks = graph::flowchart(f.start()).unwrap();
    assert!(
        !blocks.is_empty(),
        "function should have at least one basic block"
    );
    for b in &blocks {
        // Some synthetic/external blocks may have start == end
        assert!(b.start <= b.end, "basic block should satisfy start <= end");
    }
}

#[test]
fn graph_manual_construction() {
    require_db!();
    let mut g = graph::Graph::new();
    let n0 = g.add_node();
    let n1 = g.add_node();
    let n2 = g.add_node();
    assert_eq!(g.total_node_count(), 3);
    assert!(g.node_exists(n0));

    g.add_edge(n0, n1).unwrap();
    g.add_edge(n1, n2).unwrap();
    let succs = g.successors(n0).unwrap();
    assert_eq!(succs, vec![n1]);
    let preds = g.predecessors(n1).unwrap();
    assert_eq!(preds, vec![n0]);

    assert!(g.path_exists(n0, n2));
    assert!(!g.path_exists(n2, n0));

    g.remove_edge(n0, n1).unwrap();
    let succs2 = g.successors(n0).unwrap();
    assert!(succs2.is_empty());

    g.clear().unwrap();
    assert_eq!(g.total_node_count(), 0);
}

#[test]
fn graph_groups() {
    require_db!();
    let mut g = graph::Graph::new();
    let n0 = g.add_node();
    let n1 = g.add_node();
    let n2 = g.add_node();

    let group = g.create_group(&[n0, n1]).unwrap();
    assert!(g.is_group(group));
    let members = g.group_members(group).unwrap();
    assert_eq!(members.len(), 2);

    g.set_group_expanded(group, false).unwrap();
    assert!(g.is_collapsed(group));
    g.set_group_expanded(group, true).unwrap();
    assert!(!g.is_collapsed(group));

    g.delete_group(group).unwrap();
    assert!(!g.is_group(group));

    let _ = n2; // keep n2 alive
}

// ===========================================================================
// Cross-domain stress tests
// ===========================================================================

#[test]
fn cross_domain_bad_address_handling() {
    require_db!();
    // BAD_ADDRESS should fail gracefully across domains
    assert!(segment::at(BAD_ADDRESS).is_err());
    assert!(function::at(BAD_ADDRESS).is_err());
    assert!(instruction::decode(BAD_ADDRESS).is_err());
    assert!(data::read_byte(BAD_ADDRESS).is_err());
    assert!(name::get(BAD_ADDRESS).is_err());
}

#[test]
fn cross_domain_name_comment_roundtrip() {
    require_db!();
    let f = function::by_index(0).unwrap();
    let addr = f.start();

    // Save originals
    let orig_name = name::get(addr).unwrap();

    // Name roundtrip
    name::force_set(addr, "cross_domain_test_xyz").unwrap();
    let resolved = name::resolve("cross_domain_test_xyz", 0).unwrap();
    assert_eq!(resolved, addr);
    name::force_set(addr, &orig_name).unwrap();

    // Comment roundtrip
    comment::set(addr, "cross_domain_cmt", false).unwrap();
    let cmt = comment::get(addr, false).unwrap();
    assert_eq!(cmt, "cross_domain_cmt");
    comment::remove(addr, false).unwrap();
}

#[test]
fn cross_domain_segment_function_consistency() {
    require_db!();
    // Every function's start address should belong to some segment
    let funcs: Vec<_> = function::all().collect();
    for f in funcs.iter().take(20) {
        let seg = segment::at(f.start());
        assert!(
            seg.is_ok(),
            "function at {:#x} should be in a segment",
            f.start()
        );
    }
}

#[test]
fn cross_domain_data_instruction_consistency() {
    require_db!();
    // Decoding an instruction should produce bytes that match data::read_bytes
    let f = function::by_index(0).unwrap();
    let insn = instruction::decode(f.start()).unwrap();
    let bytes = data::read_bytes(f.start(), insn.size()).unwrap();
    assert_eq!(
        bytes.len() as u64,
        insn.size(),
        "byte count should match instruction size"
    );
}

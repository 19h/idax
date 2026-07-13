//! Integration tests for the idax Rust bindings.
//!
//! These tests require a real IDA installation (IDADIR set) and the test fixture
//! binary at `tests/fixtures/simple_appcall_linux64` relative to the repo root.
//!
//! Run with: cargo test --test integration
//!
//! The idalib runtime requires all calls on the thread that initialized it.
//! This target therefore uses a custom sequential harness (`harness = false`)
//! whose explicit `main` performs initialization, every test call, and cleanup
//! on process main. Tests must NOT call `database::close()` individually.

use std::io::Write;
use std::panic::{self, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Once};

use idax::address::{Address, BAD_ADDRESS};
use idax::error::{ErrorCategory, Status};
use idax::{
    analysis, comment, data, database, decompiler, entry, event, fixup, function, graph,
    instruction, lines, name, search, segment, storage, types, ui, xref,
};

// ---------------------------------------------------------------------------
// Shared one-time database initialization
// ---------------------------------------------------------------------------

static INIT: Once = Once::new();
static INIT_OK: AtomicBool = AtomicBool::new(false);

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
        INIT_OK.store(true, Ordering::Release);
    });
}

/// Returns true if the database was successfully opened.
/// Tests should call this at the top and return early if false.
fn db_ready() -> bool {
    ensure_init();
    INIT_OK.load(Ordering::Acquire)
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

fn database_input_file_path() {
    require_db!();
    let path = database::input_file_path().unwrap();
    assert!(!path.is_empty(), "input_file_path should not be empty");
    assert!(
        path.contains("simple_appcall_linux64"),
        "expected fixture name in path: {path}"
    );
}

fn database_idb_path() {
    require_db!();
    let path = database::idb_path().unwrap();
    assert!(!path.is_empty(), "idb_path should not be empty");
}

fn database_file_type_name() {
    require_db!();
    let name = database::file_type_name().unwrap();
    assert!(!name.is_empty(), "file_type_name should not be empty");
}

fn database_input_md5() {
    require_db!();
    let md5 = database::input_md5().unwrap();
    assert_eq!(md5.len(), 32, "MD5 should be 32 hex chars, got: {md5}");
    assert!(
        md5.chars().all(|c| c.is_ascii_hexdigit()),
        "MD5 should be hex: {md5}"
    );
}

fn database_address_bitness() {
    require_db!();
    let bits = database::address_bitness().unwrap();
    assert!(
        bits == 16 || bits == 32 || bits == 64,
        "unexpected bitness: {bits}"
    );
}

fn database_set_address_bitness_idempotent() {
    require_db!();
    let bits = database::address_bitness().unwrap();
    database::set_address_bitness(bits).unwrap();
    assert_eq!(database::address_bitness().unwrap(), bits);
}

fn database_processor_name() {
    require_db!();
    let pname = database::processor_name().unwrap();
    assert!(!pname.is_empty(), "processor_name should not be empty");
}

fn database_address_bounds() {
    require_db!();
    let bounds = database::address_bounds().unwrap();
    assert!(bounds.start < bounds.end, "bounds should be non-empty");
    let min = database::min_address().unwrap();
    let max = database::max_address().unwrap();
    assert_eq!(bounds.start, min);
    assert_eq!(bounds.end, max);
}

fn database_image_base() {
    require_db!();
    let base = database::image_base().unwrap();
    assert_ne!(base, BAD_ADDRESS, "image_base should not be BAD_ADDRESS");
}

fn database_endianness() {
    require_db!();
    // ELF x86-64 is little-endian
    let big = database::is_big_endian().unwrap();
    assert!(!big, "x86-64 fixture should be little-endian");
}

fn database_abi_name() {
    require_db!();
    // abi_name() may return an error for some binaries — just verify it doesn't crash
    match database::abi_name() {
        Ok(abi) => assert!(!abi.is_empty(), "abi_name should not be empty if available"),
        Err(_) => {} // acceptable — not all binaries have ABI info
    }
}

fn database_processor_typed() {
    require_db!();
    let proc = database::processor().unwrap();
    // x86/x64 fixture
    let raw = database::processor_id().unwrap();
    assert!(raw >= 0, "processor_id should be non-negative");
    let _ = proc; // just verify it's a valid ProcessorId variant
}

fn database_compiler_info() {
    require_db!();
    let ci = database::compiler_info().unwrap();
    let _ = ci; // struct existence is the check
}

fn database_import_modules() {
    require_db!();
    let mods = database::import_modules().unwrap();
    // ELF binaries may or may not have import modules — just don't crash
    let _ = mods;
}

fn database_snapshots() {
    require_db!();
    let snaps = database::snapshots().unwrap();
    let _ = snaps; // may be empty for a fresh analysis
}

// ===========================================================================
// Segments
// ===========================================================================

fn segment_count_nonzero() {
    require_db!();
    let n = segment::count().unwrap();
    assert!(n > 0, "should have at least one segment");
}

fn segment_all_iterator() {
    require_db!();
    let segs: Vec<_> = segment::all().collect();
    assert!(!segs.is_empty(), "all() iterator should yield segments");
    let n = segment::count().unwrap();
    assert_eq!(segs.len(), n, "all() count should match count()");
}

fn segment_by_index() {
    require_db!();
    let seg = segment::by_index(0).unwrap();
    assert!(seg.size() > 0, "first segment should have nonzero size");
    assert!(!seg.name().is_empty(), "first segment should have a name");
}

fn segment_at_address() {
    require_db!();
    let first = segment::first().unwrap();
    let same = segment::at(first.start()).unwrap();
    assert_eq!(first.start(), same.start());
    assert_eq!(first.end(), same.end());
}

fn segment_first_last() {
    require_db!();
    let first = segment::first().unwrap();
    let last = segment::last().unwrap();
    assert!(first.start() <= last.start(), "first <= last");
}

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

fn function_count_nonzero() {
    require_db!();
    let n = function::count().unwrap();
    assert!(n > 0, "should have at least one function");
}

fn function_all_iterator() {
    require_db!();
    let funcs: Vec<_> = function::all().collect();
    assert!(!funcs.is_empty());
    let n = function::count().unwrap();
    assert_eq!(funcs.len(), n, "all() count should match count()");
}

fn function_by_index_and_at() {
    require_db!();
    let f = function::by_index(0).unwrap();
    assert!(f.size() > 0);
    assert!(!f.name().is_empty());
    let same = function::at(f.start()).unwrap();
    assert_eq!(f.start(), same.start());
}

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

fn function_callers_callees() {
    require_db!();
    let f = function::by_index(0).unwrap();
    let _ = function::callers(f.start()).unwrap();
    let _ = function::callees(f.start()).unwrap();
}

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

fn function_frame() {
    require_db!();
    let f = function::by_index(0).unwrap();
    // Not all functions have frames — just don't crash
    let _ = function::frame(f.start());
}

// ===========================================================================
// Instructions
// ===========================================================================

fn instruction_decode_first() {
    require_db!();
    let f = function::by_index(0).unwrap();
    let insn = instruction::decode(f.start()).unwrap();
    assert_eq!(insn.address(), f.start());
    assert!(insn.size() > 0);
    assert!(!insn.mnemonic().is_empty());
}

fn instruction_text() {
    require_db!();
    let f = function::by_index(0).unwrap();
    let text = instruction::text(f.start()).unwrap();
    assert!(!text.is_empty());
}

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

fn instruction_code_refs() {
    require_db!();
    let f = function::by_index(0).unwrap();
    let _ = instruction::code_refs_from(f.start()).unwrap();
    let _ = instruction::data_refs_from(f.start()).unwrap();
}

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

fn name_get_first_function() {
    require_db!();
    let f = function::by_index(0).unwrap();
    let n = name::get(f.start()).unwrap();
    assert!(!n.is_empty(), "first function should have a name");
}

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

fn name_resolve() {
    require_db!();
    let f = function::by_index(0).unwrap();
    let n = name::get(f.start()).unwrap();
    let resolved = name::resolve(&n, 0).unwrap();
    assert_eq!(resolved, f.start(), "resolve should find the function");
}

fn name_predicates() {
    require_db!();
    let f = function::by_index(0).unwrap();
    let _ = name::is_public(f.start());
    let _ = name::is_weak(f.start());
    let _ = name::is_user_defined(f.start());
    let _ = name::is_auto_generated(f.start());
}

fn name_validation() {
    require_db!();
    assert!(name::is_valid_identifier("hello_world").unwrap());
    let sanitized = name::sanitize_identifier("hello world!").unwrap();
    assert!(!sanitized.is_empty());
}

fn name_demangle_arbitrary_symbol() {
    require_db!();
    for form in [
        name::DemangleForm::Short,
        name::DemangleForm::Long,
        name::DemangleForm::Full,
    ] {
        let demangled = name::demangle("_Z3foov", form).unwrap();
        assert!(demangled.contains("foo"));
    }
    assert!(name::demangle("not_a_mangled_symbol", name::DemangleForm::Short).is_err());
}

fn ui_current_widget_headless_safe() {
    require_db!();
    let _ = ui::current_widget().unwrap();
}

// ===========================================================================
// Comments
// ===========================================================================

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

fn comment_append() {
    require_db!();
    let f = function::by_index(0).unwrap();
    let addr = f.start();

    comment::set(addr, "first", false).unwrap();
    comment::append(addr, " second", false).unwrap();
    let got = comment::get(addr, false).unwrap();
    assert_eq!(got, "first\n second");
    comment::remove(addr, false).unwrap();
}

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

fn xref_refs_to_from() {
    require_db!();
    let f = function::by_index(0).unwrap();
    let refs_from = xref::refs_from(f.start()).unwrap();
    let _ = refs_from; // may be empty for first instruction

    // entry point likely has refs_to
    let refs_to = xref::refs_to(f.start()).unwrap();
    let _ = refs_to;
}

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

fn data_read_byte() {
    require_db!();
    let bounds = database::address_bounds().unwrap();
    let byte = data::read_byte(bounds.start).unwrap();
    // ELF magic: 0x7f
    assert_eq!(byte, 0x7f, "first byte of ELF should be 0x7f");
}

fn data_read_bytes() {
    require_db!();
    let bounds = database::address_bounds().unwrap();
    let bytes = data::read_bytes(bounds.start, 4).unwrap();
    assert_eq!(bytes.len(), 4);
    assert_eq!(&bytes, &[0x7f, b'E', b'L', b'F'], "should read ELF magic");
}

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

fn data_element_definition_units() {
    require_db!();

    let last = segment::last().unwrap();
    let start = last
        .end()
        .checked_add(0xffff)
        .expect("temporary segment address overflow")
        & !0xffff;
    let end = start.checked_add(0x1000).unwrap();
    segment::create(
        start,
        end,
        "__idax_rust_data_units",
        "DATA",
        segment::Type::Data,
    )
    .unwrap();

    struct SegmentCleanup(Address);
    impl Drop for SegmentCleanup {
        fn drop(&mut self) {
            let _ = segment::remove(self.0);
        }
    }
    let _cleanup = SegmentCleanup(start);

    type DefineFunction = fn(Address, u64) -> Status;
    let mut definitions: Vec<(&str, u64, DefineFunction)> = vec![
        ("byte", 1, data::define_byte),
        ("word", 2, data::define_word),
        ("dword", 4, data::define_dword),
        ("qword", 8, data::define_qword),
        ("oword", 16, data::define_oword),
        ("yword", 32, data::define_yword),
        ("zword", 64, data::define_zword),
        ("float", 4, data::define_float),
        ("double", 8, data::define_double),
    ];

    match data::tbyte_element_size() {
        Ok(width) => {
            assert!(width > 0);
            definitions.push(("tbyte", width, data::define_tbyte));
        }
        Err(error) => {
            assert_eq!(error.category, ErrorCategory::Unsupported);
            let define_error = data::define_tbyte(start, 1).unwrap_err();
            assert_eq!(define_error.category, ErrorCategory::Unsupported);
        }
    }
    match data::packed_real_element_size() {
        Ok(width) => {
            assert!(width > 0);
            definitions.push(("packed_real", width, data::define_packed_real));
        }
        Err(error) => {
            assert_eq!(error.category, ErrorCategory::Unsupported);
            let define_error = data::define_packed_real(start, 1).unwrap_err();
            assert_eq!(define_error.category, ErrorCategory::Unsupported);
        }
    }

    for (name, width, define) in definitions {
        define(start, 1).unwrap_or_else(|error| panic!("define_{name}(1): {error}"));
        assert_eq!(
            idax::address::item_size(start).unwrap(),
            width,
            "define_{name}(1) byte size"
        );
        data::undefine(start, width).unwrap();

        define(start, 3).unwrap_or_else(|error| panic!("define_{name}(3): {error}"));
        assert_eq!(
            idax::address::item_size(start).unwrap(),
            width * 3,
            "define_{name}(3) byte size"
        );
        data::undefine(start, width * 3).unwrap();
    }

    let zero = data::define_dword(start, 0).unwrap_err();
    assert_eq!(
        zero.category,
        ErrorCategory::Validation,
        "zero-count error: {zero:?}"
    );
    for define in [
        data::define_tbyte as DefineFunction,
        data::define_packed_real as DefineFunction,
    ] {
        let extended_zero = define(start, 0).unwrap_err();
        assert_eq!(extended_zero.category, ErrorCategory::Validation);
    }

    let overflowing_count = u64::MAX / 64 + 1;
    let overflow = data::define_zword(start, overflowing_count).unwrap_err();
    assert_eq!(
        overflow.category,
        ErrorCategory::Validation,
        "multiplication-overflow error: {overflow:?}"
    );

    let range_overflow = data::define_word(BAD_ADDRESS - 1, 1).unwrap_err();
    assert_eq!(
        range_overflow.category,
        ErrorCategory::Validation,
        "address-range-overflow error: {range_overflow:?}"
    );
}

fn data_custom_data_lifecycle() {
    require_db!();

    let last = segment::last().unwrap();
    let start = last
        .end()
        .checked_add(0xffff)
        .expect("temporary segment address overflow")
        & !0xffff;
    let end = start.checked_add(0x1000).unwrap();
    segment::create(
        start,
        end,
        "__idax_rust_custom_data",
        "DATA",
        segment::Type::Data,
    )
    .unwrap();

    struct Cleanup {
        segment_start: Address,
        fixed_type: Option<data::CustomDataTypeId>,
        variable_type: Option<data::CustomDataTypeId>,
        format: Option<data::CustomDataFormatId>,
    }
    impl Drop for Cleanup {
        fn drop(&mut self) {
            if let Some(id) = self.fixed_type.take() {
                let _ = data::unregister_custom_data_type(id);
            }
            if let Some(id) = self.variable_type.take() {
                let _ = data::unregister_custom_data_type(id);
            }
            if let Some(id) = self.format.take() {
                let _ = data::unregister_custom_data_format(id);
            }
            let _ = segment::remove(self.segment_start);
        }
    }
    let mut cleanup = Cleanup {
        segment_start: start,
        fixed_type: None,
        variable_type: None,
        format: None,
    };

    let creation_calls = Arc::new(AtomicUsize::new(0));
    let creation_calls_callback = Arc::clone(&creation_calls);
    let fixed_definition = data::CustomDataTypeDefinition {
        name: "idax_rust_p31_fixed_u16".into(),
        menu_name: "idax Rust P31 fixed u16".into(),
        assembler_keyword: "rust_p31_u16".into(),
        value_size: 2,
        allow_duplicates: false,
        may_create_at: Some(Arc::new(move |address, byte_length| {
            creation_calls_callback.fetch_add(1, Ordering::SeqCst);
            address == start && byte_length == 2
        })),
        ..Default::default()
    };
    let fixed_type = data::register_custom_data_type(&fixed_definition).unwrap();
    cleanup.fixed_type = Some(fixed_type);
    assert_eq!(
        data::register_custom_data_type(&fixed_definition)
            .unwrap_err()
            .category,
        ErrorCategory::Conflict
    );

    let render_calls = Arc::new(AtomicUsize::new(0));
    let scan_calls = Arc::new(AtomicUsize::new(0));
    let analyze_calls = Arc::new(AtomicUsize::new(0));
    let analyzed_address = Arc::new(AtomicU64::new(BAD_ADDRESS));
    let render_calls_callback = Arc::clone(&render_calls);
    let scan_calls_callback = Arc::clone(&scan_calls);
    let analyze_calls_callback = Arc::clone(&analyze_calls);
    let analyzed_address_callback = Arc::clone(&analyzed_address);
    let format_definition = data::CustomDataFormatDefinition {
        name: "idax_rust_p31_u16_format".into(),
        menu_name: "idax Rust P31 u16 format".into(),
        value_size: 0,
        text_width: 12,
        render: Some(Arc::new(move |value, context| {
            render_calls_callback.fetch_add(1, Ordering::SeqCst);
            if value.len() != 2 {
                return Err(idax::Error::validation("expected two bytes"));
            }
            let number = u16::from_le_bytes([value[0], value[1]]);
            Ok(format!("u16:{number}@{}", context.address))
        })),
        scan: Some(Arc::new(move |text, _context| {
            scan_calls_callback.fetch_add(1, Ordering::SeqCst);
            if text == "4660" {
                Ok(vec![0x34, 0x12])
            } else {
                Err(idax::Error::validation("expected decimal 4660"))
            }
        })),
        analyze: Some(Arc::new(move |context| {
            analyze_calls_callback.fetch_add(1, Ordering::SeqCst);
            analyzed_address_callback.store(context.address, Ordering::SeqCst);
        })),
        ..Default::default()
    };
    let format = data::register_custom_data_format(&format_definition).unwrap();
    cleanup.format = Some(format);

    assert_eq!(
        data::find_custom_data_type(&fixed_definition.name).unwrap(),
        fixed_type
    );
    assert_eq!(
        data::find_custom_data_format(&format_definition.name).unwrap(),
        format
    );
    let type_info = data::custom_data_type(fixed_type).unwrap();
    assert_eq!(type_info.name, fixed_definition.name);
    assert_eq!(type_info.value_size, 2);
    assert!(!type_info.allow_duplicates);
    assert!(type_info.visible_in_menu);
    assert!(type_info.has_creation_filter);
    assert!(!type_info.variable_size);
    let format_info = data::custom_data_format(format).unwrap();
    assert_eq!(format_info.name, format_definition.name);
    assert_eq!(format_info.value_size, 0);
    assert_eq!(format_info.text_width, 12);
    assert!(format_info.visible_in_menu);
    assert!(format_info.can_render && format_info.can_scan && format_info.can_analyze);
    assert!(
        data::custom_data_types(2, 2)
            .unwrap()
            .iter()
            .any(|info| info.id == fixed_type)
    );
    assert_eq!(
        data::custom_data_types(3, 2).unwrap_err().category,
        ErrorCategory::Validation
    );

    data::attach_custom_data_format(fixed_type, format).unwrap();
    assert_eq!(
        data::attach_custom_data_format(fixed_type, format)
            .unwrap_err()
            .category,
        ErrorCategory::Conflict
    );
    assert!(data::is_custom_data_format_attached(fixed_type, format).unwrap());
    assert_eq!(data::custom_data_formats(fixed_type).unwrap().len(), 1);
    data::attach_custom_data_format_to_standard_types(format).unwrap();
    assert!(data::is_custom_data_format_attached_to_standard_types(format).unwrap());
    assert!(
        data::standard_custom_data_formats()
            .unwrap()
            .iter()
            .any(|info| info.id == format)
    );
    data::detach_custom_data_format_from_standard_types(format).unwrap();

    let context = data::CustomDataFormatContext {
        address: start,
        operand_index: -1,
        type_id: fixed_type,
    };
    assert_eq!(
        data::render_custom_data(format, &[0x34, 0x12], context).unwrap(),
        format!("u16:4660@{start}")
    );
    assert_eq!(render_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        data::scan_custom_data(format, "4660", context).unwrap(),
        vec![0x34, 0x12]
    );
    assert_eq!(scan_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        data::scan_custom_data(format, "invalid", context)
            .unwrap_err()
            .category,
        ErrorCategory::SdkFailure
    );
    data::analyze_custom_data(format, context).unwrap();
    assert_eq!(analyze_calls.load(Ordering::SeqCst), 1);
    assert_eq!(analyzed_address.load(Ordering::SeqCst), start);

    data::define_custom(start, 2, fixed_type, format).unwrap();
    assert!(creation_calls.load(Ordering::SeqCst) >= 1);
    let item = data::custom_data_at(start).unwrap();
    assert_eq!(item.type_id, fixed_type);
    assert_eq!(item.format_id, format);
    assert_eq!(item.byte_length, 2);
    data::undefine(start, 2).unwrap();
    assert_eq!(
        data::custom_data_at(start).unwrap_err().category,
        ErrorCategory::NotFound
    );
    assert_eq!(
        data::custom_data_item_size(fixed_type, start, 2).unwrap(),
        2
    );
    assert_eq!(
        data::custom_data_item_size(fixed_type, start, 1)
            .unwrap_err()
            .category,
        ErrorCategory::Validation
    );
    data::define_custom_inferred(start, fixed_type, format, 2).unwrap();
    data::undefine(start, 2).unwrap();

    let size_calls = Arc::new(AtomicUsize::new(0));
    let size_calls_callback = Arc::clone(&size_calls);
    let variable_definition = data::CustomDataTypeDefinition {
        name: "idax_rust_p31_pascal".into(),
        value_size: 1,
        calculate_size: Some(Arc::new(move |address, maximum_size| {
            size_calls_callback.fetch_add(1, Ordering::SeqCst);
            data::read_byte(address)
                .ok()
                .map(|length| u64::from(length) + 1)
                .filter(|size| *size <= maximum_size)
                .unwrap_or(0)
        })),
        ..Default::default()
    };
    let variable_type = data::register_custom_data_type(&variable_definition).unwrap();
    cleanup.variable_type = Some(variable_type);
    data::attach_custom_data_format(variable_type, format).unwrap();
    data::write_bytes(start, &[3, b'a', b'b', b'c']).unwrap();
    assert_eq!(
        data::custom_data_item_size(variable_type, start, 4).unwrap(),
        4
    );
    assert_eq!(
        data::custom_data_item_size(variable_type, start, 3)
            .unwrap_err()
            .category,
        ErrorCategory::SdkFailure
    );
    let calls_before_creation = size_calls.load(Ordering::SeqCst);
    data::define_custom_inferred(start, variable_type, format, 4).unwrap();
    assert!(size_calls.load(Ordering::SeqCst) > calls_before_creation);
    assert_eq!(data::custom_data_at(start).unwrap().byte_length, 4);
    data::undefine(start, 4).unwrap();

    data::unregister_custom_data_type(fixed_type).unwrap();
    cleanup.fixed_type = None;
    assert_eq!(
        data::find_custom_data_type(&fixed_definition.name)
            .unwrap_err()
            .category,
        ErrorCategory::NotFound
    );
    assert_eq!(data::custom_data_format(format).unwrap().id, format);
    data::unregister_custom_data_type(variable_type).unwrap();
    cleanup.variable_type = None;
    data::unregister_custom_data_format(format).unwrap();
    cleanup.format = None;
}

// ===========================================================================
// Search
// ===========================================================================

fn search_next_code() {
    require_db!();
    let bounds = database::address_bounds().unwrap();
    let code_addr = search::next_code(bounds.start).unwrap();
    assert_ne!(code_addr, BAD_ADDRESS);
}

fn search_next_data() {
    require_db!();
    let bounds = database::address_bounds().unwrap();
    // May or may not find data — just don't crash
    let _ = search::next_data(bounds.start);
}

// ===========================================================================
// Analysis
// ===========================================================================

fn analysis_is_idle() {
    require_db!();
    analysis::wait().unwrap();
    assert!(analysis::is_idle(), "should be idle after wait()");
}

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

fn types_from_declaration() {
    require_db!();
    let ti = types::TypeInfo::from_declaration("int (*)(const char *, ...)").unwrap();
    assert!(
        ti.is_pointer() || ti.is_function(),
        "should parse function pointer decl"
    );
}

fn types_parse_declarations() {
    require_db!();
    let report = types::parse_declarations(
        "typedef struct idax_rust_bulk_decl { int alpha; int beta; } idax_rust_bulk_decl_alias;",
        types::ParseDeclarationsOptions {
            suppress_warnings: true,
            ..Default::default()
        },
    )
    .unwrap();
    assert!(report.ok());
    assert_eq!(report.error_count, 0);
}

fn types_retrieve_at_function() {
    require_db!();
    let f = function::by_index(0).unwrap();
    // May or may not have type info — just don't crash
    let _ = types::retrieve(f.start());
}

fn types_local_type_count() {
    require_db!();
    let n = types::local_type_count().unwrap();
    let _ = n; // may be 0 for simple binaries
}

// ===========================================================================
// Lines (color tags — runtime SDK calls)
// ===========================================================================

fn lines_tag_operations() {
    require_db!();
    let tagged = lines::colstr("hello", lines::Color::Default);
    let plain = lines::tag_remove(&tagged);
    assert_eq!(plain, "hello");
    let len = lines::tag_strlen(&tagged);
    assert_eq!(len, 5, "visible length should be 5");
}

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

fn decompiler_available() {
    require_db!();
    // Just check we can query without crashing
    let _ = decompiler::available();
}

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

    // Earlier cases decompile the same function. Invalidate that cached cfunc
    // so Hex-Rays regenerates microcode through the newly installed filter.
    decompiler::mark_dirty(f.start(), false).unwrap();
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

fn event_subscribe_unsubscribe() {
    require_db!();
    let token = event::on_renamed(|_addr, _old, _new| {
        // callback — won't fire during this test
    })
    .unwrap();
    event::unsubscribe(token).unwrap();
}

fn event_scoped_subscription() {
    require_db!();
    {
        let token = event::on_byte_patched(|_addr, _old_val| {}).unwrap();
        let _scoped = event::ScopedSubscription::new(token);
        // auto-unsubscribes on drop
    }
}

fn event_function_update_self_unsubscribe() {
    require_db!();
    let function = function::by_index(0).unwrap();
    let address = function.start();

    let token_slot = Arc::new(AtomicU64::new(0));
    let typed_count = Arc::new(AtomicUsize::new(0));
    let typed_address = Arc::new(AtomicU64::new(BAD_ADDRESS));
    let unsubscribe_ok = Arc::new(AtomicBool::new(false));

    let callback_token = Arc::clone(&token_slot);
    let callback_count = Arc::clone(&typed_count);
    let callback_address = Arc::clone(&typed_address);
    let callback_unsubscribe = Arc::clone(&unsubscribe_ok);
    let token = event::on_function_updated(move |entry| {
        callback_count.fetch_add(1, Ordering::Relaxed);
        callback_address.store(entry, Ordering::Relaxed);
        let token = callback_token.load(Ordering::Relaxed);
        if token != 0 && event::unsubscribe(token).is_ok() {
            callback_unsubscribe.store(true, Ordering::Relaxed);
        }
    })
    .unwrap();
    token_slot.store(token, Ordering::Relaxed);

    let generic_count = Arc::new(AtomicUsize::new(0));
    let generic_shape_ok = Arc::new(AtomicBool::new(false));
    let callback_generic_count = Arc::clone(&generic_count);
    let callback_generic_shape = Arc::clone(&generic_shape_ok);
    let generic_token = event::on_event(move |payload| {
        if payload.kind == event::EventKind::FunctionUpdated && payload.address == address {
            callback_generic_count.fetch_add(1, Ordering::Relaxed);
            if payload.operand_index == -1 && payload.line_index == -1 {
                callback_generic_shape.store(true, Ordering::Relaxed);
            }
        }
    })
    .unwrap();

    function::update(address).unwrap();
    function::update(address).unwrap();

    assert_eq!(typed_count.load(Ordering::Relaxed), 1);
    assert_eq!(typed_address.load(Ordering::Relaxed), address);
    assert!(unsubscribe_ok.load(Ordering::Relaxed));
    assert!(generic_count.load(Ordering::Relaxed) >= 2);
    assert!(generic_shape_ok.load(Ordering::Relaxed));
    event::unsubscribe(generic_token).unwrap();
}

fn event_extra_comment_payload() {
    require_db!();
    let address = function::by_index(0).unwrap().start();
    comment::clear_anterior(address).unwrap();

    let captured = Arc::new(Mutex::new(None));
    let callback_capture = Arc::clone(&captured);
    let token = event::on_extra_comment_changed(move |payload| {
        *callback_capture.lock().unwrap() = Some(payload);
    })
    .unwrap();

    comment::add_anterior(address, "idax rust event line").unwrap();
    event::unsubscribe(token).unwrap();

    let payload = captured
        .lock()
        .unwrap()
        .clone()
        .expect("event not delivered");
    assert_eq!(payload.address, address);
    assert_eq!(payload.placement, event::ExtraCommentPlacement::Anterior);
    assert_eq!(payload.line_index, 0);
    assert_eq!(payload.text, "idax rust event line");
    comment::clear_anterior(address).unwrap();
}

// ===========================================================================
// Graph
// ===========================================================================

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

fn cross_domain_bad_address_handling() {
    require_db!();
    // BAD_ADDRESS should fail gracefully across domains
    assert!(segment::at(BAD_ADDRESS).is_err());
    assert!(function::at(BAD_ADDRESS).is_err());
    assert!(instruction::decode(BAD_ADDRESS).is_err());
    assert!(data::read_byte(BAD_ADDRESS).is_err());
    assert!(name::get(BAD_ADDRESS).is_err());
}

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

// ---------------------------------------------------------------------------
// Process-main-thread test runner
// ---------------------------------------------------------------------------

type TestCase = (&'static str, fn());

static TEST_CASES: &[TestCase] = &[
    ("database_input_file_path", database_input_file_path),
    ("database_idb_path", database_idb_path),
    ("database_file_type_name", database_file_type_name),
    ("database_input_md5", database_input_md5),
    ("database_address_bitness", database_address_bitness),
    (
        "database_set_address_bitness_idempotent",
        database_set_address_bitness_idempotent,
    ),
    ("database_processor_name", database_processor_name),
    ("database_address_bounds", database_address_bounds),
    ("database_image_base", database_image_base),
    ("database_endianness", database_endianness),
    ("database_abi_name", database_abi_name),
    ("database_processor_typed", database_processor_typed),
    ("database_compiler_info", database_compiler_info),
    ("database_import_modules", database_import_modules),
    ("database_snapshots", database_snapshots),
    ("segment_count_nonzero", segment_count_nonzero),
    ("segment_all_iterator", segment_all_iterator),
    ("segment_by_index", segment_by_index),
    ("segment_at_address", segment_at_address),
    ("segment_first_last", segment_first_last),
    ("segment_next_prev", segment_next_prev),
    ("segment_properties", segment_properties),
    ("function_count_nonzero", function_count_nonzero),
    ("function_all_iterator", function_all_iterator),
    ("function_by_index_and_at", function_by_index_and_at),
    ("function_properties", function_properties),
    ("function_callers_callees", function_callers_callees),
    ("function_chunks", function_chunks),
    ("function_code_addresses", function_code_addresses),
    ("function_frame", function_frame),
    ("instruction_decode_first", instruction_decode_first),
    ("instruction_text", instruction_text),
    ("instruction_operands", instruction_operands),
    ("instruction_classification", instruction_classification),
    ("instruction_code_refs", instruction_code_refs),
    ("instruction_next_prev", instruction_next_prev),
    ("name_get_first_function", name_get_first_function),
    ("name_set_and_remove", name_set_and_remove),
    ("name_resolve", name_resolve),
    ("name_predicates", name_predicates),
    ("name_validation", name_validation),
    (
        "name_demangle_arbitrary_symbol",
        name_demangle_arbitrary_symbol,
    ),
    (
        "ui_current_widget_headless_safe",
        ui_current_widget_headless_safe,
    ),
    ("comment_set_get_remove", comment_set_get_remove),
    ("comment_append", comment_append),
    ("comment_anterior_posterior", comment_anterior_posterior),
    ("xref_refs_to_from", xref_refs_to_from),
    ("xref_code_data_refs", xref_code_data_refs),
    ("data_read_byte", data_read_byte),
    ("data_read_bytes", data_read_bytes),
    ("data_read_word_dword_qword", data_read_word_dword_qword),
    ("data_patch_and_revert", data_patch_and_revert),
    (
        "data_element_definition_units",
        data_element_definition_units,
    ),
    ("data_custom_data_lifecycle", data_custom_data_lifecycle),
    ("search_next_code", search_next_code),
    ("search_next_data", search_next_data),
    ("analysis_is_idle", analysis_is_idle),
    ("analysis_enable_disable", analysis_enable_disable),
    ("entry_count_and_enumerate", entry_count_and_enumerate),
    ("types_primitive_constructors", types_primitive_constructors),
    ("types_pointer_and_array", types_pointer_and_array),
    ("types_struct_creation", types_struct_creation),
    ("types_from_declaration", types_from_declaration),
    ("types_parse_declarations", types_parse_declarations),
    ("types_retrieve_at_function", types_retrieve_at_function),
    ("types_local_type_count", types_local_type_count),
    ("lines_tag_operations", lines_tag_operations),
    ("lines_addr_tag_roundtrip", lines_addr_tag_roundtrip),
    ("decompiler_available", decompiler_available),
    ("decompiler_decompile", decompiler_decompile),
    ("decompiler_variables", decompiler_variables),
    ("decompiler_microcode", decompiler_microcode),
    (
        "decompiler_microcode_filter_context_introspection",
        decompiler_microcode_filter_context_introspection,
    ),
    ("decompiler_item_type_names", decompiler_item_type_names),
    ("storage_node_lifecycle", storage_node_lifecycle),
    ("fixup_enumerate", fixup_enumerate),
    ("event_subscribe_unsubscribe", event_subscribe_unsubscribe),
    ("event_scoped_subscription", event_scoped_subscription),
    (
        "event_function_update_self_unsubscribe",
        event_function_update_self_unsubscribe,
    ),
    ("event_extra_comment_payload", event_extra_comment_payload),
    ("graph_flowchart", graph_flowchart),
    ("graph_manual_construction", graph_manual_construction),
    ("graph_groups", graph_groups),
    (
        "cross_domain_bad_address_handling",
        cross_domain_bad_address_handling,
    ),
    (
        "cross_domain_name_comment_roundtrip",
        cross_domain_name_comment_roundtrip,
    ),
    (
        "cross_domain_segment_function_consistency",
        cross_domain_segment_function_consistency,
    ),
    (
        "cross_domain_data_instruction_consistency",
        cross_domain_data_instruction_consistency,
    ),
];

#[derive(Default)]
struct RunnerOptions {
    filters: Vec<String>,
    skips: Vec<String>,
    exact: bool,
    ignored_only: bool,
    include_ignored: bool,
    list: bool,
}

fn parse_runner_options() -> RunnerOptions {
    let mut options = RunnerOptions::default();
    let mut args = std::env::args().skip(1);

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--exact" => options.exact = true,
            "--ignored" => options.ignored_only = true,
            "--include-ignored" => options.include_ignored = true,
            "--list" => options.list = true,
            "--skip" => {
                if let Some(pattern) = args.next() {
                    options.skips.push(pattern);
                }
            }
            "--test-threads" | "--format" | "--color" => {
                let _ = args.next();
            }
            "--nocapture" | "--show-output" | "--quiet" => {}
            _ if arg.starts_with("--skip=") => {
                options.skips.push(arg[7..].to_owned());
            }
            _ if arg.starts_with('-') => {}
            _ => options.filters.push(arg),
        }
    }

    options
}

fn is_selected(name: &str, options: &RunnerOptions) -> bool {
    let included = options.filters.is_empty()
        || options.filters.iter().any(|filter| {
            if options.exact {
                name == filter
            } else {
                name.contains(filter)
            }
        });
    let ignored_filter = !options.ignored_only || ignored_reason(name).is_some();
    included && ignored_filter && !options.skips.iter().any(|skip| name.contains(skip))
}

fn ignored_reason(name: &str) -> Option<&'static str> {
    #[cfg(target_os = "linux")]
    if matches!(name, "analysis_is_idle" | "analysis_enable_disable") {
        return Some("segfaults under headless idalib on Linux CI");
    }
    let _ = name;
    None
}

fn panic_message(payload: &(dyn std::any::Any + Send)) -> &str {
    payload
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
        .unwrap_or("non-string panic payload")
}

fn close_session() -> Result<(), String> {
    if INIT_OK.swap(false, Ordering::AcqRel) {
        database::close(false).map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn main() {
    let options = parse_runner_options();
    let selected: Vec<TestCase> = TEST_CASES
        .iter()
        .copied()
        .filter(|(name, _)| is_selected(name, &options))
        .collect();
    let filtered_out = TEST_CASES.len() - selected.len();

    if options.list {
        for (name, _) in &selected {
            println!("{name}: test");
        }
        return;
    }

    println!("running {} tests", selected.len());

    if std::env::var_os("IDADIR").is_none() {
        for (name, _) in &selected {
            println!("test {name} ... ignored, IDADIR not set");
        }
        println!();
        println!(
            "test result: ok. 0 passed; 0 failed; {} ignored; {filtered_out} filtered out",
            selected.len()
        );
        return;
    }

    let mut passed = 0usize;
    let mut failed = 0usize;
    let mut ignored = 0usize;

    for (name, test) in selected {
        if let Some(reason) = ignored_reason(name) {
            if !options.include_ignored && !options.ignored_only {
                ignored += 1;
                println!("test {name} ... ignored, {reason}");
                continue;
            }
        }
        print!("test {name} ... ");
        let _ = std::io::stdout().flush();
        match panic::catch_unwind(AssertUnwindSafe(test)) {
            Ok(()) => {
                passed += 1;
                println!("ok");
            }
            Err(payload) => {
                failed += 1;
                println!("FAILED: {}", panic_message(payload.as_ref()));
            }
        }
    }

    if let Err(error) = close_session() {
        failed += 1;
        eprintln!("IDA session cleanup failed: {error}");
    }

    println!();
    println!(
        "test result: {}. {passed} passed; {failed} failed; {ignored} ignored; {filtered_out} filtered out",
        if failed == 0 { "ok" } else { "FAILED" }
    );

    if failed != 0 {
        std::process::exit(101);
    }
}

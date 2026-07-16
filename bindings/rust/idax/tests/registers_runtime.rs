//! Initialized-host positive evidence for the AArch64 register tracker.

use idax::address::BAD_ADDRESS;
use idax::registers::{self, ReferenceMutation, TrackingState};
use idax::{analysis, database, name};

fn fixture_path() -> Option<std::path::PathBuf> {
    if let Some(path) = std::env::var_os("IDAX_REGISTERS_RUNTIME_FIXTURE") {
        return Some(path.into());
    }
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()?
        .parent()?
        .parent()?;
    Some(root.join("tests/fixtures/register_tracking_aarch64"))
}

fn main() {
    if std::env::var_os("IDADIR").is_none() {
        println!("test initialized_register_tracking ... ignored, IDADIR not set");
        return;
    }
    let source = fixture_path().expect("resolve register-tracking fixture");
    if !source.is_file() {
        println!("test initialized_register_tracking ... ignored, fixture is absent");
        return;
    }
    let directory =
        std::env::temp_dir().join(format!("idax_rust_registers_{}", std::process::id()));
    if directory.exists() {
        std::fs::remove_dir_all(&directory).expect("remove stale fixture directory");
    }
    std::fs::create_dir_all(&directory).expect("create fixture directory");
    let fixture = directory.join("register_tracking_aarch64");
    std::fs::copy(source, &fixture).expect("copy register-tracking fixture");

    println!("running 1 test");
    print!("test initialized_register_tracking ... ");
    database::init().expect("database init");
    database::open(fixture.to_str().expect("UTF-8 fixture path"), true).expect("database open");
    analysis::wait().expect("analysis wait");
    let start = name::resolve("_start", BAD_ADDRESS).expect("resolve _start");

    assert_eq!(
        registers::constant_at(start + 4, "x29", 0).unwrap(),
        Some(0)
    );
    let constant = registers::track(start + 4, "x29", 0).unwrap();
    assert_eq!(constant.state, TrackingState::Constant);
    assert!(constant.known());
    assert_eq!(constant.candidates[0].constant, Some(0));
    assert_eq!(constant.candidates[0].origin.address, start);
    assert_eq!(
        registers::constant_at(start + 12, "x0", 0).unwrap(),
        Some(0x0000_abcd_0000_1234)
    );
    assert_eq!(
        registers::constant_at(start + 12, "w0", 0).unwrap(),
        Some(0x1234)
    );
    assert_eq!(
        registers::constant_at(start + 12, "w0", -1).unwrap(),
        Some(0x1234)
    );

    assert_eq!(
        registers::stack_delta_at(start + 16, None).unwrap(),
        Some(-32)
    );
    let stack = registers::track(start + 16, "sp", 0).unwrap();
    assert_eq!(stack.state, TrackingState::StackPointerDelta);
    assert!(!stack.candidates.is_empty());

    let input = registers::track(start, "x0", 0).unwrap();
    assert!(matches!(
        input.state,
        TrackingState::FunctionInput | TrackingState::Undefined
    ));
    assert_eq!(registers::constant_at(start, "x0", 0).unwrap(), None);

    let multi_join = name::resolve("multi_join", BAD_ADDRESS).expect("resolve multi_join");
    let multi = registers::track(multi_join, "x2", 0).unwrap();
    assert_eq!(multi.state, TrackingState::Constant);
    assert_eq!(multi.candidates.len(), 2);
    let mut merged_constants = multi
        .candidates
        .iter()
        .map(|candidate| candidate.constant.expect("merged constant candidate"))
        .collect::<Vec<_>>();
    merged_constants.sort_unstable();
    assert_eq!(merged_constants, vec![0x11, 0x22]);
    assert_eq!(registers::constant_at(multi_join, "x2", 0).unwrap(), None);

    let nearest = registers::nearest_at(start + 12, "x29", "x0")
        .unwrap()
        .expect("nearest value");
    assert_eq!(nearest.selected_index, 0);
    assert_eq!(nearest.register_name, "x29");
    assert!(nearest.value.known());
    assert!(registers::nearest_at(start + 12, "x0", "w0").is_err());

    registers::control_flow_reference_changed(start, start + 4, ReferenceMutation::Added).unwrap();
    registers::control_flow_reference_changed(start, start + 4, ReferenceMutation::Removed)
        .unwrap();
    registers::data_reference_changed(start, ReferenceMutation::Added).unwrap();
    registers::data_reference_changed(start, ReferenceMutation::Removed).unwrap();
    registers::clear_control_flow_cache().unwrap();
    registers::clear_data_reference_cache().unwrap();

    database::close(false).expect("database close");
    std::fs::remove_dir_all(directory).expect("remove fixture directory");
    println!("ok");
    println!("\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 filtered out");
}

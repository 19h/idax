//! Initialized owned C-ABI metadata, ctree summaries, and cache parser evidence.
use idax::{analysis, database, decompiler::*, dyld_cache, function, instruction, plugin};
use std::{cell::RefCell, collections::HashSet, rc::Rc};

#[derive(Default)]
struct Counts { floats: usize, stacks: usize, calls: usize, switches: usize }
fn operand(value: &MicrocodeOperand, blocks: &HashSet<i32>, counts: &mut Counts) {
    if value.floating_point_constant == Some(65536.0) { counts.floats += 1; }
    if value.kind == MicrocodeOperandKind::CallArguments {
        counts.calls += 1;
        assert_eq!(value.call_argument_properties.len(), value.call_arguments.len());
        for range in &value.call_return_registers { assert!(range.byte_width > 0); }
    }
    if value.kind == MicrocodeOperandKind::SwitchCases { counts.switches += 1; }
    for case in &value.switch_cases { assert!(blocks.contains(&case.target_block)); }
    if let Some(target) = value.switch_default_target { assert!(blocks.contains(&target)); }
    if let Some(nested) = &value.nested_instruction { micro_instruction(nested, blocks, counts); }
    if let Some(referenced) = &value.referenced_operand { operand(referenced, blocks, counts); }
    for argument in value.call_arguments.iter().chain(&value.call_return_operands) { operand(argument, blocks, counts); }
}
fn micro_instruction(value: &MicrocodeInstruction, blocks: &HashSet<i32>, counts: &mut Counts) {
    operand(&value.left, blocks, counts); operand(&value.right, blocks, counts); operand(&value.destination, blocks, counts);
}
fn graph(value: &MicrocodeFunction, counts: &mut Counts) {
    assert!(value.stack_frame_size >= 0 && value.local_stack_size >= 0 && value.saved_register_size >= 0);
    if let Some(index) = value.return_variable_index { assert!(index < value.local_variables.len()); }
    let blocks = value.blocks.iter().map(|block| block.index).collect();
    for block in &value.blocks { for instruction in &block.instructions { micro_instruction(instruction, &blocks, counts); } }
    for variable in &value.local_variables {
        if variable.storage == VariableStorage::Stack {
            counts.stacks += 1;
            assert!(variable.stack_offset >= 0);
            assert_eq!(variable.location.as_ref().unwrap().stack_offset, variable.stack_offset);
        }
    }
}
fn main() {
    let Some(source) = std::env::var_os("IDAX_SEMANTIC_RUNTIME_FIXTURE") else {
        println!("semantic_metadata_runtime ignored: IDAX_SEMANTIC_RUNTIME_FIXTURE is not configured"); return;
    };
    let directory = std::env::temp_dir().join(format!("idax-rust-metadata-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let fixture = directory.join("metadata_fixture"); std::fs::copy(source, &fixture).unwrap();
    let cache = directory.join("cache_fixture");
    let mut bytes = vec![0u8; 0x300];
    bytes[..15].copy_from_slice(b"dyld_v1  arm64e");
    bytes[0x10..0x14].copy_from_slice(&0x1c8u32.to_le_bytes());
    bytes[0x1c0..0x1c4].copy_from_slice(&0x200u32.to_le_bytes());
    bytes[0x1c4..0x1c8].copy_from_slice(&1u32.to_le_bytes());
    bytes[0x200..0x208].copy_from_slice(&0xfedcba9876543210u64.to_le_bytes());
    bytes[0x218..0x21c].copy_from_slice(&0x240u32.to_le_bytes());
    let path = b"/usr/lib/owned.dylib"; bytes[0x240..0x240 + path.len()].copy_from_slice(path);
    std::fs::write(&cache, &bytes).unwrap();
    let inventory = dyld_cache::list_modules_from_file(cache.to_str().unwrap()).unwrap();
    assert_eq!(inventory, vec![dyld_cache::ModuleInfo { path: "/usr/lib/owned.dylib".into(), load_address: 0xfedcba9876543210 }]);
    bytes[0x1c4..0x1c8].copy_from_slice(&2u32.to_le_bytes()); std::fs::write(&cache, &bytes).unwrap();
    assert!(dyld_cache::list_modules_from_file(cache.to_str().unwrap()).is_err());
    assert!(dyld_cache::list_modules_from_file("bad\0path").is_err());
    database::init().unwrap(); database::open(fixture.to_str().unwrap(), true).unwrap(); analysis::wait().unwrap();
    assert!(!dyld_cache::is_available().unwrap());
    assert!(dyld_cache::list_modules().is_err());
    assert!(plugin::run_plugin("bad\0plugin", 0).is_err());
    assert!(available().unwrap(), "decompiler required for this evidence");
    let mut counts = Counts::default();
    let mut retained = Vec::new();
    let expressions = Rc::new(RefCell::new(Vec::new()));
    let statements = Rc::new(RefCell::new(Vec::new()));
    let mut functions = 0;
    for index in 0..function::count().unwrap() {
        let function = function::by_index(index).unwrap();
        if !function.name().contains("idax_metadata_") { continue; }
        functions += 1;
        let decoded = instruction::decode(function.start()).unwrap();
        assert_eq!(decoded.branch_condition(), instruction::branch_condition(function.start()));
        for maturity in [MicrocodeMaturity::Generated, MicrocodeMaturity::Preoptimized, MicrocodeMaturity::LocallyOptimized, MicrocodeMaturity::CallsAnalyzed, MicrocodeMaturity::GloballyOptimized1, MicrocodeMaturity::GloballyOptimized2, MicrocodeMaturity::GloballyOptimized3, MicrocodeMaturity::LocalVariables] {
            let model = generate_microcode(function.start(), MicrocodeGenerationOptions { maturity, analyze_calls: false }).unwrap();
            graph(&model, &mut counts); retained.push(model);
        }
        let decompiled = decompile(function.start()).unwrap();
        let exprs = Rc::clone(&expressions); let stmts = Rc::clone(&statements);
        decompiled.for_each_item(move |item| { exprs.borrow_mut().push(item); VisitAction::Continue }, move |item| { stmts.borrow_mut().push(item); VisitAction::Continue }).unwrap();
        let hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let contained = decompiled.for_each_expression(|_| panic!("expected contained visitor panic"));
        std::panic::set_hook(hook);
        assert!(contained.is_err());
    }
    assert!(functions >= 5 && counts.floats > 0 && counts.stacks > 0 && counts.calls > 0 && counts.switches > 0);
    assert!(expressions.borrow().iter().any(|item| !item.parents.is_empty()));
    let mut children = 0;
    for item in expressions.borrow().iter() {
        assert_eq!(item.parents.len(), item.parent_depth);
        children += item.call_arguments.len() + [&item.left, &item.right, &item.third, &item.call_callee].iter().filter(|child| child.is_some()).count();
    }
    for item in statements.borrow().iter() {
        assert_eq!(item.parents.len(), item.parent_depth);
        children += item.block_statements.len() + [&item.condition, &item.then_branch, &item.else_branch, &item.body, &item.init_expression, &item.step_expression, &item.expression].iter().filter(|child| child.is_some()).count();
    }
    assert!(children > 0);
    for model in &retained { graph(model, &mut counts); }
    let saved = directory.join("saved.i64"); database::save_to(saved.to_str().unwrap()).unwrap(); assert!(saved.is_file());
    database::close(false).unwrap(); database::open(saved.to_str().unwrap(), false).unwrap(); database::close(false).unwrap();
    std::fs::remove_dir_all(directory).unwrap();
    println!("semantic metadata passed: {} float constants, {} stack variables, {} calls, {} switch descriptors, {children} children", counts.floats, counts.stacks, counts.calls, counts.switches);
}

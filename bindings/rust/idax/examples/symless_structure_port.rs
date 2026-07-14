#[allow(dead_code)]
mod common;

// Adapted from Symless; upstream copyright/license is retained in
// examples/plugin/symless_port_LICENSE.txt at the repository root.

use common::{DatabaseSession, format_error, print_usage, resolve_symbol_or_address};
use idax::address::{Address, BAD_ADDRESS};
use idax::decompiler::{
    MicrocodeBlock, MicrocodeFunction, MicrocodeGenerationOptions, MicrocodeInstruction,
    MicrocodeMaturity, MicrocodeOpcode, MicrocodeOperand, MicrocodeOperandKind,
    MicrocodeValueLocation, MicrocodeValueLocationKind,
};
use idax::error::ErrorCategory;
use idax::types::TypeInfo;
use idax::{Error, Result, database, decompiler, types};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone)]
struct Options {
    input: String,
    function: String,
    argument_index: usize,
    structure_name: Option<String>,
    apply: bool,
    show: usize,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            input: String::new(),
            function: String::new(),
            argument_index: 0,
            structure_name: None,
            apply: false,
            show: 40,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AbstractValue {
    StructurePointer(i64),
    Integer { value: i64, byte_width: i32 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Variable {
    Register(i32),
    Local(i32, i64),
    Stack(i64),
}

#[derive(Debug, Clone, Default)]
struct State {
    values: HashMap<Variable, AbstractValue>,
}

impl State {
    fn information_score(&self) -> usize {
        self.values
            .values()
            .filter(|value| matches!(value, AbstractValue::StructurePointer(_)))
            .count()
    }

    fn value(&self, operand: &MicrocodeOperand) -> Option<AbstractValue> {
        variable_for_operand(operand).and_then(|variable| self.values.get(&variable).copied())
    }

    fn assign(&mut self, operand: &MicrocodeOperand, value: Option<AbstractValue>) {
        let Some(variable) = variable_for_operand(operand) else {
            return;
        };
        if let Some(value) = value {
            self.values.insert(variable, value);
        } else {
            self.values.remove(&variable);
        }
    }
}

#[derive(Debug, Clone)]
struct RawAccess {
    offset: i64,
    byte_width: i32,
    reads: usize,
    writes: usize,
    sites: Vec<Address>,
    first_seen: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RecoveredField {
    offset: i64,
    byte_width: i32,
    reads: usize,
    writes: usize,
    sites: Vec<Address>,
}

#[derive(Debug, Clone)]
struct Reconstruction {
    function_address: Address,
    argument_index: usize,
    argument_name: String,
    argument_location: MicrocodeValueLocation,
    fields: Vec<RecoveredField>,
    instructions_processed: usize,
    blocks_processed: usize,
    unsupported_instructions: usize,
    negative_accesses: usize,
    conflict_discards: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ArgumentEligibility {
    Eligible,
    AlreadyTyped,
    Ineligible,
}

#[derive(Debug, Default)]
struct ApplySummary {
    structure_created: bool,
    members_added: usize,
    members_reused: usize,
    members_skipped: usize,
    argument_changed: bool,
    argument_already_typed: bool,
}

fn parse_options(args: &[String]) -> Result<Options> {
    if args.len() < 2 {
        return Err(Error::validation("missing binary_file argument"));
    }
    let mut options = Options {
        input: args[1].clone(),
        ..Options::default()
    };
    let mut index = 2usize;
    while index < args.len() {
        match args[index].as_str() {
            "-h" | "--help" => {
                print_usage(
                    &args[0],
                    "<binary_file> --function <address-or-name> [--argument <index>] \
                     [--name <type>] [--show <count>] [--apply]",
                );
                std::process::exit(0);
            }
            "--function" => {
                index += 1;
                options.function = args
                    .get(index)
                    .ok_or_else(|| Error::validation("--function requires a value"))?
                    .clone();
            }
            "--argument" => {
                index += 1;
                options.argument_index = args
                    .get(index)
                    .ok_or_else(|| Error::validation("--argument requires a value"))?
                    .parse::<usize>()
                    .map_err(|_| Error::validation("invalid --argument value"))?;
            }
            "--name" => {
                index += 1;
                options.structure_name = Some(
                    args.get(index)
                        .ok_or_else(|| Error::validation("--name requires a value"))?
                        .clone(),
                );
            }
            "--show" => {
                index += 1;
                options.show = args
                    .get(index)
                    .ok_or_else(|| Error::validation("--show requires a value"))?
                    .parse::<usize>()
                    .map_err(|_| Error::validation("invalid --show value"))?;
            }
            "--apply" => options.apply = true,
            unknown => return Err(Error::validation(format!("unknown option: {unknown}"))),
        }
        index += 1;
    }
    if options.function.is_empty() {
        return Err(Error::validation("--function is required"));
    }
    Ok(options)
}

fn variable_for_operand(operand: &MicrocodeOperand) -> Option<Variable> {
    match operand.kind {
        MicrocodeOperandKind::Register => Some(Variable::Register(operand.register_id)),
        MicrocodeOperandKind::LocalVariable => Some(Variable::Local(
            operand.local_variable_index,
            operand.local_variable_offset,
        )),
        MicrocodeOperandKind::StackVariable => Some(Variable::Stack(operand.stack_offset)),
        _ => None,
    }
}

fn signed_to_width(value: i128, byte_width: i32) -> i64 {
    let bits = byte_width.clamp(1, 8) as u32 * 8;
    if bits == 64 {
        return (value as u64) as i64;
    }
    let mask = (1u128 << bits) - 1;
    let unsigned = (value as u128) & mask;
    let sign = 1u128 << (bits - 1);
    if unsigned & sign == 0 {
        unsigned as i64
    } else {
        (unsigned as i128 - (1i128 << bits)) as i64
    }
}

fn immediate_value(operand: &MicrocodeOperand) -> Option<AbstractValue> {
    match operand.kind {
        MicrocodeOperandKind::UnsignedImmediate => Some(AbstractValue::Integer {
            value: signed_to_width(operand.unsigned_immediate as i128, operand.byte_width),
            byte_width: operand.byte_width,
        }),
        MicrocodeOperandKind::SignedImmediate => Some(AbstractValue::Integer {
            value: signed_to_width(operand.signed_immediate as i128, operand.byte_width),
            byte_width: operand.byte_width,
        }),
        MicrocodeOperandKind::GlobalAddress => Some(AbstractValue::Integer {
            value: operand.global_address as i64,
            byte_width: operand.byte_width,
        }),
        MicrocodeOperandKind::AddressReference => operand
            .referenced_operand
            .as_deref()
            .and_then(immediate_value),
        _ => None,
    }
}

fn operand_value(
    state: &mut State,
    operand: &MicrocodeOperand,
    raw_accesses: &mut Vec<RawAccess>,
    unsupported: &mut usize,
) -> Option<AbstractValue> {
    if let Some(nested) = operand.nested_instruction.as_deref() {
        return process_instruction(state, nested, raw_accesses, unsupported);
    }
    state.value(operand).or_else(|| immediate_value(operand))
}

fn record_access(
    raw_accesses: &mut Vec<RawAccess>,
    pointer: Option<AbstractValue>,
    byte_width: i32,
    address: Address,
    write: bool,
) {
    let Some(AbstractValue::StructurePointer(offset)) = pointer else {
        return;
    };
    if byte_width <= 0 {
        return;
    }
    if let Some(existing) = raw_accesses
        .iter_mut()
        .find(|access| access.offset == offset)
    {
        existing.byte_width = existing.byte_width.min(byte_width);
        existing.reads += usize::from(!write);
        existing.writes += usize::from(write);
        if address != BAD_ADDRESS && !existing.sites.contains(&address) {
            existing.sites.push(address);
        }
        return;
    }
    raw_accesses.push(RawAccess {
        offset,
        byte_width,
        reads: usize::from(!write),
        writes: usize::from(write),
        sites: if address == BAD_ADDRESS {
            Vec::new()
        } else {
            vec![address]
        },
        first_seen: raw_accesses.len(),
    });
}

fn process_instruction(
    state: &mut State,
    instruction: &MicrocodeInstruction,
    raw_accesses: &mut Vec<RawAccess>,
    unsupported: &mut usize,
) -> Option<AbstractValue> {
    let result = match instruction.opcode {
        MicrocodeOpcode::Move => {
            let value = operand_value(state, &instruction.left, raw_accesses, unsupported);
            match value {
                Some(AbstractValue::Integer { value, .. }) => Some(AbstractValue::Integer {
                    value: signed_to_width(value as i128, instruction.destination.byte_width),
                    byte_width: instruction.destination.byte_width,
                }),
                other => other,
            }
        }
        MicrocodeOpcode::ZeroExtend | MicrocodeOpcode::SignedExtend => {
            match operand_value(state, &instruction.left, raw_accesses, unsupported) {
                Some(AbstractValue::Integer { value, .. }) => Some(AbstractValue::Integer {
                    value,
                    byte_width: instruction.destination.byte_width,
                }),
                _ => None,
            }
        }
        MicrocodeOpcode::Add | MicrocodeOpcode::Subtract => {
            let left = operand_value(state, &instruction.left, raw_accesses, unsupported);
            let right = operand_value(state, &instruction.right, raw_accesses, unsupported);
            match (left, right) {
                (
                    Some(AbstractValue::StructurePointer(offset)),
                    Some(AbstractValue::Integer { value, byte_width }),
                ) => {
                    let delta = if instruction.opcode == MicrocodeOpcode::Subtract {
                        -(value as i128)
                    } else {
                        value as i128
                    };
                    Some(AbstractValue::StructurePointer(signed_to_width(
                        offset as i128 + delta,
                        byte_width,
                    )))
                }
                _ => None,
            }
        }
        MicrocodeOpcode::LoadMemory => {
            let pointer = operand_value(state, &instruction.right, raw_accesses, unsupported);
            record_access(
                raw_accesses,
                pointer,
                instruction.destination.byte_width,
                instruction.address,
                false,
            );
            None
        }
        MicrocodeOpcode::StoreMemory => {
            let _ = operand_value(state, &instruction.left, raw_accesses, unsupported);
            let pointer = operand_value(state, &instruction.destination, raw_accesses, unsupported);
            record_access(
                raw_accesses,
                pointer,
                instruction.left.byte_width,
                instruction.address,
                true,
            );
            return None;
        }
        _ => {
            *unsupported += 1;
            None
        }
    };
    state.assign(&instruction.destination, result);
    result
}

fn topological_order(graph: &MicrocodeFunction) -> Vec<usize> {
    let active_ids = graph
        .blocks
        .iter()
        .filter(|block| !block.instructions.is_empty())
        .map(|block| block.index)
        .collect::<HashSet<_>>();
    let mut nodes = graph
        .blocks
        .iter()
        .enumerate()
        .filter(|(_, block)| active_ids.contains(&block.index))
        .map(|(position, block)| {
            let predecessors = block
                .predecessors
                .iter()
                .copied()
                .filter(|id| active_ids.contains(id))
                .collect::<HashSet<_>>();
            (position, block.index, predecessors)
        })
        .collect::<Vec<_>>();
    let mut visited = HashSet::new();
    let mut order = Vec::with_capacity(nodes.len());
    while !nodes.is_empty() {
        let selected = nodes
            .iter()
            .position(|(_, _, predecessors)| predecessors.is_subset(&visited))
            .or_else(|| {
                nodes
                    .iter()
                    .position(|(_, _, predecessors)| !predecessors.is_disjoint(&visited))
            })
            .unwrap_or(0);
        let (position, id, _) = nodes.remove(selected);
        visited.insert(id);
        order.push(position);
    }
    order
}

fn inject_argument(state: &mut State, location: &MicrocodeValueLocation) -> Result<()> {
    let variable = match location.kind {
        MicrocodeValueLocationKind::Register => Variable::Register(location.register_id),
        MicrocodeValueLocationKind::RegisterWithOffset if location.register_offset == 0 => {
            Variable::Register(location.register_id)
        }
        MicrocodeValueLocationKind::StackOffset => Variable::Stack(location.stack_offset),
        _ => {
            return Err(Error::unsupported(format!(
                "argument location {:?} is outside the bounded register/stack model",
                location.kind
            )));
        }
    };
    state
        .values
        .insert(variable, AbstractValue::StructurePointer(0));
    Ok(())
}

fn select_predecessor_state(block: &MicrocodeBlock, states: &HashMap<i32, State>) -> State {
    let mut selected: Option<&State> = None;
    let mut best_score = 0usize;
    for state in block
        .predecessors
        .iter()
        .filter_map(|predecessor| states.get(predecessor))
    {
        let score = state.information_score();
        if selected.is_none() || score > best_score {
            selected = Some(state);
            best_score = score;
        }
    }
    selected.cloned().unwrap_or_default()
}

fn resolve_field_conflicts(raw_accesses: &[RawAccess]) -> (Vec<RecoveredField>, usize, usize) {
    let mut candidates = raw_accesses.to_vec();
    candidates.sort_by_key(|access| access.first_seen);
    let mut selected: Vec<RecoveredField> = Vec::new();
    let mut negative = 0usize;
    let mut discarded = 0usize;
    for access in candidates {
        if access.offset < 0 {
            negative += 1;
            continue;
        }
        let end = access.offset.saturating_add(access.byte_width as i64);
        let conflicts = selected
            .iter()
            .enumerate()
            .filter_map(|(index, field)| {
                let field_end = field.offset.saturating_add(field.byte_width as i64);
                (field.offset < end && field_end > access.offset).then_some(index)
            })
            .collect::<Vec<_>>();
        if conflicts
            .iter()
            .any(|index| access.byte_width > selected[*index].byte_width)
        {
            discarded += 1;
            continue;
        }
        discarded += conflicts.len();
        for index in conflicts.into_iter().rev() {
            selected.remove(index);
        }
        selected.push(RecoveredField {
            offset: access.offset,
            byte_width: access.byte_width,
            reads: access.reads,
            writes: access.writes,
            sites: access.sites,
        });
        selected.sort_by_key(|field| field.offset);
    }
    (selected, negative, discarded)
}

fn reconstruct(graph: &MicrocodeFunction, argument_index: usize) -> Result<Reconstruction> {
    if graph.maturity != MicrocodeMaturity::Preoptimized {
        return Err(Error::validation(
            "Symless bounded reconstruction requires preoptimized microcode",
        ));
    }
    let argument = graph.arguments.get(argument_index).ok_or_else(|| {
        Error::validation(format!(
            "argument index {argument_index} is outside 0..{}",
            graph.arguments.len()
        ))
    })?;
    let order = topological_order(graph);
    if order.is_empty() {
        return Err(Error::not_found("microcode graph has no nonempty blocks"));
    }

    let mut initial = State::default();
    inject_argument(&mut initial, &argument.location)?;
    let mut end_states: HashMap<i32, State> = HashMap::new();
    let mut raw_accesses = Vec::new();
    let mut unsupported = 0usize;
    let mut instruction_count = 0usize;
    for (order_index, block_position) in order.iter().copied().enumerate() {
        let block = &graph.blocks[block_position];
        let mut state = if order_index == 0 {
            initial.clone()
        } else {
            select_predecessor_state(block, &end_states)
        };
        for instruction in &block.instructions {
            instruction_count += 1;
            let _ =
                process_instruction(&mut state, instruction, &mut raw_accesses, &mut unsupported);
        }
        end_states.insert(block.index, state);
    }
    let (fields, negative_accesses, conflict_discards) = resolve_field_conflicts(&raw_accesses);
    Ok(Reconstruction {
        function_address: graph.entry_address,
        argument_index,
        argument_name: argument.name.clone(),
        argument_location: argument.location.clone(),
        fields,
        instructions_processed: instruction_count,
        blocks_processed: order.len(),
        unsupported_instructions: unsupported,
        negative_accesses,
        conflict_discards,
    })
}

fn member_type(byte_width: i32) -> Result<TypeInfo> {
    match byte_width {
        1 => Ok(TypeInfo::uint8()),
        2 => Ok(TypeInfo::uint16()),
        4 => Ok(TypeInfo::uint32()),
        8 => Ok(TypeInfo::uint64()),
        width if width > 0 => Ok(TypeInfo::array_of(&TypeInfo::uint8(), width as usize)),
        _ => Err(Error::validation("field width must be positive")),
    }
}

fn ranges_overlap(
    left_offset: usize,
    left_size: usize,
    right_offset: usize,
    right_size: usize,
) -> bool {
    left_offset < right_offset.saturating_add(right_size)
        && right_offset < left_offset.saturating_add(left_size)
}

fn ensure_structure(
    name: &str,
    fields: &[RecoveredField],
    summary: &mut ApplySummary,
) -> Result<TypeInfo> {
    let structure = match TypeInfo::by_name(name) {
        Ok(existing) if existing.is_struct() => existing,
        Ok(_) => return Err(Error::conflict(format!("{name} is not a struct type"))),
        Err(error) if error.category == ErrorCategory::NotFound => {
            summary.structure_created = true;
            TypeInfo::create_struct()
        }
        Err(error) => return Err(error),
    };
    let mut occupied = if summary.structure_created {
        Vec::new()
    } else {
        structure
            .members()?
            .into_iter()
            .map(|member| {
                let width = member
                    .storage_byte_width
                    .max((member.bit_size + 7) / 8)
                    .max(1);
                (member.byte_offset, width)
            })
            .collect::<Vec<_>>()
    };

    for field in fields {
        let offset = field.offset as usize;
        let width = field.byte_width as usize;
        if occupied
            .iter()
            .any(|(member_offset, _)| *member_offset == offset)
        {
            summary.members_reused += 1;
            continue;
        }
        if occupied.iter().any(|(member_offset, member_width)| {
            ranges_overlap(offset, width, *member_offset, *member_width)
        }) {
            summary.members_skipped += 1;
            continue;
        }
        structure.add_member(
            &format!("field_{offset:08x}"),
            &member_type(field.byte_width)?,
            offset,
        )?;
        occupied.push((offset, width));
        summary.members_added += 1;
    }
    if summary.structure_created || summary.members_added > 0 {
        structure.save_as(name)?;
        TypeInfo::by_name(name)
    } else {
        Ok(structure)
    }
}

fn argument_eligibility(
    argument_type: &TypeInfo,
    structure_name: &str,
) -> Result<ArgumentEligibility> {
    if argument_type.is_pointer() {
        let pointee = argument_type.pointee_type()?.resolve_typedef()?;
        if pointee.is_struct() && pointee.name().is_ok_and(|name| name == structure_name) {
            return Ok(ArgumentEligibility::AlreadyTyped);
        }
        if pointee.is_struct() || pointee.is_union() || pointee.is_array() || pointee.is_function()
        {
            return Ok(ArgumentEligibility::Ineligible);
        }
        return Ok(ArgumentEligibility::Eligible);
    }
    let pointer_width = (database::address_bitness()? / 8) as usize;
    let scalar = argument_type.is_integer()
        || argument_type.is_bool()
        || argument_type.is_char()
        || argument_type.is_enum();
    Ok(if scalar && argument_type.size()? == pointer_width {
        ArgumentEligibility::Eligible
    } else {
        ArgumentEligibility::Ineligible
    })
}

fn apply_reconstruction(
    reconstruction: &Reconstruction,
    structure_name: &str,
) -> Result<ApplySummary> {
    if reconstruction.fields.is_empty() {
        return Err(Error::not_found(
            "no nonnegative structure fields were recovered",
        ));
    }
    let original = types::retrieve(reconstruction.function_address)?;
    let details = original.function_details()?;
    let argument = details
        .arguments
        .get(reconstruction.argument_index)
        .ok_or_else(|| Error::validation("function type has fewer arguments than microcode"))?;
    let eligibility = argument_eligibility(&argument.r#type, structure_name)?;
    if eligibility == ArgumentEligibility::Ineligible {
        return Err(Error::validation(
            "selected argument is not a pointer or pointer-width integral scalar",
        ));
    }
    let mut summary = ApplySummary::default();
    if eligibility == ArgumentEligibility::AlreadyTyped {
        summary.argument_already_typed = true;
        return Ok(summary);
    }

    let structure = ensure_structure(structure_name, &reconstruction.fields, &mut summary)?;
    let pointer = TypeInfo::pointer_to(&structure);
    let updated = original.with_function_argument_type(reconstruction.argument_index, &pointer)?;
    updated.apply(reconstruction.function_address)?;
    decompiler::mark_dirty(reconstruction.function_address, false)?;
    summary.argument_changed = true;
    Ok(summary)
}

fn default_structure_name(function_address: Address, argument_index: usize) -> String {
    format!("symless_{function_address:x}_arg{argument_index}")
}

fn print_report(
    options: &Options,
    reconstruction: &Reconstruction,
    structure_name: &str,
    apply_summary: Option<&ApplySummary>,
) {
    println!("Symless bounded structure reconstruction (Rust headless adaptation)");
    println!("input: {}", options.input);
    println!("mode: {}", if options.apply { "apply" } else { "report" });
    println!("function: 0x{:x}", reconstruction.function_address);
    println!("argument_index: {}", reconstruction.argument_index);
    println!("argument_name: {}", reconstruction.argument_name);
    println!(
        "argument_location: {:?}",
        reconstruction.argument_location.kind
    );
    println!("structure_name: {structure_name}");
    println!("blocks_processed: {}", reconstruction.blocks_processed);
    println!(
        "instructions_processed: {}",
        reconstruction.instructions_processed
    );
    println!("fields_recovered: {}", reconstruction.fields.len());
    println!(
        "unsupported_instructions: {}",
        reconstruction.unsupported_instructions
    );
    println!("negative_accesses: {}", reconstruction.negative_accesses);
    println!("conflict_discards: {}", reconstruction.conflict_discards);
    for field in reconstruction.fields.iter().take(options.show) {
        let sites = field
            .sites
            .iter()
            .map(|address| format!("0x{address:x}"))
            .collect::<Vec<_>>()
            .join(",");
        println!(
            "  +0x{:x} width={} B reads={} writes={} sites={}",
            field.offset, field.byte_width, field.reads, field.writes, sites
        );
    }
    if let Some(summary) = apply_summary {
        println!("structure_created: {}", summary.structure_created);
        println!("members_added: {}", summary.members_added);
        println!("members_reused: {}", summary.members_reused);
        println!("members_skipped: {}", summary.members_skipped);
        println!("argument_changed: {}", summary.argument_changed);
        println!("argument_already_typed: {}", summary.argument_already_typed);
    }
}

fn run() -> Result<()> {
    let args = std::env::args().collect::<Vec<_>>();
    let options = parse_options(&args)?;
    let _session = DatabaseSession::open(&options.input, true)?;
    let function_address = resolve_symbol_or_address(&options.function)?;
    let graph = decompiler::generate_microcode(
        function_address,
        MicrocodeGenerationOptions {
            maturity: MicrocodeMaturity::Preoptimized,
        },
    )?;
    let reconstruction = reconstruct(&graph, options.argument_index)?;
    let structure_name = options
        .structure_name
        .clone()
        .unwrap_or_else(|| default_structure_name(function_address, options.argument_index));
    let apply_summary = if options.apply {
        let summary = apply_reconstruction(&reconstruction, &structure_name)?;
        database::save()?;
        Some(summary)
    } else {
        None
    };
    print_report(
        &options,
        &reconstruction,
        &structure_name,
        apply_summary.as_ref(),
    );
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {}", format_error(&error));
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn operand(kind: MicrocodeOperandKind, byte_width: i32) -> MicrocodeOperand {
        MicrocodeOperand {
            kind,
            register_id: 0,
            local_variable_index: 0,
            local_variable_offset: 0,
            second_register_id: 0,
            global_address: BAD_ADDRESS,
            stack_offset: 0,
            helper_name: String::new(),
            block_index: 0,
            nested_instruction: None,
            unsigned_immediate: 0,
            signed_immediate: 0,
            byte_width,
            mark_user_defined_type: false,
            referenced_operand: None,
            call_arguments: Vec::new(),
            call_target: BAD_ADDRESS,
            text: String::new(),
        }
    }

    fn instruction(opcode: MicrocodeOpcode) -> MicrocodeInstruction {
        MicrocodeInstruction {
            opcode,
            left: operand(MicrocodeOperandKind::Empty, 0),
            right: operand(MicrocodeOperandKind::Empty, 0),
            destination: operand(MicrocodeOperandKind::Empty, 0),
            floating_point_instruction: false,
            address: 0x1000,
            text: String::new(),
        }
    }

    #[test]
    fn propagates_pointer_shift_and_recovers_load_store_widths() {
        let mut state = State::default();
        state
            .values
            .insert(Variable::Register(1), AbstractValue::StructurePointer(0));
        let mut add = instruction(MicrocodeOpcode::Add);
        add.left = operand(MicrocodeOperandKind::Register, 8);
        add.left.register_id = 1;
        add.right = operand(MicrocodeOperandKind::UnsignedImmediate, 8);
        add.right.unsigned_immediate = 8;
        add.destination = operand(MicrocodeOperandKind::Register, 8);
        add.destination.register_id = 2;
        let mut store = instruction(MicrocodeOpcode::StoreMemory);
        store.address = 0x1010;
        store.left = operand(MicrocodeOperandKind::UnsignedImmediate, 4);
        store.left.unsigned_immediate = 1;
        store.destination = operand(MicrocodeOperandKind::Register, 8);
        store.destination.register_id = 2;
        let mut accesses = Vec::new();
        let mut unsupported = 0;
        process_instruction(&mut state, &add, &mut accesses, &mut unsupported);
        process_instruction(&mut state, &store, &mut accesses, &mut unsupported);
        assert_eq!(accesses.len(), 1);
        assert_eq!(accesses[0].offset, 8);
        assert_eq!(accesses[0].byte_width, 4);
        assert_eq!(accesses[0].writes, 1);
    }

    #[test]
    fn conflict_policy_keeps_minimum_width() {
        let raw = vec![
            RawAccess {
                offset: 0,
                byte_width: 8,
                reads: 1,
                writes: 0,
                sites: vec![1],
                first_seen: 0,
            },
            RawAccess {
                offset: 4,
                byte_width: 2,
                reads: 1,
                writes: 0,
                sites: vec![2],
                first_seen: 1,
            },
        ];
        let (fields, negative, discarded) = resolve_field_conflicts(&raw);
        assert_eq!(negative, 0);
        assert_eq!(discarded, 1);
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].offset, 4);
        assert_eq!(fields[0].byte_width, 2);
    }

    #[test]
    fn topological_order_prefers_visited_predecessors_in_cycles() {
        let graph = MicrocodeFunction {
            entry_address: 0x1000,
            maturity: MicrocodeMaturity::Preoptimized,
            arguments: Vec::new(),
            return_location: None,
            blocks: vec![
                MicrocodeBlock {
                    index: 0,
                    start_address: 0x1000,
                    end_address: 0x1001,
                    predecessors: Vec::new(),
                    successors: vec![1],
                    instructions: vec![instruction(MicrocodeOpcode::Move)],
                },
                MicrocodeBlock {
                    index: 1,
                    start_address: 0x1001,
                    end_address: 0x1002,
                    predecessors: vec![0, 2],
                    successors: vec![2],
                    instructions: vec![instruction(MicrocodeOpcode::Move)],
                },
                MicrocodeBlock {
                    index: 2,
                    start_address: 0x1002,
                    end_address: 0x1003,
                    predecessors: vec![1],
                    successors: vec![1],
                    instructions: vec![instruction(MicrocodeOpcode::Move)],
                },
            ],
        };
        assert_eq!(topological_order(&graph), vec![0, 1, 2]);
    }
}

#[allow(dead_code)]
mod common;

// Adapted from Symless; upstream copyright/license is retained in
// examples/plugin/symless_port_LICENSE.txt at the repository root.

use common::{DatabaseSession, format_error, print_usage, resolve_symbol_or_address};
use idax::address::{Address, BAD_ADDRESS};
#[cfg(test)]
use idax::decompiler::MicrocodeFunctionArgument;
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
    max_depth: usize,
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
            max_depth: 8,
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
    max_depth: usize,
    functions_processed: usize,
    calls_followed: usize,
    depth_skips: usize,
    cycle_skips: usize,
    repeated_contexts: usize,
    unresolved_calls: usize,
    return_conflicts: usize,
    propagation_sites: Vec<PropagationSite>,
    return_sites: Vec<ReturnSite>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PropagationSite {
    function_address: Address,
    argument_index: usize,
    argument_name: String,
    shift: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ReturnSite {
    function_address: Address,
    shift: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ContextKey {
    function_address: Address,
    injected_arguments: Vec<(usize, i64)>,
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
    arguments_changed: usize,
    arguments_already_typed: usize,
    arguments_skipped_shifted: usize,
    arguments_ineligible: usize,
    returns_changed: usize,
    returns_already_typed: usize,
    returns_skipped_shifted: usize,
    returns_ineligible: usize,
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
                     [--name <type>] [--show <count>] [--max-depth <count>] [--apply]",
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
            "--max-depth" => {
                index += 1;
                options.max_depth = args
                    .get(index)
                    .ok_or_else(|| Error::validation("--max-depth requires a value"))?
                    .parse::<usize>()
                    .map_err(|_| Error::validation("invalid --max-depth value"))?;
                if options.max_depth > 100 {
                    return Err(Error::validation("--max-depth must be in 0..=100"));
                }
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

fn variable_for_location(location: &MicrocodeValueLocation) -> Result<Variable> {
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
    Ok(variable)
}

fn inject_value(
    state: &mut State,
    location: &MicrocodeValueLocation,
    value: AbstractValue,
) -> Result<()> {
    state.values.insert(variable_for_location(location)?, value);
    Ok(())
}

fn value_at_location(state: &State, location: &MicrocodeValueLocation) -> Option<AbstractValue> {
    variable_for_location(location)
        .ok()
        .and_then(|variable| state.values.get(&variable).copied())
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

fn address_from_operand(operand: &MicrocodeOperand) -> Option<Address> {
    match operand.kind {
        MicrocodeOperandKind::GlobalAddress if operand.global_address != BAD_ADDRESS => {
            Some(operand.global_address)
        }
        MicrocodeOperandKind::AddressReference => operand
            .referenced_operand
            .as_deref()
            .and_then(address_from_operand),
        _ => None,
    }
}

fn call_information(instruction: &MicrocodeInstruction) -> Option<&MicrocodeOperand> {
    [
        &instruction.destination,
        &instruction.left,
        &instruction.right,
    ]
    .into_iter()
    .find(|operand| operand.kind == MicrocodeOperandKind::CallArguments)
}

struct InterproceduralAnalyzer<F> {
    loader: F,
    max_depth: usize,
    graph_cache: HashMap<Address, MicrocodeFunction>,
    active_contexts: HashSet<ContextKey>,
    completed_contexts: HashMap<ContextKey, Option<AbstractValue>>,
    raw_accesses: Vec<RawAccess>,
    propagation_sites: Vec<PropagationSite>,
    return_sites: Vec<ReturnSite>,
    functions_processed: usize,
    blocks_processed: usize,
    instructions_processed: usize,
    unsupported_instructions: usize,
    calls_followed: usize,
    depth_skips: usize,
    cycle_skips: usize,
    repeated_contexts: usize,
    unresolved_calls: usize,
    return_conflicts: usize,
}

impl<F> InterproceduralAnalyzer<F>
where
    F: FnMut(Address) -> Result<MicrocodeFunction>,
{
    fn new(max_depth: usize, loader: F) -> Self {
        Self {
            loader,
            max_depth,
            graph_cache: HashMap::new(),
            active_contexts: HashSet::new(),
            completed_contexts: HashMap::new(),
            raw_accesses: Vec::new(),
            propagation_sites: Vec::new(),
            return_sites: Vec::new(),
            functions_processed: 0,
            blocks_processed: 0,
            instructions_processed: 0,
            unsupported_instructions: 0,
            calls_followed: 0,
            depth_skips: 0,
            cycle_skips: 0,
            repeated_contexts: 0,
            unresolved_calls: 0,
            return_conflicts: 0,
        }
    }

    fn context_key(
        function_address: Address,
        injected_arguments: &[(usize, AbstractValue)],
    ) -> ContextKey {
        let mut values = injected_arguments
            .iter()
            .filter_map(|(index, value)| match value {
                AbstractValue::StructurePointer(shift) => Some((*index, *shift)),
                AbstractValue::Integer { .. } => None,
            })
            .collect::<Vec<_>>();
        values.sort_unstable();
        ContextKey {
            function_address,
            injected_arguments: values,
        }
    }

    fn add_propagation_site(
        &mut self,
        graph: &MicrocodeFunction,
        argument_index: usize,
        shift: i64,
    ) {
        let Some(argument) = graph.arguments.get(argument_index) else {
            return;
        };
        let site = PropagationSite {
            function_address: graph.entry_address,
            argument_index,
            argument_name: argument.name.clone(),
            shift,
        };
        if !self.propagation_sites.iter().any(|existing| {
            existing.function_address == site.function_address
                && existing.argument_index == site.argument_index
                && existing.shift == site.shift
        }) {
            self.propagation_sites.push(site);
        }
    }

    fn add_return_site(&mut self, function_address: Address, shift: i64) {
        let site = ReturnSite {
            function_address,
            shift,
        };
        if !self.return_sites.contains(&site) {
            self.return_sites.push(site);
        }
    }

    fn operand_value(
        &mut self,
        state: &mut State,
        operand: &MicrocodeOperand,
        depth: usize,
    ) -> Result<Option<AbstractValue>> {
        if let Some(nested) = operand.nested_instruction.as_deref() {
            return self.process_instruction(state, nested, depth);
        }
        Ok(state.value(operand).or_else(|| immediate_value(operand)))
    }

    fn process_call(
        &mut self,
        state: &mut State,
        instruction: &MicrocodeInstruction,
        depth: usize,
    ) -> Result<Option<AbstractValue>> {
        if instruction.opcode != MicrocodeOpcode::Call {
            self.unresolved_calls += 1;
            return Ok(None);
        }
        let Some(call_info) = call_information(instruction) else {
            self.unresolved_calls += 1;
            return Ok(None);
        };
        let mut injected_arguments = Vec::new();
        for (index, operand) in call_info.call_arguments.iter().enumerate() {
            if let Some(value @ AbstractValue::StructurePointer(_)) =
                self.operand_value(state, operand, depth)?
            {
                injected_arguments.push((index, value));
            }
        }
        if injected_arguments.is_empty() {
            return Ok(None);
        }
        if depth >= self.max_depth {
            self.depth_skips += 1;
            return Ok(None);
        }
        let target = (call_info.call_target != BAD_ADDRESS)
            .then_some(call_info.call_target)
            .or_else(|| address_from_operand(&instruction.left));
        let Some(target) = target else {
            self.unresolved_calls += 1;
            return Ok(None);
        };
        let key = Self::context_key(target, &injected_arguments);
        if self.active_contexts.contains(&key) {
            self.cycle_skips += 1;
            return Ok(None);
        }
        if let Some(result) = self.completed_contexts.get(&key).copied() {
            self.repeated_contexts += 1;
            return Ok(result);
        }
        let callee = if let Some(graph) = self.graph_cache.get(&target) {
            graph.clone()
        } else {
            match (self.loader)(target) {
                Ok(graph) if graph.entry_address == target => {
                    self.graph_cache.insert(target, graph.clone());
                    graph
                }
                Ok(_) | Err(_) => {
                    self.unresolved_calls += 1;
                    return Ok(None);
                }
            }
        };
        self.calls_followed += 1;
        match self.analyze_graph(&callee, &injected_arguments, depth + 1) {
            Ok(result) => Ok(result),
            Err(_) => {
                self.unresolved_calls += 1;
                Ok(None)
            }
        }
    }

    fn process_instruction(
        &mut self,
        state: &mut State,
        instruction: &MicrocodeInstruction,
        depth: usize,
    ) -> Result<Option<AbstractValue>> {
        let result = match instruction.opcode {
            MicrocodeOpcode::Move => {
                let value = self.operand_value(state, &instruction.left, depth)?;
                match value {
                    Some(AbstractValue::Integer { value, .. }) => Some(AbstractValue::Integer {
                        value: signed_to_width(value as i128, instruction.destination.byte_width),
                        byte_width: instruction.destination.byte_width,
                    }),
                    other => other,
                }
            }
            MicrocodeOpcode::ZeroExtend | MicrocodeOpcode::SignedExtend => {
                match self.operand_value(state, &instruction.left, depth)? {
                    Some(AbstractValue::Integer { value, .. }) => Some(AbstractValue::Integer {
                        value,
                        byte_width: instruction.destination.byte_width,
                    }),
                    _ => None,
                }
            }
            MicrocodeOpcode::Add | MicrocodeOpcode::Subtract => {
                let left = self.operand_value(state, &instruction.left, depth)?;
                let right = self.operand_value(state, &instruction.right, depth)?;
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
                let pointer = self.operand_value(state, &instruction.right, depth)?;
                record_access(
                    &mut self.raw_accesses,
                    pointer,
                    instruction.destination.byte_width,
                    instruction.address,
                    false,
                );
                None
            }
            MicrocodeOpcode::StoreMemory => {
                let _ = self.operand_value(state, &instruction.left, depth)?;
                let pointer = self.operand_value(state, &instruction.destination, depth)?;
                record_access(
                    &mut self.raw_accesses,
                    pointer,
                    instruction.left.byte_width,
                    instruction.address,
                    true,
                );
                return Ok(None);
            }
            MicrocodeOpcode::Call | MicrocodeOpcode::IndirectCall => {
                self.process_call(state, instruction, depth)?
            }
            MicrocodeOpcode::Return | MicrocodeOpcode::NoOperation => None,
            _ => {
                self.unsupported_instructions += 1;
                None
            }
        };
        state.assign(&instruction.destination, result);
        Ok(result)
    }

    fn analyze_graph(
        &mut self,
        graph: &MicrocodeFunction,
        injected_arguments: &[(usize, AbstractValue)],
        depth: usize,
    ) -> Result<Option<AbstractValue>> {
        if graph.maturity != MicrocodeMaturity::Preoptimized {
            return Err(Error::validation(
                "Symless interprocedural reconstruction requires preoptimized microcode",
            ));
        }
        let key = Self::context_key(graph.entry_address, injected_arguments);
        if self.active_contexts.contains(&key) {
            self.cycle_skips += 1;
            return Ok(None);
        }
        if let Some(result) = self.completed_contexts.get(&key).copied() {
            self.repeated_contexts += 1;
            return Ok(result);
        }
        let order = topological_order(graph);
        if order.is_empty() {
            return Err(Error::not_found("microcode graph has no nonempty blocks"));
        }

        let mut initial = State::default();
        for (index, value) in injected_arguments {
            let argument = graph.arguments.get(*index).ok_or_else(|| {
                Error::validation(format!(
                    "argument index {index} is outside 0..{} for 0x{:x}",
                    graph.arguments.len(),
                    graph.entry_address
                ))
            })?;
            inject_value(&mut initial, &argument.location, *value)?;
            if let AbstractValue::StructurePointer(shift) = value {
                self.add_propagation_site(graph, *index, *shift);
            }
        }

        self.active_contexts.insert(key.clone());
        self.functions_processed += 1;
        self.blocks_processed += order.len();
        let mut end_states: HashMap<i32, State> = HashMap::new();
        let analysis_result = (|| -> Result<Option<AbstractValue>> {
            for (order_index, block_position) in order.iter().copied().enumerate() {
                let block = &graph.blocks[block_position];
                let mut state = if order_index == 0 {
                    initial.clone()
                } else {
                    select_predecessor_state(block, &end_states)
                };
                for instruction in &block.instructions {
                    self.instructions_processed += 1;
                    let _ = self.process_instruction(&mut state, instruction, depth)?;
                }
                end_states.insert(block.index, state);
            }

            let Some(return_location) = graph.return_location.as_ref() else {
                return Ok(None);
            };
            let active_ids = graph
                .blocks
                .iter()
                .filter(|block| !block.instructions.is_empty())
                .map(|block| block.index)
                .collect::<HashSet<_>>();
            let terminal_ids = graph
                .blocks
                .iter()
                .filter(|block| {
                    active_ids.contains(&block.index)
                        && !block
                            .successors
                            .iter()
                            .any(|successor| active_ids.contains(successor))
                })
                .map(|block| block.index)
                .collect::<Vec<_>>();
            if terminal_ids.is_empty() {
                return Ok(None);
            }
            let mut agreed: Option<AbstractValue> = None;
            let mut saw_non_structure = false;
            for terminal in terminal_ids {
                let value = end_states
                    .get(&terminal)
                    .and_then(|state| value_at_location(state, return_location));
                if let Some(value @ AbstractValue::StructurePointer(_)) = value {
                    if agreed.is_some_and(|existing| existing != value) {
                        self.return_conflicts += 1;
                        return Ok(None);
                    }
                    agreed = Some(value);
                } else {
                    saw_non_structure = true;
                }
            }
            if agreed.is_some() && saw_non_structure {
                self.return_conflicts += 1;
                return Ok(None);
            }
            if let Some(AbstractValue::StructurePointer(shift)) = agreed {
                self.add_return_site(graph.entry_address, shift);
            }
            Ok(agreed)
        })();
        self.active_contexts.remove(&key);
        if let Ok(result) = analysis_result {
            self.completed_contexts.insert(key, result);
        }
        analysis_result
    }
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

fn reconstruct_with_loader<F>(
    graph: &MicrocodeFunction,
    argument_index: usize,
    max_depth: usize,
    loader: F,
) -> Result<Reconstruction>
where
    F: FnMut(Address) -> Result<MicrocodeFunction>,
{
    if graph.maturity != MicrocodeMaturity::Preoptimized {
        return Err(Error::validation(
            "Symless interprocedural reconstruction requires preoptimized microcode",
        ));
    }
    let argument = graph.arguments.get(argument_index).ok_or_else(|| {
        Error::validation(format!(
            "argument index {argument_index} is outside 0..{}",
            graph.arguments.len()
        ))
    })?;
    variable_for_location(&argument.location)?;
    let mut analyzer = InterproceduralAnalyzer::new(max_depth, loader);
    analyzer.analyze_graph(
        graph,
        &[(argument_index, AbstractValue::StructurePointer(0))],
        0,
    )?;
    let (fields, negative_accesses, conflict_discards) =
        resolve_field_conflicts(&analyzer.raw_accesses);
    Ok(Reconstruction {
        function_address: graph.entry_address,
        argument_index,
        argument_name: argument.name.clone(),
        argument_location: argument.location.clone(),
        fields,
        instructions_processed: analyzer.instructions_processed,
        blocks_processed: analyzer.blocks_processed,
        unsupported_instructions: analyzer.unsupported_instructions,
        negative_accesses,
        conflict_discards,
        max_depth,
        functions_processed: analyzer.functions_processed,
        calls_followed: analyzer.calls_followed,
        depth_skips: analyzer.depth_skips,
        cycle_skips: analyzer.cycle_skips,
        repeated_contexts: analyzer.repeated_contexts,
        unresolved_calls: analyzer.unresolved_calls,
        return_conflicts: analyzer.return_conflicts,
        propagation_sites: analyzer.propagation_sites,
        return_sites: analyzer.return_sites,
    })
}

fn reconstruct(
    graph: &MicrocodeFunction,
    argument_index: usize,
    max_depth: usize,
) -> Result<Reconstruction> {
    reconstruct_with_loader(graph, argument_index, max_depth, |address| {
        decompiler::generate_microcode(
            address,
            MicrocodeGenerationOptions {
                maturity: MicrocodeMaturity::Preoptimized,
                analyze_calls: true,
            },
        )
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
    let root_type = types::retrieve(reconstruction.function_address)?;
    let root_details = root_type.function_details()?;
    let root_argument = root_details
        .arguments
        .get(reconstruction.argument_index)
        .ok_or_else(|| Error::validation("function type has fewer arguments than microcode"))?;
    if argument_eligibility(&root_argument.r#type, structure_name)?
        == ArgumentEligibility::Ineligible
    {
        return Err(Error::validation(
            "selected argument is not a pointer or pointer-width integral scalar",
        ));
    }
    let mut summary = ApplySummary::default();
    let structure = ensure_structure(structure_name, &reconstruction.fields, &mut summary)?;
    let pointer = TypeInfo::pointer_to(&structure);

    for site in &reconstruction.propagation_sites {
        let is_root = site.function_address == reconstruction.function_address
            && site.argument_index == reconstruction.argument_index;
        if site.shift != 0 {
            summary.arguments_skipped_shifted += 1;
            continue;
        }
        let original = types::retrieve(site.function_address)?;
        let details = original.function_details()?;
        let Some(argument) = details.arguments.get(site.argument_index) else {
            summary.arguments_ineligible += 1;
            continue;
        };
        match argument_eligibility(&argument.r#type, structure_name)? {
            ArgumentEligibility::Eligible => {
                original
                    .with_function_argument_type(site.argument_index, &pointer)?
                    .apply(site.function_address)?;
                decompiler::mark_dirty(site.function_address, false)?;
                summary.arguments_changed += 1;
                if is_root {
                    summary.argument_changed = true;
                }
            }
            ArgumentEligibility::AlreadyTyped => {
                summary.arguments_already_typed += 1;
                if is_root {
                    summary.argument_already_typed = true;
                }
            }
            ArgumentEligibility::Ineligible => {
                summary.arguments_ineligible += 1;
            }
        }
    }

    for site in &reconstruction.return_sites {
        if site.shift != 0 {
            summary.returns_skipped_shifted += 1;
            continue;
        }
        let original = types::retrieve(site.function_address)?;
        let return_type = original.function_return_type()?;
        match argument_eligibility(&return_type, structure_name)? {
            ArgumentEligibility::Eligible => {
                original
                    .with_function_return_type(&pointer)?
                    .apply(site.function_address)?;
                decompiler::mark_dirty(site.function_address, false)?;
                summary.returns_changed += 1;
            }
            ArgumentEligibility::AlreadyTyped => {
                summary.returns_already_typed += 1;
            }
            ArgumentEligibility::Ineligible => {
                summary.returns_ineligible += 1;
            }
        }
    }
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
    println!("Symless depth-bounded structure reconstruction (Rust headless adaptation)");
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
    println!("max_depth: {}", reconstruction.max_depth);
    println!(
        "functions_processed: {}",
        reconstruction.functions_processed
    );
    println!("calls_followed: {}", reconstruction.calls_followed);
    println!("depth_skips: {}", reconstruction.depth_skips);
    println!("cycle_skips: {}", reconstruction.cycle_skips);
    println!("repeated_contexts: {}", reconstruction.repeated_contexts);
    println!("unresolved_calls: {}", reconstruction.unresolved_calls);
    println!("return_conflicts: {}", reconstruction.return_conflicts);
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
    println!(
        "propagation_sites: {}",
        reconstruction.propagation_sites.len()
    );
    for site in &reconstruction.propagation_sites {
        println!(
            "  argument 0x{:x}[{}] name={} shift={:+#x}",
            site.function_address, site.argument_index, site.argument_name, site.shift
        );
    }
    println!("return_sites: {}", reconstruction.return_sites.len());
    for site in &reconstruction.return_sites {
        println!(
            "  return 0x{:x} shift={:+#x}",
            site.function_address, site.shift
        );
    }
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
        println!("arguments_changed: {}", summary.arguments_changed);
        println!(
            "arguments_already_typed: {}",
            summary.arguments_already_typed
        );
        println!(
            "arguments_skipped_shifted: {}",
            summary.arguments_skipped_shifted
        );
        println!("arguments_ineligible: {}", summary.arguments_ineligible);
        println!("returns_changed: {}", summary.returns_changed);
        println!("returns_already_typed: {}", summary.returns_already_typed);
        println!(
            "returns_skipped_shifted: {}",
            summary.returns_skipped_shifted
        );
        println!("returns_ineligible: {}", summary.returns_ineligible);
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
            analyze_calls: true,
        },
    )?;
    let reconstruction = reconstruct(&graph, options.argument_index, options.max_depth)?;
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
        let mut analyzer =
            InterproceduralAnalyzer::new(0, |_| Err(Error::not_found("test loader is unused")));
        analyzer.process_instruction(&mut state, &add, 0).unwrap();
        analyzer.process_instruction(&mut state, &store, 0).unwrap();
        assert_eq!(analyzer.raw_accesses.len(), 1);
        assert_eq!(analyzer.raw_accesses[0].offset, 8);
        assert_eq!(analyzer.raw_accesses[0].byte_width, 4);
        assert_eq!(analyzer.raw_accesses[0].writes, 1);
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

    fn register_location(register_id: i32) -> MicrocodeValueLocation {
        MicrocodeValueLocation {
            kind: MicrocodeValueLocationKind::Register,
            register_id,
            second_register_id: 0,
            register_offset: 0,
            register_relative_offset: 0,
            stack_offset: 0,
            static_address: BAD_ADDRESS,
            scattered_parts: Vec::new(),
        }
    }

    fn function_argument(name: &str, register_id: i32) -> MicrocodeFunctionArgument {
        MicrocodeFunctionArgument {
            name: name.to_string(),
            location: register_location(register_id),
            byte_width: 8,
        }
    }

    fn one_block_graph(
        address: Address,
        arguments: Vec<MicrocodeFunctionArgument>,
        return_location: Option<MicrocodeValueLocation>,
        instructions: Vec<MicrocodeInstruction>,
    ) -> MicrocodeFunction {
        MicrocodeFunction {
            entry_address: address,
            maturity: MicrocodeMaturity::Preoptimized,
            arguments,
            return_location,
            blocks: vec![MicrocodeBlock {
                index: 0,
                start_address: address,
                end_address: address + 1,
                predecessors: Vec::new(),
                successors: Vec::new(),
                instructions,
            }],
        }
    }

    fn direct_call(target: Address, argument_register: i32) -> MicrocodeInstruction {
        let mut call = instruction(MicrocodeOpcode::Call);
        call.left = operand(MicrocodeOperandKind::GlobalAddress, 8);
        call.left.global_address = target;
        call.destination = operand(MicrocodeOperandKind::CallArguments, 8);
        call.destination.call_target = target;
        let mut argument = operand(MicrocodeOperandKind::Register, 8);
        argument.register_id = argument_register;
        call.destination.call_arguments.push(argument);
        call
    }

    fn branching_return_graph(
        address: Address,
        left: MicrocodeInstruction,
        right: MicrocodeInstruction,
    ) -> MicrocodeFunction {
        MicrocodeFunction {
            entry_address: address,
            maturity: MicrocodeMaturity::Preoptimized,
            arguments: vec![function_argument("argument", 1)],
            return_location: Some(register_location(10)),
            blocks: vec![
                MicrocodeBlock {
                    index: 0,
                    start_address: address,
                    end_address: address + 1,
                    predecessors: Vec::new(),
                    successors: vec![1, 2],
                    instructions: vec![instruction(MicrocodeOpcode::NoOperation)],
                },
                MicrocodeBlock {
                    index: 1,
                    start_address: address + 1,
                    end_address: address + 2,
                    predecessors: vec![0],
                    successors: Vec::new(),
                    instructions: vec![left],
                },
                MicrocodeBlock {
                    index: 2,
                    start_address: address + 2,
                    end_address: address + 3,
                    predecessors: vec![0],
                    successors: Vec::new(),
                    instructions: vec![right],
                },
            ],
        }
    }

    #[test]
    fn follows_direct_callee_arguments_and_agreed_return_values() {
        let mut callee_add = instruction(MicrocodeOpcode::Add);
        callee_add.left = operand(MicrocodeOperandKind::Register, 8);
        callee_add.left.register_id = 5;
        callee_add.right = operand(MicrocodeOperandKind::UnsignedImmediate, 8);
        callee_add.right.unsigned_immediate = 8;
        callee_add.destination = operand(MicrocodeOperandKind::Register, 8);
        callee_add.destination.register_id = 6;
        let mut callee_load = instruction(MicrocodeOpcode::LoadMemory);
        callee_load.address = 0x2010;
        callee_load.right = operand(MicrocodeOperandKind::Register, 8);
        callee_load.right.register_id = 6;
        callee_load.destination = operand(MicrocodeOperandKind::Register, 8);
        callee_load.destination.register_id = 7;
        let mut callee_return = instruction(MicrocodeOpcode::Move);
        callee_return.left = operand(MicrocodeOperandKind::Register, 8);
        callee_return.left.register_id = 5;
        callee_return.destination = operand(MicrocodeOperandKind::Register, 8);
        callee_return.destination.register_id = 10;
        let callee = one_block_graph(
            0x2000,
            vec![function_argument("callee_arg", 5)],
            Some(register_location(10)),
            vec![callee_add, callee_load, callee_return],
        );

        let mut call_operand = operand(MicrocodeOperandKind::NestedInstruction, 8);
        call_operand.nested_instruction = Some(Box::new(direct_call(0x2000, 1)));
        let mut root_move = instruction(MicrocodeOpcode::Move);
        root_move.left = call_operand;
        root_move.destination = operand(MicrocodeOperandKind::Register, 8);
        root_move.destination.register_id = 2;
        let mut root_add = instruction(MicrocodeOpcode::Add);
        root_add.left = operand(MicrocodeOperandKind::Register, 8);
        root_add.left.register_id = 2;
        root_add.right = operand(MicrocodeOperandKind::UnsignedImmediate, 8);
        root_add.right.unsigned_immediate = 24;
        root_add.destination = operand(MicrocodeOperandKind::Register, 8);
        root_add.destination.register_id = 3;
        let mut root_load = instruction(MicrocodeOpcode::LoadMemory);
        root_load.address = 0x1020;
        root_load.right = operand(MicrocodeOperandKind::Register, 8);
        root_load.right.register_id = 3;
        root_load.destination = operand(MicrocodeOperandKind::Register, 1);
        root_load.destination.register_id = 4;
        let root = one_block_graph(
            0x1000,
            vec![function_argument("root_arg", 1)],
            None,
            vec![root_move, root_add, root_load],
        );

        let result = reconstruct_with_loader(&root, 0, 4, |address| {
            if address == callee.entry_address {
                Ok(callee.clone())
            } else {
                Err(Error::not_found("unknown test callee"))
            }
        })
        .unwrap();
        assert_eq!(result.functions_processed, 2);
        assert_eq!(result.calls_followed, 1);
        assert_eq!(result.propagation_sites.len(), 2);
        assert_eq!(
            result.return_sites,
            vec![ReturnSite {
                function_address: 0x2000,
                shift: 0,
            }]
        );
        assert!(
            result
                .fields
                .iter()
                .any(|field| field.offset == 8 && field.byte_width == 8)
        );
        assert!(
            result
                .fields
                .iter()
                .any(|field| field.offset == 24 && field.byte_width == 1)
        );

        let bounded = reconstruct_with_loader(&root, 0, 0, |_| {
            Err(Error::not_found("depth zero must not load callees"))
        })
        .unwrap();
        assert_eq!(bounded.functions_processed, 1);
        assert_eq!(bounded.depth_skips, 1);
        assert!(bounded.fields.is_empty());
    }

    #[test]
    fn rejects_active_recursive_and_reuses_completed_contexts() {
        let root = one_block_graph(
            0x3000,
            vec![function_argument("root_arg", 1)],
            None,
            vec![direct_call(0x3000, 1)],
        );
        let result = reconstruct_with_loader(&root, 0, 8, |_| {
            Err(Error::internal(
                "active recursion must not load the root again",
            ))
        })
        .unwrap();
        assert_eq!(result.functions_processed, 1);
        assert_eq!(result.cycle_skips, 1);
        assert_eq!(result.calls_followed, 0);
        assert_eq!(result.unresolved_calls, 0);

        let callee = one_block_graph(
            0x3100,
            vec![function_argument("callee_arg", 5)],
            None,
            vec![instruction(MicrocodeOpcode::NoOperation)],
        );
        let repeated_root = one_block_graph(
            0x3200,
            vec![function_argument("root_arg", 1)],
            None,
            vec![direct_call(0x3100, 1), direct_call(0x3100, 1)],
        );
        let repeated = reconstruct_with_loader(&repeated_root, 0, 8, |address| {
            if address == callee.entry_address {
                Ok(callee.clone())
            } else {
                Err(Error::not_found("unknown test callee"))
            }
        })
        .unwrap();
        assert_eq!(repeated.functions_processed, 2);
        assert_eq!(repeated.calls_followed, 1);
        assert_eq!(repeated.repeated_contexts, 1);
        assert_eq!(repeated.unresolved_calls, 0);
    }

    #[test]
    fn distinguishes_absent_agreed_and_conflicting_terminal_returns() {
        let mut structure_return = instruction(MicrocodeOpcode::Move);
        structure_return.left = operand(MicrocodeOperandKind::Register, 8);
        structure_return.left.register_id = 1;
        structure_return.destination = operand(MicrocodeOperandKind::Register, 8);
        structure_return.destination.register_id = 10;

        let mut scalar_return = instruction(MicrocodeOpcode::Move);
        scalar_return.left = operand(MicrocodeOperandKind::UnsignedImmediate, 8);
        scalar_return.left.unsigned_immediate = 1;
        scalar_return.destination = operand(MicrocodeOperandKind::Register, 8);
        scalar_return.destination.register_id = 10;

        let agreed =
            branching_return_graph(0x4000, structure_return.clone(), structure_return.clone());
        let agreed_result = reconstruct_with_loader(&agreed, 0, 0, |_| {
            Err(Error::internal("return-consensus graph has no calls"))
        })
        .unwrap();
        assert_eq!(agreed_result.return_conflicts, 0);
        assert_eq!(
            agreed_result.return_sites,
            vec![ReturnSite {
                function_address: 0x4000,
                shift: 0,
            }]
        );

        let absent = branching_return_graph(0x5000, scalar_return.clone(), scalar_return.clone());
        let absent_result = reconstruct_with_loader(&absent, 0, 0, |_| {
            Err(Error::internal("return-consensus graph has no calls"))
        })
        .unwrap();
        assert_eq!(absent_result.return_conflicts, 0);
        assert!(absent_result.return_sites.is_empty());

        let mixed = branching_return_graph(0x6000, structure_return, scalar_return);
        let mixed_result = reconstruct_with_loader(&mixed, 0, 0, |_| {
            Err(Error::internal("return-consensus graph has no calls"))
        })
        .unwrap();
        assert_eq!(mixed_result.return_conflicts, 1);
        assert!(mixed_result.return_sites.is_empty());

        let mut shifted_return = instruction(MicrocodeOpcode::Add);
        shifted_return.left = operand(MicrocodeOperandKind::Register, 8);
        shifted_return.left.register_id = 1;
        shifted_return.right = operand(MicrocodeOperandKind::UnsignedImmediate, 8);
        shifted_return.right.unsigned_immediate = 8;
        shifted_return.destination = operand(MicrocodeOperandKind::Register, 8);
        shifted_return.destination.register_id = 10;
        let differing = branching_return_graph(
            0x7000,
            {
                let mut direct = instruction(MicrocodeOpcode::Move);
                direct.left = operand(MicrocodeOperandKind::Register, 8);
                direct.left.register_id = 1;
                direct.destination = operand(MicrocodeOperandKind::Register, 8);
                direct.destination.register_id = 10;
                direct
            },
            shifted_return,
        );
        let differing_result = reconstruct_with_loader(&differing, 0, 0, |_| {
            Err(Error::internal("return-consensus graph has no calls"))
        })
        .unwrap();
        assert_eq!(differing_result.return_conflicts, 1);
        assert!(differing_result.return_sites.is_empty());
    }
}

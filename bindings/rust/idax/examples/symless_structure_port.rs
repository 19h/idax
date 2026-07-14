#[allow(dead_code)]
mod common;

// Adapted from Symless; upstream copyright/license is retained in
// examples/plugin/symless_port_LICENSE.txt at the repository root.

use common::{DatabaseSession, format_error, print_usage, resolve_symbol_or_address};
use idax::address::{self, Address, BAD_ADDRESS};
#[cfg(test)]
use idax::decompiler::MicrocodeFunctionArgument;
use idax::decompiler::{
    MicrocodeBlock, MicrocodeFunction, MicrocodeGenerationOptions, MicrocodeInstruction,
    MicrocodeMaturity, MicrocodeOpcode, MicrocodeOperand, MicrocodeOperandKind,
    MicrocodeValueLocation, MicrocodeValueLocationKind,
};
use idax::error::ErrorCategory;
use idax::types::TypeInfo;
use idax::{
    Error, Result, data, database, decompiler, function, instruction, segment, types, xref,
};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};

const MAXIMUM_VTABLE_METHODS: usize = 4096;

#[derive(Debug, Clone)]
struct Options {
    input: String,
    function: String,
    allocator_specs: Vec<AllocatorSpec>,
    vtables: bool,
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
            allocator_specs: Vec::new(),
            vtables: false,
            argument_index: 0,
            structure_name: None,
            apply: false,
            show: 40,
            max_depth: 8,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum AllocatorKind {
    Malloc,
    Calloc,
    Realloc,
}

impl AllocatorKind {
    fn parse(value: &str) -> Result<Self> {
        match value {
            "malloc" => Ok(Self::Malloc),
            "calloc" => Ok(Self::Calloc),
            "realloc" => Ok(Self::Realloc),
            _ => Err(Error::validation(format!(
                "unknown allocator kind '{value}'"
            ))),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Malloc => "malloc",
            Self::Calloc => "calloc",
            Self::Realloc => "realloc",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AllocatorSpec {
    locator: String,
    kind: AllocatorKind,
    count_index: Option<usize>,
    size_index: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ResolvedAllocator {
    address: Address,
    kind: AllocatorKind,
    count_index: Option<usize>,
    size_index: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AllocationRoot {
    function_address: Address,
    call_address: Address,
    allocation_size: u64,
    allocator: ResolvedAllocator,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AllocatorWrapper {
    function_address: Address,
    source_call_address: Address,
    allocator: ResolvedAllocator,
}

#[derive(Debug, Default)]
struct AllocatorDiscovery {
    seeds: Vec<ResolvedAllocator>,
    wrappers: Vec<AllocatorWrapper>,
    roots: Vec<AllocationRoot>,
    references_examined: usize,
    non_call_references: usize,
    unresolved_callers: usize,
    unclassified_calls: usize,
    database_resolved_indirect_calls: usize,
    duplicate_heirs: usize,
}

fn parse_allocator_spec(value: &str) -> Result<AllocatorSpec> {
    let parts = value.split(':').collect::<Vec<_>>();
    if parts.len() < 3 || parts.len() > 4 || parts.iter().any(|part| part.is_empty()) {
        return Err(Error::validation(
            "allocator syntax is <kind>:<name-or-address-or-module!prefix>:<size-index> or calloc:<locator>:<count-index>:<size-index>",
        ));
    }
    let kind = AllocatorKind::parse(parts[0])?;
    let parse_index = |text: &str| -> Result<usize> {
        let index = text
            .parse::<usize>()
            .map_err(|_| Error::validation(format!("invalid allocator argument index '{text}'")))?;
        if index > 1024 {
            return Err(Error::validation(
                "allocator argument indexes must be in 0..=1024",
            ));
        }
        Ok(index)
    };
    let (count_index, size_index) = match (kind, parts.len()) {
        (AllocatorKind::Calloc, 4) => (Some(parse_index(parts[2])?), parse_index(parts[3])?),
        (AllocatorKind::Calloc, _) => {
            return Err(Error::validation(
                "calloc allocator syntax requires count and size indexes",
            ));
        }
        (_, 3) => (None, parse_index(parts[2])?),
        (_, _) => {
            return Err(Error::validation(
                "malloc/realloc allocator syntax requires one size index",
            ));
        }
    };
    if count_index == Some(size_index) {
        return Err(Error::validation(
            "calloc count and size indexes must be distinct",
        ));
    }
    Ok(AllocatorSpec {
        locator: parts[1].to_owned(),
        kind,
        count_index,
        size_index,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AbstractValue {
    StructurePointer(i64),
    Integer { value: i64, byte_width: i32 },
    DatabaseValue { value: i64, byte_width: i32 },
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
    operand_sites: Vec<OperandSite>,
    first_seen: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
struct OperandSite {
    address: Address,
    processor_register_id: i32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RecoveredField {
    offset: i64,
    byte_width: i32,
    reads: usize,
    writes: usize,
    sites: Vec<Address>,
    operand_sites: Vec<OperandSite>,
    first_seen: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct OperandObservation {
    offset: i64,
    site: OperandSite,
    first_seen: usize,
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
    database_resolved_indirect_calls: usize,
    depth_skips: usize,
    cycle_skips: usize,
    repeated_contexts: usize,
    unresolved_calls: usize,
    return_conflicts: usize,
    propagation_sites: Vec<PropagationSite>,
    return_sites: Vec<ReturnSite>,
}

#[derive(Debug, Clone)]
struct AllocationReconstruction {
    root: AllocationRoot,
    fields: Vec<RecoveredField>,
    out_of_bounds_fields: usize,
    instructions_processed: usize,
    blocks_processed: usize,
    unsupported_instructions: usize,
    negative_accesses: usize,
    conflict_discards: usize,
    functions_processed: usize,
    calls_followed: usize,
    database_resolved_indirect_calls: usize,
    depth_skips: usize,
    cycle_skips: usize,
    repeated_contexts: usize,
    unresolved_calls: usize,
    return_conflicts: usize,
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
    structure_forward_replaced: bool,
    members_added: usize,
    members_reused: usize,
    members_skipped: usize,
    member_reference_candidates: usize,
    member_references_added: usize,
    member_references_reused: usize,
    member_references_skipped: usize,
    operand_struct_offset_candidates: usize,
    operand_struct_offsets_added: usize,
    operand_struct_offsets_reused: usize,
    operand_struct_offsets_skipped: usize,
    argument_changed: bool,
    argument_already_typed: bool,
    arguments_changed: usize,
    arguments_already_typed: usize,
    arguments_skipped_shifted: usize,
    arguments_shifted_changed: usize,
    arguments_shifted_already_typed: usize,
    arguments_shifted_ineligible: usize,
    arguments_ineligible: usize,
    returns_changed: usize,
    returns_already_typed: usize,
    returns_skipped_shifted: usize,
    returns_ineligible: usize,
}

#[derive(Debug, Default)]
struct AllocatorApplySummary {
    structures_created: usize,
    structures_forward_replaced: usize,
    structures_ineligible: usize,
    members_added: usize,
    members_reused: usize,
    members_skipped: usize,
    member_reference_candidates: usize,
    member_references_added: usize,
    member_references_reused: usize,
    member_references_skipped: usize,
    operand_struct_offset_candidates: usize,
    operand_struct_offsets_added: usize,
    operand_struct_offsets_reused: usize,
    operand_struct_offsets_skipped: usize,
    prototypes_changed: usize,
    prototypes_already_typed: usize,
    prototypes_ineligible: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct VtableMember {
    function_address: Address,
    imported: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct ConstructorStore {
    function_address: Address,
    instruction_address: Address,
    vtable_address: Address,
    object_offset: i64,
}

#[derive(Debug, Clone)]
struct VtableClass {
    vtable_address: Address,
    methods: Vec<VtableMember>,
    constructors: Vec<Address>,
    fields: Vec<RecoveredField>,
}

#[derive(Debug, Default)]
struct VtableDiscovery {
    classes: Vec<VtableClass>,
    secondary_stores: Vec<ConstructorStore>,
    ambiguous_constructors: Vec<Address>,
    candidates_examined: usize,
    candidate_tables: usize,
    all_import_tables: usize,
    referenced_slot_stops: usize,
    tables_without_constructor: usize,
    functions_analyzed: usize,
    functions_without_argument_zero: usize,
    graph_failures: usize,
}

#[derive(Debug, Default)]
struct VtableApplySummary {
    vtable_types_created: usize,
    vtable_types_reused: usize,
    vtable_types_forward_replaced: usize,
    class_types_created: usize,
    class_types_reused: usize,
    class_types_forward_replaced: usize,
    method_members_added: usize,
    method_members_reused: usize,
    class_members_added: usize,
    class_members_reused: usize,
    members_skipped: usize,
    member_reference_candidates: usize,
    member_references_added: usize,
    member_references_reused: usize,
    member_references_skipped: usize,
    operand_struct_offset_candidates: usize,
    operand_struct_offsets_added: usize,
    operand_struct_offsets_reused: usize,
    operand_struct_offsets_skipped: usize,
    prototypes_changed: usize,
    prototypes_already_typed: usize,
    prototypes_ineligible: usize,
    vtables_applied: usize,
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
                    "<binary_file> (--function <address-or-name> | --allocator <spec>... | --vtables) \
                     [--argument <index>] [--name <type-or-prefix>] [--show <count>] \
                     [--max-depth <count>] [--apply]\n\
                     allocator spec: malloc:<locator>:<size-index>, \
                     realloc:<locator>:<size-index>, or \
                     calloc:<locator>:<count-index>:<size-index>; \
                     locator may be a name, address, or module!import-prefix; \
                     --vtables scans for exact argument-zero constructor stores",
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
            "--allocator" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| Error::validation("--allocator requires a value"))?;
                options.allocator_specs.push(parse_allocator_spec(value)?);
            }
            "--vtables" => options.vtables = true,
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
    let selected_modes = usize::from(!options.function.is_empty())
        + usize::from(!options.allocator_specs.is_empty())
        + usize::from(options.vtables);
    if selected_modes != 1 {
        return Err(Error::validation(
            "select exactly one mode: --function, one or more --allocator specifications, or --vtables",
        ));
    }
    Ok(options)
}

fn resolve_allocator_spec(spec: &AllocatorSpec) -> Result<ResolvedAllocator> {
    let address = if let Some((module_name, prefix)) = spec.locator.split_once('!') {
        if module_name.is_empty() || prefix.is_empty() || prefix.contains('!') {
            return Err(Error::validation(format!(
                "invalid module!import-prefix locator '{}'",
                spec.locator
            )));
        }
        let modules = database::import_modules()?;
        let module = modules
            .iter()
            .find(|module| module.name == module_name)
            .ok_or_else(|| Error::not_found(format!("import module '{module_name}' not found")))?;
        let matches = module
            .symbols
            .iter()
            .filter(|symbol| symbol.name.starts_with(prefix))
            .collect::<Vec<_>>();
        if matches.len() != 1 {
            return Err(Error::validation(format!(
                "locator '{}' matched {} imports; exactly one is required",
                spec.locator,
                matches.len()
            )));
        }
        matches[0].address
    } else {
        resolve_symbol_or_address(&spec.locator)?
    };
    Ok(ResolvedAllocator {
        address,
        kind: spec.kind,
        count_index: spec.count_index,
        size_index: spec.size_index,
    })
}

fn resolve_allocator_specs(specs: &[AllocatorSpec]) -> Result<Vec<ResolvedAllocator>> {
    let mut resolved = Vec::<ResolvedAllocator>::new();
    for spec in specs {
        let allocator = resolve_allocator_spec(spec)?;
        if let Some(existing) = resolved
            .iter()
            .find(|existing| existing.address == allocator.address)
        {
            if existing != &allocator {
                return Err(Error::conflict(format!(
                    "allocator target 0x{:x} has conflicting specifications",
                    allocator.address
                )));
            }
            continue;
        }
        resolved.push(allocator);
    }
    Ok(resolved)
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

fn scalar_parts(value: AbstractValue) -> Option<(i64, i32)> {
    match value {
        AbstractValue::Integer { value, byte_width }
        | AbstractValue::DatabaseValue { value, byte_width } => Some((value, byte_width)),
        AbstractValue::StructurePointer(_) => None,
    }
}

fn unsigned_scalar(value: AbstractValue) -> Option<u64> {
    let (value, byte_width) = scalar_parts(value)?;
    let bits = byte_width.clamp(1, 8) as u32 * 8;
    let raw = value as u64;
    Some(if bits == 64 {
        raw
    } else {
        raw & ((1u64 << bits) - 1)
    })
}

fn read_database_value(address: Address, byte_width: i32) -> Result<Option<AbstractValue>> {
    if !address::is_loaded(address) {
        return Ok(None);
    }
    let raw = match byte_width {
        8 => data::read_qword(address)?,
        4 => u64::from(data::read_dword(address)?),
        2 => u64::from(data::read_word(address)?),
        _ => u64::from(data::read_byte(address)?),
    };
    Ok(Some(AbstractValue::DatabaseValue {
        value: signed_to_width(raw as i128, byte_width),
        byte_width,
    }))
}

fn address_of_global_value(operand: &MicrocodeOperand, byte_width: i32) -> Option<AbstractValue> {
    if operand.kind != MicrocodeOperandKind::AddressReference {
        return None;
    }
    let referenced = operand.referenced_operand.as_deref()?;
    if referenced.kind != MicrocodeOperandKind::GlobalAddress
        || referenced.global_address == BAD_ADDRESS
    {
        return None;
    }
    Some(AbstractValue::DatabaseValue {
        value: signed_to_width(referenced.global_address as i128, byte_width),
        byte_width,
    })
}

fn record_access(
    raw_accesses: &mut Vec<RawAccess>,
    pointer: Option<AbstractValue>,
    location: &MicrocodeOperand,
    byte_width: i32,
    address: Address,
    write: bool,
    observation_order: usize,
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
        if address != BAD_ADDRESS
            && location.kind == MicrocodeOperandKind::Register
            && location.processor_register_id >= 0
        {
            let site = OperandSite {
                address,
                processor_register_id: location.processor_register_id,
            };
            if !existing.operand_sites.contains(&site) {
                existing.operand_sites.push(site);
            }
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
        operand_sites: if address != BAD_ADDRESS
            && location.kind == MicrocodeOperandKind::Register
            && location.processor_register_id >= 0
        {
            vec![OperandSite {
                address,
                processor_register_id: location.processor_register_id,
            }]
        } else {
            Vec::new()
        },
        first_seen: observation_order,
    });
}

fn record_operand_observation(
    observations: &mut Vec<OperandObservation>,
    pointer: Option<AbstractValue>,
    location: &MicrocodeOperand,
    address: Address,
    observation_order: usize,
) {
    let Some(AbstractValue::StructurePointer(offset)) = pointer else {
        return;
    };
    if address == BAD_ADDRESS
        || location.kind != MicrocodeOperandKind::Register
        || location.processor_register_id < 0
    {
        return;
    }
    let observation = OperandObservation {
        offset,
        site: OperandSite {
            address,
            processor_register_id: location.processor_register_id,
        },
        first_seen: observation_order,
    };
    if !observations
        .iter()
        .any(|existing| existing.offset == observation.offset && existing.site == observation.site)
    {
        observations.push(observation);
    }
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DiscoveryValue {
    CallerArgument(usize),
    Integer(i64),
    DatabaseValue { value: i64, byte_width: i32 },
    CallOrigin(Address),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum SiteClassification {
    Static(u64),
    Wrapper {
        count_index: Option<usize>,
        size_index: usize,
    },
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum SiteCandidate {
    Static(u64),
    Wrapper {
        count_index: Option<usize>,
        size_index: usize,
    },
}

#[derive(Default)]
struct DiscoveryEvaluation {
    candidate: Option<SiteCandidate>,
    matching_calls: usize,
}

fn discovery_immediate(operand: &MicrocodeOperand) -> Option<DiscoveryValue> {
    match immediate_value(operand) {
        Some(AbstractValue::Integer { value, .. }) => Some(DiscoveryValue::Integer(value)),
        _ => None,
    }
}

fn discovery_database_value(address: Address, byte_width: i32) -> Option<DiscoveryValue> {
    match read_database_value(address, byte_width).ok().flatten()? {
        AbstractValue::DatabaseValue { value, byte_width } => {
            Some(DiscoveryValue::DatabaseValue { value, byte_width })
        }
        _ => None,
    }
}

fn discovery_address_of_global(
    operand: &MicrocodeOperand,
    byte_width: i32,
) -> Option<DiscoveryValue> {
    match address_of_global_value(operand, byte_width)? {
        AbstractValue::DatabaseValue { value, byte_width } => {
            Some(DiscoveryValue::DatabaseValue { value, byte_width })
        }
        _ => None,
    }
}

fn discovery_unsigned_value(value: DiscoveryValue) -> Option<u64> {
    match value {
        DiscoveryValue::DatabaseValue { value, byte_width } => {
            unsigned_scalar(AbstractValue::DatabaseValue { value, byte_width })
        }
        DiscoveryValue::Integer(value) => Some(value as u64),
        DiscoveryValue::CallerArgument(_) | DiscoveryValue::CallOrigin(_) => None,
    }
}

fn valid_allocator_size(value: i64) -> Option<u64> {
    (value > 0 && value < 0x4000).then_some(value as u64)
}

fn classify_call_arguments(
    allocator: &ResolvedAllocator,
    arguments: &[Option<DiscoveryValue>],
) -> Option<SiteCandidate> {
    let size = arguments.get(allocator.size_index)?.as_ref()?;
    match allocator.kind {
        AllocatorKind::Malloc | AllocatorKind::Realloc => match size {
            DiscoveryValue::Integer(value) => {
                valid_allocator_size(*value).map(SiteCandidate::Static)
            }
            DiscoveryValue::CallerArgument(index) => Some(SiteCandidate::Wrapper {
                count_index: None,
                size_index: *index,
            }),
            DiscoveryValue::DatabaseValue { .. } | DiscoveryValue::CallOrigin(_) => None,
        },
        AllocatorKind::Calloc => {
            let count = arguments.get(allocator.count_index?)?.as_ref()?;
            match (count, size) {
                (DiscoveryValue::Integer(count), DiscoveryValue::Integer(size)) => {
                    let count = valid_allocator_size(*count)?;
                    let size = valid_allocator_size(*size)?;
                    count.checked_mul(size).map(SiteCandidate::Static)
                }
                (
                    DiscoveryValue::CallerArgument(count_index),
                    DiscoveryValue::CallerArgument(size_index),
                ) => Some(SiteCandidate::Wrapper {
                    count_index: Some(*count_index),
                    size_index: *size_index,
                }),
                _ => None,
            }
        }
    }
}

fn discovery_operand_value(
    state: &mut HashMap<Variable, DiscoveryValue>,
    operand: &MicrocodeOperand,
    call_address: Address,
    allocator: &ResolvedAllocator,
    evaluation: &mut DiscoveryEvaluation,
) -> Option<DiscoveryValue> {
    if let Some(nested) = operand.nested_instruction.as_deref() {
        return process_discovery_instruction(state, nested, call_address, allocator, evaluation);
    }
    if let Some(address) = discovery_address_of_global(operand, operand.byte_width) {
        return Some(address);
    }
    variable_for_operand(operand)
        .and_then(|variable| state.get(&variable).copied())
        .or_else(|| discovery_immediate(operand))
}

fn process_discovery_instruction(
    state: &mut HashMap<Variable, DiscoveryValue>,
    instruction: &MicrocodeInstruction,
    call_address: Address,
    allocator: &ResolvedAllocator,
    evaluation: &mut DiscoveryEvaluation,
) -> Option<DiscoveryValue> {
    let result = match instruction.opcode {
        MicrocodeOpcode::Move => {
            let value = if instruction.left.kind == MicrocodeOperandKind::GlobalAddress {
                discovery_database_value(
                    instruction.left.global_address,
                    instruction.destination.byte_width,
                )
            } else if let Some(address) =
                discovery_address_of_global(&instruction.left, instruction.destination.byte_width)
            {
                Some(address)
            } else {
                discovery_operand_value(
                    state,
                    &instruction.left,
                    call_address,
                    allocator,
                    evaluation,
                )
            };
            match value {
                Some(DiscoveryValue::Integer(value)) => Some(DiscoveryValue::Integer(
                    signed_to_width(value as i128, instruction.destination.byte_width),
                )),
                Some(DiscoveryValue::DatabaseValue { value, .. }) => {
                    Some(DiscoveryValue::DatabaseValue {
                        value: signed_to_width(value as i128, instruction.destination.byte_width),
                        byte_width: instruction.destination.byte_width,
                    })
                }
                other => other,
            }
        }
        MicrocodeOpcode::ZeroExtend | MicrocodeOpcode::SignedExtend => {
            match discovery_operand_value(
                state,
                &instruction.left,
                call_address,
                allocator,
                evaluation,
            ) {
                Some(DiscoveryValue::Integer(value)) => Some(DiscoveryValue::Integer(
                    signed_to_width(value as i128, instruction.destination.byte_width),
                )),
                Some(value @ DiscoveryValue::DatabaseValue { .. }) => {
                    let raw = if instruction.opcode == MicrocodeOpcode::ZeroExtend {
                        discovery_unsigned_value(value).unwrap_or_default() as i128
                    } else {
                        match value {
                            DiscoveryValue::DatabaseValue { value, .. } => value as i128,
                            _ => unreachable!(),
                        }
                    };
                    Some(DiscoveryValue::DatabaseValue {
                        value: signed_to_width(raw, instruction.destination.byte_width),
                        byte_width: instruction.destination.byte_width,
                    })
                }
                other => other,
            }
        }
        MicrocodeOpcode::Add | MicrocodeOpcode::Subtract => {
            let left = discovery_operand_value(
                state,
                &instruction.left,
                call_address,
                allocator,
                evaluation,
            );
            let right = discovery_operand_value(
                state,
                &instruction.right,
                call_address,
                allocator,
                evaluation,
            );
            match (left, right) {
                (Some(DiscoveryValue::Integer(left)), Some(DiscoveryValue::Integer(right))) => {
                    let result = if instruction.opcode == MicrocodeOpcode::Subtract {
                        left as i128 - right as i128
                    } else {
                        left as i128 + right as i128
                    };
                    Some(DiscoveryValue::Integer(signed_to_width(
                        result,
                        instruction.destination.byte_width,
                    )))
                }
                (
                    Some(DiscoveryValue::DatabaseValue {
                        value: left,
                        byte_width,
                    }),
                    Some(DiscoveryValue::Integer(right)),
                ) => {
                    let result = if instruction.opcode == MicrocodeOpcode::Subtract {
                        left as i128 - right as i128
                    } else {
                        left as i128 + right as i128
                    };
                    Some(DiscoveryValue::DatabaseValue {
                        value: signed_to_width(result, byte_width),
                        byte_width,
                    })
                }
                _ => None,
            }
        }
        MicrocodeOpcode::LoadMemory => {
            match discovery_operand_value(
                state,
                &instruction.right,
                call_address,
                allocator,
                evaluation,
            ) {
                Some(value @ DiscoveryValue::DatabaseValue { .. }) => discovery_database_value(
                    discovery_unsigned_value(value).unwrap_or(BAD_ADDRESS),
                    instruction.destination.byte_width,
                ),
                _ => None,
            }
        }
        MicrocodeOpcode::Call | MicrocodeOpcode::IndirectCall => {
            let call_info = call_information(instruction);
            let target = if instruction.opcode == MicrocodeOpcode::IndirectCall {
                match discovery_operand_value(
                    state,
                    &instruction.right,
                    call_address,
                    allocator,
                    evaluation,
                ) {
                    Some(value @ DiscoveryValue::DatabaseValue { .. }) => {
                        discovery_unsigned_value(value)
                    }
                    _ => None,
                }
            } else {
                call_info
                    .and_then(|info| (info.call_target != BAD_ADDRESS).then_some(info.call_target))
                    .or_else(|| address_from_operand(&instruction.left))
            };
            if instruction.address == call_address && target == Some(allocator.address) {
                evaluation.matching_calls += 1;
                let arguments = call_info
                    .map(|info| {
                        info.call_arguments
                            .iter()
                            .map(|argument| {
                                discovery_operand_value(
                                    state,
                                    argument,
                                    call_address,
                                    allocator,
                                    evaluation,
                                )
                            })
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                let candidate = classify_call_arguments(allocator, &arguments);
                if evaluation.candidate.is_none() {
                    evaluation.candidate = candidate.clone();
                } else if evaluation.candidate != candidate {
                    evaluation.candidate = None;
                }
                match candidate {
                    Some(SiteCandidate::Wrapper { .. }) => {
                        Some(DiscoveryValue::CallOrigin(call_address))
                    }
                    _ => None,
                }
            } else {
                None
            }
        }
        MicrocodeOpcode::StoreMemory => return None,
        _ => None,
    };
    if instruction.opcode != MicrocodeOpcode::StoreMemory {
        if let Some(variable) = variable_for_operand(&instruction.destination) {
            if let Some(value) = result {
                state.insert(variable, value);
            } else {
                state.remove(&variable);
            }
        }
    }
    result
}

fn classify_allocator_site(
    graph: &MicrocodeFunction,
    call_address: Address,
    allocator: &ResolvedAllocator,
) -> Result<SiteClassification> {
    if graph.maturity != MicrocodeMaturity::Preoptimized {
        return Err(Error::validation(
            "allocator discovery requires preoptimized microcode",
        ));
    }
    let order = topological_order(graph);
    if order.is_empty() {
        return Ok(SiteClassification::Unknown);
    }
    let mut initial = HashMap::new();
    for (index, argument) in graph.arguments.iter().enumerate() {
        if let Ok(variable) = variable_for_location(&argument.location) {
            initial.insert(variable, DiscoveryValue::CallerArgument(index));
        }
    }
    let mut evaluation = DiscoveryEvaluation::default();
    let mut end_states: HashMap<i32, HashMap<Variable, DiscoveryValue>> = HashMap::new();
    for (order_index, block_position) in order.iter().copied().enumerate() {
        let block = &graph.blocks[block_position];
        let mut state = if order_index == 0 {
            initial.clone()
        } else {
            block
                .predecessors
                .iter()
                .filter_map(|predecessor| end_states.get(predecessor))
                .max_by_key(|state| state.len())
                .cloned()
                .unwrap_or_default()
        };
        for instruction in &block.instructions {
            let _ = process_discovery_instruction(
                &mut state,
                instruction,
                call_address,
                allocator,
                &mut evaluation,
            );
        }
        end_states.insert(block.index, state);
    }
    if evaluation.matching_calls != 1 {
        return Ok(SiteClassification::Unknown);
    }
    match evaluation.candidate {
        Some(SiteCandidate::Static(size)) => Ok(SiteClassification::Static(size)),
        Some(SiteCandidate::Wrapper {
            count_index,
            size_index,
        }) => {
            let Some(return_location) = graph.return_location.as_ref() else {
                return Ok(SiteClassification::Unknown);
            };
            let active_ids = graph
                .blocks
                .iter()
                .filter(|block| !block.instructions.is_empty())
                .map(|block| block.index)
                .collect::<HashSet<_>>();
            let terminals = graph
                .blocks
                .iter()
                .filter(|block| {
                    active_ids.contains(&block.index)
                        && !block
                            .successors
                            .iter()
                            .any(|successor| active_ids.contains(successor))
                })
                .collect::<Vec<_>>();
            if terminals.is_empty()
                || terminals.iter().any(|block| {
                    end_states.get(&block.index).and_then(|state| {
                        variable_for_location(return_location)
                            .ok()
                            .and_then(|variable| state.get(&variable).copied())
                    }) != Some(DiscoveryValue::CallOrigin(call_address))
                })
            {
                return Ok(SiteClassification::Unknown);
            }
            Ok(SiteClassification::Wrapper {
                count_index,
                size_index,
            })
        }
        None => Ok(SiteClassification::Unknown),
    }
}

fn analyzed_graph(address: Address) -> Result<MicrocodeFunction> {
    decompiler::generate_microcode(
        address,
        MicrocodeGenerationOptions {
            maturity: MicrocodeMaturity::Preoptimized,
            analyze_calls: true,
        },
    )
}

fn collect_indirect_call_addresses(
    instruction: &MicrocodeInstruction,
    addresses: &mut BTreeSet<Address>,
) {
    if instruction.opcode == MicrocodeOpcode::IndirectCall && instruction.address != BAD_ADDRESS {
        addresses.insert(instruction.address);
    }
    for operand in [
        &instruction.left,
        &instruction.right,
        &instruction.destination,
    ] {
        if let Some(nested) = operand.nested_instruction.as_deref() {
            collect_indirect_call_addresses(nested, addresses);
        }
    }
}

fn add_indirect_allocator_sites(
    evidence_address: Address,
    discovery: &mut AllocatorDiscovery,
    graph_cache: &mut HashMap<Address, MicrocodeFunction>,
    candidate_sites: &mut BTreeSet<(Address, Address)>,
    indirect_sites: &mut BTreeSet<(Address, Address)>,
) {
    let caller = match function::at(evidence_address) {
        Ok(function) => function.start(),
        Err(_) => {
            discovery.unresolved_callers += 1;
            return;
        }
    };
    let graph = if let Some(graph) = graph_cache.get(&caller) {
        graph.clone()
    } else {
        match analyzed_graph(caller) {
            Ok(graph) if graph.entry_address == caller => {
                graph_cache.insert(caller, graph.clone());
                graph
            }
            Ok(_) | Err(_) => {
                discovery.unresolved_callers += 1;
                return;
            }
        }
    };
    let mut indirect_calls = BTreeSet::new();
    for instruction in graph
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
    {
        collect_indirect_call_addresses(instruction, &mut indirect_calls);
    }
    for call in indirect_calls {
        candidate_sites.insert((caller, call));
        indirect_sites.insert((caller, call));
    }
}

fn discover_allocators(seeds: Vec<ResolvedAllocator>) -> Result<AllocatorDiscovery> {
    let mut discovery = AllocatorDiscovery {
        seeds: seeds.clone(),
        ..AllocatorDiscovery::default()
    };
    let mut queue = seeds.into_iter().collect::<VecDeque<_>>();
    let mut visited = HashSet::<ResolvedAllocator>::new();
    let mut graph_cache = HashMap::<Address, MicrocodeFunction>::new();
    while let Some(allocator) = queue.pop_front() {
        if !visited.insert(allocator.clone()) {
            discovery.duplicate_heirs += 1;
            continue;
        }
        let mut candidate_sites = BTreeSet::<(Address, Address)>::new();
        let mut indirect_sites = BTreeSet::<(Address, Address)>::new();
        for reference in xref::refs_to(allocator.address)? {
            discovery.references_examined += 1;
            if reference.is_code && xref::is_call(reference.ref_type) {
                match function::at(reference.from) {
                    Ok(function) => {
                        candidate_sites.insert((function.start(), reference.from));
                    }
                    Err(_) => discovery.unresolved_callers += 1,
                }
                continue;
            }

            discovery.non_call_references += 1;
            if reference.is_code {
                add_indirect_allocator_sites(
                    reference.from,
                    &mut discovery,
                    &mut graph_cache,
                    &mut candidate_sites,
                    &mut indirect_sites,
                );
                continue;
            }
            for slot_reference in xref::refs_to(reference.from)? {
                discovery.references_examined += 1;
                if !slot_reference.is_code {
                    discovery.non_call_references += 1;
                    continue;
                }
                add_indirect_allocator_sites(
                    slot_reference.from,
                    &mut discovery,
                    &mut graph_cache,
                    &mut candidate_sites,
                    &mut indirect_sites,
                );
            }
        }

        for (caller, call_address) in candidate_sites {
            let graph = if let Some(graph) = graph_cache.get(&caller) {
                graph.clone()
            } else {
                match analyzed_graph(caller) {
                    Ok(graph) if graph.entry_address == caller => {
                        graph_cache.insert(caller, graph.clone());
                        graph
                    }
                    Ok(_) | Err(_) => {
                        discovery.unresolved_callers += 1;
                        continue;
                    }
                }
            };
            let classification = classify_allocator_site(&graph, call_address, &allocator)?;
            if classification != SiteClassification::Unknown
                && indirect_sites.contains(&(caller, call_address))
            {
                discovery.database_resolved_indirect_calls += 1;
            }
            match classification {
                SiteClassification::Static(allocation_size) => {
                    let root = AllocationRoot {
                        function_address: caller,
                        call_address,
                        allocation_size,
                        allocator: allocator.clone(),
                    };
                    if !discovery.roots.iter().any(|existing| {
                        existing.function_address == root.function_address
                            && existing.call_address == root.call_address
                            && existing.allocation_size == root.allocation_size
                    }) {
                        discovery.roots.push(root);
                    }
                }
                SiteClassification::Wrapper {
                    count_index,
                    size_index,
                } => {
                    let heir = ResolvedAllocator {
                        address: caller,
                        kind: allocator.kind,
                        count_index,
                        size_index,
                    };
                    let wrapper = AllocatorWrapper {
                        function_address: caller,
                        source_call_address: call_address,
                        allocator: heir.clone(),
                    };
                    if !discovery.wrappers.iter().any(|existing| {
                        existing.function_address == wrapper.function_address
                            && existing.allocator == wrapper.allocator
                    }) {
                        discovery.wrappers.push(wrapper);
                    }
                    if visited.contains(&heir) || queue.contains(&heir) {
                        discovery.duplicate_heirs += 1;
                    } else {
                        queue.push_back(heir);
                    }
                }
                SiteClassification::Unknown => discovery.unclassified_calls += 1,
            }
        }
    }
    discovery
        .roots
        .sort_by_key(|root| (root.function_address, root.call_address));
    discovery
        .wrappers
        .sort_by_key(|wrapper| wrapper.function_address);
    Ok(discovery)
}

struct InterproceduralAnalyzer<F> {
    loader: F,
    max_depth: usize,
    allocation_call: Option<Address>,
    graph_cache: HashMap<Address, MicrocodeFunction>,
    active_contexts: HashSet<ContextKey>,
    completed_contexts: HashMap<ContextKey, Option<AbstractValue>>,
    raw_accesses: Vec<RawAccess>,
    operand_observations: Vec<OperandObservation>,
    propagation_sites: Vec<PropagationSite>,
    return_sites: Vec<ReturnSite>,
    functions_processed: usize,
    blocks_processed: usize,
    instructions_processed: usize,
    unsupported_instructions: usize,
    calls_followed: usize,
    database_resolved_indirect_calls: usize,
    depth_skips: usize,
    cycle_skips: usize,
    repeated_contexts: usize,
    unresolved_calls: usize,
    return_conflicts: usize,
    next_observation_order: usize,
}

impl<F> InterproceduralAnalyzer<F>
where
    F: FnMut(Address) -> Result<MicrocodeFunction>,
{
    fn new(max_depth: usize, loader: F) -> Self {
        Self {
            loader,
            max_depth,
            allocation_call: None,
            graph_cache: HashMap::new(),
            active_contexts: HashSet::new(),
            completed_contexts: HashMap::new(),
            raw_accesses: Vec::new(),
            operand_observations: Vec::new(),
            propagation_sites: Vec::new(),
            return_sites: Vec::new(),
            functions_processed: 0,
            blocks_processed: 0,
            instructions_processed: 0,
            unsupported_instructions: 0,
            calls_followed: 0,
            database_resolved_indirect_calls: 0,
            depth_skips: 0,
            cycle_skips: 0,
            repeated_contexts: 0,
            unresolved_calls: 0,
            return_conflicts: 0,
            next_observation_order: 0,
        }
    }

    fn new_for_allocation(max_depth: usize, call_address: Address, loader: F) -> Self {
        let mut analyzer = Self::new(max_depth, loader);
        analyzer.allocation_call = Some(call_address);
        analyzer
    }

    fn context_key(
        function_address: Address,
        injected_arguments: &[(usize, AbstractValue)],
    ) -> ContextKey {
        let mut values = injected_arguments
            .iter()
            .filter_map(|(index, value)| match value {
                AbstractValue::StructurePointer(shift) => Some((*index, *shift)),
                AbstractValue::Integer { .. } | AbstractValue::DatabaseValue { .. } => None,
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
        if let Some(address) = address_of_global_value(operand, operand.byte_width) {
            return Ok(Some(address));
        }
        Ok(state.value(operand).or_else(|| immediate_value(operand)))
    }

    fn process_call(
        &mut self,
        state: &mut State,
        instruction: &MicrocodeInstruction,
        depth: usize,
    ) -> Result<Option<AbstractValue>> {
        if self.allocation_call == Some(instruction.address) {
            return Ok(Some(AbstractValue::StructurePointer(0)));
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
        let database_resolved_indirect = instruction.opcode == MicrocodeOpcode::IndirectCall;
        let target = if database_resolved_indirect {
            match self.operand_value(state, &instruction.right, depth)? {
                Some(value @ AbstractValue::DatabaseValue { .. }) => unsigned_scalar(value),
                _ => None,
            }
        } else {
            (call_info.call_target != BAD_ADDRESS)
                .then_some(call_info.call_target)
                .or_else(|| address_from_operand(&instruction.left))
        };
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
        if database_resolved_indirect {
            self.database_resolved_indirect_calls += 1;
        }
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
                let value = if instruction.left.kind == MicrocodeOperandKind::GlobalAddress {
                    read_database_value(
                        instruction.left.global_address,
                        instruction.destination.byte_width,
                    )?
                } else if let Some(address) =
                    address_of_global_value(&instruction.left, instruction.destination.byte_width)
                {
                    Some(address)
                } else {
                    self.operand_value(state, &instruction.left, depth)?
                };
                match value {
                    Some(AbstractValue::Integer { value, .. }) => Some(AbstractValue::Integer {
                        value: signed_to_width(value as i128, instruction.destination.byte_width),
                        byte_width: instruction.destination.byte_width,
                    }),
                    Some(AbstractValue::DatabaseValue { value, .. }) => {
                        Some(AbstractValue::DatabaseValue {
                            value: signed_to_width(
                                value as i128,
                                instruction.destination.byte_width,
                            ),
                            byte_width: instruction.destination.byte_width,
                        })
                    }
                    other => other,
                }
            }
            MicrocodeOpcode::ZeroExtend | MicrocodeOpcode::SignedExtend => {
                match self.operand_value(state, &instruction.left, depth)? {
                    Some(value @ AbstractValue::Integer { .. })
                    | Some(value @ AbstractValue::DatabaseValue { .. }) => {
                        let database_derived = matches!(value, AbstractValue::DatabaseValue { .. });
                        let raw = if instruction.opcode == MicrocodeOpcode::ZeroExtend {
                            unsigned_scalar(value).unwrap_or_default() as i128
                        } else {
                            scalar_parts(value).map_or(0, |(value, _)| value as i128)
                        };
                        let value = signed_to_width(raw, instruction.destination.byte_width);
                        Some(if database_derived {
                            AbstractValue::DatabaseValue {
                                value,
                                byte_width: instruction.destination.byte_width,
                            }
                        } else {
                            AbstractValue::Integer {
                                value,
                                byte_width: instruction.destination.byte_width,
                            }
                        })
                    }
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
                        let shifted = Some(AbstractValue::StructurePointer(signed_to_width(
                            offset as i128 + delta,
                            byte_width,
                        )));
                        record_operand_observation(
                            &mut self.operand_observations,
                            shifted,
                            &instruction.left,
                            instruction.address,
                            self.next_observation_order,
                        );
                        self.next_observation_order += 1;
                        shifted
                    }
                    (
                        Some(left @ AbstractValue::Integer { .. }),
                        Some(AbstractValue::Integer {
                            value: right,
                            byte_width: _,
                        }),
                    )
                    | (
                        Some(left @ AbstractValue::DatabaseValue { .. }),
                        Some(AbstractValue::Integer {
                            value: right,
                            byte_width: _,
                        }),
                    ) => {
                        let (left_value, left_width) = scalar_parts(left).unwrap_or_default();
                        let computed = if instruction.opcode == MicrocodeOpcode::Subtract {
                            left_value as i128 - right as i128
                        } else {
                            left_value as i128 + right as i128
                        };
                        let value = signed_to_width(computed, left_width);
                        Some(match left {
                            AbstractValue::DatabaseValue { .. } => AbstractValue::DatabaseValue {
                                value,
                                byte_width: left_width,
                            },
                            _ => AbstractValue::Integer {
                                value,
                                byte_width: left_width,
                            },
                        })
                    }
                    _ => None,
                }
            }
            MicrocodeOpcode::LoadMemory => {
                let pointer = self.operand_value(state, &instruction.right, depth)?;
                record_access(
                    &mut self.raw_accesses,
                    pointer,
                    &instruction.right,
                    instruction.destination.byte_width,
                    instruction.address,
                    false,
                    self.next_observation_order,
                );
                self.next_observation_order += 1;
                match pointer {
                    Some(value @ AbstractValue::DatabaseValue { .. }) => read_database_value(
                        unsigned_scalar(value).unwrap_or(BAD_ADDRESS),
                        instruction.destination.byte_width,
                    )?,
                    _ => None,
                }
            }
            MicrocodeOpcode::StoreMemory => {
                let _ = self.operand_value(state, &instruction.left, depth)?;
                let pointer = self.operand_value(state, &instruction.destination, depth)?;
                record_access(
                    &mut self.raw_accesses,
                    pointer,
                    &instruction.destination,
                    instruction.left.byte_width,
                    instruction.address,
                    true,
                    self.next_observation_order,
                );
                self.next_observation_order += 1;
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
            operand_sites: access.operand_sites,
            first_seen: access.first_seen,
        });
        selected.sort_by_key(|field| field.offset);
    }
    (selected, negative, discarded)
}

fn attach_operand_observations(
    fields: &mut [RecoveredField],
    operand_observations: &[OperandObservation],
) {
    let mut observations = operand_observations.to_vec();
    observations.sort_by_key(|observation| observation.first_seen);
    for observation in observations {
        let Some(field) = fields
            .iter_mut()
            .find(|field| field.offset == observation.offset)
        else {
            continue;
        };
        if !field.operand_sites.contains(&observation.site) {
            field.operand_sites.push(observation.site);
        }
        field.first_seen = field.first_seen.min(observation.first_seen);
    }
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
    let (mut fields, negative_accesses, conflict_discards) =
        resolve_field_conflicts(&analyzer.raw_accesses);
    attach_operand_observations(&mut fields, &analyzer.operand_observations);
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
        database_resolved_indirect_calls: analyzer.database_resolved_indirect_calls,
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

fn reconstruct_allocation_with_loader<F>(
    graph: &MicrocodeFunction,
    root: &AllocationRoot,
    max_depth: usize,
    loader: F,
) -> Result<AllocationReconstruction>
where
    F: FnMut(Address) -> Result<MicrocodeFunction>,
{
    if graph.entry_address != root.function_address {
        return Err(Error::validation(
            "allocation root graph does not match its containing function",
        ));
    }
    let mut analyzer =
        InterproceduralAnalyzer::new_for_allocation(max_depth, root.call_address, loader);
    analyzer.analyze_graph(graph, &[], 0)?;
    let (mut resolved, negative_accesses, conflict_discards) =
        resolve_field_conflicts(&analyzer.raw_accesses);
    attach_operand_observations(&mut resolved, &analyzer.operand_observations);
    let (fields, out_of_bounds): (Vec<_>, Vec<_>) = resolved.into_iter().partition(|field| {
        (field.offset as u64)
            .checked_add(field.byte_width as u64)
            .is_some_and(|end| end <= root.allocation_size)
    });
    Ok(AllocationReconstruction {
        root: root.clone(),
        fields,
        out_of_bounds_fields: out_of_bounds.len(),
        instructions_processed: analyzer.instructions_processed,
        blocks_processed: analyzer.blocks_processed,
        unsupported_instructions: analyzer.unsupported_instructions,
        negative_accesses,
        conflict_discards,
        functions_processed: analyzer.functions_processed,
        calls_followed: analyzer.calls_followed,
        database_resolved_indirect_calls: analyzer.database_resolved_indirect_calls,
        depth_skips: analyzer.depth_skips,
        cycle_skips: analyzer.cycle_skips,
        repeated_contexts: analyzer.repeated_contexts,
        unresolved_calls: analyzer.unresolved_calls,
        return_conflicts: analyzer.return_conflicts,
    })
}

fn reconstruct_allocation(
    root: &AllocationRoot,
    max_depth: usize,
) -> Result<AllocationReconstruction> {
    let graph = analyzed_graph(root.function_address)?;
    reconstruct_allocation_with_loader(&graph, root, max_depth, analyzed_graph)
}

fn read_database_pointer(address: Address, pointer_width: usize) -> Result<Address> {
    match pointer_width {
        8 => data::read_qword(address),
        4 => data::read_dword(address).map(u64::from),
        _ => Err(Error::unsupported(
            "vtable discovery requires a 4 B or 8 B address width",
        )),
    }
}

fn vtable_member_at(
    table_address: Address,
    member_address: Address,
    pointer_width: usize,
    discovery: &mut VtableDiscovery,
) -> Result<Option<VtableMember>> {
    if member_address != table_address && !xref::refs_to(member_address)?.is_empty() {
        discovery.referenced_slot_stops += 1;
        return Ok(None);
    }
    let Ok(pointer) = read_database_pointer(member_address, pointer_width) else {
        return Ok(None);
    };
    let target = pointer & !1;
    if function::at(target).is_ok_and(|candidate| candidate.start() == target) {
        return Ok(Some(VtableMember {
            function_address: target,
            imported: false,
        }));
    }
    if !address::is_mapped(target) {
        return Ok(None);
    }
    let Ok(target_segment) = segment::at(target) else {
        return Ok(None);
    };
    let imported = matches!(
        target_segment.seg_type(),
        segment::Type::External | segment::Type::Import
    );
    Ok(imported.then_some(VtableMember {
        function_address: target,
        imported: true,
    }))
}

fn vtable_members_at(
    table_address: Address,
    segment_end: Address,
    pointer_width: usize,
    discovery: &mut VtableDiscovery,
) -> Result<Vec<VtableMember>> {
    let mut members = Vec::new();
    let mut current = table_address;
    while members.len() < MAXIMUM_VTABLE_METHODS
        && current < segment_end
        && pointer_width as u64 <= segment_end - current
    {
        let Some(member) = vtable_member_at(table_address, current, pointer_width, discovery)?
        else {
            break;
        };
        members.push(member);
        current += pointer_width as u64;
    }
    Ok(members)
}

fn next_scannable_head(current: Address, end: Address) -> Result<Address> {
    match address::next_head(current, end) {
        Ok(next) => Ok(next),
        Err(error) if error.category == ErrorCategory::NotFound => Ok(end),
        Err(error) => Err(error),
    }
}

fn scan_vtable_candidates(
    pointer_width: usize,
    discovery: &mut VtableDiscovery,
) -> Result<Vec<VtableClass>> {
    let mut candidates = Vec::new();
    for current_segment in segment::all() {
        if !matches!(
            current_segment.seg_type(),
            segment::Type::Code | segment::Type::Data
        ) {
            continue;
        }
        let mut current = current_segment.start();
        while current < current_segment.end() {
            if let Ok(containing) = function::at(current)
                && let Ok(chunks) = function::chunks(containing.start())
                && let Some(chunk) = chunks
                    .iter()
                    .find(|chunk| current >= chunk.start && current < chunk.end)
            {
                current = chunk.end;
                continue;
            }
            if !address::is_loaded(current) {
                current = next_scannable_head(current, current_segment.end())?;
                continue;
            }
            discovery.candidates_examined += 1;
            let members =
                vtable_members_at(current, current_segment.end(), pointer_width, discovery)?;
            if members.is_empty() {
                current = next_scannable_head(current, current_segment.end())?;
                continue;
            }
            let table_size = (members.len() * pointer_width) as u64;
            if members.iter().all(|member| member.imported) {
                discovery.all_import_tables += 1;
                current += table_size;
                continue;
            }
            discovery.candidate_tables += 1;
            candidates.push(VtableClass {
                vtable_address: current,
                methods: members,
                constructors: Vec::new(),
                fields: Vec::new(),
            });
            current += table_size;
        }
    }
    Ok(candidates)
}

struct ConstructorAnalyzer {
    candidate_tables: BTreeSet<Address>,
    pointer_width: usize,
    stores: Vec<ConstructorStore>,
}

impl ConstructorAnalyzer {
    fn operand_value(
        &mut self,
        state: &mut State,
        operand: &MicrocodeOperand,
    ) -> Result<Option<AbstractValue>> {
        if let Some(nested) = operand.nested_instruction.as_deref() {
            return self.process_instruction(state, nested);
        }
        Ok(state.value(operand).or_else(|| immediate_value(operand)))
    }

    fn process_instruction(
        &mut self,
        state: &mut State,
        instruction: &MicrocodeInstruction,
    ) -> Result<Option<AbstractValue>> {
        let result = match instruction.opcode {
            MicrocodeOpcode::Move | MicrocodeOpcode::ZeroExtend | MicrocodeOpcode::SignedExtend => {
                self.operand_value(state, &instruction.left)?
            }
            MicrocodeOpcode::Add | MicrocodeOpcode::Subtract => {
                let left = self.operand_value(state, &instruction.left)?;
                let right = self.operand_value(state, &instruction.right)?;
                match (left, right) {
                    (
                        Some(AbstractValue::StructurePointer(base)),
                        Some(AbstractValue::Integer { value: delta, .. }),
                    ) => Some(AbstractValue::StructurePointer(
                        if instruction.opcode == MicrocodeOpcode::Subtract {
                            base.wrapping_sub(delta)
                        } else {
                            base.wrapping_add(delta)
                        },
                    )),
                    (
                        Some(AbstractValue::Integer {
                            value: base,
                            byte_width,
                        }),
                        Some(AbstractValue::Integer { value: delta, .. }),
                    ) => Some(AbstractValue::Integer {
                        value: if instruction.opcode == MicrocodeOpcode::Subtract {
                            base.wrapping_sub(delta)
                        } else {
                            base.wrapping_add(delta)
                        },
                        byte_width,
                    }),
                    _ => None,
                }
            }
            MicrocodeOpcode::StoreMemory => {
                let value = self.operand_value(state, &instruction.left)?;
                let destination = self.operand_value(state, &instruction.destination)?;
                if instruction.left.byte_width == self.pointer_width as i32
                    && let Some(AbstractValue::Integer { value, .. }) = value
                    && let Some(AbstractValue::StructurePointer(object_offset)) = destination
                {
                    let table = value as u64;
                    if self.candidate_tables.contains(&table) {
                        let store = ConstructorStore {
                            function_address: BAD_ADDRESS,
                            instruction_address: instruction.address,
                            vtable_address: table,
                            object_offset,
                        };
                        if !self.stores.contains(&store) {
                            self.stores.push(store);
                        }
                    }
                }
                return Ok(None);
            }
            MicrocodeOpcode::Return | MicrocodeOpcode::NoOperation => return Ok(None),
            _ => None,
        };
        state.assign(&instruction.destination, result);
        Ok(result)
    }

    fn analyze(&mut self, graph: &MicrocodeFunction) -> Result<bool> {
        let Some(argument) = graph.arguments.first() else {
            return Ok(false);
        };
        let mut initial = State::default();
        inject_value(
            &mut initial,
            &argument.location,
            AbstractValue::StructurePointer(0),
        )?;
        let order = topological_order(graph);
        if order.is_empty() {
            return Err(Error::not_found("constructor graph has no nonempty blocks"));
        }
        let mut end_states = HashMap::<i32, State>::new();
        for (order_index, block_position) in order.into_iter().enumerate() {
            let block = &graph.blocks[block_position];
            let mut state = if order_index == 0 {
                initial.clone()
            } else {
                select_predecessor_state(block, &end_states)
            };
            for instruction in &block.instructions {
                self.process_instruction(&mut state, instruction)?;
            }
            end_states.insert(block.index, state);
        }
        Ok(true)
    }
}

fn classify_constructor_stores(
    stores: Vec<ConstructorStore>,
    discovery: &mut VtableDiscovery,
) -> HashMap<Address, Vec<Address>> {
    let mut zero_tables_by_function = HashMap::<Address, BTreeSet<Address>>::new();
    for store in stores {
        if store.object_offset == 0 {
            zero_tables_by_function
                .entry(store.function_address)
                .or_default()
                .insert(store.vtable_address);
        } else {
            discovery.secondary_stores.push(store);
        }
    }
    let mut constructors_by_table = HashMap::<Address, Vec<Address>>::new();
    for (function_address, tables) in zero_tables_by_function {
        if tables.len() != 1 {
            discovery.ambiguous_constructors.push(function_address);
            continue;
        }
        constructors_by_table
            .entry(*tables.iter().next().unwrap())
            .or_default()
            .push(function_address);
    }
    constructors_by_table
}

fn append_recovered_fields(
    aggregate: &mut Vec<RawAccess>,
    fields: &[RecoveredField],
    pointer_width: usize,
) {
    for field in fields {
        if field.offset < pointer_width as i64 {
            continue;
        }
        if let Some(existing) = aggregate
            .iter_mut()
            .find(|current| current.offset == field.offset)
        {
            existing.byte_width = existing.byte_width.min(field.byte_width);
            existing.reads += field.reads;
            existing.writes += field.writes;
            for site in &field.sites {
                if !existing.sites.contains(site) {
                    existing.sites.push(*site);
                }
            }
            for site in &field.operand_sites {
                if !existing.operand_sites.contains(site) {
                    existing.operand_sites.push(*site);
                }
            }
        } else {
            aggregate.push(RawAccess {
                offset: field.offset,
                byte_width: field.byte_width,
                reads: field.reads,
                writes: field.writes,
                sites: field.sites.clone(),
                operand_sites: field.operand_sites.clone(),
                first_seen: aggregate.len(),
            });
        }
    }
}

fn discover_vtable_classes(maximum_call_depth: usize) -> Result<VtableDiscovery> {
    let pointer_width = (database::address_bitness()? / 8) as usize;
    let mut discovery = VtableDiscovery::default();
    let mut candidates = scan_vtable_candidates(pointer_width, &mut discovery)?;
    let mut function_candidates = HashMap::<Address, BTreeSet<Address>>::new();
    for candidate in &candidates {
        for reference in xref::data_refs_to(candidate.vtable_address)? {
            if let Ok(containing) = function::at(reference) {
                function_candidates
                    .entry(containing.start())
                    .or_default()
                    .insert(candidate.vtable_address);
            }
        }
    }

    let mut graph_cache = HashMap::<Address, MicrocodeFunction>::new();
    let mut stores = Vec::<ConstructorStore>::new();
    for (function_address, table_addresses) in function_candidates {
        let graph = match analyzed_graph(function_address) {
            Ok(graph) => graph,
            Err(_) => {
                discovery.graph_failures += 1;
                continue;
            }
        };
        graph_cache.insert(function_address, graph.clone());
        let mut analyzer = ConstructorAnalyzer {
            candidate_tables: table_addresses,
            pointer_width,
            stores: Vec::new(),
        };
        match analyzer.analyze(&graph) {
            Ok(true) => discovery.functions_analyzed += 1,
            Ok(false) => {
                discovery.functions_analyzed += 1;
                discovery.functions_without_argument_zero += 1;
                continue;
            }
            Err(_) => {
                discovery.graph_failures += 1;
                continue;
            }
        }
        stores.extend(analyzer.stores.into_iter().map(|mut store| {
            store.function_address = function_address;
            store
        }));
    }

    let mut constructors_by_table = classify_constructor_stores(stores, &mut discovery);
    for mut candidate in candidates.drain(..) {
        let Some(constructors) = constructors_by_table.remove(&candidate.vtable_address) else {
            discovery.tables_without_constructor += 1;
            continue;
        };
        candidate.constructors = constructors;
        let mut aggregate = Vec::<RawAccess>::new();
        for constructor in &candidate.constructors {
            let Some(graph) = graph_cache.get(constructor) else {
                continue;
            };
            match reconstruct(graph, 0, maximum_call_depth) {
                Ok(reconstruction) => {
                    append_recovered_fields(&mut aggregate, &reconstruction.fields, pointer_width)
                }
                Err(_) => discovery.graph_failures += 1,
            }
        }
        candidate.fields = resolve_field_conflicts(&aggregate).0;
        discovery.classes.push(candidate);
    }
    discovery
        .classes
        .sort_by_key(|candidate| candidate.vtable_address);
    discovery.ambiguous_constructors.sort_unstable();
    Ok(discovery)
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
    let mut replacing_forward = false;
    let structure = match TypeInfo::by_name(name) {
        Ok(existing) if existing.is_forward_declaration() => {
            if existing.forward_declaration_kind()? != types::TypeKind::Struct {
                return Err(Error::conflict(format!(
                    "{name} is not a struct forward declaration"
                )));
            }
            replacing_forward = true;
            TypeInfo::create_struct()
        }
        Ok(existing) if existing.is_struct() => existing,
        Ok(_) => return Err(Error::conflict(format!("{name} is not a struct type"))),
        Err(error) if error.category == ErrorCategory::NotFound => {
            summary.structure_created = true;
            TypeInfo::create_struct()
        }
        Err(error) => return Err(error),
    };
    let mut occupied = if summary.structure_created || replacing_forward {
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
    if replacing_forward {
        let replaced = structure.replace_forward_declaration(name)?;
        summary.structure_forward_replaced = true;
        Ok(replaced)
    } else if summary.structure_created || summary.members_added > 0 {
        structure.save_as(name)?;
        TypeInfo::by_name(name)
    } else {
        Ok(structure)
    }
}

fn member_reference_candidate_count(fields: &[RecoveredField]) -> usize {
    fields.iter().map(|field| field.sites.len()).sum()
}

fn ensure_recovered_member_references(
    structure: &TypeInfo,
    fields: &[RecoveredField],
    candidates: &mut usize,
    added: &mut usize,
    reused: &mut usize,
    skipped: &mut usize,
) -> Result<()> {
    let members = structure.members()?;
    for field in fields {
        *candidates += field.sites.len();
        let Ok(offset) = usize::try_from(field.offset) else {
            *skipped += field.sites.len();
            continue;
        };
        if field.byte_width <= 0 {
            *skipped += field.sites.len();
            continue;
        }
        let expected_text = member_type(field.byte_width)?.to_string()?;
        let exact_members = members
            .iter()
            .filter(|member| member.bit_offset % 8 == 0 && member.bit_offset / 8 == offset)
            .collect::<Vec<_>>();
        if exact_members.len() != 1 || exact_members[0].r#type.to_string()? != expected_text {
            *skipped += field.sites.len();
            continue;
        }
        for site in &field.sites {
            if structure.ensure_member_reference(offset, *site)? {
                *added += 1;
            } else {
                *reused += 1;
            }
        }
    }
    Ok(())
}

fn operand_struct_offset_candidates(
    fields: &[RecoveredField],
) -> Vec<(OperandSite, &RecoveredField)> {
    let mut grouped = BTreeMap::<OperandSite, &RecoveredField>::new();
    for field in fields {
        for site in &field.operand_sites {
            match grouped.get(site) {
                Some(existing) if existing.first_seen <= field.first_seen => {}
                _ => {
                    grouped.insert(*site, field);
                }
            }
        }
    }
    grouped.into_iter().collect()
}

fn recovered_field_matches_member(
    members: &[types::Member],
    field: &RecoveredField,
) -> Result<bool> {
    let Ok(offset) = usize::try_from(field.offset) else {
        return Ok(false);
    };
    if field.byte_width <= 0 {
        return Ok(false);
    }
    let expected_text = member_type(field.byte_width)?.to_string()?;
    let exact = members
        .iter()
        .filter(|member| member.bit_offset % 8 == 0 && member.bit_offset / 8 == offset)
        .collect::<Vec<_>>();
    Ok(exact.len() == 1 && exact[0].r#type.to_string()? == expected_text)
}

#[derive(Debug, Clone, Copy)]
struct MachineOperandSelection {
    operand_index: i32,
    encoded_displacement: u64,
    signed_byte_width: i32,
}

fn find_struct_offset_operand(
    decoded: &instruction::Instruction,
    processor_register_id: i32,
) -> Option<MachineOperandSelection> {
    for (index, operand) in decoded.operands().iter().enumerate() {
        if matches!(
            operand.op_type(),
            instruction::OperandType::MemoryPhrase | instruction::OperandType::MemoryDisplacement
        ) && i32::from(operand.register_id()) == processor_register_id
        {
            let encoded_displacement =
                if operand.op_type() == instruction::OperandType::MemoryDisplacement {
                    operand.target_address()
                } else {
                    0
                };
            return Some(MachineOperandSelection {
                operand_index: operand.index(),
                encoded_displacement,
                signed_byte_width: 4,
            });
        }
        if operand.op_type() == instruction::OperandType::Immediate
            && index > 0
            && decoded.operands()[index - 1].op_type() == instruction::OperandType::Register
            && i32::from(decoded.operands()[index - 1].register_id()) == processor_register_id
            && operand.byte_width() > 0
        {
            return Some(MachineOperandSelection {
                operand_index: operand.index(),
                encoded_displacement: operand.value(),
                signed_byte_width: operand.byte_width(),
            });
        }
    }
    None
}

fn ensure_recovered_operand_struct_offsets(
    structure: &TypeInfo,
    structure_name: &str,
    fields: &[RecoveredField],
    candidates: &mut usize,
    added: &mut usize,
    reused: &mut usize,
    skipped: &mut usize,
) -> Result<()> {
    let members = structure.members()?;
    let selected = operand_struct_offset_candidates(fields);
    *candidates += selected.len();
    for (site, field) in selected {
        if !recovered_field_matches_member(&members, field)? {
            *skipped += 1;
            continue;
        }
        let Ok(decoded) = instruction::decode(site.address) else {
            *skipped += 1;
            continue;
        };
        let Some(operand) = find_struct_offset_operand(&decoded, site.processor_register_id) else {
            *skipped += 1;
            continue;
        };
        let delta = signed_to_width(
            field.offset as i128 - operand.encoded_displacement as i128,
            operand.signed_byte_width,
        );
        match instruction::ensure_operand_struct_member_offset(
            site.address,
            operand.operand_index,
            structure_name,
            field.offset as usize,
            delta,
        ) {
            Ok(true) => *added += 1,
            Ok(false) => *reused += 1,
            Err(error) if error.category == ErrorCategory::Conflict => *skipped += 1,
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn argument_eligibility(
    argument_type: &TypeInfo,
    structure_name: &str,
    expected_shift: i64,
) -> Result<ArgumentEligibility> {
    if argument_type.is_pointer() {
        let pointer = argument_type.pointer_details()?;
        let pointee = argument_type.pointee_type()?.resolve_typedef()?;
        if pointee.is_struct() && pointee.name().is_ok_and(|name| name == structure_name) {
            if expected_shift == 0 {
                return Ok(if pointer.is_shifted {
                    ArgumentEligibility::Ineligible
                } else {
                    ArgumentEligibility::AlreadyTyped
                });
            }
            if i32::try_from(expected_shift).is_err()
                || !pointer.is_shifted
                || pointer.shift_delta as i64 != expected_shift
            {
                return Ok(ArgumentEligibility::Ineligible);
            }
            let Some(parent) = pointer.shifted_parent else {
                return Ok(ArgumentEligibility::Ineligible);
            };
            let parent = parent.resolve_typedef()?;
            return Ok(
                if parent.is_struct() && parent.name().is_ok_and(|name| name == structure_name) {
                    ArgumentEligibility::AlreadyTyped
                } else {
                    ArgumentEligibility::Ineligible
                },
            );
        }
        if pointer.is_shifted {
            return Ok(ArgumentEligibility::Ineligible);
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
    if argument_eligibility(&root_argument.r#type, structure_name, 0)?
        == ArgumentEligibility::Ineligible
    {
        return Err(Error::validation(
            "selected argument is not a pointer or pointer-width integral scalar",
        ));
    }
    let mut summary = ApplySummary::default();
    let structure = ensure_structure(structure_name, &reconstruction.fields, &mut summary)?;
    ensure_recovered_member_references(
        &structure,
        &reconstruction.fields,
        &mut summary.member_reference_candidates,
        &mut summary.member_references_added,
        &mut summary.member_references_reused,
        &mut summary.member_references_skipped,
    )?;
    ensure_recovered_operand_struct_offsets(
        &structure,
        structure_name,
        &reconstruction.fields,
        &mut summary.operand_struct_offset_candidates,
        &mut summary.operand_struct_offsets_added,
        &mut summary.operand_struct_offsets_reused,
        &mut summary.operand_struct_offsets_skipped,
    )?;
    let pointer = TypeInfo::pointer_to(&structure);

    for site in &reconstruction.propagation_sites {
        let is_root = site.function_address == reconstruction.function_address
            && site.argument_index == reconstruction.argument_index;
        if i32::try_from(site.shift).is_err() {
            summary.arguments_skipped_shifted += 1;
            continue;
        }
        let site_pointer = if site.shift == 0 {
            pointer.clone()
        } else {
            pointer.with_shifted_parent(&structure, site.shift)?
        };
        let original = types::retrieve(site.function_address)?;
        let details = original.function_details()?;
        let Some(argument) = details.arguments.get(site.argument_index) else {
            summary.arguments_ineligible += 1;
            if site.shift != 0 {
                summary.arguments_shifted_ineligible += 1;
            }
            continue;
        };
        match argument_eligibility(&argument.r#type, structure_name, site.shift)? {
            ArgumentEligibility::Eligible => {
                original
                    .with_function_argument_type(site.argument_index, &site_pointer)?
                    .apply(site.function_address)?;
                decompiler::mark_dirty(site.function_address, false)?;
                summary.arguments_changed += 1;
                if site.shift != 0 {
                    summary.arguments_shifted_changed += 1;
                }
                if is_root {
                    summary.argument_changed = true;
                }
            }
            ArgumentEligibility::AlreadyTyped => {
                summary.arguments_already_typed += 1;
                if site.shift != 0 {
                    summary.arguments_shifted_already_typed += 1;
                }
                if is_root {
                    summary.argument_already_typed = true;
                }
            }
            ArgumentEligibility::Ineligible => {
                summary.arguments_ineligible += 1;
                if site.shift != 0 {
                    summary.arguments_shifted_ineligible += 1;
                }
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
        match argument_eligibility(&return_type, structure_name, 0)? {
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

fn size_type() -> Result<TypeInfo> {
    match TypeInfo::by_name("size_t") {
        Ok(value) => Ok(value),
        Err(error) if error.category == ErrorCategory::NotFound => {
            Ok(if database::address_bitness()? == 64 {
                TypeInfo::uint64()
            } else {
                TypeInfo::uint32()
            })
        }
        Err(error) => Err(error),
    }
}

fn same_type(left: &TypeInfo, right: &TypeInfo) -> Result<bool> {
    Ok(left.to_string()? == right.to_string()?)
}

fn apply_allocator_prototype(
    allocator: &ResolvedAllocator,
    summary: &mut AllocatorApplySummary,
) -> Result<()> {
    let original = types::retrieve(allocator.address)?;
    let details = original.function_details()?;
    let size = size_type()?;
    let generic_return = TypeInfo::pointer_to(&TypeInfo::void_type());
    let mut updated = original.clone();
    let mut changed = false;
    if !same_type(&original.function_return_type()?, &generic_return)? {
        updated = updated.with_function_return_type(&generic_return)?;
        changed = true;
    }
    let roles = match allocator.count_index {
        Some(count_index) => vec![(count_index, "count"), (allocator.size_index, "size")],
        None => vec![(allocator.size_index, "size")],
    };
    for (index, argument_name) in roles {
        let Some(argument) = details.arguments.get(index) else {
            summary.prototypes_ineligible += 1;
            continue;
        };
        if !same_type(&argument.r#type, &size)? {
            updated = updated.with_function_argument_type(index, &size)?;
            changed = true;
        }
        if argument.name != argument_name {
            updated = updated.with_function_argument_name(index, argument_name)?;
            changed = true;
        }
    }
    if changed {
        updated.apply(allocator.address)?;
        decompiler::mark_dirty(allocator.address, false)?;
        summary.prototypes_changed += 1;
    } else {
        summary.prototypes_already_typed += 1;
    }
    Ok(())
}

fn allocation_structure_name(prefix: &str, call_address: Address) -> String {
    format!("{prefix}_{call_address:x}")
}

fn apply_allocator_discovery(
    discovery: &AllocatorDiscovery,
    reconstructions: &[AllocationReconstruction],
    structure_prefix: &str,
) -> Result<AllocatorApplySummary> {
    let mut summary = AllocatorApplySummary::default();
    for reconstruction in reconstructions {
        if reconstruction.fields.is_empty() {
            summary.structures_ineligible += 1;
            continue;
        }
        let mut structure_summary = ApplySummary::default();
        let structure_name =
            allocation_structure_name(structure_prefix, reconstruction.root.call_address);
        let structure = ensure_structure(
            &structure_name,
            &reconstruction.fields,
            &mut structure_summary,
        )?;
        summary.structures_created += usize::from(structure_summary.structure_created);
        summary.structures_forward_replaced +=
            usize::from(structure_summary.structure_forward_replaced);
        summary.members_added += structure_summary.members_added;
        summary.members_reused += structure_summary.members_reused;
        summary.members_skipped += structure_summary.members_skipped;
        ensure_recovered_member_references(
            &structure,
            &reconstruction.fields,
            &mut summary.member_reference_candidates,
            &mut summary.member_references_added,
            &mut summary.member_references_reused,
            &mut summary.member_references_skipped,
        )?;
        ensure_recovered_operand_struct_offsets(
            &structure,
            &structure_name,
            &reconstruction.fields,
            &mut summary.operand_struct_offset_candidates,
            &mut summary.operand_struct_offsets_added,
            &mut summary.operand_struct_offsets_reused,
            &mut summary.operand_struct_offsets_skipped,
        )?;
    }

    let mut allocators = discovery.seeds.clone();
    allocators.extend(
        discovery
            .wrappers
            .iter()
            .map(|wrapper| wrapper.allocator.clone()),
    );
    allocators.sort_by_key(|allocator| allocator.address);
    allocators.dedup();
    for allocator in &allocators {
        if apply_allocator_prototype(allocator, &mut summary).is_err() {
            summary.prototypes_ineligible += 1;
        }
    }
    Ok(summary)
}

fn vtable_type_name(prefix: &str, table_address: Address) -> String {
    format!("{prefix}_vtable_{table_address:x}")
}

fn class_type_name(prefix: &str, table_address: Address) -> String {
    format!("{prefix}_class_{table_address:x}")
}

fn ensure_semantic_struct(
    name: &str,
    is_cpp_object: bool,
    is_vftable: bool,
    created: &mut usize,
    reused: &mut usize,
    forward_replaced: &mut usize,
) -> Result<TypeInfo> {
    let mut replacing_forward = false;
    let structure = match TypeInfo::by_name(name) {
        Ok(existing) if existing.is_forward_declaration() => {
            if existing.forward_declaration_kind()? != types::TypeKind::Struct {
                return Err(Error::conflict(format!(
                    "semantic UDT name '{name}' is occupied by a non-struct forward"
                )));
            }
            replacing_forward = true;
            TypeInfo::create_struct()
        }
        Ok(existing) if existing.is_struct() => {
            *reused += 1;
            return Ok(existing);
        }
        Ok(_) => {
            return Err(Error::conflict(format!(
                "semantic UDT name '{name}' is occupied by a non-struct"
            )));
        }
        Err(error) if error.category == ErrorCategory::NotFound => TypeInfo::create_struct(),
        Err(error) => return Err(error),
    };
    structure.set_udt_semantics(is_cpp_object, is_vftable)?;
    if replacing_forward {
        let replaced = structure.replace_forward_declaration(name)?;
        *forward_replaced += 1;
        return Ok(replaced);
    }
    structure.save_as(name)?;
    *created += 1;
    TypeInfo::by_name(name)
}

fn generic_virtual_method_pointer() -> Result<TypeInfo> {
    let object_pointer = TypeInfo::pointer_to(&TypeInfo::void_type());
    let function = TypeInfo::function_type(
        &TypeInfo::void_type(),
        &[object_pointer],
        types::CallingConvention::Unknown,
        false,
    )?;
    Ok(TypeInfo::pointer_to(&function))
}

fn apply_this_prototype(
    function_address: Address,
    class_pointer: &TypeInfo,
    class_name: &str,
    summary: &mut VtableApplySummary,
) -> Result<()> {
    let original = match types::retrieve(function_address) {
        Ok(original) => original,
        Err(_) => {
            summary.prototypes_ineligible += 1;
            return Ok(());
        }
    };
    let details = match original.function_details() {
        Ok(details) if !details.arguments.is_empty() => details,
        Ok(_) | Err(_) => {
            summary.prototypes_ineligible += 1;
            return Ok(());
        }
    };
    let eligibility = argument_eligibility(&details.arguments[0].r#type, class_name, 0)?;
    if eligibility == ArgumentEligibility::Ineligible {
        summary.prototypes_ineligible += 1;
        return Ok(());
    }
    let mut updated = original.clone();
    let mut changed = false;
    if eligibility == ArgumentEligibility::Eligible {
        updated = updated.with_function_argument_type(0, class_pointer)?;
        changed = true;
    }
    if details.arguments[0].name != "this" {
        updated = updated.with_function_argument_name(0, "this")?;
        changed = true;
    }
    if changed {
        updated.apply(function_address)?;
        decompiler::mark_dirty(function_address, false)?;
        summary.prototypes_changed += 1;
    } else {
        summary.prototypes_already_typed += 1;
    }
    Ok(())
}

fn populate_class_type(
    candidate: &VtableClass,
    class_name: &str,
    vtable_type: &TypeInfo,
    summary: &mut VtableApplySummary,
) -> Result<bool> {
    let class_type = ensure_semantic_struct(
        class_name,
        true,
        false,
        &mut summary.class_types_created,
        &mut summary.class_types_reused,
        &mut summary.class_types_forward_replaced,
    )?;
    let vtable_pointer = TypeInfo::pointer_to(vtable_type);
    let mut occupied = class_type
        .members()?
        .into_iter()
        .map(|member| {
            let width = member
                .storage_byte_width
                .max((member.bit_size + 7) / 8)
                .max(1);
            (member.byte_offset, width, member.r#type)
        })
        .collect::<Vec<_>>();
    let mut has_vtable = false;
    for (offset, _, member_type) in &occupied {
        if *offset != 0 {
            continue;
        }
        if !same_type(member_type, &vtable_pointer)? {
            summary.members_skipped += 1;
            return Ok(false);
        }
        has_vtable = true;
        summary.class_members_reused += 1;
    }
    if !has_vtable {
        class_type.add_member("__vftable", &vtable_pointer, 0)?;
        occupied.push((0, vtable_pointer.size().unwrap_or(1), vtable_pointer));
        summary.class_members_added += 1;
    }
    for field in &candidate.fields {
        let offset = field.offset as usize;
        let width = field.byte_width as usize;
        let field_type = member_type(field.byte_width)?;
        if let Some((_, _, existing_type)) = occupied
            .iter()
            .find(|(member_offset, _, _)| *member_offset == offset)
        {
            if same_type(existing_type, &field_type)? {
                summary.class_members_reused += 1;
            } else {
                summary.members_skipped += 1;
            }
            continue;
        }
        if occupied.iter().any(|(member_offset, member_width, _)| {
            ranges_overlap(offset, width, *member_offset, *member_width)
        }) {
            summary.members_skipped += 1;
            continue;
        }
        class_type.add_member(&format!("field_{offset:08x}"), &field_type, offset)?;
        occupied.push((offset, width, field_type));
        summary.class_members_added += 1;
    }
    class_type.set_udt_semantics(true, false)?;
    class_type.save_as(class_name)?;
    Ok(true)
}

fn method_pointer_type(member: &VtableMember) -> Result<TypeInfo> {
    let Ok(method_type) = types::retrieve(member.function_address) else {
        return generic_virtual_method_pointer();
    };
    if method_type.is_function() {
        return Ok(TypeInfo::pointer_to(&method_type));
    }
    if method_type.is_pointer()
        && method_type
            .pointee_type()
            .is_ok_and(|pointee| pointee.is_function())
    {
        return Ok(method_type);
    }
    generic_virtual_method_pointer()
}

fn vtable_layout_compatible(
    candidate: &VtableClass,
    vtable: &TypeInfo,
    summary: &mut VtableApplySummary,
) -> Result<bool> {
    let pointer_width = (database::address_bitness()? / 8) as usize;
    for member in vtable.members()? {
        if member.byte_offset % pointer_width != 0 {
            summary.members_skipped += 1;
            return Ok(false);
        }
        let index = member.byte_offset / pointer_width;
        let Some(method) = candidate.methods.get(index) else {
            summary.members_skipped += 1;
            return Ok(false);
        };
        if !same_type(&member.r#type, &method_pointer_type(method)?)? {
            summary.members_skipped += 1;
            return Ok(false);
        }
    }
    Ok(true)
}

fn populate_vtable_type(
    candidate: &VtableClass,
    vtable_name: &str,
    summary: &mut VtableApplySummary,
) -> Result<()> {
    let vtable = TypeInfo::by_name(vtable_name)?;
    let pointer_width = (database::address_bitness()? / 8) as usize;
    let mut occupied = vtable
        .members()?
        .into_iter()
        .map(|member| member.byte_offset)
        .collect::<HashSet<_>>();
    for (index, method) in candidate.methods.iter().enumerate() {
        let offset = index * pointer_width;
        if occupied.contains(&offset) {
            summary.method_members_reused += 1;
            continue;
        }
        vtable.add_member(
            &format!("method_{offset:08x}"),
            &method_pointer_type(method)?,
            offset,
        )?;
        occupied.insert(offset);
        summary.method_members_added += 1;
    }
    vtable.set_udt_semantics(false, true)?;
    vtable.save_as(vtable_name)?;
    TypeInfo::by_name(vtable_name)?.apply(candidate.vtable_address)?;
    summary.vtables_applied += 1;
    Ok(())
}

fn apply_vtable_discovery(discovery: &VtableDiscovery, prefix: &str) -> Result<VtableApplySummary> {
    let mut summary = VtableApplySummary::default();
    for candidate in &discovery.classes {
        let vtable_name = vtable_type_name(prefix, candidate.vtable_address);
        let class_name = class_type_name(prefix, candidate.vtable_address);
        let vtable_type = ensure_semantic_struct(
            &vtable_name,
            false,
            true,
            &mut summary.vtable_types_created,
            &mut summary.vtable_types_reused,
            &mut summary.vtable_types_forward_replaced,
        )?;
        if !vtable_layout_compatible(candidate, &vtable_type, &mut summary)? {
            continue;
        }
        if !populate_class_type(candidate, &class_name, &vtable_type, &mut summary)? {
            continue;
        }
        let class_type = TypeInfo::by_name(&class_name)?;
        ensure_recovered_member_references(
            &class_type,
            &candidate.fields,
            &mut summary.member_reference_candidates,
            &mut summary.member_references_added,
            &mut summary.member_references_reused,
            &mut summary.member_references_skipped,
        )?;
        ensure_recovered_operand_struct_offsets(
            &class_type,
            &class_name,
            &candidate.fields,
            &mut summary.operand_struct_offset_candidates,
            &mut summary.operand_struct_offsets_added,
            &mut summary.operand_struct_offsets_reused,
            &mut summary.operand_struct_offsets_skipped,
        )?;
        let class_pointer = TypeInfo::pointer_to(&class_type);
        let mut prototypes = candidate
            .constructors
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        prototypes.extend(
            candidate
                .methods
                .iter()
                .filter(|method| !method.imported)
                .map(|method| method.function_address),
        );
        for function_address in prototypes {
            apply_this_prototype(function_address, &class_pointer, &class_name, &mut summary)?;
        }
        populate_vtable_type(candidate, &vtable_name, &mut summary)?;
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
    println!(
        "database_resolved_indirect_calls: {}",
        reconstruction.database_resolved_indirect_calls
    );
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
    println!(
        "member_reference_candidates: {}",
        member_reference_candidate_count(&reconstruction.fields)
    );
    println!(
        "operand_struct_offset_candidates: {}",
        operand_struct_offset_candidates(&reconstruction.fields).len()
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
        println!(
            "structure_forward_replaced: {}",
            summary.structure_forward_replaced
        );
        println!("members_added: {}", summary.members_added);
        println!("members_reused: {}", summary.members_reused);
        println!("members_skipped: {}", summary.members_skipped);
        println!(
            "member_reference_candidates: {}",
            summary.member_reference_candidates
        );
        println!(
            "member_references_added: {}",
            summary.member_references_added
        );
        println!(
            "member_references_reused: {}",
            summary.member_references_reused
        );
        println!(
            "member_references_skipped: {}",
            summary.member_references_skipped
        );
        println!(
            "operand_struct_offset_candidates: {}",
            summary.operand_struct_offset_candidates
        );
        println!(
            "operand_struct_offsets_added: {}",
            summary.operand_struct_offsets_added
        );
        println!(
            "operand_struct_offsets_reused: {}",
            summary.operand_struct_offsets_reused
        );
        println!(
            "operand_struct_offsets_skipped: {}",
            summary.operand_struct_offsets_skipped
        );
        println!("argument_changed: {}", summary.argument_changed);
        println!("argument_already_typed: {}", summary.argument_already_typed);
        println!("arguments_changed: {}", summary.arguments_changed);
        println!(
            "arguments_already_typed: {}",
            summary.arguments_already_typed
        );
        println!(
            "arguments_shifted_changed: {}",
            summary.arguments_shifted_changed
        );
        println!(
            "arguments_shifted_already_typed: {}",
            summary.arguments_shifted_already_typed
        );
        println!(
            "arguments_shifted_ineligible: {}",
            summary.arguments_shifted_ineligible
        );
        println!(
            "arguments_shifted_unrepresentable: {}",
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

fn print_allocator_report(
    options: &Options,
    discovery: &AllocatorDiscovery,
    reconstructions: &[AllocationReconstruction],
    structure_prefix: &str,
    apply_summary: Option<&AllocatorApplySummary>,
) {
    println!("Symless allocator seed and wrapper discovery (Rust headless adaptation)");
    println!("input: {}", options.input);
    println!("mode: {}", if options.apply { "apply" } else { "report" });
    println!("structure_prefix: {structure_prefix}");
    println!("max_depth: {}", options.max_depth);
    println!("allocator_seeds: {}", discovery.seeds.len());
    println!("allocator_wrappers: {}", discovery.wrappers.len());
    println!("allocation_roots: {}", discovery.roots.len());
    println!("references_examined: {}", discovery.references_examined);
    println!("non_call_references: {}", discovery.non_call_references);
    println!("unresolved_callers: {}", discovery.unresolved_callers);
    println!("unclassified_calls: {}", discovery.unclassified_calls);
    println!(
        "database_resolved_indirect_calls: {}",
        discovery.database_resolved_indirect_calls
    );
    println!("duplicate_heirs: {}", discovery.duplicate_heirs);
    println!(
        "member_reference_candidates: {}",
        reconstructions
            .iter()
            .map(|reconstruction| member_reference_candidate_count(&reconstruction.fields))
            .sum::<usize>()
    );
    println!(
        "operand_struct_offset_candidates: {}",
        reconstructions
            .iter()
            .map(|reconstruction| {
                operand_struct_offset_candidates(&reconstruction.fields).len()
            })
            .sum::<usize>()
    );
    for wrapper in &discovery.wrappers {
        println!(
            "  wrapper function=0x{:x} source_call=0x{:x} kind={} count_index={} size_index={}",
            wrapper.function_address,
            wrapper.source_call_address,
            wrapper.allocator.kind.as_str(),
            wrapper
                .allocator
                .count_index
                .map(|index| index.to_string())
                .unwrap_or_else(|| "none".to_owned()),
            wrapper.allocator.size_index
        );
    }
    for reconstruction in reconstructions {
        println!(
            "  allocation_root function=0x{:x} call=0x{:x} size={} B kind={} fields={} out_of_bounds={}",
            reconstruction.root.function_address,
            reconstruction.root.call_address,
            reconstruction.root.allocation_size,
            reconstruction.root.allocator.kind.as_str(),
            reconstruction.fields.len(),
            reconstruction.out_of_bounds_fields
        );
        println!(
            "    evidence functions={} calls={} indirect={} blocks={} instructions={} unsupported={} negative={} conflicts={} depth_skips={} cycle_skips={} repeated={} unresolved={} return_conflicts={}",
            reconstruction.functions_processed,
            reconstruction.calls_followed,
            reconstruction.database_resolved_indirect_calls,
            reconstruction.blocks_processed,
            reconstruction.instructions_processed,
            reconstruction.unsupported_instructions,
            reconstruction.negative_accesses,
            reconstruction.conflict_discards,
            reconstruction.depth_skips,
            reconstruction.cycle_skips,
            reconstruction.repeated_contexts,
            reconstruction.unresolved_calls,
            reconstruction.return_conflicts
        );
        for field in reconstruction.fields.iter().take(options.show) {
            println!(
                "    +0x{:x} width={} B reads={} writes={}",
                field.offset, field.byte_width, field.reads, field.writes
            );
        }
    }
    if let Some(summary) = apply_summary {
        println!("structures_created: {}", summary.structures_created);
        println!(
            "structures_forward_replaced: {}",
            summary.structures_forward_replaced
        );
        println!("structures_ineligible: {}", summary.structures_ineligible);
        println!("members_added: {}", summary.members_added);
        println!("members_reused: {}", summary.members_reused);
        println!("members_skipped: {}", summary.members_skipped);
        println!(
            "member_reference_candidates: {}",
            summary.member_reference_candidates
        );
        println!(
            "member_references_added: {}",
            summary.member_references_added
        );
        println!(
            "member_references_reused: {}",
            summary.member_references_reused
        );
        println!(
            "member_references_skipped: {}",
            summary.member_references_skipped
        );
        println!(
            "operand_struct_offset_candidates: {}",
            summary.operand_struct_offset_candidates
        );
        println!(
            "operand_struct_offsets_added: {}",
            summary.operand_struct_offsets_added
        );
        println!(
            "operand_struct_offsets_reused: {}",
            summary.operand_struct_offsets_reused
        );
        println!(
            "operand_struct_offsets_skipped: {}",
            summary.operand_struct_offsets_skipped
        );
        println!("prototypes_changed: {}", summary.prototypes_changed);
        println!(
            "prototypes_already_typed: {}",
            summary.prototypes_already_typed
        );
        println!("prototypes_ineligible: {}", summary.prototypes_ineligible);
    }
}

fn print_vtable_report(
    options: &Options,
    discovery: &VtableDiscovery,
    prefix: &str,
    apply_summary: Option<&VtableApplySummary>,
) {
    println!("Symless constructor and vtable root discovery (Rust headless adaptation)");
    println!("input: {}", options.input);
    println!("mode: {}", if options.apply { "apply" } else { "report" });
    println!("type_prefix: {prefix}");
    println!("max_depth: {}", options.max_depth);
    println!("scan_heads_examined: {}", discovery.candidates_examined);
    println!("candidate_tables: {}", discovery.candidate_tables);
    println!("accepted_class_roots: {}", discovery.classes.len());
    println!("all_import_tables: {}", discovery.all_import_tables);
    println!("referenced_slot_stops: {}", discovery.referenced_slot_stops);
    println!(
        "tables_without_constructor: {}",
        discovery.tables_without_constructor
    );
    println!("functions_analyzed: {}", discovery.functions_analyzed);
    println!(
        "functions_without_argument_zero: {}",
        discovery.functions_without_argument_zero
    );
    println!("graph_failures: {}", discovery.graph_failures);
    println!(
        "ambiguous_constructors: {}",
        discovery.ambiguous_constructors.len()
    );
    println!("secondary_stores: {}", discovery.secondary_stores.len());
    println!(
        "member_reference_candidates: {}",
        discovery
            .classes
            .iter()
            .map(|candidate| member_reference_candidate_count(&candidate.fields))
            .sum::<usize>()
    );
    println!(
        "operand_struct_offset_candidates: {}",
        discovery
            .classes
            .iter()
            .map(|candidate| operand_struct_offset_candidates(&candidate.fields).len())
            .sum::<usize>()
    );
    for candidate in &discovery.classes {
        println!(
            "  class vtable=0x{:x} methods={} constructors={} fields={} class_type={} vtable_type={}",
            candidate.vtable_address,
            candidate.methods.len(),
            candidate.constructors.len(),
            candidate.fields.len(),
            class_type_name(prefix, candidate.vtable_address),
            vtable_type_name(prefix, candidate.vtable_address)
        );
        for constructor in &candidate.constructors {
            println!("    constructor 0x{constructor:x} argument=0 offset=0");
        }
        for (index, method) in candidate.methods.iter().take(options.show).enumerate() {
            println!(
                "    method[{index}] 0x{:x} imported={}",
                method.function_address, method.imported
            );
        }
        for field in candidate.fields.iter().take(options.show) {
            println!(
                "    +0x{:x} width={} B reads={} writes={}",
                field.offset, field.byte_width, field.reads, field.writes
            );
        }
    }
    for function_address in &discovery.ambiguous_constructors {
        println!("  ambiguous_constructor 0x{function_address:x}");
    }
    for store in &discovery.secondary_stores {
        println!(
            "  secondary function=0x{:x} site=0x{:x} vtable=0x{:x} offset={:+#x}",
            store.function_address,
            store.instruction_address,
            store.vtable_address,
            store.object_offset
        );
    }
    if let Some(summary) = apply_summary {
        println!("vtable_types_created: {}", summary.vtable_types_created);
        println!("vtable_types_reused: {}", summary.vtable_types_reused);
        println!(
            "vtable_types_forward_replaced: {}",
            summary.vtable_types_forward_replaced
        );
        println!("class_types_created: {}", summary.class_types_created);
        println!("class_types_reused: {}", summary.class_types_reused);
        println!(
            "class_types_forward_replaced: {}",
            summary.class_types_forward_replaced
        );
        println!("method_members_added: {}", summary.method_members_added);
        println!("method_members_reused: {}", summary.method_members_reused);
        println!("class_members_added: {}", summary.class_members_added);
        println!("class_members_reused: {}", summary.class_members_reused);
        println!("members_skipped: {}", summary.members_skipped);
        println!(
            "member_reference_candidates: {}",
            summary.member_reference_candidates
        );
        println!(
            "member_references_added: {}",
            summary.member_references_added
        );
        println!(
            "member_references_reused: {}",
            summary.member_references_reused
        );
        println!(
            "member_references_skipped: {}",
            summary.member_references_skipped
        );
        println!(
            "operand_struct_offset_candidates: {}",
            summary.operand_struct_offset_candidates
        );
        println!(
            "operand_struct_offsets_added: {}",
            summary.operand_struct_offsets_added
        );
        println!(
            "operand_struct_offsets_reused: {}",
            summary.operand_struct_offsets_reused
        );
        println!(
            "operand_struct_offsets_skipped: {}",
            summary.operand_struct_offsets_skipped
        );
        println!("prototypes_changed: {}", summary.prototypes_changed);
        println!(
            "prototypes_already_typed: {}",
            summary.prototypes_already_typed
        );
        println!("prototypes_ineligible: {}", summary.prototypes_ineligible);
        println!("vtables_applied: {}", summary.vtables_applied);
    }
}

fn run() -> Result<()> {
    let args = std::env::args().collect::<Vec<_>>();
    let options = parse_options(&args)?;
    let _session = DatabaseSession::open(&options.input, true)?;
    if options.vtables {
        let discovery = discover_vtable_classes(options.max_depth)?;
        let prefix = options
            .structure_name
            .clone()
            .unwrap_or_else(|| "symless".to_owned());
        if prefix.is_empty() {
            return Err(Error::validation(
                "class/vtable type prefix must not be empty",
            ));
        }
        let apply_summary = if options.apply {
            let summary = apply_vtable_discovery(&discovery, &prefix)?;
            database::save()?;
            Some(summary)
        } else {
            None
        };
        print_vtable_report(&options, &discovery, &prefix, apply_summary.as_ref());
        return Ok(());
    }
    if !options.allocator_specs.is_empty() {
        let seeds = resolve_allocator_specs(&options.allocator_specs)?;
        let discovery = discover_allocators(seeds)?;
        let reconstructions = discovery
            .roots
            .iter()
            .map(|root| reconstruct_allocation(root, options.max_depth))
            .collect::<Result<Vec<_>>>()?;
        let structure_prefix = options
            .structure_name
            .clone()
            .unwrap_or_else(|| "symless_alloc".to_owned());
        if structure_prefix.is_empty() {
            return Err(Error::validation("structure prefix must not be empty"));
        }
        let apply_summary = if options.apply {
            let summary =
                apply_allocator_discovery(&discovery, &reconstructions, &structure_prefix)?;
            database::save()?;
            Some(summary)
        } else {
            None
        };
        print_allocator_report(
            &options,
            &discovery,
            &reconstructions,
            &structure_prefix,
            apply_summary.as_ref(),
        );
        return Ok(());
    }
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
            processor_register_id: -1,
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

    fn constructor_graph(with_argument_zero: bool) -> MicrocodeFunction {
        let mut shift = instruction(MicrocodeOpcode::Add);
        shift.address = 0x1004;
        shift.left = operand(MicrocodeOperandKind::Register, 8);
        shift.left.register_id = 1;
        shift.right = operand(MicrocodeOperandKind::UnsignedImmediate, 8);
        shift.right.unsigned_immediate = 16;
        shift.destination = operand(MicrocodeOperandKind::Register, 8);
        shift.destination.register_id = 2;

        let mut root_store = instruction(MicrocodeOpcode::StoreMemory);
        root_store.address = 0x1008;
        root_store.left = operand(MicrocodeOperandKind::GlobalAddress, 8);
        root_store.left.global_address = 0x4000;
        root_store.destination = operand(MicrocodeOperandKind::Register, 8);
        root_store.destination.register_id = 1;

        let mut secondary_store = root_store.clone();
        secondary_store.address = 0x100c;
        secondary_store.destination.register_id = 2;

        MicrocodeFunction {
            entry_address: 0x1000,
            maturity: MicrocodeMaturity::Preoptimized,
            arguments: if with_argument_zero {
                vec![MicrocodeFunctionArgument {
                    name: "object".to_owned(),
                    location: MicrocodeValueLocation {
                        kind: MicrocodeValueLocationKind::Register,
                        register_id: 1,
                        second_register_id: 0,
                        register_offset: 0,
                        register_relative_offset: 0,
                        stack_offset: 0,
                        static_address: BAD_ADDRESS,
                        scattered_parts: Vec::new(),
                    },
                    byte_width: 8,
                }]
            } else {
                Vec::new()
            },
            return_location: None,
            blocks: vec![MicrocodeBlock {
                index: 0,
                start_address: 0x1000,
                end_address: 0x1010,
                predecessors: Vec::new(),
                successors: Vec::new(),
                instructions: vec![shift, root_store, secondary_store],
            }],
        }
    }

    #[test]
    fn constructor_analyzer_requires_argument_zero_and_records_exact_offsets() {
        let mut analyzer = ConstructorAnalyzer {
            candidate_tables: BTreeSet::from([0x4000]),
            pointer_width: 8,
            stores: Vec::new(),
        };
        assert!(analyzer.analyze(&constructor_graph(true)).unwrap());
        assert_eq!(analyzer.stores.len(), 2);
        assert_eq!(analyzer.stores[0].vtable_address, 0x4000);
        assert_eq!(analyzer.stores[0].object_offset, 0);
        assert_eq!(analyzer.stores[1].object_offset, 16);

        let mut without_argument = ConstructorAnalyzer {
            candidate_tables: BTreeSet::from([0x4000]),
            pointer_width: 8,
            stores: Vec::new(),
        };
        assert!(!without_argument.analyze(&constructor_graph(false)).unwrap());
        assert!(without_argument.stores.is_empty());
    }

    #[test]
    fn constructor_store_classification_rejects_ambiguous_roots_and_reports_secondary() {
        let stores = vec![
            ConstructorStore {
                function_address: 0x1000,
                instruction_address: 0x1004,
                vtable_address: 0x4000,
                object_offset: 0,
            },
            ConstructorStore {
                function_address: 0x1000,
                instruction_address: 0x1008,
                vtable_address: 0x5000,
                object_offset: 0,
            },
            ConstructorStore {
                function_address: 0x2000,
                instruction_address: 0x2004,
                vtable_address: 0x6000,
                object_offset: 0,
            },
            ConstructorStore {
                function_address: 0x2000,
                instruction_address: 0x2008,
                vtable_address: 0x7000,
                object_offset: 16,
            },
        ];
        let mut discovery = VtableDiscovery::default();
        let constructors = classify_constructor_stores(stores, &mut discovery);
        assert_eq!(discovery.ambiguous_constructors, vec![0x1000]);
        assert_eq!(discovery.secondary_stores.len(), 1);
        assert_eq!(discovery.secondary_stores[0].object_offset, 16);
        assert_eq!(constructors.get(&0x6000), Some(&vec![0x2000]));
        assert!(!constructors.contains_key(&0x4000));
        assert!(!constructors.contains_key(&0x5000));
    }

    #[test]
    fn propagates_pointer_shift_and_recovers_load_store_widths() {
        let mut state = State::default();
        state
            .values
            .insert(Variable::Register(1), AbstractValue::StructurePointer(0));
        let mut add = instruction(MicrocodeOpcode::Add);
        add.address = 0x1010;
        add.left = operand(MicrocodeOperandKind::Register, 8);
        add.left.register_id = 1;
        add.left.processor_register_id = 7;
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
        assert!(analyzer.raw_accesses[0].operand_sites.is_empty());
        assert_eq!(
            analyzer.operand_observations,
            vec![OperandObservation {
                offset: 8,
                site: OperandSite {
                    address: 0x1010,
                    processor_register_id: 7,
                },
                first_seen: 0,
            }]
        );
        let (mut fields, negative, discarded) = resolve_field_conflicts(&analyzer.raw_accesses);
        assert_eq!((negative, discarded), (0, 0));
        attach_operand_observations(&mut fields, &analyzer.operand_observations);
        assert_eq!(
            fields[0].operand_sites,
            vec![OperandSite {
                address: 0x1010,
                processor_register_id: 7,
            }]
        );
        assert_eq!(fields[0].first_seen, 0);
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
                operand_sites: Vec::new(),
                first_seen: 0,
            },
            RawAccess {
                offset: 4,
                byte_width: 2,
                reads: 1,
                writes: 0,
                sites: vec![2],
                operand_sites: Vec::new(),
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
    fn counts_member_reference_candidates_across_recovered_fields() {
        let fields = vec![
            RecoveredField {
                offset: 0,
                byte_width: 4,
                reads: 1,
                writes: 0,
                sites: vec![0x1000, 0x1004],
                operand_sites: Vec::new(),
                first_seen: 0,
            },
            RecoveredField {
                offset: 8,
                byte_width: 8,
                reads: 0,
                writes: 1,
                sites: vec![0x1010],
                operand_sites: Vec::new(),
                first_seen: 1,
            },
        ];
        assert_eq!(member_reference_candidate_count(&fields), 3);
    }

    #[test]
    fn groups_operand_struct_offsets_by_site_and_preserves_first_observation() {
        let shared = OperandSite {
            address: 0x1000,
            processor_register_id: 7,
        };
        let distinct_register = OperandSite {
            address: 0x1000,
            processor_register_id: 8,
        };
        let fields = vec![
            RecoveredField {
                offset: 4,
                byte_width: 4,
                reads: 1,
                writes: 0,
                sites: vec![0x1000],
                operand_sites: vec![shared],
                first_seen: 2,
            },
            RecoveredField {
                offset: 8,
                byte_width: 8,
                reads: 1,
                writes: 0,
                sites: vec![0x1000],
                operand_sites: vec![shared, distinct_register],
                first_seen: 1,
            },
        ];
        let selected = operand_struct_offset_candidates(&fields);
        assert_eq!(selected.len(), 2);
        assert_eq!(selected[0].0, shared);
        assert_eq!(selected[0].1.offset, 8);
        assert_eq!(selected[1].0, distinct_register);
        assert_eq!(selected[1].1.offset, 8);
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

    fn address_of_global_operand(target: Address) -> MicrocodeOperand {
        let mut global = operand(MicrocodeOperandKind::GlobalAddress, 8);
        global.global_address = target;
        let mut reference = operand(MicrocodeOperandKind::AddressReference, 8);
        reference.referenced_operand = Some(Box::new(global));
        reference
    }

    fn indirect_call(
        target_hint: Address,
        call_address: Address,
        target_register: i32,
        arguments: Vec<MicrocodeOperand>,
    ) -> MicrocodeInstruction {
        let mut call = instruction(MicrocodeOpcode::IndirectCall);
        call.address = call_address;
        call.right = operand(MicrocodeOperandKind::Register, 8);
        call.right.register_id = target_register;
        call.destination = operand(MicrocodeOperandKind::CallArguments, 8);
        call.destination.call_target = target_hint;
        call.destination.call_arguments = arguments;
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
    fn follows_only_database_derived_indirect_targets() {
        let mut callee_add = instruction(MicrocodeOpcode::Add);
        callee_add.left = register_operand(5);
        callee_add.right = immediate_operand(12);
        callee_add.destination = register_operand(6);
        let mut callee_load = instruction(MicrocodeOpcode::LoadMemory);
        callee_load.address = 0x2110;
        callee_load.right = register_operand(6);
        callee_load.destination = operand(MicrocodeOperandKind::Register, 4);
        callee_load.destination.register_id = 7;
        let callee = one_block_graph(
            0x2100,
            vec![function_argument("callee_arg", 5)],
            None,
            vec![callee_add, callee_load],
        );

        let mut database_target = instruction(MicrocodeOpcode::Move);
        database_target.left = address_of_global_operand(callee.entry_address);
        database_target.destination = register_operand(2);
        let accepted_root = one_block_graph(
            0x1100,
            vec![function_argument("root_arg", 1)],
            None,
            vec![
                database_target,
                indirect_call(BAD_ADDRESS, 0x1110, 2, vec![register_operand(1)]),
            ],
        );
        let accepted = reconstruct_with_loader(&accepted_root, 0, 4, |address| {
            if address == callee.entry_address {
                Ok(callee.clone())
            } else {
                Err(Error::not_found("unknown indirect test callee"))
            }
        })
        .unwrap();
        assert_eq!(accepted.calls_followed, 1);
        assert_eq!(accepted.database_resolved_indirect_calls, 1);
        assert_eq!(accepted.unresolved_calls, 0);
        assert!(
            accepted
                .fields
                .iter()
                .any(|field| field.offset == 12 && field.byte_width == 4)
        );

        let mut immediate_target = instruction(MicrocodeOpcode::Move);
        immediate_target.left = immediate_operand(callee.entry_address);
        immediate_target.destination = register_operand(2);
        let rejected_root = one_block_graph(
            0x1200,
            vec![function_argument("root_arg", 1)],
            None,
            vec![
                immediate_target,
                indirect_call(callee.entry_address, 0x1210, 2, vec![register_operand(1)]),
            ],
        );
        let rejected = reconstruct_with_loader(&rejected_root, 0, 4, |_| {
            Err(Error::internal(
                "plain immediate and call-info hint must not invoke the loader",
            ))
        })
        .unwrap();
        assert_eq!(rejected.calls_followed, 0);
        assert_eq!(rejected.database_resolved_indirect_calls, 0);
        assert_eq!(rejected.unresolved_calls, 1);
        assert!(rejected.fields.is_empty());
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

    fn allocator(
        address: Address,
        kind: AllocatorKind,
        count_index: Option<usize>,
        size_index: usize,
    ) -> ResolvedAllocator {
        ResolvedAllocator {
            address,
            kind,
            count_index,
            size_index,
        }
    }

    fn allocator_call(
        target: Address,
        call_address: Address,
        arguments: Vec<MicrocodeOperand>,
    ) -> MicrocodeInstruction {
        let mut call = instruction(MicrocodeOpcode::Call);
        call.address = call_address;
        call.left = operand(MicrocodeOperandKind::GlobalAddress, 8);
        call.left.global_address = target;
        call.destination = operand(MicrocodeOperandKind::CallArguments, 8);
        call.destination.call_target = target;
        call.destination.call_arguments = arguments;
        call
    }

    fn register_operand(register_id: i32) -> MicrocodeOperand {
        let mut value = operand(MicrocodeOperandKind::Register, 8);
        value.register_id = register_id;
        value
    }

    fn immediate_operand(value: u64) -> MicrocodeOperand {
        let mut operand = operand(MicrocodeOperandKind::UnsignedImmediate, 8);
        operand.unsigned_immediate = value;
        operand
    }

    fn move_nested_call(call: MicrocodeInstruction, destination: i32) -> MicrocodeInstruction {
        let mut nested = operand(MicrocodeOperandKind::NestedInstruction, 8);
        nested.nested_instruction = Some(Box::new(call));
        let mut move_result = instruction(MicrocodeOpcode::Move);
        move_result.left = nested;
        move_result.destination = register_operand(destination);
        move_result
    }

    #[test]
    fn parses_bounded_allocator_specs() {
        assert_eq!(
            parse_allocator_spec("malloc:_malloc:0").unwrap(),
            AllocatorSpec {
                locator: "_malloc".to_owned(),
                kind: AllocatorKind::Malloc,
                count_index: None,
                size_index: 0,
            }
        );
        assert_eq!(
            parse_allocator_spec("calloc:libSystem!_calloc:0:1").unwrap(),
            AllocatorSpec {
                locator: "libSystem!_calloc".to_owned(),
                kind: AllocatorKind::Calloc,
                count_index: Some(0),
                size_index: 1,
            }
        );
        assert!(parse_allocator_spec("calloc:_calloc:0:0").is_err());
        assert!(parse_allocator_spec("malloc:_malloc:1025").is_err());
        assert!(parse_allocator_spec("operator:new:0").is_err());
    }

    #[test]
    fn classifies_static_malloc_and_calloc_sizes_with_bounds() {
        let malloc = allocator(0x9000, AllocatorKind::Malloc, None, 0);
        let malloc_graph = one_block_graph(
            0x8000,
            Vec::new(),
            None,
            vec![allocator_call(0x9000, 0x8010, vec![immediate_operand(32)])],
        );
        assert_eq!(
            classify_allocator_site(&malloc_graph, 0x8010, &malloc).unwrap(),
            SiteClassification::Static(32)
        );
        let invalid_graph = one_block_graph(
            0x8100,
            Vec::new(),
            None,
            vec![allocator_call(
                0x9000,
                0x8110,
                vec![immediate_operand(0x4000)],
            )],
        );
        assert_eq!(
            classify_allocator_site(&invalid_graph, 0x8110, &malloc).unwrap(),
            SiteClassification::Unknown
        );

        let mut database_target = instruction(MicrocodeOpcode::Move);
        database_target.left = address_of_global_operand(malloc.address);
        database_target.destination = register_operand(2);
        let indirect_graph = one_block_graph(
            0x8150,
            Vec::new(),
            None,
            vec![
                database_target,
                indirect_call(BAD_ADDRESS, 0x8160, 2, vec![immediate_operand(48)]),
            ],
        );
        assert_eq!(
            classify_allocator_site(&indirect_graph, 0x8160, &malloc).unwrap(),
            SiteClassification::Static(48)
        );

        let mut immediate_target = instruction(MicrocodeOpcode::Move);
        immediate_target.left = immediate_operand(malloc.address);
        immediate_target.destination = register_operand(2);
        let rejected_indirect = one_block_graph(
            0x8170,
            Vec::new(),
            None,
            vec![
                immediate_target,
                indirect_call(malloc.address, 0x8180, 2, vec![immediate_operand(48)]),
            ],
        );
        assert_eq!(
            classify_allocator_site(&rejected_indirect, 0x8180, &malloc).unwrap(),
            SiteClassification::Unknown
        );

        let calloc = allocator(0x9100, AllocatorKind::Calloc, Some(0), 1);
        let calloc_graph = one_block_graph(
            0x8200,
            Vec::new(),
            None,
            vec![allocator_call(
                0x9100,
                0x8210,
                vec![immediate_operand(4), immediate_operand(24)],
            )],
        );
        assert_eq!(
            classify_allocator_site(&calloc_graph, 0x8210, &calloc).unwrap(),
            SiteClassification::Static(96)
        );
    }

    #[test]
    fn confirms_only_terminally_returned_forwarding_wrappers() {
        let malloc = allocator(0x9000, AllocatorKind::Malloc, None, 0);
        let wrapper = one_block_graph(
            0x8300,
            vec![function_argument("requested", 1)],
            Some(register_location(10)),
            vec![move_nested_call(
                allocator_call(0x9000, 0x8310, vec![register_operand(1)]),
                10,
            )],
        );
        assert_eq!(
            classify_allocator_site(&wrapper, 0x8310, &malloc).unwrap(),
            SiteClassification::Wrapper {
                count_index: None,
                size_index: 0,
            }
        );

        let mut scalar_return = instruction(MicrocodeOpcode::Move);
        scalar_return.left = immediate_operand(1);
        scalar_return.destination = register_operand(10);
        let rejected = one_block_graph(
            0x8400,
            vec![function_argument("requested", 1)],
            Some(register_location(10)),
            vec![
                move_nested_call(allocator_call(0x9000, 0x8410, vec![register_operand(1)]), 2),
                scalar_return,
            ],
        );
        assert_eq!(
            classify_allocator_site(&rejected, 0x8410, &malloc).unwrap(),
            SiteClassification::Unknown
        );
    }

    #[test]
    fn reconstructs_allocation_result_and_rejects_extent_overruns() {
        let root = AllocationRoot {
            function_address: 0x8500,
            call_address: 0x8510,
            allocation_size: 32,
            allocator: allocator(0x9000, AllocatorKind::Malloc, None, 0),
        };
        let allocation = move_nested_call(
            allocator_call(0x9000, root.call_address, vec![immediate_operand(32)]),
            2,
        );
        let mut in_bounds_add = instruction(MicrocodeOpcode::Add);
        in_bounds_add.left = register_operand(2);
        in_bounds_add.right = immediate_operand(4);
        in_bounds_add.destination = register_operand(3);
        let mut in_bounds_load = instruction(MicrocodeOpcode::LoadMemory);
        in_bounds_load.right = register_operand(3);
        in_bounds_load.destination = operand(MicrocodeOperandKind::Register, 4);
        in_bounds_load.destination.register_id = 4;
        let mut overrun_add = instruction(MicrocodeOpcode::Add);
        overrun_add.left = register_operand(2);
        overrun_add.right = immediate_operand(31);
        overrun_add.destination = register_operand(5);
        let mut overrun_load = instruction(MicrocodeOpcode::LoadMemory);
        overrun_load.right = register_operand(5);
        overrun_load.destination = operand(MicrocodeOperandKind::Register, 4);
        overrun_load.destination.register_id = 6;
        let graph = one_block_graph(
            root.function_address,
            Vec::new(),
            None,
            vec![
                allocation,
                in_bounds_add,
                in_bounds_load,
                overrun_add,
                overrun_load,
            ],
        );
        let reconstruction = reconstruct_allocation_with_loader(&graph, &root, 0, |_| {
            Err(Error::internal("allocation unit graph has no callees"))
        })
        .unwrap();
        assert_eq!(reconstruction.fields.len(), 1);
        assert_eq!(reconstruction.fields[0].offset, 4);
        assert_eq!(reconstruction.fields[0].byte_width, 4);
        assert_eq!(reconstruction.out_of_bounds_fields, 1);
    }
}

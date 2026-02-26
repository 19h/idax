//! Instruction decode, operand access, and text rendering.
//!
//! Mirrors the C++ `ida::instruction` namespace.

use crate::address::{Address, AddressDelta, AddressSize};
use crate::error::{self, Error, Result, Status};
use std::ffi::CString;
use std::mem::MaybeUninit;

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

/// Operand type classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum OperandType {
    None = 0,
    Register = 1,
    MemoryDirect = 2,
    MemoryPhrase = 3,
    MemoryDisplacement = 4,
    Immediate = 5,
    FarAddress = 6,
    NearAddress = 7,
    ProcessorSpecific0 = 8,
    ProcessorSpecific1 = 9,
    ProcessorSpecific2 = 10,
    ProcessorSpecific3 = 11,
    ProcessorSpecific4 = 12,
    ProcessorSpecific5 = 13,
}

/// Operand display format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum OperandFormat {
    Default = 0,
    Hex = 1,
    Decimal = 2,
    Octal = 3,
    Binary = 4,
    Character = 5,
    Float = 6,
    Offset = 7,
    StackVariable = 8,
}

/// Register classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum RegisterCategory {
    Unknown = 0,
    GeneralPurpose = 1,
    Segment = 2,
    FloatingPoint = 3,
    Vector = 4,
    Mask = 5,
    Control = 6,
    Debug = 7,
    Other = 8,
}

fn register_category_from_i32(value: i32) -> Result<RegisterCategory> {
    match value {
        0 => Ok(RegisterCategory::Unknown),
        1 => Ok(RegisterCategory::GeneralPurpose),
        2 => Ok(RegisterCategory::Segment),
        3 => Ok(RegisterCategory::FloatingPoint),
        4 => Ok(RegisterCategory::Vector),
        5 => Ok(RegisterCategory::Mask),
        6 => Ok(RegisterCategory::Control),
        7 => Ok(RegisterCategory::Debug),
        8 => Ok(RegisterCategory::Other),
        _ => Err(Error::validation("invalid register class value")),
    }
}

/// Structured representation of an operand struct-offset path.
#[derive(Debug, Clone)]
pub struct StructOffsetPath {
    pub structure_ids: Vec<u64>,
    pub delta: AddressDelta,
}

// ---------------------------------------------------------------------------
// Operand value object
// ---------------------------------------------------------------------------

/// Structured representation of a single instruction operand.
#[derive(Debug, Clone)]
pub struct Operand {
    index: i32,
    op_type: OperandType,
    reg: u16,
    value: u64,
    addr: Address,
    byte_width: i32,
    reg_name: String,
    reg_class: RegisterCategory,
}

impl Operand {
    pub fn index(&self) -> i32 {
        self.index
    }
    pub fn op_type(&self) -> OperandType {
        self.op_type
    }
    pub fn is_register(&self) -> bool {
        self.op_type == OperandType::Register
    }
    pub fn is_immediate(&self) -> bool {
        self.op_type == OperandType::Immediate
    }
    pub fn is_memory(&self) -> bool {
        matches!(
            self.op_type,
            OperandType::MemoryDirect | OperandType::MemoryPhrase | OperandType::MemoryDisplacement
        )
    }
    pub fn register_id(&self) -> u16 {
        self.reg
    }
    pub fn value(&self) -> u64 {
        self.value
    }
    pub fn target_address(&self) -> Address {
        self.addr
    }
    pub fn displacement(&self) -> i64 {
        self.value as i64
    }
    pub fn byte_width(&self) -> i32 {
        self.byte_width
    }
    pub fn register_name(&self) -> &str {
        &self.reg_name
    }
    pub fn register_category(&self) -> RegisterCategory {
        self.reg_class
    }
    pub fn is_vector_register(&self) -> bool {
        self.reg_class == RegisterCategory::Vector
    }
    pub fn is_mask_register(&self) -> bool {
        self.reg_class == RegisterCategory::Mask
    }
}

// ---------------------------------------------------------------------------
// Instruction value object
// ---------------------------------------------------------------------------

/// Decoded instruction.
#[derive(Debug, Clone)]
pub struct Instruction {
    ea: Address,
    insn_size: AddressSize,
    itype: u16,
    insn_mnemonic: String,
    operands: Vec<Operand>,
}

impl Instruction {
    pub fn address(&self) -> Address {
        self.ea
    }
    pub fn size(&self) -> AddressSize {
        self.insn_size
    }
    pub fn opcode(&self) -> u16 {
        self.itype
    }
    pub fn mnemonic(&self) -> &str {
        &self.insn_mnemonic
    }
    pub fn operand_count(&self) -> usize {
        self.operands.len()
    }
    pub fn operand(&self, index: usize) -> Result<&Operand> {
        self.operands
            .get(index)
            .ok_or_else(|| Error::validation(format!("operand index {} out of range", index)))
    }
    pub fn operands(&self) -> &[Operand] {
        &self.operands
    }
}

/// Helper: construct a Rust `Instruction` from a filled-in FFI `IdaxInstruction`,
/// then free the FFI struct's internal allocations.
unsafe fn instruction_from_ffi(raw: &idax_sys::IdaxInstruction) -> Result<Instruction> {
    let insn_mnemonic = unsafe { error::cstr_to_string(raw.mnemonic, "mnemonic")? };

    let mut operands = Vec::new();
    if !raw.operands.is_null() && raw.operand_count > 0 {
        let op_slice = unsafe { std::slice::from_raw_parts(raw.operands, raw.operand_count) };
        for op in op_slice {
            let op_type = match op.type_ {
                0 => OperandType::None,
                1 => OperandType::Register,
                2 => OperandType::MemoryDirect,
                3 => OperandType::MemoryPhrase,
                4 => OperandType::MemoryDisplacement,
                5 => OperandType::Immediate,
                6 => OperandType::FarAddress,
                7 => OperandType::NearAddress,
                _ => OperandType::None,
            };
            let reg_class = match op.register_category {
                0 => RegisterCategory::Unknown,
                1 => RegisterCategory::GeneralPurpose,
                2 => RegisterCategory::Segment,
                3 => RegisterCategory::FloatingPoint,
                4 => RegisterCategory::Vector,
                5 => RegisterCategory::Mask,
                6 => RegisterCategory::Control,
                7 => RegisterCategory::Debug,
                _ => RegisterCategory::Other,
            };
            operands.push(Operand {
                index: op.index,
                op_type,
                reg: op.register_id,
                value: op.value,
                addr: op.target_address,
                byte_width: op.byte_width,
                reg_name: unsafe {
                    error::cstr_to_string(op.register_name, "reg name").unwrap_or_default()
                },
                reg_class,
            });
        }
    }

    Ok(Instruction {
        ea: raw.address,
        insn_size: raw.size,
        itype: raw.opcode,
        insn_mnemonic,
        operands,
    })
}

// ---------------------------------------------------------------------------
// Decode / create
// ---------------------------------------------------------------------------

/// Decode an instruction without modifying the database.
pub fn decode(address: Address) -> Result<Instruction> {
    unsafe {
        let mut raw = MaybeUninit::<idax_sys::IdaxInstruction>::zeroed();
        let ret = idax_sys::idax_instruction_decode(address, raw.as_mut_ptr());
        if ret != 0 {
            return Err(error::consume_last_error("instruction decode failed"));
        }
        let raw = raw.assume_init();
        let result = instruction_from_ffi(&raw);
        idax_sys::idax_instruction_free(&raw as *const _ as *mut _);
        result
    }
}

/// Create an instruction in the database (marks bytes as code).
pub fn create(address: Address) -> Result<Instruction> {
    unsafe {
        let mut raw = MaybeUninit::<idax_sys::IdaxInstruction>::zeroed();
        let ret = idax_sys::idax_instruction_create(address, raw.as_mut_ptr());
        if ret != 0 {
            return Err(error::consume_last_error("instruction create failed"));
        }
        let raw = raw.assume_init();
        let result = instruction_from_ffi(&raw);
        idax_sys::idax_instruction_free(&raw as *const _ as *mut _);
        result
    }
}

/// Get the rendered disassembly text at an address.
pub fn text(address: Address) -> Result<String> {
    unsafe {
        let mut out: *mut std::ffi::c_char = std::ptr::null_mut();
        let ret = idax_sys::idax_instruction_text(address, &mut out);
        if ret != 0 {
            return Err(error::consume_last_error("instruction::text failed"));
        }
        Ok(error::consume_c_string(out))
    }
}

// ---------------------------------------------------------------------------
// Operand representation controls
// ---------------------------------------------------------------------------

/// Set operand display format to hexadecimal.
pub fn set_operand_hex(address: Address, n: i32) -> Status {
    let ret = unsafe { idax_sys::idax_instruction_set_operand_hex(address, n) };
    error::int_to_status(ret, "set_operand_hex failed")
}

/// Set operand display format to decimal.
pub fn set_operand_decimal(address: Address, n: i32) -> Status {
    let ret = unsafe { idax_sys::idax_instruction_set_operand_decimal(address, n) };
    error::int_to_status(ret, "set_operand_decimal failed")
}

/// Set operand display format to octal.
pub fn set_operand_octal(address: Address, n: i32) -> Status {
    let ret = unsafe { idax_sys::idax_instruction_set_operand_octal(address, n) };
    error::int_to_status(ret, "set_operand_octal failed")
}

/// Set operand display format to binary.
pub fn set_operand_binary(address: Address, n: i32) -> Status {
    let ret = unsafe { idax_sys::idax_instruction_set_operand_binary(address, n) };
    error::int_to_status(ret, "set_operand_binary failed")
}

/// Set operand display format to character constant.
pub fn set_operand_character(address: Address, n: i32) -> Status {
    let ret = unsafe { idax_sys::idax_instruction_set_operand_character(address, n) };
    error::int_to_status(ret, "set_operand_character failed")
}

/// Set operand display format to floating point.
pub fn set_operand_float(address: Address, n: i32) -> Status {
    let ret = unsafe { idax_sys::idax_instruction_set_operand_float(address, n) };
    error::int_to_status(ret, "set_operand_float failed")
}

/// Set operand display format with optional base for offset forms.
pub fn set_operand_format(
    address: Address,
    n: i32,
    format: OperandFormat,
    base: Address,
) -> Status {
    let ret =
        unsafe { idax_sys::idax_instruction_set_operand_format(address, n, format as i32, base) };
    error::int_to_status(ret, "set_operand_format failed")
}

/// Set operand as an offset reference.
pub fn set_operand_offset(address: Address, n: i32, base: Address) -> Status {
    let ret = unsafe { idax_sys::idax_instruction_set_operand_offset(address, n, base) };
    error::int_to_status(ret, "set_operand_offset failed")
}

/// Set operand as a structure member offset by structure name.
pub fn set_operand_struct_offset_by_name(
    address: Address,
    n: i32,
    structure_name: &str,
    delta: AddressDelta,
) -> Status {
    let c_structure_name =
        CString::new(structure_name).map_err(|_| Error::validation("invalid structure name"))?;
    let ret = unsafe {
        idax_sys::idax_instruction_set_operand_struct_offset_by_name(
            address,
            n,
            c_structure_name.as_ptr(),
            delta,
        )
    };
    error::int_to_status(ret, "set_operand_struct_offset_by_name failed")
}

/// Set operand as a structure member offset by raw structure id.
pub fn set_operand_struct_offset_by_id(
    address: Address,
    n: i32,
    structure_id: u64,
    delta: AddressDelta,
) -> Status {
    let ret = unsafe {
        idax_sys::idax_instruction_set_operand_struct_offset_by_id(address, n, structure_id, delta)
    };
    error::int_to_status(ret, "set_operand_struct_offset_by_id failed")
}

/// Set operand as a based structure offset.
pub fn set_operand_based_struct_offset(
    address: Address,
    n: i32,
    operand_value: Address,
    base: Address,
) -> Status {
    let ret = unsafe {
        idax_sys::idax_instruction_set_operand_based_struct_offset(address, n, operand_value, base)
    };
    error::int_to_status(ret, "set_operand_based_struct_offset failed")
}

/// Read struct-offset path metadata for an operand.
pub fn operand_struct_offset_path(address: Address, n: i32) -> Result<StructOffsetPath> {
    unsafe {
        let mut out_ids: *mut u64 = std::ptr::null_mut();
        let mut out_count: usize = 0;
        let mut out_delta: AddressDelta = 0;
        let ret = idax_sys::idax_instruction_operand_struct_offset_path(
            address,
            n,
            &mut out_ids,
            &mut out_count,
            &mut out_delta,
        );
        if ret != 0 {
            return Err(error::consume_last_error(
                "operand_struct_offset_path failed",
            ));
        }
        let structure_ids = if out_ids.is_null() || out_count == 0 {
            Vec::new()
        } else {
            std::slice::from_raw_parts(out_ids, out_count).to_vec()
        };
        if !out_ids.is_null() {
            idax_sys::idax_free_addresses(out_ids);
        }
        Ok(StructOffsetPath {
            structure_ids,
            delta: out_delta,
        })
    }
}

/// Read struct-offset path metadata with resolved structure names.
pub fn operand_struct_offset_path_names(address: Address, n: i32) -> Result<Vec<String>> {
    unsafe {
        let mut out: *mut *mut std::ffi::c_char = std::ptr::null_mut();
        let mut count: usize = 0;
        let ret = idax_sys::idax_instruction_operand_struct_offset_path_names(
            address, n, &mut out, &mut count,
        );
        if ret != 0 {
            return Err(error::consume_last_error(
                "operand_struct_offset_path_names failed",
            ));
        }
        let values_result: Result<Vec<String>> = if out.is_null() || count == 0 {
            Ok(Vec::new())
        } else {
            let raw = std::slice::from_raw_parts(out, count);
            raw.iter()
                .map(|v| error::cstr_to_string(*v, "struct offset path name"))
                .collect()
        };
        if !out.is_null() {
            idax_sys::idax_instruction_string_array_free(out, count);
        }
        values_result
    }
}

/// Set operand to display as a stack variable.
pub fn set_operand_stack_variable(address: Address, n: i32) -> Status {
    let ret = unsafe { idax_sys::idax_instruction_set_operand_stack_variable(address, n) };
    error::int_to_status(ret, "set_operand_stack_variable failed")
}

/// Clear operand representation (reset to default).
pub fn clear_operand_representation(address: Address, n: i32) -> Status {
    let ret = unsafe { idax_sys::idax_instruction_clear_operand_representation(address, n) };
    error::int_to_status(ret, "clear_operand_representation failed")
}

/// Set or clear forced (manual) operand text.
pub fn set_forced_operand(address: Address, n: i32, text: &str) -> Status {
    let c_text = CString::new(text).map_err(|_| Error::validation("invalid text"))?;
    let ret = unsafe { idax_sys::idax_instruction_set_forced_operand(address, n, c_text.as_ptr()) };
    error::int_to_status(ret, "set_forced_operand failed")
}

/// Retrieve forced (manual) operand text, if any.
pub fn get_forced_operand(address: Address, n: i32) -> Result<String> {
    unsafe {
        let mut out: *mut std::ffi::c_char = std::ptr::null_mut();
        let ret = idax_sys::idax_instruction_get_forced_operand(address, n, &mut out);
        if ret != 0 {
            return Err(error::consume_last_error("get_forced_operand failed"));
        }
        Ok(error::consume_c_string(out))
    }
}

/// Render only the operand text for operand index `n`.
pub fn operand_text(address: Address, n: i32) -> Result<String> {
    unsafe {
        let mut out: *mut std::ffi::c_char = std::ptr::null_mut();
        let ret = idax_sys::idax_instruction_operand_text(address, n, &mut out);
        if ret != 0 {
            return Err(error::consume_last_error("operand_text failed"));
        }
        Ok(error::consume_c_string(out))
    }
}

/// Structured byte-width query for operand index `n`.
pub fn operand_byte_width(address: Address, n: i32) -> Result<i32> {
    let mut out: i32 = 0;
    let ret = unsafe { idax_sys::idax_instruction_operand_byte_width(address, n, &mut out) };
    if ret != 0 {
        Err(error::consume_last_error("operand_byte_width failed"))
    } else {
        Ok(out)
    }
}

/// Register name for operand index `n`.
pub fn operand_register_name(address: Address, n: i32) -> Result<String> {
    unsafe {
        let mut out: *mut std::ffi::c_char = std::ptr::null_mut();
        let ret = idax_sys::idax_instruction_operand_register_name(address, n, &mut out);
        if ret != 0 {
            return Err(error::consume_last_error("operand_register_name failed"));
        }
        Ok(error::consume_c_string(out))
    }
}

/// Register class for operand index `n`.
pub fn operand_register_category(address: Address, n: i32) -> Result<RegisterCategory> {
    let mut out: i32 = 0;
    let ret = unsafe { idax_sys::idax_instruction_operand_register_category(address, n, &mut out) };
    if ret != 0 {
        return Err(error::consume_last_error("operand_register_category failed"));
    }
    register_category_from_i32(out)
}

/// Toggle sign inversion on operand display.
pub fn toggle_operand_sign(address: Address, n: i32) -> Status {
    let ret = unsafe { idax_sys::idax_instruction_toggle_operand_sign(address, n) };
    error::int_to_status(ret, "toggle_operand_sign failed")
}

/// Toggle bitwise negation on operand display.
pub fn toggle_operand_negate(address: Address, n: i32) -> Status {
    let ret = unsafe { idax_sys::idax_instruction_toggle_operand_negate(address, n) };
    error::int_to_status(ret, "toggle_operand_negate failed")
}

// ---------------------------------------------------------------------------
// Instruction-level xref conveniences
// ---------------------------------------------------------------------------

/// Code cross-references originating from the instruction at `address`.
pub fn code_refs_from(address: Address) -> Result<Vec<Address>> {
    unsafe {
        let mut count: usize = 0;
        let mut addrs: *mut u64 = std::ptr::null_mut();
        let ret = idax_sys::idax_instruction_code_refs_from(address, &mut addrs, &mut count);
        if ret != 0 {
            return Err(error::consume_last_error("code_refs_from failed"));
        }
        let result = if addrs.is_null() || count == 0 {
            Vec::new()
        } else {
            std::slice::from_raw_parts(addrs, count).to_vec()
        };
        if !addrs.is_null() {
            idax_sys::idax_free_addresses(addrs);
        }
        Ok(result)
    }
}

/// Data cross-references originating from the instruction at `address`.
pub fn data_refs_from(address: Address) -> Result<Vec<Address>> {
    unsafe {
        let mut count: usize = 0;
        let mut addrs: *mut u64 = std::ptr::null_mut();
        let ret = idax_sys::idax_instruction_data_refs_from(address, &mut addrs, &mut count);
        if ret != 0 {
            return Err(error::consume_last_error("data_refs_from failed"));
        }
        let result = if addrs.is_null() || count == 0 {
            Vec::new()
        } else {
            std::slice::from_raw_parts(addrs, count).to_vec()
        };
        if !addrs.is_null() {
            idax_sys::idax_free_addresses(addrs);
        }
        Ok(result)
    }
}

/// All call targets from the instruction at `address`.
pub fn call_targets(address: Address) -> Result<Vec<Address>> {
    unsafe {
        let mut count: usize = 0;
        let mut addrs: *mut u64 = std::ptr::null_mut();
        let ret = idax_sys::idax_instruction_call_targets(address, &mut addrs, &mut count);
        if ret != 0 {
            return Err(error::consume_last_error("call_targets failed"));
        }
        let result = if addrs.is_null() || count == 0 {
            Vec::new()
        } else {
            std::slice::from_raw_parts(addrs, count).to_vec()
        };
        if !addrs.is_null() {
            idax_sys::idax_free_addresses(addrs);
        }
        Ok(result)
    }
}

/// All jump targets from the instruction at `address`.
pub fn jump_targets(address: Address) -> Result<Vec<Address>> {
    unsafe {
        let mut count: usize = 0;
        let mut addrs: *mut u64 = std::ptr::null_mut();
        let ret = idax_sys::idax_instruction_jump_targets(address, &mut addrs, &mut count);
        if ret != 0 {
            return Err(error::consume_last_error("jump_targets failed"));
        }
        let result = if addrs.is_null() || count == 0 {
            Vec::new()
        } else {
            std::slice::from_raw_parts(addrs, count).to_vec()
        };
        if !addrs.is_null() {
            idax_sys::idax_free_addresses(addrs);
        }
        Ok(result)
    }
}

/// Does the instruction at `address` have fall-through to the next instruction?
pub fn has_fall_through(address: Address) -> bool {
    unsafe { idax_sys::idax_instruction_has_fall_through(address) != 0 }
}

/// Is the instruction at `address` a call instruction?
pub fn is_call(address: Address) -> bool {
    unsafe { idax_sys::idax_instruction_is_call(address) != 0 }
}

/// Is the instruction at `address` a return instruction?
pub fn is_return(address: Address) -> bool {
    unsafe { idax_sys::idax_instruction_is_return(address) != 0 }
}

/// Is the instruction at `address` any jump instruction?
pub fn is_jump(address: Address) -> bool {
    unsafe { idax_sys::idax_instruction_is_jump(address) != 0 }
}

/// Is the instruction at `address` a conditional jump?
pub fn is_conditional_jump(address: Address) -> bool {
    unsafe { idax_sys::idax_instruction_is_conditional_jump(address) != 0 }
}

/// Decode the next instruction after `address`.
pub fn next(address: Address) -> Result<Instruction> {
    unsafe {
        let mut raw = MaybeUninit::<idax_sys::IdaxInstruction>::zeroed();
        let ret = idax_sys::idax_instruction_next(address, raw.as_mut_ptr());
        if ret != 0 {
            return Err(error::consume_last_error("instruction::next failed"));
        }
        let raw = raw.assume_init();
        let result = instruction_from_ffi(&raw);
        idax_sys::idax_instruction_free(&raw as *const _ as *mut _);
        result
    }
}

/// Decode the previous instruction before `address`.
pub fn prev(address: Address) -> Result<Instruction> {
    unsafe {
        let mut raw = MaybeUninit::<idax_sys::IdaxInstruction>::zeroed();
        let ret = idax_sys::idax_instruction_prev(address, raw.as_mut_ptr());
        if ret != 0 {
            return Err(error::consume_last_error("instruction::prev failed"));
        }
        let raw = raw.assume_init();
        let result = instruction_from_ffi(&raw);
        idax_sys::idax_instruction_free(&raw as *const _ as *mut _);
        result
    }
}

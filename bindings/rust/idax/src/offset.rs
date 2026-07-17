//! Opaque operand offset and reference semantics.
//!
//! Mirrors the C++ `ida::offset` namespace without exposing SDK identities.

use crate::address::{Address, AddressDelta};
use crate::error::{self, Error, Result, Status};
use crate::xref::DataType;
use std::ffi::{CStr, CString};

/// Stable standard encodings plus name-resolved custom reference formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum ReferenceKind {
    Offset8 = 0,
    Offset16 = 1,
    Offset32 = 2,
    Offset64 = 3,
    Low8 = 4,
    Low16 = 5,
    Low32 = 6,
    High8 = 7,
    High16 = 8,
    High32 = 9,
    Custom = 10,
}

/// Semantic reference-format identity.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ReferenceType {
    pub kind: ReferenceKind,
    pub custom_name: String,
}

impl Default for ReferenceType {
    fn default() -> Self {
        Self {
            kind: ReferenceKind::Offset32,
            custom_name: String::new(),
        }
    }
}

/// Owned live description of a standard or registered custom format.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ReferenceTypeDescriptor {
    pub reference_type: ReferenceType,
    pub name: String,
    pub description: String,
    pub target_optional: bool,
}

/// One instruction/data operand, optionally its outer value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct OperandLocation {
    pub index: usize,
    pub outer: bool,
}

/// Named behavioral options for an offset reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct ReferenceOptions {
    pub relative_virtual_address: bool,
    pub allow_past_end: bool,
    pub suppress_base_reference: bool,
    pub subtract_operand: bool,
    pub sign_extend_operand: bool,
    pub accept_zero: bool,
    pub reject_all_ones: bool,
    pub self_relative: bool,
    pub ignore_fixup: bool,
}

/// Owned reference metadata. Missing target/base maps native sentinel state.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct ReferenceInfo {
    pub reference_type: ReferenceType,
    pub target: Option<Address>,
    pub base: Option<Address>,
    pub target_delta: AddressDelta,
    pub options: ReferenceOptions,
}

/// Whether rendering produced a direct or compound expression.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum ExpressionComplexity {
    Simple = 0,
    Complex = 1,
}

/// Rendering controls.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct RenderOptions {
    pub append_zero_field: bool,
    pub avoid_dummy_names: bool,
}

/// Plain, tag-free offset expression.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RenderedExpression {
    pub text: String,
    pub complexity: ExpressionComplexity,
}

/// Calculated reference endpoints.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ReferenceCalculation {
    pub target: Option<Address>,
    pub base: Option<Address>,
}

struct RawReferenceInfoInput {
    raw: idax_sys::IdaxOffsetReferenceInfoInput,
    _custom_name: CString,
}

impl RawReferenceInfoInput {
    fn new(info: &ReferenceInfo) -> Result<Self> {
        let custom_name = CString::new(info.reference_type.custom_name.as_str())
            .map_err(|_| Error::validation("custom reference name contains a NUL byte"))?;
        let raw = idax_sys::IdaxOffsetReferenceInfoInput {
            kind: info.reference_type.kind as i32,
            custom_name: custom_name.as_ptr(),
            has_target: i32::from(info.target.is_some()),
            target: info.target.unwrap_or(0),
            has_base: i32::from(info.base.is_some()),
            base: info.base.unwrap_or(0),
            target_delta: info.target_delta,
            relative_virtual_address: i32::from(info.options.relative_virtual_address),
            allow_past_end: i32::from(info.options.allow_past_end),
            suppress_base_reference: i32::from(info.options.suppress_base_reference),
            subtract_operand: i32::from(info.options.subtract_operand),
            sign_extend_operand: i32::from(info.options.sign_extend_operand),
            accept_zero: i32::from(info.options.accept_zero),
            reject_all_ones: i32::from(info.options.reject_all_ones),
            self_relative: i32::from(info.options.self_relative),
            ignore_fixup: i32::from(info.options.ignore_fixup),
        };
        Ok(Self {
            raw,
            _custom_name: custom_name,
        })
    }
}

fn reference_kind(value: i32) -> Result<ReferenceKind> {
    match value {
        0 => Ok(ReferenceKind::Offset8),
        1 => Ok(ReferenceKind::Offset16),
        2 => Ok(ReferenceKind::Offset32),
        3 => Ok(ReferenceKind::Offset64),
        4 => Ok(ReferenceKind::Low8),
        5 => Ok(ReferenceKind::Low16),
        6 => Ok(ReferenceKind::Low32),
        7 => Ok(ReferenceKind::High8),
        8 => Ok(ReferenceKind::High16),
        9 => Ok(ReferenceKind::High32),
        10 => Ok(ReferenceKind::Custom),
        _ => Err(Error::internal(format!(
            "shim returned unknown offset reference kind {value}"
        ))),
    }
}

unsafe fn copy_required_string(value: *const std::ffi::c_char, field: &str) -> Result<String> {
    if value.is_null() {
        return Err(Error::internal(format!(
            "shim returned null {field} string"
        )));
    }
    Ok(unsafe { CStr::from_ptr(value) }
        .to_string_lossy()
        .into_owned())
}

unsafe fn copy_reference_type(value: &idax_sys::IdaxOffsetReferenceType) -> Result<ReferenceType> {
    Ok(ReferenceType {
        kind: reference_kind(value.kind)?,
        custom_name: unsafe { copy_required_string(value.custom_name, "custom reference name")? },
    })
}

unsafe fn copy_reference_info(value: &idax_sys::IdaxOffsetReferenceInfo) -> Result<ReferenceInfo> {
    Ok(ReferenceInfo {
        reference_type: ReferenceType {
            kind: reference_kind(value.kind)?,
            custom_name: unsafe {
                copy_required_string(value.custom_name, "custom reference name")?
            },
        },
        target: (value.has_target != 0).then_some(value.target),
        base: (value.has_base != 0).then_some(value.base),
        target_delta: value.target_delta,
        options: ReferenceOptions {
            relative_virtual_address: value.relative_virtual_address != 0,
            allow_past_end: value.allow_past_end != 0,
            suppress_base_reference: value.suppress_base_reference != 0,
            subtract_operand: value.subtract_operand != 0,
            sign_extend_operand: value.sign_extend_operand != 0,
            accept_zero: value.accept_zero != 0,
            reject_all_ones: value.reject_all_ones != 0,
            self_relative: value.self_relative != 0,
            ignore_fixup: value.ignore_fixup != 0,
        },
    })
}

fn optional_address(value: Address, has_value: i32) -> Option<Address> {
    (has_value != 0).then_some(value)
}

/// Enumerate live standard and registered custom reference formats.
pub fn reference_types() -> Result<Vec<ReferenceTypeDescriptor>> {
    unsafe {
        let mut values = std::ptr::null_mut();
        let mut count = 0usize;
        let ret = idax_sys::idax_offset_reference_types(&mut values, &mut count);
        if ret != 0 {
            return Err(error::consume_last_error("offset::reference_types failed"));
        }
        if count != 0 && values.is_null() {
            return Err(Error::internal(
                "shim returned null offset descriptor array",
            ));
        }
        let decoded = (|| {
            let slice = if count == 0 {
                &[][..]
            } else {
                std::slice::from_raw_parts(values, count)
            };
            slice
                .iter()
                .map(|value| {
                    Ok(ReferenceTypeDescriptor {
                        reference_type: copy_reference_type(&value.type_)?,
                        name: copy_required_string(value.name, "reference type name")?,
                        description: copy_required_string(
                            value.description,
                            "reference type description",
                        )?,
                        target_optional: value.target_optional != 0,
                    })
                })
                .collect()
        })();
        idax_sys::idax_offset_reference_types_free(values, count);
        decoded
    }
}

/// Default full-width format selected for the segment containing `address`.
pub fn default_reference_type(address: Address) -> Result<ReferenceType> {
    unsafe {
        let mut raw = idax_sys::IdaxOffsetReferenceType::default();
        let ret = idax_sys::idax_offset_default_reference_type(address, &mut raw);
        if ret != 0 {
            return Err(error::consume_last_error(
                "offset::default_reference_type failed",
            ));
        }
        let decoded = copy_reference_type(&raw);
        idax_sys::idax_offset_reference_type_free(&mut raw);
        decoded
    }
}

/// Read copied reference metadata; absence is an ordinary `None`.
pub fn reference_info(
    address: Address,
    location: OperandLocation,
) -> Result<Option<ReferenceInfo>> {
    unsafe {
        let mut raw = idax_sys::IdaxOffsetReferenceInfo::default();
        let mut has_info = 0;
        let ret = idax_sys::idax_offset_reference_info(
            address,
            location.index,
            i32::from(location.outer),
            &mut raw,
            &mut has_info,
        );
        if ret != 0 {
            return Err(error::consume_last_error("offset::reference_info failed"));
        }
        if has_info == 0 {
            return Ok(None);
        }
        let decoded = copy_reference_info(&raw).map(Some);
        idax_sys::idax_offset_reference_info_free(&mut raw);
        decoded
    }
}

/// Apply reference metadata with exact-readback verification.
pub fn apply_reference(
    address: Address,
    location: OperandLocation,
    info: &ReferenceInfo,
) -> Status {
    let raw = RawReferenceInfoInput::new(info)?;
    let ret = unsafe {
        idax_sys::idax_offset_apply_reference(
            address,
            location.index,
            i32::from(location.outer),
            &raw.raw,
        )
    };
    error::int_to_status(ret, "offset::apply_reference failed")
}

/// Remove metadata and display representation; returns whether one existed.
pub fn remove_reference(address: Address, location: OperandLocation) -> Result<bool> {
    let mut removed = 0;
    let ret = unsafe {
        idax_sys::idax_offset_remove_reference(
            address,
            location.index,
            i32::from(location.outer),
            &mut removed,
        )
    };
    if ret != 0 {
        Err(error::consume_last_error("offset::remove_reference failed"))
    } else {
        Ok(removed != 0)
    }
}

unsafe fn take_rendered_expression(
    raw: &mut idax_sys::IdaxOffsetRenderedExpression,
) -> Result<RenderedExpression> {
    let decoded = (|| {
        let complexity = match raw.complexity {
            0 => ExpressionComplexity::Simple,
            1 => ExpressionComplexity::Complex,
            value => {
                return Err(Error::internal(format!(
                    "shim returned unknown offset expression complexity {value}"
                )));
            }
        };
        Ok(RenderedExpression {
            text: unsafe { copy_required_string(raw.text, "rendered expression")? },
            complexity,
        })
    })();
    unsafe { idax_sys::idax_offset_rendered_expression_free(raw) };
    decoded
}

/// Render the reference currently stored on an operand.
pub fn render_stored_expression(
    address: Address,
    location: OperandLocation,
    from: Address,
    operand_value: AddressDelta,
    options: RenderOptions,
) -> Result<RenderedExpression> {
    unsafe {
        let mut raw = idax_sys::IdaxOffsetRenderedExpression::default();
        let ret = idax_sys::idax_offset_render_stored_expression(
            address,
            location.index,
            i32::from(location.outer),
            from,
            operand_value,
            i32::from(options.append_zero_field),
            i32::from(options.avoid_dummy_names),
            &mut raw,
        );
        if ret != 0 {
            return Err(error::consume_last_error(
                "offset::render_stored_expression failed",
            ));
        }
        take_rendered_expression(&mut raw)
    }
}

/// Render explicit reference metadata without storing it.
pub fn render_expression(
    address: Address,
    location: OperandLocation,
    info: &ReferenceInfo,
    from: Address,
    operand_value: AddressDelta,
    options: RenderOptions,
) -> Result<RenderedExpression> {
    let input = RawReferenceInfoInput::new(info)?;
    unsafe {
        let mut raw = idax_sys::IdaxOffsetRenderedExpression::default();
        let ret = idax_sys::idax_offset_render_expression(
            address,
            location.index,
            i32::from(location.outer),
            &input.raw,
            from,
            operand_value,
            i32::from(options.append_zero_field),
            i32::from(options.avoid_dummy_names),
            &mut raw,
        );
        if ret != 0 {
            return Err(error::consume_last_error(
                "offset::render_expression failed",
            ));
        }
        take_rendered_expression(&mut raw)
    }
}

/// Target when the value at `address` is a valid 32-bit offset candidate.
pub fn possible_offset32_target(address: Address) -> Result<Option<Address>> {
    let mut value = 0;
    let mut has_value = 0;
    let ret = unsafe {
        idax_sys::idax_offset_possible_offset32_target(address, &mut value, &mut has_value)
    };
    if ret != 0 {
        Err(error::consume_last_error(
            "offset::possible_offset32_target failed",
        ))
    } else {
        Ok(optional_address(value, has_value))
    }
}

/// Calculate an operand's offset base using fixups and segment-register state.
pub fn calculate_offset_base(
    address: Address,
    location: OperandLocation,
) -> Result<Option<Address>> {
    let mut value = 0;
    let mut has_value = 0;
    let ret = unsafe {
        idax_sys::idax_offset_calculate_offset_base(
            address,
            location.index,
            i32::from(location.outer),
            &mut value,
            &mut has_value,
        )
    };
    if ret != 0 {
        Err(error::consume_last_error(
            "offset::calculate_offset_base failed",
        ))
    } else {
        Ok(optional_address(value, has_value))
    }
}

/// Try the current code/data segment bases for a raw operand value.
pub fn probable_base(address: Address, operand_value: u64) -> Result<Option<Address>> {
    let mut value = 0;
    let mut has_value = 0;
    let ret = unsafe {
        idax_sys::idax_offset_probable_base(address, operand_value, &mut value, &mut has_value)
    };
    if ret != 0 {
        Err(error::consume_last_error("offset::probable_base failed"))
    } else {
        Ok(optional_address(value, has_value))
    }
}

/// Calculate target/base state for explicit metadata and one raw value.
pub fn calculate_reference(
    from: Address,
    info: &ReferenceInfo,
    operand_value: AddressDelta,
) -> Result<ReferenceCalculation> {
    let input = RawReferenceInfoInput::new(info)?;
    unsafe {
        let mut raw = idax_sys::IdaxOffsetReferenceCalculation::default();
        let ret =
            idax_sys::idax_offset_calculate_reference(from, &input.raw, operand_value, &mut raw);
        if ret != 0 {
            return Err(error::consume_last_error(
                "offset::calculate_reference failed",
            ));
        }
        Ok(ReferenceCalculation {
            target: optional_address(raw.target, raw.has_target),
            base: optional_address(raw.base, raw.has_base),
        })
    }
}

/// Create reference-aware data xrefs for a stored instruction operand.
pub fn add_operand_data_references(
    instruction_address: Address,
    location: OperandLocation,
    data_type: DataType,
) -> Result<Address> {
    let mut target = 0;
    let ret = unsafe {
        idax_sys::idax_offset_add_operand_data_references(
            instruction_address,
            location.index,
            i32::from(location.outer),
            data_type as i32,
            &mut target,
        )
    };
    if ret != 0 {
        Err(error::consume_last_error(
            "offset::add_operand_data_references failed",
        ))
    } else {
        Ok(target)
    }
}

/// Calculate the SDK-defined value of the reference base; failure is `None`.
pub fn calculate_base_value(target: Address, base: Address) -> Result<Option<Address>> {
    let mut value = 0;
    let mut has_value = 0;
    let ret = unsafe {
        idax_sys::idax_offset_calculate_base_value(target, base, &mut value, &mut has_value)
    };
    if ret != 0 {
        Err(error::consume_last_error(
            "offset::calculate_base_value failed",
        ))
    } else {
        Ok(optional_address(value, has_value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reference_kind_values_match_cpp_order() {
        assert_eq!(ReferenceKind::Offset8 as i32, 0);
        assert_eq!(ReferenceKind::Offset32 as i32, 2);
        assert_eq!(ReferenceKind::High32 as i32, 9);
        assert_eq!(ReferenceKind::Custom as i32, 10);
    }

    #[test]
    fn raw_input_preserves_optional_and_flag_state() {
        let info = ReferenceInfo {
            reference_type: ReferenceType {
                kind: ReferenceKind::Offset64,
                custom_name: String::new(),
            },
            target: Some(0x1234),
            base: None,
            target_delta: -7,
            options: ReferenceOptions {
                relative_virtual_address: true,
                reject_all_ones: true,
                ..ReferenceOptions::default()
            },
        };
        let input = RawReferenceInfoInput::new(&info).expect("valid input");
        assert_eq!(input.raw.kind, ReferenceKind::Offset64 as i32);
        assert_eq!(input.raw.has_target, 1);
        assert_eq!(input.raw.target, 0x1234);
        assert_eq!(input.raw.has_base, 0);
        assert_eq!(input.raw.target_delta, -7);
        assert_eq!(input.raw.relative_virtual_address, 1);
        assert_eq!(input.raw.reject_all_ones, 1);
    }

    #[test]
    fn embedded_nul_in_custom_name_is_rejected() {
        let info = ReferenceInfo {
            reference_type: ReferenceType {
                kind: ReferenceKind::Custom,
                custom_name: "bad\0name".into(),
            },
            ..ReferenceInfo::default()
        };
        assert!(RawReferenceInfoInput::new(&info).is_err());
    }
}

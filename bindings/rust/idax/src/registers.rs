//! Opaque register-value tracking with owned semantic results.

use std::ffi::{CStr, CString};

use crate::address::{Address, AddressDelta};
use crate::error::{self, Error, Result, Status};

/// Exhaustive state returned by the pinned register tracker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum TrackingState {
    Undefined = 0,
    DeadEnd = 1,
    Aborted = 2,
    BadInstruction = 3,
    UnknownInstruction = 4,
    FunctionInput = 5,
    LoopVariant = 6,
    IncompatibleValues = 7,
    TooManyReferences = 8,
    TooManyValues = 9,
    Constant = 10,
    StackPointerDelta = 11,
}

impl TryFrom<i32> for TrackingState {
    type Error = Error;

    fn try_from(value: i32) -> Result<Self> {
        match value {
            0 => Ok(Self::Undefined),
            1 => Ok(Self::DeadEnd),
            2 => Ok(Self::Aborted),
            3 => Ok(Self::BadInstruction),
            4 => Ok(Self::UnknownInstruction),
            5 => Ok(Self::FunctionInput),
            6 => Ok(Self::LoopVariant),
            7 => Ok(Self::IncompatibleValues),
            8 => Ok(Self::TooManyReferences),
            9 => Ok(Self::TooManyValues),
            10 => Ok(Self::Constant),
            11 => Ok(Self::StackPointerDelta),
            _ => Err(Error::internal(format!(
                "unknown register tracking state {value}"
            ))),
        }
    }
}

/// Whether a reference was added or removed for tracker-cache invalidation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum ReferenceMutation {
    Added = 0,
    Removed = 1,
}

/// Copied origin metadata for one tracked value or terminal cause.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ValueOrigin {
    pub address: Address,
    pub instruction_code: u16,
    pub short_instruction: bool,
    pub program_counter_based: bool,
    pub global_offset_table_like: bool,
}

/// One possible tracked numeric value and its defining origin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValueCandidate {
    pub constant: Option<u64>,
    pub stack_pointer_delta: Option<AddressDelta>,
    pub origin: ValueOrigin,
}

/// Complete owned backward register-value query result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrackedValue {
    pub state: TrackingState,
    pub candidates: Vec<ValueCandidate>,
    pub cause: Option<ValueOrigin>,
    pub aborting_depth: Option<i32>,
    pub description: String,
}

impl TrackedValue {
    pub fn known(&self) -> bool {
        matches!(
            self.state,
            TrackingState::Constant | TrackingState::StackPointerDelta
        )
    }
}

/// Result of native nearest-of-two base-register selection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NearestValue {
    pub selected_index: usize,
    pub register_name: String,
    pub value: TrackedValue,
}

fn register_name(value: &str) -> Result<CString> {
    CString::new(value)
        .map_err(|_| Error::validation("register name contains an embedded NUL byte"))
}

fn origin_from_c(value: &idax_sys::IdaxRegisterValueOrigin) -> ValueOrigin {
    ValueOrigin {
        address: value.address,
        instruction_code: value.instruction_code,
        short_instruction: value.short_instruction != 0,
        program_counter_based: value.program_counter_based != 0,
        global_offset_table_like: value.global_offset_table_like != 0,
    }
}

unsafe fn tracked_from_c(value: &idax_sys::IdaxTrackedRegisterValue) -> Result<TrackedValue> {
    if value.description.is_null() {
        return Err(Error::internal(
            "register tracker returned a null description",
        ));
    }
    if value.candidate_count != 0 && value.candidates.is_null() {
        return Err(Error::internal(
            "register tracker returned a null candidate array",
        ));
    }
    let native_candidates = if value.candidate_count == 0 {
        &[][..]
    } else {
        unsafe { std::slice::from_raw_parts(value.candidates, value.candidate_count) }
    };
    let candidates = native_candidates
        .iter()
        .map(|candidate| ValueCandidate {
            constant: (candidate.has_constant != 0).then_some(candidate.constant),
            stack_pointer_delta: (candidate.has_stack_pointer_delta != 0)
                .then_some(candidate.stack_pointer_delta),
            origin: origin_from_c(&candidate.origin),
        })
        .collect();
    Ok(TrackedValue {
        state: TrackingState::try_from(value.state)?,
        candidates,
        cause: (value.has_cause != 0).then(|| origin_from_c(&value.cause)),
        aborting_depth: (value.has_aborting_depth != 0).then_some(value.aborting_depth),
        description: unsafe { CStr::from_ptr(value.description) }
            .to_string_lossy()
            .into_owned(),
    })
}

/// Track a named register before executing the instruction at `address`.
pub fn track(address: Address, name: &str, max_depth: i32) -> Result<TrackedValue> {
    let name = register_name(name)?;
    let mut native = idax_sys::IdaxTrackedRegisterValue::default();
    let status =
        unsafe { idax_sys::idax_registers_track(address, name.as_ptr(), max_depth, &mut native) };
    if status != 0 {
        return Err(error::consume_last_error("registers::track failed"));
    }
    let result = unsafe { tracked_from_c(&native) };
    unsafe { idax_sys::idax_registers_tracked_value_free(&mut native) };
    result
}

/// Return a unique constant, or `None` when no unique constant is known.
pub fn constant_at(address: Address, name: &str, max_depth: i32) -> Result<Option<u64>> {
    let name = register_name(name)?;
    let mut value = 0;
    let mut has_value = 0;
    let status = unsafe {
        idax_sys::idax_registers_constant_at(
            address,
            name.as_ptr(),
            max_depth,
            &mut value,
            &mut has_value,
        )
    };
    if status != 0 {
        return Err(error::consume_last_error("registers::constant_at failed"));
    }
    Ok((has_value != 0).then_some(value))
}

/// Return the default or named stack-pointer-relative delta, or `None`.
pub fn stack_delta_at(address: Address, name: Option<&str>) -> Result<Option<AddressDelta>> {
    let name = name.map(register_name).transpose()?;
    let mut value = 0;
    let mut has_value = 0;
    let status = unsafe {
        idax_sys::idax_registers_stack_delta_at(
            address,
            name.as_ref().map_or(std::ptr::null(), |name| name.as_ptr()),
            &mut value,
            &mut has_value,
        )
    };
    if status != 0 {
        return Err(error::consume_last_error(
            "registers::stack_delta_at failed",
        ));
    }
    Ok((has_value != 0).then_some(value))
}

/// Select the first native value found for two distinct base registers.
pub fn nearest_at(
    address: Address,
    first_register: &str,
    second_register: &str,
) -> Result<Option<NearestValue>> {
    let first = register_name(first_register)?;
    let second = register_name(second_register)?;
    let mut native = idax_sys::IdaxNearestRegisterValue::default();
    let mut has_value = 0;
    let status = unsafe {
        idax_sys::idax_registers_nearest_at(
            address,
            first.as_ptr(),
            second.as_ptr(),
            &mut native,
            &mut has_value,
        )
    };
    if status != 0 {
        return Err(error::consume_last_error("registers::nearest_at failed"));
    }
    let result = if has_value == 0 {
        Ok(None)
    } else if native.register_name.is_null() {
        Err(Error::internal(
            "nearest register tracker returned a null name",
        ))
    } else {
        let register_name = unsafe { CStr::from_ptr(native.register_name) }
            .to_string_lossy()
            .into_owned();
        unsafe { tracked_from_c(&native.value) }.map(|value| {
            Some(NearestValue {
                selected_index: native.selected_index,
                register_name,
                value,
            })
        })
    };
    unsafe { idax_sys::idax_registers_nearest_value_free(&mut native) };
    result
}

pub fn clear_control_flow_cache() -> Status {
    error::int_to_status(
        unsafe { idax_sys::idax_registers_clear_control_flow_cache() },
        "registers::clear_control_flow_cache failed",
    )
}

pub fn clear_data_reference_cache() -> Status {
    error::int_to_status(
        unsafe { idax_sys::idax_registers_clear_data_reference_cache() },
        "registers::clear_data_reference_cache failed",
    )
}

pub fn control_flow_reference_changed(
    from: Address,
    to: Address,
    mutation: ReferenceMutation,
) -> Status {
    error::int_to_status(
        unsafe {
            idax_sys::idax_registers_control_flow_reference_changed(from, to, mutation as i32)
        },
        "registers::control_flow_reference_changed failed",
    )
}

pub fn data_reference_changed(to: Address, mutation: ReferenceMutation) -> Status {
    error::int_to_status(
        unsafe { idax_sys::idax_registers_data_reference_changed(to, mutation as i32) },
        "registers::data_reference_changed failed",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discriminants_and_signatures_are_stable() {
        assert_eq!(TrackingState::Undefined as i32, 0);
        assert_eq!(TrackingState::StackPointerDelta as i32, 11);
        assert_eq!(ReferenceMutation::Added as i32, 0);
        assert_eq!(ReferenceMutation::Removed as i32, 1);
        let _: fn(Address, &str, i32) -> Result<TrackedValue> = track;
        let _: fn(Address, &str, i32) -> Result<Option<u64>> = constant_at;
        let _: fn(Address, Option<&str>) -> Result<Option<AddressDelta>> = stack_delta_at;
        let _: fn(Address, &str, &str) -> Result<Option<NearestValue>> = nearest_at;
    }

    #[test]
    fn embedded_nul_is_rejected_before_ffi() {
        let error = track(0, "x\0zero", 0).unwrap_err();
        assert_eq!(error.category, crate::error::ErrorCategory::Validation);
    }
}

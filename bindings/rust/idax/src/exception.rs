//! Architecture-independent C++ and structured-exception regions.

use crate::address::{Address, AddressDelta, Range};
use crate::error::{self, Error, Result, Status};
use std::ptr;

/// Metadata shared by C++ catch and SEH handler bodies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandlerMetadata {
    pub regions: Vec<Range>,
    pub stack_displacement: Option<AddressDelta>,
    pub frame_register: Option<i32>,
}

/// Semantic C++ catch selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CatchSelector {
    Typed(i64),
    CatchAll,
    Cleanup,
}

/// One C++ catch or cleanup handler.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatchHandler {
    pub metadata: HandlerMetadata,
    pub object_displacement: Option<AddressDelta>,
    pub selector: CatchSelector,
}

/// Semantic SEH disposition used when no filter regions are present.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SehDisposition {
    ContinueExecution,
    ContinueSearch,
    ExecuteHandler,
}

/// One structured-exception handler.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SehHandler {
    pub metadata: HandlerMetadata,
    pub filter_regions: Vec<Range>,
    pub disposition: Option<SehDisposition>,
}

/// Closed C++ or SEH handler payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandlerSet {
    Cpp(Vec<CatchHandler>),
    Seh(SehHandler),
}

/// Input definition for one exception region.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockDefinition {
    pub protected_regions: Vec<Range>,
    pub handlers: HandlerSet,
}

/// Retrieved exception region with the host-calculated nesting level.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block {
    pub definition: BlockDefinition,
    pub nesting_level: u8,
}

/// Semantic address-membership class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Location {
    CppTry,
    CppHandler,
    SehTry,
    SehHandler,
    SehFilter,
    Any,
    UnwindFallthrough,
}

fn raw_ranges(ranges: &[Range]) -> Vec<idax_sys::IdaxExceptionRange> {
    ranges
        .iter()
        .map(|range| idax_sys::IdaxExceptionRange {
            start: range.start,
            end: range.end,
        })
        .collect()
}

fn metadata_raw(
    metadata: &HandlerMetadata,
    regions: &mut [idax_sys::IdaxExceptionRange],
) -> idax_sys::IdaxExceptionHandlerMetadata {
    idax_sys::IdaxExceptionHandlerMetadata {
        regions: regions.as_mut_ptr(),
        regions_count: regions.len(),
        has_stack_displacement: metadata.stack_displacement.is_some() as i32,
        stack_displacement: metadata.stack_displacement.unwrap_or_default(),
        has_frame_register: metadata.frame_register.is_some() as i32,
        frame_register: metadata.frame_register.unwrap_or_default(),
    }
}

unsafe fn ranges_from_raw(
    ranges: *const idax_sys::IdaxExceptionRange,
    count: usize,
) -> Result<Vec<Range>> {
    if count != 0 && ranges.is_null() {
        return Err(Error::validation("exception range pointer is null"));
    }
    let slice = if count == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(ranges, count) }
    };
    Ok(slice
        .iter()
        .map(|range| Range::new(range.start, range.end))
        .collect())
}

unsafe fn metadata_from_raw(
    raw: &idax_sys::IdaxExceptionHandlerMetadata,
) -> Result<HandlerMetadata> {
    Ok(HandlerMetadata {
        regions: unsafe { ranges_from_raw(raw.regions, raw.regions_count)? },
        stack_displacement: (raw.has_stack_displacement != 0).then_some(raw.stack_displacement),
        frame_register: (raw.has_frame_register != 0).then_some(raw.frame_register),
    })
}

unsafe fn definition_from_raw(
    raw: &idax_sys::IdaxExceptionBlockDefinition,
) -> Result<BlockDefinition> {
    let protected_regions =
        unsafe { ranges_from_raw(raw.protected_regions, raw.protected_regions_count)? };
    let handlers = match raw.handler_kind {
        0 => {
            if raw.catches_count != 0 && raw.catches.is_null() {
                return Err(Error::validation("exception catch pointer is null"));
            }
            let catches = if raw.catches_count == 0 {
                &[]
            } else {
                unsafe { std::slice::from_raw_parts(raw.catches, raw.catches_count) }
            };
            let mut result = Vec::with_capacity(catches.len());
            for item in catches {
                let selector = match item.selector_kind {
                    0 if item.type_identifier >= 0 => CatchSelector::Typed(item.type_identifier),
                    0 => return Err(Error::validation("negative typed catch identifier")),
                    1 if item.type_identifier == 0 => CatchSelector::CatchAll,
                    2 if item.type_identifier == 0 => CatchSelector::Cleanup,
                    _ => return Err(Error::validation("invalid C++ catch selector")),
                };
                result.push(CatchHandler {
                    metadata: unsafe { metadata_from_raw(&item.metadata)? },
                    object_displacement: (item.has_object_displacement != 0)
                        .then_some(item.object_displacement),
                    selector,
                });
            }
            HandlerSet::Cpp(result)
        }
        1 => {
            let disposition = if raw.seh.has_disposition == 0 {
                None
            } else {
                Some(match raw.seh.disposition {
                    -1 => SehDisposition::ContinueExecution,
                    0 => SehDisposition::ContinueSearch,
                    1 => SehDisposition::ExecuteHandler,
                    _ => return Err(Error::validation("invalid SEH disposition")),
                })
            };
            HandlerSet::Seh(SehHandler {
                metadata: unsafe { metadata_from_raw(&raw.seh.metadata)? },
                filter_regions: unsafe {
                    ranges_from_raw(raw.seh.filter_regions, raw.seh.filter_regions_count)?
                },
                disposition,
            })
        }
        _ => return Err(Error::validation("invalid exception handler kind")),
    };
    Ok(BlockDefinition {
        protected_regions,
        handlers,
    })
}

/// Retrieve exception regions intersecting a half-open range.
pub fn list(range: Range) -> Result<Vec<Block>> {
    let mut blocks = ptr::null_mut();
    let mut count = 0usize;
    let status =
        unsafe { idax_sys::idax_exception_list(range.start, range.end, &mut blocks, &mut count) };
    if status != 0 {
        return Err(error::consume_last_error("exception::list failed"));
    }
    let converted = (|| {
        if count != 0 && blocks.is_null() {
            return Err(Error::validation("exception block pointer is null"));
        }
        let raw = if count == 0 {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(blocks, count) }
        };
        raw.iter()
            .map(|block| unsafe {
                Ok(Block {
                    definition: definition_from_raw(&block.definition)?,
                    nesting_level: block.nesting_level,
                })
            })
            .collect()
    })();
    unsafe { idax_sys::idax_exception_blocks_free(blocks, count) };
    converted
}

/// Delete all exception records intersecting a half-open range.
pub fn remove(range: Range) -> Status {
    error::int_to_status(
        unsafe { idax_sys::idax_exception_remove(range.start, range.end) },
        "exception::remove failed",
    )
}

/// Add one validated C++ or SEH exception-region definition.
pub fn add(definition: &BlockDefinition) -> Status {
    let mut protected_regions = raw_ranges(&definition.protected_regions);
    let mut raw = idax_sys::IdaxExceptionBlockDefinition {
        protected_regions: protected_regions.as_mut_ptr(),
        protected_regions_count: protected_regions.len(),
        ..Default::default()
    };

    let mut catch_regions: Vec<Vec<idax_sys::IdaxExceptionRange>> = Vec::new();
    let mut raw_catches: Vec<idax_sys::IdaxExceptionCatchHandler> = Vec::new();
    let mut seh_regions = Vec::new();
    let mut filter_regions = Vec::new();
    match &definition.handlers {
        HandlerSet::Cpp(catches) => {
            raw.handler_kind = 0;
            catch_regions = catches
                .iter()
                .map(|handler| raw_ranges(&handler.metadata.regions))
                .collect();
            raw_catches = catches
                .iter()
                .zip(catch_regions.iter_mut())
                .map(|(handler, regions)| {
                    let (selector_kind, type_identifier) = match handler.selector {
                        CatchSelector::Typed(identifier) => (0, identifier),
                        CatchSelector::CatchAll => (1, 0),
                        CatchSelector::Cleanup => (2, 0),
                    };
                    idax_sys::IdaxExceptionCatchHandler {
                        metadata: metadata_raw(&handler.metadata, regions),
                        has_object_displacement: handler.object_displacement.is_some() as i32,
                        object_displacement: handler.object_displacement.unwrap_or_default(),
                        selector_kind,
                        type_identifier,
                    }
                })
                .collect();
            raw.catches = raw_catches.as_mut_ptr();
            raw.catches_count = raw_catches.len();
        }
        HandlerSet::Seh(handler) => {
            raw.handler_kind = 1;
            seh_regions = raw_ranges(&handler.metadata.regions);
            filter_regions = raw_ranges(&handler.filter_regions);
            let disposition = match handler.disposition {
                None => 0,
                Some(SehDisposition::ContinueExecution) => -1,
                Some(SehDisposition::ContinueSearch) => 0,
                Some(SehDisposition::ExecuteHandler) => 1,
            };
            raw.seh = idax_sys::IdaxExceptionSehHandler {
                metadata: metadata_raw(&handler.metadata, &mut seh_regions),
                filter_regions: filter_regions.as_mut_ptr(),
                filter_regions_count: filter_regions.len(),
                has_disposition: handler.disposition.is_some() as i32,
                disposition,
            };
        }
    }
    let status = unsafe { idax_sys::idax_exception_add(&raw) };
    // These owners intentionally remain live through the FFI call.
    let _ = (&catch_regions, &raw_catches, &seh_regions, &filter_regions);
    error::int_to_status(status, "exception::add failed")
}

/// Find the start of a surrounding system exception-handling region.
pub fn system_region_start(address: Address) -> Result<Option<Address>> {
    let mut out = 0;
    let mut has_value = 0;
    let status =
        unsafe { idax_sys::idax_exception_system_region_start(address, &mut out, &mut has_value) };
    if status != 0 {
        Err(error::consume_last_error(
            "exception::system_region_start failed",
        ))
    } else {
        Ok((has_value != 0).then_some(out))
    }
}

/// Test an address against one or more semantic exception-location classes.
pub fn contains(address: Address, locations: &[Location]) -> Result<bool> {
    let mut bits = 0u32;
    for location in locations {
        bits |= match location {
            Location::CppTry => 0x01,
            Location::CppHandler => 0x02,
            Location::SehTry => 0x04,
            Location::SehHandler => 0x08,
            Location::SehFilter => 0x10,
            Location::Any => 0x1f,
            Location::UnwindFallthrough => 0x20,
        };
    }
    let mut out = 0;
    let status = unsafe { idax_sys::idax_exception_contains(address, bits, &mut out) };
    if status != 0 {
        Err(error::consume_last_error("exception::contains failed"))
    } else {
        Ok(out != 0)
    }
}

/// Test an address against all ordinary exception-location classes.
pub fn contains_any(address: Address) -> Result<bool> {
    contains(address, &[Location::Any])
}

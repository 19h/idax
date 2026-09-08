//! Apple dyld shared-cache inventory and incremental loading.
use std::ffi::CString;
use crate::{Address, error::{self, Error, Result, Status}};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleInfo {
    pub path: String,
    pub load_address: Address,
}

pub fn is_available() -> Result<bool> {
    let mut out = 0;
    let rc = unsafe { idax_sys::idax_dyld_cache_is_available(&mut out) };
    if rc != 0 { return Err(error::consume_last_error("dyld_cache::is_available failed")); }
    Ok(out != 0)
}

fn inventory(path: Option<&str>) -> Result<Vec<ModuleInfo>> {
    let path = path.map(CString::new).transpose().map_err(|_| Error::validation("cache path contains NUL"))?;
    let mut out = std::ptr::null_mut();
    let mut count = 0;
    unsafe {
        let rc = match path {
            Some(path) => idax_sys::idax_dyld_cache_list_modules_from_file(path.as_ptr(), &mut out, &mut count),
            None => idax_sys::idax_dyld_cache_list_modules(&mut out, &mut count),
        };
        if rc != 0 { return Err(error::consume_last_error("dyld_cache::list_modules failed")); }
        let result = (|| {
            if count == 0 { return Ok(Vec::new()); }
            if out.is_null() || count > isize::MAX as usize / std::mem::size_of::<idax_sys::IdaxDyldCacheModuleInfo>() {
                return Err(Error::internal("invalid dyld cache inventory"));
            }
            std::slice::from_raw_parts(out, count).iter().map(|module| Ok(ModuleInfo {
                path: error::cstr_to_string(module.path, "invalid dyld cache image path")?,
                load_address: module.load_address,
            })).collect()
        })();
        idax_sys::idax_dyld_cache_modules_free(out, count);
        result
    }
}

pub fn list_modules() -> Result<Vec<ModuleInfo>> { inventory(None) }
pub fn list_modules_from_file(path: &str) -> Result<Vec<ModuleInfo>> { inventory(Some(path)) }

pub fn load_module(path: &str, wait_for_analysis: bool) -> Status {
    let path = CString::new(path).map_err(|_| Error::validation("module path contains NUL"))?;
    error::int_to_status(unsafe { idax_sys::idax_dyld_cache_load_module(path.as_ptr(), wait_for_analysis as i32) }, "dyld_cache load failed")
}
pub fn load_section(address: Address, wait_for_analysis: bool) -> Status {
    error::int_to_status(unsafe { idax_sys::idax_dyld_cache_load_section(address, wait_for_analysis as i32) }, "dyld_cache load failed")
}
pub fn load_dyld_header(wait_for_analysis: bool) -> Status {
    error::int_to_status(unsafe { idax_sys::idax_dyld_cache_load_dyld_header(wait_for_analysis as i32) }, "dyld_cache load failed")
}

/// Return the number of unique previously unloaded entities loaded.
pub fn load_branch_islands(wait_for_analysis: bool) -> Result<usize> {
    let mut out = 0;
    let rc = unsafe { idax_sys::idax_dyld_cache_load_branch_islands(wait_for_analysis as i32, &mut out) };
    if rc != 0 { return Err(error::consume_last_error("dyld_cache::load_branch_islands failed")); }
    Ok(out)
}

/// Return the number of unique previously unloaded entities loaded.
pub fn load_branch_mappings(wait_for_analysis: bool) -> Result<usize> {
    let mut out = 0;
    let rc = unsafe { idax_sys::idax_dyld_cache_load_branch_mappings(wait_for_analysis as i32, &mut out) };
    if rc != 0 { return Err(error::consume_last_error("dyld_cache::load_branch_mappings failed")); }
    Ok(out)
}

/// Return the number of unique previously unloaded entities loaded.
pub fn load_global_offset_tables(wait_for_analysis: bool) -> Result<usize> {
    let mut out = 0;
    let rc = unsafe { idax_sys::idax_dyld_cache_load_global_offset_tables(wait_for_analysis as i32, &mut out) };
    if rc != 0 { return Err(error::consume_last_error("dyld_cache::load_global_offset_tables failed")); }
    Ok(out)
}

/// Return the number of unique previously unloaded entities loaded.
pub fn load_gaps(wait_for_analysis: bool) -> Result<usize> {
    let mut out = 0;
    let rc = unsafe { idax_sys::idax_dyld_cache_load_gaps(wait_for_analysis as i32, &mut out) };
    if rc != 0 { return Err(error::consume_last_error("dyld_cache::load_gaps failed")); }
    Ok(out)
}

/// Return the number of unique previously unloaded entities loaded.
pub fn load_cache_data(wait_for_analysis: bool) -> Result<usize> {
    let mut out = 0;
    let rc = unsafe { idax_sys::idax_dyld_cache_load_cache_data(wait_for_analysis as i32, &mut out) };
    if rc != 0 { return Err(error::consume_last_error("dyld_cache::load_cache_data failed")); }
    Ok(out)
}

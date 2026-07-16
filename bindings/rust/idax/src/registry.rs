//! Opaque scoped access to persistent IDA plugin configuration.

use std::ffi::{CStr, CString};

use crate::error::{self, Error, Result, Status};

/// Semantic registry value kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum ValueKind {
    String = 1,
    Binary = 3,
    Integer = 4,
}

/// One deterministic ordered string-list update.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StringListUpdate {
    pub add: Option<String>,
    pub remove: Option<String>,
    pub max_records: usize,
    pub ignore_case: bool,
}

impl Default for StringListUpdate {
    fn default() -> Self {
        Self {
            add: None,
            remove: None,
            max_records: 100,
            ignore_case: false,
        }
    }
}

/// Copyable-by-value semantic store identity with no retained native pointer.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Store {
    key: String,
}

impl Store {
    /// Open a nonempty scoped key. The key need not exist yet.
    pub fn open(key: &str) -> Result<Self> {
        let key_c = cstring(key, "registry key")?;
        let status = unsafe { idax_sys::idax_registry_open(key_c.as_ptr()) };
        error::int_to_status(status, "registry::Store::open failed")?;
        Ok(Self { key: key.into() })
    }

    #[must_use]
    pub fn key(&self) -> &str {
        &self.key
    }

    pub fn child(&self, name: &str) -> Result<Self> {
        let key = self.key_c()?;
        let name = cstring(name, "registry child name")?;
        let mut out = std::ptr::null_mut();
        let status =
            unsafe { idax_sys::idax_registry_child(key.as_ptr(), name.as_ptr(), &mut out) };
        if status != 0 {
            return Err(error::consume_last_error("registry::Store::child failed"));
        }
        let key = unsafe { error::cstr_to_string_free(out, "registry child key is null")? };
        Ok(Self { key })
    }

    pub fn exists(&self) -> Result<bool> {
        self.store_bool(
            idax_sys::idax_registry_exists,
            "registry::Store::exists failed",
        )
    }

    pub fn child_keys(&self) -> Result<Vec<String>> {
        self.string_array(
            idax_sys::idax_registry_child_keys,
            "registry::Store::child_keys failed",
        )
    }

    pub fn value_names(&self) -> Result<Vec<String>> {
        self.string_array(
            idax_sys::idax_registry_value_names,
            "registry::Store::value_names failed",
        )
    }

    pub fn contains(&self, name: &str) -> Result<bool> {
        self.named_bool(
            name,
            idax_sys::idax_registry_contains,
            "registry::Store::contains failed",
        )
    }

    pub fn value_kind(&self, name: &str) -> Result<Option<ValueKind>> {
        let key = self.key_c()?;
        let name = cstring(name, "registry value name")?;
        let mut has_value = 0;
        let mut out = 0;
        let status = unsafe {
            idax_sys::idax_registry_value_kind(
                key.as_ptr(),
                name.as_ptr(),
                &mut has_value,
                &mut out,
            )
        };
        if status != 0 {
            return Err(error::consume_last_error(
                "registry::Store::value_kind failed",
            ));
        }
        if has_value == 0 {
            return Ok(None);
        }
        match out {
            1 => Ok(Some(ValueKind::String)),
            3 => Ok(Some(ValueKind::Binary)),
            4 => Ok(Some(ValueKind::Integer)),
            value => Err(Error::internal(format!(
                "Unknown registry value kind {value}"
            ))),
        }
    }

    pub fn read_string(&self, name: &str) -> Result<Option<String>> {
        let key = self.key_c()?;
        let name = cstring(name, "registry value name")?;
        let mut has_value = 0;
        let mut out = std::ptr::null_mut();
        let status = unsafe {
            idax_sys::idax_registry_read_string(
                key.as_ptr(),
                name.as_ptr(),
                &mut has_value,
                &mut out,
            )
        };
        if status != 0 {
            return Err(error::consume_last_error(
                "registry::Store::read_string failed",
            ));
        }
        if has_value == 0 {
            return Ok(None);
        }
        unsafe { error::cstr_to_string_free(out, "registry string is null").map(Some) }
    }

    pub fn write_string(&self, name: &str, value: &str) -> Status {
        let key = self.key_c()?;
        let name = cstring(name, "registry value name")?;
        let value = cstring(value, "registry string")?;
        let status = unsafe {
            idax_sys::idax_registry_write_string(key.as_ptr(), name.as_ptr(), value.as_ptr())
        };
        error::int_to_status(status, "registry::Store::write_string failed")
    }

    pub fn read_binary(&self, name: &str) -> Result<Option<Vec<u8>>> {
        let key = self.key_c()?;
        let name = cstring(name, "registry value name")?;
        let mut has_value = 0;
        let mut out = std::ptr::null_mut();
        let mut count = 0;
        let status = unsafe {
            idax_sys::idax_registry_read_binary(
                key.as_ptr(),
                name.as_ptr(),
                &mut has_value,
                &mut out,
                &mut count,
            )
        };
        if status != 0 {
            return Err(error::consume_last_error(
                "registry::Store::read_binary failed",
            ));
        }
        if has_value == 0 {
            return Ok(None);
        }
        let result = if count == 0 {
            Ok(Vec::new())
        } else if out.is_null() {
            Err(Error::internal("Registry binary pointer is null"))
        } else {
            Ok(unsafe { std::slice::from_raw_parts(out, count) }.to_vec())
        };
        unsafe { idax_sys::idax_free_bytes(out) };
        result.map(Some)
    }

    pub fn write_binary(&self, name: &str, value: &[u8]) -> Status {
        let key = self.key_c()?;
        let name = cstring(name, "registry value name")?;
        let status = unsafe {
            idax_sys::idax_registry_write_binary(
                key.as_ptr(),
                name.as_ptr(),
                value.as_ptr(),
                value.len(),
            )
        };
        error::int_to_status(status, "registry::Store::write_binary failed")
    }

    pub fn read_integer(&self, name: &str) -> Result<Option<i32>> {
        let key = self.key_c()?;
        let name = cstring(name, "registry value name")?;
        let mut has_value = 0;
        let mut out = 0;
        let status = unsafe {
            idax_sys::idax_registry_read_integer(
                key.as_ptr(),
                name.as_ptr(),
                &mut has_value,
                &mut out,
            )
        };
        if status == 0 {
            Ok((has_value != 0).then_some(out))
        } else {
            Err(error::consume_last_error(
                "registry::Store::read_integer failed",
            ))
        }
    }

    pub fn write_integer(&self, name: &str, value: i32) -> Status {
        let key = self.key_c()?;
        let name = cstring(name, "registry value name")?;
        let status =
            unsafe { idax_sys::idax_registry_write_integer(key.as_ptr(), name.as_ptr(), value) };
        error::int_to_status(status, "registry::Store::write_integer failed")
    }

    pub fn read_boolean(&self, name: &str) -> Result<Option<bool>> {
        let key = self.key_c()?;
        let name = cstring(name, "registry value name")?;
        let mut has_value = 0;
        let mut out = 0;
        let status = unsafe {
            idax_sys::idax_registry_read_boolean(
                key.as_ptr(),
                name.as_ptr(),
                &mut has_value,
                &mut out,
            )
        };
        if status == 0 {
            Ok((has_value != 0).then_some(out != 0))
        } else {
            Err(error::consume_last_error(
                "registry::Store::read_boolean failed",
            ))
        }
    }

    pub fn write_boolean(&self, name: &str, value: bool) -> Status {
        let key = self.key_c()?;
        let name = cstring(name, "registry value name")?;
        let status = unsafe {
            idax_sys::idax_registry_write_boolean(key.as_ptr(), name.as_ptr(), value.into())
        };
        error::int_to_status(status, "registry::Store::write_boolean failed")
    }

    pub fn erase_value(&self, name: &str) -> Result<bool> {
        self.named_bool(
            name,
            idax_sys::idax_registry_erase_value,
            "registry::Store::erase_value failed",
        )
    }

    pub fn erase_key(&self) -> Result<bool> {
        self.store_bool(
            idax_sys::idax_registry_erase_key,
            "registry::Store::erase_key failed",
        )
    }

    pub fn erase_tree(&self) -> Result<bool> {
        self.store_bool(
            idax_sys::idax_registry_erase_tree,
            "registry::Store::erase_tree failed",
        )
    }

    pub fn read_string_list(&self) -> Result<Vec<String>> {
        self.string_array(
            idax_sys::idax_registry_read_string_list,
            "registry::Store::read_string_list failed",
        )
    }

    pub fn write_string_list(&self, values: &[impl AsRef<str>]) -> Status {
        let key = self.key_c()?;
        let values = values
            .iter()
            .map(|value| cstring(value.as_ref(), "registry list value"))
            .collect::<Result<Vec<_>>>()?;
        let pointers: Vec<_> = values.iter().map(|value| value.as_ptr()).collect();
        let status = unsafe {
            idax_sys::idax_registry_write_string_list(
                key.as_ptr(),
                pointers.as_ptr(),
                pointers.len(),
            )
        };
        error::int_to_status(status, "registry::Store::write_string_list failed")
    }

    pub fn update_string_list(&self, update: &StringListUpdate) -> Status {
        let key = self.key_c()?;
        let add = update
            .add
            .as_deref()
            .map(|value| cstring(value, "registry list addition"))
            .transpose()?;
        let remove = update
            .remove
            .as_deref()
            .map(|value| cstring(value, "registry list removal"))
            .transpose()?;
        let status = unsafe {
            idax_sys::idax_registry_update_string_list(
                key.as_ptr(),
                add.as_ref()
                    .map_or(std::ptr::null(), |value| value.as_ptr()),
                remove
                    .as_ref()
                    .map_or(std::ptr::null(), |value| value.as_ptr()),
                update.max_records,
                update.ignore_case.into(),
            )
        };
        error::int_to_status(status, "registry::Store::update_string_list failed")
    }

    fn key_c(&self) -> Result<CString> {
        cstring(&self.key, "registry key")
    }

    fn store_bool(
        &self,
        function: unsafe extern "C" fn(*const std::ffi::c_char, *mut i32) -> i32,
        fallback: &str,
    ) -> Result<bool> {
        let key = self.key_c()?;
        let mut out = 0;
        let status = unsafe { function(key.as_ptr(), &mut out) };
        if status == 0 {
            Ok(out != 0)
        } else {
            Err(error::consume_last_error(fallback))
        }
    }

    fn named_bool(
        &self,
        name: &str,
        function: unsafe extern "C" fn(
            *const std::ffi::c_char,
            *const std::ffi::c_char,
            *mut i32,
        ) -> i32,
        fallback: &str,
    ) -> Result<bool> {
        let key = self.key_c()?;
        let name = cstring(name, "registry value name")?;
        let mut out = 0;
        let status = unsafe { function(key.as_ptr(), name.as_ptr(), &mut out) };
        if status == 0 {
            Ok(out != 0)
        } else {
            Err(error::consume_last_error(fallback))
        }
    }

    fn string_array(
        &self,
        function: unsafe extern "C" fn(
            *const std::ffi::c_char,
            *mut *mut *mut std::ffi::c_char,
            *mut usize,
        ) -> i32,
        fallback: &str,
    ) -> Result<Vec<String>> {
        let key = self.key_c()?;
        let mut out = std::ptr::null_mut();
        let mut count = 0;
        let status = unsafe { function(key.as_ptr(), &mut out, &mut count) };
        if status != 0 {
            return Err(error::consume_last_error(fallback));
        }
        let result = if count == 0 {
            Ok(Vec::new())
        } else if out.is_null() {
            Err(Error::internal("Registry string-array pointer is null"))
        } else {
            unsafe { std::slice::from_raw_parts(out, count) }
                .iter()
                .map(|pointer| {
                    if pointer.is_null() {
                        Err(Error::internal("Registry string pointer is null"))
                    } else {
                        Ok(unsafe { CStr::from_ptr(*pointer) }
                            .to_string_lossy()
                            .into_owned())
                    }
                })
                .collect()
        };
        unsafe { idax_sys::idax_registry_strings_free(out, count) };
        result
    }
}

fn cstring(value: &str, field: &str) -> Result<CString> {
    CString::new(value)
        .map_err(|_| Error::validation(format!("{field} contains an embedded NUL byte")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn value_kinds_and_defaults_are_stable() {
        assert_eq!(ValueKind::String as i32, 1);
        assert_eq!(ValueKind::Binary as i32, 3);
        assert_eq!(ValueKind::Integer as i32, 4);
        let update = StringListUpdate::default();
        assert_eq!(update.max_records, 100);
        assert!(!update.ignore_case);
    }

    #[test]
    fn embedded_nul_is_rejected_before_ffi() {
        let error = Store::open("bad\0key").unwrap_err();
        assert_eq!(error.category, crate::error::ErrorCategory::Validation);
    }
}

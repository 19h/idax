//! Opaque access to IDA's host-owned standard database directory trees.

use std::ffi::{CStr, CString};

use crate::error::{self, Error, Result, Status};

/// One built-in database organization tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum Kind {
    LocalTypes = 0,
    Functions = 1,
    Names = 2,
    Imports = 3,
    IdaPlaceBookmarks = 4,
    Breakpoints = 5,
    LocalTypeBookmarks = 6,
    Snippets = 7,
}

/// Semantic kind of one copied tree entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EntryKind {
    Directory,
    Item,
}

/// Stable semantic result for one failed bulk source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum OperationError {
    AlreadyExists = 1,
    NotFound = 2,
    NotDirectory = 3,
    NotEmpty = 4,
    BadPath = 5,
    CannotRename = 6,
    OwnChild = 7,
    DirectoryLimit = 8,
    NotOrderable = 9,
    SdkFailure = 10,
}

/// Owned snapshot of one directory or item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub path: String,
    pub name: String,
    pub display_name: String,
    pub attributes: String,
    pub kind: EntryKind,
}

impl Entry {
    #[must_use]
    pub const fn is_directory(&self) -> bool {
        matches!(self.kind, EntryKind::Directory)
    }
}

/// One source-specific failure from a partial bulk operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BulkFailure {
    pub input_index: usize,
    pub path: String,
    pub error: OperationError,
    pub message: String,
}

/// Deterministic mixed-success report for a bulk operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BulkReport {
    pub affected_paths: Vec<String>,
    pub failures: Vec<BulkFailure>,
}

impl BulkReport {
    #[must_use]
    pub fn is_ok(&self) -> bool {
        self.failures.is_empty()
    }
}

/// Copyable semantic handle. No native pointer is retained.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Tree {
    kind: Kind,
}

impl Tree {
    /// Acquire one standard tree in the current initialized database.
    pub fn open(kind: Kind) -> Result<Self> {
        let status = unsafe { idax_sys::idax_directory_open(kind as i32) };
        error::int_to_status(status, "directory::Tree::open failed")?;
        Ok(Self { kind })
    }

    #[must_use]
    pub const fn kind(self) -> Kind {
        self.kind
    }

    pub fn is_orderable(self) -> Result<bool> {
        self.bool_result(
            |out| unsafe { idax_sys::idax_directory_is_orderable(self.kind as i32, out) },
            "directory::Tree::is_orderable failed",
        )
    }

    pub fn current_directory(self) -> Result<String> {
        self.string_result(
            |out| unsafe { idax_sys::idax_directory_current_directory(self.kind as i32, out) },
            "directory::Tree::current_directory failed",
        )
    }

    pub fn change_directory(self, path: &str) -> Status {
        self.path_status(
            path,
            "directory path",
            |pointer| unsafe {
                idax_sys::idax_directory_change_directory(self.kind as i32, pointer)
            },
            "directory::Tree::change_directory failed",
        )
    }

    pub fn absolute_path(self, relative_path: &str) -> Result<String> {
        let path = cstring(relative_path, "directory relative path")?;
        self.string_result(
            |out| unsafe {
                idax_sys::idax_directory_absolute_path(self.kind as i32, path.as_ptr(), out)
            },
            "directory::Tree::absolute_path failed",
        )
    }

    pub fn contains(self, path: &str) -> Result<bool> {
        let path = cstring(path, "directory path")?;
        self.bool_result(
            |out| unsafe {
                idax_sys::idax_directory_contains(self.kind as i32, path.as_ptr(), out)
            },
            "directory::Tree::contains failed",
        )
    }

    pub fn entry(self, path: &str) -> Result<Entry> {
        let path = cstring(path, "directory path")?;
        let mut raw = idax_sys::IdaxDirectoryEntry::default();
        let status =
            unsafe { idax_sys::idax_directory_entry(self.kind as i32, path.as_ptr(), &mut raw) };
        if status != 0 {
            return Err(error::consume_last_error("directory::Tree::entry failed"));
        }
        let result = unsafe { entry_from_raw(&raw) };
        unsafe { idax_sys::idax_directory_entry_free(&mut raw) };
        result
    }

    pub fn children(self, path: &str) -> Result<Vec<Entry>> {
        self.entry_list(path, false)
    }

    pub fn snapshot(self, path: &str) -> Result<Vec<Entry>> {
        self.entry_list(path, true)
    }

    pub fn find_items(self, pattern: &str) -> Result<Vec<Entry>> {
        let pattern = cstring(pattern, "directory search pattern")?;
        let mut raw = std::ptr::null_mut();
        let mut count = 0;
        let status = unsafe {
            idax_sys::idax_directory_find_items(
                self.kind as i32,
                pattern.as_ptr(),
                &mut raw,
                &mut count,
            )
        };
        entries_result(status, raw, count, "directory::Tree::find_items failed")
    }

    pub fn create_directory(self, path: &str) -> Status {
        self.path_status(
            path,
            "directory path",
            |pointer| unsafe {
                idax_sys::idax_directory_create_directory(self.kind as i32, pointer)
            },
            "directory::Tree::create_directory failed",
        )
    }

    pub fn remove_directory(self, path: &str) -> Status {
        self.path_status(
            path,
            "directory path",
            |pointer| unsafe {
                idax_sys::idax_directory_remove_directory(self.kind as i32, pointer)
            },
            "directory::Tree::remove_directory failed",
        )
    }

    pub fn link(self, path: &str) -> Status {
        self.path_status(
            path,
            "directory item path",
            |pointer| unsafe { idax_sys::idax_directory_link(self.kind as i32, pointer) },
            "directory::Tree::link failed",
        )
    }

    pub fn unlink(self, path: &str) -> Status {
        self.path_status(
            path,
            "directory item path",
            |pointer| unsafe { idax_sys::idax_directory_unlink(self.kind as i32, pointer) },
            "directory::Tree::unlink failed",
        )
    }

    pub fn rename(self, from: &str, to: &str) -> Status {
        let from = cstring(from, "source directory path")?;
        let to = cstring(to, "destination directory path")?;
        let status = unsafe {
            idax_sys::idax_directory_rename(self.kind as i32, from.as_ptr(), to.as_ptr())
        };
        error::int_to_status(status, "directory::Tree::rename failed")
    }

    pub fn fold_common_prefix(self, path: &str) -> Status {
        self.path_status(
            path,
            "directory path",
            |pointer| unsafe {
                idax_sys::idax_directory_fold_common_prefix(self.kind as i32, pointer)
            },
            "directory::Tree::fold_common_prefix failed",
        )
    }

    pub fn has_natural_order(self, directory_path: &str) -> Result<bool> {
        let path = cstring(directory_path, "directory path")?;
        self.bool_result(
            |out| unsafe {
                idax_sys::idax_directory_has_natural_order(self.kind as i32, path.as_ptr(), out)
            },
            "directory::Tree::has_natural_order failed",
        )
    }

    pub fn set_natural_order(self, directory_path: &str, enable: bool) -> Status {
        let path = cstring(directory_path, "directory path")?;
        let status = unsafe {
            idax_sys::idax_directory_set_natural_order(
                self.kind as i32,
                path.as_ptr(),
                enable as i32,
            )
        };
        error::int_to_status(status, "directory::Tree::set_natural_order failed")
    }

    pub fn rank(self, path: &str) -> Result<usize> {
        let path = cstring(path, "directory path")?;
        let mut out = 0;
        let status =
            unsafe { idax_sys::idax_directory_rank(self.kind as i32, path.as_ptr(), &mut out) };
        if status == 0 {
            Ok(out)
        } else {
            Err(error::consume_last_error("directory::Tree::rank failed"))
        }
    }

    pub fn change_rank(self, path: &str, delta: isize) -> Status {
        let path = cstring(path, "directory path")?;
        let status =
            unsafe { idax_sys::idax_directory_change_rank(self.kind as i32, path.as_ptr(), delta) };
        error::int_to_status(status, "directory::Tree::change_rank failed")
    }

    pub fn move_entries(
        self,
        paths: &[impl AsRef<str>],
        destination_directory: &str,
        destination_rank: Option<usize>,
    ) -> Result<BulkReport> {
        let paths = cstring_paths(paths)?;
        let pointers: Vec<_> = paths.iter().map(|path| path.as_ptr()).collect();
        let destination = cstring(destination_directory, "destination directory path")?;
        let mut raw = idax_sys::IdaxDirectoryBulkReport::default();
        let status = unsafe {
            idax_sys::idax_directory_move(
                self.kind as i32,
                pointers.as_ptr(),
                pointers.len(),
                destination.as_ptr(),
                destination_rank.is_some() as i32,
                destination_rank.unwrap_or_default(),
                &mut raw,
            )
        };
        bulk_result(status, &mut raw, "directory::Tree::move_entries failed")
    }

    pub fn remove_entries(self, paths: &[impl AsRef<str>]) -> Result<BulkReport> {
        let paths = cstring_paths(paths)?;
        let pointers: Vec<_> = paths.iter().map(|path| path.as_ptr()).collect();
        let mut raw = idax_sys::IdaxDirectoryBulkReport::default();
        let status = unsafe {
            idax_sys::idax_directory_remove(
                self.kind as i32,
                pointers.as_ptr(),
                pointers.len(),
                &mut raw,
            )
        };
        bulk_result(status, &mut raw, "directory::Tree::remove_entries failed")
    }

    fn entry_list(self, path: &str, recursive: bool) -> Result<Vec<Entry>> {
        let path = cstring(path, "directory path")?;
        let mut raw = std::ptr::null_mut();
        let mut count = 0;
        let status = unsafe {
            if recursive {
                idax_sys::idax_directory_snapshot(
                    self.kind as i32,
                    path.as_ptr(),
                    &mut raw,
                    &mut count,
                )
            } else {
                idax_sys::idax_directory_children(
                    self.kind as i32,
                    path.as_ptr(),
                    &mut raw,
                    &mut count,
                )
            }
        };
        entries_result(status, raw, count, "directory::Tree entry list failed")
    }

    fn path_status(
        self,
        path: &str,
        field: &str,
        function: impl FnOnce(*const std::ffi::c_char) -> i32,
        fallback: &str,
    ) -> Status {
        let path = cstring(path, field)?;
        error::int_to_status(function(path.as_ptr()), fallback)
    }

    fn bool_result(self, function: impl FnOnce(*mut i32) -> i32, fallback: &str) -> Result<bool> {
        let mut out = 0;
        let status = function(&mut out);
        if status == 0 {
            Ok(out != 0)
        } else {
            Err(error::consume_last_error(fallback))
        }
    }

    fn string_result(
        self,
        function: impl FnOnce(*mut *mut std::ffi::c_char) -> i32,
        fallback: &str,
    ) -> Result<String> {
        let mut out = std::ptr::null_mut();
        let status = function(&mut out);
        if status != 0 {
            return Err(error::consume_last_error(fallback));
        }
        unsafe { error::cstr_to_string_free(out, fallback) }
    }
}

fn cstring(value: &str, field: &str) -> Result<CString> {
    CString::new(value)
        .map_err(|_| Error::validation(format!("{field} contains an embedded NUL byte")))
}

fn cstring_paths(paths: &[impl AsRef<str>]) -> Result<Vec<CString>> {
    paths
        .iter()
        .map(|path| cstring(path.as_ref(), "directory path"))
        .collect()
}

unsafe fn copied_string(pointer: *const std::ffi::c_char, field: &str) -> Result<String> {
    if pointer.is_null() {
        return Err(Error::internal(format!(
            "Directory {field} pointer is null"
        )));
    }
    Ok(unsafe { CStr::from_ptr(pointer) }
        .to_string_lossy()
        .into_owned())
}

fn operation_error(value: i32) -> Result<OperationError> {
    match value {
        1 => Ok(OperationError::AlreadyExists),
        2 => Ok(OperationError::NotFound),
        3 => Ok(OperationError::NotDirectory),
        4 => Ok(OperationError::NotEmpty),
        5 => Ok(OperationError::BadPath),
        6 => Ok(OperationError::CannotRename),
        7 => Ok(OperationError::OwnChild),
        8 => Ok(OperationError::DirectoryLimit),
        9 => Ok(OperationError::NotOrderable),
        10 => Ok(OperationError::SdkFailure),
        _ => Err(Error::internal(format!(
            "Unknown directory operation error {value}"
        ))),
    }
}

unsafe fn entry_from_raw(raw: &idax_sys::IdaxDirectoryEntry) -> Result<Entry> {
    let kind = match raw.entry_kind {
        0 => EntryKind::Directory,
        1 => EntryKind::Item,
        value => {
            return Err(Error::internal(format!(
                "Unknown directory entry kind {value}"
            )));
        }
    };
    Ok(Entry {
        path: unsafe { copied_string(raw.path, "entry path")? },
        name: unsafe { copied_string(raw.name, "entry name")? },
        display_name: unsafe { copied_string(raw.display_name, "entry display name")? },
        attributes: unsafe { copied_string(raw.attributes, "entry attributes")? },
        kind,
    })
}

fn entries_result(
    status: i32,
    raw: *mut idax_sys::IdaxDirectoryEntry,
    count: usize,
    fallback: &str,
) -> Result<Vec<Entry>> {
    if status != 0 {
        return Err(error::consume_last_error(fallback));
    }
    let result = if count == 0 {
        Ok(Vec::new())
    } else if raw.is_null() {
        Err(Error::internal("Directory entries pointer is null"))
    } else {
        unsafe { std::slice::from_raw_parts(raw, count) }
            .iter()
            .map(|entry| unsafe { entry_from_raw(entry) })
            .collect()
    };
    unsafe { idax_sys::idax_directory_entries_free(raw, count) };
    result
}

fn bulk_result(
    status: i32,
    raw: &mut idax_sys::IdaxDirectoryBulkReport,
    fallback: &str,
) -> Result<BulkReport> {
    if status != 0 {
        return Err(error::consume_last_error(fallback));
    }
    let result = (|| {
        let affected = if raw.affected_paths_count == 0 {
            &[][..]
        } else if raw.affected_paths.is_null() {
            return Err(Error::internal("Directory affected-paths pointer is null"));
        } else {
            unsafe { std::slice::from_raw_parts(raw.affected_paths, raw.affected_paths_count) }
        };
        let affected_paths = affected
            .iter()
            .map(|pointer| unsafe { copied_string(*pointer, "affected path") })
            .collect::<Result<Vec<_>>>()?;

        let failures = if raw.failures_count == 0 {
            &[][..]
        } else if raw.failures.is_null() {
            return Err(Error::internal("Directory failures pointer is null"));
        } else {
            unsafe { std::slice::from_raw_parts(raw.failures, raw.failures_count) }
        };
        let failures = failures
            .iter()
            .map(|failure| {
                Ok(BulkFailure {
                    input_index: failure.input_index,
                    path: unsafe { copied_string(failure.path, "failure path")? },
                    error: operation_error(failure.operation_error)?,
                    message: unsafe { copied_string(failure.message, "failure message")? },
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(BulkReport {
            affected_paths,
            failures,
        })
    })();
    unsafe { idax_sys::idax_directory_bulk_report_free(raw) };
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discriminants_and_models_are_stable() {
        assert_eq!(Kind::LocalTypes as i32, 0);
        assert_eq!(Kind::Snippets as i32, 7);
        assert_eq!(OperationError::AlreadyExists as i32, 1);
        assert_eq!(OperationError::NotOrderable as i32, 9);
        let entry = Entry {
            path: "/alpha".into(),
            name: "alpha".into(),
            display_name: "alpha".into(),
            attributes: String::new(),
            kind: EntryKind::Directory,
        };
        assert!(entry.is_directory());
        assert!(
            BulkReport {
                affected_paths: vec![],
                failures: vec![]
            }
            .is_ok()
        );
    }

    #[test]
    fn embedded_nul_is_rejected_before_ffi() {
        let tree = Tree {
            kind: Kind::Functions,
        };
        let failure = tree.contains("bad\0path").unwrap_err();
        assert_eq!(failure.category, crate::error::ErrorCategory::Validation);
        let failure = tree
            .move_entries(&["good", "bad\0path"], "/", None)
            .unwrap_err();
        assert_eq!(failure.category, crate::error::ErrorCategory::Validation);
    }
}

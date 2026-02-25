# Tutorial: Rust Safety/Performance Trade-offs and Recovery Playbook

This guide answers a common advanced question: when should you stay on safe
`idax`, when should you drop to raw `idax-sys`, and how do you recover when
the underlying SDK state looks inconsistent.

## 1) Safe `idax` vs raw `idax-sys`

| Situation | Prefer | Why |
|-----------|--------|-----|
| Normal plugin/tool code | `idax` | Safe API, ownership handled, consistent `Result`/`Status` errors |
| Callback-heavy workflows | `idax` | Lifecycle helpers (`ScopedSubscription`, RAII handles) avoid leaks/use-after-free |
| Missing wrapper API needed now | `idax-sys` (small isolated module) | Unblocks parity while keeping most code safe |
| Tight loops where copying is proven bottleneck | `idax-sys` (surgical) | Lets you control allocation/copy behavior directly |

Default rule: start with `idax`, measure, then use `idax-sys` only where
profiling proves a real benefit.

## 2) Safe path (recommended baseline)

```rust
use idax::error::ErrorCategory;
use idax::{analysis, data, database};

struct DatabaseSession;

impl Drop for DatabaseSession {
    fn drop(&mut self) {
        let _ = database::close(false);
    }
}

fn read_window(path: &str, ea: u64, count: u64) -> idax::Result<Vec<u8>> {
    database::init()?;
    database::open(path, true)?;
    let _session = DatabaseSession;
    analysis::wait()?;

    match data::read_bytes(ea, count) {
        Ok(bytes) => Ok(bytes),
        Err(e) if e.category == ErrorCategory::NotFound => Ok(Vec::new()),
        Err(e) => Err(e),
    }
}
```

Benefits:

- No raw pointers in user code.
- Ownership cleanup is automatic.
- Error categories are normalized (`Validation`, `NotFound`, `SdkFailure`, ...).

## 3) Raw path (`idax-sys`) with explicit ownership

If you use raw FFI, you own allocation and cleanup discipline.

```rust
use std::ffi::CStr;
use std::ptr;

unsafe fn read_bytes_raw(ea: u64, count: u64) -> Result<Vec<u8>, String> {
    let mut out: *mut u8 = ptr::null_mut();
    let mut out_len: usize = 0;

    let rc = unsafe { idax_sys::idax_data_read_bytes(ea, count, &mut out, &mut out_len) };
    if rc != 0 {
        let msg_ptr = unsafe { idax_sys::idax_last_error_message() };
        let msg = if msg_ptr.is_null() {
            "idax_data_read_bytes failed".to_string()
        } else {
            unsafe { CStr::from_ptr(msg_ptr) }.to_string_lossy().into_owned()
        };
        return Err(msg);
    }

    let bytes = if out.is_null() || out_len == 0 {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(out, out_len) }.to_vec()
    };

    if !out.is_null() {
        unsafe { idax_sys::idax_free_bytes(out) };
    }

    Ok(bytes)
}
```

Raw FFI ownership checklist:

- `char*` outputs: free with `idax_free_string`.
- Byte buffers (`uint8_t*`): free with `idax_free_bytes`.
- Domain arrays/records: use the corresponding domain `_free()` helper.
- Opaque handles: release with the matching handle free function.

## 4) Handling inconsistent SDK state

Typical symptoms:

- Repeated `SdkFailure`/`Internal` errors from unrelated calls.
- Event/callback behavior becoming inconsistent.
- Decompiler/UI state diverging after mutation-heavy operations.

Use this escalation path:

1. Stop mutating state; switch to read-only probes.
2. Drain analysis queue (`analysis::wait()`).
3. Refresh dirty views (`decompiler::mark_dirty_with_callers`, `ui::refresh_all_views`).
4. Save/close/reopen the database session.
5. If still unstable, restart the process and capture a minimal repro.

```rust
use idax::{analysis, database, decompiler, ui};

fn recover_session(database_path: &str, function_ea: u64) -> idax::Result<()> {
    let _ = analysis::wait();
    let _ = decompiler::mark_dirty_with_callers(function_ea, true);
    ui::refresh_all_views();

    let _ = database::save();
    let _ = database::close(false);

    database::open(database_path, false)?;
    analysis::wait()?;
    Ok(())
}
```

## 5) Practical recommendations

- Keep unsafe FFI inside one small module and expose a safe wrapper around it.
- Prefer copy-then-single-free patterns for returned arrays/records.
- Treat `SdkFailure` and `Internal` as recovery-triggering categories.
- Add regression tests for every raw FFI bridge you keep in production.

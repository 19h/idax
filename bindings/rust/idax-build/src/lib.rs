//! Build script helpers for binary crates using [`idax`](https://crates.io/crates/idax).
//!
//! IDA Pro's dynamic libraries (`libida.dylib`/`libida.so`, `libidalib.dylib`/`libidalib.so`)
//! use `@rpath`-based install names on macOS and require RPATH entries in consuming binaries.
//! Due to Cargo limitations, library crates cannot inject RPATH entries into downstream binaries.
//!
//! This crate bridges that gap. Add it as a **build dependency** and call [`configure`] from
//! your `build.rs`:
//!
//! ```toml
//! # Cargo.toml
//! [build-dependencies]
//! idax-build = "0.2"
//! ```
//!
//! ```rust,ignore
//! // build.rs
//! fn main() {
//!     idax_build::configure();
//! }
//! ```
//!
//! This will automatically:
//! - Read IDA installation paths discovered by `idax-sys` at build time
//! - Emit the appropriate `-Wl,-rpath,...` linker arguments
//! - Respect `$IDADIR` overrides and auto-discovered installations
//!
//! On Windows (which doesn't use RPATH), this is a no-op.
//!
//! # Manual alternative
//!
//! If you prefer not to add a build dependency, you can add this to your `build.rs` directly:
//!
//! ```rust,ignore
//! fn main() {
//!     // Read RPATH directories from idax's build metadata
//!     if let Ok(rpaths) = std::env::var("DEP_IDAX_RT_RPATH_DIRS") {
//!         for rpath in rpaths.split(';').filter(|s| !s.is_empty()) {
//!             println!("cargo:rustc-link-arg=-Wl,-rpath,{}", rpath);
//!         }
//!     }
//! }
//! ```

/// Configure linker settings for an IDA SDK binary.
///
/// Call this from your binary crate's `build.rs` to inject RPATH entries
/// so the dynamic linker can find IDA's shared libraries at runtime.
///
/// This reads `DEP_IDAX_RT_RPATH_DIRS` (set by the `idax` crate's build
/// script via the Cargo `links` metadata system) and emits the appropriate
/// `cargo:rustc-link-arg` directives.
///
/// On Windows, this is a no-op (Windows uses PATH, not RPATH).
///
/// # Example
///
/// ```rust,ignore
/// // build.rs
/// fn main() {
///     idax_build::configure();
/// }
/// ```
pub fn configure() {
    if cfg!(target_os = "windows") {
        return;
    }

    if let Ok(rpaths) = std::env::var("DEP_IDAX_RT_RPATH_DIRS") {
        for rpath in rpaths.split(';').filter(|s| !s.is_empty()) {
            println!("cargo:rustc-link-arg=-Wl,-rpath,{}", rpath);
        }
    }
}

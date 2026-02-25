/// Build script for the `idax` crate.
///
/// This reads RPATH metadata from `idax-sys` (via the Cargo `links` metadata
/// system) and re-exports it so that downstream binary crates can pick it up.
///
/// ## How RPATH propagation works
///
/// Cargo's `rustc-link-arg` directive from a library dependency does NOT
/// propagate to the final binary. The only way to pass linker arguments
/// through the dependency chain is via the `links` metadata system:
///
/// 1. `idax-sys` (links = "idax") discovers IDA installation paths and emits
///    `cargo:RPATH_DIRS=path1;path2;...`
/// 2. This crate (`idax`, links = "idax_rt") reads `DEP_IDAX_RPATH_DIRS` and
///    re-exports it as `cargo:RPATH_DIRS=...`
/// 3. A downstream **binary** crate with a `build.rs` can read
///    `DEP_IDAX_RT_RPATH_DIRS` and emit `cargo:rustc-link-arg=-Wl,-rpath,...`
///
/// For convenience, binary crates that depend on `idax` only need this in
/// their `build.rs`:
///
/// ```rust,ignore
/// fn main() {
///     idax_build::configure();
/// }
/// ```
fn main() {
    // Forward RPATH metadata from idax-sys to downstream consumers.
    // idax-sys has `links = "idax"`, so its metadata appears as DEP_IDAX_*.
    if let Ok(rpaths) = std::env::var("DEP_IDAX_RPATH_DIRS") {
        // Re-export under our own `links` key ("idax_rt") so downstream
        // binary crates can read it as DEP_IDAX_RT_RPATH_DIRS.
        println!("cargo:RPATH_DIRS={}", rpaths);

        // Also emit the link args directly. This will apply to any binary,
        // cdylib, test, example, or bench target within a package that
        // directly depends on `idax` — but NOT to transitive consumers.
        // For most users (who have `idax` as a direct dependency of their
        // binary crate), this will "just work".
        if !rpaths.is_empty() {
            for rpath in rpaths.split(';') {
                if !rpath.is_empty() {
                    println!("cargo:rustc-link-arg=-Wl,-rpath,{}", rpath);
                }
            }
        }
    }

    // Don't re-run unless the dependency metadata changes (which happens
    // when idax-sys is rebuilt).
    println!("cargo:rerun-if-env-changed=DEP_IDAX_RPATH_DIRS");
}

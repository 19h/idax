use std::env;
use std::path::PathBuf;

fn main() {
    // ── Locate roots ────────────────────────────────────────────────────
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let idax_root = manifest_dir
        .join("..")
        .join("..")
        .join("..")
        .canonicalize()
        .expect("Cannot resolve idax root (expected ../../.. from crate)");

    let idasdk_env =
        PathBuf::from(env::var("IDASDK").expect("IDASDK environment variable must be set"));

    // The SDK root may be $IDASDK or $IDASDK/src depending on layout.
    // Mirror the same discovery logic as the C++ CMakeLists.txt.
    let idasdk = if idasdk_env.join("include").exists() {
        idasdk_env.clone()
    } else if idasdk_env.join("src").join("include").exists() {
        idasdk_env.join("src")
    } else {
        panic!(
            "IDASDK={} does not contain an include/ directory (checked root and src/)",
            idasdk_env.display()
        );
    };

    let idax_include = idax_root.join("include");
    let shim_dir = manifest_dir.join("shim");

    // ── Locate pre-built libidax.a ──────────────────────────────────────
    // Search common build output directories
    let libidax_search_dirs = [
        idax_root.join("build"),
        idax_root.join("build").join("Release"),
        idax_root.join("build").join("Debug"),
        idax_root.join("cmake-build-release"),
        idax_root.join("cmake-build-debug"),
    ];

    let libidax_dir = libidax_search_dirs
        .iter()
        .find(|d| d.join("libidax.a").exists())
        .unwrap_or_else(|| {
            panic!(
                "Cannot find pre-built libidax.a in any of: {:?}. \
                 Build idax first with CMake.",
                libidax_search_dirs
            );
        });

    // ── Locate IDA SDK libraries ────────────────────────────────────────
    // idalib is typically in $IDASDK/lib/x64_mac_clang_64 on macOS
    let sdk_lib_dir = if cfg!(target_os = "macos") {
        if cfg!(target_arch = "aarch64") {
            idasdk.join("lib").join("arm64_mac_clang_64")
        } else {
            idasdk.join("lib").join("x64_mac_clang_64")
        }
    } else if cfg!(target_os = "linux") {
        idasdk.join("lib").join("x64_linux_gcc_64")
    } else if cfg!(target_os = "windows") {
        idasdk.join("lib").join("x64_win_vc_64")
    } else {
        panic!("Unsupported target OS for IDA SDK");
    };

    // Fall back to just lib/ if platform-specific dir doesn't exist
    let sdk_lib_dir = if sdk_lib_dir.exists() {
        sdk_lib_dir
    } else {
        idasdk.join("lib")
    };

    // ── Compile C++ shim ────────────────────────────────────────────────
    cc::Build::new()
        .cpp(true)
        .std("c++23")
        .file(shim_dir.join("idax_shim.cpp"))
        .include(&idax_include)
        .include(idasdk.join("include"))
        .define("__EA64__", None)
        .define("__IDP__", None)
        // Suppress warnings in SDK headers
        .flag_if_supported("-Wno-unused-parameter")
        .flag_if_supported("-Wno-sign-compare")
        .flag_if_supported("-Wno-deprecated-declarations")
        .compile("idax_shim");

    // ── Link libraries ──────────────────────────────────────────────────
    println!("cargo:rustc-link-search=native={}", libidax_dir.display());
    println!("cargo:rustc-link-lib=static=idax");

    if sdk_lib_dir.exists() {
        println!("cargo:rustc-link-search=native={}", sdk_lib_dir.display());
    }

    // Link idalib (IDA's headless library)
    if sdk_lib_dir.join("libida.dylib").exists() {
        println!("cargo:rustc-link-lib=dylib=ida");
    } else if sdk_lib_dir.join("libida64.dylib").exists() {
        println!("cargo:rustc-link-lib=dylib=ida64");
    } else if sdk_lib_dir.join("libida.so").exists() {
        println!("cargo:rustc-link-lib=dylib=ida");
    } else if sdk_lib_dir.join("libida64.so").exists() {
        println!("cargo:rustc-link-lib=dylib=ida64");
    }

    // Link C++ standard library
    if cfg!(target_os = "macos") {
        println!("cargo:rustc-link-lib=c++");
    } else if cfg!(target_os = "linux") {
        println!("cargo:rustc-link-lib=stdc++");
    }

    // ── Run bindgen ─────────────────────────────────────────────────────
    let bindings = bindgen::Builder::default()
        .header(shim_dir.join("idax_shim.h").to_str().unwrap())
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .allowlist_function("idax_.*")
        .allowlist_type("Idax.*")
        .allowlist_var("IDAX_.*")
        .derive_debug(true)
        .derive_default(true)
        .derive_copy(true)
        .generate()
        .expect("Failed to generate bindings via bindgen");

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_dir.join("bindings.rs"))
        .expect("Failed to write bindings.rs");

    // ── Rerun triggers ──────────────────────────────────────────────────
    println!("cargo:rerun-if-changed=shim/idax_shim.h");
    println!("cargo:rerun-if-changed=shim/idax_shim.cpp");
    println!("cargo:rerun-if-env-changed=IDASDK");
}

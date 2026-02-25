use std::env;
use std::path::PathBuf;

fn main() {
    // ── Check if building on docs.rs ────────────────────────────────────
    if env::var("DOCS_RS").is_ok() {
        // When building on docs.rs, we don't have access to the IDA SDK
        // or network, so we can't build idax or run bindgen. We instead
        // copy the pre-generated bindings from the repository.
        let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
        let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
        let pre_generated = manifest_dir.join("src").join("bindings.rs");
        if pre_generated.exists() {
            std::fs::copy(&pre_generated, out_dir.join("bindings.rs"))
                .expect("Failed to copy pre-generated bindings to OUT_DIR");
        } else {
            // Just create an empty file so it compiles, though documentation
            // will be empty.
            std::fs::write(out_dir.join("bindings.rs"), "")
                .expect("Failed to create dummy bindings.rs");
        }
        return;
    }

    // ── Locate or clone idax ────────────────────────────────────────────
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());

    let idax_root = if let Ok(idax_dir) = env::var("IDAX_DIR") {
        if !idax_dir.is_empty() {
            PathBuf::from(idax_dir)
                .canonicalize()
                .expect("IDAX_DIR must be a valid path")
        } else {
            fallback(&manifest_dir)
        }
    } else {
        fallback(&manifest_dir)
    };

    fn fallback(manifest_dir: &std::path::Path) -> PathBuf {
        let parent_idax = manifest_dir.join("..").join("..").join("..");
        if parent_idax.join("CMakeLists.txt").exists() {
            parent_idax
                .canonicalize()
                .expect("Failed to canonicalize parent idax dir")
        } else {
            // Fallback: Clone from GitHub
            let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
            let checkout_dir = out_dir.join("idax-github");
            if !checkout_dir.join("CMakeLists.txt").exists() {
                println!(
                    "cargo:warning=Cloning idax from GitHub to {:?}",
                    checkout_dir
                );
                let url = "https://github.com/19h/idax.git";

                let status = std::process::Command::new("git")
                    .arg("clone")
                    .arg("--recurse-submodules")
                    .arg(url)
                    .arg(&checkout_dir)
                    .status()
                    .unwrap_or_else(|e| panic!("Failed to execute git clone: {}", e));

                if !status.success() {
                    panic!("Failed to clone idax from GitHub ({})", url);
                }
            }
            checkout_dir
        }
    }

    println!("cargo:rerun-if-env-changed=IDAX_DIR");

    let idasdk_env_str = env::var("IDASDK").ok().filter(|s| !s.is_empty());

    // The SDK root may be $IDASDK or $IDASDK/src depending on layout.
    // Mirror the same discovery logic as the C++ CMakeLists.txt.
    let idasdk_env = if let Some(sdk) = idasdk_env_str {
        let env_path = PathBuf::from(sdk);
        if env_path.join("include").exists() {
            Some(env_path.clone())
        } else if env_path.join("src").join("include").exists() {
            Some(env_path.join("src"))
        } else {
            panic!(
                "IDASDK={} does not contain an include/ directory (checked root and src/)",
                env_path.display()
            );
        }
    } else {
        None
    };

    let idax_include = idax_root.join("include");
    let shim_dir = manifest_dir.join("shim");

    // ── Build idax with CMake ───────────────────────────────────────────
    let mut config = cmake::Config::new(&idax_root);
    config.define("IDAX_BUILD_EXAMPLES", "OFF");
    config.define("IDAX_BUILD_TESTS", "OFF");
    // Ensure LTO is disabled when building the static idax library for Rust consumption
    config.define("CMAKE_INTERPROCEDURAL_OPTIMIZATION", "OFF");

    if idasdk_env.is_none() {
        // Force the CMake script to fetch the SDK since we don't have it locally in the env
        config.env("IDASDK", "");
    }

    let dst = config.build();
    let libidax_dir = dst.join("lib");

    // If IDASDK wasn't set, find the fetched one in the CMake build directory
    let idasdk = idasdk_env.unwrap_or_else(|| {
        let fetched_dir = dst.join("build").join("_deps").join("ida_sdk-src");
        if fetched_dir.join("include").exists() {
            fetched_dir
        } else if fetched_dir.join("src").join("include").exists() {
            fetched_dir.join("src")
        } else {
            panic!(
                "Failed to locate fetched IDASDK in cmake build output: {:?}",
                dst
            )
        }
    });

    // ── Locate IDA SDK libraries ────────────────────────────────────────
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

    if sdk_lib_dir.join("libida.dylib").exists() {
        println!("cargo:rustc-link-lib=dylib=ida");
        if sdk_lib_dir.join("libidalib.dylib").exists() {
            println!("cargo:rustc-link-lib=dylib=idalib");
        }
    } else if sdk_lib_dir.join("libida64.dylib").exists() {
        println!("cargo:rustc-link-lib=dylib=ida64");
        if sdk_lib_dir.join("libidalib.dylib").exists() {
            println!("cargo:rustc-link-lib=dylib=idalib");
        }
    } else if sdk_lib_dir.join("libida.so").exists() {
        println!("cargo:rustc-link-lib=dylib=ida");
        if sdk_lib_dir.join("libidalib.so").exists() {
            println!("cargo:rustc-link-lib=dylib=idalib");
        }
    } else if sdk_lib_dir.join("libida64.so").exists() {
        println!("cargo:rustc-link-lib=dylib=ida64");
        if sdk_lib_dir.join("libidalib.so").exists() {
            println!("cargo:rustc-link-lib=dylib=idalib");
        }
    } else if sdk_lib_dir.join("ida.lib").exists() {
        println!("cargo:rustc-link-lib=dylib=ida");
        if sdk_lib_dir.join("idalib.lib").exists() {
            println!("cargo:rustc-link-lib=dylib=idalib");
        }
    } else if sdk_lib_dir.join("ida64.lib").exists() {
        println!("cargo:rustc-link-lib=dylib=ida64");
        if sdk_lib_dir.join("idalib.lib").exists() {
            println!("cargo:rustc-link-lib=dylib=idalib");
        }
    }

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

    println!("cargo:rerun-if-changed=shim/idax_shim.h");
    println!("cargo:rerun-if-changed=shim/idax_shim.cpp");
    println!("cargo:rerun-if-env-changed=IDASDK");
    println!("cargo:rerun-if-env-changed=DOCS_RS");
}

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

    // ── Discover IDA runtime library directory ──────────────────────────
    // At link time we use the SDK stubs. At runtime we need the real IDA
    // dylibs. We embed rpath entries so the dynamic linker can find them
    // automatically. Priority order:
    //   1. $IDADIR (explicit user override)
    //   2. Auto-discovered IDA installations in standard locations
    //   3. @executable_path / $ORIGIN (for deploying next to IDA)
    //   4. SDK stub directory (fallback for compile-only / test scenarios)
    println!("cargo:rerun-if-env-changed=IDADIR");
    if !cfg!(target_os = "windows") {
        let mut rpaths: Vec<PathBuf> = Vec::new();

        // 1. $IDADIR — highest priority, user-specified
        if let Ok(idadir) = env::var("IDADIR") {
            if !idadir.is_empty() {
                let idadir_path = PathBuf::from(&idadir);
                // Also add as a link-search path so the real dylibs can
                // satisfy the linker if the SDK stubs are incomplete.
                if idadir_path.exists() {
                    println!("cargo:rustc-link-search=native={}", idadir_path.display());
                }
                rpaths.push(idadir_path);
            }
        }

        // 2. Auto-discover IDA installations in well-known locations
        if cfg!(target_os = "macos") {
            // Scan /Applications for IDA *.app bundles
            if let Ok(entries) = std::fs::read_dir("/Applications") {
                for entry in entries.flatten() {
                    let name = entry.file_name().to_string_lossy().into_owned();
                    if name.starts_with("IDA") && name.ends_with(".app") {
                        let macos_dir = entry.path().join("Contents").join("MacOS");
                        if macos_dir.join("libida.dylib").exists() {
                            rpaths.push(macos_dir);
                        }
                    }
                }
            }
            // 3. Allow loading if the binary is placed inside the IDA directory
            rpaths.push(PathBuf::from("@executable_path"));
        } else if cfg!(target_os = "linux") {
            // Scan /opt for idapro-* directories (standard Linux install)
            if let Ok(entries) = std::fs::read_dir("/opt") {
                for entry in entries.flatten() {
                    let name = entry.file_name().to_string_lossy().into_owned();
                    if name.starts_with("idapro") || name.starts_with("ida-") || name == "ida" {
                        let p = entry.path();
                        if p.join("libida.so").exists() || p.join("libida64.so").exists() {
                            rpaths.push(p);
                        }
                    }
                }
            }
            // Also check ~/ida* and ~/.idapro parent
            if let Ok(home) = env::var("HOME") {
                let home = PathBuf::from(home);
                if let Ok(entries) = std::fs::read_dir(&home) {
                    for entry in entries.flatten() {
                        let name = entry.file_name().to_string_lossy().into_owned();
                        if name.starts_with("ida") && entry.path().is_dir() {
                            let p = entry.path();
                            if p.join("libida.so").exists() || p.join("libida64.so").exists() {
                                rpaths.push(p);
                            }
                        }
                    }
                }
            }
            // 3. Allow loading if the binary is placed inside the IDA directory
            rpaths.push(PathBuf::from("$ORIGIN"));
        }

        // 4. SDK stub directory as final fallback
        if sdk_lib_dir.exists() {
            rpaths.push(sdk_lib_dir.clone());
        }

        // Emit rpaths via the `links` metadata system so downstream crates
        // can read them via `DEP_IDAX_RPATH_DIRS`. We use semicolons as
        // separators since paths may contain spaces but not semicolons.
        // NOTE: `cargo:rustc-link-arg` from a library dependency does NOT
        // propagate to the final binary in Cargo's model. The metadata
        // approach is the only way to pass this information through the
        // dependency chain. The final binary crate must have a `build.rs`
        // that reads `DEP_IDAX_RT_RPATH_DIRS` and emits the link args.
        let rpath_str = rpaths
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(";");
        println!("cargo:RPATH_DIRS={}", rpath_str);

        // Also emit as link args — these apply to idax-sys's own
        // compilation unit (effectively a no-op for rlib), but are kept
        // for completeness and for cases where idax-sys is used directly
        // as a dependency of a binary crate.
        for rpath in &rpaths {
            println!("cargo:rustc-link-arg=-Wl,-rpath,{}", rpath.display());
        }
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

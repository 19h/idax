use std::env;
use std::path::{Path, PathBuf};

fn canonicalize_safe<P: AsRef<Path>>(p: P) -> std::io::Result<PathBuf> {
    let canon = p.as_ref().canonicalize()?;
    if let Some(s) = canon.to_str() {
        if s.starts_with(r"\\?\") {
            return Ok(PathBuf::from(&s[4..]));
        }
    }
    Ok(canon)
}

fn emit_rerun_for_tree(root: &Path) {
    if !root.exists() {
        return;
    }

    if root.is_file() {
        println!("cargo:rerun-if-changed={}", root.display());
        return;
    }

    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(v) => v,
            Err(_) => continue,
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else {
                println!("cargo:rerun-if-changed={}", path.display());
            }
        }
    }
}

/// Discover the IDA runtime directory. Checks $IDADIR first, then scans
/// standard installation locations.
fn discover_ida_dir() -> Option<PathBuf> {
    // 1. $IDADIR — explicit user override
    if let Ok(idadir) = env::var("IDADIR") {
        if !idadir.is_empty() {
            let p = PathBuf::from(&idadir);
            if p.exists() {
                return Some(p);
            }
        }
    }

    // 2. Platform-specific auto-discovery
    if cfg!(target_os = "macos") {
        if let Ok(entries) = std::fs::read_dir("/Applications") {
            let mut candidates: Vec<PathBuf> = entries
                .flatten()
                .filter_map(|e| {
                    let name = e.file_name().to_string_lossy().into_owned();
                    if (name.starts_with("IDA") || name.starts_with("ida"))
                        && name.ends_with(".app")
                    {
                        let macos = e.path().join("Contents").join("MacOS");
                        if macos.join("libida.dylib").exists() {
                            return Some(macos);
                        }
                    }
                    None
                })
                .collect();
            // Sort descending so newer versions (higher numbers) come first
            candidates.sort_by(|a, b| b.cmp(a));
            if let Some(p) = candidates.into_iter().next() {
                return Some(p);
            }
        }
    } else if cfg!(target_os = "linux") {
        // Check /opt/idapro*, /opt/ida-*, /opt/ida
        if let Ok(entries) = std::fs::read_dir("/opt") {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().into_owned();
                if name.starts_with("idapro") || name.starts_with("ida-") || name == "ida" {
                    let p = entry.path();
                    if p.join("libida.so").exists() || p.join("libida64.so").exists() {
                        return Some(p);
                    }
                }
            }
        }
        // Check ~/ida*
        if let Ok(home) = env::var("HOME") {
            if let Ok(entries) = std::fs::read_dir(&home) {
                for entry in entries.flatten() {
                    let name = entry.file_name().to_string_lossy().into_owned();
                    if name.starts_with("ida") && entry.path().is_dir() {
                        let p = entry.path();
                        if p.join("libida.so").exists() || p.join("libida64.so").exists() {
                            return Some(p);
                        }
                    }
                }
            }
        }
    }

    None
}

/// macOS: Link against IDA libraries with symlinks in OUT_DIR for runtime.
///
/// Strategy:
/// 1. Link against the SDK stubs (for symbol resolution at link time)
/// 2. Create symlinks to real IDA dylibs inside OUT_DIR
/// 3. Cargo automatically adds OUT_DIR-relative search paths to
///    DYLD_FALLBACK_LIBRARY_PATH during `cargo run`/`cargo test`
/// 4. The C shim's runtime dlopen provides a fallback for deployed binaries
fn link_ida_macos(sdk_lib_dir: &Path, _dst: &Path) {
    // Link against SDK stubs for symbol resolution at link time
    if sdk_lib_dir.exists() {
        println!("cargo:rustc-link-search=native={}", sdk_lib_dir.display());
    }

    // If the real IDA installation is found, also add it as a link search
    // path. This lets the linker use the real dylibs directly.
    let ida_dir = discover_ida_dir();
    if let Some(ref dir) = ida_dir {
        println!("cargo:rustc-link-search=native={}", dir.display());
    }

    // Symlink real IDA dylibs into OUT_DIR so Cargo adds them to
    // DYLD_FALLBACK_LIBRARY_PATH during `cargo run` and `cargo test`.
    // Per Cargo docs: search paths within OUT_DIR are added to the
    // dynamic library search path environment variable.
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    if let Some(ref dir) = ida_dir {
        for lib in &["libida.dylib", "libidalib.dylib"] {
            let real = dir.join(lib);
            let link = out_dir.join(lib);
            if real.exists() {
                // Remove stale symlink if any
                let _ = std::fs::remove_file(&link);
                #[cfg(unix)]
                {
                    std::os::unix::fs::symlink(&real, &link).ok();
                }
            }
        }
    }

    // Link the IDA libraries
    for lib in &["libida.dylib", "libidalib.dylib"] {
        let exists = sdk_lib_dir.join(lib).exists()
            || ida_dir.as_ref().map_or(false, |d| d.join(lib).exists());
        if exists {
            let stem = lib
                .strip_prefix("lib")
                .unwrap()
                .strip_suffix(".dylib")
                .unwrap();
            println!("cargo:rustc-link-lib=dylib={}", stem);
        }
    }
}

/// Linux: link against SDK stubs normally. The C shim runtime loader
/// handles finding the real libraries via dlopen.
fn link_ida_linux(sdk_lib_dir: &Path) {
    if sdk_lib_dir.exists() {
        println!("cargo:rustc-link-search=native={}", sdk_lib_dir.display());
    }
    if sdk_lib_dir.join("libida.so").exists() {
        println!("cargo:rustc-link-lib=dylib=ida");
        if sdk_lib_dir.join("libidalib.so").exists() {
            println!("cargo:rustc-link-lib=dylib=idalib");
        }
    } else if sdk_lib_dir.join("libida64.so").exists() {
        println!("cargo:rustc-link-lib=dylib=ida64");
        if sdk_lib_dir.join("libidalib.so").exists() {
            println!("cargo:rustc-link-lib=dylib=idalib");
        }
    }
}

/// Windows: link against SDK .lib import stubs.
fn link_ida_windows(sdk_lib_dir: &Path) {
    if sdk_lib_dir.exists() {
        println!("cargo:rustc-link-search=native={}", sdk_lib_dir.display());
    }
    if sdk_lib_dir.join("ida.lib").exists() {
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
}

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
            canonicalize_safe(PathBuf::from(idax_dir)).expect("IDAX_DIR must be a valid path")
        } else {
            fallback(&manifest_dir)
        }
    } else {
        fallback(&manifest_dir)
    };

    fn fallback(manifest_dir: &std::path::Path) -> PathBuf {
        let parent_idax = manifest_dir.join("..").join("..").join("..");
        if parent_idax.join("CMakeLists.txt").exists() {
            canonicalize_safe(parent_idax).expect("Failed to canonicalize parent idax dir")
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
    emit_rerun_for_tree(&idax_root.join("CMakeLists.txt"));
    emit_rerun_for_tree(&idax_root.join("cmake"));
    emit_rerun_for_tree(&idax_root.join("include"));
    emit_rerun_for_tree(&idax_root.join("src"));

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
    if cfg!(target_os = "windows") {
        // IDA SDK libraries on Windows are built against static CRT settings.
        // Keep idax C++ wrapper objects on the same runtime model.
        config.define(
            "CMAKE_MSVC_RUNTIME_LIBRARY",
            "MultiThreaded$<$<CONFIG:Debug>:Debug>",
        );
    }

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
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    let mut build = cc::Build::new();
    build
        .cpp(true)
        .file(shim_dir.join("idax_shim.cpp"))
        .include(&idax_include)
        .include(idasdk.join("include"))
        .define("__EA64__", None)
        .define("__IDP__", None)
        .flag_if_supported("-Wno-unused-parameter")
        .flag_if_supported("-Wno-sign-compare")
        .flag_if_supported("-Wno-deprecated-declarations");

    if cfg!(target_os = "windows") {
        // Keep shim runtime model aligned with IDA SDK/link target.
        build.static_crt(true);
    }

    let compiler = build.get_compiler();
    if compiler.is_like_clang() && cfg!(target_os = "macos") {
        build.flag("-std=c++2b");
    } else if compiler.is_like_msvc() {
        build.flag("/std:c++latest");
        build.flag("/Zc:__cplusplus");
    } else {
        build.std("c++23");
    }

    build.compile("idax_shim");

    // ── Link libraries ──────────────────────────────────────────────────
    if cfg!(target_os = "windows") {
        let source = libidax_dir.join("idax.lib");
        if !source.exists() {
            panic!("Expected idax static library at {}", source.display());
        }

        // Avoid collision with the Rust crate name `idax` during downstream
        // link steps by exposing the C++ archive under a distinct name.
        let alias = out_dir.join("idax_cpp.lib");
        std::fs::copy(&source, &alias).unwrap_or_else(|e| {
            panic!(
                "Failed to copy {} to {}: {}",
                source.display(),
                alias.display(),
                e
            )
        });

        println!("cargo:rustc-link-search=native={}", out_dir.display());
        // On MSVC release builds, idax_cpp can contain LTCG (/GL) objects.
        // Force non-bundled linkage so rustc passes the .lib directly to
        // link.exe instead of repacking it into an rlib archive index.
        println!("cargo:rustc-link-lib=static:-bundle=idax_cpp");
    } else {
        println!("cargo:rustc-link-search=native={}", libidax_dir.display());
        println!("cargo:rustc-link-lib=static=idax");
    }

    println!("cargo:rerun-if-env-changed=IDADIR");

    // ── Link against IDA SDK stubs with rewritten install names ─────────
    // The SDK stubs use `@rpath/libida.dylib` as their install name, which
    // creates LC_LOAD_DYLIB entries that require RPATH configuration.
    // Since Cargo cannot propagate RPATH entries from dependencies to the
    // final binary, we take a different approach:
    //
    // 1. Discover the real IDA installation directory (IDADIR or auto-scan)
    // 2. Copy the SDK stubs to OUT_DIR
    // 3. Rewrite their install names to absolute paths pointing to the
    //    discovered IDA installation
    // 4. Link against the rewritten copies
    //
    // The result: the binary's load commands reference the IDA libraries
    // by absolute path (e.g. /Applications/IDA.app/Contents/MacOS/libida.dylib)
    // instead of @rpath/libida.dylib. No RPATH needed. Magic.
    //
    // Additionally, the C shim has a runtime dlopen fallback that discovers
    // and loads IDA libraries before any SDK function is called, providing
    // a safety net if the absolute path is stale (e.g. IDA was updated).

    if cfg!(target_os = "macos") {
        link_ida_macos(&sdk_lib_dir, &dst);
        println!("cargo:rustc-link-lib=c++");
    } else if cfg!(target_os = "linux") {
        link_ida_linux(&sdk_lib_dir);
        println!("cargo:rustc-link-lib=stdc++");
    } else if cfg!(target_os = "windows") {
        link_ida_windows(&sdk_lib_dir);
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

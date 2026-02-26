use std::env;

fn main() {
    if cfg!(target_os = "windows") {
        if let Ok(dir) = env::var("DEP_IDAX_IDAX_LIB_DIR") {
            if !dir.is_empty() {
                println!("cargo:rustc-link-search=native={dir}");
                println!("cargo:rustc-link-lib=static=idax_shim_merged");
            }
        }
    }

    println!("cargo:rerun-if-env-changed=DEP_IDAX_IDAX_LIB_DIR");
}

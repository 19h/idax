//! Raw FFI bindings to the idax C++ IDA SDK wrapper library.
//!
//! This crate provides unsafe `extern "C"` function declarations generated
//! by bindgen from the idax C shim layer. Use the `idax` crate for safe,
//! idiomatic Rust bindings.

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(clippy::all)]

#[cfg(target_os = "windows")]
#[link(name = "idax_cpp", kind = "static")]
unsafe extern "C" {
    fn __idax_windows_cpp_link_sentinel();
}

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

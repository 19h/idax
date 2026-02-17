//! Raw FFI bindings to the idax C++ IDA SDK wrapper library.
//!
//! This crate provides unsafe `extern "C"` function declarations generated
//! by bindgen from the idax C shim layer. Use the `idax` crate for safe,
//! idiomatic Rust bindings.

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(clippy::all)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

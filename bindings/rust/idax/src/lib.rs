//! Safe, idiomatic Rust bindings for the IDA SDK via idax.
//!
//! This crate mirrors the complete API surface of the [`idax`](https://github.com/19h/idax)
//! C++ wrapper library, providing an intuitive, concept-driven interface to IDA Pro's
//! analysis capabilities.
//!
//! # Architecture
//!
//! The crate is organized into modules that mirror the C++ `ida::` namespace hierarchy:
//!
//! | Module | C++ Namespace | Purpose |
//! |--------|---------------|---------|
//! | [`error`] | `ida::Error` | Error types, `Result<T>`, `Status` |
//! | [`address`] | `ida::address` | Address primitives, predicates, range iteration |
//! | [`database`] | `ida::database` | Database lifecycle, metadata, imports, snapshots |
//! | [`segment`] | `ida::segment` | Segment CRUD, traversal, properties |
//! | [`function`] | `ida::function` | Function CRUD, chunks, frames, register variables |
//! | [`instruction`] | `ida::instruction` | Instruction decode, operands, text rendering |
//! | [`data`] | `ida::data` | Byte-level read, write, patch, and define |
//! | [`name`] | `ida::name` | Naming and demangling |
//! | [`xref`] | `ida::xref` | Cross-reference enumeration and mutation |
//! | [`comment`] | `ida::comment` | Comments (regular, repeatable, anterior/posterior) |
//! | [`search`] | `ida::search` | Text, binary, and immediate value searches |
//! | [`analysis`] | `ida::analysis` | Auto-analysis control |
//! | [`lumina`] | `ida::lumina` | Lumina metadata pull/push |
//! | [`types`] | `ida::type` | Type system: construction, introspection, application |
//! | [`entry`] | `ida::entry` | Program entry points |
//! | [`fixup`] | `ida::fixup` | Fixup/relocation information |
//! | [`event`] | `ida::event` | IDB event subscriptions |
//! | [`plugin`] | `ida::plugin` | Plugin lifecycle, action registration |
//! | [`loader`] | `ida::loader` | Loader module helpers |
//! | [`processor`] | `ida::processor` | Processor module data types |
//! | [`debugger`] | `ida::debugger` | Debugger control, breakpoints, memory, appcall |
//! | [`decompiler`] | `ida::decompiler` | Decompiler facade, pseudocode, ctree, microcode |
//! | [`storage`] | `ida::storage` | Low-level persistent key-value storage (netnodes) |
//! | [`graph`] | `ida::graph` | Custom graphs, flow charts |
//! | [`ui`] | `ida::ui` | UI utilities: messages, dialogs, widgets, events |
//! | [`lines`] | `ida::lines` | Color tag manipulation |
//! | [`diagnostics`] | `ida::diagnostics` | Logging and performance counters |
//!
//! # Quick Start
//!
//! ```rust,no_run
//! use idax::{database, address, function, segment};
//!
//! fn main() -> idax::error::Result<()> {
//!     // Initialize IDA library
//!     database::init()?;
//!
//!     // Open a binary for analysis
//!     database::open("/path/to/binary", true)?;
//!
//!     // Query metadata
//!     let path = database::input_file_path()?;
//!     let md5 = database::input_md5()?;
//!     println!("Analyzing: {path} (MD5: {md5})");
//!
//!     // Iterate over functions
//!     let count = function::count()?;
//!     for i in 0..count {
//!         let func = function::by_index(i)?;
//!         println!("  {:#x}: {}", func.start(), func.name());
//!     }
//!
//!     // Iterate over segments
//!     let seg_count = segment::count()?;
//!     for i in 0..seg_count {
//!         let seg = segment::by_index(i)?;
//!         println!("  {}: {:#x}-{:#x}", seg.name(), seg.start(), seg.end());
//!     }
//!
//!     // Clean up
//!     database::close(false)?;
//!     Ok(())
//! }
//! ```
//!
//! # Error Handling
//!
//! All fallible operations return [`error::Result<T>`] or [`error::Status`],
//! which are type aliases for `std::result::Result<T, error::Error>` and
//! `std::result::Result<(), error::Error>` respectively. The [`error::Error`]
//! type carries a category, code, message, and context — mirroring the C++
//! `ida::Error` exactly.
//!
//! # RAII / Drop
//!
//! Types that hold SDK resources implement [`Drop`]:
//! - [`types::TypeInfo`] — pimpl-wrapped type handle
//! - [`storage::Node`] — netnode handle
//! - [`decompiler::DecompiledFunction`] — decompilation result
//! - [`graph::Graph`] — interactive graph handle
//!
//! # Safety
//!
//! All unsafe FFI calls are encapsulated within safe Rust functions.
//! Users of this crate never need to write `unsafe` code.

// ── Public modules ──────────────────────────────────────────────────────

pub mod address;
pub mod analysis;
pub mod comment;
pub mod data;
pub mod database;
pub mod debugger;
pub mod decompiler;
pub mod diagnostics;
pub mod entry;
pub mod error;
pub mod event;
pub mod fixup;
pub mod function;
pub mod graph;
pub mod instruction;
pub mod lines;
pub mod loader;
pub mod lumina;
pub mod name;
pub mod plugin;
pub mod processor;
pub mod search;
pub mod segment;
pub mod storage;
pub mod types;
pub mod ui;
pub mod xref;

// ── Convenience re-exports ──────────────────────────────────────────────

/// Re-export of the fundamental address type.
pub use address::Address;

/// Re-export of the address delta type.
pub use address::AddressDelta;

/// Re-export of the address size type.
pub use address::AddressSize;

/// Re-export of the bad address sentinel.
pub use address::BAD_ADDRESS;

/// Re-export of the error type.
pub use error::Error;

/// Re-export of the result type alias.
pub use error::Result;

/// Re-export of the status type alias.
pub use error::Status;

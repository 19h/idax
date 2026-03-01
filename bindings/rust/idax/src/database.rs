//! Database lifecycle and metadata operations.
//!
//! Mirrors the C++ `ida::database` namespace: open/close/save, metadata
//! queries.

use crate::address::{Address, AddressSize, Range};
use crate::error::{self, Error, Result, Status};
use std::ffi::CString;

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

/// Database open mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum OpenMode {
    Analyze = 0,
    SkipAnalysis = 1,
}

/// Target compiler metadata for the current database.
#[derive(Debug, Clone)]
pub struct CompilerInfo {
    pub id: u32,
    pub uncertain: bool,
    pub name: String,
    pub abbreviation: String,
}

/// Imported symbol metadata.
#[derive(Debug, Clone)]
pub struct ImportSymbol {
    pub address: Address,
    pub name: String,
    pub ordinal: u64,
}

/// Imported module metadata.
#[derive(Debug, Clone)]
pub struct ImportModule {
    pub index: usize,
    pub name: String,
    pub symbols: Vec<ImportSymbol>,
}

/// Snapshot metadata node.
#[derive(Debug, Clone)]
pub struct Snapshot {
    pub id: i64,
    pub flags: u16,
    pub description: String,
    pub filename: String,
    pub children: Vec<Snapshot>,
}

fn snapshot_from_raw(raw: &idax_sys::IdaxDatabaseSnapshot) -> Snapshot {
    let mut children = Vec::new();
    if !raw.children.is_null() && raw.child_count > 0 {
        for i in 0..raw.child_count {
            let child = unsafe { &*raw.children.add(i) };
            children.push(snapshot_from_raw(child));
        }
    }
    Snapshot {
        id: raw.id,
        flags: raw.flags,
        description: if raw.description.is_null() {
            String::new()
        } else {
            unsafe {
                std::ffi::CStr::from_ptr(raw.description)
                    .to_string_lossy()
                    .into_owned()
            }
        },
        filename: if raw.filename.is_null() {
            String::new()
        } else {
            unsafe {
                std::ffi::CStr::from_ptr(raw.filename)
                    .to_string_lossy()
                    .into_owned()
            }
        },
        children,
    }
}

/// Processor module identifiers (SDK `PLFM_*` values).
///
/// Values match the SDK constants exactly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum ProcessorId {
    IntelX86 = 0,
    Z80 = 1,
    IntelI860 = 2,
    Intel8051 = 3,
    Tms320C5x = 4,
    Mos6502 = 5,
    Pdp11 = 6,
    Motorola68k = 7,
    JavaVm = 8,
    Motorola6800 = 9,
    St7 = 10,
    Motorola68hc12 = 11,
    Mips = 12,
    Arm = 13,
    Tms320C6x = 14,
    PowerPc = 15,
    Intel80196 = 16,
    Z8 = 17,
    SuperH = 18,
    DotNet = 19,
    Avr = 20,
    H8 = 21,
    Pic = 22,
    Sparc = 23,
    Alpha = 24,
    Hppa = 25,
    H8500 = 26,
    TriCore = 27,
    Dsp56k = 28,
    C166 = 29,
    St20 = 30,
    Ia64 = 31,
    IntelI960 = 32,
    F2mc16 = 33,
    Tms320C54x = 34,
    Tms320C55x = 35,
    Trimedia = 36,
    M32r = 37,
    Nec78k0 = 38,
    Nec78k0s = 39,
    MitsubishiM740 = 40,
    MitsubishiM7700 = 41,
    St9 = 42,
    FujitsuFr = 43,
    Motorola68hc16 = 44,
    MitsubishiM7900 = 45,
    Tms320C3 = 46,
    Kr1878 = 47,
    Adsp218x = 48,
    OakDsp = 49,
    Tlcs900 = 50,
    RockwellC39 = 51,
    Cr16 = 52,
    Mn10200 = 53,
    Tms320C1x = 54,
    NecV850x = 55,
    ScriptAdapter = 56,
    EfiBytecode = 57,
    Msp430 = 58,
    Spu = 59,
    Dalvik = 60,
    Wdc65c816 = 61,
    M16c = 62,
    Arc = 63,
    Unsp = 64,
    Tms320C28x = 65,
    Dsp96000 = 66,
    Spc700 = 67,
    Adsp2106x = 68,
    Pic16 = 69,
    S390 = 70,
    Xtensa = 71,
    RiscV = 72,
    Rl78 = 73,
    Rx = 74,
    Wasm = 75,
    Nds32 = 76,
    Mcore = 77,
}

impl ProcessorId {
    /// Try to convert a raw `i32` PLFM constant to a `ProcessorId`.
    pub fn from_raw(raw: i32) -> Option<Self> {
        if raw >= 0 && raw <= 77 {
            // Safety: all values 0..=77 are valid enum variants.
            Some(unsafe { std::mem::transmute(raw) })
        } else {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// Lifecycle functions
// ---------------------------------------------------------------------------

/// Initialise the IDA library (call once, before any other idax call).
pub fn init() -> Status {
    let argv0 = CString::new("idax-rust").expect("static argv0 must be valid CString");
    let mut argv = [argv0.as_ptr() as *mut std::os::raw::c_char];
    let ret = unsafe { idax_sys::idax_database_init(1, argv.as_mut_ptr()) };
    error::int_to_status(ret, "database::init failed")
}

/// Open (or create) a database for the given input file.
///
/// If `auto_analysis` is true the auto-analyser runs to completion.
pub fn open(path: &str, auto_analysis: bool) -> Status {
    let c_path = CString::new(path).map_err(|_| Error::validation("invalid path string"))?;
    let ret = unsafe { idax_sys::idax_database_open(c_path.as_ptr(), auto_analysis as i32) };
    error::int_to_status(ret, "database::open failed")
}

/// Open a database with explicit binary-input intent.
pub fn open_binary(path: &str, mode: OpenMode) -> Status {
    let c_path = CString::new(path).map_err(|_| Error::validation("invalid path string"))?;
    let ret = unsafe { idax_sys::idax_database_open_binary(c_path.as_ptr(), mode as i32) };
    error::int_to_status(ret, "database::open_binary failed")
}

/// Open a database with explicit non-binary-input intent.
pub fn open_non_binary(path: &str, mode: OpenMode) -> Status {
    let c_path = CString::new(path).map_err(|_| Error::validation("invalid path string"))?;
    let ret = unsafe { idax_sys::idax_database_open_non_binary(c_path.as_ptr(), mode as i32) };
    error::int_to_status(ret, "database::open_non_binary failed")
}

/// Open a database with explicit analysis mode.
pub fn open_with_mode(path: &str, mode: OpenMode) -> Status {
    let auto_analysis = mode == OpenMode::Analyze;
    open(path, auto_analysis)
}

/// Save the current database.
pub fn save() -> Status {
    let ret = unsafe { idax_sys::idax_database_save() };
    error::int_to_status(ret, "database::save failed")
}

/// Close the current database.
///
/// If `save_first` is true the database is saved first.
pub fn close(save_first: bool) -> Status {
    let ret = unsafe { idax_sys::idax_database_close(save_first as i32) };
    error::int_to_status(ret, "database::close failed")
}

/// Load a file range into the database at `[ea, ea + size)`.
pub fn file_to_database(
    file_path: &str,
    file_offset: i64,
    ea: Address,
    size: AddressSize,
    patchable: bool,
    remote: bool,
) -> Status {
    let c_path = CString::new(file_path).map_err(|_| Error::validation("invalid file path"))?;
    let ret = unsafe {
        idax_sys::idax_database_file_to_database(
            c_path.as_ptr(),
            file_offset,
            ea,
            size,
            patchable as i32,
            remote as i32,
        )
    };
    error::int_to_status(ret, "database::file_to_database failed")
}

/// Load bytes into the database at `[ea, ea + bytes.len())`.
pub fn memory_to_database(bytes: &[u8], ea: Address, file_offset: i64) -> Status {
    let ret = unsafe {
        idax_sys::idax_database_memory_to_database(bytes.as_ptr(), bytes.len(), ea, file_offset)
    };
    error::int_to_status(ret, "database::memory_to_database failed")
}

// ---------------------------------------------------------------------------
// Metadata functions (output-parameter style)
// ---------------------------------------------------------------------------

/// Path of the original input file.
pub fn input_file_path() -> Result<String> {
    unsafe {
        let mut ptr: *mut std::ffi::c_char = std::ptr::null_mut();
        let ret = idax_sys::idax_database_input_file_path(&mut ptr);
        if ret != 0 {
            return Err(error::consume_last_error("input_file_path failed"));
        }
        error::cstr_to_string_free(ptr, "input_file_path null")
    }
}

/// Human-readable input file type name (e.g. "Portable executable").
pub fn file_type_name() -> Result<String> {
    unsafe {
        let mut ptr: *mut std::ffi::c_char = std::ptr::null_mut();
        let ret = idax_sys::idax_database_file_type_name(&mut ptr);
        if ret != 0 {
            return Err(error::consume_last_error("file_type_name failed"));
        }
        error::cstr_to_string_free(ptr, "file_type_name null")
    }
}

/// Loader-reported format name when provided by the active loader.
pub fn loader_format_name() -> Result<String> {
    unsafe {
        let mut ptr: *mut std::ffi::c_char = std::ptr::null_mut();
        let ret = idax_sys::idax_database_loader_format_name(&mut ptr);
        if ret != 0 {
            return Err(error::consume_last_error("loader_format_name failed"));
        }
        error::cstr_to_string_free(ptr, "loader_format_name null")
    }
}

/// MD5 hash of the original input file (hex string).
pub fn input_md5() -> Result<String> {
    unsafe {
        let mut ptr: *mut std::ffi::c_char = std::ptr::null_mut();
        let ret = idax_sys::idax_database_input_md5(&mut ptr);
        if ret != 0 {
            return Err(error::consume_last_error("input_md5 failed"));
        }
        error::cstr_to_string_free(ptr, "input_md5 null")
    }
}

/// Target compiler metadata inferred/configured for this database.
pub fn compiler_info() -> Result<CompilerInfo> {
    unsafe {
        let mut raw = idax_sys::IdaxDatabaseCompilerInfo::default();
        let ret = idax_sys::idax_database_compiler_info(&mut raw);
        if ret != 0 {
            return Err(error::consume_last_error("compiler_info failed"));
        }
        let out = CompilerInfo {
            id: raw.id,
            uncertain: raw.uncertain != 0,
            name: if raw.name.is_null() {
                String::new()
            } else {
                std::ffi::CStr::from_ptr(raw.name)
                    .to_string_lossy()
                    .into_owned()
            },
            abbreviation: if raw.abbreviation.is_null() {
                String::new()
            } else {
                std::ffi::CStr::from_ptr(raw.abbreviation)
                    .to_string_lossy()
                    .into_owned()
            },
        };
        idax_sys::idax_database_compiler_info_free(&mut raw);
        Ok(out)
    }
}

/// Import-module inventory with per-symbol names/ordinals/addresses.
pub fn import_modules() -> Result<Vec<ImportModule>> {
    unsafe {
        let mut modules_ptr: *mut idax_sys::IdaxDatabaseImportModule = std::ptr::null_mut();
        let mut count: usize = 0;
        let ret = idax_sys::idax_database_import_modules(&mut modules_ptr, &mut count);
        if ret != 0 {
            return Err(error::consume_last_error("import_modules failed"));
        }
        if modules_ptr.is_null() || count == 0 {
            return Ok(Vec::new());
        }

        let mut out = Vec::with_capacity(count);
        let modules = std::slice::from_raw_parts(modules_ptr, count);
        for module in modules {
            let name = if module.name.is_null() {
                String::new()
            } else {
                std::ffi::CStr::from_ptr(module.name)
                    .to_string_lossy()
                    .into_owned()
            };

            let mut symbols = Vec::with_capacity(module.symbol_count);
            if !module.symbols.is_null() && module.symbol_count > 0 {
                let raw_symbols = std::slice::from_raw_parts(module.symbols, module.symbol_count);
                for symbol in raw_symbols {
                    symbols.push(ImportSymbol {
                        address: symbol.address,
                        name: if symbol.name.is_null() {
                            String::new()
                        } else {
                            std::ffi::CStr::from_ptr(symbol.name)
                                .to_string_lossy()
                                .into_owned()
                        },
                        ordinal: symbol.ordinal,
                    });
                }
            }

            out.push(ImportModule {
                index: module.index,
                name,
                symbols,
            });
        }

        idax_sys::idax_database_import_modules_free(modules_ptr, count);
        Ok(out)
    }
}

/// Image base address of the loaded binary.
pub fn image_base() -> Result<Address> {
    let mut out: u64 = 0;
    let ret = unsafe { idax_sys::idax_database_image_base(&mut out) };
    if ret != 0 {
        Err(error::consume_last_error("image_base failed"))
    } else {
        Ok(out)
    }
}

/// Lowest mapped address in the database.
pub fn min_address() -> Result<Address> {
    let mut out: u64 = 0;
    let ret = unsafe { idax_sys::idax_database_min_address(&mut out) };
    if ret != 0 {
        Err(error::consume_last_error("min_address failed"))
    } else {
        Ok(out)
    }
}

/// Highest mapped address in the database.
pub fn max_address() -> Result<Address> {
    let mut out: u64 = 0;
    let ret = unsafe { idax_sys::idax_database_max_address(&mut out) };
    if ret != 0 {
        Err(error::consume_last_error("max_address failed"))
    } else {
        Ok(out)
    }
}

/// Address bounds as a half-open range `[min_address, max_address)`.
pub fn address_bounds() -> Result<Range> {
    let lo = min_address()?;
    let hi = max_address()?;
    Ok(Range::new(lo, hi))
}

/// Span of mapped address space (`max_address - min_address`).
pub fn address_span() -> Result<AddressSize> {
    let mut out: u64 = 0;
    let ret = unsafe { idax_sys::idax_database_address_span(&mut out) };
    if ret != 0 {
        Err(error::consume_last_error("address_span failed"))
    } else {
        Ok(out)
    }
}

/// Active processor module ID (PLFM_* constant from the SDK).
pub fn processor_id() -> Result<i32> {
    let mut id: i32 = -1;
    let ret = unsafe { idax_sys::idax_database_processor_id(&mut id) };
    if ret != 0 {
        Err(error::consume_last_error("processor_id failed"))
    } else {
        Ok(id)
    }
}

/// Active processor module ID as a typed enum.
pub fn processor() -> Result<ProcessorId> {
    let id = processor_id()?;
    ProcessorId::from_raw(id).ok_or_else(|| Error::sdk(format!("unknown processor id: {}", id)))
}

/// Active processor module short name (e.g. "metapc", "ARM", "mips").
pub fn processor_name() -> Result<String> {
    unsafe {
        let mut ptr: *mut std::ffi::c_char = std::ptr::null_mut();
        let ret = idax_sys::idax_database_processor_name(&mut ptr);
        if ret != 0 {
            return Err(error::consume_last_error("processor_name failed"));
        }
        error::cstr_to_string_free(ptr, "processor_name null")
    }
}

/// Program address bitness for the current database (16/32/64).
pub fn address_bitness() -> Result<i32> {
    let mut bits: i32 = 0;
    let ret = unsafe { idax_sys::idax_database_address_bitness(&mut bits) };
    if ret != 0 {
        Err(error::consume_last_error("address_bitness failed"))
    } else {
        Ok(bits)
    }
}

/// Set program address bitness for the current database (16/32/64).
pub fn set_address_bitness(bits: i32) -> Status {
    let ret = unsafe { idax_sys::idax_database_set_address_bitness(bits) };
    error::int_to_status(ret, "set_address_bitness failed")
}

/// Endianness of the current database.
pub fn is_big_endian() -> Result<bool> {
    let mut big: i32 = 0;
    let ret = unsafe { idax_sys::idax_database_is_big_endian(&mut big) };
    if ret != 0 {
        Err(error::consume_last_error("is_big_endian failed"))
    } else {
        Ok(big != 0)
    }
}

/// Active ABI name when available (e.g. "sysv", "n32", "xbox").
pub fn abi_name() -> Result<String> {
    unsafe {
        let mut ptr: *mut std::ffi::c_char = std::ptr::null_mut();
        let ret = idax_sys::idax_database_abi_name(&mut ptr);
        if ret != 0 {
            return Err(error::consume_last_error("abi_name failed"));
        }
        error::cstr_to_string_free(ptr, "abi_name null")
    }
}

/// Build and return the database snapshot tree (root-level snapshots only).
pub fn snapshots() -> Result<Vec<Snapshot>> {
    unsafe {
        let mut snapshots_ptr: *mut idax_sys::IdaxDatabaseSnapshot = std::ptr::null_mut();
        let mut count: usize = 0;
        let ret = idax_sys::idax_database_snapshots(&mut snapshots_ptr, &mut count);
        if ret != 0 {
            return Err(error::consume_last_error("snapshots failed"));
        }
        if snapshots_ptr.is_null() || count == 0 {
            return Ok(Vec::new());
        }
        let raws = std::slice::from_raw_parts(snapshots_ptr, count);
        let out = raws.iter().map(snapshot_from_raw).collect();
        idax_sys::idax_database_snapshots_free(snapshots_ptr, count);
        Ok(out)
    }
}

/// Update the current database snapshot description.
pub fn set_snapshot_description(description: &str) -> Status {
    let c_desc =
        CString::new(description).map_err(|_| Error::validation("invalid snapshot description"))?;
    let ret = unsafe { idax_sys::idax_database_set_snapshot_description(c_desc.as_ptr()) };
    error::int_to_status(ret, "set_snapshot_description failed")
}

/// Whether the current database is marked as a snapshot.
pub fn is_snapshot_database() -> Result<bool> {
    let mut out: i32 = 0;
    let ret = unsafe { idax_sys::idax_database_is_snapshot_database(&mut out) };
    if ret != 0 {
        Err(error::consume_last_error("is_snapshot_database failed"))
    } else {
        Ok(out != 0)
    }
}

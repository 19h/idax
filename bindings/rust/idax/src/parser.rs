//! Third-party source-parser selection, configuration, and type ingestion.

use std::ffi::CString;
use std::ops::BitOr;

use crate::error::{self, Error, Result, Status};

/// One source language understood by registered parsers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum Language {
    C = 0x01,
    Cpp = 0x02,
    ObjectiveC = 0x04,
    Swift = 0x08,
    Go = 0x10,
    ObjectiveCpp = 0x20,
}

/// A nonempty semantic set of required source languages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Languages(u32);

impl From<Language> for Languages {
    fn from(value: Language) -> Self {
        Self(value as u32)
    }
}

impl BitOr for Language {
    type Output = Languages;

    fn bitor(self, rhs: Self) -> Self::Output {
        Languages(self as u32 | rhs as u32)
    }
}

impl BitOr<Language> for Languages {
    type Output = Languages;

    fn bitor(self, rhs: Language) -> Self::Output {
        Languages(self.0 | rhs as u32)
    }
}

impl BitOr for Languages {
    type Output = Languages;

    fn bitor(self, rhs: Self) -> Self::Output {
        Languages(self.0 | rhs.0)
    }
}

/// Interpretation of an input string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(i32)]
pub enum InputKind {
    #[default]
    SourceText = 0,
    FilePath = 1,
}

/// Semantic options for the extended named-parser entry point.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ParseOptions {
    pub input_kind: InputKind,
    pub discard_result: bool,
    pub define_base_macros: bool,
    pub suppress_warnings: bool,
    pub ignore_errors: bool,
    pub allow_redeclarations: bool,
    pub no_decorate: bool,
    pub assume_high_level: bool,
    pub lower_prototypes: bool,
    pub raw_argument_names: bool,
    pub relaxed_namespaces: bool,
    pub exclude_base_types: bool,
    pub allow_missing_semicolon: bool,
    pub standalone_declaration: bool,
    pub allow_void: bool,
    pub no_mangle: bool,
    pub pack_alignment: usize,
}

/// Result of one parser invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParseReport {
    pub error_count: usize,
}

impl ParseReport {
    #[must_use]
    pub const fn is_ok(self) -> bool {
        self.error_count == 0
    }
}

fn cstring(value: &str, field: &str) -> Result<CString> {
    CString::new(value)
        .map_err(|_| Error::validation(format!("{field} contains an embedded NUL byte")))
}

/// Select a parser by name; `None` or an empty name selects the default.
pub fn select(name: Option<&str>) -> Status {
    let name = name
        .map(|value| cstring(value, "parser name"))
        .transpose()?;
    let status = unsafe {
        idax_sys::idax_parser_select(
            name.as_ref()
                .map_or(std::ptr::null(), |value| value.as_ptr()),
        )
    };
    error::int_to_status(status, "parser::select failed")
}

/// Select a parser supporting every required source language.
pub fn select_for(languages: impl Into<Languages>) -> Status {
    let status = unsafe { idax_sys::idax_parser_select_for(languages.into().0) };
    error::int_to_status(status, "parser::select_for failed")
}

/// Return the copied selected parser name, or `None` for unnamed default state.
pub fn selected_name() -> Result<Option<String>> {
    let mut out = std::ptr::null_mut();
    let status = unsafe { idax_sys::idax_parser_selected_name(&mut out) };
    if status != 0 {
        return Err(error::consume_last_error("parser::selected_name failed"));
    }
    if out.is_null() {
        return Ok(None);
    }
    unsafe {
        error::cstr_to_string_free(out, "parser::selected_name returned invalid UTF-8").map(Some)
    }
}

/// Configure command-line arguments for a named parser.
pub fn set_arguments(parser_name: &str, arguments: &str) -> Status {
    let parser_name = cstring(parser_name, "parser name")?;
    let arguments = cstring(arguments, "parser arguments")?;
    let status =
        unsafe { idax_sys::idax_parser_set_arguments(parser_name.as_ptr(), arguments.as_ptr()) };
    error::int_to_status(status, "parser::set_arguments failed")
}

/// Parse source text or a source file using a language-compatible parser.
pub fn parse_for(
    languages: impl Into<Languages>,
    input: &str,
    input_kind: InputKind,
) -> Result<ParseReport> {
    let input = cstring(input, "parser input")?;
    parse_report(
        |out| unsafe {
            idax_sys::idax_parser_parse_for(
                languages.into().0,
                input.as_ptr(),
                input_kind as i32,
                out,
            )
        },
        "parser::parse_for failed",
    )
}

/// Parse source text or a source file using a named parser.
pub fn parse_with(parser_name: &str, input: &str, input_kind: InputKind) -> Result<ParseReport> {
    let parser_name = cstring(parser_name, "parser name")?;
    let input = cstring(input, "parser input")?;
    parse_report(
        |out| unsafe {
            idax_sys::idax_parser_parse_with(
                parser_name.as_ptr(),
                input.as_ptr(),
                input_kind as i32,
                out,
            )
        },
        "parser::parse_with failed",
    )
}

/// Parse with a named parser and semantic extended options.
pub fn parse_with_options(
    parser_name: &str,
    input: &str,
    options: &ParseOptions,
) -> Result<ParseReport> {
    let parser_name = cstring(parser_name, "parser name")?;
    let input = cstring(input, "parser input")?;
    let native = idax_sys::IdaxParserParseOptions {
        input_kind: options.input_kind as i32,
        discard_result: options.discard_result as i32,
        define_base_macros: options.define_base_macros as i32,
        suppress_warnings: options.suppress_warnings as i32,
        ignore_errors: options.ignore_errors as i32,
        allow_redeclarations: options.allow_redeclarations as i32,
        no_decorate: options.no_decorate as i32,
        assume_high_level: options.assume_high_level as i32,
        lower_prototypes: options.lower_prototypes as i32,
        raw_argument_names: options.raw_argument_names as i32,
        relaxed_namespaces: options.relaxed_namespaces as i32,
        exclude_base_types: options.exclude_base_types as i32,
        allow_missing_semicolon: options.allow_missing_semicolon as i32,
        standalone_declaration: options.standalone_declaration as i32,
        allow_void: options.allow_void as i32,
        no_mangle: options.no_mangle as i32,
        pack_alignment: options.pack_alignment,
    };
    parse_report(
        |out| unsafe {
            idax_sys::idax_parser_parse_with_options(
                parser_name.as_ptr(),
                input.as_ptr(),
                &native,
                out,
            )
        },
        "parser::parse_with_options failed",
    )
}

/// Return one copied parser-defined option value.
pub fn option(parser_name: &str, option_name: &str) -> Result<String> {
    let parser_name = cstring(parser_name, "parser name")?;
    let option_name = cstring(option_name, "parser option name")?;
    let mut out = std::ptr::null_mut();
    let status = unsafe {
        idax_sys::idax_parser_option(parser_name.as_ptr(), option_name.as_ptr(), &mut out)
    };
    if status != 0 {
        return Err(error::consume_last_error("parser::option failed"));
    }
    unsafe { error::cstr_to_string_free(out, "parser::option returned a null string") }
}

/// Set one parser-defined option value.
pub fn set_option(parser_name: &str, option_name: &str, value: &str) -> Status {
    let parser_name = cstring(parser_name, "parser name")?;
    let option_name = cstring(option_name, "parser option name")?;
    let value = cstring(value, "parser option value")?;
    let status = unsafe {
        idax_sys::idax_parser_set_option(parser_name.as_ptr(), option_name.as_ptr(), value.as_ptr())
    };
    error::int_to_status(status, "parser::set_option failed")
}

fn parse_report(
    function: impl FnOnce(*mut idax_sys::IdaxParserParseReport) -> i32,
    fallback: &str,
) -> Result<ParseReport> {
    let mut out = idax_sys::IdaxParserParseReport::default();
    let status = function(&mut out);
    if status != 0 {
        return Err(error::consume_last_error(fallback));
    }
    Ok(ParseReport {
        error_count: out.error_count,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn language_discriminants_match_the_pinned_sdk() {
        assert_eq!(Language::C as u32, 0x01);
        assert_eq!(Language::Cpp as u32, 0x02);
        assert_eq!(Language::ObjectiveCpp as u32, 0x20);
        assert_eq!((Language::C | Language::Cpp).0, 0x03);
    }

    #[test]
    fn defaults_are_semantic_and_non_debugging() {
        let options = ParseOptions::default();
        assert_eq!(options.input_kind, InputKind::SourceText);
        assert!(!options.discard_result);
        assert_eq!(options.pack_alignment, 0);
        assert!(ParseReport { error_count: 0 }.is_ok());
        assert!(!ParseReport { error_count: 1 }.is_ok());
    }

    #[test]
    fn embedded_nul_is_rejected_before_ffi() {
        let failure = set_arguments("clang", "bad\0argument").unwrap_err();
        assert_eq!(failure.category, crate::error::ErrorCategory::Validation);
        let failure = option("clang", "bad\0option").unwrap_err();
        assert_eq!(failure.category, crate::error::ErrorCategory::Validation);
    }
}

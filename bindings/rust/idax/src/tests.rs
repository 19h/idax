//! Comprehensive unit tests for all pure-Rust types in the idax crate.
//!
//! These tests run without IDA / idalib — they validate type construction,
//! enum discriminants, trait impls, helper methods, conversion functions,
//! boundary conditions, and error model behavior.

#[cfg(test)]
mod error_tests {
    use crate::error::*;

    #[test]
    fn test_error_category_discriminants() {
        assert_eq!(ErrorCategory::Validation as i32, 0);
        assert_eq!(ErrorCategory::NotFound as i32, 1);
        assert_eq!(ErrorCategory::Conflict as i32, 2);
        assert_eq!(ErrorCategory::Unsupported as i32, 3);
        assert_eq!(ErrorCategory::SdkFailure as i32, 4);
        assert_eq!(ErrorCategory::Internal as i32, 5);
    }

    #[test]
    fn test_ffi_error_category_decode() {
        assert_eq!(decode_ffi_error_category(0), None);
        assert_eq!(
            decode_ffi_error_category(idax_sys::IDAX_ERROR_VALIDATION as i32),
            Some(ErrorCategory::Validation)
        );
        assert_eq!(
            decode_ffi_error_category(idax_sys::IDAX_ERROR_NOT_FOUND as i32),
            Some(ErrorCategory::NotFound)
        );
        assert_eq!(
            decode_ffi_error_category(idax_sys::IDAX_ERROR_CONFLICT as i32),
            Some(ErrorCategory::Conflict)
        );
        assert_eq!(
            decode_ffi_error_category(idax_sys::IDAX_ERROR_UNSUPPORTED as i32),
            Some(ErrorCategory::Unsupported)
        );
        assert_eq!(
            decode_ffi_error_category(idax_sys::IDAX_ERROR_SDK_FAILURE as i32),
            Some(ErrorCategory::SdkFailure)
        );
        assert_eq!(
            decode_ffi_error_category(idax_sys::IDAX_ERROR_INTERNAL as i32),
            Some(ErrorCategory::Internal)
        );
        assert_eq!(
            decode_ffi_error_category(i32::MAX),
            Some(ErrorCategory::Internal)
        );
    }

    #[test]
    fn test_error_category_equality() {
        assert_eq!(ErrorCategory::Validation, ErrorCategory::Validation);
        assert_ne!(ErrorCategory::Validation, ErrorCategory::NotFound);
        assert_ne!(ErrorCategory::Internal, ErrorCategory::SdkFailure);
    }

    #[test]
    fn test_error_category_clone_copy() {
        let cat = ErrorCategory::NotFound;
        let cloned = cat;
        assert_eq!(cat, cloned);
    }

    #[test]
    fn test_error_category_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(ErrorCategory::Validation);
        set.insert(ErrorCategory::NotFound);
        set.insert(ErrorCategory::Validation); // duplicate
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn test_error_validation_factory() {
        let e = Error::validation("bad input");
        assert_eq!(e.category, ErrorCategory::Validation);
        assert_eq!(e.message, "bad input");
        assert_eq!(e.code, 0);
        assert!(e.context.is_empty());
    }

    #[test]
    fn test_error_not_found_factory() {
        let e = Error::not_found("missing");
        assert_eq!(e.category, ErrorCategory::NotFound);
        assert_eq!(e.message, "missing");
    }

    #[test]
    fn test_error_conflict_factory() {
        let e = Error::conflict("already exists");
        assert_eq!(e.category, ErrorCategory::Conflict);
        assert_eq!(e.message, "already exists");
    }

    #[test]
    fn test_error_unsupported_factory() {
        let e = Error::unsupported("not available");
        assert_eq!(e.category, ErrorCategory::Unsupported);
        assert_eq!(e.message, "not available");
    }

    #[test]
    fn test_error_sdk_factory() {
        let e = Error::sdk("SDK error");
        assert_eq!(e.category, ErrorCategory::SdkFailure);
        assert_eq!(e.message, "SDK error");
    }

    #[test]
    fn test_error_internal_factory() {
        let e = Error::internal("bug");
        assert_eq!(e.category, ErrorCategory::Internal);
        assert_eq!(e.message, "bug");
    }

    #[test]
    fn test_error_with_context() {
        let e = Error::validation("bad").with_context("function::at");
        assert_eq!(e.context, "function::at");
        assert_eq!(e.message, "bad");
    }

    #[test]
    fn test_error_with_code() {
        let e = Error::sdk("fail").with_code(404);
        assert_eq!(e.code, 404);
        assert_eq!(e.category, ErrorCategory::SdkFailure);
    }

    #[test]
    fn test_error_chained_builders() {
        let e = Error::internal("oops")
            .with_context("test context")
            .with_code(42);
        assert_eq!(e.category, ErrorCategory::Internal);
        assert_eq!(e.message, "oops");
        assert_eq!(e.context, "test context");
        assert_eq!(e.code, 42);
    }

    #[test]
    fn test_error_display() {
        let e = Error::validation("bad input");
        let s = format!("{}", e);
        assert!(s.contains("Validation"));
        assert!(s.contains("bad input"));
    }

    #[test]
    fn test_error_debug() {
        let e = Error::internal("debug test");
        let s = format!("{:?}", e);
        assert!(s.contains("Internal"));
        assert!(s.contains("debug test"));
    }

    #[test]
    fn test_error_clone() {
        let e1 = Error::validation("original").with_context("ctx");
        let e2 = e1.clone();
        assert_eq!(e1.category, e2.category);
        assert_eq!(e1.message, e2.message);
        assert_eq!(e1.context, e2.context);
    }

    #[test]
    fn test_error_empty_strings() {
        let e = Error::validation("");
        assert!(e.message.is_empty());
        assert!(e.context.is_empty());
    }

    #[test]
    fn test_error_long_strings() {
        let long = "x".repeat(10000);
        let e = Error::validation(long.clone());
        assert_eq!(e.message.len(), 10000);
        assert_eq!(e.message, long);
    }

    #[test]
    fn test_error_unicode() {
        let e = Error::validation("über Ärger: ñ");
        assert!(e.message.contains("über"));
        assert!(e.message.contains("ñ"));
    }

    #[test]
    fn test_error_from_string() {
        let msg = String::from("dynamic string");
        let e = Error::validation(msg);
        assert_eq!(e.message, "dynamic string");
    }

    #[test]
    fn test_result_success() {
        let r: Result<i32> = Ok(42);
        assert!(r.is_ok());
        assert_eq!(r.unwrap(), 42);
    }

    #[test]
    fn test_result_error() {
        let r: Result<i32> = Err(Error::not_found("missing"));
        assert!(r.is_err());
        assert_eq!(r.unwrap_err().category, ErrorCategory::NotFound);
    }

    #[test]
    fn test_status_ok() {
        let s: Status = Ok(());
        assert!(s.is_ok());
    }

    #[test]
    fn test_status_error() {
        let s: Status = Err(Error::internal("fail"));
        assert!(s.is_err());
    }

    #[test]
    fn test_result_map() {
        let r: Result<i32> = Ok(42);
        let mapped = r.map(|v| v * 2);
        assert_eq!(mapped.unwrap(), 84);
    }

    #[test]
    fn test_result_and_then() {
        let r: Result<i32> = Ok(42);
        let chained = r.and_then(|v| Ok(v.to_string()));
        assert_eq!(chained.unwrap(), "42");
    }

    #[test]
    fn test_result_unwrap_or() {
        let r: Result<i32> = Err(Error::validation("bad"));
        assert_eq!(r.unwrap_or(99), 99);
    }

    #[test]
    fn test_bool_to_status_ok() {
        let s = bool_to_status(true, "test");
        assert!(s.is_ok());
    }

    #[test]
    fn test_int_to_status_ok() {
        let s = int_to_status(0, "test");
        assert!(s.is_ok());
    }

    #[test]
    fn test_error_code_boundaries() {
        let e1 = Error::internal("").with_code(i32::MAX);
        assert_eq!(e1.code, i32::MAX);

        let e2 = Error::internal("").with_code(i32::MIN);
        assert_eq!(e2.code, i32::MIN);

        let e3 = Error::internal("").with_code(0);
        assert_eq!(e3.code, 0);
    }

    #[test]
    fn test_error_stress_creation() {
        let errors: Vec<Error> = (0..10000)
            .map(|i| Error::validation(format!("error {}", i)))
            .collect();
        assert_eq!(errors.len(), 10000);
        assert_eq!(errors[0].message, "error 0");
        assert_eq!(errors[9999].message, "error 9999");
    }
}

#[cfg(test)]
mod exception_tests {
    use crate::address::Range;
    use crate::exception::*;

    #[test]
    fn exception_models_preserve_semantic_variants() {
        let metadata = HandlerMetadata {
            regions: vec![Range::new(0x20, 0x24)],
            stack_displacement: Some(-16),
            frame_register: Some(5),
        };
        let definition = BlockDefinition {
            protected_regions: vec![Range::new(0x10, 0x18)],
            handlers: HandlerSet::Cpp(vec![CatchHandler {
                metadata: metadata.clone(),
                object_displacement: Some(-8),
                selector: CatchSelector::Typed(7),
            }]),
        };
        assert_eq!(definition.protected_regions[0].end, 0x18);
        assert!(matches!(definition.handlers, HandlerSet::Cpp(_)));

        let seh = SehHandler {
            metadata,
            filter_regions: Vec::new(),
            disposition: Some(SehDisposition::ContinueSearch),
        };
        assert_eq!(seh.disposition, Some(SehDisposition::ContinueSearch));
        assert_ne!(Location::CppTry, Location::SehTry);
    }
}

#[cfg(test)]
mod address_tests {
    use crate::address::*;

    #[test]
    fn test_bad_address_value() {
        assert_eq!(BAD_ADDRESS, u64::MAX);
        assert_eq!(BAD_ADDRESS, !0u64);
        assert_eq!(BAD_ADDRESS, 0xFFFF_FFFF_FFFF_FFFFu64);
    }

    #[test]
    fn test_bad_address_arithmetic() {
        assert_eq!(BAD_ADDRESS.wrapping_add(1), 0);
        assert_eq!(BAD_ADDRESS.wrapping_sub(1), 0xFFFF_FFFF_FFFF_FFFEu64);
    }

    #[test]
    fn test_range_basic() {
        let r = Range::new(0x1000, 0x2000);
        assert_eq!(r.size(), 0x1000);
        assert!(r.contains(0x1000));
        assert!(r.contains(0x1FFF));
        assert!(!r.contains(0x2000)); // half-open
        assert!(!r.contains(0x0FFF));
        assert!(!r.is_empty());
    }

    #[test]
    fn test_range_empty_equal() {
        let r = Range::new(0x1000, 0x1000);
        assert!(r.is_empty());
        assert_eq!(r.size(), 0);
        assert!(!r.contains(0x1000));
    }

    #[test]
    fn test_range_inverted() {
        let r = Range::new(0x2000, 0x1000);
        assert!(r.is_empty());
        assert_eq!(r.size(), 0);
        assert!(!r.contains(0x1500));
    }

    #[test]
    fn test_range_single_byte() {
        let r = Range::new(0, 1);
        assert_eq!(r.size(), 1);
        assert!(r.contains(0));
        assert!(!r.contains(1));
        assert!(!r.is_empty());
    }

    #[test]
    fn test_range_max() {
        let r = Range::new(0, BAD_ADDRESS);
        assert_eq!(r.size(), BAD_ADDRESS);
        assert!(r.contains(0));
        assert!(r.contains(BAD_ADDRESS - 1));
        assert!(!r.contains(BAD_ADDRESS));
    }

    #[test]
    fn test_range_large() {
        let r = Range::new(0x7FFF_FFFF_FFFF_FFFF, 0xFFFF_FFFF_FFFF_FFFF);
        assert_eq!(r.size(), 0x8000_0000_0000_0000u64);
        assert!(r.contains(0x7FFF_FFFF_FFFF_FFFF));
        assert!(!r.contains(0xFFFF_FFFF_FFFF_FFFF));
    }

    #[test]
    fn test_range_default() {
        let r = Range::default();
        assert_eq!(r.start, BAD_ADDRESS);
        assert_eq!(r.end, BAD_ADDRESS);
        assert!(r.is_empty());
        assert_eq!(r.size(), 0);
    }

    #[test]
    fn test_range_equality() {
        let a = Range::new(0x1000, 0x2000);
        let b = Range::new(0x1000, 0x2000);
        let c = Range::new(0x1000, 0x3000);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn test_range_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(Range::new(0x1000, 0x2000));
        set.insert(Range::new(0x1000, 0x2000)); // duplicate
        set.insert(Range::new(0x3000, 0x4000));
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn test_range_clone_copy() {
        let r1 = Range::new(0x1000, 0x2000);
        let r2 = r1; // Copy
        assert_eq!(r1, r2);
        let r3 = r1.clone();
        assert_eq!(r1, r3);
    }

    #[test]
    fn test_range_debug() {
        let r = Range::new(0x1000, 0x2000);
        let s = format!("{:?}", r);
        assert!(s.contains("Range"));
        assert!(s.contains("4096")); // 0x1000
    }

    #[test]
    fn test_range_contains_stress() {
        let r = Range::new(0x400000, 0x500000);
        for a in 0x400000..0x400100 {
            assert!(r.contains(a));
        }
        for a in 0x4FFFF0..0x500000 {
            assert!(r.contains(a));
        }
        assert!(!r.contains(0x500000));
        assert!(!r.contains(0x3FFFFF));
    }

    #[test]
    fn test_range_zero() {
        let r = Range::new(0, 0);
        assert!(r.is_empty());
        let r2 = Range::new(0, 0x100);
        assert!(r2.contains(0));
    }

    #[test]
    fn test_predicate_discriminants() {
        assert_eq!(Predicate::Mapped as i32, 0);
        assert_eq!(Predicate::Loaded as i32, 1);
        assert_eq!(Predicate::Code as i32, 2);
        assert_eq!(Predicate::Data as i32, 3);
        assert_eq!(Predicate::Unknown as i32, 4);
        assert_eq!(Predicate::Head as i32, 5);
        assert_eq!(Predicate::Tail as i32, 6);
    }

    #[test]
    fn test_predicate_uniqueness() {
        let preds = [
            Predicate::Mapped,
            Predicate::Loaded,
            Predicate::Code,
            Predicate::Data,
            Predicate::Unknown,
            Predicate::Head,
            Predicate::Tail,
        ];
        for (i, a) in preds.iter().enumerate() {
            for (j, b) in preds.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b);
                }
            }
        }
    }

    #[test]
    fn test_predicate_clone() {
        let p = Predicate::Code;
        let p2 = p;
        assert_eq!(p, p2);
    }

    #[test]
    fn test_address_type_aliases() {
        let a: Address = 0xDEAD_BEEF_CAFE_BABEu64;
        assert_eq!(a, 0xDEAD_BEEF_CAFE_BABEu64);

        let d: AddressDelta = -1;
        assert_eq!(d, -1i64);
        let d_min: AddressDelta = i64::MIN;
        assert_eq!(d_min, i64::MIN);

        let s: AddressSize = u64::MAX;
        assert_eq!(s, u64::MAX);
    }
}

#[cfg(test)]
mod diagnostics_tests {
    use crate::diagnostics::*;
    use crate::error::Error;

    #[test]
    fn test_log_level_discriminants() {
        assert_eq!(LogLevel::Error as i32, 0);
        assert_eq!(LogLevel::Warning as i32, 1);
        assert_eq!(LogLevel::Info as i32, 2);
        assert_eq!(LogLevel::Debug as i32, 3);
        assert_eq!(LogLevel::Trace as i32, 4);
    }

    #[test]
    fn test_log_level_ordering() {
        assert!(LogLevel::Error < LogLevel::Warning);
        assert!(LogLevel::Warning < LogLevel::Info);
        assert!(LogLevel::Info < LogLevel::Debug);
        assert!(LogLevel::Debug < LogLevel::Trace);
    }

    #[test]
    fn test_log_level_equality() {
        assert_eq!(LogLevel::Error, LogLevel::Error);
        assert_ne!(LogLevel::Error, LogLevel::Warning);
    }

    #[test]
    fn test_performance_counters_default() {
        let c = PerformanceCounters::default();
        assert_eq!(c.log_messages, 0);
        assert_eq!(c.invariant_failures, 0);
    }

    #[test]
    fn test_performance_counters_clone() {
        let c = PerformanceCounters {
            log_messages: 42,
            invariant_failures: 5,
        };
        let c2 = c;
        assert_eq!(c.log_messages, c2.log_messages);
        assert_eq!(c.invariant_failures, c2.invariant_failures);
    }

    #[test]
    fn test_enrich_empty_context() {
        let base = Error::internal("msg");
        let enriched = enrich(base, "added");
        assert_eq!(enriched.context, "added");
        assert_eq!(enriched.message, "msg");
    }

    #[test]
    fn test_enrich_existing_context() {
        let base = Error {
            category: crate::error::ErrorCategory::Internal,
            code: 0,
            message: "msg".into(),
            context: "base".into(),
        };
        let enriched = enrich(base, "extra");
        assert!(enriched.context.contains("base"));
        assert!(enriched.context.contains("extra"));
    }

    #[test]
    fn test_enrich_chain() {
        let e = enrich(enrich(Error::validation("m"), "a"), "b");
        assert!(e.context.contains("a"));
        assert!(e.context.contains("b"));
    }

    #[test]
    fn test_assert_invariant_true() {
        let s = assert_invariant(true, "should pass");
        assert!(s.is_ok());
    }

    #[test]
    fn test_assert_invariant_false() {
        let s = assert_invariant(false, "should fail");
        assert!(s.is_err());
        let err = s.unwrap_err();
        assert_eq!(err.category, crate::error::ErrorCategory::Internal);
        assert!(err.message.contains("invariant"));
    }
}

#[cfg(test)]
mod xref_tests {
    use crate::xref::*;

    #[test]
    fn test_code_type_discriminants() {
        assert_eq!(CodeType::CallFar as i32, 0);
        assert_eq!(CodeType::CallNear as i32, 1);
        assert_eq!(CodeType::JumpFar as i32, 2);
        assert_eq!(CodeType::JumpNear as i32, 3);
        assert_eq!(CodeType::Flow as i32, 4);
    }

    #[test]
    fn test_data_type_discriminants() {
        assert_eq!(DataType::Offset as i32, 0);
        assert_eq!(DataType::Write as i32, 1);
        assert_eq!(DataType::Read as i32, 2);
        assert_eq!(DataType::Text as i32, 3);
        assert_eq!(DataType::Informational as i32, 4);
    }

    #[test]
    fn test_reference_type_discriminants() {
        assert_eq!(ReferenceType::Unknown as i32, 0);
        assert_eq!(ReferenceType::Flow as i32, 1);
        assert_eq!(ReferenceType::CallNear as i32, 2);
        assert_eq!(ReferenceType::CallFar as i32, 3);
        assert_eq!(ReferenceType::JumpNear as i32, 4);
        assert_eq!(ReferenceType::JumpFar as i32, 5);
        assert_eq!(ReferenceType::Offset as i32, 6);
        assert_eq!(ReferenceType::Read as i32, 7);
        assert_eq!(ReferenceType::Write as i32, 8);
        assert_eq!(ReferenceType::Text as i32, 9);
        assert_eq!(ReferenceType::Informational as i32, 10);
    }

    #[test]
    fn test_is_call() {
        assert!(is_call(ReferenceType::CallNear));
        assert!(is_call(ReferenceType::CallFar));
        assert!(!is_call(ReferenceType::JumpNear));
        assert!(!is_call(ReferenceType::Flow));
        assert!(!is_call(ReferenceType::Read));
    }

    #[test]
    fn test_is_jump() {
        assert!(is_jump(ReferenceType::JumpNear));
        assert!(is_jump(ReferenceType::JumpFar));
        assert!(!is_jump(ReferenceType::CallNear));
        assert!(!is_jump(ReferenceType::Flow));
    }

    #[test]
    fn test_is_flow() {
        assert!(is_flow(ReferenceType::Flow));
        assert!(!is_flow(ReferenceType::CallNear));
        assert!(!is_flow(ReferenceType::JumpNear));
        assert!(!is_flow(ReferenceType::Read));
    }

    #[test]
    fn test_is_data() {
        assert!(is_data(ReferenceType::Offset));
        assert!(is_data(ReferenceType::Read));
        assert!(is_data(ReferenceType::Write));
        assert!(is_data(ReferenceType::Text));
        assert!(is_data(ReferenceType::Informational));
        assert!(!is_data(ReferenceType::CallNear));
        assert!(!is_data(ReferenceType::Flow));
    }

    #[test]
    fn test_is_data_read() {
        assert!(is_data_read(ReferenceType::Read));
        assert!(!is_data_read(ReferenceType::Write));
        assert!(!is_data_read(ReferenceType::Offset));
    }

    #[test]
    fn test_is_data_write() {
        assert!(is_data_write(ReferenceType::Write));
        assert!(!is_data_write(ReferenceType::Read));
        assert!(!is_data_write(ReferenceType::Offset));
    }

    #[test]
    fn test_all_reference_types_classified() {
        let all_types = [
            ReferenceType::Unknown,
            ReferenceType::Flow,
            ReferenceType::CallNear,
            ReferenceType::CallFar,
            ReferenceType::JumpNear,
            ReferenceType::JumpFar,
            ReferenceType::Offset,
            ReferenceType::Read,
            ReferenceType::Write,
            ReferenceType::Text,
            ReferenceType::Informational,
        ];
        // Every type should be classifiable by at least one predicate or be Unknown/Flow
        for t in &all_types {
            let classified = is_call(*t)
                || is_jump(*t)
                || is_flow(*t)
                || is_data(*t)
                || *t == ReferenceType::Unknown;
            assert!(classified, "Unclassified type: {:?}", t);
        }
    }
}

#[cfg(test)]
mod search_tests {
    use crate::search::*;

    #[test]
    fn test_direction_values() {
        assert_ne!(Direction::Forward, Direction::Backward);
    }

    #[test]
    fn test_direction_clone() {
        let d = Direction::Forward;
        let d2 = d;
        assert_eq!(d, d2);
    }
}

#[cfg(test)]
mod lines_tests {
    use crate::address::{Address, Range};
    use crate::error::{Result, Status};
    use crate::lines::*;

    #[test]
    fn test_source_file_types_and_signatures() {
        let _: fn(Range, &str) -> Status = add_source_file;
        let _: fn(Address) -> Result<SourceFile> = source_file_at;
        let _: fn(Address) -> Status = remove_source_file;
        let source = SourceFile {
            filename: "/src/example.cpp".to_owned(),
            range: Range::new(0x1000, 0x1100),
        };
        assert!(source.range.contains(0x1080));
    }

    #[test]
    fn test_color_enum_values() {
        assert_eq!(Color::Default as u8, 0x01);
        assert_eq!(Color::Keyword as u8, 0x20);
        assert_eq!(Color::Register as u8, 0x21);
        assert_eq!(Color::Collapsed as u8, 0x27);
    }

    #[test]
    fn test_color_constants() {
        assert_eq!(COLOR_ON, '\x01');
        assert_eq!(COLOR_OFF, '\x02');
        assert_eq!(COLOR_ESC, '\x03');
        assert_eq!(COLOR_INV, '\x04');
        assert_eq!(COLOR_ADDR, 0x28);
        assert_eq!(COLOR_ADDR_SIZE, 16);
    }

    #[test]
    fn test_colstr_basic() {
        let tagged = colstr("hello", Color::Keyword);
        assert!(!tagged.is_empty());
        assert!(tagged.len() > 5); // ON + color + "hello" + OFF + color
        assert!(tagged.contains("hello"));
    }

    #[test]
    fn test_colstr_empty() {
        let tagged = colstr("", Color::Number);
        assert!(!tagged.is_empty()); // still has tags
        assert_eq!(tagged.len(), 4); // ON + color + OFF + color
    }

    #[test]
    fn test_colstr_all_colors() {
        let colors = [
            Color::Default,
            Color::RegularComment,
            Color::RepeatableComment,
            Color::AutoComment,
            Color::Instruction,
            Color::DataName,
            Color::RegularDataName,
            Color::DemangledName,
            Color::Symbol,
            Color::CharLiteral,
            Color::String,
            Color::Number,
            Color::Void,
            Color::CodeReference,
            Color::DataReference,
            Color::CodeRefTail,
            Color::DataRefTail,
            Color::Error,
            Color::Prefix,
            Color::BinaryPrefix,
            Color::Extra,
            Color::AltOperand,
            Color::HiddenName,
            Color::LibraryName,
            Color::LocalName,
            Color::DummyCodeName,
            Color::AsmDirective,
            Color::Macro,
            Color::DataString,
            Color::DataChar,
            Color::DataNumber,
            Color::Keyword,
            Color::Register,
            Color::ImportedName,
            Color::SegmentName,
            Color::UnknownName,
            Color::CodeName,
            Color::UserName,
            Color::Collapsed,
        ];
        for color in &colors {
            let tagged = colstr("test", *color);
            assert!(tagged.contains("test"));
        }
    }

    #[test]
    fn test_colstr_structure() {
        let tagged = colstr("AB", Color::Number);
        let bytes: Vec<u8> = tagged.bytes().collect();
        assert_eq!(bytes[0], COLOR_ON as u8); // ON
        assert_eq!(bytes[1], Color::Number as u8); // color
        assert_eq!(bytes[2], b'A');
        assert_eq!(bytes[3], b'B');
        assert_eq!(bytes[4], COLOR_OFF as u8); // OFF
        assert_eq!(bytes[5], Color::Number as u8); // color
    }

    #[test]
    fn test_color_uniqueness() {
        let colors = [
            Color::Default,
            Color::RegularComment,
            Color::RepeatableComment,
            Color::AutoComment,
            Color::Instruction,
            Color::DataName,
            Color::RegularDataName,
            Color::DemangledName,
            Color::Symbol,
            Color::CharLiteral,
            Color::String,
            Color::Number,
            Color::Void,
            Color::CodeReference,
            Color::DataReference,
            Color::CodeRefTail,
            Color::DataRefTail,
            Color::Error,
            Color::Prefix,
            Color::BinaryPrefix,
            Color::Extra,
            Color::AltOperand,
            Color::HiddenName,
            Color::LibraryName,
            Color::LocalName,
            Color::DummyCodeName,
            Color::AsmDirective,
            Color::Macro,
            Color::DataString,
            Color::DataChar,
            Color::DataNumber,
            Color::Keyword,
            Color::Register,
            Color::ImportedName,
            Color::SegmentName,
            Color::UnknownName,
            Color::CodeName,
            Color::UserName,
            Color::Collapsed,
        ];
        use std::collections::HashSet;
        let mut values: HashSet<u8> = HashSet::new();
        for c in &colors {
            assert!(values.insert(*c as u8), "duplicate color value: {:?}", c);
        }
    }
}

#[cfg(test)]
mod segment_tests {
    use crate::segment::{Permissions, Type};

    #[test]
    fn test_segment_type_discriminants() {
        assert_eq!(Type::Normal as i32, 0);
        assert_eq!(Type::External as i32, 1);
        assert_eq!(Type::Code as i32, 2);
        assert_eq!(Type::Data as i32, 3);
        assert_eq!(Type::Bss as i32, 4);
        assert_eq!(Type::AbsoluteSymbols as i32, 5);
        assert_eq!(Type::Common as i32, 6);
        assert_eq!(Type::Null as i32, 7);
        assert_eq!(Type::Undefined as i32, 8);
        assert_eq!(Type::Import as i32, 9);
        assert_eq!(Type::InternalMemory as i32, 10);
        assert_eq!(Type::Group as i32, 11);
    }

    #[test]
    fn test_permissions_default() {
        let p = Permissions::default();
        assert!(!p.read);
        assert!(!p.write);
        assert!(!p.execute);
    }

    #[test]
    fn test_permissions_construction() {
        let p = Permissions {
            read: true,
            write: false,
            execute: true,
        };
        assert!(p.read);
        assert!(!p.write);
        assert!(p.execute);
    }
}

#[cfg(test)]
mod data_tests {
    use crate::address::{Address, AddressSize};
    use crate::data::*;
    use crate::error::{Result, Status};

    #[test]
    fn test_string_list_types_and_signatures() {
        let options = StringListOptions::default();
        assert_eq!(options.string_types, vec![0]);
        assert_eq!(options.minimum_length, 5);
        let literal = StringLiteral {
            address: 0x1000,
            byte_length: 6,
            string_type: 0,
            text: "hello".to_owned(),
        };
        assert_eq!(literal.byte_length, 6);

        let _: fn() -> Result<StringListOptions> = string_list_options;
        let _: fn(&StringListOptions) -> Status = configure_string_list;
        let _: fn() -> Status = rebuild_string_list;
        let _: fn() -> Status = clear_string_list;
        let _: fn(bool) -> Result<Vec<StringLiteral>> = string_literals;
    }

    #[test]
    fn test_element_definition_function_signatures() {
        let functions: [fn(Address, AddressSize) -> Status; 11] = [
            define_byte,
            define_word,
            define_dword,
            define_qword,
            define_oword,
            define_yword,
            define_zword,
            define_tbyte,
            define_packed_real,
            define_float,
            define_double,
        ];
        assert_eq!(functions.len(), 11);

        let size_functions: [fn() -> crate::error::Result<AddressSize>; 2] =
            [tbyte_element_size, packed_real_element_size];
        assert_eq!(size_functions.len(), 2);
    }

    #[test]
    fn test_custom_data_lifecycle_types_and_signatures() {
        let context = CustomDataFormatContext::default();
        assert_eq!(context.type_id, CustomDataTypeId(0));
        assert_eq!(context.operand_index, -1);
        let type_definition = CustomDataTypeDefinition::default();
        assert!(type_definition.allow_duplicates);
        assert!(type_definition.may_create_at.is_none());
        assert!(type_definition.calculate_size.is_none());
        let format_definition = CustomDataFormatDefinition::default();
        assert_eq!(format_definition.value_size, 0);
        assert!(format_definition.render.is_none());

        let _: fn(&CustomDataTypeDefinition) -> Result<CustomDataTypeId> =
            register_custom_data_type;
        let _: fn(CustomDataTypeId) -> Status = unregister_custom_data_type;
        let _: fn(CustomDataTypeId) -> Result<CustomDataTypeInfo> = custom_data_type;
        let _: fn(&str) -> Result<CustomDataTypeId> = find_custom_data_type;
        let _: fn(AddressSize, AddressSize) -> Result<Vec<CustomDataTypeInfo>> = custom_data_types;
        let _: fn(&CustomDataFormatDefinition) -> Result<CustomDataFormatId> =
            register_custom_data_format;
        let _: fn(CustomDataFormatId) -> Status = unregister_custom_data_format;
        let _: fn(CustomDataFormatId) -> Result<CustomDataFormatInfo> = custom_data_format;
        let _: fn(&str) -> Result<CustomDataFormatId> = find_custom_data_format;
        let _: fn(CustomDataTypeId) -> Result<Vec<CustomDataFormatInfo>> = custom_data_formats;
        let _: fn() -> Result<Vec<CustomDataFormatInfo>> = standard_custom_data_formats;
        let _: fn(CustomDataTypeId, CustomDataFormatId) -> Status = attach_custom_data_format;
        let _: fn(CustomDataTypeId, CustomDataFormatId) -> Status = detach_custom_data_format;
        let _: fn(CustomDataTypeId, CustomDataFormatId) -> Result<bool> =
            is_custom_data_format_attached;
        let _: fn(CustomDataFormatId) -> Status = attach_custom_data_format_to_standard_types;
        let _: fn(CustomDataFormatId) -> Status = detach_custom_data_format_from_standard_types;
        let _: fn(CustomDataFormatId) -> Result<bool> =
            is_custom_data_format_attached_to_standard_types;
        let _: fn(CustomDataTypeId, Address, AddressSize) -> Result<AddressSize> =
            custom_data_item_size;
        let _: fn(Address, AddressSize, CustomDataTypeId, CustomDataFormatId) -> Status =
            define_custom;
        let _: fn(Address, CustomDataTypeId, CustomDataFormatId, AddressSize) -> Status =
            define_custom_inferred;
        let _: fn(Address) -> Result<CustomDataItemInfo> = custom_data_at;
        let _: fn(CustomDataFormatId, &[u8], CustomDataFormatContext) -> Result<String> =
            render_custom_data;
        let _: fn(CustomDataFormatId, &str, CustomDataFormatContext) -> Result<Vec<u8>> =
            scan_custom_data;
        let _: fn(CustomDataFormatId, CustomDataFormatContext) -> Status = analyze_custom_data;
    }
}

#[cfg(test)]
mod instruction_tests {
    use crate::instruction::*;

    #[test]
    fn test_operand_type_discriminants() {
        assert_eq!(OperandType::None as i32, 0);
        assert_eq!(OperandType::Register as i32, 1);
        assert_eq!(OperandType::Immediate as i32, 5);
    }

    #[test]
    fn test_operand_format_discriminants() {
        assert_eq!(OperandFormat::Default as i32, 0);
        assert_eq!(OperandFormat::Hex as i32, 1);
        assert_eq!(OperandFormat::Decimal as i32, 2);
        assert_eq!(OperandFormat::StackVariable as i32, 8);
    }

    #[test]
    fn test_register_category_discriminants() {
        assert_eq!(RegisterCategory::Unknown as i32, 0);
        assert_eq!(RegisterCategory::GeneralPurpose as i32, 1);
        assert_eq!(RegisterCategory::Segment as i32, 2);
        assert_eq!(RegisterCategory::FloatingPoint as i32, 3);
        assert_eq!(RegisterCategory::Vector as i32, 4);
        assert_eq!(RegisterCategory::Other as i32, 8);
    }

    #[test]
    fn test_operand_access_mode_signatures() {
        let _: fn(&Operand) -> bool = Operand::is_read;
        let _: fn(&Operand) -> bool = Operand::is_written;
    }

    #[test]
    fn test_operand_enum_signatures() {
        let value = OperandEnum {
            name: "sample".to_string(),
            serial: 2,
        };
        assert_eq!(value.name, "sample");
        assert_eq!(value.serial, 2);
        let _: fn(crate::address::Address, i32, &str, u8) -> crate::error::Status =
            set_operand_enum;
        let _: fn(crate::address::Address, i32) -> crate::error::Result<OperandEnum> = operand_enum;
    }

    #[test]
    fn test_opaque_struct_offset_signatures() {
        let path = StructOffsetPath {
            structure_name: "root".to_string(),
            member_names: vec!["member".to_string()],
            delta: -4,
        };
        assert_eq!(path.structure_name, "root");
        assert_eq!(path.member_names, vec!["member"]);
        assert_eq!(path.delta, -4);
        let _: fn(
            crate::address::Address,
            i32,
            &str,
            usize,
            crate::address::AddressDelta,
        ) -> crate::error::Result<bool> = ensure_operand_struct_member_offset;
        let _: fn(crate::address::Address, i32) -> crate::error::Result<StructOffsetPath> =
            operand_struct_offset_path;
    }
}

#[cfg(test)]
mod types_tests {
    use crate::error::Result;
    use crate::types::{
        self, CallingConvention, EnumDetails, EnumRadix, FunctionArgument, FunctionDetails, Member,
        ParseDeclarationsOptions, ParseDeclarationsReport, PointerDetails, TypeInfo, TypeKind,
        UdtDetails,
    };

    #[test]
    fn test_calling_convention_discriminants() {
        assert_eq!(CallingConvention::Unknown as i32, 0);
        assert_eq!(CallingConvention::Cdecl as i32, 1);
        assert_eq!(CallingConvention::Stdcall as i32, 2);
        assert_eq!(CallingConvention::Pascal as i32, 3);
        assert_eq!(CallingConvention::Fastcall as i32, 4);
        assert_eq!(CallingConvention::Thiscall as i32, 5);
        assert_eq!(CallingConvention::Swift as i32, 6);
        assert_eq!(CallingConvention::Golang as i32, 7);
        assert_eq!(CallingConvention::UserDefined as i32, 8);
    }

    #[test]
    fn test_rich_type_metadata_discriminants() {
        assert_eq!(TypeKind::Unknown as i32, 0);
        assert_eq!(TypeKind::Void as i32, 1);
        assert_eq!(TypeKind::Bool as i32, 2);
        assert_eq!(TypeKind::Character as i32, 3);
        assert_eq!(TypeKind::SignedInteger as i32, 4);
        assert_eq!(TypeKind::UnsignedInteger as i32, 5);
        assert_eq!(TypeKind::FloatingPoint as i32, 6);
        assert_eq!(TypeKind::Pointer as i32, 7);
        assert_eq!(TypeKind::Array as i32, 8);
        assert_eq!(TypeKind::Function as i32, 9);
        assert_eq!(TypeKind::Struct as i32, 10);
        assert_eq!(TypeKind::Union as i32, 11);
        assert_eq!(TypeKind::Enum as i32, 12);
        assert_eq!(TypeKind::Typedef as i32, 13);

        assert_eq!(EnumRadix::Unknown as i32, 0);
        assert_eq!(EnumRadix::Binary as i32, 1);
        assert_eq!(EnumRadix::Octal as i32, 2);
        assert_eq!(EnumRadix::Decimal as i32, 3);
        assert_eq!(EnumRadix::Hexadecimal as i32, 4);
    }

    #[test]
    fn test_rich_type_metadata_function_signatures() {
        let _: fn(&TypeInfo) -> bool = TypeInfo::is_bool;
        let _: fn(&TypeInfo) -> bool = TypeInfo::is_char;
        let _: fn(&TypeInfo) -> bool = TypeInfo::is_unsigned_char;
        let _: fn(&TypeInfo) -> bool = TypeInfo::is_signed;
        let _: fn(&TypeInfo) -> bool = TypeInfo::is_forward_declaration;
        let _: fn(&TypeInfo) -> Result<TypeKind> = TypeInfo::forward_declaration_kind;
        let _: fn(&TypeInfo) -> Result<TypeKind> = TypeInfo::kind;
        let _: fn(&TypeInfo) -> Result<String> = TypeInfo::name;
        let _: fn(&TypeInfo, Option<&str>) -> Result<String> = TypeInfo::declaration;
        let _: fn(&TypeInfo) -> Result<PointerDetails> = TypeInfo::pointer_details;
        let _: fn(&TypeInfo, &TypeInfo, i64) -> Result<TypeInfo> = TypeInfo::with_shifted_parent;
        let _: fn(&TypeInfo) -> Result<FunctionDetails> = TypeInfo::function_details;
        let _: fn(&TypeInfo, usize, &TypeInfo) -> Result<TypeInfo> =
            TypeInfo::with_function_argument_type;
        let _: fn(&TypeInfo, usize, &str) -> Result<TypeInfo> =
            TypeInfo::with_function_argument_name;
        let _: fn(&TypeInfo, &TypeInfo) -> Result<TypeInfo> = TypeInfo::with_function_return_type;
        let _: fn(&TypeInfo) -> Result<EnumDetails> = TypeInfo::enum_details;
        let _: fn(&TypeInfo) -> Result<UdtDetails> = TypeInfo::udt_details;
        let _: fn(&TypeInfo, bool, bool) -> crate::error::Status = TypeInfo::set_udt_semantics;
        let _: fn(&TypeInfo, &str) -> Result<TypeInfo> = TypeInfo::replace_forward_declaration;
        let _: fn(&TypeInfo, usize) -> Result<Vec<crate::address::Address>> =
            TypeInfo::member_references;
        let _: fn(&TypeInfo, usize, crate::address::Address) -> Result<bool> =
            TypeInfo::ensure_member_reference;

        let member = Member {
            name: "field".to_string(),
            r#type: TypeInfo::from_raw(std::ptr::null_mut()),
            byte_offset: 4,
            bit_size: 3,
            bit_offset: 32,
            storage_byte_width: 4,
            is_baseclass: false,
            is_vftable: false,
            is_gap: false,
            is_bitfield: true,
            comment: String::new(),
        };
        assert_eq!(member.bit_offset, 32);
        assert!(member.is_bitfield);

        let argument = FunctionArgument {
            name: "arg".to_string(),
            r#type: TypeInfo::from_raw(std::ptr::null_mut()),
        };
        let details = FunctionDetails {
            return_type: TypeInfo::from_raw(std::ptr::null_mut()),
            arguments: vec![argument],
            calling_convention: CallingConvention::Cdecl,
            variadic: false,
        };
        assert_eq!(details.arguments.len(), 1);
    }

    #[test]
    fn test_parse_declarations_function_signature_and_report() {
        let _: fn(&str, ParseDeclarationsOptions) -> Result<ParseDeclarationsReport> =
            types::parse_declarations;

        let options = ParseDeclarationsOptions {
            suppress_warnings: true,
            pack_alignment: 1,
            ..Default::default()
        };
        assert!(options.suppress_warnings);
        assert_eq!(options.pack_alignment, 1);

        let ok_report = ParseDeclarationsReport { error_count: 0 };
        assert!(ok_report.ok());
        let error_report = ParseDeclarationsReport { error_count: 2 };
        assert!(!error_report.ok());
    }
}

#[cfg(test)]
mod function_tests {
    use crate::address::Address;
    use crate::error::{Result, Status};
    use crate::function;
    use crate::types::TypeInfo;

    #[test]
    fn test_prototype_apply_function_signatures() {
        let _: fn(Address, &TypeInfo) -> Status = function::set_prototype;
        let _: fn(Address, &str) -> Status = function::apply_decl;
        let _: fn(Address, Option<&str>) -> Result<String> = function::declaration;
    }
}

#[cfg(test)]
mod fixup_tests {
    use crate::fixup::Type;

    #[test]
    fn test_fixup_type_discriminants() {
        assert_eq!(Type::Off8 as i32, 0);
        assert_eq!(Type::Off16 as i32, 1);
        assert_eq!(Type::Off32 as i32, 4);
        assert_eq!(Type::Off64 as i32, 10);
        assert_eq!(Type::Custom as i32, 14);
    }
}

#[cfg(test)]
mod decompiler_tests {
    use crate::address::Address;
    use crate::decompiler::*;
    use crate::error::{Result, Status};

    #[test]
    fn test_maturity_discriminants() {
        assert_eq!(Maturity::Zero as i32, 0);
        assert_eq!(Maturity::Built as i32, 1);
        assert_eq!(Maturity::Final as i32, 8);
    }

    #[test]
    fn test_owned_microcode_graph_surface() {
        assert_eq!(MicrocodeMaturity::Generated as i32, 1);
        assert_eq!(MicrocodeMaturity::Preoptimized as i32, 2);
        assert_eq!(MicrocodeMaturity::LocalVariables as i32, 8);
        assert_eq!(
            MicrocodeGenerationOptions::default().maturity,
            MicrocodeMaturity::Preoptimized
        );
        assert!(!MicrocodeGenerationOptions::default().analyze_calls);
        assert_eq!(MicrocodeOpcode::SignedExtend as i32, 20);
        assert_eq!(MicrocodeOpcode::Other as i32, 26);
        assert_eq!(MicrocodeOperandKind::AddressReference as i32, 11);
        assert_eq!(MicrocodeOperandKind::Other as i32, 15);
        assert_eq!(MicrocodeValueLocationKind::Scattered as i32, 7);
        let _: fn(Address, MicrocodeGenerationOptions) -> Result<MicrocodeFunction> =
            generate_microcode;
    }

    #[test]
    fn test_item_type_values() {
        assert_eq!(ItemType::ExprEmpty as i32, 0);
        assert_eq!(ItemType::StmtEmpty as i32, 70);
    }

    #[test]
    fn test_is_expression() {
        assert!(is_expression(ItemType::ExprEmpty));
        assert!(is_expression(ItemType::ExprComma));
        assert!(is_expression(ItemType::ExprCall));
        assert!(!is_expression(ItemType::StmtEmpty));
        assert!(!is_expression(ItemType::StmtIf));
    }

    #[test]
    fn test_is_statement() {
        assert!(is_statement(ItemType::StmtEmpty));
        assert!(is_statement(ItemType::StmtIf));
        assert!(is_statement(ItemType::StmtReturn));
        assert!(!is_statement(ItemType::ExprEmpty));
        assert!(!is_statement(ItemType::ExprCall));
    }

    #[test]
    fn test_visit_action_discriminants() {
        assert_eq!(VisitAction::Continue as i32, 0);
        assert_eq!(VisitAction::Stop as i32, 1);
        assert_eq!(VisitAction::SkipChildren as i32, 2);
    }

    #[test]
    fn test_populating_popup_event_defaults() {
        let _: fn(fn(PopulatingPopupEvent)) -> Result<Token> =
            on_populating_popup::<fn(PopulatingPopupEvent)>;

        let event = PopulatingPopupEvent {
            function_address: 0,
            widget_handle: std::ptr::null_mut(),
            popup_handle: std::ptr::null_mut(),
            view_handle: std::ptr::null_mut(),
        };
        assert_eq!(event.function_address, 0);
        assert!(event.widget_handle.is_null());
        assert!(event.popup_handle.is_null());
        assert!(event.view_handle.is_null());
    }

    #[test]
    fn test_switch_pseudocode_signature() {
        let _: fn(fn(PseudocodeEvent)) -> Result<Token> =
            on_switch_pseudocode::<fn(PseudocodeEvent)>;
    }

    #[test]
    fn test_scoped_session_function_signatures() {
        let _: fn() -> Result<ScopedSession> = initialize;
        let _: fn(&ScopedSession) -> Result<bool> = ScopedSession::valid;
        let _: fn(&mut ScopedSession) -> Status = ScopedSession::close;
    }

    #[test]
    fn test_lvar_snapshot_and_comment_function_signatures() {
        let _: fn(&DecompiledFunction) -> Result<LvarSnapshot> =
            DecompiledFunction::capture_user_lvar_settings;
        let _: fn(&DecompiledFunction, &LvarSnapshot) -> Status =
            DecompiledFunction::restore_user_lvar_settings;
        let _: fn(&DecompiledFunction, &str, &str) -> Status =
            DecompiledFunction::set_variable_comment_by_name;
        let _: fn(&DecompiledFunction, usize, &str) -> Status =
            DecompiledFunction::set_variable_comment_by_index;
        let _: fn(&DecompilerView) -> Result<LvarSnapshot> =
            DecompilerView::capture_user_lvar_settings;
        let _: fn(&DecompilerView, &LvarSnapshot) -> Status =
            DecompilerView::restore_user_lvar_settings;
        let _: fn(&DecompilerView, &str, &str) -> Status =
            DecompilerView::set_variable_comment_by_name;
        let _: fn(&DecompilerView, usize, &str) -> Status =
            DecompilerView::set_variable_comment_by_index;
        let _: fn(&DecompiledFunction, Address, &str, CommentPosition) -> Status =
            DecompiledFunction::set_comment;
        let _: fn(&DecompiledFunction, Address, CommentPosition) -> Result<String> =
            DecompiledFunction::get_comment;
        let _: fn(&DecompiledFunction) -> Result<Vec<PseudocodeComment>> =
            DecompiledFunction::comments;
        let _: fn(&DecompiledFunction) -> Status = DecompiledFunction::save_comments;
        let _: fn(&DecompiledFunction) -> Result<bool> = DecompiledFunction::has_orphan_comments;
        let _: fn(&DecompiledFunction) -> Result<usize> =
            DecompiledFunction::remove_orphan_comments;
        let _: fn(&LvarSnapshot) -> Result<bool> = LvarSnapshot::empty;
        let _: fn(&LvarSnapshot) -> Result<usize> = LvarSnapshot::saved_variable_count;
    }

    #[test]
    fn test_semantic_comment_position_values() {
        assert_eq!(CommentPosition::default(), CommentPosition::Default);
        assert_eq!(CommentPosition::Argument(0), CommentPosition::Argument(0));
        assert_ne!(CommentPosition::Argument(0), CommentPosition::Argument(63));
        assert_eq!(
            CommentPosition::SwitchCase(-0x1fff_ffff),
            CommentPosition::SwitchCase(-0x1fff_ffff),
        );
        assert_eq!(
            CommentPosition::SwitchCase(0x1fff_ffff),
            CommentPosition::SwitchCase(0x1fff_ffff),
        );

        let copied = PseudocodeComment {
            address: 0x401000,
            position: CommentPosition::Semicolon,
            text: "semantic".to_owned(),
        };
        assert_eq!(copied.position, CommentPosition::Semicolon);
        assert_eq!(copied.text, "semantic");
    }

    #[test]
    fn test_ctree_callback_payload_shapes() {
        let parent = CtreeItemInfo {
            item_type: ItemType::ExprCall,
            address: 0x401000,
            is_expression: true,
        };
        assert!(parent.is_expression);

        let expression = ExpressionInfo {
            item_type: ItemType::ExprCall,
            address: 0x401010,
            variable_index: Some(2),
            helper_name: Some("__PAIR__".to_string()),
            type_declaration: Some("int".to_string()),
            parent: Some(parent.clone()),
            parent_depth: 1,
        };
        assert!(is_expression(expression.item_type));
        assert_eq!(expression.variable_index, Some(2));
        assert_eq!(expression.helper_name.as_deref(), Some("__PAIR__"));
        assert_eq!(expression.type_declaration.as_deref(), Some("int"));
        assert_eq!(expression.parent_depth, 1);
        assert!(expression.parent.as_ref().unwrap().is_expression);

        let statement = StatementInfo {
            item_type: ItemType::StmtReturn,
            address: 0x401020,
            parent: Some(parent),
            parent_depth: 2,
        };
        assert!(is_statement(statement.item_type));
        assert_eq!(statement.parent_depth, 2);
        assert!(statement.parent.as_ref().unwrap().is_expression);

        let _: fn(&DecompiledFunction, fn(ExpressionInfo) -> VisitAction) -> Result<i32> =
            for_each_expression::<fn(ExpressionInfo) -> VisitAction>;
        let _: fn(
            &DecompiledFunction,
            fn(ExpressionInfo) -> VisitAction,
            fn(StatementInfo) -> VisitAction,
        ) -> Result<i32> =
            for_each_item::<fn(ExpressionInfo) -> VisitAction, fn(StatementInfo) -> VisitAction>;
    }
}

#[cfg(test)]
mod debugger_tests {
    use crate::debugger::*;

    #[test]
    fn test_process_state_discriminants() {
        assert_eq!(ProcessState::NoProcess as i32, 0);
        assert_eq!(ProcessState::Running as i32, 1);
        assert_eq!(ProcessState::Suspended as i32, 2);
    }

    #[test]
    fn test_appcall_value_kind_discriminants() {
        assert_eq!(AppcallValueKind::SignedInteger as i32, 0);
        assert_eq!(AppcallValueKind::UnsignedInteger as i32, 1);
        assert_eq!(AppcallValueKind::FloatingPoint as i32, 2);
        assert_eq!(AppcallValueKind::String as i32, 3);
        assert_eq!(AppcallValueKind::Address as i32, 4);
        assert_eq!(AppcallValueKind::Boolean as i32, 5);
    }

    #[test]
    fn test_breakpoint_change_discriminants() {
        assert_eq!(BreakpointChange::Added as i32, 0);
        assert_eq!(BreakpointChange::Removed as i32, 1);
        assert_eq!(BreakpointChange::Changed as i32, 2);
    }

    #[test]
    fn test_appcall_options_default() {
        let opts = AppcallOptions::default();
        assert!(opts.thread_id.is_none());
        assert!(!opts.manual);
        assert!(!opts.include_debug_event);
        assert!(opts.timeout_milliseconds.is_none());
    }
}

#[cfg(test)]
mod name_tests {
    use crate::error::Result;
    use crate::name::{self, DemangleForm};

    #[test]
    fn test_arbitrary_demangle_signature() {
        let _: fn(&str, DemangleForm) -> Result<String> = name::demangle;
    }

    #[test]
    fn test_name_inventory_signature() {
        let options = name::ListOptions::default();
        assert!(options.include_user_defined);
        assert!(options.include_auto_generated);
        let _: fn(&name::ListOptions) -> Result<Vec<name::Entry>> = name::all;
    }
}

#[cfg(test)]
mod event_tests {
    use crate::address::Address;
    use crate::error::Result;
    use crate::event::*;

    #[test]
    fn test_event_kind_discriminants() {
        assert_eq!(EventKind::SegmentAdded as i32, 0);
        assert_eq!(EventKind::SegmentDeleted as i32, 1);
        assert_eq!(EventKind::FunctionAdded as i32, 2);
        assert_eq!(EventKind::FunctionDeleted as i32, 3);
        assert_eq!(EventKind::Renamed as i32, 4);
        assert_eq!(EventKind::BytePatched as i32, 5);
        assert_eq!(EventKind::CommentChanged as i32, 6);
        assert_eq!(EventKind::SegmentMoved as i32, 7);
        assert_eq!(EventKind::FunctionUpdated as i32, 8);
        assert_eq!(EventKind::ItemTypeChanged as i32, 9);
        assert_eq!(EventKind::OperandTypeChanged as i32, 10);
        assert_eq!(EventKind::CodeCreated as i32, 11);
        assert_eq!(EventKind::DataCreated as i32, 12);
        assert_eq!(EventKind::ItemsDestroyed as i32, 13);
        assert_eq!(EventKind::ExtraCommentChanged as i32, 14);
        assert_eq!(EventKind::LocalTypesChanged as i32, 15);
        assert_eq!(ExtraCommentPlacement::Anterior as i32, 1);
        assert_eq!(LocalTypeChangeKind::OrdinalsCompacted as i32, 8);
    }

    #[test]
    fn test_event_default() {
        let e = Event::default();
        assert_eq!(e.kind, EventKind::SegmentAdded);
        assert!(e.new_name.is_empty());
        assert!(e.old_name.is_empty());
        assert_eq!(e.operand_index, -1);
        assert_eq!(e.line_index, -1);
        assert_eq!(e.extra_comment_placement, ExtraCommentPlacement::Unknown);
        assert_eq!(e.local_type_change, LocalTypeChangeKind::None);
    }

    #[test]
    fn test_change_tracking_event_function_signatures() {
        let _: fn(fn(SegmentMovedEvent)) -> Result<Token> =
            on_segment_moved::<fn(SegmentMovedEvent)>;
        let _: fn(fn(Address)) -> Result<Token> = on_function_updated::<fn(Address)>;
        let _: fn(fn(Address)) -> Result<Token> = on_item_type_changed::<fn(Address)>;
        let _: fn(fn(Address, i32)) -> Result<Token> = on_operand_type_changed::<fn(Address, i32)>;
        let _: fn(fn(ItemCreatedEvent)) -> Result<Token> = on_code_created::<fn(ItemCreatedEvent)>;
        let _: fn(fn(ItemCreatedEvent)) -> Result<Token> = on_data_created::<fn(ItemCreatedEvent)>;
        let _: fn(fn(ItemsDestroyedEvent)) -> Result<Token> =
            on_items_destroyed::<fn(ItemsDestroyedEvent)>;
        let _: fn(fn(ExtraCommentChangedEvent)) -> Result<Token> =
            on_extra_comment_changed::<fn(ExtraCommentChangedEvent)>;
        let _: fn(fn(LocalTypesChangedEvent)) -> Result<Token> =
            on_local_types_changed::<fn(LocalTypesChangedEvent)>;
    }

    #[test]
    fn test_scoped_subscription_token() {
        // ScopedSubscription should store and return a token
        // We can't actually subscribe without IDA, but we can test construction
        // with a fake token value
        let sub = ScopedSubscription::new(12345);
        assert_eq!(sub.token(), 12345);
        // Prevent Drop from trying to unsubscribe (it will call FFI which will no-op)
        std::mem::forget(sub);
    }
}

#[cfg(test)]
mod entry_tests {
    use crate::entry::EntryPoint;

    #[test]
    fn test_entry_point_construction() {
        let ep = EntryPoint {
            ordinal: 1,
            address: 0x401000,
            name: "main".to_string(),
            forwarder: String::new(),
        };
        assert_eq!(ep.ordinal, 1);
        assert_eq!(ep.address, 0x401000);
        assert_eq!(ep.name, "main");
        assert!(ep.forwarder.is_empty());
    }
}

#[cfg(test)]
mod loader_tests {
    use crate::loader::LoadFlags;

    #[test]
    fn test_load_flags_default() {
        let f = LoadFlags::default();
        assert!(!f.create_segments);
        assert!(!f.load_resources);
        assert!(!f.rename_entries);
        assert!(!f.manual_load);
        assert!(!f.fill_gaps);
        assert!(!f.create_import_segment);
        assert!(!f.first_file);
        assert!(!f.binary_code_segment);
        assert!(!f.reload);
        assert!(!f.auto_flat_group);
        assert!(!f.mini_database);
        assert!(!f.loader_options_dialog);
        assert!(!f.load_all_segments);
    }

    #[test]
    fn test_load_flags_mutation() {
        let mut f = LoadFlags::default();
        f.create_segments = true;
        f.load_resources = true;
        assert!(f.create_segments);
        assert!(f.load_resources);
        assert!(!f.manual_load); // unchanged
    }
}

#[cfg(test)]
mod database_tests {
    use crate::database::{OpenMode, ProcessorId};

    #[test]
    fn test_open_mode_discriminants() {
        assert_eq!(OpenMode::Analyze as i32, 0);
        assert_eq!(OpenMode::SkipAnalysis as i32, 1);
    }

    #[test]
    fn test_processor_id_from_raw() {
        assert_eq!(ProcessorId::from_raw(0), Some(ProcessorId::IntelX86));
        assert_eq!(ProcessorId::from_raw(13), Some(ProcessorId::Arm));
        assert_eq!(ProcessorId::from_raw(15), Some(ProcessorId::PowerPc));
        assert_eq!(ProcessorId::from_raw(12), Some(ProcessorId::Mips));
        assert_eq!(ProcessorId::from_raw(72), Some(ProcessorId::RiscV));
        assert_eq!(ProcessorId::from_raw(-1), None);
        assert_eq!(ProcessorId::from_raw(77), None);
        assert_eq!(ProcessorId::from_raw(78), None);
        assert_eq!(ProcessorId::from_raw(0x8001), None);
        assert_eq!(ProcessorId::from_raw(i32::MAX), None);
    }

    #[test]
    fn test_processor_id_boundary() {
        for i in 0..=76 {
            assert!(ProcessorId::from_raw(i).is_some());
        }
        assert!(ProcessorId::from_raw(77).is_none());
    }
}

#[cfg(test)]
mod processor_tests {
    use crate::processor::{AnalyzeDetails, InstructionFeature, ProcessorFlag, ProcessorFlag2};

    #[test]
    fn test_processor_sdk_flag_discriminants() {
        assert_eq!(ProcessorFlag::DefaultSeg32 as u32, 0x000004);
        assert_eq!(ProcessorFlag::Use64 as u32, 0x002000);
        assert_eq!(ProcessorFlag::TypeInfo as u32, 0x001000);
        assert_eq!(ProcessorFlag::UseArgTypes as u32, 0x200000);
        assert_eq!(ProcessorFlag::ConditionalInsns as u32, 0x4000000);
        assert_eq!(ProcessorFlag::HEX_NUMBERS, 0);
        assert_eq!(ProcessorFlag2::Code16Bit as u32, 0x000008);
    }

    #[test]
    fn test_eight_operand_feature_discriminants() {
        assert_eq!(InstructionFeature::Change7 as u32, 0x020000);
        assert_eq!(InstructionFeature::Change8 as u32, 0x040000);
        assert_eq!(InstructionFeature::Use7 as u32, 0x080000);
        assert_eq!(InstructionFeature::Use8 as u32, 0x100000);
    }

    #[test]
    fn test_analyze_details_default_instruction_code() {
        assert_eq!(AnalyzeDetails::default().instruction_code, 0);
    }
}

#[cfg(test)]
mod plugin_tests {
    use crate::address::BAD_ADDRESS;
    use crate::plugin::{ActionContext, TypeRef};
    use crate::types::TypeInfo;

    #[test]
    fn test_action_context_type_ref_default() {
        let context = ActionContext::default();
        assert_eq!(context.current_address, BAD_ADDRESS);
        assert!(context.type_ref.is_none());
    }

    #[test]
    fn test_action_context_type_ref_construction() {
        let context = ActionContext {
            type_ref: Some(TypeRef {
                name: "idax_test_type".to_string(),
                r#type: TypeInfo::from_raw(std::ptr::null_mut()),
            }),
            ..ActionContext::default()
        };

        let type_ref = context.type_ref.as_ref().expect("type ref present");
        assert_eq!(type_ref.name, "idax_test_type");
        assert!(type_ref.r#type.as_raw().is_null());
    }
}

#[cfg(test)]
mod path_tests {
    use crate::error::{ErrorCategory, Result};
    use crate::path;

    #[test]
    fn test_path_function_signatures() {
        let _: fn(&str) -> Result<String> = path::basename;
        let _: fn(&str) -> Result<String> = path::dirname;
        let _: fn(&str) -> Result<bool> = path::is_directory;
    }

    #[test]
    fn test_path_helpers_validate_before_ffi() {
        assert_eq!(
            path::basename("bad\0path").unwrap_err().category,
            ErrorCategory::Validation
        );
        assert_eq!(
            path::dirname("bad\0path").unwrap_err().category,
            ErrorCategory::Validation
        );
        assert_eq!(
            path::is_directory("bad\0path").unwrap_err().category,
            ErrorCategory::Validation
        );
    }
}

#[cfg(test)]
mod ui_tests {
    use crate::error::{ErrorCategory, Result, Status};
    use crate::ui::{
        self, PathBitsetFormResult, RadioSvalPathBitsetFormResult, SvalBitsetFormResult,
        SvalPathBitsetFormResult, ThreeSvalsPathTwoBitsetsFormResult,
    };

    #[test]
    fn test_current_widget_signature() {
        let _: fn() -> Result<Option<ui::WidgetRef>> = ui::current_widget;
    }

    #[test]
    fn test_codedump_typed_form_result_shapes() {
        let simple = SvalBitsetFormResult {
            accepted: true,
            sval: 3,
            bitset: 1,
        };
        assert!(simple.accepted);
        assert_eq!(simple.sval, 3);
        assert_eq!(simple.bitset, 1);

        let with_path = SvalPathBitsetFormResult {
            accepted: false,
            sval: 4,
            path: "out.json".to_string(),
            bitset: 2,
        };
        assert!(!with_path.accepted);
        assert_eq!(with_path.path, "out.json");

        let path_only = PathBitsetFormResult {
            accepted: true,
            path: "metadata.json".to_string(),
            bitset: 3,
        };
        assert_eq!(path_only.bitset, 3);

        let radio = RadioSvalPathBitsetFormResult {
            accepted: true,
            radio: 1,
            sval: 5,
            path: "graph.dot".to_string(),
            bitset: 4,
        };
        assert_eq!(radio.radio, 1);
        assert_eq!(radio.sval, 5);

        let full = ThreeSvalsPathTwoBitsetsFormResult {
            accepted: true,
            first: 1,
            second: 2,
            third: 3,
            path: "dump.json".to_string(),
            first_bitset: 4,
            second_bitset: 5,
        };
        assert_eq!(full.first + full.second + full.third, 6);
        assert_eq!(full.first_bitset, 4);
        assert_eq!(full.second_bitset, 5);
    }

    #[test]
    fn test_codedump_typed_form_function_signatures() {
        let _: fn(&str, i64, u16) -> Result<SvalBitsetFormResult> = ui::ask_form_sval_bitset;
        let _: fn(&str, i64, &str, u16, bool) -> Result<SvalPathBitsetFormResult> =
            ui::ask_form_sval_path_bitset;
        let _: fn(&str, &str, u16, bool) -> Result<PathBitsetFormResult> = ui::ask_form_path_bitset;
        let _: fn(&str, u16, i64, &str, u16, bool) -> Result<RadioSvalPathBitsetFormResult> =
            ui::ask_form_radio_sval_path_bitset;
        let _: fn(
            &str,
            i64,
            i64,
            i64,
            &str,
            u16,
            u16,
            bool,
        ) -> Result<ThreeSvalsPathTwoBitsetsFormResult> = ui::ask_form_three_svals_path_two_bitsets;
    }

    fn expect_validation_error<T>(result: Result<T>) {
        match result {
            Ok(_) => panic!("expected validation error"),
            Err(error) => assert_eq!(error.category, ErrorCategory::Validation),
        }
    }

    #[test]
    fn test_codedump_typed_forms_reject_empty_markup_without_modal_ui() {
        expect_validation_error(ui::ask_form_sval_bitset("", 1, 0));
        expect_validation_error(ui::ask_form_sval_path_bitset(
            "",
            1,
            "/tmp/out.json",
            0,
            true,
        ));
        expect_validation_error(ui::ask_form_path_bitset("", "/tmp/out.json", 0, true));
        expect_validation_error(ui::ask_form_radio_sval_path_bitset(
            "",
            0,
            1,
            "/tmp/out.json",
            0,
            true,
        ));
        expect_validation_error(ui::ask_form_three_svals_path_two_bitsets(
            "",
            1,
            2,
            3,
            "/tmp/out.json",
            0,
            0,
            true,
        ));
    }

    #[test]
    fn test_clipboard_function_signatures() {
        let _: fn(&str) -> Result<ui::WaitBox> = ui::WaitBox::new;
        let _: fn(&mut ui::WaitBox, &str) -> Status = ui::WaitBox::update;
        let _: fn(&ui::WaitBox) -> Result<bool> = ui::WaitBox::cancelled;
        let _: fn(&ui::WaitBox) -> Result<bool> = ui::WaitBox::active;
        let _: fn(&mut ui::WaitBox) = ui::WaitBox::dismiss;
        let _: fn(&str, &str, ui::AskTextOptions) -> Result<String> = ui::ask_text;
        let _: fn(&str) -> Status = ui::copy_to_clipboard;
        let _: fn() -> Result<String> = ui::read_clipboard;
        let _: fn() -> String = ui::clipboard_backend;
    }

    #[test]
    fn test_clipboard_validation_is_local() {
        let invalid = ui::copy_to_clipboard("bad\0clipboard").unwrap_err();
        assert_eq!(invalid.category, ErrorCategory::Validation);
    }

    #[test]
    fn test_ask_text_options_are_plain_value() {
        let options = ui::AskTextOptions {
            max_size: 4096,
            accept_tabs: true,
            normal_font: false,
        };
        assert_eq!(options.max_size, 4096);
        assert!(options.accept_tabs);
        assert_eq!(ui::AskTextOptions::default().max_size, 0);
    }
}

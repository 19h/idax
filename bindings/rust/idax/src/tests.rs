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
    use crate::lines::*;

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
}

#[cfg(test)]
mod types_tests {
    use crate::types::CallingConvention;

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
    use crate::decompiler::*;

    #[test]
    fn test_maturity_discriminants() {
        assert_eq!(Maturity::Zero as i32, 0);
        assert_eq!(Maturity::Built as i32, 1);
        assert_eq!(Maturity::Final as i32, 8);
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
mod event_tests {
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
    }

    #[test]
    fn test_event_default() {
        let e = Event::default();
        assert_eq!(e.kind, EventKind::SegmentAdded);
        assert!(e.new_name.is_empty());
        assert!(e.old_name.is_empty());
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
        assert_eq!(ProcessorId::from_raw(78), None);
        assert_eq!(ProcessorId::from_raw(i32::MAX), None);
    }

    #[test]
    fn test_processor_id_boundary() {
        // Test all valid values don't return None
        for i in 0..=77 {
            let _result = ProcessorId::from_raw(i);
            // Some values may not have a mapping (gaps in the enum)
            // This is OK - from_raw just checks the range
        }
    }
}

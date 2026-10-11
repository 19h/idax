//! Actual runtime 9.5 probe; input is the native producer's saved database.
use idax::{database, decompiler::{self, ItemType, VisitAction}, name};
use std::{cell::Cell, rc::Rc};

fn main() {
    let input = std::env::args().nth(1).expect("Pass the native producer's saved IDB");
    let directory = std::env::temp_dir().join(format!("idax-sdk95-rust-{}", std::process::id()));
    std::fs::create_dir(&directory).unwrap();
    let fixture = directory.join("fixture.i64");
    std::fs::copy(input, &fixture).unwrap();
    database::init().unwrap();
    database::open(fixture.to_str().unwrap(), false).unwrap();
    let wide_pointed = Rc::new(Cell::new(false));
    for (function, field, value, bitfield, union) in [
        ("read_wide", "wide", 2147483664u64, false, false),
        ("read_bits", "target", 3, true, false),
        ("read_big_bits", "target", 4294967299, true, false),
        ("read_union", "real", 1, false, true),
    ] {
        let address = name::resolve(function, u64::MAX)
            .or_else(|_| name::resolve(&format!("_{function}"), u64::MAX)).unwrap();
        let matches = Rc::new(Cell::new(0));
        let seen = matches.clone();
        let wide = wide_pointed.clone();
        decompiler::decompile(address).unwrap().for_each_expression(move |expression| {
            if expression.pointed_type_byte_width == Some(2147483668) { wide.set(true); }
            if expression.item_type != ItemType::ExprMemberRef && expression.item_type != ItemType::ExprMemberPtr {
                return VisitAction::Continue;
            }
            assert_eq!(expression.member_name.as_deref(), Some(field));
            assert_eq!(expression.member_is_bitfield, Some(bitfield));
            assert_eq!(expression.member_offset, if union { None } else { Some(if bitfield { value / 8 } else { value }) });
            assert_eq!(expression.member_bit_offset, if union { None } else { Some(if bitfield { value } else { value * 8 }) });
            assert_eq!(expression.member_index, if union { Some(value) } else { None });
            seen.set(seen.get() + 1);
            VisitAction::Continue
        }).unwrap();
        assert!(matches.get() > 0);
        println!("PASS: Rust {function} exact u64/name/unit owned snapshot");
    }
    assert!(wide_pointed.get());
    database::close(false).unwrap();
    std::fs::remove_dir_all(directory).unwrap();
}

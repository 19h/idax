#[path = "../build_support.rs"]
mod build_support;

#[test]
fn patch_bindgen_output_accepts_crlf() {
    let path = std::env::temp_dir().join(format!("idax-bindgen-crlf-{}.rs", std::process::id()));
    let input = concat!(
        "prefix\r\n",
        "#[repr(C)]\r\n",
        "pub struct IdaxMicrocodeInstruction {\r\n",
        "    pub placeholder: i32,\r\n",
        "}\r\n",
        "unsafe extern \"C\" {\r\n",
        "    pub fn idax_microcode_instruction_free(instruction: *mut IdaxMicrocodeInstruction);\r\n",
        "}\r\n",
    );
    std::fs::write(&path, input).expect("write CRLF bindgen fixture");

    build_support::patch_bindgen_output(&path);

    let patched = std::fs::read_to_string(&path).expect("read patched fixture");
    std::fs::remove_file(&path).expect("remove CRLF bindgen fixture");
    assert!(!patched.contains('\r'));
    assert!(patched.contains("pub struct IdaxMicrocodeInstruction"));
    assert!(patched.contains("pub modifies_destination: ::std::os::raw::c_int"));
    assert!(patched.contains("pub fn idax_microcode_instruction_free"));
}

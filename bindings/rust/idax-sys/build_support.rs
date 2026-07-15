use std::path::Path;

pub(crate) fn patch_bindgen_output(path: &Path) {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| {
        panic!(
            "Failed to read generated bindings {}: {}",
            path.display(),
            e
        )
    });
    let text = text.replace("\r\n", "\n");

    let struct_marker = "pub struct IdaxMicrocodeInstruction {";
    let struct_position = text.find(struct_marker).unwrap_or_else(|| {
        panic!(
            "Generated bindings for {} do not contain IdaxMicrocodeInstruction",
            path.display()
        )
    });
    let start = text[..struct_position]
        .rfind("#[repr(C)]\n")
        .unwrap_or_else(|| {
            panic!(
                "Generated bindings for {} contain IdaxMicrocodeInstruction, \
                 but the preceding repr(C) marker was not found",
                path.display()
            )
        });

    let remainder = &text[start..];
    let end_marker = "unsafe extern \"C\" {\n    pub fn idax_microcode_instruction_free";
    let end = remainder.find(end_marker).unwrap_or_else(|| {
        panic!(
            "Generated bindings for {} contain opaque IdaxMicrocodeInstruction, \
             but the following FFI marker was not found",
            path.display()
        )
    });

    // libclang versions disagree on whether the recursive instruction type is
    // opaque at this point. Normalize both shapes to the public C definition
    // and deliberately omit generated layout assertions/Default code so the
    // checked binding is byte-stable across those parser variants.
    let replacement = "#[repr(C)]\n#[derive(Debug, Copy, Clone)]\npub struct IdaxMicrocodeInstruction {\n    pub opcode: ::std::os::raw::c_int,\n    pub left: IdaxMicrocodeOperand,\n    pub right: IdaxMicrocodeOperand,\n    pub destination: IdaxMicrocodeOperand,\n    pub floating_point_instruction: ::std::os::raw::c_int,\n    pub modifies_destination: ::std::os::raw::c_int,\n    pub address: u64,\n    pub text: *mut ::std::os::raw::c_char,\n}\n";

    let mut patched = String::with_capacity(text.len());
    patched.push_str(&text[..start]);
    patched.push_str(replacement);
    patched.push_str(&remainder[end..]);

    std::fs::write(path, patched).unwrap_or_else(|e| {
        panic!(
            "Failed to write patched generated bindings {}: {}",
            path.display(),
            e
        )
    });
}

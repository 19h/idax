internal import CIDAX



extension Decompiler.Function {

    public func pseudocode() throws(IDAError) -> String {
        try withHandle("Decompiler.Function.pseudocode") { (h) throws(IDAError) -> String in try withStringOutput("Decompiler.Function.pseudocode") { idax_decompiled_pseudocode(h, $0) } }
    }

    public func microcode() throws(IDAError) -> String {
        try withHandle("Decompiler.Function.microcode") { (h) throws(IDAError) -> String in try withStringOutput("Decompiler.Function.microcode") { idax_decompiled_microcode(h, $0) } }
    }

    public func declaration() throws(IDAError) -> String {
        try withHandle("Decompiler.Function.declaration") { (h) throws(IDAError) -> String in try withStringOutput("Decompiler.Function.declaration") { idax_decompiled_declaration(h, $0) } }
    }

    public func entryAddress() throws(IDAError) -> Address {
        try withHandle("Decompiler.Function.entryAddress") { (h) throws(IDAError) -> Address in try withOutput("Decompiler.Function.entryAddress", initial: UInt64(0)) { idax_decompiled_entry_address(h, $0) } }
    }

    public func headerLineCount() throws(IDAError) -> Int32 {
        try withHandle("Decompiler.Function.headerLineCount") { (h) throws(IDAError) -> Int32 in try withOutput("Decompiler.Function.headerLineCount", initial: Int32(0)) { idax_decompiled_header_line_count(h, $0) } }
    }

    public func variableCount() throws(IDAError) -> Int {
        try withHandle("Decompiler.Function.variableCount") { (h) throws(IDAError) -> Int in try withOutput("Decompiler.Function.variableCount", initial: Int(0)) { idax_decompiled_variable_count(h, $0) } }
    }

    public func hasOrphanComments() throws(IDAError) -> Bool {
        try withHandle("Decompiler.Function.hasOrphanComments") { (h) throws(IDAError) -> Bool in try withOutput("Decompiler.Function.hasOrphanComments", initial: Int32(0)) { idax_decompiled_has_orphan_comments(h, $0) } != 0 }
    }

    public func removeOrphanComments() throws(IDAError) -> Int32 {
        try withHandle("Decompiler.Function.removeOrphanComments") { (h) throws(IDAError) -> Int32 in try withOutput("Decompiler.Function.removeOrphanComments", initial: Int32(0)) { idax_decompiled_remove_orphan_comments(h, $0) } }
    }

    public func lines() throws(IDAError) -> [String] {
        let op = "Decompiler.Function.lines"
        return try withHandle(op) { (h) throws(IDAError) -> [String] in
            var output: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?; var count = 0
            defer { idax_decompiled_lines_free(output, count) }
            try checkStatus(idax_decompiled_lines(h, &output, &count), op)
            return try copyNativeValues(output, count: count, op) { (value) throws(IDAError) -> String in try borrowCString(value.map { UnsafePointer($0) }, op) }
        }
    }

    public func rawLines() throws(IDAError) -> [String] {
        let op = "Decompiler.Function.rawLines"
        return try withHandle(op) { (h) throws(IDAError) -> [String] in
            var output: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?; var count = 0
            defer { idax_decompiled_lines_free(output, count) }
            try checkStatus(idax_decompiled_raw_lines(h, &output, &count), op)
            return try copyNativeValues(output, count: count, op) { (value) throws(IDAError) -> String in try borrowCString(value.map { UnsafePointer($0) }, op) }
        }
    }

    public func setRawLine(at index: Int, taggedText: String) throws(IDAError) {
        let op = "Decompiler.Function.setRawLine"
        try requireNonnegative(index, op)
        try validateCString(taggedText, op)
        try withHandle(op) { (h) throws(IDAError) in
            try checkStatus(taggedText.withCString { c_taggedText in idax_decompiled_set_raw_line(h, index, c_taggedText) }, op)
        }
    }

    public func renameVariable(from oldName: String, to newName: String) throws(IDAError) {
        let op = "Decompiler.Function.renameVariable"
        try validateCString(oldName, op)
        try validateCString(newName, op)
        try withHandle(op) { (h) throws(IDAError) in
            try checkStatus(oldName.withCString { c_oldName in newName.withCString { c_newName in idax_decompiled_rename_variable(h, c_oldName, c_newName) } }, op)
        }
    }

    public func setVariableComment(named name: String, comment: String) throws(IDAError) {
        let op = "Decompiler.Function.setVariableComment"
        try validateCString(name, op)
        try validateCString(comment, op)
        try withHandle(op) { (h) throws(IDAError) in
            try checkStatus(name.withCString { c_name in comment.withCString { c_comment in idax_decompiled_set_variable_comment_by_name(h, c_name, c_comment) } }, op)
        }
    }

    public func setVariableComment(at index: Int, comment: String) throws(IDAError) {
        let op = "Decompiler.Function.setVariableComment"
        try requireNonnegative(index, op)
        try validateCString(comment, op)
        try withHandle(op) { (h) throws(IDAError) in
            try checkStatus(comment.withCString { c_comment in idax_decompiled_set_variable_comment_by_index(h, index, c_comment) }, op)
        }
    }

    public func variables() throws(IDAError) -> [Decompiler.LocalVariable] {
        let op = "Decompiler.Function.variables"
        return try withHandle(op) { (h) throws(IDAError) -> [Decompiler.LocalVariable] in
            var output: UnsafeMutablePointer<IdaxLocalVariable>?; var count = 0
            defer { idax_decompiled_variables_free(output, count) }
            try checkStatus(idax_decompiled_variables(h, &output, &count), op)
            return try copyNativeValues(output, count: count, op) { (value) throws(IDAError) -> Decompiler.LocalVariable in try .init(copying: value, op) }
        }
    }
    public func variable(at index: Int) throws(IDAError) -> Decompiler.LocalVariable {
        let op = "Decompiler.Function.variable"; try requireNonnegative(index, op)
        return try withHandle(op) { (h) throws(IDAError) -> Decompiler.LocalVariable in
            var output = IdaxLocalVariable(); defer { idax_local_variable_free(&output) }
            try checkStatus(idax_decompiled_variable(h, index, &output), op)
            return try .init(copying: output, op)
        }
    }
    public func captureUserLvarSettings() throws(IDAError) -> Decompiler.LvarSnapshot {
        let op = "Decompiler.Function.captureUserLvarSettings"
        return try withHandle(op) { (h) throws(IDAError) -> Decompiler.LvarSnapshot in
            let output: UnsafeMutableRawPointer? = try withOutput(op, initial: nil) { idax_decompiled_capture_user_lvar_settings(h, $0) }
            return try .init(owning: requireOwnedHandle(output, op))
        }
    }
    public func restoreUserLvarSettings(_ snapshot: Decompiler.LvarSnapshot) throws(IDAError) {
        let op = "Decompiler.Function.restoreUserLvarSettings"
        try snapshot.resource.withPinned(op) { (s) throws(IDAError) in
            try withHandle(op) { (h) throws(IDAError) in
                try checkStatus(idax_decompiled_restore_user_lvar_settings(h, s), op)
            }
        }
    }
    public func setComment(at address: Address, text: String, position: Decompiler.CommentPosition = .default) throws(IDAError) {
        let op = "Decompiler.Function.setComment"; try validateCString(text, op); var native = try position.native(op)
        try withHandle(op) { (h) throws(IDAError) in
            try checkStatus(text.withCString { idax_decompiled_set_comment(h, address, $0, &native) }, op)
        }
    }
    public func comment(at address: Address, position: Decompiler.CommentPosition = .default) throws(IDAError) -> String {
        let op = "Decompiler.Function.comment"; var native = try position.native(op)
        return try withHandle(op) { (h) throws(IDAError) -> String in
            try withStringOutput(op) { idax_decompiled_get_comment(h, address, &native, $0) }
        }
    }
    public func comments() throws(IDAError) -> [Decompiler.PseudocodeComment] {
        let op = "Decompiler.Function.comments"
        return try withHandle(op) { (h) throws(IDAError) -> [Decompiler.PseudocodeComment] in
            var output: UnsafeMutablePointer<IdaxPseudocodeComment>?; var count = 0
            defer { idax_decompiled_comments_free(output, count) }
            try checkStatus(idax_decompiled_comments(h, &output, &count), op)
            return try copyNativeValues(output, count: count, op) { (value) throws(IDAError) -> Decompiler.PseudocodeComment in try .init(copying: value, op) }
        }
    }
    public func saveComments() throws(IDAError) {
        try withHandle("Decompiler.Function.saveComments") { (h) throws(IDAError) in try checkStatus(idax_decompiled_save_comments(h), "Decompiler.Function.saveComments") }
    }
    public func address(forLine line: Int32) throws(IDAError) -> Address {
        let op = "Decompiler.Function.address"
        return try withHandle(op) { (h) throws(IDAError) -> Address in try withOutput(op, initial: UInt64(0)) { idax_decompiled_line_to_address(h, line, $0) } }
    }
}

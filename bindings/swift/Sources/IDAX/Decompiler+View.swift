extension Decompiler.View {
    public func renameVariable(from oldName: String, to newName: String) throws(IDAError) -> Void {
        let function = try decompiledFunction()
        defer { withExtendedLifetime(function) {} }
        return try function.renameVariable(from: oldName, to: newName)
    }
    public func retypeVariable(named name: String, type: TypeInfo) throws(IDAError) -> Void {
        let function = try decompiledFunction()
        defer { withExtendedLifetime(function) {} }
        return try function.retypeVariable(named: name, type: type)
    }
    public func retypeVariable(at index: Int, type: TypeInfo) throws(IDAError) -> Void {
        let function = try decompiledFunction()
        defer { withExtendedLifetime(function) {} }
        return try function.retypeVariable(at: index, type: type)
    }
    public func captureUserLvarSettings() throws(IDAError) -> Decompiler.LvarSnapshot {
        let function = try decompiledFunction()
        defer { withExtendedLifetime(function) {} }
        return try function.captureUserLvarSettings()
    }
    public func restoreUserLvarSettings(_ snapshot: Decompiler.LvarSnapshot) throws(IDAError) -> Void {
        let function = try decompiledFunction()
        defer { withExtendedLifetime(function) {} }
        return try function.restoreUserLvarSettings(snapshot)
    }
    public func setVariableComment(named name: String, comment: String) throws(IDAError) -> Void {
        let function = try decompiledFunction()
        defer { withExtendedLifetime(function) {} }
        return try function.setVariableComment(named: name, comment: comment)
    }
    public func setVariableComment(at index: Int, comment: String) throws(IDAError) -> Void {
        let function = try decompiledFunction()
        defer { withExtendedLifetime(function) {} }
        return try function.setVariableComment(at: index, comment: comment)
    }
    public func setComment(at address: Address, text: String, position: Decompiler.CommentPosition = .default) throws(IDAError) -> Void {
        let function = try decompiledFunction()
        defer { withExtendedLifetime(function) {} }
        return try function.setComment(at: address, text: text, position: position)
    }
    public func comment(at address: Address, position: Decompiler.CommentPosition = .default) throws(IDAError) -> String {
        let function = try decompiledFunction()
        defer { withExtendedLifetime(function) {} }
        return try function.comment(at: address, position: position)
    }
    public func comments() throws(IDAError) -> [Decompiler.PseudocodeComment] {
        let function = try decompiledFunction()
        defer { withExtendedLifetime(function) {} }
        return try function.comments()
    }
    public func saveComments() throws(IDAError) -> Void {
        let function = try decompiledFunction()
        defer { withExtendedLifetime(function) {} }
        return try function.saveComments()
    }
    public func refresh() throws(IDAError) -> Void {
        let function = try decompiledFunction()
        defer { withExtendedLifetime(function) {} }
        return try function.refresh()
    }
}

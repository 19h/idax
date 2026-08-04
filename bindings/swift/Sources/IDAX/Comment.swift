internal import CIDAX
import Darwin

/// Comment operations (regular, repeatable, anterior/posterior).
///
/// Mirrors C++ `ida::comment`.
public enum Comment {
    public static func get(at address: Address, repeatable: Bool = false) throws(IDAError) -> String {
        try withStringOutput("comment.get") { idax_comment_get(address, repeatable ? 1 : 0, $0) }
    }

    public static func set(_ text: String, at address: Address, repeatable: Bool = false) throws(IDAError) {
        try checkStatus(
            text.withCString { idax_comment_set(address, $0, repeatable ? 1 : 0) },
            "comment.set"
        )
    }

    public static func append(_ text: String, at address: Address, repeatable: Bool = false) throws(IDAError) {
        try checkStatus(
            text.withCString { idax_comment_append(address, $0, repeatable ? 1 : 0) },
            "comment.append"
        )
    }

    public static func remove(at address: Address, repeatable: Bool = false) throws(IDAError) {
        try checkStatus(idax_comment_remove(address, repeatable ? 1 : 0), "comment.remove")
    }

    // MARK: - Anterior / Posterior

    public static func addAnterior(_ text: String, at address: Address) throws(IDAError) {
        try checkStatus(text.withCString { idax_comment_add_anterior(address, $0) }, "comment.addAnterior")
    }

    public static func addPosterior(_ text: String, at address: Address) throws(IDAError) {
        try checkStatus(text.withCString { idax_comment_add_posterior(address, $0) }, "comment.addPosterior")
    }

    public static func clearAnterior(at address: Address) throws(IDAError) {
        try checkStatus(idax_comment_clear_anterior(address), "comment.clearAnterior")
    }

    public static func clearPosterior(at address: Address) throws(IDAError) {
        try checkStatus(idax_comment_clear_posterior(address), "comment.clearPosterior")
    }

    // MARK: - Indexed Anterior / Posterior

    public static func getAnterior(at address: Address, lineIndex: Int) throws(IDAError) -> String {
        try withStringOutput("comment.getAnterior") { idax_comment_get_anterior(address, Int32(lineIndex), $0) }
    }

    public static func getPosterior(at address: Address, lineIndex: Int) throws(IDAError) -> String {
        try withStringOutput("comment.getPosterior") { idax_comment_get_posterior(address, Int32(lineIndex), $0) }
    }

    public static func setAnterior(_ text: String, at address: Address, lineIndex: Int) throws(IDAError) {
        try checkStatus(
            text.withCString { idax_comment_set_anterior(address, Int32(lineIndex), $0) },
            "comment.setAnterior"
        )
    }

    public static func setPosterior(_ text: String, at address: Address, lineIndex: Int) throws(IDAError) {
        try checkStatus(
            text.withCString { idax_comment_set_posterior(address, Int32(lineIndex), $0) },
            "comment.setPosterior"
        )
    }

    public static func removeAnteriorLine(at address: Address, lineIndex: Int) throws(IDAError) {
        try checkStatus(idax_comment_remove_anterior_line(address, Int32(lineIndex)), "comment.removeAnteriorLine")
    }

    public static func removePosteriorLine(at address: Address, lineIndex: Int) throws(IDAError) {
        try checkStatus(idax_comment_remove_posterior_line(address, Int32(lineIndex)), "comment.removePosteriorLine")
    }

    // MARK: - Bulk Lines

    public static func setAnteriorLines(_ lines: [String], at address: Address) throws(IDAError) {
        let mutPtrs = lines.map { strdup($0) }
        defer { mutPtrs.forEach { free($0) } }
        var constPtrs = mutPtrs.map { UnsafePointer($0) }
        let ret = constPtrs.withUnsafeMutableBufferPointer { buf in
            idax_comment_set_anterior_lines(address, buf.baseAddress, buf.count)
        }
        try checkStatus(ret, "comment.setAnteriorLines")
    }

    public static func setPosteriorLines(_ lines: [String], at address: Address) throws(IDAError) {
        let mutPtrs = lines.map { strdup($0) }
        defer { mutPtrs.forEach { free($0) } }
        var constPtrs = mutPtrs.map { UnsafePointer($0) }
        let ret = constPtrs.withUnsafeMutableBufferPointer { buf in
            idax_comment_set_posterior_lines(address, buf.baseAddress, buf.count)
        }
        try checkStatus(ret, "comment.setPosteriorLines")
    }

    public static func anteriorLines(at address: Address) throws(IDAError) -> [String] {
        var ptr: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>? = nil
        var count: Int = 0
        try checkStatus(idax_comment_anterior_lines(address, &ptr, &count), "comment.anteriorLines")
        defer { idax_comment_lines_free(ptr, count) }
        guard let ptr, count > 0 else { return [] }
        return (0..<count).map { i in
            if let s = ptr[i] { String(cString: s) } else { "" }
        }
    }

    public static func posteriorLines(at address: Address) throws(IDAError) -> [String] {
        var ptr: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>? = nil
        var count: Int = 0
        try checkStatus(idax_comment_posterior_lines(address, &ptr, &count), "comment.posteriorLines")
        defer { idax_comment_lines_free(ptr, count) }
        guard let ptr, count > 0 else { return [] }
        return (0..<count).map { i in
            if let s = ptr[i] { String(cString: s) } else { "" }
        }
    }

    // MARK: - Render

    public static func render(at address: Address, includeRepeatable: Bool = true, includeExtraLines: Bool = true) throws(IDAError) -> String {
        try withStringOutput("comment.render") {
            idax_comment_render(address, includeRepeatable ? 1 : 0, includeExtraLines ? 1 : 0, $0)
        }
    }
}

internal import CIDAX

/// Auto-analysis control.
///
/// Mirrors C++ `ida::analysis`.
public enum Analysis {

    public static func isEnabled() -> Bool {
        idax_analysis_is_enabled() != 0
    }

    public static func setEnabled(_ enabled: Bool) throws(IDAError) {
        try checkStatus(idax_analysis_set_enabled(enabled ? 1 : 0), "analysis.setEnabled")
    }

    public static func isIdle() -> Bool {
        idax_analysis_is_idle() != 0
    }

    public static func wait() throws(IDAError) {
        try checkStatus(idax_analysis_wait(), "analysis.wait")
    }

    public static func waitRange(start: Address, end: Address) throws(IDAError) {
        try checkStatus(idax_analysis_wait_range(start, end), "analysis.waitRange")
    }

    public static func schedule(_ address: Address) throws(IDAError) {
        try checkStatus(idax_analysis_schedule(address), "analysis.schedule")
    }

    public static func scheduleRange(start: Address, end: Address) throws(IDAError) {
        try checkStatus(idax_analysis_schedule_range(start, end), "analysis.scheduleRange")
    }

    public static func scheduleCode(_ address: Address) throws(IDAError) {
        try checkStatus(idax_analysis_schedule_code(address), "analysis.scheduleCode")
    }

    public static func scheduleFunction(_ address: Address) throws(IDAError) {
        try checkStatus(idax_analysis_schedule_function(address), "analysis.scheduleFunction")
    }

    public static func scheduleReanalysis(_ address: Address) throws(IDAError) {
        try checkStatus(idax_analysis_schedule_reanalysis(address), "analysis.scheduleReanalysis")
    }

    public static func scheduleReanalysisRange(start: Address, end: Address) throws(IDAError) {
        try checkStatus(
            idax_analysis_schedule_reanalysis_range(start, end),
            "analysis.scheduleReanalysisRange"
        )
    }

    public static func cancel(start: Address, end: Address) throws(IDAError) {
        try checkStatus(idax_analysis_cancel(start, end), "analysis.cancel")
    }

    public static func revertDecisions(start: Address, end: Address) throws(IDAError) {
        try checkStatus(idax_analysis_revert_decisions(start, end), "analysis.revertDecisions")
    }
}

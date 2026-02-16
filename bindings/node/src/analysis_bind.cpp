/// \file analysis_bind.cpp
/// \brief NAN bindings for ida::analysis — auto-analysis control, scheduling, waiting.

#include "helpers.hpp"
#include <ida/analysis.hpp>

namespace idax_node {
namespace {

// ── Enable / Disable ────────────────────────────────────────────────────

NAN_METHOD(IsEnabled) {
    info.GetReturnValue().Set(Nan::New(ida::analysis::is_enabled()));
}

NAN_METHOD(SetEnabled) {
    if (info.Length() < 1 || !info[0]->IsBoolean()) {
        Nan::ThrowTypeError("Expected boolean argument");
        return;
    }
    bool enabled = Nan::To<bool>(info[0]).FromJust();
    IDAX_CHECK_STATUS(ida::analysis::set_enabled(enabled));
}

// ── Idle / Wait ─────────────────────────────────────────────────────────

NAN_METHOD(IsIdle) {
    info.GetReturnValue().Set(Nan::New(ida::analysis::is_idle()));
}

NAN_METHOD(Wait) {
    IDAX_CHECK_STATUS(ida::analysis::wait());
}

NAN_METHOD(WaitRange) {
    ida::Address start, end;
    if (!GetAddressArg(info, 0, start)) return;
    if (!GetAddressArg(info, 1, end)) return;

    IDAX_CHECK_STATUS(ida::analysis::wait_range(start, end));
}

// ── Scheduling ──────────────────────────────────────────────────────────

NAN_METHOD(Schedule) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;

    IDAX_CHECK_STATUS(ida::analysis::schedule(addr));
}

NAN_METHOD(ScheduleRange) {
    ida::Address start, end;
    if (!GetAddressArg(info, 0, start)) return;
    if (!GetAddressArg(info, 1, end)) return;

    IDAX_CHECK_STATUS(ida::analysis::schedule_range(start, end));
}

NAN_METHOD(ScheduleCode) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;

    IDAX_CHECK_STATUS(ida::analysis::schedule_code(addr));
}

NAN_METHOD(ScheduleFunction) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;

    IDAX_CHECK_STATUS(ida::analysis::schedule_function(addr));
}

NAN_METHOD(ScheduleReanalysis) {
    ida::Address addr;
    if (!GetAddressArg(info, 0, addr)) return;

    IDAX_CHECK_STATUS(ida::analysis::schedule_reanalysis(addr));
}

NAN_METHOD(ScheduleReanalysisRange) {
    ida::Address start, end;
    if (!GetAddressArg(info, 0, start)) return;
    if (!GetAddressArg(info, 1, end)) return;

    IDAX_CHECK_STATUS(ida::analysis::schedule_reanalysis_range(start, end));
}

// ── Cancellation / Revert ───────────────────────────────────────────────

NAN_METHOD(Cancel) {
    ida::Address start, end;
    if (!GetAddressArg(info, 0, start)) return;
    if (!GetAddressArg(info, 1, end)) return;

    IDAX_CHECK_STATUS(ida::analysis::cancel(start, end));
}

NAN_METHOD(RevertDecisions) {
    ida::Address start, end;
    if (!GetAddressArg(info, 0, start)) return;
    if (!GetAddressArg(info, 1, end)) return;

    IDAX_CHECK_STATUS(ida::analysis::revert_decisions(start, end));
}

} // anonymous namespace

// ── Module registration ─────────────────────────────────────────────────

void InitAnalysis(v8::Local<v8::Object> target) {
    auto ns = CreateNamespace(target, "analysis");

    // Enable / disable / idle
    SetMethod(ns, "isEnabled",  IsEnabled);
    SetMethod(ns, "setEnabled", SetEnabled);
    SetMethod(ns, "isIdle",     IsIdle);

    // Waiting
    SetMethod(ns, "wait",      Wait);
    SetMethod(ns, "waitRange", WaitRange);

    // Scheduling
    SetMethod(ns, "schedule",                Schedule);
    SetMethod(ns, "scheduleRange",           ScheduleRange);
    SetMethod(ns, "scheduleCode",            ScheduleCode);
    SetMethod(ns, "scheduleFunction",        ScheduleFunction);
    SetMethod(ns, "scheduleReanalysis",      ScheduleReanalysis);
    SetMethod(ns, "scheduleReanalysisRange", ScheduleReanalysisRange);

    // Cancellation / revert
    SetMethod(ns, "cancel",          Cancel);
    SetMethod(ns, "revertDecisions", RevertDecisions);
}

} // namespace idax_node

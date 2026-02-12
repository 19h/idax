#include <ida/idax.hpp>

#include <iostream>

namespace {

int g_pass = 0;
int g_fail = 0;

void check(bool ok, const char* msg) {
    if (ok) {
        ++g_pass;
    } else {
        ++g_fail;
        std::cerr << "[FAIL] " << msg << "\n";
    }
}

void test_error_model() {
    auto e1 = ida::Error::validation("bad input", "ctx");
    check(e1.category == ida::ErrorCategory::Validation, "validation category");
    check(e1.message == "bad input", "validation message");
    check(e1.context == "ctx", "validation context");

    ida::Result<int> r = 42;
    check(r.has_value() && *r == 42, "result success value");

    ida::Status st = ida::ok();
    check(st.has_value(), "status ok");
}

void test_shared_options() {
    ida::OperationOptions op;
    check(op.strict_validation, "default strict_validation");
    check(op.cancel_on_user_break, "default cancel_on_user_break");

    ida::RangeOptions ro;
    check(ro.start == ida::BadAddress, "range start default");
    check(ro.end == ida::BadAddress, "range end default");

    ida::WaitOptions wo;
    check(wo.poll_interval_ms == 10, "wait poll interval default");
}

void test_diagnostics() {
    using namespace ida::diagnostics;
    reset_performance_counters();

    auto s1 = set_log_level(LogLevel::Debug);
    check(s1.has_value(), "set_log_level");
    check(log_level() == LogLevel::Debug, "log_level roundtrip");

    log(LogLevel::Info, "unit", "diagnostics smoke line");
    auto counters = performance_counters();
    check(counters.log_messages >= 1, "log counter incremented");

    auto inv_ok = assert_invariant(true, "must hold");
    check(inv_ok.has_value(), "assert_invariant true");

    auto inv_bad = assert_invariant(false, "expected fail");
    check(!inv_bad.has_value(), "assert_invariant false");

    auto enriched = enrich(ida::Error::internal("x", "base"), "extra");
    check(enriched.context.find("base") != std::string::npos, "enrich base");
    check(enriched.context.find("extra") != std::string::npos, "enrich suffix");
}

void test_address_range_semantics() {
    ida::address::Range r{0x1000, 0x1010};
    check(r.size() == 0x10, "range size");
    check(r.contains(0x1000), "range contains start");
    check(!r.contains(0x1010), "range excludes end");
    check(!r.empty(), "range non-empty");
}

void test_iterator_contract_basics() {
    ida::address::ItemIterator a;
    ida::address::ItemIterator b;
    check(a == b, "default iterators equal");
}

} // namespace

int main() {
    test_error_model();
    test_shared_options();
    test_diagnostics();
    test_address_range_semantics();
    test_iterator_contract_basics();

    std::cout << "idax unit tests: " << g_pass << " passed, " << g_fail << " failed\n";
    return g_fail == 0 ? 0 : 1;
}

#include <ida/idax.hpp>

#include <cstring>
#include <iostream>
#include <string>
#include <string_view>

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

void test_path_helpers() {
    check(ida::path::basename("alpha/beta.bin") == "beta.bin", "basename final component");
    check(ida::path::dirname("alpha/beta.bin") == "alpha", "dirname parent component");
    check(ida::path::is_directory("."), "current directory is directory");
}

void test_typed_form_bindings() {
    std::int64_t int_value = 5;
    auto int_binding = ida::ui::form_int(int_value);
    check(int_binding.prepare().has_value(), "form int prepare");
    *int_binding.sdk_arg() = 9;
    int_binding.commit();
    check(int_value == 9, "form int commit");

    std::uint16_t flags = 1;
    auto bitset_binding = ida::ui::form_bitset(flags);
    check(bitset_binding.prepare().has_value(), "form bitset prepare");
    *bitset_binding.sdk_arg() = 3;
    bitset_binding.commit();
    check(flags == 3, "form bitset commit");

    ida::Address address = 0x401000;
    auto address_binding = ida::ui::form_address(address);
    check(address_binding.prepare().has_value(), "form address prepare");
    *address_binding.sdk_arg() = 0x402000;
    address_binding.commit();
    check(address == 0x402000, "form address commit");

    std::string path = "/tmp/old.bin";
    auto path_binding = ida::ui::form_path(path);
    check(path_binding.prepare().has_value(), "form path prepare");
    constexpr char new_path[] = "/tmp/new.bin";
    std::memcpy(path_binding.sdk_arg(), new_path, sizeof(new_path));
    path_binding.commit();
    check(path == "/tmp/new.bin", "form path commit");

    std::string long_path(static_cast<std::size_t>(QMAXPATH), 'x');
    auto long_path_binding = ida::ui::form_path(long_path);
    check(!long_path_binding.prepare().has_value(), "form path rejects QMAXPATH overflow");
}

bool contains(std::string_view haystack, std::string_view needle) {
    return haystack.find(needle) != std::string_view::npos;
}

void test_codedump_form_builder_shapes() {
    sval_t depth = 2;
    sval_t item_limit = 256;
    sval_t type_limit = 64;
    std::uint16_t flags = 1;
    std::uint16_t output_flags = 2;
    std::uint16_t radio = 0;
    std::string path = "/tmp/codedump.json";

    auto dump_dialog = ida::ui::form_builder("dump")
        .add_sval("Depth", depth)
        .add_sval("Item limit", item_limit)
        .add_sval("Type limit", type_limit)
        .add_path("Output", path)
        .add_bitset("Sections", flags, {"metadata", "types"})
        .add_bitset("Output", output_flags, {"pretty", "clipboard"});
    check(contains(dump_dialog.markup(), "Depth:D:"), "codedump dump depth field");
    check(contains(dump_dialog.markup(), "Output:f:"), "codedump dump path field");
    check(contains(dump_dialog.markup(), "metadata:C"), "codedump dump bitset field");
    static_assert(std::is_same_v<decltype(dump_dialog.ask()), ida::Result<bool>>);

    auto type_dump_dialog = ida::ui::form_builder("type dump")
        .add_sval("Depth", depth)
        .add_path("Output", path)
        .add_bitset("Options", flags, {"recursive", "comments"});
    check(contains(type_dump_dialog.markup(), "Depth:D:"), "codedump type depth field");
    check(contains(type_dump_dialog.markup(), "Output:f:"), "codedump type path field");
    check(contains(type_dump_dialog.markup(), "recursive:C"), "codedump type bitset field");

    auto copy_type_dialog = ida::ui::form_builder("copy type")
        .add_sval("Depth", depth)
        .add_bitset("Options", flags, {"recursive", "dependencies"});
    check(contains(copy_type_dialog.markup(), "Depth:D:"), "codedump copy depth field");
    check(contains(copy_type_dialog.markup(), "dependencies:C"), "codedump copy bitset field");

    auto type_graph_dialog = ida::ui::form_builder("type graph")
        .add_radio("Graph kind", radio, {"tree", "refs"})
        .add_sval("Depth", depth)
        .add_path("Output", path)
        .add_bitset("Options", flags, {"recursive", "external"});
    check(contains(type_graph_dialog.markup(), "tree:R"), "codedump graph radio field");
    check(contains(type_graph_dialog.markup(), "Depth:D:"), "codedump graph depth field");
    check(contains(type_graph_dialog.markup(), "Output:f:"), "codedump graph path field");
    check(contains(type_graph_dialog.markup(), "external:C"), "codedump graph bitset field");

    auto apply_metadata_dialog = ida::ui::form_builder("apply metadata")
        .add_path("Input", path, false)
        .add_bitset("Options", flags, {"names", "comments"});
    check(contains(apply_metadata_dialog.markup(), "Input:f:"), "codedump apply path field");
    check(contains(apply_metadata_dialog.markup(), "comments:C"), "codedump apply bitset field");
}

} // namespace

int main() {
    test_error_model();
    test_shared_options();
    test_diagnostics();
    test_address_range_semantics();
    test_iterator_contract_basics();
    test_path_helpers();
    test_typed_form_bindings();
    test_codedump_form_builder_shapes();

    std::cout << "idax unit tests: " << g_pass << " passed, " << g_fail << " failed\n";
    return g_fail == 0 ? 0 : 1;
}

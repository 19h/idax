#include <ida/analysis.hpp>
#include <ida/database.hpp>
#include <ida/lumina.hpp>
#include <ida/name.hpp>
#include <array>
#include <iostream>

int main(int argc, char** argv) {
    if (argc != 2) return 2;
    int passed = 0, failed = 0;
    struct Report {
        int& passed;
        int& failed;
        ~Report() {
            std::cout << "lumina_connected_probe: " << passed << " passed, "
                      << failed << " failed, 0 skipped" << std::endl;
        }
    } report{passed, failed};
    auto check = [&](bool ok, const char* label) {
        std::cout << (ok ? "PASS: " : "FAIL: ") << label << std::endl;
        ok ? ++passed : ++failed;
        return ok;
    };
    if (!check(ida::database::init().has_value(), "database init")) return 1;
    if (!check(ida::database::open(argv[1], ida::database::OpenMode::Analyze).has_value(), "database open")) return 1;
    struct Close { ~Close() { ida::database::close(false); } } close;
    if (!check(ida::analysis::wait().has_value(), "analysis complete")) return 1;
    const auto main = ida::name::resolve("main");
    if (!check(main.has_value(), "main resolved")) return 1;
    const auto all = std::array{ida::lumina::Feature::PrimaryMetadata,
        ida::lumina::Feature::SecondaryMetadata, ida::lumina::Feature::Decompiler,
        ida::lumina::Feature::Telemetry};
    auto state = [&](ida::lumina::Feature feature, bool expected, const char* label) {
        auto result = ida::lumina::has_connection(feature);
        return check(result && *result == expected, label);
    };
    check(ida::lumina::close_all_connections().has_value(), "initial close all");
    for (const auto feature : all) state(feature, false, "initial channel absent");
    auto connect = [&] {
        auto result = ida::lumina::pull(*main, false, true);
        if (!result) std::cerr << "Pull error: " << result.error().message << std::endl;
        check(result && result->requested == 1 && result->completed == 1, "actual metadata pull completed");
        return state(ida::lumina::Feature::PrimaryMetadata, true, "primary cached client present");
    };
    if (!connect()) return 1;
    state(ida::lumina::Feature::Telemetry, false, "telemetry remains absent");
    check(ida::lumina::close_connection(ida::lumina::Feature::Telemetry).has_value(), "absent telemetry close");
    state(ida::lumina::Feature::PrimaryMetadata, true, "primary survives unrelated absent close");
    auto invalid = ida::lumina::close_connection(static_cast<ida::lumina::Feature>(999));
    check(!invalid && invalid.error().category == ida::ErrorCategory::Validation, "invalid feature rejected");
    state(ida::lumina::Feature::PrimaryMetadata, true, "primary survives invalid close");
    check(ida::lumina::close_connection().has_value(), "connected primary close");
    state(ida::lumina::Feature::PrimaryMetadata, false, "primary cache cleared");
    check(ida::lumina::close_connection().has_value(), "repeated absent close");
    state(ida::lumina::Feature::PrimaryMetadata, false, "repeated close never connects");
    if (!connect()) return 1;
    check(ida::lumina::close_all_connections().has_value(), "connected close all");
    for (const auto feature : all) state(feature, false, "final channel absent");
    return failed ? 1 : 0;
}

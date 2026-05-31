/// \file codedump_parity_host_gates_test.cpp
/// \brief Host-gated runtime checks for ida-cdump Phase 22 parity APIs.

#include "../test_harness.hpp"

#include <ida/idax.hpp>

#include <cstdlib>
#include <string>
#include <string_view>

namespace {

bool env_enabled(const char* name) {
    const char* value = std::getenv(name);
    return value != nullptr
        && value[0] != '\0'
        && std::string_view(value) != "0"
        && std::string_view(value) != "false"
        && std::string_view(value) != "FALSE";
}

void test_default_clipboard_contract() {
    SECTION("clipboard backend contract");

    auto backend = ida::ui::clipboard_backend();
    CHECK(!backend.empty());

    if (backend == "unsupported") {
        CHECK_ERR(ida::ui::copy_to_clipboard("idax-codedump-parity"),
                  ida::ErrorCategory::Unsupported);
        CHECK_ERR(ida::ui::read_clipboard(), ida::ErrorCategory::Unsupported);
    } else {
        CHECK(backend == "Qt" || backend.rfind("external:", 0) == 0);
        CHECK(backend.find(' ') == std::string_view::npos);
    }
}

void test_qt_clipboard_roundtrip() {
    SECTION("host-gated clipboard roundtrip");

    if (!env_enabled("IDAX_RUN_QT_CLIPBOARD")) {
        SKIP("set IDAX_RUN_QT_CLIPBOARD=1 under an IDA host with clipboard access");
        return;
    }

    auto previous = ida::ui::read_clipboard();
    const std::string token = "idax-codedump-parity-clipboard-token";
    CHECK_OK(ida::ui::copy_to_clipboard(token));
    CHECK_VAL(ida::ui::read_clipboard(), _v == token);

    if (previous) {
        CHECK_OK(ida::ui::copy_to_clipboard(*previous));
    }
}

void test_modal_typed_form() {
    SECTION("host-gated codedump-shaped typed form");

    if (!env_enabled("IDAX_RUN_MODAL_FORMS")) {
        SKIP("set IDAX_RUN_MODAL_FORMS=1 under an interactive IDA UI host");
        return;
    }

    std::int64_t depth = 2;
    std::string output_path = "codedump-parity.json";
    std::uint16_t flags = 1;

    auto builder = ida::ui::FormBuilder<>("idax codedump parity")
        .add_int("Depth", depth)
        .add_path("Output", output_path)
        .add_bitset("Options", flags, {"metadata", "types"});

    auto accepted = builder.ask();
    CHECK_OK(accepted);
    CHECK(accepted && *accepted);
    CHECK(depth >= 0);
    CHECK(!output_path.empty());
}

void test_hexrays_scoped_session(int argc, char** argv) {
    SECTION("host-gated Hex-Rays scoped session");

    if (!env_enabled("IDAX_RUN_HEXRAYS_SESSION")) {
        SKIP("set IDAX_RUN_HEXRAYS_SESSION=1 under a licensed Hex-Rays host");
        return;
    }
    if (argc < 2) {
        SKIP("fixture path is required for Hex-Rays runtime validation");
        return;
    }

    auto init = ida::database::init(argc, argv);
    CHECK_OK(init);
    if (!init) {
        return;
    }

    auto open = ida::database::open(argv[1], true);
    CHECK_OK(open);
    if (!open) {
        (void)ida::database::close(false);
        return;
    }

    (void)ida::analysis::wait();

    auto session = ida::decompiler::initialize();
    CHECK_OK(session);
    if (session) {
        CHECK(session->valid());
        CHECK_OK(session->close());
        CHECK(!session->valid());
    }

    (void)ida::database::close(false);
}

} // namespace

int main(int argc, char** argv) {
    test_default_clipboard_contract();
    test_qt_clipboard_roundtrip();
    test_modal_typed_form();
    test_hexrays_scoped_session(argc, argv);

    return idax_test::report("codedump_parity_host_gates_test");
}

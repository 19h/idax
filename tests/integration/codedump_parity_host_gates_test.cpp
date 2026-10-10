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

void test_qt_clipboard_roundtrip(bool force_enabled = false) {
    SECTION("host-gated clipboard roundtrip");

    if (!force_enabled && !env_enabled("IDAX_RUN_QT_CLIPBOARD")) {
        SKIP("set IDAX_RUN_QT_CLIPBOARD=1 under an IDA host with clipboard access");
        return;
    }

    auto previous = ida::ui::read_clipboard();
    if (!previous && previous.error().category != ida::ErrorCategory::NotFound) {
        CHECK_OK(previous);
        return;
    }
    const std::string token = "idax-codedump-parity-clipboard-token";
    CHECK_OK(ida::ui::copy_to_clipboard(token));
    CHECK_VAL(ida::ui::read_clipboard(), _v == token);

    CHECK_OK(ida::ui::copy_to_clipboard(previous ? *previous : std::string{}));
}

void test_modal_typed_form(bool force_enabled = false) {
    SECTION("host-gated codedump-shaped typed form");

    if (!force_enabled && !env_enabled("IDAX_RUN_MODAL_FORMS")) {
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
    std::cout << "Captured form: depth=" << depth << ", output=" << output_path
              << ", flags=" << flags << '\n';
}

#ifndef IDAX_CODEDUMP_UI_HOST
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
#endif

} // namespace

int run_codedump_parity_host_gates(int argc, char** argv, bool interactive_host) {
    idax_test::g_pass = idax_test::g_fail = idax_test::g_skip = 0;
    test_default_clipboard_contract();
    test_qt_clipboard_roundtrip(interactive_host);
    test_modal_typed_form(interactive_host);
#ifndef IDAX_CODEDUMP_UI_HOST
    test_hexrays_scoped_session(argc, argv);
#else
    (void)argc;
    (void)argv;
    SECTION("host-gated Hex-Rays scoped session");
    SKIP("separate idalib Hex-Rays session gate; interactive probe does not reopen a database");
#endif

    return idax_test::report("codedump_parity_host_gates_test");
}

#ifndef IDAX_CODEDUMP_UI_HOST
int main(int argc, char** argv) {
    return run_codedump_parity_host_gates(argc, argv, false);
}
#endif

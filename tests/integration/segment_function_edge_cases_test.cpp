/// \file segment_function_edge_cases_test.cpp
/// \brief Integration edge-case tests for ida::segment and ida::function.

#include <ida/idax.hpp>

#include <iostream>
#include <string>

namespace {

int g_pass = 0;
int g_fail = 0;

#define CHECK(expr)                                                       \
    do {                                                                  \
        if (expr) {                                                       \
            ++g_pass;                                                     \
        } else {                                                          \
            ++g_fail;                                                     \
            std::cerr << "FAIL: " #expr " (" << __FILE__ << ":"       \
                      << __LINE__ << ")\n";                             \
        }                                                                 \
    } while (false)

#define CHECK_OK(expr)                                                    \
    do {                                                                  \
        auto _r = (expr);                                                 \
        if (_r.has_value()) {                                             \
            ++g_pass;                                                     \
        } else {                                                          \
            ++g_fail;                                                     \
            std::cerr << "FAIL: " #expr " => error: "                   \
                      << _r.error().message << " (" << __FILE__         \
                      << ":" << __LINE__ << ")\n";                     \
        }                                                                 \
    } while (false)

void test_segment_edge_cases() {
    std::cout << "--- segment edge cases ---\n";

    auto seg_count = ida::segment::count();
    CHECK_OK(seg_count);
    if (!seg_count || *seg_count == 0)
        return;

    auto out_of_range = ida::segment::by_index(*seg_count);
    CHECK(!out_of_range.has_value());
    if (!out_of_range)
        CHECK(out_of_range.error().category == ida::ErrorCategory::Validation);

    auto missing_name = ida::segment::by_name("__idax_missing_segment__");
    CHECK(!missing_name.has_value());
    if (!missing_name)
        CHECK(missing_name.error().category == ida::ErrorCategory::NotFound);

    auto bad_at = ida::segment::at(ida::BadAddress);
    CHECK(!bad_at.has_value());
    if (!bad_at)
        CHECK(bad_at.error().category == ida::ErrorCategory::NotFound);

    auto seg0 = ida::segment::by_index(0);
    CHECK_OK(seg0);
    if (!seg0)
        return;

    auto invalid_bitness = ida::segment::set_bitness(seg0->start(), 24);
    CHECK(!invalid_bitness.has_value());
    if (!invalid_bitness)
        CHECK(invalid_bitness.error().category == ida::ErrorCategory::Validation);

    auto invalid_default_register =
        ida::segment::set_default_segment_register(seg0->start(), -1, 0);
    CHECK(!invalid_default_register.has_value());
    if (!invalid_default_register) {
        CHECK(invalid_default_register.error().category == ida::ErrorCategory::Validation);
    }

    auto invalid_default_register_all =
        ida::segment::set_default_segment_register_for_all(-1, 0);
    CHECK(!invalid_default_register_all.has_value());
    if (!invalid_default_register_all) {
        CHECK(invalid_default_register_all.error().category == ida::ErrorCategory::Validation);
    }

    auto seed_defaults = ida::segment::set_default_segment_register_for_all(0, 0);
    CHECK(seed_defaults.has_value()
          || seed_defaults.error().category == ida::ErrorCategory::SdkFailure
          || seed_defaults.error().category == ida::ErrorCategory::Validation);

    // Permission round-trip to ensure property mutation/refresh paths are stable.
    auto original_perm = seg0->permissions();
    ida::segment::Permissions toggled = original_perm;
    toggled.execute = !toggled.execute;

    CHECK_OK(ida::segment::set_permissions(seg0->start(), toggled));
    auto changed = ida::segment::at(seg0->start());
    CHECK_OK(changed);
    if (changed)
        CHECK(changed->permissions().execute == toggled.execute);

    CHECK_OK(ida::segment::set_permissions(seg0->start(), original_perm));
    auto restored = ida::segment::at(seg0->start());
    CHECK_OK(restored);
    if (restored)
        CHECK(restored->permissions().execute == original_perm.execute);

    auto first = ida::segment::first();
    auto last = ida::segment::last();
    CHECK_OK(first);
    CHECK_OK(last);
    if (first && last) {
        CHECK(first->start() <= last->start());
        auto maybe_next = ida::segment::next(first->start());
        if (maybe_next)
            CHECK(maybe_next->start() >= first->start());
    }

    CHECK_OK(ida::segment::set_comment(seg0->start(), "idax segment edge comment"));
    auto seg_comment = ida::segment::comment(seg0->start());
    CHECK_OK(seg_comment);
    if (seg_comment)
        CHECK(seg_comment->find("idax segment edge comment") != std::string::npos);
    CHECK_OK(ida::segment::set_comment(seg0->start(), ""));

    auto invalid_resize = ida::segment::resize(seg0->start(), seg0->end(), seg0->start());
    CHECK(!invalid_resize.has_value());
    if (!invalid_resize)
        CHECK(invalid_resize.error().category == ida::ErrorCategory::Validation);

    auto invalid_move = ida::segment::move(seg0->start(), ida::BadAddress);
    CHECK(!invalid_move.has_value());
    if (!invalid_move)
        CHECK(invalid_move.error().category == ida::ErrorCategory::Validation);
}

void test_function_edge_cases() {
    std::cout << "--- function edge cases ---\n";

    auto fn_count = ida::function::count();
    CHECK_OK(fn_count);
    if (!fn_count || *fn_count == 0)
        return;

    auto out_of_range = ida::function::by_index(*fn_count);
    CHECK(!out_of_range.has_value());
    if (!out_of_range)
        CHECK(out_of_range.error().category == ida::ErrorCategory::Validation);

    auto bad_at = ida::function::at(ida::BadAddress);
    CHECK(!bad_at.has_value());
    if (!bad_at)
        CHECK(bad_at.error().category == ida::ErrorCategory::NotFound);

    auto bad_callers = ida::function::callers(ida::BadAddress);
    CHECK(!bad_callers.has_value());
    if (!bad_callers)
        CHECK(bad_callers.error().category == ida::ErrorCategory::NotFound);

    auto bad_chunks = ida::function::chunk_count(ida::BadAddress);
    CHECK(!bad_chunks.has_value());
    if (!bad_chunks)
        CHECK(bad_chunks.error().category == ida::ErrorCategory::NotFound);

    auto fn0 = ida::function::by_index(0);
    CHECK_OK(fn0);
    if (!fn0)
        return;

    auto chunks = ida::function::chunks(fn0->start());
    auto tails = ida::function::tail_chunks(fn0->start());
    auto chunk_count = ida::function::chunk_count(fn0->start());
    CHECK_OK(chunks);
    CHECK_OK(tails);
    CHECK_OK(chunk_count);
    if (chunks && tails && chunk_count) {
        CHECK(!chunks->empty());
        CHECK(*chunk_count == chunks->size());
        CHECK(tails->size() <= chunks->size());
    }

    CHECK_OK(ida::function::update(fn0->start()));
    CHECK_OK(ida::function::reanalyze(fn0->start()));

    auto items = ida::function::item_addresses(fn0->start());
    auto codes = ida::function::code_addresses(fn0->start());
    CHECK_OK(items);
    CHECK_OK(codes);
    if (items && codes) {
        CHECK(!items->empty());
        CHECK(codes->size() <= items->size());
    }

    auto regvars = ida::function::register_variables(fn0->start());
    CHECK_OK(regvars);

    auto frame = ida::function::frame(fn0->start());
    if (frame && !frame->variables().empty()) {
        const auto& v = frame->variables().front();
        auto by_name = ida::function::frame_variable_by_name(fn0->start(), v.name);
        auto by_offset = ida::function::frame_variable_by_offset(fn0->start(), v.byte_offset);
        CHECK_OK(by_name);
        CHECK_OK(by_offset);
    }

    // Comment lifecycle should cleanly round-trip on valid function addresses.
    CHECK_OK(ida::function::set_comment(fn0->start(), "idax function edge comment"));
    auto got_comment = ida::function::comment(fn0->start());
    CHECK_OK(got_comment);
    if (got_comment)
        CHECK(got_comment->find("idax function edge comment") != std::string::npos);

    CHECK_OK(ida::function::set_comment(fn0->start(), ""));
    auto removed_comment = ida::function::comment(fn0->start());
    CHECK(!removed_comment.has_value());
    if (!removed_comment)
        CHECK(removed_comment.error().category == ida::ErrorCategory::NotFound);
}

} // namespace

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <binary>\n";
        return 1;
    }

    auto init = ida::database::init(argc, argv);
    if (!init) {
        std::cerr << "init_library failed: " << init.error().message << "\n";
        return 1;
    }

    auto open = ida::database::open(argv[1], true);
    if (!open) {
        std::cerr << "open_database failed: " << open.error().message << "\n";
        return 1;
    }

    CHECK_OK(ida::analysis::wait());

    test_segment_edge_cases();
    test_function_edge_cases();

    CHECK_OK(ida::database::close(false));

    std::cout << "\n=== Results: " << g_pass << " passed, " << g_fail
              << " failed ===\n";
    return g_fail > 0 ? 1 : 0;
}

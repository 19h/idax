/// \file name_comment_xref_search_test.cpp
/// \brief Behavior-focused integration checks for ida::name/comment/xref/search.

#include <ida/idax.hpp>

#include <iostream>
#include <string>
#include <utility>
#include <vector>

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

#define CHECK_VAL(expr, check)                                            \
    do {                                                                  \
        auto _r = (expr);                                                 \
        if (_r.has_value() && (check)) {                                  \
            ++g_pass;                                                     \
        } else if (!_r.has_value()) {                                     \
            ++g_fail;                                                     \
            std::cerr << "FAIL: " #expr " => error: "                   \
                      << _r.error().message << " (" << __FILE__         \
                      << ":" << __LINE__ << ")\n";                     \
        } else {                                                          \
            ++g_fail;                                                     \
            std::cerr << "FAIL: " #expr " value check failed ("         \
                      << __FILE__ << ":" << __LINE__ << ")\n";         \
        }                                                                 \
    } while (false)

void restore_name(ida::Address ea, const ida::Result<std::string>& original_name) {
    if (original_name) {
        ida::name::set(ea, *original_name);
    } else {
        ida::name::remove(ea);
    }
}

ida::Result<std::pair<ida::Address, ida::Address>>
find_call_site_and_target() {
    for (auto fn : ida::function::all()) {
        ida::Address ea = fn.start();
        while (ea < fn.end()) {
            auto insn = ida::instruction::decode(ea);
            if (!insn) {
                auto next = ida::address::next_head(ea, fn.end());
                if (!next || *next <= ea)
                    break;
                ea = *next;
                continue;
            }

            if (ida::instruction::is_call(ea)) {
                auto code_refs = ida::xref::code_refs_from(ea);
                if (code_refs && !code_refs->empty()) {
                    for (const auto& ref : *code_refs) {
                        if (ref.to != ida::BadAddress)
                            return std::make_pair(ea, ref.to);
                    }
                }
            }

            if (insn->size() == 0)
                break;
            ea += insn->size();
        }
    }

    return std::unexpected(
        ida::Error::not_found("No call instruction with code references found"));
}

void test_name_behaviors() {
    std::cout << "--- name behavior ---\n";

    auto first_fn = ida::function::by_index(0);
    CHECK_OK(first_fn);
    if (!first_fn)
        return;

    const ida::Address first_ea = first_fn->start();
    auto first_original = ida::name::get(first_ea);

    const std::string first_temp = "__idax_name_behavior_primary__";
    CHECK_OK(ida::name::set(first_ea, first_temp));
    CHECK_VAL(ida::name::get(first_ea), *_r == first_temp);
    CHECK_VAL(ida::name::resolve(first_temp), *_r == first_ea);
    CHECK(!ida::name::is_auto_generated(first_ea));

    const bool was_public = ida::name::is_public(first_ea);
    CHECK_OK(ida::name::set_public(first_ea, !was_public));
    CHECK(ida::name::is_public(first_ea) == !was_public);
    CHECK_OK(ida::name::set_public(first_ea, was_public));

    auto second_fn = ida::function::by_index(1);
    if (second_fn) {
        const ida::Address second_ea = second_fn->start();
        auto second_original = ida::name::get(second_ea);

        const std::string conflict_base = "__idax_name_conflict__";
        CHECK_OK(ida::name::set(second_ea, conflict_base));
        CHECK_OK(ida::name::force_set(first_ea, conflict_base));

        auto forced_name = ida::name::get(first_ea);
        CHECK_OK(forced_name);
        if (forced_name) {
            CHECK(forced_name->rfind(conflict_base, 0) == 0);
        }

        restore_name(second_ea, second_original);
    } else {
        std::cout << "  (skipping force-set conflict path: need >= 2 functions)\n";
    }

    restore_name(first_ea, first_original);
}

void test_comment_behaviors() {
    std::cout << "--- comment behavior ---\n";

    auto first_fn = ida::function::by_index(0);
    CHECK_OK(first_fn);
    if (!first_fn)
        return;

    const ida::Address ea = first_fn->start();

    CHECK_OK(ida::comment::remove(ea, false));
    CHECK_OK(ida::comment::remove(ea, true));
    CHECK_OK(ida::comment::clear_anterior(ea));
    CHECK_OK(ida::comment::clear_posterior(ea));

    CHECK_OK(ida::comment::set(ea, "idax regular"));
    CHECK_OK(ida::comment::append(ea, " +append"));
    auto regular = ida::comment::get(ea, false);
    CHECK_OK(regular);
    if (regular) {
        CHECK(regular->find("idax regular") != std::string::npos);
    }

    CHECK_OK(ida::comment::set(ea, "idax repeatable", true));
    CHECK_VAL(ida::comment::get(ea, true), *_r == "idax repeatable");

    const std::vector<std::string> ant = {
        "idax anterior A",
        "idax anterior B",
    };
    const std::vector<std::string> post = {
        "idax posterior A",
    };
    CHECK_OK(ida::comment::set_anterior_lines(ea, ant));
    CHECK_OK(ida::comment::set_posterior_lines(ea, post));

    auto ant_read = ida::comment::anterior_lines(ea);
    CHECK_OK(ant_read);
    if (ant_read) {
        CHECK(ant_read->size() == ant.size());
        if (ant_read->size() == ant.size()) {
            CHECK((*ant_read)[0] == ant[0]);
            CHECK((*ant_read)[1] == ant[1]);
        }
    }

    auto post_read = ida::comment::posterior_lines(ea);
    CHECK_OK(post_read);
    if (post_read) {
        CHECK(post_read->size() == post.size());
        if (post_read->size() == post.size()) {
            CHECK((*post_read)[0] == post[0]);
        }
    }

    auto rendered = ida::comment::render(ea, true, true);
    CHECK_OK(rendered);
    if (rendered) {
        CHECK(rendered->find("idax regular") != std::string::npos);
        CHECK(rendered->find("idax repeatable") != std::string::npos);
        CHECK(rendered->find("idax anterior A") != std::string::npos);
        CHECK(rendered->find("idax posterior A") != std::string::npos);
    }

    CHECK_OK(ida::comment::clear_anterior(ea));
    CHECK_OK(ida::comment::clear_posterior(ea));
    CHECK_OK(ida::comment::remove(ea, false));
    CHECK_OK(ida::comment::remove(ea, true));

    auto regular_missing = ida::comment::get(ea, false);
    CHECK(!regular_missing.has_value());
    if (!regular_missing.has_value()) {
        CHECK(regular_missing.error().category == ida::ErrorCategory::NotFound);
    }
}

void test_xref_behaviors() {
    std::cout << "--- xref behavior ---\n";

    auto call_and_target = find_call_site_and_target();
    CHECK_OK(call_and_target);
    if (!call_and_target)
        return;

    const ida::Address call_site = call_and_target->first;
    const ida::Address target = call_and_target->second;

    auto refs_from = ida::xref::refs_from(call_site);
    auto code_from = ida::xref::code_refs_from(call_site);
    auto data_from = ida::xref::data_refs_from(call_site);
    CHECK_OK(refs_from);
    CHECK_OK(code_from);
    CHECK_OK(data_from);

    if (refs_from && code_from && data_from) {
        CHECK(refs_from->size() >= code_from->size());
        CHECK(refs_from->size() >= data_from->size());
        for (const auto& ref : *code_from)
            CHECK(ref.is_code);
        for (const auto& ref : *data_from)
            CHECK(!ref.is_code);
    }

    auto refs_to = ida::xref::refs_to(target);
    auto code_to = ida::xref::code_refs_to(target);
    CHECK_OK(refs_to);
    CHECK_OK(code_to);

    if (refs_to) {
        bool call_site_found = false;
        for (const auto& ref : *refs_to) {
            if (ref.from == call_site) {
                call_site_found = true;
                break;
            }
        }
        CHECK(call_site_found);
    }

    if (code_to) {
        for (const auto& ref : *code_to)
            CHECK(ref.is_code);
    }
}

void test_search_behaviors() {
    std::cout << "--- search behavior ---\n";

    auto lo = ida::database::min_address();
    CHECK_OK(lo);
    if (!lo)
        return;

    auto plain = ida::search::text("main", *lo, ida::search::Direction::Forward, false);
    CHECK_OK(plain);
    if (plain)
        CHECK(ida::address::is_mapped(*plain));

    ida::search::TextOptions opts;
    opts.direction = ida::search::Direction::Forward;
    opts.case_sensitive = false;
    opts.regex = true;
    opts.no_break = true;
    opts.no_show = true;

    auto regex = ida::search::text("main", *lo, opts);
    CHECK_OK(regex);
    if (regex)
        CHECK(ida::address::is_mapped(*regex));

    auto elf_magic = ida::search::binary_pattern("7F 45 4C 46", *lo);
    CHECK_OK(elf_magic);
    if (elf_magic)
        CHECK(*elf_magic == *lo);

    auto impossible_immediate = ida::search::immediate(0xFFFFFFFFFFFFFFFFULL, *lo);
    CHECK(!impossible_immediate.has_value());
    if (!impossible_immediate.has_value()) {
        CHECK(impossible_immediate.error().category == ida::ErrorCategory::NotFound);
    }

    auto next_code = ida::search::next_code(*lo);
    CHECK_OK(next_code);
    if (next_code)
        CHECK(ida::address::is_code(*next_code));

    auto next_data = ida::search::next_data(*lo);
    CHECK_OK(next_data);
    if (next_data)
        CHECK(ida::address::is_data(*next_data));

    auto next_unknown = ida::search::next_unknown(*lo);
    if (next_unknown) {
        CHECK(ida::address::is_unknown(*next_unknown));
    } else {
        CHECK(next_unknown.error().category == ida::ErrorCategory::NotFound);
    }
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

    test_name_behaviors();
    test_comment_behaviors();
    test_xref_behaviors();
    test_search_behaviors();

    auto close = ida::database::close(false);
    CHECK_OK(close);

    std::cout << "\n=== Results: " << g_pass << " passed, " << g_fail
              << " failed ===\n";
    return g_fail > 0 ? 1 : 0;
}

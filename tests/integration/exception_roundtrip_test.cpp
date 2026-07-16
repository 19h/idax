/// \file exception_roundtrip_test.cpp
/// \brief Isolated real-IDA C++/SEH exception-region round-trip evidence.

#include <ida/idax.hpp>

#include <array>
#include <iostream>
#include <vector>

namespace {

int g_pass = 0;
int g_fail = 0;

#define CHECK(expression)                                                   \
    do {                                                                    \
        if (expression) {                                                   \
            ++g_pass;                                                       \
        } else {                                                            \
            ++g_fail;                                                       \
            std::cerr << "FAIL: " #expression " (" << __FILE__ << ':'      \
                      << __LINE__ << ")\n";                                \
        }                                                                   \
    } while (false)

template <typename T>
bool require_result(const ida::Result<T>& result, const char* operation) {
    if (result)
        return true;
    ++g_fail;
    std::cerr << "FAIL: " << operation << ": " << result.error().message
              << '\n';
    return false;
}

bool require_status(const ida::Status& status, const char* operation) {
    if (status)
        return true;
    ++g_fail;
    std::cerr << "FAIL: " << operation << ": " << status.error().message
              << " [" << status.error().code << "]\n";
    return false;
}

ida::Result<std::array<ida::Address, 6>> find_test_heads() {
    const auto count = ida::function::count();
    if (!count)
        return std::unexpected(count.error());
    for (std::size_t index = 0; index < *count; ++index) {
        auto function = ida::function::by_index(index);
        if (!function)
            continue;
        std::array<ida::Address, 6> heads{};
        heads[0] = function->start();
        bool complete = true;
        for (std::size_t head = 1; head < heads.size(); ++head) {
            auto next = ida::address::next_head(heads[head - 1], function->end());
            if (!next || *next >= function->end()) {
                complete = false;
                break;
            }
            heads[head] = *next;
        }
        if (complete)
            return heads;
    }
    return std::unexpected(ida::Error::not_found(
        "No function with six instruction heads is available"));
}

const ida::exception::Block* find_block(
    const std::vector<ida::exception::Block>& blocks,
    ida::Address protected_start) {
    for (const auto& block : blocks) {
        if (!block.definition.protected_regions.empty()
            && block.definition.protected_regions.front().start == protected_start)
            return &block;
    }
    return nullptr;
}

bool ranges_equal(const std::vector<ida::address::Range>& lhs,
                  const std::vector<ida::address::Range>& rhs) {
    if (lhs.size() != rhs.size())
        return false;
    for (std::size_t index = 0; index < lhs.size(); ++index) {
        if (lhs[index].start != rhs[index].start
            || lhs[index].end != rhs[index].end)
            return false;
    }
    return true;
}

} // namespace

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <binary>\n";
        return 1;
    }

    if (!require_status(ida::database::init(argc, argv), "database init"))
        return 1;
    if (!require_status(ida::database::open(argv[1], true), "database open"))
        return 1;
    if (!require_status(ida::analysis::wait(), "analysis wait"))
        return 1;

    auto heads_result = find_test_heads();
    if (!require_result(heads_result, "test instruction heads"))
        return 1;
    const auto heads = *heads_result;
    const ida::address::Range scope{heads[0], heads[5]};

    auto invalid_query = ida::exception::list({ida::BadAddress, heads[1]});
    CHECK(!invalid_query.has_value());
    if (!invalid_query)
        CHECK(invalid_query.error().category == ida::ErrorCategory::Validation);
    auto invalid_mask = ida::exception::contains(
        heads[0], static_cast<ida::exception::Location>(0));
    CHECK(!invalid_mask.has_value());
    if (!invalid_mask)
        CHECK(invalid_mask.error().category == ida::ErrorCategory::Validation);
    auto invalid_address = ida::exception::system_region_start(ida::BadAddress);
    CHECK(!invalid_address.has_value());

    ida::exception::BlockDefinition malformed;
    auto empty_block = ida::exception::add(malformed);
    CHECK(!empty_block.has_value());
    malformed.protected_regions.push_back({heads[0], heads[1]});
    auto no_catches = ida::exception::add(malformed);
    CHECK(!no_catches.has_value());

    require_status(ida::exception::remove(scope), "initial exception cleanup");

    ida::exception::CatchHandler typed_catch;
    typed_catch.metadata.regions = {{heads[3], heads[4]}};
    typed_catch.metadata.stack_displacement = 16;
    typed_catch.metadata.frame_register = 5;
    typed_catch.object_displacement = 24;
    typed_catch.selector = {ida::exception::CatchSelectorKind::Typed, 7};

    ida::exception::CatchHandler catch_all = typed_catch;
    catch_all.metadata.stack_displacement.reset();
    catch_all.metadata.frame_register.reset();
    catch_all.object_displacement.reset();
    catch_all.selector = {ida::exception::CatchSelectorKind::CatchAll, 0};

    ida::exception::CatchHandler cleanup = catch_all;
    cleanup.selector = {ida::exception::CatchSelectorKind::Cleanup, 0};

    ida::exception::BlockDefinition cpp_definition;
    cpp_definition.protected_regions = {
        {heads[0], heads[1]},
        {heads[2], heads[3]},
    };
    cpp_definition.handlers = ida::exception::CppHandlers{
        {typed_catch, catch_all, cleanup}};

    CHECK(require_status(ida::exception::add(cpp_definition),
                         "add C++ exception block"));
    auto cpp_blocks = ida::exception::list(scope);
    CHECK(require_result(cpp_blocks, "list C++ exception blocks"));
    const auto* cpp_block = cpp_blocks ? find_block(*cpp_blocks, heads[0]) : nullptr;
    CHECK(cpp_block != nullptr);
    if (cpp_block != nullptr) {
        CHECK(ranges_equal(cpp_block->definition.protected_regions,
                           cpp_definition.protected_regions));
        CHECK(cpp_block->nesting_level == 0);
        const auto* handlers = std::get_if<ida::exception::CppHandlers>(
            &cpp_block->definition.handlers);
        CHECK(handlers != nullptr);
        if (handlers != nullptr) {
            CHECK(handlers->catches.size() == 3);
            if (handlers->catches.size() == 3) {
                CHECK(handlers->catches[0].selector.kind ==
                      ida::exception::CatchSelectorKind::Typed);
                CHECK(handlers->catches[0].selector.type_identifier == 7);
                CHECK(handlers->catches[0].metadata.stack_displacement == 16);
                CHECK(handlers->catches[0].metadata.frame_register == 5);
                CHECK(handlers->catches[0].object_displacement == 24);
                CHECK(handlers->catches[1].selector.kind ==
                      ida::exception::CatchSelectorKind::CatchAll);
                CHECK(handlers->catches[2].selector.kind ==
                      ida::exception::CatchSelectorKind::Cleanup);
            }
        }
    }
    auto in_cpp_try = ida::exception::contains(
        heads[0], ida::exception::Location::CppTry);
    CHECK(in_cpp_try.has_value() && *in_cpp_try);
    auto in_cpp_handler = ida::exception::contains(
        heads[3], ida::exception::Location::CppHandler);
    CHECK(in_cpp_handler.has_value() && *in_cpp_handler);
    CHECK(require_status(ida::exception::remove(scope),
                         "remove C++ exception block"));
    auto after_cpp = ida::exception::list(scope);
    CHECK(after_cpp.has_value() && find_block(*after_cpp, heads[0]) == nullptr);

    ida::exception::SehHandler seh_handler;
    seh_handler.metadata.regions = {{heads[3], heads[4]}};
    seh_handler.metadata.stack_displacement = 32;
    seh_handler.metadata.frame_register = 6;
    seh_handler.filter_regions = {{heads[4], heads[5]}};

    ida::exception::BlockDefinition seh_definition;
    seh_definition.protected_regions = {{heads[0], heads[2]}};
    seh_definition.handlers = seh_handler;
    CHECK(require_status(ida::exception::add(seh_definition),
                         "add filtered SEH block"));
    auto seh_blocks = ida::exception::list(scope);
    CHECK(require_result(seh_blocks, "list filtered SEH blocks"));
    const auto* seh_block = seh_blocks ? find_block(*seh_blocks, heads[0]) : nullptr;
    CHECK(seh_block != nullptr);
    if (seh_block != nullptr) {
        const auto* handler = std::get_if<ida::exception::SehHandler>(
            &seh_block->definition.handlers);
        CHECK(handler != nullptr);
        if (handler != nullptr) {
            CHECK(ranges_equal(handler->filter_regions,
                               seh_handler.filter_regions));
            CHECK(!handler->disposition.has_value());
            CHECK(handler->metadata.stack_displacement == 32);
            CHECK(handler->metadata.frame_register == 6);
        }
    }
    auto in_seh_try = ida::exception::contains(
        heads[0], ida::exception::Location::SehTry);
    CHECK(in_seh_try.has_value() && *in_seh_try);
    auto in_seh_handler = ida::exception::contains(
        heads[3], ida::exception::Location::SehHandler);
    CHECK(in_seh_handler.has_value() && *in_seh_handler);
    auto in_seh_filter = ida::exception::contains(
        heads[4], ida::exception::Location::SehFilter);
    CHECK(in_seh_filter.has_value() && *in_seh_filter);
    auto system_start = ida::exception::system_region_start(heads[0]);
    CHECK(system_start.has_value());

    CHECK(require_status(ida::exception::remove(scope),
                         "remove filtered SEH block"));

    seh_handler.filter_regions.clear();
    seh_handler.disposition = ida::exception::SehDisposition::ExecuteHandler;
    seh_definition.handlers = seh_handler;
    CHECK(require_status(ida::exception::add(seh_definition),
                         "add disposition SEH block"));
    auto disposition_blocks = ida::exception::list(scope);
    CHECK(require_result(disposition_blocks, "list disposition SEH block"));
    const auto* disposition_block = disposition_blocks
        ? find_block(*disposition_blocks, heads[0]) : nullptr;
    CHECK(disposition_block != nullptr);
    if (disposition_block != nullptr) {
        const auto* handler = std::get_if<ida::exception::SehHandler>(
            &disposition_block->definition.handlers);
        CHECK(handler != nullptr);
        if (handler != nullptr)
            CHECK(handler->disposition ==
                  ida::exception::SehDisposition::ExecuteHandler);
    }
    CHECK(require_status(ida::exception::remove(scope),
                         "remove disposition SEH block"));
    auto final_blocks = ida::exception::list(scope);
    CHECK(final_blocks.has_value() && find_block(*final_blocks, heads[0]) == nullptr);
    auto final_membership = ida::exception::contains(
        heads[0], ida::exception::Location::Any);
    CHECK(final_membership.has_value() && !*final_membership);

    require_status(ida::database::close(false), "database close");
    std::cout << "=== exception round trip: " << g_pass << " passed, "
              << g_fail << " failed ===\n";
    return g_fail == 0 ? 0 : 1;
}

#include "values_extra.h"
#include "support.hpp"
#include <ida/address.hpp>
#include <ida/diagnostics.hpp>
#include <ida/lumina.hpp>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <span>
#include <vector>

namespace {
template <typename T>
T* allocate_values(std::size_t count) {
    if (count > SIZE_MAX / sizeof(T)) throw std::bad_alloc();
    if (count == 0) return nullptr;
    auto* result = static_cast<T*>(std::malloc(count * sizeof(T)));
    if (!result) throw std::bad_alloc();
    return result;
}

std::span<const ida::Address> address_input(const uint64_t* addresses, size_t count) {
    if ((count != 0 && addresses == nullptr) || count > SIZE_MAX / sizeof(uint64_t))
        throw ida::Error::validation("Invalid address array extent");
    return {addresses, count};
}

int copy_batch(ida::Result<ida::lumina::BatchResult> result,
    IdaxSwiftLuminaBatchResult* output, IdaxSwiftError* error) {
    if (!result) return idax::swift::write_error(result.error(), error);
    auto* codes = allocate_values<int32_t>(result->codes.size());
    for (std::size_t index = 0; index < result->codes.size(); ++index)
        codes[index] = static_cast<int32_t>(result->codes[index]);
    *output = {result->requested, result->completed, result->succeeded,
        result->failed, codes, result->codes.size()};
    return 0;
}
}

extern "C" int idax_swift_address_collect(uint64_t start, uint64_t end, int predicate,
    uint64_t** output, size_t* count, IdaxSwiftError* error) {
    if (output) *output = nullptr;
    if (count) *count = 0;
    return idax::swift::protect(error, [&] {
        if (idax::swift::require_runtime_thread(error) != 0) return -1;
        if (!output || !count || predicate < 0 || predicate > 7)
            throw ida::Error::validation("Invalid address collection argument");
        std::vector<uint64_t> values;
        if (predicate == 7) {
            for (auto address : ida::address::items(start, end)) values.push_back(address);
        } else {
            for (auto address : ida::address::PredicateRange(start, end,
                static_cast<ida::address::Predicate>(predicate))) values.push_back(address);
        }
        auto* result = allocate_values<uint64_t>(values.size());
        if (!values.empty()) std::memcpy(result, values.data(), values.size() * sizeof(uint64_t));
        *output = result;
        *count = values.size();
        return 0;
    });
}

extern "C" int idax_swift_diagnostics_assert_invariant(int condition, const char* message,
    IdaxSwiftError* error) {
    return idax::swift::protect(error, [&] {
        if (idax::swift::require_runtime_thread(error) != 0) return -1;
        if (!message) throw ida::Error::validation("Invariant message is null");
        auto result = ida::diagnostics::assert_invariant(condition != 0, message);
        return result ? 0 : idax::swift::write_error(result.error(), error);
    });
}

extern "C" void idax_swift_lumina_batch_free(IdaxSwiftLuminaBatchResult* value) {
    if (!value) return;
    std::free(value->codes);
    *value = {};
}

extern "C" int idax_swift_lumina_pull(const uint64_t* addresses, size_t count,
    int auto_apply, int skip_frequency_update, int feature,
    IdaxSwiftLuminaBatchResult* output, IdaxSwiftError* error) {
    if (output) *output = {};
    return idax::swift::protect(error, [&] {
        if (idax::swift::require_runtime_thread(error) != 0) return -1;
        if (!output || feature < 0 || feature > 3)
            throw ida::Error::validation("Invalid Lumina pull argument");
        return copy_batch(ida::lumina::pull(address_input(addresses, count), auto_apply != 0,
            skip_frequency_update != 0, static_cast<ida::lumina::Feature>(feature)), output, error);
    });
}

extern "C" int idax_swift_lumina_push(const uint64_t* addresses, size_t count,
    int mode, int feature, IdaxSwiftLuminaBatchResult* output, IdaxSwiftError* error) {
    if (output) *output = {};
    return idax::swift::protect(error, [&] {
        if (idax::swift::require_runtime_thread(error) != 0) return -1;
        if (!output || feature < 0 || feature > 3 || mode < 0 || mode > 3)
            throw ida::Error::validation("Invalid Lumina push argument");
        return copy_batch(ida::lumina::push(address_input(addresses, count),
            static_cast<ida::lumina::PushMode>(mode), static_cast<ida::lumina::Feature>(feature)),
            output, error);
    });
}

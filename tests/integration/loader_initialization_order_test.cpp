// The target places src/loader.cpp before this translation unit on the link
// line. LDSC queries the loader's virtual options() during initialization;
// the registration must construct the object before publishing its address.
#include "../../src/detail/sdk_bridge.hpp"
#include <ida/loader.hpp>

#include <cstdio>
#include <cstdlib>

namespace {
int constructions = 0;
int option_queries = 0;

class InitializationOrderLoader final : public ida::loader::Loader {
    unsigned initialized_;

public:
    InitializationOrderLoader() : initialized_(0x1DAAu) { ++constructions; }

    ida::loader::LoaderOptions options() const override {
        if (initialized_ != 0x1DAAu)
            std::abort();
        ++option_queries;
        return {.supports_reload = true, .requires_processor = true};
    }

    ida::Result<std::optional<ida::loader::AcceptResult>>
    accept(ida::loader::InputFile&) override {
        return std::nullopt;
    }

    ida::Status load(ida::loader::InputFile&, std::string_view) override {
        return ida::ok();
    }
};
} // namespace

IDAX_LOADER(InitializationOrderLoader)

extern "C" loader_t LDSC;

int main() {
    void* first = nullptr;
    void* second = nullptr;
    void* ignored = nullptr;
    idax_loader_bridge_init(&first, &ignored);
    idax_loader_bridge_init(&second, &ignored);
    const bool passed = first != nullptr && first == second
        && constructions == 1 && option_queries == 1
        && LDSC.flags == (LDRF_RELOAD | LDRF_REQ_PROC);
    std::puts(passed ? "PASS: loader initialization precedes option dispatch"
                     : "FAIL: loader initialization order");
    return passed ? 0 : 1;
}

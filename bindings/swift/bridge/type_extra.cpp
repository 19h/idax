#include "type_extra.h"
#include "support.hpp"
#include <ida/type.hpp>

int idax_swift_type_default(void** output, IdaxSwiftError* error) {
    if (output) *output = nullptr;
    return idax::swift::protect(error, [&] {
        if (!output) return idax::swift::write_error(ida::Error::validation("Default type output is null"), error);
        if (idax::swift::require_runtime_thread(error)) return -1;
        *output = new ida::type::TypeInfo;
        return 0;
    });
}
int idax_swift_type_ensure_named(const char* name, const char* library, void** output, IdaxSwiftError* error) {
    if (output) *output = nullptr;
    return idax::swift::protect(error, [&] {
        if (!name || !library || !output) return idax::swift::write_error(ida::Error::validation("Named type input or output is null"), error);
        if (idax::swift::require_runtime_thread(error)) return -1;
        auto result = ida::type::ensure_named_type(name, library);
        if (!result) return idax::swift::write_error(result.error(), error);
        *output = new ida::type::TypeInfo(std::move(*result));
        return 0;
    });
}

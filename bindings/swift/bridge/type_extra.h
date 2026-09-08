#ifndef IDAX_SWIFT_TYPE_EXTRA_H
#define IDAX_SWIFT_TYPE_EXTRA_H
#include "bridge.h"
#ifdef __cplusplus
extern "C" {
#endif
int idax_swift_type_default(void** output, IdaxSwiftError* error);
int idax_swift_type_ensure_named(const char* name, const char* library, void** output, IdaxSwiftError* error);
#ifdef __cplusplus
}
#endif
#endif

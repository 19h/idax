#ifndef IDAX_SWIFT_VALUES_EXTRA_H
#define IDAX_SWIFT_VALUES_EXTRA_H
#include "bridge.h"
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

typedef struct IdaxSwiftLuminaBatchResult {
    size_t requested, completed, succeeded, failed;
    int32_t* codes;
    size_t code_count;
} IdaxSwiftLuminaBatchResult;

int idax_swift_address_collect(uint64_t start, uint64_t end, int predicate,
    uint64_t** output, size_t* count, IdaxSwiftError* error);
int idax_swift_diagnostics_assert_invariant(int condition, const char* message,
    IdaxSwiftError* error);
int idax_swift_lumina_pull(const uint64_t* addresses, size_t count, int auto_apply,
    int skip_frequency_update, int feature, IdaxSwiftLuminaBatchResult* output,
    IdaxSwiftError* error);
int idax_swift_lumina_push(const uint64_t* addresses, size_t count, int mode,
    int feature, IdaxSwiftLuminaBatchResult* output, IdaxSwiftError* error);
void idax_swift_lumina_batch_free(IdaxSwiftLuminaBatchResult* value);

#ifdef __cplusplus
}
#endif
#endif

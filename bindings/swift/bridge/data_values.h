#ifndef IDAX_SWIFT_DATA_VALUES_H
#define IDAX_SWIFT_DATA_VALUES_H

#include "bridge.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* All arrays are borrowed on input and owned on output. Strings are UTF-8
 * byte spans, so embedded NUL is preserved. Free output roots exactly once. */
typedef struct IdaxSwiftDataValue {
    int kind;
    uint64_t unsigned_value;
    int64_t signed_value;
    double floating_value;
    uint64_t pointer_value;
    const uint8_t* text;
    size_t text_count;
    const uint8_t* bytes;
    size_t byte_count;
    const struct IdaxSwiftDataValue* elements;
    size_t element_count;
} IdaxSwiftDataValue;

void idax_swift_data_value_free(IdaxSwiftDataValue* value);
int idax_swift_data_read_typed(uint64_t address, void* type, IdaxSwiftDataValue* output, IdaxSwiftError* error);
int idax_swift_data_write_typed(uint64_t address, void* type, const IdaxSwiftDataValue* value, IdaxSwiftError* error);
int idax_swift_data_read_string(uint64_t address, uint64_t maximum_length, int32_t string_type,
    int conversion_flags, uint8_t** bytes, size_t* count, IdaxSwiftError* error);
int idax_swift_data_find_binary_pattern(uint64_t start, uint64_t end, const char* pattern,
    int forward, int skip_start, int case_sensitive, int radix, int string_literal_encoding,
    uint64_t* output, IdaxSwiftError* error);

#ifdef __cplusplus
}
#endif
#endif

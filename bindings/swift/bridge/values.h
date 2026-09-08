#ifndef IDAX_SWIFT_VALUES_H
#define IDAX_SWIFT_VALUES_H
#include "bridge.h"
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
/* Only malloc-owned flat arrays from the canonical transport. */
void idax_swift_free_array(void* array);
typedef struct IdaxSwiftSearchOptions {
    int direction;
    int case_sensitive;
    int regex;
    int identifier;
    int skip_start;
    int no_break;
    int no_show;
    int break_on_cancel;
} IdaxSwiftSearchOptions;
int idax_swift_search_text(const char* query, uint64_t start, const IdaxSwiftSearchOptions* options, uint64_t* output, IdaxSwiftError* error);
int idax_swift_search_immediate(uint64_t value, uint64_t start, const IdaxSwiftSearchOptions* options, uint64_t* output, IdaxSwiftError* error);
int idax_swift_search_binary(const char* pattern, uint64_t start, const IdaxSwiftSearchOptions* options, uint64_t* output, IdaxSwiftError* error);

typedef struct IdaxSwiftTypeUsedOffsets {
    const char* type_name;
    const int32_t* byte_offsets;
    size_t offset_count;
} IdaxSwiftTypeUsedOffsets;
typedef struct IdaxSwiftTypeRenderOptions {
    int size_comments;
    int trim_unreferenced;
    const IdaxSwiftTypeUsedOffsets* used_offsets;
    size_t used_offset_count;
} IdaxSwiftTypeRenderOptions;
typedef struct IdaxSwiftTypeDeclaration {
    uint32_t ordinal;
    char* name;
    char* declaration;
} IdaxSwiftTypeDeclaration;
int idax_swift_type_render_named(const char* const* names, size_t count, int max_depth, const IdaxSwiftTypeRenderOptions* options, char** output, IdaxSwiftError* error);
int idax_swift_type_render_ordinals(const uint32_t* ordinals, size_t count, const IdaxSwiftTypeRenderOptions* options, char** output, IdaxSwiftError* error);
int idax_swift_type_render_graph(const char* name, int mode, int max_depth, int include_enums, int include_typedefs, char** output, IdaxSwiftError* error);
int idax_swift_type_declarations(const uint32_t* ordinals, size_t count, IdaxSwiftTypeDeclaration** output, size_t* output_count, IdaxSwiftError* error);
void idax_swift_type_declarations_free(IdaxSwiftTypeDeclaration* values, size_t count);
#ifdef __cplusplus
}
#endif
#endif

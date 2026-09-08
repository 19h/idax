#ifndef IDAX_SWIFT_DATA_CUSTOM_H
#define IDAX_SWIFT_DATA_CUSTOM_H
#include "bridge.h"
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

/* Identity fields are opaque generation tokens, never packed SDK IDs.
 * The type token zero denotes the canonical standard-type group. */
typedef struct IdaxSwiftCustomContext { uint64_t address; int operand_index; uint64_t type_id; } IdaxSwiftCustomContext;
typedef struct IdaxSwiftCustomRequest {
    int kind; /* 0: creation filter, 1: size, 2: render, 3: scan, 4: analyze */
    IdaxSwiftCustomContext context;
    uint64_t size;
    const uint8_t* bytes;
    size_t count;
} IdaxSwiftCustomRequest;
typedef struct IdaxSwiftCustomReply { uint64_t value; uint8_t* bytes; size_t count; } IdaxSwiftCustomReply;
typedef int (*IdaxSwiftCustomInvoke)(void*, const IdaxSwiftCustomRequest*, IdaxSwiftCustomReply*, IdaxSwiftError*);
typedef struct IdaxSwiftCustomCallbacks { void* context; IdaxSwiftCustomInvoke invoke; void (*destroy)(void*); } IdaxSwiftCustomCallbacks;
typedef struct IdaxSwiftCustomDefinition {
    const char* name;
    const char* menu_name;
    const char* hotkey;
    const char* assembler_keyword;
    uint64_t value_size;
    int text_width;
    int allow_duplicates;
    unsigned callback_flags; /* bit 0 filter, 1 size, 2 render, 3 scan, 4 analyze */
} IdaxSwiftCustomDefinition;
typedef struct IdaxSwiftCustomInfo {
    uint64_t id;
    char* name;
    char* menu_name;
    char* hotkey;
    char* assembler_keyword;
    uint64_t value_size;
    int text_width;
    unsigned flags; /* bit 0 duplicates, 1 visible, 2 filter, 3 variable, 4 render, 5 scan, 6 analyze */
} IdaxSwiftCustomInfo;

/* Registration consumes the callback context on success and every failure. */
int idax_swift_custom_register(int format, const IdaxSwiftCustomDefinition*, IdaxSwiftCustomCallbacks, void** registration, uint64_t* id, IdaxSwiftError*);
int idax_swift_custom_registration_close(void* registration, IdaxSwiftError*);
void idax_swift_custom_registration_free(void* registration);
int idax_swift_custom_reply_bytes(IdaxSwiftCustomReply*, const uint8_t*, size_t, IdaxSwiftError*);
int idax_swift_custom_unregister(int format, uint64_t id, IdaxSwiftError*);
int idax_swift_custom_find(int format, const char* name, uint64_t* id, IdaxSwiftError*);
int idax_swift_custom_info(int format, uint64_t id, IdaxSwiftCustomInfo*, IdaxSwiftError*);
int idax_swift_custom_list(int selector, uint64_t type_id, uint64_t minimum_size, uint64_t maximum_size, IdaxSwiftCustomInfo**, size_t*, IdaxSwiftError*);
void idax_swift_custom_info_free(IdaxSwiftCustomInfo*);
void idax_swift_custom_infos_free(IdaxSwiftCustomInfo*, size_t);
int idax_swift_custom_relation(int operation, uint64_t type_id, uint64_t format_id, int* result, IdaxSwiftError*);
int idax_swift_custom_item_size(uint64_t type_id, uint64_t address, uint64_t maximum_size, uint64_t* size, IdaxSwiftError*);
int idax_swift_custom_define(int inferred, uint64_t address, uint64_t size, uint64_t type_id, uint64_t format_id, IdaxSwiftError*);
int idax_swift_custom_at(uint64_t address, uint64_t* type_id, uint64_t* format_id, uint64_t* byte_length, IdaxSwiftError*);
int idax_swift_custom_render(uint64_t format_id, const uint8_t* bytes, size_t count, const IdaxSwiftCustomContext*, uint8_t** output, size_t* output_count, IdaxSwiftError*);
int idax_swift_custom_scan(uint64_t format_id, const uint8_t* text, size_t count, const IdaxSwiftCustomContext*, uint8_t** output, size_t* output_count, IdaxSwiftError*);
int idax_swift_custom_analyze(uint64_t format_id, const IdaxSwiftCustomContext*, IdaxSwiftError*);
#ifdef __cplusplus
}
#endif
#endif

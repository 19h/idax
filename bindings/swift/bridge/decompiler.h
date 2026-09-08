#ifndef IDAX_SWIFT_DECOMPILER_H
#define IDAX_SWIFT_DECOMPILER_H
#include "bridge.h"
#include "../../rust/idax-sys/shim/idax_shim.h"
#ifdef __cplusplus
extern "C" {
#endif
typedef struct IdaxSwiftDecompileFailure {
    uint64_t request_address;
    uint64_t failure_address;
    char* description;
} IdaxSwiftDecompileFailure;
typedef struct IdaxSwiftAddressMapping { uint64_t address; int line_number; } IdaxSwiftAddressMapping;
typedef struct IdaxSwiftLocalVariableSetting {
    int kind;
    int register_id;
    int64_t stack_offset;
    uint64_t definition_address;
    char* name;
    char* type_declaration;
    char* comment;
} IdaxSwiftLocalVariableSetting;
typedef struct IdaxSwiftUsedOffsets { char* type_name; int32_t* offsets; size_t count; } IdaxSwiftUsedOffsets;
typedef struct IdaxSwiftReferencedTypes {
    uint32_t* ordinals; size_t ordinal_count;
    IdaxSwiftUsedOffsets* used_offsets; size_t used_offset_count;
} IdaxSwiftReferencedTypes;
/* Owned decompiler values keep explicit Hex-Rays sessions alive. */
int idax_swift_decompiler_wrap(void* value, void (*destroy)(void*), void** output, IdaxSwiftError* error);
void* idax_swift_decompiler_unwrap(void* value);
void idax_swift_decompiler_owned_free(void* value);
void idax_swift_decompiler_dependency_acquire(void);
void idax_swift_decompiler_dependency_release(void);
int idax_swift_decompiler_initialize(void** output, IdaxSwiftError* error);
int idax_swift_decompiler_session_valid(void* value, int* output, IdaxSwiftError* error);
void idax_swift_decompiler_session_free(void* value);
int idax_swift_decompiler_session_close(void* value, IdaxSwiftError* error);
int idax_swift_decompile(uint64_t address, void** output, IdaxSwiftDecompileFailure* failure, IdaxSwiftError* error);
void idax_swift_decompile_failure_free(IdaxSwiftDecompileFailure* failure);
int idax_swift_decompiler_view(uint64_t address, int current, void** output, IdaxSwiftError* error);
void idax_swift_decompiler_view_free(void* view);
int idax_swift_decompiler_view_address(void* view, uint64_t* output, IdaxSwiftError* error);
int idax_swift_decompiled_retype(void* function, const char* name, size_t index, void* type, IdaxSwiftError* error);
int idax_swift_decompiled_refresh(void* function, IdaxSwiftError* error);
int idax_swift_decompiled_microcode_lines(void* function, char*** output, size_t* count, IdaxSwiftError* error);
int idax_swift_decompiled_address_map(void* function, IdaxSwiftAddressMapping** output, size_t* count, IdaxSwiftError* error);
int idax_swift_decompiler_saved_settings(uint64_t address, IdaxSwiftLocalVariableSetting** output, size_t* count, IdaxSwiftError* error);
void idax_swift_decompiler_settings_free(IdaxSwiftLocalVariableSetting* values, size_t count);
int idax_swift_decompiler_apply_settings(uint64_t address, const IdaxSwiftLocalVariableSetting* values, size_t count, IdaxSwiftError* error);
int idax_swift_decompiler_referenced_types(uint64_t address, IdaxSwiftReferencedTypes* output, IdaxSwiftError* error);
void idax_swift_decompiler_referenced_types_free(IdaxSwiftReferencedTypes* values);
int idax_swift_lvar_snapshot_copy(void* snapshot, void** output, IdaxSwiftError* error);
int idax_swift_lvar_snapshot_new(void** output, IdaxSwiftError* error);
/* Callback nodes retain only a lease and a copied opaque core view. */
typedef int (*IdaxSwiftTreeCallback)(void* context, int phase, int expression, void* node, int* action, IdaxSwiftError* error);
int idax_swift_decompiled_visit(void* function, int post_order, int track_parents, int expressions_only, void* context, IdaxSwiftTreeCallback callback, int* output, IdaxSwiftError* error);
void idax_swift_tree_node_free(void* node);
int idax_swift_tree_info(void* node, IdaxDecompilerCtreeItemInfo* output, IdaxSwiftError* error);
int idax_swift_tree_scalar(void* node, int property, size_t index, uint64_t* output, IdaxSwiftError* error);
int idax_swift_tree_string(void* node, int property, char** output, IdaxSwiftError* error);
int idax_swift_tree_child(void* node, int property, size_t index, void** output, IdaxSwiftError* error);
int idax_swift_tree_parents(void* node, IdaxDecompilerCtreeItemInfo** output, size_t* count, IdaxSwiftError* error);
int idax_swift_tree_switch_values(void* node, size_t index, uint64_t** output, size_t* count, IdaxSwiftError* error);
#ifdef __cplusplus
}
#endif
#endif

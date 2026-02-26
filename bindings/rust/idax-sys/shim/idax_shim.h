/**
 * @file idax_shim.h
 * @brief C shim declarations for the idax C++ IDA SDK wrapper library.
 *
 * This header declares extern "C" functions covering all 27 idax namespaces.
 * It is consumed by bindgen to produce Rust FFI bindings.
 *
 * Error convention:
 *   - Functions returning int: 0 = success, negative = error.
 *   - Error details are stored in thread-local state accessible via
 *     idax_last_error_category() / idax_last_error_code() / idax_last_error_message().
 *   - Strings returned via char** output params are malloc'd; free with idax_free_string().
 *   - Arrays returned via pointer+count output params are malloc'd; free with free().
 *   - Opaque handles (void*) must be freed with their corresponding _free function.
 *   - Boolean query functions return 1=true, 0=false (never negative).
 */

#ifndef IDAX_SHIM_H
#define IDAX_SHIM_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ═══════════════════════════════════════════════════════════════════════════
 * Error category constants (matching ida::ErrorCategory)
 * ═══════════════════════════════════════════════════════════════════════════ */

#define IDAX_ERROR_NONE         0
#define IDAX_ERROR_VALIDATION   1
#define IDAX_ERROR_NOT_FOUND    2
#define IDAX_ERROR_CONFLICT     3
#define IDAX_ERROR_UNSUPPORTED  4
#define IDAX_ERROR_SDK_FAILURE  5
#define IDAX_ERROR_INTERNAL     6

/* ═══════════════════════════════════════════════════════════════════════════
 * Error handling
 * ═══════════════════════════════════════════════════════════════════════════ */

/** Get the error category from the last failed call (thread-local). */
int idax_last_error_category(void);

/** Get the error code from the last failed call (thread-local). */
int idax_last_error_code(void);

/** Get the error message from the last failed call (thread-local).
 *  Returns a pointer to a thread-local buffer. Do NOT free. */
const char* idax_last_error_message(void);

/** Free a malloc'd string returned by an idax function. */
void idax_free_string(char* s);

/** Free a malloc'd byte array returned by an idax function. */
void idax_free_bytes(uint8_t* p);

/** Free a malloc'd uint64 array returned by an idax function. */
void idax_free_addresses(uint64_t* p);

/* ═══════════════════════════════════════════════════════════════════════════
 * Database (ida::database)
 * ═══════════════════════════════════════════════════════════════════════════ */

int idax_database_init(int argc, char** argv);
int idax_database_open(const char* path, int auto_analysis);
int idax_database_open_binary(const char* path, int mode);
int idax_database_open_non_binary(const char* path, int mode);
int idax_database_save(void);
int idax_database_close(int save);

int idax_database_file_to_database(const char* file_path, int64_t file_offset,
                                   uint64_t ea, uint64_t size,
                                   int patchable, int remote);
int idax_database_memory_to_database(const uint8_t* bytes, size_t len,
                                     uint64_t ea, int64_t file_offset);

typedef struct IdaxDatabaseCompilerInfo {
    uint32_t id;
    int      uncertain;
    char*    name;
    char*    abbreviation;
} IdaxDatabaseCompilerInfo;

int idax_database_compiler_info(IdaxDatabaseCompilerInfo* out);
void idax_database_compiler_info_free(IdaxDatabaseCompilerInfo* info);

typedef struct IdaxDatabaseImportSymbol {
    uint64_t address;
    char*    name;
    uint64_t ordinal;
} IdaxDatabaseImportSymbol;

typedef struct IdaxDatabaseImportModule {
    size_t                    index;
    char*                     name;
    IdaxDatabaseImportSymbol* symbols;
    size_t                    symbol_count;
} IdaxDatabaseImportModule;

int idax_database_import_modules(IdaxDatabaseImportModule** out, size_t* count);
void idax_database_import_modules_free(IdaxDatabaseImportModule* modules,
                                       size_t count);

typedef struct IdaxDatabaseSnapshot {
    int64_t id;
    uint16_t flags;
    char* description;
    char* filename;
    struct IdaxDatabaseSnapshot* children;
    size_t child_count;
} IdaxDatabaseSnapshot;

int idax_database_snapshots(IdaxDatabaseSnapshot** out, size_t* count);
void idax_database_snapshots_free(IdaxDatabaseSnapshot* snapshots, size_t count);
int idax_database_set_snapshot_description(const char* description);
int idax_database_is_snapshot_database(int* out);

int idax_database_input_file_path(char** out);
int idax_database_file_type_name(char** out);
int idax_database_loader_format_name(char** out);
int idax_database_input_md5(char** out);
int idax_database_image_base(uint64_t* out);
int idax_database_min_address(uint64_t* out);
int idax_database_max_address(uint64_t* out);
int idax_database_processor_id(int32_t* out);
int idax_database_processor_name(char** out);
int idax_database_address_bitness(int* out);
int idax_database_is_big_endian(int* out);
int idax_database_abi_name(char** out);
int idax_database_address_span(uint64_t* out);

/* ═══════════════════════════════════════════════════════════════════════════
 * Address (ida::address)
 * ═══════════════════════════════════════════════════════════════════════════ */

/* Predicates — return 1=true, 0=false */
int idax_address_is_mapped(uint64_t ea);
int idax_address_is_loaded(uint64_t ea);
int idax_address_is_code(uint64_t ea);
int idax_address_is_data(uint64_t ea);
int idax_address_is_unknown(uint64_t ea);
int idax_address_is_head(uint64_t ea);
int idax_address_is_tail(uint64_t ea);

/* Navigation */
int idax_address_item_start(uint64_t ea, uint64_t* out);
int idax_address_item_end(uint64_t ea, uint64_t* out);
int idax_address_item_size(uint64_t ea, uint64_t* out);
int idax_address_next_head(uint64_t ea, uint64_t limit, uint64_t* out);
int idax_address_prev_head(uint64_t ea, uint64_t limit, uint64_t* out);
int idax_address_next_not_tail(uint64_t ea, uint64_t* out);
int idax_address_prev_not_tail(uint64_t ea, uint64_t* out);
int idax_address_next_mapped(uint64_t ea, uint64_t* out);
int idax_address_prev_mapped(uint64_t ea, uint64_t* out);
int idax_address_find_first(uint64_t start, uint64_t end, int predicate,
                            uint64_t* out);
int idax_address_find_next(uint64_t ea, int predicate, uint64_t end,
                           uint64_t* out);

/* ═══════════════════════════════════════════════════════════════════════════
 * Segment (ida::segment)
 * ═══════════════════════════════════════════════════════════════════════════ */

/** Flat C representation of a segment snapshot. */
typedef struct IdaxSegment {
    uint64_t start;
    uint64_t end;
    int      bitness;
    int      type;         /**< ida::segment::Type enum as int */
    int      perm_read;
    int      perm_write;
    int      perm_exec;
    char*    name;         /**< malloc'd, free with idax_free_string */
    char*    class_name;   /**< malloc'd, free with idax_free_string */
    int      visible;
} IdaxSegment;

/** Free strings inside an IdaxSegment (does NOT free the struct itself). */
void idax_segment_free(IdaxSegment* seg);

int idax_segment_at(uint64_t ea, IdaxSegment* out);
int idax_segment_by_name(const char* name, IdaxSegment* out);
int idax_segment_by_index(size_t index, IdaxSegment* out);
int idax_segment_count(size_t* out);
int idax_segment_create(uint64_t start, uint64_t end, const char* name,
                        const char* class_name, int type);
int idax_segment_remove(uint64_t ea);
int idax_segment_set_name(uint64_t ea, const char* name);
int idax_segment_set_class(uint64_t ea, const char* class_name);
int idax_segment_set_type(uint64_t ea, int type);
int idax_segment_set_permissions(uint64_t ea, int read, int write, int exec);
int idax_segment_set_bitness(uint64_t ea, int bits);
int idax_segment_comment(uint64_t ea, int repeatable, char** out);
int idax_segment_set_comment(uint64_t ea, const char* text, int repeatable);
int idax_segment_resize(uint64_t ea, uint64_t new_start, uint64_t new_end);
int idax_segment_move(uint64_t ea, uint64_t new_start);
int idax_segment_next(uint64_t ea, IdaxSegment* out);
int idax_segment_prev(uint64_t ea, IdaxSegment* out);
int idax_segment_set_default_segment_register(uint64_t ea, int register_index,
                                              uint64_t value);
int idax_segment_set_default_segment_register_for_all(int register_index,
                                                      uint64_t value);

/* ═══════════════════════════════════════════════════════════════════════════
 * Function (ida::function)
 * ═══════════════════════════════════════════════════════════════════════════ */

/** Flat C representation of a function snapshot. */
typedef struct IdaxFunction {
    uint64_t start;
    uint64_t end;
    char*    name;         /**< malloc'd, free with idax_free_string */
    int      bitness;
    int      returns;
    int      is_library;
    int      is_thunk;
    int      is_visible;
    uint64_t frame_local_size;
    uint64_t frame_regs_size;
    uint64_t frame_args_size;
} IdaxFunction;

/** Free strings inside an IdaxFunction. */
void idax_function_free(IdaxFunction* func);

int idax_function_at(uint64_t ea, IdaxFunction* out);
int idax_function_by_index(size_t index, IdaxFunction* out);
int idax_function_count(size_t* out);
int idax_function_create(uint64_t start, uint64_t end, IdaxFunction* out);
int idax_function_remove(uint64_t ea);
int idax_function_name_at(uint64_t ea, char** out);
int idax_function_set_start(uint64_t ea, uint64_t new_start);
int idax_function_set_end(uint64_t ea, uint64_t new_end);
int idax_function_update(uint64_t ea);
int idax_function_reanalyze(uint64_t ea);
int idax_function_comment(uint64_t ea, int repeatable, char** out);
int idax_function_set_comment(uint64_t ea, const char* text, int repeatable);
int idax_function_callers(uint64_t ea, uint64_t** out, size_t* count);
int idax_function_callees(uint64_t ea, uint64_t** out, size_t* count);
int idax_function_is_outlined(uint64_t ea, int* out);
int idax_function_set_outlined(uint64_t ea, int outlined);

/** Chunk descriptor. */
typedef struct IdaxChunk {
    uint64_t start;
    uint64_t end;
    int      is_tail;
    uint64_t owner;
} IdaxChunk;

int idax_function_chunks(uint64_t ea, IdaxChunk** out, size_t* count);
int idax_function_chunk_count(uint64_t ea, size_t* out);
int idax_function_add_tail(uint64_t func_ea, uint64_t tail_start, uint64_t tail_end);
int idax_function_remove_tail(uint64_t func_ea, uint64_t tail_ea);

/** Stack frame variable. */
typedef struct IdaxFrameVariable {
    char*    name;
    size_t   byte_offset;
    size_t   byte_size;
    char*    comment;
    int      is_special;
} IdaxFrameVariable;

void idax_frame_variable_free(IdaxFrameVariable* var);

typedef struct IdaxRegisterVariable {
    uint64_t range_start;
    uint64_t range_end;
    char*    canonical_name;
    char*    user_name;
    char*    comment;
} IdaxRegisterVariable;

void idax_register_variable_free(IdaxRegisterVariable* var);
void idax_register_variables_free(IdaxRegisterVariable* vars, size_t count);

typedef struct IdaxStackFrame {
    uint64_t local_variables_size;
    uint64_t saved_registers_size;
    uint64_t arguments_size;
    uint64_t total_size;
    IdaxFrameVariable* variables;
    size_t   variable_count;
} IdaxStackFrame;

void idax_stack_frame_free(IdaxStackFrame* frame);

int idax_function_frame(uint64_t ea, IdaxStackFrame* out);
int idax_function_sp_delta_at(uint64_t ea, int64_t* out);
int idax_function_frame_variable_by_name(uint64_t ea, const char* name,
                                         IdaxFrameVariable* out);
int idax_function_frame_variable_by_offset(uint64_t ea, size_t byte_offset,
                                           IdaxFrameVariable* out);
int idax_function_define_stack_variable(uint64_t function_ea,
                                        const char* name,
                                        int32_t frame_offset,
                                        void* type);
int idax_function_add_register_variable(uint64_t function_ea,
                                        uint64_t range_start,
                                        uint64_t range_end,
                                        const char* register_name,
                                        const char* user_name,
                                        const char* comment);
int idax_function_find_register_variable(uint64_t function_ea,
                                         uint64_t ea,
                                         const char* register_name,
                                         IdaxRegisterVariable* out);
int idax_function_remove_register_variable(uint64_t function_ea,
                                           uint64_t range_start,
                                           uint64_t range_end,
                                           const char* register_name);
int idax_function_rename_register_variable(uint64_t function_ea,
                                           uint64_t ea,
                                           const char* register_name,
                                           const char* new_user_name);
int idax_function_has_register_variables(uint64_t function_ea,
                                         uint64_t ea,
                                         int* out);
int idax_function_register_variables(uint64_t function_ea,
                                     IdaxRegisterVariable** out,
                                     size_t* count);
int idax_function_item_addresses(uint64_t ea, uint64_t** out, size_t* count);
int idax_function_code_addresses(uint64_t ea, uint64_t** out, size_t* count);

/* ═══════════════════════════════════════════════════════════════════════════
 * Instruction (ida::instruction)
 * ═══════════════════════════════════════════════════════════════════════════ */

/** Flat C representation of an instruction operand. */
typedef struct IdaxOperand {
    int      index;
    int      type;           /**< ida::instruction::OperandType as int */
    uint16_t register_id;
    uint64_t value;
    uint64_t target_address;
    int      byte_width;
    char*    register_name;  /**< malloc'd */
    int      register_category; /**< ida::instruction::RegisterCategory as int */
} IdaxOperand;

/** Flat C representation of a decoded instruction. */
typedef struct IdaxInstruction {
    uint64_t     address;
    uint64_t     size;
    uint16_t     opcode;
    char*        mnemonic;     /**< malloc'd */
    IdaxOperand* operands;     /**< malloc'd array */
    size_t       operand_count;
} IdaxInstruction;

/** Free all malloc'd fields inside an IdaxInstruction. */
void idax_instruction_free(IdaxInstruction* insn);

int idax_instruction_decode(uint64_t ea, IdaxInstruction* out);
int idax_instruction_create(uint64_t ea, IdaxInstruction* out);
int idax_instruction_text(uint64_t ea, char** out);

/* Operand representation controls */
int idax_instruction_set_operand_hex(uint64_t ea, int n);
int idax_instruction_set_operand_decimal(uint64_t ea, int n);
int idax_instruction_set_operand_octal(uint64_t ea, int n);
int idax_instruction_set_operand_binary(uint64_t ea, int n);
int idax_instruction_set_operand_character(uint64_t ea, int n);
int idax_instruction_set_operand_float(uint64_t ea, int n);
int idax_instruction_set_operand_format(uint64_t ea, int n, int format,
                                        uint64_t base);
int idax_instruction_set_operand_offset(uint64_t ea, int n, uint64_t base);
int idax_instruction_set_operand_struct_offset_by_name(uint64_t ea, int n,
                                                       const char* structure_name,
                                                       int64_t delta);
int idax_instruction_set_operand_struct_offset_by_id(uint64_t ea, int n,
                                                     uint64_t structure_id,
                                                     int64_t delta);
int idax_instruction_set_operand_based_struct_offset(uint64_t ea, int n,
                                                     uint64_t operand_value,
                                                     uint64_t base);
int idax_instruction_operand_struct_offset_path(uint64_t ea, int n,
                                                uint64_t** out_ids,
                                                size_t* out_count,
                                                int64_t* out_delta);
int idax_instruction_operand_struct_offset_path_names(uint64_t ea, int n,
                                                      char*** out,
                                                      size_t* count);
void idax_instruction_string_array_free(char** values, size_t count);
int idax_instruction_set_operand_stack_variable(uint64_t ea, int n);
int idax_instruction_clear_operand_representation(uint64_t ea, int n);
int idax_instruction_set_forced_operand(uint64_t ea, int n, const char* text);
int idax_instruction_get_forced_operand(uint64_t ea, int n, char** out);
int idax_instruction_operand_text(uint64_t ea, int n, char** out);
int idax_instruction_operand_byte_width(uint64_t ea, int n, int* out);
int idax_instruction_operand_register_name(uint64_t ea, int n, char** out);
int idax_instruction_operand_register_category(uint64_t ea, int n, int* out);
int idax_instruction_toggle_operand_sign(uint64_t ea, int n);
int idax_instruction_toggle_operand_negate(uint64_t ea, int n);

/* Instruction-level xref conveniences */
int idax_instruction_code_refs_from(uint64_t ea, uint64_t** out, size_t* count);
int idax_instruction_data_refs_from(uint64_t ea, uint64_t** out, size_t* count);
int idax_instruction_call_targets(uint64_t ea, uint64_t** out, size_t* count);
int idax_instruction_jump_targets(uint64_t ea, uint64_t** out, size_t* count);
int idax_instruction_has_fall_through(uint64_t ea);
int idax_instruction_is_call(uint64_t ea);
int idax_instruction_is_return(uint64_t ea);
int idax_instruction_is_jump(uint64_t ea);
int idax_instruction_is_conditional_jump(uint64_t ea);
int idax_instruction_next(uint64_t ea, IdaxInstruction* out);
int idax_instruction_prev(uint64_t ea, IdaxInstruction* out);

/* ═══════════════════════════════════════════════════════════════════════════
 * Data (ida::data)
 * ═══════════════════════════════════════════════════════════════════════════ */

int idax_data_read_byte(uint64_t ea, uint8_t* out);
int idax_data_read_word(uint64_t ea, uint16_t* out);
int idax_data_read_dword(uint64_t ea, uint32_t* out);
int idax_data_read_qword(uint64_t ea, uint64_t* out);
int idax_data_read_bytes(uint64_t ea, uint64_t count, uint8_t** out, size_t* out_len);
int idax_data_read_string(uint64_t ea, uint64_t max_len, char** out);

typedef enum IdaxDataTypedValueKind {
    IDAX_DATA_TYPED_UNSIGNED_INTEGER = 0,
    IDAX_DATA_TYPED_SIGNED_INTEGER = 1,
    IDAX_DATA_TYPED_FLOATING_POINT = 2,
    IDAX_DATA_TYPED_POINTER = 3,
    IDAX_DATA_TYPED_STRING = 4,
    IDAX_DATA_TYPED_BYTES = 5,
    IDAX_DATA_TYPED_ARRAY = 6,
} IdaxDataTypedValueKind;

typedef struct IdaxDataTypedValue {
    int kind;
    uint64_t unsigned_value;
    int64_t signed_value;
    double floating_value;
    uint64_t pointer_value;
    char* string_value;
    uint8_t* bytes;
    size_t byte_count;
    struct IdaxDataTypedValue* elements;
    size_t element_count;
} IdaxDataTypedValue;

int idax_data_read_typed(uint64_t ea, void* type, IdaxDataTypedValue* out);
int idax_data_write_typed(uint64_t ea, void* type, const IdaxDataTypedValue* value);
void idax_data_typed_value_free(IdaxDataTypedValue* value);

int idax_data_write_byte(uint64_t ea, uint8_t value);
int idax_data_write_word(uint64_t ea, uint16_t value);
int idax_data_write_dword(uint64_t ea, uint32_t value);
int idax_data_write_qword(uint64_t ea, uint64_t value);
int idax_data_write_bytes(uint64_t ea, const uint8_t* data, size_t len);

int idax_data_patch_byte(uint64_t ea, uint8_t value);
int idax_data_patch_word(uint64_t ea, uint16_t value);
int idax_data_patch_dword(uint64_t ea, uint32_t value);
int idax_data_patch_qword(uint64_t ea, uint64_t value);
int idax_data_patch_bytes(uint64_t ea, const uint8_t* data, size_t len);

int idax_data_revert_patch(uint64_t ea);
int idax_data_revert_patches(uint64_t ea, uint64_t count, uint64_t* reverted);

int idax_data_original_byte(uint64_t ea, uint8_t* out);
int idax_data_original_word(uint64_t ea, uint16_t* out);
int idax_data_original_dword(uint64_t ea, uint32_t* out);
int idax_data_original_qword(uint64_t ea, uint64_t* out);

int idax_data_define_byte(uint64_t ea, uint64_t count);
int idax_data_define_word(uint64_t ea, uint64_t count);
int idax_data_define_dword(uint64_t ea, uint64_t count);
int idax_data_define_qword(uint64_t ea, uint64_t count);
int idax_data_define_oword(uint64_t ea, uint64_t count);
int idax_data_define_tbyte(uint64_t ea, uint64_t count);
int idax_data_define_float(uint64_t ea, uint64_t count);
int idax_data_define_double(uint64_t ea, uint64_t count);
int idax_data_define_string(uint64_t ea, uint64_t length, int32_t string_type);
int idax_data_define_struct(uint64_t ea, uint64_t length, uint64_t structure_id);
int idax_data_undefine(uint64_t ea, uint64_t count);

int idax_data_find_binary_pattern(uint64_t start, uint64_t end,
                                  const char* pattern, int forward,
                                  uint64_t* out);

/* ═══════════════════════════════════════════════════════════════════════════
 * Name (ida::name)
 * ═══════════════════════════════════════════════════════════════════════════ */

int idax_name_get(uint64_t ea, char** out);
int idax_name_set(uint64_t ea, const char* name);
int idax_name_force_set(uint64_t ea, const char* name);
int idax_name_remove(uint64_t ea);
int idax_name_demangled(uint64_t ea, int form, char** out);
int idax_name_resolve(const char* name, uint64_t context, uint64_t* out);

typedef struct IdaxNameEntry {
    uint64_t address;
    char*    name;
    int      user_defined;
    int      auto_generated;
} IdaxNameEntry;

int idax_name_all_user_defined(uint64_t start, uint64_t end,
                               IdaxNameEntry** out, size_t* count);
void idax_name_entries_free(IdaxNameEntry* entries, size_t count);

int idax_name_is_public(uint64_t ea);
int idax_name_is_weak(uint64_t ea);
int idax_name_is_user_defined(uint64_t ea);
int idax_name_is_auto_generated(uint64_t ea);
int idax_name_is_valid_identifier(const char* text, int* out);
int idax_name_sanitize_identifier(const char* text, char** out);

int idax_name_set_public(uint64_t ea, int value);
int idax_name_set_weak(uint64_t ea, int value);

/* ═══════════════════════════════════════════════════════════════════════════
 * Xref (ida::xref)
 * ═══════════════════════════════════════════════════════════════════════════ */

/** Flat C representation of a cross-reference. */
typedef struct IdaxXref {
    uint64_t from;
    uint64_t to;
    int      is_code;
    int      type;           /**< ida::xref::ReferenceType as int */
    int      user_defined;
} IdaxXref;

int idax_xref_refs_from(uint64_t ea, IdaxXref** out, size_t* count);
int idax_xref_refs_to(uint64_t ea, IdaxXref** out, size_t* count);
int idax_xref_code_refs_from(uint64_t ea, uint64_t** out, size_t* count);
int idax_xref_code_refs_to(uint64_t ea, uint64_t** out, size_t* count);
int idax_xref_data_refs_from(uint64_t ea, uint64_t** out, size_t* count);
int idax_xref_data_refs_to(uint64_t ea, uint64_t** out, size_t* count);
int idax_xref_refs_from_range(uint64_t ea, IdaxXref** out, size_t* count);
int idax_xref_refs_to_range(uint64_t ea, IdaxXref** out, size_t* count);
int idax_xref_code_refs_from_range(uint64_t ea, uint64_t** out, size_t* count);
int idax_xref_code_refs_to_range(uint64_t ea, uint64_t** out, size_t* count);
int idax_xref_data_refs_from_range(uint64_t ea, uint64_t** out, size_t* count);
int idax_xref_data_refs_to_range(uint64_t ea, uint64_t** out, size_t* count);

int idax_xref_add_code(uint64_t from, uint64_t to, int type);
int idax_xref_add_data(uint64_t from, uint64_t to, int type);
int idax_xref_remove_code(uint64_t from, uint64_t to);
int idax_xref_remove_data(uint64_t from, uint64_t to);

/* ═══════════════════════════════════════════════════════════════════════════
 * Comment (ida::comment)
 * ═══════════════════════════════════════════════════════════════════════════ */

int idax_comment_get(uint64_t ea, int repeatable, char** out);
int idax_comment_set(uint64_t ea, const char* text, int repeatable);
int idax_comment_append(uint64_t ea, const char* text, int repeatable);
int idax_comment_remove(uint64_t ea, int repeatable);

int idax_comment_add_anterior(uint64_t ea, const char* text);
int idax_comment_add_posterior(uint64_t ea, const char* text);
int idax_comment_get_anterior(uint64_t ea, int line_index, char** out);
int idax_comment_get_posterior(uint64_t ea, int line_index, char** out);
int idax_comment_set_anterior(uint64_t ea, int line_index, const char* text);
int idax_comment_set_posterior(uint64_t ea, int line_index, const char* text);
int idax_comment_clear_anterior(uint64_t ea);
int idax_comment_clear_posterior(uint64_t ea);
int idax_comment_remove_anterior_line(uint64_t ea, int line_index);
int idax_comment_remove_posterior_line(uint64_t ea, int line_index);
int idax_comment_set_anterior_lines(uint64_t ea, const char* const* lines,
                                    size_t count);
int idax_comment_set_posterior_lines(uint64_t ea, const char* const* lines,
                                     size_t count);
int idax_comment_anterior_lines(uint64_t ea, char*** out, size_t* count);
int idax_comment_posterior_lines(uint64_t ea, char*** out, size_t* count);
void idax_comment_lines_free(char** lines, size_t count);
int idax_comment_render(uint64_t ea, int include_repeatable,
                        int include_extra_lines, char** out);

/* ═══════════════════════════════════════════════════════════════════════════
 * Search (ida::search)
 * ═══════════════════════════════════════════════════════════════════════════ */

int idax_search_text(const char* query, uint64_t start, int forward,
                     int case_sensitive, uint64_t* out);
int idax_search_binary_pattern(const char* hex, uint64_t start, int forward,
                               uint64_t* out);
int idax_search_immediate(uint64_t value, uint64_t start, int forward,
                          uint64_t* out);
int idax_search_next_code(uint64_t ea, uint64_t* out);
int idax_search_next_data(uint64_t ea, uint64_t* out);
int idax_search_next_unknown(uint64_t ea, uint64_t* out);
int idax_search_next_error(uint64_t ea, uint64_t* out);
int idax_search_next_defined(uint64_t ea, uint64_t* out);

/* ═══════════════════════════════════════════════════════════════════════════
 * Analysis (ida::analysis)
 * ═══════════════════════════════════════════════════════════════════════════ */

int idax_analysis_is_enabled(void);
int idax_analysis_set_enabled(int enabled);
int idax_analysis_is_idle(void);
int idax_analysis_wait(void);
int idax_analysis_wait_range(uint64_t start, uint64_t end);
int idax_analysis_schedule(uint64_t ea);
int idax_analysis_schedule_range(uint64_t start, uint64_t end);
int idax_analysis_schedule_code(uint64_t ea);
int idax_analysis_schedule_function(uint64_t ea);
int idax_analysis_schedule_reanalysis(uint64_t ea);
int idax_analysis_schedule_reanalysis_range(uint64_t start, uint64_t end);
int idax_analysis_cancel(uint64_t start, uint64_t end);
int idax_analysis_revert_decisions(uint64_t start, uint64_t end);

/* ═══════════════════════════════════════════════════════════════════════════
 * Type (ida::type)
 * ═══════════════════════════════════════════════════════════════════════════ */

/** Opaque type handle. Must be freed with idax_type_free(). */
typedef void* IdaxTypeHandle;

typedef struct IdaxTypeEnumMemberInput {
    const char* name;
    uint64_t    value;
    const char* comment;
} IdaxTypeEnumMemberInput;

typedef struct IdaxTypeEnumMember {
    char*    name;
    uint64_t value;
    char*    comment;
} IdaxTypeEnumMember;

typedef struct IdaxTypeMember {
    char*          name;
    IdaxTypeHandle type;
    size_t         byte_offset;
    size_t         bit_size;
    char*          comment;
} IdaxTypeMember;

IdaxTypeHandle idax_type_void(void);
IdaxTypeHandle idax_type_int8(void);
IdaxTypeHandle idax_type_int16(void);
IdaxTypeHandle idax_type_int32(void);
IdaxTypeHandle idax_type_int64(void);
IdaxTypeHandle idax_type_uint8(void);
IdaxTypeHandle idax_type_uint16(void);
IdaxTypeHandle idax_type_uint32(void);
IdaxTypeHandle idax_type_uint64(void);
IdaxTypeHandle idax_type_float32(void);
IdaxTypeHandle idax_type_float64(void);
IdaxTypeHandle idax_type_pointer_to(IdaxTypeHandle target);
IdaxTypeHandle idax_type_array_of(IdaxTypeHandle element, size_t count);
IdaxTypeHandle idax_type_create_struct(void);
IdaxTypeHandle idax_type_create_union(void);

void idax_type_free(IdaxTypeHandle ti);
int idax_type_clone(IdaxTypeHandle ti, IdaxTypeHandle* out);

int idax_type_function_type(IdaxTypeHandle return_type,
                            const IdaxTypeHandle* argument_types,
                            size_t argument_count,
                            int calling_convention,
                            int has_varargs,
                            IdaxTypeHandle* out);
int idax_type_enum_type(const IdaxTypeEnumMemberInput* members,
                        size_t member_count,
                        size_t byte_width,
                        int bitmask,
                        IdaxTypeHandle* out);

int idax_type_is_void(IdaxTypeHandle ti);
int idax_type_is_integer(IdaxTypeHandle ti);
int idax_type_is_floating_point(IdaxTypeHandle ti);
int idax_type_is_pointer(IdaxTypeHandle ti);
int idax_type_is_array(IdaxTypeHandle ti);
int idax_type_is_function(IdaxTypeHandle ti);
int idax_type_is_struct(IdaxTypeHandle ti);
int idax_type_is_union(IdaxTypeHandle ti);
int idax_type_is_enum(IdaxTypeHandle ti);
int idax_type_is_typedef(IdaxTypeHandle ti);

int idax_type_size(IdaxTypeHandle ti, size_t* out);
int idax_type_to_string(IdaxTypeHandle ti, char** out);
int idax_type_pointee_type(IdaxTypeHandle ti, IdaxTypeHandle* out);
int idax_type_array_element_type(IdaxTypeHandle ti, IdaxTypeHandle* out);
int idax_type_array_length(IdaxTypeHandle ti, size_t* out);
int idax_type_resolve_typedef(IdaxTypeHandle ti, IdaxTypeHandle* out);
int idax_type_function_return_type(IdaxTypeHandle ti, IdaxTypeHandle* out);
int idax_type_function_argument_types(IdaxTypeHandle ti,
                                      IdaxTypeHandle** out,
                                      size_t* count);
int idax_type_calling_convention(IdaxTypeHandle ti, int* out);
int idax_type_is_variadic_function(IdaxTypeHandle ti, int* out);
int idax_type_enum_members(IdaxTypeHandle ti, IdaxTypeEnumMember** out,
                           size_t* count);
int idax_type_by_name(const char* name, IdaxTypeHandle* out);
int idax_type_from_declaration(const char* c_decl, IdaxTypeHandle* out);

int idax_type_apply(IdaxTypeHandle ti, uint64_t ea);
int idax_type_save_as(IdaxTypeHandle ti, const char* name);
int idax_type_retrieve(uint64_t ea, IdaxTypeHandle* out);
int idax_type_retrieve_operand(uint64_t ea, int operand_index, IdaxTypeHandle* out);
int idax_type_remove(uint64_t ea);

int idax_type_member_count(IdaxTypeHandle ti, size_t* out);
int idax_type_members(IdaxTypeHandle ti, IdaxTypeMember** out, size_t* count);
int idax_type_member_by_name(IdaxTypeHandle ti, const char* name, IdaxTypeMember* out);
int idax_type_member_by_offset(IdaxTypeHandle ti, size_t byte_offset, IdaxTypeMember* out);
int idax_type_add_member(IdaxTypeHandle ti, const char* name,
                         IdaxTypeHandle member_type, size_t byte_offset);

int idax_type_load_library(const char* til_name, int* out);
int idax_type_unload_library(const char* til_name);
int idax_type_local_type_count(size_t* out);
int idax_type_local_type_name(size_t ordinal, char** out);
int idax_type_import(const char* source_til_name, const char* type_name, size_t* out);
int idax_type_apply_named(uint64_t ea, const char* type_name);

void idax_type_handle_array_free(IdaxTypeHandle* handles, size_t count);
void idax_type_enum_members_free(IdaxTypeEnumMember* members, size_t count);
void idax_type_member_free(IdaxTypeMember* member);
void idax_type_members_free(IdaxTypeMember* members, size_t count);

/* ═══════════════════════════════════════════════════════════════════════════
 * Entry (ida::entry)
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct IdaxEntryPoint {
    uint64_t ordinal;
    uint64_t address;
    char*    name;       /**< malloc'd */
    char*    forwarder;  /**< malloc'd */
} IdaxEntryPoint;

void idax_entry_free(IdaxEntryPoint* entry);

int idax_entry_count(size_t* out);
int idax_entry_by_index(size_t index, IdaxEntryPoint* out);
int idax_entry_by_ordinal(uint64_t ordinal, IdaxEntryPoint* out);
int idax_entry_add(uint64_t ordinal, uint64_t address, const char* name, int make_code);
int idax_entry_rename(uint64_t ordinal, const char* name);
int idax_entry_forwarder(uint64_t ordinal, char** out);
int idax_entry_set_forwarder(uint64_t ordinal, const char* target);
int idax_entry_clear_forwarder(uint64_t ordinal);

/* ═══════════════════════════════════════════════════════════════════════════
 * Fixup (ida::fixup)
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct IdaxFixup {
    uint64_t source;
    int      type;
    uint32_t flags;
    uint64_t base;
    uint64_t target;
    uint16_t selector;
    uint64_t offset;
    int64_t  displacement;
} IdaxFixup;

int idax_fixup_at(uint64_t source, IdaxFixup* out);
int idax_fixup_set(uint64_t source, const IdaxFixup* fixup);
int idax_fixup_remove(uint64_t source);
int idax_fixup_exists(uint64_t source);
int idax_fixup_contains(uint64_t start, uint64_t size);
int idax_fixup_in_range(uint64_t start, uint64_t end, IdaxFixup** out, size_t* count);
int idax_fixup_first(uint64_t* out);
int idax_fixup_next(uint64_t address, uint64_t* out);
int idax_fixup_prev(uint64_t address, uint64_t* out);

typedef struct IdaxFixupCustomHandler {
    const char* name;
    uint32_t    properties;
    uint8_t     size;
    uint8_t     width;
    uint8_t     shift;
    uint32_t    reference_type;
} IdaxFixupCustomHandler;

int idax_fixup_register_custom(const IdaxFixupCustomHandler* handler,
                               uint16_t* out);
int idax_fixup_unregister_custom(uint16_t custom_type);
int idax_fixup_find_custom(const char* name, uint16_t* out);

/* ═══════════════════════════════════════════════════════════════════════════
 * Event (ida::event)
 * ═══════════════════════════════════════════════════════════════════════════ */

/** Flat C transfer model for ida::event::Event. */
typedef struct IdaxEvent {
    int      kind;
    uint64_t address;
    uint64_t secondary_address;
    const char* new_name;
    const char* old_name;
    uint32_t old_value;
    int      repeatable;
} IdaxEvent;

/**
 * Legacy generic event callback.
 * Kept for backwards compatibility.
 */
typedef void (*IdaxEventCallback)(void* context, int event_kind,
                                  uint64_t address, uint64_t secondary);

typedef void (*IdaxEventSegmentAddedCallback)(void* context, uint64_t start);
typedef void (*IdaxEventSegmentDeletedCallback)(void* context, uint64_t start,
                                                uint64_t end);
typedef void (*IdaxEventFunctionAddedCallback)(void* context, uint64_t entry);
typedef void (*IdaxEventFunctionDeletedCallback)(void* context, uint64_t entry);
typedef void (*IdaxEventRenamedCallback)(void* context, uint64_t address,
                                         const char* new_name,
                                         const char* old_name);
typedef void (*IdaxEventBytePatchedCallback)(void* context, uint64_t address,
                                             uint32_t old_value);
typedef void (*IdaxEventCommentChangedCallback)(void* context, uint64_t address,
                                                int repeatable);
typedef void (*IdaxEventExCallback)(void* context, const IdaxEvent* event);
typedef int (*IdaxEventFilterCallback)(void* context, const IdaxEvent* event);

int idax_event_subscribe(int event_kind, IdaxEventCallback callback,
                         void* context, uint64_t* token_out);
int idax_event_on_segment_added(IdaxEventSegmentAddedCallback callback,
                                void* context, uint64_t* token_out);
int idax_event_on_segment_deleted(IdaxEventSegmentDeletedCallback callback,
                                  void* context, uint64_t* token_out);
int idax_event_on_function_added(IdaxEventFunctionAddedCallback callback,
                                 void* context, uint64_t* token_out);
int idax_event_on_function_deleted(IdaxEventFunctionDeletedCallback callback,
                                   void* context, uint64_t* token_out);
int idax_event_on_renamed(IdaxEventRenamedCallback callback,
                          void* context, uint64_t* token_out);
int idax_event_on_byte_patched(IdaxEventBytePatchedCallback callback,
                               void* context, uint64_t* token_out);
int idax_event_on_comment_changed(IdaxEventCommentChangedCallback callback,
                                  void* context, uint64_t* token_out);
int idax_event_on_event(IdaxEventExCallback callback,
                        void* context, uint64_t* token_out);
int idax_event_on_event_filtered(IdaxEventFilterCallback filter,
                                 IdaxEventExCallback callback,
                                 void* context,
                                 uint64_t* token_out);
int idax_event_unsubscribe(uint64_t token);

/* ═══════════════════════════════════════════════════════════════════════════
 * Plugin (ida::plugin)
 *
 * Plugin support is primarily compile-time (macros). The shim exposes
 * action registration and menu attachment.
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct IdaxPluginActionContext {
    const char* action_id;
    const char* widget_title;
    int         widget_type;
    uint64_t    current_address;
    uint64_t    current_value;
    int         has_selection;
    int         is_external_address;
    const char* register_name;
    void*       widget_handle;
    void*       focused_widget_handle;
    void*       decompiler_view_handle;
} IdaxPluginActionContext;

typedef void (*IdaxActionHandler)(void* context);
typedef void (*IdaxActionHandlerEx)(void* context,
                                    const IdaxPluginActionContext* action_context);
typedef int (*IdaxActionEnabledCheck)(void* context);
typedef int (*IdaxActionEnabledCheckEx)(void* context,
                                        const IdaxPluginActionContext* action_context);
typedef int (*IdaxPluginHostCallback)(void* context, void* host);

int idax_plugin_register_action(const char* id, const char* label,
                                const char* hotkey, const char* tooltip,
                                int icon,
                                IdaxActionHandler handler,
                                void* handler_context,
                                IdaxActionEnabledCheck enabled_check,
                                void* enabled_context);
int idax_plugin_register_action_ex(const char* id, const char* label,
                                   const char* hotkey, const char* tooltip,
                                   int icon,
                                   IdaxActionHandler handler,
                                   IdaxActionHandlerEx handler_ex,
                                   void* handler_context,
                                   IdaxActionEnabledCheck enabled_check,
                                   IdaxActionEnabledCheckEx enabled_check_ex,
                                   void* enabled_context);
int idax_plugin_unregister_action(const char* action_id);
int idax_plugin_attach_to_menu(const char* menu_path, const char* action_id);
int idax_plugin_attach_to_toolbar(const char* toolbar, const char* action_id);
int idax_plugin_attach_to_popup(const char* widget_title, const char* action_id);
int idax_plugin_detach_from_menu(const char* menu_path, const char* action_id);
int idax_plugin_detach_from_toolbar(const char* toolbar, const char* action_id);
int idax_plugin_detach_from_popup(const char* widget_title, const char* action_id);
int idax_plugin_action_context_widget_host(const IdaxPluginActionContext* action_context,
                                           void** out);
int idax_plugin_action_context_with_widget_host(
    const IdaxPluginActionContext* action_context,
    IdaxPluginHostCallback callback,
    void* callback_context);
int idax_plugin_action_context_decompiler_view_host(
    const IdaxPluginActionContext* action_context,
    void** out);
int idax_plugin_action_context_with_decompiler_view_host(
    const IdaxPluginActionContext* action_context,
    IdaxPluginHostCallback callback,
    void* callback_context);

/* ═══════════════════════════════════════════════════════════════════════════
 * Loader (ida::loader)
 *
 * Loader module support is primarily compile-time (macros/subclassing).
 * The shim exposes runtime-bindable helper functions and InputFile wrappers.
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct IdaxLoaderLoadFlags {
    int create_segments;
    int load_resources;
    int rename_entries;
    int manual_load;
    int fill_gaps;
    int create_import_segment;
    int first_file;
    int binary_code_segment;
    int reload;
    int auto_flat_group;
    int mini_database;
    int loader_options_dialog;
    int load_all_segments;
} IdaxLoaderLoadFlags;

int idax_loader_decode_load_flags(uint16_t raw_flags, IdaxLoaderLoadFlags* out);
int idax_loader_encode_load_flags(const IdaxLoaderLoadFlags* flags, uint16_t* out_raw_flags);

int idax_loader_file_to_database(void* li_handle, int64_t file_offset,
                                 uint64_t ea, uint64_t size, int patchable);
int idax_loader_memory_to_database(const uint8_t* data, uint64_t ea, uint64_t size);
void idax_loader_abort_load(const char* message);

int idax_loader_input_size(void* li_handle, int64_t* out);
int idax_loader_input_tell(void* li_handle, int64_t* out);
int idax_loader_input_seek(void* li_handle, int64_t offset, int64_t* out);
int idax_loader_input_read_bytes(void* li_handle, size_t count,
                                 uint8_t** out, size_t* out_len);
int idax_loader_input_read_bytes_at(void* li_handle, int64_t offset, size_t count,
                                    uint8_t** out, size_t* out_len);
int idax_loader_input_read_string(void* li_handle, int64_t offset, size_t max_len,
                                  char** out);
int idax_loader_input_filename(void* li_handle, char** out);

int idax_loader_set_processor(const char* processor_name);
int idax_loader_create_filename_comment(void);

/* ═══════════════════════════════════════════════════════════════════════════
 * Processor (ida::processor)
 *
 * Processor module support is primarily compile-time (macros/subclassing).
 * No runtime shim functions needed beyond what plugin/loader provide.
 * Placeholder for future runtime queries.
 * ═══════════════════════════════════════════════════════════════════════════ */

/* Reserved for future runtime processor queries. */

/* ═══════════════════════════════════════════════════════════════════════════
 * Debugger (ida::debugger)
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct IdaxThreadInfo {
    int   id;
    char* name;  /**< malloc'd */
    int   is_current;
} IdaxThreadInfo;

typedef struct IdaxBackendInfo {
    char* name;          /**< malloc'd */
    char* display_name;  /**< malloc'd */
    int   remote;
    int   supports_appcall;
    int   supports_attach;
    int   loaded;
} IdaxBackendInfo;

typedef struct IdaxDebuggerRegisterInfo {
    char* name;  /**< malloc'd */
    int   read_only;
    int   instruction_pointer;
    int   stack_pointer;
    int   frame_pointer;
    int   may_contain_address;
    int   custom_format;
} IdaxDebuggerRegisterInfo;

typedef enum IdaxDebuggerAppcallValueKind {
    IDAX_DEBUGGER_APPCALL_SIGNED_INTEGER = 0,
    IDAX_DEBUGGER_APPCALL_UNSIGNED_INTEGER = 1,
    IDAX_DEBUGGER_APPCALL_FLOATING_POINT = 2,
    IDAX_DEBUGGER_APPCALL_STRING = 3,
    IDAX_DEBUGGER_APPCALL_ADDRESS = 4,
    IDAX_DEBUGGER_APPCALL_BOOLEAN = 5,
} IdaxDebuggerAppcallValueKind;

typedef struct IdaxDebuggerAppcallValue {
    int      kind;
    int64_t  signed_value;
    uint64_t unsigned_value;
    double   floating_value;
    char*    string_value;  /**< malloc'd for output, nullable */
    uint64_t address_value;
    int      boolean_value;
} IdaxDebuggerAppcallValue;

typedef struct IdaxDebuggerAppcallOptions {
    int      has_thread_id;
    int      thread_id;
    int      manual;
    int      include_debug_event;
    int      has_timeout_milliseconds;
    uint32_t timeout_milliseconds;
} IdaxDebuggerAppcallOptions;

typedef struct IdaxDebuggerAppcallRequest {
    uint64_t                 function_address;
    void*                    function_type;   /**< IdaxTypeHandle */
    IdaxDebuggerAppcallValue* arguments;
    size_t                   argument_count;
    IdaxDebuggerAppcallOptions options;
} IdaxDebuggerAppcallRequest;

typedef struct IdaxDebuggerAppcallResult {
    IdaxDebuggerAppcallValue return_value;
    char*                    diagnostics;  /**< malloc'd */
} IdaxDebuggerAppcallResult;

typedef struct IdaxDebuggerModuleInfo {
    const char* name;
    uint64_t    base;
    uint64_t    size;
} IdaxDebuggerModuleInfo;

typedef struct IdaxDebuggerExceptionInfo {
    uint64_t    ea;
    uint32_t    code;
    int         can_continue;
    const char* message;
} IdaxDebuggerExceptionInfo;

typedef enum IdaxDebuggerBreakpointChange {
    IDAX_DEBUGGER_BREAKPOINT_ADDED = 0,
    IDAX_DEBUGGER_BREAKPOINT_REMOVED = 1,
    IDAX_DEBUGGER_BREAKPOINT_CHANGED = 2,
} IdaxDebuggerBreakpointChange;

typedef void (*IdaxDebuggerProcessStartedCallback)(
    void* context, const IdaxDebuggerModuleInfo* module_info);
typedef void (*IdaxDebuggerProcessExitedCallback)(
    void* context, int exit_code);
typedef void (*IdaxDebuggerProcessSuspendedCallback)(
    void* context, uint64_t address);
typedef void (*IdaxDebuggerBreakpointHitCallback)(
    void* context, int thread_id, uint64_t address);
typedef int (*IdaxDebuggerTraceCallback)(
    void* context, int thread_id, uint64_t ip);
typedef void (*IdaxDebuggerExceptionCallback)(
    void* context, const IdaxDebuggerExceptionInfo* exception_info);
typedef void (*IdaxDebuggerThreadStartedCallback)(
    void* context, int thread_id, const char* thread_name);
typedef void (*IdaxDebuggerThreadExitedCallback)(
    void* context, int thread_id, int exit_code);
typedef void (*IdaxDebuggerLibraryLoadedCallback)(
    void* context, const IdaxDebuggerModuleInfo* module_info);
typedef void (*IdaxDebuggerLibraryUnloadedCallback)(
    void* context, const char* library_name);
typedef void (*IdaxDebuggerBreakpointChangedCallback)(
    void* context, int change, uint64_t address);

typedef int (*IdaxDebuggerAppcallExecutorCallback)(
    void* context,
    const IdaxDebuggerAppcallRequest* request,
    IdaxDebuggerAppcallResult* out_result);
typedef void (*IdaxDebuggerAppcallExecutorCleanupCallback)(void* context);

void idax_thread_info_free(IdaxThreadInfo* info);
void idax_backend_info_free(IdaxBackendInfo* info);
void idax_debugger_register_info_free(IdaxDebuggerRegisterInfo* info);
void idax_debugger_appcall_value_free(IdaxDebuggerAppcallValue* value);
void idax_debugger_appcall_result_free(IdaxDebuggerAppcallResult* result);

int idax_debugger_available_backends(IdaxBackendInfo** out, size_t* count);
int idax_debugger_current_backend(IdaxBackendInfo* out);
int idax_debugger_load_backend(const char* name, int use_remote);

int idax_debugger_start(const char* path, const char* args,
                        const char* working_dir);
int idax_debugger_request_start(const char* path, const char* args,
                                const char* working_dir);
int idax_debugger_attach(int pid);
int idax_debugger_request_attach(int pid, int event_id);
int idax_debugger_detach(void);
int idax_debugger_terminate(void);

int idax_debugger_suspend(void);
int idax_debugger_resume(void);
int idax_debugger_step_into(void);
int idax_debugger_step_over(void);
int idax_debugger_step_out(void);
int idax_debugger_run_to(uint64_t address);

int idax_debugger_state(int* out);
int idax_debugger_instruction_pointer(uint64_t* out);
int idax_debugger_stack_pointer(uint64_t* out);
int idax_debugger_register_value(const char* reg_name, uint64_t* out);
int idax_debugger_set_register(const char* reg_name, uint64_t value);

int idax_debugger_add_breakpoint(uint64_t address);
int idax_debugger_remove_breakpoint(uint64_t address);
int idax_debugger_has_breakpoint(uint64_t address, int* out);

int idax_debugger_read_memory(uint64_t address, uint64_t size,
                              uint8_t** out, size_t* out_len);
int idax_debugger_write_memory(uint64_t address, const uint8_t* data,
                               size_t len);

int idax_debugger_is_request_running(void);
int idax_debugger_run_requests(void);
int idax_debugger_request_suspend(void);
int idax_debugger_request_resume(void);
int idax_debugger_request_step_into(void);
int idax_debugger_request_step_over(void);
int idax_debugger_request_step_out(void);
int idax_debugger_request_run_to(uint64_t address);

int idax_debugger_thread_count(size_t* out);
int idax_debugger_thread_id_at(size_t index, int* out);
int idax_debugger_thread_name_at(size_t index, char** out);
int idax_debugger_current_thread_id(int* out);
int idax_debugger_threads(IdaxThreadInfo** out, size_t* count);
int idax_debugger_select_thread(int thread_id);
int idax_debugger_request_select_thread(int thread_id);
int idax_debugger_suspend_thread(int thread_id);
int idax_debugger_request_suspend_thread(int thread_id);
int idax_debugger_resume_thread(int thread_id);
int idax_debugger_request_resume_thread(int thread_id);

int idax_debugger_register_info(const char* register_name,
                                IdaxDebuggerRegisterInfo* out);
int idax_debugger_is_integer_register(const char* register_name, int* out);
int idax_debugger_is_floating_register(const char* register_name, int* out);
int idax_debugger_is_custom_register(const char* register_name, int* out);

int idax_debugger_appcall(const IdaxDebuggerAppcallRequest* request,
                          IdaxDebuggerAppcallResult* out);
int idax_debugger_cleanup_appcall(int has_thread_id, int thread_id);
int idax_debugger_register_executor(
    const char* name,
    IdaxDebuggerAppcallExecutorCallback callback,
    IdaxDebuggerAppcallExecutorCleanupCallback cleanup,
    void* context);
int idax_debugger_unregister_executor(const char* name);
int idax_debugger_appcall_with_executor(
    const char* name,
    const IdaxDebuggerAppcallRequest* request,
    IdaxDebuggerAppcallResult* out);

int idax_debugger_on_process_started(IdaxDebuggerProcessStartedCallback callback,
                                     void* context,
                                     uint64_t* token_out);
int idax_debugger_on_process_exited(IdaxDebuggerProcessExitedCallback callback,
                                    void* context,
                                    uint64_t* token_out);
int idax_debugger_on_process_suspended(
    IdaxDebuggerProcessSuspendedCallback callback,
    void* context,
    uint64_t* token_out);
int idax_debugger_on_breakpoint_hit(IdaxDebuggerBreakpointHitCallback callback,
                                    void* context,
                                    uint64_t* token_out);
int idax_debugger_on_trace(IdaxDebuggerTraceCallback callback,
                           void* context,
                           uint64_t* token_out);
int idax_debugger_on_exception(IdaxDebuggerExceptionCallback callback,
                               void* context,
                               uint64_t* token_out);
int idax_debugger_on_thread_started(IdaxDebuggerThreadStartedCallback callback,
                                    void* context,
                                    uint64_t* token_out);
int idax_debugger_on_thread_exited(IdaxDebuggerThreadExitedCallback callback,
                                   void* context,
                                   uint64_t* token_out);
int idax_debugger_on_library_loaded(IdaxDebuggerLibraryLoadedCallback callback,
                                    void* context,
                                    uint64_t* token_out);
int idax_debugger_on_library_unloaded(IdaxDebuggerLibraryUnloadedCallback callback,
                                      void* context,
                                      uint64_t* token_out);
int idax_debugger_on_breakpoint_changed(
    IdaxDebuggerBreakpointChangedCallback callback,
    void* context,
    uint64_t* token_out);
int idax_debugger_unsubscribe(uint64_t token);

/* ═══════════════════════════════════════════════════════════════════════════
 * Decompiler (ida::decompiler)
 * ═══════════════════════════════════════════════════════════════════════════ */

/** Opaque handle to a decompiled function. Must be freed with idax_decompiled_free(). */
typedef void* IdaxDecompiledHandle;
typedef uint64_t IdaxDecompilerToken;

typedef struct IdaxDecompilerMaturityEvent {
    uint64_t function_address;
    int      new_maturity;
} IdaxDecompilerMaturityEvent;

typedef struct IdaxDecompilerPseudocodeEvent {
    uint64_t function_address;
    void*    cfunc_handle;
} IdaxDecompilerPseudocodeEvent;

typedef struct IdaxDecompilerCursorPositionEvent {
    uint64_t function_address;
    uint64_t cursor_address;
    void*    view_handle;
} IdaxDecompilerCursorPositionEvent;

typedef struct IdaxDecompilerHintRequestEvent {
    uint64_t function_address;
    uint64_t item_address;
    void*    view_handle;
} IdaxDecompilerHintRequestEvent;

typedef void (*IdaxDecompilerMaturityChangedCallback)(
    void* context,
    const IdaxDecompilerMaturityEvent* event);
typedef void (*IdaxDecompilerPseudocodeCallback)(
    void* context,
    const IdaxDecompilerPseudocodeEvent* event);
typedef void (*IdaxDecompilerCursorPositionCallback)(
    void* context,
    const IdaxDecompilerCursorPositionEvent* event);
typedef int (*IdaxDecompilerCreateHintCallback)(
    void* context,
    const IdaxDecompilerHintRequestEvent* event,
    const char** out_text,
    int* out_lines);

typedef struct IdaxDecompilerItemAtPosition {
    int      type;
    uint64_t address;
    int      item_index;
    int      is_expression;
} IdaxDecompilerItemAtPosition;

typedef struct IdaxDecompilerExpressionInfo {
    int      type;
    uint64_t address;
} IdaxDecompilerExpressionInfo;

typedef struct IdaxDecompilerStatementInfo {
    int      type;
    uint64_t address;
} IdaxDecompilerStatementInfo;

typedef int (*IdaxDecompilerExpressionVisitor)(
    void* context,
    const IdaxDecompilerExpressionInfo* expression);
typedef int (*IdaxDecompilerStatementVisitor)(
    void* context,
    const IdaxDecompilerStatementInfo* statement);

int idax_decompiler_available(int* out);
int idax_decompiler_decompile(uint64_t ea, IdaxDecompiledHandle* out);
void idax_decompiled_free(IdaxDecompiledHandle handle);

int idax_decompiler_on_maturity_changed(
    IdaxDecompilerMaturityChangedCallback callback,
    void* context,
    IdaxDecompilerToken* token_out);
int idax_decompiler_on_func_printed(
    IdaxDecompilerPseudocodeCallback callback,
    void* context,
    IdaxDecompilerToken* token_out);
int idax_decompiler_on_refresh_pseudocode(
    IdaxDecompilerPseudocodeCallback callback,
    void* context,
    IdaxDecompilerToken* token_out);
int idax_decompiler_on_curpos_changed(
    IdaxDecompilerCursorPositionCallback callback,
    void* context,
    IdaxDecompilerToken* token_out);
int idax_decompiler_on_create_hint(
    IdaxDecompilerCreateHintCallback callback,
    void* context,
    IdaxDecompilerToken* token_out);
int idax_decompiler_unsubscribe(IdaxDecompilerToken token);

int idax_decompiled_pseudocode(IdaxDecompiledHandle handle, char** out);
int idax_decompiled_microcode(IdaxDecompiledHandle handle, char** out);

int idax_decompiled_lines(IdaxDecompiledHandle handle,
                          char*** out, size_t* count);
void idax_decompiled_lines_free(char** lines, size_t count);
int idax_decompiled_raw_lines(IdaxDecompiledHandle handle,
                              char*** out, size_t* count);
int idax_decompiled_set_raw_line(IdaxDecompiledHandle handle,
                                 size_t line_index,
                                 const char* tagged_text);
int idax_decompiled_header_line_count(IdaxDecompiledHandle handle, int* out);

int idax_decompiled_declaration(IdaxDecompiledHandle handle, char** out);
int idax_decompiled_entry_address(IdaxDecompiledHandle handle, uint64_t* out);

typedef struct IdaxLocalVariable {
    char*    name;
    char*    type_name;
    int      is_argument;
    int      width;
    int      has_user_name;
    int      storage;       /**< 0=unknown, 1=register, 2=stack */
    char*    comment;
} IdaxLocalVariable;

void idax_local_variable_free(IdaxLocalVariable* var);
void idax_decompiled_variables_free(IdaxLocalVariable* vars, size_t count);

int idax_decompiled_variable_count(IdaxDecompiledHandle handle, size_t* out);
int idax_decompiled_variables(IdaxDecompiledHandle handle,
                              IdaxLocalVariable** out, size_t* count);
int idax_decompiled_rename_variable(IdaxDecompiledHandle handle,
                                    const char* old_name, const char* new_name);

int idax_decompiled_set_comment(IdaxDecompiledHandle handle, uint64_t ea,
                                const char* text, int position);
int idax_decompiled_get_comment(IdaxDecompiledHandle handle, uint64_t ea,
                                int position, char** out);
int idax_decompiled_save_comments(IdaxDecompiledHandle handle);

int idax_decompiled_line_to_address(IdaxDecompiledHandle handle,
                                    int line_number, uint64_t* out);

int idax_decompiler_mark_dirty(uint64_t func_ea, int close_views);
int idax_decompiler_mark_dirty_with_callers(uint64_t func_ea, int close_views);
int idax_decompiler_view_from_host(void* view_host, uint64_t* out_function_ea);
int idax_decompiler_view_for_function(uint64_t address, uint64_t* out_function_ea);
int idax_decompiler_current_view(uint64_t* out_function_ea);

int idax_decompiler_raw_pseudocode_lines(void* cfunc_handle,
                                         char*** out,
                                         size_t* count);
void idax_decompiler_pseudocode_lines_free(char** lines, size_t count);
int idax_decompiler_set_pseudocode_line(void* cfunc_handle,
                                        size_t line_index,
                                        const char* tagged_text);
int idax_decompiler_pseudocode_header_line_count(void* cfunc_handle, int* out);

int idax_decompiler_item_at_position(void* cfunc_handle,
                                     const char* tagged_line,
                                     int char_index,
                                     IdaxDecompilerItemAtPosition* out);
int idax_decompiler_item_type_name(int item_type, char** out);

int idax_decompiler_for_each_expression(IdaxDecompiledHandle handle,
                                        IdaxDecompilerExpressionVisitor callback,
                                        void* context,
                                        int* out_visited);
int idax_decompiler_for_each_item(IdaxDecompiledHandle handle,
                                  IdaxDecompilerExpressionVisitor expression_callback,
                                  IdaxDecompilerStatementVisitor statement_callback,
                                  void* context,
                                  int* out_visited);

/* Microcode filter support */
typedef int (*IdaxMicrocodeMatchCallback)(void* context, uint64_t address, int itype);
typedef int (*IdaxMicrocodeApplyCallback)(void* context, void* mctx);

int idax_decompiler_register_microcode_filter(
    IdaxMicrocodeMatchCallback match_cb,
    IdaxMicrocodeApplyCallback apply_cb,
    void* context,
    uint64_t* token_out);
int idax_decompiler_unregister_microcode_filter(uint64_t token);

/* ═══════════════════════════════════════════════════════════════════════════
 * Storage (ida::storage)
 * ═══════════════════════════════════════════════════════════════════════════ */

/** Opaque handle to a storage node. Must be freed with idax_storage_node_free(). */
typedef void* IdaxNodeHandle;

int idax_storage_node_open(const char* name, int create, IdaxNodeHandle* out);
int idax_storage_node_open_by_id(uint64_t node_id, IdaxNodeHandle* out);
void idax_storage_node_free(IdaxNodeHandle node);

int idax_storage_node_id(IdaxNodeHandle node, uint64_t* out);
int idax_storage_node_name(IdaxNodeHandle node, char** out);

int idax_storage_node_alt_get(IdaxNodeHandle node, uint64_t index,
                              uint8_t tag, uint64_t* out);
int idax_storage_node_alt_set(IdaxNodeHandle node, uint64_t index,
                              uint64_t value, uint8_t tag);
int idax_storage_node_alt_remove(IdaxNodeHandle node, uint64_t index,
                                 uint8_t tag);

int idax_storage_node_sup_get(IdaxNodeHandle node, uint64_t index,
                              uint8_t tag, uint8_t** out, size_t* out_len);
int idax_storage_node_sup_set(IdaxNodeHandle node, uint64_t index,
                              const uint8_t* data, size_t len, uint8_t tag);

int idax_storage_node_hash_get(IdaxNodeHandle node, const char* key,
                               uint8_t tag, char** out);
int idax_storage_node_hash_set(IdaxNodeHandle node, const char* key,
                               const char* value, uint8_t tag);

int idax_storage_node_blob_get(IdaxNodeHandle node, uint64_t index,
                               uint8_t tag, uint8_t** out, size_t* out_len);
int idax_storage_node_blob_set(IdaxNodeHandle node, uint64_t index,
                               const uint8_t* data, size_t len, uint8_t tag);
int idax_storage_node_blob_remove(IdaxNodeHandle node, uint64_t index,
                                  uint8_t tag);
int idax_storage_node_blob_size(IdaxNodeHandle node, uint64_t index,
                                uint8_t tag, size_t* out);
int idax_storage_node_blob_string(IdaxNodeHandle node, uint64_t index,
                                  uint8_t tag, char** out);

/* ═══════════════════════════════════════════════════════════════════════════
 * Graph (ida::graph)
 * ═══════════════════════════════════════════════════════════════════════════ */

/** Opaque handle to a graph. Must be freed with idax_graph_free(). */
typedef void* IdaxGraphHandle;

typedef struct IdaxGraphNodeInfo {
    uint32_t background_color;
    uint32_t frame_color;
    uint64_t address;
    char*    text;   /**< malloc'd, free with idax_free_string */
} IdaxGraphNodeInfo;

typedef struct IdaxGraphEdgeInfo {
    uint32_t color;
    int      width;
    int      source_port;
    int      target_port;
} IdaxGraphEdgeInfo;

typedef struct IdaxGraphEdge {
    int source;
    int target;
} IdaxGraphEdge;

typedef struct IdaxAddressRange {
    uint64_t start;
    uint64_t end;
} IdaxAddressRange;

typedef int (*IdaxGraphOnRefresh)(void* context, IdaxGraphHandle graph);
typedef int (*IdaxGraphOnNodeText)(void* context, int node, char** out_text);
typedef uint32_t (*IdaxGraphOnNodeColor)(void* context, int node);
typedef int (*IdaxGraphOnClicked)(void* context, int node);
typedef int (*IdaxGraphOnDoubleClicked)(void* context, int node);
typedef int (*IdaxGraphOnHint)(void* context, int node, char** out_hint);
typedef int (*IdaxGraphOnCreatingGroup)(void* context, const int* nodes, size_t count);
typedef void (*IdaxGraphOnDestroyed)(void* context);

typedef struct IdaxGraphCallbacks {
    void*                    context;
    IdaxGraphOnRefresh       on_refresh;
    IdaxGraphOnNodeText      on_node_text;
    IdaxGraphOnNodeColor     on_node_color;
    IdaxGraphOnClicked       on_clicked;
    IdaxGraphOnDoubleClicked on_double_clicked;
    IdaxGraphOnHint          on_hint;
    IdaxGraphOnCreatingGroup on_creating_group;
    IdaxGraphOnDestroyed     on_destroyed;
} IdaxGraphCallbacks;

IdaxGraphHandle idax_graph_create(void);
void idax_graph_free(IdaxGraphHandle graph);

int idax_graph_add_node(IdaxGraphHandle graph);
int idax_graph_remove_node(IdaxGraphHandle graph, int node);
int idax_graph_total_node_count(IdaxGraphHandle graph);
int idax_graph_visible_node_count(IdaxGraphHandle graph);
int idax_graph_node_exists(IdaxGraphHandle graph, int node);
int idax_graph_add_edge(IdaxGraphHandle graph, int source, int target);
int idax_graph_add_edge_with_info(IdaxGraphHandle graph, int source, int target,
                                  const IdaxGraphEdgeInfo* info);
int idax_graph_remove_edge(IdaxGraphHandle graph, int source, int target);
int idax_graph_replace_edge(IdaxGraphHandle graph, int from, int to,
                            int new_from, int new_to);
int idax_graph_clear(IdaxGraphHandle graph);

int idax_graph_successors(IdaxGraphHandle graph, int node,
                          int** out, size_t* count);
int idax_graph_predecessors(IdaxGraphHandle graph, int node,
                            int** out, size_t* count);
int idax_graph_visible_nodes(IdaxGraphHandle graph, int** out, size_t* count);
int idax_graph_edges(IdaxGraphHandle graph, IdaxGraphEdge** out, size_t* count);
int idax_graph_path_exists(IdaxGraphHandle graph, int source, int target);

int idax_graph_create_group(IdaxGraphHandle graph, const int* nodes, size_t count,
                            int* out_group);
int idax_graph_delete_group(IdaxGraphHandle graph, int group);
int idax_graph_set_group_expanded(IdaxGraphHandle graph, int group, int expanded);
int idax_graph_is_group(IdaxGraphHandle graph, int node);
int idax_graph_is_collapsed(IdaxGraphHandle graph, int group);
int idax_graph_group_members(IdaxGraphHandle graph, int group,
                             int** out, size_t* count);

int idax_graph_set_layout(IdaxGraphHandle graph, int layout);
int idax_graph_current_layout(IdaxGraphHandle graph);
int idax_graph_redo_layout(IdaxGraphHandle graph);

int idax_graph_show_graph(const char* title, IdaxGraphHandle graph,
                          const IdaxGraphCallbacks* callbacks);
int idax_graph_refresh_graph(const char* title);
int idax_graph_has_graph_viewer(const char* title, int* out);
int idax_graph_is_graph_viewer_visible(const char* title, int* out);
int idax_graph_activate_graph_viewer(const char* title);
int idax_graph_close_graph_viewer(const char* title);

void idax_graph_free_node_ids(int* p);
void idax_graph_free_edges(IdaxGraphEdge* p);

/* Flow chart */
typedef struct IdaxBasicBlock {
    uint64_t start;
    uint64_t end;
    int      type;
    int*     successors;
    size_t   successor_count;
    int*     predecessors;
    size_t   predecessor_count;
} IdaxBasicBlock;

void idax_basic_block_free(IdaxBasicBlock* block);

int idax_graph_flowchart(uint64_t function_address,
                         IdaxBasicBlock** out, size_t* count);
int idax_graph_flowchart_for_ranges(const IdaxAddressRange* ranges, size_t range_count,
                                    IdaxBasicBlock** out, size_t* count);
void idax_graph_flowchart_free(IdaxBasicBlock* blocks, size_t count);

/* ═══════════════════════════════════════════════════════════════════════════
 * UI (ida::ui)
 * ═══════════════════════════════════════════════════════════════════════════ */

void idax_ui_message(const char* text);
void idax_ui_warning(const char* text);
void idax_ui_info(const char* text);

int idax_ui_ask_yn(const char* question, int default_yes, int* out);
int idax_ui_ask_string(const char* prompt, const char* default_value, char** out);
int idax_ui_ask_file(int for_saving, const char* default_path,
                     const char* prompt, char** out);
int idax_ui_ask_address(const char* prompt, uint64_t default_value,
                        uint64_t* out);
int idax_ui_ask_long(const char* prompt, int64_t default_value, int64_t* out);

int idax_ui_jump_to(uint64_t address);
int idax_ui_screen_address(uint64_t* out);
int idax_ui_selection(uint64_t* start_out, uint64_t* end_out);

void idax_ui_refresh_all_views(void);
int idax_ui_user_directory(char** out);

/** Opaque widget handle. */
typedef void* IdaxWidgetHandle;

typedef struct IdaxShowWidgetOptions {
    int position;
    int restore_previous;
} IdaxShowWidgetOptions;

typedef struct IdaxUIEvent {
    int      kind;
    uint64_t address;
    uint64_t previous_address;
    void*    widget;
    void*    previous_widget;
    uint64_t widget_id;
    uint64_t previous_widget_id;
    int      is_new_database;
    const char* startup_script;
    const char* widget_title;
} IdaxUIEvent;

typedef struct IdaxPopupEvent {
    void*    widget;
    uint64_t widget_id;
    const char* widget_title;
    void*    popup;
    int      widget_type;
} IdaxPopupEvent;

typedef struct IdaxLineRenderEntry {
    int      line_number;
    uint32_t bg_color;
    int      start_column;
    int      length;
    int      character_range;
} IdaxLineRenderEntry;

typedef struct IdaxRenderingEvent {
    void*    widget;
    uint64_t widget_id;
    int      widget_type;
    void*    opaque;
} IdaxRenderingEvent;

typedef int (*IdaxUITimerCallback)(void* context);
typedef void (*IdaxUIEventExCallback)(void* context, const IdaxUIEvent* event);
typedef int (*IdaxUIEventFilterCallback)(void* context, const IdaxUIEvent* event);
typedef void (*IdaxUIPopupCallback)(void* context, const IdaxPopupEvent* event);
typedef void (*IdaxUIActionCallback)(void* context);
typedef void (*IdaxUIRenderingCallback)(void* context, IdaxRenderingEvent* event);
typedef int (*IdaxWidgetHostCallback)(void* context, void* host);

int idax_ui_create_widget(const char* title, IdaxWidgetHandle* out);
int idax_ui_show_widget(IdaxWidgetHandle widget, int position);
int idax_ui_show_widget_ex(IdaxWidgetHandle widget, const IdaxShowWidgetOptions* options);
int idax_ui_activate_widget(IdaxWidgetHandle widget);
int idax_ui_close_widget(IdaxWidgetHandle widget);
int idax_ui_find_widget(const char* title, IdaxWidgetHandle* out);
int idax_ui_is_widget_visible(IdaxWidgetHandle widget);
int idax_ui_widget_type(IdaxWidgetHandle widget);
int idax_ui_widget_title(IdaxWidgetHandle widget, char** out);
int idax_ui_widget_id(IdaxWidgetHandle widget, uint64_t* out);
int idax_ui_widget_host(IdaxWidgetHandle widget, void** out);
int idax_ui_with_widget_host(IdaxWidgetHandle widget, IdaxWidgetHostCallback callback,
                             void* context);

int idax_ui_ask_form(const char* markup, int* out);

int idax_ui_create_custom_viewer(const char* title,
                                 const char* const* lines,
                                 size_t line_count,
                                 IdaxWidgetHandle* out);
int idax_ui_set_custom_viewer_lines(IdaxWidgetHandle viewer,
                                    const char* const* lines,
                                    size_t line_count);
int idax_ui_custom_viewer_line_count(IdaxWidgetHandle viewer, size_t* out);
int idax_ui_custom_viewer_jump_to_line(IdaxWidgetHandle viewer,
                                       size_t line_index,
                                       int x,
                                       int y);
int idax_ui_custom_viewer_current_line(IdaxWidgetHandle viewer, int mouse, char** out);
int idax_ui_refresh_custom_viewer(IdaxWidgetHandle viewer);
int idax_ui_close_custom_viewer(IdaxWidgetHandle viewer);

int idax_ui_register_timer(int interval_ms, uint64_t* token_out);
int idax_ui_register_timer_with_callback(int interval_ms,
                                         IdaxUITimerCallback callback,
                                         void* context,
                                         uint64_t* token_out);
int idax_ui_unregister_timer(uint64_t token);

/* UI event subscriptions (legacy generic callback) */
typedef void (*IdaxUIEventCallback)(void* context, int event_kind,
                                    uint64_t address);

int idax_ui_subscribe(int event_kind, IdaxUIEventCallback callback,
                      void* context, uint64_t* token_out);

/* UI event subscriptions (typed parity with ida::ui) */
int idax_ui_on_database_closed(IdaxUIEventExCallback callback,
                               void* context,
                               uint64_t* token_out);
int idax_ui_on_database_inited(IdaxUIEventExCallback callback,
                               void* context,
                               uint64_t* token_out);
int idax_ui_on_ready_to_run(IdaxUIEventExCallback callback,
                            void* context,
                            uint64_t* token_out);
int idax_ui_on_screen_ea_changed(IdaxUIEventExCallback callback,
                                 void* context,
                                 uint64_t* token_out);
int idax_ui_on_current_widget_changed(IdaxUIEventExCallback callback,
                                      void* context,
                                      uint64_t* token_out);
int idax_ui_on_widget_visible(IdaxUIEventExCallback callback,
                              void* context,
                              uint64_t* token_out);
int idax_ui_on_widget_invisible(IdaxUIEventExCallback callback,
                                void* context,
                                uint64_t* token_out);
int idax_ui_on_widget_closing(IdaxUIEventExCallback callback,
                              void* context,
                              uint64_t* token_out);
int idax_ui_on_widget_visible_for_widget(IdaxWidgetHandle widget,
                                         IdaxUIEventExCallback callback,
                                         void* context,
                                         uint64_t* token_out);
int idax_ui_on_widget_invisible_for_widget(IdaxWidgetHandle widget,
                                           IdaxUIEventExCallback callback,
                                           void* context,
                                           uint64_t* token_out);
int idax_ui_on_widget_closing_for_widget(IdaxWidgetHandle widget,
                                         IdaxUIEventExCallback callback,
                                         void* context,
                                         uint64_t* token_out);
int idax_ui_on_cursor_changed(IdaxUIEventExCallback callback,
                              void* context,
                              uint64_t* token_out);
int idax_ui_on_view_activated(IdaxUIEventExCallback callback,
                              void* context,
                              uint64_t* token_out);
int idax_ui_on_view_deactivated(IdaxUIEventExCallback callback,
                                void* context,
                                uint64_t* token_out);
int idax_ui_on_view_created(IdaxUIEventExCallback callback,
                            void* context,
                            uint64_t* token_out);
int idax_ui_on_view_closed(IdaxUIEventExCallback callback,
                           void* context,
                           uint64_t* token_out);
int idax_ui_on_event(IdaxUIEventExCallback callback,
                     void* context,
                     uint64_t* token_out);
int idax_ui_on_event_filtered(IdaxUIEventFilterCallback filter,
                              IdaxUIEventExCallback callback,
                              void* context,
                              uint64_t* token_out);

int idax_ui_on_popup_ready(IdaxUIPopupCallback callback,
                           void* context,
                           uint64_t* token_out);
int idax_ui_attach_dynamic_action(void* popup,
                                  IdaxWidgetHandle widget,
                                  const char* action_id,
                                  const char* label,
                                  IdaxUIActionCallback callback,
                                  void* context,
                                  const char* menu_path,
                                  int icon);

void idax_ui_rendering_event_add_entry(IdaxRenderingEvent* event,
                                       const IdaxLineRenderEntry* entry);
int idax_ui_on_rendering_info(IdaxUIRenderingCallback callback,
                              void* context,
                              uint64_t* token_out);

int idax_ui_unsubscribe(uint64_t token);

/* ═══════════════════════════════════════════════════════════════════════════
 * Lines (ida::lines)
 * ═══════════════════════════════════════════════════════════════════════════ */

int idax_lines_colstr(const char* text, uint8_t color, char** out);
int idax_lines_tag_remove(const char* tagged_text, char** out);
int idax_lines_tag_advance(const char* tagged_text, int pos);
size_t idax_lines_tag_strlen(const char* tagged_text);
int idax_lines_make_addr_tag(int item_index, char** out);
int idax_lines_decode_addr_tag(const char* tagged_text, size_t pos);

/* ═══════════════════════════════════════════════════════════════════════════
 * Diagnostics (ida::diagnostics)
 * ═══════════════════════════════════════════════════════════════════════════ */

int idax_diagnostics_set_log_level(int level);
int idax_diagnostics_log_level(void);
void idax_diagnostics_log(int level, const char* domain, const char* message);
void idax_diagnostics_reset_performance_counters(void);

typedef struct IdaxPerformanceCounters {
    uint64_t log_messages;
    uint64_t invariant_failures;
} IdaxPerformanceCounters;

int idax_diagnostics_performance_counters(IdaxPerformanceCounters* out);

/* ═══════════════════════════════════════════════════════════════════════════
 * Lumina (ida::lumina)
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct IdaxLuminaBatchResult {
    size_t requested;
    size_t completed;
    size_t succeeded;
    size_t failed;
} IdaxLuminaBatchResult;

int idax_lumina_has_connection(int feature, int* out);
int idax_lumina_close_connection(int feature);
int idax_lumina_close_all_connections(void);
int idax_lumina_pull(const uint64_t* addresses, size_t count,
                     int auto_apply, int feature,
                     IdaxLuminaBatchResult* out);
int idax_lumina_push(const uint64_t* addresses, size_t count,
                     int push_mode, int feature,
                     IdaxLuminaBatchResult* out);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* IDAX_SHIM_H */

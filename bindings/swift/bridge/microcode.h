#ifndef IDAX_SWIFT_MICROCODE_H
#define IDAX_SWIFT_MICROCODE_H
#include "lifecycle.h"
#ifdef __cplusplus
extern "C" {
#endif
typedef struct IdaxSwiftMicrocodeValue {
    int kind;
    int register_id;
    int local_variable_index;
    int64_t local_variable_offset;
    int second_register_id;
    uint64_t global_address;
    int64_t stack_offset;
    const char *helper_name;
    int block_index;
    const IdaxMicrocodeInstruction *nested_instruction;
    uint64_t unsigned_immediate;
    int64_t signed_immediate;
    double floating_immediate;
    int byte_width;
    int unsigned_integer;
    int vector_element_byte_width;
    int vector_element_count;
    int vector_elements_unsigned;
    int vector_elements_floating;
    const char *type_declaration;
    const char *argument_name;
    uint32_t argument_flags;
    IdaxMicrocodeValueLocation location;
} IdaxSwiftMicrocodeValue;
typedef struct IdaxSwiftMicrocodeMemoryRange {
    uint64_t address;
    uint64_t byte_size;
} IdaxSwiftMicrocodeMemoryRange;
typedef struct IdaxSwiftMicrocodeCallOptions {
    int has_insert_policy;
    int insert_policy;
    int has_callee_address;
    uint64_t callee_address;
    int has_solid_argument_count;
    int solid_argument_count;
    int has_call_stack_pointer_delta;
    int call_stack_pointer_delta;
    int has_stack_arguments_top;
    int stack_arguments_top;
    int has_function_role;
    int function_role;
    int has_return_location;
    IdaxMicrocodeValueLocation return_location;
    const char *return_type_declaration;
    int calling_convention;
    int mark_final;
    int mark_propagated;
    int mark_dead_return_registers;
    int mark_no_return;
    int mark_pure;
    int mark_no_side_effects;
    int mark_spoiled_lists_optimized;
    int mark_synthetic_has_call;
    int mark_has_format_string;
    int has_auto_stack_start_offset;
    int64_t auto_stack_start_offset;
    int has_auto_stack_alignment;
    int auto_stack_alignment;
    int auto_stack_argument_locations;
    int mark_explicit_locations;
    const IdaxMicrocodeRegisterRange *return_registers;
    size_t return_registers_count;
    const IdaxMicrocodeRegisterRange *spoiled_registers;
    size_t spoiled_registers_count;
    const IdaxMicrocodeRegisterRange *passthrough_registers;
    size_t passthrough_registers_count;
    const IdaxMicrocodeRegisterRange *dead_registers;
    size_t dead_registers_count;
    const IdaxSwiftMicrocodeMemoryRange *visible_memory_ranges;
    size_t visible_memory_ranges_count;
    int visible_memory_all;
} IdaxSwiftMicrocodeCallOptions;
void idax_swift_microcode_lease_retain(void *);
void idax_swift_microcode_lease_release(void *);
int idax_swift_microcode_register(IdaxSwiftCallbacks, void **, IdaxSwiftError *);
int idax_swift_microcode_registration_close(void *, IdaxSwiftError *);
int idax_swift_microcode_registration_valid(void *, int *, IdaxSwiftError *);
void idax_swift_microcode_registration_release(void *);
int idax_swift_microcode_query(void *, int query, int index, uint64_t *, IdaxSwiftError *);
int idax_swift_microcode_instruction(void *, IdaxInstruction *, IdaxSwiftError *);
int idax_swift_microcode_block_instruction(void *, int index, int last, IdaxMicrocodeInstruction *,
                                           IdaxSwiftError *);
int idax_swift_microcode_operation(void *, int operation, int a, int b, int c, int d, int e,
                                   int policy, int mark_udt, int *, IdaxSwiftError *);
int idax_swift_microcode_emit(void *, const IdaxMicrocodeInstruction *, size_t, int single,
                              int policy, IdaxSwiftError *);
int idax_swift_microcode_helper(void *, const char *, const IdaxSwiftMicrocodeValue *, size_t,
                                const IdaxSwiftMicrocodeCallOptions *, int destination_kind,
                                int destination, int destination_width, int destination_unsigned,
                                const IdaxMicrocodeOperand *, IdaxSwiftError *);
#ifdef __cplusplus
}
#endif
#endif

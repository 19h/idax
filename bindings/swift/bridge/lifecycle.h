#ifndef IDAX_SWIFT_LIFECYCLE_H
#define IDAX_SWIFT_LIFECYCLE_H
#include "../../rust/idax-sys/shim/idax_shim.h"
#include "bridge.h"
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
/* Every function taking IdaxSwiftCallbacks consumes its context, on success
 * and failure. Only the supplied destroy function releases the Swift box. */
typedef struct IdaxSwiftNotification {
    int kind, phase;
    uint64_t address, secondary_address, size, identity, previous_identity;
    int number, secondary_number;
    uint32_t value;
    int flag, secondary_flag;
    const char *text, *secondary_text, *name;
    void* lease;
} IdaxSwiftNotification;
typedef struct IdaxSwiftReply {
    int decision;
    int64_t integer;
    uint64_t unsigned_integer;
    char* text;
} IdaxSwiftReply;
typedef int (*IdaxSwiftInvoke)(void*, const IdaxSwiftNotification*, IdaxSwiftReply*,
                               IdaxSwiftError*);
typedef void (*IdaxSwiftDestroy)(void*);
typedef struct IdaxSwiftCallbacks {
    void* context;
    IdaxSwiftInvoke invoke;
    IdaxSwiftDestroy destroy;
} IdaxSwiftCallbacks;
void idax_swift_reply_text(IdaxSwiftReply*, const char*);
int idax_swift_registration_close(void*, IdaxSwiftError*);
int idax_swift_registration_active(void*, int*, IdaxSwiftError*);
void idax_swift_registration_release(void*);
void idax_swift_lease_retain(void*);
void idax_swift_lease_release(void*);
void idax_swift_lease_invalidate(void*);
int idax_swift_lease_check(void*, IdaxSwiftError*);
int idax_swift_popup_lease_create(void* widget_host, void* popup_host, void** lease, char** title,
                                  int* widget_type, IdaxSwiftError*);
int idax_swift_event_subscribe(int kind, IdaxSwiftCallbacks, void**, IdaxSwiftError*);
int idax_swift_ui_subscribe(int kind, IdaxSwiftCallbacks, void**, IdaxSwiftError*);
int idax_swift_debugger_subscribe(int kind, IdaxSwiftCallbacks, void**, IdaxSwiftError*);
int idax_swift_timer_register(int interval_ms, IdaxSwiftCallbacks, void**, IdaxSwiftError*);
typedef struct IdaxSwiftAction {
    const char *identifier, *label, *shortcut, *tooltip;
    int icon;
} IdaxSwiftAction;
int idax_swift_action_register(const IdaxSwiftAction*, IdaxSwiftCallbacks, void**, IdaxSwiftError*);
int idax_swift_hotkey_register(const char*, IdaxSwiftCallbacks, void**, IdaxSwiftError*);
int idax_swift_hotkey_activate(void*, IdaxSwiftError*);
int idax_swift_action_activate(const char*, IdaxSwiftError*);
int idax_swift_action_attach(int location, int detach, const char* path, const char* identifier,
                             IdaxSwiftError*);
int idax_swift_widget_create(const char* title, const char* const* lines, size_t count, int custom,
                             void**, IdaxSwiftError*);
int idax_swift_widget_find(const char*, void**, IdaxSwiftError*);
int idax_swift_widget_current(void**, IdaxSwiftError*);
int idax_swift_context_widget(void* lease, int which, void**, IdaxSwiftError*);
int idax_swift_action_type_reference(void* lease, char**, void**, int*, IdaxSwiftError*);
int idax_swift_action_decompiler_view(void* lease, void**, IdaxSwiftError*);
void idax_swift_widget_release(void*);
int idax_swift_widget_operation(void*, int operation, int64_t argument, int auxiliary, int extra,
                                IdaxSwiftError*);
int idax_swift_widget_text(void*, int current_line, int mouse, char**, IdaxSwiftError*);
int idax_swift_widget_query(void*, int query, uint64_t*, IdaxSwiftError*);
int idax_swift_widget_lines(void*, const char* const*, size_t, IdaxSwiftError*);
int idax_swift_popup_attach(void* lease, const char* identifier, const char* label,
                            const char* path, int icon, IdaxSwiftCallbacks, IdaxSwiftError*);
int idax_swift_popup_attach_registered(void* lease, const char*, const char*, IdaxSwiftError*);
int idax_swift_rendering_add(void* lease, int line, uint32_t color, int column, int length,
                             int character_range, IdaxSwiftError*);
int idax_swift_rendering_entries(void* lease, IdaxLineRenderEntry**, size_t*, IdaxSwiftError*);
int idax_swift_rendering_replace(void* lease, const IdaxLineRenderEntry*, size_t, IdaxSwiftError*);

typedef struct IdaxSwiftGraphEdge {
    int source, target;
} IdaxSwiftGraphEdge;
int idax_swift_graph_callback_copy(void* lease, void**, IdaxSwiftError*);
typedef struct IdaxSwiftGraphEdgeStyle {
    uint32_t color;
    int width, source_port, target_port;
} IdaxSwiftGraphEdgeStyle;
int idax_swift_graph_create(void**, IdaxSwiftError*);
void idax_swift_graph_release(void*);
int idax_swift_graph_operation(void*, int operation, int a, int b, int c, int d, int* result,
                               IdaxSwiftError*);
int idax_swift_graph_add_styled_edge(void*, int source, int target, const IdaxSwiftGraphEdgeStyle*,
                                     IdaxSwiftError*);
int idax_swift_graph_nodes(void*, int operation, int node, int**, size_t*, IdaxSwiftError*);
int idax_swift_graph_edges(void*, IdaxSwiftGraphEdge**, size_t*, IdaxSwiftError*);
int idax_swift_graph_group(void*, const int*, size_t, int*, IdaxSwiftError*);
int idax_swift_graph_show(void*, const char*, IdaxSwiftCallbacks, IdaxSwiftError*);
int idax_swift_graph_viewer(int operation, const char*, int*, IdaxSwiftError*);
int idax_swift_graph_switch(uint64_t, uint64_t*, size_t*, size_t*, IdaxSwiftError*);

typedef int (*IdaxSwiftAppcallInvoke)(void*, const IdaxDebuggerAppcallRequest*,
                                      IdaxDebuggerAppcallResult*, IdaxSwiftError*);
int idax_swift_executor_register(const char*, void*, IdaxSwiftAppcallInvoke, IdaxSwiftDestroy,
                                 void**, IdaxSwiftError*);
int idax_swift_debugger_appcall(const char* executor, const IdaxDebuggerAppcallRequest*,
                                IdaxDebuggerAppcallResult*, IdaxSwiftError*);
int idax_swift_appcall_string(IdaxDebuggerAppcallValue*, const char*, IdaxSwiftError*);
int idax_swift_module_publish(int kind, IdaxSwiftCallbacks, IdaxSwiftError*);
void idax_swift_module_fail(const IdaxSwiftError*);
int idax_swift_module_strings(void* lease, int field, const char* const*, size_t, IdaxSwiftError*);
int idax_swift_module_numbers(void* lease, int field, const int64_t*, size_t, IdaxSwiftError*);
int idax_swift_module_input(void* lease, int operation, int64_t offset, size_t count,
                            uint8_t** bytes, size_t* size, int64_t* number, char** text,
                            IdaxSwiftError*);
int idax_swift_module_file_to_database(void* lease, int64_t offset, uint64_t address, uint64_t size,
                                       int patchable, IdaxSwiftError*);
int idax_swift_module_output_file(void* lease, const uint8_t*, size_t, IdaxSwiftError*);
int idax_swift_module_output_token(void* lease, int kind, const char*, IdaxSwiftError*);
typedef struct IdaxSwiftAnalyzeOperand {
    size_t index;
    int kind;
    int has_register, register_index, has_immediate;
    uint64_t immediate_value;
    int has_target_address;
    uint64_t target_address;
    int has_displacement;
    int64_t displacement;
    uint32_t data_type_code, processor_flags;
} IdaxSwiftAnalyzeOperand;
int idax_swift_module_operand(void* lease, const IdaxSwiftAnalyzeOperand*, IdaxSwiftError*);
typedef struct IdaxSwiftSwitch {
    int kind;
    uint64_t jump_table, values_table, default_target, idiom_start, element_base;
    int64_t low_case_value, indirect_low_case_value;
    uint32_t case_count, jump_table_entry_count;
    uint8_t jump_element_size, value_element_size, shift;
    int expression_register;
    uint8_t expression_data_type;
    int has_default, default_in_table, values_signed, subtract_values, self_relative, inverted,
        user_defined;
} IdaxSwiftSwitch;
int idax_swift_module_switch(void* lease, int write, IdaxSwiftSwitch*, IdaxSwiftError*);
int idax_swift_module_switch_case(void* lease, const int64_t*, size_t, uint64_t target,
                                  IdaxSwiftError*);
typedef struct IdaxSwiftChooserOptions {
    const char* title;
    const char* const* columns;
    const int *widths, *formats;
    size_t column_count;
    int modal, can_insert, can_delete, can_edit, can_refresh;
} IdaxSwiftChooserOptions;
int idax_swift_chooser_create(const IdaxSwiftChooserOptions*, IdaxSwiftCallbacks, void**,
                              IdaxSwiftError*);
void idax_swift_chooser_release(void*);
int idax_swift_chooser_operation(void*, int operation, size_t default_selection, int* has_selection,
                                 size_t* selection, IdaxSwiftError*);
int idax_swift_chooser_row(void* lease, const char* const*, size_t, int icon, int bold, int italic,
                           int strike, int gray, uint32_t background, IdaxSwiftError*);
#ifdef __cplusplus
}
#endif
#endif

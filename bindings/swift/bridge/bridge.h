#ifndef IDAX_SWIFT_BRIDGE_H
#define IDAX_SWIFT_BRIDGE_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct IdaxSwiftError {
    int category;
    int code;
    char* message;
    char* context;
} IdaxSwiftError;
/* Error outputs must be zero-initialized before first use. Bridge calls replace
 * any previously owned diagnostic. Release with idax_swift_error_free. */

typedef struct IdaxSwiftRuntimeOptions {
    int quiet;
    int disable_user_plugins;
    const char* const* allowlist_patterns;
    size_t allowlist_pattern_count;
    const char* const* arguments;
    size_t argument_count;
} IdaxSwiftRuntimeOptions;

void idax_swift_error_free(IdaxSwiftError* error);
void idax_swift_error_set(IdaxSwiftError* error, int category, int code,
                          const char* message, const char* context);
int idax_swift_runtime_initialize(const IdaxSwiftRuntimeOptions* options,
                                   IdaxSwiftError* error);
int idax_swift_runtime_is_initialized(void);
/* Called only from genuine native addon adapters, never exposed as public Swift. */
int idax_swift_runtime_attach_host(IdaxSwiftError* error);
/* Addon-owned IDB listener calls this on idb_event::closebase, before teardown. */
int idax_swift_runtime_host_database_closing(IdaxSwiftError* error);
int idax_swift_require_runtime_thread(IdaxSwiftError* error);
/* Engine-wide operations such as closing a decompiler session require no
 * borrowed callback or pinned native operation. Does not mutate resources. */
int idax_swift_runtime_require_idle(IdaxSwiftError* error);
int idax_swift_is_runtime_thread(void);
void idax_swift_defer_release(void (*release)(void*), void* context);
/* Always queue finalization, including on the owner thread. Releases drain
 * only outside borrowed callbacks and pinned native operations. */
void idax_swift_enqueue_release(void (*release)(void*), void* context);

/* Adoption consumes value on success and failure. Native destructors must not
 * throw. Database-bound values are invalidated before database open/close,
 * in reverse acquisition order. Their holders survive until released, and
 * get then returns Conflict; a subsequent database never revives a holder. */
int idax_swift_resource_adopt(void* value, void (*destroy)(void*), int database_bound,
                              void** output, IdaxSwiftError* error);
int idax_swift_resource_get(void* holder, void** value, IdaxSwiftError* error);
int idax_swift_resource_is_open(void* holder, int* open, IdaxSwiftError* error);
/* Pin for a native call that can reenter Swift. Close conflicts while pinned;
 * ARC release waits until the final unpin. Unpin must run on the runtime thread. */
int idax_swift_resource_pin(void* holder, void** value, IdaxSwiftError* error);
void idax_swift_resource_unpin(void* holder);
int idax_swift_resource_close(void* holder, IdaxSwiftError* error);
int idax_swift_resource_close_with(void* holder, int (*close)(void*, IdaxSwiftError*), IdaxSwiftError* error);
void idax_swift_resource_release(void* holder);
/* Borrowed native callbacks without a holder still guard database lifetime. */
int idax_swift_runtime_begin_activity(IdaxSwiftError* error);
void idax_swift_runtime_end_activity(void);
int idax_swift_database_open(const char* path, int auto_analysis, int load_intent,
                              IdaxSwiftError* error);
int idax_swift_database_close(int save, IdaxSwiftError* error);
int idax_swift_navigation_clone(void* history, void** output, IdaxSwiftError* error);

#ifdef __cplusplus
}
#endif
#endif

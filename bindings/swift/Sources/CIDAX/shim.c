// SPM requires at least one source file per target.
// The actual shim is pre-built (libidax_shim.a) and linked via linkerSettings.
//
// Stub definitions for IDA SDK data symbols referenced by libidax.a.
// The binary is linked with -flat_namespace -undefined dynamic_lookup so
// that IDA SDK function symbols resolve lazily at runtime (after dlopen).
// These data symbol stubs satisfy the non-lazy binding requirement — without
// them the binary would fail to load.
//
// After Database.initialize() calls init_library(), IDA's own callui/dbg
// variables (inside libida.dylib, two-level namespace) are populated.
// idax_sync_ida_globals() copies those values to our stubs so that
// libidax.a code (linked into this flat-namespace binary) sees them.

#include <stddef.h>
#include <dlfcn.h>

#if defined(__GNUC__)
#define IDAX_PRIVATE_VISIBILITY __attribute__((visibility("hidden")))
#else
#define IDAX_PRIVATE_VISIBILITY
#endif

IDAX_PRIVATE_VISIBILITY void *callui = NULL;
IDAX_PRIVATE_VISIBILITY void *dbg = NULL;
IDAX_PRIVATE_VISIBILITY int under_debugger = 0;

void idax_sync_ida_globals(void) {
    // After init_library() populates IDA's data symbols inside libida.dylib,
    // copy them to our stubs.  We open the already-loaded libida.dylib with
    // RTLD_NOLOAD to get a handle, then dlsym on that handle to find IDA's
    // versions (not ours).
#if defined(__APPLE__)
    void *h = dlopen("libida.dylib", RTLD_LAZY | RTLD_NOLOAD);
#else
    void *h = dlopen("libida.so", RTLD_LAZY | RTLD_NOLOAD);
#endif
    if (!h) return;

    void *p;
    p = dlsym(h, "callui");
    if (p) callui = *(void **)p;

    p = dlsym(h, "dbg");
    if (p) dbg = *(void **)p;

    p = dlsym(h, "under_debugger");
    if (p) under_debugger = *(int *)p;

    dlclose(h);
}

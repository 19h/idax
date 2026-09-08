#ifndef IDAX_SWIFT_DECOMPILER_EVENTS_H
#define IDAX_SWIFT_DECOMPILER_EVENTS_H
#include "decompiler.h"
#include "lifecycle.h"
#ifdef __cplusplus
extern "C" {
#endif
int idax_swift_decompiler_subscribe(int kind, IdaxSwiftCallbacks callbacks, void** output, IdaxSwiftError* error);
int idax_swift_decompiler_subscription_close(void* subscription, IdaxSwiftError* error);
void idax_swift_decompiler_subscription_free(void* subscription);
int idax_swift_decompiler_subscription_error(void* subscription, IdaxSwiftError* callback_error, int* present, int clear, IdaxSwiftError* error);
void idax_swift_decompiler_event_retain(void* lease);
void idax_swift_decompiler_event_release(void* lease);
int idax_swift_decompiler_event_lines(void* lease, char*** output, size_t* count, IdaxSwiftError* error);
int idax_swift_decompiler_event_set_line(void* lease, size_t index, const char* text, IdaxSwiftError* error);
int idax_swift_decompiler_event_header_lines(void* lease, int* output, IdaxSwiftError* error);
int idax_swift_decompiler_event_item(void* lease, const char* line, int column, IdaxDecompilerItemAtPosition* output, IdaxSwiftError* error);
int idax_swift_decompiler_event_view(void* lease, void** output, IdaxSwiftError* error);
int idax_swift_decompiler_event_popup(void* lease, IdaxSwiftNotification* output, IdaxSwiftError* error);
#ifdef __cplusplus
}
#endif
#endif

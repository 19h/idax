#ifndef IDAX_SWIFT_FORMS_H
#define IDAX_SWIFT_FORMS_H
#include "bridge.h"
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
/* SDK argument storage is private and scoped to the modal call. Text outputs
 * are separately owned and must be released even after a failed call. */
typedef struct IdaxSwiftFormField {
    int kind, width, visible_width, for_saving;
    const char* label;
    const char* const* choices;
    size_t choice_count;
    int64_t integer;
    uint64_t address;
    uint16_t bits;
    const char* text;
    char* output_text;
} IdaxSwiftFormField;
/* A null title represents native default construction; an explicit empty title
 * still contributes the native two-newline header. */
int idax_swift_form_markup(const char*, const IdaxSwiftFormField*, size_t, char**, IdaxSwiftError*);
int idax_swift_form_ask(const char*, IdaxSwiftFormField*, size_t, int*, IdaxSwiftError*);
int idax_swift_form_validate_bound(const char*, const IdaxSwiftFormField*, size_t, IdaxSwiftError*);
int idax_swift_form_ask_bound(const char*, IdaxSwiftFormField*, size_t, int*, IdaxSwiftError*);
void idax_swift_form_free_outputs(IdaxSwiftFormField*, size_t);
int idax_swift_form_ask_markup(const char*, int*, IdaxSwiftError*);
#ifdef __cplusplus
}
#endif
#endif

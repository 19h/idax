#include <stdint.h>

#if defined(__GNUC__) || defined(__clang__)
#define IDAX_EXPORTED __attribute__((noinline, used, visibility("default")))
#define IDAX_USED __attribute__((used, visibility("default")))
#else
#define IDAX_EXPORTED
#define IDAX_USED
#endif

struct symless_rtti_object;
typedef uint64_t (*symless_rtti_method)(void*, uint64_t);

struct symless_rtti_object {
    const symless_rtti_method* vtable;
    uint32_t flags;
    uint32_t reserved;
    uint64_t value;
    uint8_t marker;
    uint8_t padding[7];
    uint64_t method_only;
};

IDAX_EXPORTED uint64_t
symless_rtti_read(void* storage, uint64_t unused) {
    struct symless_rtti_object* object =
        (struct symless_rtti_object*)storage;
    (void)unused;
    return object->value + object->flags + object->marker
        + object->method_only;
}

IDAX_EXPORTED uint64_t
symless_rtti_write(void* storage, uint64_t value) {
    struct symless_rtti_object* object =
        (struct symless_rtti_object*)storage;
    object->marker = (uint8_t)value;
    object->method_only = value;
    return object->method_only;
}

IDAX_EXPORTED uint64_t
symless_rtti_clear(void* storage, uint64_t unused) {
    struct symless_rtti_object* object =
        (struct symless_rtti_object*)storage;
    (void)unused;
    object->marker = 0;
    object->method_only = 0;
    return 0;
}

IDAX_USED const uint64_t symless_rtti_type_tag =
    UINT64_C(0x53594d4c45535346);

extern const unsigned char symless_rtti_table_label[];
extern const symless_rtti_method symless_rtti_methods[];

#if defined(__APPLE__)
__asm__(
    ".section __DATA_CONST,__const,regular\n"
    ".p2align 3\n"
    ".globl _symless_rtti_table_label\n"
    "_symless_rtti_table_label:\n"
    ".quad 0\n"
    ".quad _symless_rtti_type_tag\n"
    ".globl _symless_rtti_methods\n"
    "_symless_rtti_methods:\n"
    ".quad _symless_rtti_read\n"
    ".quad _symless_rtti_write\n"
    ".quad _symless_rtti_clear\n"
    ".text\n");
#else
__asm__(
    ".section .data.rel.ro,\"aw\"\n"
    ".p2align 3\n"
    ".globl symless_rtti_table_label\n"
    "symless_rtti_table_label:\n"
    ".quad 0\n"
    ".quad symless_rtti_type_tag\n"
    ".globl symless_rtti_methods\n"
    "symless_rtti_methods:\n"
    ".quad symless_rtti_read\n"
    ".quad symless_rtti_write\n"
    ".quad symless_rtti_clear\n"
    ".text\n");
#endif

IDAX_USED const unsigned char* volatile symless_rtti_table_alias =
    symless_rtti_table_label;

IDAX_EXPORTED void*
symless_rtti_construct(void* storage, uint32_t seed) {
    struct symless_rtti_object* object =
        (struct symless_rtti_object*)storage;
    const unsigned char* table = symless_rtti_table_alias;
    table += 2 * sizeof(void*);
    object->vtable = (const symless_rtti_method*)table;
    object->flags = seed;
    object->value = (uint64_t)seed * UINT64_C(3);
    return storage;
}

int main(void) {
    struct symless_rtti_object object = {0};
    symless_rtti_construct(&object, UINT32_C(7));
    return (int)object.vtable[1](&object, UINT64_C(11));
}

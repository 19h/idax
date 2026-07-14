#include <stdint.h>

#if defined(__GNUC__) || defined(__clang__)
#define IDAX_EXPORTED __attribute__((noinline, used, visibility("default")))
#define IDAX_USED __attribute__((used, visibility("default")))
#else
#define IDAX_EXPORTED
#define IDAX_USED
#endif

struct symless_object;
typedef uint64_t (*symless_method)(void*, uint64_t);

struct symless_object {
    const symless_method* vtable;
    uint32_t flags;
    uint32_t reserved;
    uint64_t value;
    uint8_t marker;
};

IDAX_EXPORTED uint64_t
symless_method_read(void* storage, uint64_t unused) {
    struct symless_object* object = (struct symless_object*)storage;
    (void)unused;
    return object->value + object->flags + object->marker;
}

IDAX_EXPORTED uint64_t
symless_method_write(void* storage, uint64_t value) {
    struct symless_object* object = (struct symless_object*)storage;
    object->flags = (uint32_t)value;
    object->value = value;
    object->marker = (uint8_t)value;
    return object->value;
}

IDAX_EXPORTED uint64_t
symless_method_clear(void* storage, uint64_t unused) {
    struct symless_object* object = (struct symless_object*)storage;
    (void)unused;
    object->flags = 0;
    object->value = 0;
    object->marker = 0;
    return 0;
}

IDAX_USED const symless_method symless_vtable[] = {
    symless_method_read,
    symless_method_write,
    symless_method_clear,
};

IDAX_EXPORTED void*
symless_construct(void* storage, uint32_t seed) {
    struct symless_object* object = (struct symless_object*)storage;
    object->vtable = symless_vtable;
    object->flags = seed;
    object->value = (uint64_t)seed * UINT64_C(3);
    object->marker = (uint8_t)(seed ^ UINT32_C(0x5a));
    return storage;
}

int main(void) {
    struct symless_object object;
    symless_construct(&object, UINT32_C(7));
    return (int)object.vtable[1](&object, UINT64_C(11));
}

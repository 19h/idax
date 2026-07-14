#include <stdint.h>
#include <stdlib.h>

#if defined(__GNUC__) || defined(__clang__)
#define IDAX_EXPORTED __attribute__((noinline, used, visibility("default")))
#define IDAX_DATA __attribute__((used, visibility("default")))
#else
#define IDAX_EXPORTED
#define IDAX_DATA
#endif

typedef uint64_t (*symless_reader)(const unsigned char* object);
typedef void* (*symless_allocator)(size_t size);

enum { SYMLESS_POINTER_BIAS = 0x135 };

IDAX_EXPORTED uint64_t
symless_indirect_callee(const unsigned char* object) {
    return *(const uint64_t*)(object + 8);
}

IDAX_DATA uintptr_t volatile symless_indirect_slot
    = (uintptr_t)symless_indirect_callee - SYMLESS_POINTER_BIAS;

IDAX_DATA uintptr_t volatile symless_indirect_allocator_slot
    = (uintptr_t)malloc - SYMLESS_POINTER_BIAS;

IDAX_EXPORTED uint64_t
symless_indirect_root(const unsigned char* object) {
    const uint32_t first = *(const uint32_t*)(object + 4);
    symless_reader target = (symless_reader)(
        symless_indirect_slot + SYMLESS_POINTER_BIAS);
    const uint64_t second = target(object);
    const uint8_t tail = object[24];
    return (uint64_t)first + second + tail;
}

IDAX_EXPORTED void*
symless_indirect_allocate(size_t size) {
    symless_allocator target = (symless_allocator)(
        symless_indirect_allocator_slot + SYMLESS_POINTER_BIAS);
    return target(size);
}

IDAX_EXPORTED uint64_t
symless_indirect_allocation_root(void) {
    volatile unsigned char* object = symless_indirect_allocate(32);
    *(volatile uint32_t*)(object + 4) = UINT32_C(0x11223344);
    *(volatile uint64_t*)(object + 8) = UINT64_C(0x1020304050607080);
    object[24] = UINT8_C(0x5a);
    const uint64_t result = *(volatile uint32_t*)(object + 4)
        + *(volatile uint64_t*)(object + 8)
        + object[24];
    free((void*)object);
    return result;
}

int main(void) {
    _Alignas(8) unsigned char object[32] = {0};
    return (int)(symless_indirect_root(object)
        + symless_indirect_allocation_root());
}

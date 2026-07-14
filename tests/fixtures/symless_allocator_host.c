#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

static volatile uint64_t symless_allocator_sink;

__attribute__((noinline))
void *symless_wrap_alloc(size_t requested_bytes) {
    return malloc(requested_bytes);
}

__attribute__((noinline))
uint64_t symless_allocator_entry(void) {
    volatile uint8_t *allocation = symless_wrap_alloc(32);
    *(volatile uint32_t *)(allocation + 4) = UINT32_C(0x11223344);
    *(volatile uint64_t *)(allocation + 8) = UINT64_C(0x1020304050607080);
    allocation[24] = UINT8_C(0x5a);

    const uint64_t observed = *(volatile uint32_t *)(allocation + 4)
        + *(volatile uint64_t *)(allocation + 8)
        + allocation[24];
    symless_allocator_sink = observed;
    free((void *)allocation);
    return observed;
}

int main(void) {
    return (int)(symless_allocator_entry() & UINT64_C(0xff));
}

#include <stdint.h>

#if defined(_MSC_VER)
#define IDAX_NOINLINE __declspec(noinline)
#else
#define IDAX_NOINLINE __attribute__((noinline))
#endif

IDAX_NOINLINE uint64_t inspect_fields(void *opaque, uint64_t seed) {
    volatile uint8_t *bytes = (volatile uint8_t *)opaque;
    uint64_t wide = *(volatile uint64_t *)(bytes + 8);
    *(volatile uint32_t *)(bytes + 4) = (uint32_t)seed;
    uint16_t narrow = *(volatile uint16_t *)(bytes + 18);
    uint8_t flag = *(volatile uint8_t *)(bytes + 24);
    return wide + narrow + flag;
}

int main(int argc, char **argv) {
    uint64_t storage[4] = {0, 1, 2, 3};
    return (int)inspect_fields(storage, (uint64_t)argc + (argv != 0));
}

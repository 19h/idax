#include <stdint.h>

#if defined(__GNUC__) || defined(__clang__)
#define IDAX_EXPORTED __attribute__((noinline, used, visibility("default")))
#else
#define IDAX_EXPORTED
#endif

static volatile uintptr_t identity_observation;

IDAX_EXPORTED uint64_t
symless_callee_read(const unsigned char* object) {
    return *(const uint64_t*)(object + 8);
}

IDAX_EXPORTED unsigned char*
symless_identity(unsigned char* object) {
    identity_observation ^= (uintptr_t)object;
    return object;
}

IDAX_EXPORTED uint64_t
symless_interprocedural_entry(unsigned char* object) {
    const uint32_t local = *(const uint32_t*)(object + 4);
    const uint64_t callee = symless_callee_read(object);
    const uint8_t returned = symless_identity(object)[24];
    return (uint64_t)local + callee + returned;
}

int main(void) {
    unsigned char object[32] = {0};
    return (int)symless_interprocedural_entry(object);
}

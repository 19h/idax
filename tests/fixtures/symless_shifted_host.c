#include <stdint.h>

#if defined(__GNUC__) || defined(__clang__)
#define IDAX_EXPORTED __attribute__((noinline, used, visibility("default")))
#else
#define IDAX_EXPORTED
#endif

IDAX_EXPORTED uint64_t
symless_shifted_read(const unsigned char* interior) {
    return *(const uint64_t*)interior;
}

IDAX_EXPORTED uint64_t
symless_shifted_entry(unsigned char* object) {
    const uint32_t local = *(const uint32_t*)(object + 4);
    const uint64_t nested = symless_shifted_read(object + 8);
    const uint8_t tail = object[24];
    return (uint64_t)local + nested + tail;
}

int main(void) {
    unsigned char object[32] = {0};
    return (int)symless_shifted_entry(object);
}

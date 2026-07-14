#include <stdint.h>

#if defined(__GNUC__) || defined(__clang__)
#define IDAX_EXPORTED __attribute__((noinline, used, visibility("default")))
#else
#define IDAX_EXPORTED
#endif

struct symless_forward_target;

IDAX_EXPORTED uint64_t
symless_forward_root(struct symless_forward_target* object) {
    const unsigned char* bytes = (const unsigned char*)object;
    const uint32_t first = *(const uint32_t*)(bytes + 4);
    const uint64_t second = *(const uint64_t*)(bytes + 8);
    const uint8_t tail = bytes[24];
    return (uint64_t)first + second + tail;
}

int main(void) {
    _Alignas(8) unsigned char object[32] = {0};
    return (int)symless_forward_root(
        (struct symless_forward_target*)object);
}

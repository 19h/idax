// Host-native Appcall smoke fixture.
// Keep this file tiny and portable so it can be rebuilt easily on any host.

#include <stdint.h>
#include <string.h>

#if defined(_WIN32)
#include <windows.h>
#else
#include <unistd.h>
#endif

int ref1(int value) {
    return value + 1;
}

int ref2(int value) {
    return ref1(value) + 1;
}

int ref3(int value) {
    return ref2(value) + 1;
}

int ref4(int* p) {
    if (p == 0) {
        return -1;
    }
    return *p + 4;
}

static void appcall_wait_window(void) {
#if defined(_WIN32)
    Sleep(30000);
#else
    sleep(30);
#endif
}

int main(int argc, char** argv) {
    if (argc > 1 && strcmp(argv[1], "--wait") == 0) {
        appcall_wait_window();
    }
    int seed = argc > 1 ? 41 : 38;
    int value = ref3(seed);
    return ref4(&value);
}

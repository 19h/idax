// Source-built module boundaries and changed-code inputs for full export parity.
#include <cstdio>

#ifndef IDAX_DIAPHORA_VARIANT
#define IDAX_DIAPHORA_VARIANT 0
#endif

extern "C" int idax_diaphora_a0(int value) {
    std::puts("alpha_unit.c: diagnostic");
#if IDAX_DIAPHORA_VARIANT
    if (value & 1)
        return value * 3 - 7;
    return value + 14;
#else
    return value + 13;
#endif
}
extern "C" int idax_diaphora_a1(int value) { return idax_diaphora_a0(value) + 1; }
extern "C" int idax_diaphora_a2(int value) { return idax_diaphora_a0(value) + 2; }
extern "C" int idax_diaphora_a3(int value) { return idax_diaphora_a0(value) + 3; }
extern "C" int idax_diaphora_a4(int value) { return idax_diaphora_a0(value) + 4; }
extern "C" int idax_diaphora_a5(int value) { return idax_diaphora_a0(value) + 5; }
extern "C" int idax_diaphora_a6(int value) { return idax_diaphora_a0(value) + 6; }

extern "C" int idax_diaphora_b0(int value) {
    std::puts("beta_unit.cpp: diagnostic");
    return value * 7;
}
extern "C" int idax_diaphora_b1(int value) { return idax_diaphora_b0(value) + 1; }
extern "C" int idax_diaphora_b2(int value) { return idax_diaphora_b0(value) + 2; }
extern "C" int idax_diaphora_b3(int value) { return idax_diaphora_b0(value) + 3; }
extern "C" int idax_diaphora_b4(int value) { return idax_diaphora_b0(value) + 4; }
extern "C" int idax_diaphora_b5(int value) { return idax_diaphora_b0(value) + 5; }
extern "C" int idax_diaphora_b6(int value) { return idax_diaphora_b0(value) + 6; }

extern "C" int idax_diaphora_c0(int value) {
    std::puts("gamma_unit.rs: diagnostic");
    return value ^ 0x51;
}
extern "C" int idax_diaphora_c1(int value) { return idax_diaphora_c0(value) + 1; }
extern "C" int idax_diaphora_c2(int value) { return idax_diaphora_c0(value) + 2; }
extern "C" int idax_diaphora_c3(int value) { return idax_diaphora_c0(value) + 3; }
extern "C" int idax_diaphora_c4(int value) { return idax_diaphora_c0(value) + 4; }
extern "C" int idax_diaphora_c5(int value) { return idax_diaphora_c0(value) + 5; }
extern "C" int idax_diaphora_c6(int value) { return idax_diaphora_c0(value) + 6; }

using Function = int (*)(int);
Function volatile idax_diaphora_dispatch[] = {
    idax_diaphora_a1, idax_diaphora_a2, idax_diaphora_a3,
    idax_diaphora_a4, idax_diaphora_a5, idax_diaphora_a6,
    idax_diaphora_b1, idax_diaphora_b2, idax_diaphora_b3,
    idax_diaphora_b4, idax_diaphora_b5, idax_diaphora_b6,
    idax_diaphora_c1, idax_diaphora_c2, idax_diaphora_c3,
    idax_diaphora_c4, idax_diaphora_c5, idax_diaphora_c6,
};

int main(int argc, char**) {
    int sum = 0;
    for (auto& operation : idax_diaphora_dispatch)
        sum += operation(argc);
    return sum & 0x7F;
}

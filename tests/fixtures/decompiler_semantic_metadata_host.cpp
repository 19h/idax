// Disposable host-native analysis fixture. Built without debug information.
extern "C" double idax_metadata_float() { return 65536.0; }
extern "C" const char* idax_metadata_string() { return "idax-owned-text"; }
extern "C" unsigned idax_metadata_switch(int value, unsigned salt) {
    switch (value) {
        case -3: return salt * 7;
        case -2: return salt / 3;
        case -1: return salt ^ 0x1234;
        case 0: return salt << 4;
        case 1: return salt >> 2;
        case 2: return salt + 79;
        case 3: return salt - 31;
        case 4: return salt | 0x6789;
        case 5: return salt & 0xff;
        case 6: return ~salt;
        case 7: return salt % 11;
        case 8: return (salt + 1) * (salt + 3);
        case 9: return (salt >> 7) ^ salt;
        case 10: return (salt | 5) + 2;
        case 11: return salt / 101;
        case 12: return salt * 103;
        default: return salt + 100;
    }
}
extern "C" int idax_metadata_stack(int value) {
    volatile int values[4] = {value, value + 1, value + 2, value + 3};
    int sum = 0;
    for (int index = 0; index < 4; ++index) {
        if (values[index] > 0)
            sum += values[index];
        else
            sum -= values[index];
    }
    return sum;
}
extern "C" int idax_metadata_call(int argc) {
    return idax_metadata_stack(argc) + idax_metadata_switch(argc, static_cast<unsigned>(argc) + 17)
         + static_cast<int>(idax_metadata_float()) + idax_metadata_string()[0];
}
int main(int argc, char**) { return idax_metadata_call(argc); }

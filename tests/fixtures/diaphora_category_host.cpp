// Actual ambiguous, unmatched and weak-similarity functions for native matching.
// Weak functions remain externally visible without a matched caller: earlier
// call-diff heuristics would otherwise consume them before the unreliable pass.
#define main idax_diaphora_baseline_main
#include "diaphora_full_host.cpp"
#undef main

using CategoryFunction = unsigned (*)(unsigned);

#if IDAX_DIAPHORA_VARIANT
extern "C" unsigned idax_ambiguous_candidate_one(unsigned value) {
    return (value * 0x4C247U) ^ 0x31416U;
}
extern "C" unsigned idax_ambiguous_candidate_two(unsigned value) {
    return (value * 0x4C247U) ^ 0x31416U;
}
extern "C" unsigned idax_secondary_unique(unsigned value) {
    unsigned result = 0x781223U;
    for (unsigned index = 0; index < (value & 15U); ++index)
        result = (result >> 5U) ^ (index * 0x23117U);
    return result;
}
extern "C" unsigned idax_secondary_extra(unsigned value) {
    std::puts("secondary_exclusive_unit.cpp: witness");
    return value / 37U + value % 0x103U;
}
extern "C" unsigned idax_weak_secondary(volatile unsigned* data) {
    volatile unsigned value = data[0];
    if (data[1]) value = value ^ 0x1387U;
    if (data[2]) value = value / 29U;
    if (data[3]) value = value ^ (data[4] >> 5U);
    if (data[5]) value = value % 173U;
    return value;
}
CategoryFunction volatile idax_category_dispatch[] = {
    idax_ambiguous_candidate_one, idax_ambiguous_candidate_two,
    idax_secondary_unique, idax_secondary_extra,
};
#else
extern "C" unsigned idax_ambiguous_source(unsigned value) {
    return (value ^ 0x4C246U) + 0x31415U;
}
extern "C" unsigned idax_primary_unique(unsigned value) {
    unsigned result = value;
    for (unsigned index = 0; index != 7; ++index) {
        if (result & 1U) result = (result * 0x71U) + index;
        else result = (result << 3U) ^ 0x831F7U;
    }
    return result;
}
extern "C" unsigned idax_weak_primary(volatile unsigned* data) {
    volatile unsigned value = data[0];
    if (data[1]) value = value + 0xAC91U;
    if (data[2]) value = value * 17U;
    if (data[3]) value = value + (data[4] << 3U);
    if (data[5]) value = value | 0x8812U;
    return value;
}
CategoryFunction volatile idax_category_dispatch[] = {
    idax_ambiguous_source, idax_primary_unique,
};
#endif

int main(int argc, char** argv) {
    unsigned result = static_cast<unsigned>(idax_diaphora_baseline_main(argc, argv));
    for (auto& operation : idax_category_dispatch)
        result ^= operation(static_cast<unsigned>(argc));
    return static_cast<int>(result & 0x7FU);
}

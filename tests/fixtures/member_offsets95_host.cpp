// Symbolic large layouts; the fixture is analyzed, never executed.
#include <cstdint>

struct Huge { std::uint16_t padding[(1ULL << 30) + 8]; std::uint32_t wide; };
struct Bits { unsigned before : 3; unsigned target : 5; unsigned after : 8; };
struct HugeBits { char padding[1ULL << 29]; unsigned before : 3; unsigned target : 5; };
union Choice { int integer; float real; };
extern "C" std::uint32_t read_wide(const Huge* p) { return p->wide; }
extern "C" unsigned read_bits(const Bits* p) { return p->target; }
extern "C" unsigned read_big_bits(const HugeBits* p) { return p->target; }
extern "C" float read_union(const Choice* p) { return p->real; }
int main(int argc, char**) { return argc > 10 ? static_cast<int>(read_bits(nullptr)) : 0; }

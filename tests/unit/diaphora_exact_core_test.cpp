#define IDAX_DIAPHORA_EXACT_CORE_TEST
#include "../../examples/plugin/diaphora_exact_port_plugin.cpp"

#include <cstdio>
#include <string>
#include <vector>

namespace {

int failures = 0;

#define CHECK(condition)                                                        \
    do {                                                                        \
        if (!(condition)) {                                                     \
            std::fprintf(stderr, "CHECK failed at line %d: %s\n",             \
                         __LINE__, #condition);                                 \
            ++failures;                                                         \
        }                                                                       \
    } while (false)

std::string md5(std::string_view input) {
    Md5 hash;
    hash.update(reinterpret_cast<const std::uint8_t*>(input.data()), input.size());
    return hash.finish_hex();
}

FunctionRecord record(std::size_t index,
                      std::uint64_t rva,
                      char full,
                      char relocation) {
    FunctionRecord value;
    value.address = index;
    value.ordinal = index;
    value.rva = rva;
    value.segment_rva = rva;
    value.nodes = 1;
    value.edges = 0;
    value.complexity = 1;
    value.instructions = 2;
    value.byte_size = 3;
    value.full_md5 = std::string(32, full);
    value.relocation_md5 = std::string(32, relocation);
    value.name = "f" + std::to_string(index);
    value.declaration = "int __idax_diaphora_function(void);";
    value.repeatable_comment = "comment\tline\n\xce\xbb";
    value.mnemonics = "mov,ret";
    return value;
}

void test_md5() {
    CHECK(md5("") == "d41d8cd98f00b204e9800998ecf8427e");
    CHECK(md5("a") == "0cc175b9c0f1b6a831c399e269772661");
    CHECK(md5("abc") == "900150983cd24fb0d6963f7d28e17f72");
    CHECK(md5("message digest") == "f96b697d7cb7938d525a2f31aaf161d0");
}

void test_manifest() {
    auto value = record(0, 0x123, 'a', 'b');
    const std::string encoded = format_manifest({value});
    const std::string expected_prefix =
        "IDAX_DIAPHORA_EXACT\t1\tcanonical-cfg\n"
        "F\t0\t123\t123\t1\t0\t1\t2\t3\t"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\t"
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\t6630\t";
    CHECK(encoded.starts_with(expected_prefix));
    auto decoded = parse_manifest(encoded);
    CHECK(decoded.has_value());
    if (decoded) {
        CHECK(decoded->size() == 1);
        CHECK((*decoded)[0].rva == value.rva);
        CHECK((*decoded)[0].name == value.name);
        CHECK((*decoded)[0].declaration == value.declaration);
        CHECK((*decoded)[0].repeatable_comment == value.repeatable_comment);
        CHECK(format_manifest(*decoded) == encoded);
    }
    std::string malformed = encoded;
    const auto hash_position = malformed.find(std::string(32, 'a'));
    CHECK(hash_position != std::string::npos);
    malformed[hash_position] = 'z';
    CHECK(!parse_manifest(malformed));
    CHECK(!hex_decode("0"));
    CHECK(!hex_decode("0g"));
    CHECK(!hex_decode("ff"));
    CHECK(!hex_decode("c080"));
    CHECK(!hex_decode("eda080"));
    CHECK(!hex_decode("f4908080"));
}

void test_metrics_and_prefix() {
    CHECK(canonical_complexity(1, 0) == 1);
    CHECK(canonical_complexity(2, 1) == 1);
    CHECK(canonical_complexity(4, 4) == 2);
    auto prefix = normalized_prefix_size(7, {
        {true, 2, std::nullopt}, {true, 4, std::nullopt}});
    CHECK(prefix && *prefix == 1);
    auto unchanged = normalized_prefix_size(5, {{false, std::nullopt, std::nullopt}});
    CHECK(unchanged && *unchanged == 5);
    CHECK(!normalized_prefix_size(4, {{true, 4, std::nullopt}}));
    CHECK(!normalized_prefix_size(4, {{false, std::nullopt, 5}}));
}

void test_matching() {
    const std::vector baseline = {
        record(0, 0x10, 'a', 'b'),
        record(1, 0x20, 'c', 'd'),
        record(2, 0x30, 'e', 'f'),
    };
    const std::vector current = {
        record(0, 0x10, 'a', 'b'),
        record(1, 0x99, 'c', 'd'),
        record(2, 0x88, 'e', '0'),
    };
    const auto summary = compare_records(baseline, current);
    CHECK(summary.matches.size() == 3);
    CHECK((summary.tiers == std::array<std::size_t, 4>{1, 1, 1, 0}));
    CHECK(summary.ambiguous == 0);
    CHECK(summary.unmatched == 0);

    const std::vector duplicates = {
        record(0, 0x10, 'a', 'b'), record(1, 0x10, 'a', 'b')};
    const auto ambiguous = compare_records(duplicates, duplicates);
    CHECK(ambiguous.matches.empty());
    CHECK(ambiguous.ambiguous == 2);
    CHECK(ambiguous.unmatched == 0);
}

} // namespace

int main() {
    test_md5();
    test_manifest();
    test_metrics_and_prefix();
    test_matching();
    if (failures == 0)
        std::puts("Diaphora exact C++ core: PASS");
    return failures == 0 ? 0 : 1;
}

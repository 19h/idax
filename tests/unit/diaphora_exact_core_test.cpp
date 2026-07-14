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

void test_instruction_metadata_manifest() {
    InstructionMetadataManifest manifest;
    manifest.functions.push_back(record(0, 0x123, 'a', 'b'));
    manifest.instructions.push_back({
        .function_ordinal = 0,
        .instruction_ordinal = 2,
        .function_offset = 7,
        .size = 5,
        .full_md5 = std::string(32, 'c'),
        .relocation_md5 = std::string(32, 'd'),
        .mnemonic = "mov",
        .comment = "ordinary\tcomment",
        .repeatable_comment = "repeatable\n\xce\xbb",
        .forced_operands = {{0, "forced one"}, {2, "forced \xce\xbb"}},
    });
    const std::string encoded = format_instruction_metadata_manifest(manifest);
    CHECK(encoded.starts_with(
        "IDAX_DIAPHORA_INSTRUCTION_METADATA\t1\texact-relative-offset\nF\t"));
    const std::string expected_instruction_line =
        "I\t0\t2\t7\t5\tcccccccccccccccccccccccccccccccc\t"
        "dddddddddddddddddddddddddddddddd\t6d6f76\t"
        "6f7264696e61727909636f6d6d656e74\t72657065617461626c650acebb\t"
        "303a31303a666f72636564206f6e65323a393a666f7263656420cebb\n";
    CHECK(encoded.find(expected_instruction_line) != std::string::npos);
    auto decoded = parse_instruction_metadata_manifest(encoded);
    CHECK(decoded.has_value());
    if (decoded) {
        CHECK(decoded->functions.size() == 1);
        CHECK(decoded->instructions == manifest.instructions);
        CHECK(format_instruction_metadata_manifest(*decoded) == encoded);
    }

    CHECK(!parse_forced_operands("0:0:"));
    CHECK(!parse_forced_operands("0:2:x"));
    CHECK(!parse_forced_operands(std::string("0:1:\xff", 5)));
    CHECK(!parse_forced_operands(std::string("0:1:\0", 5)));
    CHECK(!parse_forced_operands("1:1:x1:1:y"));

    const auto record_start = encoded.find("I\t");
    CHECK(record_start != std::string::npos);
    if (record_start != std::string::npos) {
        std::string duplicate = encoded;
        duplicate += encoded.substr(record_start);
        CHECK(!parse_instruction_metadata_manifest(duplicate));

        std::string unknown_function = encoded;
        unknown_function.replace(record_start, 4, "I\t1\t");
        CHECK(!parse_instruction_metadata_manifest(unknown_function));

        std::string invalid_hash = encoded;
        const auto hash_start = invalid_hash.find(std::string(32, 'c'), record_start);
        CHECK(hash_start != std::string::npos);
        if (hash_start != std::string::npos) {
            invalid_hash[hash_start] = 'g';
            CHECK(!parse_instruction_metadata_manifest(invalid_hash));
        }
    }

    auto empty_metadata = manifest;
    empty_metadata.instructions[0].comment.clear();
    empty_metadata.instructions[0].repeatable_comment.clear();
    empty_metadata.instructions[0].forced_operands.clear();
    CHECK(!parse_instruction_metadata_manifest(
        format_instruction_metadata_manifest(empty_metadata)));

    auto nul_metadata = manifest;
    nul_metadata.instructions[0].comment = std::string("x\0y", 3);
    CHECK(!parse_instruction_metadata_manifest(
        format_instruction_metadata_manifest(nul_metadata)));
}

void test_pseudocode_comment_manifest() {
    PseudocodeCommentManifest manifest;
    manifest.functions.push_back(record(0, 0x123, 'a', 'b'));
    PseudocodeCommentRecord first{
        .function_ordinal = 0,
        .instruction_ordinal = 2,
        .function_offset = 7,
        .size = 5,
        .full_md5 = std::string(32, 'c'),
        .relocation_md5 = std::string(32, 'd'),
        .mnemonic = "mov",
        .position = {PseudocodePositionKind::Default, 0},
        .text = "default\tcomment",
    };
    auto second = first;
    second.position = {PseudocodePositionKind::Semicolon, 0};
    second.text = "semicolon\n\xce\xbb";
    manifest.comments = {first, second};

    const std::string encoded = format_pseudocode_comment_manifest(manifest);
    CHECK(encoded.starts_with(
        "IDAX_DIAPHORA_PSEUDOCODE_COMMENTS\t1\texact-tree-location\nF\t"));
    CHECK(encoded.find(
        "P\t0\t2\t7\t5\tcccccccccccccccccccccccccccccccc\t"
        "dddddddddddddddddddddddddddddddd\t6d6f76\tdefault\t0\t"
        "64656661756c7409636f6d6d656e74\n") != std::string::npos);
    CHECK(encoded.find("\tsemicolon\t0\t73656d69636f6c6f6e0acebb\n")
          != std::string::npos);
    auto decoded = parse_pseudocode_comment_manifest(encoded);
    CHECK(decoded.has_value());
    if (decoded) {
        CHECK(decoded->functions.size() == 1);
        CHECK(decoded->comments == manifest.comments);
        CHECK(decoded->comments[0].instruction_ordinal
              == decoded->comments[1].instruction_ordinal);
        CHECK(decoded->comments[0].position
              != decoded->comments[1].position);
        CHECK(format_pseudocode_comment_manifest(*decoded) == encoded);
    }

    auto argument = parse_pseudocode_position("argument", 63);
    CHECK(argument && argument->kind == PseudocodePositionKind::Argument
          && argument->detail == 63);
    CHECK(!parse_pseudocode_position("argument", 64));
    auto case_minimum = parse_pseudocode_position("switch-case", -0x1fffffff);
    CHECK(case_minimum && case_minimum->kind == PseudocodePositionKind::SwitchCase
          && case_minimum->detail == -0x1fffffff);
    auto case_maximum = parse_pseudocode_position("switch-case", 0x1fffffff);
    CHECK(case_maximum && case_maximum->kind == PseudocodePositionKind::SwitchCase
          && case_maximum->detail == 0x1fffffff);
    CHECK(!parse_pseudocode_position("switch-case", -0x20000000));
    CHECK(!parse_pseudocode_position("switch-case", 0x20000000));
    CHECK(!parse_pseudocode_position("semicolon", 1));
    CHECK(!parse_pseudocode_position("unknown", 0));

    const auto record_start = encoded.find("P\t");
    CHECK(record_start != std::string::npos);
    if (record_start != std::string::npos) {
        const auto record_end = encoded.find('\n', record_start);
        CHECK(record_end != std::string::npos);
        if (record_end != std::string::npos) {
            std::string duplicate = encoded;
            duplicate += encoded.substr(record_start, record_end - record_start + 1);
            CHECK(!parse_pseudocode_comment_manifest(duplicate));
        }
        std::string unknown_function = encoded;
        unknown_function.replace(record_start, 4, "P\t1\t");
        CHECK(!parse_pseudocode_comment_manifest(unknown_function));
    }

    auto empty = manifest;
    empty.comments[0].text.clear();
    CHECK(!parse_pseudocode_comment_manifest(
        format_pseudocode_comment_manifest(empty)));
    auto nul = manifest;
    nul.comments[0].text = std::string("x\0y", 3);
    CHECK(!parse_pseudocode_comment_manifest(
        format_pseudocode_comment_manifest(nul)));
}

void test_instruction_offsets() {
    CHECK(relative_offset(0x120, 0x100) == 0x20);
    CHECK(relative_offset(0xf0, 0x100) == -0x10);
    CHECK(!relative_offset(std::numeric_limits<ida::Address>::max(), 0));
    CHECK(apply_relative_offset(0x100, 0x20) == 0x120);
    CHECK(apply_relative_offset(0x100, -0x10) == 0xf0);
    CHECK(!apply_relative_offset(0, -1));
    CHECK(!apply_relative_offset(std::numeric_limits<ida::Address>::max(), 1));
    CHECK(apply_relative_offset(std::uint64_t{1} << 63,
                                std::numeric_limits<std::int64_t>::min()) == 0);
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
    test_instruction_metadata_manifest();
    test_pseudocode_comment_manifest();
    test_instruction_offsets();
    test_metrics_and_prefix();
    test_matching();
    if (failures == 0)
        std::puts("Diaphora exact C++ core: PASS");
    return failures == 0 ? 0 : 1;
}

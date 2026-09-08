/// Exact instruction encodings exercise branch predicates independently of text aliases.
#include <array>
#include <cstdint>
#include <cstdio>
#include <vector>
#include <ida/database.hpp>
#include <ida/instruction.hpp>
#include <ida/segment.hpp>
#include <ida/data.hpp>

namespace {
int passed = 0;
int failed = 0;
#define CHECK(value) do { if (value) ++passed; else { ++failed; std::printf("FAIL line %d: %s\n", __LINE__, #value); } } while (false)
using Condition = ida::instruction::BranchCondition;

void verify(ida::Address address, std::span<const std::uint8_t> bytes,
            Condition expected) {
    CHECK(ida::data::write_bytes(address, bytes).has_value());
    auto decoded = ida::instruction::decode(address);
    CHECK(decoded.has_value());
    if (!decoded) return;
    if (decoded->branch_condition() != expected) {
        std::printf("predicate mismatch for %s: actual=%d expected=%d\n",
                    decoded->mnemonic().c_str(),
                    static_cast<int>(decoded->branch_condition()),
                    static_cast<int>(expected));
    }
    CHECK(decoded->branch_condition() == expected);
    CHECK(ida::instruction::branch_condition(address) == expected);
}

void x86(ida::Address address) {
    struct Case { std::vector<std::uint8_t> bytes; Condition condition; };
    const std::vector<Case> cases{
        {{0x74, 0x00}, Condition::Equal},
        {{0x75, 0x00}, Condition::NotEqual},
        {{0x72, 0x00}, Condition::LessThanUnsigned},
        {{0x73, 0x00}, Condition::GreaterThanOrEqualUnsigned},
        {{0x76, 0x00}, Condition::LessThanOrEqualUnsigned},
        {{0x77, 0x00}, Condition::GreaterThanUnsigned},
        {{0x7c, 0x00}, Condition::LessThanSigned},
        {{0x7d, 0x00}, Condition::GreaterThanOrEqualSigned},
        {{0x7e, 0x00}, Condition::LessThanOrEqualSigned},
        {{0x7f, 0x00}, Condition::GreaterThanSigned},
        {{0x78, 0x00}, Condition::Negative},
        {{0x79, 0x00}, Condition::NotNegative},
        {{0x70, 0x00}, Condition::Overflow},
        {{0x71, 0x00}, Condition::NoOverflow},
        {{0x7a, 0x00}, Condition::Parity},
        {{0x7b, 0x00}, Condition::NoParity},
        {{0xe3, 0x00}, Condition::CountZero},
        {{0x67, 0xe3, 0x00}, Condition::CountZero},
        {{0xe2, 0x00}, Condition::CountNotZero},
        {{0x67, 0xe2, 0x00}, Condition::CountNotZero},
        {{0xe1, 0x00}, Condition::CountNotZeroAndEqual},
        {{0x67, 0xe1, 0x00}, Condition::CountNotZeroAndEqual},
        {{0xe0, 0x00}, Condition::CountNotZeroAndNotEqual},
        {{0x67, 0xe0, 0x00}, Condition::CountNotZeroAndNotEqual},
        {{0xeb, 0x00}, Condition::Always},
        {{0xe8, 0, 0, 0, 0}, Condition::Always},
        {{0xc3}, Condition::Always},
        {{0x90}, Condition::None},
        {{0x48, 0x0f, 0xbc, 0xc0}, Condition::None}, // bsf rax, rax
    };
    for (const auto& item : cases) {
        verify(address, item.bytes, item.condition);
        address += 16;
    }
}

void arm64(ida::Address address) {
    struct Case { std::uint32_t word; Condition condition; };
    const std::array cases{
        Case{0x54000000, Condition::Equal},
        Case{0x54000001, Condition::NotEqual},
        Case{0x54000002, Condition::GreaterThanOrEqualUnsigned},
        Case{0x54000003, Condition::LessThanUnsigned},
        Case{0x54000004, Condition::Negative},
        Case{0x54000005, Condition::NotNegative},
        Case{0x54000006, Condition::Overflow},
        Case{0x54000007, Condition::NoOverflow},
        Case{0x54000008, Condition::GreaterThanUnsigned},
        Case{0x54000009, Condition::LessThanOrEqualUnsigned},
        Case{0x5400000a, Condition::GreaterThanOrEqualSigned},
        Case{0x5400000b, Condition::LessThanSigned},
        Case{0x5400000c, Condition::GreaterThanSigned},
        Case{0x5400000d, Condition::LessThanOrEqualSigned},
        Case{0x5400000e, Condition::Always},
        Case{0xb4000001, Condition::Zero},
        Case{0xb5000001, Condition::NotZero},
        Case{0x36200001, Condition::BitZero},
        Case{0x37200001, Condition::BitNotZero},
        Case{0x14000000, Condition::Always},
        Case{0x94000000, Condition::Always},
        Case{0xd61f0020, Condition::Always},
        Case{0xd65f03c0, Condition::Always},
        Case{0xd503201f, Condition::None},
    };
    for (const auto& item : cases) {
        std::array<std::uint8_t, 4> bytes{};
        for (std::size_t index = 0; index < bytes.size(); ++index)
            bytes[index] = static_cast<std::uint8_t>(item.word >> (8 * index));
        verify(address, bytes, item.condition);
        address += 16;
    }
}
}

int main(int argc, char** argv) {
    if (argc < 2 || !ida::database::init(argc, argv)
        || !ida::database::open(argv[1])) return 1;
    auto profile = ida::database::processor_profile();
    auto maximum = ida::database::max_address();
    CHECK(profile.has_value());
    CHECK(maximum.has_value());
    if (profile && maximum) {
        const auto start = (*maximum + 0x1fff) & ~ida::Address{0xfff};
        auto segment = ida::segment::create(start, start + 0x1000,
                                            "idax_branch_predicates", "CODE",
                                            ida::segment::Type::Code);
        CHECK(segment.has_value());
        if (segment) {
            CHECK(ida::segment::set_bitness(start, 64).has_value());
            if (profile->known_id == ida::database::ProcessorId::IntelX86)
                x86(start);
            else if (profile->known_id == ida::database::ProcessorId::Arm)
                arm64(start);
            else
                CHECK(false);
            CHECK(ida::segment::remove(start).has_value());
        }
    }
    CHECK(ida::instruction::branch_condition(ida::BadAddress) == Condition::None);
    CHECK(ida::database::close(false).has_value());
    std::printf("Branch predicates: %d passed, %d failed\n", passed, failed);
    return failed == 0 ? 0 : 1;
}

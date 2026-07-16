/// \file diaphora_exact_port_plugin.cpp
/// \brief Bounded idax port of Diaphora exact function fingerprints.
///
/// Adapted from Diaphora 3.4.0. Upstream copyright and AGPL-3.0-or-later
/// license notice are retained in diaphora_port_LICENSE.txt.

#include <ida/idax.hpp>

#include <algorithm>
#include <array>
#include <charconv>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <functional>
#include <iomanip>
#include <limits>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace {

constexpr std::string_view kHeader = "IDAX_DIAPHORA_EXACT\t1\tcanonical-cfg";
constexpr std::string_view kInstructionMetadataHeader =
    "IDAX_DIAPHORA_INSTRUCTION_METADATA\t1\texact-relative-offset";
constexpr std::string_view kPseudocodeCommentHeader =
    "IDAX_DIAPHORA_PSEUDOCODE_COMMENTS\t1\texact-tree-location";
constexpr std::string_view kReferentMetadataHeader =
    "IDAX_DIAPHORA_REFERENT_METADATA\t1\tunique-reference-class";
constexpr std::string_view kExportAction = "idax:diaphora:export_exact";
constexpr std::string_view kCompareAction = "idax:diaphora:compare_exact";
constexpr std::string_view kApplyAction = "idax:diaphora:apply_exact";
constexpr std::string_view kExportInstructionMetadataAction =
    "idax:diaphora:export_instruction_metadata";
constexpr std::string_view kCompareInstructionMetadataAction =
    "idax:diaphora:compare_instruction_metadata";
constexpr std::string_view kApplyInstructionMetadataAction =
    "idax:diaphora:apply_instruction_metadata";
constexpr std::string_view kExportPseudocodeCommentsAction =
    "idax:diaphora:export_pseudocode_comments";
constexpr std::string_view kComparePseudocodeCommentsAction =
    "idax:diaphora:compare_pseudocode_comments";
constexpr std::string_view kApplyPseudocodeCommentsAction =
    "idax:diaphora:apply_pseudocode_comments";
constexpr std::string_view kExportReferentMetadataAction =
    "idax:diaphora:export_referent_metadata";
constexpr std::string_view kCompareReferentMetadataAction =
    "idax:diaphora:compare_referent_metadata";
constexpr std::string_view kApplyReferentMetadataAction =
    "idax:diaphora:apply_referent_metadata";
constexpr std::string_view kMenuPath = "Edit/Plugins/";

class Md5 final {
public:
    void update(const std::uint8_t* data, std::size_t size) {
        bit_count_ += static_cast<std::uint64_t>(size) * 8U;
        while (size > 0) {
            const std::size_t count = std::min(size, block_.size() - block_size_);
            std::memcpy(block_.data() + block_size_, data, count);
            block_size_ += count;
            data += count;
            size -= count;
            if (block_size_ == block_.size()) {
                transform(block_.data());
                block_size_ = 0;
            }
        }
    }

    void update(const std::vector<std::uint8_t>& bytes) {
        update(bytes.data(), bytes.size());
    }

    [[nodiscard]] std::string finish_hex() {
        const std::uint64_t original_bits = bit_count_;
        const std::uint8_t marker = 0x80;
        update(&marker, 1);
        const std::uint8_t zero = 0;
        while (block_size_ != 56)
            update(&zero, 1);
        std::array<std::uint8_t, 8> length{};
        for (std::size_t index = 0; index < length.size(); ++index)
            length[index] = static_cast<std::uint8_t>(original_bits >> (index * 8));
        update(length.data(), length.size());

        std::ostringstream output;
        output << std::hex << std::setfill('0');
        for (const std::uint32_t word : state_) {
            for (unsigned shift = 0; shift < 32; shift += 8)
                output << std::setw(2) << ((word >> shift) & 0xffU);
        }
        return output.str();
    }

private:
    static constexpr std::array<std::uint32_t, 64> kShift = {
        7,12,17,22, 7,12,17,22, 7,12,17,22, 7,12,17,22,
        5, 9,14,20, 5, 9,14,20, 5, 9,14,20, 5, 9,14,20,
        4,11,16,23, 4,11,16,23, 4,11,16,23, 4,11,16,23,
        6,10,15,21, 6,10,15,21, 6,10,15,21, 6,10,15,21,
    };
    static constexpr std::array<std::uint32_t, 64> kConstant = {
        0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,
        0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
        0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,
        0x6b901122,0xfd987193,0xa679438e,0x49b40821,
        0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,
        0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
        0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,
        0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
        0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,
        0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
        0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,
        0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
        0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,
        0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
        0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,
        0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391,
    };

    static std::uint32_t rotate_left(std::uint32_t value, std::uint32_t count) {
        return (value << count) | (value >> (32U - count));
    }

    void transform(const std::uint8_t* block) {
        std::array<std::uint32_t, 16> words{};
        for (std::size_t index = 0; index < words.size(); ++index) {
            const std::size_t offset = index * 4;
            words[index] = static_cast<std::uint32_t>(block[offset])
                | (static_cast<std::uint32_t>(block[offset + 1]) << 8)
                | (static_cast<std::uint32_t>(block[offset + 2]) << 16)
                | (static_cast<std::uint32_t>(block[offset + 3]) << 24);
        }
        std::uint32_t a = state_[0];
        std::uint32_t b = state_[1];
        std::uint32_t c = state_[2];
        std::uint32_t d = state_[3];
        for (std::uint32_t index = 0; index < 64; ++index) {
            std::uint32_t function_value = 0;
            std::uint32_t word_index = 0;
            if (index < 16) {
                function_value = (b & c) | (~b & d);
                word_index = index;
            } else if (index < 32) {
                function_value = (d & b) | (~d & c);
                word_index = (5U * index + 1U) % 16U;
            } else if (index < 48) {
                function_value = b ^ c ^ d;
                word_index = (3U * index + 5U) % 16U;
            } else {
                function_value = c ^ (b | ~d);
                word_index = (7U * index) % 16U;
            }
            const std::uint32_t next_d = d;
            d = c;
            c = b;
            b += rotate_left(a + function_value + kConstant[index] + words[word_index],
                             kShift[index]);
            a = next_d;
        }
        state_[0] += a;
        state_[1] += b;
        state_[2] += c;
        state_[3] += d;
    }

    std::array<std::uint32_t, 4> state_{0x67452301, 0xefcdab89,
                                        0x98badcfe, 0x10325476};
    std::array<std::uint8_t, 64> block_{};
    std::size_t block_size_{0};
    std::uint64_t bit_count_{0};
};

struct FunctionRecord {
    ida::Address address{ida::BadAddress};
    std::size_t ordinal{0};
    std::uint64_t rva{0};
    std::uint64_t segment_rva{0};
    std::size_t nodes{0};
    std::size_t edges{0};
    std::int64_t complexity{0};
    std::size_t instructions{0};
    std::uint64_t byte_size{0};
    std::string full_md5;
    std::string relocation_md5;
    std::string name;
    std::string declaration;
    std::string repeatable_comment;
    std::string mnemonics;
};

enum class MatchTier {
    SameRvaBothHashes,
    BothHashes,
    FullHash,
    RelocationHashAndInstructionCount,
};

struct Match {
    std::size_t baseline{0};
    std::size_t current{0};
    MatchTier tier{MatchTier::BothHashes};
};

struct MatchSummary {
    std::vector<Match> matches;
    std::size_t ambiguous{0};
    std::size_t unmatched{0};
    std::array<std::size_t, 4> tiers{};
};

struct ApplySummary {
    std::size_t renamed{0};
    std::size_t declarations{0};
    std::size_t comments{0};
    std::size_t preserved{0};
    std::size_t failures{0};
};

struct ForcedOperandMetadata {
    std::size_t index{0};
    std::string text;

    bool operator==(const ForcedOperandMetadata&) const = default;
};

struct InstructionMetadataRecord {
    std::size_t function_ordinal{0};
    std::size_t instruction_ordinal{0};
    std::int64_t function_offset{0};
    std::size_t size{0};
    std::string full_md5;
    std::string relocation_md5;
    std::string mnemonic;
    std::string comment;
    std::string repeatable_comment;
    std::vector<ForcedOperandMetadata> forced_operands;

    bool operator==(const InstructionMetadataRecord&) const = default;
};

struct InstructionMetadataManifest {
    std::vector<FunctionRecord> functions;
    std::vector<InstructionMetadataRecord> instructions;
};

struct InstructionMetadataComparison {
    MatchSummary functions;
    std::vector<std::pair<std::size_t, ida::Address>> eligible;
    std::size_t unmatched_functions{0};
    std::size_t guard_failures{0};
};

struct InstructionMetadataApplySummary {
    std::size_t comments{0};
    std::size_t repeatable_comments{0};
    std::size_t forced_operands{0};
    std::size_t preserved{0};
    std::size_t failures{0};
};

enum class ReferentKind : std::uint8_t {
    Code,
    Data,
};

struct ReferentMetadataRecord {
    std::size_t function_ordinal{0};
    std::size_t instruction_ordinal{0};
    std::int64_t function_offset{0};
    std::size_t size{0};
    std::string full_md5;
    std::string relocation_md5;
    std::string mnemonic;
    ReferentKind kind{ReferentKind::Code};
    std::string name;
    std::string declaration;

    bool operator==(const ReferentMetadataRecord&) const = default;
};

struct ReferentMetadataManifest {
    std::vector<FunctionRecord> functions;
    std::vector<ReferentMetadataRecord> referents;
};

struct EligibleReferentMetadata {
    std::size_t metadata_index{0};
    ida::Address instruction_address{ida::BadAddress};
    ida::Address referent_address{ida::BadAddress};
};

struct ReferentMetadataComparison {
    MatchSummary functions;
    std::vector<EligibleReferentMetadata> eligible;
    std::size_t unmatched_functions{0};
    std::size_t instruction_guard_failures{0};
    std::size_t reference_guard_failures{0};
};

struct ReferentMetadataApplySummary {
    std::size_t names{0};
    std::size_t types{0};
    std::size_t preserved{0};
    std::size_t failures{0};
};

enum class PseudocodePositionKind : std::uint8_t {
    Default,
    Argument,
    ParenthesisOpen,
    Assembly,
    ElseLine,
    DoLine,
    Semicolon,
    OpenBrace,
    CloseBrace,
    ParenthesisClose,
    LabelColon,
    BlockBefore,
    BlockAfter,
    TryLine,
    SwitchCase,
};

struct PseudocodePosition {
    PseudocodePositionKind kind{PseudocodePositionKind::Default};
    std::int64_t detail{0};

    bool operator==(const PseudocodePosition&) const = default;
};

struct PseudocodeCommentRecord {
    std::size_t function_ordinal{0};
    std::size_t instruction_ordinal{0};
    std::int64_t function_offset{0};
    std::size_t size{0};
    std::string full_md5;
    std::string relocation_md5;
    std::string mnemonic;
    PseudocodePosition position;
    std::string text;

    bool operator==(const PseudocodeCommentRecord&) const = default;
};

struct PseudocodeCommentManifest {
    std::vector<FunctionRecord> functions;
    std::vector<PseudocodeCommentRecord> comments;
};

struct EligiblePseudocodeComment {
    std::size_t comment_index{0};
    ida::Address function_address{ida::BadAddress};
    ida::Address comment_address{ida::BadAddress};
};

struct PseudocodeCommentComparison {
    MatchSummary functions;
    std::vector<EligiblePseudocodeComment> eligible;
    std::size_t unmatched_functions{0};
    std::size_t guard_failures{0};
};

struct PseudocodeCommentApplySummary {
    std::size_t comments{0};
    std::size_t preserved{0};
    std::size_t failures{0};
    std::size_t saved_functions{0};
};

struct InstructionFingerprint {
    std::size_t size{0};
    std::string full_md5;
    std::string relocation_md5;
    std::string mnemonic;
    std::vector<std::size_t> operand_indices;
};

std::string hex_encode(std::string_view input) {
    constexpr char digits[] = "0123456789abcdef";
    std::string output;
    output.reserve(input.size() * 2);
    for (const unsigned char byte : input) {
        output.push_back(digits[byte >> 4]);
        output.push_back(digits[byte & 0x0f]);
    }
    return output;
}

bool valid_utf8(std::string_view input) {
    const auto* bytes = reinterpret_cast<const unsigned char*>(input.data());
    std::size_t index = 0;
    while (index < input.size()) {
        const unsigned char lead = bytes[index++];
        if (lead <= 0x7f)
            continue;

        std::size_t continuation_count = 0;
        std::uint32_t code_point = 0;
        std::uint32_t minimum = 0;
        if (lead >= 0xc2 && lead <= 0xdf) {
            continuation_count = 1;
            code_point = lead & 0x1fU;
            minimum = 0x80;
        } else if (lead >= 0xe0 && lead <= 0xef) {
            continuation_count = 2;
            code_point = lead & 0x0fU;
            minimum = 0x800;
        } else if (lead >= 0xf0 && lead <= 0xf4) {
            continuation_count = 3;
            code_point = lead & 0x07U;
            minimum = 0x10000;
        } else {
            return false;
        }
        if (continuation_count > input.size() - index)
            return false;
        for (std::size_t count = 0; count < continuation_count; ++count) {
            const unsigned char continuation = bytes[index++];
            if ((continuation & 0xc0U) != 0x80U)
                return false;
            code_point = (code_point << 6U) | (continuation & 0x3fU);
        }
        if (code_point < minimum || code_point > 0x10ffffU
            || (code_point >= 0xd800U && code_point <= 0xdfffU)) {
            return false;
        }
    }
    return true;
}

std::optional<std::string> hex_decode(std::string_view input) {
    if ((input.size() & 1U) != 0)
        return std::nullopt;
    auto nibble = [](char value) -> std::optional<unsigned> {
        if (value >= '0' && value <= '9') return value - '0';
        if (value >= 'a' && value <= 'f') return value - 'a' + 10U;
        if (value >= 'A' && value <= 'F') return value - 'A' + 10U;
        return std::nullopt;
    };
    std::string output;
    output.reserve(input.size() / 2);
    for (std::size_t index = 0; index < input.size(); index += 2) {
        const auto high = nibble(input[index]);
        const auto low = nibble(input[index + 1]);
        if (!high || !low)
            return std::nullopt;
        output.push_back(static_cast<char>((*high << 4) | *low));
    }
    if (!valid_utf8(output))
        return std::nullopt;
    return output;
}

std::optional<std::string> normalize_md5(std::string_view input) {
    if (input.size() != 32)
        return std::nullopt;
    std::string output;
    output.reserve(input.size());
    for (const unsigned char byte : input) {
        if (!std::isxdigit(byte))
            return std::nullopt;
        output.push_back(static_cast<char>(std::tolower(byte)));
    }
    return output;
}

template <typename Integer>
bool parse_integer(std::string_view text, Integer& output, int base = 10) {
    const char* begin = text.data();
    const char* end = begin + text.size();
    const auto result = std::from_chars(begin, end, output, base);
    return result.ec == std::errc{} && result.ptr == end;
}

std::vector<std::string_view> split_tabs(std::string_view line) {
    std::vector<std::string_view> fields;
    std::size_t start = 0;
    while (true) {
        const std::size_t tab = line.find('\t', start);
        fields.push_back(line.substr(start, tab == std::string_view::npos
                                               ? line.size() - start
                                               : tab - start));
        if (tab == std::string_view::npos)
            return fields;
        start = tab + 1;
    }
}

std::string format_record(const FunctionRecord& record) {
    std::ostringstream output;
    output << "F\t" << record.ordinal << '\t' << std::hex << record.rva << '\t'
           << record.segment_rva << std::dec << '\t' << record.nodes << '\t'
           << record.edges << '\t' << record.complexity << '\t'
           << record.instructions << '\t' << record.byte_size << '\t'
           << record.full_md5 << '\t' << record.relocation_md5 << '\t'
           << hex_encode(record.name) << '\t' << hex_encode(record.declaration) << '\t'
           << hex_encode(record.repeatable_comment) << '\t' << hex_encode(record.mnemonics);
    return output.str();
}

ida::Result<std::vector<FunctionRecord>> parse_manifest(std::string_view text) {
    std::istringstream input{std::string(text)};
    std::string line;
    if (!std::getline(input, line) || line != kHeader)
        return std::unexpected(ida::Error::validation("Unsupported Diaphora exact manifest header"));
    std::vector<FunctionRecord> records;
    while (std::getline(input, line)) {
        if (line.empty())
            continue;
        if (!line.empty() && line.back() == '\r')
            line.pop_back();
        const auto fields = split_tabs(line);
        if (fields.size() != 15 || fields[0] != "F")
            return std::unexpected(ida::Error::validation("Malformed Diaphora exact manifest record"));
        FunctionRecord record;
        if (!parse_integer(fields[1], record.ordinal)
            || !parse_integer(fields[2], record.rva, 16)
            || !parse_integer(fields[3], record.segment_rva, 16)
            || !parse_integer(fields[4], record.nodes)
            || !parse_integer(fields[5], record.edges)
            || !parse_integer(fields[6], record.complexity)
            || !parse_integer(fields[7], record.instructions)
            || !parse_integer(fields[8], record.byte_size)) {
            return std::unexpected(ida::Error::validation("Invalid numeric manifest field"));
        }
        auto full_md5 = normalize_md5(fields[9]);
        auto relocation_md5 = normalize_md5(fields[10]);
        auto name = hex_decode(fields[11]);
        auto declaration = hex_decode(fields[12]);
        auto comment = hex_decode(fields[13]);
        auto mnemonics = hex_decode(fields[14]);
        if (!full_md5 || !relocation_md5 || !name || !declaration
            || !comment || !mnemonics) {
            return std::unexpected(ida::Error::validation("Invalid hash or encoded manifest field"));
        }
        record.full_md5 = std::move(*full_md5);
        record.relocation_md5 = std::move(*relocation_md5);
        record.name = std::move(*name);
        record.declaration = std::move(*declaration);
        record.repeatable_comment = std::move(*comment);
        record.mnemonics = std::move(*mnemonics);
        records.push_back(std::move(record));
    }
    return records;
}

std::string format_manifest(const std::vector<FunctionRecord>& records) {
    std::string output(kHeader);
    output.push_back('\n');
    for (const auto& record : records) {
        output += format_record(record);
        output.push_back('\n');
    }
    return output;
}

std::string format_forced_operands(
    const std::vector<ForcedOperandMetadata>& operands) {
    std::string output;
    for (const auto& operand : operands) {
        output += std::to_string(operand.index);
        output.push_back(':');
        output += std::to_string(operand.text.size());
        output.push_back(':');
        output += operand.text;
    }
    return output;
}

ida::Result<std::vector<ForcedOperandMetadata>> parse_forced_operands(
    std::string_view payload) {
    std::vector<ForcedOperandMetadata> operands;
    std::size_t cursor = 0;
    std::optional<std::size_t> previous_index;
    while (cursor < payload.size()) {
        const std::size_t index_end = payload.find(':', cursor);
        if (index_end == std::string_view::npos || index_end == cursor)
            return std::unexpected(ida::Error::validation("Malformed forced operand index"));
        std::size_t operand_index = 0;
        if (!parse_integer(payload.substr(cursor, index_end - cursor), operand_index)
            || operand_index > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
            return std::unexpected(ida::Error::validation("Invalid forced operand index"));
        }

        cursor = index_end + 1;
        const std::size_t length_end = payload.find(':', cursor);
        if (length_end == std::string_view::npos || length_end == cursor)
            return std::unexpected(ida::Error::validation("Malformed forced operand length"));
        std::size_t text_size = 0;
        if (!parse_integer(payload.substr(cursor, length_end - cursor), text_size))
            return std::unexpected(ida::Error::validation("Invalid forced operand length"));
        cursor = length_end + 1;
        if (text_size == 0 || text_size > payload.size() - cursor)
            return std::unexpected(ida::Error::validation("Truncated forced operand text"));
        std::string text(payload.substr(cursor, text_size));
        if (!valid_utf8(text) || text.find('\0') != std::string::npos)
            return std::unexpected(ida::Error::validation("Forced operand text is not UTF-8"));
        if (previous_index && operand_index <= *previous_index)
            return std::unexpected(ida::Error::validation(
                "Forced operand indices are duplicate or unsorted"));
        operands.push_back({operand_index, std::move(text)});
        previous_index = operand_index;
        cursor += text_size;
    }
    return operands;
}

std::string format_instruction_metadata_record(
    const InstructionMetadataRecord& record) {
    std::ostringstream output;
    output << "I\t" << record.function_ordinal << '\t'
           << record.instruction_ordinal << '\t' << record.function_offset << '\t'
           << record.size << '\t' << record.full_md5 << '\t'
           << record.relocation_md5 << '\t' << hex_encode(record.mnemonic) << '\t'
           << hex_encode(record.comment) << '\t'
           << hex_encode(record.repeatable_comment) << '\t'
           << hex_encode(format_forced_operands(record.forced_operands));
    return output.str();
}

std::string format_instruction_metadata_manifest(
    const InstructionMetadataManifest& manifest) {
    std::string output(kInstructionMetadataHeader);
    output.push_back('\n');
    for (const auto& function : manifest.functions) {
        output += format_record(function);
        output.push_back('\n');
    }
    for (const auto& instruction : manifest.instructions) {
        output += format_instruction_metadata_record(instruction);
        output.push_back('\n');
    }
    return output;
}

ida::Result<InstructionMetadataManifest> parse_instruction_metadata_manifest(
    std::string_view text) {
    std::istringstream input{std::string(text)};
    std::string line;
    if (!std::getline(input, line) || line != kInstructionMetadataHeader) {
        return std::unexpected(ida::Error::validation(
            "Unsupported Diaphora instruction metadata manifest header"));
    }

    std::string function_text(kHeader);
    function_text.push_back('\n');
    InstructionMetadataManifest manifest;
    std::unordered_set<std::string> instruction_keys;
    while (std::getline(input, line)) {
        if (line.empty())
            continue;
        if (!line.empty() && line.back() == '\r')
            line.pop_back();
        const auto fields = split_tabs(line);
        if (!fields.empty() && fields[0] == "F") {
            function_text += line;
            function_text.push_back('\n');
            continue;
        }
        if (fields.size() != 11 || fields[0] != "I") {
            return std::unexpected(ida::Error::validation(
                "Malformed Diaphora instruction metadata record"));
        }

        InstructionMetadataRecord record;
        if (!parse_integer(fields[1], record.function_ordinal)
            || !parse_integer(fields[2], record.instruction_ordinal)
            || !parse_integer(fields[3], record.function_offset)
            || !parse_integer(fields[4], record.size) || record.size == 0) {
            return std::unexpected(ida::Error::validation(
                "Invalid instruction metadata numeric field"));
        }
        auto full_md5 = normalize_md5(fields[5]);
        auto relocation_md5 = normalize_md5(fields[6]);
        auto mnemonic = hex_decode(fields[7]);
        auto comment = hex_decode(fields[8]);
        auto repeatable_comment = hex_decode(fields[9]);
        auto forced_payload = hex_decode(fields[10]);
        if (!full_md5 || !relocation_md5 || !mnemonic || !comment
            || !repeatable_comment || !forced_payload) {
            return std::unexpected(ida::Error::validation(
                "Invalid instruction metadata hash or encoded field"));
        }
        auto forced_operands = parse_forced_operands(*forced_payload);
        if (!forced_operands)
            return std::unexpected(forced_operands.error());
        if (mnemonic->find('\0') != std::string::npos
            || comment->find('\0') != std::string::npos
            || repeatable_comment->find('\0') != std::string::npos) {
            return std::unexpected(ida::Error::validation(
                "Instruction metadata text contains NUL"));
        }
        if (comment->empty() && repeatable_comment->empty()
            && forced_operands->empty()) {
            return std::unexpected(ida::Error::validation(
                "Instruction metadata record contains no metadata"));
        }

        const std::string record_key = std::to_string(record.function_ordinal)
            + ":" + std::to_string(record.instruction_ordinal);
        if (!instruction_keys.insert(record_key).second) {
            return std::unexpected(ida::Error::validation(
                "Duplicate instruction metadata record"));
        }
        record.full_md5 = std::move(*full_md5);
        record.relocation_md5 = std::move(*relocation_md5);
        record.mnemonic = std::move(*mnemonic);
        record.comment = std::move(*comment);
        record.repeatable_comment = std::move(*repeatable_comment);
        record.forced_operands = std::move(*forced_operands);
        manifest.instructions.push_back(std::move(record));
    }

    auto functions = parse_manifest(function_text);
    if (!functions)
        return std::unexpected(functions.error());
    manifest.functions = std::move(*functions);
    std::unordered_set<std::size_t> ordinals;
    for (const auto& function : manifest.functions) {
        if (!ordinals.insert(function.ordinal).second)
            return std::unexpected(ida::Error::validation("Duplicate function ordinal"));
    }
    for (const auto& instruction : manifest.instructions) {
        if (!ordinals.contains(instruction.function_ordinal)) {
            return std::unexpected(ida::Error::validation(
                "Instruction metadata references an unknown function"));
        }
    }
    return manifest;
}

std::string_view referent_kind_name(ReferentKind kind) {
    return kind == ReferentKind::Code ? "code" : "data";
}

ida::Result<ReferentKind> parse_referent_kind(std::string_view name) {
    if (name == "code")
        return ReferentKind::Code;
    if (name == "data")
        return ReferentKind::Data;
    return std::unexpected(ida::Error::validation(
        "Unknown referent metadata class", std::string(name)));
}

std::string format_referent_metadata_record(
    const ReferentMetadataRecord& record) {
    std::ostringstream output;
    output << "R\t" << record.function_ordinal << '\t'
           << record.instruction_ordinal << '\t' << record.function_offset << '\t'
           << record.size << '\t' << record.full_md5 << '\t'
           << record.relocation_md5 << '\t' << hex_encode(record.mnemonic) << '\t'
           << referent_kind_name(record.kind) << '\t' << hex_encode(record.name)
           << '\t' << hex_encode(record.declaration);
    return output.str();
}

std::string format_referent_metadata_manifest(
    const ReferentMetadataManifest& manifest) {
    std::string output(kReferentMetadataHeader);
    output.push_back('\n');
    for (const auto& function : manifest.functions) {
        output += format_record(function);
        output.push_back('\n');
    }
    for (const auto& referent : manifest.referents) {
        output += format_referent_metadata_record(referent);
        output.push_back('\n');
    }
    return output;
}

ida::Result<ReferentMetadataManifest> parse_referent_metadata_manifest(
    std::string_view text) {
    std::istringstream input{std::string(text)};
    std::string line;
    if (!std::getline(input, line) || line != kReferentMetadataHeader) {
        return std::unexpected(ida::Error::validation(
            "Unsupported Diaphora referent metadata manifest header"));
    }

    std::string function_text(kHeader);
    function_text.push_back('\n');
    ReferentMetadataManifest manifest;
    std::unordered_set<std::string> referent_keys;
    while (std::getline(input, line)) {
        if (line.empty())
            continue;
        if (!line.empty() && line.back() == '\r')
            line.pop_back();
        const auto fields = split_tabs(line);
        if (!fields.empty() && fields[0] == "F") {
            function_text += line;
            function_text.push_back('\n');
            continue;
        }
        if (fields.size() != 11 || fields[0] != "R") {
            return std::unexpected(ida::Error::validation(
                "Malformed Diaphora referent metadata record"));
        }

        ReferentMetadataRecord record;
        if (!parse_integer(fields[1], record.function_ordinal)
            || !parse_integer(fields[2], record.instruction_ordinal)
            || !parse_integer(fields[3], record.function_offset)
            || !parse_integer(fields[4], record.size) || record.size == 0) {
            return std::unexpected(ida::Error::validation(
                "Invalid referent metadata numeric field"));
        }
        auto full_md5 = normalize_md5(fields[5]);
        auto relocation_md5 = normalize_md5(fields[6]);
        auto mnemonic = hex_decode(fields[7]);
        auto kind = parse_referent_kind(fields[8]);
        auto name = hex_decode(fields[9]);
        auto declaration = hex_decode(fields[10]);
        if (!full_md5 || !relocation_md5 || !mnemonic || !kind
            || !name || !declaration) {
            return std::unexpected(ida::Error::validation(
                "Invalid referent metadata hash, class, or encoded field"));
        }
        if (mnemonic->find('\0') != std::string::npos
            || name->find('\0') != std::string::npos
            || declaration->find('\0') != std::string::npos) {
            return std::unexpected(ida::Error::validation(
                "Referent metadata text contains NUL"));
        }
        if (name->empty() && declaration->empty()) {
            return std::unexpected(ida::Error::validation(
                "Referent metadata record contains no metadata"));
        }

        const std::string record_key = std::to_string(record.function_ordinal)
            + ":" + std::to_string(record.instruction_ordinal)
            + ":" + std::string(referent_kind_name(*kind));
        if (!referent_keys.insert(record_key).second) {
            return std::unexpected(ida::Error::validation(
                "Duplicate referent metadata record"));
        }
        record.full_md5 = std::move(*full_md5);
        record.relocation_md5 = std::move(*relocation_md5);
        record.mnemonic = std::move(*mnemonic);
        record.kind = *kind;
        record.name = std::move(*name);
        record.declaration = std::move(*declaration);
        manifest.referents.push_back(std::move(record));
    }

    auto functions = parse_manifest(function_text);
    if (!functions)
        return std::unexpected(functions.error());
    manifest.functions = std::move(*functions);
    std::unordered_set<std::size_t> ordinals;
    for (const auto& function : manifest.functions) {
        if (!ordinals.insert(function.ordinal).second)
            return std::unexpected(ida::Error::validation(
                "Duplicate function ordinal"));
    }
    for (const auto& referent : manifest.referents) {
        if (!ordinals.contains(referent.function_ordinal)) {
            return std::unexpected(ida::Error::validation(
                "Referent metadata references an unknown function"));
        }
    }
    return manifest;
}

std::string_view pseudocode_position_name(
    PseudocodePositionKind kind) {
    using Kind = PseudocodePositionKind;
    switch (kind) {
    case Kind::Default: return "default";
    case Kind::Argument: return "argument";
    case Kind::ParenthesisOpen: return "parenthesis-open";
    case Kind::Assembly: return "assembly";
    case Kind::ElseLine: return "else-line";
    case Kind::DoLine: return "do-line";
    case Kind::Semicolon: return "semicolon";
    case Kind::OpenBrace: return "open-brace";
    case Kind::CloseBrace: return "close-brace";
    case Kind::ParenthesisClose: return "parenthesis-close";
    case Kind::LabelColon: return "label-colon";
    case Kind::BlockBefore: return "block-before";
    case Kind::BlockAfter: return "block-after";
    case Kind::TryLine: return "try-line";
    case Kind::SwitchCase: return "switch-case";
    }
    return "unknown";
}

std::int64_t pseudocode_position_detail(
    const PseudocodePosition& position) {
    return position.detail;
}

ida::Result<PseudocodePosition> parse_pseudocode_position(
    std::string_view name, std::int64_t detail) {
    using Kind = PseudocodePositionKind;
    auto simple = [&](std::string_view expected,
                      Kind kind) -> std::optional<PseudocodePosition> {
        if (name == expected && detail == 0)
            return PseudocodePosition{kind, 0};
        return std::nullopt;
    };
    if (auto value = simple("default", Kind::Default)) return *value;
    if (auto value = simple("parenthesis-open", Kind::ParenthesisOpen)) return *value;
    if (auto value = simple("assembly", Kind::Assembly)) return *value;
    if (auto value = simple("else-line", Kind::ElseLine)) return *value;
    if (auto value = simple("do-line", Kind::DoLine)) return *value;
    if (auto value = simple("semicolon", Kind::Semicolon)) return *value;
    if (auto value = simple("open-brace", Kind::OpenBrace)) return *value;
    if (auto value = simple("close-brace", Kind::CloseBrace)) return *value;
    if (auto value = simple("parenthesis-close", Kind::ParenthesisClose)) return *value;
    if (auto value = simple("label-colon", Kind::LabelColon)) return *value;
    if (auto value = simple("block-before", Kind::BlockBefore)) return *value;
    if (auto value = simple("block-after", Kind::BlockAfter)) return *value;
    if (auto value = simple("try-line", Kind::TryLine)) return *value;
    if (name == "argument") {
        if (detail < 0 || detail > 63)
            return std::unexpected(ida::Error::validation(
                "Pseudocode comment argument index must be in [0, 63]"));
        return PseudocodePosition{Kind::Argument, detail};
    }
    if (name == "switch-case") {
        constexpr std::int64_t maximum = 0x1fffffff;
        if (detail < -maximum || detail > maximum)
            return std::unexpected(ida::Error::validation(
                "Pseudocode switch-case comment value exceeds the supported range"));
        return PseudocodePosition{Kind::SwitchCase, detail};
    }
    if (name == "default" || name == "parenthesis-open" || name == "assembly"
        || name == "else-line" || name == "do-line" || name == "semicolon"
        || name == "open-brace" || name == "close-brace"
        || name == "parenthesis-close" || name == "label-colon"
        || name == "block-before" || name == "block-after" || name == "try-line") {
        return std::unexpected(ida::Error::validation(
            "Simple pseudocode comment position detail must be zero"));
    }
    return std::unexpected(ida::Error::validation(
        "Unknown pseudocode comment position", std::string(name)));
}

ida::Result<PseudocodePosition> to_manifest_position(
    const ida::decompiler::CommentPosition& position) {
    using Public = ida::decompiler::CommentPositionKind;
    using Kind = PseudocodePositionKind;
    Kind kind = Kind::Default;
    switch (position.kind()) {
    case Public::Default: kind = Kind::Default; break;
    case Public::Argument: kind = Kind::Argument; break;
    case Public::ParenthesisOpen: kind = Kind::ParenthesisOpen; break;
    case Public::Assembly: kind = Kind::Assembly; break;
    case Public::ElseLine: kind = Kind::ElseLine; break;
    case Public::DoLine: kind = Kind::DoLine; break;
    case Public::Semicolon: kind = Kind::Semicolon; break;
    case Public::OpenBrace: kind = Kind::OpenBrace; break;
    case Public::CloseBrace: kind = Kind::CloseBrace; break;
    case Public::ParenthesisClose: kind = Kind::ParenthesisClose; break;
    case Public::LabelColon: kind = Kind::LabelColon; break;
    case Public::BlockBefore: kind = Kind::BlockBefore; break;
    case Public::BlockAfter: kind = Kind::BlockAfter; break;
    case Public::TryLine: kind = Kind::TryLine; break;
    case Public::SwitchCase: kind = Kind::SwitchCase; break;
    }
    std::int64_t detail = 0;
    if (const auto index = position.argument_index())
        detail = static_cast<std::int64_t>(*index);
    else if (const auto value = position.switch_case_value())
        detail = *value;
    return parse_pseudocode_position(pseudocode_position_name(kind), detail);
}

ida::Result<ida::decompiler::CommentPosition> to_public_position(
    const PseudocodePosition& position) {
    using Kind = PseudocodePositionKind;
    using Public = ida::decompiler::CommentPosition;
    switch (position.kind) {
    case Kind::Default: return Public::Default;
    case Kind::Argument: return Public::argument(
        static_cast<std::size_t>(position.detail));
    case Kind::ParenthesisOpen: return Public::ParenthesisOpen;
    case Kind::Assembly: return Public::Assembly;
    case Kind::ElseLine: return Public::ElseLine;
    case Kind::DoLine: return Public::DoLine;
    case Kind::Semicolon: return Public::Semicolon;
    case Kind::OpenBrace: return Public::OpenBrace;
    case Kind::CloseBrace: return Public::CloseBrace;
    case Kind::ParenthesisClose: return Public::ParenthesisClose;
    case Kind::LabelColon: return Public::LabelColon;
    case Kind::BlockBefore: return Public::BlockBefore;
    case Kind::BlockAfter: return Public::BlockAfter;
    case Kind::TryLine: return Public::TryLine;
    case Kind::SwitchCase: return Public::switch_case(position.detail);
    }
    return std::unexpected(ida::Error::internal(
        "Unknown pseudocode comment position kind"));
}

std::string format_pseudocode_comment_record(
    const PseudocodeCommentRecord& record) {
    std::ostringstream output;
    output << "P\t" << record.function_ordinal << '\t'
           << record.instruction_ordinal << '\t' << record.function_offset << '\t'
           << record.size << '\t' << record.full_md5 << '\t'
           << record.relocation_md5 << '\t' << hex_encode(record.mnemonic) << '\t'
           << pseudocode_position_name(record.position.kind) << '\t'
           << pseudocode_position_detail(record.position) << '\t'
           << hex_encode(record.text);
    return output.str();
}

std::string format_pseudocode_comment_manifest(
    const PseudocodeCommentManifest& manifest) {
    std::string output(kPseudocodeCommentHeader);
    output.push_back('\n');
    for (const auto& function : manifest.functions) {
        output += format_record(function);
        output.push_back('\n');
    }
    for (const auto& comment : manifest.comments) {
        output += format_pseudocode_comment_record(comment);
        output.push_back('\n');
    }
    return output;
}

ida::Result<PseudocodeCommentManifest> parse_pseudocode_comment_manifest(
    std::string_view text) {
    std::istringstream input{std::string(text)};
    std::string line;
    if (!std::getline(input, line) || line != kPseudocodeCommentHeader) {
        return std::unexpected(ida::Error::validation(
            "Unsupported Diaphora pseudocode comment manifest header"));
    }

    std::string function_text(kHeader);
    function_text.push_back('\n');
    PseudocodeCommentManifest manifest;
    std::unordered_set<std::string> comment_keys;
    while (std::getline(input, line)) {
        if (line.empty())
            continue;
        if (!line.empty() && line.back() == '\r')
            line.pop_back();
        const auto fields = split_tabs(line);
        if (!fields.empty() && fields[0] == "F") {
            function_text += line;
            function_text.push_back('\n');
            continue;
        }
        if (fields.size() != 11 || fields[0] != "P") {
            return std::unexpected(ida::Error::validation(
                "Malformed Diaphora pseudocode comment record"));
        }

        PseudocodeCommentRecord record;
        std::int64_t position_detail = 0;
        if (!parse_integer(fields[1], record.function_ordinal)
            || !parse_integer(fields[2], record.instruction_ordinal)
            || !parse_integer(fields[3], record.function_offset)
            || !parse_integer(fields[4], record.size) || record.size == 0
            || !parse_integer(fields[9], position_detail)) {
            return std::unexpected(ida::Error::validation(
                "Invalid pseudocode comment numeric field"));
        }
        auto full_md5 = normalize_md5(fields[5]);
        auto relocation_md5 = normalize_md5(fields[6]);
        auto mnemonic = hex_decode(fields[7]);
        auto position = parse_pseudocode_position(fields[8], position_detail);
        auto comment = hex_decode(fields[10]);
        if (!full_md5 || !relocation_md5 || !mnemonic || !position || !comment) {
            return std::unexpected(ida::Error::validation(
                "Invalid pseudocode comment hash, position, or encoded field"));
        }
        if (mnemonic->find('\0') != std::string::npos
            || comment->empty() || comment->find('\0') != std::string::npos) {
            return std::unexpected(ida::Error::validation(
                "Pseudocode comment text is empty or contains NUL"));
        }
        const std::string record_key = std::to_string(record.function_ordinal)
            + ":" + std::to_string(record.instruction_ordinal)
            + ":" + std::string(fields[8]) + ":" + std::to_string(position_detail);
        if (!comment_keys.insert(record_key).second) {
            return std::unexpected(ida::Error::validation(
                "Duplicate pseudocode comment location record"));
        }
        record.full_md5 = std::move(*full_md5);
        record.relocation_md5 = std::move(*relocation_md5);
        record.mnemonic = std::move(*mnemonic);
        record.position = std::move(*position);
        record.text = std::move(*comment);
        manifest.comments.push_back(std::move(record));
    }

    auto functions = parse_manifest(function_text);
    if (!functions)
        return std::unexpected(functions.error());
    manifest.functions = std::move(*functions);
    std::unordered_set<std::size_t> ordinals;
    for (const auto& function : manifest.functions) {
        if (!ordinals.insert(function.ordinal).second)
            return std::unexpected(ida::Error::validation("Duplicate function ordinal"));
    }
    for (const auto& comment : manifest.comments) {
        if (!ordinals.contains(comment.function_ordinal)) {
            return std::unexpected(ida::Error::validation(
                "Pseudocode comment references an unknown function"));
        }
    }
    return manifest;
}

ida::Result<std::string> read_text_file(std::string_view path) {
    std::ifstream input(std::string(path), std::ios::binary);
    if (!input)
        return std::unexpected(ida::Error::not_found("Unable to open manifest", std::string(path)));
    std::ostringstream content;
    content << input.rdbuf();
    if (!input.good() && !input.eof())
        return std::unexpected(ida::Error::sdk("Unable to read manifest", std::string(path)));
    return content.str();
}

ida::Status write_text_file(std::string_view path, std::string_view text) {
    std::ofstream output(std::string(path), std::ios::binary | std::ios::trunc);
    if (!output)
        return std::unexpected(ida::Error::sdk("Unable to create manifest", std::string(path)));
    output.write(text.data(), static_cast<std::streamsize>(text.size()));
    if (!output)
        return std::unexpected(ida::Error::sdk("Unable to write manifest", std::string(path)));
    return ida::ok();
}

bool normalized_operand_type(ida::instruction::OperandType type) {
    using enum ida::instruction::OperandType;
    return type == MemoryDirect || type == Immediate || type == FarAddress
        || type == NearAddress || type == MemoryDisplacement;
}

struct OperandEncoding {
    bool normalizable{false};
    std::optional<std::size_t> primary;
    std::optional<std::size_t> secondary;
};

ida::Result<std::size_t> normalized_prefix_size(
    std::size_t instruction_size,
    const std::vector<OperandEncoding>& operands) {
    if (instruction_size == 0)
        return std::unexpected(ida::Error::validation("Decoded zero-byte instruction"));
    std::size_t normalized_size = instruction_size;
    const std::size_t operand_limit = std::min<std::size_t>(2, operands.size());
    for (std::size_t index = 0; index < operand_limit; ++index) {
        const auto& operand = operands[index];
        for (const auto offset : {operand.primary, operand.secondary}) {
            if (offset && *offset >= instruction_size)
                return std::unexpected(ida::Error::validation(
                    "Encoded operand byte position is outside its instruction"));
        }
        if (operand.normalizable && operand.primary)
            normalized_size = normalized_size > *operand.primary
                ? normalized_size - *operand.primary : 1;
    }
    return std::max<std::size_t>(1, normalized_size);
}

std::int64_t canonical_complexity(std::size_t nodes, std::size_t edges) {
    return static_cast<std::int64_t>(edges)
        - static_cast<std::int64_t>(nodes) + 2;
}

ida::Result<FunctionRecord> extract_record(const ida::function::Function& function,
                                           std::size_t ordinal,
                                           ida::Address image_base) {
    FunctionRecord record;
    record.address = function.start();
    record.ordinal = ordinal;
    if (function.start() < image_base)
        return std::unexpected(ida::Error::validation("Function entry precedes image base"));
    record.rva = function.start() - image_base;
    if (!ida::name::is_auto_generated(function.start()))
        record.name = function.name();

    auto segment = ida::segment::at(function.start());
    if (!segment)
        return std::unexpected(segment.error());
    record.segment_rva = function.start() - segment->start();

    auto blocks = ida::graph::flowchart(function.start());
    if (!blocks)
        return std::unexpected(blocks.error());
    record.nodes = blocks->size();
    for (const auto& block : *blocks)
        record.edges += block.successors.size();
    record.complexity = canonical_complexity(record.nodes, record.edges);

    auto declaration = ida::function::declaration(
        function.start(), "__idax_diaphora_function");
    if (declaration)
        record.declaration = std::move(*declaration);
    else if (declaration.error().category != ida::ErrorCategory::NotFound)
        return std::unexpected(declaration.error());
    auto comment = ida::function::comment(function.start(), true);
    if (comment)
        record.repeatable_comment = std::move(*comment);
    else if (comment.error().category != ida::ErrorCategory::NotFound)
        return std::unexpected(comment.error());

    auto addresses = ida::function::code_addresses(function.start());
    if (!addresses)
        return std::unexpected(addresses.error());
    std::sort(addresses->begin(), addresses->end());
    Md5 full_hash;
    Md5 relocation_hash;
    bool first_mnemonic = true;
    for (const ida::Address address : *addresses) {
        auto instruction = ida::instruction::decode(address);
        if (!instruction)
            return std::unexpected(instruction.error());
        const std::size_t size = static_cast<std::size_t>(instruction->size());
        if (size == 0)
            return std::unexpected(ida::Error::validation("Decoded zero-byte instruction"));
        auto bytes = ida::data::read_bytes(address, instruction->size());
        if (!bytes)
            return std::unexpected(bytes.error());
        if (bytes->size() != size)
            return std::unexpected(ida::Error::sdk("Instruction byte read was truncated"));

        std::vector<OperandEncoding> operand_encodings;
        const std::size_t operand_limit = std::min<std::size_t>(
            2, instruction->operands().size());
        operand_encodings.reserve(operand_limit);
        for (std::size_t index = 0; index < operand_limit; ++index) {
            const auto& operand = instruction->operands()[index];
            operand_encodings.push_back({
                normalized_operand_type(operand.type()),
                operand.encoded_value_byte_offset(),
                operand.secondary_encoded_value_byte_offset(),
            });
        }
        auto normalized_size = normalized_prefix_size(size, operand_encodings);
        if (!normalized_size)
            return std::unexpected(normalized_size.error());
        full_hash.update(*bytes);
        relocation_hash.update(bytes->data(), *normalized_size);
        if (instruction->size() > std::numeric_limits<std::uint64_t>::max()
                                      - record.byte_size) {
            return std::unexpected(ida::Error::validation("Function byte size overflow"));
        }
        record.byte_size += instruction->size();
        ++record.instructions;
        if (!first_mnemonic)
            record.mnemonics.push_back(',');
        first_mnemonic = false;
        record.mnemonics += instruction->mnemonic();
    }
    if (!valid_utf8(record.name) || !valid_utf8(record.declaration)
        || !valid_utf8(record.repeatable_comment) || !valid_utf8(record.mnemonics)) {
        return std::unexpected(ida::Error::validation(
            "Function metadata is not valid UTF-8"));
    }
    record.full_md5 = full_hash.finish_hex();
    record.relocation_md5 = relocation_hash.finish_hex();
    return record;
}

ida::Result<std::vector<FunctionRecord>> extract_manifest() {
    auto image_base = ida::database::image_base();
    if (!image_base)
        return std::unexpected(image_base.error());
    std::vector<ida::function::Function> functions;
    for (const auto& function : ida::function::all())
        functions.push_back(function);
    std::sort(functions.begin(), functions.end(), [](const auto& left, const auto& right) {
        return left.start() < right.start();
    });
    std::vector<FunctionRecord> records;
    records.reserve(functions.size());
    for (std::size_t index = 0; index < functions.size(); ++index) {
        auto record = extract_record(functions[index], index, *image_base);
        if (!record)
            return std::unexpected(record.error());
        records.push_back(std::move(*record));
    }
    return records;
}

ida::Result<std::int64_t> relative_offset(ida::Address address,
                                          ida::Address function_start) {
    if (address >= function_start) {
        const std::uint64_t magnitude = address - function_start;
        if (magnitude > static_cast<std::uint64_t>(
                            std::numeric_limits<std::int64_t>::max())) {
            return std::unexpected(ida::Error::validation(
                "Instruction offset exceeds signed manifest range"));
        }
        return static_cast<std::int64_t>(magnitude);
    }
    const std::uint64_t magnitude = function_start - address;
    if (magnitude > static_cast<std::uint64_t>(
                        std::numeric_limits<std::int64_t>::max())) {
        return std::unexpected(ida::Error::validation(
            "Instruction offset exceeds signed manifest range"));
    }
    return -static_cast<std::int64_t>(magnitude);
}

ida::Result<ida::Address> apply_relative_offset(ida::Address function_start,
                                                std::int64_t offset) {
    if (offset >= 0) {
        const auto magnitude = static_cast<std::uint64_t>(offset);
        if (magnitude > std::numeric_limits<ida::Address>::max() - function_start)
            return std::unexpected(ida::Error::validation("Instruction address overflow"));
        return function_start + magnitude;
    }
    const auto magnitude = static_cast<std::uint64_t>(-(offset + 1)) + 1U;
    if (magnitude > function_start)
        return std::unexpected(ida::Error::validation("Instruction address underflow"));
    return function_start - magnitude;
}

ida::Result<InstructionFingerprint> extract_instruction_fingerprint(
    ida::Address address) {
    auto instruction = ida::instruction::decode(address);
    if (!instruction)
        return std::unexpected(instruction.error());
    if (instruction->size() == 0
        || instruction->size() > std::numeric_limits<std::size_t>::max()) {
        return std::unexpected(ida::Error::validation("Invalid decoded instruction size"));
    }
    const std::size_t size = static_cast<std::size_t>(instruction->size());
    auto bytes = ida::data::read_bytes(address, instruction->size());
    if (!bytes)
        return std::unexpected(bytes.error());
    if (bytes->size() != size)
        return std::unexpected(ida::Error::sdk("Instruction byte read was truncated"));

    std::vector<OperandEncoding> operand_encodings;
    const std::size_t operand_limit = std::min<std::size_t>(
        2, instruction->operands().size());
    operand_encodings.reserve(operand_limit);
    for (std::size_t index = 0; index < operand_limit; ++index) {
        const auto& operand = instruction->operands()[index];
        operand_encodings.push_back({
            normalized_operand_type(operand.type()),
            operand.encoded_value_byte_offset(),
            operand.secondary_encoded_value_byte_offset(),
        });
    }
    auto normalized_size = normalized_prefix_size(size, operand_encodings);
    if (!normalized_size)
        return std::unexpected(normalized_size.error());

    Md5 full_hash;
    Md5 relocation_hash;
    full_hash.update(*bytes);
    relocation_hash.update(bytes->data(), *normalized_size);
    InstructionFingerprint fingerprint;
    fingerprint.size = size;
    fingerprint.full_md5 = full_hash.finish_hex();
    fingerprint.relocation_md5 = relocation_hash.finish_hex();
    fingerprint.mnemonic = instruction->mnemonic();
    if (!valid_utf8(fingerprint.mnemonic))
        return std::unexpected(ida::Error::validation("Instruction mnemonic is not UTF-8"));
    for (const auto& operand : instruction->operands()) {
        if (operand.index() < 0)
            return std::unexpected(ida::Error::validation("Negative operand index"));
        fingerprint.operand_indices.push_back(
            static_cast<std::size_t>(operand.index()));
    }
    return fingerprint;
}

ida::Result<std::string> optional_comment(ida::Address address, bool repeatable) {
    auto value = ida::comment::get(address, repeatable);
    if (value)
        return *value;
    if (value.error().category == ida::ErrorCategory::NotFound)
        return std::string{};
    return std::unexpected(value.error());
}

ida::Result<InstructionMetadataManifest> extract_instruction_metadata_manifest() {
    auto functions = extract_manifest();
    if (!functions)
        return std::unexpected(functions.error());
    InstructionMetadataManifest manifest;
    manifest.functions = std::move(*functions);

    for (const auto& function : manifest.functions) {
        auto addresses = ida::function::code_addresses(function.address);
        if (!addresses)
            return std::unexpected(addresses.error());
        std::sort(addresses->begin(), addresses->end());
        for (std::size_t instruction_ordinal = 0;
             instruction_ordinal < addresses->size(); ++instruction_ordinal) {
            const ida::Address address = (*addresses)[instruction_ordinal];
            auto decoded = ida::instruction::decode(address);
            if (!decoded)
                return std::unexpected(decoded.error());
            auto comment = optional_comment(address, false);
            if (!comment)
                return std::unexpected(comment.error());
            auto repeatable_comment = optional_comment(address, true);
            if (!repeatable_comment)
                return std::unexpected(repeatable_comment.error());
            std::vector<ForcedOperandMetadata> forced_operands;
            for (const auto& operand : decoded->operands()) {
                if (operand.index() < 0)
                    return std::unexpected(ida::Error::validation("Negative operand index"));
                auto forced = ida::instruction::get_forced_operand(
                    address, operand.index());
                if (forced && !forced->empty()) {
                    forced_operands.push_back({
                        static_cast<std::size_t>(operand.index()), std::move(*forced)});
                } else if (!forced
                           && forced.error().category != ida::ErrorCategory::NotFound) {
                    return std::unexpected(forced.error());
                }
            }
            std::sort(forced_operands.begin(), forced_operands.end(),
                      [](const auto& left, const auto& right) {
                          return left.index < right.index;
                      });
            if (std::adjacent_find(
                    forced_operands.begin(), forced_operands.end(),
                    [](const auto& left, const auto& right) {
                        return left.index == right.index;
                    }) != forced_operands.end()) {
                return std::unexpected(ida::Error::validation(
                    "Duplicate decoded operand index"));
            }
            if (comment->empty() && repeatable_comment->empty()
                && forced_operands.empty()) {
                continue;
            }
            if (!valid_utf8(*comment) || !valid_utf8(*repeatable_comment)) {
                return std::unexpected(ida::Error::validation(
                    "Instruction comment is not UTF-8"));
            }
            for (const auto& forced : forced_operands) {
                if (!valid_utf8(forced.text))
                    return std::unexpected(ida::Error::validation(
                        "Forced operand text is not UTF-8"));
            }
            auto offset = relative_offset(address, function.address);
            if (!offset)
                return std::unexpected(offset.error());
            auto fingerprint = extract_instruction_fingerprint(address);
            if (!fingerprint)
                return std::unexpected(fingerprint.error());
            manifest.instructions.push_back({
                function.ordinal,
                instruction_ordinal,
                *offset,
                fingerprint->size,
                std::move(fingerprint->full_md5),
                std::move(fingerprint->relocation_md5),
                std::move(fingerprint->mnemonic),
                std::move(*comment),
                std::move(*repeatable_comment),
                std::move(forced_operands),
            });
        }
    }
    return manifest;
}

std::optional<ida::Address> unique_referent(
    const std::vector<ida::xref::Reference>& references,
    ReferentKind kind) {
    std::vector<ida::Address> targets;
    for (const auto& reference : references) {
        const bool matches = kind == ReferentKind::Code
            ? reference.is_code
                && reference.type != ida::xref::ReferenceType::Flow
            : !reference.is_code;
        if (matches)
            targets.push_back(reference.to);
    }
    std::sort(targets.begin(), targets.end());
    targets.erase(std::unique(targets.begin(), targets.end()), targets.end());
    if (targets.size() != 1)
        return std::nullopt;
    return targets.front();
}

ida::Result<std::pair<std::string, std::string>> referent_payload(
    ida::Address address) {
    std::string referent_name;
    auto name = ida::name::get(address);
    if (name) {
        if (!ida::name::is_auto_generated(address))
            referent_name = std::move(*name);
    } else if (name.error().category != ida::ErrorCategory::NotFound) {
        return std::unexpected(name.error());
    }

    std::string declaration;
    auto type = ida::type::retrieve(address);
    if (type) {
        auto rendered = type->declaration("__idax_diaphora_referent");
        if (!rendered)
            return std::unexpected(rendered.error());
        declaration = std::move(*rendered);
    } else if (type.error().category != ida::ErrorCategory::NotFound) {
        return std::unexpected(type.error());
    }

    if (!valid_utf8(referent_name) || !valid_utf8(declaration)
        || referent_name.find('\0') != std::string::npos
        || declaration.find('\0') != std::string::npos) {
        return std::unexpected(ida::Error::validation(
            "Referent name or declaration is not valid UTF-8"));
    }
    return std::pair{std::move(referent_name), std::move(declaration)};
}

ida::Result<ReferentMetadataManifest> extract_referent_metadata_manifest() {
    auto functions = extract_manifest();
    if (!functions)
        return std::unexpected(functions.error());
    ReferentMetadataManifest manifest;
    manifest.functions = std::move(*functions);

    for (const auto& function : manifest.functions) {
        auto addresses = ida::function::code_addresses(function.address);
        if (!addresses)
            return std::unexpected(addresses.error());
        std::sort(addresses->begin(), addresses->end());
        for (std::size_t instruction_ordinal = 0;
             instruction_ordinal < addresses->size(); ++instruction_ordinal) {
            const ida::Address address = (*addresses)[instruction_ordinal];
            auto references = ida::xref::refs_from(address);
            if (!references)
                return std::unexpected(references.error());
            std::optional<InstructionFingerprint> fingerprint;
            std::optional<std::int64_t> offset;
            for (const ReferentKind kind : {ReferentKind::Code,
                                            ReferentKind::Data}) {
                const auto target = unique_referent(*references, kind);
                if (!target)
                    continue;
                auto payload = referent_payload(*target);
                if (!payload)
                    return std::unexpected(payload.error());
                if (payload->first.empty() && payload->second.empty())
                    continue;
                if (!fingerprint) {
                    auto extracted = extract_instruction_fingerprint(address);
                    if (!extracted)
                        return std::unexpected(extracted.error());
                    fingerprint = std::move(*extracted);
                }
                if (!offset) {
                    auto extracted = relative_offset(address, function.address);
                    if (!extracted)
                        return std::unexpected(extracted.error());
                    offset = *extracted;
                }
                manifest.referents.push_back({
                    function.ordinal,
                    instruction_ordinal,
                    *offset,
                    fingerprint->size,
                    fingerprint->full_md5,
                    fingerprint->relocation_md5,
                    fingerprint->mnemonic,
                    kind,
                    std::move(payload->first),
                    std::move(payload->second),
                });
            }
        }
    }
    return manifest;
}

ida::Result<PseudocodeCommentManifest> extract_pseudocode_comment_manifest() {
    auto available = ida::decompiler::available();
    if (!available)
        return std::unexpected(available.error());
    if (!*available)
        return std::unexpected(ida::Error::unsupported(
            "Hex-Rays decompiler is unavailable"));

    auto functions = extract_manifest();
    if (!functions)
        return std::unexpected(functions.error());
    PseudocodeCommentManifest manifest;
    manifest.functions = std::move(*functions);

    for (const auto& function : manifest.functions) {
        auto addresses = ida::function::code_addresses(function.address);
        if (!addresses)
            return std::unexpected(addresses.error());
        std::sort(addresses->begin(), addresses->end());
        std::unordered_map<ida::Address, std::size_t> ordinal_by_address;
        ordinal_by_address.reserve(addresses->size());
        for (std::size_t index = 0; index < addresses->size(); ++index)
            ordinal_by_address.emplace((*addresses)[index], index);

        auto decompiled = ida::decompiler::decompile(function.address);
        if (!decompiled)
            continue;
        auto comments = decompiled->comments();
        if (!comments)
            return std::unexpected(comments.error());
        for (const auto& comment : *comments) {
            const auto found = ordinal_by_address.find(comment.address);
            if (found == ordinal_by_address.end())
                continue;
            if (comment.text.empty() || !valid_utf8(comment.text)
                || comment.text.find('\0') != std::string::npos) {
                return std::unexpected(ida::Error::validation(
                    "Persisted pseudocode comment is empty or not valid UTF-8"));
            }
            auto offset = relative_offset(comment.address, function.address);
            if (!offset)
                return std::unexpected(offset.error());
            auto fingerprint = extract_instruction_fingerprint(comment.address);
            if (!fingerprint)
                return std::unexpected(fingerprint.error());
            auto position = to_manifest_position(comment.position);
            if (!position)
                return std::unexpected(position.error());
            manifest.comments.push_back({
                function.ordinal,
                found->second,
                *offset,
                fingerprint->size,
                std::move(fingerprint->full_md5),
                std::move(fingerprint->relocation_md5),
                std::move(fingerprint->mnemonic),
                std::move(*position),
                comment.text,
            });
        }
    }
    return manifest;
}

std::string key(std::initializer_list<std::string_view> fields) {
    std::string output;
    for (const auto field : fields) {
        output += std::to_string(field.size());
        output.push_back(':');
        output.append(field);
    }
    return output;
}

std::string decimal(std::uint64_t value) { return std::to_string(value); }

MatchSummary compare_records(const std::vector<FunctionRecord>& baseline,
                             const std::vector<FunctionRecord>& current) {
    MatchSummary summary;
    std::unordered_set<std::size_t> unmatched_baseline;
    std::unordered_set<std::size_t> unused_current;
    std::unordered_set<std::size_t> ambiguous_baseline;
    for (std::size_t index = 0; index < baseline.size(); ++index)
        unmatched_baseline.insert(index);
    for (std::size_t index = 0; index < current.size(); ++index)
        unused_current.insert(index);

    auto tier_key = [](const FunctionRecord& record, std::size_t tier) {
        switch (tier) {
        case 0: return key({decimal(record.rva), record.full_md5,
                            record.relocation_md5});
        case 1: return key({record.full_md5, record.relocation_md5});
        case 2: return key({record.full_md5});
        default: return key({record.relocation_md5,
                             decimal(record.instructions)});
        }
    };
    using Index = std::unordered_map<std::string, std::vector<std::size_t>>;
    for (std::size_t tier = 0; tier < 4; ++tier) {
        Index baseline_index;
        Index current_index;
        for (const auto index : unmatched_baseline)
            baseline_index[tier_key(baseline[index], tier)].push_back(index);
        for (const auto index : unused_current)
            current_index[tier_key(current[index], tier)].push_back(index);

        std::vector<std::pair<std::size_t, std::size_t>> accepted;
        for (const auto& [candidate_key, baseline_indices] : baseline_index) {
            const auto found = current_index.find(candidate_key);
            if (found == current_index.end())
                continue;
            if (baseline_indices.size() == 1 && found->second.size() == 1) {
                accepted.emplace_back(baseline_indices.front(), found->second.front());
            } else {
                ambiguous_baseline.insert(baseline_indices.begin(),
                                          baseline_indices.end());
            }
        }
        std::sort(accepted.begin(), accepted.end());
        for (const auto [baseline_index_value, current_index_value] : accepted) {
            unmatched_baseline.erase(baseline_index_value);
            unused_current.erase(current_index_value);
            ambiguous_baseline.erase(baseline_index_value);
            summary.matches.push_back({baseline_index_value, current_index_value,
                                       static_cast<MatchTier>(tier)});
            ++summary.tiers[tier];
        }
    }
    std::sort(summary.matches.begin(), summary.matches.end(),
              [](const Match& left, const Match& right) {
                  return left.baseline < right.baseline;
              });
    for (const auto index : unmatched_baseline) {
        if (ambiguous_baseline.contains(index))
            ++summary.ambiguous;
        else
            ++summary.unmatched;
    }
    return summary;
}

bool useful_source_name(const FunctionRecord& source) {
    return !source.name.empty() && source.address != ida::BadAddress;
}

ApplySummary apply_metadata(const std::vector<FunctionRecord>& baseline,
                            const std::vector<FunctionRecord>& current,
                            const MatchSummary& comparison) {
    ApplySummary summary;
    for (const auto& match : comparison.matches) {
        const auto& source = baseline[match.baseline];
        const auto& target = current[match.current];
        if (useful_source_name(source) && ida::name::is_auto_generated(target.address)) {
            if (ida::name::force_set(target.address, source.name))
                ++summary.renamed;
            else
                ++summary.failures;
        } else if (!source.name.empty()) {
            ++summary.preserved;
        }

        if (!source.declaration.empty()) {
            auto existing = ida::function::declaration(
                target.address, "__idax_diaphora_function");
            if (existing && !existing->empty()) {
                ++summary.preserved;
            } else if (!existing && existing.error().category != ida::ErrorCategory::NotFound) {
                ++summary.failures;
            } else if (ida::function::apply_decl(target.address, source.declaration)) {
                ++summary.declarations;
            } else {
                ++summary.failures;
            }
        }

        if (!source.repeatable_comment.empty()) {
            auto existing = ida::function::comment(target.address, true);
            if (existing && !existing->empty()) {
                ++summary.preserved;
            } else if (!existing && existing.error().category != ida::ErrorCategory::NotFound) {
                ++summary.failures;
            } else if (ida::function::set_comment(target.address,
                                                  source.repeatable_comment, true)) {
                ++summary.comments;
            } else {
                ++summary.failures;
            }
        }
    }
    return summary;
}

ida::Result<InstructionMetadataComparison> compare_instruction_metadata(
    const InstructionMetadataManifest& baseline,
    const std::vector<FunctionRecord>& current) {
    InstructionMetadataComparison comparison;
    comparison.functions = compare_records(baseline.functions, current);

    std::unordered_map<std::size_t, std::size_t> baseline_by_ordinal;
    for (std::size_t index = 0; index < baseline.functions.size(); ++index)
        baseline_by_ordinal.emplace(baseline.functions[index].ordinal, index);
    std::unordered_map<std::size_t, std::size_t> current_by_baseline;
    for (const auto& match : comparison.functions.matches)
        current_by_baseline.emplace(match.baseline, match.current);
    std::unordered_map<std::size_t, std::vector<ida::Address>> address_cache;

    for (std::size_t metadata_index = 0;
         metadata_index < baseline.instructions.size(); ++metadata_index) {
        const auto& metadata = baseline.instructions[metadata_index];
        const auto baseline_found = baseline_by_ordinal.find(metadata.function_ordinal);
        if (baseline_found == baseline_by_ordinal.end()) {
            ++comparison.unmatched_functions;
            continue;
        }
        const auto match_found = current_by_baseline.find(baseline_found->second);
        if (match_found == current_by_baseline.end()) {
            ++comparison.unmatched_functions;
            continue;
        }
        const std::size_t current_index = match_found->second;
        const auto& target_function = current[current_index];
        auto target_address = apply_relative_offset(
            target_function.address, metadata.function_offset);
        if (!target_address) {
            ++comparison.guard_failures;
            continue;
        }

        auto cached = address_cache.find(current_index);
        if (cached == address_cache.end()) {
            auto addresses = ida::function::code_addresses(target_function.address);
            if (!addresses)
                return std::unexpected(addresses.error());
            std::sort(addresses->begin(), addresses->end());
            cached = address_cache.emplace(current_index, std::move(*addresses)).first;
        }
        if (metadata.instruction_ordinal >= cached->second.size()
            || cached->second[metadata.instruction_ordinal] != *target_address) {
            ++comparison.guard_failures;
            continue;
        }
        auto fingerprint = extract_instruction_fingerprint(*target_address);
        if (!fingerprint)
            return std::unexpected(fingerprint.error());
        if (fingerprint->size != metadata.size
            || fingerprint->mnemonic != metadata.mnemonic
            || fingerprint->relocation_md5 != metadata.relocation_md5) {
            ++comparison.guard_failures;
            continue;
        }
        bool operands_valid = true;
        for (const auto& forced : metadata.forced_operands) {
            if (std::find(fingerprint->operand_indices.begin(),
                          fingerprint->operand_indices.end(),
                          forced.index) == fingerprint->operand_indices.end()) {
                operands_valid = false;
                break;
            }
        }
        if (!operands_valid) {
            ++comparison.guard_failures;
            continue;
        }
        comparison.eligible.emplace_back(metadata_index, *target_address);
    }
    return comparison;
}

InstructionMetadataApplySummary apply_instruction_metadata(
    const InstructionMetadataManifest& baseline,
    const InstructionMetadataComparison& comparison) {
    InstructionMetadataApplySummary summary;
    for (const auto& [metadata_index, target_address] : comparison.eligible) {
        const auto& metadata = baseline.instructions[metadata_index];
        auto apply_comment_slot = [&](std::string_view source,
                                      bool repeatable,
                                      std::size_t& changed) {
            if (source.empty())
                return;
            auto existing = ida::comment::get(target_address, repeatable);
            if (existing && !existing->empty()) {
                ++summary.preserved;
            } else if (!existing
                       && existing.error().category != ida::ErrorCategory::NotFound) {
                ++summary.failures;
            } else if (ida::comment::set(target_address, source, repeatable)) {
                ++changed;
            } else {
                ++summary.failures;
            }
        };
        apply_comment_slot(metadata.comment, false, summary.comments);
        apply_comment_slot(metadata.repeatable_comment, true,
                           summary.repeatable_comments);

        for (const auto& forced : metadata.forced_operands) {
            auto existing = ida::instruction::get_forced_operand(
                target_address, static_cast<int>(forced.index));
            if (existing && !existing->empty()) {
                ++summary.preserved;
            } else if (!existing
                       && existing.error().category != ida::ErrorCategory::NotFound) {
                ++summary.failures;
            } else if (ida::instruction::set_forced_operand(
                           target_address, static_cast<int>(forced.index), forced.text)) {
                ++summary.forced_operands;
            } else {
                ++summary.failures;
            }
        }
    }
    return summary;
}

std::string instruction_metadata_report(
    const InstructionMetadataManifest& baseline,
    const std::vector<FunctionRecord>& current,
    const InstructionMetadataComparison& comparison) {
    std::ostringstream output;
    output << "Diaphora exact instruction metadata comparison\n"
           << "Baseline functions: " << baseline.functions.size() << "\n"
           << "Current functions: " << current.size() << "\n"
           << "Unique function matches: " << comparison.functions.matches.size() << "\n"
           << "Ambiguous baseline functions: " << comparison.functions.ambiguous << "\n"
           << "Unmatched baseline functions: " << comparison.functions.unmatched << "\n"
           << "Metadata records: " << baseline.instructions.size() << "\n"
           << "Eligible instruction records: " << comparison.eligible.size() << "\n"
           << "Records with unmatched functions: " << comparison.unmatched_functions << "\n"
           << "Instruction guard failures: " << comparison.guard_failures;
    return output.str();
}

ida::Result<ReferentMetadataComparison> compare_referent_metadata(
    const ReferentMetadataManifest& baseline,
    const std::vector<FunctionRecord>& current) {
    ReferentMetadataComparison comparison;
    comparison.functions = compare_records(baseline.functions, current);

    std::unordered_map<std::size_t, std::size_t> baseline_by_ordinal;
    for (std::size_t index = 0; index < baseline.functions.size(); ++index)
        baseline_by_ordinal.emplace(baseline.functions[index].ordinal, index);
    std::unordered_map<std::size_t, std::size_t> current_by_baseline;
    for (const auto& match : comparison.functions.matches)
        current_by_baseline.emplace(match.baseline, match.current);
    std::unordered_map<std::size_t, std::vector<ida::Address>> address_cache;

    for (std::size_t metadata_index = 0;
         metadata_index < baseline.referents.size(); ++metadata_index) {
        const auto& metadata = baseline.referents[metadata_index];
        const auto baseline_found = baseline_by_ordinal.find(
            metadata.function_ordinal);
        if (baseline_found == baseline_by_ordinal.end()) {
            ++comparison.unmatched_functions;
            continue;
        }
        const auto match_found = current_by_baseline.find(baseline_found->second);
        if (match_found == current_by_baseline.end()) {
            ++comparison.unmatched_functions;
            continue;
        }
        const std::size_t current_index = match_found->second;
        const auto& target_function = current[current_index];
        auto instruction_address = apply_relative_offset(
            target_function.address, metadata.function_offset);
        if (!instruction_address) {
            ++comparison.instruction_guard_failures;
            continue;
        }

        auto cached = address_cache.find(current_index);
        if (cached == address_cache.end()) {
            auto addresses = ida::function::code_addresses(target_function.address);
            if (!addresses)
                return std::unexpected(addresses.error());
            std::sort(addresses->begin(), addresses->end());
            cached = address_cache.emplace(current_index, std::move(*addresses)).first;
        }
        if (metadata.instruction_ordinal >= cached->second.size()
            || cached->second[metadata.instruction_ordinal] != *instruction_address) {
            ++comparison.instruction_guard_failures;
            continue;
        }
        auto fingerprint = extract_instruction_fingerprint(*instruction_address);
        if (!fingerprint)
            return std::unexpected(fingerprint.error());
        if (fingerprint->size != metadata.size
            || fingerprint->mnemonic != metadata.mnemonic
            || fingerprint->relocation_md5 != metadata.relocation_md5) {
            ++comparison.instruction_guard_failures;
            continue;
        }
        auto references = ida::xref::refs_from(*instruction_address);
        if (!references)
            return std::unexpected(references.error());
        const auto referent = unique_referent(*references, metadata.kind);
        if (!referent) {
            ++comparison.reference_guard_failures;
            continue;
        }
        comparison.eligible.push_back(
            {metadata_index, *instruction_address, *referent});
    }
    return comparison;
}

ReferentMetadataApplySummary apply_referent_metadata(
    const ReferentMetadataManifest& baseline,
    const ReferentMetadataComparison& comparison) {
    ReferentMetadataApplySummary summary;
    for (const auto& eligible : comparison.eligible) {
        const auto& source = baseline.referents[eligible.metadata_index];
        if (!source.name.empty()) {
            auto existing = ida::name::get(eligible.referent_address);
            if (existing && !existing->empty()
                && !ida::name::is_auto_generated(eligible.referent_address)) {
                ++summary.preserved;
            } else if (!existing
                       && existing.error().category != ida::ErrorCategory::NotFound) {
                ++summary.failures;
            } else if (ida::name::set(eligible.referent_address, source.name)) {
                ++summary.names;
            } else {
                ++summary.failures;
            }
        }

        if (!source.declaration.empty()) {
            auto existing = ida::type::retrieve(eligible.referent_address);
            if (existing) {
                ++summary.preserved;
            } else if (existing.error().category != ida::ErrorCategory::NotFound) {
                ++summary.failures;
            } else {
                auto parsed = ida::type::TypeInfo::from_declaration(
                    source.declaration);
                if (!parsed) {
                    ++summary.failures;
                } else if (parsed->apply(eligible.referent_address)) {
                    ++summary.types;
                } else {
                    ++summary.failures;
                }
            }
        }
    }
    return summary;
}

std::string referent_metadata_report(
    const ReferentMetadataManifest& baseline,
    const std::vector<FunctionRecord>& current,
    const ReferentMetadataComparison& comparison) {
    std::ostringstream output;
    output << "Diaphora exact referent metadata comparison\n"
           << "Baseline functions: " << baseline.functions.size() << "\n"
           << "Current functions: " << current.size() << "\n"
           << "Unique function matches: " << comparison.functions.matches.size() << "\n"
           << "Ambiguous baseline functions: " << comparison.functions.ambiguous << "\n"
           << "Unmatched baseline functions: " << comparison.functions.unmatched << "\n"
           << "Referent records: " << baseline.referents.size() << "\n"
           << "Eligible referent records: " << comparison.eligible.size() << "\n"
           << "Records with unmatched functions: " << comparison.unmatched_functions << "\n"
           << "Instruction guard failures: "
           << comparison.instruction_guard_failures << "\n"
           << "Reference guard failures: "
           << comparison.reference_guard_failures;
    return output.str();
}

ida::Result<PseudocodeCommentComparison> compare_pseudocode_comments(
    const PseudocodeCommentManifest& baseline,
    const std::vector<FunctionRecord>& current) {
    PseudocodeCommentComparison comparison;
    comparison.functions = compare_records(baseline.functions, current);

    std::unordered_map<std::size_t, std::size_t> baseline_by_ordinal;
    for (std::size_t index = 0; index < baseline.functions.size(); ++index)
        baseline_by_ordinal.emplace(baseline.functions[index].ordinal, index);
    std::unordered_map<std::size_t, std::size_t> current_by_baseline;
    for (const auto& match : comparison.functions.matches)
        current_by_baseline.emplace(match.baseline, match.current);
    std::unordered_map<std::size_t, std::vector<ida::Address>> address_cache;

    for (std::size_t comment_index = 0;
         comment_index < baseline.comments.size(); ++comment_index) {
        const auto& comment = baseline.comments[comment_index];
        const auto baseline_found = baseline_by_ordinal.find(comment.function_ordinal);
        if (baseline_found == baseline_by_ordinal.end()) {
            ++comparison.unmatched_functions;
            continue;
        }
        const auto match_found = current_by_baseline.find(baseline_found->second);
        if (match_found == current_by_baseline.end()) {
            ++comparison.unmatched_functions;
            continue;
        }
        const std::size_t current_index = match_found->second;
        const auto& target_function = current[current_index];
        auto target_address = apply_relative_offset(
            target_function.address, comment.function_offset);
        if (!target_address) {
            ++comparison.guard_failures;
            continue;
        }

        auto cached = address_cache.find(current_index);
        if (cached == address_cache.end()) {
            auto addresses = ida::function::code_addresses(target_function.address);
            if (!addresses)
                return std::unexpected(addresses.error());
            std::sort(addresses->begin(), addresses->end());
            cached = address_cache.emplace(current_index, std::move(*addresses)).first;
        }
        if (comment.instruction_ordinal >= cached->second.size()
            || cached->second[comment.instruction_ordinal] != *target_address) {
            ++comparison.guard_failures;
            continue;
        }
        auto fingerprint = extract_instruction_fingerprint(*target_address);
        if (!fingerprint)
            return std::unexpected(fingerprint.error());
        if (fingerprint->size != comment.size
            || fingerprint->mnemonic != comment.mnemonic
            || fingerprint->relocation_md5 != comment.relocation_md5) {
            ++comparison.guard_failures;
            continue;
        }
        comparison.eligible.push_back({
            comment_index, target_function.address, *target_address});
    }
    return comparison;
}

PseudocodeCommentApplySummary apply_pseudocode_comments(
    const PseudocodeCommentManifest& baseline,
    const PseudocodeCommentComparison& comparison) {
    PseudocodeCommentApplySummary summary;
    std::unordered_map<ida::Address,
                       std::unique_ptr<ida::decompiler::DecompiledFunction>> functions;
    std::unordered_set<ida::Address> failed_functions;
    std::unordered_set<ida::Address> modified_functions;

    for (const auto& eligible : comparison.eligible) {
        if (failed_functions.contains(eligible.function_address)) {
            ++summary.failures;
            continue;
        }
        auto found = functions.find(eligible.function_address);
        if (found == functions.end()) {
            auto decompiled = ida::decompiler::decompile(eligible.function_address);
            if (!decompiled) {
                failed_functions.insert(eligible.function_address);
                ++summary.failures;
                continue;
            }
            found = functions.emplace(
                eligible.function_address,
                std::make_unique<ida::decompiler::DecompiledFunction>(
                    std::move(*decompiled))).first;
        }

        const auto& source = baseline.comments[eligible.comment_index];
        auto position = to_public_position(source.position);
        if (!position) {
            ++summary.failures;
            continue;
        }
        auto existing = found->second->get_comment(
            eligible.comment_address, *position);
        if (!existing) {
            ++summary.failures;
        } else if (!existing->empty()) {
            ++summary.preserved;
        } else if (found->second->set_comment(
                       eligible.comment_address, source.text, *position)) {
            ++summary.comments;
            modified_functions.insert(eligible.function_address);
        } else {
            ++summary.failures;
        }
    }

    for (const auto function_address : modified_functions) {
        const auto found = functions.find(function_address);
        if (found != functions.end() && found->second->save_comments())
            ++summary.saved_functions;
        else
            ++summary.failures;
    }
    return summary;
}

std::string pseudocode_comment_report(
    const PseudocodeCommentManifest& baseline,
    const std::vector<FunctionRecord>& current,
    const PseudocodeCommentComparison& comparison) {
    std::ostringstream output;
    output << "Diaphora exact pseudocode comment comparison\n"
           << "Baseline functions: " << baseline.functions.size() << "\n"
           << "Current functions: " << current.size() << "\n"
           << "Unique function matches: " << comparison.functions.matches.size() << "\n"
           << "Ambiguous baseline functions: " << comparison.functions.ambiguous << "\n"
           << "Unmatched baseline functions: " << comparison.functions.unmatched << "\n"
           << "Pseudocode comment records: " << baseline.comments.size() << "\n"
           << "Eligible comment records: " << comparison.eligible.size() << "\n"
           << "Records with unmatched functions: " << comparison.unmatched_functions << "\n"
           << "Instruction guard failures: " << comparison.guard_failures;
    return output.str();
}

std::string comparison_report(const MatchSummary& summary,
                              std::size_t baseline_count,
                              std::size_t current_count) {
    std::ostringstream output;
    output << "Diaphora exact comparison\n"
           << "Baseline functions: " << baseline_count << "\n"
           << "Current functions: " << current_count << "\n"
           << "Unique matches: " << summary.matches.size() << "\n"
           << "  same RVA + both hashes: " << summary.tiers[0] << "\n"
           << "  both hashes: " << summary.tiers[1] << "\n"
           << "  full hash: " << summary.tiers[2] << "\n"
           << "  relocation hash + instruction count: " << summary.tiers[3] << "\n"
           << "Ambiguous baseline functions: " << summary.ambiguous << "\n"
           << "Unmatched baseline functions: " << summary.unmatched;
    return output.str();
}

ida::Status export_manifest_action() {
    auto path = ida::ui::ask_file(true, "*.idax-diaphora.tsv",
                                  "Export Diaphora Exact Manifest");
    if (!path)
        return std::unexpected(path.error());
    auto records = extract_manifest();
    if (!records)
        return std::unexpected(records.error());
    auto written = write_text_file(*path, format_manifest(*records));
    if (!written)
        return written;
    std::ostringstream report;
    report << "Exported " << records->size() << " exact function fingerprints to " << *path;
    ida::ui::message("[diaphora-exact:idax] " + report.str() + "\n");
    ida::ui::info(report.str());
    return ida::ok();
}

ida::Status compare_manifest_action(bool apply) {
    auto path = ida::ui::ask_file(false, "*.idax-diaphora.tsv",
                                  "Open Diaphora Exact Manifest");
    if (!path)
        return std::unexpected(path.error());
    auto text = read_text_file(*path);
    if (!text)
        return std::unexpected(text.error());
    auto baseline = parse_manifest(*text);
    if (!baseline)
        return std::unexpected(baseline.error());
    auto image_base = ida::database::image_base();
    if (!image_base)
        return std::unexpected(image_base.error());
    for (auto& record : *baseline) {
        if (record.rva > std::numeric_limits<ida::Address>::max() - *image_base)
            return std::unexpected(ida::Error::validation("Manifest RVA overflows address space"));
        record.address = *image_base + record.rva;
    }
    auto current = extract_manifest();
    if (!current)
        return std::unexpected(current.error());
    auto comparison = compare_records(*baseline, *current);
    std::string report = comparison_report(comparison, baseline->size(), current->size());
    if (apply) {
        const auto applied = apply_metadata(*baseline, *current, comparison);
        std::ostringstream addition;
        addition << "\nRenamed: " << applied.renamed
                 << "\nDeclarations applied: " << applied.declarations
                 << "\nRepeatable comments applied: " << applied.comments
                 << "\nExisting metadata preserved: " << applied.preserved
                 << "\nMutation failures: " << applied.failures;
        report += addition.str();
        if (applied.renamed + applied.declarations + applied.comments > 0)
            ida::ui::refresh_all_views();
    }
    ida::ui::message("[diaphora-exact:idax] " + report + "\n");
    ida::ui::info(report);
    return ida::ok();
}

ida::Status export_instruction_metadata_action() {
    auto path = ida::ui::ask_file(true, "*.idax-diaphora-insn.tsv",
                                  "Export Diaphora Instruction Metadata Manifest");
    if (!path)
        return std::unexpected(path.error());
    auto manifest = extract_instruction_metadata_manifest();
    if (!manifest)
        return std::unexpected(manifest.error());
    auto written = write_text_file(
        *path, format_instruction_metadata_manifest(*manifest));
    if (!written)
        return written;
    std::ostringstream report;
    report << "Exported " << manifest->instructions.size()
           << " instruction metadata records for " << manifest->functions.size()
           << " functions to " << *path;
    ida::ui::message("[diaphora-exact:idax] " + report.str() + "\n");
    ida::ui::info(report.str());
    return ida::ok();
}

ida::Status compare_instruction_metadata_action(bool apply) {
    auto path = ida::ui::ask_file(false, "*.idax-diaphora-insn.tsv",
                                  "Open Diaphora Instruction Metadata Manifest");
    if (!path)
        return std::unexpected(path.error());
    auto text = read_text_file(*path);
    if (!text)
        return std::unexpected(text.error());
    auto baseline = parse_instruction_metadata_manifest(*text);
    if (!baseline)
        return std::unexpected(baseline.error());
    auto current = extract_manifest();
    if (!current)
        return std::unexpected(current.error());
    auto comparison = compare_instruction_metadata(*baseline, *current);
    if (!comparison)
        return std::unexpected(comparison.error());
    std::string report = instruction_metadata_report(
        *baseline, *current, *comparison);
    if (apply) {
        const auto applied = apply_instruction_metadata(*baseline, *comparison);
        std::ostringstream addition;
        addition << "\nOrdinary comments applied: " << applied.comments
                 << "\nRepeatable comments applied: " << applied.repeatable_comments
                 << "\nForced operands applied: " << applied.forced_operands
                 << "\nExisting metadata preserved: " << applied.preserved
                 << "\nMutation failures: " << applied.failures;
        report += addition.str();
        if (applied.comments + applied.repeatable_comments
                + applied.forced_operands > 0) {
            ida::ui::refresh_all_views();
        }
    }
    ida::ui::message("[diaphora-exact:idax] " + report + "\n");
    ida::ui::info(report);
    return ida::ok();
}

ida::Status export_referent_metadata_action() {
    auto path = ida::ui::ask_file(true, "*.idax-diaphora-refs.tsv",
                                  "Export Diaphora Referent Metadata Manifest");
    if (!path)
        return std::unexpected(path.error());
    auto manifest = extract_referent_metadata_manifest();
    if (!manifest)
        return std::unexpected(manifest.error());
    auto written = write_text_file(
        *path, format_referent_metadata_manifest(*manifest));
    if (!written)
        return written;
    std::ostringstream report;
    report << "Exported " << manifest->referents.size()
           << " unique referent metadata records for "
           << manifest->functions.size() << " functions to " << *path;
    ida::ui::message("[diaphora-exact:idax] " + report.str() + "\n");
    ida::ui::info(report.str());
    return ida::ok();
}

ida::Status compare_referent_metadata_action(bool apply) {
    auto path = ida::ui::ask_file(false, "*.idax-diaphora-refs.tsv",
                                  "Open Diaphora Referent Metadata Manifest");
    if (!path)
        return std::unexpected(path.error());
    auto text = read_text_file(*path);
    if (!text)
        return std::unexpected(text.error());
    auto baseline = parse_referent_metadata_manifest(*text);
    if (!baseline)
        return std::unexpected(baseline.error());
    auto current = extract_manifest();
    if (!current)
        return std::unexpected(current.error());
    auto comparison = compare_referent_metadata(*baseline, *current);
    if (!comparison)
        return std::unexpected(comparison.error());
    std::string report = referent_metadata_report(
        *baseline, *current, *comparison);
    if (apply) {
        const auto applied = apply_referent_metadata(*baseline, *comparison);
        std::ostringstream addition;
        addition << "\nReferent names applied: " << applied.names
                 << "\nReferent types applied: " << applied.types
                 << "\nExisting metadata preserved: " << applied.preserved
                 << "\nMutation failures: " << applied.failures;
        report += addition.str();
        if (applied.names + applied.types > 0)
            ida::ui::refresh_all_views();
    }
    ida::ui::message("[diaphora-exact:idax] " + report + "\n");
    ida::ui::info(report);
    return ida::ok();
}

ida::Status export_pseudocode_comments_action() {
    auto path = ida::ui::ask_file(true, "*.idax-diaphora-pseudo.tsv",
                                  "Export Diaphora Pseudocode Comment Manifest");
    if (!path)
        return std::unexpected(path.error());
    auto manifest = extract_pseudocode_comment_manifest();
    if (!manifest)
        return std::unexpected(manifest.error());
    auto written = write_text_file(
        *path, format_pseudocode_comment_manifest(*manifest));
    if (!written)
        return written;
    std::ostringstream report;
    report << "Exported " << manifest->comments.size()
           << " exact pseudocode comment records for "
           << manifest->functions.size() << " functions to " << *path;
    ida::ui::message("[diaphora-exact:idax] " + report.str() + "\n");
    ida::ui::info(report.str());
    return ida::ok();
}

ida::Status compare_pseudocode_comments_action(bool apply) {
    auto path = ida::ui::ask_file(false, "*.idax-diaphora-pseudo.tsv",
                                  "Open Diaphora Pseudocode Comment Manifest");
    if (!path)
        return std::unexpected(path.error());
    auto text = read_text_file(*path);
    if (!text)
        return std::unexpected(text.error());
    auto baseline = parse_pseudocode_comment_manifest(*text);
    if (!baseline)
        return std::unexpected(baseline.error());
    auto current = extract_manifest();
    if (!current)
        return std::unexpected(current.error());
    auto comparison = compare_pseudocode_comments(*baseline, *current);
    if (!comparison)
        return std::unexpected(comparison.error());
    std::string report = pseudocode_comment_report(
        *baseline, *current, *comparison);
    if (apply) {
        const auto applied = apply_pseudocode_comments(*baseline, *comparison);
        std::ostringstream addition;
        addition << "\nPseudocode comments applied: " << applied.comments
                 << "\nExisting locations preserved: " << applied.preserved
                 << "\nFunctions with comments saved: " << applied.saved_functions
                 << "\nMutation failures: " << applied.failures;
        report += addition.str();
        if (applied.comments > 0)
            ida::ui::refresh_all_views();
    }
    ida::ui::message("[diaphora-exact:idax] " + report + "\n");
    ida::ui::info(report);
    return ida::ok();
}

#ifndef IDAX_DIAPHORA_EXACT_CORE_TEST

class DiaphoraExactPortPlugin final : public ida::plugin::Plugin {
public:
    ida::plugin::Info info() const override {
        return {
            .name = "Diaphora Exact Port",
            .hotkey = "Ctrl-Alt-Shift-D",
            .comment = "Export and compare exact Diaphora-style function fingerprints",
            .help = "A bounded Diaphora 3.4.0 adaptation using a deterministic canonical manifest. "
                    "A byte-compatible companion manifest conservatively transfers instruction "
                    "comments, forced operands, unique referent names/types, and exact pseudocode "
                    "comment locations. SQLite "
                    "heuristics, pseudocode/microcode similarity, and chooser parity are outside "
                    "this artifact.",
        };
    }

    bool init() override {
        return add_action(kExportAction, "Diaphora Exact: Export Manifest",
                          "Export canonical exact function fingerprints",
                          [] { return export_manifest_action(); })
            && add_action(kCompareAction, "Diaphora Exact: Compare Manifest",
                          "Compare without changing the database",
                          [] { return compare_manifest_action(false); })
            && add_action(kApplyAction, "Diaphora Exact: Apply Conservative Metadata",
                          "Apply only absent names, declarations, and repeatable comments",
                          [] { return compare_manifest_action(true); })
            && add_action(kExportInstructionMetadataAction,
                          "Diaphora Exact: Export Instruction Metadata",
                          "Export exact instruction comments and forced operands",
                          [] { return export_instruction_metadata_action(); })
            && add_action(kCompareInstructionMetadataAction,
                          "Diaphora Exact: Compare Instruction Metadata",
                          "Validate instruction metadata without changing the database",
                          [] { return compare_instruction_metadata_action(false); })
            && add_action(kApplyInstructionMetadataAction,
                          "Diaphora Exact: Apply Instruction Metadata",
                          "Apply only absent instruction comments and forced operands",
                          [] { return compare_instruction_metadata_action(true); })
            && add_action(kExportReferentMetadataAction,
                          "Diaphora Exact: Export Referent Metadata",
                          "Export exact unique code/data referent names and types",
                          [] { return export_referent_metadata_action(); })
            && add_action(kCompareReferentMetadataAction,
                          "Diaphora Exact: Compare Referent Metadata",
                          "Validate referent metadata without changing the database",
                          [] { return compare_referent_metadata_action(false); })
            && add_action(kApplyReferentMetadataAction,
                          "Diaphora Exact: Apply Referent Metadata",
                          "Apply only absent/auto referent names and absent types",
                          [] { return compare_referent_metadata_action(true); })
            && add_action(kExportPseudocodeCommentsAction,
                          "Diaphora Exact: Export Pseudocode Comments",
                          "Export all exact persisted pseudocode comment locations",
                          [] { return export_pseudocode_comments_action(); })
            && add_action(kComparePseudocodeCommentsAction,
                          "Diaphora Exact: Compare Pseudocode Comments",
                          "Validate exact pseudocode comments without changing the database",
                          [] { return compare_pseudocode_comments_action(false); })
            && add_action(kApplyPseudocodeCommentsAction,
                          "Diaphora Exact: Apply Pseudocode Comments",
                          "Apply only absent exact pseudocode comment locations",
                          [] { return compare_pseudocode_comments_action(true); });
    }

    ida::Status run(std::size_t) override { return export_manifest_action(); }

    ~DiaphoraExactPortPlugin() override { unregister_all(); }

private:
    bool add_action(std::string_view id,
                    std::string_view label,
                    std::string_view tooltip,
                    std::function<ida::Status()> handler) {
        ida::plugin::Action action;
        action.id = std::string(id);
        action.label = std::string(label);
        action.tooltip = std::string(tooltip);
        action.handler = std::move(handler);
        action.enabled = [] { return true; };
        if (!ida::plugin::register_action(action)) {
            unregister_all();
            return false;
        }
        if (!ida::plugin::attach_to_menu(kMenuPath, id)) {
            (void)ida::plugin::unregister_action(id);
            unregister_all();
            return false;
        }
        registered_.emplace_back(id);
        return true;
    }

    void unregister_all() {
        for (auto it = registered_.rbegin(); it != registered_.rend(); ++it) {
            (void)ida::plugin::detach_from_menu(kMenuPath, *it);
            (void)ida::plugin::unregister_action(*it);
        }
        registered_.clear();
    }

    std::vector<std::string> registered_;
};

#endif

} // namespace

#ifndef IDAX_DIAPHORA_EXACT_CORE_TEST
IDAX_PLUGIN_WITH_FLAGS(DiaphoraExactPortPlugin,
                       ida::plugin::ExportFlags{.modifies_database = true})
#endif

/// \file lines.cpp
/// \brief Implementation of ida::lines — color tag manipulation for IDA's tagged text format.

#include "detail/sdk_bridge.hpp"
#include <ida/lines.hpp>

#include <cstdio>
#include <cstring>

namespace ida::lines {

Status add_source_file(const ida::address::Range& range,
                       std::string_view filename) {
    if (range.empty() || range.start == BadAddress || range.end == BadAddress) {
        return std::unexpected(Error::validation(
            "Source-file range must be a valid non-empty half-open range"));
    }
    if (filename.empty()) {
        return std::unexpected(Error::validation(
            "Source filename cannot be empty"));
    }
    if (filename.find('\0') != std::string_view::npos) {
        return std::unexpected(Error::validation(
            "Source filename cannot contain null bytes"));
    }
    const std::string owned_filename(filename);
    if (!::add_sourcefile(static_cast<ea_t>(range.start),
                          static_cast<ea_t>(range.end),
                          owned_filename.c_str())) {
        return std::unexpected(Error::sdk(
            "add_sourcefile failed", owned_filename));
    }
    return ida::ok();
}

Result<SourceFile> source_file_at(Address address) {
    if (address == BadAddress) {
        return std::unexpected(Error::validation(
            "Source-file query address cannot be BadAddress"));
    }
    range_t bounds;
    const char* filename = ::get_sourcefile(static_cast<ea_t>(address), &bounds);
    if (filename == nullptr) {
        return std::unexpected(Error::not_found(
            "Source-file mapping not found", std::to_string(address)));
    }
    if (bounds.empty() || bounds.start_ea == BADADDR || bounds.end_ea == BADADDR) {
        return std::unexpected(Error::sdk(
            "Source-file mapping contains an invalid range",
            std::to_string(address)));
    }
    return SourceFile{
        .filename = std::string(filename),
        .range = {
            .start = static_cast<Address>(bounds.start_ea),
            .end = static_cast<Address>(bounds.end_ea),
        },
    };
}

Status remove_source_file(Address address) {
    if (address == BadAddress) {
        return std::unexpected(Error::validation(
            "Source-file removal address cannot be BadAddress"));
    }
    if (::get_sourcefile(static_cast<ea_t>(address), nullptr) == nullptr) {
        return std::unexpected(Error::not_found(
            "Source-file mapping not found", std::to_string(address)));
    }
    if (!::del_sourcefile(static_cast<ea_t>(address))) {
        return std::unexpected(Error::sdk(
            "del_sourcefile failed", std::to_string(address)));
    }
    return ida::ok();
}

// ── Color tag manipulation ──────────────────────────────────────────────

std::string colstr(std::string_view text, Color color) {
    // Build: COLOR_ON + color_byte + text + COLOR_OFF + color_byte
    const auto c = static_cast<char>(color);
    std::string result;
    result.reserve(text.size() + 4);
    result += COLOR_ON;
    result += c;
    result += text;
    result += COLOR_OFF;
    result += c;
    return result;
}

std::string tag_remove(std::string_view tagged_text) {
    if (tagged_text.empty())
        return {};
    qstring buf;
    ::tag_remove(&buf, tagged_text.data());
    return ida::detail::to_string(buf);
}

int tag_advance(std::string_view tagged_text, int pos) {
    if (pos < 0 || static_cast<std::size_t>(pos) >= tagged_text.size())
        return 1;

    // SDK's tag_advance(const char*, int cnt) advances `cnt` visible characters
    // and returns a new pointer. We need to compute the byte offset.
    const char* start = tagged_text.data() + pos;
    const char* advanced = ::tag_advance(start, 1);
    auto skip = static_cast<int>(advanced - start);
    return skip > 0 ? skip : 1;
}

std::size_t tag_strlen(std::string_view tagged_text) {
    if (tagged_text.empty())
        return 0;
    ssize_t len = ::tag_strlen(tagged_text.data());
    return len >= 0 ? static_cast<std::size_t>(len) : 0;
}

// ── Color address tags ──────────────────────────────────────────────────

std::string make_addr_tag(int item_index) {
    // Build: COLOR_ON + COLOR_ADDR + 16-hex-digit encoded value
    // For ctree items, the anchor value is (item_index | ANCHOR_CITEM),
    // where ANCHOR_CITEM == 0x00000000, so it's just item_index.
    std::string result;
    result.reserve(2 + kColorAddrSize);
    result += COLOR_ON;
    result += static_cast<char>(COLOR_ADDR);

    char hex[kColorAddrSize + 1];
    qsnprintf(hex, sizeof(hex), "%0*llX", kColorAddrSize,
              static_cast<unsigned long long>(static_cast<unsigned int>(item_index)));
    result.append(hex, kColorAddrSize);
    return result;
}

int decode_addr_tag(std::string_view tagged_text, std::size_t pos) {
    // Expect: COLOR_ON + COLOR_ADDR at pos, followed by kColorAddrSize hex digits
    if (pos + 2 + kColorAddrSize > tagged_text.size())
        return -1;
    if (tagged_text[pos] != COLOR_ON)
        return -1;
    if (static_cast<std::uint8_t>(tagged_text[pos + 1]) != COLOR_ADDR)
        return -1;

    // Parse the 16-hex-digit address/anchor value.
    // Manual hex parsing avoids std::strtoull which MSVC's SDK header
    // interactions can break (pro.h namespace pollution).
    const char* hex_start = tagged_text.data() + pos + 2;
    unsigned long long val = 0;
    for (std::size_t i = 0; i < kColorAddrSize; ++i) {
        char ch = hex_start[i];
        unsigned digit;
        if (ch >= '0' && ch <= '9')      digit = static_cast<unsigned>(ch - '0');
        else if (ch >= 'A' && ch <= 'F') digit = static_cast<unsigned>(ch - 'A' + 10);
        else if (ch >= 'a' && ch <= 'f') digit = static_cast<unsigned>(ch - 'a' + 10);
        else return -1;
        val = (val << 4) | digit;
    }

    // Extract the item index (bottom 29 bits, ANCHOR_INDEX mask)
    constexpr unsigned int ANCHOR_INDEX = 0x1FFFFFFF;
    return static_cast<int>(val & ANCHOR_INDEX);
}

} // namespace ida::lines

#include <ida/idax.hpp>

#include "../full/jbc_common.hpp"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <string>
#include <string_view>
#include <vector>

namespace {

using idax::examples::jbc::kMagicVersion1;
using idax::examples::jbc::kMagicVersion2;
using idax::examples::jbc::kMinimumHeaderSize;
using idax::examples::jbc::kSegmentCode;
using idax::examples::jbc::kSegmentData;
using idax::examples::jbc::kSegmentStrings;
using idax::examples::jbc::kRegisterCs;
using idax::examples::jbc::kRegisterDs;
using idax::examples::jbc::kStateCodeBaseIndex;
using idax::examples::jbc::kStateNodeName;
using idax::examples::jbc::kStateStringBaseIndex;
using idax::examples::jbc::read_big_endian_u32;
using idax::examples::jbc::read_little_endian_u32;

template <typename... Args>
std::string fmt(const char* pattern, Args&&... args) {
    char buffer[2048];
    std::snprintf(buffer, sizeof(buffer), pattern, std::forward<Args>(args)...);
    return buffer;
}

ida::Address align16(ida::Address value) {
    return (value + 0xFULL) & ~0xFULL;
}

ida::Result<std::uint32_t>
read_be32_at(ida::loader::InputFile& file, std::int64_t offset) {
    auto bytes = file.read_bytes_at(offset, 4);
    if (!bytes)
        return std::unexpected(bytes.error());
    if (bytes->size() != 4) {
        return std::unexpected(ida::Error::validation(
            "Truncated 32-bit big-endian read", std::to_string(offset)));
    }
    return read_big_endian_u32(bytes->data());
}

ida::Result<std::uint8_t>
read_u8_at(ida::loader::InputFile& file, std::int64_t offset) {
    auto bytes = file.read_bytes_at(offset, 1);
    if (!bytes)
        return std::unexpected(bytes.error());
    if (bytes->size() != 1) {
        return std::unexpected(ida::Error::validation(
            "Truncated 8-bit read", std::to_string(offset)));
    }
    return (*bytes)[0];
}

std::string string_at(const std::vector<std::uint8_t>& table,
                      std::uint32_t offset) {
    if (offset >= table.size())
        return {};

    std::size_t end = offset;
    while (end < table.size() && table[end] != 0)
        ++end;

    if (end == offset)
        return {};

    const char* start = reinterpret_cast<const char*>(table.data() + offset);
    return std::string(start, end - offset);
}

void define_embedded_strings(ida::Address base,
                             const std::vector<std::uint8_t>& table) {
    std::size_t index = 0;
    while (index < table.size()) {
        if (table[index] == 0) {
            ++index;
            continue;
        }

        std::size_t end = index;
        while (end < table.size() && table[end] != 0)
            ++end;

        const ida::Address length = static_cast<ida::Address>(end - index + 1);
        ida::data::define_string(base + index, length);
        index = end + 1;
    }
}

bool is_within_file(std::uint64_t file_size, std::uint64_t offset,
                    std::uint64_t size = 1) {
    if (offset > file_size)
        return false;
    if (size > (file_size - offset))
        return false;
    return true;
}

class JbcFullLoader final : public ida::loader::Loader {
public:
    ida::loader::LoaderOptions options() const override {
        ida::loader::LoaderOptions opts;
        opts.supports_reload = true;
        opts.requires_processor = false;
        return opts;
    }

    ida::Result<std::optional<ida::loader::AcceptResult>>
    accept(ida::loader::InputFile& file) override {
        auto size = file.size();
        if (!size || *size < static_cast<std::int64_t>(kMinimumHeaderSize))
            return std::nullopt;

        auto magic_bytes = file.read_bytes_at(0, 4);
        if (!magic_bytes || magic_bytes->size() != 4)
            return std::nullopt;

        const std::uint32_t magic = read_little_endian_u32(magic_bytes->data());
        if (magic != kMagicVersion1 && magic != kMagicVersion2)
            return std::nullopt;

        ida::loader::AcceptResult result;
        result.format_name = "JAM Byte-Code (JBC) [idax full]";
        result.processor_name = "jbc";
        result.priority = (magic == kMagicVersion2) ? 120 : 100;
        return result;
    }

    ida::Status load(ida::loader::InputFile& file,
                     std::string_view format_name) override {
        (void)format_name;

        auto file_size_result = file.size();
        if (!file_size_result)
            return std::unexpected(file_size_result.error());
        const std::uint64_t file_size = static_cast<std::uint64_t>(*file_size_result);

        auto processor = ida::loader::set_processor("jbc");
        if (!processor)
            return processor;

        ida::loader::create_filename_comment();

        auto first_word = read_be32_at(file, 0);
        if (!first_word)
            return std::unexpected(first_word.error());

        const int version = static_cast<int>(*first_word & 1u);
        const std::uint32_t delta = static_cast<std::uint32_t>(version * 8);

        auto action_table = read_be32_at(file, 4);
        auto proc_table = read_be32_at(file, 8);
        auto string_table = read_be32_at(file, 4 + delta);
        auto symbol_table = read_be32_at(file, 16 + delta);
        auto data_section = read_be32_at(file, 20 + delta);
        auto code_section = read_be32_at(file, 24 + delta);
        auto debug_section = read_be32_at(file, 28 + delta);
        auto action_count = read_be32_at(file, 40 + delta);
        auto proc_count = read_be32_at(file, 44 + delta);
        auto symbol_count = read_be32_at(file, 48 + (2 * delta));
        if (!action_table || !proc_table || !string_table || !symbol_table ||
            !data_section || !code_section || !debug_section || !action_count ||
            !proc_count || !symbol_count) {
            return std::unexpected(ida::Error::validation(
                "Failed reading one or more JBC header fields"));
        }

        std::uint32_t note_strings = 0;
        if (version > 0) {
            auto ns = read_be32_at(file, 16);
            if (ns)
                note_strings = *ns;
        }

        std::uint32_t string_size = 0;
        if (version == 0) {
            if (*symbol_table > *string_table) {
                string_size = *symbol_table - *string_table;
            } else if (*data_section > *string_table) {
                string_size = *data_section - *string_table;
            }
        } else if (note_strings > *string_table) {
            string_size = note_strings - *string_table;
        }

        if (*debug_section == 0 || *debug_section > file_size) {
            *debug_section = (*data_section > 0) ? *data_section
                                                 : static_cast<std::uint32_t>(file_size);
        }

        ida::ui::message(fmt(
            "[JBC full loader] version=%d action_count=%u proc_count=%u symbol_count=%u\n",
            version + 1, *action_count, *proc_count, *symbol_count));

        std::vector<std::uint8_t> string_table_bytes;
        if (string_size > 0 &&
            is_within_file(file_size, *string_table, string_size)) {
            if (string_size > 1024u * 1024u) {
                string_size = 1024u * 1024u;
                ida::ui::message("[JBC full loader] string table capped at 1MB\n");
            }
            auto bytes = file.read_bytes_at(static_cast<std::int64_t>(*string_table),
                                            string_size);
            if (bytes)
                string_table_bytes = std::move(*bytes);
        }

        if (!is_within_file(file_size, *code_section)) {
            return std::unexpected(ida::Error::validation(
                "Invalid JBC code section offset", std::to_string(*code_section)));
        }

        std::uint64_t code_size = 0;
        if (*data_section > *code_section && *data_section <= file_size) {
            code_size = *data_section - *code_section;
        } else {
            code_size = file_size - *code_section;
        }

        std::uint64_t data_size = 0;
        if (*data_section > 0 && *data_section < file_size)
            data_size = file_size - *data_section;

        ida::Address current = 0x10000;
        ida::Address string_base = ida::BadAddress;
        ida::Address code_base = ida::BadAddress;

        if (!string_table_bytes.empty()) {
            const ida::Address start = align16(current);
            const ida::Address end = start + string_table_bytes.size();
            auto created = ida::segment::create(start, end,
                                                kSegmentStrings,
                                                "CONST",
                                                ida::segment::Type::Data);
            if (!created)
                return std::unexpected(created.error());

            ida::segment::set_permissions(start, {.read = true, .write = false, .execute = false});
            ida::segment::set_bitness(start, 32);
            auto load_status = ida::loader::file_to_database(file.handle(),
                                                             *string_table,
                                                             start,
                                                             string_table_bytes.size(),
                                                             true);
            if (!load_status)
                return load_status;

            string_base = start;
            define_embedded_strings(string_base, string_table_bytes);
            current = end;
        }

        if (code_size > 0) {
            const ida::Address start = align16(current);
            const ida::Address end = start + code_size;

            auto created = ida::segment::create(start, end,
                                                kSegmentCode,
                                                "CODE",
                                                ida::segment::Type::Code);
            if (!created)
                return std::unexpected(created.error());

            ida::segment::set_permissions(start, {.read = true, .write = false, .execute = true});
            ida::segment::set_bitness(start, 32);

            auto load_status = ida::loader::file_to_database(file.handle(),
                                                             *code_section,
                                                             start,
                                                             code_size,
                                                             true);
            if (!load_status)
                return load_status;

            code_base = start;
            current = end;
        }

        if (data_size > 0) {
            const ida::Address start = align16(current);
            const ida::Address end = start + data_size;

            auto created = ida::segment::create(start, end,
                                                kSegmentData,
                                                "DATA",
                                                ida::segment::Type::Data);
            if (!created)
                return std::unexpected(created.error());

            ida::segment::set_permissions(start, {.read = true, .write = true, .execute = false});
            ida::segment::set_bitness(start, 32);

            auto load_status = ida::loader::file_to_database(file.handle(),
                                                             *data_section,
                                                             start,
                                                             data_size,
                                                             true);
            if (!load_status)
                return load_status;

            current = end;
        }

        // Seed default CS/DS register values across all loaded segments.
        // This mirrors the raw SDK pattern (`set_default_sreg_value`) used by
        // existing JBC processor modules.
        auto cs_seed = ida::segment::set_default_segment_register_for_all(kRegisterCs, 0);
        if (!cs_seed) {
            ida::ui::message(fmt(
                "[JBC full loader] warning: failed to seed CS default (%s)\n",
                cs_seed.error().message.c_str()));
        }

        auto ds_seed = ida::segment::set_default_segment_register_for_all(kRegisterDs, 0);
        if (!ds_seed) {
            ida::ui::message(fmt(
                "[JBC full loader] warning: failed to seed DS default (%s)\n",
                ds_seed.error().message.c_str()));
        }

        if (code_base != ida::BadAddress &&
            *action_count > 0 && *action_count < 4096 &&
            is_within_file(file_size, *action_table)) {
            for (std::uint32_t index = 0; index < *action_count; ++index) {
                const std::uint64_t entry_offset =
                    static_cast<std::uint64_t>(*action_table) +
                    static_cast<std::uint64_t>(index) * 12u;
                if (!is_within_file(file_size, entry_offset, 12))
                    break;

                auto name_offset = read_be32_at(file, static_cast<std::int64_t>(entry_offset));
                auto proc_index = read_be32_at(file, static_cast<std::int64_t>(entry_offset + 8));
                if (!name_offset || !proc_index)
                    continue;
                if (*proc_index >= *proc_count)
                    continue;

                std::string action_name = string_at(string_table_bytes, *name_offset);
                if (action_name.empty())
                    continue;

                const std::uint64_t proc_offset =
                    static_cast<std::uint64_t>(*proc_table) +
                    static_cast<std::uint64_t>(*proc_index) * 13u + 9u;
                if (!is_within_file(file_size, proc_offset, 4))
                    continue;

                auto proc_code_offset = read_be32_at(file, static_cast<std::int64_t>(proc_offset));
                if (!proc_code_offset)
                    continue;

                ida::Address entry_address = code_base + *proc_code_offset;
                ida::entry::add(index, entry_address, action_name, true);
                ida::name::force_set(entry_address, action_name);
            }
        }

        if (code_base != ida::BadAddress &&
            *proc_count > 0 && *proc_count < 100000 &&
            is_within_file(file_size, *proc_table)) {
            for (std::uint32_t index = 0; index < *proc_count; ++index) {
                const std::uint64_t entry_offset =
                    static_cast<std::uint64_t>(*proc_table) +
                    static_cast<std::uint64_t>(index) * 13u;
                if (!is_within_file(file_size, entry_offset, 13))
                    break;

                auto name_offset = read_be32_at(file, static_cast<std::int64_t>(entry_offset));
                auto proc_code_offset = read_be32_at(file, static_cast<std::int64_t>(entry_offset + 9));
                auto attributes = read_u8_at(file, static_cast<std::int64_t>(entry_offset + 8));
                (void)attributes;
                if (!name_offset || !proc_code_offset)
                    continue;

                ida::Address procedure_address = code_base + *proc_code_offset;
                std::string procedure_name = string_at(string_table_bytes, *name_offset);
                if (!procedure_name.empty()) {
                    ida::name::force_set(procedure_address, procedure_name);
                }

                ida::analysis::schedule_function(procedure_address);
            }
        }

        auto state_node = ida::storage::Node::open(kStateNodeName, true);
        if (state_node) {
            state_node->set_alt(kStateCodeBaseIndex,
                                code_base == ida::BadAddress ? 0 : code_base);
            state_node->set_alt(kStateStringBaseIndex,
                                string_base == ida::BadAddress ? 0 : string_base);
        }

        ida::ui::message("[JBC full loader] load complete\n");
        return ida::ok();
    }
};

}  // namespace

IDAX_LOADER(JbcFullLoader)

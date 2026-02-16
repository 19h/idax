/// \file database.cpp
/// \brief Implementation of ida::database — query and metadata functions.
///
/// Lifecycle functions (init, open, close) are in database_lifecycle.cpp
/// to avoid pulling idalib-only symbols into plugin link units.

#include "detail/sdk_bridge.hpp"
#include <ida/database.hpp>

#include <cstdio>

namespace ida::database {

namespace {

struct ImportCollectionContext {
    std::vector<ImportSymbol>* symbols{nullptr};
};

int idaapi collect_import_symbol(ea_t address,
                                 const char* name,
                                 uval_t ordinal,
                                 void* user_data) {
    auto* context = static_cast<ImportCollectionContext*>(user_data);
    if (context == nullptr || context->symbols == nullptr)
        return 0;

    ImportSymbol symbol;
    symbol.address = static_cast<Address>(address);
    if (name != nullptr)
        symbol.name = std::string(name);
    symbol.ordinal = static_cast<std::uint64_t>(ordinal);
    context->symbols->push_back(std::move(symbol));
    return 1;
}

} // namespace

// ── Save (available in plugin context via libida) ───────────────────────

Status save() {
    save_database(nullptr, 0);
    return ida::ok();
}

Status file_to_database(std::string_view file_path,
                        std::int64_t file_offset,
                        Address ea,
                        AddressSize size,
                        bool patchable,
                        bool remote) {
    if (size == 0)
        return ida::ok();
    if (ea > (BadAddress - size))
        return std::unexpected(Error::validation("Address range overflow"));

    std::string path(file_path);
    linput_t* li = open_linput(path.c_str(), remote);
    if (li == nullptr)
        return std::unexpected(Error::not_found("open_linput failed", path));

    ea_t ea1 = static_cast<ea_t>(ea);
    ea_t ea2 = static_cast<ea_t>(ea + size);
    int rc = ::file2base(li,
                         static_cast<qoff64_t>(file_offset),
                         ea1,
                         ea2,
                         patchable ? FILEREG_PATCHABLE : FILEREG_NOTPATCHABLE);
    close_linput(li);

    if (rc != 1)
        return std::unexpected(Error::sdk("file2base failed", path));
    return ida::ok();
}

Status memory_to_database(std::span<const std::uint8_t> bytes,
                          Address ea,
                          std::int64_t file_offset) {
    if (bytes.empty())
        return ida::ok();
    if (ea > (BadAddress - bytes.size()))
        return std::unexpected(Error::validation("Address range overflow"));

    ea_t ea1 = static_cast<ea_t>(ea);
    ea_t ea2 = static_cast<ea_t>(ea + bytes.size());
    int rc = ::mem2base(bytes.data(), ea1, ea2, static_cast<qoff64_t>(file_offset));
    if (rc != 1)
        return std::unexpected(Error::sdk("mem2base failed"));
    return ida::ok();
}

// ── Metadata ────────────────────────────────────────────────────────────

Result<std::string> input_file_path() {
    char buf[QMAXPATH];
    if (get_input_file_path(buf, sizeof(buf)) <= 0)
        return std::unexpected(Error::not_found("No input file path available"));
    return std::string(buf);
}

Result<std::string> file_type_name() {
    char buf[256] = {0};
    if (get_file_type_name(buf, sizeof(buf)) == 0 || buf[0] == '\0')
        return std::unexpected(Error::not_found("No file type name available"));
    return std::string(buf);
}

Result<std::string> loader_format_name() {
    qstring out;
    if (get_loader_format_name(&out) <= 0 || out.empty())
        return std::unexpected(Error::not_found("No loader format name available"));
    return ida::detail::to_string(out);
}

Result<std::string> input_md5() {
    uchar hash[16];
    if (!retrieve_input_file_md5(hash))
        return std::unexpected(Error::not_found("No MD5 available for input file"));
    // Convert 16-byte hash to 32-char hex string.
    std::string hex;
    hex.reserve(32);
    static const char digits[] = "0123456789abcdef";
    for (int i = 0; i < 16; ++i) {
        hex.push_back(digits[(hash[i] >> 4) & 0xF]);
        hex.push_back(digits[hash[i] & 0xF]);
    }
    return hex;
}

Result<CompilerInfo> compiler_info() {
    const comp_t raw_id = inf_get_cc_id();
    const comp_t normalized_id = get_comp(raw_id);

    CompilerInfo out;
    out.id = static_cast<std::uint32_t>(normalized_id);
    out.uncertain = is_comp_unsure(raw_id) != 0;

    if (const char* full = get_compiler_name(normalized_id); full != nullptr)
        out.name = std::string(full);
    if (const char* abbr = get_compiler_abbr(normalized_id); abbr != nullptr)
        out.abbreviation = std::string(abbr);

    if (out.name.empty() && out.abbreviation.empty()) {
        out.name = "Unknown";
    }

    return out;
}

Result<std::vector<ImportModule>> import_modules() {
    const uint module_count = get_import_module_qty();
    std::vector<ImportModule> modules;
    modules.reserve(module_count);

    for (uint index = 0; index < module_count; ++index) {
        qstring module_name;
        if (!get_import_module_name(&module_name, static_cast<int>(index))) {
            return std::unexpected(
                Error::sdk("get_import_module_name failed", std::to_string(index)));
        }

        ImportModule module;
        module.index = static_cast<std::size_t>(index);
        module.name = ida::detail::to_string(module_name);

        ImportCollectionContext context{&module.symbols};
        const int rc = enum_import_names(static_cast<int>(index), collect_import_symbol, &context);
        if (rc == -1) {
            return std::unexpected(
                Error::sdk("enum_import_names failed", module.name));
        }
        if (rc != 1) {
            return std::unexpected(Error::sdk(
                "enum_import_names aborted",
                module.name + " (callback return code: " + std::to_string(rc) + ")"));
        }

        modules.push_back(std::move(module));
    }

    return modules;
}

Result<Address> image_base() {
    ea_t base = get_imagebase();
    return static_cast<Address>(base);
}

Result<Address> min_address() {
    ea_t ea = inf_get_min_ea();
    return static_cast<Address>(ea);
}

Result<Address> max_address() {
    ea_t ea = inf_get_max_ea();
    return static_cast<Address>(ea);
}

Result<ida::address::Range> address_bounds() {
    auto lo = min_address();
    if (!lo)
        return std::unexpected(lo.error());
    auto hi = max_address();
    if (!hi)
        return std::unexpected(hi.error());
    if (*hi < *lo)
        return std::unexpected(Error::sdk("Invalid address bounds",
                                          std::to_string(*lo) + ">" + std::to_string(*hi)));
    return ida::address::Range{*lo, *hi};
}

Result<AddressSize> address_span() {
    auto bounds = address_bounds();
    if (!bounds)
        return std::unexpected(bounds.error());
    return bounds->size();
}

// NOTE: processor_id() and processor_name() are declared in database.hpp
// but implemented in address.cpp to avoid pulling idalib-only symbols
// (init_library, open_database, close_database) into plugin link units
// that reference ida::database::processor_id().

// ── Snapshot wrappers ────────────────────────────────────────────────────

namespace {

Snapshot to_public_snapshot(const snapshot_t& s) {
    Snapshot out;
    out.id = static_cast<std::int64_t>(s.id);
    out.flags = s.flags;
    out.description = std::string(s.desc);
    out.filename = std::string(s.filename);
    out.children.reserve(s.children.size());
    for (const snapshot_t* child : s.children) {
        if (child != nullptr)
            out.children.push_back(to_public_snapshot(*child));
    }
    return out;
}

} // namespace

Result<std::vector<Snapshot>> snapshots() {
    snapshot_t root;
    if (!build_snapshot_tree(&root))
        return std::unexpected(Error::sdk("build_snapshot_tree failed"));

    std::vector<Snapshot> out;
    out.reserve(root.children.size());
    for (const snapshot_t* child : root.children) {
        if (child != nullptr)
            out.push_back(to_public_snapshot(*child));
    }
    return out;
}

Status set_snapshot_description(std::string_view description) {
    snapshot_t root;
    if (!build_snapshot_tree(&root))
        return std::unexpected(Error::sdk("build_snapshot_tree failed"));

    snapshot_t attr;
    qstrncpy(attr.desc, std::string(description).c_str(), sizeof(attr.desc));
    if (!update_snapshot_attributes(nullptr, &root, &attr, SSUF_DESC)) {
        return std::unexpected(Error::sdk("update_snapshot_attributes failed"));
    }
    return ida::ok();
}

Result<bool> is_snapshot_database() {
    return inf_is_snapshot();
}

} // namespace ida::database

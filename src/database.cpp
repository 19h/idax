/// \file database.cpp
/// \brief Implementation of ida::database — lifecycle and metadata.

#include "detail/sdk_bridge.hpp"
#include <ida/database.hpp>

#include <cstdio>

namespace ida::database {

// ── Lifecycle ───────────────────────────────────────────────────────────

Status init(int argc, char* argv[]) {
    int rc = init_library(argc, argv);
    if (rc != 0)
        return std::unexpected(Error::sdk("init_library failed",
                                          "return code: " + std::to_string(rc)));
    return ida::ok();
}

Status open(std::string_view path, bool auto_analysis) {
    qstring qpath = ida::detail::to_qstring(path);
    int rc = open_database(qpath.c_str(), auto_analysis);
    if (rc != 0)
        return std::unexpected(Error::sdk("open_database failed",
                                          std::string(path)));
    return ida::ok();
}

Status save() {
    save_database(nullptr, 0);
    return ida::ok();
}

Status close(bool save_first) {
    close_database(save_first);
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

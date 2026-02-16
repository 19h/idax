/// \file database.cpp
/// \brief Implementation of ida::database — lifecycle and metadata.

#include "detail/sdk_bridge.hpp"
#include <ida/database.hpp>

#include <chrono>
#include <cstdio>
#include <filesystem>
#include <system_error>

namespace ida::database {

namespace {

namespace fs = std::filesystem;

struct ImportCollectionContext {
    std::vector<ImportSymbol>* symbols{nullptr};
};

bool should_auto_analysis(OpenMode mode) {
    return mode == OpenMode::Analyze;
}

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

bool wildcard_match(std::string_view text, std::string_view pattern) {
    std::size_t text_index = 0;
    std::size_t pattern_index = 0;
    std::size_t star_index = std::string_view::npos;
    std::size_t match_after_star = 0;

    while (text_index < text.size()) {
        if (pattern_index < pattern.size()
            && (pattern[pattern_index] == '?' || pattern[pattern_index] == text[text_index])) {
            ++text_index;
            ++pattern_index;
            continue;
        }

        if (pattern_index < pattern.size() && pattern[pattern_index] == '*') {
            star_index = pattern_index++;
            match_after_star = text_index;
            continue;
        }

        if (star_index != std::string_view::npos) {
            pattern_index = star_index + 1;
            text_index = ++match_after_star;
            continue;
        }

        return false;
    }

    while (pattern_index < pattern.size() && pattern[pattern_index] == '*')
        ++pattern_index;

    return pattern_index == pattern.size();
}

bool matches_any_allowlist_pattern(std::string_view name,
                                   const std::vector<std::string>& patterns) {
    for (const auto& pattern : patterns) {
        if (!pattern.empty() && wildcard_match(name, pattern))
            return true;
    }
    return false;
}

Status set_environment_variable(std::string_view name, std::string_view value) {
    if (!qsetenv(std::string(name).c_str(), std::string(value).c_str())) {
        return std::unexpected(Error::sdk("qsetenv failed",
                                          std::string(name) + "=" + std::string(value)));
    }
    return ida::ok();
}

Status mirror_entry(const fs::path& source, const fs::path& target) {
    std::error_code ec;

    if (fs::exists(target, ec)) {
        fs::remove_all(target, ec);
        ec.clear();
    }

    const bool is_dir = fs::is_directory(source, ec);
    if (ec) {
        return std::unexpected(Error::sdk("is_directory failed",
                                          source.string() + ": " + ec.message()));
    }

    if (is_dir)
        fs::create_directory_symlink(source, target, ec);
    else
        fs::create_symlink(source, target, ec);

    if (!ec)
        return ida::ok();

    // Fallback for platforms/filesystems where symlinks are restricted.
    ec.clear();
    if (is_dir) {
        fs::copy(source,
                 target,
                 fs::copy_options::recursive
                     | fs::copy_options::copy_symlinks
                     | fs::copy_options::overwrite_existing,
                 ec);
    } else {
        fs::copy_file(source, target, fs::copy_options::overwrite_existing, ec);
    }
    if (ec) {
        return std::unexpected(Error::sdk("Failed to mirror IDAUSR entry",
                                          target.string() + ": " + ec.message()));
    }
    return ida::ok();
}

Status configure_user_plugin_policy(const PluginLoadPolicy& policy) {
    const bool requested = policy.disable_user_plugins
                        || !policy.allowlist_patterns.empty();
    if (!requested)
        return ida::ok();

#ifdef _WIN32
    return std::unexpected(Error::unsupported(
        "Plugin policy controls are not implemented on Windows yet"));
#else
    fs::path source_user_dir;

    qstring idausr;
    if (qgetenv("IDAUSR", &idausr) && !idausr.empty()) {
        source_user_dir = fs::path(ida::detail::to_string(idausr));
    } else {
        qstring home;
        if (qgetenv("HOME", &home) && !home.empty()) {
            source_user_dir = fs::path(ida::detail::to_string(home)) / ".idapro";
        }
    }

    std::error_code ec;
    fs::path tmp_base = fs::temp_directory_path(ec);
    if (ec || tmp_base.empty()) {
        ec.clear();
        tmp_base = fs::path("/tmp");
    }

    const auto now = std::chrono::high_resolution_clock::now().time_since_epoch().count();
    fs::path sandbox_root = tmp_base / ("idax_idausr_" + std::to_string(now));
    fs::path sandbox_user = sandbox_root / "user";
    fs::path sandbox_plugins = sandbox_user / "plugins";

    fs::create_directories(sandbox_plugins, ec);
    if (ec) {
        return std::unexpected(Error::sdk("Failed to create plugin sandbox",
                                          sandbox_plugins.string() + ": " + ec.message()));
    }

    if (!source_user_dir.empty() && fs::exists(source_user_dir, ec) && fs::is_directory(source_user_dir, ec)) {
        for (const auto& entry : fs::directory_iterator(source_user_dir, ec)) {
            if (ec) {
                return std::unexpected(Error::sdk("Failed to enumerate IDAUSR",
                                                  source_user_dir.string() + ": " + ec.message()));
            }

            const fs::path name = entry.path().filename();
            if (name == "plugins")
                continue;

            auto mirrored = mirror_entry(entry.path(), sandbox_user / name);
            if (!mirrored)
                return std::unexpected(mirrored.error());
        }

        const fs::path source_plugins = source_user_dir / "plugins";
        if (fs::exists(source_plugins, ec) && fs::is_directory(source_plugins, ec)) {
            const bool has_allowlist = !policy.allowlist_patterns.empty();
            const bool copy_all_plugins = !policy.disable_user_plugins && !has_allowlist;
            for (const auto& entry : fs::directory_iterator(source_plugins, ec)) {
                if (ec) {
                    return std::unexpected(Error::sdk("Failed to enumerate user plugins",
                                                      source_plugins.string() + ": " + ec.message()));
                }

                if (!copy_all_plugins && !has_allowlist)
                    continue;

                const std::string name = entry.path().filename().string();
                if (has_allowlist
                    && !matches_any_allowlist_pattern(name, policy.allowlist_patterns)) {
                    continue;
                }

                auto mirrored = mirror_entry(entry.path(), sandbox_plugins / entry.path().filename());
                if (!mirrored)
                    return std::unexpected(mirrored.error());
            }
        }
    }

    auto set = set_environment_variable("IDAUSR", sandbox_user.string());
    if (!set)
        return std::unexpected(set.error());

    return ida::ok();
#endif
}

Status apply_runtime_options_pre_init(const RuntimeOptions& options) {
    return configure_user_plugin_policy(options.plugin_policy);
}

void apply_runtime_options_post_init(const RuntimeOptions& options) {
    if (options.quiet)
        enable_console_messages(false);
}

} // namespace

// ── Lifecycle ───────────────────────────────────────────────────────────

Status init(int argc, char* argv[]) {
    return init(argc, argv, RuntimeOptions{});
}

Status init(int argc, char* argv[], const RuntimeOptions& options) {
    auto pre = apply_runtime_options_pre_init(options);
    if (!pre)
        return std::unexpected(pre.error());

    int rc = init_library(argc, argv);
    if (rc != 0)
        return std::unexpected(Error::sdk("init_library failed",
                                          "return code: " + std::to_string(rc)));

    apply_runtime_options_post_init(options);
    return ida::ok();
}

Status init(const RuntimeOptions& options) {
    return init(0, nullptr, options);
}

Status open(std::string_view path, bool auto_analysis) {
    if (path.empty())
        return std::unexpected(Error::validation("Database path cannot be empty"));

    qstring qpath = ida::detail::to_qstring(path);
    int rc = open_database(qpath.c_str(), auto_analysis);
    if (rc != 0)
        return std::unexpected(Error::sdk("open_database failed",
                                          std::string(path)));
    return ida::ok();
}

Status open(std::string_view path, OpenMode mode) {
    return open(path, should_auto_analysis(mode));
}

Status open(std::string_view path, LoadIntent intent, OpenMode mode) {
    switch (intent) {
    case LoadIntent::AutoDetect:
        return open(path, mode);
    case LoadIntent::Binary:
        return open_binary(path, mode);
    case LoadIntent::NonBinary:
        return open_non_binary(path, mode);
    }
    return std::unexpected(Error::validation("Invalid load intent"));
}

Status open_binary(std::string_view path, OpenMode mode) {
    // open_database() currently performs loader selection automatically.
    // This wrapper exists to make caller intent explicit.
    return open(path, mode);
}

Status open_non_binary(std::string_view path, OpenMode mode) {
    // open_database() currently performs loader selection automatically.
    // This wrapper exists to make caller intent explicit.
    return open(path, mode);
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

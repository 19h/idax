/**
 * @file idax_shim.cpp
 * @brief C shim implementation bridging extern "C" calls to the idax C++ API.
 *
 * Thread-local error state captures the last error for retrieval.
 * All string outputs are strdup'd (malloc) — callers free via idax_free_string().
 */

#include "idax_shim.h"

#include <ida/idax.hpp>

#include <cstdlib>
#include <cstring>
#include <mutex>
#include <optional>
#include <string>
#include <type_traits>
#include <unordered_map>
#include <vector>

// ── Runtime IDA library loader ──────────────────────────────────────────
// Instead of linking libida/libidalib at compile time (which creates @rpath
// references requiring RPATH entries in every consuming binary), we load them
// at runtime via dlopen before any IDA function is called. This makes
// `cargo add idax` + `cargo run` work without any build.rs, RPATH config,
// or environment variables — provided IDA is installed in a standard location.

#if !defined(_WIN32)
#include <dlfcn.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace {

#if !defined(_WIN32)

struct IdaLibLoader {
    bool attempted = false;
    bool loaded    = false;

    /// Try to dlopen a library from a specific directory.
    /// Returns true if the library was loaded (or was already loaded).
    bool try_load(const std::string& dir, const char* libname) {
        std::string path = dir + "/" + libname;
        struct stat st;
        if (stat(path.c_str(), &st) != 0)
            return false;
        void* h = dlopen(path.c_str(), RTLD_NOW | RTLD_GLOBAL);
        return h != nullptr;
    }

    /// Try to load both libida and libidalib from a directory.
    bool try_dir(const std::string& dir) {
#if defined(__APPLE__)
        const char* ida_lib   = "libida.dylib";
        const char* idalib_lib = "libidalib.dylib";
#else
        const char* ida_lib   = "libida.so";
        const char* idalib_lib = "libidalib.so";
#endif
        if (!try_load(dir, ida_lib))
            return false;
        // libidalib is optional (not present in all IDA editions)
        try_load(dir, idalib_lib);
        return true;
    }

    /// Auto-discover IDA installation directories.
    std::vector<std::string> discover() {
        std::vector<std::string> candidates;

        // 1. $IDADIR — explicit user override (highest priority)
        if (const char* idadir = std::getenv("IDADIR")) {
            if (idadir[0] != '\0')
                candidates.emplace_back(idadir);
        }

#if defined(__APPLE__)
        // 2. Scan /Applications for IDA *.app bundles
        if (DIR* d = opendir("/Applications")) {
            while (struct dirent* e = readdir(d)) {
                std::string name(e->d_name);
                if (name.size() > 4
                    && (name.rfind("IDA", 0) == 0 || name.rfind("ida", 0) == 0)
                    && name.substr(name.size() - 4) == ".app")
                {
                    candidates.push_back(
                        "/Applications/" + name + "/Contents/MacOS");
                }
            }
            closedir(d);
        }
#else // Linux
        // 2a. Scan /opt for idapro-* / ida-* / ida directories
        if (DIR* d = opendir("/opt")) {
            while (struct dirent* e = readdir(d)) {
                std::string name(e->d_name);
                if (name.rfind("idapro", 0) == 0
                    || name.rfind("ida-", 0) == 0
                    || name == "ida")
                {
                    candidates.push_back("/opt/" + name);
                }
            }
            closedir(d);
        }
        // 2b. Scan ~/ida* directories
        if (const char* home = std::getenv("HOME")) {
            if (DIR* d = opendir(home)) {
                while (struct dirent* e = readdir(d)) {
                    std::string name(e->d_name);
                    if (name.rfind("ida", 0) == 0) {
                        std::string p = std::string(home) + "/" + name;
                        struct stat st;
                        if (stat(p.c_str(), &st) == 0 && S_ISDIR(st.st_mode))
                            candidates.push_back(std::move(p));
                    }
                }
                closedir(d);
            }
        }
#endif
        return candidates;
    }

    /// Ensure IDA libraries are loaded. Safe to call multiple times.
    bool ensure_loaded() {
        if (attempted)
            return loaded;
        attempted = true;

        // Check if libida is already loaded (e.g. we're running as an IDA
        // plugin, or the user set LD_LIBRARY_PATH / DYLD_LIBRARY_PATH).
#if defined(__APPLE__)
        if (dlopen("libida.dylib", RTLD_NOW | RTLD_GLOBAL | RTLD_NOLOAD)) {
#else
        if (dlopen("libida.so", RTLD_NOW | RTLD_GLOBAL | RTLD_NOLOAD)) {
#endif
            loaded = true;
            return true;
        }

        auto dirs = discover();
        for (auto& dir : dirs) {
            if (try_dir(dir)) {
                loaded = true;
                return true;
            }
        }
        return false;
    }
};

static IdaLibLoader g_ida_loader;

#endif // !_WIN32

} // anonymous loader namespace

// ── Thread-local error state ────────────────────────────────────────────

namespace {

struct ErrorState {
    int         category = IDAX_ERROR_NONE;
    int         code     = 0;
    std::string message;
};

thread_local ErrorState g_last_error;

void clear_error() {
    g_last_error.category = IDAX_ERROR_NONE;
    g_last_error.code     = 0;
    g_last_error.message.clear();
}

void set_error(const ida::Error& err) {
    switch (err.category) {
        case ida::ErrorCategory::Validation:  g_last_error.category = IDAX_ERROR_VALIDATION; break;
        case ida::ErrorCategory::NotFound:    g_last_error.category = IDAX_ERROR_NOT_FOUND; break;
        case ida::ErrorCategory::Conflict:    g_last_error.category = IDAX_ERROR_CONFLICT; break;
        case ida::ErrorCategory::Unsupported: g_last_error.category = IDAX_ERROR_UNSUPPORTED; break;
        case ida::ErrorCategory::SdkFailure:  g_last_error.category = IDAX_ERROR_SDK_FAILURE; break;
        case ida::ErrorCategory::Internal:    g_last_error.category = IDAX_ERROR_INTERNAL; break;
    }
    g_last_error.code = err.code;
    g_last_error.message = err.message;
    if (!err.context.empty()) {
        g_last_error.message += " [";
        g_last_error.message += err.context;
        g_last_error.message += "]";
    }
}

int fail(const ida::Error& err) {
    set_error(err);
    return -1;
}

char* dup_string(const std::string& s) {
    char* p = static_cast<char*>(std::malloc(s.size() + 1));
    if (p) {
        std::memcpy(p, s.c_str(), s.size() + 1);
    }
    return p;
}

ida::Result<ida::address::Predicate> parse_address_predicate(int predicate) {
    using P = ida::address::Predicate;
    switch (predicate) {
        case 0: return P::Mapped;
        case 1: return P::Loaded;
        case 2: return P::Code;
        case 3: return P::Data;
        case 4: return P::Unknown;
        case 5: return P::Head;
        case 6: return P::Tail;
        default:
            return std::unexpected(ida::Error::validation(
                "Invalid address predicate",
                std::to_string(predicate)));
    }
}

int fill_string_array(const std::vector<std::string>& lines,
                      char*** out,
                      size_t* count) {
    *count = lines.size();
    if (lines.empty()) {
        *out = nullptr;
        return 0;
    }

    char** arr = static_cast<char**>(std::malloc(lines.size() * sizeof(char*)));
    if (!arr) {
        return fail(ida::Error::internal("malloc failed"));
    }

    for (size_t i = 0; i < lines.size(); ++i) {
        arr[i] = dup_string(lines[i]);
        if (!arr[i]) {
            for (size_t j = 0; j < i; ++j) {
                std::free(arr[j]);
            }
            std::free(arr);
            return fail(ida::Error::internal("malloc failed"));
        }
    }

    *out = arr;
    return 0;
}

void fill_loader_flags(IdaxLoaderLoadFlags* out, const ida::loader::LoadFlags& in) {
    out->create_segments = in.create_segments ? 1 : 0;
    out->load_resources = in.load_resources ? 1 : 0;
    out->rename_entries = in.rename_entries ? 1 : 0;
    out->manual_load = in.manual_load ? 1 : 0;
    out->fill_gaps = in.fill_gaps ? 1 : 0;
    out->create_import_segment = in.create_import_segment ? 1 : 0;
    out->first_file = in.first_file ? 1 : 0;
    out->binary_code_segment = in.binary_code_segment ? 1 : 0;
    out->reload = in.reload ? 1 : 0;
    out->auto_flat_group = in.auto_flat_group ? 1 : 0;
    out->mini_database = in.mini_database ? 1 : 0;
    out->loader_options_dialog = in.loader_options_dialog ? 1 : 0;
    out->load_all_segments = in.load_all_segments ? 1 : 0;
}

ida::loader::LoadFlags parse_loader_flags(const IdaxLoaderLoadFlags& in) {
    ida::loader::LoadFlags out;
    out.create_segments = in.create_segments != 0;
    out.load_resources = in.load_resources != 0;
    out.rename_entries = in.rename_entries != 0;
    out.manual_load = in.manual_load != 0;
    out.fill_gaps = in.fill_gaps != 0;
    out.create_import_segment = in.create_import_segment != 0;
    out.first_file = in.first_file != 0;
    out.binary_code_segment = in.binary_code_segment != 0;
    out.reload = in.reload != 0;
    out.auto_flat_group = in.auto_flat_group != 0;
    out.mini_database = in.mini_database != 0;
    out.loader_options_dialog = in.loader_options_dialog != 0;
    out.load_all_segments = in.load_all_segments != 0;
    return out;
}

ida::Result<ida::loader::InputFile> wrap_loader_input(void* li_handle) {
    if (li_handle == nullptr) {
        return std::unexpected(ida::Error::validation("loader input handle is null"));
    }
    static_assert(std::is_trivially_copyable_v<ida::loader::InputFile>);
    static_assert(sizeof(ida::loader::InputFile) == sizeof(void*));
    ida::loader::InputFile input{};
#pragma GCC diagnostic push
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic ignored "-Wclass-memaccess"
#endif
    std::memcpy(&input, &li_handle, sizeof(li_handle));
#pragma GCC diagnostic pop
    return input;
}

// Helper macros for common patterns
#define RETURN_RESULT_STRING(expr) \
    do { \
        clear_error(); \
        auto _r = (expr); \
        if (!_r) return fail(_r.error()); \
        *out = dup_string(*_r); \
        return 0; \
    } while(0)

#define RETURN_RESULT_VALUE(expr) \
    do { \
        clear_error(); \
        auto _r = (expr); \
        if (!_r) return fail(_r.error()); \
        *out = *_r; \
        return 0; \
    } while(0)

#define RETURN_STATUS(expr) \
    do { \
        clear_error(); \
        auto _s = (expr); \
        if (!_s) return fail(_s.error()); \
        return 0; \
    } while(0)

#define RETURN_RESULT_VEC_ADDR(expr) \
    do { \
        clear_error(); \
        auto _r = (expr); \
        if (!_r) return fail(_r.error()); \
        auto& _v = *_r; \
        *count = _v.size(); \
        if (_v.empty()) { *out = nullptr; return 0; } \
        *out = static_cast<uint64_t*>(std::malloc(_v.size() * sizeof(uint64_t))); \
        if (!*out) return fail(ida::Error::internal("malloc failed")); \
        std::memcpy(*out, _v.data(), _v.size() * sizeof(uint64_t)); \
        return 0; \
    } while(0)

} // anonymous namespace

// ═══════════════════════════════════════════════════════════════════════════
// Error handling
// ═══════════════════════════════════════════════════════════════════════════

int idax_last_error_category(void) {
    return g_last_error.category;
}

int idax_last_error_code(void) {
    return g_last_error.code;
}

const char* idax_last_error_message(void) {
    return g_last_error.message.c_str();
}

void idax_free_string(char* s) {
    std::free(s);
}

void idax_free_bytes(uint8_t* p) {
    std::free(p);
}

void idax_free_addresses(uint64_t* p) {
    std::free(p);
}

// ═══════════════════════════════════════════════════════════════════════════
// Database
// ═══════════════════════════════════════════════════════════════════════════

namespace {

ida::Result<ida::database::OpenMode> parse_database_open_mode(int mode) {
    switch (mode) {
        case 0:
            return ida::database::OpenMode::Analyze;
        case 1:
            return ida::database::OpenMode::SkipAnalysis;
        default:
            return std::unexpected(ida::Error::validation(
                "Invalid database open mode",
                std::to_string(mode)));
    }
}

void free_import_module_contents(IdaxDatabaseImportModule* module) {
    if (module == nullptr) {
        return;
    }
    if (module->symbols != nullptr) {
        for (size_t i = 0; i < module->symbol_count; ++i) {
            std::free(module->symbols[i].name);
            module->symbols[i].name = nullptr;
        }
        std::free(module->symbols);
        module->symbols = nullptr;
    }
    module->symbol_count = 0;
    std::free(module->name);
    module->name = nullptr;
}

int fill_snapshot(IdaxDatabaseSnapshot* out, const ida::database::Snapshot& in);

void free_snapshot_contents(IdaxDatabaseSnapshot* snapshot) {
    if (snapshot == nullptr) {
        return;
    }
    if (snapshot->children != nullptr) {
        for (size_t i = 0; i < snapshot->child_count; ++i) {
            free_snapshot_contents(&snapshot->children[i]);
        }
        std::free(snapshot->children);
        snapshot->children = nullptr;
    }
    snapshot->child_count = 0;
    std::free(snapshot->description);
    std::free(snapshot->filename);
    snapshot->description = nullptr;
    snapshot->filename = nullptr;
}

int fill_snapshot(IdaxDatabaseSnapshot* out, const ida::database::Snapshot& in) {
    out->id = in.id;
    out->flags = in.flags;
    out->description = dup_string(in.description);
    out->filename = dup_string(in.filename);
    out->children = nullptr;
    out->child_count = in.children.size();

    if ((out->description == nullptr || out->filename == nullptr)
        && (!in.description.empty() || !in.filename.empty())) {
        free_snapshot_contents(out);
        return fail(ida::Error::internal("malloc failed"));
    }

    if (in.children.empty()) {
        return 0;
    }

    out->children = static_cast<IdaxDatabaseSnapshot*>(
        std::calloc(in.children.size(), sizeof(IdaxDatabaseSnapshot)));
    if (out->children == nullptr) {
        free_snapshot_contents(out);
        return fail(ida::Error::internal("malloc failed"));
    }

    for (size_t i = 0; i < in.children.size(); ++i) {
        if (fill_snapshot(&out->children[i], in.children[i]) != 0) {
            for (size_t j = 0; j < i; ++j) {
                free_snapshot_contents(&out->children[j]);
            }
            std::free(out->children);
            out->children = nullptr;
            out->child_count = 0;
            std::free(out->description);
            std::free(out->filename);
            out->description = nullptr;
            out->filename = nullptr;
            return -1;
        }
    }

    return 0;
}

} // anonymous namespace

int idax_database_init(int argc, char** argv) {
#if !defined(_WIN32)
    // Ensure IDA shared libraries are loaded before calling any SDK function.
    // This is the magic that makes `cargo add idax` + `cargo run` work without
    // any RPATH configuration or build.rs in the user's crate.
    if (!g_ida_loader.ensure_loaded()) {
        g_last_error.category = IDAX_ERROR_SDK_FAILURE;
        g_last_error.code     = -1;
        g_last_error.message  = "Failed to locate IDA runtime libraries. "
            "Set IDADIR to the directory containing libida"
#if defined(__APPLE__)
            ".dylib"
#else
            ".so"
#endif
            " (e.g. /Applications/IDA\\ Pro.app/Contents/MacOS)";
        return -1;
    }
#endif
    RETURN_STATUS(ida::database::init(argc, argv));
}

int idax_database_open(const char* path, int auto_analysis) {
    RETURN_STATUS(ida::database::open(path, auto_analysis != 0));
}

int idax_database_open_binary(const char* path, int mode) {
    clear_error();
    auto parsed = parse_database_open_mode(mode);
    if (!parsed) return fail(parsed.error());
    auto s = ida::database::open_binary(path, *parsed);
    if (!s) return fail(s.error());
    return 0;
}

int idax_database_open_non_binary(const char* path, int mode) {
    clear_error();
    auto parsed = parse_database_open_mode(mode);
    if (!parsed) return fail(parsed.error());
    auto s = ida::database::open_non_binary(path, *parsed);
    if (!s) return fail(s.error());
    return 0;
}

int idax_database_save(void) {
    RETURN_STATUS(ida::database::save());
}

int idax_database_close(int save) {
    RETURN_STATUS(ida::database::close(save != 0));
}

int idax_database_file_to_database(const char* file_path, int64_t file_offset,
                                   uint64_t ea, uint64_t size,
                                   int patchable, int remote) {
    RETURN_STATUS(ida::database::file_to_database(
        file_path, file_offset, ea, size, patchable != 0, remote != 0));
}

int idax_database_memory_to_database(const uint8_t* bytes, size_t len,
                                     uint64_t ea, int64_t file_offset) {
    RETURN_STATUS(ida::database::memory_to_database(
        std::span<const uint8_t>(bytes, len), ea, file_offset));
}

void idax_database_compiler_info_free(IdaxDatabaseCompilerInfo* info) {
    if (info) {
        std::free(info->name);
        std::free(info->abbreviation);
        info->name = nullptr;
        info->abbreviation = nullptr;
    }
}

int idax_database_compiler_info(IdaxDatabaseCompilerInfo* out) {
    clear_error();
    auto r = ida::database::compiler_info();
    if (!r) return fail(r.error());
    out->id = r->id;
    out->uncertain = r->uncertain ? 1 : 0;
    out->name = dup_string(r->name);
    out->abbreviation = dup_string(r->abbreviation);
    if ((out->name == nullptr || out->abbreviation == nullptr)
        && (!r->name.empty() || !r->abbreviation.empty())) {
        idax_database_compiler_info_free(out);
        return fail(ida::Error::internal("malloc failed"));
    }
    return 0;
}

int idax_database_import_modules(IdaxDatabaseImportModule** out, size_t* count) {
    clear_error();
    auto r = ida::database::import_modules();
    if (!r) return fail(r.error());
    auto& modules = *r;
    *count = modules.size();
    if (modules.empty()) {
        *out = nullptr;
        return 0;
    }

    *out = static_cast<IdaxDatabaseImportModule*>(
        std::calloc(modules.size(), sizeof(IdaxDatabaseImportModule)));
    if (*out == nullptr) return fail(ida::Error::internal("malloc failed"));

    for (size_t i = 0; i < modules.size(); ++i) {
        (*out)[i].index = modules[i].index;
        (*out)[i].name = dup_string(modules[i].name);
        if ((*out)[i].name == nullptr && !modules[i].name.empty()) {
            idax_database_import_modules_free(*out, i + 1);
            *out = nullptr;
            *count = 0;
            return fail(ida::Error::internal("malloc failed"));
        }

        (*out)[i].symbol_count = modules[i].symbols.size();
        if (modules[i].symbols.empty()) {
            (*out)[i].symbols = nullptr;
            continue;
        }

        (*out)[i].symbols = static_cast<IdaxDatabaseImportSymbol*>(
            std::calloc(modules[i].symbols.size(), sizeof(IdaxDatabaseImportSymbol)));
        if ((*out)[i].symbols == nullptr) {
            idax_database_import_modules_free(*out, i + 1);
            *out = nullptr;
            *count = 0;
            return fail(ida::Error::internal("malloc failed"));
        }

        for (size_t j = 0; j < modules[i].symbols.size(); ++j) {
            (*out)[i].symbols[j].address = modules[i].symbols[j].address;
            (*out)[i].symbols[j].ordinal = modules[i].symbols[j].ordinal;
            (*out)[i].symbols[j].name = dup_string(modules[i].symbols[j].name);
            if ((*out)[i].symbols[j].name == nullptr && !modules[i].symbols[j].name.empty()) {
                idax_database_import_modules_free(*out, i + 1);
                *out = nullptr;
                *count = 0;
                return fail(ida::Error::internal("malloc failed"));
            }
        }
    }
    return 0;
}

void idax_database_import_modules_free(IdaxDatabaseImportModule* modules,
                                       size_t count) {
    if (modules == nullptr) {
        return;
    }
    for (size_t i = 0; i < count; ++i) {
        free_import_module_contents(&modules[i]);
    }
    std::free(modules);
}

int idax_database_snapshots(IdaxDatabaseSnapshot** out, size_t* count) {
    clear_error();
    auto r = ida::database::snapshots();
    if (!r) return fail(r.error());
    auto& snapshots = *r;
    *count = snapshots.size();
    if (snapshots.empty()) {
        *out = nullptr;
        return 0;
    }

    *out = static_cast<IdaxDatabaseSnapshot*>(
        std::calloc(snapshots.size(), sizeof(IdaxDatabaseSnapshot)));
    if (*out == nullptr) return fail(ida::Error::internal("malloc failed"));

    for (size_t i = 0; i < snapshots.size(); ++i) {
        if (fill_snapshot(&(*out)[i], snapshots[i]) != 0) {
            idax_database_snapshots_free(*out, snapshots.size());
            *out = nullptr;
            *count = 0;
            return -1;
        }
    }
    return 0;
}

void idax_database_snapshots_free(IdaxDatabaseSnapshot* snapshots, size_t count) {
    if (snapshots == nullptr) {
        return;
    }
    for (size_t i = 0; i < count; ++i) {
        free_snapshot_contents(&snapshots[i]);
    }
    std::free(snapshots);
}

int idax_database_set_snapshot_description(const char* description) {
    RETURN_STATUS(ida::database::set_snapshot_description(
        description == nullptr ? "" : description));
}

int idax_database_is_snapshot_database(int* out) {
    clear_error();
    auto r = ida::database::is_snapshot_database();
    if (!r) return fail(r.error());
    *out = *r ? 1 : 0;
    return 0;
}

int idax_database_input_file_path(char** out) {
    RETURN_RESULT_STRING(ida::database::input_file_path());
}

int idax_database_file_type_name(char** out) {
    RETURN_RESULT_STRING(ida::database::file_type_name());
}

int idax_database_loader_format_name(char** out) {
    RETURN_RESULT_STRING(ida::database::loader_format_name());
}

int idax_database_input_md5(char** out) {
    RETURN_RESULT_STRING(ida::database::input_md5());
}

int idax_database_image_base(uint64_t* out) {
    RETURN_RESULT_VALUE(ida::database::image_base());
}

int idax_database_min_address(uint64_t* out) {
    RETURN_RESULT_VALUE(ida::database::min_address());
}

int idax_database_max_address(uint64_t* out) {
    RETURN_RESULT_VALUE(ida::database::max_address());
}

int idax_database_processor_id(int32_t* out) {
    RETURN_RESULT_VALUE(ida::database::processor_id());
}

int idax_database_processor_name(char** out) {
    RETURN_RESULT_STRING(ida::database::processor_name());
}

int idax_database_address_bitness(int* out) {
    RETURN_RESULT_VALUE(ida::database::address_bitness());
}

int idax_database_is_big_endian(int* out) {
    clear_error();
    auto r = ida::database::is_big_endian();
    if (!r) return fail(r.error());
    *out = *r ? 1 : 0;
    return 0;
}

int idax_database_abi_name(char** out) {
    RETURN_RESULT_STRING(ida::database::abi_name());
}

int idax_database_address_span(uint64_t* out) {
    RETURN_RESULT_VALUE(ida::database::address_span());
}

// ═══════════════════════════════════════════════════════════════════════════
// Address
// ═══════════════════════════════════════════════════════════════════════════

int idax_address_is_mapped(uint64_t ea) {
    return ida::address::is_mapped(ea) ? 1 : 0;
}

int idax_address_is_loaded(uint64_t ea) {
    return ida::address::is_loaded(ea) ? 1 : 0;
}

int idax_address_is_code(uint64_t ea) {
    return ida::address::is_code(ea) ? 1 : 0;
}

int idax_address_is_data(uint64_t ea) {
    return ida::address::is_data(ea) ? 1 : 0;
}

int idax_address_is_unknown(uint64_t ea) {
    return ida::address::is_unknown(ea) ? 1 : 0;
}

int idax_address_is_head(uint64_t ea) {
    return ida::address::is_head(ea) ? 1 : 0;
}

int idax_address_is_tail(uint64_t ea) {
    return ida::address::is_tail(ea) ? 1 : 0;
}

int idax_address_item_start(uint64_t ea, uint64_t* out) {
    RETURN_RESULT_VALUE(ida::address::item_start(ea));
}

int idax_address_item_end(uint64_t ea, uint64_t* out) {
    RETURN_RESULT_VALUE(ida::address::item_end(ea));
}

int idax_address_item_size(uint64_t ea, uint64_t* out) {
    RETURN_RESULT_VALUE(ida::address::item_size(ea));
}

int idax_address_next_head(uint64_t ea, uint64_t limit, uint64_t* out) {
    RETURN_RESULT_VALUE(ida::address::next_head(ea, limit));
}

int idax_address_prev_head(uint64_t ea, uint64_t limit, uint64_t* out) {
    RETURN_RESULT_VALUE(ida::address::prev_head(ea, limit));
}

int idax_address_next_not_tail(uint64_t ea, uint64_t* out) {
    RETURN_RESULT_VALUE(ida::address::next_not_tail(ea));
}

int idax_address_prev_not_tail(uint64_t ea, uint64_t* out) {
    RETURN_RESULT_VALUE(ida::address::prev_not_tail(ea));
}

int idax_address_next_mapped(uint64_t ea, uint64_t* out) {
    RETURN_RESULT_VALUE(ida::address::next_mapped(ea));
}

int idax_address_prev_mapped(uint64_t ea, uint64_t* out) {
    RETURN_RESULT_VALUE(ida::address::prev_mapped(ea));
}

int idax_address_find_first(uint64_t start, uint64_t end, int predicate,
                            uint64_t* out) {
    clear_error();
    auto p = parse_address_predicate(predicate);
    if (!p) return fail(p.error());
    auto r = ida::address::find_first(start, end, *p);
    if (!r) return fail(r.error());
    *out = *r;
    return 0;
}

int idax_address_find_next(uint64_t ea, int predicate, uint64_t end,
                           uint64_t* out) {
    clear_error();
    auto p = parse_address_predicate(predicate);
    if (!p) return fail(p.error());
    auto r = ida::address::find_next(ea, *p, end);
    if (!r) return fail(r.error());
    *out = *r;
    return 0;
}

// ═══════════════════════════════════════════════════════════════════════════
// Segment
// ═══════════════════════════════════════════════════════════════════════════

namespace {

void fill_segment(IdaxSegment* out, const ida::segment::Segment& seg) {
    out->start      = seg.start();
    out->end        = seg.end();
    out->bitness    = seg.bitness();
    out->type       = static_cast<int>(seg.type());
    auto perm       = seg.permissions();
    out->perm_read  = perm.read ? 1 : 0;
    out->perm_write = perm.write ? 1 : 0;
    out->perm_exec  = perm.execute ? 1 : 0;
    out->name       = dup_string(seg.name());
    out->class_name = dup_string(seg.class_name());
    out->visible    = seg.is_visible() ? 1 : 0;
}

} // anonymous namespace

void idax_segment_free(IdaxSegment* seg) {
    if (seg) {
        std::free(seg->name);
        std::free(seg->class_name);
        seg->name = nullptr;
        seg->class_name = nullptr;
    }
}

int idax_segment_at(uint64_t ea, IdaxSegment* out) {
    clear_error();
    auto r = ida::segment::at(ea);
    if (!r) return fail(r.error());
    fill_segment(out, *r);
    return 0;
}

int idax_segment_by_name(const char* name, IdaxSegment* out) {
    clear_error();
    auto r = ida::segment::by_name(name);
    if (!r) return fail(r.error());
    fill_segment(out, *r);
    return 0;
}

int idax_segment_by_index(size_t index, IdaxSegment* out) {
    clear_error();
    auto r = ida::segment::by_index(index);
    if (!r) return fail(r.error());
    fill_segment(out, *r);
    return 0;
}

int idax_segment_count(size_t* out) {
    RETURN_RESULT_VALUE(ida::segment::count());
}

int idax_segment_create(uint64_t start, uint64_t end, const char* name,
                        const char* class_name, int type) {
    clear_error();
    auto r = ida::segment::create(
        start, end, name,
        class_name ? class_name : "",
        static_cast<ida::segment::Type>(type));
    if (!r) return fail(r.error());
    return 0;
}

int idax_segment_remove(uint64_t ea) {
    RETURN_STATUS(ida::segment::remove(ea));
}

int idax_segment_set_name(uint64_t ea, const char* name) {
    RETURN_STATUS(ida::segment::set_name(ea, name));
}

int idax_segment_set_class(uint64_t ea, const char* class_name) {
    RETURN_STATUS(ida::segment::set_class(ea, class_name));
}

int idax_segment_set_type(uint64_t ea, int type) {
    RETURN_STATUS(ida::segment::set_type(ea, static_cast<ida::segment::Type>(type)));
}

int idax_segment_set_permissions(uint64_t ea, int read, int write, int exec) {
    ida::segment::Permissions perm;
    perm.read = read != 0;
    perm.write = write != 0;
    perm.execute = exec != 0;
    RETURN_STATUS(ida::segment::set_permissions(ea, perm));
}

int idax_segment_set_bitness(uint64_t ea, int bits) {
    RETURN_STATUS(ida::segment::set_bitness(ea, bits));
}

int idax_segment_comment(uint64_t ea, int repeatable, char** out) {
    RETURN_RESULT_STRING(ida::segment::comment(ea, repeatable != 0));
}

int idax_segment_set_comment(uint64_t ea, const char* text, int repeatable) {
    RETURN_STATUS(ida::segment::set_comment(ea, text, repeatable != 0));
}

int idax_segment_resize(uint64_t ea, uint64_t new_start, uint64_t new_end) {
    RETURN_STATUS(ida::segment::resize(ea, new_start, new_end));
}

int idax_segment_move(uint64_t ea, uint64_t new_start) {
    RETURN_STATUS(ida::segment::move(ea, new_start));
}

int idax_segment_next(uint64_t ea, IdaxSegment* out) {
    clear_error();
    auto r = ida::segment::next(ea);
    if (!r) return fail(r.error());
    fill_segment(out, *r);
    return 0;
}

int idax_segment_prev(uint64_t ea, IdaxSegment* out) {
    clear_error();
    auto r = ida::segment::prev(ea);
    if (!r) return fail(r.error());
    fill_segment(out, *r);
    return 0;
}

int idax_segment_set_default_segment_register(uint64_t ea,
                                              int register_index,
                                              uint64_t value) {
    RETURN_STATUS(ida::segment::set_default_segment_register(ea, register_index, value));
}

int idax_segment_set_default_segment_register_for_all(int register_index,
                                                      uint64_t value) {
    RETURN_STATUS(ida::segment::set_default_segment_register_for_all(register_index, value));
}

// ═══════════════════════════════════════════════════════════════════════════
// Function
// ═══════════════════════════════════════════════════════════════════════════

namespace {

void fill_function(IdaxFunction* out, const ida::function::Function& func) {
    out->start            = func.start();
    out->end              = func.end();
    out->name             = dup_string(func.name());
    out->bitness          = func.bitness();
    out->returns          = func.returns() ? 1 : 0;
    out->is_library       = func.is_library() ? 1 : 0;
    out->is_thunk         = func.is_thunk() ? 1 : 0;
    out->is_visible       = func.is_visible() ? 1 : 0;
    out->frame_local_size = func.frame_local_size();
    out->frame_regs_size  = func.frame_regs_size();
    out->frame_args_size  = func.frame_args_size();
}

} // anonymous namespace

void idax_function_free(IdaxFunction* func) {
    if (func) {
        std::free(func->name);
        func->name = nullptr;
    }
}

int idax_function_at(uint64_t ea, IdaxFunction* out) {
    clear_error();
    auto r = ida::function::at(ea);
    if (!r) return fail(r.error());
    fill_function(out, *r);
    return 0;
}

int idax_function_by_index(size_t index, IdaxFunction* out) {
    clear_error();
    auto r = ida::function::by_index(index);
    if (!r) return fail(r.error());
    fill_function(out, *r);
    return 0;
}

int idax_function_count(size_t* out) {
    RETURN_RESULT_VALUE(ida::function::count());
}

int idax_function_create(uint64_t start, uint64_t end, IdaxFunction* out) {
    clear_error();
    auto r = ida::function::create(start, end);
    if (!r) return fail(r.error());
    fill_function(out, *r);
    return 0;
}

int idax_function_remove(uint64_t ea) {
    RETURN_STATUS(ida::function::remove(ea));
}

int idax_function_name_at(uint64_t ea, char** out) {
    RETURN_RESULT_STRING(ida::function::name_at(ea));
}

int idax_function_set_start(uint64_t ea, uint64_t new_start) {
    RETURN_STATUS(ida::function::set_start(ea, new_start));
}

int idax_function_set_end(uint64_t ea, uint64_t new_end) {
    RETURN_STATUS(ida::function::set_end(ea, new_end));
}

int idax_function_update(uint64_t ea) {
    RETURN_STATUS(ida::function::update(ea));
}

int idax_function_reanalyze(uint64_t ea) {
    RETURN_STATUS(ida::function::reanalyze(ea));
}

int idax_function_comment(uint64_t ea, int repeatable, char** out) {
    RETURN_RESULT_STRING(ida::function::comment(ea, repeatable != 0));
}

int idax_function_set_comment(uint64_t ea, const char* text, int repeatable) {
    RETURN_STATUS(ida::function::set_comment(ea, text, repeatable != 0));
}

int idax_function_callers(uint64_t ea, uint64_t** out, size_t* count) {
    RETURN_RESULT_VEC_ADDR(ida::function::callers(ea));
}

int idax_function_callees(uint64_t ea, uint64_t** out, size_t* count) {
    RETURN_RESULT_VEC_ADDR(ida::function::callees(ea));
}

int idax_function_is_outlined(uint64_t ea, int* out) {
    clear_error();
    auto r = ida::function::is_outlined(ea);
    if (!r) return fail(r.error());
    *out = *r ? 1 : 0;
    return 0;
}

int idax_function_set_outlined(uint64_t ea, int outlined) {
    RETURN_STATUS(ida::function::set_outlined(ea, outlined != 0));
}

int idax_function_chunks(uint64_t ea, IdaxChunk** out, size_t* count) {
    clear_error();
    auto r = ida::function::chunks(ea);
    if (!r) return fail(r.error());
    auto& v = *r;
    *count = v.size();
    if (v.empty()) { *out = nullptr; return 0; }
    *out = static_cast<IdaxChunk*>(std::malloc(v.size() * sizeof(IdaxChunk)));
    if (!*out) return fail(ida::Error::internal("malloc failed"));
    for (size_t i = 0; i < v.size(); ++i) {
        (*out)[i].start   = v[i].start;
        (*out)[i].end     = v[i].end;
        (*out)[i].is_tail = v[i].is_tail ? 1 : 0;
        (*out)[i].owner   = v[i].owner;
    }
    return 0;
}

int idax_function_chunk_count(uint64_t ea, size_t* out) {
    RETURN_RESULT_VALUE(ida::function::chunk_count(ea));
}

int idax_function_add_tail(uint64_t func_ea, uint64_t tail_start, uint64_t tail_end) {
    RETURN_STATUS(ida::function::add_tail(func_ea, tail_start, tail_end));
}

int idax_function_remove_tail(uint64_t func_ea, uint64_t tail_ea) {
    RETURN_STATUS(ida::function::remove_tail(func_ea, tail_ea));
}

void idax_frame_variable_free(IdaxFrameVariable* var) {
    if (var) {
        std::free(var->name);
        std::free(var->comment);
        var->name = nullptr;
        var->comment = nullptr;
    }
}

void idax_register_variable_free(IdaxRegisterVariable* var) {
    if (var) {
        std::free(var->canonical_name);
        std::free(var->user_name);
        std::free(var->comment);
        var->canonical_name = nullptr;
        var->user_name = nullptr;
        var->comment = nullptr;
    }
}

void idax_register_variables_free(IdaxRegisterVariable* vars, size_t count) {
    if (!vars) {
        return;
    }
    for (size_t i = 0; i < count; ++i) {
        idax_register_variable_free(&vars[i]);
    }
    std::free(vars);
}

void idax_stack_frame_free(IdaxStackFrame* frame) {
    if (frame && frame->variables) {
        for (size_t i = 0; i < frame->variable_count; ++i) {
            idax_frame_variable_free(&frame->variables[i]);
        }
        std::free(frame->variables);
        frame->variables = nullptr;
        frame->variable_count = 0;
    }
}

int idax_function_frame(uint64_t ea, IdaxStackFrame* out) {
    clear_error();
    auto r = ida::function::frame(ea);
    if (!r) return fail(r.error());
    auto& f = *r;
    out->local_variables_size = f.local_variables_size();
    out->saved_registers_size = f.saved_registers_size();
    out->arguments_size       = f.arguments_size();
    out->total_size           = f.total_size();
    auto& vars = f.variables();
    out->variable_count = vars.size();
    if (vars.empty()) {
        out->variables = nullptr;
    } else {
        out->variables = static_cast<IdaxFrameVariable*>(
            std::malloc(vars.size() * sizeof(IdaxFrameVariable)));
        if (!out->variables) return fail(ida::Error::internal("malloc failed"));
        for (size_t i = 0; i < vars.size(); ++i) {
            out->variables[i].name        = dup_string(vars[i].name);
            out->variables[i].byte_offset = vars[i].byte_offset;
            out->variables[i].byte_size   = vars[i].byte_size;
            out->variables[i].comment     = dup_string(vars[i].comment);
            out->variables[i].is_special  = vars[i].is_special ? 1 : 0;
        }
    }
    return 0;
}

int idax_function_sp_delta_at(uint64_t ea, int64_t* out) {
    RETURN_RESULT_VALUE(ida::function::sp_delta_at(ea));
}

int idax_function_frame_variable_by_name(uint64_t ea,
                                         const char* name,
                                         IdaxFrameVariable* out) {
    clear_error();
    auto r = ida::function::frame_variable_by_name(ea, name == nullptr ? "" : name);
    if (!r) return fail(r.error());
    out->name = dup_string(r->name);
    out->byte_offset = r->byte_offset;
    out->byte_size = r->byte_size;
    out->comment = dup_string(r->comment);
    out->is_special = r->is_special ? 1 : 0;
    if ((out->name == nullptr || out->comment == nullptr)
        && (!r->name.empty() || !r->comment.empty())) {
        idax_frame_variable_free(out);
        return fail(ida::Error::internal("malloc failed"));
    }
    return 0;
}

int idax_function_frame_variable_by_offset(uint64_t ea,
                                           size_t byte_offset,
                                           IdaxFrameVariable* out) {
    clear_error();
    auto r = ida::function::frame_variable_by_offset(ea, byte_offset);
    if (!r) return fail(r.error());
    out->name = dup_string(r->name);
    out->byte_offset = r->byte_offset;
    out->byte_size = r->byte_size;
    out->comment = dup_string(r->comment);
    out->is_special = r->is_special ? 1 : 0;
    if ((out->name == nullptr || out->comment == nullptr)
        && (!r->name.empty() || !r->comment.empty())) {
        idax_frame_variable_free(out);
        return fail(ida::Error::internal("malloc failed"));
    }
    return 0;
}

int idax_function_define_stack_variable(uint64_t function_ea,
                                        const char* name,
                                        int32_t frame_offset,
                                        void* type) {
    clear_error();
    if (type == nullptr) {
        return fail(ida::Error::validation("Type pointer is null"));
    }
    auto* ti = static_cast<ida::type::TypeInfo*>(type);
    auto s = ida::function::define_stack_variable(function_ea,
                                                  name == nullptr ? "" : name,
                                                  frame_offset,
                                                  *ti);
    if (!s) return fail(s.error());
    return 0;
}

int idax_function_add_register_variable(uint64_t function_ea,
                                        uint64_t range_start,
                                        uint64_t range_end,
                                        const char* register_name,
                                        const char* user_name,
                                        const char* comment) {
    RETURN_STATUS(ida::function::add_register_variable(
        function_ea,
        range_start,
        range_end,
        register_name == nullptr ? "" : register_name,
        user_name == nullptr ? "" : user_name,
        comment == nullptr ? "" : comment));
}

int idax_function_find_register_variable(uint64_t function_ea,
                                         uint64_t ea,
                                         const char* register_name,
                                         IdaxRegisterVariable* out) {
    clear_error();
    auto r = ida::function::find_register_variable(function_ea,
                                                   ea,
                                                   register_name == nullptr ? "" : register_name);
    if (!r) return fail(r.error());
    out->range_start = r->range_start;
    out->range_end = r->range_end;
    out->canonical_name = dup_string(r->canonical_name);
    out->user_name = dup_string(r->user_name);
    out->comment = dup_string(r->comment);
    if ((out->canonical_name == nullptr || out->user_name == nullptr || out->comment == nullptr)
        && (!r->canonical_name.empty() || !r->user_name.empty() || !r->comment.empty())) {
        idax_register_variable_free(out);
        return fail(ida::Error::internal("malloc failed"));
    }
    return 0;
}

int idax_function_remove_register_variable(uint64_t function_ea,
                                           uint64_t range_start,
                                           uint64_t range_end,
                                           const char* register_name) {
    RETURN_STATUS(ida::function::remove_register_variable(
        function_ea,
        range_start,
        range_end,
        register_name == nullptr ? "" : register_name));
}

int idax_function_rename_register_variable(uint64_t function_ea,
                                           uint64_t ea,
                                           const char* register_name,
                                           const char* new_user_name) {
    RETURN_STATUS(ida::function::rename_register_variable(
        function_ea,
        ea,
        register_name == nullptr ? "" : register_name,
        new_user_name == nullptr ? "" : new_user_name));
}

int idax_function_has_register_variables(uint64_t function_ea,
                                         uint64_t ea,
                                         int* out) {
    clear_error();
    auto r = ida::function::has_register_variables(function_ea, ea);
    if (!r) return fail(r.error());
    *out = *r ? 1 : 0;
    return 0;
}

int idax_function_register_variables(uint64_t function_ea,
                                     IdaxRegisterVariable** out,
                                     size_t* count) {
    clear_error();
    auto r = ida::function::register_variables(function_ea);
    if (!r) return fail(r.error());
    auto& vars = *r;
    *count = vars.size();
    if (vars.empty()) {
        *out = nullptr;
        return 0;
    }

    *out = static_cast<IdaxRegisterVariable*>(
        std::calloc(vars.size(), sizeof(IdaxRegisterVariable)));
    if (*out == nullptr) {
        return fail(ida::Error::internal("malloc failed"));
    }

    for (size_t i = 0; i < vars.size(); ++i) {
        (*out)[i].range_start = vars[i].range_start;
        (*out)[i].range_end = vars[i].range_end;
        (*out)[i].canonical_name = dup_string(vars[i].canonical_name);
        (*out)[i].user_name = dup_string(vars[i].user_name);
        (*out)[i].comment = dup_string(vars[i].comment);
        if (((*out)[i].canonical_name == nullptr && !vars[i].canonical_name.empty())
            || ((*out)[i].user_name == nullptr && !vars[i].user_name.empty())
            || ((*out)[i].comment == nullptr && !vars[i].comment.empty())) {
            idax_register_variables_free(*out, i + 1);
            *out = nullptr;
            *count = 0;
            return fail(ida::Error::internal("malloc failed"));
        }
    }
    return 0;
}

int idax_function_item_addresses(uint64_t ea, uint64_t** out, size_t* count) {
    RETURN_RESULT_VEC_ADDR(ida::function::item_addresses(ea));
}

int idax_function_code_addresses(uint64_t ea, uint64_t** out, size_t* count) {
    RETURN_RESULT_VEC_ADDR(ida::function::code_addresses(ea));
}

// ═══════════════════════════════════════════════════════════════════════════
// Instruction
// ═══════════════════════════════════════════════════════════════════════════

namespace {

void fill_instruction(IdaxInstruction* out, const ida::instruction::Instruction& insn) {
    out->address       = insn.address();
    out->size          = insn.size();
    out->opcode        = insn.opcode();
    out->mnemonic      = dup_string(insn.mnemonic());
    auto& ops = insn.operands();
    out->operand_count = ops.size();
    if (ops.empty()) {
        out->operands = nullptr;
    } else {
        out->operands = static_cast<IdaxOperand*>(
            std::malloc(ops.size() * sizeof(IdaxOperand)));
        for (size_t i = 0; i < ops.size(); ++i) {
            out->operands[i].index          = ops[i].index();
            out->operands[i].type           = static_cast<int>(ops[i].type());
            out->operands[i].register_id    = ops[i].register_id();
            out->operands[i].value          = ops[i].value();
            out->operands[i].target_address = ops[i].target_address();
            out->operands[i].byte_width     = ops[i].byte_width();
            out->operands[i].register_name  = dup_string(ops[i].register_name());
            out->operands[i].register_category = static_cast<int>(ops[i].register_category());
        }
    }
}

} // anonymous namespace

void idax_instruction_free(IdaxInstruction* insn) {
    if (insn) {
        std::free(insn->mnemonic);
        insn->mnemonic = nullptr;
        if (insn->operands) {
            for (size_t i = 0; i < insn->operand_count; ++i) {
                std::free(insn->operands[i].register_name);
            }
            std::free(insn->operands);
            insn->operands = nullptr;
        }
        insn->operand_count = 0;
    }
}

int idax_instruction_decode(uint64_t ea, IdaxInstruction* out) {
    clear_error();
    auto r = ida::instruction::decode(ea);
    if (!r) return fail(r.error());
    fill_instruction(out, *r);
    return 0;
}

int idax_instruction_create(uint64_t ea, IdaxInstruction* out) {
    clear_error();
    auto r = ida::instruction::create(ea);
    if (!r) return fail(r.error());
    fill_instruction(out, *r);
    return 0;
}

int idax_instruction_text(uint64_t ea, char** out) {
    RETURN_RESULT_STRING(ida::instruction::text(ea));
}

int idax_instruction_set_operand_hex(uint64_t ea, int n) {
    RETURN_STATUS(ida::instruction::set_operand_hex(ea, n));
}

int idax_instruction_set_operand_decimal(uint64_t ea, int n) {
    RETURN_STATUS(ida::instruction::set_operand_decimal(ea, n));
}

int idax_instruction_set_operand_octal(uint64_t ea, int n) {
    RETURN_STATUS(ida::instruction::set_operand_octal(ea, n));
}

int idax_instruction_set_operand_binary(uint64_t ea, int n) {
    RETURN_STATUS(ida::instruction::set_operand_binary(ea, n));
}

int idax_instruction_set_operand_character(uint64_t ea, int n) {
    RETURN_STATUS(ida::instruction::set_operand_character(ea, n));
}

int idax_instruction_set_operand_float(uint64_t ea, int n) {
    RETURN_STATUS(ida::instruction::set_operand_float(ea, n));
}

int idax_instruction_set_operand_format(uint64_t ea,
                                        int n,
                                        int format,
                                        uint64_t base) {
    RETURN_STATUS(ida::instruction::set_operand_format(
        ea,
        n,
        static_cast<ida::instruction::OperandFormat>(format),
        base));
}

int idax_instruction_set_operand_offset(uint64_t ea, int n, uint64_t base) {
    RETURN_STATUS(ida::instruction::set_operand_offset(ea, n, base));
}

int idax_instruction_set_operand_struct_offset_by_name(uint64_t ea,
                                                       int n,
                                                       const char* structure_name,
                                                       int64_t delta) {
    RETURN_STATUS(ida::instruction::set_operand_struct_offset(
        ea,
        n,
        structure_name == nullptr ? "" : structure_name,
        delta));
}

int idax_instruction_set_operand_struct_offset_by_id(uint64_t ea,
                                                     int n,
                                                     uint64_t structure_id,
                                                     int64_t delta) {
    RETURN_STATUS(ida::instruction::set_operand_struct_offset(
        ea,
        n,
        structure_id,
        delta));
}

int idax_instruction_set_operand_based_struct_offset(uint64_t ea,
                                                     int n,
                                                     uint64_t operand_value,
                                                     uint64_t base) {
    RETURN_STATUS(ida::instruction::set_operand_based_struct_offset(
        ea,
        n,
        operand_value,
        base));
}

int idax_instruction_operand_struct_offset_path(uint64_t ea,
                                                int n,
                                                uint64_t** out_ids,
                                                size_t* out_count,
                                                int64_t* out_delta) {
    clear_error();
    auto r = ida::instruction::operand_struct_offset_path(ea, n);
    if (!r) return fail(r.error());
    *out_count = r->structure_ids.size();
    *out_delta = r->delta;
    if (r->structure_ids.empty()) {
        *out_ids = nullptr;
        return 0;
    }
    *out_ids = static_cast<uint64_t*>(
        std::malloc(r->structure_ids.size() * sizeof(uint64_t)));
    if (*out_ids == nullptr) {
        return fail(ida::Error::internal("malloc failed"));
    }
    std::memcpy(*out_ids,
                r->structure_ids.data(),
                r->structure_ids.size() * sizeof(uint64_t));
    return 0;
}

int idax_instruction_operand_struct_offset_path_names(uint64_t ea,
                                                      int n,
                                                      char*** out,
                                                      size_t* count) {
    clear_error();
    auto r = ida::instruction::operand_struct_offset_path_names(ea, n);
    if (!r) return fail(r.error());
    return fill_string_array(*r, out, count);
}

void idax_instruction_string_array_free(char** values, size_t count) {
    if (values == nullptr) {
        return;
    }
    for (size_t i = 0; i < count; ++i) {
        std::free(values[i]);
    }
    std::free(values);
}

int idax_instruction_set_operand_stack_variable(uint64_t ea, int n) {
    RETURN_STATUS(ida::instruction::set_operand_stack_variable(ea, n));
}

int idax_instruction_clear_operand_representation(uint64_t ea, int n) {
    RETURN_STATUS(ida::instruction::clear_operand_representation(ea, n));
}

int idax_instruction_set_forced_operand(uint64_t ea, int n, const char* text) {
    RETURN_STATUS(ida::instruction::set_forced_operand(ea, n, text));
}

int idax_instruction_get_forced_operand(uint64_t ea, int n, char** out) {
    RETURN_RESULT_STRING(ida::instruction::get_forced_operand(ea, n));
}

int idax_instruction_operand_text(uint64_t ea, int n, char** out) {
    RETURN_RESULT_STRING(ida::instruction::operand_text(ea, n));
}

int idax_instruction_operand_byte_width(uint64_t ea, int n, int* out) {
    RETURN_RESULT_VALUE(ida::instruction::operand_byte_width(ea, n));
}

int idax_instruction_operand_register_name(uint64_t ea, int n, char** out) {
    RETURN_RESULT_STRING(ida::instruction::operand_register_name(ea, n));
}

int idax_instruction_operand_register_category(uint64_t ea, int n, int* out) {
    clear_error();
    auto r = ida::instruction::operand_register_category(ea, n);
    if (!r) return fail(r.error());
    *out = static_cast<int>(*r);
    return 0;
}

int idax_instruction_toggle_operand_sign(uint64_t ea, int n) {
    RETURN_STATUS(ida::instruction::toggle_operand_sign(ea, n));
}

int idax_instruction_toggle_operand_negate(uint64_t ea, int n) {
    RETURN_STATUS(ida::instruction::toggle_operand_negate(ea, n));
}

int idax_instruction_code_refs_from(uint64_t ea, uint64_t** out, size_t* count) {
    RETURN_RESULT_VEC_ADDR(ida::instruction::code_refs_from(ea));
}

int idax_instruction_data_refs_from(uint64_t ea, uint64_t** out, size_t* count) {
    RETURN_RESULT_VEC_ADDR(ida::instruction::data_refs_from(ea));
}

int idax_instruction_call_targets(uint64_t ea, uint64_t** out, size_t* count) {
    RETURN_RESULT_VEC_ADDR(ida::instruction::call_targets(ea));
}

int idax_instruction_jump_targets(uint64_t ea, uint64_t** out, size_t* count) {
    RETURN_RESULT_VEC_ADDR(ida::instruction::jump_targets(ea));
}

int idax_instruction_has_fall_through(uint64_t ea) {
    return ida::instruction::has_fall_through(ea) ? 1 : 0;
}

int idax_instruction_is_call(uint64_t ea) {
    return ida::instruction::is_call(ea) ? 1 : 0;
}

int idax_instruction_is_return(uint64_t ea) {
    return ida::instruction::is_return(ea) ? 1 : 0;
}

int idax_instruction_is_jump(uint64_t ea) {
    return ida::instruction::is_jump(ea) ? 1 : 0;
}

int idax_instruction_is_conditional_jump(uint64_t ea) {
    return ida::instruction::is_conditional_jump(ea) ? 1 : 0;
}

int idax_instruction_next(uint64_t ea, IdaxInstruction* out) {
    clear_error();
    auto r = ida::instruction::next(ea);
    if (!r) return fail(r.error());
    fill_instruction(out, *r);
    return 0;
}

int idax_instruction_prev(uint64_t ea, IdaxInstruction* out) {
    clear_error();
    auto r = ida::instruction::prev(ea);
    if (!r) return fail(r.error());
    fill_instruction(out, *r);
    return 0;
}

// ═══════════════════════════════════════════════════════════════════════════
// Data
// ═══════════════════════════════════════════════════════════════════════════

namespace {

void free_typed_value_contents(IdaxDataTypedValue* value) {
    if (value == nullptr) {
        return;
    }
    std::free(value->string_value);
    value->string_value = nullptr;
    std::free(value->bytes);
    value->bytes = nullptr;
    value->byte_count = 0;

    if (value->elements != nullptr) {
        for (size_t i = 0; i < value->element_count; ++i) {
            free_typed_value_contents(&value->elements[i]);
        }
        std::free(value->elements);
        value->elements = nullptr;
    }
    value->element_count = 0;
}

int fill_typed_value(IdaxDataTypedValue* out, const ida::data::TypedValue& in) {
    out->kind = static_cast<int>(in.kind);
    out->unsigned_value = in.unsigned_value;
    out->signed_value = in.signed_value;
    out->floating_value = in.floating_value;
    out->pointer_value = in.pointer_value;
    out->string_value = nullptr;
    out->bytes = nullptr;
    out->byte_count = in.bytes.size();
    out->elements = nullptr;
    out->element_count = in.elements.size();

    out->string_value = dup_string(in.string_value);
    if (out->string_value == nullptr && !in.string_value.empty()) {
        free_typed_value_contents(out);
        return fail(ida::Error::internal("malloc failed"));
    }

    if (!in.bytes.empty()) {
        out->bytes = static_cast<uint8_t*>(std::malloc(in.bytes.size()));
        if (out->bytes == nullptr) {
            free_typed_value_contents(out);
            return fail(ida::Error::internal("malloc failed"));
        }
        std::memcpy(out->bytes, in.bytes.data(), in.bytes.size());
    }

    if (!in.elements.empty()) {
        out->elements = static_cast<IdaxDataTypedValue*>(
            std::calloc(in.elements.size(), sizeof(IdaxDataTypedValue)));
        if (out->elements == nullptr) {
            free_typed_value_contents(out);
            return fail(ida::Error::internal("malloc failed"));
        }
        for (size_t i = 0; i < in.elements.size(); ++i) {
            if (fill_typed_value(&out->elements[i], in.elements[i]) != 0) {
                free_typed_value_contents(out);
                return -1;
            }
        }
    }

    return 0;
}

int parse_typed_value(const IdaxDataTypedValue* in, ida::data::TypedValue* out) {
    if (in == nullptr || out == nullptr) {
        return fail(ida::Error::validation("Typed value pointer is null"));
    }

    switch (in->kind) {
        case IDAX_DATA_TYPED_UNSIGNED_INTEGER:
            out->kind = ida::data::TypedValueKind::UnsignedInteger;
            break;
        case IDAX_DATA_TYPED_SIGNED_INTEGER:
            out->kind = ida::data::TypedValueKind::SignedInteger;
            break;
        case IDAX_DATA_TYPED_FLOATING_POINT:
            out->kind = ida::data::TypedValueKind::FloatingPoint;
            break;
        case IDAX_DATA_TYPED_POINTER:
            out->kind = ida::data::TypedValueKind::Pointer;
            break;
        case IDAX_DATA_TYPED_STRING:
            out->kind = ida::data::TypedValueKind::String;
            break;
        case IDAX_DATA_TYPED_BYTES:
            out->kind = ida::data::TypedValueKind::Bytes;
            break;
        case IDAX_DATA_TYPED_ARRAY:
            out->kind = ida::data::TypedValueKind::Array;
            break;
        default:
            return fail(ida::Error::validation(
                "Invalid typed value kind",
                std::to_string(in->kind)));
    }

    out->unsigned_value = in->unsigned_value;
    out->signed_value = in->signed_value;
    out->floating_value = in->floating_value;
    out->pointer_value = in->pointer_value;
    out->string_value = in->string_value == nullptr ? "" : in->string_value;

    out->bytes.clear();
    if (in->byte_count > 0) {
        if (in->bytes == nullptr) {
            return fail(ida::Error::validation("Typed value bytes pointer is null"));
        }
        out->bytes.assign(in->bytes, in->bytes + in->byte_count);
    }

    out->elements.clear();
    out->elements.reserve(in->element_count);
    if (in->element_count > 0 && in->elements == nullptr) {
        return fail(ida::Error::validation("Typed value elements pointer is null"));
    }
    for (size_t i = 0; i < in->element_count; ++i) {
        ida::data::TypedValue element;
        if (parse_typed_value(&in->elements[i], &element) != 0) {
            return -1;
        }
        out->elements.push_back(std::move(element));
    }
    return 0;
}

} // anonymous namespace

int idax_data_read_byte(uint64_t ea, uint8_t* out) {
    RETURN_RESULT_VALUE(ida::data::read_byte(ea));
}

int idax_data_read_word(uint64_t ea, uint16_t* out) {
    RETURN_RESULT_VALUE(ida::data::read_word(ea));
}

int idax_data_read_dword(uint64_t ea, uint32_t* out) {
    RETURN_RESULT_VALUE(ida::data::read_dword(ea));
}

int idax_data_read_qword(uint64_t ea, uint64_t* out) {
    RETURN_RESULT_VALUE(ida::data::read_qword(ea));
}

int idax_data_read_bytes(uint64_t ea, uint64_t count, uint8_t** out, size_t* out_len) {
    clear_error();
    auto r = ida::data::read_bytes(ea, count);
    if (!r) return fail(r.error());
    auto& v = *r;
    *out_len = v.size();
    if (v.empty()) { *out = nullptr; return 0; }
    *out = static_cast<uint8_t*>(std::malloc(v.size()));
    if (!*out) return fail(ida::Error::internal("malloc failed"));
    std::memcpy(*out, v.data(), v.size());
    return 0;
}

int idax_data_read_string(uint64_t ea, uint64_t max_len, char** out) {
    RETURN_RESULT_STRING(ida::data::read_string(ea, max_len));
}

int idax_data_read_typed(uint64_t ea, void* type, IdaxDataTypedValue* out) {
    clear_error();
    if (type == nullptr || out == nullptr) {
        return fail(ida::Error::validation("type/value output pointer is null"));
    }
    auto* ti = static_cast<ida::type::TypeInfo*>(type);
    auto r = ida::data::read_typed(ea, *ti);
    if (!r) return fail(r.error());
    return fill_typed_value(out, *r);
}

int idax_data_write_typed(uint64_t ea, void* type, const IdaxDataTypedValue* value) {
    clear_error();
    if (type == nullptr || value == nullptr) {
        return fail(ida::Error::validation("type/value pointer is null"));
    }
    ida::data::TypedValue parsed;
    if (parse_typed_value(value, &parsed) != 0) {
        return -1;
    }
    auto* ti = static_cast<ida::type::TypeInfo*>(type);
    auto s = ida::data::write_typed(ea, *ti, parsed);
    if (!s) return fail(s.error());
    return 0;
}

void idax_data_typed_value_free(IdaxDataTypedValue* value) {
    free_typed_value_contents(value);
}

int idax_data_write_byte(uint64_t ea, uint8_t value) {
    RETURN_STATUS(ida::data::write_byte(ea, value));
}

int idax_data_write_word(uint64_t ea, uint16_t value) {
    RETURN_STATUS(ida::data::write_word(ea, value));
}

int idax_data_write_dword(uint64_t ea, uint32_t value) {
    RETURN_STATUS(ida::data::write_dword(ea, value));
}

int idax_data_write_qword(uint64_t ea, uint64_t value) {
    RETURN_STATUS(ida::data::write_qword(ea, value));
}

int idax_data_write_bytes(uint64_t ea, const uint8_t* data, size_t len) {
    RETURN_STATUS(ida::data::write_bytes(ea, std::span<const uint8_t>(data, len)));
}

int idax_data_patch_byte(uint64_t ea, uint8_t value) {
    RETURN_STATUS(ida::data::patch_byte(ea, value));
}

int idax_data_patch_word(uint64_t ea, uint16_t value) {
    RETURN_STATUS(ida::data::patch_word(ea, value));
}

int idax_data_patch_dword(uint64_t ea, uint32_t value) {
    RETURN_STATUS(ida::data::patch_dword(ea, value));
}

int idax_data_patch_qword(uint64_t ea, uint64_t value) {
    RETURN_STATUS(ida::data::patch_qword(ea, value));
}

int idax_data_patch_bytes(uint64_t ea, const uint8_t* data, size_t len) {
    RETURN_STATUS(ida::data::patch_bytes(ea, std::span<const uint8_t>(data, len)));
}

int idax_data_revert_patch(uint64_t ea) {
    RETURN_STATUS(ida::data::revert_patch(ea));
}

int idax_data_revert_patches(uint64_t ea, uint64_t count, uint64_t* reverted) {
    clear_error();
    auto r = ida::data::revert_patches(ea, count);
    if (!r) return fail(r.error());
    *reverted = *r;
    return 0;
}

int idax_data_original_byte(uint64_t ea, uint8_t* out) {
    RETURN_RESULT_VALUE(ida::data::original_byte(ea));
}

int idax_data_original_word(uint64_t ea, uint16_t* out) {
    RETURN_RESULT_VALUE(ida::data::original_word(ea));
}

int idax_data_original_dword(uint64_t ea, uint32_t* out) {
    RETURN_RESULT_VALUE(ida::data::original_dword(ea));
}

int idax_data_original_qword(uint64_t ea, uint64_t* out) {
    RETURN_RESULT_VALUE(ida::data::original_qword(ea));
}

int idax_data_define_byte(uint64_t ea, uint64_t count) {
    RETURN_STATUS(ida::data::define_byte(ea, count));
}

int idax_data_define_word(uint64_t ea, uint64_t count) {
    RETURN_STATUS(ida::data::define_word(ea, count));
}

int idax_data_define_dword(uint64_t ea, uint64_t count) {
    RETURN_STATUS(ida::data::define_dword(ea, count));
}

int idax_data_define_qword(uint64_t ea, uint64_t count) {
    RETURN_STATUS(ida::data::define_qword(ea, count));
}

int idax_data_define_oword(uint64_t ea, uint64_t count) {
    RETURN_STATUS(ida::data::define_oword(ea, count));
}

int idax_data_define_tbyte(uint64_t ea, uint64_t count) {
    RETURN_STATUS(ida::data::define_tbyte(ea, count));
}

int idax_data_define_float(uint64_t ea, uint64_t count) {
    RETURN_STATUS(ida::data::define_float(ea, count));
}

int idax_data_define_double(uint64_t ea, uint64_t count) {
    RETURN_STATUS(ida::data::define_double(ea, count));
}

int idax_data_define_string(uint64_t ea, uint64_t length, int32_t string_type) {
    RETURN_STATUS(ida::data::define_string(ea, length, string_type));
}

int idax_data_define_struct(uint64_t ea, uint64_t length, uint64_t structure_id) {
    RETURN_STATUS(ida::data::define_struct(ea, length, structure_id));
}

int idax_data_undefine(uint64_t ea, uint64_t count) {
    RETURN_STATUS(ida::data::undefine(ea, count));
}

int idax_data_find_binary_pattern(uint64_t start, uint64_t end,
                                  const char* pattern, int forward,
                                  uint64_t* out) {
    RETURN_RESULT_VALUE(ida::data::find_binary_pattern(start, end, pattern, forward != 0));
}

// ═══════════════════════════════════════════════════════════════════════════
// Name
// ═══════════════════════════════════════════════════════════════════════════

int idax_name_get(uint64_t ea, char** out) {
    RETURN_RESULT_STRING(ida::name::get(ea));
}

int idax_name_set(uint64_t ea, const char* name) {
    RETURN_STATUS(ida::name::set(ea, name));
}

int idax_name_force_set(uint64_t ea, const char* name) {
    RETURN_STATUS(ida::name::force_set(ea, name));
}

int idax_name_remove(uint64_t ea) {
    RETURN_STATUS(ida::name::remove(ea));
}

int idax_name_demangled(uint64_t ea, int form, char** out) {
    RETURN_RESULT_STRING(ida::name::demangled(ea, static_cast<ida::name::DemangleForm>(form)));
}

int idax_name_resolve(const char* name, uint64_t context, uint64_t* out) {
    RETURN_RESULT_VALUE(ida::name::resolve(name, context));
}

int idax_name_all_user_defined(uint64_t start, uint64_t end,
                               IdaxNameEntry** out, size_t* count) {
    clear_error();
    auto r = ida::name::all_user_defined(start, end);
    if (!r) return fail(r.error());
    auto& entries = *r;
    *count = entries.size();
    if (entries.empty()) {
        *out = nullptr;
        return 0;
    }
    *out = static_cast<IdaxNameEntry*>(std::calloc(entries.size(), sizeof(IdaxNameEntry)));
    if (*out == nullptr) return fail(ida::Error::internal("malloc failed"));

    for (size_t i = 0; i < entries.size(); ++i) {
        (*out)[i].address = entries[i].address;
        (*out)[i].name = dup_string(entries[i].name);
        if ((*out)[i].name == nullptr && !entries[i].name.empty()) {
            idax_name_entries_free(*out, entries.size());
            *out = nullptr;
            *count = 0;
            return fail(ida::Error::internal("malloc failed"));
        }
        (*out)[i].user_defined = entries[i].user_defined ? 1 : 0;
        (*out)[i].auto_generated = entries[i].auto_generated ? 1 : 0;
    }
    return 0;
}

void idax_name_entries_free(IdaxNameEntry* entries, size_t count) {
    if (entries == nullptr) {
        return;
    }
    for (size_t i = 0; i < count; ++i) {
        std::free(entries[i].name);
        entries[i].name = nullptr;
    }
    std::free(entries);
}

int idax_name_is_public(uint64_t ea) {
    return ida::name::is_public(ea) ? 1 : 0;
}

int idax_name_is_weak(uint64_t ea) {
    return ida::name::is_weak(ea) ? 1 : 0;
}

int idax_name_is_user_defined(uint64_t ea) {
    return ida::name::is_user_defined(ea) ? 1 : 0;
}

int idax_name_is_auto_generated(uint64_t ea) {
    return ida::name::is_auto_generated(ea) ? 1 : 0;
}

int idax_name_is_valid_identifier(const char* text, int* out) {
    clear_error();
    auto r = ida::name::is_valid_identifier(text == nullptr ? "" : text);
    if (!r) return fail(r.error());
    *out = *r ? 1 : 0;
    return 0;
}

int idax_name_sanitize_identifier(const char* text, char** out) {
    RETURN_RESULT_STRING(ida::name::sanitize_identifier(text == nullptr ? "" : text));
}

int idax_name_set_public(uint64_t ea, int value) {
    RETURN_STATUS(ida::name::set_public(ea, value != 0));
}

int idax_name_set_weak(uint64_t ea, int value) {
    RETURN_STATUS(ida::name::set_weak(ea, value != 0));
}

// ═══════════════════════════════════════════════════════════════════════════
// Xref
// ═══════════════════════════════════════════════════════════════════════════

namespace {

void fill_xrefs(const std::vector<ida::xref::Reference>& refs,
                IdaxXref** out, size_t* count) {
    *count = refs.size();
    if (refs.empty()) { *out = nullptr; return; }
    *out = static_cast<IdaxXref*>(std::malloc(refs.size() * sizeof(IdaxXref)));
    for (size_t i = 0; i < refs.size(); ++i) {
        (*out)[i].from         = refs[i].from;
        (*out)[i].to           = refs[i].to;
        (*out)[i].is_code      = refs[i].is_code ? 1 : 0;
        (*out)[i].type         = static_cast<int>(refs[i].type);
        (*out)[i].user_defined = refs[i].user_defined ? 1 : 0;
    }
}

int fill_ref_addresses(const std::vector<ida::xref::Reference>& refs,
                       bool use_to,
                       uint64_t** out,
                       size_t* count) {
    *count = refs.size();
    if (refs.empty()) {
        *out = nullptr;
        return 0;
    }

    *out = static_cast<uint64_t*>(std::malloc(refs.size() * sizeof(uint64_t)));
    if (!*out) return fail(ida::Error::internal("malloc failed"));

    for (size_t i = 0; i < refs.size(); ++i) {
        (*out)[i] = use_to ? refs[i].to : refs[i].from;
    }
    return 0;
}

} // anonymous namespace

int idax_xref_refs_from(uint64_t ea, IdaxXref** out, size_t* count) {
    clear_error();
    auto r = ida::xref::refs_from(ea);
    if (!r) return fail(r.error());
    fill_xrefs(*r, out, count);
    return 0;
}

int idax_xref_refs_to(uint64_t ea, IdaxXref** out, size_t* count) {
    clear_error();
    auto r = ida::xref::refs_to(ea);
    if (!r) return fail(r.error());
    fill_xrefs(*r, out, count);
    return 0;
}

int idax_xref_code_refs_from(uint64_t ea, uint64_t** out, size_t* count) {
    clear_error();
    auto r = ida::xref::code_refs_from(ea);
    if (!r) return fail(r.error());
    return fill_ref_addresses(*r, true, out, count);
}

int idax_xref_code_refs_to(uint64_t ea, uint64_t** out, size_t* count) {
    clear_error();
    auto r = ida::xref::code_refs_to(ea);
    if (!r) return fail(r.error());
    return fill_ref_addresses(*r, false, out, count);
}

int idax_xref_data_refs_from(uint64_t ea, uint64_t** out, size_t* count) {
    clear_error();
    auto r = ida::xref::data_refs_from(ea);
    if (!r) return fail(r.error());
    return fill_ref_addresses(*r, true, out, count);
}

int idax_xref_data_refs_to(uint64_t ea, uint64_t** out, size_t* count) {
    clear_error();
    auto r = ida::xref::data_refs_to(ea);
    if (!r) return fail(r.error());
    return fill_ref_addresses(*r, false, out, count);
}

int idax_xref_refs_from_range(uint64_t ea, IdaxXref** out, size_t* count) {
    clear_error();
    auto r = ida::xref::refs_from_range(ea);
    if (!r) return fail(r.error());
    std::vector<ida::xref::Reference> refs(r->begin(), r->end());
    fill_xrefs(refs, out, count);
    return 0;
}

int idax_xref_refs_to_range(uint64_t ea, IdaxXref** out, size_t* count) {
    clear_error();
    auto r = ida::xref::refs_to_range(ea);
    if (!r) return fail(r.error());
    std::vector<ida::xref::Reference> refs(r->begin(), r->end());
    fill_xrefs(refs, out, count);
    return 0;
}

int idax_xref_code_refs_from_range(uint64_t ea, uint64_t** out, size_t* count) {
    clear_error();
    auto r = ida::xref::code_refs_from_range(ea);
    if (!r) return fail(r.error());
    std::vector<ida::xref::Reference> refs(r->begin(), r->end());
    return fill_ref_addresses(refs, true, out, count);
}

int idax_xref_code_refs_to_range(uint64_t ea, uint64_t** out, size_t* count) {
    clear_error();
    auto r = ida::xref::code_refs_to_range(ea);
    if (!r) return fail(r.error());
    std::vector<ida::xref::Reference> refs(r->begin(), r->end());
    return fill_ref_addresses(refs, false, out, count);
}

int idax_xref_data_refs_from_range(uint64_t ea, uint64_t** out, size_t* count) {
    clear_error();
    auto r = ida::xref::data_refs_from_range(ea);
    if (!r) return fail(r.error());
    std::vector<ida::xref::Reference> refs(r->begin(), r->end());
    return fill_ref_addresses(refs, true, out, count);
}

int idax_xref_data_refs_to_range(uint64_t ea, uint64_t** out, size_t* count) {
    clear_error();
    auto r = ida::xref::data_refs_to_range(ea);
    if (!r) return fail(r.error());
    std::vector<ida::xref::Reference> refs(r->begin(), r->end());
    return fill_ref_addresses(refs, false, out, count);
}

int idax_xref_add_code(uint64_t from, uint64_t to, int type) {
    RETURN_STATUS(ida::xref::add_code(from, to, static_cast<ida::xref::CodeType>(type)));
}

int idax_xref_add_data(uint64_t from, uint64_t to, int type) {
    RETURN_STATUS(ida::xref::add_data(from, to, static_cast<ida::xref::DataType>(type)));
}

int idax_xref_remove_code(uint64_t from, uint64_t to) {
    RETURN_STATUS(ida::xref::remove_code(from, to));
}

int idax_xref_remove_data(uint64_t from, uint64_t to) {
    RETURN_STATUS(ida::xref::remove_data(from, to));
}

// ═══════════════════════════════════════════════════════════════════════════
// Comment
// ═══════════════════════════════════════════════════════════════════════════

int idax_comment_get(uint64_t ea, int repeatable, char** out) {
    RETURN_RESULT_STRING(ida::comment::get(ea, repeatable != 0));
}

int idax_comment_set(uint64_t ea, const char* text, int repeatable) {
    RETURN_STATUS(ida::comment::set(ea, text, repeatable != 0));
}

int idax_comment_append(uint64_t ea, const char* text, int repeatable) {
    RETURN_STATUS(ida::comment::append(ea, text, repeatable != 0));
}

int idax_comment_remove(uint64_t ea, int repeatable) {
    RETURN_STATUS(ida::comment::remove(ea, repeatable != 0));
}

int idax_comment_add_anterior(uint64_t ea, const char* text) {
    RETURN_STATUS(ida::comment::add_anterior(ea, text));
}

int idax_comment_add_posterior(uint64_t ea, const char* text) {
    RETURN_STATUS(ida::comment::add_posterior(ea, text));
}

int idax_comment_get_anterior(uint64_t ea, int line_index, char** out) {
    RETURN_RESULT_STRING(ida::comment::get_anterior(ea, line_index));
}

int idax_comment_get_posterior(uint64_t ea, int line_index, char** out) {
    RETURN_RESULT_STRING(ida::comment::get_posterior(ea, line_index));
}

int idax_comment_set_anterior(uint64_t ea, int line_index, const char* text) {
    RETURN_STATUS(ida::comment::set_anterior(ea, line_index, text));
}

int idax_comment_set_posterior(uint64_t ea, int line_index, const char* text) {
    RETURN_STATUS(ida::comment::set_posterior(ea, line_index, text));
}

int idax_comment_clear_anterior(uint64_t ea) {
    RETURN_STATUS(ida::comment::clear_anterior(ea));
}

int idax_comment_clear_posterior(uint64_t ea) {
    RETURN_STATUS(ida::comment::clear_posterior(ea));
}

int idax_comment_remove_anterior_line(uint64_t ea, int line_index) {
    RETURN_STATUS(ida::comment::remove_anterior_line(ea, line_index));
}

int idax_comment_remove_posterior_line(uint64_t ea, int line_index) {
    RETURN_STATUS(ida::comment::remove_posterior_line(ea, line_index));
}

namespace {

std::vector<std::string> collect_lines_input(const char* const* lines, size_t count) {
    std::vector<std::string> out;
    if (count > 0 && lines == nullptr) {
        return out;
    }
    out.reserve(count);
    for (size_t i = 0; i < count; ++i) {
        out.emplace_back(lines[i] ? lines[i] : "");
    }
    return out;
}

} // anonymous namespace

int idax_comment_set_anterior_lines(uint64_t ea, const char* const* lines,
                                    size_t count) {
    clear_error();
    if (count > 0 && lines == nullptr) {
        return fail(ida::Error::validation("lines pointer is null"));
    }
    auto in = collect_lines_input(lines, count);
    auto s = ida::comment::set_anterior_lines(ea, in);
    if (!s) return fail(s.error());
    return 0;
}

int idax_comment_set_posterior_lines(uint64_t ea, const char* const* lines,
                                     size_t count) {
    clear_error();
    if (count > 0 && lines == nullptr) {
        return fail(ida::Error::validation("lines pointer is null"));
    }
    auto in = collect_lines_input(lines, count);
    auto s = ida::comment::set_posterior_lines(ea, in);
    if (!s) return fail(s.error());
    return 0;
}

int idax_comment_anterior_lines(uint64_t ea, char*** out, size_t* count) {
    clear_error();
    auto r = ida::comment::anterior_lines(ea);
    if (!r) return fail(r.error());
    return fill_string_array(*r, out, count);
}

int idax_comment_posterior_lines(uint64_t ea, char*** out, size_t* count) {
    clear_error();
    auto r = ida::comment::posterior_lines(ea);
    if (!r) return fail(r.error());
    return fill_string_array(*r, out, count);
}

void idax_comment_lines_free(char** lines, size_t count) {
    if (lines) {
        for (size_t i = 0; i < count; ++i) {
            std::free(lines[i]);
        }
        std::free(lines);
    }
}

int idax_comment_render(uint64_t ea, int include_repeatable,
                        int include_extra_lines, char** out) {
    RETURN_RESULT_STRING(ida::comment::render(
        ea,
        include_repeatable != 0,
        include_extra_lines != 0));
}

// ═══════════════════════════════════════════════════════════════════════════
// Search
// ═══════════════════════════════════════════════════════════════════════════

int idax_search_text(const char* query, uint64_t start, int forward,
                     int case_sensitive, uint64_t* out) {
    auto dir = forward ? ida::search::Direction::Forward : ida::search::Direction::Backward;
    RETURN_RESULT_VALUE(ida::search::text(query, start, dir, case_sensitive != 0));
}

int idax_search_binary_pattern(const char* hex, uint64_t start, int forward,
                               uint64_t* out) {
    auto dir = forward ? ida::search::Direction::Forward : ida::search::Direction::Backward;
    RETURN_RESULT_VALUE(ida::search::binary_pattern(hex, start, dir));
}

int idax_search_immediate(uint64_t value, uint64_t start, int forward,
                          uint64_t* out) {
    auto dir = forward ? ida::search::Direction::Forward : ida::search::Direction::Backward;
    RETURN_RESULT_VALUE(ida::search::immediate(value, start, dir));
}

int idax_search_next_code(uint64_t ea, uint64_t* out) {
    RETURN_RESULT_VALUE(ida::search::next_code(ea));
}

int idax_search_next_data(uint64_t ea, uint64_t* out) {
    RETURN_RESULT_VALUE(ida::search::next_data(ea));
}

int idax_search_next_unknown(uint64_t ea, uint64_t* out) {
    RETURN_RESULT_VALUE(ida::search::next_unknown(ea));
}

int idax_search_next_error(uint64_t ea, uint64_t* out) {
    RETURN_RESULT_VALUE(ida::search::next_error(ea));
}

int idax_search_next_defined(uint64_t ea, uint64_t* out) {
    RETURN_RESULT_VALUE(ida::search::next_defined(ea));
}

// ═══════════════════════════════════════════════════════════════════════════
// Analysis
// ═══════════════════════════════════════════════════════════════════════════

int idax_analysis_is_enabled(void) {
    return ida::analysis::is_enabled() ? 1 : 0;
}

int idax_analysis_set_enabled(int enabled) {
    RETURN_STATUS(ida::analysis::set_enabled(enabled != 0));
}

int idax_analysis_is_idle(void) {
    return ida::analysis::is_idle() ? 1 : 0;
}

int idax_analysis_wait(void) {
    RETURN_STATUS(ida::analysis::wait());
}

int idax_analysis_wait_range(uint64_t start, uint64_t end) {
    RETURN_STATUS(ida::analysis::wait_range(start, end));
}

int idax_analysis_schedule(uint64_t ea) {
    RETURN_STATUS(ida::analysis::schedule(ea));
}

int idax_analysis_schedule_range(uint64_t start, uint64_t end) {
    RETURN_STATUS(ida::analysis::schedule_range(start, end));
}

int idax_analysis_schedule_code(uint64_t ea) {
    RETURN_STATUS(ida::analysis::schedule_code(ea));
}

int idax_analysis_schedule_function(uint64_t ea) {
    RETURN_STATUS(ida::analysis::schedule_function(ea));
}

int idax_analysis_schedule_reanalysis(uint64_t ea) {
    RETURN_STATUS(ida::analysis::schedule_reanalysis(ea));
}

int idax_analysis_schedule_reanalysis_range(uint64_t start, uint64_t end) {
    RETURN_STATUS(ida::analysis::schedule_reanalysis_range(start, end));
}

int idax_analysis_cancel(uint64_t start, uint64_t end) {
    RETURN_STATUS(ida::analysis::cancel(start, end));
}

int idax_analysis_revert_decisions(uint64_t start, uint64_t end) {
    RETURN_STATUS(ida::analysis::revert_decisions(start, end));
}

// ═══════════════════════════════════════════════════════════════════════════
// Type
// ═══════════════════════════════════════════════════════════════════════════

namespace {

ida::Result<ida::type::CallingConvention> parse_calling_convention(int cc) {
    using Cc = ida::type::CallingConvention;
    switch (cc) {
        case 0: return Cc::Unknown;
        case 1: return Cc::Cdecl;
        case 2: return Cc::Stdcall;
        case 3: return Cc::Pascal;
        case 4: return Cc::Fastcall;
        case 5: return Cc::Thiscall;
        case 6: return Cc::Swift;
        case 7: return Cc::Golang;
        case 8: return Cc::UserDefined;
        default:
            return std::unexpected(ida::Error::validation(
                "Invalid calling convention", std::to_string(cc)));
    }
}

int calling_convention_to_int(ida::type::CallingConvention cc) {
    return static_cast<int>(cc);
}

int fill_type_member(IdaxTypeMember* out, const ida::type::Member& member) {
    out->name = dup_string(member.name);
    out->type = new ida::type::TypeInfo(member.type);
    out->byte_offset = member.byte_offset;
    out->bit_size = member.bit_size;
    out->comment = dup_string(member.comment);
    if (out->name == nullptr || out->comment == nullptr) {
        std::free(out->name);
        out->name = nullptr;
        delete static_cast<ida::type::TypeInfo*>(out->type);
        out->type = nullptr;
        std::free(out->comment);
        out->comment = nullptr;
        return fail(ida::Error::internal("malloc failed"));
    }
    return 0;
}

void free_type_member_contents(IdaxTypeMember* member) {
    if (member == nullptr) {
        return;
    }
    std::free(member->name);
    member->name = nullptr;
    delete static_cast<ida::type::TypeInfo*>(member->type);
    member->type = nullptr;
    std::free(member->comment);
    member->comment = nullptr;
}

void free_enum_member_contents(IdaxTypeEnumMember* member) {
    if (member == nullptr) {
        return;
    }
    std::free(member->name);
    member->name = nullptr;
    std::free(member->comment);
    member->comment = nullptr;
}

} // anonymous namespace

IdaxTypeHandle idax_type_void(void) {
    return new ida::type::TypeInfo(ida::type::TypeInfo::void_type());
}

IdaxTypeHandle idax_type_int8(void) {
    return new ida::type::TypeInfo(ida::type::TypeInfo::int8());
}

IdaxTypeHandle idax_type_int16(void) {
    return new ida::type::TypeInfo(ida::type::TypeInfo::int16());
}

IdaxTypeHandle idax_type_int32(void) {
    return new ida::type::TypeInfo(ida::type::TypeInfo::int32());
}

IdaxTypeHandle idax_type_int64(void) {
    return new ida::type::TypeInfo(ida::type::TypeInfo::int64());
}

IdaxTypeHandle idax_type_uint8(void) {
    return new ida::type::TypeInfo(ida::type::TypeInfo::uint8());
}

IdaxTypeHandle idax_type_uint16(void) {
    return new ida::type::TypeInfo(ida::type::TypeInfo::uint16());
}

IdaxTypeHandle idax_type_uint32(void) {
    return new ida::type::TypeInfo(ida::type::TypeInfo::uint32());
}

IdaxTypeHandle idax_type_uint64(void) {
    return new ida::type::TypeInfo(ida::type::TypeInfo::uint64());
}

IdaxTypeHandle idax_type_float32(void) {
    return new ida::type::TypeInfo(ida::type::TypeInfo::float32());
}

IdaxTypeHandle idax_type_float64(void) {
    return new ida::type::TypeInfo(ida::type::TypeInfo::float64());
}

IdaxTypeHandle idax_type_pointer_to(IdaxTypeHandle target) {
    auto* ti = static_cast<ida::type::TypeInfo*>(target);
    return new ida::type::TypeInfo(ida::type::TypeInfo::pointer_to(*ti));
}

IdaxTypeHandle idax_type_array_of(IdaxTypeHandle element, size_t count) {
    auto* ti = static_cast<ida::type::TypeInfo*>(element);
    return new ida::type::TypeInfo(ida::type::TypeInfo::array_of(*ti, count));
}

IdaxTypeHandle idax_type_create_struct(void) {
    return new ida::type::TypeInfo(ida::type::TypeInfo::create_struct());
}

IdaxTypeHandle idax_type_create_union(void) {
    return new ida::type::TypeInfo(ida::type::TypeInfo::create_union());
}

void idax_type_free(IdaxTypeHandle ti) {
    delete static_cast<ida::type::TypeInfo*>(ti);
}

int idax_type_clone(IdaxTypeHandle ti, IdaxTypeHandle* out) {
    clear_error();
    if (ti == nullptr || out == nullptr) {
        return fail(ida::Error::validation("Type handle or output pointer is null"));
    }
    *out = new ida::type::TypeInfo(*static_cast<ida::type::TypeInfo*>(ti));
    return 0;
}

int idax_type_function_type(IdaxTypeHandle return_type,
                            const IdaxTypeHandle* argument_types,
                            size_t argument_count,
                            int calling_convention,
                            int has_varargs,
                            IdaxTypeHandle* out) {
    clear_error();
    if (return_type == nullptr || out == nullptr) {
        return fail(ida::Error::validation("Return type or output pointer is null"));
    }
    if (argument_count > 0 && argument_types == nullptr) {
        return fail(ida::Error::validation("argument_types pointer is null"));
    }

    std::vector<ida::type::TypeInfo> args;
    args.reserve(argument_count);
    for (size_t i = 0; i < argument_count; ++i) {
        if (argument_types[i] == nullptr) {
            return fail(ida::Error::validation("Argument type handle is null",
                                               std::to_string(i)));
        }
        args.push_back(*static_cast<ida::type::TypeInfo*>(argument_types[i]));
    }

    auto cc = parse_calling_convention(calling_convention);
    if (!cc) {
        return fail(cc.error());
    }

    auto r = ida::type::TypeInfo::function_type(
        *static_cast<ida::type::TypeInfo*>(return_type),
        args,
        *cc,
        has_varargs != 0);
    if (!r) {
        return fail(r.error());
    }

    *out = new ida::type::TypeInfo(std::move(*r));
    return 0;
}

int idax_type_enum_type(const IdaxTypeEnumMemberInput* members,
                        size_t member_count,
                        size_t byte_width,
                        int bitmask,
                        IdaxTypeHandle* out) {
    clear_error();
    if (out == nullptr) {
        return fail(ida::Error::validation("Output pointer is null"));
    }
    if (member_count > 0 && members == nullptr) {
        return fail(ida::Error::validation("members pointer is null"));
    }

    std::vector<ida::type::EnumMember> in;
    in.reserve(member_count);
    for (size_t i = 0; i < member_count; ++i) {
        ida::type::EnumMember member;
        member.name = members[i].name ? members[i].name : "";
        member.value = members[i].value;
        member.comment = members[i].comment ? members[i].comment : "";
        in.push_back(std::move(member));
    }

    auto r = ida::type::TypeInfo::enum_type(in, byte_width, bitmask != 0);
    if (!r) {
        return fail(r.error());
    }
    *out = new ida::type::TypeInfo(std::move(*r));
    return 0;
}

int idax_type_is_void(IdaxTypeHandle ti) {
    return static_cast<ida::type::TypeInfo*>(ti)->is_void() ? 1 : 0;
}

int idax_type_is_integer(IdaxTypeHandle ti) {
    return static_cast<ida::type::TypeInfo*>(ti)->is_integer() ? 1 : 0;
}

int idax_type_is_floating_point(IdaxTypeHandle ti) {
    return static_cast<ida::type::TypeInfo*>(ti)->is_floating_point() ? 1 : 0;
}

int idax_type_is_pointer(IdaxTypeHandle ti) {
    return static_cast<ida::type::TypeInfo*>(ti)->is_pointer() ? 1 : 0;
}

int idax_type_is_array(IdaxTypeHandle ti) {
    return static_cast<ida::type::TypeInfo*>(ti)->is_array() ? 1 : 0;
}

int idax_type_is_function(IdaxTypeHandle ti) {
    return static_cast<ida::type::TypeInfo*>(ti)->is_function() ? 1 : 0;
}

int idax_type_is_struct(IdaxTypeHandle ti) {
    return static_cast<ida::type::TypeInfo*>(ti)->is_struct() ? 1 : 0;
}

int idax_type_is_union(IdaxTypeHandle ti) {
    return static_cast<ida::type::TypeInfo*>(ti)->is_union() ? 1 : 0;
}

int idax_type_is_enum(IdaxTypeHandle ti) {
    return static_cast<ida::type::TypeInfo*>(ti)->is_enum() ? 1 : 0;
}

int idax_type_is_typedef(IdaxTypeHandle ti) {
    return static_cast<ida::type::TypeInfo*>(ti)->is_typedef() ? 1 : 0;
}

int idax_type_size(IdaxTypeHandle ti, size_t* out) {
    RETURN_RESULT_VALUE(static_cast<ida::type::TypeInfo*>(ti)->size());
}

int idax_type_to_string(IdaxTypeHandle ti, char** out) {
    RETURN_RESULT_STRING(static_cast<ida::type::TypeInfo*>(ti)->to_string());
}

int idax_type_pointee_type(IdaxTypeHandle ti, IdaxTypeHandle* out) {
    clear_error();
    auto r = static_cast<ida::type::TypeInfo*>(ti)->pointee_type();
    if (!r) return fail(r.error());
    *out = new ida::type::TypeInfo(std::move(*r));
    return 0;
}

int idax_type_array_element_type(IdaxTypeHandle ti, IdaxTypeHandle* out) {
    clear_error();
    auto r = static_cast<ida::type::TypeInfo*>(ti)->array_element_type();
    if (!r) return fail(r.error());
    *out = new ida::type::TypeInfo(std::move(*r));
    return 0;
}

int idax_type_array_length(IdaxTypeHandle ti, size_t* out) {
    RETURN_RESULT_VALUE(static_cast<ida::type::TypeInfo*>(ti)->array_length());
}

int idax_type_resolve_typedef(IdaxTypeHandle ti, IdaxTypeHandle* out) {
    clear_error();
    auto r = static_cast<ida::type::TypeInfo*>(ti)->resolve_typedef();
    if (!r) return fail(r.error());
    *out = new ida::type::TypeInfo(std::move(*r));
    return 0;
}

int idax_type_function_return_type(IdaxTypeHandle ti, IdaxTypeHandle* out) {
    clear_error();
    auto r = static_cast<ida::type::TypeInfo*>(ti)->function_return_type();
    if (!r) return fail(r.error());
    *out = new ida::type::TypeInfo(std::move(*r));
    return 0;
}

int idax_type_function_argument_types(IdaxTypeHandle ti,
                                      IdaxTypeHandle** out,
                                      size_t* count) {
    clear_error();
    auto r = static_cast<ida::type::TypeInfo*>(ti)->function_argument_types();
    if (!r) return fail(r.error());
    auto& args = *r;
    *count = args.size();
    if (args.empty()) {
        *out = nullptr;
        return 0;
    }

    auto* handles = static_cast<IdaxTypeHandle*>(std::malloc(args.size() * sizeof(IdaxTypeHandle)));
    if (handles == nullptr) {
        return fail(ida::Error::internal("malloc failed"));
    }
    for (size_t i = 0; i < args.size(); ++i) {
        handles[i] = new ida::type::TypeInfo(args[i]);
    }
    *out = handles;
    return 0;
}

int idax_type_calling_convention(IdaxTypeHandle ti, int* out) {
    clear_error();
    auto r = static_cast<ida::type::TypeInfo*>(ti)->calling_convention();
    if (!r) return fail(r.error());
    *out = calling_convention_to_int(*r);
    return 0;
}

int idax_type_is_variadic_function(IdaxTypeHandle ti, int* out) {
    clear_error();
    auto r = static_cast<ida::type::TypeInfo*>(ti)->is_variadic_function();
    if (!r) return fail(r.error());
    *out = *r ? 1 : 0;
    return 0;
}

int idax_type_enum_members(IdaxTypeHandle ti, IdaxTypeEnumMember** out,
                           size_t* count) {
    clear_error();
    auto r = static_cast<ida::type::TypeInfo*>(ti)->enum_members();
    if (!r) return fail(r.error());
    auto& members = *r;
    *count = members.size();
    if (members.empty()) {
        *out = nullptr;
        return 0;
    }

    auto* raw = static_cast<IdaxTypeEnumMember*>(std::malloc(members.size() * sizeof(IdaxTypeEnumMember)));
    if (raw == nullptr) {
        return fail(ida::Error::internal("malloc failed"));
    }
    for (size_t i = 0; i < members.size(); ++i) {
        raw[i].name = dup_string(members[i].name);
        raw[i].value = members[i].value;
        raw[i].comment = dup_string(members[i].comment);
        if (raw[i].name == nullptr || raw[i].comment == nullptr) {
            for (size_t j = 0; j <= i; ++j) {
                free_enum_member_contents(&raw[j]);
            }
            std::free(raw);
            return fail(ida::Error::internal("malloc failed"));
        }
    }

    *out = raw;
    return 0;
}

int idax_type_by_name(const char* name, IdaxTypeHandle* out) {
    clear_error();
    auto r = ida::type::TypeInfo::by_name(name);
    if (!r) return fail(r.error());
    *out = new ida::type::TypeInfo(std::move(*r));
    return 0;
}

int idax_type_from_declaration(const char* c_decl, IdaxTypeHandle* out) {
    clear_error();
    auto r = ida::type::TypeInfo::from_declaration(c_decl);
    if (!r) return fail(r.error());
    *out = new ida::type::TypeInfo(std::move(*r));
    return 0;
}

int idax_type_apply(IdaxTypeHandle ti, uint64_t ea) {
    RETURN_STATUS(static_cast<ida::type::TypeInfo*>(ti)->apply(ea));
}

int idax_type_save_as(IdaxTypeHandle ti, const char* name) {
    RETURN_STATUS(static_cast<ida::type::TypeInfo*>(ti)->save_as(name));
}

int idax_type_retrieve(uint64_t ea, IdaxTypeHandle* out) {
    clear_error();
    auto r = ida::type::retrieve(ea);
    if (!r) return fail(r.error());
    *out = new ida::type::TypeInfo(std::move(*r));
    return 0;
}

int idax_type_retrieve_operand(uint64_t ea, int operand_index, IdaxTypeHandle* out) {
    clear_error();
    auto r = ida::type::retrieve_operand(ea, operand_index);
    if (!r) return fail(r.error());
    *out = new ida::type::TypeInfo(std::move(*r));
    return 0;
}

int idax_type_remove(uint64_t ea) {
    RETURN_STATUS(ida::type::remove_type(ea));
}

int idax_type_member_count(IdaxTypeHandle ti, size_t* out) {
    RETURN_RESULT_VALUE(static_cast<ida::type::TypeInfo*>(ti)->member_count());
}

int idax_type_members(IdaxTypeHandle ti, IdaxTypeMember** out, size_t* count) {
    clear_error();
    auto r = static_cast<ida::type::TypeInfo*>(ti)->members();
    if (!r) return fail(r.error());
    auto& members = *r;
    *count = members.size();
    if (members.empty()) {
        *out = nullptr;
        return 0;
    }

    auto* raw = static_cast<IdaxTypeMember*>(std::malloc(members.size() * sizeof(IdaxTypeMember)));
    if (raw == nullptr) {
        return fail(ida::Error::internal("malloc failed"));
    }

    for (size_t i = 0; i < members.size(); ++i) {
        raw[i].name = nullptr;
        raw[i].type = nullptr;
        raw[i].comment = nullptr;
        if (fill_type_member(&raw[i], members[i]) != 0) {
            for (size_t j = 0; j <= i; ++j) {
                free_type_member_contents(&raw[j]);
            }
            std::free(raw);
            return -1;
        }
    }

    *out = raw;
    return 0;
}

int idax_type_member_by_name(IdaxTypeHandle ti, const char* name, IdaxTypeMember* out) {
    clear_error();
    auto r = static_cast<ida::type::TypeInfo*>(ti)->member_by_name(name ? name : "");
    if (!r) return fail(r.error());
    out->name = nullptr;
    out->type = nullptr;
    out->comment = nullptr;
    return fill_type_member(out, *r);
}

int idax_type_member_by_offset(IdaxTypeHandle ti, size_t byte_offset, IdaxTypeMember* out) {
    clear_error();
    auto r = static_cast<ida::type::TypeInfo*>(ti)->member_by_offset(byte_offset);
    if (!r) return fail(r.error());
    out->name = nullptr;
    out->type = nullptr;
    out->comment = nullptr;
    return fill_type_member(out, *r);
}

int idax_type_add_member(IdaxTypeHandle ti, const char* name,
                         IdaxTypeHandle member_type, size_t byte_offset) {
    RETURN_STATUS(static_cast<ida::type::TypeInfo*>(ti)->add_member(
        name ? name : "",
        *static_cast<ida::type::TypeInfo*>(member_type),
        byte_offset));
}

int idax_type_load_library(const char* til_name, int* out) {
    clear_error();
    auto r = ida::type::load_type_library(til_name);
    if (!r) return fail(r.error());
    *out = *r ? 1 : 0;
    return 0;
}

int idax_type_unload_library(const char* til_name) {
    RETURN_STATUS(ida::type::unload_type_library(til_name));
}

int idax_type_local_type_count(size_t* out) {
    RETURN_RESULT_VALUE(ida::type::local_type_count());
}

int idax_type_local_type_name(size_t ordinal, char** out) {
    RETURN_RESULT_STRING(ida::type::local_type_name(ordinal));
}

int idax_type_import(const char* source_til_name, const char* type_name, size_t* out) {
    RETURN_RESULT_VALUE(ida::type::import_type(source_til_name ? source_til_name : "",
                                               type_name));
}

int idax_type_apply_named(uint64_t ea, const char* type_name) {
    RETURN_STATUS(ida::type::apply_named_type(ea, type_name));
}

void idax_type_handle_array_free(IdaxTypeHandle* handles, size_t count) {
    if (handles == nullptr) {
        return;
    }
    for (size_t i = 0; i < count; ++i) {
        delete static_cast<ida::type::TypeInfo*>(handles[i]);
    }
    std::free(handles);
}

void idax_type_enum_members_free(IdaxTypeEnumMember* members, size_t count) {
    if (members == nullptr) {
        return;
    }
    for (size_t i = 0; i < count; ++i) {
        free_enum_member_contents(&members[i]);
    }
    std::free(members);
}

void idax_type_member_free(IdaxTypeMember* member) {
    free_type_member_contents(member);
}

void idax_type_members_free(IdaxTypeMember* members, size_t count) {
    if (members == nullptr) {
        return;
    }
    for (size_t i = 0; i < count; ++i) {
        free_type_member_contents(&members[i]);
    }
    std::free(members);
}

// ═══════════════════════════════════════════════════════════════════════════
// Entry
// ═══════════════════════════════════════════════════════════════════════════

void idax_entry_free(IdaxEntryPoint* entry) {
    if (entry) {
        std::free(entry->name);
        std::free(entry->forwarder);
        entry->name = nullptr;
        entry->forwarder = nullptr;
    }
}

namespace {

void fill_entry(IdaxEntryPoint* out, const ida::entry::EntryPoint& ep) {
    out->ordinal   = ep.ordinal;
    out->address   = ep.address;
    out->name      = dup_string(ep.name);
    out->forwarder = dup_string(ep.forwarder);
}

} // anonymous namespace

int idax_entry_count(size_t* out) {
    RETURN_RESULT_VALUE(ida::entry::count());
}

int idax_entry_by_index(size_t index, IdaxEntryPoint* out) {
    clear_error();
    auto r = ida::entry::by_index(index);
    if (!r) return fail(r.error());
    fill_entry(out, *r);
    return 0;
}

int idax_entry_by_ordinal(uint64_t ordinal, IdaxEntryPoint* out) {
    clear_error();
    auto r = ida::entry::by_ordinal(ordinal);
    if (!r) return fail(r.error());
    fill_entry(out, *r);
    return 0;
}

int idax_entry_add(uint64_t ordinal, uint64_t address, const char* name, int make_code) {
    RETURN_STATUS(ida::entry::add(ordinal, address, name, make_code != 0));
}

int idax_entry_rename(uint64_t ordinal, const char* name) {
    RETURN_STATUS(ida::entry::rename(ordinal, name));
}

int idax_entry_forwarder(uint64_t ordinal, char** out) {
    RETURN_RESULT_STRING(ida::entry::forwarder(ordinal));
}

int idax_entry_set_forwarder(uint64_t ordinal, const char* target) {
    RETURN_STATUS(ida::entry::set_forwarder(ordinal, target));
}

int idax_entry_clear_forwarder(uint64_t ordinal) {
    RETURN_STATUS(ida::entry::clear_forwarder(ordinal));
}

// ═══════════════════════════════════════════════════════════════════════════
// Fixup
// ═══════════════════════════════════════════════════════════════════════════

namespace {

void fill_fixup(IdaxFixup* out, const ida::fixup::Descriptor& d) {
    out->source       = d.source;
    out->type         = static_cast<int>(d.type);
    out->flags        = d.flags;
    out->base         = d.base;
    out->target       = d.target;
    out->selector     = d.selector;
    out->offset       = d.offset;
    out->displacement = d.displacement;
}

} // anonymous namespace

int idax_fixup_at(uint64_t source, IdaxFixup* out) {
    clear_error();
    auto r = ida::fixup::at(source);
    if (!r) return fail(r.error());
    fill_fixup(out, *r);
    return 0;
}

int idax_fixup_set(uint64_t source, const IdaxFixup* fixup) {
    ida::fixup::Descriptor d;
    d.source       = fixup->source;
    d.type         = static_cast<ida::fixup::Type>(fixup->type);
    d.flags        = fixup->flags;
    d.base         = fixup->base;
    d.target       = fixup->target;
    d.selector     = fixup->selector;
    d.offset       = fixup->offset;
    d.displacement = fixup->displacement;
    RETURN_STATUS(ida::fixup::set(source, d));
}

int idax_fixup_remove(uint64_t source) {
    RETURN_STATUS(ida::fixup::remove(source));
}

int idax_fixup_exists(uint64_t source) {
    return ida::fixup::exists(source) ? 1 : 0;
}

int idax_fixup_contains(uint64_t start, uint64_t size) {
    return ida::fixup::contains(start, size) ? 1 : 0;
}

int idax_fixup_in_range(uint64_t start, uint64_t end, IdaxFixup** out, size_t* count) {
    clear_error();
    auto r = ida::fixup::in_range(start, end);
    if (!r) return fail(r.error());
    auto& v = *r;
    *count = v.size();
    if (v.empty()) { *out = nullptr; return 0; }
    *out = static_cast<IdaxFixup*>(std::malloc(v.size() * sizeof(IdaxFixup)));
    if (!*out) return fail(ida::Error::internal("malloc failed"));
    for (size_t i = 0; i < v.size(); ++i) {
        fill_fixup(&(*out)[i], v[i]);
    }
    return 0;
}

int idax_fixup_first(uint64_t* out) {
    RETURN_RESULT_VALUE(ida::fixup::first());
}

int idax_fixup_next(uint64_t address, uint64_t* out) {
    RETURN_RESULT_VALUE(ida::fixup::next(address));
}

int idax_fixup_prev(uint64_t address, uint64_t* out) {
    RETURN_RESULT_VALUE(ida::fixup::prev(address));
}

int idax_fixup_register_custom(const IdaxFixupCustomHandler* handler,
                               uint16_t* out) {
    clear_error();
    if (handler == nullptr || out == nullptr) {
        return fail(ida::Error::validation("handler/output pointer is null"));
    }
    ida::fixup::CustomHandler custom;
    custom.name = handler->name == nullptr ? "" : handler->name;
    custom.properties = handler->properties;
    custom.size = handler->size;
    custom.width = handler->width;
    custom.shift = handler->shift;
    custom.reference_type = handler->reference_type;
    auto r = ida::fixup::register_custom(custom);
    if (!r) return fail(r.error());
    *out = *r;
    return 0;
}

int idax_fixup_unregister_custom(uint16_t custom_type) {
    RETURN_STATUS(ida::fixup::unregister_custom(custom_type));
}

int idax_fixup_find_custom(const char* name, uint16_t* out) {
    clear_error();
    auto r = ida::fixup::find_custom(name == nullptr ? "" : name);
    if (!r) return fail(r.error());
    *out = *r;
    return 0;
}

// ═══════════════════════════════════════════════════════════════════════════
// Event
// ═══════════════════════════════════════════════════════════════════════════

namespace {

void fill_event(IdaxEvent* out, const ida::event::Event& in) {
    out->kind = static_cast<int>(in.kind);
    out->address = in.address;
    out->secondary_address = in.secondary_address;
    out->new_name = in.new_name.c_str();
    out->old_name = in.old_name.c_str();
    out->old_value = in.old_value;
    out->repeatable = in.repeatable ? 1 : 0;
}

} // anonymous namespace

int idax_event_subscribe(int event_kind, IdaxEventCallback callback,
                         void* context, uint64_t* token_out) {
    clear_error();
    if (callback == nullptr || token_out == nullptr) {
        return fail(ida::Error::validation("callback/token_out pointer is null"));
    }
    // Route through the generic event API
    auto r = ida::event::on_event(
        [callback, context](const ida::event::Event& ev) {
            uint64_t addr = ev.address;
            uint64_t secondary = ev.secondary_address;
            int kind = static_cast<int>(ev.kind);
            callback(context, kind, addr, secondary);
        });
    if (!r) return fail(r.error());
    *token_out = *r;
    return 0;
}

int idax_event_on_segment_added(IdaxEventSegmentAddedCallback callback,
                                void* context, uint64_t* token_out) {
    clear_error();
    if (callback == nullptr || token_out == nullptr) {
        return fail(ida::Error::validation("callback/token_out pointer is null"));
    }
    auto r = ida::event::on_segment_added(
        [callback, context](ida::Address start) { callback(context, start); });
    if (!r) return fail(r.error());
    *token_out = *r;
    return 0;
}

int idax_event_on_segment_deleted(IdaxEventSegmentDeletedCallback callback,
                                  void* context, uint64_t* token_out) {
    clear_error();
    if (callback == nullptr || token_out == nullptr) {
        return fail(ida::Error::validation("callback/token_out pointer is null"));
    }
    auto r = ida::event::on_segment_deleted(
        [callback, context](ida::Address start, ida::Address end) {
            callback(context, start, end);
        });
    if (!r) return fail(r.error());
    *token_out = *r;
    return 0;
}

int idax_event_on_function_added(IdaxEventFunctionAddedCallback callback,
                                 void* context, uint64_t* token_out) {
    clear_error();
    if (callback == nullptr || token_out == nullptr) {
        return fail(ida::Error::validation("callback/token_out pointer is null"));
    }
    auto r = ida::event::on_function_added(
        [callback, context](ida::Address entry) { callback(context, entry); });
    if (!r) return fail(r.error());
    *token_out = *r;
    return 0;
}

int idax_event_on_function_deleted(IdaxEventFunctionDeletedCallback callback,
                                   void* context, uint64_t* token_out) {
    clear_error();
    if (callback == nullptr || token_out == nullptr) {
        return fail(ida::Error::validation("callback/token_out pointer is null"));
    }
    auto r = ida::event::on_function_deleted(
        [callback, context](ida::Address entry) { callback(context, entry); });
    if (!r) return fail(r.error());
    *token_out = *r;
    return 0;
}

int idax_event_on_renamed(IdaxEventRenamedCallback callback,
                          void* context, uint64_t* token_out) {
    clear_error();
    if (callback == nullptr || token_out == nullptr) {
        return fail(ida::Error::validation("callback/token_out pointer is null"));
    }
    auto r = ida::event::on_renamed(
        [callback, context](ida::Address ea, std::string new_name, std::string old_name) {
            callback(context, ea, new_name.c_str(), old_name.c_str());
        });
    if (!r) return fail(r.error());
    *token_out = *r;
    return 0;
}

int idax_event_on_byte_patched(IdaxEventBytePatchedCallback callback,
                               void* context, uint64_t* token_out) {
    clear_error();
    if (callback == nullptr || token_out == nullptr) {
        return fail(ida::Error::validation("callback/token_out pointer is null"));
    }
    auto r = ida::event::on_byte_patched(
        [callback, context](ida::Address ea, std::uint32_t old_value) {
            callback(context, ea, old_value);
        });
    if (!r) return fail(r.error());
    *token_out = *r;
    return 0;
}

int idax_event_on_comment_changed(IdaxEventCommentChangedCallback callback,
                                  void* context, uint64_t* token_out) {
    clear_error();
    if (callback == nullptr || token_out == nullptr) {
        return fail(ida::Error::validation("callback/token_out pointer is null"));
    }
    auto r = ida::event::on_comment_changed(
        [callback, context](ida::Address ea, bool repeatable) {
            callback(context, ea, repeatable ? 1 : 0);
        });
    if (!r) return fail(r.error());
    *token_out = *r;
    return 0;
}

int idax_event_on_event(IdaxEventExCallback callback,
                        void* context, uint64_t* token_out) {
    clear_error();
    if (callback == nullptr || token_out == nullptr) {
        return fail(ida::Error::validation("callback/token_out pointer is null"));
    }
    auto r = ida::event::on_event(
        [callback, context](const ida::event::Event& ev) {
            IdaxEvent out{};
            fill_event(&out, ev);
            callback(context, &out);
        });
    if (!r) return fail(r.error());
    *token_out = *r;
    return 0;
}

int idax_event_on_event_filtered(IdaxEventFilterCallback filter,
                                 IdaxEventExCallback callback,
                                 void* context,
                                 uint64_t* token_out) {
    clear_error();
    if (filter == nullptr || callback == nullptr || token_out == nullptr) {
        return fail(ida::Error::validation("filter/callback/token_out pointer is null"));
    }
    auto r = ida::event::on_event_filtered(
        [filter, context](const ida::event::Event& ev) -> bool {
            IdaxEvent out{};
            fill_event(&out, ev);
            return filter(context, &out) != 0;
        },
        [callback, context](const ida::event::Event& ev) {
            IdaxEvent out{};
            fill_event(&out, ev);
            callback(context, &out);
        });
    if (!r) return fail(r.error());
    *token_out = *r;
    return 0;
}

int idax_event_unsubscribe(uint64_t token) {
    RETURN_STATUS(ida::event::unsubscribe(token));
}

// ═══════════════════════════════════════════════════════════════════════════
// Plugin
// ═══════════════════════════════════════════════════════════════════════════

namespace {

void fill_plugin_action_context(IdaxPluginActionContext* out,
                                const ida::plugin::ActionContext& in) {
    out->action_id = in.action_id.c_str();
    out->widget_title = in.widget_title.c_str();
    out->widget_type = in.widget_type;
    out->current_address = in.current_address;
    out->current_value = in.current_value;
    out->has_selection = in.has_selection ? 1 : 0;
    out->is_external_address = in.is_external_address ? 1 : 0;
    out->register_name = in.register_name.c_str();
    out->widget_handle = in.widget_handle;
    out->focused_widget_handle = in.focused_widget_handle;
    out->decompiler_view_handle = in.decompiler_view_handle;
}

ida::plugin::ActionContext parse_plugin_action_context(
    const IdaxPluginActionContext* in) {
    ida::plugin::ActionContext out;
    if (in == nullptr) {
        return out;
    }
    out.action_id = in->action_id == nullptr ? "" : in->action_id;
    out.widget_title = in->widget_title == nullptr ? "" : in->widget_title;
    out.widget_type = in->widget_type;
    out.current_address = in->current_address;
    out.current_value = in->current_value;
    out.has_selection = in->has_selection != 0;
    out.is_external_address = in->is_external_address != 0;
    out.register_name = in->register_name == nullptr ? "" : in->register_name;
    out.widget_handle = in->widget_handle;
    out.focused_widget_handle = in->focused_widget_handle;
    out.decompiler_view_handle = in->decompiler_view_handle;
    return out;
}

} // anonymous namespace

int idax_plugin_register_action_ex(const char* id, const char* label,
                                   const char* hotkey, const char* tooltip,
                                   int icon,
                                   IdaxActionHandler handler,
                                   IdaxActionHandlerEx handler_ex,
                                   void* handler_context,
                                   IdaxActionEnabledCheck enabled_check,
                                   IdaxActionEnabledCheckEx enabled_check_ex,
                                   void* enabled_context);

int idax_plugin_register_action(const char* id, const char* label,
                                const char* hotkey, const char* tooltip,
                                int icon,
                                IdaxActionHandler handler,
                                void* handler_context,
                                IdaxActionEnabledCheck enabled_check,
                                void* enabled_context) {
    return idax_plugin_register_action_ex(
        id,
        label,
        hotkey,
        tooltip,
        icon,
        handler,
        nullptr,
        handler_context,
        enabled_check,
        nullptr,
        enabled_context);
}

int idax_plugin_register_action_ex(const char* id, const char* label,
                                   const char* hotkey, const char* tooltip,
                                   int icon,
                                   IdaxActionHandler handler,
                                   IdaxActionHandlerEx handler_ex,
                                   void* handler_context,
                                   IdaxActionEnabledCheck enabled_check,
                                   IdaxActionEnabledCheckEx enabled_check_ex,
                                   void* enabled_context) {
    clear_error();
    if (id == nullptr || label == nullptr) {
        return fail(ida::Error::validation("id/label pointer is null"));
    }
    ida::plugin::Action action;
    action.id      = id;
    action.label   = label;
    action.hotkey  = hotkey ? hotkey : "";
    action.tooltip = tooltip ? tooltip : "";
    action.icon    = icon;
    if (handler_ex != nullptr) {
        auto ctx = handler_context;
        auto cb = handler_ex;
        action.handler_with_context = [cb, ctx](const ida::plugin::ActionContext& action_context)
            -> ida::Status {
            IdaxPluginActionContext ffi_context{};
            fill_plugin_action_context(&ffi_context, action_context);
            cb(ctx, &ffi_context);
            return ida::ok();
        };
    } else if (handler != nullptr) {
        auto ctx = handler_context;
        auto cb  = handler;
        action.handler = [cb, ctx]() -> ida::Status {
            cb(ctx);
            return ida::ok();
        };
    }
    if (enabled_check_ex != nullptr) {
        auto ctx = enabled_context;
        auto cb = enabled_check_ex;
        action.enabled_with_context =
            [cb, ctx](const ida::plugin::ActionContext& action_context) -> bool {
                IdaxPluginActionContext ffi_context{};
                fill_plugin_action_context(&ffi_context, action_context);
                return cb(ctx, &ffi_context) != 0;
            };
    } else if (enabled_check != nullptr) {
        auto ctx = enabled_context;
        auto cb  = enabled_check;
        action.enabled = [cb, ctx]() -> bool {
            return cb(ctx) != 0;
        };
    }
    RETURN_STATUS(ida::plugin::register_action(action));
}

int idax_plugin_unregister_action(const char* action_id) {
    RETURN_STATUS(ida::plugin::unregister_action(action_id));
}

int idax_plugin_attach_to_menu(const char* menu_path, const char* action_id) {
    RETURN_STATUS(ida::plugin::attach_to_menu(menu_path, action_id));
}

int idax_plugin_attach_to_toolbar(const char* toolbar, const char* action_id) {
    RETURN_STATUS(ida::plugin::attach_to_toolbar(toolbar, action_id));
}

int idax_plugin_attach_to_popup(const char* widget_title, const char* action_id) {
    RETURN_STATUS(ida::plugin::attach_to_popup(widget_title, action_id));
}

int idax_plugin_detach_from_menu(const char* menu_path, const char* action_id) {
    RETURN_STATUS(ida::plugin::detach_from_menu(menu_path, action_id));
}

int idax_plugin_detach_from_toolbar(const char* toolbar, const char* action_id) {
    RETURN_STATUS(ida::plugin::detach_from_toolbar(toolbar, action_id));
}

int idax_plugin_detach_from_popup(const char* widget_title, const char* action_id) {
    RETURN_STATUS(ida::plugin::detach_from_popup(widget_title, action_id));
}

int idax_plugin_action_context_widget_host(const IdaxPluginActionContext* action_context,
                                           void** out) {
    clear_error();
    if (action_context == nullptr || out == nullptr) {
        return fail(ida::Error::validation("action_context/output pointer is null"));
    }
    auto context = parse_plugin_action_context(action_context);
    auto r = ida::plugin::widget_host(context);
    if (!r) return fail(r.error());
    *out = *r;
    return 0;
}

int idax_plugin_action_context_with_widget_host(
    const IdaxPluginActionContext* action_context,
    IdaxPluginHostCallback callback,
    void* callback_context) {
    clear_error();
    if (action_context == nullptr || callback == nullptr) {
        return fail(ida::Error::validation("action_context/callback pointer is null"));
    }
    auto context = parse_plugin_action_context(action_context);
    auto status = ida::plugin::with_widget_host(
        context,
        [callback, callback_context](void* host) -> ida::Status {
            if (callback(callback_context, host) == 0) {
                return ida::ok();
            }
            return std::unexpected(ida::Error::sdk("plugin host callback returned failure"));
        });
    if (!status) return fail(status.error());
    return 0;
}

int idax_plugin_action_context_decompiler_view_host(
    const IdaxPluginActionContext* action_context,
    void** out) {
    clear_error();
    if (action_context == nullptr || out == nullptr) {
        return fail(ida::Error::validation("action_context/output pointer is null"));
    }
    auto context = parse_plugin_action_context(action_context);
    auto r = ida::plugin::decompiler_view_host(context);
    if (!r) return fail(r.error());
    *out = *r;
    return 0;
}

int idax_plugin_action_context_with_decompiler_view_host(
    const IdaxPluginActionContext* action_context,
    IdaxPluginHostCallback callback,
    void* callback_context) {
    clear_error();
    if (action_context == nullptr || callback == nullptr) {
        return fail(ida::Error::validation("action_context/callback pointer is null"));
    }
    auto context = parse_plugin_action_context(action_context);
    auto status = ida::plugin::with_decompiler_view_host(
        context,
        [callback, callback_context](void* host) -> ida::Status {
            if (callback(callback_context, host) == 0) {
                return ida::ok();
            }
            return std::unexpected(ida::Error::sdk("plugin host callback returned failure"));
        });
    if (!status) return fail(status.error());
    return 0;
}

// ═══════════════════════════════════════════════════════════════════════════
// Loader
// ═══════════════════════════════════════════════════════════════════════════

int idax_loader_decode_load_flags(uint16_t raw_flags, IdaxLoaderLoadFlags* out) {
    clear_error();
    if (out == nullptr) {
        return fail(ida::Error::validation("out pointer is null"));
    }
    auto flags = ida::loader::decode_load_flags(raw_flags);
    fill_loader_flags(out, flags);
    return 0;
}

int idax_loader_encode_load_flags(const IdaxLoaderLoadFlags* flags, uint16_t* out_raw_flags) {
    clear_error();
    if (flags == nullptr || out_raw_flags == nullptr) {
        return fail(ida::Error::validation("flags/out pointer is null"));
    }
    auto parsed = parse_loader_flags(*flags);
    *out_raw_flags = ida::loader::encode_load_flags(parsed);
    return 0;
}

int idax_loader_file_to_database(void* li_handle, int64_t file_offset,
                                 uint64_t ea, uint64_t size, int patchable) {
    RETURN_STATUS(ida::loader::file_to_database(
        li_handle, file_offset, ea, size, patchable != 0));
}

int idax_loader_memory_to_database(const uint8_t* data, uint64_t ea, uint64_t size) {
    RETURN_STATUS(ida::loader::memory_to_database(data, ea, size));
}

void idax_loader_abort_load(const char* message) {
    ida::loader::abort_load(message == nullptr ? "" : message);
}

int idax_loader_input_size(void* li_handle, int64_t* out) {
    clear_error();
    if (out == nullptr) {
        return fail(ida::Error::validation("out pointer is null"));
    }
    auto input = wrap_loader_input(li_handle);
    if (!input) return fail(input.error());
    auto r = input->size();
    if (!r) return fail(r.error());
    *out = *r;
    return 0;
}

int idax_loader_input_tell(void* li_handle, int64_t* out) {
    clear_error();
    if (out == nullptr) {
        return fail(ida::Error::validation("out pointer is null"));
    }
    auto input = wrap_loader_input(li_handle);
    if (!input) return fail(input.error());
    auto r = input->tell();
    if (!r) return fail(r.error());
    *out = *r;
    return 0;
}

int idax_loader_input_seek(void* li_handle, int64_t offset, int64_t* out) {
    clear_error();
    if (out == nullptr) {
        return fail(ida::Error::validation("out pointer is null"));
    }
    auto input = wrap_loader_input(li_handle);
    if (!input) return fail(input.error());
    auto r = input->seek(offset);
    if (!r) return fail(r.error());
    *out = *r;
    return 0;
}

int idax_loader_input_read_bytes(void* li_handle, size_t count,
                                 uint8_t** out, size_t* out_len) {
    clear_error();
    if (out == nullptr || out_len == nullptr) {
        return fail(ida::Error::validation("out/out_len pointer is null"));
    }
    *out = nullptr;
    *out_len = 0;
    auto input = wrap_loader_input(li_handle);
    if (!input) return fail(input.error());

    auto r = input->read_bytes(count);
    if (!r) return fail(r.error());
    const auto& bytes = *r;
    if (bytes.empty()) {
        return 0;
    }

    auto* buf = static_cast<uint8_t*>(std::malloc(bytes.size()));
    if (buf == nullptr) {
        return fail(ida::Error::internal("malloc failed"));
    }
    std::memcpy(buf, bytes.data(), bytes.size());

    *out = buf;
    *out_len = bytes.size();
    return 0;
}

int idax_loader_input_read_bytes_at(void* li_handle, int64_t offset, size_t count,
                                    uint8_t** out, size_t* out_len) {
    clear_error();
    if (out == nullptr || out_len == nullptr) {
        return fail(ida::Error::validation("out/out_len pointer is null"));
    }
    int64_t ignored = 0;
    int seek_ret = idax_loader_input_seek(li_handle, offset, &ignored);
    if (seek_ret != 0) {
        return seek_ret;
    }
    return idax_loader_input_read_bytes(li_handle, count, out, out_len);
}

int idax_loader_input_read_string(void* li_handle, int64_t offset, size_t max_len,
                                  char** out) {
    clear_error();
    if (out == nullptr) {
        return fail(ida::Error::validation("out pointer is null"));
    }
    auto input = wrap_loader_input(li_handle);
    if (!input) return fail(input.error());

    auto r = input->read_string(offset, max_len);
    if (!r) return fail(r.error());

    *out = dup_string(*r);
    if (*out == nullptr && !r->empty()) {
        return fail(ida::Error::internal("malloc failed"));
    }
    return 0;
}

int idax_loader_input_filename(void* li_handle, char** out) {
    clear_error();
    if (out == nullptr) {
        return fail(ida::Error::validation("out pointer is null"));
    }
    auto input = wrap_loader_input(li_handle);
    if (!input) return fail(input.error());
    auto r = input->filename();
    if (!r) return fail(r.error());
    *out = dup_string(*r);
    if (*out == nullptr && !r->empty()) {
        return fail(ida::Error::internal("malloc failed"));
    }
    return 0;
}

int idax_loader_set_processor(const char* processor_name) {
    RETURN_STATUS(ida::loader::set_processor(processor_name));
}

int idax_loader_create_filename_comment(void) {
    RETURN_STATUS(ida::loader::create_filename_comment());
}

// ═══════════════════════════════════════════════════════════════════════════
// Debugger
// ═══════════════════════════════════════════════════════════════════════════

namespace {

void fill_debugger_backend_info(IdaxBackendInfo* out, const ida::debugger::BackendInfo& in) {
    out->name = dup_string(in.name);
    out->display_name = dup_string(in.display_name);
    out->remote = in.remote ? 1 : 0;
    out->supports_appcall = in.supports_appcall ? 1 : 0;
    out->supports_attach = in.supports_attach ? 1 : 0;
    out->loaded = in.loaded ? 1 : 0;
}

void fill_debugger_thread_info(IdaxThreadInfo* out, const ida::debugger::ThreadInfo& in) {
    out->id = in.id;
    out->name = dup_string(in.name);
    out->is_current = in.is_current ? 1 : 0;
}

void fill_debugger_register_info(IdaxDebuggerRegisterInfo* out,
                                 const ida::debugger::RegisterInfo& in) {
    out->name = dup_string(in.name);
    out->read_only = in.read_only ? 1 : 0;
    out->instruction_pointer = in.instruction_pointer ? 1 : 0;
    out->stack_pointer = in.stack_pointer ? 1 : 0;
    out->frame_pointer = in.frame_pointer ? 1 : 0;
    out->may_contain_address = in.may_contain_address ? 1 : 0;
    out->custom_format = in.custom_format ? 1 : 0;
}

int appcall_kind_to_c(ida::debugger::AppcallValueKind kind) {
    using K = ida::debugger::AppcallValueKind;
    switch (kind) {
        case K::SignedInteger: return IDAX_DEBUGGER_APPCALL_SIGNED_INTEGER;
        case K::UnsignedInteger: return IDAX_DEBUGGER_APPCALL_UNSIGNED_INTEGER;
        case K::FloatingPoint: return IDAX_DEBUGGER_APPCALL_FLOATING_POINT;
        case K::String: return IDAX_DEBUGGER_APPCALL_STRING;
        case K::Address: return IDAX_DEBUGGER_APPCALL_ADDRESS;
        case K::Boolean: return IDAX_DEBUGGER_APPCALL_BOOLEAN;
    }
    return IDAX_DEBUGGER_APPCALL_SIGNED_INTEGER;
}

ida::Result<ida::debugger::AppcallValueKind> appcall_kind_from_c(int kind) {
    using K = ida::debugger::AppcallValueKind;
    switch (kind) {
        case IDAX_DEBUGGER_APPCALL_SIGNED_INTEGER: return K::SignedInteger;
        case IDAX_DEBUGGER_APPCALL_UNSIGNED_INTEGER: return K::UnsignedInteger;
        case IDAX_DEBUGGER_APPCALL_FLOATING_POINT: return K::FloatingPoint;
        case IDAX_DEBUGGER_APPCALL_STRING: return K::String;
        case IDAX_DEBUGGER_APPCALL_ADDRESS: return K::Address;
        case IDAX_DEBUGGER_APPCALL_BOOLEAN: return K::Boolean;
        default:
            return std::unexpected(ida::Error::validation(
                "Invalid appcall value kind",
                std::to_string(kind)));
    }
}

int fill_appcall_value_out(IdaxDebuggerAppcallValue* out,
                           const ida::debugger::AppcallValue& in) {
    out->kind = appcall_kind_to_c(in.kind);
    out->signed_value = static_cast<int64_t>(in.signed_value);
    out->unsigned_value = static_cast<uint64_t>(in.unsigned_value);
    out->floating_value = in.floating_value;
    out->string_value = nullptr;
    out->address_value = static_cast<uint64_t>(in.address_value);
    out->boolean_value = in.boolean_value ? 1 : 0;
    if (in.kind == ida::debugger::AppcallValueKind::String) {
        out->string_value = dup_string(in.string_value);
        if (out->string_value == nullptr && !in.string_value.empty()) {
            return fail(ida::Error::internal("malloc failed"));
        }
    }
    return 0;
}

ida::Result<ida::debugger::AppcallValue> appcall_value_from_c(
    const IdaxDebuggerAppcallValue& in) {
    ida::debugger::AppcallValue out;
    auto kind = appcall_kind_from_c(in.kind);
    if (!kind) {
        return std::unexpected(kind.error());
    }
    out.kind = *kind;
    out.signed_value = static_cast<std::int64_t>(in.signed_value);
    out.unsigned_value = static_cast<std::uint64_t>(in.unsigned_value);
    out.floating_value = in.floating_value;
    out.string_value = in.string_value != nullptr ? in.string_value : "";
    out.address_value = static_cast<ida::Address>(in.address_value);
    out.boolean_value = in.boolean_value != 0;
    return out;
}

ida::Result<ida::debugger::AppcallOptions> appcall_options_from_c(
    const IdaxDebuggerAppcallOptions& in) {
    ida::debugger::AppcallOptions out;
    if (in.has_thread_id != 0) {
        out.thread_id = in.thread_id;
    }
    out.manual = in.manual != 0;
    out.include_debug_event = in.include_debug_event != 0;
    if (in.has_timeout_milliseconds != 0) {
        out.timeout_milliseconds = in.timeout_milliseconds;
    }
    return out;
}

void fill_appcall_options_out(IdaxDebuggerAppcallOptions* out,
                              const ida::debugger::AppcallOptions& in) {
    out->has_thread_id = in.thread_id ? 1 : 0;
    out->thread_id = in.thread_id.value_or(0);
    out->manual = in.manual ? 1 : 0;
    out->include_debug_event = in.include_debug_event ? 1 : 0;
    out->has_timeout_milliseconds = in.timeout_milliseconds ? 1 : 0;
    out->timeout_milliseconds = in.timeout_milliseconds.value_or(0);
}

ida::Result<ida::debugger::AppcallRequest> appcall_request_from_c(
    const IdaxDebuggerAppcallRequest* request) {
    if (request == nullptr) {
        return std::unexpected(ida::Error::validation("request pointer is null"));
    }
    if (request->function_type == nullptr) {
        return std::unexpected(ida::Error::validation("request.function_type is null"));
    }

    auto* ti = static_cast<ida::type::TypeInfo*>(request->function_type);

    ida::debugger::AppcallRequest out;
    out.function_address = request->function_address;
    out.function_type = *ti;

    if (request->argument_count > 0 && request->arguments == nullptr) {
        return std::unexpected(ida::Error::validation(
            "request.arguments is null but argument_count is non-zero"));
    }

    auto opts = appcall_options_from_c(request->options);
    if (!opts) {
        return std::unexpected(opts.error());
    }
    out.options = *opts;

    out.arguments.reserve(request->argument_count);
    for (size_t i = 0; i < request->argument_count; ++i) {
        auto arg = appcall_value_from_c(request->arguments[i]);
        if (!arg) {
            auto err = arg.error();
            err.context = "argument_index=" + std::to_string(i);
            return std::unexpected(err);
        }
        out.arguments.push_back(std::move(*arg));
    }

    return out;
}

int fill_appcall_result_out(IdaxDebuggerAppcallResult* out,
                            const ida::debugger::AppcallResult& in) {
    if (out == nullptr) {
        return fail(ida::Error::validation("out pointer is null"));
    }
    std::memset(out, 0, sizeof(*out));
    int rc = fill_appcall_value_out(&out->return_value, in.return_value);
    if (rc != 0) {
        return rc;
    }
    out->diagnostics = dup_string(in.diagnostics);
    if (out->diagnostics == nullptr && !in.diagnostics.empty()) {
        idax_debugger_appcall_value_free(&out->return_value);
        return fail(ida::Error::internal("malloc failed"));
    }
    return 0;
}

int breakpoint_change_to_c(ida::debugger::BreakpointChange in) {
    switch (in) {
        case ida::debugger::BreakpointChange::Added:
            return IDAX_DEBUGGER_BREAKPOINT_ADDED;
        case ida::debugger::BreakpointChange::Removed:
            return IDAX_DEBUGGER_BREAKPOINT_REMOVED;
        case ida::debugger::BreakpointChange::Changed:
            return IDAX_DEBUGGER_BREAKPOINT_CHANGED;
    }
    return IDAX_DEBUGGER_BREAKPOINT_CHANGED;
}

class CAppcallExecutor : public ida::debugger::AppcallExecutor {
public:
    CAppcallExecutor(IdaxDebuggerAppcallExecutorCallback callback,
                     IdaxDebuggerAppcallExecutorCleanupCallback cleanup,
                     void* context)
        : callback_(callback), cleanup_(cleanup), context_(context) {}

    ~CAppcallExecutor() override {
        if (cleanup_ != nullptr) {
            cleanup_(context_);
        }
    }

    ida::Result<ida::debugger::AppcallResult> execute(
        const ida::debugger::AppcallRequest& request) override {
        if (callback_ == nullptr) {
            return std::unexpected(ida::Error::validation("executor callback is null"));
        }

        ida::type::TypeInfo function_type_copy = request.function_type;

        IdaxDebuggerAppcallRequest raw_req{};
        raw_req.function_address = request.function_address;
        raw_req.function_type = &function_type_copy;
        fill_appcall_options_out(&raw_req.options, request.options);

        std::vector<IdaxDebuggerAppcallValue> args(request.arguments.size());
        for (size_t i = 0; i < request.arguments.size(); ++i) {
            args[i].kind = appcall_kind_to_c(request.arguments[i].kind);
            args[i].signed_value = request.arguments[i].signed_value;
            args[i].unsigned_value = request.arguments[i].unsigned_value;
            args[i].floating_value = request.arguments[i].floating_value;
            args[i].string_value = const_cast<char*>(request.arguments[i].string_value.c_str());
            args[i].address_value = request.arguments[i].address_value;
            args[i].boolean_value = request.arguments[i].boolean_value ? 1 : 0;
        }

        raw_req.arguments = args.empty() ? nullptr : args.data();
        raw_req.argument_count = args.size();

        IdaxDebuggerAppcallResult raw_result{};
        std::memset(&raw_result, 0, sizeof(raw_result));

        int cb_rc = callback_(context_, &raw_req, &raw_result);
        if (cb_rc != 0) {
            idax_debugger_appcall_result_free(&raw_result);
            return std::unexpected(ida::Error::sdk("appcall executor callback failed"));
        }

        ida::debugger::AppcallResult out;
        auto value = appcall_value_from_c(raw_result.return_value);
        if (!value) {
            idax_debugger_appcall_result_free(&raw_result);
            return std::unexpected(value.error());
        }
        out.return_value = std::move(*value);
        out.diagnostics = raw_result.diagnostics != nullptr ? raw_result.diagnostics : "";
        idax_debugger_appcall_result_free(&raw_result);
        return out;
    }

private:
    IdaxDebuggerAppcallExecutorCallback callback_{nullptr};
    IdaxDebuggerAppcallExecutorCleanupCallback cleanup_{nullptr};
    void* context_{nullptr};
};

} // anonymous namespace

void idax_thread_info_free(IdaxThreadInfo* info) {
    if (info) {
        std::free(info->name);
        info->name = nullptr;
    }
}

void idax_backend_info_free(IdaxBackendInfo* info) {
    if (info) {
        std::free(info->name);
        std::free(info->display_name);
        info->name = nullptr;
        info->display_name = nullptr;
    }
}

void idax_debugger_register_info_free(IdaxDebuggerRegisterInfo* info) {
    if (info) {
        std::free(info->name);
        info->name = nullptr;
    }
}

void idax_debugger_appcall_value_free(IdaxDebuggerAppcallValue* value) {
    if (value) {
        std::free(value->string_value);
        value->string_value = nullptr;
    }
}

void idax_debugger_appcall_result_free(IdaxDebuggerAppcallResult* result) {
    if (result) {
        idax_debugger_appcall_value_free(&result->return_value);
        std::free(result->diagnostics);
        result->diagnostics = nullptr;
    }
}

int idax_debugger_available_backends(IdaxBackendInfo** out, size_t* count) {
    clear_error();
    auto r = ida::debugger::available_backends();
    if (!r) return fail(r.error());
    auto& v = *r;
    *count = v.size();
    if (v.empty()) { *out = nullptr; return 0; }
    *out = static_cast<IdaxBackendInfo*>(std::calloc(v.size(), sizeof(IdaxBackendInfo)));
    if (!*out) return fail(ida::Error::internal("malloc failed"));
    for (size_t i = 0; i < v.size(); ++i) {
        fill_debugger_backend_info(&(*out)[i], v[i]);
    }
    return 0;
}

int idax_debugger_current_backend(IdaxBackendInfo* out) {
    clear_error();
    auto r = ida::debugger::current_backend();
    if (!r) return fail(r.error());
    fill_debugger_backend_info(out, *r);
    return 0;
}

int idax_debugger_load_backend(const char* name, int use_remote) {
    RETURN_STATUS(ida::debugger::load_backend(name, use_remote != 0));
}

int idax_debugger_start(const char* path, const char* args,
                        const char* working_dir) {
    RETURN_STATUS(ida::debugger::start(
        path ? path : "",
        args ? args : "",
        working_dir ? working_dir : ""));
}

int idax_debugger_attach(int pid) {
    RETURN_STATUS(ida::debugger::attach(pid));
}

int idax_debugger_request_start(const char* path, const char* args,
                                const char* working_dir) {
    RETURN_STATUS(ida::debugger::request_start(
        path ? path : "",
        args ? args : "",
        working_dir ? working_dir : ""));
}

int idax_debugger_request_attach(int pid, int event_id) {
    RETURN_STATUS(ida::debugger::request_attach(pid, event_id));
}

int idax_debugger_detach(void) {
    RETURN_STATUS(ida::debugger::detach());
}

int idax_debugger_terminate(void) {
    RETURN_STATUS(ida::debugger::terminate());
}

int idax_debugger_suspend(void) {
    RETURN_STATUS(ida::debugger::suspend());
}

int idax_debugger_resume(void) {
    RETURN_STATUS(ida::debugger::resume());
}

int idax_debugger_step_into(void) {
    RETURN_STATUS(ida::debugger::step_into());
}

int idax_debugger_step_over(void) {
    RETURN_STATUS(ida::debugger::step_over());
}

int idax_debugger_step_out(void) {
    RETURN_STATUS(ida::debugger::step_out());
}

int idax_debugger_run_to(uint64_t address) {
    RETURN_STATUS(ida::debugger::run_to(address));
}

int idax_debugger_state(int* out) {
    clear_error();
    auto r = ida::debugger::state();
    if (!r) return fail(r.error());
    *out = static_cast<int>(*r);
    return 0;
}

int idax_debugger_instruction_pointer(uint64_t* out) {
    RETURN_RESULT_VALUE(ida::debugger::instruction_pointer());
}

int idax_debugger_stack_pointer(uint64_t* out) {
    RETURN_RESULT_VALUE(ida::debugger::stack_pointer());
}

int idax_debugger_register_value(const char* reg_name, uint64_t* out) {
    RETURN_RESULT_VALUE(ida::debugger::register_value(reg_name));
}

int idax_debugger_set_register(const char* reg_name, uint64_t value) {
    RETURN_STATUS(ida::debugger::set_register(reg_name, value));
}

int idax_debugger_add_breakpoint(uint64_t address) {
    RETURN_STATUS(ida::debugger::add_breakpoint(address));
}

int idax_debugger_remove_breakpoint(uint64_t address) {
    RETURN_STATUS(ida::debugger::remove_breakpoint(address));
}

int idax_debugger_has_breakpoint(uint64_t address, int* out) {
    clear_error();
    auto r = ida::debugger::has_breakpoint(address);
    if (!r) return fail(r.error());
    *out = *r ? 1 : 0;
    return 0;
}

int idax_debugger_read_memory(uint64_t address, uint64_t size,
                              uint8_t** out, size_t* out_len) {
    clear_error();
    auto r = ida::debugger::read_memory(address, size);
    if (!r) return fail(r.error());
    auto& v = *r;
    *out_len = v.size();
    if (v.empty()) { *out = nullptr; return 0; }
    *out = static_cast<uint8_t*>(std::malloc(v.size()));
    if (!*out) return fail(ida::Error::internal("malloc failed"));
    std::memcpy(*out, v.data(), v.size());
    return 0;
}

int idax_debugger_write_memory(uint64_t address, const uint8_t* data,
                               size_t len) {
    RETURN_STATUS(ida::debugger::write_memory(address, std::span<const uint8_t>(data, len)));
}

int idax_debugger_is_request_running(void) {
    return ida::debugger::is_request_running() ? 1 : 0;
}

int idax_debugger_run_requests(void) {
    RETURN_STATUS(ida::debugger::run_requests());
}

int idax_debugger_request_suspend(void) {
    RETURN_STATUS(ida::debugger::request_suspend());
}

int idax_debugger_request_resume(void) {
    RETURN_STATUS(ida::debugger::request_resume());
}

int idax_debugger_request_step_into(void) {
    RETURN_STATUS(ida::debugger::request_step_into());
}

int idax_debugger_request_step_over(void) {
    RETURN_STATUS(ida::debugger::request_step_over());
}

int idax_debugger_request_step_out(void) {
    RETURN_STATUS(ida::debugger::request_step_out());
}

int idax_debugger_request_run_to(uint64_t address) {
    RETURN_STATUS(ida::debugger::request_run_to(address));
}

int idax_debugger_thread_count(size_t* out) {
    RETURN_RESULT_VALUE(ida::debugger::thread_count());
}

int idax_debugger_thread_id_at(size_t index, int* out) {
    RETURN_RESULT_VALUE(ida::debugger::thread_id_at(index));
}

int idax_debugger_thread_name_at(size_t index, char** out) {
    RETURN_RESULT_STRING(ida::debugger::thread_name_at(index));
}

int idax_debugger_current_thread_id(int* out) {
    RETURN_RESULT_VALUE(ida::debugger::current_thread_id());
}

int idax_debugger_select_thread(int thread_id) {
    RETURN_STATUS(ida::debugger::select_thread(thread_id));
}

int idax_debugger_threads(IdaxThreadInfo** out, size_t* count) {
    clear_error();
    auto r = ida::debugger::threads();
    if (!r) return fail(r.error());
    auto& v = *r;
    *count = v.size();
    if (v.empty()) { *out = nullptr; return 0; }
    *out = static_cast<IdaxThreadInfo*>(std::calloc(v.size(), sizeof(IdaxThreadInfo)));
    if (!*out) return fail(ida::Error::internal("malloc failed"));
    for (size_t i = 0; i < v.size(); ++i) {
        fill_debugger_thread_info(&(*out)[i], v[i]);
    }
    return 0;
}

int idax_debugger_request_select_thread(int thread_id) {
    RETURN_STATUS(ida::debugger::request_select_thread(thread_id));
}

int idax_debugger_suspend_thread(int thread_id) {
    RETURN_STATUS(ida::debugger::suspend_thread(thread_id));
}

int idax_debugger_request_suspend_thread(int thread_id) {
    RETURN_STATUS(ida::debugger::request_suspend_thread(thread_id));
}

int idax_debugger_resume_thread(int thread_id) {
    RETURN_STATUS(ida::debugger::resume_thread(thread_id));
}

int idax_debugger_request_resume_thread(int thread_id) {
    RETURN_STATUS(ida::debugger::request_resume_thread(thread_id));
}

int idax_debugger_register_info(const char* register_name,
                                IdaxDebuggerRegisterInfo* out) {
    clear_error();
    auto r = ida::debugger::register_info(register_name == nullptr ? "" : register_name);
    if (!r) return fail(r.error());
    fill_debugger_register_info(out, *r);
    return 0;
}

int idax_debugger_is_integer_register(const char* register_name, int* out) {
    clear_error();
    auto r = ida::debugger::is_integer_register(register_name == nullptr ? "" : register_name);
    if (!r) return fail(r.error());
    *out = *r ? 1 : 0;
    return 0;
}

int idax_debugger_is_floating_register(const char* register_name, int* out) {
    clear_error();
    auto r = ida::debugger::is_floating_register(register_name == nullptr ? "" : register_name);
    if (!r) return fail(r.error());
    *out = *r ? 1 : 0;
    return 0;
}

int idax_debugger_is_custom_register(const char* register_name, int* out) {
    clear_error();
    auto r = ida::debugger::is_custom_register(register_name == nullptr ? "" : register_name);
    if (!r) return fail(r.error());
    *out = *r ? 1 : 0;
    return 0;
}

int idax_debugger_appcall(const IdaxDebuggerAppcallRequest* request,
                          IdaxDebuggerAppcallResult* out) {
    clear_error();
    auto cpp_req = appcall_request_from_c(request);
    if (!cpp_req) return fail(cpp_req.error());
    auto r = ida::debugger::appcall(*cpp_req);
    if (!r) return fail(r.error());
    return fill_appcall_result_out(out, *r);
}

int idax_debugger_cleanup_appcall(int has_thread_id, int thread_id) {
    if (has_thread_id != 0) {
        RETURN_STATUS(ida::debugger::cleanup_appcall(thread_id));
    }
    RETURN_STATUS(ida::debugger::cleanup_appcall(std::nullopt));
}

int idax_debugger_register_executor(
    const char* name,
    IdaxDebuggerAppcallExecutorCallback callback,
    IdaxDebuggerAppcallExecutorCleanupCallback cleanup,
    void* context) {
    auto executor = std::make_shared<CAppcallExecutor>(callback, cleanup, context);
    RETURN_STATUS(ida::debugger::register_executor(name, executor));
}

int idax_debugger_unregister_executor(const char* name) {
    RETURN_STATUS(ida::debugger::unregister_executor(name));
}

int idax_debugger_appcall_with_executor(
    const char* name,
    const IdaxDebuggerAppcallRequest* request,
    IdaxDebuggerAppcallResult* out) {
    clear_error();
    auto cpp_req = appcall_request_from_c(request);
    if (!cpp_req) return fail(cpp_req.error());
    auto r = ida::debugger::appcall_with_executor(name, *cpp_req);
    if (!r) return fail(r.error());
    return fill_appcall_result_out(out, *r);
}

int idax_debugger_on_process_started(IdaxDebuggerProcessStartedCallback callback,
                                     void* context,
                                     uint64_t* token_out) {
    clear_error();
    auto r = ida::debugger::on_process_started([callback, context](
        const ida::debugger::ModuleInfo& module_info) {
        if (callback != nullptr) {
            IdaxDebuggerModuleInfo raw{};
            raw.name = module_info.name.c_str();
            raw.base = module_info.base;
            raw.size = module_info.size;
            callback(context, &raw);
        }
    });
    if (!r) return fail(r.error());
    *token_out = *r;
    return 0;
}

int idax_debugger_on_process_exited(IdaxDebuggerProcessExitedCallback callback,
                                    void* context,
                                    uint64_t* token_out) {
    clear_error();
    auto r = ida::debugger::on_process_exited([callback, context](int exit_code) {
        if (callback != nullptr) {
            callback(context, exit_code);
        }
    });
    if (!r) return fail(r.error());
    *token_out = *r;
    return 0;
}

int idax_debugger_on_process_suspended(
    IdaxDebuggerProcessSuspendedCallback callback,
    void* context,
    uint64_t* token_out) {
    clear_error();
    auto r = ida::debugger::on_process_suspended([callback, context](uint64_t address) {
        if (callback != nullptr) {
            callback(context, address);
        }
    });
    if (!r) return fail(r.error());
    *token_out = *r;
    return 0;
}

int idax_debugger_on_breakpoint_hit(IdaxDebuggerBreakpointHitCallback callback,
                                    void* context,
                                    uint64_t* token_out) {
    clear_error();
    auto r = ida::debugger::on_breakpoint_hit([callback, context](int thread_id, uint64_t address) {
        if (callback != nullptr) {
            callback(context, thread_id, address);
        }
    });
    if (!r) return fail(r.error());
    *token_out = *r;
    return 0;
}

int idax_debugger_on_trace(IdaxDebuggerTraceCallback callback,
                           void* context,
                           uint64_t* token_out) {
    clear_error();
    auto r = ida::debugger::on_trace([callback, context](int thread_id, uint64_t ip) {
        if (callback == nullptr) {
            return false;
        }
        return callback(context, thread_id, ip) != 0;
    });
    if (!r) return fail(r.error());
    *token_out = *r;
    return 0;
}

int idax_debugger_on_exception(IdaxDebuggerExceptionCallback callback,
                               void* context,
                               uint64_t* token_out) {
    clear_error();
    auto r = ida::debugger::on_exception([callback, context](
        const ida::debugger::ExceptionInfo& exception_info) {
        if (callback != nullptr) {
            IdaxDebuggerExceptionInfo raw{};
            raw.ea = exception_info.ea;
            raw.code = exception_info.code;
            raw.can_continue = exception_info.can_continue ? 1 : 0;
            raw.message = exception_info.message.c_str();
            callback(context, &raw);
        }
    });
    if (!r) return fail(r.error());
    *token_out = *r;
    return 0;
}

int idax_debugger_on_thread_started(IdaxDebuggerThreadStartedCallback callback,
                                    void* context,
                                    uint64_t* token_out) {
    clear_error();
    auto r = ida::debugger::on_thread_started([callback, context](int thread_id, std::string name) {
        if (callback != nullptr) {
            callback(context, thread_id, name.c_str());
        }
    });
    if (!r) return fail(r.error());
    *token_out = *r;
    return 0;
}

int idax_debugger_on_thread_exited(IdaxDebuggerThreadExitedCallback callback,
                                   void* context,
                                   uint64_t* token_out) {
    clear_error();
    auto r = ida::debugger::on_thread_exited([callback, context](int thread_id, int exit_code) {
        if (callback != nullptr) {
            callback(context, thread_id, exit_code);
        }
    });
    if (!r) return fail(r.error());
    *token_out = *r;
    return 0;
}

int idax_debugger_on_library_loaded(IdaxDebuggerLibraryLoadedCallback callback,
                                    void* context,
                                    uint64_t* token_out) {
    clear_error();
    auto r = ida::debugger::on_library_loaded([callback, context](
        const ida::debugger::ModuleInfo& module_info) {
        if (callback != nullptr) {
            IdaxDebuggerModuleInfo raw{};
            raw.name = module_info.name.c_str();
            raw.base = module_info.base;
            raw.size = module_info.size;
            callback(context, &raw);
        }
    });
    if (!r) return fail(r.error());
    *token_out = *r;
    return 0;
}

int idax_debugger_on_library_unloaded(IdaxDebuggerLibraryUnloadedCallback callback,
                                      void* context,
                                      uint64_t* token_out) {
    clear_error();
    auto r = ida::debugger::on_library_unloaded([callback, context](std::string name) {
        if (callback != nullptr) {
            callback(context, name.c_str());
        }
    });
    if (!r) return fail(r.error());
    *token_out = *r;
    return 0;
}

int idax_debugger_on_breakpoint_changed(
    IdaxDebuggerBreakpointChangedCallback callback,
    void* context,
    uint64_t* token_out) {
    clear_error();
    auto r = ida::debugger::on_breakpoint_changed([callback, context](
        ida::debugger::BreakpointChange change,
        uint64_t address) {
        if (callback != nullptr) {
            callback(context, breakpoint_change_to_c(change), address);
        }
    });
    if (!r) return fail(r.error());
    *token_out = *r;
    return 0;
}

int idax_debugger_unsubscribe(uint64_t token) {
    RETURN_STATUS(ida::debugger::unsubscribe(token));
}

// ═══════════════════════════════════════════════════════════════════════════
// Decompiler
// ═══════════════════════════════════════════════════════════════════════════

namespace {

ida::decompiler::VisitAction visit_action_from_c_int(int value) {
    switch (value) {
        case 1:
            return ida::decompiler::VisitAction::Stop;
        case 2:
            return ida::decompiler::VisitAction::SkipChildren;
        default:
            return ida::decompiler::VisitAction::Continue;
    }
}

int copy_lines_to_c_array(const std::vector<std::string>& lines, char*** out, size_t* count) {
    *count = lines.size();
    if (lines.empty()) {
        *out = nullptr;
        return 0;
    }

    *out = static_cast<char**>(std::malloc(lines.size() * sizeof(char*)));
    if (*out == nullptr) {
        return fail(ida::Error::internal("malloc failed"));
    }

    for (size_t i = 0; i < lines.size(); ++i) {
        (*out)[i] = dup_string(lines[i]);
        if ((*out)[i] == nullptr && !lines[i].empty()) {
            for (size_t j = 0; j < i; ++j) {
                std::free((*out)[j]);
            }
            std::free(*out);
            *out = nullptr;
            *count = 0;
            return fail(ida::Error::internal("malloc failed"));
        }
    }
    return 0;
}

} // anonymous namespace

int idax_decompiler_available(int* out) {
    clear_error();
    auto r = ida::decompiler::available();
    if (!r) return fail(r.error());
    *out = *r ? 1 : 0;
    return 0;
}

int idax_decompiler_decompile(uint64_t ea, IdaxDecompiledHandle* out) {
    clear_error();
    auto r = ida::decompiler::decompile(ea);
    if (!r) return fail(r.error());
    // Move the DecompiledFunction to the heap and return as opaque handle.
    *out = new ida::decompiler::DecompiledFunction(std::move(*r));
    return 0;
}

void idax_decompiled_free(IdaxDecompiledHandle handle) {
    delete static_cast<ida::decompiler::DecompiledFunction*>(handle);
}

int idax_decompiler_on_maturity_changed(
    IdaxDecompilerMaturityChangedCallback callback,
    void* context,
    IdaxDecompilerToken* token_out) {
    clear_error();
    if (callback == nullptr) {
        return fail(ida::Error::validation("decompiler maturity callback is null"));
    }
    auto r = ida::decompiler::on_maturity_changed([callback, context](
        const ida::decompiler::MaturityEvent& event) {
        IdaxDecompilerMaturityEvent raw{};
        raw.function_address = event.function_address;
        raw.new_maturity = static_cast<int>(event.new_maturity);
        callback(context, &raw);
    });
    if (!r) return fail(r.error());
    *token_out = *r;
    return 0;
}

int idax_decompiler_on_func_printed(
    IdaxDecompilerPseudocodeCallback callback,
    void* context,
    IdaxDecompilerToken* token_out) {
    clear_error();
    if (callback == nullptr) {
        return fail(ida::Error::validation("decompiler func_printed callback is null"));
    }
    auto r = ida::decompiler::on_func_printed([callback, context](
        const ida::decompiler::PseudocodeEvent& event) {
        IdaxDecompilerPseudocodeEvent raw{};
        raw.function_address = event.function_address;
        raw.cfunc_handle = event.cfunc_handle;
        callback(context, &raw);
    });
    if (!r) return fail(r.error());
    *token_out = *r;
    return 0;
}

int idax_decompiler_on_refresh_pseudocode(
    IdaxDecompilerPseudocodeCallback callback,
    void* context,
    IdaxDecompilerToken* token_out) {
    clear_error();
    if (callback == nullptr) {
        return fail(ida::Error::validation("decompiler refresh_pseudocode callback is null"));
    }
    auto r = ida::decompiler::on_refresh_pseudocode([callback, context](
        const ida::decompiler::PseudocodeEvent& event) {
        IdaxDecompilerPseudocodeEvent raw{};
        raw.function_address = event.function_address;
        raw.cfunc_handle = event.cfunc_handle;
        callback(context, &raw);
    });
    if (!r) return fail(r.error());
    *token_out = *r;
    return 0;
}

int idax_decompiler_on_curpos_changed(
    IdaxDecompilerCursorPositionCallback callback,
    void* context,
    IdaxDecompilerToken* token_out) {
    clear_error();
    if (callback == nullptr) {
        return fail(ida::Error::validation("decompiler curpos callback is null"));
    }
    auto r = ida::decompiler::on_curpos_changed([callback, context](
        const ida::decompiler::CursorPositionEvent& event) {
        IdaxDecompilerCursorPositionEvent raw{};
        raw.function_address = event.function_address;
        raw.cursor_address = event.cursor_address;
        raw.view_handle = event.view_handle;
        callback(context, &raw);
    });
    if (!r) return fail(r.error());
    *token_out = *r;
    return 0;
}

int idax_decompiler_on_create_hint(
    IdaxDecompilerCreateHintCallback callback,
    void* context,
    IdaxDecompilerToken* token_out) {
    clear_error();
    if (callback == nullptr) {
        return fail(ida::Error::validation("decompiler create_hint callback is null"));
    }
    auto r = ida::decompiler::on_create_hint([callback, context](
        const ida::decompiler::HintRequestEvent& event) {
        IdaxDecompilerHintRequestEvent raw{};
        raw.function_address = event.function_address;
        raw.item_address = event.item_address;
        raw.view_handle = event.view_handle;

        const char* hint_text = nullptr;
        int hint_lines = 0;
        const int provided = callback(context, &raw, &hint_text, &hint_lines);
        if (provided == 0 || hint_text == nullptr) {
            return ida::decompiler::HintResult{};
        }

        ida::decompiler::HintResult result;
        result.text = hint_text;
        result.lines = hint_lines;
        return result;
    });
    if (!r) return fail(r.error());
    *token_out = *r;
    return 0;
}

int idax_decompiler_unsubscribe(IdaxDecompilerToken token) {
    RETURN_STATUS(ida::decompiler::unsubscribe(token));
}

int idax_decompiled_pseudocode(IdaxDecompiledHandle handle, char** out) {
    auto* df = static_cast<ida::decompiler::DecompiledFunction*>(handle);
    RETURN_RESULT_STRING(df->pseudocode());
}

int idax_decompiled_microcode(IdaxDecompiledHandle handle, char** out) {
    auto* df = static_cast<ida::decompiler::DecompiledFunction*>(handle);
    RETURN_RESULT_STRING(df->microcode());
}

int idax_decompiled_lines(IdaxDecompiledHandle handle, char*** out, size_t* count) {
    clear_error();
    auto* df = static_cast<ida::decompiler::DecompiledFunction*>(handle);
    auto r = df->lines();
    if (!r) return fail(r.error());
    return copy_lines_to_c_array(*r, out, count);
}

void idax_decompiled_lines_free(char** lines, size_t count) {
    if (lines) {
        for (size_t i = 0; i < count; ++i) {
            std::free(lines[i]);
        }
        std::free(lines);
    }
}

int idax_decompiled_raw_lines(IdaxDecompiledHandle handle, char*** out, size_t* count) {
    clear_error();
    auto* df = static_cast<ida::decompiler::DecompiledFunction*>(handle);
    auto r = df->raw_lines();
    if (!r) return fail(r.error());
    return copy_lines_to_c_array(*r, out, count);
}

int idax_decompiled_set_raw_line(IdaxDecompiledHandle handle,
                                 size_t line_index,
                                 const char* tagged_text) {
    auto* df = static_cast<ida::decompiler::DecompiledFunction*>(handle);
    RETURN_STATUS(df->set_raw_line(line_index, tagged_text == nullptr ? "" : tagged_text));
}

int idax_decompiled_header_line_count(IdaxDecompiledHandle handle, int* out) {
    auto* df = static_cast<ida::decompiler::DecompiledFunction*>(handle);
    RETURN_RESULT_VALUE(df->header_line_count());
}

int idax_decompiled_declaration(IdaxDecompiledHandle handle, char** out) {
    auto* df = static_cast<ida::decompiler::DecompiledFunction*>(handle);
    RETURN_RESULT_STRING(df->declaration());
}

int idax_decompiled_entry_address(IdaxDecompiledHandle handle, uint64_t* out) {
    auto* df = static_cast<ida::decompiler::DecompiledFunction*>(handle);
    *out = df->entry_address();
    return 0;
}

void idax_local_variable_free(IdaxLocalVariable* var) {
    if (var) {
        std::free(var->name);
        std::free(var->type_name);
        std::free(var->comment);
        var->name = nullptr;
        var->type_name = nullptr;
        var->comment = nullptr;
    }
}

void idax_decompiled_variables_free(IdaxLocalVariable* vars, size_t count) {
    if (vars == nullptr) {
        return;
    }
    for (size_t i = 0; i < count; ++i) {
        idax_local_variable_free(&vars[i]);
    }
    std::free(vars);
}

int idax_decompiled_variable_count(IdaxDecompiledHandle handle, size_t* out) {
    auto* df = static_cast<ida::decompiler::DecompiledFunction*>(handle);
    RETURN_RESULT_VALUE(df->variable_count());
}

int idax_decompiled_variables(IdaxDecompiledHandle handle,
                              IdaxLocalVariable** out, size_t* count) {
    clear_error();
    auto* df = static_cast<ida::decompiler::DecompiledFunction*>(handle);
    auto r = df->variables();
    if (!r) return fail(r.error());
    auto& v = *r;
    *count = v.size();
    if (v.empty()) { *out = nullptr; return 0; }
    *out = static_cast<IdaxLocalVariable*>(
        std::malloc(v.size() * sizeof(IdaxLocalVariable)));
    if (!*out) return fail(ida::Error::internal("malloc failed"));
    for (size_t i = 0; i < v.size(); ++i) {
        (*out)[i].name          = dup_string(v[i].name);
        (*out)[i].type_name     = dup_string(v[i].type_name);
        (*out)[i].is_argument   = v[i].is_argument ? 1 : 0;
        (*out)[i].width         = v[i].width;
        (*out)[i].has_user_name = v[i].has_user_name ? 1 : 0;
        (*out)[i].storage       = static_cast<int>(v[i].storage);
        (*out)[i].comment       = dup_string(v[i].comment);
    }
    return 0;
}

int idax_decompiled_rename_variable(IdaxDecompiledHandle handle,
                                    const char* old_name, const char* new_name) {
    auto* df = static_cast<ida::decompiler::DecompiledFunction*>(handle);
    RETURN_STATUS(df->rename_variable(old_name, new_name));
}

int idax_decompiled_set_comment(IdaxDecompiledHandle handle, uint64_t ea,
                                const char* text, int position) {
    auto* df = static_cast<ida::decompiler::DecompiledFunction*>(handle);
    RETURN_STATUS(df->set_comment(ea, text,
        static_cast<ida::decompiler::CommentPosition>(position)));
}

int idax_decompiled_get_comment(IdaxDecompiledHandle handle, uint64_t ea,
                                int position, char** out) {
    auto* df = static_cast<ida::decompiler::DecompiledFunction*>(handle);
    RETURN_RESULT_STRING(df->get_comment(ea,
        static_cast<ida::decompiler::CommentPosition>(position)));
}

int idax_decompiled_save_comments(IdaxDecompiledHandle handle) {
    auto* df = static_cast<ida::decompiler::DecompiledFunction*>(handle);
    RETURN_STATUS(df->save_comments());
}

int idax_decompiled_line_to_address(IdaxDecompiledHandle handle,
                                    int line_number, uint64_t* out) {
    auto* df = static_cast<ida::decompiler::DecompiledFunction*>(handle);
    RETURN_RESULT_VALUE(df->line_to_address(line_number));
}

int idax_decompiler_mark_dirty(uint64_t func_ea, int close_views) {
    RETURN_STATUS(ida::decompiler::mark_dirty(func_ea, close_views != 0));
}

int idax_decompiler_mark_dirty_with_callers(uint64_t func_ea, int close_views) {
    RETURN_STATUS(ida::decompiler::mark_dirty_with_callers(func_ea, close_views != 0));
}

int idax_decompiler_view_from_host(void* view_host, uint64_t* out_function_ea) {
    clear_error();
    auto view = ida::decompiler::view_from_host(view_host);
    if (!view) return fail(view.error());
    *out_function_ea = view->function_address();
    return 0;
}

int idax_decompiler_view_for_function(uint64_t address, uint64_t* out_function_ea) {
    clear_error();
    auto view = ida::decompiler::view_for_function(address);
    if (!view) return fail(view.error());
    *out_function_ea = view->function_address();
    return 0;
}

int idax_decompiler_current_view(uint64_t* out_function_ea) {
    clear_error();
    auto view = ida::decompiler::current_view();
    if (!view) return fail(view.error());
    *out_function_ea = view->function_address();
    return 0;
}

int idax_decompiler_raw_pseudocode_lines(void* cfunc_handle, char*** out, size_t* count) {
    clear_error();
    auto lines = ida::decompiler::raw_pseudocode_lines(cfunc_handle);
    if (!lines) return fail(lines.error());
    return copy_lines_to_c_array(*lines, out, count);
}

void idax_decompiler_pseudocode_lines_free(char** lines, size_t count) {
    idax_decompiled_lines_free(lines, count);
}

int idax_decompiler_set_pseudocode_line(void* cfunc_handle,
                                        size_t line_index,
                                        const char* tagged_text) {
    RETURN_STATUS(ida::decompiler::set_pseudocode_line(
        cfunc_handle,
        line_index,
        tagged_text == nullptr ? "" : tagged_text));
}

int idax_decompiler_pseudocode_header_line_count(void* cfunc_handle, int* out) {
    RETURN_RESULT_VALUE(ida::decompiler::pseudocode_header_line_count(cfunc_handle));
}

int idax_decompiler_item_at_position(void* cfunc_handle,
                                     const char* tagged_line,
                                     int char_index,
                                     IdaxDecompilerItemAtPosition* out) {
    clear_error();
    auto item = ida::decompiler::item_at_position(
        cfunc_handle,
        tagged_line == nullptr ? "" : tagged_line,
        char_index);
    if (!item) return fail(item.error());
    out->type = static_cast<int>(item->type);
    out->address = item->address;
    out->item_index = item->item_index;
    out->is_expression = item->is_expression ? 1 : 0;
    return 0;
}

int idax_decompiler_item_type_name(int item_type, char** out) {
    clear_error();
    const auto type = static_cast<ida::decompiler::ItemType>(item_type);
    *out = dup_string(ida::decompiler::item_type_name(type));
    if (*out == nullptr) {
        return fail(ida::Error::internal("malloc failed"));
    }
    return 0;
}

int idax_decompiler_for_each_expression(IdaxDecompiledHandle handle,
                                        IdaxDecompilerExpressionVisitor callback,
                                        void* context,
                                        int* out_visited) {
    clear_error();
    if (callback == nullptr) {
        return fail(ida::Error::validation("decompiler expression visitor callback is null"));
    }

    auto* df = static_cast<ida::decompiler::DecompiledFunction*>(handle);
    auto visited = ida::decompiler::for_each_expression(*df,
        [callback, context](ida::decompiler::ExpressionView expr) {
            IdaxDecompilerExpressionInfo raw{};
            raw.type = static_cast<int>(expr.type());
            raw.address = expr.address();
            return visit_action_from_c_int(callback(context, &raw));
        });
    if (!visited) return fail(visited.error());
    *out_visited = *visited;
    return 0;
}

int idax_decompiler_for_each_item(IdaxDecompiledHandle handle,
                                  IdaxDecompilerExpressionVisitor expression_callback,
                                  IdaxDecompilerStatementVisitor statement_callback,
                                  void* context,
                                  int* out_visited) {
    clear_error();
    if (expression_callback == nullptr && statement_callback == nullptr) {
        return fail(ida::Error::validation("at least one decompiler item visitor callback is required"));
    }

    auto* df = static_cast<ida::decompiler::DecompiledFunction*>(handle);
    auto visited = ida::decompiler::for_each_item(
        *df,
        [expression_callback, context](ida::decompiler::ExpressionView expr) {
            if (expression_callback == nullptr)
                return ida::decompiler::VisitAction::Continue;
            IdaxDecompilerExpressionInfo raw{};
            raw.type = static_cast<int>(expr.type());
            raw.address = expr.address();
            return visit_action_from_c_int(expression_callback(context, &raw));
        },
        [statement_callback, context](ida::decompiler::StatementView stmt) {
            if (statement_callback == nullptr)
                return ida::decompiler::VisitAction::Continue;
            IdaxDecompilerStatementInfo raw{};
            raw.type = static_cast<int>(stmt.type());
            raw.address = stmt.address();
            return visit_action_from_c_int(statement_callback(context, &raw));
        });
    if (!visited) return fail(visited.error());
    *out_visited = *visited;
    return 0;
}

// Microcode filter support
namespace {

struct MicrocodeFilterBridge : ida::decompiler::MicrocodeFilter {
    IdaxMicrocodeMatchCallback match_cb;
    IdaxMicrocodeApplyCallback apply_cb;
    void* context;

    bool match(const ida::decompiler::MicrocodeContext& ctx) override {
        return match_cb(context, ctx.address(), ctx.instruction_type()) != 0;
    }

    ida::decompiler::MicrocodeApplyResult
    apply(ida::decompiler::MicrocodeContext& ctx) override {
        int result = apply_cb(context, &ctx);
        return static_cast<ida::decompiler::MicrocodeApplyResult>(result);
    }
};

} // anonymous namespace

int idax_decompiler_register_microcode_filter(
    IdaxMicrocodeMatchCallback match_cb,
    IdaxMicrocodeApplyCallback apply_cb,
    void* context,
    uint64_t* token_out) {
    clear_error();
    auto filter = std::make_shared<MicrocodeFilterBridge>();
    filter->match_cb = match_cb;
    filter->apply_cb = apply_cb;
    filter->context  = context;
    auto r = ida::decompiler::register_microcode_filter(filter);
    if (!r) return fail(r.error());
    *token_out = *r;
    return 0;
}

int idax_decompiler_unregister_microcode_filter(uint64_t token) {
    RETURN_STATUS(ida::decompiler::unregister_microcode_filter(token));
}

// ═══════════════════════════════════════════════════════════════════════════
// Storage
// ═══════════════════════════════════════════════════════════════════════════

int idax_storage_node_open(const char* name, int create, IdaxNodeHandle* out) {
    clear_error();
    auto r = ida::storage::Node::open(name, create != 0);
    if (!r) return fail(r.error());
    *out = new ida::storage::Node(std::move(*r));
    return 0;
}

int idax_storage_node_open_by_id(uint64_t node_id, IdaxNodeHandle* out) {
    clear_error();
    auto r = ida::storage::Node::open_by_id(node_id);
    if (!r) return fail(r.error());
    *out = new ida::storage::Node(std::move(*r));
    return 0;
}

void idax_storage_node_free(IdaxNodeHandle node) {
    delete static_cast<ida::storage::Node*>(node);
}

int idax_storage_node_id(IdaxNodeHandle node, uint64_t* out) {
    RETURN_RESULT_VALUE(static_cast<ida::storage::Node*>(node)->id());
}

int idax_storage_node_name(IdaxNodeHandle node, char** out) {
    RETURN_RESULT_STRING(static_cast<ida::storage::Node*>(node)->name());
}

int idax_storage_node_alt_get(IdaxNodeHandle node, uint64_t index,
                              uint8_t tag, uint64_t* out) {
    RETURN_RESULT_VALUE(static_cast<ida::storage::Node*>(node)->alt(index, tag));
}

int idax_storage_node_alt_set(IdaxNodeHandle node, uint64_t index,
                              uint64_t value, uint8_t tag) {
    RETURN_STATUS(static_cast<ida::storage::Node*>(node)->set_alt(index, value, tag));
}

int idax_storage_node_alt_remove(IdaxNodeHandle node, uint64_t index,
                                 uint8_t tag) {
    RETURN_STATUS(static_cast<ida::storage::Node*>(node)->remove_alt(index, tag));
}

int idax_storage_node_sup_get(IdaxNodeHandle node, uint64_t index,
                              uint8_t tag, uint8_t** out, size_t* out_len) {
    clear_error();
    auto r = static_cast<ida::storage::Node*>(node)->sup(index, tag);
    if (!r) return fail(r.error());
    auto& v = *r;
    *out_len = v.size();
    if (v.empty()) { *out = nullptr; return 0; }
    *out = static_cast<uint8_t*>(std::malloc(v.size()));
    if (!*out) return fail(ida::Error::internal("malloc failed"));
    std::memcpy(*out, v.data(), v.size());
    return 0;
}

int idax_storage_node_sup_set(IdaxNodeHandle node, uint64_t index,
                              const uint8_t* data, size_t len, uint8_t tag) {
    RETURN_STATUS(static_cast<ida::storage::Node*>(node)->set_sup(
        index, std::span<const uint8_t>(data, len), tag));
}

int idax_storage_node_hash_get(IdaxNodeHandle node, const char* key,
                               uint8_t tag, char** out) {
    RETURN_RESULT_STRING(static_cast<ida::storage::Node*>(node)->hash(key, tag));
}

int idax_storage_node_hash_set(IdaxNodeHandle node, const char* key,
                               const char* value, uint8_t tag) {
    RETURN_STATUS(static_cast<ida::storage::Node*>(node)->set_hash(key, value, tag));
}

int idax_storage_node_blob_get(IdaxNodeHandle node, uint64_t index,
                               uint8_t tag, uint8_t** out, size_t* out_len) {
    clear_error();
    auto r = static_cast<ida::storage::Node*>(node)->blob(index, tag);
    if (!r) return fail(r.error());
    auto& v = *r;
    *out_len = v.size();
    if (v.empty()) { *out = nullptr; return 0; }
    *out = static_cast<uint8_t*>(std::malloc(v.size()));
    if (!*out) return fail(ida::Error::internal("malloc failed"));
    std::memcpy(*out, v.data(), v.size());
    return 0;
}

int idax_storage_node_blob_set(IdaxNodeHandle node, uint64_t index,
                               const uint8_t* data, size_t len, uint8_t tag) {
    RETURN_STATUS(static_cast<ida::storage::Node*>(node)->set_blob(
        index, std::span<const uint8_t>(data, len), tag));
}

int idax_storage_node_blob_remove(IdaxNodeHandle node, uint64_t index,
                                  uint8_t tag) {
    RETURN_STATUS(static_cast<ida::storage::Node*>(node)->remove_blob(index, tag));
}

int idax_storage_node_blob_size(IdaxNodeHandle node, uint64_t index,
                                uint8_t tag, size_t* out) {
    RETURN_RESULT_VALUE(static_cast<ida::storage::Node*>(node)->blob_size(index, tag));
}

int idax_storage_node_blob_string(IdaxNodeHandle node, uint64_t index,
                                  uint8_t tag, char** out) {
    RETURN_RESULT_STRING(static_cast<ida::storage::Node*>(node)->blob_string(index, tag));
}

// ═══════════════════════════════════════════════════════════════════════════
// Graph
// ═══════════════════════════════════════════════════════════════════════════

namespace {

int fill_node_ids(const std::vector<int>& v, int** out, size_t* count) {
    *count = v.size();
    if (v.empty()) {
        *out = nullptr;
        return 0;
    }
    *out = static_cast<int*>(std::malloc(v.size() * sizeof(int)));
    if (*out == nullptr) {
        return fail(ida::Error::internal("malloc failed"));
    }
    std::memcpy(*out, v.data(), v.size() * sizeof(int));
    return 0;
}

class ShimGraphCallback final : public ida::graph::GraphCallback {
public:
    explicit ShimGraphCallback(IdaxGraphHandle graph_handle,
                               const IdaxGraphCallbacks& callbacks)
        : graph_handle_(graph_handle), callbacks_(callbacks) {}

    bool on_refresh(ida::graph::Graph& graph) override {
        (void)graph;
        if (callbacks_.on_refresh == nullptr) {
            return false;
        }
        return callbacks_.on_refresh(callbacks_.context, graph_handle_) != 0;
    }

    std::string on_node_text(int node) override {
        if (callbacks_.on_node_text == nullptr) {
            return {};
        }
        char* text = nullptr;
        if (callbacks_.on_node_text(callbacks_.context, node, &text) == 0 || text == nullptr) {
            return {};
        }
        return std::string(text);
    }

    std::uint32_t on_node_color(int node) override {
        if (callbacks_.on_node_color == nullptr) {
            return 0xFFFFFFFFu;
        }
        return callbacks_.on_node_color(callbacks_.context, node);
    }

    bool on_clicked(int node) override {
        if (callbacks_.on_clicked == nullptr) {
            return false;
        }
        return callbacks_.on_clicked(callbacks_.context, node) != 0;
    }

    bool on_double_clicked(int node) override {
        if (callbacks_.on_double_clicked == nullptr) {
            return false;
        }
        return callbacks_.on_double_clicked(callbacks_.context, node) != 0;
    }

    std::string on_hint(int node) override {
        if (callbacks_.on_hint == nullptr) {
            return {};
        }
        char* hint = nullptr;
        if (callbacks_.on_hint(callbacks_.context, node, &hint) == 0 || hint == nullptr) {
            return {};
        }
        return std::string(hint);
    }

    bool on_creating_group(const std::vector<int>& nodes) override {
        if (callbacks_.on_creating_group == nullptr) {
            return true;
        }
        return callbacks_.on_creating_group(
            callbacks_.context,
            nodes.empty() ? nullptr : nodes.data(),
            nodes.size()) != 0;
    }

    void on_destroyed() override {
        if (callbacks_.on_destroyed != nullptr) {
            callbacks_.on_destroyed(callbacks_.context);
        }
        delete this;
    }

private:
    IdaxGraphHandle    graph_handle_{nullptr};
    IdaxGraphCallbacks callbacks_{};
};

int fill_basic_blocks(const std::vector<ida::graph::BasicBlock>& v,
                      IdaxBasicBlock** out,
                      size_t* count) {
    *count = v.size();
    if (v.empty()) {
        *out = nullptr;
        return 0;
    }

    *out = static_cast<IdaxBasicBlock*>(std::malloc(v.size() * sizeof(IdaxBasicBlock)));
    if (*out == nullptr) {
        return fail(ida::Error::internal("malloc failed"));
    }

    for (size_t i = 0; i < v.size(); ++i) {
        (*out)[i].start = v[i].start;
        (*out)[i].end   = v[i].end;
        (*out)[i].type  = static_cast<int>(v[i].type);

        (*out)[i].successor_count = v[i].successors.size();
        if (v[i].successors.empty()) {
            (*out)[i].successors = nullptr;
        } else {
            (*out)[i].successors = static_cast<int*>(
                std::malloc(v[i].successors.size() * sizeof(int)));
            if ((*out)[i].successors == nullptr) {
                return fail(ida::Error::internal("malloc failed"));
            }
            std::memcpy((*out)[i].successors, v[i].successors.data(),
                        v[i].successors.size() * sizeof(int));
        }

        (*out)[i].predecessor_count = v[i].predecessors.size();
        if (v[i].predecessors.empty()) {
            (*out)[i].predecessors = nullptr;
        } else {
            (*out)[i].predecessors = static_cast<int*>(
                std::malloc(v[i].predecessors.size() * sizeof(int)));
            if ((*out)[i].predecessors == nullptr) {
                return fail(ida::Error::internal("malloc failed"));
            }
            std::memcpy((*out)[i].predecessors, v[i].predecessors.data(),
                        v[i].predecessors.size() * sizeof(int));
        }
    }
    return 0;
}

} // anonymous namespace

IdaxGraphHandle idax_graph_create(void) {
    return new ida::graph::Graph();
}

void idax_graph_free(IdaxGraphHandle graph) {
    delete static_cast<ida::graph::Graph*>(graph);
}

int idax_graph_add_node(IdaxGraphHandle graph) {
    return static_cast<ida::graph::Graph*>(graph)->add_node();
}

int idax_graph_remove_node(IdaxGraphHandle graph, int node) {
    RETURN_STATUS(static_cast<ida::graph::Graph*>(graph)->remove_node(node));
}

int idax_graph_total_node_count(IdaxGraphHandle graph) {
    return static_cast<ida::graph::Graph*>(graph)->total_node_count();
}

int idax_graph_visible_node_count(IdaxGraphHandle graph) {
    return static_cast<ida::graph::Graph*>(graph)->visible_node_count();
}

int idax_graph_node_exists(IdaxGraphHandle graph, int node) {
    return static_cast<ida::graph::Graph*>(graph)->node_exists(node) ? 1 : 0;
}

int idax_graph_add_edge(IdaxGraphHandle graph, int source, int target) {
    RETURN_STATUS(static_cast<ida::graph::Graph*>(graph)->add_edge(source, target));
}

int idax_graph_add_edge_with_info(IdaxGraphHandle graph, int source, int target,
                                  const IdaxGraphEdgeInfo* info) {
    ida::graph::EdgeInfo edge_info;
    if (info != nullptr) {
        edge_info.color = info->color;
        edge_info.width = info->width;
        edge_info.source_port = info->source_port;
        edge_info.target_port = info->target_port;
    }
    RETURN_STATUS(static_cast<ida::graph::Graph*>(graph)->add_edge(source, target, edge_info));
}

int idax_graph_remove_edge(IdaxGraphHandle graph, int source, int target) {
    RETURN_STATUS(static_cast<ida::graph::Graph*>(graph)->remove_edge(source, target));
}

int idax_graph_replace_edge(IdaxGraphHandle graph, int from, int to,
                            int new_from, int new_to) {
    RETURN_STATUS(static_cast<ida::graph::Graph*>(graph)->replace_edge(from, to, new_from, new_to));
}

int idax_graph_clear(IdaxGraphHandle graph) {
    static_cast<ida::graph::Graph*>(graph)->clear();
    return 0;
}

int idax_graph_successors(IdaxGraphHandle graph, int node,
                          int** out, size_t* count) {
    clear_error();
    auto r = static_cast<ida::graph::Graph*>(graph)->successors(node);
    if (!r) return fail(r.error());
    auto& v = *r;
    *count = v.size();
    if (v.empty()) { *out = nullptr; return 0; }
    *out = static_cast<int*>(std::malloc(v.size() * sizeof(int)));
    if (!*out) return fail(ida::Error::internal("malloc failed"));
    std::memcpy(*out, v.data(), v.size() * sizeof(int));
    return 0;
}

int idax_graph_predecessors(IdaxGraphHandle graph, int node,
                            int** out, size_t* count) {
    clear_error();
    auto r = static_cast<ida::graph::Graph*>(graph)->predecessors(node);
    if (!r) return fail(r.error());
    return fill_node_ids(*r, out, count);
}

int idax_graph_visible_nodes(IdaxGraphHandle graph, int** out, size_t* count) {
    clear_error();
    auto v = static_cast<ida::graph::Graph*>(graph)->visible_nodes();
    return fill_node_ids(v, out, count);
}

int idax_graph_edges(IdaxGraphHandle graph, IdaxGraphEdge** out, size_t* count) {
    clear_error();
    auto v = static_cast<ida::graph::Graph*>(graph)->edges();
    *count = v.size();
    if (v.empty()) {
        *out = nullptr;
        return 0;
    }
    *out = static_cast<IdaxGraphEdge*>(std::malloc(v.size() * sizeof(IdaxGraphEdge)));
    if (*out == nullptr) {
        return fail(ida::Error::internal("malloc failed"));
    }
    for (size_t i = 0; i < v.size(); ++i) {
        (*out)[i].source = v[i].source;
        (*out)[i].target = v[i].target;
    }
    return 0;
}

int idax_graph_path_exists(IdaxGraphHandle graph, int source, int target) {
    return static_cast<ida::graph::Graph*>(graph)->path_exists(source, target) ? 1 : 0;
}

int idax_graph_create_group(IdaxGraphHandle graph, const int* nodes, size_t count,
                            int* out_group) {
    clear_error();
    if (count > 0 && nodes == nullptr) {
        return fail(ida::Error::validation("nodes pointer is null"));
    }
    std::vector<int> members;
    members.reserve(count);
    for (size_t i = 0; i < count; ++i) {
        members.push_back(nodes[i]);
    }
    auto r = static_cast<ida::graph::Graph*>(graph)->create_group(members);
    if (!r) {
        return fail(r.error());
    }
    *out_group = *r;
    return 0;
}

int idax_graph_delete_group(IdaxGraphHandle graph, int group) {
    RETURN_STATUS(static_cast<ida::graph::Graph*>(graph)->delete_group(group));
}

int idax_graph_set_group_expanded(IdaxGraphHandle graph, int group, int expanded) {
    RETURN_STATUS(static_cast<ida::graph::Graph*>(graph)->set_group_expanded(group, expanded != 0));
}

int idax_graph_is_group(IdaxGraphHandle graph, int node) {
    return static_cast<ida::graph::Graph*>(graph)->is_group(node) ? 1 : 0;
}

int idax_graph_is_collapsed(IdaxGraphHandle graph, int group) {
    return static_cast<ida::graph::Graph*>(graph)->is_collapsed(group) ? 1 : 0;
}

int idax_graph_group_members(IdaxGraphHandle graph, int group,
                             int** out, size_t* count) {
    clear_error();
    auto r = static_cast<ida::graph::Graph*>(graph)->group_members(group);
    if (!r) {
        return fail(r.error());
    }
    return fill_node_ids(*r, out, count);
}

int idax_graph_set_layout(IdaxGraphHandle graph, int layout) {
    RETURN_STATUS(static_cast<ida::graph::Graph*>(graph)->set_layout(
        static_cast<ida::graph::Layout>(layout)));
}

int idax_graph_current_layout(IdaxGraphHandle graph) {
    return static_cast<int>(static_cast<ida::graph::Graph*>(graph)->current_layout());
}

int idax_graph_redo_layout(IdaxGraphHandle graph) {
    RETURN_STATUS(static_cast<ida::graph::Graph*>(graph)->redo_layout());
}

int idax_graph_show_graph(const char* title, IdaxGraphHandle graph,
                          const IdaxGraphCallbacks* callbacks) {
    clear_error();
    if (title == nullptr) {
        return fail(ida::Error::validation("title is null"));
    }
    ida::graph::GraphCallback* callback_obj = nullptr;
    if (callbacks != nullptr) {
        callback_obj = new ShimGraphCallback(graph, *callbacks);
    }
    auto s = ida::graph::show_graph(title, *static_cast<ida::graph::Graph*>(graph), callback_obj);
    if (!s) {
        delete callback_obj;
        return fail(s.error());
    }
    return 0;
}

int idax_graph_refresh_graph(const char* title) {
    if (title == nullptr) {
        return fail(ida::Error::validation("title is null"));
    }
    RETURN_STATUS(ida::graph::refresh_graph(title));
}

int idax_graph_has_graph_viewer(const char* title, int* out) {
    clear_error();
    if (title == nullptr) {
        return fail(ida::Error::validation("title is null"));
    }
    auto r = ida::graph::has_graph_viewer(title);
    if (!r) {
        return fail(r.error());
    }
    *out = *r ? 1 : 0;
    return 0;
}

int idax_graph_is_graph_viewer_visible(const char* title, int* out) {
    clear_error();
    if (title == nullptr) {
        return fail(ida::Error::validation("title is null"));
    }
    auto r = ida::graph::is_graph_viewer_visible(title);
    if (!r) {
        return fail(r.error());
    }
    *out = *r ? 1 : 0;
    return 0;
}

int idax_graph_activate_graph_viewer(const char* title) {
    if (title == nullptr) {
        return fail(ida::Error::validation("title is null"));
    }
    RETURN_STATUS(ida::graph::activate_graph_viewer(title));
}

int idax_graph_close_graph_viewer(const char* title) {
    if (title == nullptr) {
        return fail(ida::Error::validation("title is null"));
    }
    RETURN_STATUS(ida::graph::close_graph_viewer(title));
}

void idax_graph_free_node_ids(int* p) {
    std::free(p);
}

void idax_graph_free_edges(IdaxGraphEdge* p) {
    std::free(p);
}

void idax_basic_block_free(IdaxBasicBlock* block) {
    if (block) {
        std::free(block->successors);
        std::free(block->predecessors);
        block->successors = nullptr;
        block->predecessors = nullptr;
    }
}

int idax_graph_flowchart(uint64_t function_address,
                         IdaxBasicBlock** out, size_t* count) {
    clear_error();
    auto r = ida::graph::flowchart(function_address);
    if (!r) {
        return fail(r.error());
    }
    return fill_basic_blocks(*r, out, count);
}

int idax_graph_flowchart_for_ranges(const IdaxAddressRange* ranges, size_t range_count,
                                    IdaxBasicBlock** out, size_t* count) {
    clear_error();
    if (range_count > 0 && ranges == nullptr) {
        return fail(ida::Error::validation("ranges pointer is null"));
    }
    std::vector<ida::address::Range> native_ranges;
    native_ranges.reserve(range_count);
    for (size_t i = 0; i < range_count; ++i) {
        native_ranges.push_back(ida::address::Range{ranges[i].start, ranges[i].end});
    }
    auto r = ida::graph::flowchart_for_ranges(native_ranges);
    if (!r) {
        return fail(r.error());
    }
    return fill_basic_blocks(*r, out, count);
}

void idax_graph_flowchart_free(IdaxBasicBlock* blocks, size_t count) {
    if (blocks) {
        for (size_t i = 0; i < count; ++i) {
            idax_basic_block_free(&blocks[i]);
        }
        std::free(blocks);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// UI
// ═══════════════════════════════════════════════════════════════════════════

namespace {

struct UiWidgetHandle {
    ida::ui::Widget widget;
};

UiWidgetHandle* as_widget_handle(IdaxWidgetHandle handle) {
    return static_cast<UiWidgetHandle*>(handle);
}

ida::ui::Widget* as_widget(IdaxWidgetHandle handle) {
    auto* h = as_widget_handle(handle);
    return h == nullptr ? nullptr : &h->widget;
}

void* widget_ptr(const ida::ui::Widget& widget) {
    if (!widget.valid()) {
        return nullptr;
    }
    auto host = ida::ui::widget_host(widget);
    if (!host || *host == nullptr) {
        return nullptr;
    }
    return *host;
}

std::vector<std::string> collect_viewer_lines(const char* const* lines, size_t line_count) {
    std::vector<std::string> out;
    out.reserve(line_count);
    for (size_t i = 0; i < line_count; ++i) {
        out.emplace_back(lines[i] != nullptr ? lines[i] : "");
    }
    return out;
}

bool parse_ui_event_kind(int raw, ida::ui::EventKind* out) {
    using K = ida::ui::EventKind;
    switch (raw) {
        case 0:  *out = K::DatabaseInited; return true;
        case 1:  *out = K::DatabaseClosed; return true;
        case 2:  *out = K::ReadyToRun; return true;
        case 3:  *out = K::CurrentWidgetChanged; return true;
        case 4:  *out = K::ScreenAddressChanged; return true;
        case 5:  *out = K::WidgetVisible; return true;
        case 6:  *out = K::WidgetInvisible; return true;
        case 7:  *out = K::WidgetClosing; return true;
        case 8:  *out = K::ViewActivated; return true;
        case 9:  *out = K::ViewDeactivated; return true;
        case 10: *out = K::ViewCreated; return true;
        case 11: *out = K::ViewClosed; return true;
        case 12: *out = K::CursorChanged; return true;
        default: return false;
    }
}

void fill_event(IdaxUIEvent* out, const ida::ui::Event& ev) {
    out->kind = static_cast<int>(ev.kind);
    out->address = ev.address;
    out->previous_address = ev.previous_address;
    out->widget = widget_ptr(ev.widget);
    out->previous_widget = widget_ptr(ev.previous_widget);
    out->widget_id = ev.widget.id();
    out->previous_widget_id = ev.previous_widget.id();
    out->is_new_database = ev.is_new_database ? 1 : 0;
    out->startup_script = ev.startup_script.c_str();
    out->widget_title = ev.widget_title.c_str();
}

int set_token(const ida::Result<ida::ui::Token>& token_r, uint64_t* token_out) {
    if (!token_r) {
        return fail(token_r.error());
    }
    *token_out = *token_r;
    return 0;
}

} // anonymous namespace

void idax_ui_message(const char* text) {
    ida::ui::message(text != nullptr ? text : "");
}

void idax_ui_warning(const char* text) {
    ida::ui::warning(text != nullptr ? text : "");
}

void idax_ui_info(const char* text) {
    ida::ui::info(text != nullptr ? text : "");
}

int idax_ui_ask_yn(const char* question, int default_yes, int* out) {
    clear_error();
    if (out == nullptr) {
        return fail(ida::Error::validation("out pointer is null"));
    }
    auto r = ida::ui::ask_yn(question != nullptr ? question : "", default_yes != 0);
    if (!r) return fail(r.error());
    *out = *r ? 1 : 0;
    return 0;
}

int idax_ui_ask_string(const char* prompt, const char* default_value, char** out) {
    RETURN_RESULT_STRING(ida::ui::ask_string(prompt != nullptr ? prompt : "",
                                             default_value != nullptr ? default_value : ""));
}

int idax_ui_ask_file(int for_saving, const char* default_path,
                     const char* prompt, char** out) {
    RETURN_RESULT_STRING(ida::ui::ask_file(for_saving != 0,
                                           default_path != nullptr ? default_path : "",
                                           prompt != nullptr ? prompt : ""));
}

int idax_ui_ask_address(const char* prompt, uint64_t default_value,
                        uint64_t* out) {
    RETURN_RESULT_VALUE(ida::ui::ask_address(prompt != nullptr ? prompt : "", default_value));
}

int idax_ui_ask_long(const char* prompt, int64_t default_value, int64_t* out) {
    RETURN_RESULT_VALUE(ida::ui::ask_long(prompt != nullptr ? prompt : "", default_value));
}

int idax_ui_ask_form(const char* markup, int* out) {
    clear_error();
    if (out == nullptr) {
        return fail(ida::Error::validation("out pointer is null"));
    }
    auto r = ida::ui::ask_form(markup != nullptr ? markup : "");
    if (!r) {
        return fail(r.error());
    }
    *out = *r ? 1 : 0;
    return 0;
}

int idax_ui_jump_to(uint64_t address) {
    RETURN_STATUS(ida::ui::jump_to(address));
}

int idax_ui_screen_address(uint64_t* out) {
    RETURN_RESULT_VALUE(ida::ui::screen_address());
}

int idax_ui_selection(uint64_t* start_out, uint64_t* end_out) {
    clear_error();
    auto r = ida::ui::selection();
    if (!r) return fail(r.error());
    *start_out = r->start;
    *end_out = r->end;
    return 0;
}

void idax_ui_refresh_all_views(void) {
    ida::ui::refresh_all_views();
}

int idax_ui_user_directory(char** out) {
    RETURN_RESULT_STRING(ida::ui::user_directory());
}

int idax_ui_create_widget(const char* title, IdaxWidgetHandle* out) {
    clear_error();
    if (out == nullptr) {
        return fail(ida::Error::validation("out pointer is null"));
    }
    auto r = ida::ui::create_widget(title != nullptr ? title : "");
    if (!r) return fail(r.error());
    *out = static_cast<IdaxWidgetHandle>(new UiWidgetHandle{std::move(*r)});
    return 0;
}

int idax_ui_show_widget(IdaxWidgetHandle widget, int position) {
    IdaxShowWidgetOptions options{};
    options.position = position;
    options.restore_previous = 1;
    return idax_ui_show_widget_ex(widget, &options);
}

int idax_ui_show_widget_ex(IdaxWidgetHandle widget, const IdaxShowWidgetOptions* options) {
    clear_error();
    auto* w = as_widget(widget);
    if (w == nullptr) {
        return fail(ida::Error::validation("widget handle is null"));
    }
    ida::ui::ShowWidgetOptions native{};
    if (options != nullptr) {
        native.position = static_cast<ida::ui::DockPosition>(options->position);
        native.restore_previous = options->restore_previous != 0;
    }
    auto status = ida::ui::show_widget(*w, native);
    if (!status) {
        return fail(status.error());
    }
    return 0;
}

int idax_ui_activate_widget(IdaxWidgetHandle widget) {
    auto* w = as_widget(widget);
    if (w == nullptr) {
        return fail(ida::Error::validation("widget handle is null"));
    }
    RETURN_STATUS(ida::ui::activate_widget(*w));
}

int idax_ui_close_widget(IdaxWidgetHandle widget) {
    auto* handle = as_widget_handle(widget);
    if (handle == nullptr) {
        return fail(ida::Error::validation("widget handle is null"));
    }
    auto s = ida::ui::close_widget(handle->widget);
    if (!s) return fail(s.error());
    delete handle;
    return 0;
}

int idax_ui_find_widget(const char* title, IdaxWidgetHandle* out) {
    clear_error();
    if (out == nullptr) {
        return fail(ida::Error::validation("out pointer is null"));
    }
    auto w = ida::ui::find_widget(title != nullptr ? title : "");
    if (!w.valid()) {
        return fail(ida::Error::not_found("Widget not found"));
    }
    *out = static_cast<IdaxWidgetHandle>(new UiWidgetHandle{std::move(w)});
    return 0;
}

int idax_ui_is_widget_visible(IdaxWidgetHandle widget) {
    auto* w = as_widget(widget);
    return w != nullptr && ida::ui::is_widget_visible(*w) ? 1 : 0;
}

int idax_ui_widget_type(IdaxWidgetHandle widget) {
    auto* w = as_widget(widget);
    if (w == nullptr) {
        return static_cast<int>(ida::ui::WidgetType::Unknown);
    }
    return static_cast<int>(ida::ui::widget_type(*w));
}

int idax_ui_widget_title(IdaxWidgetHandle widget, char** out) {
    clear_error();
    if (out == nullptr) {
        return fail(ida::Error::validation("out pointer is null"));
    }
    auto* w = as_widget(widget);
    if (w == nullptr) {
        return fail(ida::Error::validation("widget handle is null"));
    }
    *out = dup_string(w->title());
    if (*out == nullptr) {
        return fail(ida::Error::internal("malloc failed"));
    }
    return 0;
}

int idax_ui_widget_id(IdaxWidgetHandle widget, uint64_t* out) {
    clear_error();
    if (out == nullptr) {
        return fail(ida::Error::validation("out pointer is null"));
    }
    auto* w = as_widget(widget);
    if (w == nullptr) {
        return fail(ida::Error::validation("widget handle is null"));
    }
    *out = w->id();
    return 0;
}

int idax_ui_widget_host(IdaxWidgetHandle widget, void** out) {
    clear_error();
    if (out == nullptr) {
        return fail(ida::Error::validation("out pointer is null"));
    }
    auto* w = as_widget(widget);
    if (w == nullptr) {
        return fail(ida::Error::validation("widget handle is null"));
    }
    auto r = ida::ui::widget_host(*w);
    if (!r) {
        return fail(r.error());
    }
    *out = *r;
    return 0;
}

int idax_ui_with_widget_host(IdaxWidgetHandle widget,
                             IdaxWidgetHostCallback callback,
                             void* context) {
    clear_error();
    if (callback == nullptr) {
        return fail(ida::Error::validation("callback is null"));
    }
    auto* w = as_widget(widget);
    if (w == nullptr) {
        return fail(ida::Error::validation("widget handle is null"));
    }
    auto status = ida::ui::with_widget_host(
        *w,
        [callback, context](ida::ui::WidgetHost host) -> ida::Status {
            int rc = callback(context, host);
            if (rc != 0) {
                return std::unexpected(ida::Error::sdk("widget host callback failed",
                                                       std::to_string(rc)));
            }
            return ida::ok();
        });
    if (!status) {
        return fail(status.error());
    }
    return 0;
}

int idax_ui_create_custom_viewer(const char* title,
                                 const char* const* lines,
                                 size_t line_count,
                                 IdaxWidgetHandle* out) {
    clear_error();
    if (line_count > 0 && lines == nullptr) {
        return fail(ida::Error::validation("lines pointer is null"));
    }
    if (out == nullptr) {
        return fail(ida::Error::validation("out pointer is null"));
    }
    auto native_lines = collect_viewer_lines(lines, line_count);
    auto r = ida::ui::create_custom_viewer(title != nullptr ? title : "", native_lines);
    if (!r) {
        return fail(r.error());
    }
    *out = static_cast<IdaxWidgetHandle>(new UiWidgetHandle{std::move(*r)});
    return 0;
}

int idax_ui_set_custom_viewer_lines(IdaxWidgetHandle viewer,
                                    const char* const* lines,
                                    size_t line_count) {
    clear_error();
    if (line_count > 0 && lines == nullptr) {
        return fail(ida::Error::validation("lines pointer is null"));
    }
    auto* w = as_widget(viewer);
    if (w == nullptr) {
        return fail(ida::Error::validation("viewer handle is null"));
    }
    auto native_lines = collect_viewer_lines(lines, line_count);
    auto status = ida::ui::set_custom_viewer_lines(*w, native_lines);
    if (!status) {
        return fail(status.error());
    }
    return 0;
}

int idax_ui_custom_viewer_line_count(IdaxWidgetHandle viewer, size_t* out) {
    clear_error();
    if (out == nullptr) {
        return fail(ida::Error::validation("out pointer is null"));
    }
    auto* w = as_widget(viewer);
    if (w == nullptr) {
        return fail(ida::Error::validation("viewer handle is null"));
    }
    auto r = ida::ui::custom_viewer_line_count(*w);
    if (!r) {
        return fail(r.error());
    }
    *out = *r;
    return 0;
}

int idax_ui_custom_viewer_jump_to_line(IdaxWidgetHandle viewer,
                                       size_t line_index,
                                       int x,
                                       int y) {
    clear_error();
    auto* w = as_widget(viewer);
    if (w == nullptr) {
        return fail(ida::Error::validation("viewer handle is null"));
    }
    auto status = ida::ui::custom_viewer_jump_to_line(*w, line_index, x, y);
    if (!status) {
        return fail(status.error());
    }
    return 0;
}

int idax_ui_custom_viewer_current_line(IdaxWidgetHandle viewer, int mouse, char** out) {
    clear_error();
    if (out == nullptr) {
        return fail(ida::Error::validation("out pointer is null"));
    }
    auto* w = as_widget(viewer);
    if (w == nullptr) {
        return fail(ida::Error::validation("viewer handle is null"));
    }
    auto r = ida::ui::custom_viewer_current_line(*w, mouse != 0);
    if (!r) {
        return fail(r.error());
    }
    *out = dup_string(*r);
    if (*out == nullptr) {
        return fail(ida::Error::internal("malloc failed"));
    }
    return 0;
}

int idax_ui_refresh_custom_viewer(IdaxWidgetHandle viewer) {
    clear_error();
    auto* w = as_widget(viewer);
    if (w == nullptr) {
        return fail(ida::Error::validation("viewer handle is null"));
    }
    auto status = ida::ui::refresh_custom_viewer(*w);
    if (!status) {
        return fail(status.error());
    }
    return 0;
}

int idax_ui_close_custom_viewer(IdaxWidgetHandle viewer) {
    clear_error();
    auto* handle = as_widget_handle(viewer);
    if (handle == nullptr) {
        return fail(ida::Error::validation("viewer handle is null"));
    }
    auto status = ida::ui::close_custom_viewer(handle->widget);
    if (!status) {
        return fail(status.error());
    }
    delete handle;
    return 0;
}

int idax_ui_register_timer(int interval_ms, uint64_t* token_out) {
    return idax_ui_register_timer_with_callback(interval_ms,
                                                [](void*) -> int { return 0; },
                                                nullptr,
                                                token_out);
}

int idax_ui_register_timer_with_callback(int interval_ms,
                                         IdaxUITimerCallback callback,
                                         void* context,
                                         uint64_t* token_out) {
    clear_error();
    if (token_out == nullptr) {
        return fail(ida::Error::validation("token_out pointer is null"));
    }
    if (callback == nullptr) {
        return fail(ida::Error::validation("timer callback is null"));
    }
    auto r = ida::ui::register_timer(interval_ms, [callback, context]() -> int {
        return callback(context);
    });
    if (!r) return fail(r.error());
    *token_out = *r;
    return 0;
}

int idax_ui_unregister_timer(uint64_t token) {
    RETURN_STATUS(ida::ui::unregister_timer(token));
}

int idax_ui_subscribe(int event_kind, IdaxUIEventCallback callback,
                      void* context, uint64_t* token_out) {
    clear_error();
    if (callback == nullptr || token_out == nullptr) {
        return fail(ida::Error::validation("callback/token_out is null"));
    }
    ida::ui::EventKind wanted{};
    if (!parse_ui_event_kind(event_kind, &wanted)) {
        return fail(ida::Error::validation("invalid UI event kind", std::to_string(event_kind)));
    }
    auto r = ida::ui::on_event_filtered(
        [wanted](const ida::ui::Event& ev) {
            return ev.kind == wanted;
        },
        [callback, context](const ida::ui::Event& ev) {
            callback(context, static_cast<int>(ev.kind), ev.address);
        });
    if (!r) return fail(r.error());
    *token_out = *r;
    return 0;
}

int idax_ui_on_database_closed(IdaxUIEventExCallback callback,
                               void* context,
                               uint64_t* token_out) {
    clear_error();
    if (callback == nullptr || token_out == nullptr) {
        return fail(ida::Error::validation("callback/token_out is null"));
    }
    auto r = ida::ui::on_database_closed([callback, context]() {
        ida::ui::Event ev;
        ev.kind = ida::ui::EventKind::DatabaseClosed;
        IdaxUIEvent ffi{};
        fill_event(&ffi, ev);
        callback(context, &ffi);
    });
    return set_token(r, token_out);
}

int idax_ui_on_database_inited(IdaxUIEventExCallback callback,
                               void* context,
                               uint64_t* token_out) {
    clear_error();
    if (callback == nullptr || token_out == nullptr) {
        return fail(ida::Error::validation("callback/token_out is null"));
    }
    auto r = ida::ui::on_database_inited([callback, context](bool is_new, std::string script) {
        ida::ui::Event ev;
        ev.kind = ida::ui::EventKind::DatabaseInited;
        ev.is_new_database = is_new;
        ev.startup_script = std::move(script);
        IdaxUIEvent ffi{};
        fill_event(&ffi, ev);
        callback(context, &ffi);
    });
    return set_token(r, token_out);
}

int idax_ui_on_ready_to_run(IdaxUIEventExCallback callback,
                            void* context,
                            uint64_t* token_out) {
    clear_error();
    if (callback == nullptr || token_out == nullptr) {
        return fail(ida::Error::validation("callback/token_out is null"));
    }
    auto r = ida::ui::on_ready_to_run([callback, context]() {
        ida::ui::Event ev;
        ev.kind = ida::ui::EventKind::ReadyToRun;
        IdaxUIEvent ffi{};
        fill_event(&ffi, ev);
        callback(context, &ffi);
    });
    return set_token(r, token_out);
}

int idax_ui_on_screen_ea_changed(IdaxUIEventExCallback callback,
                                 void* context,
                                 uint64_t* token_out) {
    clear_error();
    if (callback == nullptr || token_out == nullptr) {
        return fail(ida::Error::validation("callback/token_out is null"));
    }
    auto r = ida::ui::on_screen_ea_changed([callback, context](ida::Address ea, ida::Address prev) {
        ida::ui::Event ev;
        ev.kind = ida::ui::EventKind::ScreenAddressChanged;
        ev.address = ea;
        ev.previous_address = prev;
        IdaxUIEvent ffi{};
        fill_event(&ffi, ev);
        callback(context, &ffi);
    });
    return set_token(r, token_out);
}

int idax_ui_on_current_widget_changed(IdaxUIEventExCallback callback,
                                      void* context,
                                      uint64_t* token_out) {
    clear_error();
    if (callback == nullptr || token_out == nullptr) {
        return fail(ida::Error::validation("callback/token_out is null"));
    }
    auto r = ida::ui::on_current_widget_changed([callback, context](ida::ui::Widget current,
                                                                     ida::ui::Widget previous) {
        ida::ui::Event ev;
        ev.kind = ida::ui::EventKind::CurrentWidgetChanged;
        ev.widget = std::move(current);
        ev.previous_widget = std::move(previous);
        IdaxUIEvent ffi{};
        fill_event(&ffi, ev);
        callback(context, &ffi);
    });
    return set_token(r, token_out);
}

int idax_ui_on_widget_visible(IdaxUIEventExCallback callback,
                              void* context,
                              uint64_t* token_out) {
    clear_error();
    if (callback == nullptr || token_out == nullptr) {
        return fail(ida::Error::validation("callback/token_out is null"));
    }
    auto r = ida::ui::on_widget_visible([callback, context](std::string title) {
        ida::ui::Event ev;
        ev.kind = ida::ui::EventKind::WidgetVisible;
        ev.widget_title = std::move(title);
        IdaxUIEvent ffi{};
        fill_event(&ffi, ev);
        callback(context, &ffi);
    });
    return set_token(r, token_out);
}

int idax_ui_on_widget_invisible(IdaxUIEventExCallback callback,
                                void* context,
                                uint64_t* token_out) {
    clear_error();
    if (callback == nullptr || token_out == nullptr) {
        return fail(ida::Error::validation("callback/token_out is null"));
    }
    auto r = ida::ui::on_widget_invisible([callback, context](std::string title) {
        ida::ui::Event ev;
        ev.kind = ida::ui::EventKind::WidgetInvisible;
        ev.widget_title = std::move(title);
        IdaxUIEvent ffi{};
        fill_event(&ffi, ev);
        callback(context, &ffi);
    });
    return set_token(r, token_out);
}

int idax_ui_on_widget_closing(IdaxUIEventExCallback callback,
                              void* context,
                              uint64_t* token_out) {
    clear_error();
    if (callback == nullptr || token_out == nullptr) {
        return fail(ida::Error::validation("callback/token_out is null"));
    }
    auto r = ida::ui::on_widget_closing([callback, context](std::string title) {
        ida::ui::Event ev;
        ev.kind = ida::ui::EventKind::WidgetClosing;
        ev.widget_title = std::move(title);
        IdaxUIEvent ffi{};
        fill_event(&ffi, ev);
        callback(context, &ffi);
    });
    return set_token(r, token_out);
}

int idax_ui_on_widget_visible_for_widget(IdaxWidgetHandle widget,
                                         IdaxUIEventExCallback callback,
                                         void* context,
                                         uint64_t* token_out) {
    clear_error();
    auto* w = as_widget(widget);
    if (w == nullptr || callback == nullptr || token_out == nullptr) {
        return fail(ida::Error::validation("widget/callback/token_out is null"));
    }
    auto r = ida::ui::on_widget_visible(*w, [callback, context](ida::ui::Widget matched) {
        ida::ui::Event ev;
        ev.kind = ida::ui::EventKind::WidgetVisible;
        ev.widget = std::move(matched);
        ev.widget_title = ev.widget.title();
        IdaxUIEvent ffi{};
        fill_event(&ffi, ev);
        callback(context, &ffi);
    });
    return set_token(r, token_out);
}

int idax_ui_on_widget_invisible_for_widget(IdaxWidgetHandle widget,
                                           IdaxUIEventExCallback callback,
                                           void* context,
                                           uint64_t* token_out) {
    clear_error();
    auto* w = as_widget(widget);
    if (w == nullptr || callback == nullptr || token_out == nullptr) {
        return fail(ida::Error::validation("widget/callback/token_out is null"));
    }
    auto r = ida::ui::on_widget_invisible(*w, [callback, context](ida::ui::Widget matched) {
        ida::ui::Event ev;
        ev.kind = ida::ui::EventKind::WidgetInvisible;
        ev.widget = std::move(matched);
        ev.widget_title = ev.widget.title();
        IdaxUIEvent ffi{};
        fill_event(&ffi, ev);
        callback(context, &ffi);
    });
    return set_token(r, token_out);
}

int idax_ui_on_widget_closing_for_widget(IdaxWidgetHandle widget,
                                         IdaxUIEventExCallback callback,
                                         void* context,
                                         uint64_t* token_out) {
    clear_error();
    auto* w = as_widget(widget);
    if (w == nullptr || callback == nullptr || token_out == nullptr) {
        return fail(ida::Error::validation("widget/callback/token_out is null"));
    }
    auto r = ida::ui::on_widget_closing(*w, [callback, context](ida::ui::Widget matched) {
        ida::ui::Event ev;
        ev.kind = ida::ui::EventKind::WidgetClosing;
        ev.widget = std::move(matched);
        ev.widget_title = ev.widget.title();
        IdaxUIEvent ffi{};
        fill_event(&ffi, ev);
        callback(context, &ffi);
    });
    return set_token(r, token_out);
}

int idax_ui_on_cursor_changed(IdaxUIEventExCallback callback,
                              void* context,
                              uint64_t* token_out) {
    clear_error();
    if (callback == nullptr || token_out == nullptr) {
        return fail(ida::Error::validation("callback/token_out is null"));
    }
    auto r = ida::ui::on_cursor_changed([callback, context](ida::Address ea) {
        ida::ui::Event ev;
        ev.kind = ida::ui::EventKind::CursorChanged;
        ev.address = ea;
        IdaxUIEvent ffi{};
        fill_event(&ffi, ev);
        callback(context, &ffi);
    });
    return set_token(r, token_out);
}

int idax_ui_on_view_activated(IdaxUIEventExCallback callback,
                              void* context,
                              uint64_t* token_out) {
    clear_error();
    if (callback == nullptr || token_out == nullptr) {
        return fail(ida::Error::validation("callback/token_out is null"));
    }
    auto r = ida::ui::on_view_activated([callback, context](ida::ui::Widget view) {
        ida::ui::Event ev;
        ev.kind = ida::ui::EventKind::ViewActivated;
        ev.widget = std::move(view);
        IdaxUIEvent ffi{};
        fill_event(&ffi, ev);
        callback(context, &ffi);
    });
    return set_token(r, token_out);
}

int idax_ui_on_view_deactivated(IdaxUIEventExCallback callback,
                                void* context,
                                uint64_t* token_out) {
    clear_error();
    if (callback == nullptr || token_out == nullptr) {
        return fail(ida::Error::validation("callback/token_out is null"));
    }
    auto r = ida::ui::on_view_deactivated([callback, context](ida::ui::Widget view) {
        ida::ui::Event ev;
        ev.kind = ida::ui::EventKind::ViewDeactivated;
        ev.widget = std::move(view);
        IdaxUIEvent ffi{};
        fill_event(&ffi, ev);
        callback(context, &ffi);
    });
    return set_token(r, token_out);
}

int idax_ui_on_view_created(IdaxUIEventExCallback callback,
                            void* context,
                            uint64_t* token_out) {
    clear_error();
    if (callback == nullptr || token_out == nullptr) {
        return fail(ida::Error::validation("callback/token_out is null"));
    }
    auto r = ida::ui::on_view_created([callback, context](ida::ui::Widget view) {
        ida::ui::Event ev;
        ev.kind = ida::ui::EventKind::ViewCreated;
        ev.widget = std::move(view);
        IdaxUIEvent ffi{};
        fill_event(&ffi, ev);
        callback(context, &ffi);
    });
    return set_token(r, token_out);
}

int idax_ui_on_view_closed(IdaxUIEventExCallback callback,
                           void* context,
                           uint64_t* token_out) {
    clear_error();
    if (callback == nullptr || token_out == nullptr) {
        return fail(ida::Error::validation("callback/token_out is null"));
    }
    auto r = ida::ui::on_view_closed([callback, context](ida::ui::Widget view) {
        ida::ui::Event ev;
        ev.kind = ida::ui::EventKind::ViewClosed;
        ev.widget = std::move(view);
        IdaxUIEvent ffi{};
        fill_event(&ffi, ev);
        callback(context, &ffi);
    });
    return set_token(r, token_out);
}

int idax_ui_on_event(IdaxUIEventExCallback callback,
                     void* context,
                     uint64_t* token_out) {
    clear_error();
    if (callback == nullptr || token_out == nullptr) {
        return fail(ida::Error::validation("callback/token_out is null"));
    }
    auto r = ida::ui::on_event([callback, context](const ida::ui::Event& ev) {
        IdaxUIEvent ffi{};
        fill_event(&ffi, ev);
        callback(context, &ffi);
    });
    return set_token(r, token_out);
}

int idax_ui_on_event_filtered(IdaxUIEventFilterCallback filter,
                              IdaxUIEventExCallback callback,
                              void* context,
                              uint64_t* token_out) {
    clear_error();
    if (filter == nullptr || callback == nullptr || token_out == nullptr) {
        return fail(ida::Error::validation("filter/callback/token_out is null"));
    }
    auto r = ida::ui::on_event_filtered(
        [filter, context](const ida::ui::Event& ev) {
            IdaxUIEvent ffi{};
            fill_event(&ffi, ev);
            return filter(context, &ffi) != 0;
        },
        [callback, context](const ida::ui::Event& ev) {
            IdaxUIEvent ffi{};
            fill_event(&ffi, ev);
            callback(context, &ffi);
        });
    return set_token(r, token_out);
}

int idax_ui_on_popup_ready(IdaxUIPopupCallback callback,
                           void* context,
                           uint64_t* token_out) {
    clear_error();
    if (callback == nullptr || token_out == nullptr) {
        return fail(ida::Error::validation("callback/token_out is null"));
    }
    auto r = ida::ui::on_popup_ready([callback, context](const ida::ui::PopupEvent& event) {
        std::string title = event.widget.title();
        IdaxPopupEvent ffi{};
        ffi.widget = widget_ptr(event.widget);
        ffi.widget_id = event.widget.id();
        ffi.widget_title = title.c_str();
        ffi.popup = event.popup;
        ffi.widget_type = static_cast<int>(event.type);
        callback(context, &ffi);
    });
    return set_token(r, token_out);
}

int idax_ui_attach_dynamic_action(void* popup,
                                  IdaxWidgetHandle widget,
                                  const char* action_id,
                                  const char* label,
                                  IdaxUIActionCallback callback,
                                  void* context,
                                  const char* menu_path,
                                  int icon) {
    clear_error();
    auto* w = as_widget(widget);
    if (w == nullptr) {
        return fail(ida::Error::validation("widget handle is null"));
    }
    if (callback == nullptr) {
        return fail(ida::Error::validation("callback is null"));
    }
    auto status = ida::ui::attach_dynamic_action(
        popup,
        *w,
        action_id != nullptr ? action_id : "",
        label != nullptr ? label : "",
        [callback, context]() { callback(context); },
        menu_path != nullptr ? menu_path : "",
        icon);
    if (!status) {
        return fail(status.error());
    }
    return 0;
}

void idax_ui_rendering_event_add_entry(IdaxRenderingEvent* event,
                                       const IdaxLineRenderEntry* entry) {
    if (event == nullptr || entry == nullptr || event->opaque == nullptr) {
        return;
    }
    auto* entries = static_cast<std::vector<ida::ui::LineRenderEntry>*>(event->opaque);
    ida::ui::LineRenderEntry native{};
    native.line_number = entry->line_number;
    native.bg_color = entry->bg_color;
    native.start_column = entry->start_column;
    native.length = entry->length;
    native.character_range = entry->character_range != 0;
    entries->push_back(native);
}

int idax_ui_on_rendering_info(IdaxUIRenderingCallback callback,
                              void* context,
                              uint64_t* token_out) {
    clear_error();
    if (callback == nullptr || token_out == nullptr) {
        return fail(ida::Error::validation("callback/token_out is null"));
    }
    auto r = ida::ui::on_rendering_info([callback, context](ida::ui::RenderingEvent& ev) {
        IdaxRenderingEvent ffi{};
        ffi.widget = widget_ptr(ev.widget);
        ffi.widget_id = ev.widget.id();
        ffi.widget_type = static_cast<int>(ev.type);
        ffi.opaque = static_cast<void*>(&ev.entries);
        callback(context, &ffi);
    });
    return set_token(r, token_out);
}

int idax_ui_unsubscribe(uint64_t token) {
    RETURN_STATUS(ida::ui::unsubscribe(token));
}

// ═══════════════════════════════════════════════════════════════════════════
// Lines
// ═══════════════════════════════════════════════════════════════════════════

int idax_lines_colstr(const char* text, uint8_t color, char** out) {
    clear_error();
    auto result = ida::lines::colstr(text, static_cast<ida::lines::Color>(color));
    *out = dup_string(result);
    return 0;
}

int idax_lines_tag_remove(const char* tagged_text, char** out) {
    clear_error();
    auto result = ida::lines::tag_remove(tagged_text);
    *out = dup_string(result);
    return 0;
}

int idax_lines_tag_advance(const char* tagged_text, int pos) {
    return ida::lines::tag_advance(tagged_text, pos);
}

size_t idax_lines_tag_strlen(const char* tagged_text) {
    return ida::lines::tag_strlen(tagged_text);
}

int idax_lines_make_addr_tag(int item_index, char** out) {
    clear_error();
    auto result = ida::lines::make_addr_tag(item_index);
    *out = dup_string(result);
    return 0;
}

int idax_lines_decode_addr_tag(const char* tagged_text, size_t pos) {
    return ida::lines::decode_addr_tag(tagged_text, pos);
}

// ═══════════════════════════════════════════════════════════════════════════
// Diagnostics
// ═══════════════════════════════════════════════════════════════════════════

int idax_diagnostics_set_log_level(int level) {
    RETURN_STATUS(ida::diagnostics::set_log_level(
        static_cast<ida::diagnostics::LogLevel>(level)));
}

int idax_diagnostics_log_level(void) {
    return static_cast<int>(ida::diagnostics::log_level());
}

void idax_diagnostics_log(int level, const char* domain, const char* message) {
    ida::diagnostics::log(static_cast<ida::diagnostics::LogLevel>(level),
                          domain, message);
}

void idax_diagnostics_reset_performance_counters(void) {
    ida::diagnostics::reset_performance_counters();
}

int idax_diagnostics_performance_counters(IdaxPerformanceCounters* out) {
    clear_error();
    auto counters = ida::diagnostics::performance_counters();
    out->log_messages       = counters.log_messages;
    out->invariant_failures = counters.invariant_failures;
    return 0;
}

// ═══════════════════════════════════════════════════════════════════════════
// Lumina
// ═══════════════════════════════════════════════════════════════════════════

int idax_lumina_has_connection(int feature, int* out) {
    clear_error();
    auto r = ida::lumina::has_connection(static_cast<ida::lumina::Feature>(feature));
    if (!r) return fail(r.error());
    *out = *r ? 1 : 0;
    return 0;
}

int idax_lumina_close_connection(int feature) {
    RETURN_STATUS(ida::lumina::close_connection(static_cast<ida::lumina::Feature>(feature)));
}

int idax_lumina_close_all_connections(void) {
    RETURN_STATUS(ida::lumina::close_all_connections());
}

int idax_lumina_pull(const uint64_t* addresses, size_t count,
                     int auto_apply, int feature,
                     IdaxLuminaBatchResult* out) {
    clear_error();
    std::span<const ida::Address> addrs(addresses, count);
    auto r = ida::lumina::pull(addrs,
                               auto_apply != 0,
                               false,
                               static_cast<ida::lumina::Feature>(feature));
    if (!r) return fail(r.error());
    out->requested = r->requested;
    out->completed = r->completed;
    out->succeeded = r->succeeded;
    out->failed    = r->failed;
    return 0;
}

int idax_lumina_push(const uint64_t* addresses, size_t count,
                     int push_mode, int feature,
                     IdaxLuminaBatchResult* out) {
    clear_error();
    std::span<const ida::Address> addrs(addresses, count);
    auto r = ida::lumina::push(addrs,
                               static_cast<ida::lumina::PushMode>(push_mode),
                               static_cast<ida::lumina::Feature>(feature));
    if (!r) return fail(r.error());
    out->requested = r->requested;
    out->completed = r->completed;
    out->succeeded = r->succeeded;
    out->failed    = r->failed;
    return 0;
}

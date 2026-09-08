#include "support.hpp"
#include <ida/database.hpp>
#include <ida/navigation.hpp>
#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <mutex>
#include <memory>
#include <thread>
#include <vector>
#if defined(__APPLE__)
#include <pthread.h>
#elif defined(__linux__)
#include <sys/syscall.h>
#include <unistd.h>
#endif

namespace {
struct DeferredRelease { void (*release)(void*); void* context; };
struct OwnedResource {
    void* value;
    void (*destroy)(void*);
    bool database_bound;
    size_t pins{0};
    bool pending_release{false};
};
struct RuntimeState {
    std::mutex mutex;
    bool initialized{false};
    bool initializing{false};
    std::thread::id owner;
    std::vector<DeferredRelease> deferred;
    // These fields are accessed only on the initialized runtime thread.
    std::vector<OwnedResource*> resources;
    bool database_open{false};
    bool database_changing{false};
    bool hosted{false};
    size_t borrowed_activity{0};
};
RuntimeState& runtime() {
    // The IDA runtime has process lifetime. Never destroy retained native
    // cleanup state from a static destructor after the host has shut down.
    static auto* state = new RuntimeState;
    return *state;
}
char* copy_text(const char* value) noexcept {
    if (value == nullptr) value = "";
    const auto size = std::strlen(value);
    auto* result = static_cast<char*>(std::malloc(size + 1));
    if (result != nullptr) std::memcpy(result, value, size + 1);
    return result;
}
bool runtime_idle() {
    if (runtime().borrowed_activity != 0) return false;
    for (const auto* resource : runtime().resources)
        if (resource->pins != 0) return false;
    return true;
}
void drain_releases() {
    thread_local bool draining = false;
    if (draining || !runtime_idle()) return;
    draining = true;
    struct Reset { bool& value; ~Reset() { value = false; } } reset{draining};
    std::vector<DeferredRelease> pending;
    {
        std::lock_guard lock(runtime().mutex);
        pending.swap(runtime().deferred);
    }
    for (const auto& entry : pending) {
        try { entry.release(entry.context); } catch (...) {}
    }
}
void close_resource(OwnedResource* resource) {
    void* value = std::exchange(resource->value, nullptr);
    if (value != nullptr) resource->destroy(value);
}
void destroy_resource(void* raw) {
    auto* resource = static_cast<OwnedResource*>(raw);
    if (resource->pins != 0) { resource->pending_release = true; return; }
    std::erase(runtime().resources, resource);
    std::unique_ptr<OwnedResource> owner(resource);
    // A native destructor can release its Swift owner reentrantly. Keep the
    // holder borrowed until this unique owner completes its one destruction.
    ++resource->pins;
    close_resource(resource);
}
void invalidate_database_resources() {
    // Re-evaluate the registry after each destructor: a destructor may release
    // another holder. No iterators, locks, or borrowed holders survive it.
    while (true) {
        auto& resources = runtime().resources;
        auto found = std::find_if(resources.rbegin(), resources.rend(), [](const auto* resource) {
            return resource->database_bound && resource->value != nullptr;
        });
        if (found == resources.rend()) break;
        close_resource(*found);
    }
}
int can_change_database(IdaxSwiftError* error) {
    if (runtime().borrowed_activity != 0)
        return idax::swift::write_error(ida::Error::conflict("A native callback currently borrows the database"), error);
    for (const auto* resource : runtime().resources) {
        if (resource->database_bound && resource->pins != 0)
            return idax::swift::write_error(ida::Error::conflict("A native operation currently borrows a database resource"), error);
    }
    return 0;
}
bool is_process_main_thread() {
#if defined(__APPLE__)
    return pthread_main_np() != 0;
#elif defined(__linux__)
    return syscall(SYS_gettid) == getpid();
#else
    return false;
#endif
}
}

void idax_swift_error_free(IdaxSwiftError* error) {
    if (error == nullptr) return;
    std::free(error->message);
    std::free(error->context);
    *error = {};
}

void idax_swift_error_set(IdaxSwiftError* error, int category, int code,
                          const char* message, const char* context) {
    if (error == nullptr) return;
    // Copy first so callers may replace an existing error using its own text.
    char* copied_message = copy_text(message);
    char* copied_context = copy_text(context);
    idax_swift_error_free(error);
    error->category = category;
    error->code = code;
    error->message = copied_message;
    error->context = copied_context;
    if (copied_message == nullptr || copied_context == nullptr) {
        idax_swift_error_free(error);
        error->category = 6;
    }
}

namespace idax::swift {
void clear_error(IdaxSwiftError* error) noexcept {
    idax_swift_error_free(error);
}
int write_error(const ida::Error& error, IdaxSwiftError* output) noexcept {
    int category = 6;
    switch (error.category) {
    case ida::ErrorCategory::Validation: category = 1; break;
    case ida::ErrorCategory::NotFound: category = 2; break;
    case ida::ErrorCategory::Conflict: category = 3; break;
    case ida::ErrorCategory::Unsupported: category = 4; break;
    case ida::ErrorCategory::SdkFailure: category = 5; break;
    case ida::ErrorCategory::Internal: category = 6; break;
    }
    idax_swift_error_set(output, category, error.code, error.message.c_str(), error.context.c_str());
    return -1;
}
int require_runtime_thread(IdaxSwiftError* error) noexcept {
    return protect(error, [&] {
        {
            std::lock_guard lock(runtime().mutex);
            if (!runtime().initialized)
                return write_error(ida::Error::conflict("IDA runtime is not initialized"), error);
            if (runtime().owner != std::this_thread::get_id())
                return write_error(ida::Error::conflict("IDA operation requires the initializing thread"), error);
        }
        drain_releases();
        return 0;
    });
}
}

int idax_swift_require_runtime_thread(IdaxSwiftError* error) {
    return idax::swift::require_runtime_thread(error);
}
int idax_swift_runtime_require_idle(IdaxSwiftError* error) {
    return idax::swift::protect(error, [&] {
        if (!idax_swift_is_runtime_thread())
            return idax::swift::write_error(ida::Error::conflict("IDA operation requires the initialized runtime thread"), error);
        if (!runtime_idle())
            return idax::swift::write_error(ida::Error::conflict("A native operation or callback is active"), error);
        return 0;
    });
}
int idax_swift_runtime_is_initialized(void) {
    std::lock_guard lock(runtime().mutex);
    return runtime().initialized ? 1 : 0;
}
int idax_swift_is_runtime_thread(void) {
    std::lock_guard lock(runtime().mutex);
    return runtime().initialized && runtime().owner == std::this_thread::get_id();
}
void idax_swift_defer_release(void (*release)(void*), void* context) {
    if (release == nullptr || context == nullptr) return;
    if (idax_swift_is_runtime_thread() && runtime_idle()) {
        try { release(context); } catch (...) {}
        return;
    }
    idax_swift_enqueue_release(release, context);
}
void idax_swift_enqueue_release(void (*release)(void*), void* context) {
    if (release == nullptr || context == nullptr) return;
    try {
        std::lock_guard lock(runtime().mutex);
        runtime().deferred.push_back({release, context});
    } catch (...) {
        // A finalizer cannot throw across the C ABI. Retain the native object
        // if queuing allocation fails; destroying it on this thread is invalid.
    }
}

int idax_swift_runtime_initialize(const IdaxSwiftRuntimeOptions* options,
                                   IdaxSwiftError* error) {
    return idax::swift::protect(error, [&] {
        if (!is_process_main_thread())
            return idax::swift::write_error(ida::Error::conflict("IDA initialization requires the process main thread"), error);
        if (options == nullptr)
            return idax::swift::write_error(ida::Error::validation("Runtime options are null"), error);
        if (options->allowlist_pattern_count != 0 && options->allowlist_patterns == nullptr)
            return idax::swift::write_error(ida::Error::validation("Plugin allowlist is null"), error);
        if (options->allowlist_pattern_count > static_cast<size_t>(std::numeric_limits<int>::max()))
            return idax::swift::write_error(ida::Error::validation("Plugin allowlist is too large"), error);
        if ((options->argument_count != 0 && options->arguments == nullptr)
            || options->argument_count > static_cast<size_t>(std::numeric_limits<int>::max()))
            return idax::swift::write_error(ida::Error::validation("Runtime argument array is invalid"), error);
        std::vector<std::string> arguments;
        arguments.reserve(options->argument_count);
        for (size_t i = 0; i < options->argument_count; ++i) {
            if (!options->arguments[i])
                return idax::swift::write_error(ida::Error::validation("Runtime argument is null"), error);
            arguments.emplace_back(options->arguments[i]);
        }
        std::vector<char*> argv;
        argv.reserve(arguments.size() + 1);
        for (auto& argument : arguments) argv.push_back(argument.data());
        argv.push_back(nullptr);
        ida::database::RuntimeOptions native;
        native.quiet = options->quiet != 0;
        native.plugin_policy.disable_user_plugins = options->disable_user_plugins != 0;
        for (size_t i = 0; i < options->allowlist_pattern_count; ++i) {
            if (options->allowlist_patterns[i] == nullptr)
                return idax::swift::write_error(ida::Error::validation("Plugin allowlist entry is null"), error);
            native.plugin_policy.allowlist_patterns.emplace_back(options->allowlist_patterns[i]);
        }
        {
            std::lock_guard lock(runtime().mutex);
            if (runtime().initialized || runtime().initializing)
                return idax::swift::write_error(ida::Error::conflict("IDA runtime has already been initialized"), error);
            runtime().initializing = true;
        }
        struct Reset {
            ~Reset() { std::lock_guard lock(runtime().mutex); runtime().initializing = false; }
        } reset;
        auto status = ida::database::init(static_cast<int>(arguments.size()), arguments.empty() ? nullptr : argv.data(), native);
        if (!status) return idax::swift::write_error(status.error(), error);
        {
            std::lock_guard lock(runtime().mutex);
            runtime().owner = std::this_thread::get_id();
            runtime().initialized = true;
        }
        drain_releases();
        return 0;
    });
}

int idax_swift_runtime_attach_host(IdaxSwiftError* error) {
    return idax::swift::protect(error, [&] {
        if (!is_process_main_thread())
            return idax::swift::write_error(ida::Error::conflict("IDA host attachment requires the process main thread"), error);
        {
            std::lock_guard lock(runtime().mutex);
            if (runtime().initializing)
                return idax::swift::write_error(ida::Error::conflict("IDA initialization is in progress"), error);
            if (runtime().initialized) {
                if (runtime().owner != std::this_thread::get_id())
                    return idax::swift::write_error(ida::Error::conflict("IDA host attachment requires the existing runtime thread"), error);
            } else {
                runtime().owner = std::this_thread::get_id();
                runtime().initialized = true;
                runtime().hosted = true;
            }
        }
        drain_releases();
        return 0;
    });
}
int idax_swift_runtime_host_database_closing(IdaxSwiftError* error) {
    return idax::swift::protect(error, [&] {
        if (idax::swift::require_runtime_thread(error) != 0) return -1;
        if (can_change_database(error) != 0) return -1;
        const bool previous = std::exchange(runtime().database_changing, true);
        struct Reset { bool previous; ~Reset() { runtime().database_changing = previous; } } reset{previous};
        invalidate_database_resources();
        return 0;
    });
}

int idax_swift_resource_adopt(void* value, void (*destroy)(void*), int database_bound,
                              void** output, IdaxSwiftError* error) {
    struct Pending {
        void* value; void (*destroy)(void*);
        ~Pending() { idax_swift_defer_release(destroy, value); }
    } pending{value, destroy};
    if (output != nullptr) *output = nullptr;
    return idax::swift::protect(error, [&] {
        if (value == nullptr || destroy == nullptr || output == nullptr)
            return idax::swift::write_error(ida::Error::validation("Invalid native resource adoption"), error);
        if (idax::swift::require_runtime_thread(error) != 0) return -1;
        if (runtime().database_changing)
            return idax::swift::write_error(ida::Error::conflict("Database lifecycle transition is in progress"), error);
        auto holder = std::make_unique<OwnedResource>(OwnedResource{value, destroy, database_bound != 0});
        runtime().resources.push_back(holder.get());
        *output = holder.release();
        pending.value = nullptr;
        return 0;
    });
}
int idax_swift_resource_get(void* raw, void** value, IdaxSwiftError* error) {
    if (value != nullptr) *value = nullptr;
    return idax::swift::protect(error, [&] {
        if (raw == nullptr || value == nullptr)
            return idax::swift::write_error(ida::Error::validation("Native resource holder is null"), error);
        if (idax::swift::require_runtime_thread(error) != 0) return -1;
        auto* holder = static_cast<OwnedResource*>(raw);
        if (holder->value == nullptr)
            return idax::swift::write_error(ida::Error::conflict("Native resource is closed or belongs to an ended database session"), error);
        *value = holder->value;
        return 0;
    });
}
int idax_swift_resource_is_open(void* raw, int* open, IdaxSwiftError* error) {
    if (open != nullptr) *open = 0;
    return idax::swift::protect(error, [&] {
        if (idax::swift::require_runtime_thread(error) != 0) return -1;
        if (raw == nullptr || open == nullptr)
            return idax::swift::write_error(ida::Error::validation("Invalid native resource state query"), error);
        *open = static_cast<OwnedResource*>(raw)->value != nullptr;
        return 0;
    });
}
int idax_swift_resource_close(void* raw, IdaxSwiftError* error) {
    return idax_swift_resource_close_with(raw, nullptr, error);
}
int idax_swift_resource_close_with(void* raw, int (*close)(void*, IdaxSwiftError*), IdaxSwiftError* error) {
    return idax::swift::protect(error, [&] {
        if (idax::swift::require_runtime_thread(error) != 0) return -1;
        if (raw != nullptr) {
            auto* resource = static_cast<OwnedResource*>(raw);
            if (resource->pins != 0)
                return idax::swift::write_error(ida::Error::conflict("Native resource is borrowed by an active operation"), error);
            ++resource->pins;
            int result = 0;
            try {
                if (resource->value != nullptr && close != nullptr) result = close(resource->value, error);
                if (result == 0) close_resource(resource);
            } catch (...) {
                --resource->pins;
                if (resource->pending_release) destroy_resource(resource);
                throw;
            }
            --resource->pins;
            if (resource->pending_release) destroy_resource(resource);
            if (result != 0) return -1;
        }
        return 0;
    });
}
int idax_swift_resource_pin(void* raw, void** value, IdaxSwiftError* error) {
    if (value) *value = nullptr;
    return idax::swift::protect(error, [&] {
        if (idax_swift_resource_get(raw, value, error) != 0) return -1;
        auto* resource = static_cast<OwnedResource*>(raw);
        if (resource->pins == std::numeric_limits<size_t>::max()) {
            *value = nullptr;
            return idax::swift::write_error(ida::Error::conflict("Native resource borrow count is exhausted"), error);
        }
        ++resource->pins;
        return 0;
    });
}
void idax_swift_resource_unpin(void* raw) {
    if (raw == nullptr || !idax_swift_is_runtime_thread()) return;
    auto* resource = static_cast<OwnedResource*>(raw);
    if (resource->pins == 0) return;
    --resource->pins;
    if (resource->pins == 0 && resource->pending_release) {
        try { destroy_resource(resource); } catch (...) {}
    }
    // The caller unpins after the entire native operation returns. Callback
    // scopes also hold an activity guard, so their local unpin cannot drain.
    drain_releases();
}
int idax_swift_runtime_begin_activity(IdaxSwiftError* error) {
    return idax::swift::protect(error, [&] {
        if (idax::swift::require_runtime_thread(error) != 0) return -1;
        if (runtime().borrowed_activity == std::numeric_limits<size_t>::max())
            return idax::swift::write_error(ida::Error::conflict("Native callback borrow count is exhausted"), error);
        ++runtime().borrowed_activity;
        return 0;
    });
}
void idax_swift_runtime_end_activity(void) {
    if (!idax_swift_is_runtime_thread()) return;
    if (runtime().borrowed_activity != 0) --runtime().borrowed_activity;
}
void idax_swift_resource_release(void* holder) {
    idax_swift_defer_release(destroy_resource, holder);
}
int idax_swift_database_open(const char* path, int auto_analysis, int load_intent,
                              IdaxSwiftError* error) {
    return idax::swift::protect(error, [&] {
        if (idax::swift::require_runtime_thread(error) != 0) return -1;
        if (runtime().hosted)
            return idax::swift::write_error(ida::Error::unsupported("The IDA host owns database open/close lifecycle"), error);
        if (path == nullptr || path[0] == '\0' || load_intent < 0 || load_intent > 2)
            return idax::swift::write_error(ida::Error::validation("Invalid database open arguments"), error);
        if (runtime().database_open || runtime().database_changing)
            return idax::swift::write_error(ida::Error::conflict("Close the current database before opening another"), error);
        if (can_change_database(error) != 0) return -1;
        runtime().database_changing = true;
        struct Reset { ~Reset() { runtime().database_changing = false; } } reset;
        invalidate_database_resources();
        auto result = ida::database::open(path, static_cast<ida::database::LoadIntent>(load_intent),
            auto_analysis ? ida::database::OpenMode::Analyze : ida::database::OpenMode::SkipAnalysis);
        if (!result) return idax::swift::write_error(result.error(), error);
        runtime().database_open = true;
        return 0;
    });
}
int idax_swift_database_close(int save, IdaxSwiftError* error) {
    return idax::swift::protect(error, [&] {
        if (idax::swift::require_runtime_thread(error) != 0) return -1;
        if (runtime().hosted)
            return idax::swift::write_error(ida::Error::unsupported("The IDA host owns database open/close lifecycle"), error);
        if (runtime().database_changing)
            return idax::swift::write_error(ida::Error::conflict("Database lifecycle transition is in progress"), error);
        if (can_change_database(error) != 0) return -1;
        runtime().database_changing = true;
        struct Reset { ~Reset() { runtime().database_changing = false; } } reset;
        invalidate_database_resources();
        if (!runtime().database_open) return 0;
        auto result = ida::database::close(save != 0);
        if (!result) return idax::swift::write_error(result.error(), error);
        runtime().database_open = false;
        return 0;
    });
}

int idax_swift_navigation_clone(void* history, void** output, IdaxSwiftError* error) {
    if (output != nullptr) *output = nullptr;
    return idax::swift::protect(error, [&] {
        if (history == nullptr || output == nullptr)
            return idax::swift::write_error(ida::Error::validation("History clone input or output is null"), error);
        if (idax::swift::require_runtime_thread(error) != 0) return -1;
        *output = new ida::navigation::History(*static_cast<ida::navigation::History*>(history));
        return 0;
    });
}

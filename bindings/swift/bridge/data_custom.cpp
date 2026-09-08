#include "data_custom.h"
#include "support.hpp"
#include <ida/data.hpp>
#include <ida/ui.hpp>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <unordered_map>
#include <vector>

namespace {
using idax::swift::protect;
using idax::swift::require_runtime_thread;
using idax::swift::write_error;
int status(ida::Status result, IdaxSwiftError* error) { return result ? 0 : write_error(result.error(), error); }
struct CallbackDiagnostic;
thread_local CallbackDiagnostic* current_diagnostic = nullptr;
// The SDK callback ABI reduces an Error to bool/text. A bridge-initiated
// dispatch keeps the original diagnostic in its lexical scope; nested calls
// restore their caller's scope and cannot overwrite it.
struct CallbackDiagnostic {
    CallbackDiagnostic* previous{current_diagnostic};
    std::optional<ida::Error> error;
    CallbackDiagnostic() { current_diagnostic = this; }
    ~CallbackDiagnostic() { current_diagnostic = previous; }
};
ida::Status callback_failure(ida::Error error) {
    if (current_diagnostic && !current_diagnostic->error)
        current_diagnostic->error = error;
    return std::unexpected(std::move(error));
}
ida::Error callback_error(const IdaxSwiftError& error) {
    const auto category = error.category >= 1 && error.category <= 6
        ? static_cast<ida::ErrorCategory>(error.category - 1) : ida::ErrorCategory::Internal;
    return {category, error.code, error.message ? error.message : "Missing Swift custom-data diagnostic", error.context ? error.context : ""};
}
struct Reply {
    IdaxSwiftCustomReply value{};
    IdaxSwiftError error{};
    ~Reply() { std::free(value.bytes); idax_swift_error_free(&error); }
};
struct Callbacks {
    IdaxSwiftCustomCallbacks value;
    explicit Callbacks(IdaxSwiftCustomCallbacks value) : value(value) {}
    Callbacks(Callbacks&& other) noexcept : value(std::exchange(other.value, {})) {}
    Callbacks(const Callbacks&) = delete;
    ~Callbacks() { if (value.destroy) value.destroy(value.context); }
    ida::Status invoke(const IdaxSwiftCustomRequest& request, Reply& reply) const {
        if (idax_swift_runtime_begin_activity(&reply.error) != 0)
            return callback_failure(callback_error(reply.error));
        struct Activity { ~Activity() { idax_swift_runtime_end_activity(); } } activity;
        if (value.invoke == nullptr)
            return callback_failure(ida::Error::validation("Missing Swift custom-data callback"));
        if (value.invoke(value.context, &request, &reply.value, &reply.error) != 0)
            return callback_failure(callback_error(reply.error));
        if (reply.value.count != 0 && reply.value.bytes == nullptr)
            return callback_failure(ida::Error::internal("Swift callback returned null bytes with a nonzero size"));
        return ida::ok();
    }
};
void report(const ida::Error& error) {
    (void)ida::ui::message("IDAX Swift custom-data callback: " + error.message + " [" + error.context + "]\n");
}
// All access, including deferred ARC release, runs on the checked runtime
// thread. Tokens carry a monotonically increasing generation and the private
// SDK slot; slot reuse cannot make a stale Swift identity address a successor.
struct Identity {
    uint16_t id;
    bool format;
    uint64_t token;
    std::string name;
    bool active{true};
};
std::unordered_map<uint32_t, std::shared_ptr<Identity>> identities;
uint64_t next_generation = 0;
uint32_t key(bool format, uint16_t id) { return uint32_t(id) | (format ? 0x10000u : 0u); }
std::shared_ptr<Identity> publish(bool format, uint16_t id, std::string name, bool fresh = false) {
    auto found = identities.find(key(format, id));
    if (found != identities.end() && !fresh && found->second->active && found->second->name == name)
        return found->second;
    if (next_generation == (UINT64_MAX >> 16))
        throw ida::Error::internal("Custom-data identity generation is exhausted");
    auto value = std::make_shared<Identity>(Identity{id, format, (++next_generation << 16) | id, std::move(name)});
    if (found != identities.end()) found->second->active = false;
    identities[key(format, id)] = value;
    return value;
}
void retire(std::shared_ptr<Identity> value) {
    value->active = false;
    auto found = identities.find(key(value->format, value->id));
    if (found != identities.end() && found->second == value) identities.erase(found);
}
uint64_t export_id(bool format, uint16_t id) {
    if (!format && id == 0) return 0; // Standard data types have no registration.
    if (format) {
        auto value = ida::data::custom_data_format({id});
        if (!value) throw value.error();
        return publish(true, id, value->name)->token;
    }
    auto value = ida::data::custom_data_type({id});
    if (!value) throw value.error();
    return publish(false, id, value->name)->token;
}
uint16_t resolve(bool format, uint64_t token) {
    if (!format && token == 0) return 0;
    const auto id = static_cast<uint16_t>(token);
    auto found = identities.find(key(format, id));
    if (found == identities.end() || !found->second->active || found->second->token != token)
        throw ida::Error::conflict("Custom-data identity is no longer registered");
    auto state = found->second;
    // Detect deletion or reuse under another name outside the Swift bridge.
    bool current = false;
    if (format) {
        auto value = ida::data::custom_data_format({id});
        current = value && value->name == state->name;
    } else {
        auto value = ida::data::custom_data_type({id});
        current = value && value->name == state->name;
    }
    if (!current) {
        retire(state);
        throw ida::Error::conflict("Custom-data identity is no longer registered", state->name);
    }
    return id;
}
ida::Status unregister(std::shared_ptr<Identity> state) {
    // Retire aliases and their owner before canonical teardown can invoke any
    // callbacks. Canonical teardown releases callable state even on failure.
    retire(state);
    return state->format ? ida::data::unregister_custom_data_format({state->id})
                         : ida::data::unregister_custom_data_type({state->id});
}
struct Registration {
    std::shared_ptr<Identity> state;
    ida::Status close() {
        if (!state->active) return ida::ok();
        try { (void)resolve(state->format, state->token); }
        catch (const ida::Error&) { return ida::ok(); }
        return unregister(state);
    }
    ~Registration() { (void)close(); }
};
ida::data::CustomDataFormatContext context(const IdaxSwiftCustomContext* input) {
    if (input == nullptr) throw ida::Error::validation("Custom-data context is null");
    return {input->address, input->operand_index, {resolve(false, input->type_id)}};
}
IdaxSwiftCustomRequest request(int kind, const ida::data::CustomDataFormatContext& input) {
    IdaxSwiftCustomRequest value{};
    value.kind = kind;
    value.context = {input.address, input.operand_index, export_id(false, input.type_id.value)};
    return value;
}
const char* text(const char* value) { return value == nullptr ? "" : value; }
char* copy(const std::string& value) {
    auto* output = static_cast<char*>(std::malloc(value.size() + 1));
    if (output == nullptr) throw std::bad_alloc();
    std::memcpy(output, value.c_str(), value.size() + 1);
    return output;
}
void fill(const ida::data::CustomDataTypeInfo& value, IdaxSwiftCustomInfo& output) {
    output.id = publish(false, value.id.value, value.name)->token;
    output.name = copy(value.name);
    output.menu_name = copy(value.menu_name);
    output.hotkey = copy(value.hotkey);
    output.assembler_keyword = copy(value.assembler_keyword);
    output.value_size = value.value_size;
    output.flags = (value.allow_duplicates ? 1 : 0) | (value.visible_in_menu ? 2 : 0)
                 | (value.has_creation_filter ? 4 : 0) | (value.variable_size ? 8 : 0);
}
void fill(const ida::data::CustomDataFormatInfo& value, IdaxSwiftCustomInfo& output) {
    output.id = publish(true, value.id.value, value.name)->token;
    output.name = copy(value.name);
    output.menu_name = copy(value.menu_name);
    output.hotkey = copy(value.hotkey);
    output.value_size = value.value_size;
    output.text_width = value.text_width;
    output.flags = (value.visible_in_menu ? 2 : 0) | (value.can_render ? 16 : 0)
                 | (value.can_scan ? 32 : 0) | (value.can_analyze ? 64 : 0);
}
template <typename Value>
int list(ida::Result<std::vector<Value>> result, IdaxSwiftCustomInfo** output, size_t* count, IdaxSwiftError* error) {
    if (!result) return write_error(result.error(), error);
    if (result->empty()) return 0;
    if (result->size() > SIZE_MAX / sizeof(IdaxSwiftCustomInfo))
        return write_error(ida::Error::internal("Custom-data metadata array is too large"), error);
    auto* values = static_cast<IdaxSwiftCustomInfo*>(std::calloc(result->size(), sizeof(IdaxSwiftCustomInfo)));
    if (values == nullptr) throw std::bad_alloc();
    try {
        for (size_t i = 0; i < result->size(); ++i) fill((*result)[i], values[i]);
    } catch (...) { idax_swift_custom_infos_free(values, result->size()); throw; }
    *output = values;
    *count = result->size();
    return 0;
}
int output_bytes(std::span<const uint8_t> bytes, uint8_t** output, size_t* count) {
    if (!bytes.empty()) {
        auto* value = static_cast<uint8_t*>(std::malloc(bytes.size()));
        if (value == nullptr) throw std::bad_alloc();
        std::memcpy(value, bytes.data(), bytes.size());
        *output = value;
    }
    *count = bytes.size();
    return 0;
}
}

int idax_swift_custom_register(int format, const IdaxSwiftCustomDefinition* input,
    IdaxSwiftCustomCallbacks callbacks, void** output, uint64_t* id, IdaxSwiftError* error) {
    Callbacks pending(callbacks);
    if (output) *output = nullptr;
    if (id) *id = 0;
    return protect(error, [&] {
        if (!input || !output || !id || (format != 0 && format != 1))
            return write_error(ida::Error::validation("Invalid custom-data registration arguments"), error);
        if (require_runtime_thread(error)) return -1;
        auto owner = std::make_shared<Callbacks>(std::move(pending));
        uint16_t identity = 0;
        if (format) {
            ida::data::CustomDataFormatDefinition definition;
            definition.name = text(input->name); definition.menu_name = text(input->menu_name);
            definition.hotkey = text(input->hotkey); definition.value_size = input->value_size; definition.text_width = input->text_width;
            if (input->callback_flags & 4) definition.render = [owner](std::span<const uint8_t> bytes, const auto& ctx) -> ida::Result<std::string> {
                auto value = request(2, ctx); value.bytes = bytes.data(); value.count = bytes.size();
                Reply reply; auto result = owner->invoke(value, reply);
                if (!result) return std::unexpected(result.error());
                if (reply.value.count == 0) return std::string{};
                return std::string(reinterpret_cast<const char*>(reply.value.bytes), reply.value.count);
            };
            if (input->callback_flags & 8) definition.scan = [owner](std::string_view bytes, const auto& ctx) -> ida::Result<std::vector<uint8_t>> {
                auto value = request(3, ctx); value.bytes = reinterpret_cast<const uint8_t*>(bytes.data()); value.count = bytes.size();
                Reply reply; auto result = owner->invoke(value, reply);
                if (!result) return std::unexpected(result.error());
                if (reply.value.count == 0) return std::vector<uint8_t>{};
                return std::vector<uint8_t>(reply.value.bytes, reply.value.bytes + reply.value.count);
            };
            if (input->callback_flags & 16) definition.analyze = [owner](const auto& ctx) {
                Reply reply; auto result = owner->invoke(request(4, ctx), reply); if (!result) report(result.error());
            };
            auto result = ida::data::register_custom_data_format(definition);
            if (!result) return write_error(result.error(), error);
            identity = result->value;
        } else {
            ida::data::CustomDataTypeDefinition definition;
            definition.name = text(input->name); definition.menu_name = text(input->menu_name); definition.hotkey = text(input->hotkey);
            definition.assembler_keyword = text(input->assembler_keyword); definition.value_size = input->value_size;
            definition.allow_duplicates = input->allow_duplicates != 0;
            if (input->callback_flags & 1) definition.may_create_at = [owner](uint64_t address, uint64_t size) {
                auto value = request(0, {address, -1, {0}}); value.size = size;
                Reply reply; auto result = owner->invoke(value, reply); if (!result) { report(result.error()); return false; }
                return reply.value.value != 0;
            };
            if (input->callback_flags & 2) definition.calculate_size = [owner](uint64_t address, uint64_t size) -> uint64_t {
                auto value = request(1, {address, -1, {0}}); value.size = size;
                Reply reply; auto result = owner->invoke(value, reply); if (!result) { report(result.error()); return 0; }
                return reply.value.value;
            };
            auto result = ida::data::register_custom_data_type(definition);
            if (!result) return write_error(result.error(), error);
            identity = result->value;
        }
        std::shared_ptr<Identity> state;
        try {
            state = publish(format != 0, identity, text(input->name), true);
            *output = new Registration{state};
        } catch (...) {
            if (state) retire(state);
            if (format) (void)ida::data::unregister_custom_data_format({identity});
            else (void)ida::data::unregister_custom_data_type({identity});
            throw;
        }
        *id = state->token;
        return 0;
    });
}
int idax_swift_custom_registration_close(void* value, IdaxSwiftError* error) {
    return protect(error, [&] { if (require_runtime_thread(error)) return -1; return value ? status(static_cast<Registration*>(value)->close(), error) : 0; });
}
void idax_swift_custom_registration_free(void* value) { delete static_cast<Registration*>(value); }
int idax_swift_custom_reply_bytes(IdaxSwiftCustomReply* reply, const uint8_t* bytes, size_t count, IdaxSwiftError* error) {
    return protect(error, [&] {
        if (!reply || (count && !bytes)) return write_error(ida::Error::validation("Invalid custom-data reply bytes"), error);
        uint8_t* replacement = nullptr; size_t copied = 0;
        output_bytes({bytes, count}, &replacement, &copied);
        std::free(reply->bytes); reply->bytes = replacement; reply->count = copied;
        return 0;
    });
}
int idax_swift_custom_unregister(int format, uint64_t token, IdaxSwiftError* error) {
    return protect(error, [&] {
        if (require_runtime_thread(error)) return -1;
        if (format != 0 && format != 1)
            return write_error(ida::Error::validation("Invalid custom-data identity kind"), error);
        const auto id = resolve(format != 0, token);
        if (id == 0)
            return write_error(ida::Error::validation("Standard data types cannot be unregistered"), error);
        return status(unregister(identities.at(key(format != 0, id))), error);
    });
}
int idax_swift_custom_find(int format, const char* name, uint64_t* output, IdaxSwiftError* error) {
    if (output) *output = 0;
    return protect(error, [&] {
        if (!name || !output) return write_error(ida::Error::validation("Custom-data name or output is null"), error);
        if (require_runtime_thread(error)) return -1;
        if (format) { auto result = ida::data::find_custom_data_format(name); if (!result) return write_error(result.error(), error); *output = export_id(format != 0, result->value); }
        else { auto result = ida::data::find_custom_data_type(name); if (!result) return write_error(result.error(), error); *output = export_id(format != 0, result->value); }
        return 0;
    });
}
void idax_swift_custom_info_free(IdaxSwiftCustomInfo* value) {
    if (!value) return;
    std::free(value->name); std::free(value->menu_name); std::free(value->hotkey); std::free(value->assembler_keyword); *value = {};
}
void idax_swift_custom_infos_free(IdaxSwiftCustomInfo* values, size_t count) {
    if (!values) return;
    for (size_t i = 0; i < count; ++i) idax_swift_custom_info_free(&values[i]);
    std::free(values);
}
int idax_swift_custom_info(int format, uint64_t token, IdaxSwiftCustomInfo* output, IdaxSwiftError* error) {
    if (output) *output = {};
    return protect(error, [&] {
        if (!output) return write_error(ida::Error::validation("Custom-data metadata output is null"), error);
        if (require_runtime_thread(error)) return -1;
        const auto id = resolve(format != 0, token);
        try {
            if (format) { auto result = ida::data::custom_data_format({id}); if (!result) return write_error(result.error(), error); fill(*result, *output); }
            else { auto result = ida::data::custom_data_type({id}); if (!result) return write_error(result.error(), error); fill(*result, *output); }
        } catch (...) { idax_swift_custom_info_free(output); throw; }
        return 0;
    });
}
int idax_swift_custom_list(int selector, uint64_t type_token, uint64_t minimum, uint64_t maximum,
    IdaxSwiftCustomInfo** output, size_t* count, IdaxSwiftError* error) {
    if (output) *output = nullptr;
    if (count) *count = 0;
    return protect(error, [&] {
        if (!output || !count) return write_error(ida::Error::validation("Custom-data metadata outputs are null"), error);
        if (require_runtime_thread(error)) return -1;
        if (selector == 0) return list(ida::data::custom_data_types(minimum, maximum), output, count, error);
        if (selector == 1) return list(ida::data::custom_data_formats({resolve(false, type_token)}), output, count, error);
        if (selector == 2) return list(ida::data::standard_custom_data_formats(), output, count, error);
        return write_error(ida::Error::validation("Invalid custom-data list selector"), error);
    });
}
int idax_swift_custom_relation(int operation, uint64_t type_token, uint64_t format_token, int* output, IdaxSwiftError* error) {
    if (output) *output = 0;
    return protect(error, [&] {
        if (!output) return write_error(ida::Error::validation("Custom-data relationship output is null"), error);
        if (require_runtime_thread(error)) return -1;
        const auto type = resolve(false, type_token);
        const auto format = resolve(true, format_token);
        switch (operation) {
        case 0: return status(ida::data::attach_custom_data_format({type}, {format}), error);
        case 1: return status(ida::data::detach_custom_data_format({type}, {format}), error);
        case 3: return status(ida::data::attach_custom_data_format_to_standard_types({format}), error);
        case 4: return status(ida::data::detach_custom_data_format_from_standard_types({format}), error);
        case 2: case 5: {
            auto result = operation == 2 ? ida::data::is_custom_data_format_attached({type}, {format}) : ida::data::is_custom_data_format_attached_to_standard_types({format});
            if (!result) return write_error(result.error(), error); *output = *result ? 1 : 0; return 0;
        }
        default: return write_error(ida::Error::validation("Invalid custom-data relationship operation"), error);
        }
    });
}
int idax_swift_custom_item_size(uint64_t type_token, uint64_t address, uint64_t maximum, uint64_t* output, IdaxSwiftError* error) {
    if (output) *output = 0;
    return protect(error, [&] {
        if (!output) return write_error(ida::Error::validation("Custom-data size output is null"), error);
        if (require_runtime_thread(error)) return -1;
        CallbackDiagnostic diagnostic;
        auto result = ida::data::custom_data_item_size({resolve(false, type_token)}, address, maximum);
        if (diagnostic.error) return write_error(*diagnostic.error, error);
        if (!result) return write_error(result.error(), error); *output = *result; return 0;
    });
}
int idax_swift_custom_define(int inferred, uint64_t address, uint64_t size, uint64_t type_token, uint64_t format_token, IdaxSwiftError* error) {
    return protect(error, [&] { if (require_runtime_thread(error)) return -1;
        CallbackDiagnostic diagnostic;
        const auto type = resolve(false, type_token);
        const auto format = resolve(true, format_token);
        auto result = inferred ? ida::data::define_custom_inferred(address, {type}, {format}, size) : ida::data::define_custom(address, size, {type}, {format});
        if (diagnostic.error) return write_error(*diagnostic.error, error);
        return status(std::move(result), error); });
}
int idax_swift_custom_at(uint64_t address, uint64_t* type, uint64_t* format, uint64_t* byte_length, IdaxSwiftError* error) {
    if (type) *type = 0;
    if (format) *format = 0;
    if (byte_length) *byte_length = 0;
    return protect(error, [&] {
        if (!type || !format || !byte_length) return write_error(ida::Error::validation("Custom-data item outputs are null"), error);
        if (require_runtime_thread(error)) return -1;
        auto result = ida::data::custom_data_at(address);
        if (!result) return write_error(result.error(), error);
        *type = export_id(false, result->type_id.value); *format = export_id(true, result->format_id.value); *byte_length = result->byte_length;
        return 0;
    });
}
int idax_swift_custom_render(uint64_t format_token, const uint8_t* bytes, size_t count, const IdaxSwiftCustomContext* input,
    uint8_t** output, size_t* output_count, IdaxSwiftError* error) {
    if (output) *output = nullptr;
    if (output_count) *output_count = 0;
    return protect(error, [&] {
        if (!output || !output_count || (count && !bytes)) return write_error(ida::Error::validation("Invalid custom-data render buffer"), error);
        if (require_runtime_thread(error)) return -1;
        CallbackDiagnostic diagnostic;
        auto result = ida::data::render_custom_data({resolve(true, format_token)}, {bytes, count}, context(input));
        if (diagnostic.error) return write_error(*diagnostic.error, error);
        if (!result) return write_error(result.error(), error);
        return output_bytes({reinterpret_cast<const uint8_t*>(result->data()), result->size()}, output, output_count);
    });
}
int idax_swift_custom_scan(uint64_t format_token, const uint8_t* bytes, size_t count, const IdaxSwiftCustomContext* input,
    uint8_t** output, size_t* output_count, IdaxSwiftError* error) {
    if (output) *output = nullptr;
    if (output_count) *output_count = 0;
    return protect(error, [&] {
        if (!output || !output_count || (count && !bytes)) return write_error(ida::Error::validation("Invalid custom-data scan buffer"), error);
        if (require_runtime_thread(error)) return -1;
        const std::string_view text = count ? std::string_view(reinterpret_cast<const char*>(bytes), count) : std::string_view{};
        CallbackDiagnostic diagnostic;
        auto result = ida::data::scan_custom_data({resolve(true, format_token)}, text, context(input));
        if (diagnostic.error) return write_error(*diagnostic.error, error);
        if (!result) return write_error(result.error(), error); return output_bytes(*result, output, output_count);
    });
}
int idax_swift_custom_analyze(uint64_t format_token, const IdaxSwiftCustomContext* input, IdaxSwiftError* error) {
    return protect(error, [&] {
        if (require_runtime_thread(error)) return -1;
        CallbackDiagnostic diagnostic;
        auto result = ida::data::analyze_custom_data({resolve(true, format_token)}, context(input));
        if (diagnostic.error) return write_error(*diagnostic.error, error);
        return status(std::move(result), error);
    });
}

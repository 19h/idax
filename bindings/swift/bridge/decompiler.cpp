#include "decompiler.h"
#include "support.hpp"
#include <ida/decompiler.hpp>
#include <ida/type.hpp>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <variant>
#include <vector>

namespace {
using namespace ida::decompiler;
template<class T> T take(ida::Result<T> result) { if (!result) throw result.error(); return std::move(*result); }
void take(ida::Status result) { if (!result) throw result.error(); }
void require(bool condition, const char* message) { if (!condition) throw ida::Error::validation(message); }
template<class T> T& object(void* value) { require(value != nullptr, "Null decompiler handle"); return *static_cast<T*>(value); }
char* copy(const std::string& text) {
    auto* result = static_cast<char*>(std::malloc(text.size() + 1));
    if (!result) throw std::bad_alloc();
    std::memcpy(result, text.c_str(), text.size() + 1); return result;
}
template<class T> T* allocate(size_t count) {
    require(count <= SIZE_MAX / sizeof(T), "Decompiler array extent overflow");
    if (!count) return nullptr;
    auto* result = static_cast<T*>(std::calloc(count, sizeof(T)));
    if (!result) throw std::bad_alloc(); return result;
}
template<class T> void clear(T* out) { if (out) *out = {}; }
#define DECOMPILER_GUARD if (idax::swift::require_runtime_thread(error) != 0) return -1
std::size_t decompiler_dependencies = 0;
struct SwiftSession {
    ScopedSession session;
    SwiftSession* next{nullptr};
};
SwiftSession* pending_sessions = nullptr;
struct DecompilerOwned {
    void* value;
    void (*destroy)(void*);
    ~DecompilerOwned() {
        destroy(value);
        idax_swift_decompiler_dependency_release();
    }
};
}
extern "C" void idax_swift_decompiler_dependency_acquire() { ++decompiler_dependencies; }
extern "C" void idax_swift_decompiler_dependency_release() {
    if (decompiler_dependencies == 0) return;
    --decompiler_dependencies;
    if (decompiler_dependencies == 0) {
        while (pending_sessions) {
            auto* session = pending_sessions;
            pending_sessions = session->next;
            delete session;
        }
    }
}
extern "C" int idax_swift_decompiler_wrap(void* value, void (*destroy)(void*), void** output, IdaxSwiftError* error) {
    clear(output);
    if (!destroy) return idax::swift::write_error(ida::Error::validation("Null decompiler destructor"), error);
    // Caller just received an owned value on the runtime thread. Consume it on entry.
    std::unique_ptr<void, void (*)(void*)> owned(value, destroy);
    return idax::swift::protect(error, [&] {
        DECOMPILER_GUARD; require(value && destroy && output, "Null owned decompiler value");
        auto result = std::make_unique<DecompilerOwned>();
        result->value = owned.release(); result->destroy = destroy;
        idax_swift_decompiler_dependency_acquire(); *output = result.release(); return 0;
    });
}
extern "C" void* idax_swift_decompiler_unwrap(void* value) { return value ? static_cast<DecompilerOwned*>(value)->value : nullptr; }
extern "C" void idax_swift_decompiler_owned_free(void* value) { delete static_cast<DecompilerOwned*>(value); }
extern "C" int idax_swift_decompiler_initialize(void** output, IdaxSwiftError* error) {
    clear(output); return idax::swift::protect(error, [&] {
        DECOMPILER_GUARD; require(output, "Null session output");
        auto session = std::make_unique<SwiftSession>();
        session->session = take(initialize()); *output = session.release(); return 0;
    });
}
extern "C" int idax_swift_decompiler_session_valid(void* value, int* output, IdaxSwiftError* error) {
    clear(output); return idax::swift::protect(error, [&] {
        DECOMPILER_GUARD; require(output, "Null session state output");
        *output = object<SwiftSession>(value).session.valid() ? 1 : 0; return 0;
    });
}
extern "C" void idax_swift_decompiler_session_free(void* value) {
    auto* session = static_cast<SwiftSession*>(value);
    if (!session) return;
    if (decompiler_dependencies) { session->next = pending_sessions; pending_sessions = session; }
    else delete session;
}
extern "C" int idax_swift_decompiler_session_close(void* value, IdaxSwiftError* error) {
    return idax::swift::protect(error, [&] {
        DECOMPILER_GUARD;
        if (decompiler_dependencies) throw ida::Error::conflict("Owned decompiler values or callbacks still depend on the Hex-Rays session");
        take(object<SwiftSession>(value).session.close()); return 0;
    });
}
extern "C" int idax_swift_decompile(uint64_t address, void** output, IdaxSwiftDecompileFailure* failure, IdaxSwiftError* error) {
    clear(output); clear(failure);
    return idax::swift::protect(error, [&] {
        DECOMPILER_GUARD; require(output && failure, "Null decompile output");
        DecompileFailure details;
        auto result = decompile(address, &details);
        failure->request_address = details.request_address;
        failure->failure_address = details.failure_address;
        failure->description = copy(details.description);
        if (!result) return idax::swift::write_error(result.error(), error);
        *output = new DecompiledFunction(std::move(*result)); return 0;
    });
}
extern "C" void idax_swift_decompile_failure_free(IdaxSwiftDecompileFailure* failure) {
    if (failure) { std::free(failure->description); *failure = {}; }
}
extern "C" int idax_swift_decompiler_view(uint64_t address, int current, void** output, IdaxSwiftError* error) {
    clear(output); return idax::swift::protect(error, [&] {
        DECOMPILER_GUARD; require(output, "Null view output");
        *output = new DecompilerView(take(current ? current_view() : view_for_function(address))); return 0;
    });
}
extern "C" void idax_swift_decompiler_view_free(void* view) { delete static_cast<DecompilerView*>(view); }
extern "C" int idax_swift_decompiler_view_address(void* view, uint64_t* output, IdaxSwiftError* error) {
    clear(output); return idax::swift::protect(error, [&] { DECOMPILER_GUARD; require(output, "Null view address output"); *output = object<DecompilerView>(view).function_address(); return 0; });
}
extern "C" int idax_swift_decompiled_retype(void* function, const char* name, size_t index, void* type, IdaxSwiftError* error) {
    return idax::swift::protect(error, [&] { DECOMPILER_GUARD; auto& f = object<DecompiledFunction>(function); auto& t = object<ida::type::TypeInfo>(type); take(name ? f.retype_variable(name, t) : f.retype_variable(index, t)); return 0; });
}
extern "C" int idax_swift_decompiled_refresh(void* function, IdaxSwiftError* error) {
    return idax::swift::protect(error, [&] { DECOMPILER_GUARD; take(object<DecompiledFunction>(function).refresh()); return 0; });
}
extern "C" int idax_swift_decompiled_microcode_lines(void* function, char*** output, size_t* count, IdaxSwiftError* error) {
    clear(output); clear(count); return idax::swift::protect(error, [&] {
        DECOMPILER_GUARD; require(output && count, "Null microcode lines output");
        auto lines = take(object<DecompiledFunction>(function).microcode_lines());
        auto* values = allocate<char*>(lines.size());
        try { for (size_t i = 0; i < lines.size(); ++i) values[i] = copy(lines[i]); }
        catch (...) { idax_decompiled_lines_free(values, lines.size()); throw; }
        *output = values; *count = lines.size(); return 0;
    });
}
extern "C" int idax_swift_decompiled_address_map(void* function, IdaxSwiftAddressMapping** output, size_t* count, IdaxSwiftError* error) {
    clear(output); clear(count); return idax::swift::protect(error, [&] {
        DECOMPILER_GUARD; require(output && count, "Null address map output"); auto values = take(object<DecompiledFunction>(function).address_map());
        auto* result = allocate<IdaxSwiftAddressMapping>(values.size());
        for (size_t i = 0; i < values.size(); ++i) result[i] = {values[i].address, values[i].line_number};
        *output = result; *count = values.size(); return 0;
    });
}
extern "C" void idax_swift_decompiler_settings_free(IdaxSwiftLocalVariableSetting* values, size_t count) {
    if (!values) return;
    for (size_t i = 0; i < count; ++i) { std::free(values[i].name); std::free(values[i].type_declaration); std::free(values[i].comment); }
    std::free(values);
}
extern "C" int idax_swift_decompiler_saved_settings(uint64_t address, IdaxSwiftLocalVariableSetting** output, size_t* count, IdaxSwiftError* error) {
    clear(output); clear(count); return idax::swift::protect(error, [&] {
        DECOMPILER_GUARD; require(output && count, "Null local variable settings output"); auto settings = take(saved_user_lvar_settings(address));
        auto* values = allocate<IdaxSwiftLocalVariableSetting>(settings.size());
        try { for (size_t i = 0; i < settings.size(); ++i) {
            const auto& s = settings[i]; auto& v = values[i];
            v.kind = static_cast<int>(s.locator.kind); v.register_id = s.locator.register_id; v.stack_offset = s.locator.stack_offset; v.definition_address = s.locator.definition_address;
            v.name = copy(s.name); v.type_declaration = copy(s.type_declaration); v.comment = copy(s.comment);
        }} catch (...) { idax_swift_decompiler_settings_free(values, settings.size()); throw; }
        *output = values; *count = settings.size(); return 0;
    });
}
extern "C" int idax_swift_decompiler_apply_settings(uint64_t address, const IdaxSwiftLocalVariableSetting* values, size_t count, IdaxSwiftError* error) {
    return idax::swift::protect(error, [&] {
        DECOMPILER_GUARD; require((values || !count) && count <= SIZE_MAX / sizeof(*values), "Invalid local variable settings array");
        std::vector<LocalVariableUserSetting> settings; settings.reserve(count);
        for (size_t i = 0; i < count; ++i) { const auto& v = values[i]; require(v.kind >= 0 && v.kind <= 2 && v.name && v.type_declaration && v.comment, "Invalid local variable setting");
            settings.push_back({{static_cast<LocalVariableLocationKind>(v.kind), v.register_id, v.stack_offset, v.definition_address}, v.name, v.type_declaration, v.comment}); }
        take(apply_user_lvar_settings(address, settings)); return 0;
    });
}
extern "C" void idax_swift_decompiler_referenced_types_free(IdaxSwiftReferencedTypes* values) {
    if (!values) return; std::free(values->ordinals);
    if (values->used_offsets) for (size_t i = 0; i < values->used_offset_count; ++i) { std::free(values->used_offsets[i].type_name); std::free(values->used_offsets[i].offsets); }
    std::free(values->used_offsets); *values = {};
}
extern "C" int idax_swift_decompiler_referenced_types(uint64_t address, IdaxSwiftReferencedTypes* output, IdaxSwiftError* error) {
    clear(output); return idax::swift::protect(error, [&] {
        DECOMPILER_GUARD; require(output, "Null referenced types output"); auto value = take(collect_referenced_types(address));
        IdaxSwiftReferencedTypes result{};
        try { result.ordinals = allocate<uint32_t>(value.ordinals.size()); result.ordinal_count = value.ordinals.size();
            std::copy(value.ordinals.begin(), value.ordinals.end(), result.ordinals);
            result.used_offsets = allocate<IdaxSwiftUsedOffsets>(value.used_offsets.size()); result.used_offset_count = value.used_offsets.size();
            for (size_t i = 0; i < value.used_offsets.size(); ++i) { auto& v = result.used_offsets[i]; const auto& source = value.used_offsets[i]; v.type_name = copy(source.type_name); v.offsets = allocate<int32_t>(source.byte_offsets.size()); v.count = source.byte_offsets.size(); std::copy(source.byte_offsets.begin(), source.byte_offsets.end(), v.offsets); }
        } catch (...) { idax_swift_decompiler_referenced_types_free(&result); throw; }
        *output = result; return 0;
    });
}
extern "C" int idax_swift_lvar_snapshot_copy(void* snapshot, void** output, IdaxSwiftError* error) {
    clear(output); return idax::swift::protect(error, [&] { DECOMPILER_GUARD; require(output, "Null local variable snapshot output"); *output = new LvarSnapshot(object<LvarSnapshot>(snapshot)); return 0; });
}
extern "C" int idax_swift_lvar_snapshot_new(void** output, IdaxSwiftError* error) {
    clear(output); return idax::swift::protect(error, [&] { DECOMPILER_GUARD; require(output, "Null local variable snapshot output"); *output = new LvarSnapshot(); return 0; });
}

namespace {
struct TreeLease { bool active{true}; };
struct TreeNode {
    std::shared_ptr<TreeLease> lease;
    std::variant<ExpressionView, StatementView> value;
};
TreeNode& tree(void* pointer) {
    auto& node = object<TreeNode>(pointer);
    if (!node.lease->active) throw ida::Error::conflict("Ctree view is outside its visitor callback");
    return node;
}
ExpressionView& expression(TreeNode& node) { require(std::holds_alternative<ExpressionView>(node.value), "Ctree item is not an expression"); return std::get<ExpressionView>(node.value); }
StatementView& statement(TreeNode& node) { require(std::holds_alternative<StatementView>(node.value), "Ctree item is not a statement"); return std::get<StatementView>(node.value); }
IdaxDecompilerCtreeItemInfo item(const CtreeItemView& value) { return {static_cast<int>(value.type), value.address, value.is_expression ? 1 : 0}; }
class SwiftVisitor final : public CtreeVisitor {
public:
    void* context;
    IdaxSwiftTreeCallback callback;
    std::optional<ida::Error> failure;
    SwiftVisitor(void* c, IdaxSwiftTreeCallback f) : context(c), callback(f) {}
    template<class T> VisitAction invoke(T value, int phase) {
        if (failure) return VisitAction::Stop;
        auto lease = std::make_shared<TreeLease>();
        auto* node = new TreeNode{lease, value};
        IdaxSwiftError error{}; int action = 0;
        // The Swift callback unconditionally adopts node on entry.
        const int status = callback(context, phase, std::is_same_v<T, ExpressionView> ? 1 : 0, node, &action, &error);
        lease->active = false;
        if (status != 0) {
            failure = ida::Error{error.category >= 1 && error.category <= 6 ? static_cast<ida::ErrorCategory>(error.category - 1) : ida::ErrorCategory::Internal, error.code,
                error.message ? error.message : "Swift ctree callback failed",
                error.context ? error.context : "Decompiler.visit"};
        } else if (action < 0 || action > 2) failure = ida::Error::validation("Invalid ctree visit action");
        idax_swift_error_free(&error);
        return failure ? VisitAction::Stop : static_cast<VisitAction>(action);
    }
    VisitAction visit_expression(ExpressionView v) override { return invoke(v, 0); }
    VisitAction visit_statement(StatementView v) override { return invoke(v, 0); }
    VisitAction leave_expression(ExpressionView v) override { return invoke(v, 1); }
    VisitAction leave_statement(StatementView v) override { return invoke(v, 1); }
};
}
extern "C" int idax_swift_decompiled_visit(void* function, int post_order, int track_parents, int expressions_only, void* context, IdaxSwiftTreeCallback callback, int* output, IdaxSwiftError* error) {
    clear(output); return idax::swift::protect(error, [&] {
        DECOMPILER_GUARD; require(callback && output, "Null ctree visitor callback/output");
        SwiftVisitor visitor(context, callback);
        auto result = object<DecompiledFunction>(function).visit(visitor, {post_order != 0, track_parents != 0, expressions_only != 0});
        if (visitor.failure) throw *visitor.failure;
        *output = take(std::move(result)); return 0;
    });
}
extern "C" void idax_swift_tree_node_free(void* node) { delete static_cast<TreeNode*>(node); }
extern "C" int idax_swift_tree_info(void* node, IdaxDecompilerCtreeItemInfo* output, IdaxSwiftError* error) {
    clear(output); return idax::swift::protect(error, [&] {
        DECOMPILER_GUARD; require(output, "Null ctree info output"); auto& n = tree(node);
        std::visit([&](const auto& v) { *output = {static_cast<int>(v.type()), v.address(), std::holds_alternative<ExpressionView>(n.value) ? 1 : 0}; }, n.value); return 0;
    });
}
extern "C" int idax_swift_tree_scalar(void* node, int property, size_t index, uint64_t* output, IdaxSwiftError* error) {
    clear(output); return idax::swift::protect(error, [&] {
        DECOMPILER_GUARD; require(output, "Null ctree scalar output"); auto& n = tree(node);
        switch (property) {
            case 0: *output = take(expression(n).number_value()); break;
            case 1: *output = take(expression(n).object_address()); break;
            case 2: *output = static_cast<uint64_t>(take(expression(n).variable_index())); break;
            case 3: *output = static_cast<uint64_t>(take(expression(n).type_byte_width())); break;
            case 4: *output = static_cast<uint64_t>(take(expression(n).pointed_type_byte_width())); break;
            case 5: *output = take(expression(n).call_argument_count()); break;
            case 6: *output = take(expression(n).member_offset()); break;
            case 7: *output = expression(n).is_assignment_lhs() ? 1 : 0; break;
            case 8: *output = static_cast<uint64_t>(expression(n).operand_count()); break;
            case 9: *output = static_cast<uint64_t>(take(statement(n).goto_target_label())); break;
            case 10: *output = statement(n).has_else_branch() ? 1 : 0; break;
            case 11: *output = take(statement(n).block_size()); break;
            case 12: *output = take(statement(n).switch_case_count()); break;
            default: throw ida::Error::validation("Unknown ctree scalar property");
        } return 0;
    });
}
extern "C" int idax_swift_tree_string(void* node, int property, char** output, IdaxSwiftError* error) {
    clear(output); return idax::swift::protect(error, [&] {
        DECOMPILER_GUARD; require(output, "Null ctree string output"); auto& v = expression(tree(node));
        switch (property) {
            case 0: *output = copy(take(v.helper_name())); break;
            case 1: *output = copy(take(v.type_declaration())); break;
            case 2: *output = copy(take(v.string_value())); break;
            case 3: *output = copy(take(v.member_name())); break;
            case 4: *output = copy(take(v.to_string())); break;
            default: throw ida::Error::validation("Unknown ctree string property");
        } return 0;
    });
}
extern "C" int idax_swift_tree_child(void* node, int property, size_t index, void** output, IdaxSwiftError* error) {
    clear(output); return idax::swift::protect(error, [&] {
        DECOMPILER_GUARD; require(output, "Null ctree child output"); auto& n = tree(node);
        switch (property) {
            case 0: *output = new TreeNode{n.lease, take(expression(n).left())}; break;
            case 1: *output = new TreeNode{n.lease, take(expression(n).right())}; break;
            case 2: *output = new TreeNode{n.lease, take(expression(n).third())}; break;
            case 3: *output = new TreeNode{n.lease, take(expression(n).call_callee())}; break;
            case 4: *output = new TreeNode{n.lease, take(expression(n).call_argument(index))}; break;
            case 5: *output = new TreeNode{n.lease, take(statement(n).condition())}; break;
            case 6: *output = new TreeNode{n.lease, take(statement(n).then_branch())}; break;
            case 7: *output = new TreeNode{n.lease, take(statement(n).else_branch())}; break;
            case 8: *output = new TreeNode{n.lease, take(statement(n).body())}; break;
            case 9: *output = new TreeNode{n.lease, take(statement(n).init_expression())}; break;
            case 10: *output = new TreeNode{n.lease, take(statement(n).step_expression())}; break;
            case 11: *output = new TreeNode{n.lease, take(statement(n).expression())}; break;
            case 12: *output = new TreeNode{n.lease, take(statement(n).block_statement(index))}; break;
            case 13: *output = new TreeNode{n.lease, take(statement(n).switch_case_body(index))}; break;
            default: throw ida::Error::validation("Unknown ctree child property");
        } return 0;
    });
}
extern "C" int idax_swift_tree_parents(void* node, IdaxDecompilerCtreeItemInfo** output, size_t* count, IdaxSwiftError* error) {
    clear(output); clear(count); return idax::swift::protect(error, [&] {
        DECOMPILER_GUARD; require(output && count, "Null ctree parents output"); auto& n = tree(node);
        auto values = std::visit([](const auto& value) { return take(value.parents()); }, n.value);
        auto* result = allocate<IdaxDecompilerCtreeItemInfo>(values.size());
        for (size_t i = 0; i < values.size(); ++i) result[i] = item(values[i]);
        *output = result; *count = values.size(); return 0;
    });
}
extern "C" int idax_swift_tree_switch_values(void* node, size_t index, uint64_t** output, size_t* count, IdaxSwiftError* error) {
    clear(output); clear(count); return idax::swift::protect(error, [&] {
        DECOMPILER_GUARD; require(output && count, "Null switch values output");
        auto values = take(statement(tree(node)).switch_case_values(index));
        auto* result = allocate<uint64_t>(values.size()); std::copy(values.begin(), values.end(), result);
        *output = result; *count = values.size(); return 0;
    });
}

/// \file decompiler.cpp
/// \brief Implementation of ida::decompiler — wrapping Hex-Rays decompiler API.
///
/// The Hex-Rays API uses runtime function-pointer dispatch (hexdsp_t), so
/// there are no link-time dependencies. We include hexrays.hpp and call
/// init_hexrays_plugin() at runtime to check availability.

#include "detail/sdk_bridge.hpp"
#include "detail/type_impl.hpp"
#include <ida/decompiler.hpp>
#include <ida/function.hpp>

// hexrays.hpp is part of the IDA SDK and provides all decompiler APIs
// through a single runtime dispatch pointer (no link dependencies).
#include <hexrays.hpp>

#include <algorithm>
#include <atomic>
#include <cstdarg>
#include <mutex>
#include <unordered_map>

namespace ida::decompiler {

// ── Availability ────────────────────────────────────────────────────────

static bool s_hexrays_initialized = false;

namespace {

std::mutex g_subscription_mutex;
std::unordered_map<Token, std::function<void(const MaturityEvent&)>> g_maturity_callbacks;
std::atomic<std::uint64_t> g_next_token{1};
bool g_hexrays_callback_installed = false;

Maturity to_maturity(int value) {
    switch (value) {
        case CMAT_ZERO:   return Maturity::Zero;
        case CMAT_BUILT:  return Maturity::Built;
        case CMAT_TRANS1: return Maturity::Trans1;
        case CMAT_NICE:   return Maturity::Nice;
        case CMAT_TRANS2: return Maturity::Trans2;
        case CMAT_CPA:    return Maturity::Cpa;
        case CMAT_TRANS3: return Maturity::Trans3;
        case CMAT_CASTED: return Maturity::Casted;
        case CMAT_FINAL:  return Maturity::Final;
        default:          return Maturity::Zero;
    }
}

ssize_t idaapi hexrays_event_bridge(void*, hexrays_event_t event, va_list va) {
    if (event != hxe_maturity)
        return 0;

    cfunc_t* cfunc = va_arg(va, cfunc_t*);
    int maturity_raw = va_arg(va, int);

    MaturityEvent evt;
    if (cfunc != nullptr)
        evt.function_address = static_cast<Address>(cfunc->entry_ea);
    evt.new_maturity = to_maturity(maturity_raw);

    std::vector<std::function<void(const MaturityEvent&)>> callbacks;
    {
        std::lock_guard<std::mutex> lock(g_subscription_mutex);
        callbacks.reserve(g_maturity_callbacks.size());
        for (const auto& [_, callback] : g_maturity_callbacks)
            callbacks.push_back(callback);
    }
    for (const auto& callback : callbacks)
        callback(evt);
    return 0;
}

Status ensure_callback_installed_locked() {
    if (g_hexrays_callback_installed)
        return ida::ok();
    if (!install_hexrays_callback(&hexrays_event_bridge, nullptr))
        return std::unexpected(Error::sdk("install_hexrays_callback failed"));
    g_hexrays_callback_installed = true;
    return ida::ok();
}

} // namespace

static Status ensure_hexrays();

Result<bool> available() {
    if (s_hexrays_initialized)
        return true;
    if (init_hexrays_plugin()) {
        s_hexrays_initialized = true;
        return true;
    }
    return false;
}

Result<Token> on_maturity_changed(std::function<void(const MaturityEvent&)> callback) {
    if (!callback)
        return std::unexpected(Error::validation("Maturity callback cannot be empty"));

    auto st = ensure_hexrays();
    if (!st)
        return std::unexpected(st.error());

    std::lock_guard<std::mutex> lock(g_subscription_mutex);
    st = ensure_callback_installed_locked();
    if (!st)
        return std::unexpected(st.error());

    const Token token = g_next_token.fetch_add(1, std::memory_order_relaxed);
    g_maturity_callbacks.emplace(token, std::move(callback));
    return token;
}

Status unsubscribe(Token token) {
    if (token == 0)
        return std::unexpected(Error::validation("Invalid subscription token"));

    std::lock_guard<std::mutex> lock(g_subscription_mutex);
    auto it = g_maturity_callbacks.find(token);
    if (it == g_maturity_callbacks.end())
        return std::unexpected(Error::not_found("Decompiler subscription token not found",
                                                std::to_string(token)));
    g_maturity_callbacks.erase(it);

    if (g_maturity_callbacks.empty() && g_hexrays_callback_installed) {
        remove_hexrays_callback(&hexrays_event_bridge, nullptr);
        g_hexrays_callback_installed = false;
    }
    return ida::ok();
}

void ScopedSubscription::reset() {
    if (token_ == 0)
        return;
    (void)unsubscribe(token_);
    token_ = 0;
}

ScopedSubscription::~ScopedSubscription() {
    reset();
}

Status mark_dirty(Address function_address, bool close_views) {
    auto st = ensure_hexrays();
    if (!st)
        return std::unexpected(st.error());

    func_t* fn = get_func(function_address);
    if (fn == nullptr)
        return std::unexpected(Error::not_found("No function at address",
                                                std::to_string(function_address)));

    if (!mark_cfunc_dirty(fn->start_ea, close_views))
        return std::unexpected(Error::sdk("mark_cfunc_dirty failed",
                                          std::to_string(function_address)));
    return ida::ok();
}

Status mark_dirty_with_callers(Address function_address, bool close_views) {
    auto st = mark_dirty(function_address, close_views);
    if (!st)
        return st;

    auto caller_addresses = ida::function::callers(function_address);
    if (!caller_addresses)
        return std::unexpected(caller_addresses.error());

    for (Address caller_address : *caller_addresses) {
        st = mark_dirty(caller_address, close_views);
        if (!st)
            return st;
    }
    return ida::ok();
}

// ── Helper: ensure decompiler is initialized ────────────────────────────

static Status ensure_hexrays() {
    if (s_hexrays_initialized)
        return ida::ok();
    if (init_hexrays_plugin()) {
        s_hexrays_initialized = true;
        return ida::ok();
    }
    return std::unexpected(Error::unsupported(
        "Decompiler not available (Hex-Rays plugin not loaded)"));
}

// ── ItemType conversion ─────────────────────────────────────────────────

static ItemType from_ctype(ctype_t ct) {
    return static_cast<ItemType>(static_cast<int>(ct));
}

// ── ExpressionView implementation ───────────────────────────────────────

ItemType ExpressionView::type() const noexcept {
    if (!raw_) return ItemType::ExprEmpty;
    return from_ctype(static_cast<cexpr_t*>(raw_)->op);
}

Address ExpressionView::address() const noexcept {
    if (!raw_) return BadAddress;
    return static_cast<cexpr_t*>(raw_)->ea;
}

Result<std::uint64_t> ExpressionView::number_value() const {
    if (!raw_) return std::unexpected(Error::internal("null expression"));
    auto* e = static_cast<cexpr_t*>(raw_);
    if (e->op != cot_num)
        return std::unexpected(Error::validation("Expression is not a number"));
    return e->numval();
}

Result<Address> ExpressionView::object_address() const {
    if (!raw_) return std::unexpected(Error::internal("null expression"));
    auto* e = static_cast<cexpr_t*>(raw_);
    if (e->op != cot_obj)
        return std::unexpected(Error::validation("Expression is not an object reference"));
    return e->obj_ea;
}

Result<int> ExpressionView::variable_index() const {
    if (!raw_) return std::unexpected(Error::internal("null expression"));
    auto* e = static_cast<cexpr_t*>(raw_);
    if (e->op != cot_var)
        return std::unexpected(Error::validation("Expression is not a variable"));
    return e->v.idx;
}

Result<std::string> ExpressionView::string_value() const {
    if (!raw_) return std::unexpected(Error::internal("null expression"));
    auto* e = static_cast<cexpr_t*>(raw_);
    if (e->op != cot_str || e->string == nullptr)
        return std::unexpected(Error::validation("Expression is not a string literal"));
    return std::string(e->string);
}

Result<std::size_t> ExpressionView::call_argument_count() const {
    if (!raw_) return std::unexpected(Error::internal("null expression"));
    auto* e = static_cast<cexpr_t*>(raw_);
    if (e->op != cot_call || e->a == nullptr)
        return std::unexpected(Error::validation("Expression is not a call"));
    return static_cast<std::size_t>(e->a->size());
}

Result<ExpressionView> ExpressionView::call_callee() const {
    if (!raw_) return std::unexpected(Error::internal("null expression"));
    auto* e = static_cast<cexpr_t*>(raw_);
    if (e->op != cot_call || e->x == nullptr)
        return std::unexpected(Error::validation("Expression is not a call"));
    return ExpressionView(ExpressionView::Tag{}, e->x);
}

Result<ExpressionView> ExpressionView::call_argument(std::size_t index) const {
    if (!raw_) return std::unexpected(Error::internal("null expression"));
    auto* e = static_cast<cexpr_t*>(raw_);
    if (e->op != cot_call || e->a == nullptr)
        return std::unexpected(Error::validation("Expression is not a call"));
    if (index >= e->a->size())
        return std::unexpected(Error::validation("Call argument index out of range"));
    return ExpressionView(ExpressionView::Tag{}, &(*e->a)[index]);
}

Result<std::uint32_t> ExpressionView::member_offset() const {
    if (!raw_) return std::unexpected(Error::internal("null expression"));
    auto* e = static_cast<cexpr_t*>(raw_);
    if (e->op != cot_memref && e->op != cot_memptr)
        return std::unexpected(Error::validation("Expression is not a member access"));
    return e->m;
}

Result<std::string> ExpressionView::to_string() const {
    if (!raw_) return std::unexpected(Error::internal("null expression"));
    // We need the cfunc_t for printing, which we don't have in this context.
    // Return a simple description based on the type.
    auto* e = static_cast<cexpr_t*>(raw_);
    switch (e->op) {
        case cot_num: {
            uint64 val = e->numval();
            char buf[64];
            qsnprintf(buf, sizeof(buf), "0x%" FMT_64 "x", val);
            return std::string(buf);
        }
        case cot_str:
            return e->string ? std::string("\"") + e->string + "\"" : std::string("\"\"");
        case cot_obj: {
            qstring nm;
            if (get_name(&nm, e->obj_ea) > 0)
                return ida::detail::to_string(nm);
            char buf[64];
            qsnprintf(buf, sizeof(buf), "obj_0x%" FMT_64 "x", (uint64)e->obj_ea);
            return std::string(buf);
        }
        default:
            break;
    }
    // Fallback: just return the op name.
    const char* name = get_ctype_name(e->op);
    if (name) return std::string(name);
    return std::string("(unknown)");
}

// ── StatementView implementation ────────────────────────────────────────

ItemType StatementView::type() const noexcept {
    if (!raw_) return ItemType::StmtEmpty;
    return from_ctype(static_cast<cinsn_t*>(raw_)->op);
}

Address StatementView::address() const noexcept {
    if (!raw_) return BadAddress;
    return static_cast<cinsn_t*>(raw_)->ea;
}

Result<int> StatementView::goto_target_label() const {
    if (!raw_) return std::unexpected(Error::internal("null statement"));
    auto* s = static_cast<cinsn_t*>(raw_);
    if (s->op != cit_goto || s->cgoto == nullptr)
        return std::unexpected(Error::validation("Statement is not a goto"));
    return s->cgoto->label_num;
}

// ── CtreeVisitor default implementations ────────────────────────────────

VisitAction CtreeVisitor::visit_expression(ExpressionView) {
    return VisitAction::Continue;
}
VisitAction CtreeVisitor::visit_statement(StatementView) {
    return VisitAction::Continue;
}
VisitAction CtreeVisitor::leave_expression(ExpressionView) {
    return VisitAction::Continue;
}
VisitAction CtreeVisitor::leave_statement(StatementView) {
    return VisitAction::Continue;
}

// ── SDK visitor adapter ─────────────────────────────────────────────────

namespace {

class MicrocodePrinter : public vd_printer_t {
public:
    AS_PRINTF(3, 4) int print(int indent, const char* format, ...) override {
        qstring line;
        if (indent > 0)
            line.fill(0, ' ', indent);

        va_list va;
        va_start(va, format);
        line.cat_vsprnt(format, va);
        va_end(va);

        tag_remove(&line);
        line.trim2();
        if (line.empty())
            return 0;

        lines_.emplace_back(line.c_str());
        return static_cast<int>(line.length());
    }

    [[nodiscard]] const std::vector<std::string>& lines() const {
        return lines_;
    }

private:
    std::vector<std::string> lines_;
};

/// Adapter that bridges the SDK's ctree_visitor_t to our CtreeVisitor.
class SdkVisitorAdapter : public ctree_visitor_t {
public:
    SdkVisitorAdapter(CtreeVisitor& visitor, int flags)
        : ctree_visitor_t(flags), visitor_(visitor), items_visited_(0) {}

    int idaapi visit_insn(cinsn_t* insn) override {
        ++items_visited_;
        StatementView sv(StatementView::Tag{}, insn);
        auto action = visitor_.visit_statement(sv);
        if (action == VisitAction::Stop)
            return 1;  // Non-zero stops traversal.
        if (action == VisitAction::SkipChildren)
            prune_now();
        return 0;
    }

    int idaapi visit_expr(cexpr_t* expr) override {
        ++items_visited_;
        ExpressionView ev(ExpressionView::Tag{}, expr);
        auto action = visitor_.visit_expression(ev);
        if (action == VisitAction::Stop)
            return 1;
        if (action == VisitAction::SkipChildren)
            prune_now();
        return 0;
    }

    int idaapi leave_insn(cinsn_t* insn) override {
        StatementView sv(StatementView::Tag{}, insn);
        auto action = visitor_.leave_statement(sv);
        return action == VisitAction::Stop ? 1 : 0;
    }

    int idaapi leave_expr(cexpr_t* expr) override {
        ExpressionView ev(ExpressionView::Tag{}, expr);
        auto action = visitor_.leave_expression(ev);
        return action == VisitAction::Stop ? 1 : 0;
    }

    int items_visited() const { return items_visited_; }

private:
    CtreeVisitor& visitor_;
    int items_visited_;
};

} // anonymous namespace

// ── DecompiledFunction impl ─────────────────────────────────────────────

struct DecompiledFunction::Impl {
    cfuncptr_t cfunc;   // Reference-counted smart pointer — keeps cfunc_t alive.
    ea_t func_ea{BADADDR};

    explicit Impl(cfuncptr_t cf, ea_t ea) : cfunc(std::move(cf)), func_ea(ea) {}
};

DecompiledFunction::~DecompiledFunction() {
    delete impl_;
}

DecompiledFunction::DecompiledFunction(DecompiledFunction&& other) noexcept
    : impl_(other.impl_) {
    other.impl_ = nullptr;
}

DecompiledFunction& DecompiledFunction::operator=(DecompiledFunction&& other) noexcept {
    if (this != &other) {
        delete impl_;
        impl_ = other.impl_;
        other.impl_ = nullptr;
    }
    return *this;
}

#define CHECK_IMPL() \
    if (impl_ == nullptr || impl_->cfunc == nullptr) \
        return std::unexpected(Error::internal("DecompiledFunction is empty"))

Result<std::string> DecompiledFunction::pseudocode() const {
    CHECK_IMPL();

    const strvec_t& sv = impl_->cfunc->get_pseudocode();
    std::string result;
    for (std::size_t i = 0; i < sv.size(); ++i) {
        qstring buf;
        tag_remove(&buf, sv[i].line);
        if (i > 0) result += '\n';
        result += ida::detail::to_string(buf);
    }
    return result;
}

Result<std::string> DecompiledFunction::microcode() const {
    auto mc_lines = microcode_lines();
    if (!mc_lines)
        return std::unexpected(mc_lines.error());

    std::string result;
    for (std::size_t i = 0; i < mc_lines->size(); ++i) {
        if (i > 0)
            result.push_back('\n');
        result += (*mc_lines)[i];
    }
    return result;
}

Result<std::vector<std::string>> DecompiledFunction::lines() const {
    CHECK_IMPL();

    const strvec_t& sv = impl_->cfunc->get_pseudocode();
    std::vector<std::string> result;
    result.reserve(sv.size());
    for (std::size_t i = 0; i < sv.size(); ++i) {
        qstring buf;
        tag_remove(&buf, sv[i].line);
        result.push_back(ida::detail::to_string(buf));
    }
    return result;
}

Result<std::vector<std::string>> DecompiledFunction::microcode_lines() const {
    CHECK_IMPL();

    mba_t* mba = impl_->cfunc->mba;
    if (mba == nullptr) {
        return std::unexpected(Error::unsupported(
            "Microcode is not available for this decompiled function",
            std::to_string(impl_->func_ea)));
    }

    MicrocodePrinter printer;
    mba->print(printer);
    return printer.lines();
}

Result<std::string> DecompiledFunction::declaration() const {
    CHECK_IMPL();

    qstring decl;
    impl_->cfunc->print_dcl(&decl);
    return ida::detail::to_string(decl);
}

Result<std::size_t> DecompiledFunction::variable_count() const {
    CHECK_IMPL();

    lvars_t* vars = impl_->cfunc->get_lvars();
    if (vars == nullptr)
        return std::size_t{0};
    return static_cast<std::size_t>(vars->size());
}

Result<std::vector<LocalVariable>> DecompiledFunction::variables() const {
    CHECK_IMPL();

    lvars_t* vars = impl_->cfunc->get_lvars();
    if (vars == nullptr)
        return std::vector<LocalVariable>{};

    std::vector<LocalVariable> result;
    result.reserve(vars->size());
    for (std::size_t i = 0; i < vars->size(); ++i) {
        const lvar_t& v = (*vars)[i];
        LocalVariable lv;
        lv.name        = ida::detail::to_string(v.name);
        lv.is_argument = v.is_arg_var();
        lv.width       = v.width;

        // Get the type as a C string.
        qstring type_str;
        if (v.type().print(&type_str))
            lv.type_name = ida::detail::to_string(type_str);
        else
            lv.type_name = "(unknown)";

        result.push_back(std::move(lv));
    }
    return result;
}

Status DecompiledFunction::rename_variable(std::string_view old_name,
                                           std::string_view new_name) {
    CHECK_IMPL();

    std::string old_str(old_name);
    std::string new_str(new_name);
    if (!rename_lvar(impl_->func_ea, old_str.c_str(), new_str.c_str()))
        return std::unexpected(Error::sdk("rename_lvar failed",
                                          std::string(old_name)));
    return ida::ok();
}

Status DecompiledFunction::retype_variable(std::string_view variable_name,
                                           const ida::type::TypeInfo& new_type) {
    CHECK_IMPL();

    if (variable_name.empty())
        return std::unexpected(Error::validation("Variable name cannot be empty"));

    const auto* type_impl = ida::type::TypeInfoAccess::get(new_type);
    if (type_impl == nullptr)
        return std::unexpected(Error::internal("TypeInfo has null implementation"));

    std::string name_str(variable_name);
    lvar_saved_info_t info;
    if (!locate_lvar(&info.ll, impl_->func_ea, name_str.c_str()))
        return std::unexpected(Error::not_found("Local variable not found", name_str));

    info.type = type_impl->ti;
    const size_t size = info.type.get_size();
    if (size != BADSIZE)
        info.size = static_cast<ssize_t>(size);

    if (!modify_user_lvar_info(impl_->func_ea, MLI_TYPE, info))
        return std::unexpected(Error::sdk("modify_user_lvar_info(type) failed", name_str));
    return ida::ok();
}

Status DecompiledFunction::retype_variable(std::size_t variable_index,
                                           const ida::type::TypeInfo& new_type) {
    CHECK_IMPL();

    const auto* type_impl = ida::type::TypeInfoAccess::get(new_type);
    if (type_impl == nullptr)
        return std::unexpected(Error::internal("TypeInfo has null implementation"));

    lvars_t* variables = impl_->cfunc->get_lvars();
    if (variables == nullptr || variable_index >= variables->size())
        return std::unexpected(Error::not_found("Variable index out of range",
                                                std::to_string(variable_index)));

    lvar_saved_info_t info;
    info.ll = (*variables)[variable_index];
    info.type = type_impl->ti;
    const size_t size = info.type.get_size();
    if (size != BADSIZE)
        info.size = static_cast<ssize_t>(size);

    std::string context = std::to_string(variable_index);
    if (!(*variables)[variable_index].name.empty())
        context = ida::detail::to_string((*variables)[variable_index].name);

    if (!modify_user_lvar_info(impl_->func_ea, MLI_TYPE, info))
        return std::unexpected(Error::sdk("modify_user_lvar_info(type) failed", context));
    return ida::ok();
}

// ── Ctree traversal ─────────────────────────────────────────────────────

Result<int> DecompiledFunction::visit(CtreeVisitor& visitor,
                                      const VisitOptions& options) const {
    CHECK_IMPL();

    int flags = CV_FAST;
    if (options.post_order) flags |= CV_POST;
    if (options.track_parents) flags |= CV_PARENTS;

    SdkVisitorAdapter adapter(visitor, flags);

    if (options.expressions_only)
        adapter.apply_to_exprs(&impl_->cfunc->body, nullptr);
    else
        adapter.apply_to(&impl_->cfunc->body, nullptr);

    return adapter.items_visited();
}

Result<int> DecompiledFunction::visit_expressions(CtreeVisitor& visitor,
                                                   bool post_order) const {
    VisitOptions opts;
    opts.expressions_only = true;
    opts.post_order = post_order;
    return visit(visitor, opts);
}

// ── User comments ───────────────────────────────────────────────────────

Status DecompiledFunction::set_comment(Address ea, std::string_view text,
                                       CommentPosition pos) {
    CHECK_IMPL();

    treeloc_t loc;
    loc.ea = ea;
    loc.itp = static_cast<item_preciser_t>(static_cast<int>(pos));

    if (text.empty()) {
        impl_->cfunc->set_user_cmt(loc, nullptr);
    } else {
        std::string str(text);
        impl_->cfunc->set_user_cmt(loc, str.c_str());
    }
    return ida::ok();
}

Result<std::string> DecompiledFunction::get_comment(Address ea,
                                                     CommentPosition pos) const {
    CHECK_IMPL();

    treeloc_t loc;
    loc.ea = ea;
    loc.itp = static_cast<item_preciser_t>(static_cast<int>(pos));

    const char* cmt = impl_->cfunc->get_user_cmt(loc, RETRIEVE_ALWAYS);
    if (cmt == nullptr)
        return std::string{};
    return std::string(cmt);
}

Status DecompiledFunction::save_comments() const {
    CHECK_IMPL();
    impl_->cfunc->save_user_cmts();
    return ida::ok();
}

Result<bool> DecompiledFunction::has_orphan_comments() const {
    CHECK_IMPL();
    return impl_->cfunc->has_orphan_cmts();
}

Result<int> DecompiledFunction::remove_orphan_comments() {
    CHECK_IMPL();
    const int removed = impl_->cfunc->del_orphan_cmts();
    if (removed < 0)
        return std::unexpected(Error::sdk("del_orphan_cmts failed"));
    return removed;
}

Status DecompiledFunction::refresh() const {
    CHECK_IMPL();
    impl_->cfunc->refresh_func_ctext();
    return ida::ok();
}

// ── Address mapping ─────────────────────────────────────────────────────

Address DecompiledFunction::entry_address() const {
    if (impl_ == nullptr) return BadAddress;
    return impl_->func_ea;
}

Result<Address> DecompiledFunction::line_to_address(int line_number) const {
    CHECK_IMPL();

    // The pseudocode uses treeitems to map indices to items.
    // A simpler approach: walk the eamap to find which ea maps to lines
    // near the requested line, then correlate with pseudocode.
    const strvec_t& sv = impl_->cfunc->get_pseudocode();
    if (line_number < 0 || static_cast<std::size_t>(line_number) >= sv.size())
        return std::unexpected(Error::validation("Line number out of range"));

    // After get_pseudocode(), treeitems should be populated.
    // Each pseudocode line has an associated ea via the ctree items.
    // We use the boundaries map for a reliable mapping.
    // Note: get_boundaries()/get_eamap() are available for advanced mapping
    // but treeitems (populated by get_pseudocode) is more direct for line mapping.

    // Use treeitems for the given line.
    int hdr = impl_->cfunc->hdrlines;
    int item_line = line_number - hdr;

    if (item_line >= 0
        && static_cast<std::size_t>(item_line) < impl_->cfunc->treeitems.size()) {
        const citem_t* item = impl_->cfunc->treeitems[item_line];
        if (item != nullptr && item->ea != BADADDR)
            return item->ea;
    }

    // Fallback: scan treeitems around the target line.
    for (int delta = 1; delta <= 5; ++delta) {
        for (int dir : {-1, 1}) {
            int probe = item_line + dir * delta;
            if (probe >= 0
                && static_cast<std::size_t>(probe) < impl_->cfunc->treeitems.size()) {
                const citem_t* item = impl_->cfunc->treeitems[probe];
                if (item != nullptr && item->ea != BADADDR)
                    return item->ea;
            }
        }
    }

    return std::unexpected(Error::not_found("No address mapping for line",
                                             std::to_string(line_number)));
}

Result<std::vector<AddressMapping>> DecompiledFunction::address_map() const {
    CHECK_IMPL();

    // Ensure pseudocode is generated (populates treeitems).
    impl_->cfunc->get_pseudocode();

    int hdr = impl_->cfunc->hdrlines;
    std::vector<AddressMapping> result;

    for (std::size_t i = 0; i < impl_->cfunc->treeitems.size(); ++i) {
        const citem_t* item = impl_->cfunc->treeitems[i];
        if (item != nullptr && item->ea != BADADDR) {
            AddressMapping am;
            am.address = item->ea;
            am.line_number = static_cast<int>(i) + hdr;
            result.push_back(am);
        }
    }

    return result;
}

#undef CHECK_IMPL

// ── Decompile ───────────────────────────────────────────────────────────

Result<DecompiledFunction> decompile(Address ea, DecompileFailure* failure) {
    if (failure != nullptr)
        *failure = DecompileFailure{};

    auto st = ensure_hexrays();
    if (!st) return std::unexpected(st.error());

    func_t* pfn = get_func(ea);
    if (pfn == nullptr) {
        if (failure != nullptr) {
            failure->request_address = ea;
            failure->failure_address = ea;
            failure->description = "No function at address";
        }
        return std::unexpected(Error::not_found("No function at address",
                                                std::to_string(ea)));
    }

    hexrays_failure_t hf;
    cfuncptr_t cfunc = decompile_func(pfn, &hf, 0);
    if (cfunc == nullptr) {
        std::string desc = ida::detail::to_string(hf.desc());
        if (failure != nullptr) {
            failure->request_address = ea;
            failure->failure_address = hf.errea;
            failure->description = desc;
        }
        return std::unexpected(Error::sdk("Decompilation failed: " + desc,
                                          "request=" + std::to_string(ea)
                                              + ", failure=" + std::to_string(hf.errea)));
    }

    auto* impl = new DecompiledFunction::Impl(std::move(cfunc), pfn->start_ea);
    return DecompiledFunction(impl);
}

Result<DecompiledFunction> decompile(Address ea) {
    return decompile(ea, nullptr);
}

// ── Functional-style visitor helpers ────────────────────────────────────

namespace {

class LambdaExprVisitor : public CtreeVisitor {
public:
    explicit LambdaExprVisitor(std::function<VisitAction(ExpressionView)> cb)
        : callback_(std::move(cb)) {}

    VisitAction visit_expression(ExpressionView expr) override {
        return callback_(expr);
    }

private:
    std::function<VisitAction(ExpressionView)> callback_;
};

class LambdaItemVisitor : public CtreeVisitor {
public:
    LambdaItemVisitor(std::function<VisitAction(ExpressionView)> on_expr,
                      std::function<VisitAction(StatementView)> on_stmt)
        : on_expr_(std::move(on_expr)), on_stmt_(std::move(on_stmt)) {}

    VisitAction visit_expression(ExpressionView expr) override {
        return on_expr_(expr);
    }

    VisitAction visit_statement(StatementView stmt) override {
        return on_stmt_(stmt);
    }

private:
    std::function<VisitAction(ExpressionView)> on_expr_;
    std::function<VisitAction(StatementView)> on_stmt_;
};

} // anonymous namespace

Result<int> for_each_expression(
    const DecompiledFunction& func,
    std::function<VisitAction(ExpressionView)> callback) {
    LambdaExprVisitor visitor(std::move(callback));
    return func.visit_expressions(visitor);
}

Result<int> for_each_item(
    const DecompiledFunction& func,
    std::function<VisitAction(ExpressionView)> on_expr,
    std::function<VisitAction(StatementView)> on_stmt) {
    LambdaItemVisitor visitor(std::move(on_expr), std::move(on_stmt));
    return func.visit(visitor);
}

} // namespace ida::decompiler

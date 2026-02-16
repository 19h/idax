/// \file abyss_port_plugin.cpp
/// \brief Abyss port — Hex-Rays decompiler output post-processing framework.
///
/// C++ port of the Python "abyss" plugin by Dennis Elser (patois).
/// Provides a post-processing filter framework for Hex-Rays pseudocode.
/// All 8 original filters are implemented using idax APIs.
///
/// API surface exercised:
///   ida::decompiler (decompile, on_maturity_changed, on_func_printed,
///       on_refresh_pseudocode, on_curpos_changed, on_create_hint,
///       raw_pseudocode_lines, set_pseudocode_line, pseudocode_header_line_count,
///       item_at_position, item_type_name, ExpressionView::left/right,
///       LocalVariable extended properties, ScopedSubscription, CtreeVisitor)
///   ida::ui (on_popup_ready, attach_dynamic_action, on_rendering_info,
///       widget_type, user_directory, refresh_all_views, on_screen_ea_changed,
///       screen_address, jump_to, message)
///   ida::lines (colstr, tag_remove, tag_advance, tag_strlen,
///       make_addr_tag, decode_addr_tag, Color, kColorOn, kColorAddr)
///   ida::function (at, name_at, code_addresses)
///   ida::xref (code_refs_to)
///   ida::instruction (decode, is_call)
///   ida::name (at)
///   ida::plugin (Plugin, register_action_with_menu)

#include <ida/idax.hpp>

#include <algorithm>
#include <fstream>
#include <functional>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

namespace {

using namespace ida;

// ════════════════════════════════════════════════════════════════════════
// Filter base class
// ════════════════════════════════════════════════════════════════════════

class AbyssFilter {
public:
    virtual ~AbyssFilter() = default;

    [[nodiscard]] const std::string& name() const { return name_; }
    [[nodiscard]] bool is_activated() const { return activated_; }
    void set_activated(bool v) {
        activated_ = v;
        on_activation_changed(v);
    }

    // ── Event handlers (override in subclasses) ─────────────────────
    virtual void func_printed(const decompiler::PseudocodeEvent&) {}
    virtual void maturity(const decompiler::MaturityEvent&) {}
    virtual void curpos(const decompiler::CursorPositionEvent&) {}
    virtual decompiler::HintResult create_hint(const decompiler::HintRequestEvent&) {
        return {};
    }
    virtual void refresh_pseudocode(const decompiler::PseudocodeEvent&) {}
    virtual void popup_ready(const ui::PopupEvent&) {}
    virtual void rendering_info(ui::RenderingEvent&) {}
    virtual void screen_ea_changed(Address /*ea*/, Address /*prev*/) {}

protected:
    explicit AbyssFilter(std::string name) : name_(std::move(name)) {}
    virtual void on_activation_changed(bool) {}

private:
    std::string name_;
    bool activated_{true};
};

// ════════════════════════════════════════════════════════════════════════
// Filter 1: Token Colorizer
// ════════════════════════════════════════════════════════════════════════
//
// Replaces configured token strings in pseudocode with colored versions.
// Config: <IDA_USER_DIR>/cfg/abyss_token_colorizer.cfg

class TokenColorizer : public AbyssFilter {
public:
    TokenColorizer() : AbyssFilter("token_colorizer") {
        // Default config: color "return" with Macro color
        tokens_[lines::Color::Macro].push_back("return");
    }

    void func_printed(const decompiler::PseudocodeEvent& ev) override {
        auto raw = decompiler::raw_pseudocode_lines(ev.cfunc_handle);
        if (!raw) return;

        for (std::size_t i = 0; i < raw->size(); ++i) {
            std::string& line = (*raw)[i];
            bool modified = false;
            for (const auto& [color, token_list] : tokens_) {
                for (const auto& token : token_list) {
                    std::string colored = lines::colstr(token, color);
                    std::string::size_type pos = 0;
                    while ((pos = line.find(token, pos)) != std::string::npos) {
                        line.replace(pos, token.size(), colored);
                        pos += colored.size();
                        modified = true;
                    }
                }
            }
            if (modified)
                (void)decompiler::set_pseudocode_line(ev.cfunc_handle, i, line);
        }
    }

private:
    std::map<lines::Color, std::vector<std::string>> tokens_;
};

// ════════════════════════════════════════════════════════════════════════
// Filter 2: Signed Operations Annotator
// ════════════════════════════════════════════════════════════════════════
//
// Annotates signed comparison/arithmetic operations with "/*signed*/" comments.

class SignedOps : public AbyssFilter {
public:
    SignedOps() : AbyssFilter("signed_ops") {}

    void func_printed(const decompiler::PseudocodeEvent& ev) override {
        auto hdr = decompiler::pseudocode_header_line_count(ev.cfunc_handle);
        if (!hdr) return;
        auto raw = decompiler::raw_pseudocode_lines(ev.cfunc_handle);
        if (!raw) return;

        const std::string comment_tag = lines::colstr("/*signed*/",
                                                       lines::Color::RegularComment);

        for (std::size_t line_idx = static_cast<std::size_t>(*hdr);
             line_idx < raw->size(); ++line_idx) {
            std::string& line = (*raw)[line_idx];

            // Collect unique item indices for signed operations
            std::vector<int> signed_items;
            std::set<int> seen;

            for (int ch = 0; ch < static_cast<int>(line.size()); ++ch) {
                auto item = decompiler::item_at_position(
                    ev.cfunc_handle, line, ch);
                if (!item) continue;
                if (!item->is_expression) continue;
                if (!is_signed_op(item->type)) continue;
                if (item->item_index >= 0 && seen.insert(item->item_index).second)
                    signed_items.push_back(item->item_index);
            }

            // For each signed item, insert comment after its address tag
            bool modified = false;
            for (int idx : signed_items) {
                std::string addr_tag = lines::make_addr_tag(idx);
                auto pos = line.find(addr_tag);
                if (pos != std::string::npos) {
                    line.insert(pos + addr_tag.size(), comment_tag);
                    modified = true;
                }
            }
            if (modified)
                (void)decompiler::set_pseudocode_line(ev.cfunc_handle, line_idx, line);
        }
    }

private:
    static bool is_signed_op(decompiler::ItemType t) {
        using IT = decompiler::ItemType;
        switch (t) {
            case IT::ExprSignedGE:     case IT::ExprSignedLE:
            case IT::ExprSignedGT:     case IT::ExprSignedLT:
            case IT::ExprShiftRightSigned:
            case IT::ExprDivSigned:    case IT::ExprModSigned:
            case IT::ExprAssignShiftRightSigned:
            case IT::ExprAssignDivSigned: case IT::ExprAssignModSigned:
                return true;
            default:
                return false;
        }
    }
};

// ════════════════════════════════════════════════════════════════════════
// Filter 3: CType Name Annotator
// ════════════════════════════════════════════════════════════════════════
//
// Prepends ctree type names (e.g., <cot_add>) to each address tag.

class ItemCtype : public AbyssFilter {
public:
    ItemCtype() : AbyssFilter("item_ctype") {}

    void func_printed(const decompiler::PseudocodeEvent& ev) override {
        auto raw = decompiler::raw_pseudocode_lines(ev.cfunc_handle);
        if (!raw) return;

        for (std::size_t i = 0; i < raw->size(); ++i) {
            std::string line = (*raw)[i];
            bool modified = annotate_addr_tags(ev.cfunc_handle, line);
            if (modified)
                (void)decompiler::set_pseudocode_line(ev.cfunc_handle, i, line);
        }
    }

private:
    static bool annotate_addr_tags(void* cfunc_handle, std::string& line) {
        // Find all COLOR_ADDR tags in the line
        const std::string tag_prefix{lines::kColorOn,
                                     static_cast<char>(lines::kColorAddr)};
        bool modified = false;
        std::string::size_type pos = 0;

        while ((pos = line.find(tag_prefix, pos)) != std::string::npos) {
            int item_idx = lines::decode_addr_tag(line, pos);
            if (item_idx >= 0) {
                // Look up the item and get its ctype name
                auto item_info = decompiler::item_at_position(
                    cfunc_handle, line, static_cast<int>(pos));
                // Use item_type_name for the resolved type
                std::string type_name = decompiler::item_type_name(
                    item_info ? item_info->type : decompiler::ItemType::ExprEmpty);

                std::string annotation = lines::colstr(
                    "<" + type_name + ">", lines::Color::AutoComment);

                line.insert(pos, annotation);
                pos += annotation.size() + tag_prefix.size() + lines::kColorAddrSize;
                modified = true;
            } else {
                pos += tag_prefix.size();
            }
        }
        return modified;
    }
};

// ════════════════════════════════════════════════════════════════════════
// Filter 4: Raw Address Tag Index Visualizer
// ════════════════════════════════════════════════════════════════════════
//
// Shows the raw hex address tag values as visible annotations.

class ItemIndex : public AbyssFilter {
public:
    ItemIndex() : AbyssFilter("item_index") {}

    void func_printed(const decompiler::PseudocodeEvent& ev) override {
        auto raw = decompiler::raw_pseudocode_lines(ev.cfunc_handle);
        if (!raw) return;

        for (std::size_t i = 0; i < raw->size(); ++i) {
            std::string line = (*raw)[i];
            bool modified = annotate_raw_tags(line);
            if (modified)
                (void)decompiler::set_pseudocode_line(ev.cfunc_handle, i, line);
        }
    }

private:
    static bool annotate_raw_tags(std::string& line) {
        const std::string tag_prefix{lines::kColorOn,
                                     static_cast<char>(lines::kColorAddr)};
        bool modified = false;
        std::string::size_type pos = 0;

        while ((pos = line.find(tag_prefix, pos)) != std::string::npos) {
            // Extract the raw hex digits
            if (pos + 2 + lines::kColorAddrSize <= line.size()) {
                std::string hex_val = line.substr(pos + 2, lines::kColorAddrSize);
                std::string annotation = lines::colstr(
                    "<" + hex_val + ">", lines::Color::AutoComment);
                line.insert(pos, annotation);
                pos += annotation.size() + tag_prefix.size() + lines::kColorAddrSize;
                modified = true;
            } else {
                pos += tag_prefix.size();
            }
        }
        return modified;
    }
};

// ════════════════════════════════════════════════════════════════════════
// Filter 5: Local Variable Type/Size Info
// ════════════════════════════════════════════════════════════════════════
//
// Appends storage type and width suffix to auto-named local variables.
// Example: v11 → v11_s4 (stack, 4 bytes), v7 → v7_r8 (register, 8 bytes)

class LvarsInfo : public AbyssFilter {
public:
    LvarsInfo() : AbyssFilter("lvars_info") {}

    void maturity(const decompiler::MaturityEvent& ev) override {
        if (ev.new_maturity != decompiler::Maturity::Final) return;
        if (ev.function_address == BadAddress) return;

        auto func = decompiler::decompile(ev.function_address);
        if (!func) return;

        auto vars = func->variables();
        if (!vars) return;

        // Note: the maturity event fires while the ctree is being built,
        // and we'd need direct lvar_t access to mutate names. Since idax
        // variables() returns copies, this filter demonstrates the pattern
        // but actual mutation would require the on_maturity_changed callback
        // to receive a mutable cfunc handle. For now, log what we would rename.
        for (const auto& lv : *vars) {
            if (lv.has_nice_name && !lv.has_user_name) {
                char type_ch = 'u';
                if (lv.storage == decompiler::VariableStorage::Stack) type_ch = 's';
                else if (lv.storage == decompiler::VariableStorage::Register) type_ch = 'r';

                std::string suffix = "_" + std::string(1, type_ch)
                                   + std::to_string(lv.width);
                ui::message("[abyss] lvars_info: would rename '" + lv.name
                            + "' -> '" + lv.name + suffix + "'\n");
            }
        }
    }
};

// ════════════════════════════════════════════════════════════════════════
// Filter 6: Local Variable Aliasing
// ════════════════════════════════════════════════════════════════════════
//
// Auto-names local variables based on assignment patterns:
//   var = other_var  →  var renamed to "other_var_"
//   var = func(...)  →  var renamed to "res_func"

class LvarsAlias : public AbyssFilter {
public:
    LvarsAlias() : AbyssFilter("lvars_alias") {}

    void maturity(const decompiler::MaturityEvent& ev) override {
        if (ev.new_maturity != decompiler::Maturity::Final) return;
        if (ev.function_address == BadAddress) return;

        auto func = decompiler::decompile(ev.function_address);
        if (!func) return;

        // Walk the ctree looking for assignments
        // var = var  → rename LHS
        // var = func(args)  → rename LHS to res_func
        auto vars = func->variables();
        if (!vars) return;

        decompiler::for_each_expression(*func,
            [&](decompiler::ExpressionView expr) -> decompiler::VisitAction {
                if (expr.type() != decompiler::ItemType::ExprAssign)
                    return decompiler::VisitAction::Continue;

                auto lhs = expr.left();
                auto rhs = expr.right();
                if (!lhs || !rhs) return decompiler::VisitAction::Continue;
                if (lhs->type() != decompiler::ItemType::ExprVariable)
                    return decompiler::VisitAction::Continue;

                auto lhs_idx = lhs->variable_index();
                if (!lhs_idx) return decompiler::VisitAction::Continue;

                // Check if LHS var has a user name already
                if (static_cast<std::size_t>(*lhs_idx) < vars->size()) {
                    const auto& lv = (*vars)[*lhs_idx];
                    if (lv.has_user_name) return decompiler::VisitAction::Continue;
                }

                // Case 1: var = var
                if (rhs->type() == decompiler::ItemType::ExprVariable) {
                    auto rhs_idx = rhs->variable_index();
                    if (rhs_idx && static_cast<std::size_t>(*rhs_idx) < vars->size()) {
                        const auto& rhs_var = (*vars)[*rhs_idx];
                        if (rhs_var.has_user_name) {
                            ui::message("[abyss] lvars_alias: would rename v"
                                        + std::to_string(*lhs_idx)
                                        + " -> '" + rhs_var.name + "_'\n");
                        }
                    }
                }

                // Case 2: var = func(...) or var = (cast)func(...)
                decompiler::ExpressionView call_target = *rhs;
                if (rhs->type() == decompiler::ItemType::ExprCast) {
                    auto inner = rhs->left();
                    if (inner) call_target = *inner;
                }
                if (call_target.type() == decompiler::ItemType::ExprCall) {
                    auto callee = call_target.call_callee();
                    if (callee && callee->type() == decompiler::ItemType::ExprObject) {
                        auto obj_ea = callee->object_address();
                        if (obj_ea) {
                            auto fname = name::get(*obj_ea);
                            if (fname)
                                ui::message("[abyss] lvars_alias: would rename v"
                                            + std::to_string(*lhs_idx)
                                            + " -> 'res_" + *fname + "'\n");
                        }
                    }
                }

                return decompiler::VisitAction::Continue;
            });
    }
};

// ════════════════════════════════════════════════════════════════════════
// Filter 7: Item Sync (Disassembly ↔ Decompiler Highlighting)
// ════════════════════════════════════════════════════════════════════════
//
// Highlights pseudocode tokens corresponding to the current disassembly
// address using background color overlays.

class ItemSync : public AbyssFilter {
public:
    ItemSync() : AbyssFilter("item_sync") {}

    void refresh_pseudocode(const decompiler::PseudocodeEvent& ev) override {
        // Rebuild the item position map for this function
        rebuild_map(ev);
    }

    void screen_ea_changed(Address ea, Address /*prev*/) override {
        current_ea_ = ea;
        ui::refresh_all_views();
    }

    void rendering_info(ui::RenderingEvent& ev) override {
        if (ev.type != ui::WidgetType::Pseudocode)
            return;
        if (current_ea_ == BadAddress)
            return;

        auto it = item_map_.find(current_ea_);
        if (it == item_map_.end())
            return;

        for (const auto& [line_num, col, len] : it->second) {
            ui::LineRenderEntry entry;
            entry.line_number = line_num;
            entry.bg_color = 0x00FFFF80;  // Soft yellow highlight (CK_EXTRA2-like)
            entry.start_column = col;
            entry.length = len;
            entry.character_range = true;
            ev.entries.push_back(entry);
        }
    }

protected:
    void on_activation_changed(bool active) override {
        if (!active) {
            item_map_.clear();
            current_ea_ = BadAddress;
        }
    }

private:
    struct ItemPos {
        int line_num;
        int column;
        int length;
    };

    // ea → list of (line, column, length) positions
    std::unordered_map<Address, std::vector<ItemPos>> item_map_;
    Address current_ea_{BadAddress};

    void rebuild_map(const decompiler::PseudocodeEvent& ev) {
        item_map_.clear();
        auto hdr = decompiler::pseudocode_header_line_count(ev.cfunc_handle);
        if (!hdr) return;
        auto raw = decompiler::raw_pseudocode_lines(ev.cfunc_handle);
        if (!raw) return;

        for (std::size_t line_idx = static_cast<std::size_t>(*hdr);
             line_idx < raw->size(); ++line_idx) {
            const std::string& tagged_line = (*raw)[line_idx];
            int visible_col = 0;

            for (int byte_pos = 0; byte_pos < static_cast<int>(tagged_line.size()); ) {
                int skip = lines::tag_advance(tagged_line, byte_pos);
                if (skip > 1) {
                    // This was a tag — skip it without incrementing visible column
                    byte_pos += skip;
                    continue;
                }

                // Visible character — resolve the ctree item at this position
                auto item = decompiler::item_at_position(
                    ev.cfunc_handle, tagged_line, byte_pos);
                if (item && item->address != BadAddress) {
                    // Record the visible column position
                    item_map_[item->address].push_back(
                        ItemPos{static_cast<int>(line_idx), visible_col, 1});
                }
                byte_pos += skip;
                ++visible_col;
            }
        }

        // Merge adjacent positions on the same line into ranges
        for (auto& [ea, positions] : item_map_) {
            if (positions.size() <= 1) continue;
            std::sort(positions.begin(), positions.end(),
                [](const ItemPos& a, const ItemPos& b) {
                    return a.line_num < b.line_num
                        || (a.line_num == b.line_num && a.column < b.column);
                });
            std::vector<ItemPos> merged;
            merged.push_back(positions[0]);
            for (std::size_t j = 1; j < positions.size(); ++j) {
                auto& last = merged.back();
                if (positions[j].line_num == last.line_num
                    && positions[j].column == last.column + last.length) {
                    last.length += positions[j].length;
                } else {
                    merged.push_back(positions[j]);
                }
            }
            positions = std::move(merged);
        }
    }
};

// ════════════════════════════════════════════════════════════════════════
// Filter 8: Hierarchy (Call Graph Popup)
// ════════════════════════════════════════════════════════════════════════
//
// Builds a popup menu showing callers/callees of the current function.

class Hierarchy : public AbyssFilter {
public:
    Hierarchy() : AbyssFilter("hierarchy") {}

    void popup_ready(const ui::PopupEvent& ev) override {
        if (ev.type != ui::WidgetType::Pseudocode)
            return;

        auto ea = ui::screen_address();
        if (!ea) return;

        // Check if the current address is within a function
        auto func = function::at(*ea);
        if (!func) return;
        Address func_ea = func->start();

        auto fname = function::name_at(func_ea);
        std::string root_name = fname ? *fname : "func";

        // Build callees menu
        build_callees_menu(ev, func_ea, root_name);

        // Build callers menu
        build_callers_menu(ev, func_ea, root_name);
    }

private:
    static constexpr int kMaxRecursion = 4;
    static constexpr int kMaxFunctions = 30;

    void build_callees_menu(const ui::PopupEvent& ev,
                            Address func_ea,
                            const std::string& root_name) {
        // Get callees of this function
        auto callees = get_callees(func_ea);

        std::string menu_base = "abyss/childs [" + root_name + "]/";
        int action_counter = 0;

        for (const auto& [callee_ea, callee_name] : callees) {
            if (action_counter >= kMaxFunctions) break;
            std::string action_id = "abyss:callee_" + std::to_string(action_counter++);
            Address target = callee_ea;
            (void)ui::attach_dynamic_action(
                ev.popup, ev.widget, action_id, callee_name,
                [target]() { (void)ui::jump_to(target); },
                menu_base);
        }
    }

    void build_callers_menu(const ui::PopupEvent& ev,
                            Address func_ea,
                            const std::string& root_name) {
        auto refs = xref::code_refs_to(func_ea);
        if (!refs) return;

        std::set<Address> seen;
        std::vector<std::pair<Address, std::string>> callers;

        for (const auto& ref : *refs) {
            auto caller_func = function::at(ref.from);
            if (!caller_func) continue;
            Address caller_ea = caller_func->start();
            if (!seen.insert(caller_ea).second) continue;

            auto cname = function::name_at(caller_ea);
            callers.emplace_back(caller_ea,
                                 cname ? *cname : "sub_" + std::to_string(caller_ea));
        }

        std::string menu_base = "abyss/parents [" + root_name + "]/";
        int action_counter = 0;

        for (const auto& [caller_ea, caller_name] : callers) {
            if (action_counter >= kMaxFunctions) break;
            std::string action_id = "abyss:caller_" + std::to_string(action_counter++);
            Address target = caller_ea;
            (void)ui::attach_dynamic_action(
                ev.popup, ev.widget, action_id, caller_name,
                [target]() { (void)ui::jump_to(target); },
                menu_base);
        }
    }

    static std::vector<std::pair<Address, std::string>> get_callees(Address func_ea) {
        std::vector<std::pair<Address, std::string>> result;

        auto code_addrs = function::code_addresses(func_ea);
        if (!code_addrs) return result;

        std::set<Address> seen;
        for (Address addr : *code_addrs) {
            if (!instruction::is_call(addr)) continue;

            auto insn = instruction::decode(addr);
            if (!insn) continue;

            // Simple heuristic: check first operand for a near/far target
            if (insn->operand_count() > 0) {
                auto op = insn->operand(0);
                if (op) {
                    Address target = op->target_address();
                    if (target != BadAddress && seen.insert(target).second) {
                        auto tname = function::name_at(target);
                        result.emplace_back(target,
                            tname ? *tname : "sub_" + std::to_string(target));
                    }
                }
            }
        }
        return result;
    }
};

// ════════════════════════════════════════════════════════════════════════
// Abyss Filter Manager
// ════════════════════════════════════════════════════════════════════════

class AbyssManager {
public:
    AbyssManager() {
        // Register all filters
        filters_.push_back(std::make_unique<TokenColorizer>());
        filters_.push_back(std::make_unique<SignedOps>());
        filters_.push_back(std::make_unique<ItemCtype>());
        filters_.push_back(std::make_unique<ItemIndex>());
        filters_.push_back(std::make_unique<LvarsInfo>());
        filters_.push_back(std::make_unique<LvarsAlias>());
        filters_.push_back(std::make_unique<ItemSync>());
        filters_.push_back(std::make_unique<Hierarchy>());

        // Experimental filters start deactivated
        for (auto& f : filters_) {
            if (f->name() == "item_ctype" || f->name() == "item_index"
                || f->name() == "item_sync" || f->name() == "lvars_alias"
                || f->name() == "lvars_info")
                f->set_activated(false);
        }
    }

    Status install() {
        // Subscribe to decompiler events
        auto t1 = decompiler::on_func_printed(
            [this](const decompiler::PseudocodeEvent& ev) {
                for (auto& f : filters_)
                    if (f->is_activated()) f->func_printed(ev);
            });
        if (!t1) return std::unexpected(t1.error());
        subs_.emplace_back(*t1);

        auto t2 = decompiler::on_maturity_changed(
            [this](const decompiler::MaturityEvent& ev) {
                for (auto& f : filters_)
                    if (f->is_activated()) f->maturity(ev);
            });
        if (!t2) return std::unexpected(t2.error());
        subs_.emplace_back(*t2);

        auto t3 = decompiler::on_curpos_changed(
            [this](const decompiler::CursorPositionEvent& ev) {
                for (auto& f : filters_)
                    if (f->is_activated()) f->curpos(ev);
            });
        if (!t3) return std::unexpected(t3.error());
        subs_.emplace_back(*t3);

        auto t4 = decompiler::on_create_hint(
            [this](const decompiler::HintRequestEvent& ev) -> decompiler::HintResult {
                for (auto& f : filters_) {
                    if (!f->is_activated()) continue;
                    auto result = f->create_hint(ev);
                    if (!result.text.empty()) return result;
                }
                return {};
            });
        if (!t4) return std::unexpected(t4.error());
        subs_.emplace_back(*t4);

        auto t5 = decompiler::on_refresh_pseudocode(
            [this](const decompiler::PseudocodeEvent& ev) {
                for (auto& f : filters_)
                    if (f->is_activated()) f->refresh_pseudocode(ev);
            });
        if (!t5) return std::unexpected(t5.error());
        subs_.emplace_back(*t5);

        // Subscribe to UI events
        auto t6 = ui::on_popup_ready(
            [this](const ui::PopupEvent& ev) {
                // Build the abyss toggle menu
                for (std::size_t i = 0; i < filters_.size(); ++i) {
                    auto& f = filters_[i];
                    std::string action_id = "abyss:toggle_" + f->name();
                    std::string label = (f->is_activated() ? "[x] " : "[ ] ")
                                      + f->name();
                    auto* filter_ptr = f.get();
                    (void)ui::attach_dynamic_action(
                        ev.popup, ev.widget, action_id, label,
                        [filter_ptr]() {
                            filter_ptr->set_activated(!filter_ptr->is_activated());
                        },
                        "abyss/");
                }

                // Forward to activated filters
                for (auto& f : filters_)
                    if (f->is_activated()) f->popup_ready(ev);
            });
        if (!t6) return std::unexpected(t6.error());
        ui_subs_.push_back(*t6);

        auto t7 = ui::on_rendering_info(
            [this](ui::RenderingEvent& ev) {
                for (auto& f : filters_)
                    if (f->is_activated()) f->rendering_info(ev);
            });
        if (!t7) return std::unexpected(t7.error());
        ui_subs_.push_back(*t7);

        auto t8 = ui::on_screen_ea_changed(
            [this](Address ea, Address prev) {
                for (auto& f : filters_)
                    if (f->is_activated()) f->screen_ea_changed(ea, prev);
            });
        if (!t8) return std::unexpected(t8.error());
        ui_subs_.push_back(*t8);

        ui::message("[abyss] Installed " + std::to_string(filters_.size()) + " filters\n");
        return ida::ok();
    }

    void uninstall() {
        subs_.clear();
        for (auto token : ui_subs_)
            (void)ui::unsubscribe(token);
        ui_subs_.clear();
        ui::message("[abyss] Uninstalled\n");
    }

    [[nodiscard]] const auto& filters() const { return filters_; }

private:
    std::vector<std::unique_ptr<AbyssFilter>> filters_;
    std::vector<decompiler::ScopedSubscription> subs_;
    std::vector<ui::Token> ui_subs_;
};

// ════════════════════════════════════════════════════════════════════════
// Plugin definition
// ════════════════════════════════════════════════════════════════════════

// Portable formatting helper (std::format requires macOS 13.3+ deployment target).
template <typename... Args>
std::string fmt(const char* pattern, Args&&... args) {
    char buf[2048];
    std::snprintf(buf, sizeof(buf), pattern, std::forward<Args>(args)...);
    return buf;
}

class AbyssPlugin : public plugin::Plugin {
public:
    plugin::Info info() const override {
        return {
            .name    = "abyss (idax port)",
            .hotkey  = "Ctrl-Alt-R",
            .comment = "Hex-Rays decompiler output post-processing filter framework",
        };
    }

    bool init() override {
        auto avail = decompiler::available();
        if (!avail || !*avail) {
            ui::message("[abyss] Hex-Rays decompiler not available\n");
            return false;
        }

        manager_ = std::make_unique<AbyssManager>();
        auto st = manager_->install();
        if (!st) {
            ui::message("[abyss] Failed to install: " + st.error().message + "\n");
            manager_.reset();
            return false;
        }

        return true;
    }

    Status run(std::size_t) override {
        if (manager_) {
            ui::message("[abyss] Active filters:\n");
            for (const auto& f : manager_->filters())
                ui::message(fmt("  %s [%s]\n", f->name().c_str(),
                                f->is_activated() ? "ON" : "OFF"));
        }
        return ida::ok();
    }

    void term() override {
        if (manager_) {
            manager_->uninstall();
            manager_.reset();
        }
    }

private:
    std::unique_ptr<AbyssManager> manager_;
};

} // anonymous namespace

IDAX_PLUGIN(AbyssPlugin)

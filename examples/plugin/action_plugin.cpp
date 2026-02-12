/// \file action_plugin.cpp
/// \brief Quick-Reference Annotator plugin — a simple but complete plugin
///        that registers keyboard-driven actions for common annotation tasks.
///
/// Reverse engineers frequently need to:
///   - Mark the current address with a "reviewed" tag
///   - Add a numbered bookmark comment for later reference
///   - Clear all plugin-generated annotations from a range
///
/// This plugin registers three actions via the idax action API, attaches
/// them to the Edit menu, and shows how a minimal but complete plugin
/// integrates with IDA's UI.
///
/// API surface exercised:
///   plugin (Plugin, Info, Action, register/unregister/attach),
///   ui (message, screen_address), comment, name, core

#include <ida/idax.hpp>

#include <cstdint>
#include <format>
#include <string>

namespace {

constexpr const char* kMarkReviewed   = "idax:annotator:mark_reviewed";
constexpr const char* kAddBookmark    = "idax:annotator:add_bookmark";
constexpr const char* kClearMarks     = "idax:annotator:clear_marks";

/// Running counter for bookmark numbering. Resets each session.
int g_bookmark_counter = 0;

/// Mark the current screen address as "reviewed" with a repeatable comment.
ida::Status mark_reviewed() {
    auto ea = ida::ui::screen_address();
    if (!ea) {
        ida::ui::message("[Annotator] No address selected.\n");
        return ida::ok();
    }

    auto existing = ida::comment::get(*ea, true);
    if (existing && existing->find("[REVIEWED]") != std::string::npos) {
        ida::ui::message(std::format(
            "[Annotator] {:#x} is already marked as reviewed.\n", *ea));
        return ida::ok();
    }

    // Prepend a [REVIEWED] tag to the repeatable comment so it shows
    // up in xref cross-references and the disassembly listing.
    std::string tag = "[REVIEWED]";
    if (existing && !existing->empty()) {
        tag = "[REVIEWED] " + *existing;
    }

    auto st = ida::comment::set(*ea, tag, true);
    if (st) {
        ida::ui::message(std::format(
            "[Annotator] Marked {:#x} as reviewed.\n", *ea));
    }
    return ida::ok();
}

/// Add a numbered bookmark comment at the current address.
ida::Status add_bookmark() {
    auto ea = ida::ui::screen_address();
    if (!ea) {
        ida::ui::message("[Annotator] No address selected.\n");
        return ida::ok();
    }

    ++g_bookmark_counter;
    std::string bookmark = std::format("[BM#{}]", g_bookmark_counter);

    // Append the bookmark to any existing non-repeatable comment.
    auto st = ida::comment::append(*ea, bookmark, false);
    if (st) {
        ida::ui::message(std::format(
            "[Annotator] Added {} at {:#x}\n", bookmark, *ea));
    }
    return ida::ok();
}

/// Clear all plugin-generated annotations (REVIEWED tags and bookmarks)
/// from the current function's address range.
ida::Status clear_marks() {
    auto ea = ida::ui::screen_address();
    if (!ea) {
        ida::ui::message("[Annotator] No address selected.\n");
        return ida::ok();
    }

    // Determine the range: use the containing function if available,
    // otherwise just clear the single address.
    ida::Address start = *ea;
    ida::Address end = *ea + 1;

    auto func = ida::function::at(*ea);
    if (func) {
        start = func->start();
        end   = func->end();
    }

    std::size_t cleared = 0;
    for (auto addr : ida::address::ItemRange(start, end)) {
        // Check and clear repeatable [REVIEWED] comments.
        auto rep = ida::comment::get(addr, true);
        if (rep && rep->find("[REVIEWED]") != std::string::npos) {
            // Remove only the [REVIEWED] prefix, preserving user text.
            std::string cleaned = *rep;
            auto pos = cleaned.find("[REVIEWED] ");
            if (pos != std::string::npos) {
                cleaned.erase(pos, 11);
            } else {
                pos = cleaned.find("[REVIEWED]");
                if (pos != std::string::npos) cleaned.erase(pos, 10);
            }

            if (cleaned.empty()) {
                ida::comment::remove(addr, true);
            } else {
                ida::comment::set(addr, cleaned, true);
            }
            ++cleared;
        }

        // Check and clear non-repeatable [BM#...] comments.
        auto reg = ida::comment::get(addr, false);
        if (reg && reg->find("[BM#") != std::string::npos) {
            ida::comment::remove(addr, false);
            ++cleared;
        }
    }

    ida::ui::message(std::format(
        "[Annotator] Cleared {} annotations in [{:#x}, {:#x})\n",
        cleared, start, end));
    return ida::ok();
}

void register_actions() {
    ida::plugin::Action mark_action;
    mark_action.id      = kMarkReviewed;
    mark_action.label   = "Annotator: Mark Reviewed";
    mark_action.hotkey  = "Ctrl-Alt-R";
    mark_action.tooltip = "Tag the current address as reviewed";
    mark_action.handler = mark_reviewed;
    mark_action.enabled = []() { return true; };

    if (auto st = ida::plugin::register_action(mark_action); st) {
        ida::plugin::attach_to_menu("Edit/Plugins/", kMarkReviewed);
    }

    ida::plugin::Action bookmark_action;
    bookmark_action.id      = kAddBookmark;
    bookmark_action.label   = "Annotator: Add Bookmark";
    bookmark_action.hotkey  = "Ctrl-Alt-B";
    bookmark_action.tooltip = "Add a numbered bookmark at the current address";
    bookmark_action.handler = add_bookmark;
    bookmark_action.enabled = []() { return true; };

    if (auto st = ida::plugin::register_action(bookmark_action); st) {
        ida::plugin::attach_to_menu("Edit/Plugins/", kAddBookmark);
    }

    ida::plugin::Action clear_action;
    clear_action.id      = kClearMarks;
    clear_action.label   = "Annotator: Clear Marks";
    clear_action.hotkey  = "Ctrl-Alt-Shift-R";
    clear_action.tooltip = "Remove all annotator marks from the current function";
    clear_action.handler = clear_marks;
    clear_action.enabled = []() { return true; };

    if (auto st = ida::plugin::register_action(clear_action); st) {
        ida::plugin::attach_to_menu("Edit/Plugins/", kClearMarks);
    }
}

void unregister_actions() {
    ida::plugin::unregister_action(kMarkReviewed);
    ida::plugin::unregister_action(kAddBookmark);
    ida::plugin::unregister_action(kClearMarks);
}

} // anonymous namespace

// ── Plugin class ────────────────────────────────────────────────────────

struct QuickAnnotatorPlugin : ida::plugin::Plugin {
    ida::plugin::Info info() const override {
        return {
            .name    = "Quick Annotator",
            .hotkey  = "Ctrl-Alt-R",
            .comment = "Keyboard-driven review annotation tools",
            .help    = "Registers three actions: mark addresses as reviewed, "
                       "add numbered bookmarks, and clear annotations from "
                       "the current function.",
        };
    }

    bool init() override {
        register_actions();
        g_bookmark_counter = 0;
        ida::ui::message("[Annotator] Quick Annotator loaded. "
                         "Ctrl-Alt-R=review, Ctrl-Alt-B=bookmark, "
                         "Ctrl-Alt-Shift-R=clear\n");
        return true;
    }

    void term() override {
        unregister_actions();
    }

    ida::Status run(std::size_t) override {
        // The primary interface is through the registered actions.
        // Running the plugin directly marks the current address as reviewed.
        return mark_reviewed();
    }
};

/// \file ui.hpp
/// \brief UI utilities: messages, warnings, dialogs, choosers, dock widgets.

#ifndef IDAX_UI_HPP
#define IDAX_UI_HPP

#include <ida/error.hpp>
#include <ida/address.hpp>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

namespace ida::ui {

// ── Widget type constants ────────────────────────────────────────────────

/// Well-known widget types returned by widget_type().
///
/// These correspond to IDA's BWN_* constants. Values match the SDK exactly.
enum class WidgetType : int {
    Unknown        = -1,  ///< BWN_UNKNOWN
    Exports        =  0,  ///< BWN_EXPORTS
    Imports        =  1,  ///< BWN_IMPORTS
    Names          =  2,  ///< BWN_NAMES
    Functions      =  3,  ///< BWN_FUNCS
    Strings        =  4,  ///< BWN_STRINGS
    Segments       =  5,  ///< BWN_SEGS
    Segregs        =  6,  ///< BWN_SEGREGS
    Selectors      =  7,  ///< BWN_SELS
    Signatures     =  8,  ///< BWN_SIGNS
    TypeLibraries  =  9,  ///< BWN_TILS
    LocalTypes     = 10,  ///< BWN_TITREE
    Problems       = 12,  ///< BWN_PROBS
    Breakpoints    = 13,  ///< BWN_BPTS
    Threads        = 14,  ///< BWN_THREADS
    Modules        = 15,  ///< BWN_MODULES
    TraceLog       = 16,  ///< BWN_TRACE
    CallStack      = 17,  ///< BWN_CALL_STACK
    CrossRefs      = 18,  ///< BWN_XREFS
    SearchResults  = 19,  ///< BWN_SEARCH
    StackFrame     = 25,  ///< BWN_FRAME
    NavBand        = 26,  ///< BWN_NAVBAND
    Disassembly    = 27,  ///< BWN_DISASM
    HexView        = 28,  ///< BWN_HEXVIEW
    Notepad        = 29,  ///< BWN_NOTEPAD
    Output         = 30,  ///< BWN_OUTPUT
    CommandLine    = 31,  ///< BWN_CLI
    Chooser        = 35,  ///< BWN_CHOOSER
    Pseudocode     = 46,  ///< BWN_PSEUDOCODE
    Microcode      = 61,  ///< BWN_MICROCODE
};

/// Get the widget type for a raw widget host handle.
WidgetType widget_type(void* widget_handle);

// ── Messages ────────────────────────────────────────────────────────────

/// Print a message to the IDA output window.
void message(std::string_view text);

/// Show a warning dialog.
void warning(std::string_view text);

/// Show an info dialog.
void info(std::string_view text);

// ── Simple dialogs ──────────────────────────────────────────────────────

/// Ask the user a yes/no question. Returns true for yes.
Result<bool> ask_yn(std::string_view question, bool default_yes = true);

/// Ask the user for a text string.
Result<std::string> ask_string(std::string_view prompt,
                                std::string_view default_value = {});

/// Ask the user for a file path.
/// @param for_saving  If true, show a "save" dialog. Otherwise "open".
/// @param default_path  Default file path or extension filter.
/// @param prompt  Dialog title.
Result<std::string> ask_file(bool for_saving,
                              std::string_view default_path = {},
                              std::string_view prompt = {});

/// Ask the user for an address.
Result<Address> ask_address(std::string_view prompt, Address default_value = BadAddress);

/// Ask the user for a long integer value.
Result<std::int64_t> ask_long(std::string_view prompt, std::int64_t default_value = 0);

/// Show an IDA form and return whether it was accepted.
///
/// This overload is for markup-only forms that do not require typed vararg
/// bindings. Returns true when accepted, false when cancelled.
Result<bool> ask_form(std::string_view markup);

// ── Navigation ──────────────────────────────────────────────────────────

/// Navigate the active disassembly view to the given address.
/// Equivalent to double-clicking an address or pressing G and entering it.
Status jump_to(Address address);

// ── Screen/cursor queries ───────────────────────────────────────────────

/// Get the current effective address in the IDA view.
Result<Address> screen_address();

/// Get the current selection range, if any.
Result<ida::address::Range> selection();

// ── Dock widget hosting ─────────────────────────────────────────────────

/// Preferred docking position when showing a widget.
enum class DockPosition {
    Left,          ///< Dock to the left pane.
    Right,         ///< Dock to the right pane.
    Top,           ///< Dock to the top pane.
    Bottom,        ///< Dock to the bottom pane.
    Floating,      ///< Free-floating window.
    Tab,           ///< Open as a tab in the current panel.
};

/// Options controlling how a widget is displayed.
struct ShowWidgetOptions {
    DockPosition position{DockPosition::Right};
    bool         restore_previous{true};   ///< Restore last-used size/position if available.
};

/// Opaque handle to a docked widget panel.
///
/// A Widget wraps IDA's internal widget pointer without exposing it.
/// Widget instances are lightweight handles — copying is cheap but both
/// copies refer to the same underlying panel.
///
/// Typical workflow:
/// \code
///     auto widget = ida::ui::create_widget("My Panel");
///     ida::ui::show_widget(widget);
///     // ... later ...
///     ida::ui::close_widget(widget);
/// \endcode
class Widget {
public:
    Widget() = default;

    /// Whether this handle refers to a live widget.
    [[nodiscard]] bool valid() const noexcept { return impl_ != nullptr; }
    explicit operator bool() const noexcept { return valid(); }

    /// The title this widget was created with.
    [[nodiscard]] std::string title() const;

    /// Stable identity token for use in event callbacks.
    /// Two handles to the same underlying widget share the same id.
    [[nodiscard]] std::uint64_t id() const noexcept { return id_; }

    friend bool operator==(const Widget& a, const Widget& b) noexcept {
        return a.impl_ == b.impl_;
    }
    friend bool operator!=(const Widget& a, const Widget& b) noexcept {
        return !(a == b);
    }

private:
    friend struct WidgetAccess;
    void*         impl_{nullptr};
    std::uint64_t id_{0};
};

/// Get the widget type for a widget handle.
WidgetType widget_type(const Widget& widget);

/// Create a new empty docked widget with the given title.
/// The widget is not yet visible — call show_widget() to display it.
Result<Widget> create_widget(std::string_view title);

/// Create a custom text viewer backed by simple line content.
///
/// The returned widget can be shown/activated like any other widget.
Result<Widget> create_custom_viewer(std::string_view title,
                                    const std::vector<std::string>& lines);

/// Replace all lines in an existing custom text viewer.
Status set_custom_viewer_lines(Widget& viewer,
                               const std::vector<std::string>& lines);

/// Get the current number of lines in a custom text viewer.
Result<std::size_t> custom_viewer_line_count(const Widget& viewer);

/// Jump to a specific line in a custom text viewer.
Status custom_viewer_jump_to_line(Widget& viewer,
                                  std::size_t line_index,
                                  int x = 0,
                                  int y = 0);

/// Read the current line text from a custom text viewer.
Result<std::string> custom_viewer_current_line(const Widget& viewer,
                                               bool mouse = false);

/// Refresh/repaint custom viewer contents.
Status refresh_custom_viewer(Widget& viewer);

/// Close and destroy a custom viewer.
Status close_custom_viewer(Widget& viewer);

/// Display (or re-display) a widget in IDA's docking system.
Status show_widget(Widget& widget,
                   const ShowWidgetOptions& options = {});

/// Bring an already-visible widget to the foreground.
Status activate_widget(Widget& widget);

/// Find an existing widget by its title.
/// Returns an empty Widget (valid()==false) if not found.
Widget find_widget(std::string_view title);

/// Close and destroy a widget.
/// After this call the handle becomes invalid.
Status close_widget(Widget& widget);

/// Check whether a widget is currently visible on screen.
bool is_widget_visible(const Widget& widget);

/// Opaque pointer type for toolkit-native widget hosts.
///
/// In GUI builds this points to IDA's native widget container (Qt QWidget in
/// current desktop builds). The exact type is intentionally hidden.
using WidgetHost = void*;

/// Callback type used by with_widget_host().
using WidgetHostCallback = std::function<Status(WidgetHost)>;

/// Get the native host pointer for a widget.
///
/// This enables advanced embedding scenarios (for example, attaching a custom
/// Qt child widget) while keeping SDK/UI types out of the public API.
Result<WidgetHost> widget_host(const Widget& widget);

/// Execute a callback with the widget's native host pointer.
///
/// Use this helper when you need temporary host access without persisting
/// toolkit pointers in your own APIs.
Status with_widget_host(const Widget& widget, WidgetHostCallback callback);

/// Get the native host pointer cast to a specific toolkit type.
///
/// Example:
/// \code
/// auto host = ida::ui::widget_host_as<QWidget>(widget);
/// \endcode
template <typename HostType>
Result<HostType*> widget_host_as(const Widget& widget) {
    auto host = widget_host(widget);
    if (!host) {
        return std::unexpected(host.error());
    }
    if (*host == nullptr) {
        return std::unexpected(Error::internal("Widget host pointer is null"));
    }
    return static_cast<HostType*>(*host);
}

/// Execute a callback with the widget host cast to a toolkit type.
///
/// Example:
/// \code
/// ida::ui::with_widget_host_as<QWidget>(widget, [](QWidget* host) {
///     host->setLayout(new QVBoxLayout(host));
///     return ida::ok();
/// });
/// \endcode
template <typename HostType, typename Callback>
Status with_widget_host_as(const Widget& widget, Callback&& callback) {
    static_assert(std::is_invocable_r_v<Status, Callback, HostType*>,
                  "Callback must be callable as Status(HostType*)");

    auto typed_host = widget_host_as<HostType>(widget);
    if (!typed_host) {
        return std::unexpected(typed_host.error());
    }
    return std::forward<Callback>(callback)(*typed_host);
}

// ── Chooser ─────────────────────────────────────────────────────────────

/// Column data type hint for a chooser column.
enum class ColumnFormat {
    Plain,         ///< Free-form string.
    Path,          ///< File path (truncated from start).
    Hex,           ///< Hex number.
    Decimal,       ///< Decimal number.
    Address,       ///< Effective address.
    FunctionName,  ///< Function name (auto-colored).
};

/// Describes a single column in a chooser.
struct Column {
    std::string  name;
    int          width{10};
    ColumnFormat format{ColumnFormat::Plain};
};

/// Per-row styling for a chooser item.
struct RowStyle {
    bool          bold{false};
    bool          italic{false};
    bool          strikethrough{false};
    bool          gray{false};
    std::uint32_t background_color{0};  ///< 0 = default.
};

/// A single row of data in a chooser.
struct Row {
    std::vector<std::string> columns;
    int                      icon{-1};
    RowStyle                 style;
};

/// Options for constructing a Chooser.
struct ChooserOptions {
    std::string          title;
    std::vector<Column>  columns;
    bool                 modal{false};
    bool                 can_insert{false};
    bool                 can_delete{false};
    bool                 can_edit{false};
    bool                 can_refresh{true};
};

/// Base class for custom choosers (list dialogs).
///
/// Subclass and override count() and row(). Optionally override callbacks
/// for insert/delete/edit/enter/close.
///
/// Example:
/// \code
/// class MyChooser : public ida::ui::Chooser {
/// public:
///     MyChooser()
///         : Chooser({.title = "My Items", .columns = {{"Name", 20}, {"Value", 10}}}) {}
///
///     std::size_t count() const override { return items_.size(); }
///     Row row(std::size_t index) const override {
///         return {{items_[index].name, items_[index].value}};
///     }
/// };
/// \endcode
class Chooser {
public:
    explicit Chooser(ChooserOptions options);
    virtual ~Chooser();

    Chooser(const Chooser&) = delete;
    Chooser& operator=(const Chooser&) = delete;

    /// Number of items in the list.
    virtual std::size_t count() const = 0;

    /// Get row data for item at \p index.
    virtual Row row(std::size_t index) const = 0;

    /// Get the address associated with row \p index (for Enter-to-jump).
    /// Return BadAddress if no associated address.
    virtual ida::Address address_for(std::size_t index) const {
        (void)index; return BadAddress;
    }

    // ── Optional callbacks ──────────────────────────────────────────────

    /// Called when the user wants to insert a new item.
    virtual void on_insert(std::size_t before_index) { (void)before_index; }

    /// Called when the user wants to delete an item.
    virtual void on_delete(std::size_t index) { (void)index; }

    /// Called when the user wants to edit an item.
    virtual void on_edit(std::size_t index) { (void)index; }

    /// Called when the user presses Enter on an item.
    virtual void on_enter(std::size_t index) { (void)index; }

    /// Called when the chooser is refreshed.
    virtual void on_refresh() {}

    /// Called when the chooser is about to close.
    virtual void on_close() {}

    // ── Display ─────────────────────────────────────────────────────────

    /// Show the chooser. For modal choosers, returns the selected index.
    /// For non-modal choosers, opens the window and returns nullopt.
    Result<std::optional<std::size_t>> show(std::size_t default_selection = 0);

    /// Refresh the chooser contents.
    Status refresh();

    /// Close the chooser.
    Status close();

    /// Get the options.
    [[nodiscard]] const ChooserOptions& options() const { return options_; }

private:
    struct Impl;
    Impl*          impl_{nullptr};
    ChooserOptions options_;
};

// ── Timer ───────────────────────────────────────────────────────────────

/// Register a periodic timer callback.
/// @param interval_ms  Interval in milliseconds.
/// @param callback  Called periodically. Return non-zero to cancel.
/// @return A token for unregistering.
Result<std::uint64_t> register_timer(int interval_ms,
                                      std::function<int()> callback);

/// Unregister a timer.
Status unregister_timer(std::uint64_t token);

// ── UI event subscriptions ──────────────────────────────────────────────

/// Token returned by UI event subscription functions.
using Token = std::uint64_t;

/// Generic UI/view event kind for broad routing subscriptions.
enum class EventKind {
    DatabaseInited,
    DatabaseClosed,
    ReadyToRun,
    CurrentWidgetChanged,
    ScreenAddressChanged,
    WidgetVisible,
    WidgetInvisible,
    WidgetClosing,
    ViewActivated,
    ViewDeactivated,
    ViewCreated,
    ViewClosed,
    CursorChanged,
};

/// Normalized UI/view event payload for generic subscriptions.
struct Event {
    EventKind kind{};

    /// Address payload (for cursor/screen-address events).
    Address address{BadAddress};

    /// Previous address for ScreenAddressChanged.
    Address previous_address{BadAddress};

    /// Previous widget for CurrentWidgetChanged.
    Widget previous_widget{};

    /// Set for DatabaseInited.
    bool is_new_database{false};
    std::string startup_script;

    /// Widget payload (for widget visibility/lifecycle events).
    Widget widget{};
    std::string widget_title;
};

/// Subscribe to the "database closed" event.
Result<Token> on_database_closed(std::function<void()> callback);

/// Subscribe to "database initialized" event.
/// Callback receives `(is_new_database, startup_script_path)`.
Result<Token> on_database_inited(std::function<void(bool, std::string)> callback);

/// Subscribe to the "ready to run" event (all UI elements initialized).
Result<Token> on_ready_to_run(std::function<void()> callback);

/// Subscribe to "current screen EA changed" event.
/// Callback receives (new_ea, prev_ea).
Result<Token> on_screen_ea_changed(std::function<void(Address, Address)> callback);

/// Subscribe to "current widget changed" event.
/// Callback receives `(current_widget, previous_widget)`.
Result<Token> on_current_widget_changed(std::function<void(Widget, Widget)> callback);

// ── Title-based widget events (global) ──────────────────────────────────
// These fire for ALL widgets and deliver the widget title as a string.

/// Subscribe to "widget visible" event.
/// Callback receives the title of the widget.
Result<Token> on_widget_visible(std::function<void(std::string)> callback);

/// Subscribe to "widget invisible" (hidden) event.
/// Callback receives the title of the widget.
Result<Token> on_widget_invisible(std::function<void(std::string)> callback);

/// Subscribe to "widget closing" event.
/// Callback receives the title of the widget.
Result<Token> on_widget_closing(std::function<void(std::string)> callback);

// ── Handle-based widget events (targeted) ───────────────────────────────
// These fire only for the specific widget and deliver the Widget handle.
// Prefer these over title-based events for stable per-panel tracking.

/// Subscribe to "widget visible" for a specific widget.
Result<Token> on_widget_visible(const Widget& widget,
                                std::function<void(Widget)> callback);

/// Subscribe to "widget invisible" (hidden) for a specific widget.
Result<Token> on_widget_invisible(const Widget& widget,
                                  std::function<void(Widget)> callback);

/// Subscribe to "widget closing" for a specific widget.
Result<Token> on_widget_closing(const Widget& widget,
                                std::function<void(Widget)> callback);

// ── View events ─────────────────────────────────────────────────────────
// These subscribe to IDA's HT_VIEW notification layer.

/// Subscribe to "cursor position changed" in any view.
/// Callback receives the address the cursor moved to.
Result<Token> on_cursor_changed(std::function<void(Address)> callback);

/// Subscribe to view activation/deactivation/lifecycle events.
Result<Token> on_view_activated(std::function<void(Widget)> callback);
Result<Token> on_view_deactivated(std::function<void(Widget)> callback);
Result<Token> on_view_created(std::function<void(Widget)> callback);
Result<Token> on_view_closed(std::function<void(Widget)> callback);

/// Subscribe to all supported UI/view events through one callback.
Result<Token> on_event(std::function<void(const Event&)> callback);

/// Subscribe to all supported UI/view events with a predicate filter.
/// Callback is invoked only when `filter(event)` returns true.
Result<Token> on_event_filtered(std::function<bool(const Event&)> filter,
                                std::function<void(const Event&)> callback);

/// Unsubscribe from a UI or view event.
Status unsubscribe(Token token);

/// RAII guard that unsubscribes on destruction.
class ScopedSubscription {
public:
    ScopedSubscription() = default;
    explicit ScopedSubscription(Token token) : token_(token) {}
    ~ScopedSubscription() { if (token_ != 0) unsubscribe(token_); }

    ScopedSubscription(const ScopedSubscription&) = delete;
    ScopedSubscription& operator=(const ScopedSubscription&) = delete;
    ScopedSubscription(ScopedSubscription&& o) noexcept : token_(o.token_) { o.token_ = 0; }
    ScopedSubscription& operator=(ScopedSubscription&& o) noexcept {
        if (this != &o) { if (token_ != 0) unsubscribe(token_); token_ = o.token_; o.token_ = 0; }
        return *this;
    }

    [[nodiscard]] Token token() const noexcept { return token_; }

private:
    Token token_{0};
};

// ── Popup menu interception ─────────────────────────────────────────────

/// Opaque handle to a popup menu being constructed.
/// Valid only during on_popup_ready callbacks.
using PopupHandle = void*;

/// Event payload for finish_populating_widget_popup.
struct PopupEvent {
    Widget      widget;       ///< The widget whose popup is being built.
    PopupHandle popup{nullptr}; ///< Opaque popup menu handle.
    WidgetType  type{WidgetType::Unknown};
};

/// Subscribe to the "finish populating widget popup" event.
///
/// This fires when IDA finishes building a context (right-click) menu for
/// any widget. Use attach_dynamic_action() within the callback to add
/// custom menu items.
Result<Token> on_popup_ready(std::function<void(const PopupEvent&)> callback);

/// Dynamically attach an action to a popup menu being constructed.
///
/// Must be called during an on_popup_ready callback. The action is
/// registered on-the-fly and attached to the popup at the given menu path.
///
/// @param popup   Popup handle from PopupEvent.
/// @param widget  Widget from PopupEvent.
/// @param action_id  Unique action identifier.
/// @param label   Display text for the menu item.
/// @param handler Action handler callback.
/// @param menu_path  Popup submenu path (e.g. "abyss/" for nested menus).
/// @param icon    Icon index (-1 = no icon).
Status attach_dynamic_action(PopupHandle popup,
                             const Widget& widget,
                             std::string_view action_id,
                             std::string_view label,
                             std::function<void()> handler,
                             std::string_view menu_path = {},
                             int icon = -1);

// ── Line rendering ──────────────────────────────────────────────────────

/// A single line rendering overlay entry.
///
/// Used within on_rendering_info callbacks to add character-range
/// background highlights to view lines (pseudocode, disassembly, etc.).
struct LineRenderEntry {
    int           line_number{0};    ///< Line number in the view (0-based).
    std::uint32_t bg_color{0};       ///< Background color (0xBBGGRR).
    int           start_column{0};   ///< Start character column.
    int           length{0};         ///< Number of characters to highlight.
    bool          character_range{false}; ///< If true, highlight a specific column range.
};

/// Event payload for get_lines_rendering_info.
struct RenderingEvent {
    Widget widget;
    WidgetType type{WidgetType::Unknown};

    /// Call add_entry() to inject background highlighting.
    /// The entries are collected and applied to the view.
    std::vector<LineRenderEntry> entries;
};

/// Subscribe to the "get lines rendering info" event.
///
/// This fires when IDA renders view lines and enables custom background
/// highlighting. Mutate `event.entries` in the callback to add overlays.
Result<Token> on_rendering_info(std::function<void(RenderingEvent&)> callback);

// ── Miscellaneous utilities ─────────────────────────────────────────────

/// Get the user's IDA configuration directory (e.g. ~/.idapro on Linux).
Result<std::string> user_directory();

/// Force all IDA views to repaint immediately.
void refresh_all_views();

} // namespace ida::ui

#endif // IDAX_UI_HPP

/// \file ui.cpp
/// \brief Implementation of ida::ui — messages, warnings, dialogs, choosers,
///        dock widgets, navigation, and event subscriptions.

#include "detail/sdk_bridge.hpp"
#include <ida/ui.hpp>
#include <mutex>
#include <atomic>
#include <memory>
#include <unordered_map>

namespace ida::ui {

// ── Messages ────────────────────────────────────────────────────────────

void message(std::string_view text) {
    // msg() is a printf-style function. Use %s to avoid format-string issues.
    ::msg("%.*s", static_cast<int>(text.size()), text.data());
}

void warning(std::string_view text) {
    qstring qtxt = ida::detail::to_qstring(text);
    ::warning("%s", qtxt.c_str());
}

void info(std::string_view text) {
    qstring qtxt = ida::detail::to_qstring(text);
    ::info("%s", qtxt.c_str());
}

// ── Simple dialogs ──────────────────────────────────────────────────────

Result<bool> ask_yn(std::string_view question, bool default_yes) {
    qstring qtxt = ida::detail::to_qstring(question);
    int deflt = default_yes ? ASKBTN_YES : ASKBTN_NO;
    int result = ::ask_yn(deflt, "%s", qtxt.c_str());
    if (result == ASKBTN_CANCEL)
        return std::unexpected(Error::validation("User cancelled dialog"));
    return result == ASKBTN_YES;
}

Result<std::string> ask_string(std::string_view prompt,
                                std::string_view default_value) {
    qstring buf = ida::detail::to_qstring(default_value);
    qstring qprompt = ida::detail::to_qstring(prompt);
    if (!::ask_str(&buf, HIST_IDENT, "%s", qprompt.c_str()))
        return std::unexpected(Error::validation("User cancelled input"));
    return ida::detail::to_string(buf);
}

Result<std::string> ask_file(bool for_saving,
                              std::string_view default_path,
                              std::string_view prompt) {
    qstring qdp = ida::detail::to_qstring(default_path);
    qstring qpr = ida::detail::to_qstring(prompt);
    const char* result = ::ask_file(for_saving ? 1 : 0,
                                     qdp.empty() ? nullptr : qdp.c_str(),
                                     "%s",
                                     qpr.empty() ? "Choose file" : qpr.c_str());
    if (result == nullptr)
        return std::unexpected(Error::validation("User cancelled file dialog"));
    return std::string(result);
}

Result<Address> ask_address(std::string_view prompt, Address default_value) {
    ea_t ea = static_cast<ea_t>(default_value);
    qstring qpr = ida::detail::to_qstring(prompt);
    if (!::ask_addr(&ea, "%s", qpr.c_str()))
        return std::unexpected(Error::validation("User cancelled address input"));
    return static_cast<Address>(ea);
}

Result<std::int64_t> ask_long(std::string_view prompt, std::int64_t default_value) {
    sval_t val = static_cast<sval_t>(default_value);
    qstring qpr = ida::detail::to_qstring(prompt);
    if (!::ask_long(&val, "%s", qpr.c_str()))
        return std::unexpected(Error::validation("User cancelled number input"));
    return static_cast<std::int64_t>(val);
}

Result<bool> ask_form(std::string_view markup) {
    if (markup.empty())
        return std::unexpected(Error::validation("Form markup cannot be empty"));

    qstring qmarkup = ida::detail::to_qstring(markup);
    int rc = ::ask_form(qmarkup.c_str());
    if (rc < 0)
        return std::unexpected(Error::sdk("ask_form failed"));
    return rc > 0;
}

// ── Navigation ──────────────────────────────────────────────────────────

Status jump_to(Address address) {
    if (address == BadAddress)
        return std::unexpected(Error::validation("Cannot jump to BadAddress"));
    if (!jumpto(static_cast<ea_t>(address)))
        return std::unexpected(Error::sdk("jumpto failed",
                                          std::to_string(address)));
    return ida::ok();
}

// ── Screen/cursor queries ───────────────────────────────────────────────

Result<Address> screen_address() {
    ea_t ea = get_screen_ea();
    if (ea == BADADDR)
        return std::unexpected(Error::not_found("No current address"));
    return static_cast<Address>(ea);
}

Result<ida::address::Range> selection() {
    ea_t start = BADADDR, end = BADADDR;
    if (!read_range_selection(nullptr, &start, &end))
        return std::unexpected(Error::not_found("No selection"));
    return ida::address::Range{static_cast<Address>(start),
                                static_cast<Address>(end)};
}

// ── Dock widget hosting ─────────────────────────────────────────────────

namespace {

// Monotonically increasing ID for widget identity tracking.
std::atomic<std::uint64_t> g_next_widget_id{1};

struct CustomViewerState {
    strvec_t lines;
    simpleline_place_t min;
    simpleline_place_t max;
    simpleline_place_t cur;
};

std::mutex g_custom_viewers_mutex;
std::unordered_map<TWidget*, std::unique_ptr<CustomViewerState>> g_custom_viewers;

bool has_custom_viewer_state(TWidget* viewer) {
    std::lock_guard<std::mutex> lock(g_custom_viewers_mutex);
    return g_custom_viewers.find(viewer) != g_custom_viewers.end();
}

void erase_custom_viewer_state(TWidget* viewer) {
    std::lock_guard<std::mutex> lock(g_custom_viewers_mutex);
    g_custom_viewers.erase(viewer);
}

Result<std::unique_ptr<CustomViewerState>> make_custom_viewer_state(
        const std::vector<std::string>& lines) {
    if (lines.size() > static_cast<std::size_t>(INT_MAX))
        return std::unexpected(Error::validation("Too many lines for custom viewer",
                                                 std::to_string(lines.size())));

    auto state = std::make_unique<CustomViewerState>();
    if (lines.empty()) {
        state->lines.push_back(simpleline_t(""));
    } else {
        state->lines.reserve(lines.size());
        for (const auto& line : lines)
            state->lines.push_back(simpleline_t(line.c_str()));
    }

    state->min = simpleline_place_t(0);
    state->max = simpleline_place_t(static_cast<int>(state->lines.size() - 1));
    state->cur = state->min;
    return state;
}

} // anonymous namespace

struct WidgetAccess {
    static Widget make(TWidget* tw) {
        Widget w;
        w.impl_ = static_cast<void*>(tw);
        w.id_   = g_next_widget_id.fetch_add(1, std::memory_order_relaxed);
        return w;
    }
    static Widget wrap(TWidget* tw, std::uint64_t existing_id = 0) {
        if (tw == nullptr)
            return Widget{};
        Widget w;
        w.impl_ = static_cast<void*>(tw);
        w.id_   = existing_id != 0 ? existing_id
                                    : g_next_widget_id.fetch_add(1, std::memory_order_relaxed);
        return w;
    }
    static TWidget* raw(const Widget& w) {
        return static_cast<TWidget*>(w.impl_);
    }
};

std::string Widget::title() const {
    if (!impl_) return {};
    qstring qtitle;
    get_widget_title(&qtitle, static_cast<TWidget*>(impl_));
    return ida::detail::to_string(qtitle);
}

namespace {

uint32 dock_position_to_flags(DockPosition pos, bool restore) {
    uint32 flags = 0;
    switch (pos) {
    case DockPosition::Left:     flags = WOPN_DP_LEFT;   break;
    case DockPosition::Right:    flags = WOPN_DP_RIGHT;  break;
    case DockPosition::Top:      flags = WOPN_DP_TOP;    break;
    case DockPosition::Bottom:   flags = WOPN_DP_BOTTOM; break;
    case DockPosition::Floating: flags = WOPN_DP_FLOATING;  break;
    case DockPosition::Tab:      flags = WOPN_DP_TAB;    break;
    }
    if (restore)
        flags |= WOPN_RESTORE;
    return flags;
}

} // anonymous namespace

Result<Widget> create_widget(std::string_view title) {
    std::string stitle(title);
    TWidget* tw = create_empty_widget(stitle.c_str());
    if (tw == nullptr)
        return std::unexpected(Error::sdk("create_empty_widget failed",
                                          stitle));
    return WidgetAccess::make(tw);
}

Result<Widget> create_custom_viewer(std::string_view title,
                                    const std::vector<std::string>& lines) {
    std::string stitle(title);
    if (stitle.empty())
        return std::unexpected(Error::validation("Viewer title cannot be empty"));

    auto state_r = make_custom_viewer_state(lines);
    if (!state_r)
        return std::unexpected(state_r.error());

    auto state = std::move(*state_r);

    TWidget* tw = ::create_custom_viewer(stitle.c_str(),
                                         &state->min,
                                         &state->max,
                                         &state->cur,
                                         nullptr,
                                         &state->lines,
                                         nullptr,
                                         nullptr,
                                         nullptr);
    if (tw == nullptr)
        return std::unexpected(Error::sdk("create_custom_viewer failed", stitle));

    {
        std::lock_guard<std::mutex> lock(g_custom_viewers_mutex);
        g_custom_viewers[tw] = std::move(state);
    }

    return WidgetAccess::make(tw);
}

Status set_custom_viewer_lines(Widget& viewer,
                               const std::vector<std::string>& lines) {
    TWidget* tw = WidgetAccess::raw(viewer);
    if (tw == nullptr)
        return std::unexpected(Error::validation("Widget handle is invalid"));

    auto state_r = make_custom_viewer_state(lines);
    if (!state_r)
        return std::unexpected(state_r.error());

    {
        std::lock_guard<std::mutex> lock(g_custom_viewers_mutex);
        auto it = g_custom_viewers.find(tw);
        if (it == g_custom_viewers.end())
            return std::unexpected(Error::validation("Widget is not a custom viewer"));
        it->second = std::move(*state_r);
        ::set_custom_viewer_range(tw, &it->second->min, &it->second->max);
    }

    ::refresh_custom_viewer(tw);
    return ida::ok();
}

Result<std::size_t> custom_viewer_line_count(const Widget& viewer) {
    TWidget* tw = WidgetAccess::raw(viewer);
    if (tw == nullptr)
        return std::unexpected(Error::validation("Widget handle is invalid"));

    std::lock_guard<std::mutex> lock(g_custom_viewers_mutex);
    auto it = g_custom_viewers.find(tw);
    if (it == g_custom_viewers.end())
        return std::unexpected(Error::validation("Widget is not a custom viewer"));

    return it->second->lines.size();
}

Status custom_viewer_jump_to_line(Widget& viewer,
                                  std::size_t line_index,
                                  int x,
                                  int y) {
    TWidget* tw = WidgetAccess::raw(viewer);
    if (tw == nullptr)
        return std::unexpected(Error::validation("Widget handle is invalid"));

    {
        std::lock_guard<std::mutex> lock(g_custom_viewers_mutex);
        auto it = g_custom_viewers.find(tw);
        if (it == g_custom_viewers.end())
            return std::unexpected(Error::validation("Widget is not a custom viewer"));
        if (line_index >= it->second->lines.size())
            return std::unexpected(Error::not_found("Line index out of range",
                                                    std::to_string(line_index)));
    }

    if (line_index > static_cast<std::size_t>(INT_MAX))
        return std::unexpected(Error::not_found("Line index out of range",
                                                std::to_string(line_index)));

    simpleline_place_t place(static_cast<int>(line_index));
    if (!::jumpto(tw, &place, x, y))
        return std::unexpected(Error::sdk("jumpto(custom viewer) failed",
                                          std::to_string(line_index)));
    return ida::ok();
}

Result<std::string> custom_viewer_current_line(const Widget& viewer,
                                               bool mouse) {
    TWidget* tw = WidgetAccess::raw(viewer);
    if (tw == nullptr)
        return std::unexpected(Error::validation("Widget handle is invalid"));

    if (!has_custom_viewer_state(tw))
        return std::unexpected(Error::validation("Widget is not a custom viewer"));

    const char* line = ::get_custom_viewer_curline(tw, mouse);
    if (line == nullptr)
        return std::unexpected(Error::not_found("No current line in custom viewer"));
    return std::string(line);
}

Status refresh_custom_viewer(Widget& viewer) {
    TWidget* tw = WidgetAccess::raw(viewer);
    if (tw == nullptr)
        return std::unexpected(Error::validation("Widget handle is invalid"));

    if (!has_custom_viewer_state(tw))
        return std::unexpected(Error::validation("Widget is not a custom viewer"));

    ::refresh_custom_viewer(tw);
    ::repaint_custom_viewer(tw);
    return ida::ok();
}

Status close_custom_viewer(Widget& viewer) {
    TWidget* tw = WidgetAccess::raw(viewer);
    if (tw == nullptr)
        return std::unexpected(Error::validation("Widget handle is invalid"));

    if (!has_custom_viewer_state(tw))
        return std::unexpected(Error::validation("Widget is not a custom viewer"));

    ::destroy_custom_viewer(tw);
    erase_custom_viewer_state(tw);
    viewer = Widget{};
    return ida::ok();
}

Status show_widget(Widget& widget, const ShowWidgetOptions& options) {
    TWidget* tw = WidgetAccess::raw(widget);
    if (tw == nullptr)
        return std::unexpected(Error::validation("Widget handle is invalid"));
    uint32 flags = dock_position_to_flags(options.position,
                                           options.restore_previous);
    display_widget(tw, flags);
    return ida::ok();
}

Status activate_widget(Widget& widget) {
    TWidget* tw = WidgetAccess::raw(widget);
    if (tw == nullptr)
        return std::unexpected(Error::validation("Widget handle is invalid"));
    ::activate_widget(tw, true);
    return ida::ok();
}

Widget find_widget(std::string_view title) {
    std::string stitle(title);
    TWidget* tw = ::find_widget(stitle.c_str());
    if (tw == nullptr)
        return Widget{}; // invalid handle
    return WidgetAccess::make(tw);
}

Status close_widget(Widget& widget) {
    TWidget* tw = WidgetAccess::raw(widget);
    if (tw == nullptr)
        return std::unexpected(Error::validation("Widget handle is invalid"));
    ::close_widget(tw, 0);
    erase_custom_viewer_state(tw);
    widget = Widget{}; // invalidate
    return ida::ok();
}

bool is_widget_visible(const Widget& widget) {
    TWidget* tw = WidgetAccess::raw(widget);
    if (tw == nullptr)
        return false;
    // A widget is visible if find_widget with its title returns the same pointer.
    qstring qtitle;
    get_widget_title(&qtitle, tw);
    TWidget* found = ::find_widget(qtitle.c_str());
    return found == tw;
}

Result<WidgetHost> widget_host(const Widget& widget) {
    TWidget* tw = WidgetAccess::raw(widget);
    if (tw == nullptr)
        return std::unexpected(Error::validation("Widget handle is invalid"));
    return static_cast<WidgetHost>(tw);
}

Status with_widget_host(const Widget& widget, WidgetHostCallback callback) {
    if (!callback)
        return std::unexpected(Error::validation("Widget host callback is empty"));
    auto host = widget_host(widget);
    if (!host)
        return std::unexpected(host.error());
    auto result = callback(*host);
    if (!result)
        return std::unexpected(result.error());
    return ida::ok();
}

// ── Chooser ─────────────────────────────────────────────────────────────

// Internal SDK chooser adapter that bridges to our Chooser base class.
namespace {

class ChooserAdapter : public chooser_t {
public:
    ida::ui::Chooser* owner;

    ChooserAdapter(ida::ui::Chooser* owner_,
                   uint32 flags_,
                   int ncols,
                   const int* widths_,
                   const char* const* headers_,
                   const char* title_)
        : chooser_t(flags_, ncols, widths_, headers_, title_)
        , owner(owner_) {}

    size_t idaapi get_count() const override {
        return owner->count();
    }

    void idaapi get_row(qstrvec_t* out, int* out_icon,
                        chooser_item_attrs_t* out_attrs,
                        size_t n) const override {
        auto row = owner->row(n);

        if (out) {
            out->resize(row.columns.size());
            for (std::size_t i = 0; i < row.columns.size(); ++i)
                (*out)[i] = ida::detail::to_qstring(row.columns[i]);
        }
        if (out_icon)
            *out_icon = row.icon;
        if (out_attrs) {
            uint32 f = 0;
            if (row.style.bold)          f |= CHITEM_BOLD;
            if (row.style.italic)        f |= CHITEM_ITALIC;
            if (row.style.strikethrough) f |= CHITEM_STRIKE;
            if (row.style.gray)          f |= CHITEM_GRAY;
            out_attrs->flags = f;
            if (row.style.background_color != 0)
                out_attrs->color = static_cast<bgcolor_t>(row.style.background_color);
        }
    }

    ea_t idaapi get_ea(size_t n) const override {
        return static_cast<ea_t>(owner->address_for(n));
    }

    cbret_t idaapi ins(ssize_t n) override {
        owner->on_insert(n >= 0 ? static_cast<std::size_t>(n) : 0);
        return {n, ALL_CHANGED};
    }

    cbret_t idaapi del(size_t n) override {
        owner->on_delete(n);
        return {ssize_t(n), ALL_CHANGED};
    }

    cbret_t idaapi edit(size_t n) override {
        owner->on_edit(n);
        return {ssize_t(n), ALL_CHANGED};
    }

    cbret_t idaapi enter(size_t n) override {
        owner->on_enter(n);
        return {};
    }

    cbret_t idaapi refresh(ssize_t n) override {
        owner->on_refresh();
        return {n, ALL_CHANGED};
    }

    void idaapi closed() override {
        owner->on_close();
    }
};

// Column format to CHCOL_ flags.
int column_format_to_chcol(ColumnFormat fmt) {
    switch (fmt) {
    case ColumnFormat::Plain:        return CHCOL_PLAIN;
    case ColumnFormat::Path:         return CHCOL_PATH;
    case ColumnFormat::Hex:          return CHCOL_HEX;
    case ColumnFormat::Decimal:      return CHCOL_DEC;
    case ColumnFormat::Address:      return CHCOL_EA;
    case ColumnFormat::FunctionName: return CHCOL_FNAME;
    default:                         return CHCOL_PLAIN;
    }
}

} // anonymous namespace

struct Chooser::Impl {
    // Stored widths and header strings for the lifetime of the adapter.
    std::vector<int>         widths;
    std::vector<std::string> header_strs;
    std::vector<const char*> header_ptrs;
    ChooserAdapter*          adapter{nullptr};

    ~Impl() {
        // The adapter is deleted by IDA's chooser framework when the widget
        // closes (unless CH_KEEP is set). We set CH_KEEP to manage lifetime.
        delete adapter;
    }
};

Chooser::Chooser(ChooserOptions options)
    : impl_(new Impl)
    , options_(std::move(options))
{
    auto& cols = options_.columns;

    // Build column widths array (width | CHCOL flags in high bits).
    impl_->widths.resize(cols.size());
    for (std::size_t i = 0; i < cols.size(); ++i)
        impl_->widths[i] = cols[i].width | column_format_to_chcol(cols[i].format);

    // Build header strings array.
    impl_->header_strs.resize(cols.size());
    impl_->header_ptrs.resize(cols.size());
    for (std::size_t i = 0; i < cols.size(); ++i) {
        impl_->header_strs[i] = cols[i].name;
        impl_->header_ptrs[i] = impl_->header_strs[i].c_str();
    }

    // Build flags.
    uint32 flags = CH_KEEP;  // We manage adapter lifetime.
    if (options_.modal)       flags |= CH_MODAL;
    if (options_.can_insert)  flags |= CH_CAN_INS;
    if (options_.can_delete)  flags |= CH_CAN_DEL;
    if (options_.can_edit)    flags |= CH_CAN_EDIT;
    if (options_.can_refresh) flags |= CH_CAN_REFRESH;
    flags |= CH_ATTRS;  // Enable per-row styling.

    impl_->adapter = new ChooserAdapter(
        this,
        flags,
        static_cast<int>(cols.size()),
        impl_->widths.data(),
        impl_->header_ptrs.data(),
        options_.title.c_str()
    );
}

Chooser::~Chooser() {
    delete impl_;
}

Result<std::optional<std::size_t>> Chooser::show(std::size_t default_selection) {
    if (!impl_ || !impl_->adapter)
        return std::unexpected(Error::internal("Chooser not initialized"));

    ssize_t result = impl_->adapter->choose(static_cast<ssize_t>(default_selection));

    if (result == chooser_base_t::NO_SELECTION)
        return std::nullopt;
    if (result == chooser_base_t::EMPTY_CHOOSER)
        return std::nullopt;
    if (result < 0)
        return std::nullopt;

    return static_cast<std::size_t>(result);
}

Status Chooser::refresh() {
    if (!impl_)
        return std::unexpected(Error::internal("Chooser not initialized"));
    if (!refresh_chooser(options_.title.c_str()))
        return std::unexpected(Error::sdk("refresh_chooser failed"));
    return ida::ok();
}

Status Chooser::close() {
    if (!impl_)
        return std::unexpected(Error::internal("Chooser not initialized"));
    if (!close_chooser(options_.title.c_str()))
        return std::unexpected(Error::sdk("close_chooser failed"));
    return ida::ok();
}

// ── Timer ───────────────────────────────────────────────────────────────

namespace {

struct TimerState {
    std::function<int()> callback;
    qtimer_t timer{nullptr};
};

int idaapi timer_adapter(void* ud) {
    auto* state = static_cast<TimerState*>(ud);
    if (!state || !state->callback) return -1;
    return state->callback();
}

// Simple registry for timers to keep them alive.
std::vector<TimerState*> g_timers;

} // anonymous namespace

Result<std::uint64_t> register_timer(int interval_ms,
                                      std::function<int()> callback) {
    auto* state = new TimerState{std::move(callback)};
    state->timer = ::register_timer(interval_ms, timer_adapter, state);
    if (state->timer == nullptr) {
        delete state;
        return std::unexpected(Error::sdk("register_timer failed"));
    }
    g_timers.push_back(state);
    auto token = reinterpret_cast<std::uint64_t>(state);
    return token;
}

Status unregister_timer(std::uint64_t token) {
    auto* state = reinterpret_cast<TimerState*>(token);
    if (!state || !state->timer)
        return std::unexpected(Error::validation("Invalid timer token"));
    if (!::unregister_timer(state->timer))
        return std::unexpected(Error::sdk("unregister_timer failed"));

    // Remove from registry.
    std::erase(g_timers, state);
    delete state;
    return ida::ok();
}

// ── Event subscription infrastructure ───────────────────────────────────

namespace {

/// Unified listener that supports multiple hook types (HT_UI, HT_VIEW).
/// Each hook type gets its own singleton instance.
class EventListener : public event_listener_t {
public:
    struct Subscription {
        Token token;
        int notification_code;
        std::function<void(va_list)> handler;
    };

    explicit EventListener(hook_type_t type) : type_(type) {}

    Token subscribe(int code, std::function<void(va_list)> handler) {
        std::lock_guard<std::mutex> lock(mutex_);
        ensure_hooked();
        Token token = ++next_token_;
        subs_.push_back({token, code, std::move(handler)});
        return token;
    }

    bool unsubscribe(Token token) {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto it = subs_.begin(); it != subs_.end(); ++it) {
            if (it->token == token) {
                subs_.erase(it);
                if (subs_.empty())
                    ensure_unhooked();
                return true;
            }
        }
        return false;
    }

    ssize_t idaapi on_event(ssize_t code, va_list va) override {
        // Copy matching handlers to avoid holding lock during callbacks.
        std::vector<std::function<void(va_list)>> matched;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            for (auto& s : subs_) {
                if (s.notification_code == static_cast<int>(code))
                    matched.push_back(s.handler);
            }
        }
        for (auto& h : matched) {
            va_list copy;
            va_copy(copy, va);
            h(copy);
            va_end(copy);
        }
        return 0;
    }

private:
    void ensure_hooked() {
        if (!hooked_) {
            hook_event_listener(type_, this, nullptr);
            hooked_ = true;
        }
    }

    void ensure_unhooked() {
        if (hooked_) {
            unhook_event_listener(type_, this);
            hooked_ = false;
        }
    }

    hook_type_t type_;
    std::mutex mutex_;
    std::vector<Subscription> subs_;
    Token next_token_{0};
    bool hooked_{false};
};

// Singleton listeners per hook type.
EventListener& ui_listener() {
    static EventListener inst(HT_UI);
    return inst;
}

EventListener& view_listener() {
    static EventListener inst(HT_VIEW);
    return inst;
}

// Token range partitioning: UI tokens in [1, 1<<62), VIEW tokens in [1<<62, 2<<62).
// This lets unsubscribe() route to the correct listener.
constexpr Token VIEW_TOKEN_BASE = Token{1} << 62;
constexpr Token GENERIC_TOKEN_BASE = Token{1} << 63;

std::mutex g_generic_routes_mutex;
std::unordered_map<Token, std::vector<Token>> g_generic_routes;
Token g_next_generic_token{0};

Token make_generic_token() {
    ++g_next_generic_token;
    return GENERIC_TOKEN_BASE + g_next_generic_token;
}

bool unsubscribe_single(Token token) {
    if (token >= VIEW_TOKEN_BASE && token < GENERIC_TOKEN_BASE)
        return view_listener().unsubscribe(token - VIEW_TOKEN_BASE);
    return ui_listener().unsubscribe(token);
}

} // anonymous namespace

// ── UI event subscriptions (global) ─────────────────────────────────────

Result<Token> on_database_closed(std::function<void()> callback) {
    auto token = ui_listener().subscribe(
        ui_database_closed,
        [cb = std::move(callback)](va_list) { cb(); }
    );
    return token;
}

Result<Token> on_database_inited(std::function<void(bool, std::string)> callback) {
    auto token = ui_listener().subscribe(
        ui_database_inited,
        [cb = std::move(callback)](va_list va) {
            int is_new = va_arg(va, int);
            const char* script = va_arg(va, const char*);
            cb(is_new != 0, script != nullptr ? std::string(script) : std::string());
        }
    );
    return token;
}

Result<Token> on_ready_to_run(std::function<void()> callback) {
    auto token = ui_listener().subscribe(
        ui_ready_to_run,
        [cb = std::move(callback)](va_list) { cb(); }
    );
    return token;
}

Result<Token> on_screen_ea_changed(std::function<void(Address, Address)> callback) {
    auto token = ui_listener().subscribe(
        ui_screen_ea_changed,
        [cb = std::move(callback)](va_list va) {
            ea_t new_ea = va_arg(va, ea_t);
            ea_t prev_ea = va_arg(va, ea_t);
            cb(static_cast<Address>(new_ea), static_cast<Address>(prev_ea));
        }
    );
    return token;
}

Result<Token> on_current_widget_changed(std::function<void(Widget, Widget)> callback) {
    auto token = ui_listener().subscribe(
        ui_current_widget_changed,
        [cb = std::move(callback)](va_list va) {
            TWidget* current = va_arg(va, TWidget*);
            TWidget* previous = va_arg(va, TWidget*);
            cb(WidgetAccess::wrap(current), WidgetAccess::wrap(previous));
        }
    );
    return token;
}

// ── Title-based widget events ───────────────────────────────────────────

Result<Token> on_widget_visible(std::function<void(std::string)> callback) {
    auto token = ui_listener().subscribe(
        ui_widget_visible,
        [cb = std::move(callback)](va_list va) {
            TWidget* widget = va_arg(va, TWidget*);
            qstring qtitle;
            get_widget_title(&qtitle, widget);
            cb(ida::detail::to_string(qtitle));
        }
    );
    return token;
}

Result<Token> on_widget_invisible(std::function<void(std::string)> callback) {
    auto token = ui_listener().subscribe(
        ui_widget_invisible,
        [cb = std::move(callback)](va_list va) {
            TWidget* widget = va_arg(va, TWidget*);
            qstring qtitle;
            get_widget_title(&qtitle, widget);
            cb(ida::detail::to_string(qtitle));
        }
    );
    return token;
}

Result<Token> on_widget_closing(std::function<void(std::string)> callback) {
    auto token = ui_listener().subscribe(
        ui_widget_closing,
        [cb = std::move(callback)](va_list va) {
            TWidget* widget = va_arg(va, TWidget*);
            qstring qtitle;
            get_widget_title(&qtitle, widget);
            cb(ida::detail::to_string(qtitle));
        }
    );
    return token;
}

// ── Handle-based widget events ──────────────────────────────────────────

Result<Token> on_widget_visible(const Widget& widget,
                                std::function<void(Widget)> callback) {
    if (!widget.valid())
        return std::unexpected(Error::validation("Widget handle is invalid"));

    void* target = WidgetAccess::raw(widget);
    std::uint64_t wid = widget.id();

    auto token = ui_listener().subscribe(
        ui_widget_visible,
        [cb = std::move(callback), target, wid](va_list va) {
            TWidget* w = va_arg(va, TWidget*);
            if (static_cast<void*>(w) == target)
                cb(WidgetAccess::wrap(w, wid));
        }
    );
    return token;
}

Result<Token> on_widget_invisible(const Widget& widget,
                                  std::function<void(Widget)> callback) {
    if (!widget.valid())
        return std::unexpected(Error::validation("Widget handle is invalid"));

    void* target = WidgetAccess::raw(widget);
    std::uint64_t wid = widget.id();

    auto token = ui_listener().subscribe(
        ui_widget_invisible,
        [cb = std::move(callback), target, wid](va_list va) {
            TWidget* w = va_arg(va, TWidget*);
            if (static_cast<void*>(w) == target)
                cb(WidgetAccess::wrap(w, wid));
        }
    );
    return token;
}

Result<Token> on_widget_closing(const Widget& widget,
                                std::function<void(Widget)> callback) {
    if (!widget.valid())
        return std::unexpected(Error::validation("Widget handle is invalid"));

    void* target = WidgetAccess::raw(widget);
    std::uint64_t wid = widget.id();

    auto token = ui_listener().subscribe(
        ui_widget_closing,
        [cb = std::move(callback), target, wid](va_list va) {
            TWidget* w = va_arg(va, TWidget*);
            if (static_cast<void*>(w) == target)
                cb(WidgetAccess::wrap(w, wid));
        }
    );
    return token;
}

// ── View events ─────────────────────────────────────────────────────────

Result<Token> on_cursor_changed(std::function<void(Address)> callback) {
    auto raw_token = view_listener().subscribe(
        static_cast<int>(view_curpos),
        [cb = std::move(callback)](va_list) {
            // view_curpos provides no va_list payload — the new cursor
            // position is obtained through get_screen_ea().
            ea_t ea = get_screen_ea();
            if (ea != BADADDR)
                cb(static_cast<Address>(ea));
        }
    );
    // Offset the token so unsubscribe can route to the correct listener.
    return raw_token + VIEW_TOKEN_BASE;
}

Result<Token> on_view_activated(std::function<void(Widget)> callback) {
    auto raw_token = view_listener().subscribe(
        static_cast<int>(view_activated),
        [cb = std::move(callback)](va_list va) {
            TWidget* view = va_arg(va, TWidget*);
            cb(WidgetAccess::wrap(view));
        }
    );
    return raw_token + VIEW_TOKEN_BASE;
}

Result<Token> on_view_deactivated(std::function<void(Widget)> callback) {
    auto raw_token = view_listener().subscribe(
        static_cast<int>(view_deactivated),
        [cb = std::move(callback)](va_list va) {
            TWidget* view = va_arg(va, TWidget*);
            cb(WidgetAccess::wrap(view));
        }
    );
    return raw_token + VIEW_TOKEN_BASE;
}

Result<Token> on_view_created(std::function<void(Widget)> callback) {
    auto raw_token = view_listener().subscribe(
        static_cast<int>(view_created),
        [cb = std::move(callback)](va_list va) {
            TWidget* view = va_arg(va, TWidget*);
            cb(WidgetAccess::wrap(view));
        }
    );
    return raw_token + VIEW_TOKEN_BASE;
}

Result<Token> on_view_closed(std::function<void(Widget)> callback) {
    auto raw_token = view_listener().subscribe(
        static_cast<int>(view_close),
        [cb = std::move(callback)](va_list va) {
            TWidget* view = va_arg(va, TWidget*);
            cb(WidgetAccess::wrap(view));
        }
    );
    return raw_token + VIEW_TOKEN_BASE;
}

Result<Token> on_event(std::function<void(const Event&)> callback) {
    if (!callback)
        return std::unexpected(Error::validation("Event callback is empty"));

    std::vector<Token> inner_tokens;
    inner_tokens.reserve(13);

    inner_tokens.push_back(ui_listener().subscribe(
        ui_database_inited,
        [cb = callback](va_list va) {
            int is_new = va_arg(va, int);
            const char* script = va_arg(va, const char*);
            Event ev;
            ev.kind = EventKind::DatabaseInited;
            ev.is_new_database = is_new != 0;
            if (script != nullptr)
                ev.startup_script = script;
            cb(ev);
        }));

    inner_tokens.push_back(ui_listener().subscribe(
        ui_database_closed,
        [cb = callback](va_list) {
            Event ev;
            ev.kind = EventKind::DatabaseClosed;
            cb(ev);
        }));

    inner_tokens.push_back(ui_listener().subscribe(
        ui_ready_to_run,
        [cb = callback](va_list) {
            Event ev;
            ev.kind = EventKind::ReadyToRun;
            cb(ev);
        }));

    inner_tokens.push_back(ui_listener().subscribe(
        ui_screen_ea_changed,
        [cb = callback](va_list va) {
            ea_t new_ea = va_arg(va, ea_t);
            ea_t prev_ea = va_arg(va, ea_t);
            Event ev;
            ev.kind = EventKind::ScreenAddressChanged;
            ev.address = static_cast<Address>(new_ea);
            ev.previous_address = static_cast<Address>(prev_ea);
            cb(ev);
        }));

    inner_tokens.push_back(ui_listener().subscribe(
        ui_current_widget_changed,
        [cb = callback](va_list va) {
            TWidget* widget = va_arg(va, TWidget*);
            TWidget* previous = va_arg(va, TWidget*);
            Event ev;
            ev.kind = EventKind::CurrentWidgetChanged;
            ev.widget = WidgetAccess::wrap(widget);
            ev.previous_widget = WidgetAccess::wrap(previous);
            cb(ev);
        }));

    inner_tokens.push_back(ui_listener().subscribe(
        ui_widget_visible,
        [cb = callback](va_list va) {
            TWidget* widget = va_arg(va, TWidget*);
            Event ev;
            ev.kind = EventKind::WidgetVisible;
            ev.widget = WidgetAccess::wrap(widget);
            qstring qtitle;
            get_widget_title(&qtitle, widget);
            ev.widget_title = ida::detail::to_string(qtitle);
            cb(ev);
        }));

    inner_tokens.push_back(ui_listener().subscribe(
        ui_widget_invisible,
        [cb = callback](va_list va) {
            TWidget* widget = va_arg(va, TWidget*);
            Event ev;
            ev.kind = EventKind::WidgetInvisible;
            ev.widget = WidgetAccess::wrap(widget);
            qstring qtitle;
            get_widget_title(&qtitle, widget);
            ev.widget_title = ida::detail::to_string(qtitle);
            cb(ev);
        }));

    inner_tokens.push_back(ui_listener().subscribe(
        ui_widget_closing,
        [cb = callback](va_list va) {
            TWidget* widget = va_arg(va, TWidget*);
            Event ev;
            ev.kind = EventKind::WidgetClosing;
            ev.widget = WidgetAccess::wrap(widget);
            qstring qtitle;
            get_widget_title(&qtitle, widget);
            ev.widget_title = ida::detail::to_string(qtitle);
            cb(ev);
        }));

    Token view_token = view_listener().subscribe(
        static_cast<int>(view_curpos),
        [cb = callback](va_list) {
            Event ev;
            ev.kind = EventKind::CursorChanged;
            ea_t ea = get_screen_ea();
            if (ea != BADADDR)
                ev.address = static_cast<Address>(ea);
            cb(ev);
        });
    inner_tokens.push_back(view_token + VIEW_TOKEN_BASE);

    Token view_activated_token = view_listener().subscribe(
        static_cast<int>(view_activated),
        [cb = callback](va_list va) {
            TWidget* view = va_arg(va, TWidget*);
            Event ev;
            ev.kind = EventKind::ViewActivated;
            ev.widget = WidgetAccess::wrap(view);
            cb(ev);
        });
    inner_tokens.push_back(view_activated_token + VIEW_TOKEN_BASE);

    Token view_deactivated_token = view_listener().subscribe(
        static_cast<int>(view_deactivated),
        [cb = callback](va_list va) {
            TWidget* view = va_arg(va, TWidget*);
            Event ev;
            ev.kind = EventKind::ViewDeactivated;
            ev.widget = WidgetAccess::wrap(view);
            cb(ev);
        });
    inner_tokens.push_back(view_deactivated_token + VIEW_TOKEN_BASE);

    Token view_created_token = view_listener().subscribe(
        static_cast<int>(view_created),
        [cb = callback](va_list va) {
            TWidget* view = va_arg(va, TWidget*);
            Event ev;
            ev.kind = EventKind::ViewCreated;
            ev.widget = WidgetAccess::wrap(view);
            cb(ev);
        });
    inner_tokens.push_back(view_created_token + VIEW_TOKEN_BASE);

    Token view_closed_token = view_listener().subscribe(
        static_cast<int>(view_close),
        [cb = callback](va_list va) {
            TWidget* view = va_arg(va, TWidget*);
            Event ev;
            ev.kind = EventKind::ViewClosed;
            ev.widget = WidgetAccess::wrap(view);
            cb(ev);
        });
    inner_tokens.push_back(view_closed_token + VIEW_TOKEN_BASE);

    Token outer_token = make_generic_token();
    {
        std::lock_guard<std::mutex> lock(g_generic_routes_mutex);
        g_generic_routes.emplace(outer_token, std::move(inner_tokens));
    }

    return outer_token;
}

Result<Token> on_event_filtered(std::function<bool(const Event&)> filter,
                                std::function<void(const Event&)> callback) {
    if (!filter)
        return std::unexpected(Error::validation("Event filter is empty"));
    if (!callback)
        return std::unexpected(Error::validation("Event callback is empty"));

    return on_event(
        [flt = std::move(filter), cb = std::move(callback)](const Event& ev) {
            if (flt(ev))
                cb(ev);
        });
}

// ── Unified unsubscribe ─────────────────────────────────────────────────

Status unsubscribe(Token token) {
    if (token == 0)
        return std::unexpected(Error::validation("Invalid subscription token (0)"));

    if (token >= GENERIC_TOKEN_BASE) {
        std::vector<Token> inner_tokens;
        {
            std::lock_guard<std::mutex> lock(g_generic_routes_mutex);
            auto it = g_generic_routes.find(token);
            if (it == g_generic_routes.end()) {
                return std::unexpected(Error::not_found("UI/view subscription not found",
                                                        std::to_string(token)));
            }
            inner_tokens = std::move(it->second);
            g_generic_routes.erase(it);
        }

        for (Token inner : inner_tokens)
            unsubscribe_single(inner);

        return ida::ok();
    }

    bool removed = unsubscribe_single(token);

    if (!removed)
        return std::unexpected(Error::not_found("UI/view subscription not found",
                                                std::to_string(token)));
    return ida::ok();
}

// ── Widget type ─────────────────────────────────────────────────────────

WidgetType widget_type(const Widget& widget) {
    TWidget* tw = WidgetAccess::raw(widget);
    if (tw == nullptr)
        return WidgetType::Unknown;
    int t = get_widget_type(tw);
    return static_cast<WidgetType>(t);
}

WidgetType widget_type(void* widget_handle) {
    if (widget_handle == nullptr)
        return WidgetType::Unknown;
    int t = get_widget_type(static_cast<TWidget*>(widget_handle));
    return static_cast<WidgetType>(t);
}

// ── Popup menu interception ─────────────────────────────────────────────

Result<Token> on_popup_ready(std::function<void(const PopupEvent&)> callback) {
    if (!callback)
        return std::unexpected(Error::validation("Popup callback is empty"));

    auto raw_token = ui_listener().subscribe(
        ui_finish_populating_widget_popup,
        [cb = std::move(callback)](va_list va) {
            TWidget* w = va_arg(va, TWidget*);
            TPopupMenu* popup = va_arg(va, TPopupMenu*);
            // third arg: const action_activation_ctx_t* ctx — unused here

            PopupEvent evt;
            evt.widget = WidgetAccess::wrap(w);
            evt.popup = static_cast<void*>(popup);
            if (w != nullptr)
                evt.type = static_cast<WidgetType>(get_widget_type(w));
            cb(evt);
        }
    );
    return raw_token;
}

namespace {

/// Dynamic action handler bridge: wraps a std::function<void()> into an
/// action_handler_t that IDA can manage. Allocated with new; IDA deletes it
/// when the action is unregistered (ADF_OWN_HANDLER semantics).
class DynamicActionHandler : public action_handler_t {
public:
    explicit DynamicActionHandler(std::function<void()> handler)
        : handler_(std::move(handler)) {}

    int idaapi activate(action_activation_ctx_t*) override {
        if (handler_)
            handler_();
        return 1;  // Refresh
    }

    action_state_t idaapi update(action_update_ctx_t*) override {
        return AST_ENABLE_ALWAYS;
    }

private:
    std::function<void()> handler_;
};

} // anonymous namespace

Status attach_dynamic_action(PopupHandle popup,
                             const Widget& /*widget*/,
                             std::string_view action_id,
                             std::string_view label,
                             std::function<void()> handler,
                             std::string_view menu_path,
                             int icon) {
    if (popup == nullptr)
        return std::unexpected(Error::validation("Popup handle is null"));
    if (!handler)
        return std::unexpected(Error::validation("Action handler is empty"));

    auto* popup_menu = static_cast<TPopupMenu*>(popup);

    // The handler is allocated with new; IDA will delete it via ADF_OWN_HANDLER.
    auto* h = new DynamicActionHandler(std::move(handler));

    // Build null-terminated strings from string_views (they may not be null-terminated).
    std::string lbl(label);
    std::string path_str(menu_path);
    (void)action_id;  // not used with DYNACTION_DESC_LITERAL

    action_desc_t desc = DYNACTION_DESC_LITERAL(
        lbl.c_str(),
        h,
        nullptr,  // shortcut
        nullptr,  // tooltip
        icon >= 0 ? icon : -1
    );

    bool ok = attach_dynamic_action_to_popup(
        nullptr,  // deprecated widget param
        popup_menu,
        desc,
        path_str.empty() ? nullptr : path_str.c_str(),
        0,
        nullptr
    );

    if (!ok)
        return std::unexpected(Error::sdk("attach_dynamic_action_to_popup failed"));

    return ida::ok();
}

// ── Line rendering ──────────────────────────────────────────────────────

Result<Token> on_rendering_info(std::function<void(RenderingEvent&)> callback) {
    if (!callback)
        return std::unexpected(Error::validation("Rendering callback is empty"));

    auto raw_token = ui_listener().subscribe(
        ui_get_lines_rendering_info,
        [cb = std::move(callback)](va_list va) {
            auto* out = va_arg(va, lines_rendering_output_t*);
            auto* w = va_arg(va, const TWidget*);
            auto* info = va_arg(va, const lines_rendering_input_t*);

            if (out == nullptr || w == nullptr || info == nullptr)
                return;

            RenderingEvent evt;
            evt.widget = WidgetAccess::wrap(const_cast<TWidget*>(w));
            evt.type = static_cast<WidgetType>(
                get_widget_type(const_cast<TWidget*>(w)));

            cb(evt);

            // Translate entries back into SDK rendering output.
            for (const auto& entry : evt.entries) {
                // Find the twinline_t for this line number.
                // The sections_lines contains references to lines per section.
                const twinline_t* tl = nullptr;
                int line_counter = 0;
                for (std::size_t s = 0; s < info->sections_lines.size() && tl == nullptr; ++s) {
                    const auto& section = info->sections_lines[s];
                    for (std::size_t l = 0; l < section.size(); ++l) {
                        if (line_counter == entry.line_number) {
                            tl = section[l];
                            break;
                        }
                        ++line_counter;
                    }
                }
                if (tl == nullptr)
                    continue;

                line_rendering_output_entry_t* sdk_entry = nullptr;
                if (entry.character_range) {
                    sdk_entry = new line_rendering_output_entry_t(
                        tl, entry.start_column, entry.length,
                        LROEF_CPS_RANGE, static_cast<bgcolor_t>(entry.bg_color));
                } else {
                    sdk_entry = new line_rendering_output_entry_t(
                        tl, LROEF_FULL_LINE, static_cast<bgcolor_t>(entry.bg_color));
                }
                out->entries.push_back(sdk_entry);
            }
        }
    );
    return raw_token;
}

// ── Miscellaneous utilities ─────────────────────────────────────────────

Result<std::string> user_directory() {
    const char* dir = get_user_idadir();
    if (dir == nullptr || dir[0] == '\0')
        return std::unexpected(Error::sdk("get_user_idadir returned empty"));
    return std::string(dir);
}

void refresh_all_views() {
    refresh_idaview_anyway();
}

} // namespace ida::ui

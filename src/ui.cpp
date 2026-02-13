/// \file ui.cpp
/// \brief Implementation of ida::ui — messages, warnings, dialogs, choosers,
///        dock widgets, navigation, and event subscriptions.

#include "detail/sdk_bridge.hpp"
#include <ida/ui.hpp>
#include <mutex>
#include <atomic>

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

} // anonymous namespace

struct WidgetAccess {
    static Widget make(TWidget* tw) {
        Widget w;
        w.impl_ = static_cast<void*>(tw);
        w.id_   = g_next_widget_id.fetch_add(1, std::memory_order_relaxed);
        return w;
    }
    static Widget wrap(TWidget* tw, std::uint64_t existing_id = 0) {
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
        for (auto& h : matched)
            h(va);
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

} // anonymous namespace

// ── UI event subscriptions (global) ─────────────────────────────────────

Result<Token> on_database_closed(std::function<void()> callback) {
    auto token = ui_listener().subscribe(
        ui_database_closed,
        [cb = std::move(callback)](va_list) { cb(); }
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

// ── Unified unsubscribe ─────────────────────────────────────────────────

Status unsubscribe(Token token) {
    if (token == 0)
        return std::unexpected(Error::validation("Invalid subscription token (0)"));

    bool removed = false;
    if (token >= VIEW_TOKEN_BASE) {
        removed = view_listener().unsubscribe(token - VIEW_TOKEN_BASE);
    } else {
        removed = ui_listener().unsubscribe(token);
    }

    if (!removed)
        return std::unexpected(Error::not_found("UI/view subscription not found",
                                                std::to_string(token)));
    return ida::ok();
}

} // namespace ida::ui

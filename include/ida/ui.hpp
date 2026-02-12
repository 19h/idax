/// \file ui.hpp
/// \brief UI utilities: messages, warnings, dialogs, choosers.

#ifndef IDAX_UI_HPP
#define IDAX_UI_HPP

#include <ida/error.hpp>
#include <ida/address.hpp>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace ida::ui {

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

// ── Screen/cursor queries ───────────────────────────────────────────────

/// Get the current effective address in the IDA view.
Result<Address> screen_address();

/// Get the current selection range, if any.
Result<ida::address::Range> selection();

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

    // ── Internal ────────────────────────────────────────────────────────
    struct Impl;
    Impl* impl() const { return impl_; }

private:
    ChooserOptions options_;
    Impl*          impl_{nullptr};
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

} // namespace ida::ui

#endif // IDAX_UI_HPP

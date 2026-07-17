/// \file navigation.hpp
/// \brief Opaque persistent address navigation history.

#ifndef IDAX_NAVIGATION_HPP
#define IDAX_NAVIGATION_HPP

#include <ida/address.hpp>
#include <ida/error.hpp>

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace ida::navigation {

/// Owned snapshot of one semantic navigation location.
struct Entry {
    Address address{BadAddress};
    std::string channel;
    std::string metadata;

    friend bool operator==(const Entry&, const Entry&) = default;
};

/// Copyable semantic handle to one persistent, IDAX-private history stream.
class History {
  public:
    /// Open or create a logical stream with one initial tip.
    static Result<History> open(std::string_view name, const Entry& initial);

    /// Return the caller-visible logical name, not the native stream key.
    [[nodiscard]] const std::string& name() const noexcept { return name_; }
    /// Report whether this handle's open call created the stream.
    [[nodiscard]] bool created() const noexcept { return created_; }

    /// Copy every stack entry in index order.
    Result<std::vector<Entry>> entries() const;
    /// Copy the number of stack entries.
    Result<std::size_t> size() const;
    /// Copy the current stack index.
    Result<std::size_t> index() const;
    /// Copy the entry at the current stack index.
    Result<Entry> current() const;

    /// Copy the current location for a semantic channel, or absence.
    Result<std::optional<Entry>> current_for(std::string_view channel) const;
    /// Copy every channel-current location; ordering is host-defined.
    Result<std::vector<Entry>> all_current() const;

    /// Update one channel's current location.
    ///
    /// When `record_in_history` is true, also replace the stack entry at the
    /// current index. This operation never appends.
    Status set_current(const Entry& entry,
                       bool record_in_history = false) const;

    /// Append after the cursor, truncating any forward entries.
    Result<Entry> push(const Entry& entry) const;
    /// Move the cursor to an exact existing index.
    Result<Entry> seek(std::size_t index) const;
    /// Move backward, or return absence when the boundary would be crossed.
    Result<std::optional<Entry>> back(std::size_t count = 1) const;
    /// Move forward, or return absence when the boundary would be crossed.
    Result<std::optional<Entry>> forward(std::size_t count = 1) const;

    /// Replace one indexed entry without changing size or cursor.
    Status replace(std::size_t index, const Entry& entry) const;
    /// Replace the complete stack with one tip at index zero.
    Status clear(const Entry& new_tip) const;

    /// Move one channel from this stream to `destination`.
    ///
    /// Source ownership is always removed. With `retain_history == true`,
    /// matching source entries append to the destination; otherwise they are
    /// discarded. Destination channel conflicts are rejected before mutation.
    Status transfer_channel_to(const History& destination,
                               std::string_view channel,
                               bool retain_history = true) const;

  private:
    History(std::string name, Entry initial, bool created)
        : name_(std::move(name)), initial_(std::move(initial)),
          created_(created) {}

    std::string name_;
    Entry initial_;
    bool created_{false};
};

} // namespace ida::navigation

#endif // IDAX_NAVIGATION_HPP

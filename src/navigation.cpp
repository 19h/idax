/// \file navigation.cpp
/// \brief Implementation of opaque persistent address navigation history.

#include "detail/sdk_bridge.hpp"

#include <ida/navigation.hpp>

#include <netnode.hpp>
#include <moves.hpp>

#include <algorithm>
#include <cstdint>
#include <iterator>
#include <limits>
#include <memory>
#include <string>
#include <unordered_map>

namespace ida::navigation {

namespace {

constexpr std::string_view NativeStreamPrefix{"$ idax navigation/"};
constexpr std::string_view PrivateChannelPrefix{"$ idax navigation/"};
constexpr std::string_view BootstrapChannel{"$ idax navigation/bootstrap"};

Status validate_text(std::string_view value, std::string_view field,
                     bool allow_empty) {
    if (!allow_empty && value.empty()) {
        return std::unexpected(
            Error::validation(std::string(field) + " cannot be empty"));
    }
    if (value.find('\0') != std::string_view::npos) {
        return std::unexpected(Error::validation(
            std::string(field) + " contains an embedded NUL byte"));
    }
    return ok();
}

Status validate_channel(std::string_view channel) {
    if (auto status = validate_text(channel, "Navigation channel", false);
        !status)
        return status;
    if (channel.starts_with(PrivateChannelPrefix)) {
        return std::unexpected(Error::validation(
            "Navigation channel uses the reserved IDAX namespace"));
    }
    return ok();
}

Status validate_entry(const Entry& entry) {
    if (entry.address == BadAddress) {
        return std::unexpected(
            Error::validation("Navigation address cannot be BadAddress"));
    }
    if (auto status = validate_channel(entry.channel); !status)
        return status;
    return validate_text(entry.metadata, "Navigation metadata", true);
}

Result<std::uint32_t> native_index(std::size_t index, std::string_view field) {
    if (index > std::numeric_limits<std::uint32_t>::max()) {
        return std::unexpected(Error::validation(
            std::string(field) + " exceeds the native index range",
            std::to_string(index)));
    }
    return static_cast<std::uint32_t>(index);
}

std::string native_stream_name(std::string_view logical_name) {
    std::string result;
    result.reserve(NativeStreamPrefix.size() + logical_name.size());
    result.append(NativeStreamPrefix);
    result.append(logical_name);
    return result;
}

navstack_entry_t make_native(const Entry& entry) {
    const idaplace_t place(static_cast<ea_t>(entry.address),
                           DEFAULT_PLACE_LNNUM);
    navstack_entry_t result(&place, renderer_info_t{},
                            detail::to_qstring(entry.channel));
    result.ud_str = detail::to_qstring(entry.metadata);
    return result;
}

Result<navstack_entry_t> to_native(const Entry& entry) {
    if (auto status = validate_entry(entry); !status)
        return std::unexpected(status.error());
    return make_native(entry);
}

Result<Entry> from_native(const navstack_entry_t& entry) {
    const place_t* place = entry.place();
    if (place == nullptr || place->toea() == BADADDR) {
        return std::unexpected(
            Error::sdk("Navigation history contains an invalid location"));
    }
    Entry result{
        static_cast<Address>(place->toea()),
        detail::to_string(entry.widget_id),
        detail::to_string(entry.ud_str),
    };
    if (auto status = validate_entry(result); !status) {
        return std::unexpected(
            Error::sdk("Navigation history contains invalid semantic state",
                       status.error().message + ":" + status.error().context));
    }
    return result;
}

struct Snapshot {
    std::vector<Entry> entries;
    std::vector<Entry> current;
    std::size_t index{0};
};

struct Session {
    std::unique_ptr<navstack_t> stack;
    bool created{false};
};

Result<std::vector<Entry>> copy_entries(const navstack_t& stack) {
    const std::uint32_t count = stack.stack_size();
    std::vector<Entry> result;
    result.reserve(count);
    for (std::uint32_t index = 0; index < count; ++index) {
        navstack_entry_t native;
        if (!stack.get_stack_entry(&native, index)) {
            return std::unexpected(
                Error::sdk("Failed to copy navigation history entry",
                           std::to_string(index)));
        }
        auto converted = from_native(native);
        if (!converted)
            return std::unexpected(converted.error());
        result.push_back(std::move(*converted));
    }
    return result;
}

Result<std::vector<Entry>> copy_current(const navstack_t& stack) {
    navstack_entry_vec_t native;
    stack.get_all_current(&native);
    std::vector<Entry> result;
    result.reserve(native.size());
    for (const auto& value : native) {
        const std::string channel = detail::to_string(value.widget_id);
        if (channel.starts_with(PrivateChannelPrefix))
            continue;
        auto converted = from_native(value);
        if (!converted)
            return std::unexpected(converted.error());
        result.push_back(std::move(*converted));
    }
    return result;
}

Result<Snapshot> snapshot(const navstack_t& stack) {
    auto entries = copy_entries(stack);
    if (!entries)
        return std::unexpected(entries.error());
    if (entries->empty()) {
        return std::unexpected(
            Error::sdk("Enabled navigation history has no stack entries"));
    }
    const std::uint32_t index = stack.stack_index();
    if (index >= entries->size()) {
        return std::unexpected(Error::sdk(
            "Navigation history cursor is outside the stack",
            std::to_string(index) + ":" + std::to_string(entries->size())));
    }
    auto current = copy_current(stack);
    if (!current)
        return std::unexpected(current.error());
    return Snapshot{std::move(*entries), std::move(*current), index};
}

Result<Session> acquire_unchecked(const std::string& logical_name,
                                  const Entry& initial) {
    const Entry bootstrap{initial.address, std::string(BootstrapChannel), {}};
    auto native_bootstrap = make_native(bootstrap);
    auto stack = std::make_unique<navstack_t>();
    const std::string stream = native_stream_name(logical_name);
    const bool created = stack->init(&native_bootstrap, stream.c_str(), 0);
    if (!stack->is_history_enabled()) {
        return std::unexpected(
            Error::sdk("Navigation history unexpectedly disabled"));
    }
    if (created) {
        auto native_initial = to_native(initial);
        if (!native_initial)
            return std::unexpected(native_initial.error());
        stack->stack_clear(*native_initial);
        stack->set_current(*native_initial, false);
    }
    return Session{std::move(stack), created};
}

Result<Session> acquire(const std::string& logical_name, const Entry& initial) {
    auto session = acquire_unchecked(logical_name, initial);
    if (!session)
        return std::unexpected(session.error());
    auto state = snapshot(*session->stack);
    if (!state)
        return std::unexpected(state.error());
    if (session->created && (state->entries.size() != 1 || state->index != 0 ||
                             state->entries.front() != initial)) {
        return std::unexpected(Error::sdk(
            "New navigation history did not preserve its initial tip"));
    }
    return session;
}

bool current_maps_equal(const std::vector<Entry>& lhs,
                        const std::vector<Entry>& rhs) {
    if (lhs.size() != rhs.size())
        return false;
    std::unordered_map<std::string, Entry> expected;
    expected.reserve(lhs.size());
    for (const auto& entry : lhs)
        expected.emplace(entry.channel, entry);
    if (expected.size() != lhs.size())
        return false;
    for (const auto& entry : rhs) {
        const auto found = expected.find(entry.channel);
        if (found == expected.end() || found->second != entry)
            return false;
    }
    return true;
}

bool snapshots_equal(const Snapshot& lhs, const Snapshot& rhs) {
    return lhs.entries == rhs.entries && lhs.index == rhs.index &&
           current_maps_equal(lhs.current, rhs.current);
}

std::string describe_snapshot(const Snapshot& value) {
    std::string result = "index=" + std::to_string(value.index) + ",entries=";
    for (const auto& entry : value.entries) {
        result += entry.channel + "@" + std::to_string(entry.address) + "#" +
                  entry.metadata + ";";
    }
    result += ",current=";
    for (const auto& entry : value.current) {
        result += entry.channel + "@" + std::to_string(entry.address) + "#" +
                  entry.metadata + ";";
    }
    return result;
}

Status restore(navstack_t& stack, const Snapshot& expected) {
    if (expected.entries.empty()) {
        return std::unexpected(
            Error::internal("Cannot restore an empty navigation stack"));
    }
    auto tip = to_native(expected.entries.front());
    if (!tip)
        return std::unexpected(tip.error());
    stack.stack_clear(*tip);
    for (std::size_t index = 1; index < expected.entries.size(); ++index) {
        auto value = to_native(expected.entries[index]);
        if (!value)
            return std::unexpected(value.error());
        stack.stack_jump(false, *value);
    }
    navstack_entry_t moved;
    if (!stack.stack_seek(&moved, static_cast<std::uint32_t>(expected.index),
                          false)) {
        return std::unexpected(
            Error::sdk("Failed to restore navigation history cursor"));
    }
    for (const auto& value : expected.current) {
        auto native = to_native(value);
        if (!native)
            return std::unexpected(native.error());
        stack.set_current(*native, false);
    }
    auto actual = snapshot(stack);
    if (!actual)
        return std::unexpected(actual.error());
    if (!snapshots_equal(*actual, expected)) {
        return std::unexpected(Error::sdk(
            "Restored navigation history differs from requested state"));
    }
    return ok();
}

Status normalize_cursor_without_current(navstack_t& stack,
                                        const std::vector<Entry>& entries,
                                        std::size_t index) {
    auto actual_entries = copy_entries(stack);
    if (!actual_entries)
        return std::unexpected(actual_entries.error());
    if (*actual_entries != entries) {
        return std::unexpected(Error::sdk(
            "Transferred navigation entries differ from expected state"));
    }
    if (index >= entries.size()) {
        return std::unexpected(
            Error::internal("Requested navigation cursor is out of range"));
    }
    if (stack.stack_index() != index) {
        auto native = native_index(index, "Navigation history index");
        if (!native)
            return std::unexpected(native.error());
        navstack_entry_t moved;
        if (!navstack_t_stack_seek(stack, &moved, *native, false, false)) {
            return std::unexpected(Error::sdk(
                "Failed to normalize transferred navigation cursor"));
        }
        auto converted = from_native(moved);
        if (!converted)
            return std::unexpected(converted.error());
        if (*converted != entries[index]) {
            return std::unexpected(Error::sdk(
                "Normalized navigation cursor returned the wrong entry"));
        }
    }
    if (stack.stack_index() != index) {
        return std::unexpected(Error::sdk(
            "Transferred navigation cursor differs from expected state"));
    }
    return ok();
}

Error mutation_with_rollback_error(std::string_view operation,
                                   const Error& failure,
                                   const Error& rollback) {
    return Error::sdk(std::string(operation) + " and rollback both failed",
                      failure.message + ":" + failure.context + ";" +
                          rollback.message + ":" + rollback.context);
}

std::vector<Entry> without_channel(const std::vector<Entry>& values,
                                   std::string_view channel) {
    std::vector<Entry> result;
    result.reserve(values.size());
    std::copy_if(
        values.begin(), values.end(), std::back_inserter(result),
        [channel](const Entry& entry) { return entry.channel != channel; });
    return result;
}

std::optional<Entry> find_channel(const std::vector<Entry>& values,
                                  std::string_view channel) {
    const auto found = std::find_if(
        values.begin(), values.end(),
        [channel](const Entry& entry) { return entry.channel == channel; });
    if (found == values.end())
        return std::nullopt;
    return *found;
}

} // namespace

Result<History> History::open(std::string_view name, const Entry& initial) {
    if (auto status = validate_text(name, "Navigation history name", false);
        !status)
        return std::unexpected(status.error());
    if (auto status = validate_entry(initial); !status)
        return std::unexpected(status.error());
    const std::string owned_name(name);
    auto session = acquire(owned_name, initial);
    if (!session)
        return std::unexpected(session.error());
    return History(owned_name, initial, session->created);
}

Result<std::vector<Entry>> History::entries() const {
    auto session = acquire(name_, initial_);
    if (!session)
        return std::unexpected(session.error());
    return copy_entries(*session->stack);
}

Result<std::size_t> History::size() const {
    auto values = entries();
    if (!values)
        return std::unexpected(values.error());
    return values->size();
}

Result<std::size_t> History::index() const {
    auto session = acquire(name_, initial_);
    if (!session)
        return std::unexpected(session.error());
    auto state = snapshot(*session->stack);
    if (!state)
        return std::unexpected(state.error());
    return state->index;
}

Result<Entry> History::current() const {
    auto session = acquire(name_, initial_);
    if (!session)
        return std::unexpected(session.error());
    auto state = snapshot(*session->stack);
    if (!state)
        return std::unexpected(state.error());
    return state->entries[state->index];
}

Result<std::optional<Entry>>
History::current_for(std::string_view channel) const {
    if (auto status = validate_channel(channel); !status)
        return std::unexpected(status.error());
    auto session = acquire(name_, initial_);
    if (!session)
        return std::unexpected(session.error());
    navstack_entry_t native;
    const std::string owned_channel(channel);
    if (!session->stack->get_current(&native, owned_channel.c_str()))
        return std::optional<Entry>{};
    auto converted = from_native(native);
    if (!converted)
        return std::unexpected(converted.error());
    return std::optional<Entry>{std::move(*converted)};
}

Result<std::vector<Entry>> History::all_current() const {
    auto session = acquire(name_, initial_);
    if (!session)
        return std::unexpected(session.error());
    return copy_current(*session->stack);
}

Status History::set_current(const Entry& entry, bool record_in_history) const {
    auto native = to_native(entry);
    if (!native)
        return std::unexpected(native.error());
    auto session = acquire(name_, initial_);
    if (!session)
        return std::unexpected(session.error());
    auto before = snapshot(*session->stack);
    if (!before)
        return std::unexpected(before.error());
    session->stack->set_current(*native, record_in_history);
    auto after = snapshot(*session->stack);
    if (!after)
        return std::unexpected(after.error());
    auto current = find_channel(after->current, entry.channel);
    bool valid = current && *current == entry;
    if (record_in_history) {
        valid = valid && after->entries.size() == before->entries.size() &&
                after->index == before->index &&
                after->entries[after->index] == entry;
    } else {
        valid = valid && after->entries == before->entries &&
                after->index == before->index;
    }
    if (!valid) {
        const Error failure =
            Error::sdk("Navigation current-state update was not exact");
        if (auto rollback = restore(*session->stack, *before); !rollback) {
            return std::unexpected(mutation_with_rollback_error(
                "Navigation current-state update", failure, rollback.error()));
        }
        return std::unexpected(failure);
    }
    return ok();
}

Result<Entry> History::push(const Entry& entry) const {
    auto native = to_native(entry);
    if (!native)
        return std::unexpected(native.error());
    auto session = acquire(name_, initial_);
    if (!session)
        return std::unexpected(session.error());
    auto before = snapshot(*session->stack);
    if (!before)
        return std::unexpected(before.error());
    session->stack->stack_jump(false, *native);
    auto after = snapshot(*session->stack);
    if (!after)
        return std::unexpected(after.error());
    std::vector<Entry> expected(before->entries.begin(),
                                before->entries.begin() + before->index + 1);
    expected.push_back(entry);
    const auto current = find_channel(after->current, entry.channel);
    if (after->entries != expected || after->index != before->index + 1 ||
        after->entries[after->index] != entry || !current ||
        *current != entry) {
        const Error failure =
            Error::sdk("Navigation push did not persist exact state");
        if (auto rollback = restore(*session->stack, *before); !rollback) {
            return std::unexpected(mutation_with_rollback_error(
                "Navigation push", failure, rollback.error()));
        }
        return std::unexpected(failure);
    }
    return after->entries[after->index];
}

Result<Entry> History::seek(std::size_t index) const {
    auto requested = native_index(index, "Navigation history index");
    if (!requested)
        return std::unexpected(requested.error());
    auto session = acquire(name_, initial_);
    if (!session)
        return std::unexpected(session.error());
    auto before = snapshot(*session->stack);
    if (!before)
        return std::unexpected(before.error());
    if (index >= before->entries.size()) {
        return std::unexpected(
            Error::validation("Navigation history index is outside the stack",
                              std::to_string(index)));
    }
    navstack_entry_t moved;
    if (!session->stack->stack_seek(&moved, *requested, false)) {
        return std::unexpected(Error::sdk("Failed to seek navigation history",
                                          std::to_string(index)));
    }
    auto converted = from_native(moved);
    if (!converted)
        return std::unexpected(converted.error());
    if (*converted != before->entries[index] ||
        session->stack->stack_index() != index) {
        return std::unexpected(
            Error::sdk("Navigation seek returned inconsistent state",
                       std::to_string(index)));
    }
    return *converted;
}

Result<std::optional<Entry>> History::back(std::size_t count) const {
    auto requested = native_index(count, "Navigation history count");
    if (!requested)
        return std::unexpected(requested.error());
    if (count == 0) {
        return std::unexpected(
            Error::validation("Navigation history count cannot be zero"));
    }
    auto session = acquire(name_, initial_);
    if (!session)
        return std::unexpected(session.error());
    auto before = snapshot(*session->stack);
    if (!before)
        return std::unexpected(before.error());
    if (count > before->index)
        return std::optional<Entry>{};
    navstack_entry_t moved;
    if (!session->stack->stack_back(&moved, *requested, false)) {
        return std::unexpected(
            Error::sdk("Failed to move backward in navigation history"));
    }
    auto converted = from_native(moved);
    if (!converted)
        return std::unexpected(converted.error());
    const std::size_t expected_index = before->index - count;
    if (*converted != before->entries[expected_index] ||
        session->stack->stack_index() != expected_index) {
        return std::unexpected(Error::sdk(
            "Navigation backward movement returned inconsistent state"));
    }
    return std::optional<Entry>{std::move(*converted)};
}

Result<std::optional<Entry>> History::forward(std::size_t count) const {
    auto requested = native_index(count, "Navigation history count");
    if (!requested)
        return std::unexpected(requested.error());
    if (count == 0) {
        return std::unexpected(
            Error::validation("Navigation history count cannot be zero"));
    }
    auto session = acquire(name_, initial_);
    if (!session)
        return std::unexpected(session.error());
    auto before = snapshot(*session->stack);
    if (!before)
        return std::unexpected(before.error());
    if (count >= before->entries.size() - before->index)
        return std::optional<Entry>{};
    navstack_entry_t moved;
    if (!session->stack->stack_forward(&moved, *requested, false)) {
        return std::unexpected(
            Error::sdk("Failed to move forward in navigation history"));
    }
    auto converted = from_native(moved);
    if (!converted)
        return std::unexpected(converted.error());
    const std::size_t expected_index = before->index + count;
    if (*converted != before->entries[expected_index] ||
        session->stack->stack_index() != expected_index) {
        return std::unexpected(Error::sdk(
            "Navigation forward movement returned inconsistent state"));
    }
    return std::optional<Entry>{std::move(*converted)};
}

Status History::replace(std::size_t index, const Entry& entry) const {
    auto requested = native_index(index, "Navigation history index");
    if (!requested)
        return std::unexpected(requested.error());
    auto native = to_native(entry);
    if (!native)
        return std::unexpected(native.error());
    auto session = acquire(name_, initial_);
    if (!session)
        return std::unexpected(session.error());
    auto before = snapshot(*session->stack);
    if (!before)
        return std::unexpected(before.error());
    if (index >= before->entries.size()) {
        return std::unexpected(
            Error::validation("Navigation history index is outside the stack",
                              std::to_string(index)));
    }
    session->stack->set_stack_entry(*requested, *native);
    auto after = snapshot(*session->stack);
    if (!after)
        return std::unexpected(after.error());
    auto expected = before->entries;
    expected[index] = entry;
    if (after->entries != expected || after->index != before->index) {
        const Error failure =
            Error::sdk("Navigation entry replacement was not exact");
        if (auto rollback = restore(*session->stack, *before); !rollback) {
            return std::unexpected(mutation_with_rollback_error(
                "Navigation entry replacement", failure, rollback.error()));
        }
        return std::unexpected(failure);
    }
    return ok();
}

Status History::clear(const Entry& new_tip) const {
    auto native = to_native(new_tip);
    if (!native)
        return std::unexpected(native.error());
    auto session = acquire(name_, initial_);
    if (!session)
        return std::unexpected(session.error());
    auto before = snapshot(*session->stack);
    if (!before)
        return std::unexpected(before.error());
    session->stack->stack_clear(*native);
    auto after = snapshot(*session->stack);
    if (!after)
        return std::unexpected(after.error());
    if (after->entries != std::vector<Entry>{new_tip} || after->index != 0) {
        const Error failure =
            Error::sdk("Navigation clear did not install the requested tip");
        if (auto rollback = restore(*session->stack, *before); !rollback) {
            return std::unexpected(mutation_with_rollback_error(
                "Navigation clear", failure, rollback.error()));
        }
        return std::unexpected(failure);
    }
    return ok();
}

Status History::transfer_channel_to(const History& destination,
                                    std::string_view channel,
                                    bool retain_history) const {
    if (auto status = validate_channel(channel); !status)
        return status;
    if (name_ == destination.name_) {
        return std::unexpected(Error::validation(
            "Navigation channel transfer requires distinct histories"));
    }
    auto source_session = acquire(name_, initial_);
    if (!source_session)
        return std::unexpected(source_session.error());
    auto destination_session = acquire(destination.name_, destination.initial_);
    if (!destination_session)
        return std::unexpected(destination_session.error());
    auto source_before = snapshot(*source_session->stack);
    if (!source_before)
        return std::unexpected(source_before.error());
    auto destination_before = snapshot(*destination_session->stack);
    if (!destination_before)
        return std::unexpected(destination_before.error());
    const auto source_current = find_channel(source_before->current, channel);
    if (!source_current) {
        return std::unexpected(Error::not_found(
            "Navigation source channel has no current location",
            std::string(channel)));
    }
    if (find_channel(destination_before->current, channel) ||
        std::any_of(destination_before->entries.begin(),
                    destination_before->entries.end(),
                    [channel](const Entry& value) {
                        return value.channel == channel;
                    })) {
        return std::unexpected(Error::conflict(
            "Navigation destination already contains the channel",
            std::string(channel)));
    }
    const auto expected_source_entries =
        without_channel(source_before->entries, channel);
    if (expected_source_entries.empty()) {
        return std::unexpected(Error::conflict(
            "Navigation transfer would leave the source stack empty",
            std::string(channel)));
    }
    const auto source_cursor_end =
        source_before->entries.begin() + source_before->index + 1;
    const std::size_t retained_through_cursor = static_cast<std::size_t>(
        std::count_if(source_before->entries.begin(), source_cursor_end,
                      [channel](const Entry& value) {
                          return value.channel != channel;
                      }));
    const std::size_t expected_source_index =
        retained_through_cursor == 0 ? 0 : retained_through_cursor - 1;
    auto expected_destination_entries = destination_before->entries;
    if (retain_history) {
        for (const auto& value : source_before->entries) {
            if (value.channel == channel)
                expected_destination_entries.push_back(value);
        }
    }
    const auto expected_source_current =
        without_channel(source_before->current, channel);
    auto expected_destination_current = destination_before->current;
    expected_destination_current.push_back(*source_current);

    const std::string source_name = native_stream_name(name_);
    const std::string destination_name = native_stream_name(destination.name_);
    const std::string owned_channel(channel);

    (void)navstack_t::perform_move(destination_name.c_str(),
                                   source_name.c_str(), owned_channel.c_str(),
                                   retain_history);

    const auto source_normalized = normalize_cursor_without_current(
        *source_session->stack, expected_source_entries, expected_source_index);
    const auto destination_normalized = normalize_cursor_without_current(
        *destination_session->stack, expected_destination_entries,
        destination_before->index);
    auto source_after = snapshot(*source_session->stack);
    auto destination_after = snapshot(*destination_session->stack);
    bool valid = source_normalized && destination_normalized && source_after &&
                 destination_after;
    if (valid) {
        valid = source_after->entries == expected_source_entries &&
                source_after->index == expected_source_index &&
                current_maps_equal(source_after->current,
                                   expected_source_current) &&
                destination_after->entries == expected_destination_entries &&
                destination_after->index == destination_before->index &&
                current_maps_equal(destination_after->current,
                                   expected_destination_current);
    }
    if (valid)
        return ok();

    std::string failure_context;
    if (!source_normalized) {
        failure_context =
            "source-normalize=" + source_normalized.error().message;
    } else if (!destination_normalized) {
        failure_context =
            "destination-normalize=" + destination_normalized.error().message;
    } else if (!source_after) {
        failure_context = "source=" + source_after.error().message;
    } else if (!destination_after) {
        failure_context = "destination=" + destination_after.error().message;
    } else {
        failure_context = "source{" + describe_snapshot(*source_after) +
                          "};destination{" +
                          describe_snapshot(*destination_after) + "}";
    }
    const Error failure = Error::sdk(
        "Navigation channel transfer was not exact", failure_context);
    (void)navstack_t::perform_move(source_name.c_str(),
                                   destination_name.c_str(),
                                   owned_channel.c_str(), false);
    const auto source_rollback =
        restore(*source_session->stack, *source_before);
    const auto destination_rollback =
        restore(*destination_session->stack, *destination_before);
    if (!source_rollback || !destination_rollback) {
        Error rollback = !source_rollback ? source_rollback.error()
                                          : destination_rollback.error();
        return std::unexpected(mutation_with_rollback_error(
            "Navigation channel transfer", failure, rollback));
    }
    return std::unexpected(failure);
}

} // namespace ida::navigation

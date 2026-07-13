# Tutorial: Function-Discovery Event Hooks

This tutorial shows how to hook IDB analysis events and run custom logic when
new functions are discovered.

## Which event to use

For "new function discovered" workflows, use:

- `ida::event::on_function_added(std::function<void(ida::Address entry)>)`

Related hooks you will often pair with it:

- `ida::event::on_function_deleted(std::function<void(ida::Address entry)>)`
- `ida::event::on_event_filtered(filter, callback)` for one routing point

`on_function_added` fires for both manual function creation and auto-analysis
discoveries that create a function entry.

## Change-tracking event families

The event domain also supplies post-change snapshots for database mirrors,
incremental indexes, and metadata synchronization:

| Mutation | Subscription | Callback payload |
|---|---|---|
| Segment relocation | `on_segment_moved` | `SegmentMovedEvent` |
| Function metadata update | `on_function_updated` | function entry address |
| Item type update | `on_item_type_changed` | item address |
| Operand representation update | `on_operand_type_changed` | item address + operand index |
| Instruction/data creation | `on_code_created`, `on_data_created` | `ItemCreatedEvent` |
| Item destruction | `on_items_destroyed` | `ItemsDestroyedEvent` |
| Anterior/posterior comment update | `on_extra_comment_changed` | `ExtraCommentChangedEvent` |
| Local type library update | `on_local_types_changed` | `LocalTypesChangedEvent` |

The structured payloads contain no SDK pointers or encoded flags. A C++
callback receives a callback-scoped `const&`; copying the structure retains the
snapshot. Node and Rust callbacks receive value-model equivalents.

Subscription mutation has event-wide isolation. Unsubscribing the active
callback is supported. A subscription created by a typed or generic callback
does not receive a later routing phase of that same IDB event; it becomes
eligible for the next event. The final listener teardown is deferred until the
active SDK dispatch returns.

## Complete plugin example (RAII subscription lifetime)

```cpp
#include <ida/idax.hpp>

#include <sstream>
#include <string>
#include <vector>

namespace {

std::string hex_address(ida::Address ea) {
  std::ostringstream os;
  os << std::hex << ea;
  return os.str();
}

class FunctionDiscoveryPlugin final : public ida::plugin::Plugin {
public:
  ida::plugin::Info info() const override {
    return {
      .name = "Function Discovery Watcher",
      .hotkey = "Ctrl-Alt-Shift-F",
      .comment = "Logs and tags newly discovered functions",
      .help = "Subscribes to ida::event::on_function_added and performs custom processing.",
    };
  }

  bool init() override {
    auto token = ida::event::on_function_added([this](ida::Address entry) {
      on_function_added(entry);
    });
    if (!token) {
      ida::ui::warning(
        "[fn-watch] failed to subscribe: " + token.error().message + "\n");
      return false;
    }

    // Keep the guard alive for as long as the plugin should receive callbacks.
    subscriptions_.emplace_back(*token);
    ida::ui::message("[fn-watch] subscription active\n");
    return true;
  }

  void term() override {
    // ScopedSubscription automatically calls ida::event::unsubscribe(token)
    // during destruction.
    subscriptions_.clear();
  }

  ida::Status run(std::size_t) override {
    ida::ui::message("[fn-watch] plugin loaded; waiting for function events\n");
    return ida::ok();
  }

private:
  void on_function_added(ida::Address entry) {
    auto fn = ida::function::at(entry);
    if (!fn) {
      ida::ui::message("[fn-watch] function-added event at 0x"
                       + hex_address(entry)
                       + " (details unavailable)\n");
      return;
    }

    ida::ui::message("[fn-watch] discovered " + fn->name()
                     + " @ 0x" + hex_address(entry) + "\n");

    // Example custom processing: annotate the entry point.
    auto comment_status = ida::comment::set(
      entry,
      "[fn-watch] discovered during analysis");
    if (!comment_status) {
      ida::ui::warning("[fn-watch] comment::set failed: "
                       + comment_status.error().message + "\n");
    }
  }

  std::vector<ida::event::ScopedSubscription> subscriptions_;
};

} // namespace

IDAX_PLUGIN(FunctionDiscoveryPlugin)
```

## Optional explicit unsubscribe pattern

Use this when you need to toggle subscriptions at runtime instead of keeping
them for the plugin lifetime.

```cpp
class ToggleWatcher {
public:
  ida::Status enable() {
    if (token_ != 0) return ida::ok();

    auto token = ida::event::on_function_added([](ida::Address entry) {
      (void) entry;
      ida::ui::message("enabled watcher saw function-added event\n");
    });
    if (!token) return std::unexpected(token.error());

    token_ = *token;
    return ida::ok();
  }

  void disable() {
    if (token_ == 0) return;
    (void) ida::event::unsubscribe(token_);
    token_ = 0;
  }

  ~ToggleWatcher() { disable(); }

private:
  ida::event::Token token_{0};
};
```

## Practical guidance

- Keep event callbacks short; hand off heavy work to timers/background queues.
- Store subscription tokens/guards in plugin state; never let them go out of
  scope accidentally.
- Prefer `ScopedSubscription` for default safety, use explicit unsubscribe only
  when runtime toggling is required.
- If your callback mutates decompiler output, pair event hooks with explicit
  refresh/dirty APIs from `ida::decompiler` and `ida::ui`.

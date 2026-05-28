# Plugin Quickstart (idax)

This quickstart shows the minimal flow for registering an IDA action through `ida::plugin`.

## 1) Define an action

```cpp
ida::plugin::Action action;
action.id = "idax:quickstart:hello";
action.label = "Hello from idax";
action.hotkey = "Ctrl-Alt-H";
action.tooltip = "Quickstart action";
action.handler = []() -> ida::Status {
  ida::ui::message("hello from idax plugin action\n");
  return ida::ok();
};
action.enabled = []() { return true; };

// Optional context-aware callbacks.
action.handler_with_context = [](const ida::plugin::ActionContext& ctx) -> ida::Status {
  if (ctx.current_address != ida::BadAddress) {
    ida::ui::message("action invoked with a valid cursor address\n");
  }
  return ida::ok();
};
action.enabled_with_context = [](const ida::plugin::ActionContext& ctx) {
  return ctx.current_address != ida::BadAddress;
};

// Local Types actions can key off the SDK type-ref payload without keeping
// raw SDK pointers beyond the callback.
action.enabled_with_context = [](const ida::plugin::ActionContext& ctx) {
  return ctx.widget_type == static_cast<int>(ida::ui::WidgetType::LocalTypes)
      && ctx.type_ref.has_value();
};
action.handler_with_context = [](const ida::plugin::ActionContext& ctx) -> ida::Status {
  if (ctx.type_ref) {
    auto type_text = ctx.type_ref->type.to_string();
    if (!type_text) return std::unexpected(type_text.error());
    ida::ui::message("Local type: %s = %s\n",
                     ctx.type_ref->name.c_str(),
                     type_text->c_str());
  }
  return ida::ok();
};

// Optional advanced host access for plugin interop paths.
action.handler_with_context = [](const ida::plugin::ActionContext& ctx) -> ida::Status {
  auto host_status = ida::plugin::with_decompiler_view_host(
    ctx,
    [](void* view_host) -> ida::Status {
      // view_host is an opaque handle (vdui_t* cast to void*) when available.
      // Keep usage scoped inside this callback.
      (void)view_host;
      return ida::ok();
    });

  if (!host_status && host_status.error().category != ida::ErrorCategory::NotFound) {
    return std::unexpected(host_status.error());
  }
  return ida::ok();
};
```

## 2) Register and attach

```cpp
auto r1 = ida::plugin::register_action(action);
auto r2 = ida::plugin::attach_to_menu("Edit/Plugins/", action.id);
```

## 3) Unregister during teardown

```cpp
auto r3 = ida::plugin::detach_from_menu("Edit/Plugins/", action.id);
auto r4 = ida::plugin::unregister_action(action.id);
```

## 4) Owning Hex-Rays in Plugin Lifetimes

Plugins that depend on Hex-Rays should acquire an explicit scoped session
during `init()` and release it after action/event teardown. This replaces raw
`init_hexrays_plugin()` / `term_hexrays_plugin()` calls while keeping
`ida::decompiler::available()` as a non-owning query.

```cpp
class MyDecompilerPlugin : public ida::plugin::Plugin {
public:
  bool init() override {
    auto session = ida::decompiler::initialize();
    if (!session) {
      ida::ui::message("Hex-Rays unavailable: " + session.error().message + "\n");
      return false;
    }
    hexrays_ = std::move(*session);

    // Register actions and decompiler subscriptions here.
    return true;
  }

  void term() override {
    // Unregister actions and unsubscribe before releasing Hex-Rays ownership.
    (void)hexrays_.close();
  }

private:
  ida::decompiler::ScopedSession hexrays_;
};
```

For toolbar/popup wiring, use:

- `ida::plugin::attach_to_toolbar()` / `ida::plugin::detach_from_toolbar()`
- `ida::plugin::attach_to_popup()` / `ida::plugin::detach_from_popup()`
- `ida::decompiler::on_populating_popup()` with
  `ida::ui::attach_dynamic_action()` for Hex-Rays pseudocode popup items:

```cpp
auto token = ida::decompiler::on_populating_popup(
    [](const ida::decompiler::PopulatingPopupEvent& ev) {
      (void)ida::ui::attach_dynamic_action(
          ev.popup_handle,
          ida::ui::Widget{},
          "my_plugin:popup_action",
          "Run analysis",
          [] { ida::ui::message("popup action\n"); },
          "my_plugin/");
    });
```

## Notes

- Keep action IDs globally unique (namespace-like prefixes are recommended).
- Use `enabled()` / `enabled_with_context()` to gate actions based on runtime state.
- See `examples/plugin/action_plugin.cpp` for a full file.
- For event-driven plugin patterns (including function-discovery hooks), see
  `docs/tutorial/function_discovery_events.md`.
- For advanced decompiler/popup workflows, see `examples/plugin/abyss_port_plugin.cpp`
  and `docs/port_gap_audit_examples.md`.
- For custom-viewer + Sleigh-backed plugin workflows, see
  `examples/plugin/idapcode_port_plugin.cpp` and
  `docs/port_gap_audit_examples.md`.

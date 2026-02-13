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

For toolbar/popup wiring, use:

- `ida::plugin::attach_to_toolbar()` / `ida::plugin::detach_from_toolbar()`
- `ida::plugin::attach_to_popup()` / `ida::plugin::detach_from_popup()`

## Notes

- Keep action IDs globally unique (namespace-like prefixes are recommended).
- Use `enabled()` / `enabled_with_context()` to gate actions based on runtime state.
- See `examples/plugin/action_plugin.cpp` for a full file.

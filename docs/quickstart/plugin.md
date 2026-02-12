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
```

## 2) Register and attach

```cpp
auto r1 = ida::plugin::register_action(action);
auto r2 = ida::plugin::attach_to_menu("Edit/Plugins/", action.id);
```

## 3) Unregister during teardown

```cpp
auto r3 = ida::plugin::unregister_action(action.id);
```

## Notes

- Keep action IDs globally unique (namespace-like prefixes are recommended).
- Use `enabled()` to gate actions based on database/debugger state.
- See `examples/plugin/action_plugin.cpp` for a full file.

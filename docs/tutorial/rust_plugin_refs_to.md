# Tutorial: Rust Plugin Workflow for `refs_to` Cross-Reference Analysis

This tutorial shows a practical Rust plugin pattern for finding every
cross-reference to a target function with `idax::xref::refs_to`.

## 1) What this solves

Given a function name (for example `main` or `decode_packet`), you want to:

1. Resolve it to an address.
2. Enumerate all incoming references.
3. Filter/format the results for analyst output.
4. Wire it into plugin action lifecycle (`register`/`attach`/`detach`).

## 2) Rust plugin action module

```rust
use idax::address::BAD_ADDRESS;
use idax::{function, name, plugin, ui, xref};

const ACTION_ID: &str = "idax:rust:xref_refs_to";
const MENU_PATH: &str = "Edit/Plugins/";

fn run_refs_to_query(target_name: &str) -> idax::Status {
    let target_ea = name::resolve(target_name, BAD_ADDRESS)?;
    let refs = xref::refs_to(target_ea)?;

    let mut out = String::new();
    out.push_str(&format!(
        "[xref] target '{}' @ {:#x}, {} incoming refs\n",
        target_name,
        target_ea,
        refs.len()
    ));

    for r in refs.into_iter().filter(|r| r.is_code) {
        let caller_name = function::at(r.from)
            .map(|f| f.name().to_string())
            .unwrap_or_else(|_| "<unknown>".to_string());
        out.push_str(&format!(
            "  from {:#x} -> {:#x} type={:?} caller={}\n",
            r.from,
            r.to,
            r.ref_type,
            caller_name
        ));
    }

    ui::message(&out);
    Ok(())
}

pub fn install_refs_to_action(target_name: &'static str) -> idax::Status {
    let action = plugin::Action {
        id: ACTION_ID.to_string(),
        label: "Show refs_to(target)".to_string(),
        hotkey: "Ctrl-Alt-Shift-X".to_string(),
        tooltip: "Enumerate incoming xrefs to configured target".to_string(),
        icon: -1,
    };

    plugin::register_action_with_context(
        &action,
        move |_ctx| {
            if let Err(e) = run_refs_to_query(target_name) {
                ui::warning(&format!("[xref] refs_to query failed: {}", e.message));
            }
        },
        Some(|ctx: &plugin::ActionContext| ctx.current_address != BAD_ADDRESS),
    )?;

    plugin::attach_to_menu(MENU_PATH, ACTION_ID)?;
    Ok(())
}

pub fn uninstall_refs_to_action() -> idax::Status {
    let _ = plugin::detach_from_menu(MENU_PATH, ACTION_ID);
    plugin::unregister_action(ACTION_ID)
}
```

## 3) Lifecycle wiring

Call `install_refs_to_action(...)` during plugin init and
`uninstall_refs_to_action()` during plugin term.

If your plugin host is C++ and your analysis logic is Rust, keep the bridge
thin: C++ owns IDA plugin export/lifecycle, Rust owns analysis logic and action
registration APIs.

## 4) Optional improvements

- Filter to call-only references (`xref::is_call(r.ref_type)`).
- Group results by caller function entry.
- Add an input prompt to choose `target_name` at runtime.
- Emit structured JSON to feed downstream tooling.

This pattern is enough to build practical xref-centric plugins while staying in
safe Rust APIs.

# Port Gap Audit: abyss

Date: 2026-02-16

This audit records findings from porting the abyss Python Hex-Rays filter
framework (Dennis Elser, "patois") to idax-first surfaces.

## Port artifact in this repository

- `examples/plugin/abyss_port_plugin.cpp`

## Covered migration flows

- Plugin lifecycle via `ida::plugin::Plugin` + `IDAX_PLUGIN(AbyssPlugin)`.
- Full 8-filter framework port: `token_colorizer`, `signed_ops`, `hierarchy`,
  `lvars_alias`, `lvars_info`, `item_sync`, `item_ctype`, `item_index`.
- Decompiler event fanout with scoped subscriptions:
  `on_func_printed`, `on_maturity_changed`, `on_curpos_changed`,
  `on_create_hint`, `on_refresh_pseudocode`.
- UI event fanout:
  `on_popup_ready`, `on_rendering_info`, `on_screen_ea_changed`.
- Pseudocode tagged-line rewriting and address-tag parsing through
  `ida::lines` (`colstr`, `tag_remove`, `tag_advance`, `tag_strlen`,
  `make_addr_tag`, `decode_addr_tag`).
- Dynamic popup action trees via `ida::ui::attach_dynamic_action`.
- Decompiler/disassembly cross-highlighting via rendering overlays and
  `ui::refresh_all_views`.

## Source-to-idax API mapping

| abyss workflow | idax mapping | Status |
|---|---|---|
| Hex-Rays callback dispatch (`hxe_*`) | `ida::decompiler::on_*` subscriptions with `ScopedSubscription` | covered |
| Pseudocode line mutation | `raw_pseudocode_lines` + `set_pseudocode_line` | covered |
| Tagged color/text helpers | `ida::lines::*` helpers and constants | covered |
| Item-at-position/type lookup | `item_at_position`, `item_type_name`, `ExpressionView::left/right` | covered |
| Popup action injection | `ida::ui::attach_dynamic_action` from `on_popup_ready` | covered |
| View rendering overlays | `ida::ui::on_rendering_info` + `LineRenderEntry` | covered |
| Caller/callee hierarchy popup | `ida::xref::code_refs_to` + `ida::function` + `ida::instruction` | covered |

## Confirmed parity gaps

- No blocking parity gaps for the audited abyss workflows.
- Non-blocking behavioral delta: `lvars_info` and `lvars_alias` currently log
  rename intent instead of mutating local-variable names in-place during
  maturity callbacks.

## Notes

- Experimental filters (`item_ctype`, `item_index`, `item_sync`, `lvars_alias`,
  `lvars_info`) are intentionally deactivated by default and are toggled from
  the pseudocode popup under `abyss/`.
- Build target: `idax_abyss_port_plugin` (enabled when
  `IDAX_BUILD_EXAMPLES=ON` and `IDAX_BUILD_EXAMPLE_ADDONS=ON`).

# Decompiler / Debugger Fixtures

Current baseline fixture set:

- Reuse `../simple_appcall_linux64` for decompiler pseudocode, ctree traversal, and address-mapping tests.

Debugger-note:

- Headless idalib runs validate subscription lifecycle (register/unregister/RAII)
  without requiring an active live debug session.

Planned additions:

- synthetic binary with richer local variable patterns for decompiler mutation tests
- debugger event replay fixture for deterministic callback verification

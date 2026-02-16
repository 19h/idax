## 18) Detailed Legacy Pain Point Catalog (Implementation Guardrails)

This section records concrete friction points discovered during SDK review so wrapper behavior can neutralize them explicitly.

1. Mixed naming within same domain (`segm` and `segment`) causes poor discoverability.
2. Bitness encoded as 0/1/2 instead of 16/32/64 is repeatedly error-prone.
3. Segment names/classes represented by internal IDs (`uval_t`) instead of strings leaks internals.
4. Function entry vs tail chunk union semantics are implicit and easy to misuse.
5. Pointer validity often depends on manual lock helpers (`lock_*`) not enforced by type system.
6. `flags64_t` packs unrelated concerns (state/type/operand metadata) behind overlapping bit regions.
7. Multiple retrieval variants exist for names and xrefs with subtle behavior differences.
8. Return conventions are inconsistent (`bool`, `int`, `ssize_t`, sentinel values).
9. Several APIs rely on magic argument combinations and sentinel values for special behavior.
10. Include-order dependencies expose features conditionally in a non-obvious way.
11. Search direction defaults rely on zero-value bitmasks that are not self-evident.
12. Debugger APIs duplicate direct and request variants, increasing accidental misuse risk.
13. UI and debugger dispatch rely on varargs notification systems with weak compile-time checks.
14. Type APIs contain deep complexity with historical encodings and many parallel concepts.
15. Decompiler APIs enforce maturity/order constraints that are easy to violate accidentally.
16. Manual memory and ownership conventions still appear in several API families.
17. Numeric and representation controls are spread across low-level helper patterns.
18. Migration requires broad knowledge of legacy naming and bitflag semantics.

Wrapper response requirements derived from these pain points:
- Convert encoded flags to typed enums/options in public API.
- Normalize naming to full words and consistent verb-first action names.
- Collapse duplicate traversal APIs into single iterable abstractions.
- Replace sentinel-heavy behavior with structured result/value objects.
- Expose explicit state/lifecycle semantics in class design.
- Make advanced operations available, but never default-obscure.

---

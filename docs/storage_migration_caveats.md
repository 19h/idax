# Storage Migration Caveats and Safety Notes

`ida::storage` wraps netnode-style persistence, but migration from raw netnode code should account for:

1. **Tag semantics remain important**
   - alt/sup/hash/blob tags still partition key spaces.
   - Keep tag constants explicit in migration code.

2. **Binary payload boundaries**
   - Prefer `set_blob()` / `blob()` for opaque bytes.
   - Use `blob_string()` only when data is truly text-oriented.

3. **Roundtrip validation**
   - After migration, read back values and compare byte-for-byte.
   - Include fixture-driven regression checks for key nodes.

4. **Versioning strategy**
   - Store a migration version key in a stable node.
   - Make migrations idempotent where possible.

5. **Error handling**
   - Treat missing nodes/keys as recoverable `not_found` cases.
   - Reserve `sdk_failure` for actual SDK operation failures.

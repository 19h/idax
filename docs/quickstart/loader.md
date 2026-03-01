# Loader Quickstart (idax)

Implement a custom loader by subclassing `ida::loader::Loader`.

## Skeleton

```cpp
class MyLoader : public ida::loader::Loader {
public:
  ida::Result<std::optional<ida::loader::AcceptResult>>
  accept(ida::loader::InputFile &file) override;

  ida::Status load(ida::loader::InputFile &file,
                   std::string_view format_name) override;
};

IDAX_LOADER(MyLoader)
```

## Typical load flow

1. Detect magic in `accept()`.
2. In `load()`, call `ida::loader::set_processor()`.
3. Set database bitness with `ida::database::set_address_bitness(16|32|64)` when the format declares pointer width.
4. Copy bytes with `ida::loader::file_to_database()`.
5. Add context comment with `ida::loader::create_filename_comment()`.

## Advanced load/reload/archive flow

Use typed request models when you need explicit reload/archive semantics:

```cpp
ida::loader::LoadRequest request;
request.format_name = "My Format";
request.flags.reload = true;
request.archive_name = "libfoo.a";
request.archive_member_name = "foo.o";

ida::loader::LoadFlags flags = ida::loader::decode_load_flags(0x0200); // NEF_RELOAD
auto raw = ida::loader::encode_load_flags(flags);
```

In custom loader subclasses, optional context-rich hooks are available:

- `load_with_request(InputFile&, const LoadRequest&)`
- `save_with_request(void*, const SaveRequest&)`
- `move_segment_with_request(..., const MoveSegmentRequest&)`
- `process_archive(InputFile&, const ArchiveMemberRequest&)`

## Database helper equivalent

For non-loader contexts, `ida::database::file_to_database()` and
`ida::database::memory_to_database()` expose similar operations.

See `examples/loader/minimal_loader.cpp`.

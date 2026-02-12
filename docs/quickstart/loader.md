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
3. Copy bytes with `ida::loader::file_to_database()`.
4. Add context comment with `ida::loader::create_filename_comment()`.

## Database helper equivalent

For non-loader contexts, `ida::database::file_to_database()` and
`ida::database::memory_to_database()` expose similar operations.

See `examples/loader/minimal_loader.cpp`.

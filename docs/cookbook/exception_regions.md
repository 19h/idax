# Architecture-independent exception regions

Use `ida::exception` to inspect or write C++ and structured-exception metadata
without exposing processor-module-specific records or SDK containers.

```cpp
#include <ida/idax.hpp>

ida::exception::CatchHandler handler;
handler.metadata.regions = {{0x401020, 0x401028}};
handler.selector = {ida::exception::CatchSelectorKind::CatchAll, 0};

ida::exception::BlockDefinition definition;
definition.protected_regions = {{0x401000, 0x401010}};
definition.handlers = ida::exception::CppHandlers{{handler}};

auto added = ida::exception::add(definition);
auto blocks = ida::exception::list({0x401000, 0x401030});
auto guarded = ida::exception::contains(
    0x401004, ida::exception::Location::CppTry);
auto removed = ida::exception::remove({0x401000, 0x401030});
```

Every range is half-open, non-empty, sorted, and non-overlapping within its
collection. A C++ block requires at least one catch. A typed selector carries a
non-negative type identifier; catch-all and cleanup selectors carry no native
sentinel. An SEH handler carries either non-empty filter regions or one closed
disposition, never both.

`system_region_start(address)` is separate from stored SEH membership. Absence
means the host does not classify the address inside a system exception region;
it does not imply that `contains(address, Location::SehTry)` is false.

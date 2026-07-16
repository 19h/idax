# Standard directory trees

IDA maintains eight built-in organization trees for Local Types, Functions,
Names, Imports, IDA-place bookmarks, breakpoints, Local Types bookmarks, and
snippets. `ida::directory::Tree` exposes those host-owned trees without
retaining or returning a native tree pointer, inode, cursor, directory index,
visitor, or SDK container.

## Traverse copied entries

```cpp
auto tree = ida::directory::Tree::open(ida::directory::Kind::Functions);
if (!tree)
    return std::unexpected(tree.error());

auto children = tree->children("/");
if (!children)
    return std::unexpected(children.error());
for (const auto& entry : *children) {
    std::cout << entry.path << " " << entry.display_name << "\n";
}
```

`children(path)` copies direct children. `snapshot(path)` copies all
descendants but does not repeat the starting directory. `find_items(pattern)`
uses the host wildcard search and returns item entries. `path` and `name` are
full identities; `display_name` is presentation text and need not be unique.

## Organize entries

```cpp
auto status = tree->create_directory("/reviewed");
if (!status)
    return std::unexpected(status.error());

std::vector<std::string> sources{
    "/first_function",
    "/missing_function",
    "/second_function",
};
auto report = tree->move(sources, "/reviewed");
if (!report)
    return std::unexpected(report.error());

for (const auto& failure : report->failures) {
    std::cerr << failure.input_index << ": " << failure.path
              << ": " << failure.message << "\n";
}
```

Bulk move and recursive remove return `BulkReport`. A missing or rejected
source does not erase successful siblings; `input_index` always refers to the
original caller sequence. An empty batch is invalid. A destination-level host
failure remains an operation error because there is no meaningful partial
destination result.

Use `unlink(path)` to remove an item from the tree without deleting its
underlying database object. Change to the intended target directory and call
`link(full_name)` to restore membership. Directory removal is available as
non-recursive `remove_directory(path)` or recursive bulk `remove({path})`.

## Ordering and folded prefixes

Call `is_orderable()` before using natural-order, rank, or rank-change methods.
Natural ordering is directory-specific. Manual rank changes are signed deltas.

`fold_common_prefix(path)` collapses single-child directory chains. The pinned
host joins the copied full names with byte `0x1D`, which the UI renders as `/`.
That byte is not a path separator: preserve the copied path/name exactly for
subsequent tree calls.

## Complexity and assumptions

- Direct enumeration is `O(N)` time and copied space for `N` children.
- Recursive snapshots are `O(V)` time and copied space for `V` descendants.
- Bulk report preparation/merging is `O(P + R log R)` for total path bytes
  `P` and `R` failures; host lookup and persistence costs are SDK-defined.
- A `Tree` reacquires the current host-owned standard tree by kind on every
  call. Retaining it across a database transition selects that same kind in
  the current database; it is not a handle to historical database state.
- Custom callback-backed directory specifications are a separate authoring
  problem and are not represented by the standard-tree `Kind` enum.

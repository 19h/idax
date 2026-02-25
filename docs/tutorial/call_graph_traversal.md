# Tutorial: Transitive Call-Graph Traversal (Find All Callers)

This tutorial shows how to go beyond one-hop caller lookup and compute the full
transitive caller set for a target function.

## 1) One-hop vs transitive

- One-hop: `function::callers(target)`
- Transitive: callers of target, plus callers of those callers, and so on

Transitive traversal needs:

- A visited set to prevent cycles/re-processing.
- Optional depth limits to bound work.

## 2) Rust BFS implementation

```rust
use idax::address::{Address, BAD_ADDRESS};
use idax::{function, name};
use std::collections::{HashSet, VecDeque};

pub fn transitive_callers(target: Address, max_depth: usize) -> idax::Result<Vec<Address>> {
    let mut visited = HashSet::<Address>::new();
    let mut result = Vec::<Address>::new();
    let mut queue = VecDeque::<(Address, usize)>::new();

    queue.push_back((target, 0));

    while let Some((current, depth)) = queue.pop_front() {
        if depth >= max_depth {
            continue;
        }

        for caller in function::callers(current)? {
            if visited.insert(caller) {
                result.push(caller);
                queue.push_back((caller, depth + 1));
            }
        }
    }

    result.sort_unstable();
    Ok(result)
}

pub fn demo(target_name: &str) -> idax::Result<()> {
    let target = name::resolve(target_name, BAD_ADDRESS)?;
    let callers = transitive_callers(target, usize::MAX)?;

    println!("transitive callers for '{}' ({} total)", target_name, callers.len());
    for ea in callers {
        let label = function::at(ea)
            .map(|f| f.name().to_string())
            .unwrap_or_else(|_| "<unknown>".to_string());
        println!("  {:#x} {}", ea, label);
    }
    Ok(())
}
```

## 3) C++ DFS variant

```cpp
#include <ida/idax.hpp>

#include <cstddef>
#include <unordered_set>
#include <vector>

void collect_transitive_callers(
  ida::Address target,
  std::unordered_set<ida::Address>& visited,
  std::vector<ida::Address>& out,
  std::size_t depth,
  std::size_t max_depth) {
  if (depth >= max_depth) return;

  auto direct = ida::function::callers(target);
  if (!direct) return;

  for (auto caller : *direct) {
    if (!visited.insert(caller).second) continue;
    out.push_back(caller);
    collect_transitive_callers(caller, visited, out, depth + 1, max_depth);
  }
}
```

## 4) Practical safeguards

- Set a depth cap for very large call graphs.
- Cache `function::callers()` results if traversing many targets.
- Emit deterministic ordering (`sort`) before diffing/exporting.
- Treat missing/non-decodable nodes as expected edge cases.

With this pattern, you get complete caller reachability instead of a fragile
single-level list.

# Tutorial: Multi-Binary Signature Generation with idax

This tutorial covers a practical pipeline for generating malware signatures by
extracting, normalizing, and comparing instruction patterns across many
binaries.

The key idea is to use idax for reliable low-level extraction, then layer your
own corpus-level scoring and signature selection policy on top.

## 1) Pipeline overview

1. Build two corpora: malware samples and clean/benign samples.
2. Extract normalized instruction windows from each sample.
3. Score windows by discrimination power (present in malware, absent in benign).
4. Materialize high-scoring windows into deployable signatures.
5. Validate signatures on holdout binaries.

## 2) Extraction layer (idax-powered)

Use `ida::function::all()` + `ida::function::code_addresses()` +
`ida::instruction::decode()` to build normalized token streams.

```cpp
#include <ida/idax.hpp>

#include <cstddef>
#include <string>
#include <unordered_set>
#include <vector>

std::string normalize_operand(const ida::instruction::Operand& op) {
  if (op.is_register()) return "reg";
  if (op.is_memory()) return "mem";
  if (op.is_immediate()) return "imm";
  return "other";
}

std::string normalize_instruction(const ida::instruction::Instruction& insn) {
  std::string token = insn.mnemonic();
  token += "(";
  for (std::size_t i = 0; i < insn.operand_count(); ++i) {
    if (i > 0) token += ",";
    auto op = insn.operand(i);
    token += op ? normalize_operand(*op) : "unknown";
  }
  token += ")";
  return token;
}

std::unordered_set<std::string> extract_windows(std::size_t window_size) {
  std::vector<std::string> stream;
  for (auto fn : ida::function::all()) {
    auto code = ida::function::code_addresses(fn.start());
    if (!code) continue;

    for (auto ea : *code) {
      auto insn = ida::instruction::decode(ea);
      if (!insn) continue;
      stream.push_back(normalize_instruction(*insn));
    }
  }

  std::unordered_set<std::string> windows;
  if (stream.size() < window_size) return windows;

  for (std::size_t i = 0; i + window_size <= stream.size(); ++i) {
    std::string key;
    for (std::size_t j = 0; j < window_size; ++j) {
      if (j > 0) key += " | ";
      key += stream[i + j];
    }
    windows.insert(std::move(key));
  }
  return windows;
}
```

Why normalization matters:

- It removes brittle constants/register allocations.
- It keeps semantic shape (`mnemonic + operand kinds`) stable.
- It increases cross-build and cross-compiler survivability.

## 3) Corpus scoring layer (you provide)

At corpus scale, track per-window prevalence:

- `malware_hits[window]` = number of malware binaries containing it
- `benign_hits[window]` = number of clean binaries containing it

Example scoring function:

```text
score(window) = (malware_hits / malware_corpus_size)
              - (benign_hits  / benign_corpus_size)
```

Select candidates with high score and minimum malware support (for example,
present in at least N malware families).

## 4) Materialize deployable signatures

Two practical output forms:

1. Normalized mnemonic-window signatures (portable, semantic).
2. Byte-pattern signatures with wildcards (fast scanner integration).

idax can provide raw bytes for anchors via `ida::data::read_bytes()`. Your
wildcard policy should mask volatile fields (immediates, relocations,
addresses) before export.

## 5) Validation loop

For each selected candidate:

1. Re-scan malware holdout set (expect high recall).
2. Re-scan benign holdout set (expect low false positives).
3. Drop signatures with unstable hit behavior across compiler/packer variants.

For byte-pattern outputs, use `ida::data::find_binary_pattern()` in validation
probes.

## 6) What idax gives you vs what you still build

idax provides:

- Database lifecycle and batch-friendly analysis control.
- Instruction decode and typed operand metadata.
- Function/code traversal and binary byte-pattern search.

You still build:

- Normalization policy and wildcard strategy.
- Corpus management and scoring model.
- Signature schema/versioning and release workflow.

This split keeps extraction robust while letting you tailor signature logic to
your threat model.

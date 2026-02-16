## 21) Comprehensive Interface Blueprint (Detailed)

This section explicitly records the interface-level design that was discussed. It is intentionally detailed so implementation can proceed with minimal ambiguity.

Scope and constraints for this section:
- These are design-level API sketches, not final ABI commitments.
- Public API remains fully opaque.
- No public `.raw()` escape hatches are allowed.
- Public strings use `std::string`/`std::string_view`.
- Error flow is standardized around `std::expected` aliases.

**NOTE (2026-02-13):** The sketches below were the *design baseline* before implementation. The actual headers in `include/ida/` are the authoritative API surface. Key deviations from sketches applied during P9.1 audit:
- All `ea` parameters renamed to `address` across public API.
- `Segment::visible()` → `Segment::is_visible()` (positive polarity).
- `Function::is_hidden()` removed; use `Function::is_visible()`.
- `frame()` / `sp_delta_at()` are free functions in `ida::function`, not `Function` members.
- `Plugin::run()` returns `Status`, not `bool`.
- `Processor::emulate()` returns `EmulateResult`, `output_operand()` returns `OutputOperandResult`.
- `attach_action_to_menu/toolbar` → `attach_to_menu/toolbar`.
- `xref::Reference::raw_type` replaced by typed `ReferenceType` enum.
- `Chooser::impl()` / `Graph::impl()` made private.
- `DecompiledFunction` is move-only (non-copyable).
- `ItemType::Call` renamed to `ItemType::ExprCall`.
- `ida::type::TypeInfo::create_struct()` takes no arguments; use `save_as(name)` afterward.
- `ida::type::import_type()` requires two arguments: `(source_til_name, type_name)`.
- `ida::ui::message()` takes single `std::string_view`, not printf-style format args.
- See `docs/namespace_topology.md` for the complete, authoritative type/function inventory.

### 21.1 Diagnosis - Why the SDK feels unintuitive

Core issues to solve:
1. Naming chaos: mixed abbreviations (`segm`, `func`, `cmt`) and inconsistent prefixes.
2. Conceptual opacity: packed flags and hidden relationships behind internal conventions.
3. Inconsistent patterns: mixed return/error conventions and multiple competing APIs.
4. Hidden dependencies: include-order constraints, pointer invalidation rules, sentinel-heavy semantics.
5. Redundancy: multiple enumeration and access paths for the same concepts.

### 21.2 Design philosophy

1. Domain-driven namespacing.
2. Self-documenting names and full words.
3. Consistent error model (`Result<T>`, `Status`).
4. RAII and value semantics by default.
5. Iterable/range-first API for traversal-heavy tasks.
6. Progressive disclosure: simple default path plus advanced options.

### 21.3 Namespace architecture (detailed)

```text
ida::
  address, data, database, segment, function, instruction,
  name, xref, comment, type, fixup, entry,
  search, analysis,
  plugin, loader, processor,
  debugger, ui, graph, event,
  decompiler,
  storage (advanced)
```

### 21.4 Cross-cutting public primitives

```cpp
namespace ida {

using Address = ea_t;
using AddressDelta = adiff_t;
using AddressSize = asize_t;

template <typename T>
using Result = std::expected<T, Error>;

using Status = std::expected<void, Error>;

enum class ErrorCategory {
  Validation,
  NotFound,
  Conflict,
  Unsupported,
  SdkFailure,
  Internal,
};

struct Error {
  ErrorCategory category;
  int code;
  std::string message;
  std::string context;
};

}  // namespace ida
```

### 21.5 Detailed interface sketches by namespace

#### 21.5.1 `ida::address`

```cpp
namespace ida::address {

struct Range {
  Address start;
  Address end;  // half-open [start, end)
};

Result<Address> next_defined(Address ea);
Result<Address> prev_defined(Address ea);
Result<Address> item_start(Address ea);
Result<Address> item_end(Address ea);
Result<AddressSize> item_size(Address ea);

bool is_mapped(Address ea);
bool is_loaded(Address ea);
bool is_code(Address ea);
bool is_data(Address ea);
bool is_unknown(Address ea);
bool is_tail(Address ea);

Range item_range(Address ea);

class ItemRange;
class CodeRange;
class DataRange;
class UnknownRange;

ItemRange items(Address start, Address end);
CodeRange code_items(Address start, Address end);
DataRange data_items(Address start, Address end);
UnknownRange unknown_bytes(Address start, Address end);

}  // namespace ida::address
```

#### 21.5.2 `ida::segment`

```cpp
namespace ida::segment {

enum class Type {
  Normal,
  External,
  Code,
  Data,
  Import,
  Null,
  Undefined,
  Bss,
  AbsoluteSymbols,
  Common,
  InternalMemory,
};

struct Permissions {
  bool read;
  bool write;
  bool execute;
};

class Segment {
 public:
  Address start() const;
  Address end() const;
  AddressSize size() const;

  std::string name() const;
  std::string class_name() const;
  Status set_name(std::string_view name);
  Status set_class_name(std::string_view class_name);

  int bitness() const;  // 16/32/64
  Status set_bitness(int bits);

  Type type() const;
  Status set_type(Type t);

  Permissions permissions() const;
  Status set_permissions(Permissions p);

  bool visible() const;
  Status set_visible(bool visible);

  std::string comment(bool repeatable = false) const;
  Status set_comment(std::string_view text, bool repeatable = false);

  Status update();
};

Result<Segment> create(Address start, Address end,
                       std::string_view name,
                       std::string_view class_name,
                       Type type = Type::Normal);
Status remove(Address any_ea_inside_segment);
Result<Segment> at(Address ea);
Result<Segment> by_name(std::string_view name);
Result<size_t> count();

class SegmentRange;
SegmentRange all();

}  // namespace ida::segment
```

#### 21.5.3 `ida::function`

```cpp
namespace ida::function {

class StackFrame {
 public:
  AddressSize local_variables_size() const;
  AddressSize saved_registers_size() const;
  AddressSize arguments_size() const;
  AddressSize total_size() const;

  Result<int32_t> stack_delta_at(Address ea) const;
  Status define_variable(std::string_view name, int32_t frame_offset,
                         const ida::type::TypeInfo &type);
};

class Function {
 public:
  Address start() const;
  Address end() const;
  std::string name() const;

  int bitness() const;
  AddressSize total_size() const;
  bool returns() const;
  bool is_library() const;
  bool is_thunk() const;
  bool visible() const;
  Status set_visible(bool visible);

  std::string comment(bool repeatable = false) const;
  Status set_comment(std::string_view text, bool repeatable = false);

  bool has_frame() const;
  Result<StackFrame> frame() const;

  Status update();
};

Result<Function> create(Address start, Address end = BADADDR);
Status remove(Address ea);
Result<Function> at(Address ea);
Result<size_t> count();

class FunctionRange;
FunctionRange all();

}  // namespace ida::function
```

#### 21.5.4 `ida::instruction`

```cpp
namespace ida::instruction {

enum class OperandType {
  None,
  Register,
  MemoryDirect,
  MemoryIndirect,
  MemoryDisplacement,
  Immediate,
  FarCodeReference,
  NearCodeReference,
  ProcessorSpecific0,
  ProcessorSpecific1,
  ProcessorSpecific2,
  ProcessorSpecific3,
  ProcessorSpecific4,
  ProcessorSpecific5,
};

class Operand {
 public:
  int index() const;
  OperandType type() const;

  bool is_register() const;
  bool is_immediate() const;
  bool is_memory() const;

  Result<uint16_t> register_id() const;
  Result<uint64_t> immediate_value() const;
  Result<Address> target_address() const;
  Result<int64_t> displacement() const;

  Result<std::string> text() const;

  Status set_hex();
  Status set_decimal();
  Status set_octal();
  Status set_binary();
  Status set_character();
  Status set_offset(Address base = 0);
  Status set_enum(uint32_t enum_id);
  Status set_struct_offset(uint32_t struct_id);
  Status set_stack_variable();
  Status clear_representation();
};

class Instruction {
 public:
  Address address() const;
  AddressSize size() const;
  uint16_t opcode() const;
  std::string mnemonic() const;

  size_t operand_count() const;
  Result<Operand> operand(size_t index) const;

  bool is_call() const;
  bool is_jump() const;
  bool is_conditional_jump() const;
  bool is_return() const;
  bool has_fallthrough() const;
};

Result<Instruction> decode(Address ea);   // no DB mutation
Result<Instruction> create(Address ea);   // DB mutation

}  // namespace ida::instruction
```

#### 21.5.5 `ida::data`

```cpp
namespace ida::data {

Result<uint8_t> read_byte(Address ea);
Result<uint16_t> read_word(Address ea);
Result<uint32_t> read_dword(Address ea);
Result<uint64_t> read_qword(Address ea);
Result<std::vector<uint8_t>> read_bytes(Address ea, AddressSize count);

Status write_byte(Address ea, uint8_t value);
Status write_word(Address ea, uint16_t value);
Status write_dword(Address ea, uint32_t value);
Status write_qword(Address ea, uint64_t value);
Status write_bytes(Address ea, std::span<const uint8_t> bytes);

Status patch_byte(Address ea, uint8_t value);
Status patch_word(Address ea, uint16_t value);
Status patch_dword(Address ea, uint32_t value);
Status patch_qword(Address ea, uint64_t value);
Status patch_bytes(Address ea, std::span<const uint8_t> bytes);
Status revert_patch(Address ea);

Result<uint8_t> original_byte(Address ea);
Result<uint16_t> original_word(Address ea);
Result<uint32_t> original_dword(Address ea);
Result<uint64_t> original_qword(Address ea);

Status define_byte(Address ea, AddressSize count = 1);
Status define_word(Address ea, AddressSize count = 1);
Status define_dword(Address ea, AddressSize count = 1);
Status define_qword(Address ea, AddressSize count = 1);
Status define_string(Address ea, AddressSize length);
Status define_struct(Address ea, AddressSize length, uint32_t struct_id);
Status undefine(Address ea, AddressSize count = 1);

}  // namespace ida::data
```

#### 21.5.6 `ida::name`

```cpp
namespace ida::name {

enum class DemangleForm {
  Short,
  Long,
  Full,
};

Status set(Address ea, std::string_view name);
Status force_set(Address ea, std::string_view name);
Status remove(Address ea);

Result<std::string> get(Address ea);
Result<std::string> demangled(Address ea, DemangleForm form = DemangleForm::Short);
Result<Address> resolve(std::string_view name, Address context = BADADDR);

bool is_public(Address ea);
bool is_weak(Address ea);
bool is_user_defined(Address ea);
bool is_auto_generated(Address ea);

Status set_public(Address ea, bool value);
Status set_weak(Address ea, bool value);

Result<bool> is_valid_identifier(std::string_view text);
Result<std::string> sanitize_identifier(std::string_view text);

}  // namespace ida::name
```

#### 21.5.7 `ida::xref`

```cpp
namespace ida::xref {

enum class CodeType {
  Call,
  Jump,
  Flow,
};

enum class DataType {
  Offset,
  Read,
  Write,
  Text,
  Informational,
};

struct Reference {
  Address from;
  Address to;
  bool is_code;
  int type;
  bool user_defined;
};

Status add_code(Address from, Address to, CodeType type);
Status add_data(Address from, Address to, DataType type);
Status remove_code(Address from, Address to);
Status remove_data(Address from, Address to);

class ReferenceRange;
ReferenceRange refs_from(Address ea);
ReferenceRange refs_to(Address ea);
ReferenceRange code_refs_from(Address ea);
ReferenceRange code_refs_to(Address ea);
ReferenceRange data_refs_from(Address ea);
ReferenceRange data_refs_to(Address ea);

}  // namespace ida::xref
```

#### 21.5.8 `ida::type`

```cpp
namespace ida::type {

enum class CallingConvention {
  Default,
  Cdecl,
  Stdcall,
  Pascal,
  Fastcall,
  Thiscall,
  Vectorcall,
  Syscall,
  Unknown,
};

class TypeInfo {
 public:
  static TypeInfo void_type();
  static TypeInfo int8();
  static TypeInfo int16();
  static TypeInfo int32();
  static TypeInfo int64();
  static TypeInfo uint8();
  static TypeInfo uint16();
  static TypeInfo uint32();
  static TypeInfo uint64();
  static TypeInfo float32();
  static TypeInfo float64();

  static TypeInfo pointer_to(const TypeInfo &target);
  static TypeInfo array_of(const TypeInfo &element, size_t count);
  static Result<TypeInfo> from_c_declaration(std::string_view declaration);

  bool is_void() const;
  bool is_integer() const;
  bool is_floating_point() const;
  bool is_pointer() const;
  bool is_array() const;
  bool is_function() const;
  bool is_struct() const;
  bool is_union() const;
  bool is_enum() const;

  Result<size_t> size() const;
  Result<std::string> to_c_declaration() const;
  Status apply(Address ea) const;
};

}  // namespace ida::type
```

#### 21.5.9 `ida::comment`

```cpp
namespace ida::comment {

Result<std::string> get(Address ea, bool repeatable = false);
Status set(Address ea, std::string_view text, bool repeatable = false);
Status append(Address ea, std::string_view text, bool repeatable = false);
Status remove(Address ea, bool repeatable = false);

Status add_anterior_line(Address ea, std::string_view text);
Status add_posterior_line(Address ea, std::string_view text);
Result<std::vector<std::string>> anterior_lines(Address ea);
Result<std::vector<std::string>> posterior_lines(Address ea);

}  // namespace ida::comment
```

#### 21.5.10 `ida::search`

```cpp
namespace ida::search {

enum class Direction {
  Forward,
  Backward,
};

Result<Address> text(std::string_view query, Address start,
                     Direction direction = Direction::Forward,
                     bool case_sensitive = true,
                     bool regex = false);

Result<Address> immediate(uint64_t value, Address start,
                          Direction direction = Direction::Forward);

Result<Address> binary_pattern(std::string_view pattern,
                               Address start,
                               Address end,
                               Direction direction = Direction::Forward);

Result<Address> next_code(Address ea);
Result<Address> next_data(Address ea);
Result<Address> next_unknown(Address ea);
Result<Address> next_error(Address ea);

}  // namespace ida::search
```

#### 21.5.11 `ida::analysis`

```cpp
namespace ida::analysis {

bool is_enabled();
Status set_enabled(bool enabled);

bool is_idle();
Status wait();
Status wait_range(Address start, Address end);

Status schedule_code(Address ea);
Status schedule_function(Address ea);
Status schedule_reanalysis(Address ea);
Status schedule_reanalysis_range(Address start, Address end);

Status revert_decisions(Address start, Address end);

}  // namespace ida::analysis
```

#### 21.5.12 `ida::database`

```cpp
namespace ida::database {

Status open(std::string_view path);
Status save(std::string_view out_path = {});
Status close();

Status load_binary(std::string_view path, Address image_base = 0);
Status load_nonbinary(std::string_view path);

Result<std::string> input_path();
Result<std::string> input_md5();
Result<Address> image_base();
Result<Address> minimum_address();
Result<Address> maximum_address();

}  // namespace ida::database
```

#### 21.5.13 `ida::fixup`

```cpp
namespace ida::fixup {

enum class Type {
  Off8,
  Off16,
  Seg16,
  Ptr16,
  Off32,
  Ptr32,
  Hi8,
  Hi16,
  Low8,
  Low16,
  Off64,
  Off8Signed,
  Off16Signed,
  Off32Signed,
  Custom,
};

struct Descriptor {
  Type type;
  uint32_t flags;
  uint64_t base;
  uint32_t selector;
  Address target;
  int64_t displacement;
};

Result<Descriptor> at(Address source);
Status set(Address source, const Descriptor &fixup);
Status remove(Address source);

class FixupRange;
FixupRange all();
FixupRange in_range(Address start, Address end);

}  // namespace ida::fixup
```

#### 21.5.14 `ida::entry`

```cpp
namespace ida::entry {

struct EntryPoint {
  uint64_t ordinal;
  Address address;
  std::string name;
  std::string forwarder;
};

Result<size_t> count();
Result<EntryPoint> by_index(size_t index);
Result<EntryPoint> by_ordinal(uint64_t ordinal);

Status add(uint64_t ordinal, Address ea, std::string_view name,
           bool make_code = true);
Status rename(uint64_t ordinal, std::string_view name);
Status set_forwarder(uint64_t ordinal, std::string_view target);

}  // namespace ida::entry
```

#### 21.5.15 `ida::plugin`

```cpp
namespace ida::plugin {

class Plugin {
 public:
  struct Info {
    std::string name;
    std::string hotkey;
    std::string comment;
    std::string help;
  };

  virtual ~Plugin() = default;
  virtual Info info() const = 0;
  virtual bool init();
  virtual void term();
  virtual Status run(size_t arg) = 0;
};

struct Action {
  std::string id;
  std::string label;
  std::string hotkey;
  std::string tooltip;
  std::function<Status()> handler;
  std::function<bool()> enabled;
};

Status register_action(const Action &action);
Status unregister_action(std::string_view action_id);
Status attach_action_to_menu(std::string_view menu_path,
                             std::string_view action_id);
Status attach_action_to_toolbar(std::string_view toolbar,
                                std::string_view action_id);

}  // namespace ida::plugin
```

#### 21.5.16 `ida::loader`

```cpp
namespace ida::loader {

class InputFile {
 public:
  Result<size_t> size() const;
  Result<size_t> read(void *buffer, size_t offset, size_t count);
  Result<std::vector<uint8_t>> read_bytes(size_t offset, size_t count);

  template <typename T>
  Result<T> read_value(size_t offset) const;

  Result<std::string> read_string(size_t offset, size_t max_len = 1024) const;
  Result<std::string> filename() const;
};

class Loader {
 public:
  struct AcceptResult {
    std::string format_name;
    std::string processor_name;
    int priority;
  };

  virtual ~Loader() = default;
  virtual Result<std::optional<AcceptResult>> accept(InputFile &file) = 0;
  virtual Status load(InputFile &file, std::string_view format_name) = 0;
  virtual Status save(FILE *out, std::string_view format_name);
  virtual Status relocate(Address from, Address to, AddressSize size);
};

Status register_loader(std::unique_ptr<Loader> loader);

}  // namespace ida::loader
```

#### 21.5.17 `ida::processor`

```cpp
namespace ida::processor {

struct RegisterInfo {
  std::string name;
  bool read_only;
  bool address_register;
};

struct InstructionDescriptor {
  std::string mnemonic;
  uint32_t feature_flags;
};

class OutputContext {
 public:
  Status mnemonic(std::string_view text, int width = 8);
  Status reg(std::string_view text);
  Status imm(uint64_t value);
  Status addr(Address ea);
  Status symbol(char c);
  Status text(std::string_view text);
  Status comment(std::string_view text);
};

class Processor {
 public:
  struct Info {
    int id;
    std::string short_name;
    std::string long_name;
    int default_bitness;
    std::vector<RegisterInfo> registers;
    std::vector<InstructionDescriptor> instructions;
    int code_sreg;
    int data_sreg;
  };

  virtual ~Processor() = default;
  virtual Info info() const = 0;
  virtual Result<int> analyze(ida::instruction::Instruction &insn) = 0;
  virtual Result<int> emulate(const ida::instruction::Instruction &insn) = 0;
  virtual Status output(OutputContext &ctx,
                        const ida::instruction::Instruction &insn) = 0;
  virtual Status output_operand(OutputContext &ctx,
                                const ida::instruction::Operand &op) = 0;
};

Status register_processor(std::unique_ptr<Processor> processor);

}  // namespace ida::processor
```

#### 21.5.18 `ida::debugger`

```cpp
namespace ida::debugger {

enum class ProcessState {
  NoProcess,
  Running,
  Suspended,
};

Status start(std::string_view path = {},
             std::string_view args = {},
             std::string_view working_dir = {});
Status attach(int pid);
Status detach();
Status terminate();

Status suspend();
Status resume();
Status step_into();
Status step_over();
Status step_out();
Status run_to(Address ea);

Result<ProcessState> state();
Result<Address> instruction_pointer();
Result<Address> stack_pointer();

Result<uint64_t> register_value(std::string_view reg_name);
Status set_register(std::string_view reg_name, uint64_t value);

Status add_breakpoint(Address ea);
Status remove_breakpoint(Address ea);
Result<bool> has_breakpoint(Address ea);

Result<std::vector<uint8_t>> read_memory(Address ea, AddressSize size);
Status write_memory(Address ea, std::span<const uint8_t> bytes);

enum class AppcallValueKind {
  SignedInteger,
  UnsignedInteger,
  FloatingPoint,
  String,
  Address,
  Boolean,
};

struct AppcallValue {
  AppcallValueKind kind;
  int64_t signed_value;
  uint64_t unsigned_value;
  double floating_value;
  std::string string_value;
  Address address_value;
  bool boolean_value;
};

struct AppcallOptions {
  std::optional<int> thread_id;
  bool manual;
  bool include_debug_event;
  std::optional<uint32_t> timeout_milliseconds;
};

struct AppcallRequest {
  Address function_address;
  ida::type::TypeInfo function_type;
  std::vector<AppcallValue> arguments;
  AppcallOptions options;
};

struct AppcallResult {
  AppcallValue return_value;
  std::string diagnostics;
};

class AppcallExecutor {
 public:
  virtual ~AppcallExecutor() = default;
  virtual Result<AppcallResult> execute(const AppcallRequest &request) = 0;
};

Result<AppcallResult> appcall(const AppcallRequest &request);
Status cleanup_appcall(std::optional<int> thread_id = std::nullopt);
Status register_executor(std::string_view name, std::shared_ptr<AppcallExecutor> executor);
Status unregister_executor(std::string_view name);
Result<AppcallResult> appcall_with_executor(std::string_view name,
                                            const AppcallRequest &request);

}  // namespace ida::debugger
```

#### 21.5.19 `ida::ui`, `ida::graph`, `ida::event`

```cpp
namespace ida::event {

using Token = uint64_t;

Token on_segment_created(std::function<void(ida::Address)> callback);
Token on_segment_deleted(std::function<void(ida::Address, ida::Address)> callback);
Token on_function_created(std::function<void(ida::Address)> callback);
Token on_name_changed(std::function<void(ida::Address, std::string, std::string)> callback);

Status unsubscribe(Token token);

class ScopedSubscription {
 public:
  explicit ScopedSubscription(Token token);
  ~ScopedSubscription();
};

}  // namespace ida::event
```

#### 21.5.20 `ida::decompiler`

```cpp
namespace ida::decompiler {

class DecompiledFunction {
 public:
  Result<std::string> pseudocode() const;
  Result<std::vector<std::string>> lines() const;

  Result<size_t> variable_count() const;
  Result<Status> rename_variable(size_t index, std::string_view name);
  Result<Status> retype_variable(size_t index, const ida::type::TypeInfo &type);

  Result<Address> map_line_to_address(size_t line, size_t column) const;
};

Result<bool> available();
Result<DecompiledFunction> decompile(Address ea);

enum class VisitResult {
  Continue,
  Stop,
  SkipChildren,
};

class CtreeVisitor {
 public:
  virtual ~CtreeVisitor() = default;
  virtual VisitResult expression(/* opaque expression view */) = 0;
  virtual VisitResult statement(/* opaque statement view */) = 0;
};

}  // namespace ida::decompiler
```

#### 21.5.21 `ida::storage` (advanced)

```cpp
namespace ida::storage {

class Node {
 public:
  static Result<Node> open(std::string_view name, bool create = false);
  static Result<Node> from_id(uint64_t id);

  Result<bool> exists() const;
  Result<uint64_t> id() const;

  Result<std::vector<uint8_t>> value() const;
  Status set_value(std::span<const uint8_t> data);

  Result<uint64_t> alt(Address index, uint8_t tag = 'A') const;
  Status set_alt(Address index, uint64_t value, uint8_t tag = 'A');
  Status del_alt(Address index, uint8_t tag = 'A');

  Result<std::vector<uint8_t>> sup(Address index, uint8_t tag = 'S') const;
  Status set_sup(Address index, std::span<const uint8_t> data, uint8_t tag = 'S');

  Result<std::string> hash(std::string_view key, uint8_t tag = 'H') const;
  Status set_hash(std::string_view key, std::string_view value, uint8_t tag = 'H');
};

}  // namespace ida::storage
```

### 21.6 Refined implementation phasing (interface-first)

1. Core end-user analysis domains first (`address`, `data`, `segment`, `function`, `instruction`, `name`, `xref`, `comment`, `type`, `search`, `analysis`, `database`).
2. Module-author domains next (`plugin`, `loader`, `processor`).
3. High-complexity/interactive domains after (`debugger`, `decompiler`, `ui`, `graph`, `event`, `storage`).

### 21.7 Proposed implementation layout (hybrid)

```text
include/ida/
  *.hpp               # public API
  detail/*.hpp        # private helper headers

src/
  *.cpp               # compiled adapters and stateful wrappers
  detail/*.cpp        # internal bridges, lifecycle logic, event bridges

tests/
  unit/
  integration/
  scenario/

examples/
  plugin/
  loader/
  procmod/
```

### 21.8 Compliance note for this section

This section is part of the mandatory baseline. If interfaces evolve, this section must be updated immediately and corresponding updates must be logged in:
- Phase TODO status
- Findings and Learnings
- Decision Log (if design changed)
- Progress Ledger

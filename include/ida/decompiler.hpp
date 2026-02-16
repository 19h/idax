/// \file decompiler.hpp
/// \brief Decompiler facade: availability, decompilation, pseudocode access,
///        ctree traversal, and user comment management.
///
/// The decompiler wraps the Hex-Rays SDK. All decompiler functions return
/// errors if the decompiler is not available (not installed or not licensed).

#ifndef IDAX_DECOMPILER_HPP
#define IDAX_DECOMPILER_HPP

#include <ida/error.hpp>
#include <ida/address.hpp>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace ida::type {
class TypeInfo;
}

namespace ida::decompiler {

/// Ctree maturity stage.
enum class Maturity : int {
    Zero   = 0,
    Built  = 1,
    Trans1 = 2,
    Nice   = 3,
    Trans2 = 4,
    Cpa    = 5,
    Trans3 = 6,
    Casted = 7,
    Final  = 8,
};

/// Event payload for a ctree maturity transition.
struct MaturityEvent {
    Address  function_address{BadAddress};
    Maturity new_maturity{Maturity::Zero};
};

/// Event payload for func_printed / refresh_pseudocode events.
/// Provides the function address whose pseudocode was affected.
struct PseudocodeEvent {
    Address function_address{BadAddress};

    /// Opaque handle to the cfunc_t* (as void*).
    /// Passed to raw_pseudocode_lines() and set_pseudocode_line() for
    /// in-place pseudocode text modification during func_printed callbacks.
    void* cfunc_handle{nullptr};
};

/// Event payload for curpos (cursor position changed) events.
struct CursorPositionEvent {
    Address function_address{BadAddress};
    Address cursor_address{BadAddress};

    /// Opaque handle to the vdui_t* (as void*).
    void* view_handle{nullptr};
};

/// Event payload for create_hint events.
struct HintRequestEvent {
    Address function_address{BadAddress};
    Address item_address{BadAddress};

    /// Opaque handle to the vdui_t* (as void*).
    void* view_handle{nullptr};
};

/// Hint result returned from create_hint subscribers.
struct HintResult {
    std::string text;    ///< Hint text to display (empty = no hint).
    int         lines{0}; ///< Number of lines in the hint.
};

/// Decompiler event subscription token.
using Token = std::uint64_t;

/// Subscribe to decompiler maturity transitions.
/// Callback is fired on `hxe_maturity` events.
Result<Token> on_maturity_changed(std::function<void(const MaturityEvent&)> callback);

/// Subscribe to the func_printed event (fired after pseudocode text is generated).
///
/// This is the primary hook for post-processing decompiler output.
/// Within the callback, use raw_pseudocode_lines() and set_pseudocode_line()
/// to read and modify the tagged pseudocode text in-place.
Result<Token> on_func_printed(std::function<void(const PseudocodeEvent&)> callback);

/// Subscribe to the refresh_pseudocode event (fired when pseudocode view refreshes).
Result<Token> on_refresh_pseudocode(std::function<void(const PseudocodeEvent&)> callback);

/// Subscribe to the curpos event (fired when cursor moves in pseudocode view).
Result<Token> on_curpos_changed(std::function<void(const CursorPositionEvent&)> callback);

/// Subscribe to the create_hint event (fired when IDA wants a tooltip).
/// Return a non-empty HintResult to provide a tooltip.
Result<Token> on_create_hint(std::function<HintResult(const HintRequestEvent&)> callback);

/// Remove a previously registered decompiler subscription.
Status unsubscribe(Token token);

/// RAII wrapper for decompiler event subscriptions.
class ScopedSubscription {
public:
    ScopedSubscription() = default;
    explicit ScopedSubscription(Token token) : token_(token) {}
    ~ScopedSubscription();

    ScopedSubscription(const ScopedSubscription&) = delete;
    ScopedSubscription& operator=(const ScopedSubscription&) = delete;

    ScopedSubscription(ScopedSubscription&& other) noexcept
        : token_(other.token_) {
        other.token_ = 0;
    }
    ScopedSubscription& operator=(ScopedSubscription&& other) noexcept {
        if (this != &other) {
            reset();
            token_ = other.token_;
            other.token_ = 0;
        }
        return *this;
    }

    void reset();
    [[nodiscard]] Token token() const noexcept { return token_; }
    [[nodiscard]] bool valid() const noexcept { return token_ != 0; }

private:
    Token token_{0};
};

/// Mark a decompiled function cache entry dirty.
/// If `close_views` is true, open pseudocode views may be closed by the SDK.
Status mark_dirty(Address function_address, bool close_views = false);

/// Mark a function and all caller functions dirty in decompiler cache.
/// This is useful after transformations that affect callsite-level decompilation.
Status mark_dirty_with_callers(Address function_address, bool close_views = false);

/// Result returned from microcode-filter apply callbacks.
enum class MicrocodeApplyResult : int {
    NotHandled = 0,  ///< Let the SDK use default lifting.
    Handled    = 1,  ///< Filter generated microcode.
    Error      = 2,  ///< Filter failed; SDK fallback is used.
};

/// Supported opcode set for generic typed microcode emission.
enum class MicrocodeOpcode : int {
    NoOperation,
    Move,
    Add,
    Subtract,
    Multiply,
    ZeroExtend,
    LoadMemory,
    StoreMemory,
    BitwiseOr,
    BitwiseAnd,
    BitwiseXor,
    ShiftLeft,
    ShiftRightLogical,
    ShiftRightArithmetic,
    FloatAdd,
    FloatSub,
    FloatMul,
    FloatDiv,
    IntegerToFloat,
    FloatToFloat,
};

struct MicrocodeInstruction;

/// Operand kind for generic typed microcode emission.
enum class MicrocodeOperandKind : int {
    Empty,
    Register,
    LocalVariable,
    RegisterPair,
    GlobalAddress,
    StackVariable,
    HelperReference,
    BlockReference,
    NestedInstruction,
    UnsignedImmediate,
    SignedImmediate,
};

/// One typed microcode operand.
struct MicrocodeOperand {
    MicrocodeOperandKind kind{MicrocodeOperandKind::Empty};
    int register_id{0};
    int local_variable_index{0};
    std::int64_t local_variable_offset{0};
    int second_register_id{0};
    Address global_address{BadAddress};
    std::int64_t stack_offset{0};
    std::string helper_name{};
    int block_index{0};
    std::shared_ptr<MicrocodeInstruction> nested_instruction{};
    std::uint64_t unsigned_immediate{0};
    std::int64_t signed_immediate{0};
    int byte_width{0};
    bool mark_user_defined_type{false};
};

/// Generic typed microcode instruction model.
///
/// Operands map to SDK `l`, `r`, and `d` fields respectively.
struct MicrocodeInstruction {
    MicrocodeOpcode opcode{MicrocodeOpcode::NoOperation};
    MicrocodeOperand left{};
    MicrocodeOperand right{};
    MicrocodeOperand destination{};
    bool floating_point_instruction{false};
};

/// Placement policy for emitted microcode instructions.
enum class MicrocodeInsertPolicy : int {
    Tail,        ///< Append at block tail (default behavior).
    Beginning,   ///< Insert at block beginning.
    BeforeTail,  ///< Insert immediately before current block tail.
};

/// Kind of typed microcode value used for helper-call arguments.
enum class MicrocodeValueKind : int {
    Register,
    LocalVariable,
    RegisterPair,
    GlobalAddress,
    StackVariable,
    HelperReference,
    BlockReference,
    NestedInstruction,
    UnsignedImmediate,
    SignedImmediate,
    Float32Immediate,
    Float64Immediate,
    ByteArray,
    Vector,
    TypeDeclarationView,
};

/// Explicit argument-location hint for helper-call arguments.
enum class MicrocodeValueLocationKind : int {
    Unspecified,
    Register,
    RegisterWithOffset,
    RegisterPair,
    RegisterRelative,
    StackOffset,
    StaticAddress,
    Scattered,
};

/// One explicit location fragment for a scattered helper-call argument.
struct MicrocodeLocationPart {
    MicrocodeValueLocationKind kind{MicrocodeValueLocationKind::Unspecified};
    int register_id{0};
    int second_register_id{0};
    int register_offset{0};
    std::int64_t register_relative_offset{0};
    std::int64_t stack_offset{0};
    Address static_address{BadAddress};
    int byte_offset{0};
    int byte_size{0};
};

/// Optional explicit location for a helper-call argument.
struct MicrocodeValueLocation {
    MicrocodeValueLocationKind kind{MicrocodeValueLocationKind::Unspecified};
    int register_id{0};
    int second_register_id{0};
    int register_offset{0};
    std::int64_t register_relative_offset{0};
    std::int64_t stack_offset{0};
    Address static_address{BadAddress};
    std::vector<MicrocodeLocationPart> scattered_parts{};
};

/// Optional per-argument semantic flags for helper-call arguments.
enum class MicrocodeArgumentFlag : std::uint32_t {
    HiddenArgument     = 0x0001,
    ReturnValuePointer = 0x0002,
    StructArgument     = 0x0004,
    ArrayArgument      = 0x0008,
    UnusedArgument     = 0x0010,
};

/// Typed microcode value for helper-call argument construction.
struct MicrocodeValue {
    MicrocodeValueKind kind{MicrocodeValueKind::Register};
    int register_id{0};
    int local_variable_index{0};
    std::int64_t local_variable_offset{0};
    int second_register_id{0};
    Address global_address{BadAddress};
    std::int64_t stack_offset{0};
    std::string helper_name{};
    int block_index{0};
    std::shared_ptr<MicrocodeInstruction> nested_instruction{};
    std::uint64_t unsigned_immediate{0};
    std::int64_t signed_immediate{0};
    double floating_immediate{0.0};
    int byte_width{0};
    bool unsigned_integer{true};
    int vector_element_byte_width{0};
    int vector_element_count{0};
    bool vector_elements_unsigned{true};
    bool vector_elements_floating{false};
    /// C-style type declaration used for typed views.
    ///
    /// - `TypeDeclarationView`: declaration of the argument type (required).
    /// - `Register`: optional declaration override for typed register arguments.
    /// - `Vector`: optional declaration override for element type.
    std::string type_declaration{};

    /// Optional formal argument name for helper-call metadata.
    std::string argument_name{};

    /// Optional bitmask of `MicrocodeArgumentFlag` values.
    std::uint32_t argument_flags{0};

    MicrocodeValueLocation location{};
};

/// Calling-convention override for helper calls.
enum class MicrocodeCallingConvention : int {
    Unspecified,
    Cdecl,
    Stdcall,
    Fastcall,
    Thiscall,
};

/// Optional semantic role hint for emitted helper calls.
enum class MicrocodeFunctionRole : int {
    Unknown,
    Empty,
    Memset,
    Memset32,
    Memset64,
    Memcpy,
    Strcpy,
    Strlen,
    Strcat,
    Tail,
    Bug,
    Alloca,
    ByteSwap,
    Present,
    ContainingRecord,
    FastFail,
    ReadFlags,
    IsMulOk,
    SaturatedMul,
    BitTest,
    BitTestAndSet,
    BitTestAndReset,
    BitTestAndComplement,
    VaArg,
    VaCopy,
    VaStart,
    VaEnd,
    RotateLeft,
    RotateRight,
    CarryFlagSub3,
    OverflowFlagSub3,
    AbsoluteValue,
    ThreeWayCompare0,
    ThreeWayCompare1,
    WideMemCopy,
    WideMemSet,
    WideStrCopy,
    WideStrLen,
    WideStrCat,
    SseCompare4,
    SseCompare8,
};

/// Additional call-shaping options for emitted helper calls.
struct MicrocodeRegisterRange {
    int register_id{0};
    int byte_width{0};
};

struct MicrocodeMemoryRange {
    Address address{BadAddress};
    std::uint64_t byte_size{0};
};

struct MicrocodeCallOptions {
    std::optional<MicrocodeInsertPolicy> insert_policy{};
    std::optional<Address> callee_address{};
    std::optional<int> solid_argument_count{};
    std::optional<int> call_stack_pointer_delta{};
    std::optional<int> stack_arguments_top{};
    std::optional<MicrocodeFunctionRole> function_role{};
    std::optional<MicrocodeValueLocation> return_location{};
    std::string return_type_declaration{};
    MicrocodeCallingConvention calling_convention{MicrocodeCallingConvention::Unspecified};
    bool mark_final{false};
    bool mark_propagated{false};
    bool mark_dead_return_registers{false};
    bool mark_no_return{false};
    bool mark_pure{false};
    bool mark_no_side_effects{false};
    bool mark_spoiled_lists_optimized{false};
    bool mark_synthetic_has_call{false};
    bool mark_has_format_string{false};
    std::optional<std::int64_t> auto_stack_start_offset{};
    std::optional<int> auto_stack_alignment{};
    bool auto_stack_argument_locations{false};
    bool mark_explicit_locations{false};
    std::vector<MicrocodeRegisterRange> return_registers{};
    std::vector<MicrocodeRegisterRange> spoiled_registers{};
    std::vector<MicrocodeRegisterRange> passthrough_registers{};
    std::vector<MicrocodeRegisterRange> dead_registers{};
    std::vector<MicrocodeMemoryRange> visible_memory_ranges{};
    bool visible_memory_all{false};
};

/// Opaque mutable context passed to microcode-filter callbacks.
class MicrocodeContext {
public:
    /// Instruction address currently being lifted.
    [[nodiscard]] Address address() const noexcept;

    /// Processor-specific instruction type code (`insn_t::itype`).
    [[nodiscard]] int instruction_type() const noexcept;

    /// Check whether the current instruction uses an AVX-512 opmask register.
    /// Returns false for non-EVEX instructions or when k0 (no masking) is used.
    [[nodiscard]] bool has_opmask() const noexcept;

    /// Check whether the instruction uses zero-masking (EVEX.z bit set).
    /// Only meaningful when `has_opmask()` returns true.
    [[nodiscard]] bool is_zero_masking() const noexcept;

    /// Return the opmask register number (1-7) for the current instruction.
    /// Returns 0 if no opmask is present (k0 means no masking).
    [[nodiscard]] int opmask_register_number() const noexcept;

    /// Number of local variables available in current microcode context.
    [[nodiscard]] Result<int> local_variable_count() const;

    /// Number of microcode instructions currently present in the active block.
    [[nodiscard]] Result<int> block_instruction_count() const;

    /// Return true when an instruction exists at the specified block index.
    [[nodiscard]] Result<bool> has_instruction_at_index(int instruction_index) const;

    /// Whether this context has tracked at least one emitted instruction.
    [[nodiscard]] Result<bool> has_last_emitted_instruction() const;

    /// Remove the most recently emitted instruction tracked by this context.
    Status remove_last_emitted_instruction();

    /// Remove an instruction by its current zero-based index in the active block.
    Status remove_instruction_at_index(int instruction_index);

    /// Emit a no-op microcode instruction for the current instruction.
    Status emit_noop();

    /// Emit a no-op with explicit placement policy.
    Status emit_noop_with_policy(MicrocodeInsertPolicy policy);

    /// Emit one typed microcode instruction.
    ///
    /// This is the additive generic instruction path for lifter-style
    /// opcode+operand emission without exposing SDK instruction types.
    Status emit_instruction(const MicrocodeInstruction& instruction);

    /// Emit one typed instruction with explicit placement policy.
    Status emit_instruction_with_policy(const MicrocodeInstruction& instruction,
                                        MicrocodeInsertPolicy policy);

    /// Emit multiple typed microcode instructions in order.
    Status emit_instructions(const std::vector<MicrocodeInstruction>& instructions);

    /// Emit multiple typed instructions with explicit placement policy.
    Status emit_instructions_with_policy(const std::vector<MicrocodeInstruction>& instructions,
                                         MicrocodeInsertPolicy policy);

    /// Load an instruction operand into a temporary register.
    /// Returns the SDK register id on success.
    Result<int> load_operand_register(int operand_index);

    /// Load effective address of a memory operand into a temporary register.
    /// Returns the SDK register id on success.
    Result<int> load_effective_address_register(int operand_index);

    /// Allocate a temporary register in the current microcode context.
    /// Returns the SDK register id on success.
    Result<int> allocate_temporary_register(int byte_width);

    /// Store a register value back to an instruction operand.
    Status store_operand_register(int operand_index, int source_register, int byte_width);

    /// Store a register value back to an instruction operand and optionally mark source as UDT.
    Status store_operand_register(int operand_index,
                                  int source_register,
                                  int byte_width,
                                  bool mark_user_defined_type);

    /// Emit register-to-register move.
    Status emit_move_register(int source_register, int destination_register, int byte_width);

    /// Emit register-to-register move and optionally mark operands as UDT.
    Status emit_move_register(int source_register,
                              int destination_register,
                              int byte_width,
                              bool mark_user_defined_type);

    /// Emit register-to-register move with explicit placement policy.
    Status emit_move_register_with_policy(int source_register,
                                          int destination_register,
                                          int byte_width,
                                          MicrocodeInsertPolicy policy);

    /// Emit register-to-register move with explicit placement policy and optional UDT marking.
    Status emit_move_register_with_policy(int source_register,
                                          int destination_register,
                                          int byte_width,
                                          MicrocodeInsertPolicy policy,
                                          bool mark_user_defined_type);

    /// Emit memory load (`m_ldx`) from selector+offset into destination register.
    Status emit_load_memory_register(int selector_register,
                                     int offset_register,
                                     int destination_register,
                                     int byte_width,
                                     int offset_byte_width);

    /// Emit memory load and optionally mark destination operand as UDT.
    Status emit_load_memory_register(int selector_register,
                                     int offset_register,
                                     int destination_register,
                                     int byte_width,
                                     int offset_byte_width,
                                     bool mark_user_defined_type);

    /// Emit memory load with explicit placement policy.
    Status emit_load_memory_register_with_policy(int selector_register,
                                                 int offset_register,
                                                 int destination_register,
                                                 int byte_width,
                                                 int offset_byte_width,
                                                 MicrocodeInsertPolicy policy);

    /// Emit memory load with explicit placement policy and optional UDT marking.
    Status emit_load_memory_register_with_policy(int selector_register,
                                                 int offset_register,
                                                 int destination_register,
                                                 int byte_width,
                                                 int offset_byte_width,
                                                 MicrocodeInsertPolicy policy,
                                                 bool mark_user_defined_type);

    /// Emit memory store (`m_stx`) from source register into selector+offset.
    Status emit_store_memory_register(int source_register,
                                      int selector_register,
                                      int offset_register,
                                      int byte_width,
                                      int offset_byte_width);

    /// Emit memory store and optionally mark source operand as UDT.
    Status emit_store_memory_register(int source_register,
                                      int selector_register,
                                      int offset_register,
                                      int byte_width,
                                      int offset_byte_width,
                                      bool mark_user_defined_type);

    /// Emit memory store with explicit placement policy.
    Status emit_store_memory_register_with_policy(int source_register,
                                                  int selector_register,
                                                  int offset_register,
                                                  int byte_width,
                                                  int offset_byte_width,
                                                  MicrocodeInsertPolicy policy);

    /// Emit memory store with explicit placement policy and optional UDT marking.
    Status emit_store_memory_register_with_policy(int source_register,
                                                  int selector_register,
                                                  int offset_register,
                                                  int byte_width,
                                                  int offset_byte_width,
                                                  MicrocodeInsertPolicy policy,
                                                  bool mark_user_defined_type);

    /// Emit helper call with no explicit arguments.
    Status emit_helper_call(std::string_view helper_name);

    /// Emit helper call with typed arguments.
    ///
    /// Current typed support includes scalar values and byte-array/vector/type-declaration views.
    Status emit_helper_call_with_arguments(
        std::string_view helper_name,
        const std::vector<MicrocodeValue>& arguments);

    /// Emit helper call with typed arguments and additional call options.
    Status emit_helper_call_with_arguments_and_options(
        std::string_view helper_name,
        const std::vector<MicrocodeValue>& arguments,
        const MicrocodeCallOptions& options);

    /// Emit helper call with typed arguments and move the return value to a register.
    ///
    /// Current typed return support is integer-oriented (`destination_byte_width` 1/2/4/8).
    Status emit_helper_call_with_arguments_to_register(
        std::string_view helper_name,
        const std::vector<MicrocodeValue>& arguments,
        int destination_register,
        int destination_byte_width,
        bool destination_unsigned = true);

    /// Emit helper call with typed arguments/return and additional call options.
    Status emit_helper_call_with_arguments_to_register_and_options(
        std::string_view helper_name,
        const std::vector<MicrocodeValue>& arguments,
        int destination_register,
        int destination_byte_width,
        bool destination_unsigned,
        const MicrocodeCallOptions& options);

    /// Emit helper call with typed arguments and move return to a typed microcode operand.
    ///
    /// Destination supports writable operand forms (register/local-variable/
    /// register-pair/global-address/stack-variable).
    Status emit_helper_call_with_arguments_to_micro_operand(
        std::string_view helper_name,
        const std::vector<MicrocodeValue>& arguments,
        const MicrocodeOperand& destination,
        bool destination_unsigned = true);

    /// Emit helper call with typed arguments/return options and micro-operand destination.
    Status emit_helper_call_with_arguments_to_micro_operand_and_options(
        std::string_view helper_name,
        const std::vector<MicrocodeValue>& arguments,
        const MicrocodeOperand& destination,
        bool destination_unsigned,
        const MicrocodeCallOptions& options);

    /// Emit helper call with typed arguments and store return into operand index.
    Status emit_helper_call_with_arguments_to_operand(
        std::string_view helper_name,
        const std::vector<MicrocodeValue>& arguments,
        int destination_operand_index,
        int destination_byte_width,
        bool destination_unsigned = true);

    /// Emit helper call with typed arguments/return, options, and operand writeback.
    Status emit_helper_call_with_arguments_to_operand_and_options(
        std::string_view helper_name,
        const std::vector<MicrocodeValue>& arguments,
        int destination_operand_index,
        int destination_byte_width,
        bool destination_unsigned,
        const MicrocodeCallOptions& options);

    struct Tag {};
    explicit MicrocodeContext(Tag, void* raw) noexcept : raw_(raw) {}

private:
    void* raw_{nullptr};
};

/// Microcode filter interface.
///
/// Filters run during microcode generation and can override lifting for
/// selected instructions.
class MicrocodeFilter {
public:
    virtual ~MicrocodeFilter() = default;
    virtual bool match(const MicrocodeContext& context) = 0;
    virtual MicrocodeApplyResult apply(MicrocodeContext& context) = 0;
};

/// Opaque token for a registered microcode filter.
using FilterToken = std::uint64_t;

/// Register a microcode filter.
Result<FilterToken> register_microcode_filter(std::shared_ptr<MicrocodeFilter> filter);

/// Unregister a previously registered microcode filter.
Status unregister_microcode_filter(FilterToken token);

/// RAII wrapper for microcode-filter registrations.
class ScopedMicrocodeFilter {
public:
    ScopedMicrocodeFilter() = default;
    explicit ScopedMicrocodeFilter(FilterToken token) : token_(token) {}
    ~ScopedMicrocodeFilter();

    ScopedMicrocodeFilter(const ScopedMicrocodeFilter&) = delete;
    ScopedMicrocodeFilter& operator=(const ScopedMicrocodeFilter&) = delete;

    ScopedMicrocodeFilter(ScopedMicrocodeFilter&& other) noexcept
        : token_(other.token_) {
        other.token_ = 0;
    }
    ScopedMicrocodeFilter& operator=(ScopedMicrocodeFilter&& other) noexcept {
        if (this != &other) {
            reset();
            token_ = other.token_;
            other.token_ = 0;
        }
        return *this;
    }

    void reset();
    [[nodiscard]] FilterToken token() const noexcept { return token_; }
    [[nodiscard]] bool valid() const noexcept { return token_ != 0; }

private:
    FilterToken token_{0};
};

/// Check whether a Hex-Rays decompiler is available.
/// Must be called before other decompiler functions.
/// Returns true if the decompiler was initialized successfully.
Result<bool> available();

/// Structured details for a failed decompilation attempt.
struct DecompileFailure {
    Address     request_address{BadAddress};
    Address     failure_address{BadAddress};
    std::string description;
};

/// Storage location classification for a local variable.
enum class VariableStorage {
    Unknown,   ///< Storage type could not be determined.
    Register,  ///< Stored in a register.
    Stack,     ///< Stored on the stack.
};

/// A local variable in a decompiled function.
struct LocalVariable {
    std::string name;
    std::string type_name;   ///< Type as a C declaration string.
    bool        is_argument{false};
    int         width{0};    ///< Size in bytes.

    // ── Extended properties ─────────────────────────────────────────────

    /// Whether this variable has a user-assigned name (vs. auto-generated).
    bool has_user_name{false};

    /// Whether this variable has a "nice" auto-generated name (vs. generic v1, v2, ...).
    bool has_nice_name{false};

    /// Storage location classification.
    VariableStorage storage{VariableStorage::Unknown};

    /// User comment on this variable (may be empty).
    std::string comment;
};

// ── Ctree item types ────────────────────────────────────────────────────

/// Ctree item type — expression and statement opcodes.
///
/// Expression opcodes (`Expr*`) and statement opcodes (`Stmt*`) correspond
/// to the SDK's `cot_*` and `cit_*` constants respectively.
enum class ItemType : int {
    // ── Expressions ────────────────────────────────────────────────────
    ExprEmpty           = 0,
    ExprComma           = 1,    ///< x, y
    ExprAssign          = 2,    ///< x = y
    ExprAssignBitOr     = 3,    ///< x |= y
    ExprAssignXor       = 4,    ///< x ^= y
    ExprAssignBitAnd    = 5,    ///< x &= y
    ExprAssignAdd       = 6,    ///< x += y
    ExprAssignSub       = 7,    ///< x -= y
    ExprAssignMul       = 8,    ///< x *= y
    ExprAssignShiftRightSigned  = 9,   ///< x >>= y (signed)
    ExprAssignShiftRightUnsigned = 10, ///< x >>= y (unsigned)
    ExprAssignShiftLeft = 11,   ///< x <<= y
    ExprAssignDivSigned = 12,   ///< x /= y (signed)
    ExprAssignDivUnsigned = 13, ///< x /= y (unsigned)
    ExprAssignModSigned = 14,   ///< x %= y (signed)
    ExprAssignModUnsigned = 15, ///< x %= y (unsigned)
    ExprTernary         = 16,   ///< x ? y : z
    ExprLogicalOr       = 17,   ///< x || y
    ExprLogicalAnd      = 18,   ///< x && y
    ExprBitOr           = 19,   ///< x | y
    ExprXor             = 20,   ///< x ^ y
    ExprBitAnd          = 21,   ///< x & y
    ExprEqual           = 22,   ///< x == y
    ExprNotEqual        = 23,   ///< x != y
    ExprSignedGE        = 24,   ///< x >= y (signed)
    ExprUnsignedGE      = 25,   ///< x >= y (unsigned)
    ExprSignedLE        = 26,   ///< x <= y (signed)
    ExprUnsignedLE      = 27,   ///< x <= y (unsigned)
    ExprSignedGT        = 28,   ///< x >  y (signed)
    ExprUnsignedGT      = 29,   ///< x >  y (unsigned)
    ExprSignedLT        = 30,   ///< x <  y (signed)
    ExprUnsignedLT      = 31,   ///< x <  y (unsigned)
    ExprShiftRightSigned   = 32,///< x >> y (signed)
    ExprShiftRightUnsigned = 33,///< x >> y (unsigned)
    ExprShiftLeft       = 34,   ///< x << y
    ExprAdd             = 35,   ///< x + y
    ExprSub             = 36,   ///< x - y
    ExprMul             = 37,   ///< x * y
    ExprDivSigned       = 38,   ///< x / y (signed)
    ExprDivUnsigned     = 39,   ///< x / y (unsigned)
    ExprModSigned       = 40,   ///< x % y (signed)
    ExprModUnsigned     = 41,   ///< x % y (unsigned)
    ExprFloatAdd        = 42,   ///< x + y (fp)
    ExprFloatSub        = 43,   ///< x - y (fp)
    ExprFloatMul        = 44,   ///< x * y (fp)
    ExprFloatDiv        = 45,   ///< x / y (fp)
    ExprFloatNeg        = 46,   ///< -x (fp)
    ExprNeg             = 47,   ///< -x
    ExprCast            = 48,   ///< (type)x
    ExprLogicalNot      = 49,   ///< !x
    ExprBitNot          = 50,   ///< ~x
    ExprDeref           = 51,   ///< *x
    ExprRef             = 52,   ///< &x
    ExprPostInc         = 53,   ///< x++
    ExprPostDec         = 54,   ///< x--
    ExprPreInc          = 55,   ///< ++x
    ExprPreDec          = 56,   ///< --x
    ExprCall            = 57,   ///< x(...)
    ExprIndex           = 58,   ///< x[y]
    ExprMemberRef       = 59,   ///< x.m
    ExprMemberPtr       = 60,   ///< x->m
    ExprNumber          = 61,   ///< numeric constant
    ExprFloatNumber     = 62,   ///< floating-point constant
    ExprString          = 63,   ///< string literal
    ExprObject          = 64,   ///< global object reference
    ExprVariable        = 65,   ///< local variable
    ExprInsn            = 66,   ///< embedded statement (internal)
    ExprSizeof          = 67,   ///< sizeof(x)
    ExprHelper          = 68,   ///< arbitrary helper name
    ExprType            = 69,   ///< arbitrary type
    ExprLast            = 69,

    // ── Statements ─────────────────────────────────────────────────────
    StmtEmpty           = 70,
    StmtBlock           = 71,   ///< { ... }
    StmtExpr            = 72,   ///< expr;
    StmtIf              = 73,   ///< if
    StmtFor             = 74,   ///< for
    StmtWhile           = 75,   ///< while
    StmtDo              = 76,   ///< do
    StmtSwitch          = 77,   ///< switch
    StmtBreak           = 78,   ///< break
    StmtContinue        = 79,   ///< continue
    StmtReturn          = 80,   ///< return
    StmtGoto            = 81,   ///< goto
    StmtAsm             = 82,   ///< __asm
    StmtTry             = 83,   ///< try
    StmtThrow           = 84,   ///< throw
};

/// Return true if the item type is an expression.
[[nodiscard]] inline bool is_expression(ItemType t) noexcept {
    return static_cast<int>(t) <= static_cast<int>(ItemType::ExprLast);
}

/// Return true if the item type is a statement.
[[nodiscard]] inline bool is_statement(ItemType t) noexcept {
    return static_cast<int>(t) > static_cast<int>(ItemType::ExprLast);
}

// ── Opaque ctree item views ─────────────────────────────────────────────

/// Read-only view of a ctree expression.
///
/// Lightweight non-owning handle. Valid only during visitor callbacks.
class ExpressionView {
public:
    /// Item type (always an expression opcode).
    [[nodiscard]] ItemType type() const noexcept;

    /// Address associated with this expression (may be BadAddress).
    [[nodiscard]] Address address() const noexcept;

    /// For ExprNumber: return the numeric value. Error otherwise.
    [[nodiscard]] Result<std::uint64_t> number_value() const;

    /// For ExprObject: return the referenced address. Error otherwise.
    [[nodiscard]] Result<Address> object_address() const;

    /// For ExprVariable: return the local variable index. Error otherwise.
    [[nodiscard]] Result<int> variable_index() const;

    /// For ExprString: return the string constant. Error otherwise.
    [[nodiscard]] Result<std::string> string_value() const;

    /// For ExprCall: return the number of arguments. Error otherwise.
    [[nodiscard]] Result<std::size_t> call_argument_count() const;

    /// For ExprCall: return the callee expression. Error otherwise.
    [[nodiscard]] Result<ExpressionView> call_callee() const;

    /// For ExprCall: return the argument expression at index. Error otherwise.
    [[nodiscard]] Result<ExpressionView> call_argument(std::size_t index) const;

    /// For ExprMemberRef/ExprMemberPtr: return the member offset. Error otherwise.
    [[nodiscard]] Result<std::uint32_t> member_offset() const;

    // ── Sub-expression navigation ───────────────────────────────────────

    /// For binary/unary expressions: return the left (first) operand.
    /// Works for assignments, arithmetic, comparisons, casts, dereferences, etc.
    /// Returns an error for leaf expressions (numbers, variables, objects).
    [[nodiscard]] Result<ExpressionView> left() const;

    /// For binary expressions: return the right (second) operand.
    /// Works for assignments, arithmetic, comparisons, etc.
    /// Returns an error for unary or leaf expressions.
    [[nodiscard]] Result<ExpressionView> right() const;

    /// Get the operand count (0 for leaves, 1 for unary, 2 for binary, etc.).
    [[nodiscard]] int operand_count() const noexcept;

    /// Get a C-like text representation of the expression.
    [[nodiscard]] Result<std::string> to_string() const;

    // ── Internal ────────────────────────────────────────────────────────
    struct Tag {};
    explicit ExpressionView(Tag, void* raw) noexcept : raw_(raw) {}

private:
    void* raw_{nullptr};
};

/// Read-only view of a ctree statement.
///
/// Lightweight non-owning handle. Valid only during visitor callbacks.
class StatementView {
public:
    /// Item type (always a statement opcode).
    [[nodiscard]] ItemType type() const noexcept;

    /// Address associated with this statement (may be BadAddress).
    [[nodiscard]] Address address() const noexcept;

    /// For StmtGoto: return the target label number. Error otherwise.
    [[nodiscard]] Result<int> goto_target_label() const;

    // ── Internal ────────────────────────────────────────────────────────
    struct Tag {};
    explicit StatementView(Tag, void* raw) noexcept : raw_(raw) {}

private:
    void* raw_{nullptr};
};

// ── Visitor ─────────────────────────────────────────────────────────────

/// Result returned from visitor callbacks to control traversal.
enum class VisitAction : int {
    Continue     = 0,   ///< Continue traversal normally.
    Stop         = 1,   ///< Stop traversal immediately.
    SkipChildren = 2,   ///< Skip children of current item.
};

/// Callback-based ctree visitor.
///
/// Derive from this class and override expression/statement visitors.
/// Call `visit()` or `visit_expressions()` to start traversal.
class CtreeVisitor {
public:
    virtual ~CtreeVisitor() = default;

    /// Called for each expression (pre-order).
    virtual VisitAction visit_expression(ExpressionView expr);

    /// Called for each statement (pre-order).
    virtual VisitAction visit_statement(StatementView stmt);

    /// Called for each expression after children (post-order).
    /// Only called if post-order mode was requested in visit().
    virtual VisitAction leave_expression(ExpressionView expr);

    /// Called for each statement after children (post-order).
    /// Only called if post-order mode was requested in visit().
    virtual VisitAction leave_statement(StatementView stmt);
};

/// Traversal options for ctree visiting.
struct VisitOptions {
    bool post_order{false};     ///< Also call leave_* callbacks.
    bool track_parents{false};  ///< Maintain parent chain (unused in current API).
    bool expressions_only{false}; ///< Only visit expressions, skip statements.
};

// ── User comment position ───────────────────────────────────────────────

/// Where a user comment attaches relative to a ctree item.
enum class CommentPosition : int {
    Default     = 0,    ///< End-of-line comment at the item's address.
    Semicolon   = 259,  ///< Comment at the semicolon.
    OpenBrace   = 260,  ///< Comment at the opening brace.
    CloseBrace  = 261,  ///< Comment at the closing brace.
    ElseLine    = 258,  ///< Comment at the else line.
};

// ── Address mapping entry ───────────────────────────────────────────────

/// Maps between binary addresses and pseudocode line numbers.
struct AddressMapping {
    Address address;
    int     line_number;   ///< 0-based pseudocode line index.
};

/// Decompiled-function handle.
///
/// Holds the result of a decompilation. Pseudocode text and local variables
/// are available as long as this object is alive.
class DecompiledFunction {
public:
    /// Get the full pseudocode as a single string.
    [[nodiscard]] Result<std::string> pseudocode() const;

    /// Get decompiler microcode as a single string.
    [[nodiscard]] Result<std::string> microcode() const;

    /// Get the pseudocode as individual lines (stripped of color codes).
    [[nodiscard]] Result<std::vector<std::string>> lines() const;

    /// Get the raw pseudocode lines with IDA color tags preserved.
    ///
    /// Each string contains embedded color-tag bytes (COLOR_ON, COLOR_ADDR, etc.).
    /// Use ida::lines utilities (tag_remove, COLSTR) to parse and modify.
    [[nodiscard]] Result<std::vector<std::string>> raw_lines() const;

    /// Replace a specific raw pseudocode line (0-indexed, including header lines).
    ///
    /// The replacement string should contain valid IDA color tags.
    /// This method directly modifies the cfunc_t's pseudocode buffer, so changes
    /// are visible in the current decompiler view after a refresh.
    Status set_raw_line(std::size_t line_index, std::string_view tagged_text);

    /// Get the number of header lines (function prototype, variable declarations).
    /// Body pseudocode starts at line index `header_line_count()`.
    [[nodiscard]] Result<int> header_line_count() const;

    /// Get decompiler microcode as individual lines.
    [[nodiscard]] Result<std::vector<std::string>> microcode_lines() const;

    /// Get the function prototype/declaration line.
    [[nodiscard]] Result<std::string> declaration() const;

    /// Number of local variables (including arguments).
    [[nodiscard]] Result<std::size_t> variable_count() const;

    /// Get all local variables.
    [[nodiscard]] Result<std::vector<LocalVariable>> variables() const;

    /// Rename a local variable (persistent — saved to database).
    Status rename_variable(std::string_view old_name, std::string_view new_name);

    /// Retype a local variable by name (persistent — saved to database).
    /// Call refresh() after success to update pseudocode text.
    Status retype_variable(std::string_view variable_name,
                           const ida::type::TypeInfo& new_type);

    /// Retype a local variable by index from variables() (persistent).
    /// Call refresh() after success to update pseudocode text.
    Status retype_variable(std::size_t variable_index,
                           const ida::type::TypeInfo& new_type);

    // ── Ctree traversal ─────────────────────────────────────────────────

    /// Traverse the function's ctree with a visitor.
    /// Returns the number of items visited, or an error.
    Result<int> visit(CtreeVisitor& visitor,
                      const VisitOptions& options = {}) const;

    /// Traverse only expressions in the function's ctree.
    /// Convenience: equivalent to visit() with expressions_only=true.
    Result<int> visit_expressions(CtreeVisitor& visitor,
                                  bool post_order = false) const;

    // ── User comments ───────────────────────────────────────────────────

    /// Set a user-defined comment at a specific address in the pseudocode.
    /// Pass an empty string to remove the comment.
    /// Call save_comments() afterward to persist to the database.
    Status set_comment(Address ea, std::string_view text,
                       CommentPosition pos = CommentPosition::Default);

    /// Get the user-defined comment at a specific address.
    /// Returns empty string if no comment is set.
    Result<std::string> get_comment(Address ea,
                                    CommentPosition pos = CommentPosition::Default) const;

    /// Save all user-defined comments to the database.
    Status save_comments() const;

    /// Return true if the decompiler has orphan user comments.
    [[nodiscard]] Result<bool> has_orphan_comments() const;

    /// Remove orphan user comments from the current decompiled function.
    /// Call save_comments() afterward to persist removal to the database.
    [[nodiscard]] Result<int> remove_orphan_comments();

    /// Refresh the pseudocode text (invalidates cached text/lines).
    /// Useful after modifying comments, variable names, or types.
    Status refresh() const;

    // ── Address mapping ─────────────────────────────────────────────────

    /// Get the entry address of the decompiled function.
    [[nodiscard]] Address entry_address() const;

    /// Map a pseudocode line number (0-based) to the best-match binary address.
    /// Returns BadAddress if no mapping is available for the given line.
    [[nodiscard]] Result<Address> line_to_address(int line_number) const;

    /// Get all address-to-line mappings for the function.
    [[nodiscard]] Result<std::vector<AddressMapping>> address_map() const;

    // ── Lifecycle ───────────────────────────────────────────────────────
    struct Impl;
    explicit DecompiledFunction(Impl* p) : impl_(p) {}
    ~DecompiledFunction();

    DecompiledFunction(const DecompiledFunction&) = delete;
    DecompiledFunction& operator=(const DecompiledFunction&) = delete;
    DecompiledFunction(DecompiledFunction&&) noexcept;
    DecompiledFunction& operator=(DecompiledFunction&&) noexcept;

private:
    Impl* impl_{nullptr};
};

/// Typed decompiler-view edit/session helper.
///
/// This class stores only stable function-address identity and exposes
/// high-value edit/read flows without leaking SDK `vdui_t`/`cfunc_t` types.
class DecompilerView {
public:
    /// Function entry address represented by this view/session.
    [[nodiscard]] Address function_address() const noexcept { return function_address_; }

    /// Resolve the current function name.
    [[nodiscard]] Result<std::string> function_name() const;

    /// Decompile the represented function.
    [[nodiscard]] Result<DecompiledFunction> decompiled_function() const;

    /// Rename local variable by name.
    Status rename_variable(std::string_view old_name, std::string_view new_name) const;

    /// Retype local variable by name.
    Status retype_variable(std::string_view variable_name,
                           const ida::type::TypeInfo& new_type) const;

    /// Retype local variable by index.
    Status retype_variable(std::size_t variable_index,
                           const ida::type::TypeInfo& new_type) const;

    /// Set user comment for represented function pseudocode.
    Status set_comment(Address address,
                       std::string_view text,
                       CommentPosition pos = CommentPosition::Default) const;

    /// Get user comment for represented function pseudocode.
    [[nodiscard]] Result<std::string> get_comment(Address address,
                                                  CommentPosition pos = CommentPosition::Default) const;

    /// Persist user comments.
    Status save_comments() const;

    /// Refresh decompiler state for represented function.
    Status refresh() const;

    struct Tag {};
    explicit DecompilerView(Tag, Address function_address) noexcept
        : function_address_(function_address) {}

private:
    Address function_address_{BadAddress};
};

/// Build a typed decompiler-view session from an opaque host (`vdui_t*` as `void*`).
Result<DecompilerView> view_from_host(void* decompiler_view_host);

/// Build a typed decompiler-view session for the function containing `address`.
Result<DecompilerView> view_for_function(Address address);

/// Build a typed decompiler-view session from the current pseudocode widget.
Result<DecompilerView> current_view();

/// Decompile the function at \p ea.
/// The decompiler must be available (call available() first or handle the error).
///
/// If `failure` is non-null and decompilation fails, it is populated with
/// failure details (including failure_address when provided by Hex-Rays).
Result<DecompiledFunction> decompile(Address ea, DecompileFailure* failure);

/// Decompile the function at \p ea.
/// The decompiler must be available (call available() first or handle the error).
Result<DecompiledFunction> decompile(Address ea);

// ── Raw pseudocode access from event handles ────────────────────────────

/// Get raw tagged pseudocode lines from a cfunc handle (obtained from PseudocodeEvent).
/// Each string contains IDA color-tag bytes. Returns an empty vector on error.
Result<std::vector<std::string>> raw_pseudocode_lines(void* cfunc_handle);

/// Replace a specific raw pseudocode line via cfunc handle (for use in func_printed callbacks).
Status set_pseudocode_line(void* cfunc_handle, std::size_t line_index,
                           std::string_view tagged_text);

/// Get the number of header lines from a cfunc handle.
Result<int> pseudocode_header_line_count(void* cfunc_handle);

// ── Ctree item at pseudocode position ───────────────────────────────────

/// Information about a ctree item at a specific pseudocode position.
struct ItemAtPosition {
    ItemType type{ItemType::ExprEmpty};
    Address  address{BadAddress};
    int      item_index{-1};      ///< Unique item index within the function.
    bool     is_expression{false};
};

/// Look up the ctree item at a character position in a pseudocode line.
///
/// @param cfunc_handle  Opaque cfunc_t* (from PseudocodeEvent or DecompiledFunction).
/// @param tagged_line   The raw tagged pseudocode line string.
/// @param char_index    Character position within the tagged line.
/// @return Information about the item at that position, or an error.
Result<ItemAtPosition> item_at_position(void* cfunc_handle,
                                        std::string_view tagged_line,
                                        int char_index);

// ── Item type name resolution ───────────────────────────────────────────

/// Get the human-readable name of an ItemType (e.g. "ExprCall", "StmtIf").
[[nodiscard]] std::string item_type_name(ItemType type);

// ── Functional-style visitor helpers ────────────────────────────────────

/// Visit all expressions in a decompiled function using a callback.
/// The callback receives each ExpressionView and returns a VisitAction.
Result<int> for_each_expression(
    const DecompiledFunction& func,
    std::function<VisitAction(ExpressionView)> callback);

/// Visit all ctree items (expressions + statements) using callbacks.
Result<int> for_each_item(
    const DecompiledFunction& func,
    std::function<VisitAction(ExpressionView)> on_expr,
    std::function<VisitAction(StatementView)> on_stmt);

} // namespace ida::decompiler

#endif // IDAX_DECOMPILER_HPP

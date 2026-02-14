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

/// Decompiler event subscription token.
using Token = std::uint64_t;

/// Subscribe to decompiler maturity transitions.
/// Callback is fired on `hxe_maturity` events.
Result<Token> on_maturity_changed(std::function<void(const MaturityEvent&)> callback);

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

/// Kind of typed microcode value used for helper-call arguments.
enum class MicrocodeValueKind : int {
    Register,
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

/// Typed microcode value for helper-call argument construction.
struct MicrocodeValue {
    MicrocodeValueKind kind{MicrocodeValueKind::Register};
    int register_id{0};
    std::uint64_t unsigned_immediate{0};
    std::int64_t signed_immediate{0};
    double floating_immediate{0.0};
    int byte_width{0};
    bool unsigned_integer{true};
    int vector_element_byte_width{0};
    int vector_element_count{0};
    bool vector_elements_unsigned{true};
    bool vector_elements_floating{false};
    std::string type_declaration{};
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

/// Additional call-shaping options for emitted helper calls.
struct MicrocodeCallOptions {
    std::optional<Address> callee_address{};
    std::optional<int> solid_argument_count{};
    std::optional<int> call_stack_pointer_delta{};
    std::optional<int> stack_arguments_top{};
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
    bool mark_explicit_locations{false};
};

/// Opaque mutable context passed to microcode-filter callbacks.
class MicrocodeContext {
public:
    /// Instruction address currently being lifted.
    [[nodiscard]] Address address() const noexcept;

    /// Processor-specific instruction type code (`insn_t::itype`).
    [[nodiscard]] int instruction_type() const noexcept;

    /// Emit a no-op microcode instruction for the current instruction.
    Status emit_noop();

    /// Load an instruction operand into a temporary register.
    /// Returns the SDK register id on success.
    Result<int> load_operand_register(int operand_index);

    /// Load effective address of a memory operand into a temporary register.
    /// Returns the SDK register id on success.
    Result<int> load_effective_address_register(int operand_index);

    /// Store a register value back to an instruction operand.
    Status store_operand_register(int operand_index, int source_register, int byte_width);

    /// Emit register-to-register move.
    Status emit_move_register(int source_register, int destination_register, int byte_width);

    /// Emit memory load (`m_ldx`) from selector+offset into destination register.
    Status emit_load_memory_register(int selector_register,
                                     int offset_register,
                                     int destination_register,
                                     int byte_width,
                                     int offset_byte_width);

    /// Emit memory store (`m_stx`) from source register into selector+offset.
    Status emit_store_memory_register(int source_register,
                                      int selector_register,
                                      int offset_register,
                                      int byte_width,
                                      int offset_byte_width);

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

/// A local variable in a decompiled function.
struct LocalVariable {
    std::string name;
    std::string type_name;   ///< Type as a C declaration string.
    bool        is_argument{false};
    int         width{0};    ///< Size in bytes.
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

/// Decompile the function at \p ea.
/// The decompiler must be available (call available() first or handle the error).
///
/// If `failure` is non-null and decompilation fails, it is populated with
/// failure details (including failure_address when provided by Hex-Rays).
Result<DecompiledFunction> decompile(Address ea, DecompileFailure* failure);

/// Decompile the function at \p ea.
/// The decompiler must be available (call available() first or handle the error).
Result<DecompiledFunction> decompile(Address ea);

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

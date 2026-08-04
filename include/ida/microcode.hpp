/// \file microcode.hpp
/// \brief Post-hoc microcode snapshot API.
///
/// This namespace exposes Hex-Rays microcode (`mba_t` / `mblock_t` /
/// `minsn_t` / `mop_t`) as deep-copied value snapshots that can be consumed
/// long after the Hex-Rays decompiler has finished running.
///
/// It complements the live `MicrocodeContext` filter API in
/// `ida::decompiler` (which is only valid *during* microcode lifting) by
/// providing the opposite shape: lift first, then walk the entire mba_t
/// tree as plain owned data.
///
/// Typical use: drive an external IR consumer (MIR-style SSA importer,
/// Swift / Rust binding, etc.) that wants a stable, off-line view of the
/// decompiler's microcode without having to register a filter callback.

#ifndef IDAX_MICROCODE_HPP
#define IDAX_MICROCODE_HPP

#include <ida/address.hpp>
#include <ida/decompiler.hpp>
#include <ida/error.hpp>

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace ida::microcode {

/// Maturity at which to snapshot the microcode.
///
/// Mirrors SDK `mba_maturity_t`. `Lvars` is closest to ctree input and the
/// recommended choice for downstream MIR-style consumers.
enum class Maturity : int {
    Generated       = 1,  ///< `MMAT_GENERATED`, raw lifter output.
    Preoptimized    = 2,  ///< `MMAT_PREOPTIMIZED`.
    Locopt          = 3,  ///< `MMAT_LOCOPT`.
    CalledArguments = 4,  ///< `MMAT_CALLS`.
    Glbopt1         = 5,  ///< `MMAT_GLBOPT1`.
    Glbopt2         = 6,  ///< `MMAT_GLBOPT2`.
    Glbopt3         = 7,  ///< `MMAT_GLBOPT3`.
    Lvars           = 8,  ///< `MMAT_LVARS` — recommended for MIR import.
};

/// Block kind, mirroring SDK `mblock_type_t`.
enum class BlockKind : int {
    None     = 0,   ///< Not computed yet.
    Stop     = 1,   ///< Regular exit block.
    NoWay    = 2,   ///< Tail is a noret function.
    OneWay   = 3,   ///< Single successor (regular or `goto`).
    TwoWay   = 4,   ///< Conditional branch.
    NWay     = 5,   ///< Switch / jump table.
    External = 6,   ///< Outside the function range.
};

/// Read-only snapshot of a `mop_t`.
struct Operand {
    /// Operand kind, mirroring SDK `mopt_t`.
    enum class Kind : int {
        None              = 0,   ///< `mop_z`.
        Register           = 1,   ///< `mop_r` — micro register number.
        NumericConstant    = 2,   ///< `mop_n` — integer immediate.
        StringLiteral      = 3,   ///< `mop_str` — string constant.
        NestedInstruction  = 4,   ///< `mop_d` — result of another microinstruction.
        StackVariable      = 5,   ///< `mop_S` — pre-LVAR stack slot.
        GlobalAddress      = 6,   ///< `mop_v` — global variable EA.
        BlockReference     = 7,   ///< `mop_b` — micro-block index.
        CallInfo           = 8,   ///< `mop_f` — call argument list.
        LocalVariable      = 9,   ///< `mop_l` — `lvar_t` reference.
        AddressOf          = 10,  ///< `mop_a` — address-of (lvar/global/stk/reg).
        Helper             = 11,  ///< `mop_h` — helper function name.
        Cases              = 12,  ///< `mop_c` — switch cases.
        FloatConstant      = 13,  ///< `mop_fn` — floating point constant.
        RegisterPair       = 14,  ///< `mop_p` — operand pair.
        Scattered          = 15,  ///< `mop_sc` — scattered location.
    };

    Kind kind{Kind::None};
    int  byte_width{0};                       ///< Size in bytes, or `-1` (`NOSIZE`).

    int           register_id{0};             ///< `mop_r`, `mop_p::lop_r`.
    int           second_register_id{0};      ///< `mop_p::hop_r`.
    std::int64_t  numeric_value{0};           ///< `mop_n` integer value (signed view).
    double        float_value{0.0};           ///< `mop_fn` decoded value (best effort).
    std::int64_t  stack_offset{0};            ///< `mop_S` / `mop_a` stack offset.
    Address       global_address{BadAddress}; ///< `mop_v` / `mop_a` global EA.
    std::string   global_name;                ///< Name at `global_address` (`get_name`), empty if none. Lets a MIR consumer render a call/global by name (e.g. `objc_opt_self`, `sub_…`) instead of a raw address.
    int           local_variable_index{-1};   ///< `mop_l`/`mop_a` index in `mba->vars`.
    std::int64_t  local_variable_offset{0};   ///< `mop_l`/`mop_a` offset within lvar.
    std::string   helper_name;                ///< `mop_h` symbolic helper name.
    std::string   string_literal;             ///< `mop_str` payload.
    int           block_index{-1};            ///< `mop_b` target block index.

    /// For `Kind::NestedInstruction`, identifies a nested microinstruction
    /// owned by the snapshot. Look it up with `FunctionSnapshot::nested_instruction(id)`.
    int           nested_instruction_id{-1};

    /// For `Kind::CallInfo` (`mop_f`), the call's argument operands in order
    /// (`mcallinfo_t::args`, each `mcallarg_t` is itself a `mop_t`). Empty for
    /// every other kind. Lets a MIR consumer bind a call's arguments (e.g.
    /// `objc_retain(v9)`) instead of dropping them.
    std::vector<Operand> call_arguments;

    /// For `Kind::CallInfo` (`mop_f`), the per-argument `mcallarg_t::flags`
    /// (`FAI_*` bitmask), index-aligned with `call_arguments`. The
    /// load-bearing bit for Swift `sret` / indirect returns is
    /// `FAI_RETPTR` (0x0002) — an argument so flagged is a hidden pointer
    /// to the call's return slot, so a large/existential return value that
    /// never lands in `return_registers` is instead written through this
    /// argument. Empty for every other kind, and the same length as
    /// `call_arguments` for `CallInfo`.
    std::vector<std::uint32_t> argument_flags;

    /// For `Kind::CallInfo` (`mop_f`), the call's return register operands
    /// (`mcallinfo_t::retregs`, a `mopvec_t` — each entry is a full `mop_t`,
    /// usually a `mop_r` register but possibly a pair/stack slot). These are
    /// the locations the call writes its result to, so a MIR consumer can
    /// register a producer for the value read after the call (e.g.
    /// `v5 = <call>` rather than treating the call as `void`). Empty for every
    /// other kind, and empty when the call has no register return value
    /// (e.g. `void`, or an `sret`/indirect return — see `argument_flags`).
    ///
    /// Note: `retregs` is cleared by Hex-Rays once a call is propagated
    /// (`FCI_PROP`/`FCI_DEAD`); `return_register_ids` (built from the more
    /// durable `mcallinfo_t::return_regs` list) survives that and should be
    /// preferred when `return_registers` is unexpectedly empty.
    std::vector<Operand> return_registers;

    /// For `Kind::CallInfo` (`mop_f`), the micro-register numbers
    /// (`mreg_t`) the call returns into, taken from `mcallinfo_t::return_regs`
    /// (an `mlist_t`; only its register part `.reg` is surfaced — memory
    /// return locations are not). Unlike `return_registers` this list is not
    /// cleared on propagation, so it is the durable source of "the call
    /// returns into these registers". Empty for every other kind.
    std::vector<int> return_register_ids;

    /// For `Kind::Cases` (`mop_c`), the switch's case-value -> target-block
    /// mapping, flattened; the default target is `switch_default_target_block`
    /// (-1 if none). Empty for every other kind.
    std::vector<std::int64_t> switch_case_values;

    /// For `Kind::Cases` (`mop_c`), the target micro-block serial for each
    /// entry in `switch_case_values` (parallel, same length). Empty for every
    /// other kind.
    std::vector<int> switch_case_target_blocks;

    /// For `Kind::Cases` (`mop_c`), the default target micro-block serial (the
    /// `mcases_t` group whose values are empty), or `-1` when there is no
    /// default case. `-1` for every other kind.
    int switch_default_target_block{-1};

    /// SSA-style value number copied from `mop_t::valnum`. Zero means unknown.
    /// Present from `MMAT_GLBOPT2` onward; populated for all maturities but
    /// only carries meaning at advanced ones.
    std::optional<int> ssa_version{};

    /// `mop_t::oprops` snapshot (bitmask of `OPROP_*`).
    std::uint8_t  operand_properties{0};
};

/// Read-only snapshot of a `minsn_t`.
struct Instruction {
    int             id{-1};                    ///< Stable id within the owning snapshot.
    Address         source_address{BadAddress};///< `minsn_t::ea`.
    int             opcode{0};                 ///< Raw `mcode_t` value.
    std::string     opcode_name;               ///< Symbolic name (e.g. `"m_add"`).
    Operand         left;                      ///< `minsn_t::l`.
    Operand         right;                     ///< `minsn_t::r`.
    Operand         destination;               ///< `minsn_t::d`.
    std::uint32_t   flags{0};                  ///< `minsn_t::iprops` snapshot.
};

/// Read-only snapshot of a `mblock_t`.
struct Block {
    int                       index{-1};                  ///< `mblock_t::serial`.
    Address                   start_address{BadAddress};  ///< `mblock_t::start`.
    Address                   end_address{BadAddress};    ///< `mblock_t::end`.
    BlockKind                 kind{BlockKind::None};      ///< `mblock_t::type`.
    std::uint32_t             flags{0};                   ///< `mblock_t::flags` snapshot.
    std::vector<int>          predecessor_indices;        ///< From `mblock_t::predset`.
    std::vector<int>          successor_indices;          ///< From `mblock_t::succset`.
    std::vector<Instruction>  instructions;               ///< Top-level instruction stream.
};

/// Read-only snapshot of a `mba_t`.
///
/// Owns its internal storage; safe to outlive the underlying `mba_t`
/// (which is freed by the snapshot helper before this object is returned).
class FunctionSnapshot {
public:
    FunctionSnapshot();
    ~FunctionSnapshot();
    FunctionSnapshot(const FunctionSnapshot&);
    FunctionSnapshot& operator=(const FunctionSnapshot&);
    FunctionSnapshot(FunctionSnapshot&&) noexcept;
    FunctionSnapshot& operator=(FunctionSnapshot&&) noexcept;

    [[nodiscard]] Address  function_address() const noexcept;
    [[nodiscard]] Maturity maturity() const noexcept;

    /// Stack frame totals copied from `mba_t` for downstream consumers.
    [[nodiscard]] std::int64_t local_variables_size() const noexcept;
    [[nodiscard]] std::int64_t saved_registers_size() const noexcept;
    [[nodiscard]] std::int64_t stack_size() const noexcept;

    /// Index into `local_variables()` of the lvar holding the function's
    /// return value (`mba_t::retvaridx`), or `-1` when the function returns
    /// `void` / the return value is undefined. At `MMAT_LVARS` the returned
    /// value lives in this lvar (not on the `m_ret` instruction's operands),
    /// so a MIR consumer recovers `return <expr>` by wiring this lvar's
    /// reaching definition at each `m_ret`.
    [[nodiscard]] int return_value_variable_index() const noexcept;

    /// Top-level blocks, ordered by serial number (`mba_t::natural` order).
    [[nodiscard]] const std::vector<Block>& blocks() const noexcept;

    /// Look up a nested `minsn_t` referenced by `Operand::nested_instruction_id`.
    [[nodiscard]] Result<Instruction> nested_instruction(int nested_instruction_id) const;

    /// Local-variable table visible at this maturity (`mba->vars` snapshot).
    [[nodiscard]] Result<std::vector<ida::decompiler::LocalVariable>>
    local_variables() const;

    /// True when the snapshot has no blocks (e.g. SDK refused to lift).
    [[nodiscard]] bool empty() const noexcept;

    struct Impl;
    explicit FunctionSnapshot(std::shared_ptr<Impl> impl) noexcept;

private:
    std::shared_ptr<Impl> impl_;
};

/// Generate and snapshot the microcode for a function at the chosen maturity.
///
/// Internally calls `gen_microcode(mbr, hf, nullptr, 0, sdk_maturity)`, deep
/// copies every block / instruction / operand into the returned value, and
/// then releases the SDK-owned `mba_t`. The caller therefore owns nothing of
/// the SDK and can move the returned snapshot freely.
///
/// Returns:
/// - `Validation`     if `function_address` is `BadAddress`.
/// - `NotFound`       if there is no function at `function_address`.
/// - `Unsupported`    if the Hex-Rays decompiler is unavailable.
/// - `SdkFailure`     if `gen_microcode` fails (with `hexrays_failure_t` message).
Result<FunctionSnapshot> snapshot(Address function_address, Maturity maturity);

/// Convenience overload: snapshot at `Maturity::Lvars`.
inline Result<FunctionSnapshot> snapshot(Address function_address) {
    return snapshot(function_address, Maturity::Lvars);
}

} // namespace ida::microcode

#endif // IDAX_MICROCODE_HPP

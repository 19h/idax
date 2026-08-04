/// \file microcode.cpp
/// \brief Implementation of `ida::microcode` — post-hoc snapshot of
///        Hex-Rays microcode (mba_t/mblock_t/minsn_t/mop_t).
///
/// The snapshot is constructed by calling `gen_microcode()` to materialise a
/// fresh `mba_t` at the requested maturity, walking it once to deep-copy
/// every operand into plain owned value types, and then releasing the SDK
/// allocation. Consumers receive a self-contained `FunctionSnapshot` whose
/// lifetime is independent of the decompiler.

#include "detail/sdk_bridge.hpp"
#include <ida/microcode.hpp>
#include <ida/decompiler.hpp>

#include <hexrays.hpp>

#include <array>
#include <cstring>
#include <unordered_map>
#include <utility>

namespace ida::microcode {

namespace {

/// Translate `ida::microcode::Maturity` into the SDK enum.
mba_maturity_t to_sdk_maturity(Maturity maturity) noexcept {
    switch (maturity) {
        case Maturity::Generated:       return MMAT_GENERATED;
        case Maturity::Preoptimized:    return MMAT_PREOPTIMIZED;
        case Maturity::Locopt:          return MMAT_LOCOPT;
        case Maturity::CalledArguments: return MMAT_CALLS;
        case Maturity::Glbopt1:         return MMAT_GLBOPT1;
        case Maturity::Glbopt2:         return MMAT_GLBOPT2;
        case Maturity::Glbopt3:         return MMAT_GLBOPT3;
        case Maturity::Lvars:           return MMAT_LVARS;
    }
    return MMAT_LVARS;
}

/// Reverse mapping for round-tripping into the snapshot.
Maturity from_sdk_maturity(mba_maturity_t maturity) noexcept {
    switch (maturity) {
        case MMAT_GENERATED:    return Maturity::Generated;
        case MMAT_PREOPTIMIZED: return Maturity::Preoptimized;
        case MMAT_LOCOPT:       return Maturity::Locopt;
        case MMAT_CALLS:        return Maturity::CalledArguments;
        case MMAT_GLBOPT1:      return Maturity::Glbopt1;
        case MMAT_GLBOPT2:      return Maturity::Glbopt2;
        case MMAT_GLBOPT3:      return Maturity::Glbopt3;
        case MMAT_LVARS:        return Maturity::Lvars;
        case MMAT_ZERO:
        default:                return Maturity::Generated;
    }
}

BlockKind to_block_kind(mblock_type_t kind) noexcept {
    switch (kind) {
        case BLT_NONE: return BlockKind::None;
        case BLT_STOP: return BlockKind::Stop;
        case BLT_0WAY: return BlockKind::NoWay;
        case BLT_1WAY: return BlockKind::OneWay;
        case BLT_2WAY: return BlockKind::TwoWay;
        case BLT_NWAY: return BlockKind::NWay;
        case BLT_XTRN: return BlockKind::External;
    }
    return BlockKind::None;
}

/// Resolve a symbolic name for an `mcode_t` opcode.
///
/// SDK does not export a name table for `mcode_t`, so we maintain our own.
/// Unknown opcodes fall back to `"m_unknown_<hex>"` so the snapshot still
/// carries something useful to downstream consumers.
std::string opcode_to_string(mcode_t opcode) {
    static constexpr std::array<const char*, m_max> names = {
        "m_nop",   "m_stx",   "m_ldx",   "m_ldc",   "m_mov",   "m_neg",
        "m_lnot",  "m_bnot",  "m_xds",   "m_xdu",   "m_low",   "m_high",
        "m_add",   "m_sub",   "m_mul",   "m_udiv",  "m_sdiv",  "m_umod",
        "m_smod",  "m_or",    "m_and",   "m_xor",   "m_shl",   "m_shr",
        "m_sar",   "m_cfadd", "m_ofadd", "m_cfshl", "m_cfshr", "m_sets",
        "m_seto",  "m_setp",  "m_setnz", "m_setz",  "m_setae", "m_setb",
        "m_seta",  "m_setbe", "m_setg",  "m_setge", "m_setl",  "m_setle",
        "m_jcnd",  "m_jnz",   "m_jz",    "m_jae",   "m_jb",    "m_ja",
        "m_jbe",   "m_jg",    "m_jge",   "m_jl",    "m_jle",   "m_jtbl",
        "m_ijmp",  "m_goto",  "m_call",  "m_icall", "m_ret",   "m_push",
        "m_pop",   "m_und",   "m_ext",   "m_f2i",   "m_f2u",   "m_i2f",
        "m_u2f",   "m_f2f",   "m_fneg",  "m_fadd",  "m_fsub",  "m_fmul",
        "m_fdiv",
    };
    const int code = static_cast<int>(opcode);
    if (code >= 0 && code < static_cast<int>(names.size()))
        return names[code];
    char buf[24];
    qsnprintf(buf, sizeof(buf), "m_unknown_%02x", code & 0xff);
    return buf;
}

double decode_float_constant(const fnumber_t* fnum) noexcept {
    if (fnum == nullptr)
        return 0.0;
    // `fpvalue_t` is IDA's processor-independent INTERNAL float representation,
    // not raw IEEE-754 bytes — a `memcpy` of `fnum.w` reinterprets the internal
    // layout as a native double and yields garbage (e.g. `65536.0` decoded as
    // `0.0`). Convert through the SDK helper, which handles every original size
    // (4 / 8 / 10 / 12 bytes) and rounds long double down to double.
    double value = 0.0;
    fnum->fnum.to_double(&value);
    return value;
}

struct OperandPopulationContext {
    int next_nested_id = 0;
    std::unordered_map<int, Instruction> nested;
};

Operand snapshot_operand(const mop_t& op, OperandPopulationContext& ctx);
Instruction snapshot_instruction(const minsn_t& insn, OperandPopulationContext& ctx, int id);

int register_nested(const minsn_t* nested,
                    OperandPopulationContext& ctx) {
    if (nested == nullptr)
        return -1;
    const int id = ctx.next_nested_id++;
    // Insert a placeholder first so a self-referential descent (should it
    // ever occur) cannot recurse infinitely.
    auto [it, inserted] = ctx.nested.try_emplace(id, Instruction{});
    it->second = snapshot_instruction(*nested, ctx, id);
    return id;
}

Operand snapshot_operand(const mop_t& op, OperandPopulationContext& ctx) {
    Operand snap;
    snap.byte_width        = op.size;
    snap.operand_properties = op.oprops;
    if (op.valnum != 0)
        snap.ssa_version = op.valnum;

    switch (op.t) {
        case mop_z:
            snap.kind = Operand::Kind::None;
            break;
        case mop_r:
            snap.kind        = Operand::Kind::Register;
            snap.register_id = op.r;
            break;
        case mop_n:
            snap.kind = Operand::Kind::NumericConstant;
            if (op.nnn != nullptr)
                snap.numeric_value = static_cast<std::int64_t>(op.nnn->value);
            break;
        case mop_str:
            snap.kind = Operand::Kind::StringLiteral;
            if (op.cstr != nullptr)
                snap.string_literal = op.cstr;
            break;
        case mop_d:
            snap.kind                  = Operand::Kind::NestedInstruction;
            snap.nested_instruction_id = register_nested(op.d, ctx);
            break;
        case mop_S:
            snap.kind = Operand::Kind::StackVariable;
            if (op.s != nullptr)
                snap.stack_offset = op.s->off;
            break;
        case mop_v:
            snap.kind           = Operand::Kind::GlobalAddress;
            snap.global_address = op.g;
            snap.global_name    = ida::detail::to_string(get_name(op.g));
            break;
        case mop_b:
            snap.kind        = Operand::Kind::BlockReference;
            snap.block_index = op.b;
            break;
        case mop_f:
            // Call info (`mcallinfo_t`). Surface the argument operands in order
            // so a consumer can bind them; each `mcallarg_t` is itself a `mop_t`
            // (sliced to its base here — the formal name/type are not yet
            // surfaced). Nested-instruction args route through `register_nested`
            // via the recursive `snapshot_operand`, so no inline recursion.
            //
            // Also surface the call's return/output locations:
            //   * `retregs` (`mopvec_t`) — return register operands, each a full
            //     `mop_t`, so a consumer can wire `v5 = <call>` instead of
            //     dropping the result. Cleared by Hex-Rays once the call is
            //     propagated, hence the second, durable source below.
            //   * `return_regs` (`mlist_t`) — the register part is walked into
            //     `return_register_ids` (mreg numbers); survives propagation.
            //   * per-argument `FAI_*` flags — index-aligned with
            //     `call_arguments`. `FAI_RETPTR` marks a hidden `sret` pointer
            //     argument, i.e. the real output location for large/existential
            //     returns that never land in a register.
            snap.kind = Operand::Kind::CallInfo;
            if (op.f != nullptr) {
                snap.call_arguments.reserve(op.f->args.size());
                snap.argument_flags.reserve(op.f->args.size());
                for (const mcallarg_t& argument : op.f->args) {
                    snap.call_arguments.push_back(snapshot_operand(argument, ctx));
                    snap.argument_flags.push_back(static_cast<std::uint32_t>(argument.flags));
                }

                snap.return_registers.reserve(op.f->retregs.size());
                for (const mop_t& return_register : op.f->retregs)
                    snap.return_registers.push_back(snapshot_operand(return_register, ctx));

                // `mlist_t::reg` is an `rlist_t` (a `bitset_t`); each set bit is
                // a micro-register number (`mreg_t`). `bitset_t::iterator` has
                // no `operator++`, so step it explicitly via `inc()`.
                const rlist_t& return_register_list = op.f->return_regs.reg;
                for (rlist_t::iterator it = return_register_list.begin();
                     it != return_register_list.end();
                     return_register_list.inc(it)) {
                    snap.return_register_ids.push_back(static_cast<int>(*it));
                }
            }
            break;
        case mop_l:
            snap.kind = Operand::Kind::LocalVariable;
            if (op.l != nullptr) {
                snap.local_variable_index  = op.l->idx;
                snap.local_variable_offset = op.l->off;
            }
            break;
        case mop_a:
            snap.kind = Operand::Kind::AddressOf;
            if (op.a != nullptr) {
                // mop_addr_t embeds another mop_t describing the pointed-to
                // operand. We surface the most useful identifier per kind.
                switch (op.a->t) {
                    case mop_r:
                        snap.register_id = op.a->r;
                        break;
                    case mop_v:
                        snap.global_address = op.a->g;
                        snap.global_name    = ida::detail::to_string(get_name(op.a->g));
                        break;
                    case mop_S:
                        if (op.a->s != nullptr)
                            snap.stack_offset = op.a->s->off;
                        break;
                    case mop_l:
                        if (op.a->l != nullptr) {
                            snap.local_variable_index  = op.a->l->idx;
                            snap.local_variable_offset = op.a->l->off;
                        }
                        break;
                    default:
                        break;
                }
            }
            break;
        case mop_h:
            snap.kind = Operand::Kind::Helper;
            if (op.helper != nullptr)
                snap.helper_name = op.helper;
            break;
        case mop_c:
            snap.kind = Operand::Kind::Cases;
            if (op.c != nullptr) {
                // `mcases_t` parallels `values` (a `qvector<svalvec_t>`) and
                // `targets` (an `intvec_t`): group `i` jumps to block
                // `targets[i]` for each case value in `values[i]`. The group
                // whose `values[i]` is empty is the default case (its
                // `targets[i]` is the default target block). Flatten each
                // non-default group into parallel (value, target-block) pairs
                // to avoid threading nested vectors through the C ABI.
                const size_t case_group_count = op.c->size();
                for (size_t group_index = 0; group_index < case_group_count; ++group_index) {
                    const svalvec_t& group_values  = op.c->values[group_index];
                    const int        target_block  = op.c->targets[group_index];
                    if (group_values.empty()) {
                        snap.switch_default_target_block = target_block;
                        continue;
                    }
                    for (const sval_t case_value : group_values) {
                        snap.switch_case_values.push_back(
                            static_cast<std::int64_t>(case_value));
                        snap.switch_case_target_blocks.push_back(target_block);
                    }
                }
            }
            break;
        case mop_fn:
            snap.kind        = Operand::Kind::FloatConstant;
            snap.float_value = decode_float_constant(op.fpc);
            break;
        case mop_p:
            snap.kind = Operand::Kind::RegisterPair;
            if (op.pair != nullptr) {
                if (op.pair->lop.t == mop_r)
                    snap.register_id = op.pair->lop.r;
                if (op.pair->hop.t == mop_r)
                    snap.second_register_id = op.pair->hop.r;
            }
            break;
        case mop_sc:
            snap.kind = Operand::Kind::Scattered;
            break;
        default:
            snap.kind = Operand::Kind::None;
            break;
    }
    return snap;
}

Instruction snapshot_instruction(const minsn_t& insn,
                                 OperandPopulationContext& ctx,
                                 int id) {
    Instruction snap;
    snap.id             = id;
    snap.source_address = static_cast<Address>(insn.ea);
    snap.opcode         = static_cast<int>(insn.opcode);
    snap.opcode_name    = opcode_to_string(insn.opcode);
    snap.flags          = static_cast<std::uint32_t>(insn.iprops);
    snap.left           = snapshot_operand(insn.l, ctx);
    snap.right          = snapshot_operand(insn.r, ctx);
    snap.destination    = snapshot_operand(insn.d, ctx);
    return snap;
}

} // namespace

// ── FunctionSnapshot::Impl ──────────────────────────────────────────────

struct FunctionSnapshot::Impl {
    Address                                            function_address{BadAddress};
    Maturity                                           maturity{Maturity::Lvars};
    std::int64_t                                       local_variables_size{0};
    std::int64_t                                       saved_registers_size{0};
    std::int64_t                                       stack_size{0};
    int                                                return_value_variable_index{-1};
    std::vector<Block>                                 blocks;
    std::unordered_map<int, Instruction>               nested_instructions;
    std::vector<ida::decompiler::LocalVariable>        local_variables;
};

FunctionSnapshot::FunctionSnapshot() = default;
FunctionSnapshot::~FunctionSnapshot() = default;
FunctionSnapshot::FunctionSnapshot(const FunctionSnapshot&) = default;
FunctionSnapshot& FunctionSnapshot::operator=(const FunctionSnapshot&) = default;
FunctionSnapshot::FunctionSnapshot(FunctionSnapshot&&) noexcept = default;
FunctionSnapshot& FunctionSnapshot::operator=(FunctionSnapshot&&) noexcept = default;

FunctionSnapshot::FunctionSnapshot(std::shared_ptr<Impl> impl) noexcept
    : impl_(std::move(impl)) {}

Address FunctionSnapshot::function_address() const noexcept {
    return impl_ ? impl_->function_address : BadAddress;
}

Maturity FunctionSnapshot::maturity() const noexcept {
    return impl_ ? impl_->maturity : Maturity::Lvars;
}

std::int64_t FunctionSnapshot::local_variables_size() const noexcept {
    return impl_ ? impl_->local_variables_size : 0;
}

std::int64_t FunctionSnapshot::saved_registers_size() const noexcept {
    return impl_ ? impl_->saved_registers_size : 0;
}

std::int64_t FunctionSnapshot::stack_size() const noexcept {
    return impl_ ? impl_->stack_size : 0;
}

int FunctionSnapshot::return_value_variable_index() const noexcept {
    return impl_ ? impl_->return_value_variable_index : -1;
}

const std::vector<Block>& FunctionSnapshot::blocks() const noexcept {
    static const std::vector<Block> empty;
    return impl_ ? impl_->blocks : empty;
}

bool FunctionSnapshot::empty() const noexcept {
    return !impl_ || impl_->blocks.empty();
}

Result<Instruction> FunctionSnapshot::nested_instruction(int id) const {
    if (!impl_)
        return std::unexpected(Error::not_found("Empty microcode snapshot"));
    auto it = impl_->nested_instructions.find(id);
    if (it == impl_->nested_instructions.end())
        return std::unexpected(Error::not_found(
            "No nested microinstruction with id " + std::to_string(id)));
    return it->second;
}

Result<std::vector<ida::decompiler::LocalVariable>>
FunctionSnapshot::local_variables() const {
    if (!impl_)
        return std::unexpected(Error::not_found("Empty microcode snapshot"));
    return impl_->local_variables;
}

// ── snapshot() entry point ──────────────────────────────────────────────

Result<FunctionSnapshot> snapshot(Address function_address, Maturity maturity) {
    if (function_address == BadAddress)
        return std::unexpected(Error::validation("function_address is BadAddress"));

    auto availability = ida::decompiler::available();
    if (!availability)
        return std::unexpected(availability.error());
    if (!*availability)
        return std::unexpected(Error::unsupported(
            "Decompiler not available (Hex-Rays plugin not loaded)"));

    func_t* function = get_func(static_cast<ea_t>(function_address));
    if (function == nullptr)
        return std::unexpected(Error::not_found(
            "No function at address", std::to_string(function_address)));

    mba_ranges_t ranges(function);
    hexrays_failure_t failure;
    const mba_maturity_t sdk_maturity = to_sdk_maturity(maturity);

    mba_t* mba = gen_microcode(ranges, &failure, nullptr, 0, sdk_maturity);
    if (mba == nullptr) {
        qstring description = failure.desc();
        return std::unexpected(Error::sdk(
            "gen_microcode failed",
            ida::detail::to_string(description)));
    }

    // The SDK ratchets maturity forward; honour whichever level it actually
    // produced rather than the one we requested.
    auto impl = std::make_shared<FunctionSnapshot::Impl>();
    impl->function_address     = function_address;
    impl->maturity             = from_sdk_maturity(mba->maturity);
    impl->local_variables_size = static_cast<std::int64_t>(mba->frsize);
    impl->saved_registers_size = static_cast<std::int64_t>(mba->frregs);
    impl->stack_size           = static_cast<std::int64_t>(mba->stacksize);
    // Index of the lvar carrying the return value. At MMAT_LVARS the returned
    // value lives in this lvar, not on the m_ret operands. `mba_t::retvaridx`
    // is -1 for a void / no-return function, so consumers skip return-value
    // wiring on -1. (The MBA2_UNDEF_RETVAR "undefined return" flag lives in the
    // private `flags2`; there is no public accessor, and retvaridx==-1 already
    // covers the common void case, so it is not consulted here.)
    impl->return_value_variable_index = mba->retvaridx;

    OperandPopulationContext ctx;

    impl->blocks.reserve(mba->qty);
    for (int block_index = 0; block_index < mba->qty; ++block_index) {
        const mblock_t* sdk_block = mba->get_mblock(block_index);
        if (sdk_block == nullptr)
            continue;

        Block block;
        block.index         = sdk_block->serial;
        block.start_address = static_cast<Address>(sdk_block->start);
        block.end_address   = static_cast<Address>(sdk_block->end);
        block.kind          = to_block_kind(sdk_block->type);
        block.flags         = sdk_block->flags;

        block.predecessor_indices.reserve(sdk_block->npred());
        for (int p = 0; p < sdk_block->npred(); ++p)
            block.predecessor_indices.push_back(sdk_block->pred(p));

        block.successor_indices.reserve(sdk_block->nsucc());
        for (int s = 0; s < sdk_block->nsucc(); ++s)
            block.successor_indices.push_back(sdk_block->succ(s));

        for (const minsn_t* mi = sdk_block->head; mi != nullptr; mi = mi->next) {
            const int top_level_id = ctx.next_nested_id++;
            // Reserve the slot so any nested operand created during the walk
            // gets a stable, unique id that is also visible via
            // `nested_instruction()`.
            auto [it, inserted] = ctx.nested.try_emplace(top_level_id, Instruction{});
            Instruction instruction = snapshot_instruction(*mi, ctx, top_level_id);
            it->second = instruction;
            block.instructions.push_back(std::move(instruction));
        }

        impl->blocks.push_back(std::move(block));
    }

    impl->nested_instructions = std::move(ctx.nested);

    // Local variable table — only fully populated from MMAT_LVARS onward,
    // but the SDK always exposes whatever it has so far.
    impl->local_variables.reserve(mba->vars.size());
    for (std::size_t i = 0; i < mba->vars.size(); ++i) {
        const lvar_t& v = mba->vars[i];
        ida::decompiler::LocalVariable lv;
        lv.index       = i;
        lv.name        = ida::detail::to_string(v.name);
        lv.is_argument = v.is_arg_var();
        lv.width       = v.width;
        qstring type_str;
        if (v.type().print(&type_str))
            lv.type_name = ida::detail::to_string(type_str);
        else
            lv.type_name = "(unknown)";
        lv.has_user_name = v.has_user_name();
        lv.has_nice_name = v.has_nice_name();
        lv.comment       = ida::detail::to_string(v.cmt);
        if (v.is_stk_var()) {
            lv.storage = ida::decompiler::VariableStorage::Stack;
        } else if (v.is_reg_var()) {
            lv.storage = ida::decompiler::VariableStorage::Register;
            // Physical microcode register number (mreg_t). On ARM64 the mreg of
            // `x<n>` is `8 + 8*n` (x0=8, x1=16, ...), so this lets consumers map
            // argument lvars back to the ABI registers x0-x7.
            lv.register_number = v.get_reg1();
        } else {
            lv.storage = ida::decompiler::VariableStorage::Unknown;
        }
        impl->local_variables.push_back(std::move(lv));
    }

    // The SDK hands us ownership of `mba`; release it now that we hold a
    // self-contained snapshot.
    delete mba;

    return FunctionSnapshot(std::move(impl));
}

} // namespace ida::microcode

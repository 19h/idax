/// \file decompiler.cpp
/// \brief Implementation of ida::decompiler — wrapping Hex-Rays decompiler API.
///
/// The Hex-Rays API uses runtime function-pointer dispatch (hexdsp_t), so
/// there are no link-time dependencies. We include hexrays.hpp and call
/// init_hexrays_plugin() at runtime to check availability.

#include "detail/sdk_bridge.hpp"
#include "detail/type_impl.hpp"
#include <ida/decompiler.hpp>
#include <ida/function.hpp>

// hexrays.hpp is part of the IDA SDK and provides all decompiler APIs
// through a single runtime dispatch pointer (no link dependencies).
#include <hexrays.hpp>

#include <algorithm>
#include <atomic>
#include <bit>
#include <cstdarg>
#include <memory>
#include <mutex>
#include <unordered_map>

namespace ida::decompiler {

// ── Availability ────────────────────────────────────────────────────────

static bool s_hexrays_initialized = false;

namespace {

std::mutex g_subscription_mutex;
std::unordered_map<Token, std::function<void(const MaturityEvent&)>> g_maturity_callbacks;
std::atomic<std::uint64_t> g_next_token{1};
bool g_hexrays_callback_installed = false;

struct MicrocodeContextImpl {
    codegen_t* codegen{nullptr};
    bool emitted_noop{false};
};

class MicrocodeFilterBridge final : public microcode_filter_t {
public:
    explicit MicrocodeFilterBridge(std::shared_ptr<MicrocodeFilter> filter)
        : filter_(std::move(filter)) {}

    bool match(codegen_t& cdg) override {
        MicrocodeContextImpl impl;
        impl.codegen = &cdg;
        MicrocodeContext context(MicrocodeContext::Tag{}, &impl);
        try {
            return filter_->match(context);
        } catch (...) {
            return false;
        }
    }

    merror_t apply(codegen_t& cdg) override {
        MicrocodeContextImpl impl;
        impl.codegen = &cdg;
        MicrocodeContext context(MicrocodeContext::Tag{}, &impl);

        MicrocodeApplyResult result = MicrocodeApplyResult::Error;
        try {
            result = filter_->apply(context);
        } catch (...) {
            result = MicrocodeApplyResult::Error;
        }
        if (result == MicrocodeApplyResult::Handled) {
            if (!impl.emitted_noop)
                cdg.emit(m_nop, 0, 0, 0, 0, 0);
            return MERR_OK;
        }
        if (result == MicrocodeApplyResult::Error)
            return MERR_INSN;
        return MERR_INSN;
    }

private:
    std::shared_ptr<MicrocodeFilter> filter_;
};

std::mutex g_microcode_filter_mutex;
std::unordered_map<FilterToken, std::unique_ptr<MicrocodeFilterBridge>> g_microcode_filters;
std::atomic<std::uint64_t> g_next_filter_token{1};

Maturity to_maturity(int value) {
    switch (value) {
        case CMAT_ZERO:   return Maturity::Zero;
        case CMAT_BUILT:  return Maturity::Built;
        case CMAT_TRANS1: return Maturity::Trans1;
        case CMAT_NICE:   return Maturity::Nice;
        case CMAT_TRANS2: return Maturity::Trans2;
        case CMAT_CPA:    return Maturity::Cpa;
        case CMAT_TRANS3: return Maturity::Trans3;
        case CMAT_CASTED: return Maturity::Casted;
        case CMAT_FINAL:  return Maturity::Final;
        default:          return Maturity::Zero;
    }
}

bool make_integer_type(tinfo_t* out, int byte_width, bool is_unsigned) {
    if (out == nullptr)
        return false;
    type_t base = 0;
    switch (byte_width) {
        case 1: base = BT_INT8; break;
        case 2: base = BT_INT16; break;
        case 4: base = BT_INT32; break;
        case 8: base = BT_INT64; break;
        default: return false;
    }
    if (is_unsigned)
        base = static_cast<type_t>(base | BTMT_USIGNED);
    *out = tinfo_t(base);
    return true;
}

callcnv_t to_sdk_calling_convention(MicrocodeCallingConvention convention) {
    switch (convention) {
        case MicrocodeCallingConvention::Unspecified: return CM_CC_INVALID;
        case MicrocodeCallingConvention::Cdecl:       return CM_CC_CDECL;
        case MicrocodeCallingConvention::Stdcall:     return CM_CC_STDCALL;
        case MicrocodeCallingConvention::Fastcall:    return CM_CC_FASTCALL;
        case MicrocodeCallingConvention::Thiscall:    return CM_CC_THISCALL;
    }
    return CM_CC_INVALID;
}

Status apply_call_options(minsn_t* root,
                          const MicrocodeCallOptions& options,
                          std::string_view helper_name) {
    const bool has_options =
        options.callee_address.has_value()
        || options.solid_argument_count.has_value()
        || options.call_stack_pointer_delta.has_value()
        || options.stack_arguments_top.has_value()
        ||
        options.calling_convention != MicrocodeCallingConvention::Unspecified
        || options.mark_final
        || options.mark_propagated
        || options.mark_dead_return_registers
        || options.mark_no_return
        || options.mark_pure
        || options.mark_no_side_effects
        || options.mark_spoiled_lists_optimized
        || options.mark_synthetic_has_call
        || options.mark_has_format_string
        || options.mark_explicit_locations;
    if (!has_options)
        return ida::ok();

    if (root == nullptr)
        return std::unexpected(Error::sdk("Helper-call root instruction missing",
                                          std::string(helper_name)));

    minsn_t* call_insn = root->find_call(true);
    if (call_insn == nullptr || call_insn->opcode != m_call || call_insn->d.t != mop_f || call_insn->d.f == nullptr) {
        return std::unexpected(Error::sdk("Helper-call instruction shape not recognized",
                                          std::string(helper_name)));
    }

    mcallinfo_t* info = call_insn->d.f;

    if (options.callee_address.has_value())
        info->callee = static_cast<ea_t>(*options.callee_address);

    if (options.solid_argument_count.has_value()) {
        if (*options.solid_argument_count < 0) {
            return std::unexpected(Error::validation(
                "Solid argument count cannot be negative",
                std::to_string(*options.solid_argument_count)));
        }
        info->solid_args = *options.solid_argument_count;
    }

    if (options.call_stack_pointer_delta.has_value())
        info->call_spd = *options.call_stack_pointer_delta;

    if (options.stack_arguments_top.has_value())
        info->stkargs_top = *options.stack_arguments_top;

    const callcnv_t calling_convention = to_sdk_calling_convention(options.calling_convention);
    if (calling_convention != CM_CC_INVALID)
        info->cc = calling_convention;

    if (options.mark_final)
        info->flags |= FCI_FINAL;
    if (options.mark_propagated)
        info->flags |= FCI_PROP;
    if (options.mark_dead_return_registers)
        info->flags |= FCI_DEAD;
    if (options.mark_no_return)
        info->flags |= FCI_NORET;
    if (options.mark_pure)
        info->flags |= FCI_PURE;
    if (options.mark_no_side_effects)
        info->flags |= FCI_NOSIDE;
    if (options.mark_spoiled_lists_optimized)
        info->flags |= FCI_SPLOK;
    if (options.mark_synthetic_has_call)
        info->flags |= FCI_HASCALL;
    if (options.mark_has_format_string)
        info->flags |= FCI_HASFMT;
    if (options.mark_explicit_locations)
        info->flags |= FCI_EXPLOCS;

    return ida::ok();
}

Status insert_call_instruction(MicrocodeContextImpl* impl,
                               minsn_t* call,
                               std::string_view helper_name) {
    if (impl == nullptr || impl->codegen == nullptr || impl->codegen->mb == nullptr)
        return std::unexpected(Error::internal("MicrocodeContext has incomplete codegen state"));
    if (call == nullptr)
        return std::unexpected(Error::sdk("create_helper_call failed",
                                          std::string(helper_name)));

    if (impl->codegen->mb->insert_into_block(call, impl->codegen->mb->tail) == nullptr) {
        delete call;
        return std::unexpected(Error::sdk("insert_into_block failed",
                                          std::string(helper_name)));
    }
    return ida::ok();
}

struct CallArgumentsBuildResult {
    mcallargs_t arguments;
    bool has_explicit_locations{false};
};

Status apply_single_location_to_argloc(argloc_t* argloc,
                                       MicrocodeValueLocationKind kind,
                                       int register_id,
                                       int second_register_id,
                                       int register_offset,
                                       std::int64_t register_relative_offset,
                                       std::int64_t stack_offset,
                                       Address static_address,
                                       std::string_view context) {
    if (argloc == nullptr)
        return std::unexpected(Error::internal("Null argument location output"));

    switch (kind) {
        case MicrocodeValueLocationKind::Register:
            if (register_id < 0)
                return std::unexpected(Error::validation(
                    "Explicit register id cannot be negative",
                    std::string(context)));
            argloc->set_reg1(register_id);
            return ida::ok();

        case MicrocodeValueLocationKind::RegisterWithOffset:
            if (register_id < 0)
                return std::unexpected(Error::validation(
                    "Explicit register id cannot be negative",
                    std::string(context)));
            argloc->set_reg1(register_id, register_offset);
            return ida::ok();

        case MicrocodeValueLocationKind::RegisterPair:
            if (register_id < 0 || second_register_id < 0)
                return std::unexpected(Error::validation(
                    "Explicit register-pair ids cannot be negative",
                    std::string(context)));
            argloc->set_reg2(register_id, second_register_id);
            return ida::ok();

        case MicrocodeValueLocationKind::RegisterRelative:
            if (register_id < 0)
                return std::unexpected(Error::validation(
                    "Explicit register-relative base register cannot be negative",
                    std::string(context)));
            {
                auto rrel = std::make_unique<rrel_t>();
                rrel->reg = register_id;
                rrel->off = static_cast<sval_t>(register_relative_offset);
                argloc->consume_rrel(rrel.release());
            }
            return ida::ok();

        case MicrocodeValueLocationKind::StackOffset:
            argloc->set_stkoff(static_cast<sval_t>(stack_offset));
            return ida::ok();

        case MicrocodeValueLocationKind::StaticAddress:
            if (static_address == BadAddress)
                return std::unexpected(Error::validation(
                    "Explicit static address cannot be BadAddress",
                    std::string(context)));
            argloc->set_ea(static_cast<ea_t>(static_address));
            return ida::ok();

        case MicrocodeValueLocationKind::Unspecified:
            return std::unexpected(Error::validation(
                "Explicit location kind is unspecified",
                std::string(context)));

        case MicrocodeValueLocationKind::Scattered:
            return std::unexpected(Error::validation(
                "Nested scattered locations are not supported",
                std::string(context)));
    }

    return std::unexpected(Error::validation("Unsupported explicit location kind",
                                             std::string(context)));
}

Status apply_explicit_location(mcallarg_t* callarg,
                               const MicrocodeValueLocation& location,
                               std::size_t index,
                               bool* has_explicit_locations) {
    if (callarg == nullptr || has_explicit_locations == nullptr)
        return std::unexpected(Error::internal("Null helper-call argument/location output"));

    switch (location.kind) {
        case MicrocodeValueLocationKind::Unspecified:
            return ida::ok();

        case MicrocodeValueLocationKind::Register:
        case MicrocodeValueLocationKind::RegisterWithOffset:
        case MicrocodeValueLocationKind::RegisterPair:
        case MicrocodeValueLocationKind::RegisterRelative:
        case MicrocodeValueLocationKind::StackOffset:
        case MicrocodeValueLocationKind::StaticAddress:
            {
                auto status = apply_single_location_to_argloc(&callarg->argloc,
                                                              location.kind,
                                                              location.register_id,
                                                              location.second_register_id,
                                                              location.register_offset,
                                                              location.register_relative_offset,
                                                              location.stack_offset,
                                                              location.static_address,
                                                              std::to_string(index));
                if (!status)
                    return status;
            }
            *has_explicit_locations = true;
            return ida::ok();

        case MicrocodeValueLocationKind::Scattered: {
            if (location.scattered_parts.empty()) {
                return std::unexpected(Error::validation(
                    "Scattered explicit location requires at least one part",
                    std::to_string(index)));
            }

            auto scattered = std::make_unique<scattered_aloc_t>();
            scattered->reserve(location.scattered_parts.size());

            for (std::size_t part_index = 0; part_index < location.scattered_parts.size(); ++part_index) {
                const auto& part = location.scattered_parts[part_index];
                if (part.byte_offset < 0 || part.byte_offset > 0xFFFF) {
                    return std::unexpected(Error::validation(
                        "Scattered location part offset out of range",
                        std::to_string(index) + ":" + std::to_string(part_index)));
                }
                if (part.byte_size <= 0 || part.byte_size > 0xFFFF) {
                    return std::unexpected(Error::validation(
                        "Scattered location part size out of range",
                        std::to_string(index) + ":" + std::to_string(part_index)));
                }

                argpart_t argpart;
                auto status = apply_single_location_to_argloc(&argpart,
                                                              part.kind,
                                                              part.register_id,
                                                              part.second_register_id,
                                                              part.register_offset,
                                                              part.register_relative_offset,
                                                              part.stack_offset,
                                                              part.static_address,
                                                              std::to_string(index) + ":" + std::to_string(part_index));
                if (!status)
                    return status;

                argpart.off = static_cast<ushort>(part.byte_offset);
                argpart.size = static_cast<ushort>(part.byte_size);
                scattered->push_back(std::move(argpart));
            }

            callarg->argloc.consume_scattered(scattered.release());
            *has_explicit_locations = true;
            return ida::ok();
        }
    }

    return std::unexpected(Error::validation("Unsupported argument location kind",
                                             std::to_string(index)));
}

Result<CallArgumentsBuildResult> build_call_arguments(const std::vector<MicrocodeValue>& arguments,
                                                      ea_t instruction_address) {
    CallArgumentsBuildResult result;
    result.arguments.reserve(arguments.size());

    for (std::size_t i = 0; i < arguments.size(); ++i) {
        const auto& argument = arguments[i];
        mcallarg_t callarg;
        switch (argument.kind) {
            case MicrocodeValueKind::Register: {
                if (argument.byte_width <= 0) {
                    return std::unexpected(Error::validation(
                        "Microcode register argument byte width must be positive",
                        std::to_string(i)));
                }
                tinfo_t argument_type;
                if (!make_integer_type(&argument_type,
                                       argument.byte_width,
                                       argument.unsigned_integer)) {
                    return std::unexpected(Error::unsupported(
                        "Microcode register argument width unsupported",
                        std::to_string(argument.byte_width)));
                }
                callarg.set_regarg(static_cast<mreg_t>(argument.register_id),
                                   argument.byte_width,
                                   argument_type);
                break;
            }

            case MicrocodeValueKind::UnsignedImmediate: {
                if (argument.byte_width <= 0) {
                    return std::unexpected(Error::validation(
                        "Microcode immediate argument byte width must be positive",
                        std::to_string(i)));
                }
                tinfo_t argument_type;
                if (!make_integer_type(&argument_type,
                                       argument.byte_width,
                                       true)) {
                    return std::unexpected(Error::unsupported(
                        "Microcode typed argument width unsupported",
                        std::to_string(argument.byte_width)));
                }
                mop_t immediate;
                immediate.make_number(argument.unsigned_immediate,
                                      argument.byte_width,
                                      instruction_address,
                                      0);
                callarg.copy_mop(immediate);
                callarg.type = argument_type;
                break;
            }

            case MicrocodeValueKind::SignedImmediate: {
                if (argument.byte_width <= 0) {
                    return std::unexpected(Error::validation(
                        "Microcode immediate argument byte width must be positive",
                        std::to_string(i)));
                }
                tinfo_t argument_type;
                if (!make_integer_type(&argument_type,
                                       argument.byte_width,
                                       false)) {
                    return std::unexpected(Error::unsupported(
                        "Microcode typed argument width unsupported",
                        std::to_string(argument.byte_width)));
                }
                mop_t immediate;
                immediate.make_number(static_cast<std::uint64_t>(argument.signed_immediate),
                                      argument.byte_width,
                                      instruction_address,
                                      0);
                callarg.copy_mop(immediate);
                callarg.type = argument_type;
                break;
            }

            case MicrocodeValueKind::Float32Immediate: {
                const int width = argument.byte_width == 0 ? 4 : argument.byte_width;
                if (width != 4) {
                    return std::unexpected(Error::validation(
                        "Float32 argument width must be 4 bytes",
                        std::to_string(i)));
                }

                const float value = static_cast<float>(argument.floating_immediate);
                const std::uint32_t bits = std::bit_cast<std::uint32_t>(value);

                mop_t immediate;
                immediate.make_number(bits,
                                      width,
                                      instruction_address,
                                      0);
                callarg.copy_mop(immediate);
                callarg.type = tinfo_t(BTF_FLOAT);
                break;
            }

            case MicrocodeValueKind::Float64Immediate: {
                const int width = argument.byte_width == 0 ? 8 : argument.byte_width;
                if (width != 8) {
                    return std::unexpected(Error::validation(
                        "Float64 argument width must be 8 bytes",
                        std::to_string(i)));
                }

                const std::uint64_t bits = std::bit_cast<std::uint64_t>(argument.floating_immediate);

                mop_t immediate;
                immediate.make_number(bits,
                                      width,
                                      instruction_address,
                                      0);
                callarg.copy_mop(immediate);
                callarg.type = tinfo_t(BTF_DOUBLE);
                break;
            }

            case MicrocodeValueKind::ByteArray: {
                if (argument.byte_width <= 0) {
                    return std::unexpected(Error::validation(
                        "ByteArray argument byte width must be positive",
                        std::to_string(i)));
                }
                if (argument.location.kind == MicrocodeValueLocationKind::Unspecified) {
                    return std::unexpected(Error::validation(
                        "ByteArray argument requires explicit location",
                        std::to_string(i)));
                }

                tinfo_t element_type(BT_INT8 | BTMT_USIGNED);
                tinfo_t array_type;
                array_type.create_array(element_type,
                                        static_cast<uint32_t>(argument.byte_width));
                callarg.type = array_type;
                break;
            }

            case MicrocodeValueKind::Vector: {
                if (argument.vector_element_count <= 0) {
                    return std::unexpected(Error::validation(
                        "Vector argument element count must be positive",
                        std::to_string(i)));
                }
                if (argument.vector_element_byte_width <= 0) {
                    return std::unexpected(Error::validation(
                        "Vector argument element byte width must be positive",
                        std::to_string(i)));
                }
                if (argument.location.kind == MicrocodeValueLocationKind::Unspecified) {
                    return std::unexpected(Error::validation(
                        "Vector argument requires explicit location",
                        std::to_string(i)));
                }

                tinfo_t element_type;
                if (argument.vector_elements_floating) {
                    if (argument.vector_element_byte_width == 4) {
                        element_type = tinfo_t(BTF_FLOAT);
                    } else if (argument.vector_element_byte_width == 8) {
                        element_type = tinfo_t(BTF_DOUBLE);
                    } else {
                        return std::unexpected(Error::validation(
                            "Floating vector elements must be 4 or 8 bytes",
                            std::to_string(i)));
                    }
                } else {
                    if (!make_integer_type(&element_type,
                                           argument.vector_element_byte_width,
                                           argument.vector_elements_unsigned)) {
                        return std::unexpected(Error::unsupported(
                            "Vector integer element width unsupported",
                            std::to_string(argument.vector_element_byte_width)));
                    }
                }

                tinfo_t vector_type;
                vector_type.create_array(element_type,
                                         static_cast<uint32_t>(argument.vector_element_count));
                callarg.type = vector_type;
                break;
            }

            case MicrocodeValueKind::TypeDeclarationView: {
                if (argument.type_declaration.empty()) {
                    return std::unexpected(Error::validation(
                        "TypeDeclarationView argument requires a non-empty declaration",
                        std::to_string(i)));
                }
                if (argument.location.kind == MicrocodeValueLocationKind::Unspecified) {
                    return std::unexpected(Error::validation(
                        "TypeDeclarationView argument requires explicit location",
                        std::to_string(i)));
                }

                qstring declaration(argument.type_declaration.c_str());
                if (!declaration.empty() && declaration.last() != ';')
                    declaration.append(';');

                qstring name;
                tinfo_t declared_type;
                if (!parse_decl(&declared_type,
                                &name,
                                nullptr,
                                declaration.c_str(),
                                PT_SIL)) {
                    return std::unexpected(Error::validation(
                        "Failed to parse TypeDeclarationView declaration",
                        argument.type_declaration));
                }

                callarg.type = declared_type;
                break;
            }
        }

        auto location_status = apply_explicit_location(&callarg,
                                                       argument.location,
                                                       i,
                                                       &result.has_explicit_locations);
        if (!location_status)
            return std::unexpected(location_status.error());

        result.arguments.push_back(std::move(callarg));
    }

    return result;
}

ssize_t idaapi hexrays_event_bridge(void*, hexrays_event_t event, va_list va) {
    if (event != hxe_maturity)
        return 0;

    cfunc_t* cfunc = va_arg(va, cfunc_t*);
    int maturity_raw = va_arg(va, int);

    MaturityEvent evt;
    if (cfunc != nullptr)
        evt.function_address = static_cast<Address>(cfunc->entry_ea);
    evt.new_maturity = to_maturity(maturity_raw);

    std::vector<std::function<void(const MaturityEvent&)>> callbacks;
    {
        std::lock_guard<std::mutex> lock(g_subscription_mutex);
        callbacks.reserve(g_maturity_callbacks.size());
        for (const auto& [_, callback] : g_maturity_callbacks)
            callbacks.push_back(callback);
    }
    for (const auto& callback : callbacks)
        callback(evt);
    return 0;
}

Status ensure_callback_installed_locked() {
    if (g_hexrays_callback_installed)
        return ida::ok();
    if (!install_hexrays_callback(&hexrays_event_bridge, nullptr))
        return std::unexpected(Error::sdk("install_hexrays_callback failed"));
    g_hexrays_callback_installed = true;
    return ida::ok();
}

} // namespace

static Status ensure_hexrays();

Result<bool> available() {
    if (s_hexrays_initialized)
        return true;
    if (init_hexrays_plugin()) {
        s_hexrays_initialized = true;
        return true;
    }
    return false;
}

Result<Token> on_maturity_changed(std::function<void(const MaturityEvent&)> callback) {
    if (!callback)
        return std::unexpected(Error::validation("Maturity callback cannot be empty"));

    auto st = ensure_hexrays();
    if (!st)
        return std::unexpected(st.error());

    std::lock_guard<std::mutex> lock(g_subscription_mutex);
    st = ensure_callback_installed_locked();
    if (!st)
        return std::unexpected(st.error());

    const Token token = g_next_token.fetch_add(1, std::memory_order_relaxed);
    g_maturity_callbacks.emplace(token, std::move(callback));
    return token;
}

Status unsubscribe(Token token) {
    if (token == 0)
        return std::unexpected(Error::validation("Invalid subscription token"));

    std::lock_guard<std::mutex> lock(g_subscription_mutex);
    auto it = g_maturity_callbacks.find(token);
    if (it == g_maturity_callbacks.end())
        return std::unexpected(Error::not_found("Decompiler subscription token not found",
                                                std::to_string(token)));
    g_maturity_callbacks.erase(it);

    if (g_maturity_callbacks.empty() && g_hexrays_callback_installed) {
        remove_hexrays_callback(&hexrays_event_bridge, nullptr);
        g_hexrays_callback_installed = false;
    }
    return ida::ok();
}

void ScopedSubscription::reset() {
    if (token_ == 0)
        return;
    (void)unsubscribe(token_);
    token_ = 0;
}

ScopedSubscription::~ScopedSubscription() {
    reset();
}

Status mark_dirty(Address function_address, bool close_views) {
    auto st = ensure_hexrays();
    if (!st)
        return std::unexpected(st.error());

    func_t* fn = get_func(function_address);
    if (fn == nullptr)
        return std::unexpected(Error::not_found("No function at address",
                                                std::to_string(function_address)));

    if (!mark_cfunc_dirty(fn->start_ea, close_views))
        return std::unexpected(Error::sdk("mark_cfunc_dirty failed",
                                          std::to_string(function_address)));
    return ida::ok();
}

Status mark_dirty_with_callers(Address function_address, bool close_views) {
    auto st = mark_dirty(function_address, close_views);
    if (!st)
        return st;

    auto caller_addresses = ida::function::callers(function_address);
    if (!caller_addresses)
        return std::unexpected(caller_addresses.error());

    for (Address caller_address : *caller_addresses) {
        st = mark_dirty(caller_address, close_views);
        if (!st)
            return st;
    }
    return ida::ok();
}

Address MicrocodeContext::address() const noexcept {
    if (raw_ == nullptr)
        return BadAddress;
    const auto* impl = static_cast<const MicrocodeContextImpl*>(raw_);
    if (impl->codegen == nullptr)
        return BadAddress;
    return static_cast<Address>(impl->codegen->insn.ea);
}

int MicrocodeContext::instruction_type() const noexcept {
    if (raw_ == nullptr)
        return 0;
    const auto* impl = static_cast<const MicrocodeContextImpl*>(raw_);
    if (impl->codegen == nullptr)
        return 0;
    return static_cast<int>(impl->codegen->insn.itype);
}

Status MicrocodeContext::emit_noop() {
    if (raw_ == nullptr)
        return std::unexpected(Error::internal("MicrocodeContext is empty"));
    auto* impl = static_cast<MicrocodeContextImpl*>(raw_);
    if (impl->codegen == nullptr)
        return std::unexpected(Error::internal("MicrocodeContext has null codegen"));
    impl->codegen->emit(m_nop, 0, 0, 0, 0, 0);
    impl->emitted_noop = true;
    return ida::ok();
}

Result<int> MicrocodeContext::load_operand_register(int operand_index) {
    if (operand_index < 0)
        return std::unexpected(Error::validation("Operand index cannot be negative",
                                                 std::to_string(operand_index)));
    if (raw_ == nullptr)
        return std::unexpected(Error::internal("MicrocodeContext is empty"));

    auto* impl = static_cast<MicrocodeContextImpl*>(raw_);
    if (impl->codegen == nullptr)
        return std::unexpected(Error::internal("MicrocodeContext has null codegen"));

    const mreg_t reg = impl->codegen->load_operand(operand_index, 0);
    if (reg == mr_none)
        return std::unexpected(Error::sdk("load_operand failed",
                                          std::to_string(operand_index)));
    return static_cast<int>(reg);
}

Result<int> MicrocodeContext::load_effective_address_register(int operand_index) {
    if (operand_index < 0)
        return std::unexpected(Error::validation("Operand index cannot be negative",
                                                 std::to_string(operand_index)));
    if (raw_ == nullptr)
        return std::unexpected(Error::internal("MicrocodeContext is empty"));

    auto* impl = static_cast<MicrocodeContextImpl*>(raw_);
    if (impl->codegen == nullptr)
        return std::unexpected(Error::internal("MicrocodeContext has null codegen"));

    const mreg_t reg = impl->codegen->load_effective_address(operand_index, 0);
    if (reg == mr_none)
        return std::unexpected(Error::sdk("load_effective_address failed",
                                          std::to_string(operand_index)));
    return static_cast<int>(reg);
}

Status MicrocodeContext::store_operand_register(int operand_index,
                                                int source_register,
                                                int byte_width) {
    if (operand_index < 0)
        return std::unexpected(Error::validation("Operand index cannot be negative",
                                                 std::to_string(operand_index)));
    if (byte_width <= 0)
        return std::unexpected(Error::validation("Byte width must be positive",
                                                 std::to_string(byte_width)));
    if (raw_ == nullptr)
        return std::unexpected(Error::internal("MicrocodeContext is empty"));

    auto* impl = static_cast<MicrocodeContextImpl*>(raw_);
    if (impl->codegen == nullptr)
        return std::unexpected(Error::internal("MicrocodeContext has null codegen"));

    mop_t source;
    source.make_reg(static_cast<mreg_t>(source_register), byte_width);
    if (!impl->codegen->store_operand(operand_index, source, 0, nullptr))
        return std::unexpected(Error::sdk("store_operand failed",
                                          std::to_string(operand_index)));
    return ida::ok();
}

Status MicrocodeContext::emit_move_register(int source_register,
                                            int destination_register,
                                            int byte_width) {
    if (byte_width <= 0)
        return std::unexpected(Error::validation("Byte width must be positive",
                                                 std::to_string(byte_width)));
    if (raw_ == nullptr)
        return std::unexpected(Error::internal("MicrocodeContext is empty"));

    auto* impl = static_cast<MicrocodeContextImpl*>(raw_);
    if (impl->codegen == nullptr)
        return std::unexpected(Error::internal("MicrocodeContext has null codegen"));

    (void)impl->codegen->emit(m_mov,
                              byte_width,
                              static_cast<uval_t>(source_register),
                              0,
                              static_cast<uval_t>(destination_register),
                              0);
    return ida::ok();
}

Status MicrocodeContext::emit_load_memory_register(int selector_register,
                                                   int offset_register,
                                                   int destination_register,
                                                   int byte_width,
                                                   int offset_byte_width) {
    if (byte_width <= 0)
        return std::unexpected(Error::validation("Byte width must be positive",
                                                 std::to_string(byte_width)));
    if (offset_byte_width <= 0)
        return std::unexpected(Error::validation("Offset byte width must be positive",
                                                 std::to_string(offset_byte_width)));
    if (raw_ == nullptr)
        return std::unexpected(Error::internal("MicrocodeContext is empty"));

    auto* impl = static_cast<MicrocodeContextImpl*>(raw_);
    if (impl->codegen == nullptr)
        return std::unexpected(Error::internal("MicrocodeContext has null codegen"));

    minsn_t* emitted = impl->codegen->emit(m_ldx,
                                           byte_width,
                                           static_cast<uval_t>(selector_register),
                                           static_cast<uval_t>(offset_register),
                                           static_cast<uval_t>(destination_register),
                                           offset_byte_width);
    if (emitted == nullptr)
        return std::unexpected(Error::sdk("emit(m_ldx) failed"));
    return ida::ok();
}

Status MicrocodeContext::emit_store_memory_register(int source_register,
                                                    int selector_register,
                                                    int offset_register,
                                                    int byte_width,
                                                    int offset_byte_width) {
    if (byte_width <= 0)
        return std::unexpected(Error::validation("Byte width must be positive",
                                                 std::to_string(byte_width)));
    if (offset_byte_width <= 0)
        return std::unexpected(Error::validation("Offset byte width must be positive",
                                                 std::to_string(offset_byte_width)));
    if (raw_ == nullptr)
        return std::unexpected(Error::internal("MicrocodeContext is empty"));

    auto* impl = static_cast<MicrocodeContextImpl*>(raw_);
    if (impl->codegen == nullptr)
        return std::unexpected(Error::internal("MicrocodeContext has null codegen"));

    minsn_t* emitted = impl->codegen->emit(m_stx,
                                           byte_width,
                                           static_cast<uval_t>(source_register),
                                           static_cast<uval_t>(selector_register),
                                           static_cast<uval_t>(offset_register),
                                           offset_byte_width);
    if (emitted == nullptr)
        return std::unexpected(Error::sdk("emit(m_stx) failed"));
    return ida::ok();
}

Status MicrocodeContext::emit_helper_call(std::string_view helper_name) {
    if (helper_name.empty())
        return std::unexpected(Error::validation("Helper name cannot be empty"));
    if (raw_ == nullptr)
        return std::unexpected(Error::internal("MicrocodeContext is empty"));

    auto* impl = static_cast<MicrocodeContextImpl*>(raw_);
    if (impl->codegen == nullptr || impl->codegen->mba == nullptr || impl->codegen->mb == nullptr)
        return std::unexpected(Error::internal("MicrocodeContext has incomplete codegen state"));

    std::string helper(helper_name);
    minsn_t* call = impl->codegen->mba->create_helper_call(impl->codegen->insn.ea,
                                                           helper.c_str(),
                                                           nullptr,
                                                           nullptr,
                                                           nullptr);
    return insert_call_instruction(impl, call, helper);
}

Status MicrocodeContext::emit_helper_call_with_arguments(
    std::string_view helper_name,
    const std::vector<MicrocodeValue>& arguments) {
    return emit_helper_call_with_arguments_and_options(helper_name,
                                                       arguments,
                                                       MicrocodeCallOptions{});
}

Status MicrocodeContext::emit_helper_call_with_arguments_and_options(
    std::string_view helper_name,
    const std::vector<MicrocodeValue>& arguments,
    const MicrocodeCallOptions& options) {
    if (helper_name.empty())
        return std::unexpected(Error::validation("Helper name cannot be empty"));
    if (raw_ == nullptr)
        return std::unexpected(Error::internal("MicrocodeContext is empty"));

    auto* impl = static_cast<MicrocodeContextImpl*>(raw_);
    if (impl->codegen == nullptr || impl->codegen->mba == nullptr || impl->codegen->mb == nullptr)
        return std::unexpected(Error::internal("MicrocodeContext has incomplete codegen state"));

    auto callargs = build_call_arguments(arguments, impl->codegen->insn.ea);
    if (!callargs)
        return std::unexpected(callargs.error());

    MicrocodeCallOptions effective_options = options;
    if (callargs->has_explicit_locations)
        effective_options.mark_explicit_locations = true;

    std::string helper(helper_name);
    minsn_t* call = impl->codegen->mba->create_helper_call(impl->codegen->insn.ea,
                                                            helper.c_str(),
                                                            nullptr,
                                                            callargs->arguments.empty()
                                                                ? nullptr
                                                                : &callargs->arguments,
                                                            nullptr);

    auto st = apply_call_options(call, effective_options, helper);
    if (!st) {
        if (call != nullptr)
            delete call;
        return st;
    }

    return insert_call_instruction(impl, call, helper);
}

Status MicrocodeContext::emit_helper_call_with_arguments_to_register(
    std::string_view helper_name,
    const std::vector<MicrocodeValue>& arguments,
    int destination_register,
    int destination_byte_width,
    bool destination_unsigned) {
    return emit_helper_call_with_arguments_to_register_and_options(helper_name,
                                                                   arguments,
                                                                   destination_register,
                                                                   destination_byte_width,
                                                                   destination_unsigned,
                                                                   MicrocodeCallOptions{});
}

Status MicrocodeContext::emit_helper_call_with_arguments_to_register_and_options(
    std::string_view helper_name,
    const std::vector<MicrocodeValue>& arguments,
    int destination_register,
    int destination_byte_width,
    bool destination_unsigned,
    const MicrocodeCallOptions& options) {
    if (helper_name.empty())
        return std::unexpected(Error::validation("Helper name cannot be empty"));
    if (destination_byte_width <= 0)
        return std::unexpected(Error::validation("Destination byte width must be positive",
                                                 std::to_string(destination_byte_width)));
    if (raw_ == nullptr)
        return std::unexpected(Error::internal("MicrocodeContext is empty"));

    auto* impl = static_cast<MicrocodeContextImpl*>(raw_);
    if (impl->codegen == nullptr || impl->codegen->mba == nullptr || impl->codegen->mb == nullptr)
        return std::unexpected(Error::internal("MicrocodeContext has incomplete codegen state"));

    auto callargs = build_call_arguments(arguments, impl->codegen->insn.ea);
    if (!callargs)
        return std::unexpected(callargs.error());

    MicrocodeCallOptions effective_options = options;
    if (callargs->has_explicit_locations)
        effective_options.mark_explicit_locations = true;

    tinfo_t return_type;
    if (!make_integer_type(&return_type, destination_byte_width, destination_unsigned)) {
        return std::unexpected(Error::unsupported("Microcode typed return width unsupported",
                                                  std::to_string(destination_byte_width)));
    }

    mop_t destination;
    destination.make_reg(static_cast<mreg_t>(destination_register), destination_byte_width);

    std::string helper(helper_name);
    minsn_t* call = impl->codegen->mba->create_helper_call(impl->codegen->insn.ea,
                                                            helper.c_str(),
                                                            &return_type,
                                                            callargs->arguments.empty()
                                                                ? nullptr
                                                                : &callargs->arguments,
                                                            &destination);

    auto st = apply_call_options(call, effective_options, helper);
    if (!st) {
        if (call != nullptr)
            delete call;
        return st;
    }

    return insert_call_instruction(impl, call, helper);
}

Result<FilterToken> register_microcode_filter(std::shared_ptr<MicrocodeFilter> filter) {
    if (!filter)
        return std::unexpected(Error::validation("Microcode filter cannot be null"));

    auto st = ensure_hexrays();
    if (!st)
        return std::unexpected(st.error());

    auto bridge = std::make_unique<MicrocodeFilterBridge>(std::move(filter));
    if (!::install_microcode_filter(bridge.get(), true))
        return std::unexpected(Error::sdk("install_microcode_filter failed"));

    const FilterToken token = g_next_filter_token.fetch_add(1, std::memory_order_relaxed);
    std::lock_guard<std::mutex> lock(g_microcode_filter_mutex);
    g_microcode_filters.emplace(token, std::move(bridge));
    return token;
}

Status unregister_microcode_filter(FilterToken token) {
    if (token == 0)
        return std::unexpected(Error::validation("Invalid microcode-filter token"));

    std::lock_guard<std::mutex> lock(g_microcode_filter_mutex);
    auto it = g_microcode_filters.find(token);
    if (it == g_microcode_filters.end())
        return std::unexpected(Error::not_found("Microcode filter token not found",
                                                std::to_string(token)));

    if (!::install_microcode_filter(it->second.get(), false))
        return std::unexpected(Error::sdk("uninstall_microcode_filter failed",
                                          std::to_string(token)));
    g_microcode_filters.erase(it);
    return ida::ok();
}

void ScopedMicrocodeFilter::reset() {
    if (token_ == 0)
        return;
    (void)unregister_microcode_filter(token_);
    token_ = 0;
}

ScopedMicrocodeFilter::~ScopedMicrocodeFilter() {
    reset();
}

// ── Helper: ensure decompiler is initialized ────────────────────────────

static Status ensure_hexrays() {
    if (s_hexrays_initialized)
        return ida::ok();
    if (init_hexrays_plugin()) {
        s_hexrays_initialized = true;
        return ida::ok();
    }
    return std::unexpected(Error::unsupported(
        "Decompiler not available (Hex-Rays plugin not loaded)"));
}

// ── ItemType conversion ─────────────────────────────────────────────────

static ItemType from_ctype(ctype_t ct) {
    return static_cast<ItemType>(static_cast<int>(ct));
}

// ── ExpressionView implementation ───────────────────────────────────────

ItemType ExpressionView::type() const noexcept {
    if (!raw_) return ItemType::ExprEmpty;
    return from_ctype(static_cast<cexpr_t*>(raw_)->op);
}

Address ExpressionView::address() const noexcept {
    if (!raw_) return BadAddress;
    return static_cast<cexpr_t*>(raw_)->ea;
}

Result<std::uint64_t> ExpressionView::number_value() const {
    if (!raw_) return std::unexpected(Error::internal("null expression"));
    auto* e = static_cast<cexpr_t*>(raw_);
    if (e->op != cot_num)
        return std::unexpected(Error::validation("Expression is not a number"));
    return e->numval();
}

Result<Address> ExpressionView::object_address() const {
    if (!raw_) return std::unexpected(Error::internal("null expression"));
    auto* e = static_cast<cexpr_t*>(raw_);
    if (e->op != cot_obj)
        return std::unexpected(Error::validation("Expression is not an object reference"));
    return e->obj_ea;
}

Result<int> ExpressionView::variable_index() const {
    if (!raw_) return std::unexpected(Error::internal("null expression"));
    auto* e = static_cast<cexpr_t*>(raw_);
    if (e->op != cot_var)
        return std::unexpected(Error::validation("Expression is not a variable"));
    return e->v.idx;
}

Result<std::string> ExpressionView::string_value() const {
    if (!raw_) return std::unexpected(Error::internal("null expression"));
    auto* e = static_cast<cexpr_t*>(raw_);
    if (e->op != cot_str || e->string == nullptr)
        return std::unexpected(Error::validation("Expression is not a string literal"));
    return std::string(e->string);
}

Result<std::size_t> ExpressionView::call_argument_count() const {
    if (!raw_) return std::unexpected(Error::internal("null expression"));
    auto* e = static_cast<cexpr_t*>(raw_);
    if (e->op != cot_call || e->a == nullptr)
        return std::unexpected(Error::validation("Expression is not a call"));
    return static_cast<std::size_t>(e->a->size());
}

Result<ExpressionView> ExpressionView::call_callee() const {
    if (!raw_) return std::unexpected(Error::internal("null expression"));
    auto* e = static_cast<cexpr_t*>(raw_);
    if (e->op != cot_call || e->x == nullptr)
        return std::unexpected(Error::validation("Expression is not a call"));
    return ExpressionView(ExpressionView::Tag{}, e->x);
}

Result<ExpressionView> ExpressionView::call_argument(std::size_t index) const {
    if (!raw_) return std::unexpected(Error::internal("null expression"));
    auto* e = static_cast<cexpr_t*>(raw_);
    if (e->op != cot_call || e->a == nullptr)
        return std::unexpected(Error::validation("Expression is not a call"));
    if (index >= e->a->size())
        return std::unexpected(Error::validation("Call argument index out of range"));
    return ExpressionView(ExpressionView::Tag{}, &(*e->a)[index]);
}

Result<std::uint32_t> ExpressionView::member_offset() const {
    if (!raw_) return std::unexpected(Error::internal("null expression"));
    auto* e = static_cast<cexpr_t*>(raw_);
    if (e->op != cot_memref && e->op != cot_memptr)
        return std::unexpected(Error::validation("Expression is not a member access"));
    return e->m;
}

Result<std::string> ExpressionView::to_string() const {
    if (!raw_) return std::unexpected(Error::internal("null expression"));
    // We need the cfunc_t for printing, which we don't have in this context.
    // Return a simple description based on the type.
    auto* e = static_cast<cexpr_t*>(raw_);
    switch (e->op) {
        case cot_num: {
            uint64 val = e->numval();
            char buf[64];
            qsnprintf(buf, sizeof(buf), "0x%" FMT_64 "x", val);
            return std::string(buf);
        }
        case cot_str:
            return e->string ? std::string("\"") + e->string + "\"" : std::string("\"\"");
        case cot_obj: {
            qstring nm;
            if (get_name(&nm, e->obj_ea) > 0)
                return ida::detail::to_string(nm);
            char buf[64];
            qsnprintf(buf, sizeof(buf), "obj_0x%" FMT_64 "x", (uint64)e->obj_ea);
            return std::string(buf);
        }
        default:
            break;
    }
    // Fallback: just return the op name.
    const char* name = get_ctype_name(e->op);
    if (name) return std::string(name);
    return std::string("(unknown)");
}

// ── StatementView implementation ────────────────────────────────────────

ItemType StatementView::type() const noexcept {
    if (!raw_) return ItemType::StmtEmpty;
    return from_ctype(static_cast<cinsn_t*>(raw_)->op);
}

Address StatementView::address() const noexcept {
    if (!raw_) return BadAddress;
    return static_cast<cinsn_t*>(raw_)->ea;
}

Result<int> StatementView::goto_target_label() const {
    if (!raw_) return std::unexpected(Error::internal("null statement"));
    auto* s = static_cast<cinsn_t*>(raw_);
    if (s->op != cit_goto || s->cgoto == nullptr)
        return std::unexpected(Error::validation("Statement is not a goto"));
    return s->cgoto->label_num;
}

// ── CtreeVisitor default implementations ────────────────────────────────

VisitAction CtreeVisitor::visit_expression(ExpressionView) {
    return VisitAction::Continue;
}
VisitAction CtreeVisitor::visit_statement(StatementView) {
    return VisitAction::Continue;
}
VisitAction CtreeVisitor::leave_expression(ExpressionView) {
    return VisitAction::Continue;
}
VisitAction CtreeVisitor::leave_statement(StatementView) {
    return VisitAction::Continue;
}

// ── SDK visitor adapter ─────────────────────────────────────────────────

namespace {

class MicrocodePrinter : public vd_printer_t {
public:
    AS_PRINTF(3, 4) int print(int indent, const char* format, ...) override {
        qstring line;
        if (indent > 0)
            line.fill(0, ' ', indent);

        va_list va;
        va_start(va, format);
        line.cat_vsprnt(format, va);
        va_end(va);

        tag_remove(&line);
        line.trim2();
        if (line.empty())
            return 0;

        lines_.emplace_back(line.c_str());
        return static_cast<int>(line.length());
    }

    [[nodiscard]] const std::vector<std::string>& lines() const {
        return lines_;
    }

private:
    std::vector<std::string> lines_;
};

/// Adapter that bridges the SDK's ctree_visitor_t to our CtreeVisitor.
class SdkVisitorAdapter : public ctree_visitor_t {
public:
    SdkVisitorAdapter(CtreeVisitor& visitor, int flags)
        : ctree_visitor_t(flags), visitor_(visitor), items_visited_(0) {}

    int idaapi visit_insn(cinsn_t* insn) override {
        ++items_visited_;
        StatementView sv(StatementView::Tag{}, insn);
        auto action = visitor_.visit_statement(sv);
        if (action == VisitAction::Stop)
            return 1;  // Non-zero stops traversal.
        if (action == VisitAction::SkipChildren)
            prune_now();
        return 0;
    }

    int idaapi visit_expr(cexpr_t* expr) override {
        ++items_visited_;
        ExpressionView ev(ExpressionView::Tag{}, expr);
        auto action = visitor_.visit_expression(ev);
        if (action == VisitAction::Stop)
            return 1;
        if (action == VisitAction::SkipChildren)
            prune_now();
        return 0;
    }

    int idaapi leave_insn(cinsn_t* insn) override {
        StatementView sv(StatementView::Tag{}, insn);
        auto action = visitor_.leave_statement(sv);
        return action == VisitAction::Stop ? 1 : 0;
    }

    int idaapi leave_expr(cexpr_t* expr) override {
        ExpressionView ev(ExpressionView::Tag{}, expr);
        auto action = visitor_.leave_expression(ev);
        return action == VisitAction::Stop ? 1 : 0;
    }

    int items_visited() const { return items_visited_; }

private:
    CtreeVisitor& visitor_;
    int items_visited_;
};

} // anonymous namespace

// ── DecompiledFunction impl ─────────────────────────────────────────────

struct DecompiledFunction::Impl {
    cfuncptr_t cfunc;   // Reference-counted smart pointer — keeps cfunc_t alive.
    ea_t func_ea{BADADDR};

    explicit Impl(cfuncptr_t cf, ea_t ea) : cfunc(std::move(cf)), func_ea(ea) {}
};

DecompiledFunction::~DecompiledFunction() {
    delete impl_;
}

DecompiledFunction::DecompiledFunction(DecompiledFunction&& other) noexcept
    : impl_(other.impl_) {
    other.impl_ = nullptr;
}

DecompiledFunction& DecompiledFunction::operator=(DecompiledFunction&& other) noexcept {
    if (this != &other) {
        delete impl_;
        impl_ = other.impl_;
        other.impl_ = nullptr;
    }
    return *this;
}

#define CHECK_IMPL() \
    if (impl_ == nullptr || impl_->cfunc == nullptr) \
        return std::unexpected(Error::internal("DecompiledFunction is empty"))

Result<std::string> DecompiledFunction::pseudocode() const {
    CHECK_IMPL();

    const strvec_t& sv = impl_->cfunc->get_pseudocode();
    std::string result;
    for (std::size_t i = 0; i < sv.size(); ++i) {
        qstring buf;
        tag_remove(&buf, sv[i].line);
        if (i > 0) result += '\n';
        result += ida::detail::to_string(buf);
    }
    return result;
}

Result<std::string> DecompiledFunction::microcode() const {
    auto mc_lines = microcode_lines();
    if (!mc_lines)
        return std::unexpected(mc_lines.error());

    std::string result;
    for (std::size_t i = 0; i < mc_lines->size(); ++i) {
        if (i > 0)
            result.push_back('\n');
        result += (*mc_lines)[i];
    }
    return result;
}

Result<std::vector<std::string>> DecompiledFunction::lines() const {
    CHECK_IMPL();

    const strvec_t& sv = impl_->cfunc->get_pseudocode();
    std::vector<std::string> result;
    result.reserve(sv.size());
    for (std::size_t i = 0; i < sv.size(); ++i) {
        qstring buf;
        tag_remove(&buf, sv[i].line);
        result.push_back(ida::detail::to_string(buf));
    }
    return result;
}

Result<std::vector<std::string>> DecompiledFunction::microcode_lines() const {
    CHECK_IMPL();

    mba_t* mba = impl_->cfunc->mba;
    if (mba == nullptr) {
        return std::unexpected(Error::unsupported(
            "Microcode is not available for this decompiled function",
            std::to_string(impl_->func_ea)));
    }

    MicrocodePrinter printer;
    mba->print(printer);
    return printer.lines();
}

Result<std::string> DecompiledFunction::declaration() const {
    CHECK_IMPL();

    qstring decl;
    impl_->cfunc->print_dcl(&decl);
    return ida::detail::to_string(decl);
}

Result<std::size_t> DecompiledFunction::variable_count() const {
    CHECK_IMPL();

    lvars_t* vars = impl_->cfunc->get_lvars();
    if (vars == nullptr)
        return std::size_t{0};
    return static_cast<std::size_t>(vars->size());
}

Result<std::vector<LocalVariable>> DecompiledFunction::variables() const {
    CHECK_IMPL();

    lvars_t* vars = impl_->cfunc->get_lvars();
    if (vars == nullptr)
        return std::vector<LocalVariable>{};

    std::vector<LocalVariable> result;
    result.reserve(vars->size());
    for (std::size_t i = 0; i < vars->size(); ++i) {
        const lvar_t& v = (*vars)[i];
        LocalVariable lv;
        lv.name        = ida::detail::to_string(v.name);
        lv.is_argument = v.is_arg_var();
        lv.width       = v.width;

        // Get the type as a C string.
        qstring type_str;
        if (v.type().print(&type_str))
            lv.type_name = ida::detail::to_string(type_str);
        else
            lv.type_name = "(unknown)";

        result.push_back(std::move(lv));
    }
    return result;
}

Status DecompiledFunction::rename_variable(std::string_view old_name,
                                           std::string_view new_name) {
    CHECK_IMPL();

    std::string old_str(old_name);
    std::string new_str(new_name);
    if (!rename_lvar(impl_->func_ea, old_str.c_str(), new_str.c_str()))
        return std::unexpected(Error::sdk("rename_lvar failed",
                                          std::string(old_name)));
    return ida::ok();
}

Status DecompiledFunction::retype_variable(std::string_view variable_name,
                                           const ida::type::TypeInfo& new_type) {
    CHECK_IMPL();

    if (variable_name.empty())
        return std::unexpected(Error::validation("Variable name cannot be empty"));

    const auto* type_impl = ida::type::TypeInfoAccess::get(new_type);
    if (type_impl == nullptr)
        return std::unexpected(Error::internal("TypeInfo has null implementation"));

    std::string name_str(variable_name);
    lvar_saved_info_t info;
    if (!locate_lvar(&info.ll, impl_->func_ea, name_str.c_str()))
        return std::unexpected(Error::not_found("Local variable not found", name_str));

    info.type = type_impl->ti;
    const size_t size = info.type.get_size();
    if (size != BADSIZE)
        info.size = static_cast<ssize_t>(size);

    if (!modify_user_lvar_info(impl_->func_ea, MLI_TYPE, info))
        return std::unexpected(Error::sdk("modify_user_lvar_info(type) failed", name_str));
    return ida::ok();
}

Status DecompiledFunction::retype_variable(std::size_t variable_index,
                                           const ida::type::TypeInfo& new_type) {
    CHECK_IMPL();

    const auto* type_impl = ida::type::TypeInfoAccess::get(new_type);
    if (type_impl == nullptr)
        return std::unexpected(Error::internal("TypeInfo has null implementation"));

    lvars_t* variables = impl_->cfunc->get_lvars();
    if (variables == nullptr || variable_index >= variables->size())
        return std::unexpected(Error::not_found("Variable index out of range",
                                                std::to_string(variable_index)));

    lvar_saved_info_t info;
    info.ll = (*variables)[variable_index];
    info.type = type_impl->ti;
    const size_t size = info.type.get_size();
    if (size != BADSIZE)
        info.size = static_cast<ssize_t>(size);

    std::string context = std::to_string(variable_index);
    if (!(*variables)[variable_index].name.empty())
        context = ida::detail::to_string((*variables)[variable_index].name);

    if (!modify_user_lvar_info(impl_->func_ea, MLI_TYPE, info))
        return std::unexpected(Error::sdk("modify_user_lvar_info(type) failed", context));
    return ida::ok();
}

// ── Ctree traversal ─────────────────────────────────────────────────────

Result<int> DecompiledFunction::visit(CtreeVisitor& visitor,
                                      const VisitOptions& options) const {
    CHECK_IMPL();

    int flags = CV_FAST;
    if (options.post_order) flags |= CV_POST;
    if (options.track_parents) flags |= CV_PARENTS;

    SdkVisitorAdapter adapter(visitor, flags);

    if (options.expressions_only)
        adapter.apply_to_exprs(&impl_->cfunc->body, nullptr);
    else
        adapter.apply_to(&impl_->cfunc->body, nullptr);

    return adapter.items_visited();
}

Result<int> DecompiledFunction::visit_expressions(CtreeVisitor& visitor,
                                                   bool post_order) const {
    VisitOptions opts;
    opts.expressions_only = true;
    opts.post_order = post_order;
    return visit(visitor, opts);
}

// ── User comments ───────────────────────────────────────────────────────

Status DecompiledFunction::set_comment(Address ea, std::string_view text,
                                       CommentPosition pos) {
    CHECK_IMPL();

    treeloc_t loc;
    loc.ea = ea;
    loc.itp = static_cast<item_preciser_t>(static_cast<int>(pos));

    if (text.empty()) {
        impl_->cfunc->set_user_cmt(loc, nullptr);
    } else {
        std::string str(text);
        impl_->cfunc->set_user_cmt(loc, str.c_str());
    }
    return ida::ok();
}

Result<std::string> DecompiledFunction::get_comment(Address ea,
                                                     CommentPosition pos) const {
    CHECK_IMPL();

    treeloc_t loc;
    loc.ea = ea;
    loc.itp = static_cast<item_preciser_t>(static_cast<int>(pos));

    const char* cmt = impl_->cfunc->get_user_cmt(loc, RETRIEVE_ALWAYS);
    if (cmt == nullptr)
        return std::string{};
    return std::string(cmt);
}

Status DecompiledFunction::save_comments() const {
    CHECK_IMPL();
    impl_->cfunc->save_user_cmts();
    return ida::ok();
}

Result<bool> DecompiledFunction::has_orphan_comments() const {
    CHECK_IMPL();
    return impl_->cfunc->has_orphan_cmts();
}

Result<int> DecompiledFunction::remove_orphan_comments() {
    CHECK_IMPL();
    const int removed = impl_->cfunc->del_orphan_cmts();
    if (removed < 0)
        return std::unexpected(Error::sdk("del_orphan_cmts failed"));
    return removed;
}

Status DecompiledFunction::refresh() const {
    CHECK_IMPL();
    impl_->cfunc->refresh_func_ctext();
    return ida::ok();
}

// ── Address mapping ─────────────────────────────────────────────────────

Address DecompiledFunction::entry_address() const {
    if (impl_ == nullptr) return BadAddress;
    return impl_->func_ea;
}

Result<Address> DecompiledFunction::line_to_address(int line_number) const {
    CHECK_IMPL();

    // The pseudocode uses treeitems to map indices to items.
    // A simpler approach: walk the eamap to find which ea maps to lines
    // near the requested line, then correlate with pseudocode.
    const strvec_t& sv = impl_->cfunc->get_pseudocode();
    if (line_number < 0 || static_cast<std::size_t>(line_number) >= sv.size())
        return std::unexpected(Error::validation("Line number out of range"));

    // After get_pseudocode(), treeitems should be populated.
    // Each pseudocode line has an associated ea via the ctree items.
    // We use the boundaries map for a reliable mapping.
    // Note: get_boundaries()/get_eamap() are available for advanced mapping
    // but treeitems (populated by get_pseudocode) is more direct for line mapping.

    // Use treeitems for the given line.
    int hdr = impl_->cfunc->hdrlines;
    int item_line = line_number - hdr;

    if (item_line >= 0
        && static_cast<std::size_t>(item_line) < impl_->cfunc->treeitems.size()) {
        const citem_t* item = impl_->cfunc->treeitems[item_line];
        if (item != nullptr && item->ea != BADADDR)
            return item->ea;
    }

    // Fallback: scan treeitems around the target line.
    for (int delta = 1; delta <= 5; ++delta) {
        for (int dir : {-1, 1}) {
            int probe = item_line + dir * delta;
            if (probe >= 0
                && static_cast<std::size_t>(probe) < impl_->cfunc->treeitems.size()) {
                const citem_t* item = impl_->cfunc->treeitems[probe];
                if (item != nullptr && item->ea != BADADDR)
                    return item->ea;
            }
        }
    }

    return std::unexpected(Error::not_found("No address mapping for line",
                                             std::to_string(line_number)));
}

Result<std::vector<AddressMapping>> DecompiledFunction::address_map() const {
    CHECK_IMPL();

    // Ensure pseudocode is generated (populates treeitems).
    impl_->cfunc->get_pseudocode();

    int hdr = impl_->cfunc->hdrlines;
    std::vector<AddressMapping> result;

    for (std::size_t i = 0; i < impl_->cfunc->treeitems.size(); ++i) {
        const citem_t* item = impl_->cfunc->treeitems[i];
        if (item != nullptr && item->ea != BADADDR) {
            AddressMapping am;
            am.address = item->ea;
            am.line_number = static_cast<int>(i) + hdr;
            result.push_back(am);
        }
    }

    return result;
}

#undef CHECK_IMPL

// ── Decompile ───────────────────────────────────────────────────────────

Result<DecompiledFunction> decompile(Address ea, DecompileFailure* failure) {
    if (failure != nullptr)
        *failure = DecompileFailure{};

    auto st = ensure_hexrays();
    if (!st) return std::unexpected(st.error());

    func_t* pfn = get_func(ea);
    if (pfn == nullptr) {
        if (failure != nullptr) {
            failure->request_address = ea;
            failure->failure_address = ea;
            failure->description = "No function at address";
        }
        return std::unexpected(Error::not_found("No function at address",
                                                std::to_string(ea)));
    }

    hexrays_failure_t hf;
    cfuncptr_t cfunc = decompile_func(pfn, &hf, 0);
    if (cfunc == nullptr) {
        std::string desc = ida::detail::to_string(hf.desc());
        if (failure != nullptr) {
            failure->request_address = ea;
            failure->failure_address = hf.errea;
            failure->description = desc;
        }
        return std::unexpected(Error::sdk("Decompilation failed: " + desc,
                                          "request=" + std::to_string(ea)
                                              + ", failure=" + std::to_string(hf.errea)));
    }

    auto* impl = new DecompiledFunction::Impl(std::move(cfunc), pfn->start_ea);
    return DecompiledFunction(impl);
}

Result<DecompiledFunction> decompile(Address ea) {
    return decompile(ea, nullptr);
}

// ── Functional-style visitor helpers ────────────────────────────────────

namespace {

class LambdaExprVisitor : public CtreeVisitor {
public:
    explicit LambdaExprVisitor(std::function<VisitAction(ExpressionView)> cb)
        : callback_(std::move(cb)) {}

    VisitAction visit_expression(ExpressionView expr) override {
        return callback_(expr);
    }

private:
    std::function<VisitAction(ExpressionView)> callback_;
};

class LambdaItemVisitor : public CtreeVisitor {
public:
    LambdaItemVisitor(std::function<VisitAction(ExpressionView)> on_expr,
                      std::function<VisitAction(StatementView)> on_stmt)
        : on_expr_(std::move(on_expr)), on_stmt_(std::move(on_stmt)) {}

    VisitAction visit_expression(ExpressionView expr) override {
        return on_expr_(expr);
    }

    VisitAction visit_statement(StatementView stmt) override {
        return on_stmt_(stmt);
    }

private:
    std::function<VisitAction(ExpressionView)> on_expr_;
    std::function<VisitAction(StatementView)> on_stmt_;
};

} // anonymous namespace

Result<int> for_each_expression(
    const DecompiledFunction& func,
    std::function<VisitAction(ExpressionView)> callback) {
    LambdaExprVisitor visitor(std::move(callback));
    return func.visit_expressions(visitor);
}

Result<int> for_each_item(
    const DecompiledFunction& func,
    std::function<VisitAction(ExpressionView)> on_expr,
    std::function<VisitAction(StatementView)> on_stmt) {
    LambdaItemVisitor visitor(std::move(on_expr), std::move(on_stmt));
    return func.visit(visitor);
}

} // namespace ida::decompiler

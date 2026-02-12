/// \file decompiler.cpp
/// \brief Implementation of ida::decompiler — wrapping Hex-Rays decompiler API.
///
/// The Hex-Rays API uses runtime function-pointer dispatch (hexdsp_t), so
/// there are no link-time dependencies. We include hexrays.hpp and call
/// init_hexrays_plugin() at runtime to check availability.

#include "detail/sdk_bridge.hpp"
#include <ida/decompiler.hpp>

// hexrays.hpp is part of the IDA SDK and provides all decompiler APIs
// through a single runtime dispatch pointer (no link dependencies).
#include <hexrays.hpp>

namespace ida::decompiler {

// ── Availability ────────────────────────────────────────────────────────

static bool s_hexrays_initialized = false;

Result<bool> available() {
    if (s_hexrays_initialized)
        return true;
    if (init_hexrays_plugin()) {
        s_hexrays_initialized = true;
        return true;
    }
    return false;
}

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

Result<std::string> DecompiledFunction::pseudocode() const {
    if (impl_ == nullptr || impl_->cfunc == nullptr)
        return std::unexpected(Error::internal("DecompiledFunction is empty"));

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

Result<std::vector<std::string>> DecompiledFunction::lines() const {
    if (impl_ == nullptr || impl_->cfunc == nullptr)
        return std::unexpected(Error::internal("DecompiledFunction is empty"));

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

Result<std::string> DecompiledFunction::declaration() const {
    if (impl_ == nullptr || impl_->cfunc == nullptr)
        return std::unexpected(Error::internal("DecompiledFunction is empty"));

    qstring decl;
    impl_->cfunc->print_dcl(&decl);
    return ida::detail::to_string(decl);
}

Result<std::size_t> DecompiledFunction::variable_count() const {
    if (impl_ == nullptr || impl_->cfunc == nullptr)
        return std::unexpected(Error::internal("DecompiledFunction is empty"));

    lvars_t* vars = impl_->cfunc->get_lvars();
    if (vars == nullptr)
        return std::size_t{0};
    return static_cast<std::size_t>(vars->size());
}

Result<std::vector<LocalVariable>> DecompiledFunction::variables() const {
    if (impl_ == nullptr || impl_->cfunc == nullptr)
        return std::unexpected(Error::internal("DecompiledFunction is empty"));

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
    if (impl_ == nullptr || impl_->cfunc == nullptr)
        return std::unexpected(Error::internal("DecompiledFunction is empty"));

    std::string old_str(old_name);
    std::string new_str(new_name);
    if (!rename_lvar(impl_->func_ea, old_str.c_str(), new_str.c_str()))
        return std::unexpected(Error::sdk("rename_lvar failed",
                                          std::string(old_name)));
    return ida::ok();
}

// ── Decompile ───────────────────────────────────────────────────────────

Result<DecompiledFunction> decompile(Address ea) {
    // Ensure the decompiler is initialized.
    if (!s_hexrays_initialized) {
        if (!init_hexrays_plugin())
            return std::unexpected(Error::unsupported(
                "Decompiler not available (Hex-Rays plugin not loaded)"));
        s_hexrays_initialized = true;
    }

    func_t* pfn = get_func(ea);
    if (pfn == nullptr)
        return std::unexpected(Error::not_found("No function at address",
                                                std::to_string(ea)));

    hexrays_failure_t hf;
    cfuncptr_t cfunc = decompile_func(pfn, &hf, 0);
    if (cfunc == nullptr) {
        std::string desc = ida::detail::to_string(hf.desc());
        return std::unexpected(Error::sdk("Decompilation failed: " + desc,
                                          std::to_string(ea)));
    }

    auto* impl = new DecompiledFunction::Impl(std::move(cfunc), pfn->start_ea);
    return DecompiledFunction(impl);
}

} // namespace ida::decompiler

/// \file function.cpp
/// \brief Implementation of ida::function — CRUD, lookup, traversal, chunks, frames.

#include "detail/sdk_bridge.hpp"
#include "detail/type_impl.hpp"
#include <ida/function.hpp>

namespace ida::function {

// ── Internal access helpers ─────────────────────────────────────────────

struct FunctionAccess {
    static Function populate(func_t* fn) {
        Function f;
        f.start_ = static_cast<Address>(fn->start_ea);
        f.end_   = static_cast<Address>(fn->end_ea);

        // Name.
        qstring qname;
        if (get_func_name(&qname, fn->start_ea) > 0)
            f.name_ = ida::detail::to_string(qname);

        // Bitness: SDK returns 0/1/2 for 16/32/64.
        f.bitness_ = ida::detail::bitness_to_bits(get_func_bitness(fn));

        // Flags.
        f.returns_  = (fn->flags & FUNC_NORET) == 0;
        f.library_  = (fn->flags & FUNC_LIB)   != 0;
        f.thunk_    = (fn->flags & FUNC_THUNK)  != 0;
        f.hidden_   = (fn->flags & FUNC_HIDDEN) != 0;

        // Frame sizes.
        f.frsize_  = static_cast<AddressSize>(fn->frsize);
        f.frregs_  = static_cast<AddressSize>(fn->frregs);
        f.argsize_ = static_cast<AddressSize>(fn->argsize);

        return f;
    }
};

struct StackFrameAccess {
    static StackFrame populate(func_t* fn) {
        StackFrame sf;
        sf.local_size_ = static_cast<AddressSize>(fn->frsize);
        sf.regs_size_  = static_cast<AddressSize>(fn->frregs);
        sf.args_size_  = static_cast<AddressSize>(fn->argsize);
        sf.total_size_ = static_cast<AddressSize>(get_frame_size(fn));

        // Extract frame variables via tinfo_t + get_udt_details.
        tinfo_t frame_type;
        if (get_func_frame(&frame_type, fn)) {
            udt_type_data_t udt;
            if (frame_type.get_udt_details(&udt)) {
                for (std::size_t i = 0; i < udt.size(); ++i) {
                    const udm_t& m = udt[i];
                    FrameVariable fv;
                    fv.name        = ida::detail::to_string(m.name);
                    fv.byte_offset = static_cast<std::size_t>(m.offset / 8);
                    fv.byte_size   = static_cast<std::size_t>(m.size / 8);
                    fv.comment     = ida::detail::to_string(m.cmt);
                    fv.is_special  = m.is_special_member();
                    sf.vars_.push_back(std::move(fv));
                }
            }
        }
        return sf;
    }
};

// ── Function::refresh ───────────────────────────────────────────────────

Status Function::refresh() {
    func_t* fn = get_func(start_);
    if (fn == nullptr)
        return std::unexpected(Error::not_found("Function no longer exists",
                                                std::to_string(start_)));
    *this = FunctionAccess::populate(fn);
    return ida::ok();
}

// ── CRUD ────────────────────────────────────────────────────────────────

Result<Function> create(Address start, Address end_addr) {
    ea_t end_ea = (end_addr == BadAddress) ? BADADDR : static_cast<ea_t>(end_addr);
    if (!add_func(start, end_ea))
        return std::unexpected(Error::sdk("add_func failed", std::to_string(start)));

    func_t* fn = get_func(start);
    if (fn == nullptr)
        return std::unexpected(Error::internal("Function created but not retrievable"));
    return FunctionAccess::populate(fn);
}

Status remove(Address ea) {
    if (!del_func(ea))
        return std::unexpected(Error::sdk("del_func failed", std::to_string(ea)));
    return ida::ok();
}

// ── Lookup ──────────────────────────────────────────────────────────────

Result<Function> at(Address ea) {
    func_t* fn = get_func(ea);
    if (fn == nullptr)
        return std::unexpected(Error::not_found("No function at address",
                                                std::to_string(ea)));
    return FunctionAccess::populate(fn);
}

Result<Function> by_index(std::size_t idx) {
    std::size_t total = get_func_qty();
    if (idx >= total)
        return std::unexpected(Error::validation("Function index out of range",
                                                 std::to_string(idx)));
    func_t* fn = getn_func(idx);
    if (fn == nullptr)
        return std::unexpected(Error::internal("getn_func returned null for valid index"));
    return FunctionAccess::populate(fn);
}

Result<std::size_t> count() {
    return static_cast<std::size_t>(get_func_qty());
}

Result<std::string> name_at(Address ea) {
    qstring qname;
    if (get_func_name(&qname, ea) <= 0)
        return std::unexpected(Error::not_found("No function name at address",
                                                std::to_string(ea)));
    return ida::detail::to_string(qname);
}

// ── Boundary mutation ───────────────────────────────────────────────────

Status set_start(Address ea, Address new_start) {
    int rc = ::set_func_start(ea, new_start);
    if (rc != MOVE_FUNC_OK)
        return std::unexpected(Error::sdk("set_func_start failed",
                                          "code: " + std::to_string(rc)));
    return ida::ok();
}

Status set_end(Address ea, Address new_end) {
    if (!::set_func_end(ea, new_end))
        return std::unexpected(Error::sdk("set_func_end failed", std::to_string(ea)));
    return ida::ok();
}

// ── Comment access ──────────────────────────────────────────────────────

Result<std::string> comment(Address ea, bool repeatable) {
    func_t* fn = get_func(ea);
    if (fn == nullptr)
        return std::unexpected(Error::not_found("No function at address"));
    qstring qcmt;
    if (get_func_cmt(&qcmt, fn, repeatable) <= 0)
        return std::unexpected(Error::not_found("No comment on function"));
    return ida::detail::to_string(qcmt);
}

Status set_comment(Address ea, std::string_view text, bool repeatable) {
    func_t* fn = get_func(ea);
    if (fn == nullptr)
        return std::unexpected(Error::not_found("No function at address"));
    qstring qcmt = ida::detail::to_qstring(text);
    set_func_cmt(fn, qcmt.c_str(), repeatable);
    return ida::ok();
}

// ── Relationship helpers ────────────────────────────────────────────────

Result<std::vector<Address>> callers(Address ea) {
    func_t* fn = get_func(ea);
    if (fn == nullptr)
        return std::unexpected(Error::not_found("No function at address",
                                                std::to_string(ea)));
    std::vector<Address> result;
    xrefblk_t xb;
    for (bool ok = xb.first_to(fn->start_ea, XREF_ALL); ok; ok = xb.next_to()) {
        if (!xb.iscode)
            continue;
        // Only call-type xrefs (fl_CN, fl_CF), not flow or jumps.
        if (xb.type != fl_CN && xb.type != fl_CF)
            continue;
        // Resolve the caller's function start address.
        func_t* caller = get_func(xb.from);
        if (caller != nullptr) {
            Address caller_ea = static_cast<Address>(caller->start_ea);
            // Avoid duplicates.
            if (result.empty() || result.back() != caller_ea)
                result.push_back(caller_ea);
        }
    }
    return result;
}

Result<std::vector<Address>> callees(Address ea) {
    func_t* fn = get_func(ea);
    if (fn == nullptr)
        return std::unexpected(Error::not_found("No function at address",
                                                std::to_string(ea)));
    std::vector<Address> result;
    // Scan all instructions in the function for call xrefs.
    func_item_iterator_t fii;
    if (fii.set(fn)) {
        do {
            ea_t item_ea = fii.current();
            xrefblk_t xb;
            for (bool ok = xb.first_from(item_ea, XREF_ALL); ok; ok = xb.next_from()) {
                if (!xb.iscode)
                    continue;
                if (xb.type != fl_CN && xb.type != fl_CF)
                    continue;
                // Resolve target function.
                func_t* target = get_func(xb.to);
                if (target != nullptr) {
                    Address target_ea = static_cast<Address>(target->start_ea);
                    // Avoid consecutive duplicates (sorted by call site).
                    bool found = false;
                    for (auto a : result)
                        if (a == target_ea) { found = true; break; }
                    if (!found)
                        result.push_back(target_ea);
                }
            }
        } while (fii.next_code());
    }
    return result;
}

// ── Chunk operations ────────────────────────────────────────────────────

Result<std::vector<Chunk>> chunks(Address ea) {
    func_t* fn = get_func(ea);
    if (fn == nullptr)
        return std::unexpected(Error::not_found("No function at address",
                                                std::to_string(ea)));

    std::vector<Chunk> result;
    func_tail_iterator_t fti(fn);
    // Iterate all chunks: entry first (via main()), then tails via next().
    for (bool ok = fti.main(); ok; ok = fti.next()) {
        const range_t& r = fti.chunk();
        Chunk c;
        c.start   = static_cast<Address>(r.start_ea);
        c.end     = static_cast<Address>(r.end_ea);
        c.is_tail = !result.empty();  // First chunk is entry, rest are tails.
        c.owner   = static_cast<Address>(fn->start_ea);
        result.push_back(c);
    }
    return result;
}

Result<std::vector<Chunk>> tail_chunks(Address ea) {
    func_t* fn = get_func(ea);
    if (fn == nullptr)
        return std::unexpected(Error::not_found("No function at address",
                                                std::to_string(ea)));

    std::vector<Chunk> result;
    func_tail_iterator_t fti(fn);
    // Iterate only tail chunks (excludes entry).
    for (bool ok = fti.first(); ok; ok = fti.next()) {
        const range_t& r = fti.chunk();
        Chunk c;
        c.start   = static_cast<Address>(r.start_ea);
        c.end     = static_cast<Address>(r.end_ea);
        c.is_tail = true;
        c.owner   = static_cast<Address>(fn->start_ea);
        result.push_back(c);
    }
    return result;
}

Result<std::size_t> chunk_count(Address ea) {
    func_t* fn = get_func(ea);
    if (fn == nullptr)
        return std::unexpected(Error::not_found("No function at address",
                                                std::to_string(ea)));
    // 1 for entry chunk + tailqty tail chunks.
    return static_cast<std::size_t>(1 + fn->tailqty);
}

Status add_tail(Address func_ea, Address tail_start, Address tail_end) {
    func_t* fn = get_func(func_ea);
    if (fn == nullptr)
        return std::unexpected(Error::not_found("No function at address",
                                                std::to_string(func_ea)));
    if (!append_func_tail(fn, tail_start, tail_end))
        return std::unexpected(Error::sdk("append_func_tail failed",
                                          std::to_string(tail_start)));
    return ida::ok();
}

Status remove_tail(Address func_ea, Address tail_ea) {
    func_t* fn = get_func(func_ea);
    if (fn == nullptr)
        return std::unexpected(Error::not_found("No function at address",
                                                std::to_string(func_ea)));
    if (!remove_func_tail(fn, tail_ea))
        return std::unexpected(Error::sdk("remove_func_tail failed",
                                          std::to_string(tail_ea)));
    return ida::ok();
}

// ── Frame operations ────────────────────────────────────────────────────

Result<StackFrame> frame(Address ea) {
    func_t* fn = get_func(ea);
    if (fn == nullptr)
        return std::unexpected(Error::not_found("No function at address",
                                                std::to_string(ea)));
    // Check if a frame exists (frame netnode id != 0 means frame present).
    tinfo_t frame_type;
    if (!get_func_frame(&frame_type, fn))
        return std::unexpected(Error::not_found("Function has no stack frame",
                                                std::to_string(ea)));
    return StackFrameAccess::populate(fn);
}

Result<AddressDelta> sp_delta_at(Address ea) {
    // get_spd accepts nullptr for pfn — it finds the function automatically.
    sval_t spd = get_spd(nullptr, ea);
    return static_cast<AddressDelta>(spd);
}

Status define_stack_variable(Address func_ea, std::string_view name,
                             std::int32_t frame_offset,
                             const ida::type::TypeInfo& type) {
    func_t* fn = get_func(func_ea);
    if (fn == nullptr)
        return std::unexpected(Error::not_found("No function at address",
                                                std::to_string(func_ea)));

    auto* impl = ida::type::TypeInfoAccess::get(type);
    if (impl == nullptr)
        return std::unexpected(Error::internal("TypeInfo has null implementation"));

    qstring qname = ida::detail::to_qstring(name);
    if (!define_stkvar(fn, qname.c_str(), static_cast<sval_t>(frame_offset), impl->ti))
        return std::unexpected(Error::sdk("define_stkvar failed",
                                          std::to_string(frame_offset)));
    return ida::ok();
}

// ── Register variable operations ────────────────────────────────────────

Status add_register_variable(Address func_ea,
                             Address range_start, Address range_end,
                             std::string_view register_name,
                             std::string_view user_name,
                             std::string_view cmt) {
    func_t* fn = get_func(func_ea);
    if (fn == nullptr)
        return std::unexpected(Error::not_found("No function at address",
                                                std::to_string(func_ea)));
    std::string canon(register_name);
    std::string user(user_name);
    std::string comment(cmt);

    int rc = ::add_regvar(fn,
                          static_cast<ea_t>(range_start),
                          static_cast<ea_t>(range_end),
                          canon.c_str(),
                          user.c_str(),
                          comment.empty() ? nullptr : comment.c_str());
    if (rc != REGVAR_ERROR_OK) {
        std::string msg;
        switch (rc) {
            case REGVAR_ERROR_ARG:   msg = "Bad arguments"; break;
            case REGVAR_ERROR_RANGE: msg = "Bad range"; break;
            case REGVAR_ERROR_NAME:  msg = "Bad name(s)"; break;
            default:                 msg = "Unknown error"; break;
        }
        return std::unexpected(Error::sdk("add_regvar failed: " + msg, canon));
    }
    return ida::ok();
}

Result<RegisterVariable> find_register_variable(Address func_ea,
                                                 Address ea,
                                                 std::string_view register_name) {
    func_t* fn = get_func(func_ea);
    if (fn == nullptr)
        return std::unexpected(Error::not_found("No function at address",
                                                std::to_string(func_ea)));
    std::string canon(register_name);
    regvar_t* rv = ::find_regvar(fn, static_cast<ea_t>(ea), canon.c_str());
    if (rv == nullptr)
        return std::unexpected(Error::not_found("Register variable not found", canon));

    RegisterVariable result;
    result.range_start     = static_cast<Address>(rv->start_ea);
    result.range_end       = static_cast<Address>(rv->end_ea);
    result.canonical_name  = rv->canon ? std::string(rv->canon) : std::string();
    result.user_name       = rv->user ? std::string(rv->user) : std::string();
    result.comment         = rv->cmt ? std::string(rv->cmt) : std::string();
    return result;
}

Status delete_register_variable(Address func_ea,
                                Address range_start, Address range_end,
                                std::string_view register_name) {
    func_t* fn = get_func(func_ea);
    if (fn == nullptr)
        return std::unexpected(Error::not_found("No function at address",
                                                std::to_string(func_ea)));
    std::string canon(register_name);
    int rc = ::del_regvar(fn,
                          static_cast<ea_t>(range_start),
                          static_cast<ea_t>(range_end),
                          canon.c_str());
    if (rc != REGVAR_ERROR_OK)
        return std::unexpected(Error::sdk("del_regvar failed", canon));
    return ida::ok();
}

Status rename_register_variable(Address func_ea,
                                Address ea,
                                std::string_view register_name,
                                std::string_view new_user_name) {
    func_t* fn = get_func(func_ea);
    if (fn == nullptr)
        return std::unexpected(Error::not_found("No function at address",
                                                std::to_string(func_ea)));
    std::string canon(register_name);
    regvar_t* rv = ::find_regvar(fn, static_cast<ea_t>(ea), canon.c_str());
    if (rv == nullptr)
        return std::unexpected(Error::not_found("Register variable not found", canon));

    std::string new_name(new_user_name);
    int rc = ::rename_regvar(fn, rv, new_name.c_str());
    if (rc != REGVAR_ERROR_OK)
        return std::unexpected(Error::sdk("rename_regvar failed", new_name));
    return ida::ok();
}

Result<bool> has_register_variables(Address func_ea, Address ea) {
    func_t* fn = get_func(func_ea);
    if (fn == nullptr)
        return std::unexpected(Error::not_found("No function at address",
                                                std::to_string(func_ea)));
    return ::has_regvar(fn, static_cast<ea_t>(ea));
}

// ── Traversal ───────────────────────────────────────────────────────────

FunctionIterator::FunctionIterator(std::size_t index, std::size_t total)
    : idx_(index), total_(total) {}

Function FunctionIterator::operator*() const {
    func_t* fn = getn_func(idx_);
    if (fn == nullptr)
        return Function{};
    return FunctionAccess::populate(fn);
}

FunctionIterator& FunctionIterator::operator++() {
    if (idx_ < total_)
        ++idx_;
    return *this;
}

FunctionIterator FunctionIterator::operator++(int) {
    FunctionIterator tmp = *this;
    ++(*this);
    return tmp;
}

FunctionRange::FunctionRange()
    : total_(static_cast<std::size_t>(get_func_qty())) {}

FunctionIterator FunctionRange::begin() const {
    return FunctionIterator(0, total_);
}

FunctionIterator FunctionRange::end() const {
    return FunctionIterator(total_, total_);
}

FunctionRange all() {
    return FunctionRange();
}

} // namespace ida::function

/// \file name.cpp
/// \brief Implementation of ida::name — naming, demangling, properties.

#include "detail/sdk_bridge.hpp"
#include <ida/name.hpp>

namespace ida::name {

namespace {

bool in_range(Address address, const ListOptions& options) {
    if (options.start != BadAddress && address < options.start)
        return false;
    if (options.end != BadAddress && address >= options.end)
        return false;
    return true;
}

bool include_name(bool user_defined, const ListOptions& options) {
    if (user_defined)
        return options.include_user_defined;
    return options.include_auto_generated;
}

} // anonymous namespace

// ── Core naming ─────────────────────────────────────────────────────────

Status set(Address ea, std::string_view name) {
    qstring qn = ida::detail::to_qstring(name);
    if (!set_name(ea, qn.c_str(), SN_NOCHECK))
        return std::unexpected(Error::sdk("set_name failed", std::to_string(ea)));
    return ida::ok();
}

Status force_set(Address ea, std::string_view name) {
    qstring qn = ida::detail::to_qstring(name);
    if (!set_name(ea, qn.c_str(), SN_FORCE))
        return std::unexpected(Error::sdk("force set_name failed", std::to_string(ea)));
    return ida::ok();
}

Status remove(Address ea) {
    if (!set_name(ea, "", 0))
        return std::unexpected(Error::sdk("remove name failed", std::to_string(ea)));
    return ida::ok();
}

Result<std::string> get(Address ea) {
    qstring qn = get_name(ea);
    if (qn.empty())
        return std::unexpected(Error::not_found("No name at address", std::to_string(ea)));
    return ida::detail::to_string(qn);
}

Result<std::string> demangled(Address ea, DemangleForm form) {
    // Map our form enum to GN_ flags.
    int gtn_flags = GN_DEMANGLED;
    switch (form) {
        case DemangleForm::Short:
            gtn_flags |= GN_SHORT;
            break;
        case DemangleForm::Long:
            // Default demangled output.
            break;
        case DemangleForm::Full:
            gtn_flags |= GN_LONG;
            break;
    }

    qstring qn;
    if (get_ea_name(&qn, ea, gtn_flags) <= 0)
        return std::unexpected(Error::not_found("No demangled name at address",
                                                std::to_string(ea)));
    return ida::detail::to_string(qn);
}

Result<Address> resolve(std::string_view name, Address context) {
    qstring qn = ida::detail::to_qstring(name);
    ea_t from = (context == BadAddress) ? BADADDR : static_cast<ea_t>(context);
    ea_t result = get_name_ea(from, qn.c_str());
    if (!ida::detail::is_valid(result))
        return std::unexpected(Error::not_found("Name not resolved",
                                                std::string(name)));
    return static_cast<Address>(result);
}

// ── Name inventory ───────────────────────────────────────────────────────

Result<std::vector<Entry>> all(const ListOptions& options) {
    if (!options.include_user_defined && !options.include_auto_generated) {
        return std::unexpected(Error::validation(
            "At least one name category must be included"));
    }
    if (options.start != BadAddress
        && options.end != BadAddress
        && options.start > options.end) {
        return std::unexpected(Error::validation(
            "Invalid name range: start is greater than end",
            std::to_string(options.start) + ":" + std::to_string(options.end)));
    }

    const std::size_t total = get_nlist_size();
    std::vector<Entry> out;
    out.reserve(total);

    for (std::size_t index = 0; index < total; ++index) {
        const ea_t ea = get_nlist_ea(index);
        if (!ida::detail::is_valid(ea))
            continue;

        const Address address = static_cast<Address>(ea);
        if (!in_range(address, options))
            continue;

        const char* raw_name = get_nlist_name(index);
        if (raw_name == nullptr || *raw_name == '\0')
            continue;

        const flags64_t flags = get_flags(ea);
        const bool user_defined = flags != 0 && has_user_name(flags);
        if (!include_name(user_defined, options))
            continue;

        Entry entry;
        entry.address = address;
        entry.name = raw_name;
        entry.user_defined = user_defined;
        entry.auto_generated = !user_defined;
        out.push_back(std::move(entry));
    }

    return out;
}

Result<std::vector<Entry>> all_user_defined(Address start, Address end) {
    ListOptions options;
    options.start = start;
    options.end = end;
    options.include_user_defined = true;
    options.include_auto_generated = false;
    return all(options);
}

// ── Name properties ─────────────────────────────────────────────────────

bool is_public(Address ea) {
    return is_public_name(ea);
}

bool is_weak(Address ea) {
    return is_weak_name(ea);
}

bool is_user_defined(Address ea) {
    flags64_t f = get_flags(ea);
    if (f == 0)
        return false;
    return has_any_name(f) && has_user_name(f);
}

bool is_auto_generated(Address ea) {
    // A name is auto-generated if it exists but is not user-defined.
    // SDK has has_user_name() which checks if the name was set by the user.
    flags64_t f = get_flags(ea);
    if (f == 0) return false;
    return has_any_name(f) && !has_user_name(f);
}

Result<bool> is_valid_identifier(std::string_view text) {
    if (text.empty())
        return false;
    std::string value(text);
    return ::is_uname(value.c_str());
}

Result<std::string> sanitize_identifier(std::string_view text) {
    if (text.empty())
        return std::unexpected(Error::validation("Identifier cannot be empty"));

    qstring value = ida::detail::to_qstring(text);
    if (!validate_name(&value, VNT_IDENT, SN_NOCHECK)) {
        return std::unexpected(Error::validation("Identifier cannot be sanitized",
                                                 std::string(text)));
    }
    return ida::detail::to_string(value);
}

Status set_public(Address ea, bool value) {
    if (value)
        make_name_public(ea);
    else
        make_name_non_public(ea);
    return ida::ok();
}

Status set_weak(Address ea, bool value) {
    if (value)
        make_name_weak(ea);
    else
        make_name_non_weak(ea);
    return ida::ok();
}

} // namespace ida::name

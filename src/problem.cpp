/// \file problem.cpp
/// \brief Implementation of typed analysis-problem lists.

#include "detail/sdk_bridge.hpp"

#include <ida/problem.hpp>

#include <problems.hpp>

namespace ida::problem {

namespace {

Result<problist_id_t> checked_kind(Kind kind) {
    const auto value = static_cast<std::uint8_t>(kind);
    if (value < PR_NOBASE || value >= PR_END) {
        return std::unexpected(Error::validation(
            "Problem kind is outside the supported range",
            std::to_string(value)));
    }
    return static_cast<problist_id_t>(value);
}

Status validate_address(Address address) {
    if (address == BadAddress)
        return std::unexpected(Error::validation(
            "Problem address cannot be BadAddress"));
    return ok();
}

} // namespace

Result<std::optional<std::string>> description(Kind kind, Address address) {
    auto native_kind = checked_kind(kind);
    if (!native_kind)
        return std::unexpected(native_kind.error());
    if (auto status = validate_address(address); !status)
        return std::unexpected(status.error());

    qstring value;
    if (::get_problem_desc(&value, *native_kind, static_cast<ea_t>(address)) < 0)
        return std::optional<std::string>{};
    return std::optional<std::string>{detail::to_string(value)};
}

Status remember(Kind kind, Address address,
                std::optional<std::string_view> message) {
    auto native_kind = checked_kind(kind);
    if (!native_kind)
        return std::unexpected(native_kind.error());
    if (auto status = validate_address(address); !status)
        return status;
    if (message && message->find('\0') != std::string_view::npos) {
        return std::unexpected(Error::validation(
            "Problem message contains an embedded NUL byte"));
    }

    if (!message) {
        ::remember_problem(*native_kind, static_cast<ea_t>(address), nullptr);
    } else {
        const std::string owned_message(*message);
        ::remember_problem(*native_kind, static_cast<ea_t>(address),
                           owned_message.c_str());
    }
    return ok();
}

Result<std::optional<Address>> next(Kind kind, Address at_or_after) {
    auto native_kind = checked_kind(kind);
    if (!native_kind)
        return std::unexpected(native_kind.error());
    if (auto status = validate_address(at_or_after); !status)
        return std::unexpected(status.error());

    const ea_t address = ::get_problem(
        *native_kind, static_cast<ea_t>(at_or_after));
    if (address == BADADDR)
        return std::optional<Address>{};
    return std::optional<Address>{static_cast<Address>(address)};
}

Result<bool> remove(Kind kind, Address address) {
    auto native_kind = checked_kind(kind);
    if (!native_kind)
        return std::unexpected(native_kind.error());
    if (auto status = validate_address(address); !status)
        return std::unexpected(status.error());
    return ::forget_problem(*native_kind, static_cast<ea_t>(address));
}

Result<std::string> name(Kind kind, bool long_form) {
    auto native_kind = checked_kind(kind);
    if (!native_kind)
        return std::unexpected(native_kind.error());

    const char* value = ::get_problem_name(*native_kind, long_form);
    if (value == nullptr)
        return std::unexpected(Error::sdk("Problem kind name is unavailable"));
    return std::string(value);
}

Result<bool> contains(Kind kind, Address address) {
    auto native_kind = checked_kind(kind);
    if (!native_kind)
        return std::unexpected(native_kind.error());
    if (auto status = validate_address(address); !status)
        return std::unexpected(status.error());
    return ::is_problem_present(*native_kind, static_cast<ea_t>(address));
}

} // namespace ida::problem

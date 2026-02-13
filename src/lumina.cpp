/// \file lumina.cpp
/// \brief Implementation of ida::lumina wrappers.

#include "detail/sdk_bridge.hpp"
#include <ida/lumina.hpp>

#include <lumina.hpp>

#include <array>
#include <memory>
#include <string>

namespace ida::lumina {

namespace {

lumina_feature_t to_sdk_feature(Feature feature) {
    switch (feature) {
    case Feature::PrimaryMetadata:
        return LFEAT_PRIMARY_MD;
    case Feature::Decompiler:
        return LFEAT_DEC;
    case Feature::Telemetry:
        return LFEAT_TLM;
    case Feature::SecondaryMetadata:
        return LFEAT_SECONDARY_MD;
    }
    return LFEAT_PRIMARY_MD;
}

uint32 to_sdk_push_flags(PushMode mode) {
    switch (mode) {
    case PushMode::PreferBetterOrDifferent:
        return PMF_PUSH_OVERRIDE_IF_BETTER_OR_DIFFERENT;
    case PushMode::Override:
        return PMF_PUSH_OVERRIDE;
    case PushMode::KeepExisting:
        return PMF_PUSH_DO_NOT_OVERRIDE;
    case PushMode::Merge:
        return PMF_PUSH_MERGE;
    }
    return PMF_PUSH_OVERRIDE_IF_BETTER_OR_DIFFERENT;
}

OperationCode to_public_code(lumina_op_res_t code) {
    switch (code) {
    case PDRES_BADPTN:
        return OperationCode::BadPattern;
    case PDRES_NOT_FOUND:
        return OperationCode::NotFound;
    case PDRES_ERROR:
        return OperationCode::Error;
    case PDRES_OK:
        return OperationCode::Ok;
    case PDRES_ADDED:
        return OperationCode::Added;
    }
    return OperationCode::Error;
}

bool is_success(OperationCode code) {
    return code == OperationCode::Ok || code == OperationCode::Added;
}

Result<lumina_client_t*> connect_client(Feature feature) {
    const int flags = static_cast<int>(to_sdk_feature(feature));
    lumina_client_t* client = get_server_connection2(flags);
    if (client == nullptr) {
        return std::unexpected(
            Error::not_found("Lumina connection is unavailable"));
    }
    return client;
}

Status validate_addresses(std::span<const Address> addresses) {
    if (addresses.empty()) {
        return std::unexpected(Error::validation("Address list cannot be empty"));
    }
    for (std::size_t index = 0; index < addresses.size(); ++index) {
        if (addresses[index] == BadAddress) {
            return std::unexpected(Error::validation(
                "Invalid function address", std::to_string(index)));
        }
    }
    return ida::ok();
}

BatchResult summarize_codes(std::span<const lumina_op_res_t> sdk_codes,
                            std::size_t requested_count) {
    BatchResult out;
    out.requested = requested_count;
    out.completed = sdk_codes.size();
    out.codes.reserve(sdk_codes.size());

    for (lumina_op_res_t code : sdk_codes) {
        OperationCode mapped = to_public_code(code);
        out.codes.push_back(mapped);
        if (is_success(mapped))
            ++out.succeeded;
        else
            ++out.failed;
    }
    return out;
}

std::string errbuf_or_default(const qstring& errbuf, std::string_view fallback) {
    if (!errbuf.empty())
        return ida::detail::to_string(errbuf);
    return std::string(fallback);
}

} // namespace

Result<bool> has_connection(Feature feature) {
    const int flags = GCSF_NO_CONNECT | static_cast<int>(to_sdk_feature(feature));
    return get_server_connection2(flags) != nullptr;
}

Status close_connection(Feature feature) {
    (void)feature;
    return std::unexpected(Error::unsupported(
        "Closing Lumina connections is unavailable in this runtime"));
}

Status close_all_connections() {
    return std::unexpected(Error::unsupported(
        "Closing Lumina connections is unavailable in this runtime"));
}

Result<BatchResult> pull(std::span<const Address> addresses,
                         bool auto_apply,
                         bool skip_frequency_update,
                         Feature feature) {
    auto validated = validate_addresses(addresses);
    if (!validated)
        return std::unexpected(validated.error());

    auto client_result = connect_client(feature);
    if (!client_result)
        return std::unexpected(client_result.error());
    lumina_client_t* client = *client_result;

    eavec_t eas;
    eas.reserve(addresses.size());
    for (Address address : addresses)
        eas.push_back(static_cast<ea_t>(address));

    uint32 flags = 0;
    if (auto_apply)
        flags |= PULL_MD_AUTO_APPLY;
    if (skip_frequency_update)
        flags |= PULL_MD_SEEN_FILE;

    qstring errbuf;
    std::unique_ptr<pkt_pull_md_result_t> result(client->pull_md(&eas, &errbuf, flags));
    if (!result) {
        return std::unexpected(Error::sdk(
            "Lumina pull_md failed",
            errbuf_or_default(errbuf, "pull_md returned null")));
    }

    return summarize_codes(result->codes, addresses.size());
}

Result<BatchResult> pull(Address address,
                         bool auto_apply,
                         bool skip_frequency_update,
                         Feature feature) {
    std::array<Address, 1> only{address};
    return pull(only, auto_apply, skip_frequency_update, feature);
}

Result<BatchResult> push(std::span<const Address> addresses,
                         PushMode mode,
                         Feature feature) {
    auto validated = validate_addresses(addresses);
    if (!validated)
        return std::unexpected(validated.error());

    auto client_result = connect_client(feature);
    if (!client_result)
        return std::unexpected(client_result.error());
    lumina_client_t* client = *client_result;

    push_md_opts_t options;
    options.eas.reserve(addresses.size());
    for (Address address : addresses)
        options.eas.push_back(static_cast<ea_t>(address));

    push_md_result_t result;
    qstring errbuf;
    const bool ok = client->push_md(
        &result,
        options,
        &errbuf,
        nullptr,
        to_sdk_push_flags(mode));
    if (!ok) {
        return std::unexpected(Error::sdk(
            "Lumina push_md failed",
            errbuf_or_default(errbuf, "push_md returned false")));
    }

    return summarize_codes(result.codes, addresses.size());
}

Result<BatchResult> push(Address address,
                         PushMode mode,
                         Feature feature) {
    std::array<Address, 1> only{address};
    return push(only, mode, feature);
}

} // namespace ida::lumina

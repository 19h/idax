/// \file lumina.hpp
/// \brief Lumina metadata pull/push wrappers.

#ifndef IDAX_LUMINA_HPP
#define IDAX_LUMINA_HPP

#include <ida/address.hpp>
#include <ida/error.hpp>

#include <cstddef>
#include <span>
#include <vector>

namespace ida::lumina {

/// Lumina feature channel.
enum class Feature {
    PrimaryMetadata,
    Decompiler,
    Telemetry,
    SecondaryMetadata,
};

/// Push conflict-resolution mode.
enum class PushMode {
    PreferBetterOrDifferent,
    Override,
    KeepExisting,
    Merge,
};

/// Per-function operation status reported by Lumina.
enum class OperationCode {
    BadPattern = -3,
    NotFound = -2,
    Error = -1,
    Ok = 0,
    Added = 1,
};

/// Pull/push batch result summary.
struct BatchResult {
    std::size_t requested{0};
    std::size_t completed{0};
    std::size_t succeeded{0};
    std::size_t failed{0};
    std::vector<OperationCode> codes;
};

/// Whether a Lumina connection is already open for the selected feature.
Result<bool> has_connection(Feature feature = Feature::PrimaryMetadata);

/// Close a Lumina connection for one feature channel.
///
/// Note: this runtime currently reports this operation as unsupported.
Status close_connection(Feature feature = Feature::PrimaryMetadata);

/// Close all Lumina connections.
///
/// Note: this runtime currently reports this operation as unsupported.
Status close_all_connections();

/// Pull metadata for the provided function addresses.
///
/// If \p auto_apply is true, metadata is immediately applied by IDA.
Result<BatchResult> pull(std::span<const Address> addresses,
                         bool auto_apply = true,
                         bool skip_frequency_update = false,
                         Feature feature = Feature::PrimaryMetadata);

/// Pull metadata for a single function address.
Result<BatchResult> pull(Address address,
                         bool auto_apply = true,
                         bool skip_frequency_update = false,
                         Feature feature = Feature::PrimaryMetadata);

/// Push metadata for the provided function addresses.
Result<BatchResult> push(std::span<const Address> addresses,
                         PushMode mode = PushMode::PreferBetterOrDifferent,
                         Feature feature = Feature::PrimaryMetadata);

/// Push metadata for a single function address.
Result<BatchResult> push(Address address,
                         PushMode mode = PushMode::PreferBetterOrDifferent,
                         Feature feature = Feature::PrimaryMetadata);

} // namespace ida::lumina

#endif // IDAX_LUMINA_HPP

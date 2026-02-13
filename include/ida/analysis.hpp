/// \file analysis.hpp
/// \brief Auto-analysis control: scheduling, waiting, enable/disable.

#ifndef IDAX_ANALYSIS_HPP
#define IDAX_ANALYSIS_HPP

#include <ida/error.hpp>
#include <ida/address.hpp>

namespace ida::analysis {

/// Is the auto-analyser enabled?
bool is_enabled();

/// Enable or disable the auto-analyser.
Status set_enabled(bool enabled);

/// Is the auto-analyser idle (no pending work)?
bool is_idle();

/// Block until the auto-analyser finishes all pending work.
Status wait();

/// Block until the auto-analyser finishes work in [start, end).
Status wait_range(Address start, Address end);

/// Schedule reanalysis of the byte at \p address.
Status schedule(Address address);

/// Schedule reanalysis of the range [start, end).
Status schedule_range(Address start, Address end);

/// Schedule conversion to code at \p address.
Status schedule_code(Address address);

/// Schedule function creation/recovery at \p address.
Status schedule_function(Address address);

/// Schedule reanalysis at \p address.
Status schedule_reanalysis(Address address);

/// Schedule reanalysis for [start, end).
Status schedule_reanalysis_range(Address start, Address end);

/// Remove pending code/function/reanalysis queue entries in [start, end).
Status cancel(Address start, Address end);

/// Revert analyzer-generated decisions in [start, end).
Status revert_decisions(Address start, Address end);

} // namespace ida::analysis

#endif // IDAX_ANALYSIS_HPP

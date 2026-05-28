/// \file path.hpp
/// \brief Portable path helpers used by plugins that should not depend on
///        IDA's q* path utility functions.

#ifndef IDAX_PATH_HPP
#define IDAX_PATH_HPP

#include <string>
#include <string_view>

namespace ida::path {

/// Return the final path component.
std::string basename(std::string_view path);

/// Return the parent directory component.
std::string dirname(std::string_view path);

/// Return true if the path currently names an existing directory.
bool is_directory(std::string_view path);

} // namespace ida::path

#endif // IDAX_PATH_HPP

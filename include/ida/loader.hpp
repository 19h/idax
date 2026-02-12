/// \file loader.hpp
/// \brief Loader module development helpers.

#ifndef IDAX_LOADER_HPP
#define IDAX_LOADER_HPP

#include <ida/error.hpp>
#include <ida/address.hpp>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace ida::loader {

/// Result returned by accept() when the loader recognises the file.
struct AcceptResult {
    std::string format_name;
    std::string processor_name;
    int         priority{0};
};

} // namespace ida::loader

#endif // IDAX_LOADER_HPP

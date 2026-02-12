/// \file processor.hpp
/// \brief Processor module development helpers.

#ifndef IDAX_PROCESSOR_HPP
#define IDAX_PROCESSOR_HPP

#include <ida/error.hpp>
#include <ida/address.hpp>
#include <cstdint>
#include <string>
#include <vector>

namespace ida::processor {

struct RegisterInfo {
    std::string name;
    bool read_only{false};
};

struct InstructionDescriptor {
    std::string   mnemonic;
    std::uint32_t feature_flags{0};
};

} // namespace ida::processor

#endif // IDAX_PROCESSOR_HPP

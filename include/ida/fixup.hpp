/// \file fixup.hpp
/// \brief Fixup / relocation information.

#ifndef IDAX_FIXUP_HPP
#define IDAX_FIXUP_HPP

#include <ida/error.hpp>
#include <ida/address.hpp>
#include <cstdint>

namespace ida::fixup {

enum class Type {
    Off8, Off16, Seg16, Ptr16,
    Off32, Ptr32,
    Hi8, Hi16, Low8, Low16,
    Off64,
    Custom,
};

struct Descriptor {
    Type          type{Type::Off32};
    std::uint32_t flags{};
    std::uint16_t selector{};
    Address       offset{};
    AddressDelta  displacement{};
};

Result<Descriptor> at(Address source);
Status set(Address source, const Descriptor& fixup);
Status remove(Address source);

} // namespace ida::fixup

#endif // IDAX_FIXUP_HPP

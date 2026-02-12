/// \file fixup.cpp
/// \brief Implementation of ida::fixup — fixup / relocation information.

#include "detail/sdk_bridge.hpp"
#include <ida/fixup.hpp>

namespace ida::fixup {

// ── Internal helpers ────────────────────────────────────────────────────

namespace {

/// Map SDK fixup type to our Type enum.
Type map_fixup_type(fixup_type_t ft) {
    switch (ft) {
        case FIXUP_OFF8:    return Type::Off8;
        case FIXUP_OFF16:   return Type::Off16;
        case FIXUP_SEG16:   return Type::Seg16;
        case FIXUP_OFF32:   return Type::Off32;
        case FIXUP_OFF64:   return Type::Off64;
        case FIXUP_HI8:     return Type::Hi8;
        case FIXUP_HI16:    return Type::Hi16;
        case FIXUP_LOW8:    return Type::Low8;
        case FIXUP_LOW16:   return Type::Low16;
        case FIXUP_CUSTOM:  return Type::Custom;
        default:            return Type::Off32;
    }
}

/// Map our Type enum back to SDK fixup_type_t.
fixup_type_t unmap_fixup_type(Type t) {
    switch (t) {
        case Type::Off8:    return FIXUP_OFF8;
        case Type::Off16:   return FIXUP_OFF16;
        case Type::Seg16:   return FIXUP_SEG16;
        case Type::Ptr16:   return FIXUP_SEG16; // closest match
        case Type::Off32:   return FIXUP_OFF32;
        case Type::Ptr32:   return FIXUP_OFF32; // closest match
        case Type::Hi8:     return FIXUP_HI8;
        case Type::Hi16:    return FIXUP_HI16;
        case Type::Low8:    return FIXUP_LOW8;
        case Type::Low16:   return FIXUP_LOW16;
        case Type::Off64:   return FIXUP_OFF64;
        case Type::Custom:  return FIXUP_CUSTOM;
    }
    return FIXUP_OFF32;
}

} // anonymous namespace

// ── Public API ──────────────────────────────────────────────────────────

Result<Descriptor> at(Address source) {
    fixup_data_t fd;
    if (!::get_fixup(&fd, source))
        return std::unexpected(Error::not_found("No fixup at address",
                                                std::to_string(source)));

    Descriptor desc;
    desc.type         = map_fixup_type(fd.get_type());
    desc.flags        = static_cast<std::uint32_t>(fd.get_type()); // raw flags
    desc.selector     = static_cast<std::uint16_t>(fd.sel);
    desc.offset       = static_cast<Address>(fd.off);
    desc.displacement = static_cast<AddressDelta>(fd.displacement);
    return desc;
}

Status set(Address source, const Descriptor& fixup) {
    fixup_data_t fd;
    fd.set_type(unmap_fixup_type(fixup.type));
    fd.sel          = fixup.selector;
    fd.off          = static_cast<ea_t>(fixup.offset);
    fd.displacement = static_cast<adiff_t>(fixup.displacement);
    ::set_fixup(source, fd);
    return ida::ok();
}

Status remove(Address source) {
    ::del_fixup(source);
    return ida::ok();
}

} // namespace ida::fixup

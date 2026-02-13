/// \file fixup.cpp
/// \brief Implementation of ida::fixup — fixup / relocation information.

#include "detail/sdk_bridge.hpp"
#include <ida/fixup.hpp>

#include <map>
#include <memory>
#include <string>
#include <vector>

namespace ida::fixup {

// ── Internal helpers ────────────────────────────────────────────────────

namespace {

struct RegisteredCustomHandler {
    std::string name;
    fixup_handler_t sdk{};
};

std::map<fixup_type_t, std::unique_ptr<RegisteredCustomHandler>> g_custom_handlers;

/// Map SDK fixup type to our Type enum.
Type map_fixup_type(fixup_type_t ft) {
    switch (ft) {
        case FIXUP_OFF8:    return Type::Off8;
        case FIXUP_OFF16:   return Type::Off16;
        case FIXUP_SEG16:   return Type::Seg16;
        case FIXUP_PTR16:   return Type::Ptr16;
        case FIXUP_OFF32:   return Type::Off32;
        case FIXUP_PTR32:   return Type::Ptr32;
        case FIXUP_OFF64:   return Type::Off64;
        case FIXUP_HI8:     return Type::Hi8;
        case FIXUP_HI16:    return Type::Hi16;
        case FIXUP_LOW8:    return Type::Low8;
        case FIXUP_LOW16:   return Type::Low16;
        case FIXUP_OFF8S:   return Type::Off8Signed;
        case FIXUP_OFF16S:  return Type::Off16Signed;
        case FIXUP_OFF32S:  return Type::Off32Signed;
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
        case Type::Ptr16:   return FIXUP_PTR16;
        case Type::Off32:   return FIXUP_OFF32;
        case Type::Ptr32:   return FIXUP_PTR32;
        case Type::Hi8:     return FIXUP_HI8;
        case Type::Hi16:    return FIXUP_HI16;
        case Type::Low8:    return FIXUP_LOW8;
        case Type::Low16:   return FIXUP_LOW16;
        case Type::Off64:   return FIXUP_OFF64;
        case Type::Off8Signed:  return FIXUP_OFF8S;
        case Type::Off16Signed: return FIXUP_OFF16S;
        case Type::Off32Signed: return FIXUP_OFF32S;
        case Type::Custom:  return FIXUP_CUSTOM;
    }
    return FIXUP_OFF32;
}

Descriptor make_descriptor(ea_t source, const fixup_data_t& fd) {
    Descriptor desc;
    desc.source       = static_cast<Address>(source);
    desc.type         = map_fixup_type(fd.get_type());
    desc.flags        = fd.get_flags();
    desc.base         = static_cast<Address>(fd.get_base());
    desc.target       = static_cast<Address>(fd.get_base() + fd.off);
    desc.selector     = static_cast<std::uint16_t>(fd.sel);
    desc.offset       = static_cast<Address>(fd.off);
    desc.displacement = static_cast<AddressDelta>(fd.displacement);
    return desc;
}

} // anonymous namespace

// ── Public API ──────────────────────────────────────────────────────────

Result<Descriptor> at(Address source) {
    fixup_data_t fd;
    if (!::get_fixup(&fd, source))
        return std::unexpected(Error::not_found("No fixup at address",
                                                std::to_string(source)));
    return make_descriptor(source, fd);
}

Status set(Address source, const Descriptor& fixup) {
    fixup_data_t fd;
    fd.set_type_and_flags(unmap_fixup_type(fixup.type), fixup.flags);
    fd.sel          = fixup.selector;
    fd.off          = static_cast<ea_t>(fixup.offset);
    fd.displacement = static_cast<adiff_t>(fixup.displacement);
    if ((fixup.flags & FIXUPF_REL) != 0 && fixup.base != 0)
        fd.set_base(static_cast<ea_t>(fixup.base));
    ::set_fixup(source, fd);
    return ida::ok();
}

Status remove(Address source) {
    ::del_fixup(source);
    return ida::ok();
}

bool exists(Address source) {
    return ::exists_fixup(source);
}

bool contains(Address start, AddressSize size) {
    return ::contains_fixups(start, size);
}

Result<std::vector<Descriptor>> in_range(Address start, Address end) {
    if (start == BadAddress || end == BadAddress || start >= end)
        return std::unexpected(Error::validation("Invalid fixup range",
                                                 std::to_string(start) + ":" + std::to_string(end)));

    fixups_t infos;
    if (!::get_fixups(&infos, start, end - start))
        return std::vector<Descriptor>{};

    std::vector<Descriptor> out;
    out.reserve(infos.size());
    for (const auto& info : infos)
        out.push_back(make_descriptor(info.ea, info.fd));
    return out;
}

// ── Traversal ───────────────────────────────────────────────────────────

Result<Address> first() {
    ea_t ea = ::get_first_fixup_ea();
    if (ea == BADADDR)
        return std::unexpected(Error::not_found("No fixups in database"));
    return static_cast<Address>(ea);
}

Result<Address> next(Address ea) {
    ea_t nea = ::get_next_fixup_ea(static_cast<ea_t>(ea));
    if (nea == BADADDR)
        return std::unexpected(Error::not_found("No more fixups"));
    return static_cast<Address>(nea);
}

Result<Address> prev(Address ea) {
    ea_t pea = ::get_prev_fixup_ea(static_cast<ea_t>(ea));
    if (pea == BADADDR)
        return std::unexpected(Error::not_found("No earlier fixups"));
    return static_cast<Address>(pea);
}

Descriptor FixupIterator::operator*() const {
    fixup_data_t fd;
    if (::get_fixup(&fd, ea_))
        return make_descriptor(ea_, fd);
    // Shouldn't happen during valid iteration, but return a default descriptor.
    Descriptor desc;
    desc.source = ea_;
    return desc;
}

FixupIterator& FixupIterator::operator++() {
    ea_t nea = ::get_next_fixup_ea(static_cast<ea_t>(ea_));
    ea_ = (nea == BADADDR) ? BadAddress : static_cast<Address>(nea);
    return *this;
}

FixupIterator FixupIterator::operator++(int) {
    FixupIterator tmp = *this;
    ++(*this);
    return tmp;
}

FixupRange all() {
    ea_t first_ea = ::get_first_fixup_ea();
    Address start = (first_ea == BADADDR) ? BadAddress
                                          : static_cast<Address>(first_ea);
    return FixupRange(start, BadAddress);
}

Result<std::uint16_t> register_custom(const CustomHandler& handler) {
    if (handler.name.empty())
        return std::unexpected(Error::validation("Custom fixup handler name cannot be empty"));

    auto owned = std::make_unique<RegisteredCustomHandler>();
    owned->name = handler.name;

    owned->sdk.cbsize = sizeof(fixup_handler_t);
    owned->sdk.name = owned->name.c_str();
    owned->sdk.props = static_cast<uint32>(handler.properties);
    owned->sdk.size = handler.size;
    owned->sdk.width = handler.width;
    owned->sdk.shift = handler.shift;
    owned->sdk.rsrv4 = 0;
    owned->sdk.reftype = static_cast<uint32>(handler.reference_type);
    owned->sdk.apply = nullptr;
    owned->sdk.get_value = nullptr;
    owned->sdk.patch_value = nullptr;

    fixup_type_t id = ::register_custom_fixup(&owned->sdk);
    if (id == 0) {
        return std::unexpected(Error::conflict("register_custom_fixup failed",
                                               handler.name));
    }

    g_custom_handlers[id] = std::move(owned);
    return static_cast<std::uint16_t>(id);
}

Status unregister_custom(std::uint16_t custom_type) {
    fixup_type_t type = static_cast<fixup_type_t>(custom_type);
    if (!::unregister_custom_fixup(type)) {
        return std::unexpected(Error::not_found("Custom fixup type not registered",
                                                std::to_string(custom_type)));
    }
    g_custom_handlers.erase(type);
    return ida::ok();
}

Result<std::uint16_t> find_custom(std::string_view name) {
    if (name.empty())
        return std::unexpected(Error::validation("Custom fixup name cannot be empty"));
    std::string n(name);
    fixup_type_t id = ::find_custom_fixup(n.c_str());
    if (id == 0)
        return std::unexpected(Error::not_found("Custom fixup not found", n));
    return static_cast<std::uint16_t>(id);
}

} // namespace ida::fixup

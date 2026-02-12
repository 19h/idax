/// \file type.cpp
/// \brief Implementation of ida::type — type system pimpl wrapping tinfo_t.

#include "detail/sdk_bridge.hpp"
#include <ida/type.hpp>

namespace ida::type {

// ── Pimpl definition ────────────────────────────────────────────────────

struct TypeInfo::Impl {
    tinfo_t ti;

    Impl() = default;
    explicit Impl(const tinfo_t& t) : ti(t) {}
};

// ── Lifecycle ───────────────────────────────────────────────────────────

TypeInfo::TypeInfo() : impl_(new Impl()) {}

TypeInfo::~TypeInfo() {
    delete impl_;
}

TypeInfo::TypeInfo(const TypeInfo& other) : impl_(new Impl(other.impl_->ti)) {}

TypeInfo& TypeInfo::operator=(const TypeInfo& other) {
    if (this != &other) {
        delete impl_;
        impl_ = new Impl(other.impl_->ti);
    }
    return *this;
}

TypeInfo::TypeInfo(TypeInfo&& other) noexcept : impl_(other.impl_) {
    other.impl_ = nullptr;
}

TypeInfo& TypeInfo::operator=(TypeInfo&& other) noexcept {
    if (this != &other) {
        delete impl_;
        impl_ = other.impl_;
        other.impl_ = nullptr;
    }
    return *this;
}

// ── Internal accessor ───────────────────────────────────────────────────

struct TypeInfoAccess {
    static TypeInfo::Impl* get(TypeInfo& ti) { return ti.impl_; }
    static const TypeInfo::Impl* get(const TypeInfo& ti) { return ti.impl_; }
};

namespace {

TypeInfo from_simple(type_t bt) {
    TypeInfo ti;
    TypeInfoAccess::get(ti)->ti.create_simple_type(bt);
    return ti;
}

} // anonymous namespace

// ── Factory constructors ────────────────────────────────────────────────

TypeInfo TypeInfo::void_type()  { return from_simple(BT_VOID); }
TypeInfo TypeInfo::int8()       { return from_simple(BT_INT8); }
TypeInfo TypeInfo::int16()      { return from_simple(BT_INT16); }
TypeInfo TypeInfo::int32()      { return from_simple(BT_INT32); }
TypeInfo TypeInfo::int64()      { return from_simple(BT_INT64); }
TypeInfo TypeInfo::uint8()      { return from_simple(BT_INT8  | BTMT_USIGNED); }
TypeInfo TypeInfo::uint16()     { return from_simple(BT_INT16 | BTMT_USIGNED); }
TypeInfo TypeInfo::uint32()     { return from_simple(BT_INT32 | BTMT_USIGNED); }
TypeInfo TypeInfo::uint64()     { return from_simple(BT_INT64 | BTMT_USIGNED); }
TypeInfo TypeInfo::float32()    { return from_simple(BTF_FLOAT); }
TypeInfo TypeInfo::float64()    { return from_simple(BTF_DOUBLE); }

TypeInfo TypeInfo::pointer_to(const TypeInfo& target) {
    TypeInfo result;
    TypeInfoAccess::get(result)->ti.create_ptr(TypeInfoAccess::get(target)->ti);
    return result;
}

TypeInfo TypeInfo::array_of(const TypeInfo& element, std::size_t count) {
    TypeInfo result;
    TypeInfoAccess::get(result)->ti.create_array(
        TypeInfoAccess::get(element)->ti, static_cast<uint32_t>(count));
    return result;
}

Result<TypeInfo> TypeInfo::from_declaration(std::string_view c_decl) {
    TypeInfo result;
    qstring qdecl = ida::detail::to_qstring(c_decl);
    // Ensure the declaration ends with a semicolon (SDK requires it).
    if (!qdecl.empty() && qdecl.last() != ';')
        qdecl.append(';');
    qstring name; // output name (may be empty for anonymous types)

    if (!parse_decl(&TypeInfoAccess::get(result)->ti, &name, nullptr,
                    qdecl.c_str(), PT_SIL))
        return std::unexpected(Error::sdk("Failed to parse C declaration",
                                          std::string(c_decl)));
    return result;
}

TypeInfo TypeInfo::create_struct() {
    TypeInfo result;
    TypeInfoAccess::get(result)->ti.create_udt(false);
    return result;
}

TypeInfo TypeInfo::create_union() {
    TypeInfo result;
    TypeInfoAccess::get(result)->ti.create_udt(true);
    return result;
}

Result<TypeInfo> TypeInfo::by_name(std::string_view name) {
    TypeInfo result;
    std::string name_str(name);
    if (!TypeInfoAccess::get(result)->ti.get_named_type(
            get_idati(), name_str.c_str(), BTF_TYPEDEF, true, true))
        return std::unexpected(Error::not_found("Type not found in local type library",
                                                name_str));
    return result;
}

// ── Introspection ───────────────────────────────────────────────────────

bool TypeInfo::is_void()           const { return impl_ && impl_->ti.is_void(); }
bool TypeInfo::is_integer()        const { return impl_ && impl_->ti.is_integral(); }
bool TypeInfo::is_floating_point() const { return impl_ && impl_->ti.is_floating(); }
bool TypeInfo::is_pointer()        const { return impl_ && impl_->ti.is_ptr(); }
bool TypeInfo::is_array()          const { return impl_ && impl_->ti.is_array(); }
bool TypeInfo::is_function()       const { return impl_ && impl_->ti.is_func(); }
bool TypeInfo::is_struct()         const { return impl_ && impl_->ti.is_struct(); }
bool TypeInfo::is_union()          const { return impl_ && impl_->ti.is_union(); }
bool TypeInfo::is_enum()           const { return impl_ && impl_->ti.is_enum(); }

Result<std::size_t> TypeInfo::size() const {
    if (!impl_)
        return std::unexpected(Error::internal("TypeInfo has null impl"));
    size_t sz = impl_->ti.get_size();
    if (sz == BADSIZE)
        return std::unexpected(Error::sdk("Cannot determine type size"));
    return sz;
}

Result<std::string> TypeInfo::to_string() const {
    if (!impl_)
        return std::unexpected(Error::internal("TypeInfo has null impl"));
    qstring buf;
    if (!impl_->ti.print(&buf))
        return std::unexpected(Error::sdk("Failed to print type"));
    return ida::detail::to_string(buf);
}

Result<std::size_t> TypeInfo::member_count() const {
    if (!impl_)
        return std::unexpected(Error::internal("TypeInfo has null impl"));
    if (!impl_->ti.is_struct() && !impl_->ti.is_union())
        return std::size_t{0};
    int n = impl_->ti.get_udt_nmembers();
    if (n < 0)
        return std::unexpected(Error::sdk("Failed to get member count"));
    return static_cast<std::size_t>(n);
}

// ── Struct/union member access ──────────────────────────────────────────

namespace {

Member make_member(const udm_t& m) {
    Member result;
    result.name = ida::detail::to_string(m.name);
    // Wrap the member's tinfo_t into a TypeInfo.
    TypeInfo ti;
    TypeInfoAccess::get(ti)->ti = m.type;
    result.type = std::move(ti);
    result.byte_offset = static_cast<std::size_t>(m.offset / 8);
    result.bit_size = static_cast<std::size_t>(m.size);
    result.comment = ida::detail::to_string(m.cmt);
    return result;
}

} // anonymous namespace

Result<std::vector<Member>> TypeInfo::members() const {
    if (!impl_)
        return std::unexpected(Error::internal("TypeInfo has null impl"));
    if (!impl_->ti.is_struct() && !impl_->ti.is_union())
        return std::unexpected(Error::validation("Type is not a struct or union"));

    udt_type_data_t udt;
    if (!impl_->ti.get_udt_details(&udt))
        return std::unexpected(Error::sdk("Failed to get UDT details"));

    std::vector<Member> result;
    result.reserve(udt.size());
    for (std::size_t i = 0; i < udt.size(); ++i)
        result.push_back(make_member(udt[i]));
    return result;
}

Result<Member> TypeInfo::member_by_name(std::string_view name) const {
    if (!impl_)
        return std::unexpected(Error::internal("TypeInfo has null impl"));
    if (!impl_->ti.is_struct() && !impl_->ti.is_union())
        return std::unexpected(Error::validation("Type is not a struct or union"));

    udm_t udm;
    std::string name_str(name);
    int idx = impl_->ti.find_udm(&udm, STRMEM_NAME);
    // find_udm with STRMEM_NAME needs the name in udm.name.
    udm.name = ida::detail::to_qstring(name);
    idx = impl_->ti.find_udm(&udm, STRMEM_NAME);
    if (idx < 0)
        return std::unexpected(Error::not_found("Member not found", name_str));
    return make_member(udm);
}

Result<Member> TypeInfo::member_by_offset(std::size_t byte_offset) const {
    if (!impl_)
        return std::unexpected(Error::internal("TypeInfo has null impl"));
    if (!impl_->ti.is_struct() && !impl_->ti.is_union())
        return std::unexpected(Error::validation("Type is not a struct or union"));

    udm_t udm;
    udm.offset = static_cast<::uint64>(byte_offset * 8);  // SDK uses bit offsets
    int idx = impl_->ti.find_udm(&udm, STRMEM_OFFSET);
    if (idx < 0)
        return std::unexpected(Error::not_found("No member at offset",
                                                std::to_string(byte_offset)));
    return make_member(udm);
}

Status TypeInfo::add_member(std::string_view name, const TypeInfo& member_type,
                            std::size_t byte_offset) {
    if (!impl_)
        return std::unexpected(Error::internal("TypeInfo has null impl"));
    if (!impl_->ti.is_struct() && !impl_->ti.is_union())
        return std::unexpected(Error::validation("Type is not a struct or union"));

    std::string name_str(name);
    const tinfo_t& mtype = TypeInfoAccess::get(member_type)->ti;
    ::uint64 boff = static_cast<::uint64>(byte_offset * 8);

    tinfo_code_t rc = impl_->ti.add_udm(name_str.c_str(), mtype, boff);
    if (rc != TERR_OK)
        return std::unexpected(Error::sdk("Failed to add member",
                                          name_str + ": " + std::string(tinfo_errstr(rc))));
    return ida::ok();
}

// ── Application ─────────────────────────────────────────────────────────

Status TypeInfo::apply(Address ea) const {
    if (!impl_)
        return std::unexpected(Error::internal("TypeInfo has null impl"));
    if (!apply_tinfo(ea, impl_->ti, TINFO_DEFINITE))
        return std::unexpected(Error::sdk("apply_tinfo failed", std::to_string(ea)));
    return ida::ok();
}

Status TypeInfo::save_as(std::string_view name) const {
    if (!impl_)
        return std::unexpected(Error::internal("TypeInfo has null impl"));
    std::string name_str(name);
    tinfo_code_t rc = impl_->ti.set_named_type(nullptr, name_str.c_str(), NTF_REPLACE);
    if (rc != TERR_OK)
        return std::unexpected(Error::sdk("Failed to save named type",
                                          name_str + ": " + std::string(tinfo_errstr(rc))));
    return ida::ok();
}

// ── Free functions ──────────────────────────────────────────────────────

Result<TypeInfo> retrieve(Address ea) {
    TypeInfo result;
    if (!get_tinfo(&TypeInfoAccess::get(result)->ti, ea))
        return std::unexpected(Error::not_found("No type at address",
                                                std::to_string(ea)));
    return result;
}

Result<TypeInfo> retrieve_operand(Address ea, int operand_index) {
    TypeInfo result;
    if (!get_op_tinfo(&TypeInfoAccess::get(result)->ti, ea, operand_index))
        return std::unexpected(Error::not_found("No operand type",
                                                std::to_string(ea) + ":" + std::to_string(operand_index)));
    return result;
}

Status remove_type(Address ea) {
    del_tinfo(ea);
    return ida::ok();
}

} // namespace ida::type

/// \file type.cpp
/// \brief Implementation of ida::type — type system pimpl wrapping tinfo_t.

#include "detail/type_impl.hpp"
#include <ida/instruction.hpp>

// IDA SDK type flags - fallback definitions if not provided by SDK headers
#ifndef NTF_FUNC
#define NTF_FUNC 0x0001
#endif
#ifndef NTF_TYPE
#define NTF_TYPE 0x0002
#endif

namespace ida::type {

// NOTE: TypeInfo::Impl and TypeInfoAccess are defined in detail/type_impl.hpp
// so they can be shared with other idax implementation files (e.g. function.cpp).

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

namespace {

TypeInfo from_simple(type_t bt) {
    TypeInfo ti;
    TypeInfoAccess::get(ti)->ti.create_simple_type(bt);
    return ti;
}

callcnv_t to_sdk_calling_convention(CallingConvention cc, bool has_varargs) {
    callcnv_t sdk = CM_CC_UNKNOWN;
    switch (cc) {
        case CallingConvention::Unknown:     sdk = CM_CC_UNKNOWN; break;
        case CallingConvention::Cdecl:       sdk = CM_CC_CDECL; break;
        case CallingConvention::Stdcall:     sdk = CM_CC_STDCALL; break;
        case CallingConvention::Pascal:      sdk = CM_CC_PASCAL; break;
        case CallingConvention::Fastcall:    sdk = CM_CC_FASTCALL; break;
        case CallingConvention::Thiscall:    sdk = CM_CC_THISCALL; break;
        case CallingConvention::Swift:       sdk = CM_CC_SWIFT; break;
        case CallingConvention::Golang:      sdk = CM_CC_GOLANG; break;
        case CallingConvention::UserDefined: sdk = CM_CC_SPECIAL; break;
    }

    if (has_varargs) {
        if (sdk == CM_CC_UNKNOWN || sdk == CM_CC_CDECL)
            return CM_CC_ELLIPSIS;
        if (sdk == CM_CC_SPECIAL)
            return CM_CC_SPECIALE;
    }
    return sdk;
}

CallingConvention from_sdk_calling_convention(callcnv_t cc) {
    switch (cc) {
        case CM_CC_CDECL:
        case CM_CC_ELLIPSIS:
            return CallingConvention::Cdecl;
        case CM_CC_STDCALL:
            return CallingConvention::Stdcall;
        case CM_CC_PASCAL:
            return CallingConvention::Pascal;
        case CM_CC_FASTCALL:
            return CallingConvention::Fastcall;
        case CM_CC_THISCALL:
            return CallingConvention::Thiscall;
        case CM_CC_SWIFT:
            return CallingConvention::Swift;
        case CM_CC_GOLANG:
        case CM_CC_GOSTK:
            return CallingConvention::Golang;
        case CM_CC_SPECIAL:
        case CM_CC_SPECIALE:
        case CM_CC_SPECIALP:
            return CallingConvention::UserDefined;
        default:
            return CallingConvention::Unknown;
    }
}

Result<tinfo_t> as_function_type(const tinfo_t& ti) {
    if (ti.is_func())
        return ti;
    if (ti.is_ptr()) {
        tinfo_t pointed = ti.get_pointed_object();
        if (pointed.is_func())
            return pointed;
    }
    return std::unexpected(Error::validation("Type is not a function or function pointer"));
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

Result<TypeInfo> TypeInfo::function_type(const TypeInfo& return_type,
                                         const std::vector<TypeInfo>& argument_types,
                                         CallingConvention calling_convention,
                                         bool has_varargs) {
    const auto* return_impl = TypeInfoAccess::get(return_type);
    if (return_impl == nullptr)
        return std::unexpected(Error::internal("Return type has null implementation"));

    func_type_data_t function_data;
    function_data.rettype = return_impl->ti;
    function_data.set_cc(to_sdk_calling_convention(calling_convention, has_varargs));

    for (const auto& argument_type : argument_types) {
        const auto* argument_impl = TypeInfoAccess::get(argument_type);
        if (argument_impl == nullptr)
            return std::unexpected(Error::internal("Argument type has null implementation"));
        funcarg_t arg;
        arg.type = argument_impl->ti;
        function_data.push_back(std::move(arg));
    }

    TypeInfo result;
    if (!TypeInfoAccess::get(result)->ti.create_func(function_data))
        return std::unexpected(Error::sdk("Failed to create function type"));
    return result;
}

Result<TypeInfo> TypeInfo::enum_type(const std::vector<EnumMember>& members,
                                     std::size_t byte_width,
                                     bool bitmask) {
    if (byte_width == 0 || byte_width > 8 || (byte_width & (byte_width - 1)) != 0)
        return std::unexpected(Error::validation("Enum byte width must be one of 1,2,4,8",
                                                 std::to_string(byte_width)));

    enum_type_data_t enum_data(bitmask ? (BTE_ALWAYS | BTE_HEX | BTE_BITMASK)
                                       : (BTE_ALWAYS | BTE_HEX));
    if (!enum_data.set_nbytes(static_cast<int>(byte_width)))
        return std::unexpected(Error::validation("Failed to set enum byte width",
                                                 std::to_string(byte_width)));

    for (const auto& member : members) {
        if (member.name.empty())
            return std::unexpected(Error::validation("Enum member name cannot be empty"));
        enum_data.add_constant(member.name.c_str(), member.value,
                               member.comment.empty() ? nullptr : member.comment.c_str());
    }

    TypeInfo result;
    if (!TypeInfoAccess::get(result)->ti.create_enum(enum_data))
        return std::unexpected(Error::sdk("Failed to create enum type"));
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
bool TypeInfo::is_typedef()        const { return impl_ && impl_->ti.is_typedef(); }

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

Result<TypeInfo> TypeInfo::pointee_type() const {
    if (!impl_)
        return std::unexpected(Error::internal("TypeInfo has null impl"));
    if (!impl_->ti.is_ptr())
        return std::unexpected(Error::validation("Type is not a pointer"));

    tinfo_t pointee = impl_->ti.get_pointed_object();
    if (!pointee.present())
        return std::unexpected(Error::sdk("Failed to get pointer target type"));

    TypeInfo result;
    TypeInfoAccess::get(result)->ti = pointee;
    return result;
}

Result<TypeInfo> TypeInfo::array_element_type() const {
    if (!impl_)
        return std::unexpected(Error::internal("TypeInfo has null impl"));
    if (!impl_->ti.is_array())
        return std::unexpected(Error::validation("Type is not an array"));

    tinfo_t element = impl_->ti.get_array_element();
    if (!element.present())
        return std::unexpected(Error::sdk("Failed to get array element type"));

    TypeInfo result;
    TypeInfoAccess::get(result)->ti = element;
    return result;
}

Result<std::size_t> TypeInfo::array_length() const {
    if (!impl_)
        return std::unexpected(Error::internal("TypeInfo has null impl"));
    if (!impl_->ti.is_array())
        return std::unexpected(Error::validation("Type is not an array"));

    int count = impl_->ti.get_array_nelems();
    if (count < 0)
        return std::unexpected(Error::sdk("Failed to get array element count"));
    return static_cast<std::size_t>(count);
}

Result<TypeInfo> TypeInfo::resolve_typedef() const {
    if (!impl_)
        return std::unexpected(Error::internal("TypeInfo has null impl"));

    if (!impl_->ti.is_typedef()) {
        TypeInfo result;
        TypeInfoAccess::get(result)->ti = impl_->ti;
        return result;
    }

    qstring final_name;
    if (!impl_->ti.get_final_type_name(&final_name) || final_name.empty()) {
        return std::unexpected(Error::sdk("Failed to resolve typedef chain"));
    }

    const std::string final_name_string = ida::detail::to_string(final_name);
    tinfo_t resolved;
    til_t* source_til = impl_->ti.get_til();
    if (!resolved.get_named_type(source_til, final_name.c_str(), BTF_TYPEDEF, true, true)
        && !resolved.get_named_type(get_idati(), final_name.c_str(), BTF_TYPEDEF, true, true)
        && !resolved.get_named_type(nullptr, final_name.c_str(), BTF_TYPEDEF, true, true)) {
        return std::unexpected(Error::not_found("Failed to resolve typedef target",
                                                final_name_string));
    }

    if (!resolved.present()) {
        return std::unexpected(Error::sdk("Resolved typedef target is invalid",
                                          final_name_string));
    }

    TypeInfo result;
    TypeInfoAccess::get(result)->ti = resolved;
    return result;
}

Result<TypeInfo> TypeInfo::function_return_type() const {
    if (!impl_)
        return std::unexpected(Error::internal("TypeInfo has null impl"));

    auto function_type = as_function_type(impl_->ti);
    if (!function_type)
        return std::unexpected(function_type.error());

    TypeInfo result;
    TypeInfoAccess::get(result)->ti = function_type->get_rettype();
    return result;
}

Result<std::vector<TypeInfo>> TypeInfo::function_argument_types() const {
    if (!impl_)
        return std::unexpected(Error::internal("TypeInfo has null impl"));

    auto function_type = as_function_type(impl_->ti);
    if (!function_type)
        return std::unexpected(function_type.error());

    func_type_data_t function_data;
    if (!function_type->get_func_details(&function_data))
        return std::unexpected(Error::sdk("Failed to get function details"));

    std::vector<TypeInfo> arguments;
    arguments.reserve(function_data.size());
    for (const auto& argument : function_data) {
        TypeInfo wrapped;
        TypeInfoAccess::get(wrapped)->ti = argument.type;
        arguments.push_back(std::move(wrapped));
    }
    return arguments;
}

Result<CallingConvention> TypeInfo::calling_convention() const {
    if (!impl_)
        return std::unexpected(Error::internal("TypeInfo has null impl"));

    auto function_type = as_function_type(impl_->ti);
    if (!function_type)
        return std::unexpected(function_type.error());

    return from_sdk_calling_convention(function_type->get_cc());
}

Result<bool> TypeInfo::is_variadic_function() const {
    if (!impl_)
        return std::unexpected(Error::internal("TypeInfo has null impl"));

    auto function_type = as_function_type(impl_->ti);
    if (!function_type)
        return std::unexpected(function_type.error());

    return function_type->is_vararg_cc();
}

Result<std::vector<EnumMember>> TypeInfo::enum_members() const {
    if (!impl_)
        return std::unexpected(Error::internal("TypeInfo has null impl"));
    if (!impl_->ti.is_enum())
        return std::unexpected(Error::validation("Type is not an enum"));

    enum_type_data_t enum_data;
    if (!impl_->ti.get_enum_details(&enum_data))
        return std::unexpected(Error::sdk("Failed to get enum details"));

    std::vector<EnumMember> members;
    members.reserve(enum_data.size());
    for (const auto& item : enum_data) {
        EnumMember member;
        member.name = ida::detail::to_string(item.name);
        member.value = item.value;
        member.comment = ida::detail::to_string(item.cmt);
        members.push_back(std::move(member));
    }
    return members;
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

  if (ida::instruction::is_call(ea)) {
    if (apply_callee_tinfo(ea, impl_->ti))
      return ida::ok();
    if (!apply_tinfo(ea, impl_->ti, TINFO_DEFINITE))
      return std::unexpected(
        Error::sdk("apply_callee_tinfo and apply_tinfo fallback both failed",
                   std::to_string(ea)));
  } else {
    if (!apply_tinfo(ea, impl_->ti, TINFO_DEFINITE))
      return std::unexpected(
        Error::sdk("apply_tinfo failed", std::to_string(ea)));
  }
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

// ── Type library access ─────────────────────────────────────────────────

Result<bool> load_type_library(std::string_view til_name) {
    std::string name_str(til_name);
    int rc = ::add_til(name_str.c_str(), ADDTIL_DEFAULT);
    if (rc == ADDTIL_FAILED)
        return std::unexpected(Error::sdk("Failed to load type library", name_str));
    if (rc == ADDTIL_ABORTED)
        return std::unexpected(Error::sdk("Type library loading aborted", name_str));
    // ADDTIL_OK or ADDTIL_COMP
    return true;
}

Status unload_type_library(std::string_view til_name) {
    std::string name_str(til_name);
    if (!::del_til(name_str.c_str()))
        return std::unexpected(Error::sdk("Failed to unload type library", name_str));
    return ida::ok();
}

Result<std::size_t> local_type_count() {
    uint32 count = get_ordinal_count(nullptr);
    return static_cast<std::size_t>(count);
}

Result<std::string> local_type_name(std::size_t ordinal) {
    const char* name = get_numbered_type_name(get_idati(),
                                               static_cast<uint32>(ordinal));
    if (name == nullptr)
        return std::unexpected(Error::not_found("No type at ordinal",
                                                 std::to_string(ordinal)));
    return std::string(name);
}

Result<std::size_t> import_type(std::string_view source_til_name,
                                 std::string_view type_name) {
    std::string src_name(source_til_name);
    std::string tname(type_name);

    til_t* src = nullptr;
    if (!src_name.empty()) {
        // Try to find the til among bases of idati.
        src = get_idati()->find_base(src_name.c_str());
        if (src == nullptr) {
            // Try loading it.
            qstring errbuf;
            src = load_til(src_name.c_str(), &errbuf, nullptr);
            if (src == nullptr)
                return std::unexpected(Error::not_found(
                    "Source type library not found: " + ida::detail::to_string(errbuf),
                    src_name));
        }
    }

    // If no source specified, use idati itself (search local types).
    if (src == nullptr) {
        // copy_named_type searches through base tils of the destination.
        src = get_idati();
    }

    uint32 ordinal = copy_named_type(get_idati(), src, tname.c_str());
    if (ordinal == 0)
        return std::unexpected(Error::not_found("Type not found in source library",
                                                 tname));
    return static_cast<std::size_t>(ordinal);
}

NamedTypeIterator::~NamedTypeIterator() {
    delete impl_;
}

NamedTypeRange::~NamedTypeRange() {
    delete impl_;
}

NamedTypeIterator::NamedTypeIterator(const NamedTypeIterator& other)
    : impl_(other.impl_ ? new NamedTypeIterator::Impl(*other.impl_) : nullptr) {
}

NamedTypeIterator& NamedTypeIterator::operator=(const NamedTypeIterator& other) {
    if (this != &other) {
        delete impl_;
        impl_ = other.impl_ ? new NamedTypeIterator::Impl(*other.impl_) : nullptr;
    }
    return *this;
}

NamedTypeRange::NamedTypeRange(const NamedTypeRange& other)
    : impl_(other.impl_ ? new NamedTypeRange::Impl(*other.impl_) : nullptr) {
}

NamedTypeRange& NamedTypeRange::operator=(const NamedTypeRange& other) {
    if (this != &other) {
        delete impl_;
        impl_ = other.impl_ ? new NamedTypeRange::Impl(*other.impl_) : nullptr;
    }
    return *this;
}


namespace {
// Helper to get library name from til_t*
std::string get_library_name(til_t* til) {
    if (!til) return {};
    return std::string(til->name, strlen(til->name));
}
} // anonymous namespace

// ============================================================================
/// TilBaseIterator implementation
// ============================================================================

TilBaseIterator::~TilBaseIterator() {
    delete TilBaseAccess::get(*this);
}

TilBaseIterator::TilBaseIterator(const TilBaseIterator& other) {
    auto* copy = new TilBaseIterator::Impl(*TilBaseAccess::get(other));
    TilBaseAccess::get(*this) = copy;
}

TilBaseIterator& TilBaseIterator::operator=(const TilBaseIterator& other) {
    if (this != &other) {
        delete TilBaseAccess::get(*this);
        auto* copy = new TilBaseIterator::Impl(*TilBaseAccess::get(other));
        TilBaseAccess::get(*this) = copy;
    }
    return *this;
}

TilBaseIterator& TilBaseIterator::operator++() {
    auto* impl = TilBaseAccess::get(*this);
    if (!impl || !impl->root_til) return *this;

    impl->base_index++;
    // base_index 0 = root til, base_index 1..base_count-1 = base[0..base_count-2]
    // When exhausted, set base_index = base_count + 1 to match end() iterator
    if (impl->base_index >= impl->base_count) {
        impl->base_index = impl->base_count + 1;
        impl->root_til = nullptr;
        impl->current_name.clear();
    } else {
        til_t* current = (impl->base_index == 0)
            ? impl->root_til
            : impl->root_til->base[impl->base_index - 1];
        impl->current_name = get_library_name(current);
    }
    return *this;
}

TilBaseIterator TilBaseIterator::operator++(int) {
    TilBaseIterator tmp = *this;
    ++(*this);
    return tmp;
}

TilBaseIterator::reference TilBaseIterator::operator*() const {
    static TilEntry entry;
    auto* impl = TilBaseAccess::get(*this);
    if (!impl || !impl->root_til || impl->base_index >= impl->base_count) {
        entry.name.clear();
        entry.til = nullptr;
    } else {
        til_t* current = (impl->base_index == 0)
            ? impl->root_til
            : impl->root_til->base[impl->base_index - 1];
        entry.name = get_library_name(current);
        entry.til = current;
    }
    return entry;
}

TilBaseIterator::pointer TilBaseIterator::operator->() const {
    static TilEntry entry;
    auto* impl = TilBaseAccess::get(*this);
    if (!impl || !impl->root_til || impl->base_index >= impl->base_count) {
        entry.name.clear();
        entry.til = nullptr;
    } else {
        til_t* current = (impl->base_index == 0)
            ? impl->root_til
            : impl->root_til->base[impl->base_index - 1];
        entry.name = get_library_name(current);
        entry.til = current;
    }
    return &entry;
}

bool TilBaseIterator::operator==(const TilBaseIterator& other) const {
    auto* a = TilBaseAccess::get(*this);
    auto* b = TilBaseAccess::get(other);
    if (!a && !b) return true;
    if (!a || !b) return false;
    if (a->root_til != b->root_til) return false;
    return a->base_index == b->base_index;
}

bool TilBaseIterator::operator!=(const TilBaseIterator& other) const {
    return !(*this == other);
}

// ============================================================================
/// TilBaseRange implementation
// ============================================================================

TilBaseRange::~TilBaseRange() {
    delete TilBaseAccess::get(*this);
}

TilBaseRange::TilBaseRange(const TilBaseRange& other) {
    auto* copy = new TilBaseRange::Impl(*TilBaseAccess::get(other));
    TilBaseAccess::get(*this) = copy;
}

TilBaseRange& TilBaseRange::operator=(const TilBaseRange& other) {
    if (this != &other) {
        delete TilBaseAccess::get(*this);
        auto* copy = new TilBaseRange::Impl(*TilBaseAccess::get(other));
        TilBaseAccess::get(*this) = copy;
    }
    return *this;
}

TilBaseIterator TilBaseRange::begin() const {
    TilBaseIterator it;
    auto* impl = new TilBaseIterator::Impl(impl_->root_til, impl_->base_count);
    TilBaseAccess::get(it) = impl;

    // Initialize current_name to root til name
    if (impl->root_til) {
        impl->current_name = get_library_name(impl->root_til);
    }
    return it;
}

TilBaseIterator TilBaseRange::end() const {
    TilBaseIterator it;
    auto* eimpl = new TilBaseIterator::Impl(nullptr, impl_->base_count);
    eimpl->base_index = impl_->base_count + 1;  // Past the last valid position
    TilBaseAccess::get(it) = eimpl;
    return it;
}

Result<TilBaseRange> all_tils() {
    til_t* til = get_idati();
    if (!til)
        return std::unexpected(Error::not_found("No type library available"));

    TilBaseRange range;
    auto* rimpl = new TilBaseRange::Impl(til, til->nbases + 1);  // +1 for root til
    TilBaseAccess::get(range) = rimpl;
    return range;
}

// ============================================================================
/// TILTypeIterator implementation
// ============================================================================

TILTypeIterator::~TILTypeIterator() {
    delete TILTypeAccess::get(*this);
}

TILTypeIterator::TILTypeIterator(const TILTypeIterator& other) {
    auto* copy = new TILTypeIterator::Impl(*TILTypeAccess::get(other));
    TILTypeAccess::get(*this) = copy;
}

TILTypeIterator& TILTypeIterator::operator=(const TILTypeIterator& other) {
    if (this != &other) {
        delete TILTypeAccess::get(*this);
        auto* copy = new TILTypeIterator::Impl(*TILTypeAccess::get(other));
        TILTypeAccess::get(*this) = copy;
    }
    return *this;
}

TILTypeIterator& TILTypeIterator::operator++() {
    auto* impl = TILTypeAccess::get(*this);
    if (!impl || !impl->til) return *this;

    if (impl->current_name.empty()) {
        // First call - use first_named_type
        const char* first = first_named_type(impl->til, impl->flags);
        if (first) {
            impl->current_name = first;
        } else {
            impl->til = nullptr;
        }
    } else {
        // Subsequent call - use next_named_type
        const char* next = next_named_type(impl->til, impl->current_name.c_str(), impl->flags);
        if (next) {
            impl->current_name = next;
        } else {
            impl->til = nullptr;
            impl->current_name.clear();
        }
    }
    return *this;
}

TILTypeIterator TILTypeIterator::operator++(int) {
    TILTypeIterator tmp = *this;
    ++(*this);
    return tmp;
}

TILTypeIterator::reference TILTypeIterator::operator*() const {
    static std::string name;
    auto* impl = TILTypeAccess::get(*this);
    name = impl ? impl->current_name : std::string{};
    return name;
}

TILTypeIterator::pointer TILTypeIterator::operator->() const {
    static std::string name;
    auto* impl = TILTypeAccess::get(*this);
    name = impl ? impl->current_name : std::string{};
    return &name;
}

bool TILTypeIterator::operator==(const TILTypeIterator& other) const {
    auto* a = TILTypeAccess::get(*this);
    auto* b = TILTypeAccess::get(other);
    if (!a && !b) return true;
    if (!a || !b) return false;
    return a->til == b->til && a->current_name == b->current_name;
}

bool TILTypeIterator::operator!=(const TILTypeIterator& other) const {
    return !(*this == other);
}

// ============================================================================
/// TILTypeRange implementation
// ============================================================================

TILTypeRange::~TILTypeRange() {
    delete TILTypeAccess::get(*this);
}

TILTypeRange::TILTypeRange(const TILTypeRange& other) {
    auto* copy = new TILTypeRange::Impl(*TILTypeAccess::get(other));
    TILTypeAccess::get(*this) = copy;
}

TILTypeRange& TILTypeRange::operator=(const TILTypeRange& other) {
    if (this != &other) {
        delete TILTypeAccess::get(*this);
        auto* copy = new TILTypeRange::Impl(*TILTypeAccess::get(other));
        TILTypeAccess::get(*this) = copy;
    }
    return *this;
}

TILTypeIterator TILTypeRange::begin() const {
    TILTypeIterator it;
    if (!impl_->til) return it;  // Early return if til is null

    auto* impl = new TILTypeIterator::Impl(impl_->til, impl_->flags);
    TILTypeAccess::get(it) = impl;

    // Get first type name
    const char* first = first_named_type(impl_->til, impl_->flags);
    if (first) {
        impl->current_name = first;
    } else {
        impl->til = nullptr;
        impl->current_name.clear();
    }
    return it;
}

TILTypeIterator TILTypeRange::end() const {
    TILTypeIterator it;
    auto* eimpl = new TILTypeIterator::Impl(nullptr, impl_->flags);
    TILTypeAccess::get(it) = eimpl;
    return it;
}

Result<TILTypeRange> named_types_in(void* til_ptr, int flags) {
    if (!til_ptr)
        return std::unexpected(Error::validation("TIL pointer cannot be null"));

    TILTypeRange range;
    auto* rimpl = new TILTypeRange::Impl(static_cast<til_t*>(til_ptr), flags);
    TILTypeAccess::get(range) = rimpl;
    return range;
}

Result<TILTypeRange> named_types_in(std::string_view til_name, int flags) {
    til_t* til = get_idati()->find_base(std::string(til_name).c_str());
    if (!til) {
        qstring errbuf;
        til = load_til(std::string(til_name).c_str(), &errbuf, nullptr);
        if (!til)
            return std::unexpected(Error::not_found(
                "Type library not found: " + std::string(til_name)));
    }
    return named_types_in(til, flags);
}

NamedTypeIterator& NamedTypeIterator::operator++() {
    if (!impl_ || !impl_->root_til) return *this;

    // Get the current til (root til is base 0, then base[1], base[2], etc.)
    til_t* current_til = (impl_->base_index == 0)
        ? impl_->root_til
        : impl_->root_til->base[impl_->base_index];

    const char* next = nullptr;
    if (impl_->current_name.empty()) {
        // Starting fresh on this til - use first_named_type
        next = first_named_type(current_til, impl_->flags);
    } else {
        // Continue from where we left off - use next_named_type
        next = next_named_type(current_til, impl_->current_name.c_str(), impl_->flags);
    }
    if (next) {
        impl_->current_name = next;
    } else {
        // Exhausted current til, advance to next base
        impl_->base_index++;
        while (impl_->base_index < impl_->base_count) {
            til_t* next_til = (impl_->base_index == 0)
                ? impl_->root_til
                : impl_->root_til->base[impl_->base_index];
            if (!next_til) break;

            impl_->current_name.clear();  // Reset before starting new til
            const char* first = first_named_type(next_til, impl_->flags);
            if (first) {
                impl_->current_name = first;
                impl_->current_library = get_library_name(next_til);
                return *this;
            }
            impl_->base_index++;
        }
        // All bases exhausted, mark as end
        impl_->current_name.clear();
        impl_->current_library.clear();
        impl_->root_til = nullptr;
        impl_->base_index = 0;  // Must match end() iterator for equality comparison
    }
    return *this;
}

NamedTypeIterator NamedTypeIterator::operator++(int) {
    NamedTypeIterator tmp = *this;
    ++(*this);
    return tmp;
}

NamedTypeIterator::reference NamedTypeIterator::operator*() const {
    static NamedTypeEntry entry;
    entry.name = impl_ ? impl_->current_name : std::string{};
    entry.library_name = impl_ ? impl_->current_library : std::string{};
    return entry;
}

NamedTypeIterator::pointer NamedTypeIterator::operator->() const {
    static NamedTypeEntry entry;
    if (impl_) {
        entry.name = impl_->current_name;
        entry.library_name = impl_->current_library;
    } else {
        entry.name.clear();
        entry.library_name.clear();
    }
    return &entry;
}

bool NamedTypeIterator::operator==(const NamedTypeIterator& other) const {
    if (!impl_ && !other.impl_) return true;
    if (!impl_ || !other.impl_) return false;
    return impl_->root_til == other.impl_->root_til
        && impl_->base_index == other.impl_->base_index
        && impl_->current_name == other.impl_->current_name;
}

bool NamedTypeIterator::operator!=(const NamedTypeIterator& other) const {
    return !(*this == other);
}

NamedTypeIterator NamedTypeRange::begin() const {
    NamedTypeIterator it;
    NamedTypeAccess::get(it) = new NamedTypeIterator::Impl(impl_->root_til, impl_->flags);
    if (NamedTypeAccess::get(it)->root_til) {
        const char* first = first_named_type(NamedTypeAccess::get(it)->root_til, NamedTypeAccess::get(it)->flags);
        if (first) {
            NamedTypeAccess::get(it)->current_name = first;
            NamedTypeAccess::get(it)->current_library = get_library_name(NamedTypeAccess::get(it)->root_til);
            return it;
        }
    }
    return end();
}

NamedTypeIterator NamedTypeRange::end() const {
    NamedTypeIterator it;
    NamedTypeAccess::get(it) = new NamedTypeIterator::Impl(nullptr, impl_->flags);
    return it;
}

Result<NamedTypeRange> named_types(std::string_view til_name, int flags) {
    std::string name_str(til_name);

    til_t* til = nullptr;
    if (!name_str.empty()) {
        til = get_idati()->find_base(name_str.c_str());
        if (til == nullptr) {
            qstring errbuf;
            til = load_til(name_str.c_str(), &errbuf, nullptr);
            if (til == nullptr)
                return std::unexpected(Error::not_found(
                    "Type library not found: " + name_str));
        }
    } else {
        til = get_idati();
    }

    if (til == nullptr)
        return std::unexpected(Error::not_found("No type library available"));

    NamedTypeRange range;
    NamedTypeAccess::get(range) = new NamedTypeRange::Impl(til, flags);
    return range;
}

Result<NamedTypeRange> named_types(std::string_view til_name) {
    return named_types(til_name, NTF_TYPE);
}

Result<NamedTypeRange> named_types() {
    return named_types({}, NTF_TYPE);
}

Result<TypeInfo> ensure_named_type(std::string_view type_name,
                                   std::string_view source_til_name) {
    if (type_name.empty()) {
        return std::unexpected(Error::validation("Type name must not be empty"));
    }

    if (auto existing = TypeInfo::by_name(type_name); existing) {
        return *existing;
    }

    auto imported = import_type(source_til_name, type_name);
    if (!imported) {
        return std::unexpected(imported.error());
    }

    auto resolved = TypeInfo::by_name(type_name);
    if (!resolved) {
        return std::unexpected(Error::sdk("Imported type did not resolve by name",
                                          std::string(type_name)));
    }
    return *resolved;
}

Status apply_named_type(Address ea, std::string_view type_name) {
    std::string name_str(type_name);
    if (!::apply_named_type(ea, name_str.c_str()))
        return std::unexpected(Error::sdk("apply_named_type failed", name_str));
    return ida::ok();
}

} // namespace ida::type

/// \file type.cpp
/// \brief Implementation of ida::type — type system pimpl wrapping tinfo_t.

#include "detail/type_impl.hpp"

#include <algorithm>
#include <functional>
#include <map>
#include <queue>
#include <set>
#include <sstream>

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

namespace {

Result<int> parse_declarations_flags(const ParseDeclarationsOptions& options) {
    int flags = HTI_DCL;
    if (options.suppress_warnings)
        flags |= HTI_NWR;
    if (options.relaxed_namespaces)
        flags |= HTI_RELAXED;
    if (options.raw_argument_names)
        flags |= HTI_RAWARGS;
    if (options.no_mangle)
        flags |= HTI_NO_MANGLE;

    switch (options.pack_alignment) {
        case 0: break;
        case 1: flags |= HTI_PAK1; break;
        case 2: flags |= HTI_PAK2; break;
        case 4: flags |= HTI_PAK4; break;
        case 8: flags |= HTI_PAK8; break;
        case 16: flags |= HTI_PAK16; break;
        default:
            return std::unexpected(Error::validation(
                "Pack alignment must be 0, 1, 2, 4, 8, or 16",
                std::to_string(options.pack_alignment)));
    }

    return flags;
}

} // anonymous namespace

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

Result<ParseDeclarationsReport>
parse_declarations(std::string_view declarations,
                   const ParseDeclarationsOptions& options) {
    if (declarations.empty())
        return std::unexpected(Error::validation("Type declaration block cannot be empty"));
    if (declarations.find('\0') != std::string_view::npos)
        return std::unexpected(Error::validation(
            "Type declaration block cannot contain embedded NUL bytes"));

    auto flags = parse_declarations_flags(options);
    if (!flags)
        return std::unexpected(flags.error());

    qstring input = ida::detail::to_qstring(declarations);
    int rc = ::parse_decls(nullptr, input.c_str(), nullptr, *flags);
    if (rc < 0)
        return std::unexpected(Error::sdk("parse_decls failed", std::to_string(rc)));

    ParseDeclarationsReport report;
    report.error_count = static_cast<std::size_t>(rc);
    return report;
}

namespace {

std::map<std::string, std::set<int>>
used_offsets_map(const TypeRenderOptions& options) {
    std::map<std::string, std::set<int>> result;
    for (const auto& entry : options.used_offsets) {
        if (entry.type_name.empty())
            continue;
        auto& offsets = result[entry.type_name];
        offsets.insert(entry.byte_offsets.begin(), entry.byte_offsets.end());
    }
    return result;
}

bool tinfo_from_ordinal(std::uint32_t ordinal, tinfo_t* out) {
    if (ordinal == 0 || out == nullptr)
        return false;
    return out->get_numbered_type(nullptr, static_cast<uint32>(ordinal));
}

bool tinfo_from_name(std::string_view name, tinfo_t* out) {
    if (name.empty() || out == nullptr)
        return false;
    std::string name_string(name);
    return out->get_named_type(nullptr, name_string.c_str());
}

std::string type_name(const tinfo_t& ti) {
    qstring name;
    if (!ti.get_type_name(&name) || name.empty())
        return {};
    return ida::detail::to_string(name);
}

std::string hex_size(std::uint64_t value) {
    char buffer[32];
    qsnprintf(buffer, sizeof(buffer), "0x%llX",
              static_cast<unsigned long long>(value));
    return buffer;
}

std::string print_member_decl(const udm_t& member) {
    qstring declaration;
    member.type.print(&declaration,
                      member.name.c_str(),
                      PRTYPE_1LINE | PRTYPE_SEMI | PRTYPE_OFFSETS);
    return std::string("    ") + declaration.c_str();
}

std::string print_type_decl(const tinfo_t& ti,
                            const char* name = nullptr,
                            int flags = PRTYPE_1LINE | PRTYPE_SEMI) {
    qstring output;
    ti.print(&output, name, flags);
    return ida::detail::to_string(output);
}

class StringSink : public text_sink_t {
public:
    qstring output;

    int idaapi print(const char* text) override {
        if (text != nullptr)
            output.append(text);
        return 0;
    }
};

class TypeDeclarationFormatter {
public:
    explicit TypeDeclarationFormatter(const TypeRenderOptions& options)
        : options_(options), used_offsets_(used_offsets_map(options)) {}

    std::string render_named(const std::vector<std::string>& names, int max_depth) {
        std::vector<OrderedType> order;
        std::set<std::string> emitted;
        std::set<std::string> on_stack;

        for (const auto& name : names) {
            tinfo_t ti;
            if (!tinfo_from_name(name, &ti))
                continue;
            walk(ti, 0, max_depth, order, emitted, on_stack);
        }
        return render_order(order);
    }

    std::string render_ordinals(const std::vector<std::uint32_t>& ordinals) {
        std::vector<OrderedType> order;
        std::set<std::string> emitted;
        std::set<std::string> on_stack;

        for (std::uint32_t ordinal : ordinals) {
            tinfo_t ti;
            if (!tinfo_from_ordinal(ordinal, &ti))
                continue;
            walk(ti, 0, -1, order, emitted, on_stack);
        }
        return render_order(order);
    }

private:
    struct OrderedType {
        std::string name;
        tinfo_t type;
    };

    void walk(const tinfo_t& ti,
              int depth,
              int max_depth,
              std::vector<OrderedType>& out,
              std::set<std::string>& emitted,
              std::set<std::string>& on_stack) {
        if (!ti.present())
            return;

        if (ti.is_ptr()) {
            walk(ti.get_pointed_object(), depth, max_depth, out, emitted, on_stack);
            return;
        }
        if (ti.is_array()) {
            walk(ti.get_array_element(), depth, max_depth, out, emitted, on_stack);
            return;
        }
        if (ti.is_func()) {
            func_type_data_t function_data;
            if (ti.get_func_details(&function_data)) {
                walk(function_data.rettype, depth, max_depth, out, emitted, on_stack);
                for (std::size_t i = 0; i < function_data.size(); ++i)
                    walk(function_data[i].type, depth, max_depth, out, emitted, on_stack);
            }
            return;
        }

        std::string name = type_name(ti);
        if (name.empty())
            return;
        if (max_depth >= 0 && depth > max_depth)
            return;
        if (emitted.count(name) != 0 || on_stack.count(name) != 0)
            return;

        on_stack.insert(name);

        bool drop_this = false;
        if (ti.is_udt()) {
            udt_type_data_t udt;
            if (ti.get_udt_details(&udt)) {
                const std::set<int>* accessed = nullptr;
                if (options_.trim_unreferenced && !udt.is_union) {
                    auto it = used_offsets_.find(name);
                    if (it != used_offsets_.end() && !it->second.empty())
                        accessed = &it->second;
                }

                if (options_.trim_unreferenced && accessed == nullptr && !udt.is_union) {
                    drop_this = true;
                } else {
                    for (std::size_t i = 0; i < udt.size(); ++i) {
                        if (accessed != nullptr) {
                            const int offset = static_cast<int>(udt[i].offset / 8);
                            int size = static_cast<int>(udt[i].size / 8);
                            if (size == 0)
                                size = 1;
                            auto lower = accessed->lower_bound(offset);
                            if (lower == accessed->end() || *lower >= offset + size)
                                continue;
                        }
                        walk(udt[i].type, depth + 1, max_depth, out, emitted, on_stack);
                    }
                }
            }
        }

        if (!drop_this) {
            out.push_back(OrderedType{name, ti});
            emitted.insert(name);
        }
        on_stack.erase(name);
    }

    std::string render_order(const std::vector<OrderedType>& order) {
        std::ostringstream output;
        for (const auto& item : order) {
            std::string text = emit_one(item.type, item.name);
            if (text.empty())
                continue;
            output << text;
            if (text.back() != '\n')
                output << '\n';
            output << '\n';
        }
        return output.str();
    }

    std::string emit_one(const tinfo_t& ti, const std::string& name) {
        if (!ti.present())
            return {};
        if (ti.is_udt())
            return emit_udt(ti, name);
        if (ti.is_enum())
            return emit_enum(ti, name);
        return emit_typedef_or_other(ti, name);
    }

    std::string emit_udt(const tinfo_t& ti, const std::string& name) {
        udt_type_data_t udt;
        if (!ti.get_udt_details(&udt))
            return emit_typedef_or_other(ti, name);

        const std::set<int>* accessed = nullptr;
        const bool trim_active = options_.trim_unreferenced && !udt.is_union;
        if (trim_active) {
            auto it = used_offsets_.find(name);
            if (it != used_offsets_.end() && !it->second.empty())
                accessed = &it->second;
        }
        if (trim_active && accessed == nullptr)
            return {};

        std::set<int> keep_indices;
        if (accessed != nullptr) {
            for (std::size_t i = 0; i < udt.size(); ++i) {
                const udm_t& member = udt[i];
                const int offset = static_cast<int>(member.offset / 8);
                int size = static_cast<int>(member.size / 8);
                if (size == 0)
                    size = 1;
                auto lower = accessed->lower_bound(offset);
                if (lower != accessed->end() && *lower < offset + size)
                    keep_indices.insert(static_cast<int>(i));
            }
            if (keep_indices.empty()) {
                std::ostringstream blob;
                blob << (udt.is_union ? "union" : "struct") << ' ' << name
                     << " // sizeof=" << hex_size(udt.total_size)
                     << " (opaque: no fields accessed)\n"
                     << "{\n"
                     << "    __int8 _pad_0[0x" << std::hex << udt.total_size
                     << std::dec << "];  // no fields accessed\n"
                     << "};\n";
                return blob.str();
            }
        } else {
            for (std::size_t i = 0; i < udt.size(); ++i)
                keep_indices.insert(static_cast<int>(i));
        }

        std::ostringstream output;
        output << (udt.is_union ? "union" : "struct") << ' ' << name;
        if (options_.size_comments || accessed != nullptr)
            output << " // sizeof=" << hex_size(udt.total_size);
        if (accessed != nullptr) {
            output << " (trimmed: " << keep_indices.size()
                   << "/" << udt.size() << " members)";
        }
        output << "\n{\n";

        struct Line {
            std::string declaration;
            std::uint64_t byte_offset{0};
            std::uint64_t byte_size{0};
            bool is_bitfield{false};
            int bit_offset{0};
            int bit_size{0};
            bool emit_comment{false};
            bool is_padding{false};
        };

        std::vector<Line> lines;
        std::size_t max_length = 0;

        auto add_line = [&](Line line) {
            max_length = std::max(max_length, line.declaration.size());
            lines.push_back(std::move(line));
        };

        auto add_padding = [&](std::uint64_t from, std::uint64_t to) {
            if (to <= from)
                return;
            const std::uint64_t bytes = to - from;
            char buffer[80];
            if (bytes == 1) {
                qsnprintf(buffer, sizeof(buffer),
                          "    __int8 _pad_%llX;",
                          static_cast<unsigned long long>(from));
            } else {
                qsnprintf(buffer, sizeof(buffer),
                          "    __int8 _pad_%llX[0x%llX];",
                          static_cast<unsigned long long>(from),
                          static_cast<unsigned long long>(bytes));
            }
            Line line;
            line.declaration = buffer;
            line.byte_offset = from;
            line.byte_size = bytes;
            line.is_padding = true;
            line.emit_comment = options_.size_comments || accessed != nullptr;
            add_line(std::move(line));
        };

        auto add_member = [&](const udm_t& member) {
            Line line;
            line.declaration = print_member_decl(member);
            line.is_bitfield = member.is_bitfield();
            if (line.is_bitfield) {
                line.byte_offset = member.offset / 8;
                line.bit_offset = static_cast<int>(member.offset % 8);
                line.bit_size = static_cast<int>(member.size);
            } else {
                line.byte_offset = member.offset / 8;
                line.byte_size = member.size / 8;
            }
            line.emit_comment = options_.size_comments;
            add_line(std::move(line));
        };

        if (accessed != nullptr) {
            std::uint64_t cursor = 0;
            for (int index : keep_indices) {
                const udm_t& member = udt[static_cast<std::size_t>(index)];
                const std::uint64_t offset = member.offset / 8;
                if (offset > cursor)
                    add_padding(cursor, offset);
                add_member(member);
                std::uint64_t end = offset + (member.is_bitfield() ? 0 : (member.size / 8));
                if (member.is_bitfield())
                    end = (member.offset + member.size + 7) / 8;
                cursor = std::max(cursor, end);
            }
            if (cursor < udt.total_size)
                add_padding(cursor, udt.total_size);
        } else {
            for (std::size_t i = 0; i < udt.size(); ++i)
                add_member(udt[i]);
        }

        for (const auto& line : lines) {
            output << line.declaration;
            if (line.emit_comment) {
                output << std::string(max_length - line.declaration.size() + 1, ' ');
                if (line.is_padding) {
                    output << "// off=" << hex_size(line.byte_offset)
                           << " size=" << hex_size(line.byte_size)
                           << " (padding)";
                } else if (line.is_bitfield) {
                    output << "// off=" << hex_size(line.byte_offset)
                           << " bits=" << line.bit_offset
                           << ".." << (line.bit_offset + line.bit_size - 1);
                } else {
                    output << "// off=" << hex_size(line.byte_offset)
                           << " size=" << hex_size(line.byte_size);
                }
            }
            output << '\n';
        }

        output << "};\n";
        return output.str();
    }

    std::string emit_enum(const tinfo_t& ti, const std::string& name) {
        return print_type_decl(ti,
                               name.c_str(),
                               PRTYPE_MULTI | PRTYPE_DEF | PRTYPE_TYPE | PRTYPE_SEMI);
    }

    std::string emit_typedef_or_other(const tinfo_t& ti, const std::string& name) {
        return print_type_decl(ti,
                               name.c_str(),
                               PRTYPE_MULTI | PRTYPE_DEF | PRTYPE_TYPE | PRTYPE_SEMI);
    }

    TypeRenderOptions options_;
    std::map<std::string, std::set<int>> used_offsets_;
};

class TypeGraphRenderer {
public:
    explicit TypeGraphRenderer(const TypeGraphOptions& options) : options_(options) {}

    std::string render(std::string_view root_name) {
        nodes_.clear();
        seen_.clear();

        tinfo_t root;
        if (!tinfo_from_name(root_name, &root))
            return {};

        walk(root, 0);
        if (nodes_.empty())
            return {};

        return options_.mode == TypeGraphOptions::Mode::Table ? emit_table() : emit_simple();
    }

private:
    struct FieldEdge {
        std::string field_name;
        int field_index{0};
        std::string target_name;
        std::string field_type_text;
    };

    struct Node {
        std::string name;
        tinfo_t type;
        std::vector<FieldEdge> edges;
    };

    static tinfo_t resolve_named(const tinfo_t& ti) {
        tinfo_t current = ti;
        int hops = 0;
        while (hops++ < 16 && current.present()) {
            if (current.is_ptr()) {
                current = current.get_pointed_object();
                continue;
            }
            if (current.is_array()) {
                current = current.get_array_element();
                continue;
            }
            if (!type_name(current).empty())
                return current;
            return tinfo_t();
        }
        return tinfo_t();
    }

    void walk(const tinfo_t& ti, int depth) {
        if (!ti.present())
            return;
        if (options_.max_depth >= 0 && depth > options_.max_depth)
            return;

        std::string name = type_name(ti);
        if (name.empty() || !seen_.insert(name).second)
            return;

        if (ti.is_enum() && !options_.include_enums)
            return;
        if (ti.is_typedef() && !options_.include_typedefs)
            return;

        Node node;
        node.name = name;
        node.type = ti;

        if (ti.is_udt()) {
            udt_type_data_t udt;
            if (ti.get_udt_details(&udt)) {
                for (std::size_t i = 0; i < udt.size(); ++i) {
                    const udm_t& member = udt[i];
                    tinfo_t target = resolve_named(member.type);
                    std::string target_name = type_name(target);
                    if (target_name.empty() || target_name == name)
                        continue;
                    if (target.is_enum() && !options_.include_enums)
                        continue;
                    if (target.is_typedef() && !options_.include_typedefs)
                        continue;

                    FieldEdge edge;
                    edge.field_name = member.name.empty()
                        ? std::string("(anon)")
                        : ida::detail::to_string(member.name);
                    edge.field_index = static_cast<int>(i);
                    edge.target_name = target_name;
                    edge.field_type_text = print_type_decl(member.type, nullptr, PRTYPE_1LINE);
                    if (!edge.field_type_text.empty() && edge.field_type_text.back() == ';')
                        edge.field_type_text.pop_back();
                    node.edges.push_back(std::move(edge));
                }
            }
        }

        nodes_.push_back(std::move(node));

        for (const auto& edge : nodes_.back().edges) {
            if (seen_.count(edge.target_name) != 0)
                continue;
            tinfo_t target;
            if (!tinfo_from_name(edge.target_name, &target))
                continue;
            walk(target, depth + 1);
        }
    }

    static std::string sanitize_id(const std::string& name) {
        std::string output;
        output.reserve(name.size() + 2);
        output += "n_";
        for (char c : name) {
            if ((c >= '0' && c <= '9')
                || (c >= 'A' && c <= 'Z')
                || (c >= 'a' && c <= 'z')) {
                output.push_back(c);
            } else {
                output.push_back('_');
            }
        }
        return output;
    }

    static std::string html_escape(const std::string& text) {
        std::string output;
        output.reserve(text.size());
        for (char c : text) {
            switch (c) {
            case '<': output += "&lt;"; break;
            case '>': output += "&gt;"; break;
            case '&': output += "&amp;"; break;
            case '"': output += "&quot;"; break;
            default: output.push_back(c); break;
            }
        }
        return output;
    }

    static const char* kind_of(const tinfo_t& ti) {
        if (ti.is_enum())
            return "enum";
        if (ti.is_typedef())
            return "typedef";
        if (ti.is_udt())
            return "udt";
        return "type";
    }

    static const char* fill_for(const tinfo_t& ti) {
        if (ti.is_enum())
            return "lightyellow";
        if (ti.is_typedef())
            return "lightgray";
        if (ti.is_udt()) {
            udt_type_data_t udt;
            if (ti.get_udt_details(&udt) && udt.is_union)
                return "mistyrose";
            return "lightblue";
        }
        return "white";
    }

    std::string emit_simple() const {
        std::ostringstream output;
        output << "digraph types {\n";
        output << "    rankdir=LR;\n";
        output << "    node  [shape=box, fontname=\"Courier\", fontsize=10];\n";
        output << "    edge  [fontname=\"Courier\", fontsize=8];\n\n";

        for (const Node& node : nodes_) {
            output << "    " << sanitize_id(node.name) << " [label=\"" << node.name
                   << "\\n[" << kind_of(node.type) << "]\"";
            output << " style=filled fillcolor=" << fill_for(node.type);
            output << "];\n";
        }
        output << "\n";

        std::set<std::pair<std::string, std::string>> seen_edges;
        for (const Node& node : nodes_) {
            for (const FieldEdge& edge : node.edges) {
                auto key = std::make_pair(node.name, edge.target_name);
                if (!seen_edges.insert(key).second)
                    continue;
                output << "    " << sanitize_id(node.name)
                       << " -> " << sanitize_id(edge.target_name) << ";\n";
            }
        }

        output << "}\n";
        return output.str();
    }

    std::string emit_table() const {
        std::ostringstream output;
        output << "digraph types {\n";
        output << "    rankdir=LR;\n";
        output << "    node  [shape=plain, fontname=\"Courier\", fontsize=10];\n";
        output << "    edge  [fontname=\"Courier\", fontsize=8];\n\n";

        for (const Node& node : nodes_) {
            const char* header_bg = fill_for(node.type);
            const char* kind = node.type.is_enum() ? "enum"
                : node.type.is_typedef() ? "typedef"
                : node.type.is_udt() ? "struct"
                : "type";

            if (node.type.is_udt()) {
                udt_type_data_t udt;
                if (node.type.get_udt_details(&udt) && udt.is_union)
                    kind = "union";
            }

            output << "    " << sanitize_id(node.name) << " [label=<\n"
                   << "      <TABLE BORDER=\"0\" CELLBORDER=\"1\" CELLSPACING=\"0\">\n";
            output << "        <TR><TD COLSPAN=\"2\" BGCOLOR=\""
                   << header_bg << "\"><B>" << html_escape(node.name)
                   << "</B>  <FONT POINT-SIZE=\"8\">" << kind << "</FONT></TD></TR>\n";

            if (node.type.is_udt()) {
                udt_type_data_t udt;
                if (node.type.get_udt_details(&udt)) {
                    for (std::size_t i = 0; i < udt.size(); ++i) {
                        const udm_t& member = udt[i];
                        char offset_buffer[24];
                        qsnprintf(offset_buffer, sizeof(offset_buffer), "0x%llX",
                                  static_cast<unsigned long long>(member.offset / 8));
                        qstring type_text;
                        member.type.print(&type_text, nullptr, PRTYPE_1LINE);
                        output << "        <TR>";
                        output << "<TD ALIGN=\"RIGHT\"><FONT POINT-SIZE=\"8\">"
                               << offset_buffer << "</FONT></TD>";
                        output << "<TD ALIGN=\"LEFT\" PORT=\"f" << i << "\">"
                               << html_escape(type_text.c_str())
                               << " <B>" << html_escape(member.name.empty()
                                   ? "(anon)"
                                   : member.name.c_str())
                               << "</B></TD>";
                        output << "</TR>\n";
                    }
                }
            } else if (node.type.is_enum()) {
                enum_type_data_t enum_data;
                if (node.type.get_enum_details(&enum_data)) {
                    std::size_t shown = 0;
                    for (std::size_t i = 0; i < enum_data.size() && shown < 12; ++i, ++shown) {
                        const edm_t& item = enum_data[i];
                        char value_buffer[32];
                        qsnprintf(value_buffer, sizeof(value_buffer), "0x%llX",
                                  static_cast<unsigned long long>(item.value));
                        output << "        <TR><TD ALIGN=\"RIGHT\"><FONT POINT-SIZE=\"8\">"
                               << value_buffer << "</FONT></TD><TD ALIGN=\"LEFT\">"
                               << html_escape(item.name.c_str())
                               << "</TD></TR>\n";
                    }
                    if (enum_data.size() > 12) {
                        output << "        <TR><TD COLSPAN=\"2\" ALIGN=\"LEFT\">"
                               << "<I>... " << (enum_data.size() - 12)
                               << " more</I></TD></TR>\n";
                    }
                }
            }

            output << "      </TABLE>\n    >];\n\n";
        }

        for (const Node& node : nodes_) {
            for (const FieldEdge& edge : node.edges) {
                output << "    " << sanitize_id(node.name) << ":f" << edge.field_index
                       << " -> " << sanitize_id(edge.target_name) << ";\n";
            }
        }

        output << "}\n";
        return output.str();
    }

    TypeGraphOptions options_;
    std::vector<Node> nodes_;
    std::set<std::string> seen_;
};

} // anonymous namespace

Result<std::string> render_named_declarations(const std::vector<std::string>& names,
                                              int max_depth,
                                              const TypeRenderOptions& options) {
    TypeDeclarationFormatter formatter(options);
    return formatter.render_named(names, max_depth);
}

Result<std::string> render_ordinal_declarations(const std::vector<std::uint32_t>& ordinals,
                                                const TypeRenderOptions& options) {
    if (!options.size_comments && !options.trim_unreferenced) {
        ordvec_t sdk_ordinals;
        for (std::uint32_t ordinal : ordinals) {
            if (ordinal != 0)
                sdk_ordinals.push_back(static_cast<uint32>(ordinal));
        }

        if (!sdk_ordinals.empty()) {
            StringSink sink;
            (void)::print_decls(sink, nullptr, &sdk_ordinals, PDF_INCL_DEPS | PDF_DEF_FWD);
            if (!sink.output.empty()) {
                std::string text = ida::detail::to_string(sink.output);
                if (text.empty() || text.back() != '\n')
                    text.push_back('\n');
                return text;
            }
        }
    }

    TypeDeclarationFormatter formatter(options);
    return formatter.render_ordinals(ordinals);
}

Result<std::string> render_type_graph(std::string_view root_name,
                                      const TypeGraphOptions& options) {
    TypeGraphRenderer renderer(options);
    std::string dot = renderer.render(root_name);
    if (dot.empty())
        return std::unexpected(Error::not_found("Type graph root not found",
                                                std::string(root_name)));
    return dot;
}

Result<std::vector<TypeDeclaration>>
declarations_for_ordinals(const std::vector<std::uint32_t>& ordinals) {
    std::vector<TypeDeclaration> result;
    std::set<std::string> seen;

    std::function<void(const tinfo_t&)> walk;
    walk = [&](const tinfo_t& ti) {
        if (!ti.present())
            return;
        if (ti.is_ptr()) {
            walk(ti.get_pointed_object());
            return;
        }
        if (ti.is_array()) {
            walk(ti.get_array_element());
            return;
        }
        if (ti.is_func()) {
            func_type_data_t function_data;
            if (ti.get_func_details(&function_data)) {
                walk(function_data.rettype);
                for (std::size_t i = 0; i < function_data.size(); ++i)
                    walk(function_data[i].type);
            }
            return;
        }

        std::string name = type_name(ti);
        if (name.empty() || !seen.insert(name).second)
            return;

        if (ti.is_udt()) {
            udt_type_data_t udt;
            if (ti.get_udt_details(&udt)) {
                for (std::size_t i = 0; i < udt.size(); ++i)
                    walk(udt[i].type);
            }
        }

        TypeDeclaration declaration;
        declaration.ordinal = ti.get_ordinal();
        declaration.name = name;
        declaration.declaration = print_type_decl(
            ti,
            name.c_str(),
            PRTYPE_MULTI | PRTYPE_DEF | PRTYPE_TYPE | PRTYPE_SEMI);
        result.push_back(std::move(declaration));
    };

    for (std::uint32_t ordinal : ordinals) {
        tinfo_t ti;
        if (tinfo_from_ordinal(ordinal, &ti))
            walk(ti);
    }

    return result;
}

} // namespace ida::type

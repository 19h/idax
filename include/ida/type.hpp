/// \file type.hpp
/// \brief Type system: construction, introspection, and application.

#ifndef IDAX_TYPE_HPP
#define IDAX_TYPE_HPP

#include <ida/error.hpp>
#include <ida/address.hpp>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace ida::type {

// Forward declaration so Member can reference TypeInfo.
class TypeInfo;
struct FunctionArgument;
struct FunctionDetails;
struct UdtDetails;
struct EnumDetails;

enum class CallingConvention {
    Unknown,
    Cdecl,
    Stdcall,
    Pascal,
    Fastcall,
    Thiscall,
    Swift,
    Golang,
    UserDefined,
};

enum class TypeKind {
    Unknown,
    Void,
    Bool,
    Character,
    SignedInteger,
    UnsignedInteger,
    FloatingPoint,
    Pointer,
    Array,
    Function,
    Struct,
    Union,
    Enum,
    Typedef,
};

enum class EnumRadix {
    Unknown,
    Binary,
    Octal,
    Decimal,
    Hexadecimal,
};

struct EnumMember {
    std::string name;
    std::uint64_t value{0};
    std::string comment;
};

struct ParseDeclarationsOptions {
    bool suppress_warnings{false};
    bool relaxed_namespaces{false};
    bool raw_argument_names{false};
    bool no_mangle{false};
    std::size_t pack_alignment{0};  ///< 0=default, otherwise one of 1,2,4,8,16.
};

struct ParseDeclarationsReport {
    std::size_t error_count{0};

    [[nodiscard]] bool ok() const noexcept { return error_count == 0; }
};

struct UsedMemberOffsets {
    std::string type_name;
    std::vector<int> byte_offsets;
};

struct TypeRenderOptions {
    bool size_comments{false};
    bool trim_unreferenced{false};
    std::vector<UsedMemberOffsets> used_offsets;
};

struct TypeGraphOptions {
    enum class Mode {
        Simple,
        Table,
    };

    Mode mode{Mode::Simple};
    int max_depth{-1};
    bool include_enums{true};
    bool include_typedefs{true};
};

struct TypeDeclaration {
    std::uint32_t ordinal{0};
    std::string name;
    std::string declaration;
};

/// Opaque handle representing a type in the IDA database.
/// This class is movable, copyable, and cheap to construct for primitives.
class TypeInfo {
public:
    TypeInfo();
    ~TypeInfo();
    TypeInfo(const TypeInfo&);
    TypeInfo& operator=(const TypeInfo&);
    TypeInfo(TypeInfo&&) noexcept;
    TypeInfo& operator=(TypeInfo&&) noexcept;

    // ── Factory constructors ────────────────────────────────────────────
    static TypeInfo void_type();
    static TypeInfo int8();
    static TypeInfo int16();
    static TypeInfo int32();
    static TypeInfo int64();
    static TypeInfo uint8();
    static TypeInfo uint16();
    static TypeInfo uint32();
    static TypeInfo uint64();
    static TypeInfo float32();
    static TypeInfo float64();

    static TypeInfo pointer_to(const TypeInfo& target);
    static TypeInfo array_of(const TypeInfo& element, std::size_t count);
    static Result<TypeInfo> function_type(const TypeInfo& return_type,
                                          const std::vector<TypeInfo>& argument_types = {},
                                          CallingConvention calling_convention = CallingConvention::Unknown,
                                          bool has_varargs = false);
    static Result<TypeInfo> enum_type(const std::vector<EnumMember>& members,
                                      std::size_t byte_width = 4,
                                      bool bitmask = false);
    static Result<TypeInfo> from_declaration(std::string_view c_decl);

    /// Create an empty struct type.
    static TypeInfo create_struct();

    /// Create an empty union type.
    static TypeInfo create_union();

    /// Lookup a named type in the local type library.
    static Result<TypeInfo> by_name(std::string_view name);

    // ── Introspection ───────────────────────────────────────────────────
    [[nodiscard]] bool is_void()           const;
    [[nodiscard]] bool is_integer()        const;
    [[nodiscard]] bool is_floating_point() const;
    [[nodiscard]] bool is_pointer()        const;
    [[nodiscard]] bool is_array()          const;
    [[nodiscard]] bool is_function()       const;
    [[nodiscard]] bool is_struct()         const;
    [[nodiscard]] bool is_union()          const;
    [[nodiscard]] bool is_enum()           const;
    [[nodiscard]] bool is_typedef()        const;
    [[nodiscard]] bool is_bool()           const;
    [[nodiscard]] bool is_char()           const;
    [[nodiscard]] bool is_unsigned_char()  const;
    [[nodiscard]] bool is_signed()         const;

    [[nodiscard]] TypeKind kind() const;
    [[nodiscard]] Result<std::string> name() const;

    [[nodiscard]] Result<std::size_t> size() const;
    [[nodiscard]] Result<std::string> to_string() const;
    [[nodiscard]] Result<std::string> declaration(std::string_view declarator_name = {}) const;

    /// For pointer types, return the pointee type.
    [[nodiscard]] Result<TypeInfo> pointee_type() const;

    /// For array types, return the array element type.
    [[nodiscard]] Result<TypeInfo> array_element_type() const;

    /// For array types, return the number of elements.
    [[nodiscard]] Result<std::size_t> array_length() const;

    /// Resolve one or more typedef links to the final target type.
    /// If this type is not a typedef, returns an unchanged copy.
    [[nodiscard]] Result<TypeInfo> resolve_typedef() const;

    [[nodiscard]] Result<TypeInfo> function_return_type() const;
    [[nodiscard]] Result<std::vector<TypeInfo>> function_argument_types() const;
    [[nodiscard]] Result<FunctionDetails> function_details() const;
    [[nodiscard]] Result<CallingConvention> calling_convention() const;
    [[nodiscard]] Result<bool> is_variadic_function() const;
    [[nodiscard]] Result<std::vector<EnumMember>> enum_members() const;
    [[nodiscard]] Result<EnumDetails> enum_details() const;

    /// Number of struct/union members (0 for non-UDT types).
    [[nodiscard]] Result<std::size_t> member_count() const;

    // ── Struct/union member access (declared below, after Member) ───────

    /// Retrieve all members of a struct/union.
    [[nodiscard]] Result<std::vector<struct Member>> members() const;

    /// Retrieve complete struct/union layout details.
    [[nodiscard]] Result<UdtDetails> udt_details() const;

    /// Find a member by name.
    [[nodiscard]] Result<struct Member> member_by_name(std::string_view name) const;

    /// Find a member by byte offset.
    [[nodiscard]] Result<struct Member> member_by_offset(std::size_t byte_offset) const;

    /// Add a member to this struct/union type. Offset in bytes.
    Status add_member(std::string_view name, const TypeInfo& member_type,
                      std::size_t byte_offset = 0);

    // ── Application ─────────────────────────────────────────────────────

    /// Apply this type at the given address.
    Status apply(Address ea) const;

    /// Save this type to the local type library under the given name.
    Status save_as(std::string_view name) const;

    // ── Internal (opaque pimpl) ─────────────────────────────────────────
    struct Impl;

private:
    friend struct TypeInfoAccess;
    Impl* impl_{nullptr};
};

/// A struct/union member descriptor (pure value, no SDK types).
/// Defined after TypeInfo so it can hold a TypeInfo by value.
struct Member {
    std::string name;
    TypeInfo    type;
    std::size_t byte_offset{0};  ///< Offset from struct start, in bytes.
    std::size_t bit_size{0};     ///< Total size in bits.
    std::size_t bit_offset{0};    ///< Offset from struct start, in bits.
    std::size_t storage_byte_width{0}; ///< Bitfield backing storage width; 0 for non-bitfields.
    bool is_baseclass{false};
    bool is_vftable{false};
    bool is_gap{false};
    bool is_bitfield{false};
    std::string comment;
};

struct FunctionArgument {
    std::string name;
    TypeInfo type;
};

struct FunctionDetails {
    TypeInfo return_type;
    std::vector<FunctionArgument> arguments;
    CallingConvention calling_convention{CallingConvention::Unknown};
    bool variadic{false};
};

struct UdtDetails {
    std::size_t total_size{0};
    bool is_union{false};
    bool is_cpp_object{false};
    bool is_vftable{false};
    std::vector<Member> members;
};

struct EnumDetails {
    std::size_t byte_width{0};
    bool signed_values{false};
    EnumRadix radix{EnumRadix::Unknown};
    std::vector<EnumMember> members;
};

/// Retrieve the type applied at an address.
Result<TypeInfo> retrieve(Address ea);

/// Retrieve the type of an operand at an address.
Result<TypeInfo> retrieve_operand(Address ea, int operand_index);

/// Remove type information at an address.
Status remove_type(Address ea);

// ── Type library access ─────────────────────────────────────────────────

/// Load a type library (.til file) and add it to the database's type library list.
/// IDA will also apply function prototypes for matching function names.
/// @param til_name  Name of the .til file (without path; e.g. "mssdk_win7").
/// @return true on success.
Result<bool> load_type_library(std::string_view til_name);

/// Remove a previously loaded type library from the database.
Status unload_type_library(std::string_view til_name);

/// Get the number of local types in the database.
Result<std::size_t> local_type_count();

/// Get the name of a local type by its ordinal number (1-based).
Result<std::string> local_type_name(std::size_t ordinal);

/// Copy a named type from a loaded type library to the local type library.
/// @param source_til_name  Name of the source til (e.g. "mssdk_win7").
///                         If empty, searches all loaded tils.
/// @param type_name  Name of the type to import.
/// @return The ordinal assigned in the local type library.
Result<std::size_t> import_type(std::string_view source_til_name,
                                 std::string_view type_name);

/// Ensure a named type exists in the local type library and return it.
///
/// If the type is already present, this returns it directly.
/// Otherwise this imports it from `source_til_name` (or searches all loaded
/// type libraries when `source_til_name` is empty), then resolves it again.
Result<TypeInfo> ensure_named_type(std::string_view type_name,
                                   std::string_view source_til_name = {});

/// Apply a named type from the local type library at an address.
/// Equivalent to looking up the type by name and calling apply().
Status apply_named_type(Address ea, std::string_view type_name);

/// Parse and import a block of local type declarations into the current IDB.
///
/// This wraps IDA's bulk declaration parser for workflows that need to import
/// ordered type-definition blocks rather than parse one standalone TypeInfo.
Result<ParseDeclarationsReport>
parse_declarations(std::string_view declarations,
                   const ParseDeclarationsOptions& options = ParseDeclarationsOptions{});

/// Render named local types plus dependencies as C declarations.
Result<std::string> render_named_declarations(
    const std::vector<std::string>& names,
    int max_depth = -1,
    const TypeRenderOptions& options = TypeRenderOptions{});

/// Render local type ordinals plus dependencies as C declarations.
Result<std::string> render_ordinal_declarations(
    const std::vector<std::uint32_t>& ordinals,
    const TypeRenderOptions& options = TypeRenderOptions{});

/// Render a Graphviz DOT type dependency graph rooted at a named type.
Result<std::string> render_type_graph(std::string_view root_name,
                                      const TypeGraphOptions& options = TypeGraphOptions{});

/// Return dependency-ordered declarations for types reachable from ordinals.
Result<std::vector<TypeDeclaration>>
declarations_for_ordinals(const std::vector<std::uint32_t>& ordinals);

} // namespace ida::type

#endif // IDAX_TYPE_HPP

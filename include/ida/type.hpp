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

struct EnumMember {
    std::string name;
    std::uint64_t value{0};
    std::string comment;
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

    // â•”"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•" Factory constructors â•”"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•
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

    // â•”"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â• Introspection â•”"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•
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

    [[nodiscard]] Result<std::size_t> size() const;
    [[nodiscard]] Result<std::string> to_string() const;

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
    [[nodiscard]] Result<CallingConvention> calling_convention() const;
    [[nodiscard]] Result<bool> is_variadic_function() const;
    [[nodiscard]] Result<std::vector<EnumMember>> enum_members() const;

    /// Number of struct/union members (0 for non-UDT types).
    [[nodiscard]] Result<std::size_t> member_count() const;

    // â•”"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â• Struct/union member access (declared below, after Member) â•”"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•

    /// Retrieve all members of a struct/union.
    [[nodiscard]] Result<std::vector<struct Member>> members() const;

    /// Find a member by name.
    [[nodiscard]] Result<struct Member> member_by_name(std::string_view name) const;

    /// Find a member by byte offset.
    [[nodiscard]] Result<struct Member> member_by_offset(std::size_t byte_offset) const;

    /// Add a member to this struct/union type. Offset in bytes.
    Status add_member(std::string_view name, const TypeInfo& member_type,
                      std::size_t byte_offset = 0);

    // â•”"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â• Application â•”"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•

    /// Apply this type at the given address.
    Status apply(Address ea) const;

    /// Save this type to the local type library under the given name.
    Status save_as(std::string_view name) const;

    // â•”"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â• Internal (opaque pimpl) â•”"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•
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
    std::string comment;
};

/// Retrieve the type applied at an address.
Result<TypeInfo> retrieve(Address ea);

/// Retrieve the type of an operand at an address.
Result<TypeInfo> retrieve_operand(Address ea, int operand_index);

/// Remove type information at an address.
Status remove_type(Address ea);

// â•”"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â• Type library access â•”"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•"â•

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

/// Entry returned when iterating named types over multiple type libraries.
/// Contains the type name and the library it belongs to.
struct NamedTypeEntry {
    std::string name;
    std::string library_name;
};

// ============================================================================
/// TIL Base Iterator - iterate over all TIL bases (root + base tils)
// ============================================================================

/// Entry returned when iterating over TIL bases.
struct TilEntry {
    std::string name;   ///< TIL library name
    void* til;           ///< Raw til_t* pointer (opaque)
};

class TilBaseIterator {
public:
    using iterator_category = std::input_iterator_tag;
    using value_type = TilEntry;
    using difference_type = std::ptrdiff_t;
    using pointer = const TilEntry*;
    using reference = const TilEntry&;

    TilBaseIterator() = default;
    ~TilBaseIterator();
    TilBaseIterator(const TilBaseIterator&);
    TilBaseIterator& operator=(const TilBaseIterator&);

    TilBaseIterator& operator++();
    TilBaseIterator operator++(int);
    reference operator*() const;
    pointer operator->() const;
    bool operator==(const TilBaseIterator&) const;
    bool operator!=(const TilBaseIterator&) const;

    struct Impl;
    Impl* impl_{nullptr};

private:
    friend struct TilBaseAccess;
};

class TilBaseRange {
public:
    TilBaseRange() = default;
    ~TilBaseRange();
    TilBaseRange(const TilBaseRange&);
    TilBaseRange& operator=(const TilBaseRange&);

    TilBaseIterator begin() const;
    TilBaseIterator end() const;

    struct Impl;
    Impl* impl_{nullptr};

private:
    friend struct TilBaseAccess;
};

/// Get all TIL bases (root til + all base tils).
/// Returns a range that iterates over each TIL library.
Result<TilBaseRange> all_tils();

// ============================================================================
/// TIL Type Iterator - iterate over type names in a single TIL
// ============================================================================

class TILTypeIterator {
public:
    using iterator_category = std::input_iterator_tag;
    using value_type = std::string;
    using difference_type = std::ptrdiff_t;
    using pointer = const std::string*;
    using reference = const std::string&;

    TILTypeIterator() = default;
    ~TILTypeIterator();
    TILTypeIterator(const TILTypeIterator&);
    TILTypeIterator& operator=(const TILTypeIterator&);

    TILTypeIterator& operator++();
    TILTypeIterator operator++(int);
    reference operator*() const;
    pointer operator->() const;
    bool operator==(const TILTypeIterator&) const;
    bool operator!=(const TILTypeIterator&) const;

    struct Impl;
    Impl* impl_{nullptr};

private:
    friend struct TILTypeAccess;
};

class TILTypeRange {
public:
    TILTypeRange() = default;
    ~TILTypeRange();
    TILTypeRange(const TILTypeRange&);
    TILTypeRange& operator=(const TILTypeRange&);

    TILTypeIterator begin() const;
    TILTypeIterator end() const;

    struct Impl;
    Impl* impl_{nullptr};

private:
    friend struct TILTypeAccess;
};

/// Get named types from a specific TIL.
/// @param til  Raw til_t* pointer (from all_tils() or get_idati())
/// @param flags  Combination of NTF_* flags (e.g., NTF_TYPE | NTF_FUNC)
Result<TILTypeRange> named_types_in(void* til, int flags);

/// Get named types from a TIL by name.
/// @param til_name  Name of the TIL library
/// @param flags  Combination of NTF_* flags (e.g., NTF_TYPE | NTF_FUNC)
Result<TILTypeRange> named_types_in(std::string_view til_name, int flags);

// ============================================================================
/// Named Type Iterator - iterate over types across all TILs (existing API)
// ============================================================================

class NamedTypeIterator {
public:
    using iterator_category = std::input_iterator_tag;
    using value_type = NamedTypeEntry;
    using difference_type = std::ptrdiff_t;
    using pointer = const NamedTypeEntry*;
    using reference = const NamedTypeEntry&;

    NamedTypeIterator() = default;
    ~NamedTypeIterator();
    NamedTypeIterator(const NamedTypeIterator&);
    NamedTypeIterator& operator=(const NamedTypeIterator&);

    NamedTypeIterator& operator++();
    NamedTypeIterator operator++(int);
    reference operator*() const;
    pointer operator->() const;
    bool operator==(const NamedTypeIterator&) const;
    bool operator!=(const NamedTypeIterator&) const;

    struct Impl;
    Impl* impl_{nullptr};

private:
    friend struct NamedTypeAccess;
};

class NamedTypeRange {
public:
    NamedTypeRange() = default;
    ~NamedTypeRange();
    NamedTypeRange(const NamedTypeRange&);
    NamedTypeRange& operator=(const NamedTypeRange&);

    NamedTypeIterator begin() const;
    NamedTypeIterator end() const;

    struct Impl;
    Impl* impl_{nullptr};

private:
    friend struct NamedTypeAccess;
};

Result<NamedTypeRange> named_types();
Result<NamedTypeRange> named_types(std::string_view til_name);
Result<NamedTypeRange> named_types(std::string_view til_name, int flags);

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

} // namespace ida::type

#endif // IDAX_TYPE_HPP

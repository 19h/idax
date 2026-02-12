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

    [[nodiscard]] Result<std::size_t> size() const;
    [[nodiscard]] Result<std::string> to_string() const;

    /// Number of struct/union members (0 for non-UDT types).
    [[nodiscard]] Result<std::size_t> member_count() const;

    // ── Struct/union member access (declared below, after Member) ───────

    /// Retrieve all members of a struct/union.
    [[nodiscard]] Result<std::vector<struct Member>> members() const;

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
    std::string comment;
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

/// Apply a named type from the local type library at an address.
/// Equivalent to looking up the type by name and calling apply().
Status apply_named_type(Address ea, std::string_view type_name);

} // namespace ida::type

#endif // IDAX_TYPE_HPP

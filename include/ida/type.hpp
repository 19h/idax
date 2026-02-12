/// \file type.hpp
/// \brief Type system: construction, introspection, and application.

#ifndef IDAX_TYPE_HPP
#define IDAX_TYPE_HPP

#include <ida/error.hpp>
#include <ida/address.hpp>
#include <cstdint>
#include <string>
#include <string_view>

namespace ida::type {

/// Opaque handle wrapping the SDK's tinfo_t.
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

    // ── Application ─────────────────────────────────────────────────────
    Status apply(Address ea) const;

    // ── Internal (opaque pimpl) ─────────────────────────────────────────
    struct Impl;
    Impl* impl() const { return impl_; }

private:
    Impl* impl_{nullptr};
};

} // namespace ida::type

#endif // IDAX_TYPE_HPP

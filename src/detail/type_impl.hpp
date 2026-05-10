/// \file type_impl.hpp
/// \brief Internal: TypeInfo::Impl definition shared across implementation files.
///
/// This header is PRIVATE to idax. It must never be included from public headers.
/// It exposes the pimpl innards so that other .cpp files (e.g. function.cpp)
/// can access the underlying tinfo_t without fragile memory tricks.

#ifndef IDAX_DETAIL_TYPE_IMPL_HPP
#define IDAX_DETAIL_TYPE_IMPL_HPP

#include "sdk_bridge.hpp"
#include <ida/type.hpp>

namespace ida::type {

/// The hidden implementation of TypeInfo — wraps a SDK tinfo_t.
struct TypeInfo::Impl {
    tinfo_t ti;

    Impl() = default;
    explicit Impl(const tinfo_t& t) : ti(t) {}
};

/// Accessor to reach into TypeInfo's pimpl from other idax translation units.
struct TypeInfoAccess {
    static TypeInfo::Impl* get(TypeInfo& ti) { return ti.impl_; }
    static const TypeInfo::Impl* get(const TypeInfo& ti) { return ti.impl_; }
};

struct NamedTypeIterator::Impl {
    til_t* root_til;              // Root til (get_idati())
    int flags;
    std::string current_name;      // Current type name
    std::string current_library;   // Library name for current entry
    std::size_t base_index;      // Current base index (0 = root til)
    std::size_t base_count;       // Total number of bases

    Impl(til_t* root, int f) : root_til(root), flags(f), base_index(0), base_count(0) {}
};

struct NamedTypeRange::Impl {
    til_t* root_til;
    int flags;
    std::size_t base_count;       // Total number of bases

    Impl(til_t* root, int f) : root_til(root), flags(f), base_count(0) {}
};

struct NamedTypeAccess {
    static NamedTypeIterator::Impl*& get(NamedTypeIterator& it) { return it.impl_; }
    static const NamedTypeIterator::Impl* get(const NamedTypeIterator& it) { return it.impl_; }
    static NamedTypeRange::Impl*& get(NamedTypeRange& r) { return r.impl_; }
    static const NamedTypeRange::Impl* get(const NamedTypeRange& r) { return r.impl_; }
};

// ============================================================================
/// TilBaseIterator and TilBaseRange implementation
// ============================================================================

struct TilBaseIterator::Impl {
    til_t* root_til;           // Root til (get_idati())
    std::size_t base_index;    // Current base index (0 = root til, 1 = base[0], etc.)
    std::size_t base_count;    // Total number of bases
    std::string current_name;  // Current TIL name

    Impl(til_t* root, std::size_t count)
        : root_til(root), base_index(0), base_count(count) {}
};

struct TilBaseRange::Impl {
    til_t* root_til;           // Root til (get_idati())
    std::size_t base_count;    // Total number of bases

    Impl(til_t* root, std::size_t count)
        : root_til(root), base_count(count) {}
};

struct TilBaseAccess {
    static TilBaseIterator::Impl*& get(TilBaseIterator& it) { return it.impl_; }
    static const TilBaseIterator::Impl* get(const TilBaseIterator& it) { return it.impl_; }
    static TilBaseRange::Impl*& get(TilBaseRange& r) { return r.impl_; }
    static const TilBaseRange::Impl* get(const TilBaseRange& r) { return r.impl_; }
};

// ============================================================================
/// TILTypeIterator and TILTypeRange implementation
// ============================================================================

struct TILTypeIterator::Impl {
    til_t* til;                // The TIL to iterate
    int flags;                 // NTF_TYPE | NTF_FUNC
    std::string current_name;  // Current type name

    Impl(til_t* t, int f) : til(t), flags(f) {}
};

struct TILTypeRange::Impl {
    til_t* til;                // The TIL to iterate
    int flags;                 // NTF_TYPE | NTF_FUNC

    Impl(til_t* t, int f) : til(t), flags(f) {}
};

struct TILTypeAccess {
    static TILTypeIterator::Impl*& get(TILTypeIterator& it) { return it.impl_; }
    static const TILTypeIterator::Impl* get(const TILTypeIterator& it) { return it.impl_; }
    static TILTypeRange::Impl*& get(TILTypeRange& r) { return r.impl_; }
    static const TILTypeRange::Impl* get(const TILTypeRange& r) { return r.impl_; }
};

} // namespace ida::type

#endif // IDAX_DETAIL_TYPE_IMPL_HPP

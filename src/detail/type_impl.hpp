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

} // namespace ida::type

#endif // IDAX_DETAIL_TYPE_IMPL_HPP

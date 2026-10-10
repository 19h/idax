#pragma once

// Hex-Rays availability and cexpr_t::m reads for one binary on IDA 9.4 and 9.5.
//
// Include after <hexrays.hpp>. codedump builds this library with
// CODEDUMP_HEXRAYS_ABI and teaches the probe both handshake magics. A standalone
// idax build keeps init_hexrays_plugin() and the SDK's reading of m.

#include <cstdint>

#if defined(CODEDUMP_HEXRAYS_ABI)
#include "common/hexrays_handshake.hpp"
#endif

namespace ida::detail {

[[nodiscard]] inline bool probe_hexrays(int flags = 0) {
#if defined(CODEDUMP_HEXRAYS_ABI)
    return codedump::hexrays::handshake(flags);
#else
    return init_hexrays_plugin(flags);
#endif
}

// Byte offset of a cot_memref/cot_memptr. Under CODEDUMP_HEXRAYS_ABI this
// follows the layout the handshake accepted; otherwise it is the SDK field.
[[nodiscard]] inline std::uint64_t decompiler_member_byte_offset(const cexpr_t& expr) {
#if defined(CODEDUMP_HEXRAYS_ABI)
    return codedump::hexrays::member_byte_offset(expr);
#else
    return static_cast<std::uint64_t>(expr.m);
#endif
}

} // namespace ida::detail

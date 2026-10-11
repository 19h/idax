#pragma once

// Hex-Rays availability and cexpr_t::m reads for one binary on IDA 9.4 and 9.5.
//
// Include after <hexrays.hpp>. codedump builds this library with
// CODEDUMP_HEXRAYS_ABI and teaches the probe both handshake magics. A standalone
// idax build keeps init_hexrays_plugin() and the SDK's reading of m.

#include <cstdint>
#include <cstring>
#include <optional>

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

struct DecompilerMemberLocation {
    std::uint64_t value;
    bool bitfield;
};

// m shares an eight-byte union slot with pointers in both supported ABIs.
// Read its runtime width before interpreting units: loading SDK 940's uint32
// field first would irreversibly discard the upper half on runtime 950.
[[nodiscard]] inline std::optional<DecompilerMemberLocation>
decompiler_member_location(const cexpr_t& expr) {
#if defined(CODEDUMP_HEXRAYS_ABI)
    const auto layout = codedump::hexrays::layout();
    static_assert(sizeof(expr.y) == sizeof(std::uint64_t));
    // y names the full pointer-sized union slot; do not ask memcpy to read
    // eight bytes from the SDK 940 declaration's four-byte m subobject.
    if (layout == codedump::hexrays_abi::DecompilerLayout::V95) {
        std::uint64_t value;
        std::memcpy(&value, &expr.y, sizeof(value));
        return DecompilerMemberLocation{value, (expr.exflags & 0x0400) != 0};
    }
    if (layout == codedump::hexrays_abi::DecompilerLayout::V94) {
        std::uint32_t value;
        std::memcpy(&value, &expr.y, sizeof(value));
        return DecompilerMemberLocation{value, false};
    }
    return std::nullopt;
#else
#if IDA_SDK_VERSION == 950
    static_assert(sizeof(expr.m) == sizeof(std::uint64_t));
    static_assert(EXFL_BITFIELD == 0x0400);
    return DecompilerMemberLocation{expr.m, (expr.exflags & EXFL_BITFIELD) != 0};
#else
    static_assert(IDA_SDK_VERSION == 940);
    static_assert(sizeof(expr.m) == sizeof(std::uint32_t));
    return DecompilerMemberLocation{expr.m, false};
#endif
#endif
}

} // namespace ida::detail

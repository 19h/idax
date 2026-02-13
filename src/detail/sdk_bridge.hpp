/// \file sdk_bridge.hpp
/// \brief Internal adapter utilities between idax public types and the IDA SDK.
///
/// This header is PRIVATE to idax. It must never be included from public headers.
/// It pulls in SDK headers and provides conversion helpers.

#ifndef IDAX_DETAIL_SDK_BRIDGE_HPP
#define IDAX_DETAIL_SDK_BRIDGE_HPP

// ── C++20/23 compatibility shim ─────────────────────────────────────────
// The IDA SDK (pro.h) uses std::is_pod<T> without including <type_traits>.
// Ensure the header is included before pro.h so std::is_pod is visible.
#include <functional>
#include <locale>
#include <vector>
#include <type_traits>

// ── IDA SDK headers ─────────────────────────────────────────────────────
// Order matters: pro.h must come first.
#include <pro.h>
#include <ida.hpp>
#include <idp.hpp>
#include <auto.hpp>
#include <bytes.hpp>
#include <diskio.hpp>
#include <entry.hpp>
#include <fixup.hpp>
#include <frame.hpp>
#include <funcs.hpp>
#include <idalib.hpp>
#include <kernwin.hpp>
#include <lines.hpp>
#include <loader.hpp>
#include <name.hpp>
#include <nalt.hpp>
#include <netnode.hpp>
#include <offset.hpp>
#include <search.hpp>
#include <segregs.hpp>
#include <segment.hpp>
#include <typeinf.hpp>
#include <ua.hpp>
#include <xref.hpp>
#include <graph.hpp>
#include <gdl.hpp>

// ── idax public types (so we can convert to/from them) ──────────────────
#include <ida/error.hpp>
#include <ida/address.hpp>

#include <string>

namespace ida::detail {

// ── String conversion ───────────────────────────────────────────────────

/// Convert qstring to std::string.
inline std::string to_string(const qstring& qs) {
    return std::string(qs.c_str(), qs.length());
}

/// Convert std::string_view to a temporary qstring.
inline qstring to_qstring(std::string_view sv) {
    return qstring(sv.data(), sv.size());
}

// ── Address validation ──────────────────────────────────────────────────

/// Check if an ea_t result is valid (not BADADDR).
inline bool is_valid(ea_t ea) {
    return ea != BADADDR;
}

// ── Bitness conversion ──────────────────────────────────────────────────

/// Convert SDK bitness code (0/1/2) to human-readable bits (16/32/64).
inline int bitness_to_bits(int sdk_bitness) {
    switch (sdk_bitness) {
        case 0:  return 16;
        case 1:  return 32;
        case 2:  return 64;
        default: return 0;
    }
}

/// Convert human-readable bits (16/32/64) to SDK bitness code (0/1/2).
inline int bits_to_bitness(int bits) {
    switch (bits) {
        case 16: return 0;
        case 32: return 1;
        case 64: return 2;
        default: return -1;
    }
}

} // namespace ida::detail

#endif // IDAX_DETAIL_SDK_BRIDGE_HPP

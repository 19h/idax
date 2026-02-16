/// \file lifter_port_plugin.cpp
/// \brief idax-first port probe of `/Users/int/dev/lifter`.
///
/// This plugin ports the lifter plugin shell (actions + pseudocode popup
/// integration + decompiler snapshot reporting) onto idax APIs and records
/// the remaining parity gaps needed for a full AVX/VMX microcode lifter port.

#include <ida/idax.hpp>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdio>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <vector>

namespace {

template <typename... Args>
std::string fmt(const char* pattern, Args&&... args) {
    char buffer[4096];
    std::snprintf(buffer, sizeof(buffer), pattern, std::forward<Args>(args)...);
    return buffer;
}

std::string error_text(const ida::Error& error) {
    if (error.context.empty()) {
        return error.message;
    }
    return error.message + " (" + error.context + ")";
}

constexpr std::string_view kPluginMenuPath = "Edit/Plugins/";
constexpr const char* kActionDumpSnapshot = "idax:lifter_port:dump_snapshot";
constexpr const char* kActionMarkInline = "idax:lifter_port:mark_inline";
constexpr const char* kActionMarkOutline = "idax:lifter_port:mark_outline";
constexpr const char* kActionShowGaps = "idax:lifter_port:show_gaps";
constexpr const char* kActionToggleDebug = "idax:lifter_port:toggle_debug";

constexpr std::array<const char*, 5> kActionIds{
    kActionDumpSnapshot,
    kActionMarkInline,
    kActionMarkOutline,
    kActionShowGaps,
    kActionToggleDebug,
};

struct PortState {
    bool actions_registered{false};
    bool debug_printing{false};
    std::unordered_set<std::string> popup_titles;
    std::vector<ida::ui::ScopedSubscription> ui_subscriptions;
    ida::decompiler::ScopedMicrocodeFilter vmx_filter;
    ida::decompiler::ScopedSubscription maturity_subscription;
};

PortState g_state;

bool is_pseudocode_widget_title(std::string_view title) {
    return title.find("Pseudocode") != std::string_view::npos;
}

std::string lower_copy(std::string text) {
    std::transform(text.begin(),
                   text.end(),
                   text.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return text;
}

int infer_operand_byte_width(const ida::instruction::Instruction& instruction,
                             std::size_t operand_index,
                             int fallback);
ida::decompiler::MicrocodeCallOptions vmx_call_options();
ida::decompiler::MicrocodeCallOptions compare_call_options(std::string_view mnemonic_lower);
std::string integer_type_declaration(int byte_width, bool unsigned_integer);
std::string floating_type_declaration(int byte_width);
std::string vector_type_declaration(int byte_width, bool is_integer, bool is_double);
ida::decompiler::MicrocodeValueLocation register_return_location(int register_id);
ida::decompiler::MicrocodeValue register_argument(int register_id,
                                                  int byte_width,
                                                  bool unsigned_integer);
ida::decompiler::MicrocodeValue pointer_argument(int register_id);
ida::decompiler::MicrocodeOperand register_destination_operand(int register_id,
                                                               int byte_width);
std::optional<ida::decompiler::MicrocodeOperand> global_destination_operand(
    const ida::instruction::Instruction& instruction,
    std::size_t operand_index,
    int fallback_byte_width);

/// SSE passthrough mnemonics — return NotHandled so IDA handles them natively.
/// These are VEX-encoded forms of instructions that IDA's default microcode generator
/// handles better than our lifter (flag-setting compares, extract-to-GPR, GPR conversions).
bool is_sse_passthrough_mnemonic(std::string_view mnemonic_lower) {
    static const std::unordered_set<std::string> kPassthrough{
        "vcomiss", "vcomisd", "vucomiss", "vucomisd",
        "vpextrb", "vpextrw", "vpextrd", "vpextrq",
        "vcvttss2si", "vcvttsd2si", "vcvtsd2si", "vcvtsi2ss", "vcvtsi2sd",
    };
    return kPassthrough.contains(std::string(mnemonic_lower));
}

/// K-register manipulation mnemonics — emit NOP since Hex-Rays microcode has no
/// native k-register support. The original lifter emits NOP for NN_kmovw..NN_kunpckdq.
bool is_k_register_manipulation_mnemonic(std::string_view mnemonic_lower) {
    if (mnemonic_lower.starts_with("kmov")
        || mnemonic_lower.starts_with("kadd")
        || mnemonic_lower.starts_with("kand")
        || mnemonic_lower.starts_with("kor")
        || mnemonic_lower.starts_with("kxor")
        || mnemonic_lower.starts_with("kxnor")
        || mnemonic_lower.starts_with("knot")
        || mnemonic_lower.starts_with("kshift")
        || mnemonic_lower.starts_with("kunpck")
        || mnemonic_lower.starts_with("ktest")) {
        return true;
    }
    return false;
}

/// Check if an instruction is a compare-to-mask (k-register destination).
/// The original lifter emits NOP for these since Hex-Rays can't represent mask-register
/// destinations natively. Our port already handles vcmp*/vpcmp* via the compare variadic
/// path, so this catches the remaining integer compare-to-mask forms.
bool is_mask_destination_mnemonic(std::string_view mnemonic_lower,
                                  const ida::instruction::Instruction& instruction) {
    auto op0 = instruction.operand(0);
    if (!op0) return false;
    return op0->is_mask_register();
}

bool is_packed_helper_misc_mnemonic(std::string_view mnemonic_lower) {
    if (mnemonic_lower.starts_with("vgather")
        || mnemonic_lower.starts_with("vpgather")
        || mnemonic_lower.starts_with("vscatter")
        || mnemonic_lower.starts_with("vpscatter")
        || mnemonic_lower.starts_with("vcompress")
        || mnemonic_lower.starts_with("vexpand")
        || mnemonic_lower.starts_with("vpcompress")
        || mnemonic_lower.starts_with("vpexpand")
        || mnemonic_lower.starts_with("vpopcnt")
        || mnemonic_lower.starts_with("vplzcnt")
        || mnemonic_lower.starts_with("vgf2")
        || mnemonic_lower.starts_with("vpclmul")
        || mnemonic_lower.starts_with("vaes")
        || mnemonic_lower.starts_with("sha")
        || mnemonic_lower.starts_with("vmovmsk")
        || mnemonic_lower.starts_with("vmovnt")
        || mnemonic_lower.starts_with("vpmov")
        || mnemonic_lower.starts_with("vpinsr")
        || mnemonic_lower.starts_with("vextractps")
        || mnemonic_lower.starts_with("vinsertps")
        || mnemonic_lower.starts_with("vphsub")
        || mnemonic_lower.starts_with("vpack")
        || mnemonic_lower.starts_with("vpbroadcast")
        || mnemonic_lower.starts_with("vfmaddsub")
        || mnemonic_lower.starts_with("vfmsubadd")
        || mnemonic_lower.starts_with("vfmadd")
        || mnemonic_lower.starts_with("vfmsub")
        || mnemonic_lower.starts_with("vfnmadd")
        || mnemonic_lower.starts_with("vfnmsub")
        || mnemonic_lower.starts_with("vpunpck")
        || mnemonic_lower.starts_with("vpmadd52")
        || mnemonic_lower.starts_with("vpdpbusd")
        || mnemonic_lower.starts_with("vpdpwssd")
        || mnemonic_lower.starts_with("vdpbf16")
        || mnemonic_lower.starts_with("vcvtne2ps2bf16")
        || mnemonic_lower.starts_with("vcvtneps2bf16")
        || mnemonic_lower.starts_with("vfcmulcph")
        || mnemonic_lower.starts_with("vfmulcph")
        || mnemonic_lower.starts_with("vfcmaddcph")
        || mnemonic_lower.starts_with("vfmaddcph")) {
        return true;
    }

    static const std::unordered_set<std::string> kSupported{
        // dot product
        "vdpps",
        // reciprocal / rsqrt (packed)
        "vrcpps", "vrsqrtps", "vrcp14ps", "vrsqrt14ps", "vrcp14pd", "vrsqrt14pd",
        // reciprocal / rsqrt (scalar)
        "vrcpss", "vrsqrtss", "vrcp14ss", "vrsqrt14ss", "vrcp14sd", "vrsqrt14sd",
        // rounding (packed + scalar)
        "vroundps", "vroundpd", "vrndscaleps", "vrndscalepd",
        "vroundss", "vroundsd", "vrndscaless", "vrndscalesd",
        // getexp / getmant (packed + scalar)
        "vgetexpps", "vgetexppd", "vgetexpss", "vgetexpsd",
        "vgetmantps", "vgetmantpd", "vgetmantss", "vgetmantsd",
        // fixupimm (packed + scalar)
        "vfixupimmps", "vfixupimmpd", "vfixupimmss", "vfixupimmsd",
        // scalef (packed + scalar)
        "vscalefps", "vscalefpd", "vscalefss", "vscalefsd",
        // range (packed + scalar)
        "vrangeps", "vrangepd", "vrangess", "vrangesd",
        // reduce (packed + scalar)
        "vreduceps", "vreducepd", "vreducess", "vreducesd",
        // broadcast
        "vbroadcastss", "vbroadcastsd", "vbroadcastf128", "vbroadcasti128",
        "vbroadcastf32x4", "vbroadcastf64x4", "vbroadcasti32x4", "vbroadcasti64x4",
        // extract / insert (128-bit lane)
        "vextractf128", "vextracti128", "vextracti32x4", "vextracti32x8", "vextracti64x4",
        "vinsertf128", "vinserti128", "vinserti32x4", "vinserti32x8", "vinserti64x4",
        "vinsertf32x4", "vinsertf64x4",
        // movdup
        "vmovshdup", "vmovsldup", "vmovddup",
        // unpack float
        "vunpckhps", "vunpcklps", "vunpckhpd", "vunpcklpd",
        // maskmov
        "vmaskmovps", "vmaskmovpd",
        // align
        "vpalignr", "valignd", "valignq",
        // permute
        "vpermb", "vpermw", "vpermt2b", "vpermt2w", "vpermt2d", "vpermt2q", "vpermt2ps", "vpermt2pd",
        "vpermpd",
        // ternary logic / conflict
        "vpternlogd", "vpternlogq", "vpconflictd", "vpconflictq",
        // integer d/q moves — handled by dedicated handler, not here
        // "vmovd", "vmovq",
        // byte shift
        "vpslldq", "vpsrldq",
        // SAD
        "vpsadbw", "vmpsadbw", "vdbpsadbw",
        // packed minmax integer
        "vpminsb", "vpminsw", "vpminsd", "vpminsq",
        "vpminub", "vpminuw", "vpminud", "vpminuq",
        "vpmaxsb", "vpmaxsw", "vpmaxsd", "vpmaxsq",
        "vpmaxub", "vpmaxuw", "vpmaxud", "vpmaxuq",
        // avg
        "vpavgb", "vpavgw",
        // abs
        "vpabsb", "vpabsw", "vpabsd", "vpabsq",
        // sign
        "vpsignb", "vpsignw", "vpsignd",
        // additional integer multiply
        "vpmulhw", "vpmulhuw", "vpmuldq", "vpmaddubsw", "vpmulhrsw",
        // multishift
        "vpmultishiftqb",
        // cache control
        "clflushopt", "clwb",
        // shuffle
        "vpshufb", "vpshufd", "vpshufhw", "vpshuflw",
        // vperm2
        "vperm2f128", "vperm2i128",
        // shuf float
        "vshufps", "vshufpd",
        // FP16 packed math
        "vaddph", "vsubph", "vmulph", "vdivph", "vminph", "vmaxph",
        // FP16 scalar math
        "vaddsh", "vsubsh", "vmulsh", "vdivsh", "vminsh", "vmaxsh",
        // FP16 sqrt
        "vsqrtph", "vsqrtsh",
        // FP16 FMA
        "vfmadd132ph", "vfmadd213ph", "vfmadd231ph",
        "vfmadd132sh", "vfmadd213sh", "vfmadd231sh",
        // FP16 fmaddsub
        "vfmaddsub132ph", "vfmaddsub213ph", "vfmaddsub231ph",
        "vfmsubadd132ph", "vfmsubadd213ph", "vfmsubadd231ph",
        // FP16 moves
        "vmovsh", "vmovw",
        // FP16 getexp / getmant / reduce / rndscale / scalef
        "vgetexpph", "vgetmantph", "vreduceph", "vrndscaleph", "vscalefph",
        // FP16 reciprocal
        "vrcpph", "vrsqrtph",
        // FP16 conversions
        "vcvtpd2ph", "vcvtph2pd", "vcvtph2psx", "vcvtps2phx",
        "vcvtph2w", "vcvttph2w", "vcvtph2uw", "vcvttph2uw",
        "vcvtw2ph", "vcvtuw2ph",
    };
    return kSupported.contains(std::string(mnemonic_lower));
}

bool is_supported_vmx_mnemonic(std::string_view mnemonic) {
    static const std::unordered_set<std::string> kSupported{
        "vzeroupper",
        "vmxon", "vmxoff", "vmcall", "vmlaunch", "vmresume",
        "vmptrld", "vmptrst", "vmclear", "vmread", "vmwrite",
        "invept", "invvpid", "vmfunc",
    };
    return kSupported.contains(std::string(mnemonic));
}

bool is_supported_avx_scalar_mnemonic(std::string_view mnemonic) {
    static const std::unordered_set<std::string> kSupported{
        "vaddss", "vsubss", "vmulss", "vdivss",
        "vaddsd", "vsubsd", "vmulsd", "vdivsd",
        "vminss", "vmaxss", "vminsd", "vmaxsd",
        "vsqrtss", "vsqrtsd",
        "vcvtss2sd", "vcvtsd2ss",
        "vmovss", "vmovsd",
        // FP16 scalar (route through scalar helper path)
        "vaddsh", "vsubsh", "vmulsh", "vdivsh",
        "vminsh", "vmaxsh", "vsqrtsh",
    };
    return kSupported.contains(std::string(mnemonic));
}

bool is_supported_avx_packed_mnemonic(std::string_view mnemonic) {
    if (mnemonic.starts_with("vcmp") || mnemonic.starts_with("vpcmp")
        || mnemonic.starts_with("vpcmpeq") || mnemonic.starts_with("vpcmpgt")) {
        return true;
    }
    if (is_packed_helper_misc_mnemonic(mnemonic)) {
        return true;
    }

    static const std::unordered_set<std::string> kSupported{
        // bitwise
        "vandps", "vandpd", "vandnps", "vandnpd",
        "vorps", "vorpd", "vxorps", "vxorpd",
        "vpand", "vpandd", "vpandq", "vpandn", "vpandnd", "vpandnq",
        "vpor", "vpord", "vporq", "vpxor", "vpxord", "vpxorq",
        // blend / shuffle / permute
        "vblendps", "vblendpd", "vblendvps", "vblendvpd", "vpblendd", "vpblendw", "vpblendvb",
        "vshufps", "vshufpd", "vpermilps", "vpermilpd", "vpermq", "vpermd",
        "vperm2f128", "vperm2i128",
        // shifts / rotates
        "vpsllw", "vpslld", "vpsllq", "vpsrlw", "vpsrld", "vpsrlq",
        "vpsraw", "vpsrad", "vpsraq",
        "vpsllvw", "vpsllvd", "vpsllvq", "vpsrlvw", "vpsrlvd", "vpsrlvq",
        "vpsravw", "vpsravd", "vpsravq",
        "vprold", "vprolq", "vprord", "vprorq", "vprolvd", "vprolvq",
        "vprorvd", "vprorvq",
        "vpshldw", "vpshldd", "vpshldq", "vpshldvw", "vpshldvd", "vpshldvq",
        "vpshrdw", "vpshrdd", "vpshrdq", "vpshrdvw", "vpshrdvd", "vpshrdvq",
        "vpslldq", "vpsrldq",
        // FP math
        "vaddps", "vsubps", "vmulps", "vdivps",
        "vaddpd", "vsubpd", "vmulpd", "vdivpd",
        "vaddsubps", "vaddsubpd",
        "vhaddps", "vhaddpd", "vhsubps", "vhsubpd",
        // integer add/sub (incl. saturating)
        "vpaddb", "vpaddw", "vpaddd", "vpaddq",
        "vpsubb", "vpsubw", "vpsubd", "vpsubq",
        "vpaddsb", "vpaddsw", "vpaddusb", "vpaddusw",
        "vpsubsb", "vpsubsw", "vpsubusb", "vpsubusw",
        // integer multiply
        "vpmulld", "vpmullq", "vpmullw", "vpmuludq", "vpmaddwd",
        "vpmulhw", "vpmulhuw", "vpmuldq", "vpmaddubsw", "vpmulhrsw",
        // packed min/max FP
        "vminps", "vmaxps", "vminpd", "vmaxpd",
        // packed min/max integer
        "vpminsb", "vpminsw", "vpminsd", "vpminsq",
        "vpminub", "vpminuw", "vpminud", "vpminuq",
        "vpmaxsb", "vpmaxsw", "vpmaxsd", "vpmaxsq",
        "vpmaxub", "vpmaxuw", "vpmaxud", "vpmaxuq",
        // sqrt
        "vsqrtps", "vsqrtpd",
        // conversions
        "vcvtps2pd", "vcvtpd2ps", "vcvtdq2ps", "vcvtudq2ps",
        "vcvtdq2pd", "vcvtudq2pd",
        "vcvttps2dq", "vcvtps2dq", "vcvttpd2dq", "vcvtpd2dq",
        "vcvtps2udq", "vcvttps2udq", "vcvtpd2udq", "vcvttpd2udq",
        "vcvtpd2qq", "vcvtpd2uqq", "vcvttpd2qq", "vcvttpd2uqq",
        "vcvtps2qq", "vcvtps2uqq", "vcvttps2qq", "vcvttps2uqq",
        "vcvtqq2pd", "vcvtqq2ps", "vcvtuqq2pd", "vcvtuqq2ps",
        // FP16 conversions
        "vcvtpd2ph", "vcvtph2pd", "vcvtph2psx", "vcvtps2phx",
        "vcvtph2w", "vcvttph2w", "vcvtph2uw", "vcvttph2uw",
        "vcvtw2ph", "vcvtuw2ph",
        // moves (packed)
        "vmovaps", "vmovups", "vmovapd", "vmovupd",
        "vmovdqa", "vmovdqu", "vmovdqa32", "vmovdqa64",
        "vmovdqu8", "vmovdqu16", "vmovdqu32", "vmovdqu64",
        "vmovd", "vmovq",
        // FP16 moves
        "vmovsh", "vmovw",
        // avg / abs / sign
        "vpavgb", "vpavgw",
        "vpabsb", "vpabsw", "vpabsd", "vpabsq",
        "vpsignb", "vpsignw", "vpsignd",
        // SAD
        "vpsadbw", "vmpsadbw", "vdbpsadbw",
        // FP16 packed math
        "vaddph", "vsubph", "vmulph", "vdivph", "vminph", "vmaxph",
        // FP16 scalar math
        "vaddsh", "vsubsh", "vmulsh", "vdivsh", "vminsh", "vmaxsh",
        // FP16 sqrt
        "vsqrtph", "vsqrtsh",
        // cache control
        "clflushopt", "clwb",
    };
    return kSupported.contains(std::string(mnemonic));
}

std::optional<ida::decompiler::MicrocodeOpcode> scalar_math_opcode(std::string_view mnemonic_lower) {
    if (mnemonic_lower == "vaddss" || mnemonic_lower == "vaddsd") {
        return ida::decompiler::MicrocodeOpcode::FloatAdd;
    }
    if (mnemonic_lower == "vsubss" || mnemonic_lower == "vsubsd") {
        return ida::decompiler::MicrocodeOpcode::FloatSub;
    }
    if (mnemonic_lower == "vmulss" || mnemonic_lower == "vmulsd") {
        return ida::decompiler::MicrocodeOpcode::FloatMul;
    }
    if (mnemonic_lower == "vdivss" || mnemonic_lower == "vdivsd") {
        return ida::decompiler::MicrocodeOpcode::FloatDiv;
    }
    return std::nullopt;
}

std::optional<ida::decompiler::MicrocodeOpcode> packed_math_opcode(std::string_view mnemonic_lower) {
    if (mnemonic_lower == "vaddps" || mnemonic_lower == "vaddpd") {
        return ida::decompiler::MicrocodeOpcode::FloatAdd;
    }
    if (mnemonic_lower == "vsubps" || mnemonic_lower == "vsubpd") {
        return ida::decompiler::MicrocodeOpcode::FloatSub;
    }
    if (mnemonic_lower == "vmulps" || mnemonic_lower == "vmulpd") {
        return ida::decompiler::MicrocodeOpcode::FloatMul;
    }
    if (mnemonic_lower == "vdivps" || mnemonic_lower == "vdivpd") {
        return ida::decompiler::MicrocodeOpcode::FloatDiv;
    }
    return std::nullopt;
}

std::optional<ida::decompiler::MicrocodeOpcode> packed_integer_arithmetic_opcode(std::string_view mnemonic_lower) {
    if (mnemonic_lower == "vpaddb" || mnemonic_lower == "vpaddw"
        || mnemonic_lower == "vpaddd" || mnemonic_lower == "vpaddq") {
        return ida::decompiler::MicrocodeOpcode::Add;
    }
    if (mnemonic_lower == "vpsubb" || mnemonic_lower == "vpsubw"
        || mnemonic_lower == "vpsubd" || mnemonic_lower == "vpsubq") {
        return ida::decompiler::MicrocodeOpcode::Subtract;
    }
    return std::nullopt;
}

std::optional<ida::decompiler::MicrocodeOpcode> packed_integer_multiply_opcode(std::string_view mnemonic_lower) {
    if (mnemonic_lower == "vpmulld" || mnemonic_lower == "vpmullq") {
        return ida::decompiler::MicrocodeOpcode::Multiply;
    }
    return std::nullopt;
}

std::optional<ida::decompiler::MicrocodeOpcode> packed_conversion_opcode(std::string_view mnemonic_lower) {
    if (mnemonic_lower == "vcvtps2pd" || mnemonic_lower == "vcvtpd2ps") {
        return ida::decompiler::MicrocodeOpcode::FloatToFloat;
    }
    if (mnemonic_lower == "vcvtdq2ps" || mnemonic_lower == "vcvtudq2ps"
        || mnemonic_lower == "vcvtdq2pd" || mnemonic_lower == "vcvtudq2pd") {
        return ida::decompiler::MicrocodeOpcode::IntegerToFloat;
    }
    return std::nullopt;
}

std::optional<ida::decompiler::MicrocodeOpcode> packed_bitwise_opcode(std::string_view mnemonic_lower) {
    if (mnemonic_lower == "vandps" || mnemonic_lower == "vandpd"
        || mnemonic_lower == "vpand" || mnemonic_lower == "vpandd" || mnemonic_lower == "vpandq") {
        return ida::decompiler::MicrocodeOpcode::BitwiseAnd;
    }
    if (mnemonic_lower == "vorps" || mnemonic_lower == "vorpd"
        || mnemonic_lower == "vpor" || mnemonic_lower == "vpord" || mnemonic_lower == "vporq") {
        return ida::decompiler::MicrocodeOpcode::BitwiseOr;
    }
    if (mnemonic_lower == "vxorps" || mnemonic_lower == "vxorpd"
        || mnemonic_lower == "vpxor" || mnemonic_lower == "vpxord" || mnemonic_lower == "vpxorq") {
        return ida::decompiler::MicrocodeOpcode::BitwiseXor;
    }
    return std::nullopt;
}

std::optional<ida::decompiler::MicrocodeOpcode> packed_shift_opcode(std::string_view mnemonic_lower) {
    if (mnemonic_lower.starts_with("vpsll") || mnemonic_lower.starts_with("vpshld")) {
        return ida::decompiler::MicrocodeOpcode::ShiftLeft;
    }
    if (mnemonic_lower.starts_with("vpsrl") || mnemonic_lower.starts_with("vpshrd")) {
        return ida::decompiler::MicrocodeOpcode::ShiftRightLogical;
    }
    if (mnemonic_lower.starts_with("vpsra")) {
        return ida::decompiler::MicrocodeOpcode::ShiftRightArithmetic;
    }
    return std::nullopt;
}

bool is_packed_helper_conversion_mnemonic(std::string_view mnemonic_lower) {
    static const std::unordered_set<std::string> kSupported{
        "vcvttps2dq", "vcvtps2dq", "vcvttpd2dq", "vcvtpd2dq",
        "vcvtps2udq", "vcvttps2udq", "vcvtpd2udq", "vcvttpd2udq",
        "vcvtpd2qq", "vcvtpd2uqq", "vcvttpd2qq", "vcvttpd2uqq",
        "vcvtps2qq", "vcvtps2uqq", "vcvttps2qq", "vcvttps2uqq",
        "vcvtqq2pd", "vcvtqq2ps", "vcvtuqq2pd", "vcvtuqq2ps",
    };
    return kSupported.contains(std::string(mnemonic_lower));
}

bool is_packed_helper_addsub_mnemonic(std::string_view mnemonic_lower) {
    static const std::unordered_set<std::string> kSupported{
        "vaddsubps", "vaddsubpd",
        "vhaddps", "vhaddpd", "vhsubps", "vhsubpd",
    };
    return kSupported.contains(std::string(mnemonic_lower));
}

bool is_packed_helper_integer_arithmetic_mnemonic(std::string_view mnemonic_lower) {
    static const std::unordered_set<std::string> kSupported{
        "vpaddb", "vpaddw", "vpaddd", "vpaddq",
        "vpsubb", "vpsubw", "vpsubd", "vpsubq",
        "vpaddsb", "vpaddsw", "vpaddusb", "vpaddusw",
        "vpsubsb", "vpsubsw", "vpsubusb", "vpsubusw",
    };
    return kSupported.contains(std::string(mnemonic_lower));
}

bool is_packed_helper_integer_multiply_mnemonic(std::string_view mnemonic_lower) {
    static const std::unordered_set<std::string> kSupported{
        "vpmulld", "vpmullq", "vpmullw", "vpmuludq", "vpmaddwd",
    };
    return kSupported.contains(std::string(mnemonic_lower));
}

bool is_packed_helper_bitwise_mnemonic(std::string_view mnemonic_lower) {
    static const std::unordered_set<std::string> kSupported{
        "vandps", "vandpd", "vandnps", "vandnpd",
        "vorps", "vorpd", "vxorps", "vxorpd",
        "vpand", "vpandd", "vpandq", "vpandn", "vpandnd", "vpandnq",
        "vpor", "vpord", "vporq", "vpxor", "vpxord", "vpxorq",
    };
    return kSupported.contains(std::string(mnemonic_lower));
}

bool is_packed_helper_permute_blend_mnemonic(std::string_view mnemonic_lower) {
    static const std::unordered_set<std::string> kSupported{
        "vblendps", "vblendpd", "vblendvps", "vblendvpd", "vpblendd", "vpblendvb",
        "vshufps", "vshufpd", "vpermilps", "vpermilpd", "vpermq", "vpermd",
        "vperm2f128", "vperm2i128",
    };
    return kSupported.contains(std::string(mnemonic_lower));
}

bool is_packed_helper_shift_mnemonic(std::string_view mnemonic_lower) {
    static const std::unordered_set<std::string> kSupported{
        "vpsllw", "vpslld", "vpsllq", "vpsrlw", "vpsrld", "vpsrlq",
        "vpsraw", "vpsrad", "vpsraq",
        "vpsllvw", "vpsllvd", "vpsllvq", "vpsrlvw", "vpsrlvd", "vpsrlvq",
        "vpsravw", "vpsravd", "vpsravq",
        "vprold", "vprolq", "vprord", "vprorq", "vprolvd", "vprolvq",
        "vprorvd", "vprorvq",
        "vpshldw", "vpshldd", "vpshldq", "vpshldvw", "vpshldvd", "vpshldvq",
        "vpshrdw", "vpshrdd", "vpshrdq", "vpshrdvw", "vpshrdvd", "vpshrdvq",
    };
    return kSupported.contains(std::string(mnemonic_lower));
}

bool is_packed_helper_store_like_mnemonic(std::string_view mnemonic_lower) {
    return mnemonic_lower.starts_with("vscatter")
        || mnemonic_lower.starts_with("vpscatter")
        || mnemonic_lower.starts_with("vmaskmov")
        || mnemonic_lower.starts_with("vmovnt")
        || mnemonic_lower.starts_with("vcompress")
        || mnemonic_lower.starts_with("vpcompress");
}

/// Infer the element byte size from a mnemonic suffix for masking purposes.
/// ps/ss/ph/sh → 4-byte float, pd/sd → 8-byte double,
/// b/ub → 1-byte, w/uw → 2-byte, d/ud/dq → 4-byte, q/uq/qq → 8-byte.
int infer_element_byte_size(std::string_view mnemonic) {
    // Check common suffixes (order matters: longer suffixes first).
    if (mnemonic.ends_with("pd") || mnemonic.ends_with("sd")
        || mnemonic.ends_with("pq") || mnemonic.ends_with("qq")
        || mnemonic.ends_with("uq")) return 8;
    if (mnemonic.ends_with("ps") || mnemonic.ends_with("ss")
        || mnemonic.ends_with("ph") || mnemonic.ends_with("sh")
        || mnemonic.ends_with("dq") || mnemonic.ends_with("ud")
        || mnemonic.ends_with("ld") || mnemonic.ends_with("lq")) return 4;
    if (mnemonic.ends_with("bw") || mnemonic.ends_with("wd")
        || mnemonic.ends_with("uw") || mnemonic.ends_with("pw")
        || mnemonic.ends_with("hw") || mnemonic.ends_with("lw")) return 2;
    if (mnemonic.ends_with("pb") || mnemonic.ends_with("ub")
        || mnemonic.ends_with("qb")) return 1;
    // Default to 4-byte elements (common for packed single/dword).
    return 4;
}

/// Construct a masked intrinsic helper name.
/// "__vaddps" → "__vaddps_mask" (merge-masking) or "__vaddps_maskz" (zero-masking).
std::string masked_helper_name(std::string_view base_helper,
                               bool is_zeroing) {
    std::string result(base_helper);
    result += is_zeroing ? "_maskz" : "_mask";
    return result;
}

/// Compute the number of mask elements from a vector width and element size.
/// Used to determine the correct __mmask type width (8/16/32/64).
int mask_element_count(int vector_byte_width, int element_byte_size) {
    if (element_byte_size <= 0)
        element_byte_size = 4;
    return vector_byte_width / element_byte_size;
}

/// Return the byte width of a __mmask type for a given element count.
/// mmask8 → 1 byte, mmask16 → 2 bytes, mmask32 → 4 bytes, mmask64 → 8 bytes.
int mask_byte_width(int element_count) {
    if (element_count <= 8)  return 1;
    if (element_count <= 16) return 2;
    if (element_count <= 32) return 4;
    return 8;
}

/// Add masking arguments to a helper-call argument list.
/// For merge-masking: adds the destination register as merge-source, then the mask.
/// For zero-masking: adds only the mask.
/// The mask is passed as an unsigned immediate (k-register number).
void append_mask_arguments(std::vector<ida::decompiler::MicrocodeValue>& args,
                           const ida::decompiler::MicrocodeContext& context,
                           int destination_reg,
                           int vector_byte_width,
                           int element_byte_size) {
    const bool is_zeroing = context.is_zero_masking();
    const int kreg_num = context.opmask_register_number();
    const int num_elements = mask_element_count(vector_byte_width, element_byte_size);
    const int mask_width = mask_byte_width(num_elements);

    // For merge-masking, pass the destination register as a merge source.
    if (!is_zeroing) {
        auto merge_source = register_argument(destination_reg, vector_byte_width, false);
        merge_source.argument_name = "merge_source";
        args.push_back(merge_source);
    }

    // Pass the mask register number as an unsigned immediate.
    ida::decompiler::MicrocodeValue mask_value;
    mask_value.kind = ida::decompiler::MicrocodeValueKind::UnsignedImmediate;
    mask_value.unsigned_immediate = static_cast<std::uint64_t>(kreg_num);
    mask_value.byte_width = mask_width;
    mask_value.unsigned_integer = true;
    mask_value.argument_name = "mask";
    args.push_back(mask_value);
}

ida::Result<bool> lift_packed_helper_variadic(ida::decompiler::MicrocodeContext& context,
                                              const ida::instruction::Instruction& instruction,
                                              std::string_view mnemonic_lower) {
    const auto operand_count = instruction.operand_count();
    if (operand_count < 2) {
        return false;
    }

    auto append_argument = [&](std::vector<ida::decompiler::MicrocodeValue>& args,
                               std::size_t index,
                               int fallback_width) -> bool {
        const std::string argument_name = "operand" + std::to_string(index);
        auto operand = instruction.operand(index);
        if (!operand) {
            return false;
        }

        if (operand->is_immediate()) {
            ida::decompiler::MicrocodeValue value;
            value.kind = ida::decompiler::MicrocodeValueKind::UnsignedImmediate;
            value.unsigned_immediate = operand->value();
            int immediate_width = infer_operand_byte_width(instruction,
                                                           index,
                                                           4);
            if (immediate_width <= 0) {
                immediate_width = 4;
            }
            value.byte_width = immediate_width;
            value.unsigned_integer = true;
            value.argument_name = argument_name;
            args.push_back(value);
            return true;
        }

        auto register_value = context.load_operand_register(static_cast<int>(index));
        if (register_value) {
            const int argument_width = infer_operand_byte_width(instruction,
                                                                index,
                                                                fallback_width);
            auto value = register_argument(*register_value, argument_width, false);
            value.argument_name = argument_name;
            args.push_back(value);
            return true;
        }

        if (operand->is_memory()) {
            auto address_register = context.load_effective_address_register(static_cast<int>(index));
            if (!address_register) {
                return false;
            }
            auto value = pointer_argument(*address_register);
            value.argument_name = argument_name;
            args.push_back(value);
            return true;
        }

        return false;
    };

    const auto destination_reg = context.load_operand_register(0);
    if (!destination_reg) {
        if (mnemonic_lower.starts_with("vcmp") || mnemonic_lower.starts_with("vpcmp")) {
            const auto destination_operand = instruction.operand(0);
            if (!destination_operand) {
                return false;
            }

            const int destination_width = infer_operand_byte_width(instruction, 0, 8);

            const bool compare_has_mask = context.has_opmask();

            std::vector<ida::decompiler::MicrocodeValue> compare_args;
            compare_args.reserve(operand_count > 0 ? operand_count - 1 : 0);
            for (std::size_t index = 1; index < operand_count; ++index) {
                if (!append_argument(compare_args, index, destination_width)) {
                    return false;
                }
            }

            // Apply AVX-512 opmask masking to compare helper.
            if (compare_has_mask) {
                const int cmp_elem_size = infer_element_byte_size(mnemonic_lower);
                // For compare, destination_operand might not be a vector register
                // (could be k-register, handled by NOP path). Use destination_width
                // as the vector width for mask element count calculation.
                append_mask_arguments(compare_args, context,
                                      destination_operand->is_register()
                                          ? static_cast<int>(destination_operand->register_id())
                                          : 0,
                                      destination_width, cmp_elem_size);
            }

            const std::string compare_base_helper = "__" + std::string(mnemonic_lower);
            const std::string helper = compare_has_mask
                ? masked_helper_name(compare_base_helper, context.is_zero_masking())
                : compare_base_helper;
            auto helper_options = compare_call_options(mnemonic_lower);
            auto return_type = vector_type_declaration(destination_width, true, false);
            if (!return_type.empty()) {
                helper_options.return_type_declaration = std::move(return_type);
            }

            if (auto global_destination = global_destination_operand(instruction,
                                                                     0,
                                                                     destination_width);
                global_destination.has_value()) {
                auto global_helper_options = helper_options;
                ida::decompiler::MicrocodeValueLocation global_return_location;
                global_return_location.kind = ida::decompiler::MicrocodeValueLocationKind::StaticAddress;
                global_return_location.static_address = global_destination->global_address;
                global_helper_options.return_location = global_return_location;

                auto micro_status = context.emit_helper_call_with_arguments_to_micro_operand_and_options(
                    helper,
                    compare_args,
                    *global_destination,
                    false,
                    global_helper_options);
                if (!micro_status
                    && micro_status.error().category == ida::ErrorCategory::Validation) {
                    micro_status = context.emit_helper_call_with_arguments_to_micro_operand_and_options(
                        helper,
                        compare_args,
                        *global_destination,
                        false,
                        helper_options);
                }
                if (!micro_status
                    && micro_status.error().category == ida::ErrorCategory::Validation) {
                    micro_status = context.emit_helper_call_with_arguments_to_micro_operand_and_options(
                        helper,
                        compare_args,
                        *global_destination,
                        false,
                        compare_call_options(mnemonic_lower));
                }
                if (micro_status) {
                    return true;
                }
                if (micro_status.error().category == ida::ErrorCategory::SdkFailure
                    || micro_status.error().category == ida::ErrorCategory::Internal) {
                    return false;
                }
            }

            if (destination_operand->is_register()) {
                const int destination_register_id =
                    static_cast<int>(destination_operand->register_id());
                if (destination_register_id >= 0) {
                    ida::decompiler::MicrocodeOperand register_destination;
                    register_destination.kind = ida::decompiler::MicrocodeOperandKind::Register;
                    register_destination.register_id = destination_register_id;
                    register_destination.byte_width = destination_width;

                    auto register_helper_options = helper_options;
                    register_helper_options.return_location =
                        register_return_location(destination_register_id);

                    auto register_micro_status =
                        context.emit_helper_call_with_arguments_to_micro_operand_and_options(
                            helper,
                            compare_args,
                            register_destination,
                            false,
                            register_helper_options);
                    if (!register_micro_status
                        && register_micro_status.error().category == ida::ErrorCategory::Validation) {
                        register_micro_status =
                            context.emit_helper_call_with_arguments_to_micro_operand_and_options(
                                helper,
                                compare_args,
                                register_destination,
                                false,
                                helper_options);
                    }
                    if (!register_micro_status
                        && register_micro_status.error().category == ida::ErrorCategory::Validation) {
                        register_micro_status =
                            context.emit_helper_call_with_arguments_to_micro_operand_and_options(
                                helper,
                                compare_args,
                                register_destination,
                                false,
                                compare_call_options(mnemonic_lower));
                    }
                    if (register_micro_status) {
                        return true;
                    }
                    if (register_micro_status.error().category == ida::ErrorCategory::SdkFailure
                        || register_micro_status.error().category == ida::ErrorCategory::Internal) {
                        return false;
                    }
                }
            }

            bool unresolved_destination_shape = false;
            if (destination_operand->is_register()) {
                unresolved_destination_shape = destination_operand->is_mask_register();
            } else if (destination_operand->is_memory()) {
                unresolved_destination_shape = destination_operand->target_address() == ida::BadAddress;
            }

            if (!unresolved_destination_shape) {
                return false;
            }

            auto temporary_destination = context.allocate_temporary_register(destination_width);
            if (temporary_destination) {
                auto temporary_helper_options = helper_options;
                temporary_helper_options.return_location =
                    register_return_location(*temporary_destination);

                const auto temporary_micro_destination =
                    register_destination_operand(*temporary_destination, destination_width);

                auto temporary_helper_status =
                    context.emit_helper_call_with_arguments_to_micro_operand_and_options(
                        helper,
                        compare_args,
                        temporary_micro_destination,
                        false,
                        temporary_helper_options);
                if (!temporary_helper_status
                    && temporary_helper_status.error().category == ida::ErrorCategory::Validation) {
                    temporary_helper_status =
                        context.emit_helper_call_with_arguments_to_micro_operand_and_options(
                            helper,
                            compare_args,
                            temporary_micro_destination,
                            false,
                            helper_options);
                }
                if (!temporary_helper_status
                    && temporary_helper_status.error().category == ida::ErrorCategory::Validation) {
                    temporary_helper_status =
                        context.emit_helper_call_with_arguments_to_micro_operand_and_options(
                            helper,
                            compare_args,
                            temporary_micro_destination,
                            false,
                            compare_call_options(mnemonic_lower));
                }

                if (temporary_helper_status) {
                    auto store_status = context.store_operand_register(
                        0,
                        *temporary_destination,
                        destination_width);
                    if (store_status) {
                        return true;
                    }
                    if (store_status.error().category == ida::ErrorCategory::SdkFailure
                        || store_status.error().category == ida::ErrorCategory::Internal) {
                        return false;
                    }
                    if (store_status.error().category != ida::ErrorCategory::Validation
                        && store_status.error().category != ida::ErrorCategory::NotFound) {
                        return std::unexpected(store_status.error());
                    }
                }

                if (!temporary_helper_status
                    && (temporary_helper_status.error().category == ida::ErrorCategory::SdkFailure
                        || temporary_helper_status.error().category == ida::ErrorCategory::Internal)) {
                    return false;
                }
            }

            auto helper_status = context.emit_helper_call_with_arguments_to_operand_and_options(
                helper,
                compare_args,
                0,
                destination_width,
                false,
                helper_options);
            if (!helper_status
                && helper_status.error().category == ida::ErrorCategory::Validation) {
                helper_status = context.emit_helper_call_with_arguments_to_operand_and_options(
                    helper,
                    compare_args,
                    0,
                    destination_width,
                    false,
                    compare_call_options(mnemonic_lower));
            }
            if (!helper_status) {
                if (helper_status.error().category == ida::ErrorCategory::SdkFailure
                    || helper_status.error().category == ida::ErrorCategory::Internal
                    || helper_status.error().category == ida::ErrorCategory::Validation
                    || helper_status.error().category == ida::ErrorCategory::NotFound) {
                    return false;
                }
                return std::unexpected(helper_status.error());
            }
            return true;
        }

        if (!is_packed_helper_store_like_mnemonic(mnemonic_lower)) {
            return false;
        }

        const bool store_has_mask = context.has_opmask();

        std::vector<ida::decompiler::MicrocodeValue> store_args;
        store_args.reserve(operand_count);
        for (std::size_t index = 0; index < operand_count; ++index) {
            if (!append_argument(store_args, index, 16)) {
                return false;
            }
        }

        // Apply AVX-512 opmask masking to store-like helper.
        if (store_has_mask) {
            const int store_elem_size = infer_element_byte_size(mnemonic_lower);
            append_mask_arguments(store_args, context, 0, 16, store_elem_size);
        }

        const std::string store_base_helper = "__" + std::string(mnemonic_lower);
        const std::string helper = store_has_mask
            ? masked_helper_name(store_base_helper, context.is_zero_masking())
            : store_base_helper;
        const auto helper_options = compare_call_options(mnemonic_lower);
        auto helper_status = context.emit_helper_call_with_arguments_and_options(
            helper,
            store_args,
            helper_options);
        if (!helper_status) {
            return std::unexpected(helper_status.error());
        }
        return true;
    }

    const int destination_width = infer_operand_byte_width(instruction, 0, 16);
    const bool has_mask = context.has_opmask();

    std::vector<ida::decompiler::MicrocodeValue> args;
    args.reserve(operand_count > 0 ? operand_count - 1 : 0);

    for (std::size_t index = 1; index < operand_count; ++index) {
        if (!append_argument(args, index, destination_width)) {
            return false;
        }
    }

    // Apply AVX-512 opmask masking: modify helper name and add mask arguments.
    if (has_mask) {
        const int element_size = infer_element_byte_size(mnemonic_lower);
        append_mask_arguments(args, context, *destination_reg,
                              destination_width, element_size);
    }

    const std::string base_helper = "__" + std::string(mnemonic_lower);
    const std::string helper = has_mask
        ? masked_helper_name(base_helper, context.is_zero_masking())
        : base_helper;
    auto helper_options = compare_call_options(mnemonic_lower);
    helper_options.return_location = register_return_location(*destination_reg);
    auto return_type = vector_type_declaration(destination_width, true, false);
    if (!return_type.empty()) {
        helper_options.return_type_declaration = std::move(return_type);
    }

    auto helper_options_without_location = helper_options;
    helper_options_without_location.return_location.reset();

    auto helper_status = context.emit_helper_call_with_arguments_to_micro_operand_and_options(
        helper,
        args,
        register_destination_operand(*destination_reg, destination_width),
        false,
        helper_options);
    if (!helper_status
        && helper_status.error().category == ida::ErrorCategory::Validation) {
        helper_status = context.emit_helper_call_with_arguments_to_micro_operand_and_options(
            helper,
            args,
            register_destination_operand(*destination_reg, destination_width),
            false,
            helper_options_without_location);
    }
    if (!helper_status
        && helper_status.error().category == ida::ErrorCategory::Validation) {
        helper_status = context.emit_helper_call_with_arguments_to_micro_operand_and_options(
            helper,
            args,
            register_destination_operand(*destination_reg, destination_width),
            false,
            compare_call_options(mnemonic_lower));
    }
    if (!helper_status) {
        if (helper_status.error().category == ida::ErrorCategory::SdkFailure
            || helper_status.error().category == ida::ErrorCategory::Internal
            || helper_status.error().category == ida::ErrorCategory::Validation
            || helper_status.error().category == ida::ErrorCategory::NotFound) {
            return false;
        }
        return std::unexpected(helper_status.error());
    }
    return true;
}

int infer_operand_byte_width(const ida::instruction::Instruction& instruction,
                             std::size_t operand_index,
                             int fallback) {
    auto operand = instruction.operand(operand_index);
    if (!operand) {
        return fallback;
    }

    if (operand->byte_width() > 0) {
        return operand->byte_width();
    }

    if (operand->is_vector_register()) {
        const std::string register_name = lower_copy(operand->register_name());
        if (register_name.starts_with("zmm")) return 64;
        if (register_name.starts_with("ymm")) return 32;
        if (register_name.starts_with("xmm")) return 16;
        if (register_name.starts_with("mm")) return 8;
    }

    if (operand->is_mask_register()) {
        return 8;
    }

    return fallback;
}

int pointer_byte_width(ida::Address address) {
    auto seg = ida::segment::at(address);
    if (seg) {
        switch (seg->bitness()) {
            case 16: return 2;
            case 32: return 4;
            case 64: return 8;
            default: break;
        }
    }
    return sizeof(ida::Address) >= 8 ? 8 : 4;
}

ida::decompiler::MicrocodeCallOptions vmx_call_options() {
    ida::decompiler::MicrocodeCallOptions options;
    options.calling_convention = ida::decompiler::MicrocodeCallingConvention::Fastcall;
    options.mark_final = true;
    options.mark_propagated = true;
    options.mark_spoiled_lists_optimized = true;
    return options;
}

ida::decompiler::MicrocodeCallOptions compare_call_options(std::string_view mnemonic_lower) {
    auto options = vmx_call_options();
    if (mnemonic_lower.starts_with("vcmp") || mnemonic_lower.starts_with("vpcmp")) {
        if (mnemonic_lower.find("pd") != std::string_view::npos
            || mnemonic_lower.find("sd") != std::string_view::npos
            || mnemonic_lower.find('q') != std::string_view::npos) {
            options.function_role = ida::decompiler::MicrocodeFunctionRole::SseCompare8;
        } else if (mnemonic_lower.find("ps") != std::string_view::npos
                   || mnemonic_lower.find("ss") != std::string_view::npos
                   || mnemonic_lower.find('d') != std::string_view::npos
                   || mnemonic_lower.find('w') != std::string_view::npos
                   || mnemonic_lower.find('b') != std::string_view::npos) {
            options.function_role = ida::decompiler::MicrocodeFunctionRole::SseCompare4;
        }
    }

    if (mnemonic_lower.starts_with("vprol")) {
        options.function_role = ida::decompiler::MicrocodeFunctionRole::RotateLeft;
    } else if (mnemonic_lower.starts_with("vpror")) {
        options.function_role = ida::decompiler::MicrocodeFunctionRole::RotateRight;
    }

    return options;
}

std::string integer_type_declaration(int byte_width, bool unsigned_integer) {
    switch (byte_width) {
        case 1:
            return unsigned_integer ? "unsigned char" : "signed char";
        case 2:
            return unsigned_integer ? "unsigned short" : "short";
        case 4:
            return unsigned_integer ? "unsigned int" : "int";
        case 8:
            return unsigned_integer ? "unsigned long long" : "long long";
        default:
            return {};
    }
}

std::string floating_type_declaration(int byte_width) {
    switch (byte_width) {
        case 4:
            return "float";
        case 8:
            return "double";
        default:
            return {};
    }
}

/// Produce a vector type declaration string matching the original lifter's
/// \c get_type_robust(size, is_int, is_double) behaviour.
/// For scalar sizes (1/2/4/8) falls through to integer/float helpers.
/// For vector sizes (16/32/64) returns \c __m128 / \c __m256i / \c __m512d etc.
/// The declaration is resolved by \c parse_decl against the DB's type library
/// at emission time, which produces the same \c tinfo_t the original lifter
/// obtained via \c get_named_type.
std::string vector_type_declaration(int byte_width, bool is_integer, bool is_double) {
    // Scalar sizes — delegate.
    if (byte_width <= 8) {
        if (is_double || (!is_integer && byte_width == 8))
            return floating_type_declaration(byte_width);
        if (!is_integer && byte_width == 4)
            return floating_type_declaration(byte_width);
        return integer_type_declaration(byte_width, !is_integer);
    }
    // Vector sizes: __m128 / __m128i / __m128d etc.
    const int bit_width = byte_width * 8;
    std::string name = "__m" + std::to_string(bit_width);
    if (is_integer)
        name += 'i';
    else if (is_double)
        name += 'd';
    return name;
}

ida::decompiler::MicrocodeValueLocation register_return_location(int register_id) {
    ida::decompiler::MicrocodeValueLocation location;
    location.kind = ida::decompiler::MicrocodeValueLocationKind::Register;
    location.register_id = register_id;
    return location;
}

ida::decompiler::MicrocodeValue register_argument(int register_id,
                                                  int byte_width,
                                                  bool unsigned_integer = true) {
    ida::decompiler::MicrocodeValue value;
    value.kind = ida::decompiler::MicrocodeValueKind::Register;
    value.register_id = register_id;
    value.byte_width = byte_width;
    value.unsigned_integer = unsigned_integer;
    return value;
}

ida::decompiler::MicrocodeValue pointer_argument(int register_id) {
    ida::decompiler::MicrocodeValue value;
    value.kind = ida::decompiler::MicrocodeValueKind::Register;
    value.register_id = register_id;
    value.byte_width = 0;
    value.type_declaration = "void *";
    return value;
}

ida::decompiler::MicrocodeOperand register_destination_operand(int register_id,
                                                               int byte_width) {
    ida::decompiler::MicrocodeOperand destination;
    destination.kind = ida::decompiler::MicrocodeOperandKind::Register;
    destination.register_id = register_id;
    destination.byte_width = byte_width;
    destination.mark_user_defined_type = byte_width > 8;
    return destination;
}

std::optional<ida::decompiler::MicrocodeOperand> global_destination_operand(
    const ida::instruction::Instruction& instruction,
    std::size_t operand_index,
    int fallback_byte_width) {
    auto operand = instruction.operand(operand_index);
    if (!operand) {
        return std::nullopt;
    }
    if (!operand->is_memory() || operand->target_address() == ida::BadAddress) {
        return std::nullopt;
    }

    ida::decompiler::MicrocodeOperand destination;
    destination.kind = ida::decompiler::MicrocodeOperandKind::GlobalAddress;
    destination.global_address = operand->target_address();
    destination.byte_width = infer_operand_byte_width(instruction,
                                                      operand_index,
                                                      fallback_byte_width);
    destination.mark_user_defined_type = destination.byte_width > 8;
    return destination;
}

ida::Result<bool> try_emit_local_variable_self_move(ida::decompiler::MicrocodeContext& context,
                                                    int byte_width,
                                                    std::int64_t local_variable_offset) {
    auto local_variable_count = context.local_variable_count();
    if (!local_variable_count) {
        return std::unexpected(local_variable_count.error());
    }
    if (*local_variable_count <= 0) {
        return false;
    }

    ida::decompiler::MicrocodeInstruction local_variable_echo;
    local_variable_echo.opcode = ida::decompiler::MicrocodeOpcode::Move;
    local_variable_echo.left.kind = ida::decompiler::MicrocodeOperandKind::LocalVariable;
    local_variable_echo.left.local_variable_index = 0;
    local_variable_echo.left.local_variable_offset = local_variable_offset;
    local_variable_echo.left.byte_width = byte_width;
    local_variable_echo.destination = local_variable_echo.left;

    auto local_variable_status = context.emit_instruction(local_variable_echo);
    if (local_variable_status) {
        return true;
    }
    if (local_variable_status.error().category == ida::ErrorCategory::SdkFailure) {
        return false;
    }
    return std::unexpected(local_variable_status.error());
}

ida::Status emit_vmx_no_operand_helper(ida::decompiler::MicrocodeContext& context,
                                       std::string_view helper_name) {
    return context.emit_helper_call_with_arguments_and_options(
        helper_name,
        {},
        vmx_call_options());
}

ida::Result<bool> try_lift_vmx_instruction(ida::decompiler::MicrocodeContext& context,
                                           const ida::instruction::Instruction& instruction,
                                           std::string_view mnemonic_lower) {
    const int integer_width = pointer_byte_width(instruction.address());

    if (mnemonic_lower == "vzeroupper") {
        auto local_variable_rewrite = try_emit_local_variable_self_move(context, 1, 0);
        if (!local_variable_rewrite) {
            return std::unexpected(local_variable_rewrite.error());
        }
        if (*local_variable_rewrite) {
            return true;
        }

        auto st = context.emit_noop();
        if (!st) return std::unexpected(st.error());
        return true;
    }

    if (mnemonic_lower == "vmxoff") {
        auto local_variable_rewrite = try_emit_local_variable_self_move(context, 1, 0);
        if (!local_variable_rewrite) {
            return std::unexpected(local_variable_rewrite.error());
        }

        auto st = emit_vmx_no_operand_helper(context, "__vmxoff");
        if (!st) return std::unexpected(st.error());
        return true;
    }
    if (mnemonic_lower == "vmcall") {
        auto st = emit_vmx_no_operand_helper(context, "__vmcall");
        if (!st) return std::unexpected(st.error());
        return true;
    }
    if (mnemonic_lower == "vmlaunch") {
        auto st = emit_vmx_no_operand_helper(context, "__vmlaunch");
        if (!st) return std::unexpected(st.error());
        return true;
    }
    if (mnemonic_lower == "vmresume") {
        auto st = emit_vmx_no_operand_helper(context, "__vmresume");
        if (!st) return std::unexpected(st.error());
        return true;
    }
    if (mnemonic_lower == "vmfunc") {
        auto st = emit_vmx_no_operand_helper(context, "__vmfunc");
        if (!st) return std::unexpected(st.error());
        return true;
    }

    if (mnemonic_lower == "vmxon" || mnemonic_lower == "vmptrld"
        || mnemonic_lower == "vmclear" || mnemonic_lower == "vmptrst") {
        auto address_reg = context.load_effective_address_register(0);
        if (!address_reg) return std::unexpected(address_reg.error());

        std::vector<ida::decompiler::MicrocodeValue> args;
        auto address_argument = pointer_argument(*address_reg);
        address_argument.argument_name = "descriptor";
        args.push_back(address_argument);

        std::string helper = "__" + std::string(mnemonic_lower);
        auto st = context.emit_helper_call_with_arguments_and_options(helper,
                                                                      args,
                                                                      vmx_call_options());
        if (!st) return std::unexpected(st.error());
        return true;
    }

    if (mnemonic_lower == "vmread") {
        auto destination_operand = instruction.operand(0);
        if (!destination_operand) return std::unexpected(destination_operand.error());

        auto encoding_reg = context.load_operand_register(1);
        if (!encoding_reg) return std::unexpected(encoding_reg.error());

        if (destination_operand->type() == ida::instruction::OperandType::Register) {
            auto destination_reg = context.load_operand_register(0);
            if (!destination_reg) return std::unexpected(destination_reg.error());

            std::vector<ida::decompiler::MicrocodeValue> args;
            auto encoding_argument = register_argument(*encoding_reg, integer_width, true);
            encoding_argument.argument_name = "encoding";
            args.push_back(encoding_argument);

            auto options = vmx_call_options();
            auto return_type = integer_type_declaration(integer_width, true);
            if (!return_type.empty()) {
                options.return_type_declaration = std::move(return_type);
            }
            options.return_location = register_return_location(*destination_reg);

            auto st = context.emit_helper_call_with_arguments_to_micro_operand_and_options(
                "__vmread",
                args,
                register_destination_operand(*destination_reg, integer_width),
                true,
                options);
            if (!st) return std::unexpected(st.error());
        } else {
            auto destination_address_reg = context.load_effective_address_register(0);
            if (!destination_address_reg) return std::unexpected(destination_address_reg.error());

            std::vector<ida::decompiler::MicrocodeValue> args;
            auto destination_argument = pointer_argument(*destination_address_reg);
            destination_argument.argument_name = "destination";
            args.push_back(destination_argument);
            auto encoding_argument = register_argument(*encoding_reg, integer_width, true);
            encoding_argument.argument_name = "encoding";
            args.push_back(encoding_argument);

            auto st = context.emit_helper_call_with_arguments_and_options(
                "__vmread",
                args,
                vmx_call_options());
            if (!st) return std::unexpected(st.error());
        }
        return true;
    }

    if (mnemonic_lower == "vmwrite") {
        auto encoding_reg = context.load_operand_register(0);
        if (!encoding_reg) return std::unexpected(encoding_reg.error());
        auto source_reg = context.load_operand_register(1);
        if (!source_reg) return std::unexpected(source_reg.error());

        std::vector<ida::decompiler::MicrocodeValue> args;
        auto encoding_argument = register_argument(*encoding_reg, integer_width, true);
        encoding_argument.argument_name = "encoding";
        args.push_back(encoding_argument);
        auto source_argument = register_argument(*source_reg, integer_width, true);
        source_argument.argument_name = "value";
        args.push_back(source_argument);

        auto st = context.emit_helper_call_with_arguments_and_options(
            "__vmwrite",
            args,
            vmx_call_options());
        if (!st) return std::unexpected(st.error());
        return true;
    }

    if (mnemonic_lower == "invept" || mnemonic_lower == "invvpid") {
        auto type_reg = context.load_operand_register(0);
        if (!type_reg) return std::unexpected(type_reg.error());
        auto descriptor_address_reg = context.load_effective_address_register(1);
        if (!descriptor_address_reg) return std::unexpected(descriptor_address_reg.error());

        std::vector<ida::decompiler::MicrocodeValue> args;
        auto type_argument = register_argument(*type_reg, integer_width, true);
        type_argument.argument_name = "type";
        args.push_back(type_argument);
        auto descriptor_argument = pointer_argument(*descriptor_address_reg);
        descriptor_argument.argument_name = "descriptor";
        args.push_back(descriptor_argument);

        const char* helper = mnemonic_lower == "invept" ? "__invept" : "__invvpid";
        auto st = context.emit_helper_call_with_arguments_and_options(
            helper,
            args,
            vmx_call_options());
        if (!st) return std::unexpected(st.error());
        return true;
    }

    return false;
}

ida::Result<bool> try_lift_avx_scalar_instruction(ida::decompiler::MicrocodeContext& context,
                                                  const ida::instruction::Instruction& instruction,
                                                  std::string_view mnemonic_lower) {
    const auto operand_count = instruction.operand_count();
    if (operand_count < 2) {
        return false;
    }

    const auto destination_operand = instruction.operand(0);
    if (!destination_operand) {
        return std::unexpected(destination_operand.error());
    }

    if ((mnemonic_lower == "vmovss" || mnemonic_lower == "vmovsd")
        && operand_count == 2
        && destination_operand->is_memory()) {
        const int scalar_width = mnemonic_lower.ends_with("ss") ? 4 : 8;
        const auto source_reg = context.load_operand_register(1);
        if (!source_reg) {
            return std::unexpected(source_reg.error());
        }

        auto store_status = context.store_operand_register(0, *source_reg, scalar_width);
        if (!store_status) {
            return std::unexpected(store_status.error());
        }
        return true;
    }

    constexpr int destination_width = 16;
    const auto destination_reg = context.load_operand_register(0);
    if (!destination_reg) {
        return std::unexpected(destination_reg.error());
    }

    const auto source1_reg = context.load_operand_register(1);
    if (!source1_reg) {
        return std::unexpected(source1_reg.error());
    }

    if (*source1_reg != *destination_reg) {
        auto move_status = context.emit_move_register(*source1_reg,
                                                      *destination_reg,
                                                      destination_width);
        if (!move_status) {
            return std::unexpected(move_status.error());
        }
    }

    if (mnemonic_lower == "vmovss" || mnemonic_lower == "vmovsd") {
        const int scalar_width = mnemonic_lower.ends_with("ss") ? 4 : 8;

        if (operand_count == 2) {
            auto move_status = context.emit_move_register(*source1_reg,
                                                          *destination_reg,
                                                          scalar_width);
            if (!move_status) {
                return std::unexpected(move_status.error());
            }
            return true;
        }

        if (operand_count >= 3) {
            const auto source2_reg = context.load_operand_register(2);
            if (!source2_reg) {
                return std::unexpected(source2_reg.error());
            }

            auto scalar_move_status = context.emit_move_register(*source2_reg,
                                                                 *destination_reg,
                                                                 scalar_width);
            if (!scalar_move_status) {
                return std::unexpected(scalar_move_status.error());
            }
            return true;
        }
    }

    if (operand_count < 3) {
        return false;
    }

    const auto source2_reg = context.load_operand_register(2);
    if (!source2_reg) {
        return std::unexpected(source2_reg.error());
    }

    if (mnemonic_lower == "vcvtss2sd" || mnemonic_lower == "vcvtsd2ss") {
        const int source_width = mnemonic_lower == "vcvtss2sd" ? 4 : 8;
        const int result_width = mnemonic_lower == "vcvtss2sd" ? 8 : 4;

        ida::decompiler::MicrocodeInstruction instruction_ir;
        instruction_ir.opcode = ida::decompiler::MicrocodeOpcode::FloatToFloat;
        instruction_ir.floating_point_instruction = true;

        instruction_ir.left.kind = ida::decompiler::MicrocodeOperandKind::Register;
        instruction_ir.left.register_id = *source2_reg;
        instruction_ir.left.byte_width = source_width;

        instruction_ir.destination.kind = ida::decompiler::MicrocodeOperandKind::Register;
        instruction_ir.destination.register_id = *destination_reg;
        instruction_ir.destination.byte_width = result_width;

        auto emit_status = context.emit_instruction(instruction_ir);
        if (!emit_status) {
            return std::unexpected(emit_status.error());
        }
        return true;
    }

    if (mnemonic_lower == "vminss" || mnemonic_lower == "vmaxss"
        || mnemonic_lower == "vminsd" || mnemonic_lower == "vmaxsd"
        || mnemonic_lower == "vsqrtss" || mnemonic_lower == "vsqrtsd"
        || mnemonic_lower == "vminsh" || mnemonic_lower == "vmaxsh"
        || mnemonic_lower == "vsqrtsh"
        || mnemonic_lower == "vaddsh" || mnemonic_lower == "vsubsh"
        || mnemonic_lower == "vmulsh" || mnemonic_lower == "vdivsh") {
        const int scalar_width = mnemonic_lower.ends_with("sh") ? 2
            : mnemonic_lower.ends_with("ss") ? 4 : 8;
        const bool scalar_has_mask = context.has_opmask();

        std::vector<ida::decompiler::MicrocodeValue> args;
        if (mnemonic_lower == "vminss" || mnemonic_lower == "vmaxss"
            || mnemonic_lower == "vminsd" || mnemonic_lower == "vmaxsd") {
            auto left_argument = register_argument(*source1_reg, scalar_width, false);
            left_argument.argument_name = "left";
            args.push_back(left_argument);
        }
        auto right_argument = register_argument(*source2_reg, scalar_width, false);
        right_argument.argument_name =
            (mnemonic_lower == "vminss" || mnemonic_lower == "vmaxss"
             || mnemonic_lower == "vminsd" || mnemonic_lower == "vmaxsd")
                ? "right"
                : "source";
        args.push_back(right_argument);

        // Apply AVX-512 opmask masking to scalar helper.
        if (scalar_has_mask) {
            const int scalar_elem_size = scalar_width;
            append_mask_arguments(args, context, *destination_reg,
                                  destination_width, scalar_elem_size);
        }

        const std::string scalar_base_helper = "__" + std::string(mnemonic_lower);
        const std::string helper = scalar_has_mask
            ? masked_helper_name(scalar_base_helper, context.is_zero_masking())
            : scalar_base_helper;
        auto helper_options = compare_call_options(mnemonic_lower);
        auto return_type = floating_type_declaration(scalar_width);
        if (!return_type.empty()) {
            helper_options.return_type_declaration = std::move(return_type);
        }
        helper_options.return_location = register_return_location(*destination_reg);
        auto helper_status = context.emit_helper_call_with_arguments_to_micro_operand_and_options(
            helper,
            args,
            register_destination_operand(*destination_reg, scalar_width),
            false,
            helper_options);
        if (!helper_status) {
            return std::unexpected(helper_status.error());
        }
        return true;
    }

    const auto opcode = scalar_math_opcode(mnemonic_lower);
    if (!opcode.has_value()) {
        return false;
    }

    const int scalar_width = mnemonic_lower.ends_with("ss") ? 4 : 8;

    ida::decompiler::MicrocodeInstruction instruction_ir;
    instruction_ir.opcode = *opcode;
    instruction_ir.floating_point_instruction = true;

    instruction_ir.left.kind = ida::decompiler::MicrocodeOperandKind::Register;
    instruction_ir.left.register_id = *source1_reg;
    instruction_ir.left.byte_width = scalar_width;

    instruction_ir.right.kind = ida::decompiler::MicrocodeOperandKind::Register;
    instruction_ir.right.register_id = *source2_reg;
    instruction_ir.right.byte_width = scalar_width;

    instruction_ir.destination.kind = ida::decompiler::MicrocodeOperandKind::Register;
    instruction_ir.destination.register_id = *destination_reg;
    instruction_ir.destination.byte_width = scalar_width;

    auto emit_status = context.emit_instruction(instruction_ir);
    if (!emit_status) {
        return std::unexpected(emit_status.error());
    }
    return true;
}

ida::Result<bool> try_lift_avx_packed_instruction(ida::decompiler::MicrocodeContext& context,
                                                   const ida::instruction::Instruction& instruction,
                                                   std::string_view mnemonic_lower) {
    const auto operand_count = instruction.operand_count();
    if (operand_count < 2) {
        return false;
    }

    // When AVX-512 opmask masking is present, skip native microcode emission
    // paths (typed binary, typed conversion, typed move) and fall through to
    // helper-call paths which can express masking via modified helper names
    // and additional mask arguments. Native microcode instructions cannot
    // represent per-element masking.
    const bool packed_has_mask = context.has_opmask();

    if (mnemonic_lower.starts_with("vcmp")
        || mnemonic_lower.starts_with("vpcmp")) {
        return lift_packed_helper_variadic(context, instruction, mnemonic_lower);
    }

    // Typed conversion path: skip when masked (fall through to helper path).
    if (!packed_has_mask) {
        if (const auto conversion_opcode = packed_conversion_opcode(mnemonic_lower);
            conversion_opcode.has_value()) {
            const auto destination_reg = context.load_operand_register(0);
            if (!destination_reg) {
                return std::unexpected(destination_reg.error());
            }
            const auto source_reg = context.load_operand_register(1);
            if (!source_reg) {
                return std::unexpected(source_reg.error());
            }

            const int destination_width = infer_operand_byte_width(instruction, 0, 16);
            const int source_width = infer_operand_byte_width(instruction, 1, destination_width);

            ida::decompiler::MicrocodeInstruction instruction_ir;
            instruction_ir.opcode = *conversion_opcode;
            instruction_ir.floating_point_instruction = true;

            instruction_ir.left.kind = ida::decompiler::MicrocodeOperandKind::Register;
            instruction_ir.left.register_id = *source_reg;
            instruction_ir.left.byte_width = source_width;
            instruction_ir.left.mark_user_defined_type = source_width > 8;

            instruction_ir.destination.kind = ida::decompiler::MicrocodeOperandKind::Register;
            instruction_ir.destination.register_id = *destination_reg;
            instruction_ir.destination.byte_width = destination_width;
            instruction_ir.destination.mark_user_defined_type = destination_width > 8;

            auto emit_status = context.emit_instruction(instruction_ir);
            if (!emit_status) {
                return std::unexpected(emit_status.error());
            }
            return true;
        }
    }

    auto try_emit_typed_binary = [&](ida::decompiler::MicrocodeOpcode opcode) -> ida::Result<bool> {
        if (operand_count < 2) {
            return false;
        }

        const auto destination_reg = context.load_operand_register(0);
        if (!destination_reg) {
            return false;
        }

        int source1_register = *destination_reg;
        std::size_t source2_index = 1;
        if (operand_count >= 3) {
            const auto source1_reg = context.load_operand_register(1);
            if (!source1_reg) {
                return false;
            }
            source1_register = *source1_reg;
            source2_index = 2;
        }

        auto source2_operand = instruction.operand(source2_index);
        if (!source2_operand) {
            return false;
        }

        const int destination_width = infer_operand_byte_width(instruction, 0, 16);

        ida::decompiler::MicrocodeOperand right{};
        const auto source2_reg = context.load_operand_register(static_cast<int>(source2_index));
        if (source2_reg) {
            right.kind = ida::decompiler::MicrocodeOperandKind::Register;
            right.register_id = *source2_reg;
            right.byte_width = destination_width;
            right.mark_user_defined_type = destination_width > 8;
        } else if (source2_operand->is_immediate()) {
            right.kind = ida::decompiler::MicrocodeOperandKind::UnsignedImmediate;
            right.unsigned_immediate = source2_operand->value();
            int immediate_width = infer_operand_byte_width(instruction,
                                                           source2_index,
                                                           1);
            if (immediate_width <= 0) {
                immediate_width = 1;
            }
            right.byte_width = immediate_width;
        } else {
            return false;
        }

        ida::decompiler::MicrocodeInstruction instruction_ir;
        instruction_ir.opcode = opcode;
        instruction_ir.floating_point_instruction = false;

        instruction_ir.left.kind = ida::decompiler::MicrocodeOperandKind::Register;
        instruction_ir.left.register_id = source1_register;
        instruction_ir.left.byte_width = destination_width;
        instruction_ir.left.mark_user_defined_type = destination_width > 8;

        instruction_ir.right = right;

        instruction_ir.destination.kind = ida::decompiler::MicrocodeOperandKind::Register;
        instruction_ir.destination.register_id = *destination_reg;
        instruction_ir.destination.byte_width = destination_width;
        instruction_ir.destination.mark_user_defined_type = destination_width > 8;

        auto emit_status = context.emit_instruction(instruction_ir);
        if (!emit_status) {
            return std::unexpected(emit_status.error());
        }
        return true;
    };

    // Typed binary paths: skip when masked (fall through to helper path).
    if (!packed_has_mask) {
        if (const auto integer_opcode = packed_integer_arithmetic_opcode(mnemonic_lower);
            integer_opcode.has_value()) {
            auto emitted = try_emit_typed_binary(*integer_opcode);
            if (!emitted) {
                return std::unexpected(emitted.error());
            }
            if (*emitted) {
                return true;
            }
        }

        if (const auto integer_multiply_opcode = packed_integer_multiply_opcode(mnemonic_lower);
            integer_multiply_opcode.has_value()) {
            auto emitted = try_emit_typed_binary(*integer_multiply_opcode);
            if (!emitted) {
                return std::unexpected(emitted.error());
            }
            if (*emitted) {
                return true;
            }
        }

        if (const auto bitwise_opcode = packed_bitwise_opcode(mnemonic_lower);
            bitwise_opcode.has_value()) {
            auto emitted = try_emit_typed_binary(*bitwise_opcode);
            if (!emitted) {
                return std::unexpected(emitted.error());
            }
            if (*emitted) {
                return true;
            }
        }

        if (const auto shift_opcode = packed_shift_opcode(mnemonic_lower);
            shift_opcode.has_value()) {
            auto emitted = try_emit_typed_binary(*shift_opcode);
            if (!emitted) {
                return std::unexpected(emitted.error());
            }
            if (*emitted) {
                return true;
            }
        }
    }

    if (is_packed_helper_conversion_mnemonic(mnemonic_lower)) {
        const auto destination_reg = context.load_operand_register(0);
        if (!destination_reg) {
            return std::unexpected(destination_reg.error());
        }
        const auto source_reg = context.load_operand_register(1);
        if (!source_reg) {
            return std::unexpected(source_reg.error());
        }

        const int destination_width = infer_operand_byte_width(instruction, 0, 16);
        const int source_width = infer_operand_byte_width(instruction, 1, destination_width);
        const bool destination_unsigned = mnemonic_lower.find("udq") != std::string::npos
            || mnemonic_lower.find("uqq") != std::string::npos;

        std::vector<ida::decompiler::MicrocodeValue> args;
        auto source_argument = register_argument(*source_reg, source_width, false);
        source_argument.argument_name = "source";
        args.push_back(source_argument);

        // Apply AVX-512 opmask masking to helper-fallback conversion.
        if (packed_has_mask) {
            const int cvt_elem_size = infer_element_byte_size(mnemonic_lower);
            append_mask_arguments(args, context, *destination_reg,
                                  destination_width, cvt_elem_size);
        }

        const std::string cvt_base_helper = "__" + std::string(mnemonic_lower);
        const std::string helper = packed_has_mask
            ? masked_helper_name(cvt_base_helper, context.is_zero_masking())
            : cvt_base_helper;
        auto helper_options = vmx_call_options();
        helper_options.return_location = register_return_location(*destination_reg);
        // Conversion targets: determine float/int/double from mnemonic.
        // *2ps → float, *2pd → double, *2dq/*2udq/*2qq/*2uqq → integer.
        const bool cvt_is_double = mnemonic_lower.ends_with("pd");
        const bool cvt_is_int = !cvt_is_double && !mnemonic_lower.ends_with("ps");
        auto return_type = vector_type_declaration(destination_width, cvt_is_int, cvt_is_double);
        if (!return_type.empty()) {
            helper_options.return_type_declaration = std::move(return_type);
        }
        auto helper_status = context.emit_helper_call_with_arguments_to_micro_operand_and_options(
            helper,
            args,
            register_destination_operand(*destination_reg, destination_width),
            destination_unsigned,
            helper_options);
        if (!helper_status) {
            return std::unexpected(helper_status.error());
        }
        return true;
    }

    // vmovd / vmovq: dedicated handler using native zero-extend (m_xdu).
    // These are GPR/memory ↔ XMM moves, NOT packed vector moves.
    // GPR/memory → XMM: zero-extend data_size bytes to full XMM width.
    // XMM → GPR/memory: extract low data_size bytes.
    if (mnemonic_lower == "vmovd" || mnemonic_lower == "vmovq") {
        const int data_size = (mnemonic_lower == "vmovd") ? 4 : 8;
        const auto op0 = instruction.operand(0);
        if (!op0) return std::unexpected(op0.error());

        if (op0->is_vector_register()) {
            // GPR/memory → XMM: load source, then zero-extend to XMM width.
            const auto source_reg = context.load_operand_register(1);
            if (!source_reg) return std::unexpected(source_reg.error());
            const auto dest_reg = context.load_operand_register(0);
            if (!dest_reg) return std::unexpected(dest_reg.error());

            const int dest_width = infer_operand_byte_width(instruction, 0, 16);

            ida::decompiler::MicrocodeInstruction xdu_ir;
            xdu_ir.opcode = ida::decompiler::MicrocodeOpcode::ZeroExtend;
            xdu_ir.left.kind = ida::decompiler::MicrocodeOperandKind::Register;
            xdu_ir.left.register_id = *source_reg;
            xdu_ir.left.byte_width = data_size;
            xdu_ir.destination.kind = ida::decompiler::MicrocodeOperandKind::Register;
            xdu_ir.destination.register_id = *dest_reg;
            xdu_ir.destination.byte_width = dest_width;
            xdu_ir.destination.mark_user_defined_type = (dest_width > 8);

            auto emit_status = context.emit_instruction(xdu_ir);
            if (!emit_status) return std::unexpected(emit_status.error());
            return true;
        }

        // XMM → GPR or memory: extract low data_size bytes.
        const auto source_reg = context.load_operand_register(1);
        if (!source_reg) return std::unexpected(source_reg.error());

        if (op0->is_memory()) {
            auto store_status = context.store_operand_register(0, *source_reg, data_size);
            if (!store_status) return std::unexpected(store_status.error());
            return true;
        }

        // GPR destination.
        const auto dest_reg = context.load_operand_register(0);
        if (!dest_reg) return std::unexpected(dest_reg.error());
        auto move_status = context.emit_move_register(*source_reg, *dest_reg, data_size);
        if (!move_status) return std::unexpected(move_status.error());
        return true;
    }

    if (is_packed_helper_integer_arithmetic_mnemonic(mnemonic_lower)
        || is_packed_helper_integer_multiply_mnemonic(mnemonic_lower)
        || is_packed_helper_bitwise_mnemonic(mnemonic_lower)
        || is_packed_helper_permute_blend_mnemonic(mnemonic_lower)
        || is_packed_helper_shift_mnemonic(mnemonic_lower)
        || is_packed_helper_misc_mnemonic(mnemonic_lower)) {
        return lift_packed_helper_variadic(context, instruction, mnemonic_lower);
    }

    // Typed move path: skip when masked (fall through to helper-call via
    // lift_packed_helper_variadic which already has masking wired).
    if (!packed_has_mask && mnemonic_lower.starts_with("vmov")) {
        const auto destination_operand = instruction.operand(0);
        if (!destination_operand) {
            return std::unexpected(destination_operand.error());
        }

        const int move_width = infer_operand_byte_width(instruction, 0, 16);
        if (destination_operand->is_memory()) {
            const auto source_reg = context.load_operand_register(1);
            if (!source_reg) {
                return std::unexpected(source_reg.error());
            }
            auto store_status = context.store_operand_register(0, *source_reg, move_width);
            if (!store_status) {
                return std::unexpected(store_status.error());
            }
            return true;
        }

        const auto destination_reg = context.load_operand_register(0);
        if (!destination_reg) {
            return std::unexpected(destination_reg.error());
        }
        const auto source_reg = context.load_operand_register(1);
        if (!source_reg) {
            return std::unexpected(source_reg.error());
        }

        auto move_status = context.emit_move_register(*source_reg, *destination_reg, move_width);
        if (!move_status) {
            return std::unexpected(move_status.error());
        }
        return true;
    }

    if (mnemonic_lower == "vsqrtps" || mnemonic_lower == "vsqrtpd") {
        const int packed_width = infer_operand_byte_width(instruction, 0, 16);
        const auto destination_reg = context.load_operand_register(0);
        if (!destination_reg) {
            return std::unexpected(destination_reg.error());
        }
        const auto source_reg = context.load_operand_register(1);
        if (!source_reg) {
            return std::unexpected(source_reg.error());
        }

        std::vector<ida::decompiler::MicrocodeValue> args;
        auto source_argument = register_argument(*source_reg, packed_width, false);
        source_argument.argument_name = "source";
        args.push_back(source_argument);

        // Apply AVX-512 opmask masking to packed sqrt helper.
        if (packed_has_mask) {
            const int sqrt_elem_size = mnemonic_lower.ends_with("pd") ? 8 : 4;
            append_mask_arguments(args, context, *destination_reg,
                                  packed_width, sqrt_elem_size);
        }

        const std::string sqrt_base_helper = "__" + std::string(mnemonic_lower);
        const std::string helper = packed_has_mask
            ? masked_helper_name(sqrt_base_helper, context.is_zero_masking())
            : sqrt_base_helper;
        const bool sqrt_is_double = mnemonic_lower.ends_with("pd");
        auto helper_options = vmx_call_options();
        helper_options.return_location = register_return_location(*destination_reg);
        helper_options.return_type_declaration = vector_type_declaration(
            packed_width, false, sqrt_is_double);
        auto helper_status = context.emit_helper_call_with_arguments_to_micro_operand_and_options(
            helper,
            args,
            register_destination_operand(*destination_reg, packed_width),
            false,
            helper_options);
        if (!helper_status) {
            return std::unexpected(helper_status.error());
        }
        return true;
    }

    if (operand_count < 3) {
        return false;
    }

    if (is_packed_helper_addsub_mnemonic(mnemonic_lower)) {
        const int packed_width = infer_operand_byte_width(instruction, 0, 16);
        const auto destination_reg = context.load_operand_register(0);
        if (!destination_reg) {
            return std::unexpected(destination_reg.error());
        }
        const auto source1_reg = context.load_operand_register(1);
        if (!source1_reg) {
            return std::unexpected(source1_reg.error());
        }
        const auto source2_reg = context.load_operand_register(2);
        if (!source2_reg) {
            return std::unexpected(source2_reg.error());
        }

        std::vector<ida::decompiler::MicrocodeValue> args;
        auto left_argument = register_argument(*source1_reg, packed_width, false);
        left_argument.argument_name = "left";
        args.push_back(left_argument);
        auto right_argument = register_argument(*source2_reg, packed_width, false);
        right_argument.argument_name = "right";
        args.push_back(right_argument);

        // Apply AVX-512 opmask masking to addsub helper.
        if (packed_has_mask) {
            const int addsub_elem_size = infer_element_byte_size(mnemonic_lower);
            append_mask_arguments(args, context, *destination_reg,
                                  packed_width, addsub_elem_size);
        }

        const std::string addsub_base_helper = "__" + std::string(mnemonic_lower);
        const std::string helper = packed_has_mask
            ? masked_helper_name(addsub_base_helper, context.is_zero_masking())
            : addsub_base_helper;
        // Addsub mnemonics: vaddsubps → float, vaddsubpd → double.
        const bool addsub_is_double = mnemonic_lower.ends_with("pd");
        auto helper_options = vmx_call_options();
        helper_options.return_location = register_return_location(*destination_reg);
        helper_options.return_type_declaration = vector_type_declaration(
            packed_width, false, addsub_is_double);
        auto helper_status = context.emit_helper_call_with_arguments_to_micro_operand_and_options(
            helper,
            args,
            register_destination_operand(*destination_reg, packed_width),
            false,
            helper_options);
        if (!helper_status) {
            return std::unexpected(helper_status.error());
        }
        return true;
    }

    if (mnemonic_lower == "vminps" || mnemonic_lower == "vmaxps"
        || mnemonic_lower == "vminpd" || mnemonic_lower == "vmaxpd") {
        const int packed_width = infer_operand_byte_width(instruction, 0, 16);
        const auto destination_reg = context.load_operand_register(0);
        if (!destination_reg) {
            return std::unexpected(destination_reg.error());
        }
        const auto source1_reg = context.load_operand_register(1);
        if (!source1_reg) {
            return std::unexpected(source1_reg.error());
        }
        const auto source2_reg = context.load_operand_register(2);
        if (!source2_reg) {
            return std::unexpected(source2_reg.error());
        }

        std::vector<ida::decompiler::MicrocodeValue> args;
        auto left_argument = register_argument(*source1_reg, packed_width, false);
        left_argument.argument_name = "left";
        args.push_back(left_argument);
        auto right_argument = register_argument(*source2_reg, packed_width, false);
        right_argument.argument_name = "right";
        args.push_back(right_argument);

        // Apply AVX-512 opmask masking to packed min/max helper.
        if (packed_has_mask) {
            const int minmax_elem_size = mnemonic_lower.ends_with("pd") ? 8 : 4;
            append_mask_arguments(args, context, *destination_reg,
                                  packed_width, minmax_elem_size);
        }

        const std::string minmax_base_helper = "__" + std::string(mnemonic_lower);
        const std::string helper = packed_has_mask
            ? masked_helper_name(minmax_base_helper, context.is_zero_masking())
            : minmax_base_helper;
        const bool minmax_is_double = mnemonic_lower.ends_with("pd");
        auto helper_options = vmx_call_options();
        helper_options.return_location = register_return_location(*destination_reg);
        helper_options.return_type_declaration = vector_type_declaration(
            packed_width, false, minmax_is_double);
        auto helper_status = context.emit_helper_call_with_arguments_to_micro_operand_and_options(
            helper,
            args,
            register_destination_operand(*destination_reg, packed_width),
            false,
            helper_options);
        if (!helper_status) {
            return std::unexpected(helper_status.error());
        }
        return true;
    }

    // Typed packed math path: skip when masked (fall through returns false,
    // which causes the dispatch to try lift_packed_helper_variadic next).
    if (packed_has_mask) {
        return false;
    }

    const auto opcode = packed_math_opcode(mnemonic_lower);
    if (!opcode.has_value()) {
        return false;
    }

    const auto destination_reg = context.load_operand_register(0);
    if (!destination_reg) {
        return std::unexpected(destination_reg.error());
    }
    const auto source1_reg = context.load_operand_register(1);
    if (!source1_reg) {
        return std::unexpected(source1_reg.error());
    }
    const auto source2_reg = context.load_operand_register(2);
    if (!source2_reg) {
        return std::unexpected(source2_reg.error());
    }

    const int packed_width = infer_operand_byte_width(instruction, 0, 16);

    ida::decompiler::MicrocodeInstruction instruction_ir;
    instruction_ir.opcode = *opcode;
    instruction_ir.floating_point_instruction = true;

    instruction_ir.left.kind = ida::decompiler::MicrocodeOperandKind::Register;
    instruction_ir.left.register_id = *source1_reg;
    instruction_ir.left.byte_width = packed_width;
    instruction_ir.left.mark_user_defined_type = packed_width > 8;

    instruction_ir.right.kind = ida::decompiler::MicrocodeOperandKind::Register;
    instruction_ir.right.register_id = *source2_reg;
    instruction_ir.right.byte_width = packed_width;
    instruction_ir.right.mark_user_defined_type = packed_width > 8;

    instruction_ir.destination.kind = ida::decompiler::MicrocodeOperandKind::Register;
    instruction_ir.destination.register_id = *destination_reg;
    instruction_ir.destination.byte_width = packed_width;
    instruction_ir.destination.mark_user_defined_type = packed_width > 8;

    auto emit_status = context.emit_instruction(instruction_ir);
    if (!emit_status) {
        return std::unexpected(emit_status.error());
    }
    return true;
}

/// Check if decoded instruction has any YMM (256-bit) register operand.
/// In 32-bit mode, Hex-Rays' microcode verifier triggers INTERR 50920
/// ("Temporary registers cannot cross block boundaries") for 256-bit kregs.
/// By returning false from match(), we let IDA show these as __asm blocks.
bool has_ymm_operand(const ida::instruction::Instruction& instruction) {
    const auto count = instruction.operand_count();
    for (std::size_t i = 0; i < count; ++i) {
        auto op = instruction.operand(i);
        if (op && op->byte_width() == 32) {
            return true;
        }
    }
    return false;
}

/// Check if the current database contains 64-bit code by inspecting
/// the function at the given address. Returns true if 64-bit, false otherwise.
bool is_64bit_context(ida::Address address) {
    auto function = ida::function::at(address);
    if (function) {
        return function->bitness() == 64;
    }
    auto segment = ida::segment::at(address);
    if (segment) {
        return segment->bitness() == 64;
    }
    return true; // assume 64-bit when no context is available
}

class VmxAvxLifterFilter final : public ida::decompiler::MicrocodeFilter {
public:
    bool match(const ida::decompiler::MicrocodeContext& context) override {
        auto decoded = ida::instruction::decode(context.address());
        if (!decoded) {
            return false;
        }
        const std::string mnemonic = lower_copy(decoded->mnemonic());

        // SSE passthrough: let IDA handle these natively (GAP 4)
        if (is_sse_passthrough_mnemonic(mnemonic)) {
            return false;
        }

        // K-register manipulation: match to emit NOP (GAP 9)
        if (is_k_register_manipulation_mnemonic(mnemonic)) {
            return true;
        }

        // Mask-destination (k-register as Op0): emit NOP (GAP 9)
        if (is_mask_destination_mnemonic(mnemonic, *decoded)) {
            return true;
        }

        // Skip YMM (256-bit) operations in 32-bit mode.
        // Hex-Rays' microcode verifier causes INTERR 50920 when emitting
        // 256-bit temporaries in 32-bit mode. XMM (128-bit) works fine.
        // By returning false, IDA shows these as __asm blocks.
        if (!is_64bit_context(context.address()) && has_ymm_operand(*decoded)) {
            return false;
        }

        return is_supported_vmx_mnemonic(mnemonic)
            || is_supported_avx_scalar_mnemonic(mnemonic)
            || is_supported_avx_packed_mnemonic(mnemonic);
    }

    ida::decompiler::MicrocodeApplyResult apply(ida::decompiler::MicrocodeContext& context) override {
        auto decoded = ida::instruction::decode(context.address());
        if (!decoded) {
            return ida::decompiler::MicrocodeApplyResult::NotHandled;
        }

        const std::string mnemonic = lower_copy(decoded->mnemonic());

        // K-register manipulation instructions: emit NOP (GAP 9)
        if (is_k_register_manipulation_mnemonic(mnemonic)) {
            auto st = context.emit_noop();
            if (!st) {
                return ida::decompiler::MicrocodeApplyResult::Error;
            }
            return ida::decompiler::MicrocodeApplyResult::Handled;
        }

        // Mask-destination (compare-to-mask with k-register as Op0): emit NOP (GAP 9)
        if (is_mask_destination_mnemonic(mnemonic, *decoded)) {
            auto st = context.emit_noop();
            if (!st) {
                return ida::decompiler::MicrocodeApplyResult::Error;
            }
            return ida::decompiler::MicrocodeApplyResult::Handled;
        }

        auto lifted = try_lift_vmx_instruction(context,
                                               *decoded,
                                               mnemonic);
        if (!lifted || !*lifted) {
            lifted = try_lift_avx_scalar_instruction(context, *decoded, mnemonic);
        }
        if (!lifted || !*lifted) {
            lifted = try_lift_avx_packed_instruction(context, *decoded, mnemonic);
        }
        if (!lifted) {
            ida::ui::message(fmt("[lifter-port] subset lift failed @ %#llx: %s\n",
                                 static_cast<unsigned long long>(context.address()),
                                 error_text(lifted.error()).c_str()));
            return ida::decompiler::MicrocodeApplyResult::Error;
        }
        return *lifted
            ? ida::decompiler::MicrocodeApplyResult::Handled
            : ida::decompiler::MicrocodeApplyResult::NotHandled;
    }
};

ida::Status install_vmx_lifter_filter() {
    if (g_state.vmx_filter.valid()) {
        return ida::ok();
    }

    auto available = ida::decompiler::available();
    if (!available) {
        return std::unexpected(available.error());
    }
    if (!*available) {
        return std::unexpected(ida::Error::unsupported(
            "Hex-Rays decompiler is unavailable; VMX lifter filter is disabled"));
    }

    auto token = ida::decompiler::register_microcode_filter(std::make_shared<VmxAvxLifterFilter>());
    if (!token) {
        return std::unexpected(token.error());
    }

    g_state.vmx_filter = ida::decompiler::ScopedMicrocodeFilter(*token);
    return ida::ok();
}

ida::Result<ida::Address> resolve_action_address(const ida::plugin::ActionContext& context) {
    if (context.current_address != ida::BadAddress) {
        return context.current_address;
    }
    auto screen = ida::ui::screen_address();
    if (!screen) {
        return std::unexpected(screen.error());
    }
    return *screen;
}

ida::Status require_decompiler() {
    auto available = ida::decompiler::available();
    if (!available) {
        return std::unexpected(available.error());
    }
    if (!*available) {
        return std::unexpected(ida::Error::unsupported(
            "Hex-Rays decompiler is unavailable on this host"));
    }
    return ida::ok();
}

ida::Result<std::size_t> count_call_expressions(const ida::decompiler::DecompiledFunction& function) {
    std::size_t call_count = 0;
    auto visited = ida::decompiler::for_each_expression(
        function,
        [&](ida::decompiler::ExpressionView expr) {
            if (expr.type() == ida::decompiler::ItemType::ExprCall) {
                ++call_count;
            }
            return ida::decompiler::VisitAction::Continue;
        });
    if (!visited) {
        return std::unexpected(visited.error());
    }
    return call_count;
}

ida::Status show_gap_report() {
    ida::ui::message(
        "[lifter-port] Confirmed parity gaps for full /Users/int/dev/lifter port:\n"
        "  1) VMX + AVX scalar/packed microcode lifting subsets are now active via idax filter hooks.\n"
        "  2) Structured operand metadata now drives width/class decisions (byte width + register class), and helper-return\n"
        "     destinations now prefer typed micro-operands (register/resolved-memory) with deterministic operand-writeback fallback.\n"
        "  3) Rich IR mutation depth is still additive follow-up (deeper vector/UDT semantics + advanced callinfo/tmop).\n"
        "  4) Typed decompiler-view helpers now bridge host handles to edit/read flows; deeper in-view mutation ergonomics\n"
        "     remain additive follow-up.\n"
        "[lifter-port] Recently closed: VMX subset, AVX scalar/packed math+conversion\n"
        "               + helper-fallback bitwise/permute/blend/shift/compare/misc subset,\n"
        "               FUNC_OUTLINE + cache-dirty helpers, and typed decompiler-view wrappers.\n");
    return ida::ok();
}

ida::Status dump_decompiler_snapshot(const ida::plugin::ActionContext& context) {
    if (auto decompiler_status = require_decompiler(); !decompiler_status) {
        return decompiler_status;
    }

    bool has_view_host = false;
    std::optional<ida::decompiler::DecompilerView> typed_view;
    auto view_host_status = ida::plugin::with_decompiler_view_host(
        context,
        [&](void* host) -> ida::Status {
            has_view_host = true;
            auto view = ida::decompiler::view_from_host(host);
            if (!view) {
                return std::unexpected(view.error());
            }
            typed_view = *view;
            return ida::ok();
        });
    if (!view_host_status
        && view_host_status.error().category != ida::ErrorCategory::NotFound) {
        return std::unexpected(view_host_status.error());
    }

    ida::decompiler::DecompileFailure failure;
    ida::Address function_start = ida::BadAddress;
    std::string function_name;

    auto decompiled = [&]() -> ida::Result<ida::decompiler::DecompiledFunction> {
        if (typed_view.has_value()) {
            function_start = typed_view->function_address();
            auto view_name = typed_view->function_name();
            if (view_name) {
                function_name = *view_name;
            }
            return typed_view->decompiled_function();
        }

        auto address = resolve_action_address(context);
        if (!address) {
            return std::unexpected(address.error());
        }

        auto function = ida::function::at(*address);
        if (!function) {
            return std::unexpected(function.error());
        }

        function_start = function->start();
        function_name = function->name();
        return ida::decompiler::decompile(function_start, &failure);
    }();

    if (!decompiled) {
        std::string details = error_text(decompiled.error());
        if (!failure.description.empty()) {
            details += " | " + failure.description;
        }
        if (failure.failure_address != ida::BadAddress) {
            details += fmt(" @ %#llx", static_cast<unsigned long long>(failure.failure_address));
        }
        return std::unexpected(ida::Error::sdk(
            "Failed to decompile function for lifter snapshot", details));
    }

    auto pseudocode_lines = decompiled->lines();
    if (!pseudocode_lines) {
        return std::unexpected(pseudocode_lines.error());
    }

    auto microcode_lines = decompiled->microcode_lines();
    if (!microcode_lines) {
        return std::unexpected(microcode_lines.error());
    }

    auto call_count = count_call_expressions(*decompiled);
    if (!call_count) {
        return std::unexpected(call_count.error());
    }

    if (function_start == ida::BadAddress)
        function_start = decompiled->entry_address();
    if (function_name.empty()) {
        auto name = ida::function::name_at(function_start);
        if (name)
            function_name = *name;
    }

    ida::ui::message(fmt(
        "[lifter-port] snapshot %s @ %#llx : pseudo=%zu lines, microcode=%zu lines, calls=%zu, view_host=%s\n",
        function_name.empty() ? "<unknown>" : function_name.c_str(),
        static_cast<unsigned long long>(function_start),
        pseudocode_lines->size(),
        microcode_lines->size(),
        *call_count,
        has_view_host ? "yes" : "no"));

    const std::size_t preview_count = std::min<std::size_t>(microcode_lines->size(), 4);
    for (std::size_t i = 0; i < preview_count; ++i) {
        ida::ui::message(fmt("[lifter-port] microcode[%zu] %s\n",
                             i,
                             (*microcode_lines)[i].c_str()));
    }
    if (microcode_lines->size() > preview_count) {
        ida::ui::message("[lifter-port] microcode preview truncated\n");
    }

    return ida::ok();
}

/// Set FUNC_OUTLINE on the function under cursor (so the decompiler inlines it
/// into callers).  Mirrors the original's "Mark as inline" action.
ida::Status mark_inline(const ida::plugin::ActionContext& context) {
    auto address = resolve_action_address(context);
    if (!address) {
        return std::unexpected(address.error());
    }

    auto function = ida::function::at(*address);
    if (!function) {
        return std::unexpected(function.error());
    }

    auto outlined = ida::function::is_outlined(function->start());
    if (!outlined)
        return std::unexpected(outlined.error());

    // Already outlined (= inline) → nothing to do.
    if (*outlined) {
        return ida::ok();
    }

    if (auto set_status = ida::function::set_outlined(function->start(), true);
        !set_status) {
        return std::unexpected(set_status.error());
    }

    if (auto dirty_status = ida::decompiler::mark_dirty_with_callers(function->start());
        !dirty_status) {
        return std::unexpected(dirty_status.error());
    }

    ida::ui::message(fmt(
        "[lifter-port] Set FUNC_OUTLINE for %s @ %#llx (mark inline) and dirtied caller cache.\n",
        function->name().c_str(),
        static_cast<unsigned long long>(function->start())));
    return ida::ok();
}

/// Clear FUNC_OUTLINE on the function under cursor (undo inline, restore to
/// normal outlined function).  Mirrors the original's "Mark as outline" action.
ida::Status mark_outline(const ida::plugin::ActionContext& context) {
    auto address = resolve_action_address(context);
    if (!address) {
        return std::unexpected(address.error());
    }

    auto function = ida::function::at(*address);
    if (!function) {
        return std::unexpected(function.error());
    }

    auto outlined = ida::function::is_outlined(function->start());
    if (!outlined)
        return std::unexpected(outlined.error());

    // Not outlined → nothing to do.
    if (!*outlined) {
        return ida::ok();
    }

    if (auto set_status = ida::function::set_outlined(function->start(), false);
        !set_status) {
        return std::unexpected(set_status.error());
    }

    if (auto dirty_status = ida::decompiler::mark_dirty_with_callers(function->start());
        !dirty_status) {
        return std::unexpected(dirty_status.error());
    }

    ida::ui::message(fmt(
        "[lifter-port] Cleared FUNC_OUTLINE for %s @ %#llx (mark outline) and dirtied caller cache.\n",
        function->name().c_str(),
        static_cast<unsigned long long>(function->start())));
    return ida::ok();
}

/// Toggle debug printing and (un)install maturity subscription for microcode
/// dumps.  Mirrors the original's `set_debug_printing` + `hexrays_debug_callback`.
ida::Status toggle_debug_printing() {
    g_state.debug_printing = !g_state.debug_printing;

    if (g_state.debug_printing) {
        // Install maturity subscription to print disassembly/microcode at key stages.
        auto token = ida::decompiler::on_maturity_changed(
            [](const ida::decompiler::MaturityEvent& event) {
                if (!g_state.debug_printing) {
                    return;
                }

                // Maturity::Built  (== MMAT_GENERATED)  → print disassembly
                // Maturity::Trans1 (== MMAT_PREOPTIMIZED) → print microcode "BEFORE LIFTER"
                // Maturity::Nice   (== MMAT_LOCOPT)      → print microcode "AFTER LIFTER"
                if (event.new_maturity == ida::decompiler::Maturity::Built) {
                    auto name = ida::function::name_at(event.function_address);
                    ida::ui::message(fmt(
                        "\n================================================================\n"
                        "DISASSEMBLY: %s (at %#llx)\n"
                        "================================================================\n",
                        name ? name->c_str() : "<unknown>",
                        static_cast<unsigned long long>(event.function_address)));

                    // Print disassembly lines for the function.
                    auto function = ida::function::at(event.function_address);
                    if (!function) return;

                    ida::Address ea = function->start();
                    int line_count = 0;
                    constexpr int kMaxLines = 200;
                    while (ea < function->end() && line_count < kMaxLines) {
                        auto text = ida::instruction::text(ea);
                        if (text) {
                            ida::ui::message(fmt("%#llx: %s\n",
                                static_cast<unsigned long long>(ea), text->c_str()));
                        }
                        auto next = ida::address::next_defined(ea);
                        if (!next || *next <= ea) break;
                        ea = *next;
                        ++line_count;
                    }
                    if (line_count >= kMaxLines) {
                        ida::ui::message(fmt("... (truncated at %d lines)\n", kMaxLines));
                    }
                    ida::ui::message(
                        "================================================================\n\n");
                }

                if (event.new_maturity == ida::decompiler::Maturity::Trans1
                    || event.new_maturity == ida::decompiler::Maturity::Nice) {
                    const char* stage =
                        (event.new_maturity == ida::decompiler::Maturity::Trans1)
                            ? "BEFORE LIFTER"
                            : "AFTER LIFTER";
                    auto name = ida::function::name_at(event.function_address);

                    ida::ui::message(fmt(
                        "\n================================================================\n"
                        "MICROCODE [%s]: %s (at %#llx)\n"
                        "================================================================\n",
                        stage,
                        name ? name->c_str() : "<unknown>",
                        static_cast<unsigned long long>(event.function_address)));

                    // Print microcode lines via decompile snapshot.
                    ida::decompiler::DecompileFailure failure;
                    auto decompiled = ida::decompiler::decompile(event.function_address, &failure);
                    if (decompiled) {
                        auto mlines = decompiled->microcode_lines();
                        if (mlines) {
                            constexpr std::size_t kMaxMicroLines = 200;
                            const auto count = std::min<std::size_t>(mlines->size(), kMaxMicroLines);
                            for (std::size_t i = 0; i < count; ++i) {
                                ida::ui::message(fmt("    %s\n", (*mlines)[i].c_str()));
                            }
                            if (mlines->size() > kMaxMicroLines) {
                                ida::ui::message(fmt("    ... (truncated at %zu lines)\n", kMaxMicroLines));
                            }
                        }
                    }

                    ida::ui::message(
                        "================================================================\n\n");
                }
            });

        if (token) {
            g_state.maturity_subscription = ida::decompiler::ScopedSubscription(*token);
        } else {
            g_state.debug_printing = false;
            return std::unexpected(token.error());
        }
    } else {
        // Tear down maturity subscription.
        g_state.maturity_subscription = ida::decompiler::ScopedSubscription{};
    }

    ida::ui::message(fmt("[lifter-port] Debug printing %s\n",
                         g_state.debug_printing ? "ENABLED" : "DISABLED"));
    return ida::ok();
}

void unregister_actions();

ida::Status register_action_with_menu(const ida::plugin::Action& action) {
    auto register_status = ida::plugin::register_action(action);
    if (!register_status) {
        return std::unexpected(register_status.error());
    }

    auto attach_status = ida::plugin::attach_to_menu(kPluginMenuPath, action.id);
    if (!attach_status) {
        (void)ida::plugin::unregister_action(action.id);
        return std::unexpected(attach_status.error());
    }

    return ida::ok();
}

ida::Status register_actions() {
    g_state.actions_registered = true;

    ida::plugin::Action dump_action;
    dump_action.id = kActionDumpSnapshot;
    dump_action.label = "Lifter Port: Dump Snapshot";
    dump_action.hotkey = "Ctrl-Alt-Shift-L";
    dump_action.tooltip = "Decompile current function and print pseudocode/microcode snapshot";
    dump_action.handler = []() {
        ida::plugin::ActionContext context;
        auto screen = ida::ui::screen_address();
        if (screen) {
            context.current_address = *screen;
        }
        return dump_decompiler_snapshot(context);
    };
    dump_action.handler_with_context = [](const ida::plugin::ActionContext& context) {
        return dump_decompiler_snapshot(context);
    };
    dump_action.enabled = []() { return true; };
    dump_action.enabled_with_context = [](const ida::plugin::ActionContext& context) {
        if (context.current_address == ida::BadAddress) {
            return false;
        }
        if (context.widget_title.empty()) {
            return true;
        }
        return is_pseudocode_widget_title(context.widget_title);
    };

    // "Mark as inline" — sets FUNC_OUTLINE so decompiler inlines the function
    // into callers.  Enabled only when FUNC_OUTLINE is NOT already set.
    ida::plugin::Action inline_action;
    inline_action.id = kActionMarkInline;
    inline_action.label = "Mark as inline";
    inline_action.tooltip = "Set FUNC_OUTLINE (inline into callers) and clear decompiler caches";
    inline_action.handler = []() {
        ida::plugin::ActionContext context;
        auto screen = ida::ui::screen_address();
        if (screen) { context.current_address = *screen; }
        return mark_inline(context);
    };
    inline_action.handler_with_context = [](const ida::plugin::ActionContext& context) {
        return mark_inline(context);
    };
    inline_action.enabled = []() { return true; };
    inline_action.enabled_with_context = [](const ida::plugin::ActionContext& context) {
        if (context.current_address == ida::BadAddress) return false;
        if (!context.widget_title.empty()
            && !is_pseudocode_widget_title(context.widget_title)) {
            return false;
        }
        // Enable only when outline flag is NOT set.
        auto func = ida::function::at(context.current_address);
        if (!func) return false;
        auto outlined = ida::function::is_outlined(func->start());
        return outlined.has_value() && !*outlined;
    };

    // "Mark as outline" — clears FUNC_OUTLINE (undo inline, restore to normal).
    // Enabled only when FUNC_OUTLINE IS set.
    ida::plugin::Action outline_action;
    outline_action.id = kActionMarkOutline;
    outline_action.label = "Mark as outline";
    outline_action.tooltip = "Clear FUNC_OUTLINE (undo inline) and clear decompiler caches";
    outline_action.handler = []() {
        ida::plugin::ActionContext context;
        auto screen = ida::ui::screen_address();
        if (screen) { context.current_address = *screen; }
        return mark_outline(context);
    };
    outline_action.handler_with_context = [](const ida::plugin::ActionContext& context) {
        return mark_outline(context);
    };
    outline_action.enabled = []() { return true; };
    outline_action.enabled_with_context = [](const ida::plugin::ActionContext& context) {
        if (context.current_address == ida::BadAddress) return false;
        if (!context.widget_title.empty()
            && !is_pseudocode_widget_title(context.widget_title)) {
            return false;
        }
        // Enable only when outline flag IS set.
        auto func = ida::function::at(context.current_address);
        if (!func) return false;
        auto outlined = ida::function::is_outlined(func->start());
        return outlined.has_value() && *outlined;
    };

    // "Toggle debug printing" — installs/removes maturity subscription for
    // disassembly and microcode dumps at key decompilation stages.
    ida::plugin::Action debug_action;
    debug_action.id = kActionToggleDebug;
    debug_action.label = "Lifter Port: Toggle Debug Printing";
    debug_action.hotkey = "Ctrl-Alt-Shift-D";
    debug_action.tooltip = "Toggle debug printing of disassembly/microcode during decompilation";
    debug_action.handler = []() { return toggle_debug_printing(); };
    debug_action.handler_with_context = [](const ida::plugin::ActionContext&) {
        return toggle_debug_printing();
    };
    debug_action.enabled = []() { return true; };
    debug_action.enabled_with_context = [](const ida::plugin::ActionContext&) { return true; };

    ida::plugin::Action gaps_action;
    gaps_action.id = kActionShowGaps;
    gaps_action.label = "Lifter Port: Show Gap Report";
    gaps_action.hotkey = "Ctrl-Alt-Shift-G";
    gaps_action.tooltip = "Print remaining parity gaps for full lifter migration";
    gaps_action.handler = []() { return show_gap_report(); };
    gaps_action.handler_with_context = [](const ida::plugin::ActionContext&) {
        return show_gap_report();
    };
    gaps_action.enabled = []() { return true; };
    gaps_action.enabled_with_context = [](const ida::plugin::ActionContext&) { return true; };

    if (auto status = register_action_with_menu(dump_action); !status) {
        unregister_actions();
        return status;
    }
    if (auto status = register_action_with_menu(inline_action); !status) {
        unregister_actions();
        return status;
    }
    if (auto status = register_action_with_menu(outline_action); !status) {
        unregister_actions();
        return status;
    }
    if (auto status = register_action_with_menu(debug_action); !status) {
        unregister_actions();
        return status;
    }
    if (auto status = register_action_with_menu(gaps_action); !status) {
        unregister_actions();
        return status;
    }

    return ida::ok();
}

void detach_popup_actions() {
    for (const auto& title : g_state.popup_titles) {
        for (const char* action_id : kActionIds) {
            (void)ida::plugin::detach_from_popup(title, action_id);
        }
    }
    g_state.popup_titles.clear();
}

void unregister_actions() {
    if (!g_state.actions_registered) {
        return;
    }

    detach_popup_actions();

    for (const char* action_id : kActionIds) {
        (void)ida::plugin::detach_from_menu(kPluginMenuPath, action_id);
        (void)ida::plugin::unregister_action(action_id);
    }

    g_state.actions_registered = false;
}

void try_attach_popup_actions(std::string_view widget_title) {
    if (!is_pseudocode_widget_title(widget_title)) {
        return;
    }

    const std::string title(widget_title);
    if (g_state.popup_titles.contains(title)) {
        return;
    }

    for (const char* action_id : kActionIds) {
        auto attach = ida::plugin::attach_to_popup(title, action_id);
        if (!attach) {
            ida::ui::message(fmt(
                "[lifter-port] popup attach failed for '%s' (%s): %s\n",
                title.c_str(), action_id, error_text(attach.error()).c_str()));
            return;
        }
    }

    g_state.popup_titles.insert(title);
}

ida::Status install_widget_subscriptions() {
    auto visible_sub = ida::ui::on_widget_visible([](std::string title) {
        try_attach_popup_actions(title);
    });
    if (!visible_sub) {
        return std::unexpected(visible_sub.error());
    }
    g_state.ui_subscriptions.emplace_back(*visible_sub);

    auto closing_sub = ida::ui::on_widget_closing([](std::string title) {
        g_state.popup_titles.erase(title);
    });
    if (!closing_sub) {
        return std::unexpected(closing_sub.error());
    }
    g_state.ui_subscriptions.emplace_back(*closing_sub);

    auto current_widget_sub = ida::ui::on_current_widget_changed(
        [](ida::ui::Widget current_widget, ida::ui::Widget) {
            if (!current_widget.valid()) {
                return;
            }
            try_attach_popup_actions(current_widget.title());
        });
    if (!current_widget_sub) {
        return std::unexpected(current_widget_sub.error());
    }
    g_state.ui_subscriptions.emplace_back(*current_widget_sub);

    return ida::ok();
}

void reset_state() {
    g_state.maturity_subscription = ida::decompiler::ScopedSubscription{};
    g_state.debug_printing = false;
    g_state.vmx_filter.reset();
    g_state.ui_subscriptions.clear();
    unregister_actions();
}

class LifterPortProbePlugin final : public ida::plugin::Plugin {
public:
    ida::plugin::Info info() const override {
        return {
            .name = "Lifter Port Probe",
            .hotkey = "Ctrl-Alt-Shift-G",
            .comment = "idax-first probe for lifter microcode-port parity",
            .help =
                "Ports lifter plugin shell workflows (actions + pseudocode popup wiring) "
                "and reports remaining parity gaps for full AVX/VMX microcode lifting."
        };
    }

    bool init() override {
        if (auto action_status = register_actions(); !action_status) {
            ida::ui::message(fmt("[lifter-port] action setup failed: %s\n",
                                 error_text(action_status.error()).c_str()));
            reset_state();
            return false;
        }

        if (auto subscription_status = install_widget_subscriptions(); !subscription_status) {
            ida::ui::message(fmt("[lifter-port] UI subscription setup failed: %s\n",
                                 error_text(subscription_status.error()).c_str()));
            reset_state();
            return false;
        }

        if (auto vmx_filter_status = install_vmx_lifter_filter(); !vmx_filter_status) {
            ida::ui::message(fmt("[lifter-port] VMX lifter filter disabled: %s\n",
                                 error_text(vmx_filter_status.error()).c_str()));
        } else {
            ida::ui::message("[lifter-port] VMX + AVX scalar/packed microcode lifter filter enabled (subset).\n");
        }

        ida::ui::message(
            "[lifter-port] initialized. Use menu action 'Lifter Port: Show Gap Report' "
            "for current parity status.\n");
        return true;
    }

    void term() override {
        reset_state();
        ida::ui::message("[lifter-port] terminated\n");
    }

    ida::Status run(std::size_t) override {
        return show_gap_report();
    }
};

} // namespace

IDAX_PLUGIN(LifterPortProbePlugin)

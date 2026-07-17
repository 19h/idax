/// \file segment.cpp
/// \brief Implementation of ida::segment — segment CRUD, lookup, traversal.

#include "detail/sdk_bridge.hpp"
#include <ida/segment.hpp>

#include <climits>
#include <limits>

namespace ida::segment {

// ── Internal access helper ──────────────────────────────────────────────

namespace {

static_assert(SR_inherit == 1);
static_assert(SR_user == 2);
static_assert(SR_auto == 3);
static_assert(SR_autostart == 4);

struct ResolvedSegmentRegister {
    int index{-1};
    int relative_index{-1};
    std::string canonical_name;
    std::size_t bit_width{0};
    bool is_code{false};
    bool is_data{false};
};

Status validate_public_address(Address address, std::string_view operation) {
    if (address == BadAddress) {
        return std::unexpected(Error::validation(
            "BadAddress is not a valid segment-register address",
            std::string(operation)));
    }
    return ida::ok();
}

Result<std::string> canonical_register_name(processor_t& processor, int index) {
    qstring name;
    const auto length = get_reg_name(
        &name, index, static_cast<std::size_t>(processor.segreg_size));
    if (length < 0 || name.empty()) {
        return std::unexpected(Error::internal(
            "Processor did not provide a segment-register name",
            std::to_string(index)));
    }
    return ida::detail::to_string(name);
}

Result<ResolvedSegmentRegister> resolve_segment_register_index(int index) {
    processor_t* processor = get_ph();
    if (processor == nullptr) {
        return std::unexpected(Error::unsupported(
            "No active processor descriptor is available"));
    }
    if (processor->reg_first_sreg < 0
        || processor->reg_last_sreg < processor->reg_first_sreg
        || processor->segreg_size <= 0) {
        return std::unexpected(Error::unsupported(
            "Active processor has no valid segment-register model"));
    }
    if (static_cast<std::size_t>(processor->segreg_size) > sizeof(sel_t)) {
        return std::unexpected(Error::unsupported(
            "Processor segment-register width exceeds value capacity",
            std::to_string(processor->segreg_size)));
    }
    if (index < processor->reg_first_sreg
        || index > processor->reg_last_sreg) {
        return std::unexpected(Error::validation(
            "Register is not in the active processor's segment-register interval",
            std::to_string(index)));
    }
    const int relative = index - processor->reg_first_sreg;
    if (relative < 0 || relative >= SREG_NUM) {
        return std::unexpected(Error::unsupported(
            "Processor segment-register interval exceeds database capacity",
            std::to_string(index)));
    }
    auto name = canonical_register_name(*processor, index);
    if (!name)
        return std::unexpected(name.error());
    return ResolvedSegmentRegister{
        .index = index,
        .relative_index = relative,
        .canonical_name = std::move(*name),
        .bit_width = static_cast<std::size_t>(processor->segreg_size) * 8U,
        .is_code = index == processor->reg_code_sreg,
        .is_data = index == processor->reg_data_sreg,
    };
}

Result<ResolvedSegmentRegister> resolve_segment_register(
    std::string_view register_name) {
    if (register_name.empty()) {
        return std::unexpected(Error::validation(
            "Segment-register name must not be empty"));
    }
    if (register_name.find('\0') != std::string_view::npos) {
        return std::unexpected(Error::validation(
            "Segment-register name must not contain NUL bytes"));
    }
    qstring name = ida::detail::to_qstring(register_name);
    const int index = str2reg(name.c_str());
    if (index < 0) {
        return std::unexpected(Error::not_found(
            "Unknown register name", std::string(register_name)));
    }
    auto resolved = resolve_segment_register_index(index);
    if (!resolved && resolved.error().category == ErrorCategory::Validation) {
        return std::unexpected(Error::validation(
            "Register is not a segment register", std::string(register_name)));
    }
    return resolved;
}

Result<sel_t> to_sdk_segment_register_value(
    std::optional<std::uint64_t> value) {
    if (!value)
        return BADSEL;
    constexpr auto maximum = std::numeric_limits<sel_t>::max();
    if (*value >= static_cast<std::uint64_t>(maximum)) {
        return std::unexpected(Error::validation(
            "Segment-register value collides with the unknown-value sentinel",
            std::to_string(*value)));
    }
    return static_cast<sel_t>(*value);
}

std::optional<std::uint64_t> from_sdk_segment_register_value(sel_t value) {
    if (value == BADSEL)
        return std::nullopt;
    return static_cast<std::uint64_t>(value);
}

Result<SegmentRegisterSource> from_sdk_segment_register_source(uchar tag) {
    switch (tag) {
    case SR_inherit: return SegmentRegisterSource::Inherited;
    case SR_user: return SegmentRegisterSource::User;
    case SR_auto: return SegmentRegisterSource::Analysis;
    case SR_autostart: return SegmentRegisterSource::AnalysisAtSegmentStart;
    default:
        return std::unexpected(Error::unsupported(
            "Unknown segment-register range provenance",
            std::to_string(tag)));
    }
}

Result<uchar> to_sdk_segment_register_source(SegmentRegisterSource source) {
    switch (source) {
    case SegmentRegisterSource::Inherited: return SR_inherit;
    case SegmentRegisterSource::User: return SR_user;
    case SegmentRegisterSource::Analysis: return SR_auto;
    case SegmentRegisterSource::AnalysisAtSegmentStart: return SR_autostart;
    }
    return std::unexpected(Error::validation(
        "Invalid segment-register range provenance"));
}

Result<SegmentRegisterRange> copy_segment_register_range(
    const sreg_range_t& range) {
    if (range.start_ea == BADADDR || range.end_ea == BADADDR
        || range.start_ea >= range.end_ea) {
        return std::unexpected(Error::internal(
            "SDK returned a malformed segment-register range"));
    }
    auto source = from_sdk_segment_register_source(range.tag);
    if (!source)
        return std::unexpected(source.error());
    return SegmentRegisterRange{
        .start = static_cast<Address>(range.start_ea),
        .end = static_cast<Address>(range.end_ea),
        .value = from_sdk_segment_register_value(range.val),
        .source = *source,
    };
}

Result<std::optional<std::uint64_t>> default_segment_register_value_by_index(
    Address address, const ResolvedSegmentRegister& reg) {
    auto valid = validate_public_address(address, "default query");
    if (!valid)
        return std::unexpected(valid.error());
    segment_info_t info;
    if (!get_segment_info(&info, static_cast<ea_t>(address))) {
        return std::unexpected(Error::not_found(
            "No segment at address", std::to_string(address)));
    }
    return from_sdk_segment_register_value(info.get_defsr(reg.relative_index));
}

Result<bool> all_segment_defaults_match(
    const ResolvedSegmentRegister& reg, sel_t expected) {
    const int total = get_segm_qty();
    if (total <= 0) {
        return std::unexpected(Error::not_found(
            "No segments are available for default verification",
            reg.canonical_name));
    }
    for (int index = 0; index < total; ++index) {
        segment_info_t info;
        if (!get_segment_info_by_num(&info, index)) {
            return std::unexpected(Error::internal(
                "Could not read segment while verifying register defaults",
                std::to_string(index)));
        }
        if (info.get_defsr(reg.relative_index) != expected)
            return false;
    }
    return true;
}

Type sdk_type_to_type(uchar sdk_type) {
    switch (sdk_type) {
    case SEG_NORM:  return Type::Normal;
    case SEG_XTRN:  return Type::External;
    case SEG_CODE:  return Type::Code;
    case SEG_DATA:  return Type::Data;
    case SEG_BSS:   return Type::Bss;
    case SEG_ABSSYM:return Type::AbsoluteSymbols;
    case SEG_COMM:  return Type::Common;
    case SEG_NULL:  return Type::Null;
    case SEG_UNDF:  return Type::Undefined;
    case SEG_IMP:   return Type::Import;
    case SEG_IMEM:  return Type::InternalMemory;
    case SEG_GRP:   return Type::Group;
    default:        return Type::Undefined;
    }
}

uchar type_to_sdk_type(Type type) {
    switch (type) {
    case Type::Normal:         return SEG_NORM;
    case Type::External:       return SEG_XTRN;
    case Type::Code:           return SEG_CODE;
    case Type::Data:           return SEG_DATA;
    case Type::Bss:            return SEG_BSS;
    case Type::AbsoluteSymbols:return SEG_ABSSYM;
    case Type::Common:         return SEG_COMM;
    case Type::Null:           return SEG_NULL;
    case Type::Undefined:      return SEG_UNDF;
    case Type::Import:         return SEG_IMP;
    case Type::InternalMemory: return SEG_IMEM;
    case Type::Group:          return SEG_GRP;
    default:                   return SEG_NORM;
    }
}

int find_segment_index_by_start(ea_t start) {
    const int total = get_segm_qty();
    for (int i = 0; i < total; ++i) {
        segment_t* seg = getnseg(i);
        if (seg != nullptr && seg->start_ea == start)
            return i;
    }
    return -1;
}

Result<segment_t*> segment_at(Address address) {
    segment_t* seg = getseg(address);
    if (seg == nullptr)
        return std::unexpected(Error::not_found("No segment at address",
                                                std::to_string(address)));
    return seg;
}

} // anonymous namespace

struct SegmentAccess {
    static Segment populate(const segment_t* seg) {
        Segment s;
        s.start_   = static_cast<Address>(seg->start_ea);
        s.end_     = static_cast<Address>(seg->end_ea);
        s.bitness_ = ida::detail::bitness_to_bits(seg->bitness);
        s.type_    = sdk_type_to_type(seg->type);

        s.perm_.read    = (seg->perm & SEGPERM_READ)  != 0;
        s.perm_.write   = (seg->perm & SEGPERM_WRITE) != 0;
        s.perm_.execute = (seg->perm & SEGPERM_EXEC)  != 0;

        // Segment name.
        qstring qname;
        if (get_segm_name(&qname, seg) > 0)
            s.name_ = ida::detail::to_string(qname);

        // Segment class.
        qstring qclass;
        if (get_segm_class(&qclass, seg) > 0)
            s.class_ = ida::detail::to_string(qclass);

        s.visible_ = seg->is_visible_segm();
        return s;
    }
};

// ── Segment::refresh ────────────────────────────────────────────────────

Status Segment::refresh() {
    segment_t* seg = getseg(start_);
    if (seg == nullptr)
        return std::unexpected(Error::not_found("Segment no longer exists",
                                                std::to_string(start_)));
    *this = SegmentAccess::populate(seg);
    return ida::ok();
}

// ── CRUD ────────────────────────────────────────────────────────────────

Result<Segment> create(Address start, Address end,
                       std::string_view name,
                       std::string_view class_name,
                       Type type) {
    qstring qname  = ida::detail::to_qstring(name);
    qstring qclass = ida::detail::to_qstring(class_name);

    // Construct a temporary segment_t and use add_segm_ex for full control.
    segment_t seg;
    seg.start_ea = static_cast<ea_t>(start);
    seg.end_ea   = static_cast<ea_t>(end);
    seg.bitness  = 1; // default 32-bit
    seg.align    = saRelByte;
    seg.comb     = scPub;
    seg.perm     = SEGPERM_READ | SEGPERM_WRITE | SEGPERM_EXEC;
    seg.type     = type_to_sdk_type(type);

    if (!add_segm_ex(&seg, qname.c_str(), qclass.c_str(), ADDSEG_OR_DIE))
        return std::unexpected(Error::sdk("add_segm_ex failed",
                                          std::to_string(start) + "-" + std::to_string(end)));

    // Re-read the newly created segment.
    segment_t* created = getseg(start);
    if (created == nullptr)
        return std::unexpected(Error::internal("Segment created but not retrievable",
                                               std::to_string(start)));
    return SegmentAccess::populate(created);
}

Status remove(Address ea) {
    if (!del_segm(ea, SEGMOD_KILL))
        return std::unexpected(Error::sdk("del_segm failed", std::to_string(ea)));
    return ida::ok();
}

// ── Lookup ──────────────────────────────────────────────────────────────

Result<Segment> at(Address ea) {
    segment_t* seg = getseg(ea);
    if (seg == nullptr)
        return std::unexpected(Error::not_found("No segment at address",
                                                std::to_string(ea)));
    return SegmentAccess::populate(seg);
}

Result<Segment> by_name(std::string_view name) {
    qstring qname = ida::detail::to_qstring(name);
    segment_t* seg = get_segm_by_name(qname.c_str());
    if (seg == nullptr)
        return std::unexpected(Error::not_found("No segment with name",
                                                std::string(name)));
    return SegmentAccess::populate(seg);
}

Result<Segment> by_index(std::size_t index) {
    int total = get_segm_qty();
    if (static_cast<int>(index) >= total)
        return std::unexpected(Error::validation("Segment index out of range",
                                                 std::to_string(index)));
    segment_t* seg = getnseg(static_cast<int>(index));
    if (seg == nullptr)
        return std::unexpected(Error::internal("getnseg returned null for valid index",
                                               std::to_string(index)));
    return SegmentAccess::populate(seg);
}

Result<std::size_t> count() {
    return static_cast<std::size_t>(get_segm_qty());
}

// ── Property mutation ───────────────────────────────────────────────────

Status set_name(Address ea, std::string_view name) {
    segment_t* seg = getseg(ea);
    if (seg == nullptr)
        return std::unexpected(Error::not_found("No segment at address",
                                                std::to_string(ea)));
    qstring qname = ida::detail::to_qstring(name);
    int rc = set_segm_name(seg, qname.c_str());
    if (rc == 0)
        return std::unexpected(Error::sdk("set_segm_name failed",
                                          std::to_string(ea)));
    return ida::ok();
}

Status set_class(Address ea, std::string_view class_name) {
    segment_t* seg = getseg(ea);
    if (seg == nullptr)
        return std::unexpected(Error::not_found("No segment at address",
                                                std::to_string(ea)));
    qstring qclass = ida::detail::to_qstring(class_name);
    int rc = set_segm_class(seg, qclass.c_str());
    if (rc == 0)
        return std::unexpected(Error::sdk("set_segm_class failed",
                                          std::to_string(ea)));
    return ida::ok();
}

Status set_type(Address ea, Type type) {
    segment_t* seg = getseg(ea);
    if (seg == nullptr)
        return std::unexpected(Error::not_found("No segment at address",
                                                std::to_string(ea)));
    seg->type = type_to_sdk_type(type);
    seg->update();
    return ida::ok();
}

Status set_permissions(Address ea, Permissions perm) {
    segment_t* seg = getseg(ea);
    if (seg == nullptr)
        return std::unexpected(Error::not_found("No segment at address"));

    uchar p = 0;
    if (perm.read)    p |= SEGPERM_READ;
    if (perm.write)   p |= SEGPERM_WRITE;
    if (perm.execute) p |= SEGPERM_EXEC;
    seg->perm = p;
    seg->update();
    return ida::ok();
}

Status set_bitness(Address ea, int bits) {
    segment_t* seg = getseg(ea);
    if (seg == nullptr)
        return std::unexpected(Error::not_found("No segment at address",
                                                std::to_string(ea)));
    int sdk_bitness = ida::detail::bits_to_bitness(bits);
    if (sdk_bitness < 0)
        return std::unexpected(Error::validation("Invalid bitness value (must be 16/32/64)",
                                                  std::to_string(bits)));
    set_segm_addressing(seg, sdk_bitness);
    return ida::ok();
}

Result<std::vector<SegmentRegisterDescriptor>> segment_registers() {
    processor_t* processor = get_ph();
    if (processor == nullptr) {
        return std::unexpected(Error::unsupported(
            "No active processor descriptor is available"));
    }
    if (processor->reg_first_sreg < 0
        || processor->reg_last_sreg < processor->reg_first_sreg) {
        return std::unexpected(Error::unsupported(
            "Active processor has no valid segment-register interval"));
    }
    const auto span = static_cast<std::int64_t>(processor->reg_last_sreg)
        - static_cast<std::int64_t>(processor->reg_first_sreg);
    if (span >= SREG_NUM) {
        return std::unexpected(Error::unsupported(
            "Processor segment-register interval exceeds database capacity"));
    }

    std::vector<SegmentRegisterDescriptor> registers;
    const auto count = static_cast<std::size_t>(span + 1);
    registers.reserve(count);
    for (std::size_t offset = 0; offset < count; ++offset) {
        const int index = processor->reg_first_sreg
            + static_cast<int>(offset);
        auto resolved = resolve_segment_register_index(index);
        if (!resolved)
            return std::unexpected(resolved.error());
        registers.push_back(SegmentRegisterDescriptor{
            .name = std::move(resolved->canonical_name),
            .bit_width = resolved->bit_width,
            .is_code = resolved->is_code,
            .is_data = resolved->is_data,
        });
    }
    return registers;
}

Result<std::optional<std::uint64_t>> segment_register_value(
    Address address, std::string_view register_name) {
    auto valid = validate_public_address(address, "value query");
    if (!valid)
        return std::unexpected(valid.error());
    auto reg = resolve_segment_register(register_name);
    if (!reg)
        return std::unexpected(reg.error());
    return from_sdk_segment_register_value(
        get_sreg(static_cast<ea_t>(address), reg->index));
}

Result<std::optional<std::uint64_t>> default_segment_register_value(
    Address address, std::string_view register_name) {
    auto reg = resolve_segment_register(register_name);
    if (!reg)
        return std::unexpected(reg.error());
    return default_segment_register_value_by_index(address, *reg);
}

Result<SegmentRegisterRange> segment_register_range(
    Address address, std::string_view register_name) {
    auto valid = validate_public_address(address, "range query");
    if (!valid)
        return std::unexpected(valid.error());
    auto reg = resolve_segment_register(register_name);
    if (!reg)
        return std::unexpected(reg.error());
    sreg_range_t range;
    if (!get_sreg_range(&range, static_cast<ea_t>(address), reg->index)) {
        return std::unexpected(Error::not_found(
            "No segment-register range at address",
            std::to_string(address) + ":" + reg->canonical_name));
    }
    return copy_segment_register_range(range);
}

Result<std::optional<SegmentRegisterRange>> previous_segment_register_range(
    Address address, std::string_view register_name) {
    auto valid = validate_public_address(address, "previous range query");
    if (!valid)
        return std::unexpected(valid.error());
    auto reg = resolve_segment_register(register_name);
    if (!reg)
        return std::unexpected(reg.error());
    sreg_range_t range;
    if (!get_prev_sreg_range(&range, static_cast<ea_t>(address), reg->index))
        return std::optional<SegmentRegisterRange>{};
    auto copied = copy_segment_register_range(range);
    if (!copied)
        return std::unexpected(copied.error());
    return std::optional<SegmentRegisterRange>{std::move(*copied)};
}

Result<std::vector<SegmentRegisterRange>> segment_register_ranges(
    std::string_view register_name) {
    auto reg = resolve_segment_register(register_name);
    if (!reg)
        return std::unexpected(reg.error());
    const std::size_t total = get_sreg_ranges_qty(reg->index);
    if (total > static_cast<std::size_t>(INT_MAX)) {
        return std::unexpected(Error::internal(
            "Segment-register range count exceeds SDK index capacity",
            std::to_string(total)));
    }
    std::vector<SegmentRegisterRange> ranges;
    ranges.reserve(total);
    for (std::size_t index = 0; index < total; ++index) {
        sreg_range_t range;
        if (!getn_sreg_range(&range, reg->index, static_cast<int>(index))) {
            return std::unexpected(Error::sdk(
                "Could not enumerate segment-register range",
                reg->canonical_name + ":" + std::to_string(index)));
        }
        auto copied = copy_segment_register_range(range);
        if (!copied)
            return std::unexpected(copied.error());
        ranges.push_back(std::move(*copied));
    }
    return ranges;
}

Result<std::optional<std::size_t>> segment_register_range_index(
    Address address, std::string_view register_name) {
    auto valid = validate_public_address(address, "range index query");
    if (!valid)
        return std::unexpected(valid.error());
    auto reg = resolve_segment_register(register_name);
    if (!reg)
        return std::unexpected(reg.error());
    const int index = get_sreg_range_num(static_cast<ea_t>(address), reg->index);
    if (index < 0)
        return std::optional<std::size_t>{};
    return std::optional<std::size_t>{static_cast<std::size_t>(index)};
}

Status split_segment_register_range(
    Address address,
    std::string_view register_name,
    std::optional<std::uint64_t> value,
    SegmentRegisterSource source) {
    auto valid = validate_public_address(address, "range split");
    if (!valid)
        return valid;
    auto reg = resolve_segment_register(register_name);
    if (!reg)
        return std::unexpected(reg.error());
    auto native_value = to_sdk_segment_register_value(value);
    if (!native_value)
        return std::unexpected(native_value.error());
    auto tag = to_sdk_segment_register_source(source);
    if (!tag)
        return std::unexpected(tag.error());

    if (!split_sreg_range(static_cast<ea_t>(address), reg->index,
                          *native_value, *tag, true)) {
        return std::unexpected(Error::sdk(
            "Processor rejected segment-register range split",
            std::to_string(address) + ":" + reg->canonical_name));
    }

    auto observed = segment_register_range(address, reg->canonical_name);
    if (!observed || observed->start != address
        || observed->value != value || observed->source != source) {
        return std::unexpected(Error::sdk(
            "Segment-register split postcondition mismatch",
            std::to_string(address) + ":" + reg->canonical_name));
    }
    return ida::ok();
}

Status remove_segment_register_range(
    Address range_start, std::string_view register_name) {
    auto valid = validate_public_address(range_start, "range removal");
    if (!valid)
        return valid;
    auto reg = resolve_segment_register(register_name);
    if (!reg)
        return std::unexpected(reg.error());
    auto before = segment_register_range(range_start, reg->canonical_name);
    if (!before)
        return std::unexpected(before.error());
    if (before->start != range_start) {
        return std::unexpected(Error::validation(
            "Address is not the start of a segment-register range",
            std::to_string(range_start) + ":" + reg->canonical_name));
    }
    if (!del_sreg_range(static_cast<ea_t>(range_start), reg->index)) {
        return std::unexpected(Error::sdk(
            "Segment-register range could not be removed",
            std::to_string(range_start) + ":" + reg->canonical_name));
    }
    sreg_range_t observed;
    if (get_sreg_range(&observed, static_cast<ea_t>(range_start), reg->index)
        && observed.start_ea == static_cast<ea_t>(range_start)) {
        return std::unexpected(Error::sdk(
            "Removed segment-register range is still present",
            std::to_string(range_start) + ":" + reg->canonical_name));
    }
    return ida::ok();
}

Status set_default_segment_register(
    Address address,
    std::string_view register_name,
    std::optional<std::uint64_t> value) {
    auto valid = validate_public_address(address, "default mutation");
    if (!valid)
        return valid;
    auto reg = resolve_segment_register(register_name);
    if (!reg)
        return std::unexpected(reg.error());
    auto native_value = to_sdk_segment_register_value(value);
    if (!native_value)
        return std::unexpected(native_value.error());
    if (!set_default_sreg_value_ea(static_cast<ea_t>(address), reg->index,
                                   *native_value)) {
        return std::unexpected(Error::sdk(
            "Could not set segment-register default",
            std::to_string(address) + ":" + reg->canonical_name));
    }
    auto observed = default_segment_register_value_by_index(address, *reg);
    if (!observed || *observed != value) {
        return std::unexpected(Error::sdk(
            "Segment-register default postcondition mismatch",
            std::to_string(address) + ":" + reg->canonical_name));
    }
    return ida::ok();
}

Status set_default_segment_register_for_all(
    std::string_view register_name,
    std::optional<std::uint64_t> value) {
    auto reg = resolve_segment_register(register_name);
    if (!reg)
        return std::unexpected(reg.error());
    auto native_value = to_sdk_segment_register_value(value);
    if (!native_value)
        return std::unexpected(native_value.error());
    if (!set_default_sreg_value_ea(BADADDR, reg->index, *native_value)) {
        return std::unexpected(Error::sdk(
            "Could not set segment-register default for all segments",
            reg->canonical_name));
    }
    auto verified = all_segment_defaults_match(*reg, *native_value);
    if (!verified)
        return std::unexpected(verified.error());
    if (!*verified) {
        return std::unexpected(Error::sdk(
            "All-segment register default postcondition mismatch",
            reg->canonical_name));
    }
    return ida::ok();
}

Status set_default_data_segment(std::optional<std::uint64_t> value) {
    processor_t* processor = get_ph();
    if (processor == nullptr) {
        return std::unexpected(Error::unsupported(
            "No active processor descriptor is available"));
    }
    auto reg = resolve_segment_register_index(processor->reg_data_sreg);
    if (!reg)
        return std::unexpected(reg.error());
    auto native_value = to_sdk_segment_register_value(value);
    if (!native_value)
        return std::unexpected(native_value.error());
    set_default_dataseg(*native_value);
    auto verified = all_segment_defaults_match(*reg, *native_value);
    if (!verified)
        return std::unexpected(verified.error());
    if (!*verified) {
        return std::unexpected(Error::sdk(
            "Data-segment default postcondition mismatch",
            reg->canonical_name));
    }
    return ida::ok();
}

Status set_segment_register_at_next_code(
    Address search_start,
    Address maximum,
    std::string_view register_name,
    std::optional<std::uint64_t> value) {
    auto valid_start = validate_public_address(search_start, "next-code mutation");
    if (!valid_start)
        return valid_start;
    auto valid_maximum = validate_public_address(maximum, "next-code maximum");
    if (!valid_maximum)
        return valid_maximum;
    if (search_start > maximum) {
        return std::unexpected(Error::validation(
            "Next-code search bounds are reversed",
            std::to_string(search_start) + ":" + std::to_string(maximum)));
    }
    auto reg = resolve_segment_register(register_name);
    if (!reg)
        return std::unexpected(reg.error());
    auto native_value = to_sdk_segment_register_value(value);
    if (!native_value)
        return std::unexpected(native_value.error());

    const ea_t next_code = find_code(
        static_cast<ea_t>(search_start),
        SEARCH_DOWN | SEARCH_NOBRK | SEARCH_NOSHOW);
    if (next_code == BADADDR || next_code > static_cast<ea_t>(maximum)) {
        return std::unexpected(Error::not_found(
            "No instruction exists within the next-code bounds",
            std::to_string(search_start) + ":" + std::to_string(maximum)));
    }
    set_sreg_at_next_code(static_cast<ea_t>(search_start),
                          static_cast<ea_t>(maximum), reg->index,
                          *native_value);
    sreg_range_t observed;
    if (!get_sreg_range(&observed, next_code, reg->index)
        || observed.start_ea != next_code || observed.val != *native_value) {
        return std::unexpected(Error::sdk(
            "Next-code segment-register postcondition mismatch",
            std::to_string(next_code) + ":" + reg->canonical_name));
    }
    return ida::ok();
}

Status copy_segment_register_ranges(
    std::string_view destination_register,
    std::string_view source_register,
    bool map_selectors_to_addresses) {
    auto destination = resolve_segment_register(destination_register);
    if (!destination)
        return std::unexpected(destination.error());
    auto source = resolve_segment_register(source_register);
    if (!source)
        return std::unexpected(source.error());
    if (destination->index == source->index) {
        return std::unexpected(Error::conflict(
            "Source and destination segment registers must differ",
            destination->canonical_name));
    }
    auto expected = segment_register_ranges(source->canonical_name);
    if (!expected)
        return std::unexpected(expected.error());
    if (map_selectors_to_addresses) {
        for (auto& range : *expected) {
            if (range.value) {
                const ea_t mapped = sel2ea(static_cast<sel_t>(*range.value));
                range.value = mapped == BADADDR
                    ? std::optional<std::uint64_t>{}
                    : std::optional<std::uint64_t>{
                          static_cast<std::uint64_t>(mapped)};
            }
        }
    }

    copy_sreg_ranges(destination->index, source->index,
                     map_selectors_to_addresses);
    auto observed = segment_register_ranges(destination->canonical_name);
    if (!observed)
        return std::unexpected(observed.error());
    if (*observed != *expected) {
        return std::unexpected(Error::sdk(
            "Copied segment-register ranges do not match source state",
            source->canonical_name + "->" + destination->canonical_name));
    }
    return ida::ok();
}

Status set_default_segment_register(Address address,
                                    int register_index,
                                    std::uint64_t value) {
    auto reg = resolve_segment_register_index(register_index);
    if (!reg)
        return std::unexpected(reg.error());
    return set_default_segment_register(
        address, reg->canonical_name,
        std::optional<std::uint64_t>{value});
}

Status set_default_segment_register_for_all(int register_index,
                                            std::uint64_t value) {
    auto reg = resolve_segment_register_index(register_index);
    if (!reg)
        return std::unexpected(reg.error());
    return set_default_segment_register_for_all(
        reg->canonical_name, std::optional<std::uint64_t>{value});
}

Result<std::string> comment(Address address, bool repeatable) {
    auto seg = segment_at(address);
    if (!seg)
        return std::unexpected(seg.error());
    segment_t* raw = *seg;

    qstring text;
    if (get_segment_cmt(&text, raw, repeatable) <= 0)
        return std::unexpected(Error::not_found("No segment comment",
                                                std::to_string(raw->start_ea)));
    return ida::detail::to_string(text);
}

Status set_comment(Address address, std::string_view text, bool repeatable) {
    auto seg = segment_at(address);
    if (!seg)
        return std::unexpected(seg.error());
    segment_t* raw = *seg;

    qstring qtext = ida::detail::to_qstring(text);
    set_segment_cmt(raw, qtext.c_str(), repeatable);
    return ida::ok();
}

Status resize(Address address, Address new_start, Address new_end) {
    if (new_start == BadAddress || new_end == BadAddress)
        return std::unexpected(Error::validation("Invalid resize bounds",
                                                 std::to_string(new_start) + ":" + std::to_string(new_end)));
    if (new_start >= new_end)
        return std::unexpected(Error::validation("Segment start must be < end",
                                                 std::to_string(new_start) + ":" + std::to_string(new_end)));

    auto seg = segment_at(address);
    if (!seg)
        return std::unexpected(seg.error());
    segment_t* raw = *seg;

    if (!set_segm_start(raw->start_ea, static_cast<ea_t>(new_start), SEGMOD_KEEP))
        return std::unexpected(Error::sdk("set_segm_start failed",
                                          std::to_string(raw->start_ea)));

    const ea_t anchor = static_cast<ea_t>(new_start);
    if (!set_segm_end(anchor, static_cast<ea_t>(new_end), SEGMOD_KEEP))
        return std::unexpected(Error::sdk("set_segm_end failed",
                                          std::to_string(anchor)));
    return ida::ok();
}

Status move(Address address, Address new_start) {
    if (new_start == BadAddress)
        return std::unexpected(Error::validation("Invalid segment move start",
                                                 std::to_string(new_start)));

    auto seg = segment_at(address);
    if (!seg)
        return std::unexpected(seg.error());

    int rc = move_segm(seg.value(), static_cast<ea_t>(new_start), MSF_FIXONCE);
    if (rc != MOVE_SEGM_OK)
        return std::unexpected(Error::sdk("move_segm failed",
                                          std::to_string(rc)));
    return ida::ok();
}

// ── Traversal ───────────────────────────────────────────────────────────

SegmentIterator::SegmentIterator(std::size_t index, std::size_t total)
    : idx_(index), total_(total) {}

Segment SegmentIterator::operator*() const {
    segment_t* seg = getnseg(static_cast<int>(idx_));
    if (seg == nullptr) {
        // Return an empty Segment; caller should not dereference past end.
        return Segment{};
    }
    return SegmentAccess::populate(seg);
}

SegmentIterator& SegmentIterator::operator++() {
    if (idx_ < total_)
        ++idx_;
    return *this;
}

SegmentIterator SegmentIterator::operator++(int) {
    SegmentIterator tmp = *this;
    ++(*this);
    return tmp;
}

SegmentRange::SegmentRange()
    : total_(static_cast<std::size_t>(get_segm_qty())) {}

SegmentIterator SegmentRange::begin() const {
    return SegmentIterator(0, total_);
}

SegmentIterator SegmentRange::end() const {
    return SegmentIterator(total_, total_);
}

SegmentRange all() {
    return SegmentRange();
}

Result<Segment> first() {
    auto qty = count();
    if (!qty)
        return std::unexpected(qty.error());
    if (*qty == 0)
        return std::unexpected(Error::not_found("No segments"));
    return by_index(0);
}

Result<Segment> last() {
    auto qty = count();
    if (!qty)
        return std::unexpected(qty.error());
    if (*qty == 0)
        return std::unexpected(Error::not_found("No segments"));
    return by_index(*qty - 1);
}

Result<Segment> next(Address address) {
    auto seg = segment_at(address);
    if (!seg)
        return std::unexpected(seg.error());
    int index = find_segment_index_by_start(seg.value()->start_ea);
    if (index < 0)
        return std::unexpected(Error::internal("Current segment index not found",
                                               std::to_string(seg.value()->start_ea)));
    return by_index(static_cast<std::size_t>(index + 1));
}

Result<Segment> prev(Address address) {
    auto seg = segment_at(address);
    if (!seg)
        return std::unexpected(seg.error());
    int index = find_segment_index_by_start(seg.value()->start_ea);
    if (index <= 0)
        return std::unexpected(Error::not_found("No previous segment",
                                                std::to_string(address)));
    return by_index(static_cast<std::size_t>(index - 1));
}

} // namespace ida::segment

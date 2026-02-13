/// \file segment.cpp
/// \brief Implementation of ida::segment — segment CRUD, lookup, traversal.

#include "detail/sdk_bridge.hpp"
#include <ida/segment.hpp>

namespace ida::segment {

// ── Internal access helper ──────────────────────────────────────────────

namespace {

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

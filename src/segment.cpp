/// \file segment.cpp
/// \brief Implementation of ida::segment — segment CRUD, lookup, traversal.

#include "detail/sdk_bridge.hpp"
#include <ida/segment.hpp>

namespace ida::segment {

// ── Internal access helper ──────────────────────────────────────────────

struct SegmentAccess {
    static Segment populate(const segment_t* seg) {
        Segment s;
        s.start_   = static_cast<Address>(seg->start_ea);
        s.end_     = static_cast<Address>(seg->end_ea);
        s.bitness_ = ida::detail::bitness_to_bits(seg->bitness);

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
                       Type /*type*/) {
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

    if (!add_segm_ex(&seg, qname.c_str(), qclass.c_str(), ADDSEG_OR_DIE))
        return std::unexpected(Error::sdk("add_segm_ex failed"));

    // Re-read the newly created segment.
    segment_t* created = getseg(start);
    if (created == nullptr)
        return std::unexpected(Error::internal("Segment created but not retrievable"));
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

Result<Segment> by_index(std::size_t idx) {
    int total = get_segm_qty();
    if (static_cast<int>(idx) >= total)
        return std::unexpected(Error::validation("Segment index out of range",
                                                 std::to_string(idx)));
    segment_t* seg = getnseg(static_cast<int>(idx));
    if (seg == nullptr)
        return std::unexpected(Error::internal("getnseg returned null for valid index"));
    return SegmentAccess::populate(seg);
}

Result<std::size_t> count() {
    return static_cast<std::size_t>(get_segm_qty());
}

// ── Property mutation ───────────────────────────────────────────────────

Status set_name(Address ea, std::string_view name) {
    segment_t* seg = getseg(ea);
    if (seg == nullptr)
        return std::unexpected(Error::not_found("No segment at address"));
    qstring qname = ida::detail::to_qstring(name);
    int rc = set_segm_name(seg, qname.c_str());
    if (rc == 0)
        return std::unexpected(Error::sdk("set_segm_name failed"));
    return ida::ok();
}

Status set_class(Address ea, std::string_view class_name) {
    segment_t* seg = getseg(ea);
    if (seg == nullptr)
        return std::unexpected(Error::not_found("No segment at address"));
    qstring qclass = ida::detail::to_qstring(class_name);
    int rc = set_segm_class(seg, qclass.c_str());
    if (rc == 0)
        return std::unexpected(Error::sdk("set_segm_class failed"));
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
        return std::unexpected(Error::not_found("No segment at address"));
    int sdk_bitness = ida::detail::bits_to_bitness(bits);
    if (sdk_bitness < 0)
        return std::unexpected(Error::validation("Invalid bitness value (must be 16/32/64)"));
    set_segm_addressing(seg, sdk_bitness);
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

} // namespace ida::segment

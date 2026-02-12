/// \file loader.cpp
/// \brief Implementation of ida::loader — InputFile wrapper, Loader base class
///        bridge, and loader helper functions.

#include "detail/sdk_bridge.hpp"
#include <ida/loader.hpp>

namespace ida::loader {

// ── Internal access helper ──────────────────────────────────────────────

struct InputFileAccess {
    static linput_t* get(const InputFile& f) {
        return static_cast<linput_t*>(f.handle_);
    }
    static InputFile wrap(linput_t* li) {
        InputFile f;
        f.handle_ = li;
        return f;
    }
};

// ── InputFile implementation ────────────────────────────────────────────

Result<std::int64_t> InputFile::size() const {
    auto* li = InputFileAccess::get(*this);
    if (li == nullptr)
        return std::unexpected(Error::validation("InputFile not initialized"));
    int64 sz = qlsize(li);
    if (sz < 0)
        return std::unexpected(Error::sdk("qlsize failed"));
    return static_cast<std::int64_t>(sz);
}

Result<std::int64_t> InputFile::tell() const {
    auto* li = InputFileAccess::get(*this);
    if (li == nullptr)
        return std::unexpected(Error::validation("InputFile not initialized"));
    qoff64_t pos = qltell(li);
    return static_cast<std::int64_t>(pos);
}

Result<std::int64_t> InputFile::seek(std::int64_t offset) {
    auto* li = InputFileAccess::get(*this);
    if (li == nullptr)
        return std::unexpected(Error::validation("InputFile not initialized"));
    qoff64_t pos = qlseek(li, static_cast<qoff64_t>(offset), 0 /*SEEK_SET*/);
    if (pos == -1)
        return std::unexpected(Error::sdk("qlseek failed"));
    return static_cast<std::int64_t>(pos);
}

Result<std::vector<std::uint8_t>> InputFile::read_bytes(std::size_t count) {
    auto* li = InputFileAccess::get(*this);
    if (li == nullptr)
        return std::unexpected(Error::validation("InputFile not initialized"));
    std::vector<std::uint8_t> buf(count);
    ssize_t nread = qlread(li, buf.data(), count);
    if (nread < 0)
        return std::unexpected(Error::sdk("qlread failed"));
    buf.resize(static_cast<std::size_t>(nread));
    return buf;
}

Result<std::vector<std::uint8_t>> InputFile::read_bytes_at(std::int64_t offset,
                                                            std::size_t count) {
    auto r = seek(offset);
    if (!r)
        return std::unexpected(r.error());
    return read_bytes(count);
}

Result<std::string> InputFile::read_string(std::int64_t offset,
                                           std::size_t max_len) const {
    auto* li = InputFileAccess::get(*this);
    if (li == nullptr)
        return std::unexpected(Error::validation("InputFile not initialized"));
    std::vector<char> buf(max_len + 1, 0);
    char* result = qlgetz(li, static_cast<int64>(offset), buf.data(), max_len);
    if (result == nullptr)
        return std::unexpected(Error::sdk("qlgetz failed"));
    return std::string(result);
}

Result<std::string> InputFile::filename() const {
    // linput_t doesn't directly expose filename, but we can return
    // an empty string with a note. The filename is typically available
    // from the loader callback parameter, not from linput_t itself.
    return std::unexpected(Error::unsupported(
        "Filename not available from InputFile; use the loader callback parameter"));
}

// ── Loader helper functions ─────────────────────────────────────────────

Status file_to_database(void* li_handle, std::int64_t file_offset,
                        Address ea, AddressSize size, bool patchable) {
    auto* li = static_cast<linput_t*>(li_handle);
    if (li == nullptr)
        return std::unexpected(Error::validation("null linput handle"));

    int rc = file2base(li,
                       static_cast<qoff64_t>(file_offset),
                       static_cast<ea_t>(ea),
                       static_cast<ea_t>(ea + size),
                       patchable ? FILEREG_PATCHABLE : FILEREG_NOTPATCHABLE);
    if (rc == 0)
        return std::unexpected(Error::sdk("file2base failed"));
    return ida::ok();
}

Status memory_to_database(const void* data, Address ea, AddressSize size) {
    if (data == nullptr)
        return std::unexpected(Error::validation("null data pointer"));
    int rc = mem2base(data,
                      static_cast<ea_t>(ea),
                      static_cast<ea_t>(ea + size),
                      -1 /*no file position*/);
    if (rc == 0)
        return std::unexpected(Error::sdk("mem2base failed"));
    return ida::ok();
}

Status set_processor(std::string_view processor_name) {
    std::string pname(processor_name);
    if (!set_processor_type(pname.c_str(), SETPROC_LOADER))
        return std::unexpected(Error::sdk("set_processor_type failed",
                                          std::string(processor_name)));
    return ida::ok();
}

Status create_filename_comment() {
    ::create_filename_cmt();
    return ida::ok();
}

[[noreturn]] void abort_load(std::string_view message) {
    std::string msg(message);
    ::loader_failure("%s", msg.c_str());
    // loader_failure does a longjmp and never returns.
    // The [[noreturn]] attribute tells the compiler this.
    // Unreachable, but some compilers warn without this:
    std::abort();
}

} // namespace ida::loader

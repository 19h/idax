#include <algorithm>
#include <array>
#include <cstring>
#include <fstream>
#include <limits>
#include "detail/sdk_bridge.hpp"
#include <ida/dyld_cache.hpp>
#include <ida/analysis.hpp>
#if IDA_SDK_VERSION >= 940
#include <dscu.h>
#endif

namespace ida::dyld_cache {
namespace {
bool valid_path(std::string_view path) {
    return !path.empty() && path.find('\0') == std::string_view::npos;
}

std::uint64_t little_endian(const unsigned char* bytes, std::size_t size) {
    std::uint64_t value = 0;
    for (std::size_t index = 0; index < size; ++index)
        value |= std::uint64_t(bytes[index]) << (index * 8);
    return value;
}

// Offsets follow Apple's mach-o/dyld_cache_format.h. Decode fields explicitly
// so file byte order, compiler packing, and host alignment cannot affect them.
class CacheFile {
public:
    explicit CacheFile(const std::string& path)
        : stream_(path, std::ios::binary | std::ios::ate) {
        if (stream_) {
            auto end = stream_.tellg();
            if (end >= 0) size_ = static_cast<std::uint64_t>(end);
        }
    }
    bool opened() const { return stream_.is_open(); }
    std::uint64_t size() const { return size_; }
    bool read(std::uint64_t offset, unsigned char* bytes, std::size_t count) {
        if (offset > size_ || count > size_ - offset
            || offset > std::uint64_t(std::numeric_limits<std::streamoff>::max())
            || count > std::size_t(std::numeric_limits<std::streamsize>::max()))
            return false;
        stream_.clear();
        stream_.seekg(static_cast<std::streamoff>(offset));
        stream_.read(reinterpret_cast<char*>(bytes), static_cast<std::streamsize>(count));
        return stream_.good();
    }
    Result<std::string> image_path(std::uint64_t offset) {
        std::string result;
        std::array<unsigned char, 512> buffer{};
        constexpr std::size_t maximum_path = 65536;
        while (offset < size_ && result.size() < maximum_path) {
            const auto count = static_cast<std::size_t>(std::min<std::uint64_t>(
                {buffer.size(), size_ - offset, maximum_path - result.size()}));
            if (!read(offset, buffer.data(), count))
                return std::unexpected(Error::sdk("Cannot read cache image path"));
            for (std::size_t index = 0; index < count; ++index) {
                if (buffer[index] == 0) {
                    if (result.empty() || result.front() != '/')
                        return std::unexpected(Error::validation("Cache image path is not absolute"));
                    return result;
                }
                result.push_back(static_cast<char>(buffer[index]));
            }
            offset += count;
        }
        return std::unexpected(Error::validation("Cache image path is unterminated or too long"));
    }
private:
    std::ifstream stream_;
    std::uint64_t size_{0};
};

bool valid_magic(const unsigned char* bytes) {
    if (std::memcmp(bytes, "dyld_v", 6) != 0
        || (bytes[6] != '0' && bytes[6] != '1') || bytes[7] != ' ')
        return false;
    bool architecture = false;
    bool terminated = false;
    for (std::size_t index = 8; index < 16; ++index) {
        const unsigned char value = bytes[index];
        if (value == 0) { terminated = true; continue; }
        if (terminated) return false;
        if (value == ' ' && !architecture) continue;
        if (!((value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z')
              || (value >= '0' && value <= '9') || value == '_'))
            return false;
        architecture = true;
    }
    return architecture;
}

Status finish_load(bool wait_for_analysis) {
    return wait_for_analysis ? ida::analysis::wait() : ida::ok();
}

#if IDA_SDK_VERSION >= 940
Result<dscu_svc_t*> service() {
    if (auto* value = get_dscu_svc()) return value;
    return std::unexpected(Error::unsupported("Current database has no dyld shared-cache service"));
}
bool loaded(const dscu_svc_t& svc, const region_info_t& region) {
    switch (region.type) {
    case rt_image_entity: return svc.is_image_loaded(region.image_index);
    case rt_island: return svc.is_island_loaded(region.branch_island_number);
    case rt_mapping: return svc.is_mapping_loaded(region.start);
    case rt_got: return svc.is_got_loaded(region.start);
    case rt_unknown: return svc.is_unknown_region_loaded(region.start);
    case rt_cache_data: return svc.is_cache_data_loaded(region.start);
    default: return false;
    }
}
Result<std::size_t> load_kind(region_type_t kind, bool wait_for_analysis) {
    auto svc = service();
    if (!svc) return std::unexpected(svc.error());
    region_info_vec_t regions;
    (*svc)->get_regions(&regions, nullptr, false);
    dscu_load_request_t request;
    for (const auto& region : regions)
        if (region.type == kind && !loaded(**svc, region))
            request.add_region(region);
    const std::size_t count = request.images.size() + request.islands.size()
        + request.mappings.size() + request.gots.size()
        + request.unknown_regions.size() + request.cache_data.size();
    if (!request.empty() && !(*svc)->load_regions(request))
        return std::unexpected(Error::sdk("Shared-cache region load failed"));
    if (auto status = finish_load(wait_for_analysis); !status)
        return std::unexpected(status.error());
    return count;
}
#else
Error unsupported_service() {
    return Error::unsupported("Dyld shared-cache loading requires SDK 9.4 or later");
}
#endif
} // namespace

Result<std::vector<ModuleInfo>> list_modules(std::string_view cache_path) {
    if (!valid_path(cache_path))
        return std::unexpected(Error::validation("Cache path must be nonempty and contain no NUL bytes"));
    CacheFile file{std::string(cache_path)};
    if (!file.opened())
        return std::unexpected(Error::sdk("Cannot open dyld shared-cache file", std::string(cache_path)));
    std::array<unsigned char, 0x1c8> header{};
    if (!file.read(0, header.data(), 0x20) || !valid_magic(header.data()))
        return std::unexpected(Error::validation("Invalid or truncated dyld cache header"));
    const auto header_size = little_endian(header.data() + 0x10, 4);
    if (header_size < 0x20 || header_size > file.size())
        return std::unexpected(Error::validation("Invalid dyld cache mapping offset"));
    const auto mapping_count = little_endian(header.data() + 0x14, 4);
    if (mapping_count > (file.size() - header_size) / 32)
        return std::unexpected(Error::validation("Dyld cache mapping table exceeds the file"));
    const auto readable_header = static_cast<std::size_t>(std::min<std::uint64_t>(header.size(), header_size));
    if (!file.read(0, header.data(), readable_header))
        return std::unexpected(Error::sdk("Cannot read dyld cache header"));

    std::uint64_t offset = 0;
    std::uint64_t count = 0;
    bool text_table = false;
    if (header_size >= 0x1c8) {
        offset = little_endian(header.data() + 0x1c0, 4);
        count = little_endian(header.data() + 0x1c4, 4);
    }
    if (offset == 0 && count == 0) {
        offset = little_endian(header.data() + 0x18, 4);
        count = little_endian(header.data() + 0x1c, 4);
    }
    if (offset == 0 && count == 0 && header_size >= 0x98) {
        offset = little_endian(header.data() + 0x88, 8);
        count = little_endian(header.data() + 0x90, 8);
        text_table = true;
    }
    if ((offset == 0) != (count == 0))
        return std::unexpected(Error::validation("Dyld cache image offset/count pair is inconsistent"));
    if (count == 0) return std::vector<ModuleInfo>{};
    if (offset < header_size || offset > file.size() || count > (file.size() - offset) / 32)
        return std::unexpected(Error::validation("Dyld cache image table exceeds the file"));
    std::vector<ModuleInfo> modules;
    if (count > modules.max_size())
        return std::unexpected(Error::validation("Dyld cache image count exceeds host capacity"));
    modules.reserve(static_cast<std::size_t>(count));
    std::array<unsigned char, 32> entry{};
    for (std::uint64_t index = 0; index < count; ++index) {
        if (!file.read(offset + index * 32, entry.data(), entry.size()))
            return std::unexpected(Error::sdk("Cannot read dyld cache image table"));
        const auto path_offset = little_endian(entry.data() + (text_table ? 28 : 24), 4);
        if (path_offset < header_size)
            return std::unexpected(Error::validation("Dyld cache image path overlaps its header"));
        auto path = file.image_path(path_offset);
        if (!path) return std::unexpected(path.error());
        modules.push_back({std::move(*path), little_endian(entry.data() + (text_table ? 16 : 0), 8)});
    }
    return modules;
}

bool is_available() {
#if IDA_SDK_VERSION >= 940
    return get_dscu_svc() != nullptr;
#else
    return false;
#endif
}

Result<std::vector<ModuleInfo>> list_modules() {
#if IDA_SDK_VERSION >= 940
    auto svc = service();
    if (!svc) return std::unexpected(svc.error());
    const int count = (*svc)->get_images_count();
    if (count < 0) return std::unexpected(Error::sdk("Invalid shared-cache image count"));
    std::vector<ModuleInfo> result;
    result.reserve(static_cast<std::size_t>(count));
    for (int index = 0; index < count; ++index) {
        qstring path;
        const auto address = (*svc)->get_image_address(index);
        if (!(*svc)->get_image_name(&path, index) || path.empty() || address == BADADDR)
            return std::unexpected(Error::sdk("Cannot retrieve shared-cache image metadata"));
        result.push_back({std::string(path.c_str(), path.length()), address});
    }
    return result;
#else
    return std::unexpected(unsupported_service());
#endif
}

Status load_module(std::string_view module_path, bool wait_for_analysis) {
    if (!valid_path(module_path) || module_path.front() != '/')
        return std::unexpected(Error::validation("Module path must be absolute and contain no NUL bytes"));
#if IDA_SDK_VERSION >= 940
    auto svc = service();
    if (!svc) return std::unexpected(svc.error());
    const int index = (*svc)->get_image_index(std::string(module_path).c_str());
    if (index < 0) return std::unexpected(Error::not_found("Shared-cache module not found", std::string(module_path)));
    if (!(*svc)->is_image_loaded(index) && !(*svc)->load_image(index))
        return std::unexpected(Error::sdk("Shared-cache module load failed", std::string(module_path)));
    return finish_load(wait_for_analysis);
#else
    (void)wait_for_analysis;
    return std::unexpected(unsupported_service());
#endif
}

Status load_section(Address address, bool wait_for_analysis) {
    if (address == BadAddress)
        return std::unexpected(Error::validation("Invalid shared-cache address"));
#if IDA_SDK_VERSION >= 940
    auto svc = service();
    if (!svc) return std::unexpected(svc.error());
    region_info_t region;
    if (!(*svc)->get_region_by_ea(&region, address, nullptr, false))
        return std::unexpected(Error::not_found("Address has no shared-cache region"));
    if (region.type == rt_header) return load_dyld_header(wait_for_analysis);
    switch (region.type) {
    case rt_image_entity: case rt_island: case rt_mapping:
    case rt_got: case rt_unknown: case rt_cache_data:
        break;
    default:
        return std::unexpected(Error::unsupported("Unsupported shared-cache region type"));
    }
    if (!loaded(**svc, region)) {
        dscu_load_request_t request;
        request.add_region(region);
        if (request.empty())
            return std::unexpected(Error::unsupported("Region has no shared-cache load operation"));
        if (!(*svc)->load_regions(request))
            return std::unexpected(Error::sdk("Shared-cache section load failed"));
    }
    return finish_load(wait_for_analysis);
#else
    (void)wait_for_analysis;
    return std::unexpected(unsupported_service());
#endif
}

Status load_dyld_header(bool wait_for_analysis) {
#if IDA_SDK_VERSION >= 940
    auto svc = service();
    if (!svc) return std::unexpected(svc.error());
    region_info_vec_t regions;
    (*svc)->get_regions(&regions, nullptr, false);
    for (const auto& region : regions) {
        if (region.type != rt_header || region.size == 0) continue;
        if (region.start == BADADDR || region.size > BADADDR - region.start)
            return std::unexpected(Error::sdk("Invalid shared-cache header range"));
        // is_mapped endpoints are insufficient when an interior gap exists.
        ea_t cursor = region.start;
        const ea_t end = cursor + region.size;
        while (cursor < end) {
            const auto* segment = getseg(cursor);
            if (segment == nullptr)
                return std::unexpected(Error::unsupported("Shared-cache header was not loaded by the loader"));
            cursor = std::min(end, segment->end_ea);
        }
        return finish_load(wait_for_analysis);
    }
    return std::unexpected(Error::not_found("Shared-cache header region not found"));
#else
    (void)wait_for_analysis;
    return std::unexpected(unsupported_service());
#endif
}

#if IDA_SDK_VERSION >= 940
Result<std::size_t> load_branch_islands(bool wait) { return load_kind(rt_island, wait); }
Result<std::size_t> load_branch_mappings(bool wait) { return load_kind(rt_mapping, wait); }
Result<std::size_t> load_global_offset_tables(bool wait) { return load_kind(rt_got, wait); }
Result<std::size_t> load_gaps(bool wait) { return load_kind(rt_unknown, wait); }
Result<std::size_t> load_cache_data(bool wait) { return load_kind(rt_cache_data, wait); }
#else
Result<std::size_t> load_branch_islands(bool) { return std::unexpected(unsupported_service()); }
Result<std::size_t> load_branch_mappings(bool) { return std::unexpected(unsupported_service()); }
Result<std::size_t> load_global_offset_tables(bool) { return std::unexpected(unsupported_service()); }
Result<std::size_t> load_gaps(bool) { return std::unexpected(unsupported_service()); }
Result<std::size_t> load_cache_data(bool) { return std::unexpected(unsupported_service()); }
#endif
} // namespace ida::dyld_cache

/// Offline cache parser adversarial cases and non-cache runtime behavior.
#include <ida/idax.hpp>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <limits>
#include <string>
#include <vector>

namespace {
int failures = 0;
int checks = 0;
#define CHECK(x) do { ++checks; if (!(x)) { ++failures; std::printf("FAIL %d: %s\n", __LINE__, #x); } } while(false)
using Bytes = std::vector<unsigned char>;
void put(Bytes& bytes, std::size_t offset, std::uint64_t value, std::size_t width = 4) {
    for (std::size_t index = 0; index < width; ++index) bytes.at(offset + index) = (value >> (8 * index)) & 0xff;
}
void path(Bytes& bytes, std::size_t offset, const std::string& value) {
    std::copy(value.begin(), value.end(), bytes.begin() + offset);
    bytes.at(offset + value.size()) = 0;
}
Bytes fixture(int format = 0) {
    Bytes bytes(0x400, 0);
    const std::string magic = "dyld_v1  arm64e";
    std::copy(magic.begin(), magic.end(), bytes.begin());
    put(bytes, 0x10, format == 1 ? 0x40 : 0x1c8);
    const std::size_t offset_field = format == 0 ? 0x1c0 : format == 1 ? 0x18 : 0x88;
    put(bytes, offset_field, 0x200, format == 2 ? 8 : 4);
    put(bytes, offset_field + (format == 2 ? 8 : 4), 2, format == 2 ? 8 : 4);
    put(bytes, 0x200 + (format == 2 ? 16 : 0), 0x123456789abcdef0ULL, 8);
    put(bytes, 0x200 + (format == 2 ? 28 : 24), 0x300);
    put(bytes, 0x220 + (format == 2 ? 16 : 0), 0xfedcba9876543210ULL, 8);
    put(bytes, 0x220 + (format == 2 ? 28 : 24), 0x330);
    path(bytes, 0x300, "/usr/lib/alpha.dylib");
    path(bytes, 0x330, "/usr/lib/beta.dylib");
    return bytes;
}
}
int main(int argc, char** argv) {
    if (argc < 2) return 1;
    const auto output = std::filesystem::path(argv[1]).parent_path() / "dyld_parser_fixture";
    auto parse = [&](const Bytes& bytes) {
        { std::ofstream file(output, std::ios::binary); file.write(reinterpret_cast<const char*>(bytes.data()), bytes.size()); }
        return ida::dyld_cache::list_modules(output.string());
    };
    for (int format = 0; format < 3; ++format) {
        auto result = parse(fixture(format));
        CHECK(result && result->size() == 2);
        if (result && result->size() == 2) {
            CHECK((*result)[0].path == "/usr/lib/alpha.dylib");
            CHECK((*result)[0].load_address == 0x123456789abcdef0ULL);
            CHECK((*result)[1].path == "/usr/lib/beta.dylib");
            CHECK((*result)[1].load_address == 0xfedcba9876543210ULL);
        }
    }
    auto modern = fixture();
    put(modern, 0x18, 0x280); put(modern, 0x1c, 1); // Stale legacy table must not win.
    CHECK(parse(modern)->size() == 2);
    for (auto bytes : {Bytes{}, Bytes(15), Bytes(31)}) CHECK(!parse(bytes));
    for (std::size_t position : {std::size_t(0), std::size_t(7), std::size_t(15)}) {
        auto bytes = fixture(); bytes[position] = 0xff; CHECK(!parse(bytes));
    }
    for (auto offset : {0ULL, 0x100ULL, 0x3ffULL, 0xffffffffULL}) {
        auto bytes = fixture(); put(bytes, 0x1c0, offset); CHECK(!parse(bytes));
    }
    { auto bytes = fixture(); put(bytes, 0x1c4, 0); CHECK(!parse(bytes)); }
    { auto bytes = fixture(); put(bytes, 0x1c4, 0xffffffff); CHECK(!parse(bytes)); }
    { auto bytes = fixture(2); put(bytes, 0x90, std::numeric_limits<std::uint64_t>::max(), 8); CHECK(!parse(bytes)); }
    { auto bytes = fixture(); put(bytes, 0x14, 0xffffffff); CHECK(!parse(bytes)); }
    { auto bytes = fixture(); put(bytes, 0x10, 0x500); CHECK(!parse(bytes)); }
    { auto bytes = fixture(); put(bytes, 0x238, 0x400); CHECK(!parse(bytes)); }
    { auto bytes = fixture(); put(bytes, 0x238, 0x10); CHECK(!parse(bytes)); }
    { auto bytes = fixture(); std::fill(bytes.begin() + 0x330, bytes.end(), 'x'); CHECK(!parse(bytes)); }
    { auto bytes = fixture(); bytes[0x330] = 0; CHECK(!parse(bytes)); }
    { auto bytes = fixture(); bytes[0x330] = 'x'; CHECK(!parse(bytes)); }
    { auto bytes = fixture(); put(bytes, 0x1c0, 0); put(bytes, 0x1c4, 0); auto result = parse(bytes); CHECK(result && result->empty()); }
    CHECK(!ida::dyld_cache::list_modules(""));
    CHECK(!ida::dyld_cache::list_modules(std::string("bad\0path", 8)));
    CHECK(!ida::dyld_cache::list_modules(output.string() + ".missing"));
    if (const char* real_cache = std::getenv("IDAX_TEST_DYLD_CACHE")) {
        auto result = ida::dyld_cache::list_modules(real_cache);
        CHECK(result && !result->empty());
        if (result) std::printf("real cache inventory: %zu images\n", result->size());
    }
    std::filesystem::remove(output);
    CHECK(ida::database::init(argc, argv));
    CHECK(ida::database::open(argv[1]));
    CHECK(!ida::dyld_cache::is_available());
    CHECK(!ida::dyld_cache::list_modules());
    CHECK(!ida::dyld_cache::load_module("/usr/lib/alpha.dylib"));
    CHECK(!ida::dyld_cache::load_module("relative.dylib"));
    CHECK(!ida::dyld_cache::load_section(ida::BadAddress));
    CHECK(!ida::dyld_cache::load_section(0x1000));
    CHECK(!ida::dyld_cache::load_dyld_header());
    CHECK(!ida::dyld_cache::load_branch_islands());
    CHECK(!ida::dyld_cache::load_branch_mappings());
    CHECK(!ida::dyld_cache::load_global_offset_tables());
    CHECK(!ida::dyld_cache::load_gaps());
    CHECK(!ida::dyld_cache::load_cache_data());
    CHECK(ida::database::close(false));
    // Opt-in real-cache evidence uses a disposable toplevel file. Sidecars
    // remain read-only inputs through symlinks; all database files are local.
    if (const char* real_cache = std::getenv("IDAX_TEST_DYLD_CACHE")) {
        const std::filesystem::path source(real_cache);
        const auto directory = output.parent_path() / "dyld_service_fixture";
        std::filesystem::create_directories(directory);
        const auto copied = directory / source.filename();
        std::filesystem::copy_file(source, copied);
        const auto prefix = source.filename().string() + ".";
        for (const auto& sidecar : std::filesystem::directory_iterator(source.parent_path())) {
            if (sidecar.path().filename().string().starts_with(prefix))
                std::filesystem::create_symlink(sidecar.path(), directory / sidecar.path().filename());
        }
        auto opened = ida::database::open(copied.string(), ida::database::OpenMode::SkipAnalysis);
        CHECK(opened);
        if (opened) {
            CHECK(ida::dyld_cache::is_available());
            CHECK(ida::dyld_cache::load_dyld_header());
            auto modules = ida::dyld_cache::list_modules();
            CHECK(modules && !modules->empty());
            bool found = false;
            if (modules) for (const auto& module : *modules) {
                if (module.path != "/usr/lib/system/libsystem_blocks.dylib") continue;
                found = true;
                CHECK(ida::dyld_cache::load_module(module.path, true));
                CHECK(ida::dyld_cache::load_module(module.path, true));
                CHECK(ida::dyld_cache::load_section(module.load_address, true));
                CHECK(ida::address::is_mapped(module.load_address));
                break;
            }
            CHECK(found);
            CHECK(ida::database::close(false));
        }
        std::filesystem::remove_all(directory);
    }
    std::printf("dyld cache: %d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
